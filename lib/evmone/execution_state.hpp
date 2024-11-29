// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "symbolic.hpp"
#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>
#include <iostream>

namespace evmone
{
namespace advanced
{
struct AdvancedCodeAnalysis;
}
namespace baseline
{
class CodeAnalysis;
}

using evmc::bytes;
using evmc::bytes_view;
using intx::uint256;

/// Provides memory for EVM stack.
template <bool isSymbolic>
class StackSpace
{
    static StackItem<isSymbolic>* allocate() noexcept
    {
        static constexpr auto alignment = std::bit_ceil(sizeof(StackItem<isSymbolic>));
        static constexpr auto size = limit * sizeof(StackItem<isSymbolic>);
#ifdef _MSC_VER
        // MSVC doesn't support aligned_alloc() but _aligned_malloc() can be used instead.
        const auto p = _aligned_malloc(size, alignment);
#else
        const auto p = std::aligned_alloc(alignment, size);
#endif
        if constexpr (isSymbolic)
        {
            for (size_t i = 0; i < limit; i++)
            {
                StackItem<isSymbolic>* ptr = &static_cast<StackItem<isSymbolic>*>(p)[i];
                ptr = new(ptr) StackItem<true> {0, SymbolicStackItemPtr()};
            }
            
        }
        return static_cast<StackItem<isSymbolic>*>(p);
    }

    struct Deleter
    {
        // TODO(C++23): static
        void operator()(void* p) noexcept
        {
#ifdef _MSC_VER
            // For MSVC the _aligned_malloc() must be paired with _aligned_free().
            _aligned_free(p);
#else
            std::free(p);
#endif
        }
    };

    /// The storage allocated for maximum possible number of items.
    /// Items are aligned to 256 bits for better packing in cache lines.
    std::unique_ptr<StackItem<isSymbolic>, Deleter> m_stack_space;

public:
    /// The maximum number of EVM stack items.
    static constexpr auto limit = 1024;

    StackSpace() noexcept : m_stack_space{allocate()} {}

    /// Returns the pointer to the "bottom", i.e. below the stack space.
    [[nodiscard, clang::no_sanitize("bounds")]] StackItem<isSymbolic>* bottom() noexcept
    {
        return m_stack_space.get() - 1;
    }
};


/// The EVM memory.
///
/// The implementations uses initial allocation of 4k and then grows capacity with 2x factor.
/// Some benchmarks have been done to confirm 4k is ok-ish value.
class Memory
{
    /// The size of allocation "page".
    static constexpr size_t page_size = 4 * 1024;

    struct FreeDeleter
    {
        void operator()(uint8_t* p) const noexcept { std::free(p); }
    };

    /// Owned pointer to allocated memory.
    std::unique_ptr<uint8_t[], FreeDeleter> m_data;

    /// The "virtual" size of the memory.
    size_t m_size = 0;

    /// The size of allocated memory. The initialization value is the initial capacity.
    size_t m_capacity = page_size;

    [[noreturn, gnu::cold]] static void handle_out_of_memory() noexcept { std::terminate(); }

    void allocate_capacity() noexcept
    {
        m_data.reset(static_cast<uint8_t*>(std::realloc(m_data.release(), m_capacity)));
        if (!m_data) [[unlikely]]
            handle_out_of_memory();
    }

public:
    /// Creates Memory object with initial capacity allocation.
    Memory() noexcept { allocate_capacity(); }

    uint8_t& operator[](size_t index) noexcept { return m_data[index]; }

    [[nodiscard]] const uint8_t* data() const noexcept { return m_data.get(); }
    [[nodiscard]] size_t size() const noexcept { return m_size; }

    /// Grows the memory to the given size. The extent is filled with zeros.
    ///
    /// @param new_size  New memory size. Must be larger than the current size and multiple of 32.
    void grow(size_t new_size) noexcept
    {
        // Restriction for future changes. EVM always has memory size as multiple of 32 bytes.
        INTX_REQUIRE(new_size % 32 == 0);

        // Allow only growing memory. Include hint for optimizing compiler.
        INTX_REQUIRE(new_size > m_size);

        if (new_size > m_capacity)
        {
            m_capacity *= 2;  // Double the capacity.

            if (m_capacity < new_size)  // If not enough.
            {
                // Set capacity to required size rounded to multiple of page_size.
                m_capacity = ((new_size + (page_size - 1)) / page_size) * page_size;
            }

            allocate_capacity();
        }
        std::memset(&m_data[m_size], 0, new_size - m_size);
        m_size = new_size;
    }

    /// Virtually clears the memory by setting its size to 0. The capacity stays unchanged.
    void clear() noexcept { m_size = 0; }
};

template <bool isSymbolic>
class SymbolicState
{
public:
    using SymbolicRequirements = std::vector<SymbolicRequirement>;
    using SymbolicRequirementsPtr = std::shared_ptr<SymbolicRequirements>;
    using SymbolicStorageMapPtr = std::shared_ptr<SymbolicStorageMap>;

    SymbolicRequirementsPtr requirements = nullptr;
    SymbolicStorageMapPtr modified_stores = nullptr;
    SymbolicStoragePtr store = nullptr;
    SymbolicMemoryPtr memory = nullptr;
    SymbolicStoragePtr tstore = nullptr;
    SymbolicStackItemPtr caller;
    SymbolicStackItemPtr callvalue;
    SymbolicMemoryPtr calldata = nullptr;
    SymbolicMemoryPtr returndata = nullptr;
    ArenaAllocator* arena = nullptr;

    void symbolic_value_matches_concrete(const StackItem<isSymbolic>& i, std::convertible_to<const StackItem<isSymbolic>&> auto... is)
    {
        if constexpr ( sizeof...( is ) > 0 )
            symbolic_value_matches_concrete( is... );
        else
            assert (requirements != nullptr);

        if (!std::holds_alternative<Pure>(*i.sval))
            requirements->push_back(Equal{i.sval, i.val});
    }

    inline void set_requirements(bool reset)
    {
        if(!requirements) requirements = std::make_shared<std::vector<SymbolicRequirement>>();
        if(reset) requirements->clear();
    }

    inline void set_modified_stores(bool reset)
    {
        if(!modified_stores) modified_stores = std::make_shared<SymbolicStorageMap>(SymbolicStorageMap(MapComparator {}));
        if(reset) modified_stores->clear();
    }

    inline void set_calldata(SymbolicStackItemPtr offset, SymbolicStackItemPtr size)
    {
        calldata = arena->make<SymbolicMemory>(Offset {offset, size}, memory);
    }

    inline void set_returndata() {
        returndata = nullptr;
    }

    inline void set_returndata(size_t offset, size_t size, SymbolicMemoryPtr m)
    {
        returndata = arena->make<SymbolicMemory>(SetMem {offset, size, m}, nullptr);
    }

    inline void set_returndata(size_t s, const void* ptr)
    {
        auto mem_copy = std::make_unique<uint8_t[]>(s);
        std::memcpy(mem_copy.get(), ptr, s);
        returndata = arena->make<SymbolicMemory>(SymbolicMemory {SetMem {0, s, std::move(mem_copy)}, nullptr});
    }

    inline void update_memory(size_t index, size_t size, SymbolicMemoryPtr m)
    {
        memory = arena->make<SymbolicMemory>(SetMem{index, size, m}, memory);
    }

    inline void update_memory(size_t dst, size_t s, const void* ptr)
    {
        auto mem_copy = std::make_unique<uint8_t[]>(s);
        std::memcpy(mem_copy.get(), ptr, s);
        memory = arena->make<SymbolicMemory>(SetMem{dst, s, std::move(mem_copy)}, memory);
    }

    // equivalent to std::memset(&state.memory[index], 0, size);
    inline void update_memory(size_t index, size_t size)
    {
        memory = arena->make<SymbolicMemory>(SetMem{index, size, {}}, memory);
    }

    // equivalent to std::memcpy(&state.memory[dst], &m[src], size);
    inline void update_memory(size_t dst, SymbolicStackItemPtr src, size_t size, SymbolicMemoryPtr m)
    {
        auto ssize = StackItem<true>::make_symbolic(*arena, Pure {size});
        auto soffset = arena->make<SymbolicMemory>(Offset {src, ssize}, m);
        memory = arena->make<SymbolicMemory>(SetMem{dst, size, soffset}, memory);
    }

    inline void update_memory(SymbolicStackItemPtr k, SymbolicStackItemPtr v)
    {
        memory = arena->make<SymbolicMemory>(SetItem{k,v}, memory);
    }

    inline void reset_memory() noexcept
    {
        memory = nullptr;
    }

    inline void update_tstore(SymbolicStackItemPtr k, SymbolicStackItemPtr v)
    {
        tstore = arena->make<SymbolicStorage>(SetItem{k,v}, tstore);
    }

    inline void reset_tstore() noexcept
    {
        tstore = nullptr;
    }

    // set up the symbolic store by looking up any previous symbolic state at the recipient address,
    // in case we are in a nested context
    inline void set_store(evmc_address init)
    {
        if (auto search = modified_stores->find(init); search != modified_stores->end())
        {
            store = search->second;
        }
        else 
            store = arena->make<SymbolicStorage>(init, nullptr);
    }

    inline void update_store(SymbolicStackItemPtr k, SymbolicStackItemPtr v)
    {
        store = arena->make<SymbolicStorage>(SetItem{k,v}, store);
    }
};

/// Generic execution state for generic instructions implementations.
// NOLINTNEXTLINE(clang-analyzer-optin.performance.Padding)
template <bool isSymbolic>
class ExecutionState
{
public:
    int64_t gas_refund = 0;
    Memory memory;
    const evmc_message* msg = nullptr;
    evmc::HostContext host;
    evmc_revision rev = {};
    bytes return_data;

    /// Reference to original EVM code container.
    /// For legacy code this is a reference to entire original code.
    /// For EOF-formatted code this is a reference to entire container.
    bytes_view original_code;

    evmc_status_code status = EVMC_SUCCESS;
    size_t output_offset = 0;
    size_t output_size = 0;

    /// Container to be deployed returned from RETURNCONTRACT, used only inside EOFCREATE execution.
    std::optional<bytes> deploy_container;

    /// Symbolic storage
    ExecutionState<isSymbolic>* child = nullptr;
    SymbolicState<isSymbolic> symbolic;
    ArenaAllocator* arena = nullptr;
private:
    evmc_tx_context m_tx = {};

public:
    /// Pointer to code analysis.
    /// This should be set and used internally by execute() function of a particular interpreter.
    union
    {
        const baseline::CodeAnalysis* baseline = nullptr;
        const advanced::AdvancedCodeAnalysis* advanced;
    } analysis{};

    std::vector<const uint8_t*> call_stack;

    /// Stack space allocation.
    ///
    /// This is the last field to make other fields' offsets of reasonable values.
    StackSpace<isSymbolic> stack_space;

    ExecutionState() noexcept = default;

    ExecutionState(const evmc_message& message, evmc_revision revision,
        const evmc_host_interface& host_interface, evmc_host_context* host_ctx,
        bytes_view _code) noexcept
      : msg{&message}, host{host_interface, host_ctx}, rev{revision}, original_code{_code}
    {
        if constexpr (isSymbolic)
            assert(arena != nullptr);
    }

    /// Resets the contents of the ExecutionState so that it could be reused.
    void reset(const evmc_message& message, evmc_revision revision,
        const evmc_host_interface& host_interface, evmc_host_context* host_ctx,
        bytes_view _code) noexcept
    {
        gas_refund = 0;
        memory.clear();
        msg = &message;
        host = {host_interface, host_ctx};
        rev = revision;
        return_data.clear();
        original_code = _code;
        status = EVMC_SUCCESS;
        output_offset = 0;
        output_size = 0;
        deploy_container = {};
        m_tx = {};
        call_stack = {};
    }

    [[nodiscard]] bool in_static_mode() const { return (msg->flags & EVMC_STATIC) != 0; }

    const evmc_tx_context& get_tx_context() noexcept
    {
        if (INTX_UNLIKELY(m_tx.block_timestamp == 0))
            m_tx = host.get_tx_context();
        return m_tx;
    }
};
}  // namespace evmone
