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



class SymbolicMemoryLocation
{
private:
    // symbolic = nullptr means the memory location has a concrete value stored in concrete_or_offset
    // otherwise concrete_or_offset an ofset of 0 to 31 bytes into the symbolic value
    rc_ptr_data<SymbolicStackItem>* symbolic;
    uint8_t concrete_or_offset;
public:
    inline bool is_conrete()
    {
        return symbolic == nullptr;
    }

    SymbolicMemoryLocation &operator=(uint8_t v)
    {
        if(symbolic != nullptr) rc_ptr<SymbolicStackItem>::release(symbolic);
        symbolic = nullptr;
        concrete_or_offset = v;
        return *this;
    }

    SymbolicMemoryLocation &operator=(Slice8&& o)
    {
        if(symbolic != nullptr) rc_ptr<SymbolicStackItem>::release(symbolic);
        if(o.symbolic.raw() != nullptr)
        {
            assert(o.concrete_or_offset < 32);
            assert(!StackItem<true>::is_pure(o.symbolic));
            concrete_or_offset = o.concrete_or_offset;
            symbolic = o.symbolic.raw();
            ++symbolic->rc;
        }
        else
        {
            concrete_or_offset = o.concrete_or_offset;
            symbolic = nullptr;
        }
        return *this;
    }

    uint8_t get_concrete()
    {
        assert(is_conrete());
        return concrete_or_offset;
    }

    Slice8 get_symbolic()
    {
        if(symbolic != nullptr) ++symbolic->rc;
        return {rc_ptr(symbolic), concrete_or_offset};
    }
};


struct FreeDeleter
{
    void operator()(SymbolicMemoryLocation* p) const noexcept { std::free(p); }
};


using SymbolicMemoryPtr = std::unique_ptr<SymbolicMemoryLocation[], FreeDeleter>;


class SymbolicMemory
{
    /// The size of allocation "page".
    static constexpr size_t page_size = 4 * 1024;

    /// Owned pointer to allocated memory.
    SymbolicMemoryPtr m_data;

    /// The "virtual" size of the memory.
    size_t m_size = 0;

    /// The size of allocated memory. The initialization value is the initial capacity.
    size_t m_capacity = page_size;

    [[noreturn, gnu::cold]] static void handle_out_of_memory() noexcept { std::terminate(); }

    void allocate_capacity() noexcept
    {
        m_data.reset(static_cast<SymbolicMemoryLocation*>(std::realloc(m_data.release(), sizeof(SymbolicMemoryLocation) * m_capacity)));
        if (!m_data) [[unlikely]]
            handle_out_of_memory();
    }

public:
    /// Creates Memory object with initial capacity allocation.
    SymbolicMemory() noexcept { allocate_capacity(); }

    SymbolicMemoryLocation& operator[](size_t index) noexcept { return m_data[index]; }

    [[nodiscard]] const SymbolicMemoryLocation* data() const noexcept { return m_data.get(); }
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
        for (size_t i = m_size; i < new_size - m_size; i++)
        {
            m_data[i] = 0;
        }
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
    SymbolicMemory memory;
    SymbolicStoragePtr tstore = nullptr;
    SymbolicStackItemPtr caller;
    SymbolicStackItemPtr callvalue;
    // SymbolicMemoryPtr calldata = nullptr;
    SymbolicMemoryPtr calldata2 = nullptr;
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
        if(!modified_stores) modified_stores = std::make_shared<SymbolicStorageMap>(SymbolicStorageMap(MapComparatorEvmcAddress {}));
        if(reset) modified_stores->clear();
    }

    inline void set_calldata(size_t offset, size_t size)
    {
        calldata2.reset(static_cast<SymbolicMemoryLocation*>(std::realloc(calldata2.release(), sizeof(SymbolicMemoryLocation) * size)));
        std::memcpy(calldata2.get(), &memory[offset], sizeof(SymbolicMemoryLocation) * size);
    }

    inline SymbolicStackItemPtr load_calldata(size_t begin, size_t end)
    {
        assert((end - begin) <= 32);
        uint8_t pure_data[32] = {};
        Slice&& symbolic {};
        bool all_pure = true;
        bool is_full_symbolic_word = (end - begin) == 32;
        rc_ptr_data<SymbolicStackItem>* symbolic_ptr = nullptr;

        for (size_t i = 0; i < (end - begin); ++i)
        {
            if(calldata2[begin + i].is_conrete()){
                pure_data[i] = calldata2[begin + i].get_concrete();
                symbolic.word[i] = calldata2[begin + i].get_symbolic();
                is_full_symbolic_word = false;
            }
            else
            {
                all_pure = false;
                symbolic.word[i] = calldata2[begin + i].get_symbolic();
                if(symbolic_ptr == nullptr) symbolic_ptr = symbolic.word[i].symbolic.raw();
                is_full_symbolic_word = 
                    is_full_symbolic_word && 
                    symbolic.word[i].symbolic.raw() == symbolic_ptr && 
                    symbolic.word[i].concrete_or_offset == i;
            }
        }
        if(all_pure)
        {
            auto loaded = intx::be::load<uint256>(pure_data);
            return StackItem<true>::make_symbolic(*arena, Pure{loaded});
        }
        else if(is_full_symbolic_word) return symbolic.word[0].symbolic;
        else return StackItem<true>::make_symbolic(*arena, symbolic);
    }

    inline void set_returndata() {
        returndata = nullptr;
    }

    inline void set_returndata(size_t offset, size_t size, const SymbolicMemoryLocation* m)
    {
        returndata.reset(static_cast<SymbolicMemoryLocation*>(std::realloc(returndata.release(), sizeof(SymbolicMemoryLocation) * size)));
        std::memcpy(returndata.get(), &m[offset], sizeof(SymbolicMemoryLocation) * size);
    }

    inline void update_memory(size_t dst, size_t src, size_t size, SymbolicMemoryPtr& m)
    {
        std::memcpy(&memory[dst], &m[src], sizeof(SymbolicMemoryLocation) * size);
    }


    inline void update_memory(size_t dst, size_t s, const void* ptr)
    {
        for (size_t i = 0; i < s; i++)
        {
            memory[dst+i] = ((uint8_t*)ptr)[i];
        }
    }

    inline void reset_memory(size_t index, size_t size)
    {
        for (size_t i = index; i < size; i++)
        {
            memory[i] = 0;
        }
    }

    inline void reset_memory() noexcept
    {
        memory.clear();
    }

    inline SymbolicStackItemPtr load_memory(size_t begin)
    {
        uint8_t pure_data[32] = {};
        Slice&& symbolic {};
        bool all_pure = true;
        bool is_full_symbolic_word = true;
        rc_ptr_data<SymbolicStackItem>* symbolic_ptr = nullptr;

        for (size_t i = 0; i < 32; ++i)
        {
            if(memory[begin + i].is_conrete()){
                pure_data[i] = memory[begin + i].get_concrete();
                symbolic.word[i] = memory[begin + i].get_symbolic();
                is_full_symbolic_word = false;
            }
            else
            {
                all_pure = false;
                symbolic.word[i] = memory[begin + i].get_symbolic();
                if(symbolic_ptr == nullptr) symbolic_ptr = symbolic.word[i].symbolic.raw();
                is_full_symbolic_word = 
                    is_full_symbolic_word && 
                    symbolic.word[i].symbolic.raw() == symbolic_ptr && 
                    symbolic.word[i].concrete_or_offset == i;
            }
        }
        if(all_pure)
        {
            auto loaded = intx::be::load<uint256>(pure_data);
            return StackItem<true>::make_symbolic(*arena, Pure{loaded});
        }
        else if(is_full_symbolic_word) return symbolic.word[0].symbolic;
        else return StackItem<true>::make_symbolic(*arena, symbolic);
    }

    inline void update_tstore(evmc_bytes32 k, SymbolicStackItemPtr v)
    {
        (*tstore)[k] = v;
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
            store = new SymbolicStorage(MapComparatorEvmcBytes32 {});
    }

    inline void update_store(evmc_bytes32 k, SymbolicStackItemPtr v)
    {
        (*store)[k] = v;
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
        symbolic.reset_memory();
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
