// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "memory.hpp"
#include "symbolic_state.hpp"
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

    void reset()
    {
        if constexpr (isSymbolic)
        {
            for (size_t i = 0; i < limit; i++)
            {
                StackItem<isSymbolic>* ptr = &static_cast<StackItem<isSymbolic>*>(m_stack_space.get())[i];
                ptr->sval.drop();
                ptr->val = 0;
            }
            
        }
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

    ExecutionState(SymbolicState<isSymbolic>&& s) noexcept : symbolic{std::move(s)} {
        if constexpr (isSymbolic) arena = &s.arena;
    }

    ExecutionState(const evmc_message& message, evmc_revision revision,
        const evmc_host_interface& host_interface, evmc_host_context* host_ctx,
        bytes_view _code, SymbolicState<isSymbolic>&& s) noexcept
      : msg{&message}, host{host_interface, host_ctx}, rev{revision}, original_code{_code}, symbolic{std::move(s)}
    {
        if constexpr (isSymbolic) arena = &s.arena;
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
        if constexpr (isSymbolic) symbolic.memory.clear();
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
