// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "execution_state.hpp"
#include "tracing.hpp"
#include <evmc/evmc.h>
#include <vector>

#if defined(_MSC_VER) && !defined(__clang__)
#define EVMONE_CGOTO_SUPPORTED 0
#else
#define EVMONE_CGOTO_SUPPORTED 1
#endif

namespace evmone
{
/// The evmone EVMC instance.
template <bool isSymbolic>
class VM : public evmc_vm
{
public:
    bool cgoto = EVMONE_CGOTO_SUPPORTED;
    bool validate_eof = false;

private:
    std::vector<ExecutionState<isSymbolic>> m_execution_states;
    std::unique_ptr<Tracer<isSymbolic>> m_first_tracer;
    ArenaAllocator arena;

public:
    VM() noexcept;

    [[nodiscard]] ExecutionState<isSymbolic>& get_execution_state(size_t depth) noexcept
    {

        // Vector already has the capacity for all possible depths,
        // so reallocation never happens (therefore: noexcept).
        // The ExecutionStates are lazily created because they pre-allocate EVM memory and stack.
        assert(depth < m_execution_states.capacity());
        if (m_execution_states.size() <= depth)
            m_execution_states.resize(depth + 1);
        return m_execution_states[depth];

    }

    void add_tracer(std::unique_ptr<Tracer<isSymbolic>> tracer) noexcept
    {
        // Find the first empty unique_ptr and assign the new tracer to it.
        auto* end = &m_first_tracer;
        while (*end)
            end = &(*end)->m_next_tracer;
        *end = std::move(tracer);
    }

    ArenaAllocator* get_arena()
    {
        return &arena;
    }

    [[nodiscard]] Tracer<isSymbolic>* get_tracer() const noexcept { return m_first_tracer.get(); }

    [[nodiscard]] void compute_symbolic(std::function<evmc_bytes32(evmc_bytes32&)> get_storage)
    {
        auto& symbolic = get_execution_state(0).symbolic;
        std::vector<std::variant<SymbolicStackItemPtr, SymbolicRequirement>> stack;
        for (auto& r : *symbolic.requirements) stack.push_back(r);

        eval(get_storage, stack);
    }
};

}  // namespace evmone
