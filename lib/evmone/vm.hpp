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
    std::vector<SymbolicRequirement> requirements;
    JournaledSymbolicState journaled = JournaledSymbolicState(arena);
    size_t current_states_size = 0;

public:
    VM() noexcept;

    [[nodiscard]] ExecutionState<isSymbolic>& get_execution_state(size_t depth) noexcept;

    void reset()
    {
        if constexpr (isSymbolic)
        {
            auto& state = get_execution_state(0);
            state.symbolic.journaled.reset();
            state.symbolic.requirements.clear();
            for (size_t i = 0; i < current_states_size; i++)
            {
                auto& s = get_execution_state(i);
                s.symbolic.memory.clear();
                s.symbolic.caller.drop();
                s.symbolic.callvalue.drop();
                s.symbolic.set_calldata();
                s.symbolic.set_returndata();
                s.status = EVMC_SUCCESS;
                s.stack_space.reset();
            }
            arena.reset();
        }
        current_states_size = 0;
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

    [[nodiscard]] bool compute_symbolic(std::function<evmc_bytes32(const evmc_address&, const evmc_bytes32&)>, std::function<void(const evmc_address&, const evmc_bytes32&, evmc_bytes32)>);
};

}  // namespace evmone
