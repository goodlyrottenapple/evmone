// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2018 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

/// @file
/// EVMC instance (class VM) and entry point of evmone is defined here.

#include "vm.hpp"
#include "advanced_execution.hpp"
#include "baseline.hpp"
#include <evmone/evmone.h>
#include <cassert>
#include <iostream>

namespace evmone
{
namespace
{
template <bool isSymbolic>
void destroy(evmc_vm* vm) noexcept
{
    assert(vm != nullptr);
    delete static_cast<VM<isSymbolic>*>(vm);
}

constexpr evmc_capabilities_flagset get_capabilities(evmc_vm* /*vm*/) noexcept
{
    return EVMC_CAPABILITY_EVM1;
}

evmc_set_option_result set_option(evmc_vm* c_vm, char const* c_name, char const* c_value) noexcept
{
    const auto name = (c_name != nullptr) ? std::string_view{c_name} : std::string_view{};
    const auto value = (c_value != nullptr) ? std::string_view{c_value} : std::string_view{};
    auto& vm = *static_cast<VM<false>*>(c_vm);

    if (name == "advanced")
    {
        c_vm->execute = evmone::advanced::execute;
        return EVMC_SET_OPTION_SUCCESS;
    }
    else if (name == "cgoto")
    {
#if EVMONE_CGOTO_SUPPORTED
        if (value == "no")
        {
            vm.cgoto = false;
            return EVMC_SET_OPTION_SUCCESS;
        }
        return EVMC_SET_OPTION_INVALID_VALUE;
#else
        return EVMC_SET_OPTION_INVALID_NAME;
#endif
    }
    else if (name == "trace")
    {
        vm.add_tracer(create_instruction_tracer(std::clog));
        return EVMC_SET_OPTION_SUCCESS;
    }
    else if (name == "histogram")
    {
        vm.add_tracer(create_histogram_tracer(std::clog));
        return EVMC_SET_OPTION_SUCCESS;
    }
    else if (name == "validate_eof")
    {
        vm.validate_eof = true;
        return EVMC_SET_OPTION_SUCCESS;
    }
    return EVMC_SET_OPTION_INVALID_NAME;
}

evmc_set_option_result set_option_symbolic(evmc_vm*, char const*, char const*) noexcept
{
    return EVMC_SET_OPTION_INVALID_NAME;
}


}  // namespace

template <>
VM<false>::VM() noexcept
  : evmc_vm{
        EVMC_ABI_VERSION,
        "evmone",
        PROJECT_VERSION,
        evmone::destroy<false>,
        evmone::baseline::execute<false>,
        evmone::get_capabilities,
        evmone::set_option,
    }
{
    m_execution_states.reserve(1025);
}

template <>
VM<true>::VM() noexcept
  : evmc_vm{
        EVMC_ABI_VERSION,
        "evmone_symbolic",
        PROJECT_VERSION,
        evmone::destroy<true>,
        evmone::baseline::execute<true>,
        evmone::get_capabilities,
        evmone::set_option_symbolic,
    }
{
    m_execution_states.reserve(1025);
}

template <bool isSymbolic>
EVMC_EXPORT ExecutionState<isSymbolic>& VM<isSymbolic>::get_execution_state(size_t depth) noexcept
{
    // Vector already has the capacity for all possible depths,
    // so reallocation never happens (therefore: noexcept).
    // The ExecutionStates are lazily created because they pre-allocate EVM memory and stack.
    assert(depth < m_execution_states.capacity());
    if (m_execution_states.size() <= depth)
    {
        if constexpr (isSymbolic)
            for (size_t i = m_execution_states.size(); i < depth+1; i++)
            {
                m_execution_states.emplace_back(SymbolicState<true>(arena, requirements, stores, tstores));
            }
        else
            m_execution_states.resize(depth + 1);
    }
    return m_execution_states[depth];
}

template ExecutionState<true>& VM<true>::get_execution_state(size_t depth) noexcept;
template ExecutionState<false>& VM<false>::get_execution_state(size_t depth) noexcept;

template <>
EVMC_EXPORT bool VM<true>::compute_symbolic(std::function<evmc_bytes32(const evmc_address&, const evmc_bytes32&)> get_storage, std::function<void(const evmc_address&, const evmc_bytes32&, evmc_bytes32)> set_storage) 
{
    std::vector<std::variant<SymbolicStackItemPtr, SymbolicRequirement>> stack;
    bool something_to_eval = requirements.size() > 0;

    for (auto &mod_store : stores)
    {
        auto& store = mod_store.second;
        assert(store);
        for (auto& it : *store)
        {
            if(StackItem<true>::is_symbolic(it.second))
            {
                stack.push_back(it.second);
                something_to_eval = true;
            }
        }
    }

    if(something_to_eval)
    {
        for (auto& r : requirements) stack.push_back(r);
        auto valid = eval(get_storage, stack);
        if (!valid) return false;
    }

    for (auto &mod_store : stores)
    {
        auto& addr = mod_store.first;
        auto& store = mod_store.second;
        for (auto& it : *store)
            set_storage(addr, it.first, intx::be::store<evmc::bytes32>(std::get<uint256>(*it.second)));
    }
    return true;
}
}  // namespace evmone

extern "C" {
EVMC_EXPORT evmc_vm* evmc_create_evmone() noexcept
{
    return new evmone::VM<false>{};
}

EVMC_EXPORT evmc_vm* evmc_create_evmone_symbolic() noexcept
{
    return new evmone::VM<true>{};
}
}
