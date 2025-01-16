// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "eof.hpp"
#include "instructions.hpp"

constexpr int64_t MIN_RETAINED_GAS = 5000;
constexpr int64_t MIN_CALLEE_GAS = 2300;
constexpr int64_t CALL_VALUE_COST = 9000;
constexpr int64_t ACCOUNT_CREATION_COST = 25000;

constexpr auto EXTCALL_SUCCESS = 0;
constexpr auto EXTCALL_REVERT = 1;
constexpr auto EXTCALL_ABORT = 2;

namespace evmone::instr::core
{
/// Converts an opcode to matching EVMC call kind.
consteval evmc_call_kind to_call_kind(Opcode op) noexcept
{
    switch (op)
    {
    case OP_CALL:
    case OP_EXTCALL:
    case OP_STATICCALL:
    case OP_EXTSTATICCALL:
        return EVMC_CALL;
    case OP_CALLCODE:
        return EVMC_CALLCODE;
    case OP_DELEGATECALL:
    case OP_EXTDELEGATECALL:
        return EVMC_DELEGATECALL;
    case OP_CREATE:
        return EVMC_CREATE;
    case OP_CREATE2:
        return EVMC_CREATE2;
    case OP_EOFCREATE:
        return EVMC_EOFCREATE;
    default:
        intx::unreachable();
    }
}

template <bool isSymbolic, bool isSymbolicEnabled, Opcode Op>
Result call_impl(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state) noexcept
{
    static_assert(
        Op == OP_CALL || Op == OP_CALLCODE || Op == OP_DELEGATECALL || Op == OP_STATICCALL);

    const auto gas = stack.popStackItem();
    const auto dstStackItem = stack.popStackItem(); 
    const auto dst = intx::be::trunc<evmc::address>(dstStackItem.val);
    const auto mvalue = (Op == OP_STATICCALL || Op == OP_DELEGATECALL) ? std::nullopt : std::optional<StackItem<isSymbolic>>(stack.popStackItem());
    const auto has_non_zero_value = mvalue.has_value() && mvalue.value().val != 0;
    const auto input_offset_u256 = stack.popStackItem();
    const auto input_size_u256 = stack.popStackItem();
    const auto output_offset_u256 = stack.popStackItem();
    const auto output_size_u256 = stack.popStackItem();
    static constexpr evmc::address precompile_address_boundary{0x13};
    bool calling_precompile = dst <= precompile_address_boundary;

    const auto input_offset = static_cast<size_t>(input_offset_u256.val);
    const auto input_size = static_cast<size_t>(input_size_u256.val);

    if constexpr (isSymbolic && isSymbolicEnabled) {
        state.symbolic.symbolic_value_matches_concrete(gas, dstStackItem, input_offset_u256, input_size_u256, output_offset_u256, output_size_u256);
        if (mvalue.has_value()) state.symbolic.symbolic_value_matches_concrete(mvalue.value());

        // if we are calling a precompile, the call is opaque and we cannot perform any analysis on data that is dependend on storage access
        if(calling_precompile)
        {
            const auto current_memory_size = state.memory.size();
            const auto input_end = std::min(current_memory_size, input_offset+input_size);
            if(input_offset <= input_end && !state.symbolic.memory.is_concrete(input_offset, input_end - input_offset))
            {
                bool current_all_concrete = true;
                uint8_t concrete_data[32];
                memset(concrete_data, 0, sizeof(concrete_data));
                Slice symbolic_data;
                for (size_t i = 0; i < 32; i++)
                {
                    symbolic_data.word[i] = Slice8 {SymbolicStackItemPtr(), 0};
                }

                size_t i = 0;
                while (i+input_offset < input_end) 
                {
                    auto current_index = i % 32;
                    concrete_data[current_index] = state.memory[i+input_offset];
                    if (auto it = state.symbolic.memory.find(i+input_offset); it != state.symbolic.memory.end())
                    {
                        current_all_concrete = false;
                        symbolic_data.word[current_index] = it->second;
                    }
                    else
                        symbolic_data.word[current_index] = {nullptr, state.memory[i+input_offset]};

                    i++;
                    if(i%32 == 0 || i+input_offset+1 == input_end)
                    {
                        if(!current_all_concrete)
                            state.symbolic.requirements.push_back(
                                SymbolicRequirement{
                                    Req::equal,
                                    StackItem<isSymbolic>::make_symbolic(*stack.arena, symbolic_data),
                                    intx::be::unsafe::load<uint256>(concrete_data)
                                });
                        current_all_concrete = true;
                        memset(concrete_data, 0, sizeof(concrete_data));
                        for (size_t j = 0; j < 32; j++)
                        {
                            symbolic_data.word[j] = Slice8 {SymbolicStackItemPtr(), 0};
                        }
                    }
                }
            }
        }
        
    }

    stack.push(0);  // Assume failure.
    state.return_data.clear();
    if constexpr (isSymbolic && isSymbolicEnabled) state.symbolic.returndata.clear();

    if (state.rev >= EVMC_BERLIN && state.host.access_account(dst) == EVMC_ACCESS_COLD)
    {
        if ((gas_left -= instr::additional_cold_account_access_cost) < 0)
            return {EVMC_OUT_OF_GAS, gas_left};
    }

    if (!check_memory<isSymbolic, isSymbolicEnabled>(gas_left, state.memory, state.symbolic.memory, input_offset_u256.val, input_size_u256.val))
        return {EVMC_OUT_OF_GAS, gas_left};

    if (!check_memory<isSymbolic, isSymbolicEnabled>(gas_left, state.memory, state.symbolic.memory, output_offset_u256.val, output_size_u256.val))
        return {EVMC_OUT_OF_GAS, gas_left};

    const auto output_offset = static_cast<size_t>(output_offset_u256.val);
    const auto output_size = static_cast<size_t>(output_size_u256.val);

    evmc_message msg{.kind = to_call_kind(Op)};
    msg.flags = (Op == OP_STATICCALL) ? uint32_t{EVMC_STATIC} : state.msg->flags;
    msg.depth = state.msg->depth + 1;
    msg.recipient = (Op == OP_CALL || Op == OP_STATICCALL) ? dst : state.msg->recipient;
    msg.code_address = dst;
    msg.sender = (Op == OP_DELEGATECALL) ? state.msg->sender : state.msg->recipient;
    msg.value =
        (Op == OP_DELEGATECALL) ? state.msg->value : (has_non_zero_value ? intx::be::store<evmc::uint256be>(mvalue.value().val) : evmc_bytes32 {});
    if constexpr (isSymbolic && isSymbolicEnabled)
        // if this check fails, we have reached the maximum stack depth of 1024, so this call will probably fail
        if (state.child != nullptr)
            state.child->symbolic.callvalue = 
                (Op == OP_DELEGATECALL) ? state.symbolic.callvalue : (has_non_zero_value ? mvalue.value().sval : SymbolicStackItemPtr());

    if (input_size > 0)
    {
        // input_offset may be garbage if input_size == 0.
        msg.input_data = &state.memory[input_offset];
        msg.input_size = input_size;
    }
    if constexpr (isSymbolic && isSymbolicEnabled) 
        if (state.child != nullptr)
            state.child->symbolic.calldata.set(View{input_offset, input_size, state.symbolic.memory}, &state.memory[input_offset]);

    auto cost = has_non_zero_value ? CALL_VALUE_COST : 0;

    if constexpr (Op == OP_CALL)
    {
        if (has_non_zero_value && state.in_static_mode())
            return {EVMC_STATIC_MODE_VIOLATION, gas_left};

        if ((has_non_zero_value || state.rev < EVMC_SPURIOUS_DRAGON) && !state.host.account_exists(dst))
            cost += ACCOUNT_CREATION_COST;
    }

    if ((gas_left -= cost) < 0)
        return {EVMC_OUT_OF_GAS, gas_left};

    msg.gas = std::numeric_limits<int64_t>::max();
    if (gas.val < msg.gas)
        msg.gas = static_cast<int64_t>(gas.val);

    if (state.rev >= EVMC_TANGERINE_WHISTLE)  // TODO: Always true for STATICCALL.
        msg.gas = std::min(msg.gas, gas_left - gas_left / 64);
    else if (msg.gas > gas_left)
        return {EVMC_OUT_OF_GAS, gas_left};

    if (has_non_zero_value)
    {
        msg.gas += 2300;  // Add stipend.
        gas_left += 2300;
    }

    if (state.msg->depth >= 1024)
        return {EVMC_SUCCESS, gas_left};  // "Light" failure.

    if (has_non_zero_value && intx::be::load<uint256>(state.host.get_balance(state.msg->recipient)) < mvalue.value().val)
        return {EVMC_SUCCESS, gas_left};  // "Light" failure.

    const auto result = state.host.call(msg);
    state.return_data.assign(result.output_data, result.output_size);

    if constexpr (isSymbolic && isSymbolicEnabled)
    {
        if(calling_precompile)
        {
            state.symbolic.returndata.set_concrete(result.output_size);
        }
        else 
        {
            if (state.child && state.child->output_size != 0)
            {
                assert(state.child->output_size == result.output_size);
                state.symbolic.returndata.set(View {state.child->output_offset, state.child->output_size, static_cast<BaseSymbolicMemory&>(state.child->symbolic.memory)});
            }
            else
                state.symbolic.returndata.clear();
        }
    }
    stack.top() = result.status_code == EVMC_SUCCESS;

    if (const auto copy_size = std::min(output_size, result.output_size); copy_size > 0)
    {
        std::memcpy(&state.memory[output_offset], result.output_data, copy_size);
        if constexpr (isSymbolic && isSymbolicEnabled)
        {
            if(calling_precompile)
                state.symbolic.memory.set_concrete(output_offset, copy_size);
            else
                state.symbolic.memory.set(output_offset, View {0, copy_size, static_cast<BaseSymbolicMemory&>(state.child->symbolic.memory)});
        }
    }
    const auto gas_used = msg.gas - result.gas_left;
    gas_left -= gas_used;
    state.gas_refund += result.gas_refund;

    return {EVMC_SUCCESS, gas_left};
}

template Result call_impl<true, true, OP_CALL>(
    StackTop<true> stack, int64_t gas_left, ExecutionState<true>& state) noexcept;
template Result call_impl<true, true, OP_STATICCALL>(
    StackTop<true> stack, int64_t gas_left, ExecutionState<true>& state) noexcept;
template Result call_impl<true, true, OP_DELEGATECALL>(
    StackTop<true> stack, int64_t gas_left, ExecutionState<true>& state) noexcept;
template Result call_impl<true, true, OP_CALLCODE>(
    StackTop<true> stack, int64_t gas_left, ExecutionState<true>& state) noexcept;

template Result call_impl<true, false, OP_CALL>(
    StackTop<true> stack, int64_t gas_left, ExecutionState<true>& state) noexcept;
template Result call_impl<true, false, OP_STATICCALL>(
    StackTop<true> stack, int64_t gas_left, ExecutionState<true>& state) noexcept;
template Result call_impl<true, false, OP_DELEGATECALL>(
    StackTop<true> stack, int64_t gas_left, ExecutionState<true>& state) noexcept;
template Result call_impl<true, false, OP_CALLCODE>(
    StackTop<true> stack, int64_t gas_left, ExecutionState<true>& state) noexcept;


template Result call_impl<false, false, OP_CALL>(
    StackTop<false> stack, int64_t gas_left, ExecutionState<false>& state) noexcept;
template Result call_impl<false, false, OP_STATICCALL>(
    StackTop<false> stack, int64_t gas_left, ExecutionState<false>& state) noexcept;
template Result call_impl<false, false, OP_DELEGATECALL>(
    StackTop<false> stack, int64_t gas_left, ExecutionState<false>& state) noexcept;
template Result call_impl<false, false, OP_CALLCODE>(
    StackTop<false> stack, int64_t gas_left, ExecutionState<false>& state) noexcept;



template <bool isSymbolic, bool isSymbolicEnabled, Opcode Op>
Result extcall_impl(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state) noexcept
{
    static_assert(Op == OP_EXTCALL || Op == OP_EXTDELEGATECALL || Op == OP_EXTSTATICCALL);

    const auto dst_u256 = stack.pop();
    const auto input_offset_u256 = stack.pop();
    const auto input_size_u256 = stack.pop();
    const auto value = (Op == OP_EXTSTATICCALL || Op == OP_EXTDELEGATECALL) ? 0 : stack.pop();
    const auto has_value = value != 0;

    stack.push(EXTCALL_ABORT);  // Assume (hard) failure.
    state.return_data.clear();

    // Address space expansion ready check.
    static constexpr auto ADDRESS_MAX = (uint256{1} << 160) - 1;
    if (dst_u256 > ADDRESS_MAX)
        return {EVMC_ARGUMENT_OUT_OF_RANGE, gas_left};

    const auto dst = intx::be::trunc<evmc::address>(dst_u256);

    if (state.host.access_account(dst) == EVMC_ACCESS_COLD)
    {
        if ((gas_left -= instr::additional_cold_account_access_cost) < 0)
            return {EVMC_OUT_OF_GAS, gas_left};
    }

    if (!check_memory<isSymbolic, isSymbolicEnabled>(gas_left, state.memory, state.symbolic.memory, input_offset_u256, input_size_u256))
        return {EVMC_OUT_OF_GAS, gas_left};

    const auto input_offset = static_cast<size_t>(input_offset_u256);
    const auto input_size = static_cast<size_t>(input_size_u256);

    evmc_message msg{.kind = to_call_kind(Op)};
    msg.flags = (Op == OP_EXTSTATICCALL) ? uint32_t{EVMC_STATIC} : state.msg->flags;
    msg.depth = state.msg->depth + 1;
    msg.recipient = (Op != OP_EXTDELEGATECALL) ? dst : state.msg->recipient;
    msg.code_address = dst;
    msg.sender = (Op == OP_EXTDELEGATECALL) ? state.msg->sender : state.msg->recipient;
    msg.value =
        (Op == OP_EXTDELEGATECALL) ? state.msg->value : intx::be::store<evmc::uint256be>(value);

    if (input_size > 0)
    {
        // input_offset may be garbage if input_size == 0.
        msg.input_data = &state.memory[input_offset];
        msg.input_size = input_size;
    }

    auto cost = has_value ? CALL_VALUE_COST : 0;

    if constexpr (Op == OP_EXTCALL)
    {
        if (has_value && state.in_static_mode())
            return {EVMC_STATIC_MODE_VIOLATION, gas_left};

        if (has_value && !state.host.account_exists(dst))
            cost += ACCOUNT_CREATION_COST;
    }

    if ((gas_left -= cost) < 0)
        return {EVMC_OUT_OF_GAS, gas_left};

    msg.gas = gas_left - std::max(gas_left / 64, MIN_RETAINED_GAS);

    if (msg.gas < MIN_CALLEE_GAS || state.msg->depth >= 1024 ||
        (has_value &&
            intx::be::load<uint256>(state.host.get_balance(state.msg->recipient)) < value))
    {
        stack.top() = EXTCALL_REVERT;
        return {EVMC_SUCCESS, gas_left};  // "Light" failure.
    }

    if constexpr (Op == OP_EXTDELEGATECALL)
    {
        // The code targeted by EXTDELEGATECALL must also be an EOF.
        // This restriction has been added to EIP-3540 in
        // https://github.com/ethereum/EIPs/pull/7131
        uint8_t target_code_prefix[2];
        const auto s = state.host.copy_code(
            msg.code_address, 0, target_code_prefix, std::size(target_code_prefix));
        if (!is_eof_container({target_code_prefix, s}))
        {
            stack.top() = EXTCALL_REVERT;
            return {EVMC_SUCCESS, gas_left};  // "Light" failure.
        }
    }

    const auto result = state.host.call(msg);
    state.return_data.assign(result.output_data, result.output_size);
    if (result.status_code == EVMC_SUCCESS)
        stack.top() = EXTCALL_SUCCESS;
    else if (result.status_code == EVMC_REVERT)
        stack.top() = EXTCALL_REVERT;
    else
        stack.top() = EXTCALL_ABORT;

    const auto gas_used = msg.gas - result.gas_left;
    gas_left -= gas_used;
    state.gas_refund += result.gas_refund;
    return {EVMC_SUCCESS, gas_left};
}

template Result extcall_impl<true, true, OP_EXTCALL>(
    StackTop<true> stack, int64_t gas_left, ExecutionState<true>& state) noexcept;
template Result extcall_impl<true, true, OP_EXTSTATICCALL>(
    StackTop<true> stack, int64_t gas_left, ExecutionState<true>& state) noexcept;
template Result extcall_impl<true, true, OP_EXTDELEGATECALL>(
    StackTop<true> stack, int64_t gas_left, ExecutionState<true>& state) noexcept;

template Result extcall_impl<true, false, OP_EXTCALL>(
    StackTop<true> stack, int64_t gas_left, ExecutionState<true>& state) noexcept;
template Result extcall_impl<true, false, OP_EXTSTATICCALL>(
    StackTop<true> stack, int64_t gas_left, ExecutionState<true>& state) noexcept;
template Result extcall_impl<true, false, OP_EXTDELEGATECALL>(
    StackTop<true> stack, int64_t gas_left, ExecutionState<true>& state) noexcept;

template Result extcall_impl<false, false, OP_EXTCALL>(
    StackTop<false> stack, int64_t gas_left, ExecutionState<false>& state) noexcept;
template Result extcall_impl<false, false, OP_EXTSTATICCALL>(
    StackTop<false> stack, int64_t gas_left, ExecutionState<false>& state) noexcept;
template Result extcall_impl<false, false, OP_EXTDELEGATECALL>(
    StackTop<false> stack, int64_t gas_left, ExecutionState<false>& state) noexcept;

template <bool isSymbolic, bool isSymbolicEnabled, Opcode Op>
Result create_impl(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state) noexcept
{
    static_assert(Op == OP_CREATE || Op == OP_CREATE2);

    if (state.in_static_mode())
        return {EVMC_STATIC_MODE_VIOLATION, gas_left};

    const auto endowment = stack.popStackItem();
    const auto init_code_offset_u256 = stack.popStackItem();
    const auto init_code_size_u256 = stack.popStackItem();
    const auto msalt = (Op == OP_CREATE2) ? std::optional<StackItem<isSymbolic>>(stack.popStackItem()) : std::nullopt;
    const auto has_salt = msalt.has_value();
    if constexpr (isSymbolic && isSymbolicEnabled) {
        state.symbolic.symbolic_value_matches_concrete(endowment, init_code_offset_u256, init_code_size_u256);
        if (has_salt) state.symbolic.symbolic_value_matches_concrete(msalt.value());
    }

    stack.push(0);  // Assume failure.
    state.return_data.clear();

    if (!check_memory<isSymbolic, isSymbolicEnabled>(gas_left, state.memory, state.symbolic.memory, init_code_offset_u256.val, init_code_size_u256.val))
        return {EVMC_OUT_OF_GAS, gas_left};

    const auto init_code_offset = static_cast<size_t>(init_code_offset_u256.val);
    const auto init_code_size = static_cast<size_t>(init_code_size_u256.val);

    if (state.rev >= EVMC_SHANGHAI && init_code_size > 0xC000)
        return {EVMC_OUT_OF_GAS, gas_left};

    const auto init_code_word_cost = 6 * (Op == OP_CREATE2) + 2 * (state.rev >= EVMC_SHANGHAI);
    const auto init_code_cost = num_words(init_code_size) * init_code_word_cost;
    if ((gas_left -= init_code_cost) < 0)
        return {EVMC_OUT_OF_GAS, gas_left};

    if (state.msg->depth >= 1024)
        return {EVMC_SUCCESS, gas_left};  // "Light" failure.

    if (endowment.val != 0 &&
        intx::be::load<uint256>(state.host.get_balance(state.msg->recipient)) < endowment.val)
        return {EVMC_SUCCESS, gas_left};  // "Light" failure.

    evmc_message msg{.kind = to_call_kind(Op)};
    msg.gas = gas_left;
    if (state.rev >= EVMC_TANGERINE_WHISTLE)
        msg.gas = msg.gas - msg.gas / 64;

    if (init_code_size > 0)
    {
        // init_code_offset may be garbage if init_code_size == 0.
        msg.input_data = &state.memory[init_code_offset];
        msg.input_size = init_code_size;
        if (state.rev >= EVMC_PRAGUE)
        {
            // EOF initcode is not allowed for legacy creation
            if (is_eof_container({msg.input_data, msg.input_size}))
                return {EVMC_SUCCESS, gas_left};  // "Light" failure.
        }
    }
    if constexpr (isSymbolic && isSymbolicEnabled) 
        if (state.child != nullptr)
            // internally, the host strips the input_size and input_data from this message
            // and passes them via the code and code_size in
            // evmc_result execute(evmc_vm* c_vm, const evmc_host_interface* host, ... const uint8_t* code, size_t code_size)
            // feels VERY hacky
            state.child->symbolic.calldata.clear();
    msg.sender = state.msg->recipient;
    msg.depth = state.msg->depth + 1;
    msg.create2_salt = intx::be::store<evmc::bytes32>(has_salt ? msalt.value().val : uint256{});
    msg.value = intx::be::store<evmc::uint256be>(endowment.val);

    const auto result = state.host.call(msg);
    gas_left -= msg.gas - result.gas_left;
    state.gas_refund += result.gas_refund;

    state.return_data.assign(result.output_data, result.output_size);


    if constexpr (isSymbolic && isSymbolicEnabled)
    {
        if (state.child && state.child->output_size != 0)
            state.symbolic.returndata.set(View{state.child->output_offset, state.child->output_size, static_cast<BaseSymbolicMemory&>(state.child->symbolic.memory)});
        else
            state.symbolic.returndata.clear();
    }


    if (result.status_code == EVMC_SUCCESS)
    {
        stack[0].val = intx::be::load<uint256>(result.create_address);
        if constexpr (isSymbolic && isSymbolicEnabled) stack[0].set_pure();
    }

    return {EVMC_SUCCESS, gas_left};
}

template <bool isSymbolic, bool isSymbolicEnabled>
Result eofcreate(
    StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state, code_iterator& pos) noexcept
{
    if (state.in_static_mode())
        return {EVMC_STATIC_MODE_VIOLATION, gas_left};

    const auto endowment = stack.pop();
    const auto salt = stack.pop();
    const auto input_offset_u256 = stack.pop();
    const auto input_size_u256 = stack.pop();

    stack.push(0);  // Assume failure.
    state.return_data.clear();

    if (!check_memory<isSymbolic, isSymbolicEnabled>(gas_left, state.memory, state.symbolic.memory, input_offset_u256, input_size_u256))
        return {EVMC_OUT_OF_GAS, gas_left};

    const auto initcontainer_index = pos[1];
    pos += 2;
    const auto& container = state.original_code;
    const auto& eof_header = state.analysis.baseline->eof_header();
    const auto initcontainer = eof_header.get_container(container, initcontainer_index);

    // Charge for initcode hashing.
    constexpr auto initcode_word_cost_hashing = 6;
    const auto initcode_cost_hashing = num_words(initcontainer.size()) * initcode_word_cost_hashing;
    if ((gas_left -= initcode_cost_hashing) < 0)
        return {EVMC_OUT_OF_GAS, gas_left};

    const auto input_offset = static_cast<size_t>(input_offset_u256);
    const auto input_size = static_cast<size_t>(input_size_u256);

    if (state.msg->depth >= 1024)
        return {EVMC_SUCCESS, gas_left};  // "Light" failure.

    if (endowment != 0 &&
        intx::be::load<uint256>(state.host.get_balance(state.msg->recipient)) < endowment)
        return {EVMC_SUCCESS, gas_left};  // "Light" failure.

    evmc_message msg{.kind = EVMC_EOFCREATE};
    msg.gas = gas_left - gas_left / 64;
    if (input_size > 0)
    {
        // input_data may be garbage if init_code_size == 0.
        msg.input_data = &state.memory[input_offset];
        msg.input_size = input_size;
    }

    msg.sender = state.msg->recipient;
    msg.depth = state.msg->depth + 1;
    msg.create2_salt = intx::be::store<evmc::bytes32>(salt);
    msg.value = intx::be::store<evmc::uint256be>(endowment);
    // init_code is guaranteed to be non-empty by validation of container sections
    msg.code = initcontainer.data();
    msg.code_size = initcontainer.size();

    const auto result = state.host.call(msg);
    gas_left -= msg.gas - result.gas_left;
    state.gas_refund += result.gas_refund;

    state.return_data.assign(result.output_data, result.output_size);
    if (result.status_code == EVMC_SUCCESS)
        stack.top() = intx::be::load<uint256>(result.create_address);

    return {EVMC_SUCCESS, gas_left};
}

template Result eofcreate<true, true>(
    StackTop<true> stack, int64_t gas_left, ExecutionState<true>& state, code_iterator& pos) noexcept;
template Result eofcreate<true, false>(
    StackTop<true> stack, int64_t gas_left, ExecutionState<true>& state, code_iterator& pos) noexcept;
template Result eofcreate<false, false>(
    StackTop<false> stack, int64_t gas_left, ExecutionState<false>& state, code_iterator& pos) noexcept;

template Result create_impl<true, true, OP_CREATE>(
    StackTop<true> stack, int64_t gas_left, ExecutionState<true>& state) noexcept;
template Result create_impl<true, true, OP_CREATE2>(
    StackTop<true> stack, int64_t gas_left, ExecutionState<true>& state) noexcept;

template Result create_impl<true, false, OP_CREATE>(
    StackTop<true> stack, int64_t gas_left, ExecutionState<true>& state) noexcept;
template Result create_impl<true, false, OP_CREATE2>(
    StackTop<true> stack, int64_t gas_left, ExecutionState<true>& state) noexcept;

template Result create_impl<false, false, OP_CREATE>(
    StackTop<false> stack, int64_t gas_left, ExecutionState<false>& state) noexcept;
template Result create_impl<false, false, OP_CREATE2>(
    StackTop<false> stack, int64_t gas_left, ExecutionState<false>& state) noexcept;
}  // namespace evmone::instr::core
