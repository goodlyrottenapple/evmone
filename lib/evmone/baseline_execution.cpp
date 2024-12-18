// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "baseline.hpp"
#include "baseline_instruction_table.hpp"
#include "eof.hpp"
#include "execution_state.hpp"
#include "instructions.hpp"
#include "symbolic.hpp"
#include "vm.hpp"
#include <memory>
#include <iostream>

#ifdef NDEBUG
#define release_inline gnu::always_inline, msvc::forceinline
#else
#define release_inline
#endif

#if defined(__GNUC__)
#define ASM_COMMENT(COMMENT) asm("# " #COMMENT)  // NOLINT(hicpp-no-assembler)
#else
#define ASM_COMMENT(COMMENT)
#endif

namespace evmone::baseline
{
namespace
{
/// Checks instruction requirements before execution.
///
/// This checks:
/// - if the instruction is defined
/// - if stack height requirements are fulfilled (stack overflow, stack underflow)
/// - charges the instruction base gas cost and checks is there is any gas left.
///
/// @tparam         Op            Instruction opcode.
/// @param          cost_table    Table of base gas costs.
/// @param [in,out] gas_left      Gas left.
/// @param          stack_top     Pointer to the stack top item.
/// @param          stack_bottom  Pointer to the stack bottom.
///                               The stack height is stack_top - stack_bottom.
/// @return  Status code with information which check has failed
///          or EVMC_SUCCESS if everything is fine.
template <bool isSymbolic, Opcode Op>
inline evmc_status_code check_requirements(const CostTable& cost_table, int64_t& gas_left,
    const StackItem<isSymbolic>* stack_top, const StackItem<isSymbolic>* stack_bottom) noexcept
{
    static_assert(
        !instr::has_const_gas_cost(Op) || instr::gas_costs[EVMC_FRONTIER][Op] != instr::undefined,
        "undefined instructions must not be handled by check_requirements()");

    auto gas_cost = instr::gas_costs[EVMC_FRONTIER][Op];  // Init assuming const cost.
    if constexpr (!instr::has_const_gas_cost(Op))
    {
        gas_cost = cost_table[Op];  // If not, load the cost from the table.

        // Negative cost marks an undefined instruction.
        // This check must be first to produce correct error code.
        if (INTX_UNLIKELY(gas_cost < 0))
            return EVMC_UNDEFINED_INSTRUCTION;
    }

    // Check stack requirements first. This is order is not required,
    // but it is nicer because complete gas check may need to inspect operands.
    if constexpr (instr::traits[Op].stack_height_change > 0)
    {
        static_assert(instr::traits[Op].stack_height_change == 1,
            "unexpected instruction with multiple results");
        if (INTX_UNLIKELY(stack_top == stack_bottom + StackSpace<isSymbolic>::limit))
            return EVMC_STACK_OVERFLOW;
    }
    if constexpr (instr::traits[Op].stack_height_required > 0)
    {
        // Check stack underflow using pointer comparison <= (better optimization).
        static constexpr auto min_offset = instr::traits[Op].stack_height_required - 1;
        if (INTX_UNLIKELY(stack_top <= stack_bottom + min_offset))
            return EVMC_STACK_UNDERFLOW;
    }

    if (INTX_UNLIKELY((gas_left -= gas_cost) < 0))
        return EVMC_OUT_OF_GAS;

    return EVMC_SUCCESS;
}


/// The execution position.
template <bool isSymbolic>
struct Position
{
    code_iterator code_it;  ///< The position in the code.
    StackItem<isSymbolic>* stack_top;     ///< The pointer to the stack top.
};

/// Helpers for invoking instruction implementations of different signatures.
/// @{
template <bool isSymbolic>
[[release_inline]] inline code_iterator invoke(void (*instr_fn)(StackTop<isSymbolic>) noexcept, Position<isSymbolic> pos,
    int64_t& /*gas*/, ExecutionState<isSymbolic>& state) noexcept
{
    instr_fn(StackTop(pos.stack_top, state.arena));
    return pos.code_it + 1;
}

template <bool isSymbolic>
[[release_inline]] inline code_iterator invoke(
    Result (*instr_fn)(StackTop<isSymbolic>, int64_t, ExecutionState<isSymbolic>&) noexcept, Position<isSymbolic> pos, int64_t& gas,
    ExecutionState<isSymbolic>& state) noexcept
{
    const auto o = instr_fn(StackTop(pos.stack_top, state.arena), gas, state);
    gas = o.gas_left;
    if (o.status != EVMC_SUCCESS)
    {
        state.status = o.status;
        return nullptr;
    }
    return pos.code_it + 1;
}

template <bool isSymbolic>
[[release_inline]] inline code_iterator invoke(void (*instr_fn)(StackTop<isSymbolic>, ExecutionState<isSymbolic>&) noexcept,
    Position<isSymbolic> pos, int64_t& /*gas*/, ExecutionState<isSymbolic>& state) noexcept
{
    instr_fn(StackTop(pos.stack_top, state.arena), state);
    return pos.code_it + 1;
}

template <bool isSymbolic>
[[release_inline]] inline code_iterator invoke(
    code_iterator (*instr_fn)(StackTop<isSymbolic>, ExecutionState<isSymbolic>&, code_iterator) noexcept, Position<isSymbolic> pos,
    int64_t& /*gas*/, ExecutionState<isSymbolic>& state) noexcept
{
    return instr_fn(StackTop(pos.stack_top, state.arena), state, pos.code_it);
}

template <bool isSymbolic>
[[release_inline]] inline code_iterator invoke(
    code_iterator (*instr_fn)(StackTop<isSymbolic>, code_iterator) noexcept, Position<isSymbolic> pos, int64_t& /*gas*/,
    ExecutionState<isSymbolic>& state) noexcept
{
    return instr_fn(StackTop(pos.stack_top, state.arena), pos.code_it);
}

template <bool isSymbolic>
[[release_inline]] inline code_iterator invoke(
    TermResult (*instr_fn)(StackTop<isSymbolic>, int64_t, ExecutionState<isSymbolic>&) noexcept, Position<isSymbolic> pos, int64_t& gas,
    ExecutionState<isSymbolic>& state) noexcept
{
    const auto result = instr_fn(StackTop(pos.stack_top, state.arena), gas, state);
    gas = result.gas_left;
    state.status = result.status;
    return nullptr;
}

template <bool isSymbolic>
[[release_inline]] inline code_iterator invoke(
    Result (*instr_fn)(StackTop<isSymbolic>, int64_t, ExecutionState<isSymbolic>&, code_iterator&) noexcept, Position<isSymbolic> pos,
    int64_t& gas, ExecutionState<isSymbolic>& state) noexcept
{
    const auto result = instr_fn(StackTop(pos.stack_top, state.arena), gas, state, pos.code_it);
    gas = result.gas_left;
    if (result.status != EVMC_SUCCESS)
    {
        state.status = result.status;
        return nullptr;
    }
    return pos.code_it;
}

template <bool isSymbolic>
[[release_inline]] inline code_iterator invoke(
    TermResult (*instr_fn)(StackTop<isSymbolic>, int64_t, ExecutionState<isSymbolic>&, code_iterator) noexcept,
    Position<isSymbolic> pos, int64_t& gas, ExecutionState<isSymbolic>& state) noexcept
{
    const auto result = instr_fn(StackTop(pos.stack_top, state.arena), gas, state, pos.code_it);
    gas = result.gas_left;
    state.status = result.status;
    return nullptr;
}

/// A helper to invoke the instruction implementation of the given opcode Op.
template <bool isSymbolic, Opcode Op>
[[release_inline]] inline Position<isSymbolic> invoke(const CostTable& cost_table, const StackItem<isSymbolic>* stack_bottom,
    Position<isSymbolic> pos, int64_t& gas, ExecutionState<isSymbolic>& state) noexcept
{
    if (const auto status = check_requirements<isSymbolic,Op>(cost_table, gas, pos.stack_top, stack_bottom);
        status != EVMC_SUCCESS)
    {
        state.status = status;
        return {nullptr, pos.stack_top};
    }
    const auto new_pos = invoke(instr::core::impl<isSymbolic,Op>, pos, gas, state);
    const auto new_stack_top = pos.stack_top + instr::traits[Op].stack_height_change;
    return {new_pos, new_stack_top};
}


template <bool isSymbolic, bool TracingEnabled>
int64_t dispatch(const CostTable& cost_table, ExecutionState<isSymbolic>& state, int64_t gas,
    const uint8_t* code, Tracer<isSymbolic>* tracer = nullptr) noexcept
{
    const auto stack_bottom = state.stack_space.bottom();

    // Code iterator and stack top pointer for interpreter loop.
    Position<isSymbolic> position{code, stack_bottom};

    while (true)  // Guaranteed to terminate because padded code ends with STOP.
    {
        if constexpr (TracingEnabled)
        {
            const auto offset = static_cast<uint32_t>(position.code_it - code);
            const auto stack_height = static_cast<int>(position.stack_top - stack_bottom);
            if (offset < state.original_code.size())  // Skip STOP from code padding.
            {
                tracer->notify_instruction_start(
                    offset, position.stack_top, stack_height, gas, state);
            }
        }

        const auto op = *position.code_it;
        switch (op)
        {
#define ON_OPCODE(OPCODE)                                                                     \
    case OPCODE:                                                                              \
        ASM_COMMENT(OPCODE);                                                                  \
        if (const auto next = invoke<isSymbolic, OPCODE>(cost_table, stack_bottom, position, gas, state); \
            next.code_it == nullptr)                                                          \
        {                                                                                     \
            return gas;                                                                       \
        }                                                                                     \
        else                                                                                  \
        {                                                                                     \
            /* Update current position only when no error,                                    \
               this improves compiler optimization. */                                        \
            position = next;                                                                  \
        }                                                                                     \
        break;

            MAP_OPCODES
#undef ON_OPCODE

        default:
            state.status = EVMC_UNDEFINED_INSTRUCTION;
            return gas;
        }
    }
    intx::unreachable();
}

#if EVMONE_CGOTO_SUPPORTED
template <bool isSymbolic>
int64_t dispatch_cgoto(
    const CostTable& cost_table, ExecutionState<isSymbolic>& state, int64_t gas, const uint8_t* code) noexcept
{
#pragma GCC diagnostic ignored "-Wpedantic"

    static constexpr void* cgoto_table[] = {
#define ON_OPCODE(OPCODE) &&TARGET_##OPCODE,
#undef ON_OPCODE_UNDEFINED
#define ON_OPCODE_UNDEFINED(_) &&TARGET_OP_UNDEFINED,
        MAP_OPCODES
#undef ON_OPCODE
#undef ON_OPCODE_UNDEFINED
#define ON_OPCODE_UNDEFINED ON_OPCODE_UNDEFINED_DEFAULT
    };
    static_assert(std::size(cgoto_table) == 256);

    const auto stack_bottom = state.stack_space.bottom();

    // Code iterator and stack top pointer for interpreter loop.
    Position<isSymbolic> position{code, stack_bottom};

    goto* cgoto_table[*position.code_it];

#define ON_OPCODE(OPCODE)                                                                 \
    TARGET_##OPCODE : ASM_COMMENT(OPCODE);                                                \
    if (const auto next = invoke<isSymbolic, OPCODE>(cost_table, stack_bottom, position, gas, state); \
        next.code_it == nullptr)                                                          \
    {                                                                                     \
        return gas;                                                                       \
    }                                                                                     \
    else                                                                                  \
    {                                                                                     \
        /* Update current position only when no error,                                    \
           this improves compiler optimization. */                                        \
        position = next;                                                                  \
    }                                                                                     \
    goto* cgoto_table[*position.code_it];

    MAP_OPCODES
#undef ON_OPCODE

TARGET_OP_UNDEFINED:
    state.status = EVMC_UNDEFINED_INSTRUCTION;
    return gas;
}
#endif
}  // namespace

template <bool isSymbolic>
evmc_result execute(VM<isSymbolic>& vm, const evmc_host_interface& host, evmc_host_context* ctx,
    evmc_revision rev, const evmc_message& msg, const CodeAnalysis& analysis) noexcept
{
    const auto code = analysis.executable_code();
    auto gas = msg.gas;

    auto& state = vm.get_execution_state(static_cast<size_t>(msg.depth));
    state.reset(msg, rev, host, ctx, analysis.raw_code());
    size_t checkpoint;

    if constexpr (isSymbolic){

        // only reset the symbolic calldata and returndata state if this is a 0 depth call.
        // for CALL opcodes, the symbolic calldata and returndata state of the child should be set up by the calling function.
        if(msg.depth == 0)
        {
            state.symbolic.journaled.reset();
            state.symbolic.requirements.clear();

            SymbolicState<true>::reset_symbolic_memory_ptr(state.symbolic.calldata.get(), state.symbolic.calldata_size);
            state.symbolic.calldata_size = state.msg->input_size;
            // TODO could this be leaking if calldata was set before??
            state.symbolic.calldata.reset(static_cast<SymbolicMemoryLocation*>(std::realloc(state.symbolic.calldata.release(), sizeof(SymbolicMemoryLocation) * state.symbolic.calldata_size)));
            for (size_t i = 0; i < state.msg->input_size; i++)
            {
                state.symbolic.calldata[i].zero(true);
                state.symbolic.calldata[i] = state.msg->input_data[i];
            }

            SymbolicState<true>::reset_symbolic_memory_ptr(state.symbolic.returndata.get(), state.symbolic.returndata_size);
            state.symbolic.returndata_size = 0;
            state.symbolic.returndata = nullptr;
        }

        if (msg.depth < 1024)
        {
            auto& state_child = vm.get_execution_state(static_cast<size_t>(msg.depth + 1));
            state.child = &state_child;
            assert(state.child != nullptr);
            state.child->symbolic.calldata_size = 0;
            state.child->symbolic.calldata = nullptr;
        }

        state.symbolic.journaled.init_address(msg.recipient);
        checkpoint = state.symbolic.journaled.checkpoint();
    }

    state.analysis.baseline = &analysis;  // Assign code analysis for instruction implementations.

    const auto& cost_table = get_baseline_cost_table(state.rev, analysis.eof_header().version);

    auto* tracer = vm.get_tracer();
    if (INTX_UNLIKELY(tracer != nullptr))
    {
        tracer->notify_execution_start(state.rev, *state.msg, code);
        gas = dispatch<isSymbolic, true>(cost_table, state, gas, code.data(), tracer);
    }
    else
    {
#if EVMONE_CGOTO_SUPPORTED
        if (vm.cgoto)
            gas = dispatch_cgoto<isSymbolic>(cost_table, state, gas, code.data());
        else
#endif
            gas = dispatch<isSymbolic, false>(cost_table, state, gas, code.data());
    }

    const auto gas_left = (state.status == EVMC_SUCCESS || state.status == EVMC_REVERT) ? gas : 0;
    const auto gas_refund = (state.status == EVMC_SUCCESS) ? state.gas_refund : 0;

    assert(state.output_size != 0 || state.output_offset == 0);
    const auto result =
        (state.deploy_container.has_value() ?
                evmc::make_result(state.status, gas_left, gas_refund,
                    state.deploy_container->data(), state.deploy_container->size()) :
                evmc::make_result(state.status, gas_left, gas_refund,
                    state.output_size != 0 ? &state.memory[state.output_offset] : nullptr,
                    state.output_size));

    if (INTX_UNLIKELY(tracer != nullptr))
        tracer->notify_execution_end(result);

    if constexpr (isSymbolic) {
        if(state.status != EVMC_SUCCESS) {
            state.symbolic.journaled.rollback(checkpoint);
        }
    }
    return result;
}

template <bool isSymbolic>
evmc_result execute(evmc_vm* c_vm, const evmc_host_interface* host, evmc_host_context* ctx,
    evmc_revision rev, const evmc_message* msg, const uint8_t* code, size_t code_size) noexcept
{
    auto vm = static_cast<VM<isSymbolic>*>(c_vm);
    const bytes_view container{code, code_size};
    const auto eof_enabled = rev >= instr::REV_EOF1;

    // Since EOF validation recurses into subcontainers, it only makes sense to do for top level
    // message calls. The condition for `msg->kind` inside differentiates between creation tx code
    // (initcode) and already deployed code (runtime).
    if (vm->validate_eof && eof_enabled && is_eof_container(container) && msg->depth == 0)
    {
        const auto container_kind =
            (msg->kind == EVMC_EOFCREATE ? ContainerKind::initcode : ContainerKind::runtime);
        if (validate_eof(rev, container_kind, container) != EOFValidationError::success)
            return evmc_make_result(EVMC_CONTRACT_VALIDATION_FAILURE, 0, 0, nullptr, 0);
    }

    const auto code_analysis = analyze(container, eof_enabled);
    return execute<isSymbolic>(*vm, *host, ctx, rev, *msg, code_analysis);
}


template evmc_result execute<true>(evmc_vm* c_vm, const evmc_host_interface* host, evmc_host_context* ctx,
    evmc_revision rev, const evmc_message* msg, const uint8_t* code, size_t code_size) noexcept;

template evmc_result execute<false>(evmc_vm* c_vm, const evmc_host_interface* host, evmc_host_context* ctx,
    evmc_revision rev, const evmc_message* msg, const uint8_t* code, size_t code_size) noexcept;

}  // namespace evmone::baseline
