// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "baseline.hpp"
#include "eof.hpp"
#include "execution_state.hpp"
#include "instructions_traits.hpp"
#include "instructions_xmacro.hpp"
#include "symbolic.hpp"
#include <ethash/keccak.hpp>
#include <variant>

namespace evmone
{
using code_iterator = const uint8_t*;

/// Represents the pointer to the stack top item
/// and allows retrieving stack items and manipulating the pointer.
template <bool isSymbolic>
class StackTop
{
    StackItem<isSymbolic>* m_top;

public:
    ArenaAllocator* arena;
    StackTop(StackItem<isSymbolic>* top, ArenaAllocator* a) noexcept : m_top{top}, arena{a} {
        if constexpr (isSymbolic) assert(arena != nullptr);
    }

    /// Returns the reference to the stack item by index, where 0 means the top item
    /// and positive index values the items further down the stack.
    /// Using [-1] is also valid, but .push() should be used instead.
    [[nodiscard]] StackItem<isSymbolic>& operator[](int index) noexcept { return m_top[-index]; }

    StackTop& operator=(StackItem<isSymbolic>* i) { m_top = i; return *this; }

    /// Returns the reference to the stack top item.
    [[nodiscard]] uint256& top() noexcept { auto& r = *m_top; return r.val; }

    /// Returns the current top item and move the stack top pointer down.
    /// The value is returned by reference because the stack slot remains valid.
    [[nodiscard]] uint256& pop() noexcept { auto& r = *m_top--; return r.val; }

    [[nodiscard]] StackItem<isSymbolic>& popStackItem() noexcept { return *m_top--; }

    /// Assigns the value to the stack top and moves the stack top pointer up.
    void push(const uint256& value) noexcept { 
        ++m_top;
        if constexpr (isSymbolic)
        {
            *m_top = {value, rc_ptr<SymbolicStackItem>()};
        }
        else 
        {
            std::memset((void*)m_top, 1, sizeof(StackItem<isSymbolic>));
            *m_top = {value};
        }    
    }
    void push(const StackItem<isSymbolic>& value) noexcept { 
        ++m_top;
        if constexpr (!isSymbolic) std::memset((void*)m_top, 2, sizeof(StackItem<isSymbolic>));
        *m_top = value; 
    }
};


/// Instruction execution result.
struct Result
{
    evmc_status_code status;
    int64_t gas_left;
};

/// Instruction result indicating that execution terminates unconditionally.
struct TermResult : Result
{};

constexpr auto max_buffer_size = std::numeric_limits<uint32_t>::max();

/// The size of the EVM 256-bit word.
constexpr auto word_size = 32;

/// Returns number of words what would fit to provided number of bytes,
/// i.e. it rounds up the number bytes to number of words.
inline constexpr int64_t num_words(uint64_t size_in_bytes) noexcept
{
    return static_cast<int64_t>((size_in_bytes + (word_size - 1)) / word_size);
}

/// Computes gas cost of copying the given amount of bytes to/from EVM memory.
inline constexpr int64_t copy_cost(uint64_t size_in_bytes) noexcept
{
    constexpr auto WordCopyCost = 3;
    return num_words(size_in_bytes) * WordCopyCost;
}

/// Grows EVM memory and checks its cost.
///
/// This function should not be inlined because this may affect other inlining decisions:
/// - making check_memory<isSymbolic>() too costly to inline,
/// - making mload()/mstore()/mstore8() too costly to inline.
///
/// TODO: This function should be moved to Memory class.
template <bool isSymbolic>
[[gnu::noinline]] inline int64_t grow_memory(
    int64_t gas_left, Memory& memory, SymbolicMemory<isSymbolic>& smemory, uint64_t new_size) noexcept
{
    // This implementation recomputes memory.size(). This value is already known to the caller
    // and can be passed as a parameter, but this make no difference to the performance.

    const auto new_words = num_words(new_size);
    const auto current_words = static_cast<int64_t>(memory.size() / word_size);
    const auto new_cost = 3 * new_words + new_words * new_words / 512;
    const auto current_cost = 3 * current_words + current_words * current_words / 512;
    const auto cost = new_cost - current_cost;

    gas_left -= cost;
    if (gas_left >= 0) [[likely]]
    {
        memory.grow(static_cast<size_t>(new_words * word_size));
        if constexpr (isSymbolic) smemory.grow(static_cast<size_t>(new_words * word_size));
    }
    return gas_left;
}

/// Check memory requirements of a reasonable size.
template <bool isSymbolic>
inline bool check_memory(
    int64_t& gas_left, Memory& memory, SymbolicMemory<isSymbolic>& smemory, const uint256& offset, uint64_t size) noexcept
{
    if constexpr (isSymbolic) assert(memory.size() == smemory.size());
    // TODO: This should be done in intx.
    // There is "branchless" variant of this using | instead of ||, but benchmarks difference
    // is within noise. This should be decided when moving the implementation to intx.
    if (((offset[3] | offset[2] | offset[1]) != 0) || (offset[0] > max_buffer_size))
        return false;

    const auto new_size = static_cast<uint64_t>(offset) + size;
    if (new_size > memory.size())
        gas_left = grow_memory<isSymbolic>(gas_left, memory, smemory, new_size);
    return gas_left >= 0;  // Always true for no-grow case.
}

/// Check memory requirements for "copy" instructions.
template <bool isSymbolic>
inline bool check_memory(
    int64_t& gas_left, Memory& memory, SymbolicMemory<isSymbolic>& smemory, const uint256& offset, const uint256& size) noexcept
{
    if (size == 0)  // Copy of size 0 is always valid (even if offset is huge).
        return true;

    // This check has 3 same word checks with the check above.
    // However, compilers do decent although not perfect job unifying common instructions.
    // TODO: This should be done in intx.
    if (((size[3] | size[2] | size[1]) != 0) || (size[0] > max_buffer_size))
        return false;

    return check_memory<isSymbolic>(gas_left, memory, smemory, offset, static_cast<uint64_t>(size));
}

namespace instr::core
{

/// The "core" instruction implementations.
///
/// These are minimal EVM instruction implementations which assume:
/// - the stack requirements (overflow, underflow) have already been checked,
/// - the "base" gas const has already been charged,
/// - the `stack` pointer points to the EVM stack top element.
/// Moreover, these implementations _do not_ inform about new stack height
/// after execution. The adjustment must be performed by the caller.
template <bool isSymbolic>
inline void noop(StackTop<isSymbolic> /*stack*/) noexcept {}
template <bool isSymbolic> inline constexpr auto pop = noop<isSymbolic>;
template <bool isSymbolic> inline constexpr auto jumpdest = noop<isSymbolic>;

template <bool isSymbolic, evmc_status_code Status>
inline TermResult stop_impl(
    StackTop<isSymbolic> /*stack*/, int64_t gas_left, ExecutionState<isSymbolic>& /*state*/) noexcept
{
    return {Status, gas_left};
}
template <bool isSymbolic> inline constexpr auto stop = stop_impl<isSymbolic,EVMC_SUCCESS>;
template <bool isSymbolic> inline constexpr auto invalid = stop_impl<isSymbolic,EVMC_INVALID_INSTRUCTION>;

template <bool isSymbolic> 
inline void add(StackTop<isSymbolic> stack) noexcept
{
    stack[1].val = stack[0].val + stack[1].val;
    if constexpr (isSymbolic)
        stack[1].set_symbolic(*stack.arena, BinOp::add, stack[0], stack[1]);
}

template <bool isSymbolic> 
inline void mul(StackTop<isSymbolic> stack) noexcept
{
    stack[1].val = stack[0].val * stack[1].val;
    if constexpr (isSymbolic)
        stack[1].set_symbolic(*stack.arena, BinOp::mul, stack[0], stack[1]);
}

template <bool isSymbolic> 
inline void sub(StackTop<isSymbolic> stack) noexcept
{
    stack[1].val = stack[0].val - stack[1].val;
    if constexpr (isSymbolic)
        stack[1].set_symbolic(*stack.arena, BinOp::sub, stack[0], stack[1]);
}

template <bool isSymbolic> 
inline void div(StackTop<isSymbolic> stack) noexcept
{
    auto& v = stack[1];
    v.val = v.val != 0 ? stack[0].val / v.val : 0;
    if constexpr (isSymbolic)
        stack[1].set_symbolic(*stack.arena, BinOp::div, stack[0], stack[1]);
}

template <bool isSymbolic> 
inline void sdiv(StackTop<isSymbolic> stack) noexcept
{
    auto& v = stack[1];
    v.val = v.val != 0 ? intx::sdivrem(stack[0].val, v.val).quot : 0;
    if constexpr (isSymbolic)
        stack[1].set_symbolic(*stack.arena, BinOp::div, stack[0], stack[1]);
}

template <bool isSymbolic> 
inline void mod(StackTop<isSymbolic> stack) noexcept
{
    auto& v = stack[1];
    v.val = v.val != 0 ? stack[0].val % v.val : 0;
    if constexpr (isSymbolic)
        stack[1].set_symbolic(*stack.arena, BinOp::mod, stack[0], stack[1]);
}

template <bool isSymbolic> 
inline void smod(StackTop<isSymbolic> stack) noexcept
{
    auto& v = stack[1];
    v.val = v.val != 0 ? intx::sdivrem(stack[0].val, v.val).rem : 0;
    if constexpr (isSymbolic) 
        stack[1].set_symbolic(*stack.arena, BinOp::smod, stack[0], stack[1]);
}

template <bool isSymbolic> 
inline void addmod(StackTop<isSymbolic> stack) noexcept
{
    const auto& x = stack[0];
    const auto& y = stack[1];
    auto& m = stack[2];
    m.val = m.val != 0 ? intx::addmod(x.val, y.val, m.val) : 0;
    if constexpr (isSymbolic)
        stack[2].set_symbolic(*stack.arena, TernOp::addmod, stack[0], stack[1], stack[2]);
}

template <bool isSymbolic> 
inline void mulmod(StackTop<isSymbolic> stack) noexcept
{
    const auto& x = stack[0];
    const auto& y = stack[1];
    auto& m = stack[2];
    m.val = m.val != 0 ? intx::mulmod(x.val, y.val, m.val) : 0;
    if constexpr (isSymbolic)
        stack[2].set_symbolic(*stack.arena, TernOp::mulmod, stack[0], stack[1], stack[2]);
}

template <bool isSymbolic> 
inline Result exp(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state) noexcept
{
    const auto& base = stack[0];
    auto& exponent = stack[1];

    const auto exponent_significant_bytes =
        static_cast<int>(intx::count_significant_bytes(exponent.val));
    const auto exponent_cost = state.rev >= EVMC_SPURIOUS_DRAGON ? 50 : 10;
    const auto additional_cost = exponent_significant_bytes * exponent_cost;
    if ((gas_left -= additional_cost) < 0)
        return {EVMC_OUT_OF_GAS, gas_left};

    exponent.val = intx::exp(base.val, exponent.val);
    if constexpr (isSymbolic) 
    {
        state.symbolic.symbolic_value_matches_concrete(exponent);
        stack[1].set_symbolic(*stack.arena, BinOp::exp, stack[0], stack[1]);
    }
    return {EVMC_SUCCESS, gas_left};
}

template <bool isSymbolic>
inline void signextend(StackTop<isSymbolic> stack) noexcept
{
    const auto& ext = stack[0];
    auto& x = stack[1];

    if (ext.val < 31)  // For 31 we also don't need to do anything.
    {
        const auto e = ext.val[0];  // uint256 -> uint64.
        const auto sign_word_index =
            static_cast<size_t>(e / sizeof(e));      // Index of the word with the sign bit.
        const auto sign_byte_index = e % sizeof(e);  // Index of the sign byte in the sign word.
        auto& sign_word = x.val[sign_word_index];

        const auto sign_byte_offset = sign_byte_index * 8;
        const auto sign_byte = sign_word >> sign_byte_offset;  // Move sign byte to position 0.

        // Sign-extend the "sign" byte and move it to the right position. Value bits are zeros.
        const auto sext_byte = static_cast<uint64_t>(int64_t{static_cast<int8_t>(sign_byte)});
        const auto sext = sext_byte << sign_byte_offset;

        const auto sign_mask = ~uint64_t{0} << sign_byte_offset;
        const auto value = sign_word & ~sign_mask;  // Reset extended bytes.
        sign_word = sext | value;                   // Combine the result word.

        // Produce bits (all zeros or ones) for extended words. This is done by SAR of
        // the sign-extended byte. Shift by any value 7-63 would work.
        const auto sign_ex = static_cast<uint64_t>(static_cast<int64_t>(sext_byte) >> 8);

        for (size_t i = 3; i > sign_word_index; --i)
            x.val[i] = sign_ex;  // Clear extended words.
    }

    if constexpr (isSymbolic)
        stack[1].set_symbolic(*stack.arena, BinOp::signextend, stack[0], stack[1]);
}

template <bool isSymbolic> 
inline void lt(StackTop<isSymbolic> stack) noexcept
{
    stack[1].val = stack[0].val < stack[1].val;
    if constexpr (isSymbolic)
        stack[1].set_symbolic(*stack.arena, BinOp::lt, stack[0], stack[1]);
}

template <bool isSymbolic> 
inline void gt(StackTop<isSymbolic> stack) noexcept
{
    stack[1].val = stack[1].val < stack[0].val; // Arguments are swapped and < is used.
    if constexpr (isSymbolic)
        stack[1].set_symbolic(*stack.arena, BinOp::gt, stack[0], stack[1]);
}

template <bool isSymbolic> 
inline void slt(StackTop<isSymbolic> stack) noexcept
{
    stack[1].val = slt(stack[0].val, stack[1].val);
    if constexpr (isSymbolic)
        stack[1].set_symbolic(*stack.arena, BinOp::slt, stack[0], stack[1]);
}

template <bool isSymbolic> 
inline void sgt(StackTop<isSymbolic> stack) noexcept
{
    stack[1].val = slt(stack[1].val, stack[0].val);  // Arguments are swapped and SLT is used.
    if constexpr (isSymbolic)
        stack[1].set_symbolic(*stack.arena, BinOp::sgt, stack[0], stack[1]);
}

template <bool isSymbolic> 
inline void eq(StackTop<isSymbolic> stack) noexcept
{
    stack[1].val = stack[0].val == stack[1].val;
    if constexpr (isSymbolic)
        stack[1].set_symbolic(*stack.arena, BinOp::eq, stack[0], stack[1]);
}

template <bool isSymbolic> 
inline void iszero(StackTop<isSymbolic> stack) noexcept
{
    stack[0].val = stack[0].val == 0;
    if constexpr (isSymbolic) 
        stack[0].set_symbolic(*stack.arena, UnOp::iszero, stack[0]); 
}

template <bool isSymbolic> 
inline void and_(StackTop<isSymbolic> stack) noexcept
{
    stack[1].val = stack[0].val & stack[1].val;
    if constexpr (isSymbolic)
        stack[1].set_symbolic(*stack.arena, BinOp::and_, stack[0], stack[1]); 
}

template <bool isSymbolic> 
inline void or_(StackTop<isSymbolic> stack) noexcept
{
    stack[1].val = stack[0].val | stack[1].val;
    if constexpr (isSymbolic)
        stack[1].set_symbolic(*stack.arena, BinOp::or_, stack[0], stack[1]); 
}

template <bool isSymbolic> 
inline void xor_(StackTop<isSymbolic> stack) noexcept
{
    stack[1].val = stack[0].val ^ stack[1].val;
    if constexpr (isSymbolic)
        stack[1].set_symbolic(*stack.arena, BinOp::xor_, stack[0], stack[1]); 
}

template <bool isSymbolic> 
inline void not_(StackTop<isSymbolic> stack) noexcept
{
    stack[0].val = ~ stack[0].val;
    if constexpr (isSymbolic)
        stack[0].set_symbolic(*stack.arena, UnOp::not_, stack[0]); 
}

template <bool isSymbolic> 
inline void byte(StackTop<isSymbolic> stack) noexcept
{
    const auto& n = stack[0];
    auto& x = stack[1];

    const bool n_valid = n.val < 32;
    const uint64_t byte_mask = (n_valid ? 0xff : 0);

    const auto index = 31 - static_cast<unsigned>(n.val[0] % 32);
    const auto word = x.val[index / 8];
    const auto byte_index = index % 8;
    const auto byte = (word >> (byte_index * 8)) & byte_mask;
    x.val = byte;
    if constexpr (isSymbolic)
        stack[1].set_symbolic(*stack.arena, BinOp::byte, stack[0], stack[1]); 
}

template <bool isSymbolic> 
inline void shl(StackTop<isSymbolic> stack) noexcept
{
    stack[1].val <<= stack[0].val;
    if constexpr (isSymbolic)
        stack[1].set_symbolic(*stack.arena, BinOp::shl, stack[0], stack[1]); 
}

template <bool isSymbolic> 
inline void shr(StackTop<isSymbolic> stack) noexcept
{
    stack[1].val >>= stack[0].val;
    if constexpr (isSymbolic)
        stack[1].set_symbolic(*stack.arena, BinOp::shr, stack[0], stack[1]); 
}

template <bool isSymbolic> 
inline void sar(StackTop<isSymbolic> stack) noexcept
{
    const auto& y = stack[0];
    auto& x = stack[1];

    const bool is_neg = static_cast<int64_t>(x.val[3]) < 0;  // Inspect the top bit (words are LE).
    const auto sign_mask = is_neg ? ~uint256{} : uint256{};

    const auto mask_shift = (y.val < 256) ? (256 - y.val[0]) : 0;
    x.val = (x.val >> y.val) | (sign_mask << mask_shift);

    if constexpr (isSymbolic)
        stack[1].set_symbolic(*stack.arena, BinOp::sar, stack[0], stack[1]); 
}

template <bool isSymbolic> 
inline Result keccak256(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state) noexcept
{
    const auto& index = stack[0];
    auto& size = stack[1];

    if constexpr (isSymbolic) state.symbolic.symbolic_value_matches_concrete(index, size);

    if (!check_memory<isSymbolic>(gas_left, state.memory, state.symbolic.memory, index.val, size.val))
        return {EVMC_OUT_OF_GAS, gas_left};

    const auto i = static_cast<size_t>(index.val);
    const auto s = static_cast<size_t>(size.val);
    const auto w = num_words(s);
    const auto cost = w * 6;
    if ((gas_left -= cost) < 0)
        return {EVMC_OUT_OF_GAS, gas_left};

    auto data = s != 0 ? &state.memory[i] : nullptr;
    size.val = intx::be::load<uint256>(ethash::keccak256(data, s));

    if constexpr (isSymbolic)
        stack[1].sval = state.symbolic.keccak256_slice(i, s);
    return {EVMC_SUCCESS, gas_left};
}


template <bool isSymbolic> 
inline void address(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state) noexcept
{
    stack.push(intx::be::load<uint256>(state.msg->recipient));
}

template <bool isSymbolic> 
inline Result balance(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state) noexcept
{
    auto& x = stack[0];
    if constexpr (isSymbolic) state.symbolic.symbolic_value_matches_concrete(x);
    const auto addr = intx::be::trunc<evmc::address>(x.val);

    if (state.rev >= EVMC_BERLIN && state.host.access_account(addr) == EVMC_ACCESS_COLD)
    {
        if ((gas_left -= instr::additional_cold_account_access_cost) < 0)
            return {EVMC_OUT_OF_GAS, gas_left};
    }

    x.val = intx::be::load<uint256>(state.host.get_balance(addr));
    // TODO do we need some constraint on gas here? probably not...
    if constexpr (isSymbolic) x.set_pure();
    return {EVMC_SUCCESS, gas_left};
}

template <bool isSymbolic> 
inline void origin(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state) noexcept
{
    stack.push(intx::be::load<uint256>(state.get_tx_context().tx_origin));
}

template <bool isSymbolic> 
inline void caller(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state) noexcept
{
    stack.push(intx::be::load<uint256>(state.msg->sender));
}

template <bool isSymbolic> 
inline void callvalue(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state) noexcept
{
    if constexpr (isSymbolic)
        // If scallvalue is unset, we are at message depth 0 and the callvalue is statically known 
        // to be the one originating from the transaction, hence we push a pure value. 
        // Otherwise, we are in a nested call where we set scallvalue to be a symbolic value, 
        // in which case we should use that
        if (state.symbolic.callvalue) stack.push({intx::be::load<uint256>(state.msg->value), state.symbolic.callvalue});
        else stack.push(intx::be::load<uint256>(state.msg->value));
    else 
        stack.push(intx::be::load<uint256>(state.msg->value)); 
}

template <bool isSymbolic> 
inline void calldataload(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state) noexcept
{
    auto& index = stack[0];

    if (state.msg->input_size < index.val) {
        index.val = 0;
        if constexpr (isSymbolic) index.set_pure();
    }
    else
    {
        const auto begin = static_cast<size_t>(index.val);
        const auto end = std::min(begin + 32, state.msg->input_size);

        uint8_t data[32] = {};
        for (size_t i = 0; i < (end - begin); ++i)
            data[i] = state.msg->input_data[begin + i];

        auto loaded = intx::be::load<uint256>(data);
        index.val = loaded;
        if constexpr (isSymbolic)
        {
            assert(state.msg->input_size == state.symbolic.calldata_size);
            index.sval = state.symbolic.load_calldata(begin, end);
        }
    }
}

template <bool isSymbolic> 
inline void calldatasize(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state) noexcept
{
    stack.push(state.msg->input_size);
}

template <bool isSymbolic> 
inline Result calldatacopy(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state) noexcept
{
    const auto& mem_index = stack[0];
    const auto& input_index = stack[1];
    const auto& size = stack[2];

    if constexpr (isSymbolic) state.symbolic.symbolic_value_matches_concrete(mem_index, input_index, size);

    if (!check_memory<isSymbolic>(gas_left, state.memory, state.symbolic.memory, mem_index.val, size.val))
        return {EVMC_OUT_OF_GAS, gas_left};

    auto dst = static_cast<size_t>(mem_index.val);
    auto src = state.msg->input_size < input_index.val ? state.msg->input_size :
                                                     static_cast<size_t>(input_index.val);
    auto s = static_cast<size_t>(size.val);
    auto copy_size = std::min(s, state.msg->input_size - src);

    if (const auto cost = copy_cost(s); (gas_left -= cost) < 0)
        return {EVMC_OUT_OF_GAS, gas_left};

    if (copy_size > 0)
    {
        std::memcpy(&state.memory[dst], &state.msg->input_data[src], copy_size);
        if constexpr (isSymbolic)
        {
            assert(state.msg->input_size == state.symbolic.calldata_size);
            state.symbolic.update_memory(dst, copy_size, &state.symbolic.calldata[src]);
        }
    }        

    if (s - copy_size > 0)
    {
        std::memset(&state.memory[dst + copy_size], 0, s - copy_size);
        if constexpr (isSymbolic) state.symbolic.reset_memory(dst + copy_size, s - copy_size);
    }
    return {EVMC_SUCCESS, gas_left};
}

template <bool isSymbolic> 
inline void codesize(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state) noexcept
{
    stack.push(state.original_code.size());
}

template <bool isSymbolic> 
inline Result codecopy(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state) noexcept
{
    const auto& mem_index = stack[0];
    const auto& input_index = stack[1];
    const auto& size = stack[2];

    if constexpr (isSymbolic) state.symbolic.symbolic_value_matches_concrete(mem_index, input_index, size);

    if (!check_memory<isSymbolic>(gas_left, state.memory, state.symbolic.memory, mem_index.val, size.val))
        return {EVMC_OUT_OF_GAS, gas_left};

    const auto code_size = state.original_code.size();
    const auto dst = static_cast<size_t>(mem_index.val);
    const auto src = code_size < input_index.val ? code_size : static_cast<size_t>(input_index.val);
    const auto s = static_cast<size_t>(size.val);
    const auto copy_size = std::min(s, code_size - src);

    if (const auto cost = copy_cost(s); (gas_left -= cost) < 0)
        return {EVMC_OUT_OF_GAS, gas_left};

    // TODO: Add unit tests for each combination of conditions.
    if (copy_size > 0)
    {
        std::memcpy(&state.memory[dst], &state.original_code[src], copy_size);

        if constexpr (isSymbolic)
            state.symbolic.update_memory(dst, copy_size, (uint8_t*)(&state.original_code[src]));
    }
    if (s - copy_size > 0)
    {
        std::memset(&state.memory[dst + copy_size], 0, s - copy_size);
        if constexpr (isSymbolic) state.symbolic.reset_memory(dst + copy_size, s - copy_size);
    }
    return {EVMC_SUCCESS, gas_left};
}


template <bool isSymbolic> 
inline void gasprice(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state) noexcept
{
    stack.push(intx::be::load<uint256>(state.get_tx_context().tx_gas_price));
}

template <bool isSymbolic> 
inline void basefee(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state) noexcept
{
    stack.push(intx::be::load<uint256>(state.get_tx_context().block_base_fee));
}

template <bool isSymbolic> 
inline void blobhash(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state) noexcept
{
    auto& index = stack[0];
    const auto& tx = state.get_tx_context();

    index.val = (index.val < tx.blob_hashes_count) ?
                intx::be::load<uint256>(tx.blob_hashes[static_cast<size_t>(index.val)]) :
                0;
    if constexpr (isSymbolic) index.set_pure();
}

template <bool isSymbolic> 
inline void blobbasefee(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state) noexcept
{
    stack.push(intx::be::load<uint256>(state.get_tx_context().blob_base_fee));
}

template <bool isSymbolic> 
inline Result extcodesize(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state) noexcept
{
    auto& x = stack[0];
    const auto addr = intx::be::trunc<evmc::address>(x.val);

    if (state.rev >= EVMC_BERLIN && state.host.access_account(addr) == EVMC_ACCESS_COLD)
    {
        if ((gas_left -= instr::additional_cold_account_access_cost) < 0)
            return {EVMC_OUT_OF_GAS, gas_left};
    }

    x.val = state.host.get_code_size(addr);
    if constexpr (isSymbolic) x.set_pure();
    return {EVMC_SUCCESS, gas_left};
}

template <bool isSymbolic> 
inline Result extcodecopy(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state) noexcept
{

    const auto& addr_index = stack[0];
    const auto addr = intx::be::trunc<evmc::address>(addr_index.val);
    const auto& mem_index = stack[1];
    const auto& input_index = stack[2];
    const auto& size = stack[3];

    if constexpr (isSymbolic) state.symbolic.symbolic_value_matches_concrete(addr_index, mem_index, input_index, size);

    if (!check_memory<isSymbolic>(gas_left, state.memory, state.symbolic.memory, mem_index.val, size.val))
        return {EVMC_OUT_OF_GAS, gas_left};

    const auto s = static_cast<size_t>(size.val);
    if (const auto cost = copy_cost(s); (gas_left -= cost) < 0)
        return {EVMC_OUT_OF_GAS, gas_left};

    if (state.rev >= EVMC_BERLIN && state.host.access_account(addr) == EVMC_ACCESS_COLD)
    {
        if ((gas_left -= instr::additional_cold_account_access_cost) < 0)
            return {EVMC_OUT_OF_GAS, gas_left};
    }

    if (s > 0)
    {
        const auto src =
            (max_buffer_size < input_index.val) ? max_buffer_size : static_cast<size_t>(input_index.val);
        const auto dst = static_cast<size_t>(mem_index.val);
        const auto num_bytes_copied = state.host.copy_code(addr, src, &state.memory[dst], s);

        if constexpr (isSymbolic)
            state.symbolic.update_memory(dst, s, &state.memory[dst]);

        if (const auto num_bytes_to_clear = s - num_bytes_copied; num_bytes_to_clear > 0)
        {
            std::memset(&state.memory[dst + num_bytes_copied], 0, num_bytes_to_clear);
            if constexpr (isSymbolic) state.symbolic.reset_memory(dst + num_bytes_copied, num_bytes_to_clear);
        }
    }
    return {EVMC_SUCCESS, gas_left};
}

template <bool isSymbolic> 
inline void returndataload(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state) noexcept
{
    auto& index = stack[0];

    if (state.return_data.size() < index.val)
        index.val = 0;
    else
    {
        const auto begin = static_cast<size_t>(index.val);
        const auto end = std::min(begin + 32, state.return_data.size());

        uint8_t data[32] = {};
        for (size_t i = 0; i < (end - begin); ++i)
            data[i] = state.return_data[begin + i];

        index.val = intx::be::unsafe::load<uint256>(data);
    }
    if constexpr (isSymbolic) index.set_pure();
}

template <bool isSymbolic> 
inline void returndatasize(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state) noexcept
{
    stack.push(state.return_data.size());
}

template <bool isSymbolic> 
inline Result returndatacopy(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state) noexcept
{
    const auto& mem_index = stack[0];
    const auto& input_index = stack[1];
    const auto& size = stack[2];

    if constexpr (isSymbolic) state.symbolic.symbolic_value_matches_concrete(mem_index, input_index, size);

    if (!check_memory<isSymbolic>(gas_left, state.memory, state.symbolic.memory, mem_index.val, size.val))
        return {EVMC_OUT_OF_GAS, gas_left};

    auto dst = static_cast<size_t>(mem_index.val);
    auto s = static_cast<size_t>(size.val);

    if (is_eof_container(state.original_code))
    {
        auto src = state.return_data.size() < input_index.val ? state.return_data.size() :
                                                            static_cast<size_t>(input_index.val);
        auto copy_size = std::min(s, state.return_data.size() - src);

        if (const auto cost = copy_cost(s); (gas_left -= cost) < 0)
            return {EVMC_OUT_OF_GAS, gas_left};

        if (copy_size > 0)
            std::memcpy(&state.memory[dst], &state.return_data[src], copy_size);

        if (s - copy_size > 0)
            std::memset(&state.memory[dst + copy_size], 0, s - copy_size);
    }
    else
    {
        if (state.return_data.size() < input_index.val)
            return {EVMC_INVALID_MEMORY_ACCESS, gas_left};
        auto src = static_cast<size_t>(input_index.val);

        if (src + s > state.return_data.size())
            return {EVMC_INVALID_MEMORY_ACCESS, gas_left};

        if (const auto cost = copy_cost(s); (gas_left -= cost) < 0)
            return {EVMC_OUT_OF_GAS, gas_left};

        if (s > 0)
        {
            std::memcpy(&state.memory[dst], &state.return_data[src], s);

            if constexpr (isSymbolic) {
                assert(state.return_data.size() == state.symbolic.returndata_size);
                state.symbolic.update_memory(dst, s, &state.symbolic.returndata[src]);
                // TODO I think we need requirements on s_return data that means we got to this point instead of failing with
                // EVMC_INVALID_MEMORY_ACCESS?
            }
        }
    }
    return {EVMC_SUCCESS, gas_left};
}

template <bool isSymbolic> 
inline Result extcodehash(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state) noexcept
{
    auto& x = stack[0];
    if constexpr (isSymbolic) state.symbolic.symbolic_value_matches_concrete(x);
    const auto addr = intx::be::trunc<evmc::address>(x.val);

    if (state.rev >= EVMC_BERLIN && state.host.access_account(addr) == EVMC_ACCESS_COLD)
    {
        if ((gas_left -= instr::additional_cold_account_access_cost) < 0)
            return {EVMC_OUT_OF_GAS, gas_left};
    }

    x.val = intx::be::load<uint256>(state.host.get_code_hash(addr));
    if constexpr (isSymbolic) x.set_pure();
    return {EVMC_SUCCESS, gas_left};
}


template <bool isSymbolic> 
inline void blockhash(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state) noexcept
{
    auto& number = stack[0];
    if constexpr (isSymbolic) state.symbolic.symbolic_value_matches_concrete(number);

    const auto upper_bound = state.get_tx_context().block_number;
    const auto lower_bound = std::max(upper_bound - 256, decltype(upper_bound){0});
    const auto n = static_cast<int64_t>(number.val);
    const auto header =
        (number.val < upper_bound && n >= lower_bound) ? state.host.get_block_hash(n) : evmc::bytes32{};

    number.val = intx::be::load<uint256>(header);
    if constexpr (isSymbolic) number.set_pure();
}

template <bool isSymbolic> 
inline void coinbase(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state) noexcept
{
    stack.push(intx::be::load<uint256>(state.get_tx_context().block_coinbase));
}

template <bool isSymbolic> 
inline void timestamp(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state) noexcept
{
    // TODO: Add tests for negative timestamp?
    stack.push(static_cast<uint64_t>(state.get_tx_context().block_timestamp));
}

template <bool isSymbolic> 
inline void number(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state) noexcept
{
    // TODO: Add tests for negative block number?
    stack.push(static_cast<uint64_t>(state.get_tx_context().block_number));
}

template <bool isSymbolic> 
inline void prevrandao(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state) noexcept
{
    stack.push(intx::be::load<uint256>(state.get_tx_context().block_prev_randao));
}

template <bool isSymbolic> 
inline void gaslimit(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state) noexcept
{
    stack.push(static_cast<uint64_t>(state.get_tx_context().block_gas_limit));
}

template <bool isSymbolic> 
inline void chainid(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state) noexcept
{
    stack.push(intx::be::load<uint256>(state.get_tx_context().chain_id));
}

template <bool isSymbolic> 
inline void selfbalance(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state) noexcept
{
    // TODO: introduce selfbalance in EVMC?
    stack.push(intx::be::load<uint256>(state.host.get_balance(state.msg->recipient)));
}

template <bool isSymbolic> 
inline Result mload(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state) noexcept
{
    auto& index = stack[0];
    if constexpr (isSymbolic) state.symbolic.symbolic_value_matches_concrete(index);

    if (!check_memory<isSymbolic>(gas_left, state.memory, state.symbolic.memory, index.val, 32))
        return {EVMC_OUT_OF_GAS, gas_left};

    auto idx = static_cast<size_t>(index.val);
    index.val = intx::be::unsafe::load<uint256>(&state.memory[idx]);
    if constexpr (isSymbolic) index.sval = state.symbolic.load_memory(idx);
    return {EVMC_SUCCESS, gas_left};
}

template <bool isSymbolic> 
inline Result mstore(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state) noexcept
{
    const auto& index = stack[0];
    const auto& value = stack[1];
    if constexpr (isSymbolic) state.symbolic.symbolic_value_matches_concrete(index);

    if (!check_memory<isSymbolic>(gas_left, state.memory, state.symbolic.memory, index.val, 32))
        return {EVMC_OUT_OF_GAS, gas_left};

    intx::be::unsafe::store(&state.memory[static_cast<size_t>(index.val)], value.val);
    if constexpr (isSymbolic)
    {
        if(value.is_pure()) {
            for (size_t i = 0; i < 32; i++)
            {
                state.symbolic.memory[static_cast<size_t>(index.val)+i] = state.memory[static_cast<size_t>(index.val)+i];
            }
        }
        else 
        {
            for (size_t i = 0; i < 32; i++)
            {
                state.symbolic.memory[static_cast<size_t>(index.val)+i] = Slice8 {value.sval, (uint8_t)i};
            }
        }
    }
    return {EVMC_SUCCESS, gas_left};
}

template <bool isSymbolic> 
inline Result mstore8(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state) noexcept
{
    const auto& index = stack[0];
    const auto& value = stack[1];
    if constexpr (isSymbolic) state.symbolic.symbolic_value_matches_concrete(index);

    if (!check_memory<isSymbolic>(gas_left, state.memory, state.symbolic.memory, index.val, 1))
        return {EVMC_OUT_OF_GAS, gas_left};

    state.memory[static_cast<size_t>(index.val)] = static_cast<uint8_t>(value.val);
    if constexpr (isSymbolic)
    {
        if(value.is_pure()) state.symbolic.memory[static_cast<size_t>(index.val)] = state.memory[static_cast<size_t>(index.val)];
        else state.symbolic.memory[static_cast<size_t>(index.val)] = Slice8 {value.sval, 31};
    }
    return {EVMC_SUCCESS, gas_left};
}

template <bool isSymbolic> 
Result sload(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state) noexcept;

template <bool isSymbolic> 
Result sstore(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state) noexcept;

/// Internal jump implementation for JUMP/JUMPI instructions.
template <bool isSymbolic> 
inline code_iterator jump_impl(ExecutionState<isSymbolic>& state, const StackItem<isSymbolic>& dst) noexcept
{
    if constexpr (isSymbolic) state.symbolic.symbolic_value_matches_concrete(dst);

    const auto hi_part_is_nonzero = (dst.val[3] | dst.val[2] | dst.val[1]) != 0;
    if (hi_part_is_nonzero || !state.analysis.baseline->check_jumpdest(dst.val[0])) [[unlikely]]
    {
        state.status = EVMC_BAD_JUMP_DESTINATION;
        return nullptr;
    }
    return &state.analysis.baseline->executable_code()[static_cast<size_t>(dst.val[0])];
}

/// JUMP instruction implementation using baseline::CodeAnalysis.
template <bool isSymbolic> 
inline code_iterator jump(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state, code_iterator /*pos*/) noexcept
{
    return jump_impl(state, stack[0]);
}

/// JUMPI instruction implementation using baseline::CodeAnalysis.
template <bool isSymbolic> 
inline code_iterator jumpi(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state, code_iterator pos) noexcept
{
    const auto& dst = stack[0];
    const auto& cond = stack[1];
    if constexpr (isSymbolic) {
        if (StackItem<true>::is_symbolic(cond.sval))
        {
            if(cond.val != 0) state.symbolic.requirements.push_back(SymbolicRequirement{Req::notEqual, cond.sval, 0});
            else state.symbolic.requirements.push_back(SymbolicRequirement{Req::equal,cond.sval, 0});
        }
    }
    return cond.val ? jump_impl(state, dst) : pos + 1;
}

template <bool isSymbolic> 
inline code_iterator rjump(StackTop<isSymbolic> /*stack*/, ExecutionState<isSymbolic>& /*state*/, code_iterator pc) noexcept
{
    // Reading next 2 bytes is guaranteed to be safe by deploy-time validation.
    const auto offset = read_int16_be(&pc[1]);
    return pc + 3 + offset;  // PC_post_rjump + offset
}

template <bool isSymbolic> 
inline code_iterator rjumpi(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state, code_iterator pc) noexcept
{
    // unsupported by monad atm
    const auto cond = stack[0];
    return cond.val ? rjump(stack, state, pc) : pc + 3;
}

template <bool isSymbolic> 
inline code_iterator rjumpv(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& /*state*/, code_iterator pc) noexcept
{
    // unsupported by monad atm
    constexpr auto REL_OFFSET_SIZE = sizeof(int16_t);
    const auto case_ = stack[0].val;

    const auto max_index = pc[1];
    const auto pc_post = pc + 1 + 1 /* max_index */ + (max_index + 1) * REL_OFFSET_SIZE /* tbl */;

    if (case_ > max_index)
    {
        return pc_post;
    }
    else
    {
        const auto rel_offset =
            read_int16_be(&pc[2 + static_cast<uint16_t>(case_) * REL_OFFSET_SIZE]);

        return pc_post + rel_offset;
    }
}

template <bool isSymbolic> 
inline code_iterator pc(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state, code_iterator pos) noexcept
{
    stack.push(static_cast<uint64_t>(pos - state.analysis.baseline->executable_code().data()));
    return pos + 1;
}

template <bool isSymbolic> 
inline void msize(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state) noexcept
{
    stack.push(state.memory.size());
    if constexpr (isSymbolic) assert(state.memory.size() == state.symbolic.memory.size());
}

template <bool isSymbolic> 
inline Result gas(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& /*state*/) noexcept
{
    stack.push(gas_left);
    return {EVMC_SUCCESS, gas_left};
}

template <bool isSymbolic> 
inline void tload(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state) noexcept
{
    auto& x = stack[0];
    const auto key = intx::be::store<evmc::bytes32>(x.val);
    const auto value = state.host.get_transient_storage(state.msg->recipient, key);
    x.val = intx::be::load<uint256>(value);
    if constexpr (isSymbolic) x.set_symbolic(*stack.arena, state.symbolic.tstore, state.msg->recipient, key, true);
}

template <bool isSymbolic> 
inline Result tstore(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state) noexcept
{
    if constexpr (isSymbolic) state.symbolic.symbolic_value_matches_concrete(stack[0]);

    if (state.in_static_mode())
        return {EVMC_STATIC_MODE_VIOLATION, 0};

    const auto key = intx::be::store<evmc::bytes32>(stack[0].val);
    const auto value = intx::be::store<evmc::bytes32>(stack[1].val);
    state.host.set_transient_storage(state.msg->recipient, key, value);
    if constexpr (isSymbolic) state.symbolic.update_tstore(key, stack[1]);
    return {EVMC_SUCCESS, gas_left};
}

template <bool isSymbolic> 
inline void push0(StackTop<isSymbolic> stack) noexcept
{
    stack.push(uint256 {});
}


template <size_t Len>
inline uint64_t load_partial_push_data(code_iterator pos) noexcept
{
    static_assert(Len > 4 && Len < 8);

    // It loads up to 3 additional bytes.
    return intx::be::unsafe::load<uint64_t>(pos) >> (8 * (sizeof(uint64_t) - Len));
}

template <>
inline uint64_t load_partial_push_data<1>(code_iterator pos) noexcept
{
    return pos[0];
}

template <>
inline uint64_t load_partial_push_data<2>(code_iterator pos) noexcept
{
    return intx::be::unsafe::load<uint16_t>(pos);
}

template <>
inline uint64_t load_partial_push_data<3>(code_iterator pos) noexcept
{
    // It loads 1 additional byte.
    return intx::be::unsafe::load<uint32_t>(pos) >> 8;
}

template <>
inline uint64_t load_partial_push_data<4>(code_iterator pos) noexcept
{
    return intx::be::unsafe::load<uint32_t>(pos);
}

/// PUSH instruction implementation.
/// @tparam Len The number of push data bytes, e.g. PUSH3 is push<3>.
///
/// It assumes that at lest 32 bytes of data are available so code padding is required.
template <bool isSymbolic, size_t Len>
inline code_iterator push(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& /*state*/, code_iterator pos) noexcept
{
    constexpr auto num_full_words = Len / sizeof(uint64_t);
    constexpr auto num_partial_bytes = Len % sizeof(uint64_t);
    auto data = pos + 1;

    stack.push(0);
    auto& r = stack[0];

    // Load top partial word.
    if constexpr (num_partial_bytes != 0)
    {
        r.val[num_full_words] = load_partial_push_data<num_partial_bytes>(data);
        data += num_partial_bytes;
    }

    // Load full words.
    for (size_t i = 0; i < num_full_words; ++i)
    {
        r.val[num_full_words - 1 - i] = intx::be::unsafe::load<uint64_t>(data);
        data += sizeof(uint64_t);
    }
    if constexpr (isSymbolic) r.set_pure();

    return pos + (Len + 1);
}

template <bool isSymbolic> inline constexpr auto push1 = push<isSymbolic, 1>;
template <bool isSymbolic> inline constexpr auto push2 = push<isSymbolic, 2>;
template <bool isSymbolic> inline constexpr auto push3 = push<isSymbolic, 3>;
template <bool isSymbolic> inline constexpr auto push4 = push<isSymbolic, 4>;
template <bool isSymbolic> inline constexpr auto push5 = push<isSymbolic, 5>;
template <bool isSymbolic> inline constexpr auto push6 = push<isSymbolic, 6>;
template <bool isSymbolic> inline constexpr auto push7 = push<isSymbolic, 7>;
template <bool isSymbolic> inline constexpr auto push8 = push<isSymbolic, 8>;
template <bool isSymbolic> inline constexpr auto push9 = push<isSymbolic, 9>;
template <bool isSymbolic> inline constexpr auto push10 = push<isSymbolic, 10>;
template <bool isSymbolic> inline constexpr auto push11 = push<isSymbolic, 11>;
template <bool isSymbolic> inline constexpr auto push12 = push<isSymbolic, 12>;
template <bool isSymbolic> inline constexpr auto push13 = push<isSymbolic, 13>;
template <bool isSymbolic> inline constexpr auto push14 = push<isSymbolic, 14>;
template <bool isSymbolic> inline constexpr auto push15 = push<isSymbolic, 15>;
template <bool isSymbolic> inline constexpr auto push16 = push<isSymbolic, 16>;
template <bool isSymbolic> inline constexpr auto push17 = push<isSymbolic, 17>;
template <bool isSymbolic> inline constexpr auto push18 = push<isSymbolic, 18>;
template <bool isSymbolic> inline constexpr auto push19 = push<isSymbolic, 19>;
template <bool isSymbolic> inline constexpr auto push20 = push<isSymbolic, 20>;
template <bool isSymbolic> inline constexpr auto push21 = push<isSymbolic, 21>;
template <bool isSymbolic> inline constexpr auto push22 = push<isSymbolic, 22>;
template <bool isSymbolic> inline constexpr auto push23 = push<isSymbolic, 23>;
template <bool isSymbolic> inline constexpr auto push24 = push<isSymbolic, 24>;
template <bool isSymbolic> inline constexpr auto push25 = push<isSymbolic, 25>;
template <bool isSymbolic> inline constexpr auto push26 = push<isSymbolic, 26>;
template <bool isSymbolic> inline constexpr auto push27 = push<isSymbolic, 27>;
template <bool isSymbolic> inline constexpr auto push28 = push<isSymbolic, 28>;
template <bool isSymbolic> inline constexpr auto push29 = push<isSymbolic, 29>;
template <bool isSymbolic> inline constexpr auto push30 = push<isSymbolic, 30>;
template <bool isSymbolic> inline constexpr auto push31 = push<isSymbolic, 31>;
template <bool isSymbolic> inline constexpr auto push32 = push<isSymbolic, 32>;


/// DUP instruction implementation.
/// @tparam N  The number as in the instruction definition, e.g. DUP3 is dup<3>.
template <bool isSymbolic, int N>
inline void dup(StackTop<isSymbolic> stack) noexcept
{
    static_assert(N >= 1 && N <= 16);
    stack.push(stack[N - 1]);
}

template <bool isSymbolic> inline constexpr auto dup1 = dup<isSymbolic, 1>;
template <bool isSymbolic> inline constexpr auto dup2 = dup<isSymbolic, 2>;
template <bool isSymbolic> inline constexpr auto dup3 = dup<isSymbolic, 3>;
template <bool isSymbolic> inline constexpr auto dup4 = dup<isSymbolic, 4>;
template <bool isSymbolic> inline constexpr auto dup5 = dup<isSymbolic, 5>;
template <bool isSymbolic> inline constexpr auto dup6 = dup<isSymbolic, 6>;
template <bool isSymbolic> inline constexpr auto dup7 = dup<isSymbolic, 7>;
template <bool isSymbolic> inline constexpr auto dup8 = dup<isSymbolic, 8>;
template <bool isSymbolic> inline constexpr auto dup9 = dup<isSymbolic, 9>;
template <bool isSymbolic> inline constexpr auto dup10 = dup<isSymbolic, 10>;
template <bool isSymbolic> inline constexpr auto dup11 = dup<isSymbolic, 11>;
template <bool isSymbolic> inline constexpr auto dup12 = dup<isSymbolic, 12>;
template <bool isSymbolic> inline constexpr auto dup13 = dup<isSymbolic, 13>;
template <bool isSymbolic> inline constexpr auto dup14 = dup<isSymbolic, 14>;
template <bool isSymbolic> inline constexpr auto dup15 = dup<isSymbolic, 15>;
template <bool isSymbolic> inline constexpr auto dup16 = dup<isSymbolic, 16>;

/// SWAP instruction implementation.
/// @tparam N  The number as in the instruction definition, e.g. SWAP3 is swap<3>.
template <bool isSymbolic, int N>
inline void swap(StackTop<isSymbolic> stack) noexcept
{
    static_assert(N >= 1 && N <= 16);

    // The simple std::swap(stack.top(), stack[N]) is not used to workaround
    // clang missed optimization: https://github.com/llvm/llvm-project/issues/59116
    // TODO(clang): Check if #59116 bug fix has been released.

    auto& a = stack[N];
    auto& t = stack[0];
    auto t0 = t.val[0];
    auto t1 = t.val[1];
    auto t2 = t.val[2];
    auto t3 = t.val[3];
    t.val = a.val;
    a.val[0] = t0;
    a.val[1] = t1;
    a.val[2] = t2;
    a.val[3] = t3;
    if constexpr (isSymbolic) t.sval.swap(a.sval);
}

template <bool isSymbolic> inline constexpr auto swap1 = swap<isSymbolic, 1>;
template <bool isSymbolic> inline constexpr auto swap2 = swap<isSymbolic, 2>;
template <bool isSymbolic> inline constexpr auto swap3 = swap<isSymbolic, 3>;
template <bool isSymbolic> inline constexpr auto swap4 = swap<isSymbolic, 4>;
template <bool isSymbolic> inline constexpr auto swap5 = swap<isSymbolic, 5>;
template <bool isSymbolic> inline constexpr auto swap6 = swap<isSymbolic, 6>;
template <bool isSymbolic> inline constexpr auto swap7 = swap<isSymbolic, 7>;
template <bool isSymbolic> inline constexpr auto swap8 = swap<isSymbolic, 8>;
template <bool isSymbolic> inline constexpr auto swap9 = swap<isSymbolic, 9>;
template <bool isSymbolic> inline constexpr auto swap10 = swap<isSymbolic, 10>;
template <bool isSymbolic> inline constexpr auto swap11 = swap<isSymbolic, 11>;
template <bool isSymbolic> inline constexpr auto swap12 = swap<isSymbolic, 12>;
template <bool isSymbolic> inline constexpr auto swap13 = swap<isSymbolic, 13>;
template <bool isSymbolic> inline constexpr auto swap14 = swap<isSymbolic, 14>;
template <bool isSymbolic> inline constexpr auto swap15 = swap<isSymbolic, 15>;
template <bool isSymbolic> inline constexpr auto swap16 = swap<isSymbolic, 16>;


template <bool isSymbolic> 
inline code_iterator dupn(StackTop<isSymbolic> stack, code_iterator pos) noexcept
{
    stack.push(stack[pos[1]]);
    return pos + 2;
}

template <bool isSymbolic> 
inline code_iterator swapn(StackTop<isSymbolic> stack, code_iterator pos) noexcept
{
    // TODO: This may not be optimal, see instr::core::swap().
    std::swap(stack[0], stack[pos[1] + 1]);
    return pos + 2;
}

template <bool isSymbolic> 
inline code_iterator exchange(StackTop<isSymbolic> stack, code_iterator pos) noexcept
{
    const auto n = (pos[1] >> 4) + 1;
    const auto m = (pos[1] & 0x0f) + 1;
    // TODO: This may not be optimal, see instr::core::swap().
    std::swap(stack[n], stack[n + m]);
    return pos + 2;
}

template <bool isSymbolic> 
inline Result mcopy(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state) noexcept
{
    const auto& dst_u256 = stack[0];
    const auto& src_u256 = stack[1];
    const auto& size_u256 = stack[2];

    if (!check_memory<isSymbolic>(gas_left, state.memory, state.symbolic.memory, std::max(dst_u256.val, src_u256.val), size_u256.val))
        return {EVMC_OUT_OF_GAS, gas_left};

    const auto dst = static_cast<size_t>(dst_u256.val);
    const auto src = static_cast<size_t>(src_u256.val);
    const auto size = static_cast<size_t>(size_u256.val);

    if (const auto cost = copy_cost(size); (gas_left -= cost) < 0)
        return {EVMC_OUT_OF_GAS, gas_left};

    if (size > 0)
    {
        std::memmove(&state.memory[dst], &state.memory[src], size);
        if constexpr (isSymbolic)
        {
            if(dst < src)
            {
                for (size_t i = 0; i < size; i++)
                {
                    state.symbolic.memory[dst+i] = state.symbolic.memory[src+i];
                }
            }
            else
            {
                for (size_t _i = 0; _i < size; _i++)
                {
                    auto i = size - 1 - _i;
                    state.symbolic.memory[dst+i] = state.symbolic.memory[src+i];
                }
            }
        }
    }
    return {EVMC_SUCCESS, gas_left};
}

template <bool isSymbolic> 
inline void dataload(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state) noexcept
{
    // unsupported by monad atm
    const auto data = state.analysis.baseline->eof_data();
    auto& index = stack[0];

    if (data.size() < index.val)
        index.val = 0;
    else
    {
        const auto begin = static_cast<size_t>(index.val);
        const auto end = std::min(begin + 32, data.size());

        uint8_t d[32] = {};
        for (size_t i = 0; i < (end - begin); ++i)
            d[i] = data[begin + i];

        index.val = intx::be::unsafe::load<uint256>(d);
    }
    if constexpr (isSymbolic) index.set_pure();
}

template <bool isSymbolic> 
inline void datasize(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state) noexcept
{
    stack.push(state.analysis.baseline->eof_data().size());
}

template <bool isSymbolic> 
inline code_iterator dataloadn(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state, code_iterator pos) noexcept
{
    const auto index = read_uint16_be(&pos[1]);

    stack.push(intx::be::unsafe::load<uint256>(&state.analysis.baseline->eof_data()[index]));
    return pos + 3;
}

template <bool isSymbolic> 
inline Result datacopy(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state) noexcept
{
    const auto data = state.analysis.baseline->eof_data();
    const auto& mem_index = stack[0];
    const auto& data_index = stack[1];
    const auto& size = stack[2];
    if constexpr (isSymbolic) state.symbolic.symbolic_value_matches_concrete(mem_index, size);

    if (!check_memory<isSymbolic>(gas_left, state.memory, state.symbolic.memory, mem_index.val, size.val))
        return {EVMC_OUT_OF_GAS, gas_left};

    const auto dst = static_cast<size_t>(mem_index.val);
    // TODO why?
    const auto src = data.size() < data_index.val ? data.size() : static_cast<size_t>(data_index.val);
    const auto s = static_cast<size_t>(size.val);
    const auto copy_size = std::min(s, data.size() - src);

    if (const auto cost = copy_cost(s); (gas_left -= cost) < 0)
        return {EVMC_OUT_OF_GAS, gas_left};

    if (copy_size > 0)
        std::memcpy(&state.memory[dst], &data[src], copy_size);

    if (s - copy_size > 0)
        std::memset(&state.memory[dst + copy_size], 0, s - copy_size);

    return {EVMC_SUCCESS, gas_left};
}

template <bool isSymbolic, size_t NumTopics>
inline Result log(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state) noexcept
{
    static_assert(NumTopics <= 4);

    if (state.in_static_mode())
        return {EVMC_STATIC_MODE_VIOLATION, 0};

    const auto& offset = stack[0];
    const auto& size = stack[1];
    if constexpr (isSymbolic) state.symbolic.symbolic_value_matches_concrete(offset, size);

    if (!check_memory<isSymbolic>(gas_left, state.memory, state.symbolic.memory, offset.val, size.val))
        return {EVMC_OUT_OF_GAS, gas_left};

    const auto o = static_cast<size_t>(offset.val);
    const auto s = static_cast<size_t>(size.val);

    const auto cost = int64_t(s) * 8;
    if ((gas_left -= cost) < 0)
        return {EVMC_OUT_OF_GAS, gas_left};

    std::array<evmc::bytes32, NumTopics> topics;  // NOLINT(cppcoreguidelines-pro-type-member-init)
    int topic_counter = 2;
    for (auto& topic : topics){
        topic = intx::be::store<evmc::bytes32>(stack[topic_counter].val);
        if constexpr (isSymbolic) state.symbolic.symbolic_value_matches_concrete(stack[topic_counter]);
        topic_counter++;
    }
        

    const auto data = s != 0 ? &state.memory[o] : nullptr;
    state.host.emit_log(state.msg->recipient, data, s, topics.data(), NumTopics);
    return {EVMC_SUCCESS, gas_left};
}

template <bool isSymbolic> inline constexpr auto log0 = log<isSymbolic, 0>;
template <bool isSymbolic> inline constexpr auto log1 = log<isSymbolic, 1>;
template <bool isSymbolic> inline constexpr auto log2 = log<isSymbolic, 2>;
template <bool isSymbolic> inline constexpr auto log3 = log<isSymbolic, 3>;
template <bool isSymbolic> inline constexpr auto log4 = log<isSymbolic, 4>;


template <bool isSymbolic, Opcode Op>
Result call_impl(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state) noexcept;
template <bool isSymbolic> inline constexpr auto call = call_impl<isSymbolic, OP_CALL>;
template <bool isSymbolic> inline constexpr auto callcode = call_impl<isSymbolic, OP_CALLCODE>;
template <bool isSymbolic> inline constexpr auto delegatecall = call_impl<isSymbolic, OP_DELEGATECALL>;
template <bool isSymbolic> inline constexpr auto staticcall = call_impl<isSymbolic, OP_STATICCALL>;

template <bool isSymbolic, Opcode Op>
Result extcall_impl(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state) noexcept;
template <bool isSymbolic> inline constexpr auto extcall = extcall_impl<isSymbolic, OP_EXTCALL>;
template <bool isSymbolic> inline constexpr auto extdelegatecall = extcall_impl<isSymbolic, OP_EXTDELEGATECALL>;
template <bool isSymbolic> inline constexpr auto extstaticcall = extcall_impl<isSymbolic, OP_EXTSTATICCALL>;

template <bool isSymbolic, Opcode Op>
Result create_impl(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state) noexcept;
template <bool isSymbolic> inline constexpr auto create = create_impl<isSymbolic, OP_CREATE>;
template <bool isSymbolic> inline constexpr auto create2 = create_impl<isSymbolic, OP_CREATE2>;

template <bool isSymbolic>
Result eofcreate(
    StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state, code_iterator& pos) noexcept;

template <bool isSymbolic>
inline code_iterator callf(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state, code_iterator pos) noexcept
{
    // unsupported by monad atm
    const auto index = read_uint16_be(&pos[1]);
    const auto& header = state.analysis.baseline->eof_header();
    const auto stack_size = &stack[0] - state.stack_space.bottom();
    const auto callee_type = header.get_type(state.original_code, index);
    const auto callee_required_stack_size = callee_type.max_stack_height - callee_type.inputs;
    if (stack_size + callee_required_stack_size > StackSpace<isSymbolic>::limit)
    {
        state.status = EVMC_STACK_OVERFLOW;
        return nullptr;
    }

    if (state.call_stack.size() >= StackSpace<isSymbolic>::limit)
    {
        // TODO: Add different error code.
        state.status = EVMC_STACK_OVERFLOW;
        return nullptr;
    }
    state.call_stack.push_back(pos + 3);

    const auto offset = header.code_offsets[index] - header.code_offsets[0];
    return state.analysis.baseline->executable_code().data() + offset;
}

template <bool isSymbolic>
inline code_iterator retf(StackTop<isSymbolic> /*stack*/, ExecutionState<isSymbolic>& state, code_iterator /*pos*/) noexcept
{
    const auto p = state.call_stack.back();
    state.call_stack.pop_back();
    return p;
}

template <bool isSymbolic>
inline code_iterator jumpf(StackTop<isSymbolic> stack, ExecutionState<isSymbolic>& state, code_iterator pos) noexcept
{
    // unsupported by monad atm
    const auto index = read_uint16_be(&pos[1]);
    const auto& header = state.analysis.baseline->eof_header();
    const auto stack_size = &stack[0] - state.stack_space.bottom();
    const auto callee_type = header.get_type(state.original_code, index);
    const auto callee_required_stack_size = callee_type.max_stack_height - callee_type.inputs;
    if (stack_size + callee_required_stack_size > StackSpace<isSymbolic>::limit)
    {
        state.status = EVMC_STACK_OVERFLOW;
        return nullptr;
    }

    const auto offset = header.code_offsets[index] - header.code_offsets[0];
    return state.analysis.baseline->executable_code().data() + offset;
}

template <bool isSymbolic, evmc_status_code StatusCode>
inline TermResult return_impl(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state) noexcept
{
    const auto& offset = stack[0];
    const auto& size = stack[1];
    if constexpr (isSymbolic) state.symbolic.symbolic_value_matches_concrete(offset, size);

    if (!check_memory<isSymbolic>(gas_left, state.memory, state.symbolic.memory, offset.val, size.val))
        return {EVMC_OUT_OF_GAS, gas_left};

    state.output_size = static_cast<size_t>(size.val);
    if (state.output_size != 0)
        state.output_offset = static_cast<size_t>(offset.val);
    return {StatusCode, gas_left};
}
template <bool isSymbolic> inline constexpr auto return_ = return_impl<isSymbolic, EVMC_SUCCESS>;
template <bool isSymbolic> inline constexpr auto revert = return_impl<isSymbolic, EVMC_REVERT>;

template <bool isSymbolic>
inline TermResult returncontract(
    StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state, code_iterator pos) noexcept
{
    // unsupported by monad atm
    if constexpr (isSymbolic) assert(false);
    const auto& offset = stack[0];
    const auto& size = stack[1];
    if constexpr (isSymbolic) state.symbolic.symbolic_value_matches_concrete(offset, size);

    if (!check_memory<isSymbolic>(gas_left, state.memory, state.symbolic.memory, offset.val, size.val))
        return {EVMC_OUT_OF_GAS, gas_left};

    const auto deploy_container_index = size_t{pos[1]};
    bytes deploy_container{state.analysis.baseline->eof_header().get_container(
        state.original_code, deploy_container_index)};

    // Append (offset, size) to data section
    if (!append_data_section(deploy_container,
            {&state.memory[static_cast<size_t>(offset.val)], static_cast<size_t>(size.val)}))
        return {EVMC_OUT_OF_GAS, gas_left};

    state.deploy_container = std::move(deploy_container);
    // TODO any symbolic requirements??
    return {EVMC_SUCCESS, gas_left};
}

template <bool isSymbolic>
inline TermResult selfdestruct(StackTop<isSymbolic> stack, int64_t gas_left, ExecutionState<isSymbolic>& state) noexcept
{
    if (state.in_static_mode())
        return {EVMC_STATIC_MODE_VIOLATION, gas_left};

    const auto& beneficiary_index = stack[0];
    const auto beneficiary = intx::be::trunc<evmc::address>(beneficiary_index.val);
    if constexpr (isSymbolic) state.symbolic.symbolic_value_matches_concrete(beneficiary_index);

    if (state.rev >= EVMC_BERLIN && state.host.access_account(beneficiary) == EVMC_ACCESS_COLD)
    {
        if ((gas_left -= instr::cold_account_access_cost) < 0)
            return {EVMC_OUT_OF_GAS, gas_left};
    }

    if (state.rev >= EVMC_TANGERINE_WHISTLE)
    {
        if (state.rev == EVMC_TANGERINE_WHISTLE || state.host.get_balance(state.msg->recipient))
        {
            // After TANGERINE_WHISTLE apply additional cost of
            // sending value to a non-existing account.
            if (!state.host.account_exists(beneficiary))
            {
                if ((gas_left -= 25000) < 0)
                    return {EVMC_OUT_OF_GAS, gas_left};
            }
        }
    }

    if (state.host.selfdestruct(state.msg->recipient, beneficiary))
    {
        if (state.rev < EVMC_LONDON)
            state.gas_refund += 24000;
    }
    return {EVMC_SUCCESS, gas_left};
}


/// Maps an opcode to the instruction implementation.
///
/// The set of template specializations which map opcodes `Op` to the function
/// implementing the instruction identified by the opcode.
///     instr::impl<OP_DUP1>(/*...*/);
/// The unspecialized template is invalid and should never to used.
template <bool isSymbolic, Opcode Op>
inline constexpr auto impl = nullptr;

#undef ON_OPCODE_IDENTIFIER
#define ON_OPCODE_IDENTIFIER(OPCODE, IDENTIFIER)                 \
    template <>                                                  \
    inline constexpr auto impl<true, OPCODE> = IDENTIFIER<true>; \
    template <>                                                  \
    inline constexpr auto impl<false, OPCODE> = IDENTIFIER<false>; // opcode -> implementation
MAP_OPCODES
#undef ON_OPCODE_IDENTIFIER
#define ON_OPCODE_IDENTIFIER ON_OPCODE_IDENTIFIER_DEFAULT
}  // namespace instr::core
}  // namespace evmone
