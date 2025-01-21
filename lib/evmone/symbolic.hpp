#pragma once

#include "baseline.hpp"
#include "rc_ptr.hpp"
#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <map>
#include <variant>

using intx::uint256;

template <class... Ts>
struct Cases : Ts...
{
    using Ts::operator()...;
};

namespace evmone
{

struct Slice;
struct UnaryOp;
struct BinaryOp;
struct TernaryOp;
struct SetItem;
struct SetMem;
struct Keccak256;


struct Sload 
{
    evmc::address addr;
    evmc_bytes32 key;
};

using SymbolicStackItem =
        std::variant<uint256, Sload, Slice, UnaryOp, BinaryOp, TernaryOp, Keccak256>;
using SymbolicStackItemPtr = rc_ptr<SymbolicStackItem>;

using SymbolicStorage = std::unordered_map<evmc::bytes32, SymbolicStackItemPtr>;
using SymbolicStorageMap = std::unordered_map<evmc::address, SymbolicStorage>;

std::ostream& operator<<(std::ostream& os, const SymbolicStackItem& i);



struct Slice8 {
    SymbolicStackItemPtr symbolic;
    uint8_t concrete_or_offset;

    inline bool is_concrete()
    {
        return symbolic.raw() == nullptr;
    }
};

uint8_t slice8(uint256&, uint8_t);

struct Slice {
    Slice8 word[32];
};


struct Keccak256
{
    std::unique_ptr<Slice8[]> data;
    size_t size;
};

enum class UnOp { iszero, not_ };
std::ostream& operator<< (std::ostream&, const UnOp&);

struct UnaryOp
{
    UnOp op;
    SymbolicStackItemPtr first;
};

enum class BinOp { add, mul, sub, div, sdiv, mod, smod, exp, signextend, lt, gt, slt, sgt, eq, and_, or_, xor_, byte, shl, shr, sar };
std::ostream& operator<< (std::ostream&, const BinOp&);

struct BinaryOp
{
    BinOp op;
    SymbolicStackItemPtr first;
    SymbolicStackItemPtr second;
};

enum class TernOp { addmod, mulmod };
std::ostream& operator<< (std::ostream&, const TernOp&);

struct TernaryOp
{
    TernOp op;
    SymbolicStackItemPtr first;
    SymbolicStackItemPtr second;
    SymbolicStackItemPtr third;
};

template <bool Symbolic>
struct StackItem;

template <>
struct StackItem<false> {
    uint256 val;
};

template <>
struct StackItem<true> {
    uint256 val;
    SymbolicStackItemPtr sval;

    // Not sure where to stick these static methods. 
    // Ideally they would go into the SymbolicStackItem namespace, but not sure how to do that...

    template <typename ...Args> inline static SymbolicStackItemPtr make_symbolic(ArenaAllocator& arena, Args&& ...args)
    {
        return rc_ptr<SymbolicStackItem>::make(arena, std::forward<Args>(args)...);
    }

    inline static bool is_symbolic(const SymbolicStackItemPtr& sval)
    {
        if(sval) return !std::holds_alternative<uint256>(*sval);
        else return false;
    }

    inline bool is_pure() const
    {
        if (sval)
        {
            assert(!std::holds_alternative<uint256>(*sval));
            return false;
        }
        else return true;
    }

    inline void set_pure()
    {
        sval = rc_ptr<SymbolicStackItem>();
    }

    inline static void set_symbolic(ArenaAllocator& arena, UnOp&& op, StackItem& first)
    {
        if (first.is_pure()) return;
        first.sval = make_symbolic(arena, UnaryOp {op, first.sval});
    }

    inline static void set_symbolic(ArenaAllocator& arena, BinOp&& op, StackItem& first, StackItem& second)
    {
        if (first.is_pure() && second.is_pure()) return;
        if (second.sval.counter() == 1 && second.is_pure())
            *second.sval =
                BinaryOp {
                    op,
                    first.sval,
                    make_symbolic(arena, second.val)
                };
        else second.sval = make_symbolic(arena, BinaryOp {
                    op,
                    first.is_pure() ? make_symbolic(arena, first.val) : first.sval,
                    second.is_pure() ? make_symbolic(arena, second.val) : second.sval
                });
    }

    inline static void set_symbolic(ArenaAllocator& arena, TernOp&& op,  StackItem& first, StackItem& second, StackItem& third)
    {
        if (first.is_pure() && second.is_pure() && third.is_pure()) return;
        if (third.sval.counter() == 1 && third.is_pure())
            *third.sval =
                TernaryOp {
                    op,
                    first.is_pure() ? make_symbolic(arena, first.val) : first.sval,
                    second.is_pure() ? make_symbolic(arena, second.val) : second.sval,
                    make_symbolic(arena, third.val)
                };
        else third.sval = make_symbolic(arena, TernaryOp {
                    op,
                    first.is_pure() ? make_symbolic(arena, first.val) : first.sval,
                    second.is_pure() ? make_symbolic(arena, second.val) : second.sval,
                    third.is_pure() ? make_symbolic(arena, third.val) : third.sval
                });
    }
};

struct Equal;
struct NotEqual;
struct LessEqual;
struct Greater;


enum class Req { equal, notEqual, lessEqual, greater };

struct SymbolicRequirement
{
    Req op;
    SymbolicStackItemPtr sval;
    uint256 val;
    std::ostream& operator<<(std::ostream& os) {
        switch (op)
        {
        case Req::equal:
            os << *sval << " == 0x" << intx::hex(val);
            break;
        case Req::notEqual:
            os << *sval << " != 0x" << intx::hex(val);
            break;
        case Req::lessEqual:
            os << *sval << " <= 0x" << intx::hex(val);
            break;
        case Req::greater:
            os << *sval << " > 0x" << intx::hex(val);
            break;
        }
        return os;
    }
};

inline bool is_uint256_value(const SymbolicStackItemPtr& sval)
{
    assert(sval);
    return std::holds_alternative<uint256>(*sval);
}

bool eval(std::function<evmc_bytes32(evmc::address&, evmc_bytes32&)>, std::vector<std::variant<SymbolicStackItemPtr, SymbolicRequirement>>);

}