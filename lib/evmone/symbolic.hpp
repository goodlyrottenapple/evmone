#pragma once

#include "baseline.hpp"
#include "rc_ptr.hpp"
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
struct Offset;
struct SetMem;
struct Keccak256;


struct Sload 
{
    evmc_bytes32 key;
};

using SymbolicStackItem =
        std::variant<uint256, Sload, Slice, UnaryOp, BinaryOp, TernaryOp, Keccak256>;
using SymbolicStackItemPtr = rc_ptr<SymbolicStackItem>;

using SymbolicStorage = std::unordered_map<evmc::bytes32, SymbolicStackItemPtr>;
using SymbolicStoragePtr = SymbolicStorage*;


using SymbolicStorageMap = std::unordered_map<evmc::address, SymbolicStoragePtr>;



std::ostream& operator<<(std::ostream& os, const SymbolicStackItem& i);


struct Offset {
    SymbolicStackItemPtr offset;
    SymbolicStackItemPtr size;
    friend std::ostream& operator<<(std::ostream&, const Offset&);
};

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

    inline static bool is_pure(const SymbolicStackItemPtr& sval)
    {
        if(sval) return std::holds_alternative<uint256>(*sval);
        else return true;
    }

    inline void set_pure()
    {
        sval = rc_ptr<SymbolicStackItem>();
    }

    inline void set_symbolic(ArenaAllocator& arena, SymbolicStoragePtr storage, evmc_bytes32 key, bool is_tload = false)
    {
        
        if (auto search = storage->find(key); search != storage->end())
        {
            sval = search->second;
        }
        else
        {
            if (is_tload)
            {
                assert(val == 0);
                set_pure();
            }
            else
            {
                if(sval.counter() == 1) *sval = Sload {key};
                else sval = make_symbolic(arena, Sload {key});
            }
        }
    }

    inline void set_symbolic(ArenaAllocator& arena, UnOp&& op, StackItem& first)
    {
        if (is_pure(first.sval)) 
            set_pure();
        else
        {
            if (sval.counter() == 1) *sval = UnaryOp {op, make_symbolic(arena, first.val)};
            else sval = make_symbolic(arena, UnaryOp {op, make_symbolic(arena, first.val)});
        }
    }

    inline void set_symbolic(ArenaAllocator& arena, BinOp&& op, StackItem& first, StackItem& second)
    {
        if (is_pure(first.sval) && is_pure(first.sval))
            set_pure();
        else
        {
            if (sval.counter() == 1) 
                *sval = 
                    BinaryOp {
                        op, 
                        is_pure(first.sval) ? make_symbolic(arena, first.val) : first.sval,
                        is_pure(second.sval) ? make_symbolic(arena, second.val) : second.sval
                    };
            else sval = make_symbolic(arena, BinaryOp {
                        op, 
                        is_pure(first.sval) ? make_symbolic(arena, first.val) : first.sval,
                        is_pure(second.sval) ? make_symbolic(arena, second.val) : second.sval
                    });
        }
    }

    inline void set_symbolic(ArenaAllocator& arena, TernOp&& op,  StackItem& first, StackItem& second, StackItem& third)
    {
        if (is_pure(first.sval) && is_pure(second.sval) && is_pure(third.sval))
            set_pure();
        else
        {
            if (sval.counter() == 1) 
                *sval = 
                    TernaryOp {
                        op, 
                        is_pure(first.sval) ? make_symbolic(arena, first.val) : first.sval,
                        is_pure(second.sval) ? make_symbolic(arena, second.val) : second.sval,
                        is_pure(third.sval) ? make_symbolic(arena, third.val) : third.sval
                    };
            else sval = make_symbolic(arena, TernaryOp {
                        op, 
                        is_pure(first.sval) ? make_symbolic(arena, first.val) : first.sval,
                        is_pure(second.sval) ? make_symbolic(arena, second.val) : second.sval,
                        is_pure(third.sval) ? make_symbolic(arena, third.val) : third.sval
                    });
        }
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


bool eval(std::function<evmc_bytes32(evmc_bytes32&)>, std::vector<std::variant<SymbolicStackItemPtr, SymbolicRequirement>>);

}