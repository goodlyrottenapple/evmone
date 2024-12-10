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


struct MapComparatorEvmcAddress
{
    bool operator()( const evmc_address& a, const evmc_address& b) const 
    {
        if ((uint64_t)a.bytes[0] < (uint64_t)b.bytes[0]) return true;
        if ((uint64_t)a.bytes[8] < (uint64_t)b.bytes[8]) return true;
        return (uint32_t)a.bytes[16] < (uint32_t)b.bytes[16];
    }
};

struct Sload 
{
    evmc_bytes32 key;
};


using SymbolicStackItem =
        std::variant<uint256, Sload, Slice, UnaryOp, BinaryOp, TernaryOp>;
using SymbolicStackItemPtr = rc_ptr<SymbolicStackItem>;


struct MapComparatorEvmcBytes32
{
    bool operator()( const evmc_bytes32& a, const evmc_bytes32& b) const 
    {
        if ((uint64_t)a.bytes[0] < (uint64_t)b.bytes[0]) return true;
        if ((uint64_t)a.bytes[8] < (uint64_t)b.bytes[8]) return true;
        return (uint32_t)a.bytes[16] < (uint32_t)b.bytes[16];
    }
};

using SymbolicStorage = std::map<evmc_bytes32, SymbolicStackItemPtr, MapComparatorEvmcBytes32>;
using SymbolicStoragePtr = SymbolicStorage*;


using SymbolicStorageMap = std::map<evmc_address, SymbolicStoragePtr, MapComparatorEvmcAddress>;



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

struct Slice {
    Slice8 word[32];
};


enum class UnOp { iszero, not_ };
std::ostream& operator<< (std::ostream&, const UnOp&);

struct UnaryOp
{
    UnOp op;
    SymbolicStackItemPtr first;
};

enum class BinOp { add, mul, sub, div, sdiv, mod, smod, exp, signextend, lt, gt, slt, sgt, eq, and_, or_, xor_, byte, shl, shr, sar, keccak256 };
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

    inline void set_symbolic(ArenaAllocator& arena, SymbolicStoragePtr storage, evmc_bytes32 key)
    {
        
        if (auto search = storage->find(key); search != storage->end())
        {
            assert(search->second != nullptr);
            if (is_pure(search->second))
            {
                assert(val == std::get<uint256>(*search->second));
                set_pure();
            }
            else sval = search->second;
        }
        else
        {
            if (sval.counter() == 1) *sval = Sload {key};
            else sval = make_symbolic(arena, Sload {key});
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

using SymbolicRequirement =
        std::variant<Equal, NotEqual, LessEqual, Greater>;

std::ostream& operator<<(std::ostream& os, const SymbolicRequirement& i);


struct Equal
{
    SymbolicStackItemPtr sval;
    uint256 val;
};

struct NotEqual
{
    SymbolicStackItemPtr sval;
    uint256 val;
};

struct LessEqual
{
    SymbolicStackItemPtr sval;
    uint256 val;
};

struct Greater
{
    SymbolicStackItemPtr sval;
    uint256 val;
};

// uint256 eval_SymbolicStackItem(SymbolicStackItemPtr);

// using StorageMap = std::map<evmc::bytes32, evmc::bytes32>;
// StorageMap eval_SymbolicStorage(StorageMap, SymbolicStoragePtr);

}