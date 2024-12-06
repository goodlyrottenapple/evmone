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


using PlainMemoryPtr = std::shared_ptr<uint8_t[]>;

// using Sload = Load<SymbolicStoragePtr>;
struct Sload 
{
    evmc_bytes32 key;
};


using SymbolicStackItem =
        std::variant<Sload, Slice, UnaryOp, BinaryOp, TernaryOp>;
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
        if(sval) return true;
        else return false;
    }

    inline static bool is_pure(const SymbolicStackItemPtr& sval)
    {
        if(sval) return false;
        else return true;
    }

    inline void set_pure()
    {
        sval = rc_ptr<SymbolicStackItem>();
    }

    inline void set_symbolic(ArenaAllocator& arena, SymbolicStoragePtr storage, Sload&& si)
    {
        
        if (auto search = storage->find(si.key); search != storage->end())
        {
            sval = search->second;
        }
        else
        {
            if (sval.counter() == 1) *sval = si;
            else sval = make_symbolic(arena, si);
        }
    }

    inline void set_symbolic(ArenaAllocator& arena, UnaryOp&& si)
    {
        if (is_pure(si.first)) 
            set_pure();
        else
        {
            if (sval.counter() == 1) *sval = si;
            else sval = make_symbolic(arena, si);
        }
    }

    inline void set_symbolic(ArenaAllocator& arena, BinaryOp&& si)
    {
        if (is_pure(si.first) && is_pure(si.second))
            set_pure();
        else
        {
            if (sval.counter() == 1) *sval = si;
            else sval = make_symbolic(arena, si);
        }
    }

    inline void set_symbolic(ArenaAllocator& arena, TernaryOp&& si)
    {
        if (is_pure(si.first) && is_pure(si.second) && is_pure(si.third))
            set_pure();
        else
        {
            if (sval.counter() == 1) *sval = si;
            else sval = make_symbolic(arena, si);
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