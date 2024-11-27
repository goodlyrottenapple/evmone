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

struct Pure;
template<typename>
struct Load;
struct UnaryOp;
struct BinaryOp;
struct TernaryOp;
template<typename>
struct SymbolicUpdates;

template <class T>
using SymbolicUpdatesPtr = std::shared_ptr<SymbolicUpdates<T>>;

struct SetItem;
struct Offset;
struct SetMem;


using SymbolicMemoryUpdate =
    std::variant<SetItem, SetMem, Offset>;
std::ostream& operator<<(std::ostream& os, const SymbolicMemoryUpdate& i);



using SymbolicStorage = SymbolicUpdates<SetItem>;
using SymbolicStoragePtr = SymbolicUpdatesPtr<SetItem>;


struct MapComparator
{
    bool operator()( const evmc_address& a, const evmc_address& b ) const 
    {
        for (size_t i = 0; i < 20; i++)
        {
            if(a.bytes[i]<b.bytes[i]) return true;
        }
        return false;
    }
};

using SymbolicStorageMap = std::map<evmc_address, SymbolicStoragePtr, MapComparator>;

using SymbolicMemory = SymbolicUpdates<SymbolicMemoryUpdate>;
using SymbolicMemoryPtr = SymbolicUpdatesPtr<SymbolicMemoryUpdate>;
using PlainMemoryPtr = std::shared_ptr<uint8_t[]>;

using Sload = Load<SymbolicStoragePtr>;
using Mload = Load<SymbolicMemoryPtr>;

using SymbolicStackItem =
        std::variant<Pure, Sload, Mload, UnaryOp, BinaryOp, TernaryOp>;
using SymbolicStackItemPtr = rc_ptr<SymbolicStackItem>;

std::ostream& operator<<(std::ostream& os, const SymbolicStackItem& i);


struct Offset {
    SymbolicStackItemPtr offset;
    SymbolicStackItemPtr size;
    friend std::ostream& operator<<(std::ostream&, const Offset&);
};

struct SetMem
{
    size_t index;
    size_t size;
    std::variant<SymbolicMemoryPtr, std::shared_ptr<uint8_t[]>> memory;
    friend std::ostream& operator<<(std::ostream&, const SetMem&);
};

struct SetItem
{
    SymbolicStackItemPtr loc;
    SymbolicStackItemPtr val;
    friend std::ostream& operator<<(std::ostream&, const SetItem&);
};

template<typename T>
struct SymbolicUpdates 
{
    // we shouuld only ever have one evmc_address per SymbolicUpdates list
    std::variant<T, evmc_address> head;
    SymbolicUpdatesPtr<T> tail;
    template<typename U>
    friend std::ostream& operator<<(std::ostream&, SymbolicUpdatesPtr<U>);
};

struct Pure
{
    uint256 pure;
};

template<typename T>
struct Load 
{
    SymbolicStackItemPtr addr;
    T symbolic_store;
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
        return !std::holds_alternative<Pure>(*sval);
    }

    inline static bool is_pure(const SymbolicStackItemPtr& sval)
    {
        return std::holds_alternative<Pure>(*sval);
    }

    inline void set_symbolic(ArenaAllocator& arena, Pure&& si)
    {
        sval = make_symbolic(arena, std::forward<Pure>(si));
    }

    inline void set_symbolic(ArenaAllocator& arena, Sload&& si)
    {
        sval = make_symbolic(arena, si);
    }

    inline void set_symbolic(ArenaAllocator& arena, Mload&& si)
    {
        sval = make_symbolic(arena, si);
    }

    inline void set_symbolic(ArenaAllocator& arena, UnaryOp&& si)
    {
        if (is_pure(si.first))
            sval = make_symbolic(arena, Pure {val});
        else
            sval = make_symbolic(arena, si);
    }

    inline void set_symbolic(ArenaAllocator& arena, BinaryOp&& si)
    {
        if (is_pure(si.first) && std::holds_alternative<Pure>(*si.second))
            sval = make_symbolic(arena, Pure {val});
        else
            sval = make_symbolic(arena, si);
    }

    inline void set_symbolic(ArenaAllocator& arena, TernaryOp&& si)
    {
        if (is_pure(si.first) && is_pure(si.second) && is_pure(si.third))
            sval = make_symbolic(arena, Pure {val});
        else
            sval = make_symbolic(arena, si);
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

}