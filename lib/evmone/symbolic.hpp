#pragma once

#include "baseline.hpp"
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

struct SetItem;
struct Offset;
struct SetMem;


using SymbolicMemoryUpdate =
    std::variant<SetItem, SetMem, Offset>;
std::ostream& operator<<(std::ostream& os, const SymbolicMemoryUpdate& i);



using SymbolicStorage = SymbolicUpdates<SetItem>;


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

using SymbolicStorageMap = std::map<evmc_address, std::shared_ptr<SymbolicStorage>, MapComparator>;

using SymbolicMemory = SymbolicUpdates<SymbolicMemoryUpdate>;

using Sload = Load<SymbolicStorage>;
using Mload = Load<SymbolicMemory>;

using SymbolicStackItem =
        std::variant<Pure, Sload, Mload, UnaryOp, BinaryOp, TernaryOp>;

std::ostream& operator<<(std::ostream& os, const SymbolicStackItem& i);


struct Offset {
    std::shared_ptr<SymbolicStackItem> offset;
    std::shared_ptr<SymbolicStackItem> size;
    friend std::ostream& operator<<(std::ostream&, const Offset&);
};

struct SetMem
{
    size_t index;
    size_t size;
    std::variant<std::shared_ptr<SymbolicMemory>, std::shared_ptr<uint8_t[]>> memory;
    friend std::ostream& operator<<(std::ostream&, const SetMem&);
};

struct SetItem
{
    std::shared_ptr<SymbolicStackItem> loc;
    std::shared_ptr<SymbolicStackItem> val;
    friend std::ostream& operator<<(std::ostream&, const SetItem&);
};

template<typename T>
struct SymbolicUpdates 
{
    // we shouuld only ever have one evmc_address per SymbolicUpdates list
    std::variant<T, evmc_address> head;
    std::shared_ptr<SymbolicUpdates<T>> tail;
    template<typename U>
    friend std::ostream& operator<<(std::ostream&, std::shared_ptr<SymbolicUpdates<U>>);
};

struct Pure
{
    uint256 pure;
};

template<typename T>
struct Load 
{
    std::shared_ptr<SymbolicStackItem> addr;
    std::shared_ptr<T> symbolic_store;
};

enum class UnOp { iszero, not_ };
std::ostream& operator<< (std::ostream&, const UnOp&);

struct UnaryOp
{
    UnOp op;
    std::shared_ptr<SymbolicStackItem> first;
};

enum class BinOp { add, mul, sub, div, sdiv, mod, smod, exp, signextend, lt, gt, slt, sgt, eq, and_, or_, xor_, byte, shl, shr, sar, keccak256 };
std::ostream& operator<< (std::ostream&, const BinOp&);

struct BinaryOp
{
    BinOp op;
    std::shared_ptr<SymbolicStackItem> first;
    std::shared_ptr<SymbolicStackItem> second;
};

enum class TernOp { addmod, mulmod };
std::ostream& operator<< (std::ostream&, const TernOp&);

struct TernaryOp
{
    TernOp op;
    std::shared_ptr<SymbolicStackItem> first;
    std::shared_ptr<SymbolicStackItem> second;
    std::shared_ptr<SymbolicStackItem> third;
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
    std::shared_ptr<SymbolicStackItem> sval;
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
    std::shared_ptr<SymbolicStackItem> sval;
    uint256 val;
};

struct NotEqual
{
    std::shared_ptr<SymbolicStackItem> sval;
    uint256 val;
};

struct LessEqual
{
    std::shared_ptr<SymbolicStackItem> sval;
    uint256 val;
};

struct Greater
{
    std::shared_ptr<SymbolicStackItem> sval;
    uint256 val;
};

}