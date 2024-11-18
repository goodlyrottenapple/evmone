#pragma once

#include "baseline.hpp"
#include <intx/intx.hpp>
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
struct Sload;
struct Mload;
struct Tload;
struct UnaryOp;
struct BinaryOp;
struct TernaryOp;
template<typename>
struct SymbolicUpdates;
struct SetItem;
struct Memcpy;
struct Memset;


using SymbolicStackItem =
        std::variant<Pure, Sload, Mload, Tload, UnaryOp, BinaryOp, TernaryOp>;

std::ostream& operator<<(std::ostream& os, const SymbolicStackItem& i);

struct SetItem
{
    std::shared_ptr<SymbolicStackItem> loc;
    std::shared_ptr<SymbolicStackItem> val;
    friend std::ostream& operator<<(std::ostream&, const SetItem&);
};

struct SetMem
{
    size_t index;
    size_t size;
    std::shared_ptr<uint8_t[]> m_data;
    friend std::ostream& operator<<(std::ostream&, const SetMem&);
};

struct SetZeros {
    size_t index;
    size_t size;
    friend std::ostream& operator<<(std::ostream&, const SetZeros&);
};

using SymbolicMemoryUpdate =
    std::variant<SetItem, SetMem, SetZeros>;
std::ostream& operator<<(std::ostream& os, const SymbolicMemoryUpdate& i);


template<typename T>
struct SymbolicUpdates 
{
    T head;
    std::shared_ptr<SymbolicUpdates<T>> tail;
    template<typename U>
    friend std::ostream& operator<<(std::ostream&, std::shared_ptr<SymbolicUpdates<U>>);
};

using SymbolicStorage = SymbolicUpdates<SetItem>;
using SymbolicMemory = SymbolicUpdates<SymbolicMemoryUpdate>;

struct Pure
{
    uint256 pure;
};

struct Sload 
{
    std::shared_ptr<SymbolicStackItem> addr;
    std::shared_ptr<SymbolicStorage> store;
};

struct Mload 
{
    std::shared_ptr<SymbolicStackItem> addr;
    std::shared_ptr<SymbolicMemory> memory;
};

struct Tload 
{
    std::shared_ptr<SymbolicStackItem> addr;
    std::shared_ptr<SymbolicStorage> store;
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

struct StackItem
{
    uint256 val;
    std::shared_ptr<SymbolicStackItem> sval;
};


struct Equal;
struct NotEqual;
struct LessEqual;
struct MemEqual;

using SymbolicRequirement =
        std::variant<Equal, NotEqual, LessEqual, MemEqual>;

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

struct FreeDeleter
{
    void operator()(uint8_t* p) const noexcept { std::free(p); }
};

struct MemEqual
{
    size_t off;
    size_t size;
    std::shared_ptr<SymbolicMemory> smemory;
    std::shared_ptr<uint8_t[]> m_data;
};

}