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

struct Concrete;
struct Sload;
struct Mload;
struct Tload;
struct UnaryOp;
struct BinaryOp;
struct TernaryOp;
struct SymbolicStorage;
struct SymbolicUpdate;

using SymbolicStackItem =
        std::variant<Concrete, Sload, Mload, Tload, UnaryOp, BinaryOp, TernaryOp>;

std::ostream& operator<<(std::ostream& os, const SymbolicStackItem& i);

struct SymbolicUpdate
{
    std::shared_ptr<SymbolicStackItem> loc;
    std::shared_ptr<SymbolicStackItem> val;
    friend std::ostream& operator<<(std::ostream&, const SymbolicUpdate&);
};

struct SymbolicStorage 
{
    SymbolicUpdate head;
    std::shared_ptr<SymbolicStorage> tail;
    friend std::ostream& operator<<(std::ostream&, std::shared_ptr<SymbolicStorage>);
};

struct Concrete
{
    uint256 concrete;
};

struct Sload 
{
    std::shared_ptr<SymbolicStackItem> addr;
    std::shared_ptr<SymbolicStorage> store;
};

struct Mload 
{
    std::shared_ptr<SymbolicStackItem> addr;
    std::shared_ptr<SymbolicStorage> memory;
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
struct AccessCold;

using SymbolicRequirement =
        std::variant<Equal, NotEqual, LessEqual>;

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

}