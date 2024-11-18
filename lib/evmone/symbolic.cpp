#include "symbolic.hpp"
#include <intx/intx.hpp>
#include <variant>


namespace evmone
{

std::ostream& operator<< (std::ostream& os, const UnOp& op)
{
    switch (op)
    {
        case UnOp::iszero : return os << "iszero" ;
        case UnOp::not_: return os << "not";
    };
    return os;
}

std::ostream& operator<< (std::ostream& os, const BinOp& op)
{
    switch (op)
    {
        case BinOp::add : return os << "+" ;
        case BinOp::mul : return os << "*";
        case BinOp::sub : return os << "-" ;
        case BinOp::div : return os << "`div`" ;
        case BinOp::sdiv : return os << "`sdiv`" ;
        case BinOp::mod : return os << "`mod`" ;
        case BinOp::smod : return os << "`smod`" ;
        case BinOp::exp : return os << "^" ;
        case BinOp::signextend : return os << "signextend" ;
        case BinOp::lt : return os << "<=" ;
        case BinOp::gt : return os << ">=" ;
        case BinOp::slt : return os << "<" ;
        case BinOp::sgt : return os << ">" ;
        case BinOp::eq : return os << "==" ;
        case BinOp::and_ : return os << "&&" ;
        case BinOp::or_ : return os << "||" ;
        case BinOp::xor_ : return os << "`xor`" ;
        case BinOp::byte : return os << "`byte`" ;
        case BinOp::shl : return os << "<<" ;
        case BinOp::shr : return os << ">>" ;
        case BinOp::sar : return os << "`sar`" ;
        case BinOp::keccak256 : return os << "`keccak256`" ;
    };
    return os;
}

std::ostream& operator<< (std::ostream& os, const TernOp& op)
{
    switch (op)
    {
        case TernOp::addmod : return os << "addmod" ;
        case TernOp::mulmod: return os << "mulmod";
    };
    return os;
}

std::ostream& operator<<(std::ostream& os, const SymbolicStackItem& si) {
    std::visit(Cases{
        [&](const Pure& i) { os << "0x" << intx::hex(i.pure);  },
        [&](const Sload& i) { os << "SLOAD(" << *i.addr << ", $" << &*i.store << ")"; },
        [&](const Mload&i) { os << "MLOAD(" << *i.addr << ", $" << &*i.memory << ")"; },
        [&](const Tload&i) { os << "TLOAD(" << *i.addr << ", $" << &*i.store << ")"; },
        [&](const UnaryOp& i) { os << "(" << i.op << " " << *i.first << ")"; },
        [&](const BinaryOp& i) { os << "(" << *i.first << " " << i.op << " " << *i.second << ")"; },
        [&](const TernaryOp& i) { os << "(" << i.op << " " << *i.first << *i.second << *i.third << ")"; }
    }, si);
    return os;
}

std::ostream& operator<<(std::ostream& os, const SetItem& i)
{
    return os << *i.loc << " -> " << *i.val; 
}

std::ostream& operator<<(std::ostream& os, const SetMem& i)
{
    return os << "set(" << i.index << ", " << i.size << ", <copied mem>)"; 
}

std::ostream& operator<<(std::ostream& os, const SetZeros& i)
{
    return os << "set_zeros(" << i.index << ", " << i.size << ")"; 
}

std::ostream& operator<<(std::ostream& os, const SymbolicMemoryUpdate& si) {
    std::visit(Cases{
        [&](const SetItem& i) { os << i;  },
        [&](const SetMem& i) { os << i; },
        [&](const SetZeros&i) { os << i; }
    }, si);
    return os;
}

template <typename T>
std::ostream& operator<<(std::ostream& os, std::shared_ptr<SymbolicUpdates<T>> i)
{
    if(i == nullptr) {
        os << "$0:              init\n" << std::flush;
        return os;
    }
    os << "$" << &*i << ": " << i->head << " ;\n";
    os << i->tail;
    return os; 
}


std::ostream& operator<<(std::ostream& os, const SymbolicRequirement& si) {
    std::visit(Cases{
        [&](const Equal& i) { os << *i.sval << " == " << "0x" << intx::hex(i.val); },
        [&](const NotEqual& i) { os << *i.sval << " != " << "0x" << intx::hex(i.val); },
        [&](const LessEqual& i) { os << *i.sval << " <= " << "0x" << intx::hex(i.val); },
        [&](const MemEqual& i) { os << "slice(" << i.off << ", " << i.size << ", $" << &*i.smemory << ") == <copied mem>"; }
    }, si);
    return os;
}

}