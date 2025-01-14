#include "symbolic.hpp"
#include <ethash/keccak.hpp>
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
    };
    return os;
}

std::ostream& operator<< (std::ostream& os, const TernOp& op)
{
    switch (op)
    {
        case TernOp::addmod : return os << "addmod" ;
        case TernOp::mulmod : return os << "mulmod";
    };
    return os;
}

std::ostream& operator<<(std::ostream& os, const SymbolicStackItem& si) {
    std::visit(Cases{
        [&](const uint256& i) { os << "0x" << intx::hex(i); },
        [&](const Sload& i) { os << "LOAD(0x" << intx::hex(intx::be::load<uint256>(i.key)) << ")"; },
        [&](const Slice&) { os << "SLICE..."; },
        [&](const Keccak256&i) { 
            os << "Keccak256([";
            for (size_t j = 0; j < i.size; j++)
            {
                if(i.data[j].is_concrete()) os << static_cast<int>(i.data[j].concrete_or_offset);
                else  os << *i.data[j].symbolic << " ! " << static_cast<int>(i.data[j].concrete_or_offset);
                if(j < i.size-1) os << ", ";
            }
            os << "], " << i.size << ")"; },
        [&](const UnaryOp& i) { os << "(" << i.op << " " << *i.first << ")"; },
        [&](const BinaryOp& i) { os << "(" << *i.first << " " << i.op << " " << *i.second << ")"; },
        [&](const TernaryOp& i) { os << "(" << i.op << " " << *i.first << *i.second << *i.third << ")"; }
    }, si);
    return os;
}

uint8_t slice8(uint256& x, uint8_t idx)
{
    assert(idx < 32);
    return intx::as_bytes(x)[idx];
}


bool eval(std::function<evmc_bytes32(evmc::address&, evmc_bytes32&)> get_storage, std::vector<std::variant<SymbolicStackItemPtr, SymbolicRequirement>> stack)
{
    bool reqs_valid = true;
    while(!stack.empty() && reqs_valid)
    {
        std::visit(Cases{
            [&](SymbolicStackItemPtr& ptr) {
                assert(ptr); //rc_ptr doesn't hold a nullptr
                std::visit(Cases{
                    [&](uint256&) { stack.pop_back(); },
                    [&](Sload& sl) 
                    { 
                        *ptr = intx::be::load<uint256>(get_storage(sl.addr, sl.key));
                        stack.pop_back();
                    },
                    [&](Slice& s) 
                    { 
                        bool word_evald = true;
                        for (size_t i = 0; i < 32; i++)
                        {
                            if(!s.word[i].is_concrete() && StackItem<true>::is_symbolic(s.word[i].symbolic))
                            {
                                stack.push_back(s.word[i].symbolic);
                                word_evald = false;
                            }
                        }
                        if(word_evald)
                        {
                            uint8_t data[32]; 
                            for (size_t i = 0; i < 32; i++)
                            {
                                if(s.word[i].is_concrete())
                                    data[i] = s.word[i].concrete_or_offset;
                                else
                                    data[i] = slice8(std::get<uint256>(*s.word[i].symbolic), s.word[i].concrete_or_offset);
                            }
                            *ptr = intx::be::unsafe::load<uint256>(data);
                            stack.pop_back();
                        }
                    },
                    [&](UnaryOp& u)
                    { 
                        assert(u.first);
                        if(StackItem<true>::is_pure(u.first))
                        {
                            const auto& x = std::get<uint256>(*u.first);
                            switch (u.op)
                            {
                            case UnOp::iszero:
                                *ptr = x == 0;
                                break;
                            case UnOp::not_:
                                *ptr = ~ x;
                                break;
                            }
                            stack.pop_back();
                        }
                        else
                        {
                            stack.push_back(u.first);
                        }
                    },
                    [&](BinaryOp& b)
                    { 
                        assert(b.first);
                        assert(b.second);
                        if(StackItem<true>::is_pure(b.first) && StackItem<true>::is_pure(b.second))
                        {
                            const auto& x = std::get<uint256>(*b.first);
                            const auto& y = std::get<uint256>(*b.second);
                            switch (b.op)
                            {
                            case BinOp::add:
                                *ptr = x + y;
                                break;
                            case BinOp::mul:
                                *ptr = x * y;
                                break;
                            case BinOp::sub:
                                *ptr = x - y;
                                break;
                            case BinOp::div:
                                *ptr = y != 0 ? x / y : 0;
                                break;
                            case BinOp::sdiv:
                                *ptr = y != 0 ? intx::sdivrem(x, y).quot : 0;
                                break;
                            case BinOp::mod:
                                *ptr = y != 0 ? x % y : 0;
                                break;
                            case BinOp::smod:
                                *ptr = y != 0 ? intx::sdivrem(x, y).rem : 0;
                                break;
                            case BinOp::exp:
                                *ptr = intx::exp(x, y);
                                break;
                            case BinOp::signextend:
                            {
                                auto n = y;
                                if (x < 31)  // For 31 we also don't need to do anything.
                                {
                                    const auto e = x[0];  // uint256 -> uint64.
                                    const auto sign_word_index =
                                        static_cast<size_t>(e / sizeof(e));      // Index of the word with the sign bit.
                                    const auto sign_byte_index = e % sizeof(e);  // Index of the sign byte in the sign word.
                                    auto& sign_word = n[sign_word_index];

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
                                        n[i] = sign_ex;  // Clear extended words.
                                }
                                *ptr = n;
                                break;
                            }
                            case BinOp::lt:
                                *ptr = x < y;
                                break;
                            case BinOp::gt:
                                *ptr = y < x;
                                break;
                            case BinOp::slt:
                                *ptr = slt(x, y);
                                break;
                            case BinOp::sgt:
                                *ptr = slt(y, x);
                                break;
                            case BinOp::eq:
                                *ptr = x == y;
                                break;
                            case BinOp::and_:
                                *ptr = x & y;
                                break;
                            case BinOp::or_:
                                *ptr = x | y;
                                break;
                            case BinOp::xor_:
                                *ptr = x ^ y;
                                break;
                            case BinOp::byte:
                            {
                                const bool n_valid = x < 32;
                                const uint64_t byte_mask = (n_valid ? 0xff : 0);
                                const auto index = 31 - static_cast<unsigned>(x[0] % 32);
                                const auto word = y[index / 8];
                                const auto byte_index = index % 8;
                                const auto byte = (word >> (byte_index * 8)) & byte_mask;
                                *ptr = byte;
                                break;
                            }
                            case BinOp::shl:
                                *ptr = y << x;
                                break;
                            case BinOp::shr:
                                *ptr = y >> x;
                                break;
                            case BinOp::sar:
                            {
                                const bool is_neg = static_cast<int64_t>(y[3]) < 0;  // Inspect the top bit (words are LE).
                                const auto sign_mask = is_neg ? ~uint256{} : uint256{};

                                const auto mask_shift = (x < 256) ? (256 - x[0]) : 0;
                                *ptr = (y >> x) | (sign_mask << mask_shift);
                                break;
                            }
                            }
                            stack.pop_back();
                        }
                        else
                        {
                            if(!StackItem<true>::is_pure(b.first)) stack.push_back(b.first);
                            if(!StackItem<true>::is_pure(b.second)) stack.push_back(b.second);
                        }
                    },
                    [&](TernaryOp& t)
                    {
                        assert(t.first);
                        assert(t.second);
                        assert(t.third);
                        if(StackItem<true>::is_pure(t.first) && StackItem<true>::is_pure(t.second) && StackItem<true>::is_pure(t.third))
                        {
                            const auto& x = std::get<uint256>(*t.first);
                            const auto& y = std::get<uint256>(*t.second);
                            const auto& m = std::get<uint256>(*t.third);

                            switch (t.op)
                            {
                            case TernOp::addmod:
                                *ptr = m != 0 ? intx::addmod(x, y, m) : 0;    
                                break;
                            case TernOp::mulmod:
                                *ptr = m != 0 ? intx::mulmod(x, y, m) : 0;
                                break;
                            }
                            stack.pop_back();
                        }
                        else
                        {
                            if(!StackItem<true>::is_pure(t.first)) stack.push_back(t.first);
                            if(!StackItem<true>::is_pure(t.second)) stack.push_back(t.second);
                            if(!StackItem<true>::is_pure(t.third)) stack.push_back(t.third);
                        }
                    },
                    [&](Keccak256& k) 
                    {
                        if(k.size == 0)
                        {
                            *ptr = intx::be::load<uint256>(ethash::keccak256(nullptr, k.size));
                            stack.pop_back();
                        }
                        else
                        {
                            bool data_evald = true;
                            for (size_t i = 0; i < k.size; i++)
                            {
                                if(!k.data[i].is_concrete() && StackItem<true>::is_symbolic(k.data[i].symbolic))
                                {
                                    stack.push_back(k.data[i].symbolic);
                                    data_evald = false;
                                }
                            }
                            if(data_evald)
                            {
                                auto data = std::make_unique<uint8_t[]>(k.size); 
                                for (size_t i = 0; i < k.size; i++)
                                {
                                    if(k.data[i].is_concrete())
                                        data[i] = k.data[i].concrete_or_offset;
                                    else
                                        data[i] = slice8(std::get<uint256>(*k.data[i].symbolic), k.data[i].concrete_or_offset);
                                }
                                *ptr = intx::be::load<uint256>(ethash::keccak256(data.get(), k.size));
                                stack.pop_back();
                            }
                        }
                    }
                }, *ptr);
            },
            [&](SymbolicRequirement& r) 
            { 
                assert(r.sval);
                if(StackItem<true>::is_pure(r.sval))
                {
                    switch (r.op)
                    {
                    case Req::equal:
                        if (!(std::get<uint256>(*r.sval) == r.val)) reqs_valid = false;
                        break;
                    case Req::notEqual:
                        if (!(std::get<uint256>(*r.sval) != r.val)) reqs_valid = false;
                        break;
                    case Req::lessEqual:
                        if (!(std::get<uint256>(*r.sval) <= r.val)) reqs_valid = false;
                        break;
                    case Req::greater:
                        if (!(std::get<uint256>(*r.sval) > r.val)) reqs_valid = false;
                        break;
                    }
                    stack.pop_back();
                }
                else
                {
                    stack.push_back(r.sval);
                }
            },
        }, stack.back());
    }
    return reqs_valid;
}




}