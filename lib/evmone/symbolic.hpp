#pragma once

#include "allocator.hpp"
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


class RefCounted
{
public:
    RefCounted() : ref_count(0) {}
	virtual ~RefCounted() {}

	void grab() const {++ref_count;}
    void release(ArenaAllocator* arena) const
	{
		assert(ref_count > 0);
		--ref_count;

		if(ref_count == 0) 
        {
            delete (RefCounted *)this;
            arena->free(this);
        }
	}

private:
    mutable size_t ref_count;
};


template < class T >
class rc_ptr
{
public:

    rc_ptr(T* ptr = nullptr, ArenaAllocator* a = nullptr) : mPtr(ptr), arena(a)
    {
        if(ptr != nullptr) {ptr->grab();}
    }

    rc_ptr(const rc_ptr &ptr) : mPtr(ptr.mPtr), arena(ptr.arena)
    {
        if(mPtr != nullptr) {mPtr->grab();}
    }

    ~rc_ptr()
    {
        if(mPtr != nullptr) {mPtr->release(arena);}
    }


    rc_ptr &operator=(T* ptr)
    {
        if(ptr != nullptr) {ptr->grab();}
        if(mPtr != nullptr) {mPtr->release(arena);}
        mPtr = ptr;
        return (*this);
    }

    //Assign another rc_ptr
    rc_ptr &operator=(const rc_ptr &ptr)
    {
        return (*this) = ptr.mPtr;
    }

    //Retrieve actual pointer
    T* get() const
    {
        return mPtr;
    }


    T* operator->() const {return mPtr;}		//x->member
    T &operator*() const {return *mPtr;}		//*x, (*x).member
    operator T*() const {return mPtr;}		//T* y = x;
    operator bool() const {return mPtr != nullptr;}	//if(x) {/*x is not nullptr*/}
    bool operator==(const rc_ptr &ptr) {return mPtr == ptr.mPtr;}
    bool operator==(const T *ptr) {return mPtr == ptr;}

    void swap(rc_ptr& other)
    {
        auto* this_mPtr = mPtr;
        auto* this_arena = arena;
        mPtr = other.mPtr;
        arena = other.arena;
        other.mPtr = this_mPtr;
        other.arena = this_arena;
    }

private:
    T *mPtr;
    ArenaAllocator* arena;
};

struct Pure;
template<typename>
struct Load;
template<typename>
struct Load2;
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

using SymbolicMemory = SymbolicUpdates<SymbolicMemoryUpdate>;

using Sload = Load<SymbolicStorage>;
using Mload = Load<SymbolicMemory>;


struct SymbolicStackItem2;

template<typename T>
struct SymbolicUpdates2
{
    // we should only ever have one evmc_address per SymbolicUpdates list
    union {
        evmc_address init;
        T head;
    };
    bool is_init;
    SymbolicUpdates2* tail;

    SymbolicUpdates2(evmc_address a) : init{a}, tail{nullptr}, is_init{true} { }
    SymbolicUpdates2(T&& h) : head{h}, tail{nullptr}, is_init{false} { }
    SymbolicUpdates2(T&& h, SymbolicUpdates2* t) : head{h}, tail{t}, is_init{false} { }
};


struct SymbolicStorageUpdate2
{
    rc_ptr<SymbolicStackItem2> loc;
    rc_ptr<SymbolicStackItem2> val;
    SymbolicStorageUpdate2 (const rc_ptr<SymbolicStackItem2>& l, const rc_ptr<SymbolicStackItem2>& v) { 
        loc = l;
        val = v;
    }
    // friend std::ostream& operator<<(std::ostream&, const SymbolicStorageUpdate2&);
};

enum class SymbolicMemoryUpdateTag { offset, update, set_symbolic, set_memory, set_empty };

struct SymbolicMemoryUpdate2
{
    union
    {
        struct 
        {
            rc_ptr<SymbolicStackItem2> offset;
            rc_ptr<SymbolicStackItem2> size;
        } offset; 
        struct 
        {
            rc_ptr<SymbolicStackItem2> loc;
            rc_ptr<SymbolicStackItem2> val;
        } update; 
        struct {
            size_t index;
            size_t size;
            SymbolicUpdates2<SymbolicMemoryUpdate2>* symbolic;
        } set_symbolic;
        struct {
            size_t index;
            size_t size;
            std::shared_ptr<uint8_t[]> mem;
        } set_memory;
    };
    SymbolicMemoryUpdateTag tag;

    SymbolicMemoryUpdate2 (const rc_ptr<SymbolicStackItem2>& a, const rc_ptr<SymbolicStackItem2>& b, SymbolicMemoryUpdateTag t) : tag{t}
    {
        assert(t == SymbolicMemoryUpdateTag::offset || t == SymbolicMemoryUpdateTag::update);
        if(t == SymbolicMemoryUpdateTag::offset) offset = {a,b};
        else update = {a,b};
    }
    SymbolicMemoryUpdate2 (size_t index, size_t size) : set_symbolic{index, size, nullptr}, tag{SymbolicMemoryUpdateTag::set_empty} { }
    SymbolicMemoryUpdate2 (size_t index, size_t size, SymbolicUpdates2<SymbolicMemoryUpdate2>* symbolic) : set_symbolic{index, size, symbolic}, tag{SymbolicMemoryUpdateTag::set_symbolic} { }
    SymbolicMemoryUpdate2 (size_t index, size_t size, std::shared_ptr<uint8_t[]> concrete) : set_memory{index, size, concrete}, tag{SymbolicMemoryUpdateTag::set_memory} { }
};


using SymbolicStorage2 = SymbolicUpdates2<SymbolicStorageUpdate2>;

using SymbolicMemory2 = SymbolicUpdates2<SymbolicMemoryUpdate2>;

using SymbolicStorageMap = std::map<evmc_address, SymbolicStorage2*, MapComparator>;


enum class SymbolicStackItemTag { pure, sload, mload, unaryOp, binaryOp, ternaryOp };

enum class UnOp { iszero, not_ };
std::ostream& operator<< (std::ostream&, const UnOp&);

enum class BinOp { add, mul, sub, div, sdiv, mod, smod, exp, signextend, lt, gt, slt, sgt, eq, and_, or_, xor_, byte, shl, shr, sar, keccak256 };
std::ostream& operator<< (std::ostream&, const BinOp&);

enum class TernOp { addmod, mulmod };
std::ostream& operator<< (std::ostream&, const TernOp&);

struct SymbolicStackItem2 : RefCounted
{
    union
    {
        uint256 pure;
        struct 
        {
            rc_ptr<SymbolicStackItem2> addr;
            SymbolicStorage2* symbolic_store;
        } sload;
        struct 
        {
            rc_ptr<SymbolicStackItem2> addr;
            SymbolicMemory2* symbolic_memory;
        } mload; 
        struct 
        {
            UnOp op;
            rc_ptr<SymbolicStackItem2> first;
        } unary; 
        struct 
        {
            BinOp op;
            rc_ptr<SymbolicStackItem2> first;
            rc_ptr<SymbolicStackItem2> second;
        } binary; 
        struct 
        {
            TernOp op;
            rc_ptr<SymbolicStackItem2> first;
            rc_ptr<SymbolicStackItem2> second;
            rc_ptr<SymbolicStackItem2> third;
        } ternary;
    };
    SymbolicStackItemTag tag;

    SymbolicStackItem2 (uint256 val), pure{val}, tag{SymbolicStackItemTag::pure} { }
    SymbolicStackItem2 (const rc_ptr<SymbolicStackItem2>& addr, SymbolicStorage2* symbolic_store) : sload{addr, symbolic_store}, tag{SymbolicStackItemTag::sload} { }
    SymbolicStackItem2 (const rc_ptr<SymbolicStackItem2>& addr, SymbolicMemory2* symbolic_memory) : mload{addr, symbolic_memory}, tag{SymbolicStackItemTag::mload} { }
    SymbolicStackItem2 (const UnOp& op, const rc_ptr<SymbolicStackItem2>& first) : unary{op, first}, tag{SymbolicStackItemTag::unaryOp} { }
    SymbolicStackItem2 (const BinOp& op, const rc_ptr<SymbolicStackItem2>& first, const rc_ptr<SymbolicStackItem2>& second), :binary{op, first, second}, tag{SymbolicStackItemTag::binaryOp} { }
    SymbolicStackItem2 (const TernOp& op, const rc_ptr<SymbolicStackItem2>& first, const rc_ptr<SymbolicStackItem2>& second, const rc_ptr<SymbolicStackItem2>& third) :ternary{op, first, second, third}, tag{SymbolicStackItemTag::ternaryOp} { }

    ~SymbolicStackItem2() 
    {
        switch (tag)
        {
        case SymbolicStackItemTag::sload:
            delete addr;
            delete symbolic_store;
            break;
        case SymbolicStackItemTag::mload:
            delete addr;
            delete symbolic_memory;
            break;
        case SymbolicStackItemTag::unaryOp:
            delete first;
            break;
        case SymbolicStackItemTag::binaryOp:
            delete first;
            delete second;
            break;
        case SymbolicStackItemTag::ternaryOp:
            delete first;
            delete second;
            delete third;
            break;
        default:
            break;
        } 
    }
};


using SymbolicStackItem =
        std::variant<Pure, Sload, Mload, UnaryOp, BinaryOp, TernaryOp>;

std::ostream& operator<<(std::ostream& os, const SymbolicStackItem& i);


struct Offset
{
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

struct UnaryOp
{
    UnOp op;
    std::shared_ptr<SymbolicStackItem> first;
};

struct BinaryOp
{
    BinOp op;
    std::shared_ptr<SymbolicStackItem> first;
    std::shared_ptr<SymbolicStackItem> second;
};

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
    rc_ptr<SymbolicStackItem2> sval;

    inline void set_symbolic(ArenaAllocator* arena, uint256 v)
    {
        auto *ptr = arena->alloc<SymbolicStackItem2>();
        ptr = new(ptr) SymbolicStackItem2(v);
        sval = ptr;
    }

    inline void set_symbolic(ArenaAllocator* arena, rc_ptr<SymbolicStackItem2>& addr, SymbolicStorage2* symbolic_store)
    {
        auto *ptr = arena->alloc<SymbolicStackItem2>();
        ptr = new(ptr) SymbolicStackItem2(addr, symbolic_store);
        sval = ptr;
    }

    inline void set_symbolic(ArenaAllocator* arena, rc_ptr<SymbolicStackItem2>& addr, SymbolicMemory2* symbolic_memory)
    {
        auto *ptr = arena->alloc<SymbolicStackItem2>();
        ptr = new(ptr) SymbolicStackItem2(addr, symbolic_memory);
        sval = ptr;
    }

    inline void set_symbolic(ArenaAllocator* arena, uint256 addr_concrete, SymbolicMemory2* symbolic_memory)
    {
        auto *addr_ptr = arena->alloc<SymbolicStackItem2>();
        addr_ptr = new(addr_ptr) SymbolicStackItem2(addr_concrete);
        auto *ptr = arena->alloc<SymbolicStackItem2>();
        ptr = new(ptr) SymbolicStackItem2(rc_ptr(addr_ptr, arena), symbolic_memory);
        sval = ptr;
    }

    inline void set_symbolic(ArenaAllocator* arena, const UnOp& op, rc_ptr<SymbolicStackItem2>& first)
    {
        auto *ptr = arena->alloc<SymbolicStackItem2>();
        if (first->tag == SymbolicStackItemTag::pure)
            ptr = new(ptr) SymbolicStackItem2(val);
        else
            ptr = new(ptr) SymbolicStackItem2(op, first);
        sval = ptr;
    }

    inline void set_symbolic(ArenaAllocator* arena, const BinOp& op, rc_ptr<SymbolicStackItem2>& first, rc_ptr<SymbolicStackItem2>& second)
    {
        auto *ptr = arena->alloc<SymbolicStackItem2>();
        if (first->tag == SymbolicStackItemTag::pure && second->tag == SymbolicStackItemTag::pure)
            ptr = new(ptr) SymbolicStackItem2(val);
        else
            ptr = new(ptr) SymbolicStackItem2(op, first, second);
        sval = ptr;
    }

    inline void set_symbolic(ArenaAllocator* arena, const TernOp& op, rc_ptr<SymbolicStackItem2>& first, rc_ptr<SymbolicStackItem2>& second, rc_ptr<SymbolicStackItem2>& third)
    {
        auto *ptr = arena->alloc<SymbolicStackItem2>();
        if (first->tag == SymbolicStackItemTag::pure && second->tag == SymbolicStackItemTag::pure && third->tag == SymbolicStackItemTag::pure)
            ptr = new(ptr) SymbolicStackItem2(val);
        else
            ptr = new(ptr) SymbolicStackItem2(op, first, second, third);
        sval = ptr;
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
    rc_ptr<SymbolicStackItem2> sval;
    uint256 val;
};

struct NotEqual
{
    rc_ptr<SymbolicStackItem2> sval;
    uint256 val;
};

struct LessEqual
{
    rc_ptr<SymbolicStackItem2> sval;
    uint256 val;
};

struct Greater
{
    rc_ptr<SymbolicStackItem2> sval;
    uint256 val;
};

}