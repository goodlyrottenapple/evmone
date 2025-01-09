// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "symbolic.hpp"
#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

namespace evmone
{
static const char zeros [16] {};

struct SymbolicMemoryLocation
{
    // symbolic = nullptr means the memory location has a concrete value stored in concrete_or_offset
    // otherwise concrete_or_offset an ofset of 0 to 31 bytes into the symbolic value
    rc_ptr_data<SymbolicStackItem>* symbolic;
    uint8_t concrete_or_offset;
    uint8_t is_concrete;

    inline bool is_conrete()
    {
        if (memcmp(this, zeros, sizeof(SymbolicMemoryLocation)) == 0) return true;
        return symbolic == nullptr;
    }

    // void zero(bool init = false)
    // {
    //     // if(!init && symbolic != nullptr) rc_ptr<SymbolicStackItem>::release(symbolic);
    //     symbolic = nullptr;
    //     concrete_or_offset = 0;
    // }

    // void acquire()
    // {
    //     if (memcmp(this, zeros, sizeof(SymbolicMemoryLocation)) == 0) return;
    //     if(symbolic != nullptr) rc_ptr<SymbolicStackItem>::acquire(symbolic);
    // }

    SymbolicMemoryLocation &operator=(uint8_t v)
    {
        // if(memcmp(this, zeros, sizeof(SymbolicMemoryLocation)) != 0 && symbolic != nullptr) rc_ptr<SymbolicStackItem>::release(symbolic);
        symbolic = nullptr;
        concrete_or_offset = v;
        return *this;
    }

    SymbolicMemoryLocation &operator=(Slice8&& o)
    {
        // if(memcmp(this, zeros, sizeof(SymbolicMemoryLocation)) != 0 && symbolic != nullptr) rc_ptr<SymbolicStackItem>::release(symbolic);
        if(o.symbolic.raw() != nullptr)
        {
            assert(o.concrete_or_offset < 32);
            assert(StackItem<true>::is_symbolic(o.symbolic));
            concrete_or_offset = o.concrete_or_offset;
            symbolic = o.symbolic.raw();
            rc_ptr<SymbolicStackItem>::lock(symbolic);
        }
        else
        {
            concrete_or_offset = o.concrete_or_offset;
            symbolic = nullptr;
        }
        return *this;
    }

    uint8_t get_concrete()
    {
        assert(is_conrete());
        return concrete_or_offset;
    }

    Slice8 get_symbolic()
    {
        if (memcmp(this, zeros, sizeof(SymbolicMemoryLocation)) == 0) return {rc_ptr<SymbolicStackItem>(), 0};
        if(symbolic != nullptr) rc_ptr<SymbolicStackItem>::acquire(symbolic);
        return {rc_ptr(symbolic), concrete_or_offset};
    }
};


struct FreeDeleter
{
    void operator()(SymbolicMemoryLocation* p) const noexcept { std::free(p); }
};


using SymbolicMemoryPtr = std::unique_ptr<SymbolicMemoryLocation[], FreeDeleter>;

template <bool isSymbolic>
class SymbolicMemory;

template<>
class SymbolicMemory<false> {
public:
    SymbolicMemory() noexcept { }
};

template<>
class SymbolicMemory<true>
{
    /// The size of allocation "page".
    static constexpr size_t page_size = 4 * 1024;

    /// Owned pointer to allocated memory.
    SymbolicMemoryPtr m_data;

    /// The "virtual" size of the memory.
    size_t m_size = 0;

    /// The size of allocated memory. The initialization value is the initial capacity.
    size_t m_capacity = page_size;

    [[noreturn, gnu::cold]] static void handle_out_of_memory() noexcept { std::terminate(); }

    void allocate_capacity() noexcept
    {
        m_data.reset(static_cast<SymbolicMemoryLocation*>(std::realloc(m_data.release(), sizeof(SymbolicMemoryLocation) * m_capacity)));
        if (!m_data) [[unlikely]]
            handle_out_of_memory();
    }

public:
    /// Creates Memory object with initial capacity allocation.
    SymbolicMemory() noexcept { allocate_capacity(); }

    SymbolicMemoryLocation& operator[](size_t index) noexcept { return m_data[index]; }

    [[nodiscard]] SymbolicMemoryLocation* data() const noexcept { return m_data.get(); }
    [[nodiscard]] size_t size() const noexcept { return m_size; }

    /// Grows the memory to the given size. The extent is filled with zeros.
    ///
    /// @param new_size  New memory size. Must be larger than the current size and multiple of 32.
    void grow(size_t new_size) noexcept
    {
        // Restriction for future changes. EVM always has memory size as multiple of 32 bytes.
        INTX_REQUIRE(new_size % 32 == 0);

        // Allow only growing memory. Include hint for optimizing compiler.
        INTX_REQUIRE(new_size > m_size);

        if (new_size > m_capacity)
        {
            m_capacity *= 2;  // Double the capacity.

            if (m_capacity < new_size)  // If not enough.
            {
                // Set capacity to required size rounded to multiple of page_size.
                m_capacity = ((new_size + (page_size - 1)) / page_size) * page_size;
            }

            allocate_capacity();
            // for (size_t i = m_size; i < m_capacity; i++)
            // {
            //     m_data[i].zero(true);
            // }
        } 
        memset(&m_data[m_size], 0, (new_size - m_size) * sizeof(SymbolicMemoryLocation));
        // if (m_size_initialised < new_size)
        // {
        //     for (size_t i = m_size_initialised; i < new_size; i++)
        //     {
        //         m_data[i].zero(true);
        //     }
        //     m_size_initialised = new_size;
        // }
        m_size = new_size;
    }

    /// Virtually clears the memory by setting its size to 0. The capacity stays unchanged.
    void clear() noexcept
    {
        m_size = 0;
    }
};

using SymbolicRequirements = std::vector<SymbolicRequirement>;


enum class JournalEntryType {StoreChange, TstoreChange};

struct JournalEntry
{
    evmc::address addr;
    evmc::bytes32 key;
    std::optional<SymbolicStackItemPtr> prev_value;
    JournalEntryType type;
};

class JournaledSymbolicState
{
    ArenaAllocator& arena;
    std::vector<JournalEntry> journal;
public:
    SymbolicStorageMap stores;
    SymbolicStorageMap tstores;
    JournaledSymbolicState(ArenaAllocator& a) : arena{a} {}

    void reset()
    {
        journal.clear();
        stores.clear();
        tstores.clear();
    }

    // set up the symbolic store by looking up any previous symbolic state at the recipient address,
    // in case we are in a nested context, otherwise initialise an empty store forthe address
    inline void init_address(evmc::address addr)
    {
        if (auto search = stores.find(addr); search == stores.end())
        {
            stores[addr] = SymbolicStorage();
        }
        if (auto search = tstores.find(addr); search == tstores.end())
        {
            tstores[addr] = SymbolicStorage();
        }
    }

    void get_(SymbolicStorageMap& m, evmc::address addr, evmc::bytes32 key, SymbolicStackItemPtr& sval, bool is_tload = false)
    {
        if (auto search = m[addr].find(key); search != m[addr].end())
        {
            sval = search->second;
        }
        else
        {
            if (is_tload)
            {
                sval = rc_ptr<SymbolicStackItem>();
            }
            else
            {
                if(sval.counter() == 1) *sval = Sload {addr, key};
                else sval = StackItem<true>::make_symbolic(arena, Sload {addr, key});
            }
        }
    }

    inline void get_store(evmc::address addr, evmc::bytes32 key, SymbolicStackItemPtr& sval)
    {
        get_(stores, addr, key, sval);
    }

    inline void get_tstore(evmc::address addr, evmc::bytes32 key, SymbolicStackItemPtr& sval)
    {
        get_(tstores, addr, key, sval, true);
    }


    void update_(SymbolicStorageMap& m, JournalEntryType&& type, evmc::address addr, evmc_bytes32 k, StackItem<true> v)
    {
        std::optional<SymbolicStackItemPtr>&& prev_value = std::nullopt;
        if (auto search = m[addr].find(k); search != m[addr].end())
        {
            prev_value = search->second;
        }
        journal.emplace_back(addr, k, prev_value, type);
        if(v.is_pure()) m[addr][k] = StackItem<true>::make_symbolic(arena, v.val);
        else m[addr][k] = v.sval;
    }

    inline void update_store(evmc::address addr, evmc::bytes32 k, StackItem<true> v)
    {
        update_(stores, JournalEntryType::StoreChange, addr, k, v);
    }

    inline void update_tstore(evmc::address addr, evmc::bytes32 k, StackItem<true> v)
    {
        update_(tstores, JournalEntryType::TstoreChange, addr, k, v);
    }

    inline size_t checkpoint()
    {
        return journal.size();
    }

    void rollback(size_t checkpoint)
    {
        while (journal.size() != checkpoint)
        {
            auto& j = journal.back();
            auto& selected_store = j.type == JournalEntryType::StoreChange ? stores : tstores;
            if(j.prev_value)
                selected_store[j.addr][j.key] = j.prev_value.value();
            else  selected_store[j.addr].erase(j.key);
            journal.pop_back();
        }
    }
};

struct SymbolicCalldata
{
    bool is_concrete;
    union {
        SymbolicMemoryLocation* symbolic;
        const uint8_t* concrete;
    };
    size_t size;
};

template <bool isSymbolic>
class SymbolicState;

template <>
class SymbolicState<false> 
{
public:
    SymbolicMemory<false> memory;
    SymbolicState() {}
};


template <>
class SymbolicState<true>
{
public:

    ArenaAllocator& arena;
    SymbolicRequirements& requirements;
    JournaledSymbolicState& journaled;
    evmc::address address;
    SymbolicMemory<true> memory;
    SymbolicStackItemPtr caller;
    SymbolicStackItemPtr callvalue;
    SymbolicCalldata calldata {true, nullptr, 0};
    SymbolicMemoryPtr returndata = nullptr;
    size_t returndata_size = 0;

    SymbolicState(ArenaAllocator& a, SymbolicRequirements& r, JournaledSymbolicState& j) : arena{a}, requirements{r}, journaled{j} {}

    void symbolic_value_matches_concrete(const StackItem<true>& i, std::convertible_to<const StackItem<true>&> auto... is)
    {
        if constexpr ( sizeof...( is ) > 0 )
            symbolic_value_matches_concrete( is... );

        if (StackItem<true>::is_symbolic(i.sval))
            requirements.push_back(SymbolicRequirement{Req::equal,i.sval, i.val});
    }

    // static inline void reset_symbolic_memory_ptr(SymbolicMemoryLocation* m, size_t size)
    // {
    //     for (size_t i = 0; i < size; i++)
    //     {
    //         m[i].zero();
    //     }
    // }

    // static inline void acquire_symbolic_memory_ptr(SymbolicMemoryLocation* m, size_t size)
    // {
    //     for (size_t i = 0; i < size; i++)
    //     {
    //         m[i].acquire();
    //     }
    // }

    static void set_(SymbolicMemoryPtr& dst, size_t& dst_size, size_t src_offset, size_t src_size, const uint8_t* src)
    {
        // if(dst) reset_symbolic_memory_ptr(dst.get(), dst_size);
        dst_size = src_size;
        if(src_size > 0)
        {
            dst.reset(static_cast<SymbolicMemoryLocation*>(std::realloc(dst.release(), sizeof(SymbolicMemoryLocation) * src_size)));
            // memset(dst.get(), 0, src_size * sizeof(SymbolicMemoryLocation));
            for (size_t i = 0; i < src_size; i++)
            {
                // dst[i].zero(true);
                dst[i] = src[i+src_offset];
            }
        }
        else
            dst = nullptr;
    }

    void set_(SymbolicMemoryPtr& dst, size_t& dst_size, size_t src_offset, size_t src_size, const SymbolicMemoryLocation* src)
    {
        // if(dst) reset_symbolic_memory_ptr(dst.get(), dst_size);
        dst_size = src_size;
        if(src_size > 0)
        {
            dst.reset(static_cast<SymbolicMemoryLocation*>(std::realloc(dst.release(), sizeof(SymbolicMemoryLocation) * src_size)));
            std::memcpy(dst.get(), &src[src_offset], sizeof(SymbolicMemoryLocation) * src_size);
            // acquire_symbolic_memory_ptr(dst.get(), dst_size);
        }
        else
            dst = nullptr;
    }

    inline void set_calldata()
    {
        calldata.is_concrete = true;
        calldata.concrete = nullptr;
        calldata.size = 0;
        // set_(calldata, calldata_size, 0, 0, (uint8_t*)nullptr);
    }

    inline void set_calldata(size_t size, SymbolicMemoryLocation* m)
    {
        calldata.is_concrete = false;
        calldata.symbolic = m;
        calldata.size = size;
    }

    inline void set_calldata(size_t size, const uint8_t* m)
    {
        calldata.is_concrete = true;
        calldata.concrete = m;
        calldata.size = size;
    }

    inline SymbolicStackItemPtr load_calldata(size_t begin, size_t end)
    {
        assert((end - begin) <= 32);
        assert(end <= calldata.size);
        if (calldata.is_concrete) return rc_ptr<SymbolicStackItem>();

        Slice&& symbolic {};
        bool all_pure = true;
        bool is_full_symbolic_word = (end - begin) == 32;
        rc_ptr_data<SymbolicStackItem>* symbolic_ptr = nullptr;

        for (size_t i = 0; i < (end - begin); ++i)
        {
            if(calldata.symbolic[begin + i].is_conrete()){
                symbolic.word[i] = calldata.symbolic[begin + i].get_symbolic();
                is_full_symbolic_word = false;
            }
            else
            {
                all_pure = false;
                symbolic.word[i] = calldata.symbolic[begin + i].get_symbolic();
                if(symbolic_ptr == nullptr) symbolic_ptr = symbolic.word[i].symbolic.raw();
                is_full_symbolic_word = 
                    is_full_symbolic_word && 
                    symbolic.word[i].symbolic.raw() == symbolic_ptr && 
                    symbolic.word[i].concrete_or_offset == i;
            }
        }
        if(all_pure)
        {
            return rc_ptr<SymbolicStackItem>();
        }
        else if(is_full_symbolic_word) return symbolic.word[0].symbolic;
        else return StackItem<true>::make_symbolic(arena, symbolic);
    }

    inline void set_returndata()
    {
        set_(returndata, returndata_size, 0, 0, (uint8_t*)nullptr);
    }

    inline void set_returndata(size_t offset, size_t size, const SymbolicMemoryLocation* m)
    {
        set_(returndata, returndata_size, offset, size, m);
    }

    inline void set_returndata(size_t offset, size_t size, const uint8_t* m)
    {
        set_(returndata, returndata_size, offset, size, m);
    }

    inline void update_memory(size_t dst, size_t size, SymbolicMemoryLocation* m)
    {
        // reset_symbolic_memory_ptr(&memory[dst], size);
        std::memcpy(&memory[dst], m, sizeof(SymbolicMemoryLocation) * size);
        // acquire_symbolic_memory_ptr(m, size);
    }


    // inline void update_memory(size_t dst, size_t s, const uint8_t* ptr)
    // {
    //     for (size_t i = 0; i < s; i++)
    //     {
    //         memory[dst+i] = ptr[i];
    //     }
    // }

    inline SymbolicStackItemPtr keccak256_slice(size_t src, size_t size)
    {
        if(size == 0) return SymbolicStackItemPtr();
        auto data = std::make_unique<Slice8[]>(size);
        bool all_concrete = true;
        for (size_t i = 0; i < size; i++)
        {
            data[i] = memory[src+i].get_symbolic();
            if(!memory[src+i].is_conrete()) all_concrete = false;
        }
        if(all_concrete) return rc_ptr<SymbolicStackItem>();
        else return StackItem<true>::make_symbolic(arena, Keccak256 {std::move(data), size});
    }

    inline void reset_memory(size_t index, size_t size)
    {
        memset(&memory[index], 0 , size * sizeof(SymbolicMemoryLocation));
        // reset_symbolic_memory_ptr(&memory[index], size);
    }


    inline void reset_memory() noexcept
    {
        memory.clear();
    }

    inline SymbolicStackItemPtr load_memory(size_t begin)
    {
        Slice&& symbolic {};
        bool all_pure = true;
        bool is_full_symbolic_word = true;
        rc_ptr_data<SymbolicStackItem>* symbolic_ptr = nullptr;

        for (size_t i = 0; i < 32; ++i)
        {
            if(memory[begin + i].is_conrete()){
                symbolic.word[i] = memory[begin + i].get_symbolic();
                is_full_symbolic_word = false;
            }
            else
            {
                all_pure = false;
                symbolic.word[i] = memory[begin + i].get_symbolic();
                if(symbolic_ptr == nullptr) symbolic_ptr = symbolic.word[i].symbolic.raw();
                is_full_symbolic_word = 
                    is_full_symbolic_word && 
                    symbolic.word[i].symbolic.raw() == symbolic_ptr && 
                    symbolic.word[i].concrete_or_offset == 31-i;
            }
        }
        if(all_pure)
        {
            return rc_ptr<SymbolicStackItem>();
        }
        else if(is_full_symbolic_word) return symbolic.word[0].symbolic;
        else return StackItem<true>::make_symbolic(arena, symbolic);
    }
};
}  // namespace evmone
