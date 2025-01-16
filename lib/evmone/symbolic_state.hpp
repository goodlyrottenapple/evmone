// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "memory.hpp"
#include "symbolic.hpp"
#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

namespace evmone
{

template <bool isSymbolic>
class SymbolicMemory;

template<>
class SymbolicMemory<false> {
public:
    SymbolicMemory() noexcept { }
};


template<class T>
struct View
{
    size_t offset;
    size_t size;
    T& ref;
    // const View& operator=(const View& other)
    // {
    //     offset = other.offset;
    //     size = other.size;
    //     ref = other.ref;
    //     return *this;
    // }
};

class BaseSymbolicMemory : public std::map<size_t, Slice8>
{
    size_t m_size;
public:
    [[nodiscard]] size_t size() const noexcept { return m_size; }

    void grow(size_t new_size) noexcept
    {
        m_size = new_size;
    }

    void clear() noexcept
    {
        m_size = 0;
        std::map<size_t, Slice8>::clear();
    }

    // returns two iterators for the range [lower ... upper] for all elements e, s.t. lower <= e < upper
    // if no such elements exist, returns nullopt
    std::optional<std::pair<iterator, iterator>> range(const size_t& lower, const size_t& upper)
    {
        assert(lower<=upper);
        auto lower_bound = find(lower);
        if(lower_bound == end()) lower_bound = std::map<size_t, Slice8>::upper_bound(lower);
        if(lower_bound == end()) return std::nullopt;
        auto upper_bound = std::map<size_t, Slice8>::lower_bound(upper);
        if(lower_bound->first <= upper_bound->first) return std::pair(lower_bound, ++upper_bound);
        else return std::nullopt;
    }

    // same as range but for iterating backwards from the upper value down to lower
    std::optional<std::pair<iterator, iterator>> range_rev(const size_t& lower, const size_t& upper)
    {
        assert(lower<=upper);
        auto lower_bound = find(lower);
        if(lower_bound == end()) lower_bound = std::map<size_t, Slice8>::upper_bound(lower);
        if(lower_bound == end()) return std::nullopt;
        auto upper_bound = std::map<size_t, Slice8>::lower_bound(upper);
        if(lower_bound->first <= upper_bound->first) return std::pair(upper_bound, --lower_bound);
        else return std::nullopt;
    }

    bool is_concrete(size_t index, size_t size)
    {
        if (size == 0) return true;
        assert(index+size <= m_size);
        return range(index, index+size) == std::nullopt;
    }

    void set_concrete(size_t index, size_t size)
    {
        auto m_range = range(index, index+size);
        if(m_range.has_value())
        {
            for (auto it = m_range.value().first; it != m_range.value().second;) erase(it++);
        }
    }

    void set(size_t index, Slice8&& v)
    {
        auto [it, _] = try_emplace(index);
        it->second = v;
    }

    template <typename T>
    void set(size_t dest, View<T>&& m)
    {
        auto m_range = m.ref.range(m.offset, m.offset+m.size);
        if(m_range.has_value())
        {
            for (auto m_it = m_range.value().first; m_it != m_range.value().second; ++m_it)
            {
                auto [it, _] = try_emplace((m_it->first - m.offset) + dest);
                it->second = m_it->second;
            }
            
        }
    }

    template <typename T>
    void set_rev(size_t dest, View<T>&& m)
    {
        auto m_range = m.ref.range_rev(m.offset, m.offset+m.size);
        if(m_range.has_value())
        {
            for (auto m_it = m_range.value().first; m_it != m_range.value().second; --m_it)
            {
                auto [it, _] = try_emplace((m_it->first - m.offset) + dest);
                it->second = m_it->second;
            }
            
        }
    }

};

template<>
class SymbolicMemory<true> : public BaseSymbolicMemory
{
    ArenaAllocator& arena;
public:
    SymbolicMemory(ArenaAllocator& a) : arena{a} {}

    inline SymbolicStackItemPtr load(const uint8_t* concrete_memory, size_t begin, size_t size)
    {
        if (is_concrete(begin,size)) return rc_ptr<SymbolicStackItem>();
        Slice&& sslice {};
        bool is_full_symbolic_word = true;
        rc_ptr_data<SymbolicStackItem>* symbolic_ptr = nullptr;

        for (size_t i = 0; i < 32; ++i)
        {
            if (auto it = find(begin + i); it != end())
            {
                sslice.word[i] = it->second;
                if(symbolic_ptr == nullptr) symbolic_ptr = sslice.word[i].symbolic.raw();
                is_full_symbolic_word = 
                    is_full_symbolic_word && 
                    sslice.word[i].symbolic.raw() == symbolic_ptr && 
                    sslice.word[i].concrete_or_offset == 31-i;
            }
            else
            {
                sslice.word[i] = {nullptr, concrete_memory[begin+i]};
                is_full_symbolic_word = false;
            }
        }
        if(is_full_symbolic_word) return sslice.word[0].symbolic;
        else return StackItem<true>::make_symbolic(arena, sslice);
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
        const auto [it, missing] = m[addr].try_emplace(k);

        if (!missing)
        {
            prev_value = it->second;
        }
        journal.emplace_back(addr, k, prev_value, type);
        if(v.is_pure()) it->second = StackItem<true>::make_symbolic(arena, v.val);
        else it->second = v.sval;
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
    SymbolicMemory<true>* symbolic = nullptr;
    const uint8_t* concrete = nullptr;
    size_t size = 0;
    size_t offset = 0;

    inline void clear()
    {
        symbolic = nullptr;
        concrete = nullptr;
        size = 0;
        size = offset;
    }

    inline void set(View<SymbolicMemory<true>>&& sm, const uint8_t* m)
    {
        symbolic = &sm.ref;
        concrete = m;
        size = sm.size;
        offset = sm.offset;
    }

    inline void set_concrete(size_t s, const uint8_t* m)
    {
        symbolic = nullptr;
        concrete = m;
        size = s;
    }

    inline SymbolicStackItemPtr load(size_t begin, size_t end)
    {
        assert(end-begin <= 32);
        assert(end <= size);
        if (!symbolic) return rc_ptr<SymbolicStackItem>();
        return symbolic->load(concrete, offset+begin, end-begin);
    }
};

class SymbolicReturndata : public BaseSymbolicMemory
{
public:
    bool is_concrete = true;

    void set_concrete(size_t size)
    {
        clear();
        grow(size);
        is_concrete = true;
    }

    void set(View<BaseSymbolicMemory>&& m)
    {
        clear();
        grow(m.size);
        BaseSymbolicMemory::set(0, std::move(m));
        is_concrete = false;
    }

    void clear()
    {
        BaseSymbolicMemory::clear();
        is_concrete = true;
    }
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
    SymbolicMemory<true> memory {arena};
    SymbolicStackItemPtr caller;
    SymbolicStackItemPtr callvalue;
    SymbolicCalldata calldata;
    SymbolicReturndata returndata;

    SymbolicState(ArenaAllocator& a, SymbolicRequirements& r, JournaledSymbolicState& j) : arena{a}, requirements{r}, journaled{j} {
    }

    void symbolic_value_matches_concrete(const StackItem<true>& i, std::convertible_to<const StackItem<true>&> auto... is)
    {
        if constexpr ( sizeof...( is ) > 0 )
            symbolic_value_matches_concrete( is... );

        if (StackItem<true>::is_symbolic(i.sval))
            requirements.push_back(SymbolicRequirement{Req::equal,i.sval, i.val});
    }

    inline SymbolicStackItemPtr keccak256_slice(const uint8_t* concrete_memory, size_t src, size_t size)
    {
        if(size == 0 || memory.is_concrete(src, size)) return SymbolicStackItemPtr();
        auto data = std::make_unique<Slice8[]>(size);
        for (size_t i = 0; i < size; i++)
        {
            if(auto it = memory.find(src+i); it != memory.end())
                data[i] = it->second;
            else
                data[i] = {nullptr, concrete_memory[src+i]};
        }
        return StackItem<true>::make_symbolic(arena, Keccak256 {std::move(data), size});
    }
};
}  // namespace evmone
