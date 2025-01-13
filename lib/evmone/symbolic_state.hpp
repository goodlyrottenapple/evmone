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
struct SymbolicMemoryLocation
{
    // symbolic = nullptr means the memory location has a concrete value stored in concrete_or_offset
    // otherwise concrete_or_offset an ofset of 0 to 31 bytes into the symbolic value
    rc_ptr_data<SymbolicStackItem>* symbolic;
    uint8_t offset;

    inline bool is_in_concrete_memory();

    SymbolicMemoryLocation &operator=(Slice8&& o)
    {
        assert(o.symbolic.raw() != nullptr);
        assert(o.concrete_or_offset < 32);
        assert(StackItem<true>::is_symbolic(o.symbolic));
        offset = o.concrete_or_offset;
        symbolic = o.symbolic.raw();
        return *this;
    }

    void set_concrete()
    {
        memset(this, 0, sizeof(SymbolicMemoryLocation));
    }

    Slice8 get_symbolic()
    {
        assert (!is_in_concrete_memory());
        return {rc_ptr(symbolic), offset};
    }
};

// can be used to check if an EVM word sized chunk of symbolic memory only contains concrete values
static const char zeros [sizeof(SymbolicMemoryLocation)*32] {};

inline bool SymbolicMemoryLocation::is_in_concrete_memory()
{
    return std::memcmp(this, zeros, sizeof(SymbolicMemoryLocation)) == 0;
}


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

class BaseSymbolicMemory
{
private:
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
    BaseSymbolicMemory() noexcept { allocate_capacity(); }

    SymbolicMemoryLocation& operator[](size_t index) noexcept { return m_data[index]; }

    [[nodiscard]] SymbolicMemoryLocation* data() const noexcept { return m_data.get(); }
    [[nodiscard]] size_t size() const noexcept { return m_size; }

    /// Grows the memory to the given size. The extent is filled with zeros.
    ///
    /// @param new_size  New memory size. Must be larger than the current size and multiple of 32.
    void grow(size_t new_size, bool strict = true) noexcept
    {
        // Restriction for future changes. EVM always has memory size as multiple of 32 bytes.
        INTX_REQUIRE(!strict || (new_size % 32 == 0));

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
        } 
        memset(&m_data[m_size], 0, (new_size - m_size) * sizeof(SymbolicMemoryLocation));
        m_size = new_size;
    }

    /// Virtually clears the memory by setting its size to 0. The capacity stays unchanged.
    void clear() noexcept
    {
        m_size = 0;
    }


    inline void set(size_t dst, size_t size, SymbolicMemoryLocation* m)
    {
        std::memcpy(&m_data[dst], m, sizeof(SymbolicMemoryLocation) * size);
    }

    inline void set_concrete(size_t dst, size_t size)
    {
        std::memset(&m_data[dst], 0, sizeof(SymbolicMemoryLocation) * size);
    }

    inline bool is_concrete_evm_word(size_t index)
    {
        return std::memcmp(&m_data[index], zeros, 32) == 0;
    }

    bool is_concrete(size_t index, size_t size)
    {
        assert(index+size <= m_size);
        size_t i = 0;
        for (; i + 32 < size; i = i + 32)
            if(!is_concrete_evm_word(index + i)) return false;
        return std::memcmp(&m_data[index + i], zeros, size - i) == 0;
    }
};


template<>
class SymbolicMemory<true> : public BaseSymbolicMemory
{
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
    bool is_concrete;
    SymbolicMemoryLocation* symbolic;
    const uint8_t* concrete;
    size_t size;

    inline void clear()
    {
        is_concrete = true;
        size = 0;
    }

    inline void set(size_t s, SymbolicMemoryLocation* sm, const uint8_t* m)
    {
        is_concrete = false;
        symbolic = sm;
        concrete = m;
        size = s;
    }

    inline void set_concrete(size_t s, const uint8_t* m)
    {
        is_concrete = true;
        concrete = m;
        size = s;
    }
};

class SymbolicReturndata : public BaseSymbolicMemory
{
public:
    bool is_concrete = true;
    size_t concrete_size = 0;

    [[nodiscard]] size_t size() const noexcept
    {
        if (is_concrete) return concrete_size;
        return BaseSymbolicMemory::size();
    }

    void clear()
    {
        BaseSymbolicMemory::clear();
        is_concrete = true;
        concrete_size = 0;
    }

    void set_concrete(size_t size)
    {
        clear();
        concrete_size = size;
    }

    void set(size_t size, const SymbolicMemoryLocation* m)
    {
        clear();
        grow(size, false);
        is_concrete = false;
        std::memcpy(data(), m, sizeof(SymbolicMemoryLocation) * size);
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
    SymbolicMemory<true> memory;
    SymbolicStackItemPtr caller;
    SymbolicStackItemPtr callvalue;
    SymbolicCalldata calldata {true, nullptr, nullptr, 0};
    SymbolicReturndata returndata;

    SymbolicState(ArenaAllocator& a, SymbolicRequirements& r, JournaledSymbolicState& j) : arena{a}, requirements{r}, journaled{j} {}

    void symbolic_value_matches_concrete(const StackItem<true>& i, std::convertible_to<const StackItem<true>&> auto... is)
    {
        if constexpr ( sizeof...( is ) > 0 )
            symbolic_value_matches_concrete( is... );

        if (StackItem<true>::is_symbolic(i.sval))
            requirements.push_back(SymbolicRequirement{Req::equal,i.sval, i.val});
    }

    inline SymbolicStackItemPtr load_calldata(size_t begin, size_t end)
    {
        assert((end - begin) <= 32);
        assert(end <= calldata.size);
        if (calldata.is_concrete || std::memcmp(&calldata.symbolic[begin], zeros, end-begin) == 0) return rc_ptr<SymbolicStackItem>();

        Slice&& symbolic {};
        bool is_full_symbolic_word = (end - begin) == 32;
        rc_ptr_data<SymbolicStackItem>* symbolic_ptr = nullptr;

        for (size_t i = 0; i < (end - begin); ++i)
        {
            if(calldata.symbolic[begin + i].is_in_concrete_memory()){
                symbolic.word[i] = {nullptr, calldata.concrete[begin+i]};
                is_full_symbolic_word = false;
            }
            else
            {
                symbolic.word[i] = calldata.symbolic[begin + i].get_symbolic();
                if(symbolic_ptr == nullptr) symbolic_ptr = symbolic.word[i].symbolic.raw();
                is_full_symbolic_word = 
                    is_full_symbolic_word && 
                    symbolic.word[i].symbolic.raw() == symbolic_ptr && 
                    symbolic.word[i].concrete_or_offset == i;
            }
        }

        if(is_full_symbolic_word) return symbolic.word[0].symbolic;
        else return StackItem<true>::make_symbolic(arena, symbolic);
    }

    void set_(SymbolicMemoryPtr& dst, size_t& dst_size, size_t src_offset, size_t src_size, const SymbolicMemoryLocation* src)
    {
        dst_size = src_size;
        if(src_size > 0)
        {
            dst.reset(static_cast<SymbolicMemoryLocation*>(std::realloc(dst.release(), sizeof(SymbolicMemoryLocation) * src_size)));
            std::memcpy(dst.get(), &src[src_offset], sizeof(SymbolicMemoryLocation) * src_size);
        }
        else
            dst = nullptr;
    }

    inline SymbolicStackItemPtr keccak256_slice(const uint8_t* concrete_memory, size_t src, size_t size)
    {
        if(size == 0 || memory.is_concrete(src, size)) return SymbolicStackItemPtr();
        auto data = std::make_unique<Slice8[]>(size);
        for (size_t i = 0; i < size; i++)
        {
            if (memory[src+i].is_in_concrete_memory())
                data[i] = {nullptr, concrete_memory[src+i]};
            else
                data[i] = memory[src+i].get_symbolic();
        }
        return StackItem<true>::make_symbolic(arena, Keccak256 {std::move(data), size});
    }

    inline SymbolicStackItemPtr load_memory(const uint8_t* concrete_memory, size_t begin)
    {
        if (memory.is_concrete_evm_word(begin)) return rc_ptr<SymbolicStackItem>();
        Slice&& symbolic {};
        bool is_full_symbolic_word = true;
        rc_ptr_data<SymbolicStackItem>* symbolic_ptr = nullptr;

        for (size_t i = 0; i < 32; ++i)
        {
            if (memory[begin+i].is_in_concrete_memory())
            {
                symbolic.word[i] = {nullptr, concrete_memory[begin+i]};
                is_full_symbolic_word = false;
            }
            else
            {
                symbolic.word[i] = memory[begin + i].get_symbolic();
                if(symbolic_ptr == nullptr) symbolic_ptr = symbolic.word[i].symbolic.raw();
                is_full_symbolic_word = 
                    is_full_symbolic_word && 
                    symbolic.word[i].symbolic.raw() == symbolic_ptr && 
                    symbolic.word[i].concrete_or_offset == 31-i;
            }
        }
        if(is_full_symbolic_word) return symbolic.word[0].symbolic;
        else return StackItem<true>::make_symbolic(arena, symbolic);
    }
};
}  // namespace evmone
