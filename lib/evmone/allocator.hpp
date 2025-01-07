#pragma once

#include <cstdlib>
#include <cstring>
#include <vector>
#include <iostream>

namespace evmone
{

class ArenaAllocator
{
    struct CacheElement
    {
        CacheElement* next;
    };

    static ssize_t constexpr alignment = sizeof(CacheElement);
    static ssize_t constexpr max_alloc_size = 1024;
    static ssize_t constexpr block_size = 4 * 1024;
    static ssize_t constexpr cache_size = max_alloc_size / alignment;

    static_assert(max_alloc_size % alignment == 0);
    static_assert(block_size % max_alloc_size == 0);

    char* block;
    std::vector<char*> blocks;
    ssize_t block_usage;
    size_t block_no;
    CacheElement* cache[cache_size];

public:
    ArenaAllocator()
        : block{new char[block_size]}, blocks{block}, block_usage{}, block_no{}, cache{}
    {}

    ArenaAllocator(ArenaAllocator &&other)
        : block{other.block}
        , blocks{}
        , block_usage{other.block_usage}
        , block_no{other.block_no}
    {
        memcpy(cache, other.cache, sizeof(cache));
        std::swap(blocks, other.blocks);
    }

    ArenaAllocator& operator=(ArenaAllocator &&other)
    {
        block = other.block;
        block_usage = other.block_usage;
        block_no = other.block_no;
        memcpy(cache, other.cache, sizeof(cache));
        blocks = {};
        std::swap(blocks, other.blocks);
        return *this;
    }

    ~ArenaAllocator()
    {
        for (char* p : blocks)
            delete[] p;
    }

    void reset() 
    {
        block_usage = 0;
        block_no = 0;
        block = blocks[0];
        for (size_t i = 0; i < cache_size; i++)
        {
            cache[i] = nullptr;
        }

        for (char* p : blocks)
            delete[] p;
        
        block = new char[block_size];
        blocks.clear();
        blocks.push_back(block);
        
    }

    template<typename T>
    [[nodiscard]]
    char* alloc()
    {
        static ssize_t constexpr N = sizeof(T);
        static_assert(N >= alignment);
        static_assert(N <= max_alloc_size);
        static ssize_t constexpr n = N + (N % alignment);
        static ssize_t constexpr i = (n / alignment) - 1;
        static_assert(i < cache_size);

        CacheElement* e;
        if (cache[i] == nullptr) {
            block_usage += n;
            if (block_usage > block_size) {
                block_no++;
                if (block_no < blocks.size()) block = blocks[block_no];
                else 
                {
                    block = new char[block_size];
                    blocks.push_back(block);
                }
                block_usage = n;
            }
            e = (CacheElement*)block;
            block += n;
        } else {
            e = cache[i];
            cache[i] = e->next;
        }
        return (char*)e;
    }

    template<typename T, typename ...Args>
    [[nodiscard]]
    T* make(Args&& ...args)
    {
        char* ptr = alloc<T>();
        return new(ptr) T(std::forward<Args>(args)...);
    }

    template<typename T>
    void free(T const* x)
    {
        static ssize_t constexpr N = sizeof(T);
        static_assert(N >= alignment);
        static_assert(N <= max_alloc_size);
        static ssize_t constexpr n = N + (N % alignment);
        static ssize_t constexpr i = (n / alignment) - 1;
        static_assert(i < cache_size);
        assert(x != nullptr);

        CacheElement* e = cache[i];
        ((CacheElement*)x)->next = e;
        cache[i] = (CacheElement*)x;
    }
};

} // namespace evmone