#include "allocator.hpp"

namespace evmone
{
template < class T >
class rc_ptr
{
private:
    rc_ptr(T* ptr, ArenaAllocator& a) : mPtr(ptr), arena(&a)
    {
        rc = a.make<size_t>((size_t)1);
    }
public:
    rc_ptr() : mPtr(nullptr), arena(nullptr), rc(nullptr) { }

    rc_ptr(const rc_ptr &ptr) : mPtr(ptr.mPtr), arena(ptr.arena), rc(ptr.rc)
    {
        if(rc != nullptr) ++*rc;
    }

    void release()
    {
        if (rc) {
            --*rc;
            if(*rc == 0) {
                if(mPtr != nullptr) 
                {
                    mPtr->~T();
                    if(arena) arena->free(mPtr);
                }
                if(arena) arena->free(rc);
            }
        }
    }

    ~rc_ptr()
    {
        release();
    }

    template<typename ...Args>
    static rc_ptr make(ArenaAllocator& arena, Args&& ...args)
    {
        auto* ptr = arena.make<T>(std::forward<Args>(args)...);
        return rc_ptr(ptr, arena);
    }

    rc_ptr &operator=(T* ptr)
    {
        release();
        if(arena) rc = arena->make<size_t>((size_t)1);
        mPtr = ptr;
        return *this;
    }

    //Assign another rc_ptr
    rc_ptr &operator=(const rc_ptr &ptr)
    {
        release();
        rc = ptr.rc;
        arena = ptr.arena;
        mPtr = ptr.mPtr;
        return *this;
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

    void swap(rc_ptr& other)
    {
        auto* this_mPtr = mPtr;
        auto* this_arena = arena;
        auto* this_rc = rc;
        mPtr = other.mPtr;
        arena = other.arena;
        rc = other.rc;
        other.mPtr = this_mPtr;
        other.arena = this_arena;
        other.rc = this_rc;
    }

private:
    T *mPtr;
    ArenaAllocator* arena;
    size_t* rc;
};
}