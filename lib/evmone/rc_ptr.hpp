#include "allocator.hpp"
#include <limits>

namespace evmone
{

template < class T >
struct rc_ptr_data
{
    T object;
    ArenaAllocator* arena;
    size_t rc;
    bool locked = false;
};

template < class T >
class rc_ptr
{
public:
    rc_ptr() : mPtr(nullptr) { }

    rc_ptr(rc_ptr_data<T>* ptr) : mPtr(ptr) { }

    rc_ptr(const rc_ptr &ptr) : mPtr(ptr.mPtr)
    {
        rc_ptr::acquire(ptr.mPtr);
    }

    void drop()
    {
        mPtr = nullptr;
    }

    static void release(rc_ptr_data<T> *mPtr)
    {
        if(mPtr != nullptr)
        {
            if(mPtr->locked) return;
            --mPtr->rc;
            if(mPtr->rc == 0)
            {
                mPtr->object.~T();
                mPtr->arena->free(mPtr);
            }
        }
    }

    static void acquire(rc_ptr_data<T> *mPtr)
    {
        if(mPtr != nullptr) ++mPtr->rc;
    }

    ~rc_ptr()
    {
        rc_ptr::release(mPtr);
    }

    template<typename ...Args>
    static rc_ptr make(ArenaAllocator& arena, Args&& ...args)
    {
        char* ptr = arena.alloc<rc_ptr_data<T>>();
        auto* mPtr = new(ptr) rc_ptr_data<T>{T(std::forward<Args>(args)...), &arena, 1};
        return rc_ptr(mPtr);
    }

    //Assign another rc_ptr
    rc_ptr &operator=(const rc_ptr &ptr)
    {
        rc_ptr::acquire(ptr.mPtr);
        rc_ptr::release(mPtr);
        mPtr = ptr.mPtr;
        return *this;
    }

    //Retrieve actual pointer
    T* get() const
    {
        return &mPtr->object;
    }


    T* operator->() const {return &mPtr->object;}		//x->member
    T &operator*() const {return mPtr->object;}		//*x, (*x).member
    operator bool() const {return mPtr != nullptr;}	//if(x) {/*x is not nullptr*/}
    bool operator==(const rc_ptr &ptr) const {return mPtr == ptr.mPtr;}

    void swap(rc_ptr& other)
    {
        auto* this_mPtr = mPtr;
        mPtr = other.mPtr;
        other.mPtr = this_mPtr;
    }

    rc_ptr_data<T>* raw()
    {
        return mPtr;
    }

    size_t counter()
    {
        if(mPtr == nullptr) return 0;
        if(mPtr->locked) return std::numeric_limits<size_t>::max();
        return mPtr->rc;
    }

    // When placing into symbolic memory, we lock the rc_ptr so that we can memcpy chunks of said memory without worrying about the underlying object getting
    // released. Otherwise we would have to walk the symbolic memory each time and manually acquire/release after each copy.
    // This can of course negatively affect the memory, however, we reset the arena after each run so we at least won't leak any memory in a long running process.
    void lock()
    {
        if(mPtr != nullptr) mPtr->locked = true;
    }

private:
    rc_ptr_data<T> *mPtr;
};
}