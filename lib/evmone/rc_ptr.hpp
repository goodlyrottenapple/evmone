#include "allocator.hpp"

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
            --mPtr->rc;
            if(mPtr->rc == 0 && !mPtr->locked)
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

    static void lock(rc_ptr_data<T> *mPtr)
    {
        if(mPtr != nullptr) mPtr->locked = true;
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
    bool operator==(const rc_ptr &ptr) {return mPtr == ptr.mPtr;}

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
        return mPtr->rc;
    }

private:
    rc_ptr_data<T> *mPtr;
};
}