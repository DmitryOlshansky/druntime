module gc.impl.vulture.pool;

static import core.memory;
import core.internal.spinlock;
import gc.os;
import common = rt.util.container.common;

alias BlkInfo = core.memory.GC.BlkInfo;
alias BlkAttr = core.memory.GC.BlkAttr;

enum PoolType {
    SMALL = 0, // up to 2K
    LARGE = 1, // from 2k+ to 8M
    HUGE = 2   // 8M+
}

struct Pool
{
package:
    union Impl
    {
        SmallPool small;
        LargePool large;
        HugePool huge;
    }
    shared SpinLock _lock; // per pool lock
    PoolType type; // type of pool (immutable)
    bool isFree;   // if this pool is completely free
    bool noScan;   // if objects of this pool have no pointers (immutable)
    ubyte shiftBy; // granularity, expressed in shift amount
    void* minAddr, maxAddr; // extent of the pool in virtual memory
    Impl impl; // concrete pool details

nothrow:
    void Dtor()
    {

    }

    void reset()
    {
        int r = os_mem_reset(minAddr, maxAddr-minAddr);
        assert(r == 0);
    }

    void lock(){ _lock.lock(); }
    void unlock(){ _lock.unlock(); }
//TODO: implement the below
    uint getAttr(void* p){ return 0; }
    
    uint setAttr(void* p, uint attrs){ return 0; }

    uint clrAttr(void* p, uint attrs){ return 0; }

    size_t sizeOf(void* p)
    {
        return 0;
    }

    void* addrOf(void* p)
    {
        return null;
    }

    // uint.max means same bits
    BlkInfo tryExtend(void* p, size_t minSize, size_t maxSize, uint bits=uint.max)
    {
        return BlkInfo.init;
    }

    BlkInfo query(void* p)
    {
        return BlkInfo.init;
    }

    void free(void* p)
    {

    }

    void runFinalizers(const void[] segment)
    {

    }
}

/// Segregated pool with a single size class.
/// Memory is allocated in bulk - 32 objects at a time.
struct SmallPool
{

}

/// A set of pages organized into a bunch of free lists
/// by size ranges. Granularity is 4K.
struct LargePool
{

}

/// A "pool" that represents single huge allocation.
/// All requests to realloc or extend are forwarded to 
/// respective OS primitives. Granularity is 1MB.
struct HugePool
{

}

Pool* newSmallPool(size_t sizeClass, bool noScan) nothrow
{
    Pool* p = cast(Pool*)common.xmalloc(Pool.sizeof);
    p.type = PoolType.SMALL;
    p.noScan = noScan;
    //TODO: proper init
    return p;
}

Pool* newLargePool(size_t size, bool noScan) nothrow
{
    Pool* p = cast(Pool*)common.xmalloc(Pool.sizeof);
    p.type = PoolType.LARGE;
    p.shiftBy = 12;
    //TODO: proper init
    return p;
}

Pool* newHugePool(size_t size, uint bits) nothrow
{
    Pool* p = cast(Pool*)common.xmalloc(Pool.sizeof);
    p.type = PoolType.HUGE;
    p.shiftBy = 20;
    p.noScan = ((bits & BlkAttr.NO_SCAN) != 0);
    //TODO: proper init
    return p;
}
