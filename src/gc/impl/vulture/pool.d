module gc.impl.vulture.pool;

static import core.memory;
import core.bitop;
import core.internal.spinlock;
import core.stdc.string;
import gc.os;
import gc.impl.vulture.bits;
import common = rt.util.container.common;

package:

enum
{
    PAGESIZE = 4096,
    CHUNKSIZE = 256 * PAGESIZE,
    MAXSMALL = 2048,
    MAXLARGE = 8 * CHUNKSIZE
}

alias BlkInfo = core.memory.GC.BlkInfo;
alias BlkAttr = core.memory.GC.BlkAttr;

enum PoolType {
    SMALL = 0, // up to 2K
    LARGE = 1, // from 2k+ to 8M
    HUGE = 2   // 8M+
}

enum { // measured as powers of 2
    FIRST_SIZE_CLASS = 4,
    LAST_SIZE_CLASS = 11,
    SIZE_CLASSES = LAST_SIZE_CLASS - FIRST_SIZE_CLASS
}

// Buckets for Large pool
enum BUCKETS = (toPow2(MAXLARGE) - 12 + 3) / 4;

ubyte toPow2(size_t size) nothrow pure
{
    ubyte notPow2 = (size & (size-1)) != 0;
    return cast(ubyte)(notPow2 + bsr(size));
}

ubyte sizeClassOf(size_t size) nothrow
{
    if (size <= 16) return 4;
    return toPow2(size);
}

ubyte bucketOf(size_t size) nothrow
{
    ubyte pow2 = toPow2(size);
    assert(pow2 >= 12); // 4K+ in large pool
    ubyte bucket = cast(ubyte)((pow2 - 12) / 4);
    return bucket > BUCKETS-1 ? BUCKETS-1 : bucket;
}

struct ThreadCache
{
nothrow:
    struct AllocCache
    {
        Pool* pool;     // the pool where block was acquired
        uint objOffset; // number of the first object in freeBits slice
        uint freeBits;  // freebits with up to 32 objects
    }

    AllocCache[SIZE_CLASSES*2] cache; // per size class per SCAN/NO_SCAN

    BlkInfo allocate(ubyte sclass, uint bits)
    {
        return BlkInfo.init; // TODO
    }

    void populate(ubyte sclass, bool noScan, Pool* pool)
    {
        // TODO
    }

    void release()
    {
        // TODO
    }
}


unittest
{
    assert(sizeClassOf(0) == 4);
    assert(sizeClassOf(15) == 4);
    assert(sizeClassOf(16) == 4);
    assert(sizeClassOf(17) == 5);
    assert(sizeClassOf(2048) == 11);
}

struct Pool
{
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
    ubyte shiftBy; // granularity, expressed in shift amount (immutable)
    void* minAddr, maxAddr; // extent of the pool in virtual memory (immutable)
    Impl impl; // concrete pool details
    void* mappedAddr; // real start of the mapping (immutable)
    size_t mappedSize; // real size of the mapping (immutable)
nothrow:

    @property ref small(){ return impl.small; }
    @property ref large(){ return impl.large; }
    @property ref huge(){ return impl.huge; }
    
    void initialize(size_t size)
    {
        _lock = shared(SpinLock)(SpinLock.Contention.medium);
        isFree = false;
        size_t CHUNKSIZE = (size + CHUNKSIZE-1) & ~(CHUNKSIZE-1);
        minAddr = cast(byte *)os_mem_map(CHUNKSIZE + CHUNKSIZE);
        mappedSize = CHUNKSIZE + CHUNKSIZE;
        mappedAddr = minAddr;
        if (cast(size_t)minAddr & (CHUNKSIZE-1))
        {
            size_t padding = CHUNKSIZE - (cast(size_t)minAddr & (CHUNKSIZE-1));
            minAddr += padding;
        }
        else
            CHUNKSIZE += CHUNKSIZE;
        maxAddr = minAddr + CHUNKSIZE;
    }

    void Dtor()
    {
        int r = os_mem_unmap(mappedAddr, mappedSize);
        assert(r == 0);
    }

    void reset()
    {
        // only need to reset the used portion of mapping
        int r = os_mem_reset(minAddr, maxAddr - minAddr);
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
    uint freeObjects;

}

/// A set of pages organized into a bunch of free lists
/// by size ranges. Granularity is 4K.
struct LargePool
{
    uint largestFreeEstimate; // strictly >= largest free block
    uint pages; // number of pages in this pool
    uint[BUCKETS] freeLists; // index of the first free run
    // offset serves double duty
    // when pages are free it contains next in a free list
    // else it is filled with offset of start of the object
    uint* offsetTable; // one uint per page
    // size of an object or a run of free pages
    uint* sizeTable; // one uint per page
    BitArray markbits;
    BitArray freebits;
    NibbleArray attrs;

    BlkInfo allocate(size_t size, uint bits) nothrow
    {
        return BlkInfo.init;
    }
}

/// A "pool" that represents single huge allocation.
/// All requests to realloc or extend are forwarded to 
/// respective OS primitives. Granularity is 1MB.
struct HugePool
{
    bool mark;
    bool finals;
    bool structFinals;
    bool appendable;
}

Pool* newSmallPool(ubyte sizeClass, bool noScan) nothrow
{
    Pool* p = cast(Pool*)common.xmalloc(Pool.sizeof);
    p.type = PoolType.SMALL;
    p.noScan = noScan;
    p.shiftBy = sizeClass;
    p.initialize((sizeClass-FIRST_SIZE_CLASS+1) * CHUNKSIZE);
    //TODO: proper init
    return p;
}

Pool* newLargePool(size_t size, bool noScan) nothrow
{
    Pool* p = cast(Pool*)common.xmalloc(Pool.sizeof);
    p.type = PoolType.LARGE;
    p.noScan = noScan;
    p.shiftBy = 12;
    p.initialize(size);
    p.large.largestFreeEstimate = cast(uint)(p.maxAddr - p.minAddr);
    p.large.pages = cast(uint)(p.maxAddr - p.minAddr) / PAGESIZE;
    p.large.freeLists[] = uint.max;
    p.large.offsetTable = cast(uint*)common.xmalloc(uint.sizeof * p.large.pages);
    p.large.sizeTable = cast(uint*)common.xmalloc(uint.sizeof * p.large.pages);

    // setup free lists as one big chunk of highest bucket
    p.large.sizeTable[0] = p.large.largestFreeEstimate;
    p.large.offsetTable[0] = uint.max;
    p.large.freeLists[BUCKETS-1] = 0;
    return p;
}

Pool* newHugePool(size_t size, uint bits) nothrow
{
    Pool* p = cast(Pool*)common.xmalloc(Pool.sizeof);
    p.type = PoolType.HUGE;
    p.shiftBy = 20;
    p.noScan = ((bits & BlkAttr.NO_SCAN) != 0);
    p.huge.finals = ((bits & BlkAttr.FINALIZE) != 0);
    p.huge.structFinals = ((bits & BlkAttr.STRUCTFINAL) != 0);
    p.huge.appendable = ((bits & BlkAttr.APPENDABLE) != 0);
    p.initialize(size);
    return p;
}
