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
    MAXLARGE = 8 * CHUNKSIZE, 
    SMALL_RUN_SIZE = 1024 // must be power of 2
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

enum NibbleAttr : ubyte {
    FINALIZE = 0x1,
    APPENDABLE = 0x2,
    NO_INTERIOR = 0x4,
    STRUCTFINAL = 0x8
}

uint attrFromNibble(ubyte nibble, bool noScan) nothrow pure
{
    uint attr;
    if (nibble & NibbleAttr.FINALIZE) attr |= BlkAttr.FINALIZE;
    if (nibble & NibbleAttr.APPENDABLE) attr |= BlkAttr.APPENDABLE;
    if (nibble & NibbleAttr.NO_INTERIOR) attr |= BlkAttr.NO_INTERIOR;
    if (nibble & NibbleAttr.STRUCTFINAL) attr |= BlkAttr.STRUCTFINAL;
    if (noScan) attr |= BlkAttr.NO_SCAN;
    return attr;
}

ubyte attrToNibble(uint attr) nothrow pure
{
    ubyte nibble;
    if (attr & BlkAttr.FINALIZE) nibble |= NibbleAttr.FINALIZE;
    if (attr & BlkAttr.APPENDABLE) nibble |= NibbleAttr.APPENDABLE;
    if (attr & BlkAttr.NO_INTERIOR) nibble |= NibbleAttr.NO_INTERIOR;
    if (attr & BlkAttr.STRUCTFINAL) nibble |= BlkAttr.STRUCTFINAL;
    return nibble;
}

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

struct AllocBatch
{
    Pool* pool;     // the pool where block was acquired
    uint objOffset; // number of the first object in freeBits slice
    uint freeBits;  // freebits with up to 32 objects
}

struct ThreadCache
{
nothrow:

    AllocBatch[SIZE_CLASSES*2] cache; // per size class per SCAN/NO_SCAN

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


/// Segregated pool with a single size class.
/// Memory is allocated in bulk - 32 objects at a time.
struct SmallPool
{
    uint freeObjects; // total free objects
    uint runs; // memory is organized into runs of 1024 objects
    uint* freeInRun; // count of free objects in each run
    BitArray markbits; // granularity is per object
    BitArray freebits; // granularity is per object
    NibbleArray attrs; // granularity is per object
}

/// A set of pages organized into a bunch of free lists
/// by size ranges. Granularity is 4K.
struct LargePool
{
    uint largestFreeEstimate; // strictly >= largest free block, in bytes
    uint pages; // number of pages in this pool
    uint[BUCKETS] buckets; // index of the first free run
    // offset serves double duty
    // when pages are free it contains next in a free list
    // else it is filled with offset of start of the object
    uint* offsetTable; // one uint per page
    // size of an object or a run of free pages, in 4k pages
    uint* sizeTable; // one uint per page
    BitArray markbits;
    BitArray freebits;
    NibbleArray attrs;

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
        isFree = true;
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

//TODO: incapsulate tagged dispatch
    uint getAttr(void* p)
    {
        if (type == PoolType.SMALL) return getAttrSmall(p);
        else if(type == PoolType.LARGE) return getAttrLarge(p);
        else return getAttrHuge(p);
    }

    uint setAttr(void* p, uint attrs)
    {
        if (type == PoolType.SMALL) return setAttrSmall(p, attrs);
        else if(type == PoolType.LARGE) return setAttrLarge(p, attrs);
        else return setAttrHuge(p, attrs);
    }

    uint clrAttr(void* p, uint attrs)
    {
        if (type == PoolType.SMALL) return clrAttrSmall(p, attrs);
        else if(type == PoolType.LARGE) return clrAttrLarge(p, attrs);
        else return clrAttrHuge(p, attrs);
    }

    size_t sizeOf(void* p)
    {
        if (type == PoolType.SMALL) return sizeOfSmall(p);
        else if(type == PoolType.LARGE) return sizeOfLarge(p);
        else return sizeOfHuge(p);
    }

    void* addrOf(void* p)
    {
        if (type == PoolType.SMALL) return addrOfSmall(p);
        else if(type == PoolType.LARGE) return addrOfLarge(p);
        else return addrOfHuge(p);
    }

    // uint.max means same bits
    BlkInfo tryExtend(void* p, size_t minSize, size_t maxSize, uint bits=uint.max)
    {
        if (type == PoolType.SMALL)
            return tryExtendSmall(p, minSize, maxSize, bits);
        else if(type == PoolType.LARGE)
            return tryExtendLarge(p, minSize, maxSize, bits);
        else
            return tryExtendHuge(p, minSize, maxSize, bits);
    }

    BlkInfo query(void* p)
    {
        if (type == PoolType.SMALL) return querySmall(p);
        else if(type == PoolType.LARGE) return queryLarge(p);
        else return queryHuge(p);
    }

    void free(void* p)
    {
        assert(type != PoolType.HUGE); // Huge is handled separately
        if (type == PoolType.SMALL) return freeSmall(p);
        else return freeLarge(p);
    }

    void runFinalizers(const void[] segment)
    {
        // TODO
    }

// SMALL POOL implementations
    AllocBatch allocateBatchSmall() return
    {
        foreach(uint i; 0..small.runs)
        {
            if (small.freeInRun[i] > 0)
            {
                uint start = i * SMALL_RUN_SIZE;
                // find first non-zero 32 bits
                uint offset = small.freebits.scan32(start);
                uint freeBits = small.freebits.read32(offset);
                small.freebits.write32(0, offset);
                small.freeInRun[i] -= popcnt(freeBits);
                return AllocBatch(&this, offset, freeBits);            
            }
        }
        return AllocBatch.init;
    }

    uint getAttrSmall(void* p)
    {
        uint offset = cast(uint)(p - minAddr)>>shiftBy;
        return attrFromNibble(small.attrs[offset], noScan);
    }

    uint setAttrSmall(void* p, uint attrs)
    {
        uint offset = cast(uint)(p - minAddr)>>shiftBy;
        small.attrs[offset] |= attrToNibble(attrs);
        return attrFromNibble(small.attrs[offset], noScan);
    }

    uint clrAttrSmall(void* p, uint attrs)
    {
        uint offset = cast(uint)(p - minAddr)>>shiftBy;
        small.attrs[offset] &= ~attrToNibble(attrs);
        return attrFromNibble(small.attrs[offset], noScan);
    }

    size_t sizeOfSmall(void* p)
    {
        return 1<<shiftBy;
    }

    void* addrOfSmall(void* p)
    {
        auto roundedDown = cast(size_t)p & ~((1<<shiftBy)-1);
        return cast(void*)roundedDown;
    }

    // uint.max means same bits
    BlkInfo tryExtendSmall(void* p, size_t minSize, size_t maxSize, uint bits=uint.max)
    {
        size_t ourSize = (1<<shiftBy);
        if (minSize < ourSize)
        {
            size_t newSize = ourSize > maxSize ? maxSize : ourSize;
            uint offset = cast(uint)(p - minAddr)>>shiftBy;
            if (bits != uint.max)
                small.attrs[offset] = attrToNibble(bits);
            return BlkInfo(p, newSize, attrFromNibble(small.attrs[offset], noScan));
        }
        return BlkInfo.init;
    }

    BlkInfo querySmall(void* p)
    {
        void* base = addrOfSmall(p);
        uint offset = cast(uint)(p - minAddr)>>shiftBy;
        return BlkInfo(base, 1<<shiftBy, attrFromNibble(small.attrs[offset], noScan));
    }

    void freeSmall(void* p)
    {
        uint offset = cast(uint)(p - minAddr)>>shiftBy;
        small.freebits[offset] = 1;
        small.attrs[offset] = 0;
    }

// LARGE POOL implementations
    uint startOfLarge(void* p)
    {
        uint i = cast(uint)(p - minAddr) / PAGESIZE;
        return large.offsetTable[i];
    }

    void putToFreeList(uint offset, uint psize)
    {
        ubyte bucket = bucketOf(psize * PAGESIZE);
        large.offsetTable[offset] = large.buckets[bucket];
        large.sizeTable[offset] = psize;
        large.buckets[bucket] = offset;
    }

    BlkInfo allocateLarge(size_t size, uint bits)
    {
        assert(type == PoolType.LARGE);
        ubyte bucket = bucketOf(size);
        uint psize = cast(uint)(size + PAGESIZE-1) / PAGESIZE;

        BlkInfo cutOut(uint start) nothrow
        {
            for (uint i = start; i < start + psize; i++)
                large.offsetTable[i] = start;
            large.sizeTable[start] = psize;
            BlkInfo blk;
            blk.base = minAddr + start*PAGESIZE;
            blk.size = psize * PAGESIZE;
            blk.attr = bits;
            // TODO: set attr metadata
            large.attrs[start] = attrToNibble(bits);
            large.freebits[start..start+psize] = 0;
            return blk;
        }

        uint head = large.buckets[bucket];
        uint cur = head, prev = head;
        while (cur != uint.max)
        {
            uint blockSize = large.sizeTable[cur];
            if (blockSize >= psize)
            {
                if (cur == head) large.buckets[bucket] = large.offsetTable[cur];
                else large.offsetTable[prev] = large.offsetTable[cur];
                uint rem = blockSize - psize;
                if (rem) putToFreeList(cur + psize, rem);
                return cutOut(cur);
            }
            prev = cur;
            cur = large.offsetTable[cur];
        }
        bucket++;
        // search larger buckets
        while (bucket < BUCKETS)
        {
            if (large.buckets[bucket] != uint.max)
            {
                uint s = large.buckets[bucket];
                large.buckets[bucket] = large.offsetTable[s];
                uint blockSize = large.sizeTable[s];
                uint rem = blockSize - psize;
                assert(rem > 0);
                putToFreeList(s + psize, rem);
                return cutOut(s);
            }
            bucket++;
        }
        // not found
        return BlkInfo.init;
    }

    uint getAttrLarge(void* p)
    {
        uint s = startOfLarge(p);
        return attrFromNibble(large.attrs[s], noScan);
    }

    uint setAttrLarge(void* p, uint attrs)
    {
        uint s = startOfLarge(p);
        large.attrs[s] |= attrToNibble(attrs);
        return attrFromNibble(large.attrs[s], noScan);
    }

    uint clrAttrLarge(void* p, uint attrs)
    {
        uint s = startOfLarge(p);
        large.attrs[s] &= ~attrToNibble(attrs);
        return attrFromNibble(large.attrs[s],noScan);
    }

    size_t sizeOfLarge(void* p)
    {
        uint s = startOfLarge(p);
        return large.sizeTable[s];
    }

    void* addrOfLarge(void* p)
    {
        return minAddr + startOfLarge(p)*PAGESIZE;
    }

    // uint.max means same bits
    BlkInfo tryExtendLarge(void* p, size_t minSize, size_t maxSize, uint bits=uint.max)
    {
        //TODO: check if followed by free space, extend + readd it from free lists
        return BlkInfo.init;
    }

    BlkInfo queryLarge(void* p)
    {
        uint s = startOfLarge(p);
        void* base = minAddr + s*PAGESIZE;
        uint size = large.sizeTable[s]*PAGESIZE;
        uint attrs = attrFromNibble(large.attrs[s], noScan);
        return BlkInfo(base, size, attrs);
    }

    void freeLarge(void* p)
    {
        uint s = startOfLarge(p);
        uint psize = large.sizeTable[s];
        putToFreeList(s, psize);
        large.attrs[s] = 0;
        large.freebits[s..s+psize] = 1;
    }

// HUGE POOL implementations
    uint getAttrHuge(void* p)
    {
        uint attrs;
        if (huge.finals) attrs |= BlkAttr.FINALIZE;
        if (huge.appendable) attrs |= BlkAttr.APPENDABLE;
        if (huge.structFinals) attrs |= BlkAttr.STRUCTFINAL;
        if (noScan) attrs |= BlkAttr.NO_SCAN;
        return attrs;
    }

    uint setAttrHuge(void* p, uint attrs)
    {
        if (attrs & BlkAttr.FINALIZE) huge.finals = true;
        if (attrs & BlkAttr.APPENDABLE) huge.appendable = true;
        if (attrs & BlkAttr.STRUCTFINAL) huge.structFinals = true;
        return getAttrHuge(p);
    }

    uint clrAttrHuge(void* p, uint attrs)
    {
        if (attrs & BlkAttr.FINALIZE) huge.finals = false;
        if (attrs & BlkAttr.APPENDABLE) huge.appendable = false;
        if (attrs & BlkAttr.STRUCTFINAL) huge.structFinals = false;
        return getAttrHuge(p);
    }

    size_t sizeOfHuge(void* p)
    {
        return maxAddr - minAddr;
    }

    void* addrOfHuge(void* p)
    {
        return minAddr;
    }

    // uint.max means same bits
    BlkInfo tryExtendHuge(void* p, size_t minSize, size_t maxSize, uint bits=uint.max)
    {
        //TODO: use mremap on *NIX
        return BlkInfo.init;
    }

    BlkInfo queryHuge(void* p)
    {
        void* base = minAddr;
        size_t size = maxAddr - minAddr;
        uint attrs = getAttrHuge(p);
        return BlkInfo(base, size, attrs);
    }
}

Pool* newSmallPool(ubyte sizeClass, bool noScan) nothrow
{
    Pool* p = cast(Pool*)common.xmalloc(Pool.sizeof);
    p.type = PoolType.SMALL;
    p.noScan = noScan;
    p.shiftBy = sizeClass;
    p.initialize((sizeClass-FIRST_SIZE_CLASS+1) * CHUNKSIZE);
    uint objects = cast(uint)(p.maxAddr - p.minAddr)>>sizeClass;
    p.small.freeObjects = objects;
    p.small.runs  = objects / SMALL_RUN_SIZE;
    p.small.freeInRun = cast(uint*)common.xmalloc(uint.sizeof*p.small.runs);
    p.small.freeInRun[0..p.small.runs] = SMALL_RUN_SIZE;
    //TODO: allocate bits and nibbles
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
    p.large.buckets[] = uint.max;
    p.large.offsetTable = cast(uint*)common.xmalloc(uint.sizeof * p.large.pages);
    p.large.sizeTable = cast(uint*)common.xmalloc(uint.sizeof * p.large.pages);
    //TODO: allocate bits and nibbles

    // setup free lists as one big chunk of highest bucket
    p.large.sizeTable[0] = (p.large.largestFreeEstimate + PAGESIZE-1) / PAGESIZE;
    p.large.offsetTable[0] = uint.max;
    p.large.buckets[BUCKETS-1] = 0;
    return p;
}

Pool* newHugePool(size_t size, uint bits) nothrow
{
    Pool* p = cast(Pool*)common.xmalloc(Pool.sizeof);
    p.type = PoolType.HUGE;
    p.shiftBy = 20;
    p.noScan = ((bits & BlkAttr.NO_SCAN) != 0);
    p.initialize(size);
    p.isFree = false;
    p.huge.finals = ((bits & BlkAttr.FINALIZE) != 0);
    p.huge.structFinals = ((bits & BlkAttr.STRUCTFINAL) != 0);
    p.huge.appendable = ((bits & BlkAttr.APPENDABLE) != 0);
    return p;
}

unittest
{
    Pool* pool = newSmallPool(5, true);

}


unittest
{
    enum size = 12*CHUNKSIZE;
    Pool* pool = newLargePool(size, true);
    foreach_reverse(item; 1..1000)
    {
        size_t itemSize = item*PAGESIZE;
        struct Link
        {
            Link* next;
        }
        Link* head = null;
        size_t cnt = 0;
        for(;;cnt++)
        {
            BlkInfo blk = pool.allocateLarge(itemSize, 0);
            if (!blk.base) break;
            Link* n = cast(Link*)blk.base;
            assert(blk.base);
            assert(blk.size == itemSize);
            n.next = head;
            head = n;
        }
        assert(cnt >= size/1000/PAGESIZE);
        if (item == 1)
            assert(cnt == size/PAGESIZE);
        while(head)
        {
            Link* cur = head;
            head = head.next;
            pool.freeLarge(cur);
        }
    }
}
