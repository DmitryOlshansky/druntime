module gc.impl.vulture.gc;

import core.internal.spinlock;
import core.stdc.string;
static import core.memory;
import gc.gcinterface;
import gc.impl.vulture.pooltable;
import gc.impl.vulture.pool;
import rt.util.container.treap;

alias Stats = core.memory.GC.Stats;

enum {
    INITIAL_POOLMAP_SIZE = 32,
    MAXSMALL = 2048
}

class VultureGC : GC
{
    auto rootsLock = shared(AlignedSpinLock)(SpinLock.Contention.brief);
    auto rangesLock = shared(AlignedSpinLock)(SpinLock.Contention.brief);
    Treap!Root roots;
    Treap!Range ranges;

    // Lock around most of GC metadata including pooltable
    auto metaLock = shared(SpinLock)(SpinLock.Contention.brief);
    auto poolTable = PoolTable(INITIAL_POOLMAP_SIZE);
    size_t enabled = 1;
    bool _inFinalizer = false;

    /*
     *
     */
    void Dtor()
    {
        metaLock.lock();
        poolTable.Dtor();
    }

    /**
     *
     */
    void enable() nothrow
    {
        metaLock.lock();
        scope(exit) metaLock.unlock();
        enabled++;
    }

    /**
     *
     */
    void disable()
    {
        metaLock.lock();
        scope(exit) metaLock.unlock();
        enabled--;
    }

    /**
     *
     */
    void collect() nothrow
    {
        //TODO: collection ;)
    }

    /**
     *
     */
    void collectNoStack() nothrow
    {
        //TODO: collection ;)
    }

    /**
     * minimize free space usage
     */
    void minimize() nothrow
    {
        metaLock.lock();
        scope(exit) metaLock.unlock();
        poolTable.minimize();
    }

    /**
     *
     */
    uint getAttr(void* p) nothrow
    {
        if (!p) return 0;
        metaLock.lock();
        scope(exit) metaLock.unlock();
        Pool* pool = poolTable.lookup(p);
        if (!pool) return 0;
        return pool.getAttr(p);
    }

    /**
     *
     */
    uint setAttr(void* p, uint mask) nothrow
    {
        if (!p) return 0;
        metaLock.lock();
        scope(exit) metaLock.unlock();
        Pool* pool = poolTable.lookup(p);
        if (!pool) return 0;
        return pool.setAttr(p, mask);
    }

    /**
     *
     */
    uint clrAttr(void* p, uint mask) nothrow
    {
        if (!p) return 0;
        metaLock.lock();
        scope(exit) metaLock.unlock();
        Pool* pool = poolTable.lookup(p);
        if (!pool) return 0;
        return pool.clrAttr(p, mask);
    }

    /**
     *
     */
    void* malloc(size_t size, uint bits, const TypeInfo ti) nothrow
    {
        return qalloc(size, bits, ti).base;
    }

    /*
     *
     */
    BlkInfo qalloc(size_t size, uint bits, const TypeInfo ti) nothrow
    {
        metaLock.lock();
        return qallocWithLock(size, bits, ti);
    }

    /*
     *
     */
    void* calloc(size_t size, uint bits, const TypeInfo ti) nothrow
    {
        return qalloc(size, bits, ti).base;
    }

    BlkInfo qallocWithLock(size_t size, uint bits, const TypeInfo ti) nothrow
    {
        // Check TypeInfo "should scan" bit
        if (ti && !(ti.flags() & 1)) bits |= BlkAttr.NO_SCAN;
        if (size <= MAXSMALL) return smallAlloc(size, bits);
        else if(size <= 8 * CHUNKSIZE) return largeAlloc(size, bits);
        else return hugeAlloc(size, bits);
    }

    BlkInfo smallAlloc(size_t size, uint bits) nothrow
    {
        return BlkInfo.init;
    }

    BlkInfo largeAlloc(size_t size, uint bits) nothrow
    {
        return BlkInfo.init;
    }

    BlkInfo hugeAlloc(size_t size, uint bits) nothrow
    {
        // No locking any pools whatsoever
        Pool* p = newHugePool(size, bits);
        metaLock.lock();
        poolTable.insert(p);
        metaLock.unlock;
        BlkInfo blk;
        blk.base = p.minAddr;
        blk.size = p.maxAddr - p.minAddr;
        blk.attr = bits;
        return blk;
    }

    /*
     *
     */
    void* realloc(void* p, size_t size, uint bits, const TypeInfo ti) nothrow
    {
        metaLock.lock();
        scope(exit) metaLock.unlock();
        Pool* pool = poolTable.lookup(p);
        if (!pool) return qallocWithLock(size, bits, ti).base;
        size_t oldSize;
        {
            pool.lock();
            metaLock.unlock();
            scope(exit) pool.unlock();
            oldSize = pool.sizeOf(p);
            BlkInfo newP = pool.tryExtend(p, size, size, bits);
            if (newP.base) return newP.base;
        }
        // metaLock is unlocked here
        BlkInfo blk = qalloc(size, bits, ti);
        memcpy(blk.base, p, oldSize);
        return blk.base;
    }

    /**
     * Attempt to in-place enlarge the memory block pointed to by p by at least
     * minsize bytes, up to a maximum of maxsize additional bytes.
     * This does not attempt to move the memory block (like realloc() does).
     *
     * Returns:
     *  0 if could not extend p,
     *  total size of entire memory block if successful.
     */
    size_t extend(void* p, size_t minsize, size_t maxsize, const TypeInfo ti) nothrow
    {
        metaLock.lock();
        Pool* pool = poolTable.lookup(p);
        if (!pool) return 0;
        pool.lock();
        metaLock.unlock();
        scope(exit) pool.unlock();
        BlkInfo newP = pool.tryExtend(p, minsize, maxsize);
        return newP.size;
    }

    /**
     *
     */
    size_t reserve(size_t size) nothrow
    {
        return size; // TODO: mmap + populate memory to be used in pools
    }

    /**
     *
     */
    void free(void* p) nothrow
    {
        metaLock.lock();
        Pool* pool = poolTable.lookup(p);
        if (!pool) return;
        pool.lock();
        metaLock.unlock();
        scope(exit) pool.unlock();
        return pool.free(p);
    }

    /**
     * Determine the base address of the block containing p.  If p is not a gc
     * allocated pointer, return null.
     */
    void* addrOf(void* p) nothrow
    {
        metaLock.lock();
        Pool* pool = poolTable.lookup(p);
        if (!pool) return null;
        pool.lock();
        metaLock.unlock();
        scope(exit) pool.unlock();
        return pool.addrOf(p);
    }

    /**
     * Determine the allocated size of pointer p.  If p is an interior pointer
     * or not a gc allocated pointer, return 0.
     */
    size_t sizeOf(void* p) nothrow
    {
        metaLock.lock();
        Pool* pool = poolTable.lookup(p);
        if (!pool) return 0;
        pool.lock();
        metaLock.unlock();
        scope(exit) pool.unlock();
        return pool.sizeOf(p);
    }

    /**
     * Determine the base address of the block containing p.  If p is not a gc
     * allocated pointer, return null.
     */
    BlkInfo query(void* p) nothrow
    {
        metaLock.lock();
        Pool* pool = poolTable.lookup(p);
        if (!pool) return BlkInfo.init;
        pool.lock();
        metaLock.unlock();
        scope(exit) pool.unlock();
        return pool.query(p);
    }

    /**
     * Retrieve statistics about garbage collection.
     * Useful for debugging and tuning.
     */
    Stats stats() nothrow
    {
        return Stats.init; // TODO: statistics
    }

    /**
     * add p to list of roots
     */
    void addRoot(void* p) nothrow @nogc
    {
        if(!p) return;
        rootsLock.lock();
        scope (exit) rootsLock.unlock();
        roots.insert(Root(p));
    }

    /**
     * remove p from list of roots
     */
    void removeRoot(void* p) nothrow @nogc
    {
        if(!p) return;
        rootsLock.lock();
        scope (exit) rootsLock.unlock();
        roots.remove(Root(p));
    }

    /**
     *
     */
    @property RootIterator rootIter() @nogc
    {
        return &this.rootsApply;
    }

    int rootsApply(scope int delegate(ref Root) nothrow dg) nothrow
    {
        rootsLock.lock();
        scope (exit) rootsLock.unlock();
        auto ret = roots.opApply(dg);
        return ret;
    }

    /**
     * add range to scan for roots
     */
    void addRange(void* p, size_t sz, const TypeInfo ti) nothrow @nogc
    {
        if(!p || !sz) return;
        rangesLock.lock();
        scope (exit) rangesLock.unlock();
        ranges.insert(Range(p, p+sz));
    }

    /**
     * remove range
     */
    void removeRange(void *pbot) nothrow @nogc
    {
        if(!pbot) return;
        rangesLock.lock();
        scope (exit) rangesLock.unlock();
        ranges.remove(Range(pbot, pbot)); // only pbot is used, see Range.opCmp
    }

    /**
     *
     */
    @property RangeIterator rangeIter() @nogc
    {
        return &this.rangesApply;
    }

    int rangesApply(scope int delegate(ref Range) nothrow dg) nothrow
    {
        rangesLock.lock();
        scope (exit) rangesLock.unlock();
        auto ret = ranges.opApply(dg);
        return ret;
    }

    /**
     * run finalizers
     */
    void runFinalizers(in void[] segment) nothrow
    {
        metaLock.lock();
        _inFinalizer = true;
        scope (exit)
        {
            _inFinalizer = false;
            metaLock.unlock();
        }

        Pool* p = poolTable.lookup(segment.ptr);
        if(!p) return;
        p.runFinalizers(segment);
    }

    /*
     *
     */
    bool inFinalizer() nothrow
    {
        metaLock.lock();
        scope(exit) metaLock.unlock();
        return _inFinalizer;
    }
}