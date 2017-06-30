/*
    Vulture GC's pool table implementaiton.
    Is a mojor part of GC metadata maintains a mapping
    from 1MB memory chunks to GC's pools.
*/
module gc.impl.vulture.pooltable;

import gc.impl.vulture.pool;
import rt.util.container.hashtab;
static import common = rt.util.container.common;

enum
{
    PAGESIZE = 4096,
    CHUNKSIZE = 256*PAGESIZE
}

struct PoolTable
{
nothrow:
    this(size_t initialSize)
    {
        poolMap = PoolMap(initialSize);
        maxAddr = null;
        minAddr = cast(void*)size_t.max;
    }

    void Dtor()
    {
        foreach (p; pools[0..npools])
        {
            p.Dtor();
            common.free(p);
        }
        common.free(pools);
        pools = null;
        npools = 0;
        maxAddr = null;
        minAddr = cast(void*)size_t.max;
        poolMap.__dtor();
    }

    size_t length() const { return npools; }

    Pool* opIndex(size_t idx)
    in
    {
        assert(idx < npools);
    }
    body
    {
        return pools[idx];
    }

    void insert(Pool* pool)
    {
        pools = cast(Pool**)common.xrealloc(pools, (npools + 1)*(Pool*).sizeof);
        pools[npools] = pool;
        if (pool.minAddr < minAddr) minAddr = pool.minAddr;
        if (pool.maxAddr > maxAddr) maxAddr = pool.maxAddr;
        ++npools;
        addToMap(pool);
    }

    // Lookup pool for a given pointer, null is not in GC heap
    Pool *lookup(const void *p)
    {
        if (p >= minAddr && p < maxAddr)
        {
            return lookupDirect(p);
        }
        return null;
    }

    Pool *lookupDirect(const void *p)
    {
        assert(npools);
        size_t adjusted = cast(size_t)p & ~(CHUNKSIZE - 1);
        return poolMap[adjusted];
    }

    void minimize()
    {
        bool rebuild = false;
        size_t i = npools;
        for(size_t j = 0; j < i; )
        {
            pools[j].lock();
            scope(exit) pools[j].unlock();
            if (pools[j].isFree)
            {
                if (pools[j].type == PoolType.HUGE)
                {
                    rebuild = true;
                    pools[j].Dtor(); // totally unmap the memory
                    common.free(pools[j]); // Pools are malloced
                    pools[j] = pools[i];
                    i--;
                    continue;
                }
                else
                    pools[j].reset(); // keep memory mapping but release the pages
            }
            j++;
        }
        npools = i;
        if (rebuild)
        {
            poolMap.reset();
            foreach(p; pools[0..npools]) addToMap(p);
        }
    }

private:

    void addToMap(Pool* pool)
    {
        for (void* p = pool.minAddr; p < pool.maxAddr; p += CHUNKSIZE)
        {
            poolMap[cast(size_t)p & ~(CHUNKSIZE - 1)] = pool;
        }
    }
    alias PoolMap = FlatHashTab!(size_t, Pool*, null,
        x => (x / CHUNKSIZE) ^ 0xAAAA_AAAA);
    Pool** pools;
    size_t npools;
    PoolMap poolMap;
    void* minAddr;
    void* maxAddr;
}
