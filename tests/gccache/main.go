package main

import (
	"flag"
	"fmt"
	"math/rand"
	"runtime"
	"time"
)

// CacheEntry represents an entry in our leaky cache
type CacheEntry struct {
	ID       int
	Data     []byte
	Refs     []*CacheEntry // References to other entries (creates cycles)
	Created  time.Time
	LastUsed time.Time
}

// LeakyCache simulates a cache that leaks memory
type LeakyCache struct {
	entries map[int]*CacheEntry
	nextID  int
}

func NewLeakyCache() *LeakyCache {
	return &LeakyCache{
		entries: make(map[int]*CacheEntry),
		nextID:  1,
	}
}

// Add creates a new entry with references to existing entries
func (c *LeakyCache) Add(dataSize int, numRefs int) {
	entry := &CacheEntry{
		ID:       c.nextID,
		Data:     make([]byte, dataSize),
		Created:  time.Now(),
		LastUsed: time.Now(),
		Refs:     make([]*CacheEntry, 0, numRefs),
	}

	// Fill data with random bytes to prevent deduplication
	rand.Read(entry.Data)

	// Create references to random existing entries (cycles)
	if len(c.entries) > 0 {
		for i := 0; i < numRefs && i < len(c.entries); i++ {
			// Pick a random entry to reference
			randomID := rand.Intn(len(c.entries)) + 1
			if ref, exists := c.entries[randomID]; exists {
				entry.Refs = append(entry.Refs, ref)
			}
		}
	}

	c.entries[c.nextID] = entry
	c.nextID++
}

// ExpireOld removes entries older than maxAge (but keeps most due to refs)
func (c *LeakyCache) ExpireOld(maxAge time.Duration) int {
	now := time.Now()
	expired := 0

	// Only expire a fraction of eligible entries (simulating pinned entries)
	for id, entry := range c.entries {
		if now.Sub(entry.Created) > maxAge && rand.Float32() < 0.1 {
			delete(c.entries, id)
			expired++
		}
	}

	return expired
}

// Touch updates the last used time of random entries
func (c *LeakyCache) Touch(count int) {
	now := time.Now()
	touched := 0

	for id := range c.entries {
		if touched >= count {
			break
		}
		c.entries[id].LastUsed = now
		touched++

		// Also touch referenced entries (increases memory scanning)
		for _, ref := range c.entries[id].Refs {
			ref.LastUsed = now
		}
	}
}

func main() {
	// Enable memory profiling for this process
	runtime.MemProfile(nil, false)

	// Sleep to ensure the process gets scanned by scanGoProcesses
	// The scan interval is 100ms, so we sleep for 200ms to be safe
	time.Sleep(50 * time.Millisecond)

	var entrySize int
	var addRate int
	var expireRate int

	flag.IntVar(&entrySize, "entry-size", 4096, "Size of each cache entry in bytes")
	flag.IntVar(&addRate, "add-rate", 1000, "Number of entries to add per iteration")
	flag.IntVar(&expireRate, "expire-rate", 100, "Number of entries to try to expire per iteration")
	flag.Parse()

	fmt.Printf("Starting GC cache test:\n")
	fmt.Printf("- Entry size: %d bytes\n", entrySize)
	fmt.Printf("- Add rate: %d entries/iteration\n", addRate)
	fmt.Printf("- Expire rate: %d entries/iteration\n", expireRate)

	cache := NewLeakyCache()
	iteration := 0

	// Force GC to run frequently
	runtime.GC()

	for {
		iteration++

		// Add new entries with cross-references
		for i := 0; i < addRate; i++ {
			numRefs := rand.Intn(5) + 1 // 1-5 references to other entries
			cache.Add(entrySize, numRefs)
		}

		// Touch some random entries (simulating cache hits)
		cache.Touch(addRate / 10)

		// Try to expire old entries (but most won't be expired due to refs)
		expired := cache.ExpireOld(5 * time.Second)

		// Print stats every 100 iterations
		if iteration%100 == 0 {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)

			fmt.Printf("Iteration %d: %d entries, %d expired, Alloc: %d MB, TotalAlloc: %d MB, GC: %d\n",
				iteration, len(cache.entries), expired,
				m.Alloc/1024/1024, m.TotalAlloc/1024/1024, m.NumGC)

			// Force GC to increase pressure
			runtime.GC()
		}

		// Small sleep to allow GC to run
		time.Sleep(1 * time.Millisecond)
	}
}
