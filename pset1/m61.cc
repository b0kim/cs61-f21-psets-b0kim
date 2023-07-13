#define M61_DISABLE 1
#include "m61.hh"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>
#include <iostream>

// struct meta {
//     meta* next;
//     meta* prev;
//     size_t block_sz; 
//     int allocated; 
//     bool active; 
//     char* file;
//     long line; 
// };

// struct list {
//     meta* head = nullptr; 
//     meta* tail = nullptr; 
// };

// void list_push_front(list* l, meta* n) {
//     n->next = l->head;
//     n->prev = nullptr;
//     if (l->head) {
//         l->head->prev = n;
//     } else {
//         l->tail = n;
//     }
//     l->head = n;
// }

// void list_push_back(list* l, meta* n) {
//     n->next = nullptr;
//     n->prev = l->tail;
//     if (l->tail) {
//         l->tail->next = n;
//     } else {
//         l->head = n;
//     }
//     l->tail = n;
// }

// void list_erase(list* l, meta* n) {
//     if (n->next) {
//         n->next->prev = n->prev;
//     } else {
//         l->tail = n->prev;
//     }
//     if (n->prev) {
//         n->prev->next = n->next;
//     } else {
//         l->head = n->next;
//     }
// }

// Initialize global struct to track allocation statistics
// Use static keyword, as this struct will only be used in this file
static m61_statistics gstats = {0, 0, 0, 0, 0, 0, std::numeric_limits<uintptr_t>::max(), 0};
const static int ALLOCATED = 0x0D6B8D6E;
const static int FOOT_KEY = 0xCF7ABCA2;

// list* activesites; 


struct meta {
    size_t block_sz; 
    int allocated; 
    bool active; 
    char* file;
    long line; 
};




/// m61_malloc(sz, file, line)
///    Return a pointer to `sz` bytes of newly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then m61_malloc must
///    return a unique, newly-allocated pointer value. The allocation
///    request was at location `file`:`line`.

void* m61_malloc(size_t sz, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    // Your code here.
    
    // Protect against integer overflow attacks
    if (sz + sizeof(meta) < sz) {
        gstats.nfail++;
        gstats.fail_size += sz; 
        return nullptr; 
    }

    size_t bytes_to_allocate = sz + sizeof(meta) + sizeof(FOOT_KEY);

    void* ptr = base_malloc(bytes_to_allocate);

    // If memory allocation fails, update gstats and return nullptr
    if (!ptr) {
        gstats.nfail++;
        gstats.fail_size += sz;
        return ptr; 
    }
    
    // Otherwise update allocation stats
    gstats.ntotal++;
    gstats.nactive++;
    gstats.total_size += sz; 
    gstats.active_size += sz; 

    uintptr_t payload_address = (uintptr_t) ptr + sizeof(meta);
    if (payload_address < gstats.heap_min)
        gstats.heap_min = payload_address; 
    if (payload_address + sz - 1 > gstats.heap_max)
        gstats.heap_max = payload_address + sz - 1;

    // Store the size of the allocated block in metadata
    meta* data = (meta*) ptr; 
    data->block_sz = sz;
    data->active = true; 
    data->allocated = ALLOCATED;

    // Set the next several bytes of memory past the end of the allocated block, so we can later detect wild writes
    int* footer = (int*) (payload_address + sz);
    *footer = FOOT_KEY; 

    // Add the meta data to our activesites linked list
    // list_push_front(activesites, data);

    // Return pointer to the payload
    return (void*) ((uintptr_t) ptr + sizeof(meta)); 
}


/// m61_free(ptr, file, line)
///    Free the memory space pointed to by `ptr`, which must have been
///    returned by a previous call to m61_malloc. If `ptr == NULL`,
///    does nothing. The free was called at location `file`:`line`.

void m61_free(void* ptr, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    // Your code here.

    // If freeing nullptr, do nothing
    if (!ptr)
        return;

    uintptr_t payload_address = (uintptr_t) ptr; 
    
    // Use pointer arithmetic to get pointer to original allocation
    meta* data = (meta*) (payload_address - sizeof(meta));

   
    if (payload_address < gstats.heap_min || payload_address + data->block_sz - 1 > gstats.heap_max) {
        std::cerr << "MEMORY BUG???: invalid free of pointer ???, not in heap" << std::endl;
    }
    else if (data->allocated != ALLOCATED) {
        std::cerr << "MEMORY BUG: " << file << ":" << line << ": invalid free of pointer "<< ptr << ", not allocated" << std::endl;
        
    }
    else if (!data->active) {
        std::cerr << "MEMORY BUG???: invalid free of pointer "<< ptr << ", double free" << std::endl;
    }
    else if (FOOT_KEY != *((int*)(payload_address + data->block_sz))) {
        std::cerr << "MEMORY BUG???: detected wild write during free of pointer " << ptr << std::endl;
    }
    else if (data->active) {
        // Update allocation stats
        gstats.nactive--;
        gstats.active_size -= data->block_sz; 
        data->active = false;
        // Free the memory

        // list_erase(activesites, data); 

        base_free(data);
    }
    
    
    
}


/// m61_calloc(nmemb, sz, file, line)
///    Return a pointer to newly-allocated dynamic memory big enough to
///    hold an array of `nmemb` elements of `sz` bytes each. If `sz == 0`,
///    then must return a unique, newly-allocated pointer value. Returned
///    memory should be initialized to zero. The allocation request was at
///    location `file`:`line`.

void* m61_calloc(size_t nmemb, size_t sz, const char* file, long line) {
    // Your code here (to fix test019).

    if (sz >= ((size_t) -1 - sizeof(meta)) / nmemb) {
        gstats.nfail++;
        gstats.fail_size += nmemb * sz; 
        return nullptr;
    }

    void* ptr = m61_malloc(nmemb * sz, file, line);
    if (ptr) {
        memset(ptr, 0, nmemb * sz);
    }
    return ptr;
}


/// m61_get_statistics(stats)
///    Store the current memory statistics in `*stats`.

void m61_get_statistics(m61_statistics* stats) {
    // Your code here: Tests 1-17
    *stats = gstats; 
}


/// m61_print_statistics()
///    Print the current memory statistics.

void m61_print_statistics() {
    m61_statistics stats;
    m61_get_statistics(&stats);

    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}


/// m61_print_leak_report()
///    Print a report of all currently-active allocated blocks of dynamic
///    memory.

void m61_print_leak_report() {
    // Your code here.
    // meta* head = activesites->head; 
    // if (!head) {
    //     std::cout << "OK" << std::endl;
    // }
}


/// m61_print_heavy_hitter_report()
///    Print a report of heavily-used allocation locations.

void m61_print_heavy_hitter_report() {
    // Your heavy-hitters code here
}
