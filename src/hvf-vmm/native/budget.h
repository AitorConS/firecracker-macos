// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stdint.h>
#include <time.h>
// Shared under the VMM device I/O lock. No waits or guest-sized allocations.
struct budget {uint64_t bytes,ops,byte_capacity,op_capacity,byte_rate,op_rate,last,byte_fraction,op_fraction;};
static inline uint64_t budget_now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec;}
static inline void budget_init(struct budget *b,uint64_t bytes,uint64_t ops,uint64_t byte_capacity,uint64_t op_capacity){
    *b=(struct budget){byte_capacity,op_capacity,byte_capacity,op_capacity,bytes,ops,budget_now(),0,0};
}
static inline uint64_t budget_refill(uint64_t have,uint64_t capacity,uint64_t rate,uint64_t elapsed,uint64_t *fraction){
    __uint128_t refill=(__uint128_t)rate*elapsed+*fraction;
    __uint128_t total=refill/1000000000ULL+have;
    *fraction=total>=capacity?0:(uint64_t)(refill%1000000000ULL);
    return total>capacity?capacity:(uint64_t)total;
}
static inline int budget_take_at(struct budget *b,uint64_t bytes,uint64_t ops,uint64_t now){
    if(!b->byte_rate&&!b->op_rate)return 1; // standalone device harness only
    if(now>b->last){
        // Preserve sub-token time: charging tiny polling intervals must not
        // discard fractional refill and starve low-rate configurations.
        uint64_t elapsed=now-b->last;
        uint64_t unit=1000000; // refill in whole milliseconds
        elapsed=elapsed/unit*unit;
        if(elapsed){b->bytes=budget_refill(b->bytes,b->byte_capacity,b->byte_rate,elapsed,&b->byte_fraction);b->ops=budget_refill(b->ops,b->op_capacity,b->op_rate,elapsed,&b->op_fraction);b->last+=elapsed;}
    }
    if(bytes>b->bytes||ops>b->ops)return 0;
    b->bytes-=bytes;b->ops-=ops;return 1;
}
static inline int budget_take(struct budget *b,uint64_t bytes,uint64_t ops){return budget_take_at(b,bytes,ops,budget_now());}
