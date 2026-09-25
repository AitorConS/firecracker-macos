// SPDX-License-Identifier: Apache-2.0
#include "budget.h"
#include <assert.h>
#include <stdio.h>
int main(void){
    struct budget b;budget_init(&b,100,1,100,1);b.last=0;
    assert(budget_take_at(&b,100,1,0));
    for(uint64_t t=1000000;t<1000000000ULL;t+=1000000)assert(!budget_take_at(&b,100,1,t));
    assert(budget_take_at(&b,100,1,1000000000ULL));
    assert(!budget_take_at(&b,1,0,1)); // backwards time does not create credit
    assert(budget_take_at(&b,100,1,UINT64_MAX)); // overflow-safe refill, capped burst
    assert(!budget_take_at(&b,1,0,UINT64_MAX));
    budget_init(&b,0,0,100,1);
    assert(budget_take_at(&b,1000000,1000000,0)); // no configured cap
    budget_init(&b,100,0,100,1);b.last=0;
    assert(budget_take_at(&b,100,1000000,0)); // packet rate independently unlimited
    assert(!budget_take_at(&b,1,1,0)); // byte rate still enforced
    budget_init(&b,0,1,100,1);b.last=0;
    assert(budget_take_at(&b,1000000,1,0)); // byte rate independently unlimited
    assert(!budget_take_at(&b,1,1,0)); // packet rate still enforced
    budget_init(&b,8ULL<<30,250000,4ULL<<20,32);b.last=0;
    assert(b.byte_capacity>=((8ULL<<30)/1000));
    assert(b.op_capacity>=250);
    assert(budget_take_at(&b,b.byte_capacity,b.op_capacity,0));
    assert(!budget_take_at(&b,1,1,0));
    assert(budget_take_at(&b,b.byte_capacity-1,b.op_capacity,1000000));
    puts("I/O budget burst, fractional refill, backwards clock, overflow and independent unlimited dimensions: PASS");
}
