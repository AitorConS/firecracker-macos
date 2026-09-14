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
    puts("I/O budget burst, fractional refill, backwards clock and overflow: PASS");
}
