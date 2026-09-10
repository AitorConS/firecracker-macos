// SPDX-License-Identifier: Apache-2.0
#pragma once
#include <stdio.h>
#include <stdlib.h>
_Noreturn void fuzz_exit(int status);
int fuzz_log(FILE *stream,const char *format,...);
#define exit fuzz_exit
#define fprintf fuzz_log
