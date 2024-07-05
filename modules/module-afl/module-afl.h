#ifndef MODULE_AFL_H
#define MODULE_AFL_H

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/in.h>
#include <stdbool.h>

int __afl_persistent_loop(unsigned int max_cnt);

#endif //MODULE_AFL_H
