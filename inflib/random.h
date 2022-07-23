#ifndef _RANDOM_H
#define _RANDOM_H

#include <stdint.h>

uint32_t rand_num(void);
int rand_int(int low, int high);
double rand_real(double low, double high);
int rand_chance(double p);

#endif