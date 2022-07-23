/* functions related with random number generation
 * credit: stanford's cs106B course reader random library
 */
#define _CRT_RAND_S
#include <stdlib.h>
#include <stdint.h>

uint32_t rand_num(void)
{
	uint32_t rand_val;
	rand_s(&rand_val);
	return rand_val;
}

int rand_int(int low, int high)
{
	double d;
	int k;

	/* normalize the value to a real number in the range [0, 1)*/
	d = (double)rand_num() / ((double)UINT_MAX + 1);
	/* scale the value to the appropriate range size and truncate it to int */
	k = (int)(d * (high - low + 1));
	/* translate the integer to the apporpirate starting value */
	return low + k;
}

double rand_real(double low, double high)
{
	double d;

	d = (double)rand_num() / ((double)UINT_MAX + 1);
	return d * (high - low + 1);
}

int rand_chance(double p)
{
	return rand_real(0, 1) < p;
}