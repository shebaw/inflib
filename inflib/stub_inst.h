#ifndef _STUB_INST_H
#define _STUB_INST_H

#include <stdint.h>
#include "infect.h"

/* the number of the total stubs ready for insertion
 * NOTE: this should be equal with the number of stubs that are available
 * for insertion
 * USED IN: tjkr_infect.c and stub_inst.c
 */
#define STUB_COUNT		17

void populate_sdtls(struct inf_stub *inf_stubs);

#endif