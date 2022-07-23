/*
 * file mmaping/unmaping, reading and other functions
 * shebaw
 */
#include <Windows.h>
#include <stdlib.h>
#include "mem_map.h"

/* returns 1 on success, 0 on failure */
int mem_mapw(const wchar_t *path, DWORD access, DWORD cd, 
	DWORD add_size, struct mmap_info *minfo)
{
	DWORD file_access, share_mode, view_protect, map_access;
	DWORD file_size;
	HANDLE file_handle, map_handle;
	void *map;

	file_handle = map_handle = NULL;
	file_access = share_mode = view_protect = map_access = 0;
	if (access & READ_ACCESS) {
		file_access |= GENERIC_READ;
		share_mode |= FILE_SHARE_READ;
		view_protect = PAGE_READONLY;
		map_access |= FILE_MAP_READ;
	}
	if (access & WRITE_ACCESS) {
		file_access |= GENERIC_WRITE;
		share_mode |= FILE_SHARE_WRITE;
		view_protect = PAGE_READWRITE;
		map_access |= FILE_MAP_WRITE;
	}

	if ((file_handle = CreateFileW(path, file_access, share_mode, NULL, cd, 
		FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
		return 0;

	if ((file_size = GetFileSize(file_handle, 0)) == INVALID_FILE_SIZE)
		goto cleanup;
	file_size += add_size;

	if (!(map_handle = CreateFileMappingW(file_handle, 0, view_protect, 0, file_size, NULL)))
		goto cleanup;

	if (!(map = MapViewOfFile(map_handle, map_access, 0, 0, file_size)))
		goto cleanup;

	minfo->map = map;
	minfo->map_size = file_size;
	minfo->file_handle = file_handle;
	minfo->map_handle = map_handle;

	/* success */
	return 1;

cleanup:
	if (map_handle)
		CloseHandle(map_handle);
	if (file_handle)
		CloseHandle(file_handle);
	return 0;
}

int mem_mapa(const char *path, DWORD access, DWORD cd, 
	DWORD add_size, struct mmap_info *minfo)
{
	wchar_t path_buf[MAX_PATH + 1];
	size_t converted;

	mbstowcs_s(&converted, path_buf, _countof(path_buf), path, _TRUNCATE);
	return mem_mapw(path_buf, access, cd, add_size, minfo);
}

void mem_unmap(struct mmap_info *minfo)
{
	FlushViewOfFile(minfo->map, 0);
	UnmapViewOfFile(minfo->map);
	CloseHandle(minfo->map_handle);
	CloseHandle(minfo->file_handle);
}