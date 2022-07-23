#ifndef _MEM_MAP_H_
#define _MEM_MAP_H_

#include <Windows.h>

struct mmap_info {
	void *map;
	DWORD map_size;
	HANDLE file_handle;
	HANDLE map_handle;
};

#define READ_ACCESS		0x01
#define WRITE_ACCESS		0x02
#define READ_WRITE_ACCESS	(READ_ACCESS | WRITE_ACCESS)

int mem_mapw(const wchar_t *path, DWORD access, DWORD creation_disposition, 
	DWORD add_size, struct mmap_info *minfo);
int mem_mapa(const char *path, DWORD access, DWORD creation_disposition, 
	DWORD add_size, struct mmap_info *minfo);

#ifdef UNICODE
#define mem_map mem_mapw
#else
#define mem_map mem_mapa
#endif

void mem_unmap(struct mmap_info *minfo);
#endif