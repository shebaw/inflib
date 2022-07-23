#ifndef _PE_MISC_H
#define _PE_MISC_H

#include <Windows.h>

#define ROUND(n, r) ((((n) + ((r) - 1)) / (r)) * (r))
#define GET_NTHDRS(module) ((IMAGE_NT_HEADERS *)((char *)module + ((IMAGE_DOS_HEADER *)module)->e_lfanew))

typedef int (*imp_iterate_cb_t)(const void *pe_map, IMAGE_IMPORT_DESCRIPTOR *imp_desc,
		IMAGE_THUNK_DATA *thunk, DWORD thunk_rva, void *param);
typedef int (*reloc_iterate_cb)(void *pe_map, DWORD page_va, WORD *cur_entry, void *param);

DWORD raw_to_rva(DWORD raw_addr, const IMAGE_NT_HEADERS *nthdrs);
DWORD rva_to_raw(DWORD rva, const IMAGE_NT_HEADERS *nthdrs);
DWORD raw_to_va(DWORD raw_addr, const IMAGE_NT_HEADERS *nthdrs, DWORD img_base);
DWORD va_to_raw(DWORD va, const IMAGE_NT_HEADERS *nthdrs, DWORD img_base);

IMAGE_SECTION_HEADER *get_parent_sec(DWORD rva, const IMAGE_NT_HEADERS *nthdrs);

int dir_exists(const IMAGE_NT_HEADERS *nthdrs, int dir_type);
int no_relocs(const IMAGE_NT_HEADERS *nthdrs);

int iterate_imp_thunks(const void *pe_map, const char *dll_name,
	imp_iterate_cb_t imp_cb, void *param);
int iterate_reloc_table(void *pe_map, reloc_iterate_cb reloc_cb,
	void *param);


DWORD get_thunk_data_rva(const void *pe_map, const char *dll_name,
		const char *func_name);

#endif