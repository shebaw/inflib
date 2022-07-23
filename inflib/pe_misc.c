/* miscellioneus PE related functions
 * shebaw
 */
#include <Windows.h>
#include <stdint.h>
#include "pe_misc.h"

DWORD raw_to_rva(DWORD raw_addr, const IMAGE_NT_HEADERS *nthdrs)
{
	WORD nsections;
	IMAGE_SECTION_HEADER *sec_hdr;
	
	sec_hdr = IMAGE_FIRST_SECTION(nthdrs);
	for (nsections = 0; nsections < nthdrs->FileHeader.NumberOfSections; nsections++) {
		if (raw_addr >= sec_hdr->PointerToRawData &&
			raw_addr < (sec_hdr->PointerToRawData + sec_hdr->SizeOfRawData))
			return sec_hdr->VirtualAddress + (raw_addr - sec_hdr->PointerToRawData);
		++sec_hdr;
	}
	return 0;
}

DWORD rva_to_raw(DWORD rva, const IMAGE_NT_HEADERS *nthdrs)
{
	WORD nsections;
	IMAGE_SECTION_HEADER *sec_hdr;

	sec_hdr = IMAGE_FIRST_SECTION(nthdrs);
	for (nsections = 0; nsections < nthdrs->FileHeader.NumberOfSections; nsections++) {
		DWORD sec_size;
		sec_size = nsections == nthdrs->FileHeader.NumberOfSections - 1 ?
			sec_hdr->Misc.VirtualSize : (sec_hdr + 1)->VirtualAddress - sec_hdr->VirtualAddress;
		if (rva >= sec_hdr->VirtualAddress &&
			rva < sec_hdr->VirtualAddress + sec_size)
			return sec_hdr->PointerToRawData + (rva - sec_hdr->VirtualAddress);
		++sec_hdr;
	}
	return 0;
}

static DWORD rva_to_va(DWORD rva, DWORD img_base)
{
	return rva + img_base;
}

DWORD raw_to_va(DWORD raw_addr, const IMAGE_NT_HEADERS *nthdrs, DWORD img_base)
{
	DWORD rva = raw_to_rva(raw_addr, nthdrs);
	return rva ? rva_to_va(rva, img_base) : 0;
}

DWORD va_to_raw(DWORD va, const IMAGE_NT_HEADERS *nthdrs, DWORD img_base)
{
	DWORD rva = va - img_base;
	return rva_to_raw(rva, nthdrs);
}

IMAGE_SECTION_HEADER *get_parent_sec(DWORD rva, const IMAGE_NT_HEADERS *nthdrs)
{
	WORD nsections;
	IMAGE_SECTION_HEADER *sec_hdr;

	sec_hdr = IMAGE_FIRST_SECTION(nthdrs);
	for (nsections = 0; nsections < nthdrs->FileHeader.NumberOfSections; nsections++) {
		DWORD sec_size;
		sec_size = nsections == nthdrs->FileHeader.NumberOfSections - 1 ?
			sec_hdr->Misc.VirtualSize : (sec_hdr + 1)->VirtualAddress - sec_hdr->VirtualAddress;
		if (rva >= sec_hdr->VirtualAddress &&
			rva < sec_hdr->VirtualAddress + sec_size)
			return sec_hdr;
		++sec_hdr;
	}
	return NULL;
}

int dir_exists(const IMAGE_NT_HEADERS *nthdrs, int dir_type)
{
	const IMAGE_DATA_DIRECTORY *dir_entry;
	dir_entry = &nthdrs->OptionalHeader.DataDirectory[dir_type];
	return dir_entry->VirtualAddress != 0 && dir_entry->Size != 0;
}

int no_relocs(const IMAGE_NT_HEADERS *nthdrs)
{
	return (nthdrs->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) || 
		!dir_exists(nthdrs, IMAGE_DIRECTORY_ENTRY_BASERELOC);
}

int iterate_imp_thunks(const void *pe_map, const char *dll_name, imp_iterate_cb_t imp_cb, void *param)
{
	IMAGE_NT_HEADERS *nthdrs;
	IMAGE_DATA_DIRECTORY *imp_dir_entry;
	IMAGE_IMPORT_DESCRIPTOR *imp_desc;

	nthdrs = GET_NTHDRS(pe_map);
	imp_dir_entry = &nthdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	for (imp_desc = (IMAGE_IMPORT_DESCRIPTOR *)((char *)pe_map + rva_to_raw(imp_dir_entry->VirtualAddress, nthdrs));
			imp_desc->Name || imp_desc->TimeDateStamp;
			++imp_desc) {
		const char *cur_name;
		DWORD thunk_rva;
		IMAGE_THUNK_DATA *thunk;

		cur_name = (char *)pe_map + rva_to_raw(imp_desc->Name, nthdrs);
		if (dll_name && _stricmp(cur_name, dll_name) != 0)
			continue;
		/* use IAT if not bound */
		thunk_rva = imp_desc->TimeDateStamp == 0 ?
			imp_desc->FirstThunk : imp_desc->OriginalFirstThunk;
		thunk = (IMAGE_THUNK_DATA *)((char *)pe_map + rva_to_raw(thunk_rva, nthdrs));
		while (thunk->u1.AddressOfData) {
			if (imp_cb(pe_map, imp_desc, thunk, thunk_rva, param))
				return 1;
			thunk_rva += sizeof(IMAGE_THUNK_DATA);
			++thunk;
		}
	}
	return 0;
}

int iterate_reloc_table(void *pe_map, reloc_iterate_cb reloc_cb, void *param)
{
	IMAGE_NT_HEADERS *nthdrs;
	IMAGE_DATA_DIRECTORY *reloc_entry;
	IMAGE_BASE_RELOCATION *breloc, *breloc_end;

	nthdrs = GET_NTHDRS(pe_map);
	if (no_relocs(nthdrs))
		return 0;
	reloc_entry = &nthdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	breloc = (IMAGE_BASE_RELOCATION *)((char *)pe_map + rva_to_raw(reloc_entry->VirtualAddress, nthdrs));
	breloc_end = (IMAGE_BASE_RELOCATION *)((char *)breloc + reloc_entry->Size);
	while (breloc < breloc_end && breloc->VirtualAddress) {
		size_t count;
		WORD *offset_entry;
		uint32_t i;

		count = (breloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		offset_entry = (WORD *)(breloc + 1);
		for (i = 0; i < count; ++i)
			if (reloc_cb(pe_map, breloc->VirtualAddress, &offset_entry[i], param))
				return 1;
		/* advance to the next reloc entry */
		breloc = (IMAGE_BASE_RELOCATION *)((char *)breloc + breloc->SizeOfBlock);
	}
	return 0;
}

struct gtd_args {
	const char *func_name;
	DWORD thunk_rva;
};

static int gtd_cb(const void *pe_map, IMAGE_IMPORT_DESCRIPTOR *imp_desc, IMAGE_THUNK_DATA *thunk,
		DWORD thunk_rva, void *param)
{
	IMAGE_NT_HEADERS *nthdrs;
	IMAGE_IMPORT_BY_NAME *imp_by_name;
	struct gtd_args *gargs;

	gargs = (struct gtd_args *)param;
	if (!gargs->func_name)
		return 1;

	nthdrs = GET_NTHDRS(pe_map);
	imp_by_name = (IMAGE_IMPORT_BY_NAME *)((char *)pe_map + rva_to_raw(thunk->u1.AddressOfData, nthdrs));
	if (_stricmp((char *)imp_by_name->Name, gargs->func_name) == 0) {
		gargs->thunk_rva = thunk_rva;
		return 1;
	}
	return 0;
}

/* Returns the rva of the IMAGE_THUNK_DATA structure that contains
 * the function specified.
 * If function isn't specified, then the address of the first function
 * that is imported from the specified dll is returned
 * Returns 0 on failure
 */
DWORD get_thunk_data_rva(const void *pe_map, const char *dll_name,
		const char *func_name)
{
	struct gtd_args gargs;

	gargs.func_name = func_name;
	return iterate_imp_thunks(pe_map, dll_name, gtd_cb, &gargs) ? gargs.thunk_rva : 0;
}