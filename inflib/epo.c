/* functions for finding control redirections
 * usefull for emplementing EPO
 * shebaw
 */
#include <Windows.h>
#include <stdint.h>
#include "pe_misc.h"
#include "random.h"
#include "cmap.h"
#include "epo.h"
#include "conf.h"

#define ABS_FAR_CALL_OPCODE		"\xFF\x15"
#define ABS_FAR_JUMP_OPCODE		"\xFF\x25"
#define REL_FAR_CALL_OPCODE		"\xE8"

#define FUNC_PROLOG1			"\x55\x8B\xEC"		/* push ebp; mov ebp, esp MASM style */
#define FUNC_PROLOG2			"\x55\x89\xE5"		/* push ebp; mov ebp, esp NASM style */ 
#define FUNC_PROLOG_SIZE		3

#define API_FUNC_PROLOG1		"\x8B\xFF\x55\x8B\xEC"	/* mov edi, edi; push ebp; mov ebp, esp MASM style */
#define API_FUNC_PROLOG2		"\x89\xFF\x55\x89\xE5"	/* mov edi, edi; push ebp; mov ebp, esp NASM style */
#define API_FUNC_PROLOG_SIZE	5

typedef int (*fsr_cb_t)(const BYTE *operand, DWORD ins_rva, DWORD subr_rva,
	const struct prolog_desc *pdesc, void *param);

struct prolog_desc {
	const BYTE *prolog;
	size_t prolog_size;
};

static int ivtr_cb(const void *pe_map, IMAGE_IMPORT_DESCRIPTOR *imp_desc, IMAGE_THUNK_DATA *thunk_data,
		DWORD thunk_rva, void *param)
{
	return thunk_rva == *(DWORD *)param;
}

static int is_valid_thunk_rva(DWORD rva, const void *pe_map)
{
	return iterate_imp_thunks(pe_map, NULL, ivtr_cb, (void *)&rva);
}

static IMAGE_SECTION_HEADER *get_ep_sec(IMAGE_NT_HEADERS *nthdrs)
{
	return get_parent_sec(nthdrs->OptionalHeader.AddressOfEntryPoint, nthdrs);
}

static int search_ep_sec(const BYTE *opcode, size_t opcode_size, size_t ins_size, 
		const void *pe_map, uint32_t *soffset, const BYTE **operand, DWORD *ins_rva)
{
	IMAGE_NT_HEADERS *nthdrs;
	IMAGE_SECTION_HEADER *ep_sec;
	const BYTE *sec, *ep, *cur_pos;
	DWORD sec_size;
	DWORD cur_rva;

	nthdrs = GET_NTHDRS(pe_map);
	if (!(ep_sec = get_ep_sec(nthdrs)))
		return 0;
	/* scan the entry point section starting from ep for control redirection
	 * opcodes */
	sec = (BYTE *)((char *)pe_map + rva_to_raw(ep_sec->VirtualAddress, nthdrs));
	ep = (BYTE *)((char *)pe_map + 
			rva_to_raw(nthdrs->OptionalHeader.AddressOfEntryPoint, nthdrs));
	sec_size = ep_sec->Misc.VirtualSize < ep_sec->SizeOfRawData ? 
		ep_sec->Misc.VirtualSize : ep_sec->SizeOfRawData;
	for (cur_pos = ep + *soffset, cur_rva = nthdrs->OptionalHeader.AddressOfEntryPoint + *soffset; 
			cur_pos <= sec + sec_size - ins_size; 
			++cur_pos, ++cur_rva) {
		if (memcmp(cur_pos, opcode, opcode_size) == 0) {
			*soffset = (cur_pos - ep) + 1;
			*operand = cur_pos + opcode_size;
			if (ins_rva)
				*ins_rva = cur_rva;
			return 1;
		}
	}
	return 0;
}

int find_subr_ref(const void *pe_map, size_t pe_fsize, fsr_cb_t fsr_cb, void *param)
{
	IMAGE_NT_HEADERS *nthdrs;
	uint32_t soffset;
	const BYTE *operand;
	DWORD ins_rva;
	int found;

	found = FALSE;

	nthdrs = GET_NTHDRS(pe_map);
	soffset = 0;
	while (search_ep_sec(REL_FAR_CALL_OPCODE, REL_CR_OPCODE_SIZE, REL_CR_INS_SIZE, 
			pe_map, &soffset, &operand, &ins_rva)) {
		DWORD dest_rva, dest_offset;
		struct prolog_desc pdescs[] = {
			{FUNC_PROLOG1, FUNC_PROLOG_SIZE}, 
			{FUNC_PROLOG2, FUNC_PROLOG_SIZE},
			{API_FUNC_PROLOG1, API_FUNC_PROLOG_SIZE},
			{API_FUNC_PROLOG2, API_FUNC_PROLOG_SIZE}
		};
		uint32_t i;

		/* get the operand (the offset starts from the next instruction */
		dest_rva = ins_rva + REL_CR_INS_SIZE + *(DWORD *)operand;
		/* is the operand we got a valid offset */
		if (!(dest_offset = rva_to_raw(dest_rva, nthdrs)))
			continue;

		for (i = 0; i < _countof(pdescs); ++i) {
			const BYTE *dest;

			dest = (BYTE *)pe_map + dest_offset;
			/* check if dest is in file boundary */
			if (((BYTE *)pe_map + pe_fsize) - dest < (int32_t)pdescs[i].prolog_size)
				continue;
			/* compare if the prolog is present */
			if (memcmp(dest, pdescs[i].prolog, pdescs[i].prolog_size) == 0) {
				if (fsr_cb(operand, ins_rva, dest_rva, &pdescs[i], param))
					return 1;
				found = TRUE;
			}
		}
	}
	return found;
}

struct fscr_fsr_arg {
	uint32_t pass_count;
	struct cr_redr_ins_info *redr_ins_info;
};

int fscr_fsr_cb(const BYTE *operand, DWORD ins_rva, DWORD subr_rva,
		const struct prolog_desc *pdesc, void *param)
{
	struct fscr_fsr_arg *farg;
	farg = (struct fscr_fsr_arg *)param;

	farg->redr_ins_info->ins_rva = ins_rva;
	farg->redr_ins_info->redr_t = rel_far_call_t;
	farg->redr_ins_info->ins_rva = ins_rva;
	farg->redr_ins_info->oprnd_rva = ins_rva + REL_CR_OPCODE_SIZE;
	farg->redr_ins_info->oprnd = *(DWORD *)operand;
	return farg->pass_count-- == 0;
}

/* finds relative cr instructions by checking
 * to see if the destination has a valid epiloge
 * low false positives
 */
int find_subr_cr_ref(const void *pe_map, size_t pe_fsize, 
		int random, union cr_redr_info *redr_info)
{
	struct fscr_fsr_arg farg;
	uint32_t pass_count;

	pass_count = random ? rand_int(0, RAND_PASS_CLNG) : 0;
	farg.pass_count = pass_count;
	farg.redr_ins_info = &redr_info->ins_info;
	return find_subr_ref(pe_map, pe_fsize, fscr_fsr_cb, (void *)&farg);
}

/* finds absolute cr instructions that call imported functions using
 * the hint that the operand will be a valid import thunk rva
 * low false positive rates 
 */
int find_imp_cr_ref(const void *pe_map, size_t pe_fsize, 
	int random, union cr_redr_info *redr_info)
{
	uint32_t soffset;
	const BYTE *operand;
	const BYTE *opcodes[] = {ABS_FAR_CALL_OPCODE, ABS_FAR_JUMP_OPCODE};
	uint32_t i;
	DWORD ins_rva;
	uint32_t pass_count;
	DWORD img_base;
	int found;

	pass_count = random ? rand_int(0, RAND_PASS_CLNG) : 0;
	img_base = (GET_NTHDRS(pe_map))->OptionalHeader.ImageBase;
	found = FALSE;
	for (i = 0; i < _countof(opcodes); ++i) {
		soffset = 0;
		while (search_ep_sec(opcodes[i], ABS_CR_OPCODE_SIZE, ABS_CR_INS_SIZE,
				pe_map, &soffset, &operand, &ins_rva)) {
			if (is_valid_thunk_rva(*(DWORD *)operand - img_base, pe_map)) {
				redr_info->ins_info.redr_t = opcodes[i] == ABS_FAR_CALL_OPCODE ?
					abs_far_call_t : abs_far_jmp_t;
				redr_info->ins_info.ins_rva = ins_rva;
				redr_info->ins_info.oprnd_rva = ins_rva + ABS_CR_OPCODE_SIZE; 
				redr_info->ins_info.oprnd = *(DWORD *)operand;
				if (pass_count == 0)
					return 1;
				found = TRUE;
				--pass_count;
			}
		}
	}
	return found;
}

static int reloc_count_cb(void *pe_map, DWORD page_va, WORD *rentry, void *param)
{
	if ((*rentry >> 12) == IMAGE_REL_BASED_HIGHLOW) {
		*(uint32_t *)param += 1;
	}
	/* continue iteration */
	return 0;
}

static uint32_t count_addr_relocs(void *pe_map)
{
	uint32_t count;
	/* initialise the count to zero here */
	count = 0;
	iterate_reloc_table(pe_map, reloc_count_cb, (void *)&count);
	return count;
}

struct reloc_ref_cb_arg {
	IMAGE_SECTION_HEADER *ep_sec;
	struct cr_redr_ins_info *redr_ins_info;
	uint32_t pass_count;
	int found;
};

static int reloc_ref_cb(void *pe_map, DWORD page_va, WORD *rentry, void *param)
{
	struct reloc_ref_cb_arg *args;
	IMAGE_SECTION_HEADER *ep_sec;
	struct cr_redr_ins_info *redr_ins_info;
	IMAGE_NT_HEADERS *nthdrs;
	void *page_dest;

	args = (struct reloc_ref_cb_arg *)param;
	ep_sec = args->ep_sec;
	redr_ins_info = args->redr_ins_info;

	nthdrs = GET_NTHDRS(pe_map);
	page_dest = (void *)((char *)pe_map + rva_to_raw(page_va, nthdrs));
	/* is valid x86 relocation */
	if ((*rentry >> 12) == IMAGE_REL_BASED_HIGHLOW) {
		WORD offset;
		DWORD oprnd_rva;
		DWORD *operand;
		WORD opcode;
		
		offset = *rentry & 0x0fff;
		oprnd_rva = page_va + offset;
		/* is this *instruction* in the ep section? */
		if (!(oprnd_rva >= ep_sec->VirtualAddress + ABS_CR_OPCODE_SIZE && 
			oprnd_rva < ep_sec->VirtualAddress + ep_sec->Misc.VirtualSize))
			return 0;

		operand = (DWORD *)((char *)page_dest + offset);
		/* is this a call or jump instruction? */
		opcode = *(WORD *)((char *)operand - sizeof(opcode));
		if ((opcode == ABS_FAR_CALL_OPCODE_LI || opcode == ABS_FAR_JUMP_OPCODE_LI) &&
			is_valid_thunk_rva(*operand - nthdrs->OptionalHeader.ImageBase, pe_map)) {
			redr_ins_info->redr_t = opcode == ABS_FAR_CALL_OPCODE_LI ? abs_far_call_t : abs_far_jmp_t;
			redr_ins_info->oprnd_rva = oprnd_rva;
			redr_ins_info->ins_rva = redr_ins_info->oprnd_rva - sizeof(opcode); 
			redr_ins_info->oprnd = *operand;
			args->found = 1;
			/* break if we skip desired number of types */
			if (args->pass_count == 0)
				return 1;
			--args->pass_count;
		}
	}

	return 0;
}

/* finds absolute cr instructions using the relocation
 * table as a reference 
 * very low false positives
 */
int find_reloc_imp_ref(void *pe_map, size_t pe_fsize, 
	int random, union cr_redr_info *redr_info)
{
	IMAGE_NT_HEADERS *nthdrs;
	IMAGE_SECTION_HEADER *ep_sec;
	struct reloc_ref_cb_arg args;

	nthdrs = GET_NTHDRS(pe_map);
	if (no_relocs(nthdrs) || !(ep_sec = get_ep_sec(nthdrs)))
		return 0;
	args.ep_sec = ep_sec;
	args.redr_ins_info = &redr_info->ins_info;
	/* make it iterate a random number of times if the caller requires it */
	args.pass_count = random ? 
		rand_int(0, count_addr_relocs(pe_map)) / RLC_RAND_FCT : 0;
	args.found = 0;

	return iterate_reloc_table(pe_map, reloc_ref_cb, (void *)&args) || args.found;
}

struct subr_count {
	DWORD subr_rva;
	uint32_t count;
	DWORD prolog_size;
};

int sc_map_cb(const void *e1, const void *e2)
{
	const struct subr_count *s1, *s2;
	s1 = (const struct subr_count *)e1;
	s2 = (const struct subr_count *)e2;
	if (s1->subr_rva == s2->subr_rva)
		return 0;
	return s1->subr_rva > s2->subr_rva ? 1 : -1;
}

struct ff_cb_arg {
	struct subr_count * const max;
	struct cmap * const map;
};

int fmrs_fsr_cb(const BYTE *operand, DWORD ins_rva, DWORD subr_rva, 
		const struct prolog_desc *pdesc, void *param)
{
	struct subr_count *max;
	struct cmap *map;
	struct subr_count sc, *scp;

	max = ((struct ff_cb_arg *)param)->max;
	map = ((struct ff_cb_arg *)param)->map;
	sc.subr_rva = subr_rva;
	sc.count = 0;
	sc.prolog_size = pdesc->prolog_size;
	/* will fail if it's already mapped */
	map_add(map, &sc);
	scp = map_get(map, (const void *)&sc);
	/* increment the counter */
	++scp->count;
	if (max->count < scp->count)
		*max = *scp;
	return 0;	/* continue */
}

/* finds most called subroutine
 * very low false positives
 */
int find_most_ref_subr(const void *pe_map, size_t pe_fsize, union cr_redr_info *redr_info)
{
	struct cmap cm;
	struct subr_count max = {0};
	struct ff_cb_arg farg = {&max, &cm};
	int res;

	res = 0;

	map_init(&cm, sizeof(struct subr_count), sc_map_cb, NULL);
	if (find_subr_ref(pe_map, pe_fsize, fmrs_fsr_cb, &farg)) {
		redr_info->sref_info.prolog_size = max.prolog_size;
		redr_info->sref_info.subr_rva = max.subr_rva;
		res = 1;
	}	
	map_free(&cm);
	return res;
}