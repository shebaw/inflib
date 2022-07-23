#include <Windows.h>
#include "epo.h"
#include "pe_misc.h"
#include "patch.h"

/* Little Indian version */
#define REL_FAR_CALL_OPCODE_LI	0xE8
#define REL_FAR_JUMP_OPCODE_LI	0xE9

#define NO_OP_OPCODE_LI		0x90

static void patch_abs_cr_ins(void *pe_map, union cr_redr_info *redr_info, DWORD dest_rva)
{
	IMAGE_NT_HEADERS *nthdrs;
	void *ins;

	nthdrs = GET_NTHDRS(pe_map);
	ins = (void *)((char *)pe_map + rva_to_raw(redr_info->ins_info.ins_rva, nthdrs));
	if (redr_info->ins_info.redr_t == abs_far_call_t) {
		/* change the instruction to REL_CALL */
		*(BYTE *)ins = REL_FAR_CALL_OPCODE_LI;
	} else {
		/* change the instruction to REL_JMP */
		*(BYTE *)ins = REL_FAR_JUMP_OPCODE_LI;
	}

	/* insert the operand as an offset to the destination */
	*(DWORD *)((char *)ins + REL_CR_OPCODE_SIZE) = dest_rva - (redr_info->ins_info.ins_rva + REL_CR_INS_SIZE);
	/* insert the no-op instruction */
	*(BYTE *)((char *)ins + REL_CR_INS_SIZE) = NO_OP_OPCODE_LI;
}

static void patch_rel_cr_ins(void *pe_map, const struct inf_info *pe_inf_info,
		const struct inf_stub *cur_stub)
{
	const IMAGE_NT_HEADERS *nthdrs;
	DWORD operand_rva;
	DWORD *dest;
	DWORD new_operand;

	nthdrs = &pe_inf_info->pehdr.nthdrs;
	operand_rva = pe_inf_info->redr_inf.ins_info.oprnd_rva;
	dest = (DWORD *)((char *)pe_map + rva_to_raw(operand_rva, nthdrs));
	/* offset is calculated from the end of the current instruction */
	new_operand = cur_stub->rva - (operand_rva + sizeof(DWORD));
	/* patch the operand */
	*dest = new_operand;
}

static int rre_cb(void *pe_map, DWORD page_va, WORD *rentry, void *param)
{
	if ((*rentry >> 12) == IMAGE_REL_BASED_HIGHLOW) {
		WORD offset;
		offset = *rentry & 0x0fff;
		if (page_va + offset == *(DWORD *)param) {
			/* zero out the relocation table entry */
			*rentry = 0;
			return 1;
		}
	}
	return 0;
}

static int remove_reloc_entry(void *pe_map, DWORD rva)
{
	return iterate_reloc_table(pe_map, rre_cb, (void *)&rva);
}

static void patch_subr_prologue(void *pe_map, const struct inf_info *pe_inf_info,
		const struct inf_stub *cur_stub)
{
	void *dest;
	void *subr;
	BYTE jmp_ins[5] = {0xe9};			/* jmp relative */

	dest = (char *)pe_map + rva_to_raw(cur_stub->rva, &pe_inf_info->pehdr.nthdrs);

	subr = (void *)((char *)pe_map + 
		rva_to_raw(pe_inf_info->redr_inf.sref_info.subr_rva, GET_NTHDRS(pe_map)));
	/* copy the 2 bytes that are going to be overwritten if prolog_size == 3 */
	if (pe_inf_info->redr_inf.sref_info.prolog_size == 3)
		*(WORD *)((char *)dest + cur_stub->sdtls.stub_size - 2) = *(WORD *)((char *)subr + 3);
	/* create the instruction */
	*(DWORD *)((char *)jmp_ins + 1) = cur_stub->rva - 
		(pe_inf_info->redr_inf.sref_info.subr_rva + 5); /* skip 5 bytes since its rel offset */
	/* overwrite the prologue */
	memcpy(subr, jmp_ins, 5);
}

void patch_cr_ins(struct inf_info *pe_inf_info, void *pe_map,
		struct inf_stub *cur_stub)
{
	if (pe_inf_info->cr_type != ep_t && pe_inf_info->cr_type != epo_most_ref_subr_t) {
		if (pe_inf_info->redr_inf.ins_info.redr_t == rel_far_call_t) {
			patch_rel_cr_ins(pe_map, pe_inf_info, cur_stub);
		} else {
			/* patch the absolute control redirection instruction */
			patch_abs_cr_ins(pe_map, &pe_inf_info->redr_inf, cur_stub->rva);
			/* remove the reloc entry since there is no need for hard coded address now */
			remove_reloc_entry(pe_map, pe_inf_info->redr_inf.ins_info.oprnd_rva);
		}
	} else if (pe_inf_info->cr_type == epo_most_ref_subr_t) {
		patch_subr_prologue(pe_map, pe_inf_info, cur_stub);
	}
}