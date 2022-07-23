#ifndef _EPO_H
#define _EPO_H

#include <Windows.h>

#define ABS_FAR_CALL_OPCODE_LI	0x15FF
#define ABS_FAR_JUMP_OPCODE_LI	0x25FF

/* control redirection opcodes size */
#define ABS_CR_OPCODE_SIZE	2
#define REL_CR_OPCODE_SIZE	1

/* control redirection instructions size */
#define ABS_CR_INS_SIZE		6
#define REL_CR_INS_SIZE		5

enum cr_redr_t {abs_far_call_t, abs_far_jmp_t, rel_far_call_t};

struct cr_redr_ins_info {
	enum cr_redr_t redr_t;
	DWORD ins_rva;
	DWORD oprnd_rva;
	DWORD oprnd;
};

struct subr_ref_info {
	DWORD prolog_size;
	DWORD subr_rva;
};

union cr_redr_info {
	struct cr_redr_ins_info ins_info;
	struct subr_ref_info sref_info;
};

int find_subr_cr_ref(const void *pe_map, size_t pe_fsize, int random, union cr_redr_info *redr_info);
int find_imp_cr_ref(const void *pe_map, size_t pe_fsize, int random, union cr_redr_info *redr_info);
int find_reloc_imp_ref(const void *pe_map, size_t pe_fsize, int random, union cr_redr_info *redr_info);
int find_most_ref_subr(const void *pe_map, size_t pe_fsize, union cr_redr_info *redr_info);

#endif