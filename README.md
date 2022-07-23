# inflib
- An EPO capable infection library + a sample POC infector that uses it.

## Intro
- This is a dump of an old proof of concept EPO capable infection library I posted [here](http://www.rohitab.com/discuss/topic/41137-inflib-an-epo-capable-infection-library-a-sample-pe-infector)

## Features
Supported infection techniques:

- **Code Cave**: the stub will be inserted into an unused code "cave" that can hold the stub.
- **Section Appending**: the last section will be enlarged and the stub will be appended to it.
- **New Section**: a new section will be created and the stub will be inserted there.
- **Code Overlay**: this is a little bit different since code/data stored here *won't* be avaiable in memory. It's used to store (large) data after the logical end of the PE file. This is usually used to store data the stub reads from the file by opening the executable as a file.

Supported control transfer techniques:

- **Entry Point Hijacking**: This is the simplest and least stealthy method. The entry point entry in the PE header is changed to point to the stub. This is easy to detect and repair.
- **[EPO]Subroutine Control Transfer Hijacking**: This will scan for control redirection instructions and hijacks a random *instruction*. This is stealthy *but* can result in hijacking an instruction that gets rarely executed.
- **[EPO]Most Referenced Subroutine Hijacking**: This will scan for control redirection instructions to find subroutines (functions) and then hooks the most referenced function. This increases(almost guarantees) that our stub will get called since control can reach it from many places.
- **[EPO]Hijacking Imported APIs**: This works by hijacking an instruction that refers an instruciton from the import table. Once the stub gets called, it will transfer control back to the original API.
- **[EPO]Relocation table assisted code hooking**: this uses the relocation table if there is one, to find control redirection instructions. This decreases the chance of errors when detecting control redirection instructions. But this requires a relocation table and won't work if it's stripped.

We use a simple heuristcs instead of a disassembler to locate control redirection instructions. This is how it works. We first look for control redirection machine codes (ex: `0xE8` for relae far call code, `0xff 0x15` absolute far call opcode, e.t.c.) and then take the address and see if it is a valid address, i.e. is in a valid virtual address range for the specified PE file. Then, we follow that address and see if there is a valid function prologue codes (ex: `push ebp; mov ebp, esp`). If that's the case then our machine code we analyzed is probably a control redirection instruction.

## How to use the library:
The main function is infect_file. It infects a file from disk.

```
int infect_file(const TCHAR *file_path, const struct infect_file_arg *arg,
	infection_status_cb status_cb);
```
### `infect_file_arg` structure description.
`inf_p` is an array of `inf_type_t`. It's used to pass the infection technique to use based on priority. So for example:

```
inf_p[] = {code_cave_t, append_t, 0};
```

will tell it to insert the stub(s) onto a code cave and only append it if there is no code cave big enough to hold the stub. Note that the array is null terminated.

`cr_p` is an array of `cntrl_redr_type_t`. It's used to pass the control redirection techniques based on priority. So for example:

```
cr_p[] = {epo_reloc_t, ep_t, 0};
```
will tell it to use the relocation table assisted code hooking EPO technique to transfer control to the stub. If that fails, for instance, because there is no relocation table, then it will just use the entry point hooking technique as a fall back.

`inf_stubs` is a description of each stub that we want to insert. It will also hold details about each stub after insertion. It's member `sdtls` *must* be populated for each stub to tell the library how insert the stub. `sdtls` is a struct stub_dtls.

### `stub_details` structure description.

```
struct stub_dtls {
    BOOL has_const_size;        /* does the stub have constant size? */
	BOOL is_overlay_data;       /* is the stub supposed to be inserted as an overlay data? */
	void *stub;                 /* pointer to the stub */
	union {
		size_t stub_size;       /* hard coded size of the stub if "has_cont-size" is set to TRUE */
		stub_size_cb_t size_cb; /* function to call if the stub doesn't have constant size */
	};
	stub_insrt_cb_t insert_cb;  /* optional: used to check stub should be inserted or not */
	stub_inst_cb_t inst_cb;     /* stub insertion callback */
	DWORD sec_prot;             /* stub section memory flags */
};
```

`insert_cb` is an optional function and will be called if it's set prior to infeciton to check if the stub should be inserted or not. For example: let's say that you have 3 stubs that do the same thing. In the case of the POC infector, it's 3 types of getting kernel32's base address.

```
{TRUE, FALSE, get_kernel32_addr1, get_kernel32_addr1_size, gka1_insert_cb, gka1_inst_cb, SEC_EXECUTE_READ},
{TRUE, FALSE, get_kernel32_addr2, get_kernel32_addr2_size, gka2_insert_cb, gka2_inst_cb, SEC_EXECUTE_READ},
{TRUE, FALSE, get_kernel32_addr3, get_kernel32_addr3_size, gka3_insert_cb, gka3_inst_cb, SEC_EXECUTE_READ},
```
They are arranged based on their stealthiness, i.e., `get_kernel32_addr1` uses `GetModuleHandle` to get the address of kernel32 dll. It's less suspicious but we can't use it always since *needs* `GetModuleHandle` to be in the import table of the executable we're trying to infect. The callback checks to see if `GetModuleHandle` is in the target executable and return false if it isn't loaded so that the library will use the next alternatives instead.

- `inst_cb` is used to insert the stub. This is useful if you need to patch the stub (overwriting place holders with some values the stub needs, e.t.c.) before inserting it.
- `sec_prot` is used to hint to the infection library on what PE section to insert the stub to. If your stub needs write permission (ex: patches itself on run time), then you can tell the infeciton library to insert it onto a `READ-WRITE` protected section.
- `status_cb` is an optional argument that will be called to check if the file should be infected or not. This is useful to use as a filter to avoid re-infecting executables.


## POC Infector
The POC infector has 17 stubs that are inserted into random locations using inflib. The infector will insert the whole executable into the target, not just the stub since writing the infector in C is easier that writing everything in ASM. This will also show how the infector library handles "code overlays". When the infected executable runs, the stub will drop the virus infection component of the virus on disk and will execute it (this can be improved to run the executable on memory instead). Since this is an example, the infector will display a message box when it's run without arguments. Each stub uses offsets instead of hard coded addresses to refer to the other stubs. This ensures that the stubs won't have address dependencies and can be inserted anywhere.
