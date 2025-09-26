.intel_syntax noprefix
.data
currentHash:    .long   0
returnAddress:  .quad   0
syscallNumber:  .long   0
syscallAddress: .quad   0

.text
.global CustomProtect
.global CustomWrite
.global CustomQuery
.global NtCreateUserProcess

.global Diff
.extern SW2_GetSyscallNumber
.extern SW2_GetRandomSyscallAddress
    
Diff:
    pop rax
    mov [rsp+ 8], rcx                           # Save registers.
    mov [rsp+16], rdx
    mov [rsp+24], r8
    mov [rsp+32], r9
    sub rsp, 0x28
    mov ecx, dword ptr [currentHash + RIP]
    call SW2_GetSyscallNumber
    mov dword ptr [syscallNumber + RIP], eax    # Save the syscall number
    mov rcx, 0
    call SW2_GetRandomSyscallAddress            # Get a random syscall address
    mov qword ptr [syscallAddress + RIP], rax   # Save the random syscall address
    mov rax, 0
    mov eax, dword ptr [syscallNumber + RIP]    # Restore the syscall vallue
    add rsp, 0x28
    mov rcx, [rsp+ 8]  
    mov r8, [rsp+24]                         # Restore registers.
    mov rdx, [rsp+16]
    mov r10, rcx
    mov r9, [rsp+32]
    pop qword ptr [returnAddress + RIP]         # Save the original return address
    call qword ptr [syscallAddress + RIP]       # Issue syscall
    push qword ptr [returnAddress + RIP]        # Restore the original return address
    ret

CustomProtect:
    mov dword ptr [currentHash + RIP], 0x05B942177   # Load function hash into global variable.
    call Diff                           # Resolve function hash into syscall number and make the call


CustomWrite:
    mov dword ptr [currentHash + RIP], 0x09918AF97   # Load function hash into global variable.
    call Diff                           # Resolve function hash into syscall number and make the call


CustomQuery:
    mov dword ptr [currentHash + RIP], 0x0819CCC4C   # Load function hash into global variable.
    call Diff                           # Resolve function hash into syscall number and make the call


NtCreateUserProcess:
    mov dword ptr [currentHash + RIP], 0x00DB2EAE0   # Load function hash into global variable.
    call Diff                           # Resolve function hash into syscall number and make the call


