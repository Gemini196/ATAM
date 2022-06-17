#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
#include "elf64.h"

#define SYSCALL_OPCODE 0X050F
#define BREAKPOINT_OPCODE 0xCC
#define BREAKPOINT_MASKING 0xFFFFFFFFFFFFFF00
#define TWO_LEAST_SEGNIFICANT_BYTES 0x000000000000FFFF

pid_t runTarget(int argc, char **argv) {
    pid_t pid;
    pid = fork();
    if (pid > 0) {
        return pid;
    } else if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(1);
        }
        if(execv(argv[2], &argv[2]) < 0) {
            perror("execv");
            exit(1);
        }

    } else {
        perror("fork");
        exit(1);
    }
    return pid;
}

void fatalError(char *str) {
    perror(str);
    exit(1);
}

void try_ptraced(enum __ptrace_request request, pid_t child_pid, void *addr, void *data) {
    if (ptrace(request, child_pid, addr, data) == -1) {
        fatalError("ptrace");
    }
}

void runDebug(void *func, pid_t child_pid) {
    int status;
    struct user_regs_struct regs;
    size_t rsp;

    if (wait(&status) < 0) {
        fatalError("wait");
    }

    while (!WIFEXITED(status)) {

        // putting the breakpoint
        uint64_t poked_8_bytes = ptrace(PTRACE_PEEKTEXT, child_pid, func, NULL);
        uint64_t new_8_bytes = (poked_8_bytes & BREAKPOINT_MASKING) | BREAKPOINT_OPCODE;
        if (poked_8_bytes == -1) {
            fatalError("ptrace");
        }
        try_ptraced(PTRACE_POKETEXT, child_pid, func, (void *) new_8_bytes);

        try_ptraced(PTRACE_CONT, child_pid, 0, 0);
        if (wait(&status) < 0) {
            fatalError("wait");
        }

        if (WIFEXITED(status)) {
            break;
        }

        try_ptraced(PTRACE_GETREGS, child_pid, 0, &regs);
        try_ptraced(PTRACE_POKETEXT, child_pid, func, (void *) poked_8_bytes);
        regs.rip -= 1;
        try_ptraced(PTRACE_SETREGS, child_pid, 0, &regs);
        try_ptraced(PTRACE_GETREGS, child_pid, NULL, &regs);
        rsp = regs.rsp;

        // Done hitting the breakpoint and calculating the rsp of the function


        while (WIFSTOPPED(status)) {
            try_ptraced(PTRACE_GETREGS, child_pid, NULL, &regs);
            size_t syscall_addr = regs.rip;
            uint64_t isntruction = ptrace(PTRACE_PEEKTEXT, child_pid, regs.rip, NULL);
            uint16_t ls_two_bytes = isntruction & TWO_LEAST_SEGNIFICANT_BYTES;
            if (regs.rsp == rsp + 8) {
                break;
            }
            try_ptraced(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
            wait(&status);

            if (ls_two_bytes == SYSCALL_OPCODE) {
                try_ptraced(PTRACE_GETREGS, child_pid, NULL, &regs);
                if ((long int) regs.rax < 0) {
                    printf("PRF:: syscall in %x returned with %ld\n", (unsigned int) syscall_addr, (long int) regs.rax);
                }
            }
        }
    }
}

int main(int argc, char *argv[]) {
    FILE *file = fopen(argv[2], "r");
    Elf64_Ehdr header;
    fread(&header, 1, sizeof(Elf64_Ehdr), file);

    rewind(file);
    fseek(file, header.e_shoff, SEEK_SET);

    Elf64_Shdr *section_headers = (Elf64_Shdr *) malloc(sizeof(Elf64_Shdr) * header.e_shnum);
    fread(section_headers, header.e_shentsize, header.e_shnum, file);

    int sym_count = 0;


    for (int i = 0; i < header.e_shnum; i++) {
        if (section_headers[i].sh_type == 2) {
            sym_count += section_headers[i].sh_size / sizeof(Elf64_Sym);
        }
    }

    Elf64_Sym *syms = (Elf64_Sym *) malloc(sizeof(Elf64_Sym) * sym_count);
    Elf64_Word *sym_links = (Elf64_Word *) malloc(sizeof(Elf64_Word) * sym_count);
    char **strings = (char **) malloc(sizeof(char *) * header.e_shnum);

    sym_count = 0;
    for (int i = 0; i < header.e_shnum; i++) {
        if (section_headers[i].sh_type == 2) {
            rewind(file);
            fseek(file, section_headers[i].sh_offset, SEEK_SET);
            int number_of_sym = section_headers[i].sh_size / sizeof(Elf64_Sym);
            fread(syms + sym_count, sizeof(Elf64_Sym), number_of_sym, file);
            Elf64_Word *ptr = sym_links + sym_count;
            for (int j = 0; j < number_of_sym; j++) {
                *ptr = section_headers[i].sh_link;
                ptr++;
            }
            sym_count += section_headers[i].sh_size / sizeof(Elf64_Sym);
        }
        if (section_headers[i].sh_type == 3) {
            rewind(file);
            fseek(file, section_headers[i].sh_offset, SEEK_SET);
            strings[i] = (char *) malloc(sizeof(char) * section_headers[i].sh_size);
            fread(strings[i], sizeof(char), section_headers[i].sh_size, file);
        } else {
            strings[i] = NULL;
        }
    }

    int sym_index = -1;
    for (int i = 0; i < sym_count; i++) {
        if (sym_links[i] != 0 && strcmp(strings[sym_links[i]] + syms[i].st_name, argv[1]) == 0) {
            sym_index = i;
            break;
        }
    }
    if (sym_index == -1) {
        printf("PRF:: not found!\n");
        fclose(file);
        return 0;
    } else if (ELF64_ST_BIND(syms[sym_index].st_info) == 0) {
        printf("PRF:: local found!\n");
        fclose(file);
        return 0;
    }

    Elf64_Addr func = syms[sym_index].st_value;

    pid_t child = runTarget(argc, argv);
    runDebug((void *) func, child);

    fclose(file);
    return 0;
}
