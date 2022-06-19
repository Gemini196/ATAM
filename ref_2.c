
#include "elf64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdbool.h>

#define MY_FUNC_UNDEF -1
//return length of string including the \0 sign
int findStrLength(FILE* file) {
    char ch;
    int size = 0;
    while(true) {
        fread(&ch, 1, 1, file);
        size++;
        if (ch == '\0') {
            break;
        }
    }
    return size; 
}

void fillBuffer(FILE* file, char* buffer) {
    char ch;
    int i = 0;
    while(1) {
        fread(&ch, 1, 1, file);
        if (ch == '\0') {
            break;
        }
        buffer[i++] = ch;
    }
    buffer[i] = '\0';
}

long locateFunction(int argc, char const *argv[])
{
    // open the elf file that we want to search for the function inisde
    FILE* elf_file = fopen(argv[2],"r");
    if (elf_file == NULL) {
        exit(1);
    }
    Elf64_Ehdr elf_header;  // we will read inside of this the curr header we check
    Elf64_Shdr curr_sect_header, func_sect_header; 
    Elf64_Sym func_sym_table; // holds the symbol table so we can try and find the func name inside of it
    uint32_t h_it, s_it;
    bool func_found = false; 
    long func_addr = 0;
    fread(&elf_header, 1, sizeof(Elf64_Ehdr), elf_file); //puts the elf header from the file
    if (elf_header.e_type != 0x7f ||
        elf_header.e_ident[1] != 'E' ||
        elf_header.e_ident[2] != 'L' ||
        elf_header.e_ident[3] != 'F') {
    {
        printf("PRF:: %s not an executable! :(\n", argv[2]);
        fclose(elf_file);
        exit(0);
    }//first step
    for (h_it = 0; h_it < elf_header.e_shnum; h_it++) {
        if (fseek(elf_file, elf_header.e_shoff + h_it * sizeof(curr_sect_header), 0) != 0) { //move seeker to the next sect header
            exit(1);
        }
        fread(&curr_sect_header, 1, sizeof(curr_sect_header), elf_file);  
        if (curr_sect_header.sh_type==2) { //weve found a section that holds strings (IN SYM TAB)
            if (fseek(elf_file, elf_header.e_shoff + curr_sect_header.sh_link * sizeof(curr_sect_header), 0) != 0) { //move the seeker to the start of it
                exit(1);
            }
            fread(&func_sect_header, 1, sizeof(curr_sect_header) , elf_file);  //the section we need to iterate on
            int it_ctr = 0; // iterator counter to the lines inside this section
            for (s_it = 0; s_it < curr_sect_header.sh_size; s_it += curr_sect_header.sh_entsize) {
                if (fseek(elf_file,curr_sect_header.sh_offset + it_ctr*curr_sect_header.sh_entsize ,0) != 0) { //move the seeker to the next line of the symbol table
                    exit(1);
                }
                fread(&func_sym_table, 1, curr_sect_header.sh_entsize , elf_file); //read the line from the symbol table 
                if (fseek(elf_file, func_sect_header.sh_offset + func_sym_table.st_name, 0) != 0) { //move seeker to the string inside this line
                    exit(1);
                }
                char *buffer;
                char ch;
                int length = findStrLength(elf_file);
                buffer = (char*)malloc(sizeof(char)*length+1);
                if (fseek(elf_file, func_sect_header.sh_offset + func_sym_table.st_name, 0) != 0) { //bring the seeker back to its position
                    exit(1);
                }
                fillBuffer(elf_file, buffer);
                if (strcmp(argv[1],buffer)==0 ) { // check if we found the func name 
                    func_found = true;
                    if(buffer) {
                        free(buffer);
                    }
                    func_addr = func_sym_table.st_value; //save the address of the function inside the code
                    break;
                }
                else {
                    if(buffer) {
                        free(buffer);
                    }
                }
                it_ctr++;
            }
        }
    }
    if (func_found && ELF64_ST_BIND(func_sym_table.st_info) == 0) //the function is local
    {
        printf("PRF:: %s is not a global symbol!:(\n", argv[1]);
        fclose(elf_file);
        exit(0);
    }
    else if (func_found && ELF64_ST_BIND(func_sym_table.st_info) == 1) //the function is global
    {
        if (fclose(elf_file) != 0) {
            exit(0);
        }
        return func_addr; //return the function address
    }
    else {
        if (func_found)
        {
            if (func_sym_table.st_shndx == SHN_UNDEF)//index of symbol is endefined
            {
                if (fclose(elf_file) != 0) {
                    exit(0);
                }
                return MY_FUNC_UNDEF;
            }
            //st_shndx
            //SHN_UNDEF
        }
        else {
            fclose(elf_file);
            printf("PRF:: %s not found!\n", argv[1]);
            exit(0);
        }
    }
    fclose(elf_file);
    exit(0);
    }
}

pid_t run_target(const char* prog, const char* args_cmd[]) {
    pid_t pid =fork();
    if(pid>0) { //father
        return pid;
    }
    else if (pid==0) { //son
        if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0){ //allow father to debug
            exit(1);
        }
        execv(prog, (char* const*)args_cmd); //execute the prog to debug
    }
    else { //an error occured...
        exit(1);
    }
}

void debugFuncSyscalls(pid_t child_pid, long func_location) {
    bool replace_bp = true;
    long ret_rip, ret_rip_data, ret_rsp; //the rip the function returns to after a call
    struct user_regs_struct regs;
    int wait_status;
    unsigned long ret_trap;
    wait(&wait_status); //waits for debugged prog to start
    long func_opcode = ptrace(PTRACE_PEEKTEXT,child_pid,(void*)func_location,NULL);
    unsigned long func_bp_opcode = (func_opcode & 0xFFFFFFFFFFFFFF00)|0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)func_location, (void*)func_bp_opcode);
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    wait(&wait_status); //wait for the first break point to occur
    while(1) {
        if(WIFEXITED(wait_status)) { //checks if prog finished
            break;
        }
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        if(replace_bp) { //the breakpoint needs to be replaced
            ptrace(PTRACE_POKETEXT, child_pid,(void*)func_location, (void*)func_opcode);
            regs.rip -= 1;
            ptrace(PTRACE_SETREGS,child_pid,0,&regs);
            replace_bp = false;
            ret_rip = ptrace(PTRACE_PEEKTEXT,child_pid,(void*)regs.rsp,NULL); //holds the rip the func will return to
            ret_rip_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)ret_rip, NULL); 
            ret_rsp = regs.rsp;
            ret_trap = (ret_rip_data & 0xFFFFFFFFFFFFFF00)|0xCC; 
            ptrace(PTRACE_POKETEXT,child_pid, (void*)ret_rip, (void*)ret_trap); //put a brake point on the return address
            ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
            wait(&wait_status);
        }
        if(WIFEXITED(wait_status)) {
            break;
        }
        ptrace(PTRACE_GETREGS,child_pid,0,&regs);
        if (regs.rip - 1 == ret_rip) { // is this the break point of the return from function?
            ptrace(PTRACE_POKETEXT, child_pid, (void*)ret_rip, (void*)ret_rip_data);
            regs.rip-=1;
            ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
            if (ret_rsp == regs.rsp-8) { //is it the real return?
                replace_bp = true;
                func_opcode = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)func_location, NULL);
                func_bp_opcode=(func_opcode & 0xFFFFFFFFFFFFFF00)|0xCC;
                ptrace(PTRACE_POKETEXT, child_pid, (void*)func_location, (void*)func_bp_opcode);
                ptrace(PTRACE_CONT, child_pid, NULL, NULL);
            }
            else { //jumped to the break point without return !!
                ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
                long curr_op = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)regs.rip, NULL);
                unsigned long syscall_op = 0x000000000000FFFF&curr_op;
                ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
                wait(&wait_status);
                if(WIFEXITED(wait_status)) { //checks if prog finished
                    break;
                }
                ptrace(PTRACE_POKETEXT, child_pid, (void*)ret_rip, (void*)ret_trap);
                if (syscall_op == 0x050F) { //have we jumped right to a syscall?
                    ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
                    if ((int)regs.rax < 0) {
                        printf("PRF:: syscall in %llx returned with %lld\n", regs.rip-2, regs.rax);
                    }
                }
                ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
            }
        }
        else {  // we stopped because of a syscall inside the function
            ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL); //continue so we can check the ret valus from the syscall
            wait(&wait_status);
            if(WIFEXITED(wait_status)) {
                exit(0);
            }
            ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
            if ((int)regs.rax < 0) { //check if its an error syscall
                printf("PRF:: syscall in %llx returned with %lld\n", regs.rip - 2, regs.rax);
            }
            ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
        }
        wait(&wait_status);
    }
    return;
}

int main(int argc, char const *argv[])
{
    long func_location = locateFunction(argc,argv);
    if (func_location == MY_FUNC_UNDEF)
    {
        //step 5
    }
    //step 6:
    pid_t child_pid = run_target(argv[2], argv+2);//not step 6
    debugFuncSyscalls(child_pid,func_location);// not step 6
    return 0;
}


