#include "elf64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdbool.h>

#define GLOBAL 1
#define SHF_ALLOC 2
#define DT_PLTRELSZ 2
#define ET_EXEC 2
#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define DT_PLTGOT 3
#define SHT_RELA  4
#define SHT_DYNAMIC 6

// =====================================================================================================================================
// ------------------------------------------------------ Declarations -----------------------------------------------------------------
// =====================================================================================================================================

typedef enum {
    SUCCESS,
    ERROR,
    SYM_NOT_FOUND,
    SYM_NOT_GLOBAL
} SearchStatus;

long getFuncAddr(void *elf_file, Elf64_Sym *symtab, char *strtab, char* func_name, int sym_num, bool* is_dyn);
void* findSectionTable (void* elf_file, Elf64_Word sh_type, int* entry_num);
SearchStatus findSymbol(Elf64_Sym *symtab, char *strtab, char* func_name, int symbol_num);
SearchStatus checkExecutable(char* file_name);
SearchStatus checkFunction(char* file_name, char* func_name, unsigned long* func_addr, bool* is_dyn);
pid_t runTarget(const char* name, char* argv[]);
void Debug(pid_t child_pid, unsigned long address, bool is_dyn);

// ======================================================================================================================================
// ----------------------------------------------------- Helper Functions ---------------------------------------------------------------
// ======================================================================================================================================

// Name: findSectionTable
// Recieves elf_file ptr (from mmap), sh_type- code representing the wanted section type (ex: SHT_SYMTAB), and ptr to entry num
// Returns ptr to said table, and *entry_num= the num of entries in said table
void* findSectionTable (void* elf_file, Elf64_Word sh_type, int* entry_num)
{
    Elf64_Ehdr* header = (Elf64_Ehdr*)elf_file;                                             // the elf header is at the beginning - we can cast it with C magic!
    Elf64_Shdr* sec_headers_arr = (Elf64_Shdr*)(elf_file + header->e_shoff);                // now we can get the section headers by using the offset from the elf header
    void *tab = NULL;
    int i = 0;
    if (sh_type == SHT_RELA)                                                                //  Case 1: get relocation table
    {
        for(i = 0; i < header->e_shnum; i++)                                           
        {
            if (sec_headers_arr[i].sh_type == sh_type &&                                    // get the rela.plt and NOT rela.dyn
                sec_headers_arr[i].sh_flags != SHF_ALLOC)
            {
                tab = (void*)(elf_file + sec_headers_arr[i].sh_offset);
                *entry_num = sec_headers_arr[i].sh_size / sec_headers_arr[i].sh_entsize;
                return tab;
            }
        }
    }

    // is there a chance that strtab appears before symtab?!!??!?
    else if (sh_type == SHT_STRTAB)                                                        //  Case 2: get string table
    {
        Elf64_Word strtab_section_index;
        for(i = 0; i < header->e_shnum; i++)                                           
        {
            if (sec_headers_arr[i].sh_type == SHT_SYMTAB){                                // find using strtab's link property
                strtab_section_index = sec_headers_arr[i].sh_link;                        // get the strtab associated with .symtab and NOT .shstrtab OR .dynstr !! (all of same type: STRTAB)
            }
            if (i == strtab_section_index) {                                              // PLZ PUT IN DIFFERENT FOR LOOP
                tab = (void*)(elf_file + sec_headers_arr[i].sh_offset);
                return tab;
            }
        }
    }
     
    else 
    {
        for(i = 0; i < header->e_shnum; i++)                                              //  Case 3: get some other table
        {
            if(sec_headers_arr[i].sh_type == sh_type)
            {
                tab = (void*)(elf_file + sec_headers_arr[i].sh_offset);
                *entry_num = sec_headers_arr[i].sh_size / sec_headers_arr[i].sh_entsize;
                return tab;
            }
        }
    }

    // not supposed to arrive here
    return tab;
}


// Name: findSymbol
// Recieves symbol table parameters & func_name
// Returns whether it exists there/not/if global..
SearchStatus findSymbol(Elf64_Sym *symtab, char *strtab, char* func_name, int symbol_num)
{
    bool found_symbol = false;                                                              // this will serve as a boolean to mark if we found our function in the symtab

    for(int i = 0; i < symbol_num; i++)                                                     // go over symbols to look for our function
    { 
        char* curr_symbol_name = strtab + symtab[i].st_name;                                // get the name of the current symbol in symtab 
        if(strcmp(func_name, curr_symbol_name) == 0)                                        // compare to our func name (strcmp returns 0 if the strings are equal)
        {     
            found_symbol = true;                                                            // we found our symbol!                                 
            if(ELF64_ST_BIND(symtab[i].st_info) != GLOBAL) {                                // check if its global
                return SYM_NOT_GLOBAL;                                                      // Y not immediately return success???????????????????????????????????????????????????????????????????????????????
            }
        }
    }

    if(!found_symbol) {                                                                     // check if we found the symbol at all
        return SYM_NOT_FOUND;
    }
    return SUCCESS;                                                                         // if we got to this point - the symbol is present and global!
}

// ======================================================================================================================================
// ----------------------------------------------------- Actual Functions ---------------------------------------------------------------
// ======================================================================================================================================

// Part 1
// Name: checkExecutable
// Recieves filename
// Returns SUCCESS if the file is executable, ERROR otherwise.
SearchStatus checkExecutable(char* file_name)
{
    FILE* to_trace = fopen(file_name, "r");                                                 // try to open file to debug
    if(to_trace == NULL) {                                                                  // file does not exist
        //printf("[DEBUG] %s does not exist! :(\n", argv[2]);
        return ERROR;
    }

    Elf64_Ehdr header;                                                                      // this will hold the elf header

    int res = fread(&header, 1, sizeof(Elf64_Ehdr), to_trace);                              // try to read the elf header of the file to our struct
    if(res != sizeof(Elf64_Ehdr)) {
        fclose(to_trace);
        return ERROR;
    }

    if(header.e_ident[0] != 0x7f ||                                                         // check if file is of ELF type
        header.e_ident[1] != 'E' ||
        header.e_ident[2] != 'L' ||
        header.e_ident[3] != 'F' ||
        header.e_type != ET_EXEC)                                                           // check if file is an executable
    {    
        fclose(to_trace);
        return ERROR;
    }
    fclose(to_trace);
    return SUCCESS; 
}

// Part 2 + 3
// Name: checkFunction
// Recieves file name, function name, and ptr to function address var.
// Returns SUCCESS if func is global AND executable  (), other errorcode otherwise (and 0x0 in func_addr).
SearchStatus checkFunction(char* file_name, char* func_name, unsigned long* func_addr, bool* is_dyn)
{
    int to_trace = open(file_name, O_RDONLY);                                               // try to open file to debug int an fd (because mmap later)
    if(to_trace == -1) {                                                                    // couldnt open fd - ABORT MISSION
        return ERROR;
    }

    int size = lseek(to_trace, 0, SEEK_END);
    void *elf_file = mmap(NULL, size, PROT_READ, MAP_PRIVATE, to_trace, 0);                 // mmap the whole entire elf file - its like malloc but for really big chuncks of data                      
   
    if(elf_file == MAP_FAILED) {                                                            
        close(to_trace);
        return ERROR;
    }

    int sym_num = 0;
    Elf64_Sym *symtab = (Elf64_Sym*)findSectionTable(elf_file, SHT_SYMTAB, &sym_num);
    char *strtab = (char*)findSectionTable(elf_file, SHT_STRTAB, NULL);

    SearchStatus res = findSymbol(symtab, strtab, func_name, sym_num);

    if (res == SUCCESS){
        *func_addr = getFuncAddr(elf_file, symtab, strtab, func_name, sym_num, is_dyn);             // part 4
    }

    close(to_trace); 
    munmap(elf_file, size);                                                                 
    return res;                                                                    
}

// Part 4 + 5
long getFuncAddr(void *elf_file, Elf64_Sym *symtab, char *strtab, char* func_name, int sym_num, bool* is_dyn)
{
    // Try finding the function in executable file
    int und_index_in_dynsym = 0;                                                             
    for(int i = 0; i < sym_num; i++)                                                        // go over symbols to look for our function
    {
        char* curr_symbol_name = strtab + symtab[i].st_name;                                // get the name of the current symbol in symtab 
        if(strcmp(func_name, curr_symbol_name) == 0){
            if(symtab[i].st_shndx!= SHN_UNDEF) { 
                return (long)symtab[i].st_value;
            }
            else {
                break;
            }
        }

        else if (symtab[i].st_shndx == SHN_UNDEF){
            und_index_in_dynsym++;
        }
    }

    // IF WE'RE HERE - SYMBOL IS UND
    int rel_entry_num = 0;
    Elf64_Rela *reltab = (Elf64_Rela*)findSectionTable(elf_file, SHT_RELA, &rel_entry_num);   // get.rela.plt
    for (int i = 0 ; i < rel_entry_num ; i++)
    {   
        if (ELF64_R_SYM(reltab[i].r_info) == und_index_in_dynsym)                             // pretty sure that r_info in reltab entry is the index of the relevant symbol in dynsym table                       
        {
            *is_dyn = true;
            return reltab[i].r_offset;              
        }
    }

    /* DO WE EVEN NEED ALL OF DIS????*/
    /*
    int entry_num = 0;
    unsigned long plt_addr = 0;
    Elf64_Dyn *dyntab = (Elf64_Dyn*)findSectionTable(elf_file, SHT_DYNAMIC, &entry_num);
    Elf64_Addr got_addr = 0;
    for (int i=0; i<entry_num; i++)
    {
        if (dyntab[i].d_tag == DT_PLTGOT){

            got_addr = dyntab[i].d_un.d_ptr;                     // found the addr of GOT table
            break;
        }
    }
    printf("address of got: %lx\n",got_addr);
    */

    return 0;
}

// Part6
pid_t runTarget(const char* name, char** argv)
{
    pid_t pid = fork();
    if(pid < 0) {
        //perror();
        exit(1);
    }

    if(pid > 0) {
        return pid;
    }

    if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
        // perror();
        exit(1);
    }
    execv(name, argv + 2);                                  // execv is better!                           
}

void Debug(pid_t child_pid, unsigned long address, const bool is_dyn)
{
    // Some vars
    int wait_status;
    struct user_regs_struct regs;
    static int counter = 0;
    bool first_br = true;   
    unsigned long got_offset = 0;                                                               

    // vars for return breakpoint
    unsigned long ret_address = 0;
    unsigned long ret_data = 0;

    waitpid(child_pid, &wait_status, 0);                                                    // wait for child to start running
    
    if(is_dyn) {
        got_offset = address;
        address = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)got_offset, NULL);
    }

    // Create breakpoint at the beginning of our function
    unsigned long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)address, NULL);
    unsigned long trap = ((data & 0xFFFFFFFFFFFFFF00) | 0xCC);
    ptrace(PTRACE_POKETEXT, child_pid, (void*)address, (void*)trap);

    // Wait for child to get to Breakpoint
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    waitpid(child_pid, &wait_status, 0);

    // Child reached breakpont
    while (WIFSTOPPED(wait_status))
    {
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);                                        // Get registers of child
        if(regs.rip - 0x1 == address)                                                       // Check location of breakpoint (start of func or end of func)
        {
            // Fix RIP and Remove breakpoint opcode
            regs.rip--;
            ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
            ptrace(PTRACE_POKETEXT, child_pid, (void*)address, (void*)data);
            counter++;

            // Set breakpoint at the end of the func
            ret_address = ptrace(PTRACE_PEEKTEXT, child_pid, regs.rsp, NULL);
            ret_data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)ret_address, NULL);
            unsigned long ret_trap = ((ret_data & 0xFFFFFFFFFFFFFF00) | 0xCC);
            ptrace(PTRACE_POKETEXT, child_pid, (void*)ret_address, (void*)ret_trap);

            // Continue until func returns
            ptrace(PTRACE_CONT, child_pid, NULL, NULL);
            waitpid(child_pid, &wait_status, 0);
        }
        else if(regs.rip - 0x1 == ret_address && ret_address != 0)
        {
            // Fix RIP and Remove breakpoint opcode
            regs.rip--;
            ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
            ptrace(PTRACE_POKETEXT, child_pid, (void*)ret_address, (void*)ret_data);

            if(is_dyn && first_br)
            {
                address = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)got_offset, NULL);
                data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)address, NULL);
                trap = ((data & 0xFFFFFFFFFFFFFF00) | 0xCC);
                first_br = false;
            }

            // Set breakpoint at the beginnig of func
            ptrace(PTRACE_POKETEXT, child_pid, (void*)address, (void*)trap);

            // Print ret val (in RAX)
            printf("PRF:: run #%d returned with %lld\n", counter, regs.rax);
            ptrace(PTRACE_CONT, child_pid, NULL, NULL);
            waitpid(child_pid, &wait_status, 0);
        }
    }
    
    if(WIFEXITED(wait_status)) {
        return;
    }
}

// This is MAIN
int main(int argc, char *argv[])
{
    char* file_name = argv[2];                                                              // save name of executable file
    char* func_name = argv[1];                                                              // save name of function to run
    unsigned long func_addr = 0;
    bool is_dyn = false;
    
    if (checkExecutable(file_name) != SUCCESS)                                              // part 1 - check if the file is an executable
    {
        printf("PRF:: %s not an executable! :(\n",  file_name);  
        return 1;
    }                  
                                                                                      
    SearchStatus res = checkFunction(file_name, func_name, &func_addr, &is_dyn);                                        
    if (res == ERROR){
        return 1;
    }

    if (res == SYM_NOT_FOUND){                                                              // part 2 - check if func exists
        printf("PRF:: %s not found!\n", func_name);
        return 1;
    }
    if (res == SYM_NOT_GLOBAL){                                                             // part 3 - check if func is global
        printf("PRF:: %s is not a global symbol! :(\n", func_name);
        return 1;
    }

    pid_t child_pid = runTarget(file_name, argv);
    Debug(child_pid, func_addr, is_dyn);
    return 0;
}



