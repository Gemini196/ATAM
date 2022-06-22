#include "elf64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdbool.h>

#define ERROR_SYMBOL_NOT_FOUND  -3
#define ERROR_SYMBOL_NOT_GLOBAL -2
#define ERROR -1
#define SUCCESS 0
#define GLOBAL 1
#define SHF_ALLOC 2
#define DT_PLTRELSZ 2
#define ET_EXEC 2
#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define DT_PLTGOT 3
#define SHT_RELA  4
#define SHT_DYNAMIC 6

// ------------------------------------------------------ Declarations -----------------------------------------------------------------

long getFuncAddr(void *elf_file, Elf64_Sym *symtab, char *strtab, char* func_name, int sym_num);


// ----------------------------------------------------- Helper Functions ---------------------------------------------------------------

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
int findSymbol(Elf64_Sym *symtab, char *strtab, char* func_name, int symbol_num)
{
    bool found_symbol = false;                                                              // this will serve as a boolean to mark if we found our function in the symtab

    for(int i = 0; i < symbol_num; i++)                                                     // go over symbols to look for our function
    { 
        char* curr_symbol_name = strtab + symtab[i].st_name;                                // get the name of the current symbol in symtab 
        if(strcmp(func_name, curr_symbol_name) == 0)                                        // compare to our func name (strcmp returns 0 if the strings are equal)
        {     
            found_symbol = true;                                                            // we found our symbol!                                 
            if(ELF64_ST_BIND(symtab[i].st_info) != GLOBAL) {                                // check if its global
                return ERROR_SYMBOL_NOT_GLOBAL;                                             // Y not immediately return success???????????????????????????????????????????????????????????????????????????????
            }
        }
    }

    if(!found_symbol) {                                                                     // check if we found the symbol at all
        return ERROR_SYMBOL_NOT_FOUND;
    }

    return SUCCESS;                                                                         // if we got to this point - the symbol is present and global!
}

// ----------------------------------------------------- Actual Functions ---------------------------------------------------------------

// Part 1
// Name: checkExecutable
// Recieves filename
// Returns SUCCESS if the file is executable, ERROR otherwise.
int checkExecutable(char* file_name)
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
int checkFunction(char* file_name, char* func_name, unsigned long* func_addr)
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

    int res = findSymbol(symtab, strtab, func_name, sym_num);

    if (res == SUCCESS){
        *func_addr = getFuncAddr(elf_file, symtab, strtab, func_name, sym_num);                 // part 4
    }

    close(to_trace); 
    munmap(elf_file, size);                                                                 
    return res;                                                                    
}


// Part 4
long getFuncAddr(void *elf_file, Elf64_Sym *symtab, char *strtab, char* func_name, int sym_num)
{
    // Try finding the function in executable file
    int und_index_in_dynsym = 0;                                                             
    for(int i = 0; i < sym_num; i++)                                                        // go over symbols to look for our function
    {
        char* curr_symbol_name = strtab + symtab[i].st_name;                                // get the name of the current symbol in symtab 
        if(strcmp(func_name, curr_symbol_name) == 0)                                        // compare to our func name (strcmp returns 0 if the strings are equal)
        {     
            if(symtab[i].st_shndx != SHN_UNDEF) {                                           // index in file exists - return value (=the function's address)
                return (long)symtab[i].st_value;
            }
            else{
                und_index_in_dynsym++;
            }
            break;
        }    
    }
    // POSSIBLE BUG: DO WE NEED TO MAKE SURE THAT  UND_INDEX_IN_DYNSYM IS -- ?
    // IF WE'RE HERE - SYMBOL IS UND

    int rel_entry_num = 0;

    Elf64_Rela *reltab = (Elf64_Rela*)findSectionTable(elf_file, SHT_RELA, &rel_entry_num);   // get.rela.plt
    for (int i = 0 ; i < rel_entry_num ; i++)
    {   
        if (ELF64_R_SYM(reltab[i].r_info) == und_index_in_dynsym)                            // pretty sure that r_info in reltab entry is the index of the relevant symbol in dynsym table                       
        {
             printf("This is address of the GOT entry of our function: %lx\n",reltab[i].r_offset);
             Elf64_Addr* got_entry = (Elf64_Addr*)reltab[i].r_offset;
            // segfault:
           // printf("This is actual addr of our function: %lx\n",*got_entry);
            //return *got_entry;               
        }
        
    }

    // OH GOD
    // how do we use the ADDENED parameter that also appears in rela.plt??
    // Does this include dynamic libraries?...
    // we use lazy binding - so the got entry value may not contain our function's addr



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

// This is MAIN
int main(int argc, char *argv[])
{
    char* file_name = argv[2];                                                              // save name of executable file
    char* func_name = argv[1];                                                              // save name of function to run
    unsigned long func_addr = 0;

    if (checkExecutable(file_name) != SUCCESS)                                              // part 1 - check if the file is an executable
    {
        printf("PRF:: %s not an executable! :(\n",  file_name);  
        return 1;
    }                  
                                                                                      
    int res = checkFunction(file_name, func_name, &func_addr);                                          
    if (res == ERROR){
        return 1;
    }

    if (res == ERROR_SYMBOL_NOT_FOUND){                                                     // part 2 - check if func exists
        printf("PRF:: %s not found!\n", func_name);
        return 1;
    }
    if (res == ERROR_SYMBOL_NOT_GLOBAL){                                                   // part 3 - check if func is global
        printf("PRF:: %s is not a global symbol! :(\n", func_name);
        return 1;
    }

    // part 4
    printf("func addr:: 0x%lx\n", func_addr); // PLZ DELETE ME!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!


    return 0;
}



