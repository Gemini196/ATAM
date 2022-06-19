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
#define SHN_UNDEF 0
#define SUCCESS 0
#define GLOBAL 1
#define ET_EXEC 2
#define SHT_SYMTAB 2
#define SHT_STRTAB 3


int checkExecutable(char* file_name)
{   
    FILE* to_trace = fopen(file_name, "r");                                                 // try to open file to debug
    if(to_trace == NULL) {                                                                  // file does not exist
        //printf("[DEBUG] %s does not exist! :(\n", argv[2]);
        return ERROR;
    }

    Elf64_Ehdr header;                                                                      // this will hold the elf header

    int res = fread(&header, 1, sizeof(Elf64_Ehdr), to_trace);                              // try to read the elf header of the file to our struct
    if(res != sizeof(Elf64_Ehdr)) {                                                         // could not read
        return ERROR;
    }

    if(header.e_ident[0] != 0x7f ||                                                         // check if file is of ELF type
        header.e_ident[1] != 'E' ||
        header.e_ident[2] != 'L' ||
        header.e_ident[3] != 'F' ||
        header.e_type != ET_EXEC)                                                           // check if file is an executable
    {                                                          
        return ERROR;
    }
    fclose(to_trace);
    return SUCCESS; 
}

int checkFunction(char* file_name, char* func_name, long* func_addr)
{
    int to_trace = open(file_name, O_RDONLY);                                               // try to open file to debug int an fd (because mmap later)
    if(to_trace == -1) {                                                                    // couldnt open fd - ABORT MISSION
        return ERROR;
    }

    int size = lseek(to_trace, 0, SEEK_END);
    void *elf_file = mmap(NULL, size,                                                       // mmap the whole entire elf file - its like malloc but for really big chuncks of data
                          PROT_READ, MAP_PRIVATE, to_trace, 0);
    if(elf_file == MAP_FAILED) {                                                            // mmap failed - ABORT MISSION
        close(to_trace);
        munmap(elf_file, size);
        return ERROR;
    }
    
    Elf64_Ehdr* header = (Elf64_Ehdr*)elf_file;                                             // the elf header is at the beginning - we can cast it with C magic!
    Elf64_Shdr* sec_headers_arr = (Elf64_Shdr*)(elf_file + header->e_shoff);                // now we can get the section headers by using the offset from the elf header

    Elf64_Shdr str_section = sec_headers_arr[header->e_shstrndx];                           // e_shstrndx is the index of the section header that contains the offset of the section header string table   
    char *sh_str_tbl = (char*)(elf_file + str_section.sh_offset);                           // get the section header string table

    Elf64_Sym *symtab;
    char *strtab;
    int symbol_num = 0;
    for(int i = 0; i < header->e_shnum; i++)                                                // find and fill symtab and strtab
    {
        if(sec_headers_arr[i].sh_type == SHT_SYMTAB) {                                      // found symbol table
            symtab = (Elf64_Sym*)(elf_file + sec_headers_arr[i].sh_offset);                 // C casting magic - save pointer to symtab
            symbol_num = sec_headers_arr[i].sh_size / sec_headers_arr[i].sh_entsize;        // save symbol number for later
        }
        else if(sec_headers_arr[i].sh_type == SHT_STRTAB) {                                 // found srrtab
            if((elf_file + sec_headers_arr[i].sh_offset) != sh_str_tbl)                     // make sure we get the right strtab and NOT the section header string table! (they are of the same type)
                strtab = (char*)(elf_file + sec_headers_arr[i].sh_offset);                  // C casting magig - save pointer to strtab
        }
    }

    bool found_symbol = false;                                                              // this will serve as a boolean to mark if we found our function in the symtab
    for(int i = 0; i < symbol_num; i++)                                                     // go over symbols to look for our function
    {
        char* curr_symbol_name = strtab + symtab[i].st_name;                                // get the name of the current symbol in symtab 
        if(strcmp(func_name, curr_symbol_name) == 0)                                        // compare to our func name (strcmp returns 0 if the strings are equal)
        {     
            found_symbol = true;                                                            // we found our symbol!                                 
            if(ELF64_ST_BIND(symtab[i].st_info) != GLOBAL) {                                // check if its global
                close(to_trace);
                munmap(elf_file, size);
                return ERROR_SYMBOL_NOT_GLOBAL;
            }
        }
    }
    if(!found_symbol) {                                                                     // check if we found the symbol at all
        close(to_trace);
        munmap(elf_file, size);
        return ERROR_SYMBOL_NOT_FOUND;
    }

    *func_addr = getFuncAddress(elf_file, sec_headers_arr, symtab, strtab, func_name);      // part 4 - get function's address (either in file section or in PLT)
    close(to_trace); 
    munmap(elf_file, size);                                                                 // dont forget to close your fd!!
    return SUCCESS;                                                                    
    // if we got to this point - the symbol is present and global!
}

long getFuncAddress(void *elf_file, Elf64_Shdr* sec_headers_arr, Elf64_Sym* symtab, char* strtab, char* func_name)
{
    for(int i = 0; i < symbol_num; i++)                                                     // go over symbols to look for our function
    {
        char* curr_symbol_name = strtab + symtab[i].st_name;                                // get the name of the current symbol in symtab 
        if(strcmp(func_name, curr_symbol_name) == 0)                                        // compare to our func name (strcmp returns 0 if the strings are equal)
        {     
            if(symtab[i].st_shndx != SHN_UNDEF) {                                           // index exists - return value (=the function's address)
                return symtab[i].st_value;  // TODO TODO TODO TODO TODO -----------------------------------------------> DO WE NEED TO ADD RELOCATION!?!?!?!??!?!?!?!  <3 <3 <3
            }

            // IF WE HERE - SYMBOL IS UND
            //  for relocation tables for dynamic libraries: check out dynsym
            // Use Elf64_R_SYM to get the index in dynsym from relocation entry
            
        }  
    }
    

    return 0;
}

int main(int argc, char *argv[])
{
    char* file_name = argv[2];                                                              // save name of executable file
    char* func_name = argv[1];                                                              // save name of function to run
    long  func_addr = 0;

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

    


    return 0;
}