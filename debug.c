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

#define ERROR -1
#define GLOBAL 1
#define ET_EXEC 2
#define SHT_SYMTAB 2
#define SHT_STRTAB 3


void checkExecutable(char* file_name)
{   
    FILE* to_trace = fopen(file_name, "r");                                                 // try to open file to debug
    if(to_trace == NULL) {                                                                  // file does not exist
        //printf("[DEBUG] %s does not exist! :(\n", argv[2]);
        exit(ERROR);
    }

    Elf64_Ehdr header;                                                                      // this will hold the elf header

    int res = fread(&header, 1, sizeof(Elf64_Ehdr), to_trace);                              // try to read the elf header of the file to our struct
    if(res != sizeof(Elf64_Ehdr)) {                                                         // could not read
        exit(ERROR);
    }

    if(header.e_ident[0] != 0x7f ||                                                         // check if file is of ELF type
        header.e_ident[1] != 'E' ||
        header.e_ident[2] != 'L' ||
        header.e_ident[3] != 'F' ||
        header.e_type != ET_EXEC)                                                           // check if file is an executable
    {                                                          
        printf("PRF:: %s not an executable! :(\n",  file_name);  
        exit(ERROR);
    }
    fclose(to_trace); 
}

void checkFunction(char* file_name, char* func_name)
{
    int to_trace = open(file_name, O_RDONLY);                                               // try to open file to debug int an fd (because mmap later)
    if(to_trace == -1) {                                                                    // couldnt open fd - ABORT MISSION
        exit(ERROR);
    }

    void *elf_file = mmap(NULL, lseek(to_trace, 0, SEEK_END),                               // mmap the whole entire elf file - its like malloc but for really big chuncks of data
                          PROT_READ, MAP_PRIVATE, to_trace, 0);
    if(elf_file == MAP_FAILED) {                                                            // mmap failed - ABORT MISSION
        close(to_trace);
        exit(ERROR);
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

    int found_symbol = 0;                                                                   // this will serve as a boolean to mark if we found our function in the symtab
    for(int i = 0; i < symbol_num; i++)                                                     // go over symbols to look for our function
    {
        char* curr_symbol_name = strtab + symtab[i].st_name;                                // get the name of the current symbol in symtab 
        if(strcmp(func_name, curr_symbol_name) == 0)                                        // compare to our func name (strcmp returns 0 if the strings are equal)
        {     
            found_symbol = 1;                                                               // we found our symbol!                                 
            if(ELF64_ST_BIND(symtab[i].st_info) != GLOBAL) {                                // check if its global
                printf("PRF:: %s is not a global symbol! :(\n", func_name);
                close(to_trace);
                exit(ERROR);
            }
        }
    }
    if(found_symbol == 0) {                                                                 // check if we found the symbol at all
        printf("PRF:: %s not found!\n", func_name);
        close(to_trace);
        exit(ERROR);
    }
    close(to_trace);                                                                        // dont forget to close your fd!!
    // if we got to this point - the symbol is present and global!
}

int main(int argc, char *argv[])
{
    char* file_name = argv[2];                                                              // save name of executable file
    char* func_name = argv[1];                                                              // save name of function to run

    checkExecutable(file_name);                                                             // part 1 - check if the file is an executable
    checkFunction(file_name, func_name);                                                    // part 2+3 - check if func exists and if its global
    return 0;
}