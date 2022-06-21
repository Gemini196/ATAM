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
#define DT_PLTRELSZ 2
#define ET_EXEC 2
#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define DT_PLTGOT 3
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
    Elf64_Word strtab_section_num;
    void *tab = NULL;
    
    for(int i = 0; i < header->e_shnum; i++)                                                // find and fill symtab and strtab
    {
        if (sh_type == SHT_STRTAB)                                                          // make sure we get the strtab associated with .symtab and NOT .shstrtab OR .dynstr !! (all of same type: STRTAB)
        {
            if (sec_headers_arr[i].sh_type == SHT_SYMTAB) {
                strtab_section_num = sec_headers_arr[i].sh_link;
            }
            if (i == strtab_section_num) {
                 tab = (void*)(elf_file + sec_headers_arr[i].sh_offset);
                 break;
            }
        }
        else if (sec_headers_arr[i].sh_type == sh_type)
        {
            tab = (void*)(elf_file + sec_headers_arr[i].sh_offset);
            *entry_num = sec_headers_arr[i].sh_size / sec_headers_arr[i].sh_entsize;
            break;
        }
    }

    return tab;
}




// Name: findSymbol
// Recieves symbol table parameters & func_name
// Returns whether it exists there/not/if global..
int findSymbol(Elf64_Sym *symtab, char *strtab, char* func_name, int symbol_num)
{
    bool found_symbol = false;                                                              // this will serve as a boolean to mark if we found our function in the symtab

    for(int i = 0; i < symbol_num; i++)                                                   // go over symbols to look for our function
    {
        char* curr_symbol_name = strtab + symtab[i].st_name;                                // get the name of the current symbol in symtab 
        //printf("%s\n",curr_symbol_name);
        if(strcmp(func_name, curr_symbol_name) == 0)                                        // compare to our func name (strcmp returns 0 if the strings are equal)
        {     
            found_symbol = true;                                                            // we found our symbol!                                 
            if(ELF64_ST_BIND(symtab[i].st_info) != GLOBAL) {                                // check if its global
                return ERROR_SYMBOL_NOT_GLOBAL;   // Y not immediately return success???????????????????????????????????????????????????????????????????????????????
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
int checkFunction(char* file_name, char* func_name, unsigned long* func_addr)
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
        return ERROR;
    }

    int sym_num = 0, str_num=0;
    Elf64_Sym *symtab = (Elf64_Sym*)findSectionTable(elf_file, SHT_SYMTAB, &sym_num);
    char *strtab = (char*)findSectionTable(elf_file, SHT_STRTAB, &str_num);

    int res = findSymbol(symtab, strtab, func_name, sym_num);
    *func_addr = getFuncAddr(elf_file, symtab, strtab, func_name, sym_num);                 // part 4
    close(to_trace); 
    munmap(elf_file, size);                                                                 // dont forget to close your fd!!
    return res;                                                                    
}


// Part 4
long getFuncAddr(void *elf_file, Elf64_Sym *symtab, char *strtab, char* func_name, int sym_num)
{
    // Try finding the function in executable file
    for(int i = 0; i < sym_num; i++)                                                     // go over symbols to look for our function
    {
        char* curr_symbol_name = strtab + symtab[i].st_name;                                // get the name of the current symbol in symtab 
        if(strcmp(func_name, curr_symbol_name) == 0)                                        // compare to our func name (strcmp returns 0 if the strings are equal)
        {     
            if(symtab[i].st_shndx != SHN_UNDEF) {                                           // index in file exists - return value (=the function's address)
                return (long)symtab[i].st_value;
            }
            break;
        }  
    }
    
    // IF WE HERE - SYMBOL IS UND - Now we must go over dynamic symbols and pray
    //////////////////////////////////////////////////// PLZ CONTINUE HERE ////////////////////////////////////////////////////////////
    int entry_num = 0;
    unsigned long plt_addr = 0;
   

   /* WHAT DO*/
    /*
    1. get relocation table and put it in struct 
    2. go over relocation table entries & find relevant rela entry (how? using dynamic table?)
    3. check relocation type (ELF64_R_TYPE)?.. (there's more than one & calculations differ..)
    4. calculate address
    5. return


   /*general data*/
   /*
   Rela entries contain an explicit addend. Entries of type Rel store an implicit addend in the location to be modified
   In all cases, the r_offset value designates the offset or virtual address of the first byte of the affected storage unit.
   The relocation type specifies which bits to change and how to calculate their values.
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





/*void* findSectionTable (void* elf_file, Elf64_Word sh_type, int* entry_num)
{
    Elf64_Ehdr* header = (Elf64_Ehdr*)elf_file;                                             // the elf header is at the beginning - we can cast it with C magic!
    Elf64_Shdr* sec_headers_arr = (Elf64_Shdr*)(elf_file + header->e_shoff);                // now we can get the section headers by using the offset from the elf header
    Elf64_Word strtab_section_index;
    void *tab = NULL;
    
    if (sh_type == SHT_STRTAB)                                                                  // make sure we get the strtab associated with .symtab and NOT .shstrtab OR .dynstr !! (all of same type: STRTAB)
    {
        for(int i = 0; i < header->e_shnum; i++)                                                // find and fill symtab and strtab
        {
            if (sec_headers_arr[i].sh_type == SHT_SYMTAB) {
                strtab_section_index = sec_headers_arr[i].sh_link;
            }
            if (i == strtab_section_index) {
                 tab = (void*)(elf_file + sec_headers_arr[i].sh_offset);
                 return tab;
            }
        }
    }// check possibility for strtab BEFORE symtab!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

    // not looking for strtab
    else{
        for(int i = 0; i < header->e_shnum; i++)                                                // find and fill symtab and strtab
        {
            if (sec_headers_arr[i].sh_type == sh_type)
            {
                tab = (void*)(elf_file + sec_headers_arr[i].sh_offset);
                *entry_num = sec_headers_arr[i].sh_size / sec_headers_arr[i].sh_entsize;
                return tab;
            }
        }
    }

    
    return tab;
}*/

