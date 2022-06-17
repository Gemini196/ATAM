#include "elf64.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdlib.h>

#define ERROR -1
#define ET_EXEC 2
#define SHT_SYMTAB 2
#define SHT_STRTAB 3

int main(int argc, char *argv[])
{
    FILE* to_trace = fopen(argv[2], "r");                                                   // try to open file to debug
    if(to_trace == NULL) {                                                                  // file does not exist
            //printf("PRF:: %s doeas not exist! :(\n", argv[2]);
            exit(ERROR);
    }

    Elf64_Ehdr header;

    int res = fread(&header, 1, sizeof(Elf64_Ehdr), to_trace);                              // try to read the elf header of the file to our struct
    if(res != sizeof(Elf64_Ehdr)) {                                                         // could not read
        exit(ERROR);
    }

    if(header.e_type != ET_EXEC) {                                                          // check if file is an executable
        printf("PRF:: %s not an executable! :(\n",  argv[2]);  
        exit(ERROR);
    }

    // rewind(to_trace);                                                                    // TO DO - maybe need to reset the seek pointer
    fseek(to_trace, header.e_shoff, SEEK_SET);                                        // move seek pointer to where we want it


    Elf64_Shdr *sec_headers = malloc(sizeof(Elf64_Shdr) * header.e_shnum);                  // arry of section headers                                             
    if(sec_headers == NULL) {                                                               // mllco failed
        exit(ERROR);
    }

    res = fread(sec_headers, header.e_shentsize, header.e_shnum, to_trace);                 // read all section headers
    if(res != header.e_shentsize * header.e_shnum) {                                        // could not read all headers
        exit(ERROR);
    }

    int sym_num = 0;
    for (int i = 0; i < header.e_shnum; i++)                                                // go over section headers to find symbol table
    {
        if(sec_headers[i].sh_type == SHT_SYMTAB) {                                          // found it!!
            sym_num += sec_headers[i].sh_size / sizeof(Elf64_Sym);                          // remember symbol number for later
        }
    }
    
    Elf64_Sym *symtab = malloc(sym_num * sizeof(Elf64_Sym));                                // alloc symbol table  
    char **names = malloc(sizeof(char*) * header.e_shnum);                                 // alloc string array for section names
    Elf64_Word *sym_sec_link = malloc(sizeof(Elf64_Word) * sym_num);                        // alloc array for each symbol section link (section index)
    if(symtab == NULL || names == NULL || sym_sec_link ==NULL) {                            // malloc failed - ABORT MISSION
        exit(ERROR);
    }

    for (int i = 0; i < header.e_shnum; i++)
    {
        if(sec_headers[i].sh_type == SHT_SYMTAB)                                            // fill symbol table and strtab
        {                                          
            // rewind(to_trace);                                                            // reset seek pointer to beginning of file
            fseek(to_trace, sec_headers[i].sh_offset, SEEK_SET);                            // set the seek point to where the symtab is
            res = fread(symtab, sizeof(Elf64_Sym), sym_num, to_trace);                      // read the symtab into array
            if(res != sym_num * sizeof(Elf64_Sym)) {                                        // read failed - ABORT MISSION
                exit(ERROR);
            }

            for (int j = 0, k = sym_sec_link; j < sym_num; j++, k+= sizeof(Elf64_Word)) {   // fill symbol section link table - for each symbol add the section num
                sym_sec_link[k] = sec_headers[i].sh_link;
            }
        }
        if(sec_headers[i].sh_type == SHT_STRTAB)                                            // fill srtab
        {
            // rewind(to_trace);                                                            // reset seek pointer to beginning of file
            fseek(to_trace, sec_headers[i].sh_offset, SEEK_SET);                            // set the seek point to where the symtab is
            names[i] = (char *) malloc(sizeof(char) * sec_headers[i].sh_size);              // alloc the string 
            if(names[i] == NULL) {
                exit(ERROR);
            }
            res = fread(names[i], sizeof(char), sec_headers[i].sh_size, to_trace);
            if(res != sizeof(char) * sec_headers[i].sh_size) {
                exit(ERROR);
            }
        } else {
            names[i] = NULL;
        }
        
    }
    

    free(sec_headers);
    free(symtab);
    fclose(to_trace);
    return 0;
}