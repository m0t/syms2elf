/*
Author:m0t
Fix elf section headers, add proper names
This was written to fix the output from the IDA script syms2elf, where symbols are added back into 
the binary, but the sections header are incorrectly named.

- some code has been taken from the Linux Anti Reversing book by Jacob Baines that i was reading when i was working on this (cool book btw)

- works for x86_64 only but should be easy to adapt to x86 if needed

*/

#include <cstdlib>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstring>
#include <stdexcept>
#include <map>
#include <elf.h>

typedef std::map<std::string, Elf64_Word> sh_map;

//retrieve ELF header ptr
Elf64_Ehdr* get_elf_header(std::string& p_data){
    if (p_data[0] != 0x7f || p_data[1] != 'E' || p_data[2] != 'L' || p_data[3] != 'F')
    {
        std::cerr << "[-] File format not recognised" << std::endl;
        //return NULL;
        throw std::runtime_error("bad file format");
    }
    return reinterpret_cast<Elf64_Ehdr*>(&p_data[0]);
}

/**
 * Finds the offset to the sections table.
 *
 * \param[in] p_data the ELF binary
 * \param[in,out] p_sec_count the number of sections in the section table
 * \param[in,out] p_str_index the section index of the section strings table
 * \return a pointer to the start of the sections table
 */
Elf64_Shdr* find_sections(std::string& p_data, int& p_sec_count, int& p_str_index)
{
    Elf64_Ehdr* ehdr = get_elf_header(p_data);

    Elf64_Off section_offset = ehdr->e_shoff;

    p_sec_count = ehdr->e_shnum;

    p_str_index = ehdr->e_shstrndx;

    return reinterpret_cast<Elf64_Shdr*>(&p_data[section_offset]);
}


/*
check if section name is what should be
*/
bool check_section_header_name(std::string& p_data, Elf64_Shdr* p_sh, const char* p_sh_name){
    //look up name of section
    std::string section_name;
    if (p_sh->sh_name != SHN_UNDEF){
        int sec_count, shstrtab_index;
        Elf64_Shdr* sections = find_sections(p_data, sec_count, shstrtab_index);
        Elf64_Off shstrtab_off = sections[shstrtab_index].sh_offset;;
        char* shstrtab = reinterpret_cast<char*>(&p_data[shstrtab_off]);
        section_name =  std::string(&shstrtab[p_sh->sh_name]);
    }
    else
        return false;

    if (section_name == p_sh_name ){
        return true;
    }

    //we'll ignore the case of a weird name, change it anyway and leave the old string in strtab anyway
    //Elf64_Word new_sh_name = add_section_name(p_data, ".symtab");
    //symtab->sh_name = new_sh_name;
    return false;
}

/*
retrieve actual symtab section header address
*/
Elf64_Shdr* get_symtab_sh(std::string& p_data){
    int s_count, shstrtab_index;
    Elf64_Shdr* sections = find_sections(p_data, s_count, shstrtab_index);
    Elf64_Shdr* symtab = NULL;
    std::string symtab_name;
    //search for symtab section
    for (Elf64_Shdr* s = sections; s < &(sections[s_count]); s++){
        if (s->sh_type == SHT_SYMTAB)
            symtab = s;
    }
    if (!symtab)
        throw std::runtime_error("No .Symtab found");

    return symtab;
}

/*
retrieve actual .strtab from binary. This must ignore .shstrtab and .dynstr
*/
Elf64_Shdr* get_strtab_sh(std::string& p_data){
    int s_count, shstrtab_index;
    Elf64_Shdr* sections = find_sections(p_data, s_count, shstrtab_index);
    Elf64_Shdr* strtabsh = NULL;
    std::string strtab_name;
    //search for symtab section
    for (Elf64_Shdr* s = sections; s < &(sections[s_count]); s++){
        if (s->sh_type == SHT_STRTAB && 
            !check_section_header_name(p_data, s, ".dynstr") && 
            !check_section_header_name(p_data, s, ".shstrtab"))
            strtabsh = s;
    }
    if (!strtabsh)
        throw std::runtime_error("No .Symtab found");

    return strtabsh;
}

/*
add the missing section names to shstrtab, 
for each key will add the string, 
then return in the map the new offset
i suppose we should return false or throw something if anything goes wrong, but still unsure on the definition of wrong
*/
bool add_section_header_names(std::string& p_data, sh_map& p_new_section_names){
    //copy current section header strtab
    int s_count, shstrtab_index;
    std::string new_strtab;
    Elf64_Shdr* sections = find_sections(p_data, s_count, shstrtab_index);

    Elf64_Shdr* shstrtab = &sections[shstrtab_index];
    Elf64_Off strtab_off = shstrtab->sh_offset;
    char* strtab_addr = reinterpret_cast<char*>(&p_data[strtab_off]);

    //actually this var is probably superfluos, can do it directly...
    char strtab[shstrtab->sh_size];
    memcpy(strtab, strtab_addr, shstrtab->sh_size);
    new_strtab.append(strtab, shstrtab->sh_size);

    //append new sections names, also insert the offsets in the map
    for (sh_map::iterator iter = p_new_section_names.begin(); iter != p_new_section_names.end(); iter++){
        iter->second = new_strtab.size();
        new_strtab += iter->first;
        new_strtab.push_back('\0');
        //s_count++;
    }
    //new_strtab.push_back('\x0');

    //fix elf header with new section headers count, not needed if sections are not new
    //Elf64_Ehdr* hdr = get_elf_header(p_data);
    //hdr->e_shnum = s_count;

    //the actual strtab is new, but we keep the shstrtab, so the shstrtab_index is ok
    //fix shstrtab->sh_offset with new offset in file os strtab
    //write new strtab
    shstrtab->sh_offset = p_data.size();
    shstrtab->sh_size = new_strtab.size();
    p_data += new_strtab;

    return true;
}

/*
this will find .symtab and .strtab section headers in the binary, and fix the names if wrong
*/
bool fix_section_names(std::string& p_data){
    /*
    alternative to the complicated map would be to extract the current strtab here, make a copy,
    add the missing string to the copy when needed, so we can know the right offset immediately,
    then write the resulting strtab as last thing
    */
    sh_map new_section_names = sh_map();
    
    //.symtab checks
    Elf64_Shdr* symtabsh = NULL;
    try {
        symtabsh = get_symtab_sh(p_data);
        if (!check_section_header_name(p_data, symtabsh, ".symtab") ) {
            std::cout << "[+] Bad symtab section name, fixing" << std::endl;
            new_section_names[".symtab"] = 0;
        }
        else {
            std::cout << "[-] Symtab section looks OK, continuing" << std::endl;
        }
    }
    catch (std::runtime_error) {
        std::cout << "[-] Could not find valid .symtab section, aborting" << std::endl;
        return false;
    }

    //.strtab checks
    Elf64_Shdr* strtabsh = NULL;
    try {
        strtabsh = get_strtab_sh(p_data);
        if (!check_section_header_name(p_data, strtabsh, ".strtab")){
            std::cout << "[+] Bad strtab section name, fixing" << std::endl;
            new_section_names[".strtab"] = 0;
        }
        else{
            std::cout << "[-] Strtab section looks OK, continuing" << std::endl;
        }
    }
    catch (std::runtime_error){
        std::cout << "[-] Could not find .strtab, aborting" << std::endl;
        return false;
    }

    //if needed, add new section names
    if (!new_section_names.empty() ) {
        if (add_section_header_names(p_data, new_section_names)){
            if (new_section_names.find(".symtab") != new_section_names.end())
                symtabsh->sh_name = new_section_names[".symtab"];
            if (new_section_names.find(".strtab") != new_section_names.end())
                strtabsh->sh_name = new_section_names[".strtab"];
        }
        else{
            std::cout << "[-] Error adding section header names in .strtab" << std::endl;
            return false;
        }
    }
    std::cout << "[+] All section names fixed" << std::endl;
    return true;
}

int main(int p_argc, char** p_argv)
{
    if (p_argc != 2)
    {
        std::cerr << "Usage: " << p_argv[0] << " <file path>" << std::endl;
        return EXIT_FAILURE;
    }

    std::ifstream inputFile(p_argv[1], std::ifstream::in | std::ifstream::binary);
    if (!inputFile.is_open() || !inputFile.good())
    {
        std::cerr << "Failed to ropen the provided file: " << p_argv[1] << std::endl;
        return EXIT_FAILURE;
    }

    std::string input((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
    inputFile.close();

    if (fix_section_names(input)){
        std::cout << "[+] Section names fixed" << std::endl;
    }
    else {
        std::cout << "[-] Failure, exiting" << std::endl;
        return EXIT_FAILURE;
    }
    
    std::ofstream outputFile(p_argv[1], std::ofstream::out | std::ofstream::binary);
    if (!outputFile.is_open() || !outputFile.good())
    {
        std::cerr << "Failed to wopen the provided file: " << p_argv[1] << std::endl;
        return EXIT_FAILURE;
    }

    outputFile.write(input.data(), input.length());
    outputFile.close();
    
    return EXIT_SUCCESS;
}