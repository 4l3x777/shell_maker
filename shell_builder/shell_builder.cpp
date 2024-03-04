#include <iostream>
#include <fstream>
#include <iterator>

#include "shell_builder.h"
#include "utils.h"

#include "shell_loader_exe_x86.h"
#include "shell_loader_exe_x64.h"

#define PUT_BYTE(p, v)     { *(uint8_t *)(p) = (uint8_t) (v); p = (uint8_t*)p + 1; }
#define PUT_WORD(p, v)     { t=v; memcpy((char*)p, (char*)&t, 4); p = (uint8_t*)p + 4; }
#define PUT_BYTES(p, v, n) { memcpy(p, v, n); p = (uint8_t*)p + n; }

PIMAGE_DOS_HEADER ShellBuilder::DosHdr(void* data) { return (PIMAGE_DOS_HEADER)data; }
PIMAGE_NT_HEADERS ShellBuilder::NtHdr(void* data) { return (PIMAGE_NT_HEADERS)((uint8_t*)data + DosHdr(data)->e_lfanew); }
PIMAGE_FILE_HEADER ShellBuilder::FileHdr(void* data) { return &NtHdr(data)->FileHeader; }

bool ShellBuilder::is_x86() { return FileHdr(PE.data())->Machine == IMAGE_FILE_MACHINE_I386; }

bool ShellBuilder::build_loader() {
    uint8_t* pl;
    uint32_t t;
    size_t payload_len;
    if (is_x86()) payload_len = sizeof(SHELL_LOADER_EXE_X86) + PE.size() + 32;
    else payload_len = sizeof(SHELL_LOADER_EXE_X64) + PE.size() + 32;
    SHELL.resize(payload_len);
    printf("Inserting opcodes\n");
    pl = (uint8_t*)SHELL.data();
    PUT_BYTE(pl, 0xE8);
    PUT_WORD(pl, PE.size());
    PUT_BYTES(pl, PE.data(), PE.size());
    PUT_BYTE(pl, 0x59);
    if (is_x86()) 
    {
        PUT_BYTE(pl, 0x5A);
        PUT_BYTE(pl, 0x51);
        PUT_BYTE(pl, 0x52);
        printf("Copying %" PRIi32 " bytes of x86 shellcode loader\n",
            (uint32_t)sizeof(SHELL_LOADER_EXE_X86));
        PUT_BYTES(pl, SHELL_LOADER_EXE_X86, sizeof(SHELL_LOADER_EXE_X86));
    }
    else 
    {
        printf("Copying %" PRIi32 " bytes of x64 shellcode loader\n",
            (uint32_t)sizeof(SHELL_LOADER_EXE_X64));
        PUT_BYTES(pl, SHELL_LOADER_EXE_X64, sizeof(SHELL_LOADER_EXE_X64));
    }
    printf("Final shellcode size is %" PRIi32 "\n",
        (uint32_t)SHELL.size());
    return true;
}

bool ShellBuilder::load_PE(const char* path) {
    if (!PE.empty()) PE.clear();
    std::ifstream file(path, std::ios::binary);
    if (file.fail()) {
        std::cout << "File " << path << " not found!" << std::endl;
        return false;
    }
    PE = std::vector<char>(std::istreambuf_iterator<char>(file), {});
    return true;
}

bool ShellBuilder::save_SHELL() {
    std::ofstream file("shell.bin", std::ios::out | std::ios::binary);
    file.write((char*)&SHELL[0], SHELL.size() * sizeof(char));
    file.close();
    std::cout << "File shell.bin saved!" << std::endl;
    return true;
};