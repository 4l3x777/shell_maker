#pragma once
#include <iostream>
#include <vector>
#include <Windows.h>

class ShellBuilder {

    std::vector<char> PE;
    std::vector<char> SHELL;

    PIMAGE_DOS_HEADER DosHdr(void* data);

    PIMAGE_NT_HEADERS NtHdr(void* data);

    PIMAGE_FILE_HEADER FileHdr(void* data);

    bool is_x86();

public:

    bool build_loader();

    bool load_PE(const char* path);

    bool save_SHELL();

    ShellBuilder() = default;
};