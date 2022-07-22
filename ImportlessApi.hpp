/*
    Created by Yoav Shaharabani (github.com/yoavshah)
    Use with your own risk and care.
    DO NOT USE FOR MALICIOUS PURPOSES!

    FOLLOW ME ON GITHUB AND BUY ME A COFFEE
*/

#include <Windows.h>
#include <winreg.h>

#pragma once

/* Convert definition to function name. CreateFile to CreateFileA or CreateFileW based on configurations. */
#define REAL_DEFINITION(x) #x

#define IMPORTLESS_API_START_NUMBER 0x1928471f

#define DATE_AND_TIME __TIME__ __DATE__


namespace importless_api
{
    namespace win {
        struct LIST_ENTRY_T {
            LIST_ENTRY_T* Flink;
            LIST_ENTRY_T* Blink;
        };

        struct UNICODE_STRING_T {
            unsigned short Length;
            unsigned short MaximumLength;
            wchar_t* Buffer;
        };

        struct PEB_LDR_DATA_T {
            unsigned long Length;
            unsigned long Initialized;
            const char* SsHandle;
            LIST_ENTRY_T  InMemoryOrderLinks;
        };

        struct PEB_T {
            unsigned char   Reserved1[2];
            unsigned char   BeingDebugged;
            unsigned char   Reserved2[1];
            const char* Reserved3[2];
            PEB_LDR_DATA_T* Ldr;
        };

        struct LDR_DATA_TABLE_ENTRY_T {
            LIST_ENTRY_T InLoadOrderLinks;
            LIST_ENTRY_T InMemoryOrderLinks;
            LIST_ENTRY_T InInitializationOrderLinks;
            char* DllBase;
            const char* EntryPoint;
            union {
                unsigned long SizeOfImage;
                const char* _dummy;
            };
            UNICODE_STRING_T FullDllName;
            UNICODE_STRING_T BaseDllName;
        };

        struct IMAGE_DOS_HEADER_T { // DOS .EXE header
            unsigned short e_magic; // Magic number
            unsigned short e_cblp; // Bytes on last page of file
            unsigned short e_cp; // Pages in file
            unsigned short e_crlc; // Relocations
            unsigned short e_cparhdr; // Size of header in paragraphs
            unsigned short e_minalloc; // Minimum extra paragraphs needed
            unsigned short e_maxalloc; // Maximum extra paragraphs needed
            unsigned short e_ss; // Initial (relative) SS value
            unsigned short e_sp; // Initial SP value
            unsigned short e_csum; // Checksum
            unsigned short e_ip; // Initial IP value
            unsigned short e_cs; // Initial (relative) CS value
            unsigned short e_lfarlc; // File address of relocation table
            unsigned short e_ovno; // Overlay number
            unsigned short e_res[4]; // Reserved words
            unsigned short e_oemid; // OEM identifier (for e_oeminfo)
            unsigned short e_oeminfo; // OEM information; e_oemid specific
            unsigned short e_res2[10]; // Reserved words
            long           e_lfanew; // File address of new exe header
        };

        struct IMAGE_FILE_HEADER_T {
            unsigned short Machine;
            unsigned short NumberOfSections;
            unsigned long  TimeDateStamp;
            unsigned long  PointerToSymbolTable;
            unsigned long  NumberOfSymbols;
            unsigned short SizeOfOptionalHeader;
            unsigned short Characteristics;
        };

        struct IMAGE_EXPORT_DIRECTORY_T {
            unsigned long  Characteristics;
            unsigned long  TimeDateStamp;
            unsigned short MajorVersion;
            unsigned short MinorVersion;
            unsigned long  Name;
            unsigned long  Base;
            unsigned long  NumberOfFunctions;
            unsigned long  NumberOfNames;
            unsigned long  AddressOfFunctions; // RVA from base of image
            unsigned long  AddressOfNames; // RVA from base of image
            unsigned long  AddressOfNameOrdinals; // RVA from base of image
        };

        struct IMAGE_DATA_DIRECTORY_T {
            unsigned long VirtualAddress;
            unsigned long Size;
        };

        struct IMAGE_OPTIONAL_HEADER64_T {
            unsigned short       Magic;
            unsigned char        MajorLinkerVersion;
            unsigned char        MinorLinkerVersion;
            unsigned long        SizeOfCode;
            unsigned long        SizeOfInitializedData;
            unsigned long        SizeOfUninitializedData;
            unsigned long        AddressOfEntryPoint;
            unsigned long        BaseOfCode;
            unsigned long long   ImageBase;
            unsigned long        SectionAlignment;
            unsigned long        FileAlignment;
            unsigned short       MajorOperatingSystemVersion;
            unsigned short       MinorOperatingSystemVersion;
            unsigned short       MajorImageVersion;
            unsigned short       MinorImageVersion;
            unsigned short       MajorSubsystemVersion;
            unsigned short       MinorSubsystemVersion;
            unsigned long        Win32VersionValue;
            unsigned long        SizeOfImage;
            unsigned long        SizeOfHeaders;
            unsigned long        CheckSum;
            unsigned short       Subsystem;
            unsigned short       DllCharacteristics;
            unsigned long long   SizeOfStackReserve;
            unsigned long long   SizeOfStackCommit;
            unsigned long long   SizeOfHeapReserve;
            unsigned long long   SizeOfHeapCommit;
            unsigned long        LoaderFlags;
            unsigned long        NumberOfRvaAndSizes;
            IMAGE_DATA_DIRECTORY_T DataDirectory[16];
        };

        struct IMAGE_OPTIONAL_HEADER32_T {
            unsigned short       Magic;
            unsigned char        MajorLinkerVersion;
            unsigned char        MinorLinkerVersion;
            unsigned long        SizeOfCode;
            unsigned long        SizeOfInitializedData;
            unsigned long        SizeOfUninitializedData;
            unsigned long        AddressOfEntryPoint;
            unsigned long        BaseOfCode;
            unsigned long        BaseOfData;
            unsigned long        ImageBase;
            unsigned long        SectionAlignment;
            unsigned long        FileAlignment;
            unsigned short       MajorOperatingSystemVersion;
            unsigned short       MinorOperatingSystemVersion;
            unsigned short       MajorImageVersion;
            unsigned short       MinorImageVersion;
            unsigned short       MajorSubsystemVersion;
            unsigned short       MinorSubsystemVersion;
            unsigned long        Win32VersionValue;
            unsigned long        SizeOfImage;
            unsigned long        SizeOfHeaders;
            unsigned long        CheckSum;
            unsigned short       Subsystem;
            unsigned short       DllCharacteristics;
            unsigned long        SizeOfStackReserve;
            unsigned long        SizeOfStackCommit;
            unsigned long        SizeOfHeapReserve;
            unsigned long        SizeOfHeapCommit;
            unsigned long        LoaderFlags;
            unsigned long        NumberOfRvaAndSizes;
            IMAGE_DATA_DIRECTORY_T DataDirectory[16];
        };

#ifdef _WIN64
        typedef IMAGE_OPTIONAL_HEADER64_T IMAGE_OPTIONAL_HEADER_T;
#else
        typedef IMAGE_OPTIONAL_HEADER32_T IMAGE_OPTIONAL_HEADER_T;
#endif

        struct IMAGE_NT_HEADERS_T {
            unsigned long     Signature;
            IMAGE_FILE_HEADER_T FileHeader;
            IMAGE_OPTIONAL_HEADER_T OptionalHeader;
        };
    }

    /*
        Hash string with start value.
        Choosed the hash function based on "The Last Stage of Delerium. Win32 Assembly Components"
    */
    constexpr UINT32 hash_str(const char* func_name, const UINT32 value)
    {

        UINT32 hash = value;
        for (;;)
        {
            char c = *func_name;
            func_name++;
            if (!c)
                return hash;

            hash = (((hash << 5) | (hash >> 27)) + c) & 0xFFFFFFFF;
        }
    }

    template<UINT32 hash> class importless_api
    {

    private:
        /* Getting the PEB struct from register based on architecture. */
        const win::PEB_T* peb() noexcept
        {
#if defined(_M_X64) || defined(__amd64__)
            return reinterpret_cast<const win::PEB_T*>(__readgsqword(0x60));
#elif defined(_M_IX86) || defined(__i386__)
            return reinterpret_cast<const win::PEB_T*>(__readfsdword(0x30));
#elif defined(_M_ARM) || defined(__arm__)
            return *reinterpret_cast<const win::PEB_T**>(_MoveFromCoprocessor(15, 0, 13, 0, 2) + 0x30);
#elif defined(_M_ARM64) || defined(__aarch64__)
            return *reinterpret_cast<const win::PEB_T**>(__getReg(18) + 0x60);
#elif defined(_M_IA64) || defined(__ia64__)
            return *reinterpret_cast<const win::PEB_T**>(static_cast<char*>(_rdteb()) + 0x60);
#else
#error Unsupported platform. 
#endif
        }




    public:

        importless_api()
        {}

        UINT32 get_hash()
        {
            return hash;
        }

        /* Iterates over the PEB and all exported functions to find function by hash. */
        LPVOID get_function()
        {
            win::LDR_DATA_TABLE_ENTRY_T* curr_module = (win::LDR_DATA_TABLE_ENTRY_T*)peb()->Ldr->InMemoryOrderLinks.Flink;

            /* Iterate over loaded modules. */
            while (curr_module->BaseDllName.Buffer != NULL) {
                char* hBase = curr_module->DllBase;


                win::IMAGE_DOS_HEADER_T* hImageDosHeader = (win::IMAGE_DOS_HEADER_T*)hBase;
                win::IMAGE_NT_HEADERS_T* hImageNtHeaders = (win::IMAGE_NT_HEADERS_T*)(hBase + hImageDosHeader->e_lfanew);

                /* If export table exists. */
                if (hImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress != 0)
                {
                    win::IMAGE_EXPORT_DIRECTORY_T* hImageExportDirectory = (win::IMAGE_EXPORT_DIRECTORY_T*)(hBase + hImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);

                    PDWORD pNamePointers = (PDWORD)(hBase + hImageExportDirectory->AddressOfNames);
                    PWORD pOrdinalPointers = (PWORD)(hBase + hImageExportDirectory->AddressOfNameOrdinals);
                    PDWORD pAddressesPointers = (PDWORD)(hBase + hImageExportDirectory->AddressOfFunctions);

                    /* Iterate over functions and check their hash. */
                    for (size_t i = 0; i < hImageExportDirectory->NumberOfNames; ++i, ++pNamePointers, ++pOrdinalPointers)
                    {
                        UINT32 func_hash = hash_str(hBase + *pNamePointers, importless_api<hash_str(DATE_AND_TIME, IMPORTLESS_API_START_NUMBER)>().get_hash());
                        if (func_hash == hash)
                        {
                            DWORD dwFuncRVA = pAddressesPointers[*pOrdinalPointers];

                            /* Return function address. */
                            return hBase + dwFuncRVA;
                        }
                    }
                }

                curr_module = (win::LDR_DATA_TABLE_ENTRY_T*)curr_module->InLoadOrderLinks.Flink;
            }

            return NULL;
        }


    };
};



/*
    Example usage:
        Handle hFile = IMPORTLESS_API(CreateFile)(Parameters);
*/
#define IMPORTLESS_API(func_name) static_cast<decltype(&func_name)>(importless_api::importless_api<importless_api::hash_str(REAL_DEFINITION(func_name), importless_api::hash_str(DATE_AND_TIME, IMPORTLESS_API_START_NUMBER))>().get_function())

#define IMPORTLESS_API_STR(func_name, t) static_cast<t>(importless_api::importless_api<importless_api::hash_str(func_name, importless_api::hash_str(DATE_AND_TIME, IMPORTLESS_API_START_NUMBER))>().get_function())


