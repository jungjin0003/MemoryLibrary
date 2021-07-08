#include "MemoryLibrary.h"

int main(int argc, char* argv[])
{
    char* DllName = "kernel32.dll";

    if (argc > 1)
    {
        DllName = argv[1];
    }

    printf("[+] File Name : %s\n", DllName);

    HANDLE hFile = CreateFileA(DllName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD Size = GetFileSize(hFile, NULL);
    printf("[*] File Size : %d Byte\n", Size);

    BYTE* Buffer = malloc(Size);
    ReadFile(hFile, Buffer, Size, &Size, NULL);
    printf("[+] File Opening!\n");

    ULONGLONG RowImageBase = Buffer;
    IMAGE_DOS_HEADER* DOS = Buffer;
    IMAGE_NT_HEADERS64* NT = RowImageBase + DOS->e_lfanew;
    ULONGLONG ImageBase;
    ULONGLONG OriginImageBase = NT->OptionalHeader.ImageBase;

    if (!(ImageBase = VirtualAlloc(NT->OptionalHeader.ImageBase, NT->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
    {
        ImageBase = VirtualAlloc(NULL, NT->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    if (ImageBase == NULL)
    {
        printf("[-] VirtualAlloc failed!!\n");
        free(Buffer);
        return -1;
    }
    printf("[*] ImageBase : 0x%p\n", ImageBase);

    memcpy(ImageBase, DOS, NT->OptionalHeader.SizeOfHeaders);
    printf("[+] PE headers writing by %d Byte\n", NT->OptionalHeader.SizeOfHeaders);

    IMAGE_SECTION_HEADER (*SECTION)[1] = RowImageBase + NT->OptionalHeader.SizeOfImage;
    printf("[*] First section : 0x%p\n", SECTION);

    for (int i = 0; i < NT->FileHeader.NumberOfSections; i++)
    {
        printf("[+] Section name : %s\n", SECTION[i]->Name);
        memcmp(ImageBase + SECTION[i]->VirtualAddress, RowImageBase + SECTION[i]->PointerToRawData, SECTION[i]->SizeOfRawData);
        printf("[+] Section mapping OK..!\n");
    }

    IMAGE_IMPORT_DESCRIPTOR (*IMPORT)[1] = ImageBase = NT->OptionalHeader.DataDirectory[1].VirtualAddress;
    printf("[*] IAT Recovery\n");

    for (int i = 0;; i++)
    {
        if (IMPORT[i]->OriginalFirstThunk == NULL)
            break;

        PSTR LibName = ImageBase + IMPORT[i]->Name;
        printf("[+] Library name : %s\n", LibName);

        HMODULE hModule;
        if (!(hModule = GetModuleHandleA(LibName)))
        {
            hModule = LoadLibraryA(LibName);
        }

        for (int j = 0; IMPORT[i]->OriginalFirstThunk + 8 * j; j++)
        {
            IMAGE_IMPORT_BY_NAME *IMPORT_NAME = ImageBase + *(ULONGLONG *)(IMPORT[i]->OriginalFirstThunk + 8 * j);
            printf("[+] Function name : %s\n", IMPORT_NAME->Name);
            *(ULONGLONG *)(IMPORT[i]->FirstThunk + 8 * j) = GetProcAddress(hModule, IMPORT_NAME->Name);
        }
    }

    if (ImageBase != NT->OptionalHeader.ImageBase)
    {
        IMAGE_BASE_RELOCATION *BASE_RELOCATION = NULL;
        for (int i = 0; i < NT->FileHeader.NumberOfSections; i++)
        {
            if (NT->OptionalHeader.DataDirectory[5].VirtualAddress == SECTION[i]->VirtualAddress)
            {
                BASE_RELOCATION = RowImageBase + SECTION[i]->PointerToRawData;
                break;
            }
        }

        DWORD SIZE_RELOCATION = NT->OptionalHeader.DataDirectory[5].Size;

        if (BASE_RELOCATION == NULL | SIZE_RELOCATION == 0)
        {
            printf("[-] This DLL is not supported Relocation!\n");
            return -1;
        }

        DWORD SIZE = 0;

        while (SIZE != SIZE_RELOCATION)
        {
            BASE_RELOCATION_ENTRY (*Type)[1] = (ULONGLONG)BASE_RELOCATION + 8;
            for (int i = 0; i < (BASE_RELOCATION->SizeOfBlock - 8) / 2; i++)
            {
                if ((*Type[i]).Offset != NULL)
                {
                    ULONGLONG *HardCodingAddress = ImageBase + BASE_RELOCATION->VirtualAddress + (*Type[i]).Offset;
                    ULONGLONG HardCodingData = *HardCodingAddress;

                    /*if (ReadProcessMemory(pi.hProcess, HardCodingAddress, &HardCodingData, 8, NULL) == NULL)
                    {
                        printf("[-] Reloc Read Failed!\n");
                        continue;
                    }*/

                    printf("[+] 0x%p : 0x%p -> ", HardCodingAddress, HardCodingData);

                    HardCodingData -= (ULONGLONG)OriginImageBase;
                    HardCodingData += (ULONGLONG)ImageBase;

                    printf("0x%p\n", HardCodingData);

                    *HardCodingAddress = HardCodingData;
                }
            }

            SIZE += BASE_RELOCATION->SizeOfBlock;
            BASE_RELOCATION = (ULONGLONG)BASE_RELOCATION + BASE_RELOCATION->SizeOfBlock;
        }
    }

    PVOID EntryPoint = ImageBase + NT->OptionalHeader.AddressOfEntryPoint;
    
}