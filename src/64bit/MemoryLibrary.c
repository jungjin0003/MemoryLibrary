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
    }
}