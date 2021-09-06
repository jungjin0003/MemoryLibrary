#pragma once

#include <stdio.h>
#include <windows.h>

#include "./CreateThread2/CreateThread2.h"

#define MZ 0x5A4D
#define PE 0x00004550

typedef struct _BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

HMODULE MemoryLoadLibrary(BYTE* MemoryStream);
FARPROC MemoryGetProcAddress(HMODULE hModule, LPCSTR lpProcName);