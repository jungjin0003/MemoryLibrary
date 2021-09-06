#include "MemoryLibrary.h"
#include "Resource.h"

void (__stdcall *test)(char *name);

int main()
{
    HMODULE hModule = MemoryLoadLibrary(testdll);
    test = MemoryGetProcAddress(hModule, "test");
    test("World!");
}