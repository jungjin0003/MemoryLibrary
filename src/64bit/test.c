#include <stdio.h>
#include <windows.h>
#include <process.h>

#define DllExport __declspec(dllexport)

DllExport void __stdcall test(char* name);

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        printf("%s\n", "DLL_PROCESS_ATTACH");
        break;
    case DLL_PROCESS_DETACH:
        printf("%s\n", "DLL_PROCESS_DETACH");
        break;
    case DLL_THREAD_ATTACH:
        printf("%s\n", "DLL_THREAD_ATTACH");
        break;
    case DLL_THREAD_DETACH:
        printf("%s\n", "DLL_THREAD_DETACH");
        break;
    }

    return TRUE;
}

DllExport void __stdcall test(char* name)
{
    printf("Hello %s\n", name);
}