#pragma once

#include <stdio.h>
#include <windows.h>

#define CustomWINAPI WINAPI

typedef struct Dynamic_Parameter
{
    LPTHREAD_START_ROUTINE Function;
    unsigned int Count;
    PVOID Parameter[1];
} Dynamic_Parameter, *PDynamic_Parameter;

HANDLE CustomWINAPI CreateThread2(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, DWORD dwCreationFlags, LPDWORD lpThreadId, SIZE_T dwParameterCount, ...);