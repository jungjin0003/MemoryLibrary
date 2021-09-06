#include "CreateThread2.h"

HANDLE CustomWINAPI CreateThread2(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, DWORD dwCreationFlags, LPDWORD lpThreadId, SIZE_T dwParameterCount, ...);

VOID Helper(PDynamic_Parameter DynamicParameter)
{
    __asm__ __volatile__ (
        "mov r15, %[free]\n\t"
        "pop rbp\n\t"
        "mov rax, rcx\n\t"
        "mov eax, dword ptr ds:[rax+0x8]\n\t"
        "cmp eax, 0x4\n\t"
        "jbe SetArg1\n\t"
        "mov r12, qword ptr ds:[rsp]\n\t"
        "add rsp, 0x10\n\t"
        "mov rdx, rax\n\t"
        "sub eax, 0x3\n\t"
        "mov rbx, 0x8\n\t"
        "mul rbx\n\t"
        "sub rsp, rax\n\t"
        "xor rax, rax\n\t"
        "mov qword ptr ds:[rsp], r12\n\t"
        "SetArg1:\n\t"
        "mov eax, dword ptr ds:[rcx+0x8]\n\t"
        "dec eax\n\t"
        "mov rsi, 0xFFFFFFFFFFFFFFFF\n\t"
        "SetArg2:\n\t"
        "inc rsi\n\r"
        "mov rbx, qword ptr ds:[rcx+0x10+rsi*0x8]\n\t"
        "mov qword ptr ds:[rsp+rsi*0x8+0x8], rbx\n\t"
        "cmp esi, eax\n\t"
        "jne SetArg2\n\t"
        "push qword ptr ds:[rcx]\n\t"
        "push qword ptr ds:[rcx]\n\t"
        "sub rsp, 0x20\n\t"
        "call r15\n\t"
        "add rsp, 0x20\n\t"
        "pop rax\n\t"
        "pop rax\n\t"
        "mov rcx, qword ptr ds:[rsp+0x8]\n\t"
        "mov rdx, qword ptr ds:[rsp+0x10]\n\t"
        "mov r8, qword ptr ds:[rsp+0x18]\n\t"
        "mov r9, qword ptr ds:[rsp+0x20]\n\t"
        "jmp rax\n\t"
        :
        : [free] "r" (free)
    );
}

HANDLE CustomWINAPI CreateThread2(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, DWORD dwCreationFlags, LPDWORD lpThreadId, SIZE_T dwParameterCount, ...)
{
    Dynamic_Parameter *DynamicParameter = malloc(16 + dwParameterCount * 8);

    DynamicParameter->Function = lpStartAddress;
    DynamicParameter->Count = dwParameterCount;

    memcpy((ULONG)DynamicParameter + 16, (ULONG)&dwParameterCount + 8, dwParameterCount * 8);

    return CreateThread(lpThreadAttributes, dwStackSize, (LPTHREAD_START_ROUTINE)Helper, DynamicParameter, dwCreationFlags, lpThreadId);
}