#include <Windows.h>
#include <iostream>
#include <tlhelp32.h>


template<typename T>
T readMemory(HANDLE proc, LPVOID addr) {
    T val;
    ReadProcessMemory(proc, addr, &val, sizeof(T), NULL);
    return val;
}

template<typename T>
void writeMemory(HANDLE proc, LPVOID addr, T val) {
    WriteProcessMemory(proc, addr, &val, sizeof(T), NULL);
}

template<typename T>
DWORD protectMemoryEx(HANDLE proc, LPVOID adr, DWORD prot) {
    DWORD oldProt;
    VirtualProtectEx(proc, adr, sizeof(T), prot, &oldProt);
    return oldProt;
}

int getProcId(const wchar_t* target)
{
    DWORD pId = 0;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    do {
        if (wcscmp(pe32.szExeFile, target) == 0) {
            pId = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));
    CloseHandle(hSnapshot);
    return pId;
}


DWORD GetProcessThreadID(HANDLE Process)
{
    THREADENTRY32 entry;
    entry.dwSize = sizeof(THREADENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (Thread32First(snapshot, &entry) == TRUE)
    {
        DWORD PID = GetProcessId(Process);
        while (Thread32Next(snapshot, &entry) == TRUE)
        {
            if (entry.th32OwnerProcessID == PID)
            {
                CloseHandle(snapshot);
                return entry.th32ThreadID;
            }
        }
    }
    CloseHandle(snapshot);
    return NULL;
}

void injectCodeUsingThreadInjection(HANDLE process, LPVOID func, int times, const char* string)
{
    BYTE codeCave[28] = {
        0x52,                                           // push rdx
        0x51,                                           // push rcx
        0x48, 0x8b, 0x14, 0x24,                         // mov rdx, qword ptr [rsp]
        0x48, 0xc7, 0xc1, 0x01, 0x00, 0x00, 0x00,       // mov rcx, 0x(times)
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00,             // movabs rax, 0x(hiddenFunction)
        0x00, 0x00, 0x00, 0x00,
        0xff, 0xd0,                                     // call rax
        0x59,                                           // pop rcx
        0x5A,                                           // pop rdx
        0xC3                                            // ret
    };

    // copy values to the shellcode
    memcpy(&codeCave[9], &times, 4);
    memcpy(&codeCave[15], func, 8);


    // allocate memory for the code cave
    int stringlen = strlen(string) + 1;
    int fulllen = stringlen + sizeof(codeCave);
    LPVOID remoteString = VirtualAllocEx(process, NULL, fulllen, MEM_COMMIT, PAGE_EXECUTE);
    if (remoteString != 0x0) {
        printf("[debug] VirtualAllocEx was successful\n");
    }
    LPVOID remoteCave = (LPVOID)((DWORD64)remoteString + stringlen);
    printf("[debug] remoteCave is at: 0x%p\n", remoteCave);


    // write the code cave
    bool result = WriteProcessMemory(process, remoteString, string, stringlen, NULL);
    if (result) {
        printf("[debug] Writing string to process memory was successful\n");
    }
    result = WriteProcessMemory(process, remoteCave, codeCave, sizeof(codeCave), NULL);
    if (result) {
        printf("[debug] Writing code cave to process memory was successful\n");
    }

    // run the thread
    HANDLE thread = CreateRemoteThread(process, NULL, NULL,
        (LPTHREAD_START_ROUTINE)remoteCave,
        remoteString, NULL, NULL);
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
}

void injectCodeUsingThreadHijacking(HANDLE process, LPVOID func, int times, const char* string)
{
    BYTE codeCave[93] = { 
        0x50,                               // push rax
        0x51,                               // push rcx
        0x52,                               // push rdx
        0x41, 0x50,                         // push r8
        0x41, 0x51,                         // push r9
        0x41, 0x52,                         // push r10
        0x41, 0x53,                         // push r11
        0x9C,                               // pushf
        0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, // movabs rax, 0x(string)
        0xEF, 0xBE, 0xAD, 0xDE, 
        0x50,                               // push rax
        0x48, 0x8B, 0x14, 0x24,             // mov rdx, qword ptr [rsp]
        0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, // movabs rax, 0x(times)
        0x00, 0x00, 0x00, 0x00,
        0x50,                               // push rax
        0x48, 0x8B, 0x0C, 0x24,             // mov rcx, qword ptr [rsp]
        0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, // movabs rax, 0x(hiddenfunction)
        0xEF, 0xBE, 0xAD, 0xDE,
        0x48, 0x83, 0xEC, 0x20,             // sub rsp, 0x20
        0xFF, 0xD0,                         // call rax
        0x48, 0x83, 0xC4, 0x20,             // add rsp, 0x20
        0x48, 0x83, 0xC4, 0x10,             // add rsp, 0x10
        0x9D,                               // popf
        0x41, 0x5B,                         // pop r11
        0x41, 0x5A,                         // pop r10
        0x41, 0x59,                         // pop r9
        0x41, 0x58,                         // pop r8
        0x5A,                               // pop rdx
        0x59,                               // pop rcx
        0xC7, 0x04, 0x24, 0xEF, 0xBE, 0xAD, // mov dword ptr [rsp], low RIP bits
        0xDE, 
        0xC7, 0x44, 0x24, 0x04, 0xEF, 0xBE, // mov dword ptr [rsp+4], high RIP bits
        0xAD, 0xDE,
        0xC3                                // ret
    };

    // allocate memory for the code cave
    int stringlen = strlen(string) + 1;
    int fulllen = stringlen + sizeof(codeCave);
    LPVOID remoteString = VirtualAllocEx(process, NULL, fulllen, MEM_COMMIT, PAGE_EXECUTE);
    if (remoteString != 0x0) {
        printf("[debug] VirtualAllocEx was successful\n");
    }
    LPVOID remoteCave = (LPVOID)((DWORD64)remoteString + stringlen);
    printf("[debug] remoteCave is at: 0x%p\n", remoteCave);

    // suspend the thread and query its control context
    DWORD threadID = GetProcessThreadID(process);
    HANDLE thread = OpenThread((THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT), false, threadID);
    SuspendThread(thread);

    CONTEXT threadContext;
    threadContext.ContextFlags = CONTEXT_CONTROL;
    GetThreadContext(thread, &threadContext);
    printf("[debug] original RIP is: 0x%p\n", threadContext.Rip);

    // copy values to the shellcode (happens late because we need values from allocation)
    memcpy(&codeCave[14], &remoteString, 8);
    memcpy(&codeCave[29], &times, 4);
    memcpy(&codeCave[44], func, 8);
    DWORD threadContextLow = (DWORD)threadContext.Rip & 0xFFFFFFFF;
    memcpy(&codeCave[80], &threadContextLow, 4);
    printf("[debug] threadContextLow is: 0x%p\n", threadContextLow);
    DWORD threadContextHigh = (DWORD)(threadContext.Rip >> 32) & 0xFFFFFFFF;
    printf("[debug] threadContextHigh is: 0x%p\n", threadContextHigh);
    memcpy(&codeCave[88], &threadContextHigh, 4);


    // write the code cave
    bool result = WriteProcessMemory(process, remoteString, string, stringlen, NULL);
    if (result) {
        printf("[debug] Writing string to process memory was successful\n");
    }
    result = WriteProcessMemory(process, remoteCave, codeCave, sizeof(codeCave), NULL);
    if (result) {
        printf("[debug] Writing code cave to process memory was successful\n");
    }

    //hijack the thread
    threadContext.Rip = (DWORD64)remoteCave;
    threadContext.ContextFlags = CONTEXT_CONTROL;
    SetThreadContext(thread, &threadContext);
    ResumeThread(thread);

    //clean
    CloseHandle(thread);
}


int main()
{
    //  write variables to code cave, write code cave into target process and execute it via thread hijacking
    // code cave should call internal function hiddenFunction in admin_check.exe

    /* HANDLE */
    const wchar_t* process = L"admin_check.exe";
    int pId = getProcId(process);
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pId);

    if (process == INVALID_HANDLE_VALUE) {
        printf("Failed to open PID %d, error code %d", pId, GetLastError());
    }

    /* VARIABLES */
    LPVOID address = (LPVOID)0x00007FF7E1EF10F0;  // hiddenFunction address from debugger. how can i get this dynamically?
    int times = 2;

    // inject code into admin_check.exe using thread injection
    //injectCodeUsingThreadInjection(hProcess, &address, times, "injected\n");

    // inject code into admin_check.exe using thread hijacking
    injectCodeUsingThreadHijacking(hProcess, &address, times, "hijacked\n");

    return 0;
}
