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

int main()
{
    //  write variables to code cave, write code cave into target process and execute it via CreateRemoteThread
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
    injectCodeUsingThreadInjection(hProcess, &address, times, "injected\n");

    return 0;
}
