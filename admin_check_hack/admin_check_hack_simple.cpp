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

int main()
{
    // overwrite memory in process "admin_check.exe" at address 00007FF617721124h with 74 00
    // changes relative jmp so that the next instruction is the destination
    const wchar_t* process = L"admin_check.exe";
    int pId = getProcId(process);
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pId);

    if (process == INVALID_HANDLE_VALUE) {
        printf("Failed to open PID %d, error code %d", pId, GetLastError());
    }

    LPVOID address = (LPVOID)0x7FF617721124;
    DWORD old_prot = protectMemoryEx<WORD>(hProcess, address, PAGE_EXECUTE_READWRITE);
    WORD newJump = 0x0074;  // little endian -> 74 00 in memory / assembly

    writeMemory<WORD>(hProcess, address, newJump);
    protectMemoryEx<WORD>(hProcess, address, old_prot);

    return 0;
}
