#include <Windows.h>
#include <iostream>

BOOL IsElevated() {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            fRet = Elevation.TokenIsElevated;
        }
    }
    if (hToken) {
        CloseHandle(hToken);
    }
    return fRet;
}

void IsAdmin() {
    std::cout << "[+] Passed the Admin check\n";
}

void IsNotAdmin() {
    std::cout << "[-] Failed the Admin check\n";
}

DWORD __cdecl hiddenFunction(int times, const char* string) {
    for (int i = 0; i < times; i++) {
        std::cout << string;
    }
    return (DWORD)0;
}

int main()
{
    BOOL isAdmin = FALSE;
    std::cout << "[?] Continuously checking if you are an Admin\n";

    while (true) {
        isAdmin = IsElevated();
        if (isAdmin) {
            IsAdmin();
            hiddenFunction(1, "hiddenFunction from IsAdmin\n");
            break;
        }
        else {
            IsNotAdmin();
        }
        Sleep(5000);
    }
    system("pause");  // needs #include <iostream> (already in console app template), Windows only
    return 0;
}
