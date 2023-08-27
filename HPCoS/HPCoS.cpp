#include "Hl2.h"
#include "Memory.h"

void HL2Trainer(HANDLE hProcess, DWORD dwThreadId) {
    HALF_LIFE_2* hl2 = new HALF_LIFE_2(hProcess, dwThreadId);

    hl2->Run();
}

int main(int argc, char** argv) {
    std::wstring processName = L"hl2.exe";
    HANDLE hProcess = GetProcessHandleByName(processName);

    if (hProcess == nullptr) {
        std::wcerr << "[ERROR] Could not get handle to " << processName << std::endl;
        Sleep(50);
        main(argc, argv);
        std::cout << std::endl << std::endl; 
    }

    DWORD dwThreadId = GetProcessId(hProcess);

    HL2Trainer(hProcess, dwThreadId);

    CloseHandle(hProcess);

    int ret = getchar();
    return 0;
}
