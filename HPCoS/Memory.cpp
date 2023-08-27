#include "Memory.h"

BOOL healthStopThread = false;
BOOL ammoStopThread = false;

ThreadArgs::ThreadArgs() {};

ThreadArgs::ThreadArgs(HANDLE hProcess, LPVOID address, const int value) {
    this->hProcess = hProcess;
    this->address = address;
    this->value = value;
}

ThreadInfo::ThreadInfo(HANDLE hThread, DWORD threadId, BOOL* threadStopper, ThreadArgs threadArgs) {
    this->hThread = hThread;
    this->threadId = threadId;
    this->threadStopper = threadStopper;
    this->threadArgs = threadArgs;
}

struct CLIENT_ID
{
    PVOID UniqueProcess;
    PVOID UniqueThread;
} *PCLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS                ExitStatus;
    PVOID                   TebBaseAddress;
    CLIENT_ID               ClientId;
    KAFFINITY               AffinityMask;
    KPRIORITY               Priority;
    KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

enum THREADINFOCLASS
{
    ThreadBasicInformation,
};

void* GetThreadStackTopAddress_x86(HANDLE hProcess, HANDLE hThread) {
    LPCWSTR moduleName = L"ntdll.dll";

    bool loadedManually = false;
    HMODULE module = GetModuleHandle(moduleName);

    if (!module)
    {
        module = LoadLibrary(moduleName);
        loadedManually = true;
    }

    NTSTATUS(__stdcall * NtQueryInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
    NtQueryInformationThread = reinterpret_cast<decltype(NtQueryInformationThread)>(GetProcAddress(module, "NtQueryInformationThread"));

    if (NtQueryInformationThread)
    {
        NT_TIB tib = { 0 };
        THREAD_BASIC_INFORMATION tbi = { 0 };

        NTSTATUS status = NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);
        if (status >= 0)
        {
            ReadProcessMemory(hProcess, tbi.TebBaseAddress, &tib, sizeof(tbi), nullptr);

            if (loadedManually)
            {
                FreeLibrary(module);
            }
            return tib.StackBase;
        }
    }


    if (loadedManually)
    {
        FreeLibrary(module);
    }

    return nullptr;
}

std::vector<DWORD> threadList(DWORD pid) {
    std::vector<DWORD> vect = std::vector<DWORD>();
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (h == INVALID_HANDLE_VALUE)
        return vect;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(h, &te)) {
        do {
            if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
                sizeof(te.th32OwnerProcessID)) {


                if (te.th32OwnerProcessID == pid) {
                    vect.push_back(te.th32ThreadID);
                }
            }
            te.dwSize = sizeof(te);
        } while (Thread32Next(h, &te));
    }

    return vect;
}

DWORD GetThreadStartAddress(HANDLE processHandle, HANDLE hThread) {
    DWORD used = 0, ret = 0;
    DWORD stacktop = 0, result = 0;

    MODULEINFO mi;

    GetModuleInformation(processHandle, GetModuleHandle(L"kernel32.dll"), &mi, sizeof(mi));
    stacktop = (DWORD)GetThreadStackTopAddress_x86(processHandle, hThread);

    CloseHandle(hThread);

    if (stacktop) {
        DWORD* buf32 = new DWORD[4096];

        if (ReadProcessMemory(processHandle, (LPCVOID)(stacktop - 4096), buf32, 4096, NULL)) {
            for (int i = 4096 / 4 - 1; i >= 0; --i) {
                if (buf32[i] >= (DWORD)mi.lpBaseOfDll && buf32[i] <= (DWORD)mi.lpBaseOfDll + mi.SizeOfImage) {
                    result = stacktop - 4096 + i * 4;
                    break;
                }
            }
        }

        delete buf32;
    }

    return result;
}

HANDLE GetProcessHandleByName(const std::wstring& processName) {
    HANDLE processHandle = NULL;
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot != INVALID_HANDLE_VALUE) {
        if (Process32First(snapshot, &processEntry)) {
            do {
                if (_wcsicmp(processEntry.szExeFile, processName.c_str()) == 0) {
                    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processEntry.th32ProcessID);
                    break;
                }
            } while (Process32Next(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }

    return processHandle;
}

uintptr_t GetBaseAddress(const HANDLE& hProcess, const std::wstring& processName) {
    HMODULE hModules[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
        uintptr_t baseAddress = reinterpret_cast<uintptr_t>(hModules[0]);
        std::wcout << "[INFO] Base address of the " << processName << " executable: 0x" << baseAddress << std::endl;
        return baseAddress;
    }
    else {
        std::wcerr << "[ERROR] Could not get base address of " << processName << " process" << std::endl;
    }

    return NULL;
}

DWORD GetThreadStackAddress(DWORD dwProcID, HANDLE hProcess) {
    std::vector<DWORD> threadID = threadList(dwProcID);

    DWORD threadStackAddress = 0;

    int stackNum = 0;
    for (auto it = threadID.begin(); it != threadID.end(); ++it) {
        HANDLE threadHandle = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, *it);
        threadStackAddress = GetThreadStartAddress(hProcess, threadHandle);
        printf("[INFO] TID: 0x%04x = THREADSTACK%2d BASE ADDRESS: 0x%04x\n", *it, stackNum, threadStackAddress);
        stackNum++;
    }

    return threadStackAddress;
}

uintptr_t FindDMAAAddress(HANDLE hProcess, uintptr_t address, const std::vector<DWORD>& offsets, int* buffer) {
    uintptr_t addr = address;
    uintptr_t oldAddr = addr;
    std::cout << "[INFO] Start following pointer chain from 0x" << std::hex << address << std::endl;
    for (unsigned int i = 0; i < offsets.size() - 1; ++i)
    {
        addr += offsets[i];
        if (ReadProcessMemory(hProcess, (BYTE*)addr, &addr, sizeof(addr), 0)) {
            std::cout << "[INFO] 0x" << std::hex << oldAddr << "+0x" << offsets[i] << "->0x" << addr << std::endl;
            oldAddr = addr;
        }
        else {
            std::cerr << std::endl << "[ERROR] Could not read process memory: " << GetLastError() << std::endl;
            return NULL;
        }
    }

    addr += offsets[offsets.size() - 1];
    address = addr;
    std::cout << "[SUCCESS] Pointer chain followed to 0x" << std::hex << addr;
    if (ReadProcessMemory(hProcess, (BYTE*)addr, &addr, sizeof(addr), NULL)) {
        std::cout << " with value " << std::dec << addr << std::endl;
        *buffer = addr;
    }
    else {
        std::cerr << std::endl << "[ERROR] Could not read process memory: " << GetLastError() << std::endl;
        return NULL;
    }

    return address;
}

BOOL WriteToProcess(HANDLE hProcess, LPVOID address, const int value) {
    if (WriteProcessMemory(hProcess, address, &value, sizeof(value), NULL)) {
        std::cout << "[INFO] Wrote value " << std::dec << value << " to address 0x" << std::hex << address << std::endl;
        return true;
    }
    else {
        std::cerr << "[ERROR] Could not write to address 0x" << address << ": " << GetLastError() << std::endl;
        return false;
    }
}

DWORD WINAPI WriteToProcessSilent(LPVOID lpParam) {
    ThreadInfo* threadInfo = static_cast<ThreadInfo*>(lpParam);
    HANDLE hThread = threadInfo->hThread;
    DWORD threadId = threadInfo->threadId;
    ThreadArgs threadArgs = threadInfo->threadArgs;

    while (!(*threadInfo->threadStopper)) {
        if (!WriteProcessMemory(threadArgs.hProcess, threadArgs.address, &threadArgs.value, sizeof(threadArgs.value), NULL)) {
            std::cerr << "[ERROR] ThreadId: " << threadId << ": Could not write to address 0x" << threadArgs.address << ": " << GetLastError() << std::endl;
        }
        Sleep(100);
    }

    std::cout << "[INFO] Thread " << threadId << " finished" << std::endl;
    *threadInfo->threadStopper = !(*threadInfo->threadStopper);
    return 0;
}

// Define the GetModuleBaseAddress function
DWORD GetModuleBaseAddress(DWORD procId, const wchar_t* modName) {
    DWORD modBaseAddr = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32First(hSnap, &modEntry))
        {
            do
            {
                if (!_wcsicmp(modEntry.szModule, modName))
                {
                    modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnap, &modEntry));
        }
    }
    CloseHandle(hSnap);
    return modBaseAddr;
}
