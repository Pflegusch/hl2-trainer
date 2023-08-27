#pragma once

#include <iostream>
#include <string>
#include <windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <vector>

typedef LONG NTSTATUS;
typedef DWORD KPRIORITY;
typedef WORD UWORD;

// Global flags for the threads
extern BOOL healthStopThread;
extern BOOL ammoStopThread;

struct ThreadArgs {
    HANDLE hProcess;
    LPVOID address;
    int value;

    ThreadArgs();
    ThreadArgs(HANDLE hProcess, LPVOID address, const int value);
};

struct ThreadInfo {
    HANDLE hThread;
    DWORD threadId;
    BOOL* threadStopper;
    ThreadArgs threadArgs;

    ThreadInfo(HANDLE hThread, DWORD threadId, BOOL* threadStopper, ThreadArgs threadArgs);
};

void* GetThreadStackTopAddress_x86(HANDLE hProcess, HANDLE hThread);
std::vector<DWORD> threadList(DWORD pid);
DWORD GetThreadStartAddress(HANDLE processHandle, HANDLE hThread);
HANDLE GetProcessHandleByName(const std::wstring& processName);
uintptr_t GetBaseAddress(const HANDLE& hProcess, const std::wstring& processName);
DWORD GetThreadStackAddress(DWORD dwProcID, HANDLE hProcess);
uintptr_t FindDMAAAddress(HANDLE hProcess, uintptr_t address, const std::vector<DWORD>& offsets, int* buffer);
BOOL WriteToProcess(HANDLE hProcess, LPVOID address, const int value);
DWORD WINAPI WriteToProcessSilent(LPVOID lpParam);
DWORD GetModuleBaseAddress(DWORD procId, const wchar_t* modName);
