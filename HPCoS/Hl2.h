#pragma once

#include <iostream>
#include <windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <vector>
#include <map>

#include "Memory.h"

#define CHAR_BIT 8

struct HALF_LIFE_2 {
    HANDLE hProcess;
    DWORD dwThreadId;
    std::vector<ThreadInfo*> hThreads;

    DWORD clientDllModuleOffset;
    DWORD serverDllModuleOffset;

    int buffer;

    std::vector<DWORD> healthOffsets;
    std::vector<DWORD> ammoOffsets;

    HALF_LIFE_2(HANDLE hProcess, DWORD dwThreadId);
    void Run();
};
