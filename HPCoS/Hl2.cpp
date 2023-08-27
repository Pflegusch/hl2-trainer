#include "hl2.h"

// Define the constructor for HALF_LIFE_2
HALF_LIFE_2::HALF_LIFE_2(HANDLE hProcess, DWORD dwThreadId) {
    this->hProcess = hProcess;
    this->dwThreadId = dwThreadId;

    this->clientDllModuleOffset = GetModuleBaseAddress(dwThreadId, L"client.dll");
    this->serverDllModuleOffset = GetModuleBaseAddress(dwThreadId, L"server.dll");

    this->buffer = 0;

    this->healthOffsets = { 0x4B9DF8, 0x64, 0x54, 0x18, 0x1C, 0x44, 0x13C, 0xE0 };
    this->ammoOffsets = { 0x6380E4, 0x14, 0x50, 0x8, 0x20, 0x18, 0x34, 0x4AC };

    std::cout << "Half Life 2 Trainer enabled" << std::endl;
    std::cout << "F2 for infinite health" << std::endl;
    std::cout << "F3 for infinite ammo" << std::endl;
}

void HALF_LIFE_2::Run() {
    uintptr_t pointerChainStartAddress = NULL;
    BOOL healthEnabled = false;
    BOOL ammoEnabled = false;

    while (true) {
        BOOL currentHealthStatus = GetAsyncKeyState(VK_F2) & 0x8000;
        BOOL currentAmmoStatus = GetAsyncKeyState(VK_F3) & 0x8000;

        if (currentHealthStatus && !healthEnabled) {
            healthEnabled = !healthEnabled;
            pointerChainStartAddress = this->clientDllModuleOffset;
            std::cout << "[INFO] pointerChainStartAddress: 0x" << std::hex << pointerChainStartAddress << std::endl;
            uintptr_t address = FindDMAAAddress(hProcess, pointerChainStartAddress, this->healthOffsets, &buffer);
            
            const int health = 100;
            ThreadArgs threadArgs(this->hProcess, reinterpret_cast<LPVOID>(address), health);
            ThreadInfo threadInfo(NULL, NULL, &healthStopThread, threadArgs);
            LPVOID threadArgsPtr = &threadInfo;

            threadInfo.hThread = CreateThread(
                NULL,
                0,
                WriteToProcessSilent,
                threadArgsPtr,
                0,
                &threadInfo.threadId
            );
            
            std::cout << "[INFO] Infinite health enabled" << std::endl;
        } 
        else if (currentHealthStatus && healthEnabled) {
            healthEnabled = false;
            healthStopThread = true;
            std::cout << "[INFO] Infinite health disabled" << std::endl;
        }

        if (currentAmmoStatus && !ammoEnabled) {
            ammoEnabled = !ammoEnabled;
            pointerChainStartAddress = this->serverDllModuleOffset;
            std::cout << "[INFO] pointerChainStartAddress: 0x" << std::hex << pointerChainStartAddress << std::endl;
            uintptr_t address = FindDMAAAddress(hProcess, pointerChainStartAddress, this->ammoOffsets, &buffer);

            const int ammo = 100;
            ThreadArgs threadArgs(this->hProcess, reinterpret_cast<LPVOID>(address), ammo);
            ThreadInfo threadInfo(NULL, NULL, &ammoStopThread, threadArgs);
            LPVOID threadArgsPtr = &threadInfo;

            threadInfo.hThread = CreateThread(
                NULL,
                0,
                WriteToProcessSilent,
                threadArgsPtr,
                0,
                &threadInfo.threadId
            );

            std::cout << "[INFO] Infinite ammo enabled" << std::endl;
        }
        else if (currentAmmoStatus && ammoEnabled) {
            ammoEnabled = false;
            ammoStopThread = true;
            std::cout << "[INFO] Infinite ammo disabled" << std::endl;
        }

        Sleep(100);
    }
}
