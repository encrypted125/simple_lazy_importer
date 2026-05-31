#include <iostream>
#include <Windows.h>
#include "include/simple_lazy.hpp"

DWORD WINAPI DummyThreadFunction(LPVOID lpParam) {
    std::cout << "[+] Hello from Thread created by Lazy!" << std::endl;
    return 0;
}

int main()
{
    void* buffer = SIMPLE_LAZY(VirtualAlloc)(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (buffer) {
        std::cout << "[+] Success alloc at addr : " << buffer << std::endl;

        HANDLE hThread = SIMPLE_LAZY(CreateThread)(nullptr, 0, DummyThreadFunction, nullptr, 0, nullptr);

        if (hThread) {
            std::cout << "[+] Thread created successfully! Handle: " << hThread << std::endl;

            SIMPLE_LAZY(WaitForSingleObject)(hThread, INFINITE);

            SIMPLE_LAZY(CloseHandle)(hThread);
        }
        else {
            std::cout << "[-] Failed to create Thread!" << std::endl;
        }

        SIMPLE_LAZY(VirtualFree)(buffer, 0, MEM_RELEASE);
    }
    else {
        std::cout << "[-] error in operation" << std::endl;
    }

    std::cout << "[+] Operation successful!" << std::endl;
    while (true) {
        SIMPLE_LAZY(Sleep)(1000);
    }
}
