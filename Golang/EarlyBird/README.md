# EarlyBird
This is an implementation of the EarlyBird injection technique. The implant will create a new process in suspended state by calling the undocumented API CreateProcessInternalW. Then a memory space for the shellcode will be allocated in the suspended process's memory. Next the shellcode is decrypted and written in such memory space. Calling NtQueueApcThread we will queue a thread pointing to the decrypted shellcode, then resuming the main thread will launch it.

All the syscalls numbers are being resolved dynamically and called directly using [bananaphone](https://github.com/C-Sto/BananaPhone), which is the golang implementation of [Hell's Gate](https://github.com/am0nsec/HellsGate), to avoid any hooked syscall stub. Except for CreateProcessInternalW

## Encrypting payload
The included bin2aes.py script will encrypt raw shellcode and displayed in a format you can include in the main.go script.
