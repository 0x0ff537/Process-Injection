# Classic + bananaphone

In this "classic remote process injection" method I use some functions from ntdll.dll to inject aes encrypted shellcode. All the syscalls numbers are being resolved dynamically and called directly using [bananaphone](https://github.com/C-Sto/BananaPhone), which is the golang implementation of [Hell's Gate](https://github.com/am0nsec/HellsGate), to avoid any hooked syscall stub.

In this case I'm targeting notepad.exe but you can replace it with your preferred target easily, the payload is a messagebox. Keep in mind that this message box won't pop up and you should look at the taskbar whithin the notepad icon.

## Encrypting shellcode
I provide a python script that will encrypt the shellcode using AES256 algorithm with a random key. Just run `python3 bin2aes.py <path to raw shellcode>`, then copy the output to the corresponding variables in the code.
