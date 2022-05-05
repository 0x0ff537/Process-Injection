## Replecating behaviour of Lazaru's loader

This is a PoC of the techniques used by one of the Lazarus group loaders to avoid calling common Win32 APIs like VirtualAlloc, MoveMemory and CreateThread to allocate space, copy shellcode and execute it. I also added some other tricks like avoid importing any suspicious fuction by resolving them dynamically with a self implementation of GetProcAddress and GetModuleHandle functions and include strings as char arrays to avoid finding suspicious strings in the final executable. All of these last techniques learned from [Sektor7's](https://twitter.com/SEKTOR7net) amazing [Intermediate Malware Development](https://institute.sektor7.net/rto-maldev-intermediate) course. 

To allocate space in memory it uses [HeapCreate](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapcreate) and [HeapAlloc](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc). There's a downside here, according to Microsoft's documentation _the largest memory block that can be allocated from the heap is slightly less than 512 KB for a 32-bit process and slightly less than 1,024 KB for a 64-bit process._ You can read more about it [here](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapcreate). So if you need more space use VirtualAlloc or your prefered method.

Then using the function [UuidFromStringA](https://docs.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-uuidfromstring) the Uuids list included in the binary is converted back to bytes and copied to the buffer created by HeapAlloc. Then the payload is decrypted to the original msfvenom shellcode.

To execute the shellcode a pointer to it is passed as a callback funtion to [EnumSystemLocalesA](https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumsystemlocalesa).
### Converting shellcode to Uuids
I created the shellcode with the following command:
`msfvenom -p windows/exec CMD=calc.exe -f raw -o calc.bin`
then converted to an Uuids list with the bin2AESUuids.py script provided. To use it just run:
```bash
python3 bin2AESUuids.py calc.bin      # This script works with python 3 only, you might also need to install some libraries.
```
The resulting list should be included in the code along with the decryption key, this is a nice trick to hide the payload.

If you want to read more about the Lazarus loader check it here: https://research.nccgroup.com/2021/01/23/rift-analysing-a-lazarus-shellcode-execution-method/.

Some other useful links:
- http://ropgadget.com/posts/abusing_win_functions.html
- https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180244/Lazarus_Under_The_Hood_PDF_final.pdf
