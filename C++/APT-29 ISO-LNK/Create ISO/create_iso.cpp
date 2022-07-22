#include <Windows.h>
#include <Stdio.h>
#include <Tchar.h>
#include <atlbase.h>
#include <imapi2fs.h>

VOID SaveIso(LPWSTR pSrcDir, LPWSTR pIsoPath)
{
	HRESULT hr;
	IFileSystemImage *pSystemImage;
	IFsiDirectoryItem *pRootDirItem;
	IFileSystemImageResult *pSystemImageResult;
	IStream *pImageStream;
	IStream *pFileStream;

	hr = CoCreateInstance(__uuidof(MsftFileSystemImage),
		NULL,
		CLSCTX_INPROC_SERVER,
		__uuidof(IFileSystemImage),
		(LPVOID*)&pSystemImage);
	if(SUCCEEDED(hr))
	{
		//Get the root entry
		pSystemImage->get_Root(&pRootDirItem);

		/*
		IFsiDirectoryItem::AddTree adds the contents of a directory tree to the file system image
		HRESULT AddTree(
		[in] BSTR sourceDirectory,
		[in] VARIANT_BOOL includeBaseDirectory
		);

		IFsiDirectoryItem::AddFile Add a file to the file system image
		HRESULT AddFile(
		[in] BSTR path,
		[in] IStream *fileData
		);

		IFsiDirectoryItem::AddDirectory adds a directory to the file system image
		HRESULT AddDirectory(
		[in] BSTR path
		);

		IFsiDirectoryItem::Add adds a file or directory described by an IFsiItem object to the file system image
		You can call IFileSystemImage::CreateDirectoryItem or IFileSystemImage::CreateFileItem method to get the IFsiItem object
		HRESULT Add(
		[in] IFsiItem *item
		);
		*/

		//Add a directory tree to the mirror
		pRootDirItem->AddTree(CComBSTR(pSrcDir), VARIANT_TRUE);

		//Create a result object containing file system and file data
		hr = pSystemImage->CreateResultImage(&pSystemImageResult);
		if(SUCCEEDED(hr))
		{
			//Get the mirror stream
			pSystemImageResult->get_ImageStream(&pImageStream);
			if(SUCCEEDED(hr))
			{
				STATSTG statstg;
				ULARGE_INTEGER ullRead;
				ULARGE_INTEGER ullWritten;

				//Create iso file
				HRESULT res = SHCreateStreamOnFileEx(pIsoPath,
					STGM_READWRITE,
					FILE_ATTRIBUTE_NORMAL,
					TRUE,
					NULL,
					&pFileStream);
				if(res != S_OK){
					printf("\n[-] Failed to create ISO.\n");
					return;
				}
				printf("\n[+] %ls file created successfully\n", pIsoPath);

				pImageStream->Stat(&statstg, STATFLAG_DEFAULT);
				pImageStream->CopyTo(pFileStream, statstg.cbSize, &ullRead, &ullWritten);

				pFileStream->Release();
				pImageStream->Release();
			}

			pSystemImageResult->Release();
		}

		pSystemImage->Release();
	}

}

int main(int argc, TCHAR *argv[])
{   
	// Checking the number ofarguments
	if(argc != 3){
		printf("\n[-] Usage: %s <dir or file path> <iso output path>\n", argv[0]);
		return 1;
	}

	// Check if path exists 
	struct stat buffer;
	if (stat((char *)argv[1], &buffer) != 0) {
    	printf("\n[-] %s doesn't exist\n", argv[1]);
		return 1;
    }

	// Convert command line arguments to wide strings (unicode)
	LPWSTR arguments = GetCommandLineW();
	if(arguments == NULL){
		printf("\n[-] GetCommandLineW failed\n");
		return 1;
	}
	
	int wArgc;
	LPWSTR * wArgv = CommandLineToArgvW(arguments, &wArgc);
	if(wArgv == NULL){
		printf("[-] CommandLineToArgvW failed, error code\n");
		return 1;
	}

	LPWSTR pSrc = wArgv[1];
    LPWSTR pIsoPath = wArgv[2];

	CoInitialize(0);
	SaveIso(pSrc, pIsoPath);
	CoUninitialize();

	return 0;
}