#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>

WCHAR* GetProcessParams(HANDLE hProcess);

int main()
{
	PROCESSENTRY32W PE32W = { 0 };
	PE32W.dwSize = sizeof(PROCESSENTRY32W);

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnap != INVALID_HANDLE_VALUE)
	{
		if (Process32FirstW(hSnap, &PE32W))
		{
			do
			{
				HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, PE32W.th32ProcessID);

				if (hProcess != INVALID_HANDLE_VALUE)
				{
					WCHAR * ProcessCommandLine = GetProcessParams(hProcess);

					if (ProcessCommandLine)
					{
						// Do something 
						printf("CommandArgs: %ls\n", ProcessCommandLine);

						free(ProcessCommandLine);
					}

					CloseHandle(hProcess);
				}

			} while (Process32NextW(hSnap, &PE32W));
		}

		CloseHandle(hSnap);
	}

	return 0;
}

DWORD GetProcessPebAddress(HANDLE hProcess)
{
	typedef NTSTATUS (WINAPI *fNtQueryInformationProcess)(
		_In_      HANDLE           ProcessHandle,
		_In_      PROCESSINFOCLASS ProcessInformationClass,
		_Out_     PVOID            ProcessInformation,
		_In_      ULONG            ProcessInformationLength,
		_Out_opt_ PULONG           ReturnLength
	);

	fNtQueryInformationProcess pNtQueryInformationProcess = (fNtQueryInformationProcess)((void*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));

	if (!pNtQueryInformationProcess)
		return NULL;

	PROCESS_BASIC_INFORMATION PBI = { 0 };
	DWORD dwReadLength = sizeof(PROCESS_BASIC_INFORMATION);

	if (NT_SUCCESS(pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &dwReadLength)))
		return (DWORD)PBI.PebBaseAddress;

	return NULL;
}	

WCHAR* GetProcessParams(HANDLE hProcess)
{
	DWORD PebAddress = GetProcessPebAddress(hProcess);

	if (!PebAddress)
		return NULL;

	void *lpProcessParameters;
	UNICODE_STRING CommandLineBuffer = { 0 };
	WCHAR *CommandLine = NULL;

	// Read ProcessParameters address (offset 0x10 from PEB-Base)
	if (ReadProcessMemory(hProcess, (LPCVOID)((DWORD)PebAddress + 0x10), &lpProcessParameters, 4, NULL))
	{
		// Read address of CommandLine buffer from PEB (offset 0x40 from ProcessParameters-Base)
		if (ReadProcessMemory(hProcess, (LPCVOID)((DWORD)lpProcessParameters + 0x40), &CommandLineBuffer, sizeof(UNICODE_STRING), NULL))
		{
			// Allocate space 
			CommandLine = (WCHAR*)malloc(CommandLineBuffer.Length);

			if (!CommandLine)
				return NULL;

			// Read buffer into our allocated buffer space
			if (ReadProcessMemory(hProcess, (LPCVOID)CommandLineBuffer.Buffer, CommandLine, CommandLineBuffer.Length, NULL))
			{
				// Read successfully
				// Return the pointer to our allocated space
				return CommandLine;
			}
		}
	}

	free(CommandLine);
	return NULL;
}