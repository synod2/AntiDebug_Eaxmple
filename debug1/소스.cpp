#include "head.h"

int main() {
	char tmp;
	HMODULE hModule = NULL;
	
	BOOL isDebug = 0;

	DWORD RLength;
	HANDLE hProcess = GetCurrentProcess();
	
	PPROCESS_BASIC_INFORMATION processBasicInformation;
	PROCESSINFOCLASS procinfoclass;
	PVOID res=0;
	
	if (IsDebuggerPresent()) {
		isDebug = 1;
	}
	
	hModule = GetModuleHandle(TEXT("ntdll"));

	if (hModule == NULL) {
		printf("load NtDLL Error\n");
		return 0;
	}

	NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");
	NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(hModule, "NtQuerySystemInformation");

	if (NtQueryInformationProcess == NULL) {
		printf("Get NtQueryInformationProcess Address Error \n");
		return 0;
	}

	if (NtQuerySystemInformation == NULL) {
		printf("Get NtQuerySystemInformation  Address Error \n");
		return 0;
	}

	processBasicInformation = (PPROCESS_BASIC_INFORMATION)malloc(sizeof(PROCESS_BASIC_INFORMATION));
	
	NTSTATUS tmpRes = NtQueryInformationProcess(hProcess, ProcessDebugPort, &res, 8,&RLength); // ProcessDebugPort = 0x7
	//if while debugging, ProcessInformation will set to -1
	if ( ((int)res == -1) && !tmpRes )
	{
		//isDebug = 1;
	}
	res = 0;
	tmpRes = NtQueryInformationProcess(hProcess, ProcessDebugObjectHandle, &res, 8, &RLength); // ProcessDebugObjectHandle  = 0x1E	
	//if while debugging, ProcessInformation has debug port
	//and NTSTAUTS return is not 0xC0000353(STATUS_PORT_NOT_SET)
	if ( tmpRes != 0xC0000353 && res)
	{
		isDebug = 1;
	}
	res = (PVOID)1;
	tmpRes = NtQueryInformationProcess(hProcess, ProcessDebugFlags, &res, 4, &RLength); // ProcessDebugFlags   = 0x1F, ProcessInformation size should be 4 bytes
	// if while debugging, ProcessInformation will set to 0
	if (res == 0)
	{
		isDebug = 1;
	}
	BOOL isdbg;
	CheckRemoteDebuggerPresent(hProcess,(PBOOL)&isdbg); 
	//if while debugging, isdbg will set to 1
	if (isdbg) {
		isDebug = 1;
	}
	/*PVOID resKdbg = malloc(sizeof(SYSTEM_KERNEL_DEBUGGER_INFORMATION));*/
	PVOID resKdbg = 0;

	NtQuerySystemInformation(0x23, &resKdbg, sizeof(resKdbg),(PULONG)8);
	printf("%x\n", resKdbg);


	
	if (isDebug) {
		printf("is Debugged\n");
	}
	else {
		printf("not debugged\n");
	}
	scanf("%c",&tmp);
	return 0;
}