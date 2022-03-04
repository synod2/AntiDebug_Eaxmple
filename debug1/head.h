#pragma once
#pragma warning(disable:4996)

#include<windows.h>
#include<stdio.h>
typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
	BYTE       Reserved1[8];
	PVOID      Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
	BOOL KernelDebuggerEnabled;
	BOOL KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef VOID(NTAPI* PPS_POST_PROCESS_INIT_ROUTINE) (
	VOID
	);

typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	BYTE                          Reserved4[104];
	PVOID                         Reserved5[52];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE                          Reserved6[128];
	PVOID                         Reserved7[1];
	ULONG                         SessionId;
} PEB, * PPEB;

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation = 0,
	ProcessDebugPort = 7,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessBreakOnTermination = 29,
	ProcessDebugObjectHandle = 30,
	ProcessDebugFlags = 31
} PROCESSINFOCLASS;

typedef struct _PROCESS_BASIC_INFORMATION {
	LONG ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	LONG BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(
	_In_       HANDLE ProcessHandle,
	_In_       PROCESSINFOCLASS ProcessInformationClass,
	_Out_      PVOID ProcessInformation,
	_In_       ULONG ProcessInformationLength,
	_Out_opt_  PULONG ReturnLength
	);

typedef NTSTATUS (WINAPI * pNtQuerySystemInformation)(
	_In_            DWORD					 SystemInformationClass,
	_Inout_			PVOID                    SystemInformation,
	_In_            ULONG                    SystemInformationLength,
	_Out_opt_		PULONG                   ReturnLength
	);

pNtQueryInformationProcess	NtQueryInformationProcess;
pNtQuerySystemInformation	NtQuerySystemInformation;