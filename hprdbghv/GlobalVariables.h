/**
 * @file GlobalVariables.h
 * @author Sina Karvandi (sina@rayanfam.com)
 * @brief Here we put global variables that are used more or less in all part of our hypervisor (not all of them)
 * @details Note : All the global variables are not here, just those that
 * will be used in all project. Special use global variables are located 
 * in their corresponding headers
 * 
 * @version 0.1
 * @date 2020-04-11
 * 
 * @copyright This project is released under the GNU Public License v3.
 * 
 */
#pragma once

 //////////////////////////////////////////////////
 //				      PEB 32    		          //
 //////////////////////////////////////////////////
//专为WoW64准备;
typedef struct _LDR_DATA_TABLE_ENTRY32 {
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;


//专为WoW64准备;
typedef struct _PEB_LDR_DATA32 {
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	ULONG EntryInProgress;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

typedef struct _PEB32 {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	UINT32 Reserved3[2];
	UINT32 Ldr;

} PEB32, *PPEB32;
 //////////////////////////////////////////////////
 //				      PEB 64     		          //
 //////////////////////////////////////////////////
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;    //双向链表
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		struct {
			ULONG TimeDateStamp;
		};
		struct {
			PVOID LoadedImports;
		};
	};
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


typedef struct _PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;

} PEB, *PPEB;

NTKERNELAPI
PPEB
PsGetProcessPeb(
	PEPROCESS Process
);

NTKERNELAPI
PVOID
PsGetProcessWow64Process(
	PEPROCESS Process
);

//////////////////////////////////////////////////
//				Global Variables				//
//////////////////////////////////////////////////

/**
 * @brief VT-X Open / Close
 * 
 *
 */
BOOLEAN g_VTEnabled;


/**
 * @brief Save the state and variables related to each to logical core
 * 
 */
VIRTUAL_MACHINE_STATE * g_GuestState;

/**
 * @brief Save the state and variables related to EPT
 * 
 */
EPT_STATE * g_EptState;

/**
 * @brief Save the state of the thread that waits for messages to deliver to user-mode
 * 
 */
NOTIFY_RECORD * g_GlobalNotifyRecord;

/**
 * @brief Support for execute-only pages (indicating that data accesses are
 *  not allowed while instruction fetches are allowed)
 * 
 */
BOOLEAN g_ExecuteOnlySupport;

/**
 * @brief Determines whether the clients are allowed to send IOCTL to the drive or not
 * 
 */
BOOLEAN g_AllowIOCTLFromUsermode;

/**
 * @brief List header of hidden hooks detour
 *
 */
LIST_ENTRY g_EptHook2sDetourListHead;


/**
 * @brief Determines whether the one application gets the handle or not
 * this is used to ensure that only one application can get the handle
 * 
 */
BOOLEAN g_HandleInUse;

/**
 * @brief Shows whether the debugger transparent mode 
 * is enabled (true) or not (false)
 * 
 */
BOOLEAN g_TransparentMode;

/**
 * @brief holds the measurements from the user-mode and kernel-mode
 * 
 */
//TRANSPARENCY_MEASUREMENTS * g_TransparentModeMeasurements;

/**
 * @brief details relating to nop-sled page
 * 
 */
//DEBUGGER_STEPPINGS_NOP_SLED  g_SteppingsNopSledState;

