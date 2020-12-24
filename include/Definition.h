/**
 * @file Definition.h
 * @author Sina Karvandi (sina@rayanfam.com)
 * @brief Header files for global definitions
 * @details This file contains definitions that are use in both user mode and
 * kernel mode Means that if you change the following files, structures or
 * enums, then these settings apply to both usermode and kernel mode
 * @version 0.1
 * @date 2020-04-10
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#pragma once

//////////////////////////////////////////////////
//				Message Tracing                 //
//////////////////////////////////////////////////

/**
 * @brief Default buffer count of packets for message tracing
 * @details number of packets storage
 */
#define MaximumPacketsCapacity 1000

/**
 * @brief Size of each packet
 * @details NOTE : REMEMBER TO CHANGE IT IN USER-MODE APP TOO
 */
#define PacketChunkSize 1000

/**
 * @brief size of usermode buffer
 * @details Because of Opeation code at the start of the
 * buffer + 1 for null-termminating
 *
 */
#define UsermodeBufferSize sizeof(UINT32) + PacketChunkSize + 1

/**
 * @brief Final storage size of message tracing
 *
 */
#define LogBufferSize                                                          \
  MaximumPacketsCapacity *(PacketChunkSize + sizeof(BUFFER_HEADER))

/**
 * @brief limitation of Windows DbgPrint message size
 * @details currently is not functional
 *
 */
#define DbgPrintLimitation 512

/**
 * @brief The seeds that user-mode codes use as the starter
 * of their events' tag
 *
 */
#define DebuggerEventTagStartSeed 0x1000000

//////////////////////////////////////////////////
//               Remote Connection              //
//////////////////////////////////////////////////

/**
 * @brief default port of HyperDbg for listening by
 * debuggee (server, guest)
 *
 */
#define DEFAULT_PORT "50000"

/**
 * @brief Packet size for TCP connections
 * @details Note that we might add something to the kernel buffers
 * that's why we add 0x100 to it
 */
#define COMMUNICATION_BUFFER_SIZE PacketChunkSize + 0x100

//////////////////////////////////////////////////
//                   Installer                  //
//////////////////////////////////////////////////

/**
 * @brief maximum results that will be returned by !s* s*
 * command
 *
 */
#define MaximumSearchResults 0x1000

//////////////////////////////////////////////////
//                 Installer                    //
//////////////////////////////////////////////////

/**
 * @brief name of HyperDbg driver
 *
 */
#define DRIVER_NAME "hprdbghv"

//////////////////////////////////////////////////
//             Operation Codes                  //
//////////////////////////////////////////////////

/**
 * @brief Message logs id that comes from kernel-mode to
 * user-mode
 * @details Message area >= 0x4
 */
#define OPERATION_LOG_INFO_MESSAGE 0x1
#define OPERATION_LOG_WARNING_MESSAGE 0x2
#define OPERATION_LOG_ERROR_MESSAGE 0x3
#define OPERATION_LOG_NON_IMMEDIATE_MESSAGE 0x4
#define OPERATION_LOG_WITH_TAG 0x5

//////////////////////////////////////////////////
//				   Test Cases                   //
//////////////////////////////////////////////////

/**
 * @brief Test case number, perform all the tests
 */
#define DEBUGGER_TEST_ALL_COMMANDS 0x0

/**
 * @brief Test case number, test attaching and detaching to processes
 */
#define DEBUGGER_TEST_USER_MODE_INFINITE_LOOP_THREAD 0x1

//////////////////////////////////////////////////
//            Callback Definitions              //
//////////////////////////////////////////////////

/**
 * @brief Callback type that can be used to be used
 * as a custom ShowMessages function
 *
 */
typedef int (*Callback)(const char *Text);

//////////////////////////////////////////////////
//               Event Details                  //
//////////////////////////////////////////////////

/**
 * @brief enum to show type of all HyperDbg events
 *
 */
typedef enum _DEBUGGER_EVENT_TYPE_ENUM {

  HIDDEN_HOOK_READ_AND_WRITE,
  HIDDEN_HOOK_READ,
  HIDDEN_HOOK_WRITE,

  HIDDEN_HOOK_EXEC_DETOURS,
  HIDDEN_HOOK_EXEC_CC,

  SYSCALL_HOOK_EFER_SYSCALL,
  SYSCALL_HOOK_EFER_SYSRET,

  CPUID_INSTRUCTION_EXECUTION,

  RDMSR_INSTRUCTION_EXECUTION,
  WRMSR_INSTRUCTION_EXECUTION,

  IN_INSTRUCTION_EXECUTION,
  OUT_INSTRUCTION_EXECUTION,

  EXCEPTION_OCCURRED,
  EXTERNAL_INTERRUPT_OCCURRED,

  DEBUG_REGISTERS_ACCESSED,

  TSC_INSTRUCTION_EXECUTION,
  PMC_INSTRUCTION_EXECUTION,

  VMCALL_INSTRUCTION_EXECUTION,
  
  // add New
  HIDDEN_HOOK_EXEC_EDTMEM,

} DEBUGGER_EVENT_TYPE_ENUM;

/**
 * @brief Type of Actions
 *
 */
typedef enum _DEBUGGER_EVENT_ACTION_TYPE_ENUM {
  BREAK_TO_DEBUGGER,
  LOG_THE_STATES,
  RUN_CUSTOM_CODE

} DEBUGGER_EVENT_ACTION_TYPE_ENUM;

/**
 * @brief Each command is like the following struct, it also used for
 * tracing works in user mode and sending it to the kernl mode
 * @details THIS IS NOT WHAT HYPERDBG SAVES FOR EVENTS IN KERNEL MODE
 */
typedef struct _DEBUGGER_GENERAL_EVENT_DETAIL {

  LIST_ENTRY
  CommandsEventList; // Linked-list of commands list (used for tracing purpose
                     // in user mode)

  time_t CreationTime; // Date of creating this event

  UINT32 CoreId; // determines the core index to apply this event to, if it's
                 // 0xffffffff means that we have to apply it to all cores

  UINT32 ProcessId; // determines the process id to apply this to
                    // only that 0xffffffff means that we have to
                    // apply it to all processes

  BOOLEAN IsEnabled;

  UINT32 CountOfActions;

  UINT64 Tag; // is same as operation code
  DEBUGGER_EVENT_TYPE_ENUM EventType;

  UINT64 OptionalParam1;
  UINT64 OptionalParam2;
  UINT64 OptionalParam3;
  UINT64 OptionalParam4;

  PVOID CommandStringBuffer;

  UINT32 ConditionBufferSize;

} DEBUGGER_GENERAL_EVENT_DETAIL, *PDEBUGGER_GENERAL_EVENT_DETAIL;

/**
 * @brief Each event can have mulitple actions
 * @details THIS STRUCTURE IS ONLY USED IN USER MODE
 * WE USE SEPARATE STRUCTURE FOR ACTIONS IN
 * KERNEL MODE
 */
typedef struct _DEBUGGER_GENERAL_ACTION {
  UINT64 EventTag;
  DEBUGGER_EVENT_ACTION_TYPE_ENUM ActionType;
  UINT32 PreAllocatedBuffer;

  UINT32 CustomCodeBufferSize;

} DEBUGGER_GENERAL_ACTION, *PDEBUGGER_GENERAL_ACTION;

/**
 * @brief Status of register buffers
 *
 */
typedef struct _DEBUGGER_EVENT_AND_ACTION_REG_BUFFER {

  BOOLEAN IsSuccessful;
  UINT32 Error; // If IsSuccessful was, FALSE

} DEBUGGER_EVENT_AND_ACTION_REG_BUFFER, *PDEBUGGER_EVENT_AND_ACTION_REG_BUFFER;

//////////////////////////////////////////////////
//                  Debugger                    //
//////////////////////////////////////////////////

/* ==============================================================================================
 */

#define SIZEOF_REGISTER_EVENT sizeof(REGISTER_NOTIFY_BUFFER)

typedef enum _NOTIFY_TYPE { IRP_BASED, EVENT_BASED } NOTIFY_TYPE;

typedef struct _REGISTER_NOTIFY_BUFFER {
  NOTIFY_TYPE Type;
  HANDLE hEvent;

} REGISTER_NOTIFY_BUFFER, *PREGISTER_NOTIFY_BUFFER;

/* ==============================================================================================
 */
#define SIZEOF_DEBUGGER_MODIFY_EVENTS sizeof(DEBUGGER_MODIFY_EVENTS)

/* Constants */
#define DEBUGGER_MODIFY_EVENTS_APPLY_TO_ALL_TAG 0xffffffffffffffff

/**
 * @brief different types of modifing events request (enable/disable/clear)
 *
 */
typedef enum _DEBUGGER_MODIFY_EVENTS_TYPE {
  DEBUGGER_MODIFY_EVENTS_ENABLE,
  DEBUGGER_MODIFY_EVENTS_DISABLE,
  DEBUGGER_MODIFY_EVENTS_CLEAR
} DEBUGGER_MODIFY_EVENTS_TYPE;

/**
 * @brief request for modifying events (enable/disable/clear)
 *
 */
typedef struct _DEBUGGER_MODIFY_EVENTS {

  UINT64 Tag;          // Tag of the target event that we want to modify
  UINT64 KernelStatus; // Kerenl put the status in this field
  DEBUGGER_MODIFY_EVENTS_TYPE
  TypeOfAction; // Determines what's the action (enable | disable | clear)

} DEBUGGER_MODIFY_EVENTS, *PDEBUGGER_MODIFY_EVENTS;

/*
==============================================================================================
 */

#define SIZEOF_DEBUGGER_READ_PAGE_TABLE_ENTRIES_DETAILS                        \
  sizeof(DEBUGGER_READ_PAGE_TABLE_ENTRIES_DETAILS)

/**
 * @brief request for !pte command
 *
 */
typedef struct _DEBUGGER_READ_PAGE_TABLE_ENTRIES_DETAILS {

  UINT64 VirtualAddress;

  UINT64 Pml4eVirtualAddress;
  UINT64 Pml4eValue;

  UINT64 PdpteVirtualAddress;
  UINT64 PdpteValue;

  UINT64 PdeVirtualAddress;
  UINT64 PdeValue;

  UINT64 PteVirtualAddress;
  UINT64 PteValue;

} DEBUGGER_READ_PAGE_TABLE_ENTRIES_DETAILS,
    *PDEBUGGER_READ_PAGE_TABLE_ENTRIES_DETAILS;

typedef struct _DEBUGGER_READ_PROCESS_CR3_DETAILS {
	UINT32 PROCESS;
	UINT64 Cr3;
}DEBUGGER_READ_PROCESS_CR3_DETAILS,*PDEBUGGER_READ_PROCESS_CR3_DETAILS;
/* ==============================================================================================
 */

#define SIZEOF_DEBUGGER_VA2PA_AND_PA2VA_COMMANDS                               \
  sizeof(DEBUGGER_VA2PA_AND_PA2VA_COMMANDS)


#define SIZEOF_DEBUGGER_READ_PROCESS_CR3_DETAILS                               \
  sizeof(DEBUGGER_READ_PROCESS_CR3_DETAILS)
/**
 * @brief requests for !va2pa and !pa2va commands
 *
 */
typedef struct _DEBUGGER_VA2PA_AND_PA2VA_COMMANDS {

  UINT64 VirtualAddress;
  UINT64 PhysicalAddress;
  UINT32 ProcessId;
  BOOLEAN IsVirtual2Physical;

} DEBUGGER_VA2PA_AND_PA2VA_COMMANDS, *PDEBUGGER_VA2PA_AND_PA2VA_COMMANDS;

/* ==============================================================================================
 */

#define SIZEOF_DEBUGGER_READ_MEMORY sizeof(DEBUGGER_READ_MEMORY)

/**
 * @brief different types of reading memory
 *
 */
typedef enum _DEBUGGER_READ_READING_TYPE {
  READ_FROM_KERNEL,
  READ_FROM_VMX_ROOT
} DEBUGGER_READ_READING_TYPE;

/**
 * @brief different type of addresses
 *
 */
typedef enum _DEBUGGER_READ_MEMORY_TYPE {
  DEBUGGER_READ_PHYSICAL_ADDRESS,
  DEBUGGER_READ_VIRTUAL_ADDRESS
} DEBUGGER_READ_MEMORY_TYPE;

/**
 * @brief the way that debugger should show
 * the details of memory or disassemble them
 *
 */
typedef enum _DEBUGGER_SHOW_MEMORY_STYLE {
  DEBUGGER_SHOW_COMMAND_DISASSEMBLE64,
  DEBUGGER_SHOW_COMMAND_DISASSEMBLE32,
  DEBUGGER_SHOW_COMMAND_DB,
  DEBUGGER_SHOW_COMMAND_DC,
  DEBUGGER_SHOW_COMMAND_DQ,
  DEBUGGER_SHOW_COMMAND_DD
} DEBUGGER_SHOW_MEMORY_STYLE;

/**
 * @brief request for reading virtual and physical memory
 *
 */
typedef struct _DEBUGGER_READ_MEMORY {

  UINT32 Pid; // Read from cr3 of what process
  UINT64 Address;
  UINT32 Size;
  DEBUGGER_READ_MEMORY_TYPE MemoryType;
  DEBUGGER_READ_READING_TYPE ReadingType;

} DEBUGGER_READ_MEMORY, *PDEBUGGER_READ_MEMORY;

/* ==============================================================================================
 */

#define SIZEOF_DEBUGGER_STEPPINGS sizeof(DEBUGGER_STEPPINGS)

/**
 * @brief Actions to debugging thread's
 *
 */
typedef enum _DEBUGGER_STEPPINGS_ACTIONS_ENUM {
  STEPPINGS_ACTION_STEP_INTO,
  STEPPINGS_ACTION_STEP_OUT,
  STEPPINGS_ACTION_CONTINUE

} DEBUGGER_STEPPINGS_ACTIONS_ENUM;

/**
 * @brief request for step-in and step-out
 *
 */
typedef struct _DEBUGGER_STEPPINGS {

  UINT32 KernelStatus;
  UINT32 ProcessId;
  UINT32 ThreadId;
  DEBUGGER_STEPPINGS_ACTIONS_ENUM SteppingAction;

} DEBUGGER_STEPPINGS, *PDEBUGGER_STEPPINGS;

/* ==============================================================================================
 */

#define SIZEOF_DEBUGGER_FLUSH_LOGGING_BUFFERS                                  \
  sizeof(DEBUGGER_FLUSH_LOGGING_BUFFERS)

/**
 * @brief request for flushing buffers
 *
 */
typedef struct _DEBUGGER_FLUSH_LOGGING_BUFFERS {

  UINT32 KernelStatus;
  UINT32 CountOfMessagesThatSetAsReadFromVmxRoot;
  UINT32 CountOfMessagesThatSetAsReadFromVmxNonRoot;

} DEBUGGER_FLUSH_LOGGING_BUFFERS, *PDEBUGGER_FLUSH_LOGGING_BUFFERS;

/* ==============================================================================================
 */

#define SIZEOF_DEBUGGER_READ_AND_WRITE_ON_MSR                                  \
  sizeof(DEBUGGER_READ_AND_WRITE_ON_MSR)
#define DEBUGGER_READ_AND_WRITE_ON_MSR_APPLY_ALL_CORES 0xffffffff

/**
 * @brief different types of actions on MSRs
 *
 */
typedef enum _DEBUGGER_MSR_ACTION_TYPE {
  DEBUGGER_MSR_READ,
  DEBUGGER_MSR_WRITE
} DEBUGGER_MSR_ACTION_TYPE;

/**
 * @brief request to read or write on MSRs
 *
 */
typedef struct _DEBUGGER_READ_AND_WRITE_ON_MSR {

  UINT64 Msr; // It's actually a 32-Bit value but let's not mess with a register
  UINT32 CoreNumber; // specifies the core to execute wrmsr or read the msr
                     // (DEBUGGER_READ_AND_WRITE_ON_MSR_APPLY_ALL_CORES mean all
                     // the cores)
  DEBUGGER_MSR_ACTION_TYPE
  ActionType; // Detects whether user needs wrmsr or rdmsr
  UINT64 Value;

} DEBUGGER_READ_AND_WRITE_ON_MSR, *PDEBUGGER_READ_AND_WRITE_ON_MSR;

/* ==============================================================================================
 */

#define SIZEOF_DEBUGGER_EDIT_MEMORY sizeof(DEBUGGER_EDIT_MEMORY)

/**
 * @brief different type of addresses for editing memory
 *
 */
typedef enum _DEBUGGER_EDIT_MEMORY_TYPE {
  EDIT_PHYSICAL_MEMORY,
  EDIT_VIRTUAL_MEMORY
} DEBUGGER_EDIT_MEMORY_TYPE;

/**
 * @brief size of editing memory
 *
 */
typedef enum _DEBUGGER_EDIT_MEMORY_BYTE_SIZE {
  EDIT_BYTE,
  EDIT_DWORD,
  EDIT_QWORD
} DEBUGGER_EDIT_MEMORY_BYTE_SIZE;

/**
 * @brief request for edit virtual and physical memory
 *
 */
typedef struct _DEBUGGER_EDIT_MEMORY {

  UINT32 Result;                           // Result from kernel
  UINT64 Address;                          // Target adddress to modify
  UINT32 ProcessId;                        // specifies the process id
  DEBUGGER_EDIT_MEMORY_TYPE MemoryType;    // Type of memory
  DEBUGGER_EDIT_MEMORY_BYTE_SIZE ByteSize; // Modification size
  UINT32 CountOf64Chunks;
  UINT32 FinalStructureSize;

} DEBUGGER_EDIT_MEMORY, *PDEBUGGER_EDIT_MEMORY;

/* ==============================================================================================
 */

#define SIZEOF_DEBUGGER_SEARCH_MEMORY sizeof(DEBUGGER_SEARCH_MEMORY)

/**
 * @brief different types of address for searching on memory
 *
 */
typedef enum _DEBUGGER_SEARCH_MEMORY_TYPE {
  SEARCH_PHYSICAL_MEMORY,
  SEARCH_VIRTUAL_MEMORY
} DEBUGGER_SEARCH_MEMORY_TYPE;

/**
 * @brief different sizes on searching memory
 *
 */
typedef enum _DEBUGGER_SEARCH_MEMORY_BYTE_SIZE {
  SEARCH_BYTE,
  SEARCH_DWORD,
  SEARCH_QWORD
} DEBUGGER_SEARCH_MEMORY_BYTE_SIZE;

/**
 * @brief request for searching memory
 *
 */
typedef struct _DEBUGGER_SEARCH_MEMORY {

  UINT64 Address;                         // Target adddress to start searching
  UINT64 Length;                          // Length of bytes to search
  UINT32 ProcessId;                       // specifies the process id
  DEBUGGER_SEARCH_MEMORY_TYPE MemoryType; // Type of memory
  DEBUGGER_SEARCH_MEMORY_BYTE_SIZE ByteSize; // Modification size
  UINT32 CountOf64Chunks;
  UINT32 FinalStructureSize;

} DEBUGGER_SEARCH_MEMORY, *PDEBUGGER_SEARCH_MEMORY;

/* ==============================================================================================
 */

#define SIZEOF_DEBUGGER_HIDE_AND_TRANSPARENT_DEBUGGER_MODE                     \
  sizeof(DEBUGGER_HIDE_AND_TRANSPARENT_DEBUGGER_MODE)

/**
 * @brief request for enable or disable transparent-mode
 *
 */
typedef struct _DEBUGGER_HIDE_AND_TRANSPARENT_DEBUGGER_MODE {

  BOOLEAN IsHide;

  UINT64 CpuidAverage;
  UINT64 CpuidStandardDeviation;
  UINT64 CpuidMedian;

  UINT64 RdtscAverage;
  UINT64 RdtscStandardDeviation;
  UINT64 RdtscMedian;

  BOOLEAN TrueIfProcessIdAndFalseIfProcessName;
  UINT32 ProcId;
  UINT32 LengthOfProcessName; // in the case of !hide name xxx, this parameter
                              // shows the length of xxx

  UINT64 KernelStatus; /* DEBUGEER_OPERATION_WAS_SUCCESSFULL ,
                          DEBUGEER_ERROR_UNABLE_TO_HIDE_OR_UNHIDE_DEBUGGER
                          */

} DEBUGGER_HIDE_AND_TRANSPARENT_DEBUGGER_MODE,
    *PDEBUGGER_HIDE_AND_TRANSPARENT_DEBUGGER_MODE;

/* ==============================================================================================
 */
#define SIZEOF_DEBUGGER_ATTACH_DETACH_USER_MODE_PROCESS                        \
  sizeof(DEBUGGER_ATTACH_DETACH_USER_MODE_PROCESS)

/**
 * @brief request for attaching user-mode process
 *
 */
typedef struct _DEBUGGER_ATTACH_DETACH_USER_MODE_PROCESS {

  BOOLEAN IsAttach;
  UINT64 Result;
  UINT32 ProcessId;
  UINT64 ThreadId;

} DEBUGGER_ATTACH_DETACH_USER_MODE_PROCESS,
    *PDEBUGGER_ATTACH_DETACH_USER_MODE_PROCESS;

/* ==============================================================================================
 */

/**
 * @brief Apply the event to all the cores
 *
 */
#define DEBUGGER_EVENT_APPLY_TO_ALL_CORES 0xffffffff

/**
 * @brief Apply the event to all the processes
 *
 */
#define DEBUGGER_EVENT_APPLY_TO_ALL_PROCESSES 0xffffffff

/**
 * @brief Apply to all Model Specific Registers
 *
 */
#define DEBUGGER_EVENT_MSR_READ_OR_WRITE_ALL_MSRS 0xffffffff

/**
 * @brief Apply to all first 32 exceptions
 *
 */
#define DEBUGGER_EVENT_EXCEPTIONS_ALL_FIRST_32_ENTRIES 0xffffffff

/**
 * @brief Apply to all syscalls and sysrets
 *
 */
#define DEBUGGER_EVENT_SYSCALL_ALL_SYSRET_OR_SYSCALLS 0xffffffff

/**
 * @brief Apply to all I/O ports
 *
 */
#define DEBUGGER_EVENT_ALL_IO_PORTS 0xffffffff

//
// Pseudo Regs Mask (It's a mask not a value)
//

/**
 * @brief equals to @$proc in windbg that shows the current eprocess
 */
#define GUEST_PSEUDO_REG_PROC 0x1

/**
 * @brief equals to @$ra in windbg that shows the return address that is
 * currently on the stack
 */
#define GUEST_PSEUDO_REG_PROC 0x2

/**
 * @brief equals to @$ip in windbg that shows the instruction pointer register
 */
#define GUEST_PSEUDO_REG_PROC 0x4

/**
 * @brief equals to @$thread in windbg that shows the address of the current
 * thread's ethread
 */
#define GUEST_PSEUDO_REG_PROC 0x8

/**
 * @brief equals to @$thread in windbg that shows the address of the current
 * thread's ethread
 */
#define GUEST_PSEUDO_REG_PROC 0x10

/**
 * @brief equals to @$peb in windbg that shows the address of the process
 * environment block(PEB) of the current process
 */
#define GUEST_PSEUDO_REG_PROC 0x20

/**
 * @brief equals to @$teb in windbg that shows the address of the thread
 * environment block(TEB) of the current thread
 */
#define GUEST_PSEUDO_REG_PROC 0x40

/**
 * @brief equals to @$tpid in windbg that shows the process ID(PID) for the
 * process that owns the current thread
 */
#define GUEST_PSEUDO_REG_PROC 0x80

/**
 * @brief equals to @$tid in windbg that shows the thread ID for the current
 * thread
 */
#define GUEST_PSEUDO_REG_PROC 0x100

//
// GP Regs Mask (It's a mask not a value)
//
#define GUEST_GP_REG_RAX 0x1
#define GUEST_GP_REG_RCX 0x2
#define GUEST_GP_REG_RDX 0x4
#define GUEST_GP_REG_RBX 0x8
#define GUEST_GP_REG_RSP 0x10
#define GUEST_GP_REG_RBP 0x20
#define GUEST_GP_REG_RSI 0x40
#define GUEST_GP_REG_RDI 0x80
#define GUEST_GP_REG_R8 0x100
#define GUEST_GP_REG_R9 0x200
#define GUEST_GP_REG_R10 0x400
#define GUEST_GP_REG_R11 0x800
#define GUEST_GP_REG_R12 0x1000
#define GUEST_GP_REG_R13 0x2000
#define GUEST_GP_REG_R14 0x4000
#define GUEST_GP_REG_R15 0x8000
#define GUEST_GP_REG_RFLAGS 0x10000

/**
 * @brief different types of log the states
 *
 */
typedef enum _DEBUGGER_EVENT_ACTION_LOG_CONFIGURATION_TYPE {

  //
  // Read the results
  //
  GUEST_LOG_READ_GENERAL_PURPOSE_REGISTERS, // r rax
  GUEST_LOG_READ_STATIC_MEMORY_ADDRESS,     // dc fffff80126551180
  GUEST_LOG_READ_REGISTER_MEMORY_ADDRESS,   // dc poi(rax)

  GUEST_LOG_READ_POI_REGISTER_ADD_VALUE,      // dc poi(rax) + xx
  GUEST_LOG_READ_POI_REGISTER_SUBTRACT_VALUE, // dc poi(rax) - xx

  GUEST_LOG_READ_POI_REGISTER_PLUS_VALUE,  // dc poi(rax + xx)
  GUEST_LOG_READ_POI_REGISTER_MINUS_VALUE, // dc poi(rax- xx)

  GUEST_LOG_READ_PSEUDO_REGISTER, // r @$proc

  GUEST_LOG_READ_MEMORY_PSEUDO_REGISTER_ADD_VALUE,      // dc @$proc + xx
  GUEST_LOG_READ_MEMORY_PSEUDO_REGISTER_SUBTRACT_VALUE, // dc @$proc - xx

  GUEST_LOG_READ_MEMORY_PSEUDO_REGISTER_PLUS_VALUE,  // dc poi(@$proc - xx)
  GUEST_LOG_READ_MEMORY_PSEUDO_REGISTER_MINUS_VALUE, // dc poi(@$proc - xx)

} DEBUGGER_EVENT_ACTION_LOG_CONFIGURATION_TYPE;

/**
 * @brief Used for log the states
 *
 */
typedef struct _DEBUGGER_EVENT_ACTION_LOG_CONFIGURATION {
  DEBUGGER_EVENT_ACTION_LOG_CONFIGURATION_TYPE
  LogType;          // Type of log (how to log)
  UINT64 LogMask;   // Mask (e.g register)
  UINT64 LogValue;  // additions or subtraction value
  UINT32 LogLength; // Length of Bytes

} DEBUGGER_EVENT_ACTION_LOG_CONFIGURATION,
    *PDEBUGGER_EVENT_ACTION_LOG_CONFIGURATION;

/**
 * @brief used in the case of requesting a "request buffer"
 *
 */
typedef struct _DEBUGGER_EVENT_REQUEST_BUFFER {
  BOOLEAN EnabledRequestBuffer;
  UINT32 RequestBufferSize;
  UINT64 RequstBufferAddress;

} DEBUGGER_EVENT_REQUEST_BUFFER, *PDEBUGGER_EVENT_REQUEST_BUFFER;

/**
 * @brief used in the case of custom code requests to the debugger
 *
 */
typedef struct _DEBUGGER_EVENT_REQUEST_CUSTOM_CODE {
  UINT32 CustomCodeBufferSize;
  PVOID CustomCodeBufferAddress;
  UINT32 OptionalRequestedBufferSize;

} DEBUGGER_EVENT_REQUEST_CUSTOM_CODE, *PDEBUGGER_EVENT_REQUEST_CUSTOM_CODE;

/* ==============================================================================================
 */

/**
 * @brief The structure of actions in HyperDbg
 *
 */
typedef struct _DEBUGGER_EVENT_ACTION {
  UINT32 ActionOrderCode; // The code for this action (it also shows the order)
  LIST_ENTRY ActionsList; // Holds the link list of next actions
  DEBUGGER_EVENT_ACTION_TYPE_ENUM ActionType; // What action we wanna perform
  BOOLEAN ImmediatelySendTheResults; // should we send the results immediately
                                     // or store them in another structure and
                                     // send multiple of them each time

  DEBUGGER_EVENT_ACTION_LOG_CONFIGURATION
  LogConfiguration; // If it's Log the Statess

  DEBUGGER_EVENT_REQUEST_BUFFER
  RequestedBuffer; // if it's a custom code and needs a buffer then we use
                   // this structs

  UINT32 CustomCodeBufferSize;   // if null, means it's not custom code type
  PVOID CustomCodeBufferAddress; // address of custom code if any

} DEBUGGER_EVENT_ACTION, *PDEBUGGER_EVENT_ACTION;

/* ==============================================================================================
 */

/**
 * @brief The structure of events in HyperDbg
 *
 */
typedef struct _DEBUGGER_EVENT {
  UINT64 Tag;
  LIST_ENTRY EventsOfSameTypeList; // Linked-list of events of a same type
  DEBUGGER_EVENT_TYPE_ENUM EventType;
  BOOLEAN Enabled;
  UINT32 CoreId; // determines the core index to apply this event to, if it's
                 // 0xffffffff means that we have to apply it to all cores

  UINT32
  ProcessId; // determines the pid to apply this event to, if it's
             // 0xffffffff means that we have to apply it to all processes

  LIST_ENTRY ActionsListHead; // Each entry is in DEBUGGER_EVENT_ACTION struct
  UINT32 CountOfActions;      // The total count of actions

  UINT64 OptionalParam1; // Optional parameter to be used differently by events
  UINT64 OptionalParam2; // Optional parameter to be used differently by events
  UINT64 OptionalParam3; // Optional parameter to be used differently by events
  UINT64 OptionalParam4; // Optional parameter to be used differently by events

  UINT32 ConditionsBufferSize;  // if null, means uncoditional
  PVOID ConditionBufferAddress; // Address of the condition buffer (most of the
                                // time at the end of this buffer)

} DEBUGGER_EVENT, *PDEBUGGER_EVENT;

//////////////////////////////////////////////////
//		    	Debugger Success Codes            //
//////////////////////////////////////////////////

/**
 * @brief General value to indicate that the operation or
 * request was successful
 *
 */
#define DEBUGEER_OPERATION_WAS_SUCCESSFULL 0xFFFFFFFF

//////////////////////////////////////////////////
//		    	Debugger Error Codes            //
//////////////////////////////////////////////////

/**
 * @brief error, the tag not exist
 *
 */
#define DEBUGEER_ERROR_TAG_NOT_EXISTS 0xc0000000

/**
 * @brief error, invalid type of action
 *
 */
#define DEBUGEER_ERROR_INVALID_ACTION_TYPE 0xc0000001

/**
 * @brief error, the action buffer size is invalid
 *
 */
#define DEBUGEER_ERROR_ACTION_BUFFER_SIZE_IS_ZERO 0xc0000002

/**
 * @brief error, the event type is unknown
 *
 */
#define DEBUGEER_ERROR_EVENT_TYPE_IS_INVALID 0xc0000003

/**
 * @brief error, enable to create event
 *
 */
#define DEBUGEER_ERROR_UNABLE_TO_CREATE_EVENT 0xc0000004

/**
 * @brief error, invalid address specified for debugger
 *
 */
#define DEBUGEER_ERROR_INVALID_ADDRESS 0xc0000005

/**
 * @brief error, the core id is invalid
 *
 */
#define DEBUGEER_ERROR_INVALID_CORE_ID 0xc0000006

/**
 * @brief error, the index is greater than 32 in !exception command
 *
 */
#define DEBUGEER_ERROR_EXCEPTION_INDEX_EXCEED_FIRST_32_ENTRIES 0xc0000007

/**
 * @brief error, the index for !interrupt command is not between 32 to 256
 *
 */
#define DEBUGEER_ERROR_INTERRUPT_INDEX_IS_NOT_VALID 0xc0000008

/**
 * @brief error, unable to hide the debugger and enter to transparent-mode
 *
 */
#define DEBUGEER_ERROR_UNABLE_TO_HIDE_OR_UNHIDE_DEBUGGER 0xc0000009

/**
 * @brief error, the debugger is already in transparent-mode
 *
 */
#define DEBUGEER_ERROR_DEBUGGER_ALREADY_UHIDE 0xc000000a

/**
 * @brief error, invalid parameters in !e* e* commands
 *
 */
#define DEBUGGER_ERROR_EDIT_MEMORY_STATUS_INVALID_PARAMETER 0xc000000b

/**
 * @brief error, an invalid address is specified based on current cr3
 * in !e* or e* commands
 *
 */
#define DEBUGGER_ERROR_EDIT_MEMORY_STATUS_INVALID_ADDRESS_BASED_ON_CURRENT_PROCESS \
  0xc000000c

/**
 * @brief error, an invalid address is specified based on anotehr process's cr3
 * in !e* or e* commands
 *
 */
#define DEBUGGER_ERROR_EDIT_MEMORY_STATUS_INVALID_ADDRESS_BASED_ON_OTHER_PROCESS \
  0xc000000d

/**
 * @brief error, invalid tag for 'events' command (tag id is unknown for kernel)
 *
 */
#define DEBUGGER_ERROR_MODIFY_EVENTS_INVALID_TAG 0xc000000e

/**
 * @brief error, type of action (enable/disable/clear) is wrong
 *
 */
#define DEBUGGER_ERROR_MODIFY_EVENTS_INVALID_TYPE_OF_ACTION 0xc000000f

/**
 * @brief error, invalid parameters steppings actions
 *
 */
#define DEBUGGER_ERROR_STEPPING_INVALID_PARAMETER 0xc0000010

/**
 * @brief error, thread is invalid (not found) or disabled in
 * stepping (step-in & step-out) requests
 *
 */
#define DEBUGGER_ERROR_STEPPINGS_EITHER_THREAD_NOT_FOUND_OR_DISABLED 0xc0000011

//
// WHEN YOU ADD ANYTHING TO THIS LIST OF ERRORS, THEN
// MAKE SURE TO ADD AN ERROR MESSAGE TO ShowErrorMessage(UINT32 Error)
// FUNCTION
//

//////////////////////////////////////////////////
//                   IOCTLs                     //
//////////////////////////////////////////////////

/**
 * @brief ioctl, to terminate vmx and exit form debugger
 *
 */
#define IOCTL_TERMINATE_VMX                                                    \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
