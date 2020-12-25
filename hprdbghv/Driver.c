/**
 * @file Driver.c
 * @author Sina Karvandi (sina@rayanfam.com)
 * @brief The project entry 
 * @details This file contains major functions and all the interactions
 * with usermode codes are managed from here.
 * e.g debugger commands and extension commands
 * @version 0.1
 * @date 2020年10月2日
 * 
 * @copyright This project is released under the GNU Public License v3.
 * 
 */
#include "pch.h"
#include "Driver.tmh"


/**
 * @brief Main Driver Entry in the case of driver load
 * 
 * @param DriverObject 
 * @param RegistryPath 
 * @return NTSTATUS 
 */
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT  DriverObject,
    PUNICODE_STRING RegistryPath)
{
    NTSTATUS       Ntstatus       = STATUS_SUCCESS;
    UINT64         Index          = 0;
    UINT32         ProcessorCount = 0;
    PDEVICE_OBJECT DeviceObject   = NULL;
    UNICODE_STRING DriverName     = RTL_CONSTANT_STRING(L"\\Device\\HyperdbgHypervisorDevice");
    UNICODE_STRING DosDeviceName  = RTL_CONSTANT_STRING(L"\\DosDevices\\HyperdbgHypervisorDevice");

    UNREFERENCED_PARAMETER(RegistryPath);
    UNREFERENCED_PARAMETER(DriverObject);

    //
    // Initialize WPP Tracing
    //

    WPP_INIT_TRACING(DriverObject, RegistryPath);

#if !UseDbgPrintInsteadOfUsermodeMessageTracking
    if (!LogInitialize())
    {
        DbgPrint("[*] Log buffer is not initialized !\n");
        DbgBreakPoint();
    }
#endif
    //
    // Opt-in to using non-executable pool memory on Windows 8 and later.
	// 在Win8以上使用不可分页内存池
    // https://msdn.microsoft.com/en-us/library/windows/hardware/hh920402(v=vs.85).aspx
    //

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    //
    // we allocate virtual machine here because
    // we want to use its state (vmx-root or vmx non-root) in logs
    //

    ProcessorCount = KeQueryActiveProcessorCount(0);

    //
    // Allocate global variable to hold Guest(s) state
    //

    g_GuestState = ExAllocatePoolWithTag(NonPagedPool, sizeof(VIRTUAL_MACHINE_STATE) * ProcessorCount, POOLTAG);
    if (!g_GuestState)
    {
        //
        // we use DbgPrint as the vmx-root or non-root is not initialized
        //

        DbgPrint("Insufficient memory\n");
        DbgBreakPoint();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Zero the memory
    //
    RtlZeroMemory(g_GuestState, sizeof(VIRTUAL_MACHINE_STATE) * ProcessorCount);

    LogInfo("Hyperdbg is Loaded :)");

    Ntstatus = IoCreateDevice(DriverObject,
                              0,
                              &DriverName,
                              FILE_DEVICE_UNKNOWN,
                              FILE_DEVICE_SECURE_OPEN,
                              FALSE,
                              &DeviceObject);

    if (Ntstatus == STATUS_SUCCESS)
    {
        for (Index = 0; Index < IRP_MJ_MAXIMUM_FUNCTION; Index++)
            DriverObject->MajorFunction[Index] = DrvUnsupported;

        LogInfo("Setting device major functions");
        DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DrvClose;
        DriverObject->MajorFunction[IRP_MJ_CREATE]         = DrvCreate;
        DriverObject->MajorFunction[IRP_MJ_READ]           = DrvRead;
        DriverObject->MajorFunction[IRP_MJ_WRITE]          = DrvWrite;
		DriverObject->MajorFunction[IRP_MJ_SHUTDOWN]	   = DrvShutdown;
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DrvDispatchIoControl;


        DriverObject->DriverUnload = DrvUnload;
        IoCreateSymbolicLink(&DosDeviceName, &DriverName);
    }

    //
    // Establish user-buffer access method.
    //
    DeviceObject->Flags |= DO_BUFFERED_IO;

    ASSERT(NT_SUCCESS(Ntstatus));
    return Ntstatus;
}

/**
 * @brief Run in the case of driver unload to unregister the devices
 * 卸载驱动
 * @param DriverObject 
 * @return VOID 
 */
VOID
DrvUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING DosDeviceName;

    RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\HyperdbgHypervisorDevice");
    IoDeleteSymbolicLink(&DosDeviceName);
    IoDeleteDevice(DriverObject->DeviceObject);

	LogWarning("Uinitializing !bye!");
#if !UseDbgPrintInsteadOfUsermodeMessageTracking

    //
    // Uinitialize log buffer
    //
    DbgPrint("Uinitializing logs\n");
    LogUnInitialize();
#endif
    //
    // Free g_GuestState
    //
	if ARGUMENT_PRESENT(g_GuestState)
	{
		ExFreePoolWithTag(g_GuestState, POOLTAG);
	}
    

    //
    // Stop the tracing
    //
    WPP_CLEANUP(DriverObject);
}


BOOLEAN
FindSubString(
	IN PUNICODE_STRING String,
	IN PUNICODE_STRING SubString
)
{
	ULONG index;

	//
	//  First, check to see if the strings are equal.
	//

	if (RtlEqualUnicodeString(String, SubString, TRUE)) {

		return TRUE;
	}

	//
	//  String and SubString aren't equal, so now see if SubString
	//  in in String any where.
	//
	for (index = 0;
		index + SubString->Length <= String->Length;
		index++) {
		if (_wcsnicmp(&(String->Buffer[index]),
			SubString->Buffer,
			SubString->Length) == 0) {
			//
			//  SubString is found in String, so return TRUE.
		   //
			return TRUE;
		}
	}

	return FALSE;
}

NTSTATUS NtCreateFileHook(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
	_In_ ULONG EaLength
)
{
	return NtCreateFileOrig(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}


/**
 * @brief IRP_MJ_CREATE Function handler
 * 
 * @param DeviceObject 
 * @param Irp 
 * @return NTSTATUS 
 */
NTSTATUS
DrvCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    int ProcessorCount;

    //
    // Check for privilege
    //
    // Check for the correct security access.
    // The caller must have the SeDebugPrivilege.
    // 验证权限，需要进程有Debug权限，因为去掉了Debug功能，所以没必要验证喽
	/*
    LUID DebugPrivilege = {SE_DEBUG_PRIVILEGE, 0};

    if (!SeSinglePrivilegeCheck(DebugPrivilege, Irp->RequestorMode))
    {
        Irp->IoStatus.Status      = STATUS_ACCESS_DENIED;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

		//返回权限不足
        return STATUS_ACCESS_DENIED;
    }
	*/
    //
    // 检查以仅允许驱动程序使用一个句柄意味着只有一个应用程序可以获取该句柄，除非调用IRP MJ CLOSE，否则新应用程序将不允许创建新的句柄。
    //
    if (g_HandleInUse)
    {
        //
        // A driver got the handle before
        //
        Irp->IoStatus.Status      = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);

        return STATUS_SUCCESS;
    }

    //
    // Allow to server IOCTL
    //
    g_AllowIOCTLFromUsermode = TRUE;

    LogInfo("Hyperdbg's hypervisor Started...");
    //
    // We have to zero the g_GuestState again as we want to support multiple initialization by CreateFile
	//获取当前处理器个数
    //
    ProcessorCount = KeQueryActiveProcessorCount(0);

    //
    // Zero the memory
    //
    RtlZeroMemory(g_GuestState, sizeof(VIRTUAL_MACHINE_STATE) * ProcessorCount);

    //
    // Initialize memory mapper
	// 初始化内存管理
    //
    MemoryMapperInitialize();
    //
    // Initialize Vmx
	// 初始化VT
    //
    if (HvVmxInitialize())
    {
		//UNICODE_STRING StringNtCreateFile = RTL_CONSTANT_STRING(L"NtCreateFile");
		//ApiLocationFromSSDTOfNtCreateFile = MmGetSystemRoutineAddress(&StringNtCreateFile);
		//NtCreateFileOrig = EptHook2(ApiLocationFromSSDTOfNtCreateFile, NtCreateFileHook, (UINT32)PsGetCurrentProcessId(), (BOOLEAN)FALSE, (BOOLEAN)FALSE, (BOOLEAN)TRUE);
		//KeGenericCallDpc(BroadcastDpcEnableBreakpointOnExceptionBitmapOnAllCores, NULL);
        LogInfo("Hyperdbg's hypervisor loaded successfully :)");

		Irp->IoStatus.Status      = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		g_VTEnabled = TRUE;
		g_HandleInUse = TRUE;
			
		return STATUS_SUCCESS;

    }
    else
    {
        LogError("Hyperdbg's hypervisor was not loaded :(");
    }

    //
    // if we didn't return by now, means that there is a problem
    //
    Irp->IoStatus.Status      = STATUS_UNSUCCESSFUL;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_UNSUCCESSFUL;
}
NTSTATUS
DrvShutdown(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	LogWarning("DrvShutdown");

	//关机或休眠则停止VT
	if (g_VTEnabled)
	{
		//
		// terminate vmx
		//
		HvTerminateVmx();

		//
		// Uninitialize memory mapper
		//
		MemoryMapperUninitialize();

		//
		// VT-X Close
		//
		g_VTEnabled = FALSE;
	}

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


/**
 * @brief IRP_MJ_READ Function handler
 * 响应ReadFile，这里没用
 * @param DeviceObject 
 * @param Irp 
 * @return NTSTATUS 
 */
NTSTATUS
DrvRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    LogWarning("Not implemented yet :(");

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

/**
 * @brief IRP_MJ_WRITE Function handler
 * 响应WriteFile，这里没用
 * @param DeviceObject 
 * @param Irp 
 * @return NTSTATUS 
 */
NTSTATUS
DrvWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    LogWarning("Not implemented yet :(");

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

/**
 * @brief IRP_MJ_CLOSE Function handler
 * 响应关闭事件，这里没用
 * @param DeviceObject 
 * @param Irp 
 * @return NTSTATUS 
 */
NTSTATUS
DrvClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    //
    // If the close is called means that all of the IOCTLs
    // are not in a pending state so we can safely allow
    // a new handle creation for future calls to the driver
    //
    g_HandleInUse = FALSE;

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

/**
 * @brief Unsupported message for all other IRP_MJ_* handlers
 * 未知IRP
 * @param DeviceObject 
 * @param Irp 
 * @return NTSTATUS 
 */
NTSTATUS
DrvUnsupported(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    DbgPrint("This function is not supported :(");

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}
