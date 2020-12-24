/**
 * @file Ioctl.c
 * @author Sina Karvandi (sina@rayanfam.com)
 * @brief IOCTL Functions form user mode and other parts 
 * @details 
 *
 * @version 0.1
 * @date 2020-06-01
 * 
 * @copyright This project is released under the GNU Public License v3.
 * 
 */
#include "pch.h"
//IO´¦Àí´úÂë
/**
 * @brief Driver IOCTL Dispatcher
 * 
 * @param DeviceObject 
 * @param Irp 
 * @return NTSTATUS 
 */
NTSTATUS
DrvDispatchIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION                           IrpStack;
    PREGISTER_NOTIFY_BUFFER                      RegisterEventRequest;
    PDEBUGGER_READ_MEMORY                        DebuggerReadMemRequest;
    PDEBUGGER_READ_AND_WRITE_ON_MSR              DebuggerReadOrWriteMsrRequest;
    PDEBUGGER_HIDE_AND_TRANSPARENT_DEBUGGER_MODE DebuggerHideAndUnhideRequest;
    PDEBUGGER_READ_PAGE_TABLE_ENTRIES_DETAILS    DebuggerPteRequest;
    PDEBUGGER_VA2PA_AND_PA2VA_COMMANDS           DebuggerVa2paAndPa2vaRequest;
    PDEBUGGER_EDIT_MEMORY                        DebuggerEditMemoryRequest;
    PDEBUGGER_SEARCH_MEMORY                      DebuggerSearchMemoryRequest;
    PDEBUGGER_EVENT_AND_ACTION_REG_BUFFER        RegBufferResult;
    PDEBUGGER_GENERAL_EVENT_DETAIL               DebuggerNewEventRequest;
    PDEBUGGER_MODIFY_EVENTS                      DebuggerModifyEventRequest;
    PDEBUGGER_FLUSH_LOGGING_BUFFERS              DebuggerFlushBuffersRequest;
    PDEBUGGER_ATTACH_DETACH_USER_MODE_PROCESS    DebuggerAttachOrDetachToThreadRequest;
    PDEBUGGER_STEPPINGS                          DebuggerSteppingsRequest;
	PDEBUGGER_READ_PROCESS_CR3_DETAILS			 DebuggerReadCR3;
    PDEBUGGER_GENERAL_ACTION                     DebuggerNewActionRequest;
    NTSTATUS                                     Status;
    ULONG                                        InBuffLength;  // Input buffer length
    ULONG                                        OutBuffLength; // Output buffer length
    SIZE_T                                       ReturnSize;
    BOOLEAN                                      DoNotChangeInformation = FALSE;

    //
    // Here's the best place to see if there is any allocation pending
    // to be allcated as we're in PASSIVE_LEVEL
    //
    PoolManagerCheckAndPerformAllocationAndDeallocation();

    if (g_AllowIOCTLFromUsermode)
    {
        IrpStack = IoGetCurrentIrpStackLocation(Irp);

        switch (IrpStack->Parameters.DeviceIoControl.IoControlCode)
        {
        case IOCTL_TERMINATE_VMX:
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
            Status = STATUS_SUCCESS;
            break;
        default:
            LogError("Unknow IOCTL");
            Status = STATUS_NOT_IMPLEMENTED;
            break;
        }
    }
    else
    {
        //
        // We're no longer serve IOCTL
        //
        Status = STATUS_SUCCESS;
    }

    if (Status != STATUS_PENDING)
    {
        Irp->IoStatus.Status = Status;
        if (!DoNotChangeInformation)
        {
            Irp->IoStatus.Information = 0;
        }
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    return Status;
}
