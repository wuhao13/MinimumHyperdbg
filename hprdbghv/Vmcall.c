/**
 * @file Vmcall.c
 * @author Sina Karvandi (sina@rayanfam.com)
 * @brief The main VMCALL and Hypercall handler
 * @details
 * @version 0.1
 * @date 2020-04-11
 * 
 * @copyright This project is released under the GNU Public License v3.
 * 
 */
#include "pch.h"

/**
 * @brief Handle vm-exits of VMCALLs
 * 
 * @param GuestRegs Guest Registers
 * @return NTSTATUS 
 */
NTSTATUS
VmxHandleVmcallVmExit(PGUEST_REGS GuestRegs)
{

    //
    // Check if it's our routines that request the VMCALL our it relates to Hyper-V
    //
    if (GuestRegs->r10 == 0x48564653 && GuestRegs->r11 == 0x564d43414c4c && GuestRegs->r12 == 0x4e4f485950455256)
    {
        //
        // Then we have to manage it as it relates to us
        //
        GuestRegs->rax = VmxVmcallHandler(GuestRegs->rcx, GuestRegs->rdx, GuestRegs->r8, GuestRegs->r9);
    }
    else
    {
        HYPERCALL_INPUT_VALUE InputValue = {0};
        InputValue.Value                 = GuestRegs->rcx;

        switch (InputValue.Bitmap.CallCode)
        {
        case HvSwitchVirtualAddressSpace:
        case HvFlushVirtualAddressSpace:
        case HvFlushVirtualAddressList:
        case HvCallFlushVirtualAddressSpaceEx:
        case HvCallFlushVirtualAddressListEx:
        {
            InvvpidAllContexts();
            break;
        }
        case HvCallFlushGuestPhysicalAddressSpace:
        case HvCallFlushGuestPhysicalAddressList:
        {
            InveptSingleContext(g_EptState->EptPointer.Flags);
            break;
        }
        }
        //
        // Let the top-level hypervisor to manage it
        //
        GuestRegs->rax = AsmHypervVmcall(GuestRegs->rcx, GuestRegs->rdx, GuestRegs->r8, GuestRegs->r9);
    }
	return STATUS_SUCCESS;
}

/**
 * @brief Main Vmcall Handler
 * 
 * @param VmcallNumber Request Number
 * @param OptionalParam1 
 * @param OptionalParam2 
 * @param OptionalParam3 
 * @return NTSTATUS 
 */
NTSTATUS
VmxVmcallHandler(UINT64 VmcallNumber,
                 UINT64 OptionalParam1,
                 UINT64 OptionalParam2,
                 UINT64 OptionalParam3)
{
    NTSTATUS VmcallStatus = STATUS_UNSUCCESSFUL;
    BOOLEAN  HookResult   = FALSE;
    BOOLEAN  UnsetExec    = TRUE;
    BOOLEAN  UnsetWrite   = TRUE;
    BOOLEAN  UnsetRead    = TRUE;

    //
    // Only 32bit of Vmcall is valid, this way we can use the upper 32 bit of the Vmcall
    //
	//取命令字
    switch (VmcallNumber & 0xffffffff)
    {
    //测试自定义VMCALL
    case VMCALL_TEST:
    {
        VmcallStatus = VmcallTest(OptionalParam1, OptionalParam2, OptionalParam3);
        break;
    }
    case VMCALL_VMXOFF:
    {
        VmxVmxoff();
        VmcallStatus = STATUS_SUCCESS;
        break;
    }
	case VMCALL_CHANGE_PAGE_ATTRIB:
	{
		//
		// Mask is the upper 32 bits to this Vmcall
		// Upper 32 bits of the Vmcall contains the attribute mask
		//

		UINT32 AttributeMask = (UINT32)((VmcallNumber & 0xFFFFFFFF00000000) >> 32);
		/*
		//wtf?这里得到的值不是预期的？
		UnsetRead  = (AttributeMask & PAGE_ATTRIB_READ) ? TRUE : FALSE;
		UnsetWrite = (AttributeMask & PAGE_ATTRIB_WRITE) ? TRUE : FALSE;
		UnsetExec  = (AttributeMask & PAGE_ATTRIB_EXEC) ? TRUE : FALSE;
		*/

		if ((AttributeMask & PAGE_ATTRIB_READ) == 0)
		{
			UnsetRead = FALSE;
			LogInfo("UnsetRead = FALSE");
		}

		if ((AttributeMask & PAGE_ATTRIB_WRITE) == 0)
		{
			UnsetWrite = FALSE;
			LogInfo("UnsetWrite = FALSE");
		}

		if ((AttributeMask & PAGE_ATTRIB_EXEC) == 0)
		{
			UnsetExec = FALSE;
			LogInfo("UnsetExec = FALSE");
		}

		CR3_TYPE ProcCr3 = { 0 };
		ProcCr3.Flags = OptionalParam3;
		LogInfo("VmxVmcallHandler EptHookPerformPageHook2.");
		HookResult = EptHookPerformPageHook2(OptionalParam1 /* TargetAddress */,
			OptionalParam2 /* Hook Function*/,
			ProcCr3 /* Process cr3 */,
			UnsetRead,
			UnsetWrite,
			UnsetExec);

		VmcallStatus = (HookResult == TRUE) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

		break;
	}
    //使ept缓存表中的单个上下文无效
    case VMCALL_INVEPT_SINGLE_CONTEXT:
    {
        InveptSingleContext(OptionalParam1);
        VmcallStatus = STATUS_SUCCESS;
        break;
    }
    //使ept缓存表中的所有上下文无效
    case VMCALL_INVEPT_ALL_CONTEXTS:
    {
        InveptAllContexts();
        VmcallStatus = STATUS_SUCCESS;
        break;
    }
	//卸载并恢复所有HOOK
	case VMCALL_UNHOOK_ALL_PAGES:
	{
		EptHookRestoreAllHooksToOrginalEntry();
		VmcallStatus = STATUS_SUCCESS;
		break;
	}
	//卸载并恢复指定HOOK
	case VMCALL_UNHOOK_SINGLE_PAGE:
	{
		if (!EptHookRestoreSingleHookToOrginalEntry(OptionalParam1))
		{
			VmcallStatus = STATUS_UNSUCCESSFUL;
		}
		break;
	}
    //更改MSR位图以进行读取
    case VMCALL_CHANGE_MSR_BITMAP_READ:
    {
        HvPerformMsrBitmapReadChange(OptionalParam1);
        VmcallStatus = STATUS_SUCCESS;
        break;
    }
    //更改MSR位图进行写入
    case VMCALL_CHANGE_MSR_BITMAP_WRITE:
    {
        HvPerformMsrBitmapWriteChange(OptionalParam1);
        VmcallStatus = STATUS_SUCCESS;
        break;
    }
    case VMCALL_SET_RDTSC_EXITING:
    {
        HvSetTscVmexit(TRUE);
        VmcallStatus = STATUS_SUCCESS;
        break;
    }
    case VMCALL_SET_RDPMC_EXITING:
    {
        HvSetPmcVmexit(TRUE);
        VmcallStatus = STATUS_SUCCESS;
        break;
    }
    case VMCALL_SET_EXCEPTION_BITMAP:
    {
        HvSetExceptionBitmap(OptionalParam1);
        VmcallStatus = STATUS_SUCCESS;
        break;
    }
    case VMCALL_ENABLE_MOV_TO_DEBUG_REGS_EXITING:
    {
        HvSetMovDebugRegsExiting(TRUE);
        VmcallStatus = STATUS_SUCCESS;
        break;
    }
    case VMCALL_ENABLE_EXTERNAL_INTERRUPT_EXITING:
    {
        HvSetExternalInterruptExiting(TRUE);
        VmcallStatus = STATUS_SUCCESS;
        break;
    }
    case VMCALL_CHANGE_IO_BITMAP:
    {
        HvPerformIoBitmapChange(OptionalParam1);
        VmcallStatus = STATUS_SUCCESS;
        break;
    }
    case VMCALL_DISABLE_EXTERNAL_INTERRUPT_EXITING:
    {
        HvSetExternalInterruptExiting(FALSE);
        VmcallStatus = STATUS_SUCCESS;
        break;
    }
    case VMCALL_ENABLE_BREAKPOINT_ON_EXCEPTION_BITMAP:
    {
        //
        // Enable vm-exits on breakpoints (exception bitmap)
        //
        HvSetExceptionBitmap(EXCEPTION_VECTOR_BREAKPOINT);
        HvSetExceptionBitmap(EXCEPTION_VECTOR_PAGE_FAULT);
        VmcallStatus = STATUS_SUCCESS;

        break;
    }
    case VMCALL_DISABLE_BREAKPOINT_ON_EXCEPTION_BITMAP:
    {
        //
        // Disable vm-exits on breakpoints (exception bitmap)
        //
		
        HvUnsetExceptionBitmap(EXCEPTION_VECTOR_BREAKPOINT);
        VmcallStatus = STATUS_SUCCESS;

        break;
    }
    case VMCALL_UNSET_RDTSC_EXITING:
    {
        HvSetTscVmexit(FALSE);
        VmcallStatus = STATUS_SUCCESS;
        break;

        break;
    }
    case VMCALL_UNSET_RDPMC_EXITING:
    {
        HvSetPmcVmexit(FALSE);
        VmcallStatus = STATUS_SUCCESS;
        break;
    }
    case VMCALL_DISABLE_MOV_TO_DEBUG_REGS_EXITING:
    {
        HvSetMovDebugRegsExiting(FALSE);
        VmcallStatus = STATUS_SUCCESS;
        break;
    }
    case VMCALL_RESET_MSR_BITMAP_READ:
    {
        HvPerformMsrBitmapReadReset();
        VmcallStatus = STATUS_SUCCESS;
        break;
    }
    case VMCALL_RESET_MSR_BITMAP_WRITE:
    {
        HvPerformMsrBitmapWriteReset();
        VmcallStatus = STATUS_SUCCESS;
        break;
    }
    case VMCALL_RESET_EXCEPTION_BITMAP:
    {
        HvResetExceptionBitmap();
        VmcallStatus = STATUS_SUCCESS;
        break;
    }
    case VMCALL_RESET_IO_BITMAP:
    {
        HvPerformIoBitmapReset();
        VmcallStatus = STATUS_SUCCESS;
        break;
    }
    case VMCALL_ENABLE_MOV_TO_CR3_EXITING:
    {
        HvSetMovToCr3Vmexit(TRUE);
        VmcallStatus = STATUS_SUCCESS;
        break;
    }
    case VMCALL_DISABLE_MOV_TO_CR3_EXITING:
    {
        HvSetMovToCr3Vmexit(FALSE);
        VmcallStatus = STATUS_SUCCESS;
        break;
    }
    default:
    {
        LogError("Unsupported VMCALL");
        VmcallStatus = STATUS_UNSUCCESSFUL;
        break;
    }
    }
    return VmcallStatus;
}

/**
 * @brief Test Vmcall (VMCALL_TEST)
 * 
 * @param Param1 
 * @param Param2 
 * @param Param3 
 * @return NTSTATUS 
 */
NTSTATUS
VmcallTest(UINT64 Param1, UINT64 Param2, UINT64 Param3)
{
    LogInfo("VmcallTest called with @Param1 = 0x%llx , @Param2 = 0x%llx , @Param3 = 0x%llx", Param1, Param2, Param3);
    return STATUS_SUCCESS;
}
