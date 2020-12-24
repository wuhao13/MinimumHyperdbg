/**
 * @file Vmexit.c
 * @author Sina Karvandi (sina@rayanfam.com)
 * @brief The functions for VM-Exit handler for different exit reasons 
 * @details
 * @version 0.1
 * @date 2020-04-11
 * 
 * @copyright This project is released under the GNU Public License v3.
 * 
 */
#include "pch.h"

/**
 * @brief VM-Exit handler for different exit reasons
 * 
 * @param GuestRegs Registers that are automatically saved by AsmVmexitHandler (HOST_RIP)
 * @return BOOLEAN Return True if VMXOFF executed (not in vmx anymore),
 *  or return false if we are still in vmx (so we should use vm resume)
 * Vm-Exit核心处理
 */
BOOLEAN
VmxVmexitHandler(PGUEST_REGS GuestRegs)
{
    VMEXIT_INTERRUPT_INFO InterruptExit         = {0};
    IO_EXIT_QUALIFICATION IoQualification       = {0};
    RFLAGS                Flags                 = {0};
    UINT64                GuestPhysicalAddr     = 0;
    UINT64                GuestRsp              = 0;
    ULONG                 ExitReason            = 0;
    ULONG                 ExitQualification     = 0;
    ULONG                 Rflags                = 0;
    ULONG                 EcxReg                = 0;
    ULONG                 ExitInstructionLength = 0;
    ULONG                 CurrentProcessorIndex = 0;
    BOOLEAN               Result                = FALSE;
    BOOLEAN               ShouldEmulateRdtscp   = TRUE;

    //
    // *********** SEND MESSAGE AFTER WE SET THE STATE ***********
    //
    CurrentProcessorIndex = KeGetCurrentProcessorNumber();

    //
    // Indicates we are in Vmx root mode in this logical core
    //
    g_GuestState[CurrentProcessorIndex].IsOnVmxRootMode = TRUE;

    //
    // read the exit reason and exit qualification
    //

    __vmx_vmread(VM_EXIT_REASON, &ExitReason);
    ExitReason &= 0xffff;

    //
    // Increase the RIP by default
    //
    g_GuestState[CurrentProcessorIndex].IncrementRip = TRUE;

    //
    // Set the rsp in general purpose registers structure
    //
    __vmx_vmread(GUEST_RSP, &GuestRsp);
    GuestRegs->rsp = GuestRsp;

    //
    // Read the exit qualification
    //

    __vmx_vmread(EXIT_QUALIFICATION, &ExitQualification);

    //
    // Debugging purpose
    //
    // LogInfo("VM_EXIT_REASON : 0x%x", ExitReason);
    // LogInfo("EXIT_QUALIFICATION : 0x%llx", ExitQualification);
    //

    switch (ExitReason)
    {
    case EXIT_REASON_TRIPLE_FAULT:
    {
        LogError("Triple fault error occured.");

        break;
    }
        //
        // 25.1.2  Instructions That Cause VM Exits Unconditionally
        // The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC,
        // INVD, and XSETBV. This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID,
        // VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON.
        //

    case EXIT_REASON_VMCLEAR:
    case EXIT_REASON_VMPTRLD:
    case EXIT_REASON_VMPTRST:
    case EXIT_REASON_VMREAD:
    case EXIT_REASON_VMRESUME:
    case EXIT_REASON_VMWRITE:
    case EXIT_REASON_VMXOFF:
    case EXIT_REASON_VMXON:
    case EXIT_REASON_VMLAUNCH:
    {
        //
        // cf=1 indicate vm instructions fail
        //
        //__vmx_vmread(GUEST_RFLAGS, &Rflags);
        //__vmx_vmwrite(GUEST_RFLAGS, Rflags | 0x1);

        //
        // Handle unconditional vm-exits (inject #ud)
		EventInjectUndefinedOpcode(CurrentProcessorIndex);
        //


        break;
    }
    case EXIT_REASON_INVEPT:
    case EXIT_REASON_INVVPID:
    case EXIT_REASON_GETSEC:
    case EXIT_REASON_INVD:
    {
        //
        // Handle unconditional vm-exits (inject #ud)
		EventInjectUndefinedOpcode(CurrentProcessorIndex);
        //
        break;
    }
    case EXIT_REASON_CR_ACCESS:
    {
        HvHandleControlRegisterAccess(GuestRegs, CurrentProcessorIndex);
        break;
    }
    case EXIT_REASON_MSR_READ:
    {
        EcxReg = GuestRegs->rcx & 0xffffffff;
        HvHandleMsrRead(GuestRegs);


        break;
    }
    case EXIT_REASON_MSR_WRITE:
    {
        EcxReg = GuestRegs->rcx & 0xffffffff;
        HvHandleMsrWrite(GuestRegs);

        break;
    }
    case EXIT_REASON_CPUID:
    {
        HvHandleCpuid(GuestRegs);
        break;
    }

    case EXIT_REASON_IO_INSTRUCTION:
    {
        //
        // Read the I/O Qualification which indicates the I/O instruction
        //
        __vmx_vmread(EXIT_QUALIFICATION, &IoQualification);

        //
        // Read Guest's RFLAGS
        //
        __vmx_vmread(GUEST_RFLAGS, &Flags);

        //
        // Call the I/O Handler
        //
        IoHandleIoVmExits(GuestRegs, IoQualification, Flags);

        break;
    }
    case EXIT_REASON_EPT_VIOLATION:
    {
        //
        // Reading guest physical address
        //
        __vmx_vmread(GUEST_PHYSICAL_ADDRESS, &GuestPhysicalAddr);
		// EPT页的处理流程
		// EptHandleEptViolation -》 EptHandlePageHookExit
        if (EptHandleEptViolation(GuestRegs, ExitQualification, GuestPhysicalAddr) == FALSE)
        {
            LogError("There were errors in handling Ept Violation");
        }

        break;
    }
    case EXIT_REASON_EPT_MISCONFIG:
    {
        __vmx_vmread(GUEST_PHYSICAL_ADDRESS, &GuestPhysicalAddr);

        EptHandleMisconfiguration(GuestPhysicalAddr);

        break;
    }
    case EXIT_REASON_VMCALL:
    {
        //
        // Handle vm-exits of VMCALLs
        //
        VmxHandleVmcallVmExit(GuestRegs);

        break;
    }
    case EXIT_REASON_EXCEPTION_NMI:
    {
        //
        // read the exit reason
        //
        __vmx_vmread(VM_EXIT_INTR_INFO, &InterruptExit);

        //
        // Call the Exception Bitmap and NMI Handler
        //
        IdtEmulationHandleExceptionAndNmi(InterruptExit, CurrentProcessorIndex, GuestRegs);

        break;
    }
    case EXIT_REASON_EXTERNAL_INTERRUPT:
    {
        //
        // read the exit reason (for interrupt)
        //
        __vmx_vmread(VM_EXIT_INTR_INFO, &InterruptExit);

        //
        // Call External Interrupt Handler
        //
        IdtEmulationHandleExternalInterrupt(InterruptExit, CurrentProcessorIndex);


        break;
    }
    case EXIT_REASON_PENDING_VIRT_INTR:
    {
        //
        // Call the interrupt-window exiting handler to re-inject the previous
        // interrupts or disable the interrupt-window exiting bit
        //
        IdtEmulationHandleInterruptWindowExiting(CurrentProcessorIndex);

        break;
    }
    case EXIT_REASON_MONITOR_TRAP_FLAG:
    {
        //
        // Monitor Trap Flag
        //
        if (g_GuestState[CurrentProcessorIndex].MtfEptHookRestorePoint)
        {
            //
            // Restore the previous state
            //
            EptHandleMonitorTrapFlag(g_GuestState[CurrentProcessorIndex].MtfEptHookRestorePoint);

            //
            // Set it to NULL
            //
            g_GuestState[CurrentProcessorIndex].MtfEptHookRestorePoint = NULL;
        }
        else
        {
            LogError("Why MTF occured ?!");
        }
        //
        // Redo the instruction
        //
        g_GuestState[CurrentProcessorIndex].IncrementRip = FALSE;

        //
        // We don't need MTF anymore if it set to disable MTF
        //
        HvSetMonitorTrapFlag(FALSE);

        break;
    }
    case EXIT_REASON_HLT:
    {
        //
        // We don't wanna halt
        //

        //
        //__halt();
        //
        break;
    }
    case EXIT_REASON_RDTSC:
    {
        //
        // Check whether we are allowed to change
        // the registers and emulate rdtsc or not
        //
        if (ShouldEmulateRdtscp)
        {
            //
            // handle rdtsc (emulate rdtsc)
            //
            CounterEmulateRdtsc(GuestRegs);

        }
        break;
    }
    case EXIT_REASON_RDTSCP:
    {
        //
        // Check whether we are allowed to change
        // the registers and emulate rdtscp or not
        //
        if (ShouldEmulateRdtscp)
        {
            //
            // handle rdtscp (emulate rdtscp)
            //
            CounterEmulateRdtscp(GuestRegs);

        }

        break;
    }
    case EXIT_REASON_RDPMC:
    {
        //
        // handle rdpmc (emulate rdpmc)
        //
        CounterEmulateRdpmc(GuestRegs);


        break;
    }
    case EXIT_REASON_DR_ACCESS:
    {
        //
        // Handle access to debug registers
        //
        HvHandleMovDebugRegister(CurrentProcessorIndex, GuestRegs);


        break;
    }
    case EXIT_REASON_XSETBV:
    {
        //
        // Handle xsetbv (unconditional vm-exit)
        //
        EcxReg = GuestRegs->rcx & 0xffffffff;
        VmxHandleXsetbv(EcxReg, GuestRegs->rdx << 32 | GuestRegs->rax);

        break;
    }
    default:
    {
        LogError("Unkown Vmexit, reason : 0x%llx", ExitReason);
        break;
    }
    }

    //
    // Check whether we need to increment the guest's ip or not
    // Also, we should not increment rip if a vmxoff executed
    //
    if (!g_GuestState[CurrentProcessorIndex].VmxoffState.IsVmxoffExecuted && g_GuestState[CurrentProcessorIndex].IncrementRip)
    {
        HvResumeToNextInstruction();
    }

    //
    // Set indicator of Vmx non root mode to false
    //
    g_GuestState[CurrentProcessorIndex].IsOnVmxRootMode = FALSE;


    if (g_GuestState[CurrentProcessorIndex].VmxoffState.IsVmxoffExecuted)
        Result = TRUE;

    //
    // By default it's FALSE, if we want to exit vmx then it's TRUE
    //
    return Result;
}
