/**
 * @file Broadcast.c
 * @author Sina Karvandi (sina@rayanfam.com)
 * @brief Broadcast debugger function to all logical cores
 * @details This file uses DPC to run its functions on all logical cores
 * @version 0.1
 * @date 2020-04-10
 * 
 * @copyright This project is released under the GNU Public License v3.
 * 
 */
#include "pch.h"
//各种修改Guest参数的Dpc调用的函数

/**
 * @brief Broadcast to enable mov-to-cr3 exitings
 * 打开move-to-cr3中断
 * 
 * @param Dpc 
 * @param DeferredContext 
 * @param SystemArgument1 
 * @param SystemArgument2 
 * @return VOID 
 */
VOID
BroadcastDpcEnableMovToCr3Exiting(KDPC * Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    //
    // Enable mov-to-cr3 exiting from vmx-root
    //
    AsmVmxVmcall(VMCALL_ENABLE_MOV_TO_CR3_EXITING, 0, 0, 0);

    //
    // Wait for all DPCs to synchronize at this point
    //
    KeSignalCallDpcSynchronize(SystemArgument2);

    //
    // Mark the DPC as being complete
    //
    KeSignalCallDpcDone(SystemArgument1);
}

/**
 * @brief Broadcast to disable mov-to-cr3 exitings
 * 关闭movetocr3中断
 * @param Dpc 
 * @param DeferredContext 
 * @param SystemArgument1 
 * @param SystemArgument2 
 * @return VOID 
 */
VOID
BroadcastDpcDisableMovToCr3Exiting(KDPC * Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    //
    // Disable mov-to-cr3 exiting from vmx-root
    //
    AsmVmxVmcall(VMCALL_DISABLE_MOV_TO_CR3_EXITING, 0, 0, 0);

    //
    // Wait for all DPCs to synchronize at this point
    //
    KeSignalCallDpcSynchronize(SystemArgument2);

    //
    // Mark the DPC as being complete
    //
    KeSignalCallDpcDone(SystemArgument1);
}

/**
 * @brief Disable Msr Bitmaps on all cores (vm-exit on all msrs)
 * 关闭读msr位图中断
 * @param Dpc 
 * @param DeferredContext 
 * @param SystemArgument1 
 * @param SystemArgument2 
 * @return VOID 
 */
VOID
BroadcastDpcChangeMsrBitmapReadOnAllCores(KDPC * Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    //
    // Disable msr bitmaps from vmx-root
    //
    AsmVmxVmcall(VMCALL_CHANGE_MSR_BITMAP_READ, DeferredContext, 0, 0);

    //
    // Wait for all DPCs to synchronize at this point
    //
    KeSignalCallDpcSynchronize(SystemArgument2);

    //
    // Mark the DPC as being complete
    //
    KeSignalCallDpcDone(SystemArgument1);
}

/**
 * @brief Reset Msr Bitmaps on all cores (vm-exit on all msrs)
 * 重置msr位图中断
 * @param Dpc 
 * @param DeferredContext 
 * @param SystemArgument1 
 * @param SystemArgument2 
 * @return VOID 
 */
VOID
BroadcastDpcResetMsrBitmapReadOnAllCores(KDPC * Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    //
    // Reset msr bitmaps from vmx-root
    //
    AsmVmxVmcall(VMCALL_RESET_MSR_BITMAP_READ, NULL, 0, 0);

    //
    // Wait for all DPCs to synchronize at this point
    //
    KeSignalCallDpcSynchronize(SystemArgument2);

    //
    // Mark the DPC as being complete
    //
    KeSignalCallDpcDone(SystemArgument1);
}

/**
 * @brief Disable Msr Bitmaps on all cores (vm-exit on all msrs)
 *	关闭msr位图写中断
 * @param Dpc 
 * @param DeferredContext Msr index to be masked on msr bitmap
 * @param SystemArgument1 
 * @param SystemArgument2 
 * @return VOID 
 */
VOID
BroadcastDpcChangeMsrBitmapWriteOnAllCores(KDPC * Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    //
    // Disable msr bitmaps from vmx-root
    //
    AsmVmxVmcall(VMCALL_CHANGE_MSR_BITMAP_WRITE, DeferredContext, 0, 0);

    //
    // Wait for all DPCs to synchronize at this point
    //
    KeSignalCallDpcSynchronize(SystemArgument2);

    //
    // Mark the DPC as being complete
    //
    KeSignalCallDpcDone(SystemArgument1);
}

/**
 * @brief Reset Msr Bitmaps on all cores (vm-exit on all msrs)
 * 重置msr位图写中断
 * @param Dpc 
 * @param DeferredContext 
 * @param SystemArgument1 
 * @param SystemArgument2 
 * @return VOID 
 */
VOID
BroadcastDpcResetMsrBitmapWriteOnAllCores(KDPC * Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    //
    // Reset msr bitmaps from vmx-root
    //
    AsmVmxVmcall(VMCALL_RESET_MSR_BITMAP_WRITE, NULL, 0, 0);

    //
    // Wait for all DPCs to synchronize at this point
    //
    KeSignalCallDpcSynchronize(SystemArgument2);

    //
    // Mark the DPC as being complete
    //
    KeSignalCallDpcDone(SystemArgument1);
}

/**
 * @brief Enables rdtsc/rdtscp exiting in primary cpu-based controls
 * 
 * @param Dpc 
 * @param DeferredContext 
 * @param SystemArgument1 
 * @param SystemArgument2 
 * @return VOID 
 */
VOID
BroadcastDpcEnableRdtscExitingAllCores(KDPC * Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    //
    // Enables rdtsc/rdtscp exiting in primary cpu-based controls
    //
    AsmVmxVmcall(VMCALL_SET_RDTSC_EXITING, 0, 0, 0);

    //
    // Wait for all DPCs to synchronize at this point
    //
    KeSignalCallDpcSynchronize(SystemArgument2);

    //
    // Mark the DPC as being complete
    //
    KeSignalCallDpcDone(SystemArgument1);
}

/**
 * @brief Disables rdtsc/rdtscp exiting in primary cpu-based controls
 * 
 * @param Dpc 
 * @param DeferredContext 
 * @param SystemArgument1 
 * @param SystemArgument2 
 * @return VOID 
 */
VOID
BroadcastDpcDisableRdtscExitingAllCores(KDPC * Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    //
    // Disables rdtsc/rdtscp exiting in primary cpu-based controls
    //
    AsmVmxVmcall(VMCALL_UNSET_RDTSC_EXITING, 0, 0, 0);

    //
    // Wait for all DPCs to synchronize at this point
    //
    KeSignalCallDpcSynchronize(SystemArgument2);

    //
    // Mark the DPC as being complete
    //
    KeSignalCallDpcDone(SystemArgument1);
}

/**
 * @brief Enables rdpmc exiting in primary cpu-based controls
 * 
 * @param Dpc 
 * @param DeferredContext 
 * @param SystemArgument1 
 * @param SystemArgument2 
 * @return VOID 
 */
VOID
BroadcastDpcEnableRdpmcExitingAllCores(KDPC * Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    //
    // Enables rdpmc exiting in primary cpu-based controls
    //
    AsmVmxVmcall(VMCALL_SET_RDPMC_EXITING, 0, 0, 0);

    //
    // Wait for all DPCs to synchronize at this point
    //
    KeSignalCallDpcSynchronize(SystemArgument2);

    //
    // Mark the DPC as being complete
    //
    KeSignalCallDpcDone(SystemArgument1);
}

/**
 * @brief Disable rdpmc exiting in primary cpu-based controls
 * 
 * @param Dpc 
 * @param DeferredContext 
 * @param SystemArgument1 
 * @param SystemArgument2 
 * @return VOID 
 */
VOID
BroadcastDpcDisableRdpmcExitingAllCores(KDPC * Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    //
    // Disable rdpmc exiting in primary cpu-based controls
    //
    AsmVmxVmcall(VMCALL_UNSET_RDPMC_EXITING, 0, 0, 0);

    //
    // Wait for all DPCs to synchronize at this point
    //
    KeSignalCallDpcSynchronize(SystemArgument2);

    //
    // Mark the DPC as being complete
    //
    KeSignalCallDpcDone(SystemArgument1);
}

/**
 * @brief Enable Exception Bitmaps on all cores
 * 启动指定idt中断
 * @param Dpc 
 * @param DeferredContext Exception index on IDT
 * @param SystemArgument1 
 * @param SystemArgument2 
 * @return VOID 
 */
VOID
BroadcastDpcSetExceptionBitmapOnAllCores(KDPC * Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    //
    // Enable Exception Bitmaps from vmx-root
    //
    AsmVmxVmcall(VMCALL_SET_EXCEPTION_BITMAP, DeferredContext, 0, 0);

    //
    // Wait for all DPCs to synchronize at this point
    //
    KeSignalCallDpcSynchronize(SystemArgument2);

    //
    // Mark the DPC as being complete
    //
    KeSignalCallDpcDone(SystemArgument1);
}

/**
 * @brief Reset Exception Bitmaps on all cores
 * 停止指定idt中断
 * @param Dpc 
 * @param DeferredContext Exception index on IDT
 * @param SystemArgument1 
 * @param SystemArgument2 
 * @return VOID 
 */
VOID
BroadcastDpcResetExceptionBitmapOnAllCores(KDPC * Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    //
    // Reset Exception Bitmaps from vmx-root
    //
    AsmVmxVmcall(VMCALL_RESET_EXCEPTION_BITMAP, DeferredContext, 0, 0);

    //
    // Wait for all DPCs to synchronize at this point
    //
    KeSignalCallDpcSynchronize(SystemArgument2);

    //
    // Mark the DPC as being complete
    //
    KeSignalCallDpcDone(SystemArgument1);
}

/**
 * @brief Enables mov debug registers exitings
 * 
 * @param Dpc 
 * @param DeferredContext 
 * @param SystemArgument1 
 * @param SystemArgument2 
 * @return VOID 
 */
VOID
BroadcastDpcEnableMovDebigRegisterExitingAllCores(KDPC * Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    //
    // Enables mov debug registers exitings in primary cpu-based controls
    //
    AsmVmxVmcall(VMCALL_ENABLE_MOV_TO_DEBUG_REGS_EXITING, 0, 0, 0);

    //
    // Wait for all DPCs to synchronize at this point
    //
    KeSignalCallDpcSynchronize(SystemArgument2);

    //
    // Mark the DPC as being complete
    //
    KeSignalCallDpcDone(SystemArgument1);
}

/**
 * @brief Disables mov debug registers exitings
 * 
 * @param Dpc 
 * @param DeferredContext 
 * @param SystemArgument1 
 * @param SystemArgument2 
 * @return VOID 
 */
VOID
BroadcastDpcDisableMovDebigRegisterExitingAllCores(KDPC * Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    //
    // Disable mov debug registers exitings in primary cpu-based controls
    //
    AsmVmxVmcall(VMCALL_DISABLE_MOV_TO_DEBUG_REGS_EXITING, 0, 0, 0);

    //
    // Wait for all DPCs to synchronize at this point
    //
    KeSignalCallDpcSynchronize(SystemArgument2);

    //
    // Mark the DPC as being complete
    //
    KeSignalCallDpcDone(SystemArgument1);
}

/**
 * @brief Enable vm-exit on all cores for external interrupts
 * 启动外部中断
 * @param Dpc 
 * @param DeferredContext 
 * @param SystemArgument1 
 * @param SystemArgument2 
 * @return VOID 
 */
VOID
BroadcastDpcSetEnableExternalInterruptExitingOnAllCores(KDPC * Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    //
    // Enable External Interrupts vm-exit from vmx-root
    //
    AsmVmxVmcall(VMCALL_ENABLE_EXTERNAL_INTERRUPT_EXITING, 0, 0, 0);

    //
    // Wait for all DPCs to synchronize at this point
    //
    KeSignalCallDpcSynchronize(SystemArgument2);

    //
    // Mark the DPC as being complete
    //
    KeSignalCallDpcDone(SystemArgument1);
}

/**
 * @brief Disable vm-exit on all cores for external interrupts
 * 关闭外部中断
 * @param Dpc 
 * @param DeferredContext 
 * @param SystemArgument1 
 * @param SystemArgument2 
 * @return VOID 
 */
VOID
BroadcastDpcSetDisableExternalInterruptExitingOnAllCores(KDPC * Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    //
    // Disable External Interrupts vm-exit from vmx-root
    //
    AsmVmxVmcall(VMCALL_DISABLE_EXTERNAL_INTERRUPT_EXITING, 0, 0, 0);

    //
    // Wait for all DPCs to synchronize at this point
    //
    KeSignalCallDpcSynchronize(SystemArgument2);

    //
    // Mark the DPC as being complete
    //
    KeSignalCallDpcDone(SystemArgument1);
}

/**
 * @brief Change I/O Bitmaps on all cores
 * 更改所有核心的IO位图
 * @param Dpc 
 * @param DeferredContext I/O Port index
 * @param SystemArgument1 
 * @param SystemArgument2 
 * @return VOID 
 */
VOID
BroadcastDpcChangeIoBitmapOnAllCores(KDPC * Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    //
    // Change I/O Bitmaps on all cores
    //
    AsmVmxVmcall(VMCALL_CHANGE_IO_BITMAP, DeferredContext, 0, 0);

    //
    // Wait for all DPCs to synchronize at this point
    //
    KeSignalCallDpcSynchronize(SystemArgument2);

    //
    // Mark the DPC as being complete
    //
    KeSignalCallDpcDone(SystemArgument1);
}

/**
 * @brief Reset I/O Bitmaps on all cores
 * 重置所有核心的IO位图
 * @param Dpc 
 * @param DeferredContext 
 * @param SystemArgument1 
 * @param SystemArgument2 
 * @return VOID 
 */
VOID
BroadcastDpcResetIoBitmapOnAllCores(KDPC * Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    //
    // Reset I/O Bitmaps on all cores
    //
    AsmVmxVmcall(VMCALL_RESET_IO_BITMAP, NULL, 0, 0);

    //
    // Wait for all DPCs to synchronize at this point
    //
    KeSignalCallDpcSynchronize(SystemArgument2);

    //
    // Mark the DPC as being complete
    //
    KeSignalCallDpcDone(SystemArgument1);
}

/**
 * @brief Enable breakpoint exiting on exception bitmaps on all cores
 * 在所有核心启动INT3中断
 * @param Dpc 
 * @param DeferredContext 
 * @param SystemArgument1 
 * @param SystemArgument2 
 * @return VOID 
 */
VOID
BroadcastDpcEnableBreakpointOnExceptionBitmapOnAllCores(KDPC * Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    //
    // Change exception bitmap
    //
    AsmVmxVmcall(VMCALL_ENABLE_BREAKPOINT_ON_EXCEPTION_BITMAP, NULL, 0, 0);

    //
    // Wait for all DPCs to synchronize at this point
    //
    KeSignalCallDpcSynchronize(SystemArgument2);

    //
    // Mark the DPC as being complete
    //
    KeSignalCallDpcDone(SystemArgument1);
}

/**
 * @brief Disable breakpoint exiting on exception bitmaps on all cores
 * 在所有核心上关闭INT3中断
 * @param Dpc 
 * @param DeferredContext 
 * @param SystemArgument1 
 * @param SystemArgument2 
 * @return VOID 
 */
VOID
BroadcastDpcDisableBreakpointOnExceptionBitmapOnAllCores(KDPC * Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
    //
    // Change exception bitmap
    //
    AsmVmxVmcall(VMCALL_DISABLE_BREAKPOINT_ON_EXCEPTION_BITMAP, NULL, 0, 0);

    //
    // Wait for all DPCs to synchronize at this point
    //
    KeSignalCallDpcSynchronize(SystemArgument2);

    //
    // Mark the DPC as being complete
    //
    KeSignalCallDpcDone(SystemArgument1);
}
