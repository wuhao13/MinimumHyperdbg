/**
 * @file EptHook.c
 * @author Sina Karvandi (sina@rayanfam.com)
 * @brief Implementation of different EPT hidden hooks functions
 * @details All the R/W hooks, Execute hooks and hardware register simulators
 * are implemented here
 *  
 * @version 0.1
 * @date 2020-04-11
 * 
 * @copyright This project is released under the GNU Public License v3.
 * 
 */
#include "pch.h"

/**
 * @brief Hook function that HooksExAllocatePoolWithTag
 * 
 * @param PoolType 
 * @param NumberOfBytes 
 * @param Tag 
 * @return PVOID 
 */
PVOID
ExAllocatePoolWithTagHook(
    POOL_TYPE PoolType,
    SIZE_T    NumberOfBytes,
    ULONG     Tag)
{
    LogInfo("ExAllocatePoolWithTag Called with : Tag = 0x%x , Number Of Bytes = %d , Pool Type = %d ", Tag, NumberOfBytes, PoolType);
    return ExAllocatePoolWithTagOrig(PoolType, NumberOfBytes, Tag);
}

/**
 * @brief Remove and Invalidate Hook in TLB (Hidden Detours and if counter of hidden breakpoint is zero)
 * @warning This function won't remove entries from LIST_ENTRY,
 *  just invalidate the paging, use EptHookUnHookSingleAddress instead
 * 
 * 
 * @param PhysicalAddress 
 * @return BOOLEAN Return false if there was an error or returns true if it was successfull
 */
BOOLEAN
EptHookRestoreSingleHookToOrginalEntry(SIZE_T PhysicalAddress)
{
    PLIST_ENTRY TempList = 0;

    //
    // Should be called from vmx-root, for calling from vmx non-root use the corresponding VMCALL
    //
    if (!g_GuestState[KeGetCurrentProcessorNumber()].IsOnVmxRootMode)
    {
        return FALSE;
    }

    TempList = &g_EptState->HookedPagesList;
    while (&g_EptState->HookedPagesList != TempList->Flink)
    {
        TempList                            = TempList->Flink;
        PEPT_HOOKED_PAGE_DETAIL HookedEntry = CONTAINING_RECORD(TempList, EPT_HOOKED_PAGE_DETAIL, PageHookList);
        if (HookedEntry->PhysicalBaseAddress == PAGE_ALIGN(PhysicalAddress))
        {
            //
            // Undo the hook on the EPT table
            // 使TLS缓存失效
            //
            EptSetPML1AndInvalidateTLB(HookedEntry->EntryAddress, HookedEntry->OriginalEntry, INVEPT_SINGLE_CONTEXT);

            return TRUE;
        }
    }
    //
    // Nothing found, probably the list is not found
    //
    return FALSE;
}

/**
 * @brief Remove and Invalidate Hook in TLB
 * @warning This function won't remove entries from LIST_ENTRY, just invalidate the paging, use EptHookUnHookAll instead
 * 
 * @return VOID 
 */
VOID
EptHookRestoreAllHooksToOrginalEntry()
{
    PLIST_ENTRY TempList = 0;

    //
    // Should be called from vmx-root, for calling from vmx non-root use the corresponding VMCALL
    //
    if (!g_GuestState[KeGetCurrentProcessorNumber()].IsOnVmxRootMode)
    {
        return FALSE;
    }

    TempList = &g_EptState->HookedPagesList;

    while (&g_EptState->HookedPagesList != TempList->Flink)
    {
        TempList                            = TempList->Flink;
        PEPT_HOOKED_PAGE_DETAIL HookedEntry = CONTAINING_RECORD(TempList, EPT_HOOKED_PAGE_DETAIL, PageHookList);

        //
        // Undo the hook on the EPT table
        //
        EptSetPML1AndInvalidateTLB(HookedEntry->EntryAddress, HookedEntry->OriginalEntry, INVEPT_SINGLE_CONTEXT);
    }
}

/**
 * @brief Write an absolute x64 jump to an arbitrary address to a buffer
 * 
 * @param TargetBuffer 
 * @param TargetAddress 
 * @return VOID 
 */
VOID
EptHookWriteAbsoluteJump(PCHAR TargetBuffer, SIZE_T TargetAddress)
{
    //
    // call $ + 5 ; A 64-bit call instruction is still 5 bytes wide!
    //
    TargetBuffer[0] = 0xe8;
    TargetBuffer[1] = 0x00;
    TargetBuffer[2] = 0x00;
    TargetBuffer[3] = 0x00;
    TargetBuffer[4] = 0x00;

    //
    // mov r11, Target
    //
    TargetBuffer[5] = 0x49;
    TargetBuffer[6] = 0xBB;

    //
    // Target
    //
    *((PSIZE_T)&TargetBuffer[7]) = TargetAddress;

    //
    // push r11
    //
    TargetBuffer[15] = 0x41;
    TargetBuffer[16] = 0x53;

    //
    // ret
    //
    TargetBuffer[17] = 0xC3;
}

/**
 * @brief Write an absolute x64 jump to an arbitrary address to a buffer
 * 
 * @param TargetBuffer 
 * @param TargetAddress 
 * @return VOID 
 */
VOID
EptHookWriteAbsoluteJump2(PCHAR TargetBuffer, SIZE_T TargetAddress)
{
    //
    // mov r11, Target
    //
    TargetBuffer[0] = 0x49;
    TargetBuffer[1] = 0xBB;

    //
    // Target
    //
    *((PSIZE_T)&TargetBuffer[2]) = TargetAddress;

    //
    // push r11
    //
    TargetBuffer[10] = 0x41;
    TargetBuffer[11] = 0x53;

    //
    // ret
    //
    TargetBuffer[12] = 0xC3;
}

/**
 * @brief Hook ins
 * 
 * @param Hook The details of hooked pages
 * @param ProcessCr3 The target Process CR3
 * @param TargetFunction Target function that needs to be hooked
 * @param TargetFunctionInSafeMemory Target content in the safe memory (used in Length Disassembler Engine)
 * @param HookFunction The function that will be called when hook triggered
 * @return BOOLEAN Returns true if the hook was successfull or returns false if it was not successfull
 */
BOOLEAN
EptHookInstructionMemory(PEPT_HOOKED_PAGE_DETAIL Hook, CR3_TYPE ProcessCr3, PVOID TargetFunction, PVOID TargetFunctionInSafeMemory, PVOID HookFunction)
{
    PHIDDEN_HOOKS_DETOUR_DETAILS DetourHookDetails;
    SIZE_T                       SizeOfHookedInstructions;
    SIZE_T                       OffsetIntoPage;
    CR3_TYPE                     Cr3OfCurrentProcess;

    OffsetIntoPage = ADDRMASK_EPT_PML1_OFFSET((SIZE_T)TargetFunction);
    LogInfo("OffsetIntoPage: 0x%llx", OffsetIntoPage);

    if ((OffsetIntoPage + 18) > PAGE_SIZE - 1)
    {
        LogError("Function extends past a page boundary. We just don't have the technology to solve this.....");
        return FALSE;
    }

    //
    // Determine the number of instructions necessary to overwrite using Length Disassembler Engine
    //
    for (SizeOfHookedInstructions = 0;
         SizeOfHookedInstructions < 13; //原始hook跳板长度为18，这里改为13
         SizeOfHookedInstructions += ldisasm(((UINT64)TargetFunctionInSafeMemory + SizeOfHookedInstructions), TRUE))
    {
        //
        // Get the full size of instructions necessary to copy
        //
    }
    LogInfo("Number of bytes of instruction mem: %d", SizeOfHookedInstructions);

    //
    // Build a trampoline
    //

    //
    // Allocate some executable memory for the trampoline
    //
    Hook->Trampoline = PoolManagerRequestPool(EXEC_TRAMPOLINE, TRUE, MAX_EXEC_TRAMPOLINE_SIZE);

    if (!Hook->Trampoline)
    {
        LogError("Could not allocate trampoline function buffer.");
        return FALSE;
    }

    //
    // Copy the trampoline instructions in
    //

    // Switch to target process
    //
    Cr3OfCurrentProcess = SwitchOnAnotherProcessMemoryLayoutByCr3(ProcessCr3);

    //
    // The following line can't be used in user mode addresses
    // 这里将原始代码保存到跳板内存中
    // RtlCopyMemory(Hook->Trampoline, TargetFunction, SizeOfHookedInstructions);
    //
    MemoryMapperReadMemorySafe(TargetFunction, Hook->Trampoline, SizeOfHookedInstructions);

    //
    // Restore to original process
    //
    RestoreToPreviousProcess(Cr3OfCurrentProcess);

    //
    // Add the absolute jump back to the original function
	// 在跳板内存尾部构造一个跳转，用于跳回原始代码
    //
    EptHookWriteAbsoluteJump2(&Hook->Trampoline[SizeOfHookedInstructions], (SIZE_T)TargetFunction + SizeOfHookedInstructions);

    LogInfo("Trampoline: 0x%llx", Hook->Trampoline);
    LogInfo("HookFunction: 0x%llx", HookFunction);

    //
    // Let the hook function call the original function
    //
    // *OrigFunction = Hook->Trampoline;
    //

    //
    // Create the structure to return for the debugger, we do it here because it's the first
    // function that changes the original function and if our structure is no ready after this
    // fucntion then we probably see BSOD on other cores
    // 
    // 从池里申请一块内存
    DetourHookDetails                        = PoolManagerRequestPool(DETOUR_HOOK_DETAILS, TRUE, sizeof(HIDDEN_HOOKS_DETOUR_DETAILS));
    DetourHookDetails->HookedFunctionAddress = TargetFunction;
    DetourHookDetails->ReturnAddress         = Hook->Trampoline;

    //
    // Save the address of DetourHookDetails because we want to
    // deallocate it when the hook is finished
    //
    Hook->AddressOfEptHook2sDetourListEntry = DetourHookDetails;

    //
    // Insert it to the list of hooked pages
    //

    InsertHeadList(&g_EptHook2sDetourListHead, &(DetourHookDetails->OtherHooksList));

    //
    // Write the absolute jump to our shadow page memory to jump to our hook
	// 最后在影子页写入跳转代码，实现hook
    // EptHookWriteAbsoluteJump有bug，会随机导致跳飞，已更换，应该问题不大
    EptHookWriteAbsoluteJump2(&Hook->FakePageContents[OffsetIntoPage], (SIZE_T)HookFunction);

    return TRUE;
}

/**
 * @brief The main function that performs EPT page hook with hidden detours and monitor
 * @details This function returns false in VMX Non-Root Mode if the VM is already initialized
 * This function have to be called through a VMCALL in VMX Root Mode
 * 
 * @param TargetAddress The address of function or memory address to be hooked
 * @param HookFunction The function that will be called when hook triggered
 * @param ProcessCr3 The process cr3 to translate based on that process's cr3
 * @param UnsetRead Hook READ Access
 * @param UnsetWrite Hook WRITE Access
 * @param UnsetExecute Hook EXECUTE Access
 * @return BOOLEAN Returns true if the hook was successfull or false if there was an error
 */
//root模式建立HOOK页
BOOLEAN
EptHookPerformPageHook2(PVOID TargetAddress, PVOID HookFunction, CR3_TYPE ProcessCr3, BOOLEAN UnsetRead, BOOLEAN UnsetWrite, BOOLEAN UnsetExecute)
{
    EPT_PML1_ENTRY          ChangedEntry;
    INVEPT_DESCRIPTOR       Descriptor;
    SIZE_T                  PhysicalBaseAddress;
    PVOID                   VirtualTarget;
    PVOID                   TargetBuffer;
    UINT64                  TargetAddressInSafeMemory;
    UINT64                  PageOffset;
    PEPT_PML1_ENTRY         TargetPage;
    PEPT_HOOKED_PAGE_DETAIL HookedPage;
    ULONG                   LogicalCoreIndex;
    CR3_TYPE                Cr3OfCurrentProcess;
    PLIST_ENTRY             TempList    = 0;
    PEPT_HOOKED_PAGE_DETAIL HookedEntry = NULL;

    //
    // Check whether we are in VMX Root Mode or Not
	// 获取当前CPU核心
    //
    LogicalCoreIndex = KeGetCurrentProcessorIndex();

	//当前核心不是根模式就退出
    if (g_GuestState[LogicalCoreIndex].IsOnVmxRootMode && !g_GuestState[LogicalCoreIndex].HasLaunched)
    {
        return FALSE;
    }

    //
    // 将页面从物理地址转换为虚拟地址，以便我们读取其内存。
    // 如果物理地址尚未映射到虚拟内存中，则此函数将返回NULL。
	// 计算虚拟地址的页地址
    //
    VirtualTarget = PAGE_ALIGN(TargetAddress);

    //
    // 在这里我们必须更改CR3，这是因为我们处于SYSTEM进程中，并且如果目标地址未映射到SYSTEM地址空间（例如另一个进程的用户模式地址）中，则转换无效
    //

    //
    // Find cr3 of target core
    // 根据CR3计算物理地址
    PhysicalBaseAddress = (SIZE_T)VirtualAddressToPhysicalAddressByProcessCr3(VirtualTarget, ProcessCr3);

    if (!PhysicalBaseAddress)
    {
        LogError("Target address could not be mapped to physical memory");
        return FALSE;
    }

    //
    // try to see if we can find the address
    //
	// 查找是否已经HOOK过了，如果hook过则放弃
    TempList = &g_EptState->HookedPagesList;

    while (&g_EptState->HookedPagesList != TempList->Flink)
    {
        TempList    = TempList->Flink;
        HookedEntry = CONTAINING_RECORD(TempList, EPT_HOOKED_PAGE_DETAIL, PageHookList);

        if (HookedEntry->PhysicalBaseAddress == PhysicalBaseAddress)
        {
            //
            // Means that we find the address and !epthook2 doesn't support
            // multiple breakpoints in on page
            //
            return FALSE;
        }
    }

    //
    // Set target buffer, request buffer from pool manager,
    // we also need to allocate new page to replace the current page ASAP
    //
	//从池里分配一个新页
    TargetBuffer = PoolManagerRequestPool(SPLIT_2MB_PAGING_TO_4KB_PAGE, TRUE, sizeof(VMM_EPT_DYNAMIC_SPLIT));

	//分配失败则放弃
    if (!TargetBuffer)
    {
        LogError("There is no pre-allocated buffer available");
        return FALSE;
    }

	//将2M页面拆分为4K
    if (!EptSplitLargePage(g_EptState->EptPageTable, TargetBuffer, PhysicalBaseAddress, LogicalCoreIndex))
    {
        LogError("Could not split page for the address : 0x%llx", PhysicalBaseAddress);
        return FALSE;
    }

    //
    // 指向页面表中页面条目的指针
    //
    TargetPage = EptGetPml1Entry(g_EptState->EptPageTable, PhysicalBaseAddress);

    //
    // 确保目标有效
    //
    if (!TargetPage)
    {
        LogError("Failed to get PML1 entry of the target address");
        return FALSE;
    }

    //
    // Save the original permissions of the page
    //
    ChangedEntry = *TargetPage;

    //
    // Execution is treated differently
	// 设置页权限
    //
    if (UnsetRead)
        ChangedEntry.ReadAccess = 0;
    else
        ChangedEntry.ReadAccess = 1;

    if (UnsetWrite)
        ChangedEntry.WriteAccess = 0;
    else
        ChangedEntry.WriteAccess = 1;

    //
    // Save the detail of hooked page to keep track of it
    //
	//从池中分配一个HOOK页
    HookedPage = PoolManagerRequestPool(TRACKING_HOOKED_PAGES, TRUE, sizeof(EPT_HOOKED_PAGE_DETAIL));

    if (!HookedPage)
    {
        LogError("There is no pre-allocated pool for saving hooked page details");
        return FALSE;
    }

    //
    // Save the virtual address
    //
    HookedPage->VirtualAddress = TargetAddress;

    //
    // Save the physical address
    //
    HookedPage->PhysicalBaseAddress = PhysicalBaseAddress;

    //
    // Fake page content physical address
    //
    HookedPage->PhysicalBaseAddressOfFakePageContents = (SIZE_T)VirtualAddressToPhysicalAddress(&HookedPage->FakePageContents[0]) / PAGE_SIZE;

    //
    // Save the entry address
    //
    HookedPage->EntryAddress = TargetPage;

    //
    // 保存原始条目
    //
    HookedPage->OriginalEntry = *TargetPage;

    //
    // If it's Execution hook then we have to set extra fields
    //
    if (UnsetExecute)
    {
        //
        // 显示条目具有隐藏的执行钩子
        //
        HookedPage->IsExecutionHook = TRUE;

        //
        // 在执行挂钩中，我们必须确保取消设置读写，因为在这种情况下会发生EPT冲突，因此我们可以交换原始页面
        //
        ChangedEntry.ReadAccess    = 0; //禁止读
        ChangedEntry.WriteAccess   = 0; //禁止写
        ChangedEntry.ExecuteAccess = 1; //允许执行

        //
        // Also set the current pfn to fake page
        //
        ChangedEntry.PageFrameNumber = HookedPage->PhysicalBaseAddressOfFakePageContents;

        //
        // 切换到目标进程
        //
        Cr3OfCurrentProcess = SwitchOnAnotherProcessMemoryLayoutByCr3(ProcessCr3);

        //
		//将内容复制到假页面
        //以下行不能在用户模式地址中使用
        // RtlCopyBytes(&HookedPage->FakePageContents, VirtualTarget, PAGE_SIZE);
        //
        MemoryMapperReadMemorySafe(VirtualTarget, &HookedPage->FakePageContents, PAGE_SIZE);

        //
        // 恢复到原始过程
        //
        RestoreToPreviousProcess(Cr3OfCurrentProcess);

        //
        // Compute new offset of target offset into a safe bufferr
        // It will be used to compute the length of the detours
        // address because we might have a user mode code
        //
        TargetAddressInSafeMemory = &HookedPage->FakePageContents;
        TargetAddressInSafeMemory = PAGE_ALIGN(TargetAddressInSafeMemory);
        PageOffset                = PAGE_OFFSET(TargetAddress);
        TargetAddressInSafeMemory = TargetAddressInSafeMemory + PageOffset;

        //
        // Create Hook
        //
        if (!EptHookInstructionMemory(HookedPage, ProcessCr3, TargetAddress, TargetAddressInSafeMemory, HookFunction))
        {
            LogError("Could not build the hook.");
            return FALSE;
        }
    }

    //
    // 保存修改后的条目
    //
    HookedPage->ChangedEntry = ChangedEntry;

    //
    // Add it to the list
	// 保存hook表
    //
    InsertHeadList(&g_EptState->HookedPagesList, &(HookedPage->PageHookList));

    //
    // 如果未启动，则无需在安全的环境中对其进行修改
    //
    if (!g_GuestState[LogicalCoreIndex].HasLaunched)
    {
        //
        // 将挂钩应用到EPT
        //
        TargetPage->Flags = ChangedEntry.Flags;
    }
    else
    {
        //
        // 将挂钩应用到EPT
        //
        EptSetPML1AndInvalidateTLB(TargetPage, ChangedEntry, INVEPT_SINGLE_CONTEXT);
    }

    return TRUE;
}

/**
 * @brief This function allocates a buffer in VMX Non Root Mode and then invokes a VMCALL to set the hook
 * @details this command uses hidden detours, this NOT be called from vmx-root mode
 *
 *
 * @param TargetAddress The address of function or memory address to be hooked
 * @param HookFunction The function that will be called when hook triggered
 * @param ProcessId The process id to translate based on that process's cr3
 * @param SetHookForRead Hook READ Access
 * @param SetHookForWrite Hook WRITE Access
 * @param SetHookForExec Hook EXECUTE Access
 * @return BOOLEAN Returns true if the hook was successfull or false if there was an error
 * 
 */
PVOID
EptHook2(PVOID TargetAddress, PVOID HookFunction, UINT32 ProcessId, BOOLEAN eSetHookForRead, BOOLEAN eSetHookForWrite, BOOLEAN eSetHookForExec)
{
    UINT32 PageHookMask = 0;
    ULONG  LogicalCoreIndex;

    //
    // Check for the features to avoid EPT Violation problems
	//检查避免EPT异常
    //

    if (eSetHookForExec && !g_ExecuteOnlySupport)
    {
        //
        // 在当前的hyperdbg设计中，我们使用仅执行页面为exec页面实现隐藏的钩子，因此您的处理器没有此功能，您必须以其他方式实现它：(
        //
        return NULL;
    }
	
    if (eSetHookForWrite && !eSetHookForRead)
    {
        //
        // The hidden hook with Write Enable and Read Disabled will cause EPT violation!
        //
        return NULL;
    }

    //
    // Check whether we are in VMX Root Mode or Not
	// 获取下当前CPU的ID
    //
    LogicalCoreIndex = KeGetCurrentProcessorIndex();

    if (eSetHookForRead)
    {
        PageHookMask |= PAGE_ATTRIB_READ;
    }
    if (eSetHookForWrite)
    {
        PageHookMask |= PAGE_ATTRIB_WRITE;
    }
    if (eSetHookForExec)
    {
        PageHookMask |= PAGE_ATTRIB_EXEC;
    }

    if (PageHookMask == 0)
    {
        //
        // nothing to hook
        //
        return NULL;
    }

	//当前CPU是否虚拟化状态
    if (g_GuestState[LogicalCoreIndex].HasLaunched)
	//虚拟化处理
    {
        //
        // Move Attribute Mask to the upper 32 bits of the VMCALL Number
		//设置标志位，使用vmcall在物理机下进行HOOK
        //
        UINT64 VmcallNumber = ((UINT64)PageHookMask << 32) | VMCALL_CHANGE_PAGE_ATTRIB;

        //使用VmCall在根模式设置钩子和EPT
        if (AsmVmxVmcall(VmcallNumber, TargetAddress, HookFunction, GetCr3FromProcessId(ProcessId).Flags) == STATUS_SUCCESS)
        {
            if (!g_GuestState[LogicalCoreIndex].IsOnVmxRootMode)
            {
                //
                // Now we have to notify all the core to invalidate their EPT
                // 通知所有EPT无效，让CPU刷新
                //
                HvNotifyAllToInvalidateEpt();
            }
            else
            {
                LogError("Unable to notify all cores to invalidate their TLB caches as you called hook on vmx-root mode.");
            }

			//hook完毕后返回指针
            return EptHookResultTrampoline(TargetAddress);
        }
    }
    else
	//非虚拟化状态,此处由Vmcall执行到
    {
		 LogInfo("[*]VM has not launched call EptHookPerformPageHook2");
    }
    LogWarning("Hook not applied");

    return NULL;
}

/**
 * @brief Handles page hooks
 * 
 * @param Regs Guest registers
 * @param HookedEntryDetails The entry that describes the hooked page
 * @param ViolationQualification The exit qualification of vm-exit
 * @param PhysicalAddress The physical address that cause this vm-exit
 * @return BOOLEAN Returns TRUE if the function was hook was handled or returns false 
 * if there was an unexpected ept violation
 */
BOOLEAN
EptHookHandleHookedPage(PGUEST_REGS Regs, EPT_HOOKED_PAGE_DETAIL * HookedEntryDetails, VMX_EXIT_QUALIFICATION_EPT_VIOLATION ViolationQualification, SIZE_T PhysicalAddress)
{
	ULONG64 GuestRip;
	ULONG64 ExactAccessedAddress;
	ULONG64 AlignedVirtualAddress;
	ULONG64 AlignedPhysicalAddress;

	//
	// 对齐
	//
	AlignedVirtualAddress = PAGE_ALIGN(HookedEntryDetails->VirtualAddress);
	AlignedPhysicalAddress = PAGE_ALIGN(PhysicalAddress);

	//
	// 让我们阅读访问的确切地址
	//
	ExactAccessedAddress = AlignedVirtualAddress + PhysicalAddress - AlignedPhysicalAddress;

	//
	// 阅读Guest的RIP
	//
	__vmx_vmread(GUEST_RIP, &GuestRip);

	if (!ViolationQualification.EptExecutable && ViolationQualification.ExecuteAccess)
	{
		//
		// Generally, we should never reach here, we didn't implement HyperDbg like this ;)
		//
		LogError("Guest RIP : 0x%llx tries to execute the page at : 0x%llx", GuestRip, ExactAccessedAddress);
	}
	else if (!ViolationQualification.EptWriteable && ViolationQualification.WriteAccess)
	{
		//
		// Test
		//

		//
		// LogInfo("Guest RIP : 0x%llx tries to write on the page at :0x%llx", GuestRip, ExactAccessedAddress);
		//

	}
	else if (!ViolationQualification.EptReadable && ViolationQualification.ReadAccess)
	{
		//
		// Test
		//

		//
		// LogInfo("Guest RIP : 0x%llx tries to read the page at :0x%llx", GuestRip, ExactAccessedAddress);
		//
	}
	else
	{
		//
		// 发生意外的ept违规
		//
		return FALSE;
	}

	//
	// 恢复一条指令的原始条目
	//
	EptSetPML1AndInvalidateTLB(HookedEntryDetails->EntryAddress, HookedEntryDetails->OriginalEntry, INVEPT_SINGLE_CONTEXT);

	//
	// 意味着在来宾中执行当前指令后，将Entry恢复到以前的状态
	//
	return TRUE;
}


/**
 * @brief Remove the enrty from g_EptHook2sDetourListHead in the case
 * of !epthook2 details
 * @param Address Address to remove
 * @return BOOLEAN TRUE if successfully removed and false if not found 
 */
BOOLEAN
EptHookRemoveEntryAndFreePoolFromEptHook2sDetourList(UINT64 Address)
{
    PLIST_ENTRY TempList = 0;

    //
    // Iterate through the list of hooked pages details to find
    // the entry in the list
    //
    TempList = &g_EptHook2sDetourListHead;

    while (&g_EptHook2sDetourListHead != TempList->Flink)
    {
        TempList                                          = TempList->Flink;
        PHIDDEN_HOOKS_DETOUR_DETAILS CurrentHookedDetails = CONTAINING_RECORD(TempList, HIDDEN_HOOKS_DETOUR_DETAILS, OtherHooksList);

        if (CurrentHookedDetails->HookedFunctionAddress == Address)
        {
            //
            // We found the address, we should remove it and add it for
            // future deallocation
            //
            RemoveEntryList(&CurrentHookedDetails->OtherHooksList);

            //
            // Free the pool in next ioctl
            //
            if (!PoolManagerFreePool(CurrentHookedDetails))
            {
                LogError("Something goes wrong ! the pool not found in the list of previously allocated pools by pool manager.");
            }
            return TRUE;
        }
    }
    //
    // No entry found !
    //
    return FALSE;
}

/**
 * @brief Remove single hook from the hooked pages list and invalidate TLB
 * @details Should be called from vmx non-root
 * 
 * @param VirtualAddress Virtual address to unhook
 * @param ProcessId The process id of target process
 * @return BOOLEAN If unhook was successful it returns true or if it was not successful returns false
 */
BOOLEAN
EptHookUnHookSingleAddress(UINT64 VirtualAddress, UINT32 ProcessId)
{
    SIZE_T      PhysicalAddress;
    UINT64      TargetAddressInFakePageContent;
    UINT64      PageOffset;
    PLIST_ENTRY TempList                   = 0;
    BOOLEAN     FoundHiddenBreakpointEntry = FALSE;

	//DbgBreakPoint();
	//判断下进程ID是0或者fff，如果是则获取当前进程
    if (ProcessId == DEBUGGER_EVENT_APPLY_TO_ALL_PROCESSES || ProcessId == 0)
    {
        ProcessId = PsGetCurrentProcessId();
    }

	//计算物理地址
    PhysicalAddress = PAGE_ALIGN(VirtualAddressToPhysicalAddressByProcessId(VirtualAddress, ProcessId));

    //
    // Should be called from vmx non-root
    //
    if (g_GuestState[KeGetCurrentProcessorNumber()].IsOnVmxRootMode)
    {
        return FALSE;
    }

	
	//搜索链表
    TempList = &g_EptState->HookedPagesList;

    while (&g_EptState->HookedPagesList != TempList->Flink)
    {
        TempList                            = TempList->Flink;
        PEPT_HOOKED_PAGE_DETAIL HookedEntry = CONTAINING_RECORD(TempList, EPT_HOOKED_PAGE_DETAIL, PageHookList);	
        //
        // It's a hidden detours
        //
		// 简单的很
        if (HookedEntry->PhysicalBaseAddress == PhysicalAddress)
        {
            //
            // Remove it in all the cores
            //
            KeGenericCallDpc(HvDpcBroadcastRemoveHookAndInvalidateSingleEntry, HookedEntry->PhysicalBaseAddress);

            //
            // Now that we removed this hidden detours hook, it is
            // time to remove it from g_EptHook2sDetourListHead
            //
            EptHookRemoveEntryAndFreePoolFromEptHook2sDetourList(HookedEntry->VirtualAddress);

            //
            // remove the entry from the list
            //
			if (!RemoveEntryList(HookedEntry->PageHookList.Flink))
			{
				LogError("RemoveEntryList Error.");
			}
            //
            // we add the hooked entry to the list
            // of pools that will be deallocated on next IOCTL
            //
            if (!PoolManagerFreePool(HookedEntry))
            {
                LogError("Something goes wrong ! the pool not found in the list of previously allocated pools by pool manager.");
            }

            return TRUE;
        }
    }
    //
    // Nothing found , probably the list is not found
    //
    return FALSE;
}

/**
 * @brief Remove all hooks from the hooked pages list and invalidate TLB
 * @detailsShould be called from Vmx Non-root
 * 
 * @return VOID 
 */
// 循环移除HOOK, 有BUG，会导致卸载异常！
// 最好手工移除所有钩子

VOID
EptHookUnHookAll()
{
    PLIST_ENTRY TempList = 0;

    //
    // Should be called from vmx non-root
    //


    if (g_GuestState[KeGetCurrentProcessorNumber()].IsOnVmxRootMode)
    {
        return;
    }

    //
    // Remove it in all the cores
    //
    KeGenericCallDpc(HvDpcBroadcastRemoveHookAndInvalidateAllEntries, 0x0);

    //
    // In the case of unhooking all pages, we remove the hooked
    // from EPT table in vmx-root and at last, we need to deallocate
    // it from the buffers
    //

    TempList = &g_EptState->HookedPagesList;

    while (&g_EptState->HookedPagesList != TempList->Flink)
    {
        TempList                            = TempList->Flink;
        PEPT_HOOKED_PAGE_DETAIL HookedEntry = CONTAINING_RECORD(TempList, EPT_HOOKED_PAGE_DETAIL, PageHookList);

        //
        // Now that we removed this hidden detours hook, it is
        // time to remove it from g_EptHook2sDetourListHead
        // if the hook is detours
        //
		KeGenericCallDpc(HvDpcBroadcastRemoveHookAndInvalidateSingleEntry, HookedEntry->PhysicalBaseAddress);
		// 从链表中移除hook页
		if (!RemoveEntryList(TempList))
		{

		}
			LogWarning("Remove Hook Success");

        if (!PoolManagerFreePool(HookedEntry))
        {
            LogError("Something goes wrong ! the pool not found in the list of previously allocated pools by pool manager.");
        }
    }
}

PVOID EptHookResultTrampoline(UINT64 VirtualAddress)
{
	PLIST_ENTRY TempList = &g_EptState->HookedPagesList;
	while (&g_EptState->HookedPagesList != TempList->Flink)
	{
		TempList = TempList->Flink;
		PEPT_HOOKED_PAGE_DETAIL HookedEntry = CONTAINING_RECORD(TempList, EPT_HOOKED_PAGE_DETAIL, PageHookList);

		//该节点是epthook节点
		if (HookedEntry->IsExecutionHook)
		{
			if (HookedEntry->VirtualAddress == VirtualAddress)
			{
				return (HookedEntry->Trampoline);
			}
		}
	}
	return NULL;
}
