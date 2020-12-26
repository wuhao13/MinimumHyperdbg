/**
 * @file Ept.c
 * @author Sina Karvandi (sina@rayanfam.com)
 * @brief The implementation of functions relating to the Extended Page Table (a.k.a. EPT)
 * @details
 * @version 0.1
 * @date 2020-04-10
 * 
 * @copyright This project is released under the GNU Public License v3.
 * 
 */
#include "pch.h"

/**
 * @brief Check whether EPT features are present or not
 * 检查EPT功能是否存在
 * @return BOOLEAN Shows whether EPT is supported in this machine or not
 */
BOOLEAN
EptCheckFeatures()
{
    IA32_VMX_EPT_VPID_CAP_REGISTER VpidRegister;
    IA32_MTRR_DEF_TYPE_REGISTER    MTRRDefType;

    VpidRegister.Flags = __readmsr(MSR_IA32_VMX_EPT_VPID_CAP);
    MTRRDefType.Flags  = __readmsr(MSR_IA32_MTRR_DEF_TYPE);

    if (!VpidRegister.PageWalkLength4 || !VpidRegister.MemoryTypeWriteBack || !VpidRegister.Pde2MbPages)
    {
        return FALSE;
    }

    if (!VpidRegister.AdvancedVmexitEptViolationsInformation)
    {
        LogWarning("The processor doesn't report advanced VM-exit information for EPT violations");
    }

    if (!VpidRegister.ExecuteOnlyPages)
    {
        g_ExecuteOnlySupport = FALSE;
        LogWarning("The processor doesn't support execute-only pages, execute hooks won't work as they're on this feature in our design");
    }
    else
    {
        g_ExecuteOnlySupport = TRUE;
    }

    if (!MTRRDefType.MtrrEnable)
    {
        LogError("Mtrr Dynamic Ranges not supported");
        return FALSE;
    }

    LogInfo(" *** All EPT features are present *** ");

    return TRUE;
}

/**
 * @brief Build MTRR Map of current physical addresses
 * 建立当前物理地址的MTRR映射
 * @return BOOLEAN 
 */
BOOLEAN
EptBuildMtrrMap()
{
    IA32_MTRR_CAPABILITIES_REGISTER MTRRCap;
    IA32_MTRR_PHYSBASE_REGISTER     CurrentPhysBase;
    IA32_MTRR_PHYSMASK_REGISTER     CurrentPhysMask;
    PMTRR_RANGE_DESCRIPTOR          Descriptor;
    ULONG                           CurrentRegister;
    ULONG                           NumberOfBitsInMask;

    MTRRCap.Flags = __readmsr(MSR_IA32_MTRR_CAPABILITIES);

    for (CurrentRegister = 0; CurrentRegister < MTRRCap.VariableRangeCount; CurrentRegister++)
    {
        //
        // For each dynamic register pair
        //
        CurrentPhysBase.Flags = __readmsr(MSR_IA32_MTRR_PHYSBASE0 + (CurrentRegister * 2));
        CurrentPhysMask.Flags = __readmsr(MSR_IA32_MTRR_PHYSMASK0 + (CurrentRegister * 2));

        //
        // Is the range enabled?
        //
        if (CurrentPhysMask.Valid)
        {
            //
            // We only need to read these once because the ISA dictates that MTRRs are
            // to be synchronized between all processors during BIOS initialization.
            //
            Descriptor = &g_EptState->MemoryRanges[g_EptState->NumberOfEnabledMemoryRanges++];

            //
            // Calculate the base address in bytes
            //
            Descriptor->PhysicalBaseAddress = CurrentPhysBase.PageFrameNumber * PAGE_SIZE;

            //
            // Calculate the total size of the range
            // The lowest bit of the mask that is set to 1 specifies the size of the range
            //
            _BitScanForward64(&NumberOfBitsInMask, CurrentPhysMask.PageFrameNumber * PAGE_SIZE);

            //
            // Size of the range in bytes + Base Address
            //
            Descriptor->PhysicalEndAddress = Descriptor->PhysicalBaseAddress + ((1ULL << NumberOfBitsInMask) - 1ULL);

            //
            // Memory Type (cacheability attributes)
            //
            Descriptor->MemoryType = (UCHAR)CurrentPhysBase.Type;

            if (Descriptor->MemoryType == MEMORY_TYPE_WRITE_BACK)
            {
                //
                // This is already our default, so no need to store this range.
                // Simply 'free' the range we just wrote.
                //
                g_EptState->NumberOfEnabledMemoryRanges--;
            }
            LogInfo("MTRR Range: Base=0x%llx End=0x%llx Type=0x%x", Descriptor->PhysicalBaseAddress, Descriptor->PhysicalEndAddress, Descriptor->MemoryType);
        }
    }

    LogInfo("Total MTRR Ranges Committed: %d", g_EptState->NumberOfEnabledMemoryRanges);

    return TRUE;
}

/**
 * @brief Get the PML1 entry for this physical address if the page is split
 * 如果页面已拆分，则获取此物理地址的PML1条目
 * @param EptPageTable The EPT Page Table
 * @param PhysicalAddress Physical address that we want to get its PML1
 * @return PEPT_PML1_ENTRY Return NULL if the address is invalid or the page wasn't already split
 */
PEPT_PML1_ENTRY
EptGetPml1Entry(PVMM_EPT_PAGE_TABLE EptPageTable, SIZE_T PhysicalAddress)
{
    SIZE_T            Directory, DirectoryPointer, PML4Entry;
    PEPT_PML2_ENTRY   PML2;
    PEPT_PML1_ENTRY   PML1;
    PEPT_PML2_POINTER PML2Pointer;

    Directory        = ADDRMASK_EPT_PML2_INDEX(PhysicalAddress);
    DirectoryPointer = ADDRMASK_EPT_PML3_INDEX(PhysicalAddress);
    PML4Entry        = ADDRMASK_EPT_PML4_INDEX(PhysicalAddress);

    //
    // 大于512GB的地址无效，因为它>物理地址总线宽度
    //
    if (PML4Entry > 0)
    {
        return NULL;
    }

    PML2 = &EptPageTable->PML2[DirectoryPointer][Directory];

    //
    // 检查以确保页面已拆分
    //
    if (PML2->LargePage)
    {
        return NULL;
    }

    //
    // 进行转换以获得正确的页面框架编号。
    // 这些指针在表中占据相同位置，并且可以直接转换。
    //
    PML2Pointer = (PEPT_PML2_POINTER)PML2;

    //
    // 如果是，则转换为PML1指针
    //
    PML1 = (PEPT_PML1_ENTRY)PhysicalAddressToVirtualAddress((PVOID)(PML2Pointer->PageFrameNumber * PAGE_SIZE));

    if (!PML1)
    {
        return NULL;
    }

    //
    // 该地址的PML1索引
    //
    PML1 = &PML1[ADDRMASK_EPT_PML1_INDEX(PhysicalAddress)];

    return PML1;
}

/**
 * @brief Get the PML2 entry for this physical address
 * 获取此物理地址的PML2条目
 * @param EptPageTable The EPT Page Table
 * @param PhysicalAddress Physical Address that we want to get its PML2
 * @return PEPT_PML2_ENTRY The PML2 Entry Structure
 */
PEPT_PML2_ENTRY
EptGetPml2Entry(PVMM_EPT_PAGE_TABLE EptPageTable, SIZE_T PhysicalAddress)
{
    SIZE_T          Directory, DirectoryPointer, PML4Entry;
    PEPT_PML2_ENTRY PML2;

    Directory        = ADDRMASK_EPT_PML2_INDEX(PhysicalAddress);
    DirectoryPointer = ADDRMASK_EPT_PML3_INDEX(PhysicalAddress);
    PML4Entry        = ADDRMASK_EPT_PML4_INDEX(PhysicalAddress);

    //
    // Addresses above 512GB are invalid because it is > physical address bus width
    //
    if (PML4Entry > 0)
    {
        return NULL;
    }

    PML2 = &EptPageTable->PML2[DirectoryPointer][Directory];
    return PML2;
}

/**
 * @brief 将2MB（大页面）拆分为4kb页面
 * 将2MB（大页面）拆分为4kb页面
 * @param EptPageTable The EPT Page Table
 * @param PreAllocatedBuffer The address of pre-allocated buffer
 * @param PhysicalAddress Physical address of where we want to split
 * @param CoreIndex The index of core
 * @return BOOLEAN Returns true if it was successfull or false if there was an error
 */
BOOLEAN
EptSplitLargePage(PVMM_EPT_PAGE_TABLE EptPageTable, PVOID PreAllocatedBuffer, SIZE_T PhysicalAddress, ULONG CoreIndex)
{
    PVMM_EPT_DYNAMIC_SPLIT NewSplit;
    EPT_PML1_ENTRY         EntryTemplate;
    SIZE_T                 EntryIndex;
    PEPT_PML2_ENTRY        TargetEntry;
    EPT_PML2_POINTER       NewPointer;

    //
    // Find the PML2 entry that's currently used
    //
    TargetEntry = EptGetPml2Entry(EptPageTable, PhysicalAddress);
    if (!TargetEntry)
    {
        LogError("An invalid physical address passed");
        return FALSE;
    }

    //
    // If this large page is not marked a large page, that means it's a pointer already.
    // That page is therefore already split.
    //
    if (!TargetEntry->LargePage)
    {
        return TRUE;
    }

    //
    // Allocate the PML1 entries
    //
    NewSplit = (PVMM_EPT_DYNAMIC_SPLIT)PreAllocatedBuffer;
    if (!NewSplit)
    {
        LogError("Failed to allocate dynamic split memory");
        return FALSE;
    }
    RtlZeroMemory(NewSplit, sizeof(VMM_EPT_DYNAMIC_SPLIT));

    //
    // Point back to the entry in the dynamic split for easy reference for which entry that
    // dynamic split is for
    //
    NewSplit->Entry = TargetEntry;

    //
    // Make a template for RWX
    //
    EntryTemplate.Flags         = 0;
    EntryTemplate.ReadAccess    = 1;
    EntryTemplate.WriteAccess   = 1;
    EntryTemplate.ExecuteAccess = 1;

    //
    // Copy the template into all the PML1 entries
    //
    __stosq((SIZE_T *)&NewSplit->PML1[0], EntryTemplate.Flags, VMM_EPT_PML1E_COUNT);

    //
    // Set the page frame numbers for identity mapping
    //
    for (EntryIndex = 0; EntryIndex < VMM_EPT_PML1E_COUNT; EntryIndex++)
    {
        //
        // Convert the 2MB page frame number to the 4096 page entry number plus the offset into the frame
        //
        NewSplit->PML1[EntryIndex].PageFrameNumber = ((TargetEntry->PageFrameNumber * SIZE_2_MB) / PAGE_SIZE) + EntryIndex;
    }

    //
    // Allocate a new pointer which will replace the 2MB entry with a pointer to 512 4096 byte entries
    //
    NewPointer.Flags           = 0;
    NewPointer.WriteAccess     = 1;
    NewPointer.ReadAccess      = 1;
    NewPointer.ExecuteAccess   = 1;
    NewPointer.PageFrameNumber = (SIZE_T)VirtualAddressToPhysicalAddress(&NewSplit->PML1[0]) / PAGE_SIZE;

    //
    // Now, replace the entry in the page table with our new split pointer
    //
    RtlCopyMemory(TargetEntry, &NewPointer, sizeof(NewPointer));

    return TRUE;
}

/**
 * @brief Set up PML2 Entries
 * 设置PML2条目
 * @param NewEntry The PML2 Entry
 * @param PageFrameNumber PFN (Physical Address)
 * @return VOID 
 */
VOID
EptSetupPML2Entry(PEPT_PML2_ENTRY NewEntry, SIZE_T PageFrameNumber)
{
    SIZE_T AddressOfPage;
    SIZE_T CurrentMtrrRange;
    SIZE_T TargetMemoryType;

    //
    // Each of the 512 collections of 512 PML2 entries is setup here
    // This will, in total, identity map every physical address from 0x0
    // to physical address 0x8000000000 (512GB of memory)
    // ((EntryGroupIndex * VMM_EPT_PML2E_COUNT) + EntryIndex) * 2MB is
    // the actual physical address we're mapping
    //
    NewEntry->PageFrameNumber = PageFrameNumber;

    //
    // Size of 2MB page * PageFrameNumber == AddressOfPage (physical memory)
    //
    AddressOfPage = PageFrameNumber * SIZE_2_MB;

    //
    // To be safe, we will map the first page as UC as to not bring up any
    // kind of undefined behavior from the fixed MTRR section which we are
    // not formally recognizing (typically there is MMIO memory in the first MB)
    //
    // I suggest reading up on the fixed MTRR section of the manual to see why the
    // first entry is likely going to need to be UC.
    //
    if (PageFrameNumber == 0)
    {
        NewEntry->MemoryType = MEMORY_TYPE_UNCACHEABLE;
        return;
    }

    //
    // Default memory type is always WB for performance
    //
    TargetMemoryType = MEMORY_TYPE_WRITE_BACK;

    //
    // For each MTRR range
    //
    for (CurrentMtrrRange = 0; CurrentMtrrRange < g_EptState->NumberOfEnabledMemoryRanges; CurrentMtrrRange++)
    {
        //
        // If this page's address is below or equal to the max physical address of the range
        //
        if (AddressOfPage <= g_EptState->MemoryRanges[CurrentMtrrRange].PhysicalEndAddress)
        {
            //
            // And this page's last address is above or equal to the base physical address of the range
            //
            if ((AddressOfPage + SIZE_2_MB - 1) >= g_EptState->MemoryRanges[CurrentMtrrRange].PhysicalBaseAddress)
            {
                //
                // If we're here, this page fell within one of the ranges specified by the variable MTRRs
                // Therefore, we must mark this page as the same cache type exposed by the MTRR
                //
                TargetMemoryType = g_EptState->MemoryRanges[CurrentMtrrRange].MemoryType;

                // LogInfo("0x%X> Range=%llX -> %llX | Begin=%llX End=%llX", PageFrameNumber, AddressOfPage, AddressOfPage + SIZE_2_MB - 1, EptState->MemoryRanges[CurrentMtrrRange].PhysicalBaseAddress, EptState->MemoryRanges[CurrentMtrrRange].PhysicalEndAddress);

                //
                // 11.11.4.1 MTRR Precedences
                //
                if (TargetMemoryType == MEMORY_TYPE_UNCACHEABLE)
                {
                    //
                    // If this is going to be marked uncacheable, then we stop the search as UC always takes precedent
                    //
                    break;
                }
            }
        }
    }
    //
    // Finally, commit the memory type to the entry
    //
    NewEntry->MemoryType = TargetMemoryType;
}

/**
 * @brief Allocates page maps and create identity page table
 * 分配页面映射并创建身份页面表
 * @return PVMM_EPT_PAGE_TABLE identity map page-table
 */
PVMM_EPT_PAGE_TABLE
EptAllocateAndCreateIdentityPageTable()
{
    PVMM_EPT_PAGE_TABLE PageTable;
    EPT_PML3_POINTER    RWXTemplate;
    EPT_PML2_ENTRY      PML2EntryTemplate;
    SIZE_T              EntryGroupIndex;
    SIZE_T              EntryIndex;

    //
    // 将所有分页结构分配为4KB对齐的页面
    //
    PHYSICAL_ADDRESS MaxSize;
    PVOID            Output;

    //
    // 在OS内存空间中的任意位置分配地址
    //
    MaxSize.QuadPart = MAXULONG64;

    PageTable = MmAllocateContiguousMemory((sizeof(VMM_EPT_PAGE_TABLE) / PAGE_SIZE) * PAGE_SIZE, MaxSize);

    if (PageTable == NULL)
    {
        LogError("Failed to allocate memory for PageTable");
        return NULL;
    }

    //
    // Zero out all entries to ensure all unused entries are marked Not Present
    //
    RtlZeroMemory(PageTable, sizeof(VMM_EPT_PAGE_TABLE));

    //
    // Mark the first 512GB PML4 entry as present, which allows us to manage up
    // to 512GB of discrete paging structures.
    //
    PageTable->PML4[0].PageFrameNumber = (SIZE_T)VirtualAddressToPhysicalAddress(&PageTable->PML3[0]) / PAGE_SIZE;
    PageTable->PML4[0].ReadAccess      = 1;
    PageTable->PML4[0].WriteAccess     = 1;
    PageTable->PML4[0].ExecuteAccess   = 1;

    //
    // Now mark each 1GB PML3 entry as RWX and map each to their PML2 entry
    //

    //
    // Ensure stack memory is cleared
    //
    RWXTemplate.Flags = 0;

    //
    // Set up one 'template' RWX PML3 entry and copy it into each of the 512 PML3 entries
    // Using the same method as SimpleVisor for copying each entry using intrinsics.
    //
    RWXTemplate.ReadAccess    = 1;
    RWXTemplate.WriteAccess   = 1;
    RWXTemplate.ExecuteAccess = 1;

    //
    // Copy the template into each of the 512 PML3 entry slots
    //
    __stosq((SIZE_T *)&PageTable->PML3[0], RWXTemplate.Flags, VMM_EPT_PML3E_COUNT);

    //
    // For each of the 512 PML3 entries
    //
    for (EntryIndex = 0; EntryIndex < VMM_EPT_PML3E_COUNT; EntryIndex++)
    {
        //
        // Map the 1GB PML3 entry to 512 PML2 (2MB) entries to describe each large page.
        // NOTE: We do *not* manage any PML1 (4096 byte) entries and do not allocate them.
        //
        PageTable->PML3[EntryIndex].PageFrameNumber = (SIZE_T)VirtualAddressToPhysicalAddress(&PageTable->PML2[EntryIndex][0]) / PAGE_SIZE;
    }

    PML2EntryTemplate.Flags = 0;

    //
    // All PML2 entries will be RWX and 'present'
    //
    PML2EntryTemplate.WriteAccess   = 1;
    PML2EntryTemplate.ReadAccess    = 1;
    PML2EntryTemplate.ExecuteAccess = 1;

    //
    // We are using 2MB large pages, so we must mark this 1 here
    //
    PML2EntryTemplate.LargePage = 1;

    //
    // For each collection of 512 PML2 entries (512 collections * 512 entries per collection),
    // mark it RWX using the same template above.
    // This marks the entries as "Present" regardless of if the actual system has memory at
    // this region or not. We will cause a fault in our EPT handler if the guest access a page
    // outside a usable range, despite the EPT frame being present here.
    //
    __stosq((SIZE_T *)&PageTable->PML2[0], PML2EntryTemplate.Flags, VMM_EPT_PML3E_COUNT * VMM_EPT_PML2E_COUNT);

    //
    // For each of the 512 collections of 512 2MB PML2 entries
    //
    for (EntryGroupIndex = 0; EntryGroupIndex < VMM_EPT_PML3E_COUNT; EntryGroupIndex++)
    {
        //
        // For each 2MB PML2 entry in the collection
        //
        for (EntryIndex = 0; EntryIndex < VMM_EPT_PML2E_COUNT; EntryIndex++)
        {
            //
            // Setup the memory type and frame number of the PML2 entry
            //
            EptSetupPML2Entry(&PageTable->PML2[EntryGroupIndex][EntryIndex], (EntryGroupIndex * VMM_EPT_PML2E_COUNT) + EntryIndex);
        }
    }

    return PageTable;
}

/**
 * @brief Initialize EPT for an individual logical processor
 * 为单个逻辑处理器初始化EPT
 * @details Creates an identity mapped page table and sets up an EPTP to be applied to the VMCS later
 * 
 * @return BOOLEAN 
 */
BOOLEAN
EptLogicalProcessorInitialize()
{
    PVMM_EPT_PAGE_TABLE PageTable;
    EPTP                EPTP = {0};

    //
    // Allocate the identity mapped page table
    //
    PageTable = EptAllocateAndCreateIdentityPageTable();
    if (!PageTable)
    {
        LogError("Unable to allocate memory for EPT");
        return FALSE;
    }

    //
    // Virtual address to the page table to keep track of it for later freeing
    //
    g_EptState->EptPageTable = PageTable;

    //
    // 为了提高性能，我们让处理器知道它可以缓存EPT
    //
    EPTP.MemoryType = MEMORY_TYPE_WRITE_BACK;

    //
    // 我们没有利用“访问”和“脏”标志功能
    //
    EPTP.EnableAccessAndDirtyFlags = FALSE;

    //
    // Bits 5:3 (1 less than the EPT page-walk length) must be 3, indicating an EPT page-walk length of 4;
    // see Section 28.2.2
    //
    EPTP.PageWalkLength = 3;

    //
    // 我们将使用的页表的物理页号
    //
    EPTP.PageFrameNumber = (SIZE_T)VirtualAddressToPhysicalAddress(&PageTable->PML4) / PAGE_SIZE;

    //
    // 稍后我们将把EPTP写入VMCS
    //
    g_EptState->EptPointer = EPTP;

    return TRUE;
}

/**
 * @brief Initialize Secondary EPT for an individual logical processor
 * 初始化单个处理器的辅助EPT
 * @details 创建一个身份映射页表并设置一个EPTP，以稍后将其应用于VMCS此身份映射将在调试器机制中使用
 * 
 * @return BOOLEAN 
 */
BOOLEAN
EptInitializeSeconadaryEpt()
{
    PVMM_EPT_PAGE_TABLE PageTable;
    EPTP                EPTP = {0};

    //
    // 分配身份映射页表
    //
    PageTable = EptAllocateAndCreateIdentityPageTable();
    if (!PageTable)
    {
        LogError("Unable to allocate memory for EPT");
        return FALSE;
    }

    //
    // Virtual address to the page table to keep track of it for later freeing
    //
    g_EptState->SecondaryEptPageTable = PageTable;

    //
    // 为了提高性能，我们让处理器知道它可以缓存EPT
    //
    EPTP.MemoryType = MEMORY_TYPE_WRITE_BACK;

    //
    // 我们没有利用“访问”和“脏”标志功能
    //
    EPTP.EnableAccessAndDirtyFlags = FALSE;

    //
    // Bits 5:3 (1 less than the EPT page-walk length) must be 3, indicating an EPT page-walk length of 4;
    // see Section 28.2.2
    //
    EPTP.PageWalkLength = 3;

    //
    // 我们将使用的页表的物理页号
    //
    EPTP.PageFrameNumber = (SIZE_T)VirtualAddressToPhysicalAddress(&PageTable->PML4) / PAGE_SIZE;

    //
    // 稍后我们将把EPTP写入VMCS
    //
    g_EptState->SecondaryEptPointer = EPTP;

    //
    // 将辅助表设置为初始化状态
    //
    g_EptState->SecondaryInitialized = TRUE;

    return TRUE;
}

/**
 * @brief 检查此退出是否是由于当前挂钩页面引起的违规
 * @details 如果内存访问尝试为RW，并且页面被标记为可执行，则该页面将与原始页面交换。
 *
 * If the memory access attempt was execute and the page was marked not executable, the page is swapped with
 * the hooked page.
 * 
 * @param ViolationQualification The violation qualification in vm-exit
 * @param GuestPhysicalAddr The GUEST_PHYSICAL_ADDRESS that caused this EPT violation
 * @return BOOLEAN Returns true if it was successfull or false if the violation was not due to a page hook
 */
BOOLEAN
EptHandlePageHookExit(PGUEST_REGS Regs, VMX_EXIT_QUALIFICATION_EPT_VIOLATION ViolationQualification, UINT64 GuestPhysicalAddr)
{
	BOOLEAN     IsHandled = FALSE;
	PLIST_ENTRY TempList = 0;

	TempList = &g_EptState->HookedPagesList;
	while (&g_EptState->HookedPagesList != TempList->Flink)
	{
		TempList = TempList->Flink;
		PEPT_HOOKED_PAGE_DETAIL HookedEntry = CONTAINING_RECORD(TempList, EPT_HOOKED_PAGE_DETAIL, PageHookList);
		//判断虚拟机的物理地址是否等于HOOK的物理地址
		if (HookedEntry->PhysicalBaseAddress == PAGE_ALIGN(GuestPhysicalAddr))
		{
			//
			// We found an address that matches the details
			//
			// Returning true means that the caller should return to the ept state to
			// the previous state when this instruction is executed
			// by setting the Monitor Trap Flag. Return false means that nothing special
			// for the caller to do
			//
			// 判断是否需要换页
			if (EptHookHandleHookedPage(Regs, HookedEntry, ViolationQualification, GuestPhysicalAddr))
			{
				//
				// Next we have to save the current hooked entry to restore on the next instruction's vm-exit
				//
				// 记录换页地址，然后设置单步执行
				g_GuestState[KeGetCurrentProcessorNumber()].MtfEptHookRestorePoint = HookedEntry;

				//
				// We have to set Monitor trap flag and give it the HookedEntry to work with
				//
				//单步执行
				HvSetMonitorTrapFlag(TRUE);
			}

			//
			// Indicate that we handled the ept violation
			//
			IsHandled = TRUE;

			//
			// Get out of the loop
			//
			break;
		}
	}
	//
	// Redo the instruction
    // 不跳到下一条指令，也就是重新执行一遍当前指令，重新执行后会陷入VM_MFT_EXIT
	//
	g_GuestState[KeGetCurrentProcessorNumber()].IncrementRip = FALSE;
	return IsHandled;
}
/**
 * @brief Handle VM exits for EPT violations
 * @details Violations are thrown whenever an operation is performed on an EPT entry 
 * that does not provide permissions to access that page
 *
 * @param Regs Guest registers
 * @param ExitQualification Exit qualification of the vm-exit
 * @param GuestPhysicalAddr Physical address that caused this EPT violation
 * @return BOOLEAN Return true if the violation was handled by the page hook handler
 * and false if it was not handled
 */
BOOLEAN
EptHandleEptViolation(PGUEST_REGS Regs, ULONG ExitQualification, UINT64 GuestPhysicalAddr)
{
    VMX_EXIT_QUALIFICATION_EPT_VIOLATION ViolationQualification;

    ViolationQualification.Flags = ExitQualification;

	/**/
    if (EptHandlePageHookExit(Regs, ViolationQualification, GuestPhysicalAddr))
    {
        //LogError("There were errors in handling Ept Violation");
        //
        // Handled by page hook code
        //
        

        return TRUE;
    }
	else
	{
		LogError("Unexpected EPT violation");
	}
    

    //
    // Redo the instruction that caused the exception
    //
	return FALSE;
}

/**
 * @brief Handle vm-exits for Monitor Trap Flag to restore previous state
 * 
 * @param HookedEntry 
 * @return VOID 
 */
VOID
EptHandleMonitorTrapFlag(PEPT_HOOKED_PAGE_DETAIL HookedEntry)
{
    //
    // restore the hooked state
    //
    EptSetPML1AndInvalidateTLB(HookedEntry->EntryAddress, HookedEntry->ChangedEntry, INVEPT_SINGLE_CONTEXT);
}

/**
 * @brief Handle vm-exits for EPT Misconfiguration
 * 处理EPT配置错误异常
 * 
 * @param GuestAddress 
 * @return VOID 
 */
VOID
EptHandleMisconfiguration(UINT64 GuestAddress)
{
    LogInfo("EPT Misconfiguration!");
    LogError("A field in the EPT paging structure was invalid, Faulting guest address : 0x%llx", GuestAddress);
	KeBugCheckEx(0xFFFFFFFF, GuestAddress,0,0,0);
    // 到这里就代表ept炸裂了~恭喜你又踩一个坑
    //
    // We can't continue now.
    // EPT misconfiguration is a fatal exception that will probably crash the OS if we don't get out now
    //
}

/**
 * @brief This function set the specific PML1 entry in a spinlock protected area then invalidate the TLB
 * 替换TLB中的PML1条目
 * @details This function should be called from vmx root-mode
 * 这个过程应当在根模式运行
 * 
 * @param EntryAddress PML1 entry information (the target address)
 * @param EntryValue The value of pm1's entry (the value that should be replaced)
 * @param InvalidationType type of invalidation
 * @return VOID 
 */
VOID
EptSetPML1AndInvalidateTLB(PEPT_PML1_ENTRY EntryAddress, EPT_PML1_ENTRY EntryValue, INVEPT_TYPE InvalidationType)
{
    //
    // acquire the lock
    //
    SpinlockLock(&Pml1ModificationAndInvalidationLock);

    //
    // set the value
    //
    EntryAddress->Flags = EntryValue.Flags;

    //
    // invalidate the cache
    //
    if (InvalidationType == INVEPT_SINGLE_CONTEXT)
    {
        InveptSingleContext(g_EptState->EptPointer.Flags);
    }
    else if (InvalidationType == INVEPT_ALL_CONTEXTS)
    {
        InveptAllContexts();
    }
    else
    {
        LogError("Invald invalidation parameter.");
    }

    //
    // release the lock
    //
    SpinlockUnlock(&Pml1ModificationAndInvalidationLock);
}
