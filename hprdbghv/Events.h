/**
 * @file Events.h
 * @author Sina Karvandi (sina@rayanfam.com)
 * @brief Headers relating to Exception Bitmap and Event (Interrupt and Exception) Injection 
 * @details
 * @version 0.1
 * @date 2020-04-11
 * 
 * @copyright This project is released under the GNU Public License v3.
 * 
 */
#pragma once

//////////////////////////////////////////////////
//					Definitions					//
//////////////////////////////////////////////////

#define RESERVED_MSR_RANGE_LOW 0x40000000
#define RESERVED_MSR_RANGE_HI  0x400000F0

//////////////////////////////////////////////////
//					Enums						//
//////////////////////////////////////////////////

/**
 * @brief Exceptions enum
 * 中断事件
 * Intel 5.2
 */
typedef enum _EXCEPTION_VECTORS
{
    EXCEPTION_VECTOR_DIVIDE_ERROR,                                              //DIV IDIV指令 ERROR NO
    EXCEPTION_VECTOR_DEBUG_BREAKPOINT,                                          //任何代码或数据引用或INT 1指令，ERROR NO
    EXCEPTION_VECTOR_NMI,                                                       //不可屏蔽中断，ERROR NO
    EXCEPTION_VECTOR_BREAKPOINT,                                                //INT3中断，ERROR NO             
    EXCEPTION_VECTOR_OVERFLOW,                                                  //INTO中断，ERROR NO
    EXCEPTION_VECTOR_BOUND_RANGE_EXCEEDED,                                      //BOUND中断，ERROR NO
    EXCEPTION_VECTOR_UNDEFINED_OPCODE,                                          //#UD2指令或保留操作码，ERROR NO
    EXCEPTION_VECTOR_NO_MATH_COPROCESSOR,                                       //浮点或WAIT/FWAIT指令，ERROR NO
    EXCEPTION_VECTOR_DOUBLE_FAULT,                                              //可以生成异常、NMI或INTR的任何指令,ERROR YES,ZERO
    EXCEPTION_VECTOR_RESERVED0,                                                 //浮点指令，ERROR NO
    EXCEPTION_VECTOR_INVALID_TASK_SEGMENT_SELECTOR,                             //任务切换或TSS访问,ERROR YES
    EXCEPTION_VECTOR_SEGMENT_NOT_PRESENT,                                       //加载段寄存器或访问系统段,ERROR YES
    EXCEPTION_VECTOR_STACK_SEGMENT_FAULT,                                       //堆栈操作和SS寄存器加载,ERROR YES
    EXCEPTION_VECTOR_GENERAL_PROTECTION_FAULT,                                  //任何内存引用和其他保护检查,ERROR YES
    EXCEPTION_VECTOR_PAGE_FAULT,                                                //任何内存引用,ERROR YES
    EXCEPTION_VECTOR_RESERVED1,                                                 //保留
    EXCEPTION_VECTOR_MATH_FAULT,                                                //浮点或WAIT/FWAIT指令，ERROR NO
    EXCEPTION_VECTOR_ALIGNMENT_CHECK,                                           //内存中的任何数据引用,ERROR YES,ZERO
    EXCEPTION_VECTOR_MACHINE_CHECK,                                             //错误代码（如果有）和来源取决于模型，ERROR NO
    EXCEPTION_VECTOR_SIMD_FLOATING_POINT_NUMERIC_ERROR,                         //SIMD浮点指令，ERROR NO
    EXCEPTION_VECTOR_VIRTUAL_EXCEPTION,                                         //？？
    EXCEPTION_VECTOR_RESERVED2,
    EXCEPTION_VECTOR_RESERVED3,
    EXCEPTION_VECTOR_RESERVED4,
    EXCEPTION_VECTOR_RESERVED5,
    EXCEPTION_VECTOR_RESERVED6,
    EXCEPTION_VECTOR_RESERVED7,
    EXCEPTION_VECTOR_RESERVED8,
    EXCEPTION_VECTOR_RESERVED9,
    EXCEPTION_VECTOR_RESERVED10,
    EXCEPTION_VECTOR_RESERVED11,
    EXCEPTION_VECTOR_RESERVED12,

    //
    // NT (Windows) specific exception vectors.
    //
    APC_INTERRUPT   = 31,
    DPC_INTERRUPT   = 47,
    CLOCK_INTERRUPT = 209,
    IPI_INTERRUPT   = 225,
    PMI_INTERRUPT   = 254,

} EXCEPTION_VECTORS;

/**
 * @brief Type of interrupts
 * 
 */
typedef enum _INTERRUPT_TYPE
{
    INTERRUPT_TYPE_EXTERNAL_INTERRUPT            = 0,
    INTERRUPT_TYPE_RESERVED                      = 1,
    INTERRUPT_TYPE_NMI                           = 2,
    INTERRUPT_TYPE_HARDWARE_EXCEPTION            = 3,
    INTERRUPT_TYPE_SOFTWARE_INTERRUPT            = 4,
    INTERRUPT_TYPE_PRIVILEGED_SOFTWARE_INTERRUPT = 5,
    INTERRUPT_TYPE_SOFTWARE_EXCEPTION            = 6,
    INTERRUPT_TYPE_OTHER_EVENT                   = 7
} INTERRUPT_TYPE;

//////////////////////////////////////////////////
//					Structures					//
//////////////////////////////////////////////////

/**
 * @brief Interrupt injection and event format
 * 
 */
typedef union _INTERRUPT_INFO
{
    struct
    {
        UINT32 Vector : 8;
        /* 0=Ext Int, 1=Rsvd, 2=NMI, 3=Exception, 4=Soft INT,
		 * 5=Priv Soft Trap, 6=Unpriv Soft Trap, 7=Other */
        UINT32 InterruptType : 3;
        UINT32 DeliverCode : 1; /* 0=Do not deliver, 1=Deliver */
        UINT32 Reserved : 19;
        UINT32 Valid : 1; /* 0=Not valid, 1=Valid. Must be checked first */
    };
    UINT32 Flags;
} INTERRUPT_INFO, *PINTERRUPT_INFO;

/**
 * @brief Event information
 * 
 */
typedef struct _EVENT_INFORMATION
{
    INTERRUPT_INFO InterruptInfo;
    UINT32         InstructionLength;
    UINT64         ErrorCode;
} EVENT_INFORMATION, *PEVENT_INFORMATION;

//////////////////////////////////////////////////
//					Functions					//
//////////////////////////////////////////////////

VOID
EventInjectBreakpoint();

VOID
EventInjectInterruption(INTERRUPT_TYPE InterruptionType, EXCEPTION_VECTORS Vector, BOOLEAN DeliverErrorCode, ULONG32 ErrorCode);

VOID
EventInjectGeneralProtection();

VOID
EventInjectUndefinedOpcode(UINT32 CurrentProcessorIndex);

VOID
EventInjectPageFault(ULONG32 ErrorCode);

VOID
EventInjectDebugBreakpoint();
