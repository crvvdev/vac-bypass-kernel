/******************************************************************************
    MIT License

    Copyright (c) 2024 Ricardo Carvalho

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
 ******************************************************************************/
#include "includes.hpp"

namespace SyscallHook
{
bool g_initialized = false;

const bool IsInitialized()
{
    return g_initialized;
}

#if (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_INFINITY_HOOK)
enum CKCL_TRACE_OPERATION
{
    CKCL_TRACE_START,
    CKCL_TRACE_SYSCALL,
    CKCL_TRACE_END
};

typedef struct _CKCL_TRACE_PROPERIES : EVENT_TRACE_PROPERTIES
{
    ULONG64 Unknown[3];
    UNICODE_STRING ProviderName;
} CKCL_TRACE_PROPERTIES, *PCKCL_TRACE_PROPERTIES;

PVOID GetSyscallEntry();

ULONG64
hkHvlGetQpcBias(VOID);

BOOLEAN
StartSyscallHook(VOID);

NTSTATUS
ModifyTraceSettings(_In_ const CKCL_TRACE_OPERATION &TraceOperation);

NTSTATUS InitializeInfinityHook()
{
    NTSTATUS Status;

    Status = ModifyTraceSettings(CKCL_TRACE_SYSCALL);
    if (!NT_SUCCESS(Status))
    {
        Status = ModifyTraceSettings(CKCL_TRACE_START);
        if (!NT_SUCCESS(Status))
        {
            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL,
                      "ModifyTraceSettings(CKCL_TRACE_START) "
                      "failed %!STATUS!",
                      Status);

            return Status;
        }

        Status = ModifyTraceSettings(CKCL_TRACE_SYSCALL);
        if (!NT_SUCCESS(Status))
        {
            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL,
                      "ModifyTraceSettings(CKCL_TRACE_SYSCALL) "
                      "failed %!STATUS!",
                      Status);

            return Status;
        }
    }

    ULONG64 CkclWmiLoggerContext;
    PVOID EtwpDebuggerData;
    PULONG64 EtwpDebuggerDataSilo;
    PVOID syscallEntry;

    EtwpDebuggerData = reinterpret_cast<VOID *>(Dynamic::g_DynamicContext.Kernel.Address.EtwpDebuggerData);

    DBG_PRINT("EtwpDebuggerData = 0x%p", EtwpDebuggerData);

    EtwpDebuggerDataSilo = *reinterpret_cast<PULONG64 *>(PTR_OFFSET_ADD(EtwpDebuggerData, 0x10));

    DBG_PRINT("EtwpDebuggerDataSilo = 0x%p", EtwpDebuggerDataSilo);

    if (!MmIsAddressValid(EtwpDebuggerDataSilo))
    {
        goto Exit;
    }

    CkclWmiLoggerContext = EtwpDebuggerDataSilo[2];

    DBG_PRINT("CkclWmiLoggerContext = 0x%016llX", CkclWmiLoggerContext);

    if (!CkclWmiLoggerContext)
    {
        goto Exit;
    }

    g_GetCpuClock = Dynamic::g_DynamicContext.Kernel.GetCpuClock(CkclWmiLoggerContext);

    DBG_PRINT("g_GetCpuClock = 0x%p", g_GetCpuClock);

    if (!MmIsAddressValid(g_GetCpuClock))
    {
        goto Exit;
    }

    syscallEntry = GetSyscallEntry();
    if (!syscallEntry)
    {
        goto Exit;
    }

    DBG_PRINT("syscallEntry = 0x%p", syscallEntry);

    g_SyscallTableAddress = PAGE_ALIGN(syscallEntry);

    DBG_PRINT("g_SyscallTableAddress = 0x%p", g_SyscallTableAddress);

    if (!g_SyscallTableAddress)
    {
        goto Exit;
    }

    if (StartSyscallHook())
    {
        return STATUS_SUCCESS;
    }

Exit:
    return STATUS_UNSUCCESSFUL;
}

void CleanupInfinityHook()
{
    if (g_SyscallHookThread.Status == Threads::KERNEL_THREAD_STATUS::Running)
    {
        Threads::StopThread(&g_SyscallHookThread, TRUE);
    }

    if (g_GetCpuClock)
    {
        InterlockedExchangePointer(g_GetCpuClock, g_GetCpuClockOriginal);
    }

    if (g_HvlGetQpcBias)
    {
        InterlockedExchangePointer(g_HvlGetQpcBias, g_HvlGetQpcBiasOriginal);
    }

    NTSTATUS Status = ModifyTraceSettings(CKCL_TRACE_END);
    if (NT_SUCCESS(Status))
    {
        ModifyTraceSettings(CKCL_TRACE_START);
    }
}

BOOLEAN WatchdogThread(PVOID StartContext)
{
    UNREFERENCED_PARAMETER(StartContext);

    // This will ensure infinityhook is still active all the time
    //
    if (NTOS_BUILD <= WINVER_WIN10_1909)
    {
        if (g_GetCpuClock && MmIsAddressValid(g_GetCpuClock))
        {
            PVOID oldValue =
                InterlockedCompareExchangePointer(g_GetCpuClock, &SyscallHookHandler, g_GetCpuClockOriginal);
            if (oldValue == g_GetCpuClockOriginal)
            {
                g_GetCpuClockOriginal = oldValue;
            }
        }
    }
    else
    {
        if (g_GetCpuClock && MmIsAddressValid(g_GetCpuClock))
        {
            PVOID oldValue = InterlockedCompareExchangePointer(g_GetCpuClock, ULongToPtr(2), g_GetCpuClockOriginal);
            if (oldValue == g_GetCpuClockOriginal)
            {
                g_GetCpuClockOriginal = oldValue;
            }
        }

        if (g_HvlGetQpcBias && MmIsAddressValid(g_HvlGetQpcBias))
        {
            PVOID oldValue =
                InterlockedCompareExchangePointer(g_HvlGetQpcBias, &hkHvlGetQpcBias, g_HvlGetQpcBiasOriginal);
            if (oldValue == g_HvlGetQpcBiasOriginal)
            {
                g_HvlGetQpcBiasOriginal = oldValue;
            }
        }
    }

    Misc::DelayThread(512);

    // Keep executing as long as thread is not signalized to stop.
    //
    return FALSE;
}

BOOLEAN
StartSyscallHook(VOID)
{
    PAGED_PASSIVE();
    NT_ASSERT(g_SsdtCallback);

    BOOLEAN bResult = FALSE;

    if (!g_GetCpuClock || !MmIsAddressValid(g_GetCpuClock))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Invalid g_GetCpuClock!");
        goto Exit;
    }

    if (NTOS_BUILD <= WINVER_WIN10_1909)
    {
        g_GetCpuClockOriginal = InterlockedExchangePointer(g_GetCpuClock, &SyscallHookHandler);

        DBG_PRINT("g_GetCpuClock = 0x%p", g_GetCpuClock);
        DBG_PRINT("g_GetCpuClockOriginal = 0x%p", g_GetCpuClockOriginal);
    }
    else
    {
        g_GetCpuClockOriginal = InterlockedExchangePointer(g_GetCpuClock, ULongToPtr(2));

        DBG_PRINT("g_GetCpuClock = 0x%p", g_GetCpuClock);
        DBG_PRINT("g_GetCpuClockOriginal = 0x%p", g_GetCpuClockOriginal);

        ULONG_PTR HvlpReferenceTscPage = Dynamic::g_DynamicContext.Kernel.Address.HvlpReferenceTscPage;

        g_HvlpReferenceTscPage = RipToAbsolute<PVOID *>(HvlpReferenceTscPage, 3, 7);
        DBG_PRINT("g_HvlpReferenceTscPage = 0x%p", g_HvlpReferenceTscPage);

        ULONG_PTR HvlGetQpcBias = Dynamic::g_DynamicContext.Kernel.Address.HvlGetQpcBias;

        g_HvlGetQpcBias = RipToAbsolute<PVOID *>(HvlGetQpcBias, 3, 7);
        DBG_PRINT("g_HvlGetQpcBias = 0x%p", g_HvlGetQpcBias);

        g_HvlGetQpcBiasOriginal = InterlockedExchangePointer(g_HvlGetQpcBias, &hkHvlGetQpcBias);
        DBG_PRINT("g_HvlGetQpcBiasOriginal = 0x%p", g_HvlGetQpcBiasOriginal);
    }

    if (!Threads::CreateThread(&WatchdogThread, nullptr, &g_SyscallHookThread))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to create syscall hook watchdog thread!");
        goto Exit;
    }

    WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "Syscall watchdog thread id %d",
              HandleToULong(g_SyscallHookThread.ClientId.UniqueThread));

    WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL, "Successfully initialized syscall hooks.");

    bResult = TRUE;

Exit:
    if (!bResult)
    {
        Cleanup();
    }

    return bResult;
}

NTSTATUS
ModifyTraceSettings(_In_ const CKCL_TRACE_OPERATION &TraceOperation)
{
    PAGED_PASSIVE();

    auto traceProperty =
        reinterpret_cast<CKCL_TRACE_PROPERTIES *>(Memory::AllocNonPaged(PAGE_SIZE, Memory::TAG_SYSCALL_HOOK));
    if (!traceProperty)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL,
                  "Could not allocate "
                  "memory for trace properties!");

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    SCOPE_EXIT
    {
        Memory::FreePool(traceProperty);
    };

    traceProperty->Wnode.BufferSize = PAGE_SIZE;
    traceProperty->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    traceProperty->ProviderName = RTL_CONSTANT_STRING(L"Circular Kernel Context Logger");
    traceProperty->Wnode.Guid = {0x54DEA73A, 0xED1F, 0x42A4, {0xAF, 0x71, 0x3E, 0x63, 0xD0, 0x56, 0xF1, 0x74}};
    traceProperty->Wnode.ClientContext = 1;
    traceProperty->BufferSize = sizeof(ULONG);
    traceProperty->MinimumBuffers = traceProperty->MaximumBuffers = 2;
    traceProperty->LogFileMode = EVENT_TRACE_BUFFERING_MODE;

    NTSTATUS status = STATUS_ACCESS_DENIED;
    ULONG returnLength = 0UL;

    switch (TraceOperation)
    {
    case CKCL_TRACE_START: {
        status = ZwTraceControl(EtwpStartTrace, traceProperty, PAGE_SIZE, traceProperty, PAGE_SIZE, &returnLength);
        break;
    }
    case CKCL_TRACE_END: {
        status = ZwTraceControl(EtwpStopTrace, traceProperty, PAGE_SIZE, traceProperty, PAGE_SIZE, &returnLength);
        break;
    }
    case CKCL_TRACE_SYSCALL: {
        traceProperty->EnableFlags = EVENT_TRACE_FLAG_SYSTEMCALL;
        status = ZwTraceControl(EtwpUpdateTrace, traceProperty, PAGE_SIZE, traceProperty, PAGE_SIZE, &returnLength);
        break;
    }
    }

    return status;
}

PVOID GetSyscallEntry()
{
    PAGED_PASSIVE();

    PIMAGE_NT_HEADERS64 nth = RtlImageNtHeader(NTOS_BASE);
    if (!nth)
    {
        return nullptr;
    }

    PVOID syscallEntry = reinterpret_cast<PVOID>(__readmsr(IA32_LSTAR_MSR));

    // If KVASCODE section does not exists it probably means the system does not support it.
    //
    PIMAGE_SECTION_HEADER section = Misc::PE::FindSection(nth, "KVASCODE");
    if (!section)
    {
        return syscallEntry;
    }

    const PVOID sectionBase = reinterpret_cast<PUCHAR>(NTOS_BASE) + section->VirtualAddress;
    const ULONG sectionSize = section->Misc.VirtualSize;

    // Is the value within this KVA shadow region? If not, we're done.
    //
    if (!(syscallEntry >= sectionBase && syscallEntry < reinterpret_cast<PUCHAR>(sectionBase) + sectionSize))
    {
        return syscallEntry;
    }

    // This is KiSystemCall64Shadow.
    //
    hde64s HDE;
    for (PUCHAR KiSystemServiceUser = reinterpret_cast<PUCHAR>(syscallEntry); /* */; KiSystemServiceUser += HDE.len)
    {
        // Disassemble every instruction till the first near jmp (E9).
        //
        if (!hde64_disasm(KiSystemServiceUser, &HDE))
        {
            break;
        }

        if (HDE.opcode != 0xE9)
        {
            continue;
        }

        // Ignore jmps within the KVA shadow region.
        //
        PVOID possibleSyscallEntry = KiSystemServiceUser + (int)HDE.len + (int)HDE.imm.imm32;
        if (possibleSyscallEntry >= sectionBase &&
            possibleSyscallEntry < reinterpret_cast<PUCHAR>(sectionBase) + sectionSize)
        {
            continue;
        }

        // Found KiSystemServiceUser.
        //
        syscallEntry = possibleSyscallEntry;
        break;
    }

    return syscallEntry;
}

ULONG64
SyscallHookHandler(VOID)
{
#define INFINITYHOOK_MAGIC_1 ((ULONG)0x501802)
#define INFINITYHOOK_MAGIC_2 ((USHORT)0xF33)

    if (ExGetPreviousMode() == KernelMode)
    {
        return __rdtsc();
    }

    const auto currentThread = __readgsqword(0x188);
    const ULONG systemCallIndex = *(ULONG *)(currentThread + 0x80); // KTHREAD->SystemCallNumber

    const auto stackMax = __readgsqword(KPCR_RSP_BASE);
    const PVOID *stackFrame = (PVOID *)_AddressOfReturnAddress();

    UINT offset = 0;

    // First walk backwards on the stack to find the 2 magic values.
    for (PVOID *stackCurrent = (PVOID *)stackMax; stackCurrent > stackFrame; --stackCurrent)
    {
        PULONG AsUlong = (PULONG)stackCurrent;
        if (*AsUlong != INFINITYHOOK_MAGIC_1)
        {
            continue;
        }

        // If the first magic is set, check for the second magic.
        --stackCurrent;

        PUSHORT AsShort = (PUSHORT)stackCurrent;
        if (*AsShort != INFINITYHOOK_MAGIC_2)
        {
            continue;
        }

        // Now we reverse the direction of the stack walk.
        for (; (ULONG_PTR)stackCurrent < stackMax; ++stackCurrent)
        {
            PULONGLONG AsUlonglong = (PULONGLONG)stackCurrent;

            if (!(PAGE_ALIGN(*AsUlonglong) >= g_SyscallTableAddress &&
                  PAGE_ALIGN(*AsUlonglong) < (PVOID)((uintptr_t)g_SyscallTableAddress + (PAGE_SIZE * 2))))
            {
                continue;
            }

            offset = (UINT)((ULONG_PTR)stackCurrent - (ULONG_PTR)stackFrame);
            break;
        }

        break;
    }

    if (offset)
    {
        PVOID *stackCurrent = (PVOID *)((ULONG_PTR)stackFrame + offset);

        if (*(ULONG_PTR *)stackCurrent >= (ULONG_PTR)g_SyscallTableAddress &&
            *(ULONG_PTR *)stackCurrent < ((ULONG_PTR)g_SyscallTableAddress + (PAGE_SIZE * 2)))
        {
            PVOID *systemCallFunction = &stackCurrent[9];

            if (g_SsdtCallback)
            {
                g_SsdtCallback(systemCallIndex, systemCallFunction);
            }
        }
    }

    return __rdtsc();
}

ULONG64
hkHvlGetQpcBias(VOID)
{
    SyscallHookHandler();

    return *((ULONG64 *)(*((ULONG64 *)g_HvlpReferenceTscPage)) + 3);
}
#elif (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_SSDT_HOOK)
BOOLEAN FindCodeCaveSection(_In_ ULONG_PTR SsdtBase, _In_ ULONG_PTR RoutineAddress, _Out_ PULONG_PTR SectionBase,
                            _Out_ PULONG SectionSize)
{
    PAGED_PASSIVE();

    PUCHAR sectionBase = nullptr;
    ULONG sectionSize = 0;

    *SectionBase = NULL;
    *SectionSize = NULL;

    if (!Misc::PE::GetSectionFromVirtualAddress(NTOS_BASE, reinterpret_cast<PUCHAR>(RoutineAddress), &sectionSize,
                                                &sectionBase))
    {

        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to find section from virtual address 0x%016llX", RoutineAddress);

        return FALSE;
    }

    ULONG_PTR baseFound = reinterpret_cast<ULONG_PTR>(sectionBase);
    ULONG_PTR Lowest = SsdtBase;

    if (baseFound < Lowest)
    {
        sectionSize -= static_cast<ULONG>(Lowest - baseFound);
        baseFound = Lowest;
    }

    *SectionBase = baseFound;
    *SectionSize = sectionSize;

    return TRUE;
}

void CleanupSsdtHook()
{
    auto serviceTable =
        reinterpret_cast<PSERVICE_DESCRIPTOR_TABLE>(Dynamic::g_DynamicContext.Kernel.Address.KeServiceDescriptorTable);

    // First unhook the SSDT entries
    //
    for (Hooks::SYSCALL_HOOK_ENTRY &entry : Hooks::g_SyscallHookList)
    {
        if (entry.OldSsdt && entry.NewSsdt)
        {
            Misc::Memory::WriteReadOnlyMemory(&serviceTable->NtosTable.ServiceTableBase[entry.ServiceIndex],
                                              &entry.OldSsdt, sizeof(entry.OldSsdt));
        }
    }

    WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "SSDT Unhook -- Waiting for pending hooks...");

    // Wait for all pending hooks to complete
    //
    while (InterlockedCompareExchange(&Hooks::g_hooksRefCount, 0, 0) != 0)
    {
        YieldProcessor();
    }

    // Finally restore the code cave bytes
    //
    for (Hooks::SYSCALL_HOOK_ENTRY &entry : Hooks::g_SyscallHookList)
    {
        if (entry.OldSsdt && entry.NewSsdt)
        {
            Misc::Memory::WriteReadOnlyMemory(entry.NewRoutineAddress, entry.OriginalBytes,
                                              sizeof(entry.OriginalBytes));

            WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "SSDT Unhook -- ServiceIndex: %d", entry.ServiceIndex);

            entry.OldSsdt = NULL;
            entry.NewSsdt = NULL;
        }
    }
}

NTSTATUS InitializeSsdtHook()
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    auto serviceTable =
        reinterpret_cast<PSERVICE_DESCRIPTOR_TABLE>(Dynamic::g_DynamicContext.Kernel.Address.KeServiceDescriptorTable);
    const PULONG KiServiceTable = serviceTable->NtosTable.ServiceTableBase;

    for (Hooks::SYSCALL_HOOK_ENTRY &entry : Hooks::g_SyscallHookList)
    {
        // mov rax, 0
        // jmp rax
        static UCHAR TrampolineShellCode[12] = {0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0};

        auto SsdtBase = reinterpret_cast<ULONG_PTR>(KiServiceTable);

        const ULONG ServiceIndex = entry.ServiceIndex;
        if (ServiceIndex == ULONG_MAX)
        {
            continue;
        }

        LONG OldSsdt = KiServiceTable[ServiceIndex];
        LONG NewSsdt = 0;

        // Try to find possible code cave
        //
        ULONG_PTR CodeStart = 0;
        ULONG CodeSize = 0;

        if (!FindCodeCaveSection(SsdtBase, reinterpret_cast<ULONG_PTR>(entry.OriginalRoutineAddress), &CodeStart,
                                 &CodeSize))
        {
            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to find code cave section!");

            goto Exit;
        }

        ULONG_PTR CaveAddress = Misc::Memory::FindCodeCaveAddress(CodeStart, CodeSize, ARRAYSIZE(TrampolineShellCode));
        if (!CaveAddress)
        {
            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to find code cave address!");

            goto Exit;
        }

        // Write shellcode to code cave address
        //
        RtlCopyMemory(entry.OriginalBytes, reinterpret_cast<PVOID>(CaveAddress), ARRAYSIZE(entry.OriginalBytes));

        *(PVOID *)(&TrampolineShellCode[2]) = entry.NewRoutineAddress;

        Status = Misc::Memory::WriteReadOnlyMemory(reinterpret_cast<PVOID>(CaveAddress), TrampolineShellCode,
                                                   ARRAYSIZE(TrampolineShellCode));

        if (!NT_SUCCESS(Status))
        {

            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to write code cave, WriteReadOnlyMemory returned %!STATUS!",
                      Status);

            goto Exit;
        }

        // Update SSDT entry
        //
        NewSsdt = static_cast<LONG>(CaveAddress - SsdtBase);
        NewSsdt = (NewSsdt << 4) | OldSsdt & 0xF;

        Status = Misc::Memory::WriteReadOnlyMemory(&serviceTable->NtosTable.ServiceTableBase[ServiceIndex], &NewSsdt,
                                                   sizeof(NewSsdt));
        if (!NT_SUCCESS(Status))
        {

            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to SSDT entry, WriteReadOnlyMemory returned %!STATUS!",
                      Status);

            goto Exit;
        }

        entry.NewRoutineAddress = reinterpret_cast<PVOID>(CaveAddress);
        entry.NewSsdt = NewSsdt;
        entry.OldSsdt = OldSsdt;

        DBG_PRINT("SSDT Hook -- ServiceIndex: %d OriginalRoutineAddress: 0x%p "
                  "NewRoutineAddress: 0x%p OldSsdt: 0x%08X NewSsdt: 0x%08X",
                  entry.ServiceIndex, entry.OriginalRoutineAddress, entry.NewRoutineAddress, entry.OldSsdt,
                  entry.NewSsdt);
    }

    Status = STATUS_SUCCESS;

Exit:
    if (!NT_SUCCESS(Status))
    {
        CleanupSsdtHook();
    }

    return Status;
}
#endif

#if (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_INFINITY_HOOK)
NTSTATUS
Initialize(_In_ SSDT_CALLBACK SsdtCallback)
#elif (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_SSDT_HOOK)
NTSTATUS
Initialize()
#endif
{
    PAGED_PASSIVE();

    NTSTATUS Status;

    if (g_initialized)
    {
        return STATUS_ALREADY_INITIALIZED;
    }

#if (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_INFINITY_HOOK)
    NT_ASSERT(SsdtCallback || MmIsAddressValid(SsdtCallback));

    g_SsdtCallback = SsdtCallback;
    Status = InitializeInfinityHook();
#elif (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_SSDT_HOOK)
    Status = InitializeSsdtHook();
#endif

    if (!NT_SUCCESS(Status))
    {
        return STATUS_UNSUCCESSFUL;
    }

    g_initialized = true;

    return STATUS_SUCCESS;
}

void Cleanup()
{
#if (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_INFINITY_HOOK)
    CleanupInfinityHook();
#elif (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_SSDT_HOOK)
    CleanupSsdtHook();
#endif
}

void Unitialize()
{
    PAGED_PASSIVE();

    if (!g_initialized)
    {
        return;
    }

    Cleanup();

    g_initialized = false;

    WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL, "Unitialized SyscallHook");
}

} // namespace SyscallHook