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

#include <algorithm>

#define BACKUP_RETURNLENGTH()                                                                                          \
    ULONG TempReturnLength = 0;                                                                                        \
    if (ARGUMENT_PRESENT(ReturnLength))                                                                                \
    {                                                                                                                  \
        ProbeForWrite(ReturnLength, sizeof(ULONG), 1);                                                                 \
        TempReturnLength = *ReturnLength;                                                                              \
    }

#define RESTORE_RETURNLENGTH()                                                                                         \
    if (ARGUMENT_PRESENT(ReturnLength))                                                                                \
    (*ReturnLength) = TempReturnLength

namespace Hooks
{
volatile LONG g_hooksRefCount = 0;
bool g_shouldBypass = true;

decltype(&ZwQuerySystemInformation) oNtQuerySystemInformation = nullptr;
decltype(&NtReadVirtualMemory) oNtReadVirtualMemory = nullptr;
decltype(&NtQueryVirtualMemory) oNtQueryVirtualMemory = nullptr;
decltype(&ZwMapViewOfSection) oNtMapViewOfSection = nullptr;

void __fastcall SsdtCallback(ULONG ServiceIndex, PVOID *ServiceAddress)
{
    for (SYSCALL_HOOK_ENTRY &Entry : g_SyscallHookList)
    {
        if (Entry.ServiceIndex == ServiceIndex)
        {
            *ServiceAddress = Entry.NewRoutineAddress;
            return;
        }
    }
}

static KPROCESSOR_MODE GetPreviousMode()
{
    return ExGetPreviousMode();
}

NTSTATUS
NTAPI
hkNtMapViewOfSection(_In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle,
                     _Outptr_result_bytebuffer_(*ViewSize) PVOID *BaseAddress, _In_ ULONG_PTR ZeroBits,
                     _In_ SIZE_T CommitSize, _Inout_opt_ PLARGE_INTEGER SectionOffset, _Inout_ PSIZE_T ViewSize,
                     _In_ SECTION_INHERIT InheritDisposition, _In_ ULONG AllocationType, _In_ ULONG Win32Protect)
{
    PAGED_CODE();

    InterlockedIncrement(&g_hooksRefCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_hooksRefCount);
    };

    const NTSTATUS Status =
        oNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize,
                            InheritDisposition, AllocationType, Win32Protect);

    const HANDLE currentPid = PsGetCurrentProcessId();

    PUNICODE_STRING MappedName = nullptr;
    SCOPE_EXIT
    {
        if (MappedName)
        {
            Memory::FreePool(MappedName);
        }
    };

    if (GetPreviousMode() != UserMode || !Processes::IsProcessGame(currentPid))
    {
        goto Exit;
    }

    if (g_shouldBypass && NT_SUCCESS(Status) && NT_SUCCESS(Misc::Memory::GetMappedFilename(*BaseAddress, &MappedName)))
    {
        // Check if currently loading module corresponds to one we're looking for.
        //
        for (const wchar_t *moduleName : Bypass::g_BackupModulesList)
        {
            if (Misc::String::wcsistr(MappedName->Buffer, moduleName))
            {
                PIMAGE_NT_HEADERS nth = nullptr;

                __try
                {
                    const NTSTATUS status = RtlImageNtHeaderEx(0, *BaseAddress, *ViewSize, &nth);
                    if (!NT_SUCCESS(status))
                    {
                        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "RtlImageNtHeaderEx returned %!STATUS!", status);
                        return STATUS_INVALID_IMAGE_FORMAT;
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Exception trying to parse mapped headers %!STATUS!",
                              GetExceptionCode());
                    return GetExceptionCode();
                }

                if (*ViewSize == nth->OptionalHeader.SizeOfImage)
                {
                    const NTSTATUS status = Bypass::CreateGameModule(currentPid, *BaseAddress, *ViewSize, MappedName);

                    if (NT_SUCCESS(status))
                    {
                        DBG_PRINT("Create game module -- Path = %wZ BaseAddress = 0x%p ViewSize = 0x%08llX", MappedName,
                                  *BaseAddress, *ViewSize);

                        WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "[VAC] SV");
                    }
                    else if (!NT_SUCCESS(status) && status != STATUS_INVALID_PARAMETER)
                    {
                        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "CreateGameModule returned %!STATUS!", status);
                        return STATUS_ACCESS_VIOLATION;
                    }
                }
            }
        }
    }
Exit:
    return Status;
}

NTSTATUS
NTAPI
hkNtQueryVirtualMemory(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress,
                       _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
                       _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
                       _In_ SIZE_T MemoryInformationLength, _Out_opt_ PSIZE_T ReturnLength)
{
    PAGED_CODE();

    InterlockedIncrement(&g_hooksRefCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_hooksRefCount);
    };

    const HANDLE currentPid = PsGetCurrentProcessId();
    const HANDLE targetPid = Misc::GetProcessIDFromProcessHandle(ProcessHandle);

    if (GetPreviousMode() != UserMode || !g_shouldBypass ||
        !Processes::IsProcessSteam(currentPid) && !Processes::IsProcessGame(targetPid))
    {
        goto Exit;
    }

    if (MemoryInformationClass == MemoryBasicInformation && BaseAddress && MemoryInformation && MemoryInformationLength)
    {
        if (Bypass::IsInProtectedModuleMemoryRange(targetPid, nullptr, BaseAddress))
        {
#if DBG
            WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "VAC query to protected module, BaseAddress = 0x%p", BaseAddress);
#else
            WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "[VAC Q1]");
#endif

#if 0
				auto mbi = reinterpret_cast<PMEMORY_BASIC_INFORMATION>(MemoryInformation);

				PVOID nextBase = reinterpret_cast<PBYTE>(mbi->BaseAddress) + mbi->RegionSize;

				SIZE_T nextLength = 0;
				MEMORY_BASIC_INFORMATION nextBlock = {};

				oNtQueryVirtualMemory(ProcessHandle, nextBase, MemoryInformationClass, &nextBlock, sizeof(nextBlock),
					&nextLength);

				mbi->AllocationBase = nullptr;
				mbi->AllocationProtect = 0;
				mbi->State = MEM_FREE;
				mbi->Protect = PAGE_NOACCESS;
				mbi->Type = 0;

				if (nextBlock.State == MEM_FREE)
				{
					mbi->RegionSize += nextBlock.RegionSize;
				}
#else
            return STATUS_ACCESS_VIOLATION;
#endif
        }
    }
Exit:
    return oNtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation,
                                 MemoryInformationLength, ReturnLength);
}

NTSTATUS NTAPI hkNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToRead,
                                     PSIZE_T NumberOfBytesReaded)
{
    PAGED_CODE();

    InterlockedIncrement(&g_hooksRefCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_hooksRefCount);
    };

    const HANDLE currentPid = PsGetCurrentProcessId();
    const HANDLE targetPid = Misc::GetProcessIDFromProcessHandle(ProcessHandle);

    // Check if bypass is enabled and if requestor process is Steam and requested process is game
    //
    if (GetPreviousMode() != UserMode || !g_shouldBypass ||
        !(Processes::IsProcessSteam(currentPid) && Processes::IsProcessGame(targetPid)))
    {
        return oNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
    }

    NTSTATUS status;

    if (Bypass::IsInProtectedModuleMemoryRange(targetPid, nullptr, BaseAddress, NumberOfBytesToRead))
    {
#if DBG
        WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "PID %d blocking memory read to protected range 0x%p",
                  HandleToULong(currentPid), BaseAddress);
#else
        WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "[VAC R1]");
#endif

        __try
        {
            if (NumberOfBytesReaded)
            {
                ProbeForWrite(NumberOfBytesReaded, sizeof(*NumberOfBytesReaded), alignof(PVOID));
                *NumberOfBytesReaded = 0;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = GetExceptionCode();
            goto Exit;
        }

        // If VAC tries to read one of our allocated memory we just return this generic ahh error
        //
        status = STATUS_PARTIAL_COPY;
        goto Exit;
    }

    status = oNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
    if (NT_SUCCESS(status))
    {
        [[maybe_unused]] const SIZE_T NumberOfBytesRead = NumberOfBytesReaded ? *NumberOfBytesReaded : 0;

        // TODO: deref object
        Bypass::PGAME_MODULE_ENTRY gameModule = nullptr;

        if (NumberOfBytesRead && Bypass::IsInGameModuleMemoryRange(targetPid, reinterpret_cast<PVOID *>(&gameModule),
                                                                   BaseAddress, NumberOfBytesRead))
        {

            const auto baseAddress = reinterpret_cast<const ULONG_PTR>(BaseAddress);
            const ULONG_PTR baseAddressEnd = baseAddress + NumberOfBytesRead;

            DBG_PRINT("Read within game module 0x%p size 0x%-16llX", baseAddress, NumberOfBytesRead);

            __try
            {
                const ULONG_PTR codeStart = gameModule->BaseAddress + gameModule->BaseOfCode;
                const ULONG_PTR codeEnd = codeStart + gameModule->SizeOfCode;

                const ULONG_PTR overlapStart = max(baseAddress, codeStart);
                const ULONG_PTR overlapEnd = min(baseAddressEnd, codeEnd);

                if (!(overlapStart >= overlapEnd) && overlapEnd > overlapStart)
                {
                    SIZE_T overlapSize = overlapEnd - overlapStart;
                    SIZE_T readOffset = overlapStart - baseAddress;

                    DBG_PRINT("[SPOOF] start = 0x%p, end = 0x%p, size = 0x%08llX, readOffset = "
                              "0x%08llX",
                              reinterpret_cast<PVOID>(overlapStart), reinterpret_cast<PVOID>(overlapEnd), overlapSize,
                              readOffset);

                    [[maybe_unused]] ULONG Crc1 =
                        Crc32::Checksum(reinterpret_cast<PUCHAR>(Buffer) + readOffset, static_cast<ULONG>(overlapSize));

                    RtlCopyMemory(reinterpret_cast<PUCHAR>(Buffer) + readOffset,
                                  reinterpret_cast<PUCHAR>(gameModule->CopyBaseAddress) +
                                      (overlapStart - gameModule->BaseAddress),
                                  overlapSize);

                    [[maybe_unused]] ULONG Crc2 =
                        Crc32::Checksum(reinterpret_cast<PUCHAR>(Buffer) + readOffset, static_cast<ULONG>(overlapSize));

                    DBG_PRINT("[SPOOF] CRC1 = 0x%08X CRC2 = 0x%08X", Crc1, Crc2);

#if DBG
                    if (Crc1 != Crc2)
                    {
                        __debugbreak();
                    }
#endif
                }

#if DBG
                DBG_PRINT("PID %d read in game module - BaseAddress = 0x%p Buffer "
                          "= 0x%p "
                          "NumberOfBytesRead = "
                          "0x%08llX ",
                          HandleToULong(currentPid), BaseAddress, Buffer, NumberOfBytesRead);
#else
                WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "[VAC] R2");
#endif
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                status = GetExceptionCode();
#if DBG
                __debugbreak();
#endif
            }

            NT_ASSERT(NT_SUCCESS(status));
        }
    }
Exit:
    return status;
}

NTSTATUS NTAPI hkNtQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
                                          OUT PVOID SystemInformation, IN ULONG SystemInformationLength,
                                          OUT PULONG ReturnLength OPTIONAL)
{
    InterlockedIncrement(&g_hooksRefCount);
    SCOPE_EXIT
    {
        InterlockedDecrement(&g_hooksRefCount);
    };

    NTSTATUS Status =
        oNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    const HANDLE currentPid = PsGetCurrentProcessId();

    // Spoof any process in list from the following queries
    //
    if (GetPreviousMode() != UserMode || !Processes::IsProcessInList(currentPid))
    {
        goto Exit;
    }

    if (NT_SUCCESS(Status) && SystemInformation)
    {
        switch (SystemInformationClass)
        {
        case SystemCodeIntegrityUnlockInformation: {

            WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL,
                      "NtQuerySystemInformation(SystemCodeIntegrityUnlockInformation) by %d",
                      HandleToUlong(currentPid));

            __try
            {
                ProbeForWrite(SystemInformation, SystemInformationLength, 1);

                BACKUP_RETURNLENGTH();

                // The size of the buffer for this class changed from 4 to 36, but the output should still be
                // all zeroes
                RtlZeroMemory(SystemInformation, SystemInformationLength);

                RESTORE_RETURNLENGTH();
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                Status = GetExceptionCode();

                WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL,
                          "Exception in NtQuerySystemInformation(SystemCodeIntegrityUnlockInformation) code = "
                          "%!STATUS!",
                          Status);
            }
            break;
        }
        case SystemCodeIntegrityInformation: {
            WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL,
                      "NtQuerySystemInformation(SystemCodeIntegrityInformation) by %d", HandleToUlong(currentPid));

            auto CodeIntegrityInfo = reinterpret_cast<PSYSTEM_CODEINTEGRITY_INFORMATION>(SystemInformation);

            __try
            {
                ProbeForWrite(SystemInformation, SystemInformationLength, 1);

                BACKUP_RETURNLENGTH();

                ULONG Options = CodeIntegrityInfo->CodeIntegrityOptions;

                Options |= CODEINTEGRITY_OPTION_ENABLED;
                Options &= ~CODEINTEGRITY_OPTION_TESTSIGN;
                Options &= ~CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED;

                CodeIntegrityInfo->CodeIntegrityOptions = Options;

                RESTORE_RETURNLENGTH();
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                Status = GetExceptionCode();

                WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL,
                          "Exception in NtQuerySystemInformation(SystemCodeIntegrityInformation) code = %!STATUS!",
                          Status);
            }

            break;
        }
        case SystemKernelDebuggerFlags: {

            __try
            {
                ProbeForWrite(SystemInformation, SystemInformationLength, 1);

                BACKUP_RETURNLENGTH();

                WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL, "NtQuerySystemInformation(SystemKernelDebuggerFlags) by %d",
                          HandleToUlong(currentPid));

                *(UCHAR *)SystemInformation = NULL;

                RESTORE_RETURNLENGTH();
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                Status = GetExceptionCode();

                WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL,
                          "Exception in NtQuerySystemInformation(SystemKernelDebuggerFlags) code = %!STATUS!", Status);
            }

            break;
        }
        case SystemKernelDebuggerInformation: {

            WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL,
                      "NtQuerySystemInformation(SystemKernelDebuggerInformation) by %d", HandleToUlong(currentPid));

            auto DebuggerInfo = reinterpret_cast<PSYSTEM_KERNEL_DEBUGGER_INFORMATION>(SystemInformation);

            __try
            {
                ProbeForWrite(SystemInformation, SystemInformationLength, 1);

                BACKUP_RETURNLENGTH();

                DebuggerInfo->KernelDebuggerEnabled = FALSE;
                DebuggerInfo->KernelDebuggerNotPresent = TRUE;

                RESTORE_RETURNLENGTH();
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                Status = GetExceptionCode();

                WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL,
                          "Exception in NtQuerySystemInformation(SystemKernelDebuggerInformation) code = %!STATUS!",
                          Status);
            }

            break;
        }
        case SystemKernelDebuggerInformationEx: {

            WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL,
                      "NtQuerySystemInformation(SystemKernelDebuggerInformationEx) by %d", HandleToUlong(currentPid));

            auto DebuggerInfo = reinterpret_cast<PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX>(SystemInformation);

            __try
            {
                ProbeForWrite(SystemInformation, SystemInformationLength, 1);

                BACKUP_RETURNLENGTH();

                DebuggerInfo->DebuggerAllowed = FALSE;
                DebuggerInfo->DebuggerEnabled = FALSE;
                DebuggerInfo->DebuggerPresent = FALSE;

                RESTORE_RETURNLENGTH();
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                Status = GetExceptionCode();

                WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL,
                          "Exception in NtQuerySystemInformation(SystemKernelDebuggerInformationEx) code = %!STATUS!",
                          Status);
            }
            break;
        }
        default:
            break;
        }
    }

Exit:
    return Status;
}

BOOLEAN CreateHook(const FNV1A_t ServiceNameHash, PVOID *OriginalRoutine)
{
    for (auto &entry : g_SyscallHookList)
    {
        if (ServiceNameHash == entry.ServiceNameHash)
        {
            if (SyscallTable::FindServiceInTable(ServiceNameHash, &entry.ServiceIndex,
                                                 reinterpret_cast<PULONG_PTR>(&entry.OriginalRoutineAddress)))
            {
                *OriginalRoutine = entry.OriginalRoutineAddress;
                return TRUE;
            }
            else
            {
                WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Service hash %lld not found!", ServiceNameHash);
            }
        }
    }
    return FALSE;
}

NTSTATUS Initialize()
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

#define CREATE_HOOK(name)                                                                                              \
    if (!CreateHook(FNV(#name), reinterpret_cast<VOID **>(&o##name)))                                                  \
    {                                                                                                                  \
        DBG_PRINT("Failed to hook " #name);                                                                            \
        goto Exit;                                                                                                     \
    }

    CREATE_HOOK(NtMapViewOfSection);
    CREATE_HOOK(NtReadVirtualMemory);
    CREATE_HOOK(NtQueryVirtualMemory);
#if DBG
    CREATE_HOOK(NtQuerySystemInformation);
#endif

#undef CREATE_HOOK

    Status = STATUS_SUCCESS;

Exit:
    return Status;
}

void Unitialize()
{
    WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL, "Unitialized Hooks");
}

} // namespace Hooks