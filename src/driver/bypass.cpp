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

namespace Bypass
{
bool g_initialized = false;

const bool IsInitialized()
{
    return g_initialized;
}

NTSTATUS Initialize()
{
    PAGED_CODE();

    if (g_initialized)
    {
        return STATUS_ALREADY_INITIALIZED;
    }

    NTSTATUS status = g_GameModulesListLock.Initialize();
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to initialized game modules list lock!");

        return STATUS_UNSUCCESSFUL;
    }

    status = g_ProtectedModulesListLock.Initialize();
    if (!NT_SUCCESS(status))
    {
        g_GameModulesListLock.Destroy();

        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to initialized protected modules list lock!");

        return STATUS_UNSUCCESSFUL;
    }

    InitializeListHead(&g_GameModulesList);
    InitializeListHead(&g_ProtectedModulesList);

    Memory::InitializeNPagedLookaside(&g_GameModulesLookasideList, sizeof(GAME_MODULE_ENTRY), Memory::TAG_GAME_MODULE);
    Memory::InitializeNPagedLookaside(&g_ProtectedModulesLookasideList, sizeof(PROTECTED_MODULE_ENTRY),
                                      Memory::TAG_PROTECTED_MODULE);

    g_initialized = true;

    return STATUS_SUCCESS;
}

void Cleanup()
{
    // Clear all lists
    //
    g_GameModulesListLock.LockExclusive();
    {
        EnumGameModulesUnsafe([&](_In_ PGAME_MODULE_ENTRY Entry) -> BOOLEAN {
            if (Entry->CopyBaseAddress)
            {
                Memory::FreePool(reinterpret_cast<void *>(Entry->CopyBaseAddress));
            }

            RemoveEntryList(&Entry->ListEntry);
            Memory::FreeFromNPagedLookaside(&g_GameModulesLookasideList, Entry);

            return FALSE;
        });

        g_GameModulesListLock.Unlock();
    }

    g_ProtectedModulesListLock.LockExclusive();
    {
        EnumProtectedModulesUnsafe([&](_In_ PPROTECTED_MODULE_ENTRY Entry) -> BOOLEAN {
            RemoveEntryList(&Entry->ListEntry);
            Memory::FreeFromNPagedLookaside(&g_ProtectedModulesLookasideList, Entry);

            return FALSE;
        });

        g_ProtectedModulesListLock.Unlock();
    }
}

void Unitialize()
{
    PAGED_CODE();

    if (!g_initialized)
    {
        return;
    }

    g_initialized = false;

    Cleanup();

    Memory::DeleteNPagedLookaside(&g_GameModulesLookasideList);
    Memory::DeleteNPagedLookaside(&g_ProtectedModulesLookasideList);

    g_GameModulesListLock.Destroy();
    g_ProtectedModulesListLock.Destroy();

    WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL, "Unitialized Bypass");
}

void EraseGameModules(HANDLE ProcessId)
{
    PAGED_CODE();

    g_GameModulesListLock.LockExclusive();
    {
        EnumGameModulesUnsafe([&](_In_ PGAME_MODULE_ENTRY Entry) -> BOOLEAN {
            if (Entry->ProcessId == ProcessId)
            {
                WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "Erasing saved module 0x%-16llX from process id %d",
                          Entry->CopyBaseAddress, HandleToULong(ProcessId));

                if (Entry->CopyBaseAddress)
                {
                    Memory::FreePool(reinterpret_cast<void *>(Entry->CopyBaseAddress));
                }

                // TODO: deref obj
                RemoveEntryList(&Entry->ListEntry);
                Memory::FreeFromNPagedLookaside(&g_GameModulesLookasideList, Entry);
            }

            return FALSE;
        });

        g_GameModulesListLock.Unlock();
    }
}

void EraseProtectedModules(HANDLE ProcessId)
{
    PAGED_CODE();

    g_ProtectedModulesListLock.LockExclusive();
    {
        EnumProtectedModulesUnsafe([&](_In_ PPROTECTED_MODULE_ENTRY Entry) -> BOOLEAN {
            if (Entry->ProcessId == ProcessId)
            {
                WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "Erasing protected module 0x%-16llX from process id %d",
                          Entry->AllocatedBase, HandleToULong(ProcessId));

                // TODO: deref obj
                RemoveEntryList(&Entry->ListEntry);
                Memory::FreeFromNPagedLookaside(&g_ProtectedModulesLookasideList, Entry);
            }

            return FALSE;
        });

        g_ProtectedModulesListLock.Unlock();
    }
}

BOOLEAN IsInGameModuleMemoryRangeUnsafe(_In_ HANDLE ProcessId, _Out_opt_ PVOID *Object, _In_ PVOID BaseAddress,
                                        _In_opt_ SIZE_T Range)
{
    PAGED_CODE();
    NT_ASSERT(BaseAddress);

    if (!IsInitialized())
    {
        return FALSE;
    }

    const BOOLEAN result = EnumGameModulesUnsafe([&](_In_ PGAME_MODULE_ENTRY Entry) -> BOOLEAN {
        const ULONG_PTR rangeStart = reinterpret_cast<const ULONG_PTR>(BaseAddress);
        const ULONG_PTR rangeEnd = rangeStart + Range;

        if (Entry->ProcessId == ProcessId &&
            (rangeStart < Entry->BaseAddress + Entry->SizeOfImage && rangeEnd > Entry->BaseAddress))
        {
            if (Object)
            {
                // TODO: reference object
                *Object = Entry;
            }
            return TRUE;
        }
        return FALSE;
    });
    return result;
}

BOOLEAN IsInGameModuleMemoryRange(_In_ HANDLE ProcessId, _Out_opt_ PVOID *Object, _In_ PVOID BaseAddress,
                                  _In_opt_ SIZE_T Range)
{
    PAGED_CODE();
    NT_ASSERT(BaseAddress);

    if (!IsInitialized())
    {
        return FALSE;
    }

    g_GameModulesListLock.LockShared();
    SCOPE_EXIT
    {
        g_GameModulesListLock.Unlock();
    };

    return IsInGameModuleMemoryRangeUnsafe(ProcessId, Object, BaseAddress, Range);
}

BOOLEAN IsInProtectedModuleMemoryRangeUnsafe(_In_ HANDLE ProcessId, _Out_opt_ PVOID *Object, _In_ PVOID BaseAddress,
                                             _In_opt_ SIZE_T Range)
{
    PAGED_CODE();
    NT_ASSERT(BaseAddress);

    if (!IsInitialized())
    {
        return FALSE;
    }

    const BOOLEAN result = EnumProtectedModulesUnsafe([&](_In_ PPROTECTED_MODULE_ENTRY Entry) -> BOOLEAN {
        const ULONG_PTR rangeStart = reinterpret_cast<const ULONG_PTR>(BaseAddress);
        const ULONG_PTR rangeEnd = rangeStart + Range;

        if (Entry->ProcessId == ProcessId && rangeStart >= Entry->AllocatedBase &&
            rangeEnd <= Entry->AllocatedBase + Entry->RegionSize)
        {
            if (Object)
            {
                // TODO: reference object
                *Object = Entry;
            }
            return TRUE;
        }
        return FALSE;
    });
    return result;
}

BOOLEAN IsInProtectedModuleMemoryRange(_In_ HANDLE ProcessId, _Out_opt_ PVOID *Object, _In_ PVOID BaseAddress,
                                       _In_opt_ SIZE_T Range)
{
    PAGED_CODE();
    NT_ASSERT(BaseAddress);

    if (!IsInitialized())
    {
        return FALSE;
    }

    g_ProtectedModulesListLock.LockShared();
    SCOPE_EXIT
    {
        g_ProtectedModulesListLock.Unlock();
    };

    return IsInProtectedModuleMemoryRangeUnsafe(ProcessId, Object, BaseAddress, Range);
}

NTSTATUS CreateProtectedModule(_In_ HANDLE ProcessId, _In_ PVOID AllocationBase, _In_ SIZE_T RegionSize)
{
    PAGED_CODE();
    NT_ASSERT(AllocationBase);

    if (!IsInitialized())
    {
        return STATUS_UNSUCCESSFUL;
    }

    g_ProtectedModulesListLock.LockExclusive();

    SCOPE_EXIT
    {
        g_ProtectedModulesListLock.Unlock();
    };

    // Check if not already in list.
    //
    if (IsInProtectedModuleMemoryRangeUnsafe(ProcessId, nullptr, AllocationBase, RegionSize))
    {
        return STATUS_ALREADY_REGISTERED;
    }

    auto entry =
        reinterpret_cast<PPROTECTED_MODULE_ENTRY>(Memory::AllocFromNPagedLookaside(&g_ProtectedModulesLookasideList));
    if (!entry)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate memory for protected module entry!");

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry->ProcessId = ProcessId;
    entry->AllocatedBase = reinterpret_cast<ULONG_PTR>(AllocationBase);
    entry->RegionSize = RegionSize;

    InsertTailList(&g_ProtectedModulesList, &entry->ListEntry);

    return STATUS_SUCCESS;
}

NTSTATUS CreateGameModule(_In_ HANDLE ProcessId, _In_ PVOID MappedBase, _In_ SIZE_T MappedSize,
                          _In_ PUNICODE_STRING MappedName)
{
    PAGED_CODE();
    NT_ASSERT(MappedBase);
    NT_ASSERT(MappedName);

    if (!IsInitialized())
    {
        return STATUS_NOT_CAPABLE;
    }

    NTSTATUS status;

    PVOID fileBuffer = nullptr;
    SIZE_T fileSize = 0ULL;

    status = Misc::LoadFileInMemory(MappedName, &fileBuffer, &fileSize);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "LoadFileInMemory returned %!STATUS!", status);

        return status;
    }

    SCOPE_EXIT
    {
        Memory::FreePool(fileBuffer);
    };

    g_GameModulesListLock.LockExclusive();
    SCOPE_EXIT
    {
        g_GameModulesListLock.Unlock();
    };

    if (IsInGameModuleMemoryRangeUnsafe(ProcessId, nullptr, MappedBase, MappedSize))
    {
        return STATUS_INVALID_PARAMETER;
    }

    PUCHAR copyBaseAddress = nullptr;
    SIZE_T copyRegionSize = 0ULL;

    ULONG SizeOfImage = 0UL;
    ULONG BaseOfCode = 0UL;
    ULONG SizeOfCode = 0UL;
    ULONG_PTR Delta = 0ULL;

    __try
    {
        PIMAGE_NT_HEADERS nth = nullptr;

        status = RtlImageNtHeaderEx(0, fileBuffer, fileSize, &nth);
        if (!NT_SUCCESS(status))
        {
            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "RtlImageNtHeaderEx returned %!STATUS!", status);

            return STATUS_INVALID_IMAGE_FORMAT;
        }

        SizeOfImage = nth->OptionalHeader.SizeOfImage;
        BaseOfCode = nth->OptionalHeader.BaseOfCode;
        SizeOfCode = nth->OptionalHeader.SizeOfCode;

        //
        // Allocate a buffer with the image size
        //
        copyRegionSize = SizeOfImage;

        copyBaseAddress = reinterpret_cast<PUCHAR>(Memory::AllocNonPaged(copyRegionSize, Memory::TAG_IMAGE));
        if (!copyBaseAddress)
        {
            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate memory for backup module!");

            return STATUS_INSUFFICIENT_RESOURCES;
        }

        //
        // Copy headers
        //
        RtlCopyMemory(copyBaseAddress, fileBuffer, nth->OptionalHeader.SizeOfHeaders);

        //
        // Copy sections
        //
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nth);

        for (ULONG i = 0ul; i < nth->FileHeader.NumberOfSections; i++, section++)
        {
            const ULONG sectionSize = min(section->SizeOfRawData, section->Misc.VirtualSize);

            if (sectionSize)
            {
                RtlCopyMemory(reinterpret_cast<PUCHAR>(copyBaseAddress) + section->VirtualAddress,
                              reinterpret_cast<PUCHAR>(fileBuffer) + section->PointerToRawData, sectionSize);
            }
        }

        //
        // Relocate to new base
        //
        Delta = reinterpret_cast<ULONG_PTR>(MappedBase) - nth->OptionalHeader.ImageBase;

        if (!Misc::PE::RelocateImage(nth, copyBaseAddress, Delta))
        {
            ExRaiseStatus(STATUS_ILLEGAL_DLL_RELOCATION);
        }

        [[maybe_unused]] ULONG Crc1 = Crc32::Checksum(reinterpret_cast<PUCHAR>(MappedBase) + BaseOfCode, SizeOfCode);
        [[maybe_unused]] ULONG Crc2 =
            Crc32::Checksum(reinterpret_cast<PUCHAR>(copyBaseAddress) + BaseOfCode, SizeOfCode);

        DBG_PRINT("[Image copy code checksum] Original = 0x%08X Copy = 0x%08X", Crc1, Crc2);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();

        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Exception trying to create module copy %!STATUS!", status);

        if (copyBaseAddress)
        {
            Memory::FreePool(copyBaseAddress);
        }
        return status;
    }

    auto entry = reinterpret_cast<PGAME_MODULE_ENTRY>(Memory::AllocFromNPagedLookaside(&g_GameModulesLookasideList));
    if (!entry)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate memory for module entry!");

        Memory::FreePool(copyBaseAddress);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry->ProcessId = ProcessId;
    entry->BaseAddress = reinterpret_cast<ULONG_PTR>(MappedBase);
    entry->SizeOfImage = SizeOfImage;
    entry->BaseOfCode = BaseOfCode;
    entry->SizeOfCode = SizeOfCode;
    entry->CopyBaseAddress = reinterpret_cast<ULONG_PTR>(copyBaseAddress);
    entry->CopyAllocatedSize = copyRegionSize;

    InsertTailList(&g_GameModulesList, &entry->ListEntry);

#if DBG
    DBG_PRINT("[Game module] MappedBase = 0x%p SizeOfImage = 0x%08X BaseOfCode = 0x%08X "
              "SizeOfCode = 0x%08X BackupBaseAddress = 0x%p BackupAllocSize = "
              "0x%08llX Delta = 0x%016llX",
              MappedBase, SizeOfImage, BaseOfCode, SizeOfCode, copyBaseAddress, copyRegionSize, Delta);
#endif

    return STATUS_SUCCESS;
}

} // namespace Bypass