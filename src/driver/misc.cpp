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

namespace Misc
{
namespace Module
{
PLDR_DATA_TABLE_ENTRY32 GetModuleByNameWow64(_In_ PWCHAR ModuleName)
{
    PAGED_CODE();
    NT_ASSERT(ModuleName);

    UNICODE_STRING moduleNameStr{};
    RtlInitUnicodeString(&moduleNameStr, ModuleName);

    PPEB32 peb32 = reinterpret_cast<PPEB32>(PsGetProcessWow64Process(PsGetCurrentProcess()));
    if (!peb32)
    {
        return nullptr;
    }

    PLIST_ENTRY32 list = &(((PPEB_LDR_DATA32)peb32->Ldr)->InLoadOrderModuleList);
    for (PLIST_ENTRY32 entry = (PLIST_ENTRY32)list->Flink; entry != list;)
    {
        PLDR_DATA_TABLE_ENTRY32 mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

        if (mod->BaseDllName.Buffer && mod->BaseDllName.Length > sizeof(WCHAR))
        {
            UNICODE_STRING modBaseDllName{};
            RtlInitUnicodeString(&modBaseDllName, (PCWSTR)mod->BaseDllName.Buffer);

            if (!RtlCompareUnicodeString(&modBaseDllName, &moduleNameStr, TRUE))
            {
                return mod;
            }
        }

        entry = (PLIST_ENTRY32)mod->InLoadOrderLinks.Flink;
    }

    return nullptr;
}

PLDR_DATA_TABLE_ENTRY GetModuleByName(_In_ PWCHAR ModuleName)
{
    PAGED_CODE();
    NT_ASSERT(ModuleName);

    UNICODE_STRING moduleNameStr{};
    RtlInitUnicodeString(&moduleNameStr, ModuleName);

    PPEB peb = PsGetProcessPeb(PsGetCurrentProcess());
    if (!peb)
    {
        return nullptr;
    }

    PLIST_ENTRY list = &(peb->Ldr->InLoadOrderModuleList);
    for (PLIST_ENTRY entry = list->Flink; entry != list;)
    {
        PLDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (mod->BaseDllName.Buffer && mod->BaseDllName.Length > sizeof(WCHAR))
        {
            if (!RtlCompareUnicodeString(&mod->BaseDllName, &moduleNameStr, TRUE))
            {
                return mod;
            }
        }

        entry = mod->InLoadOrderLinks.Flink;
    }

    return nullptr;
}

PVOID GetSystemModuleBase(_In_ LPCSTR ModuleName, _Out_opt_ PULONG ModuleSize)
{
    PAGED_CODE();
    NT_ASSERT(ModuleName);

    ULONG bufferSize = 0;
    PRTL_PROCESS_MODULES moduleInfo = NULL;
    NTSTATUS status;

    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "ZwQuerySystemInformation returned %!STATUS!", status);
        return nullptr;
    }

    bufferSize *= 2;

    moduleInfo = reinterpret_cast<PRTL_PROCESS_MODULES>(::Memory::AllocNonPaged(bufferSize, ::Memory::TAG_DEFAULT));
    if (!moduleInfo)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate %u bytes for SystemModuleInformation", bufferSize);
        return nullptr;
    }

    SCOPE_EXIT
    {
        ::Memory::FreePool(moduleInfo);
    };

    status = ZwQuerySystemInformation(SystemModuleInformation, moduleInfo, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "ZwQuerySystemInformation returned %!STATUS!", status);
        return nullptr;
    }

    for (ULONG i = 0; i < moduleInfo->NumberOfModules; i++)
    {
        PRTL_PROCESS_MODULE_INFORMATION entry = &moduleInfo->Modules[i];

        if (!_stricmp((PCHAR)entry->FullPathName + entry->OffsetToFileName, ModuleName))
        {
            if (ModuleSize)
            {
                *ModuleSize = entry->ImageSize;
            }

            return entry->ImageBase;
        }
    }
    return nullptr;
}

PVOID GetNtoskrnlBase(_Out_opt_ PULONG ModuleSize)
{
    PAGED_CODE();

    ULONG bufferSize = 0;
    PRTL_PROCESS_MODULES moduleInfo = NULL;
    NTSTATUS status;

    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "ZwQuerySystemInformation returned %!STATUS!", status);
        return nullptr;
    }

    bufferSize *= 2;

    moduleInfo = reinterpret_cast<PRTL_PROCESS_MODULES>(::Memory::AllocNonPaged(bufferSize, ::Memory::TAG_DEFAULT));
    if (!moduleInfo)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate %u bytes for SystemModuleInformation", bufferSize);
        return nullptr;
    }

    SCOPE_EXIT
    {
        ::Memory::FreePool(moduleInfo);
    };

    status = ZwQuerySystemInformation(SystemModuleInformation, moduleInfo, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "ZwQuerySystemInformation returned %!STATUS!", status);
        return nullptr;
    }

    PRTL_PROCESS_MODULE_INFORMATION entry = &moduleInfo->Modules[0];

    if (ModuleSize)
    {
        *ModuleSize = entry->ImageSize;
    }

    return entry->ImageBase;
}
} // namespace Module

namespace PE
{
PIMAGE_SECTION_HEADER FindSection(_In_ PIMAGE_NT_HEADERS nth, _In_ const char *sectionName)
{
    PAGED_CODE();
    NT_ASSERT(nth);
    NT_ASSERT(sectionName);

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nth);

    for (ULONG i = 0; i < nth->FileHeader.NumberOfSections; i++, sec++)
    {
        if (!strncmp((const CHAR *)sec->Name, sectionName, IMAGE_SIZEOF_SHORT_NAME))
        {
            return sec;
        }
    }
    return nullptr;
}

BOOLEAN GetSectionFromVirtualAddress(_In_ PVOID imageBase, _In_ PVOID routineAddress, _Out_ PULONG SectionSize,
                                     _Out_ PUCHAR *SectionVa)
{
    PAGED_CODE();
    NT_ASSERT(SectionSize);
    NT_ASSERT(SectionVa);

    PUCHAR imageBasePtr = reinterpret_cast<PUCHAR>(imageBase);
    PUCHAR routineAddressPtr = reinterpret_cast<PUCHAR>(routineAddress);

    if (routineAddressPtr < imageBasePtr)
    {
        return FALSE;
    }

    __try
    {
        PIMAGE_NT_HEADERS nth = RtlImageNtHeader(imageBase);
        if (!nth)
        {
            return FALSE;
        }

        ULONG rva = PtrToUlong(reinterpret_cast<PVOID>(routineAddressPtr - imageBasePtr));

        IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nth);

        for (auto i = 0ul; i < nth->FileHeader.NumberOfSections; i++, sec++)
        {
            if (rva >= sec->VirtualAddress && rva <= sec->VirtualAddress + sec->Misc.VirtualSize)
            {
                *SectionSize = sec->SizeOfRawData;
                *SectionVa = imageBasePtr + sec->VirtualAddress;

                return TRUE;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Exception trying to process image sections %!STATUS!",
                  GetExceptionCode());
    }
    return FALSE;
}

BOOLEAN RelocateImage(_In_ PIMAGE_NT_HEADERS Nth, _In_ void *ImageBase, _In_ ULONG_PTR Delta)
{
    PAGED_CODE();
    NT_ASSERT(Nth);
    NT_ASSERT(ImageBase);

    if (Delta == 0)
    {
        // Relocation not needed
        return TRUE;
    }
    else if (!BooleanFlagOn(Nth->OptionalHeader.DllCharacteristics, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Cannot proceed because the DLL does not support relocations.");
        return FALSE;
    }

    ULONG directorySize = 0UL;
    auto *baseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
        RtlImageDirectoryEntryToData(ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &directorySize));
    if (!baseRelocation)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Invalid relocation data directory!");
        return TRUE;
    }

    while (baseRelocation->VirtualAddress)
    {
        if (baseRelocation->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
        {
            const ULONG entriesCount = (baseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            auto relocInfo = reinterpret_cast<PWORD>(baseRelocation + 1);

            for (auto i = 0ul; i < entriesCount; i++)
            {
                int Type = relocInfo[i] >> 12;
                int Offset = relocInfo[i] & 0xfff;

                PUCHAR relocAddr = reinterpret_cast<PUCHAR>(ImageBase) + baseRelocation->VirtualAddress + Offset;

                switch (Type)
                {
                case IMAGE_REL_BASED_LOW: {
                    *((UINT16 *)relocAddr) += LOWORD(Delta);
                    break;
                }
                case IMAGE_REL_BASED_HIGH: {
                    *((UINT16 *)relocAddr) += HIWORD(Delta);
                    break;
                }
                case IMAGE_REL_BASED_HIGHLOW: {
                    *((UINT32 *)relocAddr) += (INT32)Delta;
                    break;
                }
                case IMAGE_REL_BASED_DIR64: {
                    *((ULONG64 *)relocAddr) += Delta;
                    break;
                }
                default:
                    break;
                }
            }
        }
        baseRelocation = reinterpret_cast<IMAGE_BASE_RELOCATION *>(reinterpret_cast<PUCHAR>(baseRelocation) +
                                                                   baseRelocation->SizeOfBlock);
    }

    return TRUE;
}

PVOID GetProcAddress(_In_ void *imageBase, _In_ const char *procName)
{
    PAGED_CODE();
    NT_ASSERT(imageBase);
    NT_ASSERT(procName);

    ULONG directorySize = 0UL;
    auto *exportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        RtlImageDirectoryEntryToData(imageBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &directorySize));
    if (!exportDirectory)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Invalid export data directory!");
        return nullptr;
    }

    PUCHAR imageBasePtr = reinterpret_cast<PUCHAR>(imageBase);

    auto functions = reinterpret_cast<PULONG>(imageBasePtr + exportDirectory->AddressOfFunctions);
    auto names = reinterpret_cast<PULONG>(imageBasePtr + exportDirectory->AddressOfNames);
    auto ordinals = reinterpret_cast<PUSHORT>(imageBasePtr + exportDirectory->AddressOfNameOrdinals);

    PVOID exportAddress = nullptr;

    // Handle ordinals
    //
    const bool isOrdinal = reinterpret_cast<ULONG_PTR>(procName) <= 0xFFFF;

    if (isOrdinal)
    {
        const auto ordinal = static_cast<USHORT>(reinterpret_cast<ULONG_PTR>(procName));
        if (ordinal < exportDirectory->Base || ordinal >= exportDirectory->NumberOfFunctions)
        {
            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Invalid ordinal %u", ordinal);
            return nullptr;
        }

        exportAddress = imageBasePtr + functions[ordinal - exportDirectory->Base];
    }
    else
    {
        const ULONG numberOfNames = exportDirectory->NumberOfNames;

        for (auto i = 0ul; i < numberOfNames; ++i)
        {
            auto name = reinterpret_cast<LPCSTR>(imageBasePtr + names[i]);

            if (!strcmp(procName, name))
            {
                exportAddress = imageBasePtr + functions[ordinals[i]];
                break;
            }
        }
    }

    // Handle forwarded export
    //
    if (exportAddress >= exportDirectory && exportAddress < (reinterpret_cast<PUCHAR>(exportDirectory) + directorySize))
    {
        auto forwardName = reinterpret_cast<LPCSTR>(exportAddress);
        LPCSTR dotPos = strchr(forwardName, '.');

        if (!dotPos)
        {
            return nullptr;
        }

        WCHAR forwardModuleName[256]{L'\0'};

        for (auto i = 0; i < 255 && forwardName != dotPos; ++i, ++forwardName)
        {
            forwardModuleName[i] = *forwardName;
        }

        if (!NT_SUCCESS(RtlStringCchCatW(forwardModuleName, ARRAYSIZE(forwardModuleName) - 1, L".dll")))
        {
            return nullptr;
        }

        LPCSTR forwardExportName = ++forwardName;
        if (*forwardExportName == '#')
        {
            ULONG value = 0;

            if (!NT_SUCCESS(RtlCharToInteger(++forwardExportName, 0, &value)))
            {
                return nullptr;
            }

            forwardExportName = reinterpret_cast<LPCSTR>(static_cast<ULONG_PTR>(value));
        }

        DBG_PRINT("Forwarded -> %ls!%s", forwardModuleName, forwardExportName);

        PLDR_DATA_TABLE_ENTRY forwardModule = Misc::Module::GetModuleByName(forwardModuleName);
        if (forwardModule == nullptr)
        {
            return nullptr;
        }
        return GetProcAddress(forwardModule->DllBase, forwardExportName);
    }
    return exportAddress;
}
}; // namespace PE

namespace Memory
{
#define INRANGE(x, a, b) (x >= a && x <= b)
#define getBits(x) (INRANGE(x, '0', '9') ? (x - '0') : ((x & (~0x20)) - 'A' + 0xa))
#define getByte(x) (getBits(x[0]) << 4 | getBits(x[1]))

PUCHAR FindPattern(_In_ PUCHAR searchAddress, _In_ const size_t searchSize, _In_ const char *pattern)
{
    NT_ASSERT(searchAddress);
    NT_ASSERT(pattern);

    auto pat = reinterpret_cast<const unsigned char *>(pattern);
    PUCHAR firstMatch = nullptr;

    for (PUCHAR cur = searchAddress; cur < searchAddress + searchSize - strlen(pattern); ++cur)
    {
        if (*(PUCHAR)pat == static_cast<UCHAR>('\?') || *cur == getByte(pat))
        {
            if (!firstMatch)
            {
                firstMatch = cur;
            }

            pat += (*(USHORT *)pat == static_cast<USHORT>('\?\?') || *(PUCHAR)pat != static_cast<UCHAR>('\?')) ? 2 : 1;

            if (!*pat)
            {
                return firstMatch;
            }

            pat++;

            if (!*pat)
            {
                return firstMatch;
            }
        }
        else if (firstMatch)
        {
            cur = firstMatch;
            pat = reinterpret_cast<const unsigned char *>(pattern);
            firstMatch = nullptr;
        }
    }
    return NULL;
}

PUCHAR FindPattern(_In_ PVOID imageBase, _In_ const char *sectionName, _In_ const char *pattern)
{
    NT_ASSERT(imageBase);
    NT_ASSERT(sectionName);
    NT_ASSERT(pattern);

    __try
    {
        PIMAGE_NT_HEADERS64 nth = RtlImageNtHeader(imageBase);
        if (!nth)
        {
            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to parse NT headers!");
            return nullptr;
        }

        PIMAGE_SECTION_HEADER section = PE::FindSection(nth, sectionName);
        if (!section)
        {
            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Section %s not found!", sectionName);
            return nullptr;
        }

        auto *searchAddress = reinterpret_cast<PUCHAR>(imageBase) + section->VirtualAddress;

        return FindPattern(searchAddress, section->Misc.VirtualSize, pattern);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Exception trying to find pattern %!STATUS!", GetExceptionCode());
    }
    return nullptr;
}

NTSTATUS GetMappedFilename(_In_ PVOID BaseAddress, _Out_ PUNICODE_STRING *MappedName)
{
    PAGED_CODE();
    NT_ASSERT(MappedName);

    *MappedName = nullptr;

    NTSTATUS Status;

    constexpr SIZE_T bufferLen = 1024;

    auto pBuffer = ::Memory::AllocNonPaged(bufferLen, ::Memory::TAG_DEFAULT);
    if (!pBuffer)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate %u bytes for mapped file name!", bufferLen);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = ZwQueryVirtualMemory(ZwCurrentProcess(), BaseAddress,
                                  static_cast<MEMORY_INFORMATION_CLASS>(MemoryMappedFilenameInformation), pBuffer,
                                  bufferLen, nullptr);

    if (!NT_SUCCESS(Status))
    {
        ::Memory::FreePool(pBuffer);

        return Status;
    }

    *MappedName = reinterpret_cast<PUNICODE_STRING>(pBuffer);

    return STATUS_SUCCESS;
}

NTSTATUS
WriteReadOnlyMemory(_Inout_ PVOID Destination, _Inout_ PVOID Source, _In_ SIZE_T Size)
{
    PAGED_CODE();
    NT_ASSERT(Destination);
    NT_ASSERT(Source);

    NTSTATUS Status = STATUS_SUCCESS;
    PVOID Mapped = nullptr;

    PMDL Mdl = IoAllocateMdl(Destination, static_cast<ULONG>(Size), 0, 0, nullptr);
    if (!Mdl)
    {
        return STATUS_NO_MEMORY;
    }

    __try
    {
        MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        IoFreeMdl(Mdl);
        return GetExceptionCode();
    }

    CSHORT OriginalMdlFlags = Mdl->MdlFlags;
    Mdl->MdlFlags |= MDL_PAGES_LOCKED;
    Mdl->MdlFlags &= ~MDL_SOURCE_IS_NONPAGED_POOL;

    Mapped = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    if (!Mapped)
    {
        Status = STATUS_NONE_MAPPED;
        goto Exit;
    }

    Status = MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);
    if (!NT_SUCCESS(Status))
    {
        goto Exit;
    }

    RtlCopyMemory(Mapped, Source, Size);

Exit:
    if (Mapped)
    {
        MmUnmapLockedPages(Mapped, Mdl);
    }

    MmUnlockPages(Mdl);

    Mdl->MdlFlags = OriginalMdlFlags;
    IoFreeMdl(Mdl);

    return Status;
}

ULONG_PTR FindCodeCaveAddress(_In_ ULONG_PTR CodeStart, _In_ ULONG CodeSize, _In_ ULONG CaveSize)
{
    auto *Code = reinterpret_cast<PUCHAR>(CodeStart);

    for (auto i = 0ul, j = 0ul; i < CodeSize; i++)
    {
        if (Code[i] == 0xCC)
        {
            j++;
        }
        else
        {
            j = 0;
        }

        if (j == CaveSize)
        {
            return CodeStart + i - CaveSize + 1;
        }
    }

    return NULL;
}
} // namespace Memory

namespace String
{
PWCHAR wcsistr(_In_ PWCHAR wcs1, _In_ LPCWSTR wcs2)
{
    const wchar_t *s1, *s2;
    const wchar_t l = towlower(*wcs2);
    const wchar_t u = towupper(*wcs2);

    if (!*wcs2)
    {
        return wcs1;
    }

    for (; *wcs1; ++wcs1)
    {
        if (*wcs1 == l || *wcs1 == u)
        {
            s1 = wcs1 + 1;
            s2 = wcs2 + 1;

            while (*s1 && *s2 && towlower(*s1) == towlower(*s2))
                ++s1, ++s2;

            if (!*s2)
                return wcs1;
        }
    }

    return NULL;
}
} // namespace String

VOID DelayThread(_In_ LONG64 Milliseconds, _In_ BOOLEAN Alertable)
{
    PAGED_CODE();

    LARGE_INTEGER Delay;
    Delay.QuadPart = -Milliseconds * 10000;
    KeDelayExecutionThread(KernelMode, Alertable, &Delay);
}

HANDLE GetProcessIDFromProcessHandle(_In_ HANDLE ProcessHandle)
{
    PAGED_CODE();

    if (ProcessHandle == ZwCurrentProcess())
    {
        return PsGetCurrentProcessId();
    }

    HANDLE Pid = (HANDLE)(LONG_PTR)-1;
    PEPROCESS Process = nullptr;

    const NTSTATUS status =
        ObReferenceObjectByHandle(ProcessHandle, PROCESS_QUERY_INFORMATION, *PsProcessType, ExGetPreviousMode(),
                                  reinterpret_cast<PVOID *>(&Process), nullptr);
    if (NT_SUCCESS(status))
    {
        Pid = PsGetProcessId(Process);
        ObDereferenceObject(Process);
    }
    return Pid;
}

HANDLE GetProcessIDFromThreadHandle(_In_ HANDLE ThreadHandle)
{
    PAGED_CODE();

    if (ThreadHandle == ZwCurrentThread())
    {
        return PsGetThreadProcessId(PsGetCurrentThread());
    }

    HANDLE Pid = (HANDLE)(LONG_PTR)-1;
    PETHREAD Thread = nullptr;

    const NTSTATUS status = ObReferenceObjectByHandle(ThreadHandle, THREAD_QUERY_INFORMATION, *PsThreadType,
                                                      ExGetPreviousMode(), reinterpret_cast<PVOID *>(&Thread), nullptr);
    if (NT_SUCCESS(status))
    {
        Pid = PsGetThreadProcessId(Thread);
        ObDereferenceObject(Thread);
    }
    return Pid;
}

NTSTATUS LoadFileInMemory(_In_ PUNICODE_STRING FileName, _Out_ PVOID *FileBuffer, _Out_ PSIZE_T FileSize)
{
    PAGED_CODE();
    NT_ASSERT(!KeAreAllApcsDisabled());
    NT_ASSERT(FileName);
    NT_ASSERT(FileBuffer);
    NT_ASSERT(FileSize);

    *FileBuffer = nullptr;
    *FileSize = 0ULL;

    IO_STATUS_BLOCK iosb{};
    OBJECT_ATTRIBUTES oa{};
    InitializeObjectAttributes(&oa, FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE fileHandle = nullptr;

    NTSTATUS status =
        ZwCreateFile(&fileHandle, FILE_READ_ACCESS, &oa, &iosb, nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
                     FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0ul);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "ZwCreateFile returned %!STATUS!", status);
        return status;
    }

    SCOPE_EXIT
    {
        ZwClose(fileHandle);
    };

    RtlZeroMemory(&iosb, sizeof(iosb));

    FILE_STANDARD_INFORMATION fsi{};
    status = ZwQueryInformationFile(fileHandle, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "ZwQueryInformationFile returned %!STATUS!", status);
        return status;
    }

    const ULONG fileSize = fsi.EndOfFile.LowPart;

    auto fileBuffer = reinterpret_cast<PUCHAR>(::Memory::AllocNonPaged(fileSize, ::Memory::TAG_FILE));
    if (!fileBuffer)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate %u bytes to read file!", fileSize);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(&iosb, sizeof(iosb));

    status = ZwReadFile(fileHandle, nullptr, nullptr, nullptr, &iosb, fileBuffer, fileSize, nullptr, nullptr);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "ZwReadFile returned %!STATUS!", status);

        ::Memory::FreePool(fileBuffer);
        return status;
    }

    *FileBuffer = fileBuffer;
    *FileSize = fileSize;

    return STATUS_SUCCESS;
}
} // namespace Misc