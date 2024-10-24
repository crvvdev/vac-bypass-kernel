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

namespace SyscallTable
{
NTSTATUS InitializeSyscallTable();

_IRQL_always_function_max_(DISPATCH_LEVEL) RTL_GENERIC_COMPARE_RESULTS
    CompareSyscallListAvl(PRTL_AVL_TABLE Table, PVOID a1, PVOID a2);
_IRQL_always_function_max_(DISPATCH_LEVEL) VOID *AllocateSyscallListAvl(_In_ RTL_AVL_TABLE *Table, _In_ CLONG Size);
_IRQL_always_function_max_(DISPATCH_LEVEL) VOID
    FreeSyscallListAvl(_In_ RTL_AVL_TABLE *Table, _In_ __drv_freesMem(Mem) _Post_invalid_ PVOID Buffer);

bool g_initialized = false;

const bool IsInitialized()
{
    return g_initialized;
}

NTSTATUS Initialize()
{
    PAGED_PASSIVE();

    if (g_initialized)
    {
        return STATUS_ALREADY_INITIALIZED;
    }

    RtlInitializeGenericTableAvl(&g_SyscallAvlTable, CompareSyscallListAvl, AllocateSyscallListAvl, FreeSyscallListAvl,
                                 NULL);

    const NTSTATUS status = InitializeSyscallTable();
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to initialize syscall table!");

        return STATUS_UNSUCCESSFUL;
    }

    g_initialized = true;

    return STATUS_SUCCESS;
}

void Unitialize()
{
    PAGED_PASSIVE();

    if (!g_initialized)
    {
        return;
    }

    while (!RtlIsGenericTableEmptyAvl(&g_SyscallAvlTable))
    {
        PVOID Entry = RtlGetElementGenericTableAvl(&g_SyscallAvlTable, 0);
        RtlDeleteElementGenericTableAvl(&g_SyscallAvlTable, Entry);
    }

    g_initialized = false;

    WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL, "Unitialized SyscallTable");
}

_IRQL_always_function_max_(DISPATCH_LEVEL) RTL_GENERIC_COMPARE_RESULTS
    CompareSyscallListAvl(PRTL_AVL_TABLE Table, PVOID a1, PVOID a2)
{
    UNREFERENCED_PARAMETER(Table);

    const auto lhs = reinterpret_cast<PSYSTEM_SERVICE_INFO>(a1);
    const auto rhs = reinterpret_cast<PSYSTEM_SERVICE_INFO>(a2);

    if (lhs->ServiceHash < rhs->ServiceHash)
    {
        return GenericLessThan;
    }
    else if (lhs->ServiceHash > rhs->ServiceHash)
    {
        return GenericGreaterThan;
    }
    else
    {
        return GenericEqual;
    }
}

_IRQL_always_function_max_(DISPATCH_LEVEL) VOID *AllocateSyscallListAvl(_In_ RTL_AVL_TABLE *Table, _In_ CLONG Size)
{
    UNREFERENCED_PARAMETER(Table);
    return Memory::AllocNonPaged(Size, Memory::TAG_SYSCALL_TABLE);
}

_IRQL_always_function_max_(DISPATCH_LEVEL) VOID
    FreeSyscallListAvl(_In_ RTL_AVL_TABLE *Table, _In_ __drv_freesMem(Mem) _Post_invalid_ PVOID Buffer)
{
    UNREFERENCED_PARAMETER(Table);
    Memory::FreePool(Buffer);
}

ULONG_PTR GetRoutineFromSsdtTable(const ULONG ServiceIndex)
{
    PAGED_PASSIVE();

    auto serviceDescriptorTable =
        reinterpret_cast<PSERVICE_DESCRIPTOR_TABLE>(Dynamic::g_DynamicContext.Kernel.Address.KeServiceDescriptorTable);
    ULONG_PTR SsdtBase = reinterpret_cast<ULONG_PTR>(serviceDescriptorTable->NtosTable.ServiceTableBase);
    const ULONG Offset = serviceDescriptorTable->NtosTable.ServiceTableBase[ServiceIndex] >> 4;

    return SsdtBase + Offset;
}

void SyscallTableInsertToTable(_In_ const FNV1A_t ServiceHash, _In_ const ULONG ServiceIndex)
{
    PAGED_PASSIVE();

    SYSTEM_SERVICE_INFO entry{};
    entry.ServiceHash = ServiceHash;
    entry.ServiceIndex = ServiceIndex;
    entry.RoutineAddress = GetRoutineFromSsdtTable(ServiceIndex);

    RtlInsertElementGenericTableAvl(&g_SyscallAvlTable, &entry, sizeof(SYSTEM_SERVICE_INFO), NULL);
}

BOOLEAN FindServiceInTable(_In_ const FNV1A_t ServiceHash, _Out_opt_ PULONG ServiceIndex,
                           _Out_ PULONG_PTR RoutineAddress)
{
    PAGED_PASSIVE();
    NT_ASSERT(RoutineAddress);

    *RoutineAddress = NULL;

    if (!IsInitialized())
    {
        return FALSE;
    }

    SYSTEM_SERVICE_INFO searchKey = {};
    searchKey.ServiceHash = ServiceHash;

    auto entry =
        reinterpret_cast<PSYSTEM_SERVICE_INFO>(RtlLookupElementGenericTableAvl(&g_SyscallAvlTable, &searchKey));
    if (!entry)
    {
        return FALSE;
    }

    *RoutineAddress = entry->RoutineAddress;

    if (ServiceIndex)
    {
        *ServiceIndex = entry->ServiceIndex;
    }

    return TRUE;
}

NTSTATUS DumpSyscallTable(_In_ PUCHAR mappedBase)
{
    PAGED_PASSIVE();
    NT_ASSERT(mappedBase);

    NTSTATUS status;

    __try
    {
        ULONG directorySize = 0UL;

        const auto exportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
            RtlImageDirectoryEntryToData(mappedBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &directorySize));
        if (!exportDirectory)
        {
            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Invalid export data directory!");
            return STATUS_UNSUCCESSFUL;
        }

        const PULONG addressOfNames = reinterpret_cast<PULONG>(mappedBase + exportDirectory->AddressOfNames);
        const PUSHORT addressOfNameOrdinals =
            reinterpret_cast<PUSHORT>(mappedBase + exportDirectory->AddressOfNameOrdinals);
        const PULONG addressOfFunctions = reinterpret_cast<PULONG>(mappedBase + exportDirectory->AddressOfFunctions);

        for (auto i = 0ul; i < exportDirectory->NumberOfNames; i++)
        {
            auto currentExportName = reinterpret_cast<LPCSTR>(mappedBase + addressOfNames[i]);
            auto procedureAddress = reinterpret_cast<PUCHAR>(mappedBase + addressOfFunctions[addressOfNameOrdinals[i]]);

            auto IsSyscall = [&]() -> BOOLEAN {
                return (procedureAddress[0] == 0x4C && procedureAddress[1] == 0x8B && procedureAddress[2] == 0xD1 &&
                        procedureAddress[3] == 0xB8);
            };

            if (IsSyscall())
            {
                ULONG64 function_data = *(ULONG64 *)procedureAddress;
                ULONG serviceIndex = (function_data >> 8 * 4);
                serviceIndex = serviceIndex & 0xfff;

                const FNV1A_t serviceHash = FNV1A::Hash(currentExportName);

                // DBG_PRINT("ServiceName %s Index %d Hash %lld", currentExportName, serviceIndex, serviceHash);

                SyscallTableInsertToTable(serviceHash, serviceIndex);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to dump syscalls, exception %!STATUS!", status);
        return status;
    }
    return STATUS_SUCCESS;
}

NTSTATUS InitializeSyscallTable()
{
    PAGED_PASSIVE();

    NTSTATUS status;

    OBJECT_ATTRIBUTES oa{};
    UNICODE_STRING sectionName{};

    RtlInitUnicodeString(&sectionName, L"\\KnownDlls\\ntdll.dll");
    InitializeObjectAttributes(&oa, &sectionName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE sectionHandle = NULL;

    status = ZwOpenSection(&sectionHandle, SECTION_MAP_READ | SECTION_QUERY, &oa);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "ZwOpenSection failed %!STATUS!", status);
        return status;
    }

    SCOPE_EXIT
    {
        ZwClose(sectionHandle);
    };

    PVOID section = nullptr;
    status = ObReferenceObjectByHandle(sectionHandle, 0, *MmSectionObjectType, KernelMode,
                                       reinterpret_cast<PVOID *>(&section), nullptr);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "ObReferenceObjectByHandle failed %!STATUS!", status);
        return status;
    }

    SCOPE_EXIT
    {
        ObDereferenceObject(section);
    };

    PVOID MappedBase = nullptr;
    SIZE_T ViewSize = 0ULL;

    status = MmMapViewInSystemSpace(section, &MappedBase, &ViewSize);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "MmMapViewInSessionSpace failed %!STATUS!", status);
        return status;
    }

    SCOPE_EXIT
    {
        MmUnmapViewInSystemSpace(MappedBase);
    };

    return DumpSyscallTable(reinterpret_cast<PUCHAR>(MappedBase));
}

} // namespace SyscallTable