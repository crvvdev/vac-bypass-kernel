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

namespace Inject
{
ULONG CastSectionProtection(IN ULONG characteristics, IN BOOLEAN noDEP)
{
    ULONG dwResult = PAGE_NOACCESS;

    if (characteristics & IMAGE_SCN_MEM_DISCARDABLE)
    {
        dwResult = PAGE_NOACCESS;
    }
    else if (characteristics & IMAGE_SCN_MEM_EXECUTE)
    {
        if (characteristics & IMAGE_SCN_MEM_WRITE)
            dwResult = noDEP ? PAGE_READWRITE : PAGE_EXECUTE_READWRITE;
        else if (characteristics & IMAGE_SCN_MEM_READ)
            dwResult = noDEP ? PAGE_READONLY : PAGE_EXECUTE_READ;
        else
            dwResult = noDEP ? PAGE_READONLY : PAGE_EXECUTE;
    }
    else
    {
        if (characteristics & IMAGE_SCN_MEM_WRITE)
            dwResult = PAGE_READWRITE;
        else if (characteristics & IMAGE_SCN_MEM_READ)
            dwResult = PAGE_READONLY;
        else
            dwResult = PAGE_NOACCESS;
    }

    return dwResult;
}

NTSTATUS CreateThread(_In_ PVOID StartAddress, _In_opt_ PVOID StartParameter, _Out_ PHANDLE ThreadHandle)
{
    CLIENT_ID clientId{};

    const NTSTATUS status = RtlCreateUserThread(ZwCurrentProcess(), nullptr, FALSE, 0UL, 0UL, 0UL, StartAddress,
                                                StartParameter, ThreadHandle, &clientId);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "RtlCreateUserThread returned %!STATUS!", status);
        return status;
    }
    return status;
}

NTSTATUS InjectImage(_In_ PVOID imageBase, _In_ SIZE_T imageSize)
{
    PAGED_CODE();
    NT_ASSERT(imageBase);

    NTSTATUS status;

    const HANDLE currentProcessId = PsGetCurrentProcessId();

    bool shouldFreeImage = true;

    PVOID allocatedImageBase = nullptr;
    SIZE_T allocatedImageRegionSize = 0ULL;

    PVOID exceptionHandlerBase = nullptr;
    SIZE_T exceptionHandlerRegionSize = 0x1000;

    PVOID manualMapStubBase = nullptr;
    SIZE_T manualMapStubRegionSize = 0x1000;

    ULONG oldAccess = 0;

    SCOPE_EXIT
    {
        if (shouldFreeImage)
        {
            if (allocatedImageBase)
            {
                allocatedImageRegionSize = 0;
                ZwFreeVirtualMemory(ZwCurrentProcess(), &allocatedImageBase, &allocatedImageRegionSize, MEM_RELEASE);

                allocatedImageBase = nullptr;
            }

            if (exceptionHandlerBase)
            {
                exceptionHandlerRegionSize = 0;
                ZwFreeVirtualMemory(ZwCurrentProcess(), &exceptionHandlerBase, &exceptionHandlerRegionSize,
                                    MEM_RELEASE);

                exceptionHandlerBase = nullptr;
            }
        }

        if (exceptionHandlerBase)
        {
            exceptionHandlerRegionSize = 0;
            ZwFreeVirtualMemory(ZwCurrentProcess(), &exceptionHandlerBase, &exceptionHandlerRegionSize, MEM_RELEASE);

            exceptionHandlerBase = nullptr;
        }
    };

    // Verify if image is supported
    //
    PIMAGE_NT_HEADERS nth = nullptr;

    status = RtlImageNtHeaderEx(0, imageBase, imageSize, &nth);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "RtlImageNtHeaderEx returned %!STATUS!", status);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (BooleanFlagOn(nth->OptionalHeader.Subsystem, IMAGE_SUBSYSTEM_NATIVE))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Image subsystem not supported!");
        return STATUS_IMAGE_SUBSYSTEM_NOT_PRESENT;
    }

    // Try obtaining all required modules first
    //
    PLDR_DATA_TABLE_ENTRY ntdllEntry = Misc::Module::GetModuleByName(L"ntdll.dll");
    if (!ntdllEntry)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to locate ntdll.dll in process!");
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    PLDR_DATA_TABLE_ENTRY kernel32Entry = Misc::Module::GetModuleByName(L"kernel32.dll");
    if (!kernel32Entry)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to locate kernel32.dll in process!");
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    // Now obtain the required exported procedures
    //
    PVOID LdrpHandleTlsData = Misc::Memory::FindPattern(
        ntdllEntry->DllBase, ".text", "48 89 5C 24 10 48 89 74 24 18 48 89 7C 24 20 41 54 41 56 41 57 48 81 EC 00");
    if (!LdrpHandleTlsData)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Procedure LdrpHandleTlsData not found!");
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "LdrpHandleTlsData 0x%p", LdrpHandleTlsData);

    PVOID RtlAddVectoredExceptionHandler =
        Misc::PE::GetProcAddress(ntdllEntry->DllBase, "RtlAddVectoredExceptionHandler");
    if (!RtlAddVectoredExceptionHandler)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Procedure RtlAddVectoredExceptionHandler not found!");
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "RtlAddVectoredExceptionHandler 0x%p", RtlAddVectoredExceptionHandler);

    PVOID RtlAddFunctionTable = Misc::PE::GetProcAddress(kernel32Entry->DllBase, "RtlAddFunctionTable");
    if (!RtlAddFunctionTable)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Procedure RtlAddFunctionTable not found!");
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "RtlAddFunctionTable 0x%p", RtlAddFunctionTable);

    PVOID LoadLibraryA = Misc::PE::GetProcAddress(kernel32Entry->DllBase, "LoadLibraryA");
    if (!LoadLibraryA)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Procedure LoadLibraryA not found!");
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "LoadLibraryA 0x%p", LoadLibraryA);

    PVOID GetProcAddress = Misc::PE::GetProcAddress(kernel32Entry->DllBase, "GetProcAddress");
    if (!GetProcAddress)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Procedure GetProcAddress not found!");
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "GetProcAddress 0x%p", GetProcAddress);

    // Allocate memory for image
    //
    allocatedImageRegionSize = nth->OptionalHeader.SizeOfImage;

    status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &allocatedImageBase, 0ull, &allocatedImageRegionSize,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate memory for image %!STATUS!", status);

        return STATUS_UNSUCCESSFUL;
    }

    RtlZeroMemory(allocatedImageBase, allocatedImageRegionSize);

    // Copy sections to memory
    //
    auto section = IMAGE_FIRST_SECTION(nth);

    for (ULONG i = 0ul; i < nth->FileHeader.NumberOfSections; i++, section++)
    {
        const ULONG sectionSize = min(section->SizeOfRawData, section->Misc.VirtualSize);
        if (!sectionSize)
        {
            continue;
        }

        RtlCopyMemory(reinterpret_cast<PUCHAR>(allocatedImageBase) + section->VirtualAddress,
                      reinterpret_cast<PUCHAR>(imageBase) + section->PointerToRawData, sectionSize);
    }

    [[maybe_unused]] const PUCHAR allocatedImageEntryPoint =
        reinterpret_cast<PUCHAR>(allocatedImageBase) + nth->OptionalHeader.AddressOfEntryPoint;

    WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "Allocated image base 0x%p size 0x%llX entrypoint 0x%p", allocatedImageBase,
              allocatedImageRegionSize, allocatedImageEntryPoint);

    status = Bypass::CreateProtectedModule(currentProcessId, allocatedImageBase, allocatedImageRegionSize);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to add module allocation to protected list %!STATUS!", status);

        return STATUS_UNSUCCESSFUL;
    }

    // Allocate memory for exception handler
    //
    status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &exceptionHandlerBase, 0ull, &exceptionHandlerRegionSize,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate memory for exception handler %!STATUS!", status);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(exceptionHandlerBase, exceptionHandlerRegionSize);

    status = Bypass::CreateProtectedModule(currentProcessId, exceptionHandlerBase, exceptionHandlerRegionSize);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to add exception handler allocation to protected list %!STATUS!",
                  status);

        return STATUS_UNSUCCESSFUL;
    }

    WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "Exception handler stub allocated 0x%p size 0x%llX", exceptionHandlerBase,
              exceptionHandlerRegionSize);

    // Write exception handler to memory and fix page protection
    //
    *(PVOID *)(&g_shellcodeExceptionHandlerStub[10]) = allocatedImageBase;
    *(ULONG *)(&g_shellcodeExceptionHandlerStub[27]) = nth->OptionalHeader.SizeOfImage;

    RtlCopyMemory(exceptionHandlerBase, &g_shellcodeExceptionHandlerStub, ARRAYSIZE(g_shellcodeExceptionHandlerStub));

    status = ZwProtectVirtualMemory(ZwCurrentProcess(), &exceptionHandlerBase, &exceptionHandlerRegionSize,
                                    PAGE_EXECUTE_READ, &oldAccess);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to fix exception handler stub page protection %!STATUS!", status);

        return STATUS_UNSUCCESSFUL;
    }

    // Allocate memory for mapper shellcode
    //
    status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &manualMapStubBase, 0ull, &manualMapStubRegionSize,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate memory for mapper %!STATUS!", status);

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(manualMapStubBase, manualMapStubRegionSize);

    WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "Manual map stub allocated 0x%p size 0x%llX", manualMapStubBase,
              manualMapStubRegionSize);

    // Now setup mapper param and stub
    //
    const PMANUAL_MAP_STUB_PARAM manualMapStubParam = new (manualMapStubBase) MANUAL_MAP_STUB_PARAM(
        reinterpret_cast<ULONG_PTR>(allocatedImageBase),
        reinterpret_cast<ULONG_PTR>(allocatedImageBase) - nth->OptionalHeader.ImageBase,
        nth->OptionalHeader.SizeOfImage, nth->OptionalHeader.AddressOfEntryPoint, MANUAL_MAP_STUB_FLAG_NONE,
        &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC],
        &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS],
        &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION],
        &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT],
        &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG], exceptionHandlerBase,
        RtlAddFunctionTable, LdrpHandleTlsData, RtlAddVectoredExceptionHandler, LoadLibraryA, GetProcAddress);

    const PVOID manualMapStubShellcode = ALIGN_UP_POINTER_BY(
        reinterpret_cast<PUCHAR>(manualMapStubBase) + sizeof(MANUAL_MAP_STUB_PARAM), alignof(PVOID));

    *(PVOID *)(&g_shellcodeManualMapStub[9]) = manualMapStubParam;

    RtlCopyMemory(manualMapStubShellcode, g_shellcodeManualMapStub, ARRAYSIZE(g_shellcodeManualMapStub));

    WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "Manual map stub param 0x%p", manualMapStubParam);
    WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "Manual map stub shellcode base 0x%p", manualMapStubShellcode);

    PVOID RopGadget = Misc::Memory::FindPattern(ntdllEntry->DllBase, ".text", "FF E1");
    if (!RopGadget)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Could not find a suitable ROP gadget!");

        return STATUS_PROCEDURE_NOT_FOUND;
    }

    HANDLE threadHandle = nullptr;
    status = CreateThread(RopGadget, manualMapStubShellcode, &threadHandle);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "CreateThread returned %!STATUS!", status);

        return status;
    }

    SCOPE_EXIT
    {
        ZwClose(threadHandle);
    };

    WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "Waiting for stub result...");

    LARGE_INTEGER li{};
    li.QuadPart = RELATIVE(SECONDS(60));
    status = ZwWaitForSingleObject(threadHandle, FALSE, &li);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "ZwWaitForSingleObject returned %!STATUS!", status);
        return status;
    }

    if (manualMapStubParam->Result != MANUAL_MAP_STUB_RESULT_SUCCESS)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Manual map was not successfully executed!");
        return STATUS_UNSUCCESSFUL;
    }

    auto FixSectionsProtections = [&]() {
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nth);

        for (ULONG i = 0ul; i < nth->FileHeader.NumberOfSections; i++, section++)
        {
            const ULONG sectionSize = min(section->SizeOfRawData, section->Misc.VirtualSize);
            if (sectionSize)
            {
                // Fix sections pages protections
                //
                ULONG newAccess = CastSectionProtection(section->Characteristics, FALSE);
                PVOID baseAddress = reinterpret_cast<PUCHAR>(allocatedImageBase) + section->VirtualAddress;
                SIZE_T regionSize = sectionSize;

                status = ZwProtectVirtualMemory(ZwCurrentProcess(), &baseAddress, &regionSize, newAccess, &oldAccess);
                if (!NT_SUCCESS(status))
                {
                    WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL,
                              "Failed to set page protection at 0x%p with size %lld %!STATUS!", baseAddress,
                              sectionSize, status);
                }
            }
        }
    };

    WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "Fixing image sections...");

    FixSectionsProtections();
    shouldFreeImage = false;

    WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "Image mapped successfully!");

    return STATUS_SUCCESS;
}

NTSTATUS AttachAndInject(_In_ PEPROCESS process, _In_ PVOID imageBase, _In_ SIZE_T imageSize)
{
    PAGED_CODE();
    NT_ASSERT(process);
    NT_ASSERT(imageBase);

    NTSTATUS status;

    KAPC_STATE apcState{};
    bool attached = false;

    SCOPE_EXIT
    {
        if (attached)
        {
            KeUnstackDetachProcess(&apcState);
        }
    };

    __try
    {
        KeStackAttachProcess(process, &apcState);

        attached = true;

        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Attached to pid %d (0x%p) proceeding to inject dll",
                  HandleToUlong(PsGetProcessId(process)), process);

        status = Inject::InjectImage(imageBase, imageSize);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();

        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Exception occured while trying to map image %!STATUS!", status);

        return status;
    }
    return status;
}
} // namespace Inject