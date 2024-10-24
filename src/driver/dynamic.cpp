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

namespace Dynamic
{
ULONG64 *GetKeServiceDescriptorTable(VOID)
{
    // this code was stolen from BE.
    ULONG64 KiSystemCall64;      // r9
    ULONG64 KiSystemCall64_;     // rdx
    ULONG64 v5;                  // r10
    bool i;                      // cf
    __int64 KiSystemServiceUser; // rax
    ULONG64 v8;                  // rcx

    ULONG64 *KeServiceDescriptorTable = NULL;

    KiSystemCall64 = __readmsr(IA32_LSTAR_MSR);
    KiSystemCall64_ = KiSystemCall64;
    v5 = KiSystemCall64 + 0x1000;

    for (i = KiSystemCall64 < KiSystemCall64 + 0x1000; i; i = KiSystemCall64_ < v5)
    {
        if (*(UCHAR *)KiSystemCall64_ == 0x4C && *(UCHAR *)(KiSystemCall64_ + 1) == 0x8D &&
            *(UCHAR *)(KiSystemCall64_ + 2) == 0x15 && *(UCHAR *)(KiSystemCall64_ + 7) == 0x4C &&
            *(UCHAR *)(KiSystemCall64_ + 8) == 0x8D && *(UCHAR *)(KiSystemCall64_ + 9) == 0x1D)
        {
            KeServiceDescriptorTable = (ULONG64 *)(*(INT32 *)(KiSystemCall64_ + 3) + KiSystemCall64_ + 7);

            if (KeServiceDescriptorTable)
            {
                goto Exit;
            }

            break;
        }
        ++KiSystemCall64_;
    }

    if (NTOS_BUILD > WINVER_WIN10_1803)
    {
        while (KiSystemCall64 < v5)
        {
            if (*(UCHAR *)KiSystemCall64 == 0xE9 && *(UCHAR *)(KiSystemCall64 + 5) == 0xC3 &&
                !*(UCHAR *)(KiSystemCall64 + 6))
            {
                KiSystemServiceUser = *(INT32 *)(KiSystemCall64 + 1);

                v8 = KiSystemServiceUser + KiSystemCall64 + 5;
                if (v8)
                {
                    while (v8 < KiSystemServiceUser + KiSystemCall64 + 0x1005)
                    {
                        if (*(UCHAR *)v8 == 0x4C && *(UCHAR *)(v8 + 1) == 0x8D && *(UCHAR *)(v8 + 2) == 0x15 &&
                            *(UCHAR *)(v8 + 7) == 0x4C && *(UCHAR *)(v8 + 8) == 0x8D && *(UCHAR *)(v8 + 9) == 0x1D)
                        {
                            KeServiceDescriptorTable = (ULONG64 *)(*(INT32 *)(v8 + 3) + v8 + 7);

                            if (KeServiceDescriptorTable)
                            {
                                goto Exit;
                            }

                            return NULL;
                        }
                        ++v8;
                    }
                }

                return NULL;
            }
            ++KiSystemCall64;
        }
    }

Exit:
    return KeServiceDescriptorTable;
};

NTSTATUS Initialize()
{
    static bool initialized = false;

    if (initialized)
    {
        return STATUS_ALREADY_INITIALIZED;
    }

    NTSTATUS status = STATUS_UNSUCCESSFUL;

    // Get kernel information
    //
    NTOS_BASE = Misc::Module::GetNtoskrnlBase();
    DBG_PRINT("NtoskrnlBase = 0x%p", NTOS_BASE);

    RTL_OSVERSIONINFOW osvi{};
    osvi.dwOSVersionInfoSize = sizeof(osvi);

    status = RtlGetVersion(&osvi);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "RtlGetVersion returned %!STATUS!", status);
        return status;
    }

    NTOS_MAJOR = osvi.dwMajorVersion;
    NTOS_MINOR = osvi.dwMinorVersion;
    NTOS_BUILD = osvi.dwBuildNumber;

    DBG_PRINT("Ntos Major = %d Minor = %d Build = %d", NTOS_MAJOR, NTOS_MINOR, NTOS_BUILD);

#if (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_INFINITY_HOOK)
    if (NTOS_BUILD >= WINVER_WIN11_21H2)
    {
        g_DynamicContext.Kernel.Offset.GetCpuClock = 0x18;
    }
    else
    {
        g_DynamicContext.Kernel.Offset.GetCpuClock = 0x28;
    }

    PUCHAR EtwpDebuggerData = Misc::Memory::FindPattern(NTOS_BASE, ".data", "2C 08 04 38 0C");
    if (!EtwpDebuggerData)
    {
        EtwpDebuggerData = Misc::Memory::FindPattern(NTOS_BASE, ".rdata", "2C 08 04 38 0C");
        if (!EtwpDebuggerData)
        {
            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "EtwpDebuggerData not found!");
            return STATUS_PROCEDURE_NOT_FOUND;
        }
    }

    EtwpDebuggerData -= 2;

    if (!MmIsAddressValid(EtwpDebuggerData))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Invalid EtwpDebuggerData at 0x%p", EtwpDebuggerData);
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    DBG_PRINT("EtwpDebuggerData = 0x%p", EtwpDebuggerData);
    g_DynamicContext.Kernel.Address.EtwpDebuggerData = reinterpret_cast<ULONG_PTR>(EtwpDebuggerData);

    // Starting Win10 1909 a new method to achieve Infinityhook is necessary
    //
    if (NTOS_BUILD > WINVER_WIN10_1909)
    {
        const PUCHAR HvlpReferenceTscPage =
            Misc::Memory::FindPattern(NTOS_BASE, ".text", "48 8B 05 ?? ?? ?? ?? 48 8B 40 08 48 8B 0D");
        if (!HvlpReferenceTscPage)
        {
            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "HvlpReferenceTscPage not found!");
            return STATUS_PROCEDURE_NOT_FOUND;
        }

        DBG_PRINT("HvlpReferenceTscPageRef = 0x%p", HvlpReferenceTscPage);
        g_DynamicContext.Kernel.Address.HvlpReferenceTscPage = reinterpret_cast<ULONG_PTR>(HvlpReferenceTscPage);

        PUCHAR HvlGetQpcBias = Misc::Memory::FindPattern(
            NTOS_BASE, ".text", "48 89 5C 24 08 57 48 83 EC 20 48 8B 05 ?? ?? ?? ?? 48 8B F9 48 85");
        if (!HvlGetQpcBias)
        {
            WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "HvlGetQpcBias not found!");
            return STATUS_PROCEDURE_NOT_FOUND;
        }

        HvlGetQpcBias += 0x22;

        DBG_PRINT("HvlGetQpcBiasRef = 0x%p", HvlGetQpcBias);
        g_DynamicContext.Kernel.Address.HvlGetQpcBias = reinterpret_cast<ULONG_PTR>(HvlGetQpcBias);
    }
#endif

    PULONG64 KeServiceDescriptorTable = GetKeServiceDescriptorTable();
    if (!KeServiceDescriptorTable)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "KeServiceDescriptorTable not found!");

        return STATUS_PROCEDURE_NOT_FOUND;
    }

    g_DynamicContext.Kernel.Address.KeServiceDescriptorTable = KeServiceDescriptorTable;

    DBG_PRINT("KeServiceDescriptorTable = 0x%p", g_DynamicContext.Kernel.Address.KeServiceDescriptorTable);

    initialized = true;

    return STATUS_SUCCESS;
}

void Unitialize()
{
    WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL, "Unitialized Dynamic");
}

} // namespace Dynamic