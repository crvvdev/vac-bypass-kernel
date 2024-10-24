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

namespace Callbacks
{
void ProcessCallback(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId,
                     _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateNotifyInfo);

bool g_initialized = false;

void Cleanup()
{
    PsSetCreateProcessNotifyRoutineEx(&ProcessCallback, TRUE);
}

NTSTATUS Initialize()
{
    PAGED_PASSIVE();

    if (g_initialized)
    {
        return STATUS_ALREADY_INITIALIZED;
    }

    NTSTATUS status;

    status = PsSetCreateProcessNotifyRoutineEx(&ProcessCallback, FALSE);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "PsSetCreateProcessNotifyRoutineEx returned %!STATUS!", status);
        goto Exit;
    }

    g_initialized = true;

Exit:
    if (!NT_SUCCESS(status))
    {
        Cleanup();
        status = STATUS_UNSUCCESSFUL;
    }
    return status;
}

void Unitialize()
{
    PAGED_PASSIVE();

    if (!g_initialized)
    {
        return;
    }

    Cleanup();
}

void ProcessCallback(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId,
                     _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateNotifyInfo)
{
    UNREFERENCED_PARAMETER(Process);

    static bool gameFound = false;

    if (CreateNotifyInfo)
    {
        // On process creation.
        if (!CreateNotifyInfo->ImageFileName || !CreateNotifyInfo->ImageFileName->Buffer)
        {
            return;
        }

        NTSTATUS status;

        UNICODE_STRING steamService{};
        RtlInitUnicodeString(&steamService, L"steamservice.exe");

        UNICODE_STRING steam{};
        RtlInitUnicodeString(&steam, L"steam.exe");

        UNICODE_STRING cs2{};
        RtlInitUnicodeString(&cs2, L"cs2.exe");

        if (RtlSuffixUnicodeString(&steamService, CreateNotifyInfo->ImageFileName, TRUE))
        {
            WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL, "Adding image %wZ (%d) to steam service list",
                      CreateNotifyInfo->ImageFileName, HandleToULong(ProcessId));

            status = Processes::AddProcessSteamService(ProcessId);
            if (!NT_SUCCESS(status))
            {
                WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "AddProcessSteamService returned %!STATUS!", status);
            }
        }
        else if (RtlSuffixUnicodeString(&steam, CreateNotifyInfo->ImageFileName, TRUE))
        {
            WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL, "Adding image %wZ (%d) to steam list",
                      CreateNotifyInfo->ImageFileName, HandleToULong(ProcessId));

            status = Processes::AddProcessSteam(ProcessId);
            if (!NT_SUCCESS(status))
            {
                WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "AddProcessSteam returned %!STATUS!", status);
            }
        }
        else if (Processes::IsProcessSteam(CreateNotifyInfo->ParentProcessId) &&
                 RtlSuffixUnicodeString(&cs2, CreateNotifyInfo->ImageFileName, TRUE) && !gameFound)
        {
            gameFound = true;

            WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL, "Adding image %wZ (%d) to game list",
                      CreateNotifyInfo->ImageFileName, HandleToULong(ProcessId));

            status = Processes::AddProcessGame(ProcessId);
            if (!NT_SUCCESS(status))
            {
                WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "AddProcessGame returned %!STATUS!", status);
            }
        }
    }
    else
    {
        // On process termination.
        Bypass::EraseGameModules(ProcessId);
        Bypass::EraseProtectedModules(ProcessId);

        if (Processes::IsProcessGame(ProcessId))
        {
            gameFound = false;
        }

        if (Processes::IsProcessInList(ProcessId))
        {
            WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL, "Removing %s (%d) from list",
                      (PCHAR)PsGetProcessImageFileName(Process), HandleToULong(ProcessId));

            if (!Processes::RemoveProcess(ProcessId))
            {
                WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to remove process id %d from processes list!",
                          HandleToULong(ProcessId));
            }
        }
    }
}
} // namespace Callbacks