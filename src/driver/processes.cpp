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

namespace Processes
{
bool g_initialized = false;

const static bool IsInitialized()
{
    return g_initialized;
}

NTSTATUS Initialize()
{
    PAGED_PASSIVE();

    if (g_initialized)
    {
        NT_ASSERT(FALSE); // Already initialized.
        return STATUS_ALREADY_INITIALIZED;
    }

    const NTSTATUS status = g_ProcessesListLock.Initialize();
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to initialized processes list lock!");
        return status;
    }

    InitializeListHead(&g_ProcessesList);
    Memory::InitializeNPagedLookaside(&g_ProcessesLookasideList, sizeof(PROCESS_ENTRY), Memory::TAG_PROCESS);

    g_initialized = true;

    return status;
}

void Cleanup()
{
    g_ProcessesListLock.LockExclusive();
    {
        EnumProcessesUnsafe([&](_In_ PPROCESS_ENTRY Entry) -> BOOLEAN {
            WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "Removing process id %d from list",
                      HandleToUlong(Entry->ProcessId));

            ObDereferenceObject(Entry->Process);
            // TODO: deref obj

            RemoveEntryList(&Entry->ListEntry);
            Memory::FreeFromNPagedLookaside(&g_ProcessesLookasideList, Entry);

            return FALSE;
        });

        g_ProcessesListLock.Unlock();
    }
}

void Unitialize()
{
    PAGED_PASSIVE();

    if (!g_initialized)
    {
        return;
    }

    Cleanup();

    Memory::DeleteNPagedLookaside(&g_ProcessesLookasideList);
    g_ProcessesListLock.Destroy();

    WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL, "Unitialized Processes");
}

PEPROCESS GetGameProcess()
{
    PAGED_PASSIVE();

    if (!IsInitialized())
    {
        return nullptr;
    }

    g_ProcessesListLock.LockShared();
    SCOPE_EXIT
    {
        g_ProcessesListLock.Unlock();
    };

    PEPROCESS process = nullptr;

    EnumProcessesUnsafe([&](_In_ PPROCESS_ENTRY Entry) -> BOOLEAN {
        if (Entry->Flags.Game)
        {
            process = Entry->Process;
            ObReferenceObject(process);
            return TRUE;
        }
        return FALSE;
    });

    return process;
}

NTSTATUS AddProcess(_In_ HANDLE ProcessId, _In_ BOOLEAN Game, _In_ BOOLEAN Steam, _In_ BOOLEAN SteamService)
{
    PAGED_PASSIVE();

    if (!IsInitialized())
    {
        return STATUS_NOT_CAPABLE;
    }

    g_ProcessesListLock.LockExclusive();
    SCOPE_EXIT
    {
        g_ProcessesListLock.Unlock();
    };

    if (IsProcessInListUnsafe(ProcessId))
    {
        return STATUS_ALREADY_REGISTERED; // Already in list.
    }

    PEPROCESS process = nullptr;

    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "PsLookupProcessByProcessId returned %!STATUS!", status);
        return status;
    }

    auto *entry = reinterpret_cast<PPROCESS_ENTRY>(Memory::AllocFromNPagedLookaside(&g_ProcessesLookasideList));
    if (!entry)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate memory for tracked entry!");

        ObDereferenceObject(process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry->Process = process;
    entry->ProcessId = ProcessId;
    entry->Flags.Game = Game;
    entry->Flags.Steam = Steam;
    entry->Flags.SteamService = SteamService;
    InsertTailList(&g_ProcessesList, &entry->ListEntry);

    return STATUS_SUCCESS;
}

NTSTATUS AddProcessGame(_In_ HANDLE ProcessId)
{
    PAGED_PASSIVE();

    if (!IsInitialized())
    {
        return STATUS_NOT_CAPABLE;
    }

    return AddProcess(ProcessId, TRUE, FALSE, FALSE);
}

NTSTATUS AddProcessSteam(_In_ HANDLE ProcessId)
{
    PAGED_PASSIVE();

    if (!IsInitialized())
    {
        return STATUS_NOT_CAPABLE;
    }

    return AddProcess(ProcessId, FALSE, TRUE, FALSE);
}

NTSTATUS AddProcessSteamService(_In_ HANDLE ProcessId)
{
    PAGED_PASSIVE();

    if (!IsInitialized())
    {
        return STATUS_NOT_CAPABLE;
    }

    return AddProcess(ProcessId, FALSE, FALSE, TRUE);
}

BOOLEAN RemoveProcess(_In_ HANDLE ProcessId)
{
    PAGED_PASSIVE();

    if (!IsInitialized())
    {
        return FALSE;
    }

    g_ProcessesListLock.LockExclusive();
    SCOPE_EXIT
    {
        g_ProcessesListLock.Unlock();
    };

    const BOOLEAN result = EnumProcessesUnsafe([&](_In_ PPROCESS_ENTRY Entry) -> BOOLEAN {
        if (Entry->ProcessId == ProcessId)
        {
            ObDereferenceObject(Entry->Process);

            RemoveEntryList(&Entry->ListEntry);
            Memory::FreeFromNPagedLookaside(&g_ProcessesLookasideList, Entry);
            return TRUE;
        }
        return FALSE;
    });
    return result;
}

BOOLEAN IsSteamOrSteamServiceInList()
{
    PAGED_PASSIVE();

    if (!IsInitialized())
    {
        return FALSE;
    }

    g_ProcessesListLock.LockShared();

    SCOPE_EXIT
    {
        g_ProcessesListLock.Unlock();
    };

    int i = 0;

    EnumProcessesUnsafe([&](_In_ PPROCESS_ENTRY Entry) -> BOOLEAN {
        if (Entry->Flags.Steam == TRUE)
        {
            i++;
        }
        else if (Entry->Flags.SteamService == TRUE)
        {
            i++;
        }

        return FALSE;
    });

    return (i > 0);
}

BOOLEAN IsProcessSteamUnsafe(_In_ HANDLE ProcessId)
{
    PAGED_PASSIVE();

    if (!IsInitialized())
    {
        return FALSE;
    }

    const BOOLEAN result = EnumProcessesUnsafe([&](_In_ PPROCESS_ENTRY Entry) -> BOOLEAN {
        if (Entry->ProcessId == ProcessId && (Entry->Flags.Steam == TRUE || Entry->Flags.SteamService == TRUE))
        {
            return TRUE;
        }

        return FALSE;
    });
    return result;
}

BOOLEAN IsProcessSteam(_In_ HANDLE ProcessId)
{
    PAGED_PASSIVE();

    if (!IsInitialized())
    {
        return FALSE;
    }

    g_ProcessesListLock.LockShared();
    SCOPE_EXIT
    {
        g_ProcessesListLock.Unlock();
    };

    return IsProcessSteamUnsafe(ProcessId);
}

BOOLEAN
IsProcessGameUnsafe(_In_ HANDLE ProcessId)
{
    if (!IsInitialized())
    {
        return FALSE;
    }

    const BOOLEAN result = EnumProcessesUnsafe([&](_In_ PPROCESS_ENTRY Entry) -> BOOLEAN {
        if (Entry->ProcessId == ProcessId && Entry->Flags.Game == TRUE)
        {
            return TRUE;
        }

        return FALSE;
    });
    return result;
}

BOOLEAN
IsProcessGame(_In_ HANDLE ProcessId)
{
    if (!IsInitialized())
    {
        return FALSE;
    }

    g_ProcessesListLock.LockShared();
    SCOPE_EXIT
    {
        g_ProcessesListLock.Unlock();
    };

    return IsProcessGameUnsafe(ProcessId);
}

BOOLEAN
IsProcessInListUnsafe(_In_ HANDLE ProcessId)
{
    if (!IsInitialized())
    {
        return FALSE;
    }

    const BOOLEAN result = EnumProcessesUnsafe([&](_In_ PPROCESS_ENTRY Entry) -> BOOLEAN {
        if (Entry->ProcessId == ProcessId)
        {
            return TRUE;
        }

        return FALSE;
    });
    return result;
}

BOOLEAN
IsProcessInList(_In_ HANDLE ProcessId)
{
    if (!IsInitialized())
    {
        return FALSE;
    }

    g_ProcessesListLock.LockShared();
    SCOPE_EXIT
    {
        g_ProcessesListLock.Unlock();
    };

    return IsProcessInListUnsafe(ProcessId);
}
} // namespace Processes