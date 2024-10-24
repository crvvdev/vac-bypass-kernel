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
#pragma once

namespace Processes
{
typedef struct _PROCESS_ENTRY
{
    LIST_ENTRY ListEntry;
    PEPROCESS Process;
    HANDLE ProcessId;
    union {
        struct
        {
            BOOLEAN Steam : 1;
            BOOLEAN SteamService : 1;
            BOOLEAN Game : 1;
        } Flags;
        ULONG Long;
    };

} PROCESS_ENTRY, *PPROCESS_ENTRY;

inline NPAGED_LOOKASIDE_LIST g_ProcessesLookasideList{};
inline LIST_ENTRY g_ProcessesList{};
inline Mutex::Resource g_ProcessesListLock;

[[nodiscard]] NTSTATUS Initialize();
void Unitialize();

[[nodiscard]] PEPROCESS GetGameProcess(void);

[[nodiscard]] BOOLEAN IsProcessSteam(_In_ HANDLE ProcessId);
[[nodiscard]] BOOLEAN IsProcessGame(_In_ HANDLE ProcessId);
[[nodiscard]] BOOLEAN IsProcessInList(_In_ HANDLE ProcessId);

[[nodiscard]] BOOLEAN IsProcessSteamUnsafe(_In_ HANDLE ProcessId);
[[nodiscard]] BOOLEAN IsProcessGameUnsafe(_In_ HANDLE ProcessId);
[[nodiscard]] BOOLEAN IsProcessInListUnsafe(_In_ HANDLE ProcessId);

[[nodiscard]] BOOLEAN IsSteamOrSteamServiceInList(void);

[[nodiscard]] NTSTATUS AddProcessGame(_In_ HANDLE ProcessId);
[[nodiscard]] NTSTATUS AddProcessSteam(_In_ HANDLE ProcessId);
[[nodiscard]] NTSTATUS AddProcessSteamService(_In_ HANDLE ProcessId);

[[nodiscard]] BOOLEAN RemoveProcess(_In_ HANDLE ProcessId);

using ENUM_PROCESSES = BOOLEAN (*)(_In_ PPROCESS_ENTRY);

template <typename C = ENUM_PROCESSES> __forceinline BOOLEAN EnumProcessesUnsafe(const C &Callback)
{
    NT_ASSERT(CURRENT_IRQL <= DISPATCH_LEVEL);

    LIST_ENTRY *pListHead = &g_ProcessesList;

    if (IsListEmpty(pListHead))
    {
        return FALSE;
    }

    PPROCESS_ENTRY pEntry = NULL;
    LIST_ENTRY *pListEntry = pListHead->Flink;
    BOOLEAN result = FALSE;

    while (pListEntry != pListHead)
    {
        pEntry = CONTAINING_RECORD(pListEntry, PROCESS_ENTRY, ListEntry);
        pListEntry = pListEntry->Flink;

        if (Callback(pEntry))
        {
            result = TRUE;
            break;
        }
    }
    return result;
}

} // namespace Processes