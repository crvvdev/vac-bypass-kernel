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

namespace Threads
{
using KERNEL_THREAD_CALLBACK = BOOLEAN (*)(PVOID);

enum class KERNEL_THREAD_STATUS : UINT8
{
    Running,
    Stopped
};

typedef struct _KERNEL_THREAD
{
    LIST_ENTRY ListEntry;
    CLIENT_ID ClientId;
    HANDLE Handle;
    PVOID Object;
    PVOID StartContext;
    BOOLEAN Stop;
    KERNEL_THREAD_STATUS Status;
    KERNEL_THREAD_CALLBACK Callback;

} KERNEL_THREAD, *PKERNEL_THREAD;

inline LIST_ENTRY g_ThreadsList{};
inline Mutex::Resource g_ThreadsListLock;

using ENUM_THREAD_CALLBACK = BOOLEAN (*)(PKERNEL_THREAD pEntry);

/// <summary>
///
/// </summary>
/// <returns></returns>
NTSTATUS Initialize();

/// <summary>
///
/// </summary>
void Unitialize();

/// <summary>
///
/// </summary>
/// <param name="Callback"></param>
/// <param name="StartContext"></param>
/// <param name="Thread"></param>
/// <returns></returns>
BOOLEAN CreateThread(KERNEL_THREAD_CALLBACK Callback, PVOID StartContext, PKERNEL_THREAD Thread);

/// <summary>
///
/// </summary>
/// <param name="Thread"></param>
/// <param name="Wait"></param>
void StopThread(PKERNEL_THREAD Thread, BOOLEAN Wait = FALSE);

/// <summary>
///
/// </summary>
/// <typeparam name="T"></typeparam>
/// <param name="Callback"></param>
/// <returns></returns>
template <typename T = ENUM_THREAD_CALLBACK> BOOLEAN EnumThreadsUnsafe(const T &&Callback)
{
    NT_ASSERT(CURRENT_IRQL <= DISPATCH_LEVEL);

    LIST_ENTRY *pListHead = &g_ThreadsList;

    if (IsListEmpty(pListHead))
    {
        return FALSE;
    }

    PKERNEL_THREAD pEntry = nullptr;
    LIST_ENTRY *pListEntry = pListHead->Flink;
    BOOLEAN result = FALSE;

    while (pListEntry != pListHead)
    {
        pEntry = CONTAINING_RECORD(pListEntry, KERNEL_THREAD, ListEntry);
        pListEntry = pListEntry->Flink;

        if (Callback(pEntry))
        {
            result = TRUE;
            break;
        }
    }

    return result;
}

} // namespace Threads