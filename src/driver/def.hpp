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

#define CURRENT_IRQL KeGetCurrentIrql()

#define PAGED_PASSIVE()                                                                                                \
    PAGED_CODE()                                                                                                       \
    NT_ASSERT(CURRENT_IRQL == PASSIVE_LEVEL)

#define ABSOLUTE(x) (x)
#define RELATIVE(x) (-(x))
#define NANOSECONDS(nanos) (((signed __int64)(nanos)) / 100L)
#define MICROSECONDS(micros) (((signed __int64)(micros)) * NANOSECONDS(1000L))
#define MILLISECONDS(milli) (((signed __int64)(milli)) * MICROSECONDS(1000L))
#define SECONDS(seconds) (((signed __int64)(seconds)) * MILLISECONDS(1000L))

#define PTR_OFFSET_ADD(p, o) ((ULONG_PTR)(p) + (ULONG_PTR)(o))
#define PTR_OFFSET_SUB(p, o) ((ULONG_PTR)(p) - (ULONG_PTR)(o))

#define WINVER_WIN11_24H2 (26100)
#define WINVER_WIN11_23H2 (22631)
#define WINVER_WIN11_22H2 (22621)
#define WINVER_WIN11_21H2 (22000)
#define WINVER_WIN10_22H2 (19045)
#define WINVER_WIN10_21H2 (19044)
#define WINVER_WIN10_21H1 (19043)
#define WINVER_WIN10_20H2 (19042)
#define WINVER_WIN10_2004 (19041)
#define WINVER_WIN10_1909 (18363)
#define WINVER_WIN10_1903 (18362)
#define WINVER_WIN10_1809 (17763)
#define WINVER_WIN10_1803 (17134)
#define WINVER_WIN10_1709 (16299)
#define WINVER_WIN10_1703 (15063)
#define WINVER_WIN10_1607 (14393)
#define WINVER_WIN10_1511 (10586)
#define WINVER_WIN10_1507 (10240)

#define IA32_LSTAR_MSR 0xC0000082
#define KPCR_RSP_BASE 0x1A8

template <class T = void *> __forceinline T RipToAbsolute(_In_ ULONG_PTR rip, _In_ INT offset, _In_ INT len)
{
    return (T)(rip + len + *reinterpret_cast<INT32 *>(rip + offset));
}

typedef struct _SERVICE_DESCRIPTOR
{
    PULONG ServiceTableBase;
    PULONG ServiceCounterTableBase;
    ULONG NumberOfService;
    PVOID ParamTableBase;

} SERVICE_DESCRIPTOR, *PSERVICE_DESCRIPTOR;

typedef struct _SERVICE_DESCRIPTOR_TABLE
{
    SERVICE_DESCRIPTOR NtosTable;
    SERVICE_DESCRIPTOR Win32kTable;

} SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;

#define EtwpStartTrace 1
#define EtwpStopTrace 2
#define EtwpQueryTrace 3
#define EtwpUpdateTrace 4
#define EtwpFlushTrace 5

typedef struct _EVENT_TRACE_PROPERTIES
{
    WNODE_HEADER Wnode;
    ULONG BufferSize;
    ULONG MinimumBuffers;
    ULONG MaximumBuffers;
    ULONG MaximumFileSize;
    ULONG LogFileMode;
    ULONG FlushTimer;
    ULONG EnableFlags;
    LONG AgeLimit;
    ULONG NumberOfBuffers;
    ULONG FreeBuffers;
    ULONG EventsLost;
    ULONG BuffersWritten;
    ULONG LogBuffersLost;
    ULONG RealTimeBuffersLost;
    HANDLE LoggerThreadId;
    ULONG LogFileNameOffset;
    ULONG LoggerNameOffset;
} EVENT_TRACE_PROPERTIES, *PEVENT_TRACE_PROPERTIES;

/* 54dea73a-ed1f-42a4-af713e63d056f174 */
const GUID CkclSessionGuid = {0x54dea73a, 0xed1f, 0x42a4, {0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74}};

EXTERN_C_START

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwTraceControl(_In_ ULONG FunctionCode, _In_reads_bytes_opt_(InBufferLen) PVOID InBuffer, _In_ ULONG InBufferLen,
               _Out_writes_bytes_opt_(OutBufferLen) PVOID OutBuffer, _In_ ULONG OutBufferLen,
               _Out_ PULONG ReturnLength);

NTKERNELAPI NTSTATUS NTAPI NtReadVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID Buffer,
                                               IN SIZE_T NumberOfBytesToRead, OUT PSIZE_T NumberOfBytesReaded);

NTKERNELAPI NTSTATUS NTAPI ZwProtectVirtualMemory(IN HANDLE ProcessHandle, IN PVOID *BaseAddress,
                                                  IN PSIZE_T NumberOfBytesToProtect, IN ULONG NewAccessProtection,
                                                  OUT PULONG OldAccessProtection);

NTKERNELAPI NTSTATUS NTAPI RtlCreateUserThread(IN HANDLE ProcessHandle,
                                               IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
                                               IN BOOLEAN CreateSuspended, IN ULONG StackZeroBits OPTIONAL,
                                               IN SIZE_T StackReserve OPTIONAL, IN SIZE_T StackCommit OPTIONAL,
                                               IN PVOID StartAddress, IN PVOID Parameter OPTIONAL,
                                               OUT PHANDLE ThreadHandle OPTIONAL, OUT PCLIENT_ID ClientId OPTIONAL);

NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);

EXTERN_C_END;