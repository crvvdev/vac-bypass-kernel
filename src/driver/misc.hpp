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

namespace Misc
{
namespace Process
{
__forceinline BOOL IsProcessWow64(PEPROCESS process)
{
    return (PsGetProcessWow64Process(process) != NULL);
}
} // namespace Process

namespace Module
{
PLDR_DATA_TABLE_ENTRY32 GetModuleByNameWow64(_In_ PWCHAR moduleName);
PLDR_DATA_TABLE_ENTRY GetModuleByName(_In_ PWCHAR moduleName);
PVOID GetSystemModuleBase(_In_ LPCSTR moduleName, _Out_opt_ PULONG moduleSize = nullptr);
PVOID GetNtoskrnlBase(_Out_opt_ PULONG moduleSize = nullptr);
} // namespace Module

namespace PE
{
PIMAGE_SECTION_HEADER FindSection(_In_ PIMAGE_NT_HEADERS NtHeaders, _In_ const char *SectionName);
BOOLEAN RelocateImage(_In_ PIMAGE_NT_HEADERS nth, _In_ void *imageBase, _In_ ULONG_PTR Delta);
PVOID GetProcAddress(_In_ void *imageBase, _In_ const char *szProcedure);
BOOLEAN GetSectionFromVirtualAddress(void *imageBase, void *routineAddress, PULONG SectionSize, PUCHAR *SectionVa);
}; // namespace PE

namespace Memory
{
PUCHAR FindPattern(PUCHAR searchAddress, const size_t searchSize, const char *pattern);
PUCHAR FindPattern(_In_ PVOID imageBase, _In_ const char *szSectionName, _In_ const char *szPattern);
NTSTATUS GetMappedFilename(_In_ PVOID BaseAddress, _Out_ PUNICODE_STRING *MappedName);
NTSTATUS
WriteReadOnlyMemory(_Inout_ PVOID Destination, _Inout_ PVOID Source, _In_ SIZE_T Size);
ULONG_PTR FindCodeCaveAddress(ULONG_PTR CodeStart, ULONG CodeSize, ULONG CaveSize);
} // namespace Memory

namespace String
{
PWCHAR wcsistr(PWCHAR wcs1, const wchar_t *wcs2);
} // namespace String

VOID DelayThread(_In_ LONG64 Milliseconds, _In_ BOOLEAN Alertable = FALSE);
HANDLE GetProcessIDFromProcessHandle(HANDLE ProcessHandle);
HANDLE GetProcessIDFromThreadHandle(HANDLE ThreadHandle);
NTSTATUS LoadFileInMemory(_In_ PUNICODE_STRING FileName, _Out_ PVOID *FileBuffer, _Out_ PSIZE_T FileSize);
} // namespace Misc