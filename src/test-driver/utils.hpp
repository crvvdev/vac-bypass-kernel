#pragma once

namespace Utils
{
ULONG GetProcessIdByName(const wchar_t *processName)
{
    HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    PROCESSENTRY32 pe32{};
    pe32.dwSize = sizeof(pe32);

    if (!Process32First(snapshotHandle, &pe32))
    {
        CloseHandle(snapshotHandle);
        return -1;
    }

    ULONG processId = -1;

    do
    {
        if (!_wcsicmp(pe32.szExeFile, processName))
        {
            processId = pe32.th32ProcessID;
            break;
        }

    } while (Process32Next(snapshotHandle, &pe32));

    CloseHandle(snapshotHandle);
    return processId;
}

HMODULE GetProcessModule(const ULONG processId, const wchar_t *moduleName)
{
    HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);

    MODULEENTRY32 me32{};
    me32.dwSize = sizeof(me32);

    if (!Module32First(snapshotHandle, &me32))
    {
        CloseHandle(snapshotHandle);
        return nullptr;
    }

    HMODULE hmod = nullptr;

    do
    {
        if (!_wcsicmp(me32.szModule, moduleName))
        {
            hmod = me32.hModule;
            break;
        }

    } while (Module32Next(snapshotHandle, &me32));

    CloseHandle(snapshotHandle);
    return hmod;
}
} // namespace Utils