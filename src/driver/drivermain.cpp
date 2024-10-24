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
#include <algorithm>

#pragma section(".INIT", read, write, discard)

#define DRIVER_DEVICE_NAME L"\\Device\\" VAC_DEVICE_GUID
#define DRIVER_SYMBOLIC_NAME L"\\DosDevices\\" VAC_DEVICE_GUID

UNICODE_STRING g_deviceName = RTL_CONSTANT_STRING(DRIVER_DEVICE_NAME);
UNICODE_STRING g_symbolicLinkName = RTL_CONSTANT_STRING(DRIVER_SYMBOLIC_NAME);
PDEVICE_OBJECT g_deviceObject = nullptr;

#if 0
extern "C" int abs(int v)
{
    return (v < 0) ? -v : v;
}
#endif

static void DeinitializeDriver()
{
#define UNITIALIZE_INTERFACE(name) name::Unitialize();

    UNITIALIZE_INTERFACE(Hooks);
    UNITIALIZE_INTERFACE(SyscallHook);
    UNITIALIZE_INTERFACE(SyscallTable);
    UNITIALIZE_INTERFACE(Callbacks);
    UNITIALIZE_INTERFACE(Bypass);
    UNITIALIZE_INTERFACE(Processes);
    UNITIALIZE_INTERFACE(Threads);
    UNITIALIZE_INTERFACE(Dynamic);

#undef UNITIALIZE_INTERFACE

    if (g_deviceObject)
    {
        IoDeleteDevice(g_deviceObject);
        g_deviceObject = nullptr;
    }

    IoDeleteSymbolicLink(&g_symbolicLinkName);

    WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL, "Driver de-initialized!");
}

void DriverUnload(_Inout_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    DeinitializeDriver();
    WPP_CLEANUP(DriverObject);
}

NTSTATUS DispatchDeviceControl(_In_ PDEVICE_OBJECT DriverObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DriverObject);

    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    const ULONG controlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    const ULONG inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    const ULONG outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
    auto requestData = reinterpret_cast<PVOID>(Irp->AssociatedIrp.SystemBuffer);

    if (outputBufferLength < sizeof(Comms::DRIVER_REQUEST_HEADER))
    {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    switch (controlCode)
    {
    case IOCTL_VAC_REQUEST: {
        status = Comms::HandleIoctl(requestData, inputBufferLength);
        break;
    }
    default:
        break;
    }

Exit:
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = NT_SUCCESS(status) ? sizeof(Comms::DRIVER_REQUEST_HEADER) : 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS DispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

#pragma code_seg("INIT")
EXTERN_C
NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;

    WPP_INIT_TRACING(DriverObject, RegistryPath);

    status = IoCreateDevice(DriverObject, 0, &g_deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_deviceObject);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "IoCreateDevice failed %!STATUS!", status);
        goto Exit;
    }

    status = IoCreateSymbolicLink(&g_symbolicLinkName, &g_deviceName);
    if (!NT_SUCCESS(status))
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "IoCreateSymbolicLink failed %!STATUS!", status);
        goto Exit;
    }

    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

#define INIT_INTERFACE_PARAM(name, x)                                                                                  \
    status = name::Initialize(x);                                                                                      \
    if (!NT_SUCCESS(status))                                                                                           \
    {                                                                                                                  \
        DBG_PRINT(#name " failed to initialize, error 0x%08X", status);                                                \
        goto Exit;                                                                                                     \
    }

#define INIT_INTERFACE(name)                                                                                           \
    status = name::Initialize();                                                                                       \
    if (!NT_SUCCESS(status))                                                                                           \
    {                                                                                                                  \
        DBG_PRINT(#name " failed to initialize, error 0x%08X", status);                                                \
        goto Exit;                                                                                                     \
    }

    INIT_INTERFACE(Dynamic);
    INIT_INTERFACE(Threads);
    INIT_INTERFACE(Processes);
    INIT_INTERFACE(Bypass);
    INIT_INTERFACE(Callbacks);
    INIT_INTERFACE(SyscallTable);
    INIT_INTERFACE(Hooks);
    INIT_INTERFACE(SyscallHook);

#undef INIT_INTERFACE_PARAM
#undef INIT_INTERFACE

Exit:
    if (!NT_SUCCESS(status))
    {
        DeinitializeDriver();
        WPP_CLEANUP(DriverObject);

        status = STATUS_FAILED_DRIVER_ENTRY;
    }
    else
    {
        WPP_PRINT(TRACE_LEVEL_INFORMATION, GENERAL, "Driver sucessfully initialized.");
    }
    return status;
}
#pragma code_seg()