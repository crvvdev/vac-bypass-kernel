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

#define VAC_DEVICE_GUID L"{272C5244-95ED-402D-B511-CE6511F96DFE}"

#define IOCTL_VAC_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0, METHOD_BUFFERED, FILE_ANY_ACCESS)

namespace Comms
{
enum class EDriverCommunicationRequest : int
{
    Invalid,
    EnableBypass,
    DisableBypass,
    InjectDll,
    Max
};

static constexpr int DRIVER_REQUEST_MAGIC = 'Bcta';

typedef struct _DRIVER_REQUEST_HEADER
{
    int Magic = DRIVER_REQUEST_MAGIC;
    EDriverCommunicationRequest Request = EDriverCommunicationRequest::Invalid;
    NTSTATUS Status = STATUS_INVALID_DEVICE_REQUEST;

    bool IsValid(void) const
    {
        return (this->Magic == DRIVER_REQUEST_MAGIC && (this->Request > EDriverCommunicationRequest::Invalid &&
                                                        this->Request < EDriverCommunicationRequest::Max));
    }

    void SetStatus(_In_ const NTSTATUS status)
    {
        this->Status = status;
    }

} DRIVER_REQUEST_HEADER, *PDRIVER_REQUEST_HEADER;

typedef struct _DRIVER_REQUEST_INJECT : DRIVER_REQUEST_HEADER
{
    PVOID ImageBase;
    ULONG ImageSize;

    _DRIVER_REQUEST_INJECT(_In_ PVOID imageBase, _In_ ULONG imageSize) : ImageBase(imageBase), ImageSize(imageSize)
    {
        this->Request = EDriverCommunicationRequest::InjectDll;
    }

} DRIVER_REQUEST_INJECT, *PDRIVER_REQUEST_INJECT;

typedef struct _DRIVER_REQUEST_DISABLE_BYPASS : DRIVER_REQUEST_HEADER
{
    _DRIVER_REQUEST_DISABLE_BYPASS()
    {
        this->Request = EDriverCommunicationRequest::DisableBypass;
    }

} DRIVER_REQUEST_DISABLE_BYPASS, *PDRIVER_REQUEST_DISABLE_BYPASS;

typedef struct _DRIVER_REQUEST_ENABLE_BYPASS : DRIVER_REQUEST_HEADER
{
    _DRIVER_REQUEST_ENABLE_BYPASS()
    {
        this->Request = EDriverCommunicationRequest::EnableBypass;
    }

} DRIVER_REQUEST_ENABLE_BYPASS, *PDRIVER_REQUEST_ENABLE_BYPASS;

} // namespace Comms