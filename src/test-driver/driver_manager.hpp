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

class IVACDriverManager
{
  private:
    HANDLE deviceHandle = INVALID_HANDLE_VALUE;

    template <class T> NTSTATUS SendIoctl(_In_ T *request)
    {
        const ULONG bufferSize = sizeof(T);

        IO_STATUS_BLOCK iosb{};
        const NTSTATUS status = NtDeviceIoControlFile(this->deviceHandle, nullptr, nullptr, nullptr, &iosb,
                                                      IOCTL_VAC_REQUEST, request, bufferSize, request, bufferSize);
        if (!NT_SUCCESS(status))
        {
            std::wcerr << L"Error: NtDeviceIoControlFile returned 0x" << std::hex << std::uppercase << std::setw(8)
                       << std::setfill(L'0') << status << std::endl;

            request->SetStatus(status);
        }
        return request->Status;
    }

  public:
    IVACDriverManager()
    {
        this->deviceHandle = CreateFile(L"\\\\.\\" VAC_DEVICE_GUID, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (!this->deviceHandle || this->deviceHandle == INVALID_HANDLE_VALUE)
        {
            throw std::runtime_error("Failed to open device. Error: " + std::to_string(GetLastError()));
        }
    }

    NTSTATUS DisableBypass()
    {
        auto request = new Comms::DRIVER_REQUEST_DISABLE_BYPASS();
        return SendIoctl(request);
    }

    NTSTATUS EnableBypass()
    {
        auto request = new Comms::DRIVER_REQUEST_ENABLE_BYPASS();
        return SendIoctl(request);
    }

    NTSTATUS InjectDll(_In_ std::vector<uint8_t> &imageBuffer)
    {
        auto request = new Comms::DRIVER_REQUEST_INJECT(reinterpret_cast<PVOID>(imageBuffer.data()),
                                                        static_cast<ULONG>(imageBuffer.size()));
        return SendIoctl(request);
    }
};