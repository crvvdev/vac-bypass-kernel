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

namespace Inject
{
typedef ULONG MANUAL_MAP_STUB_FLAGS;

#define MANUAL_MAP_STUB_FLAG_NONE 0

typedef BOOLEAN MANUAL_MAP_STUB_RESULT;

#define MANUAL_MAP_STUB_RESULT_FAIL FALSE
#define MANUAL_MAP_STUB_RESULT_SUCCESS TRUE

typedef struct _MANUAL_MAP_STUB_PARAM
{
    ULONG_PTR BaseAddress;
    ULONG_PTR Delta;
    ULONG ImageSize;
    ULONG EntryPoint;
    PVOID ExceptionHandler;
    PVOID RtlAddFunctionTable;
    PVOID LdrpHandleTlsData;
    PVOID RtlAddVectoredExceptionHandler;
    PVOID LoadLibraryA;
    PVOID GetProcAddress;

    IMAGE_DATA_DIRECTORY RelocationDirectory;
    IMAGE_DATA_DIRECTORY TlsDataDirectory;
    IMAGE_DATA_DIRECTORY ExceptionDataDirectory;
    IMAGE_DATA_DIRECTORY ImportDirectory;
    IMAGE_DATA_DIRECTORY LoadConfigDirectory;

    MANUAL_MAP_STUB_FLAGS Flags;
    MANUAL_MAP_STUB_RESULT Result;
    volatile LONG Lock;

    _MANUAL_MAP_STUB_PARAM(_In_ ULONG_PTR baseAddress, _In_ ULONG_PTR delta, _In_ ULONG imageSize,
                           _In_ ULONG entryPoint, _In_opt_ const MANUAL_MAP_STUB_FLAGS flags = 0UL,
                           _In_opt_ IMAGE_DATA_DIRECTORY *relocationDirectory = nullptr,
                           _In_opt_ IMAGE_DATA_DIRECTORY *tlsDataDirectory = nullptr,
                           _In_opt_ IMAGE_DATA_DIRECTORY *exceptionDataDirectory = nullptr,
                           _In_opt_ IMAGE_DATA_DIRECTORY *importDirectory = nullptr,
                           _In_opt_ IMAGE_DATA_DIRECTORY *loadConfigDirectory = nullptr,
                           _In_opt_ PVOID exceptionHandler = nullptr, _In_opt_ PVOID rtlAddFunctionTable = nullptr,
                           _In_opt_ PVOID ldrpHandleTlsData = nullptr,
                           _In_opt_ PVOID rtlAddVectoredExceptionHandler = nullptr,
                           _In_opt_ PVOID loadLibraryA = nullptr, _In_opt_ PVOID getProcAddress = nullptr)
        : BaseAddress(baseAddress), Delta(delta), ImageSize(imageSize), EntryPoint(entryPoint),
          ExceptionHandler(exceptionHandler), RtlAddFunctionTable(rtlAddFunctionTable),
          LdrpHandleTlsData(ldrpHandleTlsData), RtlAddVectoredExceptionHandler(rtlAddVectoredExceptionHandler),
          LoadLibraryA(loadLibraryA), GetProcAddress(getProcAddress), Flags(flags), Result(MANUAL_MAP_STUB_RESULT_FAIL),
          Lock(0UL)
    {
        if (relocationDirectory)
        {
            this->RelocationDirectory = *relocationDirectory;
        }
        else
        {
            this->RelocationDirectory = {};
        }

        if (tlsDataDirectory)
        {
            this->TlsDataDirectory = *tlsDataDirectory;
        }
        else
        {
            this->TlsDataDirectory = {};
        }

        if (exceptionDataDirectory)
        {
            this->ExceptionDataDirectory = *exceptionDataDirectory;
        }
        else
        {
            this->ExceptionDataDirectory = {};
        }

        if (importDirectory)
        {
            this->ImportDirectory = *importDirectory;
        }
        else
        {
            this->ImportDirectory = {};
        }

        if (loadConfigDirectory)
        {
            this->LoadConfigDirectory = *loadConfigDirectory;
        }
        else
        {
            this->LoadConfigDirectory = {};
        }
    }

    _MANUAL_MAP_STUB_PARAM()
    {
        RtlZeroMemory(this, sizeof(*this));
    }

} MANUAL_MAP_STUB_PARAM, *PMANUAL_MAP_STUB_PARAM;

static UCHAR g_shellcodeManualMapStub[] =
    {0x48, 0x81, 0xEC, 0x08, 0x02, 0x00, 0x00, 0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0x48, 0x89,
     0x44, 0x24, 0x20, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x85, 0xC0, 0x74, 0x16, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48,
     0x83, 0xC0, 0x78, 0xB9, 0x01, 0x00, 0x00, 0x00, 0x87, 0x08, 0x8B, 0xC1, 0x85, 0xC0, 0x74, 0x05, 0xE9, 0x3E, 0x07,
     0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC6, 0x40, 0x74, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x40,
     0x28, 0x48, 0x89, 0x84, 0x24, 0xB0, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x40, 0x20, 0x48,
     0x89, 0x84, 0x24, 0xB8, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x40, 0x30, 0x48, 0x89, 0x84,
     0x24, 0x48, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x40, 0x38, 0x48, 0x89, 0x84, 0x24, 0xC0,
     0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x40, 0x40, 0x48, 0x89, 0x84, 0x24, 0xE0, 0x00, 0x00,
     0x00, 0xC7, 0x44, 0x24, 0x50, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x83, 0x78, 0x48, 0x00, 0x0F,
     0x84, 0xDA, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x83, 0x78, 0x4C, 0x00, 0x0F, 0x84, 0xCB, 0x01, 0x00,
     0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x83, 0x78, 0x08, 0x00, 0x0F, 0x84, 0xBB, 0x01, 0x00, 0x00, 0x48, 0x8B,
     0x44, 0x24, 0x20, 0x48, 0x8B, 0x4C, 0x24, 0x20, 0x8B, 0x49, 0x48, 0x48, 0x03, 0x08, 0x48, 0x8B, 0xC1, 0x48, 0x89,
     0x44, 0x24, 0x30, 0x48, 0x83, 0x7C, 0x24, 0x30, 0x00, 0x0F, 0x84, 0x97, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24,
     0x30, 0x83, 0x38, 0x00, 0x0F, 0x84, 0x89, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x30, 0x8B, 0x40, 0x04, 0x48,
     0x83, 0xF8, 0x08, 0x0F, 0x82, 0x5A, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x30, 0x8B, 0x40, 0x04, 0x48, 0x83,
     0xE8, 0x08, 0x33, 0xD2, 0xB9, 0x02, 0x00, 0x00, 0x00, 0x48, 0xF7, 0xF1, 0x89, 0x44, 0x24, 0x78, 0x48, 0x8B, 0x44,
     0x24, 0x30, 0x48, 0x83, 0xC0, 0x08, 0x48, 0x89, 0x84, 0x24, 0xA0, 0x00, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x28, 0x00,
     0x00, 0x00, 0x00, 0xEB, 0x0A, 0x8B, 0x44, 0x24, 0x28, 0xFF, 0xC0, 0x89, 0x44, 0x24, 0x28, 0x8B, 0x44, 0x24, 0x78,
     0x39, 0x44, 0x24, 0x28, 0x0F, 0x83, 0x0D, 0x01, 0x00, 0x00, 0x8B, 0x44, 0x24, 0x28, 0x48, 0x8B, 0x8C, 0x24, 0xA0,
     0x00, 0x00, 0x00, 0x0F, 0xB7, 0x04, 0x41, 0xC1, 0xF8, 0x0C, 0x89, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 0x8B, 0x44,
     0x24, 0x28, 0x48, 0x8B, 0x8C, 0x24, 0xA0, 0x00, 0x00, 0x00, 0x0F, 0xB7, 0x04, 0x41, 0x25, 0xFF, 0x0F, 0x00, 0x00,
     0x89, 0x44, 0x24, 0x7C, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x4C, 0x24, 0x30, 0x8B, 0x09, 0x48, 0x8B, 0x00,
     0x48, 0x03, 0xC1, 0x48, 0x63, 0x4C, 0x24, 0x7C, 0x48, 0x03, 0xC1, 0x48, 0x89, 0x44, 0x24, 0x38, 0x8B, 0x84, 0x24,
     0x80, 0x00, 0x00, 0x00, 0x89, 0x44, 0x24, 0x2C, 0x83, 0x7C, 0x24, 0x2C, 0x01, 0x74, 0x42, 0x83, 0x7C, 0x24, 0x2C,
     0x02, 0x74, 0x13, 0x83, 0x7C, 0x24, 0x2C, 0x03, 0x74, 0x60, 0x83, 0x7C, 0x24, 0x2C, 0x0A, 0x74, 0x73, 0xE9, 0x8A,
     0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x40, 0x08, 0x48, 0x25, 0xFF, 0xFF, 0x00, 0x00, 0x0F,
     0xB7, 0xC0, 0x48, 0x8B, 0x4C, 0x24, 0x38, 0x0F, 0xB7, 0x09, 0x03, 0xC8, 0x8B, 0xC1, 0x48, 0x8B, 0x4C, 0x24, 0x38,
     0x66, 0x89, 0x01, 0xEB, 0x62, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x40, 0x08, 0x48, 0xC1, 0xE8, 0x10, 0x48,
     0x25, 0xFF, 0xFF, 0x00, 0x00, 0x0F, 0xB7, 0xC0, 0x48, 0x8B, 0x4C, 0x24, 0x38, 0x0F, 0xB7, 0x09, 0x03, 0xC8, 0x8B,
     0xC1, 0x48, 0x8B, 0x4C, 0x24, 0x38, 0x66, 0x89, 0x01, 0xEB, 0x36, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x4C,
     0x24, 0x38, 0x8B, 0x09, 0x03, 0x48, 0x08, 0x8B, 0xC1, 0x48, 0x8B, 0x4C, 0x24, 0x38, 0x89, 0x01, 0xEB, 0x1C, 0x48,
     0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x4C, 0x24, 0x38, 0x48, 0x8B, 0x09, 0x48, 0x03, 0x48, 0x08, 0x48, 0x8B, 0xC1,
     0x48, 0x8B, 0x4C, 0x24, 0x38, 0x48, 0x89, 0x01, 0xE9, 0xDB, 0xFE, 0xFF, 0xFF, 0x48, 0x8B, 0x44, 0x24, 0x30, 0x8B,
     0x40, 0x04, 0x48, 0x8B, 0x4C, 0x24, 0x30, 0x48, 0x03, 0xC8, 0x48, 0x8B, 0xC1, 0x48, 0x89, 0x44, 0x24, 0x30, 0xE9,
     0x69, 0xFE, 0xFF, 0xFF, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x83, 0x78, 0x60, 0x00, 0x0F, 0x84, 0xE0, 0x01, 0x00, 0x00,
     0x48, 0x8B, 0x44, 0x24, 0x20, 0x83, 0x78, 0x64, 0x00, 0x0F, 0x84, 0xD1, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24,
     0x20, 0x48, 0x8B, 0x4C, 0x24, 0x20, 0x8B, 0x49, 0x60, 0x48, 0x03, 0x08, 0x48, 0x8B, 0xC1, 0x48, 0x89, 0x44, 0x24,
     0x40, 0x48, 0x83, 0x7C, 0x24, 0x40, 0x00, 0x0F, 0x84, 0xAD, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x40, 0x83,
     0x38, 0x00, 0x0F, 0x84, 0x9F, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x4C, 0x24, 0x40, 0x8B,
     0x09, 0x48, 0x03, 0x08, 0x48, 0x8B, 0xC1, 0x48, 0x89, 0x44, 0x24, 0x48, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B,
     0x4C, 0x24, 0x40, 0x8B, 0x49, 0x10, 0x48, 0x03, 0x08, 0x48, 0x8B, 0xC1, 0x48, 0x89, 0x84, 0x24, 0x98, 0x00, 0x00,
     0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x4C, 0x24, 0x40, 0x8B, 0x49, 0x0C, 0x48, 0x03, 0x08, 0x48, 0x8B,
     0xC1, 0x48, 0x89, 0x84, 0x24, 0xC8, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x84, 0x24, 0xC0, 0x00, 0x00, 0x00, 0x48, 0x89,
     0x84, 0x24, 0xD0, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x8C, 0x24, 0xC8, 0x00, 0x00, 0x00, 0xFF, 0x94, 0x24, 0xD0, 0x00,
     0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0xA8, 0x00, 0x00, 0x00, 0x48, 0x83, 0xBC, 0x24, 0xA8, 0x00, 0x00, 0x00, 0x00,
     0x75, 0x0A, 0xE9, 0x1B, 0x04, 0x00, 0x00, 0xE9, 0x16, 0x04, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x48, 0x48, 0x83,
     0x38, 0x00, 0x0F, 0x84, 0xF4, 0x00, 0x00, 0x00, 0x48, 0xC7, 0x84, 0x24, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x48, 0xC7, 0x84, 0x24, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x48, 0x48,
     0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x48, 0x8B, 0x00, 0x48, 0x23, 0xC1, 0x48, 0x85, 0xC0, 0x74,
     0x18, 0x48, 0x8B, 0x44, 0x24, 0x48, 0x48, 0x8B, 0x00, 0x48, 0x25, 0xFF, 0xFF, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24,
     0x88, 0x00, 0x00, 0x00, 0xEB, 0x2C, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x00, 0x48, 0x8B, 0x4C, 0x24, 0x48,
     0x48, 0x03, 0x01, 0x48, 0x89, 0x84, 0x24, 0xD8, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x84, 0x24, 0xD8, 0x00, 0x00, 0x00,
     0x48, 0x83, 0xC0, 0x02, 0x48, 0x89, 0x84, 0x24, 0x88, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x84, 0x24, 0xE0, 0x00, 0x00,
     0x00, 0x48, 0x89, 0x84, 0x24, 0xE8, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x94, 0x24, 0x88, 0x00, 0x00, 0x00, 0x48, 0x8B,
     0x8C, 0x24, 0xA8, 0x00, 0x00, 0x00, 0xFF, 0x94, 0x24, 0xE8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0x90, 0x00,
     0x00, 0x00, 0x48, 0x83, 0xBC, 0x24, 0x90, 0x00, 0x00, 0x00, 0x00, 0x75, 0x0A, 0xE9, 0x52, 0x03, 0x00, 0x00, 0xE9,
     0x4D, 0x03, 0x00, 0x00, 0x48, 0x8B, 0x84, 0x24, 0x98, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x8C, 0x24, 0x90, 0x00, 0x00,
     0x00, 0x48, 0x89, 0x08, 0x48, 0x8B, 0x44, 0x24, 0x48, 0x48, 0x83, 0xC0, 0x08, 0x48, 0x89, 0x44, 0x24, 0x48, 0x48,
     0x8B, 0x84, 0x24, 0x98, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC0, 0x08, 0x48, 0x89, 0x84, 0x24, 0x98, 0x00, 0x00, 0x00,
     0xE9, 0xFD, 0xFE, 0xFF, 0xFF, 0x48, 0x8B, 0x44, 0x24, 0x40, 0x48, 0x83, 0xC0, 0x14, 0x48, 0x89, 0x44, 0x24, 0x40,
     0xE9, 0x53, 0xFE, 0xFF, 0xFF, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x83, 0x78, 0x68, 0x00, 0x0F, 0x84, 0x85, 0x00, 0x00,
     0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x83, 0x78, 0x6C, 0x00, 0x74, 0x7A, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x83,
     0xC0, 0x68, 0x48, 0x89, 0x84, 0x24, 0xF0, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x8C, 0x24,
     0xF0, 0x00, 0x00, 0x00, 0x8B, 0x09, 0x48, 0x8B, 0x00, 0x48, 0x8B, 0x44, 0x08, 0x58, 0x48, 0x89, 0x44, 0x24, 0x60,
     0x0F, 0x31, 0x48, 0xC1, 0xE2, 0x20, 0x48, 0x0B, 0xC2, 0xC1, 0xC0, 0x0F, 0x8B, 0xC0, 0x48, 0x89, 0x84, 0x24, 0xF8,
     0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x60, 0x48, 0x8B, 0x8C, 0x24, 0xF8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x08,
     0x48, 0x8B, 0x44, 0x24, 0x60, 0x48, 0xB9, 0x32, 0xA2, 0xDF, 0x2D, 0x99, 0x2B, 0x00, 0x00, 0x48, 0x39, 0x08, 0x75,
     0x13, 0x48, 0x8B, 0x44, 0x24, 0x60, 0x48, 0x8B, 0x00, 0x48, 0xFF, 0xC0, 0x48, 0x8B, 0x4C, 0x24, 0x60, 0x48, 0x89,
     0x01, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x83, 0x78, 0x50, 0x00, 0x0F, 0x84, 0xAA, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44,
     0x24, 0x20, 0x83, 0x78, 0x54, 0x00, 0x0F, 0x84, 0x9B, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x83,
     0xC0, 0x50, 0x48, 0x89, 0x84, 0x24, 0x00, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x8C, 0x24,
     0x00, 0x01, 0x00, 0x00, 0x8B, 0x09, 0x48, 0x03, 0x08, 0x48, 0x8B, 0xC1, 0x48, 0x89, 0x84, 0x24, 0x08, 0x01, 0x00,
     0x00, 0x48, 0x8B, 0x84, 0x24, 0x08, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x40, 0x18, 0x48, 0x89, 0x44, 0x24, 0x58, 0xEB,
     0x0E, 0x48, 0x8B, 0x44, 0x24, 0x58, 0x48, 0x83, 0xC0, 0x08, 0x48, 0x89, 0x44, 0x24, 0x58, 0x48, 0x83, 0x7C, 0x24,
     0x58, 0x00, 0x74, 0x44, 0x48, 0x8B, 0x44, 0x24, 0x58, 0x48, 0x83, 0x38, 0x00, 0x74, 0x39, 0x48, 0x8B, 0x44, 0x24,
     0x58, 0x48, 0x8B, 0x00, 0x48, 0x89, 0x84, 0x24, 0x10, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x84, 0x24, 0x10, 0x01, 0x00,
     0x00, 0x48, 0x89, 0x84, 0x24, 0x18, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x45, 0x33, 0xC0, 0xBA, 0x01,
     0x00, 0x00, 0x00, 0x48, 0x8B, 0x08, 0xFF, 0x94, 0x24, 0x18, 0x01, 0x00, 0x00, 0xEB, 0xA6, 0x48, 0x83, 0xBC, 0x24,
     0xB0, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x84, 0x93, 0x00, 0x00, 0x00, 0x48, 0xC7, 0x44, 0x24, 0x68, 0x98, 0x00, 0x00,
     0x00, 0x48, 0x8D, 0x84, 0x24, 0x60, 0x01, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0x28, 0x01, 0x00, 0x00, 0x48, 0x8B,
     0x44, 0x24, 0x68, 0x48, 0x89, 0x84, 0x24, 0x20, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x68, 0x48, 0xFF, 0xC8,
     0x48, 0x89, 0x44, 0x24, 0x68, 0x48, 0x83, 0xBC, 0x24, 0x20, 0x01, 0x00, 0x00, 0x00, 0x74, 0x18, 0x48, 0x8B, 0x44,
     0x24, 0x68, 0x48, 0x8B, 0x8C, 0x24, 0x28, 0x01, 0x00, 0x00, 0x48, 0x03, 0xC8, 0x48, 0x8B, 0xC1, 0xC6, 0x00, 0x00,
     0xEB, 0xC3, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x00, 0x48, 0x89, 0x84, 0x24, 0x90, 0x01, 0x00, 0x00, 0x48,
     0x8B, 0x84, 0x24, 0xB0, 0x00, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0x30, 0x01, 0x00, 0x00, 0x48, 0x8D, 0x8C, 0x24,
     0x60, 0x01, 0x00, 0x00, 0xFF, 0x94, 0x24, 0x30, 0x01, 0x00, 0x00, 0x85, 0xC0, 0x7D, 0x0A, 0xE9, 0x16, 0x01, 0x00,
     0x00, 0xE9, 0x11, 0x01, 0x00, 0x00, 0x48, 0x83, 0xBC, 0x24, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x84, 0xB8, 0x00,
     0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x83, 0xC0, 0x58, 0x48, 0x89, 0x44, 0x24, 0x70, 0x48, 0x8B, 0x44,
     0x24, 0x70, 0x83, 0x38, 0x00, 0x0F, 0x84, 0x9C, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x70, 0x83, 0x78, 0x04,
     0x00, 0x0F, 0x84, 0x8D, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x84, 0x24, 0xB8, 0x00, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24,
     0x40, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x89, 0x84, 0x24, 0x38, 0x01, 0x00, 0x00, 0x48, 0x8B,
     0x4C, 0x24, 0x70, 0x8B, 0x49, 0x04, 0x33, 0xD2, 0x8B, 0xC1, 0xB9, 0x0C, 0x00, 0x00, 0x00, 0x48, 0xF7, 0xF1, 0x48,
     0x8B, 0x4C, 0x24, 0x20, 0x48, 0x8B, 0x54, 0x24, 0x70, 0x8B, 0x12, 0x48, 0x03, 0x11, 0x48, 0x8B, 0xCA, 0x48, 0x8B,
     0x94, 0x24, 0x38, 0x01, 0x00, 0x00, 0x4C, 0x8B, 0x02, 0x8B, 0xD0, 0xFF, 0x94, 0x24, 0x40, 0x01, 0x00, 0x00, 0x0F,
     0xB6, 0xC0, 0x85, 0xC0, 0x75, 0x04, 0xEB, 0x77, 0xEB, 0x75, 0x48, 0x8B, 0x84, 0x24, 0x48, 0x01, 0x00, 0x00, 0x48,
     0x89, 0x84, 0x24, 0x50, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x50, 0x18, 0x33, 0xC9, 0xFF,
     0x94, 0x24, 0x50, 0x01, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x75, 0x04, 0xEB, 0x4C, 0xEB, 0x4A, 0x48, 0x8B, 0x44, 0x24,
     0x20, 0x48, 0x8B, 0x4C, 0x24, 0x20, 0x8B, 0x49, 0x14, 0x48, 0x03, 0x08, 0x48, 0x8B, 0xC1, 0x48, 0x89, 0x84, 0x24,
     0x58, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x45, 0x33, 0xC0, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B,
     0x08, 0xFF, 0x94, 0x24, 0x58, 0x01, 0x00, 0x00, 0x89, 0x44, 0x24, 0x50, 0x83, 0x7C, 0x24, 0x50, 0x01, 0x74, 0x04,
     0xEB, 0x0B, 0xEB, 0x09, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC6, 0x40, 0x74, 0x01, 0x48, 0x81, 0xC4, 0x08, 0x02, 0x00,
    0x00, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC};

static UCHAR g_shellcodeExceptionHandlerStub[] = {
    0x48, 0x83, 0xEC, 0x18, 0x48, 0x89, 0x0C, 0x24, 0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE,
    0x48, 0x89, 0x44, 0x24, 0x08, 0xC7, 0x44, 0x24, 0x14, 0xAD, 0xDE, 0xEF, 0xBE, 0x48, 0x8B, 0x04, 0x24, 0x48,
    0x8B, 0x00, 0x81, 0x38, 0x63, 0x73, 0x6D, 0xE0, 0x75, 0x70, 0x48, 0x8B, 0x04, 0x24, 0x48, 0x8B, 0x00, 0x48,
    0x8B, 0x40, 0x30, 0x48, 0x3B, 0x44, 0x24, 0x08, 0x72, 0x5C, 0x48, 0x8B, 0x04, 0x24, 0x48, 0x8B, 0x00, 0x48,
    0x8B, 0x40, 0x30, 0x48, 0x8B, 0x4C, 0x24, 0x08, 0x8B, 0x54, 0x24, 0x14, 0x48, 0x01, 0xD1, 0x48, 0x39, 0xC8,
    0x73, 0x40, 0x48, 0x8B, 0x04, 0x24, 0x48, 0x8B, 0x00, 0x48, 0x81, 0x78, 0x20, 0x00, 0x40, 0x99, 0x01, 0x75,
    0x2D, 0x48, 0x8B, 0x04, 0x24, 0x48, 0x8B, 0x00, 0x48, 0x83, 0x78, 0x38, 0x00, 0x75, 0x1F, 0x48, 0x8B, 0x04,
    0x24, 0x48, 0x8B, 0x00, 0x48, 0xC7, 0x40, 0x20, 0x20, 0x05, 0x93, 0x19, 0x48, 0x8B, 0x44, 0x24, 0x08, 0x48,
    0x8B, 0x0C, 0x24, 0x48, 0x8B, 0x09, 0x48, 0x89, 0x41, 0x38, 0xEB, 0x00, 0xEB, 0x00, 0x31, 0xC0, 0x48, 0x83,
    0xC4, 0x18, 0xC3, 0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00};

NTSTATUS InjectImage(_In_ PVOID imageBase, _In_ SIZE_T imageSize);
NTSTATUS AttachAndInject(_In_ PEPROCESS process, _In_ PVOID imageBase, _In_ SIZE_T imageSize);
} // namespace Inject