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

namespace Comms
{
typedef struct _INJECT_IMAGE_CONTEXT
{
    WORK_QUEUE_ITEM WorkItem;
    PEPROCESS Process;
    PVOID ImageBase;
    ULONG ImageSize;
    NTSTATUS Status;
    KEVENT Event;

} INJECT_IMAGE_CONTEXT, *PINJECT_IMAGE_CONTEXT;

static void InjectImageWorkerRoutine(_In_ PVOID param)
{
    PAGED_CODE();
    NT_ASSERT(param);

    auto context = reinterpret_cast<PINJECT_IMAGE_CONTEXT>(param);

    // Attach to process context and inject image
    //
    context->Status = Inject::AttachAndInject(context->Process, context->ImageBase, context->ImageSize);

    KeSetEvent(&context->Event, IO_NO_INCREMENT, FALSE);
};

NTSTATUS HandleIoctl(_In_ PVOID data, _In_ ULONG dataSize)
{
    PAGED_CODE();
    NT_ASSERT(data);

    // Communication request handlers
    //
    auto HandleDisableBypass = [](_In_ const PDRIVER_REQUEST_DISABLE_BYPASS request) -> NTSTATUS {
        NTSTATUS status;
        __try
        {
            Hooks::g_shouldBypass = false;

            WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "Bypass is currently disabled!");

            request->SetStatus(STATUS_SUCCESS);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = GetExceptionCode();
            return status;
        }
        return STATUS_SUCCESS;
    };

    auto HandleEnableBypass = [](_In_ const PDRIVER_REQUEST_ENABLE_BYPASS request) -> NTSTATUS {
        NTSTATUS status;
        __try
        {
            Hooks::g_shouldBypass = true;

            WPP_PRINT(TRACE_LEVEL_VERBOSE, GENERAL, "Bypass is currently enabled!");

            request->SetStatus(STATUS_SUCCESS);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = GetExceptionCode();
            return status;
        }
        return STATUS_SUCCESS;
    };

    auto HandleInject = [](_In_ const PDRIVER_REQUEST_INJECT request) -> NTSTATUS {
        NTSTATUS status = STATUS_UNSUCCESSFUL;

        if (request->ImageSize <= 0)
        {
            status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        __try
        {
            Hooks::g_shouldBypass = true;

            ProbeForRead(request->ImageBase, request->ImageSize, alignof(PVOID));

            // Store image in kernel memory
            //
            auto imageBase = Memory::AllocNonPaged(request->ImageSize, Memory::TAG_DEFAULT);
            if (!imageBase)
            {
                WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate %u bytes for image!", request->ImageSize);

                status = STATUS_INSUFFICIENT_RESOURCES;
                goto Exit;
            }

            RtlCopyMemory(imageBase, request->ImageBase, request->ImageSize);

            PEPROCESS process = Processes::GetGameProcess();
            if (!process)
            {
                WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to get game process!");

                status = STATUS_UNSUCCESSFUL;
                goto Exit;
            }

            SCOPE_EXIT
            {
                ObDereferenceObject(process);
            };

            // Build inject image context
            //
            auto imageContext = reinterpret_cast<PINJECT_IMAGE_CONTEXT>(
                Memory::AllocNonPaged(sizeof(INJECT_IMAGE_CONTEXT), Memory::TAG_DEFAULT));
            if (!imageContext)
            {
                WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate %u bytes for image context!",
                          sizeof(INJECT_IMAGE_CONTEXT));

                status = STATUS_INSUFFICIENT_RESOURCES;
                goto Exit;
            }

            SCOPE_EXIT
            {
                Memory::FreePool(imageContext);
            };

            // We will be issuing a worker item to do the job.
            //
            imageContext->Process = process;
            imageContext->ImageBase = imageBase;
            imageContext->ImageSize = request->ImageSize;
            KeInitializeEvent(&imageContext->Event, NotificationEvent, FALSE);
            ExInitializeWorkItem(&imageContext->WorkItem, &InjectImageWorkerRoutine, imageContext);
            ExQueueWorkItem(&imageContext->WorkItem, DelayedWorkQueue);

            // Wait for worker item to finish
            //
            status = KeWaitForSingleObject(&imageContext->Event, Executive, KernelMode, FALSE, nullptr);
            if (!NT_SUCCESS(status))
            {
                WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "KeWaitForSingleObject returned %!STATUS!", status);
                goto Exit;
            }

            status = imageContext->Status;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = GetExceptionCode();
        }
    Exit:
        request->SetStatus(status);
        return status;
    };

    // Check if size is expected
    //
    if (dataSize < sizeof(DRIVER_REQUEST_HEADER))
    {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    // Check if request is valid and process it
    //
    const auto requestData = static_cast<PDRIVER_REQUEST_HEADER>(data);
    if (!requestData->IsValid())
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Invalid communication request data!");
        return status;
    }

    switch (requestData->Request)
    {
    case EDriverCommunicationRequest::DisableBypass: {
        if (dataSize < sizeof(DRIVER_REQUEST_DISABLE_BYPASS))
        {
            status = STATUS_INVALID_PARAMETER_1;
            break;
        }
        return HandleDisableBypass(reinterpret_cast<PDRIVER_REQUEST_DISABLE_BYPASS>(data));
    }
    case EDriverCommunicationRequest::EnableBypass: {
        if (dataSize < sizeof(DRIVER_REQUEST_ENABLE_BYPASS))
        {
            status = STATUS_INVALID_PARAMETER_1;
            break;
        }
        return HandleEnableBypass(reinterpret_cast<PDRIVER_REQUEST_ENABLE_BYPASS>(data));
    }
    case EDriverCommunicationRequest::InjectDll: {
        if (dataSize < sizeof(DRIVER_REQUEST_INJECT))
        {
            status = STATUS_INVALID_PARAMETER_1;
            break;
        }
        return HandleInject(reinterpret_cast<PDRIVER_REQUEST_INJECT>(data));
    }
    }
    return status;
}
}; // namespace Comms