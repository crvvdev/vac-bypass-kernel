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

#include "includes.hpp"

namespace Mutex
{
NTSTATUS Resource::Initialize()
{
    PAGED_CODE();
    NT_ASSERT(!this->_initialized);

    if (this->_initialized)
    {
        return STATUS_ALREADY_INITIALIZED;
    }

    this->_resource = reinterpret_cast<PERESOURCE>(Memory::AllocNonPaged(sizeof(ERESOURCE), Memory::TAG_RESOURCE));
    if (!this->_resource)
    {
        WPP_PRINT(TRACE_LEVEL_ERROR, GENERAL, "Failed to allocate %u bytes for resource!", sizeof(ERESOURCE));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ExInitializeResourceLite(this->_resource);

    this->_initialized = true;

    return STATUS_SUCCESS;
}

void Resource::Destroy()
{
    PAGED_CODE();
    NT_ASSERT(this->_initialized);

    if (!this->_initialized)
    {
        return;
    }

    this->_initialized = false;

    // Wait until all references to the lock are released
    //
    while (InterlockedCompareExchange(&this->_refCount, 0, 0) != 0)
    {
        YieldProcessor();
    }

    ExDeleteResourceLite(this->_resource);
    Memory::FreePool(this->_resource);
}

void Resource::LockExclusive()
{
    PAGED_CODE();

    if (!this->_initialized)
    {
        return;
    }

    InterlockedIncrement(&this->_refCount);
    ExEnterCriticalRegionAndAcquireResourceExclusive(this->_resource);
}

void Resource::LockShared()
{
    PAGED_CODE();

    if (!this->_initialized)
    {
        return;
    }

    InterlockedIncrement(&this->_refCount);
    ExEnterCriticalRegionAndAcquireResourceShared(this->_resource);
}

void Resource::Unlock()
{
    PAGED_CODE();

    if (!this->_initialized)
    {
        return;
    }

    ExReleaseResourceAndLeaveCriticalRegion(this->_resource);
    InterlockedDecrement(&this->_refCount);
}

} // namespace Mutex