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

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <type_traits>
#include <algorithm>

#include <ntifs.h>
#include <ntintsafe.h>
#include <minwindef.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include <bcrypt.h>
#include <intrin.h>
#include <evntrace.h>
#include <wmistr.h>

#ifdef __cplusplus
extern "C"
{
#endif
#include <phnt.h>
#include <ntfill.h>
#include <ntpebteb.h>
#include <ntldr.h>
#include <ntwow64.h>
//#include "nth/ntapi.h"
#ifdef __cplusplus
}
#endif

#include <fnv1a/include/fnv1a.hpp>
#include <scope_guard/include/scope_guard.hpp>

#include "..\shared\shared.hpp"

#include "hde\hde64.h"
#include "trace.hpp"
#include "def.hpp"
#include "crc32.hpp"
#include "mutex.hpp"
#include "misc.hpp"
#include "memory.hpp"
#include "threads.hpp"
#include "dynamic.hpp"
#include "processes.hpp"
#include "hooks.hpp"
#include "syscall_hook.hpp"
#include "syscall_table.hpp"
#include "inject.hpp"
#include "callbacks.hpp"
#include "bypass.hpp"
#include "ioctl.hpp"