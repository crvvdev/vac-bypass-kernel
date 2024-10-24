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

#define DEFINE_DYN_CONTEXT_PROC(return_type, proc_name, var_type)                                                      \
    __forceinline return_type proc_name(var_type p)                                                                    \
    {                                                                                                                  \
        return reinterpret_cast<return_type>(PTR_OFFSET_ADD(p, Offset.proc_name));                                     \
    }

#define DEFINE_DYN_CONTEXT_PROC_PTR(return_type, proc_name, var_type)                                                  \
    __forceinline return_type proc_name(var_type p)                                                                    \
    {                                                                                                                  \
        return *reinterpret_cast<return_type *>(PTR_OFFSET_ADD(p, Offset.proc_name));                                  \
    }

namespace Dynamic
{
struct _DYNAMIC_CONTEXT
{
    struct
    {
        PVOID NtoskrnlBase;
        ULONG Major;
        ULONG Minor;
        ULONG Build;

        struct
        {
#if (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_INFINITY_HOOK)
            ULONG_PTR EtwpDebuggerData;
            ULONG_PTR HvlpReferenceTscPage;
            ULONG_PTR HvlGetQpcBias;
#endif
            PULONG_PTR KeServiceDescriptorTable;

        } Address;

        struct
        {
#if (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_INFINITY_HOOK)
            ULONG GetCpuClock;
#endif
        } Offset;

#if (SYSCALL_HOOK_TYPE == SYSCALL_HOOK_INFINITY_HOOK)
        DEFINE_DYN_CONTEXT_PROC(PVOID *, GetCpuClock, ULONG_PTR)
#endif
    } Kernel;

} inline g_DynamicContext{};

[[nodiscard]] NTSTATUS Initialize();
void Unitialize();

}; // namespace Dynamic

#define NTOS_BASE Dynamic::g_DynamicContext.Kernel.NtoskrnlBase
#define NTOS_MAJOR Dynamic::g_DynamicContext.Kernel.Major
#define NTOS_MINOR Dynamic::g_DynamicContext.Kernel.Minor
#define NTOS_BUILD Dynamic::g_DynamicContext.Kernel.Build