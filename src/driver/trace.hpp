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

#include <evntrace.h>

#if DBG || FORCE_DBGPRINT
#define DBG_PRINT(s, ...) DbgPrintEx(0, 0, "[VAC] F: %s L: %d -- " s "\n", __FILE__, __LINE__, __VA_ARGS__)
#else
#define DBG_PRINT(s, ...)
#endif

#if !DBG
#define WPP_PRINT(a, b, s, ...) DBG_PRINT(s, __VA_ARGS__)
#define WPP_INIT_TRACING(...)
#define WPP_CLEANUP(...)

#define GENERAL

#else
#define WPP_GLOBALLOGGER
#define WPP_CHECK_FOR_NULL_STRING

// {BBB7063B-B267-4728-A95D-304A8E4E6A89}
#define WPP_CONTROL_GUIDS                                                                                              \
    WPP_DEFINE_CONTROL_GUID(VacCtrlGuid, (BBB7063B, B267, 4728, A95D, 304A8E4E6A89),                                   \
                            WPP_DEFINE_BIT(GENERAL) /* bit  0 = 0x00000001 */                                          \
    )

#define WPP_LEVEL_EVENT_LOGGER(level, event) WPP_LEVEL_LOGGER(event)
#define WPP_LEVEL_EVENT_ENABLED(level, event) (WPP_LEVEL_ENABLED(event) && WPP_CONTROL(WPP_BIT_##event).Level >= level)

#define TMH_STRINGIFYX(x) #x
#define TMH_STRINGIFY(x) TMH_STRINGIFYX(x)

#ifdef TMH_FILE
#include TMH_STRINGIFY(TMH_FILE)
#endif
#endif