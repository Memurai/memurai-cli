/*
 * Copyright (c), Microsoft Open Technologies, Inc.
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef WIN32_INTEROP_TYPES_HIREDIS_H
#define WIN32_INTEROP_TYPES_HIREDIS_H

/* On 64-bit *nix and Windows use different data type models: LP64 and LLP64 respectively.
 * The main difference is that 'long' is 64-bit on 64-bit *nix and 32-bit on 64-bit Windows.
 * The Posix version of Redis makes many assumptions about long being 64-bit and the same size
 * as pointers.
 * To deal with this issue, we replace all occurrences of 'long' in antirez code with our own typedefs,
 * and make those definitions 64-bit to match antirez' assumptions.
 * This enables us to have merge check script to verify that no new instances of 'long' go unnoticed.
*/

#define PORT_LONGLONG     long long
#define PORT_ULONGLONG    unsigned long long
#define PORT_LONGDOUBLE   long double

#ifdef _WIN32

typedef long long ssize_t;

#define SSIZE_MAX (LLONG_MAX >> 1)

#ifndef __clang__
#define __attribute__(x)
#endif

typedef int pid_t;

#ifndef mode_t
#define mode_t unsigned __int32
#endif

#endif // _WIN32

#ifdef _WIN64
#define PORT_LONG         __int64
#define PORT_ULONG        unsigned __int64
#else
#define PORT_LONG         long
#define PORT_ULONG        unsigned long
#endif

#ifdef _WIN64
#define PORT_LONG_MAX     _I64_MAX
#define PORT_LONG_MIN     _I64_MIN
#define PORT_ULONG_MAX    _UI64_MAX
#else
#define PORT_LONG_MAX     LONG_MAX
#define PORT_LONG_MIN     LONG_MIN
#define PORT_ULONG_MAX    ULONG_MAX
#endif

#define PORT_RAND_MAX	0x7fffffff

#if defined(_WIN32) && defined(REDEFINE_OFF_T)

#if !defined(_OFF_T_DEFINED)
#error "Make sure _OFF_T_DEFINED is defined at project level"
#endif

/* The Posix version of Redis defines off_t as 64-bit integers, so we do the same.
 * On Windows, these types are defined as 32-bit in sys/types.h under and #ifndef _OFF_T_DEFINED
 * So we define _OFF_T_DEFINED at the project level, to make sure that that definition is never included.
 * If you get an error about re-definition, make sure to include this file before sys/types.h, or any other
 * file that include it (eg wchar.h).
 * _off_t is also defined #ifndef _OFF_T_DEFINED, so we need to define it here.
 * It is used by the CRT internally (but not by Redis), so we leave it as 32-bit.
 */

typedef __int64     off_t;
typedef long        _off_t;

#endif // defined(_WIN32) && defined(REDEFINE_OFF_T)

#endif // WIN32_INTEROP_TYPES_HIREDIS_H
