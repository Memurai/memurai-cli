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

#ifndef WIN32_INTEROP_SIGNALPROCESS_H
#define WIN32_INTEROP_SIGNALPROCESS_H

#include <signal.h>

/* Signals */
#define SIGNULL  0 /* Null	Check access to pid*/
#define SIGHUP	 1 /* Hangup	Terminate; can be trapped*/
#define SIGINT	 2 /* Interrupt	Terminate; can be trapped */
#define SIGQUIT	 3 /* Quit	Terminate with core dump; can be trapped */
#define SIGTRAP  5
#define SIGBUS   7
#define SIGKILL	 9 /* Kill	Forced termination; cannot be trapped */
#define SIGPIPE 13
#define SIGALRM 14
#define SIGTERM	15 /* Terminate	Terminate; can be trapped  */
#define SIGSTOP 17
#define SIGTSTP 18
#define SIGCONT 19
#define SIGCHLD 20
#define SIGTTIN 21
#define SIGTTOU 22
#define SIGABRT 22
/* #define SIGSTOP	24 /*Pause the process; cannot be trapped*/
/* #define SIGTSTP	25 /*Terminal stop	Pause the process; can be trapped*/
/* #define SIGCONT	26 /* */
#define SIGWINCH 28
#define SIGUSR1  30
#define SIGUSR2  31

#define SA_NOCLDSTOP    0x00000001u
#define SA_NOCLDWAIT    0x00000002u
#define SA_SIGINFO      0x00000004u
#define SA_ONSTACK      0x08000000u
#define SA_RESTART      0x10000000u
#define SA_NODEFER      0x40000000u
#define SA_RESETHAND    0x80000000u
#define SA_NOMASK       SA_NODEFER
#define SA_ONESHOT      SA_RESETHAND
#define SA_RESTORER     0x04000000

#endif