/*
 * Copyright (c) 2009-2012, Salvatore Sanfilippo <antirez at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* Every time the Redis Git SHA1 or Dirty status changes only this small
 * file is recompiled, as we access this information in all the other
 * files using this functions. */

#include "Win32_Interop/Win32_Portability.h"
#include "Win32_Interop/win32_types_hiredis.h"

#ifdef _WIN32
#define REDIS_GIT_SHA1 "00000000"   /* TODO: Modify build to write them to release.h from the environment */
#define REDIS_GIT_DIRTY "0"
#define REDIS_BUILD_ID "0000"
#endif

#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#include "version.h"
#else
#include "release.h"
#endif
#include "crc64.h"

char *redisGitSHA1(void) {
    return REDIS_GIT_SHA1;
}

char *redisGitDirty(void) {
    return REDIS_GIT_DIRTY;
}

const char *redisBuildIdRaw(void) {
    return MEMURAI_VERSION;         WIN_PORT_FIX /* REDIS_BUILD_ID_RAW -> MEMURAI_VERSION*/
}

uint64_t redisBuildId(void) {
    char *buildid = MEMURAI_VERSION;

    return crc64(0,(unsigned char*)buildid,strlen(buildid));
}

/* Return a cached value of the build string in order to avoid recomputing
 * and converting it in hex every time: this string is shown in the INFO
 * output that should be fast. */
char *redisBuildIdString(void) {
    static char buf[32];
    static int cached = 0;
    if (!cached) {
        snprintf(buf,sizeof(buf),"%llx",(PORT_ULONGLONG) redisBuildId());
        cached = 1;
    }
    return buf;
}
