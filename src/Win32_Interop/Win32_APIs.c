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

#include "Win32_APIs.h"
#include "Win32_Error.h"
#include <direct.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <shlobj_core.h>
#include <shlwapi.h>    // for PathRemoveFileSpecA
#pragma comment (lib, "Shlwapi.lib")

typedef BOOLEAN(_stdcall* RtlGenRandomFunc)(void * RandomBuffer, ULONG RandomBufferLength);
RtlGenRandomFunc RtlGenRandom;

extern DWORD usleep_tls_index;

void usleep_win_impl(int microseconds) {
    if (microseconds == 1) {
        // The thread yields its time slice
        Sleep(0);
    } else {
        // We accumulate the arguments until we reach at least 1000,
        // then we can call Sleep
        intptr_t micros_so_far = TlsGetValue(usleep_tls_index);
        micros_so_far += microseconds;
        if (micros_so_far >= 1000) {
            Sleep(micros_so_far / 1000);
            micros_so_far %= 1000;
        }
        TlsSetValue(usleep_tls_index, micros_so_far);
    }
}

/* Replace MS C rtl rand which is 15bit with 32 bit */
int PORT_random() {
    // If you decide to change implementation of this function,
    // remember to update PORT_RAND_MAX accordingly
    unsigned int x = 0;
    if (RtlGenRandom == NULL) {
        // Load proc if not loaded
        HMODULE lib = LoadLibraryA("advapi32.dll");
        RtlGenRandom = (RtlGenRandomFunc) GetProcAddress(lib, "SystemFunction036");
        if (RtlGenRandom == NULL) return 1;
    }
    RtlGenRandom(&x, sizeof(unsigned int));
    return (int) (x >> 1);
}

/* Return zero on success, -1 on failure */
int getAppDataPathA(char *buffer) {
    return SHGetFolderPathA(NULL,
        CSIDL_LOCAL_APPDATA | CSIDL_FLAG_CREATE,
        NULL,
        0,
        buffer) == S_OK ? 0 : -1;
}

/* Return zero on success or if the folder tree already exists, -1 on failure */
int createFolderTreeA(char *root, ... ) {
    va_list args;
    int result = 0;
    char path[MAX_PATH+1];
    _snprintf(path, MAX_PATH, "%s", root);

    va_start(args, root);
    char *child = NULL;
    do {
        child = va_arg(args, char*);
        if (child != NULL) {
            _snprintf(path, MAX_PATH, "%s\\%s", path, child);
            if (CreateDirectoryA(path, NULL) == 0) {
                if (GetLastError() != ERROR_ALREADY_EXISTS) {
                    result = -1;
                    break;
                }
            }
        }
    } while (child != NULL);

    va_end(args);
    return result;
}
