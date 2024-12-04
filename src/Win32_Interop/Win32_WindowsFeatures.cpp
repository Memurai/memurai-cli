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

#include <windows.h>
#include <stdio.h>
#include <versionhelpers.h>
#include <io.h>

class WindowsVersion {
    typedef VOID(NTAPI* TRtlGetNtVersionNumbers)(LPDWORD pdwMajorVersion, LPDWORD pdwMinorVersion, LPDWORD pdwBuildNumber);

private:
    bool _isAtLeast_6_0;
    bool _isAtLeast_6_2;
    bool _isAtLeast_10_0;
    bool _isAtLeast_10_AU; // Anniversary Update
    bool _isAtLeast_10_2004;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    char _windowsVersion[64];

    WindowsVersion() {
        TRtlGetNtVersionNumbers RtlGetNtVersionNumbers = (TRtlGetNtVersionNumbers)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetNtVersionNumbers");
        RtlGetNtVersionNumbers(&dwMajorVersion, &dwMinorVersion, &dwBuildNumber);
        dwBuildNumber &= 0x0000FFFF;

        _isAtLeast_6_0 = isWindowsVersionAtLeast(6, 0, 0);
        _isAtLeast_6_2 = isWindowsVersionAtLeast(6, 2, 0);
        _isAtLeast_10_0 = isWindowsVersionAtLeast(10, 0, 0);
        _isAtLeast_10_AU = isWindowsVersionAtLeast(10, 0, 14393);
        _isAtLeast_10_2004 = isWindowsVersionAtLeast(10, 0, 19041);

        sprintf(_windowsVersion, "%s %d.%d.%d", (IsWindowsServer() ? "Server" : "Client"), dwMajorVersion, dwMinorVersion, dwBuildNumber);
    }

    WindowsVersion(WindowsVersion const&);      // Don't implement to guarantee singleton semantics
    void operator=(WindowsVersion const&);      // Don't implement to guarantee singleton semantics

    bool isWindowsVersionAtLeast(DWORD majorVersion, DWORD minorVersion, DWORD buildNumber) {
        if (dwMajorVersion > majorVersion) {
            return true;
        }

        if (dwMajorVersion == majorVersion) {
            if (dwMinorVersion > minorVersion) {
                return true;
            }

            if (dwMinorVersion == minorVersion) {
                if (dwBuildNumber >= buildNumber) {
                    return true;
                }
            }
        }
        return false;
    }

public:
    static WindowsVersion& getInstance() {
        static WindowsVersion instance;         // Instantiated on first use. Guaranteed to be destroyed.
        return instance;
    }

    bool IsAtLeast_6_0() {
        return _isAtLeast_6_0;
    }

    bool IsAtLeast_6_2() {
        return _isAtLeast_6_2;
    }

    bool IsAtLeast_10_0() {
        return _isAtLeast_10_0;
    }

    bool IsAtLeast_10_AU() {
        return _isAtLeast_10_AU;
    }

    bool IsAtLeast_10_2004() {
        return _isAtLeast_10_2004;
    }

    char* GetVersion() {
        return _windowsVersion;
    }
};

extern "C" int IsAtLeastWindows_6_0() {
    return WindowsVersion::getInstance().IsAtLeast_6_0();
}

extern "C" int IsAtLeastWindows_6_2() {
    return WindowsVersion::getInstance().IsAtLeast_6_2();
}

extern "C" int IsAtLeastWindows_10_0() {
    return WindowsVersion::getInstance().IsAtLeast_10_0();
}

extern "C" int IsAtLeastWindows_10_AU() {
    return WindowsVersion::getInstance().IsAtLeast_10_AU();
}

extern "C" int IsAtLeastWindows_10_2004() {
    return WindowsVersion::getInstance().IsAtLeast_10_2004();
}

extern "C" char* GetWindowsVersion() {
    return WindowsVersion::getInstance().GetVersion();
}

class VTEmulation {
    
private:
    bool _CustomVTEmulationRequired;

    VTEmulation() {
        _CustomVTEmulationRequired = false;
    }

    VTEmulation(VTEmulation const&);        // Don't implement to guarantee singleton semantics
    void operator=(VTEmulation const&);     // Don't implement to guarantee singleton semantics

    bool EnableVTEmulationIfAvailable() {
        bool result = false;

        if (WindowsVersion::getInstance().IsAtLeast_10_AU()) {
            // Set output mode to handle virtual terminal sequences
            HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
            if (hOut == INVALID_HANDLE_VALUE) {
                goto EXIT;
            }

            DWORD dwMode = 0;
            if (!GetConsoleMode(hOut, &dwMode)) {
                goto EXIT;
            }

            dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            if (!SetConsoleMode(hOut, dwMode)) {
                goto EXIT;
            }

            result = true;
        }

    EXIT:
        return result;
    }

public:
    static VTEmulation& getInstance() {
        static VTEmulation instance;         // Instantiated on first use. Guaranteed to be destroyed.
        return instance;
    }

    void Initialize() {
        if (_isatty(_fileno(stdout))) {
            _CustomVTEmulationRequired = !EnableVTEmulationIfAvailable();
        }
    }

    bool IsCustomVTEmulationRequired() {
        return _CustomVTEmulationRequired;
    }
};

extern "C" void InitializeVTEmulation() {
    VTEmulation::getInstance().Initialize();
}

extern "C" int IsCustomVTEmulationRequired() {
    return VTEmulation::getInstance().IsCustomVTEmulationRequired();
}
