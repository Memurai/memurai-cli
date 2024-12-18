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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C"
{
#endif

/* Converts error codes returned by GetLastError/WSAGetLastError to errno codes */
int translate_sys_error(int sys_error) {
  switch (sys_error) {
    case ERROR_SUCCESS:                     return 0;
    case ERROR_NOACCESS:                    return EACCES;
    case WSAEACCES:                         return EACCES;
    case ERROR_ADDRESS_ALREADY_ASSOCIATED:  return EADDRINUSE;
    case WSAEADDRINUSE:                     return EADDRINUSE;
    case WSAEADDRNOTAVAIL:                  return EADDRNOTAVAIL;
    case WSAEAFNOSUPPORT:                   return EAFNOSUPPORT;
    case WSAEWOULDBLOCK:                    return EAGAIN;
    case WSAEALREADY:                       return EALREADY;
    case ERROR_INVALID_FLAGS:               return EBADF;
    case ERROR_INVALID_HANDLE:              return EBADF;
    case ERROR_LOCK_VIOLATION:              return EBUSY;
    case ERROR_PIPE_BUSY:                   return EBUSY;
    case ERROR_SHARING_VIOLATION:           return EBUSY;
    case ERROR_OPERATION_ABORTED:           return ECANCELED;
    case WSAEINTR:                          return ECANCELED;
    case ERROR_CONNECTION_ABORTED:          return ECONNABORTED;
    case WSAECONNABORTED:                   return ECONNABORTED;
    case ERROR_CONNECTION_REFUSED:          return ECONNREFUSED;
    case WSAECONNREFUSED:                   return ECONNREFUSED;
    case ERROR_NETNAME_DELETED:             return ECONNRESET;
    case WSAECONNRESET:                     return ECONNRESET;
    case ERROR_ALREADY_EXISTS:              return EEXIST;
    case ERROR_FILE_EXISTS:                 return EEXIST;
    case ERROR_BUFFER_OVERFLOW:             return EFAULT;
    case WSAEFAULT:                         return EFAULT;
    case ERROR_HOST_UNREACHABLE:            return EHOSTUNREACH;
    case WSAEHOSTUNREACH:                   return EHOSTUNREACH;
    case WSAEINPROGRESS:                    return EINPROGRESS;
    case ERROR_INSUFFICIENT_BUFFER:         return EINVAL;
    case ERROR_INVALID_DATA:                return EINVAL;
    case ERROR_INVALID_PARAMETER:           return EINVAL;
    case ERROR_SYMLINK_NOT_SUPPORTED:       return EINVAL;
    case WSAEINVAL:                         return EINVAL;
    case WSAEPFNOSUPPORT:                   return EINVAL;
    case WSAESOCKTNOSUPPORT:                return EINVAL;
    case ERROR_BEGINNING_OF_MEDIA:          return EIO;
    case ERROR_BUS_RESET:                   return EIO;
    case ERROR_CRC:                         return EIO;
    case ERROR_DEVICE_DOOR_OPEN:            return EIO;
    case ERROR_DEVICE_REQUIRES_CLEANING:    return EIO;
    case ERROR_DISK_CORRUPT:                return EIO;
    case ERROR_EOM_OVERFLOW:                return EIO;
    case ERROR_FILEMARK_DETECTED:           return EIO;
    case ERROR_GEN_FAILURE:                 return EIO;
    case ERROR_INVALID_BLOCK_LENGTH:        return EIO;
    case ERROR_IO_DEVICE:                   return EIO;
    case ERROR_NO_DATA_DETECTED:            return EIO;
    case ERROR_NO_SIGNAL_SENT:              return EIO;
    case ERROR_OPEN_FAILED:                 return EIO;
    case ERROR_SETMARK_DETECTED:            return EIO;
    case ERROR_SIGNAL_REFUSED:              return EIO;
    case WSAEISCONN:                        return EISCONN;
    case ERROR_CANT_RESOLVE_FILENAME:       return ELOOP;
    case ERROR_TOO_MANY_OPEN_FILES:         return EMFILE;
    case WSAEMFILE:                         return EMFILE;
    case WSAEMSGSIZE:                       return EMSGSIZE;
    case ERROR_FILENAME_EXCED_RANGE:        return ENAMETOOLONG;
    case WSAENETDOWN:                       return ENETDOWN;
    case WSAENETRESET:                      return ENETRESET;
    case ERROR_NETWORK_UNREACHABLE:         return ENETUNREACH;
    case WSAENETUNREACH:                    return ENETUNREACH;
    case WSAENOBUFS:                        return ENOBUFS;
    case ERROR_DIRECTORY:                   return ENOENT;
    case ERROR_FILE_NOT_FOUND:              return ENOENT;
    case ERROR_INVALID_NAME:                return ENOENT;
    case ERROR_INVALID_DRIVE:               return ENOENT;
    case ERROR_INVALID_REPARSE_DATA:        return ENOENT;
    case ERROR_MOD_NOT_FOUND:               return ENOENT;
    case ERROR_PATH_NOT_FOUND:              return ENOENT;
    case WSAHOST_NOT_FOUND:                 return ENOENT;
    case WSANO_DATA:                        return ENOENT;
    case ERROR_NOT_ENOUGH_MEMORY:           return ENOMEM;
    case ERROR_OUTOFMEMORY:                 return ENOMEM;
    case ERROR_CANNOT_MAKE:                 return ENOSPC;
    case ERROR_DISK_FULL:                   return ENOSPC;
    case ERROR_EA_TABLE_FULL:               return ENOSPC;
    case ERROR_END_OF_MEDIA:                return ENOSPC;
    case ERROR_HANDLE_DISK_FULL:            return ENOSPC;
    case ERROR_NOT_CONNECTED:               return ENOTCONN;
    case WSAENOTCONN:                       return ENOTCONN;
    case ERROR_DIR_NOT_EMPTY:               return ENOTEMPTY;
    case WSAENOTSOCK:                       return ENOTSOCK;
    case ERROR_NOT_SUPPORTED:               return ENOTSUP;
    case WSAEOPNOTSUPP:                     return EOPNOTSUPP;
    case ERROR_BROKEN_PIPE:                 return EPIPE;
    case ERROR_ACCESS_DENIED:               return EPERM;
    case ERROR_PRIVILEGE_NOT_HELD:          return EPERM;
    case ERROR_BAD_PIPE:                    return EPIPE;
    case ERROR_NO_DATA:                     return EPIPE;
    case ERROR_PIPE_NOT_CONNECTED:          return EPIPE;
    case WSAESHUTDOWN:                      return EPIPE;
    case WSAEPROTONOSUPPORT:                return EPROTONOSUPPORT;
    case ERROR_WRITE_PROTECT:               return EROFS;
    case ERROR_SEM_TIMEOUT:                 return ETIMEDOUT;
    case WSAETIMEDOUT:                      return ETIMEDOUT;
    case ERROR_NOT_SAME_DEVICE:             return EXDEV;
    case ERROR_INVALID_FUNCTION:            return EISDIR;
    case ERROR_META_EXPANSION_TOO_LONG:     return E2BIG;
    case ERROR_IO_PENDING:                  return ERROR_IO_PENDING; // Calls care about this specific error (=WSA_IO_PENDING).
    default:                                return -9999; // to avoid conflicts with other custom codes
  }
}

/* */
void set_errno_from_last_error() {
    errno = translate_sys_error(GetLastError());
}

const char* getPosixErrnoMessage(int err) {
    // This implementation only attempts to provide message strings for error codes that are not
    // already supported by strerror_s().
    // Even among those, the list might be incomplete.
    switch (err) {
    case EADDRINUSE:
        return "Address already in use";
    case EADDRNOTAVAIL:
        return "Address not available";
    case EAFNOSUPPORT:
        return "Address family not supported by protocol family";
    case EALREADY:
        return "Socket already connected";
    case ECANCELED:
        return "Operation canceled";
    case ECONNABORTED:
        return "Software caused connection abort";
    case ECONNREFUSED:
        return "Connection refused";
    case ECONNRESET:
        return "Connection reset by peer";
    case EHOSTUNREACH:
        return "Host is unreachable";
    case EISCONN:
        return "Socket is already connected";
    case ELOOP:
        return "Too many symbolic links";
    case EMSGSIZE:
        return "Message too long";
    case ENAMETOOLONG:
        return "File or path name too long";
    case ENETUNREACH:
        return "Network is unreachable";
    case ENOBUFS:
        return "No buffer space available";
    case ENOTCONN:
        return "Socket is not connected";
    case ENOTEMPTY:
        return "Directory not empty";
    case ENOTSOCK:
        return "Socket operation on non-socket";
    case ENOTSUP:
        return "Not supported";
    case EPROTONOSUPPORT:
        return "Unknown protocol";
    case ETIMEDOUT:
        return "Connection timed out";

    default:
        return NULL;
    }
}

/* */
int strerror_r(int err, char* buf, size_t buflen) {
    if (err >= 0 && err < _sys_nerr) {
        return strerror_s(buf, buflen, err);
    }

    // strerror_s only has support for a few error messages, so we fallback to our own table.
    const char *msg = getPosixErrnoMessage(err);
    if (msg != NULL) {
        int r = snprintf(buf, buflen, msg);
        return (r == -1) ? -1 : 0;
    }
    else {
        int r = snprintf(buf, buflen, "Unknown error (%d)", err);
        return (r == -1) ? -1 : 0;
    }
}

char wsa_strerror_buf[128];
/* */
char *wsa_strerror(int err) {
    int size = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        err,
        0,
        wsa_strerror_buf,
        sizeof(wsa_strerror_buf),
        NULL);
    if (size == 0) {
        return strerror(err);
    }
    if (size > 2 && wsa_strerror_buf[size - 2] == '\r') {
        /* remove extra CRLF */
        wsa_strerror_buf[size - 2] = '\0';
    }
    return wsa_strerror_buf;
}

#ifdef __cplusplus
}
#endif

