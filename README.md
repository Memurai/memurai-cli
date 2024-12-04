# Memurai-cli

**Memurai-cli** is a Windows-compatible, command-line interface tool based on the Valkey `valkey-cli` utility. It is designed for use with Valkey, Redis and [Memurai](https://www.memurai.com) - a Redis and Valkey compatible in-memory datastore for Windows environments. This project is derived from the [Valkey](https://github.com/valkey-io/valkey) repository, but focuses solely on providing a standalone cross-platform CLI client. All server-side functionality has been removed, streamlining the tool into a Windows-friendly Valkey CLI.

# Building Memurai-cli

Memurai-cli can be compiled and used on Windows and Linux.

## Windows

To build the project, use the `memurai-cli.sln` solution file located in the `msvs` directory.

For TLS support, install the OpenSSL development libraries. You can use [vcpkg](https://vcpkg.io) with the following command:

```shell
vcpkg install openssl
```

You can also use pre-built binaries, for example from Janea Systems' [openssl-binaries](https://github.com/JaneaSystems/openssl-binaries/releases) repository.

## Linux

It is as simple as:

    % make

To build with TLS support, you'll need OpenSSL development libraries (e.g.
libssl-dev on Debian/Ubuntu) and run:

    % make BUILD_TLS=yes

### Fixing build problems with dependencies or cached build options

Memurai-cli has some dependencies which are included in the `deps` directory.
`make` does not automatically rebuild dependencies even if something in
the source code of dependencies changes.

When you update the source code with `git pull` or when code inside the
dependencies tree is modified in any other way, make sure to use the following
command in order to really clean everything and rebuild from scratch:

    % make distclean

This will clean: jemalloc, lua, hiredis, linenoise and other dependencies.

### Allocator

Selecting a non-default memory allocator when building Memurai-cli is done by setting
the `MALLOC` environment variable. Memurai-cli is compiled and linked against libc
malloc by default, with the exception of jemalloc being the default on Linux
systems. This default was picked because jemalloc has proven to have fewer
fragmentation problems than libc malloc.

To force compiling against libc malloc, use:

    % make MALLOC=libc

To compile against jemalloc on Mac OS X systems, use:

    % make MALLOC=jemalloc
