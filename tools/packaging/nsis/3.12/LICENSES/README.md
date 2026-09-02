# NSIS 3.12 license inventory

This directory contains only notices applicable to the promoted project-local kit.

- `../COPYING`: upstream NSIS aggregate notice. It covers the NSIS core,
  `nsDialogs`, `System`, compression modules, and the special LZMA linking
  exception. The kit does not include bzip2 even though the unmodified upstream
  aggregate notice documents it.
- `zlib-LICENSE.txt`: upstream zlib 1.3.2 license for the locally built zlib.
- `LZMA-CPL-1.0-with-NSIS-exception.txt`: CPL 1.0 text and the upstream NSIS
  special exception applicable to the included LZMA module.

SCons is not redistributed in this kit. Its MIT license remains recorded as
build-tool provenance only.
