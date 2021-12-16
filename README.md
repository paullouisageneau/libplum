# libplum - Multi-protocol Port Mapping client library

[![Build](https://github.com/paullouisageneau/libplum/actions/workflows/build.yml/badge.svg)](https://github.com/paullouisageneau/libplum/actions/workflows/build.yml)

libplum (_Port Lightweight and Universal Mapping_) is a library allowing to forward ports on Network Address Translators (NAT). It is written in C without dependencies and supports POSIX platforms (including GNU/Linux, Android, Apple macOS and iOS) and Microsoft Windows.

Under the hood, it implements multiple protocols and automatically detects which one to use:

- Port Control Protocol (PCP, [RFC6887](https://datatracker.ietf.org/doc/html/rfc6887))
- NAT Port Mapping Protocol (NAT-PMP, [RFC6886](https://datatracker.ietf.org/doc/html/rfc6886))
- UPnP Internet Gateway Device Protocol ([UPnP-IGD](https://en.wikipedia.org/wiki/Internet_Gateway_Device_Protocol))

libplum is licensed under LGPLv2, see [LICENSE](https://github.com/paullouisageneau/libplum/blob/master/LICENSE).

![Plum in Rayman (Ubisoft, 1995)](https://github.com/paullouisageneau/libplum/blob/master/plum.gif?raw=true)

## Dependencies

None!

## Example

```c
#include "plum/plum.h"
```

### Initialize the library
```c
plum_set_log_level(PLUM_LOG_LEVEL_WARN);
plum_init();
```

### Create a mapping
```c
void mapping_callback(int id, plum_state_t state, const plum_mapping_t *mapping) {
    // Called from another thread
    if (state == PLUM_STATE_SUCCESS)
        printf("External address: %s:%hu\n", mapping->external_host, mapping->external_port);
}
```

```c
plum_mapping_t mapping;
memset(&mapping, 0, sizeof(mapping));
mapping.protocol = PLUM_IP_PROTOCOL_TCP;
mapping.internal_port = 8000;

int id = plum_create_mapping(&mapping, mapping_callback);
```

### Destroy a mapping
```c
plum_destroy_mapping(id);
```

See [example/main.c](https://github.com/paullouisageneau/libplum/blob/master/example/main.c) for a usage example.

## Building

### Clone repository

```bash
$ git clone https://github.com/paullouisageneau/libplum.git
$ cd libplum
```

### Build with CMake

The CMake library targets `libplum` and `libplum-static` respectively correspond to the shared and static libraries. The default target will build the library and example.

#### POSIX-compliant operating systems (including Linux and Apple macOS)

```bash
$ cmake -B build
$ cd build
$ make -j2
```

#### Microsoft Windows with MinGW cross-compilation

```bash
$ cmake -B build -DCMAKE_TOOLCHAIN_FILE=/usr/share/mingw/toolchain-x86_64-w64-mingw32.cmake # replace with your toolchain file
$ cd build
$ make -j2
```

#### Microsoft Windows with Microsoft Visual C++

```bash
$ cmake -B build -G "NMake Makefiles"
$ cd build
$ nmake
```

### Build directly with Make (Linux only)

```bash
$ make
```

