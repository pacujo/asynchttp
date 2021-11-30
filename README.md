## Overview

asynchttp is a C library for Linux-like operating systems that offers
an HTTP protocol abstraction compatible with the [async][] library.

## Building

asynchttp uses [SCons][] and `pkg-config` for building.

Before building asynchttp for the first time, run
```
git submodule update --init
```

To build asynchttp, run
```
scons [ prefix=<prefix> ]
```
from the top-level asynchttp directory. The optional prefix argument is a
directory, `/usr/local` by default, where the build system installs
asynchttp.

To install asynchttp, run
```
sudo scons [ prefix=<prefix> ] install
```

## Documentation

The header files under `include` contain detailed documentation.

[SCons]: https://scons.org/
[async]: https://github.com/F-Secure/async
