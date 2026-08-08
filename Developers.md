# DEVELOPERS

This repository contains both C# and C++ code. The C++ code is the (modified)
reference implementation of the Argon2 password hashing algorithm, while the
C# code provides a complete reimplementation of Argon2 with no dependency on
the reference implementation.

The reference implementation is used by the test code. At build time, the
`Argon2TestVectorSourceGenerator` project calls the reference implementation
hundereds of times to generate test vectors to compare the C# implementation
against.

## VISUAL STUDIO

This project loads into visual studio as a CMake project. You open the
directory.

As part of the build, the CMake script actually creates a solution file to
allow`dotnet` to work. You can open this solution file but you will not get
access to the C++ source. Things seem to work well enough without opening the
solution file.

## [Assemblies](#building-the-argon2-assemblies) | [Unit Tests](#building-and-running-unit-tests) | [Test Apps](#building-other-test-applications)

Everything can be built from the command line.

### BUILDING THE ARGON2 ASSEMBLIES

```sh
cmake --preset debug
cmake --build --preset debug-build
```

or for release:
```sh
cmake --preset release
cmake --build --preset release-build
```

or for signing:
```sh
cmake --preset sign-release
cmake --build --preset sign-release-build
```

### BUILDING AND RUNNING UNIT TESTS

```sh
cmake --preset debug
cmake --build --preset debug-test
```
or for release:
```sh
cmake --preset release
cmake --build --preset release-test
```

### BUILDING OTHER TEST APPLICATIONS

```sh
cmake --preset debug
cmake --build --preset debug-test-apps
```
or for release:
```sh
cmake --preset release
cmake --build --preset release-test-apps
```

This builds (on windows):
* test\TestUno\TestUno.Wasm\bin\Debug\net9.0\TestUno.Wasm.exe
* test\TestUno\TestUno.Wasm\bin\Debug\net9.0\TestUno.UWP.exe (if we can get the workload working)
* test\TestBlazor\Server\bin\Debug\net9.0\TestBlazor.Server.exe,
* test\TestBlazor\Server\bin\Debug\net9.0\TestBlazor.Server.exe,
* test\TestBlazor\Wasm\bin\Debug\net9.0\TestBlazor.Wasm.exe
* test\TestApp\bin\Debug\net9.0\TestApp.exe
* test\TestApp\bin\Debug\net9.0\TestUwpApp.exe (if we can get the workload working)

`TestApp.exe` can be run with just the path. It essentially runs through the unit tests as a console app.

I think all the others must be run from their respective folders.
