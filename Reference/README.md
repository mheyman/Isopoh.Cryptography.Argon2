# Argon2

Builds the reference argon2 command line utility modified to include optional secret and additional data.

This is the reference code from https://github.com/P-H-C/phc-winner-argon2 release 6 (2 July 2019).

## Usage

`make` builds the executable `argon2`, the static library `libargon2.a`,
and the shared library `libargon2.so` (or on macOS, the dynamic library
`libargon2.dylib` -- make sure to specify the installation prefix when
you compile: `make PREFIX=/usr`). Make sure to run `make test` to verify
that your build produces valid results. `sudo make install PREFIX=/usr`
installs it to your system.

### Command-line utility

`argon2` is a command-line utility to test specific Argon2 instances
on your system. To show usage instructions, run
`./argon2 -h` as
```
Usage:  ./argon2 [-h] salt [-i|-d|-id] [-t iterations] [-m memory] [-p parallelism] [-l hash length] [-e|-r] [-v (10|13)]
Parameters:
        salt            The salt to use, at least 8 characters
        -i              Use Argon2i (this is the default)
        -d              Use Argon2d instead of Argon2i
        -id             Use Argon2id instead of Argon2i
        -x password     Password
        -t N            Sets the number of iterations to N (default = 3)
        -s secret       Optional secret
        -a ad           Optional additional data
        -m N            Sets the memory usage of 2^N KiB (default 12)
        -k N            Sets the memory usage of N KiB (default 4)
        -p N            Sets parallelism to N threads (default 1)
        -l N            Sets hash output length to N bytes (default 32)
        -s secret       Secret
        -a ad           Additional data
        -e              Output only encoded hash
        -r              Output only the raw bytes of the hash
        -v (10|13)      Argon2 version (defaults to the most recent version, currently 13)
        -h              Print argon2 usage
```
For example, to hash "password" using "somesalt" as a salt and doing 2
iterations, consuming 64 MiB, using four parallel threads and an output hash
of 24 bytes
```
$ echo -n "password" | ./argon2 somesalt -t 2 -m 16 -p 4 -l 24
Type:           Argon2i
Iterations:     2
Memory:         65536 KiB
Parallelism:    4
Hash:           45d7ac72e76f242b20b77b9bf9bf9d5915894e669a24e6c6
Encoded:        $argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
0.188 seconds
Verification ok
```