![Isopoh](https://raw.githubusercontent.com/mheyman/Isopoh.Cryptography.Argon2/master/.github/images/isopoh144.png)

### BLAKE2B
[blake2]: #blake2 'Blake2b Pedigree'

Argon2 uses Blake2b as a cryptographic building block. This code uses the
C# implementation of Blake2 modified from https://github.com/BLAKE2.
The main modification is that the Blake2 here uses [SecureArray&lt;T>](https://mheyman.github.io/Isopoh.Cryptography.Argon2/api/Isopoh.Cryptography.SecureArray.SecureArray-1.html). The `SecureArray` takes a [SecureArrayCall](https://mheyman.github.io/Isopoh.Cryptography.Argon2/api/Isopoh.Cryptography.SecureArray.SecureArrayCall.html)
to protect potentially sensitive data. Most other modifications are
strictly cosmetic.

As part of this Blake2b port, an effort was made to speed Blake2b by using
techniques like unrolling and using raw buffers in unsafe code. It turns out
the CLR optimizes plain code better than unrolled/unsafe code and the original
always ran faster. At some point I may try a port to [System.Numerics.Vector&lt;T>](https://docs.microsoft.com/en-us/dotnet/api/system.numerics.vector-1)...

### API GENERATION
[apigen]: #apigen 'API Generation'

The API Documentation at [https://mheyman.github.io/Isopoh.Cryptography.Argon2](https://mheyman.github.io/Isopoh.Cryptography.Argon2)
gets generated automatically upon build. This happens via a dummy C# "Doc"
project that uses the [*DocFx*](https://github.com/dotnet/docfx) NuGet
package to produce the API documentation.

## AUTHOR
[auth]: #author 'Credits & author\'s contacts info'
[Michael Heyman](https://github.com/mheyman)

## ACKNOWLEDGMENTS
[acc]: acknowledgments

List of people and project that inspired creation of this one:

- The many contributers of the [Argon2 repository](https://github.com/p-h-c/phc-winner-argon2)
- and the cryptographers responsible for creating and testing that algorithm
- @CodesInChaos for the fully managed Blake2b implementation [here](https://github.com/BLAKE2/BLAKE2)
- @PurpleBooth for his readme template posted [here](https://gist.github.com/PurpleBooth/109311bb0361f32d87a2)

## LICENSE
[cpl]:#license 'License info'

<a rel="license" href="http://creativecommons.org/licenses/by/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://i.creativecommons.org/l/by/4.0/88x31.png" /></a><br /><span xmlns:dct="http://purl.org/dc/terms/" property="dct:title">Isopoh.Cryptography.Argon2</span> by <a xmlns:cc="http://creativecommons.org/ns#" href="https://github.com/mheyman/Isopoh.Cryptography.Argon2" property="cc:attributionName" rel="cc:attributionURL">Michael Heyman</a> is licensed under a <a rel="license" href="http://creativecommons.org/licenses/by/4.0/">Creative Commons Attribution 4.0 International License</a>.
## PRODUCTION STATUS & SUPPORT
[ps]: #production-status--support 'Production use disclaimer & support info'

You should be aware that this project is supported solely by me and provided as is.

Go back to the **[top][blake2]**

