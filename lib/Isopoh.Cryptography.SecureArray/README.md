![Isopoh](https://raw.githubusercontent.com/mheyman/Isopoh.Cryptography.Argon2/master/.github/images/isopoh144.png)

### SecureArray
[seca]: #securearry 'SecureArray description'

You can think of the `SecureArray` sort of like you would think of
[`SecureString`](https://docs.microsoft.com/en-us/dotnet/api/system.security.securestring)
except that `SecureString` does crypto (usually -
[encryption isn't supported everywhere](https://github.com/dotnet/platform-compat/blob/master/docs/DE0001.md))
to protect its sensitive data and has windows of vulnerability when it
decrypts the string for use. `SecureArray` protects its data by locking the
data into RAM to keep it from swapping to disk and also zeroing the buffer when
disposed. So, unlike `SecureString`, any process with access to your process's
memory will be able to read the data in your `SecureArray`, but you do not
have to worry about your data persisting anywhere or multiple copies of your
data floating around RAM due to C#'s memory management.

Because it locks the memory into RAM (and at a
non-movable-by-the-garbage-collector location), you need to use it
as infrequently as possible and for as short a time as possible. RAM secured
this way puts stress on the computer as a whole by denying physical
RAM for other processes and puts stress on your particular executable by
denying freedom to the garbage collector to reduce fragmentation as needed
for best performance.

Note: when using SecureArray in the browser (for example, under Blazor or UnoPlatform),
the memory cannot be locked into RAM so SecureArray does its best effort to protect the
data by zeroing the buffer when it is disposed.

Note similarly: when using SecureArray in a Universal Windows Platform (UWP)
application, I have yet to figure out how to use the supposedly available
`VirtualAllocFromApp()` system call to lock memory into RAM so SecureArray does
its best effort to protect the data by zeroing the buffer when it is disposed.

***Always*** dispose of your `SecureArray`s.

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

Go back to the **[top][seca]**

