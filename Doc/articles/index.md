# Argon2 in WebAssembly

It appears, as of fall 2020, there are two viable ways to run the Argon2 hash
code in this library from within a web page. Both the [Blazor](https://dotnet.microsoft.com/apps/aspnet/web-apps/blazor)
and [UnoPlatform](https://platform.uno/) allow for compiling .Net code to run
in a web page.

Both solutions can have the Mono interpreter running in the web page to run a
byte-compiled application. Additionally, Uno has the ability to do
ahead-of-time (AOT) compilation (AOT creates some limitations with what the
.Net can perform but those limitations don't impact Argon2).

The following table shows some of the relative performance I've seen as I've
played with `Argon2.Hash()` on various web page platforms (Chrome and Edge)
and the same computer on the host (`Argon2.Verify()` will perform similarly).
This technology is a moving target and with every release, these numbers can
change.

| Technology          | Performance   |
|---------------------|---------------|
| Wasm Blazor Debug   | 1.5-3 minutes |
| Wasm Blazor Publish | 20-40 seconds |
| Wasm Uno Debug      | 3-4 minutes   |
| Wasm Uno Release    | 1-2 minutes   |
| Wasm Uno Full AOT   | 4-6 seconds   |
| On Host             | .9 seconds    |

Blazor is, by far, the easiest. The Uno Platform is really impressive. It is
fun watching it bounce into WSL Linux to compile while within Visual Studio.
The **Uno Full AOT** compilation takes a _really_ long time (they need to
implement [ccache](https://ccache.dev/) because it seems much of the slowness
can be cached and only processed once.

This Argon2 library can do threading to speed processing. The current state
of .Net code running threaded in the browser is poor. _Blazor_ doesn't support
it at all and I was not able to get the _Uno Platform__ build to use threading.

## Blazor and Uno Platform Specific Notes

* [Argon2 with Blazor WebAssembly](blazor.html)
* [Argon2 with UnoPlatform WebAssembly](unoplatform.html)