# Argon2 in WebAssembly

It appears, as of fall 2021, there are two viable ways to run the Argon2 hash
code in this library from within a web page. Both the [Blazor](https://dotnet.microsoft.com/apps/aspnet/web-apps/blazor)
and [UnoPlatform](https://platform.uno/) allow for compiling .Net code to run
in a web page.

Both methods perform similarly when published (3-5x slowdown over )

## Blazor and Uno Platform Specific Notes

* [Argon2 with Blazor WebAssembly](blazor.html)
* [Argon2 with UnoPlatform WebAssembly](unoplatform.html)