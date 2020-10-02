# Argon2 With UnoPlatform WebAssembly

You can use this library to calculate Argon2 hashes in the web browser.
With the 3.1 dotnet SDK, the Blazor WebAssembly runs slower than
on the host - taking on the order of 4-6 seconds for a default
hash on common hardware (this is the speed after publishing with full
ahead-of-time (AOT) compilation, it can take 1.5-3 minutes when
interpreting). This should improve as both dotnet improves and
WebAssembly improves.

Note, unlike the current Blazor, the Uno Plaform says it supports
.Net threads (see [Threads Support](https://github.com/unoplatform/Uno.Wasm.Bootstrap#threads-support).
Please tell me how if you get it to work - I have failed with the
page hanging using 1.3.4 and failed to even load the page properly
when using 1.4.0-dev.52.

## Example

This example tries to be a little friendly in that it tells you when it is
calculating the hash and disables the controls when it is doing so.

It builds a component that looks like this:

> ![HashComponent](../images/UnoAotWasmPage.PNG)

## XAML

The WPF XAML for that page looks like:

[!code-xml[MainPage.xaml](../../TestUno/Shared/MainPage.xaml)]

## XAML Code

The code to do the processing for that XAML takes care to do as much
proccessing in async calls to give the UI a chance to be reactive. Highlighted
is the actual call to `Argon2.Hash()`:

[!code-csharp[MainPage.xaml.cs](../../TestUno/Shared/MainPage.xaml.cs?highlight=107-114)]

## Example Source

The source for this example can be found at:

(github)[TestUno](https://github.com/mheyman/Isopoh.Cryptography.Argon2/blob/master/TestUno)