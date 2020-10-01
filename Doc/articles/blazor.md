# Argon2 with Blazor WebAssembly

You can use this library to calculate Argon2 hashes in the web browser.
With the 3.1 dotnet SDK, the Blazor WebAssembly runs _a lot slower_ than
on the host - taking on the order of 20-40 seconds for a default
hash on common hardware (this is the speed after publishing, it can take
1-2 minutes when debugging). This should improve as both dotnet improves
and WebAssembly improves.

Even with the poor hashing performance in the browser, there may be use cases
that require the server to never see the secret so performing a hash with
reduced protection on the browser will be more secure than the alternative.

With Blazor, you typically assemble your pages with components. The following
is a simple example demonstrating Argon2 in the browser.

## Example

While you can call on Argon2 hashing and verifying directly from the razor
code, this example tries to be a little more friendly in that it tells you
when it is calculating the hash and disables the controls when it is doing
so.

It builds a component that looks like this:

![HashComponent](./HashComonent.PNG)


Create a component, **`HashComponent.razor`**:
```html
<div>
    @if (argoner.Calculating)
    {
        <div>&nbsp;</div>
        <div>Calculating &quot;@argoner.Secret&quot;</div>
        <div>&nbsp;</div>
    }
    else
    {
        <div>Argon2 hash of &quot;@argoner.Secret&quot;</div>
        <div>&quot;@argoner.Hash&quot;</div>
        <div>(@argoner.CalculationSeconds seconds)</div>
    }
</div>
<div>&nbsp;</div>
<EditForm Model=@argoner>
    <div>
        <div>
            <input value="@argoner.Secret" disabled="@argoner.Calculating" @onchange="@((ChangeEventArgs a) => argoner.SetSecret(a.Value.ToString(), this.StateHasChanged))" />
            <label>The &quot;secret&quot; to hash.</label>
        </div>
        <div>Hashing occurs when leaving the secret input field, or when Enter is pressed and may take 2 minutes for a default hash.</div>
        <div>&nbsp;</div>
    </div>
    <div>
        <InputNumber @bind-Value=@argoner.TimeCost disabled=@argoner.Calculating />
        <label>Time cost. Defaults to 3.</label>
    </div>
    <div>
        <InputNumber @bind-Value=@argoner.MemoryCost disabled=@argoner.Calculating />
        <label>Memory cost. Defaults to 65536 (65536 * 1024 = 64MB).</label>
    </div>
    <div>
        <InputNumber @bind-Value=@argoner.Parallelism disabled=@argoner.Calculating />
        <label>Parallelism. Defaults to 1. Blazor bug on WaitHandle.WaitAny() prevents this from working on any other value than 1.</label>
    </div>
    <div>
        <InputSelect @bind-Value=@argoner.Type disabled=@argoner.Calculating>
            <option value="DataDependentAddressing">dependent</option>
            <option value="DataIndependentAddressing">independent</option>
            <option value="HybridAddressing">hybrid</option>
        </InputSelect>
        <label>
            &quot;dependent&quot; (faster but susceptible to side-channel
            attacks), &quot;independent&quot; (slower and suitable for password
            hashing and password-based key derivation), or &quot;hybrid&quot; (a
            mixture of the two). Defaults to the recommended type:
            &quot;hybrid&quot;.
        </label>
    </div>
    <div>
        <InputNumber @bind-Value=@argoner.HashLength disabled=@argoner.Calculating />
        <label>
            Hash length. The hash string base-64 encodes the hash of this
            length along with other parameters so the length of the resulting
            hash string is significantly longer.
        </label>
    </div>
</EditForm>


@code {
    private readonly Argoner argoner = new Argoner();
}
```
