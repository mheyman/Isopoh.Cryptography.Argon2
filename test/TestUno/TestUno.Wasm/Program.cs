namespace TestUno.Wasm;

public class Program
{
    // ReSharper disable once NotAccessedField.Local
    private static App app;

    private static int Main()
    {
        Windows.UI.Xaml.Application.Start(_ => app = new App());

        return 0;
    }
}