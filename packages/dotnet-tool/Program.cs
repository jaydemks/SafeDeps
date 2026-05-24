using System.Diagnostics;

var argsList = new List<string> { "-m", "safedeps.cli" };
argsList.AddRange(args);

var psi = new ProcessStartInfo
{
    FileName = "python",
    RedirectStandardOutput = false,
    RedirectStandardError = false,
    UseShellExecute = false,
};

foreach (var a in argsList)
{
    psi.ArgumentList.Add(a);
}

try
{
    using var process = Process.Start(psi);
    if (process is null)
    {
        Console.Error.WriteLine("Unable to start python process for safedeps.");
        return 2;
    }

    process.WaitForExit();
    return process.ExitCode;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"SafeDeps .NET wrapper failed to execute: {ex.Message}");
    Console.Error.WriteLine("Ensure Python is available and safedeps is installed in the active environment.");
    return 2;
}
