using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Nucleus.Integrations.Unity.Transports.Tests;

/// <summary>
/// Points the transport's MsQuic binding at the msquic.dll this package ships, so the live tests exercise the library a game gets.
/// </summary>
/// <remarks>
/// Without it the binding resolves the name to the msquic.dll beside the .NET shared framework, which is whatever version that runtime
/// bundled. The hostile peers built on System.Net.Quic keep loading the runtime's own copy, which is a separate module.
/// </remarks>
internal static class ShippedMsQuic
{
    /// <summary>
    /// The library name the binding imports.
    /// </summary>
    private const string LibraryName = "msquic";

    /// <summary>
    /// Registers the resolver before any test touches the binding.
    /// </summary>
    [ModuleInitializer]
    internal static void Register() => NativeLibrary.SetDllImportResolver(typeof(Quic).Assembly, Resolve);

    /// <summary>
    /// Loads the shipped msquic.dll, copied beside the tests, for the binding's imports on Windows.
    /// </summary>
    /// <param name="libraryName">The imported library's name.</param>
    /// <param name="assembly">The assembly making the import.</param>
    /// <param name="searchPath">The import's search path, unused.</param>
    /// <returns>The loaded library, or zero to fall back to the default resolution.</returns>
    private static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != LibraryName || !OperatingSystem.IsWindows())
            return IntPtr.Zero;

        return NativeLibrary.Load(Path.Combine(AppContext.BaseDirectory, "msquic.dll"));
    }
}
