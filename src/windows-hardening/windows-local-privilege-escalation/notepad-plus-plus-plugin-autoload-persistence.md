# Notepad++ 插件自动加载持久化与执行

{{#include ../../banners/hacktricks-training.md}}

Notepad++ 在启动时会 **autoload every plugin DLL found under its `plugins` subfolders**。将恶意插件放入任何 **writable Notepad++ installation** 中，每次编辑器启动都会在 `notepad++.exe` 内获得代码执行权，这可以被用于 **persistence**、隐蔽的 **initial execution**，或在编辑器以高权限启动时作为一个 **in-process loader**。

## 可写插件位置
- 标准安装：`C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll`（通常需要 admin 权限写入）。
- 适合低权限操作者的可写选项：
- 将 **portable Notepad++ build** 放在用户可写的目录中。
- 将 `C:\Program Files\Notepad++` 复制到用户可控路径（例如 `%LOCALAPPDATA%\npp\`），并从那里运行 `notepad++.exe`。
- 每个插件在 `plugins` 下都有自己的子文件夹，启动时会自动加载；菜单项出现在 **Plugins** 下。

## 插件加载点（执行原语）
Notepad++ 期望特定的 **exported functions**。这些函数都会在初始化期间被调用，提供多个执行面：
- **`DllMain`** — 在 DLL 加载时立即运行（第一个执行点）。
- **`setInfo(NppData)`** — 在加载时被调用一次以提供 Notepad++ 的句柄；通常在这里注册菜单项。
- **`getName()`** — 返回在菜单中显示的插件名称。
- **`getFuncsArray(int *nbF)`** — 返回菜单命令；即使为空，也会在启动时被调用。
- **`beNotified(SCNotification*)`** — 接收编辑器事件（文件打开/更改、UI 事件），用于持续触发。
- **`messageProc(UINT, WPARAM, LPARAM)`** — 消息处理器，有助于更大数据交换。
- **`isUnicode()`** — 在加载时检查的兼容性标志。

大多数导出可以实现为 **stubs**；执行可以发生在 `DllMain` 或上述任何回调中，在自动加载期间触发。

## 最小恶意插件骨架
编译一个包含期望导出函数的 DLL，并将其放置在可写的 Notepad++ 文件夹下的 `plugins\\MyNewPlugin\\MyNewPlugin.dll`：
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. 使用 Visual Studio/MinGW 编译 DLL。
2. 在 `plugins` 下创建插件子文件夹，并把 DLL 放入其中。
3. 重启 Notepad++；DLL 会被自动加载，执行 `DllMain` 及后续回调。

## Reflective loader plugin pattern
一个被武器化的插件可以将 Notepad++ 变成一个 **reflective DLL loader**：
- 提供一个最小化的 UI/菜单项（例如，“LoadDLL”）。
- 接受一个 **file path** 或 **URL** 来获取 payload DLL。
- Reflectively map the DLL into the current process 并调用导出的入口点（例如，获取的 DLL 内的 loader 函数）。
- 好处：重用看起来无害的 GUI 进程，而不是产生新的 loader；payload 继承 `notepad++.exe` 的完整性（包括提权上下文）。
- 权衡：将 **unsigned plugin DLL** 写到磁盘会很吵闹；如果有现存的受信任插件，考虑搭便车。

## 检测与加固说明
- 阻止或监控对 **Notepad++ plugin directories** 的写入（包括用户配置文件中的便携版副本）；启用受控文件夹访问或应用程序白名单。
- 对 `plugins` 下出现的 **new unsigned DLLs** 和来自 `notepad++.exe` 的异常 **child processes/network activity** 触发告警。
- 强制仅通过 **Plugins Admin** 安装插件，并限制从不受信任路径执行便携版副本。

## References
- [Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [MyNewPlugin PoC snippet](https://gitlab.com/-/snippets/4930986)
- [LoadDLL reflective loader plugin](https://gitlab.com/KevinJClark/ops-scripts/-/tree/main/notepad_plus_plus_plugin_LoadDLL)

{{#include ../../banners/hacktricks-training.md}}
