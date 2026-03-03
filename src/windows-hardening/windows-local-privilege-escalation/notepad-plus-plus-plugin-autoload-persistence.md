# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ автоматично завантажує кожну DLL плагіна, яка знаходиться у підпапках `plugins`, під час запуску. Поміщення шкідливого плагіна в будь-яке **встановлення Notepad++, доступне для запису**, дає виконання коду всередині `notepad++.exe` щоразу при старті редактора — це можна використати для **персистентності**, прихованого **початкового виконання** або як **завантажувач в процесі**, якщо редактор запущено з підвищеними правами.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (зазвичай потрібно права адміністратора для запису).
- Writable options for low-privileged operators:
- Use the **portable Notepad++ build** in a user-writable folder.
- Copy `C:\Program Files\Notepad++` to a user-controlled path (e.g., `%LOCALAPPDATA%\npp\`) and run `notepad++.exe` from there.
- Each plugin gets its own subfolder under `plugins` and is loaded automatically at startup; menu entries appear under **Plugins**.

## Plugin load points (execution primitives)
Notepad++ очікує конкретні **експортовані функції**. Вони всі викликаються під час ініціалізації, що дає кілька поверхонь для виконання:
- **`DllMain`** — виконується одразу при завантаженні DLL (перша точка виконання).
- **`setInfo(NppData)`** — викликається один раз під час завантаження, щоб надати дескриптори Notepad++; типовe місце для реєстрації пунктів меню.
- **`getName()`** — повертає ім'я плагіна, що показується в меню.
- **`getFuncsArray(int *nbF)`** — повертає команди меню; навіть якщо масив порожній, ця функція викликається під час старту.
- **`beNotified(SCNotification*)`** — отримує події редактора (відкриття/зміна файлу, події інтерфейсу) для подальших тригерів.
- **`messageProc(UINT, WPARAM, LPARAM)`** — обробник повідомлень, корисний для обміну більшими даними.
- **`isUnicode()`** — прапорець сумісності, що перевіряється під час завантаження.

Більшість експортів можна реалізувати як **заглушки**; виконання може відбуватися з `DllMain` або будь-якого з наведених колбеків під час автозавантаження.

## Minimal malicious plugin skeleton
Скомпілюйте DLL з очікуваними експортами і помістіть її в `plugins\\MyNewPlugin\\MyNewPlugin.dll` у записуваній папці Notepad++:
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. Зібрати DLL (Visual Studio/MinGW).
2. Створити підпапку плагіна під `plugins` та помістити DLL всередину.
3. Перезапустіть Notepad++; DLL завантажується автоматично, виконуючи `DllMain` та подальші зворотні виклики.

## Reflective loader plugin pattern
A weaponized plugin can turn Notepad++ into a **reflective DLL loader**:
- Present a minimal UI/menu entry (e.g., "LoadDLL").
- Accept a **file path** or **URL** to fetch a payload DLL.
- Reflectively map the DLL into the current process and invoke an exported entry point (e.g., a loader function inside the fetched DLL).
- Benefit: reuse a benign-looking GUI process instead of spawning a new loader; payload inherits the integrity of `notepad++.exe` (including elevated contexts).
- Trade-offs: dropping an **unsigned plugin DLL** to disk is noisy; consider piggybacking on existing trusted plugins if present.

## Зауваження щодо виявлення та захисту
- Block or monitor **writes to Notepad++ plugin directories** (including portable copies in user profiles); enable controlled folder access or application allowlisting.
- Alert on **new unsigned DLLs** under `plugins` and unusual **child processes/network activity** from `notepad++.exe`.
- Enforce plugin installation via **Plugins Admin** only, and restrict execution of portable copies from untrusted paths.

## References
- [Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [MyNewPlugin PoC snippet](https://gitlab.com/-/snippets/4930986)
- [LoadDLL reflective loader plugin](https://gitlab.com/KevinJClark/ops-scripts/-/tree/main/notepad_plus_plus_plugin_LoadDLL)

{{#include ../../banners/hacktricks-training.md}}
