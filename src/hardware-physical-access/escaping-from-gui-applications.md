# Втеча з KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Перевірка фізичного пристрою

| Компонент    | Дія                                                                 |
| ------------ | ------------------------------------------------------------------ |
| Power button | Turning the device off and on again may expose the start screen    |
| Power cable  | Check whether the device reboots when the power is cut off briefly |
| USB ports    | Connect physical keyboard with more shortcuts                      |
| Ethernet     | Network scan or sniffing may enable further exploitation           |

## Перевірте можливі дії всередині GUI application

**Common Dialogs** — це опції для збереження файлу, відкриття файлу, вибору шрифту, кольору тощо. Більшість із них надають повноцінну функціональність Explorer. Це означає, що ви зможете отримати доступ до функцій Explorer, якщо матимете доступ до цих опцій:

- Close/Close as
- Open/Open with
- Print
- Export/Import
- Search
- Scan

Перевірте, чи можете ви:

- Modify or create new files
- Create symbolic links
- Get access to restricted areas
- Execute other apps

### Command Execution

Можливо, використовуючи опцію `Open with`, ви зможете відкрити/запустити якийсь shell.

#### Windows

Наприклад _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ — знайдіть більше бінарників, які можна використати для виконання команд (та для непередбачуваних дій), тут: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Більше тут: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Bypassing path restrictions

- **Environment variables**: There are a lot of environment variables that are pointing to some path
- **Other protocols**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Shortcuts**: CTRL+N (open new session), CTRL+R (Execute Commands), CTRL+SHIFT+ESC (Task Manager), Windows+E (open explorer), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Hidden Administrative menu: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Paths to connect to shared folders. You should try to connect to the C$ of the local machine ("\\\127.0.0.1\c$\Windows\System32")
- **More UNC paths:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%               | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

### Restricted Desktop Breakouts (Citrix/RDS/VDI)

- **Dialog-box pivoting**: Use *Open/Save/Print-to-file* dialogs as Explorer-lite. Try `*.*` / `*.exe` in the filename field, right-click folders for **Open in new window**, and use **Properties → Open file location** to expand navigation.
- **Create execution paths from dialogs**: Create a new file and rename it to `.CMD` or `.BAT`, or create a shortcut pointing to `%WINDIR%\System32` (or a specific binary like `%WINDIR%\System32\cmd.exe`).
- **Shell launch pivots**: If you can browse to `cmd.exe`, try **drag-and-drop** any file onto it to launch a prompt. If Task Manager is reachable (`CTRL+SHIFT+ESC`), use **Run new task**.
- **Task Scheduler bypass**: If interactive shells are blocked but scheduling is allowed, create a task to run `cmd.exe` (GUI `taskschd.msc` or `schtasks.exe`).
- **Weak allowlists**: If execution is allowed by **filename/extension**, rename your payload to a permitted name. If allowed by **directory**, copy the payload into an allowed program folder and run it there.
- **Find writable staging paths**: Start with `%TEMP%` and enumerate writeable folders with Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Наступний крок**: Якщо ви отримаєте shell, перейдіть до Windows LPE checklist:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Завантаження бінарних файлів

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Доступ до файлової системи з браузера

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### Клавішні скорочення

- Sticky Keys – натисніть SHIFT 5 разів
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – Утримуйте NUMLOCK протягом 5 секунд
- Filter Keys – Утримуйте правий SHIFT протягом 12 секунд
- WINDOWS+F1 – Windows Search
- WINDOWS+D – Показати робочий стіл
- WINDOWS+E – Відкрити Windows Explorer
- WINDOWS+R – Run
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Пошук
- SHIFT+F10 – Контекстне меню
- CTRL+SHIFT+ESC – Диспетчер завдань
- CTRL+ALT+DEL – Екран блокування на новіших версіях Windows
- F1 – Допомога F3 – Пошук
- F6 – Адресний рядок
- F11 – Увімкнути/вимкнути повноекранний режим в Internet Explorer
- CTRL+H – Історія Internet Explorer
- CTRL+T – Internet Explorer – Нова вкладка
- CTRL+N – Internet Explorer – Нова сторінка
- CTRL+O – Відкрити файл
- CTRL+S – Зберегти CTRL+N – Новий RDP / Citrix

### Жести (Swipes)

- Проведіть від лівого краю вправо, щоб побачити всі відкриті вікна, мінімізувати KIOSK app і отримати доступ до всієї ОС;
- Проведіть від правого краю вліво, щоб відкрити Action Center, мінімізувати KIOSK app і отримати доступ до всієї ОС;
- Проведіть вниз від верхнього краю, щоб зробити видимою рядок заголовка для додатка, відкритого в повноекранному режимі;
- Проведіть вгору від нижнього краю, щоб показати панель завдань у повноекранному додатку.

### Internet Explorer Трюки

#### 'Image Toolbar'

Це панель інструментів, яка з'являється у верхньому лівому куті зображення при його натисканні. Ви зможете Save, Print, Mailto, Open "My Pictures" в Explorer. Kiosk повинен використовувати Internet Explorer.

#### Shell Protocol

Введіть ці URL, щоб отримати вигляд Explorer:

- `shell:Administrative Tools`
- `shell:DocumentsLibrary`
- `shell:Libraries`
- `shell:UserProfiles`
- `shell:Personal`
- `shell:SearchHomeFolder`
- `shell:NetworkPlacesFolder`
- `shell:SendTo`
- `shell:UserProfiles`
- `shell:Common Administrative Tools`
- `shell:MyComputerFolder`
- `shell:InternetFolder`
- `Shell:Profile`
- `Shell:ProgramFiles`
- `Shell:System`
- `Shell:ControlPanelFolder`
- `Shell:Windows`
- `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Control Panel
- `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> My Computer
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> My Network Places
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Показати розширення файлів

Детальніше див. на сторінці: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Трюки в браузерах

Backup iKat versions:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Створіть загальний діалог за допомогою JavaScript і отримайте доступ до провідника файлів: `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Жести та кнопки

- Проведіть вгору чотирма (або п'ятьма) пальцями / Двічі натисніть кнопку Home: щоб побачити перегляд багатозадачності і змінити додаток
- Проведіть вліво або вправо чотирма або п'ятьма пальцями: щоб перейти до наступного/попереднього додатка
- Стисніть екран п'ятьма пальцями / Натисніть кнопку Home / Проведіть одним пальцем знизу екрана швидким рухом вгору: щоб перейти на головний екран (Home)
- Проведіть одним пальцем від нижнього краю екрана на 1–2 дюйми (повільно): з'явиться Dock
- Проведіть одним пальцем вниз із верхньої частини дисплея: щоб переглянути сповіщення
- Проведіть одним пальцем вниз у верхньому правому куті екрана: щоб побачити Control Centre iPad Pro
- Проведіть одним пальцем зліва екрану на 1–2 дюйми: щоб побачити Today view
- Швидко проведіть одним пальцем від центру екрана вправо або вліво: щоб переключитися на наступний/попередній додаток
- Натисніть і утримуйте кнопку On/**Off**/Sleep у верхньому правому куті **iPad +** Пересуньте слайдер Slide to **power off** повністю вправо: щоб вимкнути живлення
- Натисніть кнопку On/**Off**/Sleep у верхньому правому куті **iPad** і кнопку Home протягом кількох секунд: щоб примусово вимкнути
- Натисніть кнопку On/**Off**/Sleep у верхньому правому куті **iPad** і кнопку Home швидко: щоб зробити скріншот, який з'явиться в нижньому лівому куті дисплея. Натисніть обидві кнопки одночасно дуже коротко; якщо утримувати кілька секунд, буде виконано примусове вимкнення.

### Клавішні скорочення

Вам знадобиться клавіатура для iPad або USB-адаптер для клавіатури. Тут наведено тільки скорочення, що можуть допомогти вийти з додатка.

| Key | Name         |
| --- | ------------ |
| ⌘   | Command      |
| ⌥   | Option (Alt) |
| ⇧   | Shift        |
| ↩   | Return       |
| ⇥   | Tab          |
| ^   | Control      |
| ←   | Left Arrow   |
| →   | Right Arrow  |
| ↑   | Up Arrow     |
| ↓   | Down Arrow   |

#### Системні скорочення

Ці скорочення стосуються візуальних налаштувань і звуку, залежно від використання iPad.

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Зменшити яскравість екрану                                                     |
| F2       | Збільшити яскравість екрану                                                    |
| F7       | Попередній трек                                                                 |
| F8       | Відтворення/пауза                                                              |
| F9       | Наступний трек                                                                  |
| F10      | Вимкнути звук                                                                   |
| F11      | Зменшити гучність                                                               |
| F12      | Збільшити гучність                                                              |
| ⌘ Space  | Відобразити список доступних мов; щоб вибрати — натисніть пробіл ще раз.       |

#### Навігація iPad

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Перейти на Home                                         |
| ⌘⇧H (Command-Shift-H)                              | Перейти на Home                                         |
| ⌘ (Space)                                          | Відкрити Spotlight                                      |
| ⌘⇥ (Command-Tab)                                   | Показати останні десять використаних додатків           |
| ⌘\~                                                | Перейти до останнього додатка                           |
| ⌘⇧3 (Command-Shift-3)                              | Скріншот (з'являється внизу зліва для збереження або дії)|
| ⌘⇧4                                                | Скріншот і відкриття в редакторі                        |
| Press and hold ⌘                                   | Список доступних скорочень для додатка                  |
| ⌘⌥D (Command-Option/Alt-D)                         | Показати Dock                                           |
| ^⌥H (Control-Option-H)                             | Кнопка Home                                             |
| ^⌥H H (Control-Option-H-H)                         | Показати панель багатозадачності                        |
| ^⌥I (Control-Option-i)                             | Вибір елементу                                          |
| Escape                                             | Кнопка назаду                                           |
| → (Right arrow)                                    | Наступний елемент                                       |
| ← (Left arrow)                                     | Попередній елемент                                      |
| ↑↓ (Up arrow, Down arrow)                          | Одночасне натискання вибраного елемента                 |
| ⌥ ↓ (Option-Down arrow)                            | Прокрутити вниз                                         |
| ⌥↑ (Option-Up arrow)                               | Прокрутити вгору                                       |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Прокрутити вліво або вправо                             |
| ^⌥S (Control-Option-S)                             | Увімкнути/вимкнути мовлення VoiceOver                   |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Переключитися на попередній додаток                     |
| ⌘⇥ (Command-Tab)                                   | Повернутися до початкового додатка                      |
| ←+→, then Option + ← or Option+→                   | Навігація по Dock                                      |

#### Скорочення Safari

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Відкрити поле адреси                             |
| ⌘T                      | Відкрити нову вкладку                            |
| ⌘W                      | Закрити поточну вкладку                          |
| ⌘R                      | Оновити поточну вкладку                          |
| ⌘.                      | Зупинити завантаження поточної вкладки           |
| ^⇥                      | Перейти до наступної вкладки                     |
| ^⇧⇥ (Control-Shift-Tab) | Перейти до попередньої вкладки                   |
| ⌘L                      | Виділити текстове поле/URL для редагування       |
| ⌘⇧T (Command-Shift-T)   | Відкрити останню закриту вкладку (можна використовувати кілька разів) |
| ⌘\[                     | Повернутися на одну сторінку назад в історії      |
| ⌘]                      | Перейти вперед на одну сторінку в історії         |
| ⌘⇧R                     | Увімкнути режим читача (Reader Mode)             |

#### Скорочення Mail

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Відкрити поле адреси         |
| ⌘T                         | Відкрити нову вкладку        |
| ⌘W                         | Закрити поточну вкладку      |
| ⌘R                         | Оновити поточну вкладку      |
| ⌘.                         | Зупинити завантаження вкладки|
| ⌘⌥F (Command-Option/Alt-F) | Пошук у поштовій скриньці     |

## Джерела

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
