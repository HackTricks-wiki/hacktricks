# Втеча з KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Перевірте фізичний пристрій

| Component    | Action                                                             |
| ------------ | ------------------------------------------------------------------ |
| Power button | Вимкнення та повторне ввімкнення пристрою може відкрити стартовий екран |
| Power cable  | Перевірте, чи перезавантажується пристрій при короткому відключенні живлення |
| USB ports    | Підключіть фізичну клавіатуру для додаткових гарячих клавіш        |
| Ethernet     | Network scan або sniffing можуть дозволити подальшу експлуатацію   |

## Перевірте можливі дії всередині GUI-додатка

**Типові діалоги** — це опції **збереження файлу**, **відкриття файлу**, вибору шрифту, кольору... Більшість з них **пропонують повну функціональність Explorer**. Це означає, що ви зможете отримати доступ до функцій Explorer, якщо зможете відкрити ці опції:

- Close/Close as
- Open/Open with
- Print
- Export/Import
- Search
- Scan

Перевірте, чи можете ви:

- Змінювати або створювати нові файли
- Створювати символічні посилання
- Отримувати доступ до обмежених областей
- Запускати інші додатки

### Виконання команд

Можливо, використовуючи опцію `Open with` ви зможете відкрити або запустити якусь оболонку (shell).

#### Windows

Наприклад _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ Знайдіть більше бінарників, які можна використати для виконання команд (і виконання несподіваних дій), тут: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Більше тут: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Обхід обмежень шляхів

- **Змінні середовища**: Існує багато environment variables, які вказують на певні шляхи
- **Інші протоколи**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Символічні посилання**
- **Клавішні скорочення**: CTRL+N (open new session), CTRL+R (Execute Commands), CTRL+SHIFT+ESC (Task Manager), Windows+E (open explorer), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Приховане адміністративне меню: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Шляхи для підключення до shared folders. Спробуйте підключитися до C$ локальної машини ("\\\127.0.0.1\c$\Windows\System32")
- **Інші UNC-шляхи:**

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

- **Dialog-box pivoting**: Використовуйте *Open/Save/Print-to-file* діалоги як спрощений Explorer. Спробуйте `*.*` / `*.exe` у полі імені файлу, клацніть правою кнопкою по папках для **Open in new window**, і використовуйте **Properties → Open file location** для розширення навігації.
- **Create execution paths from dialogs**: Створіть новий файл і перейменуйте його в `.CMD` або `.BAT`, або створіть shortcut, який вказує на `%WINDIR%\System32` (або на конкретний бінарник, наприклад `%WINDIR%\System32\cmd.exe`).
- **Shell launch pivots**: Якщо ви можете перейти до `cmd.exe`, спробуйте перетягнути будь-який файл на нього, щоб запустити prompt. Якщо Task Manager доступний (`CTRL+SHIFT+ESC`), використовуйте **Run new task**.
- **Task Scheduler bypass**: Якщо інтерактивні оболонки заблоковані, але дозволено планування, створіть задачу, яка запускає `cmd.exe` (GUI `taskschd.msc` або `schtasks.exe`).
- **Weak allowlists**: Якщо виконання дозволене за ім'ям файлу/розширенням, перейменуйте ваш payload на дозволене ім'я. Якщо дозволено за директорією, скопіюйте payload в дозволену папку програм і запустіть звідти.
- **Find writable staging paths**: Почніть з %TEMP% і перераховуйте writable folders за допомогою Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Наступний крок**: Якщо ви отримали shell, перейдіть до чекліста Windows LPE:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Завантажте свої бінарні файли

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

### Скорочення клавіш

- Sticky Keys – Натисніть SHIFT 5 разів
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – Утримуйте NUMLOCK протягом 5 секунд
- Filter Keys – Утримуйте правий SHIFT протягом 12 секунд
- WINDOWS+F1 – Windows Search
- WINDOWS+D – Показати робочий стіл
- WINDOWS+E – Запустити Windows Explorer
- WINDOWS+R – Run
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Пошук
- SHIFT+F10 – Контекстне меню
- CTRL+SHIFT+ESC – Диспетчер завдань
- CTRL+ALT+DEL – Екран блокування на новіших версіях Windows
- F1 – Help F3 – Search
- F6 – Address Bar
- F11 – Перемикнути повноекранний режим у Internet Explorer
- CTRL+H – Історія Internet Explorer
- CTRL+T – Internet Explorer – Нова вкладка
- CTRL+N – Internet Explorer – Нова сторінка
- CTRL+O – Відкрити файл
- CTRL+S – Зберегти CTRL+N – Новий RDP / Citrix

### Жести (Swipes)

- Проведіть з лівого краю вправо, щоб побачити всі відкриті вікна, мінімізувавши KIOSK додаток і отримати доступ до всієї ОС;
- Проведіть з правого краю вліво, щоб відкрити Action Center, мінімізувавши KIOSK додаток і отримати доступ до всієї ОС;
- Проведіть зверху вниз по верхньому краю, щоб показати панель заголовка для додатку, відкритого в повноекранному режимі;
- Проведіть вгору знизу, щоб показати панель завдань у повноекранному додатку.

### Internet Explorer Tricks

#### 'Image Toolbar'

Це панель інструментів, яка з'являється у верхньому лівому куті зображення при його натисканні. Ви зможете Save, Print, Mailto, Open "My Pictures" в Explorer. Kiosk має використовувати Internet Explorer.

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

Перегляньте цю сторінку для отримання додаткової інформації: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Хитрощі для браузерів

Резервні версії iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Створіть звичний діалог за допомогою JavaScript і отримайте доступ до провідника файлів: `document.write('<input/type=file>')`\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Жести та кнопки

- Проведіть вгору чотирма (або п'ятьма) пальцями / Подвійне натискання кнопки Home: Щоб переглянути багатозадачний режим і змінити додаток
- Проведіть вліво або вправо чотирма або п'ятьма пальцями: Щоб переключитися на наступний/попередній додаток
- Зведіть екран п'ятьма пальцями / Натисніть кнопку Home / Проведіть одним пальцем знизу екрану вгору швидким рухом: Щоб повернутися на Home
- Проведіть одним пальцем знизу екрану на 1–2 дюйми (повільно): З'явиться Dock
- Проведіть вниз від верхньої частини дисплея одним пальцем: Щоб переглянути сповіщення
- Проведіть вниз одним пальцем у верхньому правому куті екрана: Щоб побачити центр керування iPad Pro
- Проведіть одним пальцем зліва екрану на 1–2 дюйми: Щоб побачити Today view
- Швидко проведіть одним пальцем від центру екрану праворуч або ліворуч: Щоб переключитися на наступний/попередній додаток
- Натисніть і утримуйте кнопку On/**Off**/Sleep у верхньому правому куті **iPad +** Перемістіть слайдер **power off** повністю вправо: Щоб вимкнути пристрій
- Натисніть і утримуйте кнопку On/**Off**/Sleep у верхньому правому куті **iPad та кнопку Home на кілька секунд**: Щоб виконати примусове вимкнення
- Натисніть кнопку On/**Off**/Sleep у верхньому правому куті **iPad і кнопку Home швидко**: Щоб зробити знімок екрана, який з'явиться в нижньому лівому куті дисплея. Натисніть обидві кнопки одночасно дуже коротко; якщо утримувати їх кілька секунд, буде виконано примусове вимкнення.

### Скорочення клавіш

Вам знадобиться клавіатура для iPad або USB-адаптер для клавіатури. Тут показані лише скорочення, які можуть допомогти вийти з додатку.

| Key | Назва        |
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

Ці скорочення керують візуальними та звуковими налаштуваннями, залежно від використання iPad.

| Комбінація | Дія                                                                 |
| ---------- | -------------------------------------------------------------------- |
| F1         | Зменшити яскравість екрану                                           |
| F2         | Збільшити яскравість екрану                                          |
| F7         | Попередня композиція                                                 |
| F8         | Відтворити/пауза                                                     |
| F9         | Наступна композиція                                                  |
| F10        | Вимкнути звук                                                         |
| F11        | Зменшити гучність                                                    |
| F12        | Збільшити гучність                                                   |
| ⌘ Space    | Відобразити список доступних мов; щоб вибрати одну, натисніть пробіл ще раз. |

#### Навігація iPad

| Комбінація                                         | Дія                                                      |
| -------------------------------------------------- | -------------------------------------------------------- |
| ⌘H                                                 | Перейти на Home                                          |
| ⌘⇧H (Command-Shift-H)                              | Перейти на Home                                          |
| ⌘ (Space)                                          | Відкрити Spotlight                                       |
| ⌘⇥ (Command-Tab)                                   | Список останніх десяти використаних додатків             |
| ⌘\~                                                | Перейти до останнього додатку                            |
| ⌘⇧3 (Command-Shift-3)                              | Знімок екрана (з'являється в нижньому лівому куті для збереження або дії) |
| ⌘⇧4                                                | Знімок екрана і відкриття в редакторі                    |
| Press and hold ⌘                                   | Список доступних скорочень для додатку                   |
| ⌘⌥D (Command-Option/Alt-D)                         | Відобразити Dock                                         |
| ^⌥H (Control-Option-H)                             | Кнопка Home                                              |
| ^⌥H H (Control-Option-H-H)                         | Показати панель багатозадачності                         |
| ^⌥I (Control-Option-i)                             | Вибір елементу                                           |
| Escape                                             | Кнопка Назад                                             |
| → (Right arrow)                                    | Наступний елемент                                        |
| ← (Left arrow)                                     | Попередній елемент                                       |
| ↑↓ (Up arrow, Down arrow)                          | Одночасне натискання виділеного елементу                 |
| ⌥ ↓ (Option-Down arrow)                            | Прокрутка вниз                                           |
| ⌥↑ (Option-Up arrow)                               | Прокрутка вгору                                          |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Прокрутка вліво або вправо                               |
| ^⌥S (Control-Option-S)                             | Увімкнути або вимкнути озвучення VoiceOver               |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Переключитися на попередній додаток                      |
| ⌘⇥ (Command-Tab)                                   | Повернутися до початкового додатку                       |
| ←+→, then Option + ← or Option+→                   | Навігація по Dock                                        |

#### Safari скорочення

| Комбінація                | Дія                                                    |
| ------------------------- | ------------------------------------------------------ |
| ⌘L (Command-L)            | Відкрити поле для введення URL                         |
| ⌘T                       | Відкрити нову вкладку                                  |
| ⌘W                       | Закрити поточну вкладку                                |
| ⌘R                       | Оновити поточну вкладку                                |
| ⌘.                       | Зупинити завантаження поточної вкладки                 |
| ^⇥                       | Перейти до наступної вкладки                           |
| ^⇧⇥ (Control-Shift-Tab)   | Перейти до попередньої вкладки                         |
| ⌘L                       | Виділити поле введення/URL для редагування             |
| ⌘⇧T (Command-Shift-T)     | Відкрити останню закриту вкладку (можна використовувати кілька разів) |
| ⌘\[                      | Назад на одну сторінку в історії                       |
| ⌘]                       | Вперед на одну сторінку в історії                      |
| ⌘⇧R                      | Увімкнути Reader Mode                                  |

#### Mail скорочення

| Комбінація                   | Дія                          |
| --------------------------- | ---------------------------- |
| ⌘L                          | Відкрити поле для введення URL|
| ⌘T                          | Відкрити нову вкладку        |
| ⌘W                          | Закрити поточну вкладку      |
| ⌘R                          | Оновити поточну вкладку      |
| ⌘.                          | Зупинити завантаження        |
| ⌘⌥F (Command-Option/Alt-F)  | Пошук у поштовій скриньці    |

## Посилання

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
