# Вихід із KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Перевірка фізичного пристрою

| Компонент    | Дія                                                             |
| ------------ | ------------------------------------------------------------------ |
| Кнопка живлення | Вимкнення та повторне ввімкнення пристрою може відкрити стартовий екран    |
| Кабель живлення  | Перевірте, чи перезавантажується пристрій після короткочасного відключення живлення |
| USB-порти    | Підключіть фізичну клавіатуру з додатковими shortcuts                      |
| Ethernet     | Сканування мережі або sniffing може уможливити подальшу експлуатацію           |

## Перевірка можливих дій усередині GUI application

**Common Dialogs** — це опції **збереження файлу**, **відкриття файлу**, вибору шрифту, кольору... Більшість із них **пропонує повну функціональність Explorer**. Це означає, що ви зможете отримати доступ до функцій Explorer, якщо маєте доступ до таких опцій:

- Close/Close as
- Open/Open with
- Print
- Export/Import
- Search
- Scan

Перевірте, чи можете ви:

- Змінювати або створювати нові файли
- Створювати symbolic links
- Отримувати доступ до обмежених областей
- Запускати інші apps

### Виконання команд

Можливо, **за допомогою опції `Open with`** ви зможете відкрити/запустити shell.

#### Windows

Наприклад, _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ знайти більше binaries, які можна використовувати для виконання команд (і неочікуваних дій), можна тут: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Більше тут: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Обхід обмежень шляхів

- **Змінні середовища**: існує багато змінних середовища, які вказують на певний шлях
- **Інші протоколи**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Shortcuts**: CTRL+N (відкрити нову сесію), CTRL+R (виконати команди), CTRL+SHIFT+ESC (Task Manager), Windows+E (відкрити explorer), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Hidden Administrative menu: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: шляхи для підключення до shared folders. Спробуйте підключитися до C$ локальної машини ("\\\127.0.0.1\c$\Windows\System32")
- **Більше UNC paths:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%              | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

### Вихід із Restricted Desktop (Citrix/RDS/VDI)

- **Dialog-box pivoting**: Використовуйте діалоги *Open/Save/Print-to-file* як спрощений Explorer. Спробуйте `*.*` / `*.exe` у полі імені файлу, клацніть правою кнопкою миші папки, щоб вибрати **Open in new window**, і скористайтеся **Properties → Open file location**, щоб розширити навігацію.<sup>[[1]](#references)</sup>
- **Створення шляхів виконання з діалогів**: Створіть новий файл і перейменуйте його на `.CMD` або `.BAT`, або створіть shortcut, що вказує на `%WINDIR%\System32` (чи на конкретний binary, наприклад `%WINDIR%\System32\cmd.exe`).
- **Shell launch pivots**: Якщо ви можете перейти до `cmd.exe`, спробуйте **перетягнути** будь-який файл на нього, щоб запустити prompt. Якщо Task Manager доступний (`CTRL+SHIFT+ESC`), використайте **Run new task**.
- **Обхід Task Scheduler**: Якщо інтерактивні shells заблоковані, але планування дозволене, створіть task для запуску `cmd.exe` (через GUI `taskschd.msc` або `schtasks.exe`).
- **Слабкі allowlists**: Якщо виконання дозволене за **ім’ям файлу/розширенням**, перейменуйте payload на дозволене ім’я. Якщо воно дозволене за **каталогом**, скопіюйте payload до дозволеної програмної папки та запустіть його звідти.
- **Пошук доступних для запису staging paths**: Почніть із `%TEMP%` і перелічіть доступні для запису папки за допомогою Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Наступний крок**: Якщо ви отримали shell, перейдіть до чекліста Windows LPE:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Завантаження бінарних файлів

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Редактор реєстру: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Доступ до файлової системи з браузера

| PATH                | PATH              | PATH              | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### Комбінації клавіш

- Sticky Keys – натиснути SHIFT 5 разів
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – утримувати NUMLOCK протягом 5 секунд
- Filter Keys – утримувати праву клавішу SHIFT протягом 12 секунд
- WINDOWS+F1 – пошук Windows
- WINDOWS+D – показати робочий стіл
- WINDOWS+E – запустити Windows Explorer
- WINDOWS+R – Run
- WINDOWS+U – Центр спеціальних можливостей
- WINDOWS+F – пошук
- SHIFT+F10 – контекстне меню
- CTRL+SHIFT+ESC – Диспетчер завдань
- CTRL+ALT+DEL – заставка в новіших версіях Windows
- F1 – довідка F3 – пошук
- F6 – адресний рядок
- F11 – увімкнути або вимкнути повноекранний режим в Internet Explorer
- CTRL+H – історія Internet Explorer
- CTRL+T – Internet Explorer – нова вкладка
- CTRL+N – Internet Explorer – нова сторінка
- CTRL+O – відкрити файл
- CTRL+S – зберегти CTRL+N – новий RDP / Citrix

### Жести

- Проведіть пальцем зліва направо, щоб переглянути всі відкриті Windows, згорнути застосунок KIOSK і отримати прямий доступ до всієї ОС;
- Проведіть пальцем справа наліво, щоб відкрити Центр дій, згорнути застосунок KIOSK і отримати прямий доступ до всієї ОС;
- Проведіть пальцем від верхнього краю, щоб зробити рядок заголовка видимим для застосунку, відкритого в повноекранному режимі;
- Проведіть пальцем знизу вгору, щоб показати панель завдань у повноекранному застосунку.

### Прийоми для Internet Explorer

#### «Image Toolbar»

Це панель інструментів, яка з’являється у верхньому лівому куті зображення після натискання на нього. Ви зможете зберігати, друкувати, надсилати поштою та відкривати «My Pictures» в Explorer. У Kiosk має використовуватися Internet Explorer.

#### Shell Protocol

Введіть ці URL, щоб отримати подання Explorer:

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
- `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Панель керування
- `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> Мій комп’ютер
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> Мережеве оточення
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Показ розширень файлів

Перегляньте цю сторінку для отримання додаткової інформації: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)<sup>[[7]](#references)</sup>

## Прийоми для браузерів

Резервні версії iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Створіть стандартне діалогове вікно за допомогою JavaScript і отримайте доступ до провідника файлів: `document.write('<input/type=file>')`<sup>[[2]](#references)</sup>\
Джерело: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Жести та кнопки

- Проведіть чотирма (або п’ятьма) пальцями вгору / двічі натисніть кнопку Home: щоб переглянути режим багатозадачності та змінити застосунок
- Проведіть чотирма або п’ятьма пальцями в один чи інший бік: щоб перейти до наступного або попереднього застосунку
- Зведіть п’ять пальців на екрані / натисніть кнопку Home / швидко проведіть одним пальцем знизу екрана вгору: щоб перейти на Home
- Повільно проведіть одним пальцем від нижнього краю екрана на 1–2 дюйми: з’явиться Dock
- Проведіть одним пальцем зверху дисплея вниз: щоб переглянути сповіщення
- Проведіть одним пальцем вниз від верхнього правого кута екрана: щоб переглянути Центр керування iPad Pro
- Проведіть одним пальцем зліва екрана на 1–2 дюйми: щоб переглянути Today
- Швидко проведіть одним пальцем від центру екрана вправо або вліво: щоб перейти до наступного або попереднього застосунку
- Натисніть і утримуйте кнопку On/**Off**/Sleep у верхньому правому куті **iPad +** перемістіть повзунок **power off** до кінця праворуч: щоб вимкнути живлення
- Натисніть кнопку On/**Off**/Sleep у верхньому правому куті **iPad і кнопку Home протягом кількох секунд**: щоб виконати примусове вимкнення
- Швидко натисніть кнопку On/**Off**/Sleep у верхньому правому куті **iPad і кнопку Home**: щоб зробити знімок екрана, який з’явиться в нижньому лівому куті дисплея. Натисніть обидві кнопки одночасно на дуже короткий час, оскільки утримування їх протягом кількох секунд призведе до примусового вимкнення.<sup>[[3]](#references)</sup>

### Комбінації клавіш

Вам знадобиться клавіатура iPad або USB-адаптер для клавіатури. Тут наведено лише комбінації, які можуть допомогти вийти із застосунку.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

| Key | Name         |
| --- | ------------ |
| ⌘   | Command      |
| ⌥   | Option (Alt) |
| ⇧   | Shift        |
| ↩   | Return       |
| ⇥   | Tab          |
| ^   | Control      |
| ←   | Стрілка вліво   |
| →   | Стрілка вправо  |
| ↑   | Стрілка вгору     |
| ↓   | Стрілка вниз   |

#### Системні комбінації клавіш

Ці комбінації призначені для візуальних і звукових налаштувань залежно від використання iPad.

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Зменшити яскравість екрана                                                                    |
| F2       | Збільшити яскравість екрана                                                                |
| F7       | Попередня пісня                                                                  |
| F8       | Відтворення/пауза                                                                     |
| F9       | Пропустити пісню                                                                      |
| F10      | Вимкнути звук                                                                           |
| F11      | Зменшити гучність                                                                |
| F12      | Збільшити гучність                                                                |
| ⌘ Space  | Показати список доступних мов; щоб вибрати мову, натисніть пробіл ще раз. |

#### Навігація iPad

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Перейти на Home                                              |
| ⌘⇧H (Command-Shift-H)                              | Перейти на Home                                              |
| ⌘ (Space)                                          | Відкрити Spotlight                                          |
| ⌘⇥ (Command-Tab)                                   | Список десяти останніх використаних застосунків                                 |
| ⌘\~                                                | Перейти до останнього застосунку                                       |
| ⌘⇧3 (Command-Shift-3)                              | Знімок екрана (відображається внизу ліворуч для збереження або виконання дій) |
| ⌘⇧4                                                | Зробити знімок екрана та відкрити його в редакторі                    |
| Натисніть і утримуйте ⌘                                   | Список доступних для застосунку комбінацій клавіш                 |
| ⌘⌥D (Command-Option/Alt-D)                         | Відкрити Dock                                      |
| ^⌥H (Control-Option-H)                             | Кнопка Home                                             |
| ^⌥H H (Control-Option-H-H)                         | Показати панель багатозадачності                                      |
| ^⌥I (Control-Option-i)                             | Вибір елемента                                            |
| Escape                                             | Кнопка «Назад»                                             |
| → (Right arrow)                                    | Наступний елемент                                               |
| ← (Left arrow)                                     | Попередній елемент                                           |
| ↑↓ (Up arrow, Down arrow)                          | Одночасно натиснути вибраний елемент                        |
| ⌥ ↓ (Option-Down arrow)                            | Прокрутити вниз                                             |
| ⌥↑ (Option-Up arrow)                               | Прокрутити вгору                                               |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Прокрутити вліво або вправо                                    |
| ^⌥S (Control-Option-S)                             | Увімкнути або вимкнути мовлення VoiceOver                         |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Перейти до попереднього застосунку                              |
| ⌘⇥ (Command-Tab)                                   | Повернутися до початкового застосунку                         |
| ←+→, then Option + ← or Option+→                   | Навігація через Dock                                   |

#### Комбінації клавіш Safari

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Відкрити адресу                                    |
| ⌘T                      | Відкрити нову вкладку                                   |
| ⌘W                      | Закрити поточну вкладку                            |
| ⌘R                      | Оновити поточну вкладку                          |
| ⌘.                      | Зупинити завантаження поточної вкладки                     |
| ^⇥                      | Перейти до наступної вкладки                           |
| ^⇧⇥ (Control-Shift-Tab) | Перейти до попередньої вкладки                         |
| ⌘L                      | Вибрати текстове поле/поле URL для редагування     |
| ⌘⇧T (Command-Shift-T)   | Відкрити останню закриту вкладку (можна використовувати кілька разів) |
| ⌘\[                     | Перейти на одну сторінку назад в історії перегляду      |
| ⌘]                      | Перейти на одну сторінку вперед в історії перегляду   |
| ⌘⇧R                     | Увімкнути режим читання                             |

#### Комбінації клавіш Mail

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Відкрити адресу                |
| ⌘T                         | Відкрити нову вкладку               |
| ⌘W                         | Закрити поточну вкладку               |
| ⌘R                         | Оновити поточну вкладку               |
| ⌘.                         | Зупинити завантаження поточної вкладки |
| ⌘⌥F (Command-Option/Alt-F) | Пошук у поштовій скриньці       |

## References

- [1] [Breaking Out of Citrix and other Restricted Desktop Environments](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [2] [Give me a browser, I'll give you a shell](https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0)
- [3] [6 only-for-iPad gestures you need to know](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [4] [iPad shortcuts guide](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [5] [Best iPad Keyboard Shortcuts](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [6] [iPad Keyboard Shortcuts](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)
- [7] [howtohaven.com - Show File Extensions In Windows Explorer](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

{{#include ../banners/hacktricks-training.md}}
