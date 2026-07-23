# Linux-Umgebungsvariablen

{{#include ../../banners/hacktricks-training.md}}

## Globale Variablen

Die globalen Variablen werden von **Kindprozessen** geerbt.

Du kannst eine globale Variable für deine aktuelle Sitzung erstellen mit:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Diese Variable ist in Ihren aktuellen Sitzungen und deren Kindprozessen verfügbar.

Sie können eine Variable wie folgt **entfernen**:
```bash
unset MYGLOBAL
```
## Lokale Variablen

Auf **lokale Variablen** kann nur von der **aktuellen Shell/dem aktuellen Skript** **zugegriffen** werden.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Aktuelle Variablen auflisten
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
Die Inhalte von `/proc/*/environ` sind **NUL-getrennt**, daher sind diese Varianten normalerweise leichter zu lesen:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Wenn du nach **Zugangsdaten** oder einer **interessanten Service-Konfiguration** in geerbten Umgebungen suchst, prüfe auch [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Häufig verwendete Variablen

Von: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – das von **X** verwendete Display. Diese Variable wird normalerweise auf **:0.0** gesetzt, was das erste Display auf dem aktuellen Computer bedeutet.
- **EDITOR** – der vom Benutzer bevorzugte Texteditor.
- **HISTFILESIZE** – die maximale Anzahl von Zeilen, die die History-Datei enthalten darf.
- **HISTSIZE** – Anzahl der Zeilen, die der History-Datei hinzugefügt werden, wenn der Benutzer seine Sitzung beendet.
- **HOME** – dein Home-Verzeichnis.
- **HOSTNAME** – der Hostname des Computers.
- **LANG** – deine aktuelle Sprache.
- **MAIL** – der Speicherort des Mail-Spools des Benutzers. Normalerweise **/var/spool/mail/USER**.
- **MANPATH** – die Liste der Verzeichnisse, die nach Manual-Seiten durchsucht werden.
- **OSTYPE** – der Typ des Betriebssystems.
- **PS1** – der Standard-Prompt in bash.
- **PATH** – speichert den Pfad aller Verzeichnisse, die ausführbare Dateien enthalten, die du ausführen möchtest, indem du einfach den Dateinamen und nicht den relativen oder absoluten Pfad angibst.
- **PWD** – das aktuelle Arbeitsverzeichnis.
- **SHELL** – der Pfad zur aktuellen Command Shell (zum Beispiel **/bin/bash**).
- **TERM** – der aktuelle Terminaltyp (zum Beispiel **xterm**).
- **TZ** – deine Zeitzone.
- **USER** – dein aktueller Benutzername.

## Interessante Variablen für Hacking

Nicht jede Variable ist gleichermaßen nützlich. Aus offensiver Sicht solltest du Variablen priorisieren, die **Suchpfade**, **Startup-Dateien**, das **Verhalten des Dynamic Linkers** oder **Audit/Logging** verändern.

### **HISTFILESIZE**

Ändere den **Wert dieser Variable auf 0**, damit beim **Beenden deiner Sitzung** die **History-Datei** (\~/.bash_history) **auf 0 Zeilen gekürzt** wird.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Ändere den **Wert dieser Variable auf 0**, damit Befehle **nicht im Verlauf im Arbeitsspeicher gespeichert** und nicht in die **Verlaufsdatei** (\~/.bash_history) geschrieben werden.
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Wenn der **Wert dieser Variable auf `ignorespace` oder `ignoreboth` gesetzt ist**, wird jeder Befehl, dem ein zusätzliches Leerzeichen vorangestellt ist, nicht in der History gespeichert.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Setze die **Verlaufsdatei** auf **`/dev/null`** oder hebe sie vollständig auf. Das ist normalerweise zuverlässiger, als nur die Verlaufsgröße zu ändern.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Die Prozesse verwenden den hier angegebenen **Proxy**, um über **http oder https** eine Verbindung zum Internet herzustellen.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: Standard-Proxy für Tools/Protokolle, die ihn beachten.
- `no_proxy`: Umgehungsliste (Hosts/Domains/CIDRs), die direkt verbunden werden sollen.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Je nach Tool können sowohl Kleinschreibungs- als auch Großschreibungsvarianten verwendet werden (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Die Prozesse vertrauen den in **diesen Umgebungsvariablen** angegebenen Zertifikaten. Dies ist nützlich, damit Tools wie **`curl`**, **`git`**, Python-HTTP-Clients oder Paketmanager einer vom Angreifer kontrollierten CA vertrauen (beispielsweise, damit ein Interception-Proxy legitim aussieht).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Wenn ein privilegierter Wrapper/ein privilegiertes Script Befehle **ohne absolute Pfade** ausführt, gewinnt das **erste vom Angreifer kontrollierte Verzeichnis** in `PATH`. Dies ist das Primitive hinter vielen **PATH hijacks** in `sudo`, Cron-Jobs, Shell-Wrappern und benutzerdefinierten SUID-Helfern. Suche nach `env_keep+=PATH`, einem schwachen `secure_path` oder Wrappern, die `tar`, `service`, `cp`, `python` usw. anhand ihres Namens aufrufen.
```bash
mkdir -p /dev/shm/bin
cat > /dev/shm/bin/tar <<'EOF'
#!/bin/sh
echo '[+] PATH hijack reached' >&2
id
EOF
chmod +x /dev/shm/bin/tar
PATH=/dev/shm/bin:$PATH vulnerable-wrapper
```
Für vollständige Privilege-Escalation-Ketten unter Ausnutzung von `PATH` siehe [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` ist nicht nur eine Verzeichnisreferenz: Viele Tools laden automatisch **dotfiles**, **Plugins** und **Benutzerkonfiguration** aus `$HOME` oder `$XDG_CONFIG_HOME`. Wenn ein privilegierter Workflow diese Werte beibehält, kann **config injection** einfacher sein als **binary hijacking**.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Interessante Ziele umfassen `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` und toolspezifische Dateien wie `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Diese Variablen beeinflussen den **dynamischen Linker**:

- `LD_PRELOAD`: Erzwingt, dass zusätzliche Shared Objects zuerst geladen werden.
- `LD_LIBRARY_PATH`: Stellt Bibliotheks-Suchverzeichnisse voran.
- `LD_AUDIT`: Lädt Auditor-Bibliotheken, die das Laden von Bibliotheken und die Symbolauflösung beobachten.

Sie sind äußerst wertvoll für **hooking**, **instrumentation** und **privilege escalation**, wenn ein privilegierter Befehl sie beibehält. Im **secure-execution**-Modus (`AT_SECURE`, z. B. setuid/setgid/capabilities) entfernt oder beschränkt der Loader viele dieser Variablen. Parser-Bugs in dieser frühen Loader-Phase sind jedoch weiterhin sehr wirkungsvoll, da sie **vor** dem Zielprogramm ausgeführt werden.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` verändert das frühe Verhalten von glibc (zum Beispiel die Tunables des Allocators) und ist in exploit labs sehr nützlich. Aus Sicherheitsperspektive ist die Variable ebenfalls relevant, weil der **dynamische Loader sie sehr früh parst**. Der **Looney Tunables**-Bug aus dem Jahr 2023 war eine gute Erinnerung daran, dass eine einzelne Umgebungsvariable, die im Loader geparst wird, zu einer **Local-Privilege-Escalation-Primitive** gegen SUID-Programme werden kann.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Wenn **Bash** **nicht-interaktiv** gestartet wird, prüft es `BASH_ENV` und führt den Inhalt dieser Datei mit `source` aus, bevor das Ziels script ausgeführt wird. Wenn Bash als `sh` oder im interaktiven POSIX-Modus aufgerufen wird, kann auch `ENV` berücksichtigt werden. Dies ist eine klassische Möglichkeit, einen Shell-Wrapper in eine Code Execution zu verwandeln, wenn die Umgebung von einem Angreifer kontrolliert wird.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash selbst deaktiviert diese Startdateien, wenn sich die **realen/effektiven IDs unterscheiden**, sofern nicht `-p` verwendet wird. Das genaue Verhalten hängt daher davon ab, wie der Wrapper die Shell startet. Seien Sie vorsichtig bei privilegierten Wrappern, die **vor** dem Start von Bash `setuid()`/`setgid()` aufrufen: Sobald die IDs wieder übereinstimmen, vertraut Bash möglicherweise `BASH_ENV`, `ENV` und dem zugehörigen Shell-Zustand, die andernfalls ignoriert würden.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Diese Variablen verändern, wie Python gestartet wird:

- `PYTHONPATH`: Import-Suchpfade voranstellen.
- `PYTHONHOME`: Den Verzeichnisbaum der Standardbibliothek verlagern.
- `PYTHONSTARTUP`: Eine Datei vor der interaktiven Eingabeaufforderung ausführen.
- `PYTHONINSPECT=1`: Nach Beendigung eines Skripts in den interaktiven Modus wechseln.

Sie sind nützlich gegen Wartungsskripte, Debugger, Shells und Wrapper, die Python mit einer kontrollierbaren Umgebung aufrufen. `python -E` und `python -I` ignorieren alle `PYTHON*`-Variablen.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
Ein aktuelles Beispiel aus der Praxis war die **needrestart**-LPE von 2024 auf Ubuntu-/Debian-Systemen: Der Scanner mit Root-Rechten kopierte den `PYTHONPATH` eines unprivilegierten Prozesses aus `/proc/<PID>/environ` und führte anschließend Python aus. Der veröffentlichte Exploit platzierte `importlib/__init__.so` im vom Angreifer kontrollierten Pfad, sodass Python während seiner eigenen Initialisierung Angreifercode ausführte, bevor das fest codierte Skript des Helfers überhaupt relevant wurde.

### **PERL5OPT & PERL5LIB**

Perl verfügt über ebenso nützliche Startup-Variablen:

- `PERL5LIB`: stellt Bibliotheksverzeichnisse voran.
- `PERL5OPT`: injiziert Optionen, als stünden sie in jeder `perl`-Befehlszeile.

Damit lassen sich **automatisches Laden von Modulen** erzwingen oder das Verhalten des Interpreters ändern, bevor das Zielskript etwas Interessantes ausführt. Perl ignoriert diese Variablen in **taint- / setuid- / setgid-Kontexten**, sie sind jedoch für normale als Root ausgeführte Wrapper, CI-Jobs, Installer und benutzerdefinierte sudoers-Regeln weiterhin sehr relevant.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
### **NODE_OPTIONS**

`NODE_OPTIONS` stellt **Node.js CLI-Flags** jedem `node`-Prozess voran, der die Umgebung erbt. Dadurch ist es nützlich gegen Wrapper, CI-Jobs, Electron-Helper und sudo-Regeln, die letztendlich Node aufrufen. Die offensiv interessantesten Flags sind normalerweise:

- `--require <file>`: lädt eine CommonJS-Datei vor dem Ziels script.
- `--import <module>`: lädt ein ES-Modul vor dem Zielskript.

Node lehnt einige gefährliche Flags in `NODE_OPTIONS` ab, aber `--require` und `--import` sind ausdrücklich erlaubt und werden **vor** den regulären Kommandozeilenargumenten verarbeitet.
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
Für remote Gadget Chains, die `NODE_OPTIONS` indirekt setzen (zum Beispiel durch Prototype Pollution zu RCE), siehe [diese andere Seite](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby bietet dieselbe Klasse von Startup-Missbrauch:

- `RUBYLIB`: Verzeichnisse dem Ruby-Ladepfad voranstellen.
- `RUBYOPT`: Kommandozeilenoptionen wie `-r` in jeden `ruby`-Aufruf einschleusen.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Die **needrestart**-Schwachstellen von 2024 haben gezeigt, dass dies nicht nur ein Lab-Trick ist: Derselbe root-eigene Helper, der für `PYTHONPATH`-Missbrauch anfällig war, konnte auch dazu gebracht werden, Ruby mit einem vom Angreifer kontrollierten `RUBYLIB` auszuführen und `enc/encdb.so` aus einem Angreiferverzeichnis zu laden.

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Einige Tools lesen nicht einfach nur einen Pfad aus der Umgebung; sie übergeben den Wert an eine **Shell**, einen **Editor** oder einen **Input-Preprocessor**. Dadurch sind die folgenden Variablen besonders interessant, wenn ein privilegierter Wrapper `git`, `man`, `less` oder ähnliche Text-Viewer ausführt:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: wählen den Pager-Befehl.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: wählen den Editor-Befehl, häufig mit Argumenten.
- `LESSOPEN`, `LESSCLOSE`: definieren Pre-/Post-Processor, die ausgeführt werden, wenn `less` eine Datei öffnet.
```bash
PAGER='sh -c "exec sh 0<&1 1>&1"' man man

cat > /tmp/lesspipe.sh <<'EOF'
#!/bin/sh
echo '[+] LESSOPEN triggered' >&2
cat "$1"
EOF
chmod +x /tmp/lesspipe.sh
LESSOPEN='|/tmp/lesspipe.sh %s' less /etc/hosts
```
Git unterstützt außerdem **env-only config injection**, ohne auf die Festplatte zuzugreifen, über `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` und `GIT_CONFIG_VALUE_<n>`:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Aus der Perspektive der post-exploitation solltest du außerdem bedenken, dass geerbte Umgebungen oft **Zugangsdaten**, **Proxy-Einstellungen**, **Service-Tokens** oder **Cloud-Schlüssel** enthalten. Siehe [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) für die Suche nach `/proc/<PID>/environ` und `systemd`-`Environment=`.

### PS1

Ändere das Aussehen deines Prompts.

[**Dies ist ein Beispiel**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Dies ist ein Beispiel](<../images/image (897).png>)

Regulärer Benutzer:

![PERL5OPT & PERL5LIB - PS1: Ein, zwei und drei Jobs im Hintergrund](<../images/image (740).png>)

Ein, zwei und drei Jobs im Hintergrund:

![PERL5OPT & PERL5LIB - PS1: Ein, zwei und drei Jobs im Hintergrund](<../images/image (145).png>)

Ein Job im Hintergrund, einer angehalten, und der letzte Befehl wurde nicht korrekt beendet:

![PERL5OPT & PERL5LIB - PS1: Ein Job im Hintergrund, einer angehalten, und der letzte Befehl wurde nicht korrekt beendet](<../images/image (715).png>)

## Referenzen

- [GNU Bash Manual - Bash-Startdateien](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [Qualys - LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [Node.js CLI-Dokumentation - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)

{{#include ../../banners/hacktricks-training.md}}
