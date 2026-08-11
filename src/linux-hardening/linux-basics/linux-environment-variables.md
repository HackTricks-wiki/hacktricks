# Linux-Umgebungsvariablen

## Globale Variablen

Die globalen Variablen **werden** von **Kindprozessen** geerbt.

Du kannst eine globale Variable für deine aktuelle Sitzung erstellen mit:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Diese Variable ist in deinen aktuellen Sitzungen und deren Kindprozessen verfügbar.

Du kannst eine Variable mit folgendem Befehl **entfernen**:
```bash
unset MYGLOBAL
```
## Lokale Variablen

Auf die **lokalen Variablen** kann nur von der **aktuellen Shell/dem aktuellen Skript** zugegriffen werden.
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
Die Inhalte von `/proc/*/environ` sind durch **NUL-Zeichen getrennt**, daher sind diese Varianten in der Regel leichter lesbar:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Wenn du innerhalb geerbter Umgebungen nach **credentials** oder einer **interessanten Service-Konfiguration** suchst, prüfe auch [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Häufige Variablen

Aus: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – das von **X** verwendete Display. Diese Variable wird normalerweise auf **:0.0** gesetzt, was das erste Display auf dem aktuellen Computer bedeutet.
- **EDITOR** – der vom Benutzer bevorzugte Texteditor.
- **HISTFILESIZE** – die maximale Anzahl von Zeilen, die die History-Datei enthalten darf.
- **HISTSIZE** – die Anzahl der Zeilen, die der History-Datei hinzugefügt werden, wenn der Benutzer seine Sitzung beendet.
- **HOME** – dein Home-Verzeichnis.
- **HOSTNAME** – der Hostname des Computers.
- **LANG** – deine aktuelle Sprache.
- **MAIL** – der Speicherort des Mail-Spools des Benutzers. Normalerweise **/var/spool/mail/USER**.
- **MANPATH** – die Liste der Verzeichnisse, die nach Manual-Seiten durchsucht werden.
- **OSTYPE** – der Typ des Betriebssystems.
- **PS1** – der Standard-Prompt in bash.
- **PATH** – speichert den Pfad aller Verzeichnisse, die Binärdateien enthalten, die du ausführen möchtest, indem du nur den Dateinamen und nicht den relativen oder absoluten Pfad angibst.
- **PWD** – das aktuelle Arbeitsverzeichnis.
- **SHELL** – der Pfad zur aktuellen Command Shell (zum Beispiel **/bin/bash**).
- **TERM** – der aktuelle Terminaltyp (zum Beispiel **xterm**).
- **TZ** – deine Zeitzone.
- **USER** – dein aktueller Benutzername.

## Interessante Variablen für hacking

Nicht jede Variable ist gleichermaßen nützlich. Aus offensiver Perspektive solltest du Variablen priorisieren, die **Suchpfade**, **Startup-Dateien**, das **Verhalten des Dynamic Linkers** oder **Auditing/Logging** ändern.

### **HISTFILESIZE**

Ändere den **Wert dieser Variable auf 0**, damit die **History-Datei** (\~/.bash_history) beim **Beenden deiner Sitzung** auf **0 Zeilen gekürzt** wird.
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

Setze die **history file** auf **`/dev/null`** oder hebe ihre Definition vollständig auf. Dies ist normalerweise zuverlässiger, als nur die history-Größe zu ändern.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Die Prozesse verwenden den hier angegebenen **proxy**, um über **http oder https** eine Verbindung zum Internet herzustellen.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: Standard-Proxy für Tools/Protokolle, die diese Variable unterstützen.
- `no_proxy`: Umgehungsliste (Hosts/Domains/CIDRs), die direkt verbunden werden sollen.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Sowohl Klein- als auch Großschreibungsvarianten können je nach Tool verwendet werden (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Die Prozesse vertrauen den in **diesen Umgebungsvariablen** angegebenen Zertifikaten. Dies ist nützlich, damit Tools wie **`curl`**, **`git`**, Python-HTTP-Clients oder Paketmanager einer vom Angreifer kontrollierten CA vertrauen (beispielsweise damit ein Interception-Proxy legitim aussieht).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Wenn ein privilegierter Wrapper/Script Befehle **ohne absolute Pfade** ausführt, gewinnt das **erste vom Angreifer kontrollierte Verzeichnis** in `PATH`. Dies ist die Grundlage vieler **PATH hijacks** in `sudo`, cron jobs, Shell-Wrappern und benutzerdefinierten SUID-Helfern. Suche nach `env_keep+=PATH`, einem schwachen `secure_path` oder Wrappern, die `tar`, `service`, `cp`, `python` usw. namentlich aufrufen.
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

`HOME` ist nicht nur ein Verzeichnisverweis: Viele Tools laden automatisch **dotfiles**, **Plugins** und **benutzerspezifische Konfigurationen** aus `$HOME` oder `$XDG_CONFIG_HOME`. Wenn ein privilegierter Workflow diese Werte beibehält, kann **config injection** einfacher sein als **binary hijacking**.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Interessante Ziele umfassen `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` sowie toolspezifische Dateien wie `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Diese Variablen beeinflussen den **dynamischen Linker**:

- `LD_PRELOAD`: erzwingt, dass zusätzliche Shared Objects zuerst geladen werden.
- `LD_LIBRARY_PATH`: setzt Bibliothekssuchverzeichnisse voran.
- `LD_AUDIT`: lädt Auditor-Bibliotheken, die das Laden von Bibliotheken und die Symbolauflösung beobachten.

Sie sind äußerst wertvoll für **hooking**, **instrumentation** und **privilege escalation**, wenn ein privilegierter Befehl sie beibehält. Im **secure-execution**-Modus (`AT_SECURE`, z. B. bei setuid/setgid/Capabilities) entfernt oder beschränkt der Loader viele dieser Variablen. Parser-Bugs in dieser frühen Loader-Phase sind jedoch weiterhin besonders kritisch, da sie **vor** dem Zielprogramm ausgeführt werden.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` verändert das frühe Verhalten von glibc (zum Beispiel die Tunables des Allocators) und ist in Exploit-Labs sehr nützlich. Aus Sicherheitsperspektive ist es ebenfalls relevant, da der **dynamische Loader die Variable sehr früh parst**. Der **Looney-Tunables**-Bug von 2023 war eine gute Erinnerung daran, dass eine einzelne, im Loader geparste Umgebungsvariable zu einem **Primitive zur lokalen Rechteausweitung** gegen SUID-Programme werden kann.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Wenn **Bash** **nicht-interaktiv** gestartet wird, prüft es `BASH_ENV` und führt diese Datei mittels `source` aus, bevor das Zielskript ausgeführt wird. Wenn Bash als `sh` oder im interaktiven POSIX-Modus aufgerufen wird, kann zusätzlich `ENV` berücksichtigt werden. Dies ist eine klassische Möglichkeit, einen Shell-Wrapper in code execution zu verwandeln, wenn die Umgebung vom Angreifer kontrolliert wird.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash ignoriert diese Startdateien, wenn die **realen/effektiven IDs unterschiedlich sind**; `-p` bewahrt die effektive ID, aktiviert diese Startdateien jedoch nicht, daher hängt das genaue Verhalten davon ab, wie der Wrapper die Shell startet. Seien Sie vorsichtig mit privilegierten Wrappern, die **vor** dem Start von Bash `setuid()`/`setgid()` aufrufen: Sobald die IDs wieder übereinstimmen, vertraut Bash möglicherweise `BASH_ENV`, `ENV` und dem zugehörigen Shell-Zustand, die andernfalls ignoriert würden.<sup>[[1]](#references)</sup>

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Diese Variablen verändern, wie Python startet:

- `PYTHONPATH`: Import-Suchpfade voranstellen.
- `PYTHONHOME`: Den Verzeichnisbaum der Standardbibliothek verlagern.
- `PYTHONSTARTUP`: Eine Datei vor der interaktiven Eingabeaufforderung ausführen.
- `PYTHONINSPECT=1`: Nach Abschluss eines Skripts in den interaktiven Modus wechseln.

Sie sind nützlich gegen Wartungsskripte, Debugger, Shells und Wrapper, die Python mit einer kontrollierbaren Umgebung aufrufen. `python -E` und `python -I` ignorieren alle `PYTHON*`-Variablen.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
Ein aktuelles Beispiel aus der Praxis war die LPE in **needrestart** aus dem Jahr 2024 auf Ubuntu-/Debian-Systemen: Der Scanner mit Root-Berechtigungen übernahm den `PYTHONPATH` eines unprivilegierten Prozesses aus `/proc/<PID>/environ` und führte anschließend Python aus. Der veröffentlichte Exploit platzierte `importlib/__init__.so` im vom Angreifer kontrollierten Pfad, sodass Python während seiner eigenen Initialisierung Angreifercode ausführte, noch bevor das fest codierte Skript des Helfers überhaupt relevant wurde.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl verfügt über ähnlich nützliche Startup-Variablen:

- `PERL5LIB`: Bibliotheksverzeichnisse voranstellen.
- `PERL5OPT`: Schalter einschleusen, als stünden sie in jeder `perl`-Befehlszeile.

Dadurch kann **automatic module loading** erzwungen oder das Verhalten des Interpreters geändert werden, bevor das Zielskript etwas Interessantes ausführt. Perl ignoriert diese Variablen in **taint / setuid / setgid**-Kontexten, dennoch sind sie für normale als Root ausgeführte Wrapper, CI-Jobs, Installer und benutzerdefinierte sudoers-Regeln weiterhin sehr relevant.
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

`NODE_OPTIONS` stellt jedem `node`-Prozess, der die Umgebung erbt, **Node.js CLI flags** voran. Dadurch ist es nützlich gegen Wrapper, CI-Jobs, Electron-Hilfsprozesse und sudo-Regeln, die letztendlich Node aufrufen. Die offensiv interessantesten Flags sind normalerweise:

- `--require <file>`: lädt eine CommonJS-Datei vor dem Zielskript vor.
- `--import <module>`: lädt ein ES-Modul vor dem Zielskript vor.

Node lehnt einige gefährliche Flags in `NODE_OPTIONS` ab, aber `--require` und `--import` sind ausdrücklich erlaubt und werden **vor** den regulären Befehlszeilenargumenten verarbeitet.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
Bei remote gadget chains, die `NODE_OPTIONS` indirekt setzen (zum Beispiel durch prototype-pollution bis hin zu RCE), siehe [diese andere Seite](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby bietet dieselbe Klasse von Missbrauchsmöglichkeiten beim Start:

- `RUBYLIB`: Verzeichnisse dem Ruby-Ladepfad voranstellen.
- `RUBYOPT`: Befehlszeilenoptionen wie `-r` in jede `ruby`-Invocation einschleusen.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Die **needrestart**-Schwachstellen von 2024 zeigten, dass dies nicht nur ein Lab-Trick ist: Derselbe Hilfsprozess mit Root-Rechten, der für `PYTHONPATH`-Missbrauch anfällig war, konnte auch dazu gebracht werden, Ruby mit einem vom Angreifer kontrollierten `RUBYLIB` auszuführen und `enc/encdb.so` aus einem vom Angreifer kontrollierten Verzeichnis zu laden.<sup>[[3]](#references)</sup>

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Einige Tools lesen nicht einfach nur einen Pfad aus der Umgebung; sie übergeben den Wert an eine **Shell**, einen **Editor** oder einen **Input-Preprocessor**. Dadurch sind die folgenden Variablen besonders interessant, wenn ein privilegierter Wrapper `git`, `man`, `less` oder ähnliche Text-Viewer ausführt:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: wählen den Pager-Befehl aus.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: wählen den Editor-Befehl aus, häufig einschließlich Argumenten.
- `LESSOPEN`, `LESSCLOSE`: definieren Prä-/Postprozessoren, die ausgeführt werden, wenn `less` eine Datei öffnet.
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
Git unterstützt außerdem **env-only config injection**, ohne die Festplatte zu berühren, über `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` und `GIT_CONFIG_VALUE_<n>`:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Aus der Perspektive der Post-Exploitation solltest du außerdem bedenken, dass geerbte Umgebungen häufig **Credentials**, **Proxy-Einstellungen**, **Service-Tokens** oder **Cloud-Keys** enthalten. Sieh dir [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) für die Suche nach `/proc/<PID>/environ` und `systemd`-`Environment=` an.

### PS1

Ändere das Aussehen deines Prompts.

[**Dies ist ein Beispiel**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Dies ist ein Beispiel](<../images/image (897).png>)

Normaler Benutzer:

![PERL5OPT & PERL5LIB - PS1: Ein, zwei und drei Jobs im Hintergrund](<../images/image (740).png>)

Ein, zwei und drei Jobs im Hintergrund:

![PERL5OPT & PERL5LIB - PS1: Ein, zwei und drei Jobs im Hintergrund](<../images/image (145).png>)

Ein Job im Hintergrund, einer angehalten und der letzte Befehl wurde nicht korrekt beendet:

![PERL5OPT & PERL5LIB - PS1: Ein Job im Hintergrund, einer angehalten und der letzte Befehl wurde nicht korrekt beendet](<../images/image (715).png>)

## References

- [1] [GNU Bash-Handbuch - Bash-Startdateien](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js-CLI-Dokumentation - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Häufige Umgebungsvariablen - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Lokale Rechteausweitung in der glibc ld.so - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
{{#include ../../banners/hacktricks-training.md}}
