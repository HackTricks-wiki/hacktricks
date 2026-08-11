# Linux-Umgebungsvariablen

{{#include ../../banners/hacktricks-training.md}}

## Globale Variablen

Die globalen Variablen **werden** von **Kindprozessen** geerbt.

Du kannst eine globale Variable für deine aktuelle Sitzung erstellen mit:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Diese Variable ist in deinen aktuellen Sessions und deren untergeordneten Prozessen verfügbar.

Du kannst eine Variable **entfernen**, indem du Folgendes ausführst:
```bash
unset MYGLOBAL
```
## Lokale Variablen

Auf die **lokalen Variablen** kann nur von der **aktuellen Shell bzw. dem aktuellen Script** aus **zugegriffen** werden.
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
Die Inhalte von `/proc/*/environ` sind durch **NUL** getrennt, daher sind diese Varianten meist leichter zu lesen:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Wenn du nach **credentials** oder **interessanter Service-Konfiguration** in geerbten Umgebungen suchst, prüfe auch [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Häufige Variablen

Quelle: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – das von **X** verwendete Display. Diese Variable ist normalerweise auf **:0.0** gesetzt, was das erste Display auf dem aktuellen Computer bedeutet.
- **EDITOR** – der vom Benutzer bevorzugte Texteditor.
- **HISTFILESIZE** – die maximale Anzahl von Zeilen, die in der history file enthalten sein dürfen.
- **HISTSIZE** – die Anzahl der Zeilen, die der history file hinzugefügt werden, wenn der Benutzer seine Sitzung beendet.
- **HOME** – dein Home-Verzeichnis.
- **HOSTNAME** – der Hostname des Computers.
- **LANG** – deine aktuelle Sprache.
- **MAIL** – der Speicherort der Mail-Spool des Benutzers. Normalerweise **/var/spool/mail/USER**.
- **MANPATH** – die Liste der Verzeichnisse, in denen nach Handbuchseiten gesucht wird.
- **OSTYPE** – der Typ des Betriebssystems.
- **PS1** – der Standard-Prompt in bash.
- **PATH** – speichert den Pfad aller Verzeichnisse, die Binärdateien enthalten, die du ausführen möchtest, indem du einfach den Dateinamen und nicht den relativen oder absoluten Pfad angibst.
- **PWD** – das aktuelle Arbeitsverzeichnis.
- **SHELL** – der Pfad zur aktuellen Command Shell (zum Beispiel **/bin/bash**).
- **TERM** – der aktuelle Terminaltyp (zum Beispiel **xterm**).
- **TZ** – deine Zeitzone.
- **USER** – dein aktueller Benutzername.

## Interessante Variablen für hacking

Nicht jede Variable ist gleichermaßen nützlich. Aus offensiver Sicht solltest du Variablen priorisieren, die **Suchpfade**, **Startup-Dateien**, das **Verhalten des Dynamic Linkers** oder **Audit/Logging** ändern.

### **HISTFILESIZE**

Ändere den **Wert dieser Variable auf 0**, damit beim **Beenden deiner Sitzung** die **history file** (\~/.bash_history) auf **0 Zeilen gekürzt** wird.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Ändere den **Wert dieser Variable auf 0**, damit Befehle **nicht im Verlauf im Arbeitsspeicher behalten** und nicht in die **Verlaufsdatei** (\~/.bash_history) geschrieben werden.
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

Setze die **Verlaufsdatei** auf **`/dev/null`** oder hebe die Variable vollständig auf. Das ist in der Regel zuverlässiger, als nur die Verlaufsgröße zu ändern.
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

- `all_proxy`: Standard-Proxy für Tools/Protokolle, die diese Variable berücksichtigen.
- `no_proxy`: Umgehungsliste (Hosts/Domains/CIDRs), die direkt verbunden werden sollen.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Sowohl Klein- als auch Großbuchstaben können je nach Tool verwendet werden (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Die Prozesse vertrauen den in **diesen Umgebungsvariablen** angegebenen Zertifikaten. Dies ist nützlich, damit Tools wie **`curl`**, **`git`**, Python-HTTP-Clients oder Paketmanager einer vom Angreifer kontrollierten CA vertrauen (beispielsweise, damit ein Interception-Proxy legitim aussieht).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Wenn ein privilegierter Wrapper/Script Befehle **ohne absolute Pfade** ausführt, gewinnt das **erste vom Angreifer kontrollierte Verzeichnis** in `PATH`. Dies ist das grundlegende Primitive hinter vielen **PATH hijacks** in `sudo`, cron jobs, Shell-Wrappern und benutzerdefinierten SUID-Helfern. Suche nach `env_keep+=PATH`, einem schwachen `secure_path` oder Wrappern, die `tar`, `service`, `cp`, `python` usw. anhand ihres Namens aufrufen.
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
Für vollständige Privilege-Escalation-Ketten, die `PATH` missbrauchen, siehe [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` ist nicht nur ein Verzeichnispfad: Viele Tools laden automatisch **Dotfiles**, **Plugins** und **benutzerspezifische Konfigurationen** aus `$HOME` oder `$XDG_CONFIG_HOME`. Wenn ein privilegierter Workflow diese Werte beibehält, kann **Config Injection** einfacher sein als Binary Hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Interessante Ziele umfassen `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` sowie toolspezifische Dateien wie `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Diese Variablen beeinflussen den **dynamic linker**:

- `LD_PRELOAD`: erzwingt, dass zusätzliche shared objects zuerst geladen werden.
- `LD_LIBRARY_PATH`: stellt Bibliothekssuchverzeichnisse voran.
- `LD_AUDIT`: lädt auditor libraries, die das Laden von Bibliotheken und die Symbolauflösung beobachten.

Sie sind äußerst wertvoll für **hooking**, **instrumentation** und **privilege escalation**, wenn ein privilegierter Befehl sie beibehält. Im **secure-execution**-Modus (`AT_SECURE`, z. B. setuid/setgid/capabilities) entfernt oder beschränkt der Loader viele dieser Variablen. Parser-Bugs in dieser frühen Loader-Phase sind jedoch weiterhin äußerst wirkungsvoll, da sie **vor** dem Zielprogramm ausgeführt werden.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` ändert das frühe Verhalten von glibc (zum Beispiel die Einstellungen des Allocators) und ist in exploit labs sehr praktisch. Aus Sicherheitsperspektive ist die Variable ebenfalls relevant, da der **dynamische Loader sie sehr früh analysiert**. Der **Looney-Tunables**-Bug aus dem Jahr 2023 erinnerte eindrücklich daran, dass eine einzelne, im Loader analysierte Umgebungsvariable zu einem **Primitive für lokale Rechteausweitung** gegen SUID-Programme werden kann.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Wenn **Bash** **nicht interaktiv** gestartet wird, prüft es `BASH_ENV` und liest diese Datei ein, bevor das Ziels script ausgeführt wird. Wenn Bash als `sh` oder im interaktiven POSIX-Stil aufgerufen wird, kann auch `ENV` berücksichtigt werden. Dies ist eine klassische Möglichkeit, einen Shell-Wrapper in Codeausführung zu verwandeln, wenn die Umgebung vom Angreifer kontrolliert wird.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash ignoriert diese Startup-Dateien, wenn die **realen/effektiven IDs unterschiedlich sind**; `-p` bewahrt die effektive ID, aktiviert diese Startup-Dateien jedoch nicht, sodass das genaue Verhalten davon abhängt, wie der Wrapper die Shell startet. Seien Sie vorsichtig mit privilegierten Wrappern, die **vor** dem Start von Bash `setuid()`/`setgid()` aufrufen: Sobald die IDs wieder übereinstimmen, vertraut Bash möglicherweise `BASH_ENV`, `ENV` und dem damit verbundenen Shell-Zustand, die andernfalls ignoriert würden.<sup>[[1]](#references)</sup>

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Diese Variablen ändern, wie Python startet:

- `PYTHONPATH`: Import-Suchpfade voranstellen.
- `PYTHONHOME`: Den Verzeichnisbaum der Standardbibliothek verschieben.
- `PYTHONSTARTUP`: Eine Datei vor der interaktiven Eingabeaufforderung ausführen.
- `PYTHONINSPECT=1`: Nach Abschluss eines Skripts in den interaktiven Modus wechseln.

Sie sind nützlich gegen Wartungsskripte, Debugger, Shells und Wrapper, die Python mit einer kontrollierbaren Umgebung aufrufen. `python -E` und `python -I` ignorieren alle `PYTHON*`-Variablen.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
Ein aktuelles Beispiel aus der Praxis war die LPE in **needrestart** auf Ubuntu-/Debian-Systemen im Jahr 2024: Der Scanner mit Root-Rechten kopierte den `PYTHONPATH` eines nicht privilegierten Prozesses aus `/proc/<PID>/environ` und führte anschließend Python aus. Der veröffentlichte Exploit platzierte `importlib/__init__.so` im vom Angreifer kontrollierten Pfad, sodass Python während seiner eigenen Initialisierung den Code des Angreifers ausführte, noch bevor das fest im Helper codierte Script überhaupt relevant wurde.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl verfügt über ähnlich nützliche Startup-Variablen:

- `PERL5LIB`: stellt Bibliotheksverzeichnisse voran.
- `PERL5OPT`: schleust Switches ein, als stünden sie in jeder `perl`-Befehlszeile.

Dadurch kann **automatisches Laden von Modulen** erzwungen oder das Verhalten des Interpreters geändert werden, bevor das Ziel-Script etwas Interessantes tut. Perl ignoriert diese Variablen in **taint / setuid / setgid**-Kontexten, aber sie sind für normale Wrapper mit Root-Rechten, CI-Jobs, Installer und benutzerdefinierte sudoers-Regeln weiterhin sehr relevant.
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

`NODE_OPTIONS` stellt jedem `node`-Prozess, der die Umgebung erbt, **Node.js CLI flags** voran. Dadurch ist es nützlich gegen Wrapper, CI-Jobs, Electron-Hilfsprozesse und sudo-Regeln, die letztendlich Node aufrufen. Die offensiv interessantesten flags sind normalerweise:

- `--require <file>`: lädt eine CommonJS-Datei vor dem Zielskript.
- `--import <module>`: lädt ein ES-Modul vor dem Zielskript.

Node lehnt einige gefährliche flags in `NODE_OPTIONS` ab, aber `--require` und `--import` sind ausdrücklich erlaubt und werden **vor** den regulären Befehlszeilenargumenten verarbeitet.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
Für entfernte Gadget Chains, die `NODE_OPTIONS` indirekt setzen (zum Beispiel durch Prototype Pollution zu RCE), siehe [diese andere Seite](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby bietet dieselbe Klasse von Startup-Missbrauch:

- `RUBYLIB`: Verzeichnisse dem Load Path von Ruby voranstellen.
- `RUBYOPT`: Kommandozeilenoptionen wie `-r` in jede `ruby`-Invocation einschleusen.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Die **needrestart**-Schwachstellen von 2024 zeigten, dass dies nicht nur ein Lab-Trick ist: Derselbe root-eigene Helper, der für **PYTHONPATH**-Missbrauch anfällig war, konnte auch dazu gebracht werden, Ruby mit einer vom Angreifer kontrollierten `RUBYLIB` auszuführen und `enc/encdb.so` aus einem vom Angreifer kontrollierten Verzeichnis zu laden.<sup>[[3]](#references)</sup>

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Einige Tools lesen nicht einfach nur einen Pfad aus der Umgebung; sie übergeben den Wert an eine **Shell**, einen **Editor** oder einen **Eingabevorprozessor**. Dadurch sind die folgenden Variablen besonders interessant, wenn ein privilegierter Wrapper `git`, `man`, `less` oder ähnliche Textbetrachter ausführt:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: wählen den Pager-Befehl aus.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: wählen den Editor-Befehl aus, häufig zusammen mit Argumenten.
- `LESSOPEN`, `LESSCLOSE`: definieren Vor-/Nachprozessoren, die ausgeführt werden, wenn `less` eine Datei öffnet.
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
Git unterstützt außerdem die **ausschließliche Injektion von Konfigurationen über Umgebungsvariablen**, ohne den Datenträger zu verändern, über `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` und `GIT_CONFIG_VALUE_<n>`:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Aus einer post-exploitation-Perspektive solltest du außerdem bedenken, dass geerbte Umgebungen häufig **Anmeldedaten**, **Proxy-Einstellungen**, **Service-Tokens** oder **Cloud-Schlüssel** enthalten. Sieh dir [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) für die Suche nach `/proc/<PID>/environ` und `systemd`-`Environment=` an.

### PS1

Ändere das Aussehen deines Prompts.

[**Dies ist ein Beispiel**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Dies ist ein Beispiel](<../images/image (897).png>)

Normaler Benutzer:

![PERL5OPT & PERL5LIB - PS1: Ein, zwei und drei Jobs im Hintergrund](<../images/image (740).png>)

Ein, zwei und drei Jobs im Hintergrund:

![PERL5OPT & PERL5LIB - PS1: Ein, zwei und drei Jobs im Hintergrund](<../images/image (145).png>)

Ein Job im Hintergrund, einer angehalten, und der letzte Befehl wurde nicht korrekt beendet:

![PERL5OPT & PERL5LIB - PS1: Ein Job im Hintergrund, einer angehalten, und der letzte Befehl wurde nicht korrekt beendet](<../images/image (715).png>)

## References

- [1] [GNU Bash Manual - Bash-Startdateien](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js CLI-Dokumentation - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Allgemeine Umgebungsvariablen - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Lokale Rechteausweitung in der glibc's ld.so - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
{{#include ../../banners/hacktricks-training.md}}
