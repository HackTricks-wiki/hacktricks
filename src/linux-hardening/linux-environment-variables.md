# Linux-Umgebungsvariablen

{{#include ../banners/hacktricks-training.md}}

## Globale Variablen

Die globalen Variablen **werden** von **Kindprozessen** geerbt.

Du kannst eine globale Variable für deine aktuelle Sitzung erstellen, indem du:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Diese Variable wird für Ihre aktuellen Sessions und deren Kindprozesse zugänglich sein.

Sie können eine Variable **entfernen** mit:
```bash
unset MYGLOBAL
```
## Lokale Variablen

Die **lokalen Variablen** können nur von der **aktuellen Shell/Script** **zugegriffen** werden.
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
Wenn du in geerbten Umgebungen nach **credentials** oder einer **interessanten service configuration** suchst, prüfe auch [Linux Post Exploitation](linux-post-exploitation/README.md).

## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – das von **X** verwendete display. Diese Variable ist normalerweise auf **:0.0** gesetzt, was das erste display auf dem aktuellen Computer bedeutet.
- **EDITOR** – der bevorzugte Texteditor des Benutzers.
- **HISTFILESIZE** – die maximale Anzahl von Zeilen, die in der history file enthalten sind.
- **HISTSIZE** – Anzahl der Zeilen, die der history file hinzugefügt werden, wenn der Benutzer seine session beendet
- **HOME** – dein home directory.
- **HOSTNAME** – der hostname des Computers.
- **LANG** – deine aktuelle Sprache.
- **MAIL** – der Speicherort des mail spool des Benutzers. Üblicherweise **/var/spool/mail/USER**.
- **MANPATH** – die Liste der Verzeichnisse, in denen nach manual pages gesucht wird.
- **OSTYPE** – der Typ des Betriebssystems.
- **PS1** – der standardmäßige prompt in bash.
- **PATH** – speichert den Pfad aller Verzeichnisse, die binary files enthalten, die du ausführen willst, indem du nur den Namen der Datei angibst und nicht einen relativen oder absoluten Pfad.
- **PWD** – das aktuelle working directory.
- **SHELL** – der Pfad zur aktuellen command shell (zum Beispiel, **/bin/bash**).
- **TERM** – der aktuelle terminal type (zum Beispiel, **xterm**).
- **TZ** – deine time zone.
- **USER** – dein aktueller username.

## Interesting variables for hacking

Nicht jede Variable ist gleich nützlich. Aus offensiver Sicht solltest du Variablen priorisieren, die **search paths**, **startup files**, **dynamic linker behavior** oder **audit/logging** ändern.

### **HISTFILESIZE**

Ändere den **Wert dieser Variable auf 0**, damit beim **Beenden deiner session** die **history file** (\~/.bash_history) auf **0 Zeilen** **truncated** wird.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Ändere den **Wert dieser Variable auf 0**, damit Befehle **nicht im In-Memory-Verlauf gespeichert** werden und nicht zurück in die **History-Datei** (\~/.bash_history) geschrieben werden.
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Wenn der **Wert dieser Variable auf `ignorespace` oder `ignoreboth` gesetzt ist**, wird jeder Befehl, dem ein zusätzliches Leerzeichen vorangestellt ist, nicht im Verlauf gespeichert.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Zeige die **History-Datei** auf **`/dev/null`** oder entferne sie vollständig. Das ist normalerweise zuverlässiger, als nur die History-Größe zu ändern.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Die Prozesse verwenden den hier deklarierten **proxy**, um sich über **http oder https** mit dem Internet zu verbinden.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: Standard-Proxy für Tools/Protokolle, die es unterstützen.
- `no_proxy`: Bypass-Liste (Hosts/Domains/CIDRs), die direkt verbinden soll.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Sowohl Klein- als auch Großschreibungsvarianten können je nach Tool verwendet werden (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Die Prozesse vertrauen den in **diesen env variables** angegebenen Zertifikaten. Das ist nützlich, um Tools wie **`curl`**, **`git`**, Python-HTTP-Clients oder Paketmanager dazu zu bringen, einer vom Angreifer kontrollierten CA zu vertrauen (zum Beispiel, um einen Interception Proxy legitim erscheinen zu lassen).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Wenn ein privilegierter Wrapper/Script Befehle **ohne absolute Pfade** ausführt, gewinnt das **erste von Angreifern kontrollierte Verzeichnis** in `PATH`. Dies ist die Grundlage vieler **PATH hijacks** in `sudo`, cron jobs, Shell-Wrappers und benutzerdefinierten SUID-Helpers. Suche nach `env_keep+=PATH`, schwachem `secure_path` oder Wrappers, die `tar`, `service`, `cp`, `python` usw. per Namen aufrufen.
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
Für vollständige Privilege-Escalation-Ketten, die `PATH` missbrauchen, siehe [Linux Privilege Escalation](privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` ist nicht nur ein Verweis auf ein Verzeichnis: Viele Tools laden automatisch **dotfiles**, **plugins** und **per-user configuration** aus `$HOME` oder `$XDG_CONFIG_HOME`. Wenn ein privilegierter Workflow diese Werte beibehält, kann **config injection** einfacher sein als Binary Hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Interessante Ziele sind `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` und toolspezifische Dateien wie `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Diese Variablen beeinflussen den **dynamic linker**:

- `LD_PRELOAD`: erzwingt, dass zusätzliche shared objects zuerst geladen werden.
- `LD_LIBRARY_PATH`: stellt Bibliotheks-Suchverzeichnisse an den Anfang.
- `LD_AUDIT`: lädt Auditor-Bibliotheken, die das Laden von Bibliotheken und die Symbolauflösung beobachten.

Sie sind äußerst wertvoll für **hooking**, **instrumentation** und **privilege escalation**, wenn ein privilegierter Befehl sie beibehält. Im **secure-execution**-Modus (`AT_SECURE`, z. B. setuid/setgid/capabilities) entfernt oder beschränkt der loader viele dieser Variablen. Parser-Bugs in dieser frühen loader-Phase sind jedoch weiterhin sehr wirkungsvoll, weil sie **vor** dem Zielprogramm ausgeführt werden.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` ändert das frühe glibc-Verhalten (zum Beispiel allocator tunables) und ist in exploit labs sehr nützlich. Es ist auch aus Sicherheitssicht wichtig, weil der **dynamic loader es sehr früh parst**. Der **Looney Tunables**-Bug von 2023 war eine gute Erinnerung daran, dass eine einzelne environment variable, die im loader geparst wird, zu einem **local privilege-escalation primitive** gegen SUID-Programme werden kann.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Wenn **Bash** **nicht-interaktiv** gestartet wird, prüft es `BASH_ENV` und sourced diese Datei, bevor das Zielskript ausgeführt wird. Wenn Bash als `sh` aufgerufen wird oder im POSIX-ähnlichen interaktiven Modus läuft, kann auch `ENV` berücksichtigt werden. Das ist ein klassischer Weg, eine Shell-Wrapper in Codeausführung zu verwandeln, wenn die Umgebung vom Angreifer kontrolliert wird.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash selbst deaktiviert diese Startdateien, wenn sich die **real/effective IDs unterscheiden**, es sei denn, `-p` wird verwendet, daher hängt das genaue Verhalten davon ab, wie der Wrapper die Shell aufruft.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Diese Variablen ändern, wie Python startet:

- `PYTHONPATH`: fügt Import-Suchpfade voran.
- `PYTHONHOME`: verschiebt den Standardbibliotheks-Baum.
- `PYTHONSTARTUP`: führt eine Datei vor der interaktiven Eingabeaufforderung aus.
- `PYTHONINSPECT=1`: wechselt nach dem Ende eines Skripts in den interaktiven Modus.

Sie sind nützlich gegen Wartungsskripte, Debugger, Shells und Wrapper, die Python mit einer kontrollierbaren Umgebung aufrufen. `python -E` und `python -I` ignorieren alle `PYTHON*`-Variablen.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl hat ebenso nützliche Startvariablen:

- `PERL5LIB`: fügt Library-Verzeichnisse am Anfang hinzu.
- `PERL5OPT`: injiziert Switches, als ob sie auf jeder `perl`-Commandline stünden.

Das kann **automatic module loading** erzwingen oder das Interpreter-Verhalten ändern, bevor das Target-Skript etwas Interessantes macht. Perl ignoriert diese Variablen in **taint / setuid / setgid**-Kontexten, aber sie sind trotzdem sehr relevant für normale root-run Wrapper, CI-Jobs, Installer und benutzerdefinierte sudoers-Regeln.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
Die gleiche Idee erscheint auch in anderen runtimes (`RUBYOPT`, `NODE_OPTIONS`, usw.): immer wenn ein Interpreter durch einen privilegierten Wrapper gestartet wird, suche nach env vars, die **module loading** oder **startup behavior** verändern.

Aus einer post-exploitation Perspektive solltest du auch daran denken, dass geerbte Umgebungen oft **credentials**, **proxy settings**, **service tokens** oder **cloud keys** enthalten. Siehe [Linux Post Exploitation](linux-post-exploitation/README.md) für `/proc/<PID>/environ` und `systemd` `Environment=` hunting.

### PS1

Ändere, wie dein prompt aussieht.

[**Dies ist ein Beispiel**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../images/image (897).png>)

Normaler Benutzer:

![](<../images/image (740).png>)

Ein, zwei und drei backgrounded jobs:

![](<../images/image (145).png>)

Ein background job, ein gestopptes und der letzte Befehl wurde nicht korrekt beendet:

![](<../images/image (715).png>)

## References

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../banners/hacktricks-training.md}}
