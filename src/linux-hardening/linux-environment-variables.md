# Linux-Umgebungsvariablen

{{#include ../banners/hacktricks-training.md}}

## Globale Variablen

Die globalen Variablen **werden** von **Kindprozessen** geerbt.

Du kannst für deine aktuelle Sitzung eine globale Variable erstellen, indem du:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Diese Variable ist für deine aktuellen Sessions und deren Kindprozesse zugänglich.

Du kannst eine Variable **entfernen**, indem du:
```bash
unset MYGLOBAL
```
## Lokale Variablen

Die **lokalen Variablen** können nur von der **aktuellen Shell/dem aktuellen Skript** **zugegriffen** werden.
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
Wenn du in übernommenen Umgebungen nach **credentials** oder **interessanter service configuration** suchst, sieh dir auch [Linux Post Exploitation](linux-post-exploitation/README.md) an.

## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – das Display, das von **X** verwendet wird. Diese Variable ist normalerweise auf **:0.0** gesetzt, was das erste Display auf dem aktuellen Computer bedeutet.
- **EDITOR** – der bevorzugte Texteditor des Benutzers.
- **HISTFILESIZE** – die maximale Anzahl von Zeilen, die in der history file enthalten sind.
- **HISTSIZE** – Anzahl der Zeilen, die der history file hinzugefügt werden, wenn der Benutzer seine Sitzung beendet
- **HOME** – dein Home-Verzeichnis.
- **HOSTNAME** – der hostname des Computers.
- **LANG** – deine aktuelle Sprache.
- **MAIL** – der Speicherort des mail spool des Benutzers. Normalerweise **/var/spool/mail/USER**.
- **MANPATH** – die Liste der Verzeichnisse, die nach manual pages durchsucht werden.
- **OSTYPE** – der Typ des Betriebssystems.
- **PS1** – der Standard-Prompt in bash.
- **PATH** – speichert den Pfad aller Verzeichnisse, die binary files enthalten, die du ausführen möchtest, indem du nur den Namen der Datei angibst und nicht einen relativen oder absoluten Pfad.
- **PWD** – das aktuelle working directory.
- **SHELL** – der Pfad zur aktuellen command shell (zum Beispiel **/bin/bash**).
- **TERM** – der aktuelle terminal type (zum Beispiel **xterm**).
- **TZ** – deine Zeitzone.
- **USER** – dein aktueller username.

## Interesting variables for hacking

Nicht jede Variable ist gleich nützlich. Aus offensiver Sicht solltest du Variablen priorisieren, die **search paths**, **startup files**, **dynamic linker behavior** oder **audit/logging** verändern.

### **HISTFILESIZE**

Ändere den **Wert dieser Variable auf 0**, damit, wenn du deine **Sitzung beendest**, die **history file** (\~/.bash_history) auf **0 Zeilen gekürzt** wird.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Ändere den **Wert dieser Variable auf 0**, damit Befehle **nicht im speicherinternen Verlauf behalten** werden und **nicht zurück in die Verlaufdatei** (\~/.bash_history) geschrieben werden.
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Wenn der **Wert dieser Variablen auf `ignorespace` oder `ignoreboth` gesetzt ist**, wird jeder Befehl, dem ein zusätzliches Leerzeichen vorangestellt ist, nicht im Verlauf gespeichert.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Zeige die **History-Datei** auf **`/dev/null`** oder unsetze sie vollständig. Das ist normalerweise zuverlässiger als nur die History-Größe zu ändern.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Die Prozesse verwenden den hier deklarierten **proxy**, um über **http oder https** eine Verbindung zum Internet herzustellen.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: Standard-Proxy für Tools/Protokolle, die es unterstützen.
- `no_proxy`: Bypass-Liste (Hosts/Domains/CIDRs), die direkt verbinden sollen.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Sowohl Klein- als auch Großschreibungsvarianten können je nach Tool verwendet werden (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Die Prozesse vertrauen den in **diesen Env-Variablen** angegebenen Zertifikaten. Dies ist nützlich, um Tools wie **`curl`**, **`git`**, Python-HTTP-Clients oder Paketmanager dazu zu bringen, einer vom Angreifer kontrollierten CA zu vertrauen (zum Beispiel, um einen Interception-Proxy legitim erscheinen zu lassen).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Wenn ein privilegierter Wrapper/Script Befehle **ohne absolute Pfade** ausführt, gewinnt das **erste angreifergesteuerte Verzeichnis** in `PATH`. Das ist die Primitive hinter vielen **PATH hijacks** in `sudo`, cron jobs, shell wrappers und custom SUID helpers. Achte auf `env_keep+=PATH`, schwaches `secure_path` oder Wrapper, die `tar`, `service`, `cp`, `python` usw. per Namen aufrufen.
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

`HOME` ist nicht nur ein Verzeichnisverweis: Viele Tools laden automatisch **dotfiles**, **plugins** und **per-user configuration** aus `$HOME` oder `$XDG_CONFIG_HOME`. Wenn ein privilegierter Workflow diese Werte beibehält, kann **config injection** einfacher sein als binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Interessante Ziele sind `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` und toolspezifische Dateien wie `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Diese Variablen beeinflussen den **dynamic linker**:

- `LD_PRELOAD`: zusätzliche shared objects erzwingen, damit sie zuerst geladen werden.
- `LD_LIBRARY_PATH`: Verzeichnisse für die Librariesuche voranstellen.
- `LD_AUDIT`: Auditor-Libraries laden, die das Laden von Libraries und die Symbolauflösung beobachten.

Sie sind extrem wertvoll für **hooking**, **instrumentation** und **privilege escalation**, wenn ein privilegierter Befehl sie beibehält. Im **secure-execution**-Modus (`AT_SECURE`, z. B. setuid/setgid/capabilities) entfernt oder beschränkt der Loader viele dieser Variablen. Parser-Bugs in dieser frühen Loader-Phase sind jedoch weiterhin hochwirksam, weil sie **vor** dem Zielprogramm ausgeführt werden.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` ändert das frühe glibc-Verhalten (zum Beispiel allocator tunables) und ist in exploit labs sehr nützlich. Es ist auch aus Sicherheitssicht wichtig, weil der **dynamic loader es sehr früh parst**. Der 2023er **Looney Tunables**-Bug war eine gute Erinnerung daran, dass eine einzige environment variable, die im loader geparst wird, zu einem **local privilege-escalation primitive** gegen SUID-Programme werden kann.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Wenn **Bash** **nicht interaktiv** gestartet wird, prüft es `BASH_ENV` und sourced diese Datei, bevor das Zielskript ausgeführt wird. Wenn Bash als `sh` aufgerufen wird oder im POSIX-ähnlichen interaktiven Modus läuft, kann auch `ENV` berücksichtigt werden. Das ist ein klassischer Weg, einen Shell-Wrapper in Codeausführung umzuwandeln, wenn die Umgebung vom Angreifer kontrolliert wird.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash selbst deaktiviert diese Startup-Dateien, wenn sich die **real/effective IDs unterscheiden**, außer `-p` wird verwendet; das genaue Verhalten hängt also davon ab, wie der Wrapper die Shell aufruft.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Diese Variablen ändern, wie Python startet:

- `PYTHONPATH`: Suchpfade für Imports voranstellen.
- `PYTHONHOME`: den Standardbibliotheksbaum umleiten.
- `PYTHONSTARTUP`: vor der interaktiven Eingabeaufforderung eine Datei ausführen.
- `PYTHONINSPECT=1`: nach dem Ende eines Skripts in den interaktiven Modus wechseln.

Sie sind nützlich gegen Wartungsskripte, Debugger, Shells und Wrapper, die Python mit einer kontrollierbaren Umgebung aufrufen. `python -E` und `python -I` ignorieren alle `PYTHON*`-Variablen.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl hat ebenso nützliche Startvariablen:

- `PERL5LIB`: fügt Library-Verzeichnisse vorne an.
- `PERL5OPT`: injiziert Switches, als ob sie auf jeder `perl`-Kommandozeile stünden.

Damit kann man **automatisches Laden von Modulen** erzwingen oder das Interpreter-Verhalten ändern, bevor das Zielskript irgendetwas Interessantes tut. Perl ignoriert diese Variablen in **taint / setuid / setgid**-Kontexten, aber sie sind weiterhin sehr relevant für normale Root-ausgeführte Wrapper, CI-Jobs, Installer und eigene `sudoers`-Regeln.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
Die gleiche Idee taucht auch in anderen Runtimes auf (`RUBYOPT`, `NODE_OPTIONS`, etc.): Immer wenn ein Interpreter durch einen privilegierten Wrapper gestartet wird, suche nach Env Vars, die **module loading** oder das **startup behavior** verändern.

Aus Post-Exploitation-Sicht solltest du außerdem daran denken, dass geerbte Environments oft **credentials**, **proxy settings**, **service tokens** oder **cloud keys** enthalten. Siehe [Linux Post Exploitation](linux-post-exploitation/README.md) für `/proc/<PID>/environ` und `systemd` `Environment=`-Suche.

### PS1

Ändere, wie dein Prompt aussieht.

[**Dies ist ein Beispiel**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../images/image (897).png>)

Normaler Benutzer:

![](<../images/image (740).png>)

Ein, zwei und drei Hintergrund-Jobs:

![](<../images/image (145).png>)

Ein Hintergrund-Job, ein gestoppter und der letzte Befehl wurde nicht korrekt beendet:

![](<../images/image (715).png>)

## References

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../banners/hacktricks-training.md}}
