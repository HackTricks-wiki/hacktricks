# Linux-Umgebungsvariablen

{{#include ../../banners/hacktricks-training.md}}

## Globale Variablen

Die globalen Variablen **werden** von **Kindprozessen** geerbt.

Du kannst eine globale Variable für deine aktuelle Sitzung erstellen mit:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Diese Variable ist in Ihren aktuellen Sessions und deren untergeordneten Prozessen zugänglich.

Sie können eine Variable folgendermaßen **entfernen**:
```bash
unset MYGLOBAL
```
## Lokale Variablen

Auf **lokale Variablen** kann nur von der **aktuellen Shell/dem aktuellen Skript** aus **zugegriffen** werden.
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
Die Inhalte von `/proc/*/environ` sind **NUL-separiert**, daher sind diese Varianten gewöhnlich leichter zu lesen:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Wenn du nach **Anmeldeinformationen** oder **interessanten Dienstkonfigurationen** in geerbten Umgebungen suchst, sieh dir auch [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) an.

## Häufige Variablen

Von: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

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
- **SHELL** – der Pfad zur aktuellen Command Shell, zum Beispiel **/bin/bash**.
- **TERM** – der aktuelle Terminaltyp, zum Beispiel **xterm**.
- **TZ** – deine Zeitzone.
- **USER** – dein aktueller Benutzername.

## Interessante Variablen für hacking

Nicht jede Variable ist gleichermaßen nützlich. Aus offensiver Sicht solltest du Variablen priorisieren, die **Suchpfade**, **Startup-Dateien**, das **Verhalten des Dynamic Linkers** oder **Audit/Logging** verändern.

### **HISTFILESIZE**

Ändere den **Wert dieser Variable auf 0**, damit die **History-Datei** (\~/.bash_history) beim **Beenden deiner Sitzung** auf **0 Zeilen gekürzt** wird.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Ändere den **Wert dieser Variable auf 0**, damit Befehle **nicht im Arbeitsspeicherverlauf gespeichert** und nicht in die **Verlaufsdatei** (\~/.bash_history) geschrieben werden.
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

Setze die **Verlaufsdatei** auf **`/dev/null`** oder hebe sie vollständig auf. Dies ist in der Regel zuverlässiger, als nur die Verlaufsgröße zu ändern.
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

- `all_proxy`: Standard-Proxy für Tools/Protokolle, die diese Variable unterstützen.
- `no_proxy`: Umgehungsliste (Hosts/Domains/CIDRs), die sich direkt verbinden sollen.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Je nach Tool können sowohl Klein- als auch Großschreibungsvarianten verwendet werden (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Die Prozesse vertrauen den in **diesen Umgebungsvariablen** angegebenen Zertifikaten. Dies ist nützlich, um Tools wie **`curl`**, **`git`**, Python-HTTP-Clients oder Paketmanager dazu zu bringen, einer vom Angreifer kontrollierten CA zu vertrauen (beispielsweise, damit ein Interception-Proxy legitim aussieht).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Wenn ein privilegierter Wrapper/ein privilegiertes Script Befehle **ohne absolute Pfade** ausführt, gewinnt das **erste vom Angreifer kontrollierte Verzeichnis** in `PATH`. Das ist die Grundlage vieler **PATH hijacks** in `sudo`, Cron-Jobs, Shell-Wrappern und benutzerdefinierten SUID-Helfern. Suche nach `env_keep+=PATH`, einem schwachen `secure_path` oder Wrappern, die `tar`, `service`, `cp`, `python` usw. anhand ihres Namens aufrufen.
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

`HOME` ist nicht nur eine Verzeichnisreferenz: Viele Tools laden automatisch **dotfiles**, **Plugins** und **Benutzerkonfigurationen** aus `$HOME` oder `$XDG_CONFIG_HOME`. Wenn ein privilegierter Workflow diese Werte beibehält, kann **config injection** einfacher sein als **binary hijacking**.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Interessante Ziele umfassen `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` sowie tool-spezifische Dateien wie `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Diese Variablen beeinflussen den **dynamischen Linker**:

- `LD_PRELOAD`: erzwingt, dass zusätzliche Shared Objects zuerst geladen werden.
- `LD_LIBRARY_PATH`: stellt Verzeichnisse für die Bibliothekssuche voran.
- `LD_AUDIT`: lädt Auditor-Bibliotheken, die das Laden von Bibliotheken und die Symbolauflösung beobachten.

Sie sind äußerst wertvoll für **hooking**, **instrumentation** und **privilege escalation**, wenn ein privilegierter Befehl sie beibehält. Im **secure-execution**-Modus (`AT_SECURE`, z. B. setuid/setgid/capabilities) entfernt oder beschränkt der Loader viele dieser Variablen. Parser-Bugs in dieser frühen Loader-Phase sind jedoch weiterhin äußerst wirkungsvoll, da sie **vor** dem Zielprogramm ausgeführt werden.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` verändert das frühe Verhalten von glibc (zum Beispiel die Allocator-Tunables) und ist in Exploit-Labs sehr nützlich. Aus Sicherheitsperspektive ist die Variable ebenfalls relevant, da der **dynamic loader sie sehr früh parst**. Der **Looney-Tunables**-Bug von 2023 war eine gute Erinnerung daran, dass eine einzelne, im Loader geparste Umgebungsvariable zu einem **lokalen Privilege-Escalation-Primitiv** gegen SUID-Programme werden kann.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Wenn **Bash** **nicht interaktiv** gestartet wird, prüft es `BASH_ENV` und lädt diese Datei, bevor das Zieldskript ausgeführt wird. Wenn Bash als `sh` oder im interaktiven POSIX-Modus aufgerufen wird, kann auch `ENV` berücksichtigt werden. Dies ist eine klassische Möglichkeit, einen Shell-Wrapper in Codeausführung umzuwandeln, wenn die Umgebung vom Angreifer kontrolliert wird.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash selbst deaktiviert diese Startdateien, wenn sich die **echten/effektiven IDs unterscheiden**, sofern nicht `-p` verwendet wird. Das genaue Verhalten hängt daher davon ab, wie der Wrapper die Shell aufruft.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Diese Variablen ändern, wie Python startet:

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
### **PERL5OPT & PERL5LIB**

Perl verfügt über ebenso nützliche Startvariablen:

- `PERL5LIB`: stellt Bibliotheksverzeichnisse voran.
- `PERL5OPT`: injiziert Schalter, als stünden sie in jeder `perl`-Befehlszeile.

Dies kann **automatisches Laden von Modulen** erzwingen oder das Verhalten des Interpreters ändern, bevor das Zielskript etwas Interessantes ausführt. Perl ignoriert diese Variablen in **taint- / setuid- / setgid**-Kontexten, aber sie sind für normale als root ausgeführte Wrapper, CI-Jobs, Installer und benutzerdefinierte sudoers-Regeln weiterhin äußerst relevant.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
Dieselbe Idee tritt auch in anderen Runtimes auf (`RUBYOPT`, `NODE_OPTIONS` usw.): Wann immer ein Interpreter von einem privilegierten Wrapper gestartet wird, sollte nach Umgebungsvariablen gesucht werden, die das **Laden von Modulen** oder das **Startverhalten** verändern.

Aus Sicht der post-exploitation sollte man außerdem bedenken, dass geerbte Umgebungen häufig **Zugangsdaten**, **Proxy-Einstellungen**, **Service-Tokens** oder **Cloud-Schlüssel** enthalten. Siehe [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) für die Suche nach `/proc/<PID>/environ` und `systemd`-`Environment=`.

### PS1

Ändere das Aussehen deines Prompts.

[**Dies ist ein Beispiel**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Dies ist ein Beispiel](<../images/image (897).png>)

Regulärer Benutzer:

![PERL5OPT & PERL5LIB - PS1: Ein, zwei und drei Hintergrundjobs](<../images/image (740).png>)

Ein, zwei und drei Hintergrundjobs:

![PERL5OPT & PERL5LIB - PS1: Ein, zwei und drei Hintergrundjobs](<../images/image (145).png>)

Ein Hintergrundjob, einer angehalten und der letzte Befehl nicht korrekt beendet:

![PERL5OPT & PERL5LIB - PS1: Ein Hintergrundjob, einer angehalten und der letzte Befehl nicht korrekt beendet](<../images/image (715).png>)

## Referenzen

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../../banners/hacktricks-training.md}}
