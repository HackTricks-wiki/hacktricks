# Variabili d'ambiente di Linux

{{#include ../../banners/hacktricks-training.md}}

## Variabili globali

Le variabili globali **verranno** ereditate dai **processi figlio**.

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

Le **variabili locali** possono essere **accessibili** solo dalla **shell/dallo script** corrente.
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
I contenuti di `/proc/*/environ` sono **separati da NUL**, quindi queste varianti sono solitamente più facili da leggere:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Se stai cercando **credenziali** o **configurazioni interessanti dei servizi** all’interno di ambienti ereditati, controlla anche [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Variabili comuni

Da: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – il display utilizzato da **X**. Questa variabile è solitamente impostata su **:0.0**, che indica il primo display del computer corrente.
- **EDITOR** – l’editor di testo preferito dall’utente.
- **HISTFILESIZE** – il numero massimo di righe contenute nel file della cronologia.
- **HISTSIZE** – il numero di righe aggiunte al file della cronologia quando l’utente termina la sessione.
- **HOME** – la directory home dell’utente.
- **HOSTNAME** – il nome host del computer.
- **LANG** – la lingua corrente.
- **MAIL** – la posizione della casella di posta dell’utente. Solitamente **/var/spool/mail/USER**.
- **MANPATH** – l’elenco delle directory in cui cercare le pagine del manuale.
- **OSTYPE** – il tipo di sistema operativo.
- **PS1** – il prompt predefinito in bash.
- **PATH** – memorizza il percorso di tutte le directory che contengono file binari che si desidera eseguire specificando semplicemente il nome del file, invece del percorso relativo o assoluto.
- **PWD** – la directory di lavoro corrente.
- **SHELL** – il percorso della shell dei comandi corrente, ad esempio **/bin/bash**.
- **TERM** – il tipo di terminale corrente, ad esempio **xterm**.
- **TZ** – il fuso orario.
- **USER** – il nome utente corrente.

## Variabili interessanti per l’hacking

Non tutte le variabili sono ugualmente utili. Da una prospettiva offensiva, dai priorità alle variabili che modificano i **percorsi di ricerca**, i **file di avvio**, il **comportamento del linker dinamico** o l’**auditing/il logging**.

### **HISTFILESIZE**

**Imposta il valore di questa variabile su 0**, così, quando **termini la sessione**, il **file della cronologia** (\~/.bash_history) verrà **troncato a 0 righe**.
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

Imposta il **file della cronologia** su **`/dev/null`** oppure annullalo completamente. In genere è più affidabile che modificare soltanto la dimensione della cronologia.
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

I processi considereranno attendibili i certificati indicati in **queste variabili d'ambiente**. Questo è utile per fare in modo che strumenti come **`curl`**, **`git`**, i client HTTP Python o i package manager considerino attendibile una CA controllata dall'attaccante (ad esempio, per far sembrare legittimo un proxy di intercettazione).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Se un wrapper/script privilegiato esegue comandi **senza percorsi assoluti**, la **prima directory controllata dall'attaccante** in `PATH` ha la precedenza. Questo è il primitive alla base di molti **PATH hijacks** in `sudo`, cron jobs, shell wrapper e helper SUID personalizzati. Cerca `env_keep+=PATH`, `secure_path` deboli o wrapper che chiamano `tar`, `service`, `cp`, `python`, ecc. per nome.
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
Per le catene complete di privilege escalation che abusano di `PATH`, consulta [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` non è solo un riferimento a una directory: molti strumenti caricano automaticamente **dotfiles**, **plugin** e **configurazioni per-utente** da `$HOME` o `$XDG_CONFIG_HOME`. Se un workflow privilegiato conserva questi valori, la **config injection** potrebbe essere più semplice del binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Target interessanti includono `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` e file specifici degli strumenti come `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Queste variabili influenzano il **dynamic linker**:

- `LD_PRELOAD`: forza il caricamento anticipato di oggetti condivisi aggiuntivi.
- `LD_LIBRARY_PATH`: antepone directory alla ricerca delle librerie.
- `LD_AUDIT`: carica librerie auditor che osservano il caricamento delle librerie e la risoluzione dei simboli.

Sono estremamente preziose per **hooking**, **instrumentation** e **privilege escalation** se un comando privilegiato le conserva. In modalità **secure-execution** (`AT_SECURE`, ad esempio setuid/setgid/capabilities), il loader rimuove o limita molte di queste variabili. Tuttavia, i bug del parser in questa fase iniziale del loader hanno comunque un impatto elevato, perché vengono eseguiti **prima** del programma target.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` modifica il comportamento iniziale di glibc (ad esempio i tunable dell'allocator) ed è molto utile nei laboratori di exploit. È importante anche dal punto di vista della sicurezza perché il **dynamic loader lo analizza molto presto**. Il bug **Looney Tunables** del 2023 è stato un buon promemoria del fatto che una singola variabile d'ambiente analizzata dal loader può diventare una **primitiva di escalation dei privilegi locale** contro i programmi SUID.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Se **Bash** viene avviato in modalità **non interattiva**, controlla `BASH_ENV` ed esegue quel file prima di eseguire lo script target. Quando Bash viene invocato come `sh`, o in modalità interattiva in stile POSIX, può essere consultata anche `ENV`. Questo è un modo classico per trasformare uno shell wrapper in un'esecuzione di codice se l'ambiente è controllato dall'attaccante.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash disabilita automaticamente questi startup files quando gli **ID reali/effettivi differiscono**, a meno che non venga usato `-p`, quindi il comportamento esatto dipende da come il wrapper avvia la shell. Prestare attenzione ai wrapper privilegiati che chiamano `setuid()`/`setgid()` **prima** di avviare Bash: una volta che gli ID tornano a coincidere, Bash potrebbe considerare attendibili `BASH_ENV`, `ENV` e lo stato della shell correlato, che altrimenti verrebbero ignorati.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Queste variabili modificano il modo in cui Python viene avviato:

- `PYTHONPATH`: antepone percorsi alla ricerca degli import.
- `PYTHONHOME`: ricolloca l'albero della libreria standard.
- `PYTHONSTARTUP`: esegue un file prima del prompt interattivo.
- `PYTHONINSPECT=1`: avvia la modalità interattiva dopo il completamento di uno script.

Sono utili contro script di manutenzione, debugger, shell e wrapper che chiamano Python con un environment controllabile. `python -E` e `python -I` ignorano tutte le variabili `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
Un recente esempio reale è stato l'LPE di **needrestart** del 2024 sui sistemi Ubuntu/Debian: lo scanner di proprietà di root copiava il `PYTHONPATH` di un processo non privilegiato da `/proc/<PID>/environ` e poi eseguiva Python. L'exploit pubblicato inseriva `importlib/__init__.so` nel percorso controllato dall'attaccante, facendo così eseguire codice dell'attaccante durante l'inizializzazione di Python, prima ancora che lo script hard-coded dell'helper diventasse rilevante.

### **PERL5OPT & PERL5LIB**

Perl dispone di variabili di startup altrettanto utili:

- `PERL5LIB`: antepone directory di librerie.
- `PERL5OPT`: inietta opzioni come se fossero presenti nella riga di comando di ogni comando `perl`.

Questo può forzare il **caricamento automatico dei moduli** o modificare il comportamento dell'interprete prima che lo script target esegua qualsiasi operazione interessante. Perl ignora queste variabili nei contesti **taint / setuid / setgid**, ma rimangono comunque molto importanti per i wrapper eseguiti normalmente come root, i job CI, gli installer e le regole `sudoers` personalizzate.
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

`NODE_OPTIONS` antepone **flag CLI di Node.js** a ogni processo `node` che eredita l'ambiente. Questo lo rende utile contro wrapper, job CI, helper Electron e regole sudo che alla fine eseguono Node. I flag più interessanti dal punto di vista offensivo sono solitamente:

- `--require <file>`: precarica un file CommonJS prima dello script target.
- `--import <module>`: precarica un modulo ES prima dello script target.

Node rifiuta alcuni flag pericolosi in `NODE_OPTIONS`, ma `--require` e `--import` sono esplicitamente consentiti e vengono elaborati **prima** dei normali argomenti della riga di comando.
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
Per le catene di gadget remote che impostano `NODE_OPTIONS` indirettamente (ad esempio, tramite prototype-pollution to RCE), consulta [questa altra pagina](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby offre la stessa classe di abuso all'avvio:

- `RUBYLIB`: antepone directory al percorso di caricamento di Ruby.
- `RUBYOPT`: inserisce opzioni della riga di comando come `-r` in ogni invocazione di `ruby`.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
Le vulnerabilità di **needrestart** del 2024 hanno mostrato che non si tratta solo di un trucco da laboratorio: lo stesso helper di proprietà di root vulnerabile all'abuso di `PYTHONPATH` poteva anche essere indotto a eseguire Ruby con un `RUBYLIB` controllato dall'attaccante, caricando `enc/encdb.so` da una directory controllata dall'attaccante.

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Alcuni strumenti non si limitano a leggere un percorso dall'ambiente; passano il valore a una **shell**, a un **editor** o a un **preprocessore di input**. Questo rende le seguenti variabili particolarmente interessanti quando un wrapper privilegiato esegue `git`, `man`, `less` o visualizzatori di testo simili:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: scelgono il comando pager.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: scelgono il comando editor, spesso con argomenti.
- `LESSOPEN`, `LESSCLOSE`: definiscono preprocessori/postprocessori che vengono eseguiti quando `less` apre un file.
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
Git supporta anche l'**injection della configurazione solo tramite env** senza toccare il disco tramite `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` e `GIT_CONFIG_VALUE_<n>`:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
Dal punto di vista della post-exploitation, ricorda inoltre che gli environment ereditati contengono spesso **credenziali**, **impostazioni proxy**, **token dei servizi** o **chiavi cloud**. Consulta [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) per la ricerca in `/proc/<PID>/environ` e nelle direttive `systemd` `Environment=`.

### PS1

Modifica l'aspetto del prompt.

[**Questo è un esempio**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Questo è un esempio](<../images/image (897).png>)

Utente normale:

![PERL5OPT & PERL5LIB - PS1: Uno, due e tre job in background](<../images/image (740).png>)

Uno, due e tre job in background:

![PERL5OPT & PERL5LIB - PS1: Uno, due e tre job in background](<../images/image (145).png>)

Un job in background, uno arrestato e l'ultimo comando non è terminato correttamente:

![PERL5OPT & PERL5LIB - PS1: Un job in background, uno arrestato e l'ultimo comando non è terminato correttamente](<../images/image (715).png>)

## Riferimenti

- [GNU Bash Manual - File di avvio di Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [Qualys - LPE in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [Documentazione CLI di Node.js - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)

{{#include ../../banners/hacktricks-training.md}}
