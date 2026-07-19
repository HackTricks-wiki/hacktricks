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
Se stai cercando **credenziali** o **configurazioni di servizio interessanti** all’interno di ambienti ereditati, consulta anche [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Variabili comuni

Da: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – il display utilizzato da **X**. Questa variabile è solitamente impostata su **:0.0**, indicando il primo display del computer corrente.
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
- **PATH** – memorizza il percorso di tutte le directory che contengono file binari che si desidera eseguire specificando solo il nome del file, anziché il percorso relativo o assoluto.
- **PWD** – la directory di lavoro corrente.
- **SHELL** – il percorso della shell dei comandi corrente (ad esempio, **/bin/bash**).
- **TERM** – il tipo di terminale corrente (ad esempio, **xterm**).
- **TZ** – il fuso orario.
- **USER** – il nome utente corrente.

## Variabili interessanti per hacking

Non tutte le variabili sono ugualmente utili. Da una prospettiva offensiva, dai priorità alle variabili che modificano i **percorsi di ricerca**, i **file di avvio**, il **comportamento del dynamic linker** o l’**audit/logging**.

### **HISTFILESIZE**

Modifica il **valore di questa variabile impostandolo su 0**, in modo che, quando **termini la sessione**, il **file della cronologia** (\~/.bash_history) venga **troncato a 0 righe**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Modifica il **valore di questa variabile a 0**, in modo che i comandi **non vengano conservati nella cronologia in memoria** e non vengano scritti nuovamente nel **file della cronologia** (\~/.bash_history).
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

Imposta il **file della cronologia** su **`/dev/null`** oppure rimuovilo completamente. Questo è generalmente più affidabile che modificare soltanto la dimensione della cronologia.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

I processi utilizzeranno il **proxy** dichiarato qui per connettersi a internet tramite **http o https**.
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
È possibile utilizzare sia le varianti minuscole che quelle maiuscole, a seconda dello strumento (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

I processi considereranno attendibili i certificati indicati in **queste variabili d'ambiente**. Questo è utile per fare in modo che strumenti come **`curl`**, **`git`**, i client HTTP Python o i package manager considerino attendibile una CA controllata dall'attaccante (ad esempio, per fare in modo che un proxy di intercettazione sembri legittimo).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Se un wrapper/script privilegiato esegue comandi **senza percorsi assoluti**, la **prima directory controllata dall'attacker** in `PATH` ha la precedenza. Questo è il meccanismo alla base di molti **PATH hijacks** in `sudo`, job cron, shell wrapper e helper SUID personalizzati. Cerca `env_keep+=PATH`, `secure_path` configurato in modo debole oppure wrapper che chiamano `tar`, `service`, `cp`, `python` e simili tramite il nome.
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
Per le catene complete di **privilege escalation** che abusano di `PATH`, consulta [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` non è solo un riferimento a una directory: molti strumenti caricano automaticamente **dotfile**, **plugin** e **configurazione per utente** da `$HOME` o `$XDG_CONFIG_HOME`. Se un flusso di lavoro privilegiato conserva questi valori, la **config injection** può essere più semplice del **binary hijacking**.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Tra i target interessanti ci sono `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` e file specifici degli strumenti come `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Queste variabili influenzano il **dynamic linker**:

- `LD_PRELOAD`: forza il caricamento anticipato di ulteriori oggetti condivisi.
- `LD_LIBRARY_PATH`: antepone directory alla ricerca delle librerie.
- `LD_AUDIT`: carica librerie auditor che osservano il caricamento delle librerie e la risoluzione dei simboli.

Sono estremamente preziose per **hooking**, **instrumentation** e **privilege escalation** se un comando privilegiato le preserva. In modalità **secure-execution** (`AT_SECURE`, ad esempio setuid/setgid/capabilities), il loader rimuove o limita molte di queste variabili. Tuttavia, i bug nei parser presenti nella fase iniziale del loader hanno comunque un impatto elevato perché vengono eseguiti **prima** del programma target.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` modifica il comportamento iniziale di glibc (ad esempio, i parametri dell'allocator) ed è molto utile nei lab di exploit. È importante anche dal punto di vista della sicurezza perché il **dynamic loader lo analizza molto presto**. Il bug **Looney Tunables** del 2023 ha ricordato che una singola variabile d'ambiente analizzata dal loader può diventare una **primitiva di escalation dei privilegi locale** contro i programmi SUID.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Se **Bash** viene avviato in modalità **non interattiva**, controlla `BASH_ENV` ed esegue il source di quel file prima di eseguire lo script di destinazione. Quando Bash viene invocato come `sh`, o in modalità interattiva POSIX, può essere consultata anche `ENV`. Questo è un metodo classico per trasformare un wrapper della shell in un'esecuzione di codice se l'ambiente è controllato dall'attaccante.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash disabilita automaticamente questi file di avvio quando gli **ID reali/effettivi differiscono**, a meno che non venga usato `-p`, quindi il comportamento esatto dipende da come il wrapper avvia la shell.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Queste variabili modificano il modo in cui Python viene avviato:

- `PYTHONPATH`: antepone i percorsi di ricerca per gli import.
- `PYTHONHOME`: ricolloca l'albero della libreria standard.
- `PYTHONSTARTUP`: esegue un file prima del prompt interattivo.
- `PYTHONINSPECT=1`: avvia la modalità interattiva al termine dell'esecuzione di uno script.

Sono utili contro script di manutenzione, debugger, shell e wrapper che chiamano Python con un ambiente controllabile. `python -E` e `python -I` ignorano tutte le variabili `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl dispone di variabili di avvio altrettanto utili:

- `PERL5LIB`: antepone directory di librerie.
- `PERL5OPT`: inietta opzioni come se fossero presenti nella riga di comando di ogni comando `perl`.

Questo può forzare il **caricamento automatico dei moduli** o modificare il comportamento dell'interprete prima che lo script target esegua operazioni interessanti. Perl ignora queste variabili nei contesti **taint / setuid / setgid**, ma rimangono molto importanti per i wrapper eseguiti normalmente come root, i job CI, gli installer e le regole sudoers personalizzate.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
La stessa idea si applica ad altri runtime (`RUBYOPT`, `NODE_OPTIONS`, ecc.): ogni volta che un interprete viene avviato da un wrapper privilegiato, cerca le variabili d'ambiente che modificano il **caricamento dei moduli** o il **comportamento all'avvio**.

Dal punto di vista del post-exploitation, ricorda anche che gli ambienti ereditati spesso contengono **credenziali**, **impostazioni proxy**, **service token** o **cloud keys**. Consulta [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) per la ricerca di `/proc/<PID>/environ` e di `Environment=` in `systemd`.

### PS1

Modifica l'aspetto del prompt.

[**Questo è un esempio**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Questo è un esempio](<../images/image (897).png>)

Utente normale:

![PERL5OPT & PERL5LIB - PS1: Un job, due job e tre job eseguiti in background](<../images/image (740).png>)

Un job, due job e tre job eseguiti in background:

![PERL5OPT & PERL5LIB - PS1: Un job, due job e tre job eseguiti in background](<../images/image (145).png>)

Un job in background, uno arrestato e l'ultimo comando non è terminato correttamente:

![PERL5OPT & PERL5LIB - PS1: Un job in background, uno arrestato e l'ultimo comando non è terminato correttamente](<../images/image (715).png>)

## Riferimenti

- [Manuale GNU Bash - File di avvio di Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../../banners/hacktricks-training.md}}
