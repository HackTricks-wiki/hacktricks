# Linux Environment Variables

{{#include ../banners/hacktricks-training.md}}

## Variabili globali

Le variabili globali **saranno** ereditate dai **processi figli**.

Puoi creare una variabile globale per la tua sessione corrente facendo:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Questa variabile sarà accessibile dalla tua sessione corrente e dai suoi processi figli.

Puoi **rimuovere** una variabile facendo:
```bash
unset MYGLOBAL
```
## Variabili locali

Le **variabili locali** possono essere **accedute** solo dalla **shell/script corrente**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Elenca le variabili attuali
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
Se stai cercando **credenziali** o **configurazione di servizio interessante** all'interno di ambienti ereditati, controlla anche [Linux Post Exploitation](linux-post-exploitation/README.md).

## Variabili comuni

Da: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – il display usato da **X**. Questa variabile è solitamente impostata a **:0.0**, che indica il primo display sul computer corrente.
- **EDITOR** – l’editor di testo preferito dall’utente.
- **HISTFILESIZE** – il numero massimo di righe contenute nel file della cronologia.
- **HISTSIZE** – numero di righe aggiunte al file della cronologia quando l’utente termina la sua sessione
- **HOME** – la tua directory home.
- **HOSTNAME** – l’hostname del computer.
- **LANG** – la tua lingua corrente.
- **MAIL** – la posizione dello spool della posta dell’utente. Di solito **/var/spool/mail/USER**.
- **MANPATH** – l’elenco delle directory da cercare per le pagine di manuale.
- **OSTYPE** – il tipo di sistema operativo.
- **PS1** – il prompt predefinito in bash.
- **PATH** – memorizza il percorso di tutte le directory che contengono file binari che vuoi eseguire semplicemente specificando il nome del file e non il percorso relativo o assoluto.
- **PWD** – la directory di lavoro corrente.
- **SHELL** – il percorso della shell di comando corrente (per esempio, **/bin/bash**).
- **TERM** – il tipo di terminale corrente (per esempio, **xterm**).
- **TZ** – il tuo fuso orario.
- **USER** – il tuo nome utente corrente.

## Variabili interessanti per hacking

Non tutte le variabili sono ugualmente utili. Da una prospettiva offensiva, dai priorità alle variabili che modificano **search paths**, **startup files**, **dynamic linker behavior** o **audit/logging**.

### **HISTFILESIZE**

Cambia il **valore di questa variabile a 0**, così quando **termini la sessione** il **history file** (\~/.bash_history) verrà **troncato a 0 righe**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Cambia il **valore di questa variabile a 0**, così i comandi **non vengono mantenuti nella history in-memory** e non verranno riscritti nel **file della history** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Se il **valore di questa variabile è impostato su `ignorespace` o `ignoreboth`**, qualsiasi comando preceduto da uno spazio extra non verrà salvato nella cronologia.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Punta il **file della cronologia** a **`/dev/null`** oppure rimuovilo completamente. Questo è di solito più affidabile che cambiare solo la dimensione della cronologia.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

I processi useranno il **proxy** dichiarato qui per connettersi a internet tramite **http o https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: proxy predefinito per strumenti/protocolli che lo supportano.
- `no_proxy`: lista di bypass (host/domini/CIDR) che devono connettersi direttamente.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Sia le varianti minuscole che quelle maiuscole possono essere usate a seconda dello strumento (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

I processi si fideranno dei certificati indicati in **queste variabili d'ambiente**. Questo è utile per far sì che strumenti come **`curl`**, **`git`**, client HTTP Python o gestori di pacchetti si fidino di una CA controllata dall'attaccante (ad esempio, per far sembrare legittimo un interception proxy).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Se un wrapper/script privilegiato esegue comandi **senza path assoluti**, vince la **prima directory controllata dall’attaccante** in `PATH`. Questo è il primitivo alla base di molti **PATH hijacks** in `sudo`, cron jobs, shell wrappers e helper SUID personalizzati. Cerca `env_keep+=PATH`, `secure_path` debole o wrapper che chiamano `tar`, `service`, `cp`, `python`, ecc. per nome.
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
Per catene complete di privilege-escalation che abusano di `PATH`, consulta [Linux Privilege Escalation](privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` non è solo un riferimento a una directory: molti strumenti caricano automaticamente **dotfile**, **plugin** e **configurazioni per singolo utente** da `$HOME` o `$XDG_CONFIG_HOME`. Se un workflow privilegiato preserva questi valori, l'**iniezione di config** può essere più semplice del binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Interessanti target includono `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` e file specifici degli strumenti come `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Queste variabili influenzano il **dynamic linker**:

- `LD_PRELOAD`: forza il caricamento per primo di ulteriori oggetti condivisi.
- `LD_LIBRARY_PATH`: antepone directory di ricerca delle librerie.
- `LD_AUDIT`: carica librerie auditor che osservano il caricamento delle librerie e la risoluzione dei simboli.

Sono estremamente utili per **hooking**, **instrumentation** e **privilege escalation** se un comando con privilegi le preserva. In modalità **secure-execution** (`AT_SECURE`, ad es. setuid/setgid/capabilities), il loader rimuove o limita molte di queste variabili. Tuttavia, i bug del parser in quella fase iniziale del loader sono ancora ad alto impatto perché vengono eseguiti **prima** del programma di destinazione.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` cambia il comportamento iniziale di glibc (per esempio, i tunables dell'allocator) ed è molto utile nei lab di exploit. È importante anche dal punto di vista della sicurezza perché il **dynamic loader lo analizza molto presto**. Il bug **Looney Tunables** del 2023 è stato un buon promemoria del fatto che una singola variabile d'ambiente analizzata nel loader può diventare un **primitive di local privilege-escalation** contro programmi SUID.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Se **Bash** viene avviato in modo **non interattivo**, controlla `BASH_ENV` e esegue il sourcing di quel file prima di eseguire lo script target. Quando Bash viene invocato come `sh`, oppure in modalità interattiva in stile POSIX, può essere consultato anche `ENV`. Questo è un modo classico per trasformare un wrapper di shell in code execution se l'ambiente è controllato dall'attaccante.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash stesso disabilita questi file di avvio quando gli **ID reali/effettivi differiscono** a meno che non venga usato `-p`, quindi il comportamento esatto dipende da come il wrapper invoca la shell.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Queste variabili cambiano il modo in cui Python si avvia:

- `PYTHONPATH`: antepone i percorsi di ricerca per gli import.
- `PYTHONHOME`: sposta l'albero della libreria standard.
- `PYTHONSTARTUP`: esegue un file prima del prompt interattivo.
- `PYTHONINSPECT=1`: entra in modalità interattiva dopo che uno script termina.

Sono utili contro script di manutenzione, debugger, shell e wrapper che chiamano Python con un ambiente controllabile. `python -E` e `python -I` ignorano tutte le variabili `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl ha variabili di startup altrettanto utili:

- `PERL5LIB`: aggiunge in testa le directory delle librerie.
- `PERL5OPT`: inietta switch come se fossero presenti su ogni riga di comando `perl`.

Questo può forzare il **caricamento automatico dei moduli** o modificare il comportamento dell’interprete prima che lo script target faccia qualcosa di interessante. Perl ignora queste variabili in contesti **taint / setuid / setgid**, ma restano comunque molto importanti per normali wrapper eseguiti come root, job CI, installer e regole `sudoers` personalizzate.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
La stessa idea appare in altri runtime (`RUBYOPT`, `NODE_OPTIONS`, ecc.): ogni volta che un interpreter viene avviato da un privileged wrapper, cerca env vars che modificano **module loading** o **startup behavior**.

Da una prospettiva di post-exploitation, ricorda anche che gli ambienti ereditati spesso contengono **credentials**, **proxy settings**, **service tokens** o **cloud keys**. Controlla [Linux Post Exploitation](linux-post-exploitation/README.md) per `/proc/<PID>/environ` e la ricerca di `Environment=` in `systemd`.

### PS1

Cambia l'aspetto del tuo prompt.

[**This is an example**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../images/image (897).png>)

Regular user:

![](<../images/image (740).png>)

One, two and three backgrounded jobs:

![](<../images/image (145).png>)

One background job, one stopped and last command didn't finish correctly:

![](<../images/image (715).png>)

## References

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../banners/hacktricks-training.md}}
