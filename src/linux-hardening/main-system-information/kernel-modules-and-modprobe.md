# Kernel Modules और modprobe Abuse

{{#include ../../banners/hacktricks-training.md}}

## Kernel module और module-loading misconfigurations

Linux privilege escalation review के दौरान Kernel module support एक high-impact क्षेत्र है। हर unsigned-module message को अपने-आप exploitable न मानें, बल्कि इन practical questions के उत्तर पाने के लिए इसका उपयोग करें:

- क्या current user `sudo`, capabilities, या किसी writable helper path के माध्यम से modules load कर सकता है?
- क्या module loading अभी भी enabled है?
- क्या module signature enforcement disabled है?
- क्या module directories या module files writable हैं?
- क्या kernel logs पढ़कर पुष्टि की जा सकती है कि क्या हुआ?

त्वरित जांच:
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
cat /proc/sys/kernel/module_sig_enforce 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
व्याख्या:

- `modules_disabled=1` का अर्थ है कि reboot होने तक नए modules load नहीं किए जा सकते।
- `module_sig_enforce=1` आमतौर पर unsigned modules को block करता है।
- `dmesg_restrict=0` कई systems पर unprivileged users को kernel logs पढ़ने देता है।
- `/lib/modules/$(uname -r)/` के अंतर्गत writable paths खतरनाक होते हैं, क्योंकि module discovery और auto-loading उस tree पर भरोसा कर सकते हैं।

### Module load करना और kernel output पढ़ना

यदि आपके पास local module load करने की वैध permission है, तो `insmod` आपके द्वारा प्रदान की गई सटीक `.ko` file को insert करता है। Module का init function तुरंत run होता है, और `printk()` से लिखे गए messages kernel logs में दिखाई देते हैं।

Review या lab environments के लिए minimal workflow:
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
यदि `sudo -l` `insmod`, `modprobe` या इनके आसपास के किसी wrapper को अनुमति देता है, तो इसे critical मानें:
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Sudo-allowed `insmod`

किसी user को `insmod` चलाने की अनुमति देने वाला sudo rule, किसी सामान्य administrative helper को अनुमति देने के समान नहीं है। `.ko` insert होते ही module का initialization code kernel context में चलता है, इसलिए practical review का प्रश्न यह है: "क्या यह user load किए जा रहे module को चुन या modify कर सकता है?"

Generic review flow:
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
यदि user कोई arbitrary `.ko` उपलब्ध करा सकता है, तो authorized assessment में इस rule को full system compromise माना जाना चाहिए। अधिक सुरक्षित operational pattern यह है कि sudo के माध्यम से module loading delegate करने से बचें; यदि यह unavoidable हो, तो exact path, ownership, permissions, signing policy और removal workflow को restrict करें।

Controlled lab में harmless module-building pattern के लिए, एक minimal source और Makefile इस प्रकार दिखते हैं:
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
केवल अधिकृत lab में build और load करें:
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### `kernel.modprobe` / `modprobe_path` abuse checks

`kernel.modprobe` उस userspace helper को नियंत्रित करता है जिसे kernel module-loading assistance की आवश्यकता होने पर invoke करता है। यदि कोई attacker इसे writable executable path में बदल सकता है और unknown binary format या किसी अन्य module request path को trigger कर सकता है, तो यह root code execution में बदल सकता है।

Current helper check करें:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
जाँचें कि क्या आप इसे प्रभावित कर सकते हैं:
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
सामान्य, केवल-लैब पैटर्न:
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger an unknown executable format so the kernel attempts helper logic
printf '\\xff\\xff\\xff\\xff' > /tmp/unknown
chmod +x /tmp/unknown
/tmp/unknown 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
Hardening किए गए systems पर, यह विफल होना चाहिए क्योंकि unprivileged users `kernel.modprobe` में write नहीं कर सकते, helper path writable नहीं है, या module-loading paths blocked हैं।

### Writable `/lib/modules` की समीक्षा

Writable module directories module replacement, malicious module planting, या बाद में `modprobe` को invoke किए जाने के तरीके के आधार पर auto-load abuse की अनुमति दे सकती हैं।

Writable locations की समीक्षा करें:
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
यदि आपको writable module content मिलता है, तो जाँचें कि modules कैसे discover किए जाते हैं:
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
रक्षात्मक नोट्स:

- `/lib/modules` का स्वामित्व `root:root` रखें और इसे users द्वारा writable न होने दें।
- जहाँ operationally संभव हो, boot के बाद `kernel.modules_disabled=1` सेट करें।
- उन systems पर module signing लागू करें जिन्हें loadable modules की आवश्यकता होती है।
- `/proc/sys/kernel/modprobe`, `/lib/modules` में writes और अप्रत्याशित `insmod`/`modprobe` execution को monitor करें।
{{#include ../../banners/hacktricks-training.md}}
