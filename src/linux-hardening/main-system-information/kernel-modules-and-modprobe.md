# Kernel Modules na modprobe Abuse

## Kernel module na module-loading misconfigurations

Usaidizi wa Kernel module ni eneo lenye athari kubwa wakati wa ukaguzi wa Linux privilege escalation. Usichukulie kila ujumbe wa unsigned-module kuwa exploitable peke yake, bali uitumie kujibu maswali ya vitendo.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Je, mtumiaji wa sasa anaweza kupakia modules kupitia `sudo`, capabilities, au helper path inayoweza kuandikwa?
- Je, module loading bado imewezeshwa?
- Je, module signature enforcement imezimwa?
- Je, module directories au module files zinaweza kuandikwa?
- Je, kernel logs zinaweza kusomwa ili kuthibitisha kilichotokea?

Quick triage huanza na ukaguzi ufuatao wa module-status, signature, logging, na module-tree.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
```bash
uname -a
uname -r
cat /proc/sys/kernel/modules_disabled 2>/dev/null
grep -Eo '(^| )module\.sig_enforce(=[^ ]*)?' /proc/cmdline 2>/dev/null
grep -E '^(CONFIG_MODULE_SIG|CONFIG_MODULE_SIG_FORCE)=' "/boot/config-$(uname -r)" 2>/dev/null
cat /proc/sys/kernel/dmesg_restrict 2>/dev/null
dmesg 2>/dev/null | grep -Ei 'module|signature|taint|verification'
find /lib/modules/$(uname -r) -type d -writable -ls 2>/dev/null
find /lib/modules/$(uname -r) -type f -name '*.ko*' -writable -ls 2>/dev/null
```
Tafsiri:

- `modules_disabled=1` inamaanisha modules haziwezi kupakiwa wala kuondolewa, na thamani hiyo haiwezi kuwekwa tena kuwa `0` hadi kuwashwa upya kwa mfumo.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` kwenye kernel command line au `CONFIG_MODULE_SIG_FORCE=y` huhitaji modules zilizotiwa saini kihalali; vinginevyo, modules ambazo hazijasainiwa zinaweza kupakiwa na kuifanya kernel kuwa tainted.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` haiweki kizuizi chochote kwenye `dmesg`; ikiwa ni `1`, ufikiaji unahitaji `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Njia zinazoweza kuandikwa chini ya `/lib/modules/$(uname -r)/` ni hatari kwa sababu `modprobe` hutafuta kwenye tree hiyo na data yake ya dependencies wakati wa kupakia modules.<sup>[[8]](#references)</sup>

### Kupakia module na kusoma kernel output

Ikiwa una ruhusa halali ya kupakia module ya ndani, `insmod` huingiza faili halisi ya `.ko` unayotoa. Init function ya module huendeshwa ikiwa sehemu ya upakiaji, na ujumbe unaoandikwa kwa `printk()` huenda kwenye kernel log buffer, ambayo kwa kawaida husomwa kwa `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Workflow ndogo ya review hutumia `modinfo` kukagua metadata, `insmod` na `rmmod` kupakia na kuondoa module, `lsmod` kuthibitisha hali ya upakiaji, na `dmesg` kukagua kernel logs.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Ikiwa `sudo -l` inaruhusu `insmod`, `modprobe`, au wrapper inayozizunguka, ichukulie kama jambo la muhimu sana: `sudo -l` huorodhesha ruhusa za mtumiaji anayeendesha amri, na kupakia kernel module kunahitaji `CAP_SYS_MODULE`.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### `insmod` Inayoruhusiwa na Sudo

Sheria ya sudo inayomruhusu mtumiaji kuendesha `insmod` si sawa na kumruhusu kutumia msaidizi wa kawaida wa kiutawala. Code ya uanzishaji ya module huendeshwa kama sehemu ya kuingizwa kwake, hivyo swali la msingi katika ukaguzi ni ikiwa mtumiaji huyu anaweza kuchagua au kurekebisha module inayopakiwa.<sup>[[3]](#references)</sup>

Mtiririko ufuatao wa ukaguzi hurudia ukaguzi wa inspection, load, state, log, na removal kwa module inayochunguzwa.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Iwapo mtumiaji anaweza kutoa `.ko` yoyote, sheria hiyo inapaswa kuchukuliwa kama full system compromise katika tathmini iliyoidhinishwa. Muundo salama zaidi wa kiutendaji ni kuepuka kukabidhi upakiaji wa module kupitia sudo; ikiwa haiwezi kuepukika, zuia path kamili, umiliki, permissions, signing policy na utaratibu wa kuiondoa.<sup>[[3]](#references)[[10]](#references)</sup>

Kwa muundo salama wa kujenga module katika lab inayodhibitiwa, source na Makefile ndogo zimeonyeshwa hapa chini; muundo wa `make -C /lib/modules/$(uname -r)/build M=$PWD` unafuata workflow ya kbuild iliyoandikwa na kernel kwa external modules.<sup>[[5]](#references)[[7]](#references)</sup>
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
Jenga na pakia katika maabara iliyoidhinishwa pekee; kbuild hujenga external module, na amri za load/remove huomba kernel module interfaces.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### `kernel.modprobe` / `modprobe_path` abuse checks

`kernel.modprobe` hutaja userspace helper ambayo kernel huitekeleza kwa maombi ya module autoload; sysctl hii huathiri autoloading, si uingizaji wa module unaofanywa wazi. Ikiwa attacker anaweza kuibadilisha iwe path ya executable inayoweza kuandikwa na kisha kuchochea ombi la module, helper huyo huwa njia ya privileged code-execution.<sup>[[1]](#references)</sup>

Kagua path ya sasa ya helper kupitia kernel sysctl interface na uchunguze umiliki na mode ya target.<sup>[[1]](#references)</sup>
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Kagua ikiwa sysctl, delegated sudo rules, au file capabilities zinaweza kuathiriwa.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Mchoro ufuatao wa maabara pekee hubadilisha njia ya helper na kuchochea ombi la module-autoload lililoandikwa kwenye nyaraka; itumie tu kwenye mfumo uliotengwa na ulioidhinishwa.<sup>[[1]](#references)</sup>

Kwenye Linux kernels za sasa, usitumie executable isiyojulikana kama kichocheo cha jumla: legacy custom binary-format module autoloading iliondolewa kwenye Linux 6.14, huku nyaraka za kernel zikitaja unknown filesystem type kama njia ya ombi la module-autoload.<sup>[[1]](#references)[[11]](#references)</sup>
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
Kwenye mifumo iliyoimarishwa, hii inapaswa kushindwa wakati permissions zinapozuia writes zisizo na privileges kwenye `kernel.modprobe`, njia ya helper haiwezi kuandikwa, au module autoloading imezimwa.<sup>[[1]](#references)</sup>

### Mapitio ya `/lib/modules` inayoweza kuandikwa

Module directories zinazoweza kuandikwa zinaweza kuruhusu module replacement, malicious module planting, au auto-load abuse kulingana na jinsi `modprobe` itakavyoitwa baadaye; `modprobe` hutafuta `/lib/modules/$(uname -r)` na hutumia dependency data yake wakati wa kutatua modules.<sup>[[8]](#references)</sup>

Kagua module files zinazoweza kuandikwa pamoja na dependency/alias metadata chini ya module tree ya kernel release inayotumika.<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Ukikuta maudhui ya module yanayoweza kuandikwa, chunguza jinsi `modprobe` inavyotatua dependencies na jinsi `modinfo` inavyoripoti module metadata.<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Defensive notes:

- Weka `/lib/modules` ikiwa inamilikiwa na `root:root` na haiwezi kuandikwa na users.<sup>[[8]](#references)</sup>
- Weka `kernel.modules_disabled=1` baada ya boot pale ambapo inawezekana kiutendaji.<sup>[[1]](#references)</sup>
- Tekeleza module signing kwenye systems zinazohitaji loadable modules.<sup>[[2]](#references)</sup>
- Fuatilia writes kwenye `/proc/sys/kernel/modprobe`, `/lib/modules`, na utekelezaji usiotarajiwa wa `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)</sup>

## References

- [1] [Documentation for /proc/sys/kernel/ — Nyaraka za Linux Kernel](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Kernel module signing facility — Nyaraka za Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Ukurasa wa manual wa Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Ukurasa wa manual wa Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Driver Basics — Nyaraka za Linux Kernel](https://docs.kernel.org/driver-api/basics.html)
- [6] [Message logging with printk — Nyaraka za Linux Kernel](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Building External Modules — Nyaraka za Linux Kernel](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Ukurasa wa manual wa Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Ukurasa wa manual wa Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Ukurasa wa manual wa Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Merge tag 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Ukurasa wa manual wa Linux](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Ukurasa wa manual wa Linux](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Ukurasa wa manual wa Linux](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Ukurasa wa manual wa Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
{{#include ../../banners/hacktricks-training.md}}
