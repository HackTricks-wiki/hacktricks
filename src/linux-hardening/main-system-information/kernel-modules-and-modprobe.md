# Kernmodules en modprobe-misbruik

## Wanopstellings van kernmodules en modulelaai

Ondersteuning vir kernmodules is 'n gebied met 'n groot impak tydens 'n oorsig van Linux privilege escalation. Moenie elke boodskap oor 'n ongetekende module op sigself as uitbuitbaar beskou nie, maar gebruik dit om praktiese vrae te beantwoord.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Kan die huidige gebruiker modules deur `sudo`, capabilities of 'n skryfbare helper path laai?
- Is modulelaai steeds geaktiveer?
- Is afdwinging van module-handtekeninge gedeaktiveer?
- Is moduledopgehoude of modulelêers skryfbaar?
- Kan kernlogs gelees word om te bevestig wat gebeur het?

Vinnige triage begin met die volgende kontroles van modulestatus, handtekeninge, logging en die moduleboom.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
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
Interpretasie:

- `modules_disabled=1` beteken modules kan nie gelaai of ontlaai word nie, en die waarde kan nie voor herlaai na `0` teruggestel word nie.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` op die kernel-opdragreël of `CONFIG_MODULE_SIG_FORCE=y` vereis geldig ondertekende modules; anders kan ongetekende modules gelaai word en die kernel taint.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` plaas geen beperking op `dmesg` nie; wanneer dit `1` is, vereis toegang `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Skryfbare paaie onder `/lib/modules/$(uname -r)/` is gevaarlik omdat `modprobe` daardie boom en sy afhanklikheidsdata deursoek wanneer modules gelaai word.<sup>[[8]](#references)</sup>

### Laai van 'n module en lees van kernel-uitset

As jy wettige toestemming het om 'n plaaslike module te laai, voeg `insmod` die presiese `.ko`-lêer wat jy verskaf in. Die module se init-funksie loop as deel van die laaiproses, en boodskappe wat met `printk()` geskryf word, gaan na die kernel-logbuffer, wat normaalweg met `dmesg` gelees word.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

'n Minimale hersieningswerkvloei gebruik `modinfo` om metadata te inspekteer, `insmod` en `rmmod` om 'n module te laai en te verwyder, `lsmod` om die gelaaide toestand te bevestig, en `dmesg` om kernel-logboeke te inspekteer.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
As `sudo -l` `insmod`, `modprobe` of 'n wrapper rondom hulle toelaat, beskou dit as kritiek: `sudo -l` lys die aanroepende gebruiker se voorregte, en die laai van 'n kernelmodule vereis `CAP_SYS_MODULE`.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Sudo-toegelate `insmod`

'n Sudo-reël wat 'n gebruiker toelaat om `insmod` uit te voer, is nie vergelykbaar met toestemming om 'n normale administratiewe helper uit te voer nie. Die module se initialiseringskode loop as deel van die invoeging, dus is die praktiese hersieningsvraag of hierdie gebruiker die module wat gelaai word, kan kies of wysig.<sup>[[3]](#references)</sup>

Die volgende generiese hersieningsvloei herhaal daardie inspeksie-, laai-, toestand-, log- en verwyderingskontroles vir 'n kandidaatmodule.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
As die gebruiker 'n arbitrêre `.ko` kan verskaf, moet die reël in 'n gemagtigde assessering as 'n volledige stelselkompromittering behandel word. 'n Veiliger operasionele patroon is om nie die laai van modules deur sudo te delegeer nie; indien dit onvermydelik is, beperk die presiese pad, eienaarskap, toestemmings, ondertekeningsbeleid en verwyderingswerkvloei.<sup>[[3]](#references)[[10]](#references)</sup>

Vir 'n skadelose module-boupatroon in 'n beheerde lab word 'n minimale bron en Makefile hieronder gewys; die `make -C /lib/modules/$(uname -r)/build M=$PWD`-vorm volg die kernel se gedokumenteerde kbuild-werkvloei vir eksterne modules.<sup>[[5]](#references)[[7]](#references)</sup>
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
Bou en laai slegs in ’n gemagtigde laboratorium; kbuild bou die eksterne module, en die laai-/verwyder-opdragte roep die kernmodule-koppelvlakke aan.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### `kernel.modprobe` / `modprobe_path`-misbruiktoetse

`kernel.modprobe` benoem die userspace-helper wat die kernel uitvoer vir versoeke om modules outomaties te laai; hierdie sysctl beïnvloed outomatiese laai, nie eksplisiete module-invoeging nie. As ’n aanvaller dit na ’n skryfbare executable-pad kan verander en ’n moduleversoek kan aktiveer, word daardie helper ’n bevoorregte code-execution-pad.<sup>[[1]](#references)</sup>

Kontroleer die huidige helper-pad deur die kernel se sysctl-koppelvlak en inspekteer die teiken se eienaarskap en modus.<sup>[[1]](#references)</sup>
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Kontroleer of die sysctl, gedelegeerde sudo-reëls of lêervermoëns beïnvloed kan word.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Die volgende patroon is slegs vir laboratoriumgebruik, verander die helper-pad en aktiveer ’n gedokumenteerde module-autoload-versoek; gebruik dit slegs op ’n geïsoleerde, gemagtigde stelsel.<sup>[[1]](#references)</sup>

Op huidige Linux-kernele, moenie ’n onbekende uitvoerbare lêer as ’n generiese sneller gebruik nie: legacy custom binary-format module autoloading is in Linux 6.14 verwyder, terwyl die kerneldokumentasie ’n onbekende lêerstelseltipe as ’n module-autoload-versoekpad identifiseer.<sup>[[1]](#references)[[11]](#references)</sup>
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
Op versterkte stelsels behoort dit te misluk wanneer toestemmings ongemagtigde skrywings na `kernel.modprobe` voorkom, die helper-pad nie skryfbaar is nie, of outomatiese modulelaai gedeaktiveer is.<sup>[[1]](#references)</sup>

### Hersiening van skryfbare `/lib/modules`

Skryfbare modulegidse kan modulevervanging, die plant van kwaadwillige modules of misbruik van outomatiese laai moontlik maak, afhangend van hoe `modprobe` later aangeroep word; `modprobe` soek in `/lib/modules/$(uname -r)` en gebruik sy afhanklikheidsdata wanneer modules opgelos word.<sup>[[8]](#references)</sup>

Hersien skryfbare modulelêers en afhanklikheids-/aliasmetadata onder die aktiewe kernvrystelling se moduleboom.<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
As jy skryfbare module-inhoud vind, ondersoek hoe `modprobe` afhanklikhede oplos en hoe `modinfo` modulemetadata rapporteer.<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Defensiewe notas:

- Hou `/lib/modules` in die besit van `root:root` en nie-skryfbaar deur gebruikers nie.<sup>[[8]](#references)</sup>
- Stel `kernel.modules_disabled=1` na selflaai waar dit operasioneel moontlik is.<sup>[[1]](#references)</sup>
- Dwing module signing af op stelsels wat laaibare modules vereis.<sup>[[2]](#references)</sup>
- Monitor skrywings na `/proc/sys/kernel/modprobe`, `/lib/modules`, en onverwagte uitvoering van `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)</sup>

## References

- [1] [Dokumentasie vir /proc/sys/kernel/ — Die Linux Kernel-dokumentasie](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Kernel module signing-fasiliteit — Die Linux Kernel-dokumentasie](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Driver Basics — Die Linux Kernel-dokumentasie](https://docs.kernel.org/driver-api/basics.html)
- [6] [Boodskaplogging met printk — Die Linux Kernel-dokumentasie](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Bou van External Modules — Die Linux Kernel-dokumentasie](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Voeg merker 'execve-v6.14-rc1' saam — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/getcap.8.html)
{{#include ../../banners/hacktricks-training.md}}
