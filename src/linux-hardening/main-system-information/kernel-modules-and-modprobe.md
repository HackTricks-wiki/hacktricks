# Zloupotreba kernel modula i modprobe-a

{{#include ../../banners/hacktricks-training.md}}

## Pogrešne konfiguracije kernel modula i učitavanja modula

Podrška za kernel module je oblast sa velikim uticajem tokom analize eskalacije privilegija na Linux-u. Nemojte svaku poruku o nepotpisanom modulu smatrati izvodljivom za exploit samu po sebi, već je koristite za dobijanje odgovora na praktična pitanja:

- Da li trenutni korisnik može da učitava module putem `sudo`, capabilities ili putanje pomoćnog programa sa dozvolom upisivanja?
- Da li je učitavanje modula i dalje omogućeno?
- Da li je enforcement potpisa modula onemogućen?
- Da li direktorijumi modula ili datoteke modula imaju dozvolu upisivanja?
- Da li se kernel logovi mogu čitati kako bi se potvrdilo šta se dogodilo?

Brza trijaža:
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
Tumačenje:

- `modules_disabled=1` znači da se novi moduli ne mogu učitati do ponovnog pokretanja sistema.
- `module_sig_enforce=1` obično blokira nepotpisane module.
- `dmesg_restrict=0` omogućava neprivilegovanim korisnicima da čitaju kernel logove na mnogim sistemima.
- Putanje sa dozvolom upisivanja unutar `/lib/modules/$(uname -r)/` su opasne jer otkrivanje modula i automatsko učitavanje mogu verovati tom stablu direktorijuma.

### Učitavanje modula i čitanje izlaza kernela

Ako imate legitimnu dozvolu za učitavanje lokalnog modula, `insmod` ubacuje tačnu `.ko` datoteku koju navedete. Init funkcija modula se odmah izvršava, a poruke zapisane pomoću `printk()` pojavljuju se u kernel logovima.

Minimalni tok rada za okruženja za pregled ili laboratorijska okruženja:
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Ako `sudo -l` dozvoljava `insmod`, `modprobe` ili wrapper oko njih, tretirajte to kao kritično:
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### `insmod` dozvoljen putem sudo-a

sudo pravilo koje korisniku dozvoljava pokretanje komande `insmod` nije uporedivo sa dozvolom za pokretanje uobičajenog administrativnog pomoćnog programa. Inicijalizacioni kod modula izvršava se u kontekstu kernela čim se `.ko` ubaci, pa je praktično pitanje tokom provere: „da li ovaj korisnik može da izabere ili izmeni modul koji se učitava?“

Opšti tok provere:
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Ako korisnik može da obezbedi proizvoljan `.ko`, pravilo u okviru ovlašćene procene treba tretirati kao potpunu kompromitaciju sistema. Bezbedniji operativni obrazac je izbegavanje delegiranja učitavanja modula putem sudo-a; ako je to neizbežno, ograničite tačnu putanju, vlasništvo, dozvole, politiku potpisivanja i proceduru uklanjanja.

Za bezopasan obrazac izgradnje modula u kontrolisanoj laboratoriji, minimalni izvorni kod i Makefile izgledaju ovako:
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
Izgradite i učitajte samo u ovlašćenoj laboratoriji:
```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```
### Provere zloupotrebe `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` kontroliše pomoćni program u korisničkom prostoru koji kernel poziva kada mu je potrebna pomoć pri učitavanju modula. Ako napadač može da ga promeni tako da pokazuje na izvršnu datoteku sa mogućnošću upisivanja i izazove nepoznat format binarne datoteke ili drugi put za zahtev učitavanja modula, to može dovesti do izvršavanja koda sa root privilegijama.

Proverite trenutni pomoćni program:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Proverite da li možete da utičete na njega:
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Opšti obrazac namenjen samo laboratoriji:
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
Na očvrsnutim sistemima, ovo bi trebalo da ne uspe jer neprivilegovani korisnici ne mogu da upisuju u `kernel.modprobe`, putanja pomoćnog programa nije upisiva ili su putanje za učitavanje modula blokirane.

### Provera upisivog direktorijuma `/lib/modules`

Upisivi direktorijumi modula mogu omogućiti zamenu modula, ubacivanje zlonamernih modula ili zloupotrebu automatskog učitavanja, u zavisnosti od toga kako se `modprobe` kasnije pozove.

Proverite upisive lokacije:
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Ako pronađete sadržaj modula u koji je moguće upisivati, proverite kako se moduli otkrivaju:
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Napomene za odbranu:

- Održavajte da `/lib/modules` bude u vlasništvu `root:root` i da korisnici nemaju dozvolu za pisanje.
- Postavite `kernel.modules_disabled=1` nakon pokretanja sistema, gde je to operativno moguće.
- Zahtevajte potpisivanje modula na sistemima koji zahtevaju module koji se mogu učitati.
- Pratite upisivanje u `/proc/sys/kernel/modprobe` i `/lib/modules`, kao i neočekivano izvršavanje `insmod`/`modprobe`.
{{#include ../../banners/hacktricks-training.md}}
