# Mount Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Osnovne informacije

Mount namespace je funkcija Linux kernela koja pruža izolaciju tačaka montiranja fajl sistema koje vide grupa procesa. Svaki mount namespace ima svoj set tačaka montiranja fajl sistema, i **promene na tačkama montiranja u jednom namespace-u ne utiču na druge namespace-e**. To znači da procesi koji se izvršavaju u različitim mount namespace-ima mogu imati različite poglede na hijerarhiju fajl sistema.

Mount namespace-i su posebno korisni u kontejnerizaciji, gde svaki kontejner treba da ima svoj fajl sistem i konfiguraciju, izolovanu od drugih kontejnera i host sistema.

### Kako to funkcioniše:

1. Kada se kreira novi mount namespace, on se inicijalizuje sa **kopijom tačaka montiranja iz svog roditeljskog namespace-a**. To znači da, prilikom kreiranja, novi namespace deli isti pogled na fajl sistem kao njegov roditelj. Međutim, sve kasnije promene na tačkama montiranja unutar namespace-a neće uticati na roditelja ili druge namespace-e.
2. Kada proces modifikuje tačku montiranja unutar svog namespace-a, kao što je montiranje ili odmontiranje fajl sistema, **promena je lokalna za taj namespace** i ne utiče na druge namespace-e. To omogućava svakom namespace-u da ima svoju nezavisnu hijerarhiju fajl sistema.
3. Procesi mogu prelaziti između namespace-a koristeći `setns()` sistemski poziv, ili kreirati nove namespace-e koristeći `unshare()` ili `clone()` sistemske pozive sa `CLONE_NEWNS` flagom. Kada proces pređe u novi namespace ili ga kreira, počinje da koristi tačke montiranja povezane sa tim namespace-om.
4. **Fajl deskriptori i inodi se dele između namespace-a**, što znači da ako proces u jednom namespace-u ima otvoren fajl deskriptor koji pokazuje na fajl, može **proslediti taj fajl deskriptor** procesu u drugom namespace-u, i **oba procesa će pristupiti istom fajlu**. Međutim, putanja fajla možda neće biti ista u oba namespace-a zbog razlika u tačkama montiranja.

## Lab:

### Kreirajte različite Namespace-e

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
Montiranjem nove instance `/proc` datoteke ako koristite parametar `--mount-proc`, osiguravate da nova mount namespace ima **tačan i izolovan prikaz informacija o procesima specifičnim za tu namespace**.

<details>

<summary>Greška: bash: fork: Ne može da dodeli memoriju</summary>

Kada se `unshare` izvrši bez opcije `-f`, dolazi do greške zbog načina na koji Linux upravlja novim PID (Process ID) namespace-ima. Ključni detalji i rešenje su navedeni u nastavku:

1. **Objašnjenje problema**:

- Linux kernel omogućava procesu da kreira nove namespace-e koristeći `unshare` sistemski poziv. Međutim, proces koji inicira kreiranje novog PID namespace-a (poznat kao "unshare" proces) ne ulazi u novi namespace; samo njegovi podprocesi to čine.
- Pokretanjem `%unshare -p /bin/bash%` pokreće se `/bin/bash` u istom procesu kao `unshare`. Kao rezultat, `/bin/bash` i njegovi podprocesi su u originalnom PID namespace-u.
- Prvi podproces `/bin/bash` u novom namespace-u postaje PID 1. Kada ovaj proces izađe, pokreće čišćenje namespace-a ako nema drugih procesa, jer PID 1 ima posebnu ulogu usvajanja siročadi. Linux kernel će tada onemogućiti dodelu PID-a u tom namespace-u.

2. **Posledica**:

- Izlazak PID 1 u novom namespace-u dovodi do čišćenja `PIDNS_HASH_ADDING` oznake. To rezultira neuspehom funkcije `alloc_pid` da dodeli novi PID prilikom kreiranja novog procesa, što proizvodi grešku "Ne može da dodeli memoriju".

3. **Rešenje**:
- Problem se može rešiti korišćenjem opcije `-f` sa `unshare`. Ova opcija čini da `unshare` fork-uje novi proces nakon kreiranja novog PID namespace-a.
- Izvršavanje `%unshare -fp /bin/bash%` osigurava da sam `unshare` komanda postane PID 1 u novom namespace-u. `/bin/bash` i njegovi podprocesi su tada sigurno sadržani unutar ovog novog namespace-a, sprečavajući prevremeni izlazak PID 1 i omogućavajući normalnu dodelu PID-a.

Osiguravanjem da `unshare` radi sa `-f` oznakom, novi PID namespace se ispravno održava, omogućavajući `/bin/bash` i njegovim podprocesima da funkcionišu bez susretanja greške u dodeli memorije.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;Proverite u kojem je namespace vaš proces
```bash
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### Pronađite sve Mount namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```

```bash
findmnt
```
### Uđite u Mount namespace
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
Takođe, možete **ući u drugi procesni namespace samo ako ste root**. I **ne možete** **ući** u drugi namespace **bez deskriptora** koji na njega ukazuje (kao što je `/proc/self/ns/mnt`).

Pošto su novi mount-ovi dostupni samo unutar namespace-a, moguće je da namespace sadrži osetljive informacije koje mogu biti dostupne samo iz njega.

### Mount-ujte nešto
```bash
# Generate new mount ns
unshare -m /bin/bash
mkdir /tmp/mount_ns_example
mount -t tmpfs tmpfs /tmp/mount_ns_example
mount | grep tmpfs # "tmpfs on /tmp/mount_ns_example"
echo test > /tmp/mount_ns_example/test
ls /tmp/mount_ns_example/test # Exists

# From the host
mount | grep tmpfs # Cannot see "tmpfs on /tmp/mount_ns_example"
ls /tmp/mount_ns_example/test # Doesn't exist
```

```
# findmnt # List existing mounts
TARGET                                SOURCE                                                                                                           FSTYPE     OPTIONS
/                                     /dev/mapper/web05--vg-root

# unshare --mount  # run a shell in a new mount namespace
# mount --bind /usr/bin/ /mnt/
# ls /mnt/cp
/mnt/cp
# exit  # exit the shell, and hence the mount namespace
# ls /mnt/cp
ls: cannot access '/mnt/cp': No such file or directory

## Notice there's different files in /tmp
# ls /tmp
revshell.elf

# ls /mnt/tmp
krb5cc_75401103_X5yEyy
systemd-private-3d87c249e8a84451994ad692609cd4b6-apache2.service-77w9dT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-resolved.service-RnMUhT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-timesyncd.service-FAnDql
vmware-root_662-2689143848

```
## Reference

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux](https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux)

{{#include ../../../../banners/hacktricks-training.md}}
