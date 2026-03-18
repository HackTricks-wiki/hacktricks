# Korisnički namespace

{{#include ../../../../banners/hacktricks-training.md}}

{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## References

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)



## Osnovne informacije

Korisnički namespace je Linux kernel feature koji **pruža izolaciju mapiranja korisničkih i grupnih ID-eva**, omogućavajući svakom korisničkom namespace-u da ima svoj **sopstveni set korisničkih i grupnih ID-eva**. Ova izolacija omogućava procesima koji rade u različitim korisničkim namespace-ovima da **imate različite privilegije i vlasništvo**, čak i ako numerički dele iste korisničke i grupne ID-eve.

Korisnički namespace-ovi su posebno korisni u kontejnerizaciji, gde svaki kontejner treba da ima svoj nezavisan skup korisničkih i grupnih ID-eva, što omogućava bolju bezbednost i izolaciju između kontejnera i host sistema.

### Kako radi:

1. Kada se kreira novi korisnički namespace, on **počinje sa praznim skupom mapiranja korisničkih i grupnih ID-eva**. To znači da bilo koji proces koji radi u novom korisničkom namespace-u **inicijalno nema privilegije izvan namespace-a**.
2. Mapiranja ID-eva mogu se uspostaviti između korisničkih i grupnih ID-eva u novom namespace-u i onih u roditeljskom (ili host) namespace-u. Ovo **dozvoljava procesima u novom namespace-u da imaju privilegije i vlasništvo odgovarajuće korisničkim i grupnim ID-evima u roditeljskom namespace-u**. Međutim, mapiranja ID-eva mogu biti ograničena na specifične opsege i podskupove ID-eva, omogućavajući finu kontrolu nad privilegijama dodeljenim procesima u novom namespace-u.
3. Unutar korisničkog namespace-a, **procesi mogu imati pune root privilegije (UID 0) za operacije unutar namespace-a**, dok i dalje imaju ograničene privilegije izvan namespace-a. Ovo omogućava **kontejnerima da rade sa privilegijama sličnim root-u unutar svog namespace-a bez posedovanja punih root privilegija na host sistemu**.
4. Procesi mogu menjati namespace koristeći `setns()` system call ili kreirati nove namespace-e koristeći `unshare()` ili `clone()` system call-e sa `CLONE_NEWUSER` flag-om. Kada proces pređe u novi namespace ili ga kreira, počinje da koristi mapiranja korisničkih i grupnih ID-eva povezanih sa tim namespace-om.

## Vežba:

### Kreiranje različitih namespace-ova

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **tačan i izolovan prikaz informacija o procesima specifičnim za tu namespace**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Objašnjenje problema**:

- Linux kernel omogućava procesu da kreira nove namespace koristeći `unshare` system call. Međutim, proces koji inicira kreiranje novog PID namespace-a (nazvan "unshare" proces) ne ulazi u novi namespace; samo njegovi child procesi ulaze.
- Pokretanje `%unshare -p /bin/bash%` startuje `/bin/bash` u istom procesu kao `unshare`. Posledično, `/bin/bash` i njegovi child procesi ostaju u originalnom PID namespace-u.
- Prvi child proces `/bin/bash` u novom namespace-u postaje PID 1. Kada taj proces izađe, to pokreće čišćenje namespace-a ako nema drugih procesa, pošto PID 1 ima specijalnu ulogu u usvajanju orphan procesa. Linux kernel tada onemogućava dodeljivanje PID-ova u tom namespace-u.

2. **Posledica**:

- Exit PID 1 u novom namespace-u dovodi do čišćenja `PIDNS_HASH_ADDING` flag-a. To rezultira time da `alloc_pid` ne uspe da dodeli novi PID prilikom kreiranja novog procesa, što proizvodi grešku "Cannot allocate memory".

3. **Rešenje**:
- Problem se može rešiti korišćenjem opcije `-f` sa `unshare`. Ova opcija tera `unshare` da forkuje novi proces nakon kreiranja novog PID namespace-a.
- Pokretanjem `%unshare -fp /bin/bash%` osiguravate da `unshare` sam postane PID 1 u novom namespace-u. `/bin/bash` i njegovi child procesi tada su bezbedno sadržani u tom novom namespace-u, sprečavajući prerani exit PID 1 i omogućavajući normalnu dodelu PID-ova.

By ensuring that `unshare` runs with the `-f` flag, the new PID namespace is correctly maintained, allowing `/bin/bash` and its sub-processes to operate without encountering the memory allocation error.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Da bi se koristio user namespace, Docker daemon mora biti pokrenut sa **`--userns-remap=default`**(U ubuntu 14.04, ovo se može uraditi izmenom `/etc/default/docker` i zatim izvršavanjem `sudo service docker restart`)

### Proverite u kojem namespace-u se nalazi vaš proces
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Moguće je proveriti user map iz docker containera pomoću:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Ili sa hosta pomoću:
```bash
cat /proc/<pid>/uid_map
```
### Pronađi sve User namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Uđite u User namespace
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Takođe, možete **ući u namespace drugog procesa samo ako ste root**.  
I **ne možete** **ući** u drugi namespace **bez deskriptora** koji pokazuje na njega (kao `/proc/self/ns/user`).

### Kreiranje novog User namespace (sa mapiranjima)
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```

```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Pravila mapiranja UID/GID za neprivilegovane procese

Kada proces koji piše u `uid_map`/`gid_map` **nema CAP_SETUID/CAP_SETGID u roditeljskom korisničkom namespace-u**, kernel primenjuje stroža pravila: dozvoljeno je samo jedno **mapiranje** za efektivni UID/GID pozivaoca, i za `gid_map` **morate prvo onemogućiti `setgroups(2)`** upisivanjem `deny` u `/proc/<pid>/setgroups`.
```bash
# Check whether setgroups is allowed in this user namespace
cat /proc/self/setgroups   # allow|deny

# For unprivileged gid_map writes, disable setgroups first
echo deny > /proc/self/setgroups
```
### Mountovi sa mapiranim ID-evima (MOUNT_ATTR_IDMAP)

ID-mapped mounts **prikače mapiranje user namespace-a na mount**, tako da se vlasništvo fajlova ponovo mapira kada se pristupa kroz taj mount. Ovo se često koristi od strane container runtimes (posebno rootless) da bi se **delili host putevi bez rekurzivnog `chown`**, a istovremeno se primenjuje prevođenje UID/GID u okviru user namespace-a.

Sa napadačkog stanovišta, **ako možete da kreirate mount namespace i zadržite `CAP_SYS_ADMIN` unutar vašeg user namespace-a**, i fajl sistem podržava ID-mapped mountove, možete premapirati *prikaze* vlasništva bind mountova. Ovo **ne menja vlasništvo na disku**, ali može učiniti da fajlovi koji su inače neupisivi izgledaju kao da su u vlasništvu vašeg mapiranog UID/GID unutar namespace-a.

### Vraćanje privilegija

U slučaju user namespace-ova, **kada se kreira novi user namespace, procesu koji uđe u taj namespace se dodeljuje kompletan skup privilegija unutar tog namespace-a**. Ove privilegije omogućavaju procesu da izvršava privilegovane operacije kao što su **montiranje** **fajl sistema**, kreiranje uređaja, ili menjanje vlasništva fajlova, ali **samo u kontekstu svog user namespace-a**.

Na primer, kada imate `CAP_SYS_ADMIN` privilegiju unutar user namespace-a, možete izvršavati operacije koje obično zahtevaju ovu privilegiju, kao što je montiranje fajl sistema, ali samo u okviru vašeg user namespace-a. Sve operacije koje izvršite sa ovom privilegijom neće uticati na host sistem ili druge namespace-ove.

> [!WARNING]
> Stoga, čak i ako dobijanje novog procesa unutar novog User namespace-a **će vam vratiti sve privilegije nazad** (CapEff: 000001ffffffffff), zapravo možete **koristiti samo one vezane za namespace** (na primer mount) ali ne i sve. Dakle, samo po sebi ovo nije dovoljno da se pobegne iz Docker containera.
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
```
{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## Reference

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)

{{#include ../../../../banners/hacktricks-training.md}}
