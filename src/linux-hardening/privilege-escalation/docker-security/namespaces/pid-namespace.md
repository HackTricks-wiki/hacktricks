# PID Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Osnovne informacije

PID (Process IDentifier) namespace je funkcionalnost u Linux kernelu koja obezbeđuje izolaciju procesa tako što omogućava grupi procesa da imaju sopstveni skup jedinstvenih PID-ova, odvojenih od PID-ova u drugim namespace-ovima. Ovo je posebno korisno u kontejnerizaciji, gde je izolacija procesa ključna za bezbednost i upravljanje resursima.

Kada se kreira novi PID namespace, prvom procesu u tom namespace-u dodeljuje se PID 1. Taj proces postaje "init" proces novog namespace-a i odgovoran je za upravljanje ostalim procesima unutar namespace-a. Svaki naredni proces kreiran u tom namespace-u ima jedinstveni PID unutar tog namespace-a, i ti PID-ovi su nezavisni od PID-ova u drugim namespace-ovima.

Iz perspektive procesa unutar PID namespace-a, on može videti samo druge procese u istom namespace-u. Nije svestan procesa u drugim namespace-ovima i ne može da utiče na njih koristeći tradicionalne alate za upravljanje procesima (npr. `kill`, `wait`, itd.). Ovo pruža nivo izolacije koji pomaže da procesi ne ometaju jedni druge.

### Kako to radi:

1. Kada se kreira novi proces (npr. korišćenjem sistemskog poziva `clone()`), proces može biti dodeljen novom ili postojećem PID namespace-u. **Ako je kreiran novi namespace, proces postaje "init" proces tog namespace-a**.
2. **kernel** održava **mapiranje između PID-ova u novom namespace-u i odgovarajućih PID-ova** u parent namespace-u (tj. namespace-u iz kojeg je novi namespace kreiran). Ovo mapiranje **omogućava kernelu da prevodi PID-ove kada je to potrebno**, na primer pri slanju signala između procesa u različitim namespace-ovima.
3. **Procesi unutar PID namespace-a mogu samo da vide i komuniciraju sa drugim procesima u istom namespace-u**. Nisu svesni procesa u drugim namespace-ovima, i njihovi PID-ovi su jedinstveni unutar njihovog namespace-a.
4. Kada je **PID namespace uništen** (npr. kada "init" proces namespace-a izađe), **svi procesi unutar tog namespace-a se završavaju**. Ovo osigurava da se svi resursi povezani sa namespace-om pravilno oslobode.

## Lab:

### Kreiranje različitih Namespaces

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Objašnjenje problema**:

- Linux kernel omogućava procesu da kreira nove PID (Process ID) namespaces pomoću sistemskog poziva `unshare`. Međutim, proces koji inicira kreiranje novog PID namespace-a (nazvan "unshare" proces) ne ulazi u novi namespace; ulaze samo njegovi child procesi.
- Pokretanje %unshare -p /bin/bash% pokreće `/bin/bash` u istom procesu kao `unshare`. Posledično, `/bin/bash` i njegovi child procesi su u originalnom PID namespace-u.
- Prvi child proces `/bin/bash` u novom namespace-u postaje PID 1. Kada taj proces izađe, pokreće se čišćenje namespace-a ako nema drugih procesa, jer PID 1 ima posebnu ulogu — usvaja napuštene procese. Linux kernel će tada onemogućiti alokaciju PID-ova u tom namespace-u.

2. **Posledica**:

- Izlazak PID 1 u novom namespace-u dovodi do uklanjanja flag-a `PIDNS_HASH_ADDING`. To rezultira time da funkcija `alloc_pid` ne uspe da dodeli novi PID pri kreiranju novog procesa, proizvodeći grešku "Cannot allocate memory".

3. **Rešenje**:
- Problem se može rešiti korišćenjem opcije `-f` sa `unshare`. Ova opcija natera `unshare` da fork-uje novi proces nakon kreiranja novog PID namespace-a.
- Izvršavanje %unshare -fp /bin/bash% osigurava da sam `unshare` postane PID 1 u novom namespace-u. `/bin/bash` i njegovi child procesi su tada bezbedno smešteni u tom novom namespace-u, sprečavajući prevremeni izlazak PID 1 i omogućavajući normalnu alokaciju PID-ova.

Osiguravanjem da se `unshare` izvršava sa `-f` flagom, novi PID namespace se pravilno održava, što omogućava `/bin/bash` i njegovim pod-procesima da rade bez nailaženja na grešku alokacije memorije.

</details>

By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **tačan i izolovan pregled informacija o procesima specifičnim za taj namespace**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Proverite u kojem namespace-u se nalazi vaš proces
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Pronađite sve PID namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
Imajte na umu da root iz početnog (default) PID namespace-a može da vidi sve procese, čak i one u novim PID namespaces, zato možemo da vidimo sve PID namespaces.

### Ulazak u PID namespace
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
When you enter inside a PID namespace from the default namespace, you will still be able to see all the processes. And the process from that PID ns will be able to see the new bash on the PID ns.

Also, you can only **enter in another process PID namespace if you are root**. And you **cannot** **enter** in other namespace **without a descriptor** pointing to it (like `/proc/self/ns/pid`)

## Nedavne beleške o eksploataciji

### CVE-2025-31133: zloupotreba `maskedPaths` za pristup host PID-ovima

runc ≤1.2.7 je dozvoljavao napadačima koji kontrolišu container images ili `runc exec` workloads da zamene container-stranu `/dev/null` neposredno pre nego što runtime zamaskira osetljive procfs unose. Kada se race uspe, `/dev/null` može biti pretvoren u simblički link koji pokazuje na bilo koju host putanju (na primer `/proc/sys/kernel/core_pattern`), pa novi container PID namespace iznenada nasleđuje read/write pristup host-globalnim procfs podešavanjima iako nikada nije napustio svoj namespace. Kada `core_pattern` ili `/proc/sysrq-trigger` postanu upisivi, generisanje coredump-a ili aktiviranje SysRq dovodi do izvršavanja koda ili denial of service u host PID namespace-u.

Praktični tok:

1. Build an OCI bundle whose rootfs replaces `/dev/null` with a link to the host path you want (`ln -sf /proc/sys/kernel/core_pattern rootfs/dev/null`).
2. Start the container before the fix so runc bind-mounts the host procfs target over the link.
3. Inside the container namespace, write to the now-exposed procfs file (e.g., point `core_pattern` to a reverse shell helper) and crash any process to force the host kernel to execute your helper as PID 1 context.

You can quickly audit whether a bundle is masking the right files before starting it:
```bash
jq '.linux.maskedPaths' config.json | tr -d '"'
```
Ako runtime nema očekivani maskirajući unos koji očekujete (ili ga preskoči zato što je `/dev/null` nestao), tretirajte kontejner kao da ima potencijalnu vidljivost host PID-a.

### Namespace injection with `insject`

NCC Group-ov `insject` se učitava kao LD_PRELOAD payload koji hook-uje kasnu fazu u ciljanom programu (podrazumevano `main`) i izvršava niz poziva `setns()` nakon `execve()`. To vam omogućava da se priključite sa host-a (ili drugog kontejnera) u PID namespace žrtve *nakon što* se njen runtime inicijalizovao, čuvajući njen `/proc/<pid>` prikaz bez potrebe da kopirate binarije u filesystem kontejnera. Pošto `insject` može odložiti pridruživanje PID namespace-u sve dok ne izvrši fork, možete zadržati jednu nit u host namespace-u (sa CAP_SYS_PTRACE) dok druga nit izvršava u ciljnom PID namespace-u, stvarajući moćne debugging ili offensive primitives.

Primer upotrebe:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Ključni zaključci pri zloupotrebi ili odbrani od namespace injection:

- Koristite `-S/--strict` da primorate `insject` da prekine izvršavanje ako threads već postoje ili ako namespace joins zakažu; u suprotnom možete ostaviti delimično-migrirane threads koje premošćuju host i container PID spaces.
- Nikada ne prikačujte alate koji i dalje drže writable host file descriptors, osim ako se i vi ne pridružite mount namespace — u suprotnom bilo koji process unutar PID namespace može ptrace-ovati vaš helper i ponovo iskoristiti te descriptors za manipulisanje host resources.

## References

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [container escape via "masked path" abuse due to mount race conditions (GitHub Security Advisory)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [Tool Release – insject: A Linux Namespace Injector (NCC Group)](https://www.nccgroup.com/us/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../banners/hacktricks-training.md}}
