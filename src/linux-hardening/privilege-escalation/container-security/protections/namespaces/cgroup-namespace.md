# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

cgroup namespace ne zamenjuje cgroups i sam po sebi ne nameće ograničenja resursa. Umesto toga, menja **kako se hijerarhija cgroup prikazuje** procesu. Drugim rečima, virtualizuje vidljive informacije o putanji cgroup tako da workload vidi prikaz ograničen na container umesto pune hijerarhije hosta.

Ovo je pretežno funkcija vidljivosti i redukcije informacija. Pomaže da okruženje deluje samostalno i otkriva manje o rasporedu cgroup na hostu. To možda zvuči skromno, ali je i dalje važno jer nepotrebna vidljivost strukture hosta može pomoći u reconnaissance i pojednostaviti environment-dependent exploit chains.

## Funkcionisanje

Bez privatnog cgroup namespace-a, proces može videti host-relativne cgroup putanje koje otkrivaju više hijerarhije mašine nego što je korisno. Sa privatnim cgroup namespace-om, `/proc/self/cgroup` i srodna zapažanja postaju lokalizovanija na sopstveni prikaz container-a. Ovo je posebno korisno u modernim runtime stacks koji žele da workload vidi čišće okruženje koje manje otkriva informacije o hostu.

## Lab

Možete ispitati cgroup namespace pomoću:
```bash
sudo unshare --cgroup --fork bash
cat /proc/self/cgroup
ls -l /proc/self/ns/cgroup
```
I uporedite ponašanje tokom izvršavanja sa:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Promena se uglavnom odnosi na ono što proces može da vidi, a ne na to da li postoji primena cgroup-a.

## Bezbednosni uticaj

The cgroup namespace is best understood as a **sloj koji otežava uvid**. Sam po sebi neće zaustaviti breakout ako container ima writable cgroup mounts, broad capabilities, ili opasno cgroup v1 environment. Međutim, ako je host cgroup namespace deljen, proces saznaje više o tome kako je sistem organizovan i može mu biti lakše da poravna host-relative cgroup paths sa drugim zapažanjima.

Dakle, iako ovaj namespace obično nije glavni u container breakout writeups, ipak doprinosi širem cilju minimiziranja curenja informacija o hostu.

## Zloupotreba

Neposredna vrednost za zloupotrebu je uglavnom izviđanje. Ako je host cgroup namespace deljen, uporedite vidljive putanje i tražite detalje hijerarhije koji otkrivaju informacije o hostu:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
Ako su writable cgroup putanje takođe izložene, kombinujte tu vidljivost sa pretragom opasnih nasleđenih interfejsa:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Sama namespace retko pruža trenutni escape, ali često olakšava mapiranje okruženja pre testiranja cgroup-based abuse primitives.

### Potpun primer: Shared cgroup Namespace + Writable cgroup v1

Sama cgroup namespace obično nije dovoljna za escape. Praktična eskalacija se događa kada host-revealing cgroup paths budu kombinovani sa writable cgroup v1 interfaces:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Ako su ti fajlovi dostupni i zapisivi, odmah pivot na kompletan `release_agent` exploitation flow iz [cgroups.md](../cgroups.md). Uticaj je izvršavanje koda na hostu iznutra kontejnera.

Bez zapisivih cgroup interfaces, uticaj je obično ograničen na reconnaissance.

## Provere

Cilj ovih komandi je da se vidi da li proces ima privatni cgroup namespace pogled ili saznaje više o hijerarhiji hosta nego što mu zaista treba.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
Šta je ovde zanimljivo:

- Ako identifikator namespace-a odgovara procesu na hostu koji vas zanima, cgroup namespace može biti deljen.
- Putanje koje otkrivaju host u `/proc/self/cgroup` korisne su za izviđanje čak i kada nisu direktno iskoristive.
- Ako su cgroup mounts takođe upisivi, pitanje vidljivosti postaje mnogo važnije.

cgroup namespace treba tretirati kao sloj za otežavanje vidljivosti, a ne kao primarni mehanizam za sprečavanje eskapiranja. Nepotrebno izlaganje strukture host cgroup-a povećava vrednost izviđanja za napadača.
