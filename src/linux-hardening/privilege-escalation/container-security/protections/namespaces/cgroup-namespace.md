# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

cgroup namespace ne zamenjuje cgroups i ne nameće sam po sebi ograničenja resursa. Umesto toga, menja **kako se cgroup hijerarhija pojavljuje** procesu. Drugim rečima, virtualizuje vidljive informacije o cgroup putanjama tako da workload vidi prikaz ograničen na container, umesto pune host hijerarhije.

Ovo je pretežno funkcija za smanjenje vidljivosti i količine informacija. Pomaže da okruženje izgleda samostalno i otkriva manje o rasporedu cgroup na hostu. To može zvučati skromno, ali je i dalje važno, jer nepotrebna vidljivost strukture hosta može pomoći u izviđanju i olakšati eksploatacione lance zavisne od okruženja.

## Način rada

Bez privatnog cgroup namespace-a, proces može videti cgroup putanje relativne na host koje otkrivaju veću hijerarhiju mašine nego što je korisno. Sa privatnim cgroup namespace-om, `/proc/self/cgroup` i srodna zapažanja postaju više lokalizovana u okviru prikaza samog containera. Ovo je naročito korisno u modernim runtime stack-ovima koji žele da workload vidi čišće, manje host-otkrivajuće okruženje.

## Lab

Možete pregledati cgroup namespace pomoću:
```bash
sudo unshare --cgroup --fork bash
cat /proc/self/cgroup
ls -l /proc/self/ns/cgroup
```
I uporedi runtime ponašanje sa:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Promena se uglavnom odnosi na to šta proces može da vidi, a ne na to da li postoji cgroup enforcement.

## Security Impact

cgroup namespace je najbolje razumeti kao **visibility-hardening layer**. Sam po sebi neće sprečiti breakout ako container ima writable cgroup mounts, široke capabilities, ili opasno cgroup v1 okruženje. Međutim, ako je host cgroup namespace podeljen, proces saznaje više o tome kako je sistem organizovan i može mu biti lakše da uskladi host-relative cgroup paths sa drugim zapažanjima.

Dakle, iako ovaj namespace obično nije zvezda u writeup-ima o container breakout-u, on i dalje doprinosi širem cilju minimiziranja host information leakage.

## Abuse

Neposredna vrednost za zloupotrebu je uglavnom reconnaissance. Ako je host cgroup namespace podeljen, uporedi vidljive putanje i traži detalje hijerarhije koji otkrivaju host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
Ako su upisive cgroup putanje takođe izložene, kombinujte tu vidljivost sa pretragom opasnih nasleđenih interfejsa:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Sâm namespace retko daje instant escape, ali često olakšava mapiranje okruženja pre testiranja cgroup-based abuse primitives.

### Kompletan primer: Zajednički cgroup namespace + Upisivi cgroup v1

Sam cgroup namespace obično nije dovoljan za escape. Praktična eskalacija dešava se kada cgroup putanje koje otkrivaju host budu kombinovane sa upisivim cgroup v1 interfejsima:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Ako su ti fajlovi dostupni i mogu se pisati, odmah pivotujte na kompletan `release_agent` exploitation flow iz [cgroups.md](../cgroups.md). Uticaj je host code execution iz unutar container-a.

Bez writable cgroup interfaces, uticaj je obično ograničen na reconnaissance.

## Provere

Cilj ovih komandi je da se proveri da li proces ima privatni pogled na cgroup namespace ili saznaje više o host hijerarhiji nego što mu je zaista potrebno.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
Šta je ovde zanimljivo:

- Ako identifikator namespace-a odgovara host procesu koji vas zanima, cgroup namespace može biti deljen.
- Putanje koje otkrivaju host u `/proc/self/cgroup` su korisne za reconnaissance čak i kada nisu direktno iskoristive.
- Ako su cgroup mounts takođe zapisivi, pitanje vidljivosti postaje mnogo važnije.

Cgroup namespace treba tretirati kao sloj za učvršćivanje vidljivosti, a ne kao primarni mehanizam za escape-prevention. Nepotrebno izlaganje host cgroup strukture povećava reconnaissance vrednost za napadača.
{{#include ../../../../../banners/hacktricks-training.md}}
