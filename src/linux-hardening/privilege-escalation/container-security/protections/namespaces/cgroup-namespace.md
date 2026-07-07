# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

cgroup namespace ne zamenjuje cgroups i ne sprovodi sam ograničenja resursa. Umesto toga, menja **kako cgroup hijerarhija izgleda** procesu. Drugim rečima, virtualizuje vidljive informacije o cgroup putanji tako da workload vidi prikaz ograničen na container, umesto pune host hijerarhije.

Ovo je prvenstveno funkcija vidljivosti i smanjenja informacija. Pomaže da okruženje deluje samostalno i otkriva manje o host cgroup rasporedu. To možda zvuči skromno, ali i dalje je važno jer nepotrebna vidljivost u host strukturu može pomoći reconnaissance i pojednostaviti exploit lance zavisne od okruženja.

## Operation

Bez private cgroup namespace, proces može da vidi host-relativne cgroup putanje koje otkrivaju više hijerarhije mašine nego što je korisno. Sa private cgroup namespace, `/proc/self/cgroup` i srodna posmatranja postaju lokalizovanija na sopstveni pogled containera. Ovo je naročito korisno u modernim runtime stackovima koji žele da workload vidi čistije okruženje koje manje otkriva host.

Virtualizacija takođe utiče na `/proc/<pid>/mountinfo`, ne samo na `/proc/<pid>/cgroup`. Kada čitate drugi proces iz drugačije cgroup-namespace perspektive, putanje van root-a vašeg namespace-a prikazuju se sa vodećim `../` komponentama, što je koristan trag da gledate iznad svog delegiranog podstabla. Korisna nijansa za labove i post-exploitation je da novokreirani cgroup namespace često zahteva **cgroupfs remount iz tog namespace-a** pre nego što `mountinfo` čisto prikaže novi root. U suprotnom i dalje možete videti mount root kao što je `/..`, što znači da nasleđeni mount i dalje otkriva prikaz ukorenjen u predak-rootu, iako se sam namespace već promenio.

## Lab

Možete pregledati cgroup namespace pomoću:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Ako želite da `mountinfo` jasnije prikaže novi cgroup-namespace root, ponovo mountujte cgroup filesystem iznutra novog namespace-a i uporedite ponovo:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
I uporedi runtime ponašanje sa:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Promena je uglavnom vezana za ono što proces može da vidi, a ne za to da li cgroup enforcement postoji.

## Security Impact

cgroup namespace je najbolje razumeti kao **layer za hardening vidljivosti**. Sam po sebi neće zaustaviti breakout ako container ima writable cgroup mounts, široke capabilities, ili opasno cgroup v1 okruženje. Međutim, ako je host cgroup namespace deljen, proces saznaje više o tome kako je sistem organizovan i možda će mu biti lakše da uskladi host-relative cgroup paths sa drugim zapažanjima.

Na **cgroup v2**, namespace postaje malo važniji zato što su delegation pravila stroža. Ako je hijerarhija montirana sa `nsdelegate`, kernel tretira cgroup namespaces kao delegation boundaries: ancestor control files bi trebalo da ostanu van dosega delegatee-a, a pisanje u namespace root je ograničeno na delegation-safe fajlove kao što su `cgroup.procs`, `cgroup.threads`, i `cgroup.subtree_control`. Ovo i dalje ne čini namespace primitive za escape samo po sebi, ali menja šta compromised workload može da ispita i gde može bezbedno da kreira sub-cgroups.

Dakle, iako ovaj namespace obično nije zvezda writeup-ova o container breakout-u, on i dalje doprinosi širem cilju minimizacije host information leakage i ograničavanja cgroup delegation.

## Abuse

Neposredna abuse vrednost je uglavnom reconnaissance. Ako je host cgroup namespace deljen, uporedite vidljive paths i tražite detalje hijerarhije koji otkrivaju host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Ako su i upisive cgroup putanje takođe izložene, kombinujte tu vidljivost sa pretragom za opasne legacy interfejse:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Sam namespace retko kada daje trenutni escape, ali često olakšava mapiranje okruženja pre testiranja cgroup-based abuse primitives.

Brza provera runtime stvarnosti takođe pomaže da se prioritetizuje attack path. Docker izlaže `--cgroupns=host|private`, dok Podman podržava `host`, `private`, `container:<id>`, i `ns:<path>`. Kod Podman-a posebno, podrazumevano je obično **`host` na cgroup v1** i **`private` na cgroup v2**, tako da samo identifikovanje cgroup verzije već govori koji je namespace posture verovatniji pre nego što uopšte pregledate pun OCI config.

### Modern v2 Recon: Is This A Delegated Subtree?

Na modernim hostovima zanimljivo pitanje često nije `release_agent`, već da li se trenutni process nalazi unutar delegated **cgroup v2** subtree sa dovoljno visibility ili write access da bi se napravile nested groups:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Korisno tumačenje:

- `cgroup2fs` znači da si u unified v2 hijerarhiji, tako da klasični v1-only `release_agent` lanci ne bi trebalo da budu prvi izbor.
- `cgroup.controllers` pokazuje koji su kontroleri dostupni iz parent-a i zato na šta bi trenutni subtree potencijalno mogao da se proširi na children.
- `cgroup.subtree_control` pokazuje koji su kontroleri zapravo enabled za descendants.
- `cgroup.events` izlaže `populated=0/1`, što je korisno za praćenje da li je subtree postao prazan, ali to **nije** host-code-execution primitive kao v1 `release_agent`.

Ako već imaš dovoljno privilegija da direktno pregledaš namespace drugog procesa, uporedi prikaze sa:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Puni primer: Shared cgroup Namespace + Writable cgroup v1

cgroup namespace sam po sebi obično nije dovoljan za escape. Praktična eskalacija se dešava kada se host-revealing cgroup putanje kombinuju sa writable cgroup v1 interfejsima:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Ako su ti fajlovi dostupni i upisivi, odmah pivotiraj u puni `release_agent` exploitation flow iz [cgroups.md](../cgroups.md). Uticaj je host code execution iznutra iz kontejnera.

Bez upisivih cgroup interfejsa, uticaj je obično ograničen na reconnaissance.

## Checks

Svrha ovih komandi je da vidiš da li proces ima privatni cgroup namespace view ili saznaje više o host hijerarhiji nego što mu zaista treba.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Šta je ovde interesantno:

- Ako se identifikator namespace-a poklapa sa host procesom koji vas zanima, cgroup namespace može biti deljen.
- Putanje koje otkrivaju host u `/proc/self/cgroup` ili unosi u `mountinfo` koji su ukorenjeni na ancestor root-u korisni su za reconnaissance čak i kada nisu direktno exploitable.
- Ako je `cgroup2fs` u upotrebi, fokusirajte se na delegation, vidljive controllers i writable subtrees umesto da pretpostavljate da i dalje postoje stari v1 primitives.
- Ako su cgroup mounts takođe writable, pitanje visibility postaje mnogo važnije.

cgroup namespace treba tretirati kao sloj za hardening visibility, a ne kao primarni mehanizam za sprečavanje escape-a. Nepotrebno izlaganje host cgroup strukture dodaje reconnaissance vrednost napadaču.

## References

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
