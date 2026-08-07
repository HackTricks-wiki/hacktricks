# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

cgroup namespace ne zamenjuje cgroups i sam po sebi ne nameće ograničenja resursa. Umesto toga, menja **način na koji se hijerarhija cgroup-ova prikazuje** procesu. Drugim rečima, virtualizuje vidljive informacije o putanji cgroup-a tako da workload vidi prikaz ograničen na container, umesto kompletne hijerarhije hosta.

Ovo je prvenstveno funkcija za vidljivost i smanjenje količine informacija. Pomaže da okruženje izgleda samostalno i otkriva manje informacija o cgroup rasporedu hosta. To možda deluje beznačajno, ali je i dalje važno jer nepotrebna vidljivost strukture hosta može pomoći pri izviđanju i pojednostaviti exploit lance zavisne od okruženja.

## Rad

Bez privatnog cgroup namespace-a, proces može videti putanje cgroup-ova relativne u odnosu na host, koje otkrivaju veći deo hijerarhije mašine nego što je korisno. Sa privatnim cgroup namespace-om, `/proc/self/cgroup` i srodna posmatranja postaju lokalizovaniji u odnosu na sopstveni prikaz container-a. Ovo je naročito korisno u modernim runtime stack-ovima koji žele da workload vidi čistije okruženje koje otkriva manje informacija o hostu.

Virtualizacija takođe utiče na `/proc/<pid>/mountinfo`, a ne samo na `/proc/<pid>/cgroup`. Kada čitate drugi proces iz perspektive drugačijeg cgroup namespace-a, putanje izvan korena vašeg namespace-a prikazuju se sa početnim komponentama `../`, što je koristan pokazatelj da gledate iznad svog delegiranog podstabla. Korisna napomena za labs i post-exploitation jeste da novokreiranom cgroup namespace-u često treba **remount cgroupfs-a iz samog namespace-a** pre nego što `mountinfo` pravilno prikaže novi koren. U suprotnom i dalje možete videti mount root kao što je `/..`, što znači da nasleđeni mount i dalje prikazuje prikaz ukorenjen u pretku, iako je sam namespace već promenjen.<sup>[[1]](#references)</sup>

## Lab

cgroup namespace možete ispitati pomoću:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Ako želite da `mountinfo` jasnije prikaže novi root cgroup namespace-a, ponovo montirajte cgroup filesystem iz novog namespace-a i ponovo izvršite poređenje:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
I uporedi ponašanje tokom izvršavanja sa:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Promena se uglavnom odnosi na ono što proces može da vidi, a ne na to da li cgroup enforcement postoji.

## Bezbednosni uticaj

cgroup namespace je najbolje posmatrati kao **sloj za ojačavanje vidljivosti**. Sam po sebi neće sprečiti breakout ako container ima writable cgroup mounts, široke capabilities ili opasno cgroup v1 okruženje. Međutim, ako je host cgroup namespace deljen, proces saznaje više o organizaciji sistema i može lakše da poveže cgroup paths relativne u odnosu na host sa drugim zapažanjima.

Na **cgroup v2**, namespace postaje nešto značajniji zato što su delegation rules stroža. Ako je hijerarhija montirana sa `nsdelegate`, kernel tretira cgroup namespaces kao granice delegation-a: ancestor control files bi trebalo da ostanu van domašaja delegatee-a, a writes u root-u namespace-a ograničeni su na delegation-safe files, kao što su `cgroup.procs`, `cgroup.threads` i `cgroup.subtree_control`.<sup>[[2]](#references)</sup> Ovo i dalje ne čini namespace escape primitive-om samim po sebi, ali menja šta compromised workload može da pregleda i gde može bezbedno da kreira sub-cgroups.

Dakle, iako ovaj namespace obično nije glavna tema container breakout writeup-ova, on i dalje doprinosi širem cilju smanjivanja leakage-a informacija o hostu i ograničavanja cgroup delegation-a.

## Zloupotreba

Neposredna vrednost za abuse uglavnom se svodi na reconnaissance. Ako je host cgroup namespace deljen, uporedite vidljive paths i potražite detalje hijerarhije koji otkrivaju host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Ako su izložene i cgroup putanje sa dozvolom upisivanja, kombinujte tu vidljivost sa pretragom opasnih zastarelih interfejsa:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Sam namespace retko omogućava trenutni escape, ali često olakšava mapiranje okruženja pre testiranja cgroup-based abuse primitives.

Brza provera stvarnog stanja runtime-a takođe pomaže pri određivanju prioriteta attack path-a. Docker izlaže `--cgroupns=host|private`, dok Podman podržava `host`, `private`, `container:<id>` i `ns:<path>`. Konkretno za Podman, podrazumevana vrednost je obično **`host` na cgroup v1** i **`private` na cgroup v2**, tako da samo utvrđivanje verzije cgroup-a već pokazuje koji je namespace posture verovatniji, čak i pre nego što pregledate punu OCI konfiguraciju.

### Moderni v2 Recon: Da Li Je Ovo Delegirani Podstablo?

Na modernim hostovima zanimljivo pitanje često nije `release_agent`, već da li se trenutni proces nalazi unutar delegiranog **cgroup v2** podstabla sa dovoljnom vidljivošću ili pravima upisa za kreiranje ugnježdenih grupa:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Korisno tumačenje:

- `cgroup2fs` znači da se nalazite u objedinjenoj v2 hijerarhiji, pa klasični lanci `release_agent` koji postoje samo u v1 ne bi trebalo da budu vaša prva pretpostavka.
- `cgroup.controllers` prikazuje koji su kontroleri dostupni iz nadređene grupe i samim tim na koje kontrolere trenutno podstablo potencijalno može da se proširi na decu.
- `cgroup.subtree_control` prikazuje koji su kontroleri zapravo omogućeni za potomke.
- `cgroup.events` izlaže `populated=0/1`, što je korisno za praćenje da li je podstablo postalo prazno, ali to **nije primitive za host-code-execution** poput v1 `release_agent`.

Ako već imate dovoljno privilegija za direktno ispitivanje namespace-a drugog procesa, uporedite prikaze pomoću:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Potpuni primer: Deljeni cgroup Namespace + Writable cgroup v1

Sam cgroup namespace obično nije dovoljan za escape. Praktična eskalacija nastaje kada se cgroup paths koji otkrivaju host kombinuju sa Writable cgroup v1 interfejsima:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Ako su te datoteke dostupne i mogu se upisivati, odmah pređite na kompletan tok eksploatacije `release_agent` iz [cgroups.md](../cgroups.md). Posledica je izvršavanje koda na hostu iz kontejnera.

Bez cgroup interfejsa sa dozvolom upisivanja, posledice su obično ograničene na izviđanje.

## Provere

Svrha ovih komandi je da se utvrdi da li proces ima privatni prikaz cgroup namespace-a ili saznaje više o hijerarhiji hosta nego što mu je zaista potrebno.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Šta je ovde interesantno:

- Ako se identifikator namespace-a podudara sa host procesom koji vas zanima, cgroup namespace možda deli taj proces.
- Putanje koje otkrivaju host u `/proc/self/cgroup` ili entries u `mountinfo` ukorenjeni u ancestor-u korisni su za reconnaissance, čak i kada nisu direktno exploitable.
- Ako se koristi `cgroup2fs`, fokusirajte se na delegation, vidljive controllere i writable podstabla, umesto da pretpostavite da stari v1 primitives i dalje postoje.
- Ako su cgroup mount-ovi takođe writable, pitanje vidljivosti postaje mnogo važnije.

cgroup namespace treba posmatrati kao sloj za ograničavanje vidljivosti, a ne kao primarni mehanizam za sprečavanje escape-a. Nepotrebno izlaganje cgroup strukture hosta napadaču daje dodatnu vrednost za reconnaissance.

## Reference

- [1] [cgroup_namespaces(7) — Linux manual page](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [2] [Control Group v2 — The Linux Kernel documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
