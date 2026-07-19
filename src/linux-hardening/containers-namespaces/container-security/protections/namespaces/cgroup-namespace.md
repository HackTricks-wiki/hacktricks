# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

cgroup namespace ne zamenjuje cgroups i sam po sebi ne primenjuje ograničenja resursa. Umesto toga, menja **način na koji se hijerarhija cgroup-ova prikazuje** procesu. Drugim rečima, virtualizuje vidljive informacije o putanji cgroup-a tako da workload vidi prikaz ograničen na container, umesto kompletne hijerarhije hosta.

Ovo je prvenstveno funkcija za ograničavanje vidljivosti i smanjenje količine informacija. Pomaže da okruženje izgleda samostalno i otkriva manje informacija o rasporedu cgroup-ova na hostu. To možda deluje skromno, ali je i dalje važno zato što nepotrebna vidljivost strukture hosta može pomoći pri izviđanju i pojednostaviti lance exploit-a zavisne od okruženja.

## Rad

Bez privatnog cgroup namespace-a, proces može videti putanje cgroup-ova relativne u odnosu na host, koje otkrivaju veći deo hijerarhije mašine nego što je korisno. Sa privatnim cgroup namespace-om, `/proc/self/cgroup` i slična posmatranja postaju lokalizovanija na prikaz samog container-a. Ovo je naročito korisno u modernim runtime stack-ovima koji žele da workload vidi čistije okruženje koje otkriva manje informacija o hostu.

Virtualizacija takođe utiče na `/proc/<pid>/mountinfo`, a ne samo na `/proc/<pid>/cgroup`. Kada čitate drugi proces iz perspektive drugog cgroup namespace-a, putanje izvan korena vašeg namespace-a prikazuju se sa početnim komponentama `../`, što je koristan znak da gledate iznad svog delegiranog podstabla. Korisna napomena za labove i post-exploitation jeste da novokreirani cgroup namespace često zahteva **remount cgroupfs-a iz samog namespace-a** pre nego što `mountinfo` pravilno prikaže novi koren. U suprotnom i dalje možete videti mount root kao što je `/..`, što znači da nasleđeni mount i dalje izlaže prikaz zasnovan na korenu pretka, iako se sam namespace već promenio.

## Lab

cgroup namespace možete pregledati pomoću:
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
I uporedite ponašanje tokom izvršavanja sa:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Promena se uglavnom odnosi na ono što proces može da vidi, a ne na to da li cgroup enforcement postoji.

## Uticaj na bezbednost

cgroup namespace je najbolje razumeti kao **sloj za ojačavanje vidljivosti**. Sam po sebi neće sprečiti breakout ako container ima writable cgroup mounts, široke capabilities ili opasno cgroup v1 okruženje. Međutim, ako je host cgroup namespace deljen, proces saznaje više o organizaciji sistema i može lakše da uskladi cgroup putanje relativne u odnosu na host sa drugim zapažanjima.

Na **cgroup v2**, namespace postaje nešto važniji zato što su pravila delegiranja stroža. Ako je hijerarhija montirana sa `nsdelegate`, kernel tretira cgroup namespaces kao granice delegiranja: ancestor control files bi trebalo da ostanu van domašaja korisnika kome je delegiranje izvršeno, a upisi u root namespace-a ograničeni su na fajlove bezbedne za delegiranje, kao što su `cgroup.procs`, `cgroup.threads` i `cgroup.subtree_control`. Ovo i dalje ne čini namespace samostalnim escape primitive-om, ali menja ono što compromised workload može da pregleda i mesta na kojima može bezbedno da kreira sub-cgroups.

Dakle, iako ovaj namespace obično nije glavna tema u writeup-ovima o container breakout-u, on i dalje doprinosi širem cilju smanjivanja leak-a informacija o hostu i ograničavanja cgroup delegiranja.

## Zloupotreba

Neposredna vrednost zloupotrebe uglavnom se svodi na reconnaissance. Ako je host cgroup namespace deljen, uporedite vidljive putanje i potražite detalje hijerarhije koji otkrivaju host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Ako su izložene i cgroup putanje sa dozvolom upisa, kombinujte tu vidljivost sa pretragom opasnih legacy interfejsa:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Sam namespace retko omogućava trenutni escape, ali često olakšava mapiranje okruženja pre testiranja primitiva za zloupotrebu zasnovanih na cgroup-u.

Brza provera stvarnog stanja runtime-a takođe pomaže pri određivanju prioriteta attack path-a. Docker izlaže `--cgroupns=host|private`, dok Podman podržava `host`, `private`, `container:<id>` i `ns:<path>`. Konkretno za Podman, podrazumevana vrednost je obično **`host` na cgroup v1** i **`private` na cgroup v2**, tako da samo identifikovanje verzije cgroup-a već ukazuje na to koji je stav namespace-a verovatniji, čak i pre pregleda kompletne OCI konfiguracije.

### Moderna v2 izviđanja: Da li je ovo delegirano podstablo?

Na modernim hostovima, zanimljivo pitanje često nije `release_agent`, već da li se trenutni proces nalazi unutar delegiranog **cgroup v2** podstabla sa dovoljnom vidljivošću ili pravima upisa za kreiranje ugnježdenih grupa:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Korisna interpretacija:

- `cgroup2fs` znači da se nalazite u objedinjenoj v2 hijerarhiji, tako da klasični lanci `release_agent` koji postoje samo u v1 više ne bi trebalo da budu vaša prva pretpostavka.
- `cgroup.controllers` prikazuje koji su kontroleri dostupni iz nadređene grupe, a samim tim i na koje kontrolere trenutno podstablo potencijalno može da se proširi na decu.
- `cgroup.subtree_control` prikazuje koji su kontroleri stvarno omogućeni za potomke.
- `cgroup.events` izlaže `populated=0/1`, što je korisno za praćenje da li je podstablo postalo prazno, ali to **nije primitiv za izvršavanje koda na hostu** poput v1 `release_agent`.

Ako već imate dovoljno privilegija da direktno pregledate namespace drugog procesa, uporedite prikaze pomoću:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Kompletan primer: Shared cgroup Namespace + Writable cgroup v1

Sam cgroup namespace obično nije dovoljan za escape. Praktična eskalacija nastaje kada se cgroup putanje koje otkrivaju host kombinuju sa Writable cgroup v1 interfejsima:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Ako su ti fajlovi dostupni i upisivi, odmah pređi na kompletan tok `release_agent` exploitation-a iz [cgroups.md](../cgroups.md). Uticaj je izvršavanje koda na hostu iz kontejnera.

Bez upisivih cgroup interfejsa, uticaj je obično ograničen na izviđanje.

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
Šta je ovde zanimljivo:

- Ako se identifikator namespace-a podudara sa procesom hosta koji vas zanima, cgroup namespace možda deli isti kontekst.
- Putanje koje otkrivaju host u `/proc/self/cgroup` ili stavke u `mountinfo` zasnovane na root-u ancestor-a korisne su za reconnaissance čak i kada nisu direktno exploitable.
- Ako se koristi `cgroup2fs`, fokusirajte se na delegation, vidljive kontrolere i writable podstabla, umesto da pretpostavljate da stari v1 primitives i dalje postoje.
- Ako su cgroup mount-ovi takođe writable, pitanje vidljivosti postaje mnogo važnije.

cgroup namespace treba posmatrati kao sloj za hardening vidljivosti, a ne kao primarni mehanizam za sprečavanje escape-a. Nepotrebno izlaganje cgroup strukture hosta napadaču pruža dodatnu reconnaissance vrednost.

## Reference

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
