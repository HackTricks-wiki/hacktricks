# User Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

User namespace menja značenje user i group ID-ova tako što omogućava kernelu da mapira ID-jeve viđene unutar namespace-a na različite ID-jeve van njega. Ovo je jedna od najvažnijih modernih zaštita za container-e jer direktno rešava najveći istorijski problem klasičnih container-a: **root unutar containera je ranije bio neprijatno blizu root-a na hostu**.

Sa user namespaces, proces može da se izvršava kao UID 0 unutar containera a ipak odgovarati opsegu neprivilegovanih UID-ova na hostu. To znači da se proces može ponašati kao root za mnoge zadatke unutar containera, dok je sa stanovišta hosta znatno manje moćan. Ovo ne rešava svaki problem sigurnosti containera, ali značajno menja posledice kompromitovanja containera.

## Rad

User namespace ima fajlove za mapiranje kao što su `/proc/self/uid_map` i `/proc/self/gid_map` koji opisuju kako se namespace ID-jevi prevode u parent ID-jeve. Ako root unutar namespace-a mapira na neprivilegovani host UID, onda operacije koje bi zahtevale stvarni host root jednostavno nemaju istu težinu. Zato su user namespaces centralni za **rootless containers** i predstavljaju jednu od najvećih razlika između starijih podrazumevanih rootful container-a i modernijih dizajna sa najmanjim privilegijama.

Poenta je suptilna ali ključna: root unutar containera nije eliminisan, on je **preveden**. Proces i dalje lokalno doživljava root-slično okruženje, ali host ne bi trebalo da ga tretira kao punog roota.

## Laboratorija

Jedan manuelni test je:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Ovo čini da trenutni korisnik izgleda kao root unutar namespace-a, dok i dalje nije host root izvan njega. To je jedan od najboljih jednostavnih demo primera za razumevanje zašto su user namespaces tako vredne.

U containers, možete uporediti vidljivo mapiranje sa:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Tačan izlaz zavisi od toga da li engine koristi user namespace remapping ili tradicionalniju rootful konfiguraciju.

Možete takođe pročitati mapiranje sa host strane pomoću:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Runtime Usage

Rootless Podman je jedan od najjasnijih primera kako se user namespaces tretiraju kao mehanizam bezbednosti prve klase. Rootless Docker takođe zavisi od njih. Docker-ova userns-remap podrška poboljšava bezbednost i u rootful daemon deploymentima, iako je istorijski mnogo deploymenta ostavljalo ovu opciju isključenom iz razloga kompatibilnosti. Kubernetes podrška za user namespaces se poboljšala, ali usvajanje i podrazumevana podešavanja variraju u zavisnosti od runtime-a, distro-a i cluster politike. Incus/LXC sistemi takođe uveliko zavise od UID/GID shifting i idmapping ideja.

## Advanced Mapping Details

Kada neprivilegovan proces upisuje u `uid_map` ili `gid_map`, kernel primenjuje strožija pravila nego za privilegovanog pisca u parent namespace-u. Dozvoljene su samo ograničene mape, i za `gid_map` pisac obično prvo mora onemogućiti `setgroups(2)`:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Ovaj detalj je važan zato što objašnjava zašto user-namespace setup ponekad ne uspeva u rootless eksperimentima i zašto runtimes trebaju pažljivu pomoćnu logiku oko delegiranja UID/GID.

Još jedna napredna funkcija je **ID-mapped mount**. Umesto menjanja vlasništva na disku, ID-mapped mount primenjuje mapiranje user-namespace na mount tako da vlasništvo izgleda prevedeno kroz taj prikaz mount-a. Ovo je posebno relevantno u rootless i modernim runtime podešavanjima jer omogućava korišćenje zajedničkih host putanja bez rekurzivnih `chown` operacija. Sa aspekta bezbednosti, ova funkcija menja kako se bind mount prikazuje kao upisiv iz unutrašnjosti namespace-a, iako ne prepisuje osnovne filesystem metapodatke.

Na kraju, imajte na umu da kada proces kreira ili uđe u novi user namespace, on dobija kompletan skup capabilities **unutar tog namespace-a**. To ne znači da je odjednom stekao globalnu moć na hostu. To znači da se te capabilities mogu koristiti samo tamo gde model namespace-a i druge zaštite to dozvoljavaju. Zato `unshare -U` može iznenada omogućiti mountovanje ili privilegovane operacije lokalne za namespace bez direktnog uklanjanja host root granice.

## Misconfigurations

Glavna slabost je jednostavno neupotreba user namespaces u okruženjima gde bi one bile moguće. Ako container root mapira previše direktno na host root, pisivi host mountovi i privilegovane kernel operacije postaju znatno opasnije. Drugi problem je forsiranje deljenja host user namespace-a ili onemogućavanje remapiranja radi kompatibilnosti, bez prepoznavanja koliko to menja granicu poverenja.

User namespaces takođe treba posmatrati zajedno sa ostatkom modela. Čak i kada su aktivne, široko izlaganje runtime API-ja ili vrlo slaba runtime konfiguracija i dalje mogu omogućiti eskalaciju privilegija drugim putem. Ali bez njih, mnoge stare klase breakout-a postaju mnogo lakše za iskorišćavanje.

## Abuse

Ako je container rootful bez odvajanja user namespace-a, pisivi host bind mount postaje znatno opasniji jer proces zaista može pisati kao host root. Opasne capabilities takođe postaju značajnije. Napadač više ne mora toliko da se bori protiv granice prevoda (translation boundary) jer ta granica gotovo ne postoji.

Prisustvo ili odsustvo user namespace-a treba proveriti rano prilikom procene puta za breakout iz containera. To ne odgovara na svako pitanje, ali odmah pokazuje da li "root in container" ima direktnu relevantnost za host.

Najpraktičniji obrazac zloupotrebe je potvrditi mapiranje i zatim odmah testirati da li je sadržaj mountovan sa hosta upisiv sa privilegijama relevantnim za host:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Ako je fajl kreiran kao real host root, izolacija user namespace-a je efektivno odsutna za taj put. U tom trenutku, klasične host-file zloupotrebe postaju realistične:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Bezbednija potvrda tokom procene uživo je upisivanje bezopasnog markera umesto menjanja kritičnih datoteka:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Ove provere su važne jer brzo odgovaraju na stvarno pitanje: da li se root u ovom containeru mapira dovoljno blizu host root-a da writable host mount odmah postane putanja ka kompromitovanju hosta?

### Potpun primer: Povraćanje namespace-local capabilities

Ako seccomp dozvoli `unshare` i okruženje dozvoljava novi user namespace, proces može povratiti kompletan skup capabilities unutar tog novog namespace-a:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Ovo samo po sebi nije host escape. Razlog zbog kojeg je to važno je što user namespaces mogu ponovo omogućiti privileged namespace-local actions koje se kasnije kombinuju sa weak mounts, vulnerable kernels, ili loše izloženim runtime surfaces.

## Checks

Ove komande služe da odgovore na najvažnije pitanje na ovoj stranici: na šta root unutar ovog container mapira na hostu?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Šta je ovde interesantno:

- Ako je proces UID 0 i mapiranja pokazuju direktno ili vrlo blisko mapiranje na root hosta, kontejner je mnogo opasniji.
- Ako se root mapira na neprivilegovan opseg na hostu, to je znatno sigurnija polazna tačka i obično ukazuje na pravu izolaciju user namespace-a.
- Fajlovi za mapiranje su vredniji od `id` samog, zato što `id` pokazuje samo namespace-lokalni identitet.

Ako workload radi kao UID 0 i mapiranje pokazuje da to odgovara blisko root-u na hostu, treba da tretirate ostatak privilegija kontejnera mnogo strože.
{{#include ../../../../../banners/hacktricks-training.md}}
