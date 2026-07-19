# Korisnički namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

Korisnički namespace menja značenje ID-jeva korisnika i grupa tako što omogućava kernelu da mapira ID-jeve vidljive unutar namespace-a na drugačije ID-jeve izvan njega. Ovo je jedna od najvažnijih modernih zaštita container-a, jer direktno rešava najveći istorijski problem klasičnih container-a: **root unutar container-a je ranije bio neprijatno blizu root-a na host-u**.

Uz user namespace, proces može da radi kao UID 0 unutar container-a, a da i dalje odgovara neprivilegovanom opsegu UID-jeva na host-u. To znači da proces može da se ponaša kao root za mnoge zadatke unutar container-a, dok je sa stanovišta host-a mnogo manje moćan. Ovo ne rešava svaki problem bezbednosti container-a, ali značajno menja posledice kompromitovanja container-a.

## Rad

User namespace ima mapping fajlove kao što su `/proc/self/uid_map` i `/proc/self/gid_map`, koji opisuju kako se ID-jevi namespace-a prevode u ID-jeve parent-a. Ako se root unutar namespace-a mapira na neprivilegovani UID na host-u, operacije koje bi zahtevale stvarni root na host-u jednostavno nemaju istu težinu. Zbog toga su user namespace-i ključni za **rootless containers** i predstavljaju jednu od najvećih razlika između starijih rootful podrazumevanih podešavanja container-a i modernijih dizajna sa principom najmanjih privilegija.

Poenta je suptilna, ali ključna: root unutar container-a nije uklonjen, već je **preveden**. Proces i dalje lokalno ima root-like okruženje, ali host ne bi trebalo da ga tretira kao puni root.

## Lab

Ručni test je:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Ovo čini da se trenutni korisnik unutar namespace-a prikazuje kao root, dok i dalje nije host root izvan njega. To je jedna od najboljih jednostavnih demonstracija za razumevanje toga zašto su user namespaces toliko vredni.

U containerima možete uporediti vidljivo mapiranje pomoću:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Tačan izlaz zavisi od toga da li engine koristi remapiranje user namespace-a ili tradicionalniju rootful konfiguraciju.

Mapiranje možete pročitati i sa strane hosta koristeći:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Upotreba tokom izvršavanja

Rootless Podman je jedan od najjasnijih primera tretiranja user namespaces kao prvoklasnog bezbednosnog mehanizma. Rootless Docker takođe zavisi od njih. Docker-ova podrška za userns-remap dodatno poboljšava bezbednost rootful daemon deployment-a, iako su je mnogi deployment-i istorijski ostavljali onemogućenu zbog razloga kompatibilnosti. Kubernetes podrška za user namespaces se poboljšala, ali se usvajanje i podrazumevane vrednosti razlikuju u zavisnosti od runtime-a, distro-a i cluster policy-ja. Incus/LXC sistemi se takođe u velikoj meri oslanjaju na pomeranje UID/GID vrednosti i idmapping koncepte.

Opšti trend je jasan: okruženja koja ozbiljno koriste user namespaces obično daju bolji odgovor na pitanje „šta container root zapravo znači?“ od okruženja koja ih ne koriste.

## Napredni detalji mapiranja

Kada unprivileged proces upisuje u `uid_map` ili `gid_map`, kernel primenjuje stroža pravila nego kada to radi privileged writer iz parent namespace-a. Dozvoljena su samo ograničena mapiranja, a za `gid_map` writer obično prvo mora da onemogući `setgroups(2)`:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Ovaj detalj je važan jer objašnjava zašto podešavanje user namespace-a ponekad ne uspeva u rootless eksperimentima i zašto runtime-i zahtevaju pažljivu pomoćnu logiku za delegiranje UID/GID vrednosti.

Još jedna napredna funkcija je **ID-mapped mount**. Umesto menjanja vlasništva na disku, ID-mapped mount primenjuje mapiranje user namespace-a na mount, tako da se vlasništvo prikazuje prevedeno kroz taj prikaz mount-a. Ovo je naročito relevantno u rootless i modernim runtime podešavanjima, jer omogućava korišćenje deljenih host putanja bez rekurzivnih `chown` operacija. Sa bezbednosne strane, ova funkcija menja koliko se writable bind mount čini iz namespace-a, iako ne menja osnovne metapodatke filesystem-a.

Na kraju, imajte na umu da proces koji kreira ili ulazi u novi user namespace dobija kompletan skup capabilities **unutar tog namespace-a**. To ne znači da je iznenada dobio host-globalne privilegije. To znači da se te capabilities mogu koristiti samo tamo gde ih namespace model i druge zaštite dozvoljavaju. Zbog toga `unshare -U` može iznenada omogućiti mount operacije ili privilegovane operacije lokalne za namespace, a da se pritom direktno ne ukloni root granica host-a.

## Pogrešna podešavanja

Glavna slabost je jednostavno nekorišćenje user namespace-a u okruženjima u kojima bi to bilo izvodljivo. Ako se container root mapira direktno na host root, writable host mount-ovi i privilegovane kernel operacije postaju znatno opasniji. Drugi problem je forsiranje deljenja host user namespace-a ili onemogućavanje remap-ovanja radi kompatibilnosti, bez razumevanja koliko to menja granicu poverenja.

User namespace-i takođe moraju da se posmatraju zajedno sa ostatkom modela. Čak i kada su aktivni, široka izloženost runtime API-ja ili veoma slaba runtime konfiguracija i dalje mogu omogućiti privilege escalation kroz druge putanje. Ali bez njih, mnoge stare klase breakout-a postaju znatno lakše za eksploataciju.

## Zloupotreba

Ako je container rootful bez razdvajanja user namespace-a, writable host bind mount postaje mnogo opasniji jer proces možda zaista upisuje kao host root. Opasne capabilities takođe postaju značajnije. Napadač više ne mora toliko da se bori protiv granice prevođenja, jer ta granica gotovo da ne postoji.

Prisustvo ili odsustvo user namespace-a treba proveriti na početku procene puta za container breakout. To ne daje odgovor na svako pitanje, ali odmah pokazuje da li „root u container-u“ ima direktan značaj za host.

Najpraktičniji obrazac zloupotrebe jeste potvrditi mapiranje i zatim odmah proveriti da li je sadržaj montiran sa host-a writable sa privilegijama relevantnim za host:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Ako je datoteka kreirana kao stvarni root hosta, izolacija user namespace-a je praktično odsutna za tu putanju. Tada klasične zloupotrebe datoteka na hostu postaju realne:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Bezbednija potvrda tokom aktivne procene jeste upisivanje bezopasnog markera umesto izmene kritičnih fajlova:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Ove provere su važne jer brzo daju odgovor na pravo pitanje: da li se root u ovom containeru dovoljno blisko mapira na root na hostu da writable host mount odmah postane put do kompromitovanja hosta?

### Potpuni primer: Ponovno sticanje capabilities lokalnih za namespace

Ako seccomp dozvoljava `unshare`, a okruženje omogućava kreiranje novog user namespace-a, proces može ponovo da stekne kompletan skup capabilities unutar tog novog namespace-a:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Ovo samo po sebi nije host escape. Važno je zato što user namespaces mogu ponovo omogućiti privilegovane radnje lokalne za namespace, koje se kasnije kombinuju sa slabim mount-ovima, ranjivim kernelima ili neadekvatno izloženim runtime površinama.

## Provere

Ove komande treba da odgovore na najvažnije pitanje na ovoj stranici: na šta se root unutar ovog containera mapira na hostu?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Šta je ovde važno:

- Ako je proces UID 0, a mape pokazuju direktno ili veoma blisko mapiranje na host root, kontejner je mnogo opasniji.
- Ako se root mapira na neprivilegovani opseg na hostu, to je mnogo bezbednija osnova i obično ukazuje na stvarnu izolaciju user namespace-a.
- Datoteke mapiranja su korisnije od samog `id`, jer `id` prikazuje samo identitet lokalni za namespace.

Ako workload radi kao UID 0, a mapiranje pokazuje da to približno odgovara root-u na hostu, privilegije ostatka kontejnera treba tumačiti mnogo strože.
{{#include ../../../../../banners/hacktricks-training.md}}
