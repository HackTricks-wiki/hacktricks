# User Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Pregled

User namespace menja značenje ID-jeva korisnika i grupa tako što omogućava kernelu da mapira ID-jeve vidljive unutar namespace-a na drugačije ID-jeve izvan njega. Ovo je jedna od najvažnijih modernih zaštita container-a, jer se direktno bavi najvećim istorijskim problemom klasičnih container-a: **root unutar container-a bio je neprijatno blizu root-u na host-u**.

Uz user namespace, proces može da radi kao UID 0 unutar container-a, a da i dalje odgovara neprivilegovanom opsegu UID-jeva na host-u. To znači da proces može da se ponaša kao root za mnoge zadatke unutar container-a, dok je sa stanovišta host-a mnogo manje moćan. Ovo ne rešava svaki security problem container-a, ali značajno menja posledice kompromitovanja container-a.

## Rad

User namespace ima mapping fajlove kao što su `/proc/self/uid_map` i `/proc/self/gid_map`, koji opisuju kako se ID-jevi namespace-a prevode u ID-jeve parent-a. Ako se root unutar namespace-a mapira na neprivilegovani UID host-a, operacije koje bi zahtevale stvarni root na host-u jednostavno nemaju istu težinu. Zbog toga su user namespace-i ključni za **rootless containers** i predstavljaju jednu od najvećih razlika između starijih rootful podrazumevanih podešavanja container-a i modernijih dizajna zasnovanih na principu najmanjih privilegija.

Poenta je suptilna, ali ključna: root unutar container-a nije uklonjen, već je **preveden**. Proces i dalje lokalno ima okruženje slično root-u, ali host ne bi trebalo da ga tretira kao potpunog root-a.

## Lab

Ručni test je:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Ovo čini da se trenutni korisnik unutar namespace-a prikazuje kao root, dok i dalje nije host root izvan njega. To je jedan od najboljih jednostavnih primera za razumevanje zašto su user namespaces toliko vredni.

U kontejnerima možete uporediti vidljivo mapiranje sa:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Tačan izlaz zavisi od toga da li engine koristi user namespace remapping ili tradicionalniju rootful konfiguraciju.

Mapiranje možete pročitati i sa host strane pomoću:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Korišćenje tokom izvršavanja

Rootless Podman je jedan od najjasnijih primera tretiranja user namespaces kao prvoklasnog security mehanizma. Rootless Docker takođe zavisi od njih. Docker-ova podrška za userns-remap poboljšava bezbednost i u rootful daemon deployment-ima, iako su ih mnogi deployment-i istorijski ostavljali onemogućene zbog razloga kompatibilnosti. Kubernetes podrška za user namespaces se poboljšala, ali se usvajanje i podrazumevane vrednosti razlikuju u zavisnosti od runtime-a, distro-a i cluster policy-ja. Incus/LXC sistemi se takođe u velikoj meri oslanjaju na pomeranje UID/GID vrednosti i ideje idmapping-a.

Opšti trend je jasan: okruženja koja ozbiljno koriste user namespaces obično daju bolji odgovor na pitanje „šta container root zapravo znači?“ od okruženja koja ih ne koriste.

## Napredni detalji mapiranja

Kada unprivileged proces upisuje u `uid_map` ili `gid_map`, kernel primenjuje stroža pravila nego kada to radi privileged writer iz parent namespace-a. Dozvoljena su samo ograničena mapiranja, a za `gid_map` writer obično prvo mora da onemogući `setgroups(2)`:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Ovaj detalj je važan jer objašnjava zašto podešavanje user namespace-a ponekad ne uspeva u rootless eksperimentima i zašto runtime-ima treba pažljivo implementirana pomoćna logika za delegiranje UID/GID vrednosti.

Još jedna napredna funkcija je **ID-mapped mount**. Umesto menjanja vlasništva na disku, ID-mapped mount primenjuje user-namespace mapiranje na mount, tako da se vlasništvo prikazuje prevedeno kroz taj mount view. Ovo je naročito relevantno u rootless i modernim runtime podešavanjima, jer omogućava korišćenje deljenih host putanja bez rekurzivnih `chown` operacija. Sa bezbednosne strane, ova funkcija menja kako writable bind mount izgleda iz namespace-a, iako ne menja osnovne metapodatke filesystem-a.

Na kraju, imajte na umu da proces, kada kreira ili uđe u novi user namespace, dobija kompletan capability set **unutar tog namespace-a**. To ne znači da je iznenada dobio globalne privilegije na hostu. To znači da se ti capabilities mogu koristiti samo tamo gde ih namespace model i druge zaštite dozvoljavaju. Zbog toga `unshare -U` može iznenada omogućiti mount operacije ili privilegovane operacije lokalne za namespace, a da se pritom direktno ne ukloni root granica hosta.

## Pogrešna podešavanja

Glavna slabost je jednostavno nekorišćenje user namespace-a u okruženjima u kojima bi to bilo izvodljivo. Ako se container root mapira direktno na host root, writable host mount-ovi i privilegovane kernel operacije postaju znatno opasniji. Drugi problem je forsiranje deljenja user namespace-a hosta ili onemogućavanje remapping-a radi kompatibilnosti, bez razumevanja koliko to menja granicu poverenja.

User namespace-i se takođe moraju posmatrati zajedno sa ostatkom modela. Čak i kada su aktivni, široka izloženost runtime API-ja ili veoma slaba runtime konfiguracija i dalje mogu omogućiti privilege escalation kroz druge putanje. Međutim, bez njih mnoge stare breakout klase postaju znatno lakše za eksploataciju.

## Zloupotreba

Ako je container rootful bez user namespace separacije, writable host bind mount postaje mnogo opasniji jer proces zaista može pisati kao host root. Opasni capabilities takođe postaju značajniji. Napadač više ne mora toliko da se bori protiv translation boundary-ja, jer ta granica gotovo da ne postoji.

Prisustvo ili odsustvo user namespace-a treba proveriti rano prilikom procene container breakout putanje. To ne daje odgovor na svako pitanje, ali odmah pokazuje da li `"root in container"` ima direktan značaj na hostu.

Najpraktičniji obrazac zloupotrebe jeste potvrditi mapiranje i zatim odmah proveriti da li je sadržaj montiran sa hosta writable uz privilegije relevantne za host:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Ako je datoteka kreirana kao stvarni host root, izolacija user namespace-a praktično ne postoji za tu putanju. U tom trenutku, klasične zloupotrebe host datoteka postaju realne:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Pouzdanija potvrda tokom procene uživo jeste upisivanje bezopasnog markera umesto izmene kritičnih datoteka:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Ove provere su važne jer brzo daju odgovor na pravo pitanje: da li se root u ovom containeru mapira dovoljno blisko sa root-om na hostu tako da writable host mount odmah postane putanja ka kompromitaciji hosta?

### Kompletan primer: Ponovno dobijanje namespace-local capabilities

Ako seccomp dozvoljava `unshare` i okruženje omogućava kreiranje novog user namespace-a, proces može ponovo dobiti kompletan skup capabilities unutar tog novog namespace-a:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Ovo samo po sebi nije host escape. Važno je zato što user namespaces mogu ponovo omogućiti privilegovane radnje lokalne za namespace, koje se kasnije kombinuju sa slabim mount-ovima, ranjivim kernelima ili loše izloženim runtime površinama.

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

- Ako je proces UID 0, a maps prikazuje direktno ili veoma blisko mapiranje ka host-root, container je mnogo opasniji.
- Ako se root mapira na neprivilegovani host opseg, to predstavlja mnogo bezbedniju osnovu i obično ukazuje na stvarnu user namespace izolaciju.
- Datoteke mapiranja su vrednije od samog `id`, jer `id` prikazuje samo identitet lokalni za namespace.

Ako workload radi kao UID 0, a mapiranje pokazuje da to približno odgovara root-u na hostu, ostale privilegije container-a treba tumačiti mnogo strože.

{{#include ../../../../../banners/hacktricks-training.md}}
