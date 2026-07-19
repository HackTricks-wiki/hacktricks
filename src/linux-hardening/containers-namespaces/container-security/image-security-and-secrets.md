# Security, Potpisivanje I Secrets U Image-ima

{{#include ../../../banners/hacktricks-training.md}}

## Registri Image-a I Poverenje

Security kontejnera počinje pre pokretanja workload-a. Image određuje koji binarni fajlovi, interpreter-i, biblioteke, startup skripte i ugrađena konfiguracija dospevaju u production. Ako image sadrži backdoor, zastareo je ili je izgrađen tako da su secrets ugrađeni u njega, runtime hardening koji sledi već radi nad kompromitovanim artifact-om.

Zato provenance image-a, vulnerability scanning, signature verification i rukovanje secrets-ima treba posmatrati u istom kontekstu kao namespaces i seccomp. Oni štite drugu fazu lifecycle-a, ali propusti ovde često definišu attack surface koji runtime kasnije mora da ograniči.

## Registri Image-a I Poverenje

Image-i mogu dolaziti iz javnih registara kao što je Docker Hub ili iz privatnih registara kojima upravlja organizacija. Security pitanje nije samo gde se image nalazi, već da li tim može da utvrdi provenance i integrity. Preuzimanje unsigned ili loše praćenih image-a iz javnih izvora povećava rizik da malicious ili tampered sadržaj dospe u production. Čak i interno hostovani registri zahtevaju jasno vlasništvo, review i trust policy.

Docker Content Trust je istorijski koristio Notary i TUF koncepte za zahtev da image-i budu signed. Tačan ekosistem se vremenom razvijao, ali trajna lekcija ostaje korisna: identity i integrity image-a treba da budu verifiable, a ne podrazumevane.

Primer istorijskog Docker Content Trust workflow-a:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Poenta primera nije u tome da svaki tim i dalje mora da koristi iste alate, već u tome da su potpisivanje i upravljanje ključevima operativni zadaci, a ne apstraktna teorija.

## Skeniranje ranjivosti

Skeniranje image-a pomaže u odgovoru na dva različita pitanja. Prvo, da li image sadrži poznate ranjive pakete ili biblioteke? Drugo, da li image sadrži nepotreban softver koji proširuje napadnu površinu? Image prepun debugging alata, shell-ova, interpreter-a i zastarelih paketa lakše je iskoristiti i teže analizirati.

Primeri često korišćenih scanner-a uključuju:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Rezultate ovih alata treba pažljivo tumačiti. Vulnerability u nekorišćenom package-u nema isti nivo rizika kao izložena RCE putanja, ali su obe i dalje relevantne za odluke o hardeningu.

## Tajne tokom build-a

Jedna od najstarijih grešaka u container build pipeline-ovima jeste direktno ugrađivanje tajni u image ili njihovo prosleđivanje kroz environment variables, koje kasnije postaju vidljive putem `docker inspect`, build logova ili obnovljenih layer-a. Tajne tokom build-a treba ephemerally montirati tokom build-a, umesto da se kopiraju u filesystem image-a.

BuildKit je unapredio ovaj model tako što je omogućio namensko rukovanje tajnama tokom build-a. Umesto upisivanja tajne u layer, build korak može privremeno da je koristi:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Ovo je važno zato što su slojevi image-a trajni artifacts. Kada se tajna jednom nađe u commitovanom sloju, kasnije brisanje fajla u drugom sloju ne uklanja zaista prvobitno otkrivanje iz istorije image-a.

## Tajne tokom izvršavanja

Tajne koje su potrebne workload-u koji radi takođe bi trebalo da izbegavaju ad hoc obrasce, kao što su obične environment variables, kad god je to moguće. Volumes, namenske integracije za upravljanje tajnama, Docker secrets i Kubernetes Secrets predstavljaju uobičajene mehanizme. Nijedan od njih ne uklanja sav rizik, naročito ako attacker već ima code execution u workload-u, ali su i dalje bolji od trajnog čuvanja credentials-a u image-u ili njihovog nepažljivog izlaganja kroz inspection tooling.

Jednostavna deklaracija tajne u stilu Docker Compose-a izgleda ovako:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
U Kubernetes-u, Secret objekti, projektovani volumeni, service-account tokeni i cloud workload identiteti stvaraju širi i moćniji model, ali takođe stvaraju više mogućnosti za slučajno izlaganje putem host mount-ova, preširokog RBAC-a ili lošeg dizajna Pod-ova.

## Zloupotreba

Prilikom pregleda targeta, cilj je utvrditi da li su secrets ugrađeni u image, leak-ovani u layers ili mount-ovani u predvidive runtime lokacije:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Ove komande pomažu da se razlikuju tri različita problema: leak-ovi konfiguracije aplikacije, leak-ovi u slojevima image-a i runtime-injektovani fajlovi sa secrets. Ako se secret pojavi u `/run/secrets`, project-ovanom volume-u ili na putanji tokena cloud identiteta, sledeći korak je da se utvrdi da li omogućava pristup samo trenutnom workload-u ili mnogo većem control plane-u.

### Kompletan primer: Secret ugrađen u filesystem image-a

Ako je build pipeline kopirao `.env` fajlove ili credentials u finalni image, post-exploitation postaje jednostavan:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Uticaj zavisi od aplikacije, ali ugrađeni signing keys, JWT secrets ili cloud credentials lako mogu pretvoriti kompromitovanje container-a u kompromitovanje API-ja, lateral movement ili falsifikovanje trusted application tokens.

### Potpun primer: provera Secret Leak-a tokom build-a

Ako postoji zabrinutost da je istorija image-a zabeležila layer koji sadrži secret:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Ova vrsta pregleda je korisna zato što je tajna možda obrisana iz konačnog prikaza sistema datoteka, ali je i dalje prisutna u ranijem sloju ili u metapodacima build-a.

## Provere

Ove provere imaju za cilj da utvrde da li su image i pipeline za rukovanje tajnama verovatno povećali attack surface pre pokretanja.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Šta je ovde interesantno:

- Sumnjiva istorija build procesa može otkriti kopirane credentials, SSH materijal ili unsafe build korake.
- Secrets u putanjama projektovanih volume-a mogu omogućiti pristup klasteru ili cloud-u, a ne samo pristup lokalnoj aplikaciji.
- Veliki broj configuration fajlova sa credentials u plaintext obliku obično ukazuje na to da image ili deployment model sadrži više materijala poverenja nego što je neophodno.

## Podrazumevane Runtime vrednosti

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker / BuildKit | Podržava bezbedne build-time secret mount-ove, ali ne automatski | Secrets se mogu privremeno mount-ovati tokom `build` procesa; image signing i scanning zahtevaju eksplicitne odluke u workflow-u | kopiranje secrets u image, prosleđivanje secrets pomoću `ARG` ili `ENV`, onemogućavanje provera provenance-a |
| Podman / Buildah | Podržava OCI-native build-ove i workflow-e koji uzimaju secrets u obzir | Dostupni su strong build workflow-i, ali operateri i dalje moraju namerno da ih izaberu | ugrađivanje secrets u Containerfile-ove, široki build context-i, permisivni bind mount-ovi tokom build procesa |
| Kubernetes | Native Secret objekti i projektovani volume-i | Runtime isporuka secrets je first-class, ali izloženost zavisi od RBAC-a, dizajna pod-a i host mount-ova | preširoki Secret mount-ovi, zloupotreba service-account tokena, `hostPath` pristup volume-ima kojima upravlja kubelet |
| Registries | Integritet je opcionalan osim ako nije nametnut | Public i private registries zavise od policy-ja, signing-a i admission odluka | slobodno povlačenje unsigned images, slaba admission kontrola, loše upravljanje ključevima |
{{#include ../../../banners/hacktricks-training.md}}
