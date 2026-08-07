# Bezbednost image-a, potpisivanje i secrets

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Bezbednost container-a počinje pre pokretanja workload-a. Image određuje koji binarni fajlovi, interpreter-i, biblioteke, startup skripte i ugrađena konfiguracija dospevaju u production. Ako image sadrži backdoor, zastareo je ili je izgrađen tako da su secrets ugrađeni u njega, hardening runtime-a koji sledi već deluje nad kompromitovanim artifact-om.

Zato provenance image-a, skeniranje ranjivosti, verifikacija potpisa i rukovanje secrets-ima treba da budu deo iste diskusije kao namespaces i seccomp. Oni štite drugu fazu lifecycle-a, ali propusti na ovom mestu često definišu attack surface koji runtime kasnije mora da ograniči.

## Registri image-a i poverenje

Image-i mogu poticati iz javnih registara kao što je Docker Hub ili iz privatnih registara kojima upravlja organizacija. Bezbednosno pitanje nije samo gde se image nalazi, već da li tim može da utvrdi provenance i integritet. Preuzimanje nepotpisanih ili nedovoljno praćenih image-a iz javnih izvora povećava rizik od ulaska malicious ili izmenjenog sadržaja u production. Čak i interno hostovani registri zahtevaju jasno vlasništvo, review i trust policy.

Docker Content Trust je istorijski koristio koncepte Notary i TUF kako bi zahtevao potpisane image-e. Tačan ecosystem se razvijao, ali trajna lekcija ostaje korisna: identitet i integritet image-a treba da budu proverljivi, a ne podrazumevani.

Primer istorijskog Docker Content Trust workflow-a:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Poenta primera nije u tome da svaki tim i dalje mora da koristi iste alate, već da su potpisivanje i upravljanje ključevima operativni zadaci, a ne apstraktna teorija.

## Skeniranje ranjivosti

Skeniranje image-a pomaže u odgovoru na dva različita pitanja. Prvo, da li image sadrži poznate ranjive pakete ili biblioteke? Drugo, da li image sadrži nepotreban software koji proširuje attack surface? Image prepun debugging alata, shell-ova, interpretera i zastarelih paketa lakše je exploitovati i teže ga je analizirati.

Primeri često korišćenih skenera uključuju:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Rezultate ovih alata treba pažljivo tumačiti. Ranjivost u nekorišćenom package-u nema isti rizik kao izložena RCE putanja, ali su obe i dalje relevantne za odluke o hardening-u.

## Tajne tokom build-a

Jedna od najstarijih grešaka u container build pipeline-ovima jeste direktno ugrađivanje secrets-a u image ili njihovo prosleđivanje kroz environment variables, koji kasnije postaju vidljivi kroz `docker inspect`, build logove ili obnovljene layer-e. Build-time secrets treba montirati privremeno tokom build-a, umesto kopiranja u filesystem image-a.

BuildKit je unapredio ovaj model tako što je omogućio namensko rukovanje build-time secrets-ima. Umesto upisivanja secret-a u layer, build korak može privremeno da ga koristi:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Ovo je važno zato što su image layers trajni artefakti. Kada secret jednom uđe u committed layer, njegovo kasnije brisanje iz fajla u drugom layeru ne uklanja zaista prvobitno otkrivanje iz istorije image-a.

## Runtime Secrets

Secrets potrebni pokrenutom workload-u takođe treba da izbegavaju ad hoc obrasce, kao što su plain environment variables, kad god je to moguće. Volumes, dedicated secret-management integrations, Docker secrets i Kubernetes Secrets predstavljaju uobičajene mehanizme. Nijedan od njih ne uklanja sav rizik, naročito ako attacker već ima code execution u workload-u, ali su ipak bolji od trajnog čuvanja credentials u image-u ili njihovog nepažljivog izlaganja kroz inspection tooling.

Jednostavna deklaracija secret-a u Docker Compose stilu izgleda ovako:
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
U Kubernetes-u, Secret objekti, projected volumes, service-account tokeni i cloud workload identities stvaraju širi i moćniji model, ali takođe stvaraju više mogućnosti za slučajno izlaganje putem host mount-ova, preširokog RBAC-a ili lošeg Pod dizajna.

## Abuse

Prilikom pregleda targeta, cilj je otkriti da li su secrets ugrađeni u image, leakovani u layer-e ili mountovani na predvidive runtime lokacije:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Ove komande pomažu da se napravi razlika između tri različita problema: leak-ova konfiguracije aplikacije, leak-ova slojeva image-a i runtime-injektovanih secret fajlova. Ako se secret pojavi u `/run/secrets`, projektovanom volume-u ili putanji tokena cloud identiteta, sledeći korak je utvrđivanje da li omogućava pristup samo trenutnom workload-u ili mnogo širem control plane-u.

### Potpun primer: Embedded Secret u Image Filesystem-u

Ako je build pipeline kopirao `.env` fajlove ili credential-e u finalni image, post-exploitation postaje jednostavan:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Uticaj zavisi od aplikacije, ali ugrađeni signing keys, JWT secrets ili cloud credentials lako mogu pretvoriti kompromitovanje kontejnera u kompromitovanje API-ja, lateral movement ili falsifikovanje trusted application tokens.

### Full Example: Provera leak-a tajni tokom build-a

Ako postoji bojazan da je istorija image-a zabeležila sloj koji sadrži secret:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Ova vrsta pregleda je korisna zato što je secret možda obrisan iz konačnog prikaza filesystem-a, ali je i dalje ostao u ranijem layer-u ili build metadata-i.

## Provere

Ove provere imaju za cilj da utvrde da li su image i pipeline za rukovanje secret-ima verovatno povećali attack surface pre pokretanja.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Šta je ovde zanimljivo:

- Sumnjiva istorija build procesa može otkriti kopirane kredencijale, SSH materijal ili nebezbedne korake build procesa.
- Secrets u putanjama projected volume-a mogu omogućiti pristup clusteru ili cloud-u, a ne samo pristup lokalnoj aplikaciji.
- Veliki broj konfiguracionih fajlova sa kredencijalima u plaintextu obično ukazuje na to da image ili model deployment-a prenosi više materijala za poverenje nego što je neophodno.

## Podrazumevane vrednosti tokom izvršavanja

| Runtime / platforma | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker / BuildKit | Podržava bezbedne secret mounts tokom build procesa, ali ne automatski | Secrets se mogu privremeno mountovati tokom `build` procesa; image signing i scanning zahtevaju eksplicitne odluke u workflow-u | kopiranje secrets u image, prosleđivanje secrets pomoću `ARG` ili `ENV`, isključivanje provenance provera |
| Podman / Buildah | Podržava OCI-native build procese i workflow-e koji koriste secrets | Dostupni su bezbedni build workflow-i, ali operatori i dalje moraju namerno da ih izaberu | ugrađivanje secrets u Containerfiles, široki build contexts, previše dozvoljeni bind mounts tokom build procesa |
| Kubernetes | Native Secret objekti i projected volumes | Runtime dostavljanje secrets je first-class funkcionalnost, ali izloženost zavisi od RBAC-a, dizajna pod-a i host mount-ova | preširoki Secret mount-ovi, zloupotreba service-account tokena, `hostPath` pristup volume-ima kojima upravlja kubelet |
| Registries | Integritet je opcion, osim ako se ne zahteva | I public i private registries zavise od policy-ja, signing-a i admission odluka | slobodno preuzimanje unsigned images, slaba admission kontrola, loše upravljanje ključevima |

{{#include ../../../banners/hacktricks-training.md}}
