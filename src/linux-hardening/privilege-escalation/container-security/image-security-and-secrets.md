# Bezbednost image-a, potpisivanje i tajne

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Bezbednost kontejnera počinje pre nego što se workload pokrene. Image određuje koji binarni fajlovi, interpreteri, biblioteke, startup skripte i ugrađena konfiguracija dospevaju u produkciju. Ako je image backdoored, zastareo ili izgrađen sa tajnama ubačenim u njega, runtime hardening koji sledi već radi nad kompromitovanim artefaktom.

Zato image provenance, vulnerability scanning, signature verification i secret handling spadaju u istu raspravu kao namespaces i seccomp. Oni štite drugačiju fazu životnog ciklusa, ali propusti ovde često definišu površinu napada koju runtime kasnije mora da ograniči.

## Image Registries And Trust

Images mogu doći iz javnih registara kao što je Docker Hub ili iz privatnih registara kojima upravlja organizacija. Bezbednosno pitanje nije samo gde se image nalazi, već da li tim može utvrditi poreklo i integritet. Preuzimanje nepotpisanih ili slabo praćenih image-a sa javnih izvora povećava rizik da maliciozni ili izmenjeni sadržaj dospe u produkciju. Čak i interno hostovani registri zahtevaju jasno vlasništvo, reviziju i politiku poverenja.

Docker Content Trust istorijski je koristio Notary i TUF koncepte da zahteva potpisane image-e. Tačan ekosistem se razvio, ali trajna lekcija ostaje korisna: identitet i integritet image-a treba da budu proverljivi, a ne podrazumevani.

Primer istorijskog Docker Content Trust workflow-a:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Poenta primera nije da svaki tim mora da koristi iste alate, već da su potpisivanje i upravljanje ključevima operativni zadaci, a ne apstraktna teorija.

## Skeniranje ranjivosti

Skeniranje image-a pomaže da se odgovore dva različita pitanja. Prvo — da li image sadrži poznate ranjive pakete ili biblioteke? Drugo — da li image nosi nepotreban softver koji proširuje attack surface? Image prepun debugging tools, shells, interpreters i stale packages je i lakši za exploit и teži za razumevanje.

Primeri često korišćenih skenera uključuju:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Rezultate ovih alata treba pažljivo tumačiti. Ranljivost u neiskorišćenom paketu nije ista po riziku kao izložen RCE put, ali oba su i dalje relevantna za odluke o hardeningu.

## Tajne tokom build-a

Jedna od najstarijih grešaka u container build pipeline-ima je ugrađivanje tajni direktno u image ili njihovo prosleđivanje kroz environment varijable koje kasnije postaju vidljive kroz `docker inspect`, build logs, ili recovered layers. Tajne koje se koriste tokom build-a treba montirati privremeno tokom build-a umesto da se kopiraju u fajl-sistem image-a.

BuildKit je poboljšao ovaj model omogućavajući namensko rukovanje tajnama tokom build-a. Umesto upisivanja tajne u layer, build korak može privremeno iskoristiti tajnu:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Ovo je važno zato što su slojevi image-a trajni artefakti. Kada tajna dospe u komitovani sloj, kasnije brisanje fajla u drugom sloju zapravo ne uklanja prvobitno otkrivanje iz istorije image-a.

## Runtime Secrets

Tajne potrebne za pokrenuti workload takođe bi trebalo da izbegavaju ad hoc obrasce kao što su obične environment variables kad god je to moguće. Volumes, dedicated secret-management integrations, Docker secrets i Kubernetes Secrets su uobičajeni mehanizmi. Nijedan od ovih ne uklanja sav rizik, naročito ako napadač već ima code execution u workload-u, ali su i dalje poželjniji od trajnog čuvanja kredencijala u image-u ili njihove olake izloženosti kroz inspection tooling.

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
U Kubernetesu, Secret objects, projected volumes, service-account tokens i cloud workload identities stvaraju širi i moćniji model, ali takođe otvaraju više prilika za slučajno izlaganje kroz host mounts, širok RBAC ili loš dizajn Pod-a.

## Zloupotreba

Prilikom pregleda cilja, svrha je otkriti da li su secrets bili ugrađeni u image, leaked u layers, ili montirani u predvidljive runtime lokacije:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Ove komande pomažu da se razlikuju tri različita problema: application configuration leaks, image-layer leaks, i runtime-injected secret files. Ako se secret pojavi pod `/run/secrets`, na projected volume, ili na putanji cloud identity token, sledeći korak je da se utvrdi da li on omogućava pristup samo trenutnom workload-u ili znatno većem control plane-u.

### Potpun primer: Ugrađeni secret u image filesystem

Ako je build pipeline kopirao `.env` fajlove ili kredencijale u finalni image, post-exploitation postaje jednostavno:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Uticaj zavisi od aplikacije, ali embedded signing keys, JWT secrets, ili cloud credentials lako mogu pretvoriti container compromise u API compromise, lateral movement ili forgery of trusted application tokens.

### Full Example: Build-Time Secret Leakage Check

Ako postoji zabrinutost da je image history zabeležio secret-bearing layer:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Ovakav pregled je koristan zato što secret može biti uklonjen iz konačnog prikaza filesystem-a, a ipak ostati u ranijem layer-u ili u build metadata.

## Provere

Ove provere imaju za cilj da utvrde da li image i secret-handling pipeline verovatno povećavaju attack surface pre runtime.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Šta je zanimljivo ovde:

- Sumnjiva build history može otkriti copied credentials, SSH material, ili unsafe build steps.
- Secrets ispod projected volume paths mogu dovesti do pristupa clusteru ili cloud-u, a ne samo do lokalnog pristupa aplikaciji.
- Velik broj configuration files sa plaintext credentials obično ukazuje da image ili deployment model nosi više trust material nego što je potrebno.

## Podrazumevana podešavanja runtime-a

| Runtime / platform | Podrazumevano stanje | Podrazumevano ponašanje | Uobičajeno ručno slabljenje |
| --- | --- | --- | --- |
| Docker / BuildKit | Podržava secure build-time secret mounts, ali ne automatski | Secrets se mogu montirati ephemerally tokom `build`; image signing i scanning zahtevaju eksplicitne odluke u workflow-u | copying secrets into the image, passing secrets by `ARG` or `ENV`, disabling provenance checks |
| Podman / Buildah | Podržava OCI-native builds i secret-aware workflows | Dostupni su snažni build workflow-i, ali operatori ih moraju namerno izabrati | embedding secrets in Containerfiles, broad build contexts, permissive bind mounts during builds |
| Kubernetes | Native Secret objects and projected volumes | Runtime delivery Secrets-a je first-class, ali izlaganje zavisi od RBAC, dizajna pod-a i host mounts | overbroad Secret mounts, service-account token misuse, `hostPath` access to kubelet-managed volumes |
| Registries | Integritet je opcion osim ako nije enforced | I javni i privatni registri zavise od policy, signing, i admission decisions | pulling unsigned images freely, weak admission control, poor key management |
