# Image bezbednost, potpisivanje i tajne

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Bezbednost kontejnera počinje pre nego što se workload pokrene. Image određuje koje binarije, interpretere, biblioteke, startup skripte i ugrađene konfiguracije stignu u produkciju. Ako je image kompromitovan, zastareo ili izgrađen sa ugrađenim tajnama, runtime hardening koji sledi već radi na kompromitovanom artefaktu.

Zato poreklo image-a, skeniranje ranjivosti, verifikacija potpisa i rukovanje tajnama treba da budu deo iste diskusije kao namespaces i seccomp. Oni štite drugu fazu životnog ciklusa, ali greške ovde često određuju napadnu površinu koju runtime kasnije mora da sadrži.

## Registri image-a i poverenje

Image-i mogu da stižu iz javnih registara kao što je Docker Hub ili iz privatnih registara kojima upravlja organizacija. Bezbednosno pitanje nije samo gde image živi, već da li tim može da utvrdi poreklo i integritet. Povlačenje nepotpisanih ili loše praćenih image-a iz javnih izvora povećava rizik da maliciozni ili manipulisan sadržaj uđe u produkciju. Čak i interno hostovani registri trebaju jasno vlasništvo, pregled i politiku poverenja.

Docker Content Trust je istorijski koristio Notary i TUF koncepte da zahteva potpisane image-e. Tačan ekosistem se razvio, ali trajan pouka ostaje korisna: identitet i integritet image-a treba da budu proverljivi, a ne podrazumevani.

Primer istorijskog Docker Content Trust workflow-a:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Poenta primera nije u tome da svaki tim mora da koristi isti tooling, već da su signing i key management operativni zadaci, a ne apstraktna teorija.

## Skeniranje ranjivosti

Skeniranje image-a pomaže da se odgovore na dva različita pitanja. Prvo, da li image sadrži poznate ranjive pakete ili biblioteke? Drugo, da li image sadrži nepotreban softver koji proširuje attack surface? Image prepun debugging tools, shells, interpreters i zastarelih paketa je i lakši za exploit i teže ga je razumeti.

Primeri često korišćenih skenera uključuju:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Rezultate ovih alata treba tumačiti pažljivo. Ranljivost u neiskorišćenom paketu nije ista po riziku kao izložen RCE put, ali oba su i dalje relevantna za odluke o hardeningu.

## Tajne tokom build-a

Jedna od najčešćih grešaka u container build pipeline-ima je ugrađivanje tajni direktno u image ili njihovo prosleđivanje preko environment varijabli koje kasnije postanu vidljive putem `docker inspect`, build logova ili rekonstruisanih slojeva. Build-time secrets treba montirati privremeno tokom build-a umesto da se kopiraju u fajl sistem image-a.

BuildKit je poboljšao ovaj model omogućavajući posebno rukovanje build-time secret-ima. Umesto upisivanja tajne u layer, build step je može transientno konzumirati:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Ovo je važno zato što su slojevi image-a trajni artefakti. Kada tajna dospe u commitovani sloj, kasnije brisanje fajla u drugom sloju zapravo ne uklanja prvobitno otkrivanje iz istorije image-a.

## Tajne u runtime-u

Tajne potrebne pokrenutom workload-u takođe bi trebalo da izbegavaju ad-hoc obrasce poput običnih promenljivih okruženja kad god je to moguće. Volumes, posvećene integracije za upravljanje tajnama, Docker secrets, i Kubernetes Secrets su uobičajeni mehanizmi. Nijedan od ovih ne eliminiše sav rizik, posebno ako napadač već ima code execution u workload-u, ali su i dalje poželjniji od trajnog čuvanja kredencijala u image-u ili njihovog slučajnog izlaganja putem alata za inspekciju.

Jednostavna Docker Compose style deklaracija tajne izgleda ovako:
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
U Kubernetesu, Secret objects, projected volumes, service-account tokens i cloud workload identities stvaraju širi i snažniji model, ali takođe stvaraju više mogućnosti za slučajno izlaganje putem host mounts, širokog RBAC-a ili lošeg dizajna Pod-a.

## Zloupotreba

Prilikom pregleda cilja treba utvrditi da li su secrets baked into the image, leaked into layers, ili mounted u predvidljive runtime lokacije:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Ove komande pomažu da se razlikuju tri različita problema: application configuration leaks, image-layer leaks, i runtime-injected secret files. Ako se tajna pojavi pod `/run/secrets`, a projected volume, ili cloud identity token path, sledeći korak je da se razume da li ona daje pristup samo trenutnom workload-u ili znatno većoj control plane.

### Potpun primer: Ugrađena tajna u image filesystem-u

Ako je build pipeline kopirao `.env` fajlove ili kredencijale u konačni image, post-exploitation postaje jednostavno:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Uticaj zavisi od aplikacije, ali ugrađeni signing keys, JWT secrets, ili cloud credentials mogu lako pretvoriti container compromise u API compromise, lateral movement, ili forgery of trusted application tokens.

### Potpun primer: Build-Time Secret Leakage Check

Ako postoji zabrinutost da je image history zabeležio sloj koji sadrži secrets:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Ovakav pregled je koristan zato što secret može biti izbrisan iz konačnog prikaza fajl sistema, dok i dalje ostaje u ranijem sloju ili u build metadata.

## Provere

Ove provere su namenjene da utvrde da li su image i secret-handling pipeline verovatno povećali attack surface pre runtime.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
What is interesting here:

- Sumnjiva istorija build-a može otkriti kopirane kredencijale, SSH materijal ili nesigurne build korake.
- Secrets under projected volume paths may lead to cluster or cloud access, not just local application access.
- Veliki broj konfiguracionih fajlova sa plaintext kredencijalima obično ukazuje da image ili model deploymenta nosi više poverljivih podataka nego što je neophodno.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | Podržava sigurne build-time secret mounts, ali ne automatski | Secrets mogu biti montirani ephemeralno tokom `build`; image signing and scanning zahtevaju eksplicitne workflow izbore | kopiranje Secrets u image, prosleđivanje Secrets preko `ARG` ili `ENV`, onemogućavanje provenance provera |
| Podman / Buildah | Podržava OCI-native builds i secret-aware workflows | Postoje snažni build workflow-i, ali operatori ih moraju namerno izabrati | embedding secrets u Containerfiles, široki build konteksti, permisivni bind mount-ovi tokom build-ova |
| Kubernetes | Native Secret objects i projected volumes | Runtime delivery Secrets-a je first-class, ali izloženost zavisi od RBAC, dizajna poda i host mount-ova | overbroad Secret mounts, service-account token misuse, `hostPath` access to kubelet-managed volumes |
| Registries | Integritet je opcionalan osim ako nije enforced | I javni i privatni registri zavise od politike, signing-a i admission odluka | pulling unsigned images freely, weak admission control, poor key management |
{{#include ../../../banners/hacktricks-training.md}}
