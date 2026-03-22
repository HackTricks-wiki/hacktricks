# Beeldsekuriteit, Ondertekening en Geheime

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Kontainersekuriteit begin voordat die werklading geloods word. Die beeld bepaal watter binaries, tolke, biblioteke, opstartskripte en ingebedde konfigurasie produksie bereik. As die beeld 'n backdoor bevat, verouderd is, of gebou is met geheime daarin ingebak, werk die uitvoeringstydse verharding wat volg reeds op 'n gekompromitteerde artefak.

Hierom behoort beeldherkoms, kwesbaarheidsskandering, handtekeningverifikasie en hantering van geheime in dieselfde gesprek as namespaces en seccomp te val. Hulle beskerm 'n ander fase van die lewensiklus, maar mislukkinge hier definieer dikwels die aanvalsoppervlak wat die uitvoeringstyd later moet beperk.

## Beeldregisters en Vertroue

Beelde kan kom van publieke registers soos Docker Hub of van private registers wat deur 'n organisasie bedryf word. Die sekuriteitsvraag is nie net waar die beeld woon nie, maar of die span herkoms en integriteit kan vestig. Om onondertekende of swak nagevolgde beelde van publieke bronne te trek verhoog die risiko dat kwaadaardige of gemanipuleerde inhoud produksie binnegaan. Selfs intern gehuisveste registers benodig duidelike eienaarskap, hersiening en 'n vertrouensbeleid.

Docker Content Trust het histories Notary- en TUF-konsepte gebruik om vereiste te stel dat beelde onderteken is. Die presiese ekosisteem het geëvolueer, maar die volhoubare les bly nuttig: beeldidentiteit en integriteit behoort verifieerbaar te wees eerder as veronderstel.

Voorbeeld historiese Docker Content Trust-werkvloei:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Die punt van die voorbeeld is nie dat elke span steeds dieselfde gereedskap moet gebruik nie, maar dat ondertekening en sleutelbestuur operasionele take is, nie abstrakte teorie nie.

## Kwetsbaarheidsskandering

Image scanning help om twee verskillende vrae te beantwoord. Eerstens: bevat die image bekende kwesbare pakkette of biblioteke? Tweedens: dra die image onnodige sagteware wat die aanvalsooppervlak vergroot? 'n Image vol debugging tools, shells, interpreters en verouderde pakkette is beide makliker om uit te buit en moeiliker om oor te dink.

Voorbeelde van algemeen gebruikte skandeerders sluit in:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Resultate van hierdie gereedskap moet noukeurig geïnterpreteer word. 'n Kwesbaarheid in 'n ongebruikte pakket is nie dieselfde risiko as 'n blootgestelde RCE-pad nie, maar albei is steeds relevant vir verhardingsbesluite.

## Boutyd-geheime

Een van die oudste foute in container build-pipelines is om geheime direk in die image in te sluit of dit deur omgewingsveranderlikes te stuur wat later sigbaar raak via `docker inspect`, build logs, of herstelde lae. Boutyd-geheime moet tydelik tydens die build gemount word in plaas daarvan om in die image-lêerstelsel gekopieer te word.

BuildKit verbeter hierdie model deur toegewyde hantering van boutyd-geheime toe te laat. In plaas daarvan om 'n geheim in 'n laag te skryf, kan die build-stap dit tydelik verbruik:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Dit maak saak omdat image-lae duursame artefakte is. Sodra 'n geheim in 'n gecommitteerde laag beland, sal die latere verwydering van die lêer in 'n ander laag nie die oorspronklike blootstelling uit die image-geskiedenis werklik verwyder nie.

## Runtime Secrets

Geheime wat deur 'n lopende werkbelasting benodig word, moet ook ad-hoc patrone soos gewone omgewingsveranderlikes waar moontlik vermy word. Volumes, toegewyde secret-management-integrasies, Docker secrets, en Kubernetes Secrets is algemene meganismes. Geen van hierdie verwyder alle risiko nie, veral as die aanvaller reeds kode-uitvoering in die werkbelasting het, maar hulle is steeds te verkies bo om kredensiale permanent in die image te stoor of dit losweg via inspeksie-gereedskap bloot te stel.

'n eenvoudige Docker Compose-styl secret-deklarasie lyk soos:
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
In Kubernetes, Secret objects, projected volumes, service-account tokens, and cloud workload identities skep 'n wyer en meer kragtige model, maar hulle skep ook meer geleenthede vir per ongeluk blootstelling deur host mounts, breë RBAC, of swak Pod-ontwerp.

## Misbruik

Wanneer 'n teiken hersien word, is die doel om te ontdek of secrets in die image ingebak is, leaked in lae, of in voorspelbare runtime-lokasies gemounted is:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Hierdie opdragte help om te onderskei tussen drie verskillende probleme: application configuration leaks, image-layer leaks, en runtime-injected secret files. As 'n secret verskyn onder `/run/secrets`, 'n projected volume, of 'n cloud identity token path, is die volgende stap om te verstaan of dit toegang gee slegs tot die huidige workload of tot 'n baie groter control plane.

### Volledige Voorbeeld: Embedded Secret In Image Filesystem

As 'n build pipeline `.env` files of credentials in die finale image gekopieer het, word post-exploitation eenvoudig:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Die impak hang af van die toepassing, maar ingebedde signing keys, JWT secrets, of cloud credentials kan maklik 'n container compromise in 'n API compromise, lateral movement, of vervalsing van vertroude toepassingstokens omskep.

### Volledige voorbeeld: Build-Time Secret Leakage Check

Indien die bekommernis is dat die image history 'n secret-bearing layer vasgevang het:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Hierdie soort hersiening is nuttig omdat 'n secret moontlik uit die finale lêerstelsel-aansig verwyder is, terwyl dit steeds in 'n vroeër laag of in die build-metadata bly.

## Checks

Hierdie kontroles is bedoel om te bepaal of die image- en secret-hanteringspyplyn waarskynlik die aanvalsoppervlak voor runtime vergroot het.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Wat hier interessant is:

- ’n Verdagte build-geskiedenis kan gekopieerde credentials, SSH-materiaal, of onveilige build-stappe openbaar.
- Secrets onder projected volume paths kan lei tot cluster- of cloud-toegang, nie net plaaslike aansoektoegang nie.
- Groot aantalle konfigurasielêers met plaintext credentials dui gewoonlik daarop dat die image of deployment model meer trust material dra as nodig.

## Runtime Defaults

| Runtime / platform | Standaardtoestand | Standaardgedrag | Algemene manuele verzwakking |
| --- | --- | --- | --- |
| Docker / BuildKit | Ondersteun veilige build-time secret mounts, maar nie outomaties nie | Secrets kan ephemerally tydens `build` gemounteer word; image signing and scanning vereis eksplisiete workflow-keuses | copying secrets into the image, passing secrets by `ARG` or `ENV`, disabling provenance checks |
| Podman / Buildah | Ondersteun OCI-native builds en secret-aware workflows | Sterk build-workflows is beskikbaar, maar operators moet dit nog steeds doelbewus kies | embedding secrets in Containerfiles, broad build contexts, permissive bind mounts during builds |
| Kubernetes | Native Secret objects and projected volumes | Runtime secret delivery is first-class, maar blootstelling hang af van RBAC, pod ontwerp, en host mounts | overbroad Secret mounts, service-account token misuse, `hostPath` access to kubelet-managed volumes |
| Registries | Integriteit is opsioneel tensy dit afgedwing word | Publieke en private registries hang beide af van beleid, signing, en admission decisions | pulling unsigned images freely, weak admission control, poor key management |
{{#include ../../../banners/hacktricks-training.md}}
