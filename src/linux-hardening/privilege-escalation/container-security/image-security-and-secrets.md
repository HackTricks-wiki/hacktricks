# Beeldsekuriteit, Ondertekening en Geheime

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Container-sekuriteit begin voordat die workload geloods word. Die image bepaal watter binaries, interpreters, libraries, opstartskripts en ingeslote konfigurasies in produksie beland. As die image backdoored is, verouderd, of gebou is met geheime daarin ingebak, werk die daaropvolgende runtime-hardening reeds op 'n gekompromitteerde artefak.

Hierom behoort image-provenansie, kwesbaarheidsskandering, handtekeningverifikasie en hantering van geheime in dieselfde gesprek as namespaces en seccomp te wees. Hulle beskerm 'n ander fase van die lewensiklus, maar mislukkings hier definieer dikwels die aanvalsvlak wat die runtime later moet beperk.

## Image Registrasies en Vertroue

Images kan kom van publieke registrasies soos Docker Hub, of van privaat registrasies wat deur 'n organisasie bedryf word. Die sekuriteitsvraag is nie net waar die image woon nie, maar of die span die herkoms en integriteit kan vasstel.

Die trek van onondertekende of swak getraceerde images vanaf publieke bronne verhoog die risiko dat kwaadwillige of gemanipuleerde inhoud in produksie beland. Selfs intern gehuisveste registrasies benodig duidelike eienaarskap, hersiening en 'n vertrouensbeleid.

Docker Content Trust het histories Notary- en TUF-konsepte gebruik om ondertekende images te vereis. Die presiese ekosisteem het ontwikkel, maar die blywende les bly nuttig: image-identiteit en integriteit behoort verifieerbaar te wees eerder as net aanvaar te word.

Voorbeeld van 'n historiese Docker Content Trust-werkvloei:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Die punt van die voorbeeld is nie dat elke span nog steeds dieselfde gereedskap moet gebruik nie, maar dat ondertekening en sleutelbestuur operasionele take is, nie abstrakte teorie nie.

## Vulnerability Scanning

Image scanning help om twee verskillende vrae te beantwoord. Eerstens, bevat die image bekende kwesbare pakkette of biblioteke? Tweedens, dra die image onnodige sagteware wat die aanvalsoppervlak vergroot? ’n Image vol debugging tools, shells, interpreters en verouderde pakkette is beide makliker om uit te buit en moeiliker om te verstaan.

Voorbeelde van algemeen gebruikte scanners sluit in:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Resultate van hierdie gereedskap moet versigtig geïnterpreteer word. 'n Kwesbaarheid in 'n ongebruikte pakket hou nie dieselfde risiko in as 'n blootgestelde RCE-pad nie, maar albei is steeds relevant vir verhardingsbesluite.

## Bou-tydse geheime

Een van die oudste foute in container-bou-pyplyne is om geheime direk in die image in te bed of om dit deur omgewingsveranderlikes te stuur wat later sigbaar word via `docker inspect`, build logs, of herwonne lae. Bou-tydse geheime moet efemeer tydens die bou gemonteer word eerder as om in die image-lêerstelsel gekopieer te word.

BuildKit verbeter hierdie model deur toegewyde hantering van bou-tydse geheime toe te laat. In plaas daarvan om 'n geheim in 'n laag te skryf, kan die bou-stap dit tydelik verbruik:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Dit is belangrik omdat image layers volhoubare artefakte is. Sodra 'n secret in 'n gecommitteerde laag beland, verwyder die latere uitvee van die lêer in 'n ander laag nie die oorspronklike openbaarmaking uit die image-geskiedenis werklik nie.

## Runtime Secrets

Secrets wat deur 'n lopende workload benodig word, moet ook ad-hoc patrone soos gewone environment variables waar moontlik vermy word. Volumes, toegewyde secret-management-integrasies, Docker secrets, en Kubernetes Secrets is algemene meganismes. Geen van hierdie verwyder alle risiko nie, veral as die aanvaller reeds code execution in die workload het, maar hulle is steeds te verkies bo om inlogbewyse permanent in die image te stoor of dit losweg deur inspeksiegereedskap bloot te stel.

A simple Docker Compose style secret declaration looks like:
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
In Kubernetes, Secret objects, projected volumes, service-account tokens, and cloud workload identities skep 'n breër en meer kragtige model, maar hulle skep ook meer geleenthede vir onbedoelde blootstelling deur host mounts, breë RBAC, of swak Pod-ontwerp.

## Misbruik

Wanneer 'n teiken hersien word, is die doel om te ontdek of secrets in die image ingebak is, leaked in layers, of mounted in voorspelbare runtime locations:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Hierdie opdragte help om te onderskei tussen drie verskillende probleme: application configuration leaks, image-layer leaks, en runtime-injected secret files. As 'n secret onder `/run/secrets`, 'n projected volume, of 'n cloud identity token path verskyn, is die volgende stap om te bepaal of dit slegs toegang verleen aan die huidige workload of aan 'n veel groter control plane.

### Volledige Voorbeeld: Embedded Secret In Image Filesystem

As 'n build pipeline `.env` files of credentials in die finale image gekopieer het, word post-exploitation eenvoudig:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Die impak hang af van die toepassing, maar ingebedde signing keys, JWT secrets, of cloud credentials kan maklik container compromise omskep in API compromise, lateral movement, of vervalsing van vertroude application tokens.

### Volledige Voorbeeld: Build-Time Secret Leakage Check

Indien daar kommer is dat die image history 'n secret-bearing layer vasgevang het:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Hierdie soort hersiening is nuttig omdat 'n secret dalk uit die finale lêerstelsel-uitsig verwyder is, terwyl dit steeds in 'n vroeëre laag of in boumetadata bly.

## Kontroles

Hierdie kontroles is bedoel om vas te stel of die image- en secret-hanteringspyplyn waarskynlik die aanvalsoppervlak voor runtime verhoog het.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Wat hier interessant is:

- ’n verdagte build-geskiedenis kan gekopieerde credentials, SSH-materiaal, of onveilige build-stappe openbaar.
- Secrets onder projected volume paths kan lei tot cluster- of cloud-toegang, nie net plaaslike toepassingstoegang nie.
- Groot aantalle konfigurasielêers met plaintext credentials dui gewoonlik daarop dat die image of deployment model meer trust material dra as nodig.

## Runtime-standaarde

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | Ondersteun veilige build-time secret mounts, maar nie outomaties nie | Secrets can be mounted ephemerally during `build`; image signing and scanning require explicit workflow choices | kopieer secrets in die image, passing secrets by `ARG` or `ENV`, disabling provenance checks |
| Podman / Buildah | Ondersteun OCI-native builds en secret-aware workflows | Sterk build-workflows is beskikbaar, maar operateurs moet dit steeds doelbewus kies | embedding secrets in Containerfiles, breë build contexts, permissiewe bind mounts tydens builds |
| Kubernetes | Inheemse Secret objects en projected volumes | Runtime-secret-aflewering is van hoë gehalte, maar blootstelling hang af van RBAC, pod-ontwerp en host mounts | oor-brede Secret mounts, service-account token misuse, `hostPath` toegang tot kubelet-managed volumes |
| Registries | Integriteit is opsioneel tensy afgedwing | Publieke en private registries hang af van beleid, signing, en admission-besluite | pulling unsigned images freely, swak admission control, swak key management |
