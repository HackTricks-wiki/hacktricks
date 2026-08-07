# Image-sekuriteit, ondertekening en secrets

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Container-sekuriteit begin voordat die workload geloods word. Die image bepaal watter binaries, interpreters, libraries, startup-skripte en ingebedde konfigurasie production bereik. As die image ’n backdoor bevat, verouderd is, of met secrets daarin ingebou is, werk die runtime-hardening wat daarop volg reeds op ’n gekompromitteerde artifact.

Dit is waarom image-provenance, vulnerability scanning, signature verification en secret handling in dieselfde gesprek as namespaces en seccomp hoort. Hulle beskerm ’n ander fase van die lifecycle, maar failures hier definieer dikwels die attack surface wat die runtime later moet beperk.

## Image Registries En Trust

Images kan afkomstig wees van public registries soos Docker Hub of van private registries wat deur ’n organisasie bedryf word. Die security-vraag is nie bloot waar die image geleë is nie, maar of die span provenance en integrity kan vasstel. Die gebruik van unsigned of swak nagespoorde images vanaf public sources verhoog die risiko dat malicious of gemanipuleerde content production binnekom. Selfs intern gehuisveste registries benodig duidelike eienaarskap, review en trust policy.

Docker Content Trust het histories Notary- en TUF-konsepte gebruik om signed images te vereis. Die presiese ecosystem het ontwikkel, maar die blywende les is steeds nuttig: image identity en integrity behoort verifieerbaar te wees eerder as om aanvaar te word.

Voorbeeld van ’n historiese Docker Content Trust-workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Die punt van die voorbeeld is nie dat elke span steeds dieselfde tooling moet gebruik nie, maar dat ondertekening en sleutelbestuur operasionele take is, nie abstrakte teorie nie.

## Kwesbaarheidskandering

Image scanning help om twee verskillende vrae te beantwoord. Eerstens, bevat die image bekende kwesbare packages of libraries? Tweedens, bevat die image onnodige software wat die attack surface vergroot? ’n Image vol debugging tools, shells, interpreters en verouderde packages is makliker om te exploit en moeiliker om te beoordeel.

Voorbeelde van algemeen gebruikte scanners sluit in:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Resultate van hierdie tools moet versigtig geïnterpreteer word. ’n Kwesbaarheid in ’n ongebruikte package hou nie dieselfde risiko in as ’n blootgestelde RCE-pad nie, maar albei is steeds relevant vir hardening-besluite.

## Secrets tydens bou

Een van die oudste foute in container build pipelines is om secrets direk in die image in te sluit of dit deur environment variables te stuur, wat later sigbaar word deur `docker inspect`, build logs of herwonne layers. Build-time secrets moet tydelik gemount word tydens die build, eerder as om dit na die image filesystem te kopieer.

BuildKit het hierdie model verbeter deur toegewyde build-time secret-hantering moontlik te maak. In plaas daarvan om ’n secret in ’n layer te skryf, kan die build step dit tydelik gebruik:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Dit is belangrik omdat image layers duursame artefakte is. Sodra 'n secret in 'n committed layer beland, verwyder die latere uitvee van die lêer in 'n ander layer nie werklik die oorspronklike disclosure uit die image history nie.

## Runtime Secrets

Secrets wat deur 'n workload tydens runtime benodig word, moet ook waar moontlik ad hoc-patrone soos plain environment variables vermy. Volumes, toegewyde secret-management-integrasies, Docker secrets en Kubernetes Secrets is algemene meganismes. Nie een hiervan verwyder alle risiko nie, veral as die aanvaller reeds code execution in die workload het, maar hulle is steeds verkieslik bo die permanente berging van credentials in die image of die sorgelose blootstelling daarvan deur inspection tooling.

'n Eenvoudige Docker Compose-styl secret-deklarasie lyk soos volg:
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
In Kubernetes skep Secret objects, projected volumes, service-account tokens en cloud workload identities ’n breër en kragtiger model, maar dit skep ook meer geleenthede vir toevallige blootstelling deur host mounts, breë RBAC of swak Pod-ontwerp.

## Misbruik

Wanneer ’n teiken hersien word, is die doel om vas te stel of secrets in die image ingebou is, in lae geleak het, of in voorspelbare runtime-liggings gemount is:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Hierdie commands help om tussen drie verskillende problems te onderskei: application configuration leaks, image-layer leaks, en runtime-injected secret files. As 'n secret onder `/run/secrets`, 'n projected volume, of 'n cloud identity token path verskyn, is die volgende stap om te verstaan of dit slegs toegang tot die huidige workload verleen of tot 'n veel groter control plane.

### Volledige voorbeeld: Embedded Secret In Image Filesystem

As 'n build pipeline `.env`-files of credentials na die final image gekopieer het, word post-exploitation eenvoudig:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Die impak hang van die application af, maar ingebedde signing keys, JWT secrets of cloud credentials kan container compromise maklik in API compromise, lateral movement of vervalsing van trusted application tokens verander.

### Volledige Voorbeeld: Build-Time Secret Leak Check

As die bekommernis is dat die image history ’n secret-bearing layer vasgelê het:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Hierdie soort hersiening is nuttig omdat ’n secret uit die finale filesystem-aansig verwyder kon wees, terwyl dit steeds in ’n vroeër laag of in build-metadata teenwoordig is.

## Kontroles

Hierdie kontroles is bedoel om vas te stel of die image- en secret-handling-pipeline waarskynlik die attack surface voor runtime vergroot het.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Wat is hier interessant:

- 'n Verdagte build-geskiedenis kan gekopieerde credentials, SSH-materiaal of onveilige build-stappe onthul.
- Secrets onder projected volume-paaie kan tot cluster- of cloud-toegang lei, nie net plaaslike application-toegang nie.
- Groot getalle konfigurasielêers met plaintext credentials dui gewoonlik daarop dat die image of deployment-model meer trust-materiaal dra as wat nodig is.

## Runtime-verstekwaardes

| Runtime / platform | Verstektoestand | Verstekgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker / BuildKit | Ondersteun veilige build-time secret mounts, maar nie outomaties nie | Secrets kan tydelik tydens `build` gemount word; image-signing en scanning vereis eksplisiete workflow-keuses | secrets na die image kopieer, secrets deur `ARG` of `ENV` deurgee, provenance checks deaktiveer |
| Podman / Buildah | Ondersteun OCI-native builds en secret-aware workflows | Sterk build-workflows is beskikbaar, maar operateurs moet dit steeds doelbewus kies | secrets in Containerfiles embed, breë build contexts, permissive bind mounts tydens builds |
| Kubernetes | Native Secret-objects en projected volumes | Runtime-secret-aflewering is first-class, maar blootstelling hang af van RBAC, pod-ontwerp en host mounts | te breë Secret-mounts, service-account token-misbruik, `hostPath`-toegang tot kubelet-managed volumes |
| Registries | Integriteit is opsioneel tensy dit afgedwing word | Public en private registries is albei afhanklik van beleid, signing en admission-besluite | unsigned images vrylik pull, swak admission control, swak key management |

{{#include ../../../banners/hacktricks-training.md}}
