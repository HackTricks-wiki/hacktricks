# Image Security, Signing, And Secrets

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Container-sekuriteit begin voordat die workload geloods word. Die image bepaal watter binaries, interpreters, libraries, startup scripts en ingebedde konfigurasie production bereik. As die image ’n backdoor bevat, verouderd is, of met secrets daarin ingebou is, werk die runtime hardening wat daarop volg reeds op ’n gekompromitteerde artifact.

Daarom hoort image provenance, vulnerability scanning, signature verification en secret handling in dieselfde gesprek as namespaces en seccomp. Hulle beskerm ’n ander fase van die lifecycle, maar failures hier bepaal dikwels die attack surface wat die runtime later moet beperk.

## Image Registries En Trust

Images kan van publieke registries soos Docker Hub afkomstig wees, of van private registries wat deur ’n organisasie bedryf word. Die security-vraag is nie bloot waar die image geleë is nie, maar of die span provenance en integrity kan vasstel. Die trek van unsigned of swak nagespoorde images vanaf publieke sources verhoog die risiko dat malicious of tampered content production binnekom. Selfs intern gehoste registries benodig duidelike ownership, review en trust policy.

Docker Content Trust het histories Notary- en TUF-konsepte gebruik om signed images te vereis. Die presiese ecosystem het ontwikkel, maar die blywende les is steeds nuttig: image identity en integrity behoort verifieerbaar te wees eerder as om aanvaar te word.

Voorbeeld van ’n historiese Docker Content Trust-workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Die punt van die voorbeeld is nie dat elke span steeds dieselfde tooling moet gebruik nie, maar dat signing en key management operasionele take is, nie abstrakte teorie nie.

## Kwesbaarheidskandering

Image scanning help om twee verskillende vrae te beantwoord. Eerstens, bevat die image bekende kwesbare pakkette of libraries? Tweedens, bevat die image onnodige sagteware wat die aanvalseoppervlak vergroot? ’n Image vol debugging-tools, shells, interpreters en verouderde pakkette is makliker om te exploit en moeiliker om te ontleed.

Voorbeelde van algemeen gebruikte skandeerders sluit in:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Resultate van hierdie tools moet versigtig geïnterpreteer word. ’n Vulnerability in ’n ongebruikte package hou nie dieselfde risiko in as ’n blootgestelde RCE-pad nie, maar albei bly relevant vir hardening-besluite.

## Secrets tydens bou

Een van die oudste foute in container build-pipelines is om secrets direk in die image in te sluit of dit deur environment variables deur te gee, wat later sigbaar word deur `docker inspect`, build-logs of herwonne layers. Build-time secrets moet tydens die build ephemeral gemount word eerder as om dit na die image-lêerstelsel te kopieer.

BuildKit het hierdie model verbeter deur toegewyde build-time secret-hantering moontlik te maak. In plaas daarvan om ’n secret in ’n layer te skryf, kan die build-stap dit tydelik verbruik:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Dit is belangrik omdat image-lae volhoubare artefakte is. Sodra ’n secret in ’n vasgelegde laag beland, verwyder die latere uitvee van die lêer in ’n ander laag nie werklik die oorspronklike disclosure uit die image-geskiedenis nie.

## Runtime Secrets

Secrets wat deur ’n lopende workload benodig word, behoort ook waar moontlik ad hoc-patrone soos gewone omgewingsveranderlikes te vermy. Volumes, toegewyde secret-management-integrasies, Docker secrets en Kubernetes Secrets is algemene meganismes. Geen van hierdie opsies verwyder alle risiko nie, veral as die aanvaller reeds code execution in die workload het, maar hulle is steeds verkieslik bo die permanente berging van credentials in die image of die onversigtige blootstelling daarvan deur inspection tooling.

’n Eenvoudige Docker Compose-styl secret-deklarasie lyk soos volg:
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

Wanneer ’n target hersien word, is die doel om vas te stel of secrets in die image ingebou is, in layers gelek het, of in voorspelbare runtime-liggings gemount is:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Hierdie opdragte help om tussen drie verskillende probleme te onderskei: leaks van application-konfigurasie, leaks in image-lae en runtime-ingespuitte secret-lêers. As ’n secret onder `/run/secrets`, ’n projected volume of ’n cloud-identiteitstokenpad verskyn, is die volgende stap om vas te stel of dit slegs toegang tot die huidige workload verleen, of tot ’n veel groter control plane.

### Volledige voorbeeld: Ingebedde secret in image-lêerstelsel

As ’n build pipeline `.env`-lêers of credentials na die finale image gekopieer het, word post-exploitation eenvoudig:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Die impak hang van die toepassing af, maar ingebedde signing keys, JWT secrets of cloud credentials kan container compromise maklik in API compromise, lateral movement of vervalsing van vertroude application tokens omskep.

### Volledige voorbeeld: Build-Time Secret Leakage Check

As die bekommernis is dat die image history ’n layer met ’n secret bevat:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Hierdie soort hersiening is nuttig omdat ’n secret moontlik uit die finale lêerstelselaansig verwyder is, terwyl dit steeds in ’n vroeëre laag of in build-metadata teenwoordig is.

## Kontroles

Hierdie kontroles is daarop gemik om vas te stel of die image- en secret-hanteringspyplyn waarskynlik die attack surface vóór runtime vergroot het.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Wat hier interessant is:

- 'n Verdachte build-geskiedenis kan gekopieerde credentials, SSH-materiaal of onveilige build-stappe openbaar maak.
- Secrets onder projected volume-paaie kan tot cluster- of cloud-toegang lei, nie net plaaslike application-toegang nie.
- Groot getalle configuration-lêers met plaintext credentials dui gewoonlik daarop dat die image of deployment-model meer trust-materiaal bevat as wat nodig is.

## Runtime-verstekwaardes

| Runtime / platform | Verstektoestand | Verstekgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker / BuildKit | Ondersteun veilige build-time secret mounts, maar nie outomaties nie | Secrets kan tydelik tydens `build` gemount word; image signing en scanning vereis eksplisiete workflow-keuses | secrets in die image kopieer, secrets deur `ARG` of `ENV` deurgee, provenance checks deaktiveer |
| Podman / Buildah | Ondersteun OCI-native builds en secret-aware workflows | Sterk build-workflows is beskikbaar, maar operators moet dit steeds doelbewus kies | secrets in Containerfiles embed, breë build contexts, permissive bind mounts tydens builds |
| Kubernetes | Native Secret-objects en projected volumes | Runtime secret delivery is first-class, maar exposure hang van RBAC, pod-ontwerp en host mounts af | oormatige Secret-mounts, service-account token-misbruik, `hostPath`-toegang tot kubelet-managed volumes |
| Registries | Integrity is opsioneel tensy dit afgedwing word | Public en private registries is albei afhanklik van policy-, signing- en admission-besluite | unsigned images vrylik pull, swak admission control, swak key management |
{{#include ../../../banners/hacktricks-training.md}}
