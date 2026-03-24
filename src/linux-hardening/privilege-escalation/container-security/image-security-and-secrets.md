# Image-sekuriteit, Ondertekening en Geheimenisse

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Container-sekuriteit begin voordat die workload van stapel gestuur word. Die image bepaal watter binaries, interpreters, libraries, startup-skripte en ingebedde konfigurasie produksie bereik. As die image backdoored is, verouderd is, of gebou is met geheime wat daarin ingesluit is, werk die runtime-hardening wat volg reeds op 'n gekompromitteerde artefak.

Hierom behoort image provenance, vulnerability scanning, signature verification en secret handling in dieselfde gesprek as namespaces en seccomp te wees. Hulle beskerm 'n ander fase van die lewenssiklus, maar mislukkings hier definieer dikwels die attack surface wat die runtime later moet bevat.

## Image Registries And Trust

Images kan van openbare registries soos Docker Hub kom of van private registries wat deur 'n organisasie bedryf word. Die sekuriteitsvraag is nie net waar die image woon nie, maar of die span provenance en integriteit kan vasstel. Om unsigned of swak gevolgde images van openbare bronne te trek verhoog die risiko dat kwaadwillige of gemanipuleerde inhoud produksie betree. Selfs internt gehuisveste registries benodig duidelike eienaarskap, hersiening en 'n trust-policy.

Docker Content Trust het histories Notary- en TUF-konsepte gebruik om signed images te vereis. Die presiese ekosisteem het ontwikkel, maar die blywende les bly nuttig: image identity en integriteit behoort verifieerbaar te wees in plaas van veronderstel.

Example historical Docker Content Trust workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Die punt van die voorbeeld is nie dat elke span steeds dieselfde gereedskap moet gebruik nie, maar dat ondertekening en sleutelbestuur operasionele take is, nie abstrakte teorie nie.

## Kwetsbaarheidsskandering

Beeldskandering help om twee verskillende vrae te beantwoord. Eerstens: bevat die beeld bekende kwesbare pakkette of biblioteke? Tweedens: dra die beeld onnodige sagteware wat die aanvalsvlak vergroot? 'n Beeld wat vol is van debugging-gereedskap, shells, interpreters en verouderde pakkette is beide makliker om misbruik van te maak en moeiliker om te begryp.

Voorbeelde van algemeen gebruikte skandeerders sluit in:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Resultate van hierdie gereedskap moet sorgvuldig geïnterpreteer word. 'n Kwesbaarheid in 'n ongebruikte pakket hou nie dieselfde risiko in as 'n blootgestelde RCE-pad nie, maar albei is steeds relevant vir verhardingsbesluite.

## Bou-tyd Geheime

Een van die oudste foute in container-bou-pipelines is om geheime direk in die image in te bou of dit deur omgewingsveranderlikes te stuur wat later sigbaar raak via `docker inspect`, build logs, of herstelde lae. Bou-tyd geheime moet tydelik gemonteer word tydens die build in plaas daarvan om in die image se filesystem gekopieer te word.

BuildKit het hierdie model verbeter deur toegewyde bou-tyd geheime hantering toe te laat. In plaas daarvan om 'n geheim in 'n laag te skryf, kan die bou-stap dit tydelik verbruik:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Dit is belangrik omdat image-lae volhoubare artefakte is. Sodra 'n geheim in 'n gecommitteerde laag beland, verwyder die latere uitvee van die lêer in 'n ander laag nie werklik die oorspronklike openbaarmaking uit die image-geskiedenis nie.

## Runtime Secrets

Geheime wat deur 'n hardloopende workload benodig word, moet ook waar moontlik ad hoc-patrone soos gewone omgewingsveranderlikes vermy. Volumes, toegewyde secret-management-integrasies, Docker secrets, en Kubernetes Secrets is algemene meganismes. Geen van hierdie verwyder alle risiko nie, veral as die aanvaller reeds kode-uitvoering in die workload het, maar hulle is steeds verkieslik bo die permanente stoor van inlogbewyse in die image of om dit gemaklik deur inspeksiegereedskap bloot te stel.

'n eenvoudige Docker Compose-styl geheimverklaring lyk soos:
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
In Kubernetes skep Secret objects, projected volumes, service-account tokens, en cloud workload identities 'n breër en meer kragtige model, maar dit skep ook meer geleenthede vir per ongeluk blootstelling deur host mounts, breë RBAC, of swak Pod-ontwerp.

## Misbruik

Wanneer 'n teiken hersien word, is die doel om te ontdek of secrets ingebak is in die image, leaked in layers, of in voorspelbare runtime-liggings gemonteer is:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Hierdie opdragte help om onderskeid te tref tussen drie verskillende probleme: application configuration leaks, image-layer leaks, en runtime-injected secret files. As 'n geheim verskyn onder `/run/secrets`, in 'n projected volume, of in 'n cloud identity token path, is die volgende stap om te verstaan of dit slegs toegang verleen tot die huidige workload of tot 'n baie groter control plane.

### Volledige voorbeeld: Ingebedde geheim in die beeld-lêerstelsel

As 'n build pipeline `.env` files of credentials in die finale image gekopieer het, word post-exploitation eenvoudig:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
Die impak hang van die toepassing af, maar embedded signing keys, JWT secrets, of cloud credentials kan maklik 'n container compromise omskep in 'n API compromise, lateral movement, of die vervalsing van trusted application tokens.

### Volledige Voorbeeld: Build-Time Secret Leakage Check

Indien die bekommernis is dat die image history 'n secret-bearing layer vasgevang het:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
## Checks

Hierdie soort hersiening is nuttig omdat 'n secret moontlik uit die final filesystem view verwyder is, terwyl dit steeds in 'n earlier layer of in build metadata aanwesig bly.

Hierdie kontroles is bedoel om vas te stel of die image en secret-handling pipeline waarskynlik die attack surface voor runtime vergroot het.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Wat hier interessant is:

- 'n Verdagte build-geskiedenis kan gekopieerde inlogbewyse, SSH-materiaal of onveilige build-stappe openbaar.
- Secrets onder geprojekteerde volume-paadjies kan lei tot cluster- of cloud-toegang, nie net plaaslike toepassings-toegang nie.
- Groot aantalle konfigurasielêers met plaintext-inlogbewyse dui gewoonlik daarop dat die image of ontplooiingsmodel meer vertrouensmateriaal dra as nodig.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | Ondersteun veilige build-time secret mounts, maar nie outomaties nie | Secrets kan ephemeries tydens `build` gemount word; image signing en scanning vereis eksplisiete workflow-keuses | kopieer secrets in die image, deurgee van secrets via `ARG` of `ENV`, deaktiveer provenance checks |
| Podman / Buildah | Ondersteun OCI-native builds en secret-aware workflows | Sterk build-workflows is beskikbaar, maar operateurs moet dit steeds doelbewus kies | inbedding van secrets in Containerfiles, breë build-kontekste, permissiewe bind mounts tydens builds |
| Kubernetes | Native Secret objects and projected volumes | Runtime secret-aflewering is eersteklas, maar blootstelling hang af van RBAC, pod-ontwerp en host mounts | oor-breë Secret-monteerplekke, misbruik van service-account tokens, `hostPath` toegang tot kubelet-managed volumes |
| Registries | Integriteit is opsioneel tensy dit afgedwing word | Openbare en private registries is afhanklik van beleid, signing, en admission-besluite | vryelik pulling van unsigned images, swak admission control, swak sleutelbestuur |
{{#include ../../../banners/hacktricks-training.md}}
