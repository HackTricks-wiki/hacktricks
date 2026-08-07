# User Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die user namespace verander die betekenis van user- en group-ID's deur die kernel toe te laat om ID's wat binne die namespace gesien word, na verskillende ID's daarbuite te karteer. Dit is een van die belangrikste moderne container-beskermingsmaatreëls omdat dit die grootste historiese probleem in klassieke containers direk aanspreek: **root binne die container was vroeër ongemaklik naby root op die host**.

Met user namespaces kan 'n proses as UID 0 binne die container loop en steeds met 'n onprivileged UID-reeks op die host ooreenstem. Dit beteken die proses kan vir baie take binne die container soos root optree, terwyl dit vanuit die host se oogpunt aansienlik minder magtig is. Dit los nie elke container-sekuriteitsprobleem op nie, maar dit verander die gevolge van 'n container compromise beduidend.

## Werking

'n User namespace het mapping-lêers soos `/proc/self/uid_map` en `/proc/self/gid_map` wat beskryf hoe namespace-ID's na ouer-ID's vertaal word. As root binne die namespace na 'n unprivileged host-UID karteer, dra bewerkings wat werklike host-root sou vereis eenvoudig nie dieselfde gewig nie. Dit is waarom user namespaces sentraal staan tot **rootless containers** en waarom dit een van die grootste verskille is tussen ouer rootful container-verstekke en meer moderne least-privilege-ontwerpe.

Die punt is subtiel maar noodsaaklik: root binne die container word nie uitgeskakel nie, dit word **vertaal**. Die proses ervaar steeds plaaslik 'n root-agtige omgewing, maar die host behoort dit nie as volle root te behandel nie.

## Lab

'n Handmatige toets is:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Dit laat die huidige gebruiker as root binne die namespace voorkom, terwyl dit steeds nie host root daarbuite is nie. Dit is een van die beste eenvoudige demonstrasies om te verstaan waarom user namespaces so waardevol is.

In containers kan jy die sigbare mapping vergelyk met:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Die presiese uitvoer hang daarvan af of die engine user namespace remapping of ’n meer tradisionele rootful-konfigurasie gebruik.

Jy kan ook die mapping vanaf die host-kant lees met:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Gebruik tydens uitvoering

Rootless Podman is een van die duidelikste voorbeelde van gebruikersnaamruimtes wat as ’n eersterangsekuriteitsmeganisme behandel word. Rootless Docker is ook daarvan afhanklik. Docker se userns-remap-ondersteuning verbeter veiligheid in rootful daemon-ontplooiings ook, hoewel baie ontplooiings dit histories weens versoenbaarheidsredes gedeaktiveer gelaat het. Kubernetes-ondersteuning vir gebruikersnaamruimtes het verbeter, maar aanneming en verstekwaardes wissel volgens runtime, distro en clusterbeleid. Incus/LXC-stelsels steun ook sterk op UID/GID-verskuiwing en idmapping-idees.

Die algemene tendens is duidelik: omgewings wat gebruikersnaamruimtes ernstig gebruik, bied gewoonlik ’n beter antwoord op “wat beteken container root werklik?” as omgewings wat dit nie doen nie.

## Gevorderde karteringbesonderhede

Wanneer ’n onbevoorregte proses na `uid_map` of `gid_map` skryf, pas die kernel strenger reëls toe as wanneer ’n bevoorregte ouer-namespace-skrywer dit doen. Slegs beperkte karterings word toegelaat, en vir `gid_map` moet die skrywer gewoonlik eers `setgroups(2)` deaktiveer:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Hierdie detail is belangrik omdat dit verduidelik waarom user-namespace-opstelling soms in rootless-eksperimente misluk en waarom runtimes noukeurige helper-logika rondom UID/GID-delegasie benodig.

Nog ’n gevorderde kenmerk is die **ID-mapped mount**. In plaas daarvan om eienaarskap op skyf te verander, pas ’n ID-mapped mount ’n user-namespace-mapping op ’n mount toe sodat eienaarskap deur daardie mount-aansig vertaal lyk. Dit is veral relevant in rootless- en moderne runtime-opstellings omdat dit gedeelde host-paaie toelaat sonder rekursiewe `chown`-bewerkings. Vanuit ’n sekuriteitsoogpunt verander die kenmerk hoe skryfbaar ’n bind mount vanuit die namespace lyk, hoewel dit nie die onderliggende lêerstelsel-metadata herskryf nie.

Onthou ten slotte dat wanneer ’n proses ’n nuwe user namespace skep of betree, dit ’n volledige capability-stel **binne daardie namespace** ontvang. Dit beteken nie dat dit skielik host-globale mag verkry het nie. Dit beteken dat daardie capabilities slegs gebruik kan word waar die namespace-model en ander beskermings dit toelaat. Dit is waarom `unshare -U` skielik mounting of namespace-plaaslike bevoorregte bewerkings moontlik kan maak sonder om die host root-grens direk te laat verdwyn.

## Verkeerde konfigurasies

Die grootste swakheid is eenvoudig om nie user namespaces te gebruik in omgewings waar dit haalbaar sou wees nie. As container root te direk na host root gemap word, word skryfbare host mounts en bevoorregte kernel-bewerkings baie gevaarliker. Nog ’n probleem is om host user-namespace-sharing af te dwing of remapping vir compatibility te deaktiveer sonder om te besef hoeveel dit die trust boundary verander.

User namespaces moet ook saam met die res van die model oorweeg word. Selfs wanneer hulle aktief is, kan ’n breë runtime API-blootstelling of ’n baie swak runtime-konfigurasie steeds privilege escalation deur ander paaie moontlik maak. Maar sonder hulle word baie ou breakout-klasse baie makliker om uit te buit.

## Misbruik

As die container rootful is sonder user-namespace-separasie, word ’n skryfbare host bind mount aansienlik gevaarliker omdat die proses moontlik werklik as host root skryf. Gevaarlike capabilities word eweneens meer betekenisvol. Die attacker hoef nie meer so hard teen die translation boundary te veg nie, omdat die translation boundary skaars bestaan.

Die teenwoordigheid of afwesigheid van user namespaces moet vroeg nagegaan word wanneer ’n container breakout-pad geëvalueer word. Dit beantwoord nie elke vraag nie, maar dit wys onmiddellik of "root in container" direkte relevansie vir die host het.

Die mees praktiese misbruikpatroon is om die mapping te bevestig en dan onmiddellik te toets of host-gemonteerde inhoud met host-relevante privileges skryfbaar is:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
As die lêer as die werklike host root geskep word, is user namespace-isolasie vir daardie pad effektief afwesig. Op daardie punt word klassieke host-file-misbruik realisties:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
’n Veiliger bevestiging tydens ’n live assessment is om ’n onskadelike merker te skryf eerder as om kritieke lêers te wysig:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Hierdie kontroles is belangrik omdat hulle die werklike vraag vinnig beantwoord: karteer root in hierdie container nou genoeg met host root dat ’n skryfbare host mount onmiddellik ’n pad na host compromise word?

### Volledige voorbeeld: Herwinning van Namespace-Local Capabilities

Indien seccomp `unshare` toelaat en die omgewing ’n nuwe user namespace toelaat, kan die proses moontlik weer ’n volledige capability set binne daardie nuwe namespace verkry:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Dit is nie op sigself ’n host escape nie. Die rede waarom dit belangrik is, is dat user namespaces bevoorregte namespace-lokale aksies weer kan aktiveer, wat later met swak mounts, kwesbare kernels of swak blootgestelde runtime-oppervlakke kan kombineer.

## Kontroles

Hierdie opdragte is bedoel om die belangrikste vraag op hierdie bladsy te beantwoord: waartoe word root binne hierdie container op die host gemap?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Wat hier interessant is:

- As die proses UID 0 is en die maps 'n direkte of baie nabye host-root mapping toon, is die container baie gevaarliker.
- As root na 'n ongeprivilegieerde host-reeks map, is dit 'n baie veiliger basislyn en dui dit gewoonlik op werklike user namespace-isolasie.
- Die mapping-lêers is meer waardevol as `id` alleen, omdat `id` slegs die namespace-plaaslike identiteit toon.

As die werklading as UID 0 loop en die mapping toon dat dit nou ooreenstem met host root, moet jy die res van die container se voorregte baie strenger interpreteer.

{{#include ../../../../../banners/hacktricks-training.md}}
