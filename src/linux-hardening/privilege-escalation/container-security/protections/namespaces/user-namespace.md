# User Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die user namespace verander die betekenis van user- en group IDs deur die kernel toe te laat om die IDs wat binne die namespace gesien word na ander IDs buite te map. Dit is een van die belangrikste moderne container protections omdat dit direk die grootste historiese probleem in klassieke containers aanspreek: **root inside the container used to be uncomfortably close to root on the host**.

Met user namespaces kan 'n proses as UID 0 binne die container loop en steeds ooreenstem met 'n unprivileged UID-reeks op die host. Dit beteken die proses kan soos root optree vir baie in-container take, terwyl dit vanuit die host se perspektief baie minder mag het. Dit los nie elke container security-probleem op nie, maar dit verander die gevolge van 'n container compromise aansienlik.

## Werking

'n user namespace het mapping-lêers soos `/proc/self/uid_map` en `/proc/self/gid_map` wat beskryf hoe namespace IDs na parent IDs vertaal. As root binne die namespace na 'n unprivileged host UID map, dan dra operasies wat regte host root sou vereis eenvoudig nie dieselfde gewig nie. Dit is hoekom user namespaces sentraal is tot **rootless containers** en waarom hulle een van die grootste verskille is tussen ouer rootful container defaults en meer moderne least-privilege-ontwerpe.

Die punt is subtiel maar deurslaggewend: root inside the container is nie uitgevee nie, dit word **vertaal**. Die proses ervaar steeds 'n root-like omgewing plaaslik, maar die host behoort dit nie as volwaardige root te behandel nie.

## Lab

'n handmatige toets is:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Dit laat die huidige gebruiker binne die namespace as root voorkom, terwyl hy buite dit steeds nie host root is nie. Dit is een van die beste eenvoudige demos om te verstaan waarom user namespaces so waardevol is.

In containers kan jy die sigbare mapping vergelyk met:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Die presiese uitset hang af of die engine user namespace remapping gebruik of 'n meer tradisionele rootful-konfigurasie.

Jy kan die mapping ook vanaf die host-kant uitlees met:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Gebruik tydens uitvoering

Rootless Podman is een van die duidelikste voorbeelde van user namespaces wat as 'n sekuriteitsmeganisme van eerste rang behandel word. Rootless Docker is ook daarop staatgemaak. Docker se userns-remap-ondersteuning verbeter ook die veiligheid in rootful daemon-ontplooiings, alhoewel histories baie ontplooiings dit gedeaktiveer gelaat het vir versoenbaarheidsredes. Kubernetes se ondersteuning vir user namespaces het verbeter, maar aanneming en verstekwaardes wissel na gelang van runtime, distro en clusterbeleid. Incus/LXC-stelsels vertrou ook sterk op UID/GID-verskuiwing en idmapping-idees.

Die algemene neiging is duidelik: omgewings wat user namespaces ernstig gebruik, bied gewoonlik 'n beter antwoord op die vraag "wat beteken 'container root' eintlik?" as omgewings wat dit nie doen nie.

## Gevorderde toewysingsbesonderhede

Wanneer 'n ongeprivilegieerde proses skryf na `uid_map` of `gid_map`, pas die kernel strenger reëls toe as vir 'n geprivilegieerde ouer-namespace-skribent. Slegs beperkte toewysings word toegelaat, en vir `gid_map` moet die skrywer gewoonlik eers `setgroups(2)` deaktiveer:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Hierdie detail is belangrik omdat dit verduidelik waarom gebruiker-naamruimte-opstelling soms in rootless-eksperimente misluk en waarom runtimes sorgsame hulp-logika rondom UID/GID-delegering nodig het.

Nog 'n gevorderde funksie is die **ID-mapped mount**. In plaas daarvan om eienaarskap op die skyf te verander, pas 'n ID-mapped mount 'n gebruiker-naamruimte-kartering op 'n mount toe sodat eienaarskap deur daardie mount-uitsig vertaal lyk. Dit is veral relevant in rootless en moderne runtime-opstellings omdat dit toelaat dat gedeelde host-paaie gebruik word sonder rekursiewe `chown`-operasies. Sekuriteitsgewys verander die funksie hoe skryfbaar 'n bind mount vanuit binne die naamruimte verskyn, al herskryf dit nie die onderliggende lêerstelsel-metadata nie.

Laastens, onthou dat wanneer 'n proses 'n nuwe gebruiker-naamruimte skep of daartoe toetree, dit 'n volledige bevoegdheidsstel ontvang **binne daardie naamruimte**. Dit beteken nie dat dit skielik gasheer-globale mag verkry het nie. Dit beteken dat daardie bevoegdhede slegs gebruik kan word waar die naamruimtemodel en ander beskermings dit toelaat. Dit is die rede waarom `unshare -U` skielik montering of naamruimte-lokale bevoorregte operasies moontlik kan maak sonder om direk die gasheer-root-grens te laat verdwyn.

## Miskonfigurasies

Die grootste swakheid is eenvoudigweg om nie gebruiker-naamruimtes te gebruik in omgewings waar dit uitvoerbaar sou wees nie. As container-root te direk op host-root gemap word, word skryfbare host-mounts en bevoorregte kernel-operasies baie meer gevaarlik. 'n Ander probleem is om gasheer-gebruiker-naamruimte-deel af te dwing of remapping vir versoenbaarheid te deaktiveer sonder om te besef hoeveel dit die vertrouensgrens verander.

Gebruiker-naamruimtes moet ook saam met die res van die model oorweeg word. Selfs wanneer hulle aktief is, kan 'n breë runtime API-blootstelling of 'n baie swak runtime-konfigurasie steeds privilege escalation deur ander paaie toelaat. Maar sonder hulle word baie ou breakout-klasses makliker om uit te buit.

## Misbruik

As die container rootful is sonder gebruiker-naamruimte-separasie, word 'n skryfbare host bind mount baie meer gevaarlik omdat die proses werklik as host-root kan skryf. Gevaarlike bevoegdhede word daarom ook meer betekenisvol. Die aanvaller hoef nie meer so hard teen die vertaalgrens te baklei nie, omdat die vertaalgrens byna nie bestaan nie.

Die aanwezigheid of afwesigheid van gebruiker-naamruimte moet vroeëlik nagegaan word wanneer 'n container breakout-pad geëvalueer word. Dit beantwoord nie elke vraag nie, maar dit wys onmiddellik of "root in container" direkte gasheer-relevansie het.

Die mees praktiese misbruikpatroon is om die kartering te bevestig en dan onmiddellik te toets of inhoud wat op die gasheer gemount is, skryfbaar is met gasheer-relevante bevoegdhede:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
As die lêer as die werklike host root geskep word, is user namespace isolation effektief afwesig vir daardie pad. Op daardie punt word klassieke host-file abuses realisties:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
'n veiliger bevestiging tydens 'n live assessment is om 'n onskadelike merker te skryf in plaas daarvan om kritieke lêers te wysig:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Hierdie kontroles maak saak omdat hulle die werklike vraag vinnig beantwoord: is root in hierdie container genoegsaam aan host root gekoppel dat 'n writable host mount onmiddellik 'n host compromise path word?

### Volledige Voorbeeld: Regaining Namespace-Local Capabilities

As seccomp `unshare` toelaat en die omgewing 'n nuwe user namespace toelaat, kan die proses 'n volledige capability set binne daardie nuwe namespace herkry:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Dit is nie op sigself 'n host escape' nie. Die rede waarom dit saak maak, is dat user namespaces privileged namespace-local actions weer kan toelaat, wat later saam kan kombineer met weak mounts, vulnerable kernels, of sleg blootgestelde runtime surfaces.

## Checks

Hierdie commands is bedoel om die belangrikste vraag op hierdie bladsy te beantwoord: na wat map root binne hierdie container op die host?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
- As die proses UID 0 is en die maps `host-root`-toewysing direk of baie nou toon, is die container veel gevaarliker.
- As root na 'n onbevoorregte gasheer-reeks kaarteer, is dit 'n baie veiliger basislyn en dui dit gewoonlik op werklike gebruiker-naamruimte isolasie.
- Die toewysingslêers is meer waardevol as `id` alleen, omdat `id` slegs die naamruimtelike plaaslike identiteit toon.

As die werkbelasting as UID 0 loop en die toewysing wys dat dit nou ooreenstem met gasheer-root, moet jy die res van die kontainer se bevoegdhede baie strenger interpreteer.
{{#include ../../../../../banners/hacktricks-training.md}}
