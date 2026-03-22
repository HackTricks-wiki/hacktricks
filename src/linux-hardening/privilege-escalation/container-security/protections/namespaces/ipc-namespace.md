# IPC Naamruimte

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die IPC-naamruimte isoleer **System V IPC objects** en **POSIX message queues**. Dit sluit gedeelde geheue-segmente, semafore, en message queues in wat andersins sigbaar sou wees oor ongerelateerde prosesse op die host. In praktiese terme verhoed dit dat 'n container sommer aan IPC-voorwerpe wat aan ander workloads of die host behoort koppel.

Vergelyk met mount, PID, of user namespaces word die IPC-naamruimte dikwels minder bespreek, maar dit moet nie met irrelevantheid verwar word nie. Gedeelde geheue en verwante IPC-meganismes kan hoogs nuttige toestand bevat. As die host IPC-naamruimte blootgestel word, mag die workload sigbaarheid kry in inter-proses koördinasie-voorwerpe of data wat nooit bedoel was om die container-grens te kruis nie.

## Werking

Wanneer die runtime 'n nuwe IPC-naamruimte skep, kry die proses sy eie geïsoleerde stel IPC-identifiers. Dit beteken dat opdragte soos `ipcs` slegs die voorwerpe in daardie naamruimte vertoon. As die container eerder by die host IPC-naamruimte aansluit, word daardie voorwerpe deel van 'n gedeelde globale aansig.

Dit maak veral saak in omgewings waar toepassings of dienste gedeelde geheue intensief gebruik. Selfs wanneer die container nie direk deur IPC alleen kan ontsnap nie, kan die naamruimte inligting leak of kruis-proses inmenging moontlik maak wat noemenswaardig 'n latere aanval help.

## Laboratorium

Jy kan 'n privaat IPC-naamruimte skep met:
```bash
sudo unshare --ipc --fork bash
ipcs
```
En vergelyk die runtime-gedrag met:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Runtime Gebruik

Docker en Podman isoleer IPC standaard. Kubernetes gee gewoonlik die Pod sy eie IPC namespace, gedeel deur kontainers in dieselfde Pod maar nie standaard met die host nie. Host IPC sharing is moontlik, maar dit moet beskou word as 'n beduidende vermindering in isolasie eerder as 'n geringe runtime-opsie.

## Konfigurasiefoute

Die duidelike fout is `--ipc=host` of `hostIPC: true`. Dit mag gedoen word vir versoenbaarheid met legacy-sagteware of vir gerief, maar dit verander die trust model aansienlik. 'n Ander terugkerende probleem is om IPC eenvoudigweg oor die hoof te sien omdat dit minder dramaties voel as host PID of host networking. In werklikheid, as die workload blaaiers, databasisse, wetenskaplike workloads, of ander sagteware hanteer wat swaar gebruik maak van gedeelde geheue, kan die IPC-oppervlak baie relevant wees.

## Misbruik

Wanneer host IPC gedeel word, kan 'n aanvaller gedeelde geheue-objekte ondersoek of daarmee inmeng, nuwe insigte in host of aangrensende workload-gedrag kry, of die daar geleerde inligting kombineer met proses-sigbaarheid en ptrace-style vermoëns. IPC-deling is dikwels 'n ondersteunende swakheid eerder as die volle breakout-pad, maar ondersteunende swakhede tel omdat hulle werklike aanvalskettings verkort en stabiliseer.

Die eerste nuttige stap is om te lys watter IPC-objekte sigbaar is:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
As die host IPC namespace gedeel word, kan groot shared-memory segments of interessante object-eienaars onmiddellik toepassingsgedrag openbaar:
```bash
ipcs -m -p
ipcs -q -p
```
In sommige omgewings lek die inhoud van `/dev/shm` self lêernaam(e), artefakte of tokens wat die moeite werd is om na te gaan:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC sharing gee selde op sigself onmiddellike host root, maar dit kan data- en koördinasiekanale blootstel wat later process-aanvalle veel makliker maak.

### Volledige Voorbeeld: `/dev/shm` Geheimherwinning

Die mees realistiese volledige misbruikgeval is data-diefstal eerder as direkte ontsnapping. As host IPC of 'n wye gedeelde-geheue-opstelling blootgestel is, kan sensitiewe artefakte soms direk herkry word:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impak:

- onttrekking van geheime of sessiemateriaal wat in gedeelde geheue agtergelaat is
- insig in die toepassings wat tans op die gasheer aktief is
- beter teiken vir latere PID-namespace of ptrace-gebaseerde aanvalle

IPC-deling word dus beter verstaan as 'n **aanvalversterker** eerder as 'n selfstandige host-escape-primitief.

## Kontroles

Hierdie opdragte is bedoel om te beantwoord of die werkbelasting 'n privaat IPC-uitsig het, of betekenisvolle gedeelde geheue of boodskapobjekte sigbaar is, en of `/dev/shm` self nuttige artefakte blootstel.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Wat hier interessant is:

- As `ipcs -a` objekte toon wat deur onverwagte gebruikers of dienste besit word, mag die namespace nie so geïsoleer wees soos verwag nie.
- Groot of ongewoon shared memory segments is dikwels die moeite werd om op te volg.
- 'n breë `/dev/shm` mount is nie outomaties 'n bug nie, maar in sommige omgewings leaks dit filenames, artifacts, en transient secrets.

IPC kry selde soveel aandag as die groter namespace-tipes, maar in omgewings wat dit intensief gebruik, is dit 'n bewuste security-besluit om dit met die host te deel.
{{#include ../../../../../banners/hacktricks-training.md}}
