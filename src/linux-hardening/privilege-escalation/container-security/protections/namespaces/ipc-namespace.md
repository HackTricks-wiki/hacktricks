# IPC-naamruimte

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die IPC-naamruimte isoleer **System V IPC objects** en **POSIX message queues**. Dit sluit shared memory segments, semaphores, en message queues in wat andersins sigbaar sou wees oor ongekoppelde prosesse op die gasheer. In praktyk keer dit dat ’n kontener sommer net aan IPC-objects wat aan ander workloads of die gasheer behoort, kan koppel.

Compared with mount, PID, or user namespaces, die IPC-naamruimte word dikwels minder bespreek, maar dit moet nie met onbelangrikheid verwar word nie. Shared memory en verwante IPC-meganismes kan baie nuttige toestand bevat. As die host IPC namespace blootgestel word, kan die workload sig kry in inter-proses-koördinering-objects of data wat nooit bedoel was om die kontener-grens te kruis nie.

## Werking

Wanneer die runtime ’n vars IPC-naamruimte skep, kry die proses sy eie geïsoleerde stel IPC-identifiers. Dit beteken opdragte soos `ipcs` wys slegs die objects wat in daardie naamruimte beskikbaar is. As die kontener in plaas daarvan by die host IPC namespace aansluit, word daardie objects deel van ’n gedeelde globale aansig.

Dit maak veral saak in omgewings waar toepassings of dienste shared memory swaar gebruik. Selfs wanneer die kontener nie direk deur middel van IPC alleen kan uitbreek nie, kan die naamruimte informasie leak of kruis-proses-interopferensie moontlik maak wat beduidend ’n later aanval help.

## Laboratorium

Jy kan ’n private IPC-naamruimte skep met:
```bash
sudo unshare --ipc --fork bash
ipcs
```
En vergelyk die runtime-gedrag met:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Runtime Usage

Docker and Podman isoleer IPC standaard. Kubernetes gee gewoonlik die Pod sy eie IPC namespace, gedeel deur die containers in dieselfde Pod maar nie standaard met die host nie. Host IPC sharing is possible, maar dit moet as 'n betekenisvolle vermindering van isolasie beskou word eerder as 'n geringe runtime-opsie.

## Misconfigurations

Die voor die hand liggende fout is `--ipc=host` of `hostIPC: true`. Dit mag gedoen word vir versoenbaarheid met legacy software of vir gerief, maar dit verander die vertrouensmodel aansienlik. Nog 'n herhalende probleem is eenvoudig om IPC oor die hoof te sien omdat dit minder dramaties lyk as host PID of host networking. In werklikheid, as die workload browsers, databases, scientific workloads of ander software hanteer wat swaar gebruik maak van shared memory, kan die IPC-oppervlakte baie relevant wees.

## Abuse

Wanneer host IPC gedeel word, kan 'n aanvaller shared memory objects inspekteer of daarmee inmeng, nuwe insigte in host of naburige workload-gedrag verkry, of die daar geleerde inligting kombineer met process visibility en ptrace-style capabilities. IPC sharing is dikwels 'n ondersteunende swakheid eerder as die volle breakout-pad, maar ondersteunende swakhede is belangrik omdat hulle werklike aanvalskettings verkort en stabieler maak.

Die eerste nuttige stap is om te lys watter IPC-objekte sigbaar is:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
As die host IPC namespace gedeel word, kan groot gedeelde geheue-segmente of interessante objek-eienaars onmiddellik toepassingsgedrag openbaar:
```bash
ipcs -m -p
ipcs -q -p
```
In sommige omgewings leak die inhoud van /dev/shm self lêername, artefakte of tokens wat die moeite werd is om na te kyk:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC sharing gee selde op sigself onmiddellik host root, maar dit kan data en koördinasiekanale blootstel wat latere prosesaanvalle baie makliker maak.

### Volledige voorbeeld: `/dev/shm` Geheimherwinning

Die mees realistiese volledige misbruikgeval is diefstal van data eerder as direkte ontsnapping. As host IPC of 'n breë gedeelde geheue-opstelling blootgestel is, kan sensitiewe artefakte soms direk herwin word:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impak:

- uittrekking van geheime of sessiemateriaal wat in gedeelde geheue agtergelaat is
- insig in die toepassings wat tans op die host aktief is
- beter teikenrigting vir latere PID-namespace of ptrace-based attacks

IPC sharing word daarom beter verstaan as 'n **aanvalsversterker** in plaas van 'n op sigself staande host-escape primitive.

## Kontroles

Hierdie opdragte is bedoel om te beantwoord of die werkbelasting 'n private IPC-uitsig het, of betekenisvolle gedeelde-geheue- of boodskap-objekte sigbaar is, en of `/dev/shm` self nuttige artefakte blootstel.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
- As `ipcs -a` objekte toon wat deur onverwagte gebruikers of dienste besit word, mag die namespace nie so geïsoleer wees as wat verwag is nie.
- Groot of ongewone gedeelde geheue-segmente is dikwels die moeite werd om verder te ondersoek.
- 'n Breë `/dev/shm` mount is nie outomaties 'n fout nie, maar in sommige omgewings leak dit lêernamen, artefakte, en kortstondige geheime.

IPC ontvang selde soveel aandag soos die groter namespace-tipes, maar in omgewings wat dit intensief gebruik, is dit om dit met die host te deel definitief 'n sekuriteitsbesluit.
