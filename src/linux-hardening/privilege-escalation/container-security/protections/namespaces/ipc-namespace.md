# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die IPC namespace isoleer **System V IPC objects** en **POSIX message queues**. Dit sluit shared memory segments, semaphores en message queues in wat andersins sigbaar sou wees oor nie-verwante prosesse op die host. In praktiese terme verhinder dit dat 'n container sommer net aan IPC objects wat aan ander workloads of die host behoort, kan koppel.

In vergelyking met mount, PID of user namespaces word die IPC namespace gereeld minder bespreek, maar dit moet nie met onbelangrikheid verwar word nie. Shared memory en verwante IPC mechanisms kan hoogs bruikbare state bevat. As die host IPC namespace blootgestel word, kan die workload sigbaarheid kry in inter-process coordination objects of data wat nooit bedoel was om die container boundary te oorskry nie.

## Werking

Wanneer die runtime 'n vars IPC namespace skep, kry die proses sy eie geïsoleerde stel IPC identifiers. Dit beteken kommando's soos `ipcs` wys slegs die objekte wat in daardie namespace beskikbaar is. As die container in plaas daarvan by die host IPC namespace aansluit, word daardie objekte deel van 'n gedeelde globale aansig.

Dit is veral belangrik in omgewings waar toepassings of dienste intensief shared memory gebruik. Selfs as die container nie direk slegs deur IPC kan ontsnap nie, kan die namespace inligting leak of cross-process interferensie moontlik maak wat 'n later attack beduidend help.

## Laboratorium

Jy kan 'n private IPC namespace skep met:
```bash
sudo unshare --ipc --fork bash
ipcs
```
En vergelyk runtime-gedrag met:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Runtime Usage

Docker en Podman isoleer IPC standaard. Kubernetes gee gewoonlik die Pod sy eie IPC namespace, gedeel deur containers in dieselfde Pod maar nie standaard met die host nie. Host IPC-deling is moontlik, maar dit moet as 'n betekenisvolle vermindering van isolasie beskou word eerder as 'n geringe runtime-opsie.

## Misconfigurations

Die voor die hand liggende fout is `--ipc=host` of `hostIPC: true`. Dit mag gedoen word vir versoenbaarheid met legacy-software of vir gerief, maar dit verander die vertrouensmodel aansienlik. 'n Ander herhalende probleem is om IPC eenvoudig oor die hoof te sien omdat dit minder dramaties voel as host PID of host networking. In werklikheid, as die workload browsers, databases, wetenskaplike workloads, of ander sagteware hanteer wat swaar gebruik maak van gedeelde geheue, kan die IPC-oppervlak baie relevant wees.

## Abuse

Wanneer host IPC gedeel word, kan 'n aanvaller gedeelde geheue-objekte inspekteer of daarmee inmeng, nuwe insig in host of naburige workload-gedrag verkry, of die inligting daar verkry gekombineer met process visibility en ptrace-style vermoëns. IPC-deling is dikwels 'n ondersteunende swakheid eerder as die volledige breakout-pad, maar ondersteunende swakhede maak saak omdat hulle werklike aanvalskettings verkort en stabiliseer.

Die eerste nuttige stap is om te bepaal watter IPC-objekte sigbaar is:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
As die host IPC namespace gedeel word, kan groot shared-memory-segmente of interessante objek-eienaars onmiddellik toepassingsgedrag openbaar:
```bash
ipcs -m -p
ipcs -q -p
```
In sommige omgewings leak die inhoud van `/dev/shm` self lêername, artefakte of tokens wat die moeite werd is om te kontroleer:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC-deling gee selde op sigself onmiddellik host root, maar dit kan data- en koördinasiekanale blootlê wat latere prosesaanvalle baie makliker maak.

### Volledige Voorbeeld: `/dev/shm` Herwinning van geheime data

Die mees realistiese volledige misbruikgeval is data-diefstal eerder as direkte ontsnapping. As host IPC of 'n uitgebreide gedeelde geheue-indeling blootgestel is, kan sensitiewe artefakte soms direk herstel word:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impak:

- onttrekking van geheime of sessiemateriaal wat in gedeelde geheue agtergelaat is
- insig in die toepassings wat tans op die host aktief is
- beter teikenrigting vir later PID-namespace of ptrace-gebaseerde aanvalle

IPC sharing word dus eerder beskou as 'n **attack amplifier** as 'n standalone host-escape primitive.

## Kontroles

Hierdie opdragte is bedoel om te bepaal of die workload 'n private IPC-uitsig het, of betekenisvolle gedeelde-geheue of boodskapobjekte sigbaar is, en of `/dev/shm` self nuttige artefakte blootstel.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Wat hier interessant is:

- As `ipcs -a` objekte openbaar wat deur onverwagte gebruikers of dienste besit word, mag die namespace nie so geïsoleer wees soos verwag nie.
- Groot of ongewone gedeelde geheue-segmente is dikwels die moeite werd om verder na te gaan.
- ’n Breë `/dev/shm` mount is nie outomaties ’n bug nie, maar in sommige omgewings it leaks filenames, artifacts, and transient secrets.

IPC kry selde soveel aandag as die groter namespace-tipes, maar in omgewings wat dit intensief gebruik, is die besluit om dit met die host te deel uiters ’n sekuriteitsbesluit.
{{#include ../../../../../banners/hacktricks-training.md}}
