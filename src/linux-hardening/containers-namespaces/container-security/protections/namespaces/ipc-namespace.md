# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die IPC namespace isoleer **System V IPC objects** en **POSIX message queues**. Dit sluit shared memory segments, semaphores en message queues in wat andersins sigbaar sou wees oor onverwante prosesse op die host. In praktiese terme voorkom dit dat ’n container sommer aan IPC objects kan koppel wat aan ander workloads of die host behoort.

In vergelyking met mount-, PID- of user namespaces word die IPC namespace dikwels minder bespreek, maar dit moet nie met irrelevansie verwar word nie. Shared memory en verwante IPC-meganismes kan hoogs nuttige state bevat. As die host IPC namespace blootgestel word, kan die workload sigbaarheid verkry van inter-process coordination objects of data wat nooit bedoel was om die container-grens te oorsteek nie.

## Werking

Wanneer die runtime ’n nuwe IPC namespace skep, kry die proses sy eie geïsoleerde stel IPC identifiers. Dit beteken opdragte soos `ipcs` wys slegs die objects wat in daardie namespace beskikbaar is. As die container eerder by die host IPC namespace aansluit, word daardie objects deel van ’n gedeelde globale view.

Dit is veral belangrik in omgewings waar applications of services shared memory intensief gebruik. Selfs wanneer die container nie direk deur IPC alleen kan escape nie, kan die namespace inligting lek of cross-process interference moontlik maak wat ’n latere aanval wesenlik kan help.

## Lab

Jy kan ’n private IPC namespace skep met:
```bash
sudo unshare --ipc --fork bash
ipcs
```
En vergelyk runtime-gedrag met:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Runtimegebruik

Docker en Podman isoleer IPC by verstek. Kubernetes gee die Pod gewoonlik sy eie IPC namespace, wat deur containers in dieselfde Pod gedeel word, maar nie by verstek met die host nie. Host IPC sharing is moontlik, maar dit moet as 'n betekenisvolle vermindering in isolasie beskou word, eerder as 'n geringe runtime-opsie.

## Wanopstellings

Die ooglopende fout is `--ipc=host` of `hostIPC: true`. Dit kan gedoen word vir versoenbaarheid met legacy-sagteware of geriefshalwe, maar dit verander die trust model aansienlik. Nog 'n herhalende probleem is om IPC eenvoudig oor die hoof te sien omdat dit minder dramaties voorkom as host PID of host networking. In werklikheid kan die IPC-oppervlak baie relevant wees as die workload browsers, databasisse, wetenskaplike workloads of ander sagteware hanteer wat intensief van shared memory gebruik maak.

## Misbruik

Wanneer host IPC gedeel word, kan 'n aanvaller shared memory-objekte inspekteer of daarmee inmeng, nuwe insig verkry in die gedrag van die host of naburige workloads, of die inligting wat daar verkry is kombineer met process visibility en ptrace-style capabilities. IPC sharing is dikwels 'n ondersteunende swakheid eerder as die volledige breakout path, maar ondersteunende swakhede is belangrik omdat hulle werklike attack chains verkort en stabiliseer.

Die eerste nuttige stap is om te enumerer watter IPC-objekte enigsins sigbaar is:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
As die host se IPC namespace gedeel word, kan groot shared-memory-segmente of interessante object owners toepassingsgedrag onmiddellik openbaar:
```bash
ipcs -m -p
ipcs -q -p
```
In sommige omgewings lek die inhoud van `/dev/shm` self lêername, artefakte of tokens wat die moeite werd is om na te gaan:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC-sharing gee selde op sigself onmiddellike host-root-toegang, maar dit kan data- en koördineringskanale blootlê wat latere prosesaanvalle aansienlik makliker maak.

### Volledige voorbeeld: Herwinning van `/dev/shm`-geheime

Die mees realistiese volledige misbruikgeval is data-diefstal eerder as direkte ontsnapping. As host-IPC of ’n breë gedeelde-geheue-uitleg blootgestel word, kan sensitiewe artefakte soms direk herwin word:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impak:

- onttrekking van geheime of sessiemateriaal wat in gedeelde geheue agtergelaat is
- insig in die toepassings wat tans op die host aktief is
- beter teikenbepaling vir latere PID-namespace- of ptrace-based attacks

IPC-deling word dus beter verstaan as ’n **aanvalversterker** eerder as ’n selfstandige host-escape primitive.

## Kontroles

Hierdie opdragte is bedoel om vas te stel of die werklading ’n private IPC-aansig het, of betekenisvolle gedeeldegeheue- of boodskapobjekte sigbaar is, en of `/dev/shm` self nuttige artefakte blootstel.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Wat is hier interessant:

- As `ipcs -a` objects onthul wat deur onverwagte users of services besit word, is die namespace moontlik nie so geïsoleer soos verwag nie.
- Groot of ongewone shared memory-segmente is dikwels die moeite werd om verder te ondersoek.
- ’n Breë `/dev/shm`-mount is nie outomaties ’n bug nie, maar in sommige omgewings lek dit filenames, artifacts en tydelike secrets.

IPC ontvang selde soveel aandag soos die groter namespace-tipes, maar in omgewings wat dit intensief gebruik, is die deel daarvan met die host beslis ’n security-besluit.

{{#include ../../../../../banners/hacktricks-training.md}}
