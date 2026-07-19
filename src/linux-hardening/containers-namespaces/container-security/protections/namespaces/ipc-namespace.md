# IPC-naamruimte

{{#include ../../../../../banners/hacktricks-training.md}}

## Oorsig

Die IPC-naamruimte isoleer **System V IPC-objekte** en **POSIX-boodskaprye**. Dit sluit gedeelde geheuesegmente, semafore en boodskaprye in wat andersins sigbaar sou wees vir onverwante prosesse op die host. In praktiese terme voorkom dit dat ’n container maklik aan IPC-objekte behoortende aan ander workloads of die host koppel.

In vergelyking met mount-, PID- of user-naamruimtes word die IPC-naamruimte dikwels minder bespreek, maar dit moet nie met irrelevansie verwar word nie. Gedeelde geheue en verwante IPC-meganismes kan hoogs nuttige state bevat. As die host se IPC-naamruimte blootgestel word, kan die workload sigbaarheid verkry van inter-proses-koördineringsobjekte of data wat nooit bedoel was om die container-grens oor te steek nie.

## Werking

Wanneer die runtime ’n nuwe IPC-naamruimte skep, kry die proses sy eie geïsoleerde stel IPC-identifiseerders. Dit beteken opdragte soos `ipcs` wys slegs die objekte wat in daardie naamruimte beskikbaar is. As die container eerder by die host se IPC-naamruimte aansluit, word daardie objekte deel van ’n gedeelde globale aansig.

Dit is veral belangrik in omgewings waar toepassings of dienste intensief van gedeelde geheue gebruik maak. Selfs wanneer die container nie direk deur IPC alleen kan escape nie, kan die naamruimte inligting lek of kruis-proses-inmenging moontlik maak wat ’n latere aanval wesenlik kan help.

## Lab

Jy kan ’n private IPC-naamruimte skep met:
```bash
sudo unshare --ipc --fork bash
ipcs
```
En vergelyk runtime-gedrag met:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Runtime-gebruik

Docker en Podman isoleer IPC by verstek. Kubernetes gee die Pod tipies sy eie IPC-namespace, wat deur containers in dieselfde Pod gedeel word, maar nie by verstek met die host nie. Host IPC-sharing is moontlik, maar dit moet as ’n betekenisvolle vermindering in isolasie beskou word, eerder as ’n geringe runtime-opsie.

## Misconfigurations

Die ooglopende fout is `--ipc=host` of `hostIPC: true`. Dit kan vir verenigbaarheid met legacy software of gerief gedoen word, maar dit verander die trust model aansienlik. Nog ’n herhalende probleem is om IPC eenvoudig oor die hoof te sien omdat dit minder dramaties as host PID of host networking voel. In werklikheid kan die IPC-surface baie relevant wees as die workload browsers, databases, scientific workloads of ander software hanteer wat intensief van shared memory gebruik maak.

## Abuse

Wanneer host IPC gedeel word, kan ’n aanvaller shared memory-objects inspekteer of daarmee inmeng, nuwe insig in die gedrag van die host of naburige workloads verkry, of die inligting wat daar geleer is kombineer met process visibility en ptrace-style capabilities. IPC-sharing is dikwels ’n ondersteunende weakness eerder as die volledige breakout path, maar ondersteunende weaknesses is belangrik omdat hulle werklike attack chains verkort en stabiliseer.

Die eerste nuttige stap is om te enumerate watter IPC-objects hoegenaamd sigbaar is:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
As die host se IPC-naamruimte gedeel word, kan groot gedeeldegeheue-segmente of interessante objek-eienaars toepassingsgedrag onmiddellik onthul:
```bash
ipcs -m -p
ipcs -q -p
```
In sommige omgewings leak die inhoud van `/dev/shm` self lêername, artefakte of tokens wat die moeite werd is om na te gaan:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC-sharing gee selde op sy eie onmiddellike host root, maar dit kan data- en koördineringskanale blootstel wat latere process-aanvalle aansienlik makliker maak.

### Volledige voorbeeld: Herwinning van geheime uit `/dev/shm`

Die mees realistiese volledige misbruikgeval is data-diefstal eerder as direkte escape. Indien host-IPC of ’n breë gedeelde-geheue-uitleg blootgestel word, kan sensitiewe artefakte soms direk herwin word:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impak:

- onttrekking van secrets of sessiemateriaal wat in gedeelde geheue agtergelaat is
- insig in die toepassings wat tans op die host aktief is
- beter teikenkeuse vir latere PID-namespace- of ptrace-gebaseerde attacks

IPC-sharing word dus beter verstaan as ’n **aanvalversterker** eerder as ’n selfstandige host-escape-primitief.

## Kontroles

Hierdie commands is bedoel om te bepaal of die workload ’n private IPC-aansig het, of betekenisvolle gedeeldegeheue- of boodskapobjekte sigbaar is, en of `/dev/shm` self nuttige artifacts blootstel.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Wat hier interessant is:

- As `ipcs -a` objekte onthul wat deur onverwagte gebruikers of dienste besit word, is die namespace moontlik nie so geïsoleer soos verwag is nie.
- Groot of ongewone shared memory-segmente is dikwels verdere ondersoek werd.
- ’n Breë `/dev/shm`-mount is nie outomaties ’n fout nie, maar in sommige omgewings lek dit lêername, artefakte en tydelike secrets.

IPC kry selde soveel aandag soos die groter namespace-tipes, maar in omgewings wat dit intensief gebruik, is dit ’n sekuriteitsbesluit om dit met die host te deel.
{{#include ../../../../../banners/hacktricks-training.md}}
