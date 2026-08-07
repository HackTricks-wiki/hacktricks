# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces is die kernelfunksie wat ’n container soos "sy eie masjien" laat voel, al is dit in werklikheid net ’n host-prosesboom. Hulle skep nie ’n nuwe kernel nie en virtualiseer nie alles nie, maar stel die kernel wel in staat om verskillende aansigte van geselekteerde hulpbronne aan verskillende groepe prosesse voor te lê. Dit is die kern van die container-illusie: die workload sien ’n filesystem, prosestabel, netwerkstack, hostname, IPC-hulpbronne en user/group-identiteitsmodel wat plaaslik lyk, al word die onderliggende stelsel gedeel.

Dit is waarom namespaces die eerste konsep is waarmee die meeste mense kennis maak wanneer hulle leer hoe containers werk. Terselfdertyd is dit een van die konsepte wat die meeste verkeerd verstaan word, omdat lesers dikwels aanvaar dat "het namespaces" beteken "is veilig geïsoleer". In werklikheid isoleer ’n namespace slegs die spesifieke klas hulpbronne waarvoor dit ontwerp is. ’n Proses kan ’n private PID namespace hê en steeds gevaarlik wees omdat dit ’n skryfbare host bind mount het. Dit kan ’n private network namespace hê en steeds gevaarlik wees omdat dit `CAP_SYS_ADMIN` behou en sonder seccomp loop. Namespaces is fundamenteel, maar hulle is slegs een laag in die finale grens.

## Namespace Types

Linux-containers maak gewoonlik terselfdertyd op verskeie namespace-types staat. Die **mount namespace** gee die proses ’n afsonderlike mount-tabel en gevolglik ’n beheerde filesystem-aansig. Die **PID namespace** verander prosessigbaarheid en -nommering sodat die workload sy eie prosesboom sien. Die **network namespace** isoleer interfaces, roetes, sockets en firewall-status. Die **IPC namespace** isoleer SysV IPC en POSIX message queues. Die **UTS namespace** isoleer hostname en NIS-domainnaam. Die **user namespace** karteer user- en group-ID’s oor sodat root binne die container nie noodwendig root op die host beteken nie. Die **cgroup namespace** virtualiseer die sigbare cgroup-hiërargie, en die **time namespace** virtualiseer geselekteerde clocks in nuwer kernels.

Elkeen van hierdie namespaces los ’n ander probleem op. Daarom kom praktiese container security analysis dikwels daarop neer om te kontroleer **watter namespaces geïsoleer is** en **watter doelbewus met die host gedeel word**.

## Host Namespace Sharing

Baie container-breakouts begin nie met ’n kernel vulnerability nie. Hulle begin wanneer ’n operator die isolasiemodel doelbewus verswak. Die voorbeelde `--pid=host`, `--network=host` en `--userns=host` is **Docker/Podman-style CLI flags** wat hier as konkrete voorbeelde van host namespace sharing gebruik word. Ander runtimes stel dieselfde idee op verskillende maniere uit. In Kubernetes verskyn die ekwivalente gewoonlik as Pod-settings soos `hostPID: true`, `hostNetwork: true` of `hostIPC: true`. In laer-vlak runtime stacks soos containerd of CRI-O word dieselfde gedrag dikwels bereik deur die gegenereerde OCI runtime-konfigurasie, eerder as deur ’n gebruikersgerigte flag met dieselfde naam. In al hierdie gevalle is die resultaat soortgelyk: die workload ontvang nie meer die verstek-geïsoleerde namespace-aansig nie.

Daarom moet namespace-reviews nooit by "die proses is in ’n namespace" ophou nie. Die belangrike vraag is of die namespace privaat tot die container is, met sibling-containers gedeel word, of direk by die host aansluit. In Kubernetes verskyn dieselfde idee met flags soos `hostPID`, `hostNetwork` en `hostIPC`. Die name verander tussen platforms, maar die risk pattern is dieselfde: ’n gedeelde host namespace maak die container se oorblywende privileges en bereikbare host-state baie meer betekenisvol.

## Inspection

Die eenvoudigste oorsig is:
```bash
ls -l /proc/self/ns
```
Elke inskrywing is ’n simboliese skakel met ’n inode-agtige identifiseerder. As twee prosesse na dieselfde naamruimte-identifiseerder wys, is hulle in dieselfde naamruimte van daardie tipe. Dit maak `/proc` ’n baie nuttige plek om die huidige proses met ander interessante prosesse op die masjien te vergelyk.

Hierdie vinnige opdragte is dikwels genoeg om te begin:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Van daar af is die volgende stap om die container process met host- of naburige processes te vergelyk en te bepaal of ’n namespace werklik private is of nie.

### Enumerating Namespace Instances From The Host

Wanneer jy reeds host access het en wil verstaan hoeveel afsonderlike namespaces van ’n gegewe tipe bestaan, bied `/proc` ’n vinnige inventaris:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name pid    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name net    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name ipc    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name uts    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name user   -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name time   -exec readlink {} \; 2>/dev/null | sort -u
```
As jy wil uitvind watter prosesse aan een spesifieke namespace-identifiseerder behoort, skakel van `readlink` na `ls -l` en gebruik grep vir die teiken-namespace-nommer:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Hierdie opdragte is nuttig omdat hulle jou in staat stel om te bepaal of ’n host een geïsoleerde workload, veelvuldige geïsoleerde workloads, of ’n mengsel van gedeelde en private namespace-instansies gebruik.

### Betreding van ’n Teiken-namespace

Wanneer die caller voldoende voorregte het, is `nsenter` die standaardmanier om by ’n ander proses se namespace aan te sluit:
```bash
nsenter -m TARGET_PID --pid /bin/bash   # mount
nsenter -t TARGET_PID --pid /bin/bash   # pid
nsenter -n TARGET_PID --pid /bin/bash   # network
nsenter -i TARGET_PID --pid /bin/bash   # ipc
nsenter -u TARGET_PID --pid /bin/bash   # uts
nsenter -U TARGET_PID --pid /bin/bash   # user
nsenter -C TARGET_PID --pid /bin/bash   # cgroup
nsenter -T TARGET_PID --pid /bin/bash   # time
```
Die punt daarvan om hierdie vorms saam te lys, is nie dat elke assessering almal daarvan benodig nie, maar dat namespace-spesifieke post-exploitation dikwels baie makliker word sodra die operateur die presiese invoersintaksis ken, eerder as om slegs die vorm vir alle naamruimtes te onthou.

## Bladsye

Die volgende bladsye verduidelik elke naamruimte in meer besonderhede:

{{#ref}}
mount-namespace.md
{{#endref}}

{{#ref}}
pid-namespace.md
{{#endref}}

{{#ref}}
network-namespace.md
{{#endref}}

{{#ref}}
ipc-namespace.md
{{#endref}}

{{#ref}}
uts-namespace.md
{{#endref}}

{{#ref}}
user-namespace.md
{{#endref}}

{{#ref}}
cgroup-namespace.md
{{#endref}}

{{#ref}}
time-namespace.md
{{#endref}}

Hou twee idees in gedagte terwyl jy dit lees. Eerstens isoleer elke naamruimte slegs een soort aansig. Tweedens is ’n private naamruimte slegs nuttig indien die res van die privilege-model steeds daardie isolasie betekenisvol maak.

## Looptydverstekwaardes

| Runtime / platform | Verstekposisie van naamruimtes | Algemene handmatige verswakking |
| --- | --- | --- |
| Docker Engine | Nuwe mount-, PID-, network-, IPC- en UTS-naamruimtes by verstek; user namespaces is beskikbaar, maar nie by verstek in standaard rootful-opstellings geaktiveer nie | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Nuwe naamruimtes by verstek; rootless Podman gebruik outomaties ’n user namespace; verstekwaardes vir cgroup-naamruimtes hang van die cgroup-weergawe af | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods deel **nie** by verstek die host se PID, network of IPC nie; Pod-networking is privaat tot die Pod, nie tot elke individuele container nie; user namespaces is opt-in via `spec.hostUsers: false` op ondersteunde clusters | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / die weglating van user-namespace opt-in, bevoorregte workload-instellings |
| containerd / CRI-O onder Kubernetes | Volg gewoonlik Kubernetes Pod-verstekwaardes | dieselfde as die Kubernetes-ry; direkte CRI/OCI-spesifikasies kan ook joins van host-naamruimtes versoek |

Die hoofreël vir portability is eenvoudig: die **konsep** van host-naamruimte-sharing is algemeen oor runtimes heen, maar die **sintaksis** is runtime-spesifiek.

{{#include ../../../../../banners/hacktricks-training.md}}
