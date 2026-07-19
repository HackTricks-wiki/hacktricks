# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces is die kernel-funksie wat ’n container soos “sy eie masjien” laat voel, al is dit eintlik net ’n host se process tree. Hulle skep nie ’n nuwe kernel nie en virtualiseer nie alles nie, maar hulle laat die kernel toe om verskillende aansigte van geselekteerde hulpbronne aan verskillende groepe prosesse te bied. Dit is die kern van die container-illusie: die workload sien ’n filesystem, process table, network stack, hostname, IPC-hulpbronne en user/group-identiteitsmodel wat plaaslik voorkom, al word die onderliggende stelsel gedeel.

Dit is waarom namespaces die eerste konsep is waarmee die meeste mense kennis maak wanneer hulle leer hoe containers werk. Terselfdertyd is hulle een van die konsepte wat die meeste verkeerd verstaan word, omdat lesers dikwels aanneem dat “het namespaces” beteken “is veilig geïsoleer”. In werklikheid isoleer ’n namespace slegs die spesifieke klas hulpbronne waarvoor dit ontwerp is. ’n Process kan ’n private PID namespace hê en steeds gevaarlik wees omdat dit ’n skryfbare host bind mount het. Dit kan ’n private network namespace hê en steeds gevaarlik wees omdat dit `CAP_SYS_ADMIN` behou en sonder seccomp loop. Namespaces is fundamenteel, maar hulle is slegs een laag in die finale grens.

## Namespace-tipes

Linux-containers maak gewoonlik gelyktydig op verskeie namespace-tipes staat. Die **mount namespace** gee die process ’n aparte mount table en dus ’n beheerde filesystem-aansig. Die **PID namespace** verander process-sigbaarheid en -nommering sodat die workload sy eie process tree sien. Die **network namespace** isoleer interfaces, routes, sockets en firewall-state. Die **IPC namespace** isoleer SysV IPC en POSIX message queues. Die **UTS namespace** isoleer hostname en NIS-domeinnaam. Die **user namespace** karteer user- en group-ID’s מחדש sodat root binne die container nie noodwendig root op die host beteken nie. Die **cgroup namespace** virtualiseer die sigbare cgroup-hiërargie, en die **time namespace** virtualiseer geselekteerde clocks in nuwer kernels.

Elkeen van hierdie namespaces los ’n ander probleem op. Daarom kom praktiese container-security-analise dikwels neer op die nagaan van **watter namespaces geïsoleer is** en **watter doelbewus met die host gedeel word**.

## Host Namespace Sharing

Baie container-breakouts begin nie met ’n kernel-kwesbaarheid nie. Hulle begin wanneer ’n operator die isolasiemodel doelbewus verswak. Die voorbeelde `--pid=host`, `--network=host` en `--userns=host` is **Docker/Podman-styl CLI-flags** wat hier as konkrete voorbeelde van host namespace sharing gebruik word. Ander runtimes druk dieselfde idee anders uit. In Kubernetes verskyn die ekwivalente gewoonlik as Pod-instellings soos `hostPID: true`, `hostNetwork: true` of `hostIPC: true`. In laervlak-runtime-stacks soos containerd of CRI-O word dieselfde gedrag dikwels bereik deur die gegenereerde OCI-runtimekonfigurasie, eerder as deur ’n gebruikersgerigte flag met dieselfde naam. In al hierdie gevalle is die resultaat soortgelyk: die workload ontvang nie meer die verstek-geïsoleerde namespace-aansig nie.

Daarom moet namespace-oorsigte nooit stop by “die process is in een of ander namespace” nie. Die belangrike vraag is of die namespace privaat tot die container is, met sibling-containers gedeel word, of direk by die host aangesluit is. In Kubernetes verskyn dieselfde idee met flags soos `hostPID`, `hostNetwork` en `hostIPC`. Die name verander tussen platforms, maar die risikopatroon bly dieselfde: ’n gedeelde host namespace maak die container se oorblywende privileges en bereikbare host-state baie betekenisvoller.

## Inspection

Die eenvoudigste oorsig is:
```bash
ls -l /proc/self/ns
```
Elke inskrywing is ’n simboliese skakel met ’n inode-agtige identifiseerder. As twee prosesse na dieselfde namespace-identifiseerder wys, is hulle in dieselfde namespace van daardie tipe. Dit maak `/proc` ’n baie nuttige plek om die huidige proses met ander interessante prosesse op die masjien te vergelyk.

Hierdie vinnige opdragte is dikwels genoeg om te begin:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Van daar af is die volgende stap om die container-proses met host- of naburige prosesse te vergelyk en te bepaal of ’n namespace werklik privaat is of nie.

### Enumerating Namespace Instances From The Host

Wanneer jy reeds host-toegang het en wil verstaan hoeveel afsonderlike namespaces van ’n gegewe tipe bestaan, bied `/proc` ’n vinnige inventaris:
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
As jy wil vasstel watter prosesse aan een spesifieke namespace-identifiseerder behoort, skakel van `readlink` na `ls -l` en gebruik grep vir die teiken-namespace-nommer:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Hierdie commands is nuttig omdat hulle jou laat bepaal of 'n host een geïsoleerde workload, baie geïsoleerde workloads, of 'n mengsel van gedeelde en private namespace-instanties uitvoer.

### Betree 'n Teiken-namespace

Wanneer die caller voldoende voorregte het, is `nsenter` die standaardmanier om by 'n ander proses se namespace aan te sluit:
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
Die punt daarvan om hierdie vorms saam te lys, is nie dat elke assessering almal daarvan benodig nie, maar dat namespace-spesifieke post-exploitation dikwels baie makliker word sodra die operateur die presiese entry-syntax ken, eerder as om slegs die all-namespaces-vorm te onthou.

## Bladsye

Die volgende bladsye verduidelik elke namespace in meer besonderhede:

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

Hou twee idees in gedagte terwyl jy dit lees. Eerstens isoleer elke namespace slegs een soort aansig. Tweedens is ’n private namespace slegs nuttig indien die res van die privilege-model steeds daardie isolasie betekenisvol maak.

## Runtime-verstekwaardes

| Runtime / platform | Verstek-namespace-houding | Algemene handmatige verswakking |
| --- | --- | --- |
| Docker Engine | Nuwe mount-, PID-, network-, IPC- en UTS-namespaces by verstek; user-namespaces is beskikbaar, maar nie by verstek in standaard rootful-opstellings geaktiveer nie | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Nuwe namespaces by verstek; rootless Podman gebruik outomaties ’n user-namespace; cgroup-namespace-verstekwaardes hang van die cgroup-weergawe af | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods deel **nie** by verstek die host se PID, network of IPC nie; Pod-networking is privaat tot die Pod, nie tot elke individuele container nie; user-namespaces is opt-in via `spec.hostUsers: false` op ondersteunde clusters | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / die weglating van user-namespace-opt-in, bevoorregte workload-instellings |
| containerd / CRI-O onder Kubernetes | Volg gewoonlik Kubernetes Pod-verstekwaardes | dieselfde as die Kubernetes-ry; direkte CRI/OCI-specs kan ook host-namespace-koppelings versoek |

Die hoofreël vir portability is eenvoudig: die **konsep** van host-namespace-sharing is algemeen oor runtimes heen, maar die **syntax** is runtime-spesifiek.
{{#include ../../../../../banners/hacktricks-training.md}}
