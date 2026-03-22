# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces is die kernel-funksie wat 'n container laat voel soos "sy eie masjien" al is dit eintlik net 'n host-prosesboom. Hulle skep nie 'n nuwe kernel nie en hulle virtualiseer nie alles nie, maar hulle laat die kernel toe om verskillende weergawes van gekose hulpbronne aan verskillende groepe prosesse voor te hou. Dit is die kern van die container-illusie: die workload sien 'n lêerstelsel, prosesregister, netwerkstapel, hostname, IPC-hulpbronne en 'n gebruiker/groep-identiteitsmodel wat plaaslik voorkom, al word die onderliggende stelsel gedeel.

Dit is ook hoekom namespaces die eerste konsep is wat die meeste mense teëkom wanneer hulle leer hoe containers werk. Tegelykertyd is dit een van die konsepte wat die meeste verkeerd verstaan word, want lesers neem dikwels aan dat "het namespaces" beteken "is veilig geïsoleer". In werklikheid is 'n namespace slegs gespesialiseer om die spesifieke klas hulpbronne te isoleer waarvoor dit ontwerp is. 'n Proses kan 'n private PID namespace hê en steeds gevaarlik wees omdat dit 'n beskryflike host bind mount skryfbaar het. Dit kan 'n private network namespace hê en steeds gevaarlik wees omdat dit `CAP_SYS_ADMIN` behou en sonder seccomp loop. Namespaces is fundamenteel, maar hulle is net een laag in die finale grens.

## Namespace Types

Linux containers vertrou dikwels gelyktydig op verskeie namespace-tipes. Die **mount namespace** gee die proses 'n aparte mount-tabel en dus 'n beheerde filesystem-weergawes. Die **PID namespace** verander proses-sigbaarheid en nommering sodat die workload sy eie prosesboom sien. Die **network namespace** isoleer interfaces, routes, sockets en firewall-status. Die **IPC namespace** isoleer SysV IPC en POSIX message queues. Die **UTS namespace** isoleer hostname en NIS domeinnaam. Die **user namespace** herkaarteer user- en group-IDs sodat root binne die container nie noodwendig root op die host beteken nie. Die **cgroup namespace** virtualiseer die sigbare cgroup-hiërargie, en die **time namespace** virtualiseer geselekteerde kloks in nuwer kernels.

Elk van hierdie namespaces los 'n ander probleem op. Dit is waarom praktiese container security-analise dikwels neerkom op om na te gaan **watter namespaces geïsoleer is** en **watter op 'n doelbewuste manier met die host gedeel is**.

## Host Namespace Sharing

Baie container breakouts begin nie met 'n kernel-kwesbaarheid nie. Hulle begin met 'n operator wat die isolasiemodel doelbewus verswakk. Die voorbeelde `--pid=host`, `--network=host`, en `--userns=host` is **Docker/Podman-style CLI flags** wat hier as konkrete voorbeelde van host namespace sharing gebruik word. Ander runtimes druk dieselfde idee op 'n ander manier uit. In Kubernetes verskyn die ekwivalente gewoonlik as Pod-instellings soos `hostPID: true`, `hostNetwork: true`, of `hostIPC: true`. In laervlak runtime-stakke soos containerd of CRI-O word dieselfde gedrag dikwels bereik deur die gegenereerde OCI runtime-configuration eerder as deur 'n gebruiker-gerigte vlag met dieselfde naam. In al hierdie gevalle is die resultaat soortgelyk: die workload ontvang nie meer die standaard geïsoleerde namespace-weergawes nie.

Dit is hoekom namespace-oorsigte nooit moet ophou by "die proses is in 'n namespace" nie. Die belangrike vraag is of die namespace privaat is vir die container, gedeel met sibling containers, of direk aan die host gekoppel is. In Kubernetes verskyn dieselfde idee met vlae soos `hostPID`, `hostNetwork`, en `hostIPC`. Die name verander tussen platforms, maar die risikopatroon is dieselfde: 'n gedeelde host-namespace maak die container se oorblywende privilegies en bereikbare host-status baie meer betekenisvol.

## Inspection

Die eenvoudigste oorsig is:
```bash
ls -l /proc/self/ns
```
Elke inskrywing is 'n symboliese skakel met 'n inode-agtige identifiseerder. As twee prosesse na dieselfde namespace-identifiseerder wys, is hulle in dieselfde namespace van daardie tipe. Dit maak `/proc` 'n baie nuttige plek om die huidige proses met ander interessante prosesse op die masjien te vergelyk.

Hierdie vinnige kommando's is dikwels genoeg om mee te begin:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Van daar af is die volgende stap om die container-proses met die host of naburige prosesse te vergelyk en te bepaal of 'n namespace werklik privaat is of nie.

### Opsomming van Namespace-instanties vanaf die Host

Wanneer jy reeds toegang tot die host het en wil verstaan hoeveel onderskeibare namespaces van 'n gegewe tipe bestaan, `/proc` gee 'n vinnige inventaris:
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
As jy wil vind watter prosesse aan 'n spesifieke namespace identifier behoort, gebruik `ls -l` in plaas van `readlink` en grep vir die teiken namespace nommer:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Hierdie opdragte is nuttig omdat hulle jou toelaat om te bepaal of 'n host een geïsoleerde workload, baie geïsoleerde workloads, of 'n mengsel van shared en private namespace instances uitvoer.

### Betree 'n Teiken-namespace

Wanneer die caller oor voldoende voorregte beskik, is `nsenter` die standaard manier om by 'n ander proses se namespace aan te sluit:
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
Die punt om hierdie vorms saam te noem is nie dat elke assessment al hulle benodig nie, maar dat namespace-specific post-exploitation dikwels baie makliker word sodra die operator die presiese entry syntax ken in plaas daarvan om net die all-namespaces-form te onthou.

## Bladsye

Die volgende bladsye verduidelik elke namespace in meer detail:

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

Terwyl jy dit lees, hou twee idees in gedagte. Eerstens is elke namespace slegs verantwoordelik vir die isolering van een soort view. Tweedens is ’n private namespace net nuttig as die res van die privilege-model daardie isolasie steeds betekenisvol maak.

## Runtime-standaarde

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | New mount, PID, network, IPC, and UTS namespaces by default; user namespaces are available but not enabled by default in standard rootful setups | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | New namespaces by default; rootless Podman automatically uses a user namespace; cgroup namespace defaults depend on cgroup version | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods do **not** share host PID, network, or IPC by default; Pod networking is private to the Pod, not to each individual container; user namespaces are opt-in via `spec.hostUsers: false` on supported clusters | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | Usually follow Kubernetes Pod defaults | same as Kubernetes row; direct CRI/OCI specs can also request host namespace joins |

Die hoof reël vir draagbaarheid is eenvoudig: die **konsep** van host namespace-deling is algemeen oor runtimes, maar die **syntax** is runtime-spesifiek.
{{#include ../../../../../banners/hacktricks-training.md}}
