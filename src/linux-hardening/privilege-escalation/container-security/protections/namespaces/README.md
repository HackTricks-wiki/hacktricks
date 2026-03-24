# Naamruimtes

{{#include ../../../../../banners/hacktricks-training.md}}

Naamruimtes is die kernel-funksie wat 'n container die gevoel gee asof dit "sy eie masjien" is, al is dit eintlik net 'n prosesboom op die host. Dit skep nie 'n nuwe kernel nie en dit virtualiseer nie alles nie, maar dit laat die kernel toe om verskillende aansigte van geselekteerde hulpbronne aan verskillende groepe prosesse voor te stel. Dit is die kern van die container-illusie: die workload sien 'n lêerstelsel, proseskaart, netwerkstapel, hostnaam, IPC-hulpbronne, en gebruiker/groep-identiteitsmodel wat lokaal lyk, al word die onderliggende stelsel gedeel.

Dit is waarom naamruimtes die eerste konsep is wat die meeste mense teëkom wanneer hulle leer hoe containers werk. Tegelykertyd is dit een van die mees verkeerd-voorgestelde konsepte, omdat lesers dikwels aanvaar dat "het naamruimtes" beteken "is veilig geïsoleer". In werklikheid is 'n naamruimte slegs daarop uitgewerk om die spesifieke klas hulpbronne te isoleer waarvoor dit ontwerp is. 'n Proses kan 'n private PID-naamruimte hê en steeds gevaarlik wees omdat dit 'n skryfbare host bind mount het. Dit kan 'n private netwerk-naamruimte hê en steeds gevaarlik wees omdat dit `CAP_SYS_ADMIN` behou en sonder seccomp loop. Naamruimtes is fundamenteel, maar hulle is slegs een laag in die finale grens.

## Soorte Naamruimtes

Linux containers staatmaak gewoonlik gelyktydig op verskeie naamruimte-tipes. Die **mount namespace** gee die proses 'n aparte mount-tabel en dus 'n beheerbare lêerstelsel-aansig. Die **PID namespace** verander proses-sigbaarheid en nommering sodat die workload sy eie prosesboom sien. Die **network namespace** isoleer interfaces, roetes, sockets, en firewall-status. Die **IPC namespace** isoleer SysV IPC en POSIX boodskapprogramme. Die **UTS namespace** isoleer hostnaam en NIS-domeinnaam. Die **user namespace** herkaart gebruiker- en groep-ID's sodat root binne die container nie noodwendig root op die host beteken nie. Die **cgroup namespace** virtualiseer die sigbare cgroup-hiërargie, en die **time namespace** virtualiseer geselekteerde horlosies in nuwer kernels.

Elkeen van hierdie naamruimtes los 'n ander probleem op. Dit is waarom praktiese container-sekuriteitsanalise gewoonlik neerkom op die kontrole van **watter naamruimtes geïsoleer is** en **watter doelbewus met die host gedeel is**.

## Gasheer Naamruimtedeling

Baie container-breakouts begin nie met 'n kernel-kwetsbaarheid nie. Hulle begin met 'n operator wat die isolasie-model doelbewus verswakk. Die voorbeelde `--pid=host`, `--network=host`, en `--userns=host` is **Docker/Podman-style CLI flags** wat hier as konkrete voorbeelde van gasheer-naamruimtedeling gebruik word. Ander runtimes druk dieselfde idee op 'n ander manier uit. In Kubernetes verskyn die ekwivalent gewoonlik as Pod-instellings soos `hostPID: true`, `hostNetwork: true`, of `hostIPC: true`. In laer-vlak runtime-stakke soos containerd of CRI-O word dieselfde gedrag dikwels bereik deur die gegenereerde OCI runtime-konfigurasie eerder as deur 'n gebruikersgesigte vlag met dieselfde naam. In al hierdie gevalle is die resultaat soortgelyk: die workload kry nie meer die standaard geïsoleerde naamruimte-aansig nie.

Dit is waarom naamruimte-oorsigte nooit by "die proses is in 'n sekere naamruimte" moet ophou nie. Die belangrike vraag is of die naamruimte privaat is vir die container, gedeel met sussie-containers, of direk aan die host gekoppel is. In Kubernetes verskyn dieselfde idee met vlagte soos `hostPID`, `hostNetwork`, en `hostIPC`. Die name verander tussen platforms, maar die risiko-patroon is dieselfde: 'n gedeelde gasheer-naamruimte maak die container se oorblywende voorregte en bereikbare host-status baie betekenisvoller.

## Inspeksie

Die eenvoudigste oorsig is:
```bash
ls -l /proc/self/ns
```
Elke inskrywing is 'n simboliese skakel met 'n inode-agtige identifiseerder. As twee prosesse na dieselfde namespace-identifiseerder wys, is hulle in dieselfde namespace van daardie tipe. Dit maak `/proc` 'n baie nuttige plek om die huidige proses met ander interessante prosesse op die masjien te vergelyk.

Hierdie vinnige kommando's is dikwels genoeg om te begin:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Van daar af is die volgende stap om die container process met die host of naburige processes te vergelyk en te bepaal of 'n namespace werklik privaat is of nie.

### Enumerering van Namespace-instansies vanaf die Host

Wanneer jy reeds host access het en wil verstaan hoeveel onderskeibare namespaces van 'n gegewe tipe bestaan, gee `/proc` 'n vinnige inventaris:
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
As jy wil uitvind watter prosesse aan 'n spesifieke namespace identifier' behoort, skakel van `readlink` na `ls -l` en grep vir die teiken namespace-nommer:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Hierdie opdragte is nuttig omdat hulle jou toelaat om te bepaal of 'n gasheer een geïsoleerde werklading, verskeie geïsoleerde werkladinge, of 'n mengsel van gedeelde en private namespace-instansies uitvoer.

### Betree 'n teiken-namespace

Wanneer die oproeper voldoende voorregte het, is `nsenter` die standaard manier om by 'n ander proses se namespace aan te sluit:
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
Die punt om hierdie vorme saam te lys is nie dat elke assessment almal benodig nie, maar dat namespace-spesifieke post-exploitation dikwels baie makliker raak sodra die operateur die presiese entry-sintaksis ken, in plaas daarvan om net die all-namespaces-vorm te onthou.

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

Terwyl jy dit lees, hou twee idees in gedagte. Eerstens, elke namespace isoleer slegs een soort aansig. Tweedens, 'n privaat namespace is net nuttig as die res van die privilege-model steeds daardie isolasie sinvol maak.

## Runtime-standaarde

| Runtime / platform | Standaard namespace-houding | Algemene handmatige verzwakking |
| --- | --- | --- |
| Docker Engine | Standaard word nuwe mount-, PID-, network-, IPC- en UTS-namespaces geskep; user namespaces is beskikbaar maar nie standaard geaktiveer in tipiese rootful-opstellings nie | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Nuwe namespaces standaard; rootless Podman gebruik outomaties 'n user namespace; cgroup namespace-standaarde hang af van die cgroup-weergawe | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods deel standaard **nie** host PID, network of IPC nie; Pod networking is privaat vir die Pod, nie vir elke individuele container nie; user namespaces is opsioneel via `spec.hostUsers: false` op ondersteunde clusters | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / weglating van user-namespace opt-in, privileged workload-instellings |
| containerd / CRI-O under Kubernetes | Volg gewoonlik Kubernetes Pod-standaarde | dieselfde as die Kubernetes-ry; direkte CRI/OCI-spesifikasies kan ook versoek om host namespace joins |

Die hoof reël vir portability is eenvoudig: die **konsep** van host namespace sharing is algemeen oor runtimes, maar die **sintaksis** is runtime-spesifiek.
{{#include ../../../../../banners/hacktricks-training.md}}
