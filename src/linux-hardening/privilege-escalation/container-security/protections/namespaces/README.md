# Naamruimtes

{{#include ../../../../../banners/hacktricks-training.md}}

Naamruimtes is die kernel-funksie wat 'n kontainer laat voel asof dit "sy eie masjien" is, al is dit eintlik net 'n host-prosesboom. Hulle skep nie 'n nuwe kernel nie en hulle virtualiseer nie alles nie, maar hulle laat die kernel toe om verskillende voorstellings van geselekteerde hulpbronne aan verskillende groepe prosesse te wys. Dit is die kern van die kontainer-illusie: die werkbelasting sien 'n lêerstelsel, prosesregister, netwerkstapel, hostname, IPC-hulpbronne, en 'n gebruiker/groep-identiteitsmodel wat plaaslik voorkom, al is die onderliggende stelsel gedeel.

Dit is hoekom naamruimtes die eerste konsep is wat die meeste mense teëkom wanneer hulle leer hoe kontainers werk. Tegelykertyd is dit een van die mees verkeerd verstaanbare konsepte omdat lesers dikwels aanvaar dat "het naamruimtes" beteken "is veilig geïsoleer". In werklikheid is 'n naamruimte slegs 'n isolasie vir die spesifieke klas hulpbronne waarvoor dit ontwerp is. 'n Proses kan 'n private PID-naamruimte hê en steeds gevaarlik wees omdat dit 'n beskryfbare host bind-mount het. Dit kan 'n private network-naamruimte hê en steeds gevaarlik wees omdat dit `CAP_SYS_ADMIN` behou en sonder seccomp loop. Naamruimtes is fundamenteel, maar hulle is slegs een laag in die finale grens.

## Tipes Naamruimtes

Linux-kontainers vertrou gewoonlik gelyktydig op verskeie tipes naamruimtes. Die **mount-naamruimte** gee die proses 'n aparte mount-tabel en dus 'n beheerste lêerstelsel-voorstelling. Die **PID-naamruimte** verander proses-sigbaarheid en nommering sodat die werkbelasting sy eie prosesboom sien. Die **network-naamruimte** isoleer interfaces, roetes, sockets, en firewall-toestand. Die **IPC-naamruimte** isoleer SysV IPC en POSIX boodskaprye. Die **UTS-naamruimte** isoleer hostname en NIS-domeinnaam. Die **user-naamruimte** herverdeel user- en group-IDs sodat root binne die kontainer nie noodwendig root op die host beteken nie. Die **cgroup-naamruimte** virtualiseer die sigbare cgroup-hiërargie, en die **time-naamruimte** virtualiseer geselekteerde klokke in nuwer kernels.

Elkeen van hierdie naamruimtes los 'n ander probleem op. Daarom kom praktiese kontainersekuriteitsontleding dikwels neer op die kontrole van **watter naamruimtes geïsoleer is** en **watter doelbewus met die host gedeel is**.

## Gasheer-naamruimtedeling

Baie kontainer-uitbrekings begin nie met 'n kernel-kwetsbaarheid nie. Hulle begin met 'n operateur wat die isolasiemodel doelbewus verswak. Die voorbeelde `--pid=host`, `--network=host`, en `--userns=host` is **Docker/Podman-styl CLI-vlae** wat hier as konkrete voorbeelde van gasheer-naamruimtedeling gebruik word. Ander runtimes druk dieselfde idee anders uit. In Kubernetes verskyn die ekwivalente gewoonlik as Pod-instellings soos `hostPID: true`, `hostNetwork: true`, of `hostIPC: true`. In laervlak runtime-stakke soos containerd of CRI-O word dieselfde gedrag dikwels bereik deur die gegenereerde OCI runtime-konfigurasie eerder as deur 'n gebruiker-gesiene vlag met dieselfde naam. In al hierdie gevalle is die resultaat soortgelyk: die werkbelasting ontvang nie meer die standaard geïsoleerde naamruimte-voorstelling nie.

Dit is hoekom naamruimte-oorsigte nooit moet stop by "die proses is in 'n sekere naamruimte" nie. Die belangrike vraag is of die naamruimte privaat aan die kontainer is, met susterkontainers gedeel word, of direk aan die host gekoppel is. In Kubernetes verskyn dieselfde idee met vlagte soos `hostPID`, `hostNetwork`, en `hostIPC`. Die name verander tussen platforms, maar die risikopatroon is dieselfde: 'n gedeelde gasheer-naamruimte maak die kontainer se oorblywende voorregte en die bereikbare host-toestand veel meer betekenisvol.

## Inspeksie

Die eenvoudigste oorsig is:
```bash
ls -l /proc/self/ns
```
Elke inskrywing is 'n symboliese skakel met 'n inode-agtige identifiseerder. As twee prosesse na dieselfde namespace-identifiseerder wys, is hulle in dieselfde namespace van daardie tipe. Dit maak `/proc` 'n baie nuttige plek om die huidige proses met ander interessante prosesse op die masjien te vergelyk.

Hierdie vinnige kommando's is dikwels genoeg om te begin:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Van daar af is die volgende stap om die container process met die host of naburige processes te vergelyk en te bepaal of 'n namespace werklik privaat is of nie.

### Enumerering van Namespace-instansies vanaf die host

Wanneer jy reeds host access het en wil verstaan hoeveel onderskeibare namespaces van 'n gegewe tipe bestaan, `/proc` gee 'n vinnige inventaris:
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
As jy wil uitvind watter prosesse tot ’n spesifieke namespace identifier behoort, skakel van `readlink` na `ls -l` en gebruik `grep` om die teiken namespace-nommer te soek:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Hierdie opdragte is nuttig omdat hulle jou toelaat om te bepaal of 'n host een geïsoleerde workload, baie geïsoleerde workloads, of 'n mengsel van gedeelde en private namespace-instanse uitvoer.

### Betree 'n teiken-namespace

As die oproeper voldoende voorregte het, is `nsenter` die standaard manier om by 'n ander proses se namespace aan te sluit:
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
Die punt van om hierdie vorme saam te lys is nie dat elke assessering al hulle benodig nie, maar dat namespace-specific post-exploitation dikwels baie makliker raak sodra die operateur die presiese toegangssintaksis ken in plaas van net die all-namespaces-vorm te onthou.

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

As jy hulle lees, hou twee idees in gedagte. Eerstens is elke namespace slegs vir die isolasie van een soort aansig. Tweedens is 'n private namespace net nuttig as die res van die privilege-model daardie isolasie steeds betekenisvol maak.

## Runtime-standaarde

| Runtime / platform | Standaard namespace-houding | Algemene handmatige verzwakking |
| --- | --- | --- |
| Docker Engine | Standaard nuwe mount-, PID-, network-, IPC- en UTS-namespaces; user namespaces is beskikbaar maar nie standaard aangeskakel in tipiese rootful-opstellings nie | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Nuwe namespaces standaard; rootless Podman gebruik outomaties 'n user namespace; cgroup namespace-standaarde hang af van die cgroup-weergawe | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods deel **nie** host PID, network, of IPC standaard nie; Pod networking is privaat vir die Pod, nie vir elke individuele container nie; user namespaces is opsioneel via `spec.hostUsers: false` op ondersteunde clusters | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | Volg gewoonlik Kubernetes Pod-standaarde | dieselfde as die Kubernetes-ry; direkte CRI/OCI spesifikasies kan ook versoek om host namespace joins |

Die hoofreël vir draagbaarheid is eenvoudig: die **concept** van host namespace-sharing is algemeen oor runtimes, maar die **syntax** is runtime-spesifiek.
