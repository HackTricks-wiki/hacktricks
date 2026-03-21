# Kontainerbeskerming Oorsig

{{#include ../../../../banners/hacktricks-training.md}}

Die belangrikste idee in kontainer-hardening is dat daar nie 'n enkele beheer bestaan wat "container security" genoem word nie. Wat mense "container isolation" noem, is eintlik die resultaat van verskeie Linux-sekuriteits- en hulpbronbestuursmeganismes wat saamwerk. As dokumentasie slegs een daarvan beskryf, neig lesers om die sterkte daarvan te oorskat. As dokumentasie almal lyste sonder om te verduidelik hoe hulle met mekaar in wisselwerking staan, sit lesers met 'n katalogus van name maar geen werklike model nie. Hierdie afdeling probeer albei foute vermy.

In die sentrum van die model staan **namespaces**, wat isoleer wat die workload kan sien. Hulle gee die proses 'n private of deels private aansig van filesystem mounts, PIDs, networking, IPC objects, hostnames, user/group mappings, cgroup paths, en sommige clocks. Maar **namespaces** alleen bepaal nie wat 'n proses toegelaat word om te doen nie. Dit is waar die volgende lae inkom.

**cgroups** beheer hulpbrongebruik. Hulle is nie primêr 'n isolasiegrens in dieselfde sin as mount of PID namespaces nie, maar hulle is operationeel noodsaaklik omdat hulle geheue, CPU, PIDs, I/O en toesteltoegang beperk. Hulle het ook sekuriteitsrelevansie omdat historiese breakout techniques skryfbare cgroup-funksies misbruik het, veral in cgroup v1-omgewings.

**Capabilities** verdeel die ou, almagtige root-model in kleiner voorreg-eenhede. Dit is fundamenteel vir containers omdat baie workloads steeds as UID 0 binne die kontainer loop. Die vraag is dus nie net "is the process root?" nie, maar eerder "which capabilities survived, inside which namespaces, under which seccomp and MAC restrictions?" Daarom kan 'n root-proses in een kontainer relatief beperk wees, terwyl 'n root-proses in 'n ander kontainer in praktyk byna onskeibaar van host root kan wees.

**seccomp** filter syscalls en verminder die kernel attack surface wat aan die workload blootgestel word. Dit is dikwels die meganisme wat duidelik gevaarlike calls soos `unshare`, `mount`, `keyctl`, of ander syscalls wat in breakout chains gebruik word, blokkeer. Selfs as 'n proses 'n capability het wat andersins 'n operasie sou toelaat, kan seccomp steeds die syscall-pad blokkeer voordat die kernel dit volledig verwerk.

**AppArmor** en **SELinux** voeg Mandatory Access Control bo-op normale filesystem- en voorregkontroles by. Dit is veral belangrik omdat dit voortgaan om saak te maak selfs wanneer 'n kontainer meer capabilities het as wat dit behoort te hê. 'n Workload mag die teoretiese voorreg hê om 'n aksie te probeer, maar steeds verhinder word om dit uit te voer omdat sy label of profiel toegang tot die relevante pad, objek of operasie verbied.

Laastens is daar addisionele hardening-lae wat minder aandag kry maar gereeld in werklike aanvalle saak maak: `no_new_privs`, masked procfs paths, read-only system paths, read-only root filesystems, en versigtige runtime defaults. Hierdie meganismes stop dikwels die "laaste myl" van 'n kompromie, veral wanneer 'n aanvaller probeer om code execution in 'n breër voorreg-verkryging om te skakel.

Die res van hierdie gids verduidelik elk van hierdie meganismes in meer detail, insluitende wat die kernel primitive werklik doen, hoe om dit lokaal waar te neem, hoe algemene runtimes dit gebruik, en hoe operateurs dit per ongeluk verswak.

## Lees Verder

{{#ref}}
namespaces/
{{#endref}}

{{#ref}}
cgroups.md
{{#endref}}

{{#ref}}
capabilities.md
{{#endref}}

{{#ref}}
seccomp.md
{{#endref}}

{{#ref}}
apparmor.md
{{#endref}}

{{#ref}}
selinux.md
{{#endref}}

{{#ref}}
no-new-privileges.md
{{#endref}}

{{#ref}}
masked-paths.md
{{#endref}}

{{#ref}}
read-only-paths.md
{{#endref}}

Baie werklike escapes hang ook af van watter host-inhoud in die workload gemount is, so nadat jy die kernbeskermings gelees het, is dit nuttig om voort te gaan met:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
