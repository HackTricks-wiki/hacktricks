# Oorsig van Container-beskerming

{{#include ../../../../banners/hacktricks-training.md}}

Die belangrikste idee by container-hardening is dat daar nie 'n enkele beheer bestaan wat "container security" genoem word nie. Wat mense "container isolation" noem, is in werklikheid die resultaat van verskeie Linux-sekuriteits- en hulpbronbestuursmeganismes wat saamwerk. As dokumentasie slegs een daarvan beskryf, neig lesers daartoe om die krag daarvan te oorwaardeer. As dokumentasie al die meganismes lys sonder om te verduidelik hoe hulle met mekaar integreer, kry lesers 'n katalogus van name maar geen werklike model nie. Hierdie afdeling probeer albei foute vermy.

In die sentrum van die model is **namespaces**, wat isoleer wat die workload kan sien. Hulle gee die proses 'n private of gedeeltelik private aansig op filesystem mounts, PIDs, networking, IPC objects, hostnames, user/group mappings, cgroup paths, en sommige clocks. Maar namespaces alleen bepaal nie wat 'n proses toegelaat word om te doen nie. Dit is waar die volgende lae inkom.

**cgroups** regeer hulpbrongebruik. Hulle is nie primêr 'n isolasiegrens in dieselfde sin as mount of PID namespaces nie, maar hulle is operationeel kritiek omdat hulle memory, CPU, PIDs, I/O, en device toegang beperk. Hulle het ook sekuriteitsrelevansie omdat historiese breakout techniques skryfbare cgroup-funksies misbruik het, veral in cgroup v1 omgewings.

**Capabilities** verdeel die ou almagtige root-model in kleiner privilegie-eenhede. Dit is fundamenteel vir containers omdat baie workloads steeds as UID 0 binne die container loop. Die vraag is dus nie slegs "is die proses root?" nie, maar eerder "which capabilities survived, inside which namespaces, under which seccomp and MAC restrictions?" Dit is hoekom 'n root-proses in een container relatief beperk kan wees terwyl 'n root-proses in 'n ander container in praktyk amper ononderskeibaar van host root kan wees.

**seccomp** filter syscalls en verminder die kernel attack surface wat aan die workload blootgestel word. Dit is dikwels die meganisme wat duidelik gevaarlike calls soos `unshare`, `mount`, `keyctl`, of ander syscalls wat in breakout chains gebruik word, blokkeer. Selfs as 'n proses 'n capability het wat andersins 'n operasie sou toelaat, kan seccomp steeds die syscall-pad blokkeer voordat die kernel dit volledig verwerk het.

**AppArmor** en **SELinux** voeg Mandatory Access Control bo-op normale filesystem- en privilegiekontrole. Hierdie is besonder belangrik omdat hulle voortgaan om saak te maak, selfs wanneer 'n container meer capabilities het as wat hy behoort te hê. 'n Workload mag die teoretiese privilegie besit om 'n aksie te probeer, maar steeds verhinder word om dit uit te voer omdat sy label of profiel toegang tot die relevante pad, objek, of operasie verbied.

Uiteindelik is daar addisionele hardening-lae wat minder aandag kry maar gereeld in werklike aanvalle saakmaak: `no_new_privs`, masked procfs paths, read-only system paths, read-only root filesystems, en sorgvuldig ingestelde runtime defaults. Hierdie meganismes stop dikwels die "laaste myl" van 'n kompromie, veral wanneer 'n attacker probeer om code execution in 'n breër privilege gain te verander.

Die res van hierdie gids verduidelik elkeen van hierdie meganismes in meer detail, insluitend wat die kernel-primitive eintlik doen, hoe om dit plaaslik te observeer, hoe algemene runtimes dit gebruik, en hoe operators dit per ongeluk verswak.

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

Many real escapes also depend on what host content was mounted into the workload, so after reading the core protections it is useful to continue with:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
