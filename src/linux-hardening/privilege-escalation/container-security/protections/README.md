# Oorsig van Kontenerbeskerming

{{#include ../../../../banners/hacktricks-training.md}}

Die belangrikste idee in kontener-harding is dat daar nie 'n enkele beheer bestaan wat "container security" genoem word nie. Wat mense "container isolation" noem, is eintlik die resultaat van verskeie Linux-sekuriteits- en hulpbronbestuursmeganismes wat saamwerk. As dokumentasie slegs een van hulle beskryf, neig lesers om die sterkte daarvan te oorskat. As dokumentasie almal opsom sonder om te verduidelik hoe hulle met mekaar interaksie het, kry lesers 'n katalogus van name maar geen werklike model nie. Hierdie afdeling probeer albei foute vermy.

In die sentrum van die model is **namespaces**, wat isoleer wat die werkbelasting kan sien. Hulle gee die proses 'n privaat of gedeeltelik privaat siening van filesystem mounts, PIDs, networking, IPC objects, hostnames, user/group mappings, cgroup paths, en sekere klowe. Maar namespaces alleen bepaal nie wat 'n proses toegelaat word om te doen nie. Dit is waar die volgende lae inkom.

**cgroups** beheer hulpbrongebruik. Hulle is nie hoofsaaklik 'n isolasiegrens in dieselfde sin as mount of PID namespaces nie, maar hulle is operationeel kritiek omdat hulle memory, CPU, PIDs, I/O, en device access beperk. Hulle het ook sekuriteitsrelevansie omdat historiese breakout-tegnieke skryfbare cgroup-funksies misbruik het, veral in cgroup v1-omgewings.

**Capabilities** verdeel die ou almagende root-model in kleiner voorreg-eenhede. Dit is fundamenteel vir konteners omdat baie werkladinge nog steeds as UID 0 binne die kontener loop. Die vraag is dus nie net "is the process root?" nie, maar eerder "which capabilities survived, inside which namespaces, under which seccomp and MAC restrictions?" Dit is waarom 'n root-proses in een kontener relatief beperk kan wees terwyl 'n root-proses in 'n ander kontener in praktyk amper nie van host root onderskei kan word nie.

**seccomp** filtreer syscalls en verminder die kernel attack surface wat aan die werkbelasting blootgestel word. Dit is dikwels die meganisme wat duidelik gevaarlike oproepe soos `unshare`, `mount`, `keyctl`, of ander syscalls wat in breakout chains gebruik word, blokkeer. Selfs as 'n proses 'n capability het wat andersins 'n operasie sou toelaat, kan seccomp steeds die syscall-pad blokkeer voordat die kernel dit volledig verwerk.

**AppArmor** en **SELinux** voeg Mandatory Access Control bo-op normale filesystem- en voorregkontroles. Hierdie is besonder belangrik omdat hulle bly saak maak selfs wanneer 'n kontener meer capabilities het as wat dit behoort te hê. 'n Werklading kan die teoretiese voorreg hê om 'n aksie te probeer, maar steeds verhinder word om dit uit te voer omdat sy label of profiel toegang tot die relevante pad, objek of operasie verbied.

Uiteindelik is daar addisionele harding-lae wat minder aandag kry maar gereeld in werklike aanvalle saak maak: `no_new_privs`, masked procfs paths, read-only system paths, read-only root filesystems, en versigtige runtime defaults. Hierdie meganismes keer dikwels die "last mile" van 'n kompromie, veral wanneer 'n aanvaller probeer om kode-uitvoering in 'n wyer voorreg-verkryging om te skakel.

Die res van hierdie gids verduidelik elk van hierdie meganismes meer in detail, insluitend wat die kernel primitive eintlik doen, hoe om dit lokaal waar te neem, hoe algemene runtimes dit gebruik, en hoe operateurs dit per ongeluk verswak.

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

Baie werklike ontsnappings hang ook af van watter host content in die werklading gemount is, so na die lees van die kernbeskermings is dit nuttig om voort te gaan met:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
