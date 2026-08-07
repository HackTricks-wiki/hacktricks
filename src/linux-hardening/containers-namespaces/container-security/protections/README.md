# Oorsig van Container-beskerming

{{#include ../../../../banners/hacktricks-training.md}}

Die belangrikste idee in container-hardening is dat daar geen enkele beheermaatreël genaamd "container security" is nie. Wat mense container-isolasie noem, is eintlik die resultaat van verskeie Linux-sekuriteits- en hulpbronbestuurmeganismes wat saamwerk. As dokumentasie slegs een daarvan beskryf, is lesers geneig om die sterkte daarvan te oorskat. As dokumentasie almal lys sonder om te verduidelik hoe hulle interaksie het, kry lesers ’n katalogus van name maar geen werklike model nie. Hierdie afdeling probeer albei foute vermy.

In die middel van die model is **namespaces**, wat isoleer wat die workload kan sien. Dit gee die proses ’n private of gedeeltelik private aansig van filesystem-mounts, PIDs, networking, IPC-objekte, hostnames, user/group mappings, cgroup paths en sommige clocks. Maar namespaces alleen bepaal nie wat ’n proses toegelaat word om te doen nie. Dit is waar die volgende lae inkom.

**cgroups** beheer hulpbrongebruik. Hulle is nie primêr ’n isolasiegrens in dieselfde sin as mount- of PID-namespaces nie, maar hulle is operasioneel noodsaaklik omdat hulle memory, CPU, PIDs, I/O en device access beperk. Hulle het ook sekuriteitsrelevansie omdat historiese breakout-tegnieke misbruik gemaak het van skryfbare cgroup-features, veral in cgroup v1-omgewings.

**Capabilities** verdeel die ou almagtige root-model in kleiner privilegie-eenhede. Dit is fundamenteel vir containers omdat baie workloads steeds as UID 0 binne die container loop. Die vraag is dus nie bloot "is die proses root?" nie, maar eerder "watter capabilities het behoue gebly, binne watter namespaces, onder watter seccomp- en MAC-beperkings?" Daarom kan ’n root-proses in een container relatief beperk wees, terwyl ’n root-proses in ’n ander container in die praktyk byna nie van host root onderskei kan word nie.

**seccomp** filter syscalls en verminder die kernel-aanvaloppervlak wat aan die workload blootgestel word. Dit is dikwels die meganisme wat ooglopend gevaarlike calls soos `unshare`, `mount`, `keyctl` of ander syscalls wat in breakout-kettings gebruik word, blokkeer. Selfs al het ’n proses ’n capability wat andersins ’n operasie sou toelaat, kan seccomp steeds die syscall-pad blokkeer voordat die kernel dit volledig verwerk.

**AppArmor** en **SELinux** voeg Mandatory Access Control bykomend tot normale filesystem- en privilegie-kontroles. Dit is besonder belangrik omdat hulle steeds saak maak wanneer ’n container meer capabilities het as wat dit behoort te hê. ’n Workload kan die teoretiese privilegie hê om ’n aksie te probeer, maar steeds verhoed word om dit uit te voer omdat sy label of profile toegang tot die relevante path, object of operasie verbied.

Laastens is daar bykomende hardening-lae wat minder aandag kry, maar gereeld in werklike aanvalle saak maak: `no_new_privs`, gemaskerde procfs-paths, leesalleen-stelselpaths, leesalleen-root-filesystems en noukeurige runtime-defaults. Hierdie meganismes keer dikwels die "laaste myl" van ’n compromise, veral wanneer ’n aanvaller probeer om code execution in ’n breër privilegie-verhoging te omskep.

Die res van hierdie folder verduidelik elk van hierdie meganismes in meer besonderhede, insluitend wat die kernel-primitive werklik doen, hoe om dit plaaslik waar te neem, hoe algemene runtimes dit gebruik en hoe operators dit per ongeluk verswak.

## Lees volgende

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

Baie werklike escapes hang ook af van watter host-inhoud in die workload gemount is, dus is dit nuttig om ná die lees van die kernbeskermings voort te gaan met:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}

{{#include ../../../../banners/hacktricks-training.md}}
