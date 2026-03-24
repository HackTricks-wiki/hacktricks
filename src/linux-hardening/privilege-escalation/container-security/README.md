# Container Security

{{#include ../../../banners/hacktricks-training.md}}

## What A Container Actually Is

'n Praktiese manier om 'n container te definieer is hierdie: 'n container is 'n **gereelde Linux-prosesboom** wat onder 'n spesifieke OCI-styl konfigurasie begin is sodat dit 'n beheerde filesystem, 'n beheerde stel kernel-hulpbronne, en 'n beperkte privilegiemodel sien. Die proses mag glo dit is PID 1, mag glo dit het sy eie netwerkstack, mag glo dit besit sy eie hostname en IPC-hulpbronne, en mag selfs as root binne sy eie user namespace loop. Maar onder die kap is dit steeds 'n host-proses wat die kernel soos enige ander skeduleer.

Dit is hoekom container security eintlik die studie is van hoe daardie illusie opgebou word en hoe dit misluk. As die mount namespace swak is, mag die proses die host filesystem sien. As die user namespace afwesig of gedeaktiveer is, mag root binne die container te na aan root op die host kaart. As seccomp ongebonde is en die capability set te breed is, mag die proses syscalls en bevoorregte kernel-funksies bereik wat buite bereik moes bly. As die runtime socket binne die container gemounte is, mag die container glad nie 'n kernel breakout nodig hê nie omdat dit eenvoudig die runtime kan vra om 'n meer kragtige sibling container te begin of die host root filesystem direk te mount.

## How Containers Differ From Virtual Machines

'n VM dra gewoonlik sy eie kernel en hardware-abstraksiegrens. Dit beteken die guest kernel kan crash, panic, of uitgebuit word sonder om outomaties direkte beheer oor die host kernel te impliseer. In containers kry die workload nie 'n aparte kernel nie. In plaas daarvan kry dit 'n noukeurig gefilterde en namespaced kyk op dieselfde kernel wat die host gebruik. Gevolglik is containers gewoonlik ligter, vinniger om te begin, makliker om dig op 'n masjien te pak, en beter geskik vir kortlewende toepassingsimplementering. Die prys is dat die isolasiegrens veel direkter op korrekte host- en runtime-konfigurasie staatmaak.

Dit beteken nie dat containers "onveilig" is en VMs "veilig" nie. Dit beteken die sekuriteitsmodel is anders. 'n Goed-gekonfigureerde container-stapel met rootless uitvoering, user namespaces, standaard seccomp, 'n stringente capability set, geen host namespace sharing nie, en sterk SELinux of AppArmor-afdwinging kan baie robuust wees. Andersyds is 'n container wat met `--privileged` begin is, host PID/network sharing het, die Docker socket binne-in gemounte is, en 'n skryfbare bind mount van `/` het, funksioneel veel nader aan host root toegang as aan 'n veilig geïsoleerde toepassingssandbox. Die verskil kom van die lae wat geaktiveer of gedeaktiveer is.

Daar is ook 'n middelgrond wat lesers moet verstaan omdat dit meer en meer in werklike omgewings voorkom. **Sandboxed container runtimes** soos **gVisor** en **Kata Containers** hardsen doelbewus die grens verder as 'n klassieke `runc` container. gVisor plaas 'n userspace-kernellaag tussen die workload en baie host kernel-interfaces, terwyl Kata die workload binne 'n ligte virtual machine begin. Hierdie word steeds deur container-ekosisteme en orkestrasie-workflows gebruik, maar hul sekuriteitskenmerke verskil van blote OCI-runtimes en moet nie geestelik saamgegroepeer word met "normal Docker containers" asof alles op dieselfde manier optree nie.

## The Container Stack: Several Layers, Not One

Wanneer iemand sê "this container is insecure", is die nuttige navrae: **watter laag het dit onseker gemaak?** 'n Containerized workload is gewoonlik die resultaat van verskeie komponente wat saamwerk.

Bo-op is daar dikwels 'n **image build layer** soos BuildKit, Buildah, of Kaniko, wat die OCI image en metadata skep. Bo die laevlak runtime kan daar 'n **engine or manager** wees soos Docker Engine, Podman, containerd, CRI-O, Incus, of systemd-nspawn. In cluster-omgewings kan daar ook 'n **orchestrator** soos Kubernetes wees wat die versoekte sekuriteitshouding deur workload-konfigurasie bepaal. Laastens is die **kernel** wat werklik namespaces, cgroups, seccomp, en MAC-beleid afdwing.

Hierdie gelaagde model is belangrik om defaults te verstaan. 'n Beperking mag deur Kubernetes versoek word, deur CRI deur containerd of CRI-O vertaal word, in 'n OCI-spec deur die runtime wrapper omgeskakel word, en eers dan deur `runc`, `crun`, `runsc`, of 'n ander runtime teen die kernel afgedwing word. Wanneer defaults tussen omgewings verskil, is dit dikwels omdat een van hierdie lae die finale konfigurasie verander het. Dieselfde meganisme kan daarom in Docker of Podman as 'n CLI-flag verskyn, in Kubernetes as 'n Pod of `securityContext` veld, en in laer-vlak runtime-stakke as OCI-konfigurasie wat vir die workload gegenereer is. Om daardie rede moet CLI-voorbeelde in hierdie afdeling gelees word as **runtime-spesifieke sintaksis vir 'n algemene container-konsep**, nie as universele vlae wat deur elke instrument ondersteun word nie.

## The Real Container Security Boundary

In die praktyk kom container security van **oorvleuelende kontroles**, nie van 'n enkele perfekte kontrole nie. Namespaces isoleer sigbaarheid. cgroups bestuur en beperk hulpbrongebruik. Capabilities verminder wat 'n bevoorregte-lykende proses eintlik kan doen. seccomp blokkeer gevaarlike syscalls voordat hulle die kernel bereik. AppArmor en SELinux voeg Mandatory Access Control bo-op normale DAC-kontroles. `no_new_privs`, masked procfs paths, en read-only system paths maak algemene privilegie- en proc/sys-misbruikkettings moeiliker. Die runtime self maak ook saak omdat dit besluit hoe mounts, sockets, labels, en namespace-joins geskep word.

Dit is waarom baie container security-dokumentasie herhalend voorkom. Dieselfde escape chain hang dikwels van verskeie meganismes gelyktydig af. Byvoorbeeld, 'n skryfbare host bind mount is sleg, maar dit word baie erger as die container ook as werklike root op die host loop, `CAP_SYS_ADMIN` het, deur seccomp ongebonde is, en nie deur SELinux of AppArmor beperk word nie. Net so is host PID-sharing 'n ernstige blootstelling, maar dit word dramaties nuttiger vir 'n aanvaller wanneer dit gekombineer word met `CAP_SYS_PTRACE`, swak procfs-beskermings, of namespace-entry gereedskap soos `nsenter`. Die regte manier om die onderwerp te dokumenteer is dus nie deur dieselfde aanval op elke bladsy te herhaal nie, maar deur te verduidelik wat elke laag tot die finale grens bydra.

## How To Read This Section

Die afdeling is georganiseer van die mees algemene konsepte tot die mees spesifieke.

Begin met die runtime en ekosisteem-oorsig:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Dan hersien die control planes en supply-chain oppervlaktes wat dikwels besluit of 'n aanvaller selfs 'n kernel escape nodig het:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
authorization-plugins.md
{{#endref}}

{{#ref}}
image-security-and-secrets.md
{{#endref}}

{{#ref}}
assessment-and-hardening.md
{{#endref}}

Beweeg dan na die beskermingsmodel:

{{#ref}}
protections/
{{#endref}}

Die namespace-bladsye verduidelik die kernel-isolasie-primitiewe individueel:

{{#ref}}
protections/namespaces/
{{#endref}}

Die bladsye oor cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths, en read-only paths verduidelik die meganismes wat gewoonlik bo-op namespaces geskik word:

{{#ref}}
protections/cgroups.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/no-new-privileges.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
distroless.md
{{#endref}}

{{#ref}}
privileged-containers.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## A Good First Enumeration Mindset

Wanneer jy 'n containerized teiken beoordeel, is dit baie meer nuttig om 'n klein stel presiese tegniese vrae te vra as om onmiddellik na beroemde escape PoCs te spring. Identifiseer eers die **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer, of iets meer gespesialiseerd. Dan identifiseer die **runtime**: `runc`, `crun`, `runsc`, `kata-runtime`, of 'n ander OCI-compatible implementasie. Daarna, kyk of die omgewing **rootful of rootless** is, of **user namespaces** aktief is, of enige **host namespaces** gedeel word, watter **capabilities** oorbly, of **seccomp** geaktiveer is, of 'n **MAC policy** werklik afdwing, of **gevaarlike mounts of sockets** teenwoordig is, en of die proses met die container runtime API kan kommunikeer.

Daardie antwoorde vertel jou veel meer oor die werklike sekuriteitshouding as die basis-image naam ooit sal doen. In baie assesserings kan jy die waarskynlike breakout-familie voorspel voordat jy 'n enkele toepassingslêer lees net deur die finale container-konfigurasie te verstaan.

## Coverage

Hierdie afdeling dek die ou Docker-gefokusde materiaal onder container-georiënteerde organisasie: runtime en daemon-exposure, authorization plugins, image trust en build secrets, sensitive host mounts, distroless workloads, privileged containers, en die kernel-beskermings wat gewoonlik rondom container-uitvoering gelaag word.
{{#include ../../../banners/hacktricks-training.md}}
