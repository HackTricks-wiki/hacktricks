# Container Sekuriteit

{{#include ../../../banners/hacktricks-training.md}}

## Wat 'n Container Werklik Is

'n Praktiese manier om 'n container te definieer is hierdie: 'n container is 'n ** gewone Linux-prosesboom ** wat onder 'n spesifieke OCI-styl konfigurasie begin is sodat dit 'n beheer­de filesystem, 'n beheer­de stel kernelhulpbronne, en 'n beperkte voorreg-model sien. Die proses mag glo dit is PID 1, mag glo dit het sy eie netwerkstapel, mag glo dit besit sy eie hostname en IPC-hulpbronne, en mag selfs as root binne sy eie user namespace loop. Maar onder die oppervlakte is dit steeds 'n gasheerversoek wat die kernel soos enige ander skeduleer.

Dit is hoekom container-sekuriteit eintlik die studie is van hoe daardie illusie gebou word en hoe dit faal. As die mount namespace swak is, mag die proses die host filesystem sien. As die user namespace afwesig of gedeaktiveer is, mag root binne die container te nou aan root op die host map. As seccomp nie beperk is nie en die capability-stel te wyd is, mag die proses syscalls en bevoegde kernel-funksies bereik wat buite bereik behoort te bly. As die runtime-socket binne die container gemount is, benodig die container dalk glad nie 'n kernel-breakout nie omdat dit eenvoudig die runtime kan vra om 'n meer kragtige broer-container te begin of die host root filesystem direk te mount.

## Hoe Containers Verskil Van Virtuele Masjiene

'n VM dra gewoonlik sy eie kernel en hardeware-abstraksiegrens. Dit beteken die guest kernel kan crash, panic, of uitgebuit word sonder dat dit outomaties direkte beheer van die host kernel impliseer. By containers kry die workload nie 'n aparte kernel nie. In plaas daarvan kry dit 'n nou gekeurde en namespaced uitsig van dieselfde kernel wat die host gebruik. Gevolglik is containers gewoonlik lichter, vinniger om te begin, makliker om dig op 'n masjien te pak, en beter geskik vir kortlewende toepassing-deploymente. Die prys is dat die isolasiegrens baie meer direk van korrekte host- en runtime-konfigurasie afhanklik is.

Dit beteken nie container is "onveilig" en VMs is "veilig" nie. Dit beteken die sekuriteitsmodel is anders. 'n Goed-gekonfigureerde container-stapel met rootless uitvoering, user namespaces, default seccomp, 'n streng capability-stel, geen host namespace-deling nie, en sterk SELinux of AppArmor-enforcing kan baie robuust wees. Andersyds is 'n container wat met `--privileged` begin is, host PID/netwerkdeling, die Docker socket daarin gemount, en 'n skryfbare bind mount van `/` funksioneel baie nader aan host root toegang as aan 'n veilig geïsoleerde toepassings-sandbox. Die verskil kom van die lae wat aangeskakel of gedeaktiveer is.

Daar is ook 'n middelgrond wat lesers moet verstaan omdat dit al hoe meer in werklike omgewings voorkom. **Sandboxed container runtimes** soos **gVisor** en **Kata Containers** verhard die grens doelbewus verder as 'n klassieke `runc` container. gVisor plaas 'n userspace-kernellaag tussen die workload en baie host kernel-koppelvlakke, terwyl Kata die workload binne 'n ligte virtuele masjien begin. Hierdie word steeds deur container-ekosisteme en orkestrasie-werkvloei gebruik, maar hul sekuriteitseienskappe verskil van gewone OCI-runtimes en moet nie mentaal saamgegroepeer word met "normal Docker containers" asof alles op dieselfde manier optree nie.

## Die Container-stapel: Verskeie Lae, Nie Net Een Nie

Wanneer iemand sê "hierdie container is onveilig", is die nuttige opvolgvraag: **watter laag het dit onveilig gemaak?** 'n Containerized workload is gewoonlik die resultaat van verskeie komponente wat saamwerk.

Bo-aan is daar dikwels 'n **image build-laag** soos BuildKit, Buildah, of Kaniko, wat die OCI-image en metadata skep. Bo die lae runtime is daar moontlik 'n **engine of manager** soos Docker Engine, Podman, containerd, CRI-O, Incus, of systemd-nspawn. In klusteromgewings mag daar ook 'n **orchestrator** soos Kubernetes wees wat die versoekte sekuriteitsposituur deur workload-konfigurasie bepaal. Laastens is die **kernel** wat namespaces, cgroups, seccomp, en MAC-beleid werklik afdwing.

Hierdie gelaagde model is belangrik vir die verstaan van defaults. 'n Beperking mag deur Kubernetes versoek word, vertaal deur CRI deur containerd of CRI-O, omskep in 'n OCI-spec deur die runtime wrapper, en eers dan afgedwing word deur `runc`, `crun`, `runsc`, of 'n ander runtime teen die kernel. Wanneer defaults tussen omgewings verskil, is dit dikwels omdat een van hierdie lae die finale konfigurasie verander het. Dieselfde meganisme kan dus in Docker of Podman as 'n CLI-vlag verskyn, in Kubernetes as 'n Pod of `securityContext`-veld, en in laervlaks runtime-stapels as OCI-konfigurasie wat vir die workload gegenereer is. Om hierdie rede moet CLI-voorbeelde in hierdie afdeling gelees word as **runtime-spesifieke sintaksis vir 'n algemene container-konsep**, nie as universele vlagte wat deur elke hulpmiddel ondersteun word nie.

## Die Ware Container Sekuriteitsgrens

In die praktyk kom container-sekuriteit van **oorvloedige kontroles**, nie van 'n enkele perfekte beheer nie. Namespaces isoleer sigbaarheid. cgroups beheer en beperk hulpbrongebruik. Capabilities verminder wat 'n meesterblikende proses eintlik kan doen. seccomp blokkeer gevaarlike syscalls voordat hulle die kernel bereik. AppArmor en SELinux voeg Mandatory Access Control bo-op normale DAC-kontroles. `no_new_privs`, gemaskerde procfs-paaie, en read-only stelselpaaie maak algemene voorreg- en proc/sys-misbruikkettings moeiliker. Die runtime self is ook belangrik omdat dit besluit hoe mounts, sockets, labels, en namespace-joins geskep word.

Dit is waarom 'n groot hoeveelheid container-sekuriteitsdokumentasie herhalend voorkom. Dieselfde escape-ketting hang dikwels op 'n paar meganismes gelyktydig af. Byvoorbeeld, 'n skryfbare host bind mount is sleg, maar dit word veel erger as die container ook as werklike root op die host loop, `CAP_SYS_ADMIN` het, deur seccomp ongesteur is, en nie deur SELinux of AppArmor beperk word nie. Net so is host PID-deling 'n ernstige blootstelling, maar dit word dramaties meer nuttig vir 'n aanvaller wanneer dit gekombineer word met `CAP_SYS_PTRACE`, swak procfs-beskermings, of namespace-entry gereedskap soos `nsenter`. Die regte manier om die onderwerp te dokumenteer is dus nie deur dieselfde aanval op elke bladsy te herhaal nie, maar deur te verduidelik wat elke laag bydra tot die finale grens.

## Hoe Om Hierdie Afdeling Te Lees

Die afdeling is georganiseer van die mees algemene konsepte na die mees spesifieke.

Begin met die runtime en ekosisteem oorsig:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Kyk dan na die control planes en supply-chain-oppervlakke wat gereeld besluit of 'n aanvaller selfs 'n kernel-escape hoef te soek:

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

Gaan dan na die beskermingsmodel:

{{#ref}}
protections/
{{#endref}}

Die namespace-bladsye verduidelik die kernel isolasie-primitiewe afsonderlik:

{{#ref}}
protections/namespaces/
{{#endref}}

Die bladsye oor cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths, en read-only system paths verduidelik die meganismes wat gewoonlik bo-op namespaces gelaag word:

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

## 'n Goeie Eerste Enumerasie-Mindset

Wanneer jy 'n containerized teiken assesseer, is dit baie nuttiger om 'n klein stel presiese tegniese vrae te vra as om onmiddellik na beroemde escape PoCs te spring. Identifiseer eers die **stapel**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer, of iets meer gespesialiseerd. Identifiseer dan die **runtime**: `runc`, `crun`, `runsc`, `kata-runtime`, of 'n ander OCI-verenigbare implementasie. Daarna, kyk of die omgewing **rootful of rootless** is, of **user namespaces** aktief is, of enige **host namespaces** gedeel word, watter **capabilities** oorbly, of **seccomp** aangeskakel is, of 'n **MAC policy** werklik afdwing, of **gevaarlike mounts of sockets** teenwoordig is, en of die proses met die container runtime API kan interakteer.

Daardie antwoorde vertel jou baie meer oor die werklike sekuriteitsposisie as die basis-image-naam ooit sal doen. In baie assesserings kan jy die waarskynlike breakout-familie voorspel voordat jy 'n enkele toepassingslêer lees net deur die finale container-konfigurasie te verstaan.

## Dekking

 Hierdie afdeling dek die ou Docker-gefokusde materiaal onder container-georiënteerde organisasie: runtime en daemon-blootstelling, authorization plugins, image trust en build secrets, gevoelige host mounts, distroless workloads, privileged containers, en die kernel-beskermings wat normaalweg rondom container-uitvoering gelaag word.
{{#include ../../../banners/hacktricks-training.md}}
