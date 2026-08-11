# Container-sekuriteit

## Wat 'n Container Werklik Is

'n Praktiese manier om 'n container te definieer, is die volgende: 'n container is 'n **gewone Linux-prosesboom** wat onder 'n spesifieke OCI-styl-konfigurasie begin is, sodat dit 'n beheerde lêerstelsel, 'n beheerde stel kernel-hulpbronne en 'n beperkte privilegemodel sien. Die proses mag glo dat dit PID 1 is, mag glo dat dit sy eie netwerkstack het, mag glo dat dit sy eie hostname en IPC-hulpbronne besit, en mag selfs as root binne sy eie user namespace loop. Maar onder die enjinkap is dit steeds 'n host-proses wat deur die kernel soos enige ander een geskeduleer word.

Dit is waarom container-sekuriteit eintlik die studie is van hoe daardie illusie geskep word en hoe dit faal. As die mount namespace swak is, mag die proses die host se lêerstelsel sien. As die user namespace afwesig of gedeaktiveer is, mag root binne die container te na aan root op die host karteer. As seccomp unconfined is en die capability-stel te wyd is, mag die proses syscalls en geprivilegeerde kernel-funksies bereik wat buite sy bereik moes gebly het. As die runtime-socket binne die container gemount is, mag die container glad nie 'n kernel breakout nodig hê nie, omdat dit eenvoudig die runtime kan vra om 'n kragtiger sibling-container te begin of die host se root-lêerstelsel direk te mount.

## Hoe Containers Van Virtual Machines Verskil

'n VM bevat normaalweg sy eie kernel en hardeware-abstraksiegrens. Dit beteken dat die guest-kernel kan crash, panic of uitgebuit kan word sonder dat dit outomaties direkte beheer oor die host-kernel impliseer. In containers kry die workload nie 'n aparte kernel nie. In plaas daarvan kry dit 'n sorgvuldig gefiltreerde en genamespaceerde aansig van dieselfde kernel wat die host gebruik. Gevolglik is containers gewoonlik ligter, begin hulle vinniger, is dit makliker om hulle dig op 'n masjien te pak, en is hulle beter geskik vir kortstondige application deployment. Die prys is dat die isolasiegrens veel meer direk van korrekte host- en runtime-konfigurasie afhanklik is.

Dit beteken nie dat containers "insecure" en VMs "secure" is nie. Dit beteken dat die security model verskil. 'n Goed gekonfigureerde container-stack met rootless execution, user namespaces, verstek-seccomp, 'n streng capability-stel, geen host namespace-sharing nie, en sterk SELinux- of AppArmor-enforcement kan baie robuust wees. Omgekeerd is 'n container wat met `--privileged` begin is, met host PID/network-sharing, die Docker-socket wat daarin gemount is, en 'n skryfbare bind mount van `/`, funksioneel veel nader aan host-roottoegang as aan 'n veilig geïsoleerde application sandbox. Die verskil kom van die lae wat geaktiveer of gedeaktiveer is.

Daar is ook 'n middelgrond wat lesers moet verstaan, omdat dit al hoe meer in werklike omgewings voorkom. **Sandboxed container runtimes** soos **gVisor** en **Kata Containers** verhard doelbewus die grens verder as 'n klassieke `runc`-container. gVisor plaas 'n userspace-kernel-laag tussen die workload en baie host-kernel-koppelvlakke, terwyl Kata die workload binne 'n liggewig virtual machine begin. Hierdie word steeds deur container-ekosisteme en orchestration-workflows gebruik, maar hul security-eienskappe verskil van gewone OCI-runtimes en moet nie verstandelik saam met "normale Docker-containers" gegroepeer word asof alles dieselfde werk nie.

## Die Container-stack: Verskeie Lae, Nie Een Nie

Wanneer iemand sê "hierdie container is insecure", is die nuttige opvolgvraag: **watter laag het dit insecure gemaak?** 'n Containerized workload is gewoonlik die resultaat van verskeie komponente wat saamwerk.

Heel bo is daar dikwels 'n **image build layer** soos BuildKit, Buildah of Kaniko, wat die OCI-image en metadata skep. Bo die laevlak-runtime kan daar 'n **engine of manager** wees, soos Docker Engine, Podman, containerd, CRI-O, Incus of systemd-nspawn. In cluster-omgewings kan daar ook 'n **orchestrator** soos Kubernetes wees wat die versoekte security posture deur workload-konfigurasie bepaal. Uiteindelik is die **kernel** wat namespaces, cgroups, seccomp en MAC-policy werklik afdwing.

Hierdie gelaagde model is belangrik om verstekwaardes te verstaan. 'n Beperking kan deur Kubernetes versoek, deur CRI via containerd of CRI-O vertaal, deur die runtime-wrapper in 'n OCI-specifikasie omgeskakel, en eers daarna deur `runc`, `crun`, `runsc` of 'n ander runtime teenoor die kernel afgedwing word. Wanneer verstekwaardes tussen omgewings verskil, is dit dikwels omdat een van hierdie lae die finale konfigurasie verander het. Dieselfde meganisme kan dus in Docker of Podman as 'n CLI-flag verskyn, in Kubernetes as 'n Pod- of `securityContext`-veld, en in laevlak-runtime-stacks as OCI-konfigurasie wat vir die workload gegenereer is. Daarom moet CLI-voorbeelde in hierdie afdeling gelees word as **runtime-spesifieke sintaksis vir 'n algemene container-konsep**, nie as universele flags wat deur elke tool ondersteun word nie.

## Die Werklike Container Security Boundary

In die praktyk kom container-sekuriteit van **oorvleuelende kontroles**, nie van een perfekte kontrole nie. Namespaces isoleer sigbaarheid. cgroups beheer en beperk hulpbrongebruik. Capabilities verminder wat 'n proses wat geprivilegeerd lyk, werklik kan doen. seccomp blokkeer gevaarlike syscalls voordat hulle die kernel bereik. AppArmor en SELinux voeg Mandatory Access Control bo-op normale DAC-kontroles. `no_new_privs`, gemaskerde procfs-paaie en lees-alleen-stelselpaaie maak algemene privilege- en proc/sys-misbruikkettings moeiliker. Die runtime self is ook belangrik, omdat dit besluit hoe mounts, sockets, labels en namespace-joins geskep word.

Dit is waarom baie container-security-dokumentasie herhalend lyk. Dieselfde escape chain hang dikwels tegelykertyd van verskeie meganismes af. Byvoorbeeld, 'n skryfbare host bind mount is sleg, maar dit word veel erger as die container ook as werklike root op die host loop, `CAP_SYS_ADMIN` het, deur seccomp unconfined is, en nie deur SELinux of AppArmor beperk word nie. Net so is host PID-sharing 'n ernstige blootstelling, maar dit word dramaties nuttiger vir 'n aanvaller wanneer dit gekombineer word met `CAP_SYS_PTRACE`, swak procfs-beskerming of namespace-entry-tools soos `nsenter`. Die korrekte manier om die onderwerp te dokumenteer, is dus nie om dieselfde attack op elke bladsy te herhaal nie, maar om te verduidelik wat elke laag tot die finale grens bydra.

## Hoe Om Hierdie Afdeling Te Lees

Die afdeling is georganiseer van die mees algemene konsepte tot die mees spesifieke.

Begin met die runtime- en ekosisteemoorsig:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Hersien daarna die control planes en supply-chain-oppervlakke wat dikwels bepaal of 'n aanvaller selfs 'n kernel escape nodig het:

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

Gaan daarna na die protection model:

{{#ref}}
protections/
{{#endref}}

Die namespace-bladsye verduidelik die kernel-isolasieprimitiewe individueel:

{{#ref}}
protections/namespaces/
{{#endref}}

Die bladsye oor cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, gemaskerde paaie en lees-alleen-stelselpaaie verduidelik die meganismes wat gewoonlik bo-op namespaces gelaag word:

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

## 'n Goeie Eerste Enumeration-ingesteldheid

Wanneer 'n containerized target geassesseer word, is dit baie nuttiger om 'n klein stel presiese tegniese vrae te vra as om onmiddellik na bekende escape-PoCs te spring. Identifiseer eerstens die **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer of iets meer gespesialiseerd. Identifiseer daarna die **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` of 'n ander OCI-compatible implementering. Kyk daarna of die omgewing **rootful of rootless** is, of **user namespaces** aktief is, of enige **host namespaces** gedeel word, watter **capabilities** oorbly, of **seccomp** geaktiveer is, of 'n **MAC-policy** werklik afdwing, of **dangerous mounts of sockets** teenwoordig is, en of die proses met die container-runtime-API kan kommunikeer.

Daardie antwoorde vertel jou veel meer van die werklike security posture as wat die basis-image-naam ooit sal doen. In baie assessments kan jy die waarskynlike breakout-familie voorspel voordat jy selfs een application file lees, bloot deur die finale container-konfigurasie te verstaan.

## Coverage

Hierdie afdeling dek die ou Docker-gefokusde materiaal onder 'n container-georiënteerde organisasie: runtime- en daemon-blootstelling, authorization plugins, image trust en build secrets, sensitiewe host mounts, distroless-workloads, privileged containers en die kernel-beskermings wat normaalweg rondom container-execution gelaag word.

{{#include ../../../banners/hacktricks-training.md}}
