# Houerveiligheid

{{#include ../../../banners/hacktricks-training.md}}

## Wat 'n Houer Werklik Is

'n Praktiese manier om 'n houer te definieer, is die volgende: 'n houer is 'n **gewone Linux-prosesboom** wat onder 'n spesifieke OCI-stylkonfigurasie begin is, sodat dit 'n beheerde lêerstelsel, 'n beheerde stel kernhulpbronne en 'n beperkte privilegemodel sien. Die proses mag glo dat dit PID 1 is, mag glo dat dit sy eie netwerkstack het, mag glo dat dit sy eie gasheernaam en IPC-hulpbronne besit, en mag selfs as root binne sy eie user namespace loop. Onder die enjinkap is dit egter steeds 'n host-proses wat deur die kernel geskeduleer word soos enige ander een.

Dit is waarom container security in werklikheid die studie is van hoe daardie illusie saamgestel word en hoe dit faal. As die mount namespace swak is, mag die proses die host-lêerstelsel sien. As die user namespace afwesig of gedeaktiveer is, mag root binne die houer te nou met root op die host ooreenstem. As seccomp unconfined is en die capability-stel te wyd is, mag die proses syscalls en geprivilegeerde kernfunksies bereik wat buite sy bereik moes gebly het. As die runtime-socket binne die houer gemount is, het die houer dalk glad nie 'n kernel breakout nodig nie, omdat dit eenvoudig die runtime kan vra om 'n kragtiger sibling-houer te begin of die host se root-lêerstelsel direk te mount.

## Hoe Houers Van Virtuele Masjiene Verskil

'n VM bevat normaalweg sy eie kernel en hardeware-abstraksiegrens. Dit beteken dat die guest-kernel kan crash, panic of exploited kan word sonder dat dit outomaties direkte beheer oor die host-kernel impliseer. In houers kry die workload nie 'n aparte kernel nie. In plaas daarvan kry dit 'n sorgvuldig gefiltreerde en genamespacede aansig van dieselfde kernel wat die host gebruik. Gevolglik is houers gewoonlik ligter, vinniger om te begin, makliker om dig op 'n masjien te pak en beter geskik vir kortstondige application deployment. Die prys is dat die isolasiegrens baie meer direk van korrekte host- en runtime-konfigurasie afhanklik is.

Dit beteken nie dat houers "insecure" en VMs "secure" is nie. Dit beteken dat die security model verskil. 'n Goed gekonfigureerde container stack met rootless execution, user namespaces, default seccomp, 'n streng capability-stel, geen host namespace sharing nie, en sterk SELinux- of AppArmor-enforcement kan baie robuust wees. Omgekeerd is 'n houer wat met `--privileged`, host PID/network sharing, die Docker-socket daarin gemount, en 'n skryfbare bind mount van `/` begin is, funksioneel baie nader aan host root access as aan 'n veilig geïsoleerde application sandbox. Die verskil kom van die lae wat geaktiveer of gedeaktiveer is.

Daar is ook 'n middelgrond waarvan lesers bewus moet wees, omdat dit al hoe meer in werklike omgewings voorkom. **Sandboxed container runtimes** soos **gVisor** en **Kata Containers** verhard die grens doelbewus verder as 'n klassieke `runc`-houer. gVisor plaas 'n userspace-kernellaag tussen die workload en baie host-kernelinterfaces, terwyl Kata die workload binne 'n liggewig virtuele masjien begin. Dit word steeds deur container ecosystems en orchestration workflows gebruik, maar hul security-eienskappe verskil van gewone OCI runtimes en behoort nie verstandelik saam met "normal Docker containers" gegroepeer te word asof alles dieselfde werk nie.

## Die Container Stack: Verskeie Lae, Nie Een Nie

Wanneer iemand sê "this container is insecure", is die nuttige opvolgvraag: **watter laag het dit insecure gemaak?** 'n Containerized workload is gewoonlik die resultaat van verskeie komponente wat saamwerk.

Heel bo is daar dikwels 'n **image build layer** soos BuildKit, Buildah of Kaniko, wat die OCI-image en metadata skep. Bo die laevlak-runtime kan daar 'n **engine or manager** soos Docker Engine, Podman, containerd, CRI-O, Incus of systemd-nspawn wees. In cluster-omgewings kan daar ook 'n **orchestrator** soos Kubernetes wees wat die aangevraagde security posture deur workload-konfigurasie bepaal. Uiteindelik is die **kernel** wat namespaces, cgroups, seccomp en MAC policy werklik afdwing.

Hierdie gelaagde model is belangrik om defaults te verstaan. 'n Beperking kan deur Kubernetes aangevra, deur CRI via containerd of CRI-O vertaal, deur die runtime wrapper in 'n OCI-spec omskep, en eers daarna deur `runc`, `crun`, `runsc` of 'n ander runtime teenoor die kernel afgedwing word. Wanneer defaults tussen omgewings verskil, is dit dikwels omdat een van hierdie lae die finale konfigurasie verander het. Dieselfde meganisme kan dus in Docker of Podman as 'n CLI-flag, in Kubernetes as 'n Pod- of `securityContext`-veld, en in laervlak-runtime stacks as OCI-konfigurasie wat vir die workload gegenereer is, verskyn. Daarom moet CLI-voorbeelde in hierdie afdeling gelees word as **runtime-specific syntax for a general container concept**, nie as universele flags wat deur elke tool ondersteun word nie.

## Die Werklike Container Security Boundary

In die praktyk kom container security van **overlapping controls**, nie van 'n enkele perfekte control nie. Namespaces isoleer sigbaarheid. cgroups beheer en beperk resource usage. Capabilities verminder wat 'n proses wat geprivilegeerd lyk, werklik kan doen. seccomp blokkeer gevaarlike syscalls voordat hulle die kernel bereik. AppArmor en SELinux voeg Mandatory Access Control bo-op normale DAC-checks. `no_new_privs`, gemaskerde procfs-paaie en read-only system paths maak algemene privilege- en proc/sys-abuse chains moeiliker. Die runtime self is ook belangrik, omdat dit besluit hoe mounts, sockets, labels en namespace joins geskep word.

Daarom lyk baie container security-dokumentasie herhalend. Dieselfde escape chain hang dikwels gelyktydig van verskeie meganismes af. Byvoorbeeld, 'n skryfbare host bind mount is sleg, maar dit word baie erger as die houer ook as werklike root op die host loop, `CAP_SYS_ADMIN` het, deur seccomp unconfined is, en nie deur SELinux of AppArmor beperk word nie. Net so is host PID sharing 'n ernstige blootstelling, maar dit word dramaties nuttiger vir 'n attacker wanneer dit gekombineer word met `CAP_SYS_PTRACE`, swak procfs-beskerming of namespace-entry tools soos `nsenter`. Die regte manier om die onderwerp te dokumenteer, is dus nie om dieselfde attack op elke bladsy te herhaal nie, maar om te verduidelik wat elke laag tot die finale grens bydra.

## Hoe Om Hierdie Afdeling Te Lees

Die afdeling is georganiseer van die mees algemene konsepte tot die mees spesifieke.

Begin met die runtime- en ecosystem-oorsig:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Hersien dan die control planes en supply-chain surfaces wat dikwels bepaal of 'n attacker selfs 'n kernel escape nodig het:

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

Gaan dan na die protection model:

{{#ref}}
protections/
{{#endref}}

Die namespace-bladsye verduidelik die kernel se isolation primitives individueel:

{{#ref}}
protections/namespaces/
{{#endref}}

Die bladsye oor cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths en read-only system paths verduidelik die meganismes wat gewoonlik bo-op namespaces gelaag word:

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

## 'n Goeie Eerste Enumeration Mindset

Wanneer 'n containerized target geassesseer word, is dit baie nuttiger om 'n klein stel presiese tegniese vrae te vra as om onmiddellik na bekende escape PoCs te spring. Identifiseer eers die **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer of iets meer gespesialiseerd. Identifiseer dan die **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` of 'n ander OCI-compatible implementasie. Kyk daarna of die omgewing **rootful of rootless** is, of **user namespaces** aktief is, of enige **host namespaces** gedeel word, watter **capabilities** oorbly, of **seccomp** geaktiveer is, of 'n **MAC policy** werklik enforcing is, of **dangerous mounts or sockets** teenwoordig is, en of die proses met die container runtime API kan kommunikeer.

Daardie antwoorde vertel jou veel meer van die werklike security posture as wat die base image name ooit sal doen. In baie assessments kan jy die waarskynlike breakout family voorspel voordat jy 'n enkele application file lees, bloot deur die finale container configuration te verstaan.

## Coverage

Hierdie afdeling dek die ou Docker-focused materiaal onder 'n container-oriented organisasie: runtime- en daemon exposure, authorization plugins, image trust en build secrets, sensitive host mounts, distroless workloads, privileged containers en die kernel protections wat normaalweg rondom container execution gelayer word.

{{#include ../../../banners/hacktricks-training.md}}
