# Container Security

{{#include ../../../banners/hacktricks-training.md}}

## What A Container Actually Is

'n Praktiese manier om 'n container te definieer is dit: 'n container is 'n **gereelde Linux-prosesboom** wat begin is onder 'n spesifieke OCI-style konfiguratie sodat dit 'n beheer­de lêerstelsel, 'n beheer­de stel kernel-hulpbronne, en 'n beperkte privilegiemodel sien. Die proses mag glo dit is PID 1, mag glo dit het sy eie netwerkstapel, mag glo dit besit sy eie hostname en IPC-hulpbronne, en mag selfs as root binne sy eie user namespace loop. Maar onder die deksel is dit steeds 'n host-proses wat die kernel soos enige ander skeduleer.

Dit is hoekom container-sekuriteit eintlik die studie is van hoe daardie illusie opgebou word en hoe dit misluk. As die mount namespace swak is, mag die proses die host-lêerstelsel sien. As die user namespace afwesig of gedeaktiveer is, mag root binne die container te nou na root op die host map. As seccomp ongekonfineer is en die capability-set te breed is, mag die proses syscalls en bevoorregte kernel-funksies bereik wat buite bereik moes gebly het. As die runtime socket binne die container gemounte is, het die container dalk glad nie 'n kernel-breakout nodig nie omdat dit eenvoudig die runtime kan vra om 'n meer kragtige sussie-container te begin of die host-root filesystem direk te mount.

## How Containers Differ From Virtual Machines

'n VM dra normaalweg sy eie kernel en hardware-abstraksiegrens. Dit beteken die guest kernel kan crash, panic, of uitgebuit word sonder om outomaties beheer van die host-kernel te impliseer. In containers kry die workload nie 'n afsonderlike kernel nie. In plaas daarvan kry dit 'n noukeurig gefiltreerde en genaamruimteerde siening van dieselfde kernel wat die host gebruik. Gevolglik is containers gewoonlik ligter, vinniger om te begin, makliker om dig op 'n masjien te pak, en beter geskik vir kortlewende toepassing‑ontplooiing. Die prys is dat die isolasiegrens baie meer direk afhanklik is van korrekte host- en runtime‑konfigurasie.

Dit beteken nie noodwendig dat containers "onveilig" is en VMs "veilig" nie. Dit beteken die sekuriteitsmodel is anders. 'n Goed-gekonfigureerde container‑stack met rootless uitvoering, user namespaces, standaard seccomp, 'n streng capability-set, geen host-namespace sharing nie, en sterk SELinux of AppArmor‑handhawing kan baie robuust wees. Omgekeerd is 'n container wat begin is met `--privileged`, host PID/network sharing, die Docker socket binne dit gemounte, en 'n skryfbare bind mount van `/` funksioneel baie nader aan host-root toegang as aan 'n veilig geïsoleerde toepassings-sandbox. Die verskil kom van die lae wat geaktiveer of gedeaktiveer is.

Daar is ook 'n middelgrond wat lesers moet verstaan omdat dit al hoe meer in werklike omgewings voorkom. **Sandboxed container runtimes** soos **gVisor** en **Kata Containers** verskerp die grens doelbewus verder as 'n klassieke `runc` container. gVisor plaas 'n userspace-kernellaag tussen die workload en baie host-kernel interfaces, terwyl Kata die workload binne 'n liggewig virtuele masjien begin. Hierdie word steeds deur container-ekosisteme en orkestrasie-werkvloei gebruik, maar hul sekuriteitseienskappe verskil van gewone OCI runtimes en moet nie sielkundig saam gegroepeer word met "normale Docker containers" asof alles op dieselfde manier optree nie.

## The Container Stack: Several Layers, Not One

Wanneer iemand sê "hierdie container is onveilig", is die nuttige opvolgvraag: **watter laag het dit onveilig gemaak?** 'n Containerized workload is gewoonlik die resultaat van verskeie komponente wat saamwerk.

Boonop is daar dikwels 'n **image build layer** soos BuildKit, Buildah, of Kaniko, wat die OCI image en metadata skep. Bo die lae‑vlak runtime kan daar 'n **engine of manager** wees soos Docker Engine, Podman, containerd, CRI-O, Incus, of systemd-nspawn. In cluster‑omgewings kan daar ook 'n **orchestrator** wees soos Kubernetes wat die versoekte sekuriteits‑houding deur workload‑konfigurasie bepaal. Laastens is die **kernel** dit wat werklik namespaces, cgroups, seccomp, en MAC‑beleid afdwing.

Hierdie gelaagde model is belangrik om standaardwaardes te verstaan. 'n Beperking kan versoek word deur Kubernetes, deur CRI vertaal word deur containerd of CRI‑O, omskep word in 'n OCI‑spesifikasie deur die runtime‑wrapper, en eers dan deur `runc`, `crun`, `runsc`, of 'n ander runtime teen die kernel afgedwing word. Wanneer standaardwaardes tussen omgewings verskil, is dit dikwels omdat een van hierdie lae die finale konfigurasie verander het. Dieselfde meganisme kan dus in Docker of Podman as 'n CLI‑vlag verskyn, in Kubernetes as 'n Pod of `securityContext`‑veld, en in laer‑vlak runtime‑stacks as OCI‑konfigurasie wat vir die workload gegenereer is. Om daardie rede moet CLI‑voorbeelde in hierdie afdeling gelees word as **runtime‑spesifieke sintaksis vir 'n algemene container‑konsep**, nie as universele vlae wat deur elke instrument ondersteun word nie.

## The Real Container Security Boundary

In die praktyk kom container‑sekuriteit van **oorvleuelende kontroles**, nie van 'n enkele perfekte beheer nie. Namespaces isoleer sigbaarheid. cgroups beheer en beperk hulpbronverbruik. Capabilities verminder wat 'n bevoorregte‑klinkende proses eintlik kan doen. seccomp blokkeer gevaarlike syscalls voordat dit die kernel bereik. AppArmor en SELinux voeg Mandatory Access Control bo-op normale DAC‑kontroles. `no_new_privs`, gemaskerde procfs‑pade, en read‑only stelsel‑pade maak algemene privilegie‑ en proc/sys‑misbruikkettings moeiliker. Die runtime self maak ook saak omdat dit besluit hoe mounts, sockets, labels, en namespace joins geskep word.

Dit is hoekom baie container‑sekuriteitsdokumentasie herhalend lyk. Dieselfde escape‑ketting hang dikwels op meerdere meganismes terselfdertyd af. Byvoorbeeld, 'n skryfbare host bind mount is sleg, maar dit word baie erger as die container ook as werklike root op die host loop, `CAP_SYS_ADMIN` het, deur seccomp ongekonfineer is, en nie deur SELinux of AppArmor beperk word nie. Net so is host PID‑sharing 'n ernstige blootstelling, maar dit word dramaties meer nuttig vir 'n aanvaller wanneer dit gekombineer word met `CAP_SYS_PTRACE`, swak procfs‑beskermings, of namespace‑betreedings‑hulpmiddels soos `nsenter`. Die regte manier om die onderwerp te dokumenteer is dus nie deur dieselfde aanval op elke bladsy te herhaal nie, maar deur te verduidelik wat elke laag bydra tot die finale grens.

## How To Read This Section

Die afdeling is georganiseer van die mees algemene konsepte na die mees spesifieke.

Begin met die runtime en ekosisteem oorsig:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Lees dan die control planes en supply‑chain oppervlaktes wat gereeld bepaal of 'n aanvaller selfs 'n kernel escape nodig het:

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

Die namespace‑bladsye verduidelik die kernel‑isolasieprimitiewe individueel:

{{#ref}}
protections/namespaces/
{{#endref}}

Die bladsye oor cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, gemaskerde pádte, en read‑only stelsel‑pade verduidelik die meganismes wat gewoonlik bo‑op namespaces geskakel word:

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

Wanneer jy 'n containerized teiken assesseer, is dit baie nuttiger om 'n klein stel presiese tegniese vrae te vra as om onmiddellik na beroemde escape PoCs te spring. Identifiseer eers die **stack**: Docker, Podman, containerd, CRI‑O, Incus/LXC, systemd‑nspawn, Apptainer, of iets meer gespesialiseerd. Identifiseer dan die **runtime**: `runc`, `crun`, `runsc`, `kata-runtime`, of 'n ander OCI‑verenigbare implementasie. Daarna, kyk of die omgewing **rootful of rootless** is, of **user namespaces** aktief is, of enige **host namespaces** gedeel word, watter **capabilities** oorbly, of **seccomp** geaktiveer is, of 'n **MAC‑beleid** werklik afdwing, of **gevaarlike mounts of sockets** teenwoordig is, en of die proses met die container runtime API kan interakteer.

Daardie antwoorde vertel jou veel meer oor die werklike sekuriteitsposisie as wat die basis‑image naam ooit sal doen. In baie assesserings kan jy die waarskynlike breakout‑familie voorspel voordat jy 'n enkele toepassingslêer lees, net deur die finale container‑konfigurasie te verstaan.

## Coverage

Hierdie afdeling dek die ou Docker‑gefokusde materiaal onder container‑georiënteerde organisasie: runtime en daemon‑blootstelling, authorization plugins, image trust en build secrets, sensitiewe host mounts, distroless workloads, privileged containers, en die kernel‑beskerming wat gewoonlik rondom container‑uitvoering gelaag word.
