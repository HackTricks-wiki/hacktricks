# Containersekuriteit

{{#include ../../../banners/hacktricks-training.md}}

## Wat 'n Container Werklik Is

'n Praktiese manier om 'n container te definieer, is die volgende: 'n container is 'n **gewone Linux-prosesboom** wat onder 'n spesifieke OCI-stylkonfigurasie begin is, sodat dit 'n beheerde lêerstelsel, 'n beheerde stel kernhulpbronne en 'n beperkte privilegiemodel sien. Die proses mag glo dat dit PID 1 is, mag glo dat dit sy eie netwerkstapel het, mag glo dat dit sy eie gasheernaam en IPC-hulpbronne besit, en mag selfs as root binne sy eie gebruikersnamespace loop. Onder die oppervlak is dit egter steeds 'n gasheerproses wat deur die kern geskeduleer word soos enige ander.

Dit is waarom containersekuriteit in werklikheid die studie is van hoe daardie illusie opgebou word en hoe dit faal. As die mount namespace swak is, kan die proses dalk die gasheerlêerstelsel sien. As die user namespace afwesig of gedeaktiveer is, kan root binne die container te nou met root op die gasheer ooreenstem. As seccomp onbeperk is en die capability-stel te breed is, kan die proses toegang kry tot syscalls en bevoorregte kernfunksies wat buite bereik moes gebly het. As die runtime-sok binne die container gemount is, het die container dalk glad nie 'n kernel breakout nodig nie, omdat dit bloot die runtime kan vra om 'n kragtiger sibling-container te begin of die gasheer se root-lêerstelsel direk te mount.

## Hoe Containers Van Virtual Machines Verskil

'n VM bevat normaalweg sy eie kern en hardeware-abstraksiegrens. Dit beteken die guest-kern kan crash, panic of uitgebuit word sonder dat dit outomaties direkte beheer oor die gasheerkern impliseer. In containers kry die workload nie 'n aparte kern nie. In plaas daarvan kry dit 'n noukeurig gefiltreerde en genamespaceerde aansig van dieselfde kern wat die gasheer gebruik. Gevolglik is containers gewoonlik ligter, begin hulle vinniger, is dit makliker om hulle dig op 'n masjien te pak, en is hulle beter geskik vir kortstondige toepassingsontplooiing. Die prys is dat die isolasiegrens baie meer direk van korrekte gasheer- en runtime-konfigurasie afhanklik is.

Dit beteken nie dat containers "onveilig" en VMs "veilig" is nie. Dit beteken dat die sekuriteitsmodel verskil. 'n Goed-gekonfigureerde containerstapel met rootless execution, user namespaces, verstek-seccomp, 'n streng capability-stel, geen host namespace-sharing nie, en sterk SELinux- of AppArmor-afdwinging kan baie robuust wees. Omgekeerd is 'n container wat met `--privileged`, host PID/network sharing, die Docker-sok binne-in gemount, en 'n skryfbare bind mount van `/` begin is, funksioneel baie nader aan root-toegang op die gasheer as aan 'n veilig geïsoleerde toepassingsandbox. Die verskil kom van die lae wat geaktiveer of gedeaktiveer is.

Daar is ook 'n middelgrond waarvan lesers bewus moet wees, omdat dit al hoe meer in werklike omgewings voorkom. **Sandboxed container runtimes** soos **gVisor** en **Kata Containers** verhard doelbewus die grens verder as 'n klassieke `runc`-container. gVisor plaas 'n userspace-kernlaag tussen die workload en baie gasheerkern-koppelvlakke, terwyl Kata die workload binne 'n liggewig virtual machine begin. Dit word steeds deur container-ekosisteme en orkestreringsworkflows gebruik, maar hul sekuriteitseienskappe verskil van gewone OCI-runtimes en moet nie verstandelik saamgegroepeer word met "normale Docker-containers" asof alles dieselfde werk nie.

## Die Containerstapel: Verskeie Lae, Nie Een Nie

Wanneer iemand sê "hierdie container is onveilig", is die nuttige opvolgvraag: **watter laag het dit onveilig gemaak?** 'n Containerized workload is gewoonlik die resultaat van verskeie komponente wat saamwerk.

Heel bo is daar dikwels 'n **image build layer** soos BuildKit, Buildah of Kaniko, wat die OCI-image en metadata skep. Bo die laevlak-runtime kan daar 'n **engine or manager** wees soos Docker Engine, Podman, containerd, CRI-O, Incus of systemd-nspawn. In cluster-omgewings kan daar ook 'n **orchestrator** soos Kubernetes wees wat die aangevraagde sekuriteitshouding deur workload-konfigurasie bepaal. Uiteindelik is dit die **kern** wat namespaces, cgroups, seccomp en MAC-beleid werklik afdwing.

Hierdie gelaagde model is belangrik om verstekwaardes te verstaan. 'n Beperking kan deur Kubernetes aangevra, deur CRI via containerd of CRI-O vertaal, deur die runtime-wrapper in 'n OCI-specifikasie omskep, en eers daarna deur `runc`, `crun`, `runsc` of 'n ander runtime teenoor die kern afgedwing word. Wanneer verstekwaardes tussen omgewings verskil, is dit dikwels omdat een van hierdie lae die finale konfigurasie verander het. Dieselfde meganisme kan dus in Docker of Podman as 'n CLI-flag verskyn, in Kubernetes as 'n Pod- of `securityContext`-veld, en in laervlak-runtimestapels as OCI-konfigurasie wat vir die workload gegenereer is. Om dié rede moet CLI-voorbeelde in hierdie afdeling gelees word as **runtime-spesifieke sintaksis vir 'n algemene containerkonsep**, nie as universele flags wat deur elke tool ondersteun word nie.

## Die Werklike Containersekuriteitsgrens

In die praktyk kom containersekuriteit van **oorvleuelende kontroles**, nie van 'n enkele perfekte kontrole nie. Namespaces isoleer sigbaarheid. cgroups beheer en beperk hulpbrongebruik. Capabilities verminder wat 'n proses wat bevoorreg lyk, werklik kan doen. seccomp blokkeer gevaarlike syscalls voordat dit die kern bereik. AppArmor en SELinux voeg Mandatory Access Control bo-op normale DAC-kontroles. `no_new_privs`, gemaskerde procfs-paaie en leesalleen-stelselpaaie maak algemene privilege- en proc/sys-misbruikkettings moeiliker. Die runtime self is ook belangrik, omdat dit bepaal hoe mounts, sokke, labels en namespace-joins geskep word.

Dit is waarom baie containersekuriteitsdokumentasie herhalend lyk. Dieselfde escape chain hang dikwels van verskeie meganismes tegelyk af. Byvoorbeeld, 'n skryfbare gasheer-bind mount is sleg, maar dit word veel erger as die container ook as werklike root op die gasheer loop, `CAP_SYS_ADMIN` het, onbeperk is deur seccomp, en nie deur SELinux of AppArmor beperk word nie. Net so is host PID sharing 'n ernstige blootstelling, maar dit word dramaties nuttiger vir 'n aanvaller wanneer dit gekombineer word met `CAP_SYS_PTRACE`, swak procfs-beskerming of namespace-entry-tools soos `nsenter`. Die korrekte manier om die onderwerp te dokumenteer, is dus nie om dieselfde aanval op elke bladsy te herhaal nie, maar om te verduidelik wat elke laag tot die finale grens bydra.

## Hoe Om Hierdie Afdeling Te Lees

Die afdeling is georganiseer vanaf die mees algemene konsepte tot die mees spesifieke.

Begin met die runtime- en ekosisteemoorsig:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Hersien daarna die beheerlae en supply-chain-oppervlakke wat dikwels bepaal of 'n aanvaller enigsins 'n kernel escape nodig het:

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

Die namespace-bladsye verduidelik die kern-isolasieprimitiewe individueel:

{{#ref}}
protections/namespaces/
{{#endref}}

Die bladsye oor cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, gemaskerde paaie en leesalleen-stelselpaaie verduidelik die meganismes wat gewoonlik bo-op namespaces gelaag word:

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

## 'n Goeie Eerste Enumerasie-ingesteldheid

Wanneer 'n containerized target geassesseer word, is dit baie nuttiger om 'n klein stel presiese tegniese vrae te vra as om onmiddellik na bekende escape PoCs te spring. Identifiseer eerstens die **stapel**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer of iets meer gespesialiseerd. Identifiseer daarna die **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` of 'n ander OCI-compatible implementasie. Kontroleer daarna of die omgewing **rootful of rootless** is, of **user namespaces** aktief is, of enige **host namespaces** gedeel word, watter **capabilities** oorbly, of **seccomp** geaktiveer is, of 'n **MAC-beleid** werklik afdwing, of **gevaarlike mounts of sokke** teenwoordig is, en of die proses met die container-runtime-API kan kommunikeer.

Daardie antwoorde vertel jou veel meer van die werklike sekuriteitshouding as wat die basis-image-naam ooit sal doen. In baie assesserings kan jy die waarskynlike breakout-familie voorspel voordat jy 'n enkele toepassingslêer lees, bloot deur die finale containerkonfigurasie te verstaan.

## Dekking

Hierdie afdeling dek die ou Docker-gefokusde materiaal onder 'n container-georiënteerde organisasie: runtime- en daemon-blootstelling, authorization plugins, image trust en build secrets, sensitiewe gasheermounts, distroless-workloads, bevoorregte containers en die kernbeskermings wat normaalweg rondom containeruitvoering gelaag word.

{{#include ../../../banners/hacktricks-training.md}}
