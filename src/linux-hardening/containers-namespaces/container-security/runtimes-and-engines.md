# Container Runtimes, Engines, Builders En Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Een van die grootste bronne van verwarring in container-sekuriteit is dat verskeie heeltemal verskillende komponente dikwels tot dieselfde woord gereduseer word. "Docker" kan na 'n image-formaat, 'n CLI, 'n daemon, 'n build-stelsel, 'n runtime-stack, of bloot die algemene idee van containers verwys. Vir sekuriteitswerk is daardie dubbelsinnigheid 'n probleem, omdat verskillende lae vir verskillende beskermings verantwoordelik is. 'n Breakout wat deur 'n swak bind mount veroorsaak word, is nie dieselfde as 'n breakout wat deur 'n low-level runtime-bug veroorsaak word nie, en nie een van hulle is dieselfde as 'n cluster-policy-fout in Kubernetes nie.

Hierdie bladsy skei die ecosystem volgens rol sodat die res van die afdeling presies kan aandui waar 'n beskerming of swakheid werklik geleë is.

## OCI As Die Gemeenskaplike Taal

Moderne Linux-container-stacks kan dikwels saamwerk omdat hulle 'n stel OCI-spesifikasies gebruik. Die **OCI Image Specification** beskryf hoe images en layers voorgestel word. Die **OCI Runtime Specification** beskryf hoe die runtime die proses moet launch, insluitend namespaces, mounts, cgroups en security settings. Die **OCI Distribution Specification** standardiseer hoe registries content beskikbaar stel.

Dit is belangrik omdat dit verduidelik waarom 'n container image wat met een tool gebou is, dikwels met 'n ander tool uitgevoer kan word, en waarom verskeie engines dieselfde low-level runtime kan deel. Dit verduidelik ook waarom security behavior soortgelyk oor verskillende produkte kan lyk: baie van hulle bou dieselfde OCI runtime configuration en gee dit aan dieselfde klein stel runtimes.

## Low-Level OCI Runtimes

Die low-level runtime is die komponent wat die naaste aan die kernel-grens is. Dit is die deel wat namespaces skep, cgroup-settings skryf, capabilities en seccomp-filters toepas, en uiteindelik `execve()` op die container-proses uitvoer. Wanneer mense op die meganiese vlak oor "container isolation" praat, verwys hulle gewoonlik na hierdie laag, selfs al sê hulle dit nie uitdruklik nie.

### `runc`

`runc` is die reference OCI runtime en bly die bekendste implementering. Dit word wyd onder Docker, containerd en baie Kubernetes-deployments gebruik. Baie publieke navorsing en exploitation-materiaal teiken `runc`-style omgewings bloot omdat hulle algemeen voorkom en omdat `runc` die baseline definieer waaraan baie mense dink wanneer hulle 'n Linux-container voorstel. Om `runc` te verstaan, gee 'n leser dus 'n sterk mental model van klassieke container-isolasie.

### `crun`

`crun` is nog 'n OCI runtime, geskryf in C en wyd gebruik in moderne Podman-omgewings. Dit word dikwels geprys vir goeie cgroup v2-support, sterk rootless-ergonomie en laer overhead. Vanuit 'n security-perspektief is die belangrike punt nie dat dit in 'n ander taal geskryf is nie, maar dat dit steeds dieselfde rol vervul: dit is die komponent wat die OCI-configuration in 'n lopende prosesboom onder die kernel omskep. 'n Rootless Podman-workflow voel dikwels veiliger, nie omdat `crun` alles magies regmaak nie, maar omdat die algehele stack daaromheen geneig is om sterker op user namespaces en least privilege te steun.

### `runsc` From gVisor

`runsc` is die runtime wat deur gVisor gebruik word. Hier verander die grens betekenisvol. In plaas daarvan om die meeste syscalls direk op die host-kernel uit te voer soos gewoonlik, voeg gVisor 'n userspace-kernel-laag in wat groot dele van die Linux-interface emuleer of modereer. Die resultaat is nie 'n normale `runc`-container met 'n paar ekstra flags nie; dit is 'n ander sandbox-ontwerp met die doel om die host-kernel se attack surface te verminder. Compatibility- en performance-trade-offs is deel van daardie ontwerp, dus moet omgewings wat `runsc` gebruik anders as normale OCI-runtime-omgewings gedokumenteer word.

### `kata-runtime`

Kata Containers verskuif die grens verder deur die workload binne 'n lightweight virtual machine te launch. Administratief kan dit steeds soos 'n container-deployment lyk, en orchestration-layers kan dit steeds so hanteer, maar die onderliggende isolation boundary is nader aan virtualisasie as aan 'n klassieke container wat die host-kernel deel. Dit maak Kata nuttig wanneer sterker tenant-isolation verlang word sonder om container-gesentreerde workflows te laat vaar.

## Engines And Container Managers

As die low-level runtime die komponent is wat direk met die kernel praat, is die engine of manager die komponent waarmee users en operators gewoonlik interaksie het. Dit hanteer image pulls, metadata, logs, networks, volumes, lifecycle operations en API-exposure. Hierdie laag is uiters belangrik omdat baie compromises in die werklike wêreld hier plaasvind: toegang tot 'n runtime-socket of daemon-API kan gelykstaande wees aan host-compromise, selfs al is die low-level runtime self heeltemal gesond.

### Docker Engine

Docker Engine is die mees herkenbare container-platform vir developers en een van die redes waarom container-woordeskat so Docker-vormig geword het. Die tipiese pad is `docker` CLI na `dockerd`, wat op sy beurt laer-vlak-komponente soos `containerd` en 'n OCI-runtime koördineer. Histories was Docker-deployments dikwels **rootful**, en toegang tot die Docker-socket was dus 'n baie kragtige primitive. Dit is waarom soveel praktiese privilege-escalation-materiaal op `docker.sock` fokus: as 'n proses `dockerd` kan vra om 'n privileged container te skep, host paths te mount, of by host namespaces aan te sluit, het dit moontlik glad nie 'n kernel-exploit nodig nie.

### Podman

Podman is rondom 'n meer daemonless-model ontwerp. Operasioneel help dit om die idee te versterk dat containers bloot prosesse is wat deur standaard Linux-meganismes bestuur word, eerder as deur een langlewende privileged daemon. Podman het ook 'n baie sterker **rootless**-verhaal as die klassieke Docker-deployments waarmee baie mense aanvanklik geleer het. Dit maak Podman nie outomaties veilig nie, maar dit verander die default risk profile betekenisvol, veral wanneer dit met user namespaces, SELinux en `crun` gekombineer word.

### containerd

containerd is 'n kern runtime-management-component in baie moderne stacks. Dit word onder Docker gebruik en is ook een van die dominante Kubernetes-runtime-backends. Dit stel kragtige APIs beskikbaar, bestuur images en snapshots, en delegeer die finale process creation aan 'n low-level runtime. Security-besprekings oor containerd moet beklemtoon dat toegang tot die containerd-socket of `ctr`/`nerdctl`-funksionaliteit net so gevaarlik kan wees soos toegang tot Docker se API, selfs al voel die interface en workflow minder "developer friendly".

### CRI-O

CRI-O is meer gefokus as Docker Engine. In plaas daarvan om 'n algemene developer-platform te wees, is dit gebou rondom die skoon implementering van Kubernetes se Container Runtime Interface. Dit maak dit veral algemeen in Kubernetes-distributions en SELinux-swaar ecosystems soos OpenShift. Vanuit 'n security-perspektief is daardie nouer scope nuttig omdat dit konseptuele clutter verminder: CRI-O is baie duidelik deel van die "run containers for Kubernetes"-laag eerder as 'n everything-platform.

### Incus, LXD, And LXC

Incus/LXD/LXC-stelsels verdien om van Docker-style application-containers onderskei te word omdat hulle dikwels as **system containers** gebruik word. Daar word gewoonlik van 'n system container verwag om meer soos 'n lightweight machine met 'n vollediger userspace, langlopende services, ryker device-exposure en meer uitgebreide host-integration te lyk. Die isolation mechanisms is steeds kernel-primitives, maar die operasionele verwagtinge verskil. As gevolg hiervan lyk misconfigurations hier dikwels minder soos "bad app-container defaults" en meer soos foute in lightweight virtualization of host delegation.

### systemd-nspawn

systemd-nspawn beklee 'n interessante plek omdat dit systemd-native is en baie nuttig is vir testing, debugging en die uitvoer van OS-like environments. Dit is nie die dominante cloud-native production-runtime nie, maar dit verskyn gereeld genoeg in labs en distro-georiënteerde omgewings dat dit vermelding verdien. Vir security analysis is dit nog 'n herinnering dat die konsep "container" oor verskeie ecosystems en operasionele style strek.

### Apptainer / Singularity

Apptainer (voorheen Singularity) is algemeen in research- en HPC-omgewings. Sy trust assumptions, user workflow en execution model verskil op belangrike maniere van Docker/Kubernetes-gesentreerde stacks. Hierdie omgewings gee veral dikwels baie om oor die vermoë om users packaged workloads te laat run sonder om aan hulle breë privileged container-management powers te gee. As 'n reviewer aanvaar dat elke container-omgewing basies "Docker op 'n server" is, sal hulle hierdie deployments ernstig verkeerd verstaan.

## Build-Time Tooling

Baie security-besprekings praat slegs oor runtime, maar build-time tooling is ook belangrik omdat dit image contents, build secrets exposure en die hoeveelheid trusted context bepaal wat in die finale artifact ingebed word.

**BuildKit** en `docker buildx` is moderne build-backends wat features soos caching, secret mounting, SSH-forwarding en multi-platform builds ondersteun. Dit is nuttige features, maar vanuit 'n security-perspektief skep dit ook plekke waar secrets in image layers kan lek of waar 'n te breë build context files kan blootstel wat nooit ingesluit moes gewees het nie. **Buildah** vervul 'n soortgelyke rol in OCI-native ecosystems, veral rondom Podman, terwyl **Kaniko** dikwels gebruik word in CI-omgewings wat nie 'n privileged Docker-daemon aan die build-pipeline wil gee nie.

Die kernles is dat image creation en image execution verskillende fases is, maar dat 'n swak build-pipeline 'n swak runtime-posture kan skep lank voordat die container gelauch word.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes moet nie verstandelik met die runtime self gelykgestel word nie. Kubernetes is die orchestrator. Dit schedule Pods, stoor desired state en druk security policy deur workload-configuration uit. Die kubelet praat dan met 'n CRI-implementering soos containerd of CRI-O, wat op sy beurt 'n low-level runtime soos `runc`, `crun`, `runsc` of `kata-runtime` invoke.

Hierdie skeiding is belangrik omdat baie mense verkeerdelik 'n protection aan "Kubernetes" toeskryf wanneer dit eintlik deur die node-runtime afgedwing word, of hulle blameer "containerd defaults" vir behavior wat uit 'n Pod-spec kom. In die praktyk is die finale security-posture 'n samestelling: die orchestrator vra vir iets, die runtime-stack vertaal dit, en die kernel dwing dit uiteindelik af.

## Why Runtime Identification Matters During Assessment

As jy die engine en runtime vroeg identifiseer, word baie latere observations makliker om te interpreteer. 'n Rootless Podman-container dui daarop dat user namespaces waarskynlik deel van die storie is. 'n Docker-socket wat in 'n workload gemount is, dui daarop dat API-driven privilege escalation 'n realistiese path is. 'n CRI-O/OpenShift-node behoort jou onmiddellik aan SELinux-labels en restricted-workload-policy te laat dink. 'n gVisor- of Kata-omgewing behoort jou versigtiger te maak om te aanvaar dat 'n klassieke `runc`-breakout-PoC dieselfde sal optree.

Daarom behoort een van die eerste stappe in container-assessment altyd te wees om twee eenvoudige vrae te beantwoord: **watter komponent bestuur die container** en **watter runtime het die proses werklik gelauch**. Sodra hierdie antwoorde duidelik is, word die res van die omgewing gewoonlik baie makliker om te ontleed.

## Runtime Vulnerabilities

Nie elke container-escape kom van operator-misconfiguration nie. Soms is die runtime self die vulnerable component. Dit is belangrik omdat 'n workload met wat na 'n versigtige configuration lyk, steeds deur 'n low-level runtime-flaw blootgestel kan word.

Die klassieke voorbeeld is **CVE-2019-5736** in `runc`, waar 'n malicious container die host se `runc`-binary kon overwrite en dan wag vir 'n latere `docker exec` of soortgelyke runtime-invocation om attacker-controlled code te trigger. Die exploit path verskil baie van 'n eenvoudige bind-mount- of capability-mistake omdat dit misbruik maak van hoe die runtime tydens exec-handling weer die container-process-space betree.<sup>[[1]](#references)</sup>

'n Minimal reproduction workflow vanuit 'n red-team-perspektief is:
```bash
go build main.go
./main
```
Dan, vanaf die host:
```bash
docker exec -it <container-name> /bin/sh
```
Die belangrikste les is nie die presiese historiese exploit-implementering nie, maar die assesseringsimplikasie: as die runtime-weergawe kwesbaar is, kan gewone code execution binne die container genoeg wees om die host te compromise, selfs wanneer die sigbare container-konfigurasie nie ooglopend swak lyk nie.

Onlangse runtime-CVE's soos `CVE-2024-21626` in `runc`, BuildKit mount races en containerd parsing-foute versterk dieselfde punt. Runtime-weergawe en patch-vlak is deel van die security boundary, nie bloot onderhoudsbesonderhede nie.

## Verwysings

- [1] [Breaking out of Docker via runC – Explaining CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)

{{#include ../../../banners/hacktricks-training.md}}
