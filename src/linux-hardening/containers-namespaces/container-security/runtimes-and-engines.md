# Container Runtimes, Engines, Builders, En Sandboxes

Een van die grootste bronne van verwarring in container security is dat verskeie heeltemal verskillende komponente dikwels onder dieselfde woord saamgevat word. "Docker" kan na 'n image format, 'n CLI, 'n daemon, 'n build system, 'n runtime stack, of bloot die algemene idee van containers verwys. Vir security-werk is daardie dubbelsinnigheid 'n probleem, omdat verskillende lae vir verskillende protections verantwoordelik is. 'n Breakout wat deur 'n verkeerde bind mount veroorsaak word, is nie dieselfde as 'n breakout wat deur 'n low-level runtime-bug veroorsaak word nie, en nie een van die twee is dieselfde as 'n cluster policy-fout in Kubernetes nie.

Hierdie bladsy skei die ecosystem volgens rol sodat die res van die afdeling presies kan bespreek waar 'n protection of weakness werklik geleë is.

## OCI As Die Algemene Taal

Moderne Linux container stacks kan dikwels met mekaar saamwerk omdat hulle 'n stel OCI specifications gebruik. Die **OCI Image Specification** beskryf hoe images en layers voorgestel word. Die **OCI Runtime Specification** beskryf hoe die runtime die process moet launch, insluitend namespaces, mounts, cgroups, en security settings. Die **OCI Distribution Specification** standaardiseer hoe registries content beskikbaar stel.

Dit is belangrik omdat dit verduidelik waarom 'n container image wat met een tool gebou is, dikwels met 'n ander een uitgevoer kan word, en waarom verskeie engines dieselfde low-level runtime kan deel. Dit verduidelik ook waarom security behaviour soortgelyk oor verskillende products kan lyk: baie van hulle bou dieselfde OCI runtime configuration en gee dit aan dieselfde klein stel runtimes.

## Low-Level OCI Runtimes

Die low-level runtime is die component wat die naaste aan die kernel boundary is. Dit is die deel wat werklik namespaces skep, cgroup settings skryf, capabilities en seccomp filters toepas, en uiteindelik die container process met `execve()` uitvoer. Wanneer mense "container isolation" op die meganiese vlak bespreek, praat hulle gewoonlik van hierdie laag, selfs al sê hulle dit nie uitdruklik nie.

### `runc`

`runc` is die reference OCI runtime en bly die bekendste implementation. Dit word baie onder Docker, containerd, en talle Kubernetes deployments gebruik. Baie public research en exploitation material teiken `runc`-style environments bloot omdat hulle algemeen voorkom en omdat `runc` die baseline definieer waaraan baie mense dink wanneer hulle 'n Linux container voorstel. Om `runc` te verstaan, gee 'n leser dus 'n sterk mental model vir klassieke container isolation.

### `crun`

`crun` is nog 'n OCI runtime, geskryf in C en wyd gebruik in moderne Podman environments. Dit word dikwels geprys vir goeie cgroup v2 support, sterk rootless ergonomics, en laer overhead. Vanuit 'n security-perspektief is die belangrike punt nie dat dit in 'n ander taal geskryf is nie, maar dat dit steeds dieselfde rol vervul: dit is die component wat die OCI configuration in 'n running process tree onder die kernel omskep. 'n Rootless Podman workflow voel dikwels veiliger, nie omdat `crun` alles magies regmaak nie, maar omdat die algehele stack daaromheen geneig is om sterker op user namespaces en least privilege te steun.

### `runsc` From gVisor

`runsc` is die runtime wat deur gVisor gebruik word. Hier verander die boundary betekenisvol. In plaas daarvan om die meeste syscalls gewoonlik direk aan die host kernel deur te gee, voeg gVisor 'n userspace kernel layer in wat groot dele van die Linux interface emuleer of medieer. Die resultaat is nie 'n normale `runc` container met 'n paar ekstra flags nie; dit is 'n ander sandbox design met die doel om die host-kernel attack surface te verminder. Compatibility- en performance tradeoffs vorm deel van daardie design, dus moet environments wat `runsc` gebruik anders as normale OCI runtime environments gedokumenteer word.

### `kata-runtime`

Kata Containers skuif die boundary verder deur die workload binne 'n lightweight virtual machine te launch. Administratief kan dit steeds soos 'n container deployment lyk, en orchestration layers kan dit steeds as sodanig behandel, maar die onderliggende isolation boundary is nader aan virtualization as aan 'n klassieke host-kernel-shared container. Dit maak Kata nuttig wanneer sterker tenant isolation verlang word sonder om container-gesentreerde workflows te laat vaar.

## Engines En Container Managers

As die low-level runtime die component is wat direk met die kernel praat, is die engine of manager die component waarmee users en operators gewoonlik interaksie het. Dit hanteer image pulls, metadata, logs, networks, volumes, lifecycle operations, en API exposure. Hierdie laag is uiters belangrik omdat baie compromises in die werklike wêreld hier plaasvind: toegang tot 'n runtime socket of daemon API kan gelykstaande wees aan host compromise, selfs al is die low-level runtime self heeltemal gesond.

### Docker Engine

Docker Engine is die mees herkenbare container platform vir developers en een van die redes waarom container vocabulary so Docker-agtig geword het. Die tipiese pad is `docker` CLI na `dockerd`, wat op sy beurt laer-vlak components soos `containerd` en 'n OCI runtime koördineer. Histories was Docker deployments dikwels **rootful**, en toegang tot die Docker socket was daarom 'n baie kragtige primitive. Dit is waarom soveel praktiese privilege-escalation material op `docker.sock` fokus: as 'n process vir `dockerd` kan vra om 'n privileged container te skep, host paths te mount, of by host namespaces aan te sluit, het dit dalk glad nie 'n kernel exploit nodig nie.

### Podman

Podman is rondom 'n meer daemonless model ontwerp. Operasioneel help dit om die idee te versterk dat containers bloot processes is wat deur standaard Linux mechanisms bestuur word, eerder as deur een langlewende privileged daemon. Podman het ook 'n veel sterker **rootless** story as die klassieke Docker deployments waarmee baie mense aanvanklik geleer het. Dit maak Podman nie outomaties veilig nie, maar dit verander die default risk profile aansienlik, veral wanneer dit met user namespaces, SELinux, en `crun` gekombineer word.

### containerd

containerd is 'n kern-runtime management component in baie moderne stacks. Dit word onder Docker gebruik en is ook een van die dominante Kubernetes runtime backends. Dit stel kragtige APIs beskikbaar, bestuur images en snapshots, en delegeer die finale process creation aan 'n low-level runtime. Security discussions rondom containerd moet beklemtoon dat toegang tot die containerd socket of `ctr`/`nerdctl` functionality net so gevaarlik kan wees soos toegang tot Docker se API, selfs al voel die interface en workflow minder "developer friendly".

### CRI-O

CRI-O is meer gefokus as Docker Engine. In plaas daarvan om 'n general-purpose developer platform te wees, is dit gebou rondom die skoon implementering van die Kubernetes Container Runtime Interface. Dit maak dit veral algemeen in Kubernetes distributions en SELinux-swaar ecosystems soos OpenShift. Vanuit 'n security-perspektief is daardie enger scope nuttig omdat dit konseptuele rommel verminder: CRI-O is baie duidelik deel van die "run containers for Kubernetes"-laag eerder as 'n everything-platform.

### Incus, LXD, En LXC

Incus/LXD/LXC systems verdien om van Docker-style application containers geskei te word omdat hulle dikwels as **system containers** gebruik word. Daar word gewoonlik van 'n system container verwag om meer soos 'n lightweight machine te lyk, met 'n vollediger userspace, langlopende services, ryker device exposure, en meer uitgebreide host integration. Die isolation mechanisms is steeds kernel primitives, maar die operasionele verwagtings verskil. Gevolglik lyk misconfigurations hier dikwels minder soos "bad app-container defaults" en meer soos foute in lightweight virtualization of host delegation.

### systemd-nspawn

systemd-nspawn beklee 'n interessante plek omdat dit systemd-native is en baie nuttig is vir testing, debugging, en die uitvoer van OS-like environments. Dit is nie die dominante cloud-native production runtime nie, maar dit kom gereeld genoeg in labs en distro-georiënteerde environments voor dat dit vermelding verdien. Vir security analysis is dit nog 'n herinnering dat die konsep "container" oor verskeie ecosystems en operasionele styles strek.

### Apptainer / Singularity

Apptainer (voorheen Singularity) is algemeen in research- en HPC-environments. Sy trust assumptions, user workflow, en execution model verskil op belangrike maniere van Docker/Kubernetes-gesentreerde stacks. Hierdie environments gee veral dikwels baie om daarvoor om users toe te laat om packaged workloads uit te voer sonder om aan hulle breë privileged container-management powers te gee. As 'n reviewer aanvaar dat elke container environment basies "Docker on a server" is, sal hulle hierdie deployments ernstig verkeerd verstaan.

## Build-Time Tooling

Baie security discussions praat slegs oor run time, maar build-time tooling is ook belangrik omdat dit image contents, build secrets exposure, en hoeveel trusted context in die finale artifact ingebed word, bepaal.

**BuildKit** en `docker buildx` is moderne build backends wat features soos caching, secret mounting, SSH forwarding, en multi-platform builds ondersteun. Dit is nuttige features, maar vanuit 'n security-perspektief skep hulle ook plekke waar secrets in image layers kan leak of waar 'n te breë build context files kan blootstel wat nooit ingesluit moes gewees het nie. **Buildah** vervul 'n soortgelyke rol in OCI-native ecosystems, veral rondom Podman, terwyl **Kaniko** dikwels in CI environments gebruik word wat nie 'n privileged Docker daemon aan die build pipeline wil gee nie.

Die kernles is dat image creation en image execution verskillende phases is, maar 'n swak build pipeline kan 'n swak runtime posture skep lank voordat die container geloods word.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes moet nie geestelik met die runtime self gelykgestel word nie. Kubernetes is die orchestrator. Dit schedule Pods, stoor desired state, en druk security policy deur workload configuration uit. Die kubelet praat dan met 'n CRI implementation soos containerd of CRI-O, wat op sy beurt 'n low-level runtime soos `runc`, `crun`, `runsc`, of `kata-runtime` invoke.

Hierdie separation is belangrik omdat baie mense 'n protection verkeerdelik aan "Kubernetes" toeskryf terwyl dit eintlik deur die node runtime afgedwing word, of hulle blameer "containerd defaults" vir behaviour wat uit 'n Pod spec gekom het. In die praktyk is die finale security posture 'n composition: die orchestrator vra vir iets, die runtime stack vertaal dit, en die kernel dwing dit uiteindelik af.

## Why Runtime Identification Matters During Assessment

As jy die engine en runtime vroeg identifiseer, word baie latere observations makliker om te interpreteer. 'n Rootless Podman container dui daarop dat user namespaces waarskynlik deel van die storie is. 'n Docker socket wat in 'n workload gemount is, dui daarop dat API-driven privilege escalation 'n realistiese path is. 'n CRI-O/OpenShift node behoort jou onmiddellik aan SELinux labels en restricted workload policy te laat dink. 'n gVisor- of Kata-environment behoort jou versigtiger te maak om aan te neem dat 'n klassieke `runc` breakout PoC dieselfde sal optree.

Daarom behoort een van die eerste steps in container assessment altyd te wees om twee eenvoudige vrae te beantwoord: **watter component bestuur die container** en **watter runtime het die process werklik geloods**. Sodra daardie antwoorde duidelik is, word die res van die environment gewoonlik baie makliker om te reason.

## Runtime Vulnerabilities

Nie elke container escape kom van operator misconfiguration nie. Soms is die runtime self die vulnerable component. Dit is belangrik omdat 'n workload met 'n configuration wat versigtig lyk, steeds deur 'n low-level runtime flaw blootgestel kan wees.

Die klassieke voorbeeld is **CVE-2019-5736** in `runc`, waar 'n malicious container die host se `runc` binary kon oorskryf en daarna wag vir 'n latere `docker exec` of soortgelyke runtime invocation om attacker-controlled code te trigger. Die exploit path verskil baie van 'n eenvoudige bind-mount- of capability-mistake omdat dit misbruik maak van hoe die runtime die container process space weer betree tydens exec handling.<sup>[[1]](#references)</sup>

'n Minimal reproduction workflow vanuit 'n red-team-perspektief is:
```bash
go build main.go
./main
```
Dan, vanaf die host:
```bash
docker exec -it <container-name> /bin/sh
```
Die sleutelles is nie die presiese historiese exploit-implementering nie, maar die assesseringsimplikasie: as die runtime-weergawe kwesbaar is, kan gewone code execution binne die container genoeg wees om die host te kompromitteer, selfs wanneer die sigbare container-konfigurasie nie ooglopend swak lyk nie.

Onlangse runtime-CVE's soos `CVE-2024-21626` in `runc`, BuildKit mount races en containerd parsing bugs versterk dieselfde punt. Die runtime-weergawe en patchvlak is deel van die security boundary, nie bloot onderhoudsbesonderhede nie.

## References

- [1] [Breaking out of Docker via runC – Explaining CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
