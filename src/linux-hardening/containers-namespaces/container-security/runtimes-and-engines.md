# Container Runtimes, Engines, Builders, En Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Een van die grootste bronne van verwarring in container security is dat verskeie heeltemal verskillende komponente dikwels onder dieselfde woord saamgevat word. "Docker" kan na ’n image format, ’n CLI, ’n daemon, ’n build system, ’n runtime stack of bloot die algemene idee van containers verwys. Vir security-werk is hierdie dubbelsinnigheid ’n probleem, omdat verskillende lae vir verskillende protections verantwoordelik is. ’n Breakout wat deur ’n slegte bind mount veroorsaak word, is nie dieselfde as ’n breakout wat deur ’n low-level runtime bug veroorsaak word nie, en nie een van die twee is dieselfde as ’n cluster policy-fout in Kubernetes nie.

Hierdie bladsy skei die ecosystem volgens rol, sodat die res van die section presies kan bespreek waar ’n protection of weakness werklik geleë is.

## OCI As The Common Language

Moderne Linux container stacks kan dikwels met mekaar interoperate omdat hulle ’n stel OCI specifications praat. Die **OCI Image Specification** beskryf hoe images en layers voorgestel word. Die **OCI Runtime Specification** beskryf hoe die runtime die process moet launch, insluitend namespaces, mounts, cgroups en security settings. Die **OCI Distribution Specification** standardiseer hoe registries content beskikbaar stel.

Dit is belangrik omdat dit verduidelik waarom ’n container image wat met een tool gebou is, dikwels met ’n ander tool run kan word, en waarom verskeie engines dieselfde low-level runtime kan deel. Dit verduidelik ook waarom security behavior soortgelyk oor verskillende products kan lyk: baie van hulle bou dieselfde OCI runtime configuration en gee dit aan dieselfde klein stel runtimes.

## Low-Level OCI Runtimes

Die low-level runtime is die component wat die naaste aan die kernel boundary is. Dit is die deel wat namespaces werklik create, cgroup settings skryf, capabilities en seccomp filters toepas, en uiteindelik die container process met `execve()` uitvoer. Wanneer mense "container isolation" op die meganiese vlak bespreek, praat hulle gewoonlik oor hierdie layer, selfs al sê hulle dit nie eksplisiet nie.

### `runc`

`runc` is die reference OCI runtime en bly die bekendste implementation. Dit word wyd onder Docker, containerd en baie Kubernetes deployments gebruik. Baie public research en exploitation-materiale teiken `runc`-style environments bloot omdat hulle algemeen voorkom en omdat `runc` die baseline definieer waaraan baie mense dink wanneer hulle ’n Linux container voorstel. Om `runc` te verstaan, gee ’n leser dus ’n sterk mental model van klassieke container isolation.

### `crun`

`crun` is nog ’n OCI runtime, geskryf in C en wyd gebruik in moderne Podman environments. Dit word dikwels geprys vir goeie cgroup v2 support, sterk rootless ergonomics en laer overhead. Vanuit ’n security-perspektief is die belangrike punt nie dat dit in ’n ander language geskryf is nie, maar dat dit steeds dieselfde rol speel: dit is die component wat die OCI configuration in ’n running process tree onder die kernel omskakel. ’n Rootless Podman workflow voel dikwels veiliger, nie omdat `crun` alles magies fix nie, maar omdat die algehele stack daaromheen geneig is om sterker op user namespaces en least privilege te steun.

### `runsc` From gVisor

`runsc` is die runtime wat deur gVisor gebruik word. Hier verander die boundary betekenisvol. In plaas daarvan om die meeste syscalls op die gewone manier direk aan die host kernel deur te gee, voeg gVisor ’n userspace kernel layer in wat groot dele van die Linux interface emuleer of medieer. Die resultaat is nie ’n normale `runc` container met ’n paar ekstra flags nie; dit is ’n ander sandbox design met die doel om host-kernel attack surface te verminder. Compatibility- en performance-tradeoffs vorm deel van daardie design, en environments wat `runsc` gebruik, behoort anders as normale OCI runtime environments gedokumenteer te word.

### `kata-runtime`

Kata Containers skuif die boundary verder deur die workload binne ’n lightweight virtual machine te launch. Administratief kan dit steeds soos ’n container deployment lyk, en orchestration layers kan dit steeds as sodanig behandel, maar die onderliggende isolation boundary is nader aan virtualization as aan ’n klassieke host-kernel-shared container. Dit maak Kata nuttig wanneer sterker tenant isolation verlang word sonder om container-centric workflows te laat vaar.

## Engines And Container Managers

As die low-level runtime die component is wat direk met die kernel praat, is die engine of manager die component waarmee users en operators gewoonlik interaksie het. Dit hanteer image pulls, metadata, logs, networks, volumes, lifecycle operations en API exposure. Hierdie layer is uiters belangrik omdat baie real-world compromises hier plaasvind: toegang tot ’n runtime socket of daemon API kan gelykstaande wees aan host compromise, selfs al is die low-level runtime self heeltemal gesond.

### Docker Engine

Docker Engine is die mees herkenbare container platform vir developers en een van die redes waarom container vocabulary so Docker-vormig geword het. Die tipiese pad is `docker` CLI na `dockerd`, wat op sy beurt lower-level components soos `containerd` en ’n OCI runtime koördineer. Histories was Docker deployments dikwels **rootful**, en toegang tot die Docker socket was gevolglik ’n baie kragtige primitive. Dit is waarom soveel praktiese privilege-escalation materiaal op `docker.sock` fokus: as ’n process vir `dockerd` kan vra om ’n privileged container te create, host paths te mount of by host namespaces aan te sluit, het dit dalk glad nie ’n kernel exploit nodig nie.

### Podman

Podman is rondom ’n meer daemonless model ontwerp. Operasioneel help dit om die idee te versterk dat containers bloot processes is wat deur standaard Linux mechanisms bestuur word, eerder as deur een langdurige privileged daemon. Podman het ook ’n veel sterker **rootless** story as die klassieke Docker deployments waarmee baie mense aanvanklik geleer het. Dit maak Podman nie outomaties veilig nie, maar dit verander die default risk profile aansienlik, veral wanneer dit met user namespaces, SELinux en `crun` gekombineer word.

### containerd

containerd is ’n core runtime management component in baie moderne stacks. Dit word onder Docker gebruik en is ook een van die dominante Kubernetes runtime backends. Dit stel powerful APIs beskikbaar, bestuur images en snapshots, en delegeer die finale process creation aan ’n low-level runtime. Security discussions oor containerd behoort te beklemtoon dat toegang tot die containerd socket of `ctr`/`nerdctl` functionality net so gevaarlik kan wees soos toegang tot Docker se API, selfs al voel die interface en workflow minder "developer friendly".

### CRI-O

CRI-O is meer gefokus as Docker Engine. In plaas daarvan om ’n general-purpose developer platform te wees, is dit gebou rondom die skoon implementering van die Kubernetes Container Runtime Interface. Dit maak dit veral algemeen in Kubernetes distributions en SELinux-heavy ecosystems soos OpenShift. Vanuit ’n security-perspektief is daardie nouer scope nuttig omdat dit conceptual clutter verminder: CRI-O is baie duidelik deel van die "run containers for Kubernetes"-layer eerder as ’n everything-platform.

### Incus, LXD, And LXC

Incus/LXD/LXC systems verdien om van Docker-style application containers geskei te word omdat hulle dikwels as **system containers** gebruik word. Daar word gewoonlik van ’n system container verwag om meer soos ’n lightweight machine te lyk, met ’n vollediger userspace, long-running services, ryker device exposure en meer uitgebreide host integration. Die isolation mechanisms is steeds kernel primitives, maar die operational expectations verskil. As gevolg hiervan lyk misconfigurations hier dikwels minder soos "bad app-container defaults" en meer soos foute in lightweight virtualization of host delegation.

### systemd-nspawn

systemd-nspawn beklee ’n interessante plek omdat dit systemd-native is en baie nuttig is vir testing, debugging en die run van OS-like environments. Dit is nie die dominante cloud-native production runtime nie, maar dit verskyn gereeld genoeg in labs en distro-georiënteerde environments dat dit vermelding verdien. Vir security analysis is dit nog ’n herinnering dat die concept "container" oor verskeie ecosystems en operational styles strek.

### Apptainer / Singularity

Apptainer (voorheen Singularity) is algemeen in research- en HPC-environments. Sy trust assumptions, user workflow en execution model verskil op belangrike maniere van Docker/Kubernetes-centric stacks. In besonder gee hierdie environments dikwels baie om daaroor om users packaged workloads te laat run sonder om aan hulle breë privileged container-management powers te gee. As ’n reviewer aanvaar dat elke container environment basies "Docker on a server" is, sal hulle hierdie deployments ernstig verkeerd verstaan.

## Build-Time Tooling

Baie security discussions praat slegs oor run time, maar build-time tooling is ook belangrik omdat dit image contents, build secrets exposure en die hoeveelheid trusted context wat in die finale artifact ingebed word, bepaal.

**BuildKit** en `docker buildx` is moderne build backends wat features soos caching, secret mounting, SSH forwarding en multi-platform builds ondersteun. Dit is nuttige features, maar vanuit ’n security-perspektief skep dit ook plekke waar secrets in image layers kan leak of waar ’n overly broad build context files kan expose wat nooit ingesluit moes gewees het nie. **Buildah** speel ’n soortgelyke rol in OCI-native ecosystems, veral rondom Podman, terwyl **Kaniko** dikwels in CI environments gebruik word wat nie ’n privileged Docker daemon aan die build pipeline wil verleen nie.

Die belangrikste les is dat image creation en image execution verskillende phases is, maar dat ’n swak build pipeline ’n swak runtime posture kan create lank voordat die container gelauch word.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes behoort nie verstandelik met die runtime self gelykgestel te word nie. Kubernetes is die orchestrator. Dit schedule Pods, stoor desired state en druk security policy deur workload configuration uit. Die kubelet praat dan met ’n CRI implementation soos containerd of CRI-O, wat op sy beurt ’n low-level runtime soos `runc`, `crun`, `runsc` of `kata-runtime` invoke.

Hierdie skeiding is belangrik omdat baie mense verkeerdelik ’n protection aan "Kubernetes" toeskryf wanneer dit eintlik deur die node runtime enforced word, of "containerd defaults" blameer vir behavior wat uit ’n Pod spec gekom het. In praktyk is die finale security posture ’n composition: die orchestrator vra vir iets, die runtime stack translateer dit, en die kernel enforceer dit uiteindelik.

## Why Runtime Identification Matters During Assessment

As jy die engine en runtime vroeg identifiseer, word baie latere observations makliker om te interpreteer. ’n Rootless Podman container dui daarop dat user namespaces waarskynlik deel van die storie is. ’n Docker socket wat in ’n workload gemount is, dui daarop dat API-driven privilege escalation ’n realistiese path is. ’n CRI-O/OpenShift node behoort jou onmiddellik aan SELinux labels en restricted workload policy te laat dink. ’n gVisor- of Kata-environment behoort jou versigtiger te maak om te aanvaar dat ’n klassieke `runc` breakout PoC dieselfde sal optree.

Daarom behoort een van die eerste steps in container assessment altyd te wees om twee eenvoudige vrae te beantwoord: **watter component bestuur die container** en **watter runtime het die process werklik gelaunch**. Sodra daardie antwoorde duidelik is, word die res van die environment gewoonlik baie makliker om te reason.

## Runtime Vulnerabilities

Nie elke container escape kom van operator misconfiguration nie. Soms is die runtime self die vulnerable component. Dit is belangrik omdat ’n workload met ’n configuration wat versigtig lyk, steeds deur ’n low-level runtime flaw blootgestel kan wees.

Die klassieke example is **CVE-2019-5736** in `runc`, waar ’n malicious container die host se `runc` binary kon overwrite en dan vir ’n latere `docker exec` of soortgelyke runtime invocation kon wag om attacker-controlled code te trigger. Die exploit path verskil baie van ’n eenvoudige bind-mount- of capability-mistake omdat dit misbruik maak van hoe die runtime tydens exec handling weer die container process space binnegaan.

’n Minimal reproduction workflow vanuit ’n red-team-perspektief is:
```bash
go build main.go
./main
```
Dan, vanaf die host:
```bash
docker exec -it <container-name> /bin/sh
```
Die belangrikste les is nie die presiese historiese implementering van die exploit nie, maar die assesseringsimplikasie: indien die runtime-weergawe kwesbaar is, kan gewone kode-uitvoering binne die container genoeg wees om die host te kompromitteer, selfs wanneer die sigbare container-konfigurasie nie ooglopend swak lyk nie.

Onlangse runtime-CVE's, soos `CVE-2024-21626` in `runc`, BuildKit-mount-races en containerd-ontleedfoute, beklemtoon dieselfde punt. Die runtime-weergawe en patch-vlak vorm deel van die sekuriteitsgrens, nie bloot onderhoudsbesonderhede nie.
{{#include ../../../banners/hacktricks-training.md}}
