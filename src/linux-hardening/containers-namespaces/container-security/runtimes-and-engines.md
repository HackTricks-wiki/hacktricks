# Container-runtimes, -enjins, -bouers en -sandkaste

{{#include ../../../banners/hacktricks-training.md}}

Een van die grootste bronne van verwarring in container-sekuriteit is dat verskeie heeltemal verskillende komponente dikwels tot dieselfde woord gereduseer word. "Docker" kan na 'n image-formaat, 'n CLI, 'n daemon, 'n boustelsel, 'n runtime-stack of eenvoudig die algemene idee van containers verwys. Vir sekuriteitswerk is daardie dubbelsinnigheid 'n probleem, omdat verskillende lae vir verskillende beskermings verantwoordelik is. 'n Breakout wat deur 'n swak bind mount veroorsaak word, is nie dieselfde as 'n breakout wat deur 'n low-level runtime-bug veroorsaak word nie, en nie een van dié is dieselfde as 'n cluster-policy-fout in Kubernetes nie.

Hierdie bladsy skei die ecosystem volgens rol, sodat die res van die afdeling presies kan aandui waar 'n beskerming of swakheid werklik voorkom.

## OCI As Die Gemeenskaplike Taal

Moderne Linux-container-stacks kan dikwels interoperereer omdat hulle 'n stel OCI-spesifikasies gebruik. Die **OCI Image Specification** beskryf hoe images en lae voorgestel word. Die **OCI Runtime Specification** beskryf hoe die runtime die proses moet begin, insluitend namespaces, mounts, cgroups en sekuriteitsinstellings. Die **OCI Distribution Specification** standardiseer hoe registries inhoud beskikbaar stel.

Dit is belangrik omdat dit verduidelik waarom 'n container image wat met een tool gebou is, dikwels met 'n ander tool uitgevoer kan word, en waarom verskeie engines dieselfde low-level runtime kan deel. Dit verduidelik ook waarom sekuriteitsgedrag soortgelyk oor verskillende produkte kan lyk: baie daarvan stel dieselfde OCI-runtime-konfigurasie saam en gee dit aan dieselfde klein stel runtimes.

## Low-Level OCI Runtimes

Die low-level runtime is die komponent wat die naaste aan die kernel-grens is. Dit is die deel wat werklik namespaces skep, cgroup-instellings skryf, capabilities en seccomp-filters toepas, en uiteindelik die container-proses met `execve()` uitvoer. Wanneer mense "container isolation" op meganiese vlak bespreek, praat hulle gewoonlik oor hierdie laag, selfs al sê hulle dit nie uitdruklik nie.

### `runc`

`runc` is die verwysings-OCI-runtime en bly die bekendste implementering. Dit word wyd onder Docker, containerd en baie Kubernetes-deployments gebruik. Baie openbare navorsing en exploitation-materiaal teiken `runc`-style omgewings bloot omdat hulle algemeen voorkom en omdat `runc` die basislyn definieer waaraan baie mense dink wanneer hulle 'n Linux-container voorstel. Om `runc` te verstaan, gee 'n leser dus 'n sterk mentale model vir klassieke container-isolation.

### `crun`

`crun` is nog 'n OCI-runtime, geskryf in C en wyd gebruik in moderne Podman-omgewings. Dit word dikwels geprys vir goeie cgroup v2-ondersteuning, sterk rootless-ergonomie en laer overhead. Vanuit 'n sekuriteitsperspektief is die belangrike punt nie dat dit in 'n ander taal geskryf is nie, maar dat dit steeds dieselfde rol speel: dit is die komponent wat die OCI-konfigurasie in 'n lopende prosesboom onder die kernel omskep. 'n Rootless Podman-workflow voel dikwels veiliger, nie omdat `crun` alles op magiese wyse regmaak nie, maar omdat die algehele stack daaromheen geneig is om sterker op user namespaces en least privilege te steun.

### `runsc` Vanaf gVisor

`runsc` is die runtime wat deur gVisor gebruik word. Hier verander die grens betekenisvol. In plaas daarvan om die meeste syscalls op die gewone manier direk aan die host-kernel deur te gee, plaas gVisor 'n userspace-kernel-laag in wat groot dele van die Linux-interface emuleer of bemiddel. Die resultaat is nie 'n normale `runc`-container met 'n paar ekstra flags nie; dit is 'n ander sandbox-ontwerp met die doel om die host-kernel se attack surface te verminder. Verenigbaarheid- en werkverrigting-afwegings vorm deel van daardie ontwerp, dus moet omgewings wat `runsc` gebruik, anders as normale OCI-runtime-omgewings gedokumenteer word.

### `kata-runtime`

Kata Containers verskuif die grens verder deur die workload binne 'n lightweight virtual machine te begin. Administratief kan dit steeds soos 'n container-deployment lyk, en orchestration-lae kan dit steeds as sodanig hanteer, maar die onderliggende isolation-grens is nader aan virtualization as aan 'n klassieke container wat die host-kernel deel. Dit maak Kata nuttig wanneer sterker tenant-isolation verlang word sonder om container-gesentreerde workflows te laat vaar.

## Engines En Container Managers

As die low-level runtime die komponent is wat direk met die kernel praat, is die engine of manager die komponent waarmee gebruikers en operators gewoonlik werk. Dit hanteer image-pulls, metadata, logs, netwerke, volumes, lifecycle-operasies en API-blootstelling. Hierdie laag is uiters belangrik omdat baie kompromitterings in die werklike wêreld hier plaasvind: toegang tot 'n runtime-socket of daemon-API kan gelykstaande wees aan host-kompromittering, selfs al is die low-level runtime self heeltemal gesond.

### Docker Engine

Docker Engine is die mees herkenbare container-platform vir developers en een van die redes waarom container-woordeskat so Docker-vormig geword het. Die tipiese pad is `docker` CLI na `dockerd`, wat op sy beurt laer-vlak-komponente soos `containerd` en 'n OCI-runtime koördineer. Histories was Docker-deployments dikwels **rootful**, en toegang tot die Docker-socket was gevolglik 'n baie kragtige primitive. Daarom fokus soveel praktiese privilege-escalation-materiaal op `docker.sock`: as 'n proses `dockerd` kan vra om 'n privileged container te skep, host-paaie te mount of by host-namespaces aan te sluit, het dit moontlik glad nie 'n kernel-exploit nodig nie.

### Podman

Podman is rondom 'n meer daemonless-model ontwerp. Operasioneel help dit om die idee te versterk dat containers bloot prosesse is wat deur standaard Linux-meganismes bestuur word, eerder as deur een langdurige privileged daemon. Podman het ook 'n veel sterker **rootless**-benadering as die klassieke Docker-deployments waarmee baie mense aanvanklik geleer het. Dit maak Podman nie outomaties veilig nie, maar dit verander die verstek-risikoprofiel betekenisvol, veral wanneer dit met user namespaces, SELinux en `crun` gekombineer word.

### containerd

containerd is 'n kern-runtime-bestuurskomponent in baie moderne stacks. Dit word onder Docker gebruik en is ook een van die dominante Kubernetes-runtime-backends. Dit stel kragtige APIs bloot, bestuur images en snapshots, en delegeer die finale prosesskepping aan 'n low-level runtime. Sekuriteitsbesprekings oor containerd moet beklemtoon dat toegang tot die containerd-socket of `ctr`/`nerdctl`-funksionaliteit net so gevaarlik kan wees as toegang tot Docker se API, selfs al voel die interface en workflow minder "developer friendly".

### CRI-O

CRI-O is meer gefokus as Docker Engine. In plaas daarvan om 'n algemene developer-platform te wees, is dit gebou rondom die skoon implementering van die Kubernetes Container Runtime Interface. Dit maak dit besonder algemeen in Kubernetes-distributions en SELinux-swaar ecosystems soos OpenShift. Vanuit 'n sekuriteitsperspektief is daardie nouer omvang nuttig omdat dit konseptuele rommel verminder: CRI-O is baie duidelik deel van die "run containers for Kubernetes"-laag eerder as 'n alles-platform.

### Incus, LXD En LXC

Incus/LXD/LXC-stelsels is die moeite werd om van Docker-style application containers te onderskei omdat hulle dikwels as **system containers** gebruik word. Daar word gewoonlik verwag dat 'n system container meer soos 'n lightweight machine lyk, met 'n vollediger userspace, langdurige services, ryker device-blootstelling en meer uitgebreide host-integrasie. Die isolation-meganismes is steeds kernel-primitives, maar die operasionele verwagtinge verskil. Gevolglik lyk misconfigurations hier dikwels minder soos "bad app-container defaults" en meer soos foute in lightweight virtualization of host-delegation.

### systemd-nspawn

systemd-nspawn beklee 'n interessante plek omdat dit systemd-native is en baie nuttig is vir testing, debugging en die uitvoering van OS-agtige omgewings. Dit is nie die dominante cloud-native production-runtime nie, maar dit kom gereeld genoeg in labs en distro-georiënteerde omgewings voor om vermelding te verdien. Vir sekuriteitsanalise is dit nog 'n herinnering dat die konsep "container" oor verskeie ecosystems en operasionele style strek.

### Apptainer / Singularity

Apptainer (voorheen Singularity) is algemeen in research- en HPC-omgewings. Die trust assumptions, gebruikersworkflow en execution model daarvan verskil op belangrike maniere van Docker/Kubernetes-gesentreerde stacks. Hierdie omgewings gee veral dikwels baie aandag daaraan om gebruikers packaged workloads te laat uitvoer sonder om aan hulle breë privileged container-management-vermoëns te gee. As 'n reviewer aanvaar dat elke container-omgewing basies "Docker op 'n server" is, sal hulle hierdie deployments ernstig verkeerd verstaan.

## Build-Time Tooling

Baie sekuriteitsbesprekings praat slegs oor run time, maar build-time tooling is ook belangrik omdat dit image-inhoud, blootstelling van build-secrets en hoeveel trusted context in die finale artifact ingebed word, bepaal.

**BuildKit** en `docker buildx` is moderne build-backends wat features soos caching, secret-mounting, SSH-forwarding en multi-platform builds ondersteun. Dit is nuttige features, maar vanuit 'n sekuriteitsperspektief skep hulle ook plekke waar secrets in image-layers kan leak of waar 'n te breë build-context lêers kan blootstel wat nooit ingesluit moes gewees het nie. **Buildah** speel 'n soortgelyke rol in OCI-native ecosystems, veral rondom Podman, terwyl **Kaniko** dikwels in CI-omgewings gebruik word wat nie 'n privileged Docker-daemon aan die build-pipeline wil toestaan nie.

Die kernles is dat image-creation en image-execution verskillende fases is, maar dat 'n swak build-pipeline 'n swak runtime-postuur kan skep lank voordat die container begin word.

## Orchestration Is Nog 'n Laag, Nie Die Runtime Nie

Kubernetes moet nie verstandelik met die runtime self gelykgestel word nie. Kubernetes is die orchestrator. Dit schedule Pods, stoor desired state en druk security policy deur workload-konfigurasie uit. Die kubelet praat dan met 'n CRI-implementering soos containerd of CRI-O, wat op sy beurt 'n low-level runtime soos `runc`, `crun`, `runsc` of `kata-runtime aanroep.

Hierdie skeiding is belangrik omdat baie mense verkeerdelik 'n beskerming aan "Kubernetes" toeskryf wanneer dit eintlik deur die node-runtime afgedwing word, of "containerd-defaults" blameer vir gedrag wat uit 'n Pod-spec gekom het. In die praktyk is die finale sekuriteitspostuur 'n samestelling: die orchestrator vra vir iets, die runtime-stack vertaal dit, en die kernel dwing dit uiteindelik af.

## Waarom Runtime-Identifikasie Tydens Assessering Belangrik Is

As jy die engine en runtime vroeg identifiseer, word baie latere waarnemings makliker om te interpreteer. 'n Rootless Podman-container dui daarop dat user namespaces waarskynlik deel van die storie is. 'n Docker-socket wat in 'n workload gemount is, dui daarop dat API-gedrewe privilege escalation 'n realistiese pad is. 'n CRI-O/OpenShift-node behoort jou onmiddellik aan SELinux-labels en restricted-workload-policy te laat dink. 'n gVisor- of Kata-omgewing behoort jou versigtiger te maak om te aanvaar dat 'n klassieke `runc`-breakout-PoC dieselfde sal optree.

Daarom behoort een van die eerste stappe in container-assessment altyd te wees om twee eenvoudige vrae te beantwoord: **watter komponent bestuur die container** en **watter runtime het die proses werklik begin**. Sodra hierdie antwoorde duidelik is, word die res van die omgewing gewoonlik baie makliker om te verstaan.

## Runtime-Vulnerabilities

Nie elke container-escape spruit uit operator-misconfiguration nie. Soms is die runtime self die kwesbare komponent. Dit is belangrik omdat 'n workload met 'n versigtige konfigurasie kan loop en steeds deur 'n low-level runtime-flaw blootgestel kan wees.

Die klassieke voorbeeld is **CVE-2019-5736** in `runc`, waar 'n malicious container die host se `runc`-binary kon oorskryf en dan vir 'n latere `docker exec` of soortgelyke runtime-invocation kon wag om attacker-controlled code te trigger. Die exploit-pad verskil sterk van 'n eenvoudige bind-mount- of capability-fout omdat dit misbruik maak van hoe die runtime tydens exec-handling weer die container se process-space betree.<sup>[[1]](#references)</sup>

'n Minimal reproduction-workflow vanuit 'n red-team-perspektief is:
```bash
go build main.go
./main
```
Dan, vanaf die host:
```bash
docker exec -it <container-name> /bin/sh
```
Die belangrikste les is nie die presiese historiese exploit-implementering nie, maar die assesseringsimplikasie: indien die runtime-weergawe kwesbaar is, kan gewone kode-uitvoering binne die container genoeg wees om die host te kompromitteer, selfs wanneer die sigbare container-konfigurasie nie ooglopend swak lyk nie.

Onlangse runtime-CVE's soos `CVE-2024-21626` in `runc`, BuildKit mount races en containerd-parsingsfoute versterk dieselfde punt. Die runtime-weergawe en patch-vlak vorm deel van die sekuriteitsgrens, nie bloot onderhoudsbesonderhede nie.

## References

- [1] [Uitbreek uit Docker via runC – Verduideliking van CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
