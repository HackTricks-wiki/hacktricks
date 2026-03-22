# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Een van die grootste bronne van verwarring in container security is dat verskeie heeltemal verskillende komponente dikwels in dieselfde woord saamgevat word. "Docker" kan na 'n image format, 'n CLI, 'n daemon, 'n build system, 'n runtime stack, of eenvoudig die idee van containers in die algemeen verwys. Vir sekuriteitswerk is daardie ambigue betekenis 'n probleem, want verskillende lae is verantwoordelik vir verskillende beskermings. 'n Breakout veroorsaak deur 'n slegte bind mount is nie dieselfde as 'n breakout veroorsaak deur 'n laagvlak runtime-bug nie, en geen van beide is dieselfde as 'n cluster policy-fout in Kubernetes nie.

Hierdie bladsy skei die ekosisteem per rol sodat die res van die afdeling presies kan praat oor waar 'n beskerming of swakpunt werklik lê.

## OCI As The Common Language

Moderne Linux container stacks werk dikwels saam omdat hulle 'n stel OCI specifications praat. Die **OCI Image Specification** beskryf hoe images en layers voorgestel word. Die **OCI Runtime Specification** beskryf hoe die runtime die proses moet begin, insluitend namespaces, mounts, cgroups, en security settings. Die **OCI Distribution Specification** standaardiseer hoe registries inhoud blootstel.

Dit maak saak omdat dit verduidelik waarom 'n container image wat met een tool gebou is dikwels met 'n ander uitgevoer kan word, en waarom verskeie engines dieselfde laagvlak runtime kan deel. Dit verduidelik ook waarom sekuriteitsgedrag oor verskillende produkte heen soortgelyk kan lyk: baie van hulle bou dieselfde OCI runtime-konfigurasie en gee dit aan dieselfde klein stel runtimes.

## Low-Level OCI Runtimes

Die laagvlak runtime is die komponent wat die naaste aan die kernel-grens is. Dit is die deel wat eintlik namespaces skep, cgroup-instellings skryf, capabilities en seccomp filters toepas, en uiteindelik die proses `execve()`er. Wanneer mense oor "container isolation" op die meganiese vlak praat, is dit gewoonlik hierdie laag waarna hulle verwys, selfs al sê hulle dit nie eksplisiet nie.

### `runc`

`runc` is die verwysings-OCI runtime en bly die bekendste implementering. Dit word wyd gebruik onder Docker, containerd, en baie Kubernetes deployments. Baie openbare navorsing en exploitasie-materiaal mik op `runc`-styl omgewings bloot omdat hulle algemeen is en omdat `runc` die basislyn definieer waaraan baie mense dink wanneer hulle 'n Linux container voorstel. Om `runc` te verstaan gee dus 'n leser 'n sterk geestelike model vir klassieke container isolation.

### `crun`

`crun` is nog 'n OCI runtime, geskryf in C en wyd gebruik in moderne Podman-omgewings. Dit word dikwels geprys vir goeie cgroup v2 ondersteuning, sterk rootless ergonomie, en laer overhead. Vanuit 'n sekuriteitsperspektief is die belangrike punt nie dat dit in 'n ander taal geskryf is nie, maar dat dit steeds dieselfde rol speel: dit is die komponent wat die OCI-konfigurasie in 'n lopende prosesboom onder die kernel omskakel. 'n Rootless Podman-werkvloei voel dikwels veiliger nie omdat `crun` alles magies regstel nie, maar omdat die algehele stack daaromheen geneig is om meer in user namespaces en least privilege te leun.

### `runsc` From gVisor

`runsc` is die runtime wat deur gVisor gebruik word. Hier verander die grens betekenisvol. In plaas daarvan om die meeste syscalls direk op die gewone manier aan die host kernel deur te gee, sit gVisor 'n userspace kernel-laag in wat groot dele van die Linux-koppelvlak emuleer of bemiddel. Die resultaat is nie 'n normale `runc` container met 'n paar ekstra flags nie; dit is 'n ander sandbox-ontwerp met die doel om die host-kernel attack surface te verminder. Kompatibiliteits- en prestasietradeoffs is deel van daardie ontwerp, dus moet omgewings wat `runsc` gebruik anders gedokumenteer word as normale OCI runtime-omgewings.

### `kata-runtime`

Kata Containers druk die grens verder deur die workload binne 'n liggewig virtual machine te begin. Administratief kan dit nog steeds soos 'n container deployment lyk, en orkestrasie-lae kan dit steeds so behandel, maar die onderliggende isolasie-grens is nader aan virtualisering as aan 'n klassieke host-kernel-gesharde container. Dit maak Kata nuttig wanneer sterker tenant isolation verlang word sonder om container-gesentreerde werkvloei te verlaat.

## Engines And Container Managers

As die laagvlak runtime die komponent is wat direk met die kernel praat, is die engine of manager die komponent waarmee gebruikers en operateurs gewoonlik interaksie het. Dit hanteer image pulls, metadata, logs, networks, volumes, lifecycle operations, en API exposure. Hierdie laag maak baie saak omdat baie werklike kompromitte hier gebeur: toegang tot 'n runtime socket of daemon API kan gelyk staan aan host compromise selfs al is die laagvlak runtime self perfek gesond.

### Docker Engine

Docker Engine is die mees herkenbare container platform vir ontwikkelaars en een van die redes hoekom container-woordeskat so Docker-vormig geword het. Die tipiese pad is `docker` CLI na `dockerd`, wat op sy beurt laervlak-komponente soos `containerd` en 'n OCI runtime koördineer. Histories was Docker deployments dikwels **rootful**, en toegang tot die Docker socket was dus 'n baie kragtige primitive. Dit is waarom soveel praktiese privilege-escalation materiaal gefokus is op `docker.sock`: as 'n proses `dockerd` kan vra om 'n privileged container te skep, host paths te mount, of host namespaces te join, mag dit nie 'n kernel exploit nodig hê nie.

### Podman

Podman is ontwerp rondom 'n meer daemonless model. Operasioneel help dit om die idee te versterk dat containers net prosesse is wat deur standaard Linux-meganismes bestuur word eerder as deur een langlewende geprivilegieerde daemon. Podman het ook 'n baie sterker **rootless** storie as die klassieke Docker deployments wat baie mense eerste geleer het. Dit maak Podman nie outomaties veilig nie, maar dit verander die standaard risikoprofiel betekenisvol, veral wanneer dit gekombineer word met user namespaces, SELinux, en `crun`.

### containerd

containerd is 'n kern runtime management komponent in baie moderne stacks. Dit word onder Docker gebruik en is ook een van die dominante Kubernetes runtime backends. Dit bied kragtige APIs, bestuur images en snapshots, en delegeer die finale proses-skepping aan 'n laagvlak runtime. Sekuriteitsbesprekings rondom containerd moet beklemtoon dat toegang tot die containerd socket of `ctr`/`nerdctl` funksionaliteit net so gevaarlik kan wees soos toegang tot Docker se API, selfs al voel die koppelvlak en werkvloei minder "developer friendly".

### CRI-O

CRI-O is meer gefokus as Docker Engine. In plaas daarvan om 'n algemene ontwikkelaarplatform te wees, is dit gebou om die Kubernetes Container Runtime Interface skoon te implementeer. Dit maak dit veral algemeen in Kubernetes-distributies en SELinux-gesentreerde ekosisteme soos OpenShift. Vanuit 'n sekuriteitsperspektief is daardie nouer omvang nuttig omdat dit konsepuele gemors verminder: CRI-O is baie deel van die "run containers for Kubernetes" laag eerder as 'n alles-in-een platform.

### Incus, LXD, And LXC

Incus/LXD/LXC-stelsels is die moeite werd om van Docker-styl applicasie-containers te skei omdat hulle dikwels as **system containers** gebruik word. 'n System container word gewoonlik verwag om meer soos 'n liggewig masjien te lyk met 'n voller userspace, langlopende dienste, ryker device exposure, en meer uitgebreide host-integrasie. Die isolasiemeganismes is steeds kernel-primitiewe, maar die operasionele verwagtinge is anders. Gevolglik lyk misconfigurations hier minder soos "slegte app-container defaults" en meer soos foute in liggewig virtualisering of host-delegasie.

### systemd-nspawn

systemd-nspawn beset 'n interessante plek omdat dit systemd-native is en baie nuttig vir testing, debugging, en die uitvoering van OS-agtige omgewings. Dit is nie die dominante cloud-native produksie-runtime nie, maar dit verskyn gereeld genoeg in labs en distro-gefokusde omgewings dat dit 'n vermelding verdien. Vir sekuriteitsanalise is dit nog 'n herinnering dat die konsep "container" oor verskeie ekosisteme en operasionele style strek.

### Apptainer / Singularity

Apptainer (voorheen Singularity) is algemeen in navorsing- en HPC-omgewings. Sy trust assumptions, user workflow, en uitvoeringmodel verskil op belangrike maniere van Docker/Kubernetes-gesentreerde stacks. In die besonder gee hierdie omgewings dikwels baie om om gebruikers toe te laat om gepakte workloads te hardloop sonder om hulle uitgebreide geprivilegieerde container-management magte te gee. As 'n beoordelaar aanneem elke container-omgewing is basies "Docker on a server", sal hulle hierdie deployments ernstig misverstaan.

## Build-Time Tooling

Baie sekuriteitsbesprekings praat slegs oor run time, maar build-time tooling maak ook saak omdat dit image-inhoud, blootstelling van build secrets, en hoeveel vertroude konteks in die finale artefak ingebed word bepaal.

**BuildKit** en `docker buildx` is moderne build backends wat kenmerke soos caching, secret mounting, SSH forwarding, en multi-platform builds ondersteun. Dit is nuttige funksies, maar vanuit 'n sekuriteitsperspektief skep hulle ook plekke waar secrets kan leak in image layers of waar 'n te breë build context lêers kan blootstel wat nooit ingesluit moes wees nie. **Buildah** speel 'n soortgelyke rol in OCI-native ekosisteme, veral rondom Podman, terwyl **Kaniko** dikwels in CI-omgewings gebruik word wat nie 'n geprivilegieerde Docker daemon aan die build-pipeline wil gee nie.

Die sleutel-les is dat image creation en image execution verskillende fases is, maar 'n swak build-pipeline 'n swak runtime-houding lank voor die container se lansering kan skep.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes moet nie sielkundig met die runtime self gelyk gestel word nie. Kubernetes is die orchestrator. Dit skeduleer Pods, stoor desired state, en druk security policy uit deur workload-konfigurasie. Die kubelet praat dan met 'n CRI implementering soos containerd of CRI-O, wat op sy beurt 'n laagvlak runtime soos `runc`, `crun`, `runsc`, of `kata-runtime` aanroep.

Hierdie skeiding maak saak omdat baie mense verkeerdelik 'n beskerming aan "Kubernetes" toeskryf wanneer dit werklik deur die node runtime afgedwing word, of hulle blameer "containerd defaults" vir gedrag wat uit 'n Pod spec gekom het. In praktyk is die finale sekuriteitshouding 'n komposisie: die orchestrator vra vir iets, die runtime stack vertaal dit, en die kernel handhaaf dit uiteindelik.

## Why Runtime Identification Matters During Assessment

As jy die engine en runtime vroeg identifiseer, raak baie latere waarnemings makliker om te interpreteer. 'n Rootless Podman container dui daarop dat user namespaces waarskynlik deel van die storie is. 'n Docker socket wat in 'n workload gemoun is dui daarop dat API-driven privilege escalation 'n realistiese pad is. 'n CRI-O/OpenShift node moet jou onmiddellik laat dink aan SELinux labels en restricted workload policy. 'n gVisor of Kata omgewing moet jou versigtiger maak om aan te neem dat 'n klassieke `runc` breakout PoC dieselfde sal optree.

Dit is hoekom een van die eerste stappe in container assessment altyd twee eenvoudige vrae beantwoord moet: **which component is managing the container** en **which runtime actually launched the process**. Sodra daardie antwoorde duidelik is, word die res van die omgewing gewoonlik baie makliker om oor na te dink.

## Runtime Vulnerabilities

Nie elke container escape kom van operateur-misconfigurasie nie. Soms is die runtime self die kwesbare komponent. Dit maak saak omdat 'n workload met wat soos 'n sorgvuldige konfigurasie lyk steeds blootgestel kan wees deur 'n laagvlak runtime-fout.

Die klassieke voorbeeld is **CVE-2019-5736** in `runc`, waar 'n kwaadwillige container die host `runc` binary kon oor-skryf en dan wag vir 'n later `docker exec` of soortgelyke runtime-aanroep om aanvallingsbeheer-kode te veroorsaak. Die eksploitpad is baie anders as 'n eenvoudige bind-mount of capability-fout omdat dit misbruik maak van hoe die runtime weer die container-prosesruimte binnegaan tydens exec-hantering.

'n Minimale reproduksie-werkvloei vanuit 'n red-team-perspektief is:
```bash
go build main.go
./main
```
Dan, vanaf die host:
```bash
docker exec -it <container-name> /bin/sh
```
Die kernles is nie die presiese historiese exploit-implementering nie, maar die assesseringsimplikasie: as die runtime-weergawe kwesbaar is, kan gewone in-container kode-uitvoering genoeg wees om die gasheer te kompromitteer, selfs wanneer die sigbare container-konfigurasie nie ooglopend swak lyk nie.

Onlangse runtime CVEs soos `CVE-2024-21626` in `runc`, BuildKit mount races, en containerd parsing bugs beklemtoon dieselfde punt. Runtime-weergawe en patchvlak is deel van die sekuriteitsgrens, nie bloot triviale onderhoudsake nie.
{{#include ../../../banners/hacktricks-training.md}}
