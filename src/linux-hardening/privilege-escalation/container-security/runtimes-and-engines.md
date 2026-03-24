# Kontainer-runtimes, enjins, bougereedskap en sandbokse

{{#include ../../../banners/hacktricks-training.md}}

Een van die grootste bronne van verwarring in kontainer-sekuriteit is dat verskeie heeltemal verskillende komponente dikwels in dieselfde woord saamgepers word. "Docker" kan verwys na 'n image-formaat, 'n CLI, 'n daemon, 'n boustelsel, 'n runtime-stapel, of bloot die idee van kontainers in die algemeen. Vir sekuriteitswerk is daardie tweesydigheid 'n probleem, want verskillende lae is verantwoordelik vir verskillende beskermings. 'n Breakout veroorsaak deur 'n slegte bind mount is nie dieselfde as 'n breakout veroorsaak deur 'n laagvlak runtime-bug nie, en geen van beide is dieselfde as 'n cluster-policy fout in Kubernetes nie.

Hierdie bladsy skei die ekosisteem volgens rol sodat die res van die afdeling presies kan praat oor waar 'n beskerming of swakheid eintlik leef.

## OCI As The Common Language

Moderne Linux-kontainer-stapels werk dikwels saam omdat hulle 'n stel OCI-spesifikasies praat. Die **OCI Image Specification** beskryf hoe images en lae voorgestel word. Die **OCI Runtime Specification** beskryf hoe die runtime die proses moet begin, insluitend namespaces, mounts, cgroups, en sekuriteitsinstellings. Die **OCI Distribution Specification** standaardiseer hoe registries inhoud blootstel.

Dit is belangrik omdat dit verduidelik waarom 'n kontainer-image gebou met een instrument dikwels met 'n ander uitgevoer kan word, en waarom verskeie enjins dieselfde laagvlak runtime kan deel. Dit verduidelik ook waarom sekuriteitsgedrag oor verskillende produkte heen soortgelyk kan lyk: baie van hulle bou dieselfde OCI runtime-konfigurasie en gee dit aan dieselfde klein stel runtimes.

## Low-Level OCI Runtimes

Die laagvlak runtime is die komponent wat die naaste aan die kernel-grens is. Dit is die deel wat eintlik namespaces skep, cgroup-instellings skryf, capabilities en seccomp-filters toepas, en uiteindelik die container-proses `execve()`-eer. Wanneer mense oor "container isolation" op die meganiese vlak praat, is dit gewoonlik hierdie laag waarna hulle verwys, selfs al sê hulle dit nie eksplisiet nie.

### `runc`

`runc` is die verwysings-OCI-runtime en bly die bekendste implementering. Dit word wyd gebruik onder Docker, containerd, en baie Kubernetes-implementasies. Baie publieke navorsing en eksploitasiemateriaal mik op `runc`-styl omgewings bloot omdat hulle algemeen is en omdat `runc` die basislyn definieer waaraan baie mense dink wanneer hulle 'n Linux-kontainer voorstel. Om `runc` te verstaan gee 'n leser dus 'n sterk verstandelike model vir klassieke kontainer-isolasie.

### `crun`

`crun` is 'n ander OCI-runtime, in C geskryf en wyd gebruik in moderne Podman-omgewings. Dit word dikwels geprys vir goeie cgroup v2-ondersteuning, sterk rootless ergonomika, en laer oorhoofse koste. Vanuit 'n sekuriteitsperspektief is die belangrike ding nie dat dit in 'n ander taal geskryf is nie, maar dat dit steeds dieselfde rol speel: dit is die komponent wat die OCI-konfigurasie omskakel in 'n lopende prosesboom onder die kernel. 'n Rootless Podman-werkvloei voel dikwels veiliger nie omdat `crun` alles magies regmaak nie, maar omdat die algehele stapel rondom dit geneig is om meer in user namespaces en minste-privilege te leun.

### `runsc` From gVisor

`runsc` is die runtime wat deur gVisor gebruik word. Hier verander die grens betekenisvol. In plaas daarvan om die meeste syscalls direk op die gewone manier na die gasheer-kernel te stuur, sit gVisor 'n userspace-kernel-laag in wat groot dele van die Linux-koppelvlak emuleer of bemiddel. Die resultaat is nie 'n normale `runc`-kontainer met 'n paar ekstra vlae nie; dit is 'n ander sandbox-ontwerp met die doel om die aanval-oppervlak van die gasheer-kernel te verminder. Kompatibiliteits- en prestasie-kompromieë is deel van daardie ontwerp, so omgewings wat `runsc` gebruik, moet anders gedokumenteer word as normale OCI runtime-omgewings.

### `kata-runtime`

Kata Containers druk die grens verder deur die werklas binne 'n liggewig virtuele masjien te begin. Administratief mag dit steeds soos 'n kontainer-ontplooiing lyk, en orkestreringslae mag dit steeds so behandel, maar die onderliggende isolasiegrens is nader aan vervirtualisering as aan 'n klassieke host-kernel-geskande kontainer. Dit maak Kata nuttig wanneer sterker huurder-isolasie verlang word sonder om kontainer-gesentreerde werkvloei te verlaat.

## Engines And Container Managers

As die laagvlak runtime die komponent is wat direk met die kernel praat, is die enjin of bestuurder die komponent waarmee gebruikers en operateurs gewoonlik interaksie het. Dit hanteer image pulls, metadata, logs, netwerke, volumes, lewensiklus-operasies, en API-blootstelling. Hierdie laag is uiters belangrik omdat baie regte wêreld kompromieë hier gebeur: toegang tot 'n runtime-sok of daemon-API kan gelykstaande wees aan gasheer-kompromie selfs al is die laagvlak runtime self perfek gesond.

### Docker Engine

Docker Engine is die mees herkenbare kontainerplatform vir ontwikkelaars en een van die redes waarom kontainer-woordeskat so Docker-gevormd geword het. Die tipiese pad is `docker` CLI na `dockerd`, wat op sy beurt koördineer met laagvlakkiger komponente soos `containerd` en 'n OCI runtime. Histories is Docker-ontplooiings dikwels **rootful**, en toegang tot die Docker-sok is gevolglik 'n baie kragtige primitief gewees. Dit is waarom soveel praktiese privilege-escalation materiaal fokus op `docker.sock`: as 'n proses `dockerd` kan vra om 'n privileged kontainer te skep, host-paaie te mount, of host-namespaces te join, mag dit geen kernel-ekspoït nodig hê nie.

### Podman

Podman is ontwerp rondom 'n meer daemonless model. Operationeel help dit om die idee te versterk dat kontainers net prosesse is wat deur standaard Linux-meganismes bestuur word eerder as deur een langlewende geprivilegieerde daemon. Podman het ook 'n baie sterker **rootless** storie as die klassieke Docker-implementasies wat baie mense eerste geleer het. Dit maak Podman nie outomaties veilig nie, maar dit verander die standaard risiko-profiel betekenisvol, veral in kombinasie met user namespaces, SELinux, en `crun`.

### containerd

containerd is 'n kern runtime-bestuurskomponent in baie moderne stapels. Dit word onder Docker gebruik en is ook een van die dominante Kubernetes runtime-backends. Dit bied kragtige APIs, bestuur images en snapshots, en delegeer die finale proses-skepping aan 'n laagvlak runtime. Sekuriteitsbesprekings rondom containerd moet beklemtoon dat toegang tot die containerd-sok of `ctr`/`nerdctl`-funksionaliteit net so gevaarlik kan wees as toegang tot Docker se API, selfs al voel die koppelvlak en werkvloei minder "ontwikkelaarvriendelik".

### CRI-O

CRI-O is meer gefokus as Docker Engine. In plaas daarvan om 'n algemene ontwikkelaarplatform te wees, is dit gebou rondom die skoon implementering van die Kubernetes Container Runtime Interface. Dit maak dit veral algemeen in Kubernetes-distribusies en SELinux-gewigte ekosisteme soos OpenShift. Vanuit 'n sekuriteitsperspektief is daardie nouer omvang nuttig omdat dit konseptuele rommel verminder: CRI-O is baie deel van die "run containers for Kubernetes"-laag eerder as 'n alles-platform.

### Incus, LXD, And LXC

Incus/LXD/LXC-stelsels is die moeite werd om te skei van Docker-styl toepassingskontainers omdat hulle dikwels as **system containers** gebruik word. 'n System container word gewoonlik verwag om meer soos 'n liggewig masjien te lyk met 'n voller userspace, langlopende dienste, rykere toestelblootstelling, en meer uitgebreide gasheer-integrasie. Die isolasiemeganismes is steeds kernel-primitiewe, maar die operasionele verwagtinge is anders. Gevolglik lyk misconfigurasies hier dikwels minder soos "slegte app-container-standaarde" en meer soos foute in liggewig vervirtualisering of gasheer-delegering.

### systemd-nspawn

systemd-nspawn beklee 'n interessante plek omdat dit systemd-inheemse is en baie nuttig vir toetsing, debugging, en die hardloop van OS-agtige omgewings. Dit is nie die dominante cloud-native produksie-runtime nie, maar dit verskyn gereeld genoeg in laboratoriums en distro-gefokusde omgewings dat dit 'n vermelding verdien. Vir sekuriteitsanalise is dit nog 'n herinnering dat die konsep "kontainer" oor veelvuldige ekosisteme en operasionele style strek.

### Apptainer / Singularity

Apptainer (voorheen Singularity) is algemeen in navorsing- en HPC-omgewings. Sy vertrouensoortassings, gebruikerwerkvloei, en uitvoeringsmodel verskil op belangrike maniere van Docker/Kubernetes-gesentreerde stapels. In die besonder gee hierdie omgewings dikwels baie om daarvoor dat gebruikers verpakte werklas kan hardloop sonder om hulle breë geprivilegieerde kontainer-bestuursmagte te gee. As 'n hersiener aanvaar dat elke kontainer-omgewing basies "Docker op 'n bediener" is, sal hulle hierdie ontplooiings ernstig misverstaan.

## Build-Time Tooling

Baie sekuriteitsbesprekings praat net oor run time, maar build-time gereedskap maak ook saak omdat dit die image-inhoud, blootstelling van bou-sekrete, en hoeveel vertroude konteks in die finale artefak ingebed word, bepaal.

**BuildKit** en `docker buildx` is moderne bou-backends wat kenmerke soos caching, secret mounting, SSH-forwarding, en multi-platform builds ondersteun. Dit is nuttige kenmerke, maar vanuit 'n sekuriteitsperspektief skep hulle ook plekke waar sekrete in image-lae kan leak of waar 'n oor-brei bou-konteks lêers kan blootstel wat nooit ingesluit moes wees nie. **Buildah** speel 'n soortgelyke rol in OCI-inheemse ekosisteme, veral rondom Podman, terwyl **Kaniko** dikwels in CI-omgewings gebruik word wat nie 'n geprivilegieerde Docker-daemon aan die boupyplyn wil toeken nie.

Die sleutel-les is dat image-skepping en image-uitvoering verskillende fases is, maar 'n swak bou-pipeline 'n swak runtime-houding lank voor die kontainer gelaunch word, kan skep.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes moet nie mentaal gelyk gestel word met die runtime self nie. Kubernetes is die orkestreerder. Dit skeduleer Pods, berg verlangde toestand, en druk sekuriteitsbeleid uit deur werklas-konfigurasie. Die kubelet praat dan met 'n CRI-implementering soos containerd of CRI-O, wat op sy beurt 'n laagvlak runtime soos `runc`, `crun`, `runsc`, of `kata-runtime` aanroep.

Hierdie skeiding is belangrik omdat baie mense verkeerdelik 'n beskerming aan "Kubernetes" toeskryf wanneer dit eintlik deur die node runtime afgedwing word, of hulle "containerd defaults" blameer vir gedrag wat uit 'n Pod-spesifikasie gekom het. In die praktyk is die finale sekuriteitshouding 'n komposisie: die orkestreerder vra vir iets, die runtime-stapel vertaal dit, en die kernel handhaaf dit uiteindelik.

## Why Runtime Identification Matters During Assessment

As jy die enjin en runtime vroeg identifiseer, word baie latere waarnemings makliker om te interpreteer. 'n Rootless Podman-kontainer dui daarop dat user namespaces waarskynlik deel van die storie is. 'n Docker-sok wat in 'n werklas gemount is, dui aan dat API-gedrewe privilege-escalation 'n realistiese pad is. 'n CRI-O/OpenShift-node behoort jou onmiddellik te laat dink aan SELinux-etikette en beperkte werklasbeleid. 'n gVisor of Kata-omgewing behoort jou meer versigtig te maak om aan te neem dat 'n klassieke `runc`-breakout PoC dieselfde sal optree.

Dit is hoekom een van die eerste stappe in kontainer-assessering altyd twee eenvoudige vrae beantwoord moet: **which component is managing the container** en **which runtime actually launched the process**. Sodra daardie antwoorde duidelik is, word die res van die omgewing gewoonlik baie makliker om oor te redeneer.

## Runtime Vulnerabilities

Nie elke kontainer-escape kom van operateur-misconfigurasie nie. Soms is die runtime self die kwesbare komponent. Dit maak saak omdat 'n werklas dalk met wat soos 'n sorgvuldige konfigurasie lyk, loop en steeds deur 'n laagvlak runtime-fout blootgestel word.

Die klassieke voorbeeld is **CVE-2019-5736** in `runc`, waar 'n kwaadwillige kontainer die gasheer `runc`-binary kon oorskryf en dan wag vir 'n latere `docker exec` of soortgelyke runtime-aanroep om aanvaller-beheerde kode te aktiveer. Die eksploitasiepad is baie anders as 'n eenvoudige bind-mount of capability-fout omdat dit misbruik maak van hoe die runtime weer in die kontainerproses-ruimte her-entreeer tydens exec-hantering.

'n Minimale reproduksie-werkvloei uit 'n red-team-perspektief is:
```bash
go build main.go
./main
```
Dan, vanaf die gasheer:
```bash
docker exec -it <container-name> /bin/sh
```
Die sleutelles is nie die presiese historiese exploit-implementering nie, maar die assesseringsimplikasie: as die runtime-weergawe kwesbaar is, kan gewone in-container kode-uitvoering voldoende wees om die host te kompromitteer, selfs wanneer die sigbare containerkonfigurasie nie blatantly swak lyk nie.

Onlangse runtime CVEs soos `CVE-2024-21626` in `runc`, BuildKit mount races, en containerd parsing bugs versterk dieselfde punt. Runtime-weergawe en patchvlak is deel van die sekuriteitsgrens, nie bloot onderhoudstrivia nie.
{{#include ../../../banners/hacktricks-training.md}}
