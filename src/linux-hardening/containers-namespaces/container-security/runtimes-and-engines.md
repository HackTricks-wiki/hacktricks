# Container-runtimes, enjins, bouers en sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Een van die grootste bronne van verwarring in container-sekuriteit is dat verskeie heeltemal verskillende komponente dikwels onder dieselfde woord saamgevat word. “Docker” kan na ’n image-formaat, ’n CLI, ’n daemon, ’n boustelsel, ’n runtime-stapel of bloot die algemene idee van containers verwys. Vir sekuriteitswerk is hierdie dubbelsinnigheid ’n probleem, want verskillende lae is verantwoordelik vir verskillende beskermings. ’n Breakout wat deur ’n swak bind mount veroorsaak word, is nie dieselfde as een wat deur ’n laevlak-runtime-bug veroorsaak word nie, en nie een van dié is dieselfde as ’n clusterbeleidfout in Kubernetes nie.

Hierdie bladsy onderskei die ekosisteem volgens rol, sodat die res van hierdie afdeling presies kan aandui waar ’n beskerming of swakheid eintlik lê.

## OCI as die gemeenskaplike taal

Moderne Linux-containerstapels kan dikwels met mekaar saamwerk omdat hulle ’n stel OCI-spesifikasies gebruik. Die **OCI Image Specification** beskryf hoe images en lae voorgestel word. Die **OCI Runtime Specification** beskryf hoe die runtime die proses moet begin, insluitend namespaces, mounts, cgroups en sekuriteitsinstellings. Die **OCI Distribution Specification** standaardiseer hoe registries inhoud beskikbaar stel.

Dit is belangrik, want dit verduidelik waarom ’n container-image wat met een hulpmiddel gebou is, dikwels met ’n ander een uitgevoer kan word, en waarom verskeie enjins dieselfde laevlak-runtime kan deel. Dit verduidelik ook waarom sekuriteitsgedrag soortgelyk kan lyk oor verskillende produkte heen: baie daarvan bou dieselfde OCI-runtime-konfigurasie en gee dit aan dieselfde klein stel runtimes.

## Laevlak-OCI-runtimes

Die laevlak-runtime is die komponent naaste aan die kern se grens. Dit is die deel wat werklik namespaces skep, cgroup-instellings skryf, capabilities en seccomp-filters toepas en uiteindelik die container-proses met `execve()` uitvoer. Wanneer mense “container-isolasie” op die meganiese vlak bespreek, bedoel hulle gewoonlik hierdie laag, selfs al sê hulle dit nie uitdruklik nie.

### `runc`

`runc` is die verwysings-OCI-runtime en bly die bekendste implementering. Dit word wyd gebruik onder Docker, containerd en baie Kubernetes-ontplooiings. Baie openbare navorsing en uitbuitingsmateriaal fokus op `runc`-agtige omgewings bloot omdat dit algemeen voorkom en omdat `runc` die basislyn definieer waaraan baie mense dink wanneer hulle ’n Linux-container voorstel. Om `runc` te verstaan, gee ’n leser dus ’n sterk denkmodel vir klassieke container-isolasie.

### `crun`

`crun` is nog ’n OCI-runtime, geskryf in C en wyd gebruik in moderne Podman-omgewings. Dit word dikwels geprys vir goeie cgroup v2-ondersteuning, sterk rootless-gebruiksgemak en laer oorhoofse las. Vanuit ’n sekuriteitsperspektief is die belangrike punt nie dat dit in ’n ander taal geskryf is nie, maar dat dit steeds dieselfde rol vervul: dit is die komponent wat die OCI-konfigurasie omskakel na ’n lopende prosesboom onder die kern. ’n Rootless Podman-werkvloei voel dikwels veiliger, nie omdat `crun` alles op ’n magiese wyse regstel nie, maar omdat die algehele stapel daaromheen geneig is om sterker op user namespaces en die beginsel van minste voorreg te steun.

### `runsc` van gVisor

`runsc` is die runtime wat deur gVisor gebruik word. Hier verander die grens betekenisvol. In plaas daarvan om die meeste syscalls soos gewoonlik direk na die gasheerkern te stuur, voeg gVisor ’n userspace-kernellaag in wat groot dele van die Linux-koppelvlak naboots of bemiddel. Die resultaat is nie ’n gewone `runc`-container met ’n paar ekstra flags nie; dit is ’n ander sandbox-ontwerp wat daarop gemik is om die gasheerkern se aanvalsvlak te verklein. Kompromieë tussen versoenbaarheid en werkverrigting is deel van dié ontwerp, dus moet omgewings wat `runsc` gebruik anders gedokumenteer word as normale OCI-runtime-omgewings.

### `kata-runtime`

Kata Containers skuif die grens verder deur die werklas binne ’n liggewig virtuele masjien te begin. Administratief kan dit steeds soos ’n container-ontplooiing lyk, en orkestreringslae kan dit steeds as sodanig hanteer, maar die onderliggende isolasiegrens is nader aan virtualisering as aan ’n klassieke container wat die gasheerkern deel. Dit maak Kata nuttig wanneer sterker tenant-isolasie verlang word sonder om containergerigte werkvloeie prys te gee.

## Enjins en containerbestuurders

As die laevlak-runtime die komponent is wat direk met die kern kommunikeer, is die enjin of bestuurder die komponent waarmee gebruikers en operateurs gewoonlik werk. Dit hanteer image-pulls, metadata, logs, netwerke, volumes, lewensiklusbewerkings en API-blootstelling. Hierdie laag is uiters belangrik omdat baie werklike kompromitterings hier plaasvind: toegang tot ’n runtime-socket of daemon-API kan gelykstaan aan kompromittering van die gasheer, selfs wanneer die laevlak-runtime self heeltemal gesond is.

### Docker Engine

Docker Engine is die mees herkenbare containerplatform vir ontwikkelaars en een van die redes waarom container-woordeskat so Docker-agtig geword het. Die tipiese pad is `docker` CLI na `dockerd`, wat op sy beurt laervlak-komponente soos `containerd` en ’n OCI-runtime koördineer. Docker-ontplooiings was histories dikwels **rootful**, en toegang tot die Docker-socket was dus ’n baie kragtige middel. Daarom fokus soveel praktiese materiaal oor voorregverhoging op `docker.sock`: as ’n proses `dockerd` kan vra om ’n bevoorregte container te skep, gasheerpaadjies te mount of by gasheer-namespaces aan te sluit, het dit dalk glad nie ’n kernuitbuiting nodig nie.

Vergelyk weergawenommers volgens hoof-, klein- en regstellingskomponent, eerder as om punte te verwyder: `18.09.1` is ouer as sowel `18.09.2` as `18.09.4`, ondanks sy nulgevulde klein komponent. Docker se [18.09-vrystellingnotas](https://docs.docker.com/engine/release-notes/18.09/) teken die saamgebondelde `runc`-regstelling vir CVE-2019-5736 in 18.09.2 aan, en die regstelling vir die bouverwysing van CVE-2019-13139 in 18.09.4. Dit is leidrade oor weergawes, nie bewys van ’n uitbuitbare kwesbaarheid nie. Dieselfde vrystellingnotas waarsku dat die daemon, kliënt en runtime afsonderlik verpak word; kontroleer dus die geïnstalleerde runtime en verskaffer-backports saam met die daemon-weergawe. ’n Bouverwysingskwessie vereis ook toegang tot die betrokke bouwerkvloei en invoer wat deur ’n aanvaller beheer word.

### Podman

Podman is ontwerp rondom ’n meer daemonlose model. Operasioneel help dit om die idee te versterk dat containers bloot prosesse is wat met standaard Linux-meganismes bestuur word, eerder as deur een langdurige bevoorregte daemon. Podman bied ook ’n veel sterker **rootless**-model as die klassieke Docker-ontplooiings waarmee baie mense aanvanklik kennis gemaak het. Dit maak Podman nie outomaties veilig nie, maar verander die verstek-risikoprofiel aansienlik, veral saam met user namespaces, SELinux en `crun`.

### containerd

containerd is ’n kernkomponent vir runtime-bestuur in baie moderne stapels. Dit word onder Docker gebruik en is ook een van die oorheersende Kubernetes-runtime-agterkante. Dit stel kragtige API’s beskikbaar, bestuur images en snapshots, en delegeer die finale proseskepping aan ’n laevlak-runtime. Sekuriteitsbesprekings oor containerd moet beklemtoon dat toegang tot die containerd-socket of `ctr`/`nerdctl`-funksionaliteit net so gevaarlik kan wees soos toegang tot Docker se API, selfs al voel die koppelvlak en werkvloei minder “ontwikkelaarvriendelik”.

### CRI-O

CRI-O is meer doelgerig as Docker Engine. In plaas daarvan om ’n algemene ontwikkelaarplatform te wees, is dit gebou om die Kubernetes Container Runtime Interface op ’n skoon manier te implementeer. Dit maak dit veral algemeen in Kubernetes-verspreidings en SELinux-swaar ekosisteme soos OpenShift. Vanuit ’n sekuriteitsperspektief is hierdie nouer omvang nuttig omdat dit konseptuele warboel verminder: CRI-O hoort duidelik by die laag wat “containers vir Kubernetes laat loop”, eerder as by ’n alles-in-een-platform.

Wanneer ’n Kubernetes-node CRI-O gebruik, kontroleer die **aktiewe CRI-O-vrystelling op die node**, saam met die vraag of die huidige identiteit Pods kan skep in ’n namespace wat daar geskeduleer word. [CVE-2022-0811](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7) het toegelaat dat vervaardigde Pod-sysctl-waardes ’n kernparameter op die gasheer verander en in geraakte vrystellings tot uitvoering as root op die gasheer lei. Die stroomopwaartse advies lys die reggestelde vrystellings en oplossings. ’n Plaaslike `crio --version` kan ’n runtime mis wat binne Minikube of ’n ander node-container genestel is; ’n leesbare Minikube-opstartlog kan ’n leidraad oor die weergawe gee, maar is historiese bewyse, nie bewys van die aktiewe runtime of sy regstellingstatus nie. Bevestig die werklike node-runtime, toestemming om Pods te skep, admission-reëls en relevante seccomp- en user-namespace-grense voordat jy dit as ’n uitbuitbare voorregverhoging beskou.

Daar is ook ’n direkte plaaslike `pinns`-ondersoekpad: die [ontdekkers merk op dat Kubernetes nie nodig is om die gebrekkige helper aan te roep nie](https://www.crowdstrike.com/en-us/blog/cr8escape-new-vulnerability-discovered-in-cri-o-container-engine-cve-2022-0811/). Kontroleer of die huidige rekening ’n root-besitte setuid-`pinns` kan uitvoer, of NoNewPrivs of ’n `nosuid`-mount daardie oorgang blokkeer, en of die geïnstalleerde **helper-bou** nie die regstelling bevat nie. Die [stroomopwaartse advies](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7) lys die reggestelde vrystellingsweergawes, maar ’n daemon se vertoonde weergawe bewys op sigself nie watter helper-binêre geïnstalleer is nie, en verspreider-backports kan die blootstelling verander. ’n Setuid-lêer is slegs ’n kandidaat; bevestig die helper se oorsprong, konfigurasie en gedrag van die gasheer se sysctl sonder om dit tydens roetine-ondersoek uit te voer.

### Incus, LXD en LXC

Incus/LXD/LXC-stelsels is die moeite werd om van Docker-agtige toepassingscontainers te onderskei omdat hulle dikwels as **stelselcontainers** gebruik word. Daar word gewoonlik verwag dat ’n stelselcontainer meer soos ’n liggewig masjien lyk, met ’n vollediger userspace, dienste wat lank loop, ryker toestelblootstelling en meer uitgebreide gasheerintegrasie. Die isolasiemeganismes is steeds kernprimitiewe, maar die operasionele verwagtinge verskil. Gevolglik lyk wanopstellings hier dikwels minder soos “swak verstekwaardes vir toepassingscontainers” en meer soos foute in liggewig-virtualisering of gasheerdelegering.

### systemd-nspawn

systemd-nspawn beklee ’n interessante plek omdat dit oorspronklik vir systemd is en baie nuttig is vir toetsing, ontfouting en die uitvoer van bedryfstelselagtige omgewings. Dit is nie die oorheersende cloud-native-produksieruntime nie, maar dit kom gereeld genoeg in labs en distrogerigte omgewings voor dat dit vermelding verdien. Vir sekuriteitsontleding herinner dit ons weer daaraan dat die begrip “container” oor verskeie ekosisteme en operasionele style strek.

### Apptainer / Singularity

Apptainer (voorheen Singularity) is algemeen in navorsings- en HPC-omgewings. Die vertrouensaannames, gebruikerswerkvloei en uitvoeringsmodel daarvan verskil op belangrike maniere van Docker/Kubernetes-gerigte stapels. Hierdie omgewings stel veral dikwels hoë eise daaraan om gebruikers verpakte werklaste te laat uitvoer sonder om hulle breë bevoorregte containerbestuursmagte te gee. As ’n beoordelaar aanneem dat elke container-omgewing basies “Docker op ’n bediener” is, sal hulle hierdie ontplooiings ernstig verkeerd verstaan.

## Bougereedskap

Baie sekuriteitsbesprekings handel net oor die runtime, maar bougereedskap is ook belangrik omdat dit die image-inhoud, blootstelling van bougeheime en hoeveelheid vertroude konteks bepaal wat in die finale artefak ingebed word.

**BuildKit** en `docker buildx` is moderne bou-agterkante wat funksies soos caching, secret-mounting, SSH-aanstuur en multi-platform-boue ondersteun. Dit is nuttige funksies, maar vanuit ’n sekuriteitsperspektief skep dit ook plekke waar geheime in image-lae kan lek, of waar ’n te breë boukonteks lêers kan blootlê wat nooit ingesluit moes word nie. **Buildah** vervul ’n soortgelyke rol in OCI-inheemse ekosisteme, veral saam met Podman, terwyl **Kaniko** dikwels in CI-omgewings gebruik word wat nie ’n bevoorregte Docker-daemon aan die bou-pyplyn wil toestaan nie.

Die belangrike les is dat image-skepping en image-uitvoering verskillende fases is, maar ’n swak bou-pyplyn kan ’n swak runtime-sekuriteitsposisie skep lank voordat die container begin word.

## Orkestrering is ’n ander laag, nie die runtime nie

Kubernetes moet nie verstandelik gelykgestel word aan die runtime self nie. Kubernetes is die orkestreerder. Dit skeduleer Pods, stoor die verlangde toestand en stel sekuriteitsbeleid deur werklaskonfigurasie uit. Die kubelet praat dan met ’n CRI-implementering soos containerd of CRI-O, wat op sy beurt ’n laevlak-runtime soos `runc`, `crun`, `runsc` of `kata-runtime aanroep.

Hierdie onderskeid is belangrik omdat baie mense ’n beskerming verkeerdelik aan “Kubernetes” toeskryf terwyl dit eintlik deur die node-runtime afgedwing word, of “containerd-verstekwaardes” blameer vir gedrag wat uit ’n Pod-spesifikasie kom. In die praktyk is die finale sekuriteitsposisie ’n samestelling: die orkestreerder vra vir iets, die runtime-stapel vertaal dit, en die kern dwing dit uiteindelik af.

## Waarom runtime-identifikasie tydens assessering belangrik is

As jy die enjin en runtime vroeg identifiseer, word baie latere waarnemings makliker om te vertolk. ’n Rootless Podman-container dui daarop dat user namespaces waarskynlik deel van die situasie is. ’n Docker-socket wat in ’n werklas gemount is, dui daarop dat API-gedrewe voorregverhoging ’n realistiese pad is. ’n CRI-O/OpenShift-node behoort jou onmiddellik aan SELinux-labels en beperkte werklasbeleid te laat dink. ’n gVisor- of Kata-omgewing behoort jou versigtiger te maak om aan te neem dat ’n klassieke `runc`-breakout-PoC dieselfde sal optree.

Daarom moet een van die eerste stappe in ’n container-assessering altyd wees om twee eenvoudige vrae te beantwoord: **watter komponent bestuur die container** en **watter runtime het die proses werklik begin**. Sodra dié antwoorde duidelik is, is die res van die omgewing gewoonlik veel makliker om te verstaan.

## Runtime-kwesbaarhede

Nie elke container-escape spruit uit ’n wanopstelling deur ’n operateur nie. Soms is die runtime self die kwesbare komponent. Dit is belangrik omdat ’n werklas met ’n oënskynlik versigtige konfigurasie steeds deur ’n laevlak-runtime-fout blootgestel kan wees.

Die klassieke voorbeeld is **CVE-2019-5736** in `runc`, waar ’n kwaadwillige container die gasheer se `runc`-binêre kon oorskryf en dan wag vir ’n latere `docker exec` of soortgelyke runtime-aanroep om aanvallerbeheerde kode te aktiveer. Die uitbuitingspad verskil baie van ’n eenvoudige bind-mount- of capability-fout omdat dit misbruik maak van hoe die runtime die container-prosesruimte weer binnegaan tydens exec-verwerking.<sup>[[1]](#references)</sup>

’n Minimale reproduksiewerkvloei vanuit ’n red-team-perspektief is:

```bash
go build main.go
./main
```

Dan, vanaf die gasheer:

```bash
docker exec -it <container-name> /bin/sh
```

Die belangrikste les is nie die presiese historiese implementering van die exploit nie, maar die implikasie vir assessering: as die runtime-weergawe kwesbaar is, kan gewone kode-uitvoering binne die container genoeg wees om die gasheer te kompromitteer, selfs wanneer die sigbare container-konfigurasie nie ooglopend swak lyk nie.

Onlangse runtime-CVE's soos `CVE-2024-21626` in `runc`, BuildKit-mount-resies en containerd-ontleedfoute versterk dieselfde punt. Die runtime-weergawe en pleistervlak vorm deel van die sekuriteitsgrens, en is nie bloot onderhoudsbesonderhede nie.

## References

- [1] [Breek uit Docker via runC – verduideliking van CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
