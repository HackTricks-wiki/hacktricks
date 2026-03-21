# Houer-runtimes, enjinne, bouers en sandbokse

{{#include ../../../banners/hacktricks-training.md}}

Een van die grootste bronne van verwarring in houersekuriteit is dat verskeie heeltemal verskillende komponente dikwels in dieselfde woord saamgevou word. "Docker" kan na 'n image-formaat, 'n CLI, 'n daemon, 'n boustelsel, 'n runtime-stapel, of bloot die idee van houers in die algemeen verwys. Vir sekuriteitswerk is daardie vaagheid 'n probleem, omdat verskillende lae vir verskillende beskermings verantwoordelik is. 'n Ontsnapping veroorsaak deur 'n slegte bind-mount is nie dieselfde as 'n ontsnapping veroorsaak deur 'n laevlak runtime-bug nie, en geen van beide is dieselfde as 'n klusterbeleid-fout in Kubernetes nie.

Hierdie blad skei die ekosisteem volgens rol sodat die res van die afdeling presies kan praat oor waar 'n beskerming of swakheid eintlik woon.

## OCI as die gemeenskaplike taal

Moderne Linux-houvergelykings werk dikwels saam omdat hulle 'n stel OCI-spesifikasies praat. Die **OCI Image Specification** beskryf hoe images en lae voorgestel word. Die **OCI Runtime Specification** beskryf hoe die runtime die proses moet begin, insluitend namespaces, mounts, cgroups en sekuriteitsinstellings. Die **OCI Distribution Specification** standaardiseer hoe registrasies inhoud blootstel.

Dit is belangrik omdat dit verduidelik waarom 'n container image wat met een hulpmiddel gebou is dikwels met 'n ander gehardloop kan word, en waarom verskeie enjinne dieselfde laevlak runtime kan deel. Dit verduidelik ook waarom sekuriteitsgedrag oor verskillende produkte heen soortgelyk kan lyk: baie van hulle konstrueer dieselfde OCI runtime-konfigurasie en gee dit aan dieselfde klein stel runtimes.

## Laevlak OCI-runtimes

Die laevlak runtime is die komponent wat die naaste aan die kernel-grens lê. Dit is die deel wat eintlik namespaces skep, cgroup-instellings skryf, capabilities en seccomp-filters toepas, en uiteindelik die containerproses met `execve()` begin. Wanneer mense op meganiese vlak oor "container isolation" praat, is dit gewoonlik hierdie laag waarna hulle verwys, selfs al sê hulle dit nie eksplisiet nie.

### `runc`

`runc` is die verwysings-OCI-runtime en bly die bekendste implementasie. Dit word wyd gebruik onder Docker, containerd, en baie Kubernetes-implementasies. Baie openbare navorsing en eksploitasie-materiaal mik op `runc`-styl omgewings bloot omdat hulle algemeen is en omdat `runc` die basislyn definieer waaraan baie mense dink wanneer hulle 'n Linux-houer voorstel. Om `runc` te verstaan gee dus 'n leser 'n sterk geestelike model vir klassieke container-isolasie.

### `crun`

`crun` is nog 'n OCI-runtime, geskryf in C en wyd gebruik in moderne Podman-omgewings. Dit word dikwels geprys vir goeie cgroup v2-ondersteuning, sterk rootless-ergonomie, en laer oorhoofse koste. Vanuit 'n sekuriteitsperspektief is die belangrike punt nie dat dit in 'n ander taal geskryf is nie, maar dat dit steeds dieselfde rol speel: dit is die komponent wat die OCI-konfigurasie in 'n hardlopende prosesboom onder die kernel omskakel. 'n Rootless Podman-werkvloei voel dikwels veiliger nie omdat `crun` alles magies regmaak nie, maar omdat die algehele stapel daaromheen geneig is om meer op user namespaces en minste-privilege te leun.

### `runsc` van gVisor

`runsc` is die runtime wat deur gVisor gebruik word. Hier verander die grens betekenisvol. In plaas daarvan om meeste syscalls direk op die gewone manier aan die gasheer-kernel deur te gee, sit gVisor 'n gebruikersruimte-kernellaag in wat groot dele van die Linux-koppelvlak emuleer of bemiddel. Die resultaat is nie 'n normale `runc`-houer met 'n paar ekstra vlae nie; dit is 'n ander sandbox-ontwerp met die doel om die aanval-oppervlakte van die gasheer-kernel te verminder. Kompatibiliteit en prestasie-kompromieë is deel van daardie ontwerp, dus omgewings wat `runsc` gebruik moet anders gedokumenteer word as normale OCI-runtime-omgewings.

### `kata-runtime`

Kata Containers stoot die grens verder deur die werklading binne 'n liggewig virtuele masjien te begin. Administratief kan dit steeds soos 'n houer-deploy lyk, en orkestrasielaag kan dit steeds so behandel, maar die onderliggende isolasiegrens is nader aan virtualisering as aan 'n klassieke gasheer-kernel-geskondel deur houer. Dit maak Kata nuttig wanneer sterker huurder-isolasie verlang word sonder om container-sentriese werkvloei te verlaat.

## Enjinne en houerbestuurders

As die laevlak runtime die komponent is wat direk met die kernel praat, is die enjin of bestuurder die komponent waarmee gebruikers en operateurs gewoonlik interaksie het. Dit hanteer image-pulls, metadata, logs, netwerke, volumes, lewensiklusoperasies en API-blootstelling. Hierdie laag is uiters belangrik omdat baie werklike kompromieë hier gebeur: toegang tot 'n runtime-sok of daemon-API kan gelyk wees aan gasheer-kompromieersel selfs al is die laevlak runtime self perfek gesond.

### Docker Engine

Docker Engine is die mees herkenbare containerplatform vir ontwikkelaars en een van die redes waarom container-vokabulêre so Docker-gevorm geword het. Die tipiese pad is die `docker` CLI na `dockerd`, wat op sy beurt laer-vlak komponente soos `containerd` en 'n OCI-runtime koördineer. Histories is Docker-implementasies dikwels as root bedryf, en toegang tot die Docker-sok (`docker.sock`) was daarom 'n baie kragtige primitief. Dit is waarom soveel praktiese privilege-escalation materiaal op `docker.sock` fokus: as 'n proses `dockerd` kan vra om 'n geprivilegieerde houer te skep, gasheer-paaie te mount, of gasheer-namespaces te join, mag dit glad nie 'n kernel-exploit nodig hê nie.

### Podman

Podman is ontwerp rondom 'n meer daemonlose model. Operationeel help dit om die idee te versterk dat houers net prosesse is wat deur standaard Linux-meganismes bestuur word in plaas van deur een langlewende geprivilegieerde daemon. Podman het ook 'n baie sterker rootless-verhaal as die klassieke Docker-implementasies wat baie mense eerstens geleer het. Dit maak Podman nie outomaties veilig nie, maar dit verander die standaardrisikoprofiel aansienlik, veral wanneer dit gekombineer word met user namespaces, SELinux en `crun`.

### containerd

containerd is 'n kern runtime-bestuurskomponent in baie moderne stapels. Dit word gebruik onder Docker en is ook een van die dominante Kubernetes-runtime-backends. Dit bied kragtige APIs, bestuur images en snapshots, en delegeer die finale prosescreatie aan 'n laevlak runtime. Sekuriteitsbesprekings oor containerd moet beklemtoon dat toegang tot die containerd-sok of `ctr`/`nerdctl`-funksionaliteit net so gevaarlik kan wees as toegang tot Docker se API, selfs al lyk die koppelvlak en werkvloei minder "ontwikkelaar-vriendelik".

### CRI-O

CRI-O is meer gefokus as Docker Engine. In plaas daarvan om 'n algemene ontwikkelaarplatform te wees, is dit gebou rondom die netjiese implementering van die Kubernetes Container Runtime Interface. Dit maak dit veral algemeen in Kubernetes-distribusies en SELinux-gewig-omgewings soos OpenShift. Vanuit 'n sekuriteitsperspektief is daardie nouer fokus nuttig omdat dit konseptuele rommel verminder: CRI-O is baie deel van die "houers vir Kubernetes hardloop" laag eerder as 'n alles-platform.

### Incus, LXD en LXC

Incus/LXD/LXC-stelsels is die moeite werd om te skei van Docker-styl toepassingshouers omdat hulle dikwels as system containers gebruik word. 'n Stelselhouer word gewoonlik verwag om meer soos 'n liggewig masjien met 'n volwaardiger userspace, langlopende dienste, ryker toestelblootstelling en meer uitgebreide gasheer-integrasie te lyk. Die isolasiemeganismes is steeds kernel-primitiewe, maar die operationele verwagtinge is anders. Gevolglik lyk verkeerdkonfigurasies hier minder soos "slegte app-container-standaarde" en meer soos foute in liggewig-virtualisering of gasheer-delegasie.

### systemd-nspawn

systemd-nspawn neem 'n interessante plek in omdat dit systemd-inheems is en baie nuttig is vir toetsing, foutopsporing, en die bestuur van OS-agtige omgewings. Dit is nie die dominante cloud-native produksie-runtime nie, maar dit kom gereeld in laboratoriums en distro-georiënteerde omgewings voor en verdien daarom 'n vermelding. Vir sekuriteitsanalise is dit nog 'n herinnering dat die konsep "houer" oor verskeie ekosisteme en operationele style strek.

### Apptainer / Singularity

Apptainer (voorheen Singularity) is algemeen in navorsing en HPC-omgewings. Sy vertrouensaanname, gebruiker-werkvloei en uitvoeringsmodel verskil op belangrike maniere van Docker/Kubernetes-gesentreerde stapels. In die besonder gee hierdie omgewings dikwels baie om die vermoë vir gebruikers om gepakte werklaaie te hardloop sonder om vir hulle uitgebreide geprivilegieerde houer-bestuurkragte te gee. As 'n hersiener aanvaar dat elke houer-omgewing basies "Docker op 'n bediener" is, sal hulle hierdie implementasies ernstig misverstaan.

## Bou-tyd gereedskap

Baie sekuriteitsbesprekings praat slegs oor runtime, maar bou-tyd gereedskap is ook belangrik omdat dit bepaal wat in images ingesluit word, blootstelling van bou-geheime, en hoeveel vertroude konteks in die finale artefak ingebed word.

**BuildKit** en `docker buildx` is moderne bou-agtergronde wat funksies soos caching, secret mounting, SSH-forwarding, en multi-platform bou ondersteun. Dit is nuttige funksies, maar vanuit 'n sekuriteitsperspektief skep hulle ook plekke waar geheime in image-lae kan lek of waar 'n te wyd boukonteks lêers blootstel wat nooit ingesluit moes word nie. **Buildah** speel 'n soortgelyke rol in OCI-inheemse ekosisteme, veral rondom Podman, terwyl **Kaniko** dikwels in CI-omgewings gebruik word wat nie 'n geprivilegieerde Docker-daemon aan die boupyplyn wil gee nie.

Die kernles is dat image-skepping en image-uitvoering verskillende fases is, maar 'n swak bou-pyplyn kan 'n swak runtime-houding skep lank voordat die houer van stapel gestuur word.

## Orkestrasie is 'n ander laag, nie die runtime nie

Kubernetes moet nie mentaal met die runtime self gelyk gestel word nie. Kubernetes is die orchestrator. Dit skeduleer Pods, berg gewenste toestand, en druk sekuriteitsbeleid uit deur werkbelastingkonfigurasie. Die kubelet praat dan met 'n CRI-implementasie soos containerd of CRI-O, wat op sy beurt 'n laevlak runtime soos `runc`, `crun`, `runsc` of `kata-runtime` aanroep.

Hierdie skeiding is belangrik omdat baie mense verkeerdelik 'n beskerming aan "Kubernetes" toeskryf wanneer dit eintlik deur die node-runtime afgedwing word, of hulle "containerd-standaarde" blameer vir gedrag wat uit 'n Pod-spec gekom het. In die praktyk is die finale sekuriteitsopstelling 'n komposisie: die orchestrator vra vir iets, die runtime-stapel vertaal dit, en die kernel dwing dit uiteindelik af.

## Waarom runtime-identifikasie tydens assessering saak maak

As jy die enjin en runtime vroeg identifiseer, word baie latere waarnemings makliker om te interpreteer. 'n Rootless Podman-houer dui daarop dat user namespaces waarskynlik deel van die storie is. 'n Docker-sok wat in 'n werkbelasting gemount is, dui daarop dat API-gedrewe privilege-escalation 'n realistiese pad is. 'n CRI-O/OpenShift-node behoort jou dadelik aan SELinux-labels en beperkte werkbelastingbeleid te laat dink. 'n gVisor of Kata-omgewing behoort jou versigtiger te maak om aan te neem dat 'n klassieke `runc`-ontsnappings-PoC dieselfde sal optree.

Daarom behoort een van die eerste stappe in 'n container-assessering altyd twee eenvoudige vrae te beantwoord: **watter komponent bestuur die houer** en **watter runtime het eintlik die proses van stapel gestuur**. Sodra daardie antwoorde duidelik is, word die res van die omgewing gewoonlik baie makliker om oor na te dink.

## Runtime-kwesbaarhede

Nie elke container-ontsnapping kom van operateur-verkeerdkonfigurasie nie. Soms is die runtime self die kwesbare komponent. Dit maak 'n verskil omdat 'n werklading met wat lyk soos 'n noukeurige konfigurasie steeds deur 'n laevlak runtime-fout blootgestel kan wees.

Die klassieke voorbeeld is **CVE-2019-5736** in `runc`, waar 'n kwaadwillige houer die gasheer se `runc`-binêr kon oor skryf en dan wag vir 'n later `docker exec` of soortgelyke runtime-aanroep om aanvallerbeheerde kode te triggere. Die eksploitasiepad is baie anders as 'n eenvoudige bind-mount of capabilities-fout omdat dit misbruik maak van hoe die runtime weer in die houerprosesruimte herintree tydens exec-hantering.

'n Minimale reproduksiewerkvloei uit 'n red-team perspektief is:
```bash
go build main.go
./main
```
Dan, vanaf die gasheer:
```bash
docker exec -it <container-name> /bin/sh
```
Die sleutelles is nie die presiese historiese exploit-implementering nie, maar die implikasie vir assessering: as die runtime version kwesbaar is, kan gewone in-container code execution genoeg wees om die host te kompromitteer, selfs wanneer die sigbare containerkonfigurasie nie duidelik swak lyk nie.

Onlangse runtime CVEs soos `CVE-2024-21626` in `runc`, BuildKit mount races, en containerd parsing bugs versterk dieselfde punt. Runtime version en patch level is deel van die sekuriteitsgrens, nie bloot onderhoudstrivia nie.
