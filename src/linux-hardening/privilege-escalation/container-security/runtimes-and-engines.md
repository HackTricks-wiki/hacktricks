# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Moja ya vyanzo vikubwa vya mkanganyiko katika usalama wa container ni kwamba vipengele vingi kabisa tofauti mara nyingi vinachanganywa ndani ya neno moja. "Docker" inaweza kumaanisha image format, CLI, daemon, build system, runtime stack, au mawazo ya container kwa ujumla. Kwa kazi za usalama, kutoeleweka kwa uhakika ni tatizo, kwa sababu tabaka tofauti zinawajibika kwa ulinzi tofauti. Kuingia nje kutokana na bind mount mbaya si sawa na kuingia nje kutokana na bug ya runtime ya chini-ndani, na wala si sawa na kosa la sera ya cluster katika Kubernetes.

Ukurasa huu unatafuta kutenganisha ekosistimu kwa kazi ili sehemu iliyobaki iweze kuzungumza kwa usahihi kuhusu wapi ulinzi au udhaifu unapatikana.

## OCI As The Common Language

Stacks za kisasa za Linux container mara nyingi zinaweza kufanya kazi pamoja kwa sababu zinazungumza seti ya specs za OCI. The **OCI Image Specification** inaeleza jinsi images na layers zinavyowakilishwa. The **OCI Runtime Specification** inaeleza jinsi runtime inavyopaswa kuanzisha process, ikiwa ni pamoja na namespaces, mounts, cgroups, na settings za usalama. The **OCI Distribution Specification** inasawazisha jinsi registries zinavyoonyesha content.

Hii ni muhimu kwa sababu inaeleza kwa nini image iliyojengwa kwa chombo kimoja mara nyingi inaweza kuendeshwa kwa kingine, na kwa nini engines kadhaa zinaweza kushiriki runtime ya chini-ndani ile ile. Pia inaeleza kwa nini tabia za usalama zinaweza kuonekana sawa kati ya bidhaa tofauti: nyingi zimetengeneza configuration ile ile ya OCI runtime na kuiruhusu seti ndogo ya runtimes.

## Low-Level OCI Runtimes

Low-level runtime ni kipengele kilicho karibu zaidi na mpaka wa kernel. Ni sehemu inayotengeneza namespaces, kuandika settings za cgroup, kutekeleza capabilities na seccomp filters, na hatimaye `execve()` process ya container. Wakati watu wanaelezea "container isolation" kwa ngazi ya mitambo, hii ndiyo tabaka wanayokuwa wanazungumzia mara nyingi, hata kama hawasema waziwazi.

### `runc`

`runc` ni reference OCI runtime na inabaki utekelezaji unaojulikana zaidi. Inatumika sana chini ya Docker, containerd, na deployments nyingi za Kubernetes. Utafiti mwingi wa umma na nyenzo za exploitation hulenga mazingira ya mtindo wa `runc` kwa sababu ni ya kawaida na kwa sababu `runc` inaweka msingi ambao watu wengi hufikiria linapokuja suala la container ya Linux. Kuelewa `runc` kwa hivyo hutoa msomaji mfano mzuri wa akili kwa isolation ya jadi ya container.

### `crun`

`crun` ni runtime nyingine ya OCI, imeandikwa kwa C na inatumiwa sana katika mazingira ya kisasa ya Podman. Mara nyingi inasifiwa kwa mkono mzuri wa cgroup v2, ergonomics bora kwa rootless, na overhead ndogo. Kutoka kwa mtazamo wa usalama, jambo muhimu si kuwa imeandikwa kwa lugha tofauti, bali kwamba bado inacheza nafasi ile ile: ni sehemu inayobadilisha configuration ya OCI kuwa mti wa process unaoendesha chini ya kernel. Workflow ya Podman isiyo na root mara nyingi huhisi kuwa salama zaidi si kwa sababu `crun` inatatua kila kitu kwa uchawi, bali kwa sababu stack nzima inayozunguka inapendelea user namespaces na kanuni ya least privilege.

### `runsc` From gVisor

`runsc` ni runtime inayotumiwa na gVisor. Hapa mpaka hubadilika kwa maana. Badala ya kupitisha syscalls nyingi moja kwa moja kwa host kernel kwa njia ya kawaida, gVisor inaingiza tabaka la kernel kwenye userspace ambalo hufanya emulation au uingiliaji sehemu kubwa za interface ya Linux. Matokeo si container ya kawaida ya `runc` yenye flags za ziada; ni muundo tofauti wa sandbox ambao lengo lake ni kupunguza attack surface ya host-kernel. Ulinganifu na makubaliano ya utendaji ni sehemu ya muundo huo, kwa hivyo mazingira yanayotumia `runsc` yanapaswa kuandikishwa tofauti na mazingira ya kawaida ya OCI runtime.

### `kata-runtime`

Kata Containers inasukuma mpaka zaidi kwa kuanzisha workload ndani ya virtual machine mwepesi. Kitaalamu, hii inaweza bado kuonekana kama deployment ya container, na layers za orchestration zinaweza kuendelea kuihudumia kama hiyo, lakini mpaka wa isolation wa msingi uko karibu zaidi na virtualization kuliko container ya kawaida inayoshiriki host-kernel. Hii inafanya Kata kuwa yenye manufaa wakati isolation kali ya tenants inahitajika bila kuachwa workflows zinazolenga container.

## Engines And Container Managers

Iwapo low-level runtime ni kipengele kinachoongea moja kwa moja na kernel, engine au manager ni kipengele ambacho watumiaji na operator mara nyingi hufanya nao kazi. Inasimamia image pulls, metadata, logs, networks, volumes, lifecycle operations, na kuonesha API. Tabaka hili ni muhimu sana kwa sababu nyongeza nyingi za ulimwengu wa kweli hutokea hapa: ufikiaji wa runtime socket au daemon API unaweza kuwa sawa na kutekwa kwa host hata kama runtime ya chini-ndani yenyewe iko katika afya nzuri.

### Docker Engine

Docker Engine ni platform ya container inayotambulika zaidi kwa watengenezaji na moja ya sababu kwanini msamiati wa container ulitengenezwa kwa mtindo wa Docker. Njia ya kawaida ni CLI ya `docker` kwenda `dockerd`, ambayo kwa upande wake inaongoza vipengele vya chini kama `containerd` na OCI runtime. Kihistoria, deployments za Docker mara nyingi zimekuwa **rootful**, na hivyo ufikiaji wa socket ya Docker umekuwa primitive yenye nguvu sana. Hii ndiyo sababu nyenzo nyingi za practical privilege-escalation zinazingatia `docker.sock`: ikiwa process inaweza kumuomba `dockerd` kuunda container yenye privileges, kuweka mount host paths, au kujiunga na host namespaces, huenda isiihitaji hata exploit ya kernel.

### Podman

Podman ilibuniwa kwa modeli isiyokuwa na daemon. Kitaendeshaji, hili husaidia kuimarisha wazo kwamba containers ni tu processes zinazosimamiwa kupitia mechanisms za kawaida za Linux badala ya daemon moja ilio hai yenye privileges nyingi. Podman pia ina hadithi ya **rootless** yenye nguvu zaidi kuliko deployments za Docker za jadi ambazo watu wengi walijifunza kwanza. Hiyo haisemi kwamba Podman ni salama moja kwa moja, lakini hubadilisha profaili ya hatari kwa msingi, hasa ikichanganywa na user namespaces, SELinux, na `crun`.

### containerd

containerd ni kipengele msingi cha usimamizi wa runtime katika stacks nyingi za kisasa. Inatumiwa chini ya Docker na pia ni moja ya backends za runtime zinazotawala katika Kubernetes. Inatoa powerful APIs, inasimamia images na snapshots, na inaelekeza uundaji wa mwisho wa process kwa runtime ya chini-ndani. Majadiliano ya usalama kuhusu containerd yanapaswa kusisitiza kwamba ufikiaji wa socket ya containerd au uwezo wa `ctr`/`nerdctl` unaweza kuwa hatari kama ufikiaji wa API ya Docker, hata interface na workflow ikihisi kuwa isiyo "rafiki kwa developer".

### CRI-O

CRI-O imejikita zaidi kuliko Docker Engine. Badala ya kuwa platform ya matumizi mengi kwa developer, imejengwa kuzunguka utekelezaji safi wa Kubernetes Container Runtime Interface. Hii inaiweka sana katika distributions za Kubernetes na ekosistimu zilizo na SELinux kama OpenShift. Kutoka kwa mtazamo wa usalama, upeo huo mdogo ni muhimu kwa sababu unapunguza vurugu za dhana: CRI-O ni sehemu ya tabaka la "run containers for Kubernetes" badala ya platform ya kila kitu.

### Incus, LXD, And LXC

Mifumo ya Incus/LXD/LXC inastahili kutenganishwa na containers za mtindo wa Docker kwa sababu mara nyingi zinatumika kama **system containers**. System container kawaida inatarajiwa kuonekana zaidi kama machine nyepesi yenye userspace kamili, services zinazoendesha kwa muda mrefu, ufichaji wa kifaa ulioboreshwa, na ushirikiano wa kina na host. Vifaa vya isolation bado ni primitives za kernel, lakini matarajio ya uendeshaji ni tofauti. Matokeo yake, misconfiguration hapa mara nyingi haitaonekana kama "app-container defaults mbaya" bali kama makosa katika lightweight virtualization au delegation ya host.

### systemd-nspawn

systemd-nspawn inachukua nafasi ya kuvutia kwa sababu ni native kwa systemd na ni muhimu kwa testing, debugging, na kuendesha mazingira yanayofanana na OS. Sio runtime kuu wa uzalishaji wa cloud-native, lakini inaonekana mara kwa mara katika maabara na mazingira yanayolengwa kwa distro kiasi kwamba inastahili kutajwa. Kwa uchambuzi wa usalama, ni ukumbusho mwingine kwamba dhana ya "container" inashughulikia ekosistimu na mitindo tofauti ya uendeshaji.

### Apptainer / Singularity

Apptainer (aliyekuwa Singularity) ni ya kawaida katika mazingira ya utafiti na HPC. Misingi ya imani, workflow ya mtumiaji, na modeli ya utekelezaji zinatofautiana kwa njia muhimu kutoka stacks zinazoelekezwa na Docker/Kubernetes. Hasa, mazingira haya mara nyingi yanathamini kabisa kuwapa watumiaji uwezo wa kuendesha workloads zilizoambatanishwa bila kuwapa uwezo mpana wa usimamizi wa container wenye privileges. Ikiwa mkaguzi anadhani kila mazingira ya container ni kimsingi "Docker on a server", watayasahau vibaya deployments hizi.

## Build-Time Tooling

Majadiliano mengi ya usalama yanazungumzia tu wakati wa runtime, lakini tooling ya wakati wa build pia ni muhimu kwa sababu inabainisha yaliyomo katika image, exposure ya siri za build, na kiasi gani cha muktadha wa kuaminika kinaingizwa kwenye artifact ya mwisho.

**BuildKit** na `docker buildx` ni backends za build za kisasa zinazounga mkono vipengele kama caching, secret mounting, SSH forwarding, na multi-platform builds. Hivyo ni vipengele vyenye manufaa, lakini kutoka kwa mtazamo wa usalama pia zinaunda maeneo ambapo siri zinaweza leak ndani ya image layers au ambapo muktadha wa build ulio mpana sana unaweza kuonyesha faili ambazo hazikutakiwa kuingizwa. **Buildah** inacheza nafasi kama hiyo katika ekosistimu za OCI-native, hasa karibu na Podman, wakati **Kaniko** mara nyingi hutumika katika mazingira ya CI ambayo hayataki kumpa pipeline ya build Docker daemon yenye privileges.

Somo kuu ni kwamba uundaji wa image na utekelezaji wa image ni hatua tofauti, lakini pipeline dhaifu ya build inaweza kuunda mkao dhaifu wa runtime mapema kabla container haijaanzishwa.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes haipaswi kufikiriwa kwa akili kuwa ndiyo runtime yenyewe. Kubernetes ni orchestrator. Inapanga Pods, inahifadhi desired state, na inaonyesha sera za usalama kupitia configuration ya workload. kubelet kisha huongea na utekelezaji wa CRI kama containerd au CRI-O, ambazo kwa upande wake zinaitekeleza runtime ya chini-ndani kama `runc`, `crun`, `runsc`, au `kata-runtime`.

Utofauti huu ni muhimu kwa sababu watu wengi huwa wanamfunga ulinzi kwa "Kubernetes" wakati kwa kweli unatimizwa na node runtime, au wanaikosoa "containerd defaults" kwa tabia iliyotokana na Pod spec. Katika vitendo, mkao wa mwisho wa usalama ni muundo wa mchanganyiko: orchestrator inaomba kitu, runtime stack inakitafsiri, na kernel hatimaye kinakilinda.

## Why Runtime Identification Matters During Assessment

Ikiwa utatambua engine na runtime mapema, uchunguzi mwingi baadaye unakuwa rahisi kuelewa. Container ya Podman isiyo na root inaashiria user namespaces kuwa sehemu ya hadithi. Socket ya Docker iliyopakiwa ndani ya workload inaonyesha kuwa escalations kwa njia ya API ni njia halisi. Node ya CRI-O/OpenShift inapaswa kukufanya ufikirie mara moja kuhusu SELinux labels na sera za restricted workload. Mazingira ya gVisor au Kata yanapaswa kukufanya uwe wa tahadhari zaidi kuhusu kudhani kwamba PoC ya breakout ya `runc` ya jadi itafanya kazi kwa namna ile ile.

Ndiyo sababu mojawapo ya hatua za kwanza katika tathmini ya container inapaswa kuwa kujibu maswali mawili rahisi: **which component is managing the container** na **which runtime actually launched the process**. Mara majibu hayo yatakapotulia, mazingira mengine kawaida yanakuwa rahisi zaidi kuyafikiria.

## Runtime Vulnerabilities

Sio kila kuvuja kwa container kunatokana na misconfiguration ya operator. Wakati mwingine runtime yenyewe ndiyo kipengele chenye udhaifu. Hii ni muhimu kwa sababu workload inaweza kuendesha kwa configuration inayofanya kama makini na bado kuwa wazi kupitia flaw ya runtime ya chini-ndani.

Mfano wa jadi ni **CVE-2019-5736** katika `runc`, ambapo container yenye nia mbaya inaweza kuandika juu binary ya host `runc` na kisha kusubiri kwa invocation ya baadaye ya `docker exec` au runtime inayofanana ili kuamsha code iliyodhibitiwa na mwizi. Njia ya exploit ni tofauti kabisa na bind-mount rahisi au kosa la capability kwa sababu inatumia jinsi runtime inavyoingia tena kwenye nafasi ya process ya container wakati wa kushughulikia exec.

A minimal reproduction workflow from a red-team perspective is:
```bash
go build main.go
./main
```
Kisha, kutoka kwa host:
```bash
docker exec -it <container-name> /bin/sh
```
Somo kuu si utekelezaji halisi wa exploit wa kihistoria, bali athari yake kwa tathmini: ikiwa runtime version imevulnerable, utekelezaji wa kawaida wa in-container code unaweza kutosha kucompromise host hata wakati usanidi unaoonekana wa container hauonekani dhaifu wazi.

CVEs za hivi karibuni za runtime kama `CVE-2024-21626` katika `runc`, BuildKit mount races, na containerd parsing bugs zinathibitisha hoja hiyo. Runtime version na patch level ni sehemu ya boundary ya usalama, si tu mambo madogo ya matengenezo.
