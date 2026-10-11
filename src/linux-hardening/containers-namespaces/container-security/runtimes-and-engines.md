# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Mojawapo ya vyanzo vikubwa vya mkanganyiko katika usalama wa containers ni kwamba vipengele kadhaa tofauti kabisa mara nyingi huwekwa chini ya neno moja. "Docker" inaweza kumaanisha umbizo la image, CLI, daemon, mfumo wa build, stack ya runtime, au wazo la containers kwa ujumla. Kwa kazi za usalama, utata huo ni tatizo, kwa sababu tabaka tofauti zinawajibikia ulinzi tofauti. Kutoroka kulikosababishwa na bind mount isiyo salama si sawa na kutoroka kulikosababishwa na hitilafu ya low-level runtime, na hakuna kati ya hayo inayofanana na kosa la sera ya cluster katika Kubernetes.

Ukurasa huu unapanga mfumo ikolojia kulingana na majukumu ili sehemu nyingine yaweze kueleza kwa usahihi mahali hasa ambapo ulinzi au udhaifu upo.

## OCI As The Common Language

Stacks za kisasa za Linux container mara nyingi huweza kuingiliana kwa sababu hutumia seti ya vipimo vya OCI. **OCI Image Specification** hueleza jinsi images na layers zinavyowakilishwa. **OCI Runtime Specification** hueleza jinsi runtime inavyopaswa kuzindua mchakato, ikijumuisha namespaces, mounts, cgroups, na mipangilio ya usalama. **OCI Distribution Specification** huweka viwango vya jinsi registries zinavyotoa maudhui.

Hili ni muhimu kwa sababu linaeleza kwa nini image ya container iliyoundwa kwa zana moja inaweza mara nyingi kuendeshwa na nyingine, na kwa nini engines kadhaa zinaweza kutumia low-level runtime ileile. Pia linaeleza kwa nini tabia za usalama zinaweza kufanana katika bidhaa tofauti: nyingi huunda usanidi uleule wa OCI runtime na kuupitisha kwa mojawapo ya runtimes chache zinazotumika.

## Low-Level OCI Runtimes

Low-level runtime ndiyo sehemu iliyo karibu zaidi na mpaka wa kernel. Ndiyo inayounda namespaces, kuandika mipangilio ya cgroup, kutumia capabilities na seccomp filters, kisha hatimaye kufanya `execve()` kwa mchakato wa container. Watu wanapojadili "container isolation" katika kiwango cha kiufundi, kwa kawaida wanazungumzia tabaka hili, hata kama hawalisemi waziwazi.

### `runc`

`runc` ndiyo OCI runtime rejea na bado ndiyo utekelezaji unaojulikana zaidi. Inatumika sana chini ya Docker, containerd, na deployments nyingi za Kubernetes. Utafiti mwingi wa umma na nyenzo za exploitation hulenga mazingira ya aina ya `runc` kwa sababu tu ni ya kawaida na kwa sababu `runc` hufafanua msingi ambao watu wengi hufikiria wanapowazia Linux container. Kwa hiyo, kuielewa `runc` humpa msomaji modeli nzuri ya kiakili ya container isolation ya kawaida.

### `crun`

`crun` ni OCI runtime nyingine, iliyoandikwa kwa C na inayotumika sana katika mazingira ya kisasa ya Podman. Mara nyingi husifiwa kwa usaidizi mzuri wa cgroup v2, urahisi mkubwa wa rootless, na overhead ndogo. Kwa mtazamo wa usalama, jambo muhimu si kwamba imeandikwa kwa lugha tofauti, bali kwamba bado ina jukumu lilelile: ni sehemu inayobadilisha usanidi wa OCI kuwa mti wa michakato unaoendeshwa chini ya kernel. Mtiririko wa kazi wa Podman rootless mara nyingi huonekana salama zaidi si kwa sababu `crun` hutatua kila kitu kimiujiza, bali kwa sababu stack nzima inayouzunguka huwa inaegemea zaidi user namespaces na least privilege.

### `runsc` From gVisor

`runsc` ndiyo runtime inayotumiwa na gVisor. Hapa mpaka wa isolation hubadilika kwa kiasi kikubwa. Badala ya kupitisha syscalls nyingi moja kwa moja kwa host kernel kwa njia ya kawaida, gVisor huweka tabaka la userspace kernel linaloiga au kudhibiti sehemu kubwa za Linux interface. Matokeo yake si container ya kawaida ya `runc` yenye flags chache za ziada; ni muundo tofauti wa sandbox ambao lengo lake ni kupunguza eneo la mashambulizi la host kernel. Tradeoffs za uoanifu na utendaji ni sehemu ya muundo huo, kwa hiyo mazingira yanayotumia `runsc` yanapaswa kuandikwa tofauti na mazingira ya kawaida ya OCI runtime.

### `kata-runtime`

Kata Containers husogeza mpaka zaidi kwa kuzindua workload ndani ya virtual machine nyepesi. Kwa upande wa usimamizi, huenda bado ukaonekana kama deployment ya container, na tabaka za orchestration zinaweza bado kuichukulia hivyo, lakini mpaka wa msingi wa isolation uko karibu zaidi na virtualization kuliko container ya kawaida inayoshiriki host kernel. Hii huifanya Kata kuwa muhimu pale ambapo isolation imara zaidi kati ya tenants inahitajika bila kuacha workflows zinazotegemea containers.

## Engines And Container Managers

Ikiwa low-level runtime ndiyo sehemu inayowasiliana moja kwa moja na kernel, engine au manager ndiyo sehemu ambayo watumiaji na waendeshaji huingiliana nayo kwa kawaida. Husimamia image pulls, metadata, logs, networks, volumes, shughuli za lifecycle, na ufichuaji wa API. Tabaka hili ni muhimu sana kwa sababu mashambulizi mengi halisi hutokea hapa: kupata ufikiaji wa runtime socket au daemon API kunaweza kuwa sawa na kuathiri host, hata kama low-level runtime yenyewe iko salama kabisa.

### Docker Engine

Docker Engine ndiyo platform ya container inayotambulika zaidi na developers, na mojawapo ya sababu zilizofanya msamiati wa containers uwe na umbo la Docker. Mtiririko wa kawaida ni kutoka `docker` CLI kwenda `dockerd`, ambayo huratibu vipengele vya chini kama `containerd` na OCI runtime. Kihistoria, deployments za Docker mara nyingi zimekuwa **rootful**, na hivyo ufikiaji wa Docker socket umekuwa uwezo wenye nguvu sana. Hii ndiyo sababu nyenzo nyingi za vitendo kuhusu privilege escalation hulenga `docker.sock`: ikiwa mchakato unaweza kuiomba `dockerd` iunde container ya privileged, imount host paths, au ijiunge na host namespaces, huenda usihitaji kernel exploit hata kidogo.

Linganisha namba za matoleo kwa kutumia vipengele vya major, minor, na patch badala ya kuondoa nukta: `18.09.1` ni ya zamani kuliko `18.09.2` na `18.09.4` licha ya kipengele chake cha minor kuwa na sifuri mwanzoni. [Maelezo ya toleo la Docker 18.09](https://docs.docker.com/engine/release-notes/18.09/) yanaeleza marekebisho ya `runc` yaliyojumuishwa kwa CVE-2019-5736 katika 18.09.2 na marekebisho ya build-reference kwa CVE-2019-13139 katika 18.09.4. Haya ni vidokezo vya matoleo, si uthibitisho kwamba exploit inaweza kufikiwa. Maelezo hayo hayo ya toleo yanaonya kuwa daemon, client, na runtime husambazwa kando, kwa hiyo kagua runtime iliyosakinishwa na marekebisho ya vendor backport pamoja na toleo la daemon; tatizo la build-reference pia huhitaji ufikiaji wa workflow ya build iliyoathirika na input inayodhibitiwa na mshambuliaji.

### Podman

Podman iliundwa kwa modeli isiyotegemea daemon. Kiutendaji, hili husaidia kusisitiza wazo kwamba containers ni michakato tu inayosimamiwa kupitia mifumo ya kawaida ya Linux badala ya daemon moja ya privileged inayofanya kazi muda wote. Podman pia ina usaidizi imara zaidi wa **rootless** kuliko deployments za kawaida za Docker ambazo watu wengi walijifunza kwanza. Hilo halifanyi Podman kuwa salama moja kwa moja, lakini hubadilisha sana kiwango cha hatari cha kawaida, hasa ikiunganishwa na user namespaces, SELinux, na `crun`.

### containerd

containerd ni kipengele kikuu cha usimamizi wa runtime katika stacks nyingi za kisasa. Inatumika chini ya Docker na pia ni mojawapo ya Kubernetes runtime backends zinazoongoza. Hutoa APIs zenye nguvu, husimamia images na snapshots, na hukabidhi uundaji wa mwisho wa mchakato kwa low-level runtime. Majadiliano ya usalama kuhusu containerd yanapaswa kusisitiza kuwa ufikiaji wa containerd socket au utendaji wa `ctr`/`nerdctl` unaweza kuwa hatari sawa na ufikiaji wa Docker API, hata kama interface na workflow vinaonekana kuwa si rafiki sana kwa developers.

### CRI-O

CRI-O ina wigo mwembamba zaidi kuliko Docker Engine. Badala ya kuwa platform ya jumla kwa developers, imejengwa ili kutekeleza Kubernetes Container Runtime Interface kwa njia safi. Hii huifanya iwe ya kawaida hasa katika Kubernetes distributions na mifumo inayotumia sana SELinux kama OpenShift. Kwa mtazamo wa usalama, wigo huo mwembamba ni muhimu kwa sababu hupunguza mkanganyiko wa dhana: CRI-O ni sehemu ya tabaka la "kuendesha containers kwa Kubernetes", badala ya kuwa platform ya kila kitu.

Node ya Kubernetes inapotumia CRI-O, kagua **toleo linalotumika la CRI-O kwenye node** pamoja na iwapo utambulisho wa sasa unaweza kuunda Pods katika namespace inayopangiwa node hiyo. [CVE-2022-0811](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7) iliruhusu thamani za sysctl zilizoundwa mahsusi kwenye Pod kubadilisha kigezo cha host kernel na kufikia utekelezaji wa host-root katika matoleo yaliyoathirika. Ushauri wa upstream unaorodhesha matoleo yaliyorekebishwa na njia za kushughulikia tatizo. `crio --version` ya ndani inaweza kukosa runtime iliyowekwa ndani ya Minikube au container nyingine ya node; log ya Minikube startup inayoweza kusomwa inaweza kutoa kidokezo cha toleo, lakini ni ushahidi wa kihistoria, si uthibitisho wa runtime inayotumika sasa au hali ya marekebisho yake. Thibitisha runtime halisi ya node, idhini ya kuunda Pod, admission rules, na mipaka husika ya seccomp na user-namespace kabla ya kuchukulia hili kama privilege escalation inayoweza kufikiwa.

Pia kuna njia ya moja kwa moja ya kukagua `pinns` ya ndani: [wagunduzi wanabainisha kuwa Kubernetes haihitajiki ili kuita helper yenye hitilafu](https://www.crowdstrike.com/en-us/blog/cr8escape-new-vulnerability-discovered-in-cri-o-container-engine-cve-2022-0811/). Kagua iwapo akaunti ya sasa inaweza kutekeleza `pinns` inayomilikiwa na root na yenye setuid, iwapo NoNewPrivs au mount ya `nosuid` inazuia mabadiliko hayo, na iwapo **helper build** iliyosakinishwa haina marekebisho. [Ushauri wa upstream](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7) unaorodhesha matoleo yaliyorekebishwa, lakini toleo linaloonyeshwa na daemon pekee halithibitishi ni binary gani ya helper iliyosakinishwa, na marekebisho ya distributor yanaweza kubadilisha uwezekano wa kuathirika. Faili ya setuid ni kitu cha kuchunguza tu; thibitisha asili ya helper, usanidi, na tabia ya host sysctl bila kuiendesha wakati wa ukaguzi wa kawaida.

### Incus, LXD, And LXC

Mifumo ya Incus/LXD/LXC inafaa kutenganishwa na application containers za mtindo wa Docker kwa sababu mara nyingi hutumika kama **system containers**. Kwa kawaida system container inatarajiwa kufanana zaidi na mashine nyepesi yenye userspace kamili zaidi, huduma zinazoendeshwa kwa muda mrefu, ufichuaji mpana zaidi wa vifaa, na muunganisho mkubwa zaidi na host. Mbinu za isolation bado ni kernel primitives, lakini matarajio ya kiutendaji ni tofauti. Kwa hiyo, usanidi usio sahihi hapa mara nyingi huonekana si kama "defaults mbaya za app-container", bali kama makosa katika virtualization nyepesi au ugawaji wa mamlaka ya host.

### systemd-nspawn

systemd-nspawn ina nafasi ya kipekee kwa sababu imejengwa kwa mfumo wa systemd na ni muhimu sana kwa majaribio, utatuzi wa hitilafu, na kuendesha mazingira yanayofanana na OS. Si runtime kuu katika uzalishaji wa cloud-native, lakini huonekana mara nyingi vya kutosha katika labs na mazingira yanayolenga distro kiasi kwamba inastahili kutajwa. Kwa uchanganuzi wa usalama, ni ukumbusho mwingine kwamba dhana ya "container" inahusu mifumo mingi na mitindo tofauti ya kiutendaji.

### Apptainer / Singularity

Apptainer (zamani Singularity) ni ya kawaida katika mazingira ya utafiti na HPC. Matarajio yake ya uaminifu, workflow ya mtumiaji, na modeli ya utekelezaji hutofautiana kwa njia muhimu na stacks zinazolenga Docker/Kubernetes. Hasa, mazingira haya mara nyingi yanataka watumiaji waweze kuendesha workloads zilizofungashwa bila kuwapa mamlaka mapana ya kusimamia containers zenye privileged. Ikiwa mkaguzi atadhani kila mazingira ya container kimsingi ni "Docker kwenye server", ataelewa deployments hizi vibaya sana.

## Build-Time Tooling

Majadiliano mengi ya usalama huzungumzia runtime pekee, lakini build-time tooling pia ni muhimu kwa sababu huamua maudhui ya image, ufichuaji wa build secrets, na kiasi cha muktadha unaoaminika kinachojumuishwa kwenye artifact ya mwisho.

**BuildKit** na `docker buildx` ni build backends za kisasa zinazotumia vipengele kama caching, secret mounting, SSH forwarding, na multi-platform builds. Vipengele hivyo ni muhimu, lakini kwa mtazamo wa usalama pia huunda maeneo ambayo secrets zinaweza kuvuja kwenye image layers au muktadha wa build ulio mpana kupita kiasi unaweza kufichua faili ambazo hazikupaswa kujumuishwa kamwe. **Buildah** ina jukumu linalofanana katika mifumo ya OCI-native, hasa inayohusiana na Podman, huku **Kaniko** ikitumiwa mara nyingi katika CI environments ambazo hazitaki kuipa build pipeline Docker daemon yenye privileged.

Somo kuu ni kwamba uundaji wa image na utekelezaji wa image ni awamu tofauti, lakini build pipeline dhaifu inaweza kusababisha hali dhaifu ya usalama wa runtime muda mrefu kabla container haijazinduliwa.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes haipaswi kuchukuliwa kuwa runtime yenyewe. Kubernetes ndiyo orchestrator. Hupanga Pods, huhifadhi hali inayotakiwa, na kueleza sera ya usalama kupitia usanidi wa workload. Kisha kubelet huwasiliana na utekelezaji wa CRI kama containerd au CRI-O, ambao nao huita low-level runtime kama `runc`, `crun`, `runsc`, au `kata-runtime`.

Mgawanyo huu ni muhimu kwa sababu watu wengi kimakosa huhusisha ulinzi na "Kubernetes" ilhali unatekelezwa na node runtime, au hulaumu "containerd defaults" kwa tabia iliyotokana na Pod spec. Kiutendaji, hali ya mwisho ya usalama ni mchanganyiko: orchestrator huomba kitu, runtime stack hukitafsiri, na hatimaye kernel hukitekeleza.

## Why Runtime Identification Matters During Assessment

Ukitambua engine na runtime mapema, mambo mengi utakayoyaona baadaye huwa rahisi kutafsiri. Container ya Podman rootless inadokeza kuwa user namespaces huenda ni sehemu ya mazingira. Docker socket iliyomountiwa ndani ya workload inadokeza kuwa privilege escalation kupitia API ni njia inayowezekana. Node ya CRI-O/OpenShift inapaswa kukukumbusha mara moja kuhusu SELinux labels na sera ya workload iliyozuiliwa. Mazingira ya gVisor au Kata yanapaswa kukufanya uwe mwangalifu zaidi kudhani kuwa classic `runc` breakout PoC itafanya kazi kwa namna ileile.

Ndiyo maana moja ya hatua za kwanza katika tathmini ya container inapaswa kuwa kujibu maswali mawili rahisi: **ni component gani inayosimamia container** na **runtime gani hasa ilizindua mchakato**. Majibu hayo yakishafahamika, kwa kawaida inakuwa rahisi zaidi kuelewa mazingira mengine.

## Runtime Vulnerabilities

Si kila container escape husababishwa na usanidi usio sahihi wa operator. Wakati mwingine runtime yenyewe ndiyo component iliyo hatarini. Hili ni muhimu kwa sababu workload inaweza kuwa inaendeshwa kwa usanidi unaoonekana kuwa makini, lakini bado iko hatarini kutokana na hitilafu ya low-level runtime.

Mfano wa kawaida ni **CVE-2019-5736** katika `runc`, ambapo container hasidi ingeweza kubadilisha binary ya host ya `runc`, kisha kusubiri mwito wa baadaye wa `docker exec` au mwito mwingine unaofanana wa runtime ili kuendesha code inayodhibitiwa na mshambuliaji. Njia ya exploit ni tofauti kabisa na kosa rahisi la bind-mount au capability kwa sababu hutumia jinsi runtime inavyoingia tena kwenye nafasi ya mchakato wa container wakati wa kushughulikia exec.<sup>[[1]](#references)</sup>

Mtiririko mdogo wa kuzalisha tena tatizo kwa mtazamo wa red-team ni:

```bash
go build main.go
./main
```

Kisha, kutoka kwa host:

```bash
docker exec -it <container-name> /bin/sh
```

Funzo kuu si utekelezaji halisi wa exploit wa kihistoria, bali athari yake katika tathmini: ikiwa toleo la runtime lina athari za kiusalama, kutekeleza code ya kawaida ndani ya container kunaweza kutosha kuhatarisha host, hata kama usanidi wa container unaoonekana hauonekani kuwa dhaifu waziwazi.

CVE za hivi karibuni za runtime, kama `CVE-2024-21626` katika `runc`, race conditions za mount za BuildKit na hitilafu za uchanganuzi za containerd, zinathibitisha jambo hilohilo. Toleo la runtime na kiwango chake cha viraka ni sehemu ya mpaka wa usalama, si mambo madogo tu ya matengenezo.

## References

- [1] [Kutoroka kutoka Docker kupitia runC – Kueleza CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
