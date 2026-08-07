# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Mojawapo ya vyanzo vikubwa vya mkanganyiko katika container security ni kwamba components kadhaa tofauti kabisa mara nyingi huwekwa chini ya neno moja. "Docker" inaweza kumaanisha image format, CLI, daemon, build system, runtime stack, au tu wazo la containers kwa ujumla. Kwa kazi za security, utata huo ni tatizo, kwa sababu layers tofauti zinawajibika kwa protections tofauti. Breakout inayosababishwa na bind mount mbaya si kitu sawa na breakout inayosababishwa na low-level runtime bug, wala si sawa na kosa la cluster policy katika Kubernetes.

Ukurasa huu unatenganisha ecosystem kwa kuzingatia role, ili sehemu iliyobaki iweze kueleza kwa usahihi protection au weakness iko wapi hasa.

## OCI As The Common Language

Modern Linux container stacks mara nyingi huingiliana kwa sababu zinazungumza seti ya OCI specifications. **OCI Image Specification** inaeleza jinsi images na layers zinavyowakilishwa. **OCI Runtime Specification** inaeleza jinsi runtime inavyopaswa kuanzisha process, ikiwemo namespaces, mounts, cgroups, na security settings. **OCI Distribution Specification** inasanifisha jinsi registries zinavyowasilisha content.

Hili ni muhimu kwa sababu linaeleza kwa nini container image iliyojengwa kwa tool moja mara nyingi inaweza kuendeshwa kwa nyingine, na kwa nini engines kadhaa zinaweza kushiriki low-level runtime sawa. Pia linaeleza kwa nini security behavior inaweza kuonekana sawa katika products tofauti: nyingi kati yao zinaunda OCI runtime configuration sawa na kuikabidhi kwa seti ndogo ileile ya runtimes.

## Low-Level OCI Runtimes

Low-level runtime ni component iliyo karibu zaidi na kernel boundary. Ndiyo inayounda namespaces, kuandika cgroup settings, kutumia capabilities na seccomp filters, na hatimaye kufanya `execve()` ya container process. Watu wanapozungumzia "container isolation" kwa kiwango cha kiufundi, kwa kawaida wanazungumzia layer hii, hata kama hawasemi hivyo waziwazi.

### `runc`

`runc` ni reference OCI runtime na bado ndiyo implementation inayojulikana zaidi. Inatumika sana chini ya Docker, containerd, na deployments nyingi za Kubernetes. Tafiti nyingi za umma na material za exploitation zinalenga `runc`-style environments kwa sababu tu ni za kawaida, na kwa sababu `runc` inaweka baseline ambayo watu wengi huifikiria wanapowaza Linux container. Kwa hiyo, kuelewa `runc` humpa msomaji mental model imara ya classic container isolation.

### `crun`

`crun` ni OCI runtime nyingine, iliyoandikwa kwa C na inayotumika sana katika modern Podman environments. Mara nyingi husifiwa kwa support nzuri ya cgroup v2, rootless ergonomics imara, na overhead ndogo. Kwa mtazamo wa security, jambo muhimu si kwamba imeandikwa kwa language tofauti, bali kwamba bado inatekeleza role ileile: ni component inayobadilisha OCI configuration kuwa process tree inayoendesha chini ya kernel. Rootless Podman workflow mara nyingi huonekana kuwa salama zaidi si kwa sababu `crun` hurekebisha kila kitu kimiujiza, bali kwa sababu stack nzima inayouzunguka huwa inaegemea zaidi user namespaces na least privilege.

### `runsc` From gVisor

`runsc` ni runtime inayotumiwa na gVisor. Hapa boundary hubadilika kwa kiwango kikubwa. Badala ya kupitisha syscalls nyingi moja kwa moja kwa host kernel kwa njia ya kawaida, gVisor huingiza userspace kernel layer inayosimulate au kusimamia sehemu kubwa za Linux interface. Matokeo yake si `runc` container ya kawaida yenye flags chache za ziada; ni sandbox design tofauti yenye lengo la kupunguza host-kernel attack surface. Compatibility na performance tradeoffs ni sehemu ya design hiyo, kwa hiyo environments zinazotumia `runsc` zinapaswa kuandikwa tofauti na normal OCI runtime environments.

### `kata-runtime`

Kata Containers husogeza boundary zaidi kwa kuanzisha workload ndani ya lightweight virtual machine. Kiutawala, hii bado inaweza kuonekana kama container deployment, na orchestration layers bado zinaweza kuichukulia hivyo, lakini isolation boundary ya msingi iko karibu zaidi na virtualization kuliko container ya kawaida inayoshiriki host kernel. Hili huifanya Kata kuwa muhimu wakati tenant isolation imara zaidi inapohitajika bila kuacha container-centric workflows.

## Engines And Container Managers

Ikiwa low-level runtime ni component inayozungumza moja kwa moja na kernel, engine au manager ndiyo component ambayo users na operators kwa kawaida huingiliana nayo. Inashughulikia image pulls, metadata, logs, networks, volumes, lifecycle operations, na API exposure. Layer hii ni muhimu sana kwa sababu compromises nyingi za real-world hutokea hapa: access kwa runtime socket au daemon API inaweza kuwa sawa na host compromise hata kama low-level runtime yenyewe iko salama kabisa.

### Docker Engine

Docker Engine ndiyo container platform inayotambulika zaidi kwa developers, na ni mojawapo ya sababu zilizofanya container vocabulary iwe na mwelekeo mkubwa wa Docker. Njia ya kawaida ni `docker` CLI kwenda kwa `dockerd`, ambayo nayo huratibu lower-level components kama `containerd` na OCI runtime. Kihistoria, Docker deployments mara nyingi zimekuwa **rootful**, na hivyo access kwa Docker socket imekuwa primitive yenye nguvu sana. Ndiyo maana material nyingi za practical privilege-escalation huzingatia `docker.sock`: ikiwa process inaweza kuiomba `dockerd` iunde privileged container, iimount host paths, au ijiunge na host namespaces, huenda isihitaji kernel exploit kabisa.

### Podman

Podman iliundwa kwa kuzingatia daemonless model zaidi. Kiutendaji, hili husaidia kusisitiza wazo kwamba containers ni processes tu zinazosimamiwa kupitia standard Linux mechanisms badala ya daemon moja ya privileged inayoendelea kwa muda mrefu. Podman pia ina **rootless** story imara zaidi kuliko classic Docker deployments ambazo watu wengi walijifunza mwanzoni. Hili halifanyi Podman iwe salama moja kwa moja, lakini hubadilisha default risk profile kwa kiasi kikubwa, hasa inapounganishwa na user namespaces, SELinux, na `crun`.

### containerd

containerd ni core runtime management component katika stacks nyingi za kisasa. Inatumika chini ya Docker na pia ni mojawapo ya Kubernetes runtime backends zinazotawala. Hutoa powerful APIs, husimamia images na snapshots, na hukabidhi process creation ya mwisho kwa low-level runtime. Majadiliano ya security kuhusu containerd yanapaswa kusisitiza kwamba access kwa containerd socket au `ctr`/`nerdctl` functionality inaweza kuwa hatari sawa na access kwa Docker's API, hata kama interface na workflow vinaonekana kuwa si vya "developer friendly" sana.

### CRI-O

CRI-O ina focus nyembamba kuliko Docker Engine. Badala ya kuwa developer platform ya matumizi ya jumla, imejengwa kuzunguka kutekeleza Kubernetes Container Runtime Interface kwa usafi. Hili huifanya itumike sana katika Kubernetes distributions na SELinux-heavy ecosystems kama OpenShift. Kwa mtazamo wa security, scope hii nyembamba ni muhimu kwa sababu hupunguza conceptual clutter: CRI-O ni sehemu ya layer ya "run containers for Kubernetes", badala ya kuwa everything-platform.

### Incus, LXD, And LXC

Incus/LXD/LXC systems zinastahili kutenganishwa na Docker-style application containers kwa sababu mara nyingi hutumika kama **system containers**. System container kwa kawaida inatarajiwa kufanana zaidi na lightweight machine yenye fuller userspace, long-running services, richer device exposure, na host integration pana zaidi. Isolation mechanisms bado ni kernel primitives, lakini operational expectations ni tofauti. Kwa hiyo, misconfigurations hapa mara nyingi huonekana chini ya lightweight virtualization au host delegation kuliko "bad app-container defaults".

### systemd-nspawn

systemd-nspawn iko katika nafasi ya kipekee kwa sababu ni systemd-native na ni muhimu sana kwa testing, debugging, na kuendesha OS-like environments. Si production runtime inayotawala katika cloud-native, lakini huonekana mara nyingi katika labs na distro-oriented environments kiasi cha kustahili kutajwa. Kwa security analysis, ni ukumbusho mwingine kwamba dhana ya "container" inahusisha ecosystems na operational styles nyingi.

### Apptainer / Singularity

Apptainer (zamani Singularity) hutumika sana katika research na HPC environments. Trust assumptions, user workflow, na execution model zake zinatofautiana kwa njia muhimu na stacks zinazozingatia Docker/Kubernetes. Hasa, environments hizi mara nyingi zinahitaji sana users waweze kuendesha packaged workloads bila kupewa broad privileged container-management powers. Ikiwa reviewer atadhani kila container environment kimsingi ni "Docker on a server", ataelewa deployments hizi vibaya sana.

## Build-Time Tooling

Majadiliano mengi ya security huzungumzia run time pekee, lakini build-time tooling pia ni muhimu kwa sababu huamua image contents, build secrets exposure, na kiasi cha trusted context kinachowekwa ndani ya final artifact.

**BuildKit** na `docker buildx` ni modern build backends zinazosaidia features kama caching, secret mounting, SSH forwarding, na multi-platform builds. Hizi ni useful features, lakini kwa mtazamo wa security pia huunda maeneo ambayo secrets zinaweza ku-leak kwenye image layers au ambapo build context iliyo pana kupita kiasi inaweza kufichua files ambazo hazikupaswa kabisa kujumuishwa. **Buildah** ina role inayofanana katika OCI-native ecosystems, hasa karibu na Podman, wakati **Kaniko** hutumika mara nyingi katika CI environments ambazo hazitaki kuipa build pipeline privileged Docker daemon.

Somo kuu ni kwamba image creation na image execution ni phases tofauti, lakini weak build pipeline inaweza kuunda weak runtime posture muda mrefu kabla container haijazinduliwa.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes haipaswi kufikiriwa kama runtime yenyewe. Kubernetes ni orchestrator. Hupanga Pods, huhifadhi desired state, na huonyesha security policy kupitia workload configuration. Kisha kubelet huzungumza na CRI implementation kama containerd au CRI-O, ambayo nayo huita low-level runtime kama `runc`, `crun`, `runsc`, au `kata-runtime`.

Utenganisho huu ni muhimu kwa sababu watu wengi huipa "Kubernetes" protection ambayo kwa kweli inatekelezwa na node runtime, au huwalaumu "containerd defaults" kwa behavior iliyotokana na Pod spec. Kiuhalisia, final security posture ni composition: orchestrator huomba kitu, runtime stack hukitafsiri, na hatimaye kernel hulazimisha utekelezaji wake.

## Why Runtime Identification Matters During Assessment

Ukibaini engine na runtime mapema, observations nyingi zinazofuata huwa rahisi kutafsiri. Rootless Podman container inaashiria kwamba user namespaces huenda ni sehemu ya story. Docker socket iliyomountiwa ndani ya workload inaashiria kwamba API-driven privilege escalation ni njia halisi. CRI-O/OpenShift node inapaswa mara moja kukufanya ufikirie kuhusu SELinux labels na restricted workload policy. gVisor au Kata environment inapaswa kukufanya uwe mwangalifu zaidi kabla ya kudhani kwamba classic `runc` breakout PoC itafanya kazi kwa namna ileile.

Ndiyo maana mojawapo ya hatua za kwanza katika container assessment inapaswa kuwa kujibu maswali mawili rahisi: **ni component gani inayosimamia container** na **ni runtime gani hasa iliyoanzisha process**. Majibu hayo yakishajulikana, mazingira mengine kwa kawaida huwa rahisi zaidi kuchanganua.

## Runtime Vulnerabilities

Si kila container escape husababishwa na operator misconfiguration. Wakati mwingine runtime yenyewe ndiyo vulnerable component. Hili ni muhimu kwa sababu workload inaweza kuwa inaendeshwa kwa configuration inayoonekana kuwa makini, lakini bado ikawa exposed kupitia low-level runtime flaw.

Mfano wa classic ni **CVE-2019-5736** katika `runc`, ambapo malicious container ingeweza ku-overwrite host `runc` binary na kisha kusubiri `docker exec` ya baadaye au runtime invocation inayofanana ili ku-trigger attacker-controlled code. Exploit path hii ni tofauti sana na simple bind-mount au capability mistake kwa sababu inatumia jinsi runtime inavyoingia tena katika container process space wakati wa kushughulikia exec.<sup>[[1]](#references)</sup>

Minimal reproduction workflow kwa mtazamo wa red-team ni:
```bash
go build main.go
./main
```
Kisha, kutoka kwa host:
```bash
docker exec -it <container-name> /bin/sh
```
Somo kuu si utekelezaji halisi wa exploit wa kihistoria, bali athari yake katika assessment: ikiwa toleo la runtime lina vulnerability, code execution ya kawaida ndani ya container inaweza kutosha ku-compromise host hata wakati container configuration inayoonekana haionekani kuwa dhaifu waziwazi.

CVEs za hivi karibuni za runtime kama `CVE-2024-21626` katika `runc`, mount races za BuildKit, na parsing bugs za containerd zinaimarisha hoja hiyo hiyo. Toleo la runtime na patch level ni sehemu ya security boundary, si mambo ya maintenance pekee.

## Marejeo

- [1] [Breaking out of Docker via runC – Explaining CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)

{{#include ../../../banners/hacktricks-training.md}}
