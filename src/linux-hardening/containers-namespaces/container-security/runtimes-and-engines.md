# Container Runtimes, Engines, Builders, And Sandboxes

Mojawapo ya vyanzo vikubwa vya mkanganyiko katika container security ni kwamba components kadhaa tofauti kabisa mara nyingi huwekwa chini ya neno moja. "Docker" inaweza kumaanisha image format, CLI, daemon, build system, runtime stack, au wazo la containers kwa ujumla. Katika kazi za security, utata huo ni tatizo kwa sababu layers tofauti zinawajibika kwa protections tofauti. Breakout inayosababishwa na bind mount mbaya si kitu sawa na breakout inayosababishwa na low-level runtime bug, na wala si sawa na kosa la cluster policy katika Kubernetes.

Ukurasa huu unatenganisha ecosystem kulingana na role ili sehemu iliyobaki iweze kueleza kwa usahihi protection au weakness iko wapi hasa.

## OCI As The Common Language

Modern Linux container stacks mara nyingi huingiliana kwa sababu zinatumia seti ya OCI specifications. **OCI Image Specification** inaeleza jinsi images na layers zinavyowakilishwa. **OCI Runtime Specification** inaeleza jinsi runtime inavyopaswa kuanzisha process, ikijumuisha namespaces, mounts, cgroups, na security settings. **OCI Distribution Specification** inasanifisha jinsi registries zinavyowasilisha content.

Hili ni muhimu kwa sababu linaeleza kwa nini container image iliyojengwa kwa tool moja mara nyingi inaweza kuendeshwa na nyingine, na kwa nini engines kadhaa zinaweza kushiriki low-level runtime ileile. Pia linaeleza kwa nini security behavior inaweza kuonekana sawa katika products tofauti: nyingi kati yake zinaunda OCI runtime configuration ileile na kuikabidhi kwa seti ileile ndogo ya runtimes.

## Low-Level OCI Runtimes

Low-level runtime ni component iliyo karibu zaidi na kernel boundary. Ndiyo sehemu inayounda namespaces, kuandika cgroup settings, kutumia capabilities na seccomp filters, na hatimaye kufanya `execve()` ya container process. Watu wanapojadili "container isolation" katika kiwango cha mechanical, kwa kawaida wanazungumzia layer hii, hata kama hawasemi hivyo waziwazi.

### `runc`

`runc` ni reference OCI runtime na bado ndiyo implementation inayojulikana zaidi. Inatumika sana chini ya Docker, containerd, na deployments nyingi za Kubernetes. Utafiti mwingi wa umma na exploitation material hulenga mazingira ya mtindo wa `runc` kwa sababu tu ni ya kawaida, na kwa sababu `runc` huweka baseline ambayo watu wengi hufikiria wanapowazia Linux container. Kwa hiyo, kuelewa `runc` humpa msomaji mental model imara ya classic container isolation.

### `crun`

`crun` ni OCI runtime nyingine, iliyoandikwa kwa C na inayotumika sana katika modern Podman environments. Mara nyingi husifiwa kwa support nzuri ya cgroup v2, rootless ergonomics nzuri, na overhead ndogo. Kwa mtazamo wa security, jambo muhimu si kwamba imeandikwa kwa language tofauti, bali bado ina role ileile: ni component inayogeuza OCI configuration kuwa process tree inayoendeshwa chini ya kernel. Rootless Podman workflow mara nyingi huonekana kuwa salama zaidi si kwa sababu `crun` hurekebisha kila kitu kichawi, bali kwa sababu stack nzima inayokizunguka kwa kawaida hutegemea zaidi user namespaces na least privilege.

### `runsc` From gVisor

`runsc` ni runtime inayotumiwa na gVisor. Hapa boundary hubadilika kwa kiasi kikubwa. Badala ya kupitisha syscalls nyingi moja kwa moja kwa host kernel kwa njia ya kawaida, gVisor huweka userspace kernel layer inayosimulate au kusimamia sehemu kubwa za Linux interface. Matokeo yake si normal `runc` container yenye flags chache za ziada; ni sandbox design tofauti yenye lengo la kupunguza host-kernel attack surface. Compatibility na performance tradeoffs ni sehemu ya design hiyo, hivyo environments zinazotumia `runsc` zinapaswa kuandikwa tofauti na normal OCI runtime environments.

### `kata-runtime`

Kata Containers husukuma boundary zaidi kwa kuanzisha workload ndani ya lightweight virtual machine. Kwa upande wa administration, hii bado inaweza kuonekana kama container deployment, na orchestration layers bado zinaweza kuichukulia hivyo, lakini isolation boundary ya msingi iko karibu zaidi na virtualization kuliko container ya kawaida inayoshiriki host kernel. Hii hufanya Kata iwe muhimu wakati tenant isolation yenye nguvu zaidi inahitajika bila kuacha container-centric workflows.

## Engines And Container Managers

Ikiwa low-level runtime ni component inayozungumza moja kwa moja na kernel, engine au manager ni component ambayo users na operators kwa kawaida huingiliana nayo. Inashughulikia image pulls, metadata, logs, networks, volumes, lifecycle operations, na API exposure. Layer hii ni muhimu sana kwa sababu compromises nyingi za ulimwengu halisi hutokea hapa: access kwa runtime socket au daemon API inaweza kuwa sawa na host compromise hata kama low-level runtime yenyewe iko salama kabisa.

### Docker Engine

Docker Engine ndiyo container platform inayotambulika zaidi na developers, na ni mojawapo ya sababu zilizofanya container vocabulary iwe na mwelekeo mkubwa wa Docker. Njia ya kawaida ni kutoka `docker` CLI hadi `dockerd`, ambayo baadaye huratibu lower-level components kama `containerd` na OCI runtime. Kihistoria, Docker deployments mara nyingi zimekuwa **rootful**, hivyo access kwa Docker socket imekuwa primitive yenye nguvu sana. Ndiyo maana practical privilege-escalation material nyingi hulenga `docker.sock`: ikiwa process inaweza kuomba `dockerd` iunde privileged container, iimount host paths, au ijiunge na host namespaces, huenda isihitaji kernel exploit kabisa.

### Podman

Podman iliundwa ikizingatia daemonless model zaidi. Kiutendaji, hii husaidia kusisitiza wazo kwamba containers ni processes zinazosimamiwa kupitia standard Linux mechanisms, badala ya daemon moja ya privileged inayoendelea kuendesha. Podman pia ina rootless story yenye nguvu zaidi kuliko classic Docker deployments ambazo watu wengi walijifunza mwanzoni. Hilo halifanyi Podman iwe salama moja kwa moja, lakini hubadilisha kwa kiasi kikubwa default risk profile, hasa inapounganishwa na user namespaces, SELinux, na `crun`.

### containerd

containerd ni core runtime management component katika modern stacks nyingi. Inatumika chini ya Docker na pia ni mojawapo ya Kubernetes runtime backends zinazotawala. Inaonyesha powerful APIs, inasimamia images na snapshots, na hukabidhi process creation ya mwisho kwa low-level runtime. Majadiliano ya security kuhusu containerd yanapaswa kusisitiza kwamba access kwa containerd socket au `ctr`/`nerdctl` functionality inaweza kuwa hatari sawa na access kwa Docker API, hata kama interface na workflow vinaonekana kuwa si vya "developer friendly" sana.

### CRI-O

CRI-O ina scope ndogo kuliko Docker Engine. Badala ya kuwa general-purpose developer platform, imejengwa kuzunguka kutekeleza Kubernetes Container Runtime Interface kwa usafi. Hii huifanya itumike sana katika Kubernetes distributions na SELinux-heavy ecosystems kama OpenShift. Kwa mtazamo wa security, scope hii finyu ni muhimu kwa sababu hupunguza conceptual clutter: CRI-O ni sehemu ya layer ya "run containers for Kubernetes", badala ya kuwa everything-platform.

### Incus, LXD, And LXC

Incus/LXD/LXC systems zinapaswa kutenganishwa na Docker-style application containers kwa sababu mara nyingi hutumiwa kama **system containers**. System container kwa kawaida inatarajiwa kufanana zaidi na lightweight machine yenye fuller userspace, long-running services, richer device exposure, na host integration pana zaidi. Isolation mechanisms bado ni kernel primitives, lakini operational expectations ni tofauti. Kwa sababu hiyo, misconfigurations hapa mara nyingi huonekana chini ya "bad app-container defaults" na zaidi kama makosa katika lightweight virtualization au host delegation.

### systemd-nspawn

systemd-nspawn ina nafasi ya kuvutia kwa sababu ni systemd-native na ni muhimu sana kwa testing, debugging, na kuendesha OS-like environments. Si production runtime inayotawala katika cloud-native, lakini huonekana mara nyingi katika labs na distro-oriented environments kiasi cha kustahili kutajwa. Kwa security analysis, ni ukumbusho mwingine kwamba dhana ya "container" inahusisha ecosystems na operational styles mbalimbali.

### Apptainer / Singularity

Apptainer (zamani Singularity) hutumika sana katika research na HPC environments. Trust assumptions, user workflow, na execution model zake hutofautiana kwa njia muhimu na stacks zinazolenga Docker/Kubernetes. Hasa, environments hizi mara nyingi hujali sana kuwawezesha users kuendesha packaged workloads bila kuwapa container-management powers pana za privileged. Ikiwa reviewer anadhani kila container environment kimsingi ni "Docker on a server", ataelewa deployments hizi vibaya sana.

## Build-Time Tooling

Majadiliano mengi ya security huzungumzia run time pekee, lakini build-time tooling pia ni muhimu kwa sababu huamua image contents, build secrets exposure, na kiasi cha trusted context kinachoingizwa katika final artifact.

**BuildKit** na `docker buildx` ni modern build backends zinazounga mkono features kama caching, secret mounting, SSH forwarding, na multi-platform builds. Hizo ni features muhimu, lakini kwa mtazamo wa security pia huunda maeneo ambayo secrets zinaweza ku-leak kwenye image layers au ambapo build context iliyo pana kupita kiasi inaweza kufichua files ambazo hazikupaswa kamwe kujumuishwa. **Buildah** ina role inayofanana katika OCI-native ecosystems, hasa karibu na Podman, huku **Kaniko** ikitumika mara nyingi katika CI environments ambazo hazitaki kumpa build pipeline privileged Docker daemon.

Somo kuu ni kwamba image creation na image execution ni phases tofauti, lakini weak build pipeline inaweza kuunda weak runtime posture muda mrefu kabla container haija запуска.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes haipaswi kufikiriwa kuwa ni runtime yenyewe. Kubernetes ni orchestrator. Inaschedule Pods, huhifadhi desired state, na huonyesha security policy kupitia workload configuration. Kisha kubelet huzungumza na CRI implementation kama containerd au CRI-O, ambayo nayo huita low-level runtime kama `runc`, `crun`, `runsc`, au `kata-runtime`.

Utenganishaji huu ni muhimu kwa sababu watu wengi huhusisha protection na "Kubernetes" wakati kwa kweli inatekelezwa na node runtime, au huwalaumu "containerd defaults" kwa behavior iliyotokana na Pod spec. Kiutendaji, final security posture ni composition: orchestrator huomba kitu, runtime stack huitafsiri, na hatimaye kernel huilazimisha.

## Why Runtime Identification Matters During Assessment

Ukitambua engine na runtime mapema, observations nyingi za baadaye huwa rahisi kutafsiri. Rootless Podman container inaashiria kwamba user namespaces huenda ni sehemu ya story. Docker socket iliyomountiwa ndani ya workload inaashiria kwamba API-driven privilege escalation ni njia halisi. CRI-O/OpenShift node inapaswa mara moja kukufanya ufikirie kuhusu SELinux labels na restricted workload policy. gVisor au Kata environment inapaswa kukufanya uwe mwangalifu zaidi kabla ya kudhani kwamba classic `runc` breakout PoC itafanya kazi kwa njia ileile.

Ndiyo maana moja ya hatua za kwanza katika container assessment inapaswa kuwa kujibu maswali mawili rahisi: **ni component gani inayosimamia container** na **ni runtime gani hasa iliyoanzisha process**. Majibu hayo yakishajulikana, mazingira yaliyobaki huwa rahisi zaidi kuyafahamu.

## Runtime Vulnerabilities

Si kila container escape hutokana na operator misconfiguration. Wakati mwingine runtime yenyewe ndiyo component iliyo vulnerable. Hili ni muhimu kwa sababu workload inaweza kuwa inaendeshwa kwa configuration inayoonekana kuwa makini, lakini bado ikawa exposed kupitia low-level runtime flaw.

Mfano wa classic ni **CVE-2019-5736** katika `runc`, ambapo malicious container ingeweza ku-overwrite host `runc` binary na kisha kusubiri `docker exec` ya baadaye au runtime invocation inayofanana ili kuchochea attacker-controlled code. Exploit path ni tofauti sana na simple bind-mount au capability mistake kwa sababu inatumia jinsi runtime inavyoingia tena kwenye container process space wakati wa exec handling.<sup>[[1]](#references)</sup>

Minimal reproduction workflow kutoka red-team perspective ni:
```bash
go build main.go
./main
```
Kisha, kutoka kwa host:
```bash
docker exec -it <container-name> /bin/sh
```
Somo kuu si utekelezaji halisi wa exploit wa kihistoria, bali ni athari yake katika assessment: ikiwa toleo la runtime lina vulnerability, code execution ya kawaida ndani ya container inaweza kutosha kucompromise host hata wakati configuration inayoonekana ya container haionekani kuwa dhaifu waziwazi.

CVE za hivi karibuni za runtime kama `CVE-2024-21626` katika `runc`, mount races za BuildKit, na parsing bugs za containerd zinaimarisha hoja hiyo hiyo. Toleo la runtime na kiwango cha patches ni sehemu ya security boundary, si masuala ya kawaida ya maintenance tu.

## References

- [1] [Kutoka kwenye Docker kupitia runC – Kueleza CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
