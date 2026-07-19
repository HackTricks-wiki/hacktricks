# Container Runtimes, Engines, Builders, Na Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Mojawapo ya vyanzo vikubwa vya mkanganyiko katika container security ni kwamba components kadhaa tofauti kabisa mara nyingi huwekwa chini ya neno moja. "Docker" inaweza kumaanisha image format, CLI, daemon, build system, runtime stack, au tu dhana ya containers kwa ujumla. Kwa kazi za security, utata huo ni tatizo, kwa sababu layers tofauti zinawajibika kwa protections tofauti. Breakout inayosababishwa na bind mount mbaya si kitu sawa na breakout inayosababishwa na low-level runtime bug, na wala si sawa na kosa la cluster policy katika Kubernetes.

Ukurasa huu unatenganisha ecosystem kwa roles ili sehemu iliyobaki iweze kueleza kwa usahihi protection au weakness ipo wapi hasa.

## OCI Kama Common Language

Modern Linux container stacks mara nyingi huingiliana kwa sababu zinazungumza seti ya OCI specifications. **OCI Image Specification** inaeleza jinsi images na layers zinavyowakilishwa. **OCI Runtime Specification** inaeleza jinsi runtime inavyopaswa kuanzisha process, ikiwemo namespaces, mounts, cgroups, na security settings. **OCI Distribution Specification** inasawazisha jinsi registries zinavyowasilisha content.

Hili ni muhimu kwa sababu linaeleza kwa nini container image iliyotengenezwa kwa tool moja mara nyingi inaweza kuendeshwa kwa nyingine, na kwa nini engines kadhaa zinaweza kushiriki low-level runtime moja. Pia linaeleza kwa nini security behavior inaweza kufanana katika products tofauti: nyingi kati yao zinatengeneza OCI runtime configuration ileile na kuikabidhi kwa seti ileile ndogo ya runtimes.

## Low-Level OCI Runtimes

Low-level runtime ni component iliyo karibu zaidi na kernel boundary. Ndiyo sehemu inayounda namespaces, kuandika cgroup settings, kutumia capabilities na seccomp filters, na hatimaye kufanya `execve()` ya container process. Watu wanapozungumzia "container isolation" katika kiwango cha kimfumo, kwa kawaida wanazungumzia layer hii, hata kama hawasemi hivyo waziwazi.

### `runc`

`runc` ni reference OCI runtime na bado ndiyo implementation inayojulikana zaidi. Inatumika sana chini ya Docker, containerd, na Kubernetes deployments nyingi. Utafiti mwingi wa public na exploitation material hulenga mazingira ya aina ya `runc` kwa sababu ni ya kawaida na kwa sababu `runc` inaweka baseline ambayo watu wengi hufikiria wanapoona Linux container. Kwa hiyo, kuelewa `runc` humpa msomaji mental model imara ya classic container isolation.

### `crun`

`crun` ni OCI runtime nyingine, iliyoandikwa kwa C na inayotumika sana katika modern Podman environments. Mara nyingi husifiwa kwa cgroup v2 support nzuri, rootless ergonomics imara, na overhead ndogo. Kwa mtazamo wa security, jambo muhimu si kwamba imeandikwa kwa language tofauti, bali kwamba bado inatekeleza role ileile: ni component inayobadilisha OCI configuration kuwa process tree inayoendeshwa chini ya kernel. Rootless Podman workflow mara nyingi huonekana kuwa salama zaidi si kwa sababu `crun` inarekebisha kila kitu kimiujiza, bali kwa sababu stack nzima inayoizunguka kwa kawaida hutumia user namespaces na least privilege kwa nguvu zaidi.

### `runsc` Kutoka gVisor

`runsc` ni runtime inayotumiwa na gVisor. Hapa boundary hubadilika kwa kiwango kikubwa. Badala ya kupitisha syscalls nyingi moja kwa moja kwa host kernel kwa njia ya kawaida, gVisor huingiza userspace kernel layer inayoiga au kudhibiti sehemu kubwa za Linux interface. Matokeo si `runc` container ya kawaida yenye flags chache za ziada; ni sandbox design tofauti yenye lengo la kupunguza host-kernel attack surface. Compatibility na performance tradeoffs ni sehemu ya design hiyo, hivyo environments zinazotumia `runsc` zinapaswa kuandikwa tofauti na normal OCI runtime environments.

### `kata-runtime`

Kata Containers husogeza boundary zaidi kwa kuendesha workload ndani ya lightweight virtual machine. Kwa upande wa administration, hii bado inaweza kuonekana kama container deployment, na orchestration layers bado zinaweza kuichukulia hivyo, lakini isolation boundary ya msingi iko karibu zaidi na virtualization kuliko container ya kawaida inayoshiriki host kernel. Hii huifanya Kata iwe muhimu wakati tenant isolation yenye nguvu zaidi inahitajika bila kuacha container-centric workflows.

## Engines Na Container Managers

Ikiwa low-level runtime ndiyo component inayowasiliana moja kwa moja na kernel, engine au manager ndiyo component ambayo users na operators kwa kawaida huingiliana nayo. Inashughulikia image pulls, metadata, logs, networks, volumes, lifecycle operations, na API exposure. Layer hii ni muhimu sana kwa sababu compromises nyingi za real-world hutokea hapa: access ya runtime socket au daemon API inaweza kuwa sawa na host compromise hata kama low-level runtime yenyewe iko salama kabisa.

### Docker Engine

Docker Engine ndiyo container platform inayotambulika zaidi kwa developers na mojawapo ya sababu zilizofanya container vocabulary iwe na mwelekeo mkubwa wa Docker. Njia ya kawaida ni `docker` CLI kwenda `dockerd`, ambayo kwa upande wake huratibu lower-level components kama `containerd` na OCI runtime. Kihistoria, Docker deployments mara nyingi zimekuwa **rootful**, na kwa hiyo access ya Docker socket imekuwa primitive yenye nguvu sana. Hii ndiyo sababu practical privilege-escalation material nyingi hulenga `docker.sock`: ikiwa process inaweza kuiomba `dockerd` iunde privileged container, iimount host paths, au ijiunge na host namespaces, huenda isihitaji kernel exploit kabisa.

### Podman

Podman iliundwa kwa kuzingatia daemonless model zaidi. Kwa upande wa operations, hii husaidia kusisitiza wazo kwamba containers ni processes tu zinazosimamiwa kupitia standard Linux mechanisms badala ya daemon moja ya privileged inayoendelea kwa muda mrefu. Podman pia ina **rootless** story yenye nguvu zaidi kuliko classic Docker deployments ambazo watu wengi walijifunza mwanzoni. Hii haifanyi Podman iwe salama moja kwa moja, lakini inabadilisha default risk profile kwa kiasi kikubwa, hasa inapounganishwa na user namespaces, SELinux, na `crun`.

### containerd

containerd ni core runtime management component katika stacks nyingi za kisasa. Inatumika chini ya Docker na pia ni mojawapo ya Kubernetes runtime backends zinazoongoza. Ina-expose powerful APIs, inasimamia images na snapshots, na hukabidhi process creation ya mwisho kwa low-level runtime. Security discussions kuhusu containerd zinapaswa kusisitiza kwamba access ya containerd socket au `ctr`/`nerdctl` functionality inaweza kuwa hatari sawa na access ya Docker API, hata kama interface na workflow vinaonekana kutokuwa "developer friendly" sana.

### CRI-O

CRI-O ina scope finyu zaidi kuliko Docker Engine. Badala ya kuwa general-purpose developer platform, imejengwa kwa kuzingatia kutekeleza Kubernetes Container Runtime Interface kwa usafi. Hii huifanya itumike sana katika Kubernetes distributions na SELinux-heavy ecosystems kama OpenShift. Kwa mtazamo wa security, scope hii finyu ni muhimu kwa sababu inapunguza conceptual clutter: CRI-O ni sehemu ya layer ya "run containers for Kubernetes", si everything-platform.

### Incus, LXD, Na LXC

Incus/LXD/LXC systems zinapaswa kutenganishwa na Docker-style application containers kwa sababu mara nyingi hutumiwa kama **system containers**. System container kwa kawaida inatarajiwa kufanana zaidi na lightweight machine yenye fuller userspace, long-running services, richer device exposure, na host integration pana zaidi. Isolation mechanisms bado ni kernel primitives, lakini operational expectations ni tofauti. Kwa hiyo, misconfigurations hapa mara nyingi huonekana kama makosa katika lightweight virtualization au host delegation, badala ya "bad app-container defaults".

### systemd-nspawn

systemd-nspawn iko katika nafasi ya kuvutia kwa sababu ni systemd-native na ni muhimu sana kwa testing, debugging, na kuendesha OS-like environments. Si production runtime inayotawala katika cloud-native, lakini huonekana mara nyingi vya kutosha katika labs na distro-oriented environments kiasi cha kustahili kutajwa. Kwa security analysis, ni ukumbusho mwingine kwamba dhana ya "container" inahusisha ecosystems na operational styles nyingi.

### Apptainer / Singularity

Apptainer (zamani Singularity) hutumika sana katika research na HPC environments. Trust assumptions, user workflow, na execution model zake hutofautiana kwa njia muhimu na stacks zinazozingatia Docker/Kubernetes. Hasa, environments hizi mara nyingi zinahitaji sana users waweze kuendesha packaged workloads bila kupewa broad privileged container-management powers. Ikiwa reviewer atadhani kila container environment kimsingi ni "Docker kwenye server", ataelewa deployments hizi vibaya sana.

## Build-Time Tooling

Security discussions nyingi huzungumzia run time pekee, lakini build-time tooling pia ni muhimu kwa sababu huamua image contents, build secrets exposure, na kiasi cha trusted context kinachoingizwa kwenye final artifact.

**BuildKit** na `docker buildx` ni modern build backends zinazosaidia features kama caching, secret mounting, SSH forwarding, na multi-platform builds. Hizi ni features muhimu, lakini kwa mtazamo wa security pia huunda maeneo ambapo secrets zinaweza ku-leak kwenye image layers au ambapo build context iliyo pana kupita kiasi inaweza kufichua files ambazo hazikupaswa kujumuishwa kamwe. **Buildah** ina role inayofanana katika OCI-native ecosystems, hasa karibu na Podman, huku **Kaniko** ikitumika mara nyingi katika CI environments ambazo hazitaki kuipa build pipeline privileged Docker daemon.

Somo kuu ni kwamba image creation na image execution ni phases tofauti, lakini weak build pipeline inaweza kuunda weak runtime posture muda mrefu kabla container haijazinduliwa.

## Orchestration Ni Layer Nyingine, Si Runtime

Kubernetes haipaswi kuhusishwa kiakili na runtime yenyewe. Kubernetes ni orchestrator. Inaschedule Pods, huhifadhi desired state, na huonyesha security policy kupitia workload configuration. Kisha kubelet huwasiliana na CRI implementation kama containerd au CRI-O, ambayo kwa upande wake huinvoke low-level runtime kama `runc`, `crun`, `runsc`, au `kata-runtime`.

Utengano huu ni muhimu kwa sababu watu wengi huhusisha protection fulani na "Kubernetes" wakati kwa kweli inatekelezwa na node runtime, au huwalaumu "containerd defaults" kwa behavior iliyotokana na Pod spec. Kwa vitendo, final security posture ni composition: orchestrator huomba kitu, runtime stack hukitafsiri, na kernel hatimaye hukitekeleza.

## Kwa Nini Runtime Identification Ni Muhimu Wakati Wa Assessment

Ukitambua engine na runtime mapema, observations nyingi za baadaye huwa rahisi kutafsiri. Rootless Podman container inaashiria kwamba user namespaces huenda ni sehemu ya story. Docker socket iliyomountiwa ndani ya workload inaashiria kwamba API-driven privilege escalation ni path halisi. CRI-O/OpenShift node inapaswa mara moja kukufanya ufikirie SELinux labels na restricted workload policy. gVisor au Kata environment inapaswa kukufanya uwe mwangalifu zaidi unapodhani kwamba classic `runc` breakout PoC itafanya kazi kwa njia ileile.

Ndiyo sababu moja ya hatua za kwanza katika container assessment inapaswa kuwa kujibu maswali mawili rahisi: **ni component gani inayosimamia container** na **ni runtime gani iliyozindua process**. Majibu hayo yakishajulikana, mazingira yaliyobaki kwa kawaida huwa rahisi zaidi kuyachanganua.

## Runtime Vulnerabilities

Si kila container escape inatokana na operator misconfiguration. Wakati mwingine runtime yenyewe ndiyo component iliyo vulnerable. Hili ni muhimu kwa sababu workload inaweza kuwa inaendeshwa kwa configuration inayoonekana kuwa makini na bado ikawa exposed kupitia low-level runtime flaw.

Mfano wa classic ni **CVE-2019-5736** katika `runc`, ambapo malicious container ingeweza ku-overwrite host `runc` binary na kisha kusubiri `docker exec` ya baadaye au runtime invocation inayofanana ili ku-trigger attacker-controlled code. Exploit path ni tofauti sana na simple bind-mount au capability mistake kwa sababu inatumia jinsi runtime inavyoingia tena kwenye container process space wakati wa kushughulikia exec.

Minimal reproduction workflow kutoka mtazamo wa red-team ni:
```bash
go build main.go
./main
```
Kisha, kutoka kwenye host:
```bash
docker exec -it <container-name> /bin/sh
```
Somo kuu si utekelezaji kamili wa kihistoria wa exploit, bali ni athari kwa tathmini: ikiwa toleo la runtime lina vulnerability, kutekeleza code ya kawaida ndani ya container kunaweza kutosha ku-compromise host hata wakati configuration inayoonekana ya container haionekani kuwa dhaifu waziwazi.

CVE za hivi karibuni za runtime kama `CVE-2024-21626` katika `runc`, mashindano ya mount ya BuildKit, na bugs za parsing za containerd zinaimarisha hoja hiyo hiyo. Toleo la runtime na kiwango cha patch ni sehemu ya security boundary, si masuala ya maintenance tu.
{{#include ../../../banners/hacktricks-training.md}}
