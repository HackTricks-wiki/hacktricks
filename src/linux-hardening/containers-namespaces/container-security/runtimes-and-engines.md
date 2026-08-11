# Container Runtimes, Engines, Builders, Na Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Mojawapo ya vyanzo vikubwa vya mkanganyiko katika container security ni kwamba components kadhaa tofauti kabisa mara nyingi huwekwa chini ya neno moja. "Docker" inaweza kumaanisha image format, CLI, daemon, build system, runtime stack, au wazo la containers kwa ujumla. Kwa kazi za security, utata huo ni tatizo, kwa sababu layers tofauti zinawajibika kwa protections tofauti. Breakout inayosababishwa na bind mount mbaya si kitu sawa na breakout inayosababishwa na bug ya low-level runtime, na wala si sawa na kosa la cluster policy katika Kubernetes.

Ukurasa huu unatenganisha ecosystem kulingana na role ili sehemu zinazofuata ziweze kueleza kwa usahihi protection au weakness iko wapi hasa.

## OCI Kama Lugha ya Pamoja

Linux container stacks za kisasa mara nyingi huingiliana kwa sababu zinazungumza seti ya OCI specifications. **OCI Image Specification** inaeleza jinsi images na layers zinavyowakilishwa. **OCI Runtime Specification** inaeleza jinsi runtime inavyopaswa kuanzisha process, ikijumuisha namespaces, mounts, cgroups, na security settings. **OCI Distribution Specification** inasanifisha jinsi registries zinavyowasilisha content.

Hili ni muhimu kwa sababu linaeleza kwa nini container image iliyojengwa kwa tool moja mara nyingi inaweza kuendeshwa kwa nyingine, na kwa nini engines kadhaa zinaweza kushiriki low-level runtime ileile. Pia linaeleza kwa nini security behavior inaweza kuonekana sawa katika products tofauti: nyingi kati yao zinaunda OCI runtime configuration ileile na kuikabidhi kwa seti ndogo ileile ya runtimes.

## Low-Level OCI Runtimes

Low-level runtime ni component iliyo karibu zaidi na kernel boundary. Ndiyo sehemu inayounda namespaces, kuandika cgroup settings, kutumia capabilities na seccomp filters, na hatimaye kufanya `execve()` ya container process. Watu wanapozungumzia "container isolation" kwa kiwango cha mechanical, kwa kawaida wanazungumzia layer hii, hata kama hawasemi hivyo waziwazi.

### `runc`

`runc` ni reference OCI runtime na bado ndiyo implementation inayojulikana zaidi. Inatumika sana chini ya Docker, containerd, na Kubernetes deployments nyingi. Tafiti nyingi za umma na exploitation material hulenga mazingira ya `runc` kwa sababu tu ni ya kawaida na kwa sababu `runc` inaweka baseline ambayo watu wengi hufikiria wanapowazia Linux container. Kwa hiyo, kuielewa `runc` humpa msomaji mental model imara ya classic container isolation.

### `crun`

`crun` ni OCI runtime nyingine, iliyoandikwa kwa C na inayotumika sana katika mazingira ya kisasa ya Podman. Mara nyingi husifiwa kwa support nzuri ya cgroup v2, rootless ergonomics imara, na overhead ndogo. Kwa mtazamo wa security, jambo muhimu si kwamba imeandikwa kwa language tofauti, bali kwamba bado inatimiza role ileile: ni component inayobadilisha OCI configuration kuwa process tree inayoendeshwa chini ya kernel. Rootless Podman workflow mara nyingi huhisi kuwa salama zaidi si kwa sababu `crun` inarekebisha kila kitu kimiujiza, bali kwa sababu stack nzima inayoiizunguka huwa inaegemea zaidi user namespaces na least privilege.

### `runsc` Kutoka gVisor

`runsc` ni runtime inayotumiwa na gVisor. Hapa boundary inabadilika kwa kiwango kikubwa. Badala ya kupitisha syscalls nyingi moja kwa moja kwa host kernel kwa njia ya kawaida, gVisor huingiza userspace kernel layer inayosimulate au kusimamia sehemu kubwa za Linux interface. Matokeo yake si container ya kawaida ya `runc` yenye flags chache za ziada; ni sandbox design tofauti yenye lengo la kupunguza host-kernel attack surface. Tradeoffs za compatibility na performance ni sehemu ya design hiyo, kwa hiyo mazingira yanayotumia `runsc` yanapaswa kuandikwa tofauti na mazingira ya kawaida ya OCI runtime.

### `kata-runtime`

Kata Containers husukuma boundary zaidi kwa kuendesha workload ndani ya lightweight virtual machine. Kwa upande wa administration, hii bado inaweza kuonekana kama container deployment, na orchestration layers bado zinaweza kuichukulia hivyo, lakini isolation boundary ya msingi iko karibu zaidi na virtualization kuliko container ya kawaida inayoshiriki host kernel. Hii hufanya Kata kuwa muhimu pale tenant isolation yenye nguvu zaidi inapohitajika bila kuacha workflows zinazotegemea containers.

## Engines Na Container Managers

Ikiwa low-level runtime ndiyo component inayowasiliana moja kwa moja na kernel, engine au manager ndiyo component ambayo users na operators kwa kawaida huingiliana nayo. Inashughulikia image pulls, metadata, logs, networks, volumes, lifecycle operations, na API exposure. Layer hii ni muhimu sana kwa sababu compromises nyingi za ulimwengu halisi hutokea hapa: access kwa runtime socket au daemon API inaweza kuwa sawa na host compromise hata kama low-level runtime yenyewe iko salama kabisa.

### Docker Engine

Docker Engine ndiyo container platform inayotambulika zaidi kwa developers na mojawapo ya sababu zilizofanya container vocabulary iwe na mwelekeo wa Docker. Njia ya kawaida ni `docker` CLI kwenda kwa `dockerd`, ambayo nayo inaratibu lower-level components kama `containerd` na OCI runtime. Kihistoria, Docker deployments mara nyingi zimekuwa **rootful**, na hivyo access kwa Docker socket imekuwa primitive yenye nguvu sana. Ndiyo sababu practical privilege-escalation material nyingi hulenga `docker.sock`: ikiwa process inaweza kuomba `dockerd` iunde privileged container, imount host paths, au ijiunge na host namespaces, huenda isihitaji kernel exploit hata kidogo.

### Podman

Podman iliundwa kwa kuzingatia daemonless model. Kiutendaji, hii husaidia kusisitiza wazo kwamba containers ni processes tu zinazosimamiwa kupitia standard Linux mechanisms badala ya daemon moja yenye privilege inayoendelea kufanya kazi muda wote. Podman pia ina **rootless** story yenye nguvu zaidi kuliko classic Docker deployments ambazo watu wengi walijifunza mwanzoni. Hili halifanyi Podman kuwa salama moja kwa moja, lakini hubadilisha default risk profile kwa kiasi kikubwa, hasa inapounganishwa na user namespaces, SELinux, na `crun`.

### containerd

containerd ni core runtime management component katika stacks nyingi za kisasa. Inatumika chini ya Docker na pia ni mojawapo ya Kubernetes runtime backends zinazotawala. Hutoa powerful APIs, husimamia images na snapshots, na hukabidhi uundaji wa mwisho wa process kwa low-level runtime. Majadiliano ya security kuhusu containerd yanapaswa kusisitiza kwamba access kwa containerd socket au functionality ya `ctr`/`nerdctl` inaweza kuwa hatari sawa na access kwa Docker API, hata kama interface na workflow vinaonekana kuwa na urafiki mdogo kwa "developer".

### CRI-O

CRI-O inalenga eneo dogo zaidi kuliko Docker Engine. Badala ya kuwa developer platform ya matumizi ya jumla, imejengwa kuhusiana na kutekeleza Kubernetes Container Runtime Interface kwa usafi. Hii huifanya itumike sana katika Kubernetes distributions na ecosystems zinazotumia SELinux kwa kiwango kikubwa kama OpenShift. Kwa mtazamo wa security, scope hii finyu ni muhimu kwa sababu inapunguza conceptual clutter: CRI-O ni sehemu ya layer ya "run containers for Kubernetes" badala ya kuwa everything-platform.

### Incus, LXD, Na LXC

Incus/LXD/LXC systems zinapaswa kutenganishwa na application containers za mtindo wa Docker kwa sababu mara nyingi hutumika kama **system containers**. System container kwa kawaida inatarajiwa kufanana zaidi na machine nyepesi yenye userspace kamili zaidi, services zinazoendelea kufanya kazi, device exposure pana zaidi, na host integration kubwa zaidi. Isolation mechanisms bado ni kernel primitives, lakini matarajio ya kiutendaji ni tofauti. Kwa sababu hiyo, misconfigurations hapa mara nyingi huonekana chini ya "bad app-container defaults" na zaidi kama makosa katika lightweight virtualization au host delegation.

### systemd-nspawn

systemd-nspawn iko katika nafasi ya kuvutia kwa sababu ni systemd-native na ni muhimu sana kwa testing, debugging, na kuendesha environments zinazofanana na OS. Si production runtime inayotawala cloud-native, lakini huonekana mara nyingi katika labs na environments zinazolenga distros kiasi cha kustahili kutajwa. Kwa security analysis, ni ukumbusho mwingine kwamba dhana ya "container" inahusisha ecosystems na operational styles nyingi.

### Apptainer / Singularity

Apptainer (zamani Singularity) hutumika sana katika research na HPC environments. Trust assumptions, user workflow, na execution model zake hutofautiana kwa njia muhimu na stacks zinazozingatia Docker/Kubernetes. Hasa, environments hizi mara nyingi hujali sana kuwawezesha users kuendesha packaged workloads bila kuwapa powers pana za privileged container-management. Ikiwa reviewer atadhani kila container environment kimsingi ni "Docker kwenye server", ataelewa deployments hizi vibaya sana.

## Build-Time Tooling

Majadiliano mengi ya security huzungumzia run time pekee, lakini build-time tooling pia ni muhimu kwa sababu huamua image contents, build secrets exposure, na kiasi cha trusted context kinachowekwa ndani ya artifact ya mwisho.

**BuildKit** na `docker buildx` ni modern build backends zinazosaidia features kama caching, secret mounting, SSH forwarding, na multi-platform builds. Hizi ni features muhimu, lakini kwa mtazamo wa security pia huunda maeneo ambayo secrets zinaweza kuleak ndani ya image layers au ambapo build context iliyo pana kupita kiasi inaweza kufichua files ambazo hazikupaswa kabisa kujumuishwa. **Buildah** hutimiza role inayofanana katika OCI-native ecosystems, hasa karibu na Podman, wakati **Kaniko** hutumika mara nyingi katika CI environments ambazo hazitaki kuipa build pipeline privileged Docker daemon.

Somo kuu ni kwamba image creation na image execution ni phases tofauti, lakini weak build pipeline inaweza kuunda weak runtime posture muda mrefu kabla container haija-launchiwa.

## Orchestration Ni Layer Nyingine, Si Runtime

Kubernetes haipaswi kufikiriwa kuwa sawa na runtime yenyewe. Kubernetes ni orchestrator. Hupanga Pods, huhifadhi desired state, na huonyesha security policy kupitia workload configuration. Kisha kubelet huwasiliana na CRI implementation kama containerd au CRI-O, ambayo nayo huita low-level runtime kama `runc`, `crun`, `runsc`, au `kata-runtime`.

Utengano huu ni muhimu kwa sababu watu wengi huhusisha protection na "Kubernetes" wakati kwa kweli inatekelezwa na node runtime, au hulalamikia "containerd defaults" kwa behavior iliyotokana na Pod spec. Kiutendaji, final security posture ni composition: orchestrator huomba kitu, runtime stack huitafsiri, na kernel hatimaye huitekeleza.

## Kwa Nini Runtime Identification Ni Muhimu Wakati wa Assessment

Ukitambua engine na runtime mapema, observations nyingi za baadaye huwa rahisi kutafsiri. Rootless Podman container inaashiria kwamba user namespaces huenda ni sehemu ya maelezo. Docker socket iliyomountiwa ndani ya workload inaashiria kwamba API-driven privilege escalation ni njia halisi. CRI-O/OpenShift node inapaswa kukufanya mara moja ufikirie SELinux labels na restricted workload policy. Mazingira ya gVisor au Kata yanapaswa kukufanya uwe mwangalifu zaidi kabla ya kudhani kwamba classic `runc` breakout PoC itafanya kazi kwa namna ileile.

Ndiyo sababu mojawapo ya hatua za kwanza katika container assessment inapaswa kuwa kujibu maswali mawili rahisi: **ni component gani inayosimamia container** na **ni runtime gani hasa iliyo-launch process**. Majibu hayo yakishakuwa wazi, environment iliyobaki kwa kawaida huwa rahisi zaidi kuielewa.

## Runtime Vulnerabilities

Si kila container escape hutokana na operator misconfiguration. Wakati mwingine runtime yenyewe ndiyo component iliyo vulnerable. Hili ni muhimu kwa sababu workload inaweza kuwa inaendeshwa kwa configuration inayoonekana kuwa makini, lakini bado ikawa exposed kupitia low-level runtime flaw.

Mfano wa classic ni **CVE-2019-5736** katika `runc`, ambapo malicious container ingeweza ku-overwrite host `runc` binary na kisha kusubiri `docker exec` ya baadaye au runtime invocation inayofanana ili ku-trigger attacker-controlled code. Exploit path ni tofauti sana na bind-mount au capability mistake rahisi kwa sababu inatumia namna runtime inavyoingia tena kwenye container process space wakati wa kushughulikia exec.<sup>[[1]](#references)</sup>

Minimal reproduction workflow kutoka red-team perspective ni:
```bash
go build main.go
./main
```
Kisha, kutoka kwenye host:
```bash
docker exec -it <container-name> /bin/sh
```
Somo kuu si utekelezaji halisi wa exploit wa kihistoria, bali ni maana yake katika tathmini: ikiwa toleo la runtime lina udhaifu, code execution ya kawaida ndani ya container inaweza kutosha kuathiri host hata wakati configuration inayoonekana ya container haionekani kuwa dhaifu waziwazi.

CVE za hivi karibuni za runtime kama vile `CVE-2024-21626` katika `runc`, mount races za BuildKit, na parsing bugs za containerd zinaimarisha hoja hiyo hiyo. Toleo la runtime na kiwango cha patches ni sehemu ya security boundary, si masuala ya matengenezo tu.

## References

- [1] [Kuvuka kutoka Docker kupitia runC – Kueleza CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
