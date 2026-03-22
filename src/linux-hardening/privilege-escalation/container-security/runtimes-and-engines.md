# Runtimes za Container, Engines, Builders, na Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Moja ya vyanzo vikubwa vya mkanganyiko katika usalama wa container ni kwamba vipengele tofauti kabisa mara nyingi huunganishwa chini ya neno moja. "Docker" inaweza kumaanisha image format, CLI, daemon, mfumo wa kujenga, runtime stack, au kwa urahisi wazo la containers kwa ujumla. Kwa kazi za usalama, kutokuwa wazi hili ni tatizo, kwa sababu tabaka tofauti zinawajibika kwa ulinzi tofauti. Ku-breakout kutokana na bind mount mbaya sio sawa na breakout inayosababishwa na mdudu wa runtime wa ngazi ya chini, na wala si sawa na kosa la sera za cluster katika Kubernetes.

Ukurasa huu unatafsanya ekosistimu kwa nafasi ili sehemu nyingine ya sura iweze kuzungumzia kwa usahihi wapi ulinzi au udhaifu upo.

## OCI Kama Lugha ya Pamoja

Miradi ya kisasa ya container kwenye Linux mara nyingi zinaendana kwa sababu zinazungumza seti ya vipimo vya OCI. The **OCI Image Specification** inaelezea jinsi images na layers zinavyowakilishwa. The **OCI Runtime Specification** inaelezea jinsi runtime inavyotakiwa kuzindua mchakato, ikiwa ni pamoja na namespaces, mounts, cgroups, na mipangilio ya usalama. The **OCI Distribution Specification** inasawazisha jinsi registries zinavyoonyesha maudhui.

Hii ni muhimu kwa sababu inafafanua kwa nini image iliyojengwa kwa kuchukua zana moja mara nyingi inaweza kuendeshwa na nyingine, na kwa nini engines kadhaa zinaweza kushiriki runtime sawa ya ngazi ya chini. Pia inaelezea kwa nini tabia za usalama zinaweza kuonekana kama sawa katika bidhaa tofauti: nyingi yao zinaunda usanidi uleule wa OCI runtime na kuipeleka kwa seti ndogo ya runtimes.

## Low-Level OCI Runtimes

Low-level runtime ni kipengele kilicho karibu kabisa na mpaka wa kernel. Ndiyo sehemu inayounda namespaces, kuandika mipangilio ya cgroup, kutumia capabilities na seccomp filters, na hatimaye `execve()` mchakato wa container. Wakati watu wanajadili "container isolation" kwa ngazi ya kifaa, hii ndilo tabaka wanazokuwa wakiongelea kawaida, hata ikiwa hawataki kusema hivyo wazi.

### `runc`

`runc` ni reference OCI runtime na hubaki utekelezaji unaojulikana zaidi. Inatumiwa sana chini ya Docker, containerd, na deployments nyingi za Kubernetes. Tafiti nyingi za umma na nyenzo za exploitation zinaelekezwa kwa mazingira ya `runc` kwa sababu ni ya kawaida na kwa sababu `runc` inaweka msingi ambao watu wengi wanafikiri wakati wanapofikiria container ya Linux. Kuelewa `runc` kunampa msomaji mfano thabiti wa kifikira kuhusu isolation ya kawaida ya container.

### `crun`

`crun` ni runtime nyingine ya OCI, imeandikwa kwa C na inatumiwa sana katika mazingira ya kisasa ya Podman. Mara nyingi inasifiwa kwa msaada mzuri wa cgroup v2, ergonomics nzuri za rootless, na overhead ndogo. Kwa mtazamo wa usalama, jambo muhimu sio kwamba imeandikwa kwa lugha tofauti, bali kwamba bado inacheza jukumu lilelile: ni sehemu inayogeuza usanidi wa OCI kuwa mti wa michakato unaoendelea chini ya kernel. Mtiririko wa kazi wa Podman bila root mara nyingi hufanya iwe salama zaidi si kwa sababu `crun` inaondoa kila shida, bali kwa sababu stack nzima inayokizunguka inaelekea zaidi kwa user namespaces na kanuni ya least privilege.

### `runsc` From gVisor

`runsc` ni runtime inayotumiwa na gVisor. Hapa mpaka hubadilika kwa maana. Badala ya kupitisha syscalls nyingi moja kwa moja kwa host kernel kwa njia ya kawaida, gVisor inaweka tabaka la kernel kwenye userspace ambalo huiga au kuingilia sehemu kubwa za interface ya Linux. Matokeo sio container ya kawaida ya `runc` na flag chache za ziada; ni muundo tofauti wa sandbox ambao lengo lake ni kupunguza attack surface ya host-kernel. Mabadiliko ya utimilifu na utendaji ni sehemu ya muundo huo, hivyo mazingira yanayotumia `runsc` yanapaswa kuandikwa tofauti na mazingira ya kawaida ya OCI runtime.

### `kata-runtime`

Kata Containers hupanua mpaka zaidi kwa kuzindua mzigo wa kazi ndani ya virtual machine nyepesi. Kiutawala, hili bado linaweza kuonekana kama deployment ya container, na layers za orchestration zinaweza kuendelea kulitenda hivyo, lakini mpaka wa isolation wa msingi ni karibu zaidi na virtualization kuliko container ya kawaida inayoshirikiana na host-kernel. Hii inafanya Kata iwe muhimu wakati isolation kali ya tenants inatakiwa bila kuacha workflows zinazozunguka container.

## Engines Na Wasimamiaji wa Container

Ikiwa low-level runtime ni kipengele kinachozungumza moja kwa moja na kernel, engine au manager ni sehemu ambayo watumiaji na wapangaji kawaida huingiliana nayo. Inashughulikia pulls za images, metadata, logs, networks, volumes, operesheni za lifecycle, na kufunua API. Tabaka hili ni muhimu sana kwa sababu baadhi ya compromises za dunia halisi hutokea hapa: upatikanaji wa runtime socket au daemon API unaweza kuwa sawa na ku-compromise host hata kama low-level runtime yenyewe iko bila kasoro.

### Docker Engine

Docker Engine ndiyo jukwaa la container linalotambulika zaidi kwa watengenezaji na ni moja ya sababu za maneno ya container kuwa yana muundo wa Docker. Njia ya kawaida ni CLI ya `docker` kwenda `dockerd`, ambayo kwa upande wake inaandamiana na vipengele vya ngazi ya chini kama `containerd` na OCI runtime. Kihistoria, deployments za Docker zimekuwa mara nyingi **rootful**, na upatikanaji wa socket ya Docker umekuwa primitive yenye nguvu sana. Hii ndicho kilichofanya nyenzo nyingi za privilege-escalation zielekeze `docker.sock`: ikiwa mchakato unaweza kumuomba `dockerd` kuunda container yenye privileges, ku-mount njia za host, au kujiunga na namespaces za host, huenda usihitaji hata exploit ya kernel.

### Podman

Podman ilibuniwa kwa kuzunguka modeli isiyo na daemon. Kitaalam, hili husaidia kuimarisha wazo kwamba containers ni mchakato tu unaosimamiwa kupitia mifumo ya kawaida ya Linux badala ya kupitia daemon moja iliyo na haki nyingi. Podman pia ina hadithi ya **rootless** yenye nguvu zaidi kuliko deployments za Docker za kawaida watu wengi walijifunza. Hiyo haisemi kwamba Podman ni salama moja kwa moja, lakini inabadili profaili ya hatari kwa kiasi kikubwa, hasa ikichanganywa na user namespaces, SELinux, na `crun`.

### containerd

containerd ni sehemu kuu ya usimamizi wa runtime katika stack nyingi za kisasa. Inatumiwa chini ya Docker na pia ni mojawapo ya backends zinazotawala za runtime za Kubernetes. Inaonyesha APIs zenye nguvu, inasimamia images na snapshots, na inakabidhi uundaji wa mchakato wa mwisho kwa runtime ya ngazi ya chini. Mijadala ya usalama kuhusu containerd inapaswa kusisitiza kwamba upatikanaji wa socket ya containerd au uwezo wa `ctr`/`nerdctl` unaweza kuwa hatari kama upatikanaji wa API ya Docker, hata kama interface na mtiririko wa kazi unaonekana kuwa "rafiki kwa watengenezaji".

### CRI-O

CRI-O imejikita zaidi kuliko Docker Engine. Badala ya kuwa jukwaa la matumizi ya jumla kwa watengenezaji, imejengwa kuzunguka kutekeleza Kubernetes Container Runtime Interface kwa usafi. Hii inafanya iwe ya kawaida zaidi katika distributions za Kubernetes na ekosistimu zinazoegemea SELinux kama OpenShift. Kutokana na mtazamo wa usalama, wigo huo mwembamba ni wa manufaa kwa sababu unapunguza vurugu za dhana: CRI-O ni sehemu ya tabaka la "kuendesha containers kwa Kubernetes" badala ya jukwaa la kila kitu.

### Incus, LXD, Na LXC

Mifumo ya Incus/LXD/LXC inastahili kutengwa kutoka kwa containers za mtindo wa Docker kwa sababu mara nyingi zinatumiwa kama **system containers**. System container kwa kawaida inatarajiwa kuonekana zaidi kama mashine nyepesi yenye userspace kamili, services zinazoendesha kwa muda mrefu, ufichaji wa device wa kina, na ushirikiano mkubwa na host. Mbinu za isolation bado ni primitives za kernel, lakini matarajio ya uendeshaji ni tofauti. Kwa hiyo, misconfiguration hapa mara nyingi inaonekana si kama "mipangilio mibaya ya app-container" bali kama makosa katika virtualization nyepesi au uhamisho wa huduma za host.

### systemd-nspawn

systemd-nspawn inachukua nafasi ya kuvutia kwa sababu ni ya asili ya systemd na ni muhimu kwa majaribio, debugging, na kuendesha mazingira yanayofanana na OS. Si runtime dominant ya uzalishaji wa cloud-native, lakini inaonekana mara kwa mara katika maabara na mazingira yanayotegemea distro kiasi inavyostahili kutajwa. Kwa uchambuzi wa usalama, ni ukumbusho mwingine kwamba dhana ya "container" inashughulikia ekosistimu na mitindo mbalimbali ya uendeshaji.

### Apptainer / Singularity

Apptainer (zamani Singularity) ni ya kawaida katika utafiti na mazingira ya HPC. Misingi ya uaminifu, mtiririko wa mtumiaji, na modeli ya utekelezaji zinatofautiana kwa njia muhimu kutoka kwa stacks zenye mizunguko ya Docker/Kubernetes. Hasa, mazingira haya mara nyingi yanajali sana kuwapa watumiaji uwezo wa kuendesha mizigo ya kazi iliyofungashwa bila kuwapa mamlaka mapana ya usimamizi wa container yenye privilage. Ikiwa mteja anadhani kila mazingira ya container ni kimsingi "Docker kwenye server", wataelewa vibaya deployments hizi.

## Build-Time Tooling

Mijadala mingi ya usalama inazungumzia tu wakati wa kuendesha, lakini zana za wakati wa kujenga pia ni muhimu kwa sababu zinaamua yaliyomo kwenye image, kufichua secrets za kujenga, na ni kiasi gani cha muktadha uliothibitishwa kinaingizwa kwenye artifact ya mwisho.

**BuildKit** na `docker buildx` ni backends za kujenga za kisasa zinazounga mkono vipengele kama caching, secret mounting, SSH forwarding, na builds za multi-platform. Hivyo ni vipengele muhimu, lakini kwa mtazamo wa usalama pia zinaweka maeneo ambapo secrets zinaweza leak ndani ya image layers au ambapo muktadha wa kujenga mpana sana unaweza kuonyesha faili ambazo hazipaswi kamwe kujumuishwa. **Buildah** inacheza jukumu sawa katika ekosistimu zinazozunguka OCI, hasa karibu na Podman, wakati **Kaniko** mara nyingi inatumiwa katika mazingira ya CI ambayo hayataka kumpa pipeline ya kujenga daemon ya Docker yenye privileges.

Somo muhimu ni kwamba uundaji wa image na utekelezaji wa image ni awamu tofauti, lakini pipeline dhaifu ya kujenga inaweza kuunda hali dhaifu ya runtime kabla hata container haijaanzishwa.

## Orchestration Ni Tabaka Nyingine, Si Runtime

Kubernetes haipaswi kuingiliana kimaoni na runtime yenyewe. Kubernetes ni orchestrator. Inapanga Pods, inahifadhi desired state, na inaonesha sera za usalama kupitia usanidi wa mzigo wa kazi. Kubelet kisha huzungumza na utekelezaji wa CRI kama containerd au CRI-O, ambayo kwa upande wake itaimba runtime ya ngazi ya chini kama `runc`, `crun`, `runsc`, au `kata-runtime`.

Tengwa hili ni muhimu kwa sababu watu wengi hukosea kuambatanisha ulinzi kwa "Kubernetes" wakati kwa kweli unafuatwa na runtime ya node, au wanalaumu "containerd defaults" kwa tabia iliyotokana na Pod spec. Kwa vitendo, msimamo wa mwisho wa usalama ni muundo: orchestrator inaomba kitu, stack ya runtime inakitafsiri, na kernel hatimaye kinafanya utekelezaji wake.

## Kwa Nini Utambuzi wa Runtime Unajali Wakati wa Assessment

Iwapo utaweka wazi engine na runtime mapema, uchunguzi mwingi baadaye unakuwa rahisi kutafsiri. Container ya Podman isiyokuwa na root inaashiria kwamba user namespaces huenda ziko sehemu ya hadithi. Socket ya Docker iliyopakiwa ndani ya mzigo wa kazi inaashiria kuwa njia ya privilege escalation inayotokana na API ni njia inayowezekana. Node ya CRI-O/OpenShift inapaswa kukufanya ufikirie mara moja kuhusu SELinux labels na sera za restricted workload. Mazingira ya gVisor au Kata yanapaswa kukufanya uwe mwangalifu zaidi kuhusu kudhani kwamba PoC ya breakout ya kawaida ya `runc` itafanya kazi kwa njia ile ile.

Hiyo ndiyo sababu mojawapo ya hatua za kwanza katika assessment ya container inapaswa kuwa kujiuliza maswali mawili rahisi: **kipi kipengele kinachosimamia container** na **kipi runtime kilichoanzisha mchakato kwa kweli**. Mara tu majibu hayo yatakapo wazi, mazingira yote kwa kawaida yanakuwa rahisi zaidi kuyatafakari.

## Runtime Vulnerabilities

Sio kila container escape inatokana na misimamizi kusahau au config mbaya. Wakati mwingine runtime yenyewe ni kipengele chenye udhaifu. Hii ni muhimu kwa sababu mzigo wa kazi unaweza kuwa unaonekana kuwa na usanidi wa tahadhari na bado uwe wazi kupitia hitilafu ya chini ya runtime.

Mfano klassiki ni **CVE-2019-5736** katika `runc`, ambapo container haribifu inaweza kuandika juu binary ya `runc` ya host na kisha kusubiri kwa `docker exec` baadaye au mwito mwingine wa runtime kusababisha kodi ya kushikwa na mshambulizi. Njia ya exploit ni tofauti kabisa na bind-mount rahisi au kosa la capability kwa sababu inatumia jinsi runtime inavyoingia tena katika nafasi ya mchakato wa container wakati wa kushughulikia exec.

Mtiririko mdogo wa kuiga kutoka kwa mtazamo wa red-team ni:
```bash
go build main.go
./main
```
Kisha, kutoka kwenye host:
```bash
docker exec -it <container-name> /bin/sh
```
Somo kuu sio utekelezaji maalumu wa exploit wa kihistoria, bali ni athari yake kwa tathmini: ikiwa toleo la runtime lina udhaifu, utekelezaji wa kawaida wa msimbo ndani ya container unaweza kutosha kuathiri host hata pale usanidi unaoonekana wa container hauonekani dhaifu wazi.

CVE za hivi karibuni za runtime kama `CVE-2024-21626` katika `runc`, BuildKit mount races, na containerd parsing bugs zinathibitisha hoja hiyo. Runtime version and patch level ni sehemu ya mpaka wa usalama, si tu masuala ya matunzo.
{{#include ../../../banners/hacktricks-training.md}}
