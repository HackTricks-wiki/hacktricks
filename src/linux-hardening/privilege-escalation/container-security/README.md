# Usalama wa Container

{{#include ../../../banners/hacktricks-training.md}}

## What A Container Actually Is

Njia ya vitendo ya kufafanua container ni hii: container ni **mti wa mchakato wa kawaida wa Linux** ambao umeanzishwa chini ya usanidi maalum wa mtindo wa OCI ili uone filesystem iliyodhibitiwa, seti ya rasilimali za kernel zilizodhibitiwa, na modeli ya vigezo iliyopunguzwa. Mchakato unaweza kudhani kuwa ni PID 1, unaweza kudhani kwamba una stack yake mwenyewe ya network, unaweza kudhani kwamba unamiliki hostname na rasilimali za IPC, na hata unaweza kuendesha kama root ndani ya user namespace yake. Lakini chini ya uso bado ni mchakato wa host ambao kernel huupanga kama zinginezozo.

Hii ndio sababu usalama wa container ni hasa utafiti wa jinsi udanganyifu huo unavyojengwa na jinsi unavyoshindwa. Ikiwa mount namespace ni dhaifu, mchakato unaweza kuona filesystem ya host. Ikiwa user namespace haipo au imezimwa, root ndani ya container inaweza kuendana sana na root kwenye host. Ikiwa seccomp haifungwi na seti ya capabilities ni pana mno, mchakato unaweza kufikia syscalls na vipengele vya kernel vinavyohitaji vigezo vya juu ambavyo vinastahili kuwa nje ya ufikiaji. Ikiwa socket ya runtime imepandikizwa ndani ya container, container inaweza isihitaji kabisa kuvunja kernel kwa sababu inaweza tu kumuuliza runtime ili ilanze container mwenye nguvu zaidi au kupanda host root filesystem moja kwa moja.

## How Containers Differ From Virtual Machines

VM kawaida ina kernel yake na mpaka wa abstraction ya vifaa. Hii ina maana kernel ya mgeni inaweza kuanguka, kufanya panic, au kutumika vibaya bila kuashiria moja kwa moja udhibiti wa kernel ya host. Katika containers, workload haipati kernel tofauti. Badala yake, inapata muonekano uliosafishwa kwa uangalifu na uliopangwa kwa namespaces wa kernel ule ule unaotumika na host. Kwa matokeo, containers kwa kawaida ni nyepesi zaidi, huanza kwa haraka zaidi, zinazidi kufungashwa kwa wingi kwenye mashine, na zinalingana vizuri na uanzishaji wa application wa muda mfupi. Gharama ni kwamba mpaka wa izolیشن hutegemea zaidi usanidi sahihi wa host na runtime.

Hii haimaanishi containers ni "zisizo salama" na VMs ni "salama". Inamaanisha mfano wa usalama ni tofauti. Stack ya container iliyosanidiwa vizuri na execution isiyokuwa root (rootless), user namespaces, seccomp ya default, seti kali ya capabilities, kutokushiriki host namespace, na utekelezaji mkali wa SELinux au AppArmor inaweza kuwa imara sana. Kinyume chake, container iliyozinduliwa na `--privileged`, kushiriki host PID/network, socket ya Docker iliyopandikizwa ndani yake, na writable bind mount ya `/` kwa vitendo iko karibu zaidi na ufikiaji wa root wa host kuliko sandbox ya application iliyopokewa salama. Tofauti inatokana na tabaka ambazo ziliwashwa au kuzimwa.

Kuna pia eneo la kati ambalo wasomaji wanapaswa kuelewa kwa sababu linaonekana mara kwa mara katika mazingira halisi. **Sandboxed container runtimes** kama **gVisor** na **Kata Containers** kwa makusudi huimarisha mpaka zaidi kuliko container ya kawaida ya `runc`. gVisor inaweka tabaka la kernel katika userspace kati ya workload na interfaces nyingi za kernel za host, wakati Kata inananzisha workload ndani ya virtual machine nyepesi. Hizi bado zinatumika kupitia ecosystems za container na workflows za orchestration, lakini mali zao za usalama zinatofautiana na runtimes za kawaida za OCI na hazipaswi kufikiriwa pamoja kimaoni na "normal Docker containers" kana kwamba kila kitu kinatenda kwa njia ile ile.

## The Container Stack: Several Layers, Not One

Wakati mtu anasema "this container is insecure", swali linalofaa kufuatia ni: **ni tabaka gani lililofanya isiwe salama?** Workload iliyo containerized kawaida ni matokeo ya vipengele kadhaa vinavyofanya kazi pamoja.

Juu kabisa, mara nyingi kuna **image build layer** kama BuildKit, Buildah, au Kaniko, ambayo huunda OCI image na metadata. Juu ya runtime ya chini, kunaweza kuwa na **engine au manager** kama Docker Engine, Podman, containerd, CRI-O, Incus, au systemd-nspawn. Katika mazingira ya cluster, kunaweza pia kuwa na **orchestrator** kama Kubernetes inayofanya maamuzi kuhusu postura inayohitajika ya usalama kupitia usanidi wa workload. Hatimaye, **kernel** ndiyo inayotekeleza namespaces, cgroups, seccomp, na sera za MAC.

Mfano huu wa tabaka ni muhimu kwa kuelewa defaults. Kizuizi kinaweza kuombwa na Kubernetes, kutafsiriwa kupitia CRI na containerd au CRI-O, kubadilishwa kuwa OCI spec na runtime wrapper, na kisha kutekelezwa na `runc`, `crun`, `runsc`, au runtime nyingine dhidi ya kernel. Wakati defaults zinatofautiana kati ya mazingira, mara nyingi ni kwa sababu moja ya tabaka hizi ilibadilisha usanidi wa mwisho. Vivyo hivyo, mekanismi ile ile inaweza kuonekana katika Docker au Podman kama flag ya CLI, katika Kubernetes kama Pod au uwanja wa `securityContext`, na katika stacks za runtime za chini kama usanidi wa OCI uliotengenezwa kwa workload. Kwa sababu hiyo, mifano ya CLI katika sehemu hii inapaswa kusomwa kama **sintaksia maalum ya runtime kwa dhana ya container kwa ujumla**, si kama flags za ulimwengu mzima zinazotambulika na kila zana.

## The Real Container Security Boundary

Kwa vitendo, usalama wa container unatokana na **udhibiti unaovuka**, si kutoka kwa udhibiti mmoja kamili. Namespaces zinatenganisha muonekano. cgroups huzuru na kupunguza matumizi ya rasilimali. Capabilities hupunguza kile mchakato unaoonekana kuwa privileged unaweza kweli kufanya. seccomp inazuia syscalls hatarishi kabla hayajafika kernel. AppArmor na SELinux zinaongeza Mandatory Access Control juu ya ukaguzi wa kawaida wa DAC. `no_new_privs`, njia za procfs zilizofichwa (masked procfs paths), na njia za mfumo zilizokuwa read-only zinafanya minyororo ya unyonyaji wa vigezo na proc/sys kuwa ngumu zaidi. Runtime yenyewe pia ni muhimu kwa sababu inaamua jinsi mounts, sockets, labels, na namespace joins zinavyoundwa.

Ndiyo maana nyaraka nyingi za usalama wa container zinaonekana kurudia. Mlolongo huo huo wa kutoroka mara nyingi unategemea mechanisms nyingi kwa wakati mmoja. Kwa mfano, writable host bind mount ni mbaya, lakini inakuwa mbaya zaidi ikiwa container pia inaendesha kama root halisi kwenye host, ina `CAP_SYS_ADMIN`, haifungwi na seccomp, na haizuiliwi na SELinux au AppArmor. Vivyo hivyo, kushiriki host PID ni mwonekano hatari, lakini inakuwa muhimu zaidi kwa mshambuliaji wakati imeunganishwa na `CAP_SYS_PTRACE`, ulinzi dhaifu wa procfs, au zana za kuingia namespace kama `nsenter`. Njia sahihi ya kuweka mada ni sio kurudia shambulio lile lile kwenye kila ukurasa, bali kuelezea kila tabaka inachochangia kwa mpaka wa mwisho.

## How To Read This Section

Sehemu imepangwa kutoka dhana za jumla zaidi hadi zile maalum zaidi.

Anza na muhtasari wa runtime na ecosystem:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Kisha pitia planes za udhibiti na uso wa supply-chain ambao mara nyingi hufanya uamuzi kama mshambuliaji hata anahitaji kuondoka kernel:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
authorization-plugins.md
{{#endref}}

{{#ref}}
image-security-and-secrets.md
{{#endref}}

{{#ref}}
assessment-and-hardening.md
{{#endref}}

Kisha hamia kwenye mfano wa ulinzi:

{{#ref}}
protections/
{{#endref}}

Kurasa za namespace zinaelezea primitives za isolation za kernel moja kwa moja:

{{#ref}}
protections/namespaces/
{{#endref}}

Kurasa juu ya cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths, na read-only system paths zinaelezea mifumo ambayo kawaida inapatikana juu ya namespaces:

{{#ref}}
protections/cgroups.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/no-new-privileges.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
distroless.md
{{#endref}}

{{#ref}}
privileged-containers.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## A Good First Enumeration Mindset

Unapotathmini lengo la containerized, ni muhimu zaidi kuuliza seti ndogo ya maswali ya kiufundi na sahihi kuliko kuruka mara moja kwenye PoC maarufu za kutoroka. Kwanza, tambua **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer, au kitu maalum zaidi. Kisha tambua **runtime**: `runc`, `crun`, `runsc`, `kata-runtime`, au utekelezaji mwingine unaolingana na OCI. Baada ya hapo, angalia kama mazingira ni **rootful au rootless**, kama **user namespaces** zinafanya kazi, kama kuna kushirikiana kwa **host namespaces**, ni **capabilities** gani zilizobaki, kama **seccomp** imewezeshwa, kama sera ya **MAC** inatumwa kwa vitendo, kama **mounts au sockets hatarishi** zipo, na kama mchakato unaweza kuingiliana na API ya runtime ya container.

Majibu hayo yanasema zaidi kuhusu postura halisi ya usalama kuliko jina la base image litakalowahi. Katika tathmini nyingi, unaweza kutabiri familia inayowezekana ya kutoroka kabla ya kusoma faili yoyote ya application kwa kuelewa tu usanidi wa mwisho wa container.

## Coverage

Sehemu hii inashughulikia nyenzo za zamani zilizoelekezwa kwenye Docker chini ya mpangilio unaolenga container: runtime na waziwa wa daemon, authorization plugins, image trust na build secrets, sensitive host mounts, distroless workloads, privileged containers, na ulinzi wa kernel ambao kwa kawaida umetengwa juu ya utekelezaji wa container.
