# Container Security

{{#include ../../../banners/hacktricks-training.md}}

## What A Container Actually Is

Njia ya vitendo ya kuelezea container ni hii: container ni **regular Linux process tree** ambayo imeanzishwa chini ya usanidi maalum wa mtindo wa OCI ili ionekane filesystem iliyodhibitiwa, seti iliyodhibitiwa ya rasilimali za kernel, na modeli ya ruhusa iliyopunguzwa. Mchakato unaweza kufikiri kwamba ni PID 1, unaweza kufikiri una stack yake ya network, unaweza kufikiri mmiliki wa hostname na rasilimali za IPC, na hata unaweza kuendesha kama root ndani ya user namespace yake. Lakini chini ya kifuniko bado ni process ya host ambayo kernel inaipeana ratiba kama ile nyingine yoyote.

Hivyo ndo maana container security ni zaidi ya kusoma jinsi udanganyifu huo unavyojengwa na jinsi unavyoshindwa. Ikiwa mount namespace ni dhaifu, process inaweza kuona host filesystem. Ikiwa user namespace haipo au imezimwa, root ndani ya container inaweza kuendana sana na root kwenye host. Ikiwa seccomp haijawekewa mipaka na seti ya capabilities ni pana sana, process inaweza kufikia syscalls na vipengele vilivyo na ruhusa za kernel ambavyo vinapaswa kuwa nje ya ufikivu. Ikiwa runtime socket imewekwa ndani ya container, container inaweza isiuhitaji kabisa breakout wa kernel kwa sababu inaweza kumwomba runtime ielekeze container yenye uwezo mkubwa zaidi au ku-mount host root filesystem moja kwa moja.

## How Containers Differ From Virtual Machines

VM kwa kawaida ina kernel yake mwenyewe na mpaka wa abstraction ya hardware. Hii inamaanisha kernel ya guest inaweza kuanguka, kuleta panic, au kutumiwa bila kuhitaji kuwa udhibiti wa moja kwa moja wa kernel ya host. Katika container, workload haipati kernel tofauti. Badala yake, inapata mtazamo uliosafishwa kwa uangalifu na uliopangwa kwa namespaces wa kernel ile ile inayotumiwa na host. Matokeo yake, containers kwa kawaida ni nyepesi, huanza haraka, ni rahisi kupakia kwa wingi kwenye mashine, na zinafaa zaidi kwa deployment za applications za muda mfupi. Gharama ni kwamba boundary ya isolation inategemea kwa karibu zaidi usanidi sahihi wa host na runtime.

Hii haisemi kwamba containers ni "insecure" na VMs ni "secure". Inasema tu kwamba modeli ya usalama ni tofauti. Stack ya container iliyosanidiwa vizuri na rootless execution, user namespaces, seccomp ya default, seti kali ya capabilities, kutoshirikisha host namespaces, na utekelezaji imara wa SELinux au AppArmor inaweza kuwa imara sana. Kinyume chake, container iliyoanzishwa na `--privileged`, host PID/network sharing, Docker socket ikiwekwa ndani yake, na writable bind mount ya `/` ni kwa vitendo karibu zaidi na access ya host root kuliko sandbox yenye kutumia isolation. Tofauti inatokana na tabaka zilizoamuliwa kuwa zimewezeshwa au kuzimwa.

Kuna pia eneo la kati ambalo wasomaji wanapaswa kuelewa kwa sababu linaonekana mara kwa mara zaidi katika mazingira ya kweli. **Sandboxed container runtimes** kama **gVisor** na **Kata Containers** kwa makusudi huimarisha boundary zaidi kuliko container ya jadi ya `runc`. gVisor inaweka layer ya userspace kernel kati ya workload na interfaces nyingi za kernel ya host, wakati Kata inaendesha workload ndani ya VM nyepesi. Hizi bado zinatumika kupitia ecosystems za container na workflows za orchestration, lakini mali zao za usalama ni tofauti na runtimes za plain OCI na hazipaswi kuingiliwa kifikira na "normal Docker containers" kana kwamba kila kitu kimefanya kazi kwa njia ile ile.

## The Container Stack: Several Layers, Not One

Wakati mtu anasema "this container is insecure", swali linalofaa la kufuatilia ni: **ni matabaka gani yaliyoifanya kuwa insecure?** Workload iliyokatwa katika container kwa kawaida ni matokeo ya vipengele kadhaa vinavyofanya kazi pamoja.

Juu kabisa, mara nyingi kuna **image build layer** kama BuildKit, Buildah, au Kaniko, inayounda OCI image na metadata. Juu ya runtime ya chini, kunaweza kuwa na **engine or manager** kama Docker Engine, Podman, containerd, CRI-O, Incus, au systemd-nspawn. Katika mazingira ya cluster, pia kunaweza kuwa na **orchestrator** kama Kubernetes kuamua postura inayohitajika ya usalama kupitia configuration ya workload. Mwisho, **kernel** ndiye anayetekeleza namespaces, cgroups, seccomp, na sera za MAC.

Mfano huu wa tabaka ni muhimu kwa kuelewa defaults. Kushinikizwa kunaweza kuombwa na Kubernetes, kutafsiriwa kupitia CRI na containerd au CRI-O, kubadilishwa kuwa spec ya OCI na wrapper ya runtime, na kisha kutekelezwa na `runc`, `crun`, `runsc`, au runtime nyingine dhidi ya kernel. Wakati defaults zinatofautiana kati ya mazingira, mara nyingi ni kwa sababu mojawapo ya tabaka hizi ilibadilisha configuration ya mwisho. Mfumo huo huo unaweza kuonekana Docker au Podman kama flag ya CLI, katika Kubernetes kama Pod au uwanja wa `securityContext`, na katika stacks za runtimes za chini kama configuration ya OCI iliyotengenezwa kwa workload. Kwa sababu hiyo, mifano ya CLI katika sehemu hii inapaswa kusomwa kama **syntax maalumu ya runtime kwa dhana ya jumla ya container**, sio flags za ulimwengu mzima zinazotumika na zana zote.

## The Real Container Security Boundary

Kivitendo, container security inatokana na **controls zinazogongana**, sio control moja kamilifu. Namespaces zinatenga uonekano. cgroups hutoa na kudhibiti matumizi ya rasilimali. Capabilities hupunguza kile ambacho process inayofanana na yenye ruhusa inaweza kufanya kwa vitendo. seccomp inazuia syscalls hatari kabla hazijaingia kernel. AppArmor na SELinux zinaongeza Mandatory Access Control juu ya ukaguzi wa kawaida wa DAC. `no_new_privs`, njia za procfs zilizofichwa, na njia za mfumo zinazosomwa tu hufanya mnyororo wa unyonyaji wa ruhusa na proc/sys kuwa mgumu zaidi. Runtime yenyewe pia ina umuhimu kwa sababu inamua jinsi mounts, sockets, labels, na namespace joins zinavyoundwa.

Hivyo ndivyo sababu nyaraka nyingi za container security zinaonekana kurudiarudia. Mnyororo wa kutoroka mara nyingi unategemea mekanizmo nyingi kwa pamoja. Kwa mfano, writable host bind mount ni mbaya, lakini inakuwa mbaya zaidi ikiwa container pia inaendesha kama root halisi kwenye host, ina `CAP_SYS_ADMIN`, haifungwi na seccomp, na haikuzuizwi na SELinux au AppArmor. Vivyo hivyo, host PID sharing ni mfunguzi mkubwa wa hatari, lakini inakuwa muhimu sana kwa mshambuliaji inapochanganywa na `CAP_SYS_PTRACE`, ulinzi dhaifu wa procfs, au zana za kuingia namespace kama `nsenter`. Njia sahihi ya kuandika mada hii si kurudia shambulio lile lile kwenye kila ukurasa, bali kueleza ni kila tabaka linachochangia kwenye boundary ya mwisho.

## How To Read This Section

Sehemu imepangwa kutoka dhana za jumla zaidi hadi zile maalum zaidi.

Anza na muhtasari wa runtime na ecosystem:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Kisha pitia control planes na uso wa supply-chain zinazokuwa mara nyingi zikiamua kama mshambuliaji hata anahitaji breakout ya kernel:

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

Kisha hamia kwenye modeli ya ulinzi:

{{#ref}}
protections/
{{#endref}}

Kurasa za namespaces zinaelezea primitives za isolation za kernel moja moja:

{{#ref}}
protections/namespaces/
{{#endref}}

Kurasa juu ya cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths, na read-only system paths zinaelezea mekanismo ambazo kwa kawaida zinawekwa juu ya namespaces:

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

Unapochambua target iliyo containerized, ni muhimu zaidi kuuliza seti ndogo ya maswali ya kiufundi yaliyo sahihi kuliko kuruka mara moja kwenye PoC za kutoroka maarufu. Kwanza, tambua **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer, au kitu kilicho maalum zaidi. Kisha tambua **runtime**: `runc`, `crun`, `runsc`, `kata-runtime`, au utekelezaji mwingine unaolingana na OCI. Baadaye, angalia ikiwa mazingira ni **rootful au rootless**, ikiwa **user namespaces** zinafanya kazi, ikiwa kuna **host namespaces** zilizoshirikiwa, ni **capabilities** zipi zilizosalia, ikiwa **seccomp** imewezeshwa, ikiwa sera ya **MAC** inatekelezwa kweli, ikiwa kuna **dangerous mounts or sockets**, na ikiwa process inaweza kuwasiliana na container runtime API.

Majibu hayo yanakuambia zaidi kuhusu postura halisi ya usalama kuliko jina la base image lolote. Katika tathmini nyingi, unaweza kutabiri familia ya breakout inayowezekana kabla ya kusoma faili moja ya application kwa kuelewa configuration ya mwisho ya container.

## Coverage

Sehemu hii inashughulikia nyaraka za zamani zilizoelekezwa kwenye Docker chini ya muundo unaolenga container: runtime na exposure ya daemon, authorization plugins, image trust na build secrets, sensitive host mounts, distroless workloads, privileged containers, na ulinzi wa kernel unaoekwa kawaida kwenye utekelezaji wa container.
{{#include ../../../banners/hacktricks-training.md}}
