# Usalama wa Container

{{#include ../../../banners/hacktricks-training.md}}

## Container Ni Nini Hasa

Njia ya kivitendo ya kufafanua container ni hii: container ni **mti wa kawaida wa michakato ya Linux** ulioanzishwa chini ya usanidi maalum wa mtindo wa OCI ili uone filesystem inayodhibitiwa, seti inayodhibitiwa ya rasilimali za kernel, na modeli ya privileges iliyowekewa mipaka. Mchakato unaweza kuamini kuwa ni PID 1, unaweza kuamini kuwa una network stack yake, unaweza kuamini kuwa unamiliki hostname na rasilimali zake za IPC, na unaweza hata kuendesha kama root ndani ya user namespace yake. Lakini kwa ndani bado ni mchakato wa host ambao kernel huupangia muda wa utekelezaji kama mchakato mwingine wowote.

Hii ndiyo sababu container security kwa kweli ni utafiti wa jinsi hiyo illusion inavyojengwa na jinsi inavyoshindwa. Ikiwa mount namespace ni dhaifu, mchakato unaweza kuona filesystem ya host. Ikiwa user namespace haipo au imezimwa, root ndani ya container inaweza kuhusishwa kwa karibu sana na root kwenye host. Ikiwa seccomp haijawekewa mipaka na capability set ni pana kupita kiasi, mchakato unaweza kufikia syscalls na vipengele vya kernel vyenye privileges ambavyo vilipaswa kubaki nje ya uwezo wake. Ikiwa runtime socket ime-mount ndani ya container, container huenda isihitaji kernel breakout hata kidogo kwa sababu inaweza kuiomba runtime ianzishe sibling container yenye nguvu zaidi au i-mount host root filesystem moja kwa moja.

## Containers Zinatofautianaje na Virtual Machines

VM kwa kawaida huwa na kernel yake na hardware abstraction boundary yake. Hii inamaanisha kuwa guest kernel inaweza ku-crash, ku-panic, au kutumiwa vibaya bila kumaanisha moja kwa moja udhibiti wa host kernel. Katika containers, workload haipati kernel tofauti. Badala yake, hupata mwonekano wa kernel ileile inayotumiwa na host, uliopitiwa kwa filters na namespaces. Kwa hiyo, containers kwa kawaida huwa nyepesi zaidi, huanza haraka zaidi, ni rahisi kuzipakia kwa msongamano mkubwa kwenye mashine, na zinafaa zaidi kwa application deployment za muda mfupi. Gharama yake ni kwamba isolation boundary hutegemea zaidi usahihi wa usanidi wa host na runtime.

Hii haimaanishi kuwa containers ni "insecure" na VMs ni "secure". Inamaanisha kuwa security model ni tofauti. Container stack iliyosanidiwa vizuri yenye rootless execution, user namespaces, default seccomp, capability set kali, kutoshirikisha host namespace, na enforcement thabiti ya SELinux au AppArmor inaweza kuwa imara sana. Kinyume chake, container iliyoanzishwa na `--privileged`, host PID/network sharing, Docker socket iliyowekwa ndani yake, na writable bind mount ya `/` inakaribia zaidi kupata host root access kuliko kuwa application sandbox iliyotengwa kwa usalama. Tofauti inatokana na layers zilizowashwa au kuzimwa.

Pia kuna hali ya kati ambayo wasomaji wanapaswa kuielewa kwa sababu inaonekana mara nyingi zaidi katika environments halisi. **Sandboxed container runtimes** kama **gVisor** na **Kata Containers** huimarisha boundary zaidi ya classic `runc` container kwa makusudi. gVisor huweka userspace kernel layer kati ya workload na interfaces nyingi za host kernel, huku Kata ikiendesha workload ndani ya lightweight virtual machine. Hizi bado hutumiwa kupitia container ecosystems na orchestration workflows, lakini security properties zake hutofautiana na plain OCI runtimes na hazipaswi kuwekwa kiakili kwenye kundi la "normal Docker containers" kana kwamba kila kitu kinafanya kazi kwa namna moja.

## Container Stack: Layers Kadhaa, Si Moja

Mtu anaposema "this container is insecure", swali la kufuatilia lenye manufaa ni: **ni layer gani iliyoifanya iwe insecure?** Workload ya container kwa kawaida hutokana na components kadhaa zinazofanya kazi pamoja.

Juu kabisa, mara nyingi kuna **image build layer** kama BuildKit, Buildah, au Kaniko, ambayo huunda OCI image na metadata. Juu ya low-level runtime, kunaweza kuwa na **engine au manager** kama Docker Engine, Podman, containerd, CRI-O, Incus, au systemd-nspawn. Katika cluster environments, kunaweza pia kuwa na **orchestrator** kama Kubernetes inayoweka security posture iliyoombwa kupitia workload configuration. Mwishowe, **kernel** ndiyo inayotekeleza kwa kweli namespaces, cgroups, seccomp, na MAC policy.

Layered model hii ni muhimu kwa kuelewa defaults. Restriction inaweza kuombwa na Kubernetes, kutafsiriwa kupitia CRI na containerd au CRI-O, kubadilishwa kuwa OCI spec na runtime wrapper, na kisha kutekelezwa na `runc`, `crun`, `runsc`, au runtime nyingine dhidi ya kernel. Defaults zinapotofautiana kati ya environments, mara nyingi sababu huwa ni kwamba mojawapo ya layers hizi ilibadilisha final configuration. Kwa hiyo, mechanism ileile inaweza kuonekana katika Docker au Podman kama CLI flag, katika Kubernetes kama Pod au `securityContext` field, na katika lower-level runtime stacks kama OCI configuration iliyotengenezwa kwa ajili ya workload. Kwa sababu hiyo, CLI examples katika sehemu hii zinapaswa kusomwa kama **runtime-specific syntax ya container concept ya jumla**, si flags za ulimwengu wote zinazoungwa mkono na kila tool.

## Container Security Boundary Halisi

Kwa vitendo, container security hutokana na **overlapping controls**, si control moja kamilifu. Namespaces hutenga visibility. cgroups hudhibiti na kuweka mipaka ya matumizi ya resources. Capabilities hupunguza kile ambacho mchakato unaoonekana kuwa na privileges unaweza kufanya kwa kweli. seccomp huzuia syscalls hatari kabla hazijafika kwenye kernel. AppArmor na SELinux huongeza Mandatory Access Control juu ya ukaguzi wa kawaida wa DAC. `no_new_privs`, masked procfs paths, na read-only system paths hufanya privilege abuse na proc/sys abuse chains za kawaida kuwa ngumu zaidi. Runtime yenyewe pia ni muhimu kwa sababu huamua jinsi mounts, sockets, labels, na namespace joins zinavyoundwa.

Ndiyo sababu nyaraka nyingi za container security huonekana kurudia mambo. Escape chain ileile mara nyingi hutegemea mechanisms nyingi kwa wakati mmoja. Kwa mfano, writable host bind mount ni hatari, lakini inakuwa mbaya zaidi ikiwa container pia inaendesha kama real root kwenye host, ina `CAP_SYS_ADMIN`, haijawekewa mipaka na seccomp, na haizuiwi na SELinux au AppArmor. Vivyo hivyo, host PID sharing ni exposure kubwa, lakini inakuwa na manufaa makubwa zaidi kwa attacker inapounganishwa na `CAP_SYS_PTRACE`, procfs protections dhaifu, au namespace-entry tools kama `nsenter`. Njia sahihi ya kuandika mada hii kwa hiyo si kurudia attack ileile kwenye kila ukurasa, bali kueleza kile ambacho kila layer inaongeza kwenye final boundary.

## Jinsi ya Kusoma Sehemu Hii

Sehemu hii imepangwa kutoka kwenye concepts za jumla zaidi hadi zile maalum zaidi.

Anza na runtime na ecosystem overview:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Kisha pitia control planes na supply-chain surfaces ambazo mara nyingi huamua ikiwa attacker anahitaji hata kernel escape:

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

Kisha nenda kwenye protection model:

{{#ref}}
protections/
{{#endref}}

Kurasa za namespace zinaeleza kernel isolation primitives moja moja:

{{#ref}}
protections/namespaces/
{{#endref}}

Kurasa kuhusu cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths, na read-only system paths zinaeleza mechanisms ambazo kwa kawaida huwekwa juu ya namespaces:

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

## Mtazamo Mzuri wa Kwanza wa Enumeration

Unapofanya assessment ya target iliyo-containerized, ni muhimu zaidi kuuliza seti ndogo ya maswali sahihi ya kiufundi kuliko kurukia moja kwa moja famous escape PoCs. Kwanza, tambua **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer, au kitu maalum zaidi. Kisha tambua **runtime**: `runc`, `crun`, `runsc`, `kata-runtime`, au implementation nyingine inayooana na OCI. Baada ya hapo, angalia ikiwa environment ni **rootful au rootless**, ikiwa **user namespaces** ziko active, ikiwa kuna **host namespaces** zilizoshirikiwa, ni **capabilities** zipi zimebaki, ikiwa **seccomp** imewezeshwa, ikiwa **MAC policy** inatekelezwa kweli, ikiwa **dangerous mounts au sockets** zipo, na ikiwa mchakato unaweza kuingiliana na container runtime API.

Majibu hayo yanakuambia mengi zaidi kuhusu security posture halisi kuliko jina la base image. Katika assessments nyingi, unaweza kutabiri breakout family inayowezekana kabla ya kusoma hata application file moja, kwa kuelewa tu final container configuration.

## Coverage

Sehemu hii inashughulikia material ya zamani iliyolenga Docker, ikiwa imepangwa kwa muundo unaolenga containers: runtime na daemon exposure, authorization plugins, image trust na build secrets, sensitive host mounts, distroless workloads, privileged containers, na kernel protections ambazo kwa kawaida huwekwa pamoja na container execution.

{{#include ../../../banners/hacktricks-training.md}}
