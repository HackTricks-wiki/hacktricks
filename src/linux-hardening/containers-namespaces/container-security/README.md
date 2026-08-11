# Usalama wa Container

{{#include ../../../banners/hacktricks-training.md}}

## Container Ni Nini Hasa

Njia ya kivitendo ya kufafanua container ni hii: container ni **mti wa kawaida wa Linux process** ulioanzishwa chini ya configuration maalum ya mtindo wa OCI, ili uone filesystem inayodhibitiwa, seti inayodhibitiwa ya kernel resources, na privilege model yenye vikwazo. Process inaweza kuamini kuwa ni PID 1, inaweza kuamini kuwa ina network stack yake, inaweza kuamini kuwa inamiliki hostname na IPC resources zake, na inaweza hata kuendesha kama root ndani ya user namespace yake. Lakini kwa ndani bado ni host process ambayo kernel hui-schedule kama process nyingine yoyote.

Hii ndiyo sababu container security kwa kweli ni utafiti wa jinsi illusion hiyo inavyoundwa na jinsi inavyoshindwa. Ikiwa mount namespace ni dhaifu, process inaweza kuona host filesystem. Ikiwa user namespace haipo au imezimwa, root ndani ya container inaweza kuunganishwa kwa karibu sana na root kwenye host. Ikiwa seccomp haijawekewa vikwazo na capability set ni pana mno, process inaweza kufikia syscalls na privileged kernel features ambazo zilipaswa kubaki nje ya uwezo wake. Ikiwa runtime socket ime-mount ndani ya container, container huenda isihitaji kernel breakout kabisa, kwa sababu inaweza kuiomba runtime ianzishe sibling container yenye nguvu zaidi au i-mount host root filesystem moja kwa moja.

## Containers Hutofautianaje na Virtual Machines

VM kwa kawaida huwa na kernel yake na hardware abstraction boundary yake. Hii inamaanisha guest kernel inaweza ku-crash, ku-panic, au kutumiwa vibaya bila kumaanisha moja kwa moja udhibiti wa host kernel. Katika containers, workload haipati kernel tofauti. Badala yake, hupata mwonekano uliowekewa vichujio na namespaces wa kernel ileile inayotumiwa na host. Kwa hiyo, containers kwa kawaida huwa nyepesi, huanza haraka, ni rahisi kuweka nyingi kwenye machine moja, na zinafaa zaidi kwa deployment ya applications za muda mfupi. Gharama yake ni kwamba isolation boundary inategemea zaidi usahihi wa host na runtime configuration.

Hii haimaanishi kuwa containers ni "insecure" na VMs ni "secure". Inamaanisha security model ni tofauti. Container stack iliyosanidiwa vizuri, yenye rootless execution, user namespaces, default seccomp, capability set kali, kutoshiriki host namespaces, na enforcement thabiti ya SELinux au AppArmor inaweza kuwa imara sana. Kinyume chake, container iliyoanzishwa kwa `--privileged`, host PID/network sharing, Docker socket iliyowekwa ndani yake, na writable bind mount ya `/`, kwa utendaji iko karibu zaidi na host root access kuliko application sandbox iliyotengwa kwa usalama. Tofauti inatokana na layers zilizowezeshwa au kuzimwa.

Pia kuna hali ya kati ambayo wasomaji wanapaswa kuielewa kwa sababu inaonekana zaidi na zaidi katika mazingira halisi. **Sandboxed container runtimes** kama **gVisor** na **Kata Containers** huimarisha boundary zaidi ya `runc` container ya kawaida. gVisor huweka userspace kernel layer kati ya workload na host kernel interfaces nyingi, huku Kata ikiendesha workload ndani ya lightweight virtual machine. Hizi bado hutumiwa kupitia container ecosystems na orchestration workflows, lakini security properties zake hutofautiana na plain OCI runtimes na hazipaswi kuwekwa kiakili pamoja na "normal Docker containers" kana kwamba kila kitu hufanya kazi kwa njia ileile.

## Container Stack: Layers Kadhaa, Sio Moja

Mtu anaposema "container hii si salama", swali muhimu la kufuatilia ni: **ni layer gani iliyoifanya isiwe salama?** Containerized workload kwa kawaida hutokana na components kadhaa zinazofanya kazi pamoja.

Juu kabisa, mara nyingi kuna **image build layer** kama BuildKit, Buildah, au Kaniko, ambayo huunda OCI image na metadata. Juu ya low-level runtime, kunaweza kuwa na **engine au manager** kama Docker Engine, Podman, containerd, CRI-O, Incus, au systemd-nspawn. Katika cluster environments, kunaweza pia kuwa na **orchestrator** kama Kubernetes inayoweka security posture iliyoombwa kupitia workload configuration. Hatimaye, **kernel** ndiyo inayotekeleza namespaces, cgroups, seccomp, na MAC policy.

Layered model hii ni muhimu kwa kuelewa defaults. Restriction inaweza kuombwa na Kubernetes, kutafsiriwa kupitia CRI na containerd au CRI-O, kubadilishwa kuwa OCI spec na runtime wrapper, na kisha kutekelezwa na `runc`, `crun`, `runsc`, au runtime nyingine dhidi ya kernel. Defaults zinapotofautiana kati ya environments, mara nyingi ni kwa sababu moja ya layers hizi ilibadilisha final configuration. Kwa hiyo, mechanism ileile inaweza kuonekana katika Docker au Podman kama CLI flag, katika Kubernetes kama Pod au `securityContext` field, na katika lower-level runtime stacks kama OCI configuration iliyotengenezwa kwa workload. Kwa sababu hiyo, CLI examples katika section hii zinapaswa kusomwa kama **runtime-specific syntax ya container concept ya jumla**, si flags za jumla zinazoungwa mkono na kila tool.

## Container Security Boundary Halisi

Kwa vitendo, container security hutokana na **overlapping controls**, si control moja kamilifu. Namespaces hutenga visibility. cgroups hudhibiti na kuweka mipaka ya matumizi ya resources. Capabilities hupunguza kile ambacho process inayoonekana kuwa privileged inaweza kufanya. seccomp huzuia dangerous syscalls kabla hazijafika kwenye kernel. AppArmor na SELinux huongeza Mandatory Access Control juu ya DAC checks za kawaida. `no_new_privs`, masked procfs paths, na read-only system paths hufanya privilege na proc/sys abuse chains za kawaida kuwa ngumu zaidi. Runtime yenyewe pia ni muhimu kwa sababu huamua jinsi mounts, sockets, labels, na namespace joins zinavyoundwa.

Ndiyo sababu nyaraka nyingi za container security zinaonekana kujirudia. Escape chain ileile mara nyingi hutegemea mechanisms nyingi kwa wakati mmoja. Kwa mfano, writable host bind mount ni hatari, lakini huwa hatari zaidi ikiwa container pia inaendesha kama real root kwenye host, ina `CAP_SYS_ADMIN`, haijawekewa vikwazo na seccomp, na haijazuiwa na SELinux au AppArmor. Vivyo hivyo, host PID sharing ni exposure kubwa, lakini huwa muhimu zaidi kwa attacker inapounganishwa na `CAP_SYS_PTRACE`, procfs protections dhaifu, au namespace-entry tools kama `nsenter`. Njia sahihi ya kuandika kuhusu mada hii si kurudia attack ileile kwenye kila ukurasa, bali kueleza mchango wa kila layer kwenye final boundary.

## Jinsi ya Kusoma Section Hii

Section hii imepangwa kutoka kwenye concepts za jumla zaidi hadi zile maalum zaidi.

Anza na runtime na ecosystem overview:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Kisha pitia control planes na supply-chain surfaces ambazo mara nyingi huamua ikiwa attacker anahitaji kernel escape hata kidogo:

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

Namespace pages zinaeleza kernel isolation primitives moja moja:

{{#ref}}
protections/namespaces/
{{#endref}}

Pages kuhusu cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths, na read-only system paths zinaeleza mechanisms ambazo kwa kawaida huwekwa juu ya namespaces:

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

Unapotathmini containerized target, ni muhimu zaidi kuuliza seti ndogo ya maswali sahihi ya kiufundi kuliko kurukia mara moja famous escape PoCs. Kwanza, tambua **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer, au kitu maalum zaidi. Kisha tambua **runtime**: `runc`, `crun`, `runsc`, `kata-runtime`, au implementation nyingine inayooana na OCI. Baada ya hapo, angalia ikiwa environment ni **rootful au rootless**, ikiwa **user namespaces** ziko active, ikiwa kuna **host namespaces** zinazoshirikiwa, ni **capabilities** zipi zimesalia, ikiwa **seccomp** imewezeshwa, ikiwa **MAC policy** inatekelezwa kwa kweli, ikiwa **dangerous mounts au sockets** zipo, na ikiwa process inaweza kuwasiliana na container runtime API.

Majibu hayo yanakuambia mengi zaidi kuhusu real security posture kuliko jina la base image. Katika assessments nyingi, unaweza kutabiri breakout family inayowezekana kabla ya kusoma application file hata moja, kwa kuelewa tu final container configuration.

## Coverage

Section hii inashughulikia material ya zamani iliyolenga Docker chini ya organization inayolenga containers: runtime na daemon exposure, authorization plugins, image trust na build secrets, sensitive host mounts, distroless workloads, privileged containers, na kernel protections ambazo kwa kawaida huwekwa karibu na container execution.

{{#include ../../../banners/hacktricks-training.md}}
