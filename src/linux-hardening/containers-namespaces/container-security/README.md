# Container Security

{{#include ../../../banners/hacktricks-training.md}}

## Container Ni Nini Kwa Hakika

Njia ya vitendo ya kufafanua container ni hii: container ni **regular Linux process tree** iliyoanzishwa kwa kutumia usanidi maalum wa mtindo wa OCI, ili ionekane ikiwa na filesystem inayodhibitiwa, seti inayodhibitiwa ya kernel resources, na modeli ya privileges iliyowekewa mipaka. Process hiyo inaweza kuamini kuwa ni PID 1, inaweza kuamini kuwa ina network stack yake, inaweza kuamini kuwa inamiliki hostname na IPC resources zake, na inaweza hata kuendesha kama root ndani ya user namespace yake. Lakini chini ya yote, bado ni host process ambayo kernel huipangia muda wa utekelezaji kama process nyingine yoyote.

Hii ndiyo sababu container security kwa hakika ni utafiti wa jinsi illusion hiyo inavyoundwa na jinsi inavyoshindwa. Ikiwa mount namespace ni dhaifu, process inaweza kuona host filesystem. Ikiwa user namespace haipo au imezimwa, root ndani ya container inaweza ku-map kwa karibu sana na root kwenye host. Ikiwa seccomp haijawekewa vikwazo na capability set ni pana mno, process inaweza kufikia syscalls na privileged kernel features ambazo zilipaswa kubaki nje ya uwezo wake. Ikiwa runtime socket ime-mount ndani ya container, container huenda isihitaji kernel breakout kabisa, kwa sababu inaweza kuiomba runtime ianzishe sibling container yenye nguvu zaidi au i-mount host root filesystem moja kwa moja.

## Jinsi Containers Zinavyotofautiana na Virtual Machines

VM kwa kawaida huwa na kernel yake na hardware abstraction boundary yake. Hii inamaanisha guest kernel inaweza ku-crash, ku-panic, au kutumiwa bila kudokeza moja kwa moja kwamba host kernel inadhibitiwa. Katika containers, workload haipati kernel tofauti. Badala yake, hupata mwonekano uliopunguzwa na kuwekwa katika namespaces wa kernel ileile inayotumiwa na host. Kwa hiyo, containers kwa kawaida huwa nyepesi, huanza haraka, ni rahisi kuweka kwa wingi kwenye mashine, na zinafaa zaidi kwa deployment za application za muda mfupi. Gharama yake ni kwamba isolation boundary hutegemea zaidi usahihi wa usanidi wa host na runtime.

Hii haimaanishi kwamba containers ni "insecure" na VMs ni "secure". Inamaanisha kwamba security model ni tofauti. Container stack iliyosanidiwa vizuri yenye rootless execution, user namespaces, default seccomp, capability set kali, kutoshiriki host namespaces, na enforcement thabiti ya SELinux au AppArmor inaweza kuwa imara sana. Kinyume chake, container iliyoanzishwa kwa `--privileged`, host PID/network sharing, Docker socket iliyowekwa ndani yake, na writable bind mount ya `/` kwa utendaji iko karibu zaidi na host root access kuliko application sandbox iliyotengwa salama. Tofauti inatokana na layers zilizowezeshwa au kuzimwa.

Pia kuna kiwango cha kati ambacho wasomaji wanapaswa kukielewa kwa sababu kinaonekana zaidi na zaidi katika mazingira halisi. **Sandboxed container runtimes** kama **gVisor** na **Kata Containers** huimarisha boundary kimakusudi zaidi ya `runc` container ya kawaida. gVisor huweka userspace kernel layer kati ya workload na interfaces nyingi za host kernel, huku Kata ikianzisha workload ndani ya lightweight virtual machine. Hizi bado hutumiwa kupitia container ecosystems na orchestration workflows, lakini security properties zake hutofautiana na plain OCI runtimes na hazipaswi kuwekwa kiakili katika kundi la "normal Docker containers" kana kwamba kila kitu hufanya kazi kwa namna ileile.

## Container Stack: Layers Kadhaa, Sio Moja

Mtu anaposema "this container is insecure", swali la maana la kufuatia ni: **ni layer gani iliyoifanya isiwe salama?** Containerized workload kwa kawaida hutokana na components kadhaa zinazofanya kazi pamoja.

Juu kabisa, mara nyingi kuna **image build layer** kama BuildKit, Buildah, au Kaniko, ambayo huunda OCI image na metadata. Juu ya low-level runtime, kunaweza kuwa na **engine au manager** kama Docker Engine, Podman, containerd, CRI-O, Incus, au systemd-nspawn. Katika cluster environments, kunaweza pia kuwa na **orchestrator** kama Kubernetes inayopanga security posture iliyoombwa kupitia workload configuration. Hatimaye, **kernel** ndiyo inayotekeleza namespaces, cgroups, seccomp, na MAC policy.

Layered model hii ni muhimu kwa kuelewa defaults. Restriction inaweza kuombwa na Kubernetes, kutafsiriwa kupitia CRI na containerd au CRI-O, kubadilishwa kuwa OCI spec na runtime wrapper, na kisha kutekelezwa na `runc`, `crun`, `runsc`, au runtime nyingine dhidi ya kernel. Defaults zinapotofautiana kati ya environments, mara nyingi ni kwa sababu mojawapo ya layers hizi ilibadilisha final configuration. Kwa hiyo, mechanism ileile inaweza kuonekana katika Docker au Podman kama CLI flag, katika Kubernetes kama Pod au `securityContext` field, na katika lower-level runtime stacks kama OCI configuration iliyotengenezwa kwa workload. Kwa sababu hiyo, CLI examples katika sehemu hii zinapaswa kusomwa kama **runtime-specific syntax ya container concept ya jumla**, si flags za kila tool.

## Container Security Boundary Halisi

Kwa vitendo, container security hutokana na **overlapping controls**, si control moja kamilifu. Namespaces hutenga visibility. cgroups husimamia na kuweka mipaka ya matumizi ya resources. Capabilities hupunguza kile ambacho process inayoonekana kuwa privileged inaweza kufanya kwa kweli. seccomp huzuia dangerous syscalls kabla hazjaufikia kernel. AppArmor na SELinux huongeza Mandatory Access Control juu ya ukaguzi wa kawaida wa DAC. `no_new_privs`, masked procfs paths, na read-only system paths hufanya privilege na proc/sys abuse chains za kawaida kuwa ngumu zaidi. Runtime yenyewe pia ni muhimu kwa sababu huamua jinsi mounts, sockets, labels, na namespace joins zinavyoundwa.

Hii ndiyo sababu nyaraka nyingi za container security huonekana kujirudia. Escape chain ileile mara nyingi hutegemea mechanisms nyingi kwa pamoja. Kwa mfano, writable host bind mount ni tatizo, lakini huwa hatari zaidi ikiwa container pia inaendesha kama root halisi kwenye host, ina `CAP_SYS_ADMIN`, haijawekewa vikwazo na seccomp, na haizuiliwi na SELinux au AppArmor. Vivyo hivyo, host PID sharing ni exposure kubwa, lakini huwa muhimu zaidi kwa attacker inapounganishwa na `CAP_SYS_PTRACE`, procfs protections dhaifu, au namespace-entry tools kama `nsenter`. Kwa hiyo, njia sahihi ya kuandika kuhusu mada hii si kurudia attack ileile kwenye kila ukurasa, bali kueleza mchango wa kila layer katika boundary ya mwisho.

## Jinsi ya Kusoma Sehemu Hii

Sehemu hii imepangwa kutoka kwenye concepts za jumla zaidi hadi zile maalum zaidi.

Anza na overview ya runtime na ecosystem:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Kisha pitia control planes na supply-chain surfaces ambazo mara nyingi huamua kama attacker anahitaji kernel escape hata kidogo:

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

## Mtazamo Mzuri wa Kuanza Enumeration

Unapotathmini containerized target, ni muhimu zaidi kuuliza seti ndogo ya maswali sahihi ya kiufundi kuliko kukimbilia mara moja famous escape PoCs. Kwanza, tambua **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer, au kitu maalum zaidi. Kisha tambua **runtime**: `runc`, `crun`, `runsc`, `kata-runtime`, au implementation nyingine inayooana na OCI. Baada ya hapo, angalia kama mazingira ni **rootful au rootless**, kama **user namespaces** ziko active, kama **host namespaces** zozote zinashirikiwa, ni **capabilities** zipi zimesalia, kama **seccomp** imewezeshwa, kama **MAC policy** inatekelezwa kwa kweli, kama **dangerous mounts au sockets** zipo, na kama process inaweza kuwasiliana na container runtime API.

Majibu hayo yanakuambia mengi zaidi kuhusu security posture halisi kuliko jina la base image. Katika assessments nyingi, unaweza kutabiri family ya breakout inayowezekana kabla ya kusoma hata application file moja, kwa kuelewa tu final container configuration.

## Coverage

Sehemu hii inashughulikia material ya zamani iliyolenga Docker, ikiwa imepangwa kwa mtazamo wa containers: runtime na daemon exposure, authorization plugins, image trust na build secrets, sensitive host mounts, distroless workloads, privileged containers, na kernel protections ambazo kwa kawaida huwekwa karibu na container execution.
{{#include ../../../banners/hacktricks-training.md}}
