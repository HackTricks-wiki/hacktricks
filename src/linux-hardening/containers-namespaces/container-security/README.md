# Usalama wa Kontena

## Kontena Ni Nini Kwa Hakika

Njia ya kivitendo ya kufafanua kontena ni hii: kontena ni **mti wa kawaida wa michakato ya Linux** ulioanzishwa chini ya usanidi maalum wa mtindo wa OCI ili uone mfumo wa faili unaodhibitiwa, seti inayodhibitiwa ya rasilimali za kernel, na muundo wa privileges uliowekewa mipaka. Mchakato unaweza kuamini kuwa ni PID 1, unaweza kuamini kuwa una network stack yake, unaweza kuamini kuwa unamiliki hostname na rasilimali zake za IPC, na unaweza hata kuendeshwa kama root ndani ya user namespace yake. Lakini kwa ndani bado ni mchakato wa host ambao kernel huupangia muda wa CPU kama michakato mingine yote.

Hii ndiyo sababu container security kwa hakika ni utafiti wa jinsi taswira hiyo inavyoundwa na jinsi inavyoshindwa. Ikiwa mount namespace ni dhaifu, mchakato unaweza kuona mfumo wa faili wa host. Ikiwa user namespace haipo au imezimwa, root ndani ya kontena inaweza kuhusishwa kwa ukaribu sana na root kwenye host. Ikiwa seccomp haijawekewa vizuizi na seti ya capabilities ni pana mno, mchakato unaweza kufikia syscalls na vipengele vya kernel vyenye privileges ambavyo vilipaswa kubaki nje ya ufikiaji. Ikiwa runtime socket ime-mount ndani ya kontena, kontena huenda lisihitaji kernel breakout hata kidogo kwa sababu linaweza kuiomba runtime ianzishe sibling container yenye nguvu zaidi au i-mount moja kwa moja host root filesystem.

## Kontena Zinatofautianaje na Virtual Machines

VM kwa kawaida huwa na kernel yake na mpaka wake wa hardware abstraction. Hii inamaanisha guest kernel inaweza ku-crash, ku-panic, au kutumiwa vibaya bila kuashiria moja kwa moja udhibiti wa host kernel. Kwenye kontena, workload haipati kernel tofauti. Badala yake, hupata mwonekano wa kernel hiyo hiyo inayotumiwa na host, lakini uliyochujwa na kuwekwa kwenye namespaces kwa uangalifu. Kwa hiyo, kontena kwa kawaida huwa nyepesi zaidi, huanza haraka zaidi, ni rahisi kupakia nyingi kwenye mashine moja, na zinafaa zaidi kwa application deployment za muda mfupi. Gharama yake ni kwamba mpaka wa isolation hutegemea zaidi usahihi wa usanidi wa host na runtime.

Hii haimaanishi kuwa kontena ni "insecure" na VM ni "secure". Inamaanisha kuwa security model ni tofauti. Container stack iliyosanidiwa vizuri ikiwa na rootless execution, user namespaces, default seccomp, seti madhubuti ya capabilities, kutoshirikisha host namespaces, na utekelezaji imara wa SELinux au AppArmor inaweza kuwa imara sana. Kinyume chake, kontena lililoanzishwa kwa `--privileged`, kushirikisha host PID/network, Docker socket iliyo-mount ndani yake, na bind mount inayoweza kuandikwa ya `/`, huwa kiutendaji karibu zaidi na ufikiaji wa host root kuliko application sandbox iliyotengwa salama. Tofauti hiyo hutokana na layers zilizowezeshwa au kuzimwa.

Pia kuna hali ya kati ambayo wasomaji wanapaswa kuielewa kwa sababu inaonekana zaidi na zaidi katika mazingira halisi. **Sandboxed container runtimes** kama **gVisor** na **Kata Containers** huimarisha mpaka zaidi ya kontena la kawaida la `runc`. gVisor huweka userspace kernel layer kati ya workload na interfaces nyingi za host kernel, huku Kata ikiendesha workload ndani ya virtual machine nyepesi. Hizi bado hutumiwa kupitia container ecosystems na orchestration workflows, lakini security properties zake hutofautiana na plain OCI runtimes na hazipaswi kuwekwa kiakili pamoja na "normal Docker containers" kana kwamba kila kitu hufanya kazi kwa njia ileile.

## Container Stack: Layers Kadhaa, Sio Moja

Mtu anaposema "this container is insecure", swali muhimu linalofuata ni: **ni layer ipi iliyoifanya isiwe salama?** Workload ya containerized kwa kawaida hutokana na vipengele kadhaa vinavyofanya kazi pamoja.

Juu kabisa, mara nyingi kuna **image build layer** kama BuildKit, Buildah, au Kaniko, ambayo huunda OCI image na metadata. Juu ya low-level runtime, kunaweza kuwa na **engine au manager** kama Docker Engine, Podman, containerd, CRI-O, Incus, au systemd-nspawn. Katika cluster environments, kunaweza pia kuwa na **orchestrator** kama Kubernetes inayoamua security posture inayohitajika kupitia workload configuration. Hatimaye, **kernel** ndiyo inayotekeleza namespaces, cgroups, seccomp, na MAC policy.

Mfano huu wa layers ni muhimu kwa kuelewa defaults. Restriction inaweza kuombwa na Kubernetes, kutafsiriwa kupitia CRI na containerd au CRI-O, kubadilishwa kuwa OCI spec na runtime wrapper, kisha kutekelezwa na `runc`, `crun`, `runsc`, au runtime nyingine dhidi ya kernel. Defaults zinapotofautiana kati ya environments, mara nyingi ni kwa sababu moja ya layers hizi ilibadilisha configuration ya mwisho. Kwa hiyo, mechanism hiyo hiyo inaweza kuonekana kwenye Docker au Podman kama CLI flag, kwenye Kubernetes kama Pod au `securityContext` field, na kwenye lower-level runtime stacks kama OCI configuration iliyozalishwa kwa workload. Kwa sababu hiyo, mifano ya CLI katika sehemu hii inapaswa kusomwa kama **runtime-specific syntax ya container concept ya jumla**, si flags za jumla zinazoungwa mkono na kila tool.

## Mpaka Halisi wa Container Security

Kwa vitendo, container security hutokana na **controls zinazoingiliana**, si control moja kamili. Namespaces hutenga mwonekano. cgroups husimamia na kuweka mipaka ya matumizi ya rasilimali. Capabilities hupunguza kile ambacho mchakato unaoonekana kuwa na privileges unaweza kufanya kwa hakika. seccomp huzuia syscalls hatari kabla hazijaufikia kernel. AppArmor na SELinux huongeza Mandatory Access Control juu ya ukaguzi wa kawaida wa DAC. `no_new_privs`, masked procfs paths, na read-only system paths hufanya privilege na proc/sys abuse chains za kawaida kuwa ngumu zaidi. Runtime yenyewe pia ni muhimu kwa sababu huamua jinsi mounts, sockets, labels, na namespace joins zinavyoundwa.

Ndiyo sababu nyaraka nyingi za container security huonekana kujirudia. Escape chain hiyo hiyo mara nyingi hutegemea mechanisms nyingi kwa wakati mmoja. Kwa mfano, writable host bind mount ni hatari, lakini huwa mbaya zaidi ikiwa kontena pia linaendeshwa kama root halisi kwenye host, lina `CAP_SYS_ADMIN`, halijawekewa vizuizi na seccomp, na halizuiliwi na SELinux au AppArmor. Vivyo hivyo, host PID sharing ni exposure kubwa, lakini huwa na manufaa makubwa zaidi kwa attacker inapounganishwa na `CAP_SYS_PTRACE`, procfs protections dhaifu, au namespace-entry tools kama `nsenter`. Njia sahihi ya kuandika kuhusu mada hii si kurudia attack hiyo hiyo kwenye kila ukurasa, bali kueleza kile ambacho kila layer huongeza kwenye mpaka wa mwisho.

## Jinsi ya Kusoma Sehemu Hii

Sehemu hii imepangwa kutoka concepts za jumla zaidi hadi zile mahususi zaidi.

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

## Mtazamo Mzuri wa Kuanza Enumeration

Unapotathmini target ya containerized, ni muhimu zaidi kuuliza seti ndogo ya maswali sahihi ya kiufundi kuliko kurukia mara moja escape PoCs maarufu. Kwanza, tambua **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer, au kitu maalum zaidi. Kisha tambua **runtime**: `runc`, `crun`, `runsc`, `kata-runtime`, au implementation nyingine inayooana na OCI. Baada ya hapo, angalia ikiwa environment ni **rootful au rootless**, ikiwa **user namespaces** ziko active, ikiwa kuna **host namespaces** zinazoshirikiwa, ni **capabilities** zipi zimesalia, ikiwa **seccomp** imewezeshwa, ikiwa **MAC policy** inatekelezwa kwa hakika, ikiwa **dangerous mounts au sockets** zipo, na ikiwa mchakato unaweza kuwasiliana na container runtime API.

Majibu hayo yanakuambia mengi zaidi kuhusu security posture halisi kuliko jina la base image. Katika assessments nyingi, unaweza kutabiri family ya breakout inayowezekana kabla ya kusoma hata file moja ya application kwa kuelewa tu container configuration ya mwisho.

## Coverage

Sehemu hii inashughulikia material ya zamani iliyolenga Docker, sasa ikiwa chini ya mpangilio unaolenga kontena: runtime na daemon exposure, authorization plugins, image trust na build secrets, sensitive host mounts, distroless workloads, privileged containers, na kernel protections ambazo kwa kawaida huwekwa kuzunguka container execution.

{{#include ../../../banners/hacktricks-training.md}}
