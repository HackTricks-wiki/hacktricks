# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Muhtasari

**seccomp** ni utaratibu unaomruhusu kernel kutumia filter kwa syscalls ambazo process inaweza kuita. Katika mazingira ya containerized, seccomp kawaida hutumiwa katika filter mode ili process isitegemewe tu kama "restricted" kwa maana isiyoeleweka, bali iwe imetekelezwa na sera mahususi ya syscall. Hii ni muhimu kwa sababu container breakouts nyingi zinahitaji kufikia interfaces maalum za kernel. Ikiwa process haiwezi kwa mafanikio kuita syscalls zinazohusika, daraja kubwa la mashambulizi linapotea kabla hata ya nuances za namespace au capability kuwa muhimu.

Mfano wa kimsingi wa kiakili ni rahisi: namespaces zinaamua **ni nini process inaweza kuona**, capabilities zinaamua **ni hatua zipi za kifao process kwa jina anaruhusiwa kujaribu**, na seccomp zinaamua **je, kernel hata itakubali entry point ya syscall kwa tendo lililojaribiwa**. Hii ndio sababu seccomp mara nyingi huzuia mashambulizi ambayo vinginevyo yangekuwa yanaonekana yafanikiwe kulingana na capabilities pekee.

## Athari za Usalama

Sehemu kubwa hatari ya kernel inafikiwa kwa kutumia set ndogo ya syscalls. Mifano inayotokea mara kwa mara katika hardening ya container ni pamoja na `mount`, `unshare`, `clone` au `clone3` na flag maalum, `bpf`, `ptrace`, `keyctl`, na `perf_event_open`. Mshambulizi anayefika syscalls hizo anaweza kuwa na uwezo wa kuunda namespaces mpya, kuendesha subsystems za kernel, au kuingiliana na attack surface ambayo container ya kawaida ya application haihitaji hata kidogo.

Hii ndiyo sababu default runtime seccomp profiles ni muhimu sana. Si ulinzi wa ziada tu. Katika mazingira mengi ni tofauti kati ya container inayoweza kutumia sehemu kubwa ya functionality ya kernel na ile iliyozuiliwa kwenye syscall surface iliyo karibu na kile application kwa kweli inahitaji.

## Modes na Ujenzi wa Filter

seccomp kihistoria ilikuwa na strict mode ambapo set ndogo mno ya syscalls ilibaki inapatikana, lakini mode inayohusiana na container runtimes ya kisasa ni seccomp filter mode, mara nyingi inayoitwa **seccomp-bpf**. Katika mfano huu, kernel inatathmini programu ya filter inayoyamua je syscall inaruhusiwa, inakataliwa na errno, kushikwa (trapped), kuandikwa (logged), au kuua process. Container runtimes hutumia mekanismo hii kwa sababu inaeleza vya kutosha kuzuia madaraja mapana ya syscalls hatari huku ikiacha tabia ya kawaida ya application ikiwa haiathiriki.

Mifano miwili ya chini ya kiwango ni muhimu kwa sababu hufanya utaratibu uwe wa wazi badala ya wa kichawi. Strict mode inaonyesha mfano wa zamani wa "only a minimal syscall set survives":
```c
#include <fcntl.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(void) {
int output = open("output.txt", O_WRONLY);
const char *val = "test";
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
write(output, val, strlen(val) + 1);
open("output.txt", O_RDONLY);
}
```
`open` ya mwisho husababisha mchakato kuuawa kwa sababu sio sehemu ya seti ndogo ya strict mode.

Mfano wa filter ya libseccomp unaonyesha kwa uwazi zaidi modeli ya sera ya kisasa:
```c
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));
seccomp_load(ctx);
seccomp_release(ctx);
printf("pid=%d\n", getpid());
}
```
Mtindo huu wa sera ndilo ambalo wasomaji wengi wanapaswa kufikiria wanapofikiria profaili za seccomp za runtime.

## Maabara

Njia rahisi ya kuthibitisha kuwa seccomp inafanya kazi katika container ni:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Unaweza pia kujaribu operesheni ambayo profaili chaguomsingi kwa kawaida huzizuia:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Ikiwa container inaendesha chini ya normal default seccomp profile, shughuli za aina ya `unshare` mara nyingi huwekewa vizuizi. Hii ni onyesho muhimu kwa sababu inaonyesha kwamba hata kama userspace tool ipo ndani ya image, kernel path inayohitaji inaweza bado isipatikane.

Ikiwa container inaendesha chini ya normal default seccomp profile, shughuli za aina ya `unshare` mara nyingi huwekewa vizuizi hata wakati userspace tool ipo ndani ya image.

Ili kuchunguza hali ya mchakato kwa ujumla, endesha:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Matumizi ya Runtime

Docker inaunga mkono seccomp profiles za default na za desturi na inaruhusu wasimamizi kuzizima kwa kutumia `--security-opt seccomp=unconfined`. Podman ina msaada sawa na mara nyingi huoanisha seccomp na rootless execution katika msimamo wa default unaofaa. Kubernetes inafichua seccomp kupitia configuration ya workload, ambapo `RuntimeDefault` kwa kawaida ni msingi mzuri na `Unconfined` inapaswa kutibiwa kama ubaguzi unaohitaji sababu badala ya kuwa kipengele cha urahisi.

Katika mazingira yanayotegemea containerd na CRI-O, njia kamilifu ni zilizounganishwa zaidi, lakini kanuni ni ile ile: engine ya ngazi ya juu au orchestrator huchukua uamuzi wa kile kinachotakiwa kutokea, na runtime hatimaye huweka sera ya seccomp iliyotokana kwa mchakato wa container. Matokeo bado yanategemea usanidi wa mwisho wa runtime unaofikia kernel.

### Mfano wa Sera ya Desturi

Docker na engines zinazofanana zinaweza kupakia seccomp profile ya desturi kutoka JSON. Mfano mdogo unaokataa `chmod` huku ukiruhusu kila kitu kingine unafanana na hiki:
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
Imetumika kwa:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
Amri inashindwa na `Operation not permitted`, ikionesha kwamba kizuizi kinatokana na sera ya syscall badala ya ruhusa za kawaida za faili pekee. Katika hardening halisi, allowlists kwa kawaida ni kali kuliko permissive defaults zikiwa na blacklist ndogo.

## Misconfigurations

Kosa kali zaidi ni kuweka seccomp kuwa **unconfined** kwa sababu programu ilishtuka chini ya sera ya default. Hii ni ya kawaida wakati wa kutatua matatizo na ni hatari sana kama suluhisho la kudumu. Mara chujio linapoondolewa, primitives nyingi za breakout zinazotegemea syscall zinaweza kufikiwa tena, hasa pale ambapo capabilities zenye nguvu au host namespace sharing pia zipo.

Shida nyingine ya mara kwa mara ni matumizi ya **custom permissive profile** ambayo ilinakiliwa kutoka blogi fulani au suluhisho la ndani bila kupitia kwa makini. Timu mara nyingine huhifadhi karibu syscalls zote hatarishi kwa sababu profile ilijengwa kwa lengo la "kuzuia programu kuvunjika" badala ya "kutoa tu kile programu inachohitaji". Dhaliliya ya tatu ni kudhani seccomp haitoshi kwa container zisizo za root. Kweli, sehemu nyingi za kernel attack surface bado zinahusiana hata wakati mchakato si UID 0.

## Abuse

Ikiwa seccomp haipo au imedhoofishwa vibaya, mshambuliaji anaweza kuwa na uwezo wa kuita syscalls za kutengeneza namespace, kupanua kernel attack surface inayofikiwa kupitia `bpf` au `perf_event_open`, kunyanyasa `keyctl`, au kuchanganya njia hizo za syscall na capabilities hatarishi kama `CAP_SYS_ADMIN`. Katika mashambulizi mengi ya kweli, seccomp si udhibiti pekee uliokosekana, lakini ukosefu wake hupunguza exploit path kwa kiasi kikubwa kwa sababu huondoa moja ya kinga chache zinazoweza kuzuia syscall hatari kabla ya remainder ya privilege model hata kuingiliana.

Jaribio lenye thamani zaidi kivitendo ni kujaribu familia za syscall ambazo default profiles kawaida huzuia. Ikiwa ghafla zinaanza kufanya kazi, container posture imebadilika sana:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Ikiwa `CAP_SYS_ADMIN` au capability nyingine yenye nguvu ipo, chunguza kama seccomp ndiyo kizuizi pekee kinachokosekana kabla ya mount-based abuse:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Kwa baadhi ya malengo, lengo la papo hapo si kutoroka kabisa bali ukusanyaji wa taarifa na upanuzi wa uso wa shambulio wa kernel. Amri hizi husaidia kubaini ikiwa hasa njia za syscall nyeti zinaweza kufikiwa:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Ikiwa seccomp haipo na container pia iko privileged kwa njia nyingine, ndiyo wakati unaofaa kufanya pivot kwenda mbinu maalum za breakout ambazo tayari zimeandikwa kwenye kurasa za legacy container-escape.

### Mfano Kamili: seccomp Ilikuwa Kitu Pekee Kinachozuia `unshare`

Katika malengo mengi, athari ya vitendo ya kuondoa seccomp ni kwamba namespace-creation au mount syscalls ghafla zinaanza kufanya kazi. Ikiwa container pia ina `CAP_SYS_ADMIN`, mfuatano ufuatao unaweza kuwawezekana:
```bash
grep Seccomp /proc/self/status
capsh --print | grep cap_sys_admin
mkdir -p /tmp/nsroot
unshare -m sh -c '
mount -t tmpfs tmpfs /tmp/nsroot &&
mkdir -p /tmp/nsroot/proc &&
mount -t proc proc /tmp/nsroot/proc &&
mount | grep /tmp/nsroot
'
```
Peke yake hili bado si host escape, lakini linaonyesha kwamba seccomp ilikuwa kizuizi kilichokuwa kinazuia mount-related exploitation.

### Mfano Kamili: seccomp Imezimwa + cgroup v1 `release_agent`

Ikiwa seccomp imezimwa na container inaweza ku-mount hierarchies za cgroup v1, mbinu ya `release_agent` kutoka sehemu ya cgroups inapatikana:
```bash
grep Seccomp /proc/self/status
mount | grep cgroup
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
Hii si exploit ya seccomp pekee. Maana ni kwamba mara seccomp itakapokuwa haifungiwi, syscall-heavy breakout chains ambazo awali zilikuwa zimezuiwa zinaweza kuanza kufanya kazi hasa kama zilivyoandikwa.

## Ukaguzi

Kusudi la ukaguzi huu ni kubaini ikiwa seccomp inafanya kazi kabisa, kama `no_new_privs` inaiambatana nayo, na kama usanidi wa runtime unaonyesha seccomp imezimwa waziwazi.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
What is interesting here:

- A non-zero `Seccomp` value means filtering is active; `0` usually means no seccomp protection.
- If the runtime security options include `seccomp=unconfined`, the workload has lost one of its most useful syscall-level defenses.
- `NoNewPrivs` is not seccomp itself, but seeing both together usually indicates a more careful hardening posture than seeing neither.

If a container already has suspicious mounts, broad capabilities, or shared host namespaces, and seccomp is also unconfined, that combination should be treated as a major escalation signal. The container may still not be trivially breakable, but the number of kernel entry points available to the attacker has increased sharply.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Usually enabled by default | Uses Docker's built-in default seccomp profile unless overridden | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Usually enabled by default | Applies the runtime default seccomp profile unless overridden | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Not guaranteed by default** | If `securityContext.seccompProfile` is unset, the default is `Unconfined` unless the kubelet enables `--seccomp-default`; `RuntimeDefault` or `Localhost` must otherwise be set explicitly | `securityContext.seccompProfile.type: Unconfined`, leaving seccomp unset on clusters without `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Follows Kubernetes node and Pod settings | Runtime profile is used when Kubernetes asks for `RuntimeDefault` or when kubelet seccomp defaulting is enabled | Same as Kubernetes row; direct CRI/OCI configuration can also omit seccomp entirely |

The Kubernetes behavior is the one that most often surprises operators. In many clusters, seccomp is still absent unless the Pod requests it or the kubelet is configured to default to `RuntimeDefault`.
