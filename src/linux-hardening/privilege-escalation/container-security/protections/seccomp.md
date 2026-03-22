# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Muhtasari

**seccomp** ni utaratibu unaomruhusu kernel kutumia kichujio kwa syscalls ambazo mchakato unaweza kuita. Katika mazingira ya containerized, seccomp kwa kawaida hutumika katika filter mode ili mchakato usibaki tu alama "restricted" kwa maana isiyoeleweka, bali awe chini ya sera maalum ya syscall. Hii ni muhimu kwa sababu kuvunja container nyingi kunahitaji kufikia interfaces maalum za kernel. Ikiwa mchakato hauwezi kwa mafanikio kuita syscalls husika, kundi kubwa la mashambulizi linapotea kabla hata masuala yoyote ya namespace au capability kuwa muhimu.

Mfano wa kimsingi wa kifikra ni rahisi: namespaces huamua **ni nini mchakato unaweza kuona**, capabilities huamua **ni hatua gani zenye ruhusa za kipekee mchakato kwa kawaida anaruhusiwa kujaribu**, na seccomp huamua **je, kernel hata itakubali entry point ya syscall kwa hatua inayojaribiwa**. Hii ndio sababu seccomp mara nyingi inazuia mashambulizi ambayo vinginevyo yataonekana kuwa yanawezekana kwa kutegemea capabilities pekee.

## Madhara kwa Usalama

Sehemu kubwa hatarishi ya uso wa kernel inapatikana tu kupitia set ndogo ya syscalls. Mifano ambayo mara kwa mara ni muhimu katika hardening ya container ni pamoja na `mount`, `unshare`, `clone` au `clone3` kwa bendera maalum, `bpf`, `ptrace`, `keyctl`, na `perf_event_open`. Mshambuliaji ambaye anaweza kufikia syscalls hizo anaweza kuunda namespaces mpya, kubadilisha subsystems za kernel, au kuingiliana na uso wa mashambulizi ambao container ya kawaida ya programu haihitaji kabisa.

Hili ndilo sababu profaili za seccomp za runtime kwa default ni muhimu sana. Sio ziada tu ya "defense". Katika mazingira mengi ni tofauti kati ya container inayoweza kutumia sehemu kubwa ya utendaji wa kernel na ile iliyopunguzwa kwa uso wa syscall unaokaribia kile programu inachohitaji kweli.

## Modes Na Uundaji wa Filter

seccomp kihistoria ilikuwa na strict mode ambapo set ndogo sana ya syscall ilibaki inapatikana, lakini mode inayohusiana na runtimes za container za kisasa ni seccomp filter mode, mara nyingi inayoitwa **seccomp-bpf**. Katika mtiririko huu, kernel hupima programu ya filter inayopiga uamuzi kama syscall inapaswa kuruhusiwa, kukataliwa kwa errno, kushikwa (trapped), kuandikwa (logged), au kuua mchakato. Container runtimes hutumia utaratibu huu kwa sababu unaelezea vya kutosha kuzuia makundi makubwa ya syscalls hatarishi huku bado ukiruhusu tabia ya kawaida ya programu.

Mifano miwili ya chini ya ngazi ni yenye faida kwa sababu hufanya utaratibu kuwa wa kimkakati badala ya kuwa wa kichawi. Strict mode inaonyesha modeli ya zamani ya "only a minimal syscall set survives":
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
`open` ya mwisho husababisha mchakato kukatizwa kwa sababu sio sehemu ya seti ndogo ya strict mode.

Mfano wa filter ya libseccomp unaonyesha modeli ya sera ya kisasa kwa uwazi zaidi:
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
Aina hii ya sera ndiyo picha ambayo wasomaji wengi wanapaswa kuwa nayo wanapofikiria profaili za seccomp za runtime.

## Maabara

Njia rahisi ya kuthibitisha kwamba seccomp inafanya kazi katika container ni:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Unaweza pia kujaribu operesheni ambayo profaili za default kwa kawaida huzuia:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Ikiwa container inakimbia chini ya seccomp profile ya kawaida ya default, operesheni za mtindo wa `unshare` mara nyingi huzuiliwa. Hii ni onyesho muhimu kwa sababu inaonyesha kwamba hata kama userspace tool ipo ndani ya image, kernel path inayohitajika inaweza bado isipatikane.

Ikiwa container inakimbia chini ya seccomp profile ya kawaida ya default, operesheni za mtindo wa `unshare` mara nyingi huzuiliwa hata wakati userspace tool ipo ndani ya image.

Ili kuchunguza hali ya mchakato kwa ujumla, endesha:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Matumizi ya runtime

Docker inaunga mkono profaili za seccomp za chaguo-msingi na zilizobinafsishwa na inawawezesha wasimamizi kuzizima kwa kutumia `--security-opt seccomp=unconfined`. Podman ina msaada sawa na mara nyingi huoanisha seccomp na utekekezaji bila root (rootless execution) katika mtazamo wa chaguo-msingi unaofaa. Kubernetes inafichua seccomp kupitia usanidi wa workload, ambapo `RuntimeDefault` kwa kawaida ni msingi wa busara na `Unconfined` inapaswa kuchukuliwa kama isipokuwa inayohitaji uhalali badala ya kuwa kitufe cha urahisi.

Katika mazingira yanayotegemea containerd na CRI-O, njia halisi ina tabaka zaidi, lakini kanuni ni ile ile: engine au orchestrator wa ngazi ya juu huamua kinachopaswa kutokea, na runtime hatimaye inainstalisha sera ya seccomp iliyotokana kwa mchakato wa container. Matokeo bado yanategemea usanidi wa mwisho wa runtime unaofika kwenye kernel.

### Mfano wa Sera Iliyobinafsishwa

Docker na engine zinazofanana zinaweza kupakia profaili ya seccomp iliyobinafsishwa kutoka JSON. Mfano mdogo unaokataa `chmod` huku ukiruhusu kila kitu kingine unaonekana kama ifuatayo:
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
The command fails with `Operation not permitted`, demonstrating that the restriction comes from the syscall policy rather than from ordinary file permissions alone. In real hardening, allowlists are generally stronger than permissive defaults with a small blacklist.

## Misconfigurations

The bluntest mistake is to set seccomp to **unconfined** because an application failed under the default policy. This is common during troubleshooting and very dangerous as a permanent fix. Once the filter is gone, many syscall-based breakout primitives become reachable again, especially when powerful capabilities or host namespace sharing are also present.

Another frequent problem is the use of a **custom permissive profile** that was copied from some blog or internal workaround without being reviewed carefully. Teams sometimes retain almost all dangerous syscalls simply because the profile was built around "stop the app from breaking" rather than "grant only what the app actually needs". A third misconception is to assume seccomp is less important for non-root containers. In reality, plenty of kernel attack surface remains relevant even when the process is not UID 0.

## Abuse

If seccomp is absent or badly weakened, an attacker may be able to invoke namespace-creation syscalls, expand the reachable kernel attack surface through `bpf` or `perf_event_open`, abuse `keyctl`, or combine those syscall paths with dangerous capabilities such as `CAP_SYS_ADMIN`. In many real attacks, seccomp is not the only missing control, but its absence shortens the exploit path dramatically because it removes one of the few defenses that can stop a risky syscall before the rest of the privilege model even comes into play.

The most useful practical test is to try the exact syscall families that default profiles usually block. If they suddenly work, the container posture has changed a lot:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Ikiwa `CAP_SYS_ADMIN` au capability nyingine yenye nguvu ipo, jaribu kama seccomp ni kizuizi pekee kabla ya mount-based abuse:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Kwenye baadhi ya malengo, thamani ya papo hapo si kutoroka kabisa bali ukusanyaji wa taarifa na kupanua kernel attack-surface. Amri hizi husaidia kubaini kama hasa nyeti syscall paths zinaweza kufikiwa:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Ikiwa seccomp haipo na container pia ina vipaumbele kwa njia nyingine, hapo ndipo inakuwa na maana kuhamia kwenye mbinu maalum za breakout ambazo tayari zimeandikwa katika kurasa za legacy container-escape.

### Mfano Kamili: seccomp Ilikuwa Pekee Iliyozuia `unshare`

Kwenye malengo mengi, athari ya vitendo ya kuondoa seccomp ni kwamba namespace-creation au mount syscalls ghafla huanza kufanya kazi. Ikiwa container pia ina `CAP_SYS_ADMIN`, mlolongo ufuatao unaweza kuwa uwezekano:
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
Peke yake, hili bado si host escape, lakini linaonyesha kwamba seccomp ilikuwa kizuizi kilichokuwa kinazuia mount-related exploitation.

### Mfano Kamili: seccomp Imezimwa + cgroup v1 `release_agent`

Ikiwa seccomp imezimwa na container inaweza mount hierarchies za cgroup v1, mbinu ya `release_agent` kutoka sehemu ya cgroups inakuwa inapatikana:
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
Hii si seccomp-only exploit. Kusudi ni kwamba mara seccomp inapokuwa bila vikwazo, syscall-heavy breakout chains ambazo awali zilikuwa zimezuiwa zinaweza kuanza kufanya kazi kabisa kama zilivyoandikwa.

## Ukaguzi

Madhumuni ya ukaguzi huu ni kubaini ikiwa seccomp inafanya kazi kabisa, ikiwa `no_new_privs` inaambatana nayo, na ikiwa usanidi wa runtime unaonyesha seccomp imezimwa waziwazi.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Kinachovutia hapa:

- Thamani ya `Seccomp` isiyokuwa sifuri ina maana uchujaji umewekwa; `0` kwa kawaida ina maana hakuna ulinzi wa seccomp.
- Ikiwa chaguzi za usalama za runtime zinajumuisha `seccomp=unconfined`, workload imepoteza mojawapo ya kinga muhimu za syscall-level.
- `NoNewPrivs` si seccomp yenyewe, lakini kuona zote mbili pamoja kwa kawaida inaashiria mkao makini zaidi wa hardening kuliko kuona hakuna.

Ikiwa container tayari ina suspicious mounts, broad capabilities, au shared host namespaces, na seccomp pia ni unconfined, mchanganyiko huo unapaswa kuchukuliwa kama ishara kubwa ya escalation. Container inaweza bado isiwe rahisi kuvunjika, lakini idadi ya kernel entry points zinazopatikana kwa mshambuliaji imeongezeka kwa kiasi kikubwa.

## Chaguo-msingi za Runtime

| Runtime / platform | Hali ya chaguo-msingi | Tabia ya chaguo-msingi | Udhoofishaji wa mkono unaotumika mara kwa mara |
| --- | --- | --- | --- |
| Docker Engine | Kawaida imewezeshwa kwa chaguo-msingi | Inatumia seccomp profile ya chaguo-msingi ya Docker isipokuwa ikibadilishwa | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Kawaida imewezeshwa kwa chaguo-msingi | Inatumia seccomp profile ya runtime isipokuwa ikibadilishwa | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Haijahakikishiwa kwa chaguo-msingi** | Ikiwa `securityContext.seccompProfile` haijowekwa, chaguo-msingi ni `Unconfined` isipokuwa kubelet ianze `--seccomp-default`; vinginevyo `RuntimeDefault` au `Localhost` lazima iwe imewekwa wazi | `securityContext.seccompProfile.type: Unconfined`, leaving seccomp unset on clusters without `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Inafuata mipangilio ya node na Pod za Kubernetes | Profaili ya runtime inatumiwa wakati Kubernetes inaomba `RuntimeDefault` au wakati kubelet imewezeshwa kufanya default ya seccomp | Same as Kubernetes row; direct CRI/OCI configuration can also omit seccomp entirely |

Tabia ya Kubernetes ndiyo mara nyingi huwatangaza waendeshaji. Katika clusters nyingi, seccomp bado haipo isipokuwa Pod itaiomba au kubelet imewekwa ili kutumia default `RuntimeDefault`.
{{#include ../../../../banners/hacktricks-training.md}}
