# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Muhtasari

**seccomp** ni mechanism inayowezesha kernel kutumia filter kwenye syscalls ambazo process inaweza kuita. Katika mazingira ya container, seccomp kwa kawaida hutumiwa katika filter mode ili process isiwekwe tu alama ya "restricted" kwa maana isiyo wazi, bali iwe chini ya syscall policy maalum. Hili ni muhimu kwa sababu container breakouts nyingi zinahitaji kufikia kernel interfaces maalum sana. Ikiwa process haiwezi kuita syscalls husika kwa mafanikio, kundi kubwa la attacks huondolewa kabla hata maelezo yoyote kuhusu namespace au capability hayajawa muhimu.

Mental model muhimu ni rahisi: namespaces huamua **kile process inaweza kuona**, capabilities huamua **ni vitendo vipi vya privileged ambavyo process inaruhusiwa rasmi kujaribu**, na seccomp huamua **ikiwa kernel itakubali hata syscall entry point ya kitendo kinachojaribiwa**. Ndiyo maana seccomp mara nyingi huzuia attacks ambazo vinginevyo zingeonekana kuwa zinawezekana kwa kutegemea capabilities pekee.

## Athari za Usalama

Sehemu kubwa ya kernel surface yenye hatari inaweza kufikiwa kupitia seti ndogo ya syscalls. Mifano ambayo hujitokeza mara kwa mara katika container hardening ni pamoja na `mount`, `unshare`, `clone` au `clone3` zikiwa na flags maalum, `bpf`, `ptrace`, `keyctl`, na `perf_event_open`. Attacker anayeweza kufikia syscalls hizo anaweza kuunda namespaces mpya, kuendesha kernel subsystems, au kuingiliana na attack surface ambayo application container ya kawaida haihitaji kabisa.

Ndiyo maana default runtime seccomp profiles ni muhimu sana. Si "extra defense" tu. Katika mazingira mengi, ndizo hutofautisha container inayoweza kutumia sehemu pana ya kernel functionality na ile iliyowekewa kikomo kwa syscall surface iliyo karibu zaidi na kile application inachohitaji kwa kweli.

## Modes Na Uundaji wa Filter

seccomp kihistoria ilikuwa na strict mode ambapo ni seti ndogo sana ya syscalls pekee iliyobaki kupatikana, lakini mode inayohusiana na container runtimes za kisasa ni seccomp filter mode, ambayo mara nyingi huitwa **seccomp-bpf**. Katika model hii, kernel hutathmini filter program inay.amua ikiwa syscall inapaswa kuruhusiwa, kukataliwa kwa errno, kutrapiwa, kuwekewa log, au kuua process.<sup>[[1]](#references)</sup> Container runtimes hutumia mechanism hii kwa sababu ina uwezo wa kutosha kuzuia makundi mapana ya syscalls hatari huku ikiendelea kuruhusu application behavior ya kawaida.

Mifano miwili ya kiwango cha chini ni muhimu kwa sababu hufanya mechanism hii iwe halisi badala ya kuonekana kama uchawi. Strict mode huonyesha model ya zamani ya "only a minimal syscall set survives":
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
`open` ya mwisho husababisha mchakato kuuawa kwa sababu si sehemu ya seti ndogo ya strict mode.

Mfano wa filter ya libseccomp unaonyesha kwa uwazi zaidi modeli ya kisasa ya policy:
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
Aina hii ya policy ndiyo wasomaji wengi wanapaswa kuifikiria wanapofikiria runtime seccomp profiles.

## Maabara

Njia rahisi ya kuthibitisha kwamba seccomp iko active kwenye container ni:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Unaweza pia kujaribu operesheni ambayo default profiles kwa kawaida huizuia:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Ikiwa container inaendeshwa chini ya seccomp profile ya kawaida ya default, operations za mtindo wa `unshare` mara nyingi huzuiwa. Huu ni mfano muhimu kwa sababu unaonyesha kwamba hata kama userspace tool ipo ndani ya image, kernel path inayohitaji inaweza bado isipatikane.  
Ikiwa container inaendeshwa chini ya seccomp profile ya kawaida ya default, operations za mtindo wa `unshare` mara nyingi huzuiwa hata wakati userspace tool ipo ndani ya image.

Ili kukagua hali ya process kwa ujumla zaidi, endesha:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Matumizi ya Runtime

Docker inasaidia seccomp profiles za default na custom, na inawaruhusu administrators kuzizima kwa `--security-opt seccomp=unconfined`.<sup>[[2]](#references)</sup> Podman ina support inayofanana na mara nyingi huunganisha seccomp na rootless execution katika posture ya default yenye busara. Kubernetes ina expose seccomp kupitia workload configuration, ambapo `RuntimeDefault` kwa kawaida huwa baseline salama, na `Unconfined` inapaswa kuchukuliwa kama exception inayohitaji justification badala ya toggle ya convenience.<sup>[[3]](#references)</sup>

Katika environments zinazotegemea containerd na CRI-O, exact path ina layers zaidi, lakini principle ni ileile: engine au orchestrator ya kiwango cha juu huamua kinachopaswa kutokea, na runtime hatimaye hu-install seccomp policy inayotokana kwa container process. Outcome bado inategemea final runtime configuration inayofika kwenye kernel.

### Mfano wa Custom Policy

Docker na engines zinazofanana zinaweza kupakia custom seccomp profile kutoka JSON. Minimal example inayokataa `chmod` huku ikiruhusu kila kitu kingine inaonekana hivi:
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
Imetumika pamoja na:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
Amri inashindwa kwa `Operation not permitted`, ikionyesha kwamba kizuizi kinatokana na sera ya syscall badala ya ruhusa za kawaida za faili pekee. Katika hardening halisi, allowlists kwa kawaida huwa imara zaidi kuliko defaults zenye ruhusa nyingi pamoja na blacklist ndogo.

## Miskonfiguresheni

Kosa kubwa zaidi ni kuweka seccomp kuwa **unconfined** kwa sababu application imeshindwa kufanya kazi chini ya sera ya default. Hili hutokea mara nyingi wakati wa troubleshooting na ni hatari sana likitumika kama suluhisho la kudumu. Filter inapoondolewa, primitives nyingi za breakout zinazotegemea syscall hupatikana tena, hasa pale ambapo capabilities zenye nguvu au kushirikisha host namespaces pia kunahusika.

Tatizo lingine la mara kwa mara ni kutumia **custom permissive profile** iliyonakiliwa kutoka kwenye blogu fulani au workaround ya ndani bila kukaguliwa kwa uangalifu. Teams wakati mwingine huacha karibu syscalls zote hatari kwa sababu profile iliundwa kwa lengo la "kuzuia application isivunjike" badala ya "kuruhusu tu kile ambacho application inahitaji kwa kweli". Dhana nyingine potofu ni kudhani kwamba seccomp si muhimu sana kwa containers zisizo root. Kwa uhalisia, kernel attack surface nyingi bado ni muhimu hata wakati process si UID 0.

## Abuse

Ikiwa seccomp haipo au imedhoofishwa vibaya, attacker anaweza kuweza kuita syscalls za kuunda namespaces, kupanua kernel attack surface inayofikika kupitia `bpf` au `perf_event_open`, kutumia vibaya `keyctl`, au kuunganisha njia hizo za syscall na capabilities hatari kama `CAP_SYS_ADMIN`. Katika attacks nyingi halisi, seccomp si control pekee iliyokosekana, lakini kutokuwepo kwake hufupisha exploit path kwa kiasi kikubwa kwa sababu huondoa mojawapo ya defenses chache zinazoweza kusimamisha syscall hatari kabla ya sehemu nyingine ya privilege model hata kuanza kutumika.

Jaribio la vitendo lenye manufaa zaidi ni kujaribu syscall families halisi ambazo default profiles kwa kawaida huzuia. Ikiwa ghafla zinafanya kazi, security posture ya container imebadilika sana:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Ikiwa `CAP_SYS_ADMIN` au capability nyingine yenye nguvu ipo, jaribu kubaini ikiwa seccomp ndiyo kizuizi pekee kilichosalia kabla ya matumizi mabaya yanayotegemea mount:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Kwenye baadhi ya targets, thamani ya haraka si full escape bali ni ukusanyaji wa taarifa na upanuzi wa attack surface ya kernel. Commands hizi husaidia kubaini ikiwa njia za syscall zilizo nyeti hasa zinaweza kufikiwa:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Ikiwa seccomp haipo na container pia ina privileged kwa njia nyingine, hapo ndipo inapokuwa na maana kuhamia kwenye mbinu mahususi zaidi za breakout ambazo tayari zimeandikwa kwenye legacy container-escape pages.

### Mfano Kamili: seccomp Ndicho Kitu Pekee Kilichokuwa Kinazuia `unshare`

Kwenye targets nyingi, athari ya kivitendo ya kuondoa seccomp ni kwamba namespace-creation au mount syscalls huanza kufanya kazi ghafla. Ikiwa container pia ina `CAP_SYS_ADMIN`, mfululizo ufuatao unaweza kuwa possible:
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
Kwa yenyewe, hii bado si host escape, lakini inaonyesha kwamba seccomp ilikuwa kizuizi kilichozuia mount-related exploitation.

### Mfano Kamili: seccomp Imezimwa + cgroup v1 `release_agent`

Ikiwa seccomp imezimwa na container inaweza ku-mount cgroup v1 hierarchies, mbinu ya `release_agent` kutoka sehemu ya cgroups inakuwa reachable:
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
Hii si exploit ya seccomp pekee. Hoja ni kwamba mara seccomp inapokuwa unconfined, breakout chains zenye matumizi mengi ya syscall ambazo hapo awali zilikuwa zimezuiwa zinaweza kuanza kufanya kazi kama zilivyoandikwa.

## Ukaguzi

Madhumuni ya ukaguzi huu ni kubaini ikiwa seccomp iko active kabisa, ikiwa `no_new_privs` inaambatana nayo, na ikiwa runtime configuration inaonyesha seccomp ikizimwa waziwazi.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Kinachovutia hapa:

- Thamani ya `Seccomp` isiyo sifuri inamaanisha filtering imewashwa; `0` kwa kawaida inamaanisha hakuna ulinzi wa seccomp.
- Ikiwa security options za runtime zinajumuisha `seccomp=unconfined`, workload imepoteza mojawapo ya defenses zake muhimu zaidi za kiwango cha syscall.
- `NoNewPrivs` si seccomp yenyewe, lakini kuona zote mbili pamoja kwa kawaida huashiria mkao wa hardening makini zaidi kuliko kutokuona zote mbili.

Ikiwa container tayari ina mounts za kutiliwa shaka, capabilities pana, au host namespaces zilizoshirikiwa, na seccomp pia ni unconfined, mchanganyiko huo unapaswa kuchukuliwa kama signal kubwa ya escalation. Container huenda bado isiwe rahisi kuvunjwa moja kwa moja, lakini idadi ya kernel entry points zinazopatikana kwa attacker imeongezeka kwa kiwango kikubwa.

## Defaults za Runtime

| Runtime / platform | Hali ya default | Tabia ya default | Kudhoofisha kwa manual kunakotokea mara nyingi |
| --- | --- | --- | --- |
| Docker Engine | Kwa kawaida imewashwa kwa default | Hutumia default seccomp profile iliyojengwa ndani ya Docker isipokuwa ibadilishwe | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Kwa kawaida imewashwa kwa default | Hutumia default seccomp profile ya runtime isipokuwa ibadilishwe | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Haijahakikishwa kwa default** | Ikiwa `securityContext.seccompProfile` haijawekwa, default ni `Unconfined` isipokuwa kubelet iwe imewashwa kwa `--seccomp-default`; `RuntimeDefault` au `Localhost` lazima vinginevyo viwekwe wazi | `securityContext.seccompProfile.type: Unconfined`, kuacha seccomp bila kuwekwa kwenye clusters zisizo na `seccompDefault`, `privileged: true` |
| containerd / CRI-O chini ya Kubernetes | Hufuata mipangilio ya Kubernetes ya node na Pod | Runtime profile hutumiwa Kubernetes inapoomba `RuntimeDefault` au kubelet seccomp defaulting inapowashwa | Sawa na mstari wa Kubernetes; direct CRI/OCI configuration pia inaweza kuacha seccomp kabisa |

Tabia ya Kubernetes ndiyo inayowashangaza operators mara nyingi zaidi. Kwenye clusters nyingi, seccomp bado haipo isipokuwa Pod iombe au kubelet iwe imesanidiwa kutumia `RuntimeDefault` kwa default.<sup>[[3]](#references)</sup>

## References

- [1] [Linux kernel documentation: Seccomp BPF (SECure COMPuting with filters)](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [2] [Docker Docs: Seccomp security profiles for Docker](https://docs.docker.com/engine/security/seccomp/)
- [3] [Kubernetes Docs: Restrict a Container's Syscalls with seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/)

{{#include ../../../../banners/hacktricks-training.md}}
