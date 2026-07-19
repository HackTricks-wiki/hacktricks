# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Muhtasari

**seccomp** ni mechanism inayowezesha kernel kuweka filter kwenye syscalls ambazo process inaweza kuita. Katika mazingira ya containerized, seccomp kwa kawaida hutumika katika filter mode ili process isiwekwe tu alama ya kuwa "restricted" kwa maana isiyo wazi, bali iwe chini ya syscall policy mahususi. Hili ni muhimu kwa sababu container breakouts nyingi zinahitaji kufikia kernel interfaces mahususi sana. Ikiwa process haiwezi kuita syscalls husika kwa mafanikio, kundi kubwa la attacks huondolewa kabla hata nuances za namespace au capability hazijawa muhimu.

Mental model muhimu ni rahisi: namespaces huamua **kile ambacho process inaweza kuona**, capabilities huamua **ni vitendo gani vya privileged ambavyo process inaruhusiwa kinominal kujaribu**, na seccomp huamua **ikiwa kernel itakubali hata syscall entry point kwa kitendo kinachojaribiwa**. Ndiyo sababu seccomp mara nyingi huzuia attacks ambazo vinginevyo zingeonekana kuwa zinawezekana kwa kuzingatia capabilities pekee.

## Athari za Usalama

Sehemu kubwa ya kernel surface yenye hatari hupatikana kupitia seti ndogo kiasi ya syscalls. Mifano ambayo hurudiwa kuwa muhimu katika container hardening ni `mount`, `unshare`, `clone` au `clone3` zenye flags mahususi, `bpf`, `ptrace`, `keyctl`, na `perf_event_open`. Attacker anayeweza kufikia syscalls hizo anaweza kuunda namespaces mpya, kuendesha manipulations kwenye kernel subsystems, au kuingiliana na attack surface ambayo application container ya kawaida haihitaji kabisa.

Ndiyo sababu default runtime seccomp profiles ni muhimu sana. Si "extra defense" tu. Katika mazingira mengi, ndizo tofauti kati ya container inayoweza kutumia sehemu kubwa ya kernel functionality na ile iliyozuiwa kwenye syscall surface iliyo karibu zaidi na kile ambacho application inahitaji kwa kweli.

## Modes na Uundaji wa Filter

seccomp kihistoria ilikuwa na strict mode ambapo seti ndogo sana ya syscalls pekee ndiyo iliendelea kupatikana, lakini mode inayohusika na modern container runtimes ni seccomp filter mode, ambayo mara nyingi huitwa **seccomp-bpf**. Katika model hii, kernel hutathmini filter program inayoamua ikiwa syscall inapaswa kuruhusiwa, kukataliwa kwa errno, kutegwa, kurekodiwa kwenye log, au kuua process. Container runtimes hutumia mechanism hii kwa sababu ina uwezo wa kutosha kuzuia makundi mapana ya syscalls hatari huku ikiendelea kuruhusu tabia ya kawaida ya application.

Mifano miwili ya kiwango cha chini ni muhimu kwa sababu hufanya mechanism hii iwe halisi badala ya kuonekana ya kichawi. Strict mode huonyesha model ya zamani ya "seti ndogo tu ya syscalls ndiyo huendelea kufanya kazi":
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

Mfano wa filter ya libseccomp unaonyesha kwa uwazi zaidi model ya kisasa ya policy:
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

Njia rahisi ya kuthibitisha kwamba seccomp imewashwa kwenye container ni:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Unaweza pia kujaribu operesheni ambayo profiles za chaguo-msingi kwa kawaida huzuia:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Ikiwa container inaendeshwa chini ya seccomp profile ya kawaida ya default, operations za mtindo wa `unshare` mara nyingi huzuiwa. Huu ni mfano muhimu kwa sababu unaonyesha kwamba hata kama tool ya userspace ipo ndani ya image, kernel path inayohitajika bado inaweza kutopatikana.

Ikiwa container inaendeshwa chini ya seccomp profile ya kawaida ya default, operations za mtindo wa `unshare` mara nyingi huzuiwa hata wakati tool ya userspace ipo ndani ya image.

Ili kuchunguza hali ya mchakato kwa ujumla zaidi, endesha:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Matumizi ya Runtime

Docker inasaidia seccomp profiles za default na custom, na inaruhusu administrators kuzizima kwa kutumia `--security-opt seccomp=unconfined`. Podman ina support inayofanana na mara nyingi huunganisha seccomp na rootless execution katika posture ya default yenye busara. Kubernetes hutoa seccomp kupitia workload configuration, ambapo `RuntimeDefault` kwa kawaida huwa baseline inayofaa, na `Unconfined` inapaswa kuchukuliwa kama exception inayohitaji justification badala ya toggle ya convenience.

Katika environments zinazotegemea containerd na CRI-O, njia halisi ina layers zaidi, lakini principle ni ileile: engine au orchestrator ya kiwango cha juu huamua kinachopaswa kutokea, na runtime hatimaye huweka seccomp policy inayotokana kwa container process. Matokeo bado yanategemea runtime configuration ya mwisho inayofika kwenye kernel.

### Mfano wa Custom Policy

Docker na engines zinazofanana zinaweza kupakia custom seccomp profile kutoka JSON. Mfano mdogo unaokataa `chmod` huku ukiruhusu kila kitu kingine unaonekana hivi:
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
Amri inashindwa kwa `Operation not permitted`, ikionyesha kwamba kizuizi kinatokana na sera ya syscall badala ya ruhusa za kawaida za faili pekee. Katika hardening halisi, allowlists kwa ujumla huwa na nguvu zaidi kuliko defaults zinazoruhusu mengi zikiwa na blacklist ndogo.

## Misconfigurations

Kosa kubwa zaidi ni kuweka seccomp kuwa **unconfined** kwa sababu application ilishindwa kufanya kazi chini ya sera ya default. Hili hutokea mara nyingi wakati wa troubleshooting na ni hatari sana likitumika kama suluhisho la kudumu. Filter inapoondolewa, primitives nyingi za breakout zinazotegemea syscall hupatikana tena, hasa pale capabilities zenye nguvu au kushiriki host namespace pia kunapokuwepo.

Tatizo lingine la mara kwa mara ni kutumia **custom permissive profile** iliyonakiliwa kutoka kwenye blogu fulani au workaround ya ndani bila kufanyiwa review kwa uangalifu. Wakati mwingine teams huacha karibu syscalls zote hatari kwa sababu profile iliundwa kwa msingi wa "zuia app isivunjike" badala ya "ruhusu tu kile ambacho app inahitaji kweli". Dhana nyingine potofu ni kudhani kwamba seccomp haina umuhimu mkubwa kwa non-root containers. Kwa uhalisia, sehemu kubwa ya kernel attack surface bado ni muhimu hata process ikiwa si UID 0.

## Abuse

Ikiwa seccomp haipo au imelegezwa vibaya, attacker anaweza kuwa na uwezo wa kuita syscalls za kuunda namespace, kupanua kernel attack surface inayofikika kupitia `bpf` au `perf_event_open`, kutumia vibaya `keyctl`, au kuchanganya njia hizo za syscall na capabilities hatari kama `CAP_SYS_ADMIN`. Katika attacks nyingi halisi, seccomp si control pekee inayokosekana, lakini kutokuwepo kwake hufupisha exploit path kwa kiasi kikubwa kwa sababu huondoa mojawapo ya defenses chache zinazoweza kuzuia syscall yenye risk kabla sehemu nyingine ya privilege model haijaanza kutumika.

Test ya vitendo yenye manufaa zaidi ni kujaribu familia halisi za syscall ambazo default profiles kwa kawaida huzuia. Ikiwa ghafla zinafanya kazi, posture ya container imebadilika sana:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Ikiwa `CAP_SYS_ADMIN` au capability nyingine yenye nguvu ipo, jaribu kubaini kama seccomp ndiyo kizuizi pekee kilichokosekana kabla ya matumizi mabaya yanayotegemea mount:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Kwenye baadhi ya targets, thamani ya papo hapo si full escape, bali ni ukusanyaji wa taarifa na kupanua attack surface ya kernel. Amri hizi husaidia kubaini ikiwa njia za syscall zilizo nyeti hasa zinaweza kufikiwa:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Ikiwa seccomp haipo na container pia ina privileged kwa njia nyingine, hapo ndipo inapokuwa na maana kufanya pivot kuelekea mbinu mahususi zaidi za breakout ambazo tayari zimeandikwa kwenye kurasa za zamani za container-escape.

### Mfano Kamili: seccomp Ndiyo Kitu Pekee Kilichokuwa Kikizuia `unshare`

Kwenye targets nyingi, athari ya kuondoa seccomp kwa vitendo ni kwamba namespace-creation au mount syscalls huanza kufanya kazi ghafla. Ikiwa container pia ina `CAP_SYS_ADMIN`, mfuatano ufuatao unaweza kuwazekana:
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
Peke yake, hii bado si host escape, lakini inaonyesha kwamba seccomp ndiyo kizuizi kilichozuia exploitation inayohusiana na mount.

### Mfano Kamili: seccomp Imezimwa + `release_agent` ya cgroup v1

Ikiwa seccomp imezimwa na container inaweza ku-mount hierarchies za cgroup v1, technique ya `release_agent` kutoka sehemu ya cgroups inakuwa reachable:
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
Hii si exploit ya seccomp pekee. Hoja ni kwamba seccomp inapokuwa unconfined, chains za breakout zenye syscalls nyingi ambazo hapo awali zilikuwa zimezuiwa zinaweza kuanza kufanya kazi jinsi zilivyoandikwa.

## Ukaguzi

Madhumuni ya ukaguzi huu ni kubaini ikiwa seccomp inatumika kabisa, ikiwa `no_new_privs` inaambatana nayo, na ikiwa usanidi wa runtime unaonyesha kuwa seccomp imezimwa waziwazi.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Kinachovutia hapa:

- Thamani ya `Seccomp` isiyo sifuri inamaanisha filtering imewashwa; `0` kwa kawaida inamaanisha hakuna ulinzi wa seccomp.
- Ikiwa security options za runtime zinajumuisha `seccomp=unconfined`, workload imepoteza mojawapo ya defenses zake muhimu zaidi katika kiwango cha syscall.
- `NoNewPrivs` si seccomp yenyewe, lakini kuona zote pamoja kwa kawaida kunaonyesha mkao wa hardening ulio makini zaidi kuliko kutokuona zote mbili.

Ikiwa container tayari ina mounts zinazotia shaka, capabilities pana, au shared host namespaces, na seccomp pia iko `unconfined`, mchanganyiko huo unapaswa kuchukuliwa kama ishara kubwa ya escalation. Container huenda bado isiwe rahisi kuvunjwa, lakini idadi ya kernel entry points zinazopatikana kwa attacker imeongezeka kwa kiwango kikubwa.

## Defaults za Runtime

| Runtime / platform | Hali ya default | Tabia ya default | Kudhoofisha kwa kawaida kwa mikono |
| --- | --- | --- | --- |
| Docker Engine | Kwa kawaida imewashwa kwa default | Hutumia default seccomp profile iliyojengwa ndani ya Docker isipokuwa ibadilishwe | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Kwa kawaida imewashwa kwa default | Hutumia default seccomp profile ya runtime isipokuwa ibadilishwe | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Haijahakikishwa kwa default** | Ikiwa `securityContext.seccompProfile` haijawekwa, default ni `Unconfined` isipokuwa kubelet iwe imewashwa kwa `--seccomp-default`; `RuntimeDefault` au `Localhost` lazima vinginevyo viwekwe wazi | `securityContext.seccompProfile.type: Unconfined`, kuacha seccomp bila kuwekwa kwenye clusters zisizo na `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Hufuata settings za Kubernetes node na Pod | Runtime profile hutumika Kubernetes inapoomba `RuntimeDefault` au kubelet seccomp defaulting inapowashwa | Sawa na row ya Kubernetes; configuration ya moja kwa moja ya CRI/OCI pia inaweza kuacha seccomp kabisa |

Tabia ya Kubernetes ndiyo inayowashangaza operators mara nyingi zaidi. Katika clusters nyingi, seccomp bado haipo isipokuwa Pod iombe itumike au kubelet iwe imesanidiwa kuweka default kuwa `RuntimeDefault`.
{{#include ../../../../banners/hacktricks-training.md}}
