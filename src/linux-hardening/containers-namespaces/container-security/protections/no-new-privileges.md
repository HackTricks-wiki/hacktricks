# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` ni kipengele cha kernel hardening kinachozuia process kupata privilege zaidi kupitia `execve()`. Kwa maana ya kiutendaji, flag inapowekwa, kuendesha setuid binary, setgid binary, au file yenye Linux file capabilities hakutoi privilege ya ziada zaidi ya ile ambayo process tayari ilikuwa nayo. Katika mazingira ya containerized, hili ni muhimu kwa sababu chains nyingi za privilege-escalation hutegemea kutafuta executable ndani ya image inayobadilisha privilege inapoanzishwa.

Kwa mtazamo wa kiulinzi, `no_new_privs` si mbadala wa namespaces, seccomp, au capability dropping. Ni reinforcement layer. Huzuia aina maalum ya follow-up escalation baada ya code execution kupatikana. Hii huifanya iwe muhimu hasa katika mazingira ambayo images zina helper binaries, package-manager artifacts, au legacy tools ambazo vinginevyo zingekuwa hatari zinapounganishwa na partial compromise.

## Uendeshaji

Kernel flag inayowezesha tabia hii ni `PR_SET_NO_NEW_PRIVS`. Mara inapowekwa kwa process, `execve()` calls za baadaye haziwezi kuongeza privilege. Jambo muhimu ni kwamba process bado inaweza kuendesha binaries; haiwezi tu kutumia binaries hizo kuvuka privilege boundary ambayo kernel ingekubali vinginevyo.

Tabia ya kernel pia **hurithiwa na haiwezi kubadilishwa kurudi nyuma**: task inapoweka `no_new_privs`, bit hurithiwa kupitia `fork()`, `clone()`, na `execve()`, na haiwezi kuondolewa baadaye. Hili ni muhimu katika assessments kwa sababu `NoNewPrivs: 1` moja kwenye container process kwa kawaida humaanisha descendants wanapaswa pia kubaki katika mode hiyo, isipokuwa unachunguza process tree tofauti kabisa.

Katika mazingira yanayolenga Kubernetes, `allowPrivilegeEscalation: false` huwakilisha tabia hii kwa container process. Katika runtimes za mtindo wa Docker na Podman, sawa na hii kwa kawaida huwezeshwa wazi kupitia security option. Kwenye OCI layer, concept hiyo hiyo huonekana kama `process.noNewPrivileges`.

## Nuances Muhimu

`no_new_privs` huzuia **exec-time** privilege gain, si kila mabadiliko ya privilege. Hasa:

- setuid na setgid transitions huacha kufanya kazi kupitia `execve()`
- file capabilities haziongezi chochote kwenye permitted set kupitia `execve()`
- LSMs kama AppArmor au SELinux hazilegezi constraints baada ya `execve()`
- privilege ambayo tayari imeshikiliwa bado ni privilege ambayo tayari imeshikiliwa

Jambo hilo la mwisho ni muhimu kiutendaji. Ikiwa process tayari inaendeshwa kama root, tayari ina dangerous capability, au tayari ina access kwa powerful runtime API au writable host mount, kuweka `no_new_privs` hakubatilishi exposures hizo. Huondoa tu **next step** moja ya kawaida katika privilege-escalation chain.

Pia zingatia kwamba flag hii haizuii privilege changes ambazo hazitegemei `execve()`. Kwa mfano, task ambayo tayari ina privilege ya kutosha bado inaweza kuita `setuid(2)` moja kwa moja au kupokea privileged file descriptor kupitia Unix socket. Ndiyo maana `no_new_privs` inapaswa kusomwa pamoja na [seccomp](seccomp.md), capability sets, na namespace exposure badala ya kuichukulia kama jibu la pekee.

## Lab

Kagua hali ya process ya sasa:
```bash
grep NoNewPrivs /proc/self/status
```
Linganisha hilo na container ambayo runtime imewezesha flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Kwenye workload iliyoimarishwa, matokeo yanapaswa kuonyesha `NoNewPrivs: 1`.

Unaweza pia kuonyesha athari halisi dhidi ya binary ya setuid:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
Hoja ya ulinganisho si kwamba `su` inaweza kutumiwa vibaya kila mahali. Ni kwamba image hiyo hiyo inaweza kufanya kazi kwa njia tofauti sana kulingana na iwapo `execve()` bado inaruhusiwa kuvuka mpaka wa privileges.

## Athari za Usalama

Ikiwa `no_new_privs` haijawekwa, foothold ndani ya container bado inaweza kuongezewa privileges kupitia setuid helpers au binaries zenye file capabilities. Ikiwa imewekwa, mabadiliko hayo ya privileges baada ya exec yanazuiwa. Athari hii ni muhimu hasa katika base images pana zinazosambaza utilities nyingi ambazo application haikuzihitaji tangu mwanzo.

Pia kuna mwingiliano muhimu wa seccomp. Tasks zisizo na privileges kwa ujumla zinahitaji `no_new_privs` iwekwe kabla ya kusakinisha seccomp filter katika filter mode. Hii ni mojawapo ya sababu zinazofanya containers zilizoimarishwa mara nyingi zionyeshe `Seccomp` na `NoNewPrivs` zikiwa zimewezeshwa pamoja. Kwa mtazamo wa attacker, kuona vyote viwili kwa kawaida humaanisha kuwa mazingira yalisanidiwa kwa makusudi badala ya kutokea kwa bahati mbaya.

## Mipangilio isiyo sahihi

Tatizo linalotokea mara nyingi ni kutowezesha control hii katika mazingira ambayo ingeweza kutumika bila tatizo. Katika Kubernetes, kuacha `allowPrivilegeEscalation` ikiwa imewezeshwa mara nyingi huwa kosa la kawaida la kiutendaji. Katika Docker na Podman, kuacha security option husika kuna athari hiyo hiyo. Hali nyingine inayojirudia ni kudhani kwamba kwa sababu container si "privileged", privilege transitions za wakati wa exec hazina umuhimu moja kwa moja.

Kosa la hila zaidi katika Kubernetes ni kwamba `allowPrivilegeEscalation: false` **haizingatiwi kwa namna watu wanavyotarajia** wakati container ni `privileged` au ikiwa ina `CAP_SYS_ADMIN`. Kubernetes API inaeleza kwamba `allowPrivilegeEscalation` huwa true kwa ufanisi katika hali hizo. Kwa vitendo, hii inamaanisha kuwa field hiyo inapaswa kuchukuliwa kama signal moja katika posture ya mwisho, si kama guarantee kwamba runtime iliishia kuwa na `NoNewPrivs: 1`.

## Matumizi mabaya

Ikiwa `no_new_privs` haijawekwa, swali la kwanza ni iwapo image ina binaries ambazo bado zinaweza kuongeza privileges:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Matokeo muhimu yanajumuisha:

- `NoNewPrivs: 0`
- wasaidizi wa setuid kama `su`, `mount`, `passwd`, au zana za usimamizi zinazotegemea distribution
- binaries zilizo na file capabilities zinazotoa ruhusa za mtandao au mfumo wa faili

Katika assessment halisi, matokeo haya hayathibitishi escalation inayofanya kazi peke yake, lakini yanabainisha kwa usahihi binaries zinazofaa kufanyiwa majaribio yanayofuata.

Katika Kubernetes, pia thibitisha kuwa dhamira ya YAML inalingana na hali halisi ya kernel:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Mchanganyiko wa kuvutia ni pamoja na:

- `allowPrivilegeEscalation: false` katika Pod spec lakini `NoNewPrivs: 0` katika container
- `cap_sys_admin` ikiwa present, jambo linalofanya field ya Kubernetes isiwe ya kuaminika sana
- `Seccomp: 0` na `NoNewPrivs: 0`, ambacho kwa kawaida huashiria runtime posture iliyodhoofishwa kwa upana badala ya kosa moja lililotengwa

### Mfano Kamili: In-Container Privilege Escalation Kupitia setuid

Control hii kwa kawaida huzuia **in-container privilege escalation** badala ya host escape moja kwa moja. Ikiwa `NoNewPrivs` ni `0` na setuid helper ipo, ifanyie test waziwazi:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Ikiwa binary ya setuid inayojulikana ipo na inafanya kazi, jaribu kuizindua kwa njia inayohifadhi privilege transition:
```bash
/bin/su -c id 2>/dev/null
```
Hii peke yake haiwezi escape kutoka kwenye container, lakini inaweza kubadilisha foothold yenye privilege ndogo ndani ya container kuwa container-root, jambo ambalo mara nyingi huwa sharti la baadaye la host escape kupitia mounts, runtime sockets, au kernel-facing interfaces.

## Checks

Lengo la checks hizi ni kubaini ikiwa exec-time privilege gain imezuiwa na ikiwa image bado ina helpers ambazo zingekuwa muhimu ikiwa haijazuiwa.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
Kinachovutia hapa:

- `NoNewPrivs: 1` kwa kawaida ndiyo hali salama zaidi.
- `NoNewPrivs: 0` inamaanisha kuwa njia za escalation zinazotegemea setuid na file-cap bado ni muhimu.
- `NoNewPrivs: 1` pamoja na `Seccomp: 2` ni ishara ya kawaida ya mkao wa hardening uliokusudiwa zaidi.
- Kubernetes manifest inayosema `allowPrivilegeEscalation: false` ni muhimu, lakini hali ya kernel ndiyo ground truth.
- Image ndogo yenye binaries chache au zisizo na setuid/file-cap huwapa attackers chaguo chache zaidi za post-exploitation hata wakati `no_new_privs` haipo.

## Chaguo-msingi za Runtime

| Runtime / platform | Hali ya msingi | Tabia ya msingi | Kudhoofisha kwa mikono kunakotokea mara nyingi |
| --- | --- | --- | --- |
| Docker Engine | Haijawezeshwa kwa msingi | Huamilishwa wazi kwa `--security-opt no-new-privileges=true`; default ya daemon-wide pia ipo kupitia `dockerd --no-new-privileges` | kuacha flag, `--privileged` |
| Podman | Haijawezeshwa kwa msingi | Huamilishwa wazi kwa `--security-opt no-new-privileges` au security configuration inayolingana | kuacha option, `--privileged` |
| Kubernetes | Hudhibitiwa na workload policy | `allowPrivilegeEscalation: false` huomba athari hiyo, lakini `privileged: true` na `CAP_SYS_ADMIN` huifanya ibaki true kwa ufanisi | `allowPrivilegeEscalation: true`, `privileged: true`, kuongeza `CAP_SYS_ADMIN` |
| containerd / CRI-O chini ya Kubernetes | Hufuata mipangilio ya Kubernetes workload / OCI `process.noNewPrivileges` | Kwa kawaida hurithiwa kutoka kwenye Pod security context na kutafsiriwa kuwa OCI runtime config | sawa na safu ya Kubernetes |

Protection hii mara nyingi haipo kwa sababu tu hakuna aliyeiwasha, si kwa sababu runtime haina support yake.

## Marejeo

- [Nyaraka za Linux kernel: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
