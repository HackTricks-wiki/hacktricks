# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` ni feature ya kernel hardening inayozuia process kupata privilege zaidi kupitia `execve()`. Kwa maana ya kiutendaji, flag ikishawekwa, kuendesha setuid binary, setgid binary, au file yenye Linux file capabilities hakutoi privilege ya ziada zaidi ya ile ambayo process ilikuwa nayo tayari. Katika mazingira ya containerized, hili ni muhimu kwa sababu privilege-escalation chains nyingi hutegemea kupata executable ndani ya image inayobadilisha privilege inapoanzishwa.

Kwa mtazamo wa defensive, `no_new_privs` si mbadala wa namespaces, seccomp, au capability dropping. Ni reinforcement layer. Inazuia aina maalum ya follow-up escalation baada ya code execution kupatikana. Hii huifanya iwe muhimu hasa katika mazingira ambayo images zina helper binaries, package-manager artifacts, au legacy tools ambazo vinginevyo zingekuwa hatari zikichanganywa na partial compromise.

## Uendeshaji

Kernel flag inayowezesha tabia hii ni `PR_SET_NO_NEW_PRIVS`. Ikishawekwa kwa process, calls za baadaye za `execve()` haziwezi kuongeza privilege. Jambo muhimu ni kwamba process bado inaweza kuendesha binaries; haiwezi tu kutumia binaries hizo kuvuka privilege boundary ambayo kernel ingekubali vinginevyo.<sup>[[1]](#references)</sup>

Tabia ya kernel pia ni **inherited na irreversible**: task ikishaweka `no_new_privs`, bit hiyo inarithiwa kupitia `fork()`, `clone()`, na `execve()`, na haiwezi kuondolewa baadaye.<sup>[[1]](#references)</sup> Hili ni muhimu katika assessments kwa sababu `NoNewPrivs: 1` moja kwenye container process kwa kawaida humaanisha descendants wanapaswa pia kubaki katika mode hiyo, isipokuwa unaangalia process tree tofauti kabisa.

Katika mazingira yanayolenga Kubernetes, `allowPrivilegeEscalation: false` huwezesha tabia hii kwa container process.<sup>[[2]](#references)</sup> Katika runtimes za mtindo wa Docker na Podman, sawa na hii kwa kawaida huwezeshwa wazi kupitia security option. Katika OCI layer, concept hiyo hiyo huonekana kama `process.noNewPrivileges`.

## Nuances Muhimu

`no_new_privs` huzuia **exec-time** privilege gain, si kila privilege change.<sup>[[1]](#references)</sup> Hasa:

- setuid na setgid transitions huacha kufanya kazi kupitia `execve()`
- file capabilities haziongezi kwenye permitted set kupitia `execve()`
- LSMs kama AppArmor au SELinux hazilegezi constraints baada ya `execve()`
- privilege iliyokuwa tayari inamilikiwa bado inabaki kuwa privilege iliyokuwa tayari inamilikiwa

Jambo hilo la mwisho ni muhimu kiutendaji. Ikiwa process tayari inaendesha kama root, tayari ina dangerous capability, au tayari ina access kwenye powerful runtime API au writable host mount, kuweka `no_new_privs` hakutaondoa exposures hizo. Huondoa tu **next step** moja ya kawaida katika privilege-escalation chain.

Pia kumbuka kuwa flag hii haizuii privilege changes ambazo hazitegemei `execve()`.<sup>[[1]](#references)</sup> Kwa mfano, task ambayo tayari ina privilege ya kutosha bado inaweza kuita `setuid(2)` moja kwa moja au kupokea privileged file descriptor kupitia Unix socket. Ndiyo maana `no_new_privs` inapaswa kusomwa pamoja na [seccomp](seccomp.md), capability sets, na namespace exposure badala ya kuchukuliwa kama jibu la pekee.

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

Unaweza pia kuonyesha athari halisi dhidi ya setuid binary:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
Hoja ya ulinganisho si kwamba `su` inaweza kutumiwa vibaya kila mahali. Ni kwamba image ileile inaweza kuwa na tabia tofauti sana kulingana na kama `execve()` bado inaruhusiwa kuvuka privilege boundary.

## Athari za Usalama

Ikiwa `no_new_privs` haijawekwa, foothold ndani ya container bado inaweza kuongezewa privilege kupitia setuid helpers au binaries zenye file capabilities. Ikiwa imewekwa, mabadiliko hayo ya privilege baada ya exec yanazuiwa. Athari hii ni muhimu hasa katika base images pana zinazosafirisha utilities nyingi ambazo application haikuzihitaji tangu mwanzo.

Pia kuna mwingiliano muhimu na seccomp. Tasks zisizo na privilege kwa ujumla zinahitaji `no_new_privs` iwekwe kabla ya kusakinisha seccomp filter katika filter mode.<sup>[[1]](#references)</sup> Hii ni sababu mojawapo inayofanya containers zilizoimarishwa kiusalama mara nyingi zionyeshe `Seccomp` na `NoNewPrivs` zikiwa enabled pamoja. Kwa mtazamo wa attacker, kuona zote mbili kwa kawaida humaanisha kuwa mazingira yalisanidiwa kwa makusudi badala ya kuwekwa hivyo kwa bahati mbaya.

## Mipangilio Isiyo Sahihi

Tatizo linalotokea mara nyingi ni kutowezesha control hii katika mazingira ambako ingeendana na mahitaji. Katika Kubernetes, kuacha `allowPrivilegeEscalation` ikiwa enabled mara nyingi huwa kosa la kawaida la kiutendaji. Katika Docker na Podman, kuacha security option husika kuna athari hiyo hiyo. Kushindwa kwingine kunakojirudia ni kudhani kwamba kwa sababu container ni "not privileged", mabadiliko ya privilege wakati wa exec hayana umuhimu moja kwa moja.

Kosa la hila zaidi katika Kubernetes ni kwamba `allowPrivilegeEscalation: false` **haizingatiwi** kwa namna watu wanavyotarajia wakati container ni `privileged` au inapokuwa na `CAP_SYS_ADMIN`. Kubernetes API inaeleza kwamba `allowPrivilegeEscalation` huwa effectively true kila mara katika hali hizo.<sup>[[2]](#references)</sup> Kwa vitendo, hii inamaanisha field hiyo inapaswa kuchukuliwa kama signal moja katika posture ya mwisho, si kama guarantee kwamba runtime iliishia na `NoNewPrivs: 1`.

## Abuse

Ikiwa `no_new_privs` haijawekwa, swali la kwanza ni kama image ina binaries ambazo bado zinaweza kuongeza privilege:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Matokeo ya kuvutia yanajumuisha:

- `NoNewPrivs: 0`
- setuid helpers kama vile `su`, `mount`, `passwd`, au admin tools maalum za distribution
- binaries zilizo na file capabilities zinazotoa network au filesystem privileges

Katika assessment halisi, findings hizi hazithibitishi escalation inayofanya kazi zenyewe, lakini zinabainisha kwa usahihi binaries zinazofaa kujaribiwa baadaye.

Katika Kubernetes, pia hakikisha kwamba dhamira ya YAML inalingana na uhalisia wa kernel:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Mchanganyiko wa kuvutia unajumuisha:

- `allowPrivilegeEscalation: false` katika Pod spec lakini `NoNewPrivs: 0` kwenye container
- `cap_sys_admin` ipo, hali inayofanya field ya Kubernetes isiwe ya kuaminika sana
- `Seccomp: 0` na `NoNewPrivs: 0`, hali ambayo kwa kawaida huashiria runtime posture iliyodhoofishwa kwa upana badala ya kosa moja lililotengwa

### Mfano Kamili: In-Container Privilege Escalation Kupitia setuid

Control hii kwa kawaida huzuia **in-container privilege escalation** badala ya host escape moja kwa moja. Ikiwa `NoNewPrivs` ni `0` na setuid helper ipo, ifanyie test moja kwa moja:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Ikiwa setuid binary inayojulikana ipo na inafanya kazi, jaribu kuiendesha kwa njia inayohifadhi mabadiliko ya privilege:
```bash
/bin/su -c id 2>/dev/null
```
Hili lenyewe halitoroshi kutoka kwenye container, lakini linaweza kubadilisha foothold yenye privileges chache ndani ya container kuwa container-root, jambo ambalo mara nyingi huwa sharti la baadaye la kutoroka kwenda kwenye host kupitia mounts, runtime sockets, au kernel-facing interfaces.

## Ukaguzi

Lengo la ukaguzi huu ni kubainisha ikiwa ongezeko la privileges wakati wa exec limezuiwa na ikiwa image bado ina helpers ambazo zingekuwa muhimu ikiwa halijazuiwa.
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
- `NoNewPrivs: 0` inamaanisha kuwa njia za escalation zinazotegemea setuid na file-cap bado zina umuhimu.
- `NoNewPrivs: 1` pamoja na `Seccomp: 2` ni ishara ya kawaida ya mkao wa hardening uliokusudiwa zaidi.
- Kubernetes manifest inayosema `allowPrivilegeEscalation: false` ni muhimu, lakini hali ya kernel ndiyo chanzo cha ukweli.
- Image ndogo yenye binaries chache au zisizo na setuid/file-cap humpa attacker chaguo chache za post-exploitation hata wakati `no_new_privs` haipo.

## Default za Runtime

| Runtime / platform | Hali ya default | Tabia ya default | Udhaifu wa kawaida unaowekwa manually |
| --- | --- | --- | --- |
| Docker Engine | Haijawezeshwa kwa default | Hujawezeshwa waziwazi kwa `--security-opt no-new-privileges=true`; default ya daemon-wide pia ipo kupitia `dockerd --no-new-privileges` | kuacha flag, `--privileged` |
| Podman | Haijawezeshwa kwa default | Hujawezeshwa waziwazi kwa `--security-opt no-new-privileges` au security configuration inayolingana | kuacha option, `--privileged` |
| Kubernetes | Inadhibitiwa na workload policy | `allowPrivilegeEscalation: false` huomba athari hiyo, lakini `privileged: true` na `CAP_SYS_ADMIN` huifanya ibaki true kwa ufanisi | `allowPrivilegeEscalation: true`, `privileged: true`, kuongeza `CAP_SYS_ADMIN` |
| containerd / CRI-O under Kubernetes | Hufuata Kubernetes workload settings / OCI `process.noNewPrivileges` | Kwa kawaida hurithiwa kutoka kwenye Pod security context na kutafsiriwa kuwa OCI runtime config | sawa na safu ya Kubernetes |

Protection hii mara nyingi haipo kwa sababu hakuna aliyeiwezesha, si kwa sababu runtime haina support yake.

## Marejeo

- [1] [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [2] [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
