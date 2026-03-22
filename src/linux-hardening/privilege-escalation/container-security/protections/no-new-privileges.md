# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` ni kipengele cha kuimarisha kernel ambacho kinazuia mchakato kupata ruhusa zaidi kupitia `execve()`. Kwa vitendo, mara tu bendera inapowekwa, kutekeleza a setuid binary, a setgid binary, au file with Linux file capabilities hakutatoa ruhusa za ziada zaidi kuliko zile mchakato ulizonazo tayari. Katika mazingira ya containerized, hili ni muhimu kwa sababu minyororo mingi ya privilege-escalation hutegemea kupata executable ndani ya image ambayo hubadilisha ruhusa wakati inapoanzishwa.

Kwa mtazamo wa kujilinda, `no_new_privs` si mbadala wa namespaces, seccomp, au capability dropping. Ni safu ya kuimarisha. Inazuia daraja maalum la follow-up escalation baada ya code execution kuwanadiwa. Hii inafanya kuwa yenye thamani hasa katika mazingira ambapo images zina helper binaries, package-manager artifacts, au legacy tools ambazo vingekuwa hatari zinapochanganywa na partial compromise.

## Operation

Bendera ya kernel nyuma ya tabia hii ni `PR_SET_NO_NEW_PRIVS`. Mara inapowekwa kwa mchakato, wito wa baadaye wa `execve()` hayawezi kuongeza ruhusa. Kitu muhimu ni kwamba mchakato bado unaweza kuendesha binaries; hawezi tu kutumia binaries hizo kuvuka mipaka ya ruhusa ambayo kernel ingeheshimu.

Katika mazingira yanayolenga Kubernetes, `allowPrivilegeEscalation: false` inaendana na tabia hii kwa mchakato wa container. Katika runtimes za aina ya Docker na Podman, sawa yake kwa kawaida huwekwa wazi kupitia chaguo la usalama.

## Maabara

Chunguza hali ya mchakato wa sasa:
```bash
grep NoNewPrivs /proc/self/status
```
Linganishwa na container ambapo runtime inawasha flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Kwenye workload iliyoboreshwa kwa usalama, matokeo yanapaswa kuonyesha `NoNewPrivs: 1`.

## Athari za Usalama

Ikiwa `no_new_privs` haipo, ufikiaji wa mwanzo ndani ya container bado unaweza kuboreshwa kupitia setuid helpers au binaries zenye file capabilities. Ikiwa ipo, mabadiliko hayo ya ruhusa baada ya exec yanakatizwa. Athari hii ni muhimu hasa katika base images za jumla ambazo zinatoa utilities nyingi ambavyo programu haikuhitaji hapo awali.

## Usanidi usio sahihi

Tatizo la kawaida kabisa ni kutowasha udhibiti huo katika mazingira ambapo ungekuwa unaendana nao. Katika Kubernetes, kuacha `allowPrivilegeEscalation` kuwekwa imewezeshwa mara nyingi ni kosa la kawaida la uendeshaji. Katika Docker na Podman, kutojumuisha chaguo husika la usalama kunaathiri kwa njia ile ile. Njia nyingine ya kushindwa kurudiwa ni kudhani kwamba kwa kuwa container ni "not privileged", mabadiliko ya ruhusa wakati wa exec hayana umuhimu kiotomatiki.

## Matumizi mabaya

Kama `no_new_privs` haijatilishwa, swali la kwanza ni kama image ina binaries ambazo bado zinaweza kuongeza ruhusa:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Matokeo ya kuvutia ni pamoja na:

- `NoNewPrivs: 0`
- wasaidizi wa setuid kama `su`, `mount`, `passwd`, au zana za usimamizi maalum za distribution
- binaries zenye file capabilities zinazotoa ruhusa za network au filesystem

Katika tathmini halisi, uvumbuzi hivi havithibitishi kwao wenyewe kuwa kuna escalation inayofanya kazi, lakini vinabainisha hasa binaries zinazostahili kujaribiwa ifuatayo.

### Mfano kamili: In-Container Privilege Escalation Through setuid

Udhibiti huu kwa kawaida huwa unazuia **in-container privilege escalation** badala ya host escape moja kwa moja. Ikiwa `NoNewPrivs` ni `0` na setuid helper ipo, ujaribu waziwazi:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Ikiwa setuid binary inayojulikana ipo na inafanya kazi, jaribu kuiendesha kwa njia inayohifadhi privilege transition:
```bash
/bin/su -c id 2>/dev/null
```
Hii yenyewe haitoki kwenye container, lakini inaweza kubadilisha foothold ya low-privilege ndani ya container kuwa container-root, ambayo mara nyingi inakuwa sharti la awali kwa host escape baadaye kupitia mounts, runtime sockets, au kernel-facing interfaces.

## Ukaguzi

Lengo la ukaguzi huu ni kubaini ikiwa exec-time privilege gain imezuiwa na ikiwa image bado ina helpers ambazo zingekuwa muhimu ikiwa haijazuiwa.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
Kinachovutia hapa:

- `NoNewPrivs: 1` kawaida ni matokeo salama zaidi.
- `NoNewPrivs: 0` ina maana njia za kuinua vibali zenye msingi setuid na file-cap bado zina umuhimu.
- Image ndogo yenye binari chache au bila setuid/file-cap hutoa kwa mshambuliaji chaguo chache za post-exploitation hata kama `no_new_privs` inakosekana.

## Default za Runtime

| Runtime / platform | Hali ya chaguo-msingi | Tabia ya chaguo-msingi | Udhoofishaji wa kawaida uliofanywa kwa mkono |
| --- | --- | --- | --- |
| Docker Engine | Haijawezeshwa kwa chaguo-msingi | Imewezeshwa wazi kwa `--security-opt no-new-privileges=true` | kuacha flag, `--privileged` |
| Podman | Haijawezeshwa kwa chaguo-msingi | Imewezeshwa wazi kwa `--security-opt no-new-privileges` au usanidi sawa wa usalama | kutochagua chaguo, `--privileged` |
| Kubernetes | Inadhibitiwa na sera ya workload | `allowPrivilegeEscalation: false` hutoa athari hiyo; workloads nyingi bado huiacha ikiwa imewezeshwa | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Inafuata mipangilio ya workload ya Kubernetes | Kwa kawaida inachukuliwa kutoka kwa Pod security context | sawa na mstari wa Kubernetes |

Ulinzi huu mara nyingi haupo tu kwa sababu hakuna aliyekuwa ameuwezesha, si kwa sababu runtime hauna msaada kwake.
{{#include ../../../../banners/hacktricks-training.md}}
