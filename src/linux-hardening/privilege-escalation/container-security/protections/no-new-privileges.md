# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` ni kipengele cha kuimarisha kernel kinachozuia mchakato kupata ruhusa zaidi kupitia `execve()`. Kwa vitendo, mara bendera inapowekwa, kutekeleza binary ya setuid, binary ya setgid, au faili yenye Linux file capabilities hakutoi ruhusa za ziada zaidi kuliko zile mchakato tayari alikuwa nazo. Katika mazingira ya container, hili ni muhimu kwa sababu minyororo mingi ya privilege-escalation inategemea kupata executable ndani ya image ambayo hubadilisha ruhusa inapotekelezwa.

Kwa mtazamo wa ulinzi, `no_new_privs` si mbadala wa namespaces, seccomp, au capability dropping. Ni safu ya kuimarisha. Inazuia daraja maalum la uongezaji ruhusa baada ya utekelezaji wa msimbo tayari kupatikana. Hii inafanya iwe ya thamani hasa katika mazingira ambapo images zina helper binaries, package-manager artifacts, au zana za legacy ambazo vingekuwa hatari inapochanganywa na kompromisi ya sehemu.

## Operation

Bendera ya kernel inayohusiana na tabia hii ni `PR_SET_NO_NEW_PRIVS`. Mara inapotumika kwa mchakato, simu za baadaye za `execve()` haziwezi kuongeza ruhusa. Maelezo muhimu ni kwamba mchakato bado unaweza kukimbia binaries; tu haiwezi kutumia binaries hizo kuvuka mpaka wa ruhusa ambao kernel ungeweza kuheshimu.

Katika mazingira yenye mwelekeo wa Kubernetes, `allowPrivilegeEscalation: false` inalingana na tabia hii kwa mchakato wa container. Katika runtimes za aina ya Docker na Podman, sawia kwa kawaida huwezeshwa wazi kupitia chaguo la usalama.

## Lab

Angalia hali ya mchakato wa sasa:
```bash
grep NoNewPrivs /proc/self/status
```
Linganisha hiyo na container ambapo runtime inawezesha flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Katika workload iliyokazwa, matokeo yanapaswa kuonyesha `NoNewPrivs: 1`.

## Athari za Usalama

Ikiwa `no_new_privs` haipo, mshikaji ndani ya container bado anaweza kupandishwa hadhi kupitia setuid helpers au binaries zenye file capabilities. Ikiwa ipo, mabadiliko hayo ya ruhusa yanayotokea baada ya exec yanakatwa. Athari hii ni muhimu hasa katika base images pana zinazobeba utilities nyingi ambazo application haikuzihitaji hapo mwanzo.

## Makosa ya Usanidi

Tatizo la kawaida ni kutozima tu udhibiti katika mazingira ambamo ungetosha. Katika Kubernetes, kuacha `allowPrivilegeEscalation` imewashwa mara nyingi ni kosa la kawaida la uendeshaji. Katika Docker na Podman, kutotaja chaguo husika la usalama kuna athari ile ile. Njia nyingine ya kushindwa inayojirudia ni kudhani kuwa kwa sababu container si "not privileged", mabadiliko ya ruhusa wakati wa exec hayana umuhimu kiotomatiki.

## Matumizi Mabaya

Ikiwa `no_new_privs` haijowekwa, swali la kwanza ni je, image ina binaries ambazo bado zinaweza kuongeza ruhusa:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Matokeo ya kuvutia ni pamoja na:

- `NoNewPrivs: 0`
- setuid helpers kama vile `su`, `mount`, `passwd`, au zana za usimamizi maalum za distribution
- binaries zenye file capabilities zinazotoa network au filesystem privileges

Katika tathmini halisi, matokeo haya hayathibitishi escalation inayofanya kazi peke yao, lakini yanabainisha hasa binaries zinazostahili kujaribiwa zifuatazo.

### Mfano Kamili: In-Container Privilege Escalation Through setuid

Udhibiti huu kwa kawaida huzuia **in-container privilege escalation** badala ya host escape moja kwa moja. Ikiwa `NoNewPrivs` ni `0` na kuna setuid helper, jaribu waziwazi:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Ikiwa setuid binary inayojulikana ipo na inafanya kazi, jaribu kuizindua kwa njia inayohifadhi mabadiliko ya ruhusa:
```bash
/bin/su -c id 2>/dev/null
```
Hii peke yake haisababisha escape ya container, lakini inaweza kubadilisha low-privilege foothold ndani ya container kuwa container-root, ambayo mara nyingi inakuwa sharti la awali kwa host escape baadaye kupitia mounts, runtime sockets, au kernel-facing interfaces.

## Checks

Lengo la ukaguzi haya ni kuthibitisha ikiwa exec-time privilege gain imezuiwa na ikiwa image bado ina helpers ambazo zingekuwa muhimu ikiwa haijazuiwa.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
Kinachovutia hapa:

- `NoNewPrivs: 1` kwa kawaida ni matokeo salama zaidi.
- `NoNewPrivs: 0` ina maana njia za escalation zinazotegemea setuid na file-cap zinaendelea kuwa muhimu.
- Image ndogo yenye binaries chache au zisizo na setuid/file-cap inampa mshambuliaji chaguzi chache za post-exploitation hata pale `no_new_privs` ukikosekana.

## Chaguo-msingi za Runtime

| Runtime / platform | Hali ya chaguo-msingi | Tabia ya chaguo-msingi | Udhoofishaji wa kawaida kwa mkono |
| --- | --- | --- | --- |
| Docker Engine | Haiwezeshwi kwa chaguo-msingi | Inawezeshwa kwa uwazi kwa `--security-opt no-new-privileges=true` | kuacha bendera, `--privileged` |
| Podman | Haiwezeshwi kwa chaguo-msingi | Inawezeshwa kwa uwazi kwa `--security-opt no-new-privileges` au usanidi wa usalama sawa | kuacha chaguo, `--privileged` |
| Kubernetes | Inadhibitiwa na workload policy | `allowPrivilegeEscalation: false` huwezesha athari; workloads nyingi bado zinaiacha iwe imewezeshwa | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Inafuata mipangilio ya workload ya Kubernetes | Kawaida huchukuliwa kutoka Pod security context | sawa na safu ya Kubernetes |

Ulinzi huu mara nyingi haupatikani kwa sababu hakuna aliyewasha, si kwa sababu runtime haikuunga mkono.
