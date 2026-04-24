# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` ni kipengele cha kuimarisha kernel kinachozuia process kupata privilege zaidi kupitia `execve()`. Kwa vitendo, mara flag hii inapowekwa, kuendesha setuid binary, setgid binary, au file lenye Linux file capabilities hakupi extra privilege zaidi ya ile ambayo process tayari ilikuwa nayo. Katika mazingira ya containerized, hili ni muhimu kwa sababu chaining nyingi za privilege-escalation hutegemea kupata executable ndani ya image inayobadilisha privilege inapozinduliwa.

Kwa mtazamo wa ulinzi, `no_new_privs` si mbadala wa namespaces, seccomp, au capability dropping. Ni layer ya kuimarisha. Inazuia aina fulani ya escalation ya hatua inayofuata baada ya code execution kuwa tayari imepatikana. Hilo linaifanya iwe muhimu sana katika mazingira ambapo images zina helper binaries, package-manager artifacts, au legacy tools ambazo vinginevyo zingekuwa hatari zikichanganywa na partial compromise.

## Operation

Kernel flag iliyo nyuma ya tabia hii ni `PR_SET_NO_NEW_PRIVS`. Mara inapowekwa kwa process, `execve()` za baadaye haziwezi kuongeza privilege. Jambo muhimu ni kwamba process bado inaweza kuendesha binaries; hawezi tu kutumia binaries hizo kuvuka privilege boundary ambayo kernel vinginevyo ingeiheshimu.

Tabia ya kernel pia ni **inherited na irreversible**: mara task inapoweka `no_new_privs`, bit hiyo hurithiwa kupitia `fork()`, `clone()`, na `execve()`, na haiwezi kuondolewa baadaye. Hii ni muhimu katika assessments kwa sababu `NoNewPrivs: 1` moja tu kwenye process ya container mara nyingi humaanisha descendants pia wanapaswa kubaki katika mode hiyo isipokuwa unaangalia process tree tofauti kabisa.

Katika mazingira ya Kubernetes-oriented, `allowPrivilegeEscalation: false` inaendana na tabia hii kwa process ya container. Katika Docker na Podman style runtimes, sawa yake kawaida huwashwa wazi kupitia security option. Katika OCI layer, dhana hiyo hiyo huonekana kama `process.noNewPrivileges`.

## Important Nuances

`no_new_privs` huzuia privilege gain wakati wa **exec-time**, si mabadiliko yote ya privilege. Kwa kawaida:

- setuid na setgid transitions huacha kufanya kazi kupitia `execve()`
- file capabilities haziongezi kwenye permitted set wakati wa `execve()`
- LSMs kama AppArmor au SELinux hazilegezi constraints baada ya `execve()`
- privilege ambayo tayari inashikiliwa bado ni privilege ambayo tayari inashikiliwa

Hoja hiyo ya mwisho ni muhimu kiutendaji. Kama process tayari inaendeshwa kama root, tayari ina dangerous capability, au tayari ina access kwa powerful runtime API au writable host mount, kuweka `no_new_privs` hakuondoi exposures hizo. Huondoa tu hatua moja ya kawaida ya **next step** katika chain ya privilege-escalation.

Pia kumbuka kuwa flag hii haizuii mabadiliko ya privilege ambayo hayategemei `execve()`. Kwa mfano, task ambayo tayari ni privileged vya kutosha bado inaweza kuita `setuid(2)` moja kwa moja au kupokea privileged file descriptor kupitia Unix socket. Ndiyo maana `no_new_privs` inapaswa kusomwa pamoja na [seccomp](seccomp.md), capability sets, na namespace exposure badala ya kuwa jibu la pekee.

## Lab

Kagua state ya current process:
```bash
grep NoNewPrivs /proc/self/status
```
Linganisha hilo na kontena ambapo runtime inawezesha bendera:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Kwenye hardened workload, matokeo yanapaswa kuonyesha `NoNewPrivs: 1`.

Unaweza pia kuonyesha athari halisi dhidi ya binary ya setuid:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
The point of the comparison is not that `su` is universally exploitable. It is that the same image can behave very differently depending on whether `execve()` is still allowed to cross a privilege boundary.

## Security Impact

If `no_new_privs` is absent, a foothold inside the container may still be upgraded through setuid helpers or binaries with file capabilities. If it is present, those post-exec privilege changes are cut off. The effect is especially relevant in broad base images that ship many utilities the application never needed in the first place.

There is also an important seccomp interaction. Unprivileged tasks generally need `no_new_privs` set before they can install a seccomp filter in filter mode. This is one reason hardened containers often show both `Seccomp` and `NoNewPrivs` enabled together. From an attacker perspective, seeing both usually means the environment was configured deliberately rather than accidentally.

## Misconfigurations

The most common problem is simply not enabling the control in environments where it would be compatible. In Kubernetes, leaving `allowPrivilegeEscalation` enabled is often the default operational mistake. In Docker and Podman, omitting the relevant security option has the same effect. Another recurring failure mode is assuming that because a container is "not privileged", exec-time privilege transitions are automatically irrelevant.

A more subtle Kubernetes pitfall is that `allowPrivilegeEscalation: false` is **not** honored the way people expect when the container is `privileged` or when it has `CAP_SYS_ADMIN`. The Kubernetes API documents that `allowPrivilegeEscalation` is effectively always true in those cases. In practice, this means the field should be treated as one signal in the final posture, not as a guarantee that the runtime ended up with `NoNewPrivs: 1`.

## Abuse

If `no_new_privs` is not set, the first question is whether the image contains binaries that can still raise privilege:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Matokeo ya kuvutia ni pamoja na:

- `NoNewPrivs: 0`
- setuid helpers kama `su`, `mount`, `passwd`, au distribution-specific admin tools
- binaries zenye file capabilities zinazotoa network au filesystem privileges

Katika tathmini ya kweli, matokeo haya hayathibitishi kwa yenyewe kwamba kuna escalation inayofanya kazi, lakini yanaonyesha kwa usahihi ni binaries zipi zinazostahili kujaribiwa baadaye.

Katika Kubernetes, pia thibitisha kwamba nia ya YAML inalingana na hali halisi ya kernel:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Mchanganyiko wa kuvutia ni pamoja na:

- `allowPrivilegeEscalation: false` katika Pod spec lakini `NoNewPrivs: 0` kwenye container
- `cap_sys_admin` ipo, jambo linalofanya field ya Kubernetes isiwe ya kuaminika sana
- `Seccomp: 0` na `NoNewPrivs: 0`, ambavyo kwa kawaida vinaonyesha posture ya runtime iliyodhoofika kwa upana badala ya kosa moja la pekee

### Full Example: In-Container Privilege Escalation Through setuid

Udhibiti huu kwa kawaida huzuia **in-container privilege escalation** badala ya host escape moja kwa moja. Ikiwa `NoNewPrivs` ni `0` na kuna setuid helper, ijaribu moja kwa moja:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Ikiwa setuid binary inayojulikana ipo na inafanya kazi, jaribu kuizindua kwa njia inayohifadhi mabadiliko ya ruhusa:
```bash
/bin/su -c id 2>/dev/null
```
Hii pekee haiikopeshi container, lakini inaweza kubadilisha foothold ya low-privilege ndani ya container kuwa container-root, jambo ambalo mara nyingi huwa hitaji la awali kwa host escape ya baadaye kupitia mounts, runtime sockets, au interfaces zinazokabiliana na kernel.

## Checks

Lengo la hizi checks ni kubaini kama exec-time privilege gain imezuiwa na kama image bado ina helpers ambazo zingekuwa muhimu ikiwa haijazuiwa.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
Ni nini cha kuvutia hapa:

- `NoNewPrivs: 1` kwa kawaida ni matokeo salama zaidi.
- `NoNewPrivs: 0` maana yake njia za eskalishaji za setuid na file-cap bado zina umuhimu.
- `NoNewPrivs: 1` pamoja na `Seccomp: 2` ni ishara ya kawaida ya posture ya hardening iliyo ya makusudi zaidi.
- Kubernetes manifest inayosema `allowPrivilegeEscalation: false` ni ya manufaa, lakini kernel status ndiyo ground truth.
- Minimal image yenye binaries chache au zisizo na setuid/file-cap humpa attacker chaguo chache zaidi za post-exploitation hata wakati `no_new_privs` haipo.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Not enabled by default | Enabled explicitly with `--security-opt no-new-privileges=true`; daemon-wide default also exists via `dockerd --no-new-privileges` | omitting the flag, `--privileged` |
| Podman | Not enabled by default | Enabled explicitly with `--security-opt no-new-privileges` or equivalent security configuration | omitting the option, `--privileged` |
| Kubernetes | Controlled by workload policy | `allowPrivilegeEscalation: false` requests the effect, but `privileged: true` and `CAP_SYS_ADMIN` keep it effectively true | `allowPrivilegeEscalation: true`, `privileged: true`, adding `CAP_SYS_ADMIN` |
| containerd / CRI-O under Kubernetes | Follows Kubernetes workload settings / OCI `process.noNewPrivileges` | Usually inherited from the Pod security context and translated into OCI runtime config | same as Kubernetes row |

Ulinzi huu mara nyingi haupo kwa sababu tu hakuna aliyewasha, si kwa sababu runtime haina support yake.

## References

- [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
