# PID Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

The PID (Process IDentifier) namespace ni kipengele katika kernel ya Linux kinachotoa process isolation kwa kuruhusu kundi la process kuwa na seti yao ya PIDs za kipekee, tofauti na PIDs katika namespaces nyingine. Hii ni hasa muhimu katika containerization, ambapo process isolation ni muhimu kwa usalama na usimamizi wa rasilimali.

Wakati namespace mpya ya PID inapoundwa, process ya kwanza katika namespace hiyo inapangiwa PID 1. Process hii inakuwa process "init" ya namespace mpya na inawajibika kusimamia processes nyingine ndani ya namespace. Kila process inayofuata inayoundwa ndani ya namespace itakuwa na PID ya kipekee ndani ya namespace hiyo, na PIDs hizi zitakuwa huru kutoka PIDs katika namespaces nyingine.

Kutoka kwa mtazamo wa process ndani ya PID namespace, inaweza kuona tu processes nyingine ndani ya namespace hiyo. Haijui kuhusu processes katika namespaces nyingine, na haiwezi kuingiliana nao kwa kutumia zana za usimamizi wa process za jadi (e.g., `kill`, `wait`, etc.). Hii inatoa kiwango cha isolation kinachosaidia kuzuia processes kuingiliana.

### Jinsi inavyofanya kazi:

1. When a new process is created (e.g., by using the `clone()` system call), the process can be assigned to a new or existing PID namespace. **If a new namespace is created, the process becomes the "init" process of that namespace**.
2. The **kernel** maintains a **mapping between the PIDs in the new namespace and the corresponding PIDs** in the parent namespace (i.e., the namespace from which the new namespace was created). This mapping **allows the kernel to translate PIDs when necessary**, such as when sending signals between processes in different namespaces.
3. **Processes within a PID namespace can only see and interact with other processes in the same namespace**. They are not aware of processes in other namespaces, and their PIDs are unique within their namespace.
4. When a **PID namespace is destroyed** (e.g., when the "init" process of the namespace exits), **all processes within that namespace are terminated**. This ensures that all resources associated with the namespace are properly cleaned up.

## Maabara:

### Create different Namespaces

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Ufafanuzi wa Tatizo**:

- Kernel ya Linux inaruhusu mchakato kuunda namespaces mpya kwa kutumia system call ya `unshare`. Hata hivyo, mchakato unaoanzisha uundaji wa namespace mpya ya PID (unayoitwa mchakato "unshare") hauingi kwenye namespace mpya; ni watoto wake tu wanaoingia.
- Kukimbiza %unshare -p /bin/bash% kunaendesha `/bin/bash` kwenye mchakato uleule na `unshare`. Kwa hiyo, `/bin/bash` na watoto wake wako katika namespace ya PID ya asili.
- Mwana wa kwanza wa `/bin/bash` ndani ya namespace mpya anakuwa PID 1. Wakati mchakato huu unapoondoka, husababisha kusafishwa kwa namespace ikiwa hakuna mchakato mwingine, kwani PID 1 ana jukumu maalum la kumpokea mchakato yatima. Kernel ya Linux kisha itazima ugawaji wa PID katika namespace hiyo.

2. **Matokeo**:

- Kuondoka kwa PID 1 katika namespace mpya husababisha kusafishwa kwa flag ya `PIDNS_HASH_ADDING`. Hii inasababisha function ya `alloc_pid` kushindwa kugawa PID mpya wakati wa kuunda mchakato mpya, na kutoa hitilafu "Cannot allocate memory".

3. **Suluhisho**:
- Tatizo linaweza kutatuliwa kwa kutumia chaguo `-f` pamoja na `unshare`. Chaguo hili hufanya `unshare` ifork mchakato mpya baada ya kuunda namespace mpya ya PID.
- Kutekeleza %unshare -fp /bin/bash% kunahakikishia kwamba amri ya `unshare` yenyewe inakuwa PID 1 katika namespace mpya. `/bin/bash` na watoto wake kisha wapo salama ndani ya namespace hii mpya, kuzuia kuondoka kwa mapema kwa PID 1 na kuruhusu ugawaji wa PID kawaida.

Kwa kuhakikisha kwamba `unshare` inaendeshwa kwa bendera `-f`, namespace mpya ya PID inahifadhiwa kwa usahihi, ikiruhusu `/bin/bash` na sub-processes zake kufanya kazi bila kukutana na hitilafu ya ugawaji kumbukumbu.

</details>

By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **mtazamo sahihi na uliotengwa wa taarifa za mchakato zinazohusiana na namespace hiyo**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Angalia mchakato wako uko katika namespace gani
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Tafuta namespaces zote za PID
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
Kumbuka kwamba root user kutoka kwa PID namespace ya awali (default) anaweza kuona michakato yote, hata michakato iliyopo katika PID namespaces mpya; ndiyo sababu tunaweza kuona PID namespaces zote.

### Ingia ndani ya PID namespace
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Unapoingia ndani ya PID namespace kutoka namespace ya default, bado utaweza kuona michakato yote. Na mchakato kutoka kwa PID ns hiyo utaweza kuona bash mpya kwenye PID ns hiyo.

Pia, unaweza tu **kuingia kwenye PID namespace ya mchakato mwingine ikiwa wewe ni root**. Na **huwezi** **kuingia** katika namespace nyingine **bila descriptor** inayoiashiria (kama `/proc/self/ns/pid`)

## Vidokezo vya Utekelezaji wa Udhaifu Hivi Karibuni

### CVE-2025-31133: kutumia vibaya `maskedPaths` kufikia host PIDs

runc ≤1.2.7 iliruhusu watapeli wanaodhibiti container images au workloads za `runc exec` kubadilisha upande wa container wa `/dev/null` tu kabla runtime ilificha entries nyeti za procfs. Wakati race inafanikiwa, `/dev/null` inaweza kubadilishwa kuwa symlink inayolenga kwenye path yoyote ya host (kwa mfano `/proc/sys/kernel/core_pattern`), hivyo PID namespace mpya ya container ghafla inapata ufikiaji wa kusoma/kuandika kwa knobs za procfs za host-global hata ingawa haikuacha namespace yake mwenyewe. Mara `core_pattern` au `/proc/sysrq-trigger` zinaweza kuandikwa, kutengeneza coredump au kuchochea SysRq kunapelekea utekelezaji wa code au denial of service katika host PID namespace.

Mtiririko wa kazi wa vitendo:

1. Jenga OCI bundle ambayo rootfs yake inabadilisha `/dev/null` na link kuelekea path ya host unayotaka (`ln -sf /proc/sys/kernel/core_pattern rootfs/dev/null`).
2. Anzisha container kabla ya marekebisho ili runc ifanye bind-mount ya target ya procfs ya host juu ya link.
3. Ndani ya container namespace, andika kwenye file ya procfs sasa iliyofichuliwa (mfano, elekeza `core_pattern` kwenye helper ya reverse shell) na kusababisha mchakato wowote kuanguka ili kulazimisha kernel ya host kutekeleza helper yako kama muktadha wa PID 1.

Unaweza kwa haraka kuchunguza ikiwa bundle inaficha faili sahihi kabla ya kuianzisha:
```bash
jq '.linux.maskedPaths' config.json | tr -d '"'
```
Kama runtime inakosa masking entry uliyotarajia (au inaiepuka kwa sababu `/dev/null` imefifia), chukulia container kuwa na uwezekano wa kuona PID za host.

### Injection ya namespace na `insject`

NCC Group’s `insject` inachajiwa kama LD_PRELOAD payload inayofunga hatua ya mwisho katika programu lengwa (default `main`) na kutuma mfululizo wa wito za `setns()` baada ya `execve()`. Hiyo inakuwezesha kuambatana kutoka host (au container nyingine) ndani ya PID namespace ya mwathirika *baada ya* runtime yake kuanzishwa, ukihifadhi mtazamo wake wa `/proc/<pid>` bila kuiga binaries ndani ya filesystem ya container. Kwa sababu `insject` inaweza kuchelewesha kujiunga na PID namespace hadi itakapofork, unaweza kuweka thread moja katika host namespace (ikiwa na CAP_SYS_PTRACE) wakati thread nyingine inatekeleza katika target PID namespace, ikitengeneza primitives zenye nguvu za debugging au za kimashambulizi.

Mfano wa matumizi:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Mambo muhimu unapoitumia au kujilinda dhidi ya namespace injection:

- Tumia `-S/--strict` kulazimisha `insject` kukatiza ikiwa threads tayari zipo au namespace joins zinashindwa; vinginevyo unaweza kuacha partly-migrated threads straddling host and container PID spaces.
- Usiwe mwanachomoa tools ambazo bado zina writable host file descriptors isipokuwa pia ujiunge na mount namespace—vinginevyo mchakato wowote ndani ya PID namespace unaweza ptrace helper wako na reuse hizo descriptors kutamper host resources.

## Marejeo

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [container escape via "masked path" abuse due to mount race conditions (GitHub Security Advisory)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [Tool Release – insject: A Linux Namespace Injector (NCC Group)](https://www.nccgroup.com/us/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../banners/hacktricks-training.md}}
