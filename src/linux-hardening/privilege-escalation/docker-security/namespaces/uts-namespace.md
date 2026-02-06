# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

Namespace ya UTS (UNIX Time-Sharing System) ni kipengele cha kernel ya Linux kinachotoa i**solation of two system identifiers**: the **hostname** na **NIS** (Network Information Service) domain name. Kutenganishwa huu unaruhusu kila UTS namespace kuwa na **own independent hostname and NIS domain name**, jambo muhimu hasa katika mazingira ya containerization ambapo kila container inapaswa kuonekana kama mfumo tofauti ukiwa na hostname yake.

### Jinsi inavyofanya kazi:

1. Wakati namespace mpya ya UTS inapoanzishwa, inaanza na **copy of the hostname and NIS domain name from its parent namespace**. Hii ina maana kwamba, wakati wa kuundwa, namespace mpya s**hares the same identifiers as its parent**. Hata hivyo, mabadiliko yoyote yanayofuata kwenye hostname au NIS domain name ndani ya namespace hayataathiri namespaces nyingine.
2. Michakato ndani ya UTS namespace **can change the hostname and NIS domain name** kwa kutumia system call `sethostname()` na `setdomainname()`, mtawalia. Mabadiliko haya ni ya ndani ya namespace na hayataathiri namespaces nyingine au mfumo wa mwenyeji.
3. Michakato inaweza kuhama kati ya namespaces kwa kutumia system call `setns()` au kuunda namespaces mpya kwa kutumia `unshare()` au `clone()` system calls kwa bendera `CLONE_NEWUTS`. Wakati mchakato unapoenda kwenye namespace mpya au kuunda moja, utaanza kutumia hostname na NIS domain name zinazohusiana na namespace hiyo.

## Maabara:

### Create different Namespaces

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
Kwa ku-mount instance mpya ya filesystem ya `/proc` ikiwa utatumia param `--mount-proc`, unahakikisha kwamba mount namespace mpya ina **mtazamo sahihi na uliotengwa wa taarifa za michakato maalum kwa namespace hiyo**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Maelezo ya Tatizo**:

- Kernel ya Linux inaruhusu mchakato kuunda namespaces mpya kwa kutumia system call ya `unshare`. Hata hivyo, mchakato unaoanzisha uundaji wa PID namespace mpya (inayorejelewa kama mchakato "unshare") hauingii kwenye namespace mpya; ni watoto wake tu wanaoingia.
- Running %unshare -p /bin/bash% starts `/bin/bash` in the same process as `unshare`. Consequently, `/bin/bash` and its child processes are in the original PID namespace.
- Mchakato wa kwanza mtoto wa `/bin/bash` katika namespace mpya anakuwa PID 1. Mchakato huu ukitoka, husababisha usafishaji wa namespace ikiwa hakuna mchakato mwingine, kwa kuwa PID 1 ina jukumu maalum la kupokea michakato mitupu. Kernel ya Linux kisha itazuia ugawaji wa PID katika namespace hiyo.

2. **Consequence**:

- Exit ya PID 1 katika namespace mpya inasababisha kusafishwa kwa flag `PIDNS_HASH_ADDING`. Hii inasababisha function `alloc_pid` kushindwa kugawa PID mpya wakati wa kuunda mchakato mpya, na kutoa kosa "Cannot allocate memory".

3. **Solution**:
- Tatizo linaweza kutatuliwa kwa kutumia chaguo `-f` na `unshare`. Chaguo hili linasababisha `unshare` kufork mchakato mpya baada ya kuunda PID namespace mpya.
- Executing %unshare -fp /bin/bash% ensures that the `unshare` command itself becomes PID 1 in the new namespace. `/bin/bash` and its child processes are then safely contained within this new namespace, preventing the premature exit of PID 1 and allowing normal PID allocation.

Kwa kuhakikisha kwamba `unshare` inaendeshwa na flag `-f`, PID namespace mpya inadumishwa ipasavyo, ikiruhusu `/bin/bash` na michakato yake ndogo kufanya kazi bila kukutana na kosa la ugawaji wa kumbukumbu.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Angalia mchakato wako uko katika namespace gani
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### Pata namespaces zote za UTS
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Ingia ndani ya UTS namespace
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## Kutumia vibaya kushiriki UTS ya host

Ikiwa container imeanzishwa kwa `--uts=host`, inajiunga na host UTS namespace badala ya kupata moja iliyotengwa. Kwa capabilities kama `--cap-add SYS_ADMIN`, code ndani ya container inaweza kubadilisha host hostname/NIS name kupitia `sethostname()`/`setdomainname()`:
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
Kubadilisha hostname kunaweza kuharibu logs/alerts, kuchanganya cluster discovery au kuvunja TLS/SSH configs zinazobana hostname.

### Tambua containers zinazoshiriki UTS na host
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
