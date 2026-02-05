# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

UTS (UNIX Time-Sharing System) namespace ni kipengele cha kernel ya Linux kinachotoa **utengwa wa vitambulisho viwili vya mfumo**: **hostname** na **NIS** (Network Information Service) domain name. Utengano huu unaruhusu kila UTS namespace kuwa na **hostname yake huru na domain name ya NIS yake mwenyewe**, jambo ambalo ni muhimu hasa katika mazingira ya containerization ambapo kila container inapaswa kuonekana kama mfumo tofauti ulio na hostname yake.

### Jinsi inavyofanya kazi:

1. Wakati UTS namespace mpya inapoanzishwa, inaanza na **nakala ya hostname na domain name ya NIS kutoka kwa namespace ya mzazi wake**. Hii inamaanisha kwamba, wakati wa uundaji, namespace mpya **inashiriki vitambulisho sawa na vya mzazi wake**. Hata hivyo, mabadiliko yoyote yanayofanywa baadaye kwa hostname au domain name ya NIS ndani ya namespace hayo hayatatafauti namespaces nyingine.
2. Michakato ndani ya UTS namespace **inaweza kubadilisha hostname na domain name ya NIS** kwa kutumia simu za mfumo `sethostname()` na `setdomainname()`, mtawalia. Mabadiliko haya ni ya ndani kwa namespace na hayataathiri namespaces nyingine au mfumo mwenyeji.
3. Michakato inaweza kuhamia kati ya namespaces kwa kutumia simu ya mfumo `setns()` au kuunda namespaces mpya kwa kutumia simu za mfumo `unshare()` au `clone()` na flag `CLONE_NEWUTS`. Mchakato ukihamia kwa namespace mpya au kuunda moja, utaanza kutumia hostname na domain name ya NIS zinazohusiana na namespace hiyo.

## Maabara:

### Unda Namespaces tofauti

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **mtazamo sahihi na uliotengwa wa taarifa za mchakato zinazohusiana na namespace hiyo**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Maelezo ya Tatizo**:

- Kernel ya Linux inaruhusu mchakato kuunda namespaces mpya kwa kutumia system call ya `unshare`. Hata hivyo, mchakato unaoanzisha uundaji wa namespace mpya ya PID (ujulikanao kama mchakato wa "unshare") hauingii ndani ya namespace mpya; ni watoto wake tu wanaoingia.
- Running `%unshare -p /bin/bash%` starts `/bin/bash` in the same process as `unshare`. Kwa hivyo, `/bin/bash` na watoto wake wa mchakato wako katika namespace ya PID ya awali.
- Mtoto wa kwanza wa `/bin/bash` katika namespace mpya anakuwa PID 1. Wakati mchakato huo unapotoka, husababisha kusafishwa kwa namespace ikiwa hakuna michakato mingine, kwa kuwa PID 1 ana jukumu maalum la kupokea michakato isiyo na mzazi (orphan). Kernel ya Linux kisha itazima ugawaji wa PID katika namespace hiyo.

2. **Matokeo**:

- Kutoka kwa PID 1 katika namespace mpya husababisha kusafishwa kwa flag `PIDNS_HASH_ADDING`. Hii inasababisha function `alloc_pid` kushindwa kugawa PID mpya wakati wa kuunda mchakato mpya, na kutoa hitilafu "Cannot allocate memory".

3. **Suluhisho**:
- Tatizo linaweza kutatuliwa kwa kutumia chaguo `-f` pamoja na `unshare`. Chaguo hili hufanya `unshare` kufork mchakato mpya baada ya kuunda namespace mpya ya PID.
- Executing `%unshare -fp /bin/bash%` ensures that the `unshare` command itself becomes PID 1 in the new namespace. `/bin/bash` na watoto wake wa mchakato basi wamehifadhiwa salama ndani ya namespace hii mpya, kuzuia kutoka mapema kwa PID 1 na kuruhusu ugawaji wa PID wa kawaida.

Kwa kuhakikisha kwamba `unshare` inakimbia kwa flag `-f`, namespace mpya ya PID inadumishwa ipasavyo, na kuruhusu `/bin/bash` na michakato yake ndogo kufanya kazi bila kukumbana na hitilafu ya ugawaji wa kumbukumbu.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Angalia namespace ambayo mchakato wako uko ndani yake
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
### Ningia ndani ya UTS namespace
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## Kutumia vibaya kushirikishwa kwa UTS ya host

Iwapo container inaanzishwa kwa `--uts=host`, itaungana na host UTS namespace badala ya kupata moja iliyotengwa. Kwa capabilities kama `--cap-add SYS_ADMIN`, code ndani ya container inaweza kubadilisha host hostname/NIS name kwa kutumia `sethostname()`/`setdomainname()`:
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
Kubadilisha host name kunaweza kuchezea logs/alerts, kuchanganya cluster discovery au kuvunja TLS/SSH configs ambazo zinaweka hostname.

### Gundua containers zinazoshiriki UTS na host
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
