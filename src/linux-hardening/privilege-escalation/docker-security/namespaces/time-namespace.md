# Time Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

Namespace ya muda katika Linux inaruhusu offsets za kila namespace kwa saa za mfumo zisizobadilika na saa za kuanzisha. Inatumika sana katika kontena za Linux kubadilisha tarehe/saa ndani ya kontena na kurekebisha saa baada ya kurejesha kutoka kwa alama ya kuangalia au picha.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
Kwa kuunganisha mfano mpya wa mfumo wa `/proc` ikiwa unatumia param `--mount-proc`, unahakikisha kwamba namespace mpya ya kuunganisha ina **mtazamo sahihi na uliojitegemea wa taarifa za mchakato zinazohusiana na namespace hiyo**.

<details>

<summary>Kosa: bash: fork: Haiwezekani kugawa kumbukumbu</summary>

Wakati `unshare` inatekelezwa bila chaguo la `-f`, kosa linakutana kutokana na jinsi Linux inavyoshughulikia namespaces mpya za PID (Kitambulisho cha Mchakato). Maelezo muhimu na suluhisho yameelezwa hapa chini:

1. **Maelezo ya Tatizo**:

- Kernel ya Linux inaruhusu mchakato kuunda namespaces mpya kwa kutumia wito wa mfumo wa `unshare`. Hata hivyo, mchakato unaoanzisha uundaji wa namespace mpya ya PID (inayojulikana kama mchakato wa "unshare") hauingii kwenye namespace mpya; ni watoto wake tu ndio wanaingia.
- Kuendesha `%unshare -p /bin/bash%` kunaanzisha `/bin/bash` katika mchakato sawa na `unshare`. Kwa hivyo, `/bin/bash` na watoto wake wako katika namespace ya awali ya PID.
- Mchakato wa kwanza wa mtoto wa `/bin/bash` katika namespace mpya unakuwa PID 1. Wakati mchakato huu unapoondoka, unachochea usafishaji wa namespace ikiwa hakuna mchakato mwingine, kwani PID 1 ina jukumu maalum la kupokea mchakato yatima. Kernel ya Linux itazima kisha ugawaji wa PID katika namespace hiyo.

2. **Matokeo**:

- Kuondoka kwa PID 1 katika namespace mpya kunasababisha usafishaji wa bendera ya `PIDNS_HASH_ADDING`. Hii inasababisha kazi ya `alloc_pid` kushindwa kugawa PID mpya wakati wa kuunda mchakato mpya, na kutoa kosa la "Haiwezekani kugawa kumbukumbu".

3. **Suluhisho**:
- Tatizo linaweza kutatuliwa kwa kutumia chaguo la `-f` pamoja na `unshare`. Chaguo hili linafanya `unshare` kuunda mchakato mpya baada ya kuunda namespace mpya ya PID.
- Kutekeleza `%unshare -fp /bin/bash%` kunahakikisha kwamba amri ya `unshare` yenyewe inakuwa PID 1 katika namespace mpya. `/bin/bash` na watoto wake wanakuwa salama ndani ya namespace hii mpya, kuzuia kuondoka mapema kwa PID 1 na kuruhusu ugawaji wa PID wa kawaida.

Kwa kuhakikisha kwamba `unshare` inatekelezwa na bendera ya `-f`, namespace mpya ya PID inatunzwa ipasavyo, ikiruhusu `/bin/bash` na michakato yake ya chini kufanya kazi bila kukutana na kosa la kugawa kumbukumbu.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Angalia ni namespace ipi mchakato wako uko ndani
```bash
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```
### Pata majina yote ya Time namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Ingia ndani ya muda namespace
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
## Manipulating Time Offsets

Kuanzia Linux 5.6, saa mbili zinaweza kuundwa kwa njia ya muda:

* `CLOCK_MONOTONIC`
* `CLOCK_BOOTTIME`

Deltas zao za kila namespace zinapatikana (na zinaweza kubadilishwa) kupitia faili `/proc/<PID>/timens_offsets`:
```
$ sudo unshare -Tr --mount-proc bash   # -T creates a new timens, -r drops capabilities
$ cat /proc/$$/timens_offsets
monotonic 0
boottime  0
```
Faili lina mistari miwili - mmoja kwa kila saa - ukiwa na tofauti katika **nanoseconds**. Mchakato ambao unashikilia **CAP_SYS_TIME** _katika eneo la muda_ unaweza kubadilisha thamani:
```
# advance CLOCK_MONOTONIC by two days (172 800 s)
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
# verify
$ cat /proc/$$/uptime   # first column uses CLOCK_MONOTONIC
172801.37  13.57
```
Ikiwa unahitaji saa ya ukuta (`CLOCK_REALTIME`) ibadilike pia, bado unapaswa kutegemea mitambo ya jadi (`date`, `hwclock`, `chronyd`, …); **sio** yenye majina.

### `unshare(1)` bendera za msaada (util-linux ≥ 2.38)
```
sudo unshare -T \
--monotonic="+24h"  \
--boottime="+7d"    \
--mount-proc         \
bash
```
The long options automatically write the chosen deltas to `timens_offsets` right after the namespace is created, saving a manual `echo`.

---

## OCI & Runtime support

* The **OCI Runtime Specification v1.1** (Nov 2023) added a dedicated `time` namespace type and the `linux.timeOffsets` field so that container engines can request time virtualisation in a portable way.
* **runc >= 1.2.0** implements that part of the spec.  A minimal `config.json` fragment looks like:
```json
{
"linux": {
"namespaces": [
{"type": "time"}
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
Then run the container with `runc run <id>`.

>  NOTE: runc **1.2.6** (Feb 2025) fixed an "exec into container with private timens" bug that could lead to a hang and potential DoS.  Make sure you are on ≥ 1.2.6 in production.

---

## Security considerations

1. **Required capability** – A process needs **CAP_SYS_TIME** inside its user/time namespace to change the offsets.  Dropping that capability in the container (default in Docker & Kubernetes) prevents tampering.
2. **No wall-clock changes** – Because `CLOCK_REALTIME` is shared with the host, attackers cannot spoof certificate lifetimes, JWT expiry, etc. via timens alone.
3. **Log / detection evasion** – Software that relies on `CLOCK_MONOTONIC` (e.g. rate-limiters based on uptime) can be confused if the namespace user adjusts the offset.  Prefer `CLOCK_REALTIME` for security-relevant timestamps.
4. **Kernel attack surface** – Even with `CAP_SYS_TIME` removed, the kernel code remains accessible; keep the host patched. Linux 5.6 → 5.12 received multiple timens bug-fixes (NULL-deref, signedness issues).

### Hardening checklist

* Drop `CAP_SYS_TIME` in your container runtime default profile.
* Keep runtimes updated (runc ≥ 1.2.6, crun ≥ 1.12).
* Pin util-linux ≥ 2.38 if you rely on the `--monotonic/--boottime` helpers.
* Audit in-container software that reads **uptime** or **CLOCK_MONOTONIC** for security-critical logic.

## References

* man7.org – Time namespaces manual page: <https://man7.org/linux/man-pages/man7/time_namespaces.7.html>
* OCI blog – "OCI v1.1: new time and RDT namespaces" (Nov 15 2023): <https://opencontainers.org/blog/2023/11/15/oci-spec-v1.1>

{{#include ../../../../banners/hacktricks-training.md}}
