# Namespace ya Mtumiaji

{{#include ../../../../banners/hacktricks-training.md}}

{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## Marejeo

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)



## Taarifa za Msingi

Namespace ya mtumiaji ni sifa ya kernel ya Linux ambayo **inatoa utengwa wa ramani za ID za mtumiaji na kikundi**, ikiruhusu kila namespace ya mtumiaji kuwa na **seti yake ya ID za mtumiaji na kikundi**. Utengano huu unawawezesha michakato inayofanya kazi katika namespaces tofauti za mtumiaji kuwa na **vibali na umiliki tofauti**, hata kama wanashiriki nambari sawa za ID za mtumiaji na kikundi.

User namespaces ni muhimu hasa katika containerization, ambapo kila container inapaswa kuwa na seti yake huru ya ID za mtumiaji na kikundi, ikiruhusu usalama bora na utengano kati ya container na mfumo mwenyeji.

### Jinsi inavyofanya kazi:

1. Wakati user namespace mpya inapotengenezwa, itaanza na **seti tupu ya ramani za ID za mtumiaji na kikundi**. Hii ina maana kwamba mchakato wowote unaoendesha katika user namespace mpya utaanza **bila vibali nje ya namespace**.
2. Ramani za ID zinaweza kuanzishwa kati ya ID za mtumiaji na kikundi katika namespace mpya na zile katika namespace ya mzazi (au mwenyeji). Hii **inawaruhusu michakato katika namespace mpya kupata vibali na umiliki vinavyoendana na ID za mtumiaji na kikundi katika namespace ya mzazi**. Hata hivyo, ramani za ID zinaweza kukomeshwa kwa anuwai maalum na sehemu za ID, zikitoa udhibiti wa kina juu ya vibali vinavyotolewa kwa michakato katika namespace mpya.
3. Ndani ya user namespace, **michakato inaweza kuwa na vibali kamili vya root (UID 0) kwa shughuli ndani ya namespace**, wakati bado ikiwa na vibali vichache nje ya namespace. Hii inaruhusu **containers kuendesha zenye uwezo unaofanana na root ndani ya namespace yao bila kuwa na vibali kamili vya root kwenye mfumo mwenyeji**.
4. Michakato inaweza kuhamia kati ya namespaces kwa kutumia system call ya `setns()` au kuunda namespaces mpya kwa kutumia system calls `unshare()` au `clone()` zenye flag ya `CLONE_NEWUSER`. Wakati mchakato unapoenda kwenye namespace mpya au kuunda moja, utaanza kutumia ramani za ID za mtumiaji na kikundi zinazohusishwa na namespace hiyo.

## Maabara:

### Unda namespaces tofauti

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **accurate and isolated view of the process information specific to that namespace**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Ufafanuzi wa Tatizo**:

- The Linux kernel allows a process to create new namespaces using the `unshare` system call. However, the process that initiates the creation of a new PID namespace (referred to as the "unshare" process) does not enter the new namespace; only its child processes do.
- Running %unshare -p /bin/bash% starts `/bin/bash` in the same process as `unshare`. Consequently, `/bin/bash` and its child processes are in the original PID namespace.
- The first child process of `/bin/bash` in the new namespace becomes PID 1. When this process exits, it triggers the cleanup of the namespace if there are no other processes, as PID 1 has the special role of adopting orphan processes. The Linux kernel will then disable PID allocation in that namespace.

2. **Matokeo**:

- The exit of PID 1 in a new namespace leads to the cleaning of the `PIDNS_HASH_ADDING` flag. This results in the `alloc_pid` function failing to allocate a new PID when creating a new process, producing the "Cannot allocate memory" error.

3. **Suluhisho**:
- The issue can be resolved by using the `-f` option with `unshare`. This option makes `unshare` fork a new process after creating the new PID namespace.
- Executing %unshare -fp /bin/bash% ensures that the `unshare` command itself becomes PID 1 in the new namespace. `/bin/bash` and its child processes are then safely contained within this new namespace, preventing the premature exit of PID 1 and allowing normal PID allocation.

By ensuring that `unshare` runs with the `-f` flag, the new PID namespace is correctly maintained, allowing `/bin/bash` and its sub-processes to operate without encountering the memory allocation error.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Ili kutumia user namespace, Docker daemon inahitaji kuanzishwa na **`--userns-remap=default`**(Katika ubuntu 14.04, hii inaweza kufanywa kwa kuhariri `/etc/default/docker` na kisha kuendesha `sudo service docker restart`)

### Angalia mchakato wako uko ndani ya namespace gani
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Inawezekana kuangalia user map kutoka kwenye docker container kwa kutumia:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Au kutoka kwa host na:
```bash
cat /proc/<pid>/uid_map
```
### Tafuta namespaces zote za Mtumiaji
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Ingia ndani ya namespace ya mtumiaji
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Pia, unaweza tu **kuingia katika namespace ya mchakato mwingine ikiwa wewe ni root**. Na **huwezi** **kuingia** katika namespace nyingine **bila descriptor** inayoashiria (kama `/proc/self/ns/user`).

### Unda User namespace mpya (na mappings)
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```

```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Sheria za Uwekaji Ramani wa UID/GID Bila Ruhusa

Wakati mchakato unaoandika kwenye `uid_map`/`gid_map` **haina CAP_SETUID/CAP_SETGID katika namespace ya mtumiaji mzazi**, kernel inatekeleza sheria kali zaidi: **ramani moja tu** inaruhusiwa kwa UID/GID ya utekelezaji ya muomba, na kwa `gid_map` **lazima kwanza uzime `setgroups(2)`** kwa kuandika `deny` kwenye `/proc/<pid>/setgroups`.
```bash
# Check whether setgroups is allowed in this user namespace
cat /proc/self/setgroups   # allow|deny

# For unprivileged gid_map writes, disable setgroups first
echo deny > /proc/self/setgroups
```
### ID-mapped Mounts (MOUNT_ATTR_IDMAP)

ID-mapped mounts **attach a user namespace mapping to a mount**, hivyo umiliki wa faili hubadilishwa wakati unafikiwa kupitia mount hiyo. Hii hutumika kawaida na container runtimes (hasa rootless) ili **kushirikisha host paths bila recursive `chown`**, huku ikidumisha utafsiri wa UID/GID wa user namespace.

Kutoka kwa mtazamo wa ushambuliaji, **ikiwa unaweza kuunda mount namespace na kushikilia `CAP_SYS_ADMIN` ndani ya user namespace yako**, na filesystem inasaidia ID-mapped mounts, unaweza kuremapa *views* za umiliki wa bind mounts. Hii **haiubadili on-disk ownership**, lakini inaweza kufanya faili ambazo vingekuwa vigumu kuandika zionekane zikiwa zinamilikiwa na UID/GID yako iliyoratibiwa ndani ya namespace.

### Kurejesha Capabilities

Katika kesi za user namespaces, **wanapotengenezwa user namespace mpya, mchakato unaoingia ndani ya namespace unapewa seti kamili ya capabilities ndani ya namespace hiyo**. Capabilities hizi zimemruhusu mchakato kufanya operesheni za kipaumbele kama **mounting** **filesystems**, kuunda devices, au kubadilisha umiliki wa faili, lakini **ndio ndani tu ya muktadha wa user namespace yake**.

Kwa mfano, wakati una capability ya `CAP_SYS_ADMIN` ndani ya user namespace, unaweza kufanya operesheni ambazo kawaida zinahitaji capability hii, kama mounting filesystems, lakini ndani tu ya muktadha wa user namespace yako. Operesheni zozote unazofanya kwa capability hii hazitaathiri host system au namespaces nyingine.

> [!WARNING]
> Kwa hiyo, hata kupata mchakato mpya ndani ya User namespace mpya **kutakupa capabilities zote tena** (CapEff: 000001ffffffffff), kwa kweli unaweza **kutumia tu zile zinazohusiana na namespace** (mount kwa mfano) lakini si zote. Hivyo, peke yake hii haitoshi kutoroka kutoka Docker container.
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
```
{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## Marejeleo

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)

{{#include ../../../../banners/hacktricks-training.md}}
