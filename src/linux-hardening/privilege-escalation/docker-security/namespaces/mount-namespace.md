# Mount Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

Mount namespace ni kipengele cha kernel ya Linux kinachotoa kutengwa kwa maeneo ya mfumo wa faili yanayoonekana na kundi la michakato. Kila mount namespace ina seti yake ya maeneo ya mfumo wa faili, na **mabadiliko kwenye maeneo ya mount katika namespace moja hayaathiri namespaces nyingine**. Hii inamaanisha kwamba michakato inayofanya kazi katika namespaces tofauti za mount inaweza kuwa na maoni tofauti ya hierarchi ya mfumo wa faili.

Mount namespaces ni muhimu sana katika uundaji wa kontena, ambapo kila kontena inapaswa kuwa na mfumo wake wa faili na usanidi, uliojitenga na kontena nyingine na mfumo wa mwenyeji.

### How it works:

1. Wakati mount namespace mpya inaundwa, inaanzishwa na **nakala ya maeneo ya mount kutoka namespace yake ya mzazi**. Hii inamaanisha kwamba, wakati wa uundaji, namespace mpya inashiriki maoni sawa ya mfumo wa faili kama mzazi wake. Hata hivyo, mabadiliko yoyote yanayofuata kwenye maeneo ya mount ndani ya namespace hayatamathiri mzazi au namespaces nyingine.
2. Wakati mchakato unabadilisha eneo la mount ndani ya namespace yake, kama vile kuunganisha au kuondoa mfumo wa faili, **mabadiliko ni ya ndani kwa namespace hiyo** na hayaathiri namespaces nyingine. Hii inaruhusu kila namespace kuwa na hierarchi yake ya mfumo wa faili isiyoegemea.
3. Michakato inaweza kuhamia kati ya namespaces kwa kutumia wito wa mfumo wa `setns()`, au kuunda namespaces mpya kwa kutumia wito wa mfumo wa `unshare()` au `clone()` na bendera ya `CLONE_NEWNS`. Wakati mchakato unahamia kwenye namespace mpya au kuunda moja, utaanza kutumia maeneo ya mount yanayohusiana na namespace hiyo.
4. **Vifaa vya faili na inodes vinashirikiwa kati ya namespaces**, ikimaanisha kwamba ikiwa mchakato katika namespace moja una kifaa cha faili kilichofunguliwa kinachoelekeza kwenye faili, kinaweza **kupitisha kifaa hicho cha faili** kwa mchakato katika namespace nyingine, na **michakato yote itapata faili hiyo hiyo**. Hata hivyo, njia ya faili inaweza isiwe sawa katika namespaces zote mbili kutokana na tofauti katika maeneo ya mount.

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
Kwa kuunganisha mfano mpya wa mfumo wa `/proc` ikiwa unatumia param `--mount-proc`, unahakikisha kwamba mount namespace mpya ina **mtazamo sahihi na wa kutengwa wa taarifa za mchakato maalum kwa namespace hiyo**.

<details>

<summary>Kosa: bash: fork: Haiwezekani kugawa kumbukumbu</summary>

Wakati `unshare` inatekelezwa bila chaguo la `-f`, kosa linakutana kutokana na jinsi Linux inavyoshughulikia namespaces mpya za PID (Process ID). Maelezo muhimu na suluhisho yameelezwa hapa chini:

1. **Maelezo ya Tatizo**:

- Kernel ya Linux inaruhusu mchakato kuunda namespaces mpya kwa kutumia wito wa mfumo wa `unshare`. Hata hivyo, mchakato unaoanzisha uundaji wa namespace mpya ya PID (inayojulikana kama mchakato wa "unshare") hauingii kwenye namespace mpya; ni watoto wake tu wanajumuishwa.
- Kukimbia `%unshare -p /bin/bash%` kunaanzisha `/bin/bash` katika mchakato sawa na `unshare`. Kwa hivyo, `/bin/bash` na watoto wake wako katika namespace ya awali ya PID.
- Mchakato wa kwanza wa mtoto wa `/bin/bash` katika namespace mpya unakuwa PID 1. Wakati mchakato huu unapoondoka, unachochea usafishaji wa namespace ikiwa hakuna mchakato mwingine, kwani PID 1 ina jukumu maalum la kupokea mchakato wa yatima. Kernel ya Linux itazima ugawaji wa PID katika namespace hiyo.

2. **Matokeo**:

- Kuondoka kwa PID 1 katika namespace mpya kunasababisha usafishaji wa bendera ya `PIDNS_HASH_ADDING`. Hii inasababisha kazi ya `alloc_pid` kushindwa kugawa PID mpya wakati wa kuunda mchakato mpya, ikitoa kosa la "Haiwezekani kugawa kumbukumbu".

3. **Suluhisho**:
- Tatizo linaweza kutatuliwa kwa kutumia chaguo la `-f` pamoja na `unshare`. Chaguo hili linafanya `unshare` kuunda mchakato mpya baada ya kuunda namespace mpya ya PID.
- Kutekeleza `%unshare -fp /bin/bash%` kunahakikisha kwamba amri ya `unshare` yenyewe inakuwa PID 1 katika namespace mpya. `/bin/bash` na watoto wake wanakuwa salama ndani ya namespace hii mpya, kuzuia kuondoka mapema kwa PID 1 na kuruhusu ugawaji wa kawaida wa PID.

Kwa kuhakikisha kwamba `unshare` inakimbia na bendera ya `-f`, namespace mpya ya PID inatunzwa kwa usahihi, ikiruhusu `/bin/bash` na mchakato wake wa chini kufanya kazi bila kukutana na kosa la ugawaji wa kumbukumbu.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Angalia ni namespace ipi mchakato wako uko ndani
```bash
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### Pata majina yote ya Mount namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```

```bash
findmnt
```
### Ingia ndani ya Mount namespace
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
Pia, unaweza tu **kuingia katika namespace ya mchakato mwingine ikiwa wewe ni root**. Na huwezi **kuingia** katika namespace nyingine **bila deskteta** inayorejelea hiyo (kama `/proc/self/ns/mnt`).

Kwa sababu milima mipya inapatikana tu ndani ya namespace, inawezekana kwamba namespace ina taarifa nyeti ambazo zinaweza kupatikana tu kutoka ndani yake.

### Mount kitu
```bash
# Generate new mount ns
unshare -m /bin/bash
mkdir /tmp/mount_ns_example
mount -t tmpfs tmpfs /tmp/mount_ns_example
mount | grep tmpfs # "tmpfs on /tmp/mount_ns_example"
echo test > /tmp/mount_ns_example/test
ls /tmp/mount_ns_example/test # Exists

# From the host
mount | grep tmpfs # Cannot see "tmpfs on /tmp/mount_ns_example"
ls /tmp/mount_ns_example/test # Doesn't exist
```

```
# findmnt # List existing mounts
TARGET                                SOURCE                                                                                                           FSTYPE     OPTIONS
/                                     /dev/mapper/web05--vg-root

# unshare --mount  # run a shell in a new mount namespace
# mount --bind /usr/bin/ /mnt/
# ls /mnt/cp
/mnt/cp
# exit  # exit the shell, and hence the mount namespace
# ls /mnt/cp
ls: cannot access '/mnt/cp': No such file or directory

## Notice there's different files in /tmp
# ls /tmp
revshell.elf

# ls /mnt/tmp
krb5cc_75401103_X5yEyy
systemd-private-3d87c249e8a84451994ad692609cd4b6-apache2.service-77w9dT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-resolved.service-RnMUhT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-timesyncd.service-FAnDql
vmware-root_662-2689143848

```
## Marejeo

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux](https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux)

{{#include ../../../../banners/hacktricks-training.md}}
