# Abusing Docker Socket for Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

Kuna nyakati ambapo una **ufikiaji wa docker socket** na unataka kuutumia ili **kuinua mamlaka**. Vitendo vingine vinaweza kuwa vya kutatanisha na unaweza kutaka kuvikwepa, hivyo hapa unaweza kupata bendera tofauti ambazo zinaweza kuwa na manufaa katika kuinua mamlaka:

### Via mount

Unaweza **kuunganisha** sehemu tofauti za **filesystem** katika kontena linalotembea kama root na **kuzipata**.\
Pia unaweza **kudhulumu kuunganisha ili kuinua mamlaka** ndani ya kontena.

- **`-v /:/host`** -> Unganisha filesystem ya mwenyeji katika kontena ili uweze **kusoma filesystem ya mwenyeji.**
- Ikiwa unataka **kujihisi kama uko kwenye mwenyeji** lakini ukiwa kwenye kontena unaweza kuzima mitambo mingine ya ulinzi kwa kutumia bendera kama:
- `--privileged`
- `--cap-add=ALL`
- `--security-opt apparmor=unconfined`
- `--security-opt seccomp=unconfined`
- `-security-opt label:disable`
- `--pid=host`
- `--userns=host`
- `--uts=host`
- `--cgroupns=host`
- \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> Hii ni sawa na njia ya awali, lakini hapa tunafanya **kuunganisha diski ya kifaa**. Kisha, ndani ya kontena endesha `mount /dev/sda1 /mnt` na unaweza **kupata** **filesystem ya mwenyeji** katika `/mnt`
- Endesha `fdisk -l` kwenye mwenyeji ili kupata kifaa `</dev/sda1>` cha kuunganisha
- **`-v /tmp:/host`** -> Ikiwa kwa sababu fulani unaweza **kuunganisha tu directory fulani** kutoka kwa mwenyeji na una ufikiaji ndani ya mwenyeji. Unganisha na uunde **`/bin/bash`** yenye **suid** katika directory iliyounganishwa ili uweze **kuikimbia kutoka kwa mwenyeji na kuinua hadi root**.

> [!NOTE]
> Kumbuka kwamba huenda usiweze kuunganisha folda `/tmp` lakini unaweza kuunganisha **folda nyingine inayoweza kuandikwa**. Unaweza kupata directories zinazoweza kuandikwa kwa kutumia: `find / -writable -type d 2>/dev/null`
>
> **Kumbuka kwamba si directories zote katika mashine ya linux zitasaidia suid bit!** Ili kuangalia ni directories zipi zinasaidia suid bit endesha `mount | grep -v "nosuid"` Kwa mfano kawaida `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` na `/var/lib/lxcfs` hazisaidii suid bit.
>
> Kumbuka pia kwamba ikiwa unaweza **kuunganisha `/etc`** au folda nyingine yoyote **iliyokuwa na faili za usanidi**, unaweza kuzibadilisha kutoka kwa kontena la docker kama root ili **uzitumie kwenye mwenyeji** na kuinua mamlaka (labda kubadilisha `/etc/shadow`)

### Escaping from the container

- **`--privileged`** -> Kwa bendera hii un [ondoa kila ulinzi kutoka kwa kontena](docker-privileged.md#what-affects). Angalia mbinu za [kutoroka kutoka kwa kontena zenye mamlaka kama root](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape).
- **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> Ili [kuinua kwa kudhulumu uwezo](../linux-capabilities.md), **peana uwezo huo kwa kontena** na uzime njia nyingine za ulinzi ambazo zinaweza kuzuia exploit kufanya kazi.

### Curl

Katika ukurasa huu tumajadili njia za kuinua mamlaka kwa kutumia bendera za docker, unaweza kupata **njia za kudhulumu mbinu hizi kwa kutumia amri ya curl** katika ukurasa:

{{#include ../../../banners/hacktricks-training.md}}
