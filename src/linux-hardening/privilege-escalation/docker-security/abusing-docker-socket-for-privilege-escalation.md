# Misbruik van Docker Socket vir Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

Daar is 'n paar geleenthede waar jy net **toegang tot die docker socket** het en jy dit wil gebruik om **privileges te eskaleer**. Sommige aksies mag baie verdag wees en jy mag dit wil vermy, so hier kan jy verskillende vlae vind wat nuttig kan wees om privileges te eskaleer:

### Via mount

Jy kan **mount** verskillende dele van die **filesystem** in 'n container wat as root loop en dit **toegang** gee.\
Jy kan ook 'n **mount misbruik om privileges te eskaleer** binne die container.

- **`-v /:/host`** -> Mount die host filesystem in die container sodat jy die **host filesystem kan lees.**
- As jy wil **voel soos jy in die host is** maar in die container is, kan jy ander verdedigingsmeganismes deaktiveer met vlae soos:
- `--privileged`
- `--cap-add=ALL`
- `--security-opt apparmor=unconfined`
- `--security-opt seccomp=unconfined`
- `-security-opt label:disable`
- `--pid=host`
- `--userns=host`
- `--uts=host`
- `--cgroupns=host`
- **`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined`** -> Dit is soortgelyk aan die vorige metode, maar hier **mount ons die toestel skyf**. Dan, binne die container, hardloop `mount /dev/sda1 /mnt` en jy kan die **host filesystem** in `/mnt` **toegang**.
- Hardloop `fdisk -l` in die host om die `</dev/sda1>` toestel te vind om te mount.
- **`-v /tmp:/host`** -> As jy om een of ander rede net **'n gids kan mount** van die host en jy het toegang binne die host. Mount dit en skep 'n **`/bin/bash`** met **suid** in die gemounte gids sodat jy dit kan **uitvoer van die host en na root eskaleer**.

> [!NOTE]
> Let daarop dat jy dalk nie die gids `/tmp` kan mount nie, maar jy kan 'n **ander skryfbare gids** mount. Jy kan skryfbare gidse vind met: `find / -writable -type d 2>/dev/null`
>
> **Let daarop dat nie al die gidse in 'n linux masjien die suid bit sal ondersteun nie!** Om te kyk watter gidse die suid bit ondersteun, hardloop `mount | grep -v "nosuid"` Byvoorbeeld, gewoonlik ondersteun `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` en `/var/lib/lxcfs` nie die suid bit nie.
>
> Let ook daarop dat as jy **`/etc`** of enige ander gids **wat konfigurasie lêers bevat**, kan mount, jy dit mag verander vanuit die docker container as root om dit te **misbruik in die host** en privileges te eskaleer (miskien deur `/etc/shadow` te wysig).

### Ontsnapping uit die container

- **`--privileged`** -> Met hierdie vlag [verwyder jy al die isolasie van die container](docker-privileged.md#what-affects). Kyk tegnieke om [uit priviligeerde containers as root te ontsnap](docker-breakout-privilege-escalation/index.html#automatic-enumeration-and-escape).
- **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> Om [te eskaleer deur capabilities te misbruik](../linux-capabilities.md), **gee daardie vermoë aan die container** en deaktiveer ander beskermingsmetodes wat die eksploit kan verhinder om te werk.

### Curl

Op hierdie bladsy het ons maniere bespreek om privileges te eskaleer met behulp van docker vlae, jy kan **maniere vind om hierdie metodes te misbruik met die curl** opdrag op die bladsy:

{{#include ../../../banners/hacktricks-training.md}}
