# Wykorzystywanie gniazda Docker do eskalacji uprawnień

{{#include ../../../banners/hacktricks-training.md}}

Są sytuacje, w których masz **dostęp do gniazda docker** i chcesz go użyć do **eskalacji uprawnień**. Niektóre działania mogą być bardzo podejrzane i możesz chcieć ich unikać, więc tutaj znajdziesz różne flagi, które mogą być przydatne do eskalacji uprawnień:

### Poprzez montowanie

Możesz **zamontować** różne części **systemu plików** w kontenerze działającym jako root i **uzyskać do nich dostęp**.\
Możesz również **wykorzystać montowanie do eskalacji uprawnień** wewnątrz kontenera.

- **`-v /:/host`** -> Zamontuj system plików hosta w kontenerze, aby móc **czytać system plików hosta.**
- Jeśli chcesz **czuć się jak na hoście**, ale będąc w kontenerze, możesz wyłączyć inne mechanizmy obronne, używając flag takich jak:
- `--privileged`
- `--cap-add=ALL`
- `--security-opt apparmor=unconfined`
- `--security-opt seccomp=unconfined`
- `-security-opt label:disable`
- `--pid=host`
- `--userns=host`
- `--uts=host`
- `--cgroupns=host`
- \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> To jest podobne do poprzedniej metody, ale tutaj **montujemy dysk urządzenia**. Następnie, wewnątrz kontenera uruchom `mount /dev/sda1 /mnt` i możesz **uzyskać dostęp** do **systemu plików hosta** w `/mnt`
- Uruchom `fdisk -l` na hoście, aby znaleźć urządzenie `</dev/sda1>` do zamontowania
- **`-v /tmp:/host`** -> Jeśli z jakiegoś powodu możesz **zamontować tylko niektóre katalogi** z hosta i masz dostęp wewnątrz hosta. Zamontuj go i utwórz **`/bin/bash`** z **suid** w zamontowanym katalogu, aby móc **wykonać go z hosta i eskalować do roota**.

> [!NOTE]
> Zauważ, że być może nie możesz zamontować folderu `/tmp`, ale możesz zamontować **inny zapisywalny folder**. Możesz znaleźć zapisywalne katalogi, używając: `find / -writable -type d 2>/dev/null`
>
> **Zauważ, że nie wszystkie katalogi w maszynie linuxowej będą wspierać bit suid!** Aby sprawdzić, które katalogi wspierają bit suid, uruchom `mount | grep -v "nosuid"` Na przykład zazwyczaj `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` i `/var/lib/lxcfs` nie wspierają bitu suid.
>
> Zauważ również, że jeśli możesz **zamontować `/etc`** lub jakikolwiek inny folder **zawierający pliki konfiguracyjne**, możesz je zmienić z kontenera docker jako root, aby **wykorzystać je na hoście** i eskalować uprawnienia (może modyfikując `/etc/shadow`)

### Ucieczka z kontenera

- **`--privileged`** -> Z tą flagą [usuwasz całe izolowanie z kontenera](docker-privileged.md#what-affects). Sprawdź techniki, aby [uciec z uprzywilejowanych kontenerów jako root](docker-breakout-privilege-escalation/index.html#automatic-enumeration-and-escape).
- **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> Aby [eskalować, wykorzystując możliwości](../linux-capabilities.md), **przyznaj tę możliwość kontenerowi** i wyłącz inne metody ochrony, które mogą uniemożliwić działanie exploita.

### Curl

Na tej stronie omówiliśmy sposoby eskalacji uprawnień przy użyciu flag docker, możesz znaleźć **sposoby na wykorzystanie tych metod za pomocą polecenia curl** na stronie:

{{#include ../../../banners/hacktricks-training.md}}
