{{#include ../../banners/hacktricks-training.md}}

# SELinux в контейнерах

[Вступ та приклад з документації redhat](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) є **системою маркування**. Кожен **процес** та кожен **об'єкт** файлової системи має **мітку**. Політики SELinux визначають правила щодо того, що **мітка процесу дозволяє робити з усіма іншими мітками** в системі.

Контейнерні движки запускають **контейнерні процеси з єдиною обмеженою міткою SELinux**, зазвичай `container_t`, а потім встановлюють мітку `container_file_t` для вмісту всередині контейнера. Правила політики SELinux в основному говорять, що **процеси `container_t` можуть лише читати/записувати/виконувати файли, помічені як `container_file_t`**. Якщо контейнерний процес вийде з контейнера і спробує записати вміст на хост, ядро Linux відмовляє в доступі і дозволяє контейнерному процесу записувати лише вміст, помічений як `container_file_t`.
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# Користувачі SELinux

Існують користувачі SELinux на додаток до звичайних користувачів Linux. Користувачі SELinux є частиною політики SELinux. Кожен користувач Linux відображається на користувача SELinux як частина політики. Це дозволяє користувачам Linux успадковувати обмеження та правила безпеки і механізми, накладені на користувачів SELinux.

{{#include ../../banners/hacktricks-training.md}}
