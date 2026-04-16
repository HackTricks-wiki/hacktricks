# Assessment And Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Хороша оцінка container має відповісти на два паралельні питання. По-перше, що може зробити attacker з поточного workload? По-друге, які рішення operator зробили це можливим? Enumeration tools допомагають із першим питанням, а hardening guidance — із другим. Тримати обидва на одній сторінці робить розділ кориснішим як польовий reference, а не просто каталог escape tricks.

Оновлення, яке варто враховувати в modern environments, полягає в тому, що багато старіших writeups про container тихо припускають **rootful runtime**, **no user namespace isolation**, і часто **cgroup v1**. Ці припущення більше не є безпечними. Перш ніж витрачати час на старі escape primitives, спочатку перевірте, чи workload є rootless або userns-remapped, чи host використовує cgroup v2, і чи Kubernetes або runtime тепер застосовує default seccomp та AppArmor profiles. Ці деталі часто вирішують, чи still applies відомий breakout.

## Enumeration Tools

Кілька tools залишаються корисними для швидкого characterization container environment:

- `linpeas` can identify many container indicators, mounted sockets, capability sets, dangerous filesystems, and breakout hints.
- `CDK` focuses specifically on container environments and includes enumeration plus some automated escape checks.
- `amicontained` is lightweight and useful for identifying container restrictions, capabilities, namespace exposure, and likely breakout classes.
- `deepce` is another container-focused enumerator with breakout-oriented checks.
- `grype` is useful when the assessment includes image-package vulnerability review instead of only runtime escape analysis.
- `Tracee` is useful when you need **runtime evidence** rather than static posture alone, especially for suspicious process execution, file access, and container-aware event collection.
- `Inspektor Gadget` is useful in Kubernetes and Linux-host investigations when you need eBPF-backed visibility tied back to pods, containers, namespaces, and other higher-level concepts.

The value of these tools is speed and coverage, not certainty. They help reveal the rough posture quickly, but the interesting findings still need manual interpretation against the actual runtime, namespace, capability, and mount model.

## Hardening Priorities

The most important hardening principles are conceptually simple even though their implementation varies by platform. Avoid privileged containers. Avoid mounted runtime sockets. Do not give containers writable host paths unless there is a very specific reason. Use user namespaces or rootless execution where feasible. Drop all capabilities and add back only the ones the workload truly needs. Keep seccomp, AppArmor, and SELinux enabled rather than disabling them to fix application compatibility problems. Limit resources so that a compromised container cannot trivially deny service to the host.

Image and build hygiene matter as much as runtime posture. Use minimal images, rebuild frequently, scan them, require provenance where practical, and keep secrets out of layers. A container running as non-root with a small image and a narrow syscall and capability surface is much easier to defend than a large convenience image running as host-equivalent root with debugging tools preinstalled.

For Kubernetes, current hardening baselines are more opinionated than many operators still assume. The built-in **Pod Security Standards** treat `restricted` as the "current best practice" profile: `allowPrivilegeEscalation` should be `false`, workloads should run as non-root, seccomp should be explicitly set to `RuntimeDefault` or `Localhost`, and capability sets should be dropped aggressively. During assessment, this matters because a cluster that is only using `warn` or `audit` labels may look hardened on paper while still admitting risky pods in practice.

## Modern Triage Questions

Before diving into escape-specific pages, answer these quick questions:

1. Is the workload **rootful**, **rootless**, or **userns-remapped**?
2. Is the node using **cgroup v1** or **cgroup v2**?
3. Are **seccomp** and **AppArmor/SELinux** explicitly configured, or merely inherited when available?
4. In Kubernetes, is the namespace actually **enforcing** `baseline` or `restricted`, or only warning/auditing?

Useful checks:
```bash
id
cat /proc/self/uid_map 2>/dev/null
cat /proc/self/gid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/1/attr/current 2>/dev/null
find /var/run/secrets -maxdepth 3 -type f 2>/dev/null | head
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get ns "$NS" -o jsonpath='{.metadata.labels}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.supplementalGroupsPolicy}{"\n"}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.seccompProfile.type}{"\n"}{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.capabilities.drop}{"\n"}' 2>/dev/null
```
Що тут цікавого:

- Якщо `/proc/self/uid_map` показує, що container root відображається в **високий діапазон host UID**, багато старіших writeups про host-root стають менш релевантними, бо root у container вже не є еквівалентом host-root.
- Якщо `/sys/fs/cgroup` має значення `cgroup2fs`, старі writeups, специфічні для **cgroup v1**, такі як зловживання `release_agent`, уже не мають бути твоєю першою здогадкою.
- Якщо seccomp і AppArmor успадковуються лише неявно, portability може бути слабшою, ніж очікують defenders. У Kubernetes явне встановлення `RuntimeDefault` часто є сильнішим, ніж мовчазна залежність від node defaults.
- Якщо `supplementalGroupsPolicy` встановлено на `Strict`, pod має уникати мовчазного успадкування додаткових group memberships з `/etc/group` всередині image, що робить поведінку доступу до volume і file через groups більш передбачуваною.
- Namespace labels на кшталт `pod-security.kubernetes.io/enforce=restricted` варто перевіряти безпосередньо. `warn` і `audit` корисні, але вони не зупиняють створення risky pod.

## Resource-Exhaustion Examples

Resource controls не є glamorous, але вони є частиною container security, бо обмежують blast radius компрометації. Без memory, CPU або PID limits навіть простий shell може бути достатнім, щоб погіршити роботу host або сусідніх workloads.

Приклади tests, що впливають на host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Ці приклади корисні, бо показують, що не кожен небезпечний результат у контейнері є чистим "escape". Слабкі обмеження cgroup все ще можуть перетворити code execution на реальний операційний вплив.

У середовищах на базі Kubernetes також перевіряйте, чи взагалі існують resource controls, перш ніж вважати DoS лише теоретичним:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Інструменти для hardening

Для Docker-centric середовищ, `docker-bench-security` залишається корисною базовою перевіркою на стороні host, оскільки він перевіряє поширені проблеми конфігурації відповідно до широко визнаних benchmark guidance:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Інструмент не є заміною threat modeling, але він усе ще корисний для виявлення недбалих daemon, mount, network і runtime default-налаштувань, які накопичуються з часом.

Для Kubernetes і runtime-heavy середовищ поєднуйте static checks із runtime visibility:

- `Tracee` корисний для container-aware runtime detection і швидкого forensics, коли потрібно підтвердити, до чого насправді звертався скомпрометований workload.
- `Inspektor Gadget` корисний, коли оцінка потребує kernel-level telemetry, зіставленої назад із pods, containers, DNS activity, file execution або network behavior.

## Checks

Використовуйте це як швидкі перші команди під час assessment:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Що тут цікаво:

- Root-процес із широкими capabilities та `Seccomp: 0` потребує негайної уваги.
- Root-процес, який також має **1:1 UID map**, набагато цікавіший, ніж "root" всередині належним чином ізольованого user namespace.
- `cgroup2fs` зазвичай означає, що багато старіших **cgroup v1** chains для escape — не найкраща стартова точка, тоді як відсутність `memory.max` або `pids.max` все ще вказує на слабкі controls blast-radius.
- Підозрілі mounts і runtime sockets часто дають швидший шлях до impact, ніж будь-який kernel exploit.
- Поєднання слабкої runtime posture і слабких resource limits зазвичай вказує на загалом permissive container environment, а не на одну ізольовану помилку.

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
