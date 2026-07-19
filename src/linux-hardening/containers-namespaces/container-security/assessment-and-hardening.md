# Оцінювання та hardening

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Якісне оцінювання контейнера має дати відповіді на два паралельні запитання. По-перше, що може зробити attacker із поточного workload? По-друге, які рішення оператора зробили це можливим? Інструменти enumeration допомагають із першим питанням, а рекомендації з hardening — із другим. Розміщення обох аспектів на одній сторінці робить цей розділ кориснішим як польовий довідник, а не просто каталог escape-трюків.

Одне практичне оновлення для сучасних середовищ полягає в тому, що багато старих container writeup неявно припускають **rootful runtime**, **відсутність user namespace isolation** і часто **cgroup v1**. Ці припущення більше не є безпечними. Перш ніж витрачати час на старі escape primitives, спочатку перевірте, чи є workload rootless або userns-remapped, чи використовує host cgroup v2 і чи застосовують Kubernetes або runtime стандартні профілі seccomp та AppArmor. Ці деталі часто визначають, чи досі працює відомий breakout.

## Інструменти Enumeration

Кілька інструментів залишаються корисними для швидкого визначення характеристик container environment:

- `linpeas` може виявляти багато індикаторів контейнера, змонтовані sockets, набори capabilities, небезпечні filesystems і підказки щодо breakout.
- `CDK` спеціально орієнтований на container environments і містить enumeration, а також деякі автоматизовані перевірки escape.
- `amicontained` є легким інструментом і корисний для визначення container restrictions, capabilities, namespace exposure та ймовірних класів breakout.
- `deepce` — ще один enumerator, орієнтований на контейнери, із перевірками, пов’язаними з breakout.
- `grype` корисний, коли оцінювання включає перевірку вразливостей пакетів в image, а не лише аналіз runtime escape.
- `Tracee` корисний, коли потрібні **runtime evidence**, а не лише статичний posture, особливо для підозрілого виконання процесів, доступу до файлів і збору container-aware events.
- `Inspektor Gadget` корисний під час досліджень Kubernetes і Linux hosts, коли потрібна visibility на основі eBPF із прив’язкою до pods, containers, namespaces та інших high-level concepts.

Цінність цих інструментів полягає у швидкості та охопленні, а не в абсолютній достовірності. Вони допомагають швидко виявити загальний posture, але цікаві findings усе одно потребують ручної інтерпретації з урахуванням фактичної моделі runtime, namespaces, capabilities і mounts.

## Пріоритети Hardening

Найважливіші принципи hardening концептуально прості, хоча їх реалізація відрізняється залежно від платформи. Уникайте privileged containers. Не використовуйте змонтовані runtime sockets. Не надавайте контейнерам writable host paths без дуже конкретної причини. За можливості використовуйте user namespaces або rootless execution. Видаляйте всі capabilities і повертайте лише ті, які справді потрібні workload. Залишайте seccomp, AppArmor і SELinux увімкненими, замість того щоб вимикати їх для вирішення проблем сумісності застосунку. Обмежуйте ресурси, щоб compromised container не міг тривіально виконати denial of service проти host.

Гігієна image і build так само важлива, як і runtime posture. Використовуйте minimal images, регулярно їх перебудовуйте, скануйте їх, вимагайте provenance, де це практично можливо, і не зберігайте secrets у layers. Контейнер, що працює як non-root, використовує невеликий image і має вузьку поверхню syscall та capability, значно легше захистити, ніж великий convenience image, який працює з host-equivalent root і містить попередньо встановлені debugging tools.

Для Kubernetes сучасні hardening baselines є більш вимогливими, ніж досі припускають багато операторів. Вбудовані **Pod Security Standards** вважають `restricted` профілем "current best practice": `allowPrivilegeEscalation` має бути `false`, workloads повинні працювати як non-root, seccomp має бути явно встановлений у `RuntimeDefault` або `Localhost`, а capability sets слід агресивно видаляти. Під час оцінювання це важливо, оскільки cluster, що використовує лише labels `warn` або `audit`, може виглядати hardened на папері, водночас фактично дозволяючи створення небезпечних pods.

## Сучасні Triage Questions

Перш ніж переходити до сторінок, присвячених escape, дайте відповіді на ці короткі запитання:

1. Чи є workload **rootful**, **rootless** або **userns-remapped**?
2. Чи використовує node **cgroup v1** або **cgroup v2**?
3. Чи явно налаштовані **seccomp** і **AppArmor/SELinux**, чи вони лише успадковуються, коли доступні?
4. У Kubernetes namespace фактично **enforcing** `baseline` або `restricted`, чи лише видає попередження/виконує auditing?

Корисні перевірки:
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
Що тут є цікавого:

- Якщо `/proc/self/uid_map` показує, що root у контейнері зіставлено з **високим діапазоном UID на host**, багато старих матеріалів про запис від імені host-root стають менш актуальними, оскільки root у контейнері більше не є еквівалентом host-root.
- Якщо `/sys/fs/cgroup` має тип `cgroup2fs`, старі матеріали, специфічні для **cgroup v1**, наприклад зловживання `release_agent`, більше не мають бути вашою першою версією.
- Якщо seccomp і AppArmor лише неявно успадковуються, portability може бути слабшою, ніж очікують defenders. У Kubernetes явне встановлення `RuntimeDefault` часто є надійнішим, ніж непомітна залежність від defaults вузла.
- Якщо `supplementalGroupsPolicy` встановлено в `Strict`, pod не повинен непомітно успадковувати додаткові членства в групах із `/etc/group` усередині image, що робить поведінку доступу до volume і файлів на основі груп більш передбачуваною.
- Labels namespace, такі як `pod-security.kubernetes.io/enforce=restricted`, варто перевіряти безпосередньо. `warn` і `audit` корисні, але вони не перешкоджають створенню risky pod.

## Первинний аналіз Runtime Baseline

Runtime baseline — це швидка перевірка, яка показує, чи виглядає контейнер як звичайне ізольоване workload, чи як foothold у control plane, що може впливати на host. Вона має зібрати достатньо фактів, щоб визначити пріоритет наступного напряму перевірки: зловживання runtime socket, mounts host, namespaces, cgroups, capabilities або review секретів image.

Корисні перевірки зсередини workload:
```bash
id
hostname
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/uid_map 2>/dev/null
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
readlink /proc/self/ns/{pid,mnt,net,ipc,cgroup,user} 2>/dev/null
mount
find /run /var/run -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Інтерпретація:

- Відсутнє або необмежене значення `memory.max` / `pids.max` вказує на слабкий контроль радіуса ураження навіть без повноцінного escape.
- Root shell із `NoNewPrivs: 0`, широкими capabilities і permissive seccomp набагато цікавіший за вузьке non-root workload.
- Runtime sockets і доступні для запису host mounts зазвичай мають вищий пріоритет за kernel exploits, оскільки вони вже відкривають шлях до керування або доступу до файлової системи.
- Shared PID, network, IPC або cgroup namespaces не завжди самі по собі забезпечують повний escape, але спрощують пошук наступного кроку.

## Приклади виснаження ресурсів

Обмеження ресурсів не є чимось захопливим, але вони є частиною container security, оскільки обмежують радіус ураження після compromise. Без обмежень пам’яті, CPU або PID простого shell може бути достатньо, щоб погіршити роботу host або сусідніх workloads.

Приклади тестів, що впливають на host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Ці приклади корисні, оскільки показують, що не кожен небезпечний результат роботи контейнера є чистим "escape". Слабкі обмеження cgroup все одно можуть перетворити виконання коду на реальний операційний вплив.

У середовищах на базі Kubernetes також перевіряйте, чи існують засоби контролю ресурсів узагалі, перш ніж вважати DoS теоретичною загрозою:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Інструменти hardening

Для середовищ, орієнтованих на Docker, `docker-bench-security` залишається корисною базовою перевіркою на стороні хоста, оскільки виявляє поширені проблеми конфігурації відповідно до загальновизнаних рекомендацій benchmark:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Цей інструмент не замінює threat modeling, але він залишається корисним для виявлення недбалих daemon, mount, network і runtime налаштувань за замовчуванням, які накопичуються з часом.

Для Kubernetes і середовищ із активним використанням runtime поєднуйте статичні перевірки з visibility під час роботи:

- `Tracee` корисний для runtime-виявлення з урахуванням контейнерів і швидкої forensics, коли потрібно підтвердити, до чого саме отримало доступ compromised workload.
- `Inspektor Gadget` корисний, коли під час assessment потрібна telemetry на рівні kernel, зіставлена з pods, containers, DNS activity, виконанням файлів або network behavior.

## Перевірки

Використовуйте їх як команди для швидкої первинної перевірки під час assessment:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Що тут є цікавого:

- Процес root із широкими capabilities та `Seccomp: 0` заслуговує на негайну увагу.
- Процес root, який також має **мапу UID 1:1**, набагато цікавіший за «root» усередині належним чином ізольованого user namespace.
- `cgroup2fs` зазвичай означає, що багато старіших ланцюжків escape через **cgroup v1** не є найкращою відправною точкою, тоді як відсутність `memory.max` або `pids.max` усе ще вказує на слабкий контроль радіуса ураження.
- Підозрілі mounts і runtime sockets часто забезпечують швидший шлях до впливу, ніж будь-який kernel exploit.
- Поєднання слабкої конфігурації runtime та слабких обмежень ресурсів зазвичай вказує на загалом permissive container environment, а не на одну ізольовану помилку.

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
