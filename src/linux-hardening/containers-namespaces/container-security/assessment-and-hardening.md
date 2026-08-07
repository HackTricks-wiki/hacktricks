# Оцінювання та hardening

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Якісне оцінювання контейнера має дати відповіді на два паралельні запитання. По-перше, що може зробити атакер із поточного workload? По-друге, які рішення оператора зробили це можливим? Інструменти enumeration допомагають із першим запитанням, а рекомендації з hardening — із другим. Розміщення обох аспектів на одній сторінці робить цей розділ кориснішим як польовий довідник, а не просто каталог escape-трюків.

Одне практичне уточнення для сучасних середовищ полягає в тому, що багато старих описів контейнерів мовчки припускають **rootful runtime**, **відсутність ізоляції user namespace** і часто **cgroup v1**. Ці припущення більше не є безпечними. Перш ніж витрачати час на старі escape-примітиви, спочатку перевірте, чи є workload rootless або userns-remapped, чи використовує host cgroup v2, а також чи застосовують Kubernetes або runtime стандартні профілі seccomp та AppArmor. Ці деталі часто визначають, чи все ще актуальний відомий breakout.

## Інструменти enumeration

Кілька інструментів залишаються корисними для швидкої характеристики середовища контейнера:

- `linpeas` може виявити багато індикаторів контейнера, змонтовані сокети, набори capabilities, небезпечні файлові системи та ознаки breakout.
- `CDK` спеціально орієнтований на середовища контейнерів і містить enumeration, а також деякі автоматизовані перевірки escape.
- `amicontained` є легким інструментом і корисний для визначення обмежень контейнера, capabilities, доступності namespace та ймовірних класів breakout.
- `deepce` — ще один enumerator, орієнтований на контейнери, із перевірками, пов’язаними з breakout.
- `grype` корисний, коли оцінювання включає перевірку вразливостей пакетів образу, а не лише аналіз runtime escape.
- `Tracee` корисний, коли потрібні **докази під час виконання**, а не лише статичний стан захисту, особливо для підозрілого запуску процесів, доступу до файлів і збору подій із прив’язкою до контейнерів.
- `Inspektor Gadget` корисний під час розслідувань у Kubernetes і на Linux-host, коли потрібна видимість на основі eBPF із прив’язкою до pod, контейнерів, namespace та інших понять вищого рівня.

Цінність цих інструментів полягає у швидкості та охопленні, а не в абсолютній достовірності. Вони допомагають швидко виявити загальний стан захисту, але цікаві результати все одно потребують ручної інтерпретації з урахуванням фактичної моделі runtime, namespace, capabilities та mount.

## Пріоритети hardening

Найважливіші принципи hardening концептуально прості, хоча їхня реалізація залежить від платформи. Уникайте privileged-контейнерів. Не монтуйте runtime-сокети. Не надавайте контейнерам доступ на запис до шляхів host, якщо для цього немає конкретної причини. Використовуйте user namespace або rootless execution, де це можливо. Видаляйте всі capabilities і повертайте лише ті, які справді потрібні workload. Не вимикайте seccomp, AppArmor і SELinux, щоб виправляти проблеми сумісності застосунків. Обмежуйте ресурси, щоб скомпрометований контейнер не міг тривіально спричинити відмову в обслуговуванні host.

Гігієна образів і процесу build має таке саме значення, як і стан runtime. Використовуйте мінімальні образи, часто перебудовуйте їх, скануйте їх, де практично можливо, вимагайте provenance і не зберігайте секрети в шарах. Контейнер, який працює не від root, використовує невеликий образ і має вузьку поверхню syscall та capabilities, значно легше захистити, ніж великий зручний образ, що працює з root, еквівалентним root на host, і містить попередньо встановлені debugging-інструменти.

Для Kubernetes сучасні базові вимоги до hardening є більш категоричними, ніж досі припускають багато операторів. Вбудовані **Pod Security Standards** визначають `restricted` як профіль "поточна найкраща практика": `allowPrivilegeEscalation` має бути `false`, workload має працювати не від root, seccomp слід явно встановлювати в `RuntimeDefault` або `Localhost`, а набори capabilities потрібно агресивно скорочувати. Під час оцінювання це важливо, оскільки кластер, що використовує лише мітки `warn` або `audit`, може виглядати захищеним на папері, але на практиці все ще допускати ризиковані pod.<sup>[[1]](#references)</sup>

## Сучасні запитання для triage

Перш ніж переходити до сторінок, присвячених escape, дайте відповіді на ці короткі запитання:

1. Чи є workload **rootful**, **rootless** або **userns-remapped**?
2. Чи використовує node **cgroup v1** або **cgroup v2**?
3. Чи явно налаштовані **seccomp** і **AppArmor/SELinux**, чи вони лише успадковуються, коли доступні?
4. У Kubernetes namespace справді **enforcing** для `baseline` або `restricted`, чи він лише попереджає/аудитує?

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
Що тут цікавого:

- Якщо `/proc/self/uid_map` показує, що root контейнера зіставлений із **діапазоном високих UID на host**, багато старих writeup'ів про запис від імені root на host стають менш актуальними, оскільки root у контейнері більше не є еквівалентом root на host.
- Якщо `/sys/fs/cgroup` має тип `cgroup2fs`, старі writeup'и, специфічні для **cgroup v1**, як-от зловживання `release_agent`, більше не повинні бути вашою першою здогадкою.
- Якщо seccomp і AppArmor лише неявно успадковуються, portability може бути слабшою, ніж очікують defenders. У Kubernetes явне встановлення `RuntimeDefault` часто надійніше, ніж непомітна залежність від defaults node.
- Якщо `supplementalGroupsPolicy` встановлено в `Strict`, pod не повинен непомітно успадковувати додаткові членства в групах із `/etc/group` усередині image, що робить поведінку доступу до volume і файлів на основі груп більш передбачуваною.
- Labels namespace, як-от `pod-security.kubernetes.io/enforce=restricted`, варто перевіряти безпосередньо. `warn` і `audit` корисні, але вони не зупиняють створення risky pod.

## Первинна перевірка baseline runtime

Runtime baseline — це швидка перевірка, яка показує, чи схожий container на звичайне ізольоване workload, чи на foothold у control plane, що впливає на host. Вона повинна зібрати достатньо фактів, щоб визначити пріоритет наступної перевірки: зловживання runtime socket, mounts host, namespaces, cgroups, capabilities або review secrets image.

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
Тлумачення:

- Відсутність або необмежені значення `memory.max` / `pids.max` вказують на слабкий контроль радіуса ураження навіть без повноцінного escape.
- Root shell із `NoNewPrivs: 0`, широкими capabilities і permissive seccomp значно цікавіший за вузьке non-root workload.
- Runtime sockets і writable host mounts зазвичай мають вищий пріоритет, ніж kernel exploits, оскільки вони вже надають шлях до керування або доступу до файлової системи.
- Shared PID, network, IPC або cgroup namespaces не завжди самі по собі забезпечують повний escape, але спрощують пошук наступного кроку.

## Приклади вичерпання ресурсів

Resource controls не є ефектними, але вони є частиною container security, оскільки обмежують радіус ураження після компрометації. Без обмежень для memory, CPU або PID простого shell може бути достатньо, щоб погіршити роботу host або сусідніх workloads.

Приклади тестів, що впливають на host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Ці приклади корисні, оскільки показують, що не кожен небезпечний результат роботи контейнера є чистим "escape". Слабкі обмеження cgroup все одно можуть перетворити виконання коду на реальний операційний вплив.

У середовищах на базі Kubernetes також перевіряйте, чи існують взагалі обмеження ресурсів, перш ніж вважати DoS теоретичною загрозою:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Інструменти для hardening

Для середовищ, орієнтованих на Docker, `docker-bench-security` залишається корисним базовим рівнем хостового аудиту, оскільки перевіряє поширені проблеми конфігурації відповідно до загальновизнаних рекомендацій бенчмарків:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Інструмент не є заміною threat modeling, але він усе ще корисний для виявлення недбалих daemon, mount, network і runtime налаштувань за замовчуванням, які з часом накопичуються.

Для Kubernetes і середовищ із активним використанням runtime поєднуйте статичні перевірки з видимістю runtime:

- `Tracee` корисний для runtime-виявлення з урахуванням контейнерів і швидкого forensics, коли потрібно підтвердити, до чого насправді отримало доступ скомпрометоване workload.
- `Inspektor Gadget` корисний, коли під час assessment потрібна телеметрія на рівні kernel, зіставлена з pods, containers, DNS-активністю, виконанням файлів або мережевою поведінкою.

## Перевірки

Використовуйте їх як швидкі команди для первинної перевірки під час assessment:
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

- Процес root із широкими capabilities і `Seccomp: 0` заслуговує на негайну увагу.
- Процес root, який також має **1:1 UID map**, набагато цікавіший за "root" усередині належним чином ізольованого user namespace.
- `cgroup2fs` зазвичай означає, що багато старих ланцюжків escape через **cgroup v1** не є найкращою відправною точкою, тоді як відсутність `memory.max` або `pids.max` усе ще вказує на слабкий контроль радіуса ураження.
- Підозрілі mounts і runtime sockets часто забезпечують швидший шлях до впливу, ніж будь-який kernel exploit.
- Поєднання слабкої конфігурації runtime і слабких обмежень ресурсів зазвичай вказує на загалом permissive container environment, а не на одну ізольовану помилку.

## References

- [1] [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)

{{#include ../../../banners/hacktricks-training.md}}
