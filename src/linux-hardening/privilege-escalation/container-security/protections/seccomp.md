# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Огляд

**seccomp** — це механізм, який дозволяє ядру застосовувати фільтр до syscalls, які може викликати процес. У контейнеризованих середовищах seccomp зазвичай використовується в режимі фільтрації, щоб процес не просто відмічався як "restricted" в абстрактному сенсі, а підлягав конкретній політиці щодо syscall. Це має значення, бо багато escape'ів з контейнера потребують доступу до дуже конкретних інтерфейсів ядра. Якщо процес не може успішно викликати відповідні syscalls, велика категорія атак зникає до того, як нюанси namespaces або capabilities стають релевантними.

Ключова ментальна модель проста: namespaces вирішують **що процес може бачити**, capabilities вирішують **які привілейовані дії процес номінально може намагатися виконати**, а seccomp вирішує **чи ядро взагалі прийме syscall-точку входу для намагаємогося виконати діяння**. Саме тому seccomp часто запобігає атакам, які інакше виглядали б можливими, ґрунтуючись лише на capabilities.

## Вплив на безпеку

Багато небезпечної поверхні ядра доступні лише через відносно невеликий набір syscalls. Приклади, що постійно мають значення при зміцненні контейнерів, включають `mount`, `unshare`, `clone` або `clone3` з певними прапорами, `bpf`, `ptrace`, `keyctl` та `perf_event_open`. Атакуючий, який може досягти цих syscalls, може створювати нові namespaces, маніпулювати підсистемами ядра або взаємодіяти з поверхнею атаки, яка звичайному прикладному контейнеру зовсім не потрібна.

Саме тому стандартні runtime seccomp профілі такі важливі. Вони не просто "додатковий захист". У багатьох середовищах вони є різницею між контейнером, який може використовувати велику частину функціоналу ядра, і тим, який обмежений до syscall-поверхні, ближчої до того, що дійсно потрібно додатку.

## Режими та побудова фільтрів

seccomp історично мав strict режим, у якому залишався доступним лише крихітний набір syscall, але режим, релевантний для сучасних runtime контейнерів, — це seccomp filter mode, часто званий **seccomp-bpf**. У цій моделі ядро оцінює програму-фільтр, яка вирішує, чи слід дозволити syscall, відхилити його з errno, перехопити (trap), логувати або завершити процес. Container runtimes використовують цей механізм, бо він достатньо виразний, щоб блокувати широкі категорії небезпечних syscalls, одночасно дозволяючи нормальну поведінку додатка.

Два низькорівневі приклади корисні, бо роблять механізм конкретним, а не магічним. Strict режим демонструє стару модель "залишаються лише мінімальні syscalls":
```c
#include <fcntl.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(void) {
int output = open("output.txt", O_WRONLY);
const char *val = "test";
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
write(output, val, strlen(val) + 1);
open("output.txt", O_RDONLY);
}
```
Останній `open` призводить до завершення процесу, оскільки він не входить до мінімального набору strict mode.

Приклад фільтра libseccomp більш чітко демонструє сучасну модель політики:
```c
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));
seccomp_load(ctx);
seccomp_release(ctx);
printf("pid=%d\n", getpid());
}
```
Цей стиль політики — те, що більшість читачів уявляють, коли думають про runtime seccomp profiles.

## Лабораторна робота

Простий спосіб підтвердити, що seccomp активний у контейнері, — такий:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Ви також можете спробувати операцію, яку профілі за замовчуванням зазвичай обмежують:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Якщо контейнер працює під типовим профілем seccomp за замовчуванням, операції типу `unshare` часто блокуються. Це корисна демонстрація, оскільки показує, що навіть якщо userspace-утиліта є всередині образу, необхідний kernel-шлях може бути недоступним.
Якщо контейнер працює під типовим профілем seccomp за замовчуванням, операції типу `unshare` часто блокуються навіть коли userspace-інструмент присутній в образі.

Щоб загалом перевірити статус процесу, виконайте:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Використання під час виконання

Docker підтримує як дефолтні, так і кастомні профілі seccomp і дозволяє адміністраторам відключати їх за допомогою `--security-opt seccomp=unconfined`. Podman має аналогічну підтримку і часто поєднує seccomp із безпривілейним виконанням (rootless) у доцільній конфігурації за замовчуванням. Kubernetes надає доступ до seccomp через конфігурацію робочого навантаження, де `RuntimeDefault` зазвичай є адекватною базовою конфігурацією, а `Unconfined` слід розглядати як виняток, що потребує обґрунтування, а не як зручний перемикач.

У середовищах на базі containerd та CRI-O конкретний шлях більш багаторівневий, але принцип той самий: вищий рівень — движок або оркестратор — вирішує, що має статися, а runtime врешті встановлює відповідну політику seccomp для процесу контейнера. Результат усе одно залежить від остаточної конфігурації runtime, яка доходить до ядра.

### Custom Policy Example

Docker та схожі движки можуть завантажувати кастомний профіль seccomp з JSON. Мінімальний приклад, який забороняє `chmod`, дозволяючи все інше, виглядає так:
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
Застосовано за допомогою:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
Команда завершується з помилкою `Operation not permitted`, що демонструє, що обмеження походить від політики syscall, а не лише від звичайних файлових прав. У реальному підсиленні безпеки allowlists зазвичай сильніші за дозволяючі значення за замовчуванням із невеликим blacklist.

## Неправильні конфігурації

Найбільш груба помилка — встановити seccomp у **unconfined** через те, що застосунок зламався під стандартною політикою. Це часто трапляється під час налагодження і дуже небезпечно як постійне рішення. Як тільки фільтр зникає, багато примітивів ескапу на основі syscall знову стають досяжними, особливо коли також присутні потужні capabilities або спільне використання host namespace.

Ще однією частою проблемою є використання **custom permissive profile**, скопійованого з якогось блогу або внутрішнього тимчасового рішення без ретельного перегляду. Команди інколи зберігають майже всі небезпечні syscalls просто тому, що профіль було побудовано навколо «не допустити, щоб застосунок ламається», а не «надавати лише те, що застосунку дійсно потрібно». Третя помилкова думка — вважати, що seccomp менш важливий для контейнерів без root. Насправді значна поверхня атаки ядра залишається релевантною навіть коли процес не має UID 0.

## Зловживання

Якщо seccomp відсутній або сильно послаблений, нападник може викликати syscalls для створення namespace, розширити досяжну поверхню атаки ядра через `bpf` або `perf_event_open`, зловживати `keyctl` або комбінувати ці шляхи syscall із небезпечними capabilities, такими як `CAP_SYS_ADMIN`. У багатьох реальних атаках seccomp не є єдиним відсутнім контролем, але його відсутність драматично скорочує шлях експлойту, оскільки прибирає один із небагатьох захистів, який може зупинити ризиковий syscall перш ніж інша частина моделі привілеїв вступить у дію.

Найкорисніший практичний тест — спробувати саме ті сімейства syscall, які профілі за замовчуванням зазвичай блокують. Якщо вони раптом працюють, постава контейнера значно змінилася:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Якщо присутній `CAP_SYS_ADMIN` або інша сильна capability, перевірте, чи seccomp є єдиною відсутньою перешкодою перед mount-based abuse:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
На деяких цілях безпосередньою метою є не повний escape, а збір інформації та kernel attack-surface expansion. Ці команди допомагають визначити, чи доступні особливо чутливі syscall paths:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Якщо seccomp відсутній і контейнер також має додаткові привілеї, саме тоді має сенс pivot до більш специфічних breakout techniques, які вже задокументовані на legacy container-escape pages.

### Повний приклад: seccomp був єдиною перешкодою для `unshare`

На багатьох цілях практичний ефект видалення seccomp полягає в тому, що namespace-creation або mount syscalls раптово починають працювати. Якщо контейнер також має `CAP_SYS_ADMIN`, може стати можливим наступний порядок дій:
```bash
grep Seccomp /proc/self/status
capsh --print | grep cap_sys_admin
mkdir -p /tmp/nsroot
unshare -m sh -c '
mount -t tmpfs tmpfs /tmp/nsroot &&
mkdir -p /tmp/nsroot/proc &&
mount -t proc proc /tmp/nsroot/proc &&
mount | grep /tmp/nsroot
'
```
Саме по собі це ще не є host escape, але демонструє, що seccomp був бар'єром, який запобігав mount-related exploitation.

### Повний приклад: seccomp вимкнено + cgroup v1 `release_agent`

Якщо seccomp вимкнено і container може mount cgroup v1 hierarchies, техніка `release_agent` з розділу cgroups стає доступною:
```bash
grep Seccomp /proc/self/status
mount | grep cgroup
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
Це не експлойт виключно для seccomp. Суть у тому, що щойно seccomp перестане діяти, syscall-heavy breakout chains, які раніше були заблоковані, можуть почати працювати точно так, як написано.

## Перевірки

Мета цих перевірок — з'ясувати, чи взагалі активний seccomp, чи супроводжується він `no_new_privs`, і чи показує runtime конфігурація, що seccomp явно відключено.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Цікаве тут:

- Ненульове значення `Seccomp` означає, що фільтрація активна; `0` зазвичай означає відсутність захисту seccomp.
- Якщо в параметрах безпеки runtime вказано `seccomp=unconfined`, робоче навантаження втрачає один із найкорисніших захистів на рівні syscall.
- `NoNewPrivs` сам по собі не є seccomp, але їх наявність разом зазвичай свідчить про більш ретельну політику hardening, ніж коли обидва відсутні.

Якщо контейнер уже має підозрілі mounts, широкі capabilities або shared host namespaces, і seccomp також unconfined, таке поєднання слід розглядати як серйозний сигнал ескалації. Контейнер може й досі не бути легко зламаним, але кількість точок входу в kernel, доступних зловмиснику, різко зросла.

## Налаштування runtime за замовчуванням

| Runtime / platform | Стан за замовчуванням | Поведінка за замовчуванням | Типові ручні послаблення |
| --- | --- | --- | --- |
| Docker Engine | Зазвичай увімкнено за замовчуванням | Використовує вбудований профіль seccomp Docker за замовчуванням, якщо його не перевизначено | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Зазвичай увімкнено за замовчуванням | Застосовує профіль seccomp за замовчуванням runtime, якщо не перевизначено | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Не гарантовано за замовчуванням** | Якщо `securityContext.seccompProfile` не встановлено, значення за замовчуванням — `Unconfined`, якщо kubelet не увімкнув `--seccomp-default`; інакше `RuntimeDefault` або `Localhost` мають бути явно вказані | `securityContext.seccompProfile.type: Unconfined`, залишення seccomp невстановленим у кластерах без `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Дотримується налаштувань вузла Kubernetes та Pod | Профіль runtime використовується, коли Kubernetes запитує `RuntimeDefault` або коли увімкнено kubelet `--seccomp-default` | Те саме, що й у рядку Kubernetes; пряма конфігурація CRI/OCI також може повністю опустити seccomp |

Поведінка Kubernetes — та, яка найчастіше дивує операторів. У багатьох кластерах seccomp відсутній, якщо Pod не запитує його або kubelet не налаштовано за замовчуванням на `RuntimeDefault`.
