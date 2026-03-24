# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Огляд

**seccomp** — механізм, який дозволяє ядру застосовувати фільтр до syscalls, які процес може викликати. У контейнеризованих середовищах seccomp зазвичай використовується в режимі фільтра, тож процес не просто позначається як "restricted" у розмитому сенсі, а підпадає під конкретну політику щодо syscalls. Це важливо, бо багато виходів з контейнера вимагають доступу до дуже конкретних інтерфейсів ядра. Якщо процес не може успішно викликати відповідні syscalls, велика частина атак зникає ще до того, як будь-які нюанси namespace чи capability стануть релевантними.

Ключова ментальна модель проста: namespace вирішують **що процес може бачити**, capabilities вирішують **які привілейовані дії процес формально має право намагатися виконати**, а seccomp вирішує **чи ядро взагалі прийме точку входу syscall для спробуваної дії**. Саме тому seccomp часто перешкоджає атакам, що інакше здавалися б можливими, базуючись лише на capabilities.

## Вплив на безпеку

Багато небезпечної поверхні ядра доступні лише через відносно невеликий набір syscalls. Приклади, що постійно мають значення при hardening контейнерів, включають `mount`, `unshare`, `clone` або `clone3` з певними прапорами, `bpf`, `ptrace`, `keyctl` та `perf_event_open`. Зловмисник, який може отримати доступ до цих syscalls, може створювати нові namespaces, маніпулювати підсистемами ядра або взаємодіяти з attack surface, яка звичайному контейнеру додатку зовсім не потрібна.

Саме тому стандартні runtime seccomp профілі такі важливі. Вони не просто "extra defense". У багатьох середовищах вони становлять різницю між контейнером, який може використовувати широку частину функціональності ядра, і тим, що обмежений до syscall surface, ближчої до того, що дійсно потрібно додатку.

## Режими та побудова фільтра

Історично seccomp мав strict режим, в якому доступний був лише крихітний набір syscalls, але режим, що має значення для сучасних container runtimes, — це режим фільтра seccomp, часто званий **seccomp-bpf**. У цій моделі ядро виконує програму-фільтр, яка вирішує, чи syscall має бути дозволений, відхилений з errno, перехоплений, записаний у лог або завершити процес. Container runtimes використовують цей механізм, бо він достатньо виразний, щоб блокувати широкі класи небезпечних syscalls, при цьому дозволяючи нормальну поведінку додатка.

Два низькорівневих приклади корисні, бо вони роблять механізм конкретним, а не магічним. Strict режим демонструє стару модель «виживає лише мінімальний набір syscalls»:
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

Приклад фільтра libseccomp чіткіше демонструє сучасну модель політики:
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
Цей тип політики — саме те, що більшість читачів уявляють, коли думають про профілі seccomp під час виконання.

## Лаб

Простий спосіб підтвердити, що seccomp активний у контейнері, це:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Ви також можете спробувати операцію, яку профілі за замовчуванням зазвичай обмежують:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Якщо контейнер працює під звичайним профілем seccomp за замовчуванням, операції типу `unshare` часто блокуються. Це корисна демонстрація, оскільки показує, що навіть якщо userspace tool існує всередині image, потрібний kernel path може залишатися недоступним.

Якщо контейнер працює під звичайним профілем seccomp за замовчуванням, операції типу `unshare` часто блокуються навіть коли userspace tool існує всередині image.

Щоб загалом перевірити статус процесу, виконайте:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Використання під час виконання

Docker підтримує як стандартні, так і користувацькі профілі seccomp і дозволяє адміністраторам вимикати їх за допомогою `--security-opt seccomp=unconfined`. Podman має схожу підтримку і часто поєднує seccomp з безпривілейним (rootless) виконанням як розумні значення за замовчуванням. Kubernetes надає доступ до seccomp через конфігурацію робочих навантажень, де `RuntimeDefault` зазвичай є розумним базовим рівнем, а `Unconfined` слід розглядати як виняток, що вимагає обґрунтування, а не зручний перемикач.

У середовищах на базі containerd та CRI-O точний шлях є більш багаторівневим, але принцип той самий: вищестоящий рушій або оркестратор вирішує, що має статися, а runtime зрештою встановлює отриману seccomp-політику для процесу контейнера. Результат усе ще залежить від фінальної конфігурації runtime, яка доходить до kernel.

### Приклад користувацької політики

Docker та подібні рушії можуть завантажувати користувацький профіль seccomp з JSON. Мінімальний приклад, який забороняє `chmod`, але дозволяє все інше, виглядає так:
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
Команда завершується з `Operation not permitted`, що демонструє, що обмеження походить від політики syscall, а не лише від звичайних файлових прав. У реальному hardening allowlists зазвичай сильніші за permissive defaults з невеликою blacklist.

## Неправильні конфігурації

Найгрубішою помилкою є встановити seccomp у **unconfined** тому, що застосунок не працював під політикою за замовчуванням. Це часто трапляється під час усунення несправностей і надзвичайно небезпечно як постійне рішення. Коли фільтр зникне, багато примітивів для виходу на хост на основі syscalls знову стануть доступними, особливо якщо також присутні потужні capabilities або спільне використання host namespace.

Ще одна часта проблема — використання **custom permissive profile**, який було скопійовано з якогось блогу або внутрішнього обходу без ретельного перегляду. Команди іноді зберігають майже всі небезпечні syscalls лише тому, що профіль був побудований навколо «зупинити збій застосунку», а не «надавати лише те, що застосунку реально потрібно». Третє хибне уявлення — вважати, що seccomp менш важливий для non-root контейнерів. Насправді велика поверхня атаки ядра залишається релевантною навіть коли процес не має UID 0.

## Зловживання

Якщо seccomp відсутній або суттєво ослаблений, зловмисник може викликати syscalls для створення namespace, розширити досяжну kernel attack surface через `bpf` або `perf_event_open`, зловживати `keyctl`, або поєднати ці шляхи syscalls з небезпечними capabilities, такими як `CAP_SYS_ADMIN`. У багатьох реальних атаках seccomp не є єдиним відсутнім контролем, але його відсутність значно скорочує шлях експлойту, оскільки усуває один із небагатьох захистів, що можуть зупинити ризиковий syscall ще до того, як інша частина моделі привілеїв вступить у дію.

Найкорисніший практичний тест — спробувати саме ті сімейства syscalls, які стандартні профілі зазвичай блокують. Якщо вони раптом працюють, постава контейнера суттєво змінилася:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Якщо `CAP_SYS_ADMIN` або інша сильна capability присутня, перевірте, чи seccomp є єдиною відсутньою перешкодою перед mount-based abuse:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
На деяких targets негайна цінність полягає не в full escape, а в information gathering та kernel attack-surface expansion. Ці команди допомагають визначити, чи особливо чутливі syscall paths доступні:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Якщо seccomp відсутній, і контейнер також має інші привілеї, саме тоді має сенс переключитися на більш специфічні breakout techniques, які вже задокументовані на legacy container-escape pages.

### Повний приклад: seccomp був єдиною перешкодою для `unshare`

На багатьох цільових системах практичний ефект від вимкнення seccomp такий: namespace-creation або mount syscalls раптово починають працювати. Якщо контейнер також має `CAP_SYS_ADMIN`, наступна послідовність може стати можливою:
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
Саме по собі це ще не є host escape, але демонструє, що seccomp був бар'єром, який перешкоджав mount-related exploitation.

### Повний приклад: seccomp Disabled + cgroup v1 `release_agent`

Якщо seccomp вимкнено і контейнер може монтувати ієрархії cgroup v1, техніка `release_agent` з розділу cgroups стає доступною:
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
Це не експлойт лише для seccomp. Суть у тому, що як тільки seccomp перестає бути обмеженим, syscall-heavy breakout chains, які раніше блокувалися, можуть почати працювати точно так, як написано.

## Перевірки

Метою цих перевірок є з'ясувати, чи seccomp взагалі активний, чи супроводжується він `no_new_privs`, а також чи конфігурація runtime явно показує, що seccomp вимкнено.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
What is interesting here:

- Ненульове значення `Seccomp` означає, що фільтрація активна; `0` зазвичай означає відсутність seccomp-захисту.
- Якщо в параметрах runtime безпеки вказано `seccomp=unconfined`, workload втратив один із своїх найкорисніших захистів на рівні syscall.
- `NoNewPrivs` не є seccomp сам по собі, але поява обох разом зазвичай свідчить про більш ретельну позицію hardening, ніж коли їх немає.

Якщо container вже має підозрілі mounts, широкі capabilities або спільні host namespaces, і seccomp також unconfined, цю комбінацію слід розглядати як серйозний сигнал ескалації. Container може й далі не бути тривіально зламаним, але кількість точок входу в kernel, доступних атакуючому, різко зросла.

## Налаштування runtime за замовчуванням

| Runtime / platform | Стан за замовчуванням | Поведінка за замовчуванням | Типове ручне послаблення |
| --- | --- | --- | --- |
| Docker Engine | Зазвичай увімкнено за замовчуванням | Використовує вбудований стандартний seccomp profile Docker, якщо його не перевизначено | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Зазвичай увімкнено за замовчуванням | Застосовує runtime default seccomp profile, якщо його не перевизначено | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Не гарантовано за замовчуванням** | Якщо `securityContext.seccompProfile` не встановлено, значення за замовчуванням — `Unconfined`, якщо kubelet не вмикає `--seccomp-default`; інакше `RuntimeDefault` або `Localhost` повинні бути встановлені явно | `securityContext.seccompProfile.type: Unconfined`, залишення seccomp незадане в кластерах без `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Слідує налаштуванням вузла Kubernetes і Pod | Профіль runtime використовується, коли Kubernetes запитує `RuntimeDefault` або коли у kubelet ввімкнено встановлення seccomp за замовчуванням | Так само, як у рядку Kubernetes; пряма CRI/OCI конфігурація також може повністю опустити seccomp |

Поведінка Kubernetes — саме та, яка найчастіше дивує операторів. У багатьох кластерах seccomp все ще відсутній, якщо Pod не запитує його або kubelet не налаштовано встановлювати `RuntimeDefault` за замовчуванням.
{{#include ../../../../banners/hacktricks-training.md}}
