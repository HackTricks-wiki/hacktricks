# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Огляд

**seccomp** — це механізм, який дозволяє kernel застосовувати фільтр до syscalls, які процес може викликати. У контейнеризованих середовищах seccomp звично використовується в режимі фільтрації, щоб процес не просто позначався як «обмежений» у загальному сенсі, а підпадав під конкретну політику syscalls. Це важливо, бо багато виходів з контейнера вимагають доступу до дуже конкретних інтерфейсів kernel. Якщо процес не може успішно викликати відповідні syscalls, велика категорія атак зникає ще до того, як будь-які нюанси namespaces або capabilities стануть релевантними.

Ключова ментальна модель проста: namespaces вирішують **що процес може бачити**, capabilities вирішують **які привілейовані дії процес формально може намагатися виконати**, а seccomp вирішує **чи взагалі kernel прийме syscall як точку входу для намагаючоїся виконати дію**. Саме тому seccomp часто запобігає атакам, які б інакше здавалися можливими, виходячи лише з capabilities.

## Вплив на безпеку

Багато небезпечної поверхні kernel доступне лише через відносно невеликий набір syscalls. Приклади, що регулярно мають значення при hardening container, включають `mount`, `unshare`, `clone` або `clone3` з певними flags, `bpf`, `ptrace`, `keyctl` та `perf_event_open`. Зловмисник, який може досягти цих syscalls, може створити нові namespaces, маніпулювати підсистемами kernel або взаємодіяти з атакувальною поверхнею, яка звичайному application container узагалі не потрібна.

Ось чому стандартні runtime seccomp profiles такі важливі. Вони не просто «додатковий захист». У багатьох середовищах вони є різницею між контейнером, який може використовувати широку частину функціональності kernel, і тим, що обмежений до набору syscalls ближче до того, що дійсно потрібно application.

## Режими та побудова фільтра

seccomp історично мав strict режим, у якому залишався доступним лише крихітний набір syscalls, але режим, релевантний для сучасних container runtimes — це seccomp filter mode, часто званий **seccomp-bpf**. У цій моделі kernel оцінює програму-фільтр, яка вирішує, чи syscall має бути дозволений, відхилений з errno, перехоплений, записаний у лог або призвести до завершення процесу. Container runtimes використовують цей механізм, бо він достатньо виразний, щоб блокувати широкі класи небезпечних syscalls, одночасно дозволяючи нормальну поведінку application.

Два низькорівневі приклади корисні, бо роблять механізм конкретним, а не магічним. Strict mode демонструє стару модель «залишається лише мінімальний набір syscalls»:
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
Остаточний `open` призводить до завершення процесу, оскільки він не входить до мінімального набору strict mode.

Приклад фільтра libseccomp більш наочно показує сучасну модель політик:
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
Такий стиль політики — те, що більшість читачів уявляють, коли думають про runtime seccomp profiles.

## Lab

Простий спосіб підтвердити, що seccomp активний у container — це:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Ви також можете спробувати операцію, яку профілі за замовчуванням зазвичай обмежують:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Якщо контейнер працює під звичайним профілем seccomp за замовчуванням, операції типу `unshare` часто блокуються. Це корисна демонстрація, оскільки показує, що навіть якщо userspace tool існує всередині образу, шлях в ядрі, який їй потрібен, може залишатися недоступним.
Якщо контейнер працює під звичайним профілем seccomp за замовчуванням, операції типу `unshare` часто блокуються навіть коли userspace tool існує всередині образу.

Щоб більш загально перевірити стан процесу, виконайте:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Використання під час виконання

Docker підтримує як стандартні, так і власні профілі seccomp і дозволяє адміністраторам вимикати їх за допомогою `--security-opt seccomp=unconfined`. Podman має подібну підтримку і часто поєднує seccomp із rootless execution у дуже розумній конфігурації за замовчуванням. Kubernetes надає доступ до seccomp через конфігурацію workload, де `RuntimeDefault` зазвичай є розумною початковою точкою, а `Unconfined` слід розглядати як виняток, що вимагає обґрунтування, а не як зручний перемикач.

У середовищах на основі containerd та CRI-O точний шлях більш багатошаровий, але принцип той самий: вищий за рівнем engine або orchestrator вирішує, що має відбутися, а runtime врешті інсталює отриману seccomp політику для процесу контейнера. Результат все одно залежить від остаточної конфігурації runtime, яка доходить до ядра.

### Приклад власної політики

Docker та подібні engines можуть завантажувати кастомний seccomp профіль з JSON. Мінімальний приклад, що забороняє `chmod`, дозволяючи все інше, виглядає так:
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
Команда завершується з помилкою `Operation not permitted`, що демонструє, що обмеження походить від політики syscall, а не лише від звичайних файлових прав. У реальному hardening allowlists зазвичай є суворішими, ніж пом'якшені налаштування за замовчуванням, з невеликим blacklist.

## Неправильні налаштування

Найгрубіша помилка — встановити seccomp в **unconfined** через те, що додаток не працював під стандартною політикою. Це поширено під час troubleshooting і дуже небезпечно як постійне рішення. Коли фільтр зникає, багато примітивів ескейпу на основі syscall знову стають досяжними, особливо якщо також присутні потужні capabilities або спільне використання host namespace.

Ще одна часта проблема — використання **custom permissive profile**, який було скопійовано з якогось блогу або внутрішнього workaround без ретельного рев'ю. Команди іноді зберігають майже всі небезпечні syscalls просто тому, що профіль був побудований навколо «не допустити, щоб додаток ламався», а не «надати тільки те, що додаток справді потребує». Третє хибне припущення — вважати, що seccomp менш важливий для non-root контейнерів. Насправді багато kernel attack surface залишається релевантним навіть коли процес не має UID 0.

## Зловживання

Якщо seccomp відсутній або суттєво послаблений, атакуючий може викликати namespace-creation syscalls, розширити досяжний kernel attack surface через `bpf` або `perf_event_open`, зловживати `keyctl`, або поєднувати ці syscall-шляхи з небезпечними capabilities, такими як `CAP_SYS_ADMIN`. У багатьох реальних атаках seccomp не є єдиним відсутнім контролем, але його відсутність значно скорочує шлях експлойту, бо вона усуває один із небагатьох захистів, що можуть зупинити ризиковий syscall ще до того, як решта моделі привілеїв вступить у дію.

Найкорисніший практичний тест — спробувати ті саме сімейства syscall, які стандартні профілі зазвичай блокують. Якщо вони раптом працюють, безпековий стан контейнера суттєво змінився:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Якщо присутній `CAP_SYS_ADMIN` або інша сильна capability, перевірте, чи seccomp є єдиним відсутнім бар'єром перед mount-based abuse:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
На деяких targets безпосередня цінність полягає не в повному escape, а в information gathering і розширенні kernel attack-surface. Ці команди допомагають визначити, чи особливо чутливі syscall paths доступні:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Якщо seccomp відсутній і container також має інші привілеї, саме тоді має сенс перейти до більш конкретних breakout techniques, які вже задокументовані на legacy container-escape pages.

### Повний приклад: seccomp був єдиним, що блокував `unshare`

На багатьох цілях практичний ефект видалення seccomp полягає в тому, що namespace-creation або mount syscalls раптово починають працювати. Якщо container також має `CAP_SYS_ADMIN`, наступна послідовність може стати можливою:
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
Саме по собі це ще не є host escape, але демонструє, що seccomp був бар'єром, який запобігав експлуатаціям, пов'язаним з mount.

### Повний приклад: seccomp вимкнено + cgroup v1 `release_agent`

Якщо seccomp вимкнено і container може mount ієрархії cgroup v1, техніка `release_agent` з розділу cgroups стає доступною:
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
Це не exploit, який залежить лише від seccomp. Суть у тому, що як тільки seccomp перестане бути обмеженим, syscall-heavy breakout chains, які раніше були заблоковані, можуть почати працювати точно так, як написано.

## Перевірки

Мета цих перевірок — встановити, чи seccomp взагалі активний, чи супроводжується він `no_new_privs`, та чи показує конфігурація середовища виконання, що seccomp явно вимкнений.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Цікаве тут:

- Ненульове значення `Seccomp` означає, що фільтрація активна; `0` зазвичай означає відсутність захисту seccomp.
- Якщо опції безпеки runtime включають `seccomp=unconfined`, робоче навантаження втратило одну з найкорисніших захисних ліній на рівні syscall.
- `NoNewPrivs` сам по собі не є seccomp, але спільна наявність обох зазвичай вказує на більш обережну hardening posture, ніж відсутність обох.

Якщо контейнер вже має підозрілі mounts, широкі capabilities або shared host namespaces, і seccomp також unconfined, таке поєднання слід розглядати як серйозний сигнал ескалації. Контейнер може все ще не бути trivially breakable, але кількість kernel entry points, доступних атакувальнику, різко зросла.

## Налаштування середовища виконання за замовчуванням

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Зазвичай увімкнено за замовчуванням | Використовує вбудований у Docker профіль seccomp за замовчуванням, якщо його не перевизначено | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Зазвичай увімкнено за замовчуванням | Застосовує runtime профіль seccomp за замовчуванням, якщо його не перевизначено | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Не гарантується за замовчуванням** | Якщо `securityContext.seccompProfile` не встановлено, за замовчуванням використовується `Unconfined`, якщо kubelet не ввімкне `--seccomp-default`; інакше потрібно явно вказати `RuntimeDefault` або `Localhost` | `securityContext.seccompProfile.type: Unconfined`, залишаючи seccomp unset на кластерах без `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Дотримується налаштувань вузла та Pod у Kubernetes | Runtime профіль використовується, коли Kubernetes запитує `RuntimeDefault` або коли на вузлі ввімкнено kubelet seccomp defaulting | Те ж, що і для Kubernetes; пряма конфігурація CRI/OCI також може повністю опустити seccomp |

Поведінка Kubernetes — це те, що найчастіше дивує операторів. У багатьох кластерах seccomp все ще відсутній, якщо Pod не запитує його або kubelet не налаштовано за замовчуванням на `RuntimeDefault`.
{{#include ../../../../banners/hacktricks-training.md}}
