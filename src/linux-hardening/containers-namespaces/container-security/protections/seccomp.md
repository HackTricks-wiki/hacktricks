# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Огляд

**seccomp** — це механізм, який дає ядру змогу застосовувати фільтр до системних викликів, які може викликати процес. У контейнеризованих середовищах seccomp зазвичай використовується в режимі фільтрації, щоб процес не просто позначався як "обмежений" у нечіткому сенсі, а підпорядковувався конкретній політиці системних викликів. Це важливо, оскільки для багатьох container breakouts потрібно отримати доступ до дуже специфічних інтерфейсів ядра. Якщо процес не може успішно викликати відповідні системні виклики, значна частина атак зникає ще до того, як взагалі стають важливими нюанси просторів імен або capabilities.

Ключова модель проста: простори імен визначають, **що процес може бачити**, capabilities визначають, **які привілейовані дії процес номінально може спробувати виконати**, а seccomp визначає, **чи прийме ядро взагалі точку входу системного виклику для спробуваної дії**. Саме тому seccomp часто запобігає атакам, які інакше здавалися б можливими, якщо судити лише за capabilities.

## Вплив на безпеку

До значної частини небезпечної поверхні атаки ядра можна отримати доступ лише через відносно невеликий набір системних викликів. Приклади, які неодноразово мають значення для hardening контейнерів, включають `mount`, `unshare`, `clone` або `clone3` з певними flags, `bpf`, `ptrace`, `keyctl` і `perf_event_open`. Зловмисник, який може викликати ці системні виклики, може отримати змогу створювати нові простори імен, маніпулювати підсистемами ядра або взаємодіяти з поверхнею атаки, яка звичайному application container взагалі не потрібна.

Саме тому default seccomp profiles runtime-середовищ такі важливі. Це не просто "додатковий захист". У багатьох середовищах вони визначають різницю між контейнером, який може використовувати значну частину функціональності ядра, і контейнером, обмеженим поверхнею системних викликів, ближчою до тієї, яка справді потрібна application.

## Режими та побудова фільтрів

Історично seccomp мав strict mode, у якому доступним залишався лише дуже малий набір системних викликів, але для сучасних container runtimes актуальним є filter mode seccomp, який часто називають **seccomp-bpf**. У цій моделі ядро обчислює filter program, що визначає, чи слід дозволити системний виклик, відхилити його з errno, перехопити, записати в log або завершити процес. Container runtimes використовують цей механізм, оскільки він достатньо виразний для блокування широких класів небезпечних системних викликів і водночас дає змогу зберегти нормальну поведінку application.

Два приклади низькорівневої реалізації корисні, оскільки вони роблять механізм конкретним, а не магічним. Strict mode демонструє стару модель "виживає лише мінімальний набір системних викликів":
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
Фінальний виклик `open` спричиняє завершення процесу, оскільки він не входить до мінімального набору strict mode.

Приклад фільтра libseccomp чіткіше демонструє сучасну модель політик:
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
Цей стиль policy — саме те, що більшість читачів мають уявляти, коли думають про runtime seccomp profiles.

## Лабораторна робота

Простий спосіб підтвердити, що seccomp активний у container:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Також можна спробувати операцію, яку типові профілі за замовчуванням часто обмежують:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Якщо контейнер працює зі стандартним профілем seccomp за замовчуванням, операції на кшталт `unshare` часто блокуються. Це корисна демонстрація, оскільки показує: навіть якщо userspace-інструмент існує всередині image, потрібний йому kernel-шлях усе одно може бути недоступним.

Якщо контейнер працює зі стандартним профілем seccomp за замовчуванням, операції на кшталт `unshare` часто блокуються, навіть коли userspace-інструмент існує всередині image.

Щоб загалом перевірити стан процесу, виконайте:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Використання під час виконання

Docker підтримує як стандартні, так і custom seccomp profiles і дозволяє адміністраторам вимикати їх за допомогою `--security-opt seccomp=unconfined`. Podman має подібну підтримку й часто поєднує seccomp із rootless execution, що є дуже розумною позицією за замовчуванням. Kubernetes надає доступ до seccomp через конфігурацію workload, де `RuntimeDefault` зазвичай є розумною базовою конфігурацією, а `Unconfined` слід розглядати як виняток, що потребує обґрунтування, а не як зручний перемикач.

У середовищах на базі containerd і CRI-O точний шлях є більш багаторівневим, але принцип залишається тим самим: engine або orchestrator вищого рівня визначає, що має відбутися, а runtime зрештою встановлює отриману seccomp policy для процесу контейнера. Результат усе ще залежить від остаточної конфігурації runtime, яка досягає kernel.

### Приклад Custom Policy

Docker та подібні engines можуть завантажувати custom seccomp profile у форматі JSON. Мінімальний приклад, який забороняє `chmod`, дозволяючи все інше, виглядає так:
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
Застосовується з:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
Команда завершується помилкою `Operation not permitted`, демонструючи, що обмеження надходить від політики syscall, а не лише від звичайних дозволів на файли. У реальному hardening allowlist зазвичай надійніші за permissive defaults із невеликим blacklist.

## Misconfigurations

Найгрубша помилка — встановити seccomp у режим **unconfined**, оскільки застосунок не працював із політикою за замовчуванням. Це часто трапляється під час troubleshooting і є дуже небезпечним як постійне виправлення. Коли filter видалено, багато примітивів breakout на основі syscall знову стають доступними, особливо якщо водночас присутні потужні capabilities або спільне використання host namespace.

Інша поширена проблема — використання **custom permissive profile**, скопійованого з якогось блогу або внутрішнього workaround без ретельного review. Команди іноді залишають майже всі небезпечні syscall лише тому, що profile створювався з метою "не допустити поломки застосунку", а не "надати лише те, що застосунку справді потрібно". Третя помилкова думка — вважати, що seccomp менш важливий для non-root containers. Насправді значна частина attack surface kernel залишається актуальною, навіть якщо процес не має UID 0.

## Abuse

Якщо seccomp відсутній або суттєво послаблений, attacker може отримати можливість викликати syscall для створення namespace, розширити доступний attack surface kernel через `bpf` або `perf_event_open`, зловживати `keyctl` або поєднати ці syscall paths із небезпечними capabilities, такими як `CAP_SYS_ADMIN`. У багатьох реальних атаках seccomp — не єдиний відсутній контроль, але його відсутність суттєво скорочує exploit path, оскільки усуває один із небагатьох захисних механізмів, здатних заблокувати небезпечний syscall ще до того, як решта privilege model взагалі вступить у дію.

Найкорисніший практичний тест — спробувати саме ті syscall families, які зазвичай блокують default profiles. Якщо вони раптом працюють, security posture контейнера суттєво змінився:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Якщо присутня `CAP_SYS_ADMIN` або інша потужна capability, перевірте, чи є seccomp єдиною відсутньою перешкодою перед зловживанням на основі mount:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
На деяких цілях безпосередньою метою є не повний escape, а збір інформації та розширення attack surface ядра. Ці команди допомагають визначити, чи доступні особливо чутливі шляхи системних викликів:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Якщо seccomp відсутній, а контейнер також має інші привілейовані можливості, саме тоді є сенс перейти до більш специфічних технік breakout, уже задокументованих на legacy-сторінках про container-escape.

### Повний приклад: seccomp був єдиною перешкодою для `unshare`

На багатьох цілях практичний ефект видалення seccomp полягає в тому, що системні виклики створення namespace або монтування раптово починають працювати. Якщо контейнер також має `CAP_SYS_ADMIN`, наступна послідовність може стати можливою:
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
Саме по собі це ще не є host escape, але демонструє, що seccomp був бар’єром, який запобігав експлуатації, пов’язаній із mount.

### Повний приклад: seccomp вимкнено + `release_agent` у cgroup v1

Якщо seccomp вимкнено, а контейнер може монтувати ієрархії cgroup v1, стає доступною техніка `release_agent` із розділу про cgroups:
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
Це exploit не лише seccomp. Суть у тому, що після переходу seccomp у стан unconfined ланцюжки breakout, що активно використовують syscall і раніше блокувалися, можуть почати працювати саме так, як написано.

## Перевірки

Мета цих перевірок — визначити, чи активний seccomp взагалі, чи супроводжується він `no_new_privs`, а також чи вказує конфігурація runtime на явне вимкнення seccomp.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Що тут важливо:

- Ненульове значення `Seccomp` означає, що фільтрація активна; `0` зазвичай означає відсутність seccomp-захисту.
- Якщо параметри безпеки runtime містять `seccomp=unconfined`, workload втратив один зі своїх найкорисніших захистів на рівні системних викликів.
- `NoNewPrivs` — це не сам seccomp, але наявність обох параметрів зазвичай свідчить про ретельніше hardening, ніж відсутність обох.

Якщо контейнер уже має підозрілі mounts, широкі capabilities або спільні host namespaces, а seccomp також має значення unconfined, таку комбінацію слід розглядати як серйозний сигнал ескалації. Контейнер усе ще може бути не таким, що легко зламати, але кількість точок входу в kernel, доступних attacker, різко зросла.

## Значення за замовчуванням Runtime

| Runtime / платформа | Стан за замовчуванням | Поведінка за замовчуванням | Поширене ручне послаблення |
| --- | --- | --- | --- |
| Docker Engine | Зазвичай увімкнено за замовчуванням | Використовує вбудований профіль seccomp за замовчуванням у Docker, якщо його не перевизначено | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Зазвичай увімкнено за замовчуванням | Застосовує профіль seccomp runtime за замовчуванням, якщо його не перевизначено | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Не гарантовано за замовчуванням** | Якщо `securityContext.seccompProfile` не задано, значенням за замовчуванням є `Unconfined`, якщо kubelet не ввімкнув `--seccomp-default`; в іншому разі потрібно явно задати `RuntimeDefault` або `Localhost` | `securityContext.seccompProfile.type: Unconfined`, якщо seccomp не задано в кластерах без `seccompDefault`, `privileged: true` |
| containerd / CRI-O під керуванням Kubernetes | Дотримується налаштувань вузла та Pod у Kubernetes | Профіль Runtime використовується, коли Kubernetes запитує `RuntimeDefault` або коли ввімкнено встановлення значення seccomp за замовчуванням у kubelet | Як у рядку Kubernetes; пряма конфігурація CRI/OCI також може повністю не містити seccomp |

Поведінка Kubernetes найчастіше дивує операторів. У багатьох кластерах seccomp усе ще не застосовується, якщо Pod не запитує його або kubelet не налаштовано на використання `RuntimeDefault` за замовчуванням.
{{#include ../../../../banners/hacktricks-training.md}}
