# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Огляд

**seccomp** — це механізм, який дає змогу ядру застосовувати фільтр до syscall, які може викликати процес. У containerized environments seccomp зазвичай використовується у filter mode, щоб процес не просто позначався як "restricted" у розмитому сенсі, а підпорядковувався конкретній політиці syscall. Це важливо, оскільки для багатьох container breakouts потрібен доступ до дуже специфічних інтерфейсів ядра. Якщо процес не може успішно викликати відповідні syscall, великий клас атак зникає ще до того, як взагалі набувають значення нюанси namespace або capability.

Ключова mental model проста: namespaces визначають, **що процес може бачити**, capabilities визначають, **які привілейовані дії процес номінально може спробувати виконати**, а seccomp визначає, **чи прийме ядро взагалі точку входу syscall для спроби виконання цієї дії**. Саме тому seccomp часто запобігає атакам, які інакше здавалися б можливими лише на підставі capabilities.

## Вплив на безпеку

Велика частина небезпечної поверхні ядра доступна лише через відносно невеликий набір syscall. Приклади, які постійно мають значення для hardening контейнерів, включають `mount`, `unshare`, `clone` або `clone3` з певними flags, `bpf`, `ptrace`, `keyctl` і `perf_event_open`. Атакер, який може отримати доступ до цих syscall, може створювати нові namespaces, маніпулювати підсистемами ядра або взаємодіяти з attack surface, яка звичайному application container взагалі не потрібна.

Саме тому default runtime seccomp profiles є такими важливими. Це не просто "додатковий захист". У багатьох середовищах вони визначають різницю між контейнером, який може використовувати значну частину функціональності ядра, і контейнером, обмеженим поверхнею syscall, ближчою до тієї, яка справді потрібна application.

## Режими та побудова фільтрів

seccomp історично мав strict mode, у якому доступним залишався лише дуже малий набір syscall, але режим, актуальний для сучасних container runtimes, — це seccomp filter mode, який часто називають **seccomp-bpf**. У цій моделі ядро оцінює filter program, що визначає, чи слід дозволити syscall, відхилити його з errno, перехопити, записати в log або завершити процес.<sup>[[1]](#references)</sup> Container runtimes використовують цей механізм, оскільки він достатньо виразний для блокування широких класів небезпечних syscall і водночас дає змогу зберігати нормальну поведінку application.

Два low-level приклади корисні тим, що роблять механізм конкретним, а не магічним. Strict mode демонструє стару модель "виживає лише мінімальний набір syscall":
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
Фінальний виклик `open` призводить до завершення процесу, оскільки він не входить до мінімального набору strict mode.

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
Цей стиль політики — саме те, що більшість читачів мають уявляти, коли думають про runtime-профілі seccomp.

## Лабораторна робота

Простий спосіб підтвердити, що seccomp активний у контейнері:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Також можна спробувати операцію, яку стандартні профілі зазвичай обмежують:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Якщо контейнер працює зі звичайним профілем seccomp за замовчуванням, операції на кшталт `unshare` часто блокуються. Це корисна демонстрація, оскільки вона показує, що навіть якщо інструмент userspace існує всередині image, необхідний йому шлях у kernel може бути недоступним.
Якщо контейнер працює зі звичайним профілем seccomp за замовчуванням, операції на кшталт `unshare` часто блокуються, навіть коли інструмент userspace існує всередині image.

Щоб загалом перевірити статус процесу, виконайте:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Використання під час роботи

Docker підтримує стандартні та custom seccomp-профілі й дозволяє адміністраторам вимикати їх за допомогою `--security-opt seccomp=unconfined`.<sup>[[2]](#references)</sup> Podman має подібну підтримку й часто поєднує seccomp із rootless execution, що забезпечує дуже розумну конфігурацію за замовчуванням. Kubernetes надає доступ до seccomp через конфігурацію workload, де `RuntimeDefault` зазвичай є безпечною базовою конфігурацією, а `Unconfined` слід розглядати як виняток, що потребує обґрунтування, а не як зручний перемикач.<sup>[[3]](#references)</sup>

У середовищах на базі containerd і CRI-O точний шлях є більш багаторівневим, але принцип залишається тим самим: engine або orchestrator вищого рівня визначає, що має відбутися, а runtime зрештою встановлює отриману seccomp-політику для процесу контейнера. Результат усе ще залежить від кінцевої конфігурації runtime, яка надходить до kernel.

### Приклад custom policy

Docker та подібні engines можуть завантажувати custom seccomp-профіль із JSON. Мінімальний приклад, який забороняє `chmod`, дозволяючи все інше, виглядає так:
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
Команда завершується помилкою `Operation not permitted`, демонструючи, що обмеження надходить від політики syscall, а не лише від звичайних дозволів на файли. У реальному hardening allowlists зазвичай сильніші за permissive defaults із невеликим blacklist.

## Неправильні конфігурації

Найгрубіша помилка — встановити seccomp у режим **unconfined**, оскільки застосунок не працював із політикою за замовчуванням. Це поширено під час troubleshooting і дуже небезпечно як постійне рішення. Після видалення filter знову стають доступними багато syscall-based breakout primitives, особливо якщо також присутні потужні capabilities або спільне використання host namespaces.

Ще одна поширена проблема — використання **custom permissive profile**, скопійованого з якогось блогу або внутрішнього workaround без ретельного review. Команди іноді залишають майже всі небезпечні syscalls лише тому, що profile створювався з орієнтацією на "stop the app from breaking", а не на "grant only what the app actually needs". Третя помилкова думка — вважати, що seccomp менш важливий для non-root containers. Насправді значна частина kernel attack surface залишається актуальною, навіть коли процес не має UID 0.

## Зловживання

Якщо seccomp відсутній або суттєво послаблений, attacker може отримати можливість викликати namespace-creation syscalls, розширити доступну kernel attack surface через `bpf` або `perf_event_open`, зловживати `keyctl` або поєднати ці syscall paths із небезпечними capabilities, такими як `CAP_SYS_ADMIN`. У багатьох реальних атаках seccomp — не єдиний відсутній контроль, але його відсутність суттєво скорочує exploit path, оскільки усуває один із небагатьох захистів, здатних зупинити risky syscall ще до того, як почне діяти решта privilege model.

Найкорисніший практичний тест — спробувати саме ті syscall families, які зазвичай блокують default profiles. Якщо вони раптом працюють, security posture контейнера суттєво змінилася:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Якщо присутня `CAP_SYS_ADMIN` або інша потужна capability, перевірте, чи є seccomp єдиною відсутньою перешкодою перед зловживанням через mount:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
На деяких цілях безпосередньою метою є не full escape, а збір інформації та розширення attack surface ядра. Ці команди допомагають визначити, чи доступні особливо чутливі шляхи syscall:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Якщо seccomp відсутній, а container також має інші привілейовані властивості, саме тоді має сенс перейти до більш специфічних breakout techniques, уже задокументованих на legacy container-escape pages.

### Повний приклад: seccomp був єдиним, що блокувало `unshare`

На багатьох цілях практичним наслідком видалення seccomp є те, що syscalls для створення namespace або mount раптово починають працювати. Якщо container також має `CAP_SYS_ADMIN`, може стати можливою така послідовність дій:
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
Само по собі це ще не є host escape, але демонструє, що seccomp був бар’єром, який перешкоджав експлуатації, пов’язаній із mount.

### Повний приклад: seccomp Disabled + cgroup v1 `release_agent`

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
Це не exploit, що стосується лише seccomp. Суть у тому, що після переходу seccomp у стан unconfined ланцюжки breakout, насичені syscall, які раніше блокувалися, можуть почати працювати саме так, як написано.

## Перевірки

Мета цих перевірок — встановити, чи активний seccomp взагалі, чи супроводжується він параметром `no_new_privs`, а також чи показує конфігурація runtime, що seccomp явно вимкнено.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Що тут цікаво:

- Ненульове значення `Seccomp` означає, що filtering активний; `0` зазвичай означає відсутність seccomp-захисту.
- Якщо параметри runtime security містять `seccomp=unconfined`, workload втратив один із найкорисніших захистів на рівні syscall.
- `NoNewPrivs` — це не сам seccomp, але наявність обох параметрів зазвичай свідчить про ретельніше hardening, ніж відсутність обох.

Якщо контейнер уже має підозрілі mounts, широкі capabilities або спільні host namespaces, а seccomp також має значення unconfined, таку комбінацію слід розглядати як серйозний сигнал ескалації. Контейнер усе ще може бути не trivially breakable, але кількість entry points до kernel, доступних attacker, різко зросла.

## Типові налаштування Runtime

| Runtime / platform | Типовий стан | Типова поведінка | Поширене ручне послаблення |
| --- | --- | --- | --- |
| Docker Engine | Зазвичай увімкнено за замовчуванням | Використовує вбудований default seccomp profile Docker, якщо його не перевизначено | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Зазвичай увімкнено за замовчуванням | Застосовує default seccomp profile runtime, якщо його не перевизначено | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Не гарантовано за замовчуванням** | Якщо `securityContext.seccompProfile` не задано, default — `Unconfined`, якщо kubelet не ввімкнув `--seccomp-default`; в іншому разі потрібно явно задати `RuntimeDefault` або `Localhost` | `securityContext.seccompProfile.type: Unconfined`, відсутність seccomp у кластерах без `seccompDefault`, `privileged: true` |
| containerd / CRI-O у Kubernetes | Дотримується налаштувань Kubernetes node і Pod | Runtime profile використовується, коли Kubernetes запитує `RuntimeDefault` або коли ввімкнено seccomp defaulting у kubelet | Як у рядку Kubernetes; пряма конфігурація CRI/OCI також може повністю не вказувати seccomp |

Поведінка Kubernetes найчастіше дивує operators. У багатьох кластерах seccomp усе ще відсутній, якщо Pod не запитує його або kubelet не налаштовано на використання `RuntimeDefault` за замовчуванням.<sup>[[3]](#references)</sup>

## References

- [1] [Linux kernel documentation: Seccomp BPF (SECure COMPuting with filters)](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [2] [Docker Docs: Seccomp security profiles for Docker](https://docs.docker.com/engine/security/seccomp/)
- [3] [Kubernetes Docs: Restrict a Container's Syscalls with seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/)

{{#include ../../../../banners/hacktricks-training.md}}
