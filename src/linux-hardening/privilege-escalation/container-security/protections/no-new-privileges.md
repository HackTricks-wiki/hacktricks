# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` — це kernel hardening feature, яка забороняє процесу отримувати більше privilege через `execve()`. На практиці це означає, що після встановлення цього прапорця виконання setuid binary, setgid binary або файла з Linux file capabilities не надає додаткового privilege понад той, який процес уже мав. У containerized environments це важливо, тому що багато privilege-escalation chains покладаються на знаходження executable всередині image, який змінює privilege під час запуску.

З точки зору захисту, `no_new_privs` не є заміною для namespaces, seccomp або capability dropping. Це reinforcement layer. Вона блокує конкретний клас подальшого escalation після того, як code execution уже отримано. Це робить її особливо корисною в середовищах, де images містять helper binaries, package-manager artifacts або legacy tools, які інакше були б небезпечними у поєднанні з partial compromise.

## Operation

Прапорець kernel, що стоїть за цією поведінкою, — `PR_SET_NO_NEW_PRIVS`. Після того як його встановлено для процесу, подальші виклики `execve()` не можуть збільшити privilege. Важлива деталь: процес усе ще може запускати binaries; він просто не може використати ці binaries, щоб перетнути privilege boundary, яку kernel інакше б визнав.

Поводження kernel також **успадковується і є незворотним**: щойно task встановлює `no_new_privs`, біт успадковується через `fork()`, `clone()` і `execve()`, і його не можна скасувати пізніше. Це корисно під час assessments, тому що один `NoNewPrivs: 1` на container process зазвичай означає, що descendants також мають залишатися в цьому режимі, якщо тільки ви не дивитеся на зовсім інше process tree.

У Kubernetes-oriented environments `allowPrivilegeEscalation: false` відповідає цій поведінці для container process. У Docker і Podman style runtimes еквівалент зазвичай вмикається явно через security option. На OCI layer та сама концепція відображається як `process.noNewPrivileges`.

## Important Nuances

`no_new_privs` блокує privilege gain **під час exec-time**, але не кожну зміну privilege. Зокрема:

- setuid і setgid transitions перестають працювати через `execve()`
- file capabilities не додаються до permitted set під час `execve()`
- LSMs, такі як AppArmor або SELinux, не послаблюють constraints після `execve()`
- already-held privilege залишається already-held privilege

Цей останній пункт важливий з operational точки зору. Якщо процес уже працює як root, уже має небезпечну capability або вже має доступ до потужного runtime API чи writable host mount, встановлення `no_new_privs` не нейтралізує ці exposures. Воно лише прибирає один поширений **next step** у privilege-escalation chain.

Також зауважте, що прапорець не блокує зміни privilege, які не залежать від `execve()`. Наприклад, task, який уже достатньо privileged, усе ще може напряму викликати `setuid(2)` або отримати privileged file descriptor через Unix socket. Саме тому `no_new_privs` слід читати разом із [seccomp](seccomp.md), capability sets і namespace exposure, а не як окрему відповідь.

## Lab

Inspect the current process state:
```bash
grep NoNewPrivs /proc/self/status
```
Порівняйте це з контейнером, де runtime увімкнув цей прапорець:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
На hardened workload результат має показувати `NoNewPrivs: 1`.

Також можна продемонструвати фактичний ефект на setuid binary:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
Суть порівняння не в тому, що `su` можна експлуатувати всюди. А в тому, що один і той самий image може поводитися зовсім по-різному залежно від того, чи `execve()` усе ще може перетинати boundary привілеїв.

## Security Impact

Якщо `no_new_privs` відсутній, foothold усередині container може все ще бути підвищений через setuid helpers або binaries з file capabilities. Якщо він присутній, ці post-exec зміни привілеїв відсікаються. Це особливо важливо для великих base images, які постачають багато utilities, що застосунку взагалі не були потрібні.

Є також важлива seccomp-взаємодія. Непривілейованим tasks зазвичай потрібно, щоб `no_new_privs` був встановлений, перш ніж вони зможуть інсталювати seccomp filter у filter mode. Саме тому hardened containers часто показують і `Seccomp`, і `NoNewPrivs` увімкненими разом. З погляду attacker, коли видно обидва, це зазвичай означає, що environment було налаштовано навмисно, а не випадково.

## Misconfigurations

Найпоширеніша проблема — просто не вмикати control у environments, де він був би сумісний. У Kubernetes залишення `allowPrivilegeEscalation` увімкненим часто є типовою operational помилкою. У Docker і Podman пропуск відповідної security option дає той самий ефект. Ще один повторюваний failure mode — припускати, що якщо container "not privileged", то exec-time переходи привілеїв автоматично не мають значення.

Більш тонка пастка Kubernetes полягає в тому, що `allowPrivilegeEscalation: false` **не** враховується так, як люди очікують, коли container `privileged` або коли він має `CAP_SYS_ADMIN`. Kubernetes API документує, що `allowPrivilegeEscalation` у цих випадках фактично завжди true. На практиці це означає, що поле слід розглядати як один із сигналів у фінальному posture, а не як гарантію того, що runtime зрештою отримав `NoNewPrivs: 1`.

## Abuse

Якщо `no_new_privs` не встановлено, перше питання — чи містить image binaries, які все ще можуть підвищити privilege:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Цікаві результати включають:

- `NoNewPrivs: 0`
- setuid helpers, такі як `su`, `mount`, `passwd` або специфічні для дистрибутива admin tools
- binaries з file capabilities, які надають network або filesystem privileges

У реальному assessment ці знахідки самі по собі не доводять working escalation, але вони точно вказують на binaries, які варто тестувати далі.

У Kubernetes також перевірте, що YAML intent відповідає kernel reality:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Цікаві комбінації включають:

- `allowPrivilegeEscalation: false` у Pod spec, але `NoNewPrivs: 0` у контейнері
- `cap_sys_admin` present, що робить поле Kubernetes значно менш надійним
- `Seccomp: 0` і `NoNewPrivs: 0`, що зазвичай вказує на загалом ослаблений runtime posture, а не на одну ізольовану помилку

### Full Example: In-Container Privilege Escalation Through setuid

Цей control зазвичай запобігає **in-container privilege escalation** rather than host escape directly. Якщо `NoNewPrivs` дорівнює `0` і існує setuid helper, перевірте це явно:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Якщо присутній і функціональний відомий setuid binary, спробуйте запустити його так, щоб зберегти перехід привілеїв:
```bash
/bin/su -c id 2>/dev/null
```
Це само по собі не дає виходу з container, але може перетворити початковий доступ з низькими привілеями всередині container на container-root, що часто стає передумовою для подальшого escape з host через mounts, runtime sockets або інтерфейси, що взаємодіють з kernel.

## Checks

Мета цих перевірок — з’ясувати, чи заблоковано підвищення привілеїв під час exec, і чи image все ще містить helpers, які будуть важливими, якщо це не так.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
Що тут цікавого:

- `NoNewPrivs: 1` зазвичай є безпечнішим результатом.
- `NoNewPrivs: 0` означає, що шляхи підвищення привілеїв через setuid і file-cap залишаються актуальними.
- `NoNewPrivs: 1` плюс `Seccomp: 2` — поширена ознака більш навмисної hardening-позиції.
- Kubernetes manifest, який каже `allowPrivilegeEscalation: false`, корисний, але kernel status — це джерело істини.
- Мінімальний image з небагатьма або без setuid/file-cap binaries дає attacker менше post-exploitation варіантів, навіть коли `no_new_privs` відсутній.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Не ввімкнено за замовчуванням | Вмикається явно через `--security-opt no-new-privileges=true`; також існує daemon-wide default через `dockerd --no-new-privileges` | пропуск прапорця, `--privileged` |
| Podman | Не ввімкнено за замовчуванням | Вмикається явно через `--security-opt no-new-privileges` або еквівалентну security configuration | пропуск опції, `--privileged` |
| Kubernetes | Керується workload policy | `allowPrivilegeEscalation: false` запитує цей ефект, але `privileged: true` і `CAP_SYS_ADMIN` фактично залишають його увімкненим | `allowPrivilegeEscalation: true`, `privileged: true`, додавання `CAP_SYS_ADMIN` |
| containerd / CRI-O under Kubernetes | Дотримується Kubernetes workload settings / OCI `process.noNewPrivileges` | Зазвичай успадковується з Pod security context і транслюється в OCI runtime config | same as Kubernetes row |

Цей захист часто відсутній просто тому, що його ніхто не вмикав, а не тому, що runtime не підтримує його.

## References

- [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
