# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` — це функція hardening ядра, яка не дає процесу отримати більше привілеїв під час `execve()`. Практично це означає, що після встановлення цього прапорця запуск setuid-бінарника, setgid-бінарника або файлу з Linux file capabilities не надає додаткових привілеїв порівняно з тими, які процес уже мав. У containerized environments це важливо, оскільки багато ланцюжків privilege-escalation залежать від пошуку executable всередині image, який змінює рівень привілеїв під час запуску.

З defensive point of view, `no_new_privs` не є заміною namespaces, seccomp або capability dropping. Це reinforcement layer. Він блокує певний клас подальшого escalation після того, як code execution уже отримано. Це робить його особливо цінним у середовищах, де images містять helper binaries, артефакти package-manager або legacy tools, які інакше були б небезпечними в разі partial compromise.

## Робота

Прапорець ядра, що забезпечує таку поведінку, — `PR_SET_NO_NEW_PRIVS`. Після його встановлення для процесу наступні виклики `execve()` не можуть підвищити рівень привілеїв. Важлива деталь: процес усе ще може запускати binaries; він просто не може використати їх для перетину privilege boundary, який ядро інакше дозволило б.

Поведінка ядра також є **успадкованою та незворотною**: після того як task встановлює `no_new_privs`, цей bit успадковується через `fork()`, `clone()` і `execve()` та надалі не може бути скасований. Це корисно під час assessments, оскільки наявність `NoNewPrivs: 1` у container process зазвичай означає, що descendants також мають залишатися в цьому режимі, якщо тільки ви не аналізуєте повністю інше process tree.

У середовищах, орієнтованих на Kubernetes, `allowPrivilegeEscalation: false` відповідає цій поведінці для container process. У runtime-ах на кшталт Docker і Podman еквівалент зазвичай вмикається явно через security option. На OCI layer та сама концепція представлена як `process.noNewPrivileges`.

## Важливі нюанси

`no_new_privs` блокує privilege gain **під час exec**, але не кожну зміну привілеїв. Зокрема:

- переходи setuid і setgid припиняють працювати під час `execve()`
- file capabilities не додаються до permitted set під час `execve()`
- LSM, такі як AppArmor або SELinux, не послаблюють обмеження після `execve()`
- привілеї, якими процес уже володіє, залишаються в його розпорядженні

Останній пункт має практичне значення. Якщо процес уже працює як root, уже має небезпечну capability або вже має доступ до потужного runtime API чи writable host mount, встановлення `no_new_privs` не усуває ці exposures. Воно лише прибирає один поширений **наступний крок** у ланцюжку privilege-escalation.

Також зверніть увагу, що цей прапорець не блокує зміни привілеїв, які не залежать від `execve()`. Наприклад, task, який уже має достатні привілеї, усе ще може безпосередньо викликати `setuid(2)` або отримати privileged file descriptor через Unix socket. Саме тому `no_new_privs` слід розглядати разом із [seccomp](seccomp.md), capability sets і namespace exposure, а не як самостійне рішення.

## Lab

Перевірте стан поточного процесу:
```bash
grep NoNewPrivs /proc/self/status
```
Порівняйте це з контейнером, у якому runtime вмикає цей прапорець:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
У hardened workload результат має показувати `NoNewPrivs: 1`.

Також можна продемонструвати фактичний ефект на setuid binary:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
Суть порівняння не в тому, що `su` можна універсально експлуатувати. Вона в тому, що один і той самий image може поводитися дуже по-різному залежно від того, чи дозволено `execve()` і надалі перетинати межу привілеїв.

## Вплив на безпеку

Якщо `no_new_privs` не встановлено, отриманий foothold усередині container усе ще можна підвищити за допомогою setuid helpers або binaries із file capabilities. Якщо його встановлено, такі зміни привілеїв після exec блокуються. Цей ефект особливо важливий для широких base images, які містять багато утиліт, що насправді не були потрібні застосунку.

Також важливою є взаємодія із seccomp. Непривілейованим tasks зазвичай потрібно встановити `no_new_privs` перед інсталяцією seccomp filter у filter mode. Це одна з причин, чому hardened containers часто мають одночасно увімкнені `Seccomp` і `NoNewPrivs`. З погляду attacker, наявність обох зазвичай означає, що середовище було налаштоване навмисно, а не випадково.

## Неправильні конфігурації

Найпоширеніша проблема — просто не ввімкнути цей control у середовищах, де він був би сумісним. У Kubernetes залишення `allowPrivilegeEscalation` увімкненим часто є типовою operational mistake. У Docker і Podman пропуск відповідної security option має такий самий ефект. Ще одна recurring failure mode — припущення, що оскільки container є «не privileged», переходи привілеїв під час exec автоматично не мають значення.

Більш subtle Kubernetes pitfall полягає в тому, що `allowPrivilegeEscalation: false` **не** обробляється так, як очікують люди, коли container є `privileged` або має `CAP_SYS_ADMIN`. У Kubernetes API зазначено, що в таких випадках `allowPrivilegeEscalation` фактично завжди має значення true. На практиці це означає, що поле слід розглядати лише як один із сигналів у фінальному security posture, а не як гарантію того, що runtime зрештою отримав `NoNewPrivs: 1`.

## Зловживання

Якщо `no_new_privs` не встановлено, перше питання полягає в тому, чи містить image binaries, які все ще можуть підвищити привілеї:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Цікаві результати включають:

- `NoNewPrivs: 0`
- setuid-помічники, такі як `su`, `mount`, `passwd`, або адміністративні інструменти, специфічні для дистрибутива
- бінарні файли з file capabilities, які надають мережеві привілеї або привілеї файлової системи

Під час реального assessment ці результати самі по собі не доводять можливість успішної ескалації, але точно визначають бінарні файли, які варто перевірити далі.

У Kubernetes також перевірте, чи відповідає задум YAML фактичному стану kernel:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Цікаві комбінації:

- `allowPrivilegeEscalation: false` у специфікації Pod, але `NoNewPrivs: 0` у контейнері
- наявний `cap_sys_admin`, що робить поле Kubernetes значно менш надійним
- `Seccomp: 0` і `NoNewPrivs: 0`, що зазвичай вказує на загалом послаблену конфігурацію runtime, а не на одну ізольовану помилку

### Повний приклад: підвищення привілеїв у контейнері через setuid

Цей механізм зазвичай запобігає **підвищенню привілеїв у контейнері**, а не безпосередньому escape на хост. Якщо `NoNewPrivs` дорівнює `0` і наявний setuid helper, явно перевірте його:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Якщо відомий бінарний файл setuid присутній і функціонує, спробуйте запустити його так, щоб зберегти перехід привілеїв:
```bash
/bin/su -c id 2>/dev/null
```
Саме по собі це не забезпечує вихід із контейнера, але може перетворити foothold із низькими привілеями всередині контейнера на container-root, що часто стає передумовою для подальшого виходу на host через mounts, runtime sockets або інтерфейси, що взаємодіють із kernel.

## Перевірки

Мета цих перевірок — визначити, чи заблоковано підвищення привілеїв під час exec, і чи містить image допоміжні засоби, які мали б значення, якщо воно не заблоковане.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
Що тут важливо:

- `NoNewPrivs: 1` зазвичай є безпечнішим результатом.
- `NoNewPrivs: 0` означає, що шляхи ескалації на основі setuid і file-cap залишаються актуальними.
- `NoNewPrivs: 1` разом із `Seccomp: 2` є поширеною ознакою більш продуманого hardening.
- Маніфест Kubernetes із `allowPrivilegeEscalation: false` корисний, але фактичним джерелом істини є статус kernel.
- Мінімальний image з малою кількістю або повною відсутністю setuid/file-cap бінарних файлів залишає attacker менше можливостей після експлуатації, навіть якщо `no_new_privs` відсутній.

## Runtime Defaults

| Runtime / платформа | Стан за замовчуванням | Поведінка за замовчуванням | Поширене ручне послаблення |
| --- | --- | --- | --- |
| Docker Engine | Не ввімкнено за замовчуванням | Вмикається явно через `--security-opt no-new-privileges=true`; також доступне глобальне налаштування за замовчуванням через `dockerd --no-new-privileges` | пропуск прапорця, `--privileged` |
| Podman | Не ввімкнено за замовчуванням | Вмикається явно через `--security-opt no-new-privileges` або еквівалентну конфігурацію безпеки | пропуск опції, `--privileged` |
| Kubernetes | Контролюється політикою workload | `allowPrivilegeEscalation: false` запитує застосування цього ефекту, але `privileged: true` і `CAP_SYS_ADMIN` фактично зберігають його ввімкненим | `allowPrivilegeEscalation: true`, `privileged: true`, додавання `CAP_SYS_ADMIN` |
| containerd / CRI-O під Kubernetes | Відповідає налаштуванням workload Kubernetes / OCI `process.noNewPrivileges` | Зазвичай успадковується з security context Pod і перетворюється на конфігурацію OCI runtime | те саме, що в рядку Kubernetes |

Цей захист часто відсутній просто тому, що його ніхто не ввімкнув, а не через відсутність підтримки з боку runtime.

## References

- [Документація Linux kernel: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Налаштування Security Context для Pod або Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
