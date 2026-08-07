# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` — це функція hardening ядра, яка не дозволяє процесу отримувати додаткові привілеї під час `execve()`. Практично це означає, що після встановлення прапора запуск setuid-бінарного файлу, setgid-бінарного файлу або файлу з Linux file capabilities не надає додаткових привілеїв порівняно з тими, які процес уже мав. У контейнеризованих середовищах це важливо, оскільки багато ланцюжків privilege-escalation ґрунтуються на пошуку виконуваного файлу всередині image, який змінює привілеї під час запуску.

З defensive point of view, `no_new_privs` не є заміною namespaces, seccomp або скидання capability. Це додатковий рівень захисту. Він блокує певний клас подальшої privilege-escalation після того, як виконання коду вже було отримано. Це робить його особливо цінним у середовищах, де images містять helper-бінарні файли, артефакти package manager або legacy-інструменти, які інакше були б небезпечними в разі partial compromise.

## Операція

Прапор ядра, що забезпечує цю поведінку, — `PR_SET_NO_NEW_PRIVS`. Після його встановлення для процесу подальші виклики `execve()` не можуть підвищити привілеї. Важлива деталь полягає в тому, що процес і надалі може запускати бінарні файли; він просто не може використовувати їх для перетину межі привілеїв, яку ядро в іншому випадку дозволило б.<sup>[[1]](#references)</sup>

Поведінка ядра також є **успадкованою та незворотною**: після того як task встановлює `no_new_privs`, цей біт успадковується через `fork()`, `clone()` і `execve()`, і надалі його неможливо скасувати.<sup>[[1]](#references)</sup> Це корисно під час assessments, оскільки наявність `NoNewPrivs: 1` у процесі контейнера зазвичай означає, що нащадки також повинні залишатися в цьому режимі, якщо тільки ви не аналізуєте зовсім інше дерево процесів.

У середовищах, орієнтованих на Kubernetes, `allowPrivilegeEscalation: false` відповідає цій поведінці для процесу контейнера.<sup>[[2]](#references)</sup> У runtime на кшталт Docker і Podman еквівалент зазвичай вмикається явно через security option. На рівні OCI ця сама концепція представлена як `process.noNewPrivileges`.

## Важливі нюанси

`no_new_privs` блокує отримання привілеїв **під час exec**, але не кожну зміну привілеїв.<sup>[[1]](#references)</sup> Зокрема:

- переходи setuid і setgid припиняють працювати під час `execve()`
- file capabilities не додаються до permitted set під час `execve()`
- LSM, такі як AppArmor або SELinux, не послаблюють обмеження після `execve()`
- привілеї, якими процес уже володіє, нікуди не зникають

Останній пункт має важливе operational значення. Якщо процес уже працює від root, уже має небезпечну capability або вже має доступ до потужного runtime API чи writable host mount, встановлення `no_new_privs` не усуває ці ризики. Воно лише прибирає один поширений **наступний крок** у ланцюжку privilege-escalation.

Також зверніть увагу, що цей прапор не блокує зміни привілеїв, які не залежать від `execve()`.<sup>[[1]](#references)</sup> Наприклад, task, який уже має достатні привілеї, може й надалі безпосередньо викликати `setuid(2)` або отримати privileged file descriptor через Unix socket. Саме тому `no_new_privs` слід розглядати разом із [seccomp](seccomp.md), наборами capability та exposure namespaces, а не як самостійне рішення.

## Лабораторна робота

Перевірте стан поточного процесу:
```bash
grep NoNewPrivs /proc/self/status
```
Порівняйте це з контейнером, у якому runtime вмикає цей прапорець:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
На захищеному workload результат має показувати `NoNewPrivs: 1`.

Ви також можете продемонструвати фактичний ефект на бінарному файлі setuid:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
Суть порівняння не в тому, що `su` є універсально придатним для експлуатації. Вона полягає в тому, що один і той самий image може поводитися дуже по-різному залежно від того, чи дозволено `execve()` і надалі перетинати межу привілеїв.

## Вплив на безпеку

Якщо `no_new_privs` не встановлено, отриману точку опори всередині контейнера все ще можна посилити через setuid-хелпери або бінарні файли з файловими capabilities. Якщо його встановлено, такі зміни привілеїв після exec блокуються. Цей ефект особливо важливий для широких base images, у яких постачається багато утиліт, що взагалі не потрібні застосунку.

Також важливо враховувати взаємодію із seccomp. Непривілейованим tasks зазвичай потрібно встановити `no_new_privs`, перш ніж вони зможуть інсталювати seccomp-фільтр у filter mode.<sup>[[1]](#references)</sup> Це одна з причин, чому hardened containers часто мають одночасно увімкнені `Seccomp` і `NoNewPrivs`. З погляду атакувальника, наявність обох параметрів зазвичай означає, що середовище було налаштоване навмисно, а не випадково.

## Неправильні конфігурації

Найпоширеніша проблема полягає просто в тому, що цей контроль не вмикають у середовищах, де він був би сумісним. У Kubernetes залишення `allowPrivilegeEscalation` увімкненим часто є типовою операційною помилкою. У Docker і Podman пропуск відповідної security option має такий самий ефект. Ще одна поширена помилка — припущення, що оскільки контейнер є "not privileged", переходи привілеїв під час exec автоматично не мають значення.

Більш прихована пастка Kubernetes полягає в тому, що `allowPrivilegeEscalation: false` **не застосовується так, як очікують користувачі**, коли контейнер є `privileged` або має `CAP_SYS_ADMIN`. В API Kubernetes зазначено, що в таких випадках `allowPrivilegeEscalation` фактично завжди має значення true.<sup>[[2]](#references)</sup> На практиці це означає, що це поле слід розглядати як один із сигналів під час оцінювання кінцевого стану безпеки, а не як гарантію того, що runtime зрештою встановив `NoNewPrivs: 1`.

## Зловживання

Якщо `no_new_privs` не встановлено, перше питання полягає в тому, чи містить image бінарні файли, здатні й надалі підвищувати привілеї:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Цікаві результати включають:

- `NoNewPrivs: 0`
- setuid helpers, такі як `su`, `mount`, `passwd` або адміністративні інструменти, специфічні для дистрибутива
- binaries із file capabilities, які надають мережеві привілеї або привілеї файлової системи

Під час реального assessment ці findings самі по собі не доводять наявність робочої ескалації, але точно визначають binaries, які варто тестувати далі.

У Kubernetes також перевірте, що призначення YAML відповідає реальності kernel:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
Цікаві комбінації включають:

- `allowPrivilegeEscalation: false` у специфікації Pod, але `NoNewPrivs: 0` у контейнері
- наявний `cap_sys_admin`, що робить поле Kubernetes значно менш надійним
- `Seccomp: 0` і `NoNewPrivs: 0`, що зазвичай вказує на загалом послаблений стан runtime, а не на одну ізольовану помилку

### Повний приклад: підвищення привілеїв усередині контейнера через setuid

Цей контроль зазвичай запобігає **підвищенню привілеїв усередині контейнера**, а не безпосередній втечі на хост. Якщо `NoNewPrivs` дорівнює `0` і наявний setuid helper, перевірте це явно:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Якщо відомий setuid binary присутній і функціонує, спробуйте запустити його у спосіб, що зберігає перехід привілеїв:
```bash
/bin/su -c id 2>/dev/null
```
Саме по собі це не забезпечує escape з container, але може перетворити foothold із низькими привілеями всередині container на container-root, що часто стає передумовою для подальшого escape на host через mounts, runtime sockets або інтерфейси, що взаємодіють із kernel.

## Перевірки

Мета цих перевірок — визначити, чи заблоковане підвищення привілеїв під час exec, а також чи містить image helpers, які мали б значення, якщо воно не заблоковане.
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
- Маніфест Kubernetes, у якому зазначено `allowPrivilegeEscalation: false`, є корисним, але фактичний стан kernel є джерелом істини.
- Мінімальний image з малою кількістю або повною відсутністю setuid/file-cap binaries надає attacker менше можливостей після експлуатації, навіть якщо `no_new_privs` відсутній.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Не увімкнено за замовчуванням | Вмикається явно через `--security-opt no-new-privileges=true`; також існує загальносистемне налаштування за замовчуванням через `dockerd --no-new-privileges` | пропуск flag, `--privileged` |
| Podman | Не увімкнено за замовчуванням | Вмикається явно через `--security-opt no-new-privileges` або еквівалентну security configuration | пропуск option, `--privileged` |
| Kubernetes | Керується workload policy | `allowPrivilegeEscalation: false` запитує застосування цього ефекту, але `privileged: true` і `CAP_SYS_ADMIN` фактично залишають його увімкненим | `allowPrivilegeEscalation: true`, `privileged: true`, додавання `CAP_SYS_ADMIN` |
| containerd / CRI-O under Kubernetes | Відповідає налаштуванням Kubernetes workload / OCI `process.noNewPrivileges` | Зазвичай успадковується з security context Pod і перетворюється на конфігурацію OCI runtime | те саме, що в рядку Kubernetes |

Цей захист часто відсутній просто тому, що його ніхто не ввімкнув, а не через відсутність підтримки з боку runtime.

## References

- [1] [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [2] [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
