# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` — це механізм жорсткого захисту ядра, який не дозволяє процесу отримувати додаткові привілеї через `execve()`. Практично це означає, що після встановлення прапора виконання setuid бінаря, setgid бінаря або файлу з Linux file capabilities не надає додаткових привілеїв понад ті, що вже були у процесу. У контейнеризованих середовищах це важливо, оскільки багато ланцюжків privilege-escalation залежать від наявності в образі виконуваного файлу, який змінює привілеї при запуску.

З оборонної точки зору, `no_new_privs` не замінює namespaces, seccomp або capability dropping. Це додатковий рівень захисту. Він блокує певний клас подальшого escalation після того, як код уже виконано. Це робить його особливо цінним у середовищах, де образи містять допоміжні бінарні файли, артефакти package-manager або legacy tools, які в іншому випадку були б небезпечні при частковому компрометі.

## Принцип роботи

За цією поведінкою стоїть прапор ядра `PR_SET_NO_NEW_PRIVS`. Після його встановлення для процесу подальші виклики `execve()` не можуть підвищити привілеї. Важливий момент: процес все ще може запускати бінарні файли; просто він не може використати ці бінарні файли для перетину межі привілеїв, яку ядро інакше б визнавало.

У Kubernetes-орієнтованих середовищах `allowPrivilegeEscalation: false` відповідає цій поведінці для процесу контейнера. У рантаймах типу Docker і Podman еквівалент зазвичай явно вмикається через опцію безпеки.

## Lab

Перевірте стан поточного процесу:
```bash
grep NoNewPrivs /proc/self/status
```
Порівняйте це з container, у якому runtime вмикає flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
На захищеному робочому навантаженні результат має показувати `NoNewPrivs: 1`.

## Вплив на безпеку

Якщо `no_new_privs` відсутній, закріплення всередині контейнера все ще може бути підвищено через setuid helpers або бінарники з file capabilities. Якщо він встановлений, такі зміни привілеїв після exec припиняються. Ефект особливо актуальний для широких базових образів, які містять багато утиліт, які додаток насправді ніколи не потребував.

## Неправильні налаштування

Найпоширеніша проблема — просто не ввімкнути цей контроль у середовищах, де він був би сумісним. В Kubernetes залишення `allowPrivilegeEscalation` увімкненим часто є типовою операційною помилкою. В Docker і Podman пропуск відповідної опції безпеки має той самий ефект. Інший повторюваний режим відмови — припущення, що оскільки контейнер "not privileged", переходи привілеїв під час exec автоматично неактуальні.

## Зловживання

Якщо `no_new_privs` не встановлений, перше питання — чи містить образ бінарні файли, які все ще можуть підвищити привілеї:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Цікаві результати включають:

- `NoNewPrivs: 0`
- setuid helpers, такі як `su`, `mount`, `passwd`, або адміністративні інструменти, специфічні для дистрибутиву
- бінарні файли з file capabilities, які надають права доступу до мережі або файлової системи

У реальному оцінюванні ці знахідки самі по собі не доводять наявність працюючої escalation, але вони точно визначають бінарні файли, які варто тестувати далі.

### Повний приклад: In-Container Privilege Escalation Through setuid

Цей контроль зазвичай запобігає **in-container privilege escalation**, а не безпосередньо host escape. Якщо `NoNewPrivs` є `0` і існує setuid helper, протестуйте його явно:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Якщо відомий setuid binary присутній та функціонує, спробуйте запустити його таким чином, щоб зберегти перехід привілеїв:
```bash
/bin/su -c id 2>/dev/null
```
Саме по собі це не дає можливості вийти з container, але може перетворити low-privilege foothold всередині container у container-root, що часто стає передумовою для подальшого host escape через mounts, runtime sockets або kernel-facing interfaces.

## Checks

Мета цих перевірок — встановити, чи заблоковано exec-time privilege gain, а також чи image все ще містить helpers, які мали б значення, якщо він не заблокований.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
Що тут цікаво:

- `NoNewPrivs: 1` зазвичай є безпечнішим результатом.
- `NoNewPrivs: 0` означає, що setuid і file-cap based escalation paths залишаються релевантними.
- Мінімальний образ з малою кількістю або без setuid/file-cap бінарних файлів надає атакуючому менше post-exploitation опцій навіть коли `no_new_privs` відсутній.

## Значення за замовчуванням під час виконання

| Runtime / платформа | Стан за замовчуванням | Поведінка за замовчуванням | Типові ручні послаблення |
| --- | --- | --- | --- |
| Docker Engine | За замовчуванням не ввімкнено | Вмикається явно через `--security-opt no-new-privileges=true` | не вказавши прапорець, `--privileged` |
| Podman | За замовчуванням не ввімкнено | Вмикається явно через `--security-opt no-new-privileges` або еквівалентною конфігурацією безпеки | не вказавши опцію, `--privileged` |
| Kubernetes | Керується політикою робочого навантаження | `allowPrivilegeEscalation: false` вмикає ефект; багато робочих навантажень досі лишають його ввімкненим | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O під Kubernetes | Дотримується налаштувань робочого навантаження Kubernetes | Зазвичай успадковується з Pod security context | те саме, що в рядку Kubernetes |

Цей захист часто відсутній просто тому, що ніхто його не увімкнув, а не тому, що runtime не підтримує його.
{{#include ../../../../banners/hacktricks-training.md}}
