# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` — це механізм укріплення ядра, який забороняє процесу отримувати додаткові привілеї через `execve()`. Практично це означає, що після встановлення прапорця виконання setuid binary, setgid binary або файлу з Linux file capabilities не надає додаткових привілеїв понад ті, які процес вже мав. В контейнеризованих середовищах це важливо, оскільки багато privilege-escalation chains покладаються на знаходження виконуваного файлу всередині образу, який змінює привілеї при запуску.

З оборонної точки зору, `no_new_privs` не замінює namespaces, seccomp або capability dropping. Це шар посилення. Він блокує певний клас наступного підвищення привілеїв після того, як виконання коду вже було отримано. Це робить його особливо цінним у середовищах, де образи містять helper binaries, package-manager artifacts або legacy tools, які в іншому випадку були б небезпечними в поєднанні з частковим компрометом.

## Operation

За цю поведінку відповідає прапорець ядра `PR_SET_NO_NEW_PRIVS`. Після його встановлення для процесу наступні виклики `execve()` не можуть підвищити привілеї. Важлива деталь: процес усе ще може запускати бінарні файли; він просто не може використати ці бінарники для перетину межі привілеїв, які ядро інакше б визнало.

У Kubernetes-орієнтованих середовищах `allowPrivilegeEscalation: false` відповідає цій поведінці для процесу контейнера. У рантаймах типу Docker і Podman еквівалент зазвичай увімкнений явно через опцію безпеки.

## Lab

Перевірте поточний стан процесу:
```bash
grep NoNewPrivs /proc/self/status
```
Порівняйте це з контейнером, у якому runtime вмикає flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
На захищеному робочому навантаженні результат має показувати `NoNewPrivs: 1`.

## Вплив на безпеку

Якщо `no_new_privs` відсутній, закріплення всередині контейнера все ще може бути підвищене через setuid helpers або бінарні файли з file capabilities. Якщо він встановлений, ці зміни привілеїв після виконання відсікаються. Ефект особливо важливий для широких базових образів, які постачають багато утиліт, які додаток ніколи не потребував.

## Неправильні конфігурації

Найпоширеніша проблема — просто не ввімкнути цей контроль у середовищах, де він був би сумісний. В Kubernetes залишення `allowPrivilegeEscalation` увімкненим часто є типовою операційною помилкою. В Docker і Podman опущення відповідної опції безпеки має той самий ефект. Ще один повторюваний режим відмови — припускати, що оскільки контейнер "not privileged", переходи привілеїв під час exec автоматично неактуальні.

## Зловживання

Якщо `no_new_privs` не встановлений, перше питання — чи містить образ бінарні файли, які все ще можуть підняти привілеї:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Interesting results include:

- `NoNewPrivs: 0`
- setuid helpers такі як `su`, `mount`, `passwd` або інструменти адміністрування, специфічні для дистрибутиву
- binaries з file capabilities, які надають мережеві або файлові привілеї

У реальному аудиті ці знахідки самі по собі не доводять наявності працездатного privilege escalation, але точно визначають, які binaries варто тестувати далі.

### Повний приклад: In-Container Privilege Escalation Through setuid

Цей контроль зазвичай запобігає **in-container privilege escalation**, а не безпосередньо host escape. Якщо `NoNewPrivs` є `0` і існує setuid helper, перевірте його явно:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Якщо відомий setuid-бінарний файл присутній і працездатний, спробуйте запустити його таким чином, щоб зберегти перехід привілеїв:
```bash
/bin/su -c id 2>/dev/null
```
Це саме по собі не дозволяє вийти з контейнера, але може перетворити низькоправовий foothold всередині контейнера на container-root, що часто стає передумовою для подальшого виходу на host через mounts, runtime sockets або kernel-facing interfaces.

## Checks

Мета цих перевірок — встановити, чи заблоковано exec-time privilege gain і чи image все ще містить helpers, які мали б значення, якщо це не так.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
Що тут цікаво:

- `NoNewPrivs: 1` зазвичай є безпечнішим результатом.
- `NoNewPrivs: 0` означає, що маршрути ескалації на основі setuid та file-cap залишаються релевантними.
- Мінімальний образ з малою кількістю або без setuid/file-cap бінарних файлів надає атакуючому менше опцій для post-exploitation навіть коли `no_new_privs` відсутній.

## Налаштування за замовчуванням середовища виконання

| Runtime / platform | Стан за замовчуванням | Поведінка за замовчуванням | Часті ручні ослаблення |
| --- | --- | --- | --- |
| Docker Engine | За замовчуванням не увімкнено | Увімкнено явно за допомогою `--security-opt no-new-privileges=true` | пропуск прапорця, `--privileged` |
| Podman | За замовчуванням не увімкнено | Увімкнено явно за допомогою `--security-opt no-new-privileges` або еквівалентної конфігурації безпеки | пропуск опції, `--privileged` |
| Kubernetes | Керується політикою робочого навантаження | `allowPrivilegeEscalation: false` вмикає ефект; багато робочих навантажень все ще залишають його увімкненим | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Відповідає налаштуванням робочого навантаження Kubernetes | Зазвичай успадковується з контексту безпеки Pod | те саме, що в рядку Kubernetes |

Цей захист часто відсутній просто тому, що ніхто його не увімкнув, а не тому, що середовище виконання не підтримує його.
{{#include ../../../../banners/hacktricks-training.md}}
