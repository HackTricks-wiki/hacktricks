# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` — це механізм укріплення ядра, що запобігає отриманню процесом додаткових привілеїв через `execve()`. Практично, після встановлення прапора виконання setuid binary, setgid binary або файлу з Linux file capabilities не надає додаткових привілеїв понад ті, що процес вже мав. У контейнеризованих середовищах це важливо, бо багато ланцюжків privilege-escalation покладаються на знаходження виконуваного файлу всередині образу, який змінює привілей при запуску.

З оборонної точки зору, `no_new_privs` не є заміною для namespaces, seccomp або capability dropping. Це шар підсилення. Він блокує певний клас подальшого escalation після того, як виконання коду вже було отримано. Це робить його особливо корисним у середовищах, де образи містять допоміжні бінарники, package-manager artifacts або застарілі інструменти, які в іншому випадку були б небезпечними в умовах часткового компромісу.

## Принцип роботи

За цим механізмом стоїть прапор ядра `PR_SET_NO_NEW_PRIVS`. Після його встановлення для процесу наступні виклики `execve()` не можуть підвищити привілеї. Важлива деталь: процес все ще може запускати бінарні файли; він просто не може використати ці бінарники, щоб перетнути межу привілеїв, яку ядро інакше б визнавало.

У середовищах, орієнтованих на Kubernetes, `allowPrivilegeEscalation: false` відповідає цій поведінці для процесу контейнера. У рантаймах типу Docker і Podman еквівалент зазвичай вмикається явно через опцію безпеки.

## Лаб

Перевірте стан поточного процесу:
```bash
grep NoNewPrivs /proc/self/status
```
Порівняйте це з container, де runtime вмикає flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
На захищеному робочому навантаженні результат має показувати `NoNewPrivs: 1`.

## Вплив на безпеку

Якщо `no_new_privs` відсутній, a foothold всередині контейнера все ще може бути підвищений через setuid helpers або binaries з file capabilities. Якщо він присутній, ці post-exec privilege changes відсікаються. Ефект особливо актуальний для broad base images, які постачають багато утиліт, яких додатку ніколи не було потрібно.

## Неправильні налаштування

Найпоширеніша проблема — просто не ввімкнути контроль у середовищах, де він був би сумісний. У Kubernetes залишення `allowPrivilegeEscalation` увімкненим часто є типовою операційною помилкою. У Docker і Podman пропуск відповідної опції безпеки має той самий ефект. Ще один повторюваний режим відмови — припущення, що оскільки контейнер "not privileged", exec-time privilege transitions автоматично не мають значення.

## Зловживання

Якщо `no_new_privs` не встановлений, перше питання — чи містить образ binaries, які все ще можуть підвищити привілеї:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Цікаві результати включають:

- `NoNewPrivs: 0`
- setuid helpers такі як `su`, `mount`, `passwd` або інструменти адміністрування, специфічні для дистрибутиву
- бінарні файли з file capabilities, які надають права для мережі або файлової системи

У реальній оцінці ці знахідки самі по собі не доводять працездатності escalation, але вони точно вказують, які бінарні файли варто тестувати далі.

### Повний приклад: Privilege Escalation в контейнері через setuid

Цей контроль зазвичай запобігає **in-container privilege escalation**, а не безпосередньому host escape. Якщо `NoNewPrivs` дорівнює `0` і існує setuid helper, протестуйте його явно:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Якщо відомий setuid binary присутній і працює, спробуйте запустити його так, щоб зберегти передачу привілеїв:
```bash
/bin/su -c id 2>/dev/null
```
Це само по собі не дозволяє escape контейнера, але може перетворити foothold з обмеженими привілеями всередині контейнера на container-root, що часто стає передумовою для пізнішого host escape через mounts, runtime sockets або kernel-facing interfaces.

## Checks

Мета цих перевірок — з'ясувати, чи заблоковано exec-time privilege gain і чи image все ще містить helpers, які матимуть значення, якщо він не заблокований.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
Що тут цікаво:

- `NoNewPrivs: 1` зазвичай є безпечнішим результатом.
- `NoNewPrivs: 0` означає, що шляхи ескалації, основані на setuid та file-cap, залишаються актуальними.
- Мінімальний образ з малою кількістю або без setuid/file-cap бінарних файлів дає атакуючому менше варіантів post-exploitation, навіть якщо `no_new_privs` відсутній.

## За замовчуванням для середовищ виконання

| Runtime / платформа | Стан за замовчуванням | Типова поведінка | Поширені ручні послаблення |
| --- | --- | --- | --- |
| Docker Engine | Не увімкнено за замовчуванням | Увімкнюється явно за допомогою `--security-opt no-new-privileges=true` | не вказуючи прапорець, `--privileged` |
| Podman | Не увімкнено за замовчуванням | Увімкнюється явно через `--security-opt no-new-privileges` або еквівалентну конфігурацію безпеки | не вказуючи опцію, `--privileged` |
| Kubernetes | Контролюється політикою робочого навантаження | `allowPrivilegeEscalation: false` забезпечує дію захисту; багато робочих навантажень і досі залишають його увімкненим | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Слідує налаштуванням робочого навантаження Kubernetes | Зазвичай успадковується з контексту безпеки Pod | те саме, що в рядку Kubernetes |

Цей захист часто відсутній просто тому, що ніхто його не увімкнув, а не через відсутність підтримки з боку середовища виконання.
