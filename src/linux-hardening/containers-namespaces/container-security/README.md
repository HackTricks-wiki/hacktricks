# Безпека контейнерів

{{#include ../../../banners/hacktricks-training.md}}

## Чим насправді є контейнер

Практично контейнер можна визначити так: контейнер — це **звичайне дерево процесів Linux**, запущене відповідно до певної конфігурації у стилі OCI, завдяки чому воно бачить контрольовану файлову систему, контрольований набір ресурсів ядра та обмежену модель привілеїв. Процес може вважати себе PID 1, вважати, що має власний мережевий стек, власне ім'я хоста та власні ресурси IPC, а також навіть працювати як root у власному user namespace. Але фактично це все одно процес хоста, який ядро планує так само, як і будь-який інший.

Саме тому безпека контейнерів фактично полягає у вивченні того, як створюється ця ілюзія і як вона дає збій. Якщо mount namespace налаштований недостатньо ізольовано, процес може побачити файлову систему хоста. Якщо user namespace відсутній або вимкнений, root усередині контейнера може бути надто тісно пов'язаний із root на хості. Якщо seccomp працює без обмежень, а набір capabilities занадто широкий, процес може отримати доступ до системних викликів і привілейованих функцій ядра, які мали залишатися недоступними. Якщо сокет runtime змонтований усередині контейнера, контейнеру може взагалі не знадобитися kernel breakout, оскільки він зможе просто попросити runtime запустити привілейованіший sibling container або безпосередньо змонтувати кореневу файлову систему хоста.

## Відмінності контейнерів від віртуальних машин

VM зазвичай має власне ядро та апаратно-абстракційний кордон. Це означає, що гостьове ядро може аварійно завершитися, перейти в стан panic або бути скомпрометованим без автоматичного надання прямого контролю над ядром хоста. Контейнери не отримують окремого ядра. Натомість вони отримують ретельно відфільтроване представлення того самого ядра з namespace-ізоляцією, яке використовує хост. У результаті контейнери зазвичай легші, швидше запускаються, дають змогу щільніше розміщувати workloads на машині та краще підходять для короткоживучого розгортання застосунків. Ціною цього є те, що межа ізоляції набагато сильніше залежить від правильної конфігурації хоста та runtime.

Це не означає, що контейнери є "небезпечними", а VM — "безпечними". Це означає, що моделі безпеки відрізняються. Добре налаштований container stack із rootless execution, user namespaces, стандартним seccomp, суворим набором capabilities, без спільного використання host namespaces і з надійним застосуванням SELinux або AppArmor може бути дуже стійким. І навпаки, контейнер, запущений із `--privileged`, спільним використанням host PID/network, змонтованим усередині нього Docker socket і доступним для запису bind mount `/`, функціонально набагато ближчий до доступу host root, ніж до безпечно ізольованого application sandbox. Різниця виникає через шари, які були ввімкнені або вимкнені.

Існує також проміжний варіант, який читачам варто розуміти, оскільки в реальних середовищах він трапляється дедалі частіше. **Sandboxed container runtimes**, такі як **gVisor** і **Kata Containers**, навмисно посилюють межу ізоляції порівняно зі звичайним контейнером `runc`. gVisor розміщує userspace kernel layer між workload і багатьма інтерфейсами ядра хоста, тоді як Kata запускає workload усередині легкої віртуальної машини. Вони все ще використовуються через container ecosystems і workflows оркестрації, але їхні властивості безпеки відрізняються від звичайних OCI runtimes, тому не слід подумки об'єднувати їх зі "звичайними Docker containers", ніби все працює однаково.

## Container Stack: кілька шарів, а не один

Коли хтось каже, що "цей контейнер небезпечний", корисне наступне запитання: **який саме шар зробив його небезпечним?** Containerized workload зазвичай є результатом спільної роботи кількох компонентів.

На верхньому рівні часто розташований **image build layer**, наприклад BuildKit, Buildah або Kaniko, який створює OCI image і метадані. Над low-level runtime може бути **engine або manager**, наприклад Docker Engine, Podman, containerd, CRI-O, Incus або systemd-nspawn. У cluster environments також може бути **orchestrator**, наприклад Kubernetes, який визначає запитаний security posture через конфігурацію workload. Зрештою, саме **kernel** фактично застосовує namespaces, cgroups, seccomp і MAC policy.

Ця багатошарова модель важлива для розуміння defaults. Обмеження може бути запитане Kubernetes, передане через CRI до containerd або CRI-O, перетворене на OCI spec wrapper-ом runtime і лише після цього застосоване `runc`, `crun`, `runsc` або іншим runtime до kernel. Коли defaults відрізняються між середовищами, часто це відбувається тому, що один із цих шарів змінив фінальну конфігурацію. Тому один і той самий механізм може виглядати в Docker або Podman як CLI flag, у Kubernetes — як поле Pod або `securityContext`, а в low-level runtime stacks — як OCI configuration, згенерована для workload. Через це CLI examples у цьому розділі слід сприймати як **runtime-specific syntax для загальної концепції контейнера**, а не як універсальні flags, підтримувані кожним інструментом.

## Справжня межа безпеки контейнера

На практиці безпека контейнерів забезпечується **комплексом взаємопов'язаних контролів**, а не одним ідеальним контролем. Namespaces ізолюють видимість. cgroups керують використанням ресурсів і обмежують його. Capabilities зменшують те, що насправді може робити процес, який виглядає привілейованим. seccomp блокує небезпечні системні виклики до того, як вони досягнуть ядра. AppArmor і SELinux додають Mandatory Access Control поверх звичайних перевірок DAC. `no_new_privs`, masked procfs paths і read-only system paths ускладнюють поширені ланцюжки зловживання привілеями та proc/sys. Сам runtime також має значення, оскільки він визначає, як створюються mounts, sockets, labels і joins до namespaces.

Саме тому значна частина документації з безпеки контейнерів здається повторюваною. Один і той самий escape chain часто залежить від кількох механізмів одночасно. Наприклад, доступний для запису host bind mount — це погано, але ситуація стає набагато гіршою, якщо контейнер також працює як справжній root на хості, має `CAP_SYS_ADMIN`, не обмежений seccomp і не контролюється SELinux або AppArmor. Так само спільне використання host PID є серйозною вразливістю, але для attacker воно стає значно кориснішим у поєднанні з `CAP_SYS_PTRACE`, слабким захистом procfs або такими namespace-entry tools, як `nsenter`. Тому правильний спосіб документувати цю тему — не повторювати ту саму атаку на кожній сторінці, а пояснювати внесок кожного шару у фінальну межу безпеки.

## Як читати цей розділ

Розділ організовано від найбільш загальних концепцій до найбільш специфічних.

Почніть з огляду runtime та ecosystem:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Потім перегляньте control planes і supply-chain surfaces, які часто визначають, чи взагалі знадобиться attacker kernel escape:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
authorization-plugins.md
{{#endref}}

{{#ref}}
image-security-and-secrets.md
{{#endref}}

{{#ref}}
assessment-and-hardening.md
{{#endref}}

Після цього переходьте до моделі захисту:

{{#ref}}
protections/
{{#endref}}

Сторінки про namespaces пояснюють окремі kernel isolation primitives:

{{#ref}}
protections/namespaces/
{{#endref}}

На сторінках про cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths і read-only system paths пояснюються механізми, які зазвичай накладаються поверх namespaces:

{{#ref}}
protections/cgroups.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/no-new-privileges.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
distroless.md
{{#endref}}

{{#ref}}
privileged-containers.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Правильний підхід до початкової enumeration

Під час assessment containerized target набагато корисніше поставити невеликий набір точних технічних запитань, ніж одразу переходити до відомих escape PoCs. Спочатку визначте **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer або щось спеціалізованіше. Потім визначте **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` або іншу OCI-compatible implementation. Після цього перевірте, чи є середовище **rootful або rootless**, чи активні **user namespaces**, чи спільно використовуються **host namespaces**, які **capabilities** залишилися, чи ввімкнено **seccomp**, чи справді застосовується **MAC policy**, чи присутні **небезпечні mounts або sockets**, а також чи може процес взаємодіяти з container runtime API.

Ці відповіді дають набагато більше інформації про реальний security posture, ніж назва base image. У багатьох assessment можна передбачити ймовірний breakout family ще до читання першого application file, просто зрозумівши фінальну конфігурацію контейнера.

## Охоплення

Цей розділ охоплює старий Docker-focused матеріал, організований за container-oriented принципом: runtime і daemon exposure, authorization plugins, image trust і build secrets, sensitive host mounts, distroless workloads, privileged containers, а також kernel protections, які зазвичай накладаються на виконання контейнерів.

{{#include ../../../banners/hacktricks-training.md}}
