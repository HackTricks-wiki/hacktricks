# Безпека контейнерів

{{#include ../../../banners/hacktricks-training.md}}

## Що Насправді Являє Собою Контейнер

Практичний спосіб визначити контейнер такий: контейнер — це **звичайне дерево процесів Linux**, запущене відповідно до спеціальної конфігурації у стилі OCI, завдяки чому воно бачить контрольовану файлову систему, контрольований набір ресурсів ядра та обмежену модель привілеїв. Процес може вважати себе PID 1, може вважати, що має власний мережевий стек, власне ім’я хоста й ресурси IPC, і навіть може працювати як root у власному user namespace. Але насправді це все одно процес хоста, який ядро планує так само, як і будь-який інший.

Саме тому безпека контейнерів фактично полягає у вивченні того, як створюється ця ілюзія і як вона руйнується. Якщо mount namespace недостатньо ізольований, процес може бачити файлову систему хоста. Якщо user namespace відсутній або вимкнений, root усередині контейнера може бути надто тісно зіставлений із root на хості. Якщо seccomp працює в режимі unconfined, а набір capabilities надто широкий, процес може отримати доступ до syscalls і привілейованих функцій ядра, які мали залишатися недоступними. Якщо socket runtime змонтований усередині контейнера, контейнеру може взагалі не знадобитися kernel breakout, оскільки він просто може попросити runtime запустити потужніший сусідній контейнер або безпосередньо змонтувати кореневу файлову систему хоста.

## Чим Контейнери Відрізняються Від Віртуальних Машин

VM зазвичай має власне ядро та межу апаратної абстракції. Це означає, що гостьове ядро може аварійно завершити роботу, панікувати або бути скомпрометованим без автоматичного отримання прямого контролю над ядром хоста. Контейнери не отримують окремого ядра. Натомість вони отримують ретельно відфільтрований і ізольований за допомогою namespaces вигляд того самого ядра, яке використовує хост. У результаті контейнери зазвичай легші, швидше запускаються, дають змогу щільніше розміщувати workloads на машині та краще підходять для короткоживучого розгортання застосунків. Ціна цього полягає в тому, що межа ізоляції значно безпосередніше залежить від правильної конфігурації хоста та runtime.

Це не означає, що контейнери є "небезпечними", а VM — "безпечними". Це означає, що модель безпеки відрізняється. Правильно налаштований стек контейнерів із rootless execution, user namespaces, типовим seccomp, суворим набором capabilities, без спільного використання host namespaces і з посиленим застосуванням SELinux або AppArmor може бути дуже надійним. І навпаки, контейнер, запущений із `--privileged`, спільним host PID/network, змонтованим усередині Docker socket і доступним для запису bind mount `/`, функціонально набагато ближчий до доступу root на хості, ніж до безпечно ізольованого sandbox застосунку. Відмінність визначається шарами, які були ввімкнені або вимкнені.

Існує також проміжний варіант, який читачам варто розуміти, оскільки він дедалі частіше трапляється в реальних середовищах. **Sandboxed container runtimes**, такі як **gVisor** і **Kata Containers**, навмисно посилюють межу захисту порівняно з класичним контейнером `runc`. gVisor розміщує userspace kernel layer між workload і багатьма інтерфейсами ядра хоста, тоді як Kata запускає workload усередині легкої віртуальної машини. Вони все ще використовуються через container ecosystems і workflows оркестрації, але їхні властивості безпеки відрізняються від звичайних OCI runtimes, тому їх не слід подумки об’єднувати зі "звичайними Docker containers", ніби все працює однаково.

## Стек Контейнерів: Кілька Шарів, А Не Один

Коли хтось каже "цей контейнер небезпечний", корисне наступне запитання: **який саме шар зробив його небезпечним?** Containerized workload зазвичай є результатом спільної роботи кількох компонентів.

На верхньому рівні часто є **image build layer**, наприклад BuildKit, Buildah або Kaniko, який створює OCI image та metadata. Над low-level runtime може бути **engine або manager**, наприклад Docker Engine, Podman, containerd, CRI-O, Incus або systemd-nspawn. У cluster environments також може бути **orchestrator**, наприклад Kubernetes, який визначає запитаний security posture через workload configuration. Нарешті, саме **kernel** фактично застосовує namespaces, cgroups, seccomp і MAC policy.

Ця багатошарова модель важлива для розуміння defaults. Обмеження може бути запитане Kubernetes, передане через CRI за допомогою containerd або CRI-O, перетворене на OCI spec wrapper-ом runtime і лише потім застосоване `runc`, `crun`, `runsc` або іншим runtime до kernel. Коли defaults відрізняються між середовищами, це часто відбувається тому, що один із цих шарів змінив фінальну конфігурацію. Тому той самий механізм може виглядати в Docker або Podman як CLI flag, у Kubernetes — як поле Pod або `securityContext`, а в lower-level runtime stacks — як OCI configuration, згенерована для workload. З цієї причини CLI examples у цьому розділі слід читати як **runtime-specific syntax для загальної концепції контейнера**, а не як універсальні flags, які підтримує кожен інструмент.

## Справжня Межа Безпеки Контейнера

На практиці безпека контейнерів забезпечується **комплексом накладених один на одного controls**, а не одним ідеальним control. Namespaces ізолюють видимість. cgroups керують використанням ресурсів і обмежують його. Capabilities зменшують те, що насправді може робити процес, який виглядає привілейованим. seccomp блокує небезпечні syscalls до того, як вони досягнуть kernel. AppArmor і SELinux додають Mandatory Access Control поверх звичайних перевірок DAC. `no_new_privs`, masked procfs paths і read-only system paths ускладнюють поширені ланцюжки зловживання привілеями та proc/sys. Сам runtime також має значення, оскільки він визначає, як створюються mounts, sockets, labels і joins до namespaces.

Саме тому значна частина документації з безпеки контейнерів здається повторюваною. Один і той самий escape chain часто залежить від кількох механізмів одночасно. Наприклад, writable host bind mount — це погано, але ситуація стає набагато гіршою, якщо контейнер також працює як справжній root на хості, має `CAP_SYS_ADMIN`, не обмежений seccomp і не захищений SELinux або AppArmor. Так само спільне використання host PID є серйозною вразливістю, але воно стає значно кориснішим для attacker, якщо поєднується з `CAP_SYS_PTRACE`, слабким захистом procfs або tools для входу в namespaces, такими як `nsenter`. Тому правильний спосіб документувати цю тему — не повторювати ту саму attack на кожній сторінці, а пояснювати внесок кожного шару у фінальну межу безпеки.

## Як Читати Цей Розділ

Розділ організовано від найзагальніших концепцій до найспецифічніших.

Почніть з огляду runtime та ecosystem:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Потім перегляньте control planes і supply-chain surfaces, які часто визначають, чи потрібно attacker взагалі виконувати kernel escape:

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

Потім перейдіть до моделі захисту:

{{#ref}}
protections/
{{#endref}}

Сторінки про namespaces окремо пояснюють примітиви ізоляції kernel:

{{#ref}}
protections/namespaces/
{{#endref}}

Сторінки про cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths і read-only system paths пояснюють механізми, які зазвичай накладаються поверх namespaces:

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

## Правильний Початковий Підхід До Enumeration

Під час assessment containerized target набагато корисніше поставити невеликий набір точних technical questions, ніж одразу переходити до відомих escape PoCs. Спочатку визначте **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer або щось спеціалізованіше. Потім визначте **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` або іншу OCI-compatible implementation. Після цього перевірте, чи є середовище **rootful або rootless**, чи активні **user namespaces**, чи використовуються спільно будь-які **host namespaces**, які **capabilities** залишилися, чи ввімкнено **seccomp**, чи **MAC policy** справді застосовується, чи присутні **небезпечні mounts або sockets**, а також чи може процес взаємодіяти з container runtime API.

Ці відповіді повідомлять про реальний security posture набагато більше, ніж назва base image. У багатьох assessments можна передбачити ймовірну breakout family ще до перегляду будь-якого application file, просто зрозумівши фінальну container configuration.

## Охоплення

Цей розділ охоплює старий Docker-focused матеріал у container-oriented організації: runtime і daemon exposure, authorization plugins, image trust і build secrets, sensitive host mounts, distroless workloads, privileged containers, а також kernel protections, які зазвичай накладаються на container execution.

{{#include ../../../banners/hacktricks-training.md}}
