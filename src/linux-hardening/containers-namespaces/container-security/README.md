# Безпека контейнерів

{{#include ../../../banners/hacktricks-training.md}}

## Чим насправді є контейнер

Практично контейнер можна визначити так: контейнер — це **звичайне дерево процесів Linux**, запущене відповідно до спеціальної конфігурації у стилі OCI, завдяки чому воно бачить контрольовану файлову систему, контрольований набір ресурсів ядра та обмежену модель привілеїв. Процес може вважати себе PID 1, може вважати, що має власний мережевий стек, власне ім’я хоста та власні ресурси IPC, і навіть може працювати як root у власному user namespace. Але насправді це все ще процес хоста, який ядро планує так само, як і будь-який інший.

Саме тому безпека контейнерів фактично є вивченням того, як створюється ця ілюзія та як вона порушується. Якщо mount namespace налаштовано ненадійно, процес може бачити файлову систему хоста. Якщо user namespace відсутній або вимкнений, root усередині контейнера може бути надто безпосередньо зіставлений із root на хості. Якщо seccomp працює в режимі unconfined, а набір capabilities надто широкий, процес може отримати доступ до системних викликів і привілейованих функцій ядра, які мали залишатися недоступними. Якщо socket runtime змонтовано всередині контейнера, контейнеру може взагалі не знадобитися kernel breakout, оскільки він може просто попросити runtime запустити потужніший сусідній контейнер або безпосередньо змонтувати кореневу файлову систему хоста.

## Чим контейнери відрізняються від віртуальних машин

VM зазвичай має власне ядро та межу апаратної абстракції. Це означає, що гостьове ядро може аварійно завершити роботу, впасти або бути скомпрометованим без автоматичного отримання прямого контролю над ядром хоста. Контейнери не отримують окремого ядра. Натомість вони отримують ретельно відфільтроване та ізольоване за допомогою namespaces представлення того самого ядра, яке використовує хост. У результаті контейнери зазвичай легші, швидше запускаються, дають змогу щільніше розміщувати workloads на машині та краще підходять для короткоживучого розгортання застосунків. Ціною цього є те, що межа ізоляції значно безпосередніше залежить від правильної конфігурації хоста та runtime.

Це не означає, що контейнери є "insecure", а VM — "secure". Це означає, що модель безпеки відрізняється. Добре налаштований container stack із rootless execution, user namespaces, стандартним seccomp, суворим набором capabilities, без спільного використання host namespaces і з надійним застосуванням SELinux або AppArmor може бути дуже стійким. І навпаки, контейнер, запущений із `--privileged`, спільним використанням host PID/network, змонтованим усередині нього Docker socket і доступним для запису bind mount `/`, функціонально набагато ближчий до доступу host root, ніж до безпечно ізольованого application sandbox. Відмінність визначається рівнями, які було ввімкнено або вимкнено.

Також існує проміжний варіант, який читачам варто розуміти, оскільки він дедалі частіше трапляється в реальних середовищах. **Sandboxed container runtimes**, такі як **gVisor** і **Kata Containers**, навмисно посилюють межу ізоляції порівняно з класичним контейнером `runc`. gVisor розміщує userspace kernel layer між workload і багатьма інтерфейсами ядра хоста, тоді як Kata запускає workload усередині легкої віртуальної машини. Вони все ще використовуються через container ecosystems та orchestration workflows, але їхні властивості безпеки відрізняються від звичайних OCI runtimes, тому їх не слід подумки об’єднувати зі "звичайними Docker containers", ніби все працює однаково.

## Container Stack: кілька рівнів, а не один

Коли хтось каже "цей контейнер insecure", корисне уточнювальне питання: **який рівень зробив його insecure?** Containerized workload зазвичай є результатом спільної роботи кількох компонентів.

На верхньому рівні часто є **image build layer**, такий як BuildKit, Buildah або Kaniko, який створює OCI image та metadata. Над low-level runtime може бути **engine або manager**, наприклад Docker Engine, Podman, containerd, CRI-O, Incus або systemd-nspawn. У cluster environments також може бути **orchestrator**, такий як Kubernetes, який визначає запитаний security posture через workload configuration. Зрештою, саме **kernel** фактично забезпечує роботу namespaces, cgroups, seccomp і MAC policy.

Ця багаторівнева модель важлива для розуміння defaults. Обмеження може бути запитане Kubernetes, передане через CRI до containerd або CRI-O, перетворене на OCI spec wrapper-ом runtime і лише після цього застосоване `runc`, `crun`, `runsc` або іншим runtime до kernel. Коли defaults відрізняються між середовищами, часто це відбувається тому, що один із цих рівнів змінив фінальну конфігурацію. Тому той самий механізм може виглядати в Docker або Podman як CLI flag, у Kubernetes — як поле Pod або `securityContext`, а в lower-level runtime stacks — як OCI configuration, згенерована для workload. З цієї причини CLI examples у цьому розділі слід сприймати як **runtime-specific syntax для загальної container concept**, а не як універсальні flags, які підтримуються кожним tool.

## Справжня межа безпеки контейнера

На практиці безпека контейнерів забезпечується **комбінацією контролів**, а не одним ідеальним контролем. Namespaces ізолюють видимість. cgroups керують використанням ресурсів та обмежують його. Capabilities зменшують те, що насправді може робити процес, який виглядає привілейованим. seccomp блокує небезпечні системні виклики до того, як вони досягнуть ядра. AppArmor і SELinux додають Mandatory Access Control поверх звичайних перевірок DAC. `no_new_privs`, masked procfs paths і read-only system paths ускладнюють поширені ланцюжки privilege abuse та proc/sys abuse. Сам runtime також має значення, оскільки він визначає, як створюються mounts, sockets, labels і namespace joins.

Саме тому багато документації з container security здається повторюваною. Один і той самий escape chain часто залежить від кількох механізмів одночасно. Наприклад, writable host bind mount — це погано, але ситуація стає набагато гіршою, якщо контейнер також працює як справжній root на хості, має `CAP_SYS_ADMIN`, не обмежений seccomp і не обмежений SELinux або AppArmor. Так само host PID sharing є серйозною вразливістю, але для attacker він стає значно кориснішим у поєднанні з `CAP_SYS_PTRACE`, слабкими procfs protections або tools для входу в namespace, такими як `nsenter`. Тому правильний спосіб документувати цю тему — не повторювати ту саму атаку на кожній сторінці, а пояснювати внесок кожного рівня у фінальну межу безпеки.

## Як читати цей розділ

Розділ організовано від найзагальніших понять до найконкретніших.

Почніть з огляду runtime та ecosystem:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Потім перегляньте control planes і supply-chain surfaces, які часто визначають, чи взагалі attacker потрібен kernel escape:

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

Сторінки про namespaces окремо пояснюють kernel isolation primitives:

{{#ref}}
protections/namespaces/
{{#endref}}

Сторінки про cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths і read-only system paths пояснюють механізми, які зазвичай додаються поверх namespaces:

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

## Правильний підхід до первинної enumeration

Під час assessment containerized target набагато корисніше поставити невеликий набір точних технічних запитань, ніж одразу переходити до відомих escape PoCs. Спочатку визначте **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer або щось спеціалізованіше. Потім визначте **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` або іншу OCI-compatible implementation. Після цього перевірте, чи є середовище **rootful або rootless**, чи активні **user namespaces**, чи використовуються спільні **host namespaces**, які **capabilities** залишилися, чи ввімкнено **seccomp**, чи справді застосовується **MAC policy**, чи присутні **dangerous mounts або sockets**, а також чи може процес взаємодіяти з container runtime API.

Ці відповіді розповідають про реальний security posture набагато більше, ніж назва base image. У багатьох assessments можна передбачити ймовірне сімейство breakout ще до відкриття хоча б одного application file, просто зрозумівши фінальну конфігурацію контейнера.

## Охоплення

Цей розділ охоплює старий Docker-focused material в організації, орієнтованій на контейнери: runtime і daemon exposure, authorization plugins, image trust і build secrets, sensitive host mounts, distroless workloads, privileged containers та kernel protections, які зазвичай застосовуються під час container execution.
{{#include ../../../banners/hacktricks-training.md}}
