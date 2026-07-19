# Контейнерні Runtimes, Engines, Builders та Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Одним із найбільших джерел плутанини у container security є те, що кілька повністю різних компонентів часто об'єднують під одним словом. "Docker" може означати формат image, CLI, daemon, build system, runtime stack або просто загальну ідею контейнерів. Для security work така неоднозначність є проблемою, оскільки різні рівні відповідають за різні захисти. Breakout, спричинений неправильним bind mount, — це не те саме, що breakout через vulnerability у low-level runtime, і жоден із них не є тим самим, що помилка cluster policy у Kubernetes.

Ця сторінка розділяє ecosystem за ролями, щоб у решті розділу можна було точно визначити, де саме знаходиться захист або weakness.

## OCI Як Спільна Мова

Сучасні Linux container stacks часто взаємодіють, оскільки використовують набір OCI specifications. **OCI Image Specification** описує, як представлені images і layers. **OCI Runtime Specification** описує, як runtime має запускати process, зокрема namespaces, mounts, cgroups і security settings. **OCI Distribution Specification** стандартизує спосіб, у який registries надають content.

Це важливо, оскільки пояснює, чому container image, зібраний одним tool, часто можна запустити іншим, а також чому кілька engines можуть використовувати той самий low-level runtime. Це також пояснює, чому security behavior може виглядати подібно в різних products: багато з них створюють однакову OCI runtime configuration і передають її тому самому невеликому набору runtimes.

## Low-Level OCI Runtimes

Low-level runtime — це компонент, найближчий до kernel boundary. Саме він створює namespaces, записує cgroup settings, застосовує capabilities і seccomp filters, а потім виконує `execve()` для container process. Коли люди обговорюють "container isolation" на механічному рівні, зазвичай вони мають на увазі саме цей layer, навіть якщо прямо цього не зазначають.

### `runc`

`runc` — це reference OCI runtime і досі найвідоміша реалізація. Він широко використовується в Docker, containerd і багатьох Kubernetes deployments. Значна частина public research та exploitation material орієнтується на `runc`-style environments просто тому, що вони поширені, а також тому, що `runc` визначає baseline, який багато хто уявляє, коли думає про Linux container. Тому розуміння `runc` дає читачеві чітку mental model класичної container isolation.

### `crun`

`crun` — ще один OCI runtime, написаний мовою C і широко використовуваний у сучасних Podman environments. Його часто відзначають за хорошу підтримку cgroup v2, зручність rootless operation і менші накладні витрати. З security perspective важливо не те, що він написаний іншою мовою, а те, що він виконує ту саму роль: перетворює OCI configuration на запущене process tree під керуванням kernel. Rootless Podman workflow часто здається безпечнішим не тому, що `crun` магічно виправляє все, а тому, що загальний stack навколо нього зазвичай сильніше орієнтований на user namespaces і least privilege.

### `runsc` Від gVisor

`runsc` — це runtime, який використовує gVisor. Тут boundary суттєво змінює своє значення. Замість того щоб передавати більшість syscalls безпосередньо до host kernel звичайним способом, gVisor вставляє userspace kernel layer, який емулює або посередницьки обробляє значну частину Linux interface. У результаті це не звичайний `runc` container із кількома додатковими flags, а інший sandbox design, призначений для зменшення attack surface host kernel. Compatibility і performance trade-offs є частиною цього design, тому environments, що використовують `runsc`, слід описувати інакше, ніж звичайні OCI runtime environments.

### `kata-runtime`

Kata Containers іще більше відсувають boundary, запускаючи workload усередині lightweight virtual machine. Адміністративно це все ще може виглядати як container deployment, а orchestration layers можуть і надалі розглядати його саме так, проте underlying isolation boundary більше відповідає virtualization, ніж класичному container із shared host kernel. Це робить Kata корисним, коли потрібна сильніша tenant isolation без відмови від container-centric workflows.

## Engines Та Container Managers

Якщо low-level runtime — це компонент, що безпосередньо взаємодіє з kernel, то engine або manager — це компонент, з яким зазвичай взаємодіють users та operators. Він обробляє image pulls, metadata, logs, networks, volumes, lifecycle operations і API exposure. Цей layer надзвичайно важливий, оскільки багато real-world compromises відбуваються саме тут: доступ до runtime socket або daemon API може бути еквівалентним host compromise, навіть якщо сам low-level runtime працює бездоганно.

### Docker Engine

Docker Engine — найвідоміша container platform для developers і одна з причин, чому container vocabulary стала настільки Docker-подібною. Типовий шлях має вигляд `docker` CLI → `dockerd`, який, своєю чергою, координує lower-level components, такі як `containerd` та OCI runtime. Історично Docker deployments часто були **rootful**, тому доступ до Docker socket був надзвичайно потужною primitive. Саме тому значна частина practical privilege-escalation material зосереджена на `docker.sock`: якщо process може попросити `dockerd` створити privileged container, змонтувати host paths або приєднатися до host namespaces, йому може взагалі не знадобитися kernel exploit.

### Podman

Podman створювався з орієнтацією на більш daemonless model. З операційної точки зору це допомагає закріпити ідею, що containers — це просто processes, якими керують через стандартні Linux mechanisms, а не через один довгоживучий privileged daemon. Podman також має набагато сильнішу **rootless** model, ніж класичні Docker deployments, з яких багато хто починав. Це не робить Podman автоматично safe, але суттєво змінює default risk profile, особливо в поєднанні з user namespaces, SELinux і `crun`.

### containerd

containerd — це core runtime management component у багатьох сучасних stacks. Він використовується під Docker і також є одним із домінуючих Kubernetes runtime backends. Він надає powerful APIs, керує images і snapshots та передає остаточне створення process до low-level runtime. Security discussions щодо containerd мають наголошувати, що доступ до containerd socket або функціональності `ctr`/`nerdctl` може бути настільки ж небезпечним, як і доступ до Docker API, навіть якщо interface та workflow здаються менш "developer friendly".

### CRI-O

CRI-O має вужчу спеціалізацію, ніж Docker Engine. Замість загальної developer platform він створений для коректної реалізації Kubernetes Container Runtime Interface. Через це він особливо поширений у Kubernetes distributions і SELinux-heavy ecosystems, таких як OpenShift. З security perspective така вузька scope є корисною, оскільки зменшує conceptual clutter: CRI-O чітко належить до layer "run containers for Kubernetes", а не до everything-platform.

### Incus, LXD Та LXC

Incus/LXD/LXC systems варто відокремлювати від Docker-style application containers, оскільки їх часто використовують як **system containers**. Від system container зазвичай очікують, що він більше нагадуватиме lightweight machine із повнішим userspace, long-running services, ширшим device exposure і масштабнішою host integration. Механізми isolation усе ще є kernel primitives, але operational expectations відрізняються. Тому misconfigurations тут часто виглядають не як "bad app-container defaults", а як помилки у lightweight virtualization або host delegation.

### systemd-nspawn

systemd-nspawn займає цікаве місце, оскільки є systemd-native і дуже корисний для testing, debugging та запуску OS-like environments. Це не домінуючий cloud-native production runtime, але він достатньо часто зустрічається в labs і distro-oriented environments, щоб згадати його окремо. Для security analysis це ще одне нагадування, що поняття "container" охоплює кілька ecosystems та operational styles.

### Apptainer / Singularity

Apptainer (раніше Singularity) поширений у research та HPC environments. Його trust assumptions, user workflow і execution model суттєво відрізняються від Docker/Kubernetes-centric stacks. Зокрема, у таких environments часто дуже важливо дозволити users запускати packaged workloads, не надаючи їм широких privileged container-management powers. Якщо reviewer припускає, що кожне container environment — це фактично "Docker on a server", він дуже неправильно зрозуміє такі deployments.

## Build-Time Tooling

Багато security discussions говорять лише про run time, але build-time tooling також має значення, оскільки саме він визначає image contents, exposure build secrets і те, скільки trusted context буде вбудовано у final artifact.

**BuildKit** і `docker buildx` — це сучасні build backends, які підтримують такі features, як caching, secret mounting, SSH forwarding і multi-platform builds. Це корисні features, але з security perspective вони також створюють місця, де secrets можуть leak у image layers або де надто широкий build context може розкрити files, які взагалі не повинні були бути включені. **Buildah** виконує подібну роль в OCI-native ecosystems, особливо разом із Podman, тоді як **Kaniko** часто використовується у CI environments, які не хочуть надавати build pipeline privileged Docker daemon.

Ключовий висновок полягає в тому, що image creation та image execution — це різні фази, але слабкий build pipeline може створити слабкий runtime posture задовго до запуску container.

## Orchestration — Це Інший Layer, А Не Runtime

Kubernetes не слід ототожнювати безпосередньо з runtime. Kubernetes — це orchestrator. Він планує Pods, зберігає desired state і виражає security policy через workload configuration. Після цього kubelet взаємодіє з CRI implementation, такою як containerd або CRI-O, яка, своєю чергою, викликає low-level runtime, наприклад `runc`, `crun`, `runsc` або `kata-runtime`.

Це розділення важливе, оскільки багато людей помилково приписують protection "Kubernetes", хоча насправді він enforced node runtime, або звинувачують "containerd defaults" у behavior, який походить із Pod spec. На практиці final security posture є композицією: orchestrator запитує певну конфігурацію, runtime stack її транслює, а kernel зрештою її enforce-ить.

## Чому Ідентифікація Runtime Важлива Під Час Assessment

Якщо на ранньому етапі визначити engine і runtime, багато подальших спостережень стають простішими для інтерпретації. Rootless Podman container вказує на те, що user namespaces, імовірно, є частиною картини. Docker socket, змонтований у workload, вказує на те, що API-driven privilege escalation є реалістичним шляхом. CRI-O/OpenShift node одразу має змусити вас подумати про SELinux labels і restricted workload policy. Середовище gVisor або Kata має змусити вас обережніше ставитися до припущення, що classic `runc` breakout PoC поводитиметься так само.

Саме тому одним із перших кроків у container assessment завжди має бути відповідь на два прості питання: **який component керує container** і **який runtime фактично запустив process**. Коли ці відповіді зрозумілі, решту environment зазвичай набагато легше проаналізувати.

## Runtime Vulnerabilities

Не кожен container escape є наслідком operator misconfiguration. Іноді vulnerable component — це сам runtime. Це важливо, оскільки workload може працювати з configuration, яка виглядає ретельно налаштованою, і все одно бути exposed через low-level runtime flaw.

Класичним прикладом є **CVE-2019-5736** у `runc`, де malicious container міг перезаписати host `runc` binary, а потім очікувати на подальший `docker exec` або подібний runtime invocation, щоб trigger attacker-controlled code. Exploit path суттєво відрізняється від простої помилки bind-mount або capabilities, оскільки він зловживає способом, у який runtime повторно входить у container process space під час обробки exec.

Minimal reproduction workflow з red-team perspective такий:
```bash
go build main.go
./main
```
Потім, із хоста:
```bash
docker exec -it <container-name> /bin/sh
```
Ключовий висновок полягає не в точній реалізації історичного exploit, а в наслідках для оцінювання: якщо версія runtime вразлива, звичайного виконання коду всередині контейнера може бути достатньо для компрометації хоста, навіть коли видима конфігурація контейнера не виглядає явно слабкою.

Нещодавні CVE у runtime, такі як `CVE-2024-21626` у `runc`, race conditions під час монтування в BuildKit і помилки парсингу в containerd, підтверджують те саме: версія runtime та рівень встановлених патчів є частиною межі безпеки, а не просто технічними деталями обслуговування.
{{#include ../../../banners/hacktricks-training.md}}
