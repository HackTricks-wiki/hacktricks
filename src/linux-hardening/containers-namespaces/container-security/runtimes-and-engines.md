# Контейнерні Runtimes, Engines, Builders і Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Одним із найбільших джерел плутанини в container security є те, що кілька цілком різних компонентів часто називають одним словом. "Docker" може означати формат image, CLI, daemon, build system, runtime stack або просто загальну концепцію containers. Для security work така неоднозначність є проблемою, оскільки різні рівні відповідають за різні механізми захисту. Breakout, спричинений некоректним bind mount, — це не те саме, що breakout через вразливість low-level runtime, і жоден із них не є тим самим, що помилка cluster policy у Kubernetes.

Ця сторінка розділяє ecosystem за ролями, щоб у решті розділу можна було точно визначати, де саме знаходиться певний захист або weakness.

## OCI Як Спільна Мова

Сучасні Linux container stacks часто взаємодіють, оскільки використовують набір OCI specifications. **OCI Image Specification** описує представлення images і layers. **OCI Runtime Specification** описує, як runtime має запускати process, зокрема namespaces, mounts, cgroups і security settings. **OCI Distribution Specification** стандартизує спосіб, у який registries надають доступ до content.

Це важливо, оскільки пояснює, чому container image, створений одним tool, часто можна запустити за допомогою іншого, а також чому кілька engines можуть використовувати один і той самий low-level runtime. Це також пояснює, чому security behavior може виглядати подібно в різних products: багато з них створюють однакову OCI runtime configuration і передають її тому самому невеликому набору runtimes.

## Low-Level OCI Runtimes

Low-level runtime — це компонент, найближчий до межі з kernel. Саме він створює namespaces, записує cgroup settings, застосовує capabilities і seccomp filters та зрештою виконує `execve()` для process контейнера. Коли люди обговорюють "container isolation" на механічному рівні, зазвичай вони мають на увазі саме цей layer, навіть якщо прямо цього не зазначають.

### `runc`

`runc` — це reference OCI runtime і досі найвідоміша реалізація. Він широко використовується в Docker, containerd і багатьох Kubernetes deployments. Значна частина public research та exploitation material спрямована на environments у стилі `runc` просто тому, що вони поширені, а також тому, що `runc` визначає baseline, який багато хто уявляє, коли думає про Linux container. Тому розуміння `runc` дає читачеві хорошу mental model класичної container isolation.

### `crun`

`crun` — це ще один OCI runtime, написаний мовою C і широко використовуваний у сучасних Podman environments. Його часто хвалять за хорошу підтримку cgroup v2, зручність rootless use і менші накладні витрати. З security perspective важливо не те, що він написаний іншою мовою, а те, що він виконує ту саму роль: перетворює OCI configuration на запущене process tree під керуванням kernel. Rootless Podman workflow часто здається безпечнішим не тому, що `crun` магічним чином виправляє все, а тому, що загальний stack навколо нього зазвичай сильніше орієнтований на user namespaces і least privilege.

### `runsc` Від gVisor

`runsc` — це runtime, який використовується gVisor. Тут boundary суттєво змінює своє значення. Замість того щоб передавати більшість syscalls безпосередньо до host kernel у звичайний спосіб, gVisor додає userspace kernel layer, який емулює або посередницьки обробляє значну частину Linux interface. У результаті це не звичайний `runc` container із кількома додатковими flags, а інша sandbox design, мета якої — зменшити attack surface host kernel. Compatibility та performance tradeoffs є частиною цього design, тому environments із `runsc` слід документувати інакше, ніж звичайні OCI runtime environments.

### `kata-runtime`

Kata Containers іще більше відсувають boundary, запускаючи workload усередині lightweight virtual machine. Адміністративно це все ще може виглядати як container deployment, а orchestration layers можуть і далі розглядати його як такий, але underlying isolation boundary ближчий до virtualization, ніж до класичного container із shared host kernel. Це робить Kata корисним, коли потрібна сильніша tenant isolation без відмови від container-centric workflows.

## Engines І Container Managers

Якщо low-level runtime — це компонент, який безпосередньо взаємодіє з kernel, то engine або manager — це компонент, із яким зазвичай взаємодіють users та operators. Він відповідає за image pulls, metadata, logs, networks, volumes, lifecycle operations і API exposure. Цей layer має величезне значення, оскільки багато компрометацій у реальних environments відбуваються саме тут: доступ до runtime socket або daemon API може бути еквівалентним host compromise, навіть якщо сам low-level runtime працює бездоганно.

### Docker Engine

Docker Engine — найвідоміша container platform для developers і одна з причин, чому container vocabulary стала такою Docker-centric. Типовий шлях виглядає як `docker` CLI до `dockerd`, який своєю чергою координує lower-level components, такі як `containerd` та OCI runtime. Історично Docker deployments часто були **rootful**, тому доступ до Docker socket був дуже потужним primitive. Саме тому значна частина практичних матеріалів із privilege escalation зосереджена на `docker.sock`: якщо process може попросити `dockerd` створити privileged container, змонтувати host paths або приєднатися до host namespaces, йому може взагалі не знадобитися kernel exploit.

### Podman

Podman було розроблено навколо більш daemonless model. З операційної точки зору це допомагає підкріпити ідею, що containers — це лише processes, якими керують через стандартні Linux mechanisms, а не через один довгоживучий privileged daemon. Podman також має значно сильнішу **rootless** model, ніж класичні Docker deployments, із яких багато хто починав навчання. Це не робить Podman автоматично безпечним, але суттєво змінює default risk profile, особливо в поєднанні з user namespaces, SELinux і `crun`.

### containerd

containerd — це основний runtime management component у багатьох сучасних stacks. Він використовується під Docker, а також є одним із домінуючих Kubernetes runtime backends. Він надає powerful APIs, керує images та snapshots і делегує фінальне створення process low-level runtime. У security discussions щодо containerd слід підкреслювати, що доступ до containerd socket або функціональності `ctr`/`nerdctl` може бути так само небезпечним, як доступ до Docker API, навіть якщо interface та workflow здаються менш "developer friendly".

### CRI-O

CRI-O має вужчу спеціалізацію, ніж Docker Engine. Замість general-purpose developer platform його створено для коректної реалізації Kubernetes Container Runtime Interface. Тому він особливо поширений у Kubernetes distributions і SELinux-heavy ecosystems, таких як OpenShift. З security perspective така вузька scope є корисною, оскільки зменшує conceptual clutter: CRI-O однозначно належить до layer "run containers for Kubernetes", а не до everything-platform.

### Incus, LXD І LXC

Incus/LXD/LXC systems варто відокремлювати від application containers у стилі Docker, оскільки їх часто використовують як **system containers**. Зазвичай очікується, що system container буде більше схожий на lightweight machine із повнішим userspace, long-running services, ширшим device exposure і більшою host integration. Механізми isolation усе ще є kernel primitives, але operational expectations відрізняються. Тому misconfigurations тут часто виглядають не як "bad app-container defaults", а як помилки у lightweight virtualization або host delegation.

### systemd-nspawn

systemd-nspawn посідає цікаве місце, оскільки є systemd-native і дуже корисний для testing, debugging та запуску OS-like environments. Це не домінуючий cloud-native production runtime, але він достатньо часто зустрічається в labs і distro-oriented environments, щоб заслуговувати на згадку. Для security analysis це ще одне нагадування, що concept "container" охоплює кілька ecosystems і operational styles.

### Apptainer / Singularity

Apptainer (раніше Singularity) поширений у research та HPC environments. Його trust assumptions, user workflow і execution model суттєво відрізняються від stack'ів, орієнтованих на Docker/Kubernetes. Зокрема, у таких environments часто дуже важливо дозволити users запускати packaged workloads, не надаючи їм широких privileged container-management powers. Якщо reviewer припускає, що кожне container environment — це фактично "Docker on a server", він серйозно неправильно зрозуміє такі deployments.

## Build-Time Tooling

У багатьох security discussions говорять лише про run time, але build-time tooling також має значення, оскільки визначає image contents, exposure build secrets і те, скільки trusted context буде вбудовано у фінальний artifact.

**BuildKit** і `docker buildx` — це сучасні build backends, які підтримують такі features, як caching, secret mounting, SSH forwarding і multi-platform builds. Це корисні features, але з security perspective вони також створюють місця, де secrets можуть leak у image layers або де надто broad build context може відкрити files, які взагалі не повинні були бути включені. **Buildah** відіграє подібну роль в OCI-native ecosystems, особливо разом із Podman, тоді як **Kaniko** часто використовується в CI environments, які не хочуть надавати build pipeline privileged Docker daemon.

Головний lesson полягає в тому, що image creation та image execution — це різні phases, але слабкий build pipeline може створити слабкий runtime posture задовго до запуску container.

## Orchestration — Це Інший Layer, А Не Runtime

Kubernetes не слід ототожнювати безпосередньо з runtime. Kubernetes — це orchestrator. Він планує Pods, зберігає desired state і виражає security policy через workload configuration. Потім kubelet взаємодіє з CRI implementation, такою як containerd або CRI-O, яка своєю чергою викликає low-level runtime, наприклад `runc`, `crun`, `runsc` або `kata-runtime`.

Це розділення важливе, оскільки багато людей помилково приписують protection "Kubernetes", хоча насправді його забезпечує node runtime, або звинувачують "containerd defaults" у поведінці, яка походить із Pod spec. На практиці фінальний security posture є composition: orchestrator запитує певну конфігурацію, runtime stack її транслює, а kernel зрештою її enforces.

## Чому Ідентифікація Runtime Важлива Під Час Assessment

Якщо рано ідентифікувати engine та runtime, багато подальших observations буде легше інтерпретувати. Rootless Podman container свідчить, що user namespaces, імовірно, є частиною цієї схеми. Docker socket, змонтований у workload, вказує, що API-driven privilege escalation є реалістичним шляхом. Вузол CRI-O/OpenShift одразу має змусити вас подумати про SELinux labels і restricted workload policy. Environment із gVisor або Kata має спонукати обережніше ставитися до припущення, що classic `runc` breakout PoC поводитиметься так само.

Тому одним із перших кроків у container assessment завжди має бути відповідь на два прості питання: **який component керує container** і **який runtime фактично запустив process**. Коли ці відповіді відомі, решту environment зазвичай стає значно легше аналізувати.

## Runtime Vulnerabilities

Не кожен container escape спричинений operator misconfiguration. Іноді vulnerable component — це сам runtime. Це важливо, оскільки workload може працювати з configuration, яка виглядає carefully налаштованою, і все одно бути exposed через low-level runtime flaw.

Класичним прикладом є **CVE-2019-5736** у `runc`, де malicious container міг перезаписати host `runc` binary, а потім чекати, поки наступний `docker exec` або подібний runtime invocation запустить attacker-controlled code. Exploit path суттєво відрізняється від простої помилки bind-mount або capability, оскільки використовує спосіб, у який runtime повторно входить у container process space під час обробки exec.<sup>[[1]](#references)</sup>

Minimal reproduction workflow з perspective red team виглядає так:
```bash
go build main.go
./main
```
Потім із host:
```bash
docker exec -it <container-name> /bin/sh
```
Ключовий висновок полягає не в точній реалізації історичного exploit, а в наслідках для оцінювання: якщо версія runtime вразлива, звичайного виконання коду всередині контейнера може бути достатньо для компрометації host, навіть якщо видима конфігурація контейнера не виглядає явно слабкою.

Нещодавні CVE у runtime, як-от `CVE-2024-21626` у `runc`, race conditions під час монтування в BuildKit і помилки парсингу в containerd, підтверджують ту саму тезу. Версія runtime та рівень встановлених patch є частиною межі безпеки, а не просто незначними аспектами обслуговування.

## References

- [1] [Breaking out of Docker via runC – Explaining CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)

{{#include ../../../banners/hacktricks-training.md}}
