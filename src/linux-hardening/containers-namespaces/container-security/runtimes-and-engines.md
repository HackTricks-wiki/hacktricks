# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Одним із найбільших джерел плутанини в container security є те, що кілька абсолютно різних компонентів часто об'єднують під одним словом. "Docker" може означати формат image, CLI, daemon, build system, runtime stack або просто загальну ідею containers. Для security work така неоднозначність є проблемою, оскільки різні рівні відповідають за різні механізми захисту. Breakout, спричинений неправильним bind mount, — це не те саме, що breakout через вразливість low-level runtime, і жоден із них не є тим самим, що помилка cluster policy у Kubernetes.

На цій сторінці екосистему розділено за ролями, щоб у решті цього розділу можна було точно визначати, де саме знаходиться захист або weakness.

## OCI As The Common Language

Сучасні Linux container stacks часто взаємодіють, оскільки використовують набір OCI specifications. **OCI Image Specification** описує представлення images і layers. **OCI Runtime Specification** описує, як runtime має запускати process, зокрема namespaces, mounts, cgroups і security settings. **OCI Distribution Specification** стандартизує спосіб, у який registries надають доступ до content.

Це важливо, оскільки пояснює, чому container image, створений одним tool, часто можна запустити іншим, а також чому кілька engines можуть використовувати один і той самий low-level runtime. Це також пояснює, чому security behavior може виглядати подібно в різних products: багато з них створюють однакову OCI runtime configuration і передають її одному з того самого невеликого набору runtimes.

## Low-Level OCI Runtimes

Low-level runtime — це компонент, найближчий до межі kernel. Саме він створює namespaces, записує cgroup settings, застосовує capabilities і seccomp filters, а потім виконує `execve()` для container process. Коли люди обговорюють "container isolation" на механічному рівні, зазвичай вони мають на увазі саме цей layer, навіть якщо не говорять про це прямо.

### `runc`

`runc` — це reference OCI runtime і досі найвідоміша реалізація. Він широко використовується в Docker, containerd і багатьох Kubernetes deployments. Значна частина public research і exploitation material націлена на `runc`-style environments просто тому, що вони поширені, а також тому, що `runc` визначає baseline, який багато хто уявляє, коли думає про Linux container. Тому розуміння `runc` дає читачеві сильну mental model для класичної container isolation.

### `crun`

`crun` — це інший OCI runtime, написаний мовою C і широко використовуваний у сучасних Podman environments. Його часто хвалять за якісну підтримку cgroup v2, зручність rootless operation і менші накладні витрати. З security perspective важливо не те, що він написаний іншою мовою, а те, що він виконує ту саму роль: перетворює OCI configuration на running process tree під керуванням kernel. Rootless Podman workflow часто здається безпечнішим не тому, що `crun` магічно виправляє все, а тому, що загальний stack навколо нього зазвичай сильніше спирається на user namespaces і least privilege.

### `runsc` From gVisor

`runsc` — це runtime, який використовується gVisor. Тут boundary суттєво змінює своє значення. Замість того щоб передавати більшість syscalls безпосередньо до host kernel, як це зазвичай відбувається, gVisor додає userspace kernel layer, який емулює або посередницьки обробляє значні частини Linux interface. У результаті це не звичайний `runc` container із кількома додатковими flags, а інший sandbox design, мета якого — зменшити attack surface host kernel. Tradeoffs щодо compatibility і performance є частиною цього design, тому environments із `runsc` слід документувати інакше, ніж звичайні OCI runtime environments.

### `kata-runtime`

Kata Containers іще більше відсувають boundary, запускаючи workload усередині lightweight virtual machine. З адміністративної точки зору це все ще може виглядати як container deployment, а orchestration layers можуть і далі працювати з ним відповідним чином, але underlying isolation boundary ближчий до virtualization, ніж до класичного container, що використовує host kernel. Це робить Kata корисним, коли потрібна сильніша tenant isolation без відмови від container-centric workflows.

## Engines And Container Managers

Якщо low-level runtime — це компонент, який безпосередньо взаємодіє з kernel, то engine або manager — це компонент, з яким зазвичай взаємодіють users і operators. Він відповідає за image pulls, metadata, logs, networks, volumes, lifecycle operations і API exposure. Цей layer надзвичайно важливий, оскільки багато real-world compromises відбуваються саме тут: доступ до runtime socket або daemon API може бути еквівалентним host compromise, навіть якщо сам low-level runtime повністю справний.

### Docker Engine

Docker Engine — найбільш упізнавана container platform для developers і одна з причин, чому container vocabulary стала настільки Docker-подібною. Типовий шлях виглядає так: `docker` CLI звертається до `dockerd`, який, своєю чергою, координує lower-level components, такі як `containerd` і OCI runtime. Історично Docker deployments часто були **rootful**, тому доступ до Docker socket був дуже потужним primitive. Саме тому значна частина practical privilege-escalation material зосереджена на `docker.sock`: якщо process може попросити `dockerd` створити privileged container, змонтувати host paths або приєднатися до host namespaces, йому може взагалі не знадобитися kernel exploit.

### Podman

Podman створювався навколо більш daemonless model. Операційно це підсилює ідею, що containers — це лише processes, якими керують через стандартні Linux mechanisms, а не через один довгоживучий privileged daemon. Podman також має значно сильнішу **rootless** model, ніж класичні Docker deployments, з яких багато хто починав навчання. Це не робить Podman автоматично safe, але суттєво змінює default risk profile, особливо в поєднанні з user namespaces, SELinux і `crun`.

### containerd

containerd — це core runtime management component у багатьох сучасних stacks. Він використовується під Docker і є одним із домінуючих Kubernetes runtime backends. Він надає powerful APIs, керує images і snapshots та делегує остаточне створення process low-level runtime. Security discussions щодо containerd мають підкреслювати, що доступ до containerd socket або функціональності `ctr`/`nerdctl` може бути таким самим небезпечним, як доступ до Docker API, навіть якщо interface і workflow здаються менш "developer friendly".

### CRI-O

CRI-O є більш спеціалізованим, ніж Docker Engine. Замість general-purpose developer platform він створений навколо коректної реалізації Kubernetes Container Runtime Interface. Тому він особливо поширений у Kubernetes distributions і SELinux-heavy ecosystems, таких як OpenShift. З security perspective ця вузька спеціалізація корисна, оскільки зменшує conceptual clutter: CRI-O є саме частиною layer "run containers for Kubernetes", а не everything-platform.

### Incus, LXD, And LXC

Incus/LXD/LXC systems варто відокремлювати від Docker-style application containers, оскільки їх часто використовують як **system containers**. Від system container зазвичай очікують, що він буде схожий на lightweight machine із повнішим userspace, long-running services, ширшим device exposure і глибшою host integration. Механізми isolation все ще є kernel primitives, але operational expectations відрізняються. У результаті misconfigurations тут часто виглядають не як "bad app-container defaults", а як помилки у lightweight virtualization або host delegation.

### systemd-nspawn

systemd-nspawn займає цікаве місце, оскільки є systemd-native і дуже корисний для testing, debugging та запуску OS-like environments. Це не dominant cloud-native production runtime, але він досить часто трапляється в labs і distro-oriented environments, щоб заслуговувати на згадку. Для security analysis це ще одне нагадування, що concept "container" охоплює кілька ecosystems і operational styles.

### Apptainer / Singularity

Apptainer (раніше Singularity) поширений у research і HPC environments. Його trust assumptions, user workflow і execution model суттєво відрізняються від Docker/Kubernetes-centric stacks. Зокрема, у таких environments часто дуже важливо дозволити users запускати packaged workloads, не надаючи їм широких privileged container-management powers. Якщо reviewer припускає, що кожне container environment — це фактично "Docker on a server", він серйозно неправильно зрозуміє такі deployments.

## Build-Time Tooling

У багатьох security discussions говорять лише про run time, але build-time tooling також має значення, оскільки визначає image contents, exposure build secrets і те, скільки trusted context буде вбудовано в кінцевий artifact.

**BuildKit** і `docker buildx` — це сучасні build backends із підтримкою таких features, як caching, secret mounting, SSH forwarding і multi-platform builds. Це корисні features, але з security perspective вони також створюють місця, де secrets можуть leak в image layers або де надто broad build context може відкрити files, які взагалі не мали бути включені. **Buildah** виконує подібну роль в OCI-native ecosystems, особливо разом із Podman, тоді як **Kaniko** часто використовується в CI environments, які не хочуть надавати privileged Docker daemon build pipeline.

Ключовий висновок полягає в тому, що image creation і image execution — це різні phases, але weak build pipeline може створити weak runtime posture задовго до запуску container.

## Orchestration Is Another Layer, Not The Runtime

Не слід ототожнювати Kubernetes із самим runtime. Kubernetes — це orchestrator. Він планує Pods, зберігає desired state і виражає security policy через workload configuration. Після цього kubelet взаємодіє з CRI implementation, такою як containerd або CRI-O, яка, своєю чергою, викликає low-level runtime, наприклад `runc`, `crun`, `runsc` або `kata-runtime`.

Це розділення важливе, оскільки багато хто помилково приписує protection "Kubernetes", хоча насправді її enforce-ить node runtime, або звинувачує "containerd defaults" у behavior, який походить від Pod spec. На практиці кінцевий security posture є композицією: orchestrator запитує певну конфігурацію, runtime stack її транслює, а kernel зрештою її enforce-ить.

## Why Runtime Identification Matters During Assessment

Якщо рано визначити engine і runtime, багато подальших observations стають простішими для інтерпретації. Rootless Podman container свідчить, що user namespaces, імовірно, є частиною цієї схеми. Docker socket, змонтований у workload, вказує, що API-driven privilege escalation є реалістичним шляхом. CRI-O/OpenShift node одразу має змусити вас подумати про SELinux labels і restricted workload policy. Environment із gVisor або Kata має змусити вас обережніше ставитися до припущення, що classic `runc` breakout PoC поводитиметься так само.

Саме тому одним із перших кроків під час container assessment завжди має бути відповідь на два прості питання: **який component керує container** і **який runtime фактично запустив process**. Коли ці відповіді відомі, решту environment зазвичай набагато легше аналізувати.

## Runtime Vulnerabilities

Не кожен container escape спричинений operator misconfiguration. Іноді вразливим компонентом є сам runtime. Це важливо, оскільки workload може працювати з configuration, яка здається ретельно налаштованою, але все одно залишатися exposed через low-level runtime flaw.

Класичним прикладом є **CVE-2019-5736** у `runc`, де malicious container міг перезаписати host `runc` binary, а потім очікувати на наступний `docker exec` або подібний runtime invocation, щоб запустити attacker-controlled code. Exploit path суттєво відрізняється від простої помилки bind-mount або capabilities, оскільки він зловживає способом, у який runtime повторно входить у container process space під час обробки exec.<sup>[[1]](#references)</sup>

Minimal reproduction workflow із red-team perspective такий:
```bash
go build main.go
./main
```
Потім із хоста:
```bash
docker exec -it <container-name> /bin/sh
```
Ключовий висновок полягає не в точній реалізації історичного exploit, а в наслідках для оцінювання: якщо версія runtime є вразливою, звичайного виконання коду всередині контейнера може бути достатньо для компрометації host, навіть якщо видима конфігурація контейнера не виглядає явно слабкою.

Нещодавні CVE у runtime, такі як `CVE-2024-21626` у `runc`, race conditions під час монтування в BuildKit і помилки парсингу в containerd, підтверджують ту саму думку. Версія runtime та рівень встановлених патчів є частиною межі безпеки, а не просто технічними деталями обслуговування.

## References

- [1] [Вихід із Docker через runC — пояснення CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
