# Runtimes, Engines, Builders I Sandboksy Kontenerów

{{#include ../../../banners/hacktricks-training.md}}

Jednym z największych źródeł nieporozumień w zakresie container security jest fakt, że kilka całkowicie różnych komponentów często określa się tym samym słowem. „Docker” może oznaczać format image, CLI, daemon, system buildowania, stack runtime albo po prostu ogólną ideę kontenerów. W pracy związanej z bezpieczeństwem taka niejednoznaczność stanowi problem, ponieważ różne warstwy odpowiadają za różne zabezpieczenia. Breakout spowodowany błędnym bind mountem nie jest tym samym co breakout wynikający z błędu low-level runtime, a żaden z nich nie jest tym samym co błąd polityki klastra w Kubernetes.

Ta strona rozdziela ekosystem według ról, aby w dalszej części można było precyzyjnie określać, gdzie faktycznie znajduje się dane zabezpieczenie lub słabość.

## OCI Jako Wspólny Język

Nowoczesne Linux container stacks często współpracują ze sobą, ponieważ korzystają z zestawu specyfikacji OCI. **OCI Image Specification** opisuje sposób reprezentowania image i layerów. **OCI Runtime Specification** opisuje sposób, w jaki runtime powinien uruchamiać proces, w tym namespaces, mounts, cgroups i ustawienia security. **OCI Distribution Specification** standaryzuje sposób, w jaki registry udostępniają content.

Jest to istotne, ponieważ wyjaśnia, dlaczego image zbudowany za pomocą jednego narzędzia często można uruchomić za pomocą innego oraz dlaczego kilka engines może korzystać z tego samego low-level runtime. Wyjaśnia to również, dlaczego zachowanie związane z security może wyglądać podobnie w różnych produktach: wiele z nich tworzy tę samą konfigurację OCI runtime i przekazuje ją do tego samego niewielkiego zestawu runtimes.

## Low-Level OCI Runtimes

Low-level runtime to komponent znajdujący się najbliżej granicy kernela. To on faktycznie tworzy namespaces, zapisuje ustawienia cgroups, stosuje capabilities i filtry seccomp, a na końcu wykonuje `execve()` dla procesu kontenera. Gdy ludzie omawiają „container isolation” na poziomie mechanicznym, zwykle właśnie o tej warstwie mówią, nawet jeśli nie wskazują tego wprost.

### `runc`

`runc` to referencyjny OCI runtime i nadal najbardziej znana implementacja. Jest szeroko używany przez Docker, containerd oraz wiele deploymentów Kubernetes. Duża część publicznych badań i materiałów dotyczących exploitation celuje w środowiska typu `runc`, po prostu dlatego, że są one powszechne, a `runc` wyznacza baseline, który wiele osób ma na myśli, wyobrażając sobie Linux container. Zrozumienie `runc` daje więc czytelnikowi solidny model mentalny klasycznego container isolation.

### `crun`

`crun` to kolejny OCI runtime, napisany w C i szeroko używany w nowoczesnych środowiskach Podman. Często chwali się go za dobre wsparcie dla cgroup v2, wygodną obsługę rootless oraz mniejszy narzut. Z perspektywy security istotne jest nie to, że został napisany w innym języku, lecz to, że nadal pełni tę samą funkcję: jest komponentem, który przekształca konfigurację OCI w działające drzewo procesów pod kontrolą kernela. Workflow rootless Podman często wydaje się bezpieczniejszy nie dlatego, że `crun` magicznie rozwiązuje wszystkie problemy, lecz dlatego, że otaczający go stack zwykle mocniej wykorzystuje user namespaces i least privilege.

### `runsc` Z gVisor

`runsc` to runtime używany przez gVisor. W tym przypadku granica zostaje znacząco zmieniona. Zamiast przekazywać większość syscalli bezpośrednio do host kernela w standardowy sposób, gVisor dodaje warstwę userspace kernel, która emuluje lub pośredniczy w dużej części Linux interface. Rezultatem nie jest standardowy `runc` container z kilkoma dodatkowymi flagami, lecz odmienny projekt sandboxa, którego celem jest ograniczenie attack surface host kernela. Kompromisy dotyczące compatibility i performance są częścią tego projektu, dlatego środowiska używające `runsc` należy opisywać inaczej niż standardowe środowiska OCI runtime.

### `kata-runtime`

Kata Containers przesuwają granicę jeszcze dalej, uruchamiając workload wewnątrz lightweight virtual machine. Z punktu widzenia administracji może to nadal wyglądać jak deployment kontenerowy, a warstwy orchestration mogą nadal traktować go w ten sposób, jednak podstawowa granica isolation jest bliższa virtualization niż klasycznemu kontenerowi współdzielącemu host kernel. Dzięki temu Kata jest przydatne, gdy potrzebna jest silniejsza tenant isolation bez rezygnowania z workflow opartego na kontenerach.

## Engines I Container Managers

Jeśli low-level runtime jest komponentem komunikującym się bezpośrednio z kernelem, engine lub manager jest komponentem, z którym zwykle kontaktują się użytkownicy i operatorzy. Obsługuje image pulls, metadata, logs, networks, volumes, operacje lifecycle oraz udostępnianie API. Ta warstwa ma ogromne znaczenie, ponieważ wiele rzeczywistych compromises ma miejsce właśnie tutaj: dostęp do runtime socket lub daemon API może być równoważny z compromise hosta, nawet jeśli sam low-level runtime działa bez zarzutu.

### Docker Engine

Docker Engine to najbardziej rozpoznawalna container platforma wśród developerów i jeden z powodów, dla których słownictwo związane z kontenerami stało się tak mocno ukształtowane przez Docker. Typowa ścieżka wygląda tak: CLI `docker` komunikuje się z `dockerd`, który następnie koordynuje komponenty niższego poziomu, takie jak `containerd` i OCI runtime. Historycznie deploymenty Docker często działały jako **rootful**, dlatego dostęp do Docker socket stanowił bardzo potężny primitive. Z tego powodu tak wiele praktycznych materiałów dotyczących privilege escalation koncentruje się na `docker.sock`: jeśli proces może poprosić `dockerd` o utworzenie privileged container, zamontowanie ścieżek hosta lub dołączenie do host namespaces, może w ogóle nie potrzebować kernel exploit.

### Podman

Podman został zaprojektowany wokół bardziej daemonless modelu. Operacyjnie pomaga to wzmacniać ideę, że kontenery są po prostu procesami zarządzanymi za pomocą standardowych mechanizmów Linux, a nie poprzez jeden długo działający privileged daemon. Podman ma również znacznie silniejsze wsparcie dla **rootless** niż klasyczne deploymenty Docker, od których wiele osób zaczynało naukę. Nie oznacza to, że Podman jest automatycznie bezpieczny, ale znacząco zmienia domyślny risk profile, szczególnie w połączeniu z user namespaces, SELinux i `crun`.

### containerd

containerd to podstawowy komponent zarządzania runtime w wielu nowoczesnych stackach. Jest używany przez Docker i stanowi jeden z dominujących Kubernetes runtime backends. Udostępnia powerful APIs, zarządza images i snapshots, a tworzenie końcowego procesu deleguje do low-level runtime. W dyskusjach dotyczących security containerd należy podkreślać, że dostęp do containerd socket lub funkcjonalności `ctr`/`nerdctl` może być równie niebezpieczny jak dostęp do Docker API, nawet jeśli interfejs i workflow wydają się mniej „developer friendly”.

### CRI-O

CRI-O jest bardziej wyspecjalizowany niż Docker Engine. Zamiast być general-purpose developer platform, został zbudowany wokół czystej implementacji Kubernetes Container Runtime Interface. Dzięki temu jest szczególnie powszechny w dystrybucjach Kubernetes i ekosystemach intensywnie wykorzystujących SELinux, takich jak OpenShift. Z perspektywy security ten węższy zakres jest przydatny, ponieważ ogranicza conceptual clutter: CRI-O jest przede wszystkim częścią warstwy „uruchamiania kontenerów dla Kubernetes”, a nie platformą do wszystkiego.

### Incus, LXD I LXC

Systemy Incus/LXD/LXC warto oddzielić od application containers w stylu Docker, ponieważ często używa się ich jako **system containers**. Od system container zwykle oczekuje się, że będzie przypominał lightweight machine z pełniejszym userspace, długo działającymi services, bogatszym dostępem do devices i szerszą integracją z hostem. Mechanizmy isolation nadal opierają się na kernel primitives, ale oczekiwania operacyjne są inne. W rezultacie misconfigurations w tych systemach często przypominają mniej „błędne domyślne ustawienia app-container”, a bardziej błędy w lightweight virtualization lub host delegation.

### systemd-nspawn

systemd-nspawn zajmuje interesujące miejsce, ponieważ jest natywny dla systemd i bardzo przydatny do testing, debugging oraz uruchamiania środowisk przypominających system operacyjny. Nie jest dominującym cloud-native production runtime, ale występuje wystarczająco często w labach i środowiskach zorientowanych na dystrybucje, aby zasługiwać na wzmiankę. Z punktu widzenia security analysis jest kolejnym przypomnieniem, że pojęcie „container” obejmuje wiele ekosystemów i stylów operacyjnych.

### Apptainer / Singularity

Apptainer (wcześniej Singularity) jest powszechny w środowiskach research i HPC. Jego trust assumptions, user workflow i execution model różnią się znacząco od stacków skoncentrowanych na Docker/Kubernetes. W szczególności środowiska te często przywiązują dużą wagę do umożliwienia użytkownikom uruchamiania packaged workloads bez przekazywania im szerokich privileged container-management powers. Jeśli reviewer założy, że każde środowisko kontenerowe to w zasadzie „Docker na serwerze”, bardzo łatwo błędnie zinterpretuje takie deploymenty.

## Build-Time Tooling

W wielu dyskusjach dotyczących security mówi się wyłącznie o runtime, jednak build-time tooling również ma znaczenie, ponieważ decyduje o zawartości image, exposure build secrets oraz o tym, jak dużo trusted context zostanie osadzone w final artifact.

**BuildKit** i `docker buildx` to nowoczesne build backends obsługujące takie funkcje jak caching, secret mounting, SSH forwarding oraz multi-platform builds. Są to przydatne funkcje, ale z perspektywy security tworzą również miejsca, w których secrets mogą wyciec do image layers, lub w których zbyt szeroki build context może ujawnić pliki, które nigdy nie powinny zostać dołączone. **Buildah** pełni podobną rolę w ekosystemach OCI-native, szczególnie w połączeniu z Podman, natomiast **Kaniko** jest często używane w środowiskach CI, które nie chcą przyznawać privileged Docker daemon do build pipeline.

Najważniejsza lekcja jest taka, że image creation i image execution to różne fazy, ale słaby build pipeline może doprowadzić do słabego runtime posture na długo przed uruchomieniem kontenera.

## Orchestration To Kolejna Warstwa, A Nie Runtime

Kubernetes nie powinien być utożsamiany z samym runtime. Kubernetes jest orchestrator. Planuje Pods, przechowuje desired state i wyraża security policy poprzez workload configuration. Następnie kubelet komunikuje się z implementacją CRI, taką jak containerd lub CRI-O, która z kolei wywołuje low-level runtime, taki jak `runc`, `crun`, `runsc` lub `kata-runtime`.

To rozdzielenie jest istotne, ponieważ wiele osób błędnie przypisuje zabezpieczenie „Kubernetes”, podczas gdy jest ono faktycznie egzekwowane przez node runtime, albo obwinia „containerd defaults” za zachowanie wynikające z Pod spec. W praktyce końcowy security posture jest złożeniem: orchestrator żąda określonej konfiguracji, runtime stack ją tłumaczy, a kernel ostatecznie ją egzekwuje.

## Dlaczego Identyfikacja Runtime Ma Znaczenie Podczas Assessment

Jeśli engine i runtime zostaną zidentyfikowane odpowiednio wcześnie, późniejsze obserwacje stają się łatwiejsze do interpretacji. Rootless Podman container sugeruje, że user namespaces prawdopodobnie odgrywają rolę. Docker socket zamontowany w workload sugeruje, że API-driven privilege escalation jest realną ścieżką. Node CRI-O/OpenShift powinien od razu kierować uwagę na SELinux labels i restricted workload policy. Środowisko gVisor lub Kata powinno skłonić do większej ostrożności przy założeniu, że klasyczny `runc` breakout PoC zadziała w ten sam sposób.

Dlatego jednym z pierwszych kroków podczas container assessment powinno być zawsze udzielenie odpowiedzi na dwa proste pytania: **który komponent zarządza kontenerem** oraz **który runtime faktycznie uruchomił proces**. Gdy odpowiedzi są już znane, resztę środowiska zwykle można znacznie łatwiej przeanalizować.

## Runtime Vulnerabilities

Nie każdy container escape wynika z misconfiguration operatora. Czasami podatnym komponentem jest sam runtime. Ma to znaczenie, ponieważ workload może działać z konfiguracją wyglądającą na staranną, a mimo to być narażony przez low-level runtime flaw.

Klasycznym przykładem jest **CVE-2019-5736** w `runc`, gdzie malicious container mógł nadpisać host `runc` binary, a następnie oczekiwać na późniejsze `docker exec` lub podobne wywołanie runtime, aby uruchomić attacker-controlled code. Ścieżka exploitation znacznie różni się od prostego błędu bind mount lub capabilities, ponieważ wykorzystuje sposób, w jaki runtime ponownie wchodzi w process space kontenera podczas obsługi exec.<sup>[[1]](#references)</sup>

Minimalny workflow reproduction z perspektywy red-team to:
```bash
go build main.go
./main
```
Następnie z hosta:
```bash
docker exec -it <container-name> /bin/sh
```
Kluczowa lekcja nie dotyczy dokładnej historycznej implementacji exploita, lecz wniosku z oceny: jeśli wersja runtime jest podatna, zwykłe wykonanie kodu wewnątrz kontenera może wystarczyć do przejęcia hosta, nawet gdy widoczna konfiguracja kontenera nie wygląda na rażąco słabą.

Najnowsze CVE dotyczące runtime, takie jak `CVE-2024-21626` w `runc`, wyścigi podczas montowania w BuildKit oraz błędy parsowania w containerd, wzmacniają ten sam przekaz. Wersja runtime i poziom poprawek są częścią granicy bezpieczeństwa, a nie jedynie kwestią utrzymania.

## Referencje

- [1] [Breaking out of Docker via runC – Explaining CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)

{{#include ../../../banners/hacktricks-training.md}}
