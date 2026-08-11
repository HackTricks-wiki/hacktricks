# Runtimes, Engines, Builders I Sandboxes Kontenerów

Jednym z największych źródeł nieporozumień w bezpieczeństwie kontenerów jest to, że kilka całkowicie różnych komponentów często określa się tym samym słowem. „Docker” może oznaczać format obrazu, CLI, daemon, system buildowania, stos runtime albo po prostu ogólną koncepcję kontenerów. W pracy związanej z bezpieczeństwem taka niejednoznaczność stanowi problem, ponieważ różne warstwy odpowiadają za różne zabezpieczenia. Breakout spowodowany nieprawidłowym bind mountem nie jest tym samym co breakout wynikający z błędu low-level runtime, a żaden z nich nie jest tym samym co błąd polityki klastra w Kubernetes.

Ta strona rozdziela ekosystem według ról, aby w dalszej części można było precyzyjnie określić, gdzie faktycznie znajduje się dane zabezpieczenie lub słabość.

## OCI As The Common Language

Współczesne stosy kontenerów Linux często współpracują ze sobą, ponieważ posługują się zestawem specyfikacji OCI. **OCI Image Specification** opisuje sposób reprezentowania obrazów i warstw. **OCI Runtime Specification** opisuje sposób, w jaki runtime powinien uruchamiać proces, w tym namespaces, mounts, cgroups i ustawienia bezpieczeństwa. **OCI Distribution Specification** standaryzuje sposób, w jaki registry udostępniają zawartość.

Jest to istotne, ponieważ wyjaśnia, dlaczego obraz kontenera zbudowany za pomocą jednego narzędzia często może zostać uruchomiony za pomocą innego oraz dlaczego kilka engines może współdzielić ten sam low-level runtime. Wyjaśnia to także, dlaczego zachowanie związane z bezpieczeństwem może wyglądać podobnie w różnych produktach: wiele z nich konstruuje tę samą konfigurację OCI runtime i przekazuje ją temu samemu niewielkiemu zbiorowi runtimes.

## Low-Level OCI Runtimes

Low-level runtime to komponent znajdujący się najbliżej granicy kernela. To on faktycznie tworzy namespaces, zapisuje ustawienia cgroups, stosuje capabilities i filtry seccomp, a następnie wykonuje `execve()` dla procesu kontenera. Gdy ludzie omawiają „container isolation” na poziomie mechanizmów, zwykle mówią właśnie o tej warstwie, nawet jeśli nie określają tego wprost.

### `runc`

`runc` jest referencyjnym OCI runtime i pozostaje najbardziej znaną implementacją. Jest szeroko używany przez Docker, containerd oraz wiele wdrożeń Kubernetes. Duża część publicznych badań i materiałów dotyczących exploitation koncentruje się na środowiskach typu `runc`, po prostu dlatego, że są one powszechne oraz że `runc` wyznacza bazowy model, który wiele osób ma na myśli, wyobrażając sobie Linux container. Zrozumienie `runc` daje więc czytelnikowi solidny model mentalny klasycznej izolacji kontenerów.

### `crun`

`crun` to kolejny OCI runtime, napisany w C i szeroko używany we współczesnych środowiskach Podman. Często jest ceniony za dobre wsparcie dla cgroup v2, wygodę pracy w trybie rootless oraz mniejszy narzut. Z perspektywy bezpieczeństwa ważne jest nie to, że został napisany w innym języku, lecz że nadal pełni tę samą rolę: jest komponentem, który zamienia konfigurację OCI w działające drzewo procesów pod kontrolą kernela. Workflow rootless Podman często wydaje się bezpieczniejszy nie dlatego, że `crun` magicznie rozwiązuje wszystkie problemy, lecz dlatego, że otaczający go stos zwykle mocniej opiera się na user namespaces i least privilege.

### `runsc` From gVisor

`runsc` jest runtime używanym przez gVisor. W tym przypadku granica izolacji zmienia się w istotny sposób. Zamiast przekazywać większość syscalls bezpośrednio do host kernela w typowy sposób, gVisor wstawia userspace kernel layer, który emuluje lub pośredniczy w obsłudze dużej części Linux interface. W rezultacie nie jest to zwykły kontener `runc` z kilkoma dodatkowymi flagami, lecz inny projekt sandboxa, którego celem jest ograniczenie attack surface host kernela. Kompromisy dotyczące kompatybilności i wydajności są częścią tego projektu, dlatego środowiska używające `runsc` należy dokumentować inaczej niż standardowe środowiska OCI runtime.

### `kata-runtime`

Kata Containers przesuwają granicę jeszcze dalej, uruchamiając workload wewnątrz lightweight virtual machine. Z administracyjnego punktu widzenia może to nadal wyglądać jak wdrożenie kontenerowe, a warstwy orchestration mogą nadal traktować je w ten sposób, jednak bazowa granica izolacji jest bliższa virtualizacji niż klasycznemu kontenerowi współdzielącemu host kernel. Dzięki temu Kata jest przydatne, gdy potrzebna jest silniejsza izolacja tenantów bez rezygnowania z workflow skoncentrowanych na kontenerach.

## Engines And Container Managers

Jeśli low-level runtime jest komponentem komunikującym się bezpośrednio z kernelem, to engine lub manager jest komponentem, z którym zwykle kontaktują się użytkownicy i operatorzy. Obsługuje image pulls, metadata, logs, networks, volumes, operacje lifecycle oraz udostępnianie API. Ta warstwa ma ogromne znaczenie, ponieważ wiele kompromitacji w rzeczywistych środowiskach ma miejsce właśnie tutaj: dostęp do runtime socket lub daemon API może być równoznaczny z kompromitacją hosta, nawet jeśli sam low-level runtime działa prawidłowo.

### Docker Engine

Docker Engine to najbardziej rozpoznawalna platforma kontenerowa dla developerów i jeden z powodów, dla których terminologia kontenerowa stała się tak silnie związana z Dockerem. Typowa ścieżka wygląda następująco: CLI `docker` komunikuje się z `dockerd`, który z kolei koordynuje komponenty niższego poziomu, takie jak `containerd` i OCI runtime. Historycznie wdrożenia Docker często działały w trybie **rootful**, dlatego dostęp do Docker socket stanowił bardzo potężny primitive. Z tego powodu tak wiele praktycznych materiałów dotyczących privilege escalation koncentruje się na `docker.sock`: jeśli proces może poprosić `dockerd` o utworzenie uprzywilejowanego kontenera, zamontowanie ścieżek hosta lub dołączenie do host namespaces, może w ogóle nie potrzebować kernel exploita.

### Podman

Podman został zaprojektowany wokół bardziej daemonless modelu. Operacyjnie pomaga to wzmacniać przekonanie, że kontenery są po prostu procesami zarządzanymi za pomocą standardowych mechanizmów Linux, a nie przez jeden długo działający uprzywilejowany daemon. Podman ma także znacznie silniejsze wsparcie dla **rootless** niż klasyczne wdrożenia Docker, od których wiele osób zaczynało naukę. Nie oznacza to, że Podman jest automatycznie bezpieczny, ale znacząco zmienia domyślny profil ryzyka, szczególnie w połączeniu z user namespaces, SELinux i `crun`.

### containerd

containerd to podstawowy komponent zarządzania runtime w wielu nowoczesnych stosach. Jest używany przez Docker i jest także jednym z dominujących backendów runtime w Kubernetes. Udostępnia potężne APIs, zarządza obrazami i snapshotami, a końcowe tworzenie procesu deleguje do low-level runtime. W dyskusjach dotyczących bezpieczeństwa containerd należy podkreślać, że dostęp do containerd socket lub funkcjonalności `ctr`/`nerdctl` może być równie niebezpieczny jak dostęp do Docker API, nawet jeśli interfejs i workflow wydają się mniej „developer friendly”.

### CRI-O

CRI-O ma węższy zakres niż Docker Engine. Zamiast być ogólną platformą dla developerów, został zbudowany wokół poprawnej implementacji Kubernetes Container Runtime Interface. Dzięki temu jest szczególnie powszechny w dystrybucjach Kubernetes oraz ekosystemach intensywnie wykorzystujących SELinux, takich jak OpenShift. Z perspektywy bezpieczeństwa ten węższy zakres jest przydatny, ponieważ ogranicza złożoność pojęciową: CRI-O należy przede wszystkim do warstwy „uruchamiania kontenerów dla Kubernetes”, a nie do platformy obsługującej wszystko.

### Incus, LXD, And LXC

Systemy Incus/LXD/LXC warto oddzielić od kontenerów aplikacyjnych w stylu Docker, ponieważ często używa się ich jako **system containers**. Od system containera zwykle oczekuje się, że będzie bardziej przypominał lightweight machine z pełniejszym userspace, długo działającymi usługami, bogatszym dostępem do urządzeń i szerszą integracją z hostem. Mechanizmy izolacji nadal opierają się na kernel primitives, ale oczekiwania operacyjne są inne. W rezultacie błędne konfiguracje częściej przypominają tu problemy z lightweight virtualization lub host delegation niż „nieprawidłowe wartości domyślne app containera”.

### systemd-nspawn

systemd-nspawn zajmuje interesujące miejsce, ponieważ jest natywny dla systemd i bardzo przydatny podczas testowania, debugowania oraz uruchamiania środowisk przypominających system operacyjny. Nie jest dominującym cloud-native production runtime, ale pojawia się wystarczająco często w labach i środowiskach zorientowanych na dystrybucje, aby zasługiwać na wzmiankę. Z punktu widzenia analizy bezpieczeństwa jest kolejnym przypomnieniem, że pojęcie „kontener” obejmuje wiele ekosystemów i stylów operacyjnych.

### Apptainer / Singularity

Apptainer (wcześniej Singularity) jest powszechny w środowiskach badawczych i HPC. Jego założenia dotyczące zaufania, workflow użytkownika oraz modelu wykonywania różnią się w istotny sposób od stosów skoncentrowanych na Docker/Kubernetes. W szczególności środowiska te często przywiązują dużą wagę do umożliwienia użytkownikom uruchamiania spakowanych workloadów bez przyznawania im szerokich uprzywilejowanych uprawnień do zarządzania kontenerami. Jeśli reviewer założy, że każde środowisko kontenerowe to zasadniczo „Docker na serwerze”, poważnie błędnie zrozumie takie wdrożenia.

## Build-Time Tooling

W wielu dyskusjach dotyczących bezpieczeństwa omawia się wyłącznie runtime, jednak build-time tooling również ma znaczenie, ponieważ wpływa na zawartość obrazów, ekspozycję build secrets oraz ilość zaufanego kontekstu osadzanego w finalnym artefakcie.

**BuildKit** i `docker buildx` to nowoczesne backendy build, obsługujące funkcje takie jak caching, secret mounting, SSH forwarding i multi-platform builds. Są to przydatne funkcje, ale z perspektywy bezpieczeństwa tworzą także miejsca, w których secrets mogą leak do image layers lub w których zbyt szeroki build context może ujawnić pliki, które nigdy nie powinny zostać dołączone. **Buildah** pełni podobną rolę w ekosystemach natywnych dla OCI, szczególnie wokół Podman, natomiast **Kaniko** jest często używane w środowiskach CI, które nie chcą przyznawać pipeline'owi build uprzywilejowanego Docker daemon.

Najważniejszy wniosek jest taki, że tworzenie obrazu i wykonywanie obrazu to różne fazy, ale słaby build pipeline może doprowadzić do słabej pozycji runtime na długo przed uruchomieniem kontenera.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes nie powinien być utożsamiany z samym runtime. Kubernetes jest orchestrator. Planuje Pods, przechowuje desired state i wyraża politykę bezpieczeństwa za pomocą konfiguracji workloadów. kubelet komunikuje się następnie z implementacją CRI, taką jak containerd lub CRI-O, która z kolei wywołuje low-level runtime, taki jak `runc`, `crun`, `runsc` lub `kata-runtime`.

To rozdzielenie ma znaczenie, ponieważ wiele osób błędnie przypisuje dane zabezpieczenie „Kubernetes”, mimo że jest ono faktycznie egzekwowane przez node runtime, albo obwinia „containerd defaults” za zachowanie wynikające z Pod spec. W praktyce końcowa pozycja bezpieczeństwa jest kompozycją: orchestrator żąda określonego działania, runtime stack je tłumaczy, a kernel ostatecznie je egzekwuje.

## Why Runtime Identification Matters During Assessment

Jeśli wcześnie zidentyfikujesz engine i runtime, wiele późniejszych obserwacji stanie się łatwiejszych do zinterpretowania. Kontener rootless Podman sugeruje, że user namespaces prawdopodobnie odgrywają rolę. Docker socket zamontowany w workloadzie sugeruje, że API-driven privilege escalation jest realistyczną ścieżką. Węzeł CRI-O/OpenShift powinien od razu skłaniać do myślenia o SELinux labels i restricted workload policy. Środowisko gVisor lub Kata powinno zwiększyć ostrożność przy założeniu, że klasyczny `runc` breakout PoC zadziała w taki sam sposób.

Dlatego jednym z pierwszych kroków podczas container assessment powinno być zawsze udzielenie odpowiedzi na dwa proste pytania: **który komponent zarządza kontenerem** oraz **który runtime faktycznie uruchomił proces**. Gdy odpowiedzi są już znane, resztę środowiska zwykle znacznie łatwiej przeanalizować.

## Runtime Vulnerabilities

Nie każdy container escape wynika z błędnej konfiguracji operatora. Czasami podatnym komponentem jest sam runtime. Ma to znaczenie, ponieważ workload może działać z konfiguracją wyglądającą na starannie przygotowaną, a mimo to być narażony na low-level runtime flaw.

Klasycznym przykładem jest **CVE-2019-5736** w `runc`, gdzie złośliwy kontener mógł nadpisać host `runc` binary, a następnie zaczekać, aż późniejsze wywołanie `docker exec` lub podobne uruchomienie runtime wyzwoli kod kontrolowany przez attackera. Ścieżka exploita znacznie różni się od prostego błędu bind-mount lub capability, ponieważ wykorzystuje sposób, w jaki runtime ponownie wchodzi do przestrzeni procesów kontenera podczas obsługi exec.<sup>[[1]](#references)</sup>

Minimalny workflow reprodukcji z perspektywy red-team to:
```bash
go build main.go
./main
```
Następnie z hosta:
```bash
docker exec -it <container-name> /bin/sh
```
Kluczowa lekcja nie dotyczy dokładnej historycznej implementacji exploita, lecz wniosku dla oceny bezpieczeństwa: jeśli wersja runtime jest podatna, zwykłe wykonanie kodu wewnątrz kontenera może wystarczyć do przejęcia hosta, nawet gdy widoczna konfiguracja kontenera nie wygląda rażąco słabo.

Najnowsze CVE dotyczące runtime, takie jak `CVE-2024-21626` w `runc`, wyścigi montowania w BuildKit oraz błędy parsowania w containerd, wzmacniają ten sam wniosek. Wersja runtime i poziom poprawek są częścią granicy bezpieczeństwa, a nie tylko kwestią utrzymania.

## References

- [1] [Wydostanie się z Dockera przez runC – wyjaśnienie CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
