# Runtime’y kontenerów, silniki, buildery i sandboxy

{{#include ../../../banners/hacktricks-training.md}}

Jednym z największych źródeł nieporozumień w bezpieczeństwie kontenerów jest utożsamianie kilku całkowicie różnych komponentów z tym samym słowem. „Docker” może oznaczać format obrazu, CLI, daemon, system build, stos runtime, a nawet samą ogólną ideę kontenerów. W kontekście bezpieczeństwa ta niejednoznaczność stanowi problem, ponieważ różne warstwy odpowiadają za różne zabezpieczenia. Container breakout spowodowany błędnym bind mountem to nie to samo co breakout wynikający z błędu low-level runtime, a żaden z nich nie jest tym samym co błąd polityki klastra w Kubernetes.

Ta strona rozdziela ekosystem według ról, aby w dalszej części można było precyzyjnie wskazać, gdzie faktycznie znajduje się dane zabezpieczenie lub słabość.

## OCI jako wspólny język

Współczesne stosy kontenerów Linux często współpracują ze sobą, ponieważ korzystają ze zbioru specyfikacji OCI. **OCI Image Specification** opisuje sposób reprezentowania obrazów i warstw. **OCI Runtime Specification** opisuje sposób uruchamiania procesu przez runtime, w tym namespaces, mounty, cgroups i ustawienia bezpieczeństwa. **OCI Distribution Specification** standaryzuje sposób, w jaki registry udostępniają zawartość.

Ma to znaczenie, ponieważ wyjaśnia, dlaczego obraz kontenera zbudowany jednym narzędziem często można uruchomić za pomocą innego oraz dlaczego kilka silników może współdzielić ten sam low-level runtime. Wyjaśnia również, dlaczego zachowanie związane z bezpieczeństwem może wyglądać podobnie w różnych produktach: wiele z nich konstruuje tę samą konfigurację OCI runtime i przekazuje ją temu samemu niewielkiemu zbiorowi runtime’ów.

## Low-Level OCI Runtimes

Low-level runtime to komponent znajdujący się najbliżej granicy kernela. To on faktycznie tworzy namespaces, zapisuje ustawienia cgroups, stosuje capabilities i filtry seccomp, a na końcu wykonuje `execve()` dla procesu kontenera. Gdy ludzie omawiają „izolację kontenerów” na poziomie mechanicznym, zwykle mają na myśli właśnie tę warstwę, nawet jeśli nie mówią tego wprost.

### `runc`

`runc` to referencyjny OCI runtime i nadal najbardziej znana implementacja. Jest szeroko używany przez Docker, containerd i wiele wdrożeń Kubernetes. Duża część publicznych badań oraz materiałów dotyczących exploitationu koncentruje się na środowiskach typu `runc`, ponieważ są one powszechne, a `runc` wyznacza bazowy model, który wiele osób ma na myśli, wyobrażając sobie kontener Linux. Zrozumienie `runc` daje więc czytelnikowi solidny model mentalny klasycznej izolacji kontenerów.

### `crun`

`crun` to kolejny OCI runtime, napisany w C i szeroko używany we współczesnych środowiskach Podman. Często docenia się go za dobre wsparcie dla cgroup v2, wygodę pracy w trybie rootless i mniejszy narzut. Z perspektywy bezpieczeństwa ważne jest nie to, że został napisany w innym języku, lecz że pełni tę samą rolę: jest komponentem, który zamienia konfigurację OCI w działające drzewo procesów pod kontrolą kernela. Workflow rootless Podman często sprawia wrażenie bezpieczniejszego nie dlatego, że `crun` magicznie rozwiązuje wszystkie problemy, lecz dlatego, że otaczający go stos zwykle mocniej opiera się na user namespaces i least privilege.

### `runsc` z gVisor

`runsc` to runtime używany przez gVisor. W tym przypadku granica izolacji zmienia się w istotny sposób. Zamiast przekazywać większość syscalli bezpośrednio do hostowego kernela, jak ma to miejsce zazwyczaj, gVisor wprowadza userspace kernel, który emuluje lub pośredniczy w dużej części interfejsu Linux. Rezultatem nie jest zwykły kontener `runc` z kilkoma dodatkowymi flagami, lecz inny projekt sandboxa, którego celem jest zmniejszenie attack surface hostowego kernela. Kompatybilność i kompromisy wydajnościowe są częścią tego projektu, dlatego środowiska korzystające z `runsc` powinny być dokumentowane inaczej niż standardowe środowiska OCI runtime.

### `kata-runtime`

Kata Containers przesuwają granicę jeszcze dalej, uruchamiając workload wewnątrz lekkiej maszyny wirtualnej. Z punktu widzenia administracji może to nadal wyglądać jak wdrożenie kontenerowe, a warstwy orkiestracji mogą nadal traktować je w ten sposób, jednak podstawowa granica izolacji jest bliższa wirtualizacji niż klasycznemu kontenerowi współdzielącemu kernel hosta. Dzięki temu Kata jest przydatne, gdy wymagana jest silniejsza izolacja tenantów bez rezygnacji z workflow zorientowanych na kontenery.

## Silniki i menedżery kontenerów

Jeśli low-level runtime jest komponentem komunikującym się bezpośrednio z kernelem, silnik lub manager jest komponentem, z którym zwykle kontaktują się użytkownicy i operatorzy. Obsługuje pobieranie obrazów, metadane, logi, sieci, wolumeny, operacje lifecycle oraz udostępnianie API. Ta warstwa ma ogromne znaczenie, ponieważ wiele rzeczywistych kompromitacji następuje właśnie tutaj: dostęp do runtime socket lub API daemona może być równoważny przejęciu hosta, nawet jeśli sam low-level runtime działa prawidłowo.

### Docker Engine

Docker Engine to najbardziej rozpoznawalna platforma kontenerowa wśród developerów i jeden z powodów, dla których terminologia kontenerowa stała się tak silnie związana z Dockerem. Typowa ścieżka wygląda następująco: CLI `docker` komunikuje się z `dockerd`, który z kolei koordynuje komponenty niższego poziomu, takie jak `containerd` i OCI runtime. Historycznie wdrożenia Docker często działały w trybie **rootful**, dlatego dostęp do Docker socket był bardzo potężnym prymitywem. Z tego powodu tak wiele praktycznych materiałów dotyczących privilege escalation koncentruje się na `docker.sock`: jeśli proces może poprosić `dockerd` o utworzenie uprzywilejowanego kontenera, zamontowanie ścieżek hosta lub dołączenie do host namespaces, może w ogóle nie potrzebować kernel exploita.

### Podman

Podman został zaprojektowany wokół modelu bez daemona. Operacyjnie pomaga to wzmacniać ideę, że kontenery są po prostu procesami zarządzanymi za pomocą standardowych mechanizmów Linux, a nie przez jeden długotrwale działający uprzywilejowany daemon. Podman ma również znacznie lepiej rozwinięte wsparcie dla **rootless** niż klasyczne wdrożenia Docker, od których wiele osób zaczynało naukę. Nie oznacza to, że Podman jest automatycznie bezpieczny, ale znacząco zmienia domyślny profil ryzyka, szczególnie w połączeniu z user namespaces, SELinux i `crun`.

### containerd

containerd to podstawowy komponent zarządzania runtime w wielu nowoczesnych stosach. Jest używany przez Docker i należy również do najważniejszych backendów runtime w Kubernetes. Udostępnia potężne API, zarządza obrazami i snapshotami, a finalne tworzenie procesu deleguje low-level runtime. W dyskusjach dotyczących bezpieczeństwa containerd należy podkreślać, że dostęp do socketu containerd lub funkcjonalności `ctr`/`nerdctl` może być równie niebezpieczny jak dostęp do API Docker, nawet jeśli interfejs i workflow wydają się mniej „przyjazne dla developera”.

### CRI-O

CRI-O ma węższy zakres niż Docker Engine. Zamiast być ogólną platformą dla developerów, został zbudowany wokół czystej implementacji Kubernetes Container Runtime Interface. Dzięki temu jest szczególnie popularny w dystrybucjach Kubernetes oraz ekosystemach intensywnie wykorzystujących SELinux, takich jak OpenShift. Z perspektywy bezpieczeństwa ten węższy zakres jest użyteczny, ponieważ ogranicza zamieszanie pojęciowe: CRI-O należy przede wszystkim do warstwy „uruchamiania kontenerów dla Kubernetes”, a nie do platform obsługujących wszystko.

### Incus, LXD i LXC

Systemy Incus/LXD/LXC warto oddzielić od kontenerów aplikacyjnych w stylu Docker, ponieważ często są używane jako **system containers**. Od system containera zwykle oczekuje się, że będzie bardziej przypominał lekką maszynę z pełniejszym userspace, długo działającymi usługami, bogatszym dostępem do urządzeń i szerszą integracją z hostem. Mechanizmy izolacji nadal opierają się na prymitywach kernela, ale oczekiwania operacyjne są inne. W rezultacie błędne konfiguracje często przypominają mniej „złe domyślne ustawienia kontenera aplikacyjnego”, a bardziej błędy w lekkiej wirtualizacji lub delegowaniu zasobów hosta.

### systemd-nspawn

systemd-nspawn zajmuje interesujące miejsce, ponieważ jest natywny dla systemd i bardzo przydatny w testowaniu, debugowaniu oraz uruchamianiu środowisk przypominających system operacyjny. Nie jest dominującym runtime w produkcji cloud-native, ale pojawia się wystarczająco często w labach i środowiskach zorientowanych na dystrybucje, aby zasługiwać na wzmiankę. Z punktu widzenia analizy bezpieczeństwa jest kolejnym przypomnieniem, że pojęcie „kontener” obejmuje wiele ekosystemów i stylów operacyjnych.

### Apptainer / Singularity

Apptainer (dawniej Singularity) jest popularny w środowiskach badawczych i HPC. Jego założenia dotyczące zaufania, workflow użytkowników i modelu wykonywania różnią się istotnie od stosów skoncentrowanych na Docker/Kubernetes. W szczególności w takich środowiskach duże znaczenie ma możliwość uruchamiania przez użytkowników spakowanych workloadów bez przyznawania im szerokich uprzywilejowanych uprawnień do zarządzania kontenerami. Jeśli analityk założy, że każde środowisko kontenerowe to zasadniczo „Docker na serwerze”, całkowicie błędnie zinterpretuje takie wdrożenia.

## Narzędzia Build-Time

Wiele dyskusji o bezpieczeństwie skupia się wyłącznie na runtime, ale narzędzia build-time również mają znaczenie, ponieważ określają zawartość obrazu, ekspozycję build secrets oraz ilość zaufanego kontekstu, który zostanie osadzony w finalnym artefakcie.

**BuildKit** i `docker buildx` to nowoczesne backendy build obsługujące funkcje takie jak caching, secret mounting, SSH forwarding i multi-platform builds. Są to przydatne funkcje, ale z perspektywy bezpieczeństwa tworzą również miejsca, w których sekrety mogą wyciec do warstw obrazu lub gdzie zbyt szeroki build context może ujawnić pliki, które nigdy nie powinny zostać dołączone. **Buildah** pełni podobną rolę w ekosystemach natywnych dla OCI, szczególnie wokół Podman, natomiast **Kaniko** jest często używane w środowiskach CI, które nie chcą przyznawać pipeline’owi build uprzywilejowanego Docker daemona.

Najważniejszy wniosek jest taki, że tworzenie obrazu i jego uruchamianie to różne fazy, ale słaby build pipeline może stworzyć słabą postawę bezpieczeństwa runtime na długo przed uruchomieniem kontenera.

## Orkiestracja to kolejna warstwa, a nie runtime

Kubernetes nie powinien być utożsamiany z samym runtime. Kubernetes jest orkiestratorem. Planuje Pody, przechowuje pożądany stan i wyraża politykę bezpieczeństwa za pomocą konfiguracji workloadów. Następnie kubelet komunikuje się z implementacją CRI, taką jak containerd lub CRI-O, która z kolei wywołuje low-level runtime, taki jak `runc`, `crun`, `runsc` lub `kata-runtime`.

To rozdzielenie ma znaczenie, ponieważ wiele osób błędnie przypisuje dane zabezpieczenie „Kubernetes”, choć w rzeczywistości jest ono egzekwowane przez runtime noda, albo obwinia „domyślne ustawienia containerd” za zachowanie wynikające z Pod spec. W praktyce finalna postawa bezpieczeństwa jest kompozycją: orkiestrator żąda określonego działania, stos runtime tłumaczy to żądanie, a kernel ostatecznie je egzekwuje.

## Dlaczego identyfikacja runtime ma znaczenie podczas assessmentu

Jeśli wcześnie zidentyfikujesz silnik i runtime, wiele późniejszych obserwacji stanie się łatwiejszych do interpretacji. Kontener rootless Podman sugeruje, że user namespaces prawdopodobnie odgrywają istotną rolę. Docker socket zamontowany w workloadzie sugeruje, że privilege escalation sterowane przez API jest realną ścieżką. Node CRI-O/OpenShift powinien od razu skłonić cię do myślenia o etykietach SELinux i polityce ograniczonych workloadów. Środowisko gVisor lub Kata powinno zwiększyć ostrożność przy założeniu, że klasyczny PoC breakout dla `runc` zadziała w taki sam sposób.

Dlatego jednym z pierwszych kroków w container assessment zawsze powinno być udzielenie odpowiedzi na dwa proste pytania: **który komponent zarządza kontenerem** oraz **który runtime faktycznie uruchomił proces**. Gdy odpowiedzi są już znane, resztę środowiska zwykle można znacznie łatwiej przeanalizować.

## Runtime Vulnerabilities

Nie każdy container escape wynika z błędnej konfiguracji operatora. Czasami podatnym komponentem jest sam runtime. Ma to znaczenie, ponieważ workload może działać z pozornie staranną konfiguracją, a mimo to być narażony na działanie low-level runtime flaw.

Klasycznym przykładem jest **CVE-2019-5736** w `runc`, gdzie złośliwy kontener mógł nadpisać hostowy plik binarny `runc`, a następnie zaczekać na późniejsze wywołanie `docker exec` lub podobne uruchomienie runtime, aby wykonać kod kontrolowany przez atakującego. Ścieżka exploitationu znacznie różni się od prostego błędu bind mount lub capability, ponieważ wykorzystuje sposób, w jaki runtime ponownie wchodzi do przestrzeni procesów kontenera podczas obsługi exec.

Minimalny workflow reprodukcji z perspektywy red teamu wygląda następująco:
```bash
go build main.go
./main
```
Następnie z hosta:
```bash
docker exec -it <container-name> /bin/sh
```
Kluczowa lekcja nie dotyczy dokładnej implementacji historycznego exploitu, lecz implikacji dla oceny bezpieczeństwa: jeśli wersja runtime'u jest podatna, zwykłe wykonanie kodu w kontenerze może wystarczyć do przejęcia hosta, nawet gdy widoczna konfiguracja kontenera nie wygląda rażąco słabo.

Nowsze CVE dotyczące runtime'u, takie jak `CVE-2024-21626` w `runc`, wyścigi podczas montowania w BuildKit oraz błędy parsowania w containerd, wzmacniają ten sam wniosek. Wersja runtime'u i poziom zastosowanych poprawek są częścią granicy bezpieczeństwa, a nie jedynie kwestią utrzymania.
{{#include ../../../banners/hacktricks-training.md}}
