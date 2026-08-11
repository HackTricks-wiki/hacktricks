# Runtime'y kontenerów, silniki, narzędzia budujące i sandboxy

{{#include ../../../banners/hacktricks-training.md}}

Jednym z największych źródeł nieporozumień w container security jest to, że kilka całkowicie różnych komponentów często określa się tym samym słowem. „Docker” może oznaczać format obrazu, CLI, daemon, system budowania, stos runtime albo po prostu ogólną koncepcję kontenerów. W pracy związanej z bezpieczeństwem ta niejednoznaczność stanowi problem, ponieważ różne warstwy odpowiadają za różne mechanizmy ochrony. Breakout spowodowany nieprawidłowym bind mountem nie jest tym samym co breakout wynikający z błędu low-level runtime, a żaden z nich nie jest tym samym co błąd w polityce klastra Kubernetes.

Ta strona rozdziela ekosystem według ról, aby w dalszej części można było precyzyjnie określać, gdzie faktycznie znajduje się dana ochrona lub słabość.

## OCI jako wspólny język

Współczesne stosy Linux containers często współdziałają, ponieważ korzystają ze specyfikacji OCI. **OCI Image Specification** opisuje sposób reprezentowania obrazów i warstw. **OCI Runtime Specification** opisuje sposób, w jaki runtime powinien uruchamiać proces, w tym namespaces, mounty, cgroups i ustawienia bezpieczeństwa. **OCI Distribution Specification** standaryzuje sposób, w jaki registry udostępniają zawartość.

Ma to znaczenie, ponieważ wyjaśnia, dlaczego obraz kontenera zbudowany za pomocą jednego narzędzia często może zostać uruchomiony za pomocą innego oraz dlaczego kilka silników może korzystać z tego samego low-level runtime. Wyjaśnia to również, dlaczego zachowanie związane z bezpieczeństwem może wyglądać podobnie w różnych produktach: wiele z nich tworzy tę samą konfigurację OCI runtime i przekazuje ją temu samemu niewielkiemu zestawowi runtime'ów.

## Low-Level OCI Runtimes

Low-level runtime to komponent znajdujący się najbliżej granicy z kernelem. To on faktycznie tworzy namespaces, zapisuje ustawienia cgroups, stosuje capabilities i filtry seccomp, a następnie wykonuje `execve()` dla procesu kontenera. Gdy ludzie omawiają „container isolation” na poziomie mechanizmów, zwykle mówią właśnie o tej warstwie, nawet jeśli nie stwierdzają tego wprost.

### `runc`

`runc` to referencyjny OCI runtime i nadal najbardziej znana implementacja. Jest szeroko używany przez Docker, containerd oraz wiele wdrożeń Kubernetes. Duża część publicznych badań i materiałów dotyczących exploitation skupia się na środowiskach typu `runc`, ponieważ są one powszechne, a także dlatego, że `runc` wyznacza bazowy model, który wiele osób ma na myśli, wyobrażając sobie Linux container. Zrozumienie `runc` daje więc czytelnikowi solidny model mentalny klasycznego container isolation.

### `crun`

`crun` to kolejny OCI runtime, napisany w C i szeroko używany we współczesnych środowiskach Podman. Często docenia się go za dobre wsparcie dla cgroup v2, wygodę rootless oraz mniejszy narzut. Z perspektywy bezpieczeństwa istotne jest nie to, że został napisany w innym języku, lecz że nadal pełni tę samą rolę: jest komponentem, który przekształca konfigurację OCI w działające drzewo procesów pod kontrolą kernela. Workflow rootless Podman często wydaje się bezpieczniejszy nie dlatego, że `crun` magicznie rozwiązuje wszystkie problemy, lecz dlatego, że otaczający go stos zwykle mocniej wykorzystuje user namespaces i least privilege.

### `runsc` z gVisor

`runsc` to runtime używany przez gVisor. W tym przypadku granica izolacji zmienia się w istotny sposób. Zamiast przekazywać większość syscalli bezpośrednio do host kernela, jak ma to miejsce zazwyczaj, gVisor wstawia userspace kernel layer, która emuluje lub pośredniczy w dużej części Linux interface. Rezultatem nie jest zwykły kontener `runc` z kilkoma dodatkowymi flagami, lecz odmienny projekt sandboxa, którego celem jest zmniejszenie attack surface host kernela. Kompatybilność i kompromisy wydajnościowe są częścią tego projektu, dlatego środowiska używające `runsc` powinny być dokumentowane inaczej niż standardowe środowiska OCI runtime.

### `kata-runtime`

Kata Containers przesuwają granicę jeszcze dalej, uruchamiając workload wewnątrz lightweight virtual machine. Administracyjnie nadal może to wyglądać jak wdrożenie kontenerowe, a warstwy orchestration mogą nadal traktować je w ten sposób, jednak bazowa granica izolacji jest bliższa virtualization niż klasycznemu kontenerowi współdzielącemu host kernel. Dzięki temu Kata jest przydatne, gdy potrzebna jest silniejsza tenant isolation bez rezygnacji z container-centric workflows.

## Silniki i menedżery kontenerów

Jeśli low-level runtime jest komponentem komunikującym się bezpośrednio z kernelem, engine lub manager jest komponentem, z którym zwykle mają kontakt użytkownicy i operatorzy. Obsługuje pobieranie obrazów, metadata, logi, sieci, volume'y, operacje lifecycle oraz udostępnianie API. Ta warstwa ma ogromne znaczenie, ponieważ wiele rzeczywistych kompromitacji ma miejsce właśnie tutaj: dostęp do runtime socket lub daemon API może być równoważny z kompromitacją hosta, nawet jeśli sam low-level runtime działa bez zarzutu.

### Docker Engine

Docker Engine to najbardziej rozpoznawalna platforma kontenerowa wśród developerów i jeden z powodów, dla których terminologia dotycząca kontenerów stała się tak silnie związana z Dockerem. Typowa ścieżka wygląda tak: CLI `docker` komunikuje się z `dockerd`, który z kolei koordynuje komponenty niższego poziomu, takie jak `containerd` i OCI runtime. Historycznie wdrożenia Docker często były **rootful**, dlatego dostęp do Docker socket stanowił bardzo potężny prymityw. Z tego powodu tak wiele praktycznych materiałów dotyczących privilege escalation koncentruje się na `docker.sock`: jeśli proces może poprosić `dockerd` o utworzenie privileged container, zamontowanie ścieżek hosta lub dołączenie do host namespaces, może wcale nie potrzebować kernel exploit.

### Podman

Podman został zaprojektowany w oparciu o bardziej daemonless model. Operacyjnie pomaga to wzmacniać koncepcję, że kontenery są po prostu procesami zarządzanymi za pomocą standardowych mechanizmów Linux, a nie przez jeden długo działający privileged daemon. Podman ma również znacznie silniejszy model **rootless** niż klasyczne wdrożenia Docker, od których wiele osób zaczynało naukę. Nie oznacza to, że Podman jest automatycznie bezpieczny, ale znacząco zmienia domyślny profil ryzyka, szczególnie w połączeniu z user namespaces, SELinux i `crun`.

### containerd

containerd jest podstawowym komponentem zarządzania runtime w wielu współczesnych stosach. Jest używany przez Docker i należy również do dominujących backendów runtime w Kubernetes. Udostępnia potężne API, zarządza obrazami i snapshotami oraz deleguje końcowe tworzenie procesu do low-level runtime. W dyskusjach dotyczących bezpieczeństwa containerd należy podkreślać, że dostęp do containerd socket lub funkcjonalności `ctr`/`nerdctl` może być równie niebezpieczny jak dostęp do Docker API, nawet jeśli interfejs i workflow wydają się mniej „developer friendly”.

### CRI-O

CRI-O ma węższy zakres niż Docker Engine. Zamiast być ogólną platformą dla developerów, został zbudowany wokół poprawnej implementacji Kubernetes Container Runtime Interface. Dzięki temu jest szczególnie powszechny w dystrybucjach Kubernetes i ekosystemach intensywnie korzystających z SELinux, takich jak OpenShift. Z perspektywy bezpieczeństwa ten węższy zakres jest korzystny, ponieważ ogranicza złożoność pojęciową: CRI-O należy przede wszystkim do warstwy „uruchamiania kontenerów dla Kubernetes”, a nie do platformy obsługującej wszystko.

### Incus, LXD i LXC

Systemy Incus/LXD/LXC warto oddzielić od application containers w stylu Docker, ponieważ często są używane jako **system containers**. Zwykle oczekuje się, że system container będzie bardziej przypominał lekką maszynę z pełniejszym userspace, długo działającymi usługami, bogatszym dostępem do urządzeń i szerszą integracją z hostem. Mechanizmy izolacji nadal opierają się na kernel primitives, ale oczekiwania operacyjne są inne. W rezultacie błędne konfiguracje często przypominają tu mniej „nieprawidłowe domyślne ustawienia app-container”, a bardziej błędy w lightweight virtualization lub host delegation.

### systemd-nspawn

systemd-nspawn zajmuje interesujące miejsce, ponieważ jest natywny dla systemd i bardzo przydatny do testowania, debugowania oraz uruchamiania środowisk przypominających system operacyjny. Nie jest dominującym cloud-native production runtime, ale pojawia się wystarczająco często w laboratoriach i środowiskach zorientowanych na dystrybucje, aby zasługiwać na wzmiankę. Z punktu widzenia analizy bezpieczeństwa jest kolejnym przypomnieniem, że pojęcie „kontener” obejmuje wiele ekosystemów i stylów operacyjnych.

### Apptainer / Singularity

Apptainer (wcześniej Singularity) jest powszechny w środowiskach badawczych i HPC. Jego założenia dotyczące zaufania, workflow użytkownika i modelu wykonania istotnie różnią się od stosów skoncentrowanych na Docker/Kubernetes. W szczególności środowiska te często przywiązują dużą wagę do umożliwienia użytkownikom uruchamiania spakowanych workloadów bez przyznawania im szerokich, privileged powers do zarządzania kontenerami. Jeśli analityk założy, że każde środowisko kontenerowe to w zasadzie „Docker na serwerze”, całkowicie błędnie zrozumie takie wdrożenia.

## Narzędzia używane podczas build time

Wiele dyskusji na temat bezpieczeństwa obejmuje wyłącznie runtime, ale narzędzia używane podczas build time również mają znaczenie, ponieważ określają zawartość obrazu, ryzyko ujawnienia build secrets oraz ilość trusted context osadzonego w finalnym artefakcie.

**BuildKit** i `docker buildx` to nowoczesne backendy budowania obsługujące między innymi caching, secret mounting, SSH forwarding i multi-platform builds. Są to przydatne funkcje, ale z perspektywy bezpieczeństwa tworzą również miejsca, w których secrets mogą wyciec do image layers lub w których zbyt szeroki build context może ujawnić pliki, które nigdy nie powinny zostać dołączone. **Buildah** pełni podobną rolę w ekosystemach OCI-native, szczególnie wokół Podman, natomiast **Kaniko** jest często używany w środowiskach CI, które nie chcą przyznawać uprzywilejowanego Docker daemon do build pipeline.

Najważniejsza lekcja jest taka, że tworzenie obrazu i jego wykonywanie to różne fazy, jednak słaby build pipeline może stworzyć słabą security posture na długo przed uruchomieniem kontenera.

## Orchestration to kolejna warstwa, a nie runtime

Kubernetes nie powinien być utożsamiany z samym runtime. Kubernetes jest orchestrator. Planuje Pody, przechowuje desired state i wyraża security policy poprzez konfigurację workloadów. Następnie kubelet komunikuje się z implementacją CRI, taką jak containerd lub CRI-O, która z kolei wywołuje low-level runtime, na przykład `runc`, `crun`, `runsc` lub `kata-runtime`.

To rozdzielenie ma znaczenie, ponieważ wiele osób błędnie przypisuje ochronę „Kubernetes”, podczas gdy w rzeczywistości jest ona wymuszana przez node runtime, albo obwinia „containerd defaults” za zachowanie wynikające z Pod spec. W praktyce finalna security posture jest kompozycją: orchestrator żąda określonego działania, runtime stack tłumaczy to żądanie, a kernel ostatecznie je wymusza.

## Dlaczego identyfikacja runtime ma znaczenie podczas assessmentu

Jeśli wcześnie zidentyfikujesz engine i runtime, późniejsze obserwacje stają się łatwiejsze do interpretacji. Rootless Podman container sugeruje, że user namespaces prawdopodobnie odgrywają rolę. Docker socket zamontowany w workloadzie sugeruje, że API-driven privilege escalation jest realistyczną ścieżką. Węzeł CRI-O/OpenShift powinien od razu skierować uwagę na SELinux labels i restricted workload policy. Środowisko gVisor lub Kata powinno skłonić do większej ostrożności przy założeniu, że klasyczny `runc` breakout PoC zadziała w ten sam sposób.

Dlatego jednym z pierwszych kroków podczas container assessment powinno być zawsze udzielenie odpowiedzi na dwa proste pytania: **który komponent zarządza kontenerem** oraz **który runtime faktycznie uruchomił proces**. Gdy odpowiedzi są jasne, resztę środowiska zwykle można znacznie łatwiej przeanalizować.

## Runtime Vulnerabilities

Nie każdy container escape wynika z błędnej konfiguracji operatora. Czasami podatnym komponentem jest sam runtime. Ma to znaczenie, ponieważ workload może działać z pozornie staranną konfiguracją, a mimo to być narażony na low-level runtime flaw.

Klasycznym przykładem jest **CVE-2019-5736** w `runc`, gdzie malicious container mógł nadpisać binarkę `runc` na hoście, a następnie oczekiwać na późniejsze wywołanie `docker exec` lub podobne uruchomienie runtime, aby wykonać code kontrolowany przez atakującego. Ścieżka exploitation znacznie różni się od prostego błędu bind mount lub capabilities, ponieważ wykorzystuje sposób, w jaki runtime ponownie wchodzi do przestrzeni procesów kontenera podczas obsługi exec.<sup>[[1]](#references)</sup>

Minimalny workflow reprodukcji z perspektywy red teamu wygląda następująco:
```bash
go build main.go
./main
```
Następnie z hosta:
```bash
docker exec -it <container-name> /bin/sh
```
Kluczowa lekcja nie dotyczy dokładnej historycznej implementacji exploita, lecz wniosku z oceny: jeśli wersja runtime jest podatna, zwykłe wykonanie kodu wewnątrz kontenera może wystarczyć do przejęcia hosta, nawet gdy widoczna konfiguracja kontenera nie wygląda rażąco słabo.

Niedawne CVE w runtime, takie jak `CVE-2024-21626` w `runc`, wyścigi montowania w BuildKit oraz błędy parsowania w containerd, wzmacniają ten sam przekaz. Wersja runtime i poziom poprawek są częścią granicy bezpieczeństwa, a nie tylko kwestią utrzymania.

## References

- [1] [Wydostanie się z Docker za pomocą runC – wyjaśnienie CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
