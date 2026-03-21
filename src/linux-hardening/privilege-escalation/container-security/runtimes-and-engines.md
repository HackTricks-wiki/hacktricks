# Środowiska uruchomieniowe (runtimes), silniki, narzędzia do budowy i sandboksy kontenerów

{{#include ../../../banners/hacktricks-training.md}}

Jednym z największych źródeł niejasności w bezpieczeństwie kontenerów jest to, że kilka zupełnie różnych komponetów jest często sprowadzanych do tego samego słowa. „Docker” może odnosić się do formatu obrazu, CLI, demona, systemu budowania, stosu runtime, albo po prostu do idei kontenerów w ogóle. Dla pracy związanej z bezpieczeństwem ta niejednoznaczność jest problemem, ponieważ różne warstwy odpowiadają za różne mechanizmy ochronne. Breakout spowodowany złym bind mountem to nie to samo co breakout spowodowany błędem na niskim poziomie w runtime, i żadne z nich nie jest tym samym co błąd polityki klastra w Kubernetes.

Ta strona rozdziela ekosystem według roli, żeby reszta sekcji mogła precyzyjnie mówić o tym, gdzie rzeczywiście leży ochrona lub słabość.

## OCI jako wspólny język

Nowoczesne stosy kontenerowe na Linuksie często interoperują, ponieważ mówią zgodnie ze zbiorem specyfikacji OCI. **OCI Image Specification** opisuje, jak reprezentowane są obrazy i warstwy. **OCI Runtime Specification** opisuje, jak runtime powinien uruchomić proces, włączając namespaces, mounty, cgroups i ustawienia bezpieczeństwa. **OCI Distribution Specification** standaryzuje, jak rejestry udostępniają zawartość.

To ma znaczenie, bo wyjaśnia, dlaczego obraz kontenera zbudowany jednym narzędziem często można uruchomić innym, i dlaczego kilka silników może współdzielić ten sam niskopoziomowy runtime. Wyjaśnia też, dlaczego zachowanie bezpieczeństwa może wyglądać podobnie w różnych produktach: wiele z nich konstruuje tę samą konfigurację runtime OCI i przekazuje ją temu samemu małemu zbiorowi runtime'ów.

## Niskopoziomowe runtimy OCI

Niskopoziomowy runtime to komponent najbliżej granicy jądra. To ta część, która faktycznie tworzy namespaces, zapisuje ustawienia cgroup, stosuje capabilities i filtry seccomp, i w końcu `execve()`-uje proces kontenera. Kiedy ludzie dyskutują o „izolacji kontenera” na poziomie mechanicznym, to zazwyczaj o tej warstwie mówią, nawet jeśli nie mówią tego wprost.

### `runc`

`runc` jest referencyjnym runtime OCI i pozostaje najlepiej znaną implementacją. Jest intensywnie używany pod Docker, containerd i w wielu wdrożeniach Kubernetes. Dużo publicznych badań i materiałów eksploatacyjnych skupia się na środowiskach w stylu `runc`, po prostu dlatego, że są powszechne i ponieważ `runc` definiuje punkt odniesienia, który wielu ludzi ma na myśli, wyobrażając sobie kontener Linuksa. Zrozumienie `runc` daje więc czytelnikowi silny model mentalny klasycznej izolacji kontenera.

### `crun`

`crun` to kolejny runtime OCI, napisany w C i szeroko używany w nowoczesnych środowiskach Podman. Często jest chwalony za dobrą obsługę cgroup v2, silną ergonomię rootless i mniejsze narzuty. Z perspektywy bezpieczeństwa ważne nie jest to, że jest napisany w innym języku, ale że wciąż pełni tę samą rolę: to komponent, który zamienia konfigurację OCI w drzewo uruchomionych procesów pod jądrem. Rootless workflow w Podmanie często wydaje się bezpieczniejszy nie dlatego, że `crun` cudownie wszystko naprawia, lecz dlatego, że cały stos wokół niego zwykle mocniej wykorzystuje user namespaces i zasadę najmniejszych uprawnień.

### `runsc` z gVisor

`runsc` to runtime używany przez gVisor. Tutaj granica znacząco się zmienia. Zamiast przekazywać większość syscalli bezpośrednio do hosta w zwykły sposób, gVisor wstawia warstwę jądra w userspace, która emuluje lub pośredniczy w dużej części interfejsu Linuksa. Wynik nie jest zwykłym kontenerem `runc` z kilkoma dodatkowymi flagami; to inny projekt sandboxa, którego celem jest zmniejszenie powierzchni ataku jądra hosta. Kompatybilność i kompromisy wydajnościowe są częścią tej konstrukcji, więc środowiska używające `runsc` powinny być dokumentowane inaczej niż normalne środowiska runtime OCI.

### `kata-runtime`

Kata Containers przesuwają granicę dalej, uruchamiając obciążenie wewnątrz lekkiej maszyny wirtualnej. Administracyjnie może to nadal wyglądać jak wdrożenie kontenerów, a warstwy orkiestracji mogą to nadal traktować jako takie, ale leżąca u podstaw granica izolacji jest bliższa wirtualizacji niż klasycznemu kontenerowi współdzielącemu jądro hosta. Dzięki temu Kata jest użyteczna, gdy pożądana jest silniejsza izolacja tenantów bez rezygnacji z przepływów pracy skoncentrowanych na kontenerach.

## Silniki i menedżery kontenerów

Jeśli niskopoziomowy runtime to komponent, który rozmawia bezpośrednio z jądrem, to engine lub manager to komponent, z którym użytkownicy i operatorzy zwykle wchodzą w interakcję. Obsługuje pobieranie obrazów, metadata, logi, sieci, wolumeny, operacje cyklu życia i ekspozycję API. Ta warstwa ma ogromne znaczenie, ponieważ wiele rzeczywistych kompromitacji zdarza się właśnie tutaj: dostęp do socketu runtime lub API demona może być równoważny z kompromitacją hosta, nawet jeśli sam niskopoziomowy runtime jest idealny.

### Docker Engine

Docker Engine jest najbardziej rozpoznawalną platformą kontenerową dla deweloperów i jedną z przyczyn, dla których słownictwo kontenerowe stało się tak „Docker-owe”. Typowa ścieżka to CLI `docker` do `dockerd`, który z kolei koordynuje niższego poziomu komponenty takie jak `containerd` i runtime OCI. Historycznie wdrożenia Docker często były **rootful**, i dostęp do socketu Docker był więc bardzo potężnym prymitywem. Dlatego tak dużo praktycznych materiałów dotyczących privilege-escalation koncentruje się na `docker.sock`: jeśli proces może poprosić `dockerd` o utworzenie uprzywilejowanego kontenera, zamontowanie ścieżek hosta lub dołączenie do namespaces hosta, może nie potrzebować wcale exploit'u jądra.

### Podman

Podman został zaprojektowany wokół modelu bez demona. Operacyjnie pomaga to utrwalić ideę, że kontenery to po prostu procesy zarządzane przez standardowe mechanizmy Linuksa, a nie przez jeden długotrwały uprzywilejowany demon. Podman ma też znacznie silniejszą historię **rootless** niż klasyczne wdrożenia Docker, które wiele osób poznało na początku. To nie czyni Podmana automatycznie bezpiecznym, ale zmienia domyślny profil ryzyka znacząco, zwłaszcza w połączeniu z user namespaces, SELinux i `crun`.

### containerd

containerd to podstawowy komponent zarządzania runtime w wielu nowoczesnych stosach. Jest używany pod Dockerem i jest też jednym z dominujących backendów runtime w Kubernetes. Eksponuje potężne API, zarządza obrazami i snapshotami, i deleguje końcowe tworzenie procesu do niskopoziomowego runtime. Dyskusje bezpieczeństwa wokół containerd powinny podkreślać, że dostęp do socketu containerd lub funkcjonalności `ctr`/`nerdctl` może być równie niebezpieczny jak dostęp do API Dockera, nawet jeśli interfejs i workflow wydają się mniej „przyjazne dla dewelopera”.

### CRI-O

CRI-O jest bardziej ukierunkowane niż Docker Engine. Zamiast być platformą ogólnego przeznaczenia dla deweloperów, jest zbudowane wokół czystej implementacji Kubernetes Container Runtime Interface. To czyni je szczególnie powszechnym w dystrybucjach Kubernetes i ekosystemach silnie wykorzystujących SELinux, takich jak OpenShift. Z perspektywy bezpieczeństwa, ten węższy zakres jest użyteczny, bo redukuje konceptualny chaos: CRI-O jest bardzo częścią warstwy „uruchamiania kontenerów dla Kubernetes”, a nie platformą wszystkiego.

### Incus, LXD i LXC

Systemy Incus/LXD/LXC warto oddzielić od kontenerów w stylu Docker, ponieważ często używane są jako systemowe kontenery. Systemowy kontener zwykle ma wyglądać bardziej jak lekka maszyna z pełniejszym userspace, długotrwałymi usługami, bogatszym dostępem do urządzeń i większą integracją z hostem. Mechanizmy izolacji wciąż opierają się na prymitywach jądra, ale oczekiwania operacyjne są inne. W efekcie błędy konfiguracji tutaj często wyglądają mniej jak „złe domyślne ustawienia app-containera”, a bardziej jak pomyłki w lekkiej wirtualizacji lub delegowaniu hosta.

### systemd-nspawn

systemd-nspawn zajmuje ciekawe miejsce, ponieważ jest natywny dla systemd i bardzo przydatny do testowania, debugowania i uruchamiania środowisk przypominających system operacyjny. Nie jest dominującym runtime w chmurze produkcyjnej, ale pojawia się wystarczająco często w labach i środowiskach zorientowanych na dystrybucje, że zasługuje na wzmiankę. Dla analizy bezpieczeństwa jest to kolejne przypomnienie, że pojęcie „konte ner” obejmuje wiele ekosystemów i stylów operacyjnych.

### Apptainer / Singularity

Apptainer (dawniej Singularity) jest powszechny w środowiskach badawczych i HPC. Jego założenia zaufania, workflow użytkownika i model wykonania różnią się istotnie od stosów zorientowanych na Docker/Kubernetes. W szczególności te środowiska często bardzo dbają o możliwość uruchamiania pakowanych zadań przez użytkowników bez nadawania im szerokich uprzywilejowanych uprawnień do zarządzania kontenerami. Jeśli recenzent zakłada, że każde środowisko kontenerowe to w gruncie rzeczy „Docker na serwerze”, źle zrozumie takie wdrożenia.

## Narzędzia działające w czasie budowania (Build-Time Tooling)

Wiele dyskusji o bezpieczeństwie dotyczy tylko czasu uruchamiania, ale narzędzia działające w czasie budowania też mają znaczenie, bo określają zawartość obrazu, ekspozycję sekretów w trakcie budowy i ile z zaufanego kontekstu trafia do finalnego artefaktu.

**BuildKit** i `docker buildx` to nowoczesne backendy buildów, które wspierają funkcje takie jak caching, secret mounting, SSH forwarding i buildy multi-platformowe. To przydatne funkcje, ale z perspektywy bezpieczeństwa tworzą też miejsca, gdzie sekrety mogą leakować do warstw obrazu lub gdzie zbyt szeroki kontekst builda może ujawnić pliki, które nigdy nie powinny zostać dołączone. **Buildah** pełni podobną rolę w ekosystemach natywnych OCI, szczególnie wokół Podmana, podczas gdy **Kaniko** jest często używany w CI, które nie chcą nadawać uprzywilejowanego demona Docker pipeline'owi budującemu obrazy.

Kluczowa lekcja jest taka, że tworzenie obrazu i jego wykonanie to różne fazy, ale słaby pipeline builda może stworzyć słabą postawę runtime dużo wcześniej, zanim kontener zostanie uruchomiony.

## Orkiestracja to inna warstwa, nie runtime

Kubernetes nie powinien być mentalnie utożsamiany z samym runtime. Kubernetes to orchestrator. Scheduluje Pody, przechowuje desired state i wyraża polityki bezpieczeństwa przez konfigurację obciążeń. kubelet następnie rozmawia z implementacją CRI taką jak containerd czy CRI-O, która z kolei wywołuje niskopoziomowy runtime taki jak `runc`, `crun`, `runsc` czy `kata-runtime`.

To rozdzielenie ma znaczenie, ponieważ wiele osób błędnie przypisuje ochronę „Kubernetesowi”, kiedy tak naprawdę jest ona egzekwowana przez runtime węzła, albo obwinia „domyślne ustawienia containerd” za zachowanie, które wynikło z specu Poda. W praktyce ostateczna postawa bezpieczeństwa to kompozycja: orchestrator prosi o coś, stos runtime to tłumaczy, a jądro ostatecznie to egzekwuje.

## Dlaczego identyfikacja runtime ma znaczenie podczas oceny

Jeśli wcześnie zidentyfikujesz engine i runtime, wiele późniejszych obserwacji staje się łatwiejszych do interpretacji. Rootless Podman sugeruje, że user namespaces prawdopodobnie odgrywają rolę. Zamontowany do workloadu socket Dockera sugeruje, że eskalacja przy użyciu API jest realistyczną ścieżką. Węzeł CRI-O/OpenShift powinien natychmiast skłaniać do myślenia o etykietach SELinux i restrykcyjnej polityce obciążeń. Środowisko gVisor lub Kata powinno sprawić, że będziesz ostrożniejszy, zakładając, że klasyczne PoC na breakout z `runc` zadziała tak samo.

Dlatego jednym z pierwszych kroków w ocenie kontenera powinny być zawsze dwie proste odpowiedzi: **który komponent zarządza kontenerem** i **który runtime faktycznie uruchomił proces**. Gdy te odpowiedzi są jasne, reszta środowiska zwykle staje się znacznie łatwiejsza do przeanalizowania.

## Luki w runtime

Nie każda ucieczka z kontenera wynika z błędu operatora. Czasem to sam runtime jest podatny. To ma znaczenie, bo obciążenie może działać z pozornie staranną konfiguracją, a mimo to być wystawione przez niskopoziomową wadę runtime.

Klasycznym przykładem jest **CVE-2019-5736** w `runc`, gdzie złośliwy kontener mógł nadpisać binarkę `runc` na hoście, a następnie czekać na późniejsze wywołanie `docker exec` lub podobne, które uruchomi kod kontrolowany przez atakującego. Ścieżka eksploatacji jest bardzo inna niż prosty błąd z bind-mountem czy capability, ponieważ nadużywa sposobu, w jaki runtime ponownie wchodzi w przestrzeń procesu kontenera podczas obsługi exec.

Minimalny workflow reprodukcyjny z perspektywy red-team wygląda następująco:
```bash
go build main.go
./main
```
Następnie, z hosta:
```bash
docker exec -it <container-name> /bin/sh
```
Kluczowa lekcja nie polega na dokładnej historycznej implementacji exploita, lecz na implikacji dla oceny: jeśli wersja runtime jest podatna, zwykłe wykonywanie kodu w kontenerze może wystarczyć do kompromitacji hosta, nawet gdy widoczna konfiguracja kontenera nie wygląda na rażąco słabą.

Niedawne runtime CVEs takie jak `CVE-2024-21626` w `runc`, wyścigi mountów w BuildKit oraz błędy parsowania w containerd wzmacniają ten sam punkt. Wersja runtime i poziom łatek są częścią granicy bezpieczeństwa, a nie jedynie drobiazgiem konserwacyjnym.
