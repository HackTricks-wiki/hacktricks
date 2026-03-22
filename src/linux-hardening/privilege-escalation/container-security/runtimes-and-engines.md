# Runtimes kontenerów, silniki, narzędzia build i sandboksy

{{#include ../../../banners/hacktricks-training.md}}

Jednym z największych źródeł zamieszania w bezpieczeństwie kontenerów jest to, że kilka zupełnie różnych komponentów często jest zbijanych w to samo słowo. "Docker" może odnosić się do formatu obrazu, CLI, demona, systemu budowania, stosu runtime albo po prostu do idei kontenerów w ogóle. Dla pracy związanej z bezpieczeństwem ta niejednoznaczność stanowi problem, ponieważ różne warstwy odpowiadają za różne zabezpieczenia. Breakout spowodowany złym bind mount nie jest tym samym co breakout spowodowany błędem niskopoziomowego runtime, i żaden z nich nie jest tym samym co błąd polityki klastra w Kubernetes.

Ta strona rozdziela ekosystem według ról, tak aby reszta sekcji mogła precyzyjnie mówić o tym, gdzie właściwie żyje ochrona lub słabość.

## OCI jako wspólny język

Nowoczesne stosy kontenerowe na Linuksie często współdziałają, ponieważ mówią zestawem specyfikacji OCI. **OCI Image Specification** opisuje, jak reprezentowane są obrazy i warstwy. **OCI Runtime Specification** opisuje, jak runtime powinien uruchomić proces, włączając namespaces, mounts, cgroups i ustawienia bezpieczeństwa. **OCI Distribution Specification** standaryzuje, jak rejestry eksponują zawartość.

To ma znaczenie, ponieważ wyjaśnia, dlaczego obraz kontenera zbudowany jednym narzędziem często można uruchomić innym, i dlaczego kilka silników może współdzielić ten sam niskopoziomowy runtime. Tłumaczy też, dlaczego zachowanie bezpieczeństwa może wyglądać podobnie w różnych produktach: wiele z nich konstruuje tę samą konfigurację runtime OCI i przekazuje ją temu samemu małemu zestawowi runtime.

## Niskopoziomowe runtime OCI

Niskopoziomowy runtime to komponent najbliżej granicy jądra. To część, która faktycznie tworzy namespaces, zapisuje ustawienia cgroup, stosuje capabilities i filtry seccomp, i w końcu `execve()` procesu kontenera. Kiedy ludzie dyskutują o "izolacji kontenera" na poziomie mechanicznym, to jest warstwa, o której zwykle mówią, nawet jeśli tego nie precyzują.

### `runc`

`runc` jest referencyjnym runtime OCI i pozostaje najlepiej znaną implementacją. Jest szeroko używany pod Docker, containerd i w wielu wdrożeniach Kubernetes. Dużo publicznych badań i materiałów eksploatacyjnych celuje w środowiska typu `runc` po prostu dlatego, że są powszechne i ponieważ `runc` definiuje punkt odniesienia, o którym wiele osób myśli, wyobrażając sobie kontener na Linuksie. Zrozumienie `runc` daje więc czytelnikowi silny model mentalny klasycznej izolacji kontenera.

### `crun`

`crun` to kolejny runtime OCI, napisany w C i szeroko stosowany w nowoczesnych środowiskach Podman. Często chwalony jest za dobrą obsługę cgroup v2, silną ergonomię rootless i niższy narzut. Z punktu widzenia bezpieczeństwa ważne nie jest to, że jest napisany w innym języku, lecz że nadal pełni tę samą rolę: jest komponentem, który zamienia konfigurację OCI w uruchomione drzewo procesów pod jądrem. Rootless workflow w Podmanie często wydaje się bezpieczniejszy nie dlatego, że `crun` cudownie wszystko naprawia, lecz dlatego, że ogólny stos wokół niego ma tendencję do silniejszego wykorzystywania user namespaces i zasady najmniejszych przywilejów.

### `runsc` od gVisor

`runsc` jest runtime używanym przez gVisor. Tutaj granica zmienia znaczenie w istotny sposób. Zamiast przekazywać większość syscalli bezpośrednio do hosta w zwykły sposób, gVisor wstawia warstwę jądra w userspace, która emuluje lub pośredniczy w dużej części interfejsu Linuksa. Rezultat to nie normalny kontener `runc` z kilkoma dodatkowymi flagami; to inna konstrukcja sandboksa, której celem jest zmniejszenie powierzchni ataku host-kernel. Kompatybilność i kompromisy wydajności są częścią tego projektu, więc środowiska używające `runsc` powinny być dokumentowane odmiennie niż normalne środowiska runtime OCI.

### `kata-runtime`

Kata Containers przesuwają granicę dalej, uruchamiając obciążenie wewnątrz lekkiej maszyny wirtualnej. Administracyjnie może to nadal wyglądać jak wdrożenie kontenerowe i warstwy orkiestracji mogą tak to traktować, ale pod spodem granica izolacji jest bliższa wirtualizacji niż klasycznemu kontenerowi współdzielącemu jądro hosta. To czyni Kata użytecznym, gdy wymagane jest silniejsze oddzielenie tenantów bez porzucania przepływów pracy skoncentrowanych na kontenerach.

## Silniki i menedżery kontenerów

Jeśli niskopoziomowy runtime to komponent, który rozmawia bezpośrednio z jądrem, to engine lub manager to komponent, z którym zwykle interagują użytkownicy i operatorzy. Obsługuje pobieranie obrazów, metadane, logi, sieci, wolumeny, operacje cyklu życia i eksponowanie API. Ta warstwa ma ogromne znaczenie, ponieważ wiele rzeczywistych kompromisów zdarza się tutaj: dostęp do socketu runtime lub API demona może być równoważny z kompromitacją hosta, nawet jeśli sam niskopoziomowy runtime jest w pełni zdrowy.

### Docker Engine

Docker Engine jest najbardziej rozpoznawalną platformą kontenerową dla deweloperów i jedną z przyczyn, dla których słownictwo kontenerowe stało się tak Docker-kształtne. Typowa ścieżka to CLI `docker` do `dockerd`, który z kolei koordynuje niższe komponenty takie jak `containerd` i runtime OCI. Historycznie wdrożenia Docker często były **rootful**, a dostęp do socketu Docker (`docker.sock`) był dlatego bardzo potężnym prymitywem. To wyjaśnia, dlaczego tyle praktycznych materiałów o eskalacji przywilejów skupia się na `docker.sock`: jeśli proces może poprosić `dockerd` o stworzenie uprzywilejowanego kontenera, zamontowanie ścieżek hosta lub dołączenie do namespaces hosta, może nie potrzebować wcale exploita jądra.

### Podman

Podman został zaprojektowany wokół modelu bez demona. Operacyjnie pomaga to podkreślić ideę, że kontenery to po prostu procesy zarządzane za pomocą standardowych mechanizmów Linuksa, a nie przez jeden długo działający uprzywilejowany demon. Podman ma też znacznie silniejszą historię rootless niż klasyczne wdrożenia Docker, które wielu użytkowników poznało. To nie czyni Podmana automatycznie bezpiecznym, ale znacząco zmienia profil ryzyka domyślnie, zwłaszcza w połączeniu z user namespaces, SELinux i `crun`.

### containerd

containerd jest podstawowym komponentem zarządzającym runtime w wielu nowoczesnych stosach. Jest używany pod Docker i jest też jednym z dominujących backendów runtime w Kubernetes. Eksponuje potężne API, zarządza obrazami i snapshotami, i deleguje ostateczne tworzenie procesów do niskopoziomowego runtime. Dyskusje o bezpieczeństwie dotyczące containerd powinny podkreślać, że dostęp do socketu containerd lub funkcji `ctr`/`nerdctl` może być równie niebezpieczny jak dostęp do API Dockera, nawet jeśli interfejs i workflow wydają się mniej "przyjazne dla dewelopera".

### CRI-O

CRI-O jest bardziej ukierunkowany niż Docker Engine. Zamiast być platformą ogólnego przeznaczenia dla deweloperów, jest zbudowany wokół czystej implementacji Kubernetes Container Runtime Interface. To sprawia, że jest szczególnie powszechny w dystrybucjach Kubernetes i w ekosystemach mocno wykorzystujących SELinux, takich jak OpenShift. Z perspektywy bezpieczeństwa ten węższy zakres jest przydatny, ponieważ redukuje konceptualny chaos: CRI-O jest zdecydowanie częścią warstwy "uruchamiaj kontenery dla Kubernetes", a nie platformą wszystkiego.

### Incus, LXD i LXC

Systemy Incus/LXD/LXC warto oddzielić od kontenerów w stylu Docker, ponieważ są często używane jako systemowe kontenery. Systemowy kontener zwykle ma wyglądać bardziej jak lekka maszyna z pełniejszym userspace, długotrwale działającymi usługami, bogatszym dostępem do urządzeń i większą integracją z hostem. Mechanizmy izolacji nadal opierają się na prymitywach jądra, ale oczekiwania operacyjne są inne. W efekcie błędy konfiguracji tutaj często wyglądają mniej jak "złe domyślne ustawienia app-container" a bardziej jak pomyłki w lekkiej wirtualizacji lub delegacji hosta.

### systemd-nspawn

systemd-nspawn zajmuje interesujące miejsce, ponieważ jest natywny dla systemd i bardzo przydatny do testowania, debugowania i uruchamiania środowisk przypominających OS. Nie jest dominującym runtime w chmurze, ale pojawia się wystarczająco często w laboratoriach i środowiskach dystrybucyjnych, żeby zasłużyć na wzmiankę. Dla analizy bezpieczeństwa jest to kolejne przypomnienie, że koncept "kontenera" obejmuje wiele ekosystemów i stylów operacyjnych.

### Apptainer / Singularity

Apptainer (dawniej Singularity) jest powszechny w środowiskach badawczych i HPC. Jego założenia dotyczące zaufania, workflow użytkownika i modelu wykonania różnią się w istotny sposób od stosów skupionych wokół Docker/Kubernetes. W szczególności te środowiska często bardzo dbają o to, aby pozwolić użytkownikom uruchamiać opakowane obciążenia bez nadawania im szerokich uprawnień do zarządzania kontenerami. Jeśli recenzent założy, że każde środowisko kontenerowe to w zasadzie "Docker na serwerze", źle zrozumie takie wdrożenia.

## Narzędzia build-time

Wiele dyskusji o bezpieczeństwie mówi tylko o czasie uruchomienia, ale narzędzia używane w czasie budowania też mają znaczenie, ponieważ determinują zawartość obrazu, eksponowanie sekretów i ile z zaufanego kontekstu zostaje osadzone w finalnym artefakcie.

**BuildKit** i `docker buildx` to nowoczesne backendy build, które wspierają funkcje takie jak caching, secret mounting, SSH forwarding i multi-platform builds. To przydatne funkcje, ale z perspektywy bezpieczeństwa tworzą też miejsca, gdzie sekrety mogą leak into image layers lub gdzie zbyt szeroki kontekst build może ujawnić pliki, które nigdy nie powinny być dołączone. **Buildah** pełni podobną rolę w ekosystemach natywnych dla OCI, szczególnie wokół Podmana, podczas gdy **Kaniko** jest często używany w CI, które nie chcą przyznawać uprzywilejowanego demona Docker pipeline'owi build.

Kluczowa lekcja jest taka, że tworzenie obrazu i uruchamianie obrazu to różne fazy, ale słaby pipeline build może stworzyć słabą postawę runtime znacznie wcześniej, zanim kontener zostanie uruchomiony.

## Orkiestracja to kolejna warstwa, nie runtime

Kubernetes nie powinien być mentalnie utożsamiany z samym runtime. Kubernetes to orkiestrator. Harmonogramuje Pody, przechowuje desired state i wyraża politykę bezpieczeństwa przez konfigurację workload. Kubelet następnie rozmawia z implementacją CRI, taką jak containerd lub CRI-O, która z kolei wywołuje niskopoziomowy runtime taki jak `runc`, `crun`, `runsc` lub `kata-runtime`.

To rozdzielenie ma znaczenie, ponieważ wiele osób mylnie przypisuje ochronę "Kubernetesowi", gdy w rzeczywistości jest ona egzekwowana przez node runtime, albo obwinia "domyślne ustawienia containerd" za zachowanie, które wyniknęło z spec Podu. W praktyce ostateczna postawa bezpieczeństwa jest kompozycją: orkiestrator prosi o coś, stos runtime to tłumaczy, a jądro w końcu to egzekwuje.

## Dlaczego identyfikacja runtime ma znaczenie podczas oceny

Jeśli wcześnie zidentyfikujesz engine i runtime, wiele późniejszych obserwacji staje się łatwiejszych do interpretacji. Rootless kontener Podmana sugeruje, że user namespaces prawdopodobnie są częścią historii. Zamontowany do workload socket Docker (`docker.sock`) sugeruje, że eskalacja przywilejów przez API jest realistyczną ścieżką. Węzeł CRI-O/OpenShift powinien natychmiast skłonić do myślenia o etykietach SELinux i ograniczonej polityce workload. Środowisko gVisor lub Kata powinno sprawić, że będziesz bardziej ostrożny zakładając, że klasyczny PoC na breakout `runc` zachowa się tak samo.

Dlatego jednym z pierwszych kroków w ocenie kontenerów powinno być zawsze odpowiedzenie na dwa proste pytania: **który komponent zarządza kontenerem** i **który runtime faktycznie uruchomił proces**. Gdy te odpowiedzi są jasne, reszta środowiska zwykle staje się znacznie łatwiejsza do rozumienia.

## Luki w runtime

Nie każda ucieczka z kontenera wynika z błędu operatora. Czasem sam runtime jest podatnym komponentem. To ma znaczenie, ponieważ workload może działać z pozornie staranną konfiguracją, a mimo to być narażony przez niskopoziomową wadę runtime.

Klasycznym przykładem jest **CVE-2019-5736** w `runc`, gdzie złośliwy kontener mógł nadpisać binarkę hosta `runc`, a potem czekać na późniejsze wywołanie `docker exec` lub podobne, które uruchomi kod kontrolowany przez atakującego. Ścieżka exploita jest bardzo różna od prostego bind-mounta lub błędu capabilities, ponieważ nadużywa sposobu, w jaki runtime ponownie wchodzi w przestrzeń procesu kontenera podczas obsługi exec.

Minimalny workflow reprodukcji z perspektywy red-teamowego to:
```bash
go build main.go
./main
```
Następnie, z hosta:
```bash
docker exec -it <container-name> /bin/sh
```
Główna lekcja to nie dokładna historyczna implementacja exploita, lecz implikacja dla oceny: jeśli wersja runtime jest podatna, zwykłe wykonanie kodu in-container może wystarczyć do przejęcia hosta, nawet gdy widoczna konfiguracja containera nie wygląda rażąco słabo.

Ostatnie runtime CVE, takie jak `CVE-2024-21626` w `runc`, BuildKit mount races oraz błędy parsowania containerd, wzmacniają tę samą tezę. Runtime version i patch level są częścią security boundary, a nie jedynie trywialną kwestią konserwacyjną.
{{#include ../../../banners/hacktricks-training.md}}
