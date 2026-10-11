# Runtimes, silniki, narzędzia do budowania i sandboxy kontenerów

{{#include ../../../banners/hacktricks-training.md}}

Jednym z największych źródeł nieporozumień w dziedzinie bezpieczeństwa kontenerów jest sprowadzanie kilku zupełnie różnych komponentów do jednego pojęcia. „Docker” może oznaczać format obrazu, CLI, demona, system budowania, stos runtime’u albo po prostu ogólną koncepcję kontenerów. W kontekście bezpieczeństwa taka niejednoznaczność stanowi problem, ponieważ różne warstwy odpowiadają za różne zabezpieczenia. Ucieczka z kontenera spowodowana błędnym bind mountem to nie to samo co ucieczka wynikająca z błędu w niskopoziomowym runtime’ie; żadna z nich nie jest też tym samym co błąd w polityce klastra Kubernetes.

Ta strona porządkuje ekosystem według ról, aby w dalszej części można było precyzyjnie wskazywać, gdzie faktycznie znajduje się dane zabezpieczenie lub słabość.

## OCI jako wspólny język

Nowoczesne stosy kontenerów Linuksa często współpracują ze sobą, ponieważ korzystają ze zbioru specyfikacji OCI. **OCI Image Specification** opisuje sposób reprezentacji obrazów i warstw. **OCI Runtime Specification** określa, jak runtime powinien uruchamiać proces, w tym konfigurować namespaces, mounty, cgroups i ustawienia bezpieczeństwa. **OCI Distribution Specification** standaryzuje sposób udostępniania zawartości przez rejestry.

To ważne, ponieważ wyjaśnia, dlaczego obraz kontenera zbudowany jednym narzędziem można często uruchomić za pomocą innego oraz dlaczego kilka silników może korzystać z tego samego niskopoziomowego runtime’u. Wyjaśnia to również, dlaczego zachowanie związane z bezpieczeństwem może wyglądać podobnie w różnych produktach: wiele z nich tworzy tę samą konfigurację runtime’u OCI i przekazuje ją do tego samego, niewielkiego zbioru runtime’ów.

## Niskopoziomowe runtime’y OCI

Niskopoziomowy runtime to komponent najbliższy granicy jądra. To on faktycznie tworzy namespaces, zapisuje ustawienia cgroups, stosuje capabilities i filtry seccomp, a na końcu wykonuje `execve()` dla procesu kontenera. Gdy mówi się o „izolacji kontenerów” na poziomie mechanizmów, zwykle chodzi właśnie o tę warstwę, nawet jeśli nie jest to powiedziane wprost.

### `runc`

`runc` to referencyjny runtime OCI i nadal najbardziej znana implementacja. Jest szeroko używany przez Docker, containerd i wiele wdrożeń Kubernetes. Wiele publicznie dostępnych badań i materiałów dotyczących exploitacji koncentruje się na środowiskach typu `runc`, po prostu dlatego, że są powszechne, a `runc` stanowi punkt odniesienia dla wyobrażeń wielu osób o kontenerze Linuksa. Zrozumienie `runc` daje więc czytelnikowi solidny model mentalny klasycznej izolacji kontenerów.

### `crun`

`crun` to kolejny runtime OCI, napisany w C i szeroko stosowany we współczesnych środowiskach Podman. Często chwali się go za dobre wsparcie cgroup v2, wygodę w trybie rootless i mniejszy narzut. Z perspektywy bezpieczeństwa ważne jest nie to, że napisano go w innym języku, ale że pełni tę samą rolę: zamienia konfigurację OCI w drzewo procesów działające pod kontrolą jądra. Przepływ pracy rootless Podman często sprawia wrażenie bezpieczniejszego nie dlatego, że `crun` magicznie rozwiązuje wszystkie problemy, ale dlatego, że otaczający go stos zwykle w większym stopniu opiera się na user namespaces i zasadzie najmniejszych uprawnień.

### `runsc` z gVisor

`runsc` to runtime używany przez gVisor. W tym przypadku granica izolacji zmienia się w istotny sposób. Zamiast przekazywać większość wywołań systemowych bezpośrednio do jądra hosta w zwykły sposób, gVisor wprowadza warstwę jądra w przestrzeni użytkownika, która emuluje lub pośredniczy w obsłudze dużej części interfejsu Linuksa. Rezultatem nie jest zwykły kontener `runc` z kilkoma dodatkowymi flagami, lecz inny projekt sandboxa, którego celem jest ograniczenie powierzchni ataku jądra hosta. Kompromisy dotyczące zgodności i wydajności są częścią tego projektu, dlatego środowiska korzystające z `runsc` należy opisywać inaczej niż środowiska ze zwykłym runtime’em OCI.

### `kata-runtime`

Kata Containers idzie o krok dalej, uruchamiając obciążenie w lekkiej maszynie wirtualnej. Z punktu widzenia administracji może to nadal wyglądać jak wdrożenie kontenerowe i warstwy orkiestracji mogą nadal tak je traktować, ale podstawowa granica izolacji jest bliższa wirtualizacji niż klasycznemu kontenerowi współdzielącemu jądro hosta. Dzięki temu Kata przydaje się, gdy potrzebna jest silniejsza izolacja między tenantami bez rezygnowania z przepływów pracy opartych na kontenerach.

## Silniki i menedżery kontenerów

Jeśli niskopoziomowy runtime to komponent komunikujący się bezpośrednio z jądrem, silnik lub menedżer to komponent, z którym zwykle pracują użytkownicy i operatorzy. Obsługuje pobieranie obrazów, metadane, logi, sieci, wolumeny, operacje cyklu życia i udostępnianie API. Ta warstwa ma ogromne znaczenie, ponieważ wiele rzeczywistych kompromitacji następuje właśnie tutaj: dostęp do gniazda runtime’u lub API demona może być równoznaczny z przejęciem hosta, nawet jeśli sam niskopoziomowy runtime działa bez zarzutu.

### Docker Engine

Docker Engine to najbardziej rozpoznawalna platforma kontenerowa wśród developerów i jeden z powodów, dla których słownictwo związane z kontenerami tak mocno przypomina terminologię Dockera. Typowa ścieżka prowadzi od CLI `docker` do `dockerd`, który z kolei koordynuje działanie niższych komponentów, takich jak `containerd` i runtime OCI. Historycznie wdrożenia Dockera często działały w trybie **rootful**, dlatego dostęp do gniazda Dockera był bardzo potężnym prymitywem. Z tego powodu tak wiele praktycznych materiałów o eskalacji uprawnień koncentruje się na `docker.sock`: jeśli proces może poprosić `dockerd` o utworzenie uprzywilejowanego kontenera, zamontowanie ścieżek hosta lub dołączenie do namespaces hosta, może w ogóle nie potrzebować exploita jądra.

Porównuj numery wydań według składowych major, minor i patch, zamiast usuwać kropki: `18.09.1` jest starszy zarówno od `18.09.2`, jak i `18.09.4`, mimo że składowa minor zawiera zero wiodące. [Informacje o wydaniach Docker 18.09](https://docs.docker.com/engine/release-notes/18.09/) odnotowują poprawkę `runc` dla CVE-2019-5736 w wersji 18.09.2 oraz poprawkę dotyczącą referencji builda dla CVE-2019-13139 w wersji 18.09.4. To wskazówki dotyczące wersji, a nie dowód na możliwość wykorzystania podatności w danym środowisku. Te same informacje o wydaniach ostrzegają, że demon, klient i runtime są pakowane osobno, dlatego obok wersji demona należy sprawdzić zainstalowany runtime i poprawki backportowane przez dostawcę; podatność dotycząca referencji builda wymaga również dostępu do podatnego przepływu pracy builda i danych wejściowych kontrolowanych przez atakującego.

### Podman

Podman zaprojektowano z myślą o modelu bezdemona. Z operacyjnego punktu widzenia wzmacnia to podejście, według którego kontenery są po prostu procesami zarządzanymi za pomocą standardowych mechanizmów Linuksa, a nie przez jeden długotrwale działający, uprzywilejowany demon. Podman oferuje też znacznie lepszą obsługę trybu **rootless** niż klasyczne wdrożenia Dockera, od których wiele osób zaczyna naukę. Nie oznacza to, że Podman jest automatycznie bezpieczny, ale istotnie zmienia domyślny profil ryzyka, zwłaszcza w połączeniu z user namespaces, SELinux i `crun`.

### containerd

containerd to podstawowy komponent zarządzania runtime’ami w wielu nowoczesnych stosach. Jest używany przez Docker i należy też do najczęściej stosowanych backendów runtime’u Kubernetes. Udostępnia potężne API, zarządza obrazami i snapshotami, a tworzenie końcowego procesu deleguje do niskopoziomowego runtime’u. W dyskusjach o bezpieczeństwie containerd należy podkreślać, że dostęp do gniazda containerd lub funkcji `ctr`/`nerdctl` może być równie niebezpieczny jak dostęp do API Dockera, nawet jeśli interfejs i przepływ pracy wydają się mniej „przyjazne developerom”.

### CRI-O

CRI-O ma węższy zakres niż Docker Engine. Zamiast być uniwersalną platformą dla developerów, został zaprojektowany tak, by poprawnie implementować Kubernetes Container Runtime Interface. Dzięki temu jest szczególnie powszechny w dystrybucjach Kubernetes i ekosystemach intensywnie korzystających z SELinux, takich jak OpenShift. Z perspektywy bezpieczeństwa ten węższy zakres jest przydatny, ponieważ ogranicza zamieszanie pojęciowe: CRI-O wyraźnie należy do warstwy „uruchamiania kontenerów dla Kubernetes”, a nie do platformy do wszystkiego.

Jeśli węzeł Kubernetes używa CRI-O, sprawdź **aktywną wersję CRI-O na węźle** oraz to, czy bieżąca tożsamość może tworzyć Pody w namespace, do którego są one przydzielane. [CVE-2022-0811](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7) umożliwiała spreparowanym wartościom sysctl w Podzie zmianę parametru jądra hosta i uzyskanie wykonania z uprawnieniami roota hosta w podatnych wydaniach. W poradniku upstream wymieniono wydania z poprawką i obejścia problemu. Lokalne `crio --version` może nie wykryć runtime’u zagnieżdżonego w Minikube lub innym kontenerze węzła; dostępny do odczytu log uruchamiania Minikube może dostarczyć wskazówki dotyczącej wersji, ale jest to historyczny dowód, a nie potwierdzenie wersji działającego runtime’u ani stanu poprawek. Zanim uznasz tę ścieżkę eskalacji za możliwą do wykorzystania, potwierdź faktyczny runtime węzła, uprawnienia do tworzenia Podów, reguły admission oraz istotne granice seccomp i user namespaces.

Istnieje również bezpośrednia lokalna ścieżka analizy `pinns`: [badacze zwracają uwagę, że do wywołania wadliwego helpera Kubernetes nie jest wymagany](https://www.crowdstrike.com/en-us/blog/cr8escape-new-vulnerability-discovered-in-cri-o-container-engine-cve-2022-0811/). Sprawdź, czy bieżące konto może uruchomić należący do roota plik `pinns` z bitem setuid, czy NoNewPrivs lub mount z opcją `nosuid` blokuje tę zmianę uprawnień oraz czy zainstalowany **build helpera** nie zawiera poprawki. W [poradniku upstream](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7) wymieniono wersje wydań z poprawką, ale wersja wyświetlana przez demona sama w sobie nie potwierdza, który plik binarny helpera jest zainstalowany; poprawki backportowane przez dystrybutorów mogą też zmieniać podatność. Plik setuid to tylko potencjalny punkt zaczepienia; podczas rutynowego rozpoznania sprawdź pochodzenie helpera, konfigurację i zachowanie sysctl hosta, nie uruchamiając go.

### Incus, LXD i LXC

Systemy Incus/LXD/LXC warto odróżniać od kontenerów aplikacyjnych w stylu Dockera, ponieważ często są używane jako **kontenery systemowe**. Zwykle oczekuje się, że kontener systemowy będzie przypominał lekką maszynę z pełniejszym userspace, długotrwale działającymi usługami, bogatszym udostępnianiem urządzeń i szerszą integracją z hostem. Mechanizmy izolacji nadal opierają się na prymitywach jądra, ale oczekiwania operacyjne są inne. Dlatego błędne konfiguracje często bardziej przypominają błędy w lekkiej wirtualizacji lub delegowaniu uprawnień hosta niż „złe ustawienia domyślne kontenera aplikacyjnego”.

### systemd-nspawn

systemd-nspawn zajmuje ciekawe miejsce, ponieważ jest natywny dla systemd i bardzo przydatny do testowania, debugowania oraz uruchamiania środowisk przypominających system operacyjny. Nie jest dominującym runtime’em produkcyjnym w środowiskach cloud-native, ale pojawia się na tyle często w laboratoriach i środowiskach skoncentrowanych na dystrybucjach, że warto o nim wspomnieć. W analizie bezpieczeństwa przypomina, że pojęcie „kontenera” obejmuje wiele ekosystemów i stylów operacyjnych.

### Apptainer / Singularity

Apptainer (wcześniej Singularity) jest powszechny w środowiskach badawczych i HPC. Jego założenia dotyczące zaufania, przepływ pracy użytkowników i model wykonywania różnią się istotnie od stosów skoncentrowanych na Docker/Kubernetes. W szczególności w tych środowiskach często dużą wagę przykłada się do umożliwienia użytkownikom uruchamiania spakowanych obciążeń bez przyznawania im szerokich uprawnień do zarządzania uprzywilejowanymi kontenerami. Jeśli recenzent założy, że każde środowisko kontenerowe to w zasadzie „Docker na serwerze”, poważnie błędnie zrozumie te wdrożenia.

## Narzędzia używane na etapie budowania

Wiele dyskusji o bezpieczeństwie dotyczy wyłącznie etapu uruchamiania, ale narzędzia używane na etapie budowania również mają znaczenie, ponieważ określają zawartość obrazu, ryzyko ujawnienia sekretów podczas builda oraz to, ile zaufanego kontekstu zostanie osadzone w końcowym artefakcie.

**BuildKit** i `docker buildx` to nowoczesne backendy builda obsługujące takie funkcje jak caching, montowanie sekretów, przekazywanie SSH i buildy wieloplatformowe. Są to przydatne funkcje, ale z perspektywy bezpieczeństwa tworzą również miejsca, w których sekrety mogą wyciec do warstw obrazu albo zbyt szeroki kontekst builda może ujawnić pliki, które nigdy nie powinny się w nim znaleźć. **Buildah** pełni podobną rolę w ekosystemach natywnych dla OCI, zwłaszcza w połączeniu z Podmanem, podczas gdy **Kaniko** jest często używane w środowiskach CI, które nie chcą przyznawać pipeline’owi builda dostępu do uprzywilejowanego demona Dockera.

Najważniejszy wniosek jest taki, że tworzenie obrazu i jego uruchamianie to odrębne etapy, ale słaby pipeline builda może pogorszyć bezpieczeństwo runtime’u na długo przed uruchomieniem kontenera.

## Orkiestracja to kolejna warstwa, a nie runtime

Kubernetes nie należy utożsamiać z samym runtime’em. Kubernetes jest orkiestratorem. Planuje Pody, przechowuje stan pożądany i definiuje politykę bezpieczeństwa za pomocą konfiguracji obciążeń. Następnie kubelet komunikuje się z implementacją CRI, taką jak containerd lub CRI-O, która z kolei wywołuje niskopoziomowy runtime, taki jak `runc`, `crun`, `runsc` lub `kata-runtime`.

To rozdzielenie ma znaczenie, ponieważ wiele osób błędnie przypisuje zabezpieczenie „Kubernetesowi”, choć w rzeczywistości egzekwuje je runtime węzła, albo obwinia „domyślną konfigurację containerd” za zachowanie wynikające ze specyfikacji Poda. W praktyce końcowy stan bezpieczeństwa jest połączeniem kilku elementów: orkiestrator zgłasza żądanie, stos runtime’u je przekształca, a jądro ostatecznie je egzekwuje.

## Dlaczego identyfikacja runtime’u ma znaczenie podczas oceny

Jeśli wcześnie zidentyfikujesz silnik i runtime, łatwiej będzie zinterpretować wiele późniejszych obserwacji. Kontener rootless Podman sugeruje, że user namespaces prawdopodobnie odgrywają istotną rolę. Gniazdo Dockera zamontowane w obciążeniu sugeruje, że eskalacja uprawnień za pośrednictwem API może być realną ścieżką. Węzeł CRI-O/OpenShift powinien od razu nasuwać skojarzenia z etykietami SELinux i restrykcyjną polityką obciążeń. Środowisko gVisor lub Kata powinno skłonić do ostrożności przy założeniu, że klasyczny PoC ucieczki z `runc` zadziała w ten sam sposób.

Dlatego jednym z pierwszych kroków oceny bezpieczeństwa kontenerów zawsze powinno być udzielenie odpowiedzi na dwa proste pytania: **który komponent zarządza kontenerem** i **który runtime faktycznie uruchomił proces**. Gdy odpowiedzi są jasne, rozumowanie o pozostałych elementach środowiska staje się znacznie łatwiejsze.

## Podatności runtime’ów

Nie każda ucieczka z kontenera wynika z błędnej konfiguracji operatora. Czasami podatny jest sam runtime. Ma to znaczenie, ponieważ obciążenie może działać przy konfiguracji, która wygląda na staranną, a mimo to być narażone na błąd w niskopoziomowym runtime’ie.

Klasycznym przykładem jest **CVE-2019-5736** w `runc`, która umożliwiała złośliwemu kontenerowi nadpisanie pliku binarnego `runc` na hoście, a następnie oczekiwanie na późniejsze wywołanie `docker exec` lub podobną operację runtime’u, aby uruchomić kod kontrolowany przez atakującego. Ścieżka wykorzystania tej podatności znacząco różni się od prostego błędu bind mounta lub capabilities, ponieważ nadużywa sposobu, w jaki runtime ponownie wchodzi do przestrzeni procesów kontenera podczas obsługi `exec`.<sup>[[1]](#references)</sup>

Minimalny przepływ reprodukcji z perspektywy red teamu wygląda następująco:

```bash
go build main.go
./main
```

Następnie, z hosta:

```bash
docker exec -it <container-name> /bin/sh
```

Kluczową lekcją nie jest dokładna implementacja historycznego exploita, lecz wniosek istotny dla oceny bezpieczeństwa: jeśli wersja runtime’u jest podatna, zwykłe wykonanie kodu w kontenerze może wystarczyć do przejęcia hosta, nawet gdy widoczna konfiguracja kontenera nie wygląda na rażąco słabą.

Nowsze CVE dotyczące runtime’ów, takie jak `CVE-2024-21626` w `runc`, wyścigi przy montowaniu w BuildKit i błędy parsowania w containerd, potwierdzają tę samą tezę. Wersja runtime’u i poziom zainstalowanych poprawek są częścią granicy bezpieczeństwa, a nie tylko nieistotnym szczegółem konserwacji.

## References

- [1] [Breaking out of Docker via runC – Explaining CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
