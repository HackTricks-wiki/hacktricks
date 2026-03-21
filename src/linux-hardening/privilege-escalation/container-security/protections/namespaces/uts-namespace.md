# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

UTS namespace izoluje **hostname** i **NIS domain name** widziane przez proces. Na pierwszy rzut oka może to wyglądać na trywialne w porównaniu z mount, PID czy user namespaces, ale jest to część tego, co sprawia, że container wydaje się być własnym hostem. Wewnątrz namespace workload może zobaczyć i czasami zmienić hostname, który jest lokalny dla tej namespace, zamiast globalnego dla maszyny.

Samo w sobie zazwyczaj nie jest to główny element historii o breakout. Jednak po udostępnieniu host UTS namespace, proces z wystarczającymi uprawnieniami może wpływać na ustawienia związane z tożsamością hosta, co może mieć znaczenie operacyjne, a czasem również dla bezpieczeństwa.

## Laboratorium

Możesz utworzyć UTS namespace za pomocą:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Zmiana nazwy hosta pozostaje lokalna dla tej przestrzeni nazw i nie zmienia globalnej nazwy hosta. To prosta, ale skuteczna demonstracja właściwości izolacji.

## Użycie w czasie działania

Zwykłe kontenery otrzymują izolowaną przestrzeń nazw UTS. Docker i Podman mogą dołączyć do przestrzeni nazw UTS hosta poprzez `--uts=host`, a podobne wzorce udostępniania hosta mogą występować w innych runtime'ach i systemach orkiestracyjnych. Jednak w większości przypadków prywatna izolacja UTS jest po prostu częścią normalnej konfiguracji kontenera i wymaga niewielkiej uwagi operatora.

## Wpływ na bezpieczeństwo

Chociaż przestrzeń nazw UTS zwykle nie jest najniebezpieczniejsza do udostępniania, nadal wpływa na integralność granicy kontenera. Jeśli przestrzeń nazw UTS hosta zostanie ujawniona i proces ma odpowiednie uprawnienia, może być w stanie zmodyfikować informacje związane z nazwą hosta. To może wpłynąć na monitoring, logowanie, założenia operacyjne lub skrypty, które podejmują decyzje zaufania na podstawie danych identyfikujących hosta.

## Nadużycie

Jeśli przestrzeń nazw UTS hosta jest udostępniona, praktyczne pytanie brzmi, czy proces może modyfikować ustawienia tożsamości hosta, a nie tylko je odczytywać:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Jeśli kontener ma również niezbędne uprawnienia, sprawdź, czy można zmienić hostname:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
To jest przede wszystkim problem integralności i wpływu operacyjnego, a nie pełny escape, ale nadal pokazuje, że container może bezpośrednio wpływać na host-global property.

Impact:

- host identity tampering
- mylące logs, monitoring lub automation, które ufają hostname
- zazwyczaj nie jest to full escape samo w sobie, chyba że połączone z innymi słabościami

On Docker-style environments, a useful host-side detection pattern is:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Kontenery pokazujące `UTSMode=host` współdzielą UTS namespace hosta i powinny być dokładniej sprawdzone, jeśli mają także capabilities pozwalające im wywołać `sethostname()` lub `setdomainname()`.

## Sprawdzenia

Te polecenia wystarczą, aby sprawdzić, czy workload ma własny widok hostname, czy współdzieli UTS namespace hosta.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Co jest tutaj interesujące:

- Dopasowanie identyfikatorów namespace do procesu hosta może wskazywać na współdzielenie UTS z hostem.
- Jeśli zmiana hostname wpływa na coś więcej niż sam container, workload ma większy wpływ na tożsamość hosta, niż powinna.
- Zazwyczaj jest to finding o niższym priorytecie niż problemy z PID, mount lub user namespace, ale nadal potwierdza, jak naprawdę izolowany jest proces.

W większości środowisk UTS namespace najlepiej traktować jako pomocniczą warstwę izolacji. Rzadko jest to pierwsza rzecz, której się szuka podczas breakout, ale wciąż jest częścią ogólnej spójności i bezpieczeństwa widoku container.
