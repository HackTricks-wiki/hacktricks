# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

Przestrzeń nazw UTS izoluje **hostname** i **NIS domain name** widoczne dla procesu. Na pierwszy rzut oka może się to wydawać trywialne w porównaniu z mount, PID czy user namespaces, ale stanowi część tego, co sprawia, że container wygląda na własny host. W obrębie namespace workload może zobaczyć i czasami zmienić hostname, który jest lokalny dla tej namespace, a nie globalny dla maszyny.

Samo w sobie zazwyczaj nie jest to główny element historii o breakout. Jednak gdy host UTS namespace zostanie udostępniony, proces z odpowiednimi uprawnieniami może wpływać na ustawienia związane z tożsamością hosta, co może mieć znaczenie operacyjne, a czasami także dla bezpieczeństwa.

## Lab

Możesz utworzyć UTS namespace za pomocą:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Zmiana nazwy hosta pozostaje lokalna dla tej przestrzeni nazw i nie zmienia globalnej nazwy hosta. To prosta, ale skuteczna demonstracja właściwości izolacji.

## Użycie w czasie wykonywania

Normalne kontenery otrzymują izolowaną przestrzeń nazw UTS. Docker i Podman mogą dołączyć do przestrzeni nazw UTS hosta za pomocą `--uts=host`, a podobne wzorce współdzielenia hosta mogą występować w innych runtime'ach i systemach orkiestracji. Jednak przez większość czasu prywatna izolacja UTS jest po prostu częścią standardowej konfiguracji kontenera i wymaga niewielkiej uwagi operatora.

## Wpływ na bezpieczeństwo

Chociaż przestrzeń nazw UTS zwykle nie jest najgroźniejszą do udostępnienia, nadal wpływa na integralność granicy kontenera. Jeśli przestrzeń nazw UTS hosta zostanie ujawniona i proces ma niezbędne uprawnienia, może być w stanie zmodyfikować informacje związane z nazwą hosta. To może wpłynąć na monitoring, logowanie, założenia operacyjne lub skrypty podejmujące decyzje zaufania na podstawie danych identyfikujących hosta.

## Nadużycia

Jeśli przestrzeń nazw UTS hosta jest współdzielona, praktycznym pytaniem jest, czy proces może modyfikować ustawienia tożsamości hosta, a nie tylko je odczytywać:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Jeśli container ma również niezbędne privilege, sprawdź, czy można zmienić hostname:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
To przede wszystkim problem integralności i wpływu operacyjnego, a nie pełne escape, ale nadal pokazuje, że kontener może bezpośrednio wpływać na globalną właściwość hosta.

Impact:

- manipulacja tożsamością hosta
- wprowadzanie w błąd logów, systemów monitoringu lub automatyzacji, które polegają na nazwie hosta
- zazwyczaj samo w sobie nie stanowi pełnego escape, chyba że połączone z innymi słabościami

On Docker-style environments, a useful host-side detection pattern is:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Kontenery pokazujące `UTSMode=host` współdzielą z hostem namespace UTS i powinny być sprawdzone bardziej szczegółowo, jeśli mają przydzielone capabilities pozwalające na wywołanie `sethostname()` lub `setdomainname()`.

## Sprawdzenia

Te polecenia wystarczą, aby sprawdzić, czy workload ma własny widok hostname, czy współdzieli z hostem UTS namespace.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Co jest tu interesujące:

- Dopasowanie identyfikatorów namespace z procesem hosta może wskazywać na współdzielenie UTS z hostem.
- Jeśli zmiana hostname wpływa na coś więcej niż sam kontener, workload ma większy wpływ na tożsamość hosta niż powinna.
- Zwykle jest to mniej istotne odkrycie niż problemy z PID, mount lub user namespace, ale nadal potwierdza, jak odizolowany jest proces.

W większości środowisk UTS namespace należy traktować jako wspierającą warstwę izolacji. Rzadko jest to pierwsza rzecz, za którą się gonisz w trakcie breakout, ale wciąż jest częścią ogólnej spójności i bezpieczeństwa widoku kontenera.
{{#include ../../../../../banners/hacktricks-training.md}}
