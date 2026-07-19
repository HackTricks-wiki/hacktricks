# Przestrzeń nazw UTS

{{#include ../../../../../banners/hacktricks-training.md}}

## Omówienie

Przestrzeń nazw UTS izoluje **hostname** oraz **NIS domain name** widoczne dla procesu. Na pierwszy rzut oka może się to wydawać błahe w porównaniu z przestrzeniami nazw mount, PID czy user, ale jest to element sprawiający, że kontener wygląda jak osobny host. Wewnątrz przestrzeni nazw workload może widzieć, a czasami także zmieniać hostname lokalny dla tej przestrzeni, zamiast globalnego dla całej maszyny.

Sam w sobie zwykle nie jest to główny element scenariusza breakout. Jednak gdy host UTS namespace jest współdzielony, odpowiednio uprzywilejowany proces może wpływać na ustawienia związane z tożsamością hosta, co może mieć znaczenie operacyjne, a czasami również security-wise.

## Laboratorium

Możesz utworzyć przestrzeń nazw UTS za pomocą:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Zmiana hostname pozostaje lokalna dla tej przestrzeni nazw i nie zmienia globalnego hostname hosta. To prosta, ale skuteczna demonstracja właściwości izolacji.

## Użycie w Runtime

Standardowe kontenery otrzymują izolowaną przestrzeń nazw UTS. Docker i Podman mogą dołączyć do przestrzeni nazw UTS hosta za pomocą `--uts=host`, a podobne wzorce współdzielenia hosta mogą występować w innych Runtime i systemach orkiestracji. Jednak przez większość czasu prywatna izolacja UTS jest po prostu częścią standardowej konfiguracji kontenera i wymaga niewielkiej uwagi operatora.

## Wpływ na bezpieczeństwo

Mimo że przestrzeń nazw UTS zwykle nie jest najniebezpieczniejszą przestrzenią nazw do współdzielenia, nadal przyczynia się do integralności granicy kontenera. Jeśli przestrzeń nazw UTS hosta jest udostępniona, a proces ma wymagane uprawnienia, może być w stanie zmieniać informacje związane z hostname hosta. Może to wpływać na monitoring, logowanie, założenia operacyjne lub skrypty podejmujące decyzje dotyczące zaufania na podstawie danych identyfikujących hosta.

## Nadużycie

Jeśli przestrzeń nazw UTS hosta jest współdzielona, praktyczne pytanie brzmi, czy proces może modyfikować ustawienia tożsamości hosta, a nie tylko je odczytywać:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Jeśli kontener ma również wymagane uprawnienia, sprawdź, czy można zmienić nazwę hosta:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Jest to przede wszystkim problem z integralnością i wpływem na działanie, a nie pełny escape, ale nadal pokazuje, że kontener może bezpośrednio wpływać na właściwość globalną dla hosta.

Wpływ:

- manipulowanie tożsamością hosta
- wprowadzanie w błąd logów, monitoringu lub automatyzacji, które ufają nazwie hosta
- zwykle nie jest to samodzielnie pełny escape, chyba że zostanie połączony z innymi słabościami

W środowiskach typu Docker przydatnym wzorcem wykrywania po stronie hosta jest:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Kontenery z `UTSMode=host` współdzielą hostową przestrzeń nazw UTS i powinny zostać dokładniej przeanalizowane, jeśli mają również capabilities umożliwiające wywołanie `sethostname()` lub `setdomainname()`.

## Kontrole

Te polecenia wystarczą, aby sprawdzić, czy workload ma własny widok hostname, czy współdzieli hostową przestrzeń nazw UTS.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Co jest tutaj interesujące:

- Identyczne identyfikatory namespace między procesem hosta a procesem może wskazywać na współdzielenie hostowego UTS.
- Jeśli zmiana hostname wpływa na coś więcej niż tylko sam kontener, workload ma większy wpływ na tożsamość hosta, niż powinien.
- Zwykle jest to finding o niższym priorytecie niż problemy z namespace PID, mount lub user, ale nadal potwierdza, jak naprawdę odizolowany jest proces.

W większości środowisk namespace UTS najlepiej traktować jako pomocniczą warstwę izolacji. Rzadko jest to pierwsza rzecz, którą analizuje się podczas breakout, ale nadal stanowi część ogólnej spójności i bezpieczeństwa widoku kontenera.
{{#include ../../../../../banners/hacktricks-training.md}}
