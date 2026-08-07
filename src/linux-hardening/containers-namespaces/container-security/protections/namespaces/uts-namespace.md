# Przestrzeń nazw UTS

{{#include ../../../../../banners/hacktricks-training.md}}

## Omówienie

Przestrzeń nazw UTS izoluje **hostname** i **nazwę domeny NIS** widoczne dla procesu. Na pierwszy rzut oka może się to wydawać nieistotne w porównaniu z przestrzeniami nazw mount, PID lub user, ale jest to część mechanizmu, dzięki któremu kontener wygląda jak osobny host. Wewnątrz tej przestrzeni obciążenie może odczytywać, a czasami także zmieniać hostname lokalny dla tej przestrzeni, a nie globalny dla całej maszyny.

Samo to zazwyczaj nie jest najważniejszym elementem scenariusza breakout. Jednak gdy współdzielona jest przestrzeń nazw UTS hosta, odpowiednio uprzywilejowany proces może wpływać na ustawienia związane z tożsamością hosta, co może mieć znaczenie operacyjne, a sporadycznie również związane z bezpieczeństwem.

## Laboratorium

Możesz utworzyć przestrzeń nazw UTS za pomocą:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
Zmiana hostname pozostaje lokalna dla tej przestrzeni nazw i nie zmienia globalnego hostname hosta. To prosty, ale skuteczny pokaz właściwości izolacji.

## Użycie w środowisku uruchomieniowym

Zwykłe kontenery otrzymują izolowaną przestrzeń nazw UTS. Docker i Podman mogą dołączać do przestrzeni nazw UTS hosta za pomocą `--uts=host`, a podobne wzorce współdzielenia hosta mogą występować w innych środowiskach uruchomieniowych i systemach orkiestracji. Jednak przez większość czasu prywatna izolacja UTS jest po prostu częścią standardowej konfiguracji kontenera i wymaga niewielkiej uwagi operatora.

## Wpływ na bezpieczeństwo

Mimo że przestrzeń nazw UTS zwykle nie jest najniebezpieczniejszą przestrzenią nazw do współdzielenia, nadal przyczynia się do zachowania integralności granicy kontenera. Jeśli przestrzeń nazw UTS hosta jest udostępniona, a proces ma wymagane uprawnienia, może być w stanie zmienić informacje związane z hostname hosta. Może to wpływać na monitoring, logowanie, założenia operacyjne lub skrypty podejmujące decyzje o zaufaniu na podstawie danych identyfikujących hosta.

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
Jest to przede wszystkim problem integralności i wpływu operacyjnego, a nie pełny escape, ale nadal pokazuje, że kontener może bezpośrednio wpływać na właściwość globalną dla hosta.

Wpływ:

- manipulowanie tożsamością hosta
- dezorientujące logi, monitoring lub automatyzacja, które ufają nazwie hosta
- zwykle nie jest to samodzielnie pełny escape, chyba że zostanie połączone z innymi słabościami

W środowiskach w stylu Docker użyteczny wzorzec wykrywania po stronie hosta to:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Kontenery z ustawieniem `UTSMode=host` współdzielą hostową przestrzeń nazw UTS i należy je dokładniej przeanalizować, jeśli mają również capabilities umożliwiające wywołanie `sethostname()` lub `setdomainname()`.

## Sprawdzenia

Te polecenia wystarczą, aby sprawdzić, czy workload ma własny widok nazwy hosta, czy współdzieli hostową przestrzeń nazw UTS.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
Co jest tutaj interesujące:

- Dopasowanie identyfikatorów przestrzeni nazw do procesu hosta może wskazywać na współdzielenie UTS z hostem.
- Jeśli zmiana hostname wpływa na coś więcej niż tylko sam kontener, workload ma większy wpływ na tożsamość hosta, niż powinien.
- Zwykle jest to finding o niższym priorytecie niż problemy z przestrzeniami nazw PID, mount lub user, ale nadal potwierdza, jak bardzo proces jest rzeczywiście odizolowany.

W większości środowisk przestrzeń nazw UTS najlepiej traktować jako pomocniczą warstwę izolacji. Rzadko jest ona pierwszą rzeczą, którą bada się podczas breakout, ale nadal stanowi część ogólnej spójności i bezpieczeństwa widoku kontenera.

{{#include ../../../../../banners/hacktricks-training.md}}
