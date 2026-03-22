# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

cgroup namespace nie zastępuje cgroups i sam z siebie nie wymusza limitów zasobów. Zamiast tego zmienia **to, jak hierarchia cgroup jest widoczna** dla procesu. Innymi słowy, wirtualizuje widoczne informacje o ścieżkach cgroup, tak aby workload widział widok ograniczony do kontenera zamiast pełnej hierarchii hosta.

To przede wszystkim funkcja zmniejszająca widoczność i ilość ujawnianych informacji. Pomaga sprawić, że środowisko wygląda na samodzielne i ujawnia mniej o układzie cgroup hosta. Może to brzmieć niepozornie, ale ma znaczenie — zbędna widoczność struktury hosta może ułatwiać rozpoznanie i upraszczać łańcuchy exploitów zależne od środowiska.

## Działanie

Bez prywatnego cgroup namespace proces może widzieć ścieżki cgroup względem hosta, które ujawniają więcej hierarchii maszyny niż jest użyteczne. Z prywatnym cgroup namespace `/proc/self/cgroup` i powiązane obserwacje stają się bardziej zlokalizowane do widoku kontenera. To jest szczególnie pomocne w nowoczesnych środowiskach uruchomieniowych, które chcą, aby workload widział czystsze środowisko ujawniające mniej informacji o hoście.

## Laboratorium

Możesz zbadać cgroup namespace za pomocą:
```bash
sudo unshare --cgroup --fork bash
cat /proc/self/cgroup
ls -l /proc/self/ns/cgroup
```
I porównaj zachowanie podczas wykonywania z:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
The change is mostly about what the process can see, not about whether cgroup enforcement exists.

## Wpływ na bezpieczeństwo

The cgroup namespace is best understood as a **warstwa ograniczająca widoczność**. Sama w sobie nie zatrzyma breakout, jeśli container ma zapisywalne cgroup mounts, szerokie capabilities lub niebezpieczne środowisko cgroup v1. Jednak jeśli host cgroup namespace jest współdzielona, proces dowiaduje się więcej o tym, jak system jest zorganizowany i może łatwiej dopasować host-relative cgroup paths do innych obserwacji.

So while this namespace is not usually the star of container breakout writeups, it still contributes to the broader goal of minimizing host information leakage.

## Nadużycie

The immediate abuse value is mostly reconnaissance. If the host cgroup namespace is shared, compare the visible paths and look for host-revealing hierarchy details:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
Jeżeli zapisywalne ścieżki cgroup są również widoczne, połącz tę widoczność z wyszukiwaniem niebezpiecznych przestarzałych interfejsów:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Sam namespace rzadko daje natychmiastowy escape, ale często ułatwia zmapowanie środowiska przed testowaniem cgroup-based abuse primitives.

### Pełny przykład: Shared cgroup Namespace + Writable cgroup v1

Sam cgroup namespace zazwyczaj nie wystarcza do escape. Praktyczna eskalacja następuje, gdy host-revealing cgroup paths zostaną połączone z writable cgroup v1 interfaces:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Jeśli te pliki są osiągalne i zapisywalne, natychmiast przejdź do pełnego procesu eksploatacji `release_agent` z [cgroups.md](../cgroups.md). Skutkiem jest wykonanie kodu na hoście z wnętrza kontenera.

Bez zapisywalnych interfejsów cgroup, wpływ zwykle ogranicza się do rozpoznania.

## Sprawdzenia

Celem tych poleceń jest sprawdzenie, czy proces ma prywatny widok cgroup namespace, czy też uzyskuje więcej informacji o hierarchii hosta, niż jest mu to naprawdę potrzebne.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
Co jest tutaj istotne:

- Jeśli identyfikator przestrzeni nazw pasuje do procesu hosta, którym się interesujesz, przestrzeń nazw cgroup może być współdzielona.
- Ścieżki ujawniające informacje o hoście w `/proc/self/cgroup` są użyteczne do rozpoznania, nawet jeśli nie są bezpośrednio eksploatowalne.
- Jeśli punkty montowania cgroup są również zapisywalne, kwestia widoczności staje się znacznie ważniejsza.

Przestrzeń nazw cgroup powinna być traktowana jako warstwa wzmacniająca ochronę widoczności, a nie jako podstawowy mechanizm zapobiegania ucieczkom. Niepotrzebne ujawnianie struktury cgroup hosta zwiększa wartość rozpoznania dla atakującego.
{{#include ../../../../../banners/hacktricks-training.md}}
