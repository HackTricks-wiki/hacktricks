# Przestrzeń nazw cgroup

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

Przestrzeń nazw cgroup nie zastępuje cgroups i sama w sobie nie wymusza limitów zasobów. Zamiast tego zmienia **sposób, w jaki hierarchia cgroup jest widoczna** dla procesu. Innymi słowy wirtualizuje widoczne informacje o ścieżce cgroup, tak że aplikacja widzi widok ograniczony do kontenera zamiast pełnej hierarchii hosta.

To przede wszystkim funkcja ograniczająca widoczność i ilość ujawnianych informacji. Pomaga sprawić, że środowisko wygląda na samodzielne i ujawnia mniej o układzie cgroup hosta. Może to brzmieć nieistotnie, ale ma znaczenie, ponieważ niepotrzebna widoczność struktury hosta może ułatwić rozpoznanie i upraszczać łańcuchy exploitów zależne od środowiska.

## Działanie

Bez prywatnej przestrzeni nazw cgroup proces może widzieć ścieżki cgroup względem hosta, które ujawniają więcej hierarchii maszyny niż jest to użyteczne. Z prywatną przestrzenią nazw cgroup `/proc/self/cgroup` i powiązane obserwacje stają się bardziej zlokalizowane w widoku samego kontenera. Jest to szczególnie pomocne w nowoczesnych stosach runtime, które chcą, aby aplikacja widziała czyściejsze, mniej ujawniające hosta środowisko.

## Laboratorium

Możesz zbadać przestrzeń nazw cgroup za pomocą:
```bash
sudo unshare --cgroup --fork bash
cat /proc/self/cgroup
ls -l /proc/self/ns/cgroup
```
I porównaj zachowanie podczas działania z:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Zmiana dotyczy głównie tego, co proces może zobaczyć, a nie tego, czy egzekwowanie cgroup istnieje.

## Wpływ na bezpieczeństwo

cgroup namespace najlepiej rozumieć jako **warstwę utrudniającą widoczność**. Sama w sobie nie powstrzyma container breakout, jeśli kontener ma zapisywalne cgroup mounts, szerokie capabilities lub niebezpieczne środowisko cgroup v1. Jednak jeśli host cgroup namespace jest współdzielona, proces dowiaduje się więcej o organizacji systemu i może łatwiej dopasować host-relative cgroup paths do innych obserwacji.

Więc chociaż ten namespace zwykle nie jest gwiazdą opisów container breakout, nadal przyczynia się do szerszego celu minimalizowania ujawniania informacji o hoście.

## Nadużycia

Bezpośrednia wartość nadużycia to głównie rozpoznanie. Jeśli host cgroup namespace jest współdzielona, porównaj widoczne ścieżki i szukaj szczegółów hierarchii ujawniających informacje o hoście:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
Jeśli zapisywalne ścieżki cgroup są również odsłonięte, połącz tę widoczność z wyszukiwaniem niebezpiecznych, przestarzałych interfejsów:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
The namespace itself rarely gives instant escape, but it often makes the environment easier to map before testing cgroup-based abuse primitives.

### Pełny przykład: Shared cgroup Namespace + Writable cgroup v1

Sam cgroup namespace zwykle nie wystarcza do escape. Praktyczna escalation ma miejsce, gdy host-revealing cgroup paths są połączone z writable cgroup v1 interfaces:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Jeśli te pliki są osiągalne i zapisywalne, pivot immediately into the full `release_agent` exploitation flow from [cgroups.md](../cgroups.md). Skutkiem jest wykonanie kodu na hoście z wnętrza kontenera.

Bez zapisywalnych cgroup interfaces wpływ jest zwykle ograniczony do reconnaissance.

## Sprawdzenia

Celem tych poleceń jest sprawdzenie, czy proces ma prywatny cgroup namespace view, czy też dowiaduje się więcej o hierarchii hosta niż naprawdę potrzebuje.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
- Jeśli identyfikator namespace pasuje do procesu hosta, którym się interesujesz, cgroup namespace może być współdzielona.
- Ścieżki ujawniające hosta w `/proc/self/cgroup` są przydatne do rozpoznania, nawet jeśli nie są bezpośrednio eksploatowalne.
- Jeśli punkty montowania cgroup są także zapisywalne, kwestia widoczności staje się znacznie ważniejsza.

Cgroup namespace należy traktować jako warstwę utwardzającą widoczność, a nie jako główny mechanizm zapobiegający ucieczkom. Niepotrzebne ujawnianie struktury cgroup hosta zwiększa wartość rozpoznawczą dla atakującego.
