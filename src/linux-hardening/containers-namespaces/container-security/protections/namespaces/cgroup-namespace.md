# Namespace cgroup

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

Namespace cgroup nie zastępuje cgroups i sam nie egzekwuje limitów zasobów. Zamiast tego zmienia sposób, w jaki hierarchia cgroup jest widoczna dla procesu. Innymi słowy, wirtualizuje widoczne informacje o ścieżkach cgroup, dzięki czemu workload widzi widok ograniczony do kontenera, a nie pełną hierarchię hosta.

Jest to przede wszystkim funkcja zapewniająca widoczność i redukcję informacji. Pomaga sprawić, że środowisko wygląda na samowystarczalne, oraz ujawnia mniej informacji o układzie cgroup hosta. Może się to wydawać niewielką korzyścią, ale nadal ma znaczenie, ponieważ zbędna widoczność struktury hosta może ułatwiać rekonesans i upraszczać zależne od środowiska łańcuchy exploitów.

## Działanie

Bez prywatnego namespace cgroup proces może widzieć ścieżki cgroup względem hosta, które ujawniają większą część hierarchii maszyny, niż jest to użyteczne. Z prywatnym namespace cgroup zawartość `/proc/self/cgroup` i powiązane obserwacje stają się bardziej lokalne dla własnego widoku kontenera. Jest to szczególnie pomocne we współczesnych stosach runtime, które chcą, aby workload widział czystsze środowisko, ujawniające mniej informacji o hoście.

Wirtualizacja wpływa również na `/proc/<pid>/mountinfo`, a nie tylko na `/proc/<pid>/cgroup`. Podczas odczytywania informacji o innym procesie z perspektywy innego namespace cgroup ścieżki znajdujące się poza katalogiem głównym Twojego namespace są wyświetlane z początkowymi komponentami `../`, co stanowi przydatną wskazówkę, że zaglądasz powyżej przydzielonego poddrzewa. Istotnym niuansem w labach i podczas post-exploitation jest to, że świeżo utworzony namespace cgroup często wymaga **ponownego zamontowania cgroupfs z poziomu tego namespace**, zanim `mountinfo` będzie poprawnie odzwierciedlać nowy katalog główny. W przeciwnym razie nadal możesz widzieć katalog główny montowania, taki jak `/..`, co oznacza, że odziedziczone montowanie nadal udostępnia widok zakorzeniony w katalogu nadrzędnym, mimo że sam namespace został już zmieniony.<sup>[[1]](#references)</sup>

## Lab

Możesz sprawdzić namespace cgroup za pomocą:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Jeśli chcesz, aby `mountinfo` wyraźniej pokazywał nowy root cgroup namespace, wykonaj remount systemu plików cgroup z wnętrza nowej przestrzeni nazw i ponownie porównaj:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
I porównaj zachowanie w czasie działania z:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Zmiana dotyczy głównie tego, co proces może zobaczyć, a nie tego, czy istnieje egzekwowanie zasad cgroup.

## Wpływ na bezpieczeństwo

Przestrzeń nazw cgroup najlepiej rozumieć jako **warstwę hardeningu widoczności**. Sama w sobie nie powstrzyma breakout, jeśli kontener ma zapisywalne mounty cgroup, szerokie capabilities lub niebezpieczne środowisko cgroup v1. Jeśli jednak współdzielona jest przestrzeń nazw cgroup hosta, proces uzyskuje więcej informacji o organizacji systemu i może łatwiej powiązać ścieżki cgroup względem hosta z innymi obserwacjami.

W przypadku **cgroup v2** przestrzeń nazw zaczyna mieć nieco większe znaczenie, ponieważ reguły delegowania są bardziej restrykcyjne. Jeśli hierarchia jest zamontowana z opcją `nsdelegate`, kernel traktuje przestrzenie nazw cgroup jako granice delegowania: nadrzędne pliki sterujące powinny pozostawać poza zasięgiem delegowanego procesu, a zapisy w katalogu głównym przestrzeni nazw są ograniczone do plików bezpiecznych dla delegowania, takich jak `cgroup.procs`, `cgroup.threads` i `cgroup.subtree_control`.<sup>[[2]](#references)</sup> Nadal nie sprawia to, że sama przestrzeń nazw staje się primitive'em umożliwiającym escape, ale zmienia zakres informacji, które przejęty workload może sprawdzać, oraz miejsca, w których może bezpiecznie tworzyć podgrupy cgroup.

Chociaż ta przestrzeń nazw zwykle nie odgrywa głównej roli w opisach container breakout, nadal przyczynia się do szerszego celu, jakim jest minimalizowanie wycieku informacji o hoście i ograniczanie delegowania cgroup.

## Abuse

Bezpośrednia wartość abuse polega głównie na reconnaissance. Jeśli współdzielona jest przestrzeń nazw cgroup hosta, porównaj widoczne ścieżki i poszukaj szczegółów hierarchii ujawniających informacje o hoście:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Jeśli widoczne są również ścieżki cgroup umożliwiające zapis, połącz tę widoczność z wyszukiwaniem niebezpiecznych starszych interfejsów:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Sama namespace rzadko zapewnia natychmiastowy escape, ale często ułatwia mapowanie środowiska przed testowaniem prymitywów nadużycia opartych na cgroup.

Szybka weryfikacja rzeczywistego środowiska uruchomieniowego pomaga również ustalić priorytet ścieżki ataku. Docker udostępnia `--cgroupns=host|private`, natomiast Podman obsługuje `host`, `private`, `container:<id>` oraz `ns:<path>`. W przypadku Podmana domyślnie jest to zazwyczaj **`host` w cgroup v1** oraz **`private` w cgroup v2**, więc samo ustalenie wersji cgroup już informuje, która konfiguracja namespace jest bardziej prawdopodobna, zanim jeszcze przeanalizujesz pełną konfigurację OCI.

### Modern v2 Recon: Czy To Delegowane Poddrzewo?

Na współczesnych hostach interesujące pytanie często nie dotyczy `release_agent`, lecz tego, czy bieżący proces znajduje się wewnątrz delegowanego poddrzewa **cgroup v2** z wystarczającą widocznością lub dostępem do zapisu, aby tworzyć zagnieżdżone grupy:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Przydatna interpretacja:

- `cgroup2fs` oznacza, że znajdujesz się w ujednoliconej hierarchii v2, więc klasyczne, dostępne wyłącznie w v1 łańcuchy `release_agent` nie powinny być Twoim pierwszym założeniem.
- `cgroup.controllers` pokazuje, które kontrolery są dostępne z nadrzędnej grupy, a tym samym które z nich bieżące poddrzewo może potencjalnie przekazywać swoim dzieciom.
- `cgroup.subtree_control` pokazuje, które kontrolery są faktycznie włączone dla elementów potomnych.
- `cgroup.events` udostępnia `populated=0/1`, co jest przydatne do obserwowania, czy poddrzewo stało się puste, ale **nie jest prymitywem wykonywania kodu na hoście**, takim jak v1 `release_agent`.

Jeśli masz już wystarczające uprawnienia, aby bezpośrednio sprawdzić przestrzeń nazw innego procesu, porównaj widoki za pomocą:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Pełny przykład: współdzielona przestrzeń nazw cgroup + zapisywalny cgroup v1

Sama przestrzeń nazw cgroup zwykle nie wystarcza do escape. Praktyczna eskalacja ma miejsce, gdy ścieżki cgroup ujawniające hosta zostaną połączone z zapisywalnymi interfejsami cgroup v1:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Jeśli te pliki są dostępne i można w nich zapisywać, natychmiast przejdź do pełnego procesu exploitation `release_agent` z [cgroups.md](../cgroups.md). Skutkiem jest wykonanie kodu hosta z wnętrza kontenera.

Bez zapisywalnych interfejsów cgroup skutki są zwykle ograniczone do rekonesansu.

## Sprawdzenie

Celem tych poleceń jest ustalenie, czy proces ma prywatny widok przestrzeni nazw cgroup, czy też uzyskuje więcej informacji o hierarchii hosta, niż jest to rzeczywiście potrzebne.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Co jest tutaj interesujące:

- Jeśli identyfikator namespace odpowiada procesowi hosta, na którym Ci zależy, namespace cgroup może być współdzielony.
- Ścieżki ujawniające hosta w `/proc/self/cgroup` lub wpisy w `mountinfo` zakotwiczone w katalogu głównym przodka są przydatne podczas reconnaissance, nawet jeśli nie da się ich bezpośrednio wykorzystać.
- Jeśli używany jest `cgroup2fs`, skup się na delegowaniu, widocznych kontrolerach i zapisywalnych poddrzewach, zamiast zakładać, że stare prymitywy v1 nadal istnieją.
- Jeśli mounty cgroup są również zapisywalne, kwestia widoczności staje się znacznie ważniejsza.

Namespace cgroup powinien być traktowany jako warstwa hardeningu widoczności, a nie jako podstawowy mechanizm zapobiegania escape. Niepotrzebne ujawnianie struktury cgroup hosta zwiększa wartość reconnaissance dla atakującego.

## References

- [1] [cgroup_namespaces(7) — Linux manual page](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [2] [Control Group v2 — The Linux Kernel documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
