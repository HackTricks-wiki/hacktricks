# Namespace cgroup

{{#include ../../../../../banners/hacktricks-training.md}}

## Wprowadzenie

Namespace cgroup nie zastępuje cgroups i samodzielnie nie egzekwuje limitów zasobów. Zamiast tego zmienia **sposób, w jaki hierarchia cgroup jest widoczna** dla procesu. Innymi słowy, wirtualizuje widoczne informacje o ścieżkach cgroup, dzięki czemu workload widzi widok ograniczony do kontenera, a nie pełną hierarchię hosta.

Jest to przede wszystkim funkcja ograniczająca widoczność i ilość ujawnianych informacji. Pomaga sprawić, aby środowisko wyglądało na samowystarczalne, oraz ujawnia mniej informacji o układzie cgroup hosta. Może się to wydawać mało istotne, ale nadal ma znaczenie, ponieważ niepotrzebna widoczność struktury hosta może ułatwiać reconnaissance i upraszczać zależne od środowiska łańcuchy exploitów.

## Działanie

Bez prywatnego namespace cgroup proces może widzieć ścieżki cgroup względem hosta, które ujawniają większą część hierarchii maszyny, niż jest to potrzebne. W przypadku prywatnego namespace cgroup informacje z `/proc/self/cgroup` i powiązane obserwacje stają się bardziej lokalne dla własnego widoku kontenera. Jest to szczególnie przydatne we współczesnych stosach runtime, które chcą zapewnić workloadowi czystsze środowisko, ujawniające mniej informacji o hoście.

Wirtualizacja wpływa również na `/proc/<pid>/mountinfo`, a nie tylko na `/proc/<pid>/cgroup`. Gdy odczytujesz informacje o innym procesie z perspektywy innego namespace cgroup, ścieżki znajdujące się poza rootem Twojego namespace są wyświetlane z początkowymi komponentami `../`. Jest to przydatna wskazówka, że przeglądasz strukturę powyżej delegowanego poddrzewa. Istotny szczegół w labach i podczas post-exploitation jest taki, że świeżo utworzony namespace cgroup często wymaga **ponownego zamontowania cgroupfs z wnętrza tego namespace**, zanim `mountinfo` poprawnie odzwierciedli nowy root. W przeciwnym razie nadal możesz zobaczyć mount root, taki jak `/..`, co oznacza, że odziedziczony mount nadal udostępnia widok zakorzeniony w przodku, mimo że sam namespace został już zmieniony.

## Lab

Namespace cgroup możesz sprawdzić za pomocą:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Jeśli chcesz, aby `mountinfo` wyraźniej pokazywał nowy root cgroup namespace, zamontuj ponownie system plików cgroup z poziomu nowej przestrzeni nazw i ponownie porównaj:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
I porównaj zachowanie w czasie wykonywania z:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Zmiana dotyczy głównie tego, co proces może zobaczyć, a nie tego, czy istnieje egzekwowanie zasad cgroup.

## Wpływ na bezpieczeństwo

Namespace cgroup najlepiej rozumieć jako **warstwę wzmacniającą ograniczenie widoczności**. Sam w sobie nie zatrzyma breakout, jeśli kontener ma zapisywalne mounty cgroup, szerokie capabilities lub niebezpieczne środowisko cgroup v1. Jeśli jednak współdzielony jest hostowy namespace cgroup, proces uzyskuje więcej informacji o organizacji systemu i może łatwiej powiązać ścieżki cgroup odnoszące się do hosta z innymi obserwacjami.

W przypadku **cgroup v2** znaczenie namespace staje się nieco większe, ponieważ zasady delegowania są bardziej restrykcyjne. Jeśli hierarchia jest zamontowana z opcją `nsdelegate`, kernel traktuje namespaces cgroup jako granice delegowania: nadrzędne pliki sterujące powinny pozostawać poza zasięgiem odbiorcy delegacji, a zapisy w głównym poziomie namespace są ograniczone do plików bezpiecznych dla delegowania, takich jak `cgroup.procs`, `cgroup.threads` i `cgroup.subtree_control`. Nadal nie sprawia to, że namespace sam w sobie staje się prymitywem escape, ale zmienia zakres informacji, które przejęty workload może sprawdzać, oraz miejsca, w których może bezpiecznie tworzyć pod-cgroupy.

Dlatego ten namespace zwykle nie jest głównym elementem opisów container breakout, ale nadal przyczynia się do szerszego celu, jakim jest ograniczenie wycieku informacji o hoście i zawężenie zakresu delegowania cgroup.

## Nadużycie

Bezpośrednia wartość nadużycia polega głównie na reconnaissance. Jeśli hostowy namespace cgroup jest współdzielony, porównaj widoczne ścieżki i szukaj szczegółów hierarchii ujawniających informacje o hoście:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Jeśli ujawnione są również zapisywalne ścieżki cgroup, połącz tę widoczność z wyszukiwaniem niebezpiecznych starszych interfejsów:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Sama przestrzeń nazw rzadko zapewnia natychmiastowe wydostanie się z kontenera, ale często ułatwia zmapowanie środowiska przed testowaniem primitives nadużyć opartych na cgroup.

Szybka weryfikacja rzeczywistej konfiguracji runtime również pomaga ustalić priorytet ścieżki ataku. Docker udostępnia `--cgroupns=host|private`, podczas gdy Podman obsługuje `host`, `private`, `container:<id>` oraz `ns:<path>`. W przypadku Podmana domyślną wartością jest zwykle **`host` w cgroup v1** oraz **`private` w cgroup v2**, więc samo ustalenie wersji cgroup już mówi, która konfiguracja przestrzeni nazw jest bardziej prawdopodobna, zanim jeszcze przeanalizujesz pełną konfigurację OCI.

### Nowoczesny Recon v2: Czy to delegowane poddrzewo?

Na nowoczesnych hostach interesujące pytanie często nie dotyczy `release_agent`, lecz tego, czy bieżący proces znajduje się w delegowanym poddrzewie **cgroup v2** z wystarczającą widocznością lub prawem zapisu, aby tworzyć zagnieżdżone grupy:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Przydatna interpretacja:

- `cgroup2fs` oznacza, że znajdujesz się w ujednoliconej hierarchii v2, więc klasyczne, właściwe wyłącznie dla v1 łańcuchy `release_agent` nie powinny być pierwszym podejrzewanym mechanizmem.
- `cgroup.controllers` pokazuje, które kontrolery są dostępne z poziomu nadrzędnego, a tym samym do jakich kontrolerów bieżące poddrzewo może potencjalnie przekazać uprawnienia swoim elementom podrzędnym.
- `cgroup.subtree_control` pokazuje, które kontrolery są faktycznie włączone dla elementów potomnych.
- `cgroup.events` udostępnia `populated=0/1`, co jest przydatne do obserwowania, czy poddrzewo stało się puste, ale **nie** jest prymitywem wykonywania kodu na hoście, takim jak `release_agent` w v1.

Jeśli masz już wystarczające uprawnienia, aby bezpośrednio sprawdzić przestrzeń nazw innego procesu, porównaj widoki za pomocą:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Pełny przykład: współdzielona przestrzeń nazw cgroup + zapisywalny cgroup v1

Sama przestrzeń nazw cgroup zwykle nie wystarcza do wykonania escape. Praktyczna eskalacja ma miejsce, gdy ścieżki cgroup ujawniające hosta zostaną połączone z zapisywalnymi interfejsami cgroup v1:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Jeśli te pliki są dostępne i zapisywalne, natychmiast przejdź do pełnego procesu exploitation `release_agent` opisanego w [cgroups.md](../cgroups.md). Skutkiem jest wykonanie kodu hosta z wnętrza kontenera.

Bez zapisywalnych interfejsów cgroup skutki są zazwyczaj ograniczone do rekonesansu.

## Sprawdzenia

Celem tych poleceń jest ustalenie, czy proces ma prywatny widok namespace cgroup, czy też uzyskuje więcej informacji o hierarchii hosta, niż jest to rzeczywiście potrzebne.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Co jest tutaj interesujące:

- Jeśli identyfikator namespace odpowiada procesowi hosta, który Cię interesuje, cgroup namespace może być współdzielony.
- Ścieżki ujawniające informacje o hoście w `/proc/self/cgroup` lub wpisy zakorzenione w ancestorze w `mountinfo` są przydatne podczas rozpoznania, nawet jeśli nie można ich bezpośrednio wykorzystać do exploitacji.
- Jeśli używany jest `cgroup2fs`, skup się na delegowaniu, widocznych kontrolerach i zapisywalnych poddrzewach, zamiast zakładać, że nadal istnieją stare prymitywy v1.
- Jeśli mounty cgroup są również zapisywalne, kwestia widoczności staje się znacznie ważniejsza.

cgroup namespace należy traktować jako warstwę hardeningu widoczności, a nie jako podstawowy mechanizm zapobiegania escape. Niepotrzebne ujawnianie struktury cgroup hosta zwiększa wartość rozpoznawczą dla atakującego.

## Referencje

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Dokumentacja Linux kernel dotycząca cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
