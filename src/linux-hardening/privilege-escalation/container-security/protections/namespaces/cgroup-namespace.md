# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

cgroup namespace nie zastępuje cgroups i sam z siebie nie wymusza limitów zasobów. Zamiast tego zmienia **to, jak hierarchia cgroup wygląda** dla procesu. Innymi słowy, virtualizuje widoczne informacje o ścieżce cgroup, tak aby workload widział widok ograniczony do kontenera, a nie pełną hierarchię hosta.

To przede wszystkim funkcja widoczności i redukcji informacji. Pomaga sprawić, że środowisko wygląda na samowystarczalne i ujawnia mniej o układzie cgroup hosta. Może brzmieć to skromnie, ale nadal ma znaczenie, ponieważ niepotrzebna widoczność struktury hosta może pomóc w reconnaissance i uprościć łańcuchy exploit zależne od środowiska.

## Operation

Bez prywatnego cgroup namespace proces może widzieć ścieżki cgroup względne względem hosta, które ujawniają więcej hierarchii maszyny, niż jest to użyteczne. Z prywatnym cgroup namespace `/proc/self/cgroup` i powiązane obserwacje stają się bardziej lokalne względem własnego widoku kontenera. Jest to szczególnie przydatne w nowoczesnych stack runtime, które chcą, aby workload widział czystsze środowisko, mniej ujawniające hosta.

Virtualization wpływa też na `/proc/<pid>/mountinfo`, nie tylko na `/proc/<pid>/cgroup`. Gdy odczytujesz inny proces z perspektywy innego cgroup-namespace, ścieżki poza rootem twojego namespace są pokazywane z wiodącymi komponentami `../`, co jest wygodną wskazówką, że patrzysz powyżej swojego delegowanego poddrzewa. Przydatnym niuansem w labach i post-exploitation jest to, że świeżo utworzony cgroup namespace często wymaga **cgroupfs remount z wnętrza tego namespace** zanim `mountinfo` poprawnie odzwierciedli nowy root. W przeciwnym razie możesz nadal widzieć root montowania taki jak `/..`, co oznacza, że odziedziczony mount nadal pokazuje widok zakorzeniony w przodku, mimo że sam namespace już się zmienił.

## Lab

You can inspect a cgroup namespace with:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Jeśli chcesz, aby `mountinfo` wyraźniej pokazywał nowy root cgroup-namespace, zamontuj ponownie system plików cgroup z wnętrza nowego namespace i porównaj ponownie:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
I porównaj zachowanie w czasie wykonania z:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Zmiana dotyczy głównie tego, co proces może zobaczyć, a nie tego, czy istnieje enforcement cgroup.

## Security Impact

cgroup namespace najlepiej rozumieć jako warstwę **visibility-hardening**. Sama w sobie nie zatrzyma breakout, jeśli kontener ma zapisywalne mounty cgroup, szerokie capabilities lub niebezpieczne środowisko cgroup v1. Jednak jeśli host cgroup namespace jest współdzielony, proces dowiaduje się więcej o tym, jak zorganizowany jest system, i może łatwiej dopasować host-relative ścieżki cgroup do innych obserwacji.

W **cgroup v2** namespace zaczyna mieć trochę większe znaczenie, ponieważ reguły delegation są bardziej rygorystyczne. Jeśli hierarchia jest zamontowana z `nsdelegate`, kernel traktuje cgroup namespaces jako granice delegation: nadrzędne control files powinny pozostawać poza zasięgiem delegatee, a zapisy w root namespace są ograniczone do plików bezpiecznych dla delegation, takich jak `cgroup.procs`, `cgroup.threads` i `cgroup.subtree_control`. Nadal nie czyni to z namespace samodzielnego prymitywu escape, ale zmienia to, co skompromitowany workload może sprawdzić i gdzie może bezpiecznie tworzyć sub-cgroups.

Więc choć ten namespace zwykle nie jest gwiazdą opisów container breakout, nadal pomaga w szerszym celu minimalizowania host information leakage i ograniczania delegation cgroup.

## Abuse

Bezpośrednia wartość abuse to głównie reconnaissance. Jeśli host cgroup namespace jest współdzielony, porównaj widoczne paths i szukaj szczegółów hierarchii ujawniających host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Jeśli również są ujawnione zapisywalne ścieżki cgroup, połącz tę widoczność z wyszukiwaniem niebezpiecznych legacy interfaces:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Sam namespace rzadko daje natychmiastowe escape, ale często ułatwia mapowanie środowiska przed testowaniem primitive opartego na cgroup abuse.

Szybki check runtime reality także pomaga priorytetyzować attack path. Docker udostępnia `--cgroupns=host|private`, a Podman wspiera `host`, `private`, `container:<id>` oraz `ns:<path>`. W przypadku Podmana domyślne ustawienie to zwykle **`host` na cgroup v1** i **`private` na cgroup v2**, więc samo ustalenie wersji cgroup już mówi, które posture namespace jest bardziej prawdopodobne, zanim jeszcze sprawdzisz pełną konfigurację OCI.

### Modern v2 Recon: Is This A Delegated Subtree?

Na nowoczesnych hostach interesujące pytanie często nie brzmi `release_agent`, lecz czy bieżący proces znajduje się w delegowanym poddrzewie **cgroup v2** z wystarczającą widocznością lub dostępem do zapisu, aby tworzyć zagnieżdżone grupy:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Przydatna interpretacja:

- `cgroup2fs` oznacza, że jesteś w zunifikowanej hierarchii v2, więc klasyczne łańcuchy `release_agent` tylko dla v1 powinny przestać być Twoim pierwszym wyborem.
- `cgroup.controllers` pokazuje, które kontrolery są dostępne od parent, a więc na co bieżące subtree mogłoby potencjalnie rozgałęziać się do children.
- `cgroup.subtree_control` pokazuje, które kontrolery są faktycznie włączone dla descendants.
- `cgroup.events` ujawnia `populated=0/1`, co jest przydatne do obserwowania, czy subtree stało się puste, ale **nie** jest primitive do host-code-execution jak v1 `release_agent`.

Jeśli masz już wystarczające privilege, aby bezpośrednio sprawdzić namespace innego procesu, porównaj widoki za pomocą:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Pełny przykład: Shared cgroup Namespace + Writable cgroup v1

cgroup namespace samo w sobie zwykle nie wystarcza do escape. Praktyczna eskalacja następuje, gdy ścieżki cgroup ujawniające host są połączone z writable interfejsami cgroup v1:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Jeśli te pliki są dostępne i zapisywalne, natychmiast przejdź do pełnego flow exploitation `release_agent` z [cgroups.md](../cgroups.md). Wpływ to host code execution z wnętrza kontenera.

Bez zapisywalnych interfejsów cgroup wpływ jest zwykle ograniczony do reconnaissance.

## Checks

Celem tych poleceń jest sprawdzenie, czy proces ma prywatny widok cgroup namespace, czy dowiaduje się więcej o hierarchii hosta, niż naprawdę potrzebuje.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Co jest tutaj interesujące:

- Jeśli identyfikator namespace pasuje do hostowego procesu, który Cię interesuje, cgroup namespace może być współdzielony.
- Ścieżki ujawniające hosta w `/proc/self/cgroup` lub wpisy zakotwiczone w root-ancestor w `mountinfo` są przydatne do reconnaissance, nawet jeśli nie da się ich bezpośrednio wykorzystać.
- Jeśli używany jest `cgroup2fs`, skup się na delegation, widocznych controllerach i zapisywalnych poddrzewach, zamiast zakładać, że nadal istnieją stare primitive v1.
- Jeśli mounty cgroup są też zapisywalne, kwestia visibility staje się znacznie ważniejsza.

cgroup namespace należy traktować jako warstwę hardeningu visibility, a nie jako główny mechanizm zapobiegania escape. Niepotrzebne ujawnianie hostowej struktury cgroup dodaje napastnikowi wartość reconnaissance.

## References

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
