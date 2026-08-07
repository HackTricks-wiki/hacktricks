# Przestrzenie nazw

{{#include ../../../../../banners/hacktricks-training.md}}

Przestrzenie nazw to funkcja kernela, dzięki której kontener sprawia wrażenie „własnej maszyny”, mimo że w rzeczywistości jest tylko drzewem procesów hosta. Nie tworzą nowego kernela i nie wirtualizują wszystkiego, ale pozwalają kernelowi prezentować różne widoki wybranych zasobów różnym grupom procesów. To podstawa iluzji kontenera: workload widzi system plików, tablicę procesów, stos sieciowy, hostname, zasoby IPC oraz model tożsamości użytkowników i grup, które wyglądają na lokalne, mimo że bazowy system jest współdzielony.

Dlatego przestrzenie nazw są pierwszym pojęciem, z którym większość osób spotyka się podczas nauki działania kontenerów. Jednocześnie są jednym z najczęściej błędnie rozumianych pojęć, ponieważ czytelnicy często zakładają, że „posiada przestrzenie nazw” oznacza „jest bezpiecznie odizolowany”. W rzeczywistości przestrzeń nazw izoluje tylko konkretną klasę zasobów, dla której została zaprojektowana. Proces może mieć prywatną przestrzeń PID i nadal stanowić zagrożenie, ponieważ ma zapisywalny bind mount hosta. Może mieć prywatną przestrzeń sieciową i nadal stanowić zagrożenie, ponieważ zachowuje `CAP_SYS_ADMIN` i działa bez seccomp. Przestrzenie nazw są fundamentem, ale stanowią tylko jedną warstwę końcowej granicy bezpieczeństwa.

## Typy przestrzeni nazw

Kontenery Linux często korzystają jednocześnie z kilku typów przestrzeni nazw. **Mount namespace** zapewnia procesowi osobną tablicę mountów, a tym samym kontrolowany widok systemu plików. **PID namespace** zmienia widoczność i numerację procesów, dzięki czemu workload widzi własne drzewo procesów. **Network namespace** izoluje interfejsy, trasy, sockety i stan firewalla. **IPC namespace** izoluje SysV IPC oraz kolejki komunikatów POSIX. **UTS namespace** izoluje hostname i nazwę domeny NIS. **User namespace** mapuje identyfikatory użytkowników i grup, dzięki czemu root wewnątrz kontenera nie musi oznaczać roota na hoście. **Cgroup namespace** wirtualizuje widoczną hierarchię cgroup, a **time namespace** wirtualizuje wybrane zegary w nowszych kernelach.

Każda z tych przestrzeni nazw rozwiązuje inny problem. Dlatego praktyczna analiza bezpieczeństwa kontenerów często sprowadza się do sprawdzenia, **które przestrzenie nazw są izolowane** oraz **które zostały celowo współdzielone z hostem**.

## Współdzielenie przestrzeni nazw hosta

Wiele container breakout nie zaczyna się od luki w kernelu. Zaczynają się od celowego osłabienia modelu izolacji przez operatora. Przykłady `--pid=host`, `--network=host` i `--userns=host` to **flagi CLI w stylu Docker/Podman**, użyte tutaj jako konkretne przykłady współdzielenia przestrzeni nazw hosta. Inne runtime wyrażają tę samą ideę w inny sposób. W Kubernetes odpowiedniki zwykle pojawiają się jako ustawienia Pod, takie jak `hostPID: true`, `hostNetwork: true` lub `hostIPC: true`. W niższych warstwach runtime, takich jak containerd lub CRI-O, ten sam efekt jest często osiągany za pomocą wygenerowanej konfiguracji runtime OCI, a nie za pomocą flagi dostępnej dla użytkownika i mającej taką samą nazwę. We wszystkich tych przypadkach rezultat jest podobny: workload nie otrzymuje już domyślnego, izolowanego widoku przestrzeni nazw.

Dlatego przegląd przestrzeni nazw nigdy nie powinien kończyć się na stwierdzeniu „proces znajduje się w jakiejś przestrzeni nazw”. Istotne pytanie brzmi, czy przestrzeń nazw jest prywatna dla kontenera, współdzielona z kontenerami równorzędnymi, czy bezpośrednio dołączona do hosta. W Kubernetes ta sama idea pojawia się przy flagach takich jak `hostPID`, `hostNetwork` i `hostIPC`. Nazwy zmieniają się między platformami, ale wzorzec ryzyka pozostaje taki sam: współdzielona przestrzeń nazw hosta sprawia, że pozostałe uprawnienia kontenera oraz dostępny stan hosta mają znacznie większe znaczenie.

## Inspekcja

Najprostszy przegląd wygląda następująco:
```bash
ls -l /proc/self/ns
```
Każdy wpis jest dowiązaniem symbolicznym z identyfikatorem podobnym do inode. Jeśli dwa procesy wskazują ten sam identyfikator namespace, znajdują się w tej samej przestrzeni nazw danego typu. Dzięki temu `/proc` jest bardzo przydatnym miejscem do porównywania bieżącego procesu z innymi interesującymi procesami na maszynie.

Te krótkie polecenia często wystarczają, aby rozpocząć:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Stamtąd kolejnym krokiem jest porównanie procesu kontenera z procesami hosta lub sąsiednich kontenerów i ustalenie, czy namespace jest faktycznie prywatny.

### Zliczanie instancji namespace z poziomu hosta

Jeśli masz już dostęp do hosta i chcesz ustalić, ile odrębnych namespace danego typu istnieje, `/proc` zapewnia szybki przegląd:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name pid    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name net    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name ipc    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name uts    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name user   -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name time   -exec readlink {} \; 2>/dev/null | sort -u
```
Jeśli chcesz ustalić, które procesy należą do konkretnego identyfikatora namespace, zamień `readlink` na `ls -l` i użyj grep do wyszukania numeru docelowego namespace:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Te polecenia są przydatne, ponieważ pozwalają określić, czy host uruchamia jedno izolowane obciążenie, wiele izolowanych obciążeń czy połączenie współdzielonych i prywatnych instancji przestrzeni nazw.

### Wchodzenie do docelowej przestrzeni nazw

Gdy wywołujący ma wystarczające uprawnienia, `nsenter` jest standardowym sposobem dołączenia do przestrzeni nazw innego procesu:
```bash
nsenter -m TARGET_PID --pid /bin/bash   # mount
nsenter -t TARGET_PID --pid /bin/bash   # pid
nsenter -n TARGET_PID --pid /bin/bash   # network
nsenter -i TARGET_PID --pid /bin/bash   # ipc
nsenter -u TARGET_PID --pid /bin/bash   # uts
nsenter -U TARGET_PID --pid /bin/bash   # user
nsenter -C TARGET_PID --pid /bin/bash   # cgroup
nsenter -T TARGET_PID --pid /bin/bash   # time
```
Celem zestawienia tych form razem nie jest stwierdzenie, że każda ocena wymaga użycia wszystkich, lecz to, że post-exploitation zależne od namespace często staje się znacznie łatwiejsze, gdy operator zna dokładną składnię wejścia, zamiast pamiętać wyłącznie formę all-namespaces.

## Strony

Poniższe strony dokładniej wyjaśniają każdy namespace:

{{#ref}}
mount-namespace.md
{{#endref}}

{{#ref}}
pid-namespace.md
{{#endref}}

{{#ref}}
network-namespace.md
{{#endref}}

{{#ref}}
ipc-namespace.md
{{#endref}}

{{#ref}}
uts-namespace.md
{{#endref}}

{{#ref}}
user-namespace.md
{{#endref}}

{{#ref}}
cgroup-namespace.md
{{#endref}}

{{#ref}}
time-namespace.md
{{#endref}}

Podczas lektury pamiętaj o dwóch kwestiach. Po pierwsze, każdy namespace izoluje tylko jeden rodzaj widoku. Po drugie, prywatny namespace jest użyteczny tylko wtedy, gdy pozostała część modelu uprawnień nadal sprawia, że ta izolacja ma znaczenie.

## Domyślne ustawienia Runtime

| Runtime / platforma | Domyślna konfiguracja namespace | Częste ręczne osłabienie |
| --- | --- | --- |
| Docker Engine | Domyślnie nowe namespace mount, PID, network, IPC i UTS; user namespaces są dostępne, ale nie są domyślnie włączone w standardowych konfiguracjach rootful | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Domyślnie nowe namespaces; rootless Podman automatycznie używa user namespace; wartości domyślne cgroup namespace zależą od wersji cgroup | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pody **nie** współdzielą domyślnie host PID, network ani IPC; Pod networking jest prywatny dla Poda, a nie dla każdego pojedynczego kontenera; user namespaces są opcjonalne za pomocą `spec.hostUsers: false` w obsługiwanych klastrach | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / pominięcie opt-in dla user namespace, ustawienia uprzywilejowanego workloadu |
| containerd / CRI-O w Kubernetes | Zwykle stosują domyślne ustawienia Podów w Kubernetes | tak samo jak w wierszu Kubernetes; bezpośrednie specyfikacje CRI/OCI również mogą żądać dołączenia do host namespaces |

Główna zasada przenośności jest prosta: **koncepcja** współdzielenia host namespace jest wspólna dla różnych runtime, ale **składnia** jest zależna od runtime.

{{#include ../../../../../banners/hacktricks-training.md}}
