# Przestrzenie nazw

{{#include ../../../../../banners/hacktricks-training.md}}

Przestrzenie nazw to funkcja kernela, dzięki której kontener sprawia wrażenie „własnej maszyny”, mimo że w rzeczywistości jest tylko drzewem procesów hosta. Nie tworzą one nowego kernela i nie wirtualizują wszystkiego, ale pozwalają kernelowi prezentować różne widoki wybranych zasobów różnym grupom procesów. To podstawa iluzji kontenera: workload widzi system plików, tabelę procesów, stos sieciowy, hostname, zasoby IPC oraz model tożsamości użytkowników i grup, które wyglądają na lokalne, mimo że bazowy system jest współdzielony.

Dlatego przestrzenie nazw są pierwszą koncepcją, z którą większość osób spotyka się podczas nauki działania kontenerów. Jednocześnie są jedną z najczęściej błędnie rozumianych koncepcji, ponieważ czytelnicy często zakładają, że „ma przestrzenie nazw” oznacza „jest bezpiecznie odizolowany”. W rzeczywistości przestrzeń nazw izoluje tylko konkretną klasę zasobów, dla której została zaprojektowana. Proces może mieć prywatną przestrzeń nazw PID i nadal być niebezpieczny, ponieważ ma zapisywalny bind mount hosta. Może mieć prywatną przestrzeń nazw sieci i nadal być niebezpieczny, ponieważ zachowuje `CAP_SYS_ADMIN` i działa bez seccomp. Przestrzenie nazw są fundamentem, ale stanowią tylko jedną warstwę końcowej granicy izolacji.

## Typy przestrzeni nazw

Kontenery Linux często korzystają jednocześnie z kilku typów przestrzeni nazw. **Przestrzeń nazw mount** daje procesowi oddzielną tabelę mountów, a tym samym kontrolowany widok systemu plików. **Przestrzeń nazw PID** zmienia widoczność i numerację procesów, dzięki czemu workload widzi własne drzewo procesów. **Przestrzeń nazw sieci** izoluje interfejsy, trasy, sockety i stan firewalla. **Przestrzeń nazw IPC** izoluje SysV IPC oraz kolejki komunikatów POSIX. **Przestrzeń nazw UTS** izoluje hostname i nazwę domeny NIS. **Przestrzeń nazw użytkownika** mapuje identyfikatory użytkowników i grup, dzięki czemu root wewnątrz kontenera nie musi oznaczać roota na hoście. **Przestrzeń nazw cgroup** wirtualizuje widoczną hierarchię cgroup, a **przestrzeń nazw czasu** wirtualizuje wybrane zegary w nowszych kernelach.

Każda z tych przestrzeni nazw rozwiązuje inny problem. Dlatego praktyczna analiza bezpieczeństwa kontenerów często sprowadza się do sprawdzenia, **które przestrzenie nazw są izolowane**, a **które zostały celowo współdzielone z hostem**.

## Współdzielenie przestrzeni nazw hosta

Wiele container breakout nie zaczyna się od luki w kernelu. Zaczynają się od celowego osłabienia modelu izolacji przez operatora. Przykłady `--pid=host`, `--network=host` i `--userns=host` to **flagi CLI w stylu Docker/Podman**, użyte tutaj jako konkretne przykłady współdzielenia przestrzeni nazw hosta. Inne runtime wyrażają tę samą ideę w inny sposób. W Kubernetes odpowiedniki zwykle występują jako ustawienia Pod, takie jak `hostPID: true`, `hostNetwork: true` lub `hostIPC: true`. W niższopoziomowych stackach runtime, takich jak containerd lub CRI-O, do tego samego zachowania często dochodzi się za pośrednictwem wygenerowanej konfiguracji runtime OCI, a nie flagi widocznej dla użytkownika i mającej taką samą nazwę. We wszystkich tych przypadkach rezultat jest podobny: workload nie otrzymuje już domyślnego, izolowanego widoku przestrzeni nazw.

Dlatego przegląd przestrzeni nazw nigdy nie powinien kończyć się na stwierdzeniu „proces znajduje się w jakiejś przestrzeni nazw”. Istotne pytanie brzmi, czy przestrzeń nazw jest prywatna dla kontenera, współdzielona z sąsiednimi kontenerami, czy bezpośrednio dołączona do hosta. W Kubernetes ta sama idea występuje przy flagach takich jak `hostPID`, `hostNetwork` i `hostIPC`. Nazwy różnią się między platformami, ale wzorzec ryzyka pozostaje taki sam: współdzielona przestrzeń nazw hosta sprawia, że pozostałe uprawnienia kontenera oraz dostępny stan hosta stają się znacznie bardziej istotne.

## Inspekcja

Najprostszy przegląd wygląda tak:
```bash
ls -l /proc/self/ns
```
Każdy wpis jest dowiązaniem symbolicznym z identyfikatorem przypominającym inode. Jeśli dwa procesy wskazują ten sam identyfikator namespace, znajdują się w tym samym namespace tego typu. Dzięki temu `/proc` jest bardzo przydatnym miejscem do porównywania bieżącego procesu z innymi interesującymi procesami na maszynie.

Te krótkie polecenia często wystarczają, aby rozpocząć:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Stamtąd następnym krokiem jest porównanie procesu kontenera z procesami hosta lub sąsiednich kontenerów oraz ustalenie, czy namespace jest rzeczywiście prywatny.

### Enumerowanie instancji namespace z hosta

Jeśli masz już dostęp do hosta i chcesz sprawdzić, ile odrębnych namespace danego typu istnieje, `/proc` zapewnia szybki przegląd:
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
Jeśli chcesz sprawdzić, które procesy należą do konkretnego identyfikatora namespace, użyj `ls -l` zamiast `readlink` i wyszukaj docelowy numer namespace:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Te polecenia są przydatne, ponieważ pozwalają określić, czy host uruchamia jeden isolated workload, wiele isolated workloads, czy połączenie współdzielonych i prywatnych instancji namespace.

### Wchodzenie do target namespace

Gdy caller ma wystarczające uprawnienia, `nsenter` jest standardowym sposobem dołączenia do namespace innego procesu:
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
Powodem zestawienia tych form nie jest to, że każda ocena wymaga ich wszystkich, lecz to, że namespace-specific post-exploitation często staje się znacznie łatwiejsze, gdy operator zna dokładną składnię wejścia, zamiast pamiętać wyłącznie formę all-namespaces.

## Strony

Poniższe strony bardziej szczegółowo wyjaśniają każdy namespace:

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

Podczas lektury pamiętaj o dwóch kwestiach. Po pierwsze, każdy namespace izoluje tylko jeden rodzaj widoku. Po drugie, prywatny namespace jest użyteczny tylko wtedy, gdy pozostały model uprawnień nadal sprawia, że ta izolacja ma znaczenie.

## Domyślne ustawienia Runtime

| Runtime / platforma | Domyślna konfiguracja namespace | Typowe ręczne osłabienie |
| --- | --- | --- |
| Docker Engine | Domyślnie nowe namespace mount, PID, network, IPC i UTS; user namespaces są dostępne, ale nie są domyślnie włączone w standardowych konfiguracjach rootful | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Domyślnie nowe namespaces; rootless Podman automatycznie używa user namespace; ustawienia cgroup namespace zależą od wersji cgroup | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pody domyślnie **nie** współdzielą z hostem PID, network ani IPC; Pod networking jest prywatny dla Poda, a nie dla każdego pojedynczego kontenera; user namespaces są opcjonalne za pomocą `spec.hostUsers: false` w obsługiwanych klastrach | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / pominięcie opt-in dla user namespace, ustawienia privileged workload |
| containerd / CRI-O under Kubernetes | Zwykle stosują domyślne ustawienia Podów Kubernetes | tak samo jak w wierszu Kubernetes; bezpośrednie specyfikacje CRI/OCI mogą również żądać dołączenia do host namespace |

Główna zasada przenośności jest prosta: **koncepcja** współdzielenia host namespace jest wspólna dla runtime’ów, ale **składnia** jest zależna od konkretnego runtime.
{{#include ../../../../../banners/hacktricks-training.md}}
