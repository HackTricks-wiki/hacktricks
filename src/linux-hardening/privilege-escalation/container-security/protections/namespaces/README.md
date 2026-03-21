# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces są funkcją jądra, która sprawia, że kontener wydaje się „własną maszyną”, choć w rzeczywistości jest tylko drzewem procesów hosta. Nie tworzą one nowego jądra i nie wirtualizują wszystkiego, ale pozwalają jądru prezentować różne widoki wybranych zasobów różnym grupom procesów. To jest sedno iluzji kontenera: obciążenie widzi system plików, tabelę procesów, stos sieciowy, nazwę hosta, zasoby IPC oraz model tożsamości użytkownika/grupy, które wydają się lokalne, mimo że system podstawowy jest współdzielony.

Dlatego namespaces są pierwszym pojęciem, na które większość osób natrafia ucząc się, jak działają kontenery. Jednocześnie są jednym z najczęściej źle rozumianych pojęć, ponieważ czytelnicy często zakładają, że „ma namespaces” oznacza „jest bezpiecznie izolowany”. W rzeczywistości namespace izoluje tylko konkretną klasę zasobów, do której został zaprojektowany. Proces może mieć prywatny PID namespace i nadal być niebezpieczny, ponieważ ma zapisywalny bind mount hosta. Może mieć prywatny network namespace i nadal być niebezpieczny, ponieważ zachowuje `CAP_SYS_ADMIN` i działa bez seccomp. Namespaces są fundamentem, ale są tylko jedną warstwą w ostatecznej granicy.

## Namespace Types

Kontenery Linuxa zwykle polegają równocześnie na kilku typach namespaces. The **mount namespace** daje procesowi oddzielną tabelę mount i w związku z tym kontrolowany widok systemu plików. The **PID namespace** zmienia widoczność i numerację procesów, więc obciążenie widzi własne drzewo procesów. The **network namespace** izoluje interfejsy, trasy, sockets i stan firewalla. The **IPC namespace** izoluje SysV IPC i kolejki komunikatów POSIX. The **UTS namespace** izoluje nazwę hosta i domenę NIS. The **user namespace** remapuje identyfikatory użytkownika i grupy tak, że root w kontenerze niekoniecznie oznacza root na hoście. The **cgroup namespace** wirtualizuje widoczną hierarchię cgroup, a The **time namespace** wirtualizuje wybrane zegary w nowszych jądrach.

Każdy z tych namespaces rozwiązuje inny problem. Dlatego praktyczna analiza bezpieczeństwa kontenerów często sprowadza się do sprawdzenia, **które namespaces są izolowane** i **które zostały celowo udostępnione z hostem**.

## Host Namespace Sharing

Wiele ucieczek z kontenera nie zaczyna się od luki w jądrze. Zaczynają się od operatora celowo osłabiającego model izolacji. Przykłady `--pid=host`, `--network=host` i `--userns=host` to **Docker/Podman-style CLI flags** użyte tutaj jako konkretne przykłady udostępniania namespace hosta. Inne runtimy wyrażają tę samą ideę inaczej. W Kubernetes równoważne ustawienia zwykle pojawiają się jako opcje Poda, takie jak `hostPID: true`, `hostNetwork: true` lub `hostIPC: true`. W niższego poziomu stosach runtime, takich jak containerd lub CRI-O, to samo zachowanie często osiąga się przez wygenerowaną konfigurację runtime OCI zamiast przez flagę widoczną dla użytkownika o tej samej nazwie. We wszystkich tych przypadkach efekt jest podobny: obciążenie nie otrzymuje już domyślnego izolowanego widoku namespace.

Dlatego przeglądy namespaces nigdy nie powinny kończyć się na „proces znajduje się w jakimś namespace”. Ważnym pytaniem jest, czy namespace jest prywatny dla kontenera, współdzielony z kontenerami-sąsiadami, czy dołączony bezpośrednio do hosta. W Kubernetes ta sama idea pojawia się z flagami takimi jak `hostPID`, `hostNetwork` i `hostIPC`. Nazwy zmieniają się między platformami, ale wzorzec ryzyka jest ten sam: współdzielony namespace hosta sprawia, że pozostałe uprawnienia kontenera i osiągalny stan hosta mają znacznie większe znaczenie.

## Inspection

Najprostszy przegląd to:
```bash
ls -l /proc/self/ns
```
Każdy wpis jest dowiązaniem symbolicznym z identyfikatorem podobnym do inode. Jeśli dwa procesy wskazują ten sam identyfikator namespace, znajdują się w tym samym namespace tego typu. To sprawia, że `/proc` jest bardzo przydatnym miejscem do porównania bieżącego procesu z innymi interesującymi procesami na maszynie.

Te szybkie polecenia często wystarczają, aby zacząć:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Stamtąd kolejnym krokiem jest porównanie procesu container z procesami na hoście lub z procesami sąsiednimi i ustalenie, czy namespace jest faktycznie prywatny, czy nie.

### Enumerowanie instancji namespace z hosta

Kiedy masz już dostęp do hosta i chcesz zrozumieć, ile różnych instancji namespace danego typu istnieje, `/proc` daje szybki przegląd:
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
Jeśli chcesz znaleźć procesy należące do konkretnego identyfikatora namespace, zamiast `readlink` użyj `ls -l` i grep, aby wyszukać docelowy numer namespace:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Te polecenia są przydatne, ponieważ pozwalają stwierdzić, czy host uruchamia jedno izolowane workload, wiele izolowanych workloads, czy mieszankę współdzielonych i prywatnych namespace instances.

### Wchodzenie do docelowego namespace

Gdy wywołujący ma wystarczające uprawnienia, `nsenter` jest standardowym sposobem dołączenia do namespace innego procesu:
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
Cel zestawienia tych form razem nie polega na tym, że każda ocena wymaga wszystkich z nich, lecz na tym, że namespace-specific post-exploitation często staje się znacznie łatwiejsze, gdy operator zna dokładną składnię wejścia zamiast pamiętać tylko formę all-namespaces.

## Pages

Poniższe strony wyjaśniają każdy namespace bardziej szczegółowo:

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

Czytając je, miej na uwadze dwie myśli. Po pierwsze, każdy namespace izoluje tylko jeden rodzaj widoku. Po drugie, prywatny namespace jest przydatny tylko wtedy, gdy reszta modelu uprawnień nadal sprawia, że ta izolacja ma sens.

## Runtime Defaults

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | Domyślnie tworzy nowe mount, PID, network, IPC i UTS namespaces; user namespaces są dostępne, ale nie są domyślnie włączone w standardowych rootful konfiguracjach | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Nowe namespaces domyślnie; rootless Podman automatycznie używa user namespace; domyślny stan cgroup namespace zależy od wersji cgroup | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pody **do not** share host PID, network, or IPC by default; Pod networking is private to the Pod, not to each individual container; user namespaces są opcjonalne poprzez `spec.hostUsers: false` w obsługiwanych klastrach | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / pominięcie opt-in dla user namespace, ustawienia uprzywilejowanych workloadów |
| containerd / CRI-O under Kubernetes | Zazwyczaj stosują się do domyślnych ustawień Pod Kubernetes | tak jak w wierszu Kubernetes; bezpośrednie specyfikacje CRI/OCI mogą też żądać dołączeń do host namespace'ów |

Główna zasada przenośności jest prosta: **koncepcja** udostępniania host namespace'ów jest wspólna dla runtime'ów, ale **składnia** jest specyficzna dla danego runtime'u.
