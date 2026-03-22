# Przestrzenie nazw

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces są funkcją jądra, która sprawia, że container wydaje się „własną maszyną”, mimo że w rzeczywistości jest to po prostu drzewo procesów hosta. Nie tworzą nowego jądra i nie wirtualizują wszystkiego, ale pozwalają jądru prezentować różne widoki wybranych zasobów różnym grupom procesów. To jest sedno iluzji kontenera: workload widzi system plików, tablicę procesów, stos sieciowy, hostname, zasoby IPC oraz model tożsamości użytkowników/grup, które wydają się lokalne, mimo że podsystemy są współdzielone.

Dlatego namespaces są pierwszym pojęciem, z którym większość osób styka się ucząc, jak działają kontenery. Jednocześnie są jednym z najczęściej źle rozumianych konceptów, ponieważ czytelnicy często zakładają, że „ma namespaces” oznacza „jest bezpiecznie izolowany”. W rzeczywistości namespace izoluje tylko konkretną klasę zasobów, do której został zaprojektowany. Proces może mieć prywatny PID namespace i nadal być niebezpieczny, bo ma zapisywalny host bind mount. Może mieć prywatny network namespace i nadal być niebezpieczny, ponieważ zachowuje `CAP_SYS_ADMIN` i działa bez seccomp. Namespaces są fundamentem, ale stanowią tylko jedną warstwę w ostatecznej granicy.

## Typy przestrzeni nazw

Linuxowe kontenery zwykle polegają równocześnie na kilku typach namespaces. The **mount namespace** daje procesowi oddzielną tabelę montowań i w konsekwencji kontrolowany widok systemu plików. The **PID namespace** zmienia widoczność i numerację procesów, tak że workload widzi własne drzewo procesów. The **network namespace** izoluje interfejsy, trasy, gniazda i stan firewall. The **IPC namespace** izoluje SysV IPC i POSIX message queues. The **UTS namespace** izoluje hostname i NIS domain name. The **user namespace** remapuje UID i GID tak, że root wewnątrz kontenera niekoniecznie oznacza root na hoście. The **cgroup namespace** wirtualizuje widoczną hierarchię cgroup, a The **time namespace** w nowszych jądrach wirtualizuje wybrane zegary.

Każdy z tych namespaces rozwiązuje inny problem. Dlatego praktyczna analiza bezpieczeństwa kontenerów często sprowadza się do sprawdzenia, **które namespaces są izolowane**, a **które zostały celowo udostępnione z hostem**.

## Udostępnianie przestrzeni nazw hosta

Wiele breakoutów kontenerów nie zaczyna się od luki w jądrze. Zaczyna się, gdy operator celowo osłabia model izolacji. Przykłady `--pid=host`, `--network=host`, i `--userns=host` to **Docker/Podman-style CLI flags** użyte tutaj jako konkretne przykłady udostępniania namespaces hosta. Inne runtime'y wyrażają tę samą ideę inaczej. W Kubernetes odpowiedniki zazwyczaj pojawiają się jako ustawienia Poda, takie jak `hostPID: true`, `hostNetwork: true`, lub `hostIPC: true`. W niższych warstwach runtime, takich jak containerd czy CRI-O, ten sam efekt często osiąga się przez wygenerowaną OCI runtime configuration, a nie przez flagę widoczną dla użytkownika o takiej samej nazwie. We wszystkich tych przypadkach wynik jest podobny: workload nie otrzymuje już domyślnego, izolowanego widoku namespace.

Dlatego przeglądy namespaces nigdy nie powinny zatrzymywać się na „proces jest w jakimś namespace”. Ważne pytanie brzmi, czy namespace jest prywatny dla kontenera, współdzielony z kontenerami współdzielonymi (sibling containers), czy połączony bezpośrednio z hostem. W Kubernetes ta sama idea pojawia się z flagami takimi jak `hostPID`, `hostNetwork` i `hostIPC`. Nazwy zmieniają się między platformami, ale wzorzec ryzyka jest ten sam: współdzielona przestrzeń nazw hosta sprawia, że pozostające uprawnienia kontenera i osiągalny stan hosta stają się znacznie bardziej istotne.

## Inspekcja

Najprostszy przegląd to:
```bash
ls -l /proc/self/ns
```
Każdy wpis jest dowiązaniem symbolicznym z identyfikatorem podobnym do inode. Jeśli dwa procesy wskazują na ten sam identyfikator przestrzeni nazw, znajdują się w tej samej przestrzeni nazw tego typu. To sprawia, że `/proc` jest bardzo przydatnym miejscem do porównywania bieżącego procesu z innymi interesującymi procesami na maszynie.

Te szybkie polecenia często wystarczą, by zacząć:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Stamtąd następnym krokiem jest porównanie procesu kontenera z procesami hosta lub procesami sąsiednimi i ustalenie, czy namespace jest faktycznie prywatny.

### Wyliczanie instancji namespace z hosta

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
Jeśli chcesz znaleźć, które procesy należą do jednego konkretnego namespace identifier, zamiast `readlink` użyj `ls -l` i `grep`, aby znaleźć docelowy numer namespace:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Te polecenia są przydatne, ponieważ pozwalają stwierdzić, czy host uruchamia jeden izolowany workload, wiele izolowanych workloads, czy mieszankę współdzielonych i prywatnych namespace instances.

### Wejście do docelowego namespace

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
Celem zestawienia tych form razem nie jest to, że każda ocena wymaga wszystkich z nich, lecz że namespace-specific post-exploitation często staje się znacznie łatwiejsze, gdy operator zna dokładną składnię wejścia zamiast pamiętać tylko all-namespaces form.

## Pages

The following pages explain each namespace in more detail:

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

As you read them, keep two ideas in mind. First, each namespace isolates only one kind of view. Second, a private namespace is useful only if the rest of the privilege model still makes that isolation meaningful.

## Runtime Defaults

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | Domyślnie tworzone nowe mount, PID, network, IPC i UTS namespaces; user namespaces są dostępne, ale w standardowych rootful konfiguracjach nie są domyślnie włączone | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Domyślnie nowe namespaces; rootless Podman automatycznie używa user namespace; domyślne zachowanie cgroup namespace zależy od wersji cgroup | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods do **not** share host PID, network, or IPC by default; Pod networking is private to the Pod, not to each individual container; user namespaces are opt-in via `spec.hostUsers: false` on supported clusters | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | Zazwyczaj stosują domyślne ustawienia Podów Kubernetes | same as Kubernetes row; direct CRI/OCI specs can also request host namespace joins |

Główna zasada przenośności jest prosta: the **concept** of host namespace sharing is common across runtimes, but the **syntax** is runtime-specific.
{{#include ../../../../../banners/hacktricks-training.md}}
