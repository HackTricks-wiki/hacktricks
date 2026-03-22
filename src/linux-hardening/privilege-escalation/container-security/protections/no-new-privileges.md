# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` to funkcja wzmacniająca jądro, która zapobiega przyznawaniu procesowi dodatkowych uprawnień podczas wywołań `execve()`. W praktyce, po ustawieniu flagi, uruchomienie programu setuid, programu setgid lub pliku z Linux file capabilities nie nadaje dodatkowych uprawnień ponad te, które proces już posiadał. W środowiskach konteneryzowanych ma to znaczenie, ponieważ wiele łańcuchów eskalacji uprawnień polega na znalezieniu w obrazie pliku wykonywalnego, który zmienia uprawnienia po uruchomieniu.

Z defensywnego punktu widzenia, `no_new_privs` nie zastępuje namespaces, seccomp ani capability dropping. Jest warstwą wzmacniającą. Blokuje określoną klasę dalszej eskalacji po tym, jak wykonanie kodu zostało już uzyskane. Dzięki temu jest szczególnie cenne w środowiskach, w których obrazy zawierają binarki pomocnicze, artefakty menedżera pakietów lub przestarzałe narzędzia, które w przeciwnym razie byłyby niebezpieczne w połączeniu z częściowym kompromisem.

## Działanie

Flaga jądra odpowiadająca za to zachowanie to `PR_SET_NO_NEW_PRIVS`. Po jej ustawieniu dla procesu, kolejne wywołania `execve()` nie mogą zwiększyć uprawnień. Ważnym szczegółem jest to, że proces nadal może uruchamiać binarki; po prostu nie może ich użyć do przekroczenia granicy uprawnień, którą jądro w innym przypadku by uwzględniło.

W środowiskach zorientowanych na Kubernetes, `allowPrivilegeEscalation: false` odwzorowuje to zachowanie dla procesu w kontenerze. W runtime'ach w stylu Docker i Podman ekwiwalent zwykle jest włączany jawnie poprzez opcję bezpieczeństwa.

## Lab

Sprawdź stan bieżącego procesu:
```bash
grep NoNewPrivs /proc/self/status
```
Porównaj to z kontenerem, w którym runtime włącza flagę:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
W zabezpieczonym środowisku roboczym wynik powinien pokazywać `NoNewPrivs: 1`.

## Wpływ na bezpieczeństwo

Jeśli `no_new_privs` jest nieobecny, zdobyta pozycja wewnątrz kontenera może nadal zostać podwyższona za pomocą setuid helpers lub binaries with file capabilities. Jeśli jest ustawiony, takie zmiany uprawnień po wykonaniu zostają zablokowane. Efekt jest szczególnie istotny w szerokich obrazach bazowych, które zawierają wiele narzędzi, których aplikacja w ogóle nie potrzebowała.

## Nieprawidłowe konfiguracje

Najczęstszym problemem jest po prostu nie włączenie tego mechanizmu w środowiskach, gdzie byłby kompatybilny. W Kubernetes pozostawienie `allowPrivilegeEscalation` włączonego jest często domyślnym błędem operacyjnym. W Docker i Podman pominięcie odpowiedniej opcji bezpieczeństwa daje ten sam efekt. Innym powtarzającym się trybem awarii jest założenie, że ponieważ kontener jest "not privileged", przejścia uprawnień w czasie wykonywania są automatycznie nieistotne.

## Nadużycia

Jeśli `no_new_privs` nie jest ustawiony, pierwsze pytanie brzmi, czy obraz zawiera binaries, które nadal mogą podnosić uprawnienia:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Interesujące wyniki obejmują:

- `NoNewPrivs: 0`
- setuid helpers takie jak `su`, `mount`, `passwd` lub narzędzia administracyjne specyficzne dla dystrybucji
- binaria z file capabilities, które przyznają uprawnienia sieciowe lub do systemu plików

W rzeczywistej ocenie te ustalenia same w sobie nie dowodzą działającej eskalacji, ale wskazują dokładnie, które binaria warto przetestować jako następne.

### Pełny przykład: In-Container Privilege Escalation Through setuid

Ten mechanizm zwykle zapobiega **in-container privilege escalation**, a nie bezpośrednio host escape. Jeśli `NoNewPrivs` ma wartość `0` i istnieje setuid helper, przetestuj go jawnie:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Jeśli znany plik binarny setuid jest obecny i działa, spróbuj uruchomić go w sposób zachowujący przejście uprawnień:
```bash
/bin/su -c id 2>/dev/null
```
To samo w sobie nie umożliwia ucieczki z kontenera, ale może przekształcić niskoprzywilejowane przyczółek wewnątrz kontenera w container-root, co często staje się warunkiem wstępnym późniejszej ucieczki na hosta przez mounts, runtime sockets lub kernel-facing interfaces.

## Sprawdzenia

Celem tych sprawdzeń jest ustalenie, czy exec-time privilege gain jest zablokowany oraz czy image nadal zawiera helpers, które miałyby znaczenie, jeśli blokada nie występuje.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
Co jest tu interesujące:

- `NoNewPrivs: 1` jest zwykle bezpieczniejszym wynikiem.
- `NoNewPrivs: 0` oznacza, że ścieżki eskalacji oparte na setuid i file-cap pozostają istotne.
- Minimalny obraz z niewielką liczbą lub bez binariów setuid/file-cap daje atakującemu mniej opcji post-exploitation nawet gdy `no_new_privs` jest nieobecny.

## Domyślne ustawienia środowiska uruchomieniowego

| Runtime / platforma | Stan domyślny | Domyślne zachowanie | Typowe ręczne osłabienia |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie nieaktywny | Włączany jawnie za pomocą `--security-opt no-new-privileges=true` | pominięcie flagi, `--privileged` |
| Podman | Domyślnie nieaktywny | Włączany jawnie za pomocą `--security-opt no-new-privileges` lub równoważnej konfiguracji zabezpieczeń | pominięcie opcji, `--privileged` |
| Kubernetes | Kontrolowane przez politykę workloadu | `allowPrivilegeEscalation: false` włącza efekt; wiele workloadów nadal pozostawia go włączonym | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O w Kubernetes | Stosuje ustawienia workloadów Kubernetes | Zwykle dziedziczone z kontekstu bezpieczeństwa Pod | tak samo jak w wierszu Kubernetes |

Ta ochrona często jest nieobecna po prostu dlatego, że nikt jej nie włączył, a nie dlatego, że środowisko uruchomieniowe nie obsługuje jej.
{{#include ../../../../banners/hacktricks-training.md}}
