# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` to mechanizm wzmacniania jądra, który zapobiega uzyskaniu przez proces dodatkowych uprawnień podczas `execve()`. W praktyce, po ustawieniu flagi, uruchomienie binarki setuid, binarki setgid lub pliku z Linux file capabilities nie nadaje dodatkowych uprawnień poza tymi, które proces już posiadał. W środowiskach skonteneryzowanych ma to znaczenie, ponieważ wiele łańcuchów eskalacji uprawnień polega na znalezieniu wykonywalnego pliku wewnątrz obrazu, który po uruchomieniu zmienia przywileje.

Z perspektywy obronnej `no_new_privs` nie zastępuje namespaces, seccomp ani capability dropping. Jest warstwą wzmocnienia. Blokuje konkretną klasę późniejszych eskalacji po tym, jak kod został już wykonany. Dzięki temu jest szczególnie wartościowy w środowiskach, gdzie obrazy zawierają pomocnicze binarki, artefakty package-managera lub narzędzia legacy, które w połączeniu z częściowym kompromisem mogłyby być niebezpieczne.

## Operation

Flaga jądra odpowiedzialna za to zachowanie to `PR_SET_NO_NEW_PRIVS`. Po ustawieniu dla procesu późniejsze wywołania `execve()` nie mogą zwiększyć uprawnień. Ważne jest, że proces nadal może uruchamiać binarki; po prostu nie może wykorzystać tych binarek do przekroczenia granicy uprawnień, którą jądro w przeciwnym razie by uznało.

W środowiskach zorientowanych na Kubernetes, `allowPrivilegeEscalation: false` odpowiada temu zachowaniu dla procesu w kontenerze. W runtime'ach w stylu Docker i Podman odpowiednik jest zwykle włączany jawnie przez opcję bezpieczeństwa.

## Laboratorium

Sprawdź bieżący stan procesu:
```bash
grep NoNewPrivs /proc/self/status
```
Porównaj to z kontenerem, w którym runtime włącza flagę:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
W środowisku o podwyższonym poziomie zabezpieczeń wynik powinien pokazywać `NoNewPrivs: 1`.

## Wpływ na bezpieczeństwo

Jeśli `no_new_privs` jest nieobecny, zdobyta pozycja wewnątrz kontenera może zostać podwyższona przez setuid helperów lub binariów posiadających file capabilities. Jeśli jest obecny, te post-exec zmiany przywilejów są odcięte. Efekt jest szczególnie istotny w rozbudowanych obrazach bazowych, które zawierają wiele narzędzi, których aplikacja nigdy nie potrzebowała.

## Błędne konfiguracje

Najczęstszym problemem jest po prostu niewłączenie tej kontroli w środowiskach, w których byłaby kompatybilna. W Kubernetes pozostawienie `allowPrivilegeEscalation` włączone jest często domyślnym błędem operacyjnym. W Dockerze i Podmanie pominięcie odpowiedniej opcji bezpieczeństwa daje ten sam efekt. Innym powtarzającym się trybem awarii jest założenie, że ponieważ kontener jest "not privileged", exec-time privilege transitions są automatycznie nieistotne.

## Nadużycie

Jeśli `no_new_privs` nie jest ustawiony, pierwsze pytanie brzmi, czy obraz zawiera binaria, które nadal mogą podnieść poziom przywilejów:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Interesujące wyniki obejmują:

- `NoNewPrivs: 0`
- narzędzia setuid takie jak `su`, `mount`, `passwd`, lub narzędzia administracyjne specyficzne dla dystrybucji
- binaria z file capabilities, które przyznają uprawnienia sieciowe lub do systemu plików

W prawdziwej ocenie te ustalenia same w sobie nie dowodzą działającej eskalacji, ale wskazują dokładnie, które binaria warto przetestować jako następne.

### Pełny przykład: eskalacja uprawnień w kontenerze przez setuid

Ten mechanizm zwykle zapobiega **eskalacji uprawnień w kontenerze** raczej niż bezpośrednio ucieczce na hosta. Jeśli `NoNewPrivs` jest `0` i istnieje narzędzie setuid, przetestuj je jawnie:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Jeśli znany setuid binary jest obecny i działa, spróbuj uruchomić go w sposób zachowujący przejście uprawnień:
```bash
/bin/su -c id 2>/dev/null
```
To samo w sobie nie umożliwia ucieczki z kontenera, ale może przekształcić niskoprzywilejowy foothold wewnątrz kontenera w container-root, co często staje się warunkiem wstępnym późniejszej ucieczki na hosta przez mounts, runtime sockets lub kernel-facing interfaces.

## Sprawdzenia

Celem tych sprawdzeń jest ustalenie, czy exec-time privilege gain jest zablokowany oraz czy image nadal zawiera helpery, które miałyby znaczenie, jeśli nie jest zablokowany.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
Co jest tutaj interesujące:

- `NoNewPrivs: 1` jest zwykle bezpieczniejszym wynikiem.
- `NoNewPrivs: 0` oznacza, że ścieżki eskalacji oparte na setuid i file-cap pozostają istotne.
- Minimalny image z niewielką liczbą lub bez binarek setuid/file-cap daje atakującemu mniej opcji post-exploitation nawet gdy brakuje `no_new_privs`.

## Domyślne ustawienia środowiska wykonawczego

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Not enabled by default | Enabled explicitly with `--security-opt no-new-privileges=true` | omitting the flag, `--privileged` |
| Podman | Not enabled by default | Enabled explicitly with `--security-opt no-new-privileges` or equivalent security configuration | omitting the option, `--privileged` |
| Kubernetes | Controlled by workload policy | `allowPrivilegeEscalation: false` enables the effect; many workloads still leave it enabled | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Follows Kubernetes workload settings | Usually inherited from the Pod security context | same as Kubernetes row |

Ta ochrona często jest nieobecna po prostu dlatego, że nikt jej nie włączył, a nie dlatego, że runtime nie obsługuje tej funkcji.
