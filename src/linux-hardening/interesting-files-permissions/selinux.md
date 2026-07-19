# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux to **oparty na etykietach Mandatory Access Control (MAC)**. W praktyce oznacza to, że nawet jeśli uprawnienia DAC, grupy lub capabilities systemu Linux wydają się wystarczające do wykonania danej akcji, kernel nadal może jej odmówić, ponieważ **kontekst źródłowy** nie ma uprawnień do dostępu do **kontekstu docelowego** z użyciem żądanej klasy/uprawnienia.

Kontekst zazwyczaj wygląda następująco:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Z perspektywy privesc pole `type` (domena dla procesów, typ dla obiektów) jest zwykle najważniejszym polem:

- Proces działa w **domenie**, takiej jak `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Pliki i sockety mają **typ**, taki jak `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Policy decyduje, czy jedna domena może odczytywać, zapisywać, wykonywać lub przechodzić do drugiej

## Szybka enumeracja

Jeśli SELinux jest włączony, przeprowadź jego enumerację na wczesnym etapie, ponieważ może wyjaśnić, dlaczego typowe ścieżki linuxowego privesc zawodzą lub dlaczego uprzywilejowany wrapper wokół „nieszkodliwego” narzędzia SELinux ma w rzeczywistości krytyczne znaczenie:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Przydatne dodatkowe kontrole:
```bash
# Installed policy modules and local customizations
semodule -lfull 2>/dev/null
semanage fcontext -C -l 2>/dev/null
semanage permissive -l 2>/dev/null
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null

# Labels that frequently reveal mistakes or unusual paths
find / -context '*:default_t:*' -o -context '*:file_t:*' 2>/dev/null

# Compare current label vs policy default for a path
matchpathcon -V /path/of/interest 2>/dev/null
restorecon -n -v /path/of/interest 2>/dev/null
```
Interesujące ustalenia:

- Tryb `Disabled` lub `Permissive` usuwa większość wartości SELinux jako granicy bezpieczeństwa.
- `unconfined_t` zazwyczaj oznacza, że SELinux jest obecny, ale nie ogranicza znacząco tego procesu.
- `default_t`, `file_t` lub ewidentnie nieprawidłowe etykiety na niestandardowych ścieżkach często wskazują na błędne etykietowanie lub niekompletne wdrożenie.
- Lokalne nadpisania w `file_contexts.local` mają pierwszeństwo przed domyślnymi ustawieniami policy, dlatego należy je dokładnie przejrzeć.

## Analiza policy

SELinux jest znacznie łatwiejszy do zaatakowania lub obejścia, gdy potrafisz odpowiedzieć na dwa pytania:

1. **Do czego może uzyskać dostęp moja bieżąca domena?**
2. **Do jakich domen mogę przejść?**

Najbardziej przydatne narzędzia do tego celu to `sepolicy` oraz **SETools** (`seinfo`, `sesearch`, `sedta`):
```bash
# Transition graph from the current domain
sepolicy transition -s "$(id -Z | awk -F: '{print $3}')" 2>/dev/null

# Search allow and type_transition rules
sesearch -A -s staff_t 2>/dev/null | head
sesearch --type_transition -s staff_t 2>/dev/null | head

# Inspect policy components
seinfo -t 2>/dev/null | head
seinfo -r 2>/dev/null | head
```
Jest to szczególnie przydatne, gdy host używa **użytkowników podlegających ograniczeniom** zamiast mapować wszystkich do `unconfined_u`. W takim przypadku sprawdź:

- mapowania użytkowników za pomocą `semanage login -l`
- dozwolone role za pomocą `semanage user -l`
- dostępne domeny administracyjne, takie jak `sysadm_t`, `secadm_t`, `webadm_t`
- wpisy `sudoers` używające `ROLE=` lub `TYPE=`

Jeśli `sudo -l` zawiera wpisy takie jak ten, SELinux stanowi część granicy uprawnień:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Sprawdź również, czy `newrole` jest dostępne:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` i `newrole` nie są automatycznie podatne na exploitację, ale jeśli uprzywilejowany wrapper lub reguła `sudoers` pozwala wybrać lepszą rolę/typ, stają się wartościowymi prymitywami eskalacji uprawnień.

## Pliki, zmiana etykiet i wysokowartościowe błędne konfiguracje

Najważniejsza praktyczna różnica między powszechnie używanymi narzędziami SELinux to:

- `chcon`: tymczasowa zmiana etykiety określonej ścieżki
- `semanage fcontext`: trwała reguła mapowania ścieżki na etykietę
- `restorecon` / `setfiles`: ponowne zastosowanie etykiety wynikającej z polityki/domyslnej

Ma to duże znaczenie podczas privesc, ponieważ **zmiana etykiety nie jest wyłącznie kwestią kosmetyczną**. Może zmienić plik z „zablokowanego przez politykę” w „czytelny/wykonywalny dla uprzywilejowanej usługi działającej w ograniczonym kontekście”.

Sprawdź lokalne reguły zmiany etykiet oraz rozbieżności etykiet:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Jeden subtelny, ale użyteczny szczegół: zwykłe `restorecon` **nie zawsze w pełni przywraca podejrzaną etykietę**. Jeśli typ docelowy znajduje się w `customizable_types`, może być konieczne użycie `-F`, aby wymusić pełne zresetowanie. Z perspektywy atakującego wyjaśnia to, dlaczego nietypowe `chcon` może czasami przetrwać pobieżne czyszczenie wykonane za pomocą „przecież już uruchomiliśmy restorecon”.
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Polecenia o wysokiej wartości do wyszukania w `sudo -l`, wrapperach root, skryptach automatyzacji lub capabilities plików:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Jeśli pojawi się którakolwiek z funkcji MAC, sprawdź również [stronę dotyczącą Linux capabilities](linux-capabilities.md); `cap_mac_admin` i `cap_mac_override` są nietypowe, ale bezpośrednio istotne, gdy SELinux stanowi część granicy bezpieczeństwa.

Szczególnie interesujące:

- `semanage fcontext`: trwale zmienia etykietę, jaką powinna otrzymać dana ścieżka
- `restorecon` / `setfiles`: ponownie stosuje te zmiany na dużą skalę
- `semodule -i`: ładuje niestandardowy moduł policy
- `semanage permissive -a <domain_t>`: ustawia jedną domenę w trybie permissive bez przełączania całego hosta
- `setsebool -P`: trwale zmienia booleany policy
- `load_policy`: ponownie ładuje aktywną policy

Często są to **helper primitives**, a nie samodzielne exploity umożliwiające uzyskanie uprawnień root. Ich wartość polega na tym, że pozwalają:

- ustawić docelową domenę w trybie permissive
- rozszerzyć dostęp między własną domeną a chronionym typem
- zmienić etykiety plików kontrolowanych przez attackera, aby uprzywilejowany service mógł je odczytać lub wykonać
- osłabić confined service na tyle, aby istniejący lokalny bug stał się exploitable

Przykładowe checks:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Jeśli możesz załadować moduł zasad jako root, zazwyczaj kontrolujesz granicę SELinux:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Dlatego `audit2allow`, `semodule` i `semanage permissive` należy traktować jako wrażliwe powierzchnie administracyjne podczas post-exploitation. Mogą po cichu przekształcić zablokowany łańcuch w działający, bez zmiany klasycznych uprawnień UNIX.

## Ukryte odmowy i ekstrakcja modułów

Bardzo częstą frustracją podczas działań ofensywnych jest łańcuch, który kończy się ogólnym błędem `EACCES`, mimo że oczekiwana odmowa AVC nigdy się nie pojawia. Reguły `dontaudit` mogą ukrywać dokładne uprawnienie, którego potrzebujesz. Jeśli możesz uruchomić `semodule` przez `sudo` lub inny uprzywilejowany wrapper, tymczasowe wyłączenie `dontaudit` może przekształcić ciche niepowodzenie w precyzyjną wskazówkę dotyczącą polityki:
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Jest to również przydatne podczas sprawdzania, co lokalni administratorzy już zmienili. Niewielki custom module lub permissive rule dla jednej domeny często stanowi powód, dla którego usługa docelowa działa znacznie mniej restrykcyjnie, niż sugerowałaby base policy.

## Wskazówki audytu

Odmowy AVC są często sygnałem ofensywnym, a nie tylko defensywnym szumem. Informują Cię:

- jaki obiekt/typ docelowy został trafiony
- które uprawnienie zostało odrzucone
- którą domenę obecnie kontrolujesz
- czy niewielka zmiana policy umożliwiłaby działanie chain
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Jeśli lokalny exploit lub próba persistence ciągle kończy się błędem `EACCES` albo dziwnymi błędami „permission denied”, mimo uprawnień DAC wyglądających na rootowe, zwykle warto sprawdzić SELinux, zanim odrzuci się ten wektor.

## Użytkownicy SELinux

Oprócz zwykłych użytkowników Linux istnieją również użytkownicy SELinux. Każdy użytkownik Linux jest mapowany na użytkownika SELinux w ramach policy, co pozwala systemowi narzucać różne dozwolone role i domeny dla poszczególnych kont.

Szybkie sprawdzenia:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Na wielu mainstreamowych systemach użytkownicy są mapowani na `unconfined_u`, co zmniejsza praktyczne znaczenie ograniczenia użytkowników. W hardened deployments ograniczeni użytkownicy mogą jednak sprawić, że `sudo`, `su`, `newrole` i `runcon` staną się znacznie bardziej interesujące, ponieważ **ścieżka eskalacji może zależeć od wejścia w lepszą rolę/typ SELinux, a nie tylko od uzyskania UID 0**. Pamiętaj również, że niektórzy ograniczeni użytkownicy nie mogą w ogóle wywoływać `sudo`/`su`, chyba że policy jawnie zezwala na bazowe przejście setuid, więc host używający `staff_u` + `sysadm_r` może zmienić pozornie nieistotną regułę `sudo ROLE=` / `TYPE=` w rzeczywistą granicę uprawnień.

## SELinux w kontenerach

Runtime'y kontenerów często uruchamiają workloady w ograniczonej domenie, takiej jak `container_t`, i oznaczają zawartość kontenera jako `container_file_t`. Jeśli proces kontenera ucieknie, ale nadal działa z etykietą kontenera, zapisy na hoście mogą nadal kończyć się niepowodzeniem, ponieważ granica etykiety pozostała nienaruszona.

Szybki przykład:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Część `c647,c780` nie jest dekoracją. W wielu wdrożeniach kontenerów runtime dynamicznie przypisuje kategorie MCS, dzięki czemu dwa procesy działające jako `container_t` nadal są od siebie odseparowane. Jeśli escape umieści Cię w namespace hosta, ale zachowa oryginalny zestaw kategorii, niezgodności kategorii nadal mogą wyjaśniać, dlaczego niektóre ścieżki hosta pozostają nieczytelne lub niezapisywalne.

Warto odnotować następujące współczesne operacje na kontenerach:

- `--security-opt label=disable` może skutecznie przenieść workload do nieograniczonego typu związanego z kontenerami, takiego jak `spc_t`
- bind mounts z `:z` / `:Z` uruchamiają ponowne etykietowanie ścieżki hosta na potrzeby współdzielonego/prywatnego użycia przez kontenery
- szerokie ponowne etykietowanie zawartości hosta samo w sobie może stać się problemem bezpieczeństwa

Ta strona zawiera niewiele treści dotyczących kontenerów, aby uniknąć powielania. Przypadki nadużyć specyficzne dla kontenerów oraz przykłady runtime znajdziesz tutaj:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## Referencje

- [Dokumentacja Red Hat: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Narzędzia do analizy policy dla SELinux](https://github.com/SELinuxProject/setools)
- [Zarządzanie użytkownikami confined i unconfined - dokumentacja RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - strona podręcznika Linux](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
