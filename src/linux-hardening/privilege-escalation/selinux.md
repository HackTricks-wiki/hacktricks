# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux to **system kontroli dostępu obowiązkowego (MAC) oparty na etykietach**. W praktyce oznacza to, że nawet jeśli uprawnienia DAC, grupy lub Linux capabilities wydają się wystarczające do wykonania akcji, kernel może to wciąż odmówić, ponieważ **kontekst źródłowy** nie ma pozwolenia na dostęp do **kontekstu docelowego** z żądaną klasą/uprawnieniem.

Kontekst zwykle wygląda tak:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Z perspektywy privesc, `type` (domena dla procesów, typ dla obiektów) jest zwykle najważniejszym polem:

- Proces działa w **domenie** takiej jak `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Pliki i gniazda mają **typ** taki jak `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Polityka decyduje, czy jedna domena może czytać/zapisywać/wykonywać/przechodzić w inną

## Szybka enumeracja

Jeśli SELinux jest włączony, przeprowadź jego enumerację wcześnie, ponieważ może to wyjaśnić, dlaczego typowe ścieżki privesc na Linuxie zawodzą lub dlaczego uprzywilejowany wrapper wokół "nieszkodliwego" narzędzia SELinux jest w rzeczywistości krytyczny:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Przydatne kontrole uzupełniające:
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
Ciekawe ustalenia:

- Tryb `Disabled` lub `Permissive` pozbawia SELinux większości wartości jako granicy.
- `unconfined_t` zazwyczaj oznacza, że SELinux jest obecny, ale nie stanowi istotnego ograniczenia dla tego procesu.
- `default_t`, `file_t` lub oczywiście błędne etykiety na niestandardowych ścieżkach często wskazują na błędne oznakowanie lub niepełne wdrożenie.
- Lokalne nadpisania w `file_contexts.local` mają pierwszeństwo przed domyślnymi ustawieniami polityki, więc sprawdź je dokładnie.

## Analiza polityki

SELinux jest znacznie łatwiejszy do zaatakowania lub obejścia, gdy potrafisz odpowiedzieć na dwa pytania:

1. **Do czego ma dostęp moja bieżąca domena?**
2. **Do jakich domen mogę przejść?**

Najbardziej przydatne narzędzia do tego to `sepolicy` i **SETools** (`seinfo`, `sesearch`, `sedta`):
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
Jest to szczególnie przydatne, gdy host używa **użytkowników ograniczonych** zamiast mapować wszystkich na `unconfined_u`. W takim przypadku szukaj:

- mapowań użytkowników za pomocą `semanage login -l`
- dozwolonych ról za pomocą `semanage user -l`
- osiągalnych domen administracyjnych, takich jak `sysadm_t`, `secadm_t`, `webadm_t`
- wpisów `sudoers` używających `ROLE=` lub `TYPE=`

Jeśli `sudo -l` zawiera wpisy takie jak te, SELinux jest częścią granicy przywilejów:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Sprawdź również, czy `newrole` jest dostępny:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` i `newrole` nie są automatycznie podatne na wykorzystanie, ale jeśli uprzywilejowany wrapper lub reguła `sudoers` pozwala ci wybrać lepszą rolę/typ, stają się one cennymi prymitywami eskalacji.

## Pliki, zmiana etykiet i misconfiguracje o wysokiej wartości

Najważniejsza różnica w działaniu między powszechnymi narzędziami SELinux to:

- `chcon`: tymczasowa zmiana etykiety na określonej ścieżce
- `semanage fcontext`: trwała reguła mapująca ścieżkę do etykiety
- `restorecon` / `setfiles`: ponowne zastosowanie etykiety z polityki / etykiety domyślnej

Ma to ogromne znaczenie podczas privesc, ponieważ **zmiana etykiet nie jest tylko kosmetyczna**. Może przekształcić plik z "zablokowanego przez politykę" w "czytelny/wykonywalny przez uprzywilejowaną, ograniczoną usługę".

Sprawdź lokalne reguły zmiany etykiet i odchylenia w ich stosowaniu:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Wysokowartościowe polecenia do wyszukania w `sudo -l`, root wrappers, automation scripts lub file capabilities:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Szczególnie warte uwagi:

- `semanage fcontext`: trwale zmienia, jaką etykietę powinna otrzymać ścieżka
- `restorecon` / `setfiles`: ponownie stosuje te zmiany na dużą skalę
- `semodule -i`: ładuje niestandardowy moduł polityki
- `semanage permissive -a <domain_t>`: ustawia jedną domenę jako permissive bez przełączania całego hosta
- `setsebool -P`: trwale zmienia wartości booleanów polityki
- `load_policy`: przeładowuje aktywną politykę

To często **prymitywy pomocnicze**, a nie samodzielne root exploits. Ich wartość polega na tym, że pozwalają na:

- ustawienie docelowej domeny jako permissive
- poszerzenie dostępu między twoją domeną a chronionym typem
- relabelowanie plików kontrolowanych przez atakującego tak, aby uprzywilejowana usługa mogła je odczytać lub wykonać
- osłabienie ograniczonej usługi na tyle, że istniejący lokalny błąd stanie się wykorzystywalny

Przykładowe sprawdzenia:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Jeśli możesz załadować moduł polityki jako root, zwykle kontrolujesz granicę SELinux:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Dlatego `audit2allow`, `semodule` i `semanage permissive` należy traktować jako wrażliwe powierzchnie administracyjne podczas post-exploitation. Mogą po cichu przekształcić zablokowany łańcuch w działający bez zmiany klasycznych uprawnień UNIX.

## Wskazówki z audytu

Odrzucenia AVC często są sygnałem ofensywnym, nie tylko obronnym szumem. Informują o:

- jaki obiekt/typ celu został trafiony
- które uprawnienie zostało odmówione
- którą domeną obecnie kontrolujesz
- czy niewielka zmiana polityki sprawiłaby, że łańcuch zacznie działać
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Jeśli lokalny exploit lub próba persistence ciągle kończy się błędem `EACCES` lub dziwnymi komunikatami "permission denied" pomimo uprawnień DAC wyglądających na rootowe, zwykle warto sprawdzić SELinux, zanim porzuci się ten wektor.

## Użytkownicy SELinux

Obok zwykłych użytkowników Linux istnieją użytkownicy SELinux. W ramach polityki każdy użytkownik Linux jest mapowany na użytkownika SELinux, co pozwala systemowi narzucać różne dozwolone role i domeny dla różnych kont.

Szybkie sprawdzenia:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
Na wielu popularnych systemach użytkownicy są mapowani na `unconfined_u`, co zmniejsza praktyczny wpływ izolacji użytkownika. W ściśle zabezpieczonych środowiskach jednakże użytkownicy objęci ograniczeniami mogą uczynić `sudo`, `su`, `newrole` i `runcon` znacznie bardziej interesującymi, ponieważ **ścieżka eskalacji może zależeć od przejścia do lepszej roli/typu SELinux, a nie tylko od uzyskania UID 0**.

## SELinux w kontenerach

Silniki kontenerów często uruchamiają zadania w ograniczonej domenie, takiej jak `container_t`, i oznaczają zawartość kontenera jako `container_file_t`. Jeśli proces z kontenera ucieknie, ale nadal działa z etykietą kontenera, zapisy na hoście mogą nadal się nie powieść, ponieważ granica etykiet pozostała nienaruszona.

Szybki przykład:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Współczesne container operations warte odnotowania:

- `--security-opt label=disable` może efektywnie przenieść workload do unconfined container-related type takiego jak `spc_t`
- bind mounts z `:z` / `:Z` wywołują relabeling host path dla shared/private container use
- szeroki relabeling host content może sam w sobie stać się security issue

Ta strona utrzymuje zawartość dotyczącą container krótką, aby uniknąć duplikacji. Dla container-specific abuse cases i runtime examples sprawdź:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## Źródła

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
