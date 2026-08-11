# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux to **oparty na etykietach system Mandatory Access Control (MAC)**. W praktyce oznacza to, że nawet jeśli uprawnienia DAC, grupy lub Linux capabilities wyglądają na wystarczające do wykonania danej operacji, kernel nadal może jej odmówić, ponieważ **kontekst źródłowy** nie ma zezwolenia na dostęp do **kontekstu docelowego** z użyciem żądanej klasy/uprawnienia.<sup>[[1]](#references)</sup>

Kontekst zazwyczaj wygląda tak:<sup>[[1]](#references)</sup>
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Z perspektywy `privesc` pole `type` (domena dla procesów, typ dla obiektów) jest zwykle najważniejszym polem:<sup>[[1]](#references)</sup>

- Proces działa w **domenie**, takiej jak `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Pliki i sockety mają **typ**, taki jak `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Policy decyduje, czy jedna domena może odczytywać, zapisywać, wykonywać lub przechodzić do innej

## Szybka enumeracja

Jeśli SELinux jest włączony, przeprowadź jego enumerację na wczesnym etapie, ponieważ może wyjaśnić, dlaczego typowe ścieżki Linux `privesc` zawodzą albo dlaczego uprzywilejowany wrapper wokół „nieszkodliwego” narzędzia SELinux ma w rzeczywistości kluczowe znaczenie:<sup>[[1]](#references)</sup>
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Przydatne kontrole uzupełniające:<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>
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
Interesujące ustalenia:<sup>[[1]](#references)[[3]](#references)[[7]](#references)[[19]](#references)</sup>

- Tryb `Disabled` lub `Permissive` pozbawia SELinux większości wartości jako granicy.
- `unconfined_t` zwykle oznacza, że SELinux jest obecny, ale nie ogranicza w praktyce danego procesu.
- `default_t`, `file_t` lub ewidentnie nieprawidłowe etykiety na niestandardowych ścieżkach często wskazują na błędne etykietowanie lub niekompletne wdrożenie.
- Lokalne nadpisania w `file_contexts.local` mają pierwszeństwo przed domyślnymi ustawieniami policy, dlatego należy je dokładnie przejrzeć.

## Analiza policy

SELinux jest znacznie łatwiejszy do zaatakowania lub obejścia, gdy można odpowiedzieć na dwa pytania:

1. **Do czego może uzyskać dostęp moja bieżąca domena?**
2. **Do jakich domen mogę przejść?**

Najbardziej przydatne narzędzia do tego celu to `sepolicy` i **SETools** (`seinfo`, `sesearch`, `sedta`):<sup>[[2]](#references)[[9]](#references)</sup>
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
Jest to szczególnie przydatne, gdy host używa **confined users** zamiast mapować wszystkich na `unconfined_u`. W takim przypadku szukaj:<sup>[[3]](#references)</sup>

- mapowań użytkowników za pomocą `semanage login -l`
- dozwolonych ról za pomocą `semanage user -l`
- dostępnych domen administracyjnych, takich jak `sysadm_t`, `secadm_t`, `webadm_t`
- wpisów `sudoers` używających `ROLE=` lub `TYPE=`

Jeśli `sudo -l` zawiera wpisy takie jak ten, SELinux jest częścią granicy uprawnień:<sup>[[3]](#references)</sup>
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Sprawdź również, czy `newrole` jest dostępne:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` i `newrole` nie są automatycznie podatne na exploitację, ale jeśli uprzywilejowany wrapper lub reguła `sudoers` pozwala wybrać lepszą rolę/typ, stają się cennymi prymitywami eskalacji uprawnień.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

## Pliki, ponowne etykietowanie i konfiguracje o wysokiej wartości

Najważniejsza praktyczna różnica między typowymi narzędziami SELinux to:<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: tymczasowa zmiana etykiety dla określonej ścieżki
- `semanage fcontext`: trwała reguła przypisująca ścieżkę do etykiety
- `restorecon` / `setfiles`: ponowne zastosowanie etykiety wynikającej z policy/dom
yślnej

Ma to duże znaczenie podczas privesc, ponieważ **ponowne etykietowanie nie jest tylko kwestią wyglądu**. Może zmienić plik z „zablokowanego przez policy” w „czytelny/wykonywalny dla uprzywilejowanej usługi działającej w ograniczonym kontekście”.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Sprawdź lokalne reguły ponownego etykietowania i rozbieżności w etykietach:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Jeden subtelny, ale przydatny szczegół: zwykłe `restorecon` **nie zawsze w pełni przywraca podejrzaną etykietę**. Jeśli typ docelowy znajduje się w `customizable_types`, może być konieczne użycie `-F`, aby wymusić pełne zresetowanie. Z perspektywy ofensywnej wyjaśnia to, dlaczego nietypowe `chcon` może czasami przetrwać pobieżne czyszczenie po stwierdzeniu „już uruchomiliśmy restorecon”.<sup>[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Cenne polecenia do wyszukania w `sudo -l`, wrapperach root, skryptach automatyzacji lub możliwościach plików:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Jeśli pojawi się którakolwiek z funkcji MAC, sprawdź również [Linux capabilities page](linux-capabilities.md); dokumentacja Linux capabilities opisuje `cap_mac_admin` i `cap_mac_override` jako specyficzne dla Smack, więc nie zakładaj, że same ich nazwy omijają SELinux.<sup>[[5]](#references)</sup>

Szczególnie interesujące:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: trwale zmienia etykietę, jaką powinna otrzymać ścieżka
- `restorecon` / `setfiles`: ponownie stosuje te zmiany na dużą skalę
- `semodule -i`: ładuje niestandardowy moduł policy
- `semanage permissive -a <domain_t>`: ustawia jedną domenę w trybie permissive bez przełączania całego hosta
- `setsebool -P`: trwale zmienia booleany policy
- `load_policy`: przeładowuje aktywną policy

Są to często **prymitywy pomocnicze**, a nie samodzielne exploity root. Ich wartość polega na tym, że pozwalają:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- ustawić docelową domenę w trybie permissive
- rozszerzyć dostęp między własną domeną a chronionym typem
- zmienić etykiety plików kontrolowanych przez attackera, aby uprzywilejowany service mógł je odczytać lub wykonać
- osłabić confined service na tyle, aby istniejący local bug stał się exploitable

Przykładowe sprawdzenia:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Jeśli możesz załadować moduł polityki jako root, zwykle kontrolujesz granicę SELinux:<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Dlatego `audit2allow`, `semodule` i `semanage permissive` należy traktować jako wrażliwe powierzchnie administracyjne podczas post-exploitation. Mogą one po cichu przekształcić zablokowany łańcuch w działający, bez zmiany klasycznych uprawnień UNIX.<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## Ukryte odmowy i ekstrakcja modułów

Bardzo częstą frustracją podczas działań ofensywnych jest łańcuch, który kończy się ogólnym błędem `EACCES`, podczas gdy oczekiwana odmowa AVC nigdy się nie pojawia. Reguły `dontaudit` mogą ukrywać dokładnie to uprawnienie, którego potrzebujesz. Jeśli możesz uruchomić `semodule` za pośrednictwem `sudo` lub innego uprzywilejowanego wrappera, tymczasowe wyłączenie `dontaudit` może przekształcić cichą awarię w precyzyjną wskazówkę dotyczącą polityki:<sup>[[4]](#references)[[15]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Jest to również przydatne podczas sprawdzania, co lokalni administratorzy już zmienili. Niewielki custom module lub reguła permissive dla jednej domeny jest często powodem, dla którego docelowa usługa działa znacznie mniej restrykcyjnie, niż sugerowałaby base policy.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Wskazówki audytowe

Odmowy AVC są często sygnałem ofensywnym, a nie tylko szumem defensywnym. Informują Cię:<sup>[[1]](#references)[[15]](#references)</sup>

- jaki obiekt docelowy/typ został trafiony
- które uprawnienie zostało odrzucone
- nad którą domeną obecnie masz kontrolę
- czy niewielka zmiana policy umożliwiłaby działanie chaina
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Jeśli lokalny exploit lub próba persistence ciągle kończy się błędem `EACCES` albo dziwnymi błędami „permission denied”, mimo że uprawnienia DAC wyglądają jak uprawnienia root, przed odrzuceniem tego wektora zwykle warto sprawdzić SELinux.<sup>[[1]](#references)</sup>

## Użytkownicy SELinux

Oprócz zwykłych użytkowników Linux istnieją także użytkownicy SELinux. Każdy użytkownik Linux jest mapowany na użytkownika SELinux w ramach polityki, co pozwala systemowi narzucać różne dozwolone role i domeny dla poszczególnych kont.<sup>[[3]](#references)</sup>

Szybkie sprawdzenia:<sup>[[3]](#references)</sup>
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Na wielu popularnych systemach użytkownicy są mapowani na `unconfined_u`, co zmniejsza praktyczne znaczenie ograniczania użytkowników. W przypadku hardened deployments użytkownicy objęci ograniczeniami mogą jednak sprawić, że `sudo`, `su`, `newrole` i `runcon` staną się znacznie bardziej interesujące, ponieważ **ścieżka eskalacji może zależeć od wejścia w lepszą rolę/typ SELinux, a nie tylko od uzyskania UID 0**. Pamiętaj również, że niektórzy użytkownicy objęci ograniczeniami nie mogą w ogóle wywoływać `sudo`/`su`, chyba że policy jawnie zezwala na bazową setuid transition, dlatego host używający `staff_u` + `sysadm_r` może zamienić pozornie nieistotną regułę `sudo ROLE=` / `TYPE=` w rzeczywistą granicę uprawnień.<sup>[[3]](#references)</sup>

## SELinux w kontenerach

Runtimes kontenerów zwykle uruchamiają workloady w ograniczonej domenie, takiej jak `container_t`, i oznaczają zawartość kontenera jako `container_file_t`. Jeśli proces kontenera ucieknie, ale nadal działa z etykietą kontenera, zapisy na hoście mogą nadal kończyć się niepowodzeniem, ponieważ granica etykiety pozostała nienaruszona.<sup>[[1]](#references)[[17]](#references)</sup>

Szybki przykład:<sup>[[16]](#references)[[18]](#references)</sup>
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Część `c647,c780` nie jest dekoracją. W wielu wdrożeniach kontenerów runtime'y dynamicznie przypisują kategorie MCS, dzięki czemu dwa procesy działające jako `container_t` nadal są od siebie odseparowane. Jeśli escape przeniesie Cię do host namespace, ale zachowa oryginalny zestaw kategorii, niezgodności kategorii nadal mogą wyjaśniać, dlaczego niektóre ścieżki hosta pozostają nieczytelne lub niezapisywalne.<sup>[[17]](#references)</sup>

Warto zwrócić uwagę na następujące współczesne operacje na kontenerach:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` wyłącza separację etykiet SELinux dla kontenera
- bind mounts z `:z` / `:Z` wywołują ponowne etykietowanie ścieżki hosta na potrzeby współdzielonego/prywatnego użycia przez kontenery
- szerokie ponowne etykietowanie zawartości hosta samo w sobie może stać się problemem bezpieczeństwa

Ta strona zawiera niewiele treści dotyczących kontenerów, aby uniknąć duplikacji. Informacje o przypadkach nadużyć specyficznych dla kontenerów i przykładach dotyczących runtime'ów znajdziesz tutaj:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## References

- [1] [Dokumentacja Red Hat: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Narzędzia do analizy polityk SELinux](https://github.com/SELinuxProject/setools)
- [3] [Zarządzanie użytkownikami confined i unconfined - dokumentacja RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - strona podręcznika Linux](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) - strona podręcznika Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) - strona podręcznika Linux](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) - strona podręcznika Linux](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) - strona podręcznika Linux](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) - strona podręcznika Linux](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) - strona podręcznika Linux](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) - strona podręcznika Linux](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) - strona podręcznika Linux](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) - strona podręcznika Linux](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) - strona podręcznika Linux](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) - strona podręcznika Linux](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Dokumentacja Podman run](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [Dlaczego warto używać Multi-Category Security dla kontenerów Linux](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Dokumentacja Podman top](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - strona podręcznika Linux](https://man7.org/linux/man-pages/man8/selinux.8.html)
{{#include ../../banners/hacktricks-training.md}}
