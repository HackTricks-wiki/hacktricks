# SELinux

SELinux to oparty na **etykietach** system Mandatory Access Control (MAC). W praktyce oznacza to, że nawet jeśli uprawnienia DAC, grupy lub capabilities systemu Linux wydają się wystarczające do wykonania danej czynności, kernel może nadal jej odmówić, ponieważ **source context** nie ma zezwolenia na dostęp do **target context** przy użyciu żądanej klasy/uprawnienia.<sup>[[1]](#references)</sup>

Context zwykle wygląda tak:<sup>[[1]](#references)</sup>
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Z perspektywy privesc pole `type` (domena dla procesów, typ dla obiektów) jest zwykle najważniejszym polem:<sup>[[1]](#references)</sup>

- Proces działa w **domenie**, takiej jak `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Pliki i sockety mają **typ**, taki jak `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Policy decyduje, czy jedna domena może odczytywać, zapisywać, wykonywać lub przechodzić do drugiej

## Szybka enumeracja

Jeśli SELinux jest włączony, przeprowadź jego enumerację na wczesnym etapie, ponieważ może wyjaśnić, dlaczego typowe ścieżki linuxowego privesc zawodzą lub dlaczego uprzywilejowany wrapper wokół „nieszkodliwego” narzędzia SELinux ma w rzeczywistości kluczowe znaczenie:<sup>[[1]](#references)</sup>
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Przydatne dalsze sprawdzenia:<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>
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

- Tryb `Disabled` lub `Permissive` usuwa większość wartości SELinux jako granicy bezpieczeństwa.
- `unconfined_t` zwykle oznacza, że SELinux jest obecny, ale nie nakłada istotnych ograniczeń na dany proces.
- `default_t`, `file_t` lub oczywiście nieprawidłowe etykiety na niestandardowych ścieżkach często wskazują na nieprawidłowe etykietowanie albo niekompletne wdrożenie.
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
Jest to szczególnie przydatne, gdy host używa **confined users**, zamiast mapować wszystkich na `unconfined_u`. W takim przypadku sprawdź:<sup>[[3]](#references)</sup>

- mapowania użytkowników za pomocą `semanage login -l`
- dozwolone role za pomocą `semanage user -l`
- dostępne domeny administracyjne, takie jak `sysadm_t`, `secadm_t`, `webadm_t`
- wpisy `sudoers` używające `ROLE=` lub `TYPE=`

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
`runcon` i `newrole` nie są automatycznie wykorzystywalne, ale jeśli uprzywilejowany wrapper lub reguła `sudoers` pozwala wybrać lepszą rolę/typ, stają się cennymi prymitywami eskalacji.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

## Pliki, zmiana etykiet i cenne błędne konfiguracje

Najważniejsza operacyjna różnica między typowymi narzędziami SELinux to:<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: tymczasowa zmiana etykiety określonej ścieżki
- `semanage fcontext`: trwała reguła mapowania ścieżki na etykietę
- `restorecon` / `setfiles`: ponowne zastosowanie etykiety wynikającej z policy/default

Ma to duże znaczenie podczas privesc, ponieważ **zmiana etykiety nie jest tylko kwestią kosmetyczną**. Może zmienić plik z „zablokowanego przez policy” w „możliwy do odczytu/wykonania przez uprzywilejowaną usługę działającą w ograniczonym kontekście”.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Sprawdź lokalne reguły zmiany etykiet oraz rozbieżności w etykietach:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Jeden subtelny, ale przydatny szczegół: zwykłe `restorecon` **nie zawsze w pełni przywraca podejrzaną etykietę**. Jeśli typ docelowy znajduje się w `customizable_types`, może być konieczne użycie `-F`, aby wymusić pełny reset. Z perspektywy offensive wyjaśnia to, dlaczego nietypowe `chcon` może czasami przetrwać pobieżne czyszczenie typu „przecież już uruchomiliśmy restorecon”.<sup>[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Polecenia o wysokiej wartości, których należy szukać w `sudo -l`, wrapperach root, skryptach automatyzacji lub capabilities plików:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Jeśli pojawi się którakolwiek z możliwości MAC, sprawdź również [stronę dotyczącą możliwości Linux](linux-capabilities.md); dokumentacja możliwości Linux opisuje `cap_mac_admin` i `cap_mac_override` jako specyficzne dla Smack, dlatego nie zakładaj, że same ich nazwy oznaczają obejście SELinux.<sup>[[5]](#references)</sup>

Szczególnie interesujące:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: trwale zmienia etykietę, którą powinna otrzymać ścieżka
- `restorecon` / `setfiles`: ponownie stosuje te zmiany na dużą skalę
- `semodule -i`: ładuje niestandardowy moduł policy
- `semanage permissive -a <domain_t>`: ustawia jedną domenę w trybie permissive bez przełączania całego hosta
- `setsebool -P`: trwale zmienia booleany policy
- `load_policy`: ponownie ładuje aktywną policy

Są to często **prymitywy pomocnicze**, a nie samodzielne root exploits. Ich wartość polega na tym, że pozwalają:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- ustawić docelową domenę w trybie permissive
- rozszerzyć dostęp między swoją domeną a chronionym typem
- zmienić etykiety plików kontrolowanych przez attackera, aby uprzywilejowany serwis mógł je odczytać lub wykonać
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
Dlatego `audit2allow`, `semodule` i `semanage permissive` należy traktować jako wrażliwe powierzchnie administracyjne podczas post-exploitation. Mogą po cichu przekształcić zablokowany łańcuch w działający, bez zmiany klasycznych uprawnień UNIX.<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## Ukryte odmowy i ekstrakcja modułów

Bardzo częstą frustracją ofensywną jest łańcuch, który kończy się ogólnym błędem `EACCES`, podczas gdy oczekiwana odmowa AVC nigdy się nie pojawia. Reguły `dontaudit` mogą ukrywać dokładne uprawnienie, którego potrzebujesz. Jeśli możesz uruchomić `semodule` za pośrednictwem `sudo` lub innego uprzywilejowanego wrappera, tymczasowe wyłączenie `dontaudit` może przekształcić ciche niepowodzenie w precyzyjną wskazówkę dotyczącą policy:<sup>[[4]](#references)[[15]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Jest to również przydatne podczas sprawdzania, co lokalni administratorzy już zmienili. Mały custom module lub reguła permissive dla jednej domeny często jest powodem, dla którego usługa docelowa działa znacznie mniej restrykcyjnie, niż sugerowałaby base policy.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Wskazówki audytowe

Odmowy AVC są często sygnałem przydatnym ofensywnie, a nie tylko szumem defensywnym. Informują Cię:<sup>[[1]](#references)[[15]](#references)</sup>

- jaki obiekt/typ docelowy został trafiony
- jakie uprawnienie zostało odrzucone
- jaką domenę obecnie kontrolujesz
- czy niewielka zmiana policy sprawiłaby, że chain zadziała
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Jeśli lokalny exploit lub próba persistence stale kończy się błędem `EACCES` albo dziwnymi błędami „permission denied”, mimo uprawnień DAC wyglądających na uprawnienia roota, przed odrzuceniem wektora zwykle warto sprawdzić SELinux.<sup>[[1]](#references)</sup>

## Użytkownicy SELinux

Oprócz zwykłych użytkowników Linux istnieją również użytkownicy SELinux. Każdy użytkownik Linux jest mapowany na użytkownika SELinux w ramach policy, co pozwala systemowi nakładać różne dozwolone role i domeny na poszczególne konta.<sup>[[3]](#references)</sup>

Szybkie sprawdzenia:<sup>[[3]](#references)</sup>
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Na wielu głównych systemach użytkownicy są mapowani na `unconfined_u`, co zmniejsza praktyczny wpływ ograniczania użytkowników. W hardened deployments ograniczeni użytkownicy mogą jednak sprawić, że `sudo`, `su`, `newrole` i `runcon` staną się znacznie ciekawsze, ponieważ **ścieżka eskalacji może zależeć od wejścia w lepszą rolę/typ SELinux, a nie tylko od uzyskania UID 0**. Należy również pamiętać, że niektórzy ograniczeni użytkownicy w ogóle nie mogą uruchamiać `sudo`/`su`, chyba że policy jawnie zezwala na bazową zmianę przez setuid, dlatego host używający `staff_u` + `sysadm_r` może zamienić pozornie nieistotną regułę `sudo ROLE=` / `TYPE=` w rzeczywistą granicę uprawnień.<sup>[[3]](#references)</sup>

## SELinux w kontenerach

Runtimes kontenerów często uruchamiają workloady w ograniczonej domenie, takiej jak `container_t`, i oznaczają zawartość kontenera jako `container_file_t`. Jeśli proces kontenera ucieknie, ale nadal działa z etykietą kontenera, zapisy na hoście mogą nadal kończyć się niepowodzeniem, ponieważ granica etykiety pozostała nienaruszona.<sup>[[1]](#references)[[17]](#references)</sup>

Szybki przykład:<sup>[[16]](#references)[[18]](#references)</sup>
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Fragment `c647,c780` nie jest dekoracją. W wielu wdrożeniach kontenerów runtime dynamicznie przypisuje kategorie MCS, dzięki czemu dwa procesy działające jako `container_t` nadal są od siebie odseparowane. Jeśli escape przeniesie Cię do host namespace, ale zachowa pierwotny zestaw kategorii, niezgodności kategorii mogą nadal wyjaśniać, dlaczego niektóre ścieżki hosta pozostają nieczytelne lub niezapisywalne.<sup>[[17]](#references)</sup>

Warto zwrócić uwagę na następujące współczesne operacje kontenerów:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` wyłącza separację etykiet SELinux dla kontenera
- bind mounts z `:z` / `:Z` uruchamiają ponowne etykietowanie ścieżki hosta na potrzeby współdzielonego/prywatnego użycia przez kontener
- szerokie ponowne etykietowanie zawartości hosta może samo w sobie stać się problemem bezpieczeństwa

Ta strona zawiera krótką sekcję dotyczącą kontenerów, aby uniknąć duplikacji. Informacje o przypadkach nadużyć specyficznych dla kontenerów i przykładach użycia runtime znajdziesz tutaj:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## References

- [1] [Dokumentacja Red Hat: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Narzędzia do analizy policy SELinux](https://github.com/SELinuxProject/setools)
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
