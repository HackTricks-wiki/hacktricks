# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux to system **Mandatory Access Control (MAC)** oparty na etykietach. W praktyce oznacza to, że nawet jeśli uprawnienia DAC, grupy lub capabilities systemu Linux wydają się wystarczające do wykonania danej czynności, kernel nadal może jej odmówić, ponieważ **kontekst źródłowy** nie ma dostępu do **kontekstu docelowego** z żądaną klasą/uprawnieniem.<sup>[[1]](#references)</sup>

Kontekst zwykle wygląda tak:<sup>[[1]](#references)</sup>

```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

Z perspektywy privesc pole `type` (domena w przypadku procesów, typ w przypadku obiektów) jest zwykle najważniejsze:<sup>[[1]](#references)</sup>

- Proces działa w **domenie**, takiej jak `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Pliki i gniazda mają **typ**, taki jak `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Polityka określa, czy jedna domena może odczytywać, zapisywać, wykonywać lub przechodzić do drugiej

## Szybka enumeracja

Jeśli SELinux jest włączony, przeprowadź jego enumerację na wczesnym etapie, ponieważ może wyjaśnić, dlaczego typowe ścieżki privesc w Linuksie zawodzą albo dlaczego uprzywilejowany wrapper wokół „nieszkodliwego” narzędzia SELinux ma w rzeczywistości kluczowe znaczenie:<sup>[[1]](#references)</sup>

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

Ciekawe ustalenia:<sup>[[1]](#references)[[3]](#references)[[7]](#references)[[19]](#references)</sup>

- Tryb `Disabled` lub `Permissive` pozbawia SELinux większości jego wartości jako granicy.
- `unconfined_t` zwykle oznacza, że SELinux jest obecny, ale nie ogranicza w istotny sposób tego procesu.
- `default_t`, `file_t` lub ewidentnie nieprawidłowe etykiety na niestandardowych ścieżkach często wskazują na błędne etykietowanie albo niekompletne wdrożenie.
- Lokalne nadpisania w `file_contexts.local` mają pierwszeństwo przed domyślnymi ustawieniami polityki, dlatego należy je dokładnie sprawdzić.

## Analiza polityki

SELinux jest znacznie łatwiejszy do zaatakowania lub ominięcia, gdy potrafisz odpowiedzieć na dwa pytania:

1. **Do czego ma dostęp moja bieżąca domena?**
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

Jest to szczególnie przydatne, gdy host używa **użytkowników z ograniczeniami**, zamiast mapować wszystkich na `unconfined_u`. W takim przypadku sprawdź:<sup>[[3]](#references)</sup>

- mapowania użytkowników za pomocą `semanage login -l`
- dozwolone role za pomocą `semanage user -l`
- dostępne domeny administracyjne, takie jak `sysadm_t`, `secadm_t`, `webadm_t`
- wpisy `sudoers` używające `ROLE=` lub `TYPE=`

Jeśli `sudo -l` zawiera takie wpisy, SELinux stanowi część granicy uprawnień:<sup>[[3]](#references)</sup>

```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```

Sprawdź również, czy `newrole` jest dostępne:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
sudo -l
which newrole runcon
newrole -V 2>/dev/null
```

`runcon` i `newrole` nie są automatycznie podatne na wykorzystanie, ale jeśli uprzywilejowany wrapper lub reguła `sudoers` pozwala wybrać korzystniejszą rolę lub typ, stają się cennymi prymitywami eskalacji.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

### Audyt zapisywalnych punktów wejścia przejścia

Graf przejść wskazuje jedynie potencjalną regułę polityki. Aby przekształcić go w ścieżkę ataku, zidentyfikuj typ pliku wykonywalnego, który umożliwia wejście do bardziej użytecznej domeny, a następnie sprawdź, czy możesz zmodyfikować plik wykonywalny z tą etykietą lub zastąpić go za pośrednictwem jego katalogu nadrzędnego.<sup>[[9]](#references)[[20]](#references)</sup> Automatyczne przejście `execve` wymaga odpowiedniej reguły `type_transition`, uprawnień domeny źródłowej do wykonywania, uprawnień domeny docelowej `entrypoint` oraz uprawnień do przejścia między domenami.<sup>[[20]](#references)</sup> Domena docelowa może uzyskać dostęp SELinux, ale samo wykonanie nie zmienia identyfikatora UID Linuksa; osobno sprawdź [SUID/SGID i ACL](suid-sgid-and-acl-triage.md).<sup>[[20]](#references)[[21]](#references)</sup>

Użyj zgłoszonego typu `entrypoint`, aby sprawdzić bazowe reguły, a następnie sprawdź ścieżkę i jej katalog nadrzędny pod kątem uprawnień do zapisu.<sup>[[9]](#references)[[20]](#references)[[22]](#references)</sup>

```bash
src=$(id -Z | cut -d: -f3)
sepolicy transition -s "$src"                 # Note target domain and entrypoint type
dst=target_t                                   # Substitute a domain from the report
entry=target_exec_t                            # Substitute its entrypoint type
sesearch -T -s "$src" -t "$entry" -c process
sesearch --allow -s "$src" -t "$dst" -c process -p transition
sesearch --allow -s "$src" -t "$entry" -c file -p execute
sesearch --allow -s "$dst" -t "$entry" -c file -p entrypoint
sesearch --allow -s "$src" -t "$entry" -c file -p write
ls -lZ /path/to/entrypoint
namei -l /path/to/entrypoint
getfacl -p /path/to/entrypoint
getfacl -p /path/to
```

Skoreluj typ entrypoint z rzeczywistą ścieżką pliku wykonywalnego. Sprawdź DAC, ACL, uprawnienia SELinux do zapisu w pliku lub katalogu nadrzędnym, etykietę pliku oraz wszelkie warunkowe boolean, zanim uznasz, że przejście między domenami wskazane przez regułę jest możliwe.<sup>[[20]](#references)[[22]](#references)</sup> Jeśli ścieżka jest zastępowana zamiast edytowana w miejscu, sprawdź kontekst nowego inode: etykiety systemu plików są przechowywane jako atrybuty rozszerzone, a zastąpiony plik może nie zachować typu entrypoint.<sup>[[21]](#references)</sup> Programy obsługujące SELinux mogą zażądać przejścia za pomocą `setexeccon`, więc brak automatycznej reguły `type_transition` nie wyklucza wszystkich przejść.<sup>[[20]](#references)</sup>

## Pliki, ponowne etykietowanie i błędy konfiguracji o wysokim znaczeniu

Najważniejsza praktyczna różnica między popularnymi narzędziami SELinux to:<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: tymczasowa zmiana etykiety konkretnej ścieżki
- `semanage fcontext`: trwała reguła przypisująca etykietę do ścieżki
- `restorecon` / `setfiles`: ponowne zastosowanie etykiety określonej przez politykę lub domyślnej

Ma to duże znaczenie podczas privesc, ponieważ **ponowne etykietowanie to nie tylko kwestia wyglądu**. Może zmienić plik z „blokowanego przez politykę” w „czytelny/wykonywalny dla uprzywilejowanej, ograniczonej usługi”.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Sprawdź lokalne reguły ponownego etykietowania i rozbieżności w etykietach:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```

Jeden subtelny, ale przydatny szczegół: zwykłe `restorecon` **nie zawsze w pełni przywraca podejrzaną etykietę**. Jeśli typ docelowy znajduje się w `customizable_types`, może być konieczne użycie `-F`, aby wymusić pełne przywrócenie. Z perspektywy ofensywnej wyjaśnia to, dlaczego nietypowe `chcon` może czasem przetrwać pobieżne czyszczenie, mimo że „uruchomiliśmy już restorecon”.<sup>[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```

Komendy o wysokiej wartości do wyszukiwania w `sudo -l`, wrapperach root, skryptach automatyzacji lub capabilities plików:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```

Jeśli pojawi się którakolwiek z capabilities MAC, sprawdź też [stronę Linux capabilities](linux-capabilities.md); dokumentacja Linux capabilities opisuje `cap_mac_admin` i `cap_mac_override` jako specyficzne dla Smack, więc nie zakładaj, że same ich nazwy pozwalają ominąć SELinux.<sup>[[5]](#references)</sup>

Szczególnie interesujące:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: trwale zmienia etykietę przypisywaną ścieżce
- `restorecon` / `setfiles`: ponownie stosuje te zmiany na dużą skalę
- `semodule -i`: ładuje niestandardowy moduł policy
- `semanage permissive -a <domain_t>`: ustawia jedną domenę w trybie permissive, nie zmieniając ustawień całego hosta
- `setsebool -P`: trwale zmienia booleany policy
- `load_policy`: ponownie ładuje aktywną policy

Często są to **prymitywy pomocnicze**, a nie samodzielne root exploits. Ich wartość polega na tym, że pozwalają:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- ustawić docelową domenę w trybie permissive
- rozszerzyć dostęp między Twoją domeną a chronionym typem
- zmienić etykiety plików kontrolowanych przez atakującego, aby uprzywilejowana usługa mogła je odczytać lub wykonać
- osłabić ograniczenia usługi na tyle, by istniejący lokalny błąd dało się wykorzystać

Przykładowe kontrole:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

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

Dlatego `audit2allow`, `semodule` i `semanage permissive` należy traktować jako wrażliwe punkty administracyjne podczas post-exploitation. Mogą po cichu zmienić zablokowany łańcuch w działający, nie zmieniając klasycznych uprawnień UNIX.<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## Ukryte odmowy i ekstrakcja modułów

Bardzo częstym źródłem frustracji w działaniach ofensywnych jest łańcuch, który kończy się ogólnym błędem `EACCES`, mimo że nie pojawia się oczekiwane AVC denial. Reguły `dontaudit` mogą ukrywać dokładnie to uprawnienie, którego potrzebujesz. Jeśli możesz uruchomić `semodule` przez `sudo` lub inny uprzywilejowany wrapper, tymczasowe wyłączenie `dontaudit` może zamienić cichą porażkę w konkretną wskazówkę dotyczącą polityki:<sup>[[4]](#references)[[15]](#references)</sup>

```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```

To również przydaje się podczas sprawdzania, co już zmienili lokalni administratorzy. Niewielki niestandardowy moduł lub reguła permissive dla jednej domeny często wyjaśnia, dlaczego usługa docelowa działa znacznie mniej restrykcyjnie, niż sugerowałaby podstawowa policy.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Audit Clues

Odmowy AVC często są sygnałem przydatnym ofensywnie, a nie tylko szumem z perspektywy obrony. Informują o tym:<sup>[[1]](#references)[[15]](#references)</sup>

- który obiekt/typ docelowy został trafiony
- które uprawnienie zostało odrzucone
- nad którą domeną masz obecnie kontrolę
- czy niewielka zmiana policy pozwoliłaby zadziałać całemu chainowi

```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```

Jeśli lokalny exploit lub próba persistence ciągle kończy się błędem `EACCES` albo dziwnymi komunikatami „permission denied”, mimo że uprawnienia DAC wyglądają na uprawnienia roota, warto sprawdzić SELinux, zanim porzucisz ten wektor.<sup>[[1]](#references)</sup>

## Użytkownicy SELinux

Oprócz zwykłych użytkowników Linuksa istnieją także użytkownicy SELinux. Zgodnie z polityką każdy użytkownik Linuksa jest mapowany na użytkownika SELinux, co pozwala systemowi przypisywać różne dozwolone role i domeny do różnych kont.<sup>[[3]](#references)</sup>

Szybkie sprawdzenia:<sup>[[3]](#references)</sup>

```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```

W wielu popularnych systemach użytkownicy są mapowani na `unconfined_u`, co ogranicza praktyczne skutki ograniczania użytkowników. W utwardzonych wdrożeniach użytkownicy objęci ograniczeniami mogą jednak sprawić, że `sudo`, `su`, `newrole` i `runcon` staną się znacznie ciekawsze, ponieważ **ścieżka eskalacji może zależeć od przejścia do lepszej roli/typu SELinux, a nie tylko od uzyskania UID 0**. Pamiętaj też, że niektórzy użytkownicy objęci ograniczeniami nie mogą w ogóle wywoływać `sudo`/`su`, chyba że polityka jawnie zezwala na bazowe przejście setuid. Oznacza to, że na hoście używającym `staff_u` + `sysadm_r` pozornie nieistotna reguła `sudo ROLE=` / `TYPE=` może wyznaczać rzeczywistą granicę uprawnień.<sup>[[3]](#references)</sup>

## SELinux w kontenerach

Środowiska uruchomieniowe kontenerów często uruchamiają obciążenia w ograniczonej domenie, takiej jak `container_t`, i oznaczają zawartość kontenera etykietą `container_file_t`. Jeśli proces w kontenerze ucieknie, ale nadal działa z etykietą kontenera, zapisy na hoście mogą nadal się nie powieść, ponieważ granica wyznaczona przez etykietę pozostała nienaruszona.<sup>[[1]](#references)[[17]](#references)</sup>

Szybki przykład:<sup>[[16]](#references)[[18]](#references)</sup>

```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```

Część `c647,c780` nie jest ozdobnikiem. W wielu wdrożeniach kontenerów środowiska uruchomieniowe dynamicznie przypisują kategorie MCS, dzięki czemu dwa procesy działające jako `container_t` są nadal od siebie odseparowane. Jeśli ucieczka przeniesie Cię do przestrzeni nazw hosta, ale zachowa pierwotny zestaw kategorii, niezgodności kategorii mogą nadal wyjaśniać, dlaczego niektóre ścieżki hosta pozostają nieczytelne lub niezapisywalne.<sup>[[17]](#references)</sup>

Warto zwrócić uwagę na następujące współczesne operacje na kontenerach:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` wyłącza separację kontenerów za pomocą etykiet SELinux
- montowania bind z `:z` / `:Z` powodują ponowne etykietowanie ścieżki hosta na potrzeby współdzielonego/prywatnego użycia przez kontener
- szeroko zakrojone ponowne etykietowanie zawartości hosta może samo w sobie stać się problemem bezpieczeństwa

Ta strona zawiera tylko krótki opis kontenerów, aby uniknąć powielania treści. Przypadki nadużyć i przykłady środowisk uruchomieniowych dotyczące kontenerów znajdziesz tutaj:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}



## References

- [1] [Dokumentacja Red Hat: Korzystanie z SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Narzędzia do analizy polityk SELinux](https://github.com/SELinuxProject/setools)
- [3] [Zarządzanie użytkownikami ograniczonymi i nieograniczonymi — dokumentacja RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) — strona podręcznika systemu Linux](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) — strona podręcznika systemu Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) — strona podręcznika systemu Linux](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) — strona podręcznika systemu Linux](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) — strona podręcznika systemu Linux](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) — strona podręcznika systemu Linux](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) — strona podręcznika systemu Linux](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) — strona podręcznika systemu Linux](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) — strona podręcznika systemu Linux](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) — strona podręcznika systemu Linux](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) — strona podręcznika systemu Linux](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) — strona podręcznika systemu Linux](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Dokumentacja polecenia Podman run](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [Dlaczego warto stosować Multi-Category Security w kontenerach Linux](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Dokumentacja polecenia Podman top](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) — strona podręcznika systemu Linux](https://man7.org/linux/man-pages/man8/selinux.8.html)
- [20] [Notatnik SELinux: przejścia domen i obiektów](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/domain_object_transitions.md)
- [21] [Red Hat Enterprise Linux 10: Korzystanie z SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html-single/using_selinux/using_selinux)
- [22] [Podręcznik SETools sesearch(1)](https://manpages.debian.org/testing/setools/sesearch.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
