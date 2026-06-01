# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux to system **Mandatory Access Control (MAC)** oparty na etykietach. W praktyce oznacza to, że nawet jeśli uprawnienia DAC, grupy lub capabilities Linux wyglądają na wystarczające do wykonania danej akcji, kernel nadal może ją odmówić, ponieważ **source context** nie ma अनुमति do dostępu do **target context** z żądaną klasą/permission.

Kontekst zwykle wygląda tak:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Z perspektywy privesc, `type` (domain dla procesów, type dla obiektów) jest zwykle najważniejszym polem:

- Proces działa w **domain** takiej jak `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Pliki i sockety mają **type** taką jak `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Policy decyduje, czy jedna domain może odczytywać/zapisywać/wykonywać/przechodzić do drugiej

## Fast Enumeration

Jeśli SELinux jest włączony, zrób jego enumerację wcześnie, ponieważ może wyjaśnić, dlaczego popularne ścieżki Linux privesc zawodzą albo dlaczego uprzywilejowany wrapper wokół „nieszkodliwego” narzędzia SELinux jest w rzeczywistości krytyczny:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Useful follow-up checks:
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
Interesting findings:

- `Disabled` lub `Permissive` mode usuwa większość wartości SELinux jako granicy.
- `unconfined_t` zwykle oznacza, że SELinux jest obecny, ale nie ogranicza w istotny sposób tego procesu.
- `default_t`, `file_t` lub oczywiście błędne etykiety na niestandardowych ścieżkach często wskazują na błędne oznaczenie lub niepełne wdrożenie.
- Lokalne nadpisania w `file_contexts.local` mają pierwszeństwo przed domyślnymi ustawieniami policy, więc sprawdzaj je dokładnie.

## Policy Analysis

SELinux jest znacznie łatwiejszy do ataku lub obejścia, gdy potrafisz odpowiedzieć na dwa pytania:

1. **Do czego mój bieżący domain ma dostęp?**
2. **Do jakich domain mogę przejść?**

Najbardziej użyteczne narzędzia do tego to `sepolicy` i **SETools** (`seinfo`, `sesearch`, `sedta`):
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
Jest to szczególnie przydatne, gdy host używa **confined users** zamiast mapować wszystkich do `unconfined_u`. W takim przypadku szukaj:

- mapowań użytkowników przez `semanage login -l`
- dozwolonych ról przez `semanage user -l`
- osiągalnych domen admin, takich jak `sysadm_t`, `secadm_t`, `webadm_t`
- wpisów `sudoers` używających `ROLE=` lub `TYPE=`

Jeśli `sudo -l` zawiera wpisy takie jak te, SELinux jest częścią granicy uprawnień:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Sprawdź też, czy `newrole` jest dostępne:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` i `newrole` nie są automatycznie podatne na exploitację, ale jeśli uprzywilejowany wrapper albo reguła `sudoers` pozwala wybrać lepszy role/type, stają się cennymi primitive do eskalacji.

## Files, Relabeling, and High-Value Misconfigurations

Najważniejsza operacyjna różnica między popularnymi narzędziami SELinux jest następująca:

- `chcon`: tymczasowa zmiana label na określonej ścieżce
- `semanage fcontext`: trwała reguła path-to-label
- `restorecon` / `setfiles`: ponownie zastosuj policy/default label

Ma to duże znaczenie podczas privesc, ponieważ **relabeling to nie tylko kosmetyka**. Może zmienić plik z "blocked by policy" na "readable/executable by a privileged confined service".

Sprawdź lokalne reguły relabel i relabel drift:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Jedna subtelna, ale użyteczna rzecz: zwykłe `restorecon` **nie zawsze całkowicie przywraca podejrzaną etykietę**. Jeśli docelowy typ znajduje się w `customizable_types`, możesz potrzebować `-F`, aby wymusić pełny reset. Z ofensywnej perspektywy wyjaśnia to, dlaczego nietypowe `chcon` czasem może przetrwać pobieżne „już uruchomiliśmy restorecon” sprzątanie.
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Wysokowartościowe komendy do wyszukiwania w `sudo -l`, root wrapperach, skryptach automatyzacji lub file capabilities:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Jeśli pojawi się którakolwiek możliwość MAC, sprawdź też [Linux capabilities page](linux-capabilities.md); `cap_mac_admin` i `cap_mac_override` są nietypowe, ale bezpośrednio istotne, gdy SELinux jest częścią granicy.

Szczególnie interesujące:

- `semanage fcontext`: trwale zmienia, jaką etykietę powinien otrzymać path
- `restorecon` / `setfiles`: ponownie stosuje te zmiany na dużą skalę
- `semodule -i`: ładuje niestandardowy moduł policy
- `semanage permissive -a <domain_t>`: robi jeden domain permissive bez wyłączania całego hosta
- `setsebool -P`: trwale zmienia policy booleans
- `load_policy`: przeładowuje aktywną policy

Często są to **helper primitives**, a nie samodzielne root exploits. Ich wartość polega na tym, że pozwalają:

- ustawić target domain jako permissive
- rozszerzyć dostęp między twoim domain a chronionym type
- ponownie otagować pliki kontrolowane przez attacker, aby uprzywilejowana usługa mogła je odczytać lub wykonać
- osłabić confined service na tyle, że istniejący local bug staje się exploitable

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
Dlatego `audit2allow`, `semodule` i `semanage permissive` powinny być traktowane jako wrażliwe powierzchnie administracyjne podczas post-exploitation. Mogą po cichu zamienić zablokowany chain w działający, bez zmiany klasycznych uprawnień UNIX.

## Ukryte odmowy i ekstrakcja modułów

Bardzo częstą frustracją ofensywną jest chain, który kończy się zwykłym `EACCES`, podczas gdy oczekiwany AVC denial nigdy się nie pojawia. Reguły `dontaudit` mogą ukrywać dokładnie to uprawnienie, którego potrzebujesz. Jeśli możesz uruchomić `semodule` przez `sudo` albo inny uprzywilejowany wrapper, tymczasowe wyłączenie `dontaudit` może zamienić cichy failure w precyzyjną wskazówkę policy:
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
To jest również przydatne do sprawdzania, co lokalni administratorzy już zmienili. Mały własny moduł albo jedna permissive reguła dla jednej domeny często są powodem, dla którego docelowa usługa zachowuje się znacznie bardziej liberalnie, niż sugerowałaby polityka bazowa.

## Wskazówki z audytu

AVC denials często są sygnałem ofensywnym, a nie tylko defensywnym szumem. Mówią ci:

- jaki docelowy obiekt/typ trafiłeś
- jaka permission została odrzucona
- jaki domain obecnie kontrolujesz
- czy mała zmiana policy sprawiłaby, że łańcuch zadziała
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Jeśli lokalny exploit lub próba persistence ciągle kończy się niepowodzeniem z `EACCES` albo dziwnymi błędami „permission denied”, mimo że DAC permissions wyglądają jak dla root, warto sprawdzić SELinux, zanim odrzuci się ten wektor.

## SELinux Users

Istnieją SELinux users oprócz zwykłych Linux users. Każdy Linux user jest mapowany na SELinux user jako część policy, co pozwala systemowi narzucać różne dozwolone roles i domains dla różnych kont.

Quick checks:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Na wielu popularnych systemach użytkownicy są mapowani do `unconfined_u`, co zmniejsza praktyczny wpływ confinement użytkownika. Na jednakowo utwardzonych wdrożeniach confined users mogą sprawić, że `sudo`, `su`, `newrole` i `runcon` staną się znacznie ciekawsze, ponieważ **ścieżka eskalacji może zależeć od wejścia do lepszej SELinux role/type, a nie tylko od stania się UID 0**. Pamiętaj też, że niektórzy confined users nie mogą w ogóle wywołać `sudo`/`su`, chyba że policy jawnie zezwala na bazową setuid transition, więc host używający `staff_u` + `sysadm_r` może zamienić pozornie drobną regułę `sudo ROLE=` / `TYPE=` w rzeczywistą granicę uprawnień.

## SELinux in Containers

Container runtimes zwykle uruchamiają workloads w confined domain, takim jak `container_t`, i oznaczają container content jako `container_file_t`. Jeśli proces kontenera ucieknie, ale nadal działa z container label, zapisy na hoście mogą nadal się nie powieść, ponieważ granica label pozostała nienaruszona.

Quick example:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Część `c647,c780` nie jest ozdobą. W wielu wdrożeniach kontenerów runtimes dynamicznie przypisują kategorie MCS, dzięki czemu dwa procesy uruchomione jako `container_t` są nadal od siebie odseparowane. Jeśli escape przeniesie cię do namespace hosta, ale zachowa oryginalny zestaw kategorii, niezgodność kategorii nadal może wyjaśniać, dlaczego niektóre ścieżki hosta pozostają nieczytelne albo niewritable.

Warto zwrócić uwagę na nowoczesne operacje kontenerowe:

- `--security-opt label=disable` może skutecznie przenieść workload do nieconfined typu związanego z kontenerami, takiego jak `spc_t`
- bind mounts z `:z` / `:Z` uruchamiają relabeling ścieżki hosta do współdzielonego/prywatnego użycia przez kontener
- szeroki relabeling zawartości hosta może sam w sobie stać się problemem bezpieczeństwa

Ta strona celowo pozostawia część dotyczącą kontenerów krótką, aby uniknąć duplikacji. Dla przypadków nadużyć specyficznych dla kontenerów i przykładów runtime sprawdź:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## References

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
- [Managing confined and unconfined users - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
