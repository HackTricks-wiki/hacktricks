# Lista kontrolna - Eskalacja uprawnień w systemie Linux

{{#include ../banners/hacktricks-training.md}}

### **Najlepsze narzędzie do wyszukiwania wektorów lokalnej eskalacji uprawnień w systemie Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informacje o systemie](privilege-escalation/index.html#system-information)

- [ ] Uzyskaj **informacje o systemie operacyjnym**
- [ ] Sprawdź [**ŚCIEŻKĘ**](privilege-escalation/index.html#path), czy jest jakaś **zapisywalna folder**?
- [ ] Sprawdź [**zmienne środowiskowe**](privilege-escalation/index.html#env-info), czy są jakieś wrażliwe dane?
- [ ] Szukaj [**eksploitów jądra**](privilege-escalation/index.html#kernel-exploits) **używając skryptów** (DirtyCow?)
- [ ] **Sprawdź**, czy [**wersja sudo** jest podatna](privilege-escalation/index.html#sudo-version)
- [ ] [**Weryfikacja podpisu Dmesg** nie powiodła się](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Więcej enumeracji systemu ([data, statystyki systemu, informacje o CPU, drukarki](privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumeruj więcej zabezpieczeń](privilege-escalation/index.html#enumerate-possible-defenses)

### [Dyski](privilege-escalation/index.html#drives)

- [ ] **Wypisz zamontowane** dyski
- [ ] **Czy jest jakiś niezmontowany dysk?**
- [ ] **Czy są jakieś dane uwierzytelniające w fstab?**

### [**Zainstalowane oprogramowanie**](privilege-escalation/index.html#installed-software)

- [ ] **Sprawdź** [**przydatne oprogramowanie**](privilege-escalation/index.html#useful-software) **zainstalowane**
- [ ] **Sprawdź** [**podatne oprogramowanie**](privilege-escalation/index.html#vulnerable-software-installed) **zainstalowane**

### [Procesy](privilege-escalation/index.html#processes)

- [ ] Czy jakieś **nieznane oprogramowanie działa**?
- [ ] Czy jakieś oprogramowanie działa z **większymi uprawnieniami niż powinno**?
- [ ] Szukaj **eksploitów działających procesów** (szczególnie wersji działającej).
- [ ] Czy możesz **zmodyfikować binarny plik** jakiegoś działającego procesu?
- [ ] **Monitoruj procesy** i sprawdź, czy jakiś interesujący proces działa często.
- [ ] Czy możesz **odczytać** jakąś interesującą **pamięć procesu** (gdzie mogą być zapisane hasła)?

### [Zadania zaplanowane/Cron?](privilege-escalation/index.html#scheduled-jobs)

- [ ] Czy [**ŚCIEŻKA**](privilege-escalation/index.html#cron-path) jest modyfikowana przez jakiś cron i możesz w niej **zapisywać**?
- [ ] Jakieś [**znaki wieloznaczne**](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) w zadaniu cron?
- [ ] Jakiś [**modyfikowalny skrypt**](privilege-escalation/index.html#cron-script-overwriting-and-symlink) jest **wykonywany** lub znajduje się w **modyfikowalnym folderze**?
- [ ] Czy wykryłeś, że jakiś **skrypt** może być lub jest [**wykonywany** bardzo **często**](privilege-escalation/index.html#frequent-cron-jobs)? (co 1, 2 lub 5 minut)

### [Usługi](privilege-escalation/index.html#services)

- [ ] Jakikolwiek **zapisywalny plik .service**?
- [ ] Jakikolwiek **zapisywalny plik binarny** wykonywany przez **usługę**?
- [ ] Jakikolwiek **zapisywalny folder w PATH systemd**?

### [Timery](privilege-escalation/index.html#timers)

- [ ] Jakikolwiek **zapisywalny timer**?

### [Gniazda](privilege-escalation/index.html#sockets)

- [ ] Jakikolwiek **zapisywalny plik .socket**?
- [ ] Czy możesz **komunikować się z jakimkolwiek gniazdem**?
- [ ] **Gniazda HTTP** z interesującymi informacjami?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] Czy możesz **komunikować się z jakimkolwiek D-Bus**?

### [Sieć](privilege-escalation/index.html#network)

- [ ] Zenumeruj sieć, aby wiedzieć, gdzie jesteś
- [ ] **Otwarte porty, do których nie mogłeś uzyskać dostępu przed** uzyskaniem powłoki wewnątrz maszyny?
- [ ] Czy możesz **przechwytywać ruch** używając `tcpdump`?

### [Użytkownicy](privilege-escalation/index.html#users)

- [ ] Ogólna **enumeracja użytkowników/grup**
- [ ] Czy masz **bardzo duży UID**? Czy **maszyna** jest **podatna**?
- [ ] Czy możesz [**eskalować uprawnienia dzięki grupie**](privilege-escalation/interesting-groups-linux-pe/), do której należysz?
- [ ] **Dane z schowka**?
- [ ] Polityka haseł?
- [ ] Spróbuj **użyć** każdego **znanego hasła**, które odkryłeś wcześniej, aby zalogować się **z każdym** możliwym **użytkownikiem**. Spróbuj również zalogować się bez hasła.

### [Zapisywalna ŚCIEŻKA](privilege-escalation/index.html#writable-path-abuses)

- [ ] Jeśli masz **uprawnienia do zapisu w jakimś folderze w PATH**, możesz być w stanie eskalować uprawnienia

### [Polecenia SUDO i SUID](privilege-escalation/index.html#sudo-and-suid)

- [ ] Czy możesz wykonać **jakiekolwiek polecenie z sudo**? Czy możesz użyć go do ODCZYTU, ZAPISU lub WYKONANIA czegokolwiek jako root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Czy jakiś **eksploatowalny plik binarny SUID**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Czy [**polecenia sudo** są **ograniczone** przez **ścieżkę**? czy możesz **obejść** te ograniczenia](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binarny bez wskazanej ścieżki**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binarny z określoną ścieżką**](privilege-escalation/index.html#suid-binary-with-command-path)? Obejście
- [ ] [**Vuln LD_PRELOAD**](privilege-escalation/index.html#ld_preload)
- [ ] [**Brak biblioteki .so w binarnym SUID**](privilege-escalation/index.html#suid-binary-so-injection) z zapisywalnego folderu?
- [ ] [**Dostępne tokeny SUDO**](privilege-escalation/index.html#reusing-sudo-tokens)? [**Czy możesz stworzyć token SUDO**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Czy możesz [**czytać lub modyfikować pliki sudoers**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Czy możesz [**zmodyfikować /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) polecenie

### [Uprawnienia](privilege-escalation/index.html#capabilities)

- [ ] Czy jakaś binarka ma jakąś **nieoczekiwaną zdolność**?

### [ACL](privilege-escalation/index.html#acls)

- [ ] Czy jakiś plik ma jakąś **nieoczekiwaną ACL**?

### [Otwarte sesje powłoki](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Przewidywalny PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Interesujące wartości konfiguracyjne SSH**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesujące pliki](privilege-escalation/index.html#interesting-files)

- [ ] **Pliki profilu** - Odczytaj wrażliwe dane? Zapisz do privesc?
- [ ] **Pliki passwd/shadow** - Odczytaj wrażliwe dane? Zapisz do privesc?
- [ ] **Sprawdź powszechnie interesujące foldery** pod kątem wrażliwych danych
- [ ] **Dziwne lokalizacje/Pliki własnościowe**, do których możesz mieć dostęp lub zmieniać pliki wykonywalne
- [ ] **Zmodyfikowane** w ostatnich minutach
- [ ] **Pliki bazy danych Sqlite**
- [ ] **Ukryte pliki**
- [ ] **Skrypty/Binarki w PATH**
- [ ] **Pliki webowe** (hasła?)
- [ ] **Kopie zapasowe**?
- [ ] **Znane pliki, które zawierają hasła**: Użyj **Linpeas** i **LaZagne**
- [ ] **Ogólne wyszukiwanie**

### [**Zapisywalne pliki**](privilege-escalation/index.html#writable-files)

- [ ] **Modyfikuj bibliotekę Pythona** w celu wykonania dowolnych poleceń?
- [ ] Czy możesz **modyfikować pliki dziennika**? **Eksploit Logtotten**
- [ ] Czy możesz **modyfikować /etc/sysconfig/network-scripts/**? Eksploit Centos/Redhat
- [ ] Czy możesz [**zapisywać w plikach ini, int.d, systemd lub rc.d**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Inne sztuczki**](privilege-escalation/index.html#other-tricks)

- [ ] Czy możesz [**wykorzystać NFS do eskalacji uprawnień**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Czy musisz [**uciec z restrykcyjnej powłoki**](privilege-escalation/index.html#escaping-from-restricted-shells)?

{{#include ../banners/hacktricks-training.md}}
