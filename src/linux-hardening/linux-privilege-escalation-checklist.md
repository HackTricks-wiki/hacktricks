# Lista kontrolna - Eskalacja uprawnień w systemie Linux

{{#include ../banners/hacktricks-training.md}}

### **Najlepsze narzędzie do wyszukiwania wektorów lokalnej eskalacji uprawnień w systemie Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informacje o systemie](privilege-escalation/#system-information)

- [ ] Uzyskaj **informacje o systemie operacyjnym**
- [ ] Sprawdź [**ŚCIEŻKĘ**](privilege-escalation/#path), czy jest jakaś **zapisywalna folder**?
- [ ] Sprawdź [**zmienne środowiskowe**](privilege-escalation/#env-info), czy są jakieś wrażliwe dane?
- [ ] Szukaj [**eksploitów jądra**](privilege-escalation/#kernel-exploits) **używając skryptów** (DirtyCow?)
- [ ] **Sprawdź**, czy [**wersja sudo** jest podatna](privilege-escalation/#sudo-version)
- [ ] [**Weryfikacja podpisu Dmesg** nie powiodła się](privilege-escalation/#dmesg-signature-verification-failed)
- [ ] Więcej enumeracji systemu ([data, statystyki systemu, informacje o CPU, drukarki](privilege-escalation/#more-system-enumeration))
- [ ] [**Enumeruj więcej zabezpieczeń**](privilege-escalation/#enumerate-possible-defenses)

### [Dyski](privilege-escalation/#drives)

- [ ] **Lista zamontowanych** dysków
- [ ] **Czy jest jakiś niezmontowany dysk?**
- [ ] **Czy są jakieś dane uwierzytelniające w fstab?**

### [**Zainstalowane oprogramowanie**](privilege-escalation/#installed-software)

- [ ] **Sprawdź** [**przydatne oprogramowanie**](privilege-escalation/#useful-software) **zainstalowane**
- [ ] **Sprawdź** [**podatne oprogramowanie**](privilege-escalation/#vulnerable-software-installed) **zainstalowane**

### [Procesy](privilege-escalation/#processes)

- [ ] Czy jakieś **nieznane oprogramowanie działa**?
- [ ] Czy jakieś oprogramowanie działa z **większymi uprawnieniami niż powinno**?
- [ ] Szukaj **eksploitów działających procesów** (szczególnie wersji działającej).
- [ ] Czy możesz **zmodyfikować binarny** plik jakiegoś działającego procesu?
- [ ] **Monitoruj procesy** i sprawdź, czy jakiś interesujący proces działa często.
- [ ] Czy możesz **odczytać** pamięć **procesu** (gdzie mogą być zapisane hasła)?

### [Zadania zaplanowane/Cron?](privilege-escalation/#scheduled-jobs)

- [ ] Czy [**ŚCIEŻKA**](privilege-escalation/#cron-path) jest modyfikowana przez jakiś cron i możesz w niej **zapisać**?
- [ ] Czy jest jakiś [**znak wieloznaczny**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection) w zadaniu cron?
- [ ] Czy jakiś [**modyfikowalny skrypt**](privilege-escalation/#cron-script-overwriting-and-symlink) jest **wykonywany** lub znajduje się w **modyfikowalnym folderze**?
- [ ] Czy wykryłeś, że jakiś **skrypt** może być lub jest [**wykonywany** bardzo **często**](privilege-escalation/#frequent-cron-jobs)? (co 1, 2 lub 5 minut)

### [Usługi](privilege-escalation/#services)

- [ ] Czy jest jakiś **zapisywalny plik .service**?
- [ ] Czy jest jakiś **zapisywalny plik binarny** wykonywany przez **usługę**?
- [ ] Czy jest jakiś **zapisywalny folder w PATH systemd**?

### [Timery](privilege-escalation/#timers)

- [ ] Czy jest jakiś **zapisywalny timer**?

### [Gniazda](privilege-escalation/#sockets)

- [ ] Czy jest jakiś **zapisywalny plik .socket**?
- [ ] Czy możesz **komunikować się z jakimkolwiek gniazdem**?
- [ ] **Gniazda HTTP** z interesującymi informacjami?

### [D-Bus](privilege-escalation/#d-bus)

- [ ] Czy możesz **komunikować się z jakimkolwiek D-Bus**?

### [Sieć](privilege-escalation/#network)

- [ ] Enumeruj sieć, aby wiedzieć, gdzie jesteś
- [ ] **Otwarte porty, do których nie mogłeś uzyskać dostępu** przed uzyskaniem powłoki wewnątrz maszyny?
- [ ] Czy możesz **przechwytywać ruch** używając `tcpdump`?

### [Użytkownicy](privilege-escalation/#users)

- [ ] Ogólna **enumeracja użytkowników/grup**
- [ ] Czy masz **bardzo duży UID**? Czy **maszyna** jest **podatna**?
- [ ] Czy możesz [**eskalować uprawnienia dzięki grupie**](privilege-escalation/interesting-groups-linux-pe/), do której należysz?
- [ ] **Dane z schowka**?
- [ ] Polityka haseł?
- [ ] Spróbuj **użyć** każdego **znanego hasła**, które odkryłeś wcześniej, aby zalogować się **z każdym** możliwym **użytkownikiem**. Spróbuj również zalogować się bez hasła.

### [Zapisywalna ŚCIEŻKA](privilege-escalation/#writable-path-abuses)

- [ ] Jeśli masz **uprawnienia do zapisu w jakimś folderze w PATH**, możesz być w stanie eskalować uprawnienia

### [Polecenia SUDO i SUID](privilege-escalation/#sudo-and-suid)

- [ ] Czy możesz wykonać **jakiekolwiek polecenie z sudo**? Czy możesz użyć go do ODCZYTU, ZAPISU lub WYKONANIA czegokolwiek jako root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Czy jest jakiś **eksploatowalny plik binarny SUID**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Czy [**polecenia sudo** są **ograniczone** przez **ścieżkę**? czy możesz **obejść** te ograniczenia](privilege-escalation/#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binarny bez wskazanej ścieżki**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binarny z określoną ścieżką**](privilege-escalation/#suid-binary-with-command-path)? Obejście
- [ ] [**Vuln LD_PRELOAD**](privilege-escalation/#ld_preload)
- [ ] [**Brak biblioteki .so w binarnym SUID**](privilege-escalation/#suid-binary-so-injection) z zapisywalnego folderu?
- [ ] [**Dostępne tokeny SUDO**](privilege-escalation/#reusing-sudo-tokens)? [**Czy możesz stworzyć token SUDO**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Czy możesz [**odczytać lub zmodyfikować pliki sudoers**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
- [ ] Czy możesz [**zmodyfikować /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/#doas) polecenie

### [Uprawnienia](privilege-escalation/#capabilities)

- [ ] Czy jakaś binarka ma jakąś **nieoczekiwaną zdolność**?

### [ACL](privilege-escalation/#acls)

- [ ] Czy jakiś plik ma jakąś **nieoczekiwaną ACL**?

### [Otwarte sesje powłoki](privilege-escalation/#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

- [ ] **Debian** [**OpenSSL Przewidywalny PRNG - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Interesujące wartości konfiguracyjne SSH**](privilege-escalation/#ssh-interesting-configuration-values)

### [Interesujące pliki](privilege-escalation/#interesting-files)

- [ ] **Pliki profilu** - Odczytaj wrażliwe dane? Zapisz do privesc?
- [ ] **Pliki passwd/shadow** - Odczytaj wrażliwe dane? Zapisz do privesc?
- [ ] **Sprawdź powszechnie interesujące foldery** pod kątem wrażliwych danych
- [ ] **Dziwne lokalizacje/Pliki własnościowe,** do których możesz mieć dostęp lub zmieniać pliki wykonywalne
- [ ] **Zmodyfikowane** w ostatnich minutach
- [ ] **Pliki bazy danych Sqlite**
- [ ] **Ukryte pliki**
- [ ] **Skrypty/Binarki w PATH**
- [ ] **Pliki webowe** (hasła?)
- [ ] **Kopie zapasowe**?
- [ ] **Znane pliki, które zawierają hasła**: Użyj **Linpeas** i **LaZagne**
- [ ] **Ogólne wyszukiwanie**

### [**Zapisywalne pliki**](privilege-escalation/#writable-files)

- [ ] **Zmodyfikuj bibliotekę Pythona** aby wykonać dowolne polecenia?
- [ ] Czy możesz **zmodyfikować pliki dziennika**? **Eksploit Logtotten**
- [ ] Czy możesz **zmodyfikować /etc/sysconfig/network-scripts/**? Eksploit Centos/Redhat
- [ ] Czy możesz [**zapisać w plikach ini, int.d, systemd lub rc.d**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Inne sztuczki**](privilege-escalation/#other-tricks)

- [ ] Czy możesz [**wykorzystać NFS do eskalacji uprawnień**](privilege-escalation/#nfs-privilege-escalation)?
- [ ] Czy musisz [**uciec z restrykcyjnej powłoki**](privilege-escalation/#escaping-from-restricted-shells)?

{{#include ../banners/hacktricks-training.md}}
