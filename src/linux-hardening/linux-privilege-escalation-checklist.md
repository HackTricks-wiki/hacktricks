# Lista kontrolna - Linux Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Najlepsze narzędzie do wyszukiwania lokalnych wektorów eskalacji uprawnień w Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informacje o systemie](privilege-escalation/index.html#system-information)

- [ ] Uzyskaj **informacje o OS**
- [ ] Sprawdź [**PATH**](privilege-escalation/index.html#path), czy jest jakiś **folder z prawem zapisu**?
- [ ] Sprawdź [**zmienne env**](privilege-escalation/index.html#env-info), czy zawierają poufne informacje?
- [ ] Wyszukaj [**eksploity jądra**](privilege-escalation/index.html#kernel-exploits) **używając skryptów** (DirtyCow?)
- [ ] **Sprawdź**, czy [**wersja sudo** jest podatna](privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** signature verification failed](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Dalsza enumeracja systemu ([date, system stats, cpu info, printers](privilege-escalation/index.html#more-system-enumeration))
- [ ] [Wykryj dodatkowe mechanizmy obronne](privilege-escalation/index.html#enumerate-possible-defenses)

### [Dyski](privilege-escalation/index.html#drives)

- [ ] **Wyświetl zamontowane** dyski
- [ ] **Jakiś odmontowany dysk?**
- [ ] **Jakieś poświadczenia w fstab?**

### [**Zainstalowane oprogramowanie**](privilege-escalation/index.html#installed-software)

- [ ] **Sprawdź**, czy jest zainstalowane [**przydatne oprogramowanie**](privilege-escalation/index.html#useful-software)
- [ ] **Sprawdź**, czy jest zainstalowane [**podatne oprogramowanie**](privilege-escalation/index.html#vulnerable-software-installed)

### [Procesy](privilege-escalation/index.html#processes)

- [ ] Czy jakieś **nieznane oprogramowanie działa**?
- [ ] Czy jakieś oprogramowanie działa z **większymi uprawnieniami niż powinno**?
- [ ] Szukaj **eksploitów uruchomionych procesów** (zwłaszcza dla uruchomionej wersji).
- [ ] Czy możesz **zmodyfikować binarkę** jakiegokolwiek uruchomionego procesu?
- [ ] **Monitoruj procesy** i sprawdź, czy jakiś interesujący proces uruchamia się często.
- [ ] Czy możesz **odczytać pamięć procesu** (gdzie mogą być zapisane hasła)?

### [Zadania cykliczne/Cron?](privilege-escalation/index.html#scheduled-jobs)

- [ ] Czy [**PATH** ](privilege-escalation/index.html#cron-path) jest modyfikowany przez jakiś cron i możesz w nim **zapisać**?
- [ ] Jakiś [**wildcard** ](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) w zadaniu cron?
- [ ] Jakiś [**modyfikowalny skrypt** ](privilege-escalation/index.html#cron-script-overwriting-and-symlink) jest **wykonywany** lub znajduje się w **modyfikowalnym folderze**?
- [ ] Czy wykryłeś, że jakiś **skrypt** może być lub jest [**wykonywany** bardzo **często**](privilege-escalation/index.html#frequent-cron-jobs)? (co 1, 2 lub 5 minut)

### [Usługi](privilege-escalation/index.html#services)

- [ ] Jakiś **pliku .service z prawem zapisu**?
- [ ] Jakiś **binarny plik wykonywany przez usługę z prawem zapisu**?
- [ ] Jakiś **modyfikowalny folder w systemd PATH**?
- [ ] Jakiś **wpis drop-in systemd** w `/etc/systemd/system/<unit>.d/*.conf` który może nadpisać `ExecStart`/`User`?

### [Timery](privilege-escalation/index.html#timers)

- [ ] Jakiś **timer z prawem zapisu**?

### [Gniazda (Sockets)](privilege-escalation/index.html#sockets)

- [ ] Jakiś **plik .socket z prawem zapisu**?
- [ ] Możesz **komunikować się z jakimkolwiek socketem**?
- [ ] **HTTP sockets** z interesującymi informacjami?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] Możesz **komunikować się z jakimkolwiek D-Bus**?

### [Sieć](privilege-escalation/index.html#network)

- [ ] Enumeruj sieć, aby wiedzieć, gdzie jesteś
- [ ] **Otwarte porty, do których nie miałeś dostępu przed** uzyskaniem shella na maszynie?
- [ ] Czy możesz **podsłuchiwać ruch** używając `tcpdump`?

### [Użytkownicy](privilege-escalation/index.html#users)

- [ ] Ogólna enumeracja użytkowników/grup
- [ ] Czy masz **bardzo duże UID**? Czy **maszyna** jest **podatna**?
- [ ] Czy możesz [**eskalować uprawnienia dzięki grupie**](privilege-escalation/interesting-groups-linux-pe/index.html), do której należysz?
- [ ] Dane ze **schowka (Clipboard)**?
- [ ] Polityka haseł?
- [ ] Spróbuj **użyć** każdego **znanego hasła**, które odkryłeś wcześniej, aby zalogować się **każdym** możliwym **użytkownikiem**. Spróbuj także zalogować się bez hasła.

### [Zapisywalny PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] Jeśli masz **prawo zapisu do jakiegoś folderu w PATH** możesz być w stanie eskalować uprawnienia

### [SUDO i polecenia SUID](privilege-escalation/index.html#sudo-and-suid)

- [ ] Czy możesz wykonać **jakieś polecenie przez sudo**? Czy możesz go użyć do ODCZYTU, ZAPISU lub WYKONANIA czegokolwiek jako root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Jeśli `sudo -l` pozwala na `sudoedit`, sprawdź podatność na **sudoedit argument injection** (CVE-2023-22809) przez `SUDO_EDITOR`/`VISUAL`/`EDITOR` aby edytować dowolne pliki na podatnych wersjach (`sudo -V` < 1.9.12p2). Przykład: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Czy jest jakiś **eksploatowalny binarny plik SUID**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Czy [**polecenia sudo są ograniczone przez path? czy możesz obejść ograniczenia**](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Polecenie Sudo/SUID bez wskazanej ścieżki**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary ze wskazaną ścieżką**](privilege-escalation/index.html#suid-binary-with-command-path)? Obejście
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/index.html#ld_preload)
- [ ] [**Brak biblioteki .so w binarce SUID**](privilege-escalation/index.html#suid-binary-so-injection) z folderu z prawem zapisu?
- [ ] [**Dostępne tokeny SUDO**](privilege-escalation/index.html#reusing-sudo-tokens)? [**Czy możesz utworzyć token SUDO**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Czy możesz [**odczytać lub zmodyfikować pliki sudoers**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Czy możesz [**zmodyfikować /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) command

### [Capabilities](privilege-escalation/index.html#capabilities)

- [ ] Czy jakiś binarny plik ma **nieoczekiwaną capability**?

### [ACLs](privilege-escalation/index.html#acls)

- [ ] Czy jakiś plik ma **nieoczekiwany ACL**?

### [Otwarte sesje shell](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Interesujące wartości konfiguracji SSH**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesujące pliki](privilege-escalation/index.html#interesting-files)

- [ ] **Pliki profilu** - Odczyt poufnych danych? Zapis do privesc?
- [ ] **passwd/shadow** - Odczyt poufnych danych? Zapis do privesc?
- [ ] **Sprawdź powszechnie interesujące foldery** pod kątem poufnych danych
- [ ] **Dziwne lokalizacje/własność plików,** możesz mieć dostęp do lub modyfikować pliki wykonywalne
- [ ] **Zmodyfikowane** w ostatnich minutach
- [ ] **Pliki Sqlite DB**
- [ ] **Ukryte pliki**
- [ ] **Skrypty/Binarki w PATH**
- [ ] **Pliki webowe** (hasła?)
- [ ] **Kopie zapasowe**?
- [ ] **Znane pliki zawierające hasła**: użyj **Linpeas** i **LaZagne**
- [ ] **Ogólne przeszukiwanie**

### [**Pliki z prawem zapisu**](privilege-escalation/index.html#writable-files)

- [ ] **Zmodyfikować bibliotekę python** aby wykonać dowolne polecenia?
- [ ] Czy możesz **modyfikować pliki logów**? exploit Logrotten
- [ ] Czy możesz **modyfikować /etc/sysconfig/network-scripts/**? exploit Centos/Redhat
- [ ] Czy możesz [**zapisać w ini, init.d, systemd lub rc.d plikach**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Inne triki**](privilege-escalation/index.html#other-tricks)

- [ ] Czy możesz [**nadużyć NFS do eskalacji uprawnień**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Czy musisz [**uciec z restrykcyjnej powłoki**](privilege-escalation/index.html#escaping-from-restricted-shells)?



## Referencje

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../banners/hacktricks-training.md}}
