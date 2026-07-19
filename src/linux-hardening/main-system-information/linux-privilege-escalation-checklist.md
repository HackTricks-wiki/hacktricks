# Lista kontrolna - Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

### **Najlepsze narzędzie do wyszukiwania lokalnych wektorów Linux privilege escalation:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informacje o systemie](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Uzyskaj **informacje o systemie operacyjnym**
- [ ] Sprawdź [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), czy znajduje się w nim **zapisywalny folder**?
- [ ] Sprawdź [**zmienne env**](../linux-basics/linux-privilege-escalation/index.html#env-info), czy zawierają poufne informacje?
- [ ] Wyszukaj [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **za pomocą skryptów** (DirtyCow?)
- [ ] **Sprawdź**, czy [**wersja sudo** jest podatna](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Weryfikacja sygnatury Dmesg nie powiodła się**](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Sprawdź [**błędy konfiguracji modułów kernela i ich ładowania**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, wymuszanie sygnatur i `modules_disabled`.
- [ ] Sprawdź [**ścieżki nadużycia kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks), jeśli ścieżkę helpera można zmodyfikować lub wywołać.
- [ ] Sprawdź [**zapisywalne ścieżki /lib/modules**](kernel-modules-and-modprobe.md#writable-libmodules-review), w tym zapisywalne pliki `.ko*` i metadane `modules.*`.
- [ ] Więcej informacji o systemie ([data, statystyki systemu, informacje o CPU, drukarki](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Sprawdź więcej mechanizmów ochrony](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Dyski](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Wyświetl zamontowane** dyski
- [ ] **Czy są jakieś niezamontowane dyski?**
- [ ] **Czy w fstab znajdują się dane uwierzytelniające?**

### [**Zainstalowane oprogramowanie**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Sprawdź, czy jest zainstalowane** [**przydatne oprogramowanie**](../linux-basics/linux-privilege-escalation/index.html#useful-software)
- [ ] **Sprawdź, czy jest zainstalowane** [**podatne oprogramowanie**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed)

### [Procesy](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Czy działa jakieś **nieznane oprogramowanie**?
- [ ] Czy jakieś oprogramowanie działa z **większymi uprawnieniami, niż powinno**?
- [ ] Wyszukaj **exploity działających procesów** (szczególnie dla uruchomionej wersji).
- [ ] Czy możesz **zmodyfikować plik binarny** dowolnego działającego procesu?
- [ ] **Monitoruj procesy** i sprawdź, czy jakiś interesujący proces działa często.
- [ ] Czy możesz **odczytać** pamięć któregoś interesującego **procesu** (w której mogą być zapisane hasła)?

### [Zadania zaplanowane/Cron?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Czy [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)jest modyfikowany przez jakiś cron i czy możesz w nim **zapisywać**?
- [ ] Czy w zadaniu cron znajduje się [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)?
- [ ] Czy jakiś [**modyfikowalny skrypt** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)jest **wykonywany** lub znajduje się w **modyfikowalnym folderze**?
- [ ] Czy wykryłeś, że jakiś **skrypt** może być lub jest [**wykonywany** bardzo **często**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (co 1, 2 lub 5 minut)

### [Usługi](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Czy istnieje jakiś **zapisywalny plik .service**?
- [ ] Czy istnieje jakiś **zapisywalny plik binarny** wykonywany przez **usługę**?
- [ ] Czy istnieje jakiś **zapisywalny folder w PATH systemd**?
- [ ] Czy istnieje jakiś **zapisywalny drop-in systemd** w `/etc/systemd/system/<unit>.d/*.conf`, który może nadpisać `ExecStart`/`User`?

### [Timery](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Czy istnieje jakiś **zapisywalny timer**?

### [Sockety](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Czy możesz **komunikować się z dowolnym socketem**?
- [ ] Czy istnieje jakiś **zapisywalny plik .socket**?
- [ ] **Sockety HTTP** z interesującymi informacjami?

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Czy możesz **komunikować się z dowolnym D-Bus**?

### [Sieć](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Wykonaj enumerację sieci, aby ustalić, gdzie jesteś
- [ ] **Otwarte porty, do których wcześniej nie mogłeś uzyskać dostępu** przed uzyskaniem shella wewnątrz maszyny?
- [ ] Czy możesz **podsłuchiwać ruch** za pomocą `tcpdump`?

### [Użytkownicy](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Ogólna **enumeracja użytkowników/grup**
- [ ] Czy masz **bardzo duży UID**? Czy **maszyna** jest **podatna**?
- [ ] Czy możesz [**eskalować uprawnienia dzięki grupie**](../user-information/interesting-groups-linux-pe/index.html), do której należysz?
- [ ] Dane ze **schowka**?
- [ ] Polityka haseł?
- [ ] Spróbuj **użyć** każdego **znanego hasła**, które wcześniej odkryłeś, aby zalogować się **każdym** możliwym **użytkownikiem**. Spróbuj również zalogować się bez hasła.

### [Zapisywalny PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Jeśli masz **uprawnienia zapisu do folderu w PATH**, możesz być w stanie eskalować uprawnienia

### [Polecenia SUDO i SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Czy możesz wykonać **dowolne polecenie za pomocą sudo**? Czy możesz użyć go do ODCZYTU, ZAPISU lub WYKONANIA czegokolwiek jako root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Jeśli `sudo -l` zezwala na `sudoedit`, sprawdź **sudoedit argument injection** (CVE-2023-22809) za pomocą `SUDO_EDITOR`/`VISUAL`/`EDITOR`, aby edytować dowolne pliki w podatnych wersjach (`sudo -V` < 1.9.12p2). Przykład: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Czy istnieje jakiś **wykorzystywalny plik binarny SUID**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Czy polecenia [**sudo** są **ograniczone** przez **path**? Czy możesz **obejść ograniczenia**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Plik binarny Sudo/SUID bez wskazanej ścieżki**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**Plik binarny SUID ze wskazaną ścieżką**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Obejście
- [ ] [**Podatność LD_PRELOAD**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Brak biblioteki .so w pliku binarnym SUID**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) z zapisywalnego folderu?
- [ ] [**SUID RPATH/RUNPATH lub zapisywalna ścieżka biblioteki**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**Dostępne tokeny SUDO**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Czy możesz utworzyć token SUDO**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Czy możesz [**odczytać lub zmodyfikować pliki sudoers**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Czy możesz [**zmodyfikować /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] Polecenie [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Czy jakiś plik binarny ma **nieoczekiwane capability**?

### [ACL](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Czy jakiś plik ma **nieoczekiwaną ACL**?

### [Otwarte sesje shell](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**Przewidywalny PRNG OpenSSL - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Interesujące wartości konfiguracji SSH**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesujące pliki](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Pliki profilu** - Odczyt poufnych danych? Zapis w celu privesc?
- [ ] **Pliki passwd/shadow** - Odczyt poufnych danych? Zapis w celu privesc?
- [ ] **Sprawdź często interesujące foldery** pod kątem poufnych danych
- [ ] **Pliki w nietypowych lokalizacjach/należące do użytkownika**, do których możesz mieć dostęp lub które możesz zmodyfikować
- [ ] **Zmodyfikowane** w ciągu ostatnich minut
- [ ] **Pliki baz danych Sqlite**
- [ ] **Ukryte pliki**
- [ ] **Skrypty/pliki binarne w PATH**
- [ ] **Pliki webowe** (hasła?)
- [ ] **Backupy**?
- [ ] **Znane pliki zawierające hasła**: użyj **Linpeas** i **LaZagne**
- [ ] **Ogólne wyszukiwanie**

### [**Zapisywalne pliki**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Zmodyfikować bibliotekę Pythona**, aby wykonywała dowolne polecenia?
- [ ] Czy możesz **modyfikować pliki logów**? Exploit **Logtotten**
- [ ] Czy możesz **modyfikować /etc/sysconfig/network-scripts/**? Exploit Centos/Redhat
- [ ] Czy możesz [**zapisywać w plikach ini, int.d, systemd lub rc.d**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Inne triki**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Czy możesz [**nadużyć NFS w celu eskalacji uprawnień**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Czy musisz [**uciec z restrykcyjnego shella**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## Referencje

- [Poradnik Sudo: sudoedit - edycja dowolnych plików](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Dokumentacja Oracle Linux: konfiguracja drop-in systemd](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}
