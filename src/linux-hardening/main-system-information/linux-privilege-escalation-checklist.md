# Lista kontrolna eskalacji uprawnień w Linuxie

{{#include ../../banners/hacktricks-training.md}}

# Lista kontrolna - eskalacja uprawnień w Linuxie



### **Najlepsze narzędzie do wyszukiwania lokalnych wektorów eskalacji uprawnień w Linuxie:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informacje o systemie](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Uzyskaj **informacje o systemie operacyjnym**
- [ ] Sprawdź [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), czy znajduje się w nim jakiś **zapisywalny folder**?
- [ ] Sprawdź [**zmienne środowiskowe**](../linux-basics/linux-privilege-escalation/index.html#env-info), czy zawierają poufne informacje?
- [ ] Wyszukaj [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **za pomocą skryptów** (DirtyCow?)
- [ ] Przed uruchomieniem kernel PoC sprawdź jego **rzeczywiste wymagania**, a nie tylko `uname -r`: architekturę, wymagane opcje/moduły `CONFIG_*`, możliwość tworzenia namespace oraz aktywne mechanizmy ochrony. Na przykład sprawdź dostępność user/network namespace za pomocą `unshare -Urn true`; nowoczesne netfilter exploits mogą wymagać `CONFIG_USER_NS`, nieuprzywilejowanych user namespaces oraz `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Sprawdź**, czy [**wersja sudo** jest podatna](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Weryfikacja sygnatury Dmesg nie powiodła się**](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Przejrzyj [**błędne konfiguracje modułów kernela i ich ładowania**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, wymuszanie sygnatur oraz `modules_disabled`.
- [ ] Sprawdź [**ścieżki nadużyć kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks), jeśli ścieżka helpera może zostać zmodyfikowana lub wywołana.
- [ ] Sprawdź [**zapisywalne ścieżki /lib/modules**](kernel-modules-and-modprobe.md#writable-libmodules-review), w tym zapisywalne pliki `.ko*` oraz metadane `modules.*`.
- [ ] Więcej informacji o systemie ([data, statystyki systemu, informacje o CPU, drukarki](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Wyszukaj więcej mechanizmów ochrony](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Dyski](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Wyświetl zamontowane** dyski
- [ ] **Czy są jakieś niezamontowane dyski?**
- [ ] **Czy w fstab znajdują się jakieś dane uwierzytelniające?**

### [**Zainstalowane oprogramowanie**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Sprawdź, czy zainstalowano** [**przydatne oprogramowanie**](../linux-basics/linux-privilege-escalation/index.html#useful-software)
- [ ] **Sprawdź, czy zainstalowano** [**podatne oprogramowanie**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed)
- [ ] W Debian/Ubuntu sprawdź, czy zainstalowano/włączono **needrestart interpreter scanning**: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Podatne wersje przekraczały granicę uprawnień, ponownie wykorzystując kontrolowane przez atakującego `PYTHONPATH`/`RUBYLIB`, wyścigowo odczytując `/proc/<pid>/exe` lub skanując kontrolowane przez atakującego ścieżki Perl, gdy APT albo `unattended-upgrades` uruchamiały needrestart jako root.<sup>[[4]](#references)</sup>

### [Procesy](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Czy działa jakieś **nieznane oprogramowanie**?
- [ ] Czy jakieś oprogramowanie działa z **większymi uprawnieniami, niż powinno**?
- [ ] Wyszukaj **exploits działających procesów** (szczególnie dla używanej wersji).
- [ ] Czy możesz **zmodyfikować binary** dowolnego działającego procesu?
- [ ] **Monitoruj procesy** i sprawdź, czy jakiś interesujący proces działa często.
- [ ] Czy możesz **odczytać** pamięć któregoś interesującego **procesu** (gdzie mogą być zapisane hasła)?

### [Zaplanowane zadania/Cron?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Czy [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)jest modyfikowany przez jakiś cron i czy możesz go **zapisywać**?
- [ ] Czy w zadaniu cron występuje [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)?
- [ ] Czy jakiś [**modyfikowalny skrypt** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)jest **wykonywany** lub znajduje się w **modyfikowalnym folderze**?
- [ ] Czy wykryłeś, że jakiś **skrypt** może być lub jest [**wykonywany** bardzo **często**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (co 1, 2 lub 5 minut)

### [Usługi](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Czy istnieje jakiś **zapisywalny plik .service**?
- [ ] Czy istnieje jakiś **zapisywalny binary** wykonywany przez **usługę**?
- [ ] Czy istnieje zapisywalny **helper, plik konfiguracyjny lub plik środowiskowy wskazany przez root unit** (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Sprawdź scaloną unit za pomocą `systemctl cat <unit>` i przejrzyj [nadużycia plików service/socket](../interesting-files-permissions/write-to-root.md).
- [ ] Czy w systemd PATH znajduje się jakiś **zapisywalny folder**?
- [ ] Czy istnieje **zapisywalny systemd unit drop-in** w `/etc/systemd/system/<unit>.d/*.conf`, który może nadpisać `ExecStart`/`User`?<sup>[[2]](#references)</sup>

### [Timery](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Czy istnieje jakiś **zapisywalny timer**?

### [Sockety](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Czy istnieje jakiś **zapisywalny plik .socket**?
- [ ] Czy możesz **komunikować się z dowolnym socketem**?
- [ ] Czy istnieją **sockety HTTP** zawierające interesujące informacje?
- [ ] Czy możesz uzyskać dostęp do [**API container-runtime lub node-agent**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md), takiego jak `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` albo endpointu kubelet? Przetestuj surowe API HTTP/gRPC, nawet jeśli jego standardowe CLI nie jest dostępne.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Czy możesz **komunikować się z dowolnym D-Bus**?

### [Sieć](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Przeprowadź enumerację sieci, aby określić, gdzie się znajdujesz
- [ ] **Otwarte porty, do których wcześniej nie miałeś dostępu** po uzyskaniu shella na maszynie?
- [ ] Czy możesz **sniffować ruch** za pomocą `tcpdump`?

### [Użytkownicy](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Ogólna **enumeracja użytkowników/grup**
- [ ] Czy masz **bardzo duży UID**? Czy **maszyna** jest **podatna**?
- [ ] Czy możesz [**eskalować uprawnienia dzięki grupie**](../user-information/interesting-groups-linux-pe/index.html), do której należysz?
- [ ] Dane ze **schowka**?
- [ ] Polityka haseł?
- [ ] Spróbuj **użyć** każdego **znanego hasła**, które wcześniej odkryłeś, aby zalogować się **na każdego** możliwego **użytkownika**. Spróbuj również zalogować się bez hasła.

### [Zapisywalny PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Jeśli masz **uprawnienia zapisu do folderu znajdującego się w PATH**, możesz być w stanie eskalować uprawnienia

### [Polecenia SUDO i SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Czy możesz wykonać **dowolne polecenie za pomocą sudo**? Czy możesz użyć go do ODCZYTU, ZAPISU lub WYKONANIA czegokolwiek jako root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Jeśli `sudo -l` zezwala na `sudoedit`, sprawdź **wstrzykiwanie argumentów sudoedit** (CVE-2023-22809) przez `SUDO_EDITOR`/`VISUAL`/`EDITOR`, aby edytować dowolne pliki w podatnych wersjach (`sudo -V` < 1.9.12p2). Przykład: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`<sup>[[1]](#references)</sup>
- [ ] Czy istnieje jakiś **wykorzystywalny binary SUID**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Czy polecenia [**sudo** są **ograniczone** przez **ścieżkę**? Czy możesz [**ominąć te ograniczenia**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Binary Sudo/SUID bez wskazanej ścieżki**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**Binary SUID ze wskazaną ścieżką**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Omiń
- [ ] [**Podatność LD_PRELOAD**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Brak biblioteki .so w binary SUID**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) w zapisywalnym folderze?
- [ ] [**SUID RPATH/RUNPATH lub zapisywalna ścieżka biblioteki**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**Dostępne tokeny SUDO**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Czy możesz utworzyć token SUDO**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Czy możesz [**odczytać lub zmodyfikować pliki sudoers**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Czy możesz [**zmodyfikować /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] Polecenie [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Czy jakiś binary ma **nieoczekiwaną capability**?

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
- [ ] **Dziwnie zlokalizowane/pliki należące do nietypowych właścicieli**, do których możesz mieć dostęp lub które możesz modyfikować
- [ ] **Zmodyfikowane** w ciągu ostatnich minut
- [ ] **Pliki baz danych Sqlite**
- [ ] **Ukryte pliki**
- [ ] **Skrypty/Binary w PATH**
- [ ] **Pliki webowe** (hasła?)
- [ ] **Backupy**?
- [ ] **Znane pliki zawierające hasła**: Użyj **Linpeas** i **LaZagne**
- [ ] **Wyszukiwanie ogólne**

### [**Zapisywalne pliki**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Zmodyfikować bibliotekę Pythona**, aby wykonywać dowolne polecenia?
- [ ] Czy możesz **modyfikować pliki logów**? Exploit **Logtotten**
- [ ] Czy możesz **modyfikować /etc/sysconfig/network-scripts/**? Exploit Centos/Redhat
- [ ] Czy możesz [**zapisywać w plikach ini, int.d, systemd lub rc.d**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Inne triki**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Czy możesz [**nadużyć NFS w celu eskalacji uprawnień**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Czy musisz [**wydostać się z restrykcyjnego shella**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## Referencje

- [1] [Poradnik Sudo: edycja dowolnych plików przez sudoedit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Dokumentacja Oracle Linux: konfiguracja systemd drop-in](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: wymagania exploita CVE-2024-1086 i badania](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Poradnik bezpieczeństwa Qualys: LPE w needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
