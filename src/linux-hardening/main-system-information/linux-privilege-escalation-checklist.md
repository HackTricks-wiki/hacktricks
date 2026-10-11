# Lista kontrolna eskalacji uprawnień w systemie Linux

{{#include ../../banners/hacktricks-training.md}}

# Lista kontrolna — eskalacja uprawnień w systemie Linux



### **Najlepsze narzędzie do wyszukiwania lokalnych wektorów eskalacji uprawnień w systemie Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informacje o systemie](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Zbierz **informacje o systemie operacyjnym**
- [ ] Sprawdź [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path) — czy któryś **katalog jest zapisywalny**?
- [ ] Sprawdź [**zmienne środowiskowe**](../linux-basics/linux-privilege-escalation/index.html#env-info) — czy zawierają wrażliwe dane?
- [ ] **Za pomocą skryptów** wyszukaj [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) (DirtyCow?)
- [ ] Przed uruchomieniem kernel PoC zweryfikuj jego **rzeczywiste wymagania**, a nie tylko `uname -r`: architekturę, wymagane opcje/moduły `CONFIG_*`, możliwość tworzenia namespace’ów i aktywne zabezpieczenia. Dostępność user/network namespace możesz sprawdzić poleceniem `unshare -Urn true`; współczesne exploity netfilter mogą wymagać `CONFIG_USER_NS`, nieuprzywilejowanych user namespace i `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Sprawdź**, czy [**wersja sudo jest podatna**](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Weryfikacja podpisu Dmesg nie powiodła się**](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Sprawdź [**błędną konfigurację modułów jądra i ich ładowania**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, wymuszanie podpisów i `modules_disabled`.
- [ ] Sprawdź [**ścieżki nadużyć kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks), jeśli ścieżkę helpera można zmodyfikować lub wywołać.
- [ ] Sprawdź [**zapisywalne ścieżki /lib/modules**](kernel-modules-and-modprobe.md#writable-libmodules-review), w tym zapisywalne pliki `.ko*` i metadane `modules.*`.
- [ ] Sprawdź pozostałe informacje o systemie ([datę, statystyki systemu, informacje o CPU, drukarki](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Sprawdź więcej mechanizmów ochronnych](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Dyski](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Wyświetl zamontowane** dyski
- [ ] Czy są **niezamontowane dyski**?
- [ ] Czy w pliku fstab są **dane uwierzytelniające**?

### [**Zainstalowane oprogramowanie**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Sprawdź, czy zainstalowano** [**przydatne oprogramowanie**](../linux-basics/linux-privilege-escalation/index.html#useful-software)
- [ ] **Sprawdź, czy zainstalowano** [**podatne oprogramowanie**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed)
- [ ] W Debianie/Ubuntu sprawdź, czy zainstalowano/włączono **skanowanie interpreterów needrestart**: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Podatne wersje przekraczały granicę uprawnień, ponownie wykorzystując kontrolowane przez atakującego zmienne `PYTHONPATH`/`RUBYLIB`, ścigając się z `/proc/<pid>/exe` lub skanując kontrolowane przez atakującego ścieżki Perla, gdy APT lub `unattended-upgrades` uruchamiały needrestart jako root.<sup>[[4]](#references)</sup>

### [Procesy](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Czy działa jakieś **nieznane oprogramowanie**?
- [ ] Czy jakieś oprogramowanie działa z **większymi uprawnieniami, niż powinno**?
- [ ] Poszukaj **exploitów dla działających procesów** (zwłaszcza dla używanej wersji).
- [ ] Czy możesz **zmodyfikować plik binarny** któregoś działającego procesu?
- [ ] **Monitoruj procesy** i sprawdź, czy jakiś interesujący proces regularnie się uruchamia.
- [ ] Czy możesz **odczytać pamięć** interesującego **procesu** (mogą być w niej zapisane hasła)?

### [Zaplanowane zadania/Cron?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] Czy jakiś cron modyfikuje [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)i możesz w nim **zapisywać**?
- [ ] Czy zadanie cron zawiera [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)?
- [ ] Czy jest **uruchamiany** jakiś [**modyfikowalny skrypt** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)lub znajduje się on w **modyfikowalnym katalogu**?
- [ ] Czy udało Ci się wykryć, że jakiś **skrypt może być lub jest [**uruchamiany** bardzo **często**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs) (co 1, 2 lub 5 minut)?

### [Usługi](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Czy jest jakiś **zapisywalny plik .service**?
- [ ] Czy usługa uruchamia jakiś **zapisywalny plik binarny**?
- [ ] Czy któryś helper, plik konfiguracyjny lub środowiskowy wskazywany przez jednostkę root jest zapisywalny (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Sprawdź połączoną konfigurację jednostki poleceniem `systemctl cat <unit>` i przejrzyj [nadużycia plików service/socket](../interesting-files-permissions/write-to-root.md).
- [ ] Czy uruchamiany na żądanie uprzywilejowany przepływ pracy wykonuje helpera z katalogu o niższych uprawnieniach, do którego można zapisywać? Sprawdź zarówno helpera, jak i jego katalog nadrzędny pod kątem [uruchamiania przez root ścieżek modyfikowalnych przez użytkownika](../interesting-files-permissions/write-to-root.md#root-executing-user-writable-scriptsbinaries); krótkotrwałe help​​ery mogą być widoczne tylko podczas działania przepływu pracy.
- [ ] Czy w PATH systemd jest jakiś **zapisywalny katalog**?
- [ ] Czy w `/etc/systemd/system/<unit>.d/*.conf` jest jakiś **zapisywalny plik drop-in systemd**, który może nadpisać `ExecStart`/`User`?<sup>[[2]](#references)</sup>

### [Timery](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Czy jest jakiś **zapisywalny timer**?

### [Sockety](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Czy jest jakiś **zapisywalny plik .socket**?
- [ ] Czy możesz **komunikować się z jakimś socketem**?
- [ ] Czy **sockety HTTP** zawierają interesujące informacje?
- [ ] Czy masz dostęp do [**API środowiska uruchomieniowego kontenerów lub agenta węzła**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md), takiego jak `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` lub endpointu kubelet? Przetestuj surowe API HTTP/gRPC, nawet jeśli zwykle używane CLI nie jest dostępne.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Czy możesz **komunikować się z jakimś D-Bus**?

### [Sieć](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Rozpoznaj sieć, aby ustalić, gdzie się znajdujesz
- [ ] Czy są **otwarte porty, do których nie było dostępu przed** uzyskaniem powłoki na maszynie?
- [ ] Czy możesz **nasłuchiwać ruchu** za pomocą `tcpdump`?

### [Użytkownicy](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Ogólna **enumeracja użytkowników/grup**
- [ ] Czy masz **bardzo duży UID**? Czy **maszyna** jest **podatna**?
- [ ] Czy możesz [**eskalować uprawnienia dzięki grupie**](../user-information/interesting-groups-linux-pe/index.html), do której należysz?
- [ ] Dane ze **schowka**?
- [ ] Zasady haseł?
- [ ] Spróbuj **użyć** każdego **znanego hasła**, które wcześniej udało Ci się znaleźć, aby zalogować się jako każdy możliwy **użytkownik**. Spróbuj też zalogować się bez hasła.

### [Zapisywalny PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Jeśli masz **uprawnienia do zapisu w którymś katalogu z PATH**, możesz być w stanie eskalować uprawnienia

### [Polecenia SUDO i SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Czy możesz wykonać **jakieś polecenie przez sudo**? Czy możesz użyć go, aby CZYTAĆ, ZAPISYWAĆ lub WYKONYWAĆ cokolwiek jako root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Jeśli `sudo -l` zezwala na `sudoedit`, sprawdź **wstrzyknięcie argumentów sudoedit** (CVE-2023-22809) za pomocą `SUDO_EDITOR`/`VISUAL`/`EDITOR`, aby edytować dowolne pliki w podatnych wersjach (`sudo -V` < 1.9.12p2). Przykład: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] Czy jest jakiś **podatny plik binarny SUID**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Czy polecenia [**sudo** są **ograniczone** przez **ścieżkę**? Czy możesz **ominąć** te ograniczenia](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Plik binarny sudo/SUID bez podanej ścieżki**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**Plik binarny SUID z podaną ścieżką**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Omiń ograniczenie
- [ ] [**Podatność LD_PRELOAD**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] Czy w zapisywalnym katalogu brakuje biblioteki `.so` [**używanej przez plik binarny SUID**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection)?
- [ ] [**SUID RPATH/RUNPATH lub zapisywalna ścieżka biblioteki**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] Czy są dostępne [**tokeny SUDO**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Czy możesz utworzyć token SUDO**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Czy możesz [**odczytać lub zmodyfikować pliki sudoers**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Czy możesz [**zmodyfikować /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] Polecenie [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Czy jakiś plik binarny ma **nieoczekiwaną capability**?

### [ACL](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Czy jakiś plik ma **nieoczekiwaną ACL**?

### [Otwarte sesje powłoki](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**Przewidywalny PRNG w OpenSSL — CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Interesujące wartości konfiguracji SSH**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesujące pliki](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Pliki profilu** — Czy można odczytać wrażliwe dane? Zapisać dane w celu eskalacji uprawnień?
- [ ] **Pliki passwd/shadow** — Czy można odczytać wrażliwe dane? Zapisać dane w celu eskalacji uprawnień?
- [ ] **Sprawdź często interesujące katalogi** pod kątem wrażliwych danych
- [ ] **Pliki w nietypowej lokalizacji lub należące do innych użytkowników** — możesz mieć do nich dostęp lub możliwość modyfikacji plików wykonywalnych
- [ ] **Zmodyfikowane** w ciągu ostatnich minut
- [ ] **Pliki baz danych Sqlite**
- [ ] **Ukryte pliki**
- [ ] **Skrypty/pliki binarne w PATH**
- [ ] **Pliki webowe** (hasła?)
- [ ] **Kopie zapasowe**?
- [ ] **Znane pliki zawierające hasła**: użyj **Linpeas** i **LaZagne**
- [ ] **Ogólne wyszukiwanie**

### [**Zapisywalne pliki**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] Czy możesz **zmodyfikować bibliotekę Pythona**, aby wykonywać dowolne polecenia?
- [ ] Czy możesz **modyfikować pliki dziennika**? Exploit **Logtotten**
- [ ] Czy możesz **zmodyfikować /etc/sysconfig/network-scripts/**? Exploit Centos/Redhat
- [ ] Czy możesz [**zapisywać w plikach ini, int.d, systemd lub rc.d**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Inne sztuczki**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Czy możesz [**nadużyć NFS, aby eskalować uprawnienia**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Czy musisz [**uciec z ograniczonej powłoki**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [1] [Informacja o bezpieczeństwie Sudo: sudoedit umożliwia edycję dowolnych plików](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Dokumentacja Oracle Linux: konfiguracja drop-in systemd](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: wymagania exploita CVE-2024-1086 i badania](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Informacja o bezpieczeństwie Qualys: LPE w needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}
