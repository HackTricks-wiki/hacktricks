# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

Jeśli masz plik pcap zawierający komunikację przez USB z klawiatury, takiej jak poniższa:

![USB Keystrokes: If you have a pcap containing the communication via USB of a keyboard like the following one](<../../../images/image (962).png>)

W przypadku klawiatury używającej HID **boot protocol** każdy raport Interrupt IN ma stały układ 8 bajtów: jeden bajt modyfikatorów, jeden bajt zarezerwowany i sześć bajtów kodów klawiszy. Host porównuje kolejne raporty i mapuje kody klawiszy na identyfikatory HID usage, aby odtworzyć zdarzenia klawiszy.<sup>[[8]](#references)</sup>

Ogólne informacje o wstępnej analizie przechwyconych pakietów znajdziesz w [Pcap Inspection](./).

## Podstawy raportów USB HID

Standardowy raport wejściowy klawiatury boot ma następującą strukturę.<sup>[[8]](#references)[[9]](#references)</sup>

| Bajt | Znaczenie |
| --- | --- |
| 0 | Maska bitowa modyfikatorów (`0x02` = lewy Shift, `0x20` = prawy Shift, `0x40` = prawy Alt itd.). Jednocześnie może być ustawionych wiele bitów. |
| 1 | Zarezerwowany bajt; w nieużywanych raportach zwykle powinien mieć wartość zero. Zastosowania OEM lub specyficzne dla systemu nie są przenośne. |
| 2-7 | Do sześciu jednocześnie wciśniętych kodów klawiszy w formacie USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` oznacza „brak klawisza”. | 

W układzie boot usage ID `0x01` (`Keyboard ErrorRollOver`) jest raportowany we wszystkich polach klawiszy, gdy wciśnięto więcej niż sześć klawiszy niebędących modyfikatorami; może też sygnalizować nierozpoznawalną kombinację.<sup>[[8]](#references)[[9]](#references)</sup> Zrozumienie tego układu jest pomocne, gdy masz tylko surowe bajty `usb.capdata`.

## Wyodrębnianie danych HID z pliku PCAP

### Najpierw zidentyfikuj interfejs klawiatury

W przypadku dużych przechwyceń zidentyfikuj klawiaturę HID przed wyodrębnieniem raportów. Dobrym punktem wyjścia jest odpowiedź z deskryptorem interfejsu:<sup>[[3]](#references)[[8]](#references)</sup>

```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```

Klasa HID definiuje następujące wartości interfejsu:<sup>[[8]](#references)</sup>

- `subclass == 1` to Boot Interface Subclass; `protocol == 1` wskazuje klawiaturę boot
- `protocol == 2` wskazuje mysz boot
- `protocol == 0` oznacza brak boot protocol; sprawdź deskryptor raportu HID zamiast zakładać układ 8-bajtowy

Interfejs obsługujący boot **nie jest dowodem, że boot protocol jest aktywny**. Urządzenia HID inicjują pracę w report protocol. Host wybiera boot mode za pomocą `SET_PROTOCOL` (`bRequest = 0x0b`, `wValue = 0`); `wValue = 1` wybiera report protocol. Jeśli przechwycenie obejmuje enumerację, przed użyciem 8-bajtowego dekodera boot sprawdź żądanie dotyczące interfejsu klawiatury (`wIndex`). Jeśli go nie ma, zweryfikuj zaobserwowany układ raportu, zamiast wnioskować o trybie na podstawie deskryptora interfejsu.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usb.setup.bRequest == 0x0b' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address \
  -e usb.setup.wIndex -e usb.setup.wValue
```

Gdy znasz już interfejs, przed wyeksportowaniem czegokolwiek ogranicz filtry do `usb.bus_id`, `usb.device_address` i, jeśli to możliwe, `usb.bInterfaceNumber`.

### Przepływ pracy w Wireshark

1. **Wyodrębnij ruch urządzenia**: filtruj ruch interrupt IN z klawiatury, np. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Dodaj przydatne kolumny**: kliknij prawym przyciskiem pole `Leftover Capture Data` (`usb.capdata`) oraz wybrane pola `usbhid.*` (np. `usbhid.boot_report.keyboard.keycode_1`), aby śledzić naciśnięcia klawiszy bez otwierania każdej ramki.<sup>[[11]](#references)</sup>
3. **Ukryj puste raporty**: zastosuj filtr `!(usb.capdata == 00:00:00:00:00:00:00:00)`, aby odrzucić nieaktywne ramki.
4. **Wyeksportuj dane do dalszego przetwarzania**: wybierz `File -> Export Packet Dissections -> As CSV`, uwzględnij `frame.number`, `usb.src`, `usb.capdata` oraz zdekodowane pola modyfikatorów, takie jak `usbhid.boot_report.keyboard.modifier.left_shift` i `usbhid.boot_report.keyboard.modifier.right_alt`, aby później odtworzyć dane za pomocą skryptu.<sup>[[10]](#references)[[11]](#references)</sup>

### Przepływ pracy z wiersza poleceń

Klasyczny sposób ekstrakcji — zrzucenie `usb.capdata`, odrzucenie nieaktywnych raportów i mapowanie identyfikatorów usage — opisano w oryginalnej analizie z 2017 roku i jej omówieniu krok po kroku.<sup>[[1]](#references)[[2]](#references)</sup>

Repozytorium `ctf-usb-keyboard-parser` automatyzuje klasyczny potok tshark + sed:<sup>[[5]](#references)</sup>

```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```

W przypadku nowszych przechwyceń preferuj zdekodowane pole `usbhid.data` w Wiresharku, a w razie potrzeby użyj `usb.capdata`; zapisuj jeden payload na raport do pliku przypisanego do urządzenia:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
  awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```

Te pliki dla poszczególnych urządzeń można przekazać dekoderowi po normalizacji formatu hex, którego oczekuje. Jeśli przechwycony ruch pochodził z klawiatur BLE tunelowanych przez GATT, filtruj za pomocą `btatt.value && frame.len == 20` i zrzucaj payloady hex przed dekodowaniem.<sup>[[7]](#references)</sup>

### Gdy raport nie jest klasycznym 8-bajtowym raportem boot

Interfejs non-boot lub identyfikator raportu mogą zmienić układ payloadu, więc nie zakładaj, że każdy raport klawiatury ma postać `modifier,reserved,key1..key6`.<sup>[[8]](#references)[[11]](#references)</sup>

- Preferuj `usbhid.data` zamiast `usb.capdata`, jeśli Wireshark przeanalizował już warstwę HID.
- Jeśli każda linia zaczyna się od stałego prefiksu lub identyfikatora raportu, usuń go za pomocą dekodera uwzględniającego offset, zamiast zakładać, że bajt 0 zawsze zawiera modyfikator.<sup>[[7]](#references)</sup>
- Niektóre eksporty USBPcap pomijają bajt zarezerwowany, więc dekodery obsługujące `--no-reserved` lub niestandardowy offset pozwalają zaoszczędzić czas.<sup>[[7]](#references)</sup>
- Jeśli w przechwyconym ruchu znajduje się deskryptor raportu HID lub mapa raportów BLE HOGP, użyj jej, aby odtworzyć rzeczywisty układ pól przed napisaniem parsera.

### Dekodowanie bitmapy klawiszy z protokołu raportów

W przypadku klawiatury, której raport wejściowy jest bitmapą zamiast zawierać sześć slotów klawiszy boot, znajdź jej **deskryptor raportu HID** w ruchu związanym z enumeracją. Ten filtr znajduje ramki, w których Wireshark zdekodował element Report Size; otwórz jedną z nich i sprawdź cały deskryptor. Jeśli brakuje deskryptora, rozpocznij nowe przechwytywanie przed podłączeniem klawiatury.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usbhid.item.global.report_size' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address
```

Dla każdego raportu `Input` klawiatury zanotuj jego `Report ID` (jeśli występuje), `Usage Page` (`0x07` dla klawiszy klawiatury), `Usage Minimum/Maximum`, `Report Size`, `Report Count` oraz informację, czy każdy element `Input` jest typu **Variable**, czy **Array**. Zsumuj wszystkie poprzedzające pola `Input` i bity dopełnienia stałego, aby znaleźć przesunięcie bitowe pola klawiszy; pola raportu nie muszą być wyrównane do bajtów. Jednobitowe pole `Variable` z kolejnymi wartościami usage klawiatury to bitmapa stanu klawiszy: bit 0 tego pola odpowiada pierwszej zadeklarowanej wartości usage, bit 1 — następnej i tak dalej. `Array` zawiera natomiast wartości interpretowane na podstawie zakresu usage deskryptora, a nie osobny bit dla każdego wciśniętego klawisza. Jeśli zadeklarowano `Report ID`, najpierw wybierz raporty z tym prefiksem i pomiń jego bajt podczas obliczania przesunięć pól. Porównuj zbiory wciśniętych wartości usage w kolejnych raportach tego samego interfejsu i `Report ID`, aby wyemitować tylko nowe naciśnięcia.<sup>[[8]](#references)[[12]](#references)[[13]](#references)</sup>

## Automatyzacja dekodowania

- **ctf-usb-keyboard-parser** nadal przydaje się do szybkich wyzwań CTF i jest już dostępny w repozytorium.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) natywnie analizuje pliki `pcap` i `pcapng`, obsługuje `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` i nie wymaga tshark ani innych zewnętrznych zależności, dzięki czemu nadaje się do odizolowanych środowisk.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** udostępnia wizualizatory klawiatury, myszy i tabletu. Możesz uruchomić pomocniczy skrypt `extract_hid_data.sh` (backend tshark) lub `extract_hid_data.py` (backend scapy), a następnie przekazać wynikowy plik tekstowy do dekodera lub modułów odtwarzania, aby obserwować sekwencję naciśnięć klawiszy.<sup>[[7]](#references)</sup>

### Dekodowanie stanowe ma znaczenie

Klawiatury USB działające w trybie boot wysyłają raporty z częstotliwością określoną przez czas bezczynności, nawet gdy nie pojawia się nowe zdarzenie klawisza, więc przechwycone dane mogą zawierać powtarzające się raporty przed zdarzeniem zwolnienia klawisza. Praktyczny dekoder powinien:<sup>[[3]](#references)[[8]](#references)</sup>

- emitować tylko nowe kody klawiszy w porównaniu z poprzednim raportem
- zachowywać stan modyfikatorów (`Shift`, `Ctrl`, `AltGr`) odczytany z bajtu 0 lub przeanalizowanych pól, takich jak `usbhid.boot_report.keyboard.modifier.left_shift` i `usbhid.boot_report.keyboard.modifier.right_alt`
- śledzić klawisze przełączające, takie jak `Caps Lock`, ponieważ wielkie litery nie zależą wyłącznie od `Shift`
- pamiętać, że identyfikatory usage HID nie zależą od układu: `0x1d` odpowiada fizycznemu położeniu klawisza `z` lub `y`, zależnie od układu klawiatury hosta.<sup>[[9]](#references)</sup>

## Szybki dekoder Python

```python
#!/usr/bin/env python3
import sys
NORMAL = {0x04:'a',0x05:'b',0x06:'c',0x07:'d',0x08:'e',0x09:'f',0x0a:'g',0x1c:'y',0x1d:'z',0x28:'\n',0x2d:'-',0x2e:'=',0x2f:'[',0x30:']',0x33:';',0x34:"'",0x36:',',0x37:'.'}
SHIFTED = {0x2d:'_',0x2e:'+',0x2f:'{',0x30:'}',0x33:':',0x34:'"',0x36:'<',0x37:'>'}
prev = set()
caps = False
for raw in sys.stdin:
    raw = raw.strip().replace(':', '')
    if len(raw) != 16:
        continue
    modifier = int(raw[0:2], 16)
    keycodes = [int(raw[i:i+2], 16) for i in range(4, 16, 2)]
    current = {k for k in keycodes if k}
    newly_pressed = [k for k in keycodes if k and k not in prev]
    shift = bool(modifier & 0x22)
    for keycode in newly_pressed:
        if keycode == 0x39:
            caps = not caps
            continue
        char = SHIFTED.get(keycode) if shift else None
        if char is None:
            char = NORMAL.get(keycode, '?')
            if char.isalpha() and (shift ^ caps):
                char = char.upper()
        sys.stdout.write(char)
    prev = current
```

Podaj mu zwykłe linie hex zrzutu wykonane wcześniej, aby uzyskać natychmiastową, przybliżoną rekonstrukcję bez dołączania pełnego parsera do środowiska. W przypadku układów innych niż US nadal rekonstruuje to fizyczne położenie klawisza, niekoniecznie końcowy znak wyświetlony na hoście ofiary.

## Wskazówki dotyczące rozwiązywania problemów

- Jeśli Wireshark nie wypełnia pól `usbhid.*`, prawdopodobnie nie przechwycono deskryptora raportu HID. Odłącz i ponownie podłącz klawiaturę podczas przechwytywania albo użyj surowego `usb.capdata`.
- W przechwyceniach programowych w systemie Linux standardowym źródłem jest `usbmon`; w systemie Windows Wireshark wymaga extcap **USBPcap**, aby w ogóle widzieć surowe URB USB.<sup>[[4]](#references)</sup>
- Jeśli klawiatura była podłączona przez hub lub stację dokującą, najpierw sprawdź deskryptor interfejsu, a następnie dekoduj tylko tę parę urządzenie/interfejs. Przechwycenia złożonych urządzeń HID często mieszają raporty klawiatury i myszy.
- Przechwycenia w systemie Windows wymagają interfejsu extcap **USBPcap**; upewnij się, że działa po aktualizacji Wireshark, ponieważ brak extcap powoduje, że lista urządzeń jest pusta.<sup>[[4]](#references)</sup>
- Przed dekodowaniem czegokolwiek zawsze zweryfikuj krotkę magistrali, urządzenia i interfejsu (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; np. `1.9.1`) — pomieszanie kilku klawiatur lub urządzeń pamięci masowej prowadzi do bezsensownych wyników.<sup>[[10]](#references)</sup>



## References

- [1] [Raport z HackIT CTF 2017: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Analiza przechwyconych pakietów z klawiatury USB](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 — raport z pcap 1, 2](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Konfiguracja przechwytywania USB w Wireshark](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [Dekodery USB-HID](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Definicja klasy urządzeń dla urządzeń interfejsu człowiek–komputer (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [Tabele użycia HID 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Dokumentacja filtrów wyświetlania Wireshark: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Dokumentacja filtrów wyświetlania Wireshark: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
- [12] [Jądro Linux: wprowadzenie do deskryptorów raportów HID](https://docs.kernel.org/hid/hidintro.html)
- [13] [snakeCTF 2024: raport z zadania ordinary-keyboard](https://snakectf.org/writeups/2024-quals/misc/ordinary-keyboard)
{{#include ../../../banners/hacktricks-training.md}}
