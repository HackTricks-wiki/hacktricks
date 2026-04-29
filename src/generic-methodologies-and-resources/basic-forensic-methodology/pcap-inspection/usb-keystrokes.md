# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

Se hai un pcap contenente la comunicazione via USB di una tastiera come la seguente:

![](<../../../images/image (962).png>)

Le tastiere USB di solito parlano il protocollo HID **boot**, quindi ogni transfer di interrupt verso l'host è lungo solo 8 byte: un byte di bit modifier (Ctrl/Shift/Alt/Super), un byte riservato e fino a sei keycode per report. Decodificare questi byte è sufficiente per ricostruire tutto ciò che è stato digitato.

## USB HID report basics

Il tipico report IN ha l'aspetto seguente:

| Byte | Meaning |
| --- | --- |
| 0 | Bitmap dei modifier (`0x02` = Left Shift, `0x20` = Right Alt, ecc.). Più bit possono essere impostati contemporaneamente. |
| 1 | Riservato/padding, ma spesso riutilizzato dalle tastiere gaming per dati vendor. |
| 2-7 | Fino a sei keycode concorrenti nel formato USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` significa "no key". |

Le tastiere senza NKRO di solito inviano `0x01` nel byte 2 quando vengono premuti più di sei tasti per segnalare "rollover". Capire questo layout aiuta quando hai solo i byte grezzi `usb.capdata`.

## Extracting HID data from a PCAP

### Identify the keyboard interface first

Su capture molto trafficate, identifica prima la tastiera HID prima di esportare qualsiasi report. Un punto di partenza affidabile è la risposta del descriptor dell'interfaccia:
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Guarda `usb.bInterfaceSubClass` e `usb.bInterfaceProtocol`:

- `subclass == 1` e `protocol == 1` di solito significa una boot keyboard
- `protocol == 2` è in genere un mouse
- `protocol == 0` spesso indica un'interfaccia HID vendor-defined o in stile NKRO che trasporta comunque dati da tastiera, ma non nel semplice layout boot a 8 byte

Una volta nota l'interfaccia, fissa i filtri su `usb.bus_id`, `usb.device_address` e, se possibile, `usb.interface_number` prima di esportare qualsiasi cosa.

### Flusso di lavoro in Wireshark

1. **Isola il dispositivo**: filtra il traffico interrupt IN dalla tastiera, ad es. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Aggiungi colonne utili**: fai clic destro sul campo `Leftover Capture Data` (`usb.capdata`) e sui tuoi campi `usbhid.*` preferiti (ad es. `usbhid.boot_report.keyboard.keycode_1`) per seguire le keystrokes senza aprire ogni frame.
3. **Nascondi i report vuoti**: applica `!(usb.capdata == 00:00:00:00:00:00:00:00)` per eliminare i frame inattivi.
4. **Esporta per il post-processing**: `File -> Export Packet Dissections -> As CSV`, includi `frame.number`, `usb.src`, `usb.capdata` e `usbhid.modifiers` per scriptare la ricostruzione in seguito.

### Flusso di lavoro da command-line

`ctf-usb-keyboard-parser` automatizza già la classica pipeline tshark + sed:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Sulle acquisizioni più recenti puoi mantenere sia `usb.capdata` sia il campo più ricco `usbhid.data` raggruppando per dispositivo:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Quei file per-device si inseriscono direttamente in qualsiasi decoder. Se la cattura proviene da tastiere BLE tunnelizzate su GATT, filtra con `btatt.value && frame.len == 20` e scarica i payload hex prima della decodifica.

### Quando il report non è il classico report boot da 8 byte

Le tastiere gaming recenti, le tastiere split e i dispositivi HID compositi spesso espongono un'interfaccia keyboard non-boot in cui il payload non corrisponde più a `modifier,reserved,key1..key6`.

- Preferisci `usbhid.data` a `usb.capdata` quando Wireshark ha già analizzato il layer HID.
- Se ogni riga inizia con un prefisso costante o un report ID, rimuovilo con un decoder offset-aware invece di assumere che il byte 0 sia sempre il modifier.
- Alcuni export USBPcap omettono il byte reserved, quindi i decoder che supportano `--no-reserved` o un offset personalizzato fanno risparmiare tempo.
- Se il report descriptor HID o la BLE HOGP report map è presente nella cattura, usalo per recuperare il layout reale dei campi prima di scrivere un parser.

## Automazione della decodifica

- **ctf-usb-keyboard-parser** resta utile per challenge CTF rapide ed è già incluso nel repository.
- **CTF-Usb_Keyboard_Parser** (`main.py`) analizza nativamente sia file `pcap` che `pcapng`, comprende `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` e non richiede tshark, quindi funziona bene dentro sandbox isolate.
- **USB-HID-decoders** aggiunge visualizzatori per keyboard, mouse e tablet. Puoi eseguire l'helper `extract_hid_data.sh` (backend tshark) oppure `extract_hid_data.py` (backend scapy) e poi passare il file di testo risultante al decoder o ai moduli di replay per osservare l'evoluzione dei keystrokes.

### La decodifica stateful è importante

Le catture USB interrupt di solito contengono sia la pressione del tasto sia una o più copie ripetute dello stesso report prima che arrivi l'evento di rilascio. Un decoder pratico dovrebbe:

- emettere solo i keycode appena premuti rispetto al report precedente
- mantenere lo stato dei modifier (`Shift`, `Ctrl`, `AltGr`) dal byte 0 o dal campo `usbhid.boot_report.keyboard.modifier` parsato
- tracciare i tasti toggle come `Caps Lock`, perché l'output in maiuscolo non è controllato solo da Shift
- ricordare che gli HID usage ID sono indipendenti dal layout: `0x1d` è la posizione fisica del tasto `z`/`y` a seconda del layout della tastiera dell'host

## Quick Python decoder
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
Usalo con le righe hex grezze dumpate in precedenza per ottenere subito una ricostruzione approssimativa senza dover caricare un parser completo nell'ambiente. Per layout non-US, questo ricostruisce comunque la posizione fisica del tasto, non necessariamente il glyph finale mostrato sull'host della vittima.

## Troubleshooting tips

- Se Wireshark non popola i campi `usbhid.*`, probabilmente il HID report descriptor non è stato catturato. Ricollega la tastiera durante la cattura oppure passa al raw `usb.capdata`.
- Sulle capture software Linux, `usbmon` è la sorgente normale; su Windows, Wireshark dipende dall'extcap **USBPcap** per vedere in assoluto i raw USB URBs.
- Se la tastiera era collegata tramite un hub o dock, conferma prima l'interface descriptor e poi decodifica solo quella coppia device/interface. Le capture HID composite mescolano spesso report di tastiera e mouse.
- Le capture Windows richiedono l'interfaccia extcap **USBPcap**; assicurati che sia sopravvissuta agli upgrade di Wireshark, perché extcap mancanti ti lasciano con liste dispositivi vuote.
- Correlare sempre `usb.bus_id:device:interface` (ad es. `1.9.1`) prima di decodificare qualsiasi cosa — mescolare più tastiere o dispositivi di storage porta a keystrokes senza senso.

## References

- [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)

{{#include ../../../banners/hacktricks-training.md}}
