# Keystroke USB

{{#include ../../../banners/hacktricks-training.md}}

Se hai un pcap contenente la comunicazione via USB di una tastiera come quella seguente:

![Keystroke USB: Se hai un pcap contenente la comunicazione via USB di una tastiera come quella seguente](<../../../images/image (962).png>)

Le tastiere USB utilizzano generalmente il **boot protocol** HID, quindi ogni interrupt transfer verso l'host è lungo solo 8 byte: un byte di bit dei modificatori (Ctrl/Shift/Alt/Super), un byte riservato e fino a sei keycode per report. Decodificare questi byte è sufficiente per ricostruire tutto ciò che è stato digitato.

## Nozioni di base sui report USB HID

Il tipico report IN è strutturato come segue:

| Byte | Significato |
| --- | --- |
| 0 | Bitmap dei modificatori (`0x02` = Left Shift, `0x20` = Right Alt, ecc.). È possibile impostare più bit contemporaneamente. |
| 1 | Riservato/padding, ma spesso riutilizzato dalle tastiere gaming per dati del vendor. |
| 2-7 | Fino a sei keycode simultanei nel formato USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` significa "nessun tasto". |

Le tastiere senza NKRO generalmente inviano `0x01` nel byte 2 quando vengono premuti più di sei tasti, per segnalare il "rollover". Comprendere questo layout è utile quando si dispone solo dei byte `usb.capdata` raw.

## Estrazione dei dati HID da un PCAP

### Identificare prima l'interfaccia della tastiera

Nelle catture trafficate, identifica la tastiera HID prima di eseguire il dump dei report. Un punto di partenza affidabile è la risposta al descrittore dell'interfaccia:<sup>[[2]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Controlla `usb.bInterfaceSubClass` e `usb.bInterfaceProtocol`:

- `subclass == 1` e `protocol == 1` indicano solitamente una boot keyboard
- `protocol == 2` indica in genere un mouse
- `protocol == 0` spesso indica un'interfaccia HID vendor-defined o in stile NKRO che trasporta comunque dati della tastiera, ma non nel semplice layout boot da 8 byte

Una volta identificata l'interfaccia, limita i tuoi filtri a `usb.bus_id`, `usb.device_address` e, se possibile, `usb.interface_number` prima di esportare qualsiasi dato.

### Workflow Wireshark

1. **Isola il dispositivo**: filtra il traffico interrupt IN proveniente dalla tastiera, ad esempio `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Aggiungi colonne utili**: fai clic con il tasto destro sul campo `Leftover Capture Data` (`usb.capdata`) e sui campi `usbhid.*` che preferisci, ad esempio `usbhid.boot_report.keyboard.keycode_1`, per seguire le sequenze di tasti senza aprire ogni frame.
3. **Nascondi i report vuoti**: applica `!(usb.capdata == 00:00:00:00:00:00:00:00)` per rimuovere i frame inattivi.
4. **Esporta per il post-processing**: `File -> Export Packet Dissections -> As CSV`, includendo `frame.number`, `usb.src`, `usb.capdata` e `usbhid.modifiers` per eseguire in seguito lo script di ricostruzione.

### Workflow da riga di comando

`ctf-usb-keyboard-parser` automatizza già la classica pipeline tshark + sed:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Nelle catture più recenti puoi mantenere sia `usb.capdata` sia il campo più ricco `usbhid.data` raggruppando per dispositivo:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Questi file per dispositivo possono essere inseriti direttamente in qualsiasi decoder. Se la cattura proviene da tastiere BLE incanalate tramite GATT, filtra con `btatt.value && frame.len == 20` ed estrai i payload esadecimali prima della decodifica.

### Quando il report non è il classico boot report da 8 byte

Le tastiere gaming recenti, le tastiere split e i dispositivi HID compositi espongono spesso un'interfaccia per tastiera non-boot, in cui il payload non corrisponde più a `modifier,reserved,key1..key6`.

- Preferisci `usbhid.data` a `usb.capdata` quando Wireshark ha già analizzato il livello HID.
- Se ogni riga inizia con un prefisso costante o un report ID, rimuovilo con un decoder che tenga conto dell'offset invece di presumere che il byte 0 sia sempre il modificatore.
- Alcuni export USBPcap omettono il byte riservato, quindi i decoder che supportano `--no-reserved` o un offset personalizzato fanno risparmiare tempo.
- Se nella cattura è presente il descrittore del report HID o la report map BLE HOGP, usala per recuperare la struttura effettiva dei campi prima di scrivere un parser.

## Automazione della decodifica

- **ctf-usb-keyboard-parser** resta utile per le rapide challenge CTF ed è già incluso nel repository.<sup>[[3]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) analizza nativamente i file `pcap` e `pcapng`, comprende `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` e non richiede tshark, quindi funziona bene all'interno di sandbox isolate.<sup>[[4]](#references)</sup>
- **USB-HID-decoders** aggiunge visualizzatori per tastiere, mouse e tablet. Puoi eseguire l'helper `extract_hid_data.sh` (backend tshark) oppure `extract_hid_data.py` (backend scapy), quindi fornire il file di testo risultante al decoder o ai moduli di replay per osservare la sequenza dei tasti premuti.<sup>[[5]](#references)</sup>

### La decodifica stateful è importante

Le catture degli interrupt USB contengono solitamente sia la pressione del tasto sia una o più copie ripetute dello stesso report prima che arrivi l'evento di rilascio. Un decoder pratico dovrebbe:<sup>[[2]](#references)</sup>

- emettere solo i keycode appena premuti rispetto al report precedente
- mantenere lo stato dei modificatori (`Shift`, `Ctrl`, `AltGr`) dal byte 0 o dal campo analizzato `usbhid.boot_report.keyboard.modifier`
- tenere traccia dei tasti di commutazione come `Caps Lock`, poiché l'output maiuscolo non è controllato esclusivamente da Shift
- ricordare che gli HID usage ID sono indipendenti dal layout: `0x1d` indica la posizione fisica del tasto `z`/`y` a seconda del layout della tastiera host

## Decoder Python rapido
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
Alimentalo con le righe hex grezze scaricate in precedenza per ottenere una ricostruzione approssimativa immediata senza inserire nell'ambiente un parser completo. Per i layout non statunitensi, questa procedura ricostruisce comunque la posizione fisica del tasto, ma non necessariamente il carattere finale visualizzato sull'host della vittima.

## Suggerimenti per la risoluzione dei problemi

- Se Wireshark non valorizza i campi `usbhid.*`, probabilmente il descrittore del report HID non è stato catturato. Scollega e ricollega la tastiera durante la cattura oppure usa `usb.capdata` grezzo.
- Nelle catture software su Linux, `usbmon` è la sorgente normale; su Windows, Wireshark dipende dall'extcap **USBPcap** per vedere gli URB USB grezzi.<sup>[[1]](#references)</sup>
- Se la tastiera era collegata tramite un hub o una dock, verifica prima il descrittore dell'interfaccia e poi decodifica solo quella coppia dispositivo/interfaccia. Le catture HID composite spesso mescolano i report della tastiera e del mouse.
- Le catture su Windows richiedono l'interfaccia extcap **USBPcap**; assicurati che sia rimasta disponibile dopo gli aggiornamenti di Wireshark, poiché l'assenza degli extcap lascia gli elenchi dei dispositivi vuoti.<sup>[[1]](#references)</sup>
- Correla sempre `usb.bus_id:device:interface` (ad esempio `1.9.1`) prima di decodificare qualsiasi elemento: mescolare più tastiere o dispositivi di archiviazione produce sequenze di tasti senza senso.

## Riferimenti

- [1] [Configurazione della cattura USB in Wireshark](https://wiki.wireshark.org/CaptureSetup/USB)
- [2] [ACSC Quals 2023 - write-up di pcap 1, 2](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [3] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [4] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [5] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
