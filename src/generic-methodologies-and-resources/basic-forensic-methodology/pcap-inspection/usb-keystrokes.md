# Pressioni dei tasti USB

{{#include ../../../banners/hacktricks-training.md}}

Se hai un pcap che contiene la comunicazione via USB di una tastiera come la seguente:

![](<../../../images/image (962).png>)

Le tastiere USB solitamente usano il protocollo HID **boot protocol**, quindi ogni transfer interrupt verso l'host è lungo solo 8 byte: un byte di bit modificatori (Ctrl/Shift/Alt/Super), un byte riservato, e fino a sei keycode per report. Decodificare questi byte è sufficiente per ricostruire tutto ciò che è stato digitato.

## Nozioni di base sul report USB HID

Il tipico report IN è simile a:

| Byte | Significato |
| --- | --- |
| 0 | Bitmap dei modificatori (`0x02` = Left Shift, `0x20` = Right Alt, etc.). Possono essere impostati più bit contemporaneamente. |
| 1 | Riservato/padding ma spesso riutilizzato dalle tastiere da gaming per dati vendor. |
| 2-7 | Fino a sei keycode contemporanei in formato USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` significa "nessun tasto". |

Le tastiere senza NKRO solitamente inviano `0x01` nel byte 2 quando vengono premuti più di sei tasti per segnalare il "rollover". Capire questa struttura aiuta quando si hanno solo i byte grezzi `usb.capdata`.

## Estrazione dei dati HID da un PCAP

### Flusso di lavoro in Wireshark

1. **Isolare il dispositivo**: filtrare il traffico interrupt IN dalla tastiera, es. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Aggiungere colonne utili**: clic destro sul campo `Leftover Capture Data` (`usb.capdata`) e sui campi `usbhid.*` preferiti (es. `usbhid.boot_report.keyboard.keycode_1`) per seguire le pressioni senza aprire ogni frame.
3. **Nascondere i report vuoti**: applicare `!(usb.capdata == 00:00:00:00:00:00:00:00)` per eliminare i frame inattivi.
4. **Esportare per post-processing**: `File -> Export Packet Dissections -> As CSV`, includere `frame.number`, `usb.src`, `usb.capdata`, e `usbhid.modifiers` per automatizzare la ricostruzione successivamente.

### Flusso di lavoro da riga di comando

`ctf-usb-keyboard-parser` automatizza già la classica pipeline tshark + sed:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Nelle acquisizioni più recenti puoi conservare sia `usb.capdata` che il più ricco campo `usbhid.data` raggruppando per dispositivo:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Questi file per dispositivo possono essere inseriti direttamente in qualsiasi decoder. Se la cattura proviene da tastiere BLE tunnellate su GATT, filtra con `btatt.value && frame.len == 20` ed esporta i payload esadecimali prima della decodifica.

## Automazione della decodifica

- **ctf-usb-keyboard-parser** rimane utile per veloci sfide CTF ed è già incluso nel repository.
- **CTF-Usb_Keyboard_Parser** (`main.py`) analizza nativamente sia file `pcap` che `pcapng`, comprende `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` e non richiede tshark, quindi funziona bene all'interno di sandbox isolate.
- **USB-HID-decoders** aggiunge visualizzatori per keyboard, mouse e tablet. Puoi eseguire l'helper `extract_hid_data.sh` (backend tshark) o `extract_hid_data.py` (backend scapy) e poi fornire il file di testo risultante ai moduli decoder o replay per vedere le pressioni dei tasti riprodotte.

## Decodificatore Python rapido
```python
#!/usr/bin/env python3
import sys
HID = {0x04:'a',0x05:'b',0x06:'c',0x07:'d',0x08:'e',0x09:'f',0x0a:'g',0x1c:'y',0x1d:'z',0x28:'\n'}
for raw in sys.stdin:
raw = raw.strip().replace(':', '')
if len(raw) != 16:
continue
keycode = int(raw[4:6], 16)
modifier = int(raw[0:2], 16)
if keycode:
char = HID.get(keycode, '?')
if modifier & 0x02:
char = char.upper()
sys.stdout.write(char)
```
Passagli le righe esadecimali grezze esportate in precedenza per ottenere una ricostruzione approssimativa immediata senza dover caricare un parser completo nell'ambiente.

## Suggerimenti per la risoluzione dei problemi

- Se Wireshark non popola i campi `usbhid.*`, probabilmente il descriptor del report HID non è stato catturato. Scollega e ricollega la tastiera durante la cattura o usa il raw `usb.capdata`.
- Le catture su Windows richiedono l'interfaccia extcap **USBPcap**; assicurati che sia sopravvissuta agli aggiornamenti di Wireshark, perché extcap mancanti lasciano liste di dispositivi vuote.
- Correlare sempre `usb.bus_id:device:interface` (ad es. `1.9.1`) prima di decodificare qualsiasi cosa — mescolare più tastiere o dispositivi di storage porta a sequenze di tasti senza senso.

## Riferimenti

- [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [HackTheBox Deadly Arthropod write-up](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)
- [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
