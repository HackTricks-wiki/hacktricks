# Keystrokes USB

Se hai un pcap contenente la comunicazione via USB di una tastiera come quella seguente:

![Keystrokes USB: Se hai un pcap contenente la comunicazione via USB di una tastiera come quella seguente](<../../../images/image (962).png>)

Per una tastiera che utilizza il **boot protocol** HID, ogni report Interrupt IN ha una struttura fissa di 8 byte: un byte per i modificatori, un byte riservato e sei byte per i keycode. L'host confronta i report successivi e associa i keycode agli utilizzi HID per ricostruire gli eventi dei tasti.<sup>[[8]](#references)</sup>

## Nozioni di base sui report USB HID

Il report di input standard della tastiera in modalità boot è strutturato come segue.<sup>[[8]](#references)[[9]](#references)</sup>

| Byte | Significato |
| --- | --- |
| 0 | Bitmap dei modificatori (`0x02` = Shift sinistro, `0x20` = Shift destro, `0x40` = Alt destro, ecc.). È possibile impostare contemporaneamente più bit. |
| 1 | Byte riservato; i report non utilizzati dovrebbero normalmente impostarlo su zero. L'utilizzo specifico dell'OEM o del sistema non è portabile. |
| 2-7 | Fino a sei keycode simultanei nel formato USB usage ID (`0x04` = a, `0x1E` = 1). `0x00` significa "nessun tasto". |

Nella struttura boot, l'usage ID `0x01` (`Keyboard ErrorRollOver`) viene riportato in tutti gli slot dei tasti quando vengono premuti più di sei tasti non modificatori; può anche segnalare una combinazione non riconoscibile.<sup>[[8]](#references)[[9]](#references)</sup> Comprendere questa struttura è utile quando si dispone soltanto dei byte grezzi `usb.capdata`.

## Estrazione dei dati HID da un PCAP

### Identifica prima l'interfaccia della tastiera

Nei capture ricchi di traffico, identifica la tastiera HID prima di eseguire il dump dei report. Un punto di partenza affidabile è la risposta del descrittore dell'interfaccia:<sup>[[3]](#references)[[8]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
La classe HID definisce questi valori di interfaccia:<sup>[[8]](#references)</sup>

- `subclass == 1` è la Boot Interface Subclass; con `protocol == 1` identifica una tastiera boot
- `protocol == 2` identifica un mouse boot
- `protocol == 0` indica l'assenza del boot protocol; esamina invece l'HID report descriptor anziché presumere un layout di 8 byte

Una volta identificata l'interfaccia, applica i filtri a `usb.bus_id`, `usb.device_address` e, se possibile, `usb.bInterfaceNumber` prima di esportare qualsiasi dato.

### Workflow con Wireshark

1. **Isola il dispositivo**: applica un filtro al traffico interrupt IN della tastiera, ad esempio `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Aggiungi colonne utili**: fai clic con il pulsante destro sul campo `Leftover Capture Data` (`usb.capdata`) e sui campi `usbhid.*` preferiti (ad esempio `usbhid.boot_report.keyboard.keycode_1`) per seguire i tasti premuti senza aprire ogni frame.<sup>[[11]](#references)</sup>
3. **Nascondi i report vuoti**: applica `!(usb.capdata == 00:00:00:00:00:00:00:00)` per eliminare i frame inattivi.
4. **Esporta per il post-processing**: `File -> Export Packet Dissections -> As CSV`, includendo `frame.number`, `usb.src`, `usb.capdata` e i campi dei modifier decodificati, come `usbhid.boot_report.keyboard.modifier.left_shift` e `usbhid.boot_report.keyboard.modifier.right_alt`, per eseguire in seguito la ricostruzione tramite script.<sup>[[10]](#references)[[11]](#references)</sup>

### Workflow da riga di comando

Il classico pattern di estrazione — scaricare `usb.capdata`, eliminare i report inattivi e mappare gli usage ID — compare nell'analisi originale del 2017 e nel relativo walkthrough.<sup>[[1]](#references)[[2]](#references)</sup>

Il repository `ctf-usb-keyboard-parser` automatizza la classica pipeline `tshark + sed`:<sup>[[5]](#references)</sup>
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Nelle acquisizioni più recenti, preferisci il campo decodificato `usbhid.data` di Wireshark e usa `usb.capdata` come fallback; scrivi un payload per report in un file specifico per dispositivo:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```
Questi file per dispositivo possono essere passati a un decoder dopo aver normalizzato il formato hex previsto. Se la capture proviene da keyboard BLE incapsulate tramite GATT, applica il filtro `btatt.value && frame.len == 20` ed estrai i payload hex prima del decoding.<sup>[[7]](#references)</sup>

### Quando il report non è il classico boot report da 8 byte

Un'interfaccia non-boot o un report ID può modificare il layout del payload, quindi non assumere che ogni keyboard report corrisponda a `modifier,reserved,key1..key6`.<sup>[[8]](#references)[[11]](#references)</sup>

- Preferisci `usbhid.data` a `usb.capdata` quando Wireshark ha già effettuato il parsing del livello HID.
- Se ogni riga inizia con un prefisso costante o un report ID, rimuovilo con un decoder che tenga conto dell'offset invece di assumere che il byte 0 sia sempre il modifier.<sup>[[7]](#references)</sup>
- Alcuni export USBPcap omettono il reserved byte, quindi i decoder che supportano `--no-reserved` o un offset personalizzato fanno risparmiare tempo.<sup>[[7]](#references)</sup>
- Se l'HID report descriptor o la BLE HOGP report map è presente nella capture, usala per recuperare l'effettivo layout dei campi prima di scrivere un parser.

## Automazione del decoding

- **ctf-usb-keyboard-parser** rimane utile per i CTF rapidi ed è già incluso nel repository.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) analizza nativamente file `pcap` e `pcapng`, comprende `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` e non richiede tshark né altre dipendenze esterne, quindi è adatto a sandbox isolate.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** aggiunge visualizzatori per keyboard, mouse e tablet. Puoi eseguire l'helper `extract_hid_data.sh` (backend tshark) oppure `extract_hid_data.py` (backend scapy), quindi passare il file di testo risultante al decoder o ai moduli di replay per osservare la sequenza dei keystroke.<sup>[[7]](#references)</sup>

### L'importanza del decoding stateful

Le USB boot keyboard inviano report alla idle rate anche quando non si verifica un nuovo key event, quindi le capture possono contenere report ripetuti prima dell'evento di rilascio. Un decoder pratico dovrebbe:<sup>[[3]](#references)[[8]](#references)</sup>

- emettere solo i keycode premuti di recente rispetto al report precedente
- mantenere lo stato dei modifier (`Shift`, `Ctrl`, `AltGr`) dal byte 0 o da campi analizzati come `usbhid.boot_report.keyboard.modifier.left_shift` e `usbhid.boot_report.keyboard.modifier.right_alt`
- tenere traccia dei tasti toggle come `Caps Lock`, perché l'output maiuscolo non è controllato solo da Shift
- ricordare che gli HID usage ID sono indipendenti dal layout: `0x1d` indica la posizione fisica del tasto `z`/`y` a seconda del layout della keyboard host.<sup>[[9]](#references)</sup>

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
Usalo con le righe esadecimali semplici scaricate in precedenza per ottenere una ricostruzione approssimativa immediata senza introdurre nell'ambiente un parser completo. Per i layout non statunitensi, questo ricostruisce comunque la posizione fisica del tasto, non necessariamente il glifo finale mostrato sull'host della vittima.

## Troubleshooting tips

- Se Wireshark non popola i campi `usbhid.*`, probabilmente il descrittore del report HID non è stato catturato. Ricollega la tastiera durante la cattura oppure usa `usb.capdata` grezzo.
- Nelle catture software su Linux, `usbmon` è la sorgente normale; su Windows, Wireshark dipende dall'extcap **USBPcap** per poter visualizzare gli URB USB grezzi.<sup>[[4]](#references)</sup>
- Se la tastiera era collegata tramite un hub o una dock, verifica prima il descrittore dell'interfaccia e decodifica quindi solo quella coppia dispositivo/interfaccia. Le catture HID composite mescolano spesso i report di tastiera e mouse.
- Le catture Windows richiedono l'interfaccia extcap **USBPcap**; assicurati che sia ancora presente dopo gli aggiornamenti di Wireshark, poiché gli extcap mancanti lasciano gli elenchi dei dispositivi vuoti.<sup>[[4]](#references)</sup>
- Correla sempre la tupla bus, dispositivo e interfaccia (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; ad esempio `1.9.1`) prima di decodificare qualsiasi dato: mescolare più tastiere o dispositivi di storage produce keystroke senza senso.<sup>[[10]](#references)</sup>

## References

- [1] [HackIT CTF 2017 Writeup: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Analisi della cattura dei pacchetti della tastiera USB](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - write-up di pcap 1, 2](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Configurazione della cattura USB in Wireshark](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [Decoder USB-HID](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Definizione della classe del dispositivo per dispositivi di interfaccia umana (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [Tabelle degli utilizzi HID 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Riferimento dei Display Filter di Wireshark: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Riferimento dei Display Filter di Wireshark: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
{{#include ../../../banners/hacktricks-training.md}}
