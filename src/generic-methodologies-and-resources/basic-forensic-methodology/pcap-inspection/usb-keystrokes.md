# Tasti USB

{{#include ../../../banners/hacktricks-training.md}}

Se hai un pcap contenente la comunicazione via USB di una tastiera come quella seguente:

![Tasti USB: se hai un pcap contenente la comunicazione via USB di una tastiera come quella seguente](<../../../images/image (962).png>)

Per una tastiera che utilizza il **boot protocol** HID, ogni report Interrupt IN ha un layout fisso di 8 byte: un byte per i modificatori, un byte riservato e sei byte per i keycode. L'host confronta i report consecutivi e associa i keycode agli utilizzi HID per ricostruire gli eventi dei tasti.<sup>[[8]](#references)</sup>

## Nozioni di base sui report USB HID

Il report di input standard di una tastiera in boot mode è strutturato come segue.<sup>[[8]](#references)[[9]](#references)</sup>

| Byte | Significato |
| --- | --- |
| 0 | Bitmap dei modificatori (`0x02` = Left Shift, `0x20` = Right Shift, `0x40` = Right Alt, ecc.). È possibile impostare più bit contemporaneamente. |
| 1 | Byte riservato; i report non utilizzati dovrebbero normalmente impostarlo su zero. L'utilizzo specifico da parte di OEM o del sistema non è portabile. |
| 2-7 | Fino a sei keycode simultanei nel formato USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` significa "nessun tasto". |

Nel layout boot, l'usage ID `0x01` (`Keyboard ErrorRollOver`) viene riportato in tutti gli slot dei tasti quando vengono premuti più di sei tasti non modificatori; può anche indicare una combinazione non riconoscibile.<sup>[[8]](#references)[[9]](#references)</sup> Comprendere questo layout è utile quando si hanno solo i byte raw `usb.capdata`.

## Estrazione dei dati HID da un PCAP

### Identificare prima l'interfaccia della tastiera

Nei capture molto trafficati, identifica la tastiera HID prima di eseguire il dump dei report. Un punto di partenza affidabile è la risposta del descrittore dell'interfaccia:<sup>[[3]](#references)[[8]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
La classe HID definisce questi valori dell'interfaccia:<sup>[[8]](#references)</sup>

- `subclass == 1` è la Boot Interface Subclass; con `protocol == 1` identifica una tastiera boot
- `protocol == 2` identifica un mouse boot
- `protocol == 0` indica l'assenza del boot protocol; esamina invece l'HID report descriptor, anziché assumere un layout di 8 byte

Una volta identificata l'interfaccia, restringi i filtri a `usb.bus_id`, `usb.device_address` e, se possibile, `usb.bInterfaceNumber` prima di esportare qualsiasi dato.

### Workflow Wireshark

1. **Isola il dispositivo**: filtra il traffico interrupt IN proveniente dalla tastiera, ad esempio `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Aggiungi colonne utili**: fai clic con il pulsante destro del mouse sul campo `Leftover Capture Data` (`usb.capdata`) e sui campi `usbhid.*` preferiti (ad esempio `usbhid.boot_report.keyboard.keycode_1`) per seguire le sequenze di tasti senza aprire ogni frame.<sup>[[11]](#references)</sup>
3. **Nascondi i report vuoti**: applica `!(usb.capdata == 00:00:00:00:00:00:00:00)` per rimuovere i frame inattivi.
4. **Esporta per il post-processing**: `File -> Export Packet Dissections -> As CSV`, includendo `frame.number`, `usb.src`, `usb.capdata` e i campi dei modificatori decodificati, come `usbhid.boot_report.keyboard.modifier.left_shift` e `usbhid.boot_report.keyboard.modifier.right_alt`, per eseguire successivamente la ricostruzione tramite script.<sup>[[10]](#references)[[11]](#references)</sup>

### Workflow da riga di comando

Il classico pattern di estrazione — eseguire il dump di `usb.capdata`, rimuovere i report inattivi e mappare gli usage ID — compare nell'analisi originale del 2017 e nel relativo walkthrough.<sup>[[1]](#references)[[2]](#references)</sup>

Il repository `ctf-usb-keyboard-parser` automatizza la classica pipeline tshark + sed:<sup>[[5]](#references)</sup>
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Nelle catture più recenti, preferisci il campo decodificato `usbhid.data` di Wireshark e usa `usb.capdata` come fallback; scrivi un payload per report in un file per dispositivo:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```
Questi file per dispositivo possono essere forniti a un decoder dopo aver normalizzato il formato esadecimale previsto. Se la cattura proviene da tastiere BLE incanalate tramite GATT, applica il filtro `btatt.value && frame.len == 20` ed estrai i payload esadecimali prima della decodifica.<sup>[[7]](#references)</sup>

### Quando il report non è il classico report di boot da 8 byte

Un'interfaccia non di boot o un report ID può modificare il layout del payload, quindi non presumere che ogni report della tastiera corrisponda a `modifier,reserved,key1..key6`.<sup>[[8]](#references)[[11]](#references)</sup>

- Preferisci `usbhid.data` a `usb.capdata` quando Wireshark ha già analizzato il livello HID.
- Se ogni riga inizia con un prefisso o un report ID costante, rimuovilo con un decoder che tenga conto dell'offset, invece di presumere che il byte 0 sia sempre il modificatore.<sup>[[7]](#references)</sup>
- Alcuni export di USBPcap omettono il byte riservato, quindi i decoder che supportano `--no-reserved` o un offset personalizzato fanno risparmiare tempo.<sup>[[7]](#references)</sup>
- Se nella cattura è presente il descrittore del report HID o la report map BLE HOGP, usalo per recuperare il layout effettivo dei campi prima di scrivere un parser.

## Automazione della decodifica

- **ctf-usb-keyboard-parser** rimane utile per le rapide challenge CTF ed è già incluso nel repository.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) analizza nativamente file `pcap` e `pcapng`, comprende `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` e non richiede tshark né altre dipendenze esterne, quindi è adatto agli ambienti sandbox isolati.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** aggiunge visualizzatori per tastiere, mouse e tablet. Puoi eseguire l'helper `extract_hid_data.sh` (backend tshark) oppure `extract_hid_data.py` (backend scapy), quindi fornire il file di testo risultante al decoder o ai moduli di replay per osservare la sequenza dei tasti premuti.<sup>[[7]](#references)</sup>

### La decodifica stateful è importante

Le tastiere USB di tipo boot inviano report alla frequenza di idle anche quando non si verifica un nuovo evento di pressione, quindi le catture possono contenere report ripetuti prima dell'evento di rilascio. Un decoder pratico dovrebbe:<sup>[[3]](#references)[[8]](#references)</sup>

- emettere solo i keycode premuti recentemente rispetto al report precedente
- mantenere lo stato dei modificatori (`Shift`, `Ctrl`, `AltGr`) dal byte 0 o da campi analizzati come `usbhid.boot_report.keyboard.modifier.left_shift` e `usbhid.boot_report.keyboard.modifier.right_alt`
- tenere traccia dei tasti di commutazione come `Caps Lock`, perché l'output maiuscolo non è controllato solo da Shift
- ricordare che gli Usage ID HID sono indipendenti dal layout: `0x1d` corrisponde alla posizione fisica del tasto `z`/`y`, a seconda del layout della tastiera host.<sup>[[9]](#references)</sup>

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
Inseriscigli le righe esadecimali pure scaricate in precedenza per ottenere una ricostruzione approssimativa immediata senza introdurre nell'ambiente un parser completo. Per i layout non statunitensi, questo ricostruisce comunque la posizione fisica del tasto, non necessariamente il carattere finale visualizzato sull'host della vittima.

## Suggerimenti per la risoluzione dei problemi

- Se Wireshark non popola i campi `usbhid.*`, probabilmente il descrittore del report HID non è stato catturato. Ricollega la tastiera durante la cattura oppure ricorri a `usb.capdata` grezzo.
- Nelle catture software su Linux, `usbmon` è la sorgente normale; su Windows, Wireshark dipende dall'extcap **USBPcap** per visualizzare i raw USB URB.<sup>[[4]](#references)</sup>
- Se la tastiera era collegata tramite un hub o una dock, verifica prima il descrittore dell'interfaccia e poi decodifica solo quella coppia dispositivo/interfaccia. Le catture HID composite mescolano spesso i report di tastiera e mouse.
- Le catture Windows richiedono l'interfaccia extcap **USBPcap**; assicurati che sia rimasta disponibile dopo gli aggiornamenti di Wireshark, poiché extcap mancanti lasciano gli elenchi dei dispositivi vuoti.<sup>[[4]](#references)</sup>
- Correlaziona sempre la tupla bus, dispositivo e interfaccia (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; ad esempio `1.9.1`) prima di decodificare qualsiasi cosa: mescolare più tastiere o dispositivi di archiviazione produce sequenze di tasti senza senso.<sup>[[10]](#references)</sup>

## References

- [1] [Writeup dell'CTF HackIT 2017: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Analisi della cattura dei pacchetti della tastiera USB](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - write-up di pcap 1, 2](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Configurazione della cattura USB in Wireshark](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [Decoder USB-HID](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Definizione della classe del dispositivo per i dispositivi di interfaccia umana (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [Tabelle degli utilizzi HID 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Riferimento dei filtri di visualizzazione di Wireshark: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Riferimento dei filtri di visualizzazione di Wireshark: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
{{#include ../../../banners/hacktricks-training.md}}
